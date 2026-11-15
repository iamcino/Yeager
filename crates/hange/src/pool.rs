//! What the stub forwards to: the provider the user chose, with a backup that
//! takes over while it stays unreachable, or in Auto mode whichever of
//! Cloudflare and Google answers faster.

use crate::upstream::{Stat, Transport, Upstream};
use common::DohProvider;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A chosen provider gives way to its backup after failing this long.
const FAILOVER_AFTER: Duration = Duration::from_secs(10);
/// While on the backup, how often the chosen provider is tried again.
const RECOVER_EVERY: Duration = Duration::from_secs(30);
/// Auto mode: how often the provider not in use is measured.
const AUTO_EVERY: Duration = Duration::from_secs(30 * 60);
/// Keep-warm: while queries came in the last [`WARM_FOR`], a connection idle
/// for [`WARM_IDLE`] gets one small query, so the next real one does not pay
/// for a new TLS/QUIC handshake. Checked every [`WARM_EVERY`].
const WARM_EVERY: Duration = Duration::from_secs(45);
const WARM_IDLE: Duration = Duration::from_secs(40);
const WARM_FOR: Duration = Duration::from_secs(15 * 60);
/// Auto mode switches only to a provider this much faster…
const AUTO_FASTER: f64 = 0.8;
const AUTO_MIN_GAIN: Duration = Duration::from_millis(5);
/// …in this many measurements in a row, so it does not flap.
const AUTO_STREAK: u8 = 2;

/// The provider setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Fixed(DohProvider),
    /// The faster of [`AUTO_PROVIDERS`].
    Auto,
}

/// What Auto picks from. AdGuard is left out: it filters ads, and that should
/// not come and go with latency.
pub const AUTO_PROVIDERS: [DohProvider; 2] = [DohProvider::Cloudflare, DohProvider::Google];

/// The provider that stands in while `provider` is unreachable.
fn backup(provider: DohProvider) -> DohProvider {
    match provider {
        DohProvider::Cloudflare => DohProvider::Google,
        DohProvider::Google | DohProvider::AdGuard => DohProvider::Cloudflare,
    }
}

/// Which provider answers now, over which route.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoolStatus {
    pub provider: DohProvider,
    pub stat: Option<Stat>,
    /// The chosen provider is unreachable and its backup answers instead.
    pub on_backup: bool,
}

pub struct Pool {
    /// Fixed: the choice, then its backup. Auto: [`AUTO_PROVIDERS`].
    /// Behind a lock so a serving stub can retarget its upstream to a new
    /// `Choice` while its sockets stay bound (U06-REV2 item 1).
    members: Mutex<[Arc<Upstream>; 2]>,
    auto: AtomicBool,
    /// The member answering queries.
    active: AtomicUsize,
    checked_at: Mutex<Option<Instant>>,
    checking: AtomicBool,
    /// Auto: measurements in a row in which the other provider was faster.
    streak: AtomicU8,
    /// When a client query last went upstream.
    used_at: Mutex<Option<Instant>>,
}

impl Pool {
    pub fn new(choice: Choice) -> Self {
        let (members, auto) = match choice {
            Choice::Fixed(p) => ([p, backup(p)], false),
            Choice::Auto => (AUTO_PROVIDERS, true),
        };
        Self::from_upstreams(members.map(|p| Arc::new(Upstream::new(p))), auto)
    }

    pub(crate) fn from_upstreams(members: [Arc<Upstream>; 2], auto: bool) -> Self {
        Self {
            members: Mutex::new(members),
            auto: AtomicBool::new(auto),
            active: AtomicUsize::new(0),
            checked_at: Mutex::new(None),
            checking: AtomicBool::new(false),
            streak: AtomicU8::new(0),
            used_at: Mutex::new(None),
        }
    }

    /// Retarget the forwarder to a new `Choice` without rebinding sockets.
    /// Replaces both members, resets the active index to the new primary,
    /// and clears failover/auto measurement state. Old connections close
    /// when their `Arc`s drop.
    pub fn retarget(&self, choice: Choice) {
        let (providers, auto) = match choice {
            Choice::Fixed(p) => ([p, backup(p)], false),
            Choice::Auto => (AUTO_PROVIDERS, true),
        };
        let fresh = providers.map(|p| Arc::new(Upstream::new(p)));
        let old = {
            let mut guard = self.members.lock().unwrap();
            std::mem::replace(&mut *guard, fresh)
        };
        for m in &old {
            m.close();
        }
        self.auto.store(auto, Ordering::Relaxed);
        self.active.store(0, Ordering::Relaxed);
        self.streak.store(0, Ordering::Relaxed);
        *self.checked_at.lock().unwrap() = None;
        self.checking.store(false, Ordering::Relaxed);
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    fn is_auto(&self) -> bool {
        self.auto.load(Ordering::Relaxed)
    }

    pub fn status(&self) -> PoolStatus {
        let i = self.active();
        let guard = self.members.lock().unwrap();
        let member = &guard[i];
        let auto = self.is_auto();
        PoolStatus {
            provider: member.provider(),
            stat: member.stat(),
            on_backup: !auto && i == 1,
        }
    }

    /// Sends `query` to the provider in use, falling over to the other one
    /// as described on [`Pool`].
    pub async fn query(self: &Arc<Self>, query: &Message) -> Result<(Message, Transport), String> {
        *self.used_at.lock().unwrap() = Some(Instant::now());
        let i = self.active();
        let (first_member, other_member, auto) = {
            let guard = self.members.lock().unwrap();
            (guard[i].clone(), guard[1 - i].clone(), self.is_auto())
        };
        let first = first_member.query(query).await;
        self.maybe_check();
        let error = match first {
            Ok(answer) => return Ok(answer),
            Err(e) => e,
        };
        // Auto has no preference, and the backup gives way at once; the
        // chosen provider gets a grace period first.
        let other = 1 - i;
        let down_long = first_member.failing_for().is_some_and(|d| d >= FAILOVER_AFTER);
        if !(auto || i == 1 || down_long) {
            return Err(error);
        }
        match other_member.query(query).await {
            Ok(answer) => {
                self.active.store(other, Ordering::Relaxed);
                self.streak.store(0, Ordering::Relaxed);
                Ok(answer)
            }
            Err(e) => Err(format!("{error}; {}: {e}", other_member.provider().label())),
        }
    }

    /// Runs for the life of the stub, keeping the connection in use warm as
    /// described on [`WARM_EVERY`]. Nothing is sent while the PC is idle.
    pub async fn keep_warm(self: Arc<Self>) {
        loop {
            tokio::time::sleep(WARM_EVERY).await;
            let idle = self.used_at.lock().unwrap().map(|at| at.elapsed());
            if idle.is_some_and(|idle| idle >= WARM_IDLE && idle < WARM_FOR) {
                let member = {
                    let i = self.active();
                    self.members.lock().unwrap()[i].clone()
                };
                let _ = member.query(&probe()).await;
            }
        }
    }

    /// Starts a background check when one is due: while on the backup, whether
    /// the chosen provider is back; in Auto mode, whether the other provider
    /// has become faster.
    fn maybe_check(self: &Arc<Self>) {
        let auto = self.is_auto();
        let on_backup = !auto && self.active() == 1;
        if !auto && !on_backup {
            return;
        }
        let every = if auto { AUTO_EVERY } else { RECOVER_EVERY };
        {
            let mut checked_at = self.checked_at.lock().unwrap();
            if checked_at.is_some_and(|at| at.elapsed() < every) || self.checking.swap(true, Ordering::Relaxed) {
                return;
            }
            *checked_at = Some(Instant::now());
        }
        let this = self.clone();
        tokio::spawn(async move {
            let auto_now = this.is_auto();
            if auto_now {
                this.compare().await;
            } else {
                let (first, second) = {
                    let guard = this.members.lock().unwrap();
                    (guard[0].clone(), guard[1].clone())
                };
                if first.query(&probe()).await.is_ok() {
                    this.active.store(0, Ordering::Relaxed);
                    second.close();
                }
            }
            this.checking.store(false, Ordering::Relaxed);
        });
    }

    /// Auto mode: measures the provider not in use and switches to it if it
    /// has been clearly faster. The first measurement switches at once.
    async fn compare(&self) {
        let i = self.active();
        let (current, other) = {
            let guard = self.members.lock().unwrap();
            (guard[i].clone(), guard[1 - i].clone())
        };
        let first = current.stat().is_none();
        if first {
            let _ = current.query(&probe()).await;
        }
        let measured = other.query(&probe()).await.ok().and(other.stat());
        let faster = match (current.stat(), measured) {
            (Some(now), Some(then)) => {
                let (a, b) = (now.rtt, then.rtt);
                if first {
                    b < a
                } else {
                    b < a.mul_f64(AUTO_FASTER) && a.saturating_sub(b) >= AUTO_MIN_GAIN
                }
            }
            (None, Some(_)) => true,
            _ => false,
        };
        let streak = if faster { self.streak.load(Ordering::Relaxed) + 1 } else { 0 };
        if faster && (first || streak >= AUTO_STREAK) {
            self.active.store(1 - i, Ordering::Relaxed);
            self.streak.store(0, Ordering::Relaxed);
            current.close();
        } else {
            self.streak.store(streak, Ordering::Relaxed);
            other.close();
        }
    }
}

/// A small query whose answer every resolver keeps cached.
fn probe() -> Message {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str("example.com.").unwrap(), RecordType::A));
    query
}

/// Measures `provider` with one query per address and transport, and returns
/// the quickest route. HTTP/3 only if `http3`.
pub async fn measure(provider: DohProvider, http3: bool) -> Option<Stat> {
    let upstream = Upstream::new(provider);
    let upstream = Arc::new(if http3 { upstream } else { upstream.without_http3() });
    upstream.query(&probe()).await.ok()?;
    // Let the other routes finish their race so the quickest is kept.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let stat = upstream.stat();
    upstream.close();
    stat
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead(provider: DohProvider) -> Arc<Upstream> {
        Arc::new(Upstream::with_addrs(provider, vec!["127.0.0.1:1".parse().unwrap()]))
    }

    #[tokio::test]
    async fn backup_waits_for_grace_period() {
        let pool = Arc::new(Pool::from_upstreams([dead(DohProvider::AdGuard), dead(DohProvider::Cloudflare)], false));
        assert!(pool.query(&probe()).await.is_err());
        // Within the grace period the chosen provider stays in use.
        assert_eq!(pool.status().provider, DohProvider::AdGuard);
        assert!(!pool.status().on_backup);
    }

    /// Needs the Internet: `cargo test -p hange live_routes -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn live_routes() {
        for p in DohProvider::ALL {
            println!("{}: {:?}", p.label(), measure(p, true).await);
        }
        for choice in [Choice::Fixed(DohProvider::AdGuard), Choice::Auto] {
            let pool = Arc::new(Pool::new(choice));
            for _ in 0..5 {
                let started = Instant::now();
                let result = pool.query(&probe()).await.map(|(_, t)| t);
                println!("{choice:?}: {result:?} in {:?}, {:?}", started.elapsed(), pool.status());
            }
        }
    }

    #[test]
    fn auto_leaves_adguard_out() {
        assert!(!AUTO_PROVIDERS.contains(&DohProvider::AdGuard));
        assert_eq!(backup(DohProvider::AdGuard), DohProvider::Cloudflare);
    }
}

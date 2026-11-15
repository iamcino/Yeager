//! U07 — admission and shutdown coordinator (SPEC-DNS-FIX.md §6, §12 U07).
//!
//! Placement: `crates/app/src/lifecycle.rs`, extending the U06 coordinator
//! layer. The U06 [`hange::Coordinator`] owns transactional listener/DNS
//! state; this module owns what sits in front of it and around it: the
//! admission queue with epoch barriers, and the engine-independent teardown.
//!
//! Section 12 law holds: everything here is built and tested against fakes.
//! There is deliberately no production takeover wiring in this unit — no
//! `main.rs` exit path, toggle handler, updater or installer calls this
//! module yet. That wiring is U08's job ("wire every exit-table row"). The
//! seams ([`DnsCtl`], [`EngineCtl`], [`UiNotify`], [`PersistCfg`]) are what
//! U08 will bind to the real coordinator / engine / UI / config-save.
//!
//! Ordering (spec §6), enforced structurally, not by convention:
//!
//! 1. Shutdown marks quiescing FIRST under the admission mutex: the epoch is
//!    bumped, `enable` / engine-start callbacks with older epochs are
//!    rejected, queued-but-unstarted work is cancelled, and [`DnsCtl::quiesce`]
//!    is sent immediately. Engine stop is never first.
//! 2. In-flight (already started) DNS work settles: shutdown waits for it on
//!    a condition variable, then the restore runs behind it. A stale success
//!    is discarded — it can never start the engine or enqueue new work, and
//!    no new apply starts after the restore barrier.
//! 3. Restore and verify run on the DNS path with no engine/TCP/config locks
//!    held. The engine stop runs on its own detached thread with a bounded
//!    join and caught unwind: a hanging or panicking `engine::stop` can
//!    neither block nor break DNS recovery. UI-callback and config-save
//!    failures are recorded but never gate recovery.
//! 4. Only after verified restore do listeners stop (bounded, inside the
//!    DNS seam). The pending/conflict branch keeps the listener and performs
//!    an explicit service handoff instead — it never reports success.
//! 5. DNS-off reopens admission only on a fresh clean epoch after verified
//!    restoration. A process quit never reopens. Repeated same-kind shutdowns
//!    join the same result; the DNS restore runs exactly once.
//!
//! [`hange::Coordinator`]: ../../hange/struct.Coordinator.html

// U07 builds against fakes; U08 wires the production paths (SPEC §12
// sequencing), so nothing here is referenced from `main.rs` yet.
#![allow(dead_code)]

use hange::Choice;
use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// How long shutdown waits for a hanging engine stop before declaring it
/// timed-out and reporting the DNS result anyway.
const DEFAULT_ENGINE_STOP_BOUND: Duration = Duration::from_secs(30);

/// Which teardown the caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownKind {
    /// DNS toggle off: restore, verify, stop listeners, then reopen admission
    /// on a fresh clean epoch.
    DnsOff,
    /// Process exit: restore, verify, stop listeners, never reopen.
    ProcessQuit,
}

/// DNS-side outcome of an operation or a shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOutcome {
    /// Originals restored and freshly verified.
    Verified,
    /// Not fully restored; the listener is retained and the debt is kept.
    /// Never reported as success.
    Pending(String),
    /// A foreign/owner conflict; the listener is retained, no overwrite.
    /// Never reported as success.
    Conflict(String),
}

impl DnsOutcome {
    /// Only [`DnsOutcome::Verified`] counts as success.
    pub fn successful(&self) -> bool {
        matches!(self, DnsOutcome::Verified)
    }
}

/// What happened to the engine stop that ran alongside shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineOutcome {
    /// The engine stop returned.
    Completed,
    /// Still running past the bound; shutdown reported the DNS result anyway.
    TimedOut,
    /// The engine stop panicked; the panic was caught, DNS still recovered.
    Panicked(String),
}

/// Idempotent result of [`Lifecycle::shutdown`]. Cloned to every joiner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    pub kind: ShutdownKind,
    pub dns: DnsOutcome,
    pub engine: EngineOutcome,
    /// Epoch at report time (post-reopen for a clean DNS-off).
    pub epoch: u64,
    /// True only for a verified DNS-off, on a fresh clean epoch.
    pub reopened: bool,
    /// Queued-but-unstarted enables cancelled by the admission close.
    pub cancelled_queued: usize,
    /// Best-effort UI notification failure; never gates recovery.
    pub ui_error: Option<String>,
    /// Best-effort config-save failure; never gates recovery.
    pub persist_error: Option<String>,
}

impl ShutdownReport {
    /// Pending/conflict is visible, never successful — even for DNS-off.
    pub fn successful(&self) -> bool {
        self.dns.successful()
    }
}

/// Why an enable or engine-start request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused: {}", self.reason)
    }
}

/// Admission ticket for a queued enable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub id: u64,
    pub epoch: u64,
}

/// What [`Lifecycle::run_queued`] did with the oldest queued enable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Nothing was queued.
    Empty,
    /// The ticket's epoch no longer matches: discarded without touching DNS.
    StaleDiscarded { id: u64 },
    /// The enable ran under a still-current epoch.
    Finished { id: u64, outcome: DnsOutcome },
}

/// Point-in-time admission state (diagnostics/tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub admission_open: bool,
    pub epoch: u64,
    pub queued: usize,
    pub running: usize,
}

/// DNS seam: quiesce / restore / verify / listener-stop / handoff plus a
/// transactional epoch-bound enable. U08 binds this to the U06 coordinator;
/// U07 tests script it.
pub trait DnsCtl: Send + Sync {
    /// Close admission on the DNS side (idempotent barrier).
    fn quiesce(&self);
    /// Restore pre-takeover originals (spec §5.3 R0–R5).
    fn restore(&self) -> DnsOutcome;
    /// Fresh configured readback equality sweep (spec §5.3 R6).
    fn verify(&self) -> bool;
    /// Bounded listener stop, only after verified restore.
    fn stop_listeners(&self);
    /// Explicit service handoff for the pending/conflict branch: the
    /// listener is retained and DNS authority stays alive elsewhere.
    fn handoff(&self);
    /// Transactional enable bound to an admission epoch.
    fn enable(&self, choice: Choice, local: bool, epoch: u64) -> DnsOutcome;
}

/// Engine seam: stop may hang forever or panic; start is gated by epoch.
/// U08 binds this to `engine::{start,stop}`; U07 tests script it.
pub trait EngineCtl: Send + Sync {
    fn stop(&self);
    fn start(&self);
}

/// Best-effort UI notification seam. Failure never gates recovery.
pub trait UiNotify: Send + Sync {
    fn notify(&self, message: &str) -> Result<(), String>;
}

/// Best-effort config-save seam. Failure never gates recovery.
pub trait PersistCfg: Send + Sync {
    fn save(&self) -> Result<(), String>;
}

/// Tuning for [`Lifecycle`].
#[derive(Debug, Clone, Copy)]
pub struct LifecycleConfig {
    /// Bound for the detached engine-stop join.
    pub engine_stop_bound: Duration,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            engine_stop_bound: DEFAULT_ENGINE_STOP_BOUND,
        }
    }
}

struct QueuedOp {
    id: u64,
    epoch: u64,
    choice: Choice,
    local: bool,
}

#[derive(Debug, Clone)]
enum Slot {
    Idle,
    Active,
    Done(ShutdownReport),
}

struct State {
    open: bool,
    epoch: u64,
    queue: VecDeque<QueuedOp>,
    next_id: u64,
    running: usize,
    off: Slot,
    quit: Slot,
}

/// Admission queue with barriers and engine-independent teardown.
///
/// `&self` methods with interior mutability so UI callbacks, queued work and
/// concurrent shutdowns share one coordinator. All blocking waits release
/// the state lock; the DNS path never holds engine/TCP/config locks.
pub struct Lifecycle<D, E, U, P> {
    dns: D,
    engine: Arc<E>,
    ui: U,
    persist: P,
    config: LifecycleConfig,
    state: Mutex<State>,
    settle_cv: Condvar,
    done_cv: Condvar,
}

impl<D: DnsCtl + 'static, E: EngineCtl + 'static, U: UiNotify + 'static, P: PersistCfg + 'static>
    Lifecycle<D, E, U, P>
{
    pub fn new(dns: D, engine: E, ui: U, persist: P, config: LifecycleConfig) -> Self {
        Self {
            dns,
            engine: Arc::new(engine),
            ui,
            persist,
            config,
            state: Mutex::new(State {
                open: true,
                epoch: 0,
                queue: VecDeque::new(),
                next_id: 0,
                running: 0,
                off: Slot::Idle,
                quit: Slot::Idle,
            }),
            settle_cv: Condvar::new(),
            done_cv: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current admission state.
    pub fn snapshot(&self) -> Snapshot {
        let s = self.lock();
        Snapshot {
            admission_open: s.open,
            epoch: s.epoch,
            queued: s.queue.len(),
            running: s.running,
        }
    }

    /// Enqueue an enable under the current epoch. Refused when admission is
    /// closed or a process quit already completed. A successful request
    /// invalidates a stale completed DNS-off result so the next off is fresh.
    pub fn request_enable(&self, choice: Choice, local: bool) -> Result<Ticket, Refusal> {
        let mut s = self.lock();
        if matches!(s.quit, Slot::Done(_)) {
            return Err(Refusal {
                reason: "process quit completed; admission never reopens".into(),
            });
        }
        if !s.open {
            return Err(Refusal {
                reason: "admission closed".into(),
            });
        }
        let ticket = Ticket {
            id: s.next_id,
            epoch: s.epoch,
        };
        s.next_id += 1;
        s.queue.push_back(QueuedOp {
            id: ticket.id,
            epoch: ticket.epoch,
            choice,
            local,
        });
        // New work supersedes any completed off: the next off must run fresh.
        s.off = Slot::Idle;
        Ok(ticket)
    }

    /// Run the oldest queued enable. A ticket whose epoch no longer matches
    /// (quit/off closed admission after it was queued) is discarded without
    /// touching DNS. A success that completes after an epoch bump is stale:
    /// reported as discarded, never as fresh success, and it never starts
    /// the engine.
    pub fn run_queued(&self) -> RunOutcome {
        let op = {
            let mut s = self.lock();
            match s.queue.pop_front() {
                None => return RunOutcome::Empty,
                Some(op) => {
                    let quit_done = matches!(s.quit, Slot::Done(_));
                    if quit_done || !s.open || op.epoch != s.epoch {
                        return RunOutcome::StaleDiscarded { id: op.id };
                    }
                    s.running += 1;
                    op
                }
            }
        };
        let outcome = self.dns.enable(op.choice, op.local, op.epoch);
        let mut s = self.lock();
        s.running = s.running.saturating_sub(1);
        self.settle_cv.notify_all();
        if op.epoch != s.epoch {
            // Settled after the restore barrier moved on: discard the stale
            // success instead of treating it as a fresh enable.
            return RunOutcome::StaleDiscarded { id: op.id };
        }
        RunOutcome::Finished {
            id: op.id,
            outcome,
        }
    }

    /// Gate an engine start (or any late UI callback) on a still-current
    /// epoch. Stale callbacks are refused and never touch the engine.
    pub fn request_engine_start(&self, epoch: u64) -> Result<(), Refusal> {
        {
            let s = self.lock();
            if matches!(s.quit, Slot::Done(_)) {
                return Err(Refusal {
                    reason: "process quit completed; engine stays down".into(),
                });
            }
            if !s.open || epoch != s.epoch {
                return Err(Refusal {
                    reason: format!("stale epoch {epoch}; current {}", s.epoch),
                });
            }
        }
        self.engine.start();
        Ok(())
    }

    /// Idempotent shutdown. Concurrent same-kind callers join the in-flight
    /// (or completed) result; the DNS restore runs exactly once per fresh
    /// shutdown.
    pub fn shutdown(&self, kind: ShutdownKind) -> ShutdownReport {
        // Join or become the owner.
        {
            let mut s = self.lock();
            loop {
                let slot = match kind {
                    ShutdownKind::DnsOff => &mut s.off,
                    ShutdownKind::ProcessQuit => &mut s.quit,
                };
                match slot.clone() {
                    Slot::Done(report) => return report,
                    Slot::Active => {
                        s = self
                            .done_cv
                            .wait(s)
                            .unwrap_or_else(|e| e.into_inner());
                    }
                    Slot::Idle => {
                        *slot = Slot::Active;
                        break;
                    }
                }
            }
        }
        let report = self.run_shutdown(kind);
        let mut s = self.lock();
        let slot = match kind {
            ShutdownKind::DnsOff => &mut s.off,
            ShutdownKind::ProcessQuit => &mut s.quit,
        };
        *slot = Slot::Done(report.clone());
        self.done_cv.notify_all();
        report
    }

    /// The single owner runs the teardown phases. No state lock is held
    /// across DNS calls, the settle wait, or the engine join.
    fn run_shutdown(&self, kind: ShutdownKind) -> ShutdownReport {
        // 1. Close admission FIRST under the mutex: bump the epoch, reject
        //    new/queued work, cancel queued-but-unstarted enables.
        let (shutdown_epoch, cancelled_queued) = {
            let mut s = self.lock();
            s.open = false;
            s.epoch += 1;
            let cancelled = s.queue.drain(..).count();
            (s.epoch, cancelled)
        };
        // 2. Quiesce immediately — strictly before the engine stop is kicked.
        self.dns.quiesce();

        // 3. Engine stop on its own detached thread: a hang or panic here
        //    can neither block nor break the DNS path below.
        let engine = Arc::clone(&self.engine);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| engine.stop()));
            let _ = tx.send(outcome);
        });

        // 4. Settle in-flight DNS work, then restore behind it.
        {
            let mut s = self.lock();
            while s.running > 0 {
                s = self
                    .settle_cv
                    .wait(s)
                    .unwrap_or_else(|e| e.into_inner());
            }
        }
        let restore = self.dns.restore();
        let verified = restore == DnsOutcome::Verified && self.dns.verify();
        let dns = if verified {
            DnsOutcome::Verified
        } else if restore == DnsOutcome::Verified {
            DnsOutcome::Pending("post-restore verification mismatch".into())
        } else {
            restore
        };

        // 5. Verified: stop listeners only now. Pending/conflict: retain the
        //    listener and hand DNS authority off explicitly — never success.
        if dns.successful() {
            self.dns.stop_listeners();
        } else {
            self.dns.handoff();
        }

        // 6. Bounded engine join; the DNS result stands regardless.
        let engine_outcome = match rx.recv_timeout(self.config.engine_stop_bound) {
            Ok(Ok(())) => EngineOutcome::Completed,
            Ok(Err(payload)) => EngineOutcome::Panicked(panic_message(payload)),
            Err(_) => EngineOutcome::TimedOut,
        };

        // 7. Best-effort UI/persist: recorded, never gating.
        let summary = format!(
            "{kind:?} shutdown: {dns:?} (epoch {shutdown_epoch}); engine {engine_outcome:?}"
        );
        let ui_error = self.ui.notify(&summary).err();
        let persist_error = self.persist.save().err();

        // 8. DNS-off reopens only on a fresh clean epoch after verified
        //    restoration. A process quit never reopens.
        let mut s = self.lock();
        let reopened = kind == ShutdownKind::DnsOff && dns.successful();
        if reopened {
            s.epoch += 1;
            s.open = true;
        }
        ShutdownReport {
            kind,
            dns,
            engine: engine_outcome,
            epoch: s.epoch,
            reopened,
            cancelled_queued,
            ui_error,
            persist_error,
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send + 'static>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "engine stop panicked".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::DohProvider;
    use std::sync::mpsc;
    use std::sync::Mutex as StdMutex;

    // ---- shared world log: every fake records here in call order --------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum WorldEvent {
        Quiesce,
        EnableEnter(u64),
        EnableExit,
        Restore,
        Verify,
        StopListeners,
        Handoff,
        EngineStop,
        EngineStart,
        UiNotify,
        PersistSave,
    }

    type WorldLog = Arc<StdMutex<Vec<WorldEvent>>>;

    fn world_index(log: &WorldLog, want: &WorldEvent) -> Option<usize> {
        log.lock().unwrap().iter().position(|e| e == want)
    }

    // ---- fakes ----------------------------------------------------------

    struct FakeDns {
        world: WorldLog,
        restore_outcome: StdMutex<DnsOutcome>,
        verify_ok: StdMutex<bool>,
        enable_outcome: StdMutex<DnsOutcome>,
        enable_calls: StdMutex<usize>,
        restore_calls: StdMutex<usize>,
        // When set, `enable` blocks: signals `entered`, waits `release`.
        entered: StdMutex<Option<mpsc::Sender<()>>>,
        release: StdMutex<Option<mpsc::Receiver<()>>>,
        quiesced: StdMutex<Option<mpsc::Sender<()>>>,
    }

    impl FakeDns {
        fn new(world: WorldLog) -> Self {
            Self {
                world,
                restore_outcome: StdMutex::new(DnsOutcome::Verified),
                verify_ok: StdMutex::new(true),
                enable_outcome: StdMutex::new(DnsOutcome::Verified),
                enable_calls: StdMutex::new(0),
                restore_calls: StdMutex::new(0),
                entered: StdMutex::new(None),
                release: StdMutex::new(None),
                quiesced: StdMutex::new(None),
            }
        }

        fn push(&self, e: WorldEvent) {
            self.world.lock().unwrap().push(e);
        }

        fn with_blocking_enable(self, entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) -> Self {
            *self.entered.lock().unwrap() = Some(entered);
            *self.release.lock().unwrap() = Some(release);
            self
        }

        fn with_quiesce_hook(self, quiesced: mpsc::Sender<()>) -> Self {
            *self.quiesced.lock().unwrap() = Some(quiesced);
            self
        }
    }

    impl DnsCtl for FakeDns {
        fn quiesce(&self) {
            self.push(WorldEvent::Quiesce);
            if let Some(tx) = self.quiesced.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
        fn restore(&self) -> DnsOutcome {
            *self.restore_calls.lock().unwrap() += 1;
            self.push(WorldEvent::Restore);
            self.restore_outcome.lock().unwrap().clone()
        }
        fn verify(&self) -> bool {
            self.push(WorldEvent::Verify);
            *self.verify_ok.lock().unwrap()
        }
        fn stop_listeners(&self) {
            self.push(WorldEvent::StopListeners);
        }
        fn handoff(&self) {
            self.push(WorldEvent::Handoff);
        }
        fn enable(&self, _choice: Choice, _local: bool, epoch: u64) -> DnsOutcome {
            *self.enable_calls.lock().unwrap() += 1;
            self.push(WorldEvent::EnableEnter(epoch));
            if let Some(tx) = self.entered.lock().unwrap().take() {
                let _ = tx.send(());
            }
            if let Some(rx) = self.release.lock().unwrap().take() {
                let _ = rx.recv();
            }
            self.push(WorldEvent::EnableExit);
            self.enable_outcome.lock().unwrap().clone()
        }
    }

    enum EngineMode {
        Return,
        Hang(mpsc::Receiver<()>),
        Panic,
    }

    struct FakeEngine {
        world: WorldLog,
        mode: StdMutex<Option<EngineMode>>,
        stop_calls: StdMutex<usize>,
        start_calls: StdMutex<usize>,
    }

    impl FakeEngine {
        fn new(world: WorldLog, mode: EngineMode) -> Self {
            Self {
                world,
                mode: StdMutex::new(Some(mode)),
                stop_calls: StdMutex::new(0),
                start_calls: StdMutex::new(0),
            }
        }
    }

    impl EngineCtl for FakeEngine {
        fn stop(&self) {
            *self.stop_calls.lock().unwrap() += 1;
            self.world.lock().unwrap().push(WorldEvent::EngineStop);
            match self.mode.lock().unwrap().take() {
                Some(EngineMode::Return) | None => {}
                Some(EngineMode::Hang(rx)) => {
                    let _ = rx.recv();
                }
                Some(EngineMode::Panic) => panic!("scripted engine stop panic"),
            }
        }
        fn start(&self) {
            *self.start_calls.lock().unwrap() += 1;
            self.world.lock().unwrap().push(WorldEvent::EngineStart);
        }
    }

    struct FakeUi {
        world: WorldLog,
        fail: bool,
    }

    impl UiNotify for FakeUi {
        fn notify(&self, _message: &str) -> Result<(), String> {
            self.world.lock().unwrap().push(WorldEvent::UiNotify);
            if self.fail {
                return Err("scripted ui callback failure".into());
            }
            Ok(())
        }
    }

    struct FakePersist {
        world: WorldLog,
        fail: bool,
    }

    impl PersistCfg for FakePersist {
        fn save(&self) -> Result<(), String> {
            self.world.lock().unwrap().push(WorldEvent::PersistSave);
            if self.fail {
                return Err("scripted config-save failure".into());
            }
            Ok(())
        }
    }

    type Fixture = Lifecycle<FakeDns, FakeEngine, FakeUi, FakePersist>;

    fn fixture(world: &WorldLog, engine_mode: EngineMode) -> Fixture {
        Lifecycle::new(
            FakeDns::new(Arc::clone(world)),
            FakeEngine::new(Arc::clone(world), engine_mode),
            FakeUi {
                world: Arc::clone(world),
                fail: false,
            },
            FakePersist {
                world: Arc::clone(world),
                fail: false,
            },
            LifecycleConfig {
                engine_stop_bound: Duration::from_secs(10),
            },
        )
    }

    fn auto() -> (Choice, bool) {
        (Choice::Fixed(DohProvider::Cloudflare), true)
    }

    fn assert_ordered(log: &WorldLog, seq: &[WorldEvent]) {
        let events = log.lock().unwrap().clone();
        let mut from = 0;
        for want in seq {
            let pos = events[from..]
                .iter()
                .position(|e| e == want)
                .unwrap_or_else(|| panic!("{want:?} missing after index {from} in {events:?}"));
            from += pos + 1;
        }
    }

    // ---- U07 concrete test 1: idle trace ordering -----------------------

    #[test]
    fn idle_off_orders_quiesce_settle_restore_verify_listener_stop() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = fixture(&world, EngineMode::Return);

        let report = lc.shutdown(ShutdownKind::DnsOff);

        assert!(report.successful());
        assert!(report.reopened);
        // quiesce -> settle(implicit: nothing running) -> restore -> verify
        // -> listener-stop, with the engine stop kicked only after quiesce.
        assert_ordered(
            &world,
            &[
                WorldEvent::Quiesce,
                WorldEvent::Restore,
                WorldEvent::Verify,
                WorldEvent::StopListeners,
            ],
        );
        let quiesce = world_index(&world, &WorldEvent::Quiesce).unwrap();
        let engine_stop = world_index(&world, &WorldEvent::EngineStop).unwrap();
        assert!(quiesce < engine_stop, "quiesce must precede engine stop");
        assert_eq!(report.engine, EngineOutcome::Completed);
        assert_eq!(report.cancelled_queued, 0);
    }

    // ---- U07 concrete test 2: queued-before-quit never starts ------------

    #[test]
    fn enable_queued_before_quit_but_not_started_never_applies() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = fixture(&world, EngineMode::Return);
        let (choice, local) = auto();

        let ticket = lc.request_enable(choice, local).unwrap();
        assert_eq!(ticket.epoch, 0);
        let report = lc.shutdown(ShutdownKind::ProcessQuit);
        assert!(report.successful());
        assert_eq!(report.cancelled_queued, 1);

        // Admission closed first: the queued request was cancelled at close
        // (spec: cancel queued preparations), so there is nothing to run and
        // DNS was never touched.
        assert_eq!(lc.run_queued(), RunOutcome::Empty);
        assert_eq!(*lc.dns.enable_calls.lock().unwrap(), 0);
        assert!(lc.request_enable(choice, local).is_err());
        assert!(world.lock().unwrap().iter().all(|e| !matches!(
            e,
            WorldEvent::EnableEnter(_) | WorldEvent::EnableExit
        )));
    }

    // ---- U07 concrete test 3: capture running, setter running ------------

    #[test]
    fn inflight_enable_settles_before_restore_and_stale_success_starts_nothing() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (quiesced_tx, quiesced_rx) = mpsc::channel();
        let lc = Arc::new(Lifecycle::new(
            FakeDns::new(Arc::clone(&world))
                .with_blocking_enable(entered_tx, release_rx)
                .with_quiesce_hook(quiesced_tx),
            FakeEngine::new(Arc::clone(&world), EngineMode::Return),
            FakeUi {
                world: Arc::clone(&world),
                fail: false,
            },
            FakePersist {
                world: Arc::clone(&world),
                fail: false,
            },
            LifecycleConfig {
                engine_stop_bound: Duration::from_secs(10),
            },
        ));
        let (choice, local) = auto();
        let ticket = lc.request_enable(choice, local).unwrap();

        // The setter is running inside DNS when quit arrives.
        let worker = Arc::clone(&lc);
        let enable_thread = std::thread::spawn(move || worker.run_queued());
        entered_rx.recv().unwrap();
        let shutdown_lc = Arc::clone(&lc);
        let shutdown_thread =
            std::thread::spawn(move || shutdown_lc.shutdown(ShutdownKind::ProcessQuit));
        // Quiesce landed before the in-flight setter settles.
        quiesced_rx.recv().unwrap();
        assert!(world.lock().unwrap().contains(&WorldEvent::Quiesce));
        let _ = release_tx.send(());
        let run = enable_thread.join().unwrap();
        let report = shutdown_thread.join().unwrap();

        // The late success is stale: discarded, never a fresh enable.
        assert_eq!(run, RunOutcome::StaleDiscarded { id: ticket.id });
        // Settle (EnableExit) precedes restore; restore precedes verify and
        // the listener stop. No late apply lands after the restore barrier.
        assert_ordered(
            &world,
            &[
                WorldEvent::Quiesce,
                WorldEvent::EnableExit,
                WorldEvent::Restore,
                WorldEvent::Verify,
                WorldEvent::StopListeners,
            ],
        );
        assert!(report.successful());
        assert!(!report.reopened);
        // The stale success cannot start the engine: the old epoch is dead.
        assert!(lc.request_engine_start(ticket.epoch).is_err());
        assert_eq!(*lc.engine.start_calls.lock().unwrap(), 0);
    }

    // ---- U07 concrete test 4: callbacks queued after quit ----------------

    #[test]
    fn callback_queued_after_quit_is_refused_and_quit_never_reopens() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = fixture(&world, EngineMode::Return);
        let (choice, local) = auto();

        let first = lc.shutdown(ShutdownKind::ProcessQuit);
        assert!(first.successful());
        assert!(!first.reopened);

        // A process quit never reopens: later enables and engine starts fail.
        assert!(lc.request_enable(choice, local).is_err());
        assert!(lc.request_engine_start(first.epoch).is_err());
        assert!(lc.request_engine_start(first.epoch + 100).is_err());
        assert_eq!(lc.snapshot().epoch, first.epoch);

        // A repeated quit joins the same result; the restore ran once.
        let second = lc.shutdown(ShutdownKind::ProcessQuit);
        assert_eq!(first, second);
        assert_eq!(*lc.dns.restore_calls.lock().unwrap(), 1);
    }

    // ---- U07 concrete test 5: repeated shutdown joins one result ---------

    #[test]
    fn repeated_off_joins_same_result_with_single_restore() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = Arc::new(fixture(&world, EngineMode::Return));

        let gate = Arc::new(std::sync::Barrier::new(4));
        let mut threads = Vec::new();
        for _ in 0..3 {
            let (lc, gate) = (Arc::clone(&lc), Arc::clone(&gate));
            threads.push(std::thread::spawn(move || {
                gate.wait();
                lc.shutdown(ShutdownKind::DnsOff)
            }));
        }
        gate.wait();
        let reports: Vec<ShutdownReport> = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        assert_eq!(reports[0], reports[1]);
        assert_eq!(reports[1], reports[2]);
        assert!(reports[0].successful());
        assert_eq!(*lc.dns.restore_calls.lock().unwrap(), 1);
    }

    // ---- U07 concrete test 6: rapid off -> on ----------------------------

    #[test]
    fn rapid_off_then_on_uses_a_fresh_clean_epoch() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = fixture(&world, EngineMode::Return);
        let (choice, local) = auto();

        let off = lc.shutdown(ShutdownKind::DnsOff);
        assert!(off.successful());
        assert!(off.reopened);
        let snap = lc.snapshot();
        assert!(snap.admission_open);
        assert_eq!(snap.epoch, off.epoch);

        // DNS-off opened a fresh clean epoch: new work is accepted on it.
        let ticket = lc.request_enable(choice, local).unwrap();
        assert_eq!(ticket.epoch, snap.epoch);
        assert_ne!(ticket.epoch, 0);
        assert_eq!(
            lc.run_queued(),
            RunOutcome::Finished {
                id: ticket.id,
                outcome: DnsOutcome::Verified,
            }
        );
        assert_eq!(*lc.dns.enable_calls.lock().unwrap(), 1);
        // A stale callback on the pre-off epoch cannot start the engine.
        assert!(lc.request_engine_start(0).is_err());
        assert_eq!(*lc.engine.start_calls.lock().unwrap(), 0);
        // But the current epoch can.
        assert!(lc.request_engine_start(ticket.epoch).is_ok());
        assert_eq!(*lc.engine.start_calls.lock().unwrap(), 1);
    }

    // ---- U07 concrete test 7: engine hang --------------------------------

    #[test]
    fn engine_stop_hang_cannot_block_dns_restore_and_verify() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let (_hang_tx, hang_rx) = mpsc::channel::<()>();
        let lc = Lifecycle::new(
            FakeDns::new(Arc::clone(&world)),
            FakeEngine::new(Arc::clone(&world), EngineMode::Hang(hang_rx)),
            FakeUi {
                world: Arc::clone(&world),
                fail: true,
            },
            FakePersist {
                world: Arc::clone(&world),
                fail: true,
            },
            LifecycleConfig {
                engine_stop_bound: Duration::from_millis(200),
            },
        );

        let report = lc.shutdown(ShutdownKind::DnsOff);

        // DNS restore/verify still completed; the hang is reported, and the
        // UI/config-save failures did not gate recovery either.
        assert_eq!(report.dns, DnsOutcome::Verified);
        assert!(report.successful());
        assert!(report.reopened);
        assert_eq!(report.engine, EngineOutcome::TimedOut);
        assert!(report.ui_error.is_some());
        assert!(report.persist_error.is_some());
        assert_ordered(
            &world,
            &[
                WorldEvent::Quiesce,
                WorldEvent::Restore,
                WorldEvent::Verify,
                WorldEvent::StopListeners,
            ],
        );
    }

    // ---- U07 concrete test 8: engine panic -------------------------------

    #[test]
    fn engine_stop_panic_cannot_break_dns_restore_and_verify() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = Lifecycle::new(
            FakeDns::new(Arc::clone(&world)),
            FakeEngine::new(Arc::clone(&world), EngineMode::Panic),
            FakeUi {
                world: Arc::clone(&world),
                fail: false,
            },
            FakePersist {
                world: Arc::clone(&world),
                fail: false,
            },
            LifecycleConfig {
                engine_stop_bound: Duration::from_secs(10),
            },
        );

        let report = lc.shutdown(ShutdownKind::ProcessQuit);

        assert_eq!(report.dns, DnsOutcome::Verified);
        assert!(report.successful());
        assert!(matches!(report.engine, EngineOutcome::Panicked(_)));
        assert_ordered(
            &world,
            &[
                WorldEvent::Quiesce,
                WorldEvent::Restore,
                WorldEvent::Verify,
                WorldEvent::StopListeners,
            ],
        );
    }

    // ---- U07 concrete test 9: pending retains listener + handoff ---------

    #[test]
    fn pending_branch_retains_listener_with_handoff_and_never_succeeds() {
        for outcome in [
            DnsOutcome::Pending("adapter gone".into()),
            DnsOutcome::Conflict("foreign admin edit".into()),
        ] {
            let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
            let lc = Lifecycle::new(
                FakeDns {
                    restore_outcome: StdMutex::new(outcome.clone()),
                    ..FakeDns::new(Arc::clone(&world))
                },
                FakeEngine::new(Arc::clone(&world), EngineMode::Return),
                FakeUi {
                    world: Arc::clone(&world),
                    fail: false,
                },
                FakePersist {
                    world: Arc::clone(&world),
                    fail: false,
                },
                LifecycleConfig {
                    engine_stop_bound: Duration::from_secs(10),
                },
            );

            let report = lc.shutdown(ShutdownKind::DnsOff);

            assert!(!report.successful(), "pending must never read as success");
            assert!(!report.reopened);
            assert_eq!(report.dns, outcome);
            // The listener is retained (no stop) and handed off explicitly.
            let events = world.lock().unwrap().clone();
            assert!(events.contains(&WorldEvent::Handoff));
            assert!(!events.contains(&WorldEvent::StopListeners));
            // Admission stays closed: no fresh epoch, no new work.
            assert!(!lc.snapshot().admission_open);
            let (choice, local) = auto();
            assert!(lc.request_enable(choice, local).is_err());
            // A repeated off joins the same pending result; no second restore.
            let again = lc.shutdown(ShutdownKind::DnsOff);
            assert_eq!(report, again);
            assert_eq!(*lc.dns.restore_calls.lock().unwrap(), 1);
        }
    }

    // ---- U07 concrete test 10: verify mismatch is not success ------------

    #[test]
    fn restore_without_verify_match_is_pending_not_success() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = Lifecycle::new(
            FakeDns {
                verify_ok: StdMutex::new(false),
                ..FakeDns::new(Arc::clone(&world))
            },
            FakeEngine::new(Arc::clone(&world), EngineMode::Return),
            FakeUi {
                world: Arc::clone(&world),
                fail: false,
            },
            FakePersist {
                world: Arc::clone(&world),
                fail: false,
            },
            LifecycleConfig {
                engine_stop_bound: Duration::from_secs(10),
            },
        );

        let report = lc.shutdown(ShutdownKind::DnsOff);

        assert!(!report.successful());
        assert!(!report.reopened);
        assert!(matches!(report.dns, DnsOutcome::Pending(_)));
        let events = world.lock().unwrap().clone();
        assert!(events.contains(&WorldEvent::Handoff));
        assert!(!events.contains(&WorldEvent::StopListeners));
    }

    // ---- U07 concrete test 11: failing UI/persist still recover ---------

    #[test]
    fn ui_callback_and_config_save_failures_do_not_gate_recovery() {
        let world: WorldLog = Arc::new(StdMutex::new(Vec::new()));
        let lc = Lifecycle::new(
            FakeDns::new(Arc::clone(&world)),
            FakeEngine::new(Arc::clone(&world), EngineMode::Return),
            FakeUi {
                world: Arc::clone(&world),
                fail: true,
            },
            FakePersist {
                world: Arc::clone(&world),
                fail: true,
            },
            LifecycleConfig {
                engine_stop_bound: Duration::from_secs(10),
            },
        );

        let report = lc.shutdown(ShutdownKind::DnsOff);

        assert!(report.successful());
        assert!(report.reopened);
        assert!(report.ui_error.is_some());
        assert!(report.persist_error.is_some());
        assert_ordered(
            &world,
            &[
                WorldEvent::Restore,
                WorldEvent::Verify,
                WorldEvent::StopListeners,
            ],
        );
    }
}

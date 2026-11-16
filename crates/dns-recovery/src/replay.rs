//! U04: startup replay, owner identity, conflict handling and the deferred
//! scheduler (SPEC-DNS-FIX.md §12 U04, §5.3 retry schedule, §5.4
//! classification, §7 startup replay).
//!
//! Library-only, UI/service-independent: the driver touches only the journal
//! store (under the machine lock), the [`DnsBackend`] read path, the
//! [`DnsSetter`] write path and an [`OwnerProbe`]. It needs no user profile,
//! no network, no listener runtime and no UI. Actual DNS mutation always goes
//! through the U03 [`TransactionEngine`], so every durability rule carries
//! over: durable before/target intents, readback verification, whole-
//! transaction rollback to immutable originals, admission closure on
//! persistence failure, and no lifetime expiry of debt.
//!
//! Owner identity (§3.2 / §7 steps 2–3): liveness is PID + creation FILETIME +
//! a held process handle. A matching FILETIME with a nonsignaled handle is
//! live; a different FILETIME means the PID was reused and the recorded owner
//! is dead; a missing PID (or a signaled matching handle) proves death. Image
//! fields are authentication/diagnostics only, never death evidence. Access
//! denied or any other query failure is UNKNOWN — never a license to write.
//! The decision is machine-wide: a live owner in another session still blocks
//! replay ("leave untouched").
//!
//! Replay decisions (§7):
//! - no journal candidates → nothing to recover ([`Outcome::VerifiedRestored`]);
//! - clean tombstone → best-effort obsolete cleanup, no DNS writes;
//! - live owner → [`Outcome::Busy`], journal and DNS left untouched;
//! - unknown owner → [`Outcome::Refused`], journal retained, zero writes
//!   pending a privileged recheck;
//! - dead owner → adopt the recorded owner's authority for a *restoration*
//!   pass only (the process is dead, so no competing writer exists) and run
//!   the engine's restore state machine to classification, exact-original
//!   restore, conflict retention or the durable clean tombstone.
//!
//! A dead owner is proven dead, so acting under the recorded transaction to
//! restore immutable originals cannot collide with a live writer: the global
//! lock serializes machine writers, and any live owner takes the Busy path
//! before any mutation. Replay NEVER performs the old heuristic
//! public-provider reset: every setter call it (transitively) issues targets
//! a journaled immutable original. Foreign current images become conflicts
//! with no write; unrelated context (domain/suffix/registration/profile)
//! never blocks a DNS restore.
//!
//! Deferred scheduler (§5.3): [`ReplayDriver::background_wake`] runs one due
//! pass (at most three entries, one attempt each, persisted counts and
//! next-attempt times from [`background_delay_ms`]); [`next_wake_ms`]
//! reports the earliest persisted next-attempt time so a host can sleep until
//! then; [`notify_arrival`] re-drives Failed/Deferred entries (and fresh
//! reads for Conflict entries) for the arrived GUIDs without waiting for the
//! schedule. Missing GUIDs stay debt; a new GUID that reuses a name/index
//! never inherits old settings (identity is GUID only); nothing is ever aged
//! out.

use std::cell::RefCell;
use std::collections::HashSet;

use crate::backend::DnsBackend;
use crate::clock::Clock;
use crate::fs::JournalFs;
use crate::journal::{self, EntryState, JournalState, OwnerIdentity, Phase};
use crate::lock::{LockError, MachineLock, LOCK_BUDGET};
use crate::setter::DnsSetter;
use crate::store::{JournalStore, ValidCandidate};
use crate::transaction::{EngineError, EngineReport, FamilyError, Outcome, TransactionEngine};

// ---- owner identity --------------------------------------------------------

/// Owner liveness from the recorded PID + creation FILETIME (§7 steps 2–3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerLiveness {
    /// Matching FILETIME and a nonsignaled held handle: another launch owns
    /// the machine lease. Replay must leave journal and DNS untouched.
    Live,
    /// Different FILETIME (PID reuse), missing PID, or signaled matching
    /// handle: the recorded owner is dead and replay may restore.
    Dead,
    /// Access denied or any other query failure: neither live nor dead is
    /// proven. The journal is retained and NO write happens pending a
    /// privileged recheck.
    Unknown(String),
}

/// Process-identity probe. The Windows implementation (U05 service) opens the
/// recorded PID with SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION, compares
/// GetProcessTimes creation time and polls WaitForSingleObject(handle, 0).
/// Image path/hash fields are never consulted for liveness.
pub trait OwnerProbe {
    fn check(&self, owner: &OwnerIdentity) -> OwnerLiveness;
}

/// In-memory owner probe for tests. Models the machine process table as a set
/// of live (pid, creation FILETIME) pairs plus per-PID fault flags. Never
/// touches a real process.
#[derive(Clone, Debug, Default)]
pub struct FakeOwnerProbe {
    live: RefCell<HashSet<(u32, u64)>>,
    denied: RefCell<HashSet<u32>>,
    failing: RefCell<HashSet<u32>>,
}

impl FakeOwnerProbe {
    pub fn new() -> Self {
        Self::default()
    }
    /// A process is alive with this PID and creation FILETIME.
    pub fn spawn(&self, pid: u32, creation_time_filetime: u64) {
        self.live.borrow_mut().insert((pid, creation_time_filetime));
    }
    /// The PID is gone (or was never alive): missing PIDs prove death.
    pub fn kill(&self, pid: u32) {
        self.live.borrow_mut().retain(|(p, _)| *p != pid);
        self.denied.borrow_mut().remove(&pid);
        self.failing.borrow_mut().remove(&pid);
    }
    /// OpenProcess would return access denied for this PID (unknown, not dead).
    pub fn set_access_denied(&self, pid: u32, denied: bool) {
        if denied {
            self.denied.borrow_mut().insert(pid);
        } else {
            self.denied.borrow_mut().remove(&pid);
        }
    }
    /// GetProcessTimes / handle polling fails for this PID (unknown, not dead).
    pub fn set_query_failure(&self, pid: u32, fail: bool) {
        if fail {
            self.failing.borrow_mut().insert(pid);
        } else {
            self.failing.borrow_mut().remove(&pid);
        }
    }
}

impl OwnerProbe for FakeOwnerProbe {
    fn check(&self, owner: &OwnerIdentity) -> OwnerLiveness {
        if self.denied.borrow().contains(&owner.pid) {
            return OwnerLiveness::Unknown(format!("access denied opening pid {}", owner.pid));
        }
        if self.failing.borrow().contains(&owner.pid) {
            return OwnerLiveness::Unknown(format!("owner query failed for pid {}", owner.pid));
        }
        if self.live.borrow().contains(&(owner.pid, owner.creation_time_filetime)) {
            OwnerLiveness::Live
        } else {
            // Missing PID, PID reuse under a different FILETIME, or a PID that
            // was never alive: the recorded owner is dead.
            OwnerLiveness::Dead
        }
    }
}

// ---- replay report / driver ------------------------------------------------

/// One replay/scheduler pass result. `liveness` is None when the journal
/// holds no transaction (nothing to decide about).
#[derive(Clone, Debug)]
pub struct ReplayReport {
    pub outcome: Outcome,
    pub liveness: Option<OwnerLiveness>,
    pub errors: Vec<FamilyError>,
    pub generation: u64,
    pub note: String,
}

impl ReplayReport {
    fn busy(generation: u64, note: String) -> Self {
        Self { outcome: Outcome::Busy, liveness: Some(OwnerLiveness::Live), errors: Vec::new(), generation, note }
    }
    fn refused(generation: u64, liveness: Option<OwnerLiveness>, note: String) -> Self {
        Self { outcome: Outcome::Refused, liveness, errors: Vec::new(), generation, note }
    }
    fn from_engine(rep: EngineReport, liveness: OwnerLiveness, note: String) -> Self {
        Self {
            outcome: rep.outcome,
            liveness: Some(liveness),
            errors: rep.errors,
            generation: rep.generation,
            note,
        }
    }
}

/// UI/service-independent replay driver. Factories (not shared references) let
/// every pass build a fresh [`TransactionEngine`] incarnation — the model for
/// process restart — over the same durable journal and fake/real OS state.
pub struct ReplayDriver<F: JournalFs> {
    backend_factory: Box<dyn Fn() -> Box<dyn DnsBackend>>,
    setter_factory: Box<dyn Fn() -> Box<dyn DnsSetter>>,
    lock_factory: Box<dyn Fn() -> Box<dyn MachineLock>>,
    clock_factory: Box<dyn Fn() -> Box<dyn Clock>>,
    fs_factory: Box<dyn Fn() -> F>,
    dir: String,
    machine_id: String,
    service_instance_id: String,
    probe: Box<dyn OwnerProbe>,
}

impl<F: JournalFs> ReplayDriver<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend_factory: Box<dyn Fn() -> Box<dyn DnsBackend>>,
        setter_factory: Box<dyn Fn() -> Box<dyn DnsSetter>>,
        lock_factory: Box<dyn Fn() -> Box<dyn MachineLock>>,
        clock_factory: Box<dyn Fn() -> Box<dyn Clock>>,
        fs_factory: Box<dyn Fn() -> F>,
        dir: String,
        machine_id: String,
        service_instance_id: String,
        probe: Box<dyn OwnerProbe>,
    ) -> Self {
        Self {
            backend_factory,
            setter_factory,
            lock_factory,
            clock_factory,
            fs_factory,
            dir,
            machine_id,
            service_instance_id,
            probe,
        }
    }

    fn open_store(&self) -> Result<JournalStore<F>, EngineError> {
        JournalStore::open((self.fs_factory)(), &self.dir).map_err(EngineError::Store)
    }

    fn engine_for(&self, owner: &OwnerIdentity) -> Result<TransactionEngine<F>, EngineError> {
        Ok(TransactionEngine::new(
            (self.backend_factory)(),
            (self.setter_factory)(),
            self.open_store()?,
            (self.lock_factory)(),
            (self.clock_factory)(),
            self.machine_id.clone(),
            owner.clone(),
            self.service_instance_id.clone(),
        ))
    }

    /// Lock, reconcile and return the authoritative candidate. Lock contention
    /// is Busy; reconciliation failures (integrity, unknown version, unsafe
    /// storage) are reported as Refused — never deleted, never overwritten,
    /// never written through.
    fn locked_current(&self) -> Result<Result<Option<ValidCandidate>, String>, EngineError> {
        let lock = (self.lock_factory)();
        let guard = match lock.acquire(LOCK_BUDGET) {
            Ok((g, _)) => g,
            Err(LockError::Timeout) => {
                return Ok(Err("machine lock held by another writer".to_string()));
            }
            Err(e) => return Err(EngineError::Lock(e)),
        };
        let result = match self.open_store() {
            Ok(store) => match store.reconcile() {
                Ok(rec) => {
                    // §3.3 deletes obsolete candidates under the lock: a clean
                    // tombstone's post-barrier cleanup runs while the guard is
                    // still held (best-effort, errors stay for the next pass).
                    if let Some(winner) = &rec.current {
                        if winner.env.payload.transaction.is_none()
                            && winner.env.payload.journal_state == JournalState::Clean
                            && winner.env.is_clean_tombstone()
                        {
                            let _ = store.cleanup_obsolete(&winner.env);
                        }
                    }
                    Ok(rec.current)
                }
                Err(e) => Err(format!("journal reconciliation blocks replay: {e}")),
            },
            Err(e) => Err(format!("journal unavailable: {e}")),
        };
        drop(guard);
        Ok(result)
    }

    /// Full startup replay (§7): reconcile, classify the owner, and — only
    /// for a proven-dead owner — restore exact originals through the engine.
    /// Live and unknown owners cause zero journal and zero DNS writes.
    pub fn replay(&self) -> Result<ReplayReport, EngineError> {
        match self.locked_current()? {
            Err(busy_or_refused) => {
                // Lock contention (Busy) vs reconciliation failure (Refused)
                // is distinguished by the message channel below; lock
                // contention reports Busy with no liveness decision.
                if busy_or_refused == "machine lock held by another writer" {
                    return Ok(ReplayReport {
                        outcome: Outcome::Busy,
                        liveness: None,
                        errors: Vec::new(),
                        generation: 0,
                        note: busy_or_refused,
                    });
                }
                return Ok(ReplayReport::refused(0, None, busy_or_refused));
            }
            Ok(None) => {
                return Ok(ReplayReport {
                    outcome: Outcome::VerifiedRestored,
                    liveness: None,
                    errors: Vec::new(),
                    generation: 0,
                    note: "no journal candidates: nothing to recover".to_string(),
                });
            }
            Ok(Some(winner)) => {
                let generation = winner.env.generation;
                let Some(tx) = winner.env.payload.transaction.clone() else {
                    // Clean tombstone: obsolete cleanup already ran under the
                    // machine lock in locked_current; no DNS writes here.
                    return Ok(ReplayReport {
                        outcome: Outcome::VerifiedRestored,
                        liveness: None,
                        errors: Vec::new(),
                        generation,
                        note: "clean journal: no recovery debt".to_string(),
                    });
                };
                match self.probe.check(&tx.owner) {
                    OwnerLiveness::Live => Ok(ReplayReport::busy(
                        generation,
                        format!(
                            "live owner pid {} (session {}): journal and DNS left untouched",
                            tx.owner.pid, tx.owner.session_id
                        ),
                    )),
                    OwnerLiveness::Unknown(detail) => Ok(ReplayReport::refused(
                        generation,
                        Some(OwnerLiveness::Unknown(detail.clone())),
                        format!("owner liveness unknown ({detail}): journal retained, no writes"),
                    )),
                    OwnerLiveness::Dead => {
                        // Proven dead: the recorded owner cannot race us. Run
                        // the restoration under its transaction authority; the
                        // engine re-acquires the lock, closes admission, bumps
                        // the epoch and classifies every entry.
                        let rep = self.engine_for(&tx.owner)?.restore()?;
                        let note = match rep.outcome {
                            Outcome::VerifiedRestored => {
                                "dead owner: all originals verified, clean tombstone".to_string()
                            }
                            Outcome::Pending => {
                                "dead owner: restored what is configurable, debt retained".to_string()
                            }
                            Outcome::Conflict => {
                                "dead owner: foreign images preserved as conflicts, owned families restored"
                                    .to_string()
                            }
                            _ => "dead owner: restore pass settled".to_string(),
                        };
                        Ok(ReplayReport::from_engine(rep, OwnerLiveness::Dead, note))
                    }
                }
            }
        }
    }

    /// One scheduled background pass (§5.3): only Failed/Deferred entries
    /// whose persisted next-attempt time is due get one attempt each (at most
    /// three per pass). Live/unknown owners and clean journals behave as in
    /// [`replay`](Self::replay); debt is never expired.
    pub fn background_wake(&self) -> Result<ReplayReport, EngineError> {
        let current = match self.locked_current()? {
            Err(msg) => {
                if msg == "machine lock held by another writer" {
                    return Ok(ReplayReport {
                        outcome: Outcome::Busy,
                        liveness: None,
                        errors: Vec::new(),
                        generation: 0,
                        note: msg,
                    });
                }
                return Ok(ReplayReport::refused(0, None, msg));
            }
            Ok(c) => c,
        };
        let Some(winner) = current else {
            return Ok(ReplayReport {
                outcome: Outcome::VerifiedRestored,
                liveness: None,
                errors: Vec::new(),
                generation: 0,
                note: "no journal candidates: nothing to recover".to_string(),
            });
        };
        let generation = winner.env.generation;
        let Some(tx) = winner.env.payload.transaction.clone() else {
            return Ok(ReplayReport {
                outcome: Outcome::VerifiedRestored,
                liveness: None,
                errors: Vec::new(),
                generation,
                note: "clean journal: no recovery debt".to_string(),
            });
        };
        match self.probe.check(&tx.owner) {
            OwnerLiveness::Live => Ok(ReplayReport::busy(
                generation,
                format!("live owner pid {}: background pass skipped", tx.owner.pid),
            )),
            OwnerLiveness::Unknown(detail) => Ok(ReplayReport::refused(
                generation,
                Some(OwnerLiveness::Unknown(detail.clone())),
                format!("owner liveness unknown ({detail}): journal retained, no writes"),
            )),
            OwnerLiveness::Dead => {
                let rep = self.engine_for(&tx.owner)?.run_background_pass()?;
                Ok(ReplayReport::from_engine(rep, OwnerLiveness::Dead, "background wake settled".to_string()))
            }
        }
    }

    /// Adapter-arrival trigger (§7 step 5 / §5.3): retry Failed/Deferred
    /// entries — and take fresh reads for Conflict entries — for exactly the
    /// arrived GUIDs, without waiting for the persisted schedule. GUIDs with
    /// no journal entry are ignored: a new GUID reusing a name/index never
    /// inherits old settings. At most three entries per pass; the rest stays
    /// debt for the next wake.
    pub fn notify_arrival(&self, arrived: &[String]) -> Result<ReplayReport, EngineError> {
        let current = match self.locked_current()? {
            Err(msg) => {
                if msg == "machine lock held by another writer" {
                    return Ok(ReplayReport {
                        outcome: Outcome::Busy,
                        liveness: None,
                        errors: Vec::new(),
                        generation: 0,
                        note: msg,
                    });
                }
                return Ok(ReplayReport::refused(0, None, msg));
            }
            Ok(c) => c,
        };
        let Some(winner) = current else {
            return Ok(ReplayReport {
                outcome: Outcome::VerifiedRestored,
                liveness: None,
                errors: Vec::new(),
                generation: 0,
                note: "no journal candidates: arrival needs no recovery".to_string(),
            });
        };
        let generation = winner.env.generation;
        let Some(tx) = winner.env.payload.transaction.clone() else {
            return Ok(ReplayReport {
                outcome: Outcome::VerifiedRestored,
                liveness: None,
                errors: Vec::new(),
                generation,
                note: "clean journal: arrival needs no recovery".to_string(),
            });
        };
        match self.probe.check(&tx.owner) {
            OwnerLiveness::Live => Ok(ReplayReport::busy(
                generation,
                format!("live owner pid {}: arrival ignored", tx.owner.pid),
            )),
            OwnerLiveness::Unknown(detail) => Ok(ReplayReport::refused(
                generation,
                Some(OwnerLiveness::Unknown(detail.clone())),
                format!("owner liveness unknown ({detail}): journal retained, no writes"),
            )),
            OwnerLiveness::Dead => {
                let rep = self.engine_for(&tx.owner)?.run_arrival_pass(arrived)?;
                Ok(ReplayReport::from_engine(
                    rep,
                    OwnerLiveness::Dead,
                    format!("arrival pass settled for {} guid(s)", arrived.len()),
                ))
            }
        }
    }

    /// Scheduler hint (§5.3): the earliest persisted next-attempt time (ms
    /// since epoch) over Failed/Deferred entries, or None when no entry is
    /// waiting. Best-effort and read-only: store failures yield None rather
    /// than a wake storm. Conflict entries carry no schedule (they get fresh
    /// reads on arrival or admin request, never repeated overwrites).
    pub fn next_wake_ms(&self) -> Option<i64> {
        let store = self.open_store().ok()?;
        let rec = store.reconcile().ok()?;
        let tx = rec.current?.env.payload.transaction?;
        let mut next: Option<i64> = None;
        for e in &tx.entries {
            if !matches!(e.state, EntryState::Failed | EntryState::Deferred) {
                continue;
            }
            let Some(at) = &e.retry.next_attempt_utc else { continue };
            let Some(secs) = journal::parse_utc(at) else { continue };
            let ms = secs.saturating_mul(1000);
            next = Some(next.map_or(ms, |n: i64| n.min(ms)));
        }
        next
    }

    /// Current journal phase for diagnostics (read-only; None when clean).
    pub fn journal_phase(&self) -> Option<Phase> {
        let store = self.open_store().ok()?;
        let rec = store.reconcile().ok()?;
        rec.current?.env.payload.transaction.map(|tx| tx.phase)
    }
}

//! U05: privileged-service host core (SPEC-DNS-FIX.md §8, §12 U05).
//!
//! Portable state machine over the U01–U04 surfaces. The host is a THIN
//! layer: every DNS mutation goes through the U03 [`TransactionEngine`]
//! (durable intent → setter → readback), every startup/scheduled pass
//! through the U04 [`ReplayDriver`], every journal write through the U02
//! [`JournalStore`] barrier. There is no second journal, no direct setter
//! use and no GUI fallback writer here.
//!
//! Transport specifics (named-pipe server, impersonation, SCM dispatcher)
//! live in `service_os` (Windows only). This module owns:
//! - owner leases: PID + creation-FILETIME identity bound at registration to
//!   the transport-authenticated process, with a random 256-bit in-memory
//!   lease token (never persisted, never logged) and a journal-mirrored
//!   epoch. Registration holds the process identity before replying (T0).
//! - health/watchdog: GUI health every 2 s; three missed reports (6 s) or an
//!   explicitly non-responding listener closes the epoch and restores, even
//!   when the process is still alive. A responding listener that answers
//!   SERVFAIL still counts as alive — SERVFAIL is not listener death.
//! - request-ID dedup: duplicate mutating request IDs replay the stored
//!   reply and never repeat the mutation.
//! - SCM control machine: STOP/SHUTDOWN/PRESHUTDOWN quiesce, settle and
//!   restore with retained debt and a nonzero service-specific result when
//!   recovery is incomplete. The control path never waits on GUI responses.
//! - offline guard: the elevated offline helper path refuses unless the SCM
//!   service is proven STOPPED (running/start-pending/unknown refuse).
//! - background scheduling: due passes and adapter-arrival triggers delegate
//!   to the U04 driver; debt is never expired.
//!
//! The host is single-threaded by construction: all entry points take
//! `&mut self`, so the transport's serial worker is the one mutation
//! authority. Lock discipline from U02/U03 carries over unchanged (global
//! lock held across reload/intent/mutation/readback, released across retry
//! delays; never held while waiting on GUI/pipe responses).

use crate::clock::Clock;
use crate::codec;
use crate::fs::{join, JournalFs};
use crate::journal::{
    self, Admission, JournalState, Maintenance, OwnerIdentity, Phase, MAINTENANCE_LEASE_SECS,
};
use crate::lock::MachineLock;
use crate::protocol::{
    self, DedupCache, Operation, PeerAuth, Reply, Request,
};
use crate::replay::{OwnerLiveness, OwnerProbe, ReplayDriver, ReplayReport};
use crate::setter::DnsSetter;
use crate::store::{JournalStore, StoreError};
use crate::transaction::{EngineError, EngineReport, Outcome, TransactionEngine};
use crate::backend::DnsBackend;
use std::collections::HashMap;
use std::rc::Rc;

// ---- configuration ------------------------------------------------------------

/// Health cadence (§6): GUI sends readiness/health every 2 s.
pub const HEALTH_INTERVAL_MS: i64 = 2_000;
/// Three missed health reports trigger quiesce + restore.
pub const MISSED_HEALTH_LIMIT: u32 = 3;
/// Watchdog restoration target: begin restoration within 1 s of proven
/// owner death under normal scheduling (§8.3, first concrete test).
pub const RESTORE_START_TARGET_MS: i64 = 1_000;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub dir: String,
    pub machine_id: String,
    pub service_instance_id: String,
}

// ---- leases -------------------------------------------------------------------

/// One authenticated owner lease. The token is 256-bit random hex held only
/// in memory; the Debug impl redacts it so leases can never leak into logs.
pub struct Lease {
    pub owner: OwnerIdentity,
    pub token: String,
    pub last_health_ms: i64,
    pub readiness_generation: u64,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("owner", &self.owner)
            .field("token", &"<redacted>")
            .field("last_health_ms", &self.last_health_ms)
            .field("readiness_generation", &self.readiness_generation)
            .finish()
    }
}

fn fresh_token() -> String {
    // Two v4 UUIDs = 256 bits of OS-seeded entropy, brace-free hex.
    let a: String = journal::new_uuid().chars().filter(|c| *c != '-').collect();
    let b: String = journal::new_uuid().chars().filter(|c| *c != '-').collect();
    format!("{a}{b}")
}

// ---- SCM control ---------------------------------------------------------------

/// Host-side SCM control state. The Windows dispatcher maps
/// STOP/SHUTDOWN/PRESHUTDOWN onto [`ServiceHost::prepare_stop`]; the state
/// machine records the outcome so the dispatcher can report checkpoints,
/// wait hints and a nonzero service-specific exit when debt remains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlState {
    Running,
    StopPending,
    Stopped,
}

/// SCM service state as observed by the offline helper (via SCM query).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScmServiceState {
    Unknown,
    Stopped,
    StartPending,
    Running,
    StopPending,
}

// ---- host -----------------------------------------------------------------------

type BackendFactory = Rc<dyn Fn() -> Box<dyn DnsBackend>>;
type SetterFactory = Rc<dyn Fn() -> Box<dyn DnsSetter>>;
type LockFactory = Rc<dyn Fn() -> Box<dyn MachineLock>>;
type ClockFactory = Rc<dyn Fn() -> Box<dyn Clock>>;
type ProbeFactory = Rc<dyn Fn() -> Box<dyn OwnerProbe>>;
type FsFactory<F> = Rc<dyn Fn() -> F>;

/// The privileged-service host. Generic over the journal filesystem so the
/// full state machine — including the synthetic-owner harness — runs
/// against fakes without touching real adapters or the SCM.
///
/// Dedup discipline: mutating replies are memoized in the bounded in-memory
/// table AND in a durable overflow file (`dedup-v1.json` in the service
/// directory, up to [`protocol::MAX_PERSISTED_DEDUP_ENTRIES`] entries). A
/// replayed request id is answered from the stored reply even after the
/// in-memory eviction, and a hit only counts when the stored reply's journal
/// generation matches the current generation (results are retained for the
/// transaction lifetime, never across it).
pub struct ServiceHost<F: JournalFs> {
    backend_factory: BackendFactory,
    setter_factory: SetterFactory,
    lock_factory: LockFactory,
    clock: Box<dyn Clock>,
    clock_factory: ClockFactory,
    fs_factory: FsFactory<F>,
    probe_factory: ProbeFactory,
    config: ServiceConfig,
    leases: HashMap<String, Lease>,
    dedup: DedupCache,
    /// Durable overflow: request id → stored reply, oldest-first order.
    durable_dedup: HashMap<String, Reply>,
    durable_order: std::collections::VecDeque<String>,
    durable_loaded: bool,
    control: ControlState,
    hook: Rc<dyn Fn(crate::transaction::DeathPoint)>,
}

impl<F: JournalFs + 'static> ServiceHost<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend_factory: BackendFactory,
        setter_factory: SetterFactory,
        lock_factory: LockFactory,
        clock: Box<dyn Clock>,
        clock_factory: ClockFactory,
        fs_factory: FsFactory<F>,
        probe_factory: ProbeFactory,
        config: ServiceConfig,
    ) -> Self {
        Self {
            backend_factory,
            setter_factory,
            lock_factory,
            clock,
            clock_factory,
            fs_factory,
            probe_factory,
            config,
            leases: HashMap::new(),
            dedup: DedupCache::new(),
            durable_dedup: HashMap::new(),
            durable_order: std::collections::VecDeque::new(),
            durable_loaded: false,
            control: ControlState::Running,
            hook: Rc::new(|_| {}),
        }
    }

    /// Death-injection hook for the synthetic harness (latency measurement).
    pub fn set_hook(&mut self, hook: Rc<dyn Fn(crate::transaction::DeathPoint)>) {
        self.hook = hook;
    }

    /// Override the in-memory dedup bound (tests force eviction with a small
    /// table; production uses [`protocol::MAX_DEDUP_ENTRIES`]). The durable
    /// overflow and the generation-checked replay are identical either way.
    pub fn with_dedup_cap(mut self, cap: usize) -> Self {
        self.dedup.set_cap(cap);
        self
    }

    pub fn control_state(&self) -> ControlState {
        self.control
    }

    /// Live leases for the transport's held-handle bookkeeping:
    /// (owner_id, pid). The Windows transport releases process handles whose
    /// leases are gone.
    pub fn live_owner_ids(&self) -> Vec<(String, u32)> {
        self.leases
            .iter()
            .map(|(id, l)| (id.clone(), l.owner.pid))
            .collect()
    }

    pub fn lease_count(&self) -> usize {
        self.leases.len()
    }

    pub fn dedup_len(&self) -> usize {
        self.dedup.len()
    }

    // ---- durable dedup ----------------------------------------------------------

    fn dedup_path(&self) -> String {
        join(&self.config.dir, protocol::DEDUP_FILE)
    }

    /// Best-effort load of the durable overflow (once per host incarnation).
    /// A missing or corrupt file means an empty overflow — never a failure.
    fn dedup_ensure_loaded(&mut self) {
        if self.durable_loaded {
            return;
        }
        self.durable_loaded = true;
        let path = self.dedup_path();
        let fs = (self.fs_factory)();
        let bytes = match fs.read_file(&path) {
            Ok(b) => b,
            Err(_) => return,
        };
        #[derive(serde::Deserialize)]
        struct DedupFile {
            #[serde(default)]
            entries: Vec<(String, Reply)>,
        }
        let file: DedupFile = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(_) => return,
        };
        for (id, reply) in file.entries {
            if journal::is_lower_uuid(&id) && !self.durable_dedup.contains_key(&id) {
                self.durable_order.push_back(id.clone());
                self.durable_dedup.insert(id, reply);
                while self.durable_dedup.len() > protocol::MAX_PERSISTED_DEDUP_ENTRIES {
                    match self.durable_order.pop_front() {
                        Some(old) => {
                            self.durable_dedup.remove(&old);
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// Best-effort persist of the durable overflow. Failures are ignored:
    /// the in-memory table still answers, and the next store retries.
    fn dedup_persist(&self) {
        let entries: Vec<(String, Reply)> = self
            .durable_order
            .iter()
            .filter_map(|k| self.durable_dedup.get(k).map(|r| (k.clone(), r.clone())))
            .collect();
        let bytes = match serde_json::to_vec(&serde_json::json!({"v": 1u32, "entries": entries})) {
            Ok(b) => b,
            Err(_) => return,
        };
        let fs = (self.fs_factory)();
        let path = self.dedup_path();
        let _ = fs.delete(&path);
        let h = match fs.create_new(&path) {
            Ok(h) => h,
            Err(_) => return,
        };
        let _ = fs.write_all(h, &bytes).and(fs.flush_file(h));
        let _ = fs.close(h);
    }

    /// Idempotency lookup: a stored reply is replayed only when its journal
    /// generation matches the current generation (results live for the
    /// transaction lifetime). The durable overflow keeps replayed ids
    /// answerable after the 512-entry in-memory eviction; a hit there is
    /// promoted back into memory.
    fn dedup_lookup(&mut self, request_id: &str) -> Option<Reply> {
        let generation = self.journal_generation();
        if let Some(stored) = self.dedup.lookup(request_id) {
            if stored.generation == generation {
                return Some(stored.clone());
            }
        }
        self.dedup_ensure_loaded();
        if let Some(stored) = self.durable_dedup.get(request_id).cloned() {
            if stored.generation == generation {
                self.dedup.store(request_id.to_string(), stored.clone());
                return Some(stored);
            }
        }
        None
    }

    fn dedup_store(&mut self, request_id: String, reply: Reply) {
        self.dedup.store(request_id.clone(), reply.clone());
        if !self.durable_dedup.contains_key(&request_id) {
            self.durable_order.push_back(request_id.clone());
            self.durable_dedup.insert(request_id, reply);
            while self.durable_dedup.len() > protocol::MAX_PERSISTED_DEDUP_ENTRIES {
                match self.durable_order.pop_front() {
                    Some(old) => {
                        self.durable_dedup.remove(&old);
                    }
                    None => break,
                }
            }
        }
        self.dedup_persist();
    }

    fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    fn open_store(&self) -> Result<JournalStore<F>, StoreError> {
        JournalStore::open((self.fs_factory)(), &self.config.dir)
    }

    fn engine_for(&self, owner: &OwnerIdentity) -> Result<TransactionEngine<F>, EngineError> {
        let store = self.open_store().map_err(EngineError::Store)?;
        Ok(TransactionEngine::new(
            (self.backend_factory)(),
            (self.setter_factory)(),
            store,
            (self.lock_factory)(),
            (self.clock_factory)(),
            self.config.machine_id.clone(),
            owner.clone(),
            self.config.service_instance_id.clone(),
        )
        .with_hook(Rc::clone(&self.hook)))
    }

    /// Fresh U04 driver incarnation over the same durable state.
    /// Every factory is Rc-shared, so each pass re-invokes them exactly
    /// like a restarted process would. The probe factory is re-invoked per
    /// pass: stateless probes (the real Windows owner probe) observe live
    /// state; the fake probe snapshots at call time, so tests program probe
    /// state before each pass.
    fn build_driver(&self) -> Result<ReplayDriver<F>, EngineError> {
        let backend_factory = Rc::clone(&self.backend_factory);
        let setter_factory = Rc::clone(&self.setter_factory);
        let lock_factory = Rc::clone(&self.lock_factory);
        let clock_factory = Rc::clone(&self.clock_factory);
        let fs_factory = Rc::clone(&self.fs_factory);
        let probe_factory = Rc::clone(&self.probe_factory);
        Ok(ReplayDriver::new(
            Box::new(move || backend_factory()),
            Box::new(move || setter_factory()),
            Box::new(move || lock_factory()),
            Box::new(move || clock_factory()),
            Box::new(move || fs_factory()),
            self.config.dir.clone(),
            self.config.machine_id.clone(),
            self.config.service_instance_id.clone(),
            probe_factory(),
        ))
    }

    fn reply(&self, req: &Request, generation: u64, outcome: &str, body: serde_json::Value) -> Reply {
        Reply::new(
            req.request_id.clone(),
            self.config.service_instance_id.clone(),
            generation,
            outcome,
            body,
        )
    }

    fn auth_reply(&self, req: &Request, err: &str) -> Reply {
        self.reply(
            req,
            0,
            "auth_rejected",
            serde_json::json!({"error": err}),
        )
    }

    /// Current journal epoch (0 when no transaction is recorded).
    fn journal_epoch(&self) -> u64 {
        match self.open_store().map_err(|e| e.to_string()).and_then(|s| {
            s.reconcile()
                .map_err(|e| e.to_string())
        }) {
            Ok(rec) => rec
                .current
                .and_then(|c| c.env.payload.transaction.map(|t| t.epoch))
                .unwrap_or(0),
            Err(_) => 0,
        }
    }

    fn journal_generation(&self) -> u64 {
        match self
            .open_store()
            .map_err(|e| e.to_string())
            .and_then(|s| s.reconcile().map_err(|e| e.to_string()))
        {
            Ok(rec) => rec.current.map(|c| c.env.generation).unwrap_or(0),
            Err(_) => 0,
        }
    }

    // ---- entry points ---------------------------------------------------------

    /// Service boot replay (§8.3): locked replay before accepting any
    /// takeover. Recovers a dead owner, reattaches nothing blindly, leaves a
    /// live owner's journal untouched.
    pub fn boot_replay(&self) -> Result<ReplayReport, EngineError> {
        self.build_driver()?.replay()
    }

    /// Authenticated dispatch: exactly one frame in, exactly one reply out.
    /// Unknown protocol versions/operations never reach here (the codec
    /// rejects them); every arm re-checks peer authorization first.
    pub fn dispatch(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        if let Err(e) = peer.authorize(req.operation) {
            return self.auth_reply(req, &e.to_string());
        }
        if self.control != ControlState::Running
            && !matches!(
                req.operation,
                Operation::Hello | Operation::Inspect | Operation::Status
            )
            && !req.operation.requires_admin()
        {
            return self.reply(
                req,
                self.journal_generation(),
                "busy",
                serde_json::json!({"error": "service is stopping; only inspection and admin stop-path calls are accepted"}),
            );
        }
        match req.operation {
            Operation::Hello => self.op_hello(req),
            Operation::Inspect => self.op_inspect(req),
            Operation::RegisterOwner => self.op_register(peer, req),
            Operation::Apply => self.op_apply(peer, req),
            Operation::Reconfigure => self.op_reconfigure(peer, req),
            Operation::Health => self.op_health(peer, req),
            Operation::Quiesce => self.op_quiesce(peer, req),
            Operation::Restore => self.op_restore(peer, req),
            Operation::Status => self.op_status(req),
            Operation::EnterMaintenance => self.op_enter_maintenance(peer, req),
            Operation::LeaveMaintenance => self.op_leave_maintenance(peer, req),
            Operation::PrepareStop => self.op_prepare_stop(peer, req),
        }
    }

    // ---- read-only ops ---------------------------------------------------------

    fn op_hello(&self, req: &Request) -> Reply {
        self.reply(
            req,
            self.journal_generation(),
            "success",
            serde_json::json!({
                "protocol": protocol::PROTOCOL_VERSION,
                "service_instance": self.config.service_instance_id,
                "pipe": protocol::PIPE_NAME,
            }),
        )
    }

    fn op_inspect(&self, req: &Request) -> Reply {
        let store = match self.open_store() {
            Ok(s) => s,
            Err(e) => {
                return self.reply(
                    req,
                    0,
                    "unavailable",
                    serde_json::json!({"error": format!("journal unavailable: {e}")}),
                );
            }
        };
        match store.reconcile() {
            Err(e) => self.reply(
                req,
                0,
                integrity_or_unavailable(&e),
                serde_json::json!({"error": format!("journal reconciliation failed: {e}")}),
            ),
            Ok(rec) => {
                let (state, phase, epoch, owner, generation) = match &rec.current {
                    None => ("absent", None, None, None, 0),
                    Some(c) => {
                        let tx = c.env.payload.transaction.as_ref();
                        (
                            match c.env.payload.journal_state {
                                JournalState::Clean => "clean",
                                JournalState::Owned => "owned",
                                JournalState::Restoring => "restoring",
                                JournalState::RecoveryPending => "recovery_pending",
                                JournalState::Maintenance => "maintenance",
                            },
                            tx.map(|t| format!("{:?}", t.phase).to_lowercase()),
                            tx.map(|t| t.epoch),
                            tx.map(|t| {
                                serde_json::json!({
                                    "owner_id": t.owner.owner_id,
                                    "pid": t.owner.pid,
                                    "session_id": t.owner.session_id,
                                })
                            }),
                            c.env.generation,
                        )
                    }
                };
                let outcome = match state {
                    "clean" | "absent" => "verified_restored",
                    _ => "pending",
                };
                self.reply(
                    req,
                    generation,
                    outcome,
                    serde_json::json!({
                        "journal_state": state,
                        "phase": phase,
                        "epoch": epoch,
                        "owner": owner,
                        "candidates": rec.candidates.len(),
                    }),
                )
            }
        }
    }

    fn op_status(&self, req: &Request) -> Reply {
        let inspect = self.op_inspect(req);
        let mut body = inspect.body.clone();
        if let serde_json::Value::Object(ref mut map) = body {
            let leases: Vec<serde_json::Value> = self
                .leases
                .values()
                .map(|l| {
                    serde_json::json!({
                        "owner_id": l.owner.owner_id,
                        "pid": l.owner.pid,
                        "session_id": l.owner.session_id,
                        "last_health_ms": l.last_health_ms,
                        "health_age_ms": self.now_ms().saturating_sub(l.last_health_ms),
                        "readiness_generation": l.readiness_generation,
                    })
                })
                .collect();
            map.insert("leases".into(), serde_json::Value::Array(leases));
            map.insert(
                "control".into(),
                serde_json::Value::String(
                    match self.control {
                        ControlState::Running => "running",
                        ControlState::StopPending => "stop_pending",
                        ControlState::Stopped => "stopped",
                    }
                    .into(),
                ),
            );
            map.insert(
                "dedup_entries".into(),
                serde_json::Value::from(self.dedup.len() as u64),
            );
        }
        self.reply(req, inspect.generation, inspect.outcome.as_str(), body)
    }

    // ---- registration -----------------------------------------------------------

    /// T0: authenticate the caller's process identity, bind the lease to it
    /// and hold that identity before replying. No DNS mutation happens here.
    ///
    /// Identity comes from the transport-authenticated peer (process-derived
    /// image path/file id/SHA-256 and token-derived logon LUID) — never from
    /// the request body. A caller-claimed image hash or file id that differs
    /// from the process-observed value is rejected.
    fn op_register(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        let body = &req.body;
        let owner_id = match body
            .get("owner_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        {
            Some(s) => s,
            None => return self.auth_reply(req, "register_owner requires owner_id"),
        };
        if !journal::is_lower_uuid(&owner_id) {
            return self.auth_reply(req, "owner_id is not a lowercase UUID");
        }
        // Server-side identity: the process-observed image hash/file id win.
        // A caller-supplied value that contradicts the observed process is a
        // spoof attempt.
        if let Some(claimed) = body.get("image_sha256").and_then(|v| v.as_str()) {
            if claimed != peer.image_sha256 {
                return self.auth_reply(req, "caller-claimed image hash differs from the process image");
            }
        }
        if let Some(claimed) = body.get("image_file_id").and_then(|v| v.as_str()) {
            if claimed != peer.image_file_id {
                return self.auth_reply(req, "caller-claimed image file id differs from the process image");
            }
        }
        // The journal may already record a transaction: a service restart
        // with a LIVE owner reattaches to it (no blind restore); anything
        // else refuses until recovery settles.
        let (generation, tx_owner, tx_epoch) = match self.current_transaction() {
            Err(e) => {
                return self.reply(
                    req,
                    0,
                    "unavailable",
                    serde_json::json!({"error": format!("journal unavailable: {e}")}),
                );
            }
            Ok(None) => (self.journal_generation(), None, 0),
            Ok(Some((g, tx))) => (g, Some(tx.owner.clone()), tx.epoch),
        };
        if let Some(recorded) = tx_owner {
            let live = matches!((self.probe_factory)().check(&recorded), OwnerLiveness::Live);
            if recorded.owner_id == owner_id
                && recorded.pid == peer.pid
                && recorded.creation_time_filetime == peer.creation_filetime
                && live
            {
                // Reattach: same live process, fresh token, journal epoch.
                let token = fresh_token();
                let now = self.now_ms();
                self.leases.insert(
                    owner_id.clone(),
                    Lease {
                        owner: recorded,
                        token: token.clone(),
                        last_health_ms: now,
                        readiness_generation: body
                            .get("readiness_generation")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    },
                );
                return self.reply(
                    req,
                    generation,
                    "success",
                    serde_json::json!({
                        "owner_id": owner_id,
                        "token": token,
                        "epoch": tx_epoch,
                        "reattached": true,
                    }),
                );
            }
            if live {
                return self.reply(
                    req,
                    generation,
                    "busy",
                    serde_json::json!({
                        "error": "a live owner holds the machine lease; activation must target the existing instance",
                        "owner_id": recorded.owner_id,
                    }),
                );
            }
            return self.reply(
                req,
                generation,
                "unavailable",
                serde_json::json!({
                    "error": "recovery debt is unsettled; restore before new registration",
                    "owner_id": recorded.owner_id,
                }),
            );
        }
        if self.leases.contains_key(&owner_id) {
            return self.reply(
                req,
                generation,
                "busy",
                serde_json::json!({"error": "owner id already registered"}),
            );
        }
        let owner = OwnerIdentity {
            owner_id: owner_id.clone(),
            pid: peer.pid,
            creation_time_filetime: peer.creation_filetime,
            user_sid: peer.user_sid.clone(),
            logon_luid: peer.logon_luid,
            session_id: peer.session_id,
            image_path: peer.image_path.clone(),
            image_file_id: peer.image_file_id.clone(),
            image_sha256: peer.image_sha256.clone(),
        };
        let token = fresh_token();
        let now = self.now_ms();
        self.leases.insert(
            owner_id.clone(),
            Lease {
                owner,
                token: token.clone(),
                last_health_ms: now,
                readiness_generation: body
                    .get("readiness_generation")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            },
        );
        self.reply(
            req,
            generation,
            "success",
            serde_json::json!({
                "owner_id": owner_id,
                "token": token,
                "epoch": 0u64,
                "reattached": false,
            }),
        )
    }

    // ---- mutation ops ------------------------------------------------------------

    /// Common gate for owner-bound calls: live lease, token match, same
    /// process identity (pid + creation FILETIME + sid), open control state
    /// and a non-stale epoch. Late heartbeats/applies on a revoked epoch are
    /// rejected, never revived.
    fn check_lease(
        &self,
        peer: &PeerAuth,
        req: &Request,
    ) -> Result<(LeaseSnapshot, u64), Reply> {
        let owner_id = req.owner_id.clone().ok_or_else(|| {
            self.auth_reply(req, "owner operation requires owner_id")
        })?;
        let lease = self.leases.get(&owner_id).ok_or_else(|| {
            self.reply(
                req,
                self.journal_generation(),
                "refused",
                serde_json::json!({"error": "no live lease for owner id; revoked epochs cannot be revived"}),
            )
        })?;
        let token = req
            .body
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if token != lease.token {
            return Err(self.auth_reply(req, "lease token mismatch"));
        }
        if peer.pid != lease.owner.pid
            || peer.creation_filetime != lease.owner.creation_time_filetime
            || peer.user_sid != lease.owner.user_sid
        {
            return Err(self.auth_reply(req, "caller process identity does not own the lease"));
        }
        let journal_epoch = self.journal_epoch();
        match req.epoch {
            Some(e) if e != journal_epoch => Err(self.reply(
                req,
                self.journal_generation(),
                "refused",
                serde_json::json!({
                    "error": "stale epoch; the lease was revoked and cannot be revived by a late call",
                    "expected_epoch": journal_epoch,
                }),
            )),
            _ => Ok((
                LeaseSnapshot {
                    owner: lease.owner.clone(),
                    readiness_generation: lease.readiness_generation,
                },
                journal_epoch,
            )),
        }
    }

    fn readiness_ok(&self, snap: &LeaseSnapshot, plan_gen: u64) -> bool {
        // T1: the submitted plan must carry the readiness the GUI proved via
        // health. Windows-only plans (no listener) prove generation 0.
        plan_gen == snap.readiness_generation
    }

    fn op_apply(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        if self.maintenance_active() {
            return self.reply(
                req,
                self.journal_generation(),
                "refused",
                serde_json::json!({"error": "service is in maintenance; takeover refused"}),
            );
        }
        let (snap, _) = match self.check_lease(peer, req) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if let Some(stored) = self.dedup_lookup(&req.request_id) {
            return stored.clone();
        }
        let selected = match protocol::parse_selected(&req.body) {
            Ok(s) => s,
            Err(e) => return self.reply(req, self.journal_generation(), "refused",
                serde_json::json!({"error": e.to_string()})),
        };
        let plan = match protocol::parse_plan(&req.body) {
            Ok(p) => p,
            Err(e) => return self.reply(req, self.journal_generation(), "refused",
                serde_json::json!({"error": e.to_string()})),
        };
        if !self.readiness_ok(&snap, plan.readiness_generation) {
            return self.reply(req, self.journal_generation(), "refused",
                serde_json::json!({
                    "error": "plan readiness generation does not match proved listener readiness",
                    "expected": snap.readiness_generation,
                }));
        }
        let readiness = snap.readiness_generation;
        let engine = match self.engine_for(&snap.owner) {
            Ok(e) => e.with_readiness(Rc::new(move |p| p.readiness_generation == readiness)),
            Err(e) => {
                return self.reply(req, self.journal_generation(), "unavailable",
                    serde_json::json!({"error": format!("engine unavailable: {e}")}));
            }
        };
        let report = match engine.takeover(&selected, &plan) {
            Ok(r) => r,
            Err(e) => {
                return self.reply(req, self.journal_generation(), engine_error_outcome(&e),
                    serde_json::json!({"error": e.to_string()}));
            }
        };
        let outcome = outcome_str(report.outcome);
        let generation = report.generation;
        let errors: Vec<serde_json::Value> = report
            .errors
            .iter()
            .map(|e| {
                serde_json::json!({
                    "adapter_guid": e.adapter_guid,
                    "family": e.family.as_str(),
                    "phase": e.phase,
                    "message": e.message,
                })
            })
            .collect();
        let reply = self.reply(
            req,
            generation,
            outcome,
            serde_json::json!({"errors": errors}),
        );
        self.dedup_store(req.request_id.clone(), reply.clone());
        reply
    }

    fn op_reconfigure(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        if self.maintenance_active() {
            return self.reply(
                req,
                self.journal_generation(),
                "refused",
                serde_json::json!({"error": "service is in maintenance; reconfigure refused"}),
            );
        }
        let (snap, _) = match self.check_lease(peer, req) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if let Some(stored) = self.dedup_lookup(&req.request_id) {
            return stored.clone();
        }
        let selected = match protocol::parse_selected(&req.body) {
            Ok(s) => s,
            Err(e) => return self.reply(req, self.journal_generation(), "refused",
                serde_json::json!({"error": e.to_string()})),
        };
        let plan = match protocol::parse_plan(&req.body) {
            Ok(p) => p,
            Err(e) => return self.reply(req, self.journal_generation(), "refused",
                serde_json::json!({"error": e.to_string()})),
        };
        if !self.readiness_ok(&snap, plan.readiness_generation) {
            return self.reply(req, self.journal_generation(), "refused",
                serde_json::json!({
                    "error": "plan readiness generation does not match proved listener readiness",
                    "expected": snap.readiness_generation,
                }));
        }
        let readiness = snap.readiness_generation;
        let engine = match self.engine_for(&snap.owner) {
            Ok(e) => e.with_readiness(Rc::new(move |p| p.readiness_generation == readiness)),
            Err(e) => {
                return self.reply(req, self.journal_generation(), "unavailable",
                    serde_json::json!({"error": format!("engine unavailable: {e}")}));
            }
        };
        let report = match engine.reconfigure(&selected, &plan) {
            Ok(r) => r,
            Err(e) => {
                return self.reply(req, self.journal_generation(), engine_error_outcome(&e),
                    serde_json::json!({"error": e.to_string()}));
            }
        };
        let outcome = outcome_str(report.outcome);
        let reply = self.reply(
            req,
            report.generation,
            outcome,
            serde_json::json!({"errors": report.errors.len()}),
        );
        self.dedup_store(req.request_id.clone(), reply.clone());
        reply
    }

    /// Quiesce (§2): atomically close admission and cancel queued writes;
    /// idempotent. The lease is revoked (epoch can never be revived) and the
    /// journal records admission Closed + phase Quiescing under the machine
    /// lock. Listeners stay up; restoration is a separate step.
    fn op_quiesce(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        let (snap, _) = match self.check_lease(peer, req) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let _ = snap;
        let owner_id = req.owner_id.clone().unwrap_or_default();
        // Revoke first: no late call can slip in after the barrier.
        self.leases.remove(&owner_id);
        match self.commit_admin(|env| {
            if let Some(tx) = &mut env.payload.transaction {
                tx.admission = Admission::Closed;
                if tx.phase == Phase::Active || tx.phase == Phase::Reconfiguring {
                    tx.phase = Phase::Quiescing;
                }
            }
        }) {
            Ok(generation) => self.reply(
                req,
                generation,
                "success",
                serde_json::json!({"quiesced": true}),
            ),
            Err(e) => self.reply(
                req,
                self.journal_generation(),
                "unavailable",
                serde_json::json!({"error": format!("quiesce barrier failed: {e}")}),
            ),
        }
    }

    fn op_restore(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        let (snap, _) = match self.check_lease(peer, req) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if let Some(stored) = self.dedup_lookup(&req.request_id) {
            return stored.clone();
        }
        let engine = match self.engine_for(&snap.owner) {
            Ok(e) => e,
            Err(e) => {
                return self.reply(req, self.journal_generation(), "unavailable",
                    serde_json::json!({"error": format!("engine unavailable: {e}")}));
            }
        };
        let report = match engine.restore() {
            Ok(r) => r,
            Err(e) => {
                return self.reply(req, self.journal_generation(), engine_error_outcome(&e),
                    serde_json::json!({"error": e.to_string()}));
            }
        };
        let reply = self.reply(req, report.generation, outcome_str(report.outcome),
            serde_json::json!({"errors": report.errors.len()}));
        self.dedup_store(req.request_id.clone(), reply.clone());
        reply
    }

    // ---- health ------------------------------------------------------------------

    /// GUI health (§6): proves listener responsiveness every 2 s and carries
    /// the readiness generation subsequent plans must match. A responding
    /// listener that answers SERVFAIL still counts as alive.
    fn op_health(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        let owner_id = match req.owner_id.clone() {
            Some(o) => o,
            None => return self.auth_reply(req, "health requires owner_id"),
        };
        let token = req.body.get("token").and_then(|v| v.as_str()).unwrap_or("");
        let responding = req
            .body
            .get("listener_responding")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let readiness = req
            .body
            .get("readiness_generation")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Epoch gate: a revoked epoch cannot be revived by a late heartbeat.
        let now = self.now_ms();
        let journal_epoch = self.journal_epoch();
        if let Some(e) = req.epoch {
            if e != journal_epoch {
                return self.reply(req, self.journal_generation(), "refused",
                    serde_json::json!({
                        "error": "stale epoch; re-register after restore",
                        "expected_epoch": journal_epoch,
                    }));
            }
        }
        let lease = match self.leases.get_mut(&owner_id) {
            Some(l) => l,
            None => {
                return self.reply(req, self.journal_generation(), "refused",
                    serde_json::json!({"error": "no live lease; revoked epochs cannot be revived"}));
            }
        };
        if lease.token != token
            || peer.pid != lease.owner.pid
            || peer.creation_filetime != lease.owner.creation_time_filetime
        {
            return self.auth_reply(req, "health caller does not own the lease");
        }
        if !responding {
            // Terminal listener-task loss is explicit, not a timeout: close
            // the epoch and restore now, revoking the lease.
            let owner = lease.owner.clone();
            self.leases.remove(&owner_id);
            return self.restore_after_lease_loss(req, &owner, "listener non-responding");
        }
        lease.last_health_ms = now;
        lease.readiness_generation = readiness;
        self.reply(
            req,
            journal_epoch,
            "success",
            serde_json::json!({"epoch": journal_epoch}),
        )
    }

    /// Watchdog sweep (§6/§8.3): three missed health reports (6 s) close the
    /// epoch and restore — even when the process is still alive — and revoke
    /// the lease. Liveness decides the report note, never whether recovery
    /// runs: health expiry always quiesces/restores.
    pub fn sweep(&mut self, now_ms: i64) -> Vec<Reply> {
        let expired: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, l)| {
                now_ms.saturating_sub(l.last_health_ms)
                    > HEALTH_INTERVAL_MS * MISSED_HEALTH_LIMIT as i64
            })
            .map(|(id, _)| id.clone())
            .collect();
        let mut out = Vec::new();
        for owner_id in expired {
            if let Some(lease) = self.leases.remove(&owner_id) {
                let live = matches!((self.probe_factory)().check(&lease.owner), OwnerLiveness::Live);
                let note = if live {
                    "health expiry with live process: epoch closed, restored, lease revoked"
                } else {
                    "health expiry, owner dead: restored"
                };
                let report = self.restore_for_owner(&lease.owner);
                out.push(Reply::new(
                    format!("sweep-{}", lease.owner.owner_id),
                    self.config.service_instance_id.clone(),
                    report.generation,
                    outcome_str(report.outcome),
                    serde_json::json!({"note": note}),
                ));
            }
        }
        out
    }

    /// Watchdog entry for a signaled owner handle (proven death): begin
    /// restoration immediately (§8.3: target 1 s under normal scheduling).
    /// Returns the restore report; the caller measures start latency.
    ///
    /// Liveness is checked BEFORE the lease is touched: a non-dead probe
    /// (live or unknown) leaves the lease in place and returns `None`. A
    /// live owner is never restored from here.
    pub fn on_owner_death(&mut self, owner_id: &str) -> Option<EngineReport> {
        let live = match self.leases.get(owner_id) {
            None => return None,
            Some(lease) => (self.probe_factory)().check(&lease.owner),
        };
        if !matches!(live, OwnerLiveness::Dead) {
            return None;
        }
        let lease = self.leases.remove(owner_id)?;
        Some(self.restore_for_owner(&lease.owner))
    }

    /// Journal-recorded owner, if a transaction exists (used by the service
    /// loop to keep a live owner under the held-handle monitor across a
    /// restart, before any takeover and without a mutation lease).
    pub fn recorded_owner(&self) -> Option<OwnerIdentity> {
        self.current_transaction()
            .ok()
            .flatten()
            .map(|(_, tx)| tx.owner)
    }

    /// Service-loop watchdog poll (§8.3, ~1 s cadence on the service thread):
    /// poll every held owner handle AND the journal's recorded owner. A
    /// `Dead` result starts `restore` inside the 1 s target and never
    /// relaunches a GUI (restore runs through the engine only). A `Live`
    /// result keeps the handle (the probe holds it). A service restart that
    /// sees a live owner leaves that handle in the monitor before accepting
    /// takeover — no blind restore, no mutation lease. Returns one report
    /// per owner restored.
    pub fn watchdog_poll(&mut self) -> Vec<EngineReport> {
        let mut out = Vec::new();
        // Snapshot the lease table so the probe (which may cache handles)
        // never runs under a lease borrow.
        let leased: Vec<(String, OwnerIdentity)> = self
            .leases
            .iter()
            .map(|(id, l)| (id.clone(), l.owner.clone()))
            .collect();
        let mut dead_leases = Vec::new();
        for (id, owner) in &leased {
            if matches!((self.probe_factory)().check(owner), OwnerLiveness::Dead) {
                dead_leases.push(id.clone());
            }
        }
        for id in dead_leases {
            if let Some(lease) = self.leases.remove(&id) {
                out.push(self.restore_for_owner(&lease.owner));
            }
        }
        // Journal-recorded owner without a covering lease (e.g. right after
        // a service restart, before the live owner re-registers): a dead
        // recorded owner restores now; a live one is left in the monitor
        // (the check above holds the handle) with no blind restore and no
        // lease minted here.
        if let Some(recorded) = self.recorded_owner() {
            let covered = self.leases.values().any(|l| {
                l.owner.owner_id == recorded.owner_id
                    && l.owner.pid == recorded.pid
                    && l.owner.creation_time_filetime == recorded.creation_time_filetime
            });
            if !covered {
                match (self.probe_factory)().check(&recorded) {
                    OwnerLiveness::Dead => out.push(self.restore_for_owner(&recorded)),
                    OwnerLiveness::Live | OwnerLiveness::Unknown(_) => {}
                }
            }
        }
        out
    }

    fn restore_after_lease_loss(&mut self, req: &Request, owner: &OwnerIdentity, why: &str) -> Reply {
        let report = self.restore_for_owner(owner);
        self.reply(
            req,
            report.generation,
            outcome_str(report.outcome),
            serde_json::json!({"note": why, "errors": report.errors.len()}),
        )
    }

    fn restore_for_owner(&mut self, owner: &OwnerIdentity) -> EngineReport {
        match self.engine_for(owner) {
            Ok(e) => e.restore().unwrap_or_else(|_| EngineReport {
                outcome: Outcome::Refused,
                errors: Vec::new(),
                generation: self.journal_generation(),
            }),
            Err(_) => EngineReport {
                outcome: Outcome::Refused,
                errors: Vec::new(),
                generation: self.journal_generation(),
            },
        }
    }

    // ---- admin ---------------------------------------------------------------------

    fn op_enter_maintenance(&mut self, peer: &PeerAuth, req: &Request) -> Reply {
        let reason = req
            .body
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("admin maintenance")
            .to_string();
        let quiesce_owner = req
            .body
            .get("quiesce_owner")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !self.leases.is_empty() && !quiesce_owner {
            return self.reply(req, self.journal_generation(), "busy",
                serde_json::json!({"error": "a live owner holds the lease; quiesce it first or set quiesce_owner"}));
        }
        // Audited revocation of every lease before the maintenance barrier.
        self.leases.clear();
        let caller = format!("{}@{}:{}", peer.user_sid, peer.pid, reason);
        let now = crate::clock::utc_string(self.now_ms());
        let expires = crate::clock::utc_string(
            self.now_ms() + MAINTENANCE_LEASE_SECS * 1000,
        );
        let id = journal::new_uuid();
        match self.commit_admin(|env| {
            if env.payload.transaction.is_some() {
                env.payload.journal_state = JournalState::Maintenance;
            } else {
                env.payload.journal_state = JournalState::Maintenance;
            }
            env.payload.maintenance = Some(Maintenance {
                id: id.clone(),
                caller_identity: caller.clone(),
                started_at_utc: now.clone(),
                expires_at_utc: expires.clone(),
                phase: "enter".into(),
            });
        }) {
            Ok(generation) => self.reply(req, generation, "success",
                serde_json::json!({"maintenance": id, "leases_revoked": true})),
            Err(e) => self.reply(req, self.journal_generation(), "unavailable",
                serde_json::json!({"error": format!("maintenance barrier failed: {e}")})),
        }
    }

    fn op_leave_maintenance(&mut self, _peer: &PeerAuth, req: &Request) -> Reply {
        // commit_admin runs journal::validate: leaving maintenance on a
        // journal with no transaction and no clean tombstone is a schema
        // violation, so a genesis journal honestly refuses here.
        match self.commit_admin(|env| {
            env.payload.maintenance = None;
            if env.payload.transaction.is_some() {
                env.payload.journal_state = JournalState::RecoveryPending;
            } else if env.payload.last_completed.is_some() {
                env.payload.journal_state = JournalState::Clean;
            }
        }) {
            Ok(generation) => self.reply(req, generation, "success",
                serde_json::json!({"maintenance": "left"})),
            Err(e) => self.reply(req, self.journal_generation(), "unavailable",
                serde_json::json!({"error": format!("leave-maintenance barrier failed: {e}")})),
        }
    }

    /// SCM STOP/SHUTDOWN/PRESHUTDOWN (§8.3): reject new registration/apply,
    /// restore with bounded retry while a healthy GUI would retain listeners,
    /// persist pending debt and return a nonzero-mapped result when recovery
    /// is incomplete. Never blocks on a GUI response.
    fn op_prepare_stop(&mut self, _peer: &PeerAuth, req: &Request) -> Reply {
        let reason = req
            .body
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("scm_stop")
            .to_string();
        self.control = ControlState::StopPending;
        // No new work: revoke every lease up front.
        self.leases.clear();
        let owner = match self.current_transaction() {
            Err(e) => {
                self.control = ControlState::Stopped;
                return self.reply(req, 0, "unavailable",
                    serde_json::json!({"error": format!("journal unavailable: {e}")}));
            }
            Ok(None) => {
                self.control = ControlState::Stopped;
                return self.reply(req, self.journal_generation(), "verified_restored",
                    serde_json::json!({"note": format!("{reason}: clean journal, nothing to restore")}));
            }
            Ok(Some((_, tx))) => tx.owner.clone(),
        };
        let report = self.restore_for_owner(&owner);
        self.control = ControlState::Stopped;
        let outcome = outcome_str(report.outcome);
        self.reply(
            req,
            report.generation,
            outcome,
            serde_json::json!({
                "reason": reason,
                "errors": report.errors.len(),
                "service_exit": protocol::exit_code_for_outcome(outcome),
            }),
        )
    }

    // ---- scheduler ------------------------------------------------------------------

    /// Earliest persisted retry time, for the transport's sleep scheduling.
    pub fn next_wake_ms(&self) -> Option<i64> {
        self.build_driver().ok()?.next_wake_ms()
    }

    /// One scheduled background pass (at most three entries, one attempt
    /// each, §5.3). Debt is never expired.
    pub fn background_tick(&mut self) -> Option<ReplayReport> {
        self.build_driver().ok()?.background_wake().ok()
    }

    /// Adapter-arrival trigger (§7 step 5): retry Failed/Deferred entries for
    /// exactly the arrived GUIDs; a new GUID reusing a name/index never
    /// inherits old settings.
    pub fn notify_arrival(&mut self, arrived: &[String]) -> Option<ReplayReport> {
        self.build_driver().ok()?.notify_arrival(arrived).ok()
    }

    // ---- offline guard ----------------------------------------------------------------

    /// The elevated offline helper may proceed only after proving the SCM
    /// service STOPPED. Running, start-pending and unknown refuse.
    pub fn offline_precheck(state: ScmServiceState) -> Result<(), String> {
        match state {
            ScmServiceState::Stopped => Ok(()),
            ScmServiceState::Running => {
                Err("offline restore refused: service is RUNNING".into())
            }
            ScmServiceState::StartPending | ScmServiceState::StopPending => Err(
                "offline restore refused: service is start-pending/stop-pending".into(),
            ),
            ScmServiceState::Unknown => {
                Err("offline restore refused: service state unknown".into())
            }
        }
    }

    // ---- internals ----------------------------------------------------------------------

    fn current_transaction(
        &self,
    ) -> Result<Option<(u64, crate::journal::Transaction)>, StoreError> {
        let store = self.open_store()?;
        let rec = store.reconcile()?;
        Ok(rec.current.and_then(|c| {
            c.env
                .payload
                .transaction
                .clone()
                .map(|tx| (c.env.generation, tx))
        }))
    }

    fn maintenance_active(&self) -> bool {
        match self
            .open_store()
            .map_err(|e| e.to_string())
            .and_then(|s| s.reconcile().map_err(|e| e.to_string()))
        {
            Ok(rec) => rec.current.is_some_and(|c| {
                c.env.payload.journal_state == JournalState::Maintenance
            }),
            Err(_) => false,
        }
    }

    /// Administrative journal commit under the machine lock: generation+1
    /// with the full U02 durability barrier (stage → flush → readback →
    /// replace → primary verify → primary flush → volume flush). Used for
    /// quiesce/maintenance only — never for DNS mutation, which stays inside
    /// the U03 engine.
    fn commit_admin(
        &self,
        mutate: impl FnOnce(&mut crate::journal::Envelope),
    ) -> Result<u64, StoreError> {
        let lock = (self.lock_factory)();
        let _guard = lock
            .acquire(crate::lock::LOCK_BUDGET)
            .map_err(|e| StoreError::Integrity(format!("admin lock: {e:?}")))?;
        let store = self.open_store()?;
        let rec = store.reconcile()?;
        let mut env = match rec.current {
            Some(c) => {
                let mut e = c.env.clone();
                e.generation += 1;
                e.previous_digest = Some(c.digest.clone());
                e
            }
            None => crate::journal::Envelope {
                format: journal::JOURNAL_FORMAT.to_string(),
                version: journal::JOURNAL_VERSION,
                machine_id: self.config.machine_id.clone(),
                generation: 1,
                previous_digest: None,
                payload_digest: String::new(),
                payload: crate::journal::Payload {
                    journal_state: JournalState::Clean,
                    transaction: None,
                    last_completed: None,
                    maintenance: None,
                    diagnostics: Vec::new(),
                },
            },
        };
        mutate(&mut env);
        // Sealed first: commit() re-validates the sealed envelope (digest +
        // schema), exactly like the U03 engine's commit path.
        codec::seal(&mut env);
        let report = store.commit(&env)?;
        Ok(report.generation)
    }

}

/// Snapshot of the lease fields a mutation call needs after the borrow ends.
#[derive(Clone, Debug)]
struct LeaseSnapshot {
    owner: OwnerIdentity,
    readiness_generation: u64,
}

fn outcome_str(o: Outcome) -> &'static str {
    match o {
        Outcome::Active => "active",
        Outcome::VerifiedRestored => "verified_restored",
        Outcome::Pending => "pending",
        Outcome::Conflict => "conflict",
        Outcome::Refused => "refused",
        Outcome::Busy => "busy",
        Outcome::Unsupported => "unsupported",
    }
}

/// EngineError → IPC outcome: infrastructure failures are never reported as
/// success; lock contention is busy; persistence/IO failures are
/// unavailable (debt retained); semantic refusals stay refused.
fn engine_error_outcome(e: &EngineError) -> &'static str {
    match e {
        EngineError::Busy(_) => "busy",
        EngineError::Refused(_) => "unavailable",
        EngineError::Conflict(_) => "conflict",
        EngineError::Lock(_) => "busy",
        EngineError::Store(_) => "unavailable",
        EngineError::Capture(_) => "unsupported",
    }
}

fn integrity_or_unavailable(e: &StoreError) -> &'static str {
    match e {
        StoreError::Integrity(_) | StoreError::UnknownVersion(_) => "integrity_error",
        _ => "unavailable",
    }
}

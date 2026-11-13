//! U03: the apply/reconfigure/restore transaction engine (SPEC-DNS-FIX.md
//! §5.1 T0–T7, §5.2 C0–C4, §5.3 R0–R6, §5.4 classification).
//!
//! Library-only: the engine drives a [`DnsBackend`] (read) and a [`DnsSetter`]
//! (write) against the durable [`JournalStore`] under the cross-session
//! [`MachineLock`]. The fake OS/journal implementations make every death
//! injection point deterministic; the qualified Windows setter adapter lives
//! in `windows.rs`. No GUI activation and no production takeover wiring.
//!
//! Durability rules enforced here:
//! - the entire transaction and its immutable originals are committed with a
//!   full barrier BEFORE the first setter call (T3);
//! - every separate mutation API call gets its own full before/target intent
//!   committed and flushed BEFORE the call (§3.2); request UUIDs are
//!   idempotency keys — a lost reply is settled by readback, never by a
//!   duplicate call under a new request ID;
//! - `applied_fingerprint` is only recorded after a verified configured
//!   readback (API success alone is never sufficient);
//! - any family failure closes admission and rolls the ENTIRE attempted
//!   transaction back to the immutable originals;
//! - a persistence failure closes admission (the store's dirty flag) and no
//!   further mutation happens until reconciliation;
//! - restore classifies the current configured image against the original
//!   and every committed/intent image (§5.4): original match verifies without
//!   a setter call, foreign divergence is a conflict with no write, and only
//!   qualified partial images are restorable.

use std::cell::RefCell;
use std::rc::Rc;

use crate::backend::DnsBackend;
use crate::clock::{utc_string, Clock};
use crate::codec;
use crate::fs::JournalFs;
use crate::journal::{
    self, Admission, BaselineKind, Diagnostic, Entry, EntryState, Envelope, JournalState,
    Observation, Operation, OperationKind, OperationState, OwnerIdentity, Payload, Phase, Reason,
    RetryState, Tombstone, Transaction, Verification, VerificationKind, WriteFacet,
    MAX_OPERATIONS_PER_ENTRY,
};
use crate::lock::{Acquired, LockError, LockGuard, MachineLock, LOCK_BUDGET};
use crate::model::{AdapterIdentity, CaptureError, DesiredPlan, Family, Snapshot};
use crate::plan::plan_image;
use crate::setter::{DnsSetter, SetterImage};
use crate::store::{CandidateKind, JournalStore, StoreError, ValidCandidate};

/// Deterministic death-injection points. The hook runs AFTER the named
/// durability barrier (or immediately around the setter call); a test panics
/// inside the hook to simulate process death at that exact point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeathPoint {
    TransactionCommitted,
    ApplyIntentFlushed,
    BeforeSetterCall,
    AfterSetterCall,
    AfterReadback,
    AppliedMarkerFlushed,
    ActiveMarkerFlushed,
    ReconfigureIntentFlushed,
    RestoreEpochFlushed,
    RestoreIntentFlushed,
    BeforeRestoreCall,
    AfterRestoreCall,
    AfterRestoreReadback,
    RestoredMarkerFlushed,
    CompleteMarkerFlushed,
    TombstoneFlushed,
}

/// Transaction outcomes (SPEC-DNS-FIX.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Active,
    VerifiedRestored,
    Pending,
    Conflict,
    Refused,
    Busy,
    Unsupported,
}

/// Per-family error detail (§2): never hides an IPv6 failure inside an
/// overall success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyError {
    pub adapter_guid: String,
    pub name_hint: String,
    pub family: Family,
    pub phase: String,
    pub api: String,
    pub windows_status: Option<u32>,
    pub retryable: bool,
    pub attempts: u32,
    pub expected_fingerprint: Option<String>,
    pub observed_fingerprint: Option<String>,
    pub at_utc: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct EngineReport {
    pub outcome: Outcome,
    pub errors: Vec<FamilyError>,
    pub generation: u64,
}

/// Infrastructure failures. Semantic outcomes (busy/refused/conflict/…) are
/// returned as [`EngineReport`] values, not errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    Lock(LockError),
    Store(StoreError),
    Capture(CaptureError),
    Busy(String),
    Refused(String),
    Conflict(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Lock(e) => write!(f, "machine lock: {e:?}"),
            EngineError::Store(e) => write!(f, "journal store: {e}"),
            EngineError::Capture(e) => write!(f, "capture: {e}"),
            EngineError::Busy(m) => write!(f, "busy: {m}"),
            EngineError::Refused(m) => write!(f, "refused: {m}"),
            EngineError::Conflict(m) => write!(f, "conflict: {m}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<LockError> for EngineError {
    fn from(e: LockError) -> Self {
        EngineError::Lock(e)
    }
}
impl From<StoreError> for EngineError {
    fn from(e: StoreError) -> Self {
        EngineError::Store(e)
    }
}
impl From<CaptureError> for EngineError {
    fn from(e: CaptureError) -> Self {
        EngineError::Capture(e)
    }
}

/// Background retry schedule (§5.3): 5 s, 30 s, 5 min, then every 15 min.
/// `attempts` is the number of failed attempts already persisted.
pub fn background_delay_ms(attempts: u32) -> i64 {
    match attempts {
        0 | 1 => 5_000,
        2 => 30_000,
        3 => 300_000,
        _ => 900_000,
    }
}

fn capture_retryable(e: &CaptureError) -> bool {
    matches!(
        e,
        CaptureError::QueryFailure(_) | CaptureError::CaptureUnstable | CaptureError::NoSelectedOnlineAdapter
    )
}

fn next_ordinal(e: &Entry) -> u32 {
    e.operations.last().map(|o| o.ordinal + 1).unwrap_or(1)
}

fn observation(s: &Snapshot, now: &str) -> Observation {
    Observation {
        snapshot: s.clone(),
        fingerprint: s.fingerprint(),
        observed_at_utc: now.to_string(),
    }
}

fn reset_retry() -> RetryState {
    RetryState { attempts: 0, next_attempt_utc: None, last_error: None }
}

fn make_entry(
    ident: &AdapterIdentity,
    family: Family,
    snap: &Snapshot,
    now: &str,
    plan_revision: u64,
) -> Entry {
    Entry {
        adapter_guid: ident.adapter_guid.clone(),
        family,
        name_hint: ident.name_hint.clone(),
        device_instance_hint: ident.device_instance_hint.clone(),
        original_if_index: Some(ident.if_index),
        original_luid: ident.luid,
        first_captured_at_utc: now.to_string(),
        original: snap.clone(),
        original_fingerprint: snap.fingerprint(),
        baseline_kind: BaselineKind::PreTakeover,
        previous_committed: None,
        previous_fingerprint: None,
        intended: None,
        intended_fingerprint: None,
        applied_fingerprint: None,
        plan_revision,
        operations: Vec::new(),
        state: EntryState::Captured,
        last_observed: None,
        retry: reset_retry(),
        verification: None,
        approved_legacy_target: None,
    }
}

/// §5.4 classification of the current configured image during restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoreClass {
    AlreadyOriginal,
    Known,
    PartialKnown,
    Foreign,
}

fn ns_facet_eq(a: &Snapshot, b: &Snapshot) -> bool {
    a.name_server_raw == b.name_server_raw && a.ordered_servers == b.ordered_servers
}

fn props_facet_eq(a: &Snapshot, b: &Snapshot) -> bool {
    a.server_properties == b.server_properties
}

fn provenance_consistent(s: &Snapshot) -> bool {
    let raw = s.name_server_raw.as_deref().unwrap_or("");
    match s.provenance {
        crate::model::Provenance::Automatic => raw.is_empty(),
        crate::model::Provenance::Static => !raw.is_empty(),
    }
}

fn classify_restore(current: &Snapshot, e: &Entry) -> RestoreClass {
    if current.configured_eq(&e.original) {
        return RestoreClass::AlreadyOriginal;
    }
    let mut known: Vec<&Snapshot> = vec![&e.original];
    if let Some(s) = &e.intended {
        known.push(s);
    }
    if let Some(s) = &e.previous_committed {
        known.push(s);
    }
    for op in &e.operations {
        known.push(&op.before);
        known.push(&op.target);
    }
    if known.iter().any(|s| current.configured_eq(s)) {
        return RestoreClass::Known;
    }
    // Qualified partial image: each changed facet equals the corresponding
    // facet of the latest intent's before or target, indices are valid and
    // provenance is consistent. Any other mixture is foreign.
    if let Some(op) = e.operations.last() {
        let (b, t) = (&op.before, &op.target);
        let ns_ok = ns_facet_eq(current, b) || ns_facet_eq(current, t);
        let props_ok = props_facet_eq(current, b) || props_facet_eq(current, t);
        let indices_ok = current
            .server_properties
            .iter()
            .all(|p| (p.server_index as usize) < current.ordered_servers.len());
        if ns_ok && props_ok && indices_ok && provenance_consistent(current) {
            return RestoreClass::PartialKnown;
        }
    }
    RestoreClass::Foreign
}

#[derive(Clone, Copy)]
struct ApplyStep {
    idx: usize,
    kind: OperationKind,
    expect_original: bool,
}

/// The U03 transaction engine. One instance is one DNS writer incarnation;
/// death-injection tests construct a fresh instance over the same shared fake
/// OS/journal/lock state to model process restart.
pub struct TransactionEngine<F: JournalFs> {
    backend: Box<dyn DnsBackend>,
    setter: Box<dyn DnsSetter>,
    store: JournalStore<F>,
    lock: Box<dyn MachineLock>,
    clock: Box<dyn Clock>,
    machine_id: String,
    owner: OwnerIdentity,
    service_instance_id: String,
    hook: Rc<dyn Fn(DeathPoint)>,
    readiness: Rc<dyn Fn(&DesiredPlan) -> bool>,
    current: RefCell<Option<ValidCandidate>>,
    errors: RefCell<Vec<FamilyError>>,
}

impl<F: JournalFs> TransactionEngine<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: Box<dyn DnsBackend>,
        setter: Box<dyn DnsSetter>,
        store: JournalStore<F>,
        lock: Box<dyn MachineLock>,
        clock: Box<dyn Clock>,
        machine_id: String,
        owner: OwnerIdentity,
        service_instance_id: String,
    ) -> Self {
        Self {
            backend,
            setter,
            store,
            lock,
            clock,
            machine_id,
            owner,
            service_instance_id,
            hook: Rc::new(|_| {}),
            readiness: Rc::new(|_| true),
            current: RefCell::new(None),
            errors: RefCell::new(Vec::new()),
        }
    }

    pub fn with_hook(mut self, hook: Rc<dyn Fn(DeathPoint)>) -> Self {
        self.hook = hook;
        self
    }

    pub fn with_readiness(mut self, readiness: Rc<dyn Fn(&DesiredPlan) -> bool>) -> Self {
        self.readiness = readiness;
        self
    }

    pub fn store(&self) -> &JournalStore<F> {
        &self.store
    }

    pub fn current_envelope(&self) -> Option<Envelope> {
        self.current.borrow().as_ref().map(|c| c.env.clone())
    }

    pub fn current_generation(&self) -> u64 {
        self.current.borrow().as_ref().map(|c| c.env.generation).unwrap_or(0)
    }

    // ---- internal helpers --------------------------------------------------

    fn now(&self) -> String {
        utc_string(self.clock.now_ms())
    }

    fn next_gen(&self) -> u64 {
        self.current.borrow().as_ref().map(|c| c.env.generation + 1).unwrap_or(1)
    }

    fn tx(&self) -> Option<Transaction> {
        self.current.borrow().as_ref().and_then(|c| c.env.payload.transaction.clone())
    }

    fn hook(&self, p: DeathPoint) {
        (self.hook)(p);
    }

    fn record(&self, e: FamilyError) {
        self.errors.borrow_mut().push(e);
    }

    fn report(&self, outcome: Outcome) -> EngineReport {
        EngineReport {
            outcome,
            errors: self.errors.borrow().clone(),
            generation: self.current_generation(),
        }
    }

    fn diagnostic(&self, env: &mut Envelope, kind: &str, message: String) {
        let transaction_id = env.payload.transaction.as_ref().map(|t| t.id.clone());
        env.payload.diagnostics.push(Diagnostic {
            at_utc: self.now(),
            transaction_id,
            kind: kind.to_string(),
            message,
        });
    }

    /// Commit generation+1 with a full durability barrier. On failure the
    /// store's dirty flag closes admission; no further mutation is possible
    /// until a successful reconciliation (§3.3).
    fn commit_next(&self, mutate: impl FnOnce(&mut Envelope)) -> Result<(), EngineError> {
        let base = self.current.borrow().clone();
        let mut env = match &base {
            Some(c) => {
                let mut e = c.env.clone();
                e.generation += 1;
                e.previous_digest = Some(c.digest.clone());
                e
            }
            None => Envelope {
                format: journal::JOURNAL_FORMAT.to_string(),
                version: journal::JOURNAL_VERSION,
                machine_id: self.machine_id.clone(),
                generation: 1,
                previous_digest: None,
                payload_digest: String::new(),
                payload: Payload {
                    journal_state: JournalState::Clean,
                    transaction: None,
                    last_completed: None,
                    maintenance: None,
                    diagnostics: Vec::new(),
                },
            },
        };
        mutate(&mut env);
        if let Some(tx) = &mut env.payload.transaction {
            tx.updated_at_utc = self.now();
        }
        let live = env.payload.transaction.as_ref().map(|t| t.id.clone());
        env.payload.diagnostics =
            journal::truncate_diagnostics(&env.payload.diagnostics, live.as_deref());
        codec::seal(&mut env);
        let report = self.store.commit(&env).map_err(EngineError::Store)?;
        let bytes = codec::encode(&env);
        *self.current.borrow_mut() = Some(ValidCandidate {
            path: self.store.primary_path(),
            kind: CandidateKind::Primary,
            env,
            bytes,
            digest: report.digest,
        });
        Ok(())
    }

    /// Acquire the machine lock. `Ok(None)` means busy (timeout); other lock
    /// failures are infrastructure errors (fail-closed).
    fn acquire(&self) -> Result<Option<(LockGuard, Acquired)>, EngineError> {
        match self.lock.acquire(LOCK_BUDGET) {
            Ok(v) => Ok(Some(v)),
            Err(LockError::Timeout) => Ok(None),
            Err(e) => Err(EngineError::Lock(e)),
        }
    }

    /// Reconcile the journal and adopt the highest unambiguous valid
    /// generation. This is also the mandatory rescan after WAIT_ABANDONED.
    fn load(&self) -> Result<(), EngineError> {
        let rec = self.store.reconcile().map_err(EngineError::Store)?;
        *self.current.borrow_mut() = rec.current;
        Ok(())
    }

    fn family_error(
        &self,
        e: &Entry,
        phase: &str,
        api: &str,
        windows_status: Option<u32>,
        retryable: bool,
        attempts: u32,
        expected: Option<String>,
        observed: Option<String>,
        message: String,
    ) -> FamilyError {
        FamilyError {
            adapter_guid: e.adapter_guid.clone(),
            name_hint: e.name_hint.clone(),
            family: e.family,
            phase: phase.to_string(),
            api: api.to_string(),
            windows_status,
            retryable,
            attempts,
            expected_fingerprint: expected,
            observed_fingerprint: observed,
            at_utc: self.now(),
            message,
        }
    }

    // ---- takeover (T0–T7) ----------------------------------------------------

    pub fn takeover(
        &self,
        selected: &[String],
        plan: &DesiredPlan,
    ) -> Result<EngineReport, EngineError> {
        self.errors.borrow_mut().clear();
        let Some((guard, acquired)) = self.acquire()? else {
            return Ok(self.report(Outcome::Busy));
        };
        self.load()?;
        let _ = acquired; // Abandoned: load() above is the mandatory rescan.
        // Unresolved debt (any live transaction) blocks a new takeover.
        if self.tx().is_some() {
            return Ok(self.report(Outcome::Busy));
        }

        // T2: capture ALL baselines for every selected adapter/family.
        let mut guids: Vec<String> = selected.to_vec();
        guids.sort();
        guids.dedup();
        if guids.is_empty() {
            return Ok(self.report(Outcome::Refused));
        }
        let identities = self.backend.adapters().map_err(EngineError::Capture)?;
        let now = self.now();
        let mut entries: Vec<Entry> = Vec::new();
        for guid in &guids {
            let Some(ident) = identities.iter().find(|i| &i.adapter_guid == guid) else {
                return Ok(self.report(Outcome::Refused));
            };
            for family in [Family::Ipv4, Family::Ipv6] {
                let cap = self.backend.capability(guid, family).map_err(EngineError::Capture)?;
                if !cap.family_supported {
                    continue; // no mutation of an explicitly unsupported family
                }
                match self.backend.capture(guid, family) {
                    Ok(snap) => entries.push(make_entry(ident, family, &snap, &now, 1)),
                    Err(ce) => {
                        let fe = FamilyError {
                            adapter_guid: guid.clone(),
                            name_hint: ident.name_hint.clone(),
                            family,
                            phase: "capture".to_string(),
                            api: "GetInterfaceDnsSettings".to_string(),
                            windows_status: None,
                            retryable: capture_retryable(&ce),
                            attempts: 0,
                            expected_fingerprint: None,
                            observed_fingerprint: None,
                            at_utc: self.now(),
                            message: ce.to_string(),
                        };
                        self.record(fe);
                        return Ok(self.report(Outcome::Refused)); // zero writes
                    }
                }
            }
        }
        if entries.is_empty() {
            return Ok(self.report(Outcome::Unsupported));
        }
        if !(self.readiness)(plan) {
            return Ok(self.report(Outcome::Refused));
        }

        // T3: commit the entire transaction, immutable originals and plan
        // with a full barrier — replayable even if no write ever happens.
        let tx = Transaction {
            id: journal::new_uuid(),
            created_at_utc: now.clone(),
            updated_at_utc: now.clone(),
            reason: Reason::Takeover,
            phase: Phase::Preparing,
            owner: self.owner.clone(),
            epoch: 1,
            admission: Admission::Open,
            desired: plan.clone(),
            service_instance_id: self.service_instance_id.clone(),
            registered_at_utc: now.clone(),
            entries,
        };
        self.commit_next(|env| {
            env.payload.journal_state = JournalState::Owned;
            env.payload.transaction = Some(tx.clone());
        })?;
        self.hook(DeathPoint::TransactionCommitted);

        // T4–T6: deterministic GUID order, v4 then v6 per GUID.
        let steps: Vec<ApplyStep> = (0..self.tx().unwrap().entries.len())
            .map(|idx| ApplyStep { idx, kind: OperationKind::Apply, expect_original: true })
            .collect();
        let mut ok = self.run_apply(&steps, Phase::Applying, DeathPoint::ApplyIntentFlushed)?;
        if ok {
            ok = self.final_verify_apply()?;
        }
        if ok {
            // T7: active marker, then acknowledge.
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    tx.phase = Phase::Active;
                }
            })?;
            self.hook(DeathPoint::ActiveMarkerFlushed);
            return Ok(self.report(Outcome::Active));
        }
        // Any family failure rolls the ENTIRE attempted transaction back to
        // the immutable originals.
        let mut guard_opt = Some(guard);
        self.restore_core(&mut guard_opt)
    }

    /// T4–T6 (shared with C3). Returns false on the first family failure;
    /// admission is already closed and the failure durably recorded.
    fn run_apply(
        &self,
        steps: &[ApplyStep],
        phase: Phase,
        intent_hook: DeathPoint,
    ) -> Result<bool, EngineError> {
        for step in steps {
            let tx = self.tx().unwrap();
            if tx.admission != Admission::Open || tx.owner.owner_id != self.owner.owner_id {
                return Ok(false);
            }
            let e = tx.entries[step.idx].clone();
            let before = match self.backend.readback(&e.adapter_guid, e.family) {
                Ok(s) => s,
                Err(ce) => {
                    let fe = self.family_error(
                        &e, "apply-before", "GetInterfaceDnsSettings", None,
                        capture_retryable(&ce), 0, None, None, ce.to_string(),
                    );
                    self.record(fe);
                    let msg = ce.to_string();
                    self.commit_next(|env| {
                        if let Some(tx) = &mut env.payload.transaction {
                            let e = &mut tx.entries[step.idx];
                            e.state = EntryState::Failed;
                            e.retry.last_error = Some(msg.clone());
                            tx.admission = Admission::Closed;
                        }
                        self.diagnostic(env, "apply-readback-failure", msg.clone());
                    })?;
                    return Ok(false);
                }
            };
            let expected = if step.expect_original {
                e.original.clone()
            } else {
                e.intended.clone().unwrap_or_else(|| e.original.clone())
            };
            if !before.configured_eq(&expected) {
                // External divergence before the write: conflict, never
                // recapture (§5.2 C1 / §5.4).
                let fe = self.family_error(
                    &e, "apply-before", "GetInterfaceDnsSettings", None, false, 0,
                    Some(expected.fingerprint()), Some(before.fingerprint()),
                    "configured state diverged from the committed baseline".to_string(),
                );
                self.record(fe);
                let obs = observation(&before, &self.now());
                self.commit_next(|env| {
                    if let Some(tx) = &mut env.payload.transaction {
                        let e = &mut tx.entries[step.idx];
                        e.state = EntryState::Conflict;
                        e.last_observed = Some(obs.clone());
                        tx.admission = Admission::Closed;
                    }
                    self.diagnostic(env, "apply-conflict", "external divergence before write".into());
                })?;
                return Ok(false);
            }

            let target = plan_image(&e.adapter_guid, e.family, &tx.desired, &before, &self.now());
            let target_fp = target.fingerprint();

            if before.configured_eq(&target) {
                // Already at target: verify without writing.
                let generation = self.next_gen();
                let now = self.now();
                let op = Operation {
                    id: journal::new_uuid(),
                    request_id: journal::new_uuid(),
                    ordinal: next_ordinal(&e),
                    kind: step.kind,
                    state: OperationState::Verified,
                    before: before.clone(),
                    before_fingerprint: before.fingerprint(),
                    target: target.clone(),
                    target_fingerprint: target_fp.clone(),
                    write_mask: vec![WriteFacet::Nameserver, WriteFacet::ServerProperties],
                    intent_generation: generation,
                    api_started_at: None,
                    api_finished_at: None,
                    windows_status: None,
                    observed_after: Some(before.clone()),
                    observed_fingerprint: Some(before.fingerprint()),
                    attempts: 0,
                    error: None,
                };
                let obs = observation(&before, &now);
                self.commit_next(|env| {
                    if let Some(tx) = &mut env.payload.transaction {
                        tx.phase = phase;
                        let e = &mut tx.entries[step.idx];
                        e.operations.push(op.clone());
                        e.state = EntryState::Applied;
                        e.intended = Some(target.clone());
                        e.intended_fingerprint = Some(target_fp.clone());
                        e.applied_fingerprint = Some(target_fp.clone());
                        e.verification = Some(Verification {
                            kind: VerificationKind::Applied,
                            fingerprint: target_fp.clone(),
                            observed_at_utc: now.clone(),
                            generation: generation,
                        });
                        e.last_observed = Some(obs.clone());
                    }
                })?;
                self.hook(DeathPoint::AppliedMarkerFlushed);
                continue;
            }

            // Durable per-call intent BEFORE the setter call (§3.2).
            let request_id = journal::new_uuid();
            let generation = self.next_gen();
            let op = Operation {
                id: journal::new_uuid(),
                request_id: request_id.clone(),
                ordinal: next_ordinal(&e),
                kind: step.kind,
                state: OperationState::Intent,
                before: before.clone(),
                before_fingerprint: before.fingerprint(),
                target: target.clone(),
                target_fingerprint: target_fp.clone(),
                write_mask: vec![WriteFacet::Nameserver, WriteFacet::ServerProperties],
                intent_generation: generation,
                api_started_at: None,
                api_finished_at: None,
                windows_status: None,
                observed_after: None,
                observed_fingerprint: None,
                attempts: 0,
                error: None,
            };
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    tx.phase = phase;
                    let e = &mut tx.entries[step.idx];
                    e.operations.push(op.clone());
                    e.state = EntryState::ApplyIntent;
                    e.intended = Some(target.clone());
                    e.intended_fingerprint = Some(target_fp.clone());
                }
            })?;
            self.hook(intent_hook);

            // T5: one setter call; read configured state even on API error.
            self.hook(DeathPoint::BeforeSetterCall);
            let set_res =
                self.setter.set(&request_id, &e.adapter_guid, e.family, &SetterImage::from_target(&target));
            self.hook(DeathPoint::AfterSetterCall);
            let after = self.backend.readback(&e.adapter_guid, e.family);
            self.hook(DeathPoint::AfterReadback);

            let now = self.now();
            let status = set_res.as_ref().err().map(|se| se.status).unwrap_or(0);
            let matched = matches!(&after, Ok(a) if a.configured_eq(&target));
            if matched {
                let after = after.unwrap();
                let obs_fp = after.fingerprint();
                let obs = observation(&after, &now);
                let vgen = self.next_gen();
                let err_note = set_res.as_ref().err().map(|se| {
                    format!("setter status {} but configured readback matches target", se.status)
                });
                self.commit_next(|env| {
                    if let Some(tx) = &mut env.payload.transaction {
                        let e = &mut tx.entries[step.idx];
                        let op = e.operations.last_mut().unwrap();
                        op.state = OperationState::Verified;
                        op.api_started_at = Some(now.clone());
                        op.api_finished_at = Some(now.clone());
                        op.windows_status = Some(status);
                        op.observed_after = Some(after.clone());
                        op.observed_fingerprint = Some(obs_fp.clone());
                        op.attempts = 1;
                        op.error = err_note.clone();
                        e.state = EntryState::Applied;
                        e.applied_fingerprint = Some(target_fp.clone());
                        e.verification = Some(Verification {
                            kind: VerificationKind::Applied,
                            fingerprint: target_fp.clone(),
                            observed_at_utc: now.clone(),
                            generation: vgen,
                        });
                        e.last_observed = Some(obs.clone());
                    }
                    if let Some(note) = &err_note {
                        self.diagnostic(env, "setter-error-readback-match", note.clone());
                    }
                })?;
                self.hook(DeathPoint::AppliedMarkerFlushed);
            } else {
                let (obs_after, obs_fp, msg, retryable) = match (&set_res, &after) {
                    (Err(se), Ok(a)) => (
                        Some(a.clone()), Some(a.fingerprint()),
                        format!("setter failed: {se}"), se.retryable(),
                    ),
                    (Err(se), Err(ce)) => (
                        None, None,
                        format!("setter failed: {se}; readback failed: {ce}"), se.retryable(),
                    ),
                    (Ok(()), Ok(a)) => (
                        Some(a.clone()), Some(a.fingerprint()),
                        "configured readback diverges from target".to_string(), true,
                    ),
                    (Ok(()), Err(ce)) => (
                        None, None, format!("readback failed: {ce}"), true,
                    ),
                };
                let fe = self.family_error(
                    &e, "apply", "SetInterfaceDnsSettings",
                    set_res.as_ref().err().map(|se| se.status), retryable, 1,
                    Some(target_fp.clone()), obs_fp.clone(), msg.clone(),
                );
                self.record(fe);
                let obs = obs_after.as_ref().map(|s| observation(s, &now));
                self.commit_next(|env| {
                    if let Some(tx) = &mut env.payload.transaction {
                        let e = &mut tx.entries[step.idx];
                        let op = e.operations.last_mut().unwrap();
                        op.state = OperationState::Failed;
                        op.api_started_at = Some(now.clone());
                        op.api_finished_at = Some(now.clone());
                        op.windows_status = Some(status);
                        op.observed_after = obs_after.clone();
                        op.observed_fingerprint = obs_fp.clone();
                        op.attempts = 1;
                        op.error = Some(msg.clone());
                        e.state = EntryState::Failed;
                        e.retry.last_error = Some(msg.clone());
                        e.last_observed = obs.clone();
                        tx.admission = Admission::Closed;
                    }
                    self.diagnostic(env, "apply-failure", msg.clone());
                })?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// T7 / C4 final verification: re-read every target and recheck readiness.
    /// On failure admission is closed and the caller rolls back.
    fn final_verify_apply(&self) -> Result<bool, EngineError> {
        let tx = self.tx().unwrap();
        let mut diverged: Vec<usize> = Vec::new();
        for (idx, e) in tx.entries.iter().enumerate() {
            let want = e.intended.clone().unwrap();
            match self.backend.readback(&e.adapter_guid, e.family) {
                Ok(a) if a.configured_eq(&want) => {}
                Ok(a) => {
                    let fe = self.family_error(
                        e, "final-verify", "GetInterfaceDnsSettings", None, true, 1,
                        Some(want.fingerprint()), Some(a.fingerprint()),
                        "final verification race: configured state diverged".to_string(),
                    );
                    self.record(fe);
                    diverged.push(idx);
                }
                Err(ce) => {
                    let fe = self.family_error(
                        e, "final-verify", "GetInterfaceDnsSettings", None,
                        capture_retryable(&ce), 1, Some(want.fingerprint()), None, ce.to_string(),
                    );
                    self.record(fe);
                    diverged.push(idx);
                }
            }
        }
        let ready = (self.readiness)(&tx.desired);
        if diverged.is_empty() && ready {
            return Ok(true);
        }
        self.commit_next(|env| {
            if let Some(tx) = &mut env.payload.transaction {
                tx.admission = Admission::Closed;
                for idx in &diverged {
                    tx.entries[*idx].state = EntryState::Failed;
                }
            }
            if !ready {
                self.diagnostic(env, "readiness-lost", "readiness recheck failed at final verification".into());
            }
        })?;
        Ok(false)
    }

    // ---- reconfigure (C0–C4) -------------------------------------------------

    pub fn reconfigure(
        &self,
        selected: &[String],
        new_plan: &DesiredPlan,
    ) -> Result<EngineReport, EngineError> {
        self.errors.borrow_mut().clear();
        let Some((guard, _)) = self.acquire()? else {
            return Ok(self.report(Outcome::Busy));
        };
        self.load()?;
        let Some(tx) = self.tx() else {
            return Ok(self.report(Outcome::Refused));
        };
        if tx.owner.owner_id != self.owner.owner_id {
            return Ok(self.report(Outcome::Busy));
        }
        if tx.phase != Phase::Active || tx.admission != Admission::Open {
            return Ok(self.report(Outcome::Refused));
        }
        // Refuse incoherent reconfigure with unresolved debt.
        if tx.entries.iter().any(|e| e.state != EntryState::Applied) {
            return Ok(self.report(Outcome::Refused));
        }
        // At the per-entry operation limit: refuse, require restore/new tx.
        if tx.entries.iter().any(|e| e.operations.len() >= MAX_OPERATIONS_PER_ENTRY) {
            return Ok(self.report(Outcome::Refused));
        }

        let mut guids: Vec<String> = selected.to_vec();
        guids.sort();
        guids.dedup();
        let mut existing: Vec<String> = tx.entries.iter().map(|e| e.adapter_guid.clone()).collect();
        existing.sort();
        existing.dedup();
        let removed: Vec<String> =
            existing.iter().filter(|g| !guids.contains(g)).cloned().collect();
        let added: Vec<String> =
            guids.iter().filter(|g| !existing.contains(g)).cloned().collect();
        let mut guard_opt = Some(guard);

        // C4: restore journaled adapters no longer selected BEFORE releasing
        // them; missing/unrestorable entries remain debt.
        if !removed.is_empty() {
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    tx.phase = Phase::Quiescing;
                }
            })?;
            let indices: Vec<usize> = tx
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| removed.contains(&e.adapter_guid))
                .map(|(i, _)| i)
                .collect();
            let overall_deadline = self.clock.now_ms() + 30_000;
            for idx in indices {
                let cont = self.restore_entry(idx, overall_deadline, &mut guard_opt, true)?;
                if !cont {
                    return Ok(self.report(Outcome::Pending));
                }
            }
            let tx = self.tx().unwrap();
            let mut debt = false;
            let keep: Vec<Entry> = tx
                .entries
                .iter()
                .filter(|e| {
                    if removed.contains(&e.adapter_guid) {
                        if e.state == EntryState::RestoredVerified {
                            false
                        } else {
                            debt = true;
                            true
                        }
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();
            if debt {
                self.commit_next(|env| {
                    env.payload.journal_state = JournalState::RecoveryPending;
                    if let Some(tx) = &mut env.payload.transaction {
                        tx.phase = Phase::Pending;
                        tx.admission = Admission::Closed;
                        tx.entries = keep.clone();
                    }
                })?;
                // C3: any failure closes admission and restores ORIGINAL
                // across the whole transaction — retained entries included,
                // so background retry can drive the rollback to completion.
                return self.restore_core(&mut guard_opt);
            }
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    tx.entries = keep.clone();
                }
            })?;
        }

        // Newly selected GUIDs: fresh capture, committed BEFORE first write.
        let identities = self.backend.adapters().map_err(EngineError::Capture)?;
        let now = self.now();
        let new_rev = tx.entries.first().map(|e| e.plan_revision + 1).unwrap_or(1);
        let mut new_entries: Vec<Entry> = Vec::new();
        for guid in &added {
            let Some(ident) = identities.iter().find(|i| &i.adapter_guid == guid) else {
                return Ok(self.report(Outcome::Refused));
            };
            for family in [Family::Ipv4, Family::Ipv6] {
                let cap = self.backend.capability(guid, family).map_err(EngineError::Capture)?;
                if !cap.family_supported {
                    continue;
                }
                match self.backend.capture(guid, family) {
                    Ok(snap) => new_entries.push(make_entry(ident, family, &snap, &now, new_rev)),
                    Err(ce) => {
                        let fe = FamilyError {
                            adapter_guid: guid.clone(),
                            name_hint: ident.name_hint.clone(),
                            family,
                            phase: "capture".to_string(),
                            api: "GetInterfaceDnsSettings".to_string(),
                            windows_status: None,
                            retryable: capture_retryable(&ce),
                            attempts: 0,
                            expected_fingerprint: None,
                            observed_fingerprint: None,
                            at_utc: self.now(),
                            message: ce.to_string(),
                        };
                        self.record(fe);
                        return Ok(self.report(Outcome::Refused)); // zero writes
                    }
                }
            }
        }
        if !new_entries.is_empty() {
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    for ne in new_entries.clone() {
                        tx.entries.push(ne);
                    }
                    tx.entries.sort_by(|a, b| {
                        a.adapter_guid.cmp(&b.adapter_guid).then(family_rank(a.family).cmp(&family_rank(b.family)))
                    });
                }
            })?;
        }

        // C1: retained entries must still equal the committed Yeager image.
        let tx = self.tx().unwrap();
        let mut steps: Vec<ApplyStep> = Vec::new();
        for (idx, e) in tx.entries.iter().enumerate() {
            let is_added = added.contains(&e.adapter_guid);
            if !is_added {
                let before = match self.backend.readback(&e.adapter_guid, e.family) {
                    Ok(s) => s,
                    Err(ce) => {
                        let fe = self.family_error(
                            e, "reconfigure-before", "GetInterfaceDnsSettings", None,
                            capture_retryable(&ce), 0, None, None, ce.to_string(),
                        );
                        self.record(fe);
                        let msg = ce.to_string();
                        self.commit_next(|env| {
                            if let Some(tx) = &mut env.payload.transaction {
                                let e = &mut tx.entries[idx];
                                e.state = EntryState::Failed;
                                e.retry.last_error = Some(msg.clone());
                                tx.admission = Admission::Closed;
                            }
                        })?;
                        return self.restore_core(&mut guard_opt);
                    }
                };
                let committed = e.intended.clone().unwrap();
                if !before.configured_eq(&committed) {
                    let fe = self.family_error(
                        e, "reconfigure-before", "GetInterfaceDnsSettings", None, false, 0,
                        Some(committed.fingerprint()), Some(before.fingerprint()),
                        "foreign divergence from the committed Yeager image".to_string(),
                    );
                    self.record(fe);
                    let obs = observation(&before, &self.now());
                    self.commit_next(|env| {
                        if let Some(tx) = &mut env.payload.transaction {
                            let e = &mut tx.entries[idx];
                            e.state = EntryState::Conflict;
                            e.last_observed = Some(obs.clone());
                            tx.admission = Admission::Closed;
                        }
                        self.diagnostic(env, "reconfigure-conflict", "foreign divergence; never recaptured".into());
                    })?;
                    // C3: restore ORIGINAL across the whole transaction.
                    return self.restore_core(&mut guard_opt);
                }
            }
            steps.push(ApplyStep {
                idx,
                kind: if is_added { OperationKind::Apply } else { OperationKind::Reconfigure },
                expect_original: is_added,
            });
        }

        // C2: commit the next plan_revision AND the new desired plan as the
        // durable intent BEFORE any setter call, so run_apply builds each
        // family's target from the new plan (not the previous revision).
        self.commit_next(|env| {
            if let Some(tx) = &mut env.payload.transaction {
                for e in &mut tx.entries {
                    e.plan_revision = new_rev;
                }
                tx.desired = new_plan.clone();
                tx.phase = Phase::Reconfiguring;
            }
        })?;

        // C3: apply/readback/persist as T4–T7.
        let mut ok =
            self.run_apply(&steps, Phase::Reconfiguring, DeathPoint::ReconfigureIntentFlushed)?;
        if ok {
            ok = self.final_verify_apply()?;
        }
        if !ok {
            return self.restore_core(&mut guard_opt);
        }

        // C4: final verification passed — publish previous_committed (the
        // pre-reconfigure image, retained for audit). The desired plan was
        // committed at C2; the original baseline survives every revision.
        self.commit_next(|env| {
            if let Some(tx) = &mut env.payload.transaction {
                for e in &mut tx.entries {
                    if !added.contains(&e.adapter_guid) {
                        if let Some(op) = e.operations.last() {
                            e.previous_committed = Some(op.before.clone());
                            e.previous_fingerprint = Some(op.before_fingerprint.clone());
                        }
                    }
                }
                tx.phase = Phase::Active;
            }
        })?;
        self.hook(DeathPoint::ActiveMarkerFlushed);
        Ok(self.report(Outcome::Active))
    }

    // ---- restore (R0–R6) -----------------------------------------------------

    pub fn restore(&self) -> Result<EngineReport, EngineError> {
        self.errors.borrow_mut().clear();
        let Some((guard, _)) = self.acquire()? else {
            return Ok(self.report(Outcome::Busy));
        };
        self.load()?;
        let Some(tx) = self.tx() else {
            // Clean journal: idempotent success; best-effort cleanup of
            // obsolete candidates after the tombstone's volume barrier.
            if let Some(c) = self.current.borrow().as_ref() {
                let env = c.env.clone();
                let _ = self.store.cleanup_obsolete(&env);
            }
            return Ok(self.report(Outcome::VerifiedRestored));
        };
        if tx.owner.owner_id != self.owner.owner_id {
            // Unknown owner: no writes (owner-identity takeover is U04).
            return Ok(self.report(Outcome::Busy));
        }
        let mut guard_opt = Some(guard);
        self.restore_core(&mut guard_opt)
    }

    fn restore_core(&self, guard: &mut Option<LockGuard>) -> Result<EngineReport, EngineError> {
        let overall_deadline = self.clock.now_ms() + 30_000;
        if self.tx().is_none() {
            return Ok(self.report(Outcome::VerifiedRestored));
        }
        // R0: close admission, bump epoch, restoring phase — full barrier,
        // then reload regardless of the prior phase (even Active).
        self.commit_next(|env| {
            if let Some(tx) = &mut env.payload.transaction {
                tx.admission = Admission::Closed;
                tx.epoch += 1;
                tx.phase = Phase::Restoring;
            }
            env.payload.journal_state = JournalState::Restoring;
        })?;
        self.hook(DeathPoint::RestoreEpochFlushed);

        let n = self.tx().map(|t| t.entries.len()).unwrap_or(0);
        for idx in 0..n {
            if self.tx().is_none() {
                break;
            }
            let cont = self.restore_entry(idx, overall_deadline, guard, true)?;
            if !cont {
                return Ok(self.report(Outcome::Pending));
            }
        }
        self.finish_restore()
    }

    /// R1–R5 for one entry. Foreground: ≤3 attempts, 250 ms then 1 s delays,
    /// 10 s per-family / 30 s overall budgets, release/reacquire/reload/
    /// reclassify across delays. Background: a single attempt per pass.
    /// Returns false only when the lock cannot be reacquired (abort).
    fn restore_entry(
        &self,
        idx: usize,
        overall_deadline: i64,
        guard: &mut Option<LockGuard>,
        foreground: bool,
    ) -> Result<bool, EngineError> {
        let family_deadline = self.clock.now_ms() + 10_000;
        let max_attempts: u32 = if foreground { 3 } else { 1 };
        let mut attempts: u32 = 0;
        loop {
            let Some(tx) = self.tx() else { return Ok(true); };
            if idx >= tx.entries.len() {
                return Ok(true);
            }
            let e = tx.entries[idx].clone();
            if e.state == EntryState::RestoredVerified {
                return Ok(true);
            }

            // R1: query even disconnected adapters; missing/unqueryable is
            // deferred, never restored.
            let current = match self.backend.readback(&e.adapter_guid, e.family) {
                Ok(s) => s,
                Err(ce) => {
                    let fe = self.family_error(
                        &e, "restore-readback", "GetInterfaceDnsSettings", None,
                        capture_retryable(&ce), attempts, None, None, ce.to_string(),
                    );
                    self.record(fe);
                    let next = utc_string(self.clock.now_ms() + background_delay_ms(attempts.max(1)));
                    let msg = ce.to_string();
                    self.commit_next(|env| {
                        if let Some(tx) = &mut env.payload.transaction {
                            let e = &mut tx.entries[idx];
                            e.state = EntryState::Deferred;
                            e.retry = RetryState {
                                attempts,
                                next_attempt_utc: Some(next.clone()),
                                last_error: Some(msg.clone()),
                            };
                        }
                    })?;
                    return Ok(true);
                }
            };

            // Settle an interrupted intent (§5.4): current==target proves the
            // call ran — mark the SAME request verified, never call again.
            // current==before means the call may not have run.
            if let Some(op) = tx.entries[idx].operations.last().cloned() {
                if op.state == OperationState::Intent || op.state == OperationState::CallReturned {
                    if current.configured_eq(&op.target) {
                        let now = self.now();
                        let generation = self.next_gen();
                        let to_original = op.kind == OperationKind::Restore
                            && current.configured_eq(&e.original);
                        let obs = observation(&current, &now);
                        let ofp = current.fingerprint();
                        self.commit_next(|env| {
                            if let Some(tx) = &mut env.payload.transaction {
                                let e = &mut tx.entries[idx];
                                let op = e.operations.last_mut().unwrap();
                                op.state = OperationState::Verified;
                                op.observed_after = Some(current.clone());
                                op.observed_fingerprint = Some(ofp.clone());
                                op.api_finished_at = Some(now.clone());
                                if to_original {
                                    e.state = EntryState::RestoredVerified;
                                    e.verification = Some(Verification {
                                        kind: VerificationKind::Original,
                                        fingerprint: e.original_fingerprint.clone(),
                                        observed_at_utc: now.clone(),
                                        generation: generation,
                                    });
                                    e.intended = None;
                                    e.intended_fingerprint = None;
                                    e.applied_fingerprint = None;
                                    e.last_observed = Some(obs.clone());
                                    e.retry = reset_retry();
                                }
                            }
                        })?;
                        if to_original {
                            self.hook(DeathPoint::RestoredMarkerFlushed);
                            return Ok(true);
                        }
                    } else if current.configured_eq(&op.before) {
                        self.commit_next(|env| {
                            if let Some(tx) = &mut env.payload.transaction {
                                let op = tx.entries[idx].operations.last_mut().unwrap();
                                op.state = OperationState::Deferred;
                            }
                        })?;
                    }
                }
            }

            // R2: classify against the original and every committed/intent
            // image. Original match verifies without a setter call; foreign
            // divergence is a conflict with no write.
            let tx = self.tx().unwrap();
            let e = tx.entries[idx].clone();
            match classify_restore(&current, &e) {
                RestoreClass::AlreadyOriginal => {
                    let now = self.now();
                    let generation = self.next_gen();
                    let obs = observation(&current, &now);
                    self.commit_next(|env| {
                        if let Some(tx) = &mut env.payload.transaction {
                            let e = &mut tx.entries[idx];
                            e.state = EntryState::RestoredVerified;
                            e.verification = Some(Verification {
                                kind: VerificationKind::Original,
                                fingerprint: e.original_fingerprint.clone(),
                                observed_at_utc: now.clone(),
                                generation: generation,
                            });
                            e.intended = None;
                            e.intended_fingerprint = None;
                            e.applied_fingerprint = None;
                            e.last_observed = Some(obs.clone());
                            e.retry = reset_retry();
                        }
                    })?;
                    self.hook(DeathPoint::RestoredMarkerFlushed);
                    return Ok(true);
                }
                RestoreClass::Foreign => {
                    let fe = self.family_error(
                        &e, "restore-classify", "GetInterfaceDnsSettings", None, false,
                        attempts, Some(e.original_fingerprint.clone()),
                        Some(current.fingerprint()),
                        "foreign configuration: conflict, no write".to_string(),
                    );
                    self.record(fe);
                    let obs = observation(&current, &self.now());
                    self.commit_next(|env| {
                        if let Some(tx) = &mut env.payload.transaction {
                            let e = &mut tx.entries[idx];
                            e.state = EntryState::Conflict;
                            e.last_observed = Some(obs.clone());
                        }
                        self.diagnostic(env, "restore-conflict", "foreign image; original retained".into());
                    })?;
                    return Ok(true);
                }
                RestoreClass::Known | RestoreClass::PartialKnown => {}
            }

            // Budgets and attempt cap before any new call.
            let now_ms = self.clock.now_ms();
            if attempts >= max_attempts || now_ms >= family_deadline || now_ms >= overall_deadline {
                let next = utc_string(now_ms + background_delay_ms(attempts.max(1)));
                self.commit_next(|env| {
                    if let Some(tx) = &mut env.payload.transaction {
                        let e = &mut tx.entries[idx];
                        if e.state != EntryState::Failed {
                            e.state = EntryState::Failed;
                        }
                        e.retry.attempts = attempts;
                        e.retry.next_attempt_utc = Some(next.clone());
                    }
                })?;
                return Ok(true);
            }

            // R3: restoring phase + restore intent (before=current,
            // target=immutable original), full barrier before the call.
            let request_id = journal::new_uuid();
            let generation = self.next_gen();
            let op = Operation {
                id: journal::new_uuid(),
                request_id: request_id.clone(),
                ordinal: next_ordinal(&e),
                kind: OperationKind::Restore,
                state: OperationState::Intent,
                before: current.clone(),
                before_fingerprint: current.fingerprint(),
                target: e.original.clone(),
                target_fingerprint: e.original_fingerprint.clone(),
                write_mask: vec![WriteFacet::Nameserver, WriteFacet::ServerProperties],
                intent_generation: generation,
                api_started_at: None,
                api_finished_at: None,
                windows_status: None,
                observed_after: None,
                observed_fingerprint: None,
                attempts: 0,
                error: None,
            };
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    let e = &mut tx.entries[idx];
                    e.operations.push(op.clone());
                    e.state = EntryState::RestoreIntent;
                }
            })?;
            self.hook(DeathPoint::RestoreIntentFlushed);

            // R4: exact setter call; fresh query even after an API error.
            self.hook(DeathPoint::BeforeRestoreCall);
            let res = self.setter.set(
                &request_id,
                &e.adapter_guid,
                e.family,
                &SetterImage::from_target(&e.original),
            );
            self.hook(DeathPoint::AfterRestoreCall);
            let after = self.backend.readback(&e.adapter_guid, e.family);
            self.hook(DeathPoint::AfterRestoreReadback);
            attempts += 1;
            let now = self.now();
            let status = res.as_ref().err().map(|se| se.status).unwrap_or(0);

            // R5: original equality => durable restored_verified.
            if let Ok(a) = &after {
                if a.configured_eq(&e.original) {
                    let generation = self.next_gen();
                    let obs = observation(a, &now);
                    let ofp = a.fingerprint();
                    let err_note = res.as_ref().err().map(|se| {
                        format!("setter status {} but configured readback matches original", se.status)
                    });
                    self.commit_next(|env| {
                        if let Some(tx) = &mut env.payload.transaction {
                            let e = &mut tx.entries[idx];
                            let op = e.operations.last_mut().unwrap();
                            op.state = OperationState::Verified;
                            op.api_started_at = Some(now.clone());
                            op.api_finished_at = Some(now.clone());
                            op.windows_status = Some(status);
                            op.observed_after = Some(a.clone());
                            op.observed_fingerprint = Some(ofp.clone());
                            op.attempts = attempts;
                            op.error = err_note.clone();
                            e.state = EntryState::RestoredVerified;
                            e.verification = Some(Verification {
                                kind: VerificationKind::Original,
                                fingerprint: e.original_fingerprint.clone(),
                                observed_at_utc: now.clone(),
                                generation: generation,
                            });
                            e.intended = None;
                            e.intended_fingerprint = None;
                            e.applied_fingerprint = None;
                            e.last_observed = Some(obs.clone());
                            e.retry = reset_retry();
                        }
                        if let Some(note) = &err_note {
                            self.diagnostic(env, "restore-error-readback-match", note.clone());
                        }
                    })?;
                    self.hook(DeathPoint::RestoredMarkerFlushed);
                    return Ok(true);
                }
            }

            // Mismatch/error: record, retain baseline, schedule retry.
            let (obs_after, obs_fp, msg, retryable) = match (&res, &after) {
                (Err(se), Ok(a)) => (
                    Some(a.clone()), Some(a.fingerprint()),
                    format!("restore setter failed: {se}"), se.retryable(),
                ),
                (Err(se), Err(ce)) => (
                    None, None,
                    format!("restore setter failed: {se}; readback failed: {ce}"), se.retryable(),
                ),
                (Ok(()), Ok(a)) => (
                    Some(a.clone()), Some(a.fingerprint()),
                    "restore readback diverges from original".to_string(), true,
                ),
                (Ok(()), Err(ce)) => (
                    None, None, format!("restore readback failed: {ce}"), true,
                ),
            };
            let fe = self.family_error(
                &e, "restore", "SetInterfaceDnsSettings",
                res.as_ref().err().map(|se| se.status), retryable, attempts,
                Some(e.original_fingerprint.clone()), obs_fp.clone(), msg.clone(),
            );
            self.record(fe);
            let next = utc_string(self.clock.now_ms() + background_delay_ms(attempts));
            let obs = obs_after.as_ref().map(|s| observation(s, &now));
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    let e = &mut tx.entries[idx];
                    let op = e.operations.last_mut().unwrap();
                    op.state = OperationState::Failed;
                    op.api_started_at = Some(now.clone());
                    op.api_finished_at = Some(now.clone());
                    op.windows_status = Some(status);
                    op.observed_after = obs_after.clone();
                    op.observed_fingerprint = obs_fp.clone();
                    op.attempts = attempts;
                    op.error = Some(msg.clone());
                    e.state = EntryState::Failed;
                    e.retry = RetryState {
                        attempts,
                        next_attempt_utc: Some(next.clone()),
                        last_error: Some(msg.clone()),
                    };
                    e.last_observed = obs.clone();
                }
                self.diagnostic(env, "restore-failure", msg.clone());
            })?;

            // Access denied / unsupported / conflict are NOT automatic write
            // retries; background schedule still applies for transient debt.
            if !foreground || !retryable || attempts >= max_attempts {
                return Ok(true);
            }
            let delay: i64 = if attempts == 1 { 250 } else { 1_000 };
            let now_ms = self.clock.now_ms();
            if now_ms + delay >= family_deadline || now_ms + delay >= overall_deadline {
                return Ok(true);
            }
            // Release the lock across the delay, then reacquire, reload and
            // reclassify. Never start a competing writer.
            *guard = None;
            self.clock.sleep_ms(delay as u64);
            match self.lock.acquire(LOCK_BUDGET) {
                Ok((g, acquired)) => {
                    *guard = Some(g);
                    self.load()?; // mandatory rescan (also on Abandoned)
                    let _ = acquired;
                    match self.tx() {
                        None => return Ok(true),
                        Some(tx) => {
                            if tx.owner.owner_id != self.owner.owner_id {
                                return Ok(false);
                            }
                        }
                    }
                }
                Err(LockError::Timeout) => return Ok(false),
                Err(e) => return Err(EngineError::Lock(e)),
            }
            // Loop: fresh readback + reclassification on the next iteration.
        }
    }

    /// R6: final configured-read sweep. All original => complete + durable
    /// clean tombstone + cleanup; otherwise recovery-pending with retained
    /// baselines and persisted retry schedules.
    fn finish_restore(&self) -> Result<EngineReport, EngineError> {
        let Some(tx) = self.tx() else {
            return Ok(self.report(Outcome::VerifiedRestored));
        };
        let mut all_original = true;
        let mut any_conflict = false;
        let mut observations: Vec<(usize, Option<Snapshot>)> = Vec::new();
        for (idx, e) in tx.entries.iter().enumerate() {
            match self.backend.readback(&e.adapter_guid, e.family) {
                Ok(s) if s.configured_eq(&e.original) => observations.push((idx, Some(s))),
                Ok(s) => {
                    all_original = false;
                    if e.state == EntryState::Conflict {
                        any_conflict = true;
                    }
                    observations.push((idx, Some(s)));
                }
                Err(_) => {
                    all_original = false;
                    observations.push((idx, None));
                }
            }
        }
        if all_original {
            let generation = self.next_gen();
            let now = self.now();
            let txid = tx.id.clone();
            self.commit_next(|env| {
                if let Some(tx) = &mut env.payload.transaction {
                    tx.phase = Phase::Complete;
                    for (idx, obs) in &observations {
                        let e = &mut tx.entries[*idx];
                        e.state = EntryState::RestoredVerified;
                        e.verification = Some(Verification {
                            kind: VerificationKind::Original,
                            fingerprint: e.original_fingerprint.clone(),
                            observed_at_utc: now.clone(),
                            generation: generation,
                        });
                        e.intended = None;
                        e.intended_fingerprint = None;
                        e.applied_fingerprint = None;
                        if let Some(s) = obs {
                            e.last_observed = Some(observation(s, &now));
                        }
                        e.retry = reset_retry();
                    }
                }
            })?;
            self.hook(DeathPoint::CompleteMarkerFlushed);
            let completed = Tombstone {
                transaction_id: txid,
                verified_at_utc: self.now(),
                completed_generation: self.next_gen(),
            };
            self.commit_next(|env| {
                env.payload.journal_state = JournalState::Clean;
                env.payload.transaction = None;
                env.payload.last_completed = Some(completed.clone());
            })?;
            self.hook(DeathPoint::TombstoneFlushed);
            if let Some(c) = self.current.borrow().as_ref() {
                let env = c.env.clone();
                let _ = self.store.cleanup_obsolete(&env);
            }
            Ok(self.report(Outcome::VerifiedRestored))
        } else {
            let now = self.now();
            self.commit_next(|env| {
                env.payload.journal_state = JournalState::RecoveryPending;
                if let Some(tx) = &mut env.payload.transaction {
                    tx.phase = Phase::Pending;
                    for (idx, obs) in &observations {
                        if let Some(s) = obs {
                            tx.entries[*idx].last_observed = Some(observation(s, &now));
                        }
                    }
                }
            })?;
            Ok(self.report(if any_conflict { Outcome::Conflict } else { Outcome::Pending }))
        }
    }

    // ---- background retry pass ----------------------------------------------

    /// One background wake pass: at most 3 due entries, one attempt each,
    /// persisted counts and next-attempt times. No lifetime expiry of debt.
    pub fn run_background_pass(&self) -> Result<EngineReport, EngineError> {
        self.errors.borrow_mut().clear();
        let Some((guard, _)) = self.acquire()? else {
            return Ok(self.report(Outcome::Busy));
        };
        self.load()?;
        let Some(tx) = self.tx() else {
            return Ok(self.report(Outcome::VerifiedRestored));
        };
        if tx.owner.owner_id != self.owner.owner_id {
            return Ok(self.report(Outcome::Busy));
        }
        let now = self.now();
        let due: Vec<usize> = tx
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                matches!(e.state, EntryState::Failed | EntryState::Deferred)
                    && e.retry
                        .next_attempt_utc
                        .as_deref()
                        .map(|t| t <= now.as_str())
                        .unwrap_or(true)
            })
            .map(|(i, _)| i)
            .collect();
        if due.is_empty() && tx.phase == Phase::Active {
            return Ok(self.report(Outcome::Active));
        }
        let mut guard_opt = Some(guard);
        let overall_deadline = self.clock.now_ms() + 30_000;
        for idx in due.into_iter().take(3) {
            let cont = self.restore_entry(idx, overall_deadline, &mut guard_opt, false)?;
            if !cont {
                return Ok(self.report(Outcome::Pending));
            }
        }
        self.finish_restore()
    }
}

fn family_rank(f: Family) -> u8 {
    match f {
        Family::Ipv4 => 0,
        Family::Ipv6 => 1,
    }
}

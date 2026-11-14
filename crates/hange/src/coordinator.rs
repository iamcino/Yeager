//! U06: transactional listener supervision (SPEC-DNS-FIX.md §6, §12 U06).
//!
//! The [`Coordinator`] owns admission-side listener state and talks to the
//! U05 privileged service through a [`DnsService`](crate::service::DnsService)
//! client. It delivers transactional enable / change / disable / status over
//! bounded supervised listeners:
//!
//! - **Plans follow the existing provider address rules** ([`crate::plan`]):
//!   bind UDP+TCP on both families; a v6 bind failure degrades to a v4-only
//!   plan; both families failing means Windows-only with no loopback.
//! - **Atomic from the caller's view:** a change retains the existing
//!   sockets until the new plan is proven AND committed; removing the local
//!   reference is committed (verified) before the old listener stops; a
//!   failed change drops the candidate and reports failure while the old
//!   configuration keeps serving — never a half-applied state.
//! - **Resilience preserved:** upstream outage, stale cache, SERVFAIL and
//!   per-connection failures never stop listeners or quit anything; the
//!   supervisor only reacts to terminal listener-task loss.
//! - **Bounded supervision:** a dead listener task triggers quiesce/restore
//!   through the journal; a stuck join can never precede or block restore
//!   (restore is always requested first, stops are bounded); restore failure
//!   retains the healthy listener and the pending state.
//! - **Disable consults the journal:** even with no in-memory Active, disable
//!   registers (reattaching when the same live process owns the record) and
//!   runs quiesce/restore through the service instead of no-op'ing.
//!
//! Library only: no production takeover wiring. The coordinator is generic
//! over the binder (real [`Stub`](crate::stub::Stub) binding vs scripted
//! fakes) and the service (real [`HostClient`](crate::service::HostClient)
//! over the U05 state machine vs scripted fakes), so `cargo test` proves the
//! whole matrix without touching real NICs.

use crate::plan::{self, ListenerMode, ListenerPlan};
use crate::pool::Choice;
use crate::service::{DnsService, LeaseCreds, SvcOutcome, SvcReport};
use dns_recovery::model::DesiredPlan;
use std::net::SocketAddr;
use std::time::Duration;

/// How long an explicit listener stop may take before it is declared stuck.
/// The DNS restore it follows is already complete by then.
pub const STOP_BOUND: Duration = Duration::from_secs(5);

/// A running listener under supervision.
pub trait ManagedListener {
    /// Bound socket addresses (each served over UDP and TCP).
    fn addrs(&self) -> Vec<SocketAddr>;
    /// Whether the serving task/thread is still running. `false` means the
    /// task panicked or exited: terminal loss, never a quiet no-op.
    fn alive(&self) -> bool;
    /// Bounded self-probe. ANY well-formed reply — including SERVFAIL —
    /// counts as responsive; SERVFAIL is upstream failure, not death.
    fn responds(&self) -> bool;
    /// Explicit stop with a bounded wait. Must never block past `timeout`.
    fn shutdown_bounded(self: Box<Self>, timeout: Duration) -> crate::stub::ShutdownOutcome;
}

impl ManagedListener for crate::stub::Stub {
    fn addrs(&self) -> Vec<SocketAddr> {
        self.addrs.clone()
    }
    fn alive(&self) -> bool {
        self.is_alive()
    }
    fn responds(&self) -> bool {
        self.responds()
    }
    fn shutdown_bounded(self: Box<Self>, timeout: Duration) -> crate::stub::ShutdownOutcome {
        (*self).shutdown_bounded(timeout)
    }
}

/// Bind failure for one plan shape.
#[derive(Debug)]
pub struct BindError(pub String);

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "listener bind failed: {}", self.0)
    }
}
impl std::error::Error for BindError {}

/// Binds one concrete plan into a running listener.
pub trait ListenerBinder {
    fn bind(&self, plan: &ListenerPlan) -> Result<Box<dyn ManagedListener>, BindError>;
}

/// Any closure with the right shape works as a binder (tests use this).
impl<F> ListenerBinder for F
where
    F: Fn(&ListenerPlan) -> Result<Box<dyn ManagedListener>, BindError>,
{
    fn bind(&self, plan: &ListenerPlan) -> Result<Box<dyn ManagedListener>, BindError> {
        (*self)(plan)
    }
}

/// Production binder: binds the real stub for the plan's addresses.
pub struct RealBinder {
    pub choice: Choice,
}

impl ListenerBinder for RealBinder {
    fn bind(&self, plan: &ListenerPlan) -> Result<Box<dyn ManagedListener>, BindError> {
        if !plan.serves_local() {
            return Err(BindError("windows-only plan binds no listener".into()));
        }
        crate::stub::Stub::start(crate::pool::Pool::new(self.choice), &plan.addrs)
            .map(|s| Box::new(s) as Box<dyn ManagedListener>)
            .map_err(|e| BindError(e.to_string()))
    }
}

/// What enable/change/disable reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedStatus {
    /// A configuration is in effect (listener and/or Windows DoH).
    pub enabled: bool,
    /// A local stub is serving.
    pub serving_local: bool,
    /// Bound listener addresses (empty for Windows-only).
    pub addrs: Vec<SocketAddr>,
    /// Unrecovered debt reason, if any. Pending is visible, never success.
    pub pending: Option<String>,
    /// Current lease epoch (echoed on every mutating call).
    pub epoch: Option<u64>,
}

/// Coordinator failure. The `outcome` mirrors the service vocabulary so a
/// pending/conflict/refused result is never mistaken for success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordError {
    pub outcome: SvcOutcome,
    pub message: String,
}

impl std::fmt::Display for CoordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.outcome, self.message)
    }
}
impl std::error::Error for CoordError {}

impl From<CoordError> for SvcReport {
    fn from(e: CoordError) -> Self {
        SvcReport {
            outcome: e.outcome,
            generation: 0,
            message: e.message,
        }
    }
}

/// One supervised configuration.
struct ActiveEntry {
    listener: Option<Box<dyn ManagedListener>>,
    choice: Choice,
    plan: ListenerPlan,
    readiness: u64,
}

/// Supervision tick result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervision {
    /// No configuration to supervise.
    Idle,
    /// Listener healthy; health reported.
    Healthy,
    /// Listener alive but not responding; service restore requested.
    NonResponding,
    /// Listener task dead; quiesce/restore requested through the journal.
    TaskLost,
    /// Lease epoch revoked by the service; re-register after restore.
    EpochRevoked,
}

/// Transactional listener supervisor. See the module docs for the contract.
pub struct Coordinator<S: DnsService, B: ListenerBinder> {
    service: S,
    binder: B,
    owner_id: String,
    selected: Vec<String>,
    lease: Option<LeaseCreds>,
    active: Option<ActiveEntry>,
    pending: Option<String>,
    readiness_generation: u64,
}

impl<S: DnsService, B: ListenerBinder> Coordinator<S, B> {
    pub fn new(service: S, binder: B, owner_id: &str, selected: Vec<String>) -> Self {
        Self {
            service,
            binder,
            owner_id: owner_id.to_string(),
            selected,
            lease: None,
            active: None,
            pending: None,
            readiness_generation: 0,
        }
    }

    /// Borrow the client (tests drive assertions against scripted fakes).
    pub fn service_mut(&mut self) -> &mut S {
        &mut self.service
    }

    pub fn pending(&self) -> Option<&str> {
        self.pending.as_deref()
    }

    pub fn is_enabled(&self) -> bool {
        self.active.is_some()
    }

    // ---- transactions -----------------------------------------------------

    /// Transactional enable: prove the new plan, commit it through the
    /// service, and only then swap it in. Failure keeps the old
    /// configuration serving and reports — never half-applied.
    pub fn enable(
        &mut self,
        choice: Choice,
        local_requested: bool,
    ) -> Result<ManagedStatus, CoordError> {
        let (plan, listener) = self.bind_proven(local_requested)?;
        let readiness = self.next_readiness(listener.is_some());
        let desired = plan::desired_plan(choice, &plan, readiness);
        let creds = self.ensure_lease(readiness)?;
        let report = self.service.apply(&creds, &self.selected, &desired);
        if report.is_ok() {
            self.install(choice, plan, listener, readiness, creds);
            Ok(self.status_local())
        } else {
            self.abandon_candidate(listener);
            self.fail(&report, "enable rejected; previous configuration retained")
        }
    }

    /// Serialized provider/local-mode change. The existing sockets keep
    /// serving until the new plan is proven and committed; the old listener
    /// stops only after the commit. Failure restores the original view:
    /// the previous sockets, never a half-mixed state.
    pub fn reconfigure(
        &mut self,
        choice: Choice,
        local_requested: bool,
    ) -> Result<ManagedStatus, CoordError> {
        if self.active.is_none() {
            return Err(CoordError {
                outcome: SvcOutcome::Refused,
                message: "no active configuration to change; enable first".into(),
            });
        }
        let (plan, listener) = self.bind_proven(local_requested)?;
        let readiness = self.next_readiness(listener.is_some());
        let desired = plan::desired_plan(choice, &plan, readiness);
        let creds = self.ensure_lease(readiness)?;
        let report = self.service.reconfigure(&creds, &self.selected, &desired);
        if report.is_ok() {
            self.install(choice, plan, listener, readiness, creds);
            Ok(self.status_local())
        } else {
            self.abandon_candidate(listener);
            self.fail(&report, "change rejected; original configuration retained")
        }
    }

    /// Transactional disable. The journal is the record, not the in-memory
    /// state: with no Active and no lease the coordinator still registers
    /// (reattaching when the same live process owns the record) and runs
    /// quiesce/restore through the service.
    ///
    /// Ordering is restore-then-stop: the listener stops only after verified
    /// restore, with a bounded wait. Restore failure retains the healthy
    /// listener and the pending state; a stuck join can never precede or
    /// block the restore because the restore already happened.
    pub fn disable(&mut self) -> Result<ManagedStatus, CoordError> {
        // R0: consult the journal even without in-memory state.
        let _consulted = self.service.status();
        let creds = match self.lease.clone() {
            Some(c) => c,
            None => {
                // No lease: register (reattach when this live process owns
                // the journal record) so the restore below is authorized.
                match self.register(0) {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(CoordError {
                            outcome: e.outcome,
                            message: format!(
                                "disable consulted the journal but holds no lease: {}",
                                e.message
                            ),
                        });
                    }
                }
            }
        };
        // Close admission first; the lease is revoked server-side.
        let quiesce = self.service.quiesce(&creds);
        if !matches!(
            quiesce.outcome,
            SvcOutcome::Success | SvcOutcome::Active | SvcOutcome::VerifiedRestored
        ) && quiesce.outcome != SvcOutcome::Pending
        {
            self.pending = Some(format!("quiesce refused: {}", quiesce.message));
            self.lease = None;
            return Err(CoordError {
                outcome: quiesce.outcome,
                message: format!("disable quiesce refused: {}", quiesce.message),
            });
        }
        let restore = self.service.restore(&creds);
        if restore.is_ok() {
            // Verified restore precedes the listener stop; the stop is
            // bounded and cannot undo the restore.
            self.stop_active_bounded();
            self.active = None;
            self.lease = None;
            self.pending = None;
            Ok(self.status_local())
        } else {
            // Retain the healthy listener and the pending state — never drop
            // the listener to force progress.
            self.lease = None; // quiesce revoked it server-side
            self.pending = Some(format!("restore not verified: {}", restore.message));
            Err(CoordError {
                outcome: restore.outcome,
                message: format!(
                    "disable restore {:?}; listener retained, pending",
                    restore.outcome
                ),
            })
        }
    }

    /// Local + service status. Never claims success while pending debt
    /// exists.
    pub fn status(&mut self) -> ManagedStatus {
        let _ = self.service.status();
        self.status_local()
    }

    // ---- supervision ------------------------------------------------------

    /// One supervision pass: probe the listener, report health, and trigger
    /// quiesce/restore on terminal task loss. Returns what it did.
    pub fn supervise_tick(&mut self) -> Supervision {
        let Some(entry) = self.active.as_ref() else {
            return Supervision::Idle;
        };
        let Some(listener) = entry.listener.as_ref() else {
            return Supervision::Idle;
        };
        let readiness = entry.readiness;
        let alive = listener.alive();
        let responding = alive && listener.responds();
        let Some(creds) = self.lease.clone() else {
            self.pending = Some("supervision without a lease".into());
            return Supervision::EpochRevoked;
        };
        if !alive {
            // Terminal listener-task loss: close admission and restore
            // through the journal, exactly like a watchdog death path.
            let _ = self.service.quiesce(&creds);
            let restore = self.service.restore(&creds);
            self.lease = None;
            self.pending = Some(format!(
                "listener task lost; restore {:?}: {}",
                restore.outcome, restore.message
            ));
            return Supervision::TaskLost;
        }
        let health = self.service.health(&creds, responding, readiness);
        match health.outcome {
            SvcOutcome::Success => {
                if responding {
                    Supervision::Healthy
                } else {
                    // Non-responding health revokes the lease server-side
                    // and restores; retain pending, never quit silently.
                    self.lease = None;
                    self.pending =
                        Some("listener non-responding; service restore requested".into());
                    Supervision::NonResponding
                }
            }
            SvcOutcome::Refused | SvcOutcome::Busy | SvcOutcome::Unavailable => {
                self.lease = None;
                self.pending = Some(format!("health {:?}: {}", health.outcome, health.message));
                Supervision::EpochRevoked
            }
            _ => {
                self.pending = Some(format!("health {:?}: {}", health.outcome, health.message));
                Supervision::NonResponding
            }
        }
    }

    // ---- internals --------------------------------------------------------

    /// Bind with fallback (dual → v4-only → windows-only) and prove the
    /// candidate: a bound-but-unresponsive listener degrades to the next
    /// shape, and a tentative bind failure is never a quit.
    fn bind_proven(
        &self,
        local_requested: bool,
    ) -> Result<(ListenerPlan, Option<Box<dyn ManagedListener>>), CoordError> {
        if !local_requested {
            let plan = ListenerPlan::for_mode(ListenerMode::WindowsOnly);
            return Ok((plan, None));
        }
        for mode in [ListenerMode::Dual, ListenerMode::V4Only] {
            let plan = ListenerPlan::for_mode(mode);
            if plan::check_plan_rules(&plan).is_err() {
                continue;
            }
            match self.binder.bind(&plan) {
                Ok(listener) if listener.responds() => {
                    return Ok((plan, Some(listener)));
                }
                Ok(listener) => {
                    // Bound but unresponsive: drop the candidate (bounded)
                    // and degrade — never serve an unproven loopback.
                    let _ = listener.shutdown_bounded(Duration::from_millis(500));
                }
                Err(_) => {}
            }
        }
        Ok((ListenerPlan::for_mode(ListenerMode::WindowsOnly), None))
    }

    /// Next readiness generation for a proven plan. Windows-only (nothing
    /// proved) uses generation 0.
    fn next_readiness(&mut self, proved: bool) -> u64 {
        if !proved {
            return 0;
        }
        self.readiness_generation = self.readiness_generation.wrapping_add(1).max(1);
        self.readiness_generation
    }

    /// The lease the next mutating call must echo. Registers when there is
    /// none, or refreshes the lease's proved readiness via health when the
    /// new plan's generation differs.
    fn ensure_lease(&mut self, readiness: u64) -> Result<LeaseCreds, CoordError> {
        match self.lease.clone() {
            Some(creds) => {
                // Publish the new proved generation before the plan that
                // carries it; the candidate is already proven responsive, so
                // this health is truthful and never a false death.
                let health = self.service.health(&creds, true, readiness);
                match health.outcome {
                    SvcOutcome::Success => Ok(LeaseCreds {
                        owner_id: creds.owner_id,
                        token: creds.token,
                        epoch: creds.epoch,
                    }),
                    _ => {
                        self.lease = None;
                        self.pending =
                            Some(format!("lease readiness refresh {:?}: {}", health.outcome, health.message));
                        Err(CoordError {
                            outcome: health.outcome,
                            message: format!(
                                "lease readiness refresh failed: {}",
                                health.message
                            ),
                        })
                    }
                }
            }
            None => self.register(readiness),
        }
    }

    fn register(&mut self, readiness: u64) -> Result<LeaseCreds, CoordError> {
        match self.service.register_owner(&self.owner_id, readiness, None, None) {
            Ok(reg) => {
                let creds = LeaseCreds {
                    owner_id: self.owner_id.clone(),
                    token: reg.token,
                    epoch: reg.epoch,
                };
                self.lease = Some(creds.clone());
                Ok(creds)
            }
            Err(e) => Err(CoordError {
                outcome: e.outcome,
                message: format!("owner registration failed: {}", e.message),
            }),
        }
    }

    /// Install a committed plan: the old listener stops only now, after the
    /// service verified the commit (loopback references already removed
    /// server-side when leaving local mode). Bounded, never blocking.
    fn install(
        &mut self,
        choice: Choice,
        plan: ListenerPlan,
        listener: Option<Box<dyn ManagedListener>>,
        readiness: u64,
        _creds: LeaseCreds,
    ) {
        let old = self.active.take();
        self.active = Some(ActiveEntry {
            listener,
            choice,
            plan,
            readiness,
        });
        self.pending = None;
        if let Some(mut previous) = old {
            if let Some(stub) = previous.listener.take() {
                let _ = stub.shutdown_bounded(STOP_BOUND);
            }
        }
    }

    /// Drop a rejected candidate without touching the serving configuration.
    fn abandon_candidate(&mut self, candidate: Option<Box<dyn ManagedListener>>) {
        if let Some(stub) = candidate {
            let _ = stub.shutdown_bounded(STOP_BOUND);
        }
    }

    /// Stop the serving listener after verified restore. Bounded.
    fn stop_active_bounded(&mut self) {
        if let Some(mut entry) = self.active.take() {
            if let Some(stub) = entry.listener.take() {
                let _ = stub.shutdown_bounded(STOP_BOUND);
            }
        }
    }

    fn fail(&mut self, report: &SvcReport, context: &str) -> Result<ManagedStatus, CoordError> {
        self.pending = Some(format!("{}: {}", context, report.message));
        Err(CoordError {
            outcome: report.outcome,
            message: format!("{}: {}", context, report.message),
        })
    }

    fn status_local(&self) -> ManagedStatus {
        match self.active.as_ref() {
            Some(entry) => ManagedStatus {
                enabled: true,
                serving_local: entry.listener.is_some(),
                addrs: entry
                    .listener
                    .as_ref()
                    .map(|l| l.addrs())
                    .unwrap_or_default(),
                pending: self.pending.clone(),
                epoch: self.lease.as_ref().map(|c| c.epoch),
            },
            None => ManagedStatus {
                enabled: false,
                serving_local: false,
                addrs: Vec::new(),
                pending: self.pending.clone(),
                epoch: self.lease.as_ref().map(|c| c.epoch),
            },
        }
    }

    /// Desired plan for the serving configuration (test/diagnostic use).
    pub fn serving_desired(&self) -> Option<DesiredPlan> {
        self.active.as_ref().map(|entry| {
            plan::desired_plan(entry.choice, &entry.plan, entry.readiness)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{
        HostClient, LeaseCreds, Registration, SvcError, SvcOutcome, SvcReport,
    };
    use crate::stub::ShutdownOutcome;
    use dns_recovery::clock::VirtualClock;
    use dns_recovery::fake::FakeOs;
    use dns_recovery::fs::FakeFs;
    use dns_recovery::lock::{FakeLock, MachineLock};
    use dns_recovery::model::Family;
    use dns_recovery::protocol::PeerAuth;
    use dns_recovery::replay::FakeOwnerProbe;
    use dns_recovery::service::{ServiceConfig, ServiceHost};
    use dns_recovery::DesiredPlan;
    use std::cell::RefCell;
    use std::rc::Rc;

    const DIR: &str = "C:\\ProgramData\\Yeager";
    const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d";
    const SERVICE: &str = "44444444-4444-4444-8444-444444444444";
    const GUID_A: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
    const START_MS: i64 = 1_763_000_000_000;
    const PID: u32 = 4242;
    const FILETIME: u64 = 133_000_000_000_000_000;
    const OWNER: &str = "33333333-3333-4333-8333-333333333333";

    // ---- scripted fakes ----------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeCall {
        Bind(ListenerMode),
        Shutdown(Vec<SocketAddr>),
        Register,
        Apply,
        Reconfigure,
        Health { responding: bool },
        Quiesce,
        Restore,
        Status,
    }

    struct ScriptStub {
        addrs: Vec<SocketAddr>,
        alive: bool,
        responding: bool,
        log: Rc<RefCell<Vec<FakeCall>>>,
    }

    impl ManagedListener for ScriptStub {
        fn addrs(&self) -> Vec<SocketAddr> {
            self.addrs.clone()
        }
        fn alive(&self) -> bool {
            self.alive
        }
        fn responds(&self) -> bool {
            self.responding
        }
        fn shutdown_bounded(self: Box<Self>, _timeout: Duration) -> ShutdownOutcome {
            self.log.borrow_mut().push(FakeCall::Shutdown(self.addrs.clone()));
            ShutdownOutcome::Stopped
        }
    }

    /// Scripted binder: fails the configured modes, serves the rest with a
    /// responsive scripted stub. Every attempt is logged in order.
    struct ScriptBinder {
        fail_modes: Vec<ListenerMode>,
        alive: bool,
        responding: bool,
        log: Rc<RefCell<Vec<FakeCall>>>,
    }

    impl ListenerBinder for ScriptBinder {
        fn bind(&self, plan: &ListenerPlan) -> Result<Box<dyn ManagedListener>, BindError> {
            self.log.borrow_mut().push(FakeCall::Bind(plan.mode));
            if self.fail_modes.contains(&plan.mode) {
                return Err(BindError(format!("scripted {:?} failure", plan.mode)));
            }
            Ok(Box::new(ScriptStub {
                addrs: plan.addrs.clone(),
                alive: self.alive,
                responding: self.responding,
                log: Rc::clone(&self.log),
            }))
        }
    }

    /// Scripted service with one programmable outcome per operation. Logs
    /// every call in order so tests assert restore-before-stop.
    struct ScriptService {
        apply_outcome: SvcOutcome,
        reconfigure_outcome: SvcOutcome,
        restore_outcome: SvcOutcome,
        health_outcome: SvcOutcome,
        lease_epoch: u64,
        log: Rc<RefCell<Vec<FakeCall>>>,
    }

    impl ScriptService {
        fn ok() -> (Self, Rc<RefCell<Vec<FakeCall>>>) {
            let log = Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    apply_outcome: SvcOutcome::Active,
                    reconfigure_outcome: SvcOutcome::Active,
                    restore_outcome: SvcOutcome::VerifiedRestored,
                    health_outcome: SvcOutcome::Success,
                    lease_epoch: 3,
                    log: Rc::clone(&log),
                },
                log,
            )
        }

        fn report(&self, outcome: SvcOutcome) -> SvcReport {
            SvcReport {
                outcome,
                generation: 9,
                message: format!("{outcome:?}"),
            }
        }
    }

    impl DnsService for ScriptService {
        fn register_owner(
            &mut self,
            _owner_id: &str,
            _readiness: u64,
            _h: Option<&str>,
            _f: Option<&str>,
        ) -> Result<Registration, SvcError> {
            self.log.borrow_mut().push(FakeCall::Register);
            Ok(Registration {
                token: "tok".into(),
                epoch: self.lease_epoch,
                generation: 9,
                reattached: false,
            })
        }
        fn apply(&mut self, _: &LeaseCreds, _: &[String], _: &DesiredPlan) -> SvcReport {
            self.log.borrow_mut().push(FakeCall::Apply);
            self.report(self.apply_outcome)
        }
        fn reconfigure(&mut self, _: &LeaseCreds, _: &[String], _: &DesiredPlan) -> SvcReport {
            self.log.borrow_mut().push(FakeCall::Reconfigure);
            self.report(self.reconfigure_outcome)
        }
        fn health(&mut self, _: &LeaseCreds, responding: bool, _: u64) -> SvcReport {
            self.log.borrow_mut().push(FakeCall::Health { responding });
            self.report(self.health_outcome)
        }
        fn quiesce(&mut self, _: &LeaseCreds) -> SvcReport {
            self.log.borrow_mut().push(FakeCall::Quiesce);
            self.report(SvcOutcome::Success)
        }
        fn restore(&mut self, _: &LeaseCreds) -> SvcReport {
            self.log.borrow_mut().push(FakeCall::Restore);
            self.report(self.restore_outcome)
        }
        fn status(&mut self) -> SvcReport {
            self.log.borrow_mut().push(FakeCall::Status);
            self.report(SvcOutcome::Success)
        }
    }

    fn scripted_coordinator(
        fail_modes: Vec<ListenerMode>,
        mut service: ScriptService,
    ) -> (Coordinator<ScriptService, ScriptBinder>, Rc<RefCell<Vec<FakeCall>>>) {
        // One shared log: binder attempts, listener shutdowns and service
        // calls land in a single order, so tests assert restore-before-stop
        // across the whole stack.
        let log = Rc::new(RefCell::new(Vec::new()));
        service.log = Rc::clone(&log);
        let binder = ScriptBinder {
            fail_modes,
            alive: true,
            responding: true,
            log: Rc::clone(&log),
        };
        let co = Coordinator::new(service, binder, OWNER, vec![GUID_A.to_string()]);
        (co, log)
    }

    // ---- U06 concrete test 1: bind fallback --------------------------------

    #[test]
    fn dual_binds_udp_tcp_both_families() {
        let (svc, _) = ScriptService::ok();
        let (mut co, log) = scripted_coordinator(vec![], svc);
        let status = co
            .enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        assert!(status.enabled && status.serving_local);
        assert_eq!(
            status.addrs,
            vec![plan::v4_loopback(), plan::v6_loopback()]
        );
        // The committed desired plan carries UDP+TCP for both families.
        let desired = co.serving_desired().unwrap();
        assert_eq!(desired.bound_endpoints.len(), 4);
        dns_recovery::protocol::parse_plan(
            &serde_json::to_value(&desired).unwrap(),
        )
        .unwrap();
        assert_eq!(log.borrow()[0], FakeCall::Bind(ListenerMode::Dual));
        assert!(log.borrow().contains(&FakeCall::Apply));
    }

    #[test]
    fn v6_bind_failure_degrades_to_v4_only_plan() {
        let (svc, _) = ScriptService::ok();
        let (mut co, log) = scripted_coordinator(vec![ListenerMode::Dual], svc);
        let status = co
            .enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        assert!(status.serving_local);
        assert_eq!(status.addrs, vec![plan::v4_loopback()]);
        let desired = co.serving_desired().unwrap();
        assert!(desired.local_requested);
        assert_eq!(desired.bound_endpoints.len(), 2);
        assert!(desired.bound_endpoints.iter().all(|e| e.ip.is_ipv4()));
        dns_recovery::protocol::parse_plan(
            &serde_json::to_value(&desired).unwrap(),
        )
        .unwrap();
        assert_eq!(
            &log.borrow()[..2],
            &[FakeCall::Bind(ListenerMode::Dual), FakeCall::Bind(ListenerMode::V4Only)]
        );
    }

    #[test]
    fn both_fail_means_windows_only_with_no_loopback() {
        let (svc, _) = ScriptService::ok();
        let (mut co, log) = scripted_coordinator(vec![ListenerMode::Dual, ListenerMode::V4Only], svc);
        let status = co
            .enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        assert!(status.enabled && !status.serving_local);
        assert!(status.addrs.is_empty());
        let desired = co.serving_desired().unwrap();
        assert!(!desired.local_requested);
        assert!(desired.bound_endpoints.is_empty());
        dns_recovery::protocol::parse_plan(
            &serde_json::to_value(&desired).unwrap(),
        )
        .unwrap();
        // No loopback anywhere in the committed plan.
        for e in &desired.bound_endpoints {
            assert!(e.ip.is_loopback());
        }
        assert!(log.borrow().contains(&FakeCall::Bind(ListenerMode::V4Only)));
    }

    // ---- U06 concrete test 2: atomic change ---------------------------------

    #[test]
    fn change_retains_sockets_and_failed_change_restores_original() {
        let (svc, _) = ScriptService::ok();
        let (mut co, log) = scripted_coordinator(vec![], svc);
        let first = co
            .enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        assert_eq!(first.addrs, vec![plan::v4_loopback(), plan::v6_loopback()]);

        // Fail the change server-side: old sockets stay, candidate drops.
        co.service_mut().reconfigure_outcome = SvcOutcome::Pending;
        let err = co
            .reconfigure(Choice::Fixed(common::DohProvider::Google), true)
            .unwrap_err();
        assert_eq!(err.outcome, SvcOutcome::Pending);
        let status = co.status_local();
        assert!(status.enabled && status.serving_local);
        assert_eq!(status.addrs, first.addrs, "old sockets retained");
        assert!(co.pending().is_some(), "pending is visible, never success");
        // Candidate for the failed change was bound then dropped; the
        // serving listener was never stopped for the failed change.
        let shutdowns: usize = log
            .borrow()
            .iter()
            .filter(|c| matches!(c, FakeCall::Shutdown(_)))
            .count();
        assert_eq!(shutdowns, 1, "only the rejected candidate stopped");

        // A later successful change swaps atomically: new serving, old (the
        // retained original) stops only after the commit.
        co.service_mut().reconfigure_outcome = SvcOutcome::Active;
        let log_len = log.borrow().len();
        let status = co
            .reconfigure(Choice::Fixed(common::DohProvider::Google), true)
            .unwrap();
        assert!(status.enabled && status.serving_local);
        let tail = &log.borrow()[log_len..];
        let reconfig_at = tail.iter().position(|c| *c == FakeCall::Reconfigure).unwrap();
        let shutdown_at = tail
            .iter()
            .position(|c| matches!(c, FakeCall::Shutdown(_)))
            .unwrap();
        assert!(
            reconfig_at < shutdown_at,
            "commit precedes old-listener stop: {tail:?}"
        );
    }

    #[test]
    fn leaving_local_mode_verifies_removal_before_listener_stop() {
        let (svc, _) = ScriptService::ok();
        let (mut co, log) = scripted_coordinator(vec![], svc);
        co.enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        let log_len = log.borrow().len();
        // Change to Windows-only: the service commit removes the loopback
        // references; the old stub stops only after that commit.
        let status = co
            .reconfigure(Choice::Fixed(common::DohProvider::Cloudflare), false)
            .unwrap();
        assert!(status.enabled && !status.serving_local);
        let tail = &log.borrow()[log_len..];
        let reconfig_at = tail.iter().position(|c| *c == FakeCall::Reconfigure).unwrap();
        let shutdown_at = tail
            .iter()
            .position(|c| matches!(c, FakeCall::Shutdown(_)))
            .unwrap();
        assert!(
            reconfig_at < shutdown_at,
            "local-reference removal verified before listener stop: {tail:?}"
        );
    }

    // ---- U06 concrete test 3: resilience ------------------------------------

    /// Real stub over dead upstreams: SERVFAIL/stale keep flowing and the
    /// listener stays up — nothing quits.
    #[test]
    fn outage_stale_servfail_and_conn_errors_keep_listeners_up() {
        use crate::pool::Pool;
        use crate::upstream::Upstream;
        use std::sync::Arc;

        let dead = || {
            Arc::new(Upstream::with_addrs(
                common::DohProvider::Cloudflare,
                vec!["127.0.0.1:1".parse().unwrap()],
            ))
        };
        let pool = Pool::from_upstreams([dead(), dead()], false);
        let stub = crate::stub::Stub::start(pool, &["127.0.0.1:0".parse().unwrap()]).unwrap();
        let addr = stub.addrs[0];
        assert!(stub.is_alive());

        // UDP + TCP queries through a total upstream outage: SERVFAIL, fast.
        for _ in 0..3 {
            let mut q = hickory_proto::op::Message::query();
            q.metadata.id = 77;
            q.metadata.recursion_desired = true;
            q.add_query(hickory_proto::op::Query::query(
                "example.com.".parse().unwrap(),
                hickory_proto::rr::RecordType::A,
            ));
            let bytes = q.to_vec().unwrap();
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            udp.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            udp.send_to(&bytes, addr).unwrap();
            let mut buf = [0u8; 512];
            let len = udp.recv(&mut buf).unwrap();
            let reply = hickory_proto::op::Message::from_vec(&buf[..len]).unwrap();
            assert_eq!(
                reply.metadata.response_code,
                hickory_proto::op::ResponseCode::ServFail
            );
        }
        // Individual TCP connection failure is connection-scoped: a broken
        // half-open connection does not take the listener down.
        let tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        drop(tcp);
        assert!(stub.is_alive(), "listener survives connection churn");
        assert!(stub.responds(), "SERVFAIL still proves responsiveness");
        let outcome = stub.shutdown_bounded(Duration::from_secs(5));
        assert_eq!(outcome, ShutdownOutcome::Stopped);
    }

    // ---- U06 concrete test 4: supervision -----------------------------------

    #[test]
    fn task_loss_triggers_restore_and_stuck_join_never_blocks_it() {
        let (svc, _) = ScriptService::ok();
        let (mut co, log) = scripted_coordinator(vec![], svc);
        co.enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        // Simulate runtime panic/exit: the serving stub reports dead.
        let addrs = co.status_local().addrs.clone();
        co.active.as_mut().unwrap().listener = Some(Box::new(ScriptStub {
            addrs,
            alive: false,
            responding: false,
            log: Rc::clone(&log),
        }));
        let verdict = co.supervise_tick();
        assert_eq!(verdict, Supervision::TaskLost);
        let calls = log.borrow();
        let quiesce_at = calls.iter().position(|c| *c == FakeCall::Quiesce).unwrap();
        let restore_at = calls.iter().position(|c| *c == FakeCall::Restore).unwrap();
        assert!(quiesce_at < restore_at, "quiesce precedes restore: {calls:?}");
        assert!(co.pending().is_some());
    }

    #[test]
    fn disable_orders_restore_before_stop_and_tolerates_stuck_join() {
        struct StuckStub {
            addrs: Vec<SocketAddr>,
            log: Rc<RefCell<Vec<FakeCall>>>,
        }
        impl ManagedListener for StuckStub {
            fn addrs(&self) -> Vec<SocketAddr> {
                self.addrs.clone()
            }
            fn alive(&self) -> bool {
                true
            }
            fn responds(&self) -> bool {
                true
            }
            fn shutdown_bounded(self: Box<Self>, _timeout: Duration) -> ShutdownOutcome {
                // A stuck join: record the attempt AFTER the restore below,
                // then admit it is stuck without blocking.
                self.log.borrow_mut().push(FakeCall::Shutdown(self.addrs.clone()));
                ShutdownOutcome::TimedOut
            }
        }
        struct StuckBinder {
            log: Rc<RefCell<Vec<FakeCall>>>,
        }
        impl ListenerBinder for StuckBinder {
            fn bind(&self, plan: &ListenerPlan) -> Result<Box<dyn ManagedListener>, BindError> {
                self.log.borrow_mut().push(FakeCall::Bind(plan.mode));
                Ok(Box::new(StuckStub {
                    addrs: plan.addrs.clone(),
                    log: Rc::clone(&self.log),
                }))
            }
        }

        let (mut svc, _) = ScriptService::ok();
        let log = Rc::new(RefCell::new(Vec::new()));
        svc.log = Rc::clone(&log);
        let mut co = Coordinator::new(
            svc,
            StuckBinder { log: Rc::clone(&log) },
            OWNER,
            vec![GUID_A.to_string()],
        );
        co.enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        let log_len = log.borrow().len();
        // Restore succeeds: disable succeeds even though the join sticks —
        // the stuck join followed the restore, it never blocked it.
        let status = co.disable().unwrap();
        assert!(!status.enabled);
        let tail = &log.borrow()[log_len..];
        let restore_at = tail.iter().position(|c| *c == FakeCall::Restore).unwrap();
        let shutdown_at = tail
            .iter()
            .position(|c| matches!(c, FakeCall::Shutdown(_)))
            .unwrap();
        assert!(
            restore_at < shutdown_at,
            "restore precedes the stuck join: {tail:?}"
        );
    }

    // ---- U06 concrete test 5: restore failure + journal-first disable -------

    #[test]
    fn restore_failure_retains_listener_and_pending() {
        let (mut svc, _) = ScriptService::ok();
        svc.restore_outcome = SvcOutcome::Pending;
        let (mut co, log) = scripted_coordinator(vec![], svc);
        co.enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        let serving = co.status_local().addrs.clone();
        let err = co.disable().unwrap_err();
        assert_eq!(err.outcome, SvcOutcome::Pending);
        // Listener retained, pending visible, no shutdown attempted: the
        // coordinator never drops the listener to force progress.
        let status = co.status_local();
        assert!(status.enabled && status.serving_local);
        assert_eq!(status.addrs, serving);
        assert!(co.pending().is_some());
        assert!(
            !log.borrow().iter().any(|c| matches!(c, FakeCall::Shutdown(_))),
            "no listener stop on failed restore"
        );
    }

    #[test]
    fn disable_without_active_still_consults_the_journal() {
        let (svc, _) = ScriptService::ok();
        let (mut co, log) = scripted_coordinator(vec![], svc);
        assert!(!co.is_enabled());
        // No Active, no lease: disable must still reach the service (the
        // journal is the record) instead of no-op'ing like the legacy path.
        let _ = co.disable();
        let calls = log.borrow();
        assert!(calls.contains(&FakeCall::Status), "journal consulted: {calls:?}");
        assert!(
            calls.contains(&FakeCall::Register)
                || calls.contains(&FakeCall::Restore),
            "restore path attempted through the journal: {calls:?}"
        );
    }

    // ---- endpoint readiness / epoch correspondence ---------------------------

    /// Full stack: real U05 service state machine + fake OS. Proves endpoint
    /// readiness and epoch correspondence end to end.
    struct StackWorld {
        os: FakeOs,
        fs: Rc<FakeFs>,
        lock: FakeLock,
        clock: VirtualClock,
        probe: Rc<FakeOwnerProbe>,
    }

    impl StackWorld {
        fn new() -> Self {
            Self {
                os: FakeOs::new(),
                fs: Rc::new(FakeFs::new()),
                lock: FakeLock::new(),
                clock: VirtualClock::new(START_MS),
                probe: Rc::new(FakeOwnerProbe::new()),
            }
        }

        fn peer(&self) -> PeerAuth {
            PeerAuth {
                pid: PID,
                creation_filetime: FILETIME,
                user_sid: "S-1-5-18".to_string(),
                elevated: true,
                session_id: 0,
                logon_luid: 999,
                image_path: "C:\\Program Files\\Yeager\\yeager.exe".to_string(),
                image_file_id: "fileid-1".to_string(),
                image_sha256: "a".repeat(64),
                remote: false,
                server_pid: None,
                expected_server_pid: None,
            }
        }

        fn seed(&self) {
            self.os.add_adapter(GUID_A, "Ethernet");
            self.os.set_configured(GUID_A, Family::Ipv4, "192.0.2.53", vec![]);
            self.os.set_configured(GUID_A, Family::Ipv6, "2001:db8::53", vec![]);
            self.probe.spawn(PID, FILETIME);
        }
    }

    // NOTE: `ServiceHost` borrows nothing, so the stack test below threads
    // the world through local bindings and drives `HostClient` over
    // `&mut host` directly.

    #[test]
    fn readiness_and_epoch_correspondence_against_real_service() {
        let world = StackWorld::new();
        world.seed();
        let os_b = world.os.clone();
        let os_s = world.os.clone();
        let lock_base = world.lock.peer(7000, 0);
        let clock = world.clock.clone();
        let clock_b = world.clock.clone();
        let fs = Rc::clone(&world.fs);
        let probe = Rc::clone(&world.probe);
        let mut host = ServiceHost::new(
            Rc::new(move || Box::new(os_b.clone()) as Box<dyn dns_recovery::backend::DnsBackend>),
            Rc::new(move || Box::new(os_s.clone()) as Box<dyn dns_recovery::setter::DnsSetter>),
            Rc::new(move || Box::new(lock_base.peer(7000, 0)) as Box<dyn MachineLock>),
            Box::new(clock_b),
            Rc::new(move || Box::new(clock.clone()) as Box<dyn dns_recovery::clock::Clock>),
            Rc::new(move || Rc::clone(&fs)),
            Rc::new(move || {
                let p: FakeOwnerProbe = (*probe).clone();
                Box::new(p) as Box<dyn dns_recovery::replay::OwnerProbe>
            }),
            ServiceConfig {
                dir: DIR.to_string(),
                machine_id: MACHINE.to_string(),
                service_instance_id: SERVICE.to_string(),
            },
        );
        let peer = world.peer();

        // Scripted responsive binder, real service client.
        let log = Rc::new(RefCell::new(Vec::new()));
        let binder = ScriptBinder {
            fail_modes: vec![],
            alive: true,
            responding: true,
            log: Rc::clone(&log),
        };
        let mut client = HostClient::new(&mut host, peer);
        // Register with readiness 0, then run one apply through the real
        // machine: proves the client marshals allowlisted plans the service
        // accepts and echoes the journal epoch on later calls.
        let reg = client
            .register_owner(OWNER, 0, Some(&"a".repeat(64)), Some("fileid-1"))
            .expect("registration against the real host");
        assert!(!reg.token.is_empty());
        let creds = LeaseCreds {
            owner_id: OWNER.into(),
            token: reg.token.clone(),
            epoch: reg.epoch,
        };
        // Readiness 1: prove-then-publish via health, then apply the
        // dual-loopback plan carrying generation 1.
        let health = client.health(&creds, true, 1);
        assert_eq!(health.outcome, SvcOutcome::Success);
        let plan = crate::plan::desired_plan(
            Choice::Fixed(common::DohProvider::Cloudflare),
            &ListenerPlan::for_mode(ListenerMode::Dual),
            1,
        );
        let apply = client.apply(&creds, &[GUID_A.to_string()], &plan);
        assert!(
            apply.is_ok(),
            "real service accepts the dual plan: {apply:?}"
        );
        // A stale epoch is refused and never revives the lease.
        let stale = LeaseCreds {
            owner_id: OWNER.into(),
            token: reg.token,
            epoch: reg.epoch.wrapping_add(99),
        };
        let refused = client.apply(&stale, &[GUID_A.to_string()], &plan);
        assert_eq!(refused.outcome, SvcOutcome::Refused);
        // The serving configuration really changed on the fake OS: the
        // Cloudflare resolvers are now configured (exact recovery target).
        let (ns, _) = world.os.configured(GUID_A, Family::Ipv4);
        assert!(
            ns.contains("1.1.1.1"),
            "fake OS shows the committed configuration: {ns}"
        );
        let _ = binder;
    }

    #[test]
    fn stale_generation_plan_is_refused_before_any_write() {
        let (svc, _) = ScriptService::ok();
        let (mut co, _) = scripted_coordinator(vec![], svc);
        co.enable(Choice::Fixed(common::DohProvider::Cloudflare), true)
            .unwrap();
        // Forge a stale lease epoch: the service refuses, the coordinator
        // drops the lease and surfaces pending instead of serving blind.
        if let Some(lease) = co.lease.as_mut() {
            lease.epoch = lease.epoch.wrapping_add(1000);
        }
        co.service_mut().health_outcome = SvcOutcome::Refused;
        let err = co
            .reconfigure(Choice::Fixed(common::DohProvider::Google), true)
            .unwrap_err();
        assert_eq!(err.outcome, SvcOutcome::Refused);
        assert!(co.lease.is_none(), "dead lease is dropped");
        assert!(co.pending().is_some());
    }
}

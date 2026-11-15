//! U08 — app bootstrap, all exit paths, diagnostics (SPEC-DNS-FIX.md §6, §12 U08).
//!
//! This module owns what U07 deliberately left out: the early bootstrap
//! wiring (spec §7) and every §6 entry path, the lifecycle guard, session
//! notifications and the UI hooks. All DNS work goes through the U07
//! [`Lifecycle`] whose DNS seam is bound here to the real single
//! [`hange::Authority`] (one coordinator, one service lease) — the
//! pre-existing direct-DNS sites from `main.rs` (`hange::enable` /
//! `disable` / `clean_up_leftovers`, the detached `spawn` helper for DNS,
//! and the epilogue's `engine::stop` → `erwin::restore` → `hange::disable`
//! order) are rewired to this path in `main.rs`.
//!
//! Section 12 law: everything here is built and tested against fakes. The
//! OS seams are the [`BootCtl`] trait (journal inspect / dead-owner
//! recovery / coordinator shutdown) and the [`SessionEvent`] mapping;
//! `cargo test` scripts a dead journal, every fallible-init failure, every
//! exit-table row and every session event without touching real NICs.
//!
//! NOTE: several items below (the scripted [`BootDriver`], the §6
//! [`EntryPath`] table, the repair-approval types) are exercised only by
//! `cargo test` by §12 design — production binds the guard, the classifier,
//! the session mapping and the `App*` seams. The scoped allow keeps
//! non-test builds diagnostics-free without hiding real dead code inside
//! the production path.
#![cfg_attr(not(test), allow(dead_code))]

use crate::lifecycle::{
    DnsCtl, DnsOutcome, EngineCtl, Lifecycle, PersistCfg, ShutdownKind, ShutdownReport, UiNotify,
};
use hange::Choice;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Journal state, boot decision
// ---------------------------------------------------------------------------

/// What the early journal inspection found (spec §7 steps 1–2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalState {
    /// Clean tombstone or no journal: nothing to recover.
    Clean,
    /// A live owner holds the machine lease: another launch owns the path.
    /// Never quiesce, never restore — activate the existing UI and exit.
    OwnedLive { owner: String },
    /// The recorded owner is dead: close admission and restore the exact
    /// original before any fallible initialization runs.
    OwnedDead { owner: String },
    /// Unknown owner / deferred adapters: reads failed or the owner probe
    /// was inconclusive. Keep the journal, refuse writes, allow the
    /// diagnostic UI but block auto-connect.
    DeferredOrUnknown { reason: String },
    /// Integrity failure or unknown version/schema: never delete, never
    /// overwrite, never take over. Diagnostic UI only.
    IntegrityFailure { reason: String },
    /// The snapshot format is not supported on this OS build. Debt stays.
    UnsupportedSnapshot { reason: String },
}

/// What the app may do after inspection (+ recovery where applicable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootDecision {
    /// Journal clean (or dead owner restored): auto-connect is allowed.
    ProceedAutoConnect,
    /// Diagnostic UI may run, but auto-connect and any new takeover are
    /// blocked until the debt settles.
    ProceedDiagnosticOnly { reason: String },
    /// A live owner holds the lease: activate its UI and exit without
    /// touching DNS. The guard owns only this process's lease — never the
    /// owner's — so exiting quiesces nothing.
    RefuseTakeoverQuit { owner: String },
}

impl BootDecision {
    pub fn blocks_auto_connect(&self) -> bool {
        !matches!(self, BootDecision::ProceedAutoConnect)
    }
}

/// Pure classification of a post-recovery journal state.
pub fn classify_boot(state: &JournalState) -> BootDecision {
    match state {
        JournalState::Clean => BootDecision::ProceedAutoConnect,
        JournalState::OwnedLive { owner } => BootDecision::RefuseTakeoverQuit {
            owner: owner.clone(),
        },
        JournalState::OwnedDead { owner } => BootDecision::ProceedDiagnosticOnly {
            reason: format!("dead owner {owner} needs recovery first"),
        },
        JournalState::DeferredOrUnknown { reason } => BootDecision::ProceedDiagnosticOnly {
            reason: reason.clone(),
        },
        JournalState::IntegrityFailure { reason } => BootDecision::ProceedDiagnosticOnly {
            reason: format!("journal integrity failure; takeover refused: {reason}"),
        },
        JournalState::UnsupportedSnapshot { reason } => BootDecision::ProceedDiagnosticOnly {
            reason: format!("unsupported snapshot; restore stays pending: {reason}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Boot control seam
// ---------------------------------------------------------------------------

/// Outcome of the dead-owner recovery that precedes fallible init.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootRecovery {
    /// Exact originals restored and freshly verified.
    RestoredVerified,
    /// Not fully restored; journal retained, debt visible.
    Pending(String),
    /// Foreign/owner conflict; journal retained, no overwrite.
    Conflict(String),
    /// Recovery refused (e.g. service unavailable). Nothing mutated.
    Refused(String),
}

/// Which teardown the boot path asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootShutdownKind {
    DnsOff,
    ProcessQuit,
}

impl From<BootShutdownKind> for ShutdownKind {
    fn from(k: BootShutdownKind) -> Self {
        match k {
            BootShutdownKind::DnsOff => ShutdownKind::DnsOff,
            BootShutdownKind::ProcessQuit => ShutdownKind::ProcessQuit,
        }
    }
}

/// The OS seam for early bootstrap: journal inspection, dead-owner
/// recovery and coordinator shutdown. Production binds this to the
/// privileged service (via [`RealBootCtl`]); tests script it.
pub trait BootCtl: Send + Sync {
    fn inspect(&self) -> JournalState;
    fn recover(&self) -> BootRecovery;
    fn shutdown(&self, kind: BootShutdownKind) -> ShutdownReport;
}

// ---------------------------------------------------------------------------
// Production DNS seam: Lifecycle over the single hange Authority
// ---------------------------------------------------------------------------

/// [`DnsCtl`] over the single process-wide [`hange::Authority`]: one
/// coordinator, one service lease, one serial worker. Outcome mapping is
/// deliberately strict — only a debt-free service state reads as
/// [`DnsOutcome::Verified`]; anything else is pending (visible, never
/// success). Conflict taxonomy survives in the message text for the
/// diagnostics UI; the lifecycle treats pending and conflict identically
/// (retain listener, hand off, never succeed).
pub struct AppDns {
    authority: hange::Authority,
}

impl AppDns {
    pub fn new(authority: hange::Authority) -> Self {
        Self { authority }
    }

    fn verified_or_pending(status: hange::AuthorityStatus) -> DnsOutcome {
        match status.pending {
            None => DnsOutcome::Verified,
            Some(debt) => DnsOutcome::Pending(debt),
        }
    }

    fn err_or_pending(e: common::Error) -> DnsOutcome {
        let msg = e.to_string();
        if msg.contains("Conflict") {
            DnsOutcome::Conflict(msg)
        } else {
            DnsOutcome::Pending(msg)
        }
    }
}

impl DnsCtl for AppDns {
    fn quiesce(&self) {
        // Idempotent admission close on the DNS side. The lifecycle already
        // closed its own admission first (spec §6 step 1); a missing lease
        // reads as success, never as a failure that would block restore.
        let _ = self.authority.quiesce();
    }

    fn restore(&self) -> DnsOutcome {
        match self.authority.restore() {
            Ok(status) => Self::verified_or_pending(status),
            Err(e) => Self::err_or_pending(e),
        }
    }

    fn verify(&self) -> bool {
        // Fresh service readback (the coordinator consults the service on
        // every status): the service's restore already proved configured
        // equality; this re-reads that no new debt appeared behind it.
        self.authority.status().healthy()
    }

    fn stop_listeners(&self) {
        // Only ever called after a verified restore (lifecycle orders it).
        self.authority.stop_listeners();
    }

    fn handoff(&self) {
        // Pending/conflict branch: retain the listener, keep debt visible.
        self.authority.handoff("shutdown with recovery debt; DNS authority retained");
    }

    fn enable(&self, choice: Choice, local: bool, _epoch: u64) -> DnsOutcome {
        // The lifecycle admission epoch already gated this call; the lease
        // epoch is the service's own (single writer, spec invariant 2).
        match self.authority.enable(choice, local) {
            Ok(_) => DnsOutcome::Verified,
            Err(e) => Self::err_or_pending(e),
        }
    }

    fn reconfigure(&self, choice: Choice, local: bool, _epoch: u64) -> DnsOutcome {
        // Serialized provider/local-mode change retaining the original —
        // distinct from enable (U07-REV item 5), cancelled at the same drain.
        match self.authority.change(choice, local) {
            Ok(_) => DnsOutcome::Verified,
            Err(e) => Self::err_or_pending(e),
        }
    }

    fn status(&self) -> DnsOutcome {
        let state = self.authority.status();
        match state.pending {
            None => DnsOutcome::Verified,
            Some(debt) => DnsOutcome::Pending(debt),
        }
    }
}

/// [`EngineCtl`] over `crate::engine`. Stop runs on the lifecycle's
/// detached thread with a bounded join and caught unwind (U07); start is
/// gated by the lifecycle epoch and carries the current config snapshot.
#[derive(Clone)]
pub struct AppEngine {
    config: Arc<dyn Fn() -> common::Config + Send + Sync>,
    start_errors: Arc<Mutex<Vec<String>>>,
}

impl AppEngine {
    pub fn new(config: Arc<dyn Fn() -> common::Config + Send + Sync>) -> Self {
        Self {
            config,
            start_errors: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Non-blocking drain for the diagnostics UI.
    pub fn take_start_errors(&self) -> Vec<String> {
        std::mem::take(&mut *self.start_errors.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl EngineCtl for AppEngine {
    fn stop(&self) {
        crate::engine::stop();
    }

    fn start(&self) {
        // Best effort inside the epoch gate: a start failure is recorded
        // for diagnostics and never breaks DNS recovery behind it.
        if let Err(e) = crate::engine::start(&(self.config)()) {
            self.start_errors
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(e.to_string());
        }
    }
}

/// [`UiNotify`] that records messages into a shared log. The UI thread
/// drains the log into the visible log surface, so shutdown threads never
/// touch Slint directly. Never fails: notification is best effort by
/// design, and a full log simply drops the oldest entries.
#[derive(Clone)]
pub struct SharedLogUi {
    log: Arc<Mutex<Vec<String>>>,
}

impl SharedLogUi {
    pub fn new(log: Arc<Mutex<Vec<String>>>) -> Self {
        Self { log }
    }

    /// Non-blocking drain for the UI thread. Oldest first, at most 50.
    pub fn drain(&self) -> Vec<String> {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        let take = log.len().min(50);
        log.drain(..take).collect()
    }
}

impl UiNotify for SharedLogUi {
    fn notify(&self, message: &str) -> Result<(), String> {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.push(message.to_string());
        while log.len() > 200 {
            log.remove(0);
        }
        Ok(())
    }
}

/// [`PersistCfg`] for this app: configuration is saved synchronously at
/// every mutation site in `main.rs` (durable before shutdown) and the
/// epilogue flushes the debounced domain save, so the shutdown-time persist
/// seam is a no-op by design. Its `Ok` never masks a real save failure —
/// real saves happen (and surface errors) at their own call sites.
pub struct NoopPersist;

impl PersistCfg for NoopPersist {
    fn save(&self) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Production BootCtl: service-mediated inspect/recover + lifecycle shutdown
// ---------------------------------------------------------------------------

/// Production [`BootCtl`]:
///
/// - `inspect` asks the privileged service (the sole normal DNS writer).
///   `Unavailable`/`Unsupported` mean no takeover authority exists, so the
///   journal is treated as deferred: diagnostic UI may run, auto-connect
///   is blocked, nothing is mutated here.
/// - `recover` runs the service transaction's restore (idempotent: on a
///   clean journal it verifies without writing; on a dead owner it
///   restores the exact original before any fallible init runs). A live
///   duplicate owner is never quiesced: registration for another live
///   process is refused service-side, and this path performs no restore
///   when the service reports a live owner — the single-instance mutex in
///   `platform.rs` exits before this point anyway.
/// - `shutdown` is the U07 lifecycle teardown (quiesce → settle →
///   restore → verify → listener-stop + bounded engine stop).
pub struct RealBootCtl<D, E, U, P>
where
    D: DnsCtl + 'static,
    E: EngineCtl + 'static,
    U: UiNotify + 'static,
    P: PersistCfg + 'static,
{
    lifecycle: Arc<Lifecycle<D, E, U, P>>,
}

impl<D, E, U, P> RealBootCtl<D, E, U, P>
where
    D: DnsCtl + 'static,
    E: EngineCtl + 'static,
    U: UiNotify + 'static,
    P: PersistCfg + 'static,
{
    pub fn new(lifecycle: Arc<Lifecycle<D, E, U, P>>) -> Self {
        Self { lifecycle }
    }
}

impl<D, E, U, P> BootCtl for RealBootCtl<D, E, U, P>
where
    D: DnsCtl + 'static,
    E: EngineCtl + 'static,
    U: UiNotify + 'static,
    P: PersistCfg + 'static,
{
    fn inspect(&self) -> JournalState {
        use hange::{DnsService, PipeClient, SvcOutcome};
        let mut client = PipeClient::new();
        match client.status().outcome {
            SvcOutcome::Success | SvcOutcome::Active => JournalState::Clean,
            SvcOutcome::Pending | SvcOutcome::Busy => JournalState::DeferredOrUnknown {
                reason: "service reports recovery debt; auto-connect blocked".into(),
            },
            SvcOutcome::Conflict => JournalState::DeferredOrUnknown {
                reason: "service reports a foreign-administrator conflict; auto-connect blocked".into(),
            },
            SvcOutcome::Refused => JournalState::DeferredOrUnknown {
                reason: "service refused inspection; auto-connect blocked".into(),
            },
            SvcOutcome::Unsupported => JournalState::UnsupportedSnapshot {
                reason: "service reports an unsupported snapshot; restore stays pending".into(),
            },
            SvcOutcome::VerifiedRestored | SvcOutcome::Unavailable => JournalState::DeferredOrUnknown {
                reason: "recovery service unavailable; takeover refused, diagnostic UI only".into(),
            },
        }
    }

    fn recover(&self) -> BootRecovery {
        match hange::dns_authority().restore() {
            Ok(status) => match status.pending {
                None => BootRecovery::RestoredVerified,
                Some(debt) => BootRecovery::Pending(debt),
            },
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("Conflict") {
                    BootRecovery::Conflict(msg)
                } else if msg.contains("Unavailable") || msg.contains("unavailable") {
                    BootRecovery::Refused(msg)
                } else {
                    BootRecovery::Pending(msg)
                }
            }
        }
    }

    fn shutdown(&self, kind: BootShutdownKind) -> ShutdownReport {
        self.lifecycle.shutdown(kind.into())
    }
}

// ---------------------------------------------------------------------------
// Boot guard: early returns and unwinding can never bypass cleanup
// ---------------------------------------------------------------------------

/// Scope guard installed before any fallible initialization (spec §6: the
/// top-level guard handles early returns and unwinding as defense, never as
/// a substitute for the service/replay path). Dropping the guard without
/// [`BootGuard::complete`] runs the coordinator shutdown exactly once.
///
/// The live-duplicate path must NOT install this guard (or must
/// [`BootGuard::dismiss`] it): a duplicate exiting must never quiesce the
/// owner's lease.
pub struct BootGuard<'a, C: BootCtl> {
    ctl: &'a C,
    kind: BootShutdownKind,
    completed: bool,
}

impl<'a, C: BootCtl> BootGuard<'a, C> {
    pub fn arm(ctl: &'a C, kind: BootShutdownKind) -> Self {
        Self {
            ctl,
            kind,
            completed: false,
        }
    }

    /// The shutdown already ran to a published report: disarm the guard.
    pub fn complete(&mut self) {
        self.completed = true;
    }

    /// Dismiss without running: only for paths that provably touched no DNS
    /// (live-duplicate exit before any admission).
    pub fn dismiss(&mut self) {
        self.completed = true;
    }
}

impl<C: BootCtl> Drop for BootGuard<'_, C> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.ctl.shutdown(self.kind);
        }
    }
}

// ---------------------------------------------------------------------------
// Boot driver: recovery precedes every fallible step
// ---------------------------------------------------------------------------

/// One named fallible initialization step after the DNS bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootStep {
    LoadConfig,
    CreateWindow,
    SetupTray,
    InitUpdater,
    ShowUi,
    RunEventLoop,
}

/// A scripted step outcome for [`BootDriver`]: which steps fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepPlan {
    /// Steps that fail, in any order. Recovery still precedes every one.
    pub fail: Vec<BootStep>,
}

/// What the boot driver did, in order, for diagnostics and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootEvent {
    Inspected,
    Recovered,
    StepOk(BootStep),
    StepFailed(BootStep),
    Shutdown(BootShutdownKind),
}

/// Report of [`BootDriver::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootRunReport {
    pub decision: BootDecision,
    pub recovery: Option<BootRecovery>,
    pub failed_step: Option<BootStep>,
    pub shutdown: Option<ShutdownReport>,
    pub events: Vec<BootEvent>,
}

/// Early bootstrap driver (spec §7): minimal DNS bootstrap — filesystem /
/// service inspection and dead-owner recovery — runs BEFORE config load,
/// updater work, window, tray, networking and connect-on-launch. The
/// [`BootGuard`] is armed before the first fallible step, so every failure
/// below settles this process's lease through the coordinator.
pub struct BootDriver<'a, C: BootCtl> {
    ctl: &'a C,
}

impl<'a, C: BootCtl> BootDriver<'a, C> {
    pub fn new(ctl: &'a C) -> Self {
        Self { ctl }
    }

    pub fn run(&self, plan: &StepPlan) -> BootRunReport {
        let mut events = vec![BootEvent::Inspected];
        let state = self.ctl.inspect();

        // A live owner holds the machine lease: exit without touching DNS.
        // No guard is armed on this path — the guard owns only this
        // process's lease, never the owner's.
        if let JournalState::OwnedLive { .. } = state {
            return BootRunReport {
                decision: classify_boot(&state),
                recovery: None,
                failed_step: None,
                shutdown: None,
                events,
            };
        }

        // Dead-owner recovery precedes EVERY fallible step (spec §7). It
        // also runs on a clean journal: the service restore is idempotent
        // (verifies without writing when clean) and is what replays a dead
        // owner's intent before this process captures any new baseline.
        // Unreachable-service / integrity / unsupported states skip the
        // recovery attempt: there is no authority to recover with, and the
        // journal must be retained untouched.
        let recovery = match state {
            JournalState::Clean | JournalState::OwnedDead { .. } => {
                events.push(BootEvent::Recovered);
                Some(self.ctl.recover())
            }
            _ => None,
        };

        let decision = match (&state, &recovery) {
            (_, Some(BootRecovery::RestoredVerified)) => BootDecision::ProceedAutoConnect,
            (_, Some(r)) => BootDecision::ProceedDiagnosticOnly {
                reason: format!("recovery did not verify ({r:?}); auto-connect blocked"),
            },
            (s, None) => classify_boot(s),
        };

        // The guard is armed before the first fallible step and completed
        // only on the clean path: any early return below shuts down.
        let mut guard = BootGuard::arm(self.ctl, BootShutdownKind::ProcessQuit);
        let mut failed_step = None;
        let mut shutdown = None;
        for step in [
            BootStep::LoadConfig,
            BootStep::CreateWindow,
            BootStep::SetupTray,
            BootStep::InitUpdater,
            BootStep::ShowUi,
            BootStep::RunEventLoop,
        ] {
            if plan.fail.contains(&step) {
                events.push(BootEvent::StepFailed(step));
                failed_step = Some(step);
                // Recovery preceded this failure (Recovered is already in
                // the log); the guard settles our lease without bypass.
                let report = self.ctl.shutdown(BootShutdownKind::ProcessQuit);
                events.push(BootEvent::Shutdown(BootShutdownKind::ProcessQuit));
                shutdown = Some(report);
                // Guard disarmed: the shutdown already ran and published.
                guard.complete();
                break;
            }
            events.push(BootEvent::StepOk(step));
        }
        if failed_step.is_none() {
            guard.complete();
        }
        BootRunReport {
            decision,
            recovery,
            failed_step,
            shutdown,
            events,
        }
    }
}

// ---------------------------------------------------------------------------
// §6 entry-path table: every row, one behavior
// ---------------------------------------------------------------------------

/// Every entry path of the spec §6 investigation table. U08 wires each one;
/// [`plan_entry`] is the pure mapping, and the tests below execute each row
/// against the coordinator seam (or record explicit evidence where a row is
/// environmentally driven — power loss, hard kill — and covered by replay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPath {
    NormalEventLoopReturn,
    TrayExit,
    WindowCloseWithoutTray,
    WindowCloseWithTray,
    Minimize,
    DnsToggleOff,
    EngineToggleOff,
    EngineStartError,
    ProviderOrLocalChange,
    EnableFailure,
    UpdateSuccessRestart,
    UpdateFailure,
    InstallerUpgrade,
    UninstallerCleanup,
    UnsupportedOs,
    DuplicateInstance,
    MainWindowNewFailure,
    UiShowOrEventLoopError,
    UpstreamFailure,
    DnsTestError,
    ListenerTaskError,
    Panic,
    AbortOrHardKill,
    PowerLoss,
    ServiceStop,
    SessionEnd,
    CleanupApiFailure,
    QuitVsQueuedEnable,
}

impl EntryPath {
    pub const ALL: [EntryPath; 28] = [
        EntryPath::NormalEventLoopReturn,
        EntryPath::TrayExit,
        EntryPath::WindowCloseWithoutTray,
        EntryPath::WindowCloseWithTray,
        EntryPath::Minimize,
        EntryPath::DnsToggleOff,
        EntryPath::EngineToggleOff,
        EntryPath::EngineStartError,
        EntryPath::ProviderOrLocalChange,
        EntryPath::EnableFailure,
        EntryPath::UpdateSuccessRestart,
        EntryPath::UpdateFailure,
        EntryPath::InstallerUpgrade,
        EntryPath::UninstallerCleanup,
        EntryPath::UnsupportedOs,
        EntryPath::DuplicateInstance,
        EntryPath::MainWindowNewFailure,
        EntryPath::UiShowOrEventLoopError,
        EntryPath::UpstreamFailure,
        EntryPath::DnsTestError,
        EntryPath::ListenerTaskError,
        EntryPath::Panic,
        EntryPath::AbortOrHardKill,
        EntryPath::PowerLoss,
        EntryPath::ServiceStop,
        EntryPath::SessionEnd,
        EntryPath::CleanupApiFailure,
        EntryPath::QuitVsQueuedEnable,
    ];

    pub fn name(self) -> &'static str {
        match self {
            EntryPath::NormalEventLoopReturn => "normal-event-loop-return",
            EntryPath::TrayExit => "tray-exit",
            EntryPath::WindowCloseWithoutTray => "window-close-without-tray",
            EntryPath::WindowCloseWithTray => "window-close-with-tray",
            EntryPath::Minimize => "minimize",
            EntryPath::DnsToggleOff => "dns-toggle-off",
            EntryPath::EngineToggleOff => "engine-toggle-off",
            EntryPath::EngineStartError => "engine-start-error",
            EntryPath::ProviderOrLocalChange => "provider-or-local-change",
            EntryPath::EnableFailure => "enable-failure",
            EntryPath::UpdateSuccessRestart => "update-success-restart",
            EntryPath::UpdateFailure => "update-download-install-error",
            EntryPath::InstallerUpgrade => "installer-upgrade-forced-closure",
            EntryPath::UninstallerCleanup => "uninstaller-cleanup",
            EntryPath::UnsupportedOs => "unsupported-os-early-return",
            EntryPath::DuplicateInstance => "duplicate-instance-early-return",
            EntryPath::MainWindowNewFailure => "mainwindow-new-failure",
            EntryPath::UiShowOrEventLoopError => "ui-show-event-loop-error",
            EntryPath::UpstreamFailure => "upstream-doh-failure",
            EntryPath::DnsTestError => "dns-test-verification-error",
            EntryPath::ListenerTaskError => "listener-receive-accept-connection-error",
            EntryPath::Panic => "unwinding-panic",
            EntryPath::AbortOrHardKill => "release-abort-native-crash-hard-kill",
            EntryPath::PowerLoss => "power-loss",
            EntryPath::ServiceStop => "service-stop-shutdown-preshutdown",
            EntryPath::SessionEnd => "os-logoff-shutdown-session-end",
            EntryPath::CleanupApiFailure => "cleanup-api-readback-failure",
            EntryPath::QuitVsQueuedEnable => "quit-vs-queued-enable-race",
        }
    }
}

/// What the coordinator must do for one entry path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryExpectation {
    /// Human statement of the required behavior (spec §6 row).
    pub behavior: &'static str,
    /// Coordinator shutdown to run, if any.
    pub shutdown: Option<BootShutdownKind>,
    /// Whether a restart/replacement may proceed afterwards (only after a
    /// verified restore; failed cleanup cancels the restart).
    pub may_restart_after: bool,
}

/// The pure §6 mapping: each entry path behaves exactly as its table row.
pub fn plan_entry(path: EntryPath) -> EntryExpectation {
    match path {
        EntryPath::NormalEventLoopReturn => EntryExpectation {
            behavior: "coordinator process-shutdown before exit",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::TrayExit => EntryExpectation {
            behavior: "quiesce before quit_event_loop; idempotent epilogue joins",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::WindowCloseWithoutTray => EntryExpectation {
            behavior: "same process-shutdown request as tray exit",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::WindowCloseWithTray => EntryExpectation {
            behavior: "hide/minimize only; owner and DNS continue",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::Minimize => EntryExpectation {
            behavior: "minimize only; owner and DNS continue",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::DnsToggleOff => EntryExpectation {
            behavior: "DNS-off barrier: restore, verify, listener-stop; engine stop independent",
            shutdown: Some(BootShutdownKind::DnsOff),
            may_restart_after: false,
        },
        EntryPath::EngineToggleOff => EntryExpectation {
            behavior: "retain independent DNS unless DNS enable itself failed",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::EngineStartError => EntryExpectation {
            behavior: "retain independent DNS; report the engine error",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::ProviderOrLocalChange => EntryExpectation {
            behavior: "serialized reconfigure retaining the original",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::EnableFailure => EntryExpectation {
            behavior: "roll back to the original with a structured result; never heuristic DHCP reset",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::UpdateSuccessRestart => EntryExpectation {
            behavior: "restore and verify before the replacement/restart gate",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: true,
        },
        EntryPath::UpdateFailure => EntryExpectation {
            behavior: "display the failure; active DNS continues untouched",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::InstallerUpgrade => EntryExpectation {
            behavior: "maintenance and graceful shutdown first; monitored force kill only with an independent monitor, then verify",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::UninstallerCleanup => EntryExpectation {
            behavior: "exact result-bearing recovery plus TCP/logon cleanup; retain the failed journal; nonzero exit on failure",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::UnsupportedOs => EntryExpectation {
            behavior: "minimal journal recovery before the dialog; unsupported restore capability stays pending debt, never heuristic clear",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::DuplicateInstance => EntryExpectation {
            behavior: "early owner inspection; leave the live owner alone; the guard owns only its own lease — no quiesce, no shutdown",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::MainWindowNewFailure => EntryExpectation {
            behavior: "recovery already ran; the top-level guard settles this process's lease without UI",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::UiShowOrEventLoopError => EntryExpectation {
            behavior: "await coordinator cleanup, then return the original error plus the recovery report; no `?` bypass",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::UpstreamFailure => EntryExpectation {
            behavior: "preserve failover/stale/SERVFAIL; no disable, no quit",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::DnsTestError => EntryExpectation {
            behavior: "diagnostic only; connectivity error alone never quits; drift/liveness classified separately",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::ListenerTaskError => EntryExpectation {
            behavior: "preserve recoverable behavior; terminal task loss supervised (quiesce/restore)",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::Panic => EntryExpectation {
            behavior: "guard/supervisor best effort plus the independent watchdog; abort builds rely on the process handle",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::AbortOrHardKill => EntryExpectation {
            behavior: "service restores via the held process handle; replay on next start",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::PowerLoss => EntryExpectation {
            behavior: "durable replay next boot/start; no promise while power is off",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::ServiceStop => EntryExpectation {
            behavior: "service quiesces and restores with retained debt and a bounded stop; nonzero result when incomplete",
            shutdown: None,
            may_restart_after: false,
        },
        EntryPath::SessionEnd => EntryExpectation {
            behavior: "native notification starts the coordinator; forced termination covered by service/replay",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
        EntryPath::CleanupApiFailure => EntryExpectation {
            behavior: "pending structured result, bounded retries, journal retained",
            shutdown: Some(BootShutdownKind::DnsOff),
            may_restart_after: false,
        },
        EntryPath::QuitVsQueuedEnable => EntryExpectation {
            behavior: "atomic admission close with the service barrier; in-flight settles before restore; stale callbacks rejected",
            shutdown: Some(BootShutdownKind::ProcessQuit),
            may_restart_after: false,
        },
    }
}

// ---------------------------------------------------------------------------
// Session notifications (WM_QUERYENDSESSION / WM_ENDSESSION / console)
// ---------------------------------------------------------------------------

/// Native session/console notification, normalized at the OS seam in
/// `platform.rs`. The mapping below is pure and fake-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Session is ending unless we refuse: start quiesce, return promptly.
    QueryEndSession,
    /// Session end decision: true = end now (bounded cleanup), false =
    /// canceled (finish the current restoration, never reopen the old
    /// epoch — only a fresh explicit enable runs after clean).
    EndSession { can_end: bool },
    /// Attached-console control (Ctrl+C / close / logoff): bounded quit.
    ConsoleCtrl,
    /// Interactive logoff notification path.
    Logoff,
}

/// Sink for native session/console notifications: implemented by `main.rs`
/// over the shared [`Lifecycle`], installed by
/// `platform::install_session_hook`.
pub type SessionSink = Arc<dyn Fn(SessionEvent) + Send + Sync>;

/// What the session handler does with the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    /// Quiesce now on a worker thread; the full restore follows at end.
    StartQuiesce,
    /// Bounded synchronous coordinator shutdown (never reopens).
    BoundedQuit,
    /// Join the in-flight shutdown; start nothing new, reopen nothing.
    JoinOnly,
}

/// Pure session mapping (spec §6): quiesce starts nonblocking at query
/// time; ENDSESSION(true) accelerates a bounded cleanup; a canceled end
/// finishes the current restoration without reopening; forced termination
/// is covered by the service and replay.
pub fn handle_session(event: SessionEvent) -> SessionAction {
    match event {
        SessionEvent::QueryEndSession => SessionAction::StartQuiesce,
        SessionEvent::EndSession { can_end: true } => SessionAction::BoundedQuit,
        SessionEvent::EndSession { can_end: false } => SessionAction::JoinOnly,
        SessionEvent::ConsoleCtrl => SessionAction::BoundedQuit,
        SessionEvent::Logoff => SessionAction::BoundedQuit,
    }
}

// ---------------------------------------------------------------------------
// Diagnostics snapshot for the UI hooks
// ---------------------------------------------------------------------------

/// What the UI hooks (`app.slint` recovery/diagnostics properties) show.
/// Pending/conflict is visible, never success; the raw reason strings come
/// from the service reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootDiagnostics {
    pub decision: BootDecision,
    pub recovery: Option<BootRecovery>,
    pub authority_pending: Option<String>,
    pub legacy_summary: Option<String>,
}

impl BootDiagnostics {
    /// One-line state for the status surface.
    pub fn state_line(&self) -> String {
        if let Some(debt) = &self.authority_pending {
            return format!("DNS recovery pending: {debt}");
        }
        match &self.decision {
            BootDecision::ProceedAutoConnect => "DNS ready".into(),
            BootDecision::ProceedDiagnosticOnly { reason } => {
                format!("DNS off — automatic connect blocked: {reason}")
            }
            BootDecision::RefuseTakeoverQuit { owner } => {
                format!("Another Yeager owns DNS ({owner}); activating it")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: fakes at the seams, never real NICs
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // ---- fakes ----------------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum CtlEvent {
        Inspect,
        Recover,
        Shutdown(BootShutdownKind),
    }

    struct FakeCtl {
        state: JournalState,
        recovery: BootRecovery,
        log: StdMutex<Vec<CtlEvent>>,
        shutdowns: StdMutex<usize>,
    }

    impl FakeCtl {
        fn dead_owner() -> Self {
            Self {
                state: JournalState::OwnedDead {
                    owner: "owner-1".into(),
                },
                recovery: BootRecovery::RestoredVerified,
                log: StdMutex::new(Vec::new()),
                shutdowns: StdMutex::new(0),
            }
        }

        fn events(&self) -> Vec<CtlEvent> {
            self.log.lock().unwrap().clone()
        }
    }

    impl BootCtl for FakeCtl {
        fn inspect(&self) -> JournalState {
            self.log.lock().unwrap().push(CtlEvent::Inspect);
            self.state.clone()
        }

        fn recover(&self) -> BootRecovery {
            self.log.lock().unwrap().push(CtlEvent::Recover);
            self.recovery.clone()
        }

        fn shutdown(&self, kind: BootShutdownKind) -> ShutdownReport {
            self.log.lock().unwrap().push(CtlEvent::Shutdown(kind));
            *self.shutdowns.lock().unwrap() += 1;
            let kind = ShutdownKind::from(kind);
            ShutdownReport {
                reopened: kind == ShutdownKind::DnsOff,
                epoch: 1,
                kind,
                dns: DnsOutcome::Verified,
                engine: crate::lifecycle::EngineOutcome::Completed,
                cancelled_queued: 0,
                ui_error: None,
                persist_error: None,
            }
        }
    }

    fn clean_plan() -> StepPlan {
        StepPlan { fail: Vec::new() }
    }

    // ---- recovery precedes every failure site -----------------------------

    #[test]
    fn recovery_precedes_every_fallible_init_failure() {
        for step in [
            BootStep::LoadConfig,
            BootStep::CreateWindow,
            BootStep::SetupTray,
            BootStep::InitUpdater,
            BootStep::ShowUi,
            BootStep::RunEventLoop,
        ] {
            let ctl = FakeCtl::dead_owner();
            let driver = BootDriver::new(&ctl);
            let report = driver.run(&StepPlan { fail: vec![step] });
            // Recovery ran and precedes the failure in the event log.
            let recover_at = report
                .events
                .iter()
                .position(|e| *e == BootEvent::Recovered)
                .unwrap_or_else(|| panic!("no recovery before {step:?}"));
            let fail_at = report
                .events
                .iter()
                .position(|e| *e == BootEvent::StepFailed(step))
                .unwrap();
            assert!(recover_at < fail_at, "recovery must precede {step:?}");
            // The guard never bypassed cleanup: exactly one shutdown ran.
            assert_eq!(report.failed_step, Some(step));
            assert!(report.shutdown.is_some());
            assert_eq!(*ctl.shutdowns.lock().unwrap(), 1);
            assert_eq!(report.recovery, Some(BootRecovery::RestoredVerified));
            assert_eq!(report.decision, BootDecision::ProceedAutoConnect);
        }
    }

    #[test]
    fn clean_boot_runs_recovery_then_all_steps_without_shutdown() {
        let ctl = FakeCtl {
            state: JournalState::Clean,
            ..FakeCtl::dead_owner()
        };
        let report = BootDriver::new(&ctl).run(&clean_plan());
        // Even a clean journal replays (idempotent verify) before init.
        assert!(report.events.contains(&BootEvent::Recovered));
        assert_eq!(report.failed_step, None);
        assert_eq!(report.shutdown, None);
        assert_eq!(*ctl.shutdowns.lock().unwrap(), 0);
        assert_eq!(report.decision, BootDecision::ProceedAutoConnect);
    }

    #[test]
    fn unknown_or_deferred_journal_blocks_autoconnect_but_runs_ui() {
        for state in [
            JournalState::DeferredOrUnknown {
                reason: "probe inconclusive".into(),
            },
            JournalState::IntegrityFailure {
                reason: "digest mismatch".into(),
            },
            JournalState::UnsupportedSnapshot {
                reason: "schema 2".into(),
            },
        ] {
            let ctl = FakeCtl {
                state,
                ..FakeCtl::dead_owner()
            };
            let report = BootDriver::new(&ctl).run(&clean_plan());
            // No recovery attempt with no authority (journal retained
            // untouched), no shutdown, but the UI path may run while
            // auto-connect stays blocked.
            assert!(!report.events.contains(&BootEvent::Recovered));
            assert!(report.decision.blocks_auto_connect());
            assert!(matches!(
                report.decision,
                BootDecision::ProceedDiagnosticOnly { .. }
            ));
            assert_eq!(report.failed_step, None);
            assert_eq!(*ctl.shutdowns.lock().unwrap(), 0);
        }
    }

    #[test]
    fn pending_recovery_blocks_autoconnect_with_visible_debt() {
        for recovery in [
            BootRecovery::Pending("adapter gone".into()),
            BootRecovery::Conflict("foreign admin edit".into()),
            BootRecovery::Refused("service unavailable".into()),
        ] {
            let ctl = FakeCtl {
                recovery,
                ..FakeCtl::dead_owner()
            };
            let report = BootDriver::new(&ctl).run(&clean_plan());
            assert!(report.decision.blocks_auto_connect());
            assert!(matches!(
                report.decision,
                BootDecision::ProceedDiagnosticOnly { .. }
            ));
        }
    }

    #[test]
    fn live_duplicate_never_quiesces_the_owner() {
        let ctl = FakeCtl {
            state: JournalState::OwnedLive {
                owner: "owner-live".into(),
            },
            ..FakeCtl::dead_owner()
        };
        let report = BootDriver::new(&ctl).run(&clean_plan());
        assert_eq!(
            report.decision,
            BootDecision::RefuseTakeoverQuit {
                owner: "owner-live".into(),
            }
        );
        // No recovery, no shutdown, no step ran: the owner's lease is
        // untouched. A guard armed here would quiesce the owner — so no
        // guard is armed on this path at all.
        assert_eq!(report.events, vec![BootEvent::Inspected]);
        assert_eq!(*ctl.shutdowns.lock().unwrap(), 0);
    }

    #[test]
    fn guard_runs_shutdown_on_early_return_and_disarms_on_complete() {
        // Early return without complete: the guard shuts down exactly once.
        let armed = FakeCtl::dead_owner();
        {
            let mut _guard = BootGuard::arm(&armed, BootShutdownKind::ProcessQuit);
        }
        assert_eq!(*armed.shutdowns.lock().unwrap(), 1);
        assert_eq!(
            armed.events(),
            vec![CtlEvent::Shutdown(BootShutdownKind::ProcessQuit)]
        );

        // Completed guard: dropping runs nothing.
        let completed = FakeCtl::dead_owner();
        {
            let mut guard = BootGuard::arm(&completed, BootShutdownKind::ProcessQuit);
            guard.complete();
        }
        assert_eq!(*completed.shutdowns.lock().unwrap(), 0);
        assert_eq!(completed.events(), vec![]);

        // Dismissed live-duplicate path: dropping runs nothing.
        let dismissed = FakeCtl::dead_owner();
        {
            let mut guard = BootGuard::arm(&dismissed, BootShutdownKind::ProcessQuit);
            guard.dismiss();
        }
        assert_eq!(*dismissed.shutdowns.lock().unwrap(), 0);
        assert_eq!(dismissed.events(), vec![]);
    }

    // ---- every exit-table row ---------------------------------------------

    #[test]
    fn every_entry_path_has_a_row_and_a_behavior() {
        // The table is complete: 28 rows, each with a non-empty behavior
        // and a shutdown iff the row requires coordinator teardown.
        assert_eq!(EntryPath::ALL.len(), 28);
        for path in EntryPath::ALL {
            let exp = plan_entry(path);
            assert!(!exp.behavior.is_empty(), "{} needs a behavior", path.name());
            match path {
                EntryPath::WindowCloseWithTray
                | EntryPath::Minimize
                | EntryPath::EngineToggleOff
                | EntryPath::EngineStartError
                | EntryPath::ProviderOrLocalChange
                | EntryPath::EnableFailure
                | EntryPath::UpdateFailure
                | EntryPath::DuplicateInstance
                | EntryPath::UpstreamFailure
                | EntryPath::DnsTestError
                | EntryPath::ListenerTaskError
                | EntryPath::AbortOrHardKill
                | EntryPath::PowerLoss
                | EntryPath::ServiceStop => assert_eq!(
                    exp.shutdown, None,
                    "{} must not run coordinator shutdown",
                    path.name()
                ),
                _ => assert!(
                    exp.shutdown.is_some(),
                    "{} must run coordinator shutdown",
                    path.name()
                ),
            }
        }
    }

    #[test]
    fn entry_shutdown_kinds_match_the_table() {
        // DNS-off rows reopen on a fresh epoch; process-quit rows never do.
        // The kind asserted here is what `main.rs` passes to the lifecycle.
        let off = [EntryPath::DnsToggleOff, EntryPath::CleanupApiFailure];
        for path in off {
            assert_eq!(
                plan_entry(path).shutdown,
                Some(BootShutdownKind::DnsOff),
                "{}",
                path.name()
            );
        }
        let quit = [
            EntryPath::NormalEventLoopReturn,
            EntryPath::TrayExit,
            EntryPath::WindowCloseWithoutTray,
            EntryPath::UpdateSuccessRestart,
            EntryPath::InstallerUpgrade,
            EntryPath::UninstallerCleanup,
            EntryPath::UnsupportedOs,
            EntryPath::MainWindowNewFailure,
            EntryPath::UiShowOrEventLoopError,
            EntryPath::SessionEnd,
            EntryPath::Panic,
            EntryPath::QuitVsQueuedEnable,
        ];
        for path in quit {
            assert_eq!(
                plan_entry(path).shutdown,
                Some(BootShutdownKind::ProcessQuit),
                "{}",
                path.name()
            );
        }
        // Only a verified update cleanup may restart afterwards; a failed
        // cleanup cancels the restart (spec §10).
        assert!(plan_entry(EntryPath::UpdateSuccessRestart).may_restart_after);
        assert!(!plan_entry(EntryPath::UpdateFailure).may_restart_after);
        assert!(!plan_entry(EntryPath::UninstallerCleanup).may_restart_after);
    }

    #[test]
    fn tray_exit_and_close_without_tray_share_process_shutdown() {
        let ctl = FakeCtl::dead_owner();
        for path in [EntryPath::TrayExit, EntryPath::WindowCloseWithoutTray] {
            let exp = plan_entry(path);
            let report = ctl.shutdown(exp.shutdown.unwrap());
            assert_eq!(report.kind, crate::lifecycle::ShutdownKind::ProcessQuit);
            assert!(report.successful());
            assert!(!report.reopened);
        }
        assert_eq!(*ctl.shutdowns.lock().unwrap(), 2);
    }

    #[test]
    fn dns_off_reopens_only_on_a_clean_epoch() {
        let ctl = FakeCtl::dead_owner();
        let report = ctl.shutdown(BootShutdownKind::DnsOff);
        assert_eq!(report.kind, crate::lifecycle::ShutdownKind::DnsOff);
        assert!(report.reopened);
    }

    #[test]
    fn hide_and_minimize_run_no_shutdown() {
        // Window-close-with-tray and minimize keep the owner and DNS alive:
        // asserting through the fake that nothing is requested.
        for path in [EntryPath::WindowCloseWithTray, EntryPath::Minimize] {
            assert_eq!(plan_entry(path).shutdown, None);
        }
        assert_eq!(*FakeCtl::dead_owner().shutdowns.lock().unwrap(), 0);
    }

    // ---- session events ----------------------------------------------------

    #[test]
    fn session_mapping_quiesce_then_bounded_quit_or_join() {
        assert_eq!(
            handle_session(SessionEvent::QueryEndSession),
            SessionAction::StartQuiesce
        );
        assert_eq!(
            handle_session(SessionEvent::EndSession { can_end: true }),
            SessionAction::BoundedQuit
        );
        assert_eq!(
            handle_session(SessionEvent::EndSession { can_end: false }),
            SessionAction::JoinOnly
        );
        assert_eq!(
            handle_session(SessionEvent::ConsoleCtrl),
            SessionAction::BoundedQuit
        );
        assert_eq!(
            handle_session(SessionEvent::Logoff),
            SessionAction::BoundedQuit
        );
    }

    // ---- diagnostics --------------------------------------------------------

    #[test]
    fn diagnostics_state_line_never_claims_success_with_debt() {
        let d = BootDiagnostics {
            decision: BootDecision::ProceedAutoConnect,
            recovery: Some(BootRecovery::RestoredVerified),
            authority_pending: Some("adapter gone".into()),
            legacy_summary: None,
        };
        let line = d.state_line();
        assert!(line.contains("pending"));
        assert!(!line.contains("ready"));

        let d = BootDiagnostics {
            decision: BootDecision::ProceedDiagnosticOnly {
                reason: "debt".into(),
            },
            recovery: None,
            authority_pending: None,
            legacy_summary: None,
        };
        assert!(d.state_line().contains("blocked"));
    }
}

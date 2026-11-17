//! App bootstrap seams: the lifecycle's DNS/engine/UI/config bindings, the
//! session-notification mapping and the exit guard.
//!
//! DNS is backup state and restore only — no recovery service, journal,
//! transaction engine or replay. Every DNS operation goes through the single
//! process-wide [`hange::Authority`], which saves the affected adapters'
//! current DNS to a plain backup file before a takeover and writes it back on
//! disable/exit. Any backup/restore failure degrades the DNS feature only; it
//! never blocks launch, the engine or uninstall.

use crate::lifecycle::{DnsCtl, DnsOutcome, EngineCtl, PersistCfg, ShutdownKind, UiNotify};
use hange::Choice;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Production DNS seam: Lifecycle over the single hange Authority
// ---------------------------------------------------------------------------

/// [`DnsCtl`] over the single process-wide [`hange::Authority`]. Only a
/// debt-free state reads as [`DnsOutcome::Verified`]; anything else is pending
/// (visible, never success).
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
        // Admission close is the lifecycle's own; the authority holds no
        // separate lease to revoke, so there is nothing to do here.
    }

    fn restore(&self) -> DnsOutcome {
        match self.authority.restore() {
            Ok(status) => Self::verified_or_pending(status),
            Err(e) => Self::err_or_pending(e),
        }
    }

    fn verify(&self) -> bool {
        self.authority.status().healthy()
    }

    fn stop_listeners(&self) {
        // Only ever called after a verified restore (lifecycle orders it).
        self.authority.stop_listeners();
    }

    fn handoff(&self) {
        // Pending branch: retain the listener, keep the debt visible.
        self.authority.handoff("shutdown with restore debt; DNS authority retained");
    }

    fn enable(&self, choice: Choice, local: bool, _epoch: u64) -> DnsOutcome {
        match self.authority.enable(choice, local) {
            Ok(_) => DnsOutcome::Verified,
            Err(e) => Self::err_or_pending(e),
        }
    }

    fn reconfigure(&self, choice: Choice, local: bool, _epoch: u64) -> DnsOutcome {
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

/// [`EngineCtl`] over `crate::engine`. Stop runs on the lifecycle's detached
/// thread with a bounded join and caught unwind; start is gated by the
/// lifecycle epoch and carries the current config snapshot.
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
        // Best effort inside the epoch gate: a start failure is recorded for
        // diagnostics and never breaks DNS recovery behind it.
        if let Err(e) = crate::engine::start(&(self.config)()) {
            self.start_errors
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(e.to_string());
        }
    }
}

/// [`UiNotify`] that records messages into a shared log. The UI thread drains
/// the log into the visible log surface, so shutdown threads never touch
/// Slint directly. Never fails: a full log simply drops the oldest entries.
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

/// [`PersistCfg`] for this app: configuration is saved synchronously at every
/// mutation site in `main.rs` (durable before shutdown) and the epilogue
/// flushes the debounced domain save, so the shutdown-time persist seam is a
/// no-op by design. Real saves happen (and surface errors) at their own sites.
pub struct NoopPersist;

impl PersistCfg for NoopPersist {
    fn save(&self) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Exit guard
// ---------------------------------------------------------------------------

/// RAII exit guard: settles this process's DNS through the lifecycle on any
/// early return after it is armed, unless the normal path already shut down
/// and marked it complete. Armed only after the early-return paths (duplicate
/// instance, unsupported OS) so none of them can fire it by accident.
pub struct BootGuard<'a> {
    lifecycle: &'a crate::AppLifecycle,
    kind: ShutdownKind,
    completed: bool,
}

impl<'a> BootGuard<'a> {
    pub fn arm(lifecycle: &'a crate::AppLifecycle, kind: ShutdownKind) -> Self {
        Self { lifecycle, kind, completed: false }
    }

    pub fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for BootGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.lifecycle.shutdown(self.kind);
        }
    }
}

// ---------------------------------------------------------------------------
// Session notifications (WM_QUERYENDSESSION / WM_ENDSESSION / console)
// ---------------------------------------------------------------------------

/// Native session/console notification, normalized at the OS seam in
/// `platform.rs`. The mapping below is pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Session is ending unless we refuse: start quiesce, return promptly.
    QueryEndSession,
    /// Session end decision: true = end now (bounded cleanup), false =
    /// canceled (finish the current restoration, never reopen).
    EndSession { can_end: bool },
    /// Attached-console control (Ctrl+C / close / logoff): bounded quit.
    ConsoleCtrl,
}

/// Sink for native session/console notifications: implemented by `main.rs`
/// over the shared lifecycle, installed by `platform::install_session_hook`.
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

/// Pure session mapping: quiesce starts nonblocking at query time;
/// ENDSESSION(true) accelerates a bounded cleanup; a canceled end finishes the
/// current restoration without reopening. A forced termination leaves a
/// backup the next launch restores.
pub fn handle_session(event: SessionEvent) -> SessionAction {
    match event {
        SessionEvent::QueryEndSession => SessionAction::StartQuiesce,
        SessionEvent::EndSession { can_end: true } => SessionAction::BoundedQuit,
        SessionEvent::EndSession { can_end: false } => SessionAction::JoinOnly,
        SessionEvent::ConsoleCtrl => SessionAction::BoundedQuit,
    }
}

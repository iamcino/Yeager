//! Bounded supervised listeners: the binder seam the DNS controller uses.
//!
//! A [`ManagedListener`] is a running stub under supervision; a
//! [`ListenerBinder`] turns a [`ListenerPlan`] into one. The seam is generic
//! so the controller's fallbacks are testable against scripted fakes without
//! touching real NICs. Plans follow the provider address rules in
//! [`crate::plan`]: UDP+TCP on both families, v6 failure degrades to v4-only,
//! both failing means Windows-only with no loopback listener.

use crate::plan::ListenerPlan;
use crate::pool::Choice;
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
    /// Retarget the serving forwarder to a new provider while the sockets
    /// stay bound.
    fn retarget(&self, choice: Choice);
    /// The provider the serving forwarder actually uses right now. `None`
    /// for script stubs without a real pool.
    fn effective_provider(&self) -> Option<common::DohProvider>;
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
    fn retarget(&self, choice: Choice) {
        crate::stub::Stub::retarget(self, choice);
    }
    fn effective_provider(&self) -> Option<common::DohProvider> {
        Some(crate::stub::Stub::effective_provider(self))
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

/// Production binder: binds the real stub for the plan's addresses, with the
/// choice following the latest mutating call rather than construction time.
/// The controller serves many enable/change calls with different choices over
/// one process lifetime; this lets it retarget the choice before each fresh
/// bind while keeping the serving sockets.
pub struct ChoiceBinder {
    choice: std::sync::Mutex<Choice>,
}

impl ChoiceBinder {
    pub fn new(choice: Choice) -> Self {
        Self { choice: std::sync::Mutex::new(choice) }
    }

    /// Point future binds at `choice`. In-flight serving listeners are
    /// retargeted by the controller itself; this only affects the next bind.
    pub fn set(&self, choice: Choice) {
        *self.choice.lock().unwrap_or_else(|e| e.into_inner()) = choice;
    }

    pub fn get(&self) -> Choice {
        *self.choice.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ListenerBinder for ChoiceBinder {
    fn bind(&self, plan: &ListenerPlan) -> Result<Box<dyn ManagedListener>, BindError> {
        if !plan.serves_local() {
            return Err(BindError("windows-only plan binds no listener".into()));
        }
        let choice = self.get();
        crate::stub::Stub::start(crate::pool::Pool::new(choice), &plan.addrs)
            .map(|s| Box::new(s) as Box<dyn ManagedListener>)
            .map_err(|e| BindError(e.to_string()))
    }
}

/// Supervision tick result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervision {
    /// No configuration to supervise.
    Idle,
    /// Listener healthy; health reported.
    Healthy,
    /// Listener alive but not responding; restore requested.
    NonResponding,
    /// Listener task dead; restore requested.
    TaskLost,
}

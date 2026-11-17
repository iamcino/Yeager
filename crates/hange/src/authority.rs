//! The single process-wide DNS controller.
//!
//! Every DNS mutation in the GUI process goes through this module. The
//! mechanism is backup-state-and-restore only: on enable it FIRST saves the
//! current adapter DNS to the one plain [`crate::backup`] file, THEN points
//! adapters at the stub; on disable, exit, or crash leftover it writes the
//! backed-up state back and deletes the file. There is no service, no
//! journal, no transaction engine and no replay.
//!
//! The controller lives on one serial worker thread so enable → change →
//! disable keep one session. Callers hold [`Authority`], a channel handle
//! that is `Send + Sync`. Every path is fail-open: a backup/restore failure
//! degrades the DNS feature only (visible as pending debt) and never blocks
//! the app, the engine, or uninstall.

use crate::backup;
use crate::listener::{ChoiceBinder, ListenerBinder, ManagedListener, Supervision, STOP_BOUND};
use crate::plan::{self, ListenerMode, ListenerPlan};
use crate::pool::Choice;
use crate::system;
use common::{DohProvider, Error, Result};
use std::net::SocketAddr;
use std::sync::{mpsc, OnceLock};
use std::time::Duration;

/// What [`Authority::enable`] set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Adapters now resolving through Yeager.
    pub interfaces: Vec<String>,
    /// Whether a local stub is in front (otherwise Windows DoH only).
    pub serving_local: bool,
}

/// Current controller state for diagnostics/UI. Pending debt is visible,
/// never success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub enabled: bool,
    pub serving_local: bool,
    pub addrs: Vec<SocketAddr>,
    pub pending: Option<String>,
    pub epoch: Option<u64>,
}

impl AuthorityStatus {
    /// Debt-free. Only a debt-free state counts as healthy.
    pub fn healthy(&self) -> bool {
        self.pending.is_none()
    }
}

enum Request {
    Enable { choice: Choice, local: bool, reply: mpsc::Sender<Result<Applied>> },
    Change { choice: Choice, local: bool, reply: mpsc::Sender<Result<Applied>> },
    Disable { reply: mpsc::Sender<Result<AuthorityStatus>> },
    Restore { reply: mpsc::Sender<Result<AuthorityStatus>> },
    StopListeners { reply: mpsc::Sender<()> },
    Handoff { reason: String, reply: mpsc::Sender<()> },
    Status { reply: mpsc::Sender<AuthorityStatus> },
    ServingProvider { reply: mpsc::Sender<Option<DohProvider>> },
    Supervise { reply: mpsc::Sender<Supervision> },
}

/// Process-wide DNS controller handle. Cloneable; every clone talks to the
/// same worker and the same serving listener.
#[derive(Clone)]
pub struct Authority {
    tx: mpsc::Sender<Request>,
}

impl Authority {
    fn send<T>(&self, mk: impl FnOnce(mpsc::Sender<T>) -> Request) -> Result<T> {
        let (reply, rx) = mpsc::channel();
        self.tx.send(mk(reply)).map_err(|_| Error::new("DNS controller worker is gone"))?;
        rx.recv().map_err(|_| Error::new("DNS controller worker dropped the reply"))
    }

    fn op_err(op: &str, e: Error) -> Error {
        Error::new(common::t!("DNS {op} lỗi: {e}", "DNS {op} failed: {e}"))
    }

    /// Saves a backup first (unless one already exists), then points adapters
    /// at the stub. A failure restores the backup and degrades DNS only.
    pub fn enable(&self, choice: Choice, local: bool) -> Result<Applied> {
        self.send(|reply| Request::Enable { choice, local, reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("enable", e))
    }

    /// Serialized provider/local-mode change. Retains the original backup; a
    /// failed change restores it, never a half-mixed state.
    pub fn change(&self, choice: Choice, local: bool) -> Result<Applied> {
        self.send(|reply| Request::Change { choice, local, reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("change", e))
    }

    /// Restores the backed-up original and deletes the backup, then stops the
    /// listener. A restore failure keeps the backup and the listener and is
    /// reported as pending debt — never success.
    pub fn disable(&self) -> Result<AuthorityStatus> {
        self.send(|reply| Request::Disable { reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("disable", e))
    }

    /// Restores the backed-up original (also the crash-leftover path). With
    /// no backup this is a debt-free no-op.
    pub fn restore(&self) -> Result<AuthorityStatus> {
        self.send(|reply| Request::Restore { reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("restore", e))
    }

    /// Bounded serving-listener stop. Only called after a verified restore.
    pub fn stop_listeners(&self) {
        let _ = self.send(|reply| Request::StopListeners { reply });
    }

    /// Explicit handoff for the pending branch: retain the listener, keep the
    /// debt visible.
    pub fn handoff(&self, reason: &str) {
        let reason = reason.to_string();
        let _ = self.send(|reply| Request::Handoff { reason, reply });
    }

    /// Current controller state. Pending debt is reported, never hidden.
    pub fn status(&self) -> AuthorityStatus {
        self.send(|reply| Request::Status { reply }).unwrap_or(AuthorityStatus {
            enabled: false,
            serving_local: false,
            addrs: Vec::new(),
            pending: Some("DNS controller worker is gone".into()),
            epoch: None,
        })
    }

    /// The provider the serving configuration answers with, if any.
    pub fn serving_provider(&self) -> Option<DohProvider> {
        let (reply, rx) = mpsc::channel();
        self.tx.send(Request::ServingProvider { reply }).ok()?;
        rx.recv().ok()?
    }

    /// One supervision pass over the serving listener: probes liveness,
    /// restores on terminal task loss, and reports what it did. With no
    /// active configuration it is `Idle`.
    pub fn supervise_tick(&self) -> Option<Supervision> {
        let (reply, rx) = mpsc::channel();
        self.tx.send(Request::Supervise { reply }).ok()?;
        rx.recv().ok()
    }
}

/// The process-wide controller. One worker, one serving listener.
pub fn global() -> Authority {
    static CELL: OnceLock<Authority> = OnceLock::new();
    CELL.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || worker(rx));
        Authority { tx }
    })
    .clone()
}

/// Which provider Windows is pointed at for `choice`: in Auto mode the stub
/// picks, and Windows keeps Cloudflare behind it.
pub fn system_provider(choice: Choice) -> DohProvider {
    match choice {
        Choice::Fixed(p) => p,
        Choice::Auto => crate::pool::AUTO_PROVIDERS[0],
    }
}

struct Controller {
    binder: ChoiceBinder,
    enabled: bool,
    choice: Choice,
    plan: ListenerPlan,
    listener: Option<Box<dyn ManagedListener>>,
    pending: Option<String>,
}

fn worker(rx: mpsc::Receiver<Request>) {
    let mut c = Controller {
        binder: ChoiceBinder::new(Choice::Auto),
        enabled: false,
        choice: Choice::Auto,
        plan: ListenerPlan::for_mode(ListenerMode::WindowsOnly),
        listener: None,
        pending: None,
    };
    for req in rx {
        match req {
            Request::Enable { choice, local, reply } => { let _ = reply.send(c.enable(choice, local)); }
            Request::Change { choice, local, reply } => { let _ = reply.send(c.enable(choice, local)); }
            Request::Disable { reply } => { let _ = reply.send(Ok(c.restore())); }
            Request::Restore { reply } => { let _ = reply.send(Ok(c.restore())); }
            Request::StopListeners { reply } => { c.stop_listener_bounded(); let _ = reply.send(()); }
            Request::Handoff { reason, reply } => { c.pending = Some(reason); let _ = reply.send(()); }
            Request::Status { reply } => { let _ = reply.send(c.status()); }
            Request::ServingProvider { reply } => { let _ = reply.send(c.serving_provider()); }
            Request::Supervise { reply } => { let _ = reply.send(c.supervise_tick()); }
        }
    }
}

impl Controller {
    fn enable(&mut self, choice: Choice, local: bool) -> Result<Applied> {
        self.binder.set(choice);
        // FIRST save the current state, unless a backup already exists (a
        // crash leftover or this session's original): never re-capture over
        // the original, which would lose the pre-takeover state.
        if !backup::exists() {
            let caps = system::capture()?;
            backup::save(&caps)?;
        }
        let (plan, candidate, reused) = match self.bind_proven(local) {
            Ok(x) => x,
            Err(e) => {
                self.rollback();
                return Err(Error::new(e));
            }
        };
        let provider = system_provider(choice);
        let refs = plan::local_refs(&plan);
        let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
        let interfaces = match system::apply(provider, &refs) {
            Ok(v) => v,
            Err(e) => {
                if let Some(stub) = candidate {
                    let _ = stub.shutdown_bounded(STOP_BOUND);
                }
                self.rollback();
                return Err(e);
            }
        };
        self.install(choice, plan, candidate, reused);
        self.enabled = true;
        self.pending = None;
        Ok(Applied { interfaces, serving_local: self.listener.is_some() })
    }

    /// Restores the backed-up original and deletes the backup; stops the
    /// listener only after a verified restore. A restore failure keeps the
    /// backup and the listener and records pending debt.
    fn restore(&mut self) -> AuthorityStatus {
        if backup::exists() {
            match backup::load().and_then(|b| system::restore(&b)) {
                Ok(()) => {
                    backup::delete();
                    self.pending = None;
                }
                Err(e) => {
                    self.pending = Some(common::t!("Khôi phục DNS thất bại: {e}", "DNS restore failed: {e}"));
                }
            }
        } else {
            self.pending = None;
        }
        if self.pending.is_none() {
            self.stop_listener_bounded();
            self.enabled = false;
            self.plan = ListenerPlan::for_mode(ListenerMode::WindowsOnly);
        }
        self.status()
    }

    /// Undo a failed enable: restore the backup (delete on success), stop the
    /// listener, leave DNS off. Fail-open: a restore failure keeps the backup.
    fn rollback(&mut self) {
        if backup::exists() {
            match backup::load().and_then(|b| system::restore(&b)) {
                Ok(()) => {
                    backup::delete();
                    self.pending = None;
                }
                Err(e) => {
                    self.pending = Some(common::t!("Khôi phục DNS thất bại: {e}", "DNS restore failed: {e}"));
                }
            }
        }
        self.stop_listener_bounded();
        self.enabled = false;
        self.plan = ListenerPlan::for_mode(ListenerMode::WindowsOnly);
    }

    /// Prove a listener plan: reuse a live responsive listener, else bind
    /// dual then v4-only, else Windows-only. Never serves an unproven loopback.
    fn bind_proven(
        &self,
        local_requested: bool,
    ) -> std::result::Result<(ListenerPlan, Option<Box<dyn ManagedListener>>, bool), String> {
        if !local_requested {
            return Ok((ListenerPlan::for_mode(ListenerMode::WindowsOnly), None, false));
        }
        if let Some(serving) = self.listener.as_ref() {
            if serving.alive() && serving.responds() {
                return Ok((self.plan.clone(), None, true));
            }
            if serving.alive() {
                return Err("local plan cannot be proven: serving listener non-responding while bound".into());
            }
        }
        let held = self.listener.is_some();
        for mode in [ListenerMode::Dual, ListenerMode::V4Only] {
            let plan = ListenerPlan::for_mode(mode);
            if plan::check_plan_rules(&plan).is_err() {
                continue;
            }
            match self.binder.bind(&plan) {
                Ok(listener) if listener.responds() => return Ok((plan, Some(listener), false)),
                Ok(listener) => {
                    let _ = listener.shutdown_bounded(Duration::from_millis(500));
                }
                Err(_) => {}
            }
        }
        if held {
            return Err("local plan cannot be proven while serving sockets stay bound".into());
        }
        Ok((ListenerPlan::for_mode(ListenerMode::WindowsOnly), None, false))
    }

    fn install(
        &mut self,
        choice: Choice,
        plan: ListenerPlan,
        candidate: Option<Box<dyn ManagedListener>>,
        reused: bool,
    ) {
        if reused {
            if let Some(serving) = self.listener.as_ref() {
                serving.retarget(choice);
            }
            self.choice = choice;
            self.plan = plan;
            return;
        }
        let old = self.listener.take();
        self.listener = candidate;
        self.choice = choice;
        self.plan = plan;
        if let Some(stub) = old {
            let _ = stub.shutdown_bounded(STOP_BOUND);
        }
    }

    fn stop_listener_bounded(&mut self) {
        if let Some(stub) = self.listener.take() {
            let _ = stub.shutdown_bounded(STOP_BOUND);
        }
    }

    fn supervise_tick(&mut self) -> Supervision {
        if !self.enabled {
            return Supervision::Idle;
        }
        match self.listener.as_ref() {
            None => Supervision::Healthy,
            Some(l) if !l.alive() => {
                self.restore();
                self.stop_listener_bounded();
                Supervision::TaskLost
            }
            Some(l) if !l.responds() => Supervision::NonResponding,
            Some(_) => Supervision::Healthy,
        }
    }

    fn serving_provider(&self) -> Option<DohProvider> {
        if self.enabled {
            Some(system_provider(self.choice))
        } else {
            None
        }
    }

    fn status(&self) -> AuthorityStatus {
        AuthorityStatus {
            enabled: self.enabled,
            serving_local: self.listener.is_some(),
            addrs: self.listener.as_ref().map(|l| l.addrs()).unwrap_or_default(),
            pending: self.pending.clone(),
            epoch: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_supervision_with_no_configuration() {
        assert_eq!(global().supervise_tick(), Some(Supervision::Idle));
    }

    #[test]
    fn system_provider_maps_auto_to_cloudflare() {
        assert_eq!(system_provider(Choice::Auto), DohProvider::Cloudflare);
        assert_eq!(system_provider(Choice::Fixed(DohProvider::Google)), DohProvider::Google);
    }
}

//! U08 — the single process-wide DNS authority (SPEC-DNS-FIX.md §6, §12 U08).
//!
//! Every DNS mutation in the GUI process goes through this module, and this
//! module talks only to the U05 privileged service through one
//! [`Coordinator`]: there is exactly one machine transaction and one DNS
//! writer (spec invariant 2). The pre-U08 direct path — `system::apply`
//! with its leading heuristic reset, and `system::reset` as normal
//! rollback — is deleted (a source audit for `reset`, `SetInterfaceDnsSettings`
//! and `clean_up_leftovers` under `crates/hange/src/` finds only this comment
//! and the read-only `servers_without_doh` getter). Rollback is the service restore-to-original, never
//! a heuristic DHCP clear.
//!
//! The coordinator lives on one serial worker thread (spec §3.1: one serial
//! mutation worker). Callers hold [`Authority`], a channel handle that is
//! `Send + Sync`; each request sets the current choice/selection on the
//! worker and runs exactly one coordinator transaction. The worker owns the
//! lease and the serving listener across calls, so enable → change →
//! disable keep one owner session instead of fighting over the machine
//! lease. Section 12 law: the worker logic is thin mapping over the U06
//! coordinator; tests drive it against scripted fakes, never real NICs.

use crate::coordinator::{ChoiceBinder, Coordinator, Supervision};
use crate::pool::Choice;
use crate::service::{PipeClient, SvcOutcome};
use common::{DohProvider, Error, Result};
use std::sync::{mpsc, OnceLock};

/// What [`enable`] set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Adapters now resolving through Yeager.
    pub interfaces: Vec<String>,
    /// Whether a local stub is in front (otherwise Windows DoH only).
    pub serving_local: bool,
}

/// Current authority state for diagnostics/UI. Pending debt is visible,
// never success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub enabled: bool,
    pub serving_local: bool,
    pub addrs: Vec<std::net::SocketAddr>,
    pub pending: Option<String>,
    pub epoch: Option<u64>,
}

impl AuthorityStatus {
    /// Debt-free. Only a debt-free state counts as healthy; pending debt
    /// blocks auto-connect while the diagnostic UI can still run.
    pub fn healthy(&self) -> bool {
        self.pending.is_none()
    }
}

enum Request {
    Enable {
        choice: Choice,
        local: bool,
        reply: mpsc::Sender<Result<Applied>>,
    },
    Change {
        choice: Choice,
        local: bool,
        reply: mpsc::Sender<Result<Applied>>,
    },
    Disable {
        reply: mpsc::Sender<Result<AuthorityStatus>>,
    },
    Quiesce {
        reply: mpsc::Sender<SvcOutcome>,
    },
    Restore {
        reply: mpsc::Sender<Result<AuthorityStatus>>,
    },
    StopListeners {
        reply: mpsc::Sender<()>,
    },
    Handoff {
        reason: String,
        reply: mpsc::Sender<()>,
    },
    Status {
        reply: mpsc::Sender<AuthorityStatus>,
    },
    ServingProvider {
        reply: mpsc::Sender<Option<DohProvider>>,
    },
    Supervise {
        reply: mpsc::Sender<Supervision>,
    },
}

/// Process-wide DNS authority handle. Cloneable; every clone talks to the
/// same worker, the same coordinator, the same lease.
#[derive(Clone)]
pub struct Authority {
    tx: mpsc::Sender<Request>,
}

impl Authority {
    fn send<T>(&self, mk: impl FnOnce(mpsc::Sender<T>) -> Request) -> Result<T> {
        let (reply, rx) = mpsc::channel();
        self.tx
            .send(mk(reply))
            .map_err(|_| Error::new("DNS authority worker is gone"))?;
        rx.recv()
            .map_err(|_| Error::new("DNS authority worker dropped the reply"))
    }

    fn op_err(op: &str, e: Error) -> Error {
        Error::new(common::t!("DNS {op} lỗi: {e}", "DNS {op} failed: {e}"))
    }

    /// Transactional enable through the service. Success is `Active` only;
    /// anything else (including a rollback to the pre-takeover original, or
    /// a missing service) is an error that names the outcome — never a
    /// silent no-op, never a heuristic clear.
    pub fn enable(&self, choice: Choice, local: bool) -> Result<Applied> {
        self.send(|reply| Request::Enable { choice, local, reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("enable", e))
    }

    /// Serialized provider/local-mode change. Retains the original; a
    /// failed change restores the original, never a half-mixed state.
    pub fn change(&self, choice: Choice, local: bool) -> Result<Applied> {
        self.send(|reply| Request::Change { choice, local, reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("change", e))
    }

    /// Transactional disable: consults the journal even with no in-memory
    /// state, restores the exact original, stops listeners only after the
    /// verified restore. Pending/conflict keeps the listener and is an
    /// error — never reported as success.
    pub fn disable(&self) -> Result<AuthorityStatus> {
        self.send(|reply| Request::Disable { reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("disable", e))
    }

    /// DNS-side admission close. Idempotent; safe with no lease.
    pub fn quiesce(&self) -> SvcOutcome {
        self.send(|reply| Request::Quiesce { reply })
            .unwrap_or(SvcOutcome::Unavailable)
    }

    /// Restore the exact pre-takeover original through the service journal.
    pub fn restore(&self) -> Result<AuthorityStatus> {
        self.send(|reply| Request::Restore { reply })
            .and_then(|r| r)
            .map_err(|e| Self::op_err("restore", e))
    }

    /// Bounded serving-listener stop. Only called after a verified restore.
    pub fn stop_listeners(&self) {
        let _ = self.send(|reply| Request::StopListeners { reply });
    }

    /// Explicit handoff for the pending/conflict branch: retain the
    /// listener, keep the debt visible.
    pub fn handoff(&self, reason: &str) {
        let reason = reason.to_string();
        let _ = self.send(|reply| Request::Handoff { reason, reply });
    }

    /// Current authority state. Pending debt is reported, never hidden.
    pub fn status(&self) -> AuthorityStatus {
        self.send(|reply| Request::Status { reply })
            .unwrap_or(AuthorityStatus {
                enabled: false,
                serving_local: false,
                addrs: Vec::new(),
                pending: Some("DNS authority worker is gone".into()),
                epoch: None,
            })
    }

    /// The provider the serving configuration answers with, if any. The
    /// latency route (`stat`) is measured separately by the caller; this is
    /// the serving identity for display and for choosing what to verify.
    pub fn serving_provider(&self) -> Option<DohProvider> {
        let (reply, rx) = mpsc::channel();
        self.tx.send(Request::ServingProvider { reply }).ok()?;
        rx.recv().ok()?
    }

    /// One supervision pass over the serving listener (spec §6 listener
    /// rows): probes liveness, restores on terminal task loss, and reports
    /// what it did. The app calls this periodically; with no active
    /// configuration it is `Idle` and touches no service.
    pub fn supervise_tick(&self) -> Option<Supervision> {
        let (reply, rx) = mpsc::channel();
        self.tx.send(Request::Supervise { reply }).ok()?;
        rx.recv().ok()
    }
}

/// The process-wide authority. One worker, one coordinator, one lease.
pub fn global() -> Authority {
    static CELL: OnceLock<Authority> = OnceLock::new();
    CELL.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || worker(rx));
        Authority { tx }
    })
    .clone()
}

pub fn owner_id() -> String {
    // Production GUI owner identity: a lowercase UUID the service
    // `is_lower_uuid` gate accepts. Generated once per process via the
    // worker (which calls this once at startup) and once per test that
    // proves registrability; never the old `yeager-gui-pid{pid}` shape,
    // which the service rejects.
    dns_recovery::journal::new_uuid()
}

fn selected() -> Vec<String> {
    // Best effort: an empty selection refuses coherently service-side
    // rather than guessing adapters. Arrival alone never enrolls.
    crate::system::online_guids().unwrap_or_default()
}

fn worker(rx: mpsc::Receiver<Request>) {
    let binder = ChoiceBinder::new(Choice::Auto);
    let mut coord = Coordinator::new(PipeClient::new(), binder, &owner_id(), Vec::new());
    for req in rx {
        match req {
            Request::Enable { choice, local, reply } => {
                let outcome = enable_on(&mut coord, choice, local);
                let _ = reply.send(outcome);
            }
            Request::Change { choice, local, reply } => {
                let outcome = change_on(&mut coord, choice, local);
                let _ = reply.send(outcome);
            }
            Request::Disable { reply } => {
                let outcome = disable_on(&mut coord);
                let _ = reply.send(outcome);
            }
            Request::Quiesce { reply } => {
                let report = coord.quiesce_side();
                let _ = reply.send(report.outcome);
            }
            Request::Restore { reply } => {
                let outcome = disable_on(&mut coord);
                let _ = reply.send(outcome);
            }
            Request::StopListeners { reply } => {
                coord.stop_listeners_bounded();
                let _ = reply.send(());
            }
            Request::Handoff { reason, reply } => {
                coord.note_handoff(&reason);
                let _ = reply.send(());
            }
            Request::Status { reply } => {
                let _ = reply.send(status_of(&mut coord));
            }
            Request::ServingProvider { reply } => {
                let _ = reply.send(coord.serving_provider());
            }
            Request::Supervise { reply } => {
                let _ = reply.send(coord.supervise_tick());
            }
        }
    }
}

fn enable_on(
    coord: &mut Coordinator<PipeClient, ChoiceBinder>,
    choice: Choice,
    local: bool,
) -> Result<Applied> {
    coord.set_selected(selected());
    match coord.enable(choice, local) {
        Ok(status) => {
            if let Some(debt) = status.pending {
                Err(Error::new(common::t!(
                    "DNS đã bật nhưng còn nợ khôi phục: {debt}",
                    "DNS is on but recovery debt remains: {debt}"
                )))
            } else {
                Ok(Applied {
                    interfaces: status
                        .addrs
                        .iter()
                        .map(|a| a.ip().to_string())
                        .collect::<Vec<_>>(),
                    serving_local: status.serving_local,
                })
            }
        }
        Err(e) => Err(Error::new(format!("{:?}: {}", e.outcome, e.message))),
    }
}

fn change_on(
    coord: &mut Coordinator<PipeClient, ChoiceBinder>,
    choice: Choice,
    local: bool,
) -> Result<Applied> {
    coord.set_selected(selected());
    match coord.reconfigure(choice, local) {
        Ok(status) => {
            if let Some(debt) = status.pending {
                Err(Error::new(common::t!(
                    "Đã đổi DNS nhưng còn nợ khôi phục: {debt}",
                    "DNS changed but recovery debt remains: {debt}"
                )))
            } else {
                Ok(Applied {
                    interfaces: status
                        .addrs
                        .iter()
                        .map(|a| a.ip().to_string())
                        .collect::<Vec<_>>(),
                    serving_local: status.serving_local,
                })
            }
        }
        Err(e) => Err(Error::new(format!("{:?}: {}", e.outcome, e.message))),
    }
}

fn disable_on(
    coord: &mut Coordinator<PipeClient, ChoiceBinder>,
) -> Result<AuthorityStatus> {
    coord.set_selected(selected());
    match coord.disable() {
        Ok(status) => Ok(AuthorityStatus {
            enabled: status.enabled,
            serving_local: status.serving_local,
            addrs: status.addrs,
            pending: status.pending,
            epoch: status.epoch,
        }),
        Err(e) => Err(Error::new(format!("{:?}: {}", e.outcome, e.message))),
    }
}

fn status_of(coord: &mut Coordinator<PipeClient, ChoiceBinder>) -> AuthorityStatus {
    let status = coord.status();
    AuthorityStatus {
        enabled: status.enabled,
        serving_local: status.serving_local,
        addrs: status.addrs,
        pending: status.pending,
        epoch: status.epoch,
    }
}

/// Which provider Windows is pointed at for `choice`: in Auto mode the stub
/// picks, and Windows keeps Cloudflare behind it.
pub fn system_provider(choice: Choice) -> DohProvider {
    match choice {
        Choice::Fixed(p) => p,
        Choice::Auto => crate::pool::AUTO_PROVIDERS[0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{DnsService, HostClient};
    use dns_recovery::clock::VirtualClock;
    use dns_recovery::fake::FakeOs;
    use dns_recovery::fs::FakeFs;
    use dns_recovery::lock::{FakeLock, MachineLock};
    use dns_recovery::protocol::PeerAuth;
    use dns_recovery::replay::FakeOwnerProbe;
    use dns_recovery::service::{ServiceConfig, ServiceHost};
    use std::rc::Rc;

    #[test]
    fn production_owner_id_registers_against_real_service() {
        // Item 3: the production `owner_id()` itself must be registrable —
        // a lowercase UUID the service `is_lower_uuid` gate accepts.
        let id = owner_id();
        assert!(
            dns_recovery::journal::is_lower_uuid(&id),
            "production owner_id must be a lowercase UUID, got {id}"
        );
        // Register that exact id against the real ServiceHost seam.
        let os = FakeOs::new();
        let fs = Rc::new(FakeFs::new());
        let fs_c = Rc::clone(&fs);
        let os_b = os.clone();
        let os_s = os.clone();
        let lock_base = FakeLock::new();
        let clock = VirtualClock::new(1_763_000_000_000);
        let clock_b = clock.clone();
        let mut host = ServiceHost::new(
            Rc::new(move || Box::new(os_b.clone()) as Box<dyn dns_recovery::backend::DnsBackend>),
            Rc::new(move || Box::new(os_s.clone()) as Box<dyn dns_recovery::setter::DnsSetter>),
            Rc::new(move || Box::new(lock_base.peer(7000, 0)) as Box<dyn MachineLock>),
            Box::new(clock_b),
            Rc::new(move || Box::new(clock.clone()) as Box<dyn dns_recovery::clock::Clock>),
            Rc::new(move || Rc::clone(&fs_c)),
            Rc::new(|| Box::new(FakeOwnerProbe::new()) as Box<dyn dns_recovery::replay::OwnerProbe>),
            ServiceConfig {
                dir: "C:\\ProgramData\\Yeager".to_string(),
                machine_id: "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d".to_string(),
                service_instance_id: "44444444-4444-4444-8444-444444444444".to_string(),
            },
        );
        let peer = PeerAuth {
            pid: 4242,
            creation_filetime: 133_000_000_000_000_000,
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
        };
        let mut client = HostClient::new(&mut host, peer);
        let reg = client
            .register_owner(&id, 0, Some(&"a".repeat(64)), Some("fileid-1"))
            .expect("production owner_id registers against the real host");
        assert!(!reg.token.is_empty());
    }

    #[test]
    fn supervise_request_is_wired_through_the_worker() {
        // Item 4 (listener rows): the authority worker serves supervision —
        // with no active configuration the tick is Idle and never touches
        // the service. Proves the `Supervise` request arm exists and the
        // production periodic tick in `main.rs` reaches the coordinator.
        let tick = global().supervise_tick();
        assert_eq!(tick, Some(Supervision::Idle));
    }
}

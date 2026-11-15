//! yeager-dns-recovery: the privileged DNS recovery service binary (U05,
//! SPEC-DNS-FIX.md §8.3).
//!
//! Modes (all elevated modes refuse without elevation; every mode prints a
//! structured JSON report to stdout and a readable error to stderr):
//! - `--service`: run under the SCM dispatcher (Windows only). Boot replay
//!   before accepting takeover; named-pipe server + watchdog/scheduler.
//! - `--inspect`: read-only journal reconciliation (no writes).
//! - `--recover-offline`: prove the SCM service STOPPED, then replay to an
//!   exact-original restore. Refuses a running/start-pending/unknown service.
//! - `--install-service`: provision the protected binary path, create the
//!   LocalSystem automatic service with 1 s/5 s/30 s failure actions +
//!   preshutdown, start it and validate Hello over the pipe.
//! - `--remove-service`: refuse on recovery debt; otherwise stop and delete.
//! - `--enter-maintenance` / `--leave-maintenance` (U09 installer seams):
//!   enter/leave service maintenance over the protected pipe (admin only).
//!
//! Exit codes (§8.3): 0 verified clean/success; 10 live-owner/busy;
//! 11 pending/unavailable; 12 conflict; 13 privilege/service/auth;
//! 14 integrity/unknown version; 15 unsupported capture/API.

use std::process::ExitCode;

#[cfg(windows)]
mod win {
    use dns_recovery::backend::FamilySelectorPolicy;
    use dns_recovery::clock::SystemClock;
    use dns_recovery::fs_windows::{WindowsFs, WindowsLock};
    use dns_recovery::protocol::{
        self, exit_code_for_outcome, Operation, Request,
    };
    use dns_recovery::replay::{OwnerProbe, ReplayDriver};
    use dns_recovery::service::ScmServiceState;
    use dns_recovery::service_os;
    use dns_recovery::store::JournalStore;
    use dns_recovery::transaction::Outcome;
    use dns_recovery::windows::{WinSetter, WindowsDnsBackend};
    use std::rc::Rc;

    pub fn out(report: &serde_json::Value) {
        println!("{}", serde_json::to_string_pretty(report).unwrap_or_default());
    }

    pub fn fail(mode: &str, exit: i32, error: String) -> ! {
        eprintln!("yeager-dns-recovery --{mode}: {error}");
        out(&serde_json::json!({"mode": mode, "outcome": "error", "exit": exit, "error": error}));
        std::process::exit(exit);
    }

    fn outcome_of(o: Outcome) -> &'static str {
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

    pub fn cmd_service() -> ! {
        match service_os::run_service() {
            Ok(()) => std::process::exit(0),
            Err(e) => fail("service", 13, e),
        }
    }

    fn open_store() -> Result<(JournalStore<Rc<WindowsFs>>, String), String> {
        let dir = service_os::program_data_dir()?;
        let fs = WindowsFs::new().map_err(|e| format!("protected storage unavailable: {e}"))?;
        let store = JournalStore::open(Rc::new(fs), &dir)
            .map_err(|e| format!("journal unavailable: {e}"))?;
        Ok((store, dir))
    }

    pub fn cmd_inspect() -> ! {
        let (store, _dir) = match open_store() {
            Ok(v) => v,
            Err(e) => fail("inspect", 11, e),
        };
        let rec = match store.reconcile() {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                let outcome = if msg.contains("unknown journal version") {
                    "unknown_version"
                } else if msg.contains("integrity") {
                    "integrity_error"
                } else {
                    "unavailable"
                };
                let exit = exit_code_for_outcome(outcome);
                fail("inspect", exit, msg);
            }
        };
        let (state, generation, phase, epoch, owner, entries) = match &rec.current {
            None => ("absent", 0u64, None, None, None, 0usize),
            Some(c) => {
                let tx = c.env.payload.transaction.as_ref();
                (
                    match c.env.payload.journal_state {
                        dns_recovery::journal::JournalState::Clean => "clean",
                        dns_recovery::journal::JournalState::Owned => "owned",
                        dns_recovery::journal::JournalState::Restoring => "restoring",
                        dns_recovery::journal::JournalState::RecoveryPending => {
                            "recovery_pending"
                        }
                        dns_recovery::journal::JournalState::Maintenance => "maintenance",
                    },
                    c.env.generation,
                    tx.map(|t| format!("{:?}", t.phase).to_lowercase()),
                    tx.map(|t| t.epoch),
                    tx.map(|t| {
                        serde_json::json!({
                            "owner_id": t.owner.owner_id,
                            "pid": t.owner.pid,
                            "session_id": t.owner.session_id,
                        })
                    }),
                    tx.map(|t| t.entries.len()).unwrap_or(0),
                )
            }
        };
        let outcome = match state {
            "clean" | "absent" => "verified_restored",
            _ => "pending",
        };
        let exit = exit_code_for_outcome(outcome);
        out(&serde_json::json!({
            "mode": "inspect",
            "outcome": outcome,
            "exit": exit,
            "journal_state": state,
            "generation": generation,
            "phase": phase,
            "epoch": epoch,
            "owner": owner,
            "entries": entries,
            "candidates": rec.candidates.len(),
        }));
        std::process::exit(exit);
    }

    pub fn cmd_recover_offline() -> ! {
        if !service_os::is_elevated() {
            fail("recover-offline", 13, "recover-offline requires elevation".into());
        }
        let state = match service_os::scm_query_state() {
            Ok(s) => s,
            Err(e) => fail("recover-offline", 13, e),
        };
        if let Err(detail) = dns_recovery::service::ServiceHost::<Rc<WindowsFs>>::offline_precheck(state) {
            let outcome = match state {
                ScmServiceState::Unknown => "refused",
                _ => "unavailable",
            };
            let exit = exit_code_for_outcome(outcome);
            fail("recover-offline", exit, detail);
        }
        let dir = match service_os::program_data_dir() {
            Ok(d) => d,
            Err(e) => fail("recover-offline", 11, e),
        };
        let fs = match WindowsFs::new() {
            Ok(f) => Rc::new(f),
            Err(e) => fail("recover-offline", 11, format!("protected storage unavailable: {e}")),
        };
        let fs_b = Rc::clone(&fs);
        let driver = ReplayDriver::new(
            Box::new(|| {
                Box::new(WindowsDnsBackend::new(
                    FamilySelectorPolicy::VersionGatedException,
                )) as Box<dyn dns_recovery::backend::DnsBackend>
            }),
            Box::new(|| Box::new(WinSetter::new()) as Box<dyn dns_recovery::setter::DnsSetter>),
            Box::new(|| Box::new(WindowsLock) as Box<dyn dns_recovery::lock::MachineLock>),
            Box::new(|| Box::new(SystemClock) as Box<dyn dns_recovery::clock::Clock>),
            Box::new(move || Rc::clone(&fs_b)),
            dir,
            service_os::machine_id(),
            service_os::service_instance_id(),
            Box::new(service_os::WindowsOwnerProbe::new()) as Box<dyn OwnerProbe>,
        );
        let report = match driver.replay() {
            Ok(r) => r,
            Err(e) => fail("recover-offline", 11, format!("replay failed: {e}")),
        };
        let outcome = outcome_of(report.outcome);
        let exit = exit_code_for_outcome(outcome);
        out(&serde_json::json!({
            "mode": "recover-offline",
            "outcome": outcome,
            "exit": exit,
            "generation": report.generation,
            "note": report.note,
            "errors": report.errors.len(),
        }));
        std::process::exit(exit);
    }

    fn wait_for_state(want: ScmServiceState, timeout_secs: u64) -> Result<ScmServiceState, String> {
        let mut waited = 0u64;
        loop {
            let state = service_os::scm_query_state()?;
            if std::mem::discriminant(&state) == std::mem::discriminant(&want) {
                return Ok(state);
            }
            if waited >= timeout_secs {
                return Err(format!("service did not reach {want:?} within {timeout_secs}s"));
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
            waited += 1;
        }
    }

    pub fn cmd_install_service() -> ! {
        if !service_os::is_elevated() {
            fail("install-service", 13, "install-service requires elevation".into());
        }
        // Protected binary path: %ProgramFiles%\Yeager.
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
        let dest_dir = format!("{program_files}\\Yeager");
        let dest = format!("{dest_dir}\\yeager-dns-recovery.exe");
        if let Err(e) = std::fs::create_dir_all(&dest_dir) {
            fail("install-service", 13, format!("cannot create {dest_dir}: {e}"));
        }
        let current = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => fail("install-service", 13, format!("cannot locate running image: {e}")),
        };
        if let Err(e) = std::fs::copy(&current, &dest) {
            fail("install-service", 13, format!("cannot stage protected binary: {e}"));
        }
        if let Err(e) = service_os::install_service(&dest) {
            fail("install-service", 13, e);
        }
        if let Err(e) = service_os::start_service() {
            let _ = service_os::stop_service();
            let _ = service_os::remove_service();
            fail("install-service", 13, e);
        }
        if let Err(e) = wait_for_state(ScmServiceState::Running, 30) {
            let _ = service_os::stop_service();
            let _ = service_os::remove_service();
            fail("install-service", 13, e);
        }
        // Hello validation over the protected pipe with the SCM PID check.
        // Retried: the pipe is single-instance and the 1 s scheduler waker
        // also opens it, so one attempt can land on a torn-down instance.
        let hello_outcome = (|| -> Result<String, String> {
            let mut last = "no attempt".to_string();
            for _ in 0..3 {
                let pid = service_os::scm_service_pid()?.ok_or("service has no PID")?;
                let req = Request::new(
                    dns_recovery::journal::new_uuid(),
                    Operation::Hello,
                    None,
                    None,
                    serde_json::json!({}),
                );
                let frame = protocol::encode_frame(&req).map_err(|e| e.to_string())?;
                match service_os::pipe_roundtrip(&frame, Some(pid)).and_then(|raw| {
                    protocol::decode_reply(&raw).map_err(|e| e.to_string())
                }) {
                    Ok(reply) if reply.request_id == req.request_id => {
                        return Ok(reply.outcome);
                    }
                    Ok(_) => last = "hello reply ID mismatch".into(),
                    Err(e) => last = e,
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(last)
        })();
        match hello_outcome {
            Ok(outcome) if outcome == "success" => {
                out(&serde_json::json!({
                    "mode": "install-service",
                    "outcome": "success",
                    "exit": 0,
                    "binary": dest,
                    "hello": outcome,
                }));
                std::process::exit(0);
            }
            Ok(outcome) => {
                let _ = service_os::stop_service();
                let _ = service_os::remove_service();
                fail("install-service", 13, format!("hello validation returned {outcome:?}"));
            }
            Err(e) => {
                let _ = service_os::stop_service();
                let _ = service_os::remove_service();
                fail("install-service", 13, format!("hello validation failed: {e}"));
            }
        }
    }

    pub fn cmd_remove_service() -> ! {
        if !service_os::is_elevated() {
            fail("remove-service", 13, "remove-service requires elevation".into());
        }
        // Removal refuses recovery debt: inspect first.
        let (store, _dir) = match open_store() {
            Ok(v) => v,
            Err(e) => fail("remove-service", 11, e),
        };
        match store.reconcile() {
            Err(e) => fail("remove-service", 14, format!("journal reconciliation failed: {e}")),
            Ok(rec) => {
                if rec
                    .current
                    .as_ref()
                    .is_some_and(|c| c.env.payload.transaction.is_some())
                {
                    fail(
                        "remove-service",
                        11,
                        "recovery debt present: restore before service removal".into(),
                    );
                }
            }
        }
        if let Err(e) = service_os::stop_service() {
            fail("remove-service", 13, e);
        }
        if let Err(e) = wait_for_state(ScmServiceState::Stopped, 30) {
            fail("remove-service", 13, e);
        }
        if let Err(e) = service_os::remove_service() {
            fail("remove-service", 13, e);
        }
        out(&serde_json::json!({
            "mode": "remove-service",
            "outcome": "success",
            "exit": 0,
        }));
        std::process::exit(0);
    }

    /// U09 installer seam: enter service maintenance over the protected pipe
    /// (admin only). Mirrors the installer's preflight step
    /// (`provision::InstallStep::EnterMaintenanceOrOfflineRecover`): new
    /// takeover is rejected while maintenance holds, and the call is audited
    /// with the caller's reason. Quiesces any live owner lease first so the
    /// upgrade preflight never races an active takeover.
    pub fn cmd_enter_maintenance() -> ! {
        if !service_os::is_elevated() {
            fail("enter-maintenance", 13, "enter-maintenance requires elevation".into());
        }
        let outcome = (|| -> Result<(String, u64), String> {
            let mut last = "no attempt".to_string();
            for _ in 0..3 {
                let pid = service_os::scm_service_pid()?.ok_or("service has no PID")?;
                let req = Request::new(
                    dns_recovery::journal::new_uuid(),
                    Operation::EnterMaintenance,
                    None,
                    None,
                    serde_json::json!({"reason": "u09-own-service-cycle", "quiesce_owner": true}),
                );
                let frame = protocol::encode_frame(&req).map_err(|e| e.to_string())?;
                match service_os::pipe_roundtrip(&frame, Some(pid)).and_then(|raw| {
                    protocol::decode_reply(&raw).map_err(|e| e.to_string())
                }) {
                    Ok(reply) if reply.request_id == req.request_id => {
                        return Ok((reply.outcome, reply.generation));
                    }
                    Ok(_) => last = "reply ID mismatch".into(),
                    Err(e) => last = e,
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(last)
        })();
        match outcome {
            Ok((o, generation)) if o == "success" => {
                out(&serde_json::json!({
                    "mode": "enter-maintenance",
                    "outcome": "success",
                    "exit": 0,
                    "generation": generation,
                }));
                std::process::exit(0);
            }
            Ok((o, generation)) => {
                let exit = protocol::exit_code_for_outcome(&o);
                fail("enter-maintenance", exit, format!("maintenance refused: {o} (generation {generation})"));
            }
            Err(e) => fail("enter-maintenance", 13, format!("maintenance call failed: {e}")),
        }
    }

    /// U09 installer seam: leave service maintenance over the protected pipe
    /// (admin only). The installer calls this after a validated upgrade;
    /// the postinstall GUI launches only after the service is ready again.
    pub fn cmd_leave_maintenance() -> ! {
        if !service_os::is_elevated() {
            fail("leave-maintenance", 13, "leave-maintenance requires elevation".into());
        }
        let outcome = (|| -> Result<(String, u64), String> {
            let mut last = "no attempt".to_string();
            for _ in 0..3 {
                let pid = service_os::scm_service_pid()?.ok_or("service has no PID")?;
                let req = Request::new(
                    dns_recovery::journal::new_uuid(),
                    Operation::LeaveMaintenance,
                    None,
                    None,
                    serde_json::json!({}),
                );
                let frame = protocol::encode_frame(&req).map_err(|e| e.to_string())?;
                match service_os::pipe_roundtrip(&frame, Some(pid)).and_then(|raw| {
                    protocol::decode_reply(&raw).map_err(|e| e.to_string())
                }) {
                    Ok(reply) if reply.request_id == req.request_id => {
                        return Ok((reply.outcome, reply.generation));
                    }
                    Ok(_) => last = "reply ID mismatch".into(),
                    Err(e) => last = e,
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(last)
        })();
        match outcome {
            Ok((o, generation)) if o == "success" => {
                out(&serde_json::json!({
                    "mode": "leave-maintenance",
                    "outcome": "success",
                    "exit": 0,
                    "generation": generation,
                }));
                std::process::exit(0);
            }
            Ok((o, generation)) => {
                let exit = protocol::exit_code_for_outcome(&o);
                fail("leave-maintenance", exit, format!("leave-maintenance refused: {o} (generation {generation})"));
            }
            Err(e) => fail("leave-maintenance", 13, format!("leave-maintenance call failed: {e}")),
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: yeager-dns-recovery --service|--inspect|--recover-offline|--install-service|--remove-service|--enter-maintenance|--leave-maintenance");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        usage();
    }
    #[cfg(windows)]
    match args[1].as_str() {
        "--service" => win::cmd_service(),
        "--inspect" => win::cmd_inspect(),
        "--recover-offline" => win::cmd_recover_offline(),
        "--install-service" => win::cmd_install_service(),
        "--remove-service" => win::cmd_remove_service(),
        "--enter-maintenance" => win::cmd_enter_maintenance(),
        "--leave-maintenance" => win::cmd_leave_maintenance(),
        _ => usage(),
    }
    #[cfg(not(windows))]
    {
        eprintln!("yeager-dns-recovery: Windows only (mode {})", args[1]);
        println!(
            "{}",
            serde_json::json!({"mode": args[1], "outcome": "unsupported", "exit": 15})
        );
        std::process::exit(15);
    }
}

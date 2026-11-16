//! yeager-dns-recovery: the privileged DNS recovery service binary (U05,
//! SPEC-DNS-FIX.md §8.3). U09-REV2 upgrade-cycle build marker.
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
//! - `--query-service-config` (U09-REV4 item 2): read-only dump of the
//!   complete registration (ImagePath, start type, failure actions/flag,
//!   preshutdown) via Win32 reads — the rollback capture source.
//! - `--restore-service-registration --file <capture.json>` (U09-REV4 item 2):
//!   installer rollback path; writes back the CAPTURED values, never the
//!   canonical §8.1 configuration.
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
        // U09-REV2 item 2: ABSENT vs STOPPED. `OpenServiceW` failing with
        // 1060 means ABSENT — proceed to create. The STOPPED wait applies
        // only when a record exists; any other query failure refuses.
        let had_service = match service_os::service_exists() {
            Ok(v) => v,
            Err(e) => fail("install-service", 13, format!("cannot query service record: {e}")),
        };
        // U09-REV4 item 2: capture the COMPLETE previous registration
        // (ImagePath, start type + delayed flag, failure reset/actions,
        // non-crash flag, preshutdown) via Win32 reads, so a start/Hello
        // failure after the in-place replacement writes back THOSE values �
        // never the canonical �8.1 standard configuration.
        let prev_reg: Option<service_os::ServiceRegistration> = if had_service {
            match service_os::query_service_registration() {
                Ok(r) => Some(r),
                Err(e) => fail("install-service", 13, format!("cannot capture previous registration: {e}")),
            }
        } else {
            None
        };
        // Whether the service was running at capture: only then does the
        // rollback restart it (a stopped/disabled record stays stopped).
        let was_running_at_capture: bool = matches!(
            service_os::scm_query_state(),
            Ok(dns_recovery::service::ScmServiceState::Running)
        );
        // The running image, resolved before the staged check below.
        let current_early = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => fail("install-service", 13, format!("cannot locate running image: {e}")),
        };
        // Staged check (item 2 adopt path): the installer flow runs the helper
        // from the target path itself. Computed here so backup skips the
        // already-staged file (the installer holds the true previous binary).
        let staged_early = (|| -> bool {
            let canon = |p: &std::path::Path| {
                std::fs::canonicalize(p)
                    .map(|c| c.to_string_lossy().to_lowercase())
                    .unwrap_or_else(|_| p.to_string_lossy().to_lowercase())
            };
            canon(&current_early) == canon(std::path::Path::new(&dest))
        })();
        // U09-REV B: real rollback. Back up the previous executable before
        // replacement so a start/Hello failure restores both the binary and
        // the registration (the previous claim of a backup with no code is
        // removed). A clean install (no SCM record) has no previous binary
        // even when Inno already staged the new file at the target path;
        // the staged installer flow never backs up (its previous binary is
        // the installer's own `{tmp}` backup).
        let had_previous_binary =
            had_service && !staged_early && std::path::Path::new(&dest).exists();
        let backup = format!("{dest}.prev-{}", std::process::id());
        if had_previous_binary {
            if let Err(e) = std::fs::copy(&dest, &backup) {
                fail("install-service", 13, format!("cannot back up previous binary: {e}"));
            }
        }
        // Rollback helper. `staged_in_place` marks the installer flow where
        // the running image already IS the target file (Inno copied + signature-
        // verified it before invoking the seam): the seam skips backup and copy,
        // and on failure only ensures the service is stopped — the installer's
        // own RestorePreviousState owns the exe + registration write-back and
        // the restart. Otherwise (seam invoked from elsewhere): restore the
        // previous binary AND registration when a record existed, else remove
        // the fresh registration and the copied exe.
        let rollback = |had_previous: bool,
                        backup: &str,
                        dest: &str,
                        prev_reg: &Option<service_os::ServiceRegistration>,
                        was_running: bool,
                        staged_in_place: bool| {
            let _ = service_os::stop_service();
            if staged_in_place {
                return;
            }
            if had_previous {
                let _ = std::fs::copy(backup, dest);
                let _ = std::fs::remove_file(backup);
                if let Some(prev) = prev_reg {
                    let _ = service_os::restore_service_registration(prev);
                }
                // U09-REV4 item 2: restart only when the captured state was
                // running � a stopped/disabled record stays stopped.
                if was_running {
                    let _ = service_os::start_service();
                }
            } else {
                let _ = service_os::remove_service();
                let _ = std::fs::remove_file(dest);
            }
        };
        if let Err(e) = std::fs::create_dir_all(&dest_dir) {
            if had_previous_binary {
                let _ = std::fs::remove_file(&backup);
            }
            fail("install-service", 13, format!("cannot create {dest_dir}: {e}"));
        }
        // Protected ACL on the binary directory, not only ProgramData
        // (exact DIR_SDDL: SYSTEM + Administrators, protected).
        if let Err(e) = service_os::apply_protected_binary_dir_acl(&dest_dir) {
            if had_previous_binary {
                let _ = std::fs::remove_file(&backup);
            }
            fail("install-service", 13, e);
        }
        let current = current_early;
        // Adopt path (item 2): the installer flow runs the helper from the
        // target path itself after Inno's copy + signature verification. When
        // the running image already IS the protected file, skip backup and
        // copy and register/configure/start/Hello in place — whether or not
        // a service record exists (clean install AND upgrade take this path
        // through the installer; copying a file onto itself fails).
        let staged_in_place = staged_early;
        // Upgrade replace: the running service locks the protected binary,
        // so stop and prove STOPPED before overwriting it (mirrors the
        // installer's PrepareToInstall `sc stop` + STOPPED poll; the offline
        // guard refuses anything but proven STOPPED). Applies only when a
        // record exists; ABSENT proceeds to create with no wait. In the
        // staged flow the installer already stopped the service; the seam's
        // stop is a no-op (1062 already-stopped is success) and the wait
        // returns immediately.
        if had_service {
            let _ = service_os::stop_service();
            if let Err(e) = wait_for_state(ScmServiceState::Stopped, 30) {
                if !staged_in_place {
                    let _ = std::fs::remove_file(&backup);
                }
                fail("install-service", 13, format!("cannot stop service for replacement: {e}"));
            }
        }
        if !staged_in_place {
            if let Err(e) = std::fs::copy(&current, &dest) {
                if had_previous_binary {
                    let _ = std::fs::remove_file(&backup);
                } else {
                    let _ = std::fs::remove_file(&dest);
                }
                fail("install-service", 13, format!("cannot stage protected binary: {e}"));
            }
        }
        if let Err(e) = service_os::install_service(&dest) {
            // Registration failed: restore the previous binary when one
            // existed, otherwise remove the copied exe. In the staged flow
            // the installer owns the files — leave them for its restore.
            if !staged_in_place {
                if had_previous_binary {
                    let _ = std::fs::copy(&backup, &dest);
                    let _ = std::fs::remove_file(&backup);
                } else {
                    let _ = std::fs::remove_file(&dest);
                }
            }
            fail("install-service", 13, e);
        }
        if let Err(e) = service_os::start_service() {
            rollback(had_previous_binary, &backup, &dest, &prev_reg, was_running_at_capture, staged_in_place);
            fail("install-service", 13, e);
        }
        if let Err(e) = wait_for_state(ScmServiceState::Running, 30) {
            rollback(had_previous_binary, &backup, &dest, &prev_reg, was_running_at_capture, staged_in_place);
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
                // Upgrade success: the backup is no longer needed.
                let _ = std::fs::remove_file(&backup);
                out(&serde_json::json!({
                    "mode": "install-service",
                    "outcome": "success",
                    "exit": 0,
                    "binary": dest,
                    "hello": outcome,
                    "replaced": had_service,
                }));
                std::process::exit(0);
            }
            Ok(outcome) => {
                rollback(had_previous_binary, &backup, &dest, &prev_reg, was_running_at_capture, staged_in_place);
                fail("install-service", 13, format!("hello validation returned {outcome:?}"));
            }
            Err(e) => {
                rollback(had_previous_binary, &backup, &dest, &prev_reg, was_running_at_capture, staged_in_place);
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

    /// U09-REV2 item 3 installer seam: enter service maintenance over the
    /// protected pipe (admin only). Accepts the installer's reason token
    /// (`--enter-maintenance "installer-upgrade"` /
    /// `"installer-uninstall"`); the single-token form keeps working with
    /// the service default. The recorded reason is THAT reason — no
    /// hardcoded string. Mirrors the installer's preflight step: new
    /// takeover is rejected while maintenance holds. Quiesces any live owner
    /// lease first so the upgrade preflight never races an active takeover.
    pub fn cmd_enter_maintenance(reason: &str) -> ! {
        if !service_os::is_elevated() {
            fail("enter-maintenance", 13, "enter-maintenance requires elevation".into());
        }
        let reason_owned = reason.to_string();
        let outcome = (|| -> Result<(String, u64), String> {
            let mut last = "no attempt".to_string();
            for _ in 0..3 {
                let pid = service_os::scm_service_pid()?.ok_or("service has no PID")?;
                let req = Request::new(
                    dns_recovery::journal::new_uuid(),
                    Operation::EnterMaintenance,
                    None,
                    None,
                    serde_json::json!({"reason": reason_owned, "quiesce_owner": true}),
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

    /// U09-REV2 item 7: exact restore through the helper when the GUI exe is
    /// absent. The uninstaller (`setup.iss` GUI-absent arm) calls this — not
    /// `--inspect` — so the restore actually runs. Replays the journal to an
    /// exact-original restore via the same driver as `--recover-offline`
    /// (maintenance already holds, so no new takeover can race it). Exit 0
    /// only on a verified restore; debt exits map to §8.3 like the GUI path.
    /// U09-REV4 item 2: read-only dump of the complete current registration
    /// (ImagePath, start type + delayed flag, failure reset/actions, non-crash
    /// flag, preshutdown) via Win32 reads. Read-only: no elevation required.
    /// The installer calls this before replacement and stores the stdout JSON
    /// as the rollback capture; the same JSON is the live-cycle evidence.
    pub fn cmd_query_service_config() -> ! {
        match service_os::query_service_registration() {
            Ok(reg) => {
                out(&serde_json::json!({
                    "mode": "query-service-config",
                    "outcome": "success",
                    "exit": 0,
                    "registration": reg,
                }));
                std::process::exit(0);
            }
            Err(e) => fail("query-service-config", 11, e),
        }
    }

    /// U09-REV4 item 2: installer rollback path. Reads a capture file written
    /// from `--query-service-config` stdout (accepts the wrapper object or
    /// the bare registration) and writes back the CAPTURED values via Win32 —
    /// ImagePath, start type, failure actions/flag, preshutdown — never the
    /// canonical §8.1 values. Requires elevation.
    pub fn cmd_restore_service_registration(file: &str) -> ! {
        if !service_os::is_elevated() {
            fail("restore-service-registration", 13, "restore-service-registration requires elevation".into());
        }
        let raw = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => fail("restore-service-registration", 11, format!("cannot read capture file: {e}")),
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => fail("restore-service-registration", 11, format!("capture file is not JSON: {e}")),
        };
        let reg_value = value.get("registration").unwrap_or(&value);
        let reg: service_os::ServiceRegistration = match serde_json::from_value(reg_value.clone()) {
            Ok(r) => r,
            Err(e) => fail("restore-service-registration", 11, format!("capture file has no registration: {e}")),
        };
        match service_os::apply_service_registration(&reg) {
            Ok(()) => {
                out(&serde_json::json!({
                    "mode": "restore-service-registration",
                    "outcome": "success",
                    "exit": 0,
                }));
                std::process::exit(0);
            }
            Err(e) => fail("restore-service-registration", 13, e),
        }
    }

    pub fn cmd_cleanup() -> ! {
        if !service_os::is_elevated() {
            fail("cleanup", 13, "cleanup requires elevation".into());
        }
        let dir = match service_os::program_data_dir() {
            Ok(d) => d,
            Err(e) => fail("cleanup", 11, e),
        };
        let fs = match WindowsFs::new() {
            Ok(f) => Rc::new(f),
            Err(e) => fail("cleanup", 11, format!("protected storage unavailable: {e}")),
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
            Err(e) => fail("cleanup", 11, format!("restore failed: {e}")),
        };
        let outcome = outcome_of(report.outcome);
        let exit = protocol::exit_code_for_outcome(outcome);
        out(&serde_json::json!({
            "mode": "cleanup",
            "outcome": outcome,
            "exit": exit,
            "generation": report.generation,
            "note": report.note,
            "errors": report.errors.len(),
        }));
        std::process::exit(exit);
    }
}

fn usage() -> ! {
    eprintln!("usage: yeager-dns-recovery --service|--inspect|--recover-offline|--install-service|--remove-service|--enter-maintenance [reason]|--leave-maintenance|--cleanup|--query-service-config|--restore-service-registration --file <capture.json>");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        usage();
    }
    #[cfg(windows)]
    match args[1].as_str() {
        "--service" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_service()
        }
        "--inspect" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_inspect()
        }
        "--recover-offline" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_recover_offline()
        }
        "--install-service" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_install_service()
        }
        "--remove-service" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_remove_service()
        }
        "--enter-maintenance" => {
            if args.len() == 3 {
                // Installer passes its own reason token; record THAT reason.
                let reason = args[2].clone();
                win::cmd_enter_maintenance(&reason)
            } else if args.len() == 2 {
                win::cmd_enter_maintenance("admin maintenance")
            } else {
                usage()
            }
        }
        "--leave-maintenance" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_leave_maintenance()
        }
        "--cleanup" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_cleanup()
        }
        "--query-service-config" => {
            if args.len() != 2 {
                usage();
            }
            win::cmd_query_service_config()
        }
        "--restore-service-registration" => {
            if args.len() != 4 || args[2] != "--file" {
                usage();
            }
            let file = args[3].clone();
            win::cmd_restore_service_registration(&file)
        }
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

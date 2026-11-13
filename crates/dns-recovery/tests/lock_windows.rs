//! U02 real-Windows multi-process lock/store harness (SPEC-DNS-FIX.md §3.1,
//! envelope U02 gate: "Two elevated processes in different sessions plus
//! offline helper contend; one critical section only. Abandoned mutex rescans.
//! Wrong-type/security-squatted named object fails closed.").
//!
//! Standard `cargo test` runs this (harness = false, own main). It performs NO
//! NIC operations and confines all filesystem work to a scratch directory under
//! %ProgramData%. When not elevated it prints SKIP and exits 0.
//!
//! Session topology: the orchestrator runs as SYSTEM (session 0). Participant A
//! is a SYSTEM worker whose duplicated token is retargeted into the active
//! console session (SetTokenInformation(TokenSessionId) + CreateProcessAsUserW);
//! participants B and C are SYSTEM session-0 workers (the offline helper). All
//! three are elevated and A is in a distinct session, regardless of the session
//! the test runner happens to be in.
//!
//! Modes (argv):
//!   (default)                        launcher: run the orchestrator as SYSTEM
//!   --system-orchestrate <scratch>   full evidence run (SYSTEM); writes evidence.json
//!   --child <scratch> <id> <n>       contention worker: n locked counter increments
//!   --try-once <scratch>             single short-budget acquire (exclusion probe)
//!   --hold-and-die                   acquire then exit without releasing (abandon)

#[cfg(not(windows))]
fn main() {
    println!("SKIP: lock_windows is Windows only.");
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(imp::dispatch(&args));
}

#[cfg(windows)]
mod imp {
    use dns_recovery::fs::JournalFs;
    use dns_recovery::lock::{Acquired, LockError, MachineLock, LOCK_NAME};
    use dns_recovery::security::{win::Sddl, MUTEX_ALL_ACCESS, MUTEX_SDDL};
    use dns_recovery::store::JournalStore;
    use dns_recovery::{codec, fs_windows, journal, model, WindowsFs, WindowsLock};
    use serde_json::{json, Value};
    use std::ffi::c_void;
    use std::process::Command;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, SetTokenInformation, SecurityImpersonation, TokenPrimary, TokenSessionId,
        SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateMutexExW, CreateProcessAsUserW, CreateSemaphoreW, GetCurrentProcess,
        GetCurrentProcessId, OpenProcessToken, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOW,
    };

    const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d";
    const TX: &str = "11111111-1111-4111-8111-111111111111";
    const GUID: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
    const NOW: &str = "2026-11-13T18:08:29Z";
    const ITERS: u32 = 150;
    const WEAK_MUTEX_SDDL: &str = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)";

    pub fn dispatch(args: &[String]) -> i32 {
        match args.first().map(|s| s.as_str()) {
            Some("--child") => child_main(&args[1..]),
            Some("--try-once") => try_once(&args[1..]),
            Some("--hold-and-die") => hold_and_die(),
            Some("--system-orchestrate") => orchestrate_main(&args[1]),
            _ => launcher_main(),
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn identity() -> (u32, u32) {
        let pid = unsafe { GetCurrentProcessId() };
        let mut session = 0u32;
        unsafe { ProcessIdToSessionId(pid, &mut session) };
        (pid, session)
    }

    fn sa_of(sddl: &Sddl) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sddl.ptr,
            bInheritHandle: 0,
        }
    }

    // ---- envelope fixtures (same shapes as the fake-backed suite) -----------

    fn snap(server: &str) -> model::Snapshot {
        model::Snapshot {
            schema_version: 1,
            family: model::Family::Ipv4,
            provenance: model::Provenance::Static,
            name_server_raw: Some(server.to_string()),
            ordered_servers: vec![model::CanonicalServer::parse(server).unwrap()],
            provenance_evidence: model::ProvenanceEvidence {
                registry_path: format!(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{{{GUID}}}"
                ),
                value_exists: true,
                value_type: Some(1),
                raw_value_base64: None,
                api_flags: 0,
                captured_at_utc: NOW.to_string(),
            },
            server_properties: Vec::new(),
            context: model::DnsContext::default(),
            capability: model::Capability {
                os_build: "26300.9974".to_string(),
                reader_revision: 1,
                api_version: 3,
                family_supported: true,
            },
        }
    }

    fn tx() -> journal::Transaction {
        let original = snap("192.0.2.53");
        journal::Transaction {
            id: TX.to_string(),
            created_at_utc: NOW.to_string(),
            updated_at_utc: NOW.to_string(),
            reason: journal::Reason::Takeover,
            phase: journal::Phase::Preparing,
            owner: journal::OwnerIdentity {
                owner_id: "33333333-3333-4333-8333-333333333333".to_string(),
                pid: 4242,
                creation_time_filetime: 133_000_000_000_000_000,
                user_sid: "S-1-5-18".to_string(),
                logon_luid: 999,
                session_id: 0,
                image_path: "C:\\Program Files\\Yeager\\yeager.exe".to_string(),
                image_file_id: "fileid-1".to_string(),
                image_sha256: "a".repeat(64),
            },
            epoch: 1,
            admission: journal::Admission::Open,
            desired: model::DesiredPlan {
                provider: model::Provider::Auto,
                local_requested: false,
                bound_endpoints: Vec::new(),
                readiness_generation: 0,
            },
            service_instance_id: "44444444-4444-4444-8444-444444444444".to_string(),
            registered_at_utc: NOW.to_string(),
            entries: vec![journal::Entry {
                adapter_guid: GUID.to_string(),
                family: model::Family::Ipv4,
                name_hint: "Ethernet".to_string(),
                device_instance_hint: None,
                original_if_index: Some(12),
                original_luid: 1,
                first_captured_at_utc: NOW.to_string(),
                original_fingerprint: original.fingerprint(),
                original,
                baseline_kind: journal::BaselineKind::PreTakeover,
                previous_committed: None,
                previous_fingerprint: None,
                intended: None,
                intended_fingerprint: None,
                applied_fingerprint: None,
                plan_revision: 1,
                operations: Vec::new(),
                state: journal::EntryState::Captured,
                last_observed: None,
                retry: journal::RetryState { attempts: 0, next_attempt_utc: None, last_error: None },
                verification: None,
                approved_legacy_target: None,
            }],
        }
    }

    fn genesis() -> journal::Envelope {
        let mut env = journal::Envelope {
            format: journal::JOURNAL_FORMAT.to_string(),
            version: journal::JOURNAL_VERSION,
            machine_id: MACHINE.to_string(),
            generation: 1,
            previous_digest: None,
            payload_digest: String::new(),
            payload: journal::Payload {
                journal_state: journal::JournalState::Clean,
                transaction: None,
                last_completed: None,
                maintenance: None,
                diagnostics: Vec::new(),
            },
        };
        codec::seal(&mut env);
        env
    }

    fn owned(generation: u64, prev: Option<String>) -> journal::Envelope {
        let mut env = journal::Envelope {
            format: journal::JOURNAL_FORMAT.to_string(),
            version: journal::JOURNAL_VERSION,
            machine_id: MACHINE.to_string(),
            generation,
            previous_digest: prev,
            payload_digest: String::new(),
            payload: journal::Payload {
                journal_state: journal::JournalState::Owned,
                transaction: Some(tx()),
                last_completed: None,
                maintenance: None,
                diagnostics: Vec::new(),
            },
        };
        codec::seal(&mut env);
        env
    }

    // ---- worker modes ---------------------------------------------------------

    fn child_main(args: &[String]) -> i32 {
        let scratch = &args[0];
        let id = &args[1];
        let iters: u32 = args[2].parse().expect("iters");
        let lock = match WindowsLock::new() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("child {id}: WindowsLock::new: {e}");
                return 1;
            }
        };
        let counter_path = format!("{scratch}\\counter.txt");
        let mut fresh = 0u32;
        let mut abandoned = 0u32;
        for _ in 0..iters {
            let (guard, acq) = match lock.acquire(Duration::from_secs(30)) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("child {id}: acquire: {e}");
                    return 1;
                }
            };
            match acq {
                Acquired::Fresh => fresh += 1,
                Acquired::Abandoned => abandoned += 1,
            }
            // Critical section: read-modify-write the shared counter.
            let cur: u64 = std::fs::read_to_string(&counter_path)
                .expect("read counter")
                .trim()
                .parse()
                .expect("parse counter");
            std::fs::write(&counter_path, (cur + 1).to_string()).expect("write counter");
            drop(guard);
        }
        let (pid, session_id) = identity();
        let done = json!({
            "id": id, "pid": pid, "session_id": session_id,
            "iterations": iters, "fresh": fresh, "abandoned": abandoned,
        });
        std::fs::write(format!("{scratch}\\done-{id}.json"), done.to_string()).expect("write done");
        0
    }

    fn try_once(args: &[String]) -> i32 {
        let scratch = &args[0];
        let lock = match WindowsLock::new() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("try-once: WindowsLock::new: {e}");
                return 1;
            }
        };
        let outcome = match lock.acquire(Duration::from_millis(700)) {
            Err(LockError::Timeout) => "timeout",
            Ok((_guard, _acq)) => "acquired",
            Err(e) => {
                eprintln!("try-once: {e}");
                "error"
            }
        };
        let (pid, session_id) = identity();
        let done = json!({"outcome": outcome, "pid": pid, "session_id": session_id});
        std::fs::write(format!("{scratch}\\done-tryonce.json"), done.to_string()).expect("write done");
        if outcome == "timeout" {
            0
        } else {
            2
        }
    }

    fn hold_and_die() -> i32 {
        let lock = match WindowsLock::new() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("hold-and-die: WindowsLock::new: {e}");
                return 1;
            }
        };
        let (_guard, _acq) = match lock.acquire(Duration::from_secs(30)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("hold-and-die: acquire: {e}");
                return 1;
            }
        };
        // Die without dropping the guard: the mutex becomes abandoned. The
        // orchestrator holds a keep-alive handle so the named object survives.
        std::process::exit(0);
    }

    // ---- cross-session spawn (SYSTEM orchestrator only) -----------------------

    /// Place a worker in the active console session while keeping SYSTEM
    /// elevation. We duplicate our own SYSTEM primary token and retarget the
    /// duplicate's session id (SeTcb), then CreateProcessAsUserW
    /// (SeAssignPrimaryToken). The interactive user's console token is
    /// UAC-filtered and would not be elevated, so it is deliberately not used.
    fn spawn_console_child(worker: &str, scratch: &str, id: &str) -> Result<(), String> {
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err("no active console session".to_string());
        }
        let mut tok = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut tok) } == 0
            || tok.is_null()
        {
            return Err(format!("OpenProcessToken failed: {}", unsafe { GetLastError() }));
        }
        let mut dup = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateTokenEx(
                tok,
                TOKEN_ALL_ACCESS,
                std::ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut dup,
            )
        };
        unsafe { CloseHandle(tok) };
        if ok == 0 || dup.is_null() {
            return Err(format!("DuplicateTokenEx failed: {}", unsafe { GetLastError() }));
        }
        let sid = session;
        if unsafe {
            SetTokenInformation(dup, TokenSessionId, &sid as *const u32 as *const c_void, 4)
        } == 0
        {
            unsafe { CloseHandle(dup) };
            return Err(format!(
                "SetTokenInformation(TokenSessionId={session}) failed: {}",
                unsafe { GetLastError() }
            ));
        }
        let mut cmd = wide(&format!("\"{worker}\" --child \"{scratch}\" {id} {ITERS}"));
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessAsUserW(
                dup,
                wide(worker).as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_NO_WINDOW,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        unsafe { CloseHandle(dup) };
        if ok == 0 {
            return Err(format!("CreateProcessAsUserW failed: {}", unsafe { GetLastError() }));
        }
        unsafe {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        Ok(())
    }

    // ---- orchestrator helpers -------------------------------------------------

    fn wait_done(scratch: &str, id: &str, timeout: Duration) -> Result<Value, String> {
        let path = format!("{scratch}\\done-{id}.json");
        let start = Instant::now();
        while start.elapsed() < timeout {
            if let Ok(bytes) = std::fs::read(&path) {
                return serde_json::from_slice(&bytes).map_err(|e| format!("parse done-{id}: {e}"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(format!("timed out waiting for done-{id}.json"))
    }

    // ---- orchestrator (SYSTEM) ------------------------------------------------

    fn orchestrate_main(scratch: &str) -> i32 {
        let lock = match WindowsLock::new() {
            Ok(l) => l,
            Err(e) => {
                let _ = std::fs::write(format!("{scratch}\\error.txt"), format!("WindowsLock::new: {e}"));
                return 1;
            }
        };
        match run_orchestrator(&lock, scratch) {
            Ok(report) => {
                let _ = std::fs::write(
                    format!("{scratch}\\evidence.json"),
                    serde_json::to_string_pretty(&report).unwrap(),
                );
                0
            }
            Err(e) => {
                let _ = std::fs::write(format!("{scratch}\\error.txt"), e);
                1
            }
        }
    }

    fn run_orchestrator(lock: &WindowsLock, scratch: &str) -> Result<Value, String> {
        let fs = WindowsFs::new().map_err(|e| format!("WindowsFs: {e}"))?;
        fs.ensure_directory(scratch).map_err(|e| format!("ensure scratch: {e}"))?;
        let worker = format!("{scratch}\\worker.exe");
        std::fs::write(format!("{scratch}\\counter.txt"), "0").map_err(|e| format!("seed counter: {e}"))?;
        let (orch_pid, orch_session) = identity();

        // ---- Phase 1: wrong-type / security-squatted named objects fail closed.
        let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, wide(LOCK_NAME).as_ptr()) };
        if event.is_null() {
            return Err("could not create squat event".to_string());
        }
        let event_verdict = matches!(lock.acquire(Duration::from_secs(1)), Err(LockError::WrongType));
        unsafe { CloseHandle(event) };

        let sem = unsafe { CreateSemaphoreW(std::ptr::null(), 1, 1, wide(LOCK_NAME).as_ptr()) };
        if sem.is_null() {
            return Err("could not create squat semaphore".to_string());
        }
        let sem_verdict = matches!(lock.acquire(Duration::from_secs(1)), Err(LockError::WrongType));
        unsafe { CloseHandle(sem) };

        let weak_sddl = Sddl::parse(WEAK_MUTEX_SDDL).map_err(|e| format!("weak SDDL: {}", e.0))?;
        let weak_sa = sa_of(&weak_sddl);
        let weak = unsafe { CreateMutexExW(&weak_sa, wide(LOCK_NAME).as_ptr(), 0, MUTEX_ALL_ACCESS) };
        if weak.is_null() {
            return Err("could not create weak-DACL squat mutex".to_string());
        }
        let weak_verdict = matches!(lock.acquire(Duration::from_secs(1)), Err(LockError::BadSecurity(_)));
        unsafe { CloseHandle(weak) };

        if !(event_verdict && sem_verdict && weak_verdict) {
            return Err(format!(
                "squat fail-closed violated: event={event_verdict} semaphore={sem_verdict} weak_mutex={weak_verdict}"
            ));
        }

        // ---- Phase 2: exclusion while held (cross-process).
        let (parent_guard, parent_acq) = lock.acquire(Duration::from_secs(5)).map_err(|e| format!("orchestrator acquire: {e}"))?;
        if parent_acq != Acquired::Fresh {
            return Err("orchestrator expected Fresh acquisition".to_string());
        }
        let tryonce = Command::new(&worker)
            .args(["--try-once", scratch])
            .spawn()
            .map_err(|e| format!("spawn try-once: {e}"))?;
        let tryonce_status = tryonce.wait_with_output().map_err(|e| format!("wait try-once: {e}"))?;
        let tryonce_done = wait_done(scratch, "tryonce", Duration::from_secs(10))?;
        drop(parent_guard);
        if tryonce_done["outcome"] != "timeout" || !tryonce_status.status.success() {
            return Err(format!("exclusion violated: {tryonce_done}"));
        }

        // ---- Phase 3: three participants across two sessions contend.
        // A: elevated interactive user in the active console session.
        spawn_console_child(&worker, scratch, "A")?;
        // B and C: SYSTEM session-0 workers (offline helper).
        let mut child_b = Command::new(&worker)
            .args(["--child", scratch, "B", &ITERS.to_string()])
            .spawn()
            .map_err(|e| format!("spawn child B: {e}"))?;
        let mut child_c = Command::new(&worker)
            .args(["--child", scratch, "C", &ITERS.to_string()])
            .spawn()
            .map_err(|e| format!("spawn child C: {e}"))?;
        let done_a = wait_done(scratch, "A", Duration::from_secs(120))?;
        let done_b = wait_done(scratch, "B", Duration::from_secs(120))?;
        let done_c = wait_done(scratch, "C", Duration::from_secs(120))?;
        let _ = child_b.wait();
        let _ = child_c.wait();
        let counter: u64 = std::fs::read_to_string(format!("{scratch}\\counter.txt"))
            .map_err(|e| format!("read counter: {e}"))?
            .trim()
            .parse()
            .map_err(|e| format!("parse counter: {e}"))?;
        let expected = (ITERS * 3) as u64;
        if counter != expected {
            return Err(format!("lost updates: counter={counter}, expected={expected}"));
        }
        for d in [&done_a, &done_b, &done_c] {
            let fresh = d["fresh"].as_u64().unwrap_or(0);
            let abandoned = d["abandoned"].as_u64().unwrap_or(0);
            if fresh + abandoned != ITERS as u64 {
                return Err(format!("participant {} did not complete {ITERS} acquisitions: {d}", d["id"]));
            }
        }
        let session_a = done_a["session_id"].as_u64().unwrap_or(u64::MAX);
        let session_b = done_b["session_id"].as_u64().unwrap_or(u64::MAX);
        let session_c = done_c["session_id"].as_u64().unwrap_or(u64::MAX);
        if session_a == session_b || session_b != 0 || session_c != 0 {
            return Err(format!(
                "expected two distinct sessions with B/C in session 0: A={session_a} B={session_b} C={session_c}"
            ));
        }

        // ---- Phase 4: abandoned mutex mandates a journal rescan before write.
        let journal_dir = format!("{scratch}\\journal");
        fs.ensure_directory(&journal_dir).map_err(|e| format!("ensure journal dir: {e}"))?;
        let store = JournalStore::open(WindowsFs::new().map_err(|e| format!("{e}"))?, &journal_dir)
            .map_err(|e| format!("open store: {e}"))?;
        let genesis_report = store.commit(&genesis()).map_err(|e| format!("genesis commit: {e}"))?;

        // Keep-alive handle so the named mutex survives the holder's death.
        let ka_sddl = Sddl::parse(MUTEX_SDDL).map_err(|e| format!("keep-alive SDDL: {}", e.0))?;
        let ka_sa = sa_of(&ka_sddl);
        let keepalive = unsafe { CreateMutexExW(&ka_sa, wide(LOCK_NAME).as_ptr(), 0, MUTEX_ALL_ACCESS) };
        if keepalive.is_null() {
            return Err("could not create keep-alive mutex handle".to_string());
        }
        let holder = Command::new(&worker)
            .arg("--hold-and-die")
            .spawn()
            .map_err(|e| format!("spawn hold-and-die: {e}"))?;
        let holder_status = holder.wait_with_output().map_err(|e| format!("wait hold-and-die: {e}"))?;
        if !holder_status.status.success() {
            unsafe { CloseHandle(keepalive) };
            return Err("hold-and-die child failed".to_string());
        }
        let (ab_guard, ab_acq) = lock.acquire(Duration::from_secs(5)).map_err(|e| format!("abandoned acquire: {e}"))?;
        let observed_abandoned = ab_acq == Acquired::Abandoned;
        if !observed_abandoned {
            unsafe { CloseHandle(keepalive) };
            return Err(format!("expected WAIT_ABANDONED, got {ab_acq:?}"));
        }
        // Mandatory rescan before any write, then a durable commit.
        let rescanned = store.reconcile().map_err(|e| format!("rescan: {e}"))?;
        let rescan_generation = rescanned.current.as_ref().map(|c| c.env.generation).unwrap_or(0);
        if rescan_generation != 1 {
            unsafe { CloseHandle(keepalive) };
            return Err(format!("rescan found generation {rescan_generation}, expected 1"));
        }
        let commit_report = store
            .commit(&owned(2, Some(genesis_report.digest.clone())))
            .map_err(|e| format!("post-rescan commit: {e}"))?;
        drop(ab_guard);
        let (re_guard, re_acq) = lock.acquire(Duration::from_secs(5)).map_err(|e| format!("re-acquire: {e}"))?;
        let reacquire_fresh = re_acq == Acquired::Fresh;
        drop(re_guard);
        unsafe { CloseHandle(keepalive) };
        if !reacquire_fresh {
            return Err("expected Fresh after abandoned recovery".to_string());
        }

        let report = json!({
            "harness": "lock_windows",
            "platform": "windows",
            "elevated": true,
            "orchestrator": {"pid": orch_pid, "session_id": orch_session, "identity": "SYSTEM"},
            "scratch": scratch,
            "lock_name": LOCK_NAME,
            "squat_fail_closed": {
                "event_wrong_type": event_verdict,
                "semaphore_wrong_type": sem_verdict,
                "weak_dacl_mutex_bad_security": weak_verdict,
            },
            "exclusion_while_held": {"orchestrator": "fresh", "other_process": tryonce_done["outcome"]},
            "contention": {
                "participants": [done_a, done_b, done_c],
                "counter": counter,
                "expected": expected,
                "no_lost_updates": counter == expected,
                "distinct_sessions": [session_a, session_b, session_c],
            },
            "abandoned_mutex": {
                "observed_abandoned": observed_abandoned,
                "rescan_generation": rescan_generation,
                "committed_generation": commit_report.generation,
                "reacquire_fresh": reacquire_fresh,
            },
        });
        Ok(report)
    }

    // ---- launcher (the cargo-test process; elevated, any session) -------------

    fn launcher_main() -> i32 {
        if WindowsLock::new().is_err() {
            println!("SKIP: lock_windows requires elevation.");
            return 0;
        }
        let fs = match WindowsFs::new() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR: WindowsFs: {e}");
                return 1;
            }
        };
        let scratch = match fs_windows::program_data_dir() {
            Ok(pd) => format!("{pd}\\Yeager-u02-lock-{}", journal::new_uuid()),
            Err(e) => {
                eprintln!("ERROR: program_data_dir: {e}");
                return 1;
            }
        };
        let result = launcher_run(&fs, &scratch);
        let _ = std::fs::remove_dir_all(&scratch);
        match result {
            Ok(report) => {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                eprintln!("PASS");
                0
            }
            Err(e) => {
                eprintln!("ERROR: {e}");
                1
            }
        }
    }

    fn launcher_run(fs: &WindowsFs, scratch: &str) -> Result<Value, String> {
        fs.ensure_directory(scratch).map_err(|e| format!("ensure scratch: {e}"))?;
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let worker = format!("{scratch}\\worker.exe");
        std::fs::copy(&exe, &worker).map_err(|e| format!("copy worker: {e}"))?;

        let task = format!("YeagerU02Lock{}", &journal::new_uuid()[..8]);
        let tr = format!("\"{worker}\" --system-orchestrate \"{scratch}\"");
        let create = Command::new("schtasks")
            .args(["/create", "/tn", &task, "/tr", &tr, "/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/f"])
            .output()
            .map_err(|e| format!("schtasks create: {e}"))?;
        if !create.status.success() {
            return Err(format!("schtasks create failed: {}", String::from_utf8_lossy(&create.stderr)));
        }
        let run = Command::new("schtasks")
            .args(["/run", "/tn", &task])
            .output()
            .map_err(|e| format!("schtasks run: {e}"))?;
        if !run.status.success() {
            let _ = Command::new("schtasks").args(["/delete", "/tn", &task, "/f"]).output();
            return Err(format!("schtasks run failed: {}", String::from_utf8_lossy(&run.stderr)));
        }

        // Poll for the orchestrator's evidence or error file.
        let evidence_path = format!("{scratch}\\evidence.json");
        let error_path = format!("{scratch}\\error.txt");
        let start = Instant::now();
        let outcome = loop {
            if let Ok(bytes) = std::fs::read(&evidence_path) {
                break serde_json::from_slice::<Value>(&bytes).map_err(|e| format!("parse evidence: {e}"));
            }
            if let Ok(bytes) = std::fs::read(&error_path) {
                break Err(format!("orchestrator: {}", String::from_utf8_lossy(&bytes)));
            }
            if start.elapsed() > Duration::from_secs(180) {
                break Err("timed out waiting for orchestrator evidence".to_string());
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        let _ = Command::new("schtasks").args(["/delete", "/tn", &task, "/f"]).output();
        outcome
    }
}
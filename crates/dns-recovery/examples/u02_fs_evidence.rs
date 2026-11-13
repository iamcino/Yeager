//! U02 real-Windows filesystem evidence harness (SPEC-DNS-FIX.md §3.3,
//! envelope U02 gate: "Measure real Windows volume-flush availability/latency
//! and verify replacement ACL").
//!
//! Development-only: built solely with `--features dev-experiment`. Requires
//! elevation. All filesystem work is confined to a scratch directory under
//! %TEMP%; no NIC operations, no production paths. Runs 20 full durable
//! replacement pipelines through WindowsFs + JournalStore, times every
//! pipeline phase, probes raw volume-flush availability/latency, and verifies
//! the exact protected ACL on the directory, every stage, every backup and
//! every replaced primary. Prints a human summary plus one JSON object
//! (optionally also written to `--json-out <path>`).

#[cfg(not(windows))]
fn main() {
    eprintln!("u02_fs_evidence: Windows only.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    match imp::run() {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            if let Some(path) = imp::json_out_path() {
                if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()) {
                    eprintln!("ERROR: cannot write {path}: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
mod imp {
    use dns_recovery::fs::{FsError, JournalFs};
    use dns_recovery::security::{validate_journal_security, ObjectKind, SecurityInfo};
    use dns_recovery::store::JournalStore;
    use dns_recovery::{codec, journal, model, WindowsFs};
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, GetVolumePathNameW, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d";
    const TX: &str = "11111111-1111-4111-8111-111111111111";
    const GUID: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
    const NOW: &str = "2026-11-13T18:08:29Z";
    const COMMITS: u64 = 20;
    const VOLUME_FLUSH_ITERATIONS: usize = 20;

    pub fn json_out_path() -> Option<String> {
        let args: Vec<String> = std::env::args().collect();
        args.iter().position(|a| a == "--json-out").and_then(|i| args.get(i + 1)).cloned()
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

    fn envelope(generation: u64, prev: Option<String>, clean: bool) -> journal::Envelope {
        let mut env = journal::Envelope {
            format: journal::JOURNAL_FORMAT.to_string(),
            version: journal::JOURNAL_VERSION,
            machine_id: MACHINE.to_string(),
            generation,
            previous_digest: prev,
            payload_digest: String::new(),
            payload: journal::Payload {
                journal_state: if clean { journal::JournalState::Clean } else { journal::JournalState::Owned },
                transaction: if clean { None } else { Some(tx()) },
                last_completed: if clean {
                    Some(journal::Tombstone {
                        transaction_id: TX.to_string(),
                        verified_at_utc: NOW.to_string(),
                        completed_generation: generation - 1,
                    })
                } else {
                    None
                },
                maintenance: None,
                diagnostics: Vec::new(),
            },
        };
        codec::seal(&mut env);
        env
    }

    // ---- timing decorator ----------------------------------------------------

    struct AclCheck {
        object: String,
        kind: &'static str,
        ok: bool,
        detail: String,
    }

    /// Delegates to the real WindowsFs, recording per-phase latency and
    /// verifying the protected ACL at every security-relevant step.
    struct TimedFs {
        inner: WindowsFs,
        samples: RefCell<Vec<(&'static str, u64)>>,
        acl: RefCell<Vec<AclCheck>>,
    }

    fn format_security(sec: &SecurityInfo) -> String {
        let aces: Vec<String> = sec
            .aces
            .iter()
            .map(|a| format!("{}:{:#x}/{}", a.sid, a.mask, a.inherit_flags))
            .collect();
        format!(
            "owner={} group={} protected={} aces=[{}]",
            sec.owner,
            sec.group,
            sec.protected_dacl,
            aces.join(",")
        )
    }

    impl TimedFs {
        fn timed<T>(
            &self,
            phase: &'static str,
            f: impl FnOnce() -> Result<T, FsError>,
        ) -> Result<T, FsError> {
            let t = Instant::now();
            let r = f();
            self.samples.borrow_mut().push((phase, t.elapsed().as_nanos() as u64));
            r
        }

        fn check_acl(&self, path: &str, kind: ObjectKind, label: &'static str) {
            let (ok, detail) = match self.inner.file_security(path) {
                Ok(sec) => match validate_journal_security(&sec, kind) {
                    Ok(()) => (true, format_security(&sec)),
                    Err(e) => (false, e.0),
                },
                Err(e) => (false, format!("{e}")),
            };
            self.acl.borrow_mut().push(AclCheck {
                object: path.to_string(),
                kind: label,
                ok,
                detail,
            });
        }

        fn check_dir_acl(&self, dir: &str) {
            let (ok, detail) = match self.inner.directory_security(dir) {
                Ok(sec) => match validate_journal_security(&sec, ObjectKind::Directory) {
                    Ok(()) => (true, format_security(&sec)),
                    Err(e) => (false, e.0),
                },
                Err(e) => (false, format!("{e}")),
            };
            self.acl.borrow_mut().push(AclCheck {
                object: dir.to_string(),
                kind: "directory",
                ok,
                detail,
            });
        }
    }

    impl JournalFs for TimedFs {
        fn ensure_directory(&self, dir: &str) -> Result<(), FsError> {
            self.timed("ensure_directory", || self.inner.ensure_directory(dir))
        }
        fn directory_security(&self, dir: &str) -> Result<SecurityInfo, FsError> {
            self.timed("directory_security", || self.inner.directory_security(dir))
        }
        fn storage_kind(&self, dir: &str) -> Result<dns_recovery::fs::StorageKind, FsError> {
            self.timed("storage_kind", || self.inner.storage_kind(dir))
        }
        fn list_candidates(&self, dir: &str) -> Result<Vec<String>, FsError> {
            self.timed("list_candidates", || self.inner.list_candidates(dir))
        }
        fn create_new(&self, path: &str) -> Result<u64, FsError> {
            let r = self.timed("create_new", || self.inner.create_new(path));
            if r.is_ok() {
                self.check_acl(path, ObjectKind::File, "stage");
            }
            r
        }
        fn write_all(&self, h: u64, data: &[u8]) -> Result<(), FsError> {
            self.timed("write_all", || self.inner.write_all(h, data))
        }
        fn flush_file(&self, h: u64) -> Result<(), FsError> {
            self.timed("flush_file", || self.inner.flush_file(h))
        }
        fn close(&self, h: u64) -> Result<(), FsError> {
            self.timed("close", || self.inner.close(h))
        }
        fn read_file(&self, path: &str) -> Result<Vec<u8>, FsError> {
            self.timed("read_file", || self.inner.read_file(path))
        }
        fn file_security(&self, path: &str) -> Result<SecurityInfo, FsError> {
            self.timed("file_security", || self.inner.file_security(path))
        }
        fn replace(&self, primary: &str, stage: &str, backup: &str) -> Result<(), FsError> {
            let r = self.timed("replace", || self.inner.replace(primary, stage, backup));
            if r.is_ok() {
                self.check_acl(backup, ObjectKind::File, "backup");
            }
            r
        }
        fn move_write_through(&self, from: &str, to: &str) -> Result<(), FsError> {
            self.timed("move_write_through", || self.inner.move_write_through(from, to))
        }
        fn delete(&self, path: &str) -> Result<(), FsError> {
            self.timed("delete", || self.inner.delete(path))
        }
        fn flush_volume(&self, path: &str) -> Result<(), FsError> {
            self.timed("flush_volume", || self.inner.flush_volume(path))
        }
        fn flush_file_at(&self, path: &str) -> Result<(), FsError> {
            self.timed("flush_file_at", || self.inner.flush_file_at(path))
        }
        fn read_stage_back(&self, path: &str) -> Result<Vec<u8>, FsError> {
            self.timed("read_stage_back", || self.inner.read_stage_back(path))
        }
        fn reopen_primary(&self, path: &str) -> Result<Vec<u8>, FsError> {
            self.timed("reopen_primary", || self.inner.reopen_primary(path))
        }
        fn flush_volume_post_cleanup(&self, path: &str) -> Result<(), FsError> {
            self.timed("flush_volume_post_cleanup", || self.inner.flush_volume_post_cleanup(path))
        }
    }

    // ---- statistics -----------------------------------------------------------

    fn stats_ns(samples: &[u64]) -> Value {
        let mut s = samples.to_vec();
        s.sort_unstable();
        let n = s.len();
        json!({
            "count": n,
            "min_us": s[0] / 1000,
            "median_us": s[n / 2] / 1000,
            "p95_us": s[(n * 95 / 100).min(n - 1)] / 1000,
            "max_us": s[n - 1] / 1000,
        })
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Raw volume-flush availability/latency probe on the volume holding the
    /// scratch directory (the same device path the store flushes).
    fn volume_probe(dir: &str, iterations: usize) -> Result<Value, String> {
        let w = wide(dir);
        let mut buf = vec![0u16; 1024];
        if unsafe { GetVolumePathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } == 0 {
            return Err(format!("GetVolumePathNameW failed: {}", unsafe { GetLastError() }));
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let root = String::from_utf16_lossy(&buf[..len]);
        let device = format!("\\\\.\\{}", root.trim_end_matches('\\'));
        let h = unsafe {
            CreateFileW(
                wide(&device).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Ok(json!({
                "device": device, "available": false,
                "open_error": unsafe { GetLastError() },
            }));
        }
        let mut lat = Vec::new();
        let mut errors = 0u32;
        let mut last_error = 0u32;
        for _ in 0..iterations {
            let t = Instant::now();
            let ok = unsafe { FlushFileBuffers(h) };
            lat.push(t.elapsed().as_nanos() as u64);
            if ok == 0 {
                errors += 1;
                last_error = unsafe { GetLastError() };
            }
        }
        unsafe { CloseHandle(h) };
        Ok(json!({
            "device": device,
            "available": errors == 0,
            "iterations": iterations,
            "errors": errors,
            "last_error": last_error,
            "latency_us": stats_ns(&lat),
        }))
    }

    // ---- main -------------------------------------------------------------------

    pub fn run() -> Result<Value, String> {
        let inner = WindowsFs::new()
            .map_err(|e| format!("elevation required (SeRestore/SeBackup/SeTakeOwnership/SeSecurity): {e}"))?;
        let scratch = std::env::temp_dir()
            .join(format!("yeager-u02-evidence-{}", journal::new_uuid()))
            .to_string_lossy()
            .to_string();
        let result = run_inner(inner, &scratch);
        // Best-effort scratch cleanup on every path.
        let _ = std::fs::remove_dir_all(&scratch);
        result
    }

    fn run_inner(inner: WindowsFs, scratch: &str) -> Result<Value, String> {
        let fs = TimedFs {
            inner,
            samples: RefCell::new(Vec::new()),
            acl: RefCell::new(Vec::new()),
        };
        fs.inner.ensure_directory(scratch).map_err(|e| format!("ensure scratch dir: {e}"))?;
        fs.check_dir_acl(scratch);

        let volume = volume_probe(scratch, VOLUME_FLUSH_ITERATIONS)?;

        let store = JournalStore::open(fs, scratch).map_err(|e| format!("open store: {e}"))?;
        let primary = store.primary_path();

        let mut prev: Option<String> = None;
        let mut commit_wall_ns = Vec::new();
        let mut tombstone_env = None;
        for generation in 1..=COMMITS {
            let clean = generation == COMMITS;
            let env = envelope(generation, prev.clone(), clean);
            let t = Instant::now();
            let report = store.commit(&env).map_err(|e| format!("commit gen {generation}: {e}"))?;
            commit_wall_ns.push(t.elapsed().as_nanos() as u64);
            // Independent readback: the durable primary must decode to exactly
            // the generation we just committed, with the exact protected ACL.
            let bytes = store.fs().inner.read_file(&primary).map_err(|e| format!("readback: {e}"))?;
            let durable = codec::decode(&bytes).map_err(|e| format!("readback decode: {e}"))?;
            if durable.generation != generation {
                return Err(format!("readback generation {} != {generation}", durable.generation));
            }
            store.fs().check_acl(&primary, ObjectKind::File, "primary");
            prev = Some(report.digest);
            if clean {
                tombstone_env = Some(env);
            }
        }
        let tombstone_env = tombstone_env.unwrap();

        let cleanup = store
            .cleanup_obsolete(&tombstone_env)
            .map_err(|e| format!("cleanup: {e}"))?;
        let reconciled = store.reconcile().map_err(|e| format!("final reconcile: {e}"))?;
        let current = reconciled.current.ok_or("no current after cleanup")?;
        if !current.env.is_clean_tombstone() || current.env.generation != COMMITS {
            return Err("final state is not the clean tombstone".to_string());
        }
        let remaining = store.fs().inner.list_candidates(scratch).map_err(|e| format!("{e}"))?;
        if remaining != vec![primary.clone()] {
            return Err(format!("unexpected candidates after cleanup: {remaining:?}"));
        }

        // ---- aggregate -------------------------------------------------------
        let samples = store.fs().samples.borrow();
        let mut by_phase: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
        for (phase, ns) in samples.iter() {
            by_phase.entry(phase).or_default().push(*ns);
        }
        let phases: serde_json::Map<String, Value> = by_phase
            .iter()
            .map(|(p, s)| (p.to_string(), stats_ns(s)))
            .collect();
        let count_of = |p: &str| by_phase.get(p).map(|v| v.len()).unwrap_or(0);

        let acl = store.fs().acl.borrow();
        let acl_failures: Vec<&AclCheck> = acl.iter().filter(|c| !c.ok).collect();
        let acl_by_kind = |kind: &str| {
            let subset: Vec<&AclCheck> = acl.iter().filter(|c| c.kind == kind).collect();
            json!({
                "count": subset.len(),
                "all_ok": subset.iter().all(|c| c.ok),
                "example": subset.first().map(|c| c.detail.clone()).unwrap_or_default(),
            })
        };

        let report = json!({
            "harness": "u02_fs_evidence",
            "platform": "windows",
            "elevated": true,
            "scratch": scratch,
            "volume_flush_probe": volume,
            "commits": COMMITS,
            "first_primary_mechanism": "MoveFileExW(MOVEFILE_WRITE_THROUGH)",
            "subsequent_mechanism": "ReplaceFileW(flags=0)",
            "move_count": count_of("move_write_through"),
            "replace_count": count_of("replace"),
            "commit_wall_us": stats_ns(&commit_wall_ns),
            "pipeline_volume_flush_us": by_phase.get("flush_volume").map(|s| stats_ns(s)),
            "phases_us": phases,
            "acl": {
                "total": acl.len(),
                "all_ok": acl_failures.is_empty(),
                "failures": acl_failures.iter().map(|c| json!({"object": c.object, "kind": c.kind, "detail": c.detail})).collect::<Vec<_>>(),
                "directory": acl_by_kind("directory"),
                "stage": acl_by_kind("stage"),
                "backup": acl_by_kind("backup"),
                "primary": acl_by_kind("primary"),
            },
            "cleanup": {"deleted": cleanup.deleted.len(), "retained": cleanup.retained},
            "final_generation": COMMITS,
            "final_state": "clean_tombstone",
        });

        // Human summary on stderr so stdout stays pure JSON.
        eprintln!("U02 filesystem evidence (real Windows, elevated)");
        eprintln!("scratch: {scratch}");
        eprintln!("volume flush probe: {volume}");
        eprintln!(
            "commits: {COMMITS} (moves={}, replaces={}), cleanup deleted {} candidates",
            count_of("move_write_through"),
            count_of("replace"),
            cleanup.deleted.len()
        );
        eprintln!(
            "ACL checks: {} total, all_ok={}",
            acl.len(),
            acl_failures.is_empty()
        );
        for kind in ["directory", "stage", "backup", "primary"] {
            eprintln!("  {kind}: {}", acl_by_kind(kind));
        }
        eprintln!("commit wall: {}", stats_ns(&commit_wall_ns));
        for (p, s) in &by_phase {
            eprintln!("  {p}: {}", stats_ns(s));
        }
        if !acl_failures.is_empty() {
            return Err(format!("{} ACL checks failed", acl_failures.len()));
        }
        eprintln!("PASS");
        Ok(report)
    }
}
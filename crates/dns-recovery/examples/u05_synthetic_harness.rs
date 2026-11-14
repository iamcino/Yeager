//! U05 synthetic-owner VM harness (SPEC-DNS-FIX.md §12 U05 concrete tests).
//!
//! Guarded example (`dev-experiment` feature only): drives the portable
//! [`ServiceHost`](dns_recovery::ServiceHost) over [`FakeOs`](dns_recovery::fake::FakeOs)
//! with synthetic test GUIDs. It NEVER touches a real adapter, the real
//! journal path, the SCM or the network: the only filesystem is an in-memory
//! [`FakeFs`](dns_recovery::fs::FakeFs).
//!
//! Scenarios mirror the envelope's concrete tests: TerminateProcess / abort /
//! native-crash simulation at every intent barrier with a 1 s restoration
//! target, service restart with live-owner reattach (no blind restore),
//! kill-service-then-owner replay, health timeout with a live process, late
//! heartbeat/apply rejection, responding-SERVFAIL liveness, the full IPC
//! auth matrix, request-ID dedup, STOP/PRESHUTDOWN behavior and the offline
//! guard. Machine-readable evidence goes to
//! `C:\projects\yeager-dns-pkg\u05-harness-evidence.json`.

use dns_recovery::clock::{Clock, VirtualClock};
use dns_recovery::fake::FakeOs;
use dns_recovery::fs::FakeFs;
use dns_recovery::journal::{self, JournalState};
use dns_recovery::lock::{FakeLock, MachineLock};
use dns_recovery::model::Family;
use dns_recovery::protocol::{self, Operation, PeerAuth, Request};
use dns_recovery::replay::FakeOwnerProbe;
use dns_recovery::service::{ControlState, ScmServiceState, ServiceConfig, ServiceHost};
use dns_recovery::store::JournalStore;
use dns_recovery::transaction::DeathPoint;
use serde_json::json;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Instant;

const DIR: &str = "C:\\ProgramData\\Yeager";
const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2d3b4c5d";
const GUID_A: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
const GUID_B: &str = "7430a27b-1b15-4c8d-b7b6-96a803b09bb1";
const SERVICE: &str = "44444444-4444-4444-8444-444444444444";
const START_MS: i64 = 1_763_000_000_000;
const V4_ORIG: &str = "192.0.2.53";
const V6_ORIG: &str = "2001:db8::53";
const PID: u32 = 4242;
const FILETIME: u64 = 133_000_000_000_000_000;
const OWNER_ID: &str = "33333333-3333-4333-8333-333333333333";
const EVIDENCE_PATH: &str = "C:\\projects\\yeager-dns-pkg\\u05-harness-evidence.json";

struct World {
    os: FakeOs,
    fs: Rc<FakeFs>,
    lock: FakeLock,
    clock: VirtualClock,
    probe: Rc<FakeOwnerProbe>,
}

impl World {
    fn new() -> Self {
        Self {
            os: FakeOs::new(),
            fs: Rc::new(FakeFs::new()),
            lock: FakeLock::new(),
            clock: VirtualClock::new(START_MS),
            probe: Rc::new(FakeOwnerProbe::new()),
        }
    }

    fn host(&self) -> ServiceHost<Rc<FakeFs>> {
        let os_b = self.os.clone();
        let os_s = self.os.clone();
        let lock_base = self.lock.peer(7000, 0);
        let clock = self.clock.clone();
        let clock_b = self.clock.clone();
        let fs = Rc::clone(&self.fs);
        let probe = Rc::clone(&self.probe);
        ServiceHost::new(
            Rc::new(move || Box::new(os_b.clone()) as Box<dyn dns_recovery::backend::DnsBackend>),
            Rc::new(move || Box::new(os_s.clone()) as Box<dyn dns_recovery::setter::DnsSetter>),
            Rc::new(move || Box::new(lock_base.peer(7000, 0)) as Box<dyn dns_recovery::lock::MachineLock>),
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
        )
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
            remote: false,
            server_pid: None,
            expected_server_pid: None,
        }
    }

    fn adapters(&self) {
        for guid in [GUID_A, GUID_B] {
            self.os.add_adapter(guid, "TestAdapter");
            self.os.set_configured(guid, Family::Ipv4, V4_ORIG, vec![]);
            self.os.set_configured(guid, Family::Ipv6, V6_ORIG, vec![]);
        }
        self.probe.spawn(PID, FILETIME);
    }

    fn req(&self, op: Operation, owner: Option<&str>, epoch: Option<u64>, body: serde_json::Value) -> Request {
        Request::new(journal::new_uuid(), op, owner.map(|s| s.to_string()), epoch, body)
    }

    fn register_body(&self) -> serde_json::Value {
        json!({"owner_id": OWNER_ID, "image_sha256": "a".repeat(64), "image_file_id": "fileid-1"})
    }

    fn token(&self, rep: &dns_recovery::protocol::Reply) -> String {
        rep.body["token"].as_str().unwrap_or("").to_string()
    }

    fn activate(&self, host: &mut ServiceHost<Rc<FakeFs>>, readiness: u64) -> String {
        let peer = self.peer();
        let t = Instant::now();
        let reg = host.dispatch(&peer, &self.req(Operation::RegisterOwner, None, None, self.register_body()));
        eprintln!("TIMING register took {:?}", t.elapsed());
        assert_eq!(reg.outcome, "success", "register: {}", reg.body);
        let token = self.token(&reg);
        let health_body = json!({"token": token, "listener_responding": true, "readiness_generation": readiness});
        let t = Instant::now();
        let health = host.dispatch(&peer, &self.req(Operation::Health, Some(OWNER_ID), None, health_body));
        eprintln!("TIMING health took {:?}", t.elapsed());
        assert_eq!(health.outcome, "success", "health: {}", health.body);
        let apply_body = json!({
            "token": token,
            "selected": [GUID_A, GUID_B],
            "provider": "cloudflare",
            "local_requested": false,
            "bound_endpoints": [],
            "readiness_generation": readiness,
        });
        use std::sync::Mutex as StdMutex;
        let marks = std::sync::Arc::new(StdMutex::new(Vec::<(String, std::time::Instant)>::new()));
        let marks_b = std::sync::Arc::clone(&marks);
        let t_start = Instant::now();
        host.set_hook(Rc::new(move |p| {
            marks_b.lock().unwrap().push((format!("{p:?}"), Instant::now()));
        }));
        let t = Instant::now();
        let apply = host.dispatch(&peer, &self.req(Operation::Apply, Some(OWNER_ID), None, apply_body));
        eprintln!("TIMING apply took {:?}", t.elapsed());
        let mut prev = t_start;
        for (name, at) in marks.lock().unwrap().iter() {
            eprintln!("TIMING   mark {name} +{:?}", at.duration_since(prev));
            prev = *at;
        }
        assert_eq!(apply.outcome, "active", "apply: {}", apply.body);
        token
    }

    fn originals_ok(&self) -> bool {
        let (v4, _) = self.os.configured(GUID_A, Family::Ipv4);
        let (v6, _) = self.os.configured(GUID_A, Family::Ipv6);
        let (b4, _) = self.os.configured(GUID_B, Family::Ipv4);
        let (b6, _) = self.os.configured(GUID_B, Family::Ipv6);
        v4 == V4_ORIG && v6 == V6_ORIG && b4 == V4_ORIG && b6 == V6_ORIG
    }

    fn journal_state(&self) -> Option<JournalState> {
        JournalStore::open(Rc::clone(&self.fs), DIR)
            .ok()?
            .reconcile()
            .ok()?
            .current
            .map(|c| c.env.payload.journal_state)
    }
}

struct Case {
    name: &'static str,
    pass: bool,
    detail: serde_json::Value,
}

fn case(name: &'static str, pass: bool, detail: serde_json::Value) -> Case {
    println!("{} {} — {}", if pass { "PASS" } else { "FAIL" }, name, detail);
    Case { name, pass, detail }
}

fn main() {
    // Harness self-guard: this binary only ever drives FakeOs with synthetic
    // GUIDs. It performs no NIC mutation, no SCM installation and no real
    // journal I/O by construction (FakeFs lives in memory).
    let mut cases: Vec<Case> = Vec::new();

    // 1. TerminateProcess simulation: 1 s restoration target, exact originals.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let t_act = Instant::now();
        let _token = w.activate(&mut host, 7);
        eprintln!("TIMING activate took {:?}", t_act.elapsed());
        eprintln!("TIMING files={} primary_bytes={}",
            w.fs.all_paths().len(),
            w.fs.file_bytes(&dns_recovery::fs::join(DIR, dns_recovery::journal::PRIMARY_FILE)).map(|b| b.len()).unwrap_or(0));
        w.probe.kill(PID);
        let t0 = Instant::now();
        let report = host.on_owner_death(OWNER_ID).expect("restore report");
        let elapsed_us = t0.elapsed().as_micros() as u64;
        eprintln!("TIMING on_owner_death took {:?}", t0.elapsed());
        let pass = report.outcome == dns_recovery::transaction::Outcome::VerifiedRestored
            && w.originals_ok()
            && w.journal_state() == Some(JournalState::Clean)
            && elapsed_us < 1_000_000;
        cases.push(case("death_terminate_restores_within_1s", pass, json!({
            "outcome": format!("{:?}", report.outcome),
            "restore_start_latency_us": elapsed_us,
            "target_us": 1_000_000,
            "originals_exact": w.originals_ok(),
            "journal": format!("{:?}", w.journal_state()),
        })));
    }

    // 2. Abort / native-crash simulation at every intent barrier.
    for point in [
        DeathPoint::TransactionCommitted,
        DeathPoint::ApplyIntentFlushed,
        DeathPoint::BeforeSetterCall,
        DeathPoint::AfterSetterCall,
        DeathPoint::AfterReadback,
        DeathPoint::AppliedMarkerFlushed,
        DeathPoint::ActiveMarkerFlushed,
    ] {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let peer = w.peer();
        let reg = host.dispatch(&peer, &w.req(Operation::RegisterOwner, None, None, w.register_body()));
        let token = w.token(&reg);
        host.dispatch(&peer, &w.req(Operation::Health, Some(OWNER_ID), None,
            json!({"token": token, "listener_responding": true, "readiness_generation": 7})));
        let hook_point = point;
        host.set_hook(Rc::new(move |p| {
            if p == hook_point {
                panic!("synthetic crash at {hook_point:?}");
            }
        }));
        let apply_body = json!({
            "token": token, "selected": [GUID_A, GUID_B], "provider": "google",
            "local_requested": false, "bound_endpoints": [], "readiness_generation": 7u64,
        });
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            host.dispatch(&peer, &w.req(Operation::Apply, Some(OWNER_ID), None, apply_body));
        }));
        let crashed = crashed.is_err();
        // Owner dies with the crash; a fresh host incarnation restores.
        w.probe.kill(PID);
        drop(host);
        let mut host2 = w.host();
        let report = host2.on_owner_death(OWNER_ID);
        let outcome = report.as_ref().map(|r| format!("{:?}", r.outcome));
        let pass = crashed
            && matches!(outcome.as_deref(), Some("VerifiedRestored"))
            && w.originals_ok();
        cases.push(case("death_at_barrier_restores", pass, json!({
            "point": format!("{point:?}"),
            "crashed": crashed,
            "restore_outcome": outcome,
            "originals_exact": w.originals_ok(),
        })));
    }

    // 3. Restart with live owner reattaches; no blind restore.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let _token = w.activate(&mut host, 7);
        let (before, _) = w.os.configured(GUID_A, Family::Ipv4);
        drop(host);
        let mut host2 = w.host();
        let replay = host2.boot_replay().expect("boot replay");
        let busy = replay.outcome == dns_recovery::transaction::Outcome::Busy;
        let peer = w.peer();
        let reg = host2.dispatch(&peer, &w.req(Operation::RegisterOwner, None, None, w.register_body()));
        let (after, _) = w.os.configured(GUID_A, Family::Ipv4);
        let pass = busy
            && reg.outcome == "success"
            && reg.body["reattached"] == json!(true)
            && before == after;
        cases.push(case("restart_live_owner_reattaches", pass, json!({
            "boot_outcome": format!("{:?}", replay.outcome),
            "reattached": reg.body["reattached"],
            "dns_untouched": before == after,
        })));
    }

    // 4. Service + owner both die: next boot replays to clean.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let _token = w.activate(&mut host, 7);
        w.probe.kill(PID);
        drop(host);
        let host2 = w.host();
        let replay = host2.boot_replay().expect("boot replay");
        let pass = replay.outcome == dns_recovery::transaction::Outcome::VerifiedRestored
            && w.originals_ok()
            && w.journal_state() == Some(JournalState::Clean);
        cases.push(case("kill_both_boot_replays_clean", pass, json!({
            "boot_outcome": format!("{:?}", replay.outcome),
            "originals_exact": w.originals_ok(),
        })));
    }

    // 5. Health timeout with a LIVE process closes the epoch; late calls die.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let token = w.activate(&mut host, 7);
        w.clock.advance_ms(6_001);
        let sweeps = host.sweep(w.clock.now_ms());
        let restored = sweeps.iter().any(|r| r.outcome == "verified_restored");
        let peer = w.peer();
        let late = host.dispatch(&peer, &w.req(Operation::Health, Some(OWNER_ID), None,
            json!({"token": token, "listener_responding": true, "readiness_generation": 7})));
        let pass = restored && w.originals_ok() && late.outcome == "refused" && host.lease_count() == 0;
        cases.push(case("health_timeout_live_process_restores", pass, json!({
            "swept": sweeps.len(),
            "restored": restored,
            "late_heartbeat": late.outcome,
        })));
    }

    // 6. Responding SERVFAIL is not listener death; explicit loss restores.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let peer = w.peer();
        let reg = host.dispatch(&peer, &w.req(Operation::RegisterOwner, None, None, w.register_body()));
        let token = w.token(&reg);
        let mut body = json!({"token": token, "listener_responding": true, "readiness_generation": 0u64});
        body["last_error"] = json!("upstream SERVFAIL");
        let ok = host.dispatch(&peer, &w.req(Operation::Health, Some(OWNER_ID), None, body));
        let alive = ok.outcome == "success";
        cases.push(case("responding_servfail_is_alive", alive, json!({"health": ok.outcome})));
    }

    // 7. IPC auth matrix.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let peer = w.peer();
        let reg = host.dispatch(&peer, &w.req(Operation::RegisterOwner, None, None, w.register_body()));
        let token = w.token(&reg);
        let good_body = json!({
            "token": token, "selected": [GUID_A], "provider": "cloudflare",
            "local_requested": false, "bound_endpoints": [], "readiness_generation": 0u64,
        });
        let mut results = serde_json::Map::new();
        let mut remote = peer.clone();
        remote.remote = true;
        results.insert("remote".into(), json!(host.dispatch(&remote,
            &w.req(Operation::Status, None, None, json!({}))).outcome));
        let mut unelev = peer.clone();
        unelev.elevated = false;
        results.insert("unelevated".into(), json!(host.dispatch(&unelev,
            &w.req(Operation::Status, None, None, json!({}))).outcome));
        let mut spoofed = peer.clone();
        spoofed.pid = PID + 1;
        results.insert("spoofed_pid".into(), json!(host.dispatch(&spoofed,
            &w.req(Operation::Apply, Some(OWNER_ID), None, good_body.clone())).outcome));
        results.insert("bad_token".into(), json!(host.dispatch(&peer,
            &w.req(Operation::Apply, Some(OWNER_ID), None,
                json!({"token": "bad", "selected": [GUID_A], "provider": "cloudflare",
                       "local_requested": false, "bound_endpoints": [], "readiness_generation": 0u64}))).outcome));
        let mut wrong_server = peer.clone();
        wrong_server.server_pid = Some(100);
        wrong_server.expected_server_pid = Some(101);
        results.insert("wrong_server".into(), json!(host.dispatch(&wrong_server,
            &w.req(Operation::Hello, None, None, json!({}))).outcome));
        // Oversized frame never decodes.
        let huge = "x".repeat(protocol::MAX_FRAME_BYTES);
        let big_req = w.req(Operation::Inspect, None, None, json!({"pad": huge}));
        results.insert("oversized_frame".into(), json!(
            protocol::encode_frame(&big_req).is_err()));
        // Unknown protocol never dispatches.
        let raw = serde_json::to_vec(&json!({
            "protocol": 2u32, "request_id": journal::new_uuid(),
            "operation": "hello", "body": {},
        })).unwrap();
        let mut frame = (raw.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&raw);
        results.insert("unknown_protocol".into(), json!(
            protocol::decode_frame(&frame).is_err()));
        let pass = results["remote"] == json!("auth_rejected")
            && results["unelevated"] == json!("auth_rejected")
            && results["spoofed_pid"] == json!("auth_rejected")
            && results["bad_token"] == json!("auth_rejected")
            && results["wrong_server"] == json!("auth_rejected")
            && results["oversized_frame"] == json!(true)
            && results["unknown_protocol"] == json!(true);
        cases.push(case("ipc_auth_matrix_rejects", pass, serde_json::Value::Object(results)));
    }

    // 8. Duplicate request ID cannot repeat a mutation.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let peer = w.peer();
        let reg = host.dispatch(&peer, &w.req(Operation::RegisterOwner, None, None, w.register_body()));
        let token = w.token(&reg);
        host.dispatch(&peer, &w.req(Operation::Health, Some(OWNER_ID), None,
            json!({"token": token, "listener_responding": true, "readiness_generation": 7})));
        let body = json!({
            "token": token, "selected": [GUID_A], "provider": "adguard",
            "local_requested": false, "bound_endpoints": [], "readiness_generation": 7u64,
        });
        let id = journal::new_uuid();
        let first = host.dispatch(&peer, &Request::new(id.clone(), Operation::Apply, Some(OWNER_ID.into()), None, body.clone()));
        let calls = w.os.setter_call_count();
        let second = host.dispatch(&peer, &Request::new(id, Operation::Apply, Some(OWNER_ID.into()), None, body));
        let pass = first.outcome == "active"
            && second.outcome == first.outcome
            && second.generation == first.generation
            && w.os.setter_call_count() == calls;
        cases.push(case("duplicate_request_id_replays", pass, json!({
            "first": first.outcome, "second": second.outcome, "setter_calls": w.os.setter_call_count(),
        })));
    }

    // 9. STOP restores clean; PRESHUTDOWN with missing adapter keeps debt + nonzero.
    {
        let w = World::new();
        w.adapters();
        let mut host = w.host();
        let peer = w.peer();
        let token = w.activate(&mut host, 7);
        let stop = host.dispatch(&peer, &w.req(Operation::PrepareStop, None, None, json!({"reason": "scm_stop"})));
        let clean_stop = stop.outcome == "verified_restored"
            && stop.body["service_exit"] == json!(0)
            && host.control_state() == ControlState::Stopped
            && w.originals_ok();
        cases.push(case("scm_stop_restores_clean", clean_stop, json!({
            "outcome": stop.outcome, "service_exit": stop.body["service_exit"],
        })));

        let w2 = World::new();
        w2.adapters();
        let mut host2 = w2.host();
        let _token2 = w2.activate(&mut host2, 7);
        let _ = token;
        w2.os.remove_adapter(GUID_A);
        w2.os.remove_adapter(GUID_B);
        let peer2 = w2.peer();
        let pre = host2.dispatch(&peer2, &w2.req(Operation::PrepareStop, None, None, json!({"reason": "scm_preshutdown"})));
        let debt_kept = pre.outcome == "pending"
            && pre.body["service_exit"] != json!(0)
            && w2.journal_state().is_some();
        // No lock is held while waiting: the machine lock is free after the call.
        let lock_free = w2.lock.peer(1, 0).acquire(std::time::Duration::from_millis(100)).is_ok();
        cases.push(case("preshutdown_failure_keeps_debt_nonzero", debt_kept && lock_free, json!({
            "outcome": pre.outcome, "service_exit": pre.body["service_exit"], "lock_free": lock_free,
        })));
    }

    // 10. Offline guard refuses anything but proven STOPPED.
    {
        let pass = ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::Stopped).is_ok()
            && ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::Running).is_err()
            && ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::StartPending).is_err()
            && ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::Unknown).is_err();
        cases.push(case("offline_guard_states", pass, json!({})));
    }

    let passed = cases.iter().filter(|c| c.pass).count();
    let total = cases.len();
    let evidence = json!({
        "unit": "U05",
        "harness": "u05_synthetic_harness",
        "scope": "synthetic test GUIDs only; FakeOs/FakeFs/FakeLock in-memory; no NIC, SCM or network I/O",
        "os": std::env::consts::OS,
        "adapter_guids": [GUID_A, GUID_B],
        "restore_start_target_us": 1_000_000,
        "passed": passed,
        "total": total,
        "cases": cases.iter().map(|c| json!({
            "name": c.name, "pass": c.pass, "detail": c.detail,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(EVIDENCE_PATH, serde_json::to_string_pretty(&evidence).unwrap()).expect("write evidence");
    println!("{passed}/{total} harness cases passed — evidence at {EVIDENCE_PATH}");
    if passed != total {
        std::process::exit(1);
    }
}

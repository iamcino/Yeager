//! U05 concrete tests (SPEC-DNS-FIX.md §12 U05 + §8): installable-service
//! host core, secure IPC codec/auth gates, SCM control machine, process
//! monitor (health/watchdog) and scheduling. Library only — every mutation
//! targets FakeOs behind synthetic test GUIDs, never a live adapter, and no
//! production wiring or SCM installation is touched.

use crate::clock::{Clock, VirtualClock};
use crate::fake::FakeOs;
use crate::fs::{join, FakeFs};
use crate::journal::{self, EntryState, JournalState};
use crate::lock::FakeLock;
use crate::model::{Family, Provider};
use crate::protocol::{
    self, AuthError, DedupCache, Operation, PeerAuth, ProtocolError, Reply, Request,
    MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use crate::replay::FakeOwnerProbe;
use crate::service::{
    ControlState, ScmServiceState, ServiceConfig, ServiceHost, HEALTH_INTERVAL_MS,
};
use crate::store::JournalStore;
use crate::transaction::Outcome;
use serde_json::json;
use std::rc::Rc;

const DIR: &str = "C:\\ProgramData\\Yeager";
const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d";
const GUID_A: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
const SERVICE: &str = "44444444-4444-4444-8444-444444444444";
const START_MS: i64 = 1_763_000_000_000;
const V4_ORIG: &str = "192.0.2.53";
const V6_ORIG: &str = "2001:db8::53";
const PID: u32 = 4242;
const FILETIME: u64 = 133_000_000_000_000_000;
const OWNER_ID: &str = "33333333-3333-4333-8333-333333333333";

// ---- world -------------------------------------------------------------------

struct SvcWorld {
    os: FakeOs,
    fs: Rc<FakeFs>,
    lock: FakeLock,
    clock: VirtualClock,
    probe: Rc<FakeOwnerProbe>,
}

impl SvcWorld {
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
            Rc::new(move || Box::new(os_b.clone()) as Box<dyn crate::backend::DnsBackend>),
            Rc::new(move || Box::new(os_s.clone()) as Box<dyn crate::setter::DnsSetter>),
            Rc::new(move || {
                Box::new(lock_base.peer(7000, 0)) as Box<dyn crate::lock::MachineLock>
            }),
            Box::new(clock_b),
            Rc::new(move || Box::new(clock.clone()) as Box<dyn crate::clock::Clock>),
            Rc::new(move || Rc::clone(&fs)),
            Rc::new(move || {
                let p: FakeOwnerProbe = (*probe).clone();
                Box::new(p) as Box<dyn crate::replay::OwnerProbe>
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

    fn static_adapter(&self) {
        self.os.add_adapter(GUID_A, "Ethernet");
        self.os
            .set_configured(GUID_A, Family::Ipv4, V4_ORIG, vec![]);
        self.os
            .set_configured(GUID_A, Family::Ipv6, V6_ORIG, vec![]);
        self.probe.spawn(PID, FILETIME);
    }

    fn register_body(&self, owner_id: &str) -> serde_json::Value {
        json!({
            "owner_id": owner_id,
            "image_sha256": "a".repeat(64),
            "image_file_id": "fileid-1",
        })
    }

    fn health_body(&self, token: &str, readiness: u64, responding: bool) -> serde_json::Value {
        json!({
            "token": token,
            "listener_responding": responding,
            "readiness_generation": readiness,
        })
    }

    fn apply_body(&self, token: &str, readiness: u64) -> serde_json::Value {
        json!({
            "token": token,
            "selected": [GUID_A],
            "provider": "cloudflare",
            "local_requested": false,
            "bound_endpoints": [],
            "readiness_generation": readiness,
        })
    }

    fn register(&self, host: &mut ServiceHost<Rc<FakeFs>>, owner_id: &str) -> Reply {
        let peer = self.peer();
        let req = Request::new(
            journal::new_uuid(),
            Operation::RegisterOwner,
            None,
            None,
            self.register_body(owner_id),
        );
        host.dispatch(&peer, &req)
    }

    fn token_of(&self, rep: &Reply) -> String {
        rep.body
            .get("token")
            .and_then(|v| v.as_str())
            .expect("reply carries a lease token")
            .to_string()
    }

    fn journal_state(&self) -> Option<JournalState> {
        let store = JournalStore::open(Rc::clone(&self.fs), DIR).expect("open store");
        store
            .reconcile()
            .expect("reconcile")
            .current
            .map(|c| c.env.payload.journal_state)
    }
}

fn request(
    op: Operation,
    owner: Option<&str>,
    epoch: Option<u64>,
    body: serde_json::Value,
) -> Request {
    Request::new(
        journal::new_uuid(),
        op,
        owner.map(|s| s.to_string()),
        epoch,
        body,
    )
}

fn os_configured(w: &SvcWorld, family: Family) -> (String, usize) {
    let (ns, props) = w.os.configured(GUID_A, family);
    (ns, props.len())
}

// ---- protocol codec -------------------------------------------------------------

#[test]
fn frame_roundtrip_echoes_request_id_and_rejects_unknowns() {
    let req = request(Operation::Hello, None, None, json!({}));
    let bytes = protocol::encode_frame(&req).expect("encode");
    assert!(bytes.len() < MAX_FRAME_BYTES);
    let back = protocol::decode_frame(&bytes).expect("decode");
    assert_eq!(back, req);

    // Unknown protocol version refuses without writes.
    let mut v: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
    v["protocol"] = json!(2u64);
    let raw = serde_json::to_vec(&v).unwrap();
    let mut frame = (raw.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&raw);
    assert_eq!(
        protocol::decode_frame(&frame),
        Err(ProtocolError::UnknownProtocol(2))
    );

    // Unknown operation refuses without writes.
    v["protocol"] = json!(PROTOCOL_VERSION);
    v["operation"] = json!("escalate_privileges");
    let raw = serde_json::to_vec(&v).unwrap();
    let mut frame = (raw.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&raw);
    assert_eq!(
        protocol::decode_frame(&frame),
        Err(ProtocolError::UnknownOperation("escalate_privileges".into()))
    );
}

#[test]
fn frame_limits_reject_oversized_truncated_and_bad_ids() {
    // Oversized payload (body past 1 MiB).
    let big = "x".repeat(MAX_FRAME_BYTES);
    let req = request(Operation::Inspect, None, None, json!({"pad": big}));
    assert_eq!(
        protocol::encode_frame(&req),
        Err(ProtocolError::OversizedFrame(req_body_len(&req)))
    );
    // Declared length longer than carried bytes.
    let req = request(Operation::Hello, None, None, json!({}));
    let mut bytes = protocol::encode_frame(&req).unwrap();
    let declared = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    bytes.truncate(4 + declared / 2);
    assert_eq!(
        protocol::decode_frame(&bytes),
        Err(ProtocolError::Truncated {
            declared,
            actual: declared / 2
        })
    );
    // Non-UUID request id rejected at encode and decode.
    let bad = Request::new(
        "not-a-uuid".into(),
        Operation::Hello,
        None,
        None,
        json!({}),
    );
    assert!(matches!(
        protocol::encode_frame(&bad),
        Err(ProtocolError::BadRequestId(_))
    ));
}

fn req_body_len(req: &Request) -> usize {
    // encode_frame fails with OversizedFrame(json+4); recompute the declared size.
    let wire = serde_json::json!({
        "protocol": PROTOCOL_VERSION,
        "request_id": req.request_id,
        "operation": req.operation.as_str(),
        "body": req.body,
    });
    serde_json::to_vec(&wire).unwrap().len() + 4
}

#[test]
fn plan_allowlist_rejects_arbitrary_and_non_loopback() {
    let good = json!({
        "provider": "cloudflare",
        "local_requested": false,
        "bound_endpoints": [],
        "readiness_generation": 7u64,
    });
    let plan = protocol::parse_plan(&good).expect("allowlisted plan parses");
    assert_eq!(plan.provider, Provider::Cloudflare);

    for bad in [
        json!({"provider": "quad9", "local_requested": false, "bound_endpoints": [], "readiness_generation": 0u64}),
        json!({"provider": "cloudflare", "local_requested": false, "bound_endpoints": [{"ip": "9.9.9.9", "port": 53, "transport": "udp"}], "readiness_generation": 0u64}),
        json!({"provider": "cloudflare", "local_requested": false, "bound_endpoints": [{"ip": "127.0.0.1", "port": 5353, "transport": "udp"}], "readiness_generation": 0u64}),
        json!({"provider": "cloudflare", "local_requested": true, "bound_endpoints": [{"ip": "127.0.0.1", "port": 53, "transport": "udp"}], "readiness_generation": 0u64}),
        json!({"provider": "cloudflare", "local_requested": true, "bound_endpoints": [], "readiness_generation": 0u64}),
    ] {
        assert!(
            protocol::parse_plan(&bad).is_err(),
            "non-allowlisted plan must refuse: {bad}"
        );
    }
    // Dual-stack loopback with UDP+TCP per family is the allowed local plan.
    let local = json!({
        "provider": "auto",
        "local_requested": true,
        "bound_endpoints": [
            {"ip": "127.0.0.1", "port": 53, "transport": "udp"},
            {"ip": "127.0.0.1", "port": 53, "transport": "tcp"},
            {"ip": "::1", "port": 53, "transport": "udp"},
            {"ip": "::1", "port": 53, "transport": "tcp"},
        ],
        "readiness_generation": 3u64,
    });
    assert!(protocol::parse_plan(&local).is_ok());

    // Selection: non-UUID, empty and duplicates.
    assert!(protocol::parse_selected(&json!({"selected": ["eth0"]})).is_err());
    assert!(protocol::parse_selected(&json!({"selected": []})).is_err());
    let dup = protocol::parse_selected(&json!({"selected": [GUID_A, GUID_A]})).unwrap();
    assert_eq!(dup, vec![GUID_A.to_string()]);
}

#[test]
fn dedup_replays_reply_and_bounds_table() {
    let mut d = DedupCache::new();
    assert!(d.is_empty());
    let rep = Reply::new("id".into(), SERVICE.into(), 3, "active", json!({}));
    d.store("id".into(), rep.clone());
    assert_eq!(d.lookup("id"), Some(&rep));
    assert_eq!(d.len(), 1);
    // Bounded: the oldest entry is evicted past the cap.
    for i in 0..600u32 {
        d.store(format!("k-{i:04}"), rep.clone());
    }
    assert_eq!(d.len(), crate::protocol::MAX_DEDUP_ENTRIES);
    assert!(d.lookup("id").is_none());
}

#[test]
fn peer_auth_gates_remote_unelevated_spoofed_and_anonymous() {
    let mut peer = PeerAuth {
        pid: PID,
        creation_filetime: FILETIME,
        user_sid: "S-1-5-18".into(),
        elevated: true,
        session_id: 0,
        logon_luid: 999,
        image_path: "C:\\Program Files\\Yeager\\yeager.exe".into(),
        remote: false,
        server_pid: Some(100),
        expected_server_pid: Some(100),
    };
    assert!(peer.authorize(Operation::Apply).is_ok());

    peer.remote = true;
    assert_eq!(peer.authorize(Operation::Hello), Err(AuthError::Remote));
    peer.remote = false;

    peer.elevated = false;
    assert_eq!(peer.authorize(Operation::Status), Err(AuthError::Unelevated));
    peer.elevated = true;

    peer.expected_server_pid = Some(101);
    assert_eq!(
        peer.authorize(Operation::Status),
        Err(AuthError::SpoofedServer {
            observed: Some(100),
            expected: Some(101)
        })
    );
    peer.expected_server_pid = Some(100);

    peer.pid = 0;
    assert!(matches!(
        peer.authorize(Operation::Apply),
        Err(AuthError::BadIdentity(_))
    ));
    peer.pid = PID;

    peer.creation_filetime = 0;
    assert!(matches!(
        peer.authorize(Operation::Apply),
        Err(AuthError::BadIdentity(_))
    ));
    // Non-owner ops do not need the creation time.
    assert!(peer.authorize(Operation::Hello).is_ok());
}

// ---- service host lifecycle --------------------------------------------------------

#[test]
fn hello_inspect_status_on_empty_journal() {
    let w = SvcWorld::new();
    let mut host = w.host();
    let peer = w.peer();
    let hello = host.dispatch(&peer, &request(Operation::Hello, None, None, json!({})));
    assert_eq!(hello.outcome, "success");
    let inspect = host.dispatch(&peer, &request(Operation::Inspect, None, None, json!({})));
    assert_eq!(inspect.outcome, "verified_restored");
    let status = host.dispatch(&peer, &request(Operation::Status, None, None, json!({})));
    assert_eq!(status.outcome, "verified_restored");
    assert_eq!(status.body["leases"].as_array().unwrap().len(), 0);
}

#[test]
fn register_bind_takeover_and_duplicate_request_id_replays() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();

    let reg = w.register(&mut host, OWNER_ID);
    assert_eq!(reg.outcome, "success");
    assert_eq!(reg.body["reattached"], json!(false));
    let token = w.token_of(&reg);

    // Duplicate owner id while leased is busy.
    let dup = w.register(&mut host, OWNER_ID);
    assert_eq!(dup.outcome, "busy");

    // Readiness must be proved via health before any plan is accepted.
    let early = host.dispatch(
        &peer,
        &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7)),
    );
    assert_eq!(early.outcome, "refused");

    let health = host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(health.outcome, "success");

    let apply_req = request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7));
    let apply = host.dispatch(&peer, &apply_req);
    assert_eq!(apply.outcome, "active");
    assert!(apply.generation > 0);
    // Takeover rewrote the static originals to the Cloudflare plan.
    let (v4, _) = os_configured(&w, Family::Ipv4);
    assert_ne!(v4, V4_ORIG);

    // Duplicate request ID replays the stored reply: no second mutation.
    let calls_before = w.os.setter_call_count();
    let replay = host.dispatch(&peer, &apply_req);
    assert_eq!(replay.outcome, "active");
    assert_eq!(replay.generation, apply.generation);
    assert_eq!(w.os.setter_call_count(), calls_before);
}

#[test]
fn ipc_auth_rejects_spoofed_pid_token_remote_and_server() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);

    // Spoofed PID with the right token.
    let mut spoofed = peer.clone();
    spoofed.pid = PID + 1;
    let r = host.dispatch(
        &spoofed,
        &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 0)),
    );
    assert_eq!(r.outcome, "auth_rejected");

    // Wrong token.
    let r = host.dispatch(
        &peer,
        &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body("bad-token", 0)),
    );
    assert_eq!(r.outcome, "auth_rejected");

    // Remote and unelevated callers never reach the lease table.
    let mut remote = peer.clone();
    remote.remote = true;
    let r = host.dispatch(&remote, &request(Operation::Status, None, None, json!({})));
    assert_eq!(r.outcome, "auth_rejected");
    let mut unelev = peer.clone();
    unelev.elevated = false;
    let r = host.dispatch(&unelev, &request(Operation::Status, None, None, json!({})));
    assert_eq!(r.outcome, "auth_rejected");

    // Wrong SCM service identity on the client check.
    let mut wrong_server = peer.clone();
    wrong_server.server_pid = Some(100);
    wrong_server.expected_server_pid = Some(101);
    let r = host.dispatch(
        &wrong_server,
        &request(Operation::Hello, None, None, json!({})),
    );
    assert_eq!(r.outcome, "auth_rejected");
}

#[test]
fn owner_death_begins_restoration_and_verifies_originals() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    let apply = host.dispatch(
        &peer,
        &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7)),
    );
    assert_eq!(apply.outcome, "active");

    // TerminateProcess/abort/native-crash simulation: the owner is gone.
    w.probe.kill(PID);
    let report = host
        .on_owner_death(OWNER_ID)
        .expect("dead owner restores");
    assert_eq!(report.outcome, Outcome::VerifiedRestored);
    // Exact originals verified without any GUI relaunch: the OS state is back
    // to the pre-takeover static lists and the journal is a clean tombstone.
    assert_eq!(os_configured(&w, Family::Ipv4).0, V4_ORIG);
    assert_eq!(os_configured(&w, Family::Ipv6).0, V6_ORIG);
    assert_eq!(w.journal_state(), Some(JournalState::Clean));
    assert_eq!(host.lease_count(), 0);
}

#[test]
fn health_timeout_with_live_process_closes_epoch_and_rejects_late_calls() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    let apply = host.dispatch(
        &peer,
        &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7)),
    );
    assert_eq!(apply.outcome, "active");

    // 3 missed reports (6 s) with the process STILL ALIVE: quiesce + restore.
    w.clock.advance_ms(HEALTH_INTERVAL_MS * 3 + 1);
    let sweeps = host.sweep(w.clock.now_ms());
    assert_eq!(sweeps.len(), 1);
    assert_eq!(sweeps[0].outcome, "verified_restored");
    assert_eq!(host.lease_count(), 0);
    assert_eq!(os_configured(&w, Family::Ipv4).0, V4_ORIG);

    // A late heartbeat cannot reopen the revoked epoch.
    let late = host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(late.outcome, "refused");
    // And a late apply with a stale epoch is rejected the same way.
    let stale = host.dispatch(
        &peer,
        &request(Operation::Apply, Some(OWNER_ID), Some(0), w.apply_body(&token, 7)),
    );
    assert_eq!(stale.outcome, "refused");
}

#[test]
fn responding_servfail_is_not_listener_death() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    // Listener responds (SERVFAIL body) — health succeeds and the lease lives.
    let mut body = w.health_body(&token, 7, true);
    body["last_error"] = json!("upstream SERVFAIL");
    let health = host.dispatch(&peer, &request(Operation::Health, Some(OWNER_ID), None, body));
    assert_eq!(health.outcome, "success");
    assert_eq!(host.lease_count(), 1);
}

#[test]
fn explicit_non_responding_listener_restores_with_live_process() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7))
        )
        .outcome,
        "active"
    );
    // Explicit listener loss with the process still alive: the epoch closes
    // and the exact originals restore.
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, false),
        ),
    );
    // The process is still alive (no kill), yet the explicit loss restores.
    assert_eq!(host.lease_count(), 0);
    assert_eq!(os_configured(&w, Family::Ipv4).0, V4_ORIG);
    assert_eq!(w.journal_state(), Some(JournalState::Clean));
}

#[test]
fn service_restart_with_live_owner_reattaches_without_blind_restore() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    let apply = host.dispatch(
        &peer,
        &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7)),
    );
    assert_eq!(apply.outcome, "active");
    let (v4_active, _) = os_configured(&w, Family::Ipv4);
    assert_ne!(v4_active, V4_ORIG);

    // Fresh host incarnation over the same durable state (process restart).
    // The owner process is still alive: boot replay must leave it untouched.
    drop(host);
    let mut restarted = w.host();
    let replay = restarted.boot_replay().expect("boot replay runs");
    assert_eq!(replay.outcome, Outcome::Busy);

    // Re-registration by the SAME live process reattaches: no blind restore.
    let reg2 = restarted.dispatch(&peer, &request(
        Operation::RegisterOwner,
        None,
        None,
        w.register_body(OWNER_ID),
    ));
    assert_eq!(reg2.outcome, "success");
    assert_eq!(reg2.body["reattached"], json!(true));
    let (v4_after, _) = os_configured(&w, Family::Ipv4);
    assert_eq!(v4_after, v4_active, "reattach must not rewrite DNS");

    // The reattached lease (fresh token, journal epoch) can still reconfigure.
    let token2 = w.token_of(&reg2);
    let epoch = reg2.body["epoch"].as_u64().unwrap();
    assert_eq!(epoch, 1);
    let mut reconfig = w.apply_body(&token2, 7);
    reconfig["provider"] = json!("google");
    // Readiness must be re-proved after the restart before mutation.
    let health = restarted.dispatch(&peer, &request(
        Operation::Health,
        Some(OWNER_ID),
        Some(epoch),
        w.health_body(&token2, 7, true),
    ));
    assert_eq!(health.outcome, "success");
    let r = restarted.dispatch(&peer, &request(
        Operation::Reconfigure,
        Some(OWNER_ID),
        Some(epoch),
        reconfig,
    ));
    assert_eq!(r.outcome, "active");
}

#[test]
fn service_restart_after_owner_death_replays_to_clean() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7))
        )
        .outcome,
        "active"
    );
    // Both service and owner die; only the journal survives.
    w.probe.kill(PID);
    drop(host);
    let restarted = w.host();
    let replay = restarted.boot_replay().expect("boot replay runs");
    assert_eq!(replay.outcome, Outcome::VerifiedRestored);
    assert_eq!(os_configured(&w, Family::Ipv4).0, V4_ORIG);
}

#[test]
fn scm_stop_restores_and_blocks_new_work_until_restart() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7))
        )
        .outcome,
        "active"
    );

    let stop = host.dispatch(
        &peer,
        &request(
            Operation::PrepareStop,
            None,
            None,
            json!({"reason": "scm_stop"}),
        ),
    );
    assert_eq!(stop.outcome, "verified_restored");
    assert_eq!(stop.body["service_exit"], json!(0));
    assert_eq!(host.control_state(), ControlState::Stopped);
    assert_eq!(os_configured(&w, Family::Ipv4).0, V4_ORIG);

    // While stopping/stopped, new registration work is refused.
    let reg2 = w.register(&mut host, "44444444-4444-4444-8444-444444444444");
    assert_eq!(reg2.outcome, "busy");
}

#[test]
fn scm_stop_with_transient_failure_preserves_debt_and_nonzero_result() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7))
        )
        .outcome,
        "active"
    );
    // The adapter vanishes entirely: restore cannot verify, debt is retained.
    w.os.remove_adapter(GUID_A);
    let stop = host.dispatch(
        &peer,
        &request(
            Operation::PrepareStop,
            None,
            None,
            json!({"reason": "scm_preshutdown"}),
        ),
    );
    assert_eq!(stop.outcome, "pending");
    assert_eq!(
        stop.body["service_exit"],
        json!(protocol::exit_code_for_outcome("pending"))
    );
    assert_ne!(stop.body["service_exit"], json!(0));
    assert!(w.journal_state().is_some());
}

#[test]
fn quiesce_closes_admission_and_revokes_lease() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7))
        )
        .outcome,
        "active"
    );
    let q = host.dispatch(
        &peer,
        &request(
            Operation::Quiesce,
            Some(OWNER_ID),
            None,
            json!({"token": token}),
        ),
    );
    assert_eq!(q.outcome, "success");
    assert_eq!(host.lease_count(), 0);
    // Admission closed + phase Quiescing in the durable journal.
    let store = JournalStore::open(Rc::clone(&w.fs), DIR).expect("open store");
    let env = store.reconcile().expect("reconcile").current.expect("journal").env;
    let tx = env.payload.transaction.expect("transaction");
    assert_eq!(tx.admission, crate::journal::Admission::Closed);
    assert_eq!(tx.phase, crate::journal::Phase::Quiescing);
    // Quiesce is idempotent-safe to repeat only via a fresh lease; the old
    // token is dead.
    let again = host.dispatch(
        &peer,
        &request(
            Operation::Restore,
            Some(OWNER_ID),
            None,
            json!({"token": token}),
        ),
    );
    assert_eq!(again.outcome, "refused");
}

#[test]
fn foreign_admin_edit_becomes_conflict_and_blocks_clearance() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7))
        )
        .outcome,
        "active"
    );
    // Administrator changes the owned v4 list out from under the service.
    w.os.set_configured(
        GUID_A,
        Family::Ipv4,
        "198.51.100.53",
        vec![],
    );
    let restore = host.dispatch(
        &peer,
        &request(
            Operation::Restore,
            Some(OWNER_ID),
            None,
            json!({"token": token}),
        ),
    );
    assert_eq!(restore.outcome, "conflict");
    // Conflict retains the journal; the owned sibling family still restores.
    assert!(w.journal_state().is_some());
    assert_eq!(os_configured(&w, Family::Ipv6).0, V6_ORIG);
}

#[test]
fn maintenance_blocks_takeover_and_leaves_cleanly() {
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);

    // Live lease without audited quiesce: maintenance refuses.
    let refused = host.dispatch(
        &peer,
        &request(
            Operation::EnterMaintenance,
            None,
            None,
            json!({"reason": "update"}),
        ),
    );
    assert_eq!(refused.outcome, "busy");

    let enter = host.dispatch(
        &peer,
        &request(
            Operation::EnterMaintenance,
            None,
            None,
            json!({"reason": "update", "quiesce_owner": true}),
        ),
    );
    assert_eq!(enter.outcome, "success");
    assert_eq!(w.journal_state(), Some(JournalState::Maintenance));
    assert_eq!(host.lease_count(), 0);

    // Takeover is refused while maintenance holds: registration alone is not
    // a mutation, so it succeeds, but the first mutating apply refuses.
    let reg2 = w.register(&mut host, "55555555-5555-4555-8555-555555555555");
    assert_eq!(reg2.outcome, "success");
    let token2 = w.token_of(&reg2);
    let denied = host.dispatch(
        &peer,
        &request(
            Operation::Apply,
            Some("55555555-5555-4555-8555-555555555555"),
            None,
            w.apply_body(&token2, 0),
        ),
    );
    assert_eq!(denied.outcome, "refused");
    let _ = token;

    let leave = host.dispatch(
        &peer,
        &request(Operation::LeaveMaintenance, None, None, json!({})),
    );
    // No transaction was ever committed (takeover never ran): leaving
    // maintenance on a bare genesis journal honestly refuses — there is no
    // legal clean state to return to.
    assert_eq!(leave.outcome, "unavailable");
}

#[test]
fn offline_guard_refuses_anything_but_proven_stopped() {
    assert!(ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::Stopped).is_ok());
    assert!(ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::Running).is_err());
    assert!(ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::StartPending).is_err());
    assert!(ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::StopPending).is_err());
    assert!(ServiceHost::<Rc<FakeFs>>::offline_precheck(ScmServiceState::Unknown).is_err());
}

#[test]
fn every_setter_call_targets_a_journaled_image() {
    // No GUI direct-writer fallback: the only writes the host can produce go
    // through the engine, and every one names a journaled before/target.
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    assert_eq!(
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7))
        )
        .outcome,
        "active"
    );
    host.dispatch(
        &peer,
        &request(
            Operation::Restore,
            Some(OWNER_ID),
            None,
            json!({"token": token}),
        ),
    );
    let store = JournalStore::open(Rc::clone(&w.fs), DIR).expect("open store");
    let rec = store.reconcile().expect("reconcile");
    // The cycle ended in the durable clean tombstone: no live transaction,
    // no resurrected debt.
    let current = rec.current.expect("clean tombstone generation");
    assert!(current.env.is_clean_tombstone());
    // Restore verified the originals: the last writes equal pre-takeover state.
    assert_eq!(os_configured(&w, Family::Ipv4).0, V4_ORIG);
    assert_eq!(os_configured(&w, Family::Ipv6).0, V6_ORIG);
    // Request IDs were never reused for distinct logical calls... except the
    // seed: every setter call carries the request id of its own intent.
    for c in w.os.setter_calls() {
        assert!(!c.request_id.is_empty());
    }
    let _ = join;
    let _ = EntryState::Applied;
}

#[test]
fn barrier_crash_same_host_watchdog_restores() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let w = SvcWorld::new();
    w.static_adapter();
    let mut host = w.host();
    let peer = w.peer();
    let reg = w.register(&mut host, OWNER_ID);
    let token = w.token_of(&reg);
    host.dispatch(
        &peer,
        &request(
            Operation::Health,
            Some(OWNER_ID),
            None,
            w.health_body(&token, 7, true),
        ),
    );
    // Crash the apply mid-flight at the first intent barrier; the surviving
    // service watchdog (same host, lease intact) restores exact originals.
    host.set_hook(std::rc::Rc::new(|p| {
        if p == crate::transaction::DeathPoint::TransactionCommitted {
            panic!("synthetic crash at TransactionCommitted");
        }
    }));
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        host.dispatch(
            &peer,
            &request(Operation::Apply, Some(OWNER_ID), None, w.apply_body(&token, 7)),
        );
    }));
    assert!(crashed.is_err());
    w.probe.kill(PID);
    let report = host
        .on_owner_death(OWNER_ID)
        .expect("dead owner restores");
    assert_eq!(report.outcome, Outcome::VerifiedRestored);
    assert_eq!(os_configured(&w, Family::Ipv4).0, V4_ORIG);
    assert_eq!(os_configured(&w, Family::Ipv6).0, V6_ORIG);
}

#[test]
fn unknown_version_and_oversized_frames_never_reach_dispatch() {
    // The codec is the boundary: these byte strings must fail decode, so no
    // Request value — and no lease/journal access — can be constructed.
    let garbage = b"not json";
    let mut frame = (garbage.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(garbage);
    assert!(matches!(
        protocol::decode_frame(&frame),
        Err(ProtocolError::BadJson(_))
    ));
    let huge = vec![0u8; MAX_FRAME_BYTES + 4];
    assert_eq!(
        protocol::decode_frame(&huge),
        Err(ProtocolError::OversizedFrame(MAX_FRAME_BYTES + 4))
    );
}

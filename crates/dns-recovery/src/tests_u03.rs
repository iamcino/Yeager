//! U03 concrete tests (SPEC-DNS-FIX.md §12): apply/reconfigure/restore against
//! the fake OS/journal, the full named death-injection and restore list, and
//! the plan/setter-mask rules. Library only — every mutation targets FakeOs,
//! never a live adapter. Configured equality (not lookup) is the success gate.

use crate::backend::{DnsBackend, DNS_SETTING_IPV6};
use crate::clock::{utc_string, Clock, VirtualClock};
use crate::codec;
use crate::fake::{doh_prop, FakeOs};
use crate::fs::{FakeFs, Fault, FaultPoint, FsError};
use crate::journal::{
    self, Admission, BaselineKind, Entry, EntryState, Envelope, JournalState, OperationKind,
    OperationState, OwnerIdentity, Payload, Phase, MAX_OPERATIONS_PER_ENTRY,
};
use crate::lock::FakeLock;
use crate::model::{
    BoundEndpoint, CaptureError, DesiredPlan, Family, Provenance, Provider, Snapshot, Transport,
};
use crate::plan::{automatic_image, plan_image, provider_spec, setter_mask};
use crate::setter::{DNS_SETTING_DOH, DNS_SETTING_NAMESERVER, DOH_ENABLE, ERROR_ACCESS_DENIED};
use crate::store::{JournalStore, StoreError};
use crate::transaction::{background_delay_ms, DeathPoint, EngineError, Outcome, TransactionEngine};
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

const DIR: &str = "C:\\ProgramData\\Yeager";
const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d";
const GUID_A: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
const GUID_B: &str = "7430a27b-1b15-4d8c-b7b6-96a803b09bb1";
const SERVICE: &str = "44444444-4444-4444-8444-444444444444";
const START_MS: i64 = 1_763_000_000_000;
const V4_ORIG: &str = "192.0.2.53";
const V6_ORIG: &str = "2001:db8::53";
const CF_TEMPLATE: &str = "https://cloudflare-dns.com/dns-query";
const NOW: &str = "2026-11-13T18:08:29Z";

fn owner() -> OwnerIdentity {
    OwnerIdentity {
        owner_id: "33333333-3333-4333-8333-333333333333".to_string(),
        pid: 4242,
        creation_time_filetime: 133_000_000_000_000_000,
        user_sid: "S-1-5-18".to_string(),
        logon_luid: 999,
        session_id: 0,
        image_path: "C:\\Program Files\\Yeager\\yeager.exe".to_string(),
        image_file_id: "fileid-1".to_string(),
        image_sha256: "a".repeat(64),
    }
}

fn loopback_eps() -> Vec<BoundEndpoint> {
    vec![
        BoundEndpoint { ip: "127.0.0.1".parse().unwrap(), port: 53, transport: Transport::Udp },
        BoundEndpoint { ip: "127.0.0.1".parse().unwrap(), port: 53, transport: Transport::Tcp },
        BoundEndpoint { ip: "::1".parse().unwrap(), port: 53, transport: Transport::Udp },
        BoundEndpoint { ip: "::1".parse().unwrap(), port: 53, transport: Transport::Tcp },
    ]
}

fn plan_provider(provider: Provider) -> DesiredPlan {
    DesiredPlan { provider, local_requested: false, bound_endpoints: Vec::new(), readiness_generation: 1 }
}

fn plan_local(provider: Provider) -> DesiredPlan {
    DesiredPlan { provider, local_requested: true, bound_endpoints: loopback_eps(), readiness_generation: 1 }
}

fn plan_local_v4only(provider: Provider) -> DesiredPlan {
    DesiredPlan {
        provider,
        local_requested: true,
        bound_endpoints: vec![
            BoundEndpoint { ip: "127.0.0.1".parse().unwrap(), port: 53, transport: Transport::Udp },
            BoundEndpoint { ip: "127.0.0.1".parse().unwrap(), port: 53, transport: Transport::Tcp },
        ],
        readiness_generation: 1,
    }
}

fn cf_props() -> Vec<crate::backend::RawProperty> {
    vec![doh_prop(0, Some(CF_TEMPLATE), DOH_ENABLE), doh_prop(1, Some(CF_TEMPLATE), DOH_ENABLE)]
}

struct World {
    os: FakeOs,
    fs: Rc<FakeFs>,
    lock: FakeLock,
    clock: VirtualClock,
}

impl World {
    fn new() -> Self {
        Self { os: FakeOs::new(), fs: Rc::new(FakeFs::new()), lock: FakeLock::new(), clock: VirtualClock::new(START_MS) }
    }

    fn engine(&self) -> TransactionEngine<Rc<FakeFs>> {
        let store = JournalStore::open(Rc::clone(&self.fs), DIR).expect("open journal store");
        TransactionEngine::new(
            Box::new(self.os.clone()),
            Box::new(self.os.clone()),
            store,
            Box::new(self.lock.peer(4242, 0)),
            Box::new(self.clock.clone()),
            MACHINE.to_string(),
            owner(),
            SERVICE.to_string(),
        )
    }

    fn static_adapter(&self, guid: &str) {
        self.os.add_adapter(guid, "Ethernet");
        self.os.set_configured(guid, Family::Ipv4, V4_ORIG, vec![]);
        self.os.set_configured(guid, Family::Ipv6, V6_ORIG, vec![]);
    }
}

/// Model holder death after an unwind: close every fake handle, mark the lock
/// abandoned, then build a fresh engine incarnation on the shared durable state.
fn recover(w: &World) -> TransactionEngine<Rc<FakeFs>> {
    w.fs.close_all_handles();
    w.lock.simulate_holder_death();
    w.engine()
}

fn originals(os: &FakeOs, guid: &str) -> (Snapshot, Snapshot) {
    (os.readback(guid, Family::Ipv4).unwrap(), os.readback(guid, Family::Ipv6).unwrap())
}

fn entries(eng: &TransactionEngine<Rc<FakeFs>>) -> Vec<Entry> {
    eng.current_envelope().expect("envelope").payload.transaction.expect("transaction").entries
}

fn entry_for(eng: &TransactionEngine<Rc<FakeFs>>, guid: &str, family: Family) -> Entry {
    entries(eng).into_iter().find(|e| e.adapter_guid == guid && e.family == family).expect("entry")
}

fn assert_active_configured(os: &FakeOs, eng: &TransactionEngine<Rc<FakeFs>>, guid: &str) {
    for family in [Family::Ipv4, Family::Ipv6] {
        let e = entry_for(eng, guid, family);
        let intended = e.intended.as_ref().expect("intended image");
        let now = os.readback(guid, family).expect("readback");
        assert!(now.configured_eq(intended), "configured equality {guid} {family:?}");
        assert_eq!(e.applied_fingerprint, Some(intended.fingerprint()));
        assert_eq!(e.state, EntryState::Applied);
    }
}

fn assert_original(os: &FakeOs, guid: &str, o4: &Snapshot, o6: &Snapshot) {
    assert!(os.readback(guid, Family::Ipv4).unwrap().configured_eq(o4), "v4 original {guid}");
    assert!(os.readback(guid, Family::Ipv6).unwrap().configured_eq(o6), "v6 original {guid}");
}

fn assert_request_ids_unique(os: &FakeOs) {
    for c in os.setter_calls() {
        assert_eq!(os.calls_for_request(&c.request_id), 1, "request id reused: {}", c.request_id);
    }
}

fn v4_restore_calls(os: &FakeOs) -> usize {
    os.setter_calls().iter().filter(|c| c.family == Family::Ipv4 && c.image.name_server == V4_ORIG).count()
}

// ---- 1. exact round trips --------------------------------------------------

#[test]
fn roundtrip_static_all_providers() {
    for provider in [Provider::Auto, Provider::Cloudflare, Provider::Google, Provider::Adguard] {
        for mode in 0..3 {
            let w = World::new();
            w.static_adapter(GUID_A);
            let (o4, o6) = originals(&w.os, GUID_A);
            let plan = match mode {
                0 => plan_provider(provider),
                1 => plan_local(provider),
                _ => plan_local_v4only(provider),
            };
            let eng = w.engine();
            let rep = eng.takeover(&[GUID_A.to_string()], &plan).unwrap();
            assert_eq!(rep.outcome, Outcome::Active, "{provider:?} mode {mode}");
            assert!(rep.errors.is_empty());
            assert_active_configured(&w.os, &eng, GUID_A);
            assert_request_ids_unique(&w.os);
            let rep = eng.restore().unwrap();
            assert_eq!(rep.outcome, Outcome::VerifiedRestored);
            assert_original(&w.os, GUID_A, &o4, &o6);
            assert_request_ids_unique(&w.os);
        }
    }
}

#[test]
fn roundtrip_automatic_original() {
    let w = World::new();
    w.os.add_adapter(GUID_A, "Ethernet");
    let (o4, o6) = originals(&w.os, GUID_A);
    assert_eq!(o4.provenance, Provenance::Automatic);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
    let r4 = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    assert_eq!(r4.provenance, Provenance::Automatic);
    assert_eq!(r4.name_server_raw, Some(String::new()));
    assert!(r4.server_properties.is_empty());
}

#[test]
fn roundtrip_static_doh_original() {
    let w = World::new();
    w.os.add_adapter(GUID_A, "Ethernet");
    w.os.set_configured(GUID_A, Family::Ipv4, V4_ORIG, vec![doh_prop(0, Some("https://orig.example/dns-query"), DOH_ENABLE)]);
    w.os.set_configured(GUID_A, Family::Ipv6, V6_ORIG, vec![doh_prop(0, Some("https://orig.example/dns-query"), DOH_ENABLE)]);
    let (o4, o6) = originals(&w.os, GUID_A);
    assert!(!o4.server_properties.is_empty());
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
    let r4 = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    assert_eq!(r4.server_properties, o4.server_properties);
}

#[test]
fn roundtrip_mixed_families() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.os.add_adapter(GUID_B, "Wi-Fi");
    w.os.set_configured(GUID_B, Family::Ipv4, "198.51.100.7", vec![]);
    w.os.set_configured(GUID_B, Family::Ipv6, "2001:db8::7", vec![]);
    let (a4, a6) = originals(&w.os, GUID_A);
    let (b4, b6) = originals(&w.os, GUID_B);
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string(), GUID_B.to_string()], &plan_local(Provider::Google)).unwrap();
    assert_eq!(rep.outcome, Outcome::Active);
    assert_active_configured(&w.os, &eng, GUID_A);
    assert_active_configured(&w.os, &eng, GUID_B);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &a4, &a6);
    assert_original(&w.os, GUID_B, &b4, &b6);
}

#[test]
fn plan_builder_rules() {
    let w = World::new();
    w.os.add_adapter(GUID_A, "Ethernet");
    let before = w.os.readback(GUID_A, Family::Ipv4).unwrap();

    let img = plan_image(GUID_A, Family::Ipv4, &plan_provider(Provider::Cloudflare), &before, NOW);
    assert_eq!(img.name_server_raw, Some("1.1.1.1,1.0.0.1".to_string()));
    assert_eq!(img.provenance, Provenance::Static);
    assert_eq!(img.ordered_servers.len(), 2);
    assert_eq!(img.server_properties.len(), 2);
    assert_eq!(img.server_properties[0].server_index, 0);
    assert_eq!(img.server_properties[0].doh.template, Some(CF_TEMPLATE.to_string()));
    assert_eq!(img.server_properties[0].doh.flags, DOH_ENABLE);

    // Single bound endpoint isolates the builder rule (one token per matching
    // endpoint, loopback first, provider fallback last) from UDP+TCP duplication.
    let single_local = DesiredPlan {
        provider: Provider::Cloudflare,
        local_requested: true,
        bound_endpoints: vec![BoundEndpoint { ip: "127.0.0.1".parse().unwrap(), port: 53, transport: Transport::Udp }],
        readiness_generation: 1,
    };
    let limg = plan_image(GUID_A, Family::Ipv4, &single_local, &before, NOW);
    assert_eq!(limg.name_server_raw, Some("127.0.0.1,1.1.1.1".to_string()));
    assert_eq!(limg.server_properties.len(), 1, "loopback carries no DoH property");
    assert_eq!(limg.server_properties[0].server_index, 1);

    let v6img = plan_image(GUID_A, Family::Ipv6, &plan_local_v4only(Provider::Cloudflare), &before, NOW);
    assert_eq!(v6img.name_server_raw, Some("2606:4700:4700::1111".to_string()));
    assert_eq!(v6img.server_properties.len(), 1);

    let auto = automatic_image(GUID_A, &before, NOW);
    assert_eq!(auto.provenance, Provenance::Automatic);
    assert_eq!(auto.name_server_raw, Some(String::new()));
    assert!(auto.ordered_servers.is_empty());
    assert!(auto.server_properties.is_empty());

    let cf = provider_spec(Provider::Cloudflare);
    assert_eq!(cf.template, CF_TEMPLATE);
    assert_eq!(cf.v4, ["1.1.1.1", "1.0.0.1"]);
    assert_eq!(cf.v6, ["2606:4700:4700::1111", "2606:4700:4700::1001"]);
    assert_eq!(provider_spec(Provider::Auto).v4, cf.v4);
    assert_eq!(provider_spec(Provider::Google).v4, ["8.8.8.8", "8.8.4.4"]);
    assert_eq!(provider_spec(Provider::Adguard).v4, ["94.140.14.14", "94.140.15.15"]);

    assert_eq!(setter_mask(Family::Ipv4), DNS_SETTING_NAMESERVER | DNS_SETTING_DOH);
    assert_eq!(setter_mask(Family::Ipv6), DNS_SETTING_NAMESERVER | DNS_SETTING_DOH | DNS_SETTING_IPV6);
}

// ---- 2. failure capturing / setter failures restore every original ---------

#[test]
fn capture_failure_second_adapter_zero_writes() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.static_adapter(GUID_B);
    w.os.set_capture_error(GUID_B, Family::Ipv4, CaptureError::QueryFailure("capture denied".into()));
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string(), GUID_B.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::Refused);
    assert_eq!(w.os.setter_call_count(), 0);
    assert!(rep.errors.iter().any(|e| e.adapter_guid == GUID_B && e.family == Family::Ipv4 && e.phase == "capture"));
    assert!(eng.current_envelope().is_none(), "no journal commit before capture completes");
}

#[test]
fn setter_fail_first_v4() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    w.os.fail_setter_for(GUID_A, Family::Ipv4, 1231, false);
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(rep.errors.iter().any(|e| e.family == Family::Ipv4 && e.phase == "apply"
        && e.windows_status == Some(1231) && e.retryable && e.attempts == 1));
    assert_original(&w.os, GUID_A, &o4, &o6);
    assert_eq!(w.os.setter_call_count(), 1);
    assert_request_ids_unique(&w.os);
}

#[test]
fn setter_fail_v6_after_v4() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    w.os.fail_setter_for(GUID_A, Family::Ipv6, 1231, false);
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(rep.errors.iter().any(|e| e.family == Family::Ipv6 && e.phase == "apply" && e.windows_status == Some(1231)));
    assert_original(&w.os, GUID_A, &o4, &o6);
    assert_eq!(w.os.setter_call_count(), 3, "v4 apply + v6 apply + v4 restore");
    assert_request_ids_unique(&w.os);
}

#[test]
fn setter_fail_second_adapter() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.static_adapter(GUID_B);
    let (a4, a6) = originals(&w.os, GUID_A);
    let (b4, b6) = originals(&w.os, GUID_B);
    w.os.fail_setter_for(GUID_B, Family::Ipv4, 1231, false);
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string(), GUID_B.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(rep.errors.iter().any(|e| e.adapter_guid == GUID_B && e.family == Family::Ipv4 && e.phase == "apply"));
    assert_original(&w.os, GUID_A, &a4, &a6);
    assert_original(&w.os, GUID_B, &b4, &b6);
    assert_request_ids_unique(&w.os);
}

// ---- 3. death injection at every intent flush / call / readback / marker ----

#[test]
fn death_at_every_takeover_point() {
    let points = [
        DeathPoint::TransactionCommitted,
        DeathPoint::ApplyIntentFlushed,
        DeathPoint::BeforeSetterCall,
        DeathPoint::AfterSetterCall,
        DeathPoint::AfterReadback,
        DeathPoint::AppliedMarkerFlushed,
        DeathPoint::ActiveMarkerFlushed,
    ];
    for point in points {
        let w = World::new();
        w.static_adapter(GUID_A);
        let (o4, o6) = originals(&w.os, GUID_A);
        let eng1 = w.engine().with_hook(Rc::new(move |p| {
            if p == point {
                panic!("U03 death injection at {p:?}");
            }
        }));
        let res = catch_unwind(AssertUnwindSafe(|| {
            eng1.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare))
        }));
        assert!(res.is_err(), "takeover must die at {point:?}");
        let eng2 = recover(&w);
        let rep = eng2.restore().expect("restore after takeover death");
        assert_eq!(rep.outcome, Outcome::VerifiedRestored, "recover {point:?}");
        assert_original(&w.os, GUID_A, &o4, &o6);
        assert_request_ids_unique(&w.os);
    }
}

#[test]
fn death_at_every_restore_point() {
    let points = [
        DeathPoint::RestoreEpochFlushed,
        DeathPoint::RestoreIntentFlushed,
        DeathPoint::BeforeRestoreCall,
        DeathPoint::AfterRestoreCall,
        DeathPoint::AfterRestoreReadback,
        DeathPoint::RestoredMarkerFlushed,
        DeathPoint::CompleteMarkerFlushed,
        DeathPoint::TombstoneFlushed,
    ];
    for point in points {
        let w = World::new();
        w.static_adapter(GUID_A);
        let (o4, o6) = originals(&w.os, GUID_A);
        let eng0 = w.engine();
        assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
        let eng1 = w.engine().with_hook(Rc::new(move |p| {
            if p == point {
                panic!("U03 death injection at {p:?}");
            }
        }));
        let res = catch_unwind(AssertUnwindSafe(|| eng1.restore()));
        assert!(res.is_err(), "restore must die at {point:?}");
        let eng2 = recover(&w);
        let rep = eng2.restore().expect("restore after restore death");
        assert_eq!(rep.outcome, Outcome::VerifiedRestored, "recover {point:?}");
        assert_original(&w.os, GUID_A, &o4, &o6);
        assert_request_ids_unique(&w.os);
    }
}

#[test]
fn death_at_reconfigure_intent() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    let eng1 = w.engine().with_hook(Rc::new(|p| {
        if p == DeathPoint::ReconfigureIntentFlushed {
            panic!("U03 death at reconfigure intent");
        }
    }));
    let res = catch_unwind(AssertUnwindSafe(|| eng1.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google))));
    assert!(res.is_err());
    let eng2 = recover(&w);
    assert_eq!(eng2.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
}

#[test]
fn setter_error_after_change_matches() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.os.fail_next_setter(1231, true);
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::Active);
    assert!(rep.errors.is_empty(), "readback match authorizes success despite API error");
    assert_active_configured(&w.os, &eng, GUID_A);
    let env = eng.current_envelope().unwrap();
    assert!(env.payload.diagnostics.iter().any(|d| d.kind == "setter-error-readback-match"));
    assert_eq!(w.os.setter_call_count(), 2);
}

#[test]
fn setter_error_after_change_divergent() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    w.os.fail_next_setter(1231, true);
    let os = w.os.clone();
    let fired = Rc::new(Cell::new(false));
    let eng = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::AfterSetterCall && !fired.get() {
            fired.set(true);
            os.set_configured(GUID_A, Family::Ipv4, V4_ORIG, vec![]);
        }
    }));
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(rep.errors.iter().any(|e| e.family == Family::Ipv4 && e.phase == "apply" && e.windows_status == Some(1231)));
    assert_original(&w.os, GUID_A, &o4, &o6);
    assert_eq!(w.os.setter_call_count(), 1);
}

#[test]
fn intent_only_success_no_call() {
    let w = World::new();
    w.os.add_adapter(GUID_A, "Ethernet");
    w.os.set_configured(GUID_A, Family::Ipv4, "1.1.1.1,1.0.0.1", cf_props());
    w.os.set_configured(GUID_A, Family::Ipv6, "2606:4700:4700::1111,2606:4700:4700::1001", cf_props());
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::Active);
    assert_eq!(w.os.setter_call_count(), 0, "already at target: intent verified without a call");
    assert_active_configured(&w.os, &eng, GUID_A);
}

#[test]
fn lost_reply_request_id_dedup() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    w.os.die_after_change();
    let eng1 = w.engine();
    let res = catch_unwind(AssertUnwindSafe(|| eng1.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare))));
    assert!(res.is_err());
    let env = eng1.current_envelope().unwrap();
    let e4 = env.payload.transaction.unwrap().entries.into_iter().find(|e| e.family == Family::Ipv4).unwrap();
    let last = e4.operations.last().unwrap();
    assert_eq!(last.state, OperationState::Intent);
    let apply_req = last.request_id.clone();
    let eng2 = recover(&w);
    assert_eq!(eng2.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
    assert_eq!(w.os.calls_for_request(&apply_req), 1, "lost reply settles by readback, never re-calls");
    assert_request_ids_unique(&w.os);
}

// ---- 4. provider / local sequences then original restoration ---------------

#[test]
fn cloudflare_google_auto_then_restore() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    assert_active_configured(&w.os, &eng, GUID_A);
    let first_fp = entry_for(&eng, GUID_A, Family::Ipv4).original_fingerprint.clone();
    assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap().outcome, Outcome::Active);
    assert_active_configured(&w.os, &eng, GUID_A);
    assert_eq!(entry_for(&eng, GUID_A, Family::Ipv4).original_fingerprint, first_fp);
    assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Auto)).unwrap().outcome, Outcome::Active);
    assert_active_configured(&w.os, &eng, GUID_A);
    assert_eq!(entry_for(&eng, GUID_A, Family::Ipv4).original_fingerprint, first_fp);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
}

#[test]
fn local_on_off_v4only_then_restore() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_local(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    assert_active_configured(&w.os, &eng, GUID_A);
    assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    assert_active_configured(&w.os, &eng, GUID_A);
    assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_local_v4only(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    assert_active_configured(&w.os, &eng, GUID_A);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
}

#[test]
fn failed_reconfigure_restores_original() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    // One-shot: the reconfigure's first v4 setter call fails, then the
    // whole-transaction rollback to the immutable originals must succeed.
    w.os.fail_next_setter(1231, false);
    let rep = eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(rep.errors.iter().any(|e| e.family == Family::Ipv4 && e.phase == "apply"));
    assert_original(&w.os, GUID_A, &o4, &o6);
}

#[test]
fn reconfigure_removed_adapter_restored_before_release() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.os.add_adapter(GUID_B, "Wi-Fi");
    w.os.set_configured(GUID_B, Family::Ipv4, "198.51.100.7", vec![]);
    w.os.set_configured(GUID_B, Family::Ipv6, "2001:db8::7", vec![]);
    let (a4, a6) = originals(&w.os, GUID_A);
    let (b4, b6) = originals(&w.os, GUID_B);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string(), GUID_B.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    let rep = eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap();
    assert_eq!(rep.outcome, Outcome::Active);
    assert!(rep.errors.is_empty());
    // C4: the removed adapter is back to its exact original and released.
    assert_original(&w.os, GUID_B, &b4, &b6);
    let es = entries(&eng);
    assert_eq!(es.len(), 2);
    assert!(es.iter().all(|e| e.adapter_guid == GUID_A));
    assert_active_configured(&w.os, &eng, GUID_A);
    let ea4 = entry_for(&eng, GUID_A, Family::Ipv4);
    assert!(ea4.previous_committed.is_some(), "C4 publishes previous_committed");
    assert!(ea4.original.configured_eq(&a4), "original survives the revision");
    // Ordering: both B restore calls precede the first retained-adapter write.
    let calls = w.os.setter_calls();
    let a_google = calls.iter().position(|c| c.guid == GUID_A && c.image.name_server.starts_with("8.8.8.8")).expect("retained Google write");
    let b4_restore = calls.iter().rposition(|c| c.guid == GUID_B && c.image.name_server == "198.51.100.7").expect("B v4 restore");
    let b6_restore = calls.iter().rposition(|c| c.guid == GUID_B && c.image.name_server == "2001:db8::7").expect("B v6 restore");
    assert!(b4_restore < a_google && b6_restore < a_google, "removed adapter restored before release");
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &a4, &a6);
    assert_original(&w.os, GUID_B, &b4, &b6);
    assert_request_ids_unique(&w.os);
}

#[test]
fn death_during_quiescing_recovers_both_adapters() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.static_adapter(GUID_B);
    let (a4, a6) = originals(&w.os, GUID_A);
    let (b4, b6) = originals(&w.os, GUID_B);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string(), GUID_B.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    let fired = Rc::new(Cell::new(false));
    let fired2 = Rc::clone(&fired);
    let eng1 = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::RestoreIntentFlushed && !fired2.get() {
            fired2.set(true);
            panic!("U03 death at quiescing restore intent");
        }
    }));
    let res = catch_unwind(AssertUnwindSafe(|| {
        eng1.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google))
    }));
    assert!(res.is_err());
    let env = eng1.current_envelope().unwrap();
    let tx = env.payload.transaction.unwrap();
    assert_eq!(tx.phase, Phase::Quiescing, "removal enters Quiescing before restoring");
    let eb4 = tx.entries.iter().find(|e| e.adapter_guid == GUID_B && e.family == Family::Ipv4).unwrap();
    assert_eq!(eb4.state, EntryState::RestoreIntent);
    let op = eb4.operations.last().unwrap();
    assert_eq!(op.kind, OperationKind::Restore);
    assert!(op.target.configured_eq(&b4), "restore intent targets the immutable original");
    let ea4 = tx.entries.iter().find(|e| e.adapter_guid == GUID_A && e.family == Family::Ipv4).unwrap();
    assert_eq!(ea4.state, EntryState::Applied, "retained adapter untouched during quiesce");
    assert_eq!(w.os.setter_call_count(), 4, "no restore call before the intent barrier");
    assert!(w.os.readback(GUID_B, Family::Ipv4).unwrap().configured_eq(eb4.intended.as_ref().unwrap()));
    let eng2 = recover(&w);
    assert_eq!(eng2.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &a4, &a6);
    assert_original(&w.os, GUID_B, &b4, &b6);
    assert_request_ids_unique(&w.os);
}

#[test]
fn reconfigure_removal_failure_retains_debt() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.static_adapter(GUID_B);
    let (a4, a6) = originals(&w.os, GUID_A);
    let (b4, b6) = originals(&w.os, GUID_B);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string(), GUID_B.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.fail_setter_for(GUID_B, Family::Ipv4, ERROR_ACCESS_DENIED, false);
    let rep = eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    assert!(rep.errors.iter().any(|e| e.adapter_guid == GUID_B && e.family == Family::Ipv4));
    let env = eng.current_envelope().unwrap();
    assert_eq!(env.payload.journal_state, JournalState::RecoveryPending);
    let tx = env.payload.transaction.unwrap();
    assert_eq!(tx.phase, Phase::Pending);
    assert_eq!(tx.admission, Admission::Closed);
    // Unrestorable removed entry retained as debt; restored v6 released.
    let eb4 = tx.entries.iter().find(|e| e.adapter_guid == GUID_B && e.family == Family::Ipv4).expect("debt entry retained");
    assert_eq!(eb4.state, EntryState::Failed);
    assert!(eb4.retry.next_attempt_utc.is_some());
    assert!(!tx.entries.iter().any(|e| e.adapter_guid == GUID_B && e.family == Family::Ipv6));
    // C3: the whole transaction rolls back — retained adapters restored too.
    assert_original(&w.os, GUID_A, &a4, &a6);
    assert!(w.os.readback(GUID_B, Family::Ipv6).unwrap().configured_eq(&b6));
    assert!(w.os.setter_calls().iter().all(|c| !c.image.name_server.starts_with("8.8.8.8")), "no reconfigure writes while debt unresolved");
    // Debt blocks new admission.
    assert!(matches!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Google)), Ok(r) if r.outcome == Outcome::Busy));
    assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap().outcome, Outcome::Refused);
    // Background retry settles the debt and completes the rollback.
    w.clock.advance_ms(5_000);
    w.os.clear_failures();
    assert_eq!(eng.run_background_pass().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &a4, &a6);
    assert_original(&w.os, GUID_B, &b4, &b6);
    assert!(eng.current_envelope().unwrap().payload.transaction.is_none(), "clean tombstone after debt settles");
    assert_request_ids_unique(&w.os);
}

// ---- 5. noninterference, baseline ordering, immutability, operation limit ---

#[test]
fn no_profile_global_context_writes() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.os.update_raw(GUID_A, Family::Ipv4, |r| {
        r.domain = Some("corp.example".into());
        r.search_list = Some("corp.example".into());
        r.registration_enabled = 1;
    });
    w.os.update_raw(GUID_A, Family::Ipv6, |r| {
        r.domain = Some("corp.example".into());
    });
    let ctx4_before = w.os.readback(GUID_A, Family::Ipv4).unwrap().context;
    let ctx6_before = w.os.readback(GUID_A, Family::Ipv6).unwrap().context;
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap().outcome, Outcome::Active);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    let ctx4_after = w.os.readback(GUID_A, Family::Ipv4).unwrap().context;
    let ctx6_after = w.os.readback(GUID_A, Family::Ipv6).unwrap().context;
    assert_eq!(ctx4_before, ctx4_after, "profile/global/context untouched (v4)");
    assert_eq!(ctx6_before, ctx6_after, "profile/global/context untouched (v6)");
    assert_request_ids_unique(&w.os);
}

#[test]
fn new_guid_baseline_committed_before_first_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.static_adapter(GUID_B);
    let (b4, b6) = originals(&w.os, GUID_B);
    let os = w.os.clone();
    let eng1 = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::AfterSetterCall {
            let calls = os.setter_calls();
            if calls.last().map(|c| c.guid == GUID_B).unwrap_or(false) {
                panic!("U03 death at new GUID first write");
            }
        }
    }));
    let res = catch_unwind(AssertUnwindSafe(|| {
        eng1.reconfigure(&[GUID_A.to_string(), GUID_B.to_string()], &plan_provider(Provider::Google))
    }));
    assert!(res.is_err());
    let env = eng1.current_envelope().unwrap();
    let eb4 = env.payload.transaction.unwrap().entries.into_iter()
        .find(|e| e.adapter_guid == GUID_B && e.family == Family::Ipv4).unwrap();
    assert_eq!(eb4.baseline_kind, BaselineKind::PreTakeover);
    assert!(eb4.original.configured_eq(&b4), "new GUID original captured before its first write");
    let last = eb4.operations.last().unwrap();
    assert_eq!(last.kind, OperationKind::Apply);
    assert!(last.before.configured_eq(&b4));
    let eng2 = recover(&w);
    assert_eq!(eng2.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_B, &b4, &b6);
}

#[test]
fn new_guid_capture_failure_zero_writes() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.static_adapter(GUID_B);
    w.os.set_capture_error(GUID_B, Family::Ipv4, CaptureError::QueryFailure("capture denied".into()));
    let rep = eng.reconfigure(&[GUID_A.to_string(), GUID_B.to_string()], &plan_provider(Provider::Google)).unwrap();
    assert_eq!(rep.outcome, Outcome::Refused);
    assert!(rep.errors.iter().any(|e| e.adapter_guid == GUID_B && e.phase == "capture"));
    assert_eq!(w.os.setter_call_count(), 2, "no new writes on capture failure");
    assert_active_configured(&w.os, &eng, GUID_A);
}

#[test]
fn previous_originals_immutable() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, _o6) = originals(&w.os, GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    let fp = entry_for(&eng, GUID_A, Family::Ipv4).original_fingerprint.clone();
    for provider in [Provider::Google, Provider::Auto, Provider::Adguard] {
        assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_provider(provider)).unwrap().outcome, Outcome::Active);
        let e = entry_for(&eng, GUID_A, Family::Ipv4);
        assert_eq!(e.original_fingerprint, fp, "first original survives reconfigure");
        assert!(e.original.configured_eq(&o4));
    }
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
}

#[test]
fn operation_limit_refuses_reconfigure() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    // Two real revisions prove operations accumulate across reconfigures.
    for provider in [Provider::Google, Provider::Cloudflare] {
        assert_eq!(eng.reconfigure(&[GUID_A.to_string()], &plan_provider(provider)).unwrap().outcome, Outcome::Active);
    }
    assert_eq!(entry_for(&eng, GUID_A, Family::Ipv4).operations.len(), 3);

    // Seed each entry to the 256-operation cap with cloned Verified operations
    // (fresh ids/request-ids/ordinals) rather than 255 full revisions, which are
    // O(n^2) in the debug journal. The refusal gate reads operations.len(), so
    // this exercises the same path as naturally reaching the cap.
    let mut env = eng.current_envelope().unwrap();
    let digest = codec::envelope_digest(&codec::encode(&env));
    env.generation += 1;
    env.previous_digest = Some(digest);
    if let Some(tx) = &mut env.payload.transaction {
        for e in tx.entries.iter_mut() {
            let template = e.operations.last().unwrap().clone();
            let mut ordinal = template.ordinal;
            while e.operations.len() < MAX_OPERATIONS_PER_ENTRY {
                ordinal += 1;
                let mut op = template.clone();
                op.id = journal::new_uuid();
                op.request_id = journal::new_uuid();
                op.ordinal = ordinal;
                op.intent_generation = env.generation;
                e.operations.push(op);
            }
        }
    }
    codec::seal(&mut env);
    eng.store().commit(&env).expect("seeded envelope commits");

    // The next operation reloads the seeded journal before the cap check.
    let calls_before = w.os.setter_call_count();
    let rep = eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap();
    assert_eq!(rep.outcome, Outcome::Refused, "at the 256-operation limit reconfigure is refused");
    assert_eq!(w.os.setter_call_count(), calls_before, "refused reconfigure writes nothing");
    assert_eq!(entry_for(&eng, GUID_A, Family::Ipv4).operations.len(), MAX_OPERATIONS_PER_ENTRY);
    assert_eq!(entry_for(&eng, GUID_A, Family::Ipv6).operations.len(), MAX_OPERATIONS_PER_ENTRY);
}

// ---- 6. virtual-clock retries, budgets, races, pending retention -----------

#[test]
fn foreground_retry_counts_and_delays() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.fail_setter_for(GUID_A, Family::Ipv4, 1231, false);
    let os = w.os.clone();
    let count = Rc::new(Cell::new(0u32));
    let eng1 = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::AfterRestoreCall {
            let calls = os.setter_calls();
            if calls.last().map(|c| c.family == Family::Ipv4 && c.image.name_server == V4_ORIG).unwrap_or(false) {
                let n = count.get() + 1;
                count.set(n);
                if n >= 2 {
                    os.clear_failures();
                }
            }
        }
    }));
    let rep = eng1.restore().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
    assert_eq!(v4_restore_calls(&w.os), 3, "three foreground attempts");
    assert_eq!(w.clock.now_ms(), START_MS + 1250, "250 ms then 1 s delays");
    assert_request_ids_unique(&w.os);
}

#[test]
fn foreground_budgets() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.fail_setter_for(GUID_A, Family::Ipv4, 1231, false);
    let clock = w.clock.clone();
    let os = w.os.clone();
    let fired = Rc::new(Cell::new(false));
    let eng1 = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::AfterRestoreCall && !fired.get() {
            let calls = os.setter_calls();
            if calls.last().map(|c| c.family == Family::Ipv4 && c.image.name_server == V4_ORIG).unwrap_or(false) {
                fired.set(true);
                clock.advance_ms(11_000);
            }
        }
    }));
    let rep = eng1.restore().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    let e4 = entry_for(&eng1, GUID_A, Family::Ipv4);
    assert_eq!(e4.state, EntryState::Failed);
    assert_eq!(e4.retry.attempts, 1, "10 s per-family budget cuts retries");
    assert_eq!(v4_restore_calls(&w.os), 1);
    assert_eq!(w.clock.now_ms(), START_MS + 11_000);
}

#[test]
fn no_retry_access_denied() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.fail_setter_for(GUID_A, Family::Ipv4, ERROR_ACCESS_DENIED, false);
    let eng1 = w.engine();
    let rep = eng1.restore().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    let e4 = entry_for(&eng1, GUID_A, Family::Ipv4);
    assert_eq!(e4.retry.attempts, 1, "access denied is not an automatic write retry");
    assert_eq!(e4.state, EntryState::Failed);
    assert_eq!(v4_restore_calls(&w.os), 1);
}

#[test]
fn foreign_divergence_conflict() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (_o4, o6) = originals(&w.os, GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.set_configured(GUID_A, Family::Ipv4, "203.0.113.99", vec![]);
    let eng1 = w.engine();
    let rep = eng1.restore().unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    assert_eq!(entry_for(&eng1, GUID_A, Family::Ipv4).state, EntryState::Conflict);
    assert_eq!(v4_restore_calls(&w.os), 0, "foreign state is never overwritten");
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    assert_eq!(w.os.readback(GUID_A, Family::Ipv4).unwrap().name_server_raw, Some("203.0.113.99".to_string()));
}

#[test]
fn background_schedule() {
    assert_eq!(background_delay_ms(0), 5_000);
    assert_eq!(background_delay_ms(1), 5_000);
    assert_eq!(background_delay_ms(2), 30_000);
    assert_eq!(background_delay_ms(3), 300_000);
    assert_eq!(background_delay_ms(4), 900_000);
    assert_eq!(background_delay_ms(99), 900_000);

    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.fail_setter_for(GUID_A, Family::Ipv4, 1231, false);
    let rep = eng.restore().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    let e4 = entry_for(&eng, GUID_A, Family::Ipv4);
    assert_eq!(e4.retry.attempts, 3);
    assert_eq!(e4.retry.next_attempt_utc, Some(utc_string(START_MS + 1250 + 300_000)));
    let calls_after_foreground = w.os.setter_call_count();

    let rep = eng.run_background_pass().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending, "not due: no mutation");
    assert_eq!(w.os.setter_call_count(), calls_after_foreground);

    w.clock.advance_ms(1_000_000);
    w.os.clear_failures();
    let rep = eng.run_background_pass().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
    assert_eq!(v4_restore_calls(&w.os), 4, "3 foreground + 1 background");
    assert_request_ids_unique(&w.os);
}

#[test]
fn final_verification_race_takeover() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let os = w.os.clone();
    let fired = Rc::new(Cell::new(false));
    let eng = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::AppliedMarkerFlushed && !fired.get() {
            fired.set(true);
            os.set_configured(GUID_A, Family::Ipv4, V4_ORIG, vec![]);
        }
    }));
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(rep.errors.iter().any(|e| e.family == Family::Ipv4 && e.phase == "final-verify"));
    assert_original(&w.os, GUID_A, &o4, &o6);
}

#[test]
fn final_verification_race_restore() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (_o4, o6) = originals(&w.os, GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    let os = w.os.clone();
    let fired = Rc::new(Cell::new(false));
    let eng1 = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::RestoredMarkerFlushed && !fired.get() {
            fired.set(true);
            os.set_configured(GUID_A, Family::Ipv4, "1.1.1.1,1.0.0.1", cf_props());
        }
    }));
    let rep = eng1.restore().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending, "final verification race retains debt");
    assert_eq!(w.os.readback(GUID_A, Family::Ipv4).unwrap().name_server_raw, Some("1.1.1.1,1.0.0.1".to_string()));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    assert_eq!(eng1.current_envelope().unwrap().payload.journal_state, JournalState::RecoveryPending);
}

#[test]
fn pending_retention_blocks_takeover() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.fail_setter_for(GUID_A, Family::Ipv4, ERROR_ACCESS_DENIED, false);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::Pending);
    assert_eq!(eng.current_envelope().unwrap().payload.journal_state, JournalState::RecoveryPending);
    let calls = w.os.setter_call_count();
    assert!(matches!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Google)), Ok(r) if r.outcome == Outcome::Busy));
    assert!(matches!(eng.takeover(&[GUID_B.to_string()], &plan_provider(Provider::Google)), Ok(r) if r.outcome == Outcome::Busy));
    assert_eq!(w.os.setter_call_count(), calls, "unresolved debt blocks new takeover writes");
    w.clock.advance_ms(5_000);
    w.os.clear_failures();
    assert_eq!(eng.run_background_pass().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
}

#[test]
fn persistence_failure_forbids_mutation() {
    let w = World::new();
    w.static_adapter(GUID_A);
    w.fs.inject_once(FaultPoint::VolumeFlush, Fault::Error(FsError::DiskFull));
    let eng = w.engine();
    let res = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare));
    assert!(matches!(res, Err(EngineError::Store(_))), "persistence failure aborts takeover");
    assert_eq!(w.os.setter_call_count(), 0, "no mutation after a failed durable commit");
    assert!(eng.store().admission_closed(), "persistence failure closes admission");

    let mut env = Envelope {
        format: journal::JOURNAL_FORMAT.to_string(),
        version: journal::JOURNAL_VERSION,
        machine_id: MACHINE.to_string(),
        generation: 1,
        previous_digest: None,
        payload_digest: String::new(),
        payload: Payload {
            journal_state: JournalState::Clean,
            transaction: None,
            last_completed: None,
            maintenance: None,
            diagnostics: Vec::new(),
        },
    };
    codec::seal(&mut env);
    assert!(matches!(eng.store().commit(&env), Err(StoreError::ReconciliationRequired)),
        "subsequent mutation forbidden until reconciliation");
    eng.store().reconcile().expect("reconciliation reopens admission");
    assert!(!eng.store().admission_closed());
}

#[test]
fn missing_adapter_deferred() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    w.os.remove_adapter(GUID_A);
    let eng1 = w.engine();
    let rep = eng1.restore().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    let e4 = entry_for(&eng1, GUID_A, Family::Ipv4);
    assert_eq!(e4.state, EntryState::Deferred);
    assert!(e4.retry.next_attempt_utc.is_some());
    assert_eq!(w.os.setter_call_count(), 2, "readback failure defers without writing");
}

#[test]
fn partial_image_classification() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) = originals(&w.os, GUID_A);
    let eng0 = w.engine();
    assert_eq!(eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    // ns facet from target, property facet from before: a recognized partial image.
    w.os.set_configured(GUID_A, Family::Ipv4, "1.1.1.1,1.0.0.1", vec![]);
    let eng1 = w.engine();
    assert_eq!(eng1.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert_original(&w.os, GUID_A, &o4, &o6);
}

#[test]
fn unsupported_family_no_mutation() {
    let w = World::new();
    w.os.add_adapter(GUID_A, "Ethernet");
    w.os.set_configured(GUID_A, Family::Ipv4, V4_ORIG, vec![]);
    w.os.probe().set(GUID_A, Family::Ipv6, false);
    let o4 = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    let v6_before = w.os.configured(GUID_A, Family::Ipv6);
    let eng = w.engine();
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::Active);
    assert_eq!(entries(&eng).len(), 1);
    assert!(entries(&eng).iter().all(|e| e.family == Family::Ipv4));
    assert!(w.os.setter_calls().iter().all(|c| c.family == Family::Ipv4));
    assert_eq!(w.os.configured(GUID_A, Family::Ipv6).0, v6_before.0, "unsupported family untouched");
    assert_eq!(eng.restore().unwrap().outcome, Outcome::VerifiedRestored);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert_eq!(w.os.configured(GUID_A, Family::Ipv6).0, v6_before.0);
}

#[test]
fn epoch_and_admission() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    let env = eng.current_envelope().unwrap();
    assert_eq!(env.payload.journal_state, JournalState::Owned);
    let tx = env.payload.transaction.unwrap();
    assert_eq!(tx.epoch, 1);
    assert_eq!(tx.admission, Admission::Open);
    assert_eq!(tx.phase, Phase::Active);
    let gen_active = eng.current_generation();

    w.os.fail_setter_for(GUID_A, Family::Ipv4, ERROR_ACCESS_DENIED, false);
    assert_eq!(eng.restore().unwrap().outcome, Outcome::Pending);
    let env = eng.current_envelope().unwrap();
    assert_eq!(env.payload.journal_state, JournalState::RecoveryPending);
    let tx = env.payload.transaction.unwrap();
    assert_eq!(tx.epoch, 2, "restore bumps the epoch");
    assert_eq!(tx.admission, Admission::Closed);
    assert_eq!(tx.phase, Phase::Pending);
    assert!(eng.current_generation() > gen_active);

    w.clock.advance_ms(5_000);
    w.os.clear_failures();
    assert_eq!(eng.run_background_pass().unwrap().outcome, Outcome::VerifiedRestored);
    let env = eng.current_envelope().unwrap();
    assert!(env.is_clean_tombstone());
    assert_eq!(env.payload.journal_state, JournalState::Clean);
    assert!(env.payload.transaction.is_none());
    assert!(env.payload.last_completed.is_some());
}

#[test]
fn journal_state_transitions() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome, Outcome::Active);
    let env = eng.current_envelope().unwrap();
    assert_eq!(env.payload.journal_state, JournalState::Owned);
    assert_eq!(env.payload.transaction.unwrap().phase, Phase::Active);

    let eng1 = w.engine().with_hook(Rc::new(|p| {
        if p == DeathPoint::RestoreEpochFlushed {
            panic!("U03 death at restore epoch");
        }
    }));
    assert!(catch_unwind(AssertUnwindSafe(|| eng1.restore())).is_err());
    let env = eng1.current_envelope().unwrap();
    assert_eq!(env.payload.journal_state, JournalState::Restoring);
    let tx = env.payload.transaction.unwrap();
    assert_eq!(tx.phase, Phase::Restoring);
    assert_eq!(tx.epoch, 2);

    let eng2 = recover(&w).with_hook(Rc::new(|p| {
        if p == DeathPoint::CompleteMarkerFlushed {
            panic!("U03 death at complete marker");
        }
    }));
    assert!(catch_unwind(AssertUnwindSafe(|| eng2.restore())).is_err());
    let env = eng2.current_envelope().unwrap();
    assert_eq!(env.payload.journal_state, JournalState::Restoring);
    assert_eq!(env.payload.transaction.unwrap().phase, Phase::Complete);

    let eng3 = recover(&w);
    assert_eq!(eng3.restore().unwrap().outcome, Outcome::VerifiedRestored);
    let env = eng3.current_envelope().unwrap();
    assert!(env.is_clean_tombstone());
    assert_eq!(env.payload.journal_state, JournalState::Clean);
}

#[test]
fn external_edit_before_first_write_conflict() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let os = w.os.clone();
    let eng = w.engine().with_hook(Rc::new(move |p| {
        if p == DeathPoint::TransactionCommitted {
            os.set_configured(GUID_A, Family::Ipv4, "203.0.113.99", vec![]);
        }
    }));
    let rep = eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    assert_eq!(w.os.setter_call_count(), 0, "conflict before the first write");
    assert!(rep.errors.iter().any(|e| e.family == Family::Ipv4 && e.phase == "apply-before"));
    assert_eq!(entry_for(&eng, GUID_A, Family::Ipv4).state, EntryState::Conflict);
    assert_eq!(w.os.readback(GUID_A, Family::Ipv4).unwrap().name_server_raw, Some("203.0.113.99".to_string()));
}
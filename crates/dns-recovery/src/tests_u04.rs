//! U04 concrete tests (SPEC-DNS-FIX.md §12): startup replay, owner identity,
//! §5.4 classification, conflict handling and the deferred scheduler.
//! Library only — every mutation targets FakeOs, never a live adapter, and no
//! production wiring is touched.

use crate::backend::{DnsBackend, RawProperty};
use crate::clock::VirtualClock;
use crate::codec;
use crate::fake::{doh_prop, FakeOs};
use crate::fs::{join, FakeFs};
use crate::journal::{
    self, EntryState, Envelope, JournalState, OwnerIdentity, Phase, Tombstone, Transaction,
    BACKUP_PREFIX, PRIMARY_FILE, STAGE_PREFIX,
};
use crate::lock::FakeLock;
use crate::model::{Family, Provenance, Provider, ServerProperty, Snapshot};
use crate::replay::{FakeOwnerProbe, OwnerLiveness, OwnerProbe, ReplayDriver};
use crate::lock::{LockError, MachineLock, LOCK_BUDGET};
use crate::setter::{DOH_ENABLE, DOH_FALLBACK_TO_UDP, ERROR_ACCESS_DENIED};
use crate::store::{tombstone_envelope, JournalStore};
use crate::transaction::{DeathPoint, Outcome, TransactionEngine};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

const DIR: &str = "C:\\ProgramData\\Yeager";
const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d";
const GUID_A: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
const GUID_B: &str = "7430a27b-1b15-4d8c-b7b6-96a803b09bb1";
const GUID_C: &str = "8541b38c-2c26-5e9d-c8c7-a7b914c10cc2";
const SERVICE: &str = "44444444-4444-4444-8444-444444444444";
const START_MS: i64 = 1_763_000_000_000;
const V4_ORIG: &str = "192.0.2.53";
const V6_ORIG: &str = "2001:db8::53";
const GOOGLE_TEMPLATE: &str = "https://dns.google/dns-query";
const CF_TEMPLATE: &str = "https://cloudflare-dns.com/dns-query";
const FILETIME: u64 = 133_000_000_000_000_000;
const OTHER_FILETIME: u64 = 133_000_000_111_111_111;

fn owner() -> OwnerIdentity {
    OwnerIdentity {
        owner_id: "33333333-3333-4333-8333-333333333333".to_string(),
        pid: 4242,
        creation_time_filetime: FILETIME,
        user_sid: "S-1-5-18".to_string(),
        logon_luid: 999,
        session_id: 0,
        image_path: "C:\\Program Files\\Yeager\\yeager.exe".to_string(),
        image_file_id: "fileid-1".to_string(),
        image_sha256: "a".repeat(64),
    }
}

fn plan_provider(provider: Provider) -> crate::model::DesiredPlan {
    crate::model::DesiredPlan {
        provider,
        local_requested: false,
        bound_endpoints: Vec::new(),
        readiness_generation: 1,
    }
}

fn google_props() -> Vec<RawProperty> {
    vec![
        doh_prop(0, Some(GOOGLE_TEMPLATE), DOH_ENABLE),
        doh_prop(1, Some(GOOGLE_TEMPLATE), DOH_ENABLE),
    ]
}

struct World {
    os: FakeOs,
    fs: Rc<FakeFs>,
    lock: FakeLock,
    clock: VirtualClock,
    probe: FakeOwnerProbe,
}

impl World {
    fn new() -> Self {
        Self {
            os: FakeOs::new(),
            fs: Rc::new(FakeFs::new()),
            lock: FakeLock::new(),
            clock: VirtualClock::new(START_MS),
            probe: FakeOwnerProbe::new(),
        }
    }

    fn engine(&self) -> TransactionEngine<Rc<FakeFs>> {
        self.engine_as(owner())
    }

    fn engine_as(&self, owner: OwnerIdentity) -> TransactionEngine<Rc<FakeFs>> {
        let store = JournalStore::open(Rc::clone(&self.fs), DIR).expect("open journal store");
        TransactionEngine::new(
            Box::new(self.os.clone()),
            Box::new(self.os.clone()),
            store,
            Box::new(self.lock.peer(owner.pid, owner.session_id)),
            Box::new(self.clock.clone()),
            MACHINE.to_string(),
            owner,
            SERVICE.to_string(),
        )
    }

    /// Fresh driver incarnation: the probe state must be programmed BEFORE
    /// this call (the driver snapshots it, like a process reading the table
    /// once at startup).
    fn driver(&self) -> ReplayDriver<Rc<FakeFs>> {
        let os_b = self.os.clone();
        let os_s = self.os.clone();
        let lock = self.lock.peer(9000, 0);
        let clock = self.clock.clone();
        let fs = Rc::clone(&self.fs);
        let probe = self.probe.clone();
        ReplayDriver::new(
            Box::new(move || Box::new(os_b.clone()) as Box<dyn DnsBackend>),
            Box::new(move || Box::new(os_s.clone()) as Box<dyn crate::setter::DnsSetter>),
            Box::new(move || Box::new(lock.peer(9000, 0)) as Box<dyn crate::lock::MachineLock>),
            Box::new(move || Box::new(clock.clone()) as Box<dyn crate::clock::Clock>),
            Box::new(move || Rc::clone(&fs)),
            DIR.to_string(),
            MACHINE.to_string(),
            SERVICE.to_string(),
            Box::new(probe),
        )
    }

    fn static_adapter(&self, guid: &str) {
        self.os.add_adapter(guid, "Ethernet");
        self.os.set_configured(guid, Family::Ipv4, V4_ORIG, vec![]);
        self.os.set_configured(guid, Family::Ipv6, V6_ORIG, vec![]);
    }
}

/// Crash the holder (handles + abandoned lock), modelling process death.
fn recover(w: &World) {
    w.fs.close_all_handles();
    w.lock.simulate_holder_death();
}

fn journal_env(w: &World) -> Option<Envelope> {
    let store = JournalStore::open(Rc::clone(&w.fs), DIR).expect("open journal store");
    store.reconcile().expect("reconcile").current.map(|c| c.env)
}

fn journal_tx(w: &World) -> Option<Transaction> {
    journal_env(w).and_then(|e| e.payload.transaction)
}

fn generation_of(w: &World) -> u64 {
    journal_env(w).map(|e| e.generation).unwrap_or(0)
}

fn primary_bytes(w: &World) -> Option<Vec<u8>> {
    w.fs.file_bytes(&join(DIR, PRIMARY_FILE))
}

fn state_of(w: &World, guid: &str, family: Family) -> EntryState {
    journal_tx(w)
        .expect("transaction")
        .entries
        .into_iter()
        .find(|e| e.adapter_guid == guid && e.family == family)
        .expect("entry")
        .state
}

fn snapshot_of(w: &World, guid: &str, family: Family, which: &str) -> Snapshot {
    let e = journal_tx(w)
        .expect("transaction")
        .entries
        .into_iter()
        .find(|e| e.adapter_guid == guid && e.family == family)
        .expect("entry");
    match which {
        "original" => e.original,
        "intended" => e.intended.expect("intended image"),
        "previous" => e.previous_committed.expect("previous_committed image"),
        _ => panic!("unknown image selector"),
    }
}

/// Fixture input: force the OS state to a journaled image (models an
/// administrator edit, a reverted list, or an arrived adapter).
fn apply_snapshot(os: &FakeOs, guid: &str, family: Family, snap: &Snapshot) {
    let props = snap
        .server_properties
        .iter()
        .map(|p| RawProperty {
            version: p.version,
            server_index: p.server_index,
            prop_type: p.prop_type,
            template: p.doh.template.clone(),
            flags: p.doh.flags,
        })
        .collect();
    os.set_configured(guid, family, snap.name_server_raw.as_deref().unwrap_or(""), props);
}

/// Immutable originals captured BEFORE a replay pass (a successful replay
/// writes the durable clean tombstone, so the transaction is gone after).
fn journal_originals(w: &World) -> HashMap<(String, Family), (String, Vec<ServerProperty>)> {
    let tx = journal_tx(w).expect("transaction");
    let mut originals = HashMap::new();
    for e in &tx.entries {
        originals.insert(
            (e.adapter_guid.clone(), e.family),
            (
                e.original.name_server_raw.clone().unwrap_or_default(),
                e.original.server_properties.clone(),
            ),
        );
    }
    originals
}

/// Every setter call issued from `calls_before` on must target a journaled
/// immutable original: replay never invents a write (in particular never the
/// old heuristic public-provider reset).
fn assert_only_original_writes(
    w: &World,
    calls_before: usize,
    originals: &HashMap<(String, Family), (String, Vec<ServerProperty>)>,
) {
    for c in w.os.setter_calls().iter().skip(calls_before) {
        let key = (c.guid.clone(), c.family);
        let (ns, props) =
            originals.get(&key).unwrap_or_else(|| panic!("replay wrote non-journaled target {} {:?}", c.guid, c.family));
        assert_eq!(&c.image.name_server, ns, "replay wrote a non-original server list");
        assert_eq!(&c.image.properties, props, "replay wrote non-original DoH properties");
    }
}

fn assert_request_ids_unique(os: &FakeOs) {
    for c in os.setter_calls() {
        assert_eq!(os.calls_for_request(&c.request_id), 1, "request id reused: {}", c.request_id);
    }
}

// ---- 1. owner identity -----------------------------------------------------

#[test]
fn owner_probe_same_pid_different_filetime_is_dead() {
    let probe = FakeOwnerProbe::new();
    let o = owner();
    // Live table holds the same PID under a DIFFERENT creation time: PID
    // reuse, so the recorded owner is dead.
    probe.spawn(o.pid, OTHER_FILETIME);
    assert_eq!(probe.check(&o), OwnerLiveness::Dead);
    // Missing PID (never alive, or reaped) also proves death.
    probe.kill(o.pid);
    assert_eq!(probe.check(&o), OwnerLiveness::Dead);
    // Matching PID + FILETIME is live.
    probe.spawn(o.pid, FILETIME);
    assert_eq!(probe.check(&o), OwnerLiveness::Live);
}

#[test]
fn live_owner_replay_leaves_everything_untouched() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let generation = generation_of(&w);
    let bytes_before = primary_bytes(&w);
    let calls_before = w.os.setter_call_count();
    // The owner is still alive: replay must not write anything.
    w.probe.spawn(4242, FILETIME);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Busy);
    assert_eq!(rep.liveness, Some(OwnerLiveness::Live));
    assert_eq!(generation_of(&w), generation, "journal generation must not advance");
    assert_eq!(primary_bytes(&w), bytes_before, "journal bytes must be untouched");
    assert_eq!(w.os.setter_call_count(), calls_before, "no DNS write under a live owner");
    // The live Yeager configuration is still in place.
    let current = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    let intended = snapshot_of(&w, GUID_A, Family::Ipv4, "intended");
    assert!(current.configured_eq(&intended));
}

#[test]
fn access_denied_owner_refuses_without_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let generation = generation_of(&w);
    let bytes_before = primary_bytes(&w);
    let calls_before = w.os.setter_call_count();
    w.probe.set_access_denied(4242, true);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Refused);
    assert!(matches!(rep.liveness, Some(OwnerLiveness::Unknown(_))));
    assert_eq!(generation_of(&w), generation);
    assert_eq!(primary_bytes(&w), bytes_before);
    assert_eq!(w.os.setter_call_count(), calls_before);
}

#[test]
fn query_failure_owner_refuses_without_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let generation = generation_of(&w);
    let calls_before = w.os.setter_call_count();
    w.probe.set_query_failure(4242, true);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Refused);
    assert!(matches!(rep.liveness, Some(OwnerLiveness::Unknown(_))));
    assert_eq!(generation_of(&w), generation);
    assert_eq!(w.os.setter_call_count(), calls_before);
}

#[test]
fn live_cross_session_owner_is_protected() {
    let w = World::new();
    w.static_adapter(GUID_A);
    // The owner runs in session 1; liveness is machine-wide, so a replay
    // driven from session 0 must still stand down.
    let mut remote = owner();
    remote.session_id = 1;
    let eng = w.engine_as(remote);
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let generation = generation_of(&w);
    let calls_before = w.os.setter_call_count();
    w.probe.spawn(4242, FILETIME);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Busy);
    assert_eq!(rep.liveness, Some(OwnerLiveness::Live));
    assert_eq!(generation_of(&w), generation);
    assert_eq!(w.os.setter_call_count(), calls_before);
}

// ---- 2. classification ------------------------------------------------------

#[test]
fn current_original_verifies_without_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let (o4, o6) = (snapshot_of(&w, GUID_A, Family::Ipv4, "original"), snapshot_of(&w, GUID_A, Family::Ipv6, "original"));
    // The administrator reverted both families to the journaled originals.
    apply_snapshot(&w.os, GUID_A, Family::Ipv4, &o4);
    apply_snapshot(&w.os, GUID_A, Family::Ipv6, &o6);
    recover(&w);
    let calls_before = w.os.setter_call_count();
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_eq!(rep.liveness, Some(OwnerLiveness::Dead));
    assert_eq!(w.os.setter_call_count(), calls_before, "original match verifies without a call");
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    assert!(journal_tx(&w).is_none(), "durable clean tombstone, no transaction");
}

#[test]
fn previous_committed_image_restores_original() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    assert_eq!(
        eng.reconfigure(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap().outcome,
        Outcome::Active
    );
    // Current == the previous committed (Cloudflare) image, not the latest.
    let (p4, p6) = (snapshot_of(&w, GUID_A, Family::Ipv4, "previous"), snapshot_of(&w, GUID_A, Family::Ipv6, "previous"));
    apply_snapshot(&w.os, GUID_A, Family::Ipv4, &p4);
    apply_snapshot(&w.os, GUID_A, Family::Ipv6, &p6);
    recover(&w);
    let calls_before = w.os.setter_call_count();
    let originals = journal_originals(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_only_original_writes(&w, calls_before, &originals);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    assert_request_ids_unique(&w.os);
}

#[test]
fn new_intent_only_settles_by_readback_without_recall() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    // The setter applies the change, then the process dies before readback:
    // a durable intent with current == target, never re-called.
    w.os.die_after_change();
    let eng1 = w.engine();
    let res = catch_unwind(AssertUnwindSafe(|| {
        eng1.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare))
    }));
    assert!(res.is_err(), "takeover must die after the change lands");
    recover(&w);
    let env = eng1.current_envelope().expect("durable intent survives death");
    let tx = env.payload.transaction.expect("transaction");
    assert!(tx.entries.iter().any(|e| e.operations.iter().any(|op| op.state == crate::journal::OperationState::Intent)));
    let originals = journal_originals(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_only_original_writes(&w, 1, &originals);
    assert_request_ids_unique(&w.os);
    assert_eq!(w.os.setter_call_count(), 2, "one intent call + one restore call, never a duplicate");
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
}

#[test]
fn older_unresolved_intent_restores_original() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng0 = w.engine();
    assert_eq!(
        eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Death after the restore intent is flushed but before the call: current
    // still equals the OLDER apply target while a newer intent is pending.
    let eng1 = w.engine().with_hook(Rc::new(|p| {
        if p == DeathPoint::RestoreIntentFlushed {
            panic!("U04 death at restore intent");
        }
    }));
    let res = catch_unwind(AssertUnwindSafe(|| eng1.restore()));
    assert!(res.is_err());
    recover(&w);
    let calls_before = w.os.setter_call_count();
    let originals = journal_originals(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_only_original_writes(&w, calls_before, &originals);
    assert_request_ids_unique(&w.os);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
}

#[test]
fn qualified_partial_image_restores_original() {
    let w = World::new();
    // Pristine automatic originals on both families.
    w.os.add_adapter(GUID_A, "Ethernet");
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Qualified partial: the target server list with the before (empty)
    // properties. Indices stay valid, provenance stays consistent.
    w.os.set_configured(GUID_A, Family::Ipv4, "1.1.1.1,1.0.0.1", vec![]);
    w.os.set_configured(GUID_A, Family::Ipv6, "2606:4700:4700::1111,2606:4700:4700::1001", vec![]);
    recover(&w);
    let calls_before = w.os.setter_call_count();
    let originals = journal_originals(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_only_original_writes(&w, calls_before, &originals);
    for family in [Family::Ipv4, Family::Ipv6] {
        let restored = w.os.readback(GUID_A, family).unwrap();
        assert_eq!(restored.provenance, Provenance::Automatic);
        assert!(restored.ordered_servers.is_empty());
        assert!(restored.server_properties.is_empty());
    }
}

#[test]
fn foreign_static_list_is_conflict_without_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Foreign static list on v4 (never journaled); v6 still owned.
    w.os.set_configured(GUID_A, Family::Ipv4, "9.9.9.9", vec![]);
    recover(&w);
    let v4_calls_before = w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count();
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    assert_eq!(
        w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count(),
        v4_calls_before,
        "foreign v4 gets no write"
    );
    let kept = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    assert_eq!(kept.ordered_servers.len(), 1);
    assert_eq!(kept.name_server_raw.as_deref(), Some("9.9.9.9"));
    // The owned sibling still restores; the journal is retained (no tombstone).
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    assert_eq!(state_of(&w, GUID_A, Family::Ipv4), EntryState::Conflict);
    let tx = journal_tx(&w).expect("journal retained");
    assert!(tx.entries.iter().any(|e| e.original_fingerprint == o4.fingerprint()));
}

#[test]
fn changed_doh_template_is_conflict_without_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Same server list as the journaled image, but a foreign DoH template:
    // not equal to any known image and not a qualified partial.
    w.os.set_configured(GUID_A, Family::Ipv4, "1.1.1.1,1.0.0.1", google_props());
    recover(&w);
    let v4_calls_before = w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count();
    let calls_before = w.os.setter_call_count();
    let originals = journal_originals(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    assert_eq!(
        w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count(),
        v4_calls_before,
        "foreign template gets no write"
    );
    assert_only_original_writes(&w, calls_before, &originals);
    let kept = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    assert_eq!(kept.server_properties[0].doh.template.as_deref(), Some(GOOGLE_TEMPLATE));
    assert_eq!(state_of(&w, GUID_A, Family::Ipv4), EntryState::Conflict);
}

#[test]
fn changed_doh_flags_is_conflict_without_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Same server list and same template as the journaled image, but foreign
    // DoH flags: not equal to any known image and not a qualified partial, so
    // the classifier must still report Conflict (a flags-blind classifier
    // would wrongly verify without a write).
    let flags_only = vec![
        doh_prop(0, Some(CF_TEMPLATE), DOH_ENABLE | DOH_FALLBACK_TO_UDP),
        doh_prop(1, Some(CF_TEMPLATE), DOH_ENABLE | DOH_FALLBACK_TO_UDP),
    ];
    w.os.set_configured(GUID_A, Family::Ipv4, "1.1.1.1,1.0.0.1", flags_only);
    recover(&w);
    let v4_calls_before = w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count();
    let calls_before = w.os.setter_call_count();
    let originals = journal_originals(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    assert_eq!(
        w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count(),
        v4_calls_before,
        "foreign flags get no write"
    );
    assert_only_original_writes(&w, calls_before, &originals);
    let kept = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    assert_eq!(kept.server_properties[0].doh.template.as_deref(), Some(CF_TEMPLATE));
    assert_eq!(
        kept.server_properties[0].doh.flags,
        DOH_ENABLE | DOH_FALLBACK_TO_UDP,
        "edited flags stay on the adapter"
    );
    assert_eq!(state_of(&w, GUID_A, Family::Ipv4), EntryState::Conflict);
}

// ---- 3. administrator edits and unrelated context ---------------------------

#[test]
fn admin_family_edit_preserved_sibling_restored_journal_retained() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let o6 = w.os.readback(GUID_A, Family::Ipv6).unwrap();
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // The administrator takes over v4 with a static edit while v6 stays ours.
    w.os.set_configured(GUID_A, Family::Ipv4, "9.9.9.9", vec![]);
    recover(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    assert!(!rep.errors.is_empty());
    // v4 preserved exactly; v6 restored to the original.
    let kept = w.os.readback(GUID_A, Family::Ipv4).unwrap();
    assert_eq!(kept.name_server_raw.as_deref(), Some("9.9.9.9"));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    // Journal retained as recovery-pending debt: no tombstone, both entries
    // and the originals intact.
    let env = journal_env(&w).expect("journal retained");
    assert_eq!(env.payload.journal_state, JournalState::RecoveryPending);
    let tx = env.payload.transaction.expect("transaction retained");
    assert_eq!(tx.phase, Phase::Pending);
    assert_eq!(tx.entries.len(), 2);
    assert!(env.payload.last_completed.is_none());
    assert!(w.driver().journal_phase().is_some());
}

#[test]
fn unrelated_suffix_edit_does_not_block_restore() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Unrelated context edits (search/suffix/registration/profile-adjacent
    // fields the DNS writer never restores) on the owned images.
    for family in [Family::Ipv4, Family::Ipv6] {
        w.os.update_raw(GUID_A, family, |raw| {
            raw.domain = Some("admin.example".to_string());
            raw.search_list = Some("admin.example".to_string());
            raw.registration_enabled = 1;
        });
    }
    recover(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    // The unrelated edits remain: only NameServer/ServerProperties move.
    for family in [Family::Ipv4, Family::Ipv6] {
        let restored = w.os.readback(GUID_A, family).unwrap();
        assert_eq!(restored.context.domain.as_deref(), Some("admin.example"));
    }
}

// ---- 4. disconnected adapters, arrival and no age-out ----------------------

#[test]
fn disconnected_but_configurable_restores_now() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Link down, but the adapter stays enumerated and configurable.
    w.os.set_disconnected(GUID_A, true);
    recover(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    assert!(w.os.is_disconnected(GUID_A), "link state is orthogonal and untouched");
}

#[test]
fn missing_guid_deferred_then_arrival_restores() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let (i4, i6) = (snapshot_of(&w, GUID_A, Family::Ipv4, "intended"), snapshot_of(&w, GUID_A, Family::Ipv6, "intended"));
    // The adapter vanishes before shutdown: both families defer.
    w.os.remove_adapter(GUID_A);
    recover(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    assert_eq!(state_of(&w, GUID_A, Family::Ipv4), EntryState::Deferred);
    assert_eq!(state_of(&w, GUID_A, Family::Ipv6), EntryState::Deferred);
    assert!(w.driver().next_wake_ms().is_some(), "debt carries a persisted schedule");
    // The same GUID returns (still at the Yeager image): arrival retries now
    // instead of waiting for the schedule.
    w.os.add_adapter(GUID_A, "Ethernet");
    apply_snapshot(&w.os, GUID_A, Family::Ipv4, &i4);
    apply_snapshot(&w.os, GUID_A, Family::Ipv6, &i6);
    let rep = w.driver().notify_arrival(&[GUID_A.to_string()]).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    assert!(w.driver().next_wake_ms().is_none(), "no debt left behind");
}

#[test]
fn new_guid_same_name_index_gets_no_old_settings() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    w.os.remove_adapter(GUID_A);
    recover(&w);
    assert_eq!(w.driver().replay().unwrap().outcome, Outcome::Pending);
    // A NEW adapter arrives reusing the name/index hints: identity is GUID
    // only, so it must never inherit the old adapter's settings.
    w.os.add_adapter(GUID_B, "Ethernet");
    let rep = w.driver().notify_arrival(&[GUID_B.to_string()]).unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    let fresh = w.os.readback(GUID_B, Family::Ipv4).unwrap();
    assert_eq!(fresh.provenance, Provenance::Automatic, "new GUID keeps its own state");
    assert!(w.os.setter_calls().iter().all(|c| c.guid != GUID_B), "no write ever targets the new GUID");
    assert!(journal_tx(&w).expect("old debt retained").entries.iter().all(|e| e.adapter_guid == GUID_A));
}

#[test]
fn debt_is_never_aged_out() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    w.os.remove_adapter(GUID_A);
    recover(&w);
    assert_eq!(w.driver().replay().unwrap().outcome, Outcome::Pending);
    // Thirty days pass with no adapter return: the debt is retained, never
    // tombstoned, never trimmed.
    for _ in 0..3 {
        w.clock.advance_ms(30 * 86400 * 1000);
        let rep = w.driver().background_wake().unwrap();
        assert_eq!(rep.outcome, Outcome::Pending);
    }
    let tx = journal_tx(&w).expect("debt retained after 90 days");
    assert_eq!(tx.entries.len(), 2);
    assert!(tx.entries.iter().all(|e| e.adapter_guid == GUID_A));
    assert!(journal_env(&w).expect("envelope").payload.last_completed.is_none());
    assert_eq!(w.driver().journal_phase(), Some(Phase::Pending));
}

#[test]
fn background_schedule_eventually_restores() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let (i4, i6) = (snapshot_of(&w, GUID_A, Family::Ipv4, "intended"), snapshot_of(&w, GUID_A, Family::Ipv6, "intended"));
    w.os.remove_adapter(GUID_A);
    recover(&w);
    assert_eq!(w.driver().replay().unwrap().outcome, Outcome::Pending);
    let first_wake = w.driver().next_wake_ms().expect("scheduled retry");
    w.clock.set_ms(first_wake + 1);
    // Still missing: the pass keeps the debt and pushes the schedule out.
    assert_eq!(w.driver().background_wake().unwrap().outcome, Outcome::Pending);
    let second_wake = w.driver().next_wake_ms().expect("rescheduled retry");
    assert!(second_wake > first_wake);
    // The adapter returns at the Yeager image; the schedule (not an arrival
    // event) drives the restore.
    w.os.add_adapter(GUID_A, "Ethernet");
    apply_snapshot(&w.os, GUID_A, Family::Ipv4, &i4);
    apply_snapshot(&w.os, GUID_A, Family::Ipv6, &i6);
    w.clock.set_ms(second_wake + 1);
    let rep = w.driver().background_wake().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
}

// ---- 5. pending blocks takeover, tombstone discipline, no heuristics --------

#[test]
fn pending_state_blocks_new_takeover() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    w.os.remove_adapter(GUID_A);
    recover(&w);
    assert_eq!(w.driver().replay().unwrap().outcome, Outcome::Pending);
    // A new owner cannot take over while recovery debt is unresolved.
    let mut newcomer = owner();
    newcomer.owner_id = "55555555-5555-4555-8555-555555555555".to_string();
    newcomer.pid = 9999;
    let generation = generation_of(&w);
    let calls_before = w.os.setter_call_count();
    let rep = w.engine_as(newcomer).takeover(&[GUID_A.to_string()], &plan_provider(Provider::Google)).unwrap();
    assert_eq!(rep.outcome, Outcome::Busy);
    assert_eq!(generation_of(&w), generation);
    assert_eq!(w.os.setter_call_count(), calls_before);
}

#[test]
fn tombstone_only_after_all_original_verification() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    w.os.set_configured(GUID_A, Family::Ipv4, "9.9.9.9", vec![]);
    recover(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    // No tombstone while any family is unresolved: the transaction and its
    // originals stay durable.
    let env = journal_env(&w).expect("journal retained");
    assert_eq!(env.payload.journal_state, JournalState::RecoveryPending);
    assert!(env.payload.last_completed.is_none());
    assert!(env.payload.transaction.is_some());
    // The administrator reverts v4 to the owned image: replay completes with
    // a tombstone naming the finished transaction.
    let txid = env.payload.transaction.as_ref().expect("tx").id.clone();
    let i4 = snapshot_of(&w, GUID_A, Family::Ipv4, "intended");
    apply_snapshot(&w.os, GUID_A, Family::Ipv4, &i4);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    let env = journal_env(&w).expect("tombstone envelope");
    assert!(env.is_clean_tombstone());
    assert_eq!(env.payload.last_completed.expect("tombstone").transaction_id, txid);
}

#[test]
fn replay_needs_no_profile_network_or_ui() {
    // The driver constructor takes only the journal, the OS read/write
    // paths, the lock, the clock, machine identity and the owner probe: no
    // user profile, no network handle, no listener runtime, no UI object.
    // Proof by construction — a bare world recovers a dead-owner journal.
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    recover(&w);
    let driver = w.driver();
    let rep = driver.replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_eq!(rep.liveness, Some(OwnerLiveness::Dead));
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
}

#[test]
fn no_heuristic_public_cleanup_on_unknown_state() {
    let w = World::new();
    // Public DNS that the old heuristic reset would have "cleaned": with no
    // journal the replay must not touch it (no ownership, no baseline).
    w.os.add_adapter(GUID_A, "Ethernet");
    w.os.set_configured(GUID_A, Family::Ipv4, "8.8.8.8,8.8.4.4", vec![]);
    w.os.set_configured(GUID_A, Family::Ipv6, "2001:4860:4860::8888,2001:4860:4860::8844", vec![]);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_eq!(w.os.setter_call_count(), 0, "no journal means no DNS write, ever");
    assert!(primary_bytes(&w).is_none(), "no journal file is created by a clean replay");
    assert_eq!(
        w.os.readback(GUID_A, Family::Ipv4).unwrap().name_server_raw.as_deref(),
        Some("8.8.8.8,8.8.4.4")
    );
}

#[test]
fn unknown_version_blocks_without_mutation() {
    let w = World::new();
    w.static_adapter(GUID_A);
    // A newer journal the reader cannot understand: reported and retained,
    // never deleted, never overwritten, never written through.
    let foreign = Envelope {
        format: journal::JOURNAL_FORMAT.to_string(),
        version: 2,
        machine_id: MACHINE.to_string(),
        generation: 9,
        previous_digest: None,
        payload_digest: String::new(),
        payload: journal::Payload {
            journal_state: JournalState::Clean,
            transaction: None,
            last_completed: None,
            maintenance: None,
            diagnostics: Vec::new(),
        },
    };
    let bytes = codec::encode(&foreign);
    let stage = join(DIR, &format!("{STAGE_PREFIX}9.{}", journal::new_uuid()));
    w.fs.seed_file(&stage, bytes.clone());
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Refused);
    assert_eq!(w.fs.file_bytes(&stage), Some(bytes), "unknown state is retained");
    assert_eq!(w.os.setter_call_count(), 0);
}

#[test]
fn integrity_failure_blocks_without_mutation() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let calls_before = w.os.setter_call_count();
    // Corrupt primary with a valid older backup: integrity failure — the
    // older backup is NOT assumed complete (§3.3), and nothing is written.
    let backup = tombstone_envelope(
        MACHINE,
        1,
        None,
        Tombstone {
            transaction_id: journal::new_uuid(),
            verified_at_utc: "2026-11-13T18:08:29Z".to_string(),
            completed_generation: 1,
        },
    );
    w.fs.seed_file(&join(DIR, PRIMARY_FILE), b"corrupt primary".to_vec());
    w.fs.seed_file(&join(DIR, &format!("{BACKUP_PREFIX}1.{}", journal::new_uuid())), codec::encode(&backup));
    recover(&w);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Refused);
    assert_eq!(w.fs.file_bytes(&join(DIR, PRIMARY_FILE)), Some(b"corrupt primary".to_vec()));
    assert_eq!(w.os.setter_call_count(), calls_before);
}

// ---- cross-checks ------------------------------------------------------------

#[test]
fn conflict_entries_get_fresh_reads_on_arrival() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let o6 = w.os.readback(GUID_A, Family::Ipv6).unwrap();
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    w.os.set_configured(GUID_A, Family::Ipv4, "9.9.9.9", vec![]);
    recover(&w);
    assert_eq!(w.driver().replay().unwrap().outcome, Outcome::Conflict);
    // Arrival re-reads the conflict: still foreign, still preserved, still no
    // write — and the completed sibling stays verified.
    let v4_calls = w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count();
    let rep = w.driver().notify_arrival(&[GUID_A.to_string()]).unwrap();
    assert_eq!(rep.outcome, Outcome::Conflict);
    assert_eq!(
        w.os.setter_calls().iter().filter(|c| c.family == Family::Ipv4).count(),
        v4_calls,
        "arrival never overwrites a conflict"
    );
    assert_eq!(w.os.readback(GUID_A, Family::Ipv4).unwrap().name_server_raw.as_deref(), Some("9.9.9.9"));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
}

#[test]
fn unrelated_guid_arrival_changes_nothing() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    w.os.remove_adapter(GUID_A);
    recover(&w);
    assert_eq!(w.driver().replay().unwrap().outcome, Outcome::Pending);
    let generation = generation_of(&w);
    // Arrival of a GUID the journal never recorded is a no-op.
    let rep = w.driver().notify_arrival(&[GUID_C.to_string()]).unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    assert_eq!(generation_of(&w), generation);
    assert!(journal_tx(&w).expect("debt").entries.iter().all(|e| e.adapter_guid == GUID_A));
}

#[test]
fn access_denied_setter_is_never_retried_as_write() {
    let w = World::new();
    w.static_adapter(GUID_A);
    let eng = w.engine();
    assert_eq!(
        eng.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    recover(&w);
    // The restore write itself is forbidden: the baseline is retained and the
    // failure is reported, never looped as blind rewrites.
    w.os.fail_setter_for(GUID_A, Family::Ipv4, ERROR_ACCESS_DENIED, false);
    let rep = w.driver().replay().unwrap();
    assert_eq!(rep.outcome, Outcome::Pending);
    assert!(rep.errors.iter().any(|e| e.family == Family::Ipv4 && e.windows_status == Some(ERROR_ACCESS_DENIED)));
    let tx = journal_tx(&w).expect("baseline retained");
    let e4 = tx.entries.iter().find(|e| e.family == Family::Ipv4).expect("v4 entry");
    assert_eq!(e4.original.name_server_raw.as_deref(), Some(V4_ORIG));
}

#[test]
fn arrival_complete_keeps_lock_across_tombstone() {
    // Crash window between the Complete marker and the tombstone, re-driven
    // via arrival: the tombstone commit and obsolete cleanup must run with
    // the machine lock held by that arrival pass.
    let w = World::new();
    w.static_adapter(GUID_A);
    let (o4, o6) =
        (w.os.readback(GUID_A, Family::Ipv4).unwrap(), w.os.readback(GUID_A, Family::Ipv6).unwrap());
    let eng0 = w.engine();
    assert_eq!(
        eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    // Die after the Complete marker is flushed but before the tombstone.
    let eng1 = w.engine().with_hook(Rc::new(|p| {
        if p == DeathPoint::CompleteMarkerFlushed {
            panic!("U04b death at complete marker");
        }
    }));
    let res = catch_unwind(AssertUnwindSafe(|| eng1.restore()));
    assert!(res.is_err(), "restore must die at the complete marker");
    recover(&w);
    let tx = journal_tx(&w).expect("Phase::Complete survives the crash");
    assert_eq!(tx.phase, Phase::Complete);
    // Arrival re-drives the Complete branch via the driver: tombstone written.
    let rep = w.driver().notify_arrival(&[GUID_A.to_string()]).unwrap();
    assert_eq!(rep.outcome, Outcome::VerifiedRestored);
    assert_eq!(rep.liveness, Some(OwnerLiveness::Dead));
    assert!(w.os.readback(GUID_A, Family::Ipv4).unwrap().configured_eq(&o4));
    assert!(w.os.readback(GUID_A, Family::Ipv6).unwrap().configured_eq(&o6));
    let env = journal_env(&w).expect("tombstone envelope");
    assert!(env.is_clean_tombstone(), "arrival tombstones under the lock");

    // Same crash window, re-driven via the engine with a hook that observes
    // the lock held across TombstoneFlushed: holder pid is the arrival
    // engine's pid and a second acquire times out until the pass returns.
    let w2 = World::new();
    w2.static_adapter(GUID_A);
    let eng0 = w2.engine();
    assert_eq!(
        eng0.takeover(&[GUID_A.to_string()], &plan_provider(Provider::Cloudflare)).unwrap().outcome,
        Outcome::Active
    );
    let eng1 = w2.engine().with_hook(Rc::new(|p| {
        if p == DeathPoint::CompleteMarkerFlushed {
            panic!("U04b death at complete marker");
        }
    }));
    let res = catch_unwind(AssertUnwindSafe(|| eng1.restore()));
    assert!(res.is_err());
    recover(&w2);
    assert_eq!(journal_tx(&w2).expect("tx").phase, Phase::Complete);
    use std::cell::Cell;
    let saw = Rc::new(Cell::new(false));
    let saw_hook = Rc::clone(&saw);
    let lock_clone = w2.lock.peer(4242, 0);
    let hook = Rc::new(move |p| {
        if p == DeathPoint::TombstoneFlushed {
            assert!(lock_clone.is_held(), "tombstone must commit with lock held");
            assert_eq!(
                lock_clone.holder().expect("holder").pid, 4242,
                "holder pid is the arrival engine's pid"
            );
            let contender = lock_clone.peer(9999, 0);
            assert!(
                matches!(contender.acquire(LOCK_BUDGET), Err(LockError::Timeout)),
                "second acquire times out while arrival pass holds the lock"
            );
            saw_hook.set(true);
        }
    });
    let eng2 = w2.engine().with_hook(hook);
    let rep2 = eng2.run_arrival_pass(&[GUID_A.to_string()]).unwrap();
    assert_eq!(rep2.outcome, Outcome::VerifiedRestored);
    assert!(saw.get(), "TombstoneFlushed hook must run under the lock");
    assert!(!w2.lock.is_held(), "lock released after the pass returns");
    let env2 = journal_env(&w2).expect("tombstone envelope");
    assert!(env2.is_clean_tombstone());
}

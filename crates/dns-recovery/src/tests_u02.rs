//! U02 fake-backed suite: durable replacement, reconciliation, tombstone,
//! lock and codec contracts (SPEC-DNS-FIX.md §3, envelope test list).
//!
//! Library-only: every filesystem interaction goes through FakeFs, every lock
//! through FakeLock, and DNS mutation is modelled by a call-counting fake.
//! Real-Windows volume-flush/ACL evidence lives in examples/u02_fs_evidence.rs
//! and tests/lock_windows.rs.

use crate::codec;
use crate::fs::{
    expected_security, join, FakeFs, Fault, FaultPoint, FsError, JournalFs, ReplaceFailure,
    StorageKind,
};
use crate::journal::{
    self, Admission, BaselineKind, Diagnostic, Envelope, Entry, EntryState, JournalError,
    JournalState, Maintenance, Operation, OperationKind, OperationState, OwnerIdentity, Payload,
    Phase, Reason, RetryState, Tombstone, Transaction, WriteFacet, BACKUP_PREFIX, MAX_DIAGNOSTICS,
    MAX_JOURNAL_BYTES, STAGE_PREFIX,
};
use crate::lock::{Acquired, FakeLock, FakeObjectKind, LockError, MachineLock, LOCK_BUDGET};
use crate::model::{
    BoundEndpoint, CanonicalServer, Capability, DesiredPlan, DnsContext, Family, Provider,
    Provenance, ProvenanceEvidence, Snapshot, Transport,
};
use crate::security::{Ace, ObjectKind, SecurityInfo, FILE_ALL_ACCESS, SID_ADMINISTRATORS};
use crate::store::{self, CandidateKind, CandidateStatus, CommitReport, JournalStore, StoreError};
use std::cell::Cell;

const DIR: &str = "C:\\ProgramData\\Yeager";
const MACHINE: &str = "b7d3a1f2-4c5e-4a6b-8c9d-0e1f2a3b4c5d";
const OTHER_MACHINE: &str = "c9e4b2a3-5d6f-4b7c-9d0e-1f2a3b4c5d6e";
const TX_A: &str = "11111111-1111-4111-8111-111111111111";
const TX_B: &str = "22222222-2222-4222-8222-222222222222";
const GUID: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
const UUID0: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NOW: &str = "2026-11-13T18:08:29Z";

type Store = JournalStore<FakeFs>;

// ---- fixtures ---------------------------------------------------------------

fn snap(family: Family, server: &str) -> Snapshot {
    let automatic = server.is_empty();
    Snapshot {
        schema_version: 1,
        family,
        provenance: if automatic { Provenance::Automatic } else { Provenance::Static },
        name_server_raw: (!automatic).then(|| server.to_string()),
        ordered_servers: if automatic {
            Vec::new()
        } else {
            vec![CanonicalServer::parse(server).unwrap()]
        },
        provenance_evidence: ProvenanceEvidence {
            registry_path: format!(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}\\Parameters\\Interfaces\\{{{GUID}}}",
                family.registry_service()
            ),
            value_exists: !automatic,
            value_type: (!automatic).then_some(1),
            raw_value_base64: None,
            api_flags: 0,
            captured_at_utc: NOW.to_string(),
        },
        server_properties: Vec::new(),
        context: DnsContext::default(),
        capability: Capability {
            os_build: "26300.9974".to_string(),
            reader_revision: 1,
            api_version: 3,
            family_supported: true,
        },
    }
}

fn entry(family: Family, server: &str) -> Entry {
    let original = snap(family, server);
    Entry {
        adapter_guid: GUID.to_string(),
        family,
        name_hint: "Ethernet".to_string(),
        device_instance_hint: None,
        original_if_index: Some(12),
        original_luid: 1,
        first_captured_at_utc: NOW.to_string(),
        original_fingerprint: original.fingerprint(),
        original,
        baseline_kind: BaselineKind::PreTakeover,
        previous_committed: None,
        previous_fingerprint: None,
        intended: None,
        intended_fingerprint: None,
        applied_fingerprint: None,
        plan_revision: 1,
        operations: Vec::new(),
        state: EntryState::Captured,
        last_observed: None,
        retry: RetryState { attempts: 0, next_attempt_utc: None, last_error: None },
        verification: None,
        approved_legacy_target: None,
    }
}

fn plan() -> DesiredPlan {
    DesiredPlan {
        provider: Provider::Auto,
        local_requested: false,
        bound_endpoints: Vec::new(),
        readiness_generation: 0,
    }
}

fn tx(id: &str, server: &str) -> Transaction {
    Transaction {
        id: id.to_string(),
        created_at_utc: NOW.to_string(),
        updated_at_utc: NOW.to_string(),
        reason: Reason::Takeover,
        phase: Phase::Preparing,
        owner: OwnerIdentity {
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
        admission: Admission::Open,
        desired: plan(),
        service_instance_id: "44444444-4444-4444-8444-444444444444".to_string(),
        registered_at_utc: NOW.to_string(),
        entries: vec![entry(Family::Ipv4, server)],
    }
}

fn owned_with(generation: u64, prev: Option<String>, tx_id: &str, server: &str) -> Envelope {
    let mut env = Envelope {
        format: journal::JOURNAL_FORMAT.to_string(),
        version: journal::JOURNAL_VERSION,
        machine_id: MACHINE.to_string(),
        generation,
        previous_digest: prev,
        payload_digest: String::new(),
        payload: Payload {
            journal_state: JournalState::Owned,
            transaction: Some(tx(tx_id, server)),
            last_completed: None,
            maintenance: None,
            diagnostics: Vec::new(),
        },
    };
    codec::seal(&mut env);
    env
}

fn owned(generation: u64, prev: Option<String>, tx_id: &str) -> Envelope {
    owned_with(generation, prev, tx_id, "192.0.2.53")
}

fn genesis() -> Envelope {
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
    env
}

fn tombstone(generation: u64, prev: Option<String>, tx_id: &str, completed: u64) -> Envelope {
    store::tombstone_envelope(
        MACHINE,
        generation,
        prev,
        Tombstone {
            transaction_id: tx_id.to_string(),
            verified_at_utc: NOW.to_string(),
            completed_generation: completed,
        },
    )
}

fn digest_of(env: &Envelope) -> String {
    codec::envelope_digest(&codec::encode(env))
}

fn open_store() -> Store {
    JournalStore::open(FakeFs::new(), DIR).expect("open store")
}

fn commit_genesis(s: &Store) -> CommitReport {
    s.commit(&genesis()).expect("genesis commit")
}

fn stage_paths(s: &Store) -> Vec<String> {
    s.fs().all_paths().into_iter().filter(|p| p.contains(".stage.")).collect()
}

fn backup_paths(s: &Store) -> Vec<String> {
    s.fs().all_paths().into_iter().filter(|p| p.contains(".bak.")).collect()
}

fn stage_name(generation: u64) -> String {
    format!("{STAGE_PREFIX}{generation}.{UUID0}")
}

fn backup_name(generation: u64) -> String {
    format!("{BACKUP_PREFIX}{generation}.{UUID0}")
}

fn io_fault() -> FsError {
    FsError::Io { code: 1117, context: "injected device error".to_string() }
}

fn weak_security(kind: ObjectKind) -> SecurityInfo {
    let mut sec = expected_security(kind);
    sec.aces.push(Ace {
        allow: true,
        sid: "S-1-1-0".to_string(),
        mask: FILE_ALL_ACCESS,
        inherit_flags: 0,
    });
    sec
}

fn bad_owner_security(kind: ObjectKind) -> SecurityInfo {
    let mut sec = expected_security(kind);
    sec.owner = SID_ADMINISTRATORS.to_string();
    sec
}

fn primary_env(s: &Store) -> Envelope {
    codec::decode(&s.fs().file_bytes(&s.primary_path()).unwrap()).unwrap()
}

// ---- codec strictness ---------------------------------------------------------

#[test]
fn codec_roundtrip_is_canonical() {
    for env in [genesis(), owned(2, Some(digest_of(&genesis())), TX_A)] {
        let bytes = codec::encode(&env);
        assert_eq!(bytes[0], b'{');
        assert_eq!(codec::decode(&bytes).unwrap(), env);
        assert_eq!(codec::encode(&codec::decode(&bytes).unwrap()), bytes);
    }
}

#[test]
fn codec_rejects_bom() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend(codec::encode(&genesis()));
    assert_eq!(codec::decode(&bytes), Err(JournalError::Bom));
}

#[test]
fn codec_rejects_non_utf8() {
    let mut bytes = codec::encode(&genesis());
    bytes.push(0xFF);
    assert_eq!(codec::decode(&bytes), Err(JournalError::NotUtf8));
}

#[test]
fn codec_rejects_oversize() {
    let bytes = vec![b' '; MAX_JOURNAL_BYTES + 1];
    assert_eq!(codec::decode(&bytes), Err(JournalError::TooLarge(MAX_JOURNAL_BYTES + 1)));
}

#[test]
fn codec_rejects_duplicate_keys() {
    let txt = String::from_utf8(codec::encode(&genesis())).unwrap();
    let dup = txt.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    match codec::decode(dup.as_bytes()) {
        Err(JournalError::Json(m)) => assert!(m.contains("duplicate"), "{m}"),
        other => panic!("expected duplicate-key refusal, got {other:?}"),
    }
}

#[test]
fn codec_rejects_unknown_field() {
    let txt = String::from_utf8(codec::encode(&genesis())).unwrap();
    let patched = txt.replacen('{', "{\"surprise\":1,", 1);
    assert!(matches!(codec::decode(patched.as_bytes()), Err(JournalError::Schema(_))));
}

#[test]
fn codec_rejects_unknown_version() {
    let txt = String::from_utf8(codec::encode(&genesis())).unwrap();
    let patched = txt.replacen("\"version\":1", "\"version\":2", 1);
    assert_eq!(codec::decode(patched.as_bytes()), Err(JournalError::UnknownVersion(2)));
}

#[test]
fn codec_rejects_unknown_format() {
    let txt = String::from_utf8(codec::encode(&genesis())).unwrap();
    let patched = txt.replacen(journal::JOURNAL_FORMAT, "other-format", 1);
    assert!(matches!(codec::decode(patched.as_bytes()), Err(JournalError::UnknownFormat(_))));
}

#[test]
fn codec_rejects_non_normalized_u64() {
    let txt = String::from_utf8(codec::encode(&genesis())).unwrap();
    let patched = txt.replacen("\"generation\":\"1\"", "\"generation\":\"01\"", 1);
    assert!(matches!(codec::decode(patched.as_bytes()), Err(JournalError::Schema(_))));
}

#[test]
fn codec_rejects_digest_mismatch() {
    let mut env = genesis();
    env.payload_digest = "0".repeat(64);
    assert_eq!(codec::decode(&codec::encode(&env)), Err(JournalError::DigestMismatch));
}

#[test]
fn codec_rejects_non_canonical_bytes() {
    let mut bytes = codec::encode(&genesis());
    bytes.insert(1, b' ');
    assert_eq!(codec::decode(&bytes), Err(JournalError::NotCanonical));
}

#[test]
fn codec_rejects_semantic_violation() {
    // Clean state with a transaction: canonical bytes and a valid digest, but
    // semantic validation must still refuse.
    let mut env = genesis();
    env.payload.transaction = Some(tx(TX_A, "192.0.2.53"));
    codec::seal(&mut env);
    assert!(matches!(codec::decode(&codec::encode(&env)), Err(JournalError::Schema(_))));
}

// ---- semantic validation ------------------------------------------------------

fn reseal(mut env: Envelope) -> Envelope {
    codec::seal(&mut env);
    env
}

#[test]
fn validate_owned_requires_transaction() {
    let mut env = owned(1, None, TX_A);
    env.payload.transaction = None;
    let env = reseal(env);
    assert!(matches!(journal::validate(&env), Err(JournalError::Schema(_))));
}

#[test]
fn validate_maintenance_lease_bounds() {
    let mk = |start: &str, end: &str| {
        let mut env = genesis();
        env.payload.journal_state = JournalState::Maintenance;
        env.payload.maintenance = Some(Maintenance {
            id: UUID0.to_string(),
            caller_identity: "installer".to_string(),
            started_at_utc: start.to_string(),
            expires_at_utc: end.to_string(),
            phase: "upgrade".to_string(),
        });
        reseal(env)
    };
    // Exactly 600 s is allowed.
    assert!(journal::validate(&mk(NOW, "2026-11-13T18:18:29Z")).is_ok());
    // 601 s is not.
    assert!(matches!(
        journal::validate(&mk(NOW, "2026-11-13T18:18:30Z")),
        Err(JournalError::Schema(_))
    ));
    // Non-positive lease is not.
    assert!(matches!(journal::validate(&mk(NOW, NOW)), Err(JournalError::Schema(_))));
    // Missing lease is not.
    let mut env = genesis();
    env.payload.journal_state = JournalState::Maintenance;
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_tombstone_generation_bound() {
    let env = tombstone(2, Some(digest_of(&genesis())), TX_A, 5);
    assert!(matches!(journal::validate(&env), Err(JournalError::Schema(_))));
}

fn ep(ip: &str, transport: Transport) -> BoundEndpoint {
    BoundEndpoint { ip: ip.parse().unwrap(), port: 53, transport }
}

fn with_plan(env: Envelope, desired: DesiredPlan) -> Envelope {
    let mut env = env;
    env.payload.transaction.as_mut().unwrap().desired = desired;
    reseal(env)
}

#[test]
fn validate_plan_loopback_port53_only() {
    let base = owned(1, None, TX_A);
    let mut p = plan();
    p.bound_endpoints = vec![ep("192.0.2.1", Transport::Udp), ep("192.0.2.1", Transport::Tcp)];
    assert!(matches!(journal::validate(&with_plan(base.clone(), p)), Err(JournalError::Schema(_))));
    let mut p = plan();
    p.bound_endpoints = vec![BoundEndpoint { ip: "127.0.0.1".parse().unwrap(), port: 54, transport: Transport::Udp }];
    assert!(matches!(journal::validate(&with_plan(base.clone(), p)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_plan_family_needs_udp_and_tcp() {
    let base = owned(1, None, TX_A);
    let mut p = plan();
    p.bound_endpoints = vec![ep("127.0.0.1", Transport::Udp)];
    assert!(matches!(journal::validate(&with_plan(base.clone(), p)), Err(JournalError::Schema(_))));
    let mut p = plan();
    p.local_requested = true;
    assert!(matches!(journal::validate(&with_plan(base.clone(), p)), Err(JournalError::Schema(_))));
    let mut p = plan();
    p.local_requested = true;
    p.bound_endpoints = vec![
        ep("127.0.0.1", Transport::Udp),
        ep("127.0.0.1", Transport::Tcp),
        ep("::1", Transport::Udp),
        ep("::1", Transport::Tcp),
    ];
    assert!(journal::validate(&with_plan(base, p)).is_ok());
}

#[test]
fn validate_applied_fingerprint_requires_verified_operation() {
    let mut env = owned(1, None, TX_A);
    let target_fp = snap(Family::Ipv4, "127.0.0.1").fingerprint();
    env.payload.transaction.as_mut().unwrap().entries[0].applied_fingerprint = Some(target_fp);
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

fn operation(ordinal: u32, generation: u64, state: OperationState) -> Operation {
    let before = snap(Family::Ipv4, "192.0.2.53");
    let target = snap(Family::Ipv4, "127.0.0.1");
    Operation {
        id: "55555555-5555-4555-8555-555555555555".to_string(),
        request_id: "66666666-6666-4666-8666-666666666666".to_string(),
        ordinal,
        kind: OperationKind::Apply,
        state,
        before_fingerprint: before.fingerprint(),
        before,
        target_fingerprint: target.fingerprint(),
        target,
        write_mask: vec![WriteFacet::Nameserver],
        intent_generation: generation,
        api_started_at: None,
        api_finished_at: None,
        windows_status: None,
        observed_after: None,
        observed_fingerprint: None,
        attempts: 0,
        error: None,
    }
}

#[test]
fn validate_verified_operation_satisfies_applied_fingerprint() {
    let mut env = owned(1, None, TX_A);
    let op = operation(1, 1, OperationState::Verified);
    let fp = op.target_fingerprint.clone();
    let e = &mut env.payload.transaction.as_mut().unwrap().entries[0];
    e.operations.push(op);
    e.applied_fingerprint = Some(fp);
    assert!(journal::validate(&reseal(env)).is_ok());
}

#[test]
fn validate_duplicate_entry_refused() {
    let mut env = owned(1, None, TX_A);
    let dup = env.payload.transaction.as_ref().unwrap().entries[0].clone();
    env.payload.transaction.as_mut().unwrap().entries.push(dup);
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_ordinals_strictly_increasing() {
    let mut env = owned(1, None, TX_A);
    let ops = &mut env.payload.transaction.as_mut().unwrap().entries[0].operations;
    ops.push(operation(1, 1, OperationState::Intent));
    ops.push(operation(1, 1, OperationState::Intent));
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_baseline_matches_reason() {
    let mut env = owned(1, None, TX_A);
    env.payload.transaction.as_mut().unwrap().entries[0].baseline_kind = BaselineKind::LegacyCurrent;
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_legacy_target_forbidden_for_takeover() {
    let mut env = owned(1, None, TX_A);
    env.payload.transaction.as_mut().unwrap().entries[0].approved_legacy_target =
        Some(snap(Family::Ipv4, "192.0.2.54"));
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_intent_generation_bound() {
    let mut env = owned(1, None, TX_A);
    env.payload.transaction.as_mut().unwrap().entries[0]
        .operations
        .push(operation(1, 5, OperationState::Intent));
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_diagnostics_cap() {
    let mut env = genesis();
    env.payload.diagnostics = (0..MAX_DIAGNOSTICS + 1)
        .map(|i| Diagnostic {
            at_utc: NOW.to_string(),
            transaction_id: None,
            kind: "info".to_string(),
            message: format!("m{i}"),
        })
        .collect();
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn truncate_diagnostics_protects_live_transaction() {
    let diags: Vec<Diagnostic> = (0..150)
        .map(|i| Diagnostic {
            at_utc: NOW.to_string(),
            transaction_id: if i % 15 == 0 { Some(TX_A.to_string()) } else { None },
            kind: "info".to_string(),
            message: format!("m{i}"),
        })
        .collect();
    let kept = journal::truncate_diagnostics(&diags, Some(TX_A));
    assert_eq!(kept.len(), MAX_DIAGNOSTICS);
    assert_eq!(
        kept.iter().filter(|d| d.transaction_id.as_deref() == Some(TX_A)).count(),
        10
    );
    assert!(kept.iter().any(|d| d.message == "m149"));
    assert!(!kept.iter().any(|d| d.message == "m1"));
    // Without a live transaction the newest 100 win.
    let kept = journal::truncate_diagnostics(&diags, None);
    assert_eq!(kept.len(), MAX_DIAGNOSTICS);
    assert_eq!(kept[0].message, "m50");
}

#[test]
fn validate_timestamp_shape() {
    let mut env = owned(1, None, TX_A);
    env.payload.transaction.as_mut().unwrap().entries[0].first_captured_at_utc =
        "yesterday".to_string();
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_machine_id_lowercase_uuid() {
    let mut env = genesis();
    env.machine_id = MACHINE.to_uppercase();
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

#[test]
fn validate_original_fingerprint_must_match() {
    let mut env = owned(1, None, TX_A);
    env.payload.transaction.as_mut().unwrap().entries[0].original_fingerprint = "0".repeat(64);
    assert!(matches!(journal::validate(&reseal(env)), Err(JournalError::Schema(_))));
}

// ---- store open / storage safety ----------------------------------------------

#[test]
fn open_accepts_clean_directory() {
    let s = open_store();
    assert!(!s.admission_closed());
    assert_eq!(s.dir(), DIR);
    let r = s.reconcile().unwrap();
    assert!(r.current.is_none());
    assert!(r.primary.is_none());
    assert!(r.candidates.is_empty());
}

#[test]
fn open_rejects_bad_directory_acl() {
    let fs = FakeFs::new();
    fs.seed_directory(DIR, weak_security(ObjectKind::Directory));
    assert!(matches!(JournalStore::open(fs, DIR), Err(StoreError::Unsafe(_))));
}

#[test]
fn open_rejects_network_storage() {
    let fs = FakeFs::new();
    fs.set_storage(StorageKind::Network);
    assert!(matches!(JournalStore::open(fs, DIR), Err(StoreError::Unsafe(_))));
}

#[test]
fn open_rejects_non_ntfs() {
    let fs = FakeFs::new();
    fs.set_storage(StorageKind::NonNtfs);
    assert!(matches!(JournalStore::open(fs, DIR), Err(StoreError::Unsafe(_))));
}

#[test]
fn reparse_primary_refuses_all_writes() {
    let s = open_store();
    s.fs().seed_file(&s.primary_path(), codec::encode(&genesis()));
    s.fs().set_reparse(&s.primary_path(), true);
    assert!(matches!(s.reconcile(), Err(StoreError::Unsafe(_))));
    assert!(matches!(s.commit(&genesis()), Err(StoreError::Unsafe(_))));
    assert_eq!(s.fs().counters().creates, 0);
}

#[test]
fn hardlink_stage_refuses_reconciliation() {
    let s = open_store();
    let g = digest_of(&genesis());
    s.fs().seed_file(&s.primary_path(), codec::encode(&genesis()));
    let stage = join(DIR, &stage_name(2));
    s.fs().seed_file(&stage, codec::encode(&owned(2, Some(g), TX_A)));
    s.fs().set_links(&stage, 2);
    assert!(matches!(s.reconcile(), Err(StoreError::Unsafe(_))));
}

#[test]
fn bad_file_owner_refuses_reconciliation() {
    let s = open_store();
    s.fs().seed_file_with_security(
        &s.primary_path(),
        codec::encode(&genesis()),
        bad_owner_security(ObjectKind::File),
    );
    assert!(matches!(s.reconcile(), Err(StoreError::Unsafe(_))));
}

#[test]
fn bad_file_dacl_refuses_reconciliation() {
    let s = open_store();
    s.fs().seed_file_with_security(
        &s.primary_path(),
        codec::encode(&genesis()),
        weak_security(ObjectKind::File),
    );
    assert!(matches!(s.reconcile(), Err(StoreError::Unsafe(_))));
}

#[test]
fn midflight_volume_flush_unsupported_closes_admission() {
    let s = open_store();
    let g = commit_genesis(&s);
    // The store flushes the volume containing the primary path.
    s.fs().set_storage_override(&s.primary_path(), StorageKind::NonNtfs);
    let env = owned(2, Some(g.digest), TX_A);
    assert!(matches!(
        s.commit(&env),
        Err(StoreError::Fs(FsError::VolumeFlushUnsupported))
    ));
    assert!(s.admission_closed());
    // The replacement itself completed; both generations remain recoverable.
    assert_eq!(primary_env(&s).generation, 2);
    assert_eq!(backup_paths(&s).len(), 1);
}

// ---- happy-path barrier --------------------------------------------------------

#[test]
fn genesis_commit_runs_full_barrier() {
    let s = open_store();
    let report = commit_genesis(&s);
    assert_eq!(report.generation, 1);
    assert!(report.backup.is_none());
    assert_eq!(report.digest, digest_of(&genesis()));
    assert_eq!(s.fs().file_bytes(&s.primary_path()).unwrap(), codec::encode(&genesis()));
    assert!(stage_paths(&s).is_empty());
    assert!(backup_paths(&s).is_empty());
    let c = s.fs().counters();
    assert_eq!(c.creates, 1);
    assert_eq!(c.writes, 1);
    assert_eq!(c.moves, 1, "first primary uses MoveFileExW WRITE_THROUGH");
    assert_eq!(c.replaces, 0);
    assert_eq!(c.file_flushes, 2, "stage flush + primary flush");
    assert_eq!(c.volume_flushes, 1, "no optimistic rename durability");
    assert!(!s.admission_closed());
}

#[test]
fn second_commit_replaces_with_backup() {
    let s = open_store();
    let g1 = commit_genesis(&s);
    let env = owned(2, Some(g1.digest.clone()), TX_A);
    let g2 = s.commit(&env).unwrap();
    assert_eq!(g2.generation, 2);
    let backup = g2.backup.expect("backup created");
    assert!(backup.contains(&format!("{BACKUP_PREFIX}1.")));
    assert_eq!(s.fs().file_bytes(&backup).unwrap(), codec::encode(&genesis()));
    assert_eq!(s.fs().file_bytes(&s.primary_path()).unwrap(), codec::encode(&env));
    assert!(stage_paths(&s).is_empty());
    let c = s.fs().counters();
    assert_eq!(c.replaces, 1);
    assert_eq!(c.moves, 1);
    assert_eq!(c.volume_flushes, 2);
    assert_eq!(primary_env(&s).previous_digest.as_deref(), Some(g1.digest.as_str()));
}

#[test]
fn commit_enforces_generation_lineage_machine() {
    let s = open_store();
    let g1 = commit_genesis(&s);
    // Stale generation.
    assert!(matches!(s.commit(&genesis()), Err(StoreError::InvalidNextGeneration(_))));
    // Missing previous_digest.
    assert!(matches!(
        s.commit(&owned(2, None, TX_A)),
        Err(StoreError::InvalidNextGeneration(_))
    ));
    // Wrong previous_digest.
    assert!(matches!(
        s.commit(&owned(2, Some("0".repeat(64)), TX_A)),
        Err(StoreError::InvalidNextGeneration(_))
    ));
    // Wrong machine.
    let mut env = owned(2, Some(g1.digest.clone()), TX_A);
    env.machine_id = OTHER_MACHINE.to_string();
    codec::seal(&mut env);
    assert!(matches!(s.commit(&env), Err(StoreError::InvalidNextGeneration(_))));
    // Unsealed envelope.
    let mut env = owned(2, Some(g1.digest), TX_A);
    env.payload_digest = String::new();
    assert!(matches!(s.commit(&env), Err(StoreError::Codec(JournalError::DigestMismatch))));
    // Nothing was written by any refused attempt.
    assert_eq!(s.fs().counters().creates, 1);
}

#[test]
fn commit_genesis_rules_on_empty_journal() {
    let s = open_store();
    assert!(matches!(
        s.commit(&owned(2, None, TX_A)),
        Err(StoreError::InvalidNextGeneration(_))
    ));
    let mut env = genesis();
    env.previous_digest = Some("0".repeat(64));
    codec::seal(&mut env);
    assert!(matches!(s.commit(&env), Err(StoreError::InvalidNextGeneration(_))));
    assert_eq!(s.fs().counters().creates, 0);
}

#[test]
fn commit_validates_schema_before_writing() {
    let s = open_store();
    let mut env = owned(1, None, TX_A);
    env.payload.transaction = None;
    codec::seal(&mut env);
    assert!(matches!(s.commit(&env), Err(StoreError::Codec(JournalError::Schema(_)))));
    assert_eq!(s.fs().counters().creates, 0);
}

// ---- fault injection: pre-replacement ------------------------------------------

#[test]
fn create_new_fault_keeps_baseline_and_recovers() {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject(FaultPoint::CreateNew, Fault::Error(FsError::DiskFull));
    let env = owned(2, Some(g.digest.clone()), TX_A);
    assert!(matches!(s.commit(&env), Err(StoreError::Fs(FsError::DiskFull))));
    assert!(s.admission_closed());
    assert!(stage_paths(&s).is_empty());
    assert_eq!(s.fs().file_bytes(&s.primary_path()).unwrap(), codec::encode(&genesis()));
    assert!(matches!(s.commit(&env), Err(StoreError::ReconciliationRequired)));
    s.fs().clear_faults();
    let r = s.reconcile().unwrap();
    assert!(!s.admission_closed());
    assert_eq!(r.current.unwrap().env.generation, 1);
    let g2 = s.commit(&owned(2, Some(g.digest), TX_A)).unwrap();
    assert_eq!(g2.generation, 2);
}

#[test]
fn write_fault_keeps_empty_stage_as_artifact() {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject(FaultPoint::Write, Fault::Error(FsError::DiskFull));
    let env = owned(2, Some(g.digest.clone()), TX_A);
    assert!(matches!(s.commit(&env), Err(StoreError::Fs(FsError::DiskFull))));
    assert!(s.admission_closed());
    let stages = stage_paths(&s);
    assert_eq!(stages.len(), 1);
    assert!(s.fs().file_bytes(&stages[0]).unwrap().is_empty());
    s.fs().clear_faults();
    let r = s.reconcile().unwrap();
    assert_eq!(r.current.unwrap().env.generation, 1);
    let report = r.candidates.iter().find(|c| c.kind == CandidateKind::Stage).unwrap();
    assert!(matches!(report.status, CandidateStatus::Invalid(_)));
    assert!(s.fs().exists(&stages[0]), "crash artifact retained");
    s.commit(&owned(2, Some(g.digest), TX_A)).unwrap();
}

#[test]
fn partial_write_is_caught_by_stage_readback() {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject_once(FaultPoint::Write, Fault::PartialWrite);
    let env = owned(2, Some(g.digest.clone()), TX_A);
    match s.commit(&env) {
        Err(StoreError::VerificationMismatch { at, .. }) => assert_eq!(at, "stage readback"),
        other => panic!("expected readback mismatch, got {other:?}"),
    }
    assert!(s.admission_closed());
    let stages = stage_paths(&s);
    assert_eq!(stages.len(), 1);
    assert_eq!(
        s.fs().file_bytes(&stages[0]).unwrap().len(),
        codec::encode(&env).len() / 2
    );
    assert_eq!(s.fs().file_bytes(&s.primary_path()).unwrap(), codec::encode(&genesis()));
    let r = s.reconcile().unwrap();
    assert_eq!(r.current.unwrap().env.generation, 1, "incomplete stage never authorizes");
    s.commit(&owned(2, Some(g.digest), TX_A)).unwrap();
}

#[test]
fn sharing_violation_at_create_new() {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject(FaultPoint::CreateNew, Fault::Error(FsError::SharingViolation));
    assert!(matches!(
        s.commit(&owned(2, Some(g.digest), TX_A)),
        Err(StoreError::Fs(FsError::SharingViolation))
    ));
    assert!(s.admission_closed());
    assert!(stage_paths(&s).is_empty());
}

#[test]
fn access_denied_at_replace_leaves_recoverable_intent() {
    stage_intent_recovery(FaultPoint::Replace, Fault::Error(FsError::AccessDenied));
}

/// Faults after a fully written stage but before a completed replacement:
/// the stage is a possible intent, admission closes, and recovery republishes
/// the reconciled winner as generation+1. No baseline or intent is lost.
fn stage_intent_recovery(point: FaultPoint, fault: Fault) {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject(point, fault);
    let env = owned(2, Some(g.digest.clone()), TX_A);
    assert!(matches!(s.commit(&env), Err(StoreError::Fs(_))), "point {point:?}");
    assert!(s.admission_closed());
    assert_eq!(s.fs().file_bytes(&s.primary_path()).unwrap(), codec::encode(&genesis()));
    let stages = stage_paths(&s);
    assert_eq!(stages.len(), 1, "point {point:?}");
    assert_eq!(s.fs().file_bytes(&stages[0]).unwrap(), codec::encode(&env));
    assert!(backup_paths(&s).is_empty());
    assert!(matches!(s.commit(&env), Err(StoreError::ReconciliationRequired)));
    s.fs().clear_faults();
    let r = s.reconcile().unwrap();
    assert!(!s.admission_closed());
    let cur = r.current.clone().expect("current");
    assert_eq!(cur.env.generation, 2);
    assert_eq!(cur.kind, CandidateKind::Stage);
    assert_eq!(r.primary.unwrap().env.generation, 1);
    let rep = s.republish(&cur).unwrap();
    assert_eq!(rep.generation, 3);
    assert!(rep.backup.is_some());
    let primary = primary_env(&s);
    assert_eq!(primary.generation, 3);
    assert_eq!(primary.previous_digest.as_deref(), Some(cur.digest.as_str()));
    assert!(s.fs().exists(&stages[0]), "failed stage retained as evidence");
}

#[test]
fn file_flush_fault_leaves_recoverable_intent() {
    stage_intent_recovery(FaultPoint::FileFlush, Fault::Error(io_fault()));
}

#[test]
fn stage_readback_fault_leaves_recoverable_intent() {
    stage_intent_recovery(FaultPoint::StageReadback, Fault::Error(io_fault()));
}

#[test]
fn replace_fault_leaves_recoverable_intent() {
    stage_intent_recovery(FaultPoint::Replace, Fault::Error(io_fault()));
}

#[test]
fn move_fault_on_first_primary_recovers_via_stage() {
    let s = open_store();
    s.fs().inject(FaultPoint::Move, Fault::Error(io_fault()));
    assert!(matches!(s.commit(&genesis()), Err(StoreError::Fs(_))));
    assert!(s.admission_closed());
    assert!(!s.fs().exists(&s.primary_path()));
    let stages = stage_paths(&s);
    assert_eq!(stages.len(), 1);
    assert_eq!(s.fs().file_bytes(&stages[0]).unwrap(), codec::encode(&genesis()));
    s.fs().clear_faults();
    let r = s.reconcile().unwrap();
    let cur = r.current.clone().unwrap();
    assert_eq!(cur.env.generation, 1);
    assert_eq!(cur.kind, CandidateKind::Stage);
    assert!(r.primary.is_none());
    // A clean genesis cannot be republished as gen 2 (tombstone required), so
    // the next real envelope chains from the surviving stage instead.
    let g2 = s.commit(&owned(2, Some(cur.digest), TX_A)).unwrap();
    assert_eq!(g2.generation, 2);
    assert_eq!(primary_env(&s).generation, 2);
}

// ---- fault injection: post-replacement ------------------------------------------

/// Faults after ReplaceFileW succeeded: primary=new, backup=old, stage gone.
/// Both generations stay recoverable; reconciliation elects the new primary.
fn post_replace_recovery(point: FaultPoint) {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject(point, Fault::Error(io_fault()));
    let env = owned(2, Some(g.digest.clone()), TX_A);
    assert!(matches!(s.commit(&env), Err(StoreError::Fs(_))), "point {point:?}");
    assert!(s.admission_closed());
    assert_eq!(s.fs().file_bytes(&s.primary_path()).unwrap(), codec::encode(&env));
    let baks = backup_paths(&s);
    assert_eq!(baks.len(), 1);
    assert_eq!(s.fs().file_bytes(&baks[0]).unwrap(), codec::encode(&genesis()));
    assert!(stage_paths(&s).is_empty());
    s.fs().clear_faults();
    let r = s.reconcile().unwrap();
    let cur = r.current.clone().unwrap();
    assert_eq!(cur.env.generation, 2);
    assert_eq!(cur.kind, CandidateKind::Primary);
    let rep = s.republish(&cur).unwrap();
    assert_eq!(rep.generation, 3);
    assert_eq!(primary_env(&s).generation, 3);
    assert_eq!(backup_paths(&s).len(), 2, "candidates kept on every error");
}

#[test]
fn primary_reopen_fault_after_replace() {
    post_replace_recovery(FaultPoint::PrimaryReopen);
}

#[test]
fn primary_flush_fault_after_replace() {
    post_replace_recovery(FaultPoint::PrimaryFlush);
}

#[test]
fn volume_flush_fault_after_replace() {
    post_replace_recovery(FaultPoint::VolumeFlush);
}

// ---- ReplaceFileW documented failure shapes --------------------------------------

fn replace_shape(shape: ReplaceFailure, code: u32, primary_present: bool, backup_present: bool) {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject(FaultPoint::Replace, Fault::ReplaceShape(shape));
    let env = owned(2, Some(g.digest.clone()), TX_A);
    match s.commit(&env) {
        Err(StoreError::Fs(FsError::Io { code: c, .. })) => assert_eq!(c, code),
        other => panic!("expected Io {code}, got {other:?}"),
    }
    assert!(s.admission_closed());
    let stages = stage_paths(&s);
    assert_eq!(stages.len(), 1, "stage always retained");
    assert_eq!(s.fs().file_bytes(&stages[0]).unwrap(), codec::encode(&env));
    assert_eq!(s.fs().exists(&s.primary_path()), primary_present);
    if primary_present {
        assert_eq!(s.fs().file_bytes(&s.primary_path()).unwrap(), codec::encode(&genesis()));
    }
    let baks = backup_paths(&s);
    assert_eq!(baks.len(), usize::from(backup_present));
    if backup_present {
        assert_eq!(s.fs().file_bytes(&baks[0]).unwrap(), codec::encode(&genesis()));
    }
    s.fs().clear_faults();
    let r = s.reconcile().unwrap();
    let cur = r.current.clone().unwrap();
    assert_eq!(cur.env.generation, 2, "newer fully written stage wins");
    assert_eq!(cur.kind, CandidateKind::Stage);
    assert_eq!(r.primary.is_some(), primary_present);
    let rep = s.republish(&cur).unwrap();
    assert_eq!(rep.generation, 3);
    assert_eq!(primary_env(&s).generation, 3);
    assert_eq!(rep.backup.is_some(), primary_present);
}

#[test]
fn replace_shape_1176_primary_old_stage_new() {
    replace_shape(ReplaceFailure::UnableToMoveReplacement, 1176, true, false);
}

#[test]
fn replace_shape_1177_primary_missing_backup_old() {
    replace_shape(ReplaceFailure::UnableToMoveReplacement2, 1177, false, true);
}

#[test]
fn replace_shape_1175_both_retain_names() {
    replace_shape(ReplaceFailure::UnableToRemoveReplaced, 1175, true, false);
}

#[test]
fn replace_shape_other_both_retain_names() {
    replace_shape(ReplaceFailure::Other(87), 87, true, false);
}

// ---- reconciliation semantics -----------------------------------------------------

#[test]
fn corrupt_primary_with_valid_backup_refuses() {
    let s = open_store();
    s.fs().seed_file(&s.primary_path(), b"corrupt primary".to_vec());
    s.fs().seed_file(&join(DIR, &backup_name(1)), codec::encode(&genesis()));
    assert!(matches!(s.reconcile(), Err(StoreError::Integrity(_))));
    assert!(matches!(s.commit(&genesis()), Err(StoreError::Integrity(_))));
    assert_eq!(s.fs().all_paths().len(), 2, "evidence retained, nothing deleted");
    assert_eq!(s.fs().counters().creates, 0);
}

#[test]
fn corrupt_primary_alone_refuses() {
    let s = open_store();
    s.fs().seed_file(&s.primary_path(), b"{}".to_vec());
    assert!(matches!(s.reconcile(), Err(StoreError::Integrity(_))));
}

#[test]
fn corrupt_stage_is_retained_artifact_not_authoritative() {
    let s = open_store();
    s.fs().seed_file(&s.primary_path(), codec::encode(&genesis()));
    let stage = join(DIR, &stage_name(2));
    s.fs().seed_file(&stage, b"half-written".to_vec());
    let r = s.reconcile().unwrap();
    let cur = r.current.unwrap();
    assert_eq!(cur.env.generation, 1);
    assert_eq!(cur.kind, CandidateKind::Primary);
    let report = r.candidates.iter().find(|c| c.kind == CandidateKind::Stage).unwrap();
    assert!(matches!(report.status, CandidateStatus::Invalid(_)));
    assert!(s.fs().exists(&stage));
}

#[test]
fn missing_primary_with_valid_stage_and_backup() {
    let s = open_store();
    let e1 = genesis();
    let e2 = owned(2, Some(digest_of(&e1)), TX_A);
    s.fs().seed_file(&join(DIR, &backup_name(1)), codec::encode(&e1));
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&e2));
    let r = s.reconcile().unwrap();
    assert!(r.primary.is_none(), "missing primary is never proof of no ownership");
    let cur = r.current.unwrap();
    assert_eq!(cur.env.generation, 2);
    assert_eq!(cur.kind, CandidateKind::Stage);
}

#[test]
fn missing_primary_with_valid_backup_only() {
    let s = open_store();
    s.fs().seed_file(&join(DIR, &backup_name(1)), codec::encode(&genesis()));
    let r = s.reconcile().unwrap();
    let cur = r.current.unwrap();
    assert_eq!(cur.env.generation, 1);
    assert_eq!(cur.kind, CandidateKind::Backup);
}

#[test]
fn divergent_same_generation_branches_refuse() {
    let s = open_store();
    let e1 = genesis();
    let a = owned(2, Some(digest_of(&e1)), TX_A);
    let b = owned(2, Some(digest_of(&e1)), TX_B);
    s.fs().seed_file(&s.primary_path(), codec::encode(&a));
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&b));
    match s.reconcile() {
        Err(StoreError::Integrity(m)) => assert!(m.contains("divergent valid branches"), "{m}"),
        other => panic!("expected divergence refusal, got {other:?}"),
    }
}

#[test]
fn divergent_transaction_ids_without_tombstone_refuse() {
    let s = open_store();
    let e1 = owned(1, None, TX_A);
    let e2 = owned(2, Some(digest_of(&e1)), TX_B);
    s.fs().seed_file(&s.primary_path(), codec::encode(&e1));
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&e2));
    match s.reconcile() {
        Err(StoreError::Integrity(m)) => assert!(m.contains("divergent transaction IDs"), "{m}"),
        other => panic!("expected tx divergence refusal, got {other:?}"),
    }
}

#[test]
fn divergent_transaction_ids_separated_by_tombstone_are_compatible() {
    let s = open_store();
    let e1 = owned(1, None, TX_A);
    let t2 = tombstone(2, Some(digest_of(&e1)), TX_A, 1);
    let e3 = owned(3, Some(digest_of(&t2)), TX_B);
    s.fs().seed_file(&join(DIR, &backup_name(1)), codec::encode(&e1));
    s.fs().seed_file(&s.primary_path(), codec::encode(&t2));
    s.fs().seed_file(&join(DIR, &stage_name(3)), codec::encode(&e3));
    let r = s.reconcile().unwrap();
    let cur = r.current.unwrap();
    assert_eq!(cur.env.generation, 3);
    assert_eq!(cur.env.payload.transaction.as_ref().unwrap().id, TX_B);
}

#[test]
fn completed_transaction_cannot_be_resurrected() {
    let s = open_store();
    let t1 = tombstone(1, None, TX_A, 1);
    let e2 = owned(2, Some(digest_of(&t1)), TX_A);
    s.fs().seed_file(&join(DIR, &backup_name(1)), codec::encode(&t1));
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&e2));
    match s.reconcile() {
        Err(StoreError::Integrity(m)) => assert!(m.contains("resurrected"), "{m}"),
        other => panic!("expected resurrection refusal, got {other:?}"),
    }
}

#[test]
fn conflicting_originals_within_transaction_refuse() {
    let s = open_store();
    let e1 = owned_with(1, None, TX_A, "192.0.2.53");
    let e2 = owned_with(2, Some(digest_of(&e1)), TX_A, "192.0.2.54");
    s.fs().seed_file(&s.primary_path(), codec::encode(&e1));
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&e2));
    match s.reconcile() {
        Err(StoreError::Integrity(m)) => assert!(m.contains("conflicting originals"), "{m}"),
        other => panic!("expected originals refusal, got {other:?}"),
    }
}

#[test]
fn lineage_break_refuses() {
    let s = open_store();
    s.fs().seed_file(&s.primary_path(), codec::encode(&genesis()));
    let e2 = owned(2, Some("0".repeat(64)), TX_A);
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&e2));
    match s.reconcile() {
        Err(StoreError::Integrity(m)) => assert!(m.contains("lineage break"), "{m}"),
        other => panic!("expected lineage refusal, got {other:?}"),
    }
}

#[test]
fn genesis_with_previous_digest_refuses() {
    let s = open_store();
    let mut e1 = owned(1, None, TX_A);
    e1.previous_digest = Some("0".repeat(64));
    codec::seal(&mut e1);
    s.fs().seed_file(&join(DIR, &stage_name(1)), codec::encode(&e1));
    assert!(matches!(s.reconcile(), Err(StoreError::Integrity(_))));
}

#[test]
fn generation_missing_previous_digest_refuses() {
    let s = open_store();
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&owned(2, None, TX_A)));
    assert!(matches!(s.reconcile(), Err(StoreError::Integrity(_))));
}

#[test]
fn missing_intermediate_generations_are_acceptable() {
    let s = open_store();
    s.fs().seed_file(&s.primary_path(), codec::encode(&genesis()));
    let e5 = owned(5, Some("f".repeat(64)), TX_A);
    s.fs().seed_file(&join(DIR, &stage_name(5)), codec::encode(&e5));
    let r = s.reconcile().unwrap();
    assert_eq!(r.current.unwrap().env.generation, 5);
}

#[test]
fn identical_copies_prefer_primary() {
    let s = open_store();
    let e2 = owned(2, Some(digest_of(&genesis())), TX_A);
    let bytes = codec::encode(&e2);
    s.fs().seed_file(&s.primary_path(), bytes.clone());
    s.fs().seed_file(&join(DIR, &backup_name(2)), bytes);
    let r = s.reconcile().unwrap();
    let cur = r.current.unwrap();
    assert_eq!(cur.kind, CandidateKind::Primary);
    assert_eq!(cur.env.generation, 2);
}

#[test]
fn unknown_version_blocks_without_deleting() {
    let s = open_store();
    let txt = String::from_utf8(codec::encode(&genesis())).unwrap();
    let patched = txt.replacen("\"version\":1", "\"version\":2", 1);
    s.fs().seed_file(&s.primary_path(), patched.into_bytes());
    assert!(matches!(s.reconcile(), Err(StoreError::UnknownVersion(2))));
    assert!(matches!(s.commit(&genesis()), Err(StoreError::UnknownVersion(2))));
    assert!(s.fs().exists(&s.primary_path()), "unknown state never deleted");
    let c = s.fs().counters();
    assert_eq!(c.creates, 0);
    assert_eq!(c.deletes, 0);
}

#[test]
fn conflicting_machine_ids_refuse() {
    let s = open_store();
    s.fs().seed_file(&s.primary_path(), codec::encode(&genesis()));
    let mut e2 = owned(2, Some(digest_of(&genesis())), TX_A);
    e2.machine_id = OTHER_MACHINE.to_string();
    codec::seal(&mut e2);
    s.fs().seed_file(&join(DIR, &stage_name(2)), codec::encode(&e2));
    match s.reconcile() {
        Err(StoreError::Integrity(m)) => assert!(m.contains("machine IDs"), "{m}"),
        other => panic!("expected machine refusal, got {other:?}"),
    }
}

#[test]
fn failed_reconciliation_keeps_admission_closed() {
    let s = open_store();
    let g = commit_genesis(&s);
    s.fs().inject(FaultPoint::VolumeFlush, Fault::Error(io_fault()));
    assert!(s.commit(&owned(2, Some(g.digest), TX_A)).is_err());
    assert!(s.admission_closed());
    // Reconciliation itself fails while the primary is unsafe.
    s.fs().set_reparse(&s.primary_path(), true);
    assert!(matches!(s.reconcile(), Err(StoreError::Unsafe(_))));
    assert!(s.admission_closed(), "failed reconcile must not reopen admission");
    assert!(matches!(
        s.commit(&owned(3, None, TX_A)),
        Err(StoreError::ReconciliationRequired)
    ));
    s.fs().set_reparse(&s.primary_path(), false);
    s.fs().clear_faults();
    s.reconcile().unwrap();
    assert!(!s.admission_closed());
}

// ---- clean tombstone lifecycle ------------------------------------------------------

/// Build the durable layout: genesis(1) → owned(2, tx A) → clean tombstone(3).
fn tombstone_layout(s: &Store) -> Envelope {
    let g1 = commit_genesis(s);
    let e2 = owned(2, Some(g1.digest), TX_A);
    let g2 = s.commit(&e2).unwrap();
    let t3 = tombstone(3, Some(g2.digest), TX_A, 2);
    s.commit(&t3).unwrap();
    t3
}

#[test]
fn full_clean_lifecycle_and_cleanup() {
    let s = open_store();
    let t3 = tombstone_layout(&s);
    assert!(t3.is_clean_tombstone());
    assert_eq!(backup_paths(&s).len(), 2);
    let report = s.cleanup_obsolete(&t3).unwrap();
    assert_eq!(report.deleted.len(), 2);
    assert_eq!(report.retained, vec![s.primary_path()]);
    assert_eq!(s.fs().all_paths(), vec![s.primary_path()]);
    assert_eq!(s.fs().counters().deletes, 2);
    assert_eq!(s.fs().counters().volume_flushes, 4, "3 commits + post-cleanup flush");
    let r = s.reconcile().unwrap();
    assert!(r.current.unwrap().env.is_clean_tombstone());
}

#[test]
fn cleanup_crash_leaves_tombstone_authoritative() {
    let s = open_store();
    let t3 = tombstone_layout(&s);
    s.fs().inject_once(FaultPoint::CleanupDelete, Fault::Error(io_fault()));
    assert!(matches!(s.cleanup_obsolete(&t3), Err(StoreError::Fs(_))));
    assert!(s.admission_closed());
    assert!(matches!(s.cleanup_obsolete(&t3), Err(StoreError::ReconciliationRequired)));
    let r = s.reconcile().unwrap();
    assert!(r.current.unwrap().env.is_clean_tombstone(), "tombstone survives cleanup crash");
    let report = s.cleanup_obsolete(&t3).unwrap();
    assert_eq!(report.deleted.len(), 2);
    assert_eq!(s.fs().all_paths(), vec![s.primary_path()]);
}

#[test]
fn cleanup_resumes_after_partial_deletion() {
    let s = open_store();
    let t3 = tombstone_layout(&s);
    // Simulate a crash midway through cleanup: one backup already deleted.
    let baks = backup_paths(&s);
    s.fs().delete(&baks[0]).unwrap();
    let r = s.reconcile().unwrap();
    assert!(r.current.unwrap().env.is_clean_tombstone());
    let report = s.cleanup_obsolete(&t3).unwrap();
    assert_eq!(report.deleted, vec![baks[1].clone()]);
    assert_eq!(s.fs().all_paths(), vec![s.primary_path()]);
}

#[test]
fn cleanup_requires_clean_tombstone() {
    let s = open_store();
    let g1 = commit_genesis(&s);
    let e2 = owned(2, Some(g1.digest), TX_A);
    s.commit(&e2).unwrap();
    assert!(matches!(s.cleanup_obsolete(&e2), Err(StoreError::Integrity(_))));
    assert_eq!(s.fs().counters().deletes, 0);
}

#[test]
fn cleanup_requires_tombstone_as_durable_primary() {
    let s = open_store();
    let t3 = tombstone_layout(&s);
    // A different (uncommitted) tombstone must not authorize deletion.
    let other = tombstone(4, Some(digest_of(&t3)), TX_A, 3);
    assert!(matches!(s.cleanup_obsolete(&other), Err(StoreError::Integrity(_))));
    assert_eq!(s.fs().counters().deletes, 0);
}

#[test]
fn cleanup_retains_newer_and_unparseable_names() {
    let s = open_store();
    let t3 = tombstone(3, Some(digest_of(&genesis())), TX_A, 2);
    s.fs().seed_file(&s.primary_path(), codec::encode(&t3));
    let newer = join(DIR, &stage_name(4));
    s.fs().seed_file(&newer, codec::encode(&owned(4, Some(digest_of(&t3)), TX_B)));
    let obsolete_artifact = join(DIR, &stage_name(2));
    s.fs().seed_file(&obsolete_artifact, b"crash artifact".to_vec());
    let malformed = join(DIR, &format!("{STAGE_PREFIX}999999999999999999999999.{UUID0}"));
    s.fs().seed_file(&malformed, b"crash artifact".to_vec());
    let report = s.cleanup_obsolete(&t3).unwrap();
    assert_eq!(report.deleted, vec![obsolete_artifact]);
    assert!(report.retained.contains(&s.primary_path()));
    assert!(report.retained.contains(&newer));
    assert!(report.retained.contains(&malformed), "malformed names never deleted");
}

#[test]
fn clean_new_supersedes_active_old_backup() {
    let s = open_store();
    let e1 = owned(1, None, TX_A);
    let t2 = tombstone(2, Some(digest_of(&e1)), TX_A, 1);
    s.fs().seed_file(&join(DIR, &backup_name(1)), codec::encode(&e1));
    s.fs().seed_file(&s.primary_path(), codec::encode(&t2));
    let r = s.reconcile().unwrap();
    let cur = r.current.unwrap();
    assert_eq!(cur.env.generation, 2);
    assert!(cur.env.is_clean_tombstone(), "clean tombstone wins over active backup");
    let report = s.cleanup_obsolete(&t2).unwrap();
    assert_eq!(report.deleted.len(), 1);
    let r = s.reconcile().unwrap();
    assert!(r.current.unwrap().env.is_clean_tombstone());
    assert!(r.candidates.iter().all(|c| c.kind == CandidateKind::Primary));
}

#[test]
fn tombstone_completed_generation_cannot_exceed_envelope() {
    let s = open_store();
    let g1 = commit_genesis(&s);
    let bad = tombstone(2, Some(g1.digest), TX_A, 5);
    assert!(matches!(s.commit(&bad), Err(StoreError::Codec(JournalError::Schema(_)))));
    assert_eq!(s.fs().counters().creates, 1);
}

// ---- lock contention ----------------------------------------------------------------

#[test]
fn one_critical_section_across_sessions_and_offline_helper() {
    let a = FakeLock::new().with_identity(100, 1);
    let b = a.peer(200, 2); // second elevated process, different session
    let c = a.peer(300, 0); // offline helper, session 0
    let (guard, acquired) = a.acquire(LOCK_BUDGET).unwrap();
    assert_eq!(acquired, Acquired::Fresh);
    assert!(a.is_held());
    assert_eq!(a.holder().unwrap().pid, 100);
    assert!(matches!(b.acquire(LOCK_BUDGET), Err(LockError::Timeout)));
    assert!(matches!(c.acquire(LOCK_BUDGET), Err(LockError::Timeout)));
    drop(guard);
    assert!(!a.is_held());
    assert!(a.holder().is_none());
    let (gb, _) = b.acquire(LOCK_BUDGET).unwrap();
    assert_eq!(b.holder().unwrap().session_id, 2);
    assert!(matches!(a.acquire(LOCK_BUDGET), Err(LockError::Timeout)));
    assert!(matches!(c.acquire(LOCK_BUDGET), Err(LockError::Timeout)));
    drop(gb);
    let (_gc, _) = c.acquire(LOCK_BUDGET).unwrap();
    assert_eq!(c.holder().unwrap().pid, 300);
}

#[test]
fn abandoned_mutex_is_acquired_but_mandates_rescan() {
    let s = open_store();
    commit_genesis(&s);
    let lock = FakeLock::new();
    let (g, _) = lock.acquire(LOCK_BUDGET).unwrap();
    lock.simulate_holder_death();
    drop(g);
    let (g2, acquired) = lock.acquire(LOCK_BUDGET).unwrap();
    assert_eq!(acquired, Acquired::Abandoned);
    // WAIT_ABANDONED mandates a journal rescan before any write.
    let r = s.reconcile().unwrap();
    assert_eq!(r.current.unwrap().env.generation, 1);
    drop(g2);
    let (_g3, acquired) = lock.acquire(LOCK_BUDGET).unwrap();
    assert_eq!(acquired, Acquired::Fresh, "abandoned flag consumed once");
}

#[test]
fn wrong_type_squat_fails_closed() {
    for kind in [FakeObjectKind::Event, FakeObjectKind::Semaphore] {
        let lock = FakeLock::new();
        lock.squat(kind, expected_security(ObjectKind::Mutex));
        assert!(matches!(lock.acquire(LOCK_BUDGET), Err(LockError::WrongType)));
        assert!(!lock.is_held(), "a collision is never permission to proceed");
    }
}

#[test]
fn security_squat_fails_closed() {
    let lock = FakeLock::new();
    lock.squat(FakeObjectKind::Mutex, weak_security(ObjectKind::Mutex));
    assert!(matches!(lock.acquire(LOCK_BUDGET), Err(LockError::BadSecurity(_))));
    assert!(!lock.is_held());
    let lock = FakeLock::new();
    lock.squat(FakeObjectKind::Mutex, bad_owner_security(ObjectKind::Mutex));
    assert!(matches!(lock.acquire(LOCK_BUDGET), Err(LockError::BadSecurity(_))));
}

// ---- fake DNS barrier ordering --------------------------------------------------------

/// Library-only stand-in for the DNS applier: counts mutation calls. The
/// orchestration rule under test is "commit barrier first, mutation only after
/// it fully succeeds".
struct FakeDns {
    calls: Cell<u32>,
}

impl FakeDns {
    fn new() -> Self {
        Self { calls: Cell::new(0) }
    }
    fn apply(&self) {
        self.calls.set(self.calls.get() + 1);
    }
}

fn takeover_attempt(s: &Store, env: &Envelope, dns: &FakeDns) -> Result<CommitReport, StoreError> {
    let report = s.commit(env)?;
    dns.apply();
    Ok(report)
}

#[test]
fn fake_dns_runs_only_after_successful_barrier() {
    let s = open_store();
    let dns = FakeDns::new();
    takeover_attempt(&s, &genesis(), &dns).unwrap();
    assert_eq!(dns.calls.get(), 1);
}

#[test]
fn fake_dns_zero_calls_on_every_persistence_failure() {
    let cases: Vec<(FaultPoint, Fault)> = vec![
        (FaultPoint::CreateNew, Fault::Error(io_fault())),
        (FaultPoint::Write, Fault::Error(io_fault())),
        (FaultPoint::Write, Fault::PartialWrite),
        (FaultPoint::FileFlush, Fault::Error(io_fault())),
        (FaultPoint::StageReadback, Fault::Error(io_fault())),
        (FaultPoint::Replace, Fault::Error(io_fault())),
        (FaultPoint::Replace, Fault::ReplaceShape(ReplaceFailure::UnableToMoveReplacement)),
        (FaultPoint::Replace, Fault::ReplaceShape(ReplaceFailure::UnableToMoveReplacement2)),
        (FaultPoint::Replace, Fault::ReplaceShape(ReplaceFailure::UnableToRemoveReplaced)),
        (FaultPoint::Replace, Fault::ReplaceShape(ReplaceFailure::Other(87))),
        (FaultPoint::PrimaryReopen, Fault::Error(io_fault())),
        (FaultPoint::PrimaryFlush, Fault::Error(io_fault())),
        (FaultPoint::VolumeFlush, Fault::Error(io_fault())),
    ];
    for (point, fault) in cases {
        let s = open_store();
        let dns = FakeDns::new();
        let g = commit_genesis(&s);
        s.fs().inject(point, fault);
        let env = owned(2, Some(g.digest), TX_A);
        assert!(takeover_attempt(&s, &env, &dns).is_err(), "point {point:?}");
        assert_eq!(dns.calls.get(), 0, "mutation before barrier at {point:?}");
        // Reconciliation alone never authorizes a mutation either.
        s.fs().clear_faults();
        s.reconcile().unwrap();
        assert_eq!(dns.calls.get(), 0, "mutation after failed persistence at {point:?}");
    }
    // Move fault applies to the first primary (genesis).
    let s = open_store();
    let dns = FakeDns::new();
    s.fs().inject(FaultPoint::Move, Fault::Error(io_fault()));
    assert!(takeover_attempt(&s, &genesis(), &dns).is_err());
    assert_eq!(dns.calls.get(), 0);
}

#[test]
fn fake_dns_zero_new_calls_after_cleanup_failure() {
    let s = open_store();
    let dns = FakeDns::new();
    let t3 = tombstone_layout(&s);
    dns.apply(); // verified restore acknowledgement
    s.fs().inject(FaultPoint::CleanupDelete, Fault::Error(io_fault()));
    assert!(s.cleanup_obsolete(&t3).is_err());
    assert_eq!(dns.calls.get(), 1, "failed cleanup authorizes nothing");
    s.fs().clear_faults();
    s.reconcile().unwrap();
    assert_eq!(dns.calls.get(), 1);
    s.cleanup_obsolete(&t3).unwrap();
    assert_eq!(dns.calls.get(), 1);
    // CleanupVolumeFlush failure behaves the same way.
    let s = open_store();
    let dns = FakeDns::new();
    let t3 = tombstone_layout(&s);
    dns.apply();
    s.fs().inject(FaultPoint::CleanupVolumeFlush, Fault::Error(io_fault()));
    assert!(s.cleanup_obsolete(&t3).is_err());
    assert_eq!(dns.calls.get(), 1);
}
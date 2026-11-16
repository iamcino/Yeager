//! U09-REV3-AMEND Alt A scaffolding: seed a genuine Owned payload through the
//! production writer path (crate codec + WindowsFs + WindowsLock).
//!
//! - Fake adapter GUID (synthetic `deadbeef-...`, never a real NIC).
//! - Schema-valid, sealed envelope committed via `JournalStore::commit`
//!   (codec `seal` + `validate` enforced, no hand-edited journal bytes).
//! - Holds the machine `WindowsLock` across the commit like production.
//! - Generation follows the reconciled journal (genesis 1 when absent).
//!
//! Honest scaffolding: the debt is synthetic (fake adapter cannot restore,
//! U04), retired by a recorded manual clear. Never presented as product
//! behavior. Run elevated: `cargo run --example u09_seed_owned`.

#[cfg(windows)]
fn main() {
    use dns_recovery::fs_windows::{WindowsFs, WindowsLock};
    use dns_recovery::journal::{self, JournalState};
    use dns_recovery::lock::MachineLock;
    use dns_recovery::model::{
        CanonicalServer, Capability, DnsContext, Family, Provenance, ProvenanceEvidence, Snapshot,
    };
    use dns_recovery::service_os;
    use dns_recovery::store::JournalStore;
    use std::rc::Rc;
    use std::time::Duration;

    if !service_os::is_elevated() {
        eprintln!("u09_seed_owned: requires elevation");
        std::process::exit(13);
    }
    // Synthetic constants: clearly fake, schema-valid, never a real NIC.
    const FAKE_GUID: &str = "deadbeef-dead-beef-dead-beefdeadbeef";
    const NOW: &str = "2026-11-16T08:30:00Z";
    const OWNER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const SERVICE_INSTANCE: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    let dir = service_os::program_data_dir().expect("program_data_dir");
    let machine = service_os::machine_id();
    let fs = Rc::new(WindowsFs::new().expect("WindowsFs"));
    let store = JournalStore::open(Rc::clone(&fs), &dir).expect("open store");

    // Production mutual exclusion: hold the machine lock across the commit.
    let locker = WindowsLock::new().expect("WindowsLock");
    let (_guard, acquired) = locker.acquire(Duration::from_secs(10)).expect("acquire lock");
    let _ = acquired;

    let rec = store.reconcile().expect("reconcile");
    let (generation, previous_digest) = match &rec.current {
        None => (1u64, None),
        Some(cur) => (
            cur.env.generation + 1,
            Some(cur.digest.clone()),
        ),
    };
    if generation != 1 && previous_digest.is_none() {
        eprintln!("u09_seed_owned: refusing non-genesis commit without lineage");
        std::process::exit(14);
    }

    // Valid snapshot fixture (TEST-NET-1 original, never a real server).
    let original = Snapshot {
        schema_version: 1,
        family: Family::Ipv4,
        provenance: Provenance::Static,
        name_server_raw: Some("192.0.2.53".to_string()),
        ordered_servers: vec![CanonicalServer::parse("192.0.2.53").expect("parse server")],
        provenance_evidence: ProvenanceEvidence {
            registry_path: format!(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{{{FAKE_GUID}}}"
            ),
            value_exists: true,
            value_type: Some(1),
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
    };
    let fingerprint = original.fingerprint();
    let entry = journal::Entry {
        adapter_guid: FAKE_GUID.to_string(),
        family: Family::Ipv4,
        name_hint: "U09REV-AMEND-SYNTHETIC".to_string(),
        device_instance_hint: None,
        original_if_index: Some(99),
        original_luid: 9999,
        first_captured_at_utc: NOW.to_string(),
        original_fingerprint: fingerprint.clone(),
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
        retry: journal::RetryState {
            attempts: 0,
            next_attempt_utc: None,
            last_error: None,
        },
        verification: None,
        approved_legacy_target: None,
    };
    let tx = journal::Transaction {
        id: journal::new_uuid(),
        created_at_utc: NOW.to_string(),
        updated_at_utc: NOW.to_string(),
        reason: journal::Reason::Takeover,
        phase: journal::Phase::Preparing,
        owner: journal::OwnerIdentity {
            owner_id: OWNER_ID.to_string(),
            pid: 4242,
            creation_time_filetime: 133_000_000_000_000_000,
            user_sid: "S-1-5-18".to_string(),
            logon_luid: 999,
            session_id: 0,
            image_path: "C:\\Program Files\\Yeager\\yeager.exe".to_string(),
            image_file_id: "u09rev3amend-synthetic-1".to_string(),
            image_sha256: "b".repeat(64),
        },
        epoch: 1,
        admission: journal::Admission::Open,
        desired: dns_recovery::model::DesiredPlan {
            provider: dns_recovery::model::Provider::Auto,
            local_requested: false,
            bound_endpoints: Vec::new(),
            readiness_generation: 0,
        },
        service_instance_id: SERVICE_INSTANCE.to_string(),
        registered_at_utc: NOW.to_string(),
        entries: vec![entry],
    };
    let tx_id = tx.id.clone();
    let mut env = journal::Envelope {
        format: journal::JOURNAL_FORMAT.to_string(),
        version: journal::JOURNAL_VERSION,
        machine_id: machine,
        generation,
        previous_digest,
        payload_digest: String::new(),
        payload: journal::Payload {
            journal_state: JournalState::Owned,
            transaction: Some(tx),
            last_completed: None,
            maintenance: None,
            diagnostics: Vec::new(),
        },
    };
    dns_recovery::codec::seal(&mut env);
    let report = store.commit(&env).expect("commit Owned payload");
    println!(
        "{}",
        serde_json::json!({
            "mode": "u09-seed-owned",
            "outcome": "seeded",
            "generation": report.generation,
            "journal_state": "owned",
            "transaction_id": tx_id,
            "entries": 1,
            "adapter_guid": FAKE_GUID,
            "synthetic": true,
            "note": "scaffolding only: fake-adapter debt cannot restore; retired by recorded manual clear, never product behavior",
        })
    );
}

#[cfg(not(windows))]
fn main() {
    eprintln!("u09_seed_owned: Windows only");
    std::process::exit(15);
}

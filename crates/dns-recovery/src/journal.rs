//! Journal v1 schema and strict semantic validation (U02, SPEC-DNS-FIX.md
//! §3.2). Pure value types: no filesystem, no Windows API. The canonical
//! encoder/decoder lives in [`crate::codec`]; durable replacement and candidate
//! reconciliation live in [`crate::store`].
//!
//! Conventions enforced here and by the codec:
//! * u64/FILETIME values are normalized decimal strings (no leading zeros, no
//!   `+` sign); UUIDs lowercase; adapter GUIDs lowercase brace-free.
//! * Explicit nulls, bounded arrays/strings, no unknown fields.
//! * SHA-256 digests are corruption/equality detection, not authorization.

use crate::model::{DesiredPlan, Family, Snapshot, Transport};
use serde::{Deserialize, Serialize};

pub const JOURNAL_FORMAT: &str = "yeager-dns-takeover";
pub const JOURNAL_VERSION: u32 = 1;
pub const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DIAGNOSTICS: usize = 100;
pub const MAX_OPERATIONS_PER_ENTRY: usize = 256;
/// Bounded-array cap for entries (spec requires bounded arrays; 1024 is far
/// above any realistic adapter count and keeps the 16 MiB envelope bound).
pub const MAX_ENTRIES: usize = 1024;
/// Bounded-string cap for every free-form string in the schema.
pub const MAX_STRING_BYTES: usize = 8192;
pub const MAX_BOUND_ENDPOINTS: usize = 8;
/// Maintenance admission lease: 10 minutes (never expiry of recovery debt).
pub const MAINTENANCE_LEASE_SECS: i64 = 600;

pub const PRIMARY_FILE: &str = "dns-takeover-v1.json";
pub const STAGE_PREFIX: &str = "dns-takeover-v1.json.stage.";
pub const BACKUP_PREFIX: &str = "dns-takeover-v1.json.bak.";

/// Schema/validation failure. `UnknownVersion` is distinguished from generic
/// corruption because an unknown newer journal must block takeover without
/// being deleted or overwritten (§7 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    TooLarge(usize),
    Bom,
    NotUtf8,
    Json(String),
    UnknownFormat(String),
    UnknownVersion(u32),
    Schema(String),
    DigestMismatch,
    NotCanonical,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::TooLarge(n) => write!(f, "journal exceeds 16 MiB ({n} bytes)"),
            JournalError::Bom => write!(f, "journal has a UTF-8 BOM"),
            JournalError::NotUtf8 => write!(f, "journal is not valid UTF-8"),
            JournalError::Json(m) => write!(f, "journal JSON invalid: {m}"),
            JournalError::UnknownFormat(s) => write!(f, "unknown journal format {s:?}"),
            JournalError::UnknownVersion(v) => write!(f, "unknown journal version {v}"),
            JournalError::Schema(m) => write!(f, "journal schema violation: {m}"),
            JournalError::DigestMismatch => write!(f, "journal payload digest mismatch"),
            JournalError::NotCanonical => write!(f, "journal bytes are not canonical"),
        }
    }
}

impl std::error::Error for JournalError {}

/// serde helper: u64 as a *normalized* decimal string. Unlike the U01 capture
/// helper this rejects non-canonical spellings ("007", "+5") on decode, because
/// the journal canonical form is byte-exact.
pub(crate) mod norm_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        let v: u64 = s.parse().map_err(serde::de::Error::custom)?;
        if s != v.to_string() {
            return Err(serde::de::Error::custom(format!(
                "non-normalized decimal string {s:?}"
            )));
        }
        Ok(v)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Clean,
    Owned,
    Restoring,
    RecoveryPending,
    Maintenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Takeover,
    LegacyRepair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Applying,
    Active,
    Reconfiguring,
    Quiescing,
    Restoring,
    Pending,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineKind {
    PreTakeover,
    LegacyCurrent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    Captured,
    ApplyIntent,
    Applied,
    RestoreIntent,
    RestoredVerified,
    Deferred,
    Conflict,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationKind {
    Original,
    Applied,
    LegacyTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Apply,
    Reconfigure,
    Restore,
    LegacyDhcpRepair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Intent,
    CallReturned,
    Verified,
    Failed,
    Conflict,
    Deferred,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteFacet {
    Nameserver,
    ServerProperties,
}

/// Durable clean tombstone (§3.3): written only after every entry has a fresh
/// verified target; retained across clean generations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    pub transaction_id: String,
    pub verified_at_utc: String,
    #[serde(with = "norm_u64")]
    pub completed_generation: u64,
}

/// Maintenance admission lease (10 minutes). Never expires recovery debt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maintenance {
    pub id: String,
    pub caller_identity: String,
    pub started_at_utc: String,
    pub expires_at_utc: String,
    pub phase: String,
}

/// One structured diagnostic. Entries carrying the live transaction id are
/// protected from the latest-100 truncation (§3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub at_utc: String,
    pub transaction_id: Option<String>,
    pub kind: String,
    pub message: String,
}

/// Owner process identity: PID + creation FILETIME + held handle prevent PID
/// reuse (§3.2). Image fields are diagnostics/authentication, not death proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerIdentity {
    pub owner_id: String,
    pub pid: u32,
    #[serde(with = "norm_u64")]
    pub creation_time_filetime: u64,
    pub user_sid: String,
    #[serde(with = "norm_u64")]
    pub logon_luid: u64,
    pub session_id: u32,
    pub image_path: String,
    pub image_file_id: String,
    pub image_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub snapshot: Snapshot,
    pub fingerprint: String,
    pub observed_at_utc: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryState {
    pub attempts: u32,
    pub next_attempt_utc: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub kind: VerificationKind,
    pub fingerprint: String,
    pub observed_at_utc: String,
    #[serde(with = "norm_u64")]
    pub generation: u64,
}

/// One durable per-call before/target intent. A durable intent means the API
/// MAY have run even without call_returned/api_started_at (§3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub request_id: String,
    pub ordinal: u32,
    pub kind: OperationKind,
    pub state: OperationState,
    pub before: Snapshot,
    pub before_fingerprint: String,
    pub target: Snapshot,
    pub target_fingerprint: String,
    pub write_mask: Vec<WriteFacet>,
    #[serde(with = "norm_u64")]
    pub intent_generation: u64,
    pub api_started_at: Option<String>,
    pub api_finished_at: Option<String>,
    pub windows_status: Option<u32>,
    pub observed_after: Option<Snapshot>,
    pub observed_fingerprint: Option<String>,
    pub attempts: u32,
    pub error: Option<String>,
}

/// One adapter GUID × family journal entry. The original is immutable; hints
/// detect reincarnation but never substitute for the GUID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub adapter_guid: String,
    pub family: Family,
    pub name_hint: String,
    pub device_instance_hint: Option<String>,
    pub original_if_index: Option<u32>,
    #[serde(with = "norm_u64")]
    pub original_luid: u64,
    pub first_captured_at_utc: String,
    pub original: Snapshot,
    pub original_fingerprint: String,
    pub baseline_kind: BaselineKind,
    pub previous_committed: Option<Snapshot>,
    pub previous_fingerprint: Option<String>,
    pub intended: Option<Snapshot>,
    pub intended_fingerprint: Option<String>,
    pub applied_fingerprint: Option<String>,
    #[serde(with = "norm_u64")]
    pub plan_revision: u64,
    pub operations: Vec<Operation>,
    pub state: EntryState,
    pub last_observed: Option<Observation>,
    pub retry: RetryState,
    pub verification: Option<Verification>,
    pub approved_legacy_target: Option<Snapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub id: String,
    pub created_at_utc: String,
    pub updated_at_utc: String,
    pub reason: Reason,
    pub phase: Phase,
    pub owner: OwnerIdentity,
    #[serde(with = "norm_u64")]
    pub epoch: u64,
    pub admission: Admission,
    pub desired: DesiredPlan,
    pub service_instance_id: String,
    pub registered_at_utc: String,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub journal_state: JournalState,
    pub transaction: Option<Transaction>,
    pub last_completed: Option<Tombstone>,
    pub maintenance: Option<Maintenance>,
    pub diagnostics: Vec<Diagnostic>,
}

/// The complete v1 envelope. `payload_digest` covers the canonical
/// identity/version/generation/previous_digest and payload, excluding itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub version: u32,
    pub machine_id: String,
    #[serde(with = "norm_u64")]
    pub generation: u64,
    pub previous_digest: Option<String>,
    pub payload_digest: String,
    pub payload: Payload,
}

impl Envelope {
    pub fn is_clean_tombstone(&self) -> bool {
        self.payload.journal_state == JournalState::Clean
            && self.payload.transaction.is_none()
            && self.payload.last_completed.is_some()
    }
}

// ---- validation -----------------------------------------------------------

pub fn is_lower_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_digit() && !(*c >= b'a' && *c <= b'f') {
                    return false;
                }
            }
        }
    }
    true
}

pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Parse the schema's second-precision UTC timestamps to epoch seconds.
pub fn parse_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = &s[r];
        if !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    let y = num(0..4)?;
    let mo = num(5..7)?;
    let d = num(8..10)?;
    let h = num(11..13)?;
    let mi = num(14..16)?;
    let sec = num(17..19)?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    // days from civil (inverse of the backend's civil_from_days)
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + sec)
}

fn schema_err<T>(m: impl Into<String>) -> Result<T, JournalError> {
    Err(JournalError::Schema(m.into()))
}

fn check_string(name: &str, s: &str) -> Result<(), JournalError> {
    if s.len() > MAX_STRING_BYTES {
        return schema_err(format!("{name} exceeds {MAX_STRING_BYTES} bytes"));
    }
    Ok(())
}

fn check_opt_string(name: &str, s: &Option<String>) -> Result<(), JournalError> {
    if let Some(s) = s {
        check_string(name, s)?;
    }
    Ok(())
}

fn check_utc(name: &str, s: &str) -> Result<(), JournalError> {
    if parse_utc(s).is_none() {
        return schema_err(format!("{name} is not a UTC timestamp: {s:?}"));
    }
    Ok(())
}

fn check_opt_utc(name: &str, s: &Option<String>) -> Result<(), JournalError> {
    if let Some(s) = s {
        check_utc(name, s)?;
    }
    Ok(())
}

fn check_uuid(name: &str, s: &str) -> Result<(), JournalError> {
    if !is_lower_uuid(s) {
        return schema_err(format!("{name} is not a lowercase UUID: {s:?}"));
    }
    Ok(())
}

fn check_digest(name: &str, s: &str) -> Result<(), JournalError> {
    if !is_sha256_hex(s) {
        return schema_err(format!("{name} is not lowercase SHA-256 hex: {s:?}"));
    }
    Ok(())
}

fn check_snapshot(name: &str, s: &Snapshot) -> Result<(), JournalError> {
    if s.schema_version != 1 {
        return schema_err(format!("{name}: unknown snapshot schema_version {}", s.schema_version));
    }
    check_string("snapshot.name_server_raw", &s.name_server_raw.clone().unwrap_or_default())?;
    check_string("snapshot.registry_path", &s.provenance_evidence.registry_path)?;
    check_utc("snapshot.captured_at_utc", &s.provenance_evidence.captured_at_utc)?;
    if s.ordered_servers.len() > 64 {
        return schema_err(format!("{name}: too many ordered servers"));
    }
    if s.server_properties.len() > 64 {
        return schema_err(format!("{name}: too many server properties"));
    }
    for p in &s.server_properties {
        if p.server_index as usize >= s.ordered_servers.len() {
            return schema_err(format!("{name}: property index {} out of range", p.server_index));
        }
        check_opt_string("property.template", &p.doh.template)?;
    }
    Ok(())
}

fn check_opt_snapshot(name: &str, s: &Option<Snapshot>) -> Result<(), JournalError> {
    if let Some(s) = s {
        check_snapshot(name, s)?;
    }
    Ok(())
}

fn check_plan(plan: &DesiredPlan) -> Result<(), JournalError> {
    if plan.bound_endpoints.len() > MAX_BOUND_ENDPOINTS {
        return schema_err("desired.bound_endpoints exceeds bound");
    }
    let mut v4_udp = false;
    let mut v4_tcp = false;
    let mut v6_udp = false;
    let mut v6_tcp = false;
    for e in &plan.bound_endpoints {
        if !e.ip.is_loopback() || e.port != 53 {
            return schema_err("bound_endpoints allow loopback port 53 only");
        }
        match (e.ip.is_ipv4(), e.transport) {
            (true, Transport::Udp) => v4_udp = true,
            (true, Transport::Tcp) => v4_tcp = true,
            (false, Transport::Udp) => v6_udp = true,
            (false, Transport::Tcp) => v6_tcp = true,
        }
    }
    // An advertised family requires UDP+TCP readiness.
    if (v4_udp || v4_tcp) && !(v4_udp && v4_tcp) {
        return schema_err("advertised IPv4 endpoint family lacks UDP+TCP readiness");
    }
    if (v6_udp || v6_tcp) && !(v6_udp && v6_tcp) {
        return schema_err("advertised IPv6 endpoint family lacks UDP+TCP readiness");
    }
    if plan.local_requested && plan.bound_endpoints.is_empty() {
        return schema_err("local_requested without bound loopback endpoints");
    }
    Ok(())
}

fn check_operation(op: &Operation, generation: u64) -> Result<(), JournalError> {
    check_uuid("operation.id", &op.id)?;
    check_uuid("operation.request_id", &op.request_id)?;
    check_snapshot("operation.before", &op.before)?;
    check_snapshot("operation.target", &op.target)?;
    check_digest("operation.before_fingerprint", &op.before_fingerprint)?;
    check_digest("operation.target_fingerprint", &op.target_fingerprint)?;
    if op.before_fingerprint != op.before.fingerprint() {
        return schema_err("operation.before_fingerprint does not match before snapshot");
    }
    if op.target_fingerprint != op.target.fingerprint() {
        return schema_err("operation.target_fingerprint does not match target snapshot");
    }
    if op.write_mask.is_empty() || op.write_mask.len() > 2 {
        return schema_err("operation.write_mask must name 1..2 facets");
    }
    if op.write_mask.windows(2).any(|w| w[0] == w[1]) {
        return schema_err("operation.write_mask has duplicate facets");
    }
    if op.intent_generation > generation {
        return schema_err("operation.intent_generation exceeds envelope generation");
    }
    check_opt_utc("operation.api_started_at", &op.api_started_at)?;
    check_opt_utc("operation.api_finished_at", &op.api_finished_at)?;
    check_opt_snapshot("operation.observed_after", &op.observed_after)?;
    if let Some(fp) = &op.observed_fingerprint {
        check_digest("operation.observed_fingerprint", fp)?;
        let Some(obs) = &op.observed_after else {
            return schema_err("operation.observed_fingerprint without observed_after");
        };
        if *fp != obs.fingerprint() {
            return schema_err("operation.observed_fingerprint does not match observed_after");
        }
    }
    check_opt_string("operation.error", &op.error)?;
    Ok(())
}

fn check_entry(e: &Entry, reason: Reason, generation: u64) -> Result<(), JournalError> {
    if !is_lower_uuid(&e.adapter_guid) {
        return schema_err(format!("entry.adapter_guid not lowercase brace-free UUID: {:?}", e.adapter_guid));
    }
    check_string("entry.name_hint", &e.name_hint)?;
    check_opt_string("entry.device_instance_hint", &e.device_instance_hint)?;
    check_utc("entry.first_captured_at_utc", &e.first_captured_at_utc)?;
    check_snapshot("entry.original", &e.original)?;
    check_digest("entry.original_fingerprint", &e.original_fingerprint)?;
    if e.original_fingerprint != e.original.fingerprint() {
        return schema_err("entry.original_fingerprint does not match original snapshot");
    }
    if e.original.family != e.family {
        return schema_err("entry.original family does not match entry family");
    }
    match (reason, e.baseline_kind) {
        (Reason::Takeover, BaselineKind::PreTakeover) => {}
        (Reason::LegacyRepair, BaselineKind::LegacyCurrent) => {}
        _ => return schema_err("entry.baseline_kind does not match transaction reason"),
    }
    check_opt_snapshot("entry.previous_committed", &e.previous_committed)?;
    if let Some(fp) = &e.previous_fingerprint {
        check_digest("entry.previous_fingerprint", fp)?;
        let Some(s) = &e.previous_committed else {
            return schema_err("entry.previous_fingerprint without previous_committed");
        };
        if *fp != s.fingerprint() {
            return schema_err("entry.previous_fingerprint does not match previous_committed");
        }
    }
    check_opt_snapshot("entry.intended", &e.intended)?;
    if let Some(fp) = &e.intended_fingerprint {
        check_digest("entry.intended_fingerprint", fp)?;
        let Some(s) = &e.intended else {
            return schema_err("entry.intended_fingerprint without intended");
        };
        if *fp != s.fingerprint() {
            return schema_err("entry.intended_fingerprint does not match intended");
        }
    }
    if let Some(fp) = &e.applied_fingerprint {
        check_digest("entry.applied_fingerprint", fp)?;
        // Only after verified readback: some verified operation must carry it.
        if !e.operations.iter().any(|o| o.state == OperationState::Verified && o.target_fingerprint == *fp) {
            return schema_err("entry.applied_fingerprint without a verified readback operation");
        }
    }
    if e.operations.len() > MAX_OPERATIONS_PER_ENTRY {
        return schema_err(format!("entry.operations exceeds {MAX_OPERATIONS_PER_ENTRY}"));
    }
    let mut last_ordinal: Option<u32> = None;
    for op in &e.operations {
        if let Some(prev) = last_ordinal {
            if op.ordinal <= prev {
                return schema_err("entry.operations ordinals must be strictly increasing");
            }
        }
        last_ordinal = Some(op.ordinal);
        check_operation(op, generation)?;
    }
    if let Some(obs) = &e.last_observed {
        check_snapshot("entry.last_observed.snapshot", &obs.snapshot)?;
        check_digest("entry.last_observed.fingerprint", &obs.fingerprint)?;
        if obs.fingerprint != obs.snapshot.fingerprint() {
            return schema_err("entry.last_observed.fingerprint does not match snapshot");
        }
        check_utc("entry.last_observed.observed_at_utc", &obs.observed_at_utc)?;
    }
    check_opt_utc("entry.retry.next_attempt_utc", &e.retry.next_attempt_utc)?;
    check_opt_string("entry.retry.last_error", &e.retry.last_error)?;
    if let Some(v) = &e.verification {
        check_digest("entry.verification.fingerprint", &v.fingerprint)?;
        check_utc("entry.verification.observed_at_utc", &v.observed_at_utc)?;
        if v.generation > generation {
            return schema_err("entry.verification.generation exceeds envelope generation");
        }
        match v.kind {
            VerificationKind::Original => {
                if v.fingerprint != e.original_fingerprint {
                    return schema_err("original verification fingerprint != original_fingerprint");
                }
            }
            VerificationKind::Applied => {
                if !e.operations.iter().any(|o| o.state == OperationState::Verified && o.target_fingerprint == v.fingerprint) {
                    return schema_err("applied verification without matching verified operation");
                }
            }
            VerificationKind::LegacyTarget => {
                let Some(t) = &e.approved_legacy_target else {
                    return schema_err("legacy_target verification without approved_legacy_target");
                };
                if v.fingerprint != t.fingerprint() {
                    return schema_err("legacy_target verification fingerprint != approved target");
                }
            }
        }
    }
    match (&e.approved_legacy_target, reason) {
        (Some(t), Reason::LegacyRepair) => check_snapshot("entry.approved_legacy_target", t)?,
        (None, _) => {}
        (Some(_), Reason::Takeover) => {
            return schema_err("approved_legacy_target forbidden for normal takeover");
        }
    }
    Ok(())
}

/// Full semantic validation of a decoded envelope (the codec additionally
/// checks digests and canonical bytes).
pub fn validate(env: &Envelope) -> Result<(), JournalError> {
    if env.format != JOURNAL_FORMAT {
        return Err(JournalError::UnknownFormat(env.format.clone()));
    }
    if env.version != JOURNAL_VERSION {
        return Err(JournalError::UnknownVersion(env.version));
    }
    check_uuid("machine_id", &env.machine_id)?;
    check_digest("payload_digest", &env.payload_digest)?;
    if let Some(d) = &env.previous_digest {
        check_digest("previous_digest", d)?;
    }
    let p = &env.payload;
    match p.journal_state {
        JournalState::Clean => {
            if p.transaction.is_some() {
                return schema_err("clean journal must have transaction=null");
            }
            if p.last_completed.is_none() && env.generation != 1 {
                return schema_err("clean journal without tombstone only allowed at genesis");
            }
        }
        JournalState::Maintenance => {
            if p.maintenance.is_none() {
                return schema_err("maintenance journal requires maintenance lease");
            }
        }
        _ => {
            if p.transaction.is_none() {
                return schema_err("owned/restoring/recovery_pending journal requires a transaction");
            }
        }
    }
    if let Some(t) = &p.last_completed {
        check_uuid("last_completed.transaction_id", &t.transaction_id)?;
        check_utc("last_completed.verified_at_utc", &t.verified_at_utc)?;
        if t.completed_generation > env.generation {
            return schema_err("last_completed.completed_generation exceeds envelope generation");
        }
    }
    if let Some(m) = &p.maintenance {
        check_uuid("maintenance.id", &m.id)?;
        check_string("maintenance.caller_identity", &m.caller_identity)?;
        check_string("maintenance.phase", &m.phase)?;
        let start = parse_utc(&m.started_at_utc)
            .ok_or_else(|| JournalError::Schema("maintenance.started_at_utc invalid".into()))?;
        let end = parse_utc(&m.expires_at_utc)
            .ok_or_else(|| JournalError::Schema("maintenance.expires_at_utc invalid".into()))?;
        if end <= start || end - start > MAINTENANCE_LEASE_SECS {
            return schema_err("maintenance lease must be within 10 minutes");
        }
    }
    if p.diagnostics.len() > MAX_DIAGNOSTICS {
        return schema_err(format!("diagnostics exceeds {MAX_DIAGNOSTICS}"));
    }
    for d in &p.diagnostics {
        check_utc("diagnostic.at_utc", &d.at_utc)?;
        check_opt_string("diagnostic.transaction_id", &d.transaction_id)?;
        if let Some(id) = &d.transaction_id {
            check_uuid("diagnostic.transaction_id", id)?;
        }
        check_string("diagnostic.kind", &d.kind)?;
        check_string("diagnostic.message", &d.message)?;
    }
    if let Some(tx) = &p.transaction {
        check_uuid("transaction.id", &tx.id)?;
        check_utc("transaction.created_at_utc", &tx.created_at_utc)?;
        check_utc("transaction.updated_at_utc", &tx.updated_at_utc)?;
        check_uuid("transaction.owner.owner_id", &tx.owner.owner_id)?;
        check_string("transaction.owner.user_sid", &tx.owner.user_sid)?;
        check_string("transaction.owner.image_path", &tx.owner.image_path)?;
        check_string("transaction.owner.image_file_id", &tx.owner.image_file_id)?;
        check_digest("transaction.owner.image_sha256", &tx.owner.image_sha256)?;
        check_plan(&tx.desired)?;
        check_uuid("transaction.service_instance_id", &tx.service_instance_id)?;
        check_utc("transaction.registered_at_utc", &tx.registered_at_utc)?;
        if tx.entries.len() > MAX_ENTRIES {
            return schema_err(format!("transaction.entries exceeds {MAX_ENTRIES}"));
        }
        let mut seen = std::collections::HashSet::new();
        for e in &tx.entries {
            if !seen.insert((e.adapter_guid.clone(), e.family)) {
                return schema_err("duplicate entry for adapter GUID/family");
            }
            check_entry(e, tx.reason, env.generation)?;
        }
    }
    Ok(())
}

/// Latest-100 diagnostics truncation that never removes entries belonging to
/// the live transaction (§3.2). Returns the retained list (newest last).
pub fn truncate_diagnostics(diags: &[Diagnostic], live_transaction: Option<&str>) -> Vec<Diagnostic> {
    if diags.len() <= MAX_DIAGNOSTICS {
        return diags.to_vec();
    }
    let is_prot = |d: &Diagnostic| {
        live_transaction.is_some() && d.transaction_id.as_deref() == live_transaction
    };
    let protected_count = diags.iter().filter(|d| is_prot(d)).count();
    let room = MAX_DIAGNOSTICS.saturating_sub(protected_count);
    let non_prot: Vec<usize> = diags
        .iter()
        .enumerate()
        .filter(|(_, d)| !is_prot(d))
        .map(|(i, _)| i)
        .collect();
    let keep_from = non_prot.len().saturating_sub(room);
    let keep: std::collections::HashSet<usize> = non_prot[keep_from..].iter().copied().collect();
    diags
        .iter()
        .enumerate()
        .filter(|(i, d)| is_prot(d) || keep.contains(i))
        .map(|(_, d)| d.clone())
        .collect()
}

/// Fresh lowercase UUID v4. Entropy comes from the OS-seeded `RandomState`
/// (two independent SipHash keys) plus time/counter domain separation; no
/// external RNG dependency is needed for a machine identifier.
pub fn new_uuid() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let stack_marker = &n as *const u64 as u64;
    let mut h1 = RandomState::new().build_hasher();
    h1.write_u64(nanos);
    h1.write_u64(n);
    h1.write_u64(stack_marker);
    let a = h1.finish();
    let mut h2 = RandomState::new().build_hasher();
    h2.write_u64(a);
    h2.write_u64(nanos.rotate_left(32));
    h2.write_u64(n.wrapping_mul(0x9E3779B97F4A7C15));
    let b = h2.finish();
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..].copy_from_slice(&b.to_le_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
    let hex: String = bytes.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

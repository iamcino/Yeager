//! Strict canonical journal codec (U02, SPEC-DNS-FIX.md §3.2).
//!
//! Encoding is manual canonical JSON: compact, lexicographic keys (serde_json
//! BTreeMap), array order preserved, u64 as normalized decimal strings and
//! *explicit nulls* for every nullable field. The U01 capture model's serde
//! attributes (e.g. `CanonicalServer.scope` skip-if-none) are deliberately not
//! reused for journal bytes — the journal owns its canonical form.
//!
//! Decoding order is strict: size cap → BOM rejection → UTF-8 → duplicate-key
//! scan → version/format gate → typed decode (deny_unknown_fields) → semantic
//! validation → payload digest → byte-canonical equality. Any failure refuses
//! the candidate; nothing is repaired silently.

use crate::journal::*;
use crate::model::{
    CanonicalServer, DesiredPlan, DnsContext, DohSettings, Provenance, ProvenanceEvidence,
    ServerProperty, Snapshot,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn u64s(v: u64) -> Value {
    Value::String(v.to_string())
}

fn opt_str(v: &Option<String>) -> Value {
    match v {
        Some(s) => Value::String(s.clone()),
        None => Value::Null,
    }
}

fn opt_u32(v: Option<u32>) -> Value {
    match v {
        Some(n) => json!(n),
        None => Value::Null,
    }
}

// ---- canonical value builders ---------------------------------------------

fn server_value(c: &CanonicalServer) -> Value {
    json!({
        "address": c.address.to_string(),
        "scope": opt_u32(c.scope),
    })
}

fn doh_value(d: &DohSettings) -> Value {
    json!({
        "template": opt_str(&d.template),
        "flags": u64s(d.flags),
    })
}

fn property_value(p: &ServerProperty) -> Value {
    json!({
        "version": p.version,
        "server_index": p.server_index,
        "type": p.prop_type,
        "doh": doh_value(&p.doh),
    })
}

fn properties_value(ps: &[ServerProperty]) -> Value {
    Value::Array(ps.iter().map(property_value).collect())
}

fn evidence_value(e: &ProvenanceEvidence) -> Value {
    json!({
        "registry_path": e.registry_path,
        "value_exists": e.value_exists,
        "value_type": opt_u32(e.value_type),
        "raw_value_base64": opt_str(&e.raw_value_base64),
        "api_flags": u64s(e.api_flags),
        "captured_at_utc": e.captured_at_utc,
    })
}

fn context_value(c: &DnsContext) -> Value {
    json!({
        "interface_flags": u64s(c.interface_flags),
        "profile_name_server": opt_str(&c.profile_name_server),
        "profile_server_properties": properties_value(&c.profile_server_properties),
        "domain": opt_str(&c.domain),
        "search_list": opt_str(&c.search_list),
        "registration_enabled": c.registration_enabled,
        "register_adapter_name": c.register_adapter_name,
        "enable_llmnr": c.enable_llmnr,
        "query_adapter_name": c.query_adapter_name,
        "disable_unconstrained_queries": c.disable_unconstrained_queries,
        "supplemental_search_list": opt_str(&c.supplemental_search_list),
    })
}

fn snapshot_value(s: &Snapshot) -> Value {
    json!({
        "schema_version": s.schema_version,
        "family": s.family.as_str(),
        "provenance": match s.provenance {
            Provenance::Automatic => "automatic",
            Provenance::Static => "static",
        },
        "name_server_raw": opt_str(&s.name_server_raw),
        "ordered_servers": Value::Array(s.ordered_servers.iter().map(server_value).collect()),
        "provenance_evidence": evidence_value(&s.provenance_evidence),
        "server_properties": properties_value(&s.server_properties),
        "context": context_value(&s.context),
        "capability": {
            "os_build": s.capability.os_build,
            "reader_revision": s.capability.reader_revision,
            "api_version": s.capability.api_version,
            "family_supported": s.capability.family_supported,
        },
    })
}

fn opt_snapshot_value(s: &Option<Snapshot>) -> Value {
    match s {
        Some(s) => snapshot_value(s),
        None => Value::Null,
    }
}

fn plan_value(p: &DesiredPlan) -> Value {
    json!({
        "provider": match p.provider {
            crate::model::Provider::Auto => "auto",
            crate::model::Provider::Cloudflare => "cloudflare",
            crate::model::Provider::Google => "google",
            crate::model::Provider::Adguard => "adguard",
        },
        "local_requested": p.local_requested,
        "bound_endpoints": Value::Array(
            p.bound_endpoints
                .iter()
                .map(|e| {
                    json!({
                        "ip": e.ip.to_string(),
                        "port": e.port,
                        "transport": match e.transport {
                            crate::model::Transport::Udp => "udp",
                            crate::model::Transport::Tcp => "tcp",
                        },
                    })
                })
                .collect(),
        ),
        "readiness_generation": u64s(p.readiness_generation),
    })
}

fn owner_value(o: &OwnerIdentity) -> Value {
    json!({
        "owner_id": o.owner_id,
        "pid": o.pid,
        "creation_time_filetime": u64s(o.creation_time_filetime),
        "user_sid": o.user_sid,
        "logon_luid": u64s(o.logon_luid),
        "session_id": o.session_id,
        "image_path": o.image_path,
        "image_file_id": o.image_file_id,
        "image_sha256": o.image_sha256,
    })
}

fn operation_value(o: &Operation) -> Value {
    json!({
        "id": o.id,
        "request_id": o.request_id,
        "ordinal": o.ordinal,
        "kind": match o.kind {
            OperationKind::Apply => "apply",
            OperationKind::Reconfigure => "reconfigure",
            OperationKind::Restore => "restore",
            OperationKind::LegacyDhcpRepair => "legacy_dhcp_repair",
        },
        "state": match o.state {
            OperationState::Intent => "intent",
            OperationState::CallReturned => "call_returned",
            OperationState::Verified => "verified",
            OperationState::Failed => "failed",
            OperationState::Conflict => "conflict",
            OperationState::Deferred => "deferred",
        },
        "before": snapshot_value(&o.before),
        "before_fingerprint": o.before_fingerprint,
        "target": snapshot_value(&o.target),
        "target_fingerprint": o.target_fingerprint,
        "write_mask": Value::Array(
            o.write_mask
                .iter()
                .map(|f| match f {
                    WriteFacet::Nameserver => json!("nameserver"),
                    WriteFacet::ServerProperties => json!("server_properties"),
                })
                .collect(),
        ),
        "intent_generation": u64s(o.intent_generation),
        "api_started_at": opt_str(&o.api_started_at),
        "api_finished_at": opt_str(&o.api_finished_at),
        "windows_status": opt_u32(o.windows_status),
        "observed_after": opt_snapshot_value(&o.observed_after),
        "observed_fingerprint": opt_str(&o.observed_fingerprint),
        "attempts": o.attempts,
        "error": opt_str(&o.error),
    })
}

fn observation_value(o: &Observation) -> Value {
    json!({
        "snapshot": snapshot_value(&o.snapshot),
        "fingerprint": o.fingerprint,
        "observed_at_utc": o.observed_at_utc,
    })
}

fn entry_value(e: &Entry) -> Value {
    json!({
        "adapter_guid": e.adapter_guid,
        "family": e.family.as_str(),
        "name_hint": e.name_hint,
        "device_instance_hint": opt_str(&e.device_instance_hint),
        "original_if_index": opt_u32(e.original_if_index),
        "original_luid": u64s(e.original_luid),
        "first_captured_at_utc": e.first_captured_at_utc,
        "original": snapshot_value(&e.original),
        "original_fingerprint": e.original_fingerprint,
        "baseline_kind": match e.baseline_kind {
            BaselineKind::PreTakeover => "pre_takeover",
            BaselineKind::LegacyCurrent => "legacy_current",
        },
        "previous_committed": opt_snapshot_value(&e.previous_committed),
        "previous_fingerprint": opt_str(&e.previous_fingerprint),
        "intended": opt_snapshot_value(&e.intended),
        "intended_fingerprint": opt_str(&e.intended_fingerprint),
        "applied_fingerprint": opt_str(&e.applied_fingerprint),
        "plan_revision": u64s(e.plan_revision),
        "operations": Value::Array(e.operations.iter().map(operation_value).collect()),
        "state": match e.state {
            EntryState::Captured => "captured",
            EntryState::ApplyIntent => "apply_intent",
            EntryState::Applied => "applied",
            EntryState::RestoreIntent => "restore_intent",
            EntryState::RestoredVerified => "restored_verified",
            EntryState::Deferred => "deferred",
            EntryState::Conflict => "conflict",
            EntryState::Failed => "failed",
        },
        "last_observed": match &e.last_observed {
            Some(o) => observation_value(o),
            None => Value::Null,
        },
        "retry": {
            "attempts": e.retry.attempts,
            "next_attempt_utc": opt_str(&e.retry.next_attempt_utc),
            "last_error": opt_str(&e.retry.last_error),
        },
        "verification": match &e.verification {
            Some(v) => json!({
                "kind": match v.kind {
                    VerificationKind::Original => "original",
                    VerificationKind::Applied => "applied",
                    VerificationKind::LegacyTarget => "legacy_target",
                },
                "fingerprint": v.fingerprint,
                "observed_at_utc": v.observed_at_utc,
                "generation": u64s(v.generation),
            }),
            None => Value::Null,
        },
        "approved_legacy_target": opt_snapshot_value(&e.approved_legacy_target),
    })
}

fn transaction_value(t: &Transaction) -> Value {
    json!({
        "id": t.id,
        "created_at_utc": t.created_at_utc,
        "updated_at_utc": t.updated_at_utc,
        "reason": match t.reason {
            Reason::Takeover => "takeover",
            Reason::LegacyRepair => "legacy_repair",
        },
        "phase": match t.phase {
            Phase::Preparing => "preparing",
            Phase::Applying => "applying",
            Phase::Active => "active",
            Phase::Reconfiguring => "reconfiguring",
            Phase::Quiescing => "quiescing",
            Phase::Restoring => "restoring",
            Phase::Pending => "pending",
            Phase::Complete => "complete",
        },
        "owner": owner_value(&t.owner),
        "epoch": u64s(t.epoch),
        "admission": match t.admission {
            Admission::Open => "open",
            Admission::Closed => "closed",
        },
        "desired": plan_value(&t.desired),
        "service_instance_id": t.service_instance_id,
        "registered_at_utc": t.registered_at_utc,
        "entries": Value::Array(t.entries.iter().map(entry_value).collect()),
    })
}

fn payload_value(p: &Payload) -> Value {
    json!({
        "journal_state": match p.journal_state {
            JournalState::Clean => "clean",
            JournalState::Owned => "owned",
            JournalState::Restoring => "restoring",
            JournalState::RecoveryPending => "recovery_pending",
            JournalState::Maintenance => "maintenance",
        },
        "transaction": match &p.transaction {
            Some(t) => transaction_value(t),
            None => Value::Null,
        },
        "last_completed": match &p.last_completed {
            Some(t) => json!({
                "transaction_id": t.transaction_id,
                "verified_at_utc": t.verified_at_utc,
                "completed_generation": u64s(t.completed_generation),
            }),
            None => Value::Null,
        },
        "maintenance": match &p.maintenance {
            Some(m) => json!({
                "id": m.id,
                "caller_identity": m.caller_identity,
                "started_at_utc": m.started_at_utc,
                "expires_at_utc": m.expires_at_utc,
                "phase": m.phase,
            }),
            None => Value::Null,
        },
        "diagnostics": Value::Array(
            p.diagnostics
                .iter()
                .map(|d| {
                    json!({
                        "at_utc": d.at_utc,
                        "transaction_id": opt_str(&d.transaction_id),
                        "kind": d.kind,
                        "message": d.message,
                    })
                })
                .collect(),
        ),
    })
}

/// Canonical identity object: everything the payload digest covers.
fn identity_value(env: &Envelope) -> Value {
    json!({
        "format": env.format,
        "version": env.version,
        "machine_id": env.machine_id,
        "generation": u64s(env.generation),
        "previous_digest": opt_str(&env.previous_digest),
        "payload": payload_value(&env.payload),
    })
}

fn envelope_value(env: &Envelope) -> Value {
    json!({
        "format": env.format,
        "version": env.version,
        "machine_id": env.machine_id,
        "generation": u64s(env.generation),
        "previous_digest": opt_str(&env.previous_digest),
        "payload_digest": env.payload_digest,
        "payload": payload_value(&env.payload),
    })
}

// ---- digests / encode ------------------------------------------------------

/// SHA-256 over the canonical identity object (excludes payload_digest itself).
pub fn compute_payload_digest(env: &Envelope) -> String {
    let bytes = serde_json::to_vec(&identity_value(env)).expect("identity value serializes");
    sha256_hex(&bytes)
}

/// Set `payload_digest` from the current envelope contents.
pub fn seal(env: &mut Envelope) {
    env.payload_digest = compute_payload_digest(env);
}

/// Canonical compact UTF-8 bytes (no BOM, explicit nulls, sorted keys).
pub fn encode(env: &Envelope) -> Vec<u8> {
    serde_json::to_vec(&envelope_value(env)).expect("envelope value serializes")
}

/// SHA-256 of the full canonical envelope bytes — the lineage digest stored in
/// the *next* generation's `previous_digest`.
pub fn envelope_digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

// ---- duplicate-key scan ----------------------------------------------------

/// Consume a JSON string starting at `s[i] == '"'`; return (decoded, next_i).
fn scan_string(s: &str, i: usize) -> Result<(String, usize), JournalError> {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'"' => return Ok((out, j + 1)),
            b'\\' => {
                j += 1;
                if j >= b.len() {
                    return Err(JournalError::Json("unterminated escape".into()));
                }
                match b[j] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let cp = scan_hex4(s, j + 1)?;
                        j += 4;
                        let ch = if (0xD800..0xDC00).contains(&cp) {
                            // high surrogate: require a following \uXXXX low pair
                            if j + 2 < b.len() && b[j + 1] == b'\\' && b[j + 2] == b'u' {
                                let lo = scan_hex4(s, j + 3)?;
                                if (0xDC00..0xE000).contains(&lo) {
                                    j += 6;
                                    let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    char::from_u32(c).unwrap_or('\u{FFFD}')
                                } else {
                                    '\u{FFFD}'
                                }
                            } else {
                                '\u{FFFD}'
                            }
                        } else {
                            char::from_u32(cp).unwrap_or('\u{FFFD}')
                        };
                        out.push(ch);
                    }
                    _ => return Err(JournalError::Json("bad escape".into())),
                }
                j += 1;
            }
            c if c < 0x20 => return Err(JournalError::Json("control char in string".into())),
            _ => {
                // copy one UTF-8 char
                let start = j;
                j += 1;
                while j < b.len() && (b[j] & 0xC0) == 0x80 {
                    j += 1;
                }
                out.push_str(&s[start..j]);
            }
        }
    }
    Err(JournalError::Json("unterminated string".into()))
}

fn scan_hex4(s: &str, i: usize) -> Result<u32, JournalError> {
    let b = s.as_bytes();
    if i + 4 > b.len() {
        return Err(JournalError::Json("truncated \\u escape".into()));
    }
    let t = &s[i..i + 4];
    u32::from_str_radix(t, 16).map_err(|_| JournalError::Json("bad \\u escape".into()))
}

/// Reject duplicate object keys at any depth (serde_json would silently keep
/// the last). Structural validity beyond this is left to serde_json.
fn scan_duplicate_keys(s: &str) -> Result<(), JournalError> {
    #[derive(Default)]
    struct Frame {
        keys: std::collections::HashSet<String>,
    }
    let b = s.as_bytes();
    let mut stack: Vec<Option<Frame>> = Vec::new(); // Some = object, None = array
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let (key, next) = scan_string(s, i)?;
                // A string is an object key iff the next significant char is ':'.
                let mut k = next;
                while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\n' | b'\r') {
                    k += 1;
                }
                if k < b.len() && b[k] == b':' {
                    if let Some(Some(frame)) = stack.last_mut() {
                        if frame.keys.contains(&key) {
                            return Err(JournalError::Json(format!("duplicate object key {key:?}")));
                        }
                        frame.keys.insert(key);
                    }
                }
                i = next;
            }
            b'{' => {
                stack.push(Some(Frame::default()));
                i += 1;
            }
            b'}' => {
                stack.pop();
                i += 1;
            }
            b'[' => {
                stack.push(None);
                i += 1;
            }
            b']' => {
                stack.pop();
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

// ---- strict decode ---------------------------------------------------------

/// Strict decode. See module docs for the exact refusal order.
pub fn decode(bytes: &[u8]) -> Result<Envelope, JournalError> {
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::TooLarge(bytes.len()));
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(JournalError::Bom);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| JournalError::NotUtf8)?;
    scan_duplicate_keys(text)?;
    let value: Value = serde_json::from_str(text).map_err(|e| JournalError::Json(e.to_string()))?;
    // Version/format gate before typed decode so an unknown newer version is
    // reported as UnknownVersion, not as a generic unknown-field error.
    let obj = value
        .as_object()
        .ok_or_else(|| JournalError::Schema("journal root is not an object".into()))?;
    match obj.get("version") {
        Some(Value::Number(n)) => {
            let v = n
                .as_u64()
                .filter(|v| *v <= u32::MAX as u64)
                .ok_or_else(|| JournalError::Schema("version is not a u32 integer".into()))?;
            if v != JOURNAL_VERSION as u64 {
                return Err(JournalError::UnknownVersion(v as u32));
            }
        }
        Some(_) => return Err(JournalError::Schema("version is not an integer".into())),
        None => return Err(JournalError::Schema("missing version".into())),
    }
    match obj.get("format") {
        Some(Value::String(f)) if f == JOURNAL_FORMAT => {}
        Some(Value::String(f)) => return Err(JournalError::UnknownFormat(f.clone())),
        _ => return Err(JournalError::Schema("missing format".into())),
    }
    let env: Envelope =
        serde_json::from_value(value).map_err(|e| JournalError::Schema(e.to_string()))?;
    validate(&env)?;
    if env.payload_digest != compute_payload_digest(&env) {
        return Err(JournalError::DigestMismatch);
    }
    if encode(&env) != bytes {
        return Err(JournalError::NotCanonical);
    }
    Ok(env)
}

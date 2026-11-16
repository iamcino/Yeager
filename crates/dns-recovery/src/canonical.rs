//! Canonical configured fingerprint: SHA-256 over compact canonical JSON with
//! lexicographic keys and u64 values rendered as decimal strings. Only the
//! configured fields participate; context/capability/raw evidence do not.

use crate::model::{Provenance, Snapshot};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Canonical JSON value of the configured fields (sorted keys via BTreeMap).
pub fn canonical_value(s: &Snapshot) -> Value {
    json!({
        "family": s.family.as_str(),
        "provenance": match s.provenance {
            Provenance::Automatic => "automatic",
            Provenance::Static => "static",
        },
        "ordered_servers": s
            .ordered_servers
            .iter()
            .map(|c| c.canonical())
            .collect::<Vec<_>>(),
        "server_properties": s
            .server_properties
            .iter()
            .map(|p| {
                json!({
                    "version": p.version,
                    "server_index": p.server_index,
                    "type": p.prop_type,
                    "doh": {
                        "template": p.doh.template,
                        "flags": p.doh.flags.to_string(),
                    },
                })
            })
            .collect::<Vec<_>>(),
    })
}

/// Compact canonical JSON string (deterministic; used for the digest).
pub fn canonical_json(s: &Snapshot) -> String {
    serde_json::to_string(&canonical_value(s)).expect("canonical value serializes")
}

/// Hex SHA-256 fingerprint of the configured fields.
pub fn fingerprint(s: &Snapshot) -> String {
    let bytes = serde_json::to_vec(&canonical_value(s)).expect("canonical value serializes");
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

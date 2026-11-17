//! The one plain DNS backup state file.
//!
//! Before any takeover the controller [`save`]s the captured adapter DNS
//! here; on disable, normal exit, or crash leftover it [`load`]s the file,
//! restores it, and [`delete`]s it. There is no journal, no transaction
//! engine and no states machine — just this file's presence (a takeover is
//! outstanding) or absence (nothing to restore). Every operation is
//! fail-open: a failure degrades the DNS feature only and never blocks the
//! app, the engine, or uninstall.

use crate::system::{AdapterBackup, DohProperty, FamilyBackup};
use common::{Error, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

/// `%ProgramData%\Yeager\dns-backup.json`. `None` if ProgramData is unset.
pub fn path() -> Option<PathBuf> {
    let base = std::env::var_os("ProgramData")?;
    Some(PathBuf::from(base).join("Yeager").join("dns-backup.json"))
}

/// Whether a leftover backup exists (a takeover is outstanding).
pub fn exists() -> bool {
    path().is_some_and(|p| p.exists())
}

/// Serializes the captured state to the backup file, creating the directory
/// if needed. The caller saves this BEFORE pointing adapters at the stub.
pub fn save(backups: &[AdapterBackup]) -> Result<()> {
    let p = path().ok_or_else(|| Error::new("ProgramData is not set"))?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(io_err)?;
    }
    let doc = Value::Array(backups.iter().map(adapter_json).collect());
    let text = serde_json::to_string_pretty(&doc).map_err(|e| Error::new(e.to_string()))?;
    std::fs::write(&p, text).map_err(io_err)
}

/// Reads the backup file back into captured adapter state.
pub fn load() -> Result<Vec<AdapterBackup>> {
    let p = path().ok_or_else(|| Error::new("ProgramData is not set"))?;
    let text = std::fs::read_to_string(&p).map_err(io_err)?;
    let doc: Value = serde_json::from_str(&text).map_err(|e| Error::new(e.to_string()))?;
    let arr = doc.as_array().ok_or_else(|| Error::new("backup is not a list"))?;
    arr.iter().map(adapter_from).collect()
}

/// Removes the backup file. Best effort: a missing file is success.
pub fn delete() {
    if let Some(p) = path() {
        let _ = std::fs::remove_file(p);
    }
}

fn io_err(e: std::io::Error) -> Error {
    Error::new(common::t!("Lỗi tệp sao lưu DNS: {e}", "DNS backup file error: {e}"))
}

fn adapter_json(b: &AdapterBackup) -> Value {
    json!({
        "guid": b.guid,
        "name": b.name,
        "v4": family_json(&b.v4),
        "v6": family_json(&b.v6),
    })
}

fn family_json(f: &FamilyBackup) -> Value {
    json!({
        "name_server": f.name_server,
        "properties": f.properties.iter().map(|p| json!({
            "version": p.version,
            "index": p.index,
            "prop_type": p.prop_type,
            "template": p.template,
            "flags": p.flags,
        })).collect::<Vec<_>>(),
    })
}

fn adapter_from(v: &Value) -> Result<AdapterBackup> {
    let guid = v["guid"].as_str().ok_or_else(|| Error::new("backup adapter missing guid"))?.to_string();
    let name = v["name"].as_str().unwrap_or_default().to_string();
    Ok(AdapterBackup {
        guid,
        name,
        v4: family_from(&v["v4"])?,
        v6: family_from(&v["v6"])?,
    })
}

fn family_from(v: &Value) -> Result<FamilyBackup> {
    let name_server = v["name_server"].as_str().unwrap_or_default().to_string();
    let mut properties = Vec::new();
    if let Some(arr) = v["properties"].as_array() {
        for p in arr {
            properties.push(DohProperty {
                version: p["version"].as_u64().unwrap_or(1) as u32,
                index: p["index"].as_u64().unwrap_or(0) as u32,
                prop_type: p["prop_type"].as_u64().unwrap_or(1) as u32,
                template: p["template"].as_str().map(String::from),
                flags: p["flags"].as_u64().unwrap_or(0),
            });
        }
    }
    Ok(FamilyBackup { name_server, properties })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<AdapterBackup> {
        vec![AdapterBackup {
            guid: "4d36e972-e325-11ce-bfc1-08002be10318".into(),
            name: "Ethernet".into(),
            v4: FamilyBackup {
                name_server: "192.168.1.1,8.8.8.8".into(),
                properties: vec![DohProperty {
                    version: 1,
                    index: 1,
                    prop_type: 1,
                    template: Some("https://dns.google/dns-query".into()),
                    flags: 2,
                }],
            },
            v6: FamilyBackup { name_server: String::new(), properties: Vec::new() },
        }]
    }

    #[test]
    fn json_round_trips_byte_for_byte() {
        let backups = sample();
        let doc = Value::Array(backups.iter().map(adapter_json).collect());
        let text = serde_json::to_string(&doc).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        let back: Vec<AdapterBackup> = parsed.as_array().unwrap().iter().map(adapter_from).collect::<Result<_>>().unwrap();
        assert_eq!(back, backups);
    }

    #[test]
    fn dhcp_empty_family_round_trips() {
        let backups = vec![AdapterBackup {
            guid: "a".into(),
            name: "Wi-Fi".into(),
            v4: FamilyBackup { name_server: String::new(), properties: Vec::new() },
            v6: FamilyBackup { name_server: String::new(), properties: Vec::new() },
        }];
        let doc = Value::Array(backups.iter().map(adapter_json).collect());
        let back: Vec<AdapterBackup> = doc.as_array().unwrap().iter().map(adapter_from).collect::<Result<_>>().unwrap();
        assert_eq!(back, backups);
        assert!(back[0].v4.name_server.is_empty());
    }
}

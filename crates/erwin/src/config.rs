//! Loading and saving the persisted [`Config`] as JSON under `%LOCALAPPDATA%`.

use common::Config;
use std::path::{Path, PathBuf};

/// `%LOCALAPPDATA%\Yeager` (or the OS temp dir as a fallback).
pub fn dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("Yeager")
}

/// `%LOCALAPPDATA%\Yeager\config.json`.
pub fn path() -> PathBuf {
    dir().join("config.json")
}

fn backup(path: &Path) -> PathBuf {
    path.with_extension("json.bak")
}

/// Loads the config, falling back to the last good copy if the file is
/// damaged, then to the default.
pub fn load() -> Config {
    load_from(&path())
}

fn load_from(path: &Path) -> Config {
    let read = |p: &Path| std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str(&s).ok());
    read(path).or_else(|| read(&backup(path))).unwrap_or_default()
}

/// Writes the config without ever leaving a half-written file behind, keeping
/// the previous version as `config.json.bak`.
pub fn save(cfg: &Config) {
    let _ = save_to(&path(), cfg);
}

fn save_to(path: &Path, cfg: &Config) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(cfg)?;
    if std::fs::metadata(path).is_ok_and(|m| m.len() > 0) {
        let _ = std::fs::copy(path, backup(path));
    }
    write_atomic(path, json.as_bytes())
}

/// Writes to a temporary file next to `path`, then renames it over `path`, so a
/// crash or power cut leaves either the old file or the new one.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn survives_a_damaged_file() {
        let dir = std::env::temp_dir().join(format!("erwin-config-test-{}", std::process::id()));
        let path = dir.join("config.json");

        let mut cfg = Config::default();
        cfg.hosts = vec!["example.com".into()];
        save_to(&path, &cfg).unwrap();
        cfg.dark = false;
        save_to(&path, &cfg).unwrap();
        assert_eq!(load_from(&path), cfg);

        // A torn write: the previous version comes back.
        std::fs::write(&path, "{\"scope\":").unwrap();
        let loaded = load_from(&path);
        assert_eq!(loaded.hosts, vec!["example.com".to_string()]);
        assert!(loaded.dark);

        let _ = std::fs::remove_dir_all(dir);
    }
}

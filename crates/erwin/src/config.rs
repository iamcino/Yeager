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
///
/// Geometry is validated independently for the primary file and the `.bak`:
/// a malformed `window_size` field never discards unrelated config. The bad
/// input is preserved in the diagnostic log, only the geometry field is
/// repaired in memory, and the validated replacement is written after
/// successful normal presentation by the app (not here).
pub fn load() -> Config {
    load_from(&path())
}

fn load_one(path: &Path) -> Option<Config> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    if !value.is_object() {
        return None;
    }
    let raw_geometry = value.get("window_size").cloned();
    let mut cfg: Config = match serde_json::from_value(value) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Yeager config: ignoring unreadable {}: {e}", path.display());
            return None;
        }
    };
    // Field-specific migration: tolerate corrupt legacy geometry, keep the
    // rest of the file. `common` deserialization already yields `None` for
    // non-numeric/negative shapes; here we also repair numeric but invalid
    // pairs ([0,0], [1,1], below-minimum, huge) as a pair.
    match (&raw_geometry, cfg.window_size) {
        // Deserialized to a valid pair: keep it.
        (_, Some([w, h])) if common::is_valid_window_size_u32(w, h) => {}
        // No geometry field and no pair, or explicitly null: nothing to repair.
        (None, None) | (Some(serde_json::Value::Null), None) => {}
        // Anything else with a present raw field: preserve the bad input for
        // diagnosis, repair only the geometry field in memory.
        (Some(raw), _) => {
            eprintln!(
                "Yeager config: invalid window_size {raw} in {}; repairing geometry only, keeping other settings",
                path.display()
            );
            cfg.window_size = None;
        }
        // No raw field but an invalid pair (possible programmatically):
        // repair in memory.
        (None, Some([w, h])) => {
            eprintln!(
                "Yeager config: invalid window_size [{w},{h}] in {}; repairing geometry only",
                path.display()
            );
            cfg.window_size = None;
        }
    }
    Some(cfg)
}

fn load_from(path: &Path) -> Config {
    if let Some(cfg) = load_one(path) {
        return cfg;
    }
    // The ordinary `.bak` is not a guaranteed good geometry source: validate
    // it independently before trusting its geometry.
    if let Some(cfg) = load_one(&backup(path)) {
        return cfg;
    }
    Config::default()
}

/// Writes the config without ever leaving a half-written file behind, keeping
/// the previous version as `config.json.bak`.
///
/// Failures are logged (not silently discarded); see [`try_save`] for an
/// observable `Result`.
pub fn save(cfg: &Config) {
    if let Err(e) = try_save(cfg) {
        eprintln!("Yeager config: failed to save {}: {e}", path().display());
    }
}

/// Fallible save for callers (and tests) that need to observe write failures.
pub fn try_save(cfg: &Config) -> std::io::Result<()> {
    save_to(&path(), cfg).map_err(|e| {
        eprintln!("Yeager config: failed to save {}: {e}", path().display());
        e
    })
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
        cfg.selected_hosts = vec!["example.com".into()];
        save_to(&path, &cfg).unwrap();
        cfg.dark = false;
        save_to(&path, &cfg).unwrap();
        assert_eq!(load_from(&path), cfg);

        // A torn write: the previous version comes back.
        std::fs::write(&path, "{\"scope\":").unwrap();
        let loaded = load_from(&path);
        assert_eq!(loaded.selected_hosts, vec!["example.com".to_string()]);
        assert!(loaded.dark);

        let _ = std::fs::remove_dir_all(dir);
    }

    fn test_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "erwin-config-ui-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn corrupted_geometry_migrates_as_pair_and_preserves_unrelated_config() {
        let dir = test_path("corrupt");
        let path = dir.join("config.json");
        // [0,0], [1,1], negative, huge, non-numeric -> fallback pair (None in
        // memory), unrelated config intact.
        for (i, raw) in [
            "[0,0]",
            "[1,1]",
            "[-5,100]",
            "[99999,99999]",
            "[4294967299,600]",
            r#"["a","b"]"#,
            r#""huge""#,
        ]
        .iter()
        .enumerate()
        {
            let dir = dir.join(format!("case{i}"));
            let path = dir.join("config.json");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                &path,
                format!(r#"{{"window_size": {raw}, "dark": false, "selected_hosts": ["keep.example"]}}"#),
            )
            .unwrap();
            let loaded = load_from(&path);
            assert_eq!(loaded.window_size, None, "raw {raw}");
            assert!(!loaded.dark, "raw {raw}");
            assert_eq!(loaded.selected_hosts, vec!["keep.example".to_string()], "raw {raw}");
            // Missing field also yields None without losing other settings.
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Absent geometry keeps other settings.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, r#"{"dark": false}"#).unwrap();
        let loaded = load_from(&path);
        assert_eq!(loaded.window_size, None);
        assert!(!loaded.dark);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deliberate_minimum_size_persists_and_restores() {
        let dir = test_path("min");
        let path = dir.join("config.json");
        let mut cfg = Config::default();
        cfg.window_size = Some([700, 500]);
        save_to(&path, &cfg).unwrap();
        let loaded = load_from(&path);
        assert_eq!(loaded.window_size, Some([700, 500]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn valid_normal_resize_round_trips() {
        let dir = test_path("roundtrip");
        let path = dir.join("config.json");
        let mut cfg = Config::default();
        cfg.window_size = Some([900, 650]);
        save_to(&path, &cfg).unwrap();
        assert_eq!(load_from(&path).window_size, Some([900, 650]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn backup_geometry_is_validated_independently() {
        let dir = test_path("bak");
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        // Primary is a torn write; backup holds bad geometry: neither is trusted.
        std::fs::write(&path, "{\"scope\":").unwrap();
        std::fs::write(backup(&path), r#"{"window_size": [0,0], "dark": false}"#).unwrap();
        let loaded = load_from(&path);
        assert_eq!(loaded.window_size, None);
        assert!(!loaded.dark);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_failure_is_surfaced_not_swallowed() {
        // Saving through a directory path must fail observably.
        let dir = test_path("write-fail");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = Config::default();
        let err = save_to(&dir, &cfg).expect_err("writing to a directory must fail");
        assert!(!err.to_string().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_and_try_save_surface_write_error() {
        // The pre-fix `save()` discarded the write `Result`, so helpers alone
        // passed while the top-level swallow stayed. Exercise `try_save` /
        // `save` themselves by pointing the config dir at a regular file.
        let anchor = std::env::temp_dir().join(format!(
            "erwin-save-fail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&anchor, b"not-a-dir").unwrap();
        let prev = std::env::var_os("LOCALAPPDATA");
        unsafe {
            std::env::set_var("LOCALAPPDATA", &anchor);
        }
        let err = try_save(&Config::default()).expect_err("try_save must fail when dir is a file");
        assert!(!err.to_string().is_empty());
        // `save()` logs instead of panicking on the same failure.
        save(&Config::default());
        unsafe {
            match prev {
                Some(v) => std::env::set_var("LOCALAPPDATA", v),
                None => std::env::remove_var("LOCALAPPDATA"),
            }
        }
        let _ = std::fs::remove_file(&anchor);
    }
}

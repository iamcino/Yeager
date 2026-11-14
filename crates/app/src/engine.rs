//! Integration point for the connection resilience engine core (`levi`).

use common::{Config, Error, Result, TransportProfile};
use std::path::PathBuf;
use std::sync::Mutex;

/// Process-wide `--driver-dir` override, parsed once from the `yeager.exe`
/// command line at startup (see `main`). The ONLY driver-location override
/// channel: `config.json` and the environment are never consulted.
static DRIVER_DIR_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Records the `--driver-dir` CLI flag for this process. Called once at
/// startup; later engine starts pick it up automatically.
pub fn set_driver_dir_override(dir: Option<PathBuf>) {
    *DRIVER_DIR_OVERRIDE.lock().unwrap() = dir;
}

/// Starts the native Levi engine for the given configuration.
pub fn start(cfg: &Config) -> Result<()> {
    let profile = match cfg.transport_profile {
        TransportProfile::Auto => levi::ResilienceProfile::Auto,
        TransportProfile::Fast => levi::ResilienceProfile::Fast,
        TransportProfile::Hardened => levi::ResilienceProfile::Hardened,
        TransportProfile::Observe => levi::ResilienceProfile::Observe,
    };
    let driver_dir = DRIVER_DIR_OVERRIDE.lock().unwrap().clone();
    levi::start_with_profile_and_driver_dir(cfg, profile, driver_dir).map_err(Error::new)
}

/// Stops the native Levi engine.
pub fn stop() {
    levi::stop();
}

/// Returns whether the engine is currently running.
#[allow(dead_code)]
pub fn is_running() -> bool {
    levi::is_running()
}

/// Returns current connection resilience telemetry:
/// (handshakes_intercepted, sessions_stabilized, middlebox_rsts_silenced).
#[allow(dead_code)]
pub fn get_telemetry() -> (usize, usize, usize) {
    (
        levi::STATS_HANDSHAKES.load(std::sync::atomic::Ordering::Relaxed),
        levi::STATS_STABILIZED.load(std::sync::atomic::Ordering::Relaxed),
        levi::STATS_DROPPED_RSTS.load(std::sync::atomic::Ordering::Relaxed),
    )
}

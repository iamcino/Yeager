//! Integration point for the connection resilience engine core (`levi`).

use common::{Config, Error, Result, TransportProfile};

/// Starts the native Levi engine for the given configuration.
pub fn start(cfg: &Config) -> Result<()> {
    let profile = match cfg.transport_profile {
        TransportProfile::Auto => levi::ResilienceProfile::Auto,
        TransportProfile::Fast => levi::ResilienceProfile::Fast,
        TransportProfile::Hardened => levi::ResilienceProfile::Hardened,
        TransportProfile::Observe => levi::ResilienceProfile::Observe,
    };
    levi::start_with_profile(cfg, profile).map_err(Error::new)
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

//! Yeager DNS recovery — unit U01: model, original capture and Windows API
//! qualification (SPEC-DNS-FIX.md §12).
//!
//! Library-only deliverable behind development-only gating: no production
//! mutation integration and no wiring into the app's takeover path. The
//! guarded Q1 experiment harness lives in `examples/q1_experiment.rs` and is
//! only built with the opt-in `dev-experiment` feature.
//!
//! Q1 gate (§4/§13): the documented getter path (Flags=0) exposes IPv4 only.
//! Complete IPv6 readback needs the DNS_SETTING_IPV6 family selector, which is
//! a candidate pending a coordinator/owner ruling. The default
//! [`FamilySelectorPolicy::DocumentedOnly`] therefore refuses IPv6 capture
//! ([`CaptureError::RefuseUnsupportedTakeover`]); nothing here self-approves
//! the exception.

pub mod backend;
pub mod canonical;
pub mod fake;
pub mod model;

#[cfg(windows)]
pub mod windows;

#[cfg(test)]
mod tests;

pub use backend::{
    capture_family, capture_stable, system_clock, DnsBackend, FamilyProbe, FamilySelectorPolicy,
    RawProperty, RawSettings, ReaderDnsBackend, RegistryProvenance, RegistryValue, SettingsApi,
    SettingsGuard, DNS_SETTING_IPV6,
};
pub use canonical::{canonical_json, canonical_value, fingerprint};
pub use model::*;

#[cfg(windows)]
pub use windows::{WinProbe, WinRegistry, WinSettingsApi, WindowsDnsBackend};

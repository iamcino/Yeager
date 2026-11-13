//! Yeager DNS recovery — units U01 + U01b: model, original capture and Windows
//! API qualification (SPEC-DNS-FIX.md §12).
//!
//! Library-only deliverable behind development-only gating: no production
//! mutation integration and no wiring into the app's takeover path. The
//! guarded Q1 experiment harness lives in `examples/q1_experiment.rs` and is
//! only built with the opt-in `dev-experiment` feature.
//!
//! # Capture contract and the Q1 ruling
//!
//! Q1 (SPEC-DNS-FIX.md §4/§13) asked whether any *documented* getter path yields
//! a complete per-family capture. The guarded experiment (evidence base:
//! `Q1-EVIDENCE.md`, garen-pc Windows 11 build 26300.9974) established that
//! `Version=3/Flags=0` returns complete IPv4 only, while complete IPv6 readback
//! requires the `DNS_SETTING_IPV6` family selector — so no complete documented
//! path covers both families.
//!
//! The coordinator ruling (Garen, 2026-11-14, under Cino's flow delegation of
//! 2026-11-14 00:46, reported to the owner at 09:00) APPROVES a bounded,
//! version-gated family-selector exception for the reader:
//!
//! 1. The documented path stays primary: IPv4 capture uses `Version=3/Flags=0`.
//! 2. IPv6 capture may use `Flags=DNS_SETTING_IPV6` as a family selector only on
//!    Windows builds >= 20348 ([`MIN_SELECTOR_BUILD`]), and only as a read
//!    (getter) — never as a setter flag introduced by the ruling.
//! 3. Defense in depth: the reader verifies the selector result is
//!    self-consistent (every nameserver parses as IPv6; the returned properties
//!    belong to the IPv6 settings structure) and REFUSES capture — not a silent
//!    fallback — if the build is below 20348, the selector call errors, or the
//!    data is family-inconsistent ([`CaptureError::FamilyInconsistent`]).
//! 4. Where the exception is unavailable the reader keeps its prior behavior:
//!    refuse unsupported takeover ([`CaptureError::RefuseUnsupportedTakeover`]).
//!    There is no IPv4-only snapshot fallback.
//!
//! [`FamilySelectorPolicy::VersionGatedException`] implements the approved
//! exception; the build gate is read from the OS at runtime, not a compile-time
//! constant. The conservative [`FamilySelectorPolicy::DocumentedOnly`] remains
//! the default and still refuses IPv6. [`capture_two_families`] /
//! [`ReaderDnsBackend::capture_complete`] assemble the complete two-family
//! snapshot. The library performs no writes.

pub mod backend;
pub mod canonical;
pub mod fake;
pub mod model;

#[cfg(windows)]
pub mod windows;

#[cfg(test)]
mod tests;

pub use backend::{
    capture_family, capture_stable, capture_two_families, system_clock, DnsBackend, FamilyProbe,
    FamilySelectorPolicy, RawProperty, RawSettings, ReaderDnsBackend, RegistryProvenance,
    RegistryValue, SettingsApi, SettingsGuard, DNS_SETTING_IPV6, MIN_SELECTOR_BUILD,
};
pub use canonical::{canonical_json, canonical_value, fingerprint};
pub use model::*;

#[cfg(windows)]
pub use windows::{WinProbe, WinRegistry, WinSettingsApi, WindowsDnsBackend};

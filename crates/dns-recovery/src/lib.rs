//! Yeager DNS recovery — units U01 + U01b + U02: model, original capture,
//! Windows API qualification and the durable journal (SPEC-DNS-FIX.md §12).
//!
//! Library-only deliverable behind development-only gating: no production
//! mutation integration and no wiring into the app's takeover path. The
//! guarded experiment/evidence harnesses live in `examples/` and are only
//! built with the opt-in `dev-experiment` feature.
//!
//! # U02: protected journal, shared lock, durable replacement
//!
//! [`journal`] defines the schema and semantic validation, [`codec`] the
//! strict canonical codec (digest + canonical-byte equality), [`security`]
//! the exact protected-DACL contract, [`lock`] the cross-session named mutex
//! (fail-closed against wrong-type/security squatting, WAIT_ABANDONED mandates
//! a rescan), [`fs`] the fault-injectable filesystem abstraction and [`store`]
//! the durable replacement pipeline (CREATE_NEW stage → file flush → verified
//! readback → ReplaceFileW/MoveFileExW → primary reopen/verify → primary flush
//! → volume flush) with reconciliation and clean-tombstone cleanup. No
//! optimistic rename durability anywhere. The real Windows implementations
//! are [`WindowsFs`] / [`WindowsLock`] (`fs_windows`).
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
pub mod codec;
pub mod fake;
pub mod fs;
pub mod journal;
pub mod lock;
pub mod model;
pub mod security;
pub mod store;

#[cfg(windows)]
pub mod fs_windows;
#[cfg(windows)]
pub mod windows;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_u02;

pub use backend::{
    capture_family, capture_stable, capture_two_families, system_clock, DnsBackend, FamilyProbe,
    FamilySelectorPolicy, RawProperty, RawSettings, ReaderDnsBackend, RegistryProvenance,
    RegistryValue, SettingsApi, SettingsGuard, DNS_SETTING_IPV6, MIN_SELECTOR_BUILD,
};
pub use canonical::{canonical_json, canonical_value, fingerprint};
pub use model::*;

#[cfg(windows)]
pub use fs_windows::{WindowsFs, WindowsLock};
#[cfg(windows)]
pub use windows::{WinProbe, WinRegistry, WinSettingsApi, WindowsDnsBackend};

//! Yeager DNS recovery — units U01 + U01b + U02 + U03 + U04 + U05: model,
//! original capture, Windows API qualification, the durable journal, the
//! apply/reconfigure/restore transaction engine, the startup replay with
//! owner identity, conflict handling and the deferred scheduler, and the
//! privileged-service host with secure IPC (SPEC-DNS-FIX.md §12).
//!
//! # U04: replay, owner identity and deferred scheduler
//!
//! [`replay`] implements SPEC-DNS-FIX.md §7 startup replay over the U03
//! engine: PID + creation-FILETIME liveness ([`OwnerProbe`]; access
//! denied/query failure is unknown, never dead), live-owner protection across
//! sessions, §5.4 classification of every intent/current family against the
//! original and all committed/intent images, exact-original restore, conflict
//! retention without writes, and the §5.3 deferred scheduler (due passes,
//! arrival-triggered retries, no age-based removal). Replay needs no user
//! profile, network, listener runtime or UI, and never performs the old
//! heuristic public-provider reset: every setter call targets a journaled
//! immutable original.
//!
//! # U03: transaction engine
//!
//! # U03: transaction engine
//!
//! [`transaction`] implements takeover T0–T7, reconfigure C0–C4 and restore
//! R0–R6 with §5.4 image classification: durable before/target intent before
//! every setter call, request-ID idempotency (lost replies settle by readback,
//! never by duplicate calls), configured-readback verification, whole-
//! transaction rollback to immutable originals on any family failure, and
//! admission closure on persistence failure. [`setter`] is the mutation
//! contract (qualified by Q1-EVIDENCE.md), [`plan`] builds source-compatible
//! target images, [`clock`] provides the deterministic virtual clock, and
//! [`fake::FakeOs`] is the mutable fake OS. The qualified Windows setter
//! adapter is `windows::WinSetter`. Still no GUI activation and no production
//! takeover wiring.
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
pub mod clock;
pub mod codec;
pub mod fake;
pub mod fs;
pub mod journal;
pub mod lock;
pub mod model;
pub mod plan;
pub mod protocol;
pub mod replay;
pub mod security;
pub mod service;
pub mod setter;
pub mod store;
pub mod transaction;

#[cfg(windows)]
pub mod fs_windows;
#[cfg(windows)]
pub mod service_os;
#[cfg(windows)]
pub mod windows;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_u02;
#[cfg(test)]
mod tests_u03;
#[cfg(test)]
mod tests_u04;
#[cfg(test)]
mod tests_u05;

pub use backend::{
    capture_family, capture_family_with_effective, capture_stable, capture_two_families,
    system_clock, DnsBackend, EffectiveDnsProbe, FamilyProbe, FamilySelectorPolicy, RawProperty,
    RawSettings, ReaderDnsBackend, RegistryProvenance, RegistryValue, SettingsApi, SettingsGuard,
    DNS_SETTING_IPV6, MIN_SELECTOR_BUILD,
};
pub use canonical::{canonical_json, canonical_value, fingerprint};
pub use clock::{utc_string, Clock, SystemClock, VirtualClock};
pub use model::*;
pub use plan::{automatic_image, plan_image, provider_spec, setter_mask, ProviderSpec};
pub use protocol::{
    exit_code_for_outcome, AuthError, DedupCache, Operation, PeerAuth, ProtocolError, Request,
    Reply, MAX_DEDUP_ENTRIES, MAX_FRAME_BYTES, PIPE_NAME, PIPE_SDDL, PROTOCOL_VERSION,
};
pub use replay::{FakeOwnerProbe, OwnerLiveness, OwnerProbe, ReplayDriver, ReplayReport};
pub use service::{
    ControlState, Lease, ScmServiceState, ServiceConfig, ServiceHost, HEALTH_INTERVAL_MS,
    MISSED_HEALTH_LIMIT, RESTORE_START_TARGET_MS,
};
pub use setter::{
    DnsSetter, SetterError, SetterImage, DNS_SETTING_DOH, DNS_SETTING_NAMESERVER, DOH_ENABLE,
    DOH_ENABLE_AUTO, DOH_ENABLE_DDR, DOH_FALLBACK_TO_UDP,
};
pub use transaction::{
    background_delay_ms, DeathPoint, EngineError, EngineReport, FamilyError, Outcome,
    TransactionEngine,
};

#[cfg(windows)]
pub use fs_windows::{WindowsFs, WindowsLock};
#[cfg(windows)]
pub use windows::{WinProbe, WinRegistry, WinSettingsApi, WinSetter, WindowsDnsBackend};

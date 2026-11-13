//! Setter contract (U03, SPEC-DNS-FIX.md §4). The only mutation surface the
//! transaction engine may use: interface NameServer + interface
//! ServerProperties, Version=3, mask NAMESERVER|DOH plus the family selector.
//!
//! Q1-EVIDENCE.md qualified this contract on garen-pc (build 26300.9974):
//! - an empty NameServer string plus zero properties restores automatic and
//!   clears prior DoH properties;
//! - the setter is NOT field-atomic: a NAMESERVER-only write clears existing
//!   DoH properties, so every call must carry the FULL intended property set
//!   (NAMESERVER|DOH together), and each call is journaled separately;
//! - profile/context/global tables are untouched by interface-scoped writes.
//!
//! The qualified Windows adapter is `windows::WinSetter`; the fake is
//! `fake::FakeOs`. Nothing here touches a NIC by itself.

use crate::model::{Family, ServerProperty, Snapshot};

pub const DNS_SETTING_NAMESERVER: u64 = 2;
pub const DNS_SETTING_DOH: u64 = 4096;
pub const DOH_ENABLE_AUTO: u64 = 1;
pub const DOH_ENABLE: u64 = 2;
pub const DOH_FALLBACK_TO_UDP: u64 = 4;
pub const DOH_ENABLE_DDR: u64 = 16;

pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_NOT_SUPPORTED: u32 = 50;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_CANCELLED: u32 = 1223;

/// Numeric Windows status plus a message. Retryability follows §5.3: access
/// denied, unsupported, invalid parameter, missing interface and cancellation
/// are NOT automatically write-retried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetterError {
    pub status: u32,
    pub message: String,
}

impl SetterError {
    pub fn retryable(&self) -> bool {
        !matches!(
            self.status,
            ERROR_ACCESS_DENIED | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER
                | ERROR_FILE_NOT_FOUND | ERROR_CANCELLED
        )
    }
}

impl std::fmt::Display for SetterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "setter failed (status {}): {}", self.status, self.message)
    }
}

impl std::error::Error for SetterError {}

/// The complete intended interface image for one setter call: the NameServer
/// string and the FULL property set (never a partial facet write).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetterImage {
    pub name_server: String,
    pub properties: Vec<ServerProperty>,
}

impl SetterImage {
    pub fn from_target(target: &Snapshot) -> Self {
        Self {
            name_server: target.name_server_raw.clone().unwrap_or_default(),
            properties: target.server_properties.clone(),
        }
    }
}

/// One mutation API call. `request_id` is the journaled idempotency key: the
/// engine never re-issues a call whose intent already exists — a lost reply is
/// settled by configured readback (§3.2). Implementations must scope the write
/// to the interface's NameServer + ServerProperties for exactly one family.
pub trait DnsSetter {
    fn set(
        &self,
        request_id: &str,
        guid: &str,
        family: Family,
        image: &SetterImage,
    ) -> Result<(), SetterError>;
}

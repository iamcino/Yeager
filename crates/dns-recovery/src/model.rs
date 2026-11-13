//! Snapshot / error / plan types and canonical configured equality (U01).
//!
//! These are pure, platform-independent value types. The configured
//! fingerprint covers family, provenance, ordered canonical servers and
//! server properties; context and capability are evidence compared separately
//! (SPEC-DNS-FIX.md §3.2 / §4).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Address family of a captured configured DNS set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }
    /// Registry service key holding the per-interface NameServer override.
    pub fn registry_service(self) -> &'static str {
        match self {
            Family::Ipv4 => "Tcpip",
            Family::Ipv6 => "Tcpip6",
        }
    }
}

/// How the configured resolver list is supplied. Automatic means no static
/// DNS override; it is never inferred from DHCP IP assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    Automatic,
    Static,
}

/// One ordered resolver, canonicalised but retaining order, duplicates and
/// IPv6 scope. Equivalent address formatting compares equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalServer {
    pub address: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<u32>,
}

impl CanonicalServer {
    pub fn parse(token: &str) -> Result<Self, CaptureError> {
        let (addr, scope) = match token.split_once('%') {
            Some((a, s)) => {
                let scope: u32 = s
                    .parse()
                    .map_err(|_| CaptureError::MalformedAddress(token.to_string()))?;
                (a, Some(scope))
            }
            None => (token, None),
        };
        let address: IpAddr = addr
            .parse()
            .map_err(|_| CaptureError::MalformedAddress(token.to_string()))?;
        if address.is_ipv4() && scope.is_some() {
            return Err(CaptureError::MalformedAddress(token.to_string()));
        }
        Ok(Self { address, scope })
    }

    pub fn canonical(&self) -> String {
        match self.scope {
            Some(s) => format!("{}%{s}", self.address),
            None => self.address.to_string(),
        }
    }
}

/// Parse a Windows NameServer string (comma/space separated) into an ordered
/// canonical list. Empty/whitespace yields an empty list (automatic candidate).
pub fn parse_servers(raw: &str) -> Result<Vec<CanonicalServer>, CaptureError> {
    raw.split([',', ' '])
        .filter(|s| !s.is_empty())
        .map(CanonicalServer::parse)
        .collect()
}

/// DoH settings for one server property. A null template is preserved as
/// `None` (AUTO), distinct from an empty string. Flags keep every supported
/// bit, including AUTO and fallback-to-UDP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DohSettings {
    pub template: Option<String>,
    #[serde(with = "u64_str")]
    pub flags: u64,
}

/// One interface server property. Absence (not in the array) differs from a
/// present property whose flags are zero.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerProperty {
    pub version: u32,
    pub server_index: u32,
    #[serde(rename = "type")]
    pub prop_type: u32,
    pub doh: DohSettings,
}

/// Raw registry evidence distinguishing absent / empty / denied / bad type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEvidence {
    pub registry_path: String,
    pub value_exists: bool,
    pub value_type: Option<u32>,
    pub raw_value_base64: Option<String>,
    #[serde(with = "u64_str")]
    pub api_flags: u64,
    pub captured_at_utc: String,
}

/// Deep-owned interface context returned by the getter. Evidence and
/// noninterference only — never permission to restore these fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsContext {
    #[serde(with = "u64_str")]
    pub interface_flags: u64,
    pub profile_name_server: Option<String>,
    pub profile_server_properties: Vec<ServerProperty>,
    pub domain: Option<String>,
    pub search_list: Option<String>,
    pub registration_enabled: u32,
    pub register_adapter_name: u32,
    pub enable_llmnr: u32,
    pub query_adapter_name: u32,
    pub disable_unconstrained_queries: u32,
    pub supplemental_search_list: Option<String>,
}

/// Reader capability for one family on one build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub os_build: String,
    pub reader_revision: u32,
    pub api_version: u32,
    pub family_supported: bool,
}

/// Immutable configured DNS snapshot for one adapter/family (schema_version 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub family: Family,
    pub provenance: Provenance,
    pub name_server_raw: Option<String>,
    pub ordered_servers: Vec<CanonicalServer>,
    pub provenance_evidence: ProvenanceEvidence,
    pub server_properties: Vec<ServerProperty>,
    pub context: DnsContext,
    pub capability: Capability,
}

impl Snapshot {
    /// Configured equality: family, provenance, ordered canonical servers and
    /// server properties. Context, capability and raw evidence are excluded
    /// (compared separately); equivalent address formatting compares equal.
    pub fn configured_eq(&self, other: &Snapshot) -> bool {
        self.family == other.family
            && self.provenance == other.provenance
            && self.ordered_servers == other.ordered_servers
            && self.server_properties == other.server_properties
    }

    /// Canonical SHA-256 fingerprint over the configured fields.
    pub fn fingerprint(&self) -> String {
        crate::canonical::fingerprint(self)
    }
}

/// Adapter identity. Hints detect reincarnation; the GUID is authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterIdentity {
    pub adapter_guid: String,
    pub luid: u64,
    pub if_index: u32,
    pub name_hint: String,
    pub device_instance_hint: Option<String>,
}

/// Desired DoH provider for a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Auto,
    Cloudflare,
    Google,
    Adguard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

/// A local stub endpoint a plan may bind. Loopback port 53 only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundEndpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: Transport,
}

/// Desired takeover plan (model only in U01; no mutation integration).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredPlan {
    pub provider: Provider,
    pub local_requested: bool,
    pub bound_endpoints: Vec<BoundEndpoint>,
    #[serde(with = "u64_str")]
    pub readiness_generation: u64,
}

/// Reasons capture must refuse (SPEC-DNS-FIX.md §4). Any of these aborts the
/// initial takeover with zero writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureError {
    QueryFailure(String),
    AccessDenied(String),
    MalformedRegistryType { path: String, value_type: u32 },
    MalformedAddress(String),
    InvalidPropertyIndex { index: u32, servers: usize },
    UnknownProperty { version: u32, prop_type: u32 },
    UnsupportedFlags { flags: u64 },
    ContradictoryProvenance(String),
    CaptureUnstable,
    UnsupportedReplayFormat(String),
    ProfilePolicyOverride(String),
    NoSelectedOnlineAdapter,
    UnsupportedFamily(Family),
    /// Q1 gate: no approved complete getter contract for this family/build.
    RefuseUnsupportedTakeover(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::QueryFailure(m) => write!(f, "DNS query failed: {m}"),
            CaptureError::AccessDenied(m) => write!(f, "DNS access denied: {m}"),
            CaptureError::MalformedRegistryType { path, value_type } => {
                write!(f, "malformed registry type {value_type} at {path}")
            }
            CaptureError::MalformedAddress(a) => write!(f, "malformed DNS address {a:?}"),
            CaptureError::InvalidPropertyIndex { index, servers } => {
                write!(f, "property index {index} out of range ({servers} servers)")
            }
            CaptureError::UnknownProperty { version, prop_type } => {
                write!(f, "unknown server property version {version} type {prop_type}")
            }
            CaptureError::UnsupportedFlags { flags } => write!(f, "unsupported DoH flags {flags}"),
            CaptureError::ContradictoryProvenance(m) => write!(f, "contradictory provenance: {m}"),
            CaptureError::CaptureUnstable => write!(f, "DNS configuration changing; capture unstable"),
            CaptureError::UnsupportedReplayFormat(m) => write!(f, "unsupported replay format: {m}"),
            CaptureError::ProfilePolicyOverride(m) => write!(f, "profile/policy override: {m}"),
            CaptureError::NoSelectedOnlineAdapter => write!(f, "no selected online adapter"),
            CaptureError::UnsupportedFamily(fam) => write!(f, "unsupported family {}", fam.as_str()),
            CaptureError::RefuseUnsupportedTakeover(m) => write!(f, "refusing unsupported takeover: {m}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// serde helper: u64 rendered as a decimal string (spec schema convention).
pub(crate) mod u64_str {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

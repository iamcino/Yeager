//! DnsBackend trait, deep-owned reader/readback/capability probing and the
//! capture pipeline (U01). Platform-independent: the Windows API and a fake
//! both plug into the same generic pipeline, so the capture contract is
//! testable off Windows. No mutation/setter integration lives here.

use crate::model::*;

pub const DNS_SETTING_IPV6: u64 = 1;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
/// ENABLE_AUTO | ENABLE | FALLBACK_TO_UDP | ENABLE_DDR.
const SUPPORTED_DOH_FLAGS: u64 = 1 | 2 | 4 | 16;
const PROPERTY_VERSION1: u32 = 1;
const DOH_PROPERTY_TYPE: u32 = 1;

/// Deep-owned getter dump (mirrors DNS_INTERFACE_SETTINGS3). Owned strings and
/// vectors only — nothing points back into API-allocated memory.
#[derive(Clone, Debug, Default)]
pub struct RawSettings {
    pub flags_returned: u64,
    pub name_server: Option<String>,
    pub server_properties: Vec<RawProperty>,
    pub profile_name_server: Option<String>,
    pub profile_server_properties: Vec<RawProperty>,
    pub domain: Option<String>,
    pub search_list: Option<String>,
    pub registration_enabled: u32,
    pub register_adapter_name: u32,
    pub enable_llmnr: u32,
    pub query_adapter_name: u32,
    pub disable_unconstrained_queries: u32,
    pub supplemental_search_list: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RawProperty {
    pub version: u32,
    pub server_index: u32,
    pub prop_type: u32,
    pub template: Option<String>,
    pub flags: u64,
}

/// The configured-settings API lifecycle: get → deep-copy → free. `free` must
/// be called exactly once for every successful `get`, including when later
/// validation fails. The RAII [`SettingsGuard`] enforces this.
pub trait SettingsApi {
    type Handle;
    fn get(&self, guid: &str, flags: u64) -> Result<Self::Handle, CaptureError>;
    fn deep_copy(&self, handle: &Self::Handle) -> Result<RawSettings, CaptureError>;
    fn free(&self, handle: Self::Handle);
}

/// RAII owner of a successful get. Frees exactly once on drop, on every path
/// (including validation errors). Deep copies taken via [`Self::deep_copy`]
/// are owned and survive the free.
pub struct SettingsGuard<'a, A: SettingsApi> {
    api: &'a A,
    handle: Option<A::Handle>,
}

impl<'a, A: SettingsApi> SettingsGuard<'a, A> {
    pub fn new(api: &'a A, guid: &str, flags: u64) -> Result<Self, CaptureError> {
        let handle = api.get(guid, flags)?;
        Ok(Self { api, handle: Some(handle) })
    }
    pub fn deep_copy(&self) -> Result<RawSettings, CaptureError> {
        self.api.deep_copy(self.handle.as_ref().expect("guard holds a handle"))
    }
}

impl<A: SettingsApi> Drop for SettingsGuard<'_, A> {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            self.api.free(h);
        }
    }
}

/// Raw registry NameServer evidence for one adapter/family.
#[derive(Clone, Debug)]
pub struct RegistryValue {
    pub path: String,
    pub exists: bool,
    pub value_type: Option<u32>,
    pub raw: Option<Vec<u8>>,
    pub text: Option<String>,
}

/// Registry provenance source. Access/query failures surface as errors; the
/// pipeline classifies absent/empty/bad-type from the returned evidence.
pub trait RegistryProvenance {
    fn read_name_server(&self, guid: &str, family: Family) -> Result<RegistryValue, CaptureError>;
}

/// Family presence probe (GetIpInterfaceEntry on Windows).
pub trait FamilyProbe {
    fn family_supported(&self, guid: &str, family: Family) -> Result<bool, CaptureError>;
}

/// Which getter family-selector contract the reader may use.
///
/// Q1 (SPEC-DNS-FIX.md §4/§13): the documented path (Flags=0) exposes IPv4
/// only. Complete IPv6 readback requires the DNS_SETTING_IPV6 family selector,
/// which is a *candidate*, not an approved documented contract. The default
/// policy therefore refuses IPv6 capture; the exception is usable only when
/// explicitly approved for specific builds (a coordinator/owner ruling).
#[derive(Clone, Debug)]
pub enum FamilySelectorPolicy {
    DocumentedOnly,
    VersionGatedException { approved_builds: Vec<String> },
}

impl Default for FamilySelectorPolicy {
    fn default() -> Self {
        FamilySelectorPolicy::DocumentedOnly
    }
}

impl FamilySelectorPolicy {
    pub fn flags_for(&self, family: Family, os_build: &str) -> Result<u64, CaptureError> {
        match self {
            FamilySelectorPolicy::DocumentedOnly => match family {
                Family::Ipv4 => Ok(0),
                Family::Ipv6 => Err(CaptureError::RefuseUnsupportedTakeover(
                    "Q1 unresolved: no approved documented IPv6 getter contract".into(),
                )),
            },
            FamilySelectorPolicy::VersionGatedException { approved_builds } => {
                if !approved_builds.iter().any(|b| b == os_build) {
                    return Err(CaptureError::RefuseUnsupportedTakeover(format!(
                        "Q1 family-selector exception not approved for build {os_build}"
                    )));
                }
                Ok(match family {
                    Family::Ipv4 => 0,
                    Family::Ipv6 => DNS_SETTING_IPV6,
                })
            }
        }
    }
}

/// Capture one family once: registry provenance corroborated by the configured
/// getter, deep-owned, freed exactly once. Read-only; performs no writes.
pub fn capture_family<A: SettingsApi, R: RegistryProvenance>(
    api: &A,
    reg: &R,
    guid: &str,
    family: Family,
    policy: &FamilySelectorPolicy,
    capability: Capability,
    captured_at_utc: &str,
) -> Result<Snapshot, CaptureError> {
    let flags = policy.flags_for(family, &capability.os_build)?;

    let rv = reg.read_name_server(guid, family)?;
    if rv.exists {
        if let Some(t) = rv.value_type {
            if t != REG_SZ && t != REG_EXPAND_SZ {
                return Err(CaptureError::MalformedRegistryType { path: rv.path.clone(), value_type: t });
            }
        }
    }
    let reg_servers = match (&rv.text, rv.exists) {
        (Some(text), true) if !text.trim().is_empty() => Some(parse_servers(text)?),
        _ => None,
    };

    let guard = SettingsGuard::new(api, guid, flags)?;
    let raw = guard.deep_copy()?;
    let snapshot = build_snapshot(family, flags, &rv, reg_servers, &raw, capability, captured_at_utc)?;
    drop(guard);
    Ok(snapshot)
}

/// Repeat capture until two consecutive configured fingerprints agree, at most
/// three attempts, then [`CaptureError::CaptureUnstable`]. Read-only.
pub fn capture_stable<A: SettingsApi, R: RegistryProvenance>(
    api: &A,
    reg: &R,
    guid: &str,
    family: Family,
    policy: &FamilySelectorPolicy,
    capability: Capability,
    captured_at_utc: &str,
) -> Result<Snapshot, CaptureError> {
    let mut last = capture_family(api, reg, guid, family, policy, capability.clone(), captured_at_utc)?;
    for _ in 0..2 {
        let again = capture_family(api, reg, guid, family, policy, capability.clone(), captured_at_utc)?;
        if again.fingerprint() == last.fingerprint() {
            return Ok(again);
        }
        last = again;
    }
    Err(CaptureError::CaptureUnstable)
}

fn build_snapshot(
    family: Family,
    flags: u64,
    rv: &RegistryValue,
    reg_servers: Option<Vec<CanonicalServer>>,
    raw: &RawSettings,
    capability: Capability,
    captured_at_utc: &str,
) -> Result<Snapshot, CaptureError> {
    if let Some(p) = &raw.profile_name_server {
        if !p.trim().is_empty() {
            return Err(CaptureError::ProfilePolicyOverride(
                "active profile NameServer makes the interface set unreliable".into(),
            ));
        }
    }

    let getter_raw = raw.name_server.clone();
    let getter_servers = match &getter_raw {
        Some(s) if !s.trim().is_empty() => parse_servers(s)?,
        _ => Vec::new(),
    };

    let mut props = Vec::new();
    for p in &raw.server_properties {
        validate_property(p, getter_servers.len())?;
        props.push(ServerProperty {
            version: p.version,
            server_index: p.server_index,
            prop_type: p.prop_type,
            doh: DohSettings { template: p.template.clone(), flags: p.flags },
        });
    }

    let provenance = match (&reg_servers, getter_servers.is_empty()) {
        (Some(rs), false) => {
            if rs != &getter_servers {
                return Err(CaptureError::ContradictoryProvenance(format!(
                    "registry list {:?} != getter list {:?}",
                    rs.iter().map(|c| c.canonical()).collect::<Vec<_>>(),
                    getter_servers.iter().map(|c| c.canonical()).collect::<Vec<_>>()
                )));
            }
            Provenance::Static
        }
        (None, true) => Provenance::Automatic,
        (Some(_), true) => {
            return Err(CaptureError::ContradictoryProvenance(
                "registry static override but getter reports automatic".into(),
            ))
        }
        (None, false) => {
            return Err(CaptureError::ContradictoryProvenance(
                "registry automatic but getter reports a static override".into(),
            ))
        }
    };

    let ordered_servers = match provenance {
        Provenance::Static => getter_servers,
        Provenance::Automatic => Vec::new(),
    };

    let profile_props = raw
        .profile_server_properties
        .iter()
        .map(|p| ServerProperty {
            version: p.version,
            server_index: p.server_index,
            prop_type: p.prop_type,
            doh: DohSettings { template: p.template.clone(), flags: p.flags },
        })
        .collect();

    let context = DnsContext {
        interface_flags: raw.flags_returned,
        profile_name_server: raw.profile_name_server.clone(),
        profile_server_properties: profile_props,
        domain: raw.domain.clone(),
        search_list: raw.search_list.clone(),
        registration_enabled: raw.registration_enabled,
        register_adapter_name: raw.register_adapter_name,
        enable_llmnr: raw.enable_llmnr,
        query_adapter_name: raw.query_adapter_name,
        disable_unconstrained_queries: raw.disable_unconstrained_queries,
        supplemental_search_list: raw.supplemental_search_list.clone(),
    };

    let evidence = ProvenanceEvidence {
        registry_path: rv.path.clone(),
        value_exists: rv.exists,
        value_type: rv.value_type,
        raw_value_base64: rv.raw.as_ref().map(|b| base64(b)),
        api_flags: flags,
        captured_at_utc: captured_at_utc.to_string(),
    };

    Ok(Snapshot {
        schema_version: 1,
        family,
        provenance,
        name_server_raw: getter_raw,
        ordered_servers,
        provenance_evidence: evidence,
        server_properties: props,
        context,
        capability,
    })
}

fn validate_property(p: &RawProperty, servers: usize) -> Result<(), CaptureError> {
    if p.version != PROPERTY_VERSION1 || p.prop_type != DOH_PROPERTY_TYPE {
        return Err(CaptureError::UnknownProperty { version: p.version, prop_type: p.prop_type });
    }
    if p.server_index as usize >= servers {
        return Err(CaptureError::InvalidPropertyIndex { index: p.server_index, servers });
    }
    if p.flags & !SUPPORTED_DOH_FLAGS != 0 {
        return Err(CaptureError::UnsupportedFlags { flags: p.flags });
    }
    Ok(())
}

/// The OS DNS backend contract used by the rest of the system (U02+).
pub trait DnsBackend {
    fn adapters(&self) -> Result<Vec<AdapterIdentity>, CaptureError>;
    fn capability(&self, guid: &str, family: Family) -> Result<Capability, CaptureError>;
    fn capture(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError>;
    fn readback(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError>;
}

/// Generic deep-owned reader assembling capability probing + stable capture.
pub struct ReaderDnsBackend<A: SettingsApi, R: RegistryProvenance, P: FamilyProbe> {
    pub api: A,
    pub registry: R,
    pub probe: P,
    pub policy: FamilySelectorPolicy,
    pub os_build: String,
    pub reader_revision: u32,
    pub clock: Box<dyn Fn() -> String>,
}

impl<A: SettingsApi, R: RegistryProvenance, P: FamilyProbe> ReaderDnsBackend<A, R, P> {
    fn capability_for(&self, guid: &str, family: Family) -> Result<Capability, CaptureError> {
        Ok(Capability {
            os_build: self.os_build.clone(),
            reader_revision: self.reader_revision,
            api_version: 3,
            family_supported: self.probe.family_supported(guid, family)?,
        })
    }
}

impl<A: SettingsApi, R: RegistryProvenance, P: FamilyProbe> DnsBackend for ReaderDnsBackend<A, R, P> {
    fn adapters(&self) -> Result<Vec<AdapterIdentity>, CaptureError> {
        // Adapter enumeration is OS-specific; the generic reader does not
        // invent identities. Windows supplies them via its own backend.
        Err(CaptureError::NoSelectedOnlineAdapter)
    }
    fn capability(&self, guid: &str, family: Family) -> Result<Capability, CaptureError> {
        self.capability_for(guid, family)
    }
    fn capture(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError> {
        let cap = self.capability_for(guid, family)?;
        if !cap.family_supported {
            return Err(CaptureError::UnsupportedFamily(family));
        }
        let now = (self.clock)();
        capture_stable(&self.api, &self.registry, guid, family, &self.policy, cap, &now)
    }
    fn readback(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError> {
        self.capture(guid, family)
    }
}

/// Minimal standard base64 (no dependency) for raw registry evidence.
pub(crate) fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// System UTC clock (ISO-8601, second precision) for capture timestamps.
pub fn system_clock() -> Box<dyn Fn() -> String> {
    Box::new(|| {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (y, mo, d) = civil_from_days((secs / 86400) as i64);
        let rem = secs % 86400;
        format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
    })
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

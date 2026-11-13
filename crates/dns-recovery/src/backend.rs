//! DnsBackend trait, deep-owned reader/readback/capability probing and the
//! capture pipeline (U01 + U01b). Platform-independent: the Windows API and a
//! fake both plug into the same generic pipeline, so the capture contract is
//! testable off Windows. No mutation/setter integration lives here.
//!
//! Q1 ruling (Garen, 2026-11-14, under Cino's flow delegation of 2026-11-14
//! 00:46, reported to the owner 09:00; evidence base Q1-EVIDENCE.md): the
//! version-gated family-selector exception is approved for the reader. IPv4
//! stays on the documented Version=3/Flags=0 path; IPv6 may use the
//! DNS_SETTING_IPV6 selector only on OS builds >= [`MIN_SELECTOR_BUILD`], as a
//! read only, with defense-in-depth family-consistency verification. Where the
//! exception is unavailable the reader refuses unsupported takeover — there is
//! no silent IPv4-only snapshot fallback.

use crate::model::*;

pub const DNS_SETTING_IPV6: u64 = 1;
/// Minimum Windows build for the approved IPv6 family-selector exception
/// (Q1 ruling, Garen 2026-11-14). The *threshold* is the ruling's bound; the
/// actual OS build is read at runtime (see `windows::os_build`) and compared
/// against it — never a compile-time build assumption.
pub const MIN_SELECTOR_BUILD: u32 = 20348;
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

/// Effective-address observation source: the adapter's currently effective
/// DNS servers (e.g. from the active DHCP lease), distinct from the configured
/// baseline. Read-only evidence recorded alongside the snapshot; it never
/// feeds the configured fingerprint (SPEC-DNS-FIX.md §12 U01).
pub trait EffectiveDnsProbe {
    fn effective_servers(&self, guid: &str, family: Family) -> Result<Vec<CanonicalServer>, CaptureError>;
}

/// Which getter family-selector contract the reader may use.
///
/// Q1 (SPEC-DNS-FIX.md §4/§13) was settled by the coordinator ruling (Garen,
/// 2026-11-14, under Cino's flow delegation of 2026-11-14 00:46, reported to the
/// owner 09:00; evidence base Q1-EVIDENCE.md): the documented path (Flags=0)
/// exposes complete IPv4 only, and complete IPv6 readback is obtained with the
/// DNS_SETTING_IPV6 family selector. The ruling APPROVES that selector as a
/// bounded, version-gated, read-only exception — implemented by
/// [`Self::VersionGatedException`]. [`Self::DocumentedOnly`] keeps the prior
/// conservative behavior (refuse IPv6). The default stays conservative; the
/// approved exception is opt-in and is never self-applied by the library.
#[derive(Clone, Debug)]
pub enum FamilySelectorPolicy {
    /// Documented path only: IPv4 via Flags=0; IPv6 capture is refused.
    DocumentedOnly,
    /// The approved Q1 exception: IPv4 via Flags=0 (documented path stays
    /// primary) and IPv6 via the DNS_SETTING_IPV6 selector, but only when the
    /// runtime OS build is >= [`MIN_SELECTOR_BUILD`]. Read-only; the selector
    /// is never a setter flag. Below the gate, or if the build cannot be
    /// established, IPv6 capture is refused (no silent fallback).
    VersionGatedException,
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
                    "no approved documented IPv6 getter contract (DocumentedOnly policy)".into(),
                )),
            },
            FamilySelectorPolicy::VersionGatedException => match family {
                // Bound 1: the documented path stays primary for IPv4.
                Family::Ipv4 => Ok(0),
                // Bound 2: the IPv6 selector is gated on the runtime OS build.
                Family::Ipv6 => {
                    let build = major_build(os_build).ok_or_else(|| {
                        CaptureError::RefuseUnsupportedTakeover(format!(
                            "cannot establish OS build from {os_build:?}; refusing IPv6 selector"
                        ))
                    })?;
                    if build < MIN_SELECTOR_BUILD {
                        return Err(CaptureError::RefuseUnsupportedTakeover(format!(
                            "Q1 family-selector exception requires build >= {MIN_SELECTOR_BUILD}; OS build {build}"
                        )));
                    }
                    Ok(DNS_SETTING_IPV6)
                }
            },
        }
    }
}

/// Major Windows build number from an OS build string such as "26300.9974" or
/// "20348". The UBR suffix is a revision, not part of the >= 20348 gate. Returns
/// `None` when the build cannot be established, so the caller refuses rather
/// than guesses (defense in depth).
fn major_build(os_build: &str) -> Option<u32> {
    os_build.split('.').next()?.trim().parse::<u32>().ok()
}

/// Defense in depth for the approved IPv6 selector (Q1 ruling bound 3): the
/// selector result must be self-consistent before it is accepted.
///
/// * The getter must echo the DNS_SETTING_IPV6 selector in `flags_returned`
///   (Q1-EVIDENCE.md: "flags_returned echoes the input selector"). That confirms
///   the returned properties belong to the IPv6 settings structure, not the
///   IPv4 one.
/// * Every returned nameserver address must parse as IPv6.
///
/// Any violation refuses capture with [`CaptureError::FamilyInconsistent`];
/// there is no silent fallback to an IPv4-only snapshot.
fn verify_ipv6_selector(raw: &RawSettings) -> Result<(), CaptureError> {
    if raw.flags_returned != DNS_SETTING_IPV6 {
        return Err(CaptureError::FamilyInconsistent(format!(
            "selector returned flags {} (expected {DNS_SETTING_IPV6}); properties are not the IPv6 settings structure",
            raw.flags_returned
        )));
    }
    if let Some(ns) = &raw.name_server {
        for server in parse_servers(ns)? {
            if !server.address.is_ipv6() {
                return Err(CaptureError::FamilyInconsistent(format!(
                    "IPv6 selector returned non-IPv6 nameserver {}",
                    server.canonical()
                )));
            }
        }
    }
    Ok(())
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
    // Bound 3: when the IPv6 selector was used, verify the result is
    // self-consistent before accepting it. On refusal the guard still drops
    // (frees exactly once); there is no silent fallback.
    if flags == DNS_SETTING_IPV6 {
        verify_ipv6_selector(&raw)?;
    }
    let snapshot = build_snapshot(family, flags, &rv, reg_servers, &raw, capability, captured_at_utc)?;
    drop(guard);
    Ok(snapshot)
}

/// Capture one family and record the adapter's effective DNS observation
/// alongside the configured snapshot (SPEC-DNS-FIX.md §12 U01). The
/// observation is evidence only: a lease change may alter the effective
/// addresses while the configured baseline fingerprint stays unchanged.
/// Read-only; performs no writes.
pub fn capture_family_with_effective<A: SettingsApi, R: RegistryProvenance, E: EffectiveDnsProbe>(
    api: &A,
    reg: &R,
    effective: &E,
    guid: &str,
    family: Family,
    policy: &FamilySelectorPolicy,
    capability: Capability,
    captured_at_utc: &str,
) -> Result<(Snapshot, EffectiveDns), CaptureError> {
    let snapshot = capture_family(api, reg, guid, family, policy, capability, captured_at_utc)?;
    let servers = effective.effective_servers(guid, family)?;
    Ok((snapshot, EffectiveDns { servers }))
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

/// Assemble a complete two-family snapshot: IPv4 from the documented Flags=0
/// path plus IPv6 from the approved version-gated selector (Q1 ruling, Garen
/// 2026-11-14). Each family is captured stably and deep-owned, freed exactly
/// once. Read-only.
///
/// Bound 4: if the IPv6 selector is unavailable (DocumentedOnly policy, build
/// below [`MIN_SELECTOR_BUILD`]) or errors or returns family-inconsistent data,
/// the whole capture is refused — there is NO IPv4-only snapshot fallback.
pub fn capture_two_families<A: SettingsApi, R: RegistryProvenance>(
    api: &A,
    reg: &R,
    guid: &str,
    policy: &FamilySelectorPolicy,
    capability: Capability,
    captured_at_utc: &str,
) -> Result<TwoFamilySnapshot, CaptureError> {
    let ipv4 = capture_stable(api, reg, guid, Family::Ipv4, policy, capability.clone(), captured_at_utc)?;
    let ipv6 = capture_stable(api, reg, guid, Family::Ipv6, policy, capability, captured_at_utc)?;
    Ok(TwoFamilySnapshot { ipv4, ipv6 })
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

    /// Complete two-family capture for one adapter (Q1 ruling). Probes both
    /// families, then assembles IPv4 (documented Flags=0) + IPv6 (approved
    /// version-gated selector). Refuses the whole capture if either family is
    /// unsupported or the IPv6 selector is unavailable/inconsistent — no
    /// IPv4-only fallback. Read-only.
    pub fn capture_complete(&self, guid: &str) -> Result<TwoFamilySnapshot, CaptureError> {
        let cap4 = self.capability_for(guid, Family::Ipv4)?;
        if !cap4.family_supported {
            return Err(CaptureError::UnsupportedFamily(Family::Ipv4));
        }
        let cap6 = self.capability_for(guid, Family::Ipv6)?;
        if !cap6.family_supported {
            return Err(CaptureError::UnsupportedFamily(Family::Ipv6));
        }
        let now = (self.clock)();
        let ipv4 = capture_stable(&self.api, &self.registry, guid, Family::Ipv4, &self.policy, cap4, &now)?;
        let ipv6 = capture_stable(&self.api, &self.registry, guid, Family::Ipv6, &self.policy, cap6, &now)?;
        Ok(TwoFamilySnapshot { ipv4, ipv6 })
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

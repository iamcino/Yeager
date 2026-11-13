//! Deep-owned Windows reader/readback/capability probing (U01) and the
//! qualified setter adapter (U03). The reader implements the same
//! [`SettingsApi`]/[`RegistryProvenance`]/[`FamilyProbe`] traits as the fakes,
//! so the capture contract is identical; every successful getter is freed
//! exactly once via the generic RAII guard after a deep copy.
//!
//! [`WinSetter`] is the qualified mutation adapter (Q1-EVIDENCE.md, build
//! 26300.9974): Version=3, mask NAMESERVER|DOH (+ IPv6 family selector, gated
//! at runtime on build >= [`MIN_SELECTOR_BUILD`]), full intended property set
//! on every call (the setter is not field-atomic), empty-string NameServer for
//! automatic — never a null pointer. Interface-scoped only: no profile, global
//! DoH table, NRPT or domain/search/registration writes. Standard tests cover
//! mask/construction only; live-adapter operations belong to guarded,
//! fully-restored qualified probes, never to `cargo test`.

#![cfg(windows)]

use crate::backend::*;
use crate::backend::{DNS_SETTING_IPV6, MIN_SELECTOR_BUILD};
use crate::model::*;
use crate::setter::{DnsSetter, SetterError, SetterImage, DNS_SETTING_DOH, DNS_SETTING_NAMESERVER};
use std::ptr;
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
    ERROR_NOT_SUPPORTED, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
use windows_sys::Win32::System::Registry::*;

const SETTINGS_VERSION3: u32 = 3;
const DOH_PROPERTY_TYPE: i32 = 1;

// ---- configured-settings API ---------------------------------------------

/// Real GetInterfaceDnsSettings lifecycle. Handle is the owned settings struct;
/// `free` releases the API-allocated strings/properties exactly once.
pub struct WinSettingsApi;

impl SettingsApi for WinSettingsApi {
    type Handle = DNS_INTERFACE_SETTINGS3;

    fn get(&self, guid: &str, flags: u64) -> Result<Self::Handle, CaptureError> {
        let g = parse_guid(guid).ok_or_else(|| CaptureError::QueryFailure(format!("bad adapter GUID {guid:?}")))?;
        let mut s: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        s.Version = SETTINGS_VERSION3;
        s.Flags = flags;
        let st = unsafe { GetInterfaceDnsSettings(g, (&mut s as *mut DNS_INTERFACE_SETTINGS3).cast()) };
        if st != NO_ERROR {
            // Nothing allocated on failure; do not free.
            return Err(map_status(st, format!("GetInterfaceDnsSettings flags={flags}")));
        }
        Ok(s)
    }

    fn deep_copy(&self, handle: &Self::Handle) -> Result<RawSettings, CaptureError> {
        let s = handle;
        Ok(RawSettings {
            flags_returned: s.Flags,
            name_server: unsafe { wstr(s.NameServer) },
            server_properties: unsafe { props_owned(s.ServerProperties, s.cServerProperties) },
            profile_name_server: unsafe { wstr(s.ProfileNameServer) },
            profile_server_properties: unsafe { props_owned(s.ProfileServerProperties, s.cProfileServerProperties) },
            domain: unsafe { wstr(s.Domain) },
            search_list: unsafe { wstr(s.SearchList) },
            registration_enabled: s.RegistrationEnabled,
            register_adapter_name: s.RegisterAdapterName,
            enable_llmnr: s.EnableLLMNR,
            query_adapter_name: s.QueryAdapterName,
            disable_unconstrained_queries: s.DisableUnconstrainedQueries,
            supplemental_search_list: unsafe { wstr(s.SupplementalSearchList) },
        })
    }

    fn free(&self, mut handle: Self::Handle) {
        unsafe { FreeInterfaceDnsSettings((&mut handle as *mut DNS_INTERFACE_SETTINGS3).cast()) };
    }
}

unsafe fn props_owned(p: *mut DNS_SERVER_PROPERTY, count: u32) -> Vec<RawProperty> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    for i in 0..count as usize {
        let prop = unsafe { &*p.add(i) };
        let (template, flags) = if prop.Type == DOH_PROPERTY_TYPE {
            match unsafe { prop.Property.DohSettings.as_ref() } {
                Some(d) => (unsafe { wstr(d.Template) }, d.Flags),
                None => (None, 0),
            }
        } else {
            (None, 0)
        };
        out.push(RawProperty {
            version: prop.Version,
            server_index: prop.ServerIndex,
            prop_type: prop.Type as u32,
            template,
            flags,
        });
    }
    out
}

// ---- registry provenance --------------------------------------------------

pub struct WinRegistry;

impl RegistryProvenance for WinRegistry {
    fn read_name_server(&self, guid: &str, family: Family) -> Result<RegistryValue, CaptureError> {
        let path = format!(
            "SYSTEM\\CurrentControlSet\\Services\\{}\\Parameters\\Interfaces\\{{{}}}",
            family.registry_service(),
            guid.to_uppercase()
        );
        let full = format!("HKLM\\{path}");
        let sub = wide(&path);
        let val = wide("NameServer");
        let mut hkey: HKEY = ptr::null_mut();
        let st = unsafe {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &mut hkey)
        };
        if st == ERROR_FILE_NOT_FOUND {
            return Ok(RegistryValue { path: full, exists: false, value_type: None, raw: None, text: None });
        }
        if st != NO_ERROR {
            return Err(map_status(st, format!("RegOpenKeyExW {full}")));
        }
        let result = query_name_server(hkey, &val, &full);
        unsafe { RegCloseKey(hkey) };
        result
    }
}

fn query_name_server(hkey: HKEY, val: &[u16], full: &str) -> Result<RegistryValue, CaptureError> {
    let mut typ = 0u32;
    let mut len = 0u32;
    let st = unsafe { RegQueryValueExW(hkey, val.as_ptr(), ptr::null_mut(), &mut typ, ptr::null_mut(), &mut len) };
    if st == ERROR_FILE_NOT_FOUND {
        return Ok(RegistryValue { path: full.to_string(), exists: false, value_type: None, raw: None, text: None });
    }
    if st != NO_ERROR {
        return Err(map_status(st, format!("RegQueryValueExW {full}")));
    }
    let mut data = vec![0u8; len as usize];
    let st2 = unsafe { RegQueryValueExW(hkey, val.as_ptr(), ptr::null_mut(), &mut typ, data.as_mut_ptr(), &mut len) };
    if st2 != NO_ERROR {
        return Err(map_status(st2, format!("RegQueryValueExW {full} (data)")));
    }
    data.truncate(len as usize);
    let text = match typ {
        1 | 2 => {
            let u16s: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let end = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
            Some(String::from_utf16_lossy(&u16s[..end]))
        }
        _ => None,
    };
    Ok(RegistryValue { path: full.to_string(), exists: true, value_type: Some(typ), raw: Some(data), text })
}

// ---- family probe ---------------------------------------------------------

pub struct WinProbe;

impl FamilyProbe for WinProbe {
    fn family_supported(&self, guid: &str, family: Family) -> Result<bool, CaptureError> {
        let g = parse_guid(guid).ok_or_else(|| CaptureError::QueryFailure(format!("bad adapter GUID {guid:?}")))?;
        let mut luid = NET_LUID_LH { Value: 0 };
        if unsafe { ConvertInterfaceGuidToLuid(&g, &mut luid) } != NO_ERROR {
            return Ok(false);
        }
        let af = match family {
            Family::Ipv4 => AF_INET,
            Family::Ipv6 => AF_INET6,
        };
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        row.Family = af;
        row.InterfaceLuid = luid;
        let st = unsafe { GetIpInterfaceEntry(&mut row) };
        Ok(st == NO_ERROR)
    }
}

// ---- backend --------------------------------------------------------------

/// Windows DNS backend: capability probing + stable deep-owned capture.
/// Construct with an explicit [`FamilySelectorPolicy`]. The conservative
/// default refuses IPv6; [`FamilySelectorPolicy::VersionGatedException`] enables
/// the Q1 ruling's approved, version-gated IPv6 selector (build >= 20348, read
/// only, family-consistency verified). The OS build used for the gate is read
/// from the registry at runtime by [`os_build`], not a compile-time constant.
pub struct WindowsDnsBackend {
    reader: ReaderDnsBackend<WinSettingsApi, WinRegistry, WinProbe>,
}

impl WindowsDnsBackend {
    pub fn new(policy: FamilySelectorPolicy) -> Self {
        Self {
            reader: ReaderDnsBackend {
                api: WinSettingsApi,
                registry: WinRegistry,
                probe: WinProbe,
                policy,
                os_build: os_build(),
                reader_revision: 1,
                clock: system_clock(),
            },
        }
    }

    /// Complete two-family capture (Q1 ruling): IPv4 via the documented Flags=0
    /// path plus IPv6 via the approved version-gated selector. Refuses the whole
    /// capture if the exception is unavailable or inconsistent — no IPv4-only
    /// fallback. Read-only.
    pub fn capture_complete(&self, guid: &str) -> Result<TwoFamilySnapshot, CaptureError> {
        self.reader.capture_complete(guid)
    }
}

impl DnsBackend for WindowsDnsBackend {
    fn adapters(&self) -> Result<Vec<AdapterIdentity>, CaptureError> {
        enumerate_identities()
    }
    fn capability(&self, guid: &str, family: Family) -> Result<Capability, CaptureError> {
        DnsBackend::capability(&self.reader, guid, family)
    }
    fn capture(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError> {
        self.reader.capture(guid, family)
    }
    fn readback(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError> {
        self.reader.readback(guid, family)
    }
}

fn enumerate_identities() -> Result<Vec<AdapterIdentity>, CaptureError> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 16 * 1024u32;
    let mut buf: Vec<u64> = Vec::new();
    let mut status = ERROR_BUFFER_OVERFLOW;
    for _ in 0..3 {
        buf.resize((size as usize).div_ceil(8), 0);
        let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        status = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, ptr::null(), head, &mut size) };
        if status != ERROR_BUFFER_OVERFLOW {
            break;
        }
    }
    if status != NO_ERROR {
        return Err(map_status(status, "GetAdaptersAddresses".into()));
    }
    let mut list = Vec::new();
    let mut next = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while let Some(a) = unsafe { next.as_ref() } {
        next = a.Next;
        if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let guid_str = unsafe { cstr(a.AdapterName) }.trim_matches(['{', '}']).to_lowercase();
        let Some(guid) = parse_guid(&guid_str) else { continue };
        let mut luid = NET_LUID_LH { Value: 0 };
        let mut if_index = 0u32;
        if unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) } == NO_ERROR {
            unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
        }
        list.push(AdapterIdentity {
            adapter_guid: guid_str,
            luid: unsafe { luid.Value },
            if_index,
            name_hint: unsafe { wstr(a.FriendlyName) }.unwrap_or_default(),
            device_instance_hint: None,
        });
    }
    Ok(list)
}

// ---- helpers --------------------------------------------------------------

fn map_status(st: u32, ctx: String) -> CaptureError {
    if st == ERROR_ACCESS_DENIED {
        CaptureError::AccessDenied(ctx)
    } else {
        CaptureError::QueryFailure(format!("{ctx}: {st}"))
    }
}

fn parse_guid(s: &str) -> Option<GUID> {
    let hex: String = s.trim_matches(['{', '}']).split('-').collect();
    if hex.len() != 32 {
        return None;
    }
    Some(GUID::from_u128(u128::from_str_radix(&hex, 16).ok()?))
}

unsafe fn cstr(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(p.cast()).to_string_lossy().into_owned() }
}

unsafe fn wstr(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let len = unsafe { (0..).take_while(|&i| *p.add(i) != 0).count() };
    Some(unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(p, len)) })
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn reg_text(subkey: &str, value: &str) -> Option<String> {
    let sub = wide(subkey);
    let val = wide(value);
    let mut hkey: HKEY = ptr::null_mut();
    let st = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &mut hkey) };
    if st != NO_ERROR {
        return None;
    }
    let mut typ = 0u32;
    let mut len = 0u32;
    let st = unsafe { RegQueryValueExW(hkey, val.as_ptr(), ptr::null_mut(), &mut typ, ptr::null_mut(), &mut len) };
    let out = if st == NO_ERROR {
        let mut data = vec![0u8; len as usize];
        let st2 = unsafe { RegQueryValueExW(hkey, val.as_ptr(), ptr::null_mut(), &mut typ, data.as_mut_ptr(), &mut len) };
        if st2 == NO_ERROR {
            data.truncate(len as usize);
            match typ {
                1 | 2 => {
                    let u16s: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let end = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
                    Some(String::from_utf16_lossy(&u16s[..end]))
                }
                4 if data.len() >= 4 => Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string()),
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    };
    unsafe { RegCloseKey(hkey) };
    out
}

/// Runtime OS build ("CurrentBuild" + optional ".UBR") read from the registry.
/// This is the value the Q1 version gate compares against MIN_SELECTOR_BUILD;
/// it is read from the OS at runtime, never a compile-time constant.
fn os_build() -> String {
    let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let build = reg_text(key, "CurrentBuild").unwrap_or_default();
    let ubr = reg_text(key, "UBR").unwrap_or_default();
    if ubr.is_empty() { build } else { format!("{build}.{ubr}") }
}

// ---- qualified setter adapter (U03) ----------------------------------------

/// Setter mask for one family. NAMESERVER|DOH always travel together (the
/// qualified setter is not field-atomic: a NAMESERVER-only write clears DoH
/// properties). IPv6 adds the family selector only on builds >=
/// MIN_SELECTOR_BUILD; below the gate the call is refused as unsupported —
/// never silently downgraded to an IPv4-masked write.
fn setter_mask_for(family: Family, build: &str) -> Result<u64, SetterError> {
    let mut mask = DNS_SETTING_NAMESERVER | DNS_SETTING_DOH;
    if family == Family::Ipv6 {
        let major = build
            .split('.')
            .next()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .ok_or_else(|| SetterError {
                status: ERROR_NOT_SUPPORTED,
                message: format!("cannot establish OS build from {build:?}; refusing IPv6 setter selector"),
            })?;
        if major < MIN_SELECTOR_BUILD {
            return Err(SetterError {
                status: ERROR_NOT_SUPPORTED,
                message: format!(
                    "IPv6 setter selector requires build >= {MIN_SELECTOR_BUILD}; OS build {major}"
                ),
            });
        }
        mask |= DNS_SETTING_IPV6;
    }
    Ok(mask)
}

/// Owned property arrays for one setter call. The template buffers and DoH
/// settings must outlive the property array (which points into them); the
/// caller keeps all three alive across the API call.
fn property_arrays(
    image: &SetterImage,
) -> (Vec<Vec<u16>>, Vec<DNS_DOH_SERVER_SETTINGS>, Vec<DNS_SERVER_PROPERTY>) {
    let n = image.properties.len();
    let mut templates: Vec<Vec<u16>> = Vec::with_capacity(n);
    let mut doh: Vec<DNS_DOH_SERVER_SETTINGS> = Vec::with_capacity(n);
    for p in &image.properties {
        let buf = p.doh.template.as_deref().map(wide).unwrap_or_default();
        let template_ptr = if p.doh.template.is_some() {
            buf.as_ptr() as PWSTR
        } else {
            ptr::null_mut()
        };
        templates.push(buf);
        doh.push(DNS_DOH_SERVER_SETTINGS { Template: template_ptr, Flags: p.doh.flags });
    }
    let mut props: Vec<DNS_SERVER_PROPERTY> = Vec::with_capacity(n);
    for (i, p) in image.properties.iter().enumerate() {
        props.push(DNS_SERVER_PROPERTY {
            Version: p.version,
            ServerIndex: p.server_index,
            Type: p.prop_type as i32,
            Property: DNS_SERVER_PROPERTY_TYPES { DohSettings: &mut doh[i] },
        });
    }
    (templates, doh, props)
}

/// Qualified Windows setter adapter. One interface-scoped
/// SetInterfaceDnsSettings call per journaled intent; the request ID is the
/// engine's idempotency key (the OS API itself has none — a lost reply is
/// settled by configured readback, never by a duplicate call).
pub struct WinSetter {
    os_build: String,
}

impl Default for WinSetter {
    fn default() -> Self {
        Self::new()
    }
}

impl WinSetter {
    /// Reads the OS build from the registry at runtime for the IPv6 gate.
    pub fn new() -> Self {
        Self { os_build: os_build() }
    }
}

impl DnsSetter for WinSetter {
    fn set(
        &self,
        request_id: &str,
        guid: &str,
        family: Family,
        image: &SetterImage,
    ) -> Result<(), SetterError> {
        let mask = setter_mask_for(family, &self.os_build)?;
        let g = parse_guid(guid).ok_or_else(|| SetterError {
            status: ERROR_INVALID_PARAMETER,
            message: format!("bad adapter GUID {guid:?}"),
        })?;
        // Empty automatic NameServer is a pointer to an empty wide string,
        // never null (Q1-EVIDENCE.md qualification 1/2).
        let ns = wide(&image.name_server);
        let (_templates, _doh, mut props) = property_arrays(image);
        let mut s: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        s.Version = SETTINGS_VERSION3;
        s.Flags = mask;
        s.NameServer = ns.as_ptr() as PWSTR;
        if !props.is_empty() {
            s.cServerProperties = props.len() as u32;
            s.ServerProperties = props.as_mut_ptr();
        }
        let st = unsafe { SetInterfaceDnsSettings(g, (&s as *const DNS_INTERFACE_SETTINGS3).cast()) };
        if st != NO_ERROR {
            return Err(SetterError {
                status: st,
                message: format!(
                    "SetInterfaceDnsSettings {guid} {} mask={mask} request={request_id}",
                    family.as_str()
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod setter_tests {
    use super::*;
    use crate::model::{DohSettings, ServerProperty};

    #[test]
    fn mask_v4_is_nameserver_plus_doh_only() {
        let mask = setter_mask_for(Family::Ipv4, "26300.9974").unwrap();
        assert_eq!(mask, DNS_SETTING_NAMESERVER | DNS_SETTING_DOH);
        assert_eq!(mask & DNS_SETTING_IPV6, 0);
    }

    #[test]
    fn mask_v6_adds_selector_above_gate() {
        let mask = setter_mask_for(Family::Ipv6, "26300.9974").unwrap();
        assert_eq!(mask, DNS_SETTING_NAMESERVER | DNS_SETTING_DOH | DNS_SETTING_IPV6);
        assert_eq!(setter_mask_for(Family::Ipv6, "20348").unwrap(), mask);
    }

    #[test]
    fn mask_v6_refused_below_gate_or_unknown_build() {
        for build in ["19045", "20347.1", ""] {
            let e = setter_mask_for(Family::Ipv6, build).unwrap_err();
            assert_eq!(e.status, ERROR_NOT_SUPPORTED);
            assert!(!e.retryable());
        }
        // IPv4 never needs the selector gate.
        assert!(setter_mask_for(Family::Ipv4, "19045").is_ok());
    }

    #[test]
    fn empty_name_server_is_empty_wide_not_null() {
        let w = wide("");
        assert_eq!(w, vec![0], "one terminator element: a real buffer, never NULL");
    }

    #[test]
    fn property_arrays_preserve_index_type_flags_and_templates() {
        let image = SetterImage {
            name_server: "1.1.1.1,1.0.0.1".into(),
            properties: vec![
                ServerProperty {
                    version: 1,
                    server_index: 0,
                    prop_type: 1,
                    doh: DohSettings { template: Some("https://cloudflare-dns.com/dns-query".into()), flags: 2 },
                },
                ServerProperty {
                    version: 1,
                    server_index: 1,
                    prop_type: 1,
                    doh: DohSettings { template: None, flags: 1 },
                },
            ],
        };
        let (templates, doh, props) = property_arrays(&image);
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].ServerIndex, 0);
        assert_eq!(props[1].ServerIndex, 1);
        assert_eq!(props[0].Version, 1);
        assert_eq!(props[0].Type, DOH_PROPERTY_TYPE);
        assert_eq!(doh[0].Flags, 2);
        assert_eq!(doh[1].Flags, 1);
        assert!(!doh[0].Template.is_null());
        assert!(doh[1].Template.is_null());
        let decoded = unsafe { wstr(doh[0].Template) }.unwrap();
        assert_eq!(decoded, "https://cloudflare-dns.com/dns-query");
        assert_eq!(templates.len(), 2);
    }

    #[test]
    fn automatic_image_is_empty_string_zero_properties() {
        let snap = Snapshot {
            schema_version: 1,
            family: Family::Ipv4,
            provenance: Provenance::Automatic,
            name_server_raw: Some(String::new()),
            ordered_servers: vec![],
            provenance_evidence: ProvenanceEvidence {
                registry_path: String::new(),
                value_exists: true,
                value_type: Some(1),
                raw_value_base64: None,
                api_flags: 0,
                captured_at_utc: "2026-11-14T00:00:00Z".into(),
            },
            server_properties: vec![],
            context: DnsContext::default(),
            capability: Capability {
                os_build: "26300.9974".into(),
                reader_revision: 1,
                api_version: 3,
                family_supported: true,
            },
        };
        let image = SetterImage::from_target(&snap);
        assert_eq!(image.name_server, "");
        assert!(image.properties.is_empty());
    }
}

//! Deep-owned Windows reader/readback/capability probing (U01). Implements the
//! same [`SettingsApi`]/[`RegistryProvenance`]/[`FamilyProbe`] traits as the
//! fakes, so the capture contract is identical. Read-only: no setter is linked
//! into the library. Every successful getter is freed exactly once via the
//! generic RAII guard after a deep copy.

#![cfg(windows)]

use crate::backend::*;
use crate::model::*;
use std::ptr;
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, NO_ERROR,
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
/// Construct with an explicit [`FamilySelectorPolicy`]; the default refuses
/// IPv6 until Q1 is ruled (no approved documented IPv6 getter contract).
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

fn os_build() -> String {
    let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let build = reg_text(key, "CurrentBuild").unwrap_or_default();
    let ubr = reg_text(key, "UBR").unwrap_or_default();
    if ubr.is_empty() { build } else { format!("{build}.{ubr}") }
}

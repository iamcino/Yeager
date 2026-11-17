//! Windows side: which resolvers each network adapter uses, and Windows'
//! own DNS over HTTPS settings for them — read and written through the
//! documented IP Helper API (`GetAdaptersAddresses`,
//! `GetInterfaceDnsSettings`, `SetInterfaceDnsSettings`), the same calls the
//! Settings app makes, rather than scripting PowerShell and the registry:
//! a hidden encoded PowerShell rewriting DNS is exactly what antivirus
//! behaviour engines flag as a DNS hijacker.
//!
//! The mutation side is backup-state-and-restore only: [`capture`] reads the
//! current configured state, [`apply`] points adapters at the stub, and
//! [`restore`] writes the captured state back. There is no heuristic clear
//! and no service: the caller saves a backup first and restores it on
//! disable, exit, or crash leftover.

use common::{DohProvider, Error, Result};
use std::net::IpAddr;

/// One address family's captured configured state: the getter-raw
/// `NameServer` string (empty means automatic/DHCP) and its DoH server
/// properties. Writing these back verbatim is the qualified restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyBackup {
    pub name_server: String,
    pub properties: Vec<DohProperty>,
}

/// One adapter's captured DNS, keyed by GUID so restore targets the same
/// interface even if it has since gone offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterBackup {
    pub guid: String,
    pub name: String,
    pub v4: FamilyBackup,
    pub v6: FamilyBackup,
}

/// Points every online adapter at `local` (the stub's loopback addresses,
/// if serving) followed by the provider's resolvers, each set to DoH with no
/// plaintext fallback. Returns the adapters changed. No heuristic clear:
/// the caller must [`capture`] a backup before calling this.
pub fn apply(provider: DohProvider, local: &[&str]) -> Result<Vec<String>> {
    win::apply(provider, local)
}

/// Captures the current configured DNS of every online adapter (the ones
/// [`apply`] touches), for a backup saved before any mutation.
pub fn capture() -> Result<Vec<AdapterBackup>> {
    win::capture()
}

/// Writes captured state back to each adapter: IPv4 must succeed, IPv6 is
/// best-effort. Flushes the resolver cache. The caller deletes the backup
/// only once this returns `Ok`.
pub fn restore(backups: &[AdapterBackup]) -> Result<()> {
    win::restore(backups)
}

/// Effective (static or DHCP) DNS per adapter, for diagnostics and legacy
/// detection evidence. Read-only: names with their configured resolver
/// lists. This sees effective addresses only — not provenance or DoH
/// properties — so legacy classification from this input alone can never
/// reach "exact candidate" (see `legacy::classify_family`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    pub name: String,
    pub dns: Vec<String>,
}

/// All adapters with their effective DNS. Off Windows this reports the
/// platform error instead of guessing.
pub fn adapter_dns() -> Result<Vec<AdapterInfo>> {
    Ok(win::adapters()?
        .into_iter()
        .map(|a| AdapterInfo {
            name: a.name,
            dns: a.dns.iter().map(|ip| ip.to_string()).collect(),
        })
        .collect())
}

/// One DoH server property as configured on the interface (spec §9 input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohProperty {
    pub version: u32,
    pub index: u32,
    pub prop_type: u32,
    pub template: Option<String>,
    pub flags: u64,
}

/// One address family's configured servers plus their DoH properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyDns {
    pub servers: Vec<String>,
    pub properties: Vec<DohProperty>,
}

/// One adapter's configured DNS for legacy detection: both families with
/// full server lists and DoH properties (unlike [`adapter_dns`], which sees
/// effective addresses only). Empty when the family is not configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyAdapterInfo {
    pub guid: String,
    pub name: String,
    pub v4: Option<FamilyDns>,
    pub v6: Option<FamilyDns>,
}

/// Configured DNS with DoH properties for every adapter (spec §9 input).
/// Unlike [`adapter_dns`], this carries templates/flags, so an exact legacy
/// shape can classify as `ExactCandidate` when the facts say so. Read-only.
pub fn legacy_adapter_info() -> Result<Vec<LegacyAdapterInfo>> {
    win::legacy_adapters()
}

/// PIDs holding loopback port 53 (spec §9 listener evidence): TCP and UDP
/// owners of 127.0.0.1:53 via the owner tables with process identity.
/// `None` per family means unknown/free. Read-only; used to tell our own
/// stub from a live legacy GUI or an unidentified foreign listener.
pub fn loopback_port_owners() -> (Option<u32>, Option<u32>) {
    win::loopback_owners()
}

/// Checks that Windows itself resolves through Yeager: every online adapter
/// lists only `local` and the provider's resolvers, the latter with DoH on.
/// Returns the adapters verified, or says which one is not.
pub fn verify(provider: DohProvider, local: &[&str]) -> Result<Vec<String>> {
    let encrypted = encrypted_servers(provider, local);
    let allowed: Vec<IpAddr> = local
        .iter()
        .chain(&encrypted)
        .filter_map(|s| s.parse().ok())
        .collect();
    let online: Vec<_> = win::adapters()?.into_iter().filter(|a| a.online).collect();
    if online.is_empty() {
        return Err(Error::new(common::lang::tr(
            "Không tìm thấy card mạng đang có kết nối Internet.",
            "No network adapter with an Internet connection was found.",
        )));
    }
    for adapter in &online {
        let foreign: Vec<String> = adapter
            .dns
            .iter()
            .filter(|ip| !allowed.contains(ip))
            .map(IpAddr::to_string)
            .collect();
        if adapter.dns.is_empty() || !foreign.is_empty() {
            return Err(Error::new(common::t!(
                "{} đang dùng DNS {}, không chỉ {}.",
                "{} uses DNS {}, not only {}.",
                adapter.name,
                foreign.join(", "),
                provider.label()
            )));
        }
        for ipv6 in [false, true] {
            if !adapter.dns.iter().any(|ip| ip.is_ipv6() == ipv6) {
                continue; // family not in use on this adapter
            }
            let missing = win::servers_without_doh(&adapter.guid, ipv6, &encrypted)?;
            if let Some(server) = missing.first() {
                return Err(Error::new(common::t!(
                    "{} chưa bật mã hoá cho {server}.",
                    "{} has no encryption on for {server}.",
                    adapter.name
                )));
            }
        }
    }
    Ok(online.into_iter().map(|a| a.name).collect())
}

/// With a stub in front, one resolver per address family is enough as the
/// encrypted fallback; without one, all of them.
fn encrypted_servers(provider: DohProvider, local: &[&str]) -> Vec<&'static str> {
    let servers = provider.servers();
    if local.is_empty() {
        servers.to_vec()
    } else {
        vec![servers[0], servers[2]]
    }
}

#[cfg(windows)]
mod win {
    use common::{DohProvider, Error, Result};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr;
    use windows_sys::core::{GUID, PWSTR};
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKET_ADDRESS};

    pub struct Adapter {
        pub guid: GUID,
        pub name: String,
        /// Up and with a default gateway: actually carries traffic.
        pub online: bool,
        /// Resolvers in effect, static or from DHCP.
        pub dns: Vec<IpAddr>,
    }

    impl Adapter {
        /// Lowercase brace-free GUID string: the identity the journal keys
        /// entries on (never display name or index).
        pub fn guid_string(&self) -> String {
            format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                self.guid.data1,
                self.guid.data2,
                self.guid.data3,
                self.guid.data4[0],
                self.guid.data4[1],
                self.guid.data4[2],
                self.guid.data4[3],
                self.guid.data4[4],
                self.guid.data4[5],
                self.guid.data4[6],
                self.guid.data4[7],
            )
        }
    }

    pub fn adapters() -> Result<Vec<Adapter>> {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size = 16 * 1024u32;
        let mut buf: Vec<u64> = Vec::new(); // u64 keeps the structs aligned
        let mut status = ERROR_BUFFER_OVERFLOW;
        for _ in 0..3 {
            buf.resize((size as usize).div_ceil(8), 0);
            let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            status = unsafe {
                GetAdaptersAddresses(AF_UNSPEC as u32, flags, ptr::null(), head, &mut size)
            };
            if status != ERROR_BUFFER_OVERFLOW {
                break;
            }
        }
        if status != NO_ERROR {
            return Err(Error::new(common::t!(
                "Không đọc được danh sách card mạng (lỗi {status}).",
                "Could not read the network adapters (error {status})."
            )));
        }

        let mut list = Vec::new();
        let mut next = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while let Some(a) = unsafe { next.as_ref() } {
            next = a.Next;
            if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            let Some(guid) = parse_guid(&unsafe { cstr(a.AdapterName) }) else {
                continue;
            };
            let mut dns = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while let Some(entry) = unsafe { d.as_ref() } {
                dns.extend(unsafe { sockaddr_ip(&entry.Address) });
                d = entry.Next;
            }
            let mut has_gateway = false;
            let mut g = a.FirstGatewayAddress;
            while let Some(entry) = unsafe { g.as_ref() } {
                has_gateway |=
                    unsafe { sockaddr_ip(&entry.Address) }.is_some_and(|ip| !ip.is_unspecified());
                g = entry.Next;
            }
            list.push(Adapter {
                guid,
                name: unsafe { wstr(a.FriendlyName) },
                online: a.OperStatus == IfOperStatusUp && has_gateway,
                dns,
            });
        }
        Ok(list)
    }

    /// Those of `expected` configured on the adapter for this family without
    /// DoH required (not set at all, DoH off, or plaintext fallback allowed).
    pub fn servers_without_doh(guid: &GUID, ipv6: bool, expected: &[&str]) -> Result<Vec<String>> {
        let mut settings: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
        settings.Flags = if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 };
        let status = unsafe {
            GetInterfaceDnsSettings(
                *guid,
                (&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast(),
            )
        };
        if status != NO_ERROR {
            return Err(Error::new(common::t!("GetInterfaceDnsSettings lỗi {status}.", "GetInterfaceDnsSettings failed ({status}).")));
        }
        let servers: Vec<String> = unsafe { wstr(settings.NameServer) }
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let mut encrypted = vec![false; servers.len()];
        for i in 0..settings.cServerProperties as usize {
            let p = unsafe { &*settings.ServerProperties.add(i) };
            if p.Type != DnsServerDohProperty {
                continue;
            }
            let flags = unsafe { p.Property.DohSettings.as_ref() }.map_or(0, |d| d.Flags);
            let required = flags
                & (DNS_DOH_SERVER_SETTINGS_ENABLE | DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO) as u64
                != 0
                && flags & DNS_DOH_SERVER_SETTINGS_FALLBACK_TO_UDP as u64 == 0;
            if let Some(slot) = encrypted.get_mut(p.ServerIndex as usize) {
                *slot = required;
            }
        }
        unsafe { FreeInterfaceDnsSettings((&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast()) };

        let family = |s: &&&str| s.contains(':') == ipv6;
        Ok(expected
            .iter()
            .filter(family)
            .filter(|s| {
                !servers
                    .iter()
                    .zip(&encrypted)
                    .any(|(server, &enc)| server == **s && enc)
            })
            .map(|s| s.to_string())
            .collect())
    }

    pub fn apply(provider: DohProvider, local: &[&str]) -> Result<Vec<String>> {
        let encrypted = super::encrypted_servers(provider, local);
        let online: Vec<_> = adapters()?.into_iter().filter(|a| a.online).collect();
        if online.is_empty() {
            return Err(Error::new(common::lang::tr(
                "Không tìm thấy card mạng đang có kết nối Internet.",
                "No network adapter with an Internet connection was found.",
            )));
        }
        for ipv6 in [false, true] {
            let family = |s: &&str| s.contains(':') == ipv6;
            let servers: Vec<&str> = local.iter().chain(&encrypted).copied().filter(family).collect();
            let properties: Vec<super::DohProperty> = servers
                .iter()
                .enumerate()
                .filter(|(_, s)| !local.contains(s))
                .map(|(i, _)| super::DohProperty {
                    version: DNS_SERVER_PROPERTY_VERSION1,
                    index: i as u32,
                    prop_type: DnsServerDohProperty as u32,
                    template: Some(provider.template().to_string()),
                    flags: DNS_DOH_SERVER_SETTINGS_ENABLE as u64,
                })
                .collect();
            let name_server = servers.join(",");
            for adapter in &online {
                let set = write_family(&adapter.guid, ipv6, &name_server, &properties);
                // IPv6 may be switched off on the adapter; IPv4 must work.
                if !ipv6 {
                    set.map_err(|e| {
                        Error::new(common::t!("Không đặt được DNS cho {}: {e}", "Could not set DNS on {}: {e}", adapter.name))
                    })?;
                }
            }
        }
        flush_cache();
        Ok(online.into_iter().map(|a| a.name).collect())
    }

    pub fn capture() -> Result<Vec<super::AdapterBackup>> {
        let mut out = Vec::new();
        for a in adapters()?.into_iter().filter(|a| a.online) {
            let v4 = capture_family(&a.guid, false)?;
            let v6 = capture_family(&a.guid, true).unwrap_or(super::FamilyBackup {
                name_server: String::new(),
                properties: Vec::new(),
            });
            out.push(super::AdapterBackup { guid: a.guid_string(), name: a.name, v4, v6 });
        }
        Ok(out)
    }

    pub fn restore(backups: &[super::AdapterBackup]) -> Result<()> {
        for b in backups {
            let Some(guid) = parse_guid(&b.guid) else { continue };
            write_family(&guid, false, &b.v4.name_server, &b.v4.properties).map_err(|e| {
                Error::new(common::t!("Không khôi phục được DNS cho {}: {e}", "Could not restore DNS on {}: {e}", b.name))
            })?;
            let _ = write_family(&guid, true, &b.v6.name_server, &b.v6.properties);
        }
        flush_cache();
        Ok(())
    }

    /// Getter-raw `NameServer` plus DoH properties for one family. Unlike
    /// [`family_settings`], an unconfigured family is a valid empty capture
    /// (writing it back restores automatic/DHCP), not an error.
    fn capture_family(guid: &GUID, ipv6: bool) -> Result<super::FamilyBackup> {
        let mut settings: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
        settings.Flags = if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 };
        let status = unsafe {
            GetInterfaceDnsSettings(*guid, (&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast())
        };
        if status != NO_ERROR {
            unsafe { FreeInterfaceDnsSettings((&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast()) };
            return Err(Error::new(common::t!("GetInterfaceDnsSettings lỗi {status}.", "GetInterfaceDnsSettings failed ({status}).")));
        }
        let name_server = unsafe { wstr(settings.NameServer) };
        let mut properties = Vec::new();
        for i in 0..settings.cServerProperties as usize {
            let p = unsafe { &*settings.ServerProperties.add(i) };
            let template = unsafe { p.Property.DohSettings.as_ref() }.and_then(|d| {
                if d.Template.is_null() { None } else { Some(unsafe { wstr(d.Template) }) }
            });
            let flags = unsafe { p.Property.DohSettings.as_ref() }.map_or(0, |d| d.Flags);
            properties.push(super::DohProperty {
                version: p.Version,
                index: p.ServerIndex,
                prop_type: p.Type as u32,
                template,
                flags,
            });
        }
        unsafe { FreeInterfaceDnsSettings((&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast()) };
        Ok(super::FamilyBackup { name_server, properties })
    }

    /// Writes one family's `NameServer` and DoH properties together. The
    /// setter is not field-atomic: a NAMESERVER-only write clears DoH, so
    /// both flags are always carried. An empty `name_server` is a pointer to
    /// an empty wide string (never null), which restores automatic/DHCP.
    fn write_family(
        guid: &GUID,
        ipv6: bool,
        name_server: &str,
        properties: &[super::DohProperty],
    ) -> Result<()> {
        let mut ns = wide(name_server);
        // Template buffers must outlive the property arrays that point at them.
        let mut templates: Vec<Vec<u16>> = properties
            .iter()
            .map(|p| wide(p.template.as_deref().unwrap_or("")))
            .collect();
        let mut doh: Vec<DNS_DOH_SERVER_SETTINGS> = properties
            .iter()
            .enumerate()
            .map(|(i, p)| DNS_DOH_SERVER_SETTINGS { Template: templates[i].as_mut_ptr(), Flags: p.flags })
            .collect();
        let mut props: Vec<DNS_SERVER_PROPERTY> = properties
            .iter()
            .enumerate()
            .map(|(i, p)| DNS_SERVER_PROPERTY {
                Version: p.version,
                ServerIndex: p.index,
                Type: p.prop_type as _,
                Property: DNS_SERVER_PROPERTY_TYPES { DohSettings: &mut doh[i] },
            })
            .collect();
        let mut settings: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
        settings.Flags = (DNS_SETTING_NAMESERVER | DNS_SETTING_DOH | if ipv6 { DNS_SETTING_IPV6 } else { 0 }) as u64;
        settings.NameServer = ns.as_mut_ptr();
        settings.cServerProperties = props.len() as u32;
        settings.ServerProperties = if props.is_empty() { ptr::null_mut() } else { props.as_mut_ptr() };
        let status = unsafe {
            SetInterfaceDnsSettings(*guid, (&settings as *const DNS_INTERFACE_SETTINGS3).cast())
        };
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(Error::new(common::t!(
                "SetInterfaceDnsSettings lỗi {status}. Yeager cần quyền Administrator.",
                "SetInterfaceDnsSettings failed ({status}). Yeager needs administrator rights."
            )))
        }
    }

    pub fn flush_cache() {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
        unsafe {
            let lib = LoadLibraryA(b"dnsapi.dll\0".as_ptr());
            if !lib.is_null() {
                if let Some(proc) = GetProcAddress(lib, b"DnsFlushResolverCache\0".as_ptr()) {
                    let func: unsafe extern "system" fn() -> i32 = std::mem::transmute(proc);
                    func();
                }
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` → GUID.
    fn parse_guid(s: &str) -> Option<GUID> {
        let hex: String = s.trim_matches(['{', '}']).split('-').collect();
        if hex.len() != 32 {
            return None;
        }
        let n = u128::from_str_radix(&hex, 16).ok()?;
        Some(GUID::from_u128(n))
    }

    unsafe fn sockaddr_ip(a: &SOCKET_ADDRESS) -> Option<IpAddr> {
        let p = a.lpSockaddr.cast::<u8>();
        if p.is_null() {
            return None;
        }
        let family = unsafe { (*a.lpSockaddr).sa_family };
        if family == AF_INET && a.iSockaddrLength >= 8 {
            let b = unsafe { std::slice::from_raw_parts(p.add(4), 4) };
            Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        } else if family == AF_INET6 && a.iSockaddrLength >= 24 {
            let mut b = [0u8; 16];
            unsafe {
                b.copy_from_slice(std::slice::from_raw_parts(p.add(8), 16));
            }
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        } else {
            None
        }
    }

    unsafe fn cstr(p: *const u8) -> String {
        if p.is_null() {
            return String::new();
        }
        unsafe {
            std::ffi::CStr::from_ptr(p.cast())
                .to_string_lossy()
                .into_owned()
        }
    }

    unsafe fn wstr(p: PWSTR) -> String {
        if p.is_null() {
            return String::new();
        }
        let len = unsafe { (0..).take_while(|&i| *p.add(i) != 0).count() };
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(p, len)) }
    }

    fn family_settings(guid: &GUID, ipv6: bool) -> Result<super::FamilyDns> {
        let mut settings: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
        settings.Flags = if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 };
        let status = unsafe {
            GetInterfaceDnsSettings(
                *guid,
                (&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast(),
            )
        };
        if status != NO_ERROR {
            unsafe { FreeInterfaceDnsSettings((&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast()) };
            return Err(Error::new(common::t!("GetInterfaceDnsSettings lỗi {status}.", "GetInterfaceDnsSettings failed ({status}).")));
        }
        let servers: Vec<String> = unsafe { wstr(settings.NameServer) }
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let mut properties = Vec::new();
        for i in 0..settings.cServerProperties as usize {
            let p = unsafe { &*settings.ServerProperties.add(i) };
            let template = unsafe { p.Property.DohSettings.as_ref() }.and_then(|d| {
                if d.Template.is_null() {
                    None
                } else {
                    Some(unsafe { wstr(d.Template) })
                }
            });
            let flags = unsafe { p.Property.DohSettings.as_ref() }.map_or(0, |d| d.Flags);
            properties.push(super::DohProperty {
                version: p.Version,
                index: p.ServerIndex,
                prop_type: p.Type as u32,
                template,
                flags,
            });
        }
        unsafe { FreeInterfaceDnsSettings((&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast()) };
        if servers.is_empty() && properties.is_empty() {
            // Family not configured: leave absent so classification treats it
            // as unsupported rather than as an empty exact shape.
            return Err(Error::new("family not configured"));
        }
        Ok(super::FamilyDns { servers, properties })
    }

    pub fn legacy_adapters() -> Result<Vec<super::LegacyAdapterInfo>> {
        let mut out = Vec::new();
        for a in adapters()? {
            let guid_str = a.guid_string();
            let v4 = family_settings(&a.guid, false).ok();
            let v6 = family_settings(&a.guid, true).ok();
            if v4.is_none() && v6.is_none() {
                continue;
            }
            out.push(super::LegacyAdapterInfo {
                guid: guid_str,
                name: a.name,
                v4,
                v6,
            });
        }
        Ok(out)
    }

    /// Owner PIDs for 127.0.0.1:53 from the TCP/UDP owner tables (spec §9).
    /// Returns `(tcp_owner, udp_owner)`; `None` means no entry or unknown.
    pub fn loopback_owners() -> (Option<u32>, Option<u32>) {
        (tcp_loopback_owner(), udp_loopback_owner())
    }

    const LOOPBACK_V4: u32 = 0x0100007f; // 127.0.0.1 as little-endian u32
    const PORT53_NET: u32 = 0x3500; // 53 in network byte order (low 16 bits)

    fn tcp_loopback_owner() -> Option<u32> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;
        let mut size: u32 = 0;
        // Size query first.
        let rc = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        // 122 == ERROR_INSUFFICIENT_BUFFER: size now holds the need.
        if rc != 122 || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        let rows = unsafe {
            std::slice::from_raw_parts(
                (&table.table as *const _) as *const MIB_TCPROW_OWNER_PID,
                n.min(4096),
            )
        };
        use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID;
        let mut found: Option<u32> = None;
        for r in rows {
            // dwLocalAddr is network-order IPv4; dwLocalPort holds the port
            // in network byte order in its low 16 bits.
            if r.dwLocalAddr == LOOPBACK_V4 && (r.dwLocalPort & 0xffff) == PORT53_NET {
                found = Some(r.dwOwningPid);
                break;
            }
        }
        found
    }

    fn udp_loopback_owner() -> Option<u32> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;
        let mut size: u32 = 0;
        let rc = unsafe {
            GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if rc != 122 || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        let rows = unsafe {
            std::slice::from_raw_parts(
                (&table.table as *const _) as *const MIB_UDPROW_OWNER_PID,
                n.min(4096),
            )
        };
        use windows_sys::Win32::NetworkManagement::IpHelper::MIB_UDPROW_OWNER_PID;
        let mut found: Option<u32> = None;
        for r in rows {
            if r.dwLocalAddr == LOOPBACK_V4 && (r.dwLocalPort & 0xffff) == PORT53_NET {
                found = Some(r.dwOwningPid);
                break;
            }
        }
        found
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn parses_adapter_guid() {
            let g = super::parse_guid("{4D36E972-E325-11CE-BFC1-08002BE10318}").unwrap();
            assert_eq!(g.data1, 0x4D36E972);
            assert_eq!(g.data4, [0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18]);
        }
    }
}

/// Lets the crate build and its tests run off Windows; nothing here is ever
/// reached in the app, which only ships for Windows.
#[cfg(not(windows))]
mod win {
    use common::{DohProvider, Error, Result};
    use std::net::IpAddr;

    pub struct Adapter {
        pub guid: (),
        pub name: String,
        pub online: bool,
        pub dns: Vec<IpAddr>,
    }

    impl Adapter {
        pub fn guid_string(&self) -> String {
            String::new()
        }
    }

    fn unsupported<T>() -> Result<T> {
        Err(Error::new(common::lang::tr("Chỉ hỗ trợ Windows.", "Windows only.")))
    }

    pub fn adapters() -> Result<Vec<Adapter>> {
        unsupported()
    }

    pub fn servers_without_doh(_: &(), _: bool, _: &[&str]) -> Result<Vec<String>> {
        unsupported()
    }

    pub fn legacy_adapters() -> Result<Vec<super::LegacyAdapterInfo>> {
        unsupported()
    }

    pub fn loopback_owners() -> (Option<u32>, Option<u32>) {
        (None, None)
    }

    pub fn apply(_: DohProvider, _: &[&str]) -> Result<Vec<String>> {
        unsupported()
    }

    pub fn capture() -> Result<Vec<super::AdapterBackup>> {
        unsupported()
    }

    pub fn restore(_: &[super::AdapterBackup]) -> Result<()> {
        unsupported()
    }
}

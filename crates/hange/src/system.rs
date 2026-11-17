//! Windows side: which resolvers each network adapter uses, and Windows'
//! own DNS over HTTPS settings for them.
//!
//! Everything goes through the documented IP Helper API
//! (`GetAdaptersAddresses`, `SetInterfaceDnsSettings`), the same calls the
//! Settings app makes, rather than scripting PowerShell and the registry:
//! a hidden encoded PowerShell rewriting DNS is exactly what antivirus
//! behaviour engines flag as a DNS hijacker.

use common::{DohProvider, Error, Result};
use std::net::IpAddr;

/// Points every online adapter at `local` (Yeager's loopback stub, if
/// running) followed by the provider's resolvers, each set to DoH with no
/// plaintext fallback, so that if the stub stops answering Windows falls back
/// to its own DoH instead of plaintext. Returns the adapters changed.
///
/// Every adapter is first cleared of resolvers from an earlier run, so the
/// system never mixes two providers.
pub fn apply(provider: DohProvider, local: &[&str]) -> Result<Vec<String>> {
    reset();
    let encrypted = encrypted_servers(provider, local);
    let online: Vec<_> = win::adapters()?.into_iter().filter(|a| a.online).collect();
    if online.is_empty() {
        return Err(Error::new(common::lang::tr(
            "Không tìm thấy card mạng đang có kết nối Internet.",
            "No network adapter with an Internet connection was found.",
        )));
    }
    for ipv6 in [false, true] {
        let family = |s: &&str| s.contains(':') == ipv6;
        let servers: Vec<&str> = local
            .iter()
            .chain(&encrypted)
            .copied()
            .filter(family)
            .collect();
        let doh: Vec<usize> = servers
            .iter()
            .enumerate()
            .filter(|(_, s)| !local.contains(s))
            .map(|(i, _)| i)
            .collect();
        for adapter in &online {
            let set = win::set_dns(&adapter.guid, ipv6, &servers, &doh, provider.template());
            // IPv6 may be switched off on the adapter; IPv4 must work.
            if !ipv6 {
                set.map_err(|e| {
                    Error::new(common::t!("Không đặt được DNS cho {}: {e}", "Could not set DNS on {}: {e}", adapter.name))
                })?;
            }
        }
    }
    win::flush_cache();
    Ok(online.into_iter().map(|a| a.name).collect())
}

/// Undoes [`apply`] on every adapter, connected or not, whose DNS still
/// points at one of Yeager's resolvers: back to DHCP-provided DNS.
pub fn reset() {
    let ours: Vec<IpAddr> = DohProvider::ALL
        .iter()
        .flat_map(|p| p.servers())
        .filter_map(|s| s.parse().ok())
        .collect();
    let Ok(adapters) = win::adapters() else {
        return;
    };
    for adapter in adapters
        .iter()
        .filter(|a| a.dns.iter().any(|ip| ours.contains(ip)))
    {
        for ipv6 in [false, true] {
            let _ = win::set_dns(&adapter.guid, ipv6, &[], &[], "");
        }
    }
    win::flush_cache();
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
    use common::{Error, Result};
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

    /// Sets one address family's static resolvers on an adapter; `servers`
    /// empty reverts to DHCP. Servers at the `doh` indices use `template`
    /// with DoH required (no plaintext fallback); all others have DoH off.
    pub fn set_dns(
        guid: &GUID,
        ipv6: bool,
        servers: &[&str],
        doh: &[usize],
        template: &str,
    ) -> Result<()> {
        let mut name_server = wide(&servers.join(","));
        let mut template = wide(template);
        let mut doh_settings = DNS_DOH_SERVER_SETTINGS {
            Template: template.as_mut_ptr(),
            Flags: DNS_DOH_SERVER_SETTINGS_ENABLE as u64,
        };
        let mut properties: Vec<DNS_SERVER_PROPERTY> = doh
            .iter()
            .map(|&i| DNS_SERVER_PROPERTY {
                Version: DNS_SERVER_PROPERTY_VERSION1,
                ServerIndex: i as u32,
                Type: DnsServerDohProperty,
                Property: DNS_SERVER_PROPERTY_TYPES {
                    DohSettings: &mut doh_settings,
                },
            })
            .collect();

        let mut settings: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
        settings.Flags = (DNS_SETTING_NAMESERVER
            | DNS_SETTING_DOH
            | if ipv6 { DNS_SETTING_IPV6 } else { 0 }) as u64;
        settings.NameServer = name_server.as_mut_ptr();
        settings.cServerProperties = properties.len() as u32;
        settings.ServerProperties = if properties.is_empty() {
            ptr::null_mut()
        } else {
            properties.as_mut_ptr()
        };

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

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
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
    use common::{Error, Result};
    use std::net::IpAddr;

    pub struct Adapter {
        pub guid: (),
        pub name: String,
        pub online: bool,
        pub dns: Vec<IpAddr>,
    }

    fn unsupported<T>() -> Result<T> {
        Err(Error::new(common::lang::tr("Chỉ hỗ trợ Windows.", "Windows only.")))
    }

    pub fn adapters() -> Result<Vec<Adapter>> {
        unsupported()
    }

    pub fn set_dns(_: &(), _: bool, _: &[&str], _: &[usize], _: &str) -> Result<()> {
        unsupported()
    }

    pub fn servers_without_doh(_: &(), _: bool, _: &[&str]) -> Result<Vec<String>> {
        unsupported()
    }

    pub fn flush_cache() {}
}

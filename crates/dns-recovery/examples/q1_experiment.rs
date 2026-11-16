//! Guarded Q1 experiment harness (SPEC-DNS-FIX.md §4 / §13, envelope U01).
//!
//! Development-only: built solely with `--features dev-experiment`. Read-only
//! subcommands (`capture`, `getters`, `verify`) never mutate. Mutating
//! subcommands (`apply`, `restore`) require YEAGER_Q1_EXPERIMENT=1, an explicit
//! `--confirm`, and the designated adapter (GUID + name "Ethernet" + Up).
//! Every setter call is journaled (intent before, result after) and every
//! successful getter is freed exactly once via RAII after a deep copy.
//!
//! Nothing here is production code; the app never links this example.

#[cfg(not(windows))]
fn main() {
    eprintln!("q1_experiment: Windows only.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(e) = imp::run() {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod imp {
    use serde_json::{json, Map, Value};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr;
    use windows_sys::core::{GUID, PWSTR};
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKET_ADDRESS};
    use windows_sys::Win32::System::Registry::*;

    const DESIGNATED_GUID: &str = "6329f16a-0a04-4c7b-a6a5-85f792a98aa0";
    const DESIGNATED_NAME: &str = "Ethernet";
    const ENV_GATE: &str = "YEAGER_Q1_EXPERIMENT";
    const PRE_FORMAT: &str = "yeager-q1-prestate/1";

    const DNS_SETTING_IPV6: u64 = 1;
    const DNS_SETTING_NAMESERVER: u64 = 2;
    const DNS_SETTING_DOH: u64 = 4096;
    const DOH_ENABLE_AUTO: u64 = 1;
    const DOH_ENABLE: u64 = 2;
    const DOH_FALLBACK_TO_UDP: u64 = 4;
    const SETTINGS_VERSION3: u32 = 3;
    const PROPERTY_VERSION1: u32 = 1;
    const DOH_PROPERTY_TYPE: i32 = 1;
    const ERROR_FILE_NOT_FOUND: u32 = 2;

    // ---- entry / dispatch -------------------------------------------------

    pub fn run() -> Result<(), String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let cmd = args.first().map(String::as_str).unwrap_or("");
        match cmd {
            "capture" => {
                let out = opt(&args, "--out").ok_or("capture needs --out <path>")?;
                let cap = capture()?;
                std::fs::write(&out, cap.render()).map_err(|e| format!("write {out}: {e}"))?;
                println!("pre-state written to {out}");
                println!("{}", cap.core_pretty());
                Ok(())
            }
            "getters" => {
                let a = designated()?;
                print_getters(&a)?;
                Ok(())
            }
            "apply" => {
                gate()?;
                require_confirm(&args)?;
                let phase = opt(&args, "--phase").ok_or("apply needs --phase static|clear|partial")?;
                let journal = opt(&args, "--journal")
                    .unwrap_or_else(|| r"C:\projects\yeager-dns-pkg\Q1-journal.jsonl".into());
                let a = designated()?;
                apply(&a, &phase, &journal)
            }
            "restore" => {
                gate()?;
                require_confirm(&args)?;
                let pre = opt(&args, "--pre").ok_or("restore needs --pre <path>")?;
                let v4src = opt(&args, "--v4-source").unwrap_or_else(|| "auto".into());
                let v6src = opt(&args, "--v6-source").unwrap_or_else(|| "auto".into());
                let journal = opt(&args, "--journal")
                    .unwrap_or_else(|| r"C:\projects\yeager-dns-pkg\Q1-journal.jsonl".into());
                let a = designated()?;
                restore(&a, &pre, &v4src, &v6src, &journal)
            }
            "verify" => {
                let pre = opt(&args, "--pre").ok_or("verify needs --pre <path>")?;
                verify(&pre)
            }
            _ => Err("usage: q1_experiment <capture|getters|apply|restore|verify> [flags]".into()),
        }
    }

    fn opt(args: &[String], name: &str) -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    }
    fn has(args: &[String], name: &str) -> bool {
        args.iter().any(|a| a == name)
    }
    fn gate() -> Result<(), String> {
        if std::env::var(ENV_GATE).ok().as_deref() != Some("1") {
            return Err(format!("refusing to mutate: set {ENV_GATE}=1 to enable the experiment"));
        }
        Ok(())
    }
    fn require_confirm(args: &[String]) -> Result<(), String> {
        if !has(args, "--confirm") {
            return Err("refusing to mutate: pass --confirm".into());
        }
        Ok(())
    }

    // ---- adapter enumeration / designation --------------------------------

    #[derive(Clone)]
    struct AdapterInfo {
        guid: GUID,
        guid_str: String,
        name: String,
        description: String,
        oper_up: bool,
        dns: Vec<String>,
        unicast: Vec<String>,
        gateways: Vec<String>,
        luid: u64,
        if_index: u32,
    }

    fn enumerate() -> Result<Vec<AdapterInfo>, String> {
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
            return Err(format!("GetAdaptersAddresses failed: {status}"));
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
            let mut dns = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while let Some(e) = unsafe { d.as_ref() } {
                if let Some(ip) = unsafe { sockaddr_ip(&e.Address) } {
                    dns.push(ip.to_string());
                }
                d = e.Next;
            }
            let mut unicast = Vec::new();
            let mut u = a.FirstUnicastAddress;
            while let Some(e) = unsafe { u.as_ref() } {
                if let Some(ip) = unsafe { sockaddr_ip(&e.Address) } {
                    unicast.push(ip.to_string());
                }
                u = e.Next;
            }
            let mut gateways = Vec::new();
            let mut g = a.FirstGatewayAddress;
            while let Some(e) = unsafe { g.as_ref() } {
                if let Some(ip) = unsafe { sockaddr_ip(&e.Address) } {
                    gateways.push(ip.to_string());
                }
                g = e.Next;
            }
            let mut luid = NET_LUID_LH { Value: 0 };
            let luid_ok = unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) } == NO_ERROR;
            let mut if_index = 0u32;
            if luid_ok {
                unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
            }
            list.push(AdapterInfo {
                guid,
                guid_str,
                name: unsafe { wstr(a.FriendlyName) }.unwrap_or_default(),
                description: unsafe { wstr(a.Description) }.unwrap_or_default(),
                oper_up: a.OperStatus == IfOperStatusUp,
                dns,
                unicast,
                gateways,
                luid: unsafe { luid.Value },
                if_index,
            });
        }
        Ok(list)
    }

    fn designated() -> Result<AdapterInfo, String> {
        let all = enumerate()?;
        let a = all
            .iter()
            .find(|a| a.guid_str == DESIGNATED_GUID)
            .ok_or_else(|| format!("designated adapter {{{DESIGNATED_GUID}}} not present"))?;
        if a.name != DESIGNATED_NAME {
            return Err(format!("designated adapter name is {:?}, expected {DESIGNATED_NAME:?}", a.name));
        }
        if !a.oper_up {
            return Err("designated adapter is not Up; refusing".into());
        }
        Ok(a.clone())
    }

    // ---- registry provenance (read-only) ----------------------------------

    fn reg_read(subkey: &str, value: &str) -> Result<Value, String> {
        let sub = wide(subkey);
        let val = wide(value);
        let mut hkey: HKEY = ptr::null_mut();
        let st = unsafe {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &mut hkey)
        };
        if st != NO_ERROR {
            return Ok(json!({"exists": false, "open_error": st, "value_type": null, "raw_hex": null, "text": null}));
        }
        let mut typ = 0u32;
        let mut len = 0u32;
        let st = unsafe { RegQueryValueExW(hkey, val.as_ptr(), ptr::null_mut(), &mut typ, ptr::null_mut(), &mut len) };
        let out = if st == ERROR_FILE_NOT_FOUND {
            json!({"exists": false, "value_type": null, "raw_hex": null, "text": null})
        } else if st != NO_ERROR {
            json!({"exists": false, "query_error": st, "value_type": null, "raw_hex": null, "text": null})
        } else {
            let mut data = vec![0u8; len as usize];
            let st2 = unsafe { RegQueryValueExW(hkey, val.as_ptr(), ptr::null_mut(), &mut typ, data.as_mut_ptr(), &mut len) };
            if st2 != NO_ERROR {
                json!({"exists": false, "query_error": st2, "value_type": null, "raw_hex": null, "text": null})
            } else {
                data.truncate(len as usize);
                let text = match typ {
                    1 | 2 => {
                        let u16s: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                        let end = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
                        Some(String::from_utf16_lossy(&u16s[..end]))
                    }
                    4 if data.len() >= 4 => Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string()),
                    _ => None,
                };
                json!({"exists": true, "value_type": typ, "raw_hex": hex(&data), "text": text})
            }
        };
        unsafe { RegCloseKey(hkey) };
        Ok(out)
    }

    fn interface_key(family_key: &str, guid_str: &str) -> String {
        format!("SYSTEM\\CurrentControlSet\\Services\\{family_key}\\Parameters\\Interfaces\\{{{}}}", guid_str.to_uppercase())
    }

    fn reg_family(family_key: &str, guid_str: &str) -> Result<Value, String> {
        let key = interface_key(family_key, guid_str);
        Ok(json!({
            "key": key,
            "name_server": reg_read(&key, "NameServer")?,
            "enable_dhcp": reg_read(&key, "EnableDHCP")?,
            "dhcp_name_server": reg_read(&key, "DhcpNameServer")?,
        }))
    }

    // ---- getter with RAII free + deep copy --------------------------------

    struct SettingsGuard(DNS_INTERFACE_SETTINGS3);
    impl Drop for SettingsGuard {
        fn drop(&mut self) {
            unsafe { FreeInterfaceDnsSettings((&mut self.0 as *mut DNS_INTERFACE_SETTINGS3).cast()) };
        }
    }

    fn getter(guid: GUID, flags: u64) -> Result<Value, String> {
        let mut s: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        s.Version = SETTINGS_VERSION3;
        s.Flags = flags;
        let st = unsafe { GetInterfaceDnsSettings(guid, (&mut s as *mut DNS_INTERFACE_SETTINGS3).cast()) };
        if st != NO_ERROR {
            // Nothing allocated on failure; do not free.
            return Err(format!("GetInterfaceDnsSettings flags={flags} failed: {st}"));
        }
        let guard = SettingsGuard(s);
        let v = dump_settings(&guard.0);
        Ok(v) // guard drops here -> freed exactly once, after the deep copy
    }

    fn getter_or_error(guid: GUID, flags: u64) -> Value {
        match getter(guid, flags) {
            Ok(v) => v,
            Err(e) => json!({"error": e}),
        }
    }

    fn dump_settings(s: &DNS_INTERFACE_SETTINGS3) -> Value {
        json!({
            "version": s.Version,
            "flags_returned": s.Flags.to_string(),
            "name_server": unsafe { wstr(s.NameServer) },
            "domain": unsafe { wstr(s.Domain) },
            "search_list": unsafe { wstr(s.SearchList) },
            "registration_enabled": s.RegistrationEnabled,
            "register_adapter_name": s.RegisterAdapterName,
            "enable_llmnr": s.EnableLLMNR,
            "query_adapter_name": s.QueryAdapterName,
            "profile_name_server": unsafe { wstr(s.ProfileNameServer) },
            "disable_unconstrained_queries": s.DisableUnconstrainedQueries,
            "supplemental_search_list": unsafe { wstr(s.SupplementalSearchList) },
            "server_properties": dump_props(s.ServerProperties, s.cServerProperties),
            "profile_server_properties": dump_props(s.ProfileServerProperties, s.cProfileServerProperties),
        })
    }

    fn dump_props(p: *mut DNS_SERVER_PROPERTY, count: u32) -> Value {
        let mut arr = Vec::new();
        for i in 0..count as usize {
            let prop = unsafe { &*p.add(i) };
            let doh = if prop.Type == DOH_PROPERTY_TYPE {
                let d = unsafe { prop.Property.DohSettings.as_ref() };
                match d {
                    Some(d) => json!({"template": unsafe { wstr(d.Template) }, "flags": d.Flags.to_string()}),
                    None => Value::Null,
                }
            } else {
                Value::Null
            };
            arr.push(json!({
                "version": prop.Version,
                "server_index": prop.ServerIndex,
                "type": prop.Type,
                "doh": doh,
            }));
        }
        Value::Array(arr)
    }

    fn ip_interface_entry(luid: u64, family: u16) -> Value {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        row.Family = family;
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        let st = unsafe { GetIpInterfaceEntry(&mut row) };
        json!({"status": st, "family_supported": st == NO_ERROR, "interface_index": row.InterfaceIndex})
    }

    // ---- capture / pre-state file -----------------------------------------

    struct Capture {
        core: Value,
        volatile: Value,
        raw: String,
        captured_at: String,
        host: String,
        os_build: String,
        adapter_label: String,
    }

    impl Capture {
        fn core_pretty(&self) -> String {
            serde_json::to_string_pretty(&self.core).unwrap()
        }
        fn render(&self) -> String {
            format!(
                "# YEAGER Q1 PRE-STATE v1\n# captured_at_utc: {}\n# host: {}  os_build: {}\n# adapter: {}\n[core]\n{}\n[volatile]\n{}\n[raw]\n{}",
                self.captured_at,
                self.host,
                self.os_build,
                self.adapter_label,
                serde_json::to_string(&self.core).unwrap(),
                serde_json::to_string(&self.volatile).unwrap(),
                self.raw,
            )
        }
    }

    fn capture() -> Result<Capture, String> {
        let a = designated()?;
        let g0 = getter_or_error(a.guid, 0);
        let g6 = getter_or_error(a.guid, DNS_SETTING_IPV6);
        let mut families = Map::new();
        let mut raw = String::new();
        for (fam, key, af) in [("ipv4", "Tcpip", AF_INET), ("ipv6", "Tcpip6", AF_INET6)] {
            let reg = reg_family(key, &a.guid_str)?;
            let iie = ip_interface_entry(a.luid, af);
            families.insert(fam.into(), json!({"registry": reg, "ip_interface_entry": iie}));
            raw.push_str(&format!("=== registry {fam} ===\n{}\n", serde_json::to_string_pretty(&reg).unwrap()));
            raw.push_str(&format!("=== ip_interface_entry {fam} ===\n{}\n", serde_json::to_string_pretty(&iie).unwrap()));
        }
        raw.push_str(&format!("=== getter Flags=0 ===\n{}\n", serde_json::to_string_pretty(&g0).unwrap()));
        raw.push_str(&format!("=== getter Flags=DNS_SETTING_IPV6 ===\n{}\n", serde_json::to_string_pretty(&g6).unwrap()));
        raw.push_str(&format!("=== effective DNS (ordered) ===\n{:?}\n", a.dns));
        raw.push_str(&format!("=== unicast ===\n{:?}\n=== gateways ===\n{:?}\n", a.unicast, a.gateways));

        let core = json!({
            "format": PRE_FORMAT,
            "adapter_guid": a.guid_str,
            "getter_flags0": g0,
            "getter_flags_ipv6": g6,
            "families": Value::Object(families),
        });
        let os_build = os_build();
        let host = hostname();
        let volatile = json!({
            "host": host,
            "os_build": os_build,
            "adapter_name": a.name,
            "description": a.description,
            "oper_up": a.oper_up,
            "luid": a.luid.to_string(),
            "if_index": a.if_index,
            "effective_dns": a.dns,
            "unicast": a.unicast,
            "gateways": a.gateways,
        });
        Ok(Capture {
            core,
            volatile,
            raw,
            captured_at: utc_now(),
            host,
            os_build,
            adapter_label: format!("{} {{{}}}", a.name, a.guid_str.to_uppercase()),
        })
    }

    fn section(file: &str, name: &str) -> Result<String, String> {
        let marker = format!("\n[{name}]\n");
        let start = file.find(&marker).ok_or_else(|| format!("pre-state missing [{name}] section"))? + marker.len();
        let rest = &file[start..];
        let end = rest.find("\n[").map(|i| start + i).unwrap_or(file.len());
        Ok(file[start..end].to_string())
    }

    fn read_core(pre_path: &str) -> Result<Value, String> {
        let file = std::fs::read_to_string(pre_path).map_err(|e| format!("read {pre_path}: {e}"))?;
        let core = section(&file, "core")?;
        serde_json::from_str(&core).map_err(|e| format!("parse core: {e}"))
    }

    fn verify(pre_path: &str) -> Result<(), String> {
        let file = std::fs::read_to_string(pre_path).map_err(|e| format!("read {pre_path}: {e}"))?;
        let pre_core = section(&file, "core")?;
        let pre_vol = section(&file, "volatile")?;
        let cap = capture()?;
        let now_core = serde_json::to_string(&cap.core).unwrap();
        let now_vol = serde_json::to_string(&cap.volatile).unwrap();
        if now_core != pre_core {
            println!("VERIFY FAIL: core DNS configuration differs from pre-state.");
            println!("--- pre core ---\n{pre_core}\n--- now core ---\n{now_core}");
            std::process::exit(1);
        }
        println!("VERIFY PASS: core DNS configuration is byte-for-byte identical to pre-state.");
        if now_vol != pre_vol {
            println!("VERIFY WARN: volatile context differs (lease/address churn?).");
            println!("--- pre volatile ---\n{pre_vol}\n--- now volatile ---\n{now_vol}");
            std::process::exit(2);
        }
        println!("VERIFY PASS: volatile context also identical.");
        Ok(())
    }

    fn print_getters(a: &AdapterInfo) -> Result<(), String> {
        println!("adapter: {} {{{}}}  luid={} if_index={}", a.name, a.guid_str, a.luid, a.if_index);
        for (label, flags) in [("Flags=0", 0u64), ("Flags=DNS_SETTING_IPV6", DNS_SETTING_IPV6)] {
            println!("=== getter {label} ===");
            match getter(a.guid, flags) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => println!("ERROR: {e}"),
            }
        }
        for (fam, key) in [("ipv4", "Tcpip"), ("ipv6", "Tcpip6")] {
            println!("=== registry {fam} ===");
            println!("{}", serde_json::to_string_pretty(&reg_family(key, &a.guid_str)?).unwrap());
        }
        println!("=== effective DNS ===\n{:?}", a.dns);
        Ok(())
    }

    // ---- setter (experiment only; journaled) ------------------------------

    struct PropSpec {
        index: u32,
        template: Option<String>,
        flags: u64,
    }

    fn prop_json(p: &PropSpec) -> Value {
        json!({"version": PROPERTY_VERSION1, "server_index": p.index, "type": DOH_PROPERTY_TYPE,
               "doh": {"template": p.template, "flags": p.flags.to_string()}})
    }

    fn set_family(
        a: &AdapterInfo,
        ipv6: bool,
        name_server: &str,
        props: &[PropSpec],
        mask: u64,
        journal: &str,
        phase: &str,
    ) -> Result<u32, String> {
        let fam = if ipv6 { "ipv6" } else { "ipv4" };
        let before = json!({"getter_flags0": getter_or_error(a.guid, 0), "getter_flags_ipv6": getter_or_error(a.guid, DNS_SETTING_IPV6)});
        let target = json!({"name_server": name_server, "properties": props.iter().map(prop_json).collect::<Vec<_>>(), "flags_mask": mask.to_string()});
        journal_line(journal, &json!({"ts": utc_now(), "kind": "intent", "phase": phase, "family": fam, "guid": a.guid_str, "target": target, "before": before}))?;

        let mut ns = wide(name_server);
        let mut templates: Vec<Option<Vec<u16>>> = props.iter().map(|p| p.template.as_deref().map(wide)).collect();
        let mut doh: Vec<DNS_DOH_SERVER_SETTINGS> = props
            .iter()
            .enumerate()
            .map(|(i, p)| DNS_DOH_SERVER_SETTINGS {
                Template: match templates[i].as_mut() {
                    Some(t) => t.as_mut_ptr(),
                    None => ptr::null_mut(),
                },
                Flags: p.flags,
            })
            .collect();
        let mut properties: Vec<DNS_SERVER_PROPERTY> = props
            .iter()
            .enumerate()
            .map(|(i, p)| DNS_SERVER_PROPERTY {
                Version: PROPERTY_VERSION1,
                ServerIndex: p.index,
                Type: DOH_PROPERTY_TYPE,
                Property: DNS_SERVER_PROPERTY_TYPES { DohSettings: &mut doh[i] },
            })
            .collect();
        let mut settings: DNS_INTERFACE_SETTINGS3 = unsafe { std::mem::zeroed() };
        settings.Version = SETTINGS_VERSION3;
        settings.Flags = mask;
        settings.NameServer = ns.as_mut_ptr();
        settings.cServerProperties = properties.len() as u32;
        settings.ServerProperties = if properties.is_empty() { ptr::null_mut() } else { properties.as_mut_ptr() };

        let st = unsafe { SetInterfaceDnsSettings(a.guid, (&settings as *const DNS_INTERFACE_SETTINGS3).cast()) };

        let after = json!({"getter_flags0": getter_or_error(a.guid, 0), "getter_flags_ipv6": getter_or_error(a.guid, DNS_SETTING_IPV6)});
        let reg_after = json!({"ipv4": reg_family("Tcpip", &a.guid_str)?, "ipv6": reg_family("Tcpip6", &a.guid_str)?});
        journal_line(journal, &json!({"ts": utc_now(), "kind": "result", "phase": phase, "family": fam, "guid": a.guid_str, "api_status": st, "after": after, "registry_after": reg_after}))?;

        println!("[{phase} {fam}] SetInterfaceDnsSettings status={st}");
        println!("  target NameServer={name_server:?} props={} mask={mask}", props.len());
        println!("  after getter Flags=0: {}", serde_json::to_string(&after["getter_flags0"]).unwrap());
        println!("  after getter Flags=IPV6: {}", serde_json::to_string(&after["getter_flags_ipv6"]).unwrap());
        if st != NO_ERROR {
            return Err(format!("SetInterfaceDnsSettings {fam} failed: {st}"));
        }
        Ok(st)
    }

    fn journal_line(path: &str, v: &Value) -> Result<(), String> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("journal {path}: {e}"))?;
        writeln!(f, "{}", serde_json::to_string(v).unwrap()).map_err(|e| format!("journal write: {e}"))?;
        f.flush().ok();
        Ok(())
    }

    fn apply(a: &AdapterInfo, phase: &str, journal: &str) -> Result<(), String> {
        let full = DNS_SETTING_NAMESERVER | DNS_SETTING_DOH;
        match phase {
            "static" => {
                set_family(a, false, "9.9.9.9,149.112.112.112",
                    &[PropSpec { index: 1, template: Some("https://dns.quad9.net/dns-query".into()), flags: DOH_ENABLE }],
                    full, journal, "static")?;
                set_family(a, true, "2620:fe::fe,2620:fe::9",
                    &[PropSpec { index: 0, template: Some("https://dns9.quad9.net/dns-query".into()), flags: DOH_ENABLE | DOH_FALLBACK_TO_UDP },
                      PropSpec { index: 1, template: None, flags: DOH_ENABLE_AUTO }],
                    full | DNS_SETTING_IPV6, journal, "static")?;
            }
            "clear" => {
                set_family(a, false, "", &[], full, journal, "clear")?;
                set_family(a, true, "", &[], full | DNS_SETTING_IPV6, journal, "clear")?;
            }
            "partial" => {
                set_family(a, false, "9.9.9.9",
                    &[PropSpec { index: 0, template: Some("https://cloudflare-dns.com/dns-query".into()), flags: DOH_ENABLE }],
                    full, journal, "partial-setup")?;
                set_family(a, false, "149.112.112.112", &[], DNS_SETTING_NAMESERVER, journal, "partial")?;
            }
            _ => return Err(format!("unknown phase {phase:?}")),
        }
        Ok(())
    }

    fn restore(a: &AdapterInfo, pre_path: &str, v4src: &str, v6src: &str, journal: &str) -> Result<(), String> {
        let core = read_core(pre_path)?;
        if core["format"].as_str() != Some(PRE_FORMAT) {
            return Err("pre-state format mismatch".into());
        }
        if core["adapter_guid"].as_str() != Some(a.guid_str.as_str()) {
            return Err("pre-state adapter GUID does not match designated adapter".into());
        }
        for (ipv6, src) in [(false, v4src), (true, v6src)] {
            let fam = if ipv6 { "ipv6" } else { "ipv4" };
            let dump = pick_dump(&core, fam, src)?;
            let ns = dump["name_server"].as_str().ok_or_else(|| format!("pre-state {fam}: getter name_server missing/null"))?.to_string();
            let reg_text = core["families"][fam]["registry"]["name_server"]["text"].as_str();
            if let Some(rt) = reg_text {
                if rt != ns {
                    return Err(format!("pre-state {fam}: getter NameServer {ns:?} != registry {rt:?}; refusing to guess"));
                }
            }
            let props = parse_props(&dump["server_properties"])?;
            let mask = DNS_SETTING_NAMESERVER | DNS_SETTING_DOH | if ipv6 { DNS_SETTING_IPV6 } else { 0 };
            set_family(a, ipv6, &ns, &props, mask, journal, &format!("restore-{fam}"))?;
        }
        println!("restore complete; run: q1_experiment verify --pre {pre_path}");
        Ok(())
    }

    fn pick_dump(core: &Value, fam: &str, src: &str) -> Result<Value, String> {
        let g0 = core["getter_flags0"].clone();
        let g6 = core["getter_flags_ipv6"].clone();
        let matches = |v: &Value| -> bool {
            match v["name_server"].as_str() {
                Some(s) if !s.is_empty() => s.split([',', ' ']).filter(|x| !x.is_empty()).all(|x| x.contains(':') == (fam == "ipv6")),
                _ => false,
            }
        };
        let chosen = match src {
            "flags0" => g0,
            "ipv6" => g6,
            "auto" => {
                if matches(&g0) { g0 } else if matches(&g6) { g6 }
                else if fam == "ipv4" { g0 } else { g6 }
            }
            _ => return Err(format!("unknown source {src:?}")),
        };
        if chosen.get("error").is_some() {
            return Err(format!("pre-state {fam}: chosen getter dump ({src}) recorded an error"));
        }
        Ok(chosen)
    }

    fn parse_props(v: &Value) -> Result<Vec<PropSpec>, String> {
        let arr = v.as_array().ok_or("server_properties not an array")?;
        let mut out = Vec::new();
        for p in arr {
            if p["type"].as_i64() != Some(DOH_PROPERTY_TYPE as i64) {
                return Err(format!("pre-state has non-DoH property type {:?}; refusing", p["type"]));
            }
            let doh = &p["doh"];
            let template = doh["template"].as_str().map(String::from);
            let flags = doh["flags"].as_str().ok_or("property flags missing")?.parse::<u64>().map_err(|e| format!("flags parse: {e}"))?;
            let index = p["server_index"].as_u64().ok_or("server_index missing")? as u32;
            out.push(PropSpec { index, template, flags });
        }
        Ok(out)
    }

    // ---- small helpers ----------------------------------------------------

    fn parse_guid(s: &str) -> Option<GUID> {
        let hex: String = s.trim_matches(['{', '}']).split('-').collect();
        if hex.len() != 32 {
            return None;
        }
        Some(GUID::from_u128(u128::from_str_radix(&hex, 16).ok()?))
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
            unsafe { b.copy_from_slice(std::slice::from_raw_parts(p.add(8), 16)) };
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        } else {
            None
        }
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

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn os_build() -> String {
        let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        let build = reg_read(key, "CurrentBuild").ok().and_then(|v| v["text"].as_str().map(String::from)).unwrap_or_default();
        let ubr = reg_read(key, "UBR").ok().and_then(|v| v["text"].as_str().map(String::from)).unwrap_or_default();
        if ubr.is_empty() { build } else { format!("{build}.{ubr}") }
    }

    fn hostname() -> String {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    }

    fn utc_now() -> String {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let days = secs / 86400;
        let rem = secs % 86400;
        let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        let (y, mo, d) = civil_from_days(days as i64);
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
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
}

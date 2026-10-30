//! Low-latency mode: Windows settings that add delay on the client side.
//!
//! The round trip to a server is set by distance and the ISP's routing; no
//! client setting shortens it. What can be removed is delay the PC adds:
//!
//! - delayed ACKs (`TcpAckFrequency`) and Nagle (`TCPNoDelay`) on the adapters
//!   in use, which hold small TCP segments back by up to 200 ms;
//! - the multimedia scheduler's network throttling while audio or video plays
//!   (`NetworkThrottlingIndex`, `SystemResponsiveness`; needs a reboot);
//! - power saving on the network adapter: Energy Efficient Ethernet and its
//!   vendor variants, and Wi-Fi power saving in the active power plan.
//!
//! Registry writes go through Win32, Wi-Fi power through `powercfg`, and the
//! adapters are restarted through SetupAPI the way Device Manager does it, so
//! the drivers re-read their settings. No PowerShell.
//!
//! Unlike the congestion controller, these settings stay in place when the app
//! exits: most of them only take effect after an adapter restart or a reboot,
//! so undoing them on every exit would only cost a network drop. They are
//! undone when the switch is turned off or Yeager is uninstalled, from the
//! values saved in `latency-backup.json` before the first change.

use crate::{config, probe, LOCK};
use common::lang::tr;
use common::{process, t, Error, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const TCPIP_IFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const MULTIMEDIA: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
/// Label of the default gateway in [`check`].
const ROUTER: &str = "Router";
const NET_CLASS: &str = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

/// Adapter properties that save power at the cost of latency, where `"0"`
/// means off: the standard keyword and the Realtek and Intel variants.
const POWER_SAVING: [&str; 9] = [
    "*EEE",
    "EEE",
    "AdvancedEEE",
    "EEELinkAdvertisement",
    "EnableGreenEthernet",
    "GreenEthernet",
    "PowerSavingMode",
    "GigaLite",
    "ReduceSpeedOnPowerDown",
];

/// Values Yeager may write or put back.
const NAMES: [&str; 4] = ["TcpAckFrequency", "TCPNoDelay", "NetworkThrottlingIndex", "SystemResponsiveness"];

/// "Wireless Adapter Settings" → "Power Saving Mode" in the power plan;
/// index 0 is Maximum Performance.
const WIFI_SUBGROUP: &str = "19cbb8fa-5279-450e-9fac-8a3d5fedd0c1";
const WIFI_POWER: &str = "12bc94b0-5e9e-4f31-bab0-5c3c5d0b2c43";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Value {
    Dword(u32),
    Sz(String),
}

/// A registry value as it was before Yeager changed it; `None` if absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    key: String,
    name: String,
    before: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Snapshot {
    values: Vec<Saved>,
    /// Wi-Fi power saving index on mains and on battery.
    wifi_power: Option<[u32; 2]>,
    /// Adapters to restart on restore, as their `NET_CLASS` subkey ("0007").
    devices: Vec<String>,
}

/// What [`apply`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The adapters tuned, by their Windows names.
    pub adapters: Vec<String>,
    /// Adapters that could not be restarted: their changes wait for a reboot.
    pub not_restarted: Vec<String>,
}

/// Whether low-latency settings are in place (a snapshot is saved).
pub fn is_active() -> bool {
    backup_path().exists()
}

/// Turns the low-latency settings on for the adapters that are online, saving
/// what they were first, then restarts those adapters (the network drops for
/// a few seconds). Running it again picks up adapters added since.
pub fn apply() -> Result<Applied> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let adapters: Vec<_> = sys::adapters()?.into_iter().filter(|a| a.online).collect();
    if adapters.is_empty() {
        return Err(Error::new(tr(
            "Không thấy card mạng nào đang kết nối Internet.",
            "No network adapter is connected to the Internet.",
        )));
    }

    let mut wanted: Vec<(String, &str, Value)> = vec![
        (MULTIMEDIA.into(), "NetworkThrottlingIndex", Value::Dword(u32::MAX)),
        (MULTIMEDIA.into(), "SystemResponsiveness", Value::Dword(10)),
    ];
    let mut devices = Vec::new();
    for a in &adapters {
        let key = format!(r"{TCPIP_IFACES}\{}", a.guid);
        wanted.push((key.clone(), "TcpAckFrequency", Value::Dword(1)));
        wanted.push((key, "TCPNoDelay", Value::Dword(1)));
        let Some(sub) = sys::class_subkey(&a.guid) else { continue };
        let key = format!(r"{NET_CLASS}\{sub}");
        for name in POWER_SAVING {
            let on = matches!(sys::read(&key, name), Some(Value::Sz(v)) if v != "0");
            if on && sys::accepts_zero(&key, name) {
                wanted.push((key.clone(), name, Value::Sz("0".into())));
            }
        }
        devices.push((sub, a.name.clone()));
    }

    // Save what is there before touching anything.
    let mut snapshot = read_snapshot(&backup_path()).unwrap_or_default();
    for (key, name, value) in &wanted {
        let before = sys::read(key, name);
        let known = snapshot.values.iter().any(|s| s.key.eq_ignore_ascii_case(key) && s.name == *name);
        if before.as_ref() != Some(value) && !known {
            snapshot.values.push(Saved { key: key.clone(), name: name.to_string(), before });
        }
    }
    let wifi = adapters.iter().any(|a| a.wifi);
    let wifi_before = wifi.then(wifi_power).flatten();
    if snapshot.wifi_power.is_none() && wifi_before.is_some_and(|p| p != [0, 0]) {
        snapshot.wifi_power = wifi_before;
    }
    for (sub, _) in &devices {
        if !snapshot.devices.contains(sub) {
            snapshot.devices.push(sub.clone());
        }
    }
    write_snapshot(&backup_path(), &snapshot)?;

    for (key, name, value) in &wanted {
        sys::write(key, name, value)?;
    }
    if wifi_before.is_some_and(|p| p != [0, 0]) {
        let _ = set_wifi_power([0, 0]);
    }

    let not_restarted = devices
        .iter()
        .filter(|(sub, _)| sys::restart_device(sub).is_err())
        .map(|(_, name)| name.clone())
        .collect();
    Ok(Applied { adapters: adapters.into_iter().map(|a| a.name).collect(), not_restarted })
}

/// Puts back what [`apply`] changed and restarts the adapters it tuned. Does
/// nothing if nothing was changed. Returns whether something was restored.
/// A value that cannot be put back keeps the snapshot for another try.
pub fn restore() -> Result<bool> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = backup_path();
    let Some(snapshot) = read_snapshot(&path) else {
        let _ = std::fs::remove_file(&path);
        return Ok(false);
    };
    let mut failed = None;
    for saved in snapshot.values.iter().rev() {
        let res = match &saved.before {
            Some(value) => sys::write(&saved.key, &saved.name, value),
            None => sys::delete(&saved.key, &saved.name),
        };
        if let Err(e) = res {
            failed.get_or_insert(e);
        }
    }
    if let Some(power) = snapshot.wifi_power {
        let _ = set_wifi_power(power);
    }
    for sub in &snapshot.devices {
        let _ = sys::restart_device(sub);
    }
    match failed {
        Some(e) => Err(e),
        None => {
            let _ = std::fs::remove_file(&path);
            Ok(true)
        }
    }
}

/// Wi-Fi power saving [mains, battery] in the active power plan.
fn wifi_power() -> Option<[u32; 2]> {
    let text = process::run("powercfg", &["/query", "SCHEME_CURRENT", WIFI_SUBGROUP, WIFI_POWER]).ok()?;
    parse_power_indices(&text)
}

/// The current AC and DC indices: the last two `0x…` values `powercfg /query`
/// prints. The labels next to them are localised, the numbers are not.
fn parse_power_indices(text: &str) -> Option<[u32; 2]> {
    let values: Vec<u32> = text
        .lines()
        .filter_map(|l| l.rsplit_once(':'))
        .filter_map(|(_, v)| u32::from_str_radix(v.trim().strip_prefix("0x")?, 16).ok())
        .collect();
    match values[..] {
        [.., ac, dc] => Some([ac, dc]),
        _ => None,
    }
}

fn set_wifi_power([ac, dc]: [u32; 2]) -> Result<()> {
    for (verb, value) in [("/setacvalueindex", ac), ("/setdcvalueindex", dc)] {
        process::run("powercfg", &[verb, "SCHEME_CURRENT", WIFI_SUBGROUP, WIFI_POWER, &value.to_string()])?;
    }
    process::run("powercfg", &["/setactive", "SCHEME_CURRENT"]).map(|_| ())
}

/// The default gateway of the first online adapter, for [`check`].
pub fn gateway() -> Option<Ipv4Addr> {
    sys::adapters().ok()?.into_iter().filter(|a| a.online).find_map(|a| a.gateway)
}

fn backup_path() -> PathBuf {
    config::dir().join("latency-backup.json")
}

fn write_snapshot(path: &Path, snapshot: &Snapshot) -> Result<()> {
    let json = serde_json::to_string(snapshot).map_err(|e| Error::new(e.to_string()))?;
    config::write_atomic(path, json.as_bytes())?;
    Ok(())
}

/// The saved snapshot, if it exists and only names keys and values Yeager
/// itself would write.
fn read_snapshot(path: &Path) -> Option<Snapshot> {
    let snapshot: Snapshot = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let subkey = |s: &str| s.len() == 4 && s.bytes().all(|b| b.is_ascii_digit());
    let guid = |s: &str| {
        s.len() == 38 && s.starts_with('{') && s.ends_with('}') && s[1..37].bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    };
    let ok = |s: &Saved| {
        let place = if let Some(g) = s.key.strip_prefix(TCPIP_IFACES).and_then(|r| r.strip_prefix('\\')) {
            guid(g) && NAMES[..2].contains(&s.name.as_str())
        } else if let Some(sub) = s.key.strip_prefix(NET_CLASS).and_then(|r| r.strip_prefix('\\')) {
            subkey(sub) && POWER_SAVING.contains(&s.name.as_str())
        } else {
            s.key == MULTIMEDIA && NAMES[2..].contains(&s.name.as_str())
        };
        let value = match &s.before {
            Some(Value::Sz(v)) => v.len() <= 16 && v.bytes().all(|b| b.is_ascii_alphanumeric()),
            _ => true,
        };
        place && value
    };
    let power = snapshot.wifi_power.is_none_or(|p| p.iter().all(|&i| i <= 3));
    (snapshot.values.iter().all(ok) && snapshot.devices.iter().all(|d| subkey(d)) && power).then_some(snapshot)
}

/// Ping results for one target in [`check`].
#[derive(Debug, Clone, PartialEq)]
pub struct Hop {
    pub label: &'static str,
    pub stats: probe::LinkStats,
}

impl Hop {
    /// Round trips well above the median: the spikes felt as lag in games
    /// and calls.
    pub fn spikes(&self) -> usize {
        let Some(median) = self.stats.median_ms() else { return 0 };
        let limit = median + (median / 2).max(30);
        self.stats.rtts.iter().filter(|&&r| r > limit).count()
    }

    fn unsteady(&self, jitter_ms: f64) -> bool {
        self.stats.loss() >= 0.02 || self.stats.jitter_ms().unwrap_or(0.0) >= jitter_ms || self.spikes() >= 2
    }

    fn summary(&self) -> String {
        match self.stats.median_ms() {
            None => t!("{}: không trả lời", "{}: no answer", self.label),
            Some(ms) => t!(
                "{} {ms} ms (dao động {:.0} ms, mất {:.0}%, {} lần vọt)",
                "{} {ms} ms (jitter {:.0} ms, loss {:.0}%, {} spikes)",
                self.label,
                self.stats.jitter_ms().unwrap_or(0.0),
                self.stats.loss() * 100.0,
                self.spikes()
            ),
        }
    }
}

/// Pings the router and two public resolvers side by side for about ten
/// seconds, so a laggy Wi-Fi or home network can be told apart from the ISP.
/// Returns the readings and a verdict, in words for the user.
pub fn check() -> Result<(Vec<Hop>, String)> {
    let mut targets = vec![];
    if let Some(gw) = gateway() {
        targets.push((ROUTER, gw));
    }
    targets.push(("1.1.1.1", probe::PING_TARGETS[0]));
    targets.push(("8.8.8.8", probe::PING_TARGETS[1]));

    let stop = AtomicBool::new(false);
    let hops = std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|&(label, ip)| {
                let stop = &stop;
                (label, s.spawn(move || probe::ping(ip, 50, Duration::from_millis(200), stop)))
            })
            .collect();
        handles
            .into_iter()
            .map(|(label, h)| {
                let stats = h.join().unwrap_or_else(|_| Err(Error::new(tr("ping lỗi", "ping failed"))))?;
                Ok(Hop { label, stats })
            })
            .collect::<Result<Vec<_>>>()
    })?;
    let verdict = verdict(&hops);
    Ok((hops, verdict))
}

fn verdict(hops: &[Hop]) -> String {
    let readings = hops.iter().map(Hop::summary).collect::<Vec<_>>().join("; ");
    let router = hops.iter().find(|h| h.label == ROUTER && h.stats.median_ms().is_some());
    let internet: Vec<&Hop> = hops.iter().filter(|h| h.label != ROUTER).collect();
    let why = if internet.iter().all(|h| h.stats.median_ms().is_none()) {
        tr("Không đo được ping ra Internet (ICMP bị chặn?)", "No ping answers from the Internet (ICMP blocked?)")
    } else if router.is_some_and(|h| h.unsteady(5.0)) {
        tr(
            "Giật nằm ngay trong nhà (Wi-Fi hoặc router): cắm dây LAN hoặc bật Độ trễ thấp sẽ giúp nhiều nhất",
            "The lag starts at home (Wi-Fi or router): a cable or Low latency mode helps most",
        )
    } else if internet.iter().any(|h| h.unsteady(10.0)) {
        tr(
            "Mạng trong nhà ổn, giật đến từ nhà mạng hoặc tuyến quốc tế: chỉnh máy không cải thiện được nhiều",
            "The home network is fine; the lag comes from the ISP or its routes, which client settings cannot fix",
        )
    } else {
        tr(
            "Đường truyền ổn định; ping nền là do khoảng cách tới máy chủ, không giảm được bằng cách chỉnh máy",
            "The link is steady; the base ping is distance to the server, which client settings cannot lower",
        )
    };
    format!("{why}. {readings}.")
}

#[cfg(windows)]
mod sys {
    use super::{Value, NET_CLASS};
    use common::{Error, Result};
    use std::net::Ipv4Addr;
    use std::ptr;
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC};
    use windows_sys::Win32::System::Registry::*;

    pub struct Adapter {
        /// `{XXXXXXXX-…}`, as in the registry.
        pub guid: String,
        pub name: String,
        pub wifi: bool,
        /// Up, Ethernet or Wi-Fi, and with a default gateway.
        pub online: bool,
        pub gateway: Option<Ipv4Addr>,
    }

    pub fn adapters() -> Result<Vec<Adapter>> {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size = 16 * 1024u32;
        let mut buf: Vec<u64> = Vec::new(); // u64 keeps the structs aligned
        let mut status = ERROR_BUFFER_OVERFLOW;
        for _ in 0..3 {
            buf.resize((size as usize).div_ceil(8), 0);
            let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: `buf` holds `size` bytes, as passed.
            status = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, ptr::null(), head, &mut size) };
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
        // SAFETY: a linked list GetAdaptersAddresses built inside `buf`.
        while let Some(a) = unsafe { next.as_ref() } {
            next = a.Next;
            let wifi = a.IfType == IF_TYPE_IEEE80211;
            if a.IfType != IF_TYPE_ETHERNET_CSMACD && !wifi {
                continue;
            }
            let mut gateway = None;
            let mut has_gateway = false;
            let mut g = a.FirstGatewayAddress;
            // SAFETY: as above; the sockaddr length is checked before reading.
            while let Some(entry) = unsafe { g.as_ref() } {
                let addr = entry.Address;
                if !addr.lpSockaddr.is_null() {
                    has_gateway = true;
                    if unsafe { (*addr.lpSockaddr).sa_family } == AF_INET && addr.iSockaddrLength >= 8 {
                        let b = unsafe { std::slice::from_raw_parts(addr.lpSockaddr.cast::<u8>().add(4), 4) };
                        let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                        if !ip.is_unspecified() {
                            gateway.get_or_insert(ip);
                        }
                    }
                }
                g = entry.Next;
            }
            // SAFETY: NUL-terminated strings owned by `buf`.
            let guid = unsafe { std::ffi::CStr::from_ptr(a.AdapterName.cast()) }.to_string_lossy().into_owned();
            let name = unsafe { wstr(a.FriendlyName) };
            list.push(Adapter { guid, name, wifi, online: a.OperStatus == IfOperStatusUp && has_gateway, gateway });
        }
        Ok(list)
    }

    /// The `NET_CLASS` subkey ("0007") whose `NetCfgInstanceId` is `guid`.
    pub fn class_subkey(guid: &str) -> Option<String> {
        let class = Key::open(NET_CLASS, KEY_READ).ok()?;
        (0..)
            .map_while(|i| class.subkey_name(i))
            .filter(|sub| sub.len() == 4 && sub.bytes().all(|b| b.is_ascii_digit()))
            .find(|sub| {
                matches!(read(&format!(r"{NET_CLASS}\{sub}"), "NetCfgInstanceId"), Some(Value::Sz(id)) if id.eq_ignore_ascii_case(guid))
            })
    }

    /// Whether the driver lists `"0"` among the choices for `name`.
    pub fn accepts_zero(key: &str, name: &str) -> bool {
        Key::open(&format!(r"{key}\Ndi\Params\{name}\enum"), KEY_READ).is_ok_and(|k| k.query("0").is_some())
    }

    pub fn read(key: &str, name: &str) -> Option<Value> {
        Key::open(key, KEY_READ).ok()?.query(name)
    }

    pub fn write(key: &str, name: &str, value: &Value) -> Result<()> {
        let k = Key::open(key, KEY_SET_VALUE)?;
        let name = wide(name);
        let (kind, data): (_, Vec<u8>) = match value {
            Value::Dword(v) => (REG_DWORD, v.to_le_bytes().to_vec()),
            Value::Sz(s) => (REG_SZ, wide(s).iter().flat_map(|c| c.to_le_bytes()).collect()),
        };
        // SAFETY: `data` outlives the call and its length is passed.
        let status = unsafe { RegSetValueExW(k.0, name.as_ptr(), 0, kind, data.as_ptr(), data.len() as u32) };
        check(status)
    }

    pub fn delete(key: &str, name: &str) -> Result<()> {
        let k = Key::open(key, KEY_SET_VALUE)?;
        let name = wide(name);
        // SAFETY: plain call with a NUL-terminated name.
        match unsafe { RegDeleteValueW(k.0, name.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => Ok(()),
            status => check(status),
        }
    }

    /// Restarts the network adapter at `NET_CLASS\<subkey>` so its driver
    /// re-reads its settings, as Device Manager does after a property change.
    pub fn restart_device(subkey: &str) -> Result<()> {
        let fail = || Error::new(common::lang::tr("Không khởi động lại được card mạng.", "Could not restart the network adapter."));
        // SAFETY: the list is destroyed below; structs are sized as SetupAPI expects.
        unsafe {
            let set = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, ptr::null(), ptr::null_mut(), DIGCF_PRESENT);
            if set == -1 {
                return Err(fail());
            }
            let wanted = format!(r"{{4d36e972-e325-11ce-bfc1-08002be10318}}\{subkey}");
            let mut result = Err(fail());
            let mut data: SP_DEVINFO_DATA = std::mem::zeroed();
            data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
            let mut i = 0;
            while SetupDiEnumDeviceInfo(set, i, &mut data) != 0 {
                i += 1;
                let mut buf = [0u16; 128];
                let ok = SetupDiGetDeviceRegistryPropertyW(
                    set,
                    &data,
                    SPDRP_DRIVER,
                    ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    std::mem::size_of_val(&buf) as u32,
                    ptr::null_mut(),
                );
                let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                if ok == 0 || !String::from_utf16_lossy(&buf[..len]).eq_ignore_ascii_case(&wanted) {
                    continue;
                }
                let params = SP_PROPCHANGE_PARAMS {
                    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                        cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                        InstallFunction: DIF_PROPERTYCHANGE,
                    },
                    StateChange: DICS_PROPCHANGE,
                    Scope: DICS_FLAG_GLOBAL,
                    HwProfile: 0,
                };
                let header = &params.ClassInstallHeader as *const SP_CLASSINSTALL_HEADER;
                if SetupDiSetClassInstallParamsW(set, &data, header, std::mem::size_of_val(&params) as u32) != 0
                    && SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set, &data) != 0
                {
                    result = Ok(());
                }
                break;
            }
            SetupDiDestroyDeviceInfoList(set);
            result
        }
    }

    struct Key(HKEY);

    impl Key {
        fn open(path: &str, access: REG_SAM_FLAGS) -> Result<Key> {
            let path = wide(path);
            let mut key = ptr::null_mut();
            // SAFETY: plain call; the key is closed in Drop.
            check(unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, access, &mut key) })?;
            Ok(Key(key))
        }

        fn query(&self, name: &str) -> Option<Value> {
            let name = wide(name);
            let mut kind = 0;
            let mut buf = [0u8; 512];
            let mut len = buf.len() as u32;
            // SAFETY: `buf` holds `len` bytes, as passed.
            let status = unsafe { RegQueryValueExW(self.0, name.as_ptr(), ptr::null(), &mut kind, buf.as_mut_ptr(), &mut len) };
            if status != NO_ERROR {
                return None;
            }
            let data = &buf[..len as usize];
            match kind {
                REG_DWORD if data.len() == 4 => Some(Value::Dword(u32::from_le_bytes(data.try_into().ok()?))),
                REG_SZ => {
                    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
                    Some(Value::Sz(String::from_utf16_lossy(&units[..end])))
                }
                _ => None,
            }
        }

        fn subkey_name(&self, index: u32) -> Option<String> {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            // SAFETY: `buf` holds `len` UTF-16 units, as passed.
            let status = unsafe {
                RegEnumKeyExW(self.0, index, buf.as_mut_ptr(), &mut len, ptr::null(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
            };
            (status == NO_ERROR).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the key came from RegOpenKeyExW.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn check(status: u32) -> Result<()> {
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(Error::new(common::t!(
                "Không ghi được registry (lỗi {status}). Yeager cần quyền Administrator.",
                "Could not write the registry (error {status}). Yeager needs administrator rights."
            )))
        }
    }

    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let len = unsafe { (0..).take_while(|&i| *p.add(i) != 0).count() };
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(p, len)) }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
}

/// Lets the crate build and its tests run off Windows; nothing here is ever
/// reached in the app, which only ships for Windows.
#[cfg(not(windows))]
mod sys {
    use super::Value;
    use common::{Error, Result};
    use std::net::Ipv4Addr;

    pub struct Adapter {
        pub guid: String,
        pub name: String,
        pub wifi: bool,
        pub online: bool,
        pub gateway: Option<Ipv4Addr>,
    }

    fn unsupported<T>() -> Result<T> {
        Err(Error::new(common::lang::tr("Chỉ hỗ trợ Windows.", "Windows only.")))
    }

    pub fn adapters() -> Result<Vec<Adapter>> {
        unsupported()
    }

    pub fn class_subkey(_: &str) -> Option<String> {
        None
    }

    pub fn accepts_zero(_: &str, _: &str) -> bool {
        false
    }

    pub fn read(_: &str, _: &str) -> Option<Value> {
        None
    }

    pub fn write(_: &str, _: &str, _: &Value) -> Result<()> {
        unsupported()
    }

    pub fn delete(_: &str, _: &str) -> Result<()> {
        unsupported()
    }

    pub fn restart_device(_: &str) -> Result<()> {
        unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_power_indices_in_any_language() {
        let en = "\
Power Setting GUID: 12bc94b0-5e9e-4f31-bab0-5c3c5d0b2c43  (Power Saving Mode)
  Possible Setting Index: 000
  Possible Setting Friendly Name: Maximum Performance
  Possible Setting Index: 003
  Possible Setting Friendly Name: Maximum Power Saving
Current AC Power Setting Index: 0x00000000
Current DC Power Setting Index: 0x00000002
";
        assert_eq!(parse_power_indices(en), Some([0, 2]));
        let de = "Aktueller Wechselstrom-Energieeinstellungsindex: 0x00000001\nAktueller Gleichstrom-Energieeinstellungsindex: 0x00000003\n";
        assert_eq!(parse_power_indices(de), Some([1, 3]));
        assert_eq!(parse_power_indices("nothing"), None);
    }

    #[test]
    fn snapshot_round_trips_and_rejects_foreign_keys() {
        let dir = std::env::temp_dir().join(format!("erwin-latency-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("latency-backup.json");

        let snapshot = Snapshot {
            values: vec![
                Saved {
                    key: format!(r"{TCPIP_IFACES}\{{4D36E972-E325-11CE-BFC1-08002BE10318}}"),
                    name: "TcpAckFrequency".into(),
                    before: None,
                },
                Saved { key: format!(r"{NET_CLASS}\0007"), name: "*EEE".into(), before: Some(Value::Sz("1".into())) },
                Saved { key: MULTIMEDIA.into(), name: "SystemResponsiveness".into(), before: Some(Value::Dword(20)) },
            ],
            wifi_power: Some([0, 2]),
            devices: vec!["0007".into()],
        };
        write_snapshot(&path, &snapshot).unwrap();
        assert_eq!(read_snapshot(&path), Some(snapshot.clone()));

        let mut bad = snapshot.clone();
        bad.values[0].key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters".into();
        write_snapshot(&path, &bad).unwrap();
        assert_eq!(read_snapshot(&path), None);

        let mut bad = snapshot.clone();
        bad.values[1].name = "NetCfgInstanceId".into();
        write_snapshot(&path, &bad).unwrap();
        assert_eq!(read_snapshot(&path), None);

        let mut bad = snapshot;
        bad.devices = vec![r"..\0007".into()];
        write_snapshot(&path, &bad).unwrap();
        assert_eq!(read_snapshot(&path), None);

        let _ = std::fs::remove_dir_all(dir);
    }

    fn hop(label: &'static str, rtts: Vec<u32>) -> Hop {
        Hop { label, stats: probe::LinkStats { sent: rtts.len() as u32, rtts } }
    }

    #[test]
    fn counts_spikes() {
        assert_eq!(hop("x", vec![60, 61, 62, 60, 150, 61, 200]).spikes(), 2);
        assert_eq!(hop("x", vec![60, 85, 62]).spikes(), 0);
        assert_eq!(hop("x", vec![]).spikes(), 0);
    }

    #[test]
    fn blames_the_right_place() {
        common::lang::set(common::Language::En);
        let steady = |label| hop(label, vec![60; 50]);
        let wifi = hop("Router", vec![2, 40, 3, 2, 80, 2, 2, 3]);
        let v = verdict(&[wifi, steady("1.1.1.1"), steady("8.8.8.8")]);
        assert!(v.starts_with("The lag starts at home"), "{v}");

        let isp = hop("1.1.1.1", vec![60, 140, 60, 61, 160, 60]);
        let v = verdict(&[hop("Router", vec![1; 50]), isp, steady("8.8.8.8")]);
        assert!(v.starts_with("The home network is fine"), "{v}");

        let v = verdict(&[hop("Router", vec![1; 50]), steady("1.1.1.1"), steady("8.8.8.8")]);
        assert!(v.starts_with("The link is steady"), "{v}");
    }
}

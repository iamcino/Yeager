//! Levi Native Connection Resilience Engine.
//! Provides surgical-precision TLS transport stabilization directly in user-space via WinDivert.

pub mod adaptive;
pub mod adaptive_emit;
pub mod engine;
pub mod packet;
pub mod raw;
pub mod tls;

use common::{Config, Scope};
use engine::ResilienceEngine;
use packet::{PacketMetadata, ParsedPacket};
use raw::{SafeHandle, WinDivertAddress, WinDivertApi, WINDIVERT_LAYER_NETWORK};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const WINDIVERT_DLL: &[u8] = include_bytes!("../../../assets/engine/WinDivert.dll");
const WINDIVERT_SYS: &[u8] = include_bytes!("../../../assets/engine/WinDivert64.sys");

static RUNNING: AtomicBool = AtomicBool::new(false);
static ACTIVE_PROFILE: AtomicU8 = AtomicU8::new(0); // 0 = Auto, 1 = Fast, 2 = Hardened, 3 = Observe
static RECV_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);
static WORKER_POOL: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
static TASK_SENDER: Mutex<Option<SyncSender<ResilienceTask>>> = Mutex::new(None);
static CURRENT_HANDLE: Mutex<Option<(Arc<WinDivertApi>, SafeHandle)>> = Mutex::new(None);

#[derive(Clone, Default)]
struct RuntimePolicy {
    is_hostlist: bool,
    compat_mode: bool,
    target_hosts: HashSet<String>,
    custom_excluded: Vec<String>,
}

static POLICY_GENERATION: AtomicUsize = AtomicUsize::new(0);
static RUNTIME_POLICY: RwLock<Option<Arc<RuntimePolicy>>> = RwLock::new(None);

/// Hot-reloads the domain lists and Compatibility Mode flag at runtime without restarting
/// the WinDivert driver or interrupting active connections.
/// Uses an atomic generation counter + `RwLock<Option<Arc<RuntimePolicy>>>` so the capture thread
/// only takes a brief read lock and performs an O(1) `Arc::clone` when the generation changes.
pub fn update_lists(selected_hosts: &[String], custom_excluded: &[String], compat_mode: bool) {
    let mut guard = RUNTIME_POLICY.write().unwrap();
    let is_hostlist = guard.as_ref().map(|p| p.is_hostlist).unwrap_or(false);
    *guard = Some(Arc::new(RuntimePolicy {
        is_hostlist,
        compat_mode,
        target_hosts: selected_hosts.iter().map(|h| h.trim().to_lowercase()).collect(),
        custom_excluded: custom_excluded
            .iter()
            .map(|h| h.trim().to_lowercase())
            .filter(|h| !h.is_empty())
            .collect(),
    }));
    POLICY_GENERATION.fetch_add(1, Ordering::Release);
}

pub static STATS_HANDSHAKES: AtomicUsize = AtomicUsize::new(0);
pub static STATS_STABILIZED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_DROPPED_RSTS: AtomicUsize = AtomicUsize::new(0);

// v1.1.1 Untouched / Pass-Through Telemetry
pub static STATS_DOH_UNTOUCHED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_COMPAT_UNTOUCHED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_CUSTOM_UNTOUCHED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_NO_SNI_UNTOUCHED: AtomicUsize = AtomicUsize::new(0);

// Backwards compatibility aliases for existing UI/API
pub static STATS_BYPASSED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_GAME_PROTECTED: AtomicUsize = AtomicUsize::new(0);

/// Computes the total number of untouched connections across all categories.
pub fn total_untouched() -> usize {
    STATS_DOH_UNTOUCHED.load(Ordering::Relaxed)
        + STATS_COMPAT_UNTOUCHED.load(Ordering::Relaxed)
        + STATS_CUSTOM_UNTOUCHED.load(Ordering::Relaxed)
        + STATS_NO_SNI_UNTOUCHED.load(Ordering::Relaxed)
}

/// Encrypted DNS Resolvers (DoH) that must ALWAYS pass through raw without mutation,
/// ensuring reliable DNS queries regardless of whether Compatibility Mode is enabled.
pub const BUILTIN_DOH_DOMAINS: &[&str] = &[
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "one.one.one.one",
    "dns.adguard-dns.com",
    "dns.adguard.com",
];

/// Remote Desktop and remote support domains in the compatibility list.
pub const REMOTE_TOOL_DOMAINS: &[&str] = &[
    "ultraviewer.net",
    "uvnc.com",
    "ultraviewer.com",
    "teamviewer.com",
    "teamviewer.de",
    "tvv.su",
    "anydesk.com",
    "anydesk.net",
    "adsk.me",
    "rustdesk.com",
    "rdp.rs",
    "parsec.app",
    "parsecgaming.com",
    "splashtop.com",
];

/// Game platforms and launcher domains in the compatibility list.
pub const GAME_PLATFORM_DOMAINS: &[&str] = &[
    "ubi.com",
    "ubisoft.com",
    "ubisoftconnect.com",
    "uplay.com",
    "ubi.li",
    "riotgames.com",
    "pvp.net",
    "leagueoflegends.com",
    "valgame.net",
    "playvalorant.com",
    "rgpub.io",
    "riotcdn.net",
    "riotcdn.com",
    "rdatasrv.net",
    "riotstatus.net",
    "riotcontent.com",
    "riotgames.net",
    "lolesports.com",
    "riot.com",
    "leagueoflegends.net",
    "vnggames.com",
    "vnggames.net",
    "vnggames.vn",
    "vng.com.vn",
    "vng.vn",
    "zing.vn",
    "vgplay.vn",
    "vngcloud.vn",
    "vngcloud.com",
    "zalopay.vn",
    "garena.com",
    "garena.vn",
    "garenanow.com",
    "battle.net",
    "blizzard.com",
    "ea.com",
    "origin.com",
    "epicgames.com",
    "unrealengine.com",
    "steampowered.com",
    "steamcommunity.com",
    "steamcontent.com",
    "steamstatic.com",
    "xboxlive.com",
    "playfabapi.com",
];

/// Steam ecosystem domains: targeting any of these in Scope::HostList automatically
/// protects the complete Steam ecosystem against ISP DPI RST injection (Store, Community, API, and Server networks).
/// Note: Cloud save storage buckets (GCS, S3, Azure) and content CDNs are intentionally handled
/// by [`is_cloud_storage_endpoint`] to pass through raw without packet mutation.
pub const STEAM_ECOSYSTEM_DOMAINS: &[&str] = &[
    "steampowered.com",
    "steamcommunity.com",
    "steamstatic.com",
    "steamusercontent.com",
    "steamgames.com",
    "steamserver.net",
];

/// Single-label Subject CN identifiers passed by remote tools in `SslStream.AuthenticateAsClient`
/// (e.g. UltraViewer's `RemoteControl20.dll` passes `"ultraviewer"` as the TLS SNI).
pub const BUILTIN_COMPAT_SINGLE_LABELS: &[&str] = &[
    "ultraviewer",
    "teamviewer",
    "anydesk",
    "rustdesk",
    "parsec",
    "splashtop",
];

/// Unified compatibility list: Remote Desktop tools, game platforms, and launcher services
/// that pass through raw without mutation when Compatibility Mode is enabled.
/// Note: Actively filtered game ecosystems (such as Steam store, community, and cloud save endpoints)
/// are intentionally excluded so they are always stabilized and protected against ISP middlebox RSTs.
pub const UNIFIED_COMPAT_DOMAINS: &[&str] = &[
    // Remote tools
    "ultraviewer.net",
    "uvnc.com",
    "ultraviewer.com",
    "teamviewer.com",
    "teamviewer.de",
    "tvv.su",
    "anydesk.com",
    "anydesk.net",
    "adsk.me",
    "rustdesk.com",
    "rdp.rs",
    "parsec.app",
    "parsecgaming.com",
    "splashtop.com",

    // Game platforms & Launchers
    "ubi.com",
    "ubisoft.com",
    "ubisoftconnect.com",
    "uplay.com",
    "ubi.li",
    "riotgames.com",
    "pvp.net",
    "leagueoflegends.com",
    "valgame.net",
    "playvalorant.com",
    "rgpub.io",
    "riotcdn.net",
    "riotcdn.com",
    "rdatasrv.net",
    "riotstatus.net",
    "riotcontent.com",
    "riotgames.net",
    "lolesports.com",
    "riot.com",
    "leagueoflegends.net",
    "vnggames.com",
    "vnggames.net",
    "vnggames.vn",
    "vng.com.vn",
    "vng.vn",
    "zing.vn",
    "vgplay.vn",
    "vngcloud.vn",
    "vngcloud.com",
    "zalopay.vn",
    "garena.com",
    "garena.vn",
    "garenanow.com",
    "battle.net",
    "blizzard.com",
    "ea.com",
    "origin.com",
    "epicgames.com",
    "unrealengine.com",
    "xboxlive.com",
    "playfabapi.com",
];

/// Reason why an outbound TLS connection was passed through raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassThroughReason {
    /// Built-in Encrypted DNS Resolver (always-on).
    Doh,
    /// Built-in Cloud Storage & Game CDN endpoints (always-on raw pass-through).
    Storage,
    /// Built-in Compatibility Mode (remote tools, game launchers).
    Compat,
    /// User-defined custom excluded domain.
    Custom,
    /// TLS ClientHello where SNI is missing, empty, or not a valid public FQDN
    /// (e.g. direct-IP, single-label certificate CN like `"ultraviewer"`, `localhost`, or IP literal).
    NoSni,
}

/// Checks whether an extracted SNI string is a valid public FQDN (contains at least one dot,
/// has valid DNS labels of length 1..=63 with alphanumeric/hyphen characters, has alphabetic
/// characters in the final TLD label, and is not an IPv4/IPv6 literal or single-label CN).
///
/// Note on special characters & IDN:
/// - Hostnames containing `_` (e.g. `_service._tcp.example.com` or internal SMB names) intentionally
///   return `false` and fall back to [`PassThroughReason::NoSni`] (raw pass-through for safety).
/// - IDN Punycode labels (`xn--...`, e.g. `xn--bcher-kva.example.com` or `example.xn--fiqs8s`)
///   consist of ASCII alphanumeric characters and internal hyphens with alphabetic TLDs, so they are accepted.
/// - Zero heap allocation: operates strictly on borrowed byte/str iterators.
#[inline]
pub fn is_valid_fqdn_sni(sni: &str) -> bool {
    if sni.is_empty() || sni.len() > 253 || !sni.contains('.') || sni.contains(':') {
        return false;
    }

    // Explicit IP literal rejection (IPv4 all-digits/dots or parseable IpAddr)
    if sni.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || sni.parse::<std::net::IpAddr>().is_ok()
    {
        return false;
    }

    // Validate each DNS label (1..=63 chars, alphanumeric or '-', not starting/ending with '-')
    // and ensure the final TLD label contains at least one ASCII letter (RFC 1123 / RFC 6066).
    let mut last_label_has_alpha = false;
    for label in sni.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
        last_label_has_alpha = label.bytes().any(|b| b.is_ascii_alphabetic());
    }

    last_label_has_alpha
}

/// Checks whether a domain is a cloud save storage endpoint, multi-cloud bucket,
/// or high-throughput game content CDN that must always pass through raw without
/// transport mutation to prevent ingress proxy resets and TLS record fragmentation aborts.
#[inline]
pub fn is_cloud_storage_endpoint(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();

    // Steam Cloud storage buckets on Google Cloud Storage, AWS S3, and Azure Blob
    if lower.starts_with("steamcloud-") || lower.starts_with("steamcloud") {
        if matches_host(&lower, "storage.googleapis.com")
            || matches_host(&lower, "amazonaws.com")
            || matches_host(&lower, "blob.core.windows.net")
        {
            return true;
        }
    }

    // Generic Google Cloud Storage, AWS S3, and Azure Blob endpoints
    if matches_host(&lower, "storage.googleapis.com")
        || matches_host(&lower, "s3.amazonaws.com")
        || lower.contains(".s3.dualstack.")
        || matches_host(&lower, "blob.core.windows.net")
    {
        return true;
    }

    // SteamPipe game download CDN & cache (high throughput, not filtered by ISP)
    if matches_host(&lower, "steamcontent.com") {
        return true;
    }

    // Riot Games patch & dynamic asset delivery CDN (high throughput, not filtered by ISP)
    if matches_host(&lower, "riotcdn.net") || matches_host(&lower, "riotcdn.com") {
        return true;
    }

    // VNGGames patch & static asset CDN (high throughput, not filtered by ISP)
    if matches_host(&lower, "cdn-apo.vnggames.com") {
        return true;
    }

    false
}

/// Evaluates whether an outbound TLS connection should pass through raw without packet mutation.
/// Centralized evaluation function used identically by the driver hot path and unit tests.
/// Zero heap allocation: operates directly on borrowed `&str` slices via case-insensitive comparisons.
#[inline]
pub fn evaluate_pass_through(
    sni: Option<&str>,
    compat_mode: bool,
    custom_excluded: &[String],
) -> Option<PassThroughReason> {
    let s = match sni {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Some(PassThroughReason::NoSni);
            }
            trimmed
        }
        None => return Some(PassThroughReason::NoSni),
    };

    if BUILTIN_DOH_DOMAINS.iter().any(|target| matches_host(s, target)) {
        return Some(PassThroughReason::Doh);
    }

    if is_cloud_storage_endpoint(s) {
        return Some(PassThroughReason::Storage);
    }

    if compat_mode && is_builtin_compat(s) {
        return Some(PassThroughReason::Compat);
    }

    if custom_excluded.iter().any(|target| matches_host(s, target)) {
        return Some(PassThroughReason::Custom);
    }

    // Fallback for non-FQDN SNI values (e.g. single-label certificate CN like "ultraviewer"
    // or IPv4/IPv6 address literals passed to SslStream.AuthenticateAsClient):
    if !is_valid_fqdn_sni(s) {
        return Some(PassThroughReason::NoSni);
    }

    None
}

/// Checks whether a domain is a built-in encrypted DNS resolver (always pass-through).
#[inline]
pub fn is_builtin_doh(domain: &str) -> bool {
    BUILTIN_DOH_DOMAINS.iter().any(|target| matches_host(domain, target))
}

/// Checks whether a domain belongs to the unified compatibility pass-through list
/// (including single-label certificate CNs like `"ultraviewer"`).
#[inline]
pub fn is_builtin_compat(domain: &str) -> bool {
    UNIFIED_COMPAT_DOMAINS.iter().any(|target| matches_host(domain, target))
        || BUILTIN_COMPAT_SINGLE_LABELS.iter().any(|target| domain.eq_ignore_ascii_case(target))
}

/// Backwards-compatibility alias for v1.1.0 callers.
#[inline]
pub fn is_builtin_game(domain: &str) -> bool {
    is_builtin_compat(domain)
}

/// Backwards-compatibility alias for v1.1.0 callers.
#[inline]
pub fn is_builtin_bypass(domain: &str) -> bool {
    is_builtin_doh(domain) || is_cloud_storage_endpoint(domain) || is_builtin_compat(domain)
}

/// Backwards-compatibility helper for v1.1.0 callers.
#[inline]
pub fn should_pass_through(sni: &str, compat_mode: bool, custom_excluded: &[String]) -> bool {
    evaluate_pass_through(Some(sni), compat_mode, custom_excluded).is_some()
}

/// Transport Layer Resilience & Stabilization Profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResilienceProfile {
    /// Auto-detects network conditions and adapter MTU (In-Order on tunnels, Hardened on physical).
    #[default]
    Auto,
    /// Fast: In-Order 3-Way Multi-Split (0ms added delay, optimal for gaming, streaming & VPN WireGuard tunnels).
    Fast,
    /// Hardened: Out-of-Order Multi-Split with calibrated 3.3-3.5ms jitter for resilient transport against middlebox stream disruptions.
    Hardened,
    /// Observe: Passive Telemetry & Monitoring Mode (Zero packet mutation, safe network auditing).
    Observe,
}

impl std::str::FromStr for ResilienceProfile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(ResilienceProfile::Auto),
            "fast" | "in-order" | "inorder" => Ok(ResilienceProfile::Fast),
            "hardened" | "disorder" | "anti-reassembly" => Ok(ResilienceProfile::Hardened),
            "observe" | "passive" | "monitor" => Ok(ResilienceProfile::Observe),
            _ => Err(format!("Unknown profile: '{}'. Available: auto, fast, hardened, observe", s)),
        }
    }
}

/// Tracks active outbound TLS handshakes to distinguish between:
/// 1. Abnormal Middlebox RST packets (injected prematurely during the handshake window).
/// 2. Legitimate Server RST packets (closing an established or non-handshake socket).
#[derive(Debug, Default)]
pub struct HandshakeTracker {
    // Key: (remote_server_ip_16, client_port), Value: Instant of ClientHello
    active: HashMap<([u8; 16], u16), Instant>,
}

impl HandshakeTracker {
    pub const HANDSHAKE_WINDOW: Duration = Duration::from_millis(3500); // 3.5 seconds
    pub const MAX_ENTRIES: usize = 512;

    pub fn new() -> Self {
        Self {
            active: HashMap::with_capacity(64),
        }
    }

    /// Records an outbound ClientHello sent to `remote_server_ip` from `client_port`.
    pub fn record_client_hello(&mut self, server_ip: [u8; 16], client_port: u16) {
        let now = Instant::now();
        if self.active.len() >= Self::MAX_ENTRIES {
            self.active.retain(|_, time| now.duration_since(*time) < Self::HANDSHAKE_WINDOW);
        }
        self.active.insert((server_ip, client_port), now);
    }

    /// Checks whether an inbound RST from `server_ip` addressed to `client_port` arrived
    /// within the active handshake window.
    pub fn is_in_handshake_window(&mut self, server_ip: [u8; 16], client_port: u16) -> bool {
        let now = Instant::now();
        if let Some(&time) = self.active.get(&(server_ip, client_port)) {
            if now.duration_since(time) <= Self::HANDSHAKE_WINDOW {
                return true;
            } else {
                self.active.remove(&(server_ip, client_port));
            }
        }
        false
    }
}

const DEFAULT_MIN_WORKERS: usize = 4;
const DEFAULT_MAX_WORKERS: usize = 6;
const TASK_QUEUE_CAPACITY: usize = 256;

/// Determines the optimal number of worker threads based on system logical CPU cores.
/// Clamped between 4 and 6 (sweet spot) to prevent WinDivert handle contention while handling burst concurrency.
pub fn get_optimal_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(DEFAULT_MIN_WORKERS, DEFAULT_MAX_WORKERS))
        .unwrap_or(DEFAULT_MIN_WORKERS)
}

struct ResilienceTask {
    pkt_bytes: Vec<u8>,
    meta: PacketMetadata,
    sni_split: Option<usize>,
    addr: WinDivertAddress,
}

pub fn get_driver_dir() -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push("Yeager_bin");
    dir
}

pub fn ensure_driver_extracted() -> Result<PathBuf, String> {
    let bin_dir = get_driver_dir();
    fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;

    let files: [(&str, &[u8]); 2] = [
        ("WinDivert.dll", WINDIVERT_DLL),
        ("WinDivert64.sys", WINDIVERT_SYS),
    ];

    for (name, bytes) in files.iter() {
        let dest = bin_dir.join(name);
        if !dest.exists() || fs::metadata(&dest).map(|m| m.len()).unwrap_or(0) == 0 {
            fs::write(&dest, bytes).map_err(|e| format!("Failed writing {}: {}", name, e))?;
        }
    }

    Ok(bin_dir.join("WinDivert.dll"))
}

/// Starts the native Levi connection resilience engine with default Auto profile.
pub fn start(cfg: &Config) -> Result<(), String> {
    start_with_profile(cfg, ResilienceProfile::Auto)
}

/// Starts the native Levi connection resilience engine with the specified transport profile.
pub fn start_with_profile(cfg: &Config, profile: ResilienceProfile) -> Result<(), String> {
    stop();

    ACTIVE_PROFILE.store(
        match profile {
            ResilienceProfile::Auto => 0,
            ResilienceProfile::Fast => 1,
            ResilienceProfile::Hardened => 2,
            ResilienceProfile::Observe => 3,
        },
        Ordering::SeqCst,
    );

    let dll_path = ensure_driver_extracted()?;
    let api = Arc::new(WinDivertApi::load(&dll_path)?);

    // Surgical WinDivert filter:
    // Outbound: Port 443 TCP packets with payload >= 40 bytes.
    // Inbound: Middlebox-injected TCP RST packets from Port 443 to be neutralized.
    // Crucially '!impostor' prevents re-capturing our own injected fragmented packets!
    let filter = "(!impostor and outbound and tcp.DstPort == 443 and tcp.PayloadLength >= 40) or (inbound and tcp.SrcPort == 443 and tcp.Rst)";
    let filter_cstr = std::ffi::CString::new(filter).map_err(|e| e.to_string())?;

    let raw_handle = unsafe {
        (api.open)(
            filter_cstr.as_ptr(),
            WINDIVERT_LAYER_NETWORK,
            0, // Priority
            0, // Flags
        )
    };

    let handle = SafeHandle::from_raw(raw_handle);
    if handle.is_invalid() {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(format!(
            "Failed to open WinDivert handle (code {}). Please ensure Yeager is running as Administrator.",
            err
        ));
    }

    // Configure WinDivert queue parameters for maximum throughput and buffer capacity
    unsafe {
        (api.set_param)(handle.as_raw(), raw::WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
        (api.set_param)(handle.as_raw(), raw::WINDIVERT_PARAM_QUEUE_TIME, 2000);
        (api.set_param)(handle.as_raw(), raw::WINDIVERT_PARAM_QUEUE_SIZE, 32 * 1024 * 1024);
    }

    {
        let mut h_guard = CURRENT_HANDLE.lock().unwrap();
        *h_guard = Some((Arc::clone(&api), handle));
    }

    let initial_policy = Arc::new(RuntimePolicy {
        is_hostlist: cfg.scope == Scope::HostList,
        compat_mode: cfg.compatibility_mode_enabled,
        target_hosts: cfg
            .selected_hosts
            .iter()
            .map(|h| h.trim().to_lowercase())
            .collect(),
        custom_excluded: cfg
            .custom_excluded_domains
            .iter()
            .map(|h| h.trim().to_lowercase())
            .filter(|h| !h.is_empty())
            .collect(),
    });

    {
        let mut pol_guard = RUNTIME_POLICY.write().unwrap();
        *pol_guard = Some(Arc::clone(&initial_policy));
    }
    let mut local_gen = POLICY_GENERATION.fetch_add(1, Ordering::Release).wrapping_add(1);
    let mut active_policy = initial_policy;

    RUNNING.store(true, Ordering::SeqCst);

    // Initialize bounded worker pool for resilience tasks scaled to CPU thread capacity
    let worker_count = get_optimal_worker_count();
    let (tx, rx) = sync_channel::<ResilienceTask>(TASK_QUEUE_CAPACITY);
    let rx_arc = Arc::new(Mutex::new(rx));
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let rx_worker = Arc::clone(&rx_arc);
        let api_worker = Arc::clone(&api);
        let handle_worker = handle;

        let th = std::thread::spawn(move || {
            while RUNNING.load(Ordering::Relaxed) {
                let task = {
                    let rx_guard = match rx_worker.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    // Bounded wait with 100ms timeout to periodically check RUNNING flag
                    match rx_guard.recv_timeout(Duration::from_millis(100)) {
                        Ok(t) => t,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                };

                let mut addr = task.addr;
                let parsed = task.meta.to_parsed(&task.pkt_bytes);
                let prof = ACTIVE_PROFILE.load(Ordering::Relaxed);
                let use_inorder = match prof {
                    1 => true,  // Fast: In-Order 3-Way Split (0ms delay)
                    _ => false, // Auto & Hardened: Out-of-Order Multi-Split with calibrated jitter
                };

                if use_inorder {
                    let _ = ResilienceEngine::fragment_and_send_multisplit_inorder(
                        &api_worker,
                        handle_worker,
                        &task.pkt_bytes,
                        &parsed,
                        task.sni_split,
                        &mut addr,
                    );
                } else {
                    let _ = ResilienceEngine::fragment_and_send_multisplit(
                        &api_worker,
                        handle_worker,
                        &task.pkt_bytes,
                        &parsed,
                        task.sni_split,
                        &mut addr,
                    );
                }
            }
        });
        workers.push(th);
    }

    {
        let mut pool_guard = WORKER_POOL.lock().unwrap();
        *pool_guard = workers;
        let mut tx_guard = TASK_SENDER.lock().unwrap();
        *tx_guard = Some(tx.clone());
    }

    let api_clone = Arc::clone(&api);
    let tx_clone = tx;

    let recv_thread = std::thread::spawn(move || {
        let mut buffer = vec![0u8; 65535];
        let mut addr = WinDivertAddress::default();
        let mut recv_len: u32 = 0;
        let mut handshake_tracker = HandshakeTracker::new();

        while RUNNING.load(Ordering::Relaxed) {
            let res = unsafe {
                (api_clone.recv)(
                    handle.as_raw(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut recv_len as *mut _,
                    &mut addr as *mut _,
                )
            };

            if res == 0 {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                if err == 6 || err == 995 {
                    // ERROR_INVALID_HANDLE or ERROR_OPERATION_ABORTED when handle is closed
                    break;
                }
                if RUNNING.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                } else {
                    break;
                }
                continue;
            }

            let pkt_bytes = &buffer[..recv_len as usize];

            // Inbound Middlebox RST Neutralization (State-Aware Silencer):
            // Filters abnormal TCP RST packets injected during the initial handshake window (3.5s).
            // Legitimate RSTs from remote servers (closing finished or dead sockets) pass through safely!
            if !addr.is_outbound() {
                if let Some(ref parsed) = ParsedPacket::parse(pkt_bytes) {
                    if (parsed.tcp_flags & packet::TCP_FLAG_RST) != 0 {
                        if handshake_tracker.is_in_handshake_window(parsed.src_ip, parsed.dst_port) {
                            STATS_DROPPED_RSTS.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                }
                let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
                continue;
            }

            if let Some(parsed) = ParsedPacket::parse(pkt_bytes) {
                // RFC 1918 Private, Loopback, Link-Local & Multicast Pass-Through:
                // Keep internal network, captive portal, and router admin traffic unmodified!
                if parsed.is_private_or_local_dst() {
                    let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
                    continue;
                }

                if tls::is_client_hello(parsed.payload) {
                    STATS_HANDSHAKES.fetch_add(1, Ordering::Relaxed);

                    // Zero-contention check for hot-reloaded domain lists & compatibility mode:
                    // Fast path is a single Acquire load; slow path (on UI config save) takes a brief
                    // RwLock read guard and performs an O(1) Arc pointer clone (zero collection cloning).
                    let cur_gen = POLICY_GENERATION.load(Ordering::Acquire);
                    if cur_gen != local_gen {
                        if let Ok(guard) = RUNTIME_POLICY.read() {
                            if let Some(ref pol) = *guard {
                                active_policy = Arc::clone(pol);
                            }
                        }
                        local_gen = cur_gen;
                    }

                    // Observe Mode: Monitor & Telemetry only, zero packet mutation
                    if ACTIVE_PROFILE.load(Ordering::Relaxed) == 3 {
                        let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
                        continue;
                    }

                    let info = tls::parse_client_hello(parsed.payload);
                    let sni_opt = info.as_ref().and_then(|inf| inf.sni);

                    // Scope::HostList explicit target check: user-selected target domains
                    // take precedence over built-in compatibility pass-through (while DoH,
                    // custom exclusions, and invalid/missing SNI still pass through).
                    let hostlist_target = active_policy.is_hostlist
                        && sni_opt.is_some_and(|s| {
                            active_policy.target_hosts.iter().any(|target| matches_target_or_ecosystem(s, target))
                        });

                    if active_policy.is_hostlist && !hostlist_target {
                        let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
                        continue;
                    }

                    // Centralized Pass-Through Evaluation (DoH, Compatibility Mode, Custom, No-SNI Fallback):
                    if let Some(reason) = evaluate_pass_through(
                        sni_opt,
                        active_policy.compat_mode && !hostlist_target,
                        &active_policy.custom_excluded,
                    ) {
                        match reason {
                            PassThroughReason::Doh => {
                                STATS_DOH_UNTOUCHED.fetch_add(1, Ordering::Relaxed);
                            }
                            PassThroughReason::Storage => {
                                STATS_COMPAT_UNTOUCHED.fetch_add(1, Ordering::Relaxed);
                            }
                            PassThroughReason::Compat => {
                                STATS_COMPAT_UNTOUCHED.fetch_add(1, Ordering::Relaxed);
                                STATS_GAME_PROTECTED.fetch_add(1, Ordering::Relaxed);
                            }
                            PassThroughReason::Custom => {
                                STATS_CUSTOM_UNTOUCHED.fetch_add(1, Ordering::Relaxed);
                            }
                            PassThroughReason::NoSni => {
                                STATS_NO_SNI_UNTOUCHED.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        STATS_BYPASSED.fetch_add(1, Ordering::Relaxed);
                        let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
                        continue;
                    }

                    // Register handshake for state-aware RST silencer tracking ONLY when stabilizing
                    handshake_tracker.record_client_hello(parsed.dst_ip, parsed.src_port);
                    STATS_STABILIZED.fetch_add(1, Ordering::Relaxed);

                        // Proven resilient TLS transport stabilization strategy:
                        // 3-way multi-split (TLS Record header + prefix SNI split).
                        let sni_split = info.as_ref().and_then(|inf| {
                            match (inf.sni_offset, inf.sni) {
                                (Some(off), Some(sni)) if !sni.is_empty() => {
                                    // Split at byte 2 of the SNI (e.g. "st" | "eam...") to break
                                    // brand identifiers across TCP segment boundaries and neutralize
                                    // keyword-matching in ISP deep packet inspection middleboxes.
                                    let cut = if sni.len() > 3 { 2 } else { 1 };
                                    Some(off + cut)
                                }
                                (Some(off), _) => Some(off + 1),
                                _ => None,
                            }
                        });

                        let prof = ACTIVE_PROFILE.load(Ordering::Relaxed);
                        if prof == 1 {
                            // Fast (1) profile: strictly in-order 3-way split (0ms delay), optimal for tunnels
                            let _ = ResilienceEngine::fragment_and_send_multisplit_inorder(
                                &api_clone,
                                handle,
                                pkt_bytes,
                                &parsed,
                                sni_split,
                                &mut addr,
                            );
                            continue;
                        }

                        if prof == 0 {
                            // Auto (0) profile fast-path:
                            // If the ClientHello contains >= 5 bytes of TLS padding (e.g. modern browsers),
                            // execute zero-delta record splitting in-order directly on stack buffer (0ms delay).
                            let mut rec_buf = [0u8; 2048];
                            let payload = parsed.payload;
                            if payload.len() <= rec_buf.len() {
                                if let Some(rec2_off) = crate::tls::try_build_zero_delta_record_split(
                                    payload,
                                    &mut rec_buf[..payload.len()],
                                ) {
                                    addr.set_outbound(true);
                                    addr.set_ipv6(parsed.ip_version == 6);
                                    addr.set_impostor(true);

                                    let rec1 = &rec_buf[..rec2_off];
                                    let rec2 = &rec_buf[rec2_off..payload.len()];

                                    let _ = ResilienceEngine::send_tcp_segment(
                                        &api_clone,
                                        handle,
                                        pkt_bytes,
                                        &parsed,
                                        0,
                                        rec1,
                                        &mut addr,
                                    );
                                    let _ = ResilienceEngine::send_tcp_segment(
                                        &api_clone,
                                        handle,
                                        pkt_bytes,
                                        &parsed,
                                        rec2_off as u32,
                                        rec2,
                                        &mut addr,
                                    );
                                    continue;
                                }
                            }
                        }

                        // Hardened profile (2) OR Auto profile when TLS padding is absent (e.g. Steam / OpenSSL):
                        // Dispatches to worker pool for Out-of-Order Multi-Split with 3.3-3.5ms jitter,
                        // preventing middlebox TCP reassembly queues from reconstructing the ClientHello.
                        let task = ResilienceTask {
                            pkt_bytes: pkt_bytes.to_vec(),
                            meta: parsed.metadata(),
                            sni_split,
                            addr,
                        };

                        // Non-blocking dispatch to worker pool; fallback to raw send if queue is saturated
                        if tx_clone.try_send(task).is_err() {
                            let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
                        }
                        continue;
                    }
                }

            // Normal pass-through for non-ClientHello or non-target hosts
            let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
        }
    });

    let mut guard = RECV_THREAD.lock().unwrap();
    *guard = Some(recv_thread);

    Ok(())
}

/// Stops the native Levi connection resilience engine.
pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);

    // Drop task sender to wake up any receivers
    {
        let mut tx_guard = TASK_SENDER.lock().unwrap();
        let _ = tx_guard.take();
    }

    // Immediately close handle to unblock any pending recv() in worker thread
    if let Some((api, handle)) = CURRENT_HANDLE.lock().unwrap().take() {
        unsafe {
            (api.close)(handle.as_raw());
        }
    }

    // Join main capture thread
    let mut guard = RECV_THREAD.lock().unwrap();
    if let Some(handle) = guard.take() {
        let _ = handle.join();
    }

    // Join pool workers
    let mut pool_guard = WORKER_POOL.lock().unwrap();
    for worker in pool_guard.drain(..) {
        let _ = worker.join();
    }
}

/// Returns whether the native Levi engine is currently active.
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Zero-allocation domain matching for hostlist scoping.
/// Matches exact domain (case-insensitive) or any subdomain (e.g. "sub.example.com" matches "example.com").
/// Prevents false positives like "evil-example.com" matching "example.com".
#[inline]
pub fn matches_host(domain: &str, target: &str) -> bool {
    if domain.eq_ignore_ascii_case(target) {
        return true;
    }
    if domain.len() > target.len() {
        let prefix_len = domain.len() - target.len();
        return domain.as_bytes()[prefix_len - 1] == b'.'
            && domain[prefix_len..].eq_ignore_ascii_case(target);
    }
    false
}

/// Matches host with ecosystem expansion for coupled platforms (e.g. Steam).
/// If the target is a core ecosystem domain, associated platform, community,
/// API, and gaming servers in the same ecosystem are automatically covered
/// without requiring the user to manually discover each individual subdomain.
/// Note: Cloud save storage buckets (GCS, S3, Azure) and content CDNs are intentionally
/// excluded from active mutation and pass through raw via [`is_cloud_storage_endpoint`].
#[inline]
pub fn matches_target_or_ecosystem(domain: &str, target: &str) -> bool {
    if matches_host(domain, target) {
        return true;
    }
    if STEAM_ECOSYSTEM_DOMAINS.iter().any(|&s| target.eq_ignore_ascii_case(s)) {
        if STEAM_ECOSYSTEM_DOMAINS.iter().any(|&s| matches_host(domain, s)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_tracker_window() {
        let mut tracker = HandshakeTracker::new();
        let server_ip = [0,0,0,0,0,0,0,0,0,0,0xff,0xff,93,184,216,34];
        let client_port = 54321;

        // Record a ClientHello
        tracker.record_client_hello(server_ip, client_port);

        // Immediate RST arrival -> In window -> MUST be true
        assert!(tracker.is_in_handshake_window(server_ip, client_port));

        // Different client port -> NOT in window -> MUST be false
        assert!(!tracker.is_in_handshake_window(server_ip, 12345));

        // Different server IP -> NOT in window -> MUST be false
        let other_ip = [0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,1,1,1];
        assert!(!tracker.is_in_handshake_window(other_ip, client_port));
    }

    #[test]
    fn test_resilience_profile_observe() {
        let prof = "observe".parse::<ResilienceProfile>().expect("Should parse observe");
        assert_eq!(prof, ResilienceProfile::Observe);

        let prof2 = "passive".parse::<ResilienceProfile>().expect("Should parse passive");
        assert_eq!(prof2, ResilienceProfile::Observe);
    }

    #[test]
    fn test_evaluate_pass_through_comprehensive() {
        let custom: Vec<String> = vec!["internal-company.net".to_string(), "my-custom-proxy.org".to_string()];

        // F1 & F4 & F5 (T1, T3, T8, T9): Remote tools and Game launchers with compat_mode = true
        assert_eq!(evaluate_pass_through(Some("ultraviewer"), true, &custom), Some(PassThroughReason::Compat)); // T1
        assert_eq!(evaluate_pass_through(Some("teamviewer"), true, &custom), Some(PassThroughReason::Compat));  // T3
        assert_eq!(evaluate_pass_through(Some("ultraviewer.net"), true, &custom), Some(PassThroughReason::Compat)); // T8
        assert_eq!(evaluate_pass_through(Some("connect.ultraviewer.net"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("rdp.ultraviewer.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("server.uvnc.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("master.teamviewer.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("relay.anydesk.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("relay.rustdesk.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("kessel.parsec.app"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("relay.splashtop.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("public-ubiservices.ubi.com"), true, &custom), Some(PassThroughReason::Compat)); // T9
        assert_eq!(evaluate_pass_through(Some("auth.riotgames.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("edge.rgpub.io"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("cmsassets.rgpub.io"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("dradis-prod.rdatasrv.net"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("status.riotstatus.net"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("playvalorant.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("sso.vnggames.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("login.vnggames.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("id.vnggames.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("lienminh.vnggames.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("sdk.vnggames.net"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("id.zing.vn"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("gas.garena.com"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("client.battle.net"), true, &custom), Some(PassThroughReason::Compat));

        // Steam platform domains (Store, Community, API, etc.) MUST NOT be bypassed by Compatibility Mode!
        // They are actively blocked by ISP DPI in Vietnam and require transport resilience stabilization.
        assert_eq!(evaluate_pass_through(Some("steampowered.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("store.steampowered.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("api.steampowered.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("steamcommunity.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("steamstatic.com"), true, &custom), None);

        // Steam Cloud Save Storage & Game Content CDN MUST pass through raw (Reason: Storage)
        // to prevent ingress proxy resets and TLS record fragmentation aborts on Google GCS / AWS S3
        assert_eq!(evaluate_pass_through(Some("steamcloud-singapore.storage.googleapis.com"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("steamcloud-taiwan.storage.googleapis.com"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("steamcloud-hk.storage.googleapis.com"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("steamcloud-sg.s3.dualstack.ap-southeast-1.amazonaws.com"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("steamcloudsg.blob.core.windows.net"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("steamcontent.com"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("steamcloud-ord1.steamcontent.com"), true, &custom), Some(PassThroughReason::Storage));

        // Riot Games Patch & Asset CDN MUST pass through raw (Reason: Storage)
        assert_eq!(evaluate_pass_through(Some("riotcdn.net"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("lol.secure.dyn.riotcdn.net"), true, &custom), Some(PassThroughReason::Storage));
        assert_eq!(evaluate_pass_through(Some("riot-client.secure.dyn.riotcdn.net"), false, &custom), Some(PassThroughReason::Storage));

        // F2 (T2, T4, T5, T6, T7, T12, T13): Direct IP, empty SNI, single-label, or invalid FQDN
        assert_eq!(evaluate_pass_through(None, true, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some(""), true, &custom), Some(PassThroughReason::NoSni));               // T12
        assert_eq!(evaluate_pass_through(Some("   "), true, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(None, false, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some("ultraviewer"), false, &custom), Some(PassThroughReason::NoSni));   // T2
        assert_eq!(evaluate_pass_through(Some("unknown-service"), true, &custom), Some(PassThroughReason::NoSni)); // T4
        assert_eq!(evaluate_pass_through(Some("localhost"), true, &custom), Some(PassThroughReason::NoSni));      // T5
        assert_eq!(evaluate_pass_through(Some("localhost"), false, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some("42.96.32.170"), true, &custom), Some(PassThroughReason::NoSni));   // T6
        assert_eq!(evaluate_pass_through(Some("51.222.43.134"), false, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some("2001:db8::1"), true, &custom), Some(PassThroughReason::NoSni));    // T7
        assert_eq!(evaluate_pass_through(Some("example.com."), true, &custom), Some(PassThroughReason::NoSni));   // T13
        assert_eq!(evaluate_pass_through(Some(".example.com"), true, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some("bad..domain.com"), true, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some("-bad.domain.com"), true, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some("host.123"), true, &custom), Some(PassThroughReason::NoSni));

        // Underscore hostnames (_service._tcp.example.com) intentionally fall back to NoSni pass-through
        assert_eq!(evaluate_pass_through(Some("_service._tcp.example.com"), true, &custom), Some(PassThroughReason::NoSni));
        assert_eq!(evaluate_pass_through(Some("internal_host.local"), true, &custom), Some(PassThroughReason::NoSni));

        // Punycode IDN domains (xn--...) and mixed-case FQDNs are accepted as valid FQDNs
        assert_eq!(evaluate_pass_through(Some("xn--bcher-kva.example.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("example.xn--fiqs8s"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("Connect.UltraViewer.NET"), true, &custom), Some(PassThroughReason::Compat));
        assert_eq!(evaluate_pass_through(Some("Sub.Internal-Company.NET"), false, &custom), Some(PassThroughReason::Custom));

        // F6: DoH resolvers ALWAYS pass-through, even when compat_mode = false!
        assert_eq!(evaluate_pass_through(Some("cloudflare-dns.com"), false, &custom), Some(PassThroughReason::Doh));
        assert_eq!(evaluate_pass_through(Some("dns.google"), false, &custom), Some(PassThroughReason::Doh));
        assert_eq!(evaluate_pass_through(Some("dns.quad9.net"), false, &custom), Some(PassThroughReason::Doh));
        assert_eq!(evaluate_pass_through(Some("dns.adguard-dns.com"), false, &custom), Some(PassThroughReason::Doh));

        // F3: When compat_mode = false, game/remote domains are NOT passed through!
        assert_eq!(evaluate_pass_through(Some("connect.ultraviewer.net"), false, &custom), None);
        assert_eq!(evaluate_pass_through(Some("public-ubiservices.ubi.com"), false, &custom), None);
        assert_eq!(evaluate_pass_through(Some("auth.riotgames.com"), false, &custom), None);
        assert_eq!(evaluate_pass_through(Some("edge.rgpub.io"), false, &custom), None);
        assert_eq!(evaluate_pass_through(Some("dradis-prod.rdatasrv.net"), false, &custom), None);
        assert_eq!(evaluate_pass_through(Some("sso.vnggames.com"), false, &custom), None);
        assert_eq!(evaluate_pass_through(Some("id.zing.vn"), false, &custom), None);

        // Custom excluded domains pass through regardless of compat_mode
        assert_eq!(evaluate_pass_through(Some("internal-company.net"), false, &custom), Some(PassThroughReason::Custom));
        assert_eq!(evaluate_pass_through(Some("sub.internal-company.net"), false, &custom), Some(PassThroughReason::Custom));

        // F7: Standard websites that should be stabilized (None = not passed through)
        assert_eq!(evaluate_pass_through(Some("google.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("facebook.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("discord.com"), true, &custom), None);
        assert_eq!(evaluate_pass_through(Some("youtube.com"), true, &custom), None);
    }

    #[test]
    fn test_is_builtin_bypass_domains() {
        // DoH resolvers: MUST match is_builtin_doh and is_builtin_bypass, but NOT is_builtin_compat
        assert!(is_builtin_doh("cloudflare-dns.com"));
        assert!(is_builtin_doh("dns.google"));
        assert!(is_builtin_doh("dns.adguard-dns.com"));
        assert!(!is_builtin_compat("cloudflare-dns.com"));
        assert!(is_builtin_bypass("cloudflare-dns.com"));

        // Compat ecosystems & sensitive WAF endpoints: MUST match is_builtin_compat and is_builtin_bypass, but NOT is_builtin_doh
        assert!(is_builtin_compat("public-ubiservices.ubi.com"));
        assert!(is_builtin_compat("connect.ubisoft.com"));
        assert!(is_builtin_compat("connect.ultraviewer.net"));
        assert!(is_builtin_compat("master.teamviewer.com"));
        assert!(is_builtin_compat("relay.anydesk.com"));
        assert!(is_builtin_compat("relay.rustdesk.com"));
        assert!(is_builtin_compat("sso.vnggames.com"));
        assert!(is_builtin_compat("lienminh.vnggames.com"));
        assert!(is_builtin_compat("id.zing.vn"));
        assert!(is_builtin_compat("gas.garena.com"));
        assert!(!is_builtin_doh("connect.ultraviewer.net"));
        assert!(is_builtin_bypass("connect.ultraviewer.net"));

        // Target domains that should be stabilized (MUST NOT match either)
        assert!(!is_builtin_bypass("discord.com"));
        assert!(!is_builtin_bypass("google.com"));
        assert!(!is_builtin_bypass("youtube.com"));
        assert!(!is_builtin_bypass("notubi.com"));
    }

    #[test]
    fn test_steam_ecosystem_expansion_in_hostlist() {
        // When user targets steampowered.com in Scope::HostList, core Steam platform endpoints
        // (Community, Store, API, CM servers) are automatically covered.
        assert!(matches_target_or_ecosystem("community.steamstatic.com", "steampowered.com"));
        assert!(matches_target_or_ecosystem("steamcommunity.com", "steampowered.com"));
        assert!(matches_target_or_ecosystem("store.steampowered.com", "steampowered.com"));
        assert!(matches_target_or_ecosystem("api.steampowered.com", "steampowered.com"));
        assert!(matches_target_or_ecosystem("images.steamusercontent.com", "steampowered.com"));
        assert!(matches_target_or_ecosystem("api.steamgames.com", "steampowered.com"));
        assert!(matches_target_or_ecosystem("cm1.steamserver.net", "steampowered.com"));

        // Direct matching still works for non-Steam targets
        assert!(matches_target_or_ecosystem("sub.example.com", "example.com"));
        assert!(!matches_target_or_ecosystem("otherdomain.com", "example.com"));

        // Cloud save storage buckets (GCS, S3, Azure) and content CDN are intentionally NOT matched
        // as active resilience mutation targets; they pass through raw via is_cloud_storage_endpoint!
        assert!(!matches_target_or_ecosystem("steamcloud-singapore.storage.googleapis.com", "steampowered.com"));
        assert!(!matches_target_or_ecosystem("steamcloud-taiwan.storage.googleapis.com", "steampowered.com"));
        assert!(!matches_target_or_ecosystem("steamcloud-hk.storage.googleapis.com", "steampowered.com"));
        assert!(!matches_target_or_ecosystem("steamcloud-sg.s3.dualstack.ap-southeast-1.amazonaws.com", "steampowered.com"));
        assert!(!matches_target_or_ecosystem("steamcloudsg.blob.core.windows.net", "steampowered.com"));
        assert!(!matches_target_or_ecosystem("steamcontent.com", "steampowered.com"));
    }

    #[test]
    fn test_is_cloud_storage_endpoint() {
        // Multi-cloud Cloud Save Storage Buckets used by Steam
        assert!(is_cloud_storage_endpoint("steamcloud-singapore.storage.googleapis.com"));
        assert!(is_cloud_storage_endpoint("steamcloud-taiwan.storage.googleapis.com"));
        assert!(is_cloud_storage_endpoint("steamcloud-hk.storage.googleapis.com"));
        assert!(is_cloud_storage_endpoint("steamcloud-sg.s3.dualstack.ap-southeast-1.amazonaws.com"));
        assert!(is_cloud_storage_endpoint("steamcloudsg.blob.core.windows.net"));

        // Generic cloud storage endpoints
        assert!(is_cloud_storage_endpoint("storage.googleapis.com"));
        assert!(is_cloud_storage_endpoint("mybucket.storage.googleapis.com"));
        assert!(is_cloud_storage_endpoint("mybucket.s3.amazonaws.com"));
        assert!(is_cloud_storage_endpoint("mybucket.blob.core.windows.net"));

        // Steam content distribution CDN
        assert!(is_cloud_storage_endpoint("steamcontent.com"));
        assert!(is_cloud_storage_endpoint("steamcloud-ord1.steamcontent.com"));

        // Riot Games & VNGGames content distribution & patch CDN
        assert!(is_cloud_storage_endpoint("riotcdn.net"));
        assert!(is_cloud_storage_endpoint("lol.secure.dyn.riotcdn.net"));
        assert!(is_cloud_storage_endpoint("riot-client.secure.dyn.riotcdn.net"));
        assert!(is_cloud_storage_endpoint("riotcdn.com"));
        assert!(is_cloud_storage_endpoint("cdn-apo.vnggames.com"));

        // Non-storage domains that must be stabilized (must NOT match)
        assert!(!is_cloud_storage_endpoint("store.steampowered.com"));
        assert!(!is_cloud_storage_endpoint("steamcommunity.com"));
        assert!(!is_cloud_storage_endpoint("discord.com"));
        assert!(!is_cloud_storage_endpoint("youtube.com"));
    }

    #[test]
    fn test_concurrent_update_lists_and_hot_path_reads() {
        // Initialize runtime policy
        update_lists(
            &["discord.com".to_string()],
            &["alpha.internal.net".to_string()],
            true,
        );

        let writer = std::thread::spawn(|| {
            for i in 0..500 {
                let compat = i % 2 == 0;
                let custom = if compat {
                    vec!["alpha.internal.net".to_string()]
                } else {
                    vec!["beta.internal.net".to_string()]
                };
                let selected = vec![format!("host-{i}.example.com")];
                update_lists(&selected, &custom, compat);
            }
        });

        let mut readers = Vec::new();
        for _ in 0..4 {
            readers.push(std::thread::spawn(|| {
                let mut local_gen = 0usize;
                let mut active = Arc::new(RuntimePolicy::default());
                for _ in 0..2000 {
                    let cur_gen = POLICY_GENERATION.load(Ordering::Acquire);
                    if cur_gen != local_gen {
                        if let Ok(guard) = RUNTIME_POLICY.read() {
                            if let Some(ref pol) = *guard {
                                active = Arc::clone(pol);
                            }
                        }
                        local_gen = cur_gen;
                    }
                    // Verify atomic snapshot consistency: when compat_mode is true, alpha.internal.net
                    // is in custom_excluded; when false, beta.internal.net is in custom_excluded.
                    if !active.custom_excluded.is_empty() {
                        if active.compat_mode {
                            assert_eq!(
                                evaluate_pass_through(Some("alpha.internal.net"), active.compat_mode, &active.custom_excluded),
                                Some(PassThroughReason::Custom)
                            );
                            assert_eq!(
                                evaluate_pass_through(Some("ultraviewer"), active.compat_mode, &active.custom_excluded),
                                Some(PassThroughReason::Compat)
                            );
                        } else {
                            assert_eq!(
                                evaluate_pass_through(Some("beta.internal.net"), active.compat_mode, &active.custom_excluded),
                                Some(PassThroughReason::Custom)
                            );
                            assert_eq!(
                                evaluate_pass_through(Some("ultraviewer"), active.compat_mode, &active.custom_excluded),
                                Some(PassThroughReason::NoSni)
                            );
                        }
                    }
                }
            }));
        }

        writer.join().expect("Writer thread should not panic");
        for r in readers {
            r.join().expect("Reader thread should not panic");
        }
    }
}

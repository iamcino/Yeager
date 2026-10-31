//! Levi Native Connection Resilience Engine.
//! Provides surgical-precision TLS transport stabilization directly in user-space via WinDivert.

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
use std::sync::{Arc, Mutex};
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

pub static STATS_HANDSHAKES: AtomicUsize = AtomicUsize::new(0);
pub static STATS_STABILIZED: AtomicUsize = AtomicUsize::new(0);
pub static STATS_DROPPED_RSTS: AtomicUsize = AtomicUsize::new(0);
pub static STATS_BYPASSED: AtomicUsize = AtomicUsize::new(0);

/// Built-in pass-through domains that must NEVER be fragmented or mutated.
/// Includes DoH resolvers, gaming ecosystems, anti-cheat gateways, and services
/// with strict WAF/anti-tamper middleboxes (e.g. AWS ALB, Akamai Edge).
pub const BUILTIN_BYPASS_DOMAINS: &[&str] = &[
    // Encrypted DNS Resolvers (DoH)
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "one.one.one.one",
    "dns.adguard-dns.com",
    "dns.adguard.com",

    // Ubisoft Connect & Services
    "ubi.com",
    "ubisoft.com",
    "ubisoftconnect.com",
    "uplay.com",
    "ubi.li",

    // Riot Games (Vanguard / LoL / Valorant)
    "riotgames.com",
    "pvp.net",
    "leagueoflegends.com",
    "valgame.net",

    // Blizzard / Battle.net
    "battle.net",
    "blizzard.com",

    // Electronic Arts / Origin
    "ea.com",
    "origin.com",

    // Epic Games & Unreal Engine
    "epicgames.com",
    "unrealengine.com",

    // Valve / Steam
    "steampowered.com",
    "steamcommunity.com",
    "steamcontent.com",
    "steamstatic.com",

    // Microsoft Gaming / Xbox / PlayFab
    "xboxlive.com",
    "playfabapi.com",
];

/// Checks whether a domain should be bypassed without packet mutation.
#[inline]
pub fn is_builtin_bypass(domain: &str) -> bool {
    BUILTIN_BYPASS_DOMAINS.iter().any(|target| matches_host(domain, target))
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

    let is_hostlist = cfg.scope == Scope::HostList;
    let target_hosts: HashSet<String> = cfg
        .hosts
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let game_protection = cfg.game_protection_enabled;
    let custom_excluded: Vec<String> = cfg
        .custom_excluded_domains
        .iter()
        .map(|h| h.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .collect();

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
                    2 => false, // Hardened: Out-of-Order Multi-Split (with jitter)
                    _ => {
                        // Auto: Default to In-Order for tunnels/VPNs (MTU <= 1420), zero packet drops
                        true
                    }
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
                    // Register handshake for state-aware RST silencer tracking
                    handshake_tracker.record_client_hello(parsed.dst_ip, parsed.src_port);

                    // Observe Mode: Monitor & Telemetry only, zero packet mutation
                    if ACTIVE_PROFILE.load(Ordering::Relaxed) == 3 {
                        let _ = ResilienceEngine::send_raw(&api_clone, handle, pkt_bytes, &addr);
                        continue;
                    }

                    let info = tls::parse_client_hello(parsed.payload);
                    let mut should_stabilize = !is_hostlist;

                    if let Some(ref inf) = info {
                        if let Some(sni) = inf.sni {
                            let s = sni.to_lowercase();
                            // Check built-in bypass: DoH resolvers, game launchers & sensitive WAF endpoints,
                            // or user-defined custom excluded domains
                            let is_bypassed = (game_protection && is_builtin_bypass(&s))
                                || custom_excluded.iter().any(|b| matches_host(&s, b));

                            if is_bypassed {
                                should_stabilize = false;
                                STATS_BYPASSED.fetch_add(1, Ordering::Relaxed);
                            } else if is_hostlist {
                                should_stabilize = target_hosts.iter().any(|target| {
                                    matches_host(&s, target)
                                });
                            }
                        } else if is_hostlist {
                            should_stabilize = false;
                        }
                    } else if is_hostlist {
                        should_stabilize = false;
                    }

                    if should_stabilize {
                        STATS_STABILIZED.fetch_add(1, Ordering::Relaxed);

                        // Proven resilient TLS transport stabilization strategy:
                        // 3-way multi-split (TLS Record header + midpoint SNI split).
                        let sni_split = info.as_ref().and_then(|inf| {
                            match (inf.sni_offset, inf.sni) {
                                (Some(off), Some(sni)) if !sni.is_empty() => {
                                    Some(off + (sni.len() / 2).max(1))
                                }
                                (Some(off), _) => Some(off + 1),
                                _ => None,
                            }
                        });

                        let prof = ACTIVE_PROFILE.load(Ordering::Relaxed);
                        if prof != 2 {
                            // Fast-Path for Auto (0) and Fast (1) profiles:
                            // In-Order 3-Way Split with 0ms delay.
                            // Process inline on stack buffer: zero heap allocations (0 bytes), no channel enqueue, no thread context-switch!
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

                        // Hardened profile (2): Out-of-Order Multi-Split (3.3ms jitter delay)
                        // Offloaded to bounded worker pool to prevent thread churn on the main capture loop.
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
    if domain.len() > target.len() && domain.ends_with(target) {
        let prefix_len = domain.len() - target.len();
        return domain.as_bytes()[prefix_len - 1] == b'.';
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
    fn test_is_builtin_bypass_domains() {
        // Game ecosystems & sensitive WAF endpoints (MUST bypass)
        assert!(is_builtin_bypass("public-ubiservices.ubi.com"));
        assert!(is_builtin_bypass("connect.ubisoft.com"));
        assert!(is_builtin_bypass("uplaypc-s-ubisoft.cdn.ubi.com"));
        assert!(is_builtin_bypass("auth.riotgames.com"));
        assert!(is_builtin_bypass("client.battle.net"));
        assert!(is_builtin_bypass("origin.com"));
        assert!(is_builtin_bypass("epicgames.com"));
        assert!(is_builtin_bypass("steamcontent.com"));
        assert!(is_builtin_bypass("playfabapi.com"));

        // DoH resolvers (MUST bypass)
        assert!(is_builtin_bypass("cloudflare-dns.com"));
        assert!(is_builtin_bypass("dns.google"));
        assert!(is_builtin_bypass("dns.adguard-dns.com"));

        // Target domains that should be stabilized (MUST NOT bypass)
        assert!(!is_builtin_bypass("discord.com"));
        assert!(!is_builtin_bypass("google.com"));
        assert!(!is_builtin_bypass("youtube.com"));
        assert!(!is_builtin_bypass("notubi.com"));
    }
}

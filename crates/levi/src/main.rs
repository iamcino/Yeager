//! Standalone CLI executable for Levi Engine.

use common::{Config, Scope};
use std::io::{self, Write};

#[cfg(windows)]
fn check_supported_os() {
    #[repr(C)]
    struct OsVersionInfoExW {
        dw_os_version_info_size: u32,
        dw_major_version: u32,
        dw_minor_version: u32,
        dw_build_number: u32,
        dw_platform_id: u32,
        sz_csd_version: [u16; 128],
        w_service_pack_major: u16,
        w_service_pack_minor: u16,
        w_suite_mask: u16,
        w_product_type: u8,
        w_reserved: u8,
    }
    type RtlGetVersionFn = unsafe extern "system" fn(*mut OsVersionInfoExW) -> i32;

    let build = unsafe {
        let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if !ntdll.is_null() {
            let proc = windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, c"RtlGetVersion".as_ptr().cast());
            if let Some(func) = proc {
                let rtl_get_version: RtlGetVersionFn = std::mem::transmute(func);
                let mut info: OsVersionInfoExW = std::mem::zeroed();
                info.dw_os_version_info_size = std::mem::size_of::<OsVersionInfoExW>() as u32;
                if rtl_get_version(&mut info) == 0 {
                    info.dw_build_number
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    };

    if build > 0 && build < 20348 {
        eprintln!("[-] Error: Levi requires Windows 11 or Windows Server 2022+ (build 20348 or newer).");
        eprintln!("[-] Detected build: {build}.");
        eprintln!("[-] Levi and Yeager rely on Windows 11 native DoH and network architecture.");
        eprintln!("[-] Windows 10 is not supported.");
        std::process::exit(1);
    }
}

fn print_help() {
    println!("Yeager - Levi Connection Resilience & TLS Stabilization Engine (CLI)");
    println!("Usage: levi.exe [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --all                   Intercept all outbound HTTPS (Port 443)");
    println!("  --hosts <domain,...>    Target specific domains (comma-separated)");
    println!("  --profile <name>        Resilience profile: auto, fast, hardened, observe");
    println!("  --help, -h              Print this help message and exit");
    println!("  --version, -V           Print version information and exit");
    println!("  --license               Print license information and exit");
}

fn print_license() {
    println!("Yeager / Levi Engine");
    println!("Copyright (C) 2026 Cino");
    println!("Licensed under the MIT License.");
    println!("See https://github.com/iamcino/Yeager/blob/master/LICENSE for details.");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Harmless informational commands run freely without requiring OS gate
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("levi {} (Yeager connection resilience engine)", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--license") {
        print_license();
        return;
    }

    #[cfg(windows)]
    check_supported_os();

    println!("Yeager - Levi Connection Resilience & TLS Stabilization Engine (CLI)");
    println!("Platform: Windows 11 x64 | Engine: WinDivert Native");
    println!("--------------------------------------------------");

    let mut cfg = Config::default();

    let profile = if let Some(idx) = args.iter().position(|a| a == "--profile") {
        args.get(idx + 1)
            .and_then(|s| s.parse::<levi::ResilienceProfile>().ok())
            .unwrap_or_else(|| {
                eprintln!("[-] Invalid profile specified. Defaulting to Auto.");
                levi::ResilienceProfile::Auto
            })
    } else {
        levi::ResilienceProfile::Auto
    };

    if args.iter().any(|arg| arg == "--all") {
        cfg.scope = Scope::All;
        println!("[*] Scope: All outbound HTTPS (Port 443)");
    } else if let Some(hosts_idx) = args.iter().position(|arg| arg == "--hosts") {
        if let Some(hosts_val) = args.get(hosts_idx + 1) {
            cfg.scope = Scope::HostList;
            cfg.selected_hosts = hosts_val.split(',').map(|s| s.trim().to_string()).collect();
            println!("[*] Scope: HostList ({:?})", cfg.selected_hosts);
        }
    } else {
        println!("Usage: levi.exe [--all] [--profile auto|fast|hardened|observe] [--hosts domain1.com,domain2.com]");
        println!("Defaulting to Scope: All");
        cfg.scope = Scope::All;
    }

    println!("[*] Transport Profile: {:?}", profile);
    println!("[*] Starting Levi Native Engine...");
    match levi::start_with_profile(&cfg, profile) {
        Ok(()) => {
            println!("[+] Levi Engine is running smoothly.");
            println!("[+] Engine packet-loop is intercepting TLS Handshakes.");
            println!("[+] Live stats will be displayed when traffic occurs.");
            println!("[+] Press Enter to stop.\n");
            let _ = io::stdout().flush();
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
            println!("[*] Stopping Levi Engine...");
            levi::stop();
            println!("[+] Stopped. WinDivert handle closed.\n");

            // Telemetry Report Dashboard
            let hs = levi::STATS_HANDSHAKES.load(std::sync::atomic::Ordering::Relaxed);
            let bp = levi::STATS_STABILIZED.load(std::sync::atomic::Ordering::Relaxed);
            let rst = levi::STATS_DROPPED_RSTS.load(std::sync::atomic::Ordering::Relaxed);

            println!("==================================================");
            println!("   LEVI ENGINE TRANSPORT TELEMETRY REPORT        ");
            println!("==================================================");
            println!("  Total TLS Handshakes Intercepted : {}", hs);
            println!("  Sessions Stabilized (Multi-Split): {}", bp);
            println!("  Inbound Middlebox RSTs Silenced  : {}", rst);
            if hs > 0 {
                let ratio = (bp as f64 / hs as f64) * 100.0;
                println!("  Stabilization Coverage Rate      : {:.1}%", ratio);
            }
            println!("==================================================");
        }
        Err(e) => {
            eprintln!("[-] Error starting Levi Engine: {}", e);
            std::process::exit(1);
        }
    }
}

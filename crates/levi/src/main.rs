//! Standalone CLI executable for Levi Engine.

use common::{Config, Scope};
use std::io::{self, Write};

fn main() {
    println!("Yeager - Levi Connection Resilience & TLS Stabilization Engine (CLI)");
    println!("Platform: Windows 11 x64 | Engine: WinDivert Native");
    println!("--------------------------------------------------");

    let args: Vec<String> = std::env::args().collect();
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
            cfg.hosts = hosts_val.split(',').map(|s| s.trim().to_string()).collect();
            println!("[*] Scope: HostList ({:?})", cfg.hosts);
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

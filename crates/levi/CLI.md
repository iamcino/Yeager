# Levi — Native Connection Resilience & Headless TLS Transport Engine

**English** · [Tiếng Việt](CLI.vi.md)

`levi` is a pure-Rust native connection-resilience engine and standalone headless CLI tool (`levi.exe`) designed to maintain the stability and reliability of HTTPS connections across challenging, lossy, or interfering local networks:

- **Standalone Headless CLI & Embeddable Crate:** Can be run directly as a lightweight console daemon (`dist/levi.exe`, ~500 KB) or embedded into the Yeager desktop application.
- **Zero-configuration Transparency:** Operates directly at the Windows network layer via an embedded, signed WinDivert 2.2 driver; requires no local SOCKS/HTTP proxy configuration and no extra root CA certificates.
- **Surgical Precision:** Focuses exclusively on the opening TLS `ClientHello` handshake segment; 100% of subsequent application payload streams at full hardware line-rate.
- **Zero-Heap Fast-Path:** Non-target packets and local encrypted DNS traffic pass through immediately without heap allocations, keeping added latency under 20 microseconds.
- **Bounded Zero-Lag Worker Pool:** Dispatches packet processing across a dedicated pool of 4–6 worker threads communicating via `sync_channel(256)`, eliminating thread-spawn jitter under high connection loads.

---

## 1. Headless CLI Quick Start (`levi.exe`)

The headless CLI executable is located at `dist/levi.exe` or can be built directly via `cargo build -p levi --bin levi --release`.

> [!IMPORTANT]
> Because Levi interacts with the network layer via the WinDivert kernel driver, `levi.exe` must be run from an **Administrator command prompt** or PowerShell session.

### Basic Usage

```powershell
# Run with default settings (Scope: All HTTPS, Profile: Auto)
.\levi.exe

# Explicitly process all outbound HTTPS traffic (Port 443)
.\levi.exe --all

# Run with Fast profile (In-Order 3-way split, 0ms latency, gaming & VPN friendly)
.\levi.exe --all --profile fast

# Run with Hardened profile (Alternative-sequence split with 3.3ms–3.5ms timing)
.\levi.exe --all --profile hardened

# Run in Observe mode (Passive telemetry only, zero packet modification)
.\levi.exe --all --profile observe

# Limit processing to specific target domains (Domain list scope)
.\levi.exe --profile fast --hosts example.com,cdn.example.org,api.target.net
```

### CLI Options

| Flag | Parameter | Description |
| :--- | :--- | :--- |
| `--all` | *(none)* | Process all outbound HTTPS traffic on TCP port 443. *(Default scope)* |
| `--profile` | `auto` \| `fast` \| `hardened` \| `observe` | Select transport resilience profile. Defaults to `auto`. |
| `--hosts` | `domain1,domain2,...` | Limit segmentation to a comma-separated list of domain names (SNI matching). |

### Graceful Shutdown & Telemetry Report

Press <kbd>Enter</kbd> at any time to stop the engine. Levi immediately closes the WinDivert handle, unloads kernel hooks, restores clean packet flow, and prints a **Transport Telemetry Report**:

```text
==================================================
   LEVI ENGINE TRANSPORT TELEMETRY REPORT        
==================================================
  Total TLS Handshakes Intercepted : 142
  Sessions Stabilized (Multi-Split): 142
  Inbound Middlebox RSTs Silenced  : 38
  Stabilization Coverage Rate      : 100.0%
==================================================
```

---

## 2. Transport Profiles (`ResilienceProfile`)

Levi provides four standardized transport profiles exposed via the `ResilienceProfile` enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResilienceProfile {
    #[default]
    Auto,      // Adaptive 0ms profile; optimal for both physical interfaces and VPN tunnels
    Fast,      // In-Order 3-Way Multi-Split (0ms added delay; optimal for gaming, streaming & WireGuard)
    Hardened,  // Alternative-Sequence Multi-Split + Calibrated 3.3ms–3.5ms Timing (for lossy, interfering links)
    Observe,   // Passive Monitoring Mode (0% packet modification; monitors connection health & reset anomalies)
}
```

### 2.1. Profile `Fast` (In-Order Multi-Split — 0ms Latency)
- **Mechanism:** Surgically splits the TLS `ClientHello` into three contiguous segments:
  - *Cut Point 1:* After byte 2 of the TLS Record Header (`0x16 0x03`).
  - *Cut Point 2:* Midpoint of the Server Name Indication (SNI) hostname.
- **Transmission Order:** Segment 1 $\rightarrow$ Segment 2 $\rightarrow$ Segment 3 (**strictly in-order, 0 ms added delay**).
- **Advantages:**
  - Preserves exact TCP sequence ordering; 100% compatible with VPN tunnels (WireGuard, NetBird, OpenVPN, MTU 1280).
  - Ideal for competitive gaming, voice calls, and real-time streaming where added latency is unacceptable.

### 2.2. Profile `Hardened` (Alternative-Sequence Multi-Split + Hybrid Timing)
- **Mechanism:** Emits segments in an alternative order: Segment 3 $\rightarrow$ [Hybrid Timing] $\rightarrow$ Segment 2 $\rightarrow$ [Hybrid Timing] $\rightarrow$ Segment 1.
- **High-Precision Timing:** Combines thread sleep (CPU power/battery saving) and cycle spin-loops (`Instant::now()` + `std::hint::spin_loop()`) in the calibrated $[3300\,\mu\text{s} .. 3500\,\mu\text{s}]$ window.
- **Application:** Helps connections traverse congested middlebox queues and networks that drop or stall early handshake packets.

### 2.3. Profile `Observe` (Passive Telemetry & Audit Mode)
- **Mechanism:** Zero packet modification. All TLS handshakes pass untouched.
- **Application:** Safe network diagnostics and auditing. Accurately measures handshake volumes and detects abnormal network-injected TCP resets without altering packet structure.

### 2.4. Profile `Auto` (Default)
- Automatically prioritizes the `Fast` (In-Order) strategy to deliver immediate 0ms-latency protection, seamlessly adapting across network interface changes and VPN connects/disconnects.

---

## 3. Inbound Reset Silencer

Lossy or interfering middleboxes sometimes emit premature `TCP RST` packets (`SrcPort == 443`) before the real remote server can reply. Levi deploys an inbound kernel filter:

```text
(inbound and tcp.SrcPort == 443 and tcp.Rst)
```

- Abnormal resets arriving during initial handshake establishment are silently dropped at the driver level, keeping the user socket alive for the genuine server reply.
- Normal connection closures after an established session are never blocked.
- Total dropped resets are tracked in real-time in `STATS_DROPPED_RSTS`.

---

## 4. Real-time Telemetry Counters

Global atomic counters are exposed for the CLI and UI to read concurrently without locking:

- `levi::STATS_HANDSHAKES`: Total number of TLS handshakes received.
- `levi::STATS_STABILIZED`: Total number of sessions stabilized.
- `levi::STATS_DROPPED_RSTS`: Total number of abnormal inbound resets dropped.

---

## 5. Rust Library Integration API

Levi can be embedded into any Rust application (`crates/app`):

```rust
use common::Config;
use levi::ResilienceProfile;
use std::sync::atomic::Ordering;

// 1. Start engine with default configuration (Auto profile)
levi::start(&cfg)?;

// 2. Or start with a specific transport profile
levi::start_with_profile(&cfg, ResilienceProfile::Fast)?;

// 3. Query real-time telemetry stats (e.g. for a UI poll loop)
let handshakes = levi::STATS_HANDSHAKES.load(Ordering::Relaxed);
let stabilized = levi::STATS_STABILIZED.load(Ordering::Relaxed);
let rst_dropped = levi::STATS_DROPPED_RSTS.load(Ordering::Relaxed);

// 4. Clean, graceful teardown (releases driver handle and worker pool in < 0.1s)
levi::stop();
```

---

## 6. Building from Source

To compile the headless CLI binary independently:

```powershell
# From project root
cargo build -p levi --bin levi --release

# Output binary:
# target/release/levi.exe (~500 KB)
```

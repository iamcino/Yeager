# Yeager — Design Document

**English** · [Tiếng Việt](DESIGN.vi.md)

> Version 1.0.0 · Windows 11 x64 · Rust + Slint + WinDivert

This document describes how Yeager is put together and the rules the code
follows. For installing and using the app, see the [README](../README.md).

## 1. Principles

Yeager is a local network helper, **not** a VPN, proxy or anonymiser.

1. **Transparent.** Browsers and apps need no proxy settings and no extra
   certificate. Traffic goes directly to its destination from the user's own
   IP address and stays end-to-end encrypted.
2. **Precise.** Act only where it helps (one port, an optional domain list);
   everything else runs at native speed.
3. **Reversible.** Every system change is saved first and put back on disable,
   on exit, and on the next launch after a crash.
4. **Light.** One native binary in the system tray, low idle memory, short CPU
   bursts only while connections are being set up.
5. **Security-software friendly.** Windows APIs instead of hidden PowerShell or
   raw registry writes; no fake packets or unusual TCP flags.

## 2. Architecture

A Cargo workspace whose crates are named after *Attack on Titan* characters:

```
yeager/
├── Cargo.toml          workspace root
├── crates/
│   ├── app/            Yeager: Slint UI, tray, orchestration (yeager.exe)
│   ├── levi/           Levi:   connection engine library + levi.exe CLI
│   ├── erwin/          Erwin:  TCP congestion control, config, startup task
│   ├── hange/          Hange:  DNS over HTTPS/3 resolver, system DoH setup
│   └── common/         shared types, config model, errors, process helpers
├── assets/             driver files, fonts, icons
├── installer/          Inno Setup script
├── tools/              icon generator, DNS test script
└── docs/               this document
```

### Data flow

```
 Browser / apps
       │
       ▼
 Windows TCP/IP stack ──── Erwin: congestion control (BBRv2 / CUBIC / CTCP)
       │
       ├── DNS (port 53) ──► Hange stub 127.0.0.1:53 ──► DoH over HTTP/3 (→ HTTP/2) ──► provider
       │
       └── HTTPS (443) ────► Levi: All / Domain list ──► Internet
```

### Feature dependencies

- The engine requires encrypted DNS: enabling the engine enables DoH first;
  disabling DoH stops the engine.
- DoH and TCP tuning each run on their own.

## 3. Modules

### app — Yeager

- Slint UI with pages Home, System, Engine, TCP, DNS and Appearance;
  Vietnamese and English text.
- System tray menu; closing the window hides it to the tray, *Quit* exits.
- Long operations run on background threads and report back to the UI thread.
- On exit: stop the engine, restore TCP settings, disable DoH.
- The engine is reached only through `crates/app/src/engine.rs`
  (`start`, `stop`, `is_running`).
- Ships a `requireAdministrator` manifest and the app icon via `embed-resource`.

### levi — connection engine

- Native Rust library linked into `yeager.exe`, plus a standalone `levi.exe`
  command-line build (~486 KB).
- Embeds the signed WinDivert 2.2 driver and unpacks it on start; no separate
  install.
- Supports 4 Transport Profiles (`ResilienceProfile`):
  - `Auto` (default, used by `start`): selects `Fast`.
  - `Fast`: 3-way In-Order Multi-Split (0ms added delay, optimal for gaming & WireGuard VPN tunnels).
  - `Hardened`: Stream Anti-Tampering Multi-Split (Disorder + Calibrated Jitter 3.3ms..3.5ms).
  - `Observe`: passive; counts handshakes and injected resets, sends every
    packet unchanged.
- Scope: `All` (every outgoing TCP 443 connection) or `HostList` (listed
  domains and their subdomains only).
- Non-blocking: bounded pool of 4 to 6 worker threads communicating via `sync_channel(256)`,
  completely eliminating Windows thread allocation churn.
- Only connection-opening payloads are captured outbound, so ACKs and
  keepalives never reach user space; the per-packet path is 100% allocation-free (zero-alloc).
- Anti-tampering: Inbound Middlebox RST Silencer drops spoofed reset packets
  on port 443 in kernel space before they reach application sockets. Only
  resets matching a connection opened in the last 3.5 s are dropped, so a real
  server's reset on an established connection still closes the socket.
- Local traffic is never touched: private and local destinations (RFC 1918,
  loopback, link-local, ULA) and IPv6 destinations on the same /64 as the
  source pass straight through.
- Real-time telemetry: exposes atomic counters (`STATS_HANDSHAKES`,
  `STATS_STABILIZED`, `STATS_DROPPED_RSTS`) for UI and telemetry dashboards.
- Excludes DNS (port 53) and Yeager's own DoH upstream connections, and ignores
  packets it has itself sent (`!impostor`).
- `start(&Config)`, `start_with_profile(&Config, ResilienceProfile)`, `stop()` and
  `is_running()`; stopping releases driver handle and worker pool in < 0.1s.
- Maintained by the project owner.

### erwin — TCP tuning and configuration

- Sets the Windows congestion provider for the `internet` TCP template via
  `netsh int tcp set supplemental`, plus the pacing profile.
- **Auto:** pings 1.1.1.1 and 8.8.8.8; a clean, stable link gets CUBIC, loss,
  jitter or a long path gets BBRv2.
- **Diagnose:** a timed download from `speed.cloudflare.com` with each
  candidate, comparing throughput and latency under load, then suggests the
  best.
- Backs up the original provider and pacing to `tcp-backup.json` before the
  first change; `restore()` puts them back; *Restore Windows defaults* restores
  the backup or, without one, CUBIC with pacing off.
- Owns the persisted `Config` (`%LOCALAPPDATA%\Yeager\config.json`, written
  atomically) and the elevated logon scheduled task used for launch at login.

### hange — encrypted DNS

- Local stub on `127.0.0.1:53` and `[::1]:53` (UDP and TCP) with a TTL-aware
  LRU cache of 4096 entries. Positive answers are kept at least 60 s (TTL 0
  is never cached). Resolvers are dialled by IP, so there is no plaintext
  bootstrap.
- Keep-warm: while queries came in the last 15 min, a connection idle for
  40 s gets one small query (checked every 45 s), so the next lookup does not
  pay for a new TLS/QUIC handshake. Nothing is sent while the PC is idle.
- A new upstream connection is raced over every resolver address and both
  DNS over HTTP/3 and HTTP/2 at once (3 s to connect, 1.5 s per query). The
  first answer is returned and, of the routes that answer within another
  second, the quickest is kept. HTTP/3 is left out of races for 2 min after
  none of its routes answered, doubling up to 30 min; the route in use is
  raced again every 10 min in the background.
- Expired answers are served (TTL 30 s) when the upstream fails or takes over
  1.5 s, up to a day past their TTL, and refreshed in the background
  (RFC 8767).
- Upstreams sit in a pool: the chosen provider and a backup (AdGuard and
  Google fall back to Cloudflare, Cloudflare to Google) that answers after the
  chosen one has failed for 10 s; the chosen one is retried every 30 s. In
  Auto mode the pool holds Cloudflare and Google and moves to the other one
  when it measures over 20% (and at least 5 ms) faster twice in a row, checked
  every 30 min. AdGuard is never picked automatically, since it filters.
- The app shows each provider's route and latency: the one in use from its
  live queries, the others from one small query per address and transport
  while the DNS page is open (every 2 min at most).
- Each online adapter lists the stub first and then the provider's resolvers,
  with Windows' own DoH required (no UDP fallback), so a stopped stub degrades
  to Windows DoH, never plaintext. If port 53 is taken or *Speed up with
  *Local DNS* is off, only Windows DoH is used. In Auto mode Windows lists
  Cloudflare behind the stub.
- Adapter DNS is set through the IP Helper API (`GetAdaptersAddresses`,
  `SetInterfaceDnsSettings` with per-server DoH properties).
- Uses the Windows certificate store, so antivirus TLS scanning keeps working.
- Disabling resets the adapters to DHCP DNS; leftovers from a crash are
  cleaned on the next launch. An internal test suite checks the result from
  outside the app.

### common

`Config`, `Scope`, `Congestion`, `DohProvider`, the shared `Error` type and the
process helpers that run system tools without a console window.

## 4. Roadmap

1. **Foundation** — workspace, Slint shell, tray, engine integration. ✔
2. **Engine core** — native engine with embedded driver, scopes, CLI. ✔
3. **TCP and DNS** — congestion control with diagnosis, DoH over HTTP/3. ✔
4. **1.0.0** — bilingual UI and documentation, first public release. ✔
5. **Next** — code signing, encrypted Client Hello (ECH) support, a statistics
   view, per-network profiles.

## 5. Release notes for maintainers

- The WinDivert `.sys` driver is signed by its authors; keep the official
  binaries in `assets/engine/`.
- Version numbers live in `Cargo.toml` (`workspace.package.version`) and
  `installer/setup.iss` (`AppVersion`); update [CHANGELOG.md](../CHANGELOG.md)
  and [CHANGELOG.vi.md](../CHANGELOG.vi.md) with each release.
- Release assets must keep the "Made with Slint" attribution (see
  [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md)).

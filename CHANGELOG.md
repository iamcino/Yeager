# Changelog

**English** · [Tiếng Việt](CHANGELOG.vi.md)

All notable changes to Yeager are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.8] - 2026-10-30

### Changed
- Local DNS keeps its connection to the provider warm while you are using the PC, so the first lookup after a pause no longer waits for a new handshake. Nothing is sent while the PC is idle.
- Local DNS keeps answers for at least 60 seconds, so sites with very short TTLs are not looked up again and again.
- Engine: faster handling of new connections in the Auto and Fast profiles, and AdGuard DNS traffic is left untouched like the other encrypted DNS providers.
- Network card: IPv6 is no longer looked up on networks without IPv6, so Refresh finishes at once on IPv4-only connections.

### Fixed
- Sidebar icons are now drawn as vector shapes instead of recoloured images, so they no longer show up with pieces missing.

## [1.0.7] - 2026-10-30

### Added
- Engine: an **Observe** transport profile that changes no packets and only counts connections and injected resets, to check safely how the network behaves.
- Home page: a **Network** card with your local and public IPv4 and IPv6 addresses, and a Refresh button.
- The window can be resized by dragging its edges and corners, and opens at the size you left it.

### Changed
- Engine: injected resets are only dropped while a connection is being opened (about 3.5 s), so a real server closing an established connection is no longer held up.
- Engine: traffic to private and local addresses, and to IPv6 devices on the same /64 network as your PC (a NAS, a TV…), goes straight through at full LAN speed.
- The window opens larger (860 × 600).

### Fixed
- Long values on the home page, such as the encrypted DNS status, are cut with "…" instead of running past the card.
- Sidebar icons are drawn grey instead of black underneath their colour, to keep black dots from showing on them.

## [1.0.6] - 2026-10-30

### Added
- Engine: three transport profiles. **Auto** (default) picks **Fast**, which splits the start of each HTTPS connection into three in-order pieces and adds no latency, on direct lines and inside WireGuard / NetBird tunnels alike. **Hardened** sends the pieces out of order with a short calibrated pause (about 3.4 ms) for networks that tamper harder. Choose one on the Engine page; the home page shows the one in use.
- Engine page: live counters for connections stabilised and abnormal resets blocked; the sidebar status also shows how many resets were blocked.
- `levi.exe`: `--profile auto|fast|hardened`, and a summary of the counters when it stops.

### Changed
- Engine: injected connection resets are now dropped at the driver level, before they reach the app's sockets.
- Engine: per-connection work runs on a fixed pool of 4–6 worker threads instead of a new thread per connection, and stopping the engine takes well under a second.

## [1.0.5] - 2026-10-30

### Added
- DNS page: an **Automatic** provider that uses whichever of Cloudflare and Google answers faster. AdGuard stays a choice of its own, since it blocks ads.
- Each DNS provider shows the transport and latency it gets on your network (for example "HTTP/2 · 35 ms"); the home page shows the latency of the DNS in use.
- If the chosen DNS provider stays unreachable for 10 seconds, another one stands in until it is back, and the app says so (with AdGuard: ads are not blocked meanwhile).
- While a DNS server is unreachable, recently visited sites keep opening from the cache.

### Changed
- "Speed up with HTTP/3" is now **Local DNS**: it tries every server address over HTTP/3 and HTTP/2 at once and keeps the fastest route, instead of always preferring IPv4 and HTTP/3.
- The DNS latency on the home page is measured with real DNS queries instead of ping.

### Fixed
- AdGuard DNS no longer stalls for a few seconds after switching to it or about once a minute, and now uses its fastest route (often IPv6 over HTTP/2).

## [1.0.4] - 2026-10-29

### Added
- AdGuard DNS as a third DNS provider, for blocking ads and trackers. The DNS page now lists Cloudflare, Google and AdGuard with their logos.
- The tray icon shows a small green arrow when a new version is out.

### Changed
- New logo colors: white wing behind, blue wing in front.
- Engine: steadier connections and lower CPU use.
- The changelog is now split into English (`CHANGELOG.md`) and Vietnamese (`CHANGELOG.vi.md`).

### Fixed
- When Yeager starts with Windows, the tray icon now lights up as soon as the taskbar is ready, instead of only after turning Yeager off and on.

## [1.0.3] - 2026-10-29

### Changed
- Diagnose also measures CTCP, alongside CUBIC and BBRv2.
- "Restore Windows defaults" also turns low-latency mode off and puts those settings back.

### Fixed
- The ISP above the status pill now shows: the lookup falls back to the AS number Cloudflare sends, retries while the network comes up, and logs why when it fails.
- The logo's rim is even on all four sides.

## [1.0.2] - 2026-10-29

### Added
- In-app updates, as in EasyKey: Yeager checks GitHub for a new release at start and every few hours, shows **↑ Update to …** in the sidebar and tray, and on **Update** downloads the new `yeager.exe`, checks its SHA-256, replaces itself and restarts. Can be turned off under General → Updates.
- Releases also carry `yeager.exe` on its own, listed in `SHA256SUMS.txt`.
- Low-latency mode (TCP page): turns off delayed ACKs and Nagle on the adapters in use and adapter power saving; everything is put back when switched off.
- Ping check on the TCP page (router, 1.1.1.1, 8.8.8.8) tells whether lag comes from the home network or the ISP; the home page shows the ping to the DNS server in use.
- The tray icon's rim lights up in the accent color while Yeager is on; the tray menu shows the engine scope, TCP algorithm and DNS in use, and follows the app's theme and language.

- The sidebar shows your ISP, looked up from Cloudflare once at start and again by Diagnose.

### Changed
- New app icon from Cino's finished artwork, sharp at every size.
- The README version badge and download link follow the latest release.

### Fixed
- The accent color is remembered across restarts.

## [1.0.1] - 2026-10-28

### Changed
- Levi engine updates (PR #12).
- The release workflow uses actions that run on Node.js 24 and can publish a release from a manual run.

## [1.0.0] - 2026-10-28

First public release.

### Added

**Levi: connection engine**
- Native Rust engine linked into `yeager.exe`; no helper processes.
- WinDivert 2.2 driver embedded and unpacked automatically; nothing extra to install.
- Scope *All* (every outgoing HTTPS connection) or *Domain list* (only listed domains and their subdomains).
- Non-blocking packet loop and large driver queues for many parallel connections and heavy traffic.
- Never touches DNS (port 53) or Yeager's own encrypted DNS connections; no fake packets.
- Starts and stops in under two seconds without leaving processes or drivers behind.
- Standalone `levi.exe` command-line build for headless use.

**Erwin: TCP tuning**
- Congestion control choice: Auto, BBRv2, CUBIC, CTCP. Auto picks from measured ping, jitter and loss.
- Diagnose: measures throughput and latency under load per algorithm and suggests the best.
- Settings are backed up before the first change and restored on disable, exit or after a crash; "Restore Windows defaults".
- Runs independently of the engine and DNS.

**Hange: encrypted DNS**
- DNS over HTTPS with Cloudflare or Google, through a local cached resolver over HTTP/3 with HTTP/2 fallback.
- Windows' built-in DoH as the backup path, never plaintext DNS.
- Adapters configured through the IP Helper API; Windows certificate store trusted.
- "Check" button and `tools/test-dns.ps1` to verify encryption and leaks.

**App**
- Vietnamese and English interface with a language switch.
- Light/dark mode, accent color, system tray, connect on launch, start with Windows.
- The engine requires encrypted DNS: enabling the engine enables DoH, disabling DoH stops the engine.

**Documentation**
- Bilingual README, design document, license, third-party notices, disclaimer, privacy, security and contributing guides.

### Fixed
- "Restore Windows defaults" on the TCP page.

[1.0.8]: https://github.com/iamcino/Yeager/releases/tag/v1.0.8
[1.0.7]: https://github.com/iamcino/Yeager/releases/tag/v1.0.7
[1.0.6]: https://github.com/iamcino/Yeager/releases/tag/v1.0.6
[1.0.5]: https://github.com/iamcino/Yeager/releases/tag/v1.0.5
[1.0.4]: https://github.com/iamcino/Yeager/releases/tag/v1.0.4
[1.0.3]: https://github.com/iamcino/Yeager/releases/tag/v1.0.3
[1.0.2]: https://github.com/iamcino/Yeager/releases/tag/v1.0.2
[1.0.1]: https://github.com/iamcino/Yeager/releases/tag/v1.0.1
[1.0.0]: https://github.com/iamcino/Yeager/releases/tag/v1.0.0

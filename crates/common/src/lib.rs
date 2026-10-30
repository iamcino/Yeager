//! Shared types for the Yeager workspace.
//!
//! Every crate talks through these types so that `app`, `levi`, `erwin` and
//! `hange` stay decoupled. See the Technical Design Document for the role of
//! each crate.

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod lang;
pub mod process;

pub use lang::Language;

/// Which connections the transport resilience engine (`levi`) acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// Every outbound TLS connection on port 443.
    #[default]
    All,
    /// Only the hosts in the user's list (split tunneling).
    HostList,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::All => lang::tr("Toàn bộ", "All"),
            Scope::HostList => lang::tr("Theo tên miền", "By domain"),
        }
    }
}

/// Transport resilience profiles for `levi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportProfile {
    /// Auto-detects network environment, defaulting to In-Order 0ms split.
    #[default]
    Auto,
    /// Fast: 3-way In-Order Multi-Split (0ms added delay, optimal for gaming & VPN tunnels).
    Fast,
    /// Hardened: Out-of-Order Multi-Split with calibrated jitter for enhanced stream stability.
    Hardened,
    /// Observe: passive, counts handshakes and injected resets without
    /// changing any packet.
    Observe,
}

impl TransportProfile {
    pub const ALL: [TransportProfile; 4] = [
        TransportProfile::Auto,
        TransportProfile::Fast,
        TransportProfile::Hardened,
        TransportProfile::Observe,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TransportProfile::Auto => lang::tr("Tự động", "Auto"),
            TransportProfile::Fast => lang::tr("Tối ưu tốc độ", "Fast"),
            TransportProfile::Hardened => lang::tr("Tăng cường", "Hardened"),
            TransportProfile::Observe => lang::tr("Giám sát", "Observe"),
        }
    }
}

/// TCP congestion controller requested by the user, applied by `erwin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Congestion {
    /// Follow the engine state automatically (see the TDD §3 Erwin).
    #[default]
    Auto,
    Bbr2,
    Cubic,
    Ctcp,
}

impl Congestion {
    pub const ALL: [Congestion; 4] = [
        Congestion::Auto,
        Congestion::Bbr2,
        Congestion::Cubic,
        Congestion::Ctcp,
    ];

    /// The netsh/PowerShell provider name, or `None` for `Auto`.
    pub fn provider(self) -> Option<&'static str> {
        match self {
            Congestion::Auto => None,
            Congestion::Bbr2 => Some("bbr2"),
            Congestion::Cubic => Some("cubic"),
            Congestion::Ctcp => Some("ctcp"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Congestion::Auto => lang::tr("Tự động", "Automatic"),
            Congestion::Bbr2 => "BBRv2",
            Congestion::Cubic => "CUBIC",
            Congestion::Ctcp => "CTCP",
        }
    }
}

/// DNS over HTTPS upstream used by `hange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DohProvider {
    #[default]
    Cloudflare,
    Google,
    /// AdGuard's default (filtering) resolver: blocks ads and trackers.
    #[serde(rename = "adguard")]
    AdGuard,
}

impl DohProvider {
    pub const ALL: [DohProvider; 3] = [DohProvider::Cloudflare, DohProvider::Google, DohProvider::AdGuard];

    pub fn label(self) -> &'static str {
        match self {
            DohProvider::Cloudflare => "Cloudflare",
            DohProvider::Google => "Google",
            DohProvider::AdGuard => "AdGuard",
        }
    }

    /// Name on the resolver's TLS certificate.
    pub fn server_name(self) -> &'static str {
        match self {
            DohProvider::Cloudflare => "cloudflare-dns.com",
            DohProvider::Google => "dns.google",
            DohProvider::AdGuard => "dns.adguard-dns.com",
        }
    }

    pub fn template(self) -> &'static str {
        match self {
            DohProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DohProvider::Google => "https://dns.google/dns-query",
            DohProvider::AdGuard => "https://dns.adguard-dns.com/dns-query",
        }
    }

    /// Resolver addresses, IPv4 first then IPv6.
    pub fn servers(self) -> &'static [&'static str] {
        match self {
            DohProvider::Cloudflare => &[
                "1.1.1.1",
                "1.0.0.1",
                "2606:4700:4700::1111",
                "2606:4700:4700::1001",
            ],
            DohProvider::Google => &[
                "8.8.8.8",
                "8.8.4.4",
                "2001:4860:4860::8888",
                "2001:4860:4860::8844",
            ],
            DohProvider::AdGuard => &[
                "94.140.14.14",
                "94.140.15.15",
                "2a10:50c0::ad1:ff",
                "2a10:50c0::ad2:ff",
            ],
        }
    }
}

/// Persistent user configuration, stored as JSON by `erwin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub scope: Scope,
    pub hosts: Vec<String>,
    pub congestion: Congestion,
    /// Erwin's TCP tuning, independent of the engine and DoH.
    pub tcp_enabled: bool,
    /// Erwin's low-latency settings (ACKs, throttling, adapter power saving).
    pub low_latency: bool,
    pub doh_enabled: bool,
    pub doh_provider: DohProvider,
    /// Let the local DNS use whichever of Cloudflare and Google answers
    /// faster, instead of `doh_provider`.
    pub doh_auto: bool,
    /// Run the local DNS (cache, HTTP/3) on port 53; off = Windows' own DoH only.
    pub doh_http3: bool,
    pub connect_on_launch: bool,
    pub launch_at_login: bool,
    pub dark: bool,
    /// Accent color as `#rrggbb`.
    pub accent: String,
    /// Look for a new release at start and every few hours.
    pub check_updates: bool,
    /// UI language; `None` until the user picks one, then follows Windows.
    pub language: Option<Language>,
    pub transport_profile: TransportProfile,
    /// Window size in logical pixels, as the user last left it.
    pub window_size: Option<[u32; 2]>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scope: Scope::default(),
            hosts: [
                "discord.com",
                "discord.gg",
                "discordapp.com",
                "discordapp.net",
                "discord.media",
            ]
            .map(String::from)
            .to_vec(),
            congestion: Congestion::default(),
            tcp_enabled: true,
            low_latency: false,
            doh_enabled: true,
            doh_provider: DohProvider::default(),
            doh_auto: false,
            doh_http3: true,
            connect_on_launch: true,
            launch_at_login: false,
            dark: true,
            accent: "#0a7aff".into(),
            check_updates: true,
            language: None,
            transport_profile: TransportProfile::default(),
            window_size: None,
        }
    }
}

/// Error shared across crates. Messages are user facing, in the
/// language of [`lang::current`] when they were made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

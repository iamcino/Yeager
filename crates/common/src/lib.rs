//! Shared types for the Yeager workspace.
//!
//! Every crate talks through these types so that `app`, `levi`, `erwin` and
//! `hange` stay decoupled. See the Technical Design Document for the role of
//! each crate.

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod domain;
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

/// Preferred window size in logical pixels (matches `app.slint`).
pub const WINDOW_PREFERRED_W: f32 = 860.0;
/// Preferred window height in logical pixels (matches `app.slint`).
pub const WINDOW_PREFERRED_H: f32 = 600.0;
/// Minimum window width in logical pixels (matches `app.slint` `min-width-px`).
pub const WINDOW_MIN_W: f32 = 700.0;
/// Minimum window height in logical pixels (matches `app.slint` `min-height-px`).
pub const WINDOW_MIN_H: f32 = 500.0;
/// Plausibility ceiling: larger persisted dimensions are treated as corrupt
/// legacy values and fall back as a pair instead of being clamped.
pub const WINDOW_MAX_W: f32 = 7680.0;
/// Plausibility ceiling for height (see [`WINDOW_MAX_W`]).
pub const WINDOW_MAX_H: f32 = 4320.0;
/// Preferred window size in logical pixels, used when no valid geometry exists.
pub const WINDOW_PREFERRED_SIZE: [u32; 2] = [860, 600];

/// Whether a logical size is a plausible, acceptable normal window geometry.
///
/// Accepts finite positive dimensions at/above the declared minimum and
/// at/below the plausibility ceiling. A deliberate stable 700x500 is valid;
/// minimum size alone is not corruption. Zero, below-minimum, non-finite and
/// implausibly huge values are invalid.
pub fn is_valid_window_size(w: f32, h: f32) -> bool {
    w.is_finite()
        && h.is_finite()
        && w >= WINDOW_MIN_W
        && h >= WINDOW_MIN_H
        && w <= WINDOW_MAX_W
        && h <= WINDOW_MAX_H
}

/// [`is_valid_window_size`] for integer config values.
pub fn is_valid_window_size_u32(w: u32, h: u32) -> bool {
    is_valid_window_size(w as f32, h as f32)
}

/// Validates a persisted geometry pair, falling back AS A PAIR to the
/// preferred 860x600 when missing/invalid/below-minimum/implausibly huge.
///
/// Never clamps garbage into a minimum-size window: `[0,0]`, `[1,1]` and other
/// corrupt legacy values all resolve to preferred, while a deliberate stable
/// `[700,500]` is preserved.
pub fn resolve_window_size(raw: Option<[u32; 2]>) -> [u32; 2] {
    match raw {
        Some([w, h]) if is_valid_window_size_u32(w, h) => [w, h],
        _ => WINDOW_PREFERRED_SIZE,
    }
}

/// Clamps otherwise-valid dimensions to the target monitor's usable logical
/// work area. When the work area itself is smaller than the UI minimum, the UI
/// minimum is honored (reachable caption/resize affordances) instead of
/// silently persisting a temporary constrained size. Invalid work-area inputs
/// leave the size unchanged.
pub fn clamp_window_size_to_work_area(w: f32, h: f32, work_w: f32, work_h: f32) -> (f32, f32) {
    if !w.is_finite() || !h.is_finite() || !work_w.is_finite() || !work_h.is_finite() {
        return (w, h);
    }
    if work_w <= 0.0 || work_h <= 0.0 {
        return (w, h);
    }
    let cw = w.min(work_w).max(WINDOW_MIN_W);
    let ch = h.min(work_h).max(WINDOW_MIN_H);
    (cw, ch)
}

/// Tolerant `window_size` deserialization: any malformed geometry field yields
/// `None` instead of failing the whole `Config`, so unrelated config survives.
/// Valid `[w,h]` arrays still deserialize normally; `[0,0]`/`[1,1]` stay
/// `Some` here and are rejected later by [`is_valid_window_size`] as a pair.
/// Parses a raw JSON geometry value into a validated pair. Consumes the whole
/// value via [`serde_json::Value`] so a malformed field never corrupts the
/// surrounding stream nor fails the whole `Config`.
fn parse_window_size_value(v: Option<serde_json::Value>) -> Option<[u32; 2]> {
    match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(items)) if items.len() == 2 => match (&items[0], &items[1]) {
            (serde_json::Value::Number(a), serde_json::Value::Number(b)) => match (a.as_u64(), b.as_u64())
            {
                (Some(w), Some(h)) if w <= u32::MAX as u64 && h <= u32::MAX as u64 => {
                    Some([w as u32, h as u32])
                }
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn de_window_size<'de, D>(d: D) -> std::result::Result<Option<[u32; 2]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Consume the full field value first so malformed geometry (negative,
    // non-numeric, wrong shape) cannot corrupt the stream; then convert
    // purely. Valid numeric pairs (including [0,0]/[1,1]) stay `Some` here
    // and are rejected later as a pair by [`is_valid_window_size`].
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(parse_window_size_value(v))
}

/// Persistent user configuration, stored as JSON by `erwin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub scope: Scope,
    /// Selected target hosts for `Scope::HostList` (alias `hosts` for backwards compatibility).
    #[serde(alias = "hosts")]
    pub selected_hosts: Vec<String>,
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
    #[serde(default, deserialize_with = "de_window_size")]
    pub window_size: Option<[u32; 2]>,
    /// Whether compatibility pass-through mode for game launchers and remote tools is enabled.
    #[serde(alias = "game_protection_enabled")]
    pub compatibility_mode_enabled: bool,
    /// User-defined domains excluded from transport resilience (raw pass-through).
    pub custom_excluded_domains: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scope: Scope::default(),
            selected_hosts: [
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
            compatibility_mode_enabled: true,
            custom_excluded_domains: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backward_compatibility_serde_aliases() {
        // BC1: v1.1.0 JSON with "game_protection_enabled" reads as compatibility_mode_enabled
        let json_v110 = r#"{"game_protection_enabled": true}"#;
        let cfg: Config = serde_json::from_str(json_v110).expect("Should deserialize v1.1.0 config");
        assert!(cfg.compatibility_mode_enabled);

        // BC2: Older JSON with "hosts" reads as selected_hosts
        let json_hosts = r#"{"hosts": ["example.com", "test.org"]}"#;
        let cfg2: Config = serde_json::from_str(json_hosts).expect("Should deserialize hosts config");
        assert_eq!(cfg2.selected_hosts, vec!["example.com".to_string(), "test.org".to_string()]);

        // BC3: Empty / missing JSON uses safe defaults
        let json_empty = "{}";
        let cfg3: Config = serde_json::from_str(json_empty).expect("Should deserialize empty config");
        assert!(cfg3.compatibility_mode_enabled);
        assert!(!cfg3.selected_hosts.is_empty());
    }

    #[test]
    fn corrupted_geometry_falls_back_as_pair_and_preserves_unrelated_config() {
        // [0,0], [1,1]: valid JSON, invalid geometry -> fallback pair.
        for raw in [Some([0, 0]), Some([1, 1]), None] {
            assert_eq!(resolve_window_size(raw), WINDOW_PREFERRED_SIZE);
        }
        // One undersized dimension also falls back as a pair (never clamps garbage).
        assert_eq!(resolve_window_size(Some([100, 600])), WINDOW_PREFERRED_SIZE);
        assert_eq!(resolve_window_size(Some([860, 100])), WINDOW_PREFERRED_SIZE);
        // Implausibly huge legacy values fall back as a pair.
        assert_eq!(resolve_window_size(Some([99999, 99999])), WINDOW_PREFERRED_SIZE);
        assert_eq!(resolve_window_size(Some([u32::MAX, u32::MAX])), WINDOW_PREFERRED_SIZE);

        // Malformed geometry must not discard unrelated config.
        let cfg: Config =
            serde_json::from_str(r#"{"window_size": [-5, 100], "dark": false}"#).expect("tolerant geometry");
        assert_eq!(cfg.window_size, None);
        assert!(!cfg.dark);
        let cfg: Config =
            serde_json::from_str(r#"{"window_size": ["a", "b"], "dark": false}"#).expect("tolerant geometry");
        assert_eq!(cfg.window_size, None);
        assert!(!cfg.dark);
        let cfg: Config =
            serde_json::from_str(r#"{"window_size": "huge", "selected_hosts": ["x.example"]}"#)
                .expect("tolerant geometry");
        assert_eq!(cfg.window_size, None);
        assert_eq!(cfg.selected_hosts, vec!["x.example".to_string()]);
        // Valid geometry still parses; unrelated fields intact.
        let cfg: Config =
            serde_json::from_str(r#"{"window_size": [900, 650], "dark": false}"#).expect("valid geometry");
        assert_eq!(cfg.window_size, Some([900, 650]));
        assert!(!cfg.dark);
    }

    #[test]
    fn deliberate_minimum_size_persists_and_restores() {
        assert!(is_valid_window_size(700.0, 500.0));
        assert!(is_valid_window_size_u32(700, 500));
        assert_eq!(resolve_window_size(Some([700, 500])), [700, 500]);
    }

    #[test]
    fn valid_normal_resize_round_trips() {
        assert!(is_valid_window_size(900.0, 650.0));
        assert_eq!(resolve_window_size(Some([900, 650])), [900, 650]);
        assert_eq!(resolve_window_size(Some([859, 671])), [859, 671]);
    }

    #[test]
    fn work_area_clamp_keeps_minimum_when_area_is_smaller() {
        // Otherwise-valid dimensions clamp to the usable work area.
        assert_eq!(clamp_window_size_to_work_area(1000.0, 800.0, 1920.0, 1080.0), (1000.0, 800.0));
        assert_eq!(clamp_window_size_to_work_area(2000.0, 1200.0, 1920.0, 1080.0), (1920.0, 1080.0));
        // Work area smaller than UI minimum: honor the minimum, don't persist
        // a temporary constrained size.
        assert_eq!(clamp_window_size_to_work_area(860.0, 600.0, 600.0, 400.0), (700.0, 500.0));
    }
}

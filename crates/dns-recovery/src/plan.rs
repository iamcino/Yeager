//! Plan → target image builder (U03, SPEC-DNS-FIX.md §5.1 plan rules).
//!
//! Plans stay source-compatible with the app's encrypted-DNS plans:
//! - Auto uses Cloudflare for the Windows fallback.
//! - Fixed providers use the `common::DohProvider` addresses/templates
//!   (mirrored here as data — this crate must not depend on `common`).
//! - Dual-family stub: local first, then the first provider address per family.
//! - IPv4-only stub: v4 = local + first v4 provider; v6 = first v6 provider
//!   (the current `encrypted_servers` behavior).
//! - No stub: both provider addresses per supported family.
//! - Public addresses carry explicit ENABLE + template, never FALLBACK_TO_UDP;
//!   loopback has no DoH property.
//!
//! Automatic restoration (§4) clears the static list AND the Yeager interface
//! properties: empty NameServer string + zero properties. It never restores
//! lease addresses or DHCP state.

use crate::backend::{base64, DNS_SETTING_IPV6};
use crate::model::{
    CanonicalServer, DesiredPlan, DohSettings, Family, Provenance, ProvenanceEvidence, Provider,
    ServerProperty, Snapshot,
};
use crate::setter::{DOH_ENABLE, DNS_SETTING_NAMESERVER};

/// Provider addresses/templates (mirror of `common::DohProvider`).
#[derive(Clone, Copy, Debug)]
pub struct ProviderSpec {
    pub template: &'static str,
    pub v4: [&'static str; 2],
    pub v6: [&'static str; 2],
}

pub fn provider_spec(provider: Provider) -> ProviderSpec {
    match provider {
        Provider::Auto | Provider::Cloudflare => ProviderSpec {
            template: "https://cloudflare-dns.com/dns-query",
            v4: ["1.1.1.1", "1.0.0.1"],
            v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        },
        Provider::Google => ProviderSpec {
            template: "https://dns.google/dns-query",
            v4: ["8.8.8.8", "8.8.4.4"],
            v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"],
        },
        Provider::Adguard => ProviderSpec {
            template: "https://dns.adguard-dns.com/dns-query",
            v4: ["94.140.14.14", "94.140.15.15"],
            v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        },
    }
}

fn utf16le_z(text: &str) -> Vec<u8> {
    let mut v: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

fn registry_path(guid: &str, family: Family) -> String {
    format!(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}\\Parameters\\Interfaces\\{guid}",
        family.registry_service()
    )
}

fn api_flags(family: Family) -> u64 {
    match family {
        Family::Ipv4 => 0,
        Family::Ipv6 => DNS_SETTING_IPV6,
    }
}

/// Build the static target image for one adapter/family under a plan. The
/// returned snapshot carries the plan's full intended property set; context
/// and capability are inherited from `before` (evidence only).
pub fn plan_image(
    guid: &str,
    family: Family,
    plan: &DesiredPlan,
    before: &Snapshot,
    captured_at_utc: &str,
) -> Snapshot {
    let spec = provider_spec(plan.provider);
    let want_v4 = family == Family::Ipv4;
    let provider_addrs: [&str; 2] = if want_v4 { spec.v4 } else { spec.v6 };

    let mut tokens: Vec<String> = Vec::new();
    if plan.local_requested {
        for e in &plan.bound_endpoints {
            if e.ip.is_ipv4() == want_v4 {
                let s = e.ip.to_string();
                if !tokens.iter().any(|t| t == &s) {
                    tokens.push(s);
                }
            }
        }
        tokens.push(provider_addrs[0].to_string());
    } else {
        tokens.push(provider_addrs[0].to_string());
        tokens.push(provider_addrs[1].to_string());
    }

    let ordered_servers: Vec<CanonicalServer> = tokens
        .iter()
        .map(|t| CanonicalServer::parse(t).expect("plan addresses are valid"))
        .collect();
    let name_server = tokens.join(",");

    let server_properties: Vec<ServerProperty> = ordered_servers
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.address.is_loopback())
        .map(|(i, _)| ServerProperty {
            version: 1,
            server_index: i as u32,
            prop_type: 1,
            doh: DohSettings {
                template: Some(spec.template.to_string()),
                flags: DOH_ENABLE,
            },
        })
        .collect();

    Snapshot {
        schema_version: 1,
        family,
        provenance: Provenance::Static,
        name_server_raw: Some(name_server.clone()),
        ordered_servers,
        provenance_evidence: ProvenanceEvidence {
            registry_path: registry_path(guid, family),
            value_exists: true,
            value_type: Some(1),
            raw_value_base64: Some(base64(&utf16le_z(&name_server))),
            api_flags: api_flags(family),
            captured_at_utc: captured_at_utc.to_string(),
        },
        server_properties,
        context: before.context.clone(),
        capability: before.capability.clone(),
    }
}

/// The automatic restoration image (§4): empty NameServer string + zero
/// properties. Clears the static list and every Yeager interface DoH property;
/// never touches lease addresses, DHCP, profiles or global tables.
pub fn automatic_image(guid: &str, before: &Snapshot, captured_at_utc: &str) -> Snapshot {
    Snapshot {
        schema_version: 1,
        family: before.family,
        provenance: Provenance::Automatic,
        name_server_raw: Some(String::new()),
        ordered_servers: Vec::new(),
        provenance_evidence: ProvenanceEvidence {
            registry_path: registry_path(guid, before.family),
            value_exists: true,
            value_type: Some(1),
            raw_value_base64: Some(base64(&[0, 0])),
            api_flags: api_flags(before.family),
            captured_at_utc: captured_at_utc.to_string(),
        },
        server_properties: Vec::new(),
        context: before.context.clone(),
        capability: before.capability.clone(),
    }
}

/// The setter mask for one family (§4): NAMESERVER|DOH always together (the
/// qualified setter is not field-atomic), plus the family selector for IPv6.
pub fn setter_mask(family: Family) -> u64 {
    let mut mask = DNS_SETTING_NAMESERVER | crate::setter::DNS_SETTING_DOH;
    if family == Family::Ipv6 {
        mask |= DNS_SETTING_IPV6;
    }
    mask
}

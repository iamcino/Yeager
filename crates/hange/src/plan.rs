//! U06: listener plans and their service-side desired plans.
//!
//! The listener follows the provider address rules the codebase already
//! uses: UDP+TCP is bound on both loopback families; a v6 bind failure
//! degrades to a v4-only plan; both families failing means Windows-only
//! mode with **no** loopback listener. No plan ever invents addresses
//! outside these rules.
//!
//! This module is pure (no sockets, no NIC writes): it classifies bind
//! outcomes and maps the bound addresses onto the U05 allowlisted
//! [`DesiredPlan`](dns_recovery::model::DesiredPlan) the service accepts
//! (loopback port 53 only, an advertised family requires UDP+TCP
//! readiness). Socket binding itself stays in [`crate::stub`] / the
//! coordinator's binder seam so every fallback is testable against fakes.

use common::DohProvider;
use dns_recovery::model::{BoundEndpoint, DesiredPlan, Provider as SvcProvider, Transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Loopback port 53, the only address the stub may serve.
pub const LOOPBACK_PORT: u16 = 53;
/// IPv4 loopback endpoint the stub binds.
pub fn v4_loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, LOOPBACK_PORT))
}
/// IPv6 loopback endpoint the stub binds.
pub fn v6_loopback() -> SocketAddr {
    SocketAddr::from((Ipv6Addr::LOCALHOST, LOOPBACK_PORT))
}

/// Which listener shape a bind outcome degrades to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerMode {
    /// UDP+TCP on both loopback families.
    Dual,
    /// UDP+TCP on IPv4 loopback only (v6 bind failed).
    V4Only,
    /// No loopback listener at all (both families failed).
    WindowsOnly,
}

/// Classify a bind attempt: each flag says whether that family's UDP+TCP
/// bind succeeded. Mirrors the existing `start_stub` fallback
/// (dual, else v4, else Windows-only).
pub fn classify_bind(v4_ok: bool, v6_ok: bool) -> ListenerMode {
    if v4_ok && v6_ok {
        ListenerMode::Dual
    } else if v4_ok {
        ListenerMode::V4Only
    } else {
        // v6 alone never serves: without v4 there is no complete plan, so a
        // v6-only bind outcome is Windows-only, never a v6-only listener.
        ListenerMode::WindowsOnly
    }
}

/// The concrete listener plan: which loopback socket addresses to serve.
/// Each address is served over UDP **and** TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerPlan {
    pub mode: ListenerMode,
    pub addrs: Vec<SocketAddr>,
}

impl ListenerPlan {
    /// Plan for `mode` using only the loopback addresses above — no other
    /// address may ever appear here.
    pub fn for_mode(mode: ListenerMode) -> Self {
        let addrs = match mode {
            ListenerMode::Dual => vec![v4_loopback(), v6_loopback()],
            ListenerMode::V4Only => vec![v4_loopback()],
            ListenerMode::WindowsOnly => Vec::new(),
        };
        Self { mode, addrs }
    }

    /// Whether this plan serves a local stub at all.
    pub fn serves_local(&self) -> bool {
        !self.addrs.is_empty()
    }
}

/// Map the GUI provider choice onto the service-side provider enum.
pub fn service_provider(choice: crate::pool::Choice) -> SvcProvider {
    match choice {
        crate::pool::Choice::Fixed(DohProvider::Cloudflare) => SvcProvider::Cloudflare,
        crate::pool::Choice::Fixed(DohProvider::Google) => SvcProvider::Google,
        crate::pool::Choice::Fixed(DohProvider::AdGuard) => SvcProvider::Adguard,
        crate::pool::Choice::Auto => SvcProvider::Auto,
    }
}

/// Expand each bound address into its UDP+TCP [`BoundEndpoint`] pair
/// (loopback port 53 only), as the U05 allowlist requires.
pub fn bound_endpoints(plan: &ListenerPlan) -> Vec<BoundEndpoint> {
    let mut out = Vec::with_capacity(plan.addrs.len() * 2);
    for addr in &plan.addrs {
        debug_assert!(addr.port() == LOOPBACK_PORT);
        debug_assert!(addr.ip().is_loopback());
        out.push(BoundEndpoint {
            ip: addr.ip(),
            port: LOOPBACK_PORT,
            transport: Transport::Udp,
        });
        out.push(BoundEndpoint {
            ip: addr.ip(),
            port: LOOPBACK_PORT,
            transport: Transport::Tcp,
        });
    }
    out
}

/// Build the service-side desired plan for `choice` + `plan`, carrying the
/// proved `readiness_generation` (0 for Windows-only: no listener proved).
/// The service refuses any plan whose readiness does not match the lease's
/// proved generation, so callers must only pass generations the health
/// path proved via a responding listener.
pub fn desired_plan(
    choice: crate::pool::Choice,
    plan: &ListenerPlan,
    readiness_generation: u64,
) -> DesiredPlan {
    DesiredPlan {
        provider: service_provider(choice),
        local_requested: plan.serves_local(),
        bound_endpoints: bound_endpoints(plan),
        readiness_generation,
    }
}

/// The local resolver references Windows is pointed at for `plan`: the
/// loopback IPs only (local stub first, provider resolvers after it).
/// Windows-only carries no references.
pub fn local_refs(plan: &ListenerPlan) -> Vec<String> {
    plan.addrs.iter().map(|a| a.ip().to_string()).collect()
}

/// Assert a plan obeys the existing provider address rules: only loopback
/// port-53 addresses, and every advertised family has both UDP and TCP.
pub fn check_plan_rules(plan: &ListenerPlan) -> Result<(), String> {
    for addr in &plan.addrs {
        if addr.port() != LOOPBACK_PORT {
            return Err(format!("non-53 listener address {addr}"));
        }
        if !addr.ip().is_loopback() {
            return Err(format!("non-loopback listener address {addr}"));
        }
    }
    let endpoints = bound_endpoints(plan);
    for family_v4 in [true, false] {
        let mut udp = false;
        let mut tcp = false;
        for e in &endpoints {
            if e.ip.is_ipv4() == family_v4 {
                match e.transport {
                    Transport::Udp => udp = true,
                    Transport::Tcp => tcp = true,
                }
            }
        }
        if (udp || tcp) && !(udp && tcp) {
            return Err(format!(
                "family v4={family_v4} lacks UDP+TCP readiness"
            ));
        }
    }
    if plan.mode == ListenerMode::WindowsOnly && !plan.addrs.is_empty() {
        return Err("windows-only plan must carry no loopback listener".into());
    }
    if plan.mode != ListenerMode::WindowsOnly && plan.addrs.is_empty() {
        return Err("serving plan must bind at least one loopback address".into());
    }
    Ok(())
}

/// Is `ip` one of the loopback addresses this module may ever plan?
pub fn is_planned_loopback(ip: &IpAddr) -> bool {
    *ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || *ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Choice;

    #[test]
    fn classify_follows_existing_fallback_rules() {
        assert_eq!(classify_bind(true, true), ListenerMode::Dual);
        assert_eq!(classify_bind(true, false), ListenerMode::V4Only);
        assert_eq!(classify_bind(false, false), ListenerMode::WindowsOnly);
        // v6 alone never serves: no v6-only listener exists.
        assert_eq!(classify_bind(false, true), ListenerMode::WindowsOnly);
    }

    #[test]
    fn dual_binds_udp_plus_tcp_on_both_families() {
        let plan = ListenerPlan::for_mode(ListenerMode::Dual);
        assert_eq!(plan.addrs, vec![v4_loopback(), v6_loopback()]);
        let eps = bound_endpoints(&plan);
        assert_eq!(eps.len(), 4);
        for (ip, transport) in [
            ("127.0.0.1", Transport::Udp),
            ("127.0.0.1", Transport::Tcp),
            ("::1", Transport::Udp),
            ("::1", Transport::Tcp),
        ] {
            assert!(
                eps.iter()
                    .any(|e| e.ip.to_string() == ip && e.port == 53 && e.transport == transport),
                "missing {ip}/{transport:?}"
            );
        }
        check_plan_rules(&plan).unwrap();
    }

    #[test]
    fn v6_failure_degrades_to_v4_only_plan() {
        let mode = classify_bind(true, false);
        let plan = ListenerPlan::for_mode(mode);
        assert_eq!(plan.mode, ListenerMode::V4Only);
        assert_eq!(plan.addrs, vec![v4_loopback()]);
        let eps = bound_endpoints(&plan);
        assert_eq!(eps.len(), 2);
        assert!(eps.iter().all(|e| e.ip.is_ipv4()));
        check_plan_rules(&plan).unwrap();
    }

    #[test]
    fn both_fail_means_windows_only_with_no_loopback() {
        let mode = classify_bind(false, false);
        let plan = ListenerPlan::for_mode(mode);
        assert_eq!(plan.mode, ListenerMode::WindowsOnly);
        assert!(plan.addrs.is_empty());
        assert!(!plan.serves_local());
        assert!(bound_endpoints(&plan).is_empty());
        assert!(local_refs(&plan).is_empty());
        check_plan_rules(&plan).unwrap();
        let desired = desired_plan(Choice::Fixed(DohProvider::Cloudflare), &plan, 0);
        assert!(!desired.local_requested);
        assert!(desired.bound_endpoints.is_empty());
    }

    #[test]
    fn desired_plans_carry_readiness_and_allowlisted_providers() {
        for (choice, provider) in [
            (Choice::Fixed(DohProvider::Cloudflare), SvcProvider::Cloudflare),
            (Choice::Fixed(DohProvider::Google), SvcProvider::Google),
            (Choice::Fixed(DohProvider::AdGuard), SvcProvider::Adguard),
            (Choice::Auto, SvcProvider::Auto),
        ] {
            let plan = ListenerPlan::for_mode(ListenerMode::Dual);
            let desired = desired_plan(choice, &plan, 7);
            assert_eq!(desired.provider, provider);
            assert!(desired.local_requested);
            assert_eq!(desired.readiness_generation, 7);
            assert_eq!(desired.bound_endpoints.len(), 4);
            dns_recovery::protocol::parse_plan(
                &serde_json::to_value(&desired).unwrap(),
            )
            .expect("every desired plan must pass the service allowlist");
        }
    }

    #[test]
    fn local_refs_match_existing_system_rules() {
        // Existing rule: stub in front lists the stub IPs first; without a
        // stub only provider resolvers are used (Windows-only plan).
        let dual = ListenerPlan::for_mode(ListenerMode::Dual);
        assert_eq!(local_refs(&dual), vec!["127.0.0.1".to_string(), "::1".to_string()]);
        for r in local_refs(&dual) {
            let ip: IpAddr = r.parse().unwrap();
            assert!(is_planned_loopback(&ip));
        }
    }
}

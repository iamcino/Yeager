//! `hange` — discovery engine.
//!
//! Hange is the "scientist" from the Technical Design Document: it resolves
//! names over an encrypted channel and points the whole system at it so that
//! plaintext DNS no longer leaks.
//!
//! U08: every mutation goes through the single process-wide [`authority`]
//! (one coordinator, one service lease, one serial worker). The pre-U08
//! direct path is gone: `system::reset` (heuristic "clear anything that
//! looks like a public resolver back to DHCP") is deleted, and no normal
//! path writes system DNS outside a service transaction. Rollback is the
//! service's restore-to-original, verified by configured readback — never
//! a heuristic clear.

mod authority;
mod coordinator;
mod plan;
mod pool;
mod service;
mod stub;
mod system;
mod upstream;

pub use authority::{global as dns_authority, owner_id as gui_owner_id, Applied, Authority, AuthorityStatus};
pub use coordinator::{
    ChoiceBinder, CoordError, Coordinator, ListenerBinder, ManagedListener, ManagedStatus, RealBinder,
    Supervision, STOP_BOUND,
};
pub use plan::{
    bound_endpoints, check_plan_rules, classify_bind, desired_plan, is_planned_loopback,
    local_refs, service_provider, v4_loopback, v6_loopback, ListenerMode, ListenerPlan,
    LOOPBACK_PORT,
};
pub use pool::{Choice, PoolStatus, AUTO_PROVIDERS};
pub use service::{DnsService, HostClient, InspectSnapshot, LeaseCreds, OwnerSnapshot, PipeClient, Registration, SvcError, SvcOutcome, SvcReport, IPC_DEADLINE, map_outcome};
pub use stub::ShutdownOutcome;
pub use system::{adapter_dns, AdapterInfo, DohProperty, FamilyDns, LegacyAdapterInfo, legacy_adapter_info, loopback_port_owners};
pub use upstream::{Stat, Transport};

use common::{DohProvider, Error, Result};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

/// Which provider Windows is pointed at for `choice`: in Auto mode the stub
/// picks, and Windows keeps Cloudflare behind it.
pub fn system_provider(choice: Choice) -> DohProvider {
    authority::system_provider(choice)
}

/// Transactional enable through the single DNS authority: prove the plan,
/// commit it through the privileged service, and only then swap it in.
/// Success is `Active` only — anything else (including a missing service)
/// is an error, never a silent no-op and never a heuristic clear.
pub fn enable(choice: Choice, local: bool) -> Result<Applied> {
    authority::global().enable(choice, local)
}

/// Serialized provider/local-mode change through the same authority.
/// Retains the pre-takeover original; a failed change restores the
/// original, never a half-mixed provider set.
pub fn change(choice: Choice, local: bool) -> Result<Applied> {
    authority::global().change(choice, local)
}

/// Transactional disable through the same authority: consults the journal
/// even with no in-memory state, restores the exact original, and stops
/// listeners only after the verified restore. Pending/conflict keeps the
/// listener and is an error — never reported as success.
pub fn disable() -> Result<AuthorityStatus> {
    authority::global().disable()
}

/// DNS-side admission close for the shutdown path (idempotent).
pub fn quiesce() -> SvcOutcome {
    authority::global().quiesce()
}

/// Restore the exact pre-takeover original through the service journal.
pub fn restore() -> Result<AuthorityStatus> {
    authority::global().restore()
}

/// Current authority state. Pending debt is reported, never hidden.
pub fn authority_status() -> AuthorityStatus {
    authority::global().status()
}

/// One supervision pass over the serving listener (spec §6 listener rows).
/// Terminal task loss closes admission and restores; with no active
/// configuration it is idle. The app drives this periodically.
pub fn supervise_tick() -> Option<Supervision> {
    authority::global().supervise_tick()
}

/// Measures `provider` with one small query per address and transport
/// (HTTP/3 only if `http3`) and returns its quickest route. Blocks for a
/// second or two; independent of what is enabled.
pub fn measure(provider: DohProvider, http3: bool) -> Option<Stat> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?
        .block_on(pool::measure(provider, http3))
}

/// Resolves `domain`'s first A record the way the system does: through the
/// running stub if there is one, otherwise straight over `provider`'s
/// encrypted upstream. Also returns the transport that carried it (`None`
/// when the serving stub carried it — the stub forwards over its own
/// fastest route, so the display layer names the stub instead).
pub fn resolve(provider: DohProvider, domain: &str) -> Result<(String, Option<Transport>)> {
    let mut query = Message::query();
    query.metadata.id = rand_id();
    query.metadata.recursion_desired = true;
    let name = Name::from_str(domain).map_err(|e| Error::new(e.to_string()))?;
    query.add_query(Query::query(name, RecordType::A));

    let via_stub = {
        let status = authority::global().status();
        if status.enabled && status.serving_local {
            status.addrs.into_iter().next()
        } else {
            None
        }
    };
    let (answer, transport) = match via_stub {
        Some(addr) => {
            let answer = ask_stub(addr, &query)?;
            if answer.metadata.response_code == ResponseCode::ServFail {
                return Err(Error::new(common::t!(
                    "DNS cục bộ không tới được {}",
                    "The local DNS could not reach {}",
                    provider.label()
                )));
            }
            (answer, None)
        }
        None => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::new(e.to_string()))?;
            let upstream = std::sync::Arc::new(upstream::Upstream::new(provider));
            let (answer, transport) = runtime
                .block_on(upstream.query(&query))
                .map_err(|e| Error::new(common::t!("Truy vấn DoH thất bại: {e}", "DoH query failed: {e}")))?;
            (answer, Some(transport))
        }
    };

    answer
        .answers
        .iter()
        .find_map(|r| match &r.data {
            RData::A(a) => Some(a.to_string()),
            _ => None,
        })
        .map(|ip| (ip, transport))
        .ok_or_else(|| {
            Error::new(common::t!(
                "Không nhận được địa chỉ IP ({})",
                "No IP address in the answer ({})",
                answer.metadata.response_code
            ))
        })
}

fn ask_stub(addr: SocketAddr, query: &Message) -> Result<Message> {
    let fail = |e: std::io::Error| Error::new(common::t!("DNS cục bộ không phản hồi: {e}", "The local DNS did not answer: {e}"));
    let socket = UdpSocket::bind(SocketAddr::new(addr.ip(), 0)).map_err(fail)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(fail)?;
    let bytes = query.to_vec().map_err(|e| Error::new(e.to_string()))?;
    socket.send_to(&bytes, addr).map_err(fail)?;
    let mut buf = [0u8; 4096];
    let len = socket.recv(&mut buf).map_err(fail)?;
    Message::from_vec(&buf[..len]).map_err(|e| Error::new(e.to_string()))
}

fn rand_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos ^ (nanos >> 16)) as u16
}

/// Checks that Windows itself, not just this app, resolves through Yeager:
/// every online adapter lists only the stub and the provider's encrypted
/// resolvers. Returns the adapters verified. Pure readback — never a
/// mutation, never a heuristic clear.
pub fn verify_system(provider: DohProvider) -> Result<Vec<String>> {
    let status = authority::global().status();
    let local: Vec<String> = if status.enabled && status.serving_local {
        status.addrs.iter().map(|a| a.ip().to_string()).collect()
    } else {
        Vec::new()
    };
    let local: Vec<&str> = local.iter().map(String::as_str).collect();
    system::verify(provider, &local)
}

/// Whether the local stub is serving for Windows (otherwise DNS goes
/// through Windows' own DoH, which uses HTTP/2).
pub fn stub_running() -> bool {
    let status = authority::global().status();
    status.enabled && status.serving_local
}

/// Whether transactional enable is in effect.
pub fn is_enabled() -> bool {
    authority::global().status().enabled
}

/// The serving provider for display, with no latency route attached (the
/// caller measures routes itself). `None` when nothing is enabled.
pub fn status() -> Option<PoolStatus> {
    let state = authority::global().status();
    if !state.enabled {
        return None;
    }
    Some(PoolStatus {
        provider: authority::global().serving_provider().unwrap_or(DohProvider::Cloudflare),
        stat: None,
        on_backup: false,
    })
}

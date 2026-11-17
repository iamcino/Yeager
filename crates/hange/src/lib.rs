//! `hange` — discovery engine.
//!
//! Hange is the "scientist" from the Technical Design Document: it resolves
//! names over an encrypted channel and points the whole system at it so that
//! plaintext DNS no longer leaks.
//!
//! The DNS mechanism is backup-state-and-restore only. Every mutation goes
//! through the single process-wide [`authority`] (one serial worker, one
//! serving listener): on enable it FIRST saves the current adapter DNS to the
//! one plain [`backup`] file, THEN points adapters at the stub; on disable,
//! exit, or crash leftover it writes the backed-up state back and deletes the
//! file. There is no recovery service, no journal, no transaction engine and
//! no replay. Every path is fail-open: a backup/restore failure degrades the
//! DNS feature only and never blocks the app, the engine, or uninstall.

mod authority;
mod backup;
mod listener;
mod plan;
mod pool;
mod stub;
mod system;
mod upstream;

pub use authority::{global as dns_authority, Applied, Authority, AuthorityStatus};
pub use listener::{BindError, ChoiceBinder, ListenerBinder, ManagedListener, Supervision, STOP_BOUND};
pub use plan::{
    check_plan_rules, classify_bind, is_planned_loopback, local_refs, v4_loopback, v6_loopback,
    ListenerMode, ListenerPlan, LOOPBACK_PORT,
};
pub use pool::{Choice, PoolStatus, AUTO_PROVIDERS};
pub use stub::ShutdownOutcome;
pub use system::{
    adapter_dns, AdapterBackup, AdapterInfo, DohProperty, FamilyBackup, FamilyDns, LegacyAdapterInfo,
    legacy_adapter_info, loopback_port_owners,
};
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

/// Enable through the single DNS controller: save a backup of the current
/// adapter DNS first (unless a leftover backup already exists), prove the
/// listener plan, then point adapters at the stub. A failure restores the
/// backup and degrades DNS only — never a silent no-op, never a heuristic
/// clear.
pub fn enable(choice: Choice, local: bool) -> Result<Applied> {
    authority::global().enable(choice, local)
}

/// Serialized provider/local-mode change through the same controller.
/// Retains the pre-takeover original; a failed change restores the original,
/// never a half-mixed provider set.
pub fn change(choice: Choice, local: bool) -> Result<Applied> {
    authority::global().change(choice, local)
}

/// Disable through the same controller: restores the exact backed-up
/// original, deletes the backup, and stops listeners only after a verified
/// restore. A restore failure keeps the backup and the listener and is
/// reported as pending debt — never success.
pub fn disable() -> Result<AuthorityStatus> {
    authority::global().disable()
}

/// Restore the backed-up original (also the crash-leftover path). With no
/// backup this is a debt-free no-op. Fail-open: a restore failure keeps the
/// backup and reports pending debt.
pub fn restore() -> Result<AuthorityStatus> {
    authority::global().restore()
}

/// Whether a leftover backup exists (a takeover is outstanding). The launch
/// path uses this to decide between restoring a crash leftover and entering
/// an enabled session.
pub fn has_leftover_backup() -> bool {
    backup::exists()
}

/// Current controller state. Pending debt is reported, never hidden.
pub fn authority_status() -> AuthorityStatus {
    authority::global().status()
}

/// One supervision pass over the serving listener. Terminal task loss
/// restores the backup and stops the listener; with no active configuration
/// it is idle. The app drives this periodically.
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
    let len = socket.recv(&mut buf).map_err(|e| Error::new(e.to_string()))?;
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

/// Whether DNS enable is in effect.
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

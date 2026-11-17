//! `hange` — discovery engine.
//!
//! Hange is the "scientist" from the Technical Design Document: it resolves
//! names over an encrypted channel and points the whole system at it so that
//! plaintext DNS no longer leaks.
//!
//! The preferred path is a local stub on `127.0.0.1:53` that answers from an
//! LRU cache and forwards over whichever route of DNS over HTTP/3 or HTTP/2
//! answers fastest, to the chosen provider or, in Auto mode, to the faster of
//! Cloudflare and Google. Each
//! adapter lists the stub first and the provider's resolvers, with Windows'
//! own DoH forced on, after it, so a dead stub degrades to Windows DoH rather
//! than plaintext. If port 53 is taken, or the stub is switched off, only
//! Windows DoH is used.

mod pool;
mod stub;
mod system;
mod upstream;

pub use pool::{Choice, PoolStatus, AUTO_PROVIDERS};
pub use upstream::{Stat, Transport};

use common::{DohProvider, Error, Result};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;
use std::sync::Arc;
use stub::Stub;
use upstream::Upstream;

/// What [`enable`] set up.
pub struct Applied {
    /// Adapters now resolving through Yeager.
    pub interfaces: Vec<String>,
    /// Whether the local HTTP/3 stub is in front (otherwise Windows DoH only).
    pub stub: bool,
}

struct Active {
    stub: Option<Stub>,
}

/// The provider Windows is pointed at for `choice`: in Auto mode the stub
/// picks, and Windows keeps Cloudflare behind it.
pub fn system_provider(choice: Choice) -> DohProvider {
    match choice {
        Choice::Fixed(p) => p,
        Choice::Auto => AUTO_PROVIDERS[0],
    }
}

/// The current setup. Holding the lock also serialises system DNS changes,
/// so a quick off→on toggle cannot finish in the wrong order.
static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

fn active() -> std::sync::MutexGuard<'static, Option<Active>> {
    ACTIVE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Starts the stub (if `local` and port 53 is free) and points every online
/// adapter at it and at the provider's encrypted resolvers.
pub fn enable(choice: Choice, local: bool) -> Result<Applied> {
    let mut active = active();
    *active = None; // stop an earlier stub first: it holds port 53

    let provider = system_provider(choice);
    let stub = if local { start_stub(choice) } else { None };
    let local: Vec<String> = stub
        .iter()
        .flat_map(|s| &s.addrs)
        .map(|a| a.ip().to_string())
        .collect();
    let local: Vec<&str> = local.iter().map(String::as_str).collect();
    let interfaces = system::apply(provider, &local).inspect_err(|_| system::reset())?;

    let applied = Applied {
        interfaces,
        stub: stub.is_some(),
    };
    *active = Some(Active { stub });
    Ok(applied)
}

/// Puts DNS back to DHCP and stops the stub. A no-op if nothing is enabled.
pub fn disable() {
    let mut active = active();
    if active.take().is_some() {
        system::reset();
    }
}

/// Clears DNS settings left behind by a run that did not shut down cleanly.
pub fn clean_up_leftovers() {
    let active = active();
    if active.is_none() {
        system::reset();
    }
}

/// Binds the loopback addresses Windows will query. IPv6 loopback is a bonus:
/// some machines have IPv6 disabled.
fn start_stub(choice: Choice) -> Option<Stub> {
    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 53));
    Stub::start(pool::Pool::new(choice), &[v4, v6])
        .or_else(|_| Stub::start(pool::Pool::new(choice), &[v4]))
        .ok()
}

/// Which provider the stub is using now, over which route. `None` without
/// the stub (Windows' own DoH resolves then).
pub fn status() -> Option<PoolStatus> {
    active().as_ref()?.stub.as_ref().map(|s| s.pool.status())
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
/// encrypted upstream. Also returns the transport that carried it.
pub fn resolve(provider: DohProvider, domain: &str) -> Result<(String, Option<Transport>)> {
    let mut query = Message::query();
    query.metadata.id = rand_id();
    query.metadata.recursion_desired = true;
    let name = Name::from_str(domain).map_err(|e| Error::new(e.to_string()))?;
    query.add_query(Query::query(name, RecordType::A));

    let via_stub = active().as_ref().and_then(|a| {
        let stub = a.stub.as_ref()?;
        Some((stub.addrs[0], stub.pool.clone()))
    });
    let (answer, transport) = match via_stub {
        Some((addr, pool)) => {
            let answer = ask_stub(addr, &query)?;
            if answer.metadata.response_code == ResponseCode::ServFail {
                if let Some(e) = pool.last_error() {
                    return Err(Error::new(common::t!(
                        "DNS cục bộ không tới được {}: {e}",
                        "The local DNS could not reach {}: {e}",
                        pool.status().provider.label()
                    )));
                }
            }
            (answer, pool.status().stat.map(|s| s.transport))
        }
        None => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::new(e.to_string()))?;
            let upstream = Arc::new(Upstream::new(provider));
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
/// resolvers. Returns the adapters verified.
pub fn verify_system(provider: DohProvider) -> Result<Vec<String>> {
    let local: Vec<String> = active()
        .as_ref()
        .and_then(|a| a.stub.as_ref())
        .map(|s| s.addrs.iter().map(|a| a.ip().to_string()).collect())
        .unwrap_or_default();
    let local: Vec<&str> = local.iter().map(String::as_str).collect();
    system::verify(provider, &local)
}

/// Whether the local stub is answering for Windows (otherwise DNS goes
/// through Windows' own DoH, which uses HTTP/2).
pub fn stub_running() -> bool {
    active().as_ref().is_some_and(|a| a.stub.is_some())
}

/// Whether [`enable`] is in effect.
pub fn is_enabled() -> bool {
    active().is_some()
}

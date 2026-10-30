//! Encrypted upstream for one provider: DNS over HTTP/3 or over HTTP/2 (TCP),
//! whichever route answers fastest.
//!
//! Resolvers are dialled by IP with the provider's certificate name, so the
//! stub never needs plaintext DNS to find its own upstream. A new connection
//! is raced over every address and both transports at once: the first answer
//! goes straight back to the caller, and of the routes that answer within a
//! moment the quickest is kept. A route that connects but never answers
//! (AdGuard's IPv6 over HTTP/3 from some networks) simply loses the race.

use common::DohProvider;
use futures_util::StreamExt;
use hickory_net::h2::HttpsClientStream;
use hickory_net::h3::H3ClientStream;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::xfer::DnsRequestSender;
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Time to set up one connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Time one query gets on a connection. Past it the connection is dropped and
/// the race runs again, instead of waiting on a dead route.
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// Budget for one query across everything; Windows gives up on a resolver
/// sooner than this anyway.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
/// After the first answer, how long the other routes get to answer too, so
/// the quickest of them can be kept.
const RACE_WINDOW: Duration = Duration::from_secs(1);
/// HTTP/3 is left out of races for this long after none of its routes
/// answered, doubling each time up to [`H3_BACKOFF_MAX`].
const H3_BACKOFF_FIRST: Duration = Duration::from_secs(2 * 60);
const H3_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
/// How often the route in use is raced again in the background, in case a
/// faster one has opened.
const RERACE_EVERY: Duration = Duration::from_secs(10 * 60);

/// Transport of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http3,
    Http2,
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Transport::Http3 => "HTTP/3",
            Transport::Http2 => "HTTP/2",
        }
    }
}

/// The route in use and how fast it answers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stat {
    pub transport: Transport,
    pub addr: SocketAddr,
    /// Smoothed time to answer a query, handshake excluded.
    pub rtt: Duration,
}

#[derive(Clone)]
enum Conn {
    H3(H3ClientStream),
    H2(HttpsClientStream),
}

impl Conn {
    async fn exchange(&self, query: &Message) -> Result<Message, String> {
        match self.clone() {
            Conn::H3(mut stream) => exchange(&mut stream, query).await,
            Conn::H2(mut stream) => exchange(&mut stream, query).await,
        }
    }
}

/// What one route of a race reports: the connection, the answer and how
/// long the answer took once connected.
type RaceResult = (Transport, SocketAddr, Result<(Conn, Message, Duration), String>);

struct Current {
    conn: Conn,
    stat: Stat,
    id: u64,
}

pub struct Upstream {
    provider: DohProvider,
    addrs: Vec<SocketAddr>,
    /// Whether HTTP/3 may be raced at all.
    http3: bool,
    current: Mutex<Option<Current>>,
    next_id: AtomicU64,
    /// One race at a time: queries that miss meanwhile wait for its route.
    racing: tokio::sync::Mutex<()>,
    h3_off_until: Mutex<Option<Instant>>,
    h3_backoff: Mutex<Duration>,
    raced_at: Mutex<Option<Instant>>,
    /// Since when no route has answered, until one does.
    failing_since: Mutex<Option<Instant>>,
    /// Why the last query failed, until one succeeds again.
    last_error: Mutex<Option<String>>,
}

impl Upstream {
    pub fn new(provider: DohProvider) -> Self {
        let addrs = provider
            .servers()
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 443))
            .collect();
        Self::with_addrs(provider, addrs)
    }

    /// Dials `addrs` instead of the provider's published resolvers.
    pub fn with_addrs(provider: DohProvider, addrs: Vec<SocketAddr>) -> Self {
        Self {
            provider,
            addrs,
            http3: true,
            current: Mutex::new(None),
            next_id: AtomicU64::new(0),
            racing: tokio::sync::Mutex::new(()),
            h3_off_until: Mutex::new(None),
            h3_backoff: Mutex::new(H3_BACKOFF_FIRST),
            raced_at: Mutex::new(None),
            failing_since: Mutex::new(None),
            last_error: Mutex::new(None),
        }
    }

    /// Races HTTP/2 only, as Windows' own DoH would use.
    pub fn without_http3(mut self) -> Self {
        self.http3 = false;
        self
    }

    pub fn provider(&self) -> DohProvider {
        self.provider
    }

    /// The route in use, if a connection is up.
    pub fn stat(&self) -> Option<Stat> {
        self.current.lock().unwrap().as_ref().map(|c| c.stat)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    /// How long no route has answered, if none is answering now.
    pub fn failing_for(&self) -> Option<Duration> {
        self.failing_since.lock().unwrap().map(|at| at.elapsed())
    }

    /// Drops the connection in use; the next query races a new one.
    pub fn close(&self) {
        *self.current.lock().unwrap() = None;
    }

    /// Sends `query` upstream and returns the answer with the client's id.
    pub async fn query(self: &Arc<Self>, query: &Message) -> Result<(Message, Transport), String> {
        let result = tokio::time::timeout(TOTAL_TIMEOUT, self.query_inner(query))
            .await
            .unwrap_or_else(|_| Err(timed_out().into()));
        match &result {
            Ok(_) => *self.failing_since.lock().unwrap() = None,
            Err(_) => {
                self.failing_since.lock().unwrap().get_or_insert_with(Instant::now);
            }
        }
        *self.last_error.lock().unwrap() = result.as_ref().err().cloned();
        result.map(|(mut answer, transport)| {
            answer.metadata.id = query.metadata.id;
            (answer, transport)
        })
    }

    async fn query_inner(self: &Arc<Self>, query: &Message) -> Result<(Message, Transport), String> {
        if let Some(answer) = self.via_current(query).await {
            return Ok(answer);
        }
        let _racing = self.racing.lock().await;
        // Another query may have raced while this one waited.
        if let Some(answer) = self.via_current(query).await {
            return Ok(answer);
        }
        self.race(query).await
    }

    /// Asks over the connection in use. `None` if there is none or it failed,
    /// in which case it is dropped.
    async fn via_current(self: &Arc<Self>, query: &Message) -> Option<(Message, Transport)> {
        let (conn, transport, id) = {
            let current = self.current.lock().unwrap();
            let c = current.as_ref()?;
            (c.conn.clone(), c.stat.transport, c.id)
        };
        let started = Instant::now();
        match tokio::time::timeout(QUERY_TIMEOUT, conn.exchange(query)).await {
            Ok(Ok(answer)) => {
                self.observe(id, started.elapsed());
                self.maybe_rerace(query);
                Some((answer, transport))
            }
            _ => {
                let mut current = self.current.lock().unwrap();
                if current.as_ref().is_some_and(|c| c.id == id) {
                    *current = None;
                }
                None
            }
        }
    }

    /// Folds one answer time into the route's smoothed time.
    fn observe(&self, id: u64, took: Duration) {
        if let Some(c) = self.current.lock().unwrap().as_mut().filter(|c| c.id == id) {
            c.stat.rtt = c.stat.rtt.mul_f64(0.8) + took.mul_f64(0.2);
        }
    }

    /// Every so often, races again in the background while the route in use
    /// keeps answering.
    fn maybe_rerace(self: &Arc<Self>, query: &Message) {
        {
            let mut raced_at = self.raced_at.lock().unwrap();
            if raced_at.is_some_and(|at| at.elapsed() < RERACE_EVERY) {
                return;
            }
            *raced_at = Some(Instant::now());
        }
        let (this, query) = (self.clone(), query.clone());
        tokio::spawn(async move {
            if let Ok(_racing) = this.racing.try_lock() {
                let _ = this.race(&query).await;
            }
        });
    }

    fn h3_allowed(&self) -> bool {
        self.http3 && self.h3_off_until.lock().unwrap().is_none_or(|at| Instant::now() >= at)
    }

    fn h3_answered(&self) {
        *self.h3_off_until.lock().unwrap() = None;
        *self.h3_backoff.lock().unwrap() = H3_BACKOFF_FIRST;
    }

    fn h3_failed(&self) {
        let mut backoff = self.h3_backoff.lock().unwrap();
        *self.h3_off_until.lock().unwrap() = Some(Instant::now() + *backoff);
        *backoff = (*backoff * 2).min(H3_BACKOFF_MAX);
    }

    /// Connects over every address and transport at once and asks `query`
    /// on each. Returns the first answer and adopts its route; the routes
    /// still racing get [`RACE_WINDOW`] more, and a quicker one replaces it.
    async fn race(self: &Arc<Self>, query: &Message) -> Result<(Message, Transport), String> {
        *self.raced_at.lock().unwrap() = Some(Instant::now());
        let mut transports = vec![Transport::Http2];
        if self.h3_allowed() {
            transports.insert(0, Transport::Http3);
        }
        let tls = hickory_net::tls::client_config().map(Arc::new).ok();
        let name: Arc<str> = self.provider.server_name().into();

        let (tx, mut rx) = mpsc::unbounded_channel();
        for &transport in &transports {
            for &addr in &self.addrs {
                let (tx, tls, name, query) = (tx.clone(), tls.clone(), name.clone(), query.clone());
                tokio::spawn(async move {
                    let attempt = async {
                        let connect = async {
                            match transport {
                                Transport::Http3 => H3ClientStream::builder()
                                    .request_timeout(QUERY_TIMEOUT)
                                    .build(addr, name, PATH.into())
                                    .await
                                    .map(Conn::H3)
                                    .map_err(|e| e.to_string()),
                                Transport::Http2 => {
                                    let tls = tls.ok_or("TLS")?;
                                    let mut builder = HttpsClientStream::builder(tls, TokioRuntimeProvider::new());
                                    builder.request_timeout(QUERY_TIMEOUT);
                                    builder
                                        .build(addr, name, PATH.into())
                                        .await
                                        .map(Conn::H2)
                                        .map_err(|e| e.to_string())
                                }
                            }
                        };
                        let conn = tokio::time::timeout(CONNECT_TIMEOUT, connect)
                            .await
                            .map_err(|_| timed_out().to_string())??;
                        let started = Instant::now();
                        let answer = tokio::time::timeout(QUERY_TIMEOUT, conn.exchange(&query))
                            .await
                            .map_err(|_| timed_out().to_string())??;
                        Ok::<_, String>((conn, answer, started.elapsed()))
                    };
                    let _ = tx.send((transport, addr, attempt.await));
                });
            }
        }
        drop(tx);

        let h3_raced = transports.contains(&Transport::Http3);
        let mut errors = Vec::new();
        while let Some((transport, addr, result)) = rx.recv().await {
            match result {
                Ok((conn, answer, took)) => {
                    let id = self.adopt(conn, transport, addr, took);
                    let this = self.clone();
                    tokio::spawn(async move {
                        this.settle(rx, id, took, h3_raced, transport == Transport::Http3).await;
                    });
                    return Ok((answer, transport));
                }
                Err(e) => errors.push(format!("{} {addr}: {e}", transport.label())),
            }
        }
        if h3_raced {
            self.h3_failed();
        }
        Err(errors.join("; "))
    }

    fn adopt(&self, conn: Conn, transport: Transport, addr: SocketAddr, took: Duration) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let stat = Stat { transport, addr, rtt: took };
        *self.current.lock().unwrap() = Some(Current { conn, stat, id });
        id
    }

    /// Lets the routes still racing answer for [`RACE_WINDOW`] and keeps the
    /// quickest, unless the route adopted as `adopted` was replaced meanwhile.
    async fn settle(
        &self,
        mut rx: mpsc::UnboundedReceiver<RaceResult>,
        adopted: u64,
        adopted_took: Duration,
        h3_raced: bool,
        mut h3_answered: bool,
    ) {
        let deadline = tokio::time::Instant::now() + RACE_WINDOW;
        let mut best: Option<(Conn, Transport, SocketAddr, Duration)> = None;
        while let Ok(Some((transport, addr, result))) = tokio::time::timeout_at(deadline, rx.recv()).await {
            let Ok((conn, _, took)) = result else { continue };
            h3_answered |= transport == Transport::Http3;
            if took < best.as_ref().map_or(adopted_took, |b| b.3) {
                best = Some((conn, transport, addr, took));
            }
        }
        if h3_raced {
            if h3_answered {
                self.h3_answered();
            } else {
                self.h3_failed();
            }
        }
        if let Some((conn, transport, addr, took)) = best {
            let mut current = self.current.lock().unwrap();
            if let Some(c) = current.as_mut().filter(|c| c.id == adopted) {
                c.conn = conn;
                c.stat = Stat { transport, addr, rtt: took };
            }
        }
    }
}

const PATH: &str = "/dns-query";

async fn exchange(stream: &mut impl DnsRequestSender, query: &Message) -> Result<Message, String> {
    let request = DnsRequest::new(query.clone(), DnsRequestOptions::default());
    let response = tokio::time::timeout(QUERY_TIMEOUT, stream.send_message(request).next())
        .await
        .map_err(|_| timed_out().to_string())?
        .ok_or(common::lang::tr("không có phản hồi", "no answer"))?
        .map_err(|e| e.to_string())?;
    Ok(response.into_message())
}

fn timed_out() -> &'static str {
    common::lang::tr("hết thời gian chờ", "timed out")
}

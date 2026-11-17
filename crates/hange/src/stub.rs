//! Local DNS stub: listens on loopback port 53 (UDP and TCP), answers from an
//! LRU cache, and forwards misses over the encrypted upstreams in a [`Pool`].
//!
//! When the upstream is slow or down, an answer that has just expired is
//! served instead (RFC 8767) and refreshed in the background, so sites the
//! user has visited keep opening through a short outage.

use crate::pool::Pool;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use lru::LruCache;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

const CACHE_SIZE: usize = 4096;
/// Never keep an answer longer than this, whatever its TTL says.
const MAX_TTL: u32 = 86_400;
/// Positive answers are cached at least this long, so names with very short
/// TTLs (5–10 s) are not asked upstream over and over. Clients still see the
/// original TTL counted down.
const MIN_TTL: u32 = 60;
/// TTL for negative answers that carry no SOA.
const NEGATIVE_TTL: u32 = 60;
/// How long past its TTL an answer may still be served when the upstream
/// cannot answer (RFC 8767 suggests one to three days).
const MAX_STALE: u32 = 86_400;
/// TTL given to a stale answer, so the client asks again soon.
const STALE_TTL: u32 = 30;
/// With a stale answer at hand, how long the upstream gets before it is used.
const STALE_AFTER: Duration = Duration::from_millis(1500);

/// A running stub. Dropping it stops the listeners.
pub struct Stub {
    pub pool: Arc<Pool>,
    pub addrs: Vec<SocketAddr>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Stub {
    /// Binds every address in `addrs` (port 0 picks a free port) and serves
    /// them on a background runtime. Fails if any address cannot be bound.
    pub fn start(pool: Pool, addrs: &[SocketAddr]) -> io::Result<Stub> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("hange-stub")
            .enable_all()
            .build()?;
        let pool = Arc::new(pool);
        let cache = Arc::new(Cache::new(CACHE_SIZE));

        let mut bound = Vec::new();
        let mut sockets = Vec::new();
        for &addr in addrs {
            let (udp, tcp) = runtime.block_on(async {
                let udp = UdpSocket::bind(addr).await?;
                let tcp = TcpListener::bind(udp.local_addr()?).await?;
                Ok::<_, io::Error>((udp, tcp))
            })?;
            bound.push(udp.local_addr()?);
            sockets.push((udp, tcp));
        }

        let (stop, stopped) = oneshot::channel::<()>();
        let served = pool.clone();
        let thread = std::thread::Builder::new()
            .name("hange-stub".into())
            .spawn(move || {
                runtime.block_on(async move {
                    tokio::spawn(served.clone().keep_warm());
                    for (udp, tcp) in sockets {
                        tokio::spawn(serve_udp(Arc::new(udp), served.clone(), cache.clone()));
                        tokio::spawn(serve_tcp(tcp, served.clone(), cache.clone()));
                    }
                    let _ = stopped.await;
                });
                runtime.shutdown_timeout(Duration::from_millis(200));
            })?;

        Ok(Stub {
            pool,
            addrs: bound,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn serve_udp(socket: Arc<UdpSocket>, pool: Arc<Pool>, cache: Arc<Cache>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let packet = buf[..len].to_vec();
        let (socket, pool, cache) = (socket.clone(), pool.clone(), cache.clone());
        tokio::spawn(async move {
            if let Some(reply) = handle(&packet, &pool, &cache, true).await {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

async fn serve_tcp(listener: TcpListener, pool: Arc<Pool>, cache: Arc<Cache>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let (pool, cache) = (pool.clone(), cache.clone());
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                serve_tcp_conn(stream, &pool, &cache),
            )
            .await;
        });
    }
}

async fn serve_tcp_conn(
    mut stream: TcpStream,
    pool: &Arc<Pool>,
    cache: &Arc<Cache>,
) -> io::Result<()> {
    loop {
        let len = stream.read_u16().await? as usize;
        let mut packet = vec![0u8; len];
        stream.read_exact(&mut packet).await?;
        let Some(reply) = handle(&packet, pool, cache, false).await else {
            return Ok(());
        };
        stream.write_u16(reply.len() as u16).await?;
        stream.write_all(&reply).await?;
    }
}

/// Answers one wire-format query. `None` drops packets that are not queries.
async fn handle(packet: &[u8], pool: &Arc<Pool>, cache: &Arc<Cache>, udp: bool) -> Option<Vec<u8>> {
    let query = Message::from_vec(packet).ok()?;
    if query.metadata.message_type != MessageType::Query {
        return None;
    }
    let key = CacheKey::of(&query);
    let answer = match key.as_ref().and_then(|k| cache.get(k)) {
        Some(mut cached) => {
            cached.metadata.id = query.metadata.id;
            cached
        }
        None => {
            let stale = key.as_ref().and_then(|k| cache.get_stale(k));
            // Spawned so that, if the stale answer goes out first, the query
            // still finishes and refreshes the cache.
            let ask = {
                let (pool, cache, query) = (pool.clone(), cache.clone(), query.clone());
                tokio::spawn(async move {
                    let result = pool.query(&query).await;
                    if let (Ok((answer, _)), Some(key)) = (&result, key) {
                        cache.put(key, answer);
                    }
                    result
                })
            };
            let result = match stale {
                Some(_) => tokio::time::timeout(STALE_AFTER, ask).await.ok(),
                None => Some(ask.await),
            };
            match (result, stale) {
                (Some(Ok(Ok((answer, _)))), _) => answer,
                (_, Some(mut stale)) => {
                    stale.metadata.id = query.metadata.id;
                    stale
                }
                _ => {
                    let mut fail = Message::error_msg(
                        query.metadata.id,
                        query.metadata.op_code,
                        ResponseCode::ServFail,
                    );
                    fail.queries = query.queries.clone();
                    fail
                }
            }
        }
    };
    let mut bytes = answer.to_vec().ok()?;
    if udp && bytes.len() > query.max_payload() as usize {
        // Tell the client to retry over TCP.
        bytes = answer.truncate().to_vec().ok()?;
    }
    Some(bytes)
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: Name,
    record_type: RecordType,
    class: DNSClass,
    dnssec_ok: bool,
}

impl CacheKey {
    /// Only plain single-question queries are cached.
    fn of(query: &Message) -> Option<CacheKey> {
        let [q] = query.queries.as_slice() else {
            return None;
        };
        Some(CacheKey {
            name: q.name.to_lowercase(),
            record_type: q.query_type,
            class: q.query_class,
            dnssec_ok: query.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
        })
    }
}

struct Entry {
    answer: Message,
    stored: Instant,
    ttl: u32,
}

struct Cache(Mutex<LruCache<CacheKey, Entry>>);

impl Cache {
    fn new(size: usize) -> Self {
        Cache(Mutex::new(LruCache::new(NonZeroUsize::new(size).unwrap())))
    }

    /// The cached answer with every TTL counted down by its age. Expired
    /// entries stay (for [`Cache::get_stale`]) until the LRU drops them.
    fn get(&self, key: &CacheKey) -> Option<Message> {
        let mut cache = self.0.lock().unwrap();
        let entry = cache.get(key)?;
        let age = entry.stored.elapsed().as_secs().min(u32::MAX as u64) as u32;
        if age >= entry.ttl {
            return None;
        }
        Some(with_ttl(&entry.answer, |ttl| ttl.saturating_sub(age).max(1)))
    }

    /// An expired answer still within [`MAX_STALE`], with a short TTL.
    fn get_stale(&self, key: &CacheKey) -> Option<Message> {
        let mut cache = self.0.lock().unwrap();
        let entry = cache.get(key)?;
        let age = entry.stored.elapsed().as_secs().min(u32::MAX as u64) as u32;
        if age > entry.ttl.saturating_add(MAX_STALE) {
            cache.pop(key);
            return None;
        }
        Some(with_ttl(&entry.answer, |_| STALE_TTL))
    }

    fn put(&self, key: CacheKey, answer: &Message) {
        let Some(ttl) = cache_ttl(answer) else { return };
        self.0.lock().unwrap().put(
            key,
            Entry {
                answer: answer.clone(),
                stored: Instant::now(),
                ttl,
            },
        );
    }
}

/// `answer` with every record's TTL mapped by `ttl`.
fn with_ttl(answer: &Message, ttl: impl Fn(u32) -> u32) -> Message {
    let mut answer = answer.clone();
    for record in answer
        .answers
        .iter_mut()
        .chain(&mut answer.authorities)
        .chain(&mut answer.additionals)
    {
        record.ttl = ttl(record.ttl);
    }
    answer
}

/// How long `answer` may be cached: the lowest record TTL for a positive
/// answer, the SOA minimum for a negative one. `None` means don't cache.
fn cache_ttl(answer: &Message) -> Option<u32> {
    if answer.metadata.truncation {
        return None;
    }
    let records = answer.answers.iter().chain(&answer.authorities);
    let ttl = match answer.metadata.response_code {
        // A TTL of 0 means "do not cache" and is left alone.
        ResponseCode::NoError if !answer.answers.is_empty() => match records.map(|r| r.ttl).min()? {
            0 => 0,
            ttl => ttl.max(MIN_TTL),
        },
        ResponseCode::NoError | ResponseCode::NXDomain => answer
            .authorities
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(NEGATIVE_TTL),
        _ => return None,
    };
    (ttl > 0).then_some(ttl.min(MAX_TTL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::Upstream;
    use common::DohProvider;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::{rdata::A, RData, Record};
    use std::str::FromStr;

    fn query(name: &str) -> Message {
        let mut q = Message::query();
        q.metadata.id = 42;
        q.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        q
    }

    fn answer(name: &str, ttl: u32) -> Message {
        let mut a = Message::response(7, OpCode::Query);
        a.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        a.answers.push(Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(A::new(1, 2, 3, 4)),
        ));
        a
    }

    /// Listener plumbing over UDP and TCP, with an upstream that refuses:
    /// the client gets SERVFAIL for its own id and question, quickly.
    #[test]
    fn unreachable_upstream_answers_servfail() {
        let dead = || {
            Arc::new(Upstream::with_addrs(
                DohProvider::Cloudflare,
                vec!["127.0.0.1:1".parse().unwrap()],
            ))
        };
        let pool = Pool::from_upstreams([dead(), dead()], false);
        let stub = Stub::start(pool, &["127.0.0.1:0".parse().unwrap()]).unwrap();
        let addr = stub.addrs[0];
        let q = query("discord.com.");
        let bytes = q.to_vec().unwrap();

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        udp.send_to(&bytes, addr).unwrap();
        let mut buf = [0u8; 512];
        let len = udp.recv(&mut buf).unwrap();
        let reply = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!(reply.metadata.id, 42);
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(reply.queries, q.queries);

        use std::io::{Read, Write};
        let mut tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.write_all(&(bytes.len() as u16).to_be_bytes()).unwrap();
        tcp.write_all(&bytes).unwrap();
        let mut len = [0u8; 2];
        tcp.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        tcp.read_exact(&mut reply).unwrap();
        assert_eq!(
            Message::from_vec(&reply).unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
    }

    #[test]
    fn cache_key_ignores_case_and_id() {
        let a = CacheKey::of(&query("Discord.COM.")).unwrap();
        let mut other = query("discord.com.");
        other.metadata.id = 9;
        assert!(a == CacheKey::of(&other).unwrap());
    }

    #[test]
    fn cache_returns_answer_until_ttl() {
        let cache = Cache::new(8);
        let key = CacheKey::of(&query("discord.com.")).unwrap();
        cache.put(key.clone(), &answer("discord.com.", 300));
        let hit = cache.get(&key).unwrap();
        assert_eq!(hit.answers[0].ttl, 300);

        let zero = CacheKey::of(&query("zero.example.")).unwrap();
        cache.put(zero.clone(), &answer("zero.example.", 0));
        assert!(cache.get(&zero).is_none());
    }

    #[test]
    fn expired_answer_is_served_stale() {
        let cache = Cache::new(8);
        let key = CacheKey::of(&query("discord.com.")).unwrap();
        cache.0.lock().unwrap().put(
            key.clone(),
            Entry {
                answer: answer("discord.com.", 60),
                stored: Instant::now() - Duration::from_secs(120),
                ttl: 60,
            },
        );
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.get_stale(&key).unwrap().answers[0].ttl, STALE_TTL);
    }

    #[test]
    fn negative_and_failed_answers() {
        let mut nx = Message::response(1, OpCode::Query);
        nx.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(cache_ttl(&nx), Some(NEGATIVE_TTL));

        let mut fail = Message::response(1, OpCode::Query);
        fail.metadata.response_code = ResponseCode::ServFail;
        assert_eq!(cache_ttl(&fail), None);

        assert_eq!(
            cache_ttl(&answer("big.example.", 10 * MAX_TTL)),
            Some(MAX_TTL)
        );
        assert_eq!(cache_ttl(&answer("short.example.", 5)), Some(MIN_TTL));
    }
}

//! Measuring the link so Erwin can pick a congestion controller: ICMP pings
//! for latency, jitter and loss, and a timed HTTPS download for throughput.

use common::{Error, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Anycast resolvers with nearby points of presence, used as ping targets.
pub const PING_TARGETS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];

const SPEED_HOST: &str = "speed.cloudflare.com";

/// Round-trip times of the echoes that came back, out of `sent`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkStats {
    pub sent: u32,
    pub rtts: Vec<u32>,
}

impl LinkStats {
    pub fn merge(mut self, other: LinkStats) -> LinkStats {
        self.sent += other.sent;
        self.rtts.extend(other.rtts);
        self
    }

    /// Share of echoes lost, 0.0–1.0.
    pub fn loss(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        1.0 - self.rtts.len() as f64 / self.sent as f64
    }

    pub fn median_ms(&self) -> Option<u32> {
        let mut v = self.rtts.clone();
        v.sort_unstable();
        v.get(v.len() / 2).copied()
    }

    /// Mean difference between consecutive round trips, in ms.
    pub fn jitter_ms(&self) -> Option<f64> {
        if self.rtts.len() < 2 {
            return None;
        }
        let sum: u32 = self.rtts.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
        Some(sum as f64 / (self.rtts.len() - 1) as f64)
    }
}

/// Pings `target` every `interval` until `count` echoes are sent or `stop` is
/// set, whichever comes first.
pub fn ping(target: Ipv4Addr, count: u32, interval: Duration, stop: &AtomicBool) -> Result<LinkStats> {
    let pinger = Pinger::new()?;
    let mut stats = LinkStats::default();
    while stats.sent < count && !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        stats.sent += 1;
        if let Some(rtt) = pinger.echo(target, 1000) {
            stats.rtts.push(rtt);
        }
        if let Some(rest) = interval.checked_sub(started.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    Ok(stats)
}

/// Pings every target in parallel, `count` echoes each.
pub fn ping_all(count: u32, interval: Duration) -> Result<LinkStats> {
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let handles: Vec<_> = PING_TARGETS
            .iter()
            .map(|&t| {
                let stop = &stop;
                s.spawn(move || ping(t, count, interval, stop))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| Err(Error::new(common::lang::tr("ping lỗi", "ping failed")))))
            .try_fold(LinkStats::default(), |acc, r| Ok(acc.merge(r?)))
    })
}

/// Bytes received and how long the body took.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Download {
    pub bytes: u64,
    pub elapsed: Duration,
}

impl Download {
    pub fn mbps(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.bytes as f64 * 8.0 / secs / 1_000_000.0
    }
}

/// Downloads up to `bytes` from Cloudflare's speed test on a fresh connection
/// (so it uses the congestion controller in force now), stopping after
/// `max_time`.
pub fn download(bytes: u64, max_time: Duration) -> Result<Download> {
    let err = |e: &dyn std::fmt::Display| Error::new(common::t!("Không tải thử được: {e}", "Test download failed: {e}"));
    let (mut conn, mut sock) = connect().map_err(|e| err(&e))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let request = format!(
        "GET /__down?bytes={bytes} HTTP/1.1\r\nHost: {SPEED_HOST}\r\nUser-Agent: Yeager\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).map_err(|e| err(&e))?;

    let mut buf = vec![0u8; 64 * 1024];
    let mut received = 0u64;
    let mut started: Option<Instant> = None;
    loop {
        let n = match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // Cloudflare closes without close_notify once the body is sent.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(err(&e)),
        };
        // Time the body only, not the TCP and TLS handshakes.
        let start = *started.get_or_insert_with(Instant::now);
        received += n as u64;
        if start.elapsed() >= max_time {
            break;
        }
    }
    let elapsed = started.map(|s| s.elapsed()).unwrap_or_default();
    if received < 64 * 1024 {
        return Err(err(&common::lang::tr("máy chủ không trả dữ liệu", "the server sent no data")));
    }
    Ok(Download { bytes: received, elapsed })
}

/// A fresh TLS connection to the speed-test host, trusting the Windows
/// certificate store (so it works behind antivirus TLS scanning).
fn connect() -> Result<(rustls::ClientConnection, TcpStream)> {
    connect_over(None)
}

/// Like [`connect`], over IPv6 if `Some(true)` and IPv4 if `Some(false)`.
fn connect_over(ipv6: Option<bool>) -> Result<(rustls::ClientConnection, TcpStream)> {
    let err = |e: &dyn std::fmt::Display| Error::new(e.to_string());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| err(&e))?;
    let config = rustls_platform_verifier::BuilderVerifierExt::with_platform_verifier(config)
        .map_err(|e| err(&e))?
        .with_no_client_auth();
    let name = SPEED_HOST.try_into().map_err(|e| err(&e))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| err(&e))?;

    let addr = (SPEED_HOST, 443)
        .to_socket_addrs()
        .map_err(|e| err(&e))?
        .find(|a| ipv6.is_none_or(|v6| a.is_ipv6() == v6))
        .ok_or_else(|| err(&common::lang::tr("không phân giải được tên miền", "could not resolve the host")))?;
    let sock = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| err(&e))?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| err(&e))?;
    Ok((conn, sock))
}

/// The network the connection comes from, as Cloudflare sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Isp {
    pub asn: u32,
    /// The organisation that owns the address block, e.g. "VNPT Corp".
    pub organization: String,
    /// Cloudflare's data centre that answered, e.g. "HKG".
    pub colo: String,
}

impl Isp {
    /// A short, familiar name: "VNPT", "Viettel", "FPT Telecom"…
    pub fn name(&self) -> String {
        if let Some(name) = name_for_asn(self.asn) {
            return name.to_string();
        }
        if !self.organization.is_empty() {
            return short_isp_name(&self.organization);
        }
        format!("AS{}", self.asn)
    }
}

/// Asks Cloudflare's speed test which network this connection comes from.
/// `/meta` names the AS and its organisation; if it does not answer, the AS
/// number the download endpoint puts in its `cf-meta-asn` header is used and
/// named from a short table. Through a VPN this is the VPN's network.
pub fn isp() -> Result<Isp> {
    let err = |e: &dyn std::fmt::Display| Error::new(common::t!("Không xác định được nhà mạng: {e}", "Could not detect the ISP: {e}"));
    let meta = get("/meta");
    if let Some(isp) = meta
        .as_ref()
        .ok()
        .filter(|m| m.status == 200)
        .and_then(|m| parse_meta(&String::from_utf8_lossy(&m.body)))
    {
        return Ok(isp);
    }
    let down = get("/__down?bytes=0").map_err(|e| err(&e))?;
    let header = |name: &str| {
        down.headers.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
        })
    };
    let asn = header("cf-meta-asn").and_then(|a| a.parse().ok()).filter(|&a| a > 0);
    match asn {
        Some(asn) => Ok(Isp {
            asn,
            organization: String::new(),
            colo: header("cf-meta-colo").unwrap_or_default(),
        }),
        None => Err(err(&match meta {
            Ok(m) => format!("HTTP {}", m.status),
            Err(e) => e.to_string(),
        })),
    }
}

struct Response {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

/// The address this PC uses on the Internet over IPv4 or IPv6, as Cloudflare
/// sees it. Fails when there is no route over that family.
pub fn public_ip(ipv6: bool) -> Result<IpAddr> {
    let meta = get_over("/meta", Some(ipv6))?;
    let v: serde_json::Value = serde_json::from_slice(&meta.body).map_err(|e| Error::new(e.to_string()))?;
    v.get("clientIp")
        .and_then(|ip| ip.as_str()?.parse().ok())
        .ok_or_else(|| Error::new(format!("HTTP {}", meta.status)))
}

/// The local address Windows picks for traffic to the Internet over IPv4 or
/// IPv6, or `None` without such a route. Nothing is sent: connecting a UDP
/// socket only selects the route.
pub fn local_ip(ipv6: bool) -> Option<IpAddr> {
    let (bind, target): (SocketAddr, SocketAddr) = if ipv6 {
        ((Ipv6Addr::UNSPECIFIED, 0).into(), (Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), 53).into())
    } else {
        ((Ipv4Addr::UNSPECIFIED, 0).into(), (PING_TARGETS[0], 53).into())
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(target).ok()?;
    Some(sock.local_addr().ok()?.ip()).filter(|ip| !ip.is_unspecified())
}

/// A small GET to the speed-test host over a fresh connection.
fn get(path: &str) -> Result<Response> {
    get_over(path, None)
}

fn get_over(path: &str, ipv6: Option<bool>) -> Result<Response> {
    let err = |e: &dyn std::fmt::Display| Error::new(e.to_string());
    let (mut conn, mut sock) = connect_over(ipv6)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {SPEED_HOST}\r\nUser-Agent: Yeager\r\nAccept: */*\r\nReferer: https://{SPEED_HOST}/\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).map_err(|e| err(&e))?;
    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw) {
        Ok(_) => {}
        // Cloudflare closes without close_notify once the body is sent.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(err(&e)),
    }
    parse_response(&raw).ok_or_else(|| err(&common::lang::tr("phản hồi không hợp lệ", "invalid response")))
}

fn parse_response(raw: &[u8]) -> Option<Response> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = headers.split_whitespace().nth(1)?.parse().ok()?;
    let mut body = raw[split + 4..].to_vec();
    let chunked = headers.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"))
    });
    if chunked {
        body = dechunk(&body)?;
    }
    Some(Response { status, headers, body })
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(data.get(..size)?);
        data = data.get(size + 2..)?;
    }
}

fn parse_meta(body: &str) -> Option<Isp> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let organization = v.get("asOrganization").and_then(|o| o.as_str()).unwrap_or("").trim().to_string();
    let asn = v.get("asn").and_then(|a| a.as_u64()).unwrap_or(0) as u32;
    if organization.is_empty() && asn == 0 {
        return None;
    }
    // `colo` is a plain code ("HKG") or an object with it under `iata`.
    let colo = v.get("colo").map(|c| c.get("iata").unwrap_or(c)).and_then(|c| c.as_str()).unwrap_or("");
    Some(Isp { asn, organization, colo: colo.to_string() })
}

/// Vietnamese networks by AS number, for when only the number is known.
fn name_for_asn(asn: u32) -> Option<&'static str> {
    Some(match asn {
        45899 | 7643 => "VNPT",
        7552 | 24086 => "Viettel",
        18403 => "FPT Telecom",
        45903 => "CMC Telecom",
        _ => return None,
    })
}

/// Vietnamese networks by the names people know them by; anything else keeps
/// its registered name without the company suffix.
fn short_isp_name(organization: &str) -> String {
    let upper = organization.to_ascii_uppercase();
    const KNOWN: [(&str, &str); 9] = [
        ("VNPT", "VNPT"),
        ("POSTS AND TELECOMMUNICATIONS", "VNPT"),
        ("VIETTEL", "Viettel"),
        ("FPT", "FPT Telecom"),
        ("CMC", "CMC Telecom"),
        ("MOBIFONE", "MobiFone"),
        ("VIETNAMOBILE", "Vietnamobile"),
        ("SCTV", "SCTV"),
        ("NETNAM", "NetNam"),
    ];
    if let Some((_, name)) = KNOWN.iter().find(|(key, _)| upper.contains(key)) {
        return name.to_string();
    }
    let mut name = organization.trim().trim_end_matches(['.', ',']).to_string();
    for suffix in [" Corporation", " Corp", " Group", " JSC", " Company", " Co", " Limited", " Ltd", " Inc", " LLC"] {
        if name.len() > suffix.len() && name.to_ascii_lowercase().ends_with(&suffix.to_ascii_lowercase()) {
            name.truncate(name.len() - suffix.len());
            name = name.trim().trim_end_matches(['.', ',']).to_string();
        }
    }
    name
}

#[cfg(windows)]
struct Pinger(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Pinger {
    fn new() -> Result<Self> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::NetworkManagement::IpHelper::IcmpCreateFile;
        // SAFETY: plain call; the handle is closed in Drop.
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error::new(common::lang::tr("Không mở được ICMP.", "Could not open ICMP.")));
        }
        Ok(Self(handle))
    }

    /// One echo; the round trip in ms, or `None` if it timed out or failed.
    fn echo(&self, target: Ipv4Addr, timeout_ms: u32) -> Option<u32> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{IcmpSendEcho, ICMP_ECHO_REPLY};
        const PAYLOAD: [u8; 32] = *b"yeager-erwin-probe-yeager-erwin!";
        let mut reply = [0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8];
        // SAFETY: the buffers outlive the call and their sizes are passed in.
        let n = unsafe {
            IcmpSendEcho(
                self.0,
                u32::from_ne_bytes(target.octets()),
                PAYLOAD.as_ptr().cast(),
                PAYLOAD.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout_ms,
            )
        };
        if n == 0 {
            return None;
        }
        // SAFETY: a non-zero return means the buffer starts with a reply.
        let reply = unsafe { std::ptr::read_unaligned(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
        (reply.Status == 0).then_some(reply.RoundTripTime)
    }
}

#[cfg(windows)]
impl Drop for Pinger {
    fn drop(&mut self) {
        // SAFETY: the handle came from IcmpCreateFile.
        unsafe { windows_sys::Win32::NetworkManagement::IpHelper::IcmpCloseHandle(self.0) };
    }
}

#[cfg(not(windows))]
struct Pinger;

#[cfg(not(windows))]
impl Pinger {
    fn new() -> Result<Self> {
        Err(Error::new(common::lang::tr("Đo ping chỉ có trên Windows.", "Ping is Windows only.")))
    }

    fn echo(&self, _target: Ipv4Addr, _timeout_ms: u32) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_stats() {
        let s = LinkStats { sent: 10, rtts: vec![20, 30, 20, 40, 20, 20, 20, 20] };
        assert!((s.loss() - 0.2).abs() < 1e-9);
        assert_eq!(s.median_ms(), Some(20));
        assert_eq!(s.jitter_ms(), Some(60.0 / 7.0));
        assert_eq!(LinkStats::default().median_ms(), None);
        assert_eq!(LinkStats::default().loss(), 0.0);
    }

    #[test]
    fn reads_meta() {
        let body = r#"{"hostname":"speed.cloudflare.com","clientIp":"203.0.113.7","asn":45899,"asOrganization":"VNPT Corp","colo":"HKG","country":"VN"}"#;
        let isp = parse_meta(body).unwrap();
        assert_eq!((isp.asn, isp.colo.as_str(), isp.name().as_str()), (45899, "HKG", "VNPT"));
        assert_eq!(parse_meta(r#"{"asn":45899}"#).unwrap().name(), "VNPT");
        // As speed.cloudflare.com answers today.
        let body = r#"{"hostname":"speed.cloudflare.com","httpProtocol":"HTTP/1.1","asn":45899,"asOrganization":"Vietnam Posts and Telecommunications Group","country":"VN","colo":{"iata":"HKG","lat":22.308901,"lon":113.915001,"cca2":"HK"}}"#;
        let isp = parse_meta(body).unwrap();
        assert_eq!((isp.asn, isp.colo.as_str(), isp.name().as_str()), (45899, "HKG", "VNPT"));
        assert_eq!(parse_meta(r#"{"asn":64500}"#).unwrap().name(), "AS64500");
        assert_eq!(parse_meta("{}"), None);
        assert_eq!(parse_meta("not json"), None);
    }

    #[test]
    fn reads_responses() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncf-meta-asn: 7552\r\n\r\n{}";
        let r = parse_response(plain).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"{}"[..]));
        assert!(r.headers.contains("cf-meta-asn: 7552"));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap().body, b"{\"a\":1}");
        assert!(parse_response(b"garbage").is_none());
    }

    #[test]
    fn short_isp_names() {
        assert_eq!(short_isp_name("Viettel Group"), "Viettel");
        assert_eq!(short_isp_name("Vietnam Posts and Telecommunications Group"), "VNPT");
        assert_eq!(short_isp_name("FPT Telecom Company"), "FPT Telecom");
        assert_eq!(short_isp_name("Cloudflare, Inc."), "Cloudflare");
        assert_eq!(short_isp_name("Comcast Cable Communications, LLC"), "Comcast Cable Communications");
    }

    #[test]
    fn mbps() {
        let d = Download { bytes: 12_500_000, elapsed: Duration::from_secs(2) };
        assert!((d.mbps() - 50.0).abs() < 1e-9);
    }
}

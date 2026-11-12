//! Levi Adaptive L2 measurement harness (Unit 2, MEASURE-PLAN sections a/d/e/h/i).
//!
//! Injection design: harness-owned TCP state. The harness builds SYN / ACK /
//! ClientHello fragments / RST itself and injects them with WinDivertSend; the
//! OS stack never owns the connection. A DROP handle scoped to the harness's
//! own inbound flow shields the host stack from the server's replies (so it
//! cannot RST an unowned port); a SNIFF handle records both directions,
//! including the injected fragments. Rationale: YUMI-UNIT2-L2.md.
//!
//! No module, engine, main.rs or Cargo edits. No dependency beyond levi's own.
//! SMOKE runs are machinery proofs, never evidence. Evidence runs additionally
//! require --confirm-approved and stay gated on the landing review.

use levi::adaptive::{
    self, AdaptiveLevel, AdaptiveMaps, ClientHello, ClientHelloAction, EscalationState, FlowKey,
    ProfileConfig, SegmentOrder, HANDSHAKE_WINDOW,
};
use levi::adaptive_emit::{EmitQueue, Fragment, FragmentSender};
use levi::packet::{ParsedPacket, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN};
use levi::raw::{
    SafeHandle, WinDivertAddress, WinDivertApi, WINDIVERT_FLAG_SNIFF, WINDIVERT_LAYER_NETWORK,
    WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_TIME,
};
use levi::tls;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

const BASE_SHA: &str = "abbfd6e5f5805e90e1a2ac9a257efc6773ee197a";
const CLEAN_SITES: &[&str] = &[
    "example.com",
    "google.com",
    "wikipedia.org",
    "cloudflare.com",
    "microsoft.com",
    "youtube.com",
];
const HOURLY_CAP: usize = 60;
const MIN_SPACING: Duration = Duration::from_secs(2);
const HOUR: Duration = Duration::from_secs(3600);
const DEFAULT_N: usize = 20;
const DEFAULT_SESSION_CAP: usize = 120;
const MAX_SESSION_CAP: usize = 240;
const PCAP_MAGIC: u32 = 0xA1B2_C3D4;
const LINKTYPE_RAW: u32 = 101;
const DRAIN_AFTER_OUTCOME: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Arms (MEASURE-PLAN section g matrix). balanced_cut_variant has no arm: the
// variant table is empty and filling it would be a banned module edit.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Arm {
    name: &'static str,
    level: AdaptiveLevel,
    delay: bool,
    window: bool,
}

const ARMS: &[Arm] = &[
    Arm { name: "fast", level: AdaptiveLevel::Fast, delay: false, window: false },
    Arm { name: "hardened", level: AdaptiveLevel::Hardened, delay: false, window: false },
    Arm { name: "ultra", level: AdaptiveLevel::Ultra, delay: false, window: false },
    Arm { name: "hardened-delay", level: AdaptiveLevel::Hardened, delay: true, window: false },
    Arm { name: "hardened-window", level: AdaptiveLevel::Hardened, delay: false, window: true },
    Arm { name: "ultra-delay", level: AdaptiveLevel::Ultra, delay: true, window: false },
    Arm { name: "ultra-window", level: AdaptiveLevel::Ultra, delay: false, window: true },
];

fn arm_by_name(name: &str) -> Option<Arm> {
    ARMS.iter().copied().find(|a| a.name == name)
}

fn arm_cfg(a: Arm) -> ProfileConfig {
    ProfileConfig {
        enabled_max_level: a.level,
        allow_inter_delay: a.delay,
        allow_window_override: a.window,
        balanced_cut_variant: 0,
    }
}

fn level_name(l: AdaptiveLevel) -> &'static str {
    match l {
        AdaptiveLevel::Passthrough => "Passthrough",
        AdaptiveLevel::Fast => "Fast",
        AdaptiveLevel::Balanced => "Balanced",
        AdaptiveLevel::Hardened => "Hardened",
        AdaptiveLevel::Ultra => "Ultra",
    }
}

fn order_name(o: &SegmentOrder) -> String {
    match o {
        SegmentOrder::InOrder => "InOrder".to_string(),
        SegmentOrder::Reverse => "Reverse".to_string(),
        SegmentOrder::Fixed(arr) => format!("Fixed[{},{},{},{}]", arr[0], arr[1], arr[2], arr[3]),
    }
}

fn approved_site(s: &str) -> bool {
    CLEAN_SITES.contains(&s)
}

/// Cut points for the arm: 3 segments [5, SNI midpoint] for Fast/Hardened,
/// 4 segments (extra tail midpoint) for Ultra, matching the live engine's
/// SNI-midpoint convention.
fn cuts_for_arm(level: AdaptiveLevel, payload: &[u8]) -> Result<Vec<usize>, String> {
    let info = tls::parse_client_hello(payload).ok_or("ClientHello parse failed")?;
    let off = info.sni_offset.ok_or("ClientHello has no SNI")?;
    let sni_len = info.sni.map(|s| s.len()).unwrap_or(0);
    if sni_len == 0 {
        return Err("empty SNI".into());
    }
    let mid = off + (sni_len / 2).max(1);
    let mut cuts = vec![5usize, mid];
    if level == AdaptiveLevel::Ultra {
        let sni_end = off + sni_len;
        if sni_end >= payload.len() {
            return Err("SNI extends to payload end; no tail to cut".into());
        }
        cuts.push(sni_end + (payload.len() - sni_end) / 2);
    }
    if cuts[0] == 0 || cuts.last().copied().unwrap_or(0) >= payload.len() {
        return Err("cuts out of range".into());
    }
    if cuts.windows(2).any(|w| w[0] >= w[1]) {
        return Err("cuts not strictly increasing".into());
    }
    Ok(cuts)
}

// ---------------------------------------------------------------------------
// Safety gate: <= 60 handshakes per target per rolling hour (hard stop),
// >= 2 s between handshakes to the same target, session cap.
// ---------------------------------------------------------------------------

struct SafetyGate {
    history: HashMap<String, VecDeque<Instant>>,
    session_count: usize,
    session_cap: usize,
}

impl SafetyGate {
    fn new(session_cap: usize) -> Self {
        Self { history: HashMap::new(), session_count: 0, session_cap }
    }

    fn check(&mut self, target: &str, now: Instant) -> Result<(), String> {
        if self.session_count >= self.session_cap {
            return Err(format!(
                "session cap reached ({} handshakes); hard stop",
                self.session_cap
            ));
        }
        let h = self.history.entry(target.to_string()).or_default();
        while h.front().is_some_and(|t| now.duration_since(*t) >= HOUR) {
            h.pop_front();
        }
        if h.len() >= HOURLY_CAP {
            return Err(format!(
                "hourly cap reached for {target} ({HOURLY_CAP}/hour); hard stop"
            ));
        }
        if let Some(last) = h.back() {
            if now.duration_since(*last) < MIN_SPACING {
                return Err(format!(
                    "spacing violation for {target}: < {} between handshakes",
                    MIN_SPACING.as_secs()
                ));
            }
        }
        h.push_back(now);
        self.session_count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// QPC clock + interface resolution, resolved dynamically (no Cargo changes).
// ---------------------------------------------------------------------------

fn load_library(name: &str) -> Result<HMODULE, String> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let h = unsafe { LoadLibraryW(wide.as_ptr()) };
    if h.is_null() {
        Err(format!("LoadLibraryW({name}) failed"))
    } else {
        Ok(h)
    }
}

fn get_proc<T>(h: HMODULE, name: &str) -> Result<T, String> {
    let sym = unsafe { GetProcAddress(h, name.as_ptr()) };
    match sym {
        Some(p) => Ok(unsafe {
            std::mem::transmute_copy::<unsafe extern "system" fn() -> isize, T>(&p)
        }),
        None => Err(format!("GetProcAddress({name}) failed")),
    }
}

struct Qpc {
    freq: i64,
    counter: unsafe extern "system" fn(*mut i64) -> i32,
}

impl Qpc {
    fn new() -> Result<Self, String> {
        let k32 = load_library("kernel32.dll")?;
        let qpf: unsafe extern "system" fn(*mut i64) -> i32 =
            get_proc(k32, "QueryPerformanceFrequency\0")?;
        let counter: unsafe extern "system" fn(*mut i64) -> i32 =
            get_proc(k32, "QueryPerformanceCounter\0")?;
        let mut freq = 0i64;
        if unsafe { qpf(&mut freq) } == 0 || freq <= 0 {
            return Err("QueryPerformanceFrequency failed".into());
        }
        Ok(Self { freq, counter })
    }

    fn now(&self) -> i64 {
        let mut v = 0i64;
        unsafe { (self.counter)(&mut v) };
        v
    }

    fn ns_between(&self, earlier: i64, later: i64) -> i64 {
        let delta = later.wrapping_sub(earlier) as f64;
        (delta / self.freq as f64 * 1e9) as i64
    }
}

/// Outbound interface index for the destination, from the Windows routing
/// table (same index space WinDivert uses). Avoids guessing if_idx.
fn best_if_index(dst: Ipv4Addr) -> Result<u32, String> {
    let iphlp = load_library("iphlpapi.dll")?;
    let f: unsafe extern "system" fn(u32, *mut u32) -> u32 =
        get_proc(iphlp, "GetBestInterface\0")?;
    let addr = u32::from_ne_bytes(dst.octets());
    let mut idx = 0u32;
    let rc = unsafe { f(addr, &mut idx) };
    if rc != 0 {
        return Err(format!("GetBestInterface failed: {rc}"));
    }
    Ok(idx)
}

// ---------------------------------------------------------------------------
// SHA-256 (std only) for manifest.sha256.
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Minimal JSON writer/parser (std only; levi has no serde).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum J {
    Null,
    B(bool),
    I(i64),
    U(u64),
    F(f64),
    S(String),
    A(Vec<J>),
    O(Vec<(String, J)>),
}

impl J {
    fn s(v: impl Into<String>) -> J {
        J::S(v.into())
    }

    fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::O(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            J::S(s) => Some(s),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            J::F(f) => Some(*f),
            J::I(i) => Some(*i as f64),
            J::U(u) => Some(*u as f64),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            J::B(b) => Some(*b),
            _ => None,
        }
    }

    fn compact(&self) -> String {
        let mut out = String::new();
        self.render(&mut out, 0, false);
        out
    }

    fn pretty(&self) -> String {
        let mut out = String::new();
        self.render(&mut out, 0, true);
        out
    }

    fn render(&self, out: &mut String, depth: usize, pretty: bool) {
        match self {
            J::Null => out.push_str("null"),
            J::B(b) => out.push_str(if *b { "true" } else { "false" }),
            J::I(i) => out.push_str(&i.to_string()),
            J::U(u) => out.push_str(&u.to_string()),
            J::F(f) => {
                if f.is_finite() {
                    out.push_str(&f.to_string());
                } else {
                    out.push_str("null");
                }
            }
            J::S(s) => json_escape(s, out),
            J::A(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push('\n');
                        push_indent(out, depth + 1);
                    }
                    item.render(out, depth + 1, pretty);
                }
                if pretty && !items.is_empty() {
                    out.push('\n');
                    push_indent(out, depth);
                }
                out.push(']');
            }
            J::O(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push('\n');
                        push_indent(out, depth + 1);
                    }
                    json_escape(k, out);
                    out.push(':');
                    if pretty {
                        out.push(' ');
                    }
                    v.render(out, depth + 1, pretty);
                }
                if pretty && !pairs.is_empty() {
                    out.push('\n');
                    push_indent(out, depth);
                }
                out.push('}');
            }
        }
    }
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn json_escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_parse(input: &str) -> Result<J, String> {
    let b = input.as_bytes();
    let mut i = 0usize;
    let v = parse_value(b, &mut i)?;
    skip_ws(b, &mut i);
    if i != b.len() {
        return Err("trailing characters in JSON".into());
    }
    Ok(v)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
        *i += 1;
    }
}

fn parse_value(b: &[u8], i: &mut usize) -> Result<J, String> {
    skip_ws(b, i);
    if *i >= b.len() {
        return Err("unexpected end of JSON".into());
    }
    match b[*i] {
        b'{' => {
            *i += 1;
            let mut pairs = Vec::new();
            skip_ws(b, i);
            if *i < b.len() && b[*i] == b'}' {
                *i += 1;
                return Ok(J::O(pairs));
            }
            loop {
                skip_ws(b, i);
                let key = match parse_value(b, i)? {
                    J::S(s) => s,
                    _ => return Err("object key must be a string".into()),
                };
                skip_ws(b, i);
                if *i >= b.len() || b[*i] != b':' {
                    return Err("expected ':'".into());
                }
                *i += 1;
                let val = parse_value(b, i)?;
                pairs.push((key, val));
                skip_ws(b, i);
                if *i >= b.len() {
                    return Err("unterminated object".into());
                }
                match b[*i] {
                    b',' => *i += 1,
                    b'}' => {
                        *i += 1;
                        return Ok(J::O(pairs));
                    }
                    _ => return Err("expected ',' or '}'".into()),
                }
            }
        }
        b'[' => {
            *i += 1;
            let mut items = Vec::new();
            skip_ws(b, i);
            if *i < b.len() && b[*i] == b']' {
                *i += 1;
                return Ok(J::A(items));
            }
            loop {
                items.push(parse_value(b, i)?);
                skip_ws(b, i);
                if *i >= b.len() {
                    return Err("unterminated array".into());
                }
                match b[*i] {
                    b',' => *i += 1,
                    b']' => {
                        *i += 1;
                        return Ok(J::A(items));
                    }
                    _ => return Err("expected ',' or ']'".into()),
                }
            }
        }
        b'"' => {
            *i += 1;
            let mut s = String::new();
            while *i < b.len() {
                match b[*i] {
                    b'"' => {
                        *i += 1;
                        return Ok(J::S(s));
                    }
                    b'\\' => {
                        *i += 1;
                        if *i >= b.len() {
                            return Err("bad escape".into());
                        }
                        match b[*i] {
                            b'"' => s.push('"'),
                            b'\\' => s.push('\\'),
                            b'/' => s.push('/'),
                            b'n' => s.push('\n'),
                            b'r' => s.push('\r'),
                            b't' => s.push('\t'),
                            b'b' => s.push('\u{0008}'),
                            b'f' => s.push('\u{000C}'),
                            b'u' => {
                                if *i + 4 >= b.len() {
                                    return Err("bad \\u escape".into());
                                }
                                let hex = std::str::from_utf8(&b[*i + 1..*i + 5])
                                    .map_err(|_| "bad \\u escape")?;
                                let cp = u32::from_str_radix(hex, 16)
                                    .map_err(|_| "bad \\u escape")?;
                                s.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                                *i += 4;
                            }
                            _ => return Err("bad escape".into()),
                        }
                        *i += 1;
                    }
                    c if c < 0x80 => {
                        s.push(c as char);
                        *i += 1;
                    }
                    _ => {
                        let start = *i;
                        while *i < b.len() && b[*i] >= 0x80 && b[*i] != b'"' && b[*i] != b'\\' {
                            *i += 1;
                        }
                        s.push_str(
                            std::str::from_utf8(&b[start..*i]).map_err(|_| "bad utf8")?,
                        );
                    }
                }
            }
            Err("unterminated string".into())
        }
        b't' => {
            if b[*i..].starts_with(b"true") {
                *i += 4;
                Ok(J::B(true))
            } else {
                Err("bad literal".into())
            }
        }
        b'f' => {
            if b[*i..].starts_with(b"false") {
                *i += 5;
                Ok(J::B(false))
            } else {
                Err("bad literal".into())
            }
        }
        b'n' => {
            if b[*i..].starts_with(b"null") {
                *i += 4;
                Ok(J::Null)
            } else {
                Err("bad literal".into())
            }
        }
        b'-' | b'0'..=b'9' => {
            let start = *i;
            if b[*i] == b'-' {
                *i += 1;
            }
            let mut is_float = false;
            while *i < b.len() {
                match b[*i] {
                    b'0'..=b'9' => *i += 1,
                    b'.' | b'e' | b'E' | b'+' | b'-' => {
                        is_float = true;
                        *i += 1;
                    }
                    _ => break,
                }
            }
            let text = std::str::from_utf8(&b[start..*i]).map_err(|_| "bad number")?;
            if !is_float {
                if let Ok(v) = text.parse::<i64>() {
                    return Ok(J::I(v));
                }
                if let Ok(v) = text.parse::<u64>() {
                    return Ok(J::U(v));
                }
            }
            text.parse::<f64>().map(J::F).map_err(|_| format!("bad number: {text}"))
        }
        _ => Err("unexpected character in JSON".into()),
    }
}

// ---------------------------------------------------------------------------
// Classic libpcap writer, std only. Byte spec locked by tests: magic
// 0xA1B2C3D4 (LE on disk), version 2.4, 24-byte global header, 16-byte record
// headers, LINKTYPE_RAW = 101 (WinDivert network-layer raw IP).
// ---------------------------------------------------------------------------

fn pcap_global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes());
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone (8..12) and sigfigs (12..16) stay zero.
    h[16..20].copy_from_slice(&65535u32.to_le_bytes());
    h[20..24].copy_from_slice(&LINKTYPE_RAW.to_le_bytes());
    h
}

struct PcapWriter {
    f: std::fs::File,
}

impl PcapWriter {
    fn create(path: &Path) -> std::io::Result<Self> {
        let mut f = std::fs::File::create(path)?;
        f.write_all(&pcap_global_header())?;
        Ok(Self { f })
    }

    fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> std::io::Result<()> {
        let mut hdr = [0u8; 16];
        hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes());
        self.f.write_all(&hdr)?;
        self.f.write_all(data)
    }
}

// ---------------------------------------------------------------------------
// UTC formatting (std only).
// ---------------------------------------------------------------------------

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn utc_parts(t: SystemTime) -> (i64, u32, u32, u32, u32, u32, u32) {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    (
        y,
        mo,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
        millis,
    )
}

fn format_utc(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s, ms) = utc_parts(t);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
}

fn format_utc_compact(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s, ms) = utc_parts(t);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}{ms:03}Z")
}

// ---------------------------------------------------------------------------
// ClientHello builder (hand-rolled TLS; no TLS crate). Realistic extensions so
// ordinary servers answer with ServerHello; the harness stops there.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next_u64().to_le_bytes();
            let n = (buf.len() - i).min(8);
            buf[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
    }
}

fn push_ext(exts: &mut Vec<u8>, kind: u16, data: &[u8]) {
    exts.extend_from_slice(&kind.to_be_bytes());
    exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
    exts.extend_from_slice(data);
}

fn build_client_hello(sni: &str, rng: &mut Rng) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    body.extend_from_slice(&random);
    let mut sid = [0u8; 32];
    rng.fill(&mut sid);
    body.push(32);
    body.extend_from_slice(&sid);
    let suites: &[u16] = &[
        0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C, 0x009D, 0x002F, 0x0035,
    ];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.push(1);
    body.push(0);

    let mut exts = Vec::new();
    let name = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);
    push_ext(&mut exts, 0x0000, &sni_ext);
    push_ext(&mut exts, 0x000a, &[0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19]);
    push_ext(&mut exts, 0x000b, &[0x01, 0x00]);
    let sigalgs: &[u16] = &[
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201,
    ];
    let mut sa = Vec::new();
    sa.extend_from_slice(&((sigalgs.len() * 2) as u16).to_be_bytes());
    for s in sigalgs {
        sa.extend_from_slice(&s.to_be_bytes());
    }
    push_ext(&mut exts, 0x000d, &sa);
    push_ext(&mut exts, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    let mut ks = Vec::new();
    ks.extend_from_slice(&[0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    ks.extend_from_slice(&key);
    push_ext(&mut exts, 0x0033, &ks);
    push_ext(
        &mut exts,
        0x0010,
        &[0x00, 0x0e, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'],
    );
    push_ext(&mut exts, 0x0017, &[]);
    push_ext(&mut exts, 0x0023, &[]);
    push_ext(&mut exts, 0x002d, &[0x01, 0x01]);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut out = Vec::new();
    out.push(0x16);
    out.extend_from_slice(&[0x03, 0x01]);
    out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    out.push(0x01);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------------
// TCP/IP construction. Every ClientHello fragment carries the identical
// option set [NOP, NOP, Timestamp] (invariant 3: option presence consistent
// across the fragments of one hello).
// ---------------------------------------------------------------------------

fn ts_opts(val: u32, ecr: u32) -> [u8; 12] {
    let mut o = [0u8; 12];
    o[0] = 1;
    o[1] = 1;
    o[2] = 8;
    o[3] = 10;
    o[4..8].copy_from_slice(&val.to_be_bytes());
    o[8..12].copy_from_slice(&ecr.to_be_bytes());
    o
}

fn syn_opts(val: u32) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[0] = 2;
    o[1] = 4;
    o[2..4].copy_from_slice(&1460u16.to_be_bytes());
    o[4] = 1;
    o[5] = 8;
    o[6] = 10;
    o[7..11].copy_from_slice(&val.to_be_bytes());
    o[15] = 1;
    o
}

fn build_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ip_id: u16,
    opts: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    assert!(opts.len() % 4 == 0, "TCP options must be 4-byte aligned");
    let tcp_hlen = 20 + opts.len();
    let total = 20 + tcp_hlen + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&ip_id.to_be_bytes());
    p[6] = 0x40;
    p[8] = 128;
    p[9] = 6;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let t = &mut p[20..];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = ((tcp_hlen / 4) as u8) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&window.to_be_bytes());
    t[20..20 + opts.len()].copy_from_slice(opts);
    p[20 + tcp_hlen..].copy_from_slice(payload);
    p
}

fn tcp_option_kinds(tcp_hdr: &[u8]) -> Vec<u8> {
    let mut kinds = Vec::new();
    let mut i = 20;
    while i < tcp_hdr.len() {
        let k = tcp_hdr[i];
        kinds.push(k);
        match k {
            0 => break,
            1 => i += 1,
            _ => {
                if i + 1 >= tcp_hdr.len() {
                    break;
                }
                let len = tcp_hdr[i + 1] as usize;
                if len < 2 {
                    break;
                }
                i += len;
            }
        }
    }
    kinds
}

fn tcp_ts_val(tcp_hdr: &[u8]) -> Option<u32> {
    let mut i = 20;
    while i < tcp_hdr.len() {
        let k = tcp_hdr[i];
        match k {
            0 => break,
            1 => i += 1,
            8 => {
                if i + 10 <= tcp_hdr.len() && tcp_hdr[i + 1] >= 10 {
                    return Some(u32::from_be_bytes([
                        tcp_hdr[i + 2],
                        tcp_hdr[i + 3],
                        tcp_hdr[i + 4],
                        tcp_hdr[i + 5],
                    ]));
                }
                break;
            }
            _ => {
                if i + 1 >= tcp_hdr.len() {
                    break;
                }
                let len = tcp_hdr[i + 1] as usize;
                if len < 2 {
                    break;
                }
                i += len;
            }
        }
    }
    None
}

fn segment_id_for_offset(cuts: &[usize], offset: usize) -> u8 {
    let mut id = 1u8;
    for &c in cuts {
        if offset >= c {
            id += 1;
        } else {
            break;
        }
    }
    id
}

fn fragment_window(wo: Option<(u16, u8)>, segment_id: u8) -> u16 {
    match wo {
        Some(w) if adaptive::window_includes_segment(w, segment_id) => w.1 as u16,
        _ => 65535,
    }
}

fn flow_key_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> FlowKey {
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s[..4].copy_from_slice(&src.octets());
    d[..4].copy_from_slice(&dst.octets());
    FlowKey { src_ip: s, dst_ip: d, src_port: sport, dst_port: dport, family: 4 }
}

// ---------------------------------------------------------------------------
// WireSender: the real FragmentSender. Wraps each merged-module Fragment in
// IP+TCP, applies the plan's window override by original segment id, keeps
// seq verbatim (base + offset, computed by EmitQueue), checksums, injects.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FlowTcp {
    base_seq: u32,
    ack: u32,
    cuts: Vec<usize>,
    window_override: Option<(u16, u8)>,
    ts_val: u32,
    ts_ecr: u32,
    if_idx: u32,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
}

struct SentRecord {
    seq: u32,
    len: usize,
    qpc: i64,
    kind: &'static str,
}

struct WireSender {
    api: Arc<WinDivertApi>,
    handle: SafeHandle,
    qpc: Arc<Qpc>,
    flows: Mutex<HashMap<FlowKey, FlowTcp>>,
    error: Mutex<Option<String>>,
    sent: Mutex<Vec<SentRecord>>,
    ip_id: AtomicU16,
}

impl WireSender {
    fn send_packet(&self, pkt: &mut [u8], if_idx: u32) -> Result<(), String> {
        let mut addr = WinDivertAddress::default();
        addr.set_outbound(true);
        addr.set_impostor(true);
        addr.if_idx = if_idx;
        unsafe {
            (self.api.calc_checksums)(pkt.as_mut_ptr(), pkt.len() as u32, &mut addr, 0);
        }
        let mut sent_len = 0u32;
        let res = unsafe {
            (self.api.send)(
                self.handle.as_raw(),
                pkt.as_ptr(),
                pkt.len() as u32,
                &mut sent_len,
                &addr,
            )
        };
        if res == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!("WinDivertSend failed with code {err}"));
        }
        Ok(())
    }

    fn send_control(
        &self,
        flow: &FlowKey,
        flags: u8,
        seq: u32,
        payload: &[u8],
        kind: &'static str,
    ) -> Result<(), String> {
        let f = self
            .flows
            .lock()
            .unwrap()
            .get(flow)
            .cloned()
            .ok_or("no flow context for control packet")?;
        let opts = ts_opts(f.ts_val, f.ts_ecr);
        let mut pkt = build_tcp_packet(
            f.src,
            f.dst,
            f.sport,
            443,
            seq,
            f.ack,
            flags,
            65535,
            self.ip_id.fetch_add(1, Ordering::Relaxed),
            &opts,
            payload,
        );
        self.send_packet(&mut pkt, f.if_idx)?;
        self.sent.lock().unwrap().push(SentRecord { seq, len: payload.len(), qpc: self.qpc.now(), kind });
        Ok(())
    }

    fn take_error(&self) -> Option<String> {
        self.error.lock().unwrap().take()
    }
}

impl FragmentSender for WireSender {
    fn send_fragment(&self, fragment: Fragment) {
        let result = (|| -> Result<(), String> {
            let f = self
                .flows
                .lock()
                .unwrap()
                .get(&fragment.flow)
                .cloned()
                .ok_or("no flow context for fragment")?;
            let offset = fragment.seq.wrapping_sub(f.base_seq) as usize;
            let seg_id = segment_id_for_offset(&f.cuts, offset);
            let window = fragment_window(f.window_override, seg_id);
            let opts = ts_opts(f.ts_val, f.ts_ecr);
            let mut pkt = build_tcp_packet(
                f.src,
                f.dst,
                f.sport,
                443,
                fragment.seq,
                f.ack,
                TCP_FLAG_ACK | TCP_FLAG_PSH,
                window,
                self.ip_id.fetch_add(1, Ordering::Relaxed),
                &opts,
                &fragment.payload,
            );
            self.send_packet(&mut pkt, f.if_idx)?;
            self.sent.lock().unwrap().push(SentRecord {
                seq: fragment.seq,
                len: fragment.payload.len(),
                qpc: self.qpc.now(),
                kind: "fragment",
            });
            Ok(())
        })();
        if let Err(e) = result {
            *self.error.lock().unwrap() = Some(e);
        }
    }
}

// ---------------------------------------------------------------------------
// Capture: SNIFF handle records both directions (no impostor exclusion, so
// injected fragments are recorded). The DROP shield consumes the harness's
// own inbound flow without re-injecting, keeping the host stack out.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CapturedPacket {
    bytes: Vec<u8>,
    qpc: i64,
    utc: SystemTime,
    outbound: bool,
    impostor: bool,
}

struct CaptureShared {
    packets: Mutex<Vec<CapturedPacket>>,
    interference: AtomicBool,
    stop: AtomicBool,
}

fn capture_loop(api: Arc<WinDivertApi>, handle: SafeHandle, shared: Arc<CaptureShared>, qpc: Arc<Qpc>) {
    let mut buf = vec![0u8; 65535];
    let mut addr = WinDivertAddress::default();
    let mut recv_len = 0u32;
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        let res = unsafe {
            (api.recv)(
                handle.as_raw(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };
        if res == 0 {
            let err = unsafe { GetLastError() };
            if err == 6 || err == 995 || shared.stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let outbound = addr.is_outbound();
        let impostor = addr.is_impostor();
        // Any host-originated packet on the measurement flow means something
        // else owns this port: stop the session (blocker).
        if outbound && !impostor {
            shared.interference.store(true, Ordering::SeqCst);
        }
        let ts = if addr.timestamp != 0 { addr.timestamp } else { qpc.now() };
        shared.packets.lock().unwrap().push(CapturedPacket {
            bytes: buf[..recv_len as usize].to_vec(),
            qpc: ts,
            utc: SystemTime::now(),
            outbound,
            impostor,
        });
    }
}

fn shield_loop(api: Arc<WinDivertApi>, handle: SafeHandle, stop: Arc<AtomicBool>, count: Arc<AtomicUsize>) {
    let mut buf = vec![0u8; 65535];
    let mut addr = WinDivertAddress::default();
    let mut recv_len = 0u32;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let res = unsafe {
            (api.recv)(
                handle.as_raw(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };
        if res == 0 {
            let err = unsafe { GetLastError() };
            if err == 6 || err == 995 || stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        // Deliberately not re-injected: the host stack must never see this flow.
        count.fetch_add(1, Ordering::Relaxed);
    }
}

fn open_handle(api: &WinDivertApi, filter: &str, priority: i16, flags: u64) -> Result<SafeHandle, String> {
    let cstr = std::ffi::CString::new(filter).map_err(|e| e.to_string())?;
    let raw = unsafe { (api.open)(cstr.as_ptr(), WINDIVERT_LAYER_NETWORK, priority, flags) };
    let handle = SafeHandle::from_raw(raw);
    if handle.is_invalid() {
        let err = unsafe { GetLastError() };
        return Err(format!(
            "WinDivertOpen failed (code {err}); filter: {filter}. Administrator rights and the WinDivert driver are required."
        ));
    }
    unsafe {
        (api.set_param)(handle.as_raw(), WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
        (api.set_param)(handle.as_raw(), WINDIVERT_PARAM_QUEUE_TIME, 2000);
        (api.set_param)(handle.as_raw(), WINDIVERT_PARAM_QUEUE_SIZE, 16 * 1024 * 1024);
    }
    Ok(handle)
}

// ---------------------------------------------------------------------------
// Detectors (MEASURE-PLAN section e). They record observations; the verdict
// comes from the gated-vs-Fast comparison, never from a single run.
// ---------------------------------------------------------------------------

struct GapStats {
    gaps_ns: Vec<u64>,
    mean_ns: f64,
    std_ns: f64,
    cov: f64,
    quantized_frac: f64,
    flag: bool,
}

/// Regular/even gaps: 1 ms tick quantization (TICK_NANOS) or very low CoV in
/// the tick regime (mean >= 0.5 ms). Sub-0.5 ms back-to-back spacing is the
/// Fast arm's own signature and is not flagged.
fn detect_regular_gaps(gaps_ns: &[u64]) -> GapStats {
    let n = gaps_ns.len();
    let mean = if n == 0 { 0.0 } else { gaps_ns.iter().sum::<u64>() as f64 / n as f64 };
    let var = if n == 0 {
        0.0
    } else {
        gaps_ns.iter().map(|g| (*g as f64 - mean).powi(2)).sum::<f64>() / n as f64
    };
    let std = var.sqrt();
    let cov = if mean > 0.0 { std / mean } else { 0.0 };
    let quantized = gaps_ns
        .iter()
        .filter(|&&g| {
            let k = (g as f64 / 1e6).round();
            k >= 1.0 && (g as f64 - k * 1e6).abs() <= 100_000.0
        })
        .count();
    let quantized_frac = if n == 0 { 0.0 } else { quantized as f64 / n as f64 };
    let flag = n >= 2 && (quantized_frac >= 0.8 || (mean >= 500_000.0 && cov < 0.05));
    GapStats { gaps_ns: gaps_ns.to_vec(), mean_ns: mean, std_ns: std, cov, quantized_frac, flag }
}

fn detect_uneven_options(kinds_per_fragment: &[Vec<u8>]) -> bool {
    let mut sorted: Vec<Vec<u8>> = kinds_per_fragment
        .iter()
        .map(|k| {
            let mut k = k.clone();
            k.sort_unstable();
            k
        })
        .collect();
    if sorted.len() < 2 {
        return false;
    }
    let first = sorted.remove(0);
    sorted.iter().any(|k| *k != first)
}

struct WindowStall {
    min_inbound_window: Option<u16>,
    min_outbound_window: Option<u16>,
    zero_window_seen: bool,
    progress: bool,
    flag: bool,
}

/// Window stall: a zero advertised window with no handshake progress inside
/// HANDSHAKE_WINDOW. The gated override advertises window = 1, not zero; an
/// induced stall surfaces as missing progress (timeout), recorded honestly.
fn detect_window_stall(
    min_inbound_window: Option<u16>,
    min_outbound_window: Option<u16>,
    progress: bool,
) -> WindowStall {
    let zero_window_seen = min_inbound_window == Some(0) || min_outbound_window == Some(0);
    WindowStall {
        min_inbound_window,
        min_outbound_window,
        zero_window_seen,
        progress,
        flag: zero_window_seen && !progress,
    }
}

fn percentile_nearest_rank(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    Some(sorted[idx])
}

fn new_anomaly(gated_flags: usize, fast_flags: usize) -> bool {
    gated_flags > 0 && fast_flags == 0
}

// ---------------------------------------------------------------------------
// One handshake run.
// ---------------------------------------------------------------------------

struct SessionCtx {
    kind: &'static str,
    out_dir: PathBuf,
    api: Arc<WinDivertApi>,
    qpc: Arc<Qpc>,
    gate: Mutex<SafetyGate>,
    harness_commit: String,
    anchor_utc: SystemTime,
    anchor_qpc: i64,
}

struct RunResult {
    summary: J,
    run_id: String,
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn flags_str(flags: u8) -> String {
    let mut s = String::new();
    if flags & TCP_FLAG_SYN != 0 {
        s.push('S');
    }
    if flags & TCP_FLAG_ACK != 0 {
        s.push('A');
    }
    if flags & TCP_FLAG_RST != 0 {
        s.push('R');
    }
    if flags & TCP_FLAG_PSH != 0 {
        s.push('P');
    }
    if flags & levi::packet::TCP_FLAG_FIN != 0 {
        s.push('F');
    }
    s
}

fn run_one(ctx: &SessionCtx, site: &str, arm: Arm, seq_no: usize) -> Result<RunResult, String> {
    if !approved_site(site) {
        return Err(format!("target {site} is not on the approved clean-site list"));
    }
    let started = SystemTime::now();
    ctx.gate
        .lock()
        .unwrap()
        .check(site, Instant::now())?;

    let cfg = arm_cfg(arm);
    let run_id = format!("{}-{}-{}-{:03}", format_utc_compact(started), site, arm.name, seq_no);
    let mut log: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    log.push(format!(
        "{} RUN {run_id} kind={} site={site} arm={} level={}",
        format_utc(started),
        ctx.kind,
        arm.name,
        level_name(arm.level)
    ));

    let addrs: Vec<SocketAddr> = format!("{site}:443")
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {site}: {e}"))?
        .collect();
    let remote: Ipv4Addr = addrs
        .iter()
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        })
        .ok_or(format!("no IPv4 address resolved for {site}"))?;
    log.push(format!("resolved {site} -> {remote} ({} addresses)", addrs.len()));

    // UDP bind reserves an ephemeral port and reveals the routed source IP
    // without sending anything; TCP and UDP port namespaces are separate on
    // Windows, so the SYN-ACK ack check below verifies the TCP port is free.
    let reserve = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("port reservation: {e}"))?;
    reserve
        .connect((remote, 443))
        .map_err(|e| format!("route lookup: {e}"))?;
    let local = reserve.local_addr().map_err(|e| format!("local_addr: {e}"))?;
    let local_ip = match local.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => return Err("routed source address is not IPv4".into()),
    };
    let local_port = local.port();

    let (if_idx, if_idx_source) = match best_if_index(remote) {
        Ok(idx) => (idx, "GetBestInterface"),
        Err(e) => {
            notes.push(format!("GetBestInterface failed ({e}); falling back to if_idx=0"));
            (0, "fallback-zero")
        }
    };
    log.push(format!(
        "local {local_ip}:{local_port} if_idx={if_idx} ({if_idx_source})"
    ));

    let mut rng = Rng::new(ctx.qpc.now() as u64 ^ started.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64);
    let hello = build_client_hello(site, &mut rng);
    let cuts = cuts_for_arm(arm.level, &hello)?;
    let expected_plan = adaptive::plan_for(arm.level, &cuts, &cfg)
        .ok_or(format!("plan_for returned None for arm {} (Ultra needs 4 segments)", arm.name))?;
    let isn = rng.next_u64() as u32;
    let ts_val = (rng.next_u64() & 0x7FFF_FFFF) as u32;
    let flow = flow_key_v4(local_ip, remote, local_port, 443);

    let sniff_filter = format!(
        "(ip.SrcAddr == {local_ip} and ip.DstAddr == {remote} and tcp.SrcPort == {local_port} and tcp.DstPort == 443) or (ip.SrcAddr == {remote} and ip.DstAddr == {local_ip} and tcp.SrcPort == 443 and tcp.DstPort == {local_port})"
    );
    let shield_filter = format!(
        "inbound and ip.SrcAddr == {remote} and ip.DstAddr == {local_ip} and tcp.SrcPort == 443 and tcp.DstPort == {local_port}"
    );
    // SNIFF at higher priority (lower number) than the DROP shield so the
    // capture sees every inbound packet before the shield removes it.
    let sniff = open_handle(&ctx.api, &sniff_filter, -100, WINDIVERT_FLAG_SNIFF)?;
    let shield = match open_handle(&ctx.api, &shield_filter, 0, 0) {
        Ok(h) => h,
        Err(e) => {
            unsafe { (ctx.api.close)(sniff.as_raw()) };
            return Err(e);
        }
    };

    let shared = Arc::new(CaptureShared {
        packets: Mutex::new(Vec::new()),
        interference: AtomicBool::new(false),
        stop: AtomicBool::new(false),
    });
    let shield_stop = Arc::new(AtomicBool::new(false));
    let shield_count = Arc::new(AtomicUsize::new(0));
    let cap_thread = {
        let api = Arc::clone(&ctx.api);
        let shared = Arc::clone(&shared);
        let qpc = Arc::clone(&ctx.qpc);
        std::thread::spawn(move || capture_loop(api, sniff, shared, qpc))
    };
    let shield_thread = {
        let api = Arc::clone(&ctx.api);
        let stop = Arc::clone(&shield_stop);
        let count = Arc::clone(&shield_count);
        std::thread::spawn(move || shield_loop(api, shield, stop, count))
    };

    let sender = Arc::new(WireSender {
        api: Arc::clone(&ctx.api),
        handle: shield,
        qpc: Arc::clone(&ctx.qpc),
        flows: Mutex::new(HashMap::new()),
        error: Mutex::new(None),
        sent: Mutex::new(Vec::new()),
        ip_id: AtomicU16::new((rng.next_u64() & 0xFFFF) as u16),
    });
    sender.flows.lock().unwrap().insert(
        flow,
        FlowTcp {
            base_seq: isn.wrapping_add(1),
            ack: 0,
            cuts: cuts.clone(),
            window_override: expected_plan.window_override,
            ts_val,
            ts_ecr: 0,
            if_idx,
            src: local_ip,
            dst: remote,
            sport: local_port,
        },
    );

    // Cleanup closure: stop threads, close handles, join.
    let cleanup = |shared: &Arc<CaptureShared>, shield_stop: &Arc<AtomicBool>| {
        shared.stop.store(true, Ordering::SeqCst);
        shield_stop.store(true, Ordering::SeqCst);
        unsafe {
            (ctx.api.close)(sniff.as_raw());
            (ctx.api.close)(shield.as_raw());
        }
    };

    let mut outcome = "timeout".to_string();
    let mut server_isn: Option<u32> = None;
    let mut synack_qpc: Option<i64> = None;
    let mut first_frag_qpc: Option<i64> = None;
    let mut serverhello_qpc: Option<i64> = None;
    let mut rst_in_window = false;
    let mut cursor = 0usize;
    let mut reassembly: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut assembled: Vec<u8> = Vec::new();
    let mut next_rel_seq = 0u32;
    let mut server_acked_data = false;
    let mut fatal: Option<String> = None;

    // SYN.
    let syn = {
        let f = sender.flows.lock().unwrap().get(&flow).cloned().unwrap();
        let opts = syn_opts(f.ts_val);
        build_tcp_packet(
            f.src, f.dst, f.sport, 443, isn, 0, TCP_FLAG_SYN, 65535,
            sender.ip_id.fetch_add(1, Ordering::Relaxed), &opts, &[],
        )
    };
    let syn_qpc = ctx.qpc.now();
    if let Err(e) = sender.send_packet(&mut syn.clone(), if_idx) {
        cleanup(&shared, &shield_stop);
        let _ = cap_thread.join();
        let _ = shield_thread.join();
        return Err(format!("SYN send failed: {e}"));
    }
    sender.sent.lock().unwrap().push(SentRecord { seq: isn, len: 0, qpc: syn_qpc, kind: "syn" });
    log.push(format!("SYN sent isn={isn}"));

    // Wait SYN-ACK (or RST / timeout).
    let syn_deadline = Instant::now() + HANDSHAKE_WINDOW;
    let mut port_collision = false;
    while Instant::now() < syn_deadline {
        if shared.interference.load(Ordering::SeqCst) {
            fatal = Some("INTERFERENCE: host-originated outbound packet on the measurement flow".into());
            break;
        }
        let snapshot: Vec<CapturedPacket> = {
            let pkts = shared.packets.lock().unwrap();
            pkts[cursor..].to_vec()
        };
        cursor += snapshot.len();
        for p in &snapshot {
            let Some(parsed) = ParsedPacket::parse(&p.bytes) else { continue };
            if p.outbound {
                continue;
            }
            if parsed.tcp_flags & TCP_FLAG_RST != 0 {
                outcome = "reset".into();
                fatal = None;
                break;
            }
            if parsed.tcp_flags & TCP_FLAG_SYN != 0 && parsed.tcp_flags & TCP_FLAG_ACK != 0 {
                if parsed.tcp_ack != isn.wrapping_add(1) {
                    port_collision = true;
                    break;
                }
                server_isn = Some(parsed.tcp_seq);
                synack_qpc = Some(p.qpc);
                let hdr = &p.bytes[parsed.ip_header_len..parsed.ip_header_len + parsed.tcp_header_len];
                if let Some(v) = tcp_ts_val(hdr) {
                    sender.flows.lock().unwrap().get_mut(&flow).unwrap().ts_ecr = v;
                }
                break;
            }
        }
        if server_isn.is_some() || outcome == "reset" || port_collision || fatal.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    if port_collision {
        cleanup(&shared, &shield_stop);
        let _ = cap_thread.join();
        let _ = shield_thread.join();
        return Err("PORT_COLLISION".into());
    }

    let mut maps = AdaptiveMaps::new();
    let mut queue: Option<Arc<EmitQueue>> = None;

    if fatal.is_none() && outcome != "reset" {
        if let Some(sisn) = server_isn {
            sender.flows.lock().unwrap().get_mut(&flow).unwrap().ack = sisn.wrapping_add(1);
            log.push(format!(
                "SYN-ACK server_isn={sisn} rtt_ms={:.3}",
                ctx.qpc.ns_between(syn_qpc, synack_qpc.unwrap_or(syn_qpc)) as f64 / 1e6
            ));
            if let Err(e) = sender.send_control(&flow, TCP_FLAG_ACK, isn.wrapping_add(1), &[], "ack") {
                fatal = Some(format!("ACK send failed: {e}"));
            } else {
                log.push("ACK sent".into());
            }

            if fatal.is_none() {
                let q = EmitQueue::start(Arc::clone(&sender) as Arc<dyn FragmentSender>);
                maps = AdaptiveMaps::with_sink(Arc::clone(&q) as Arc<dyn adaptive::EmitSink>);
                queue = Some(q);
                maps.flow_map.insert(
                    flow,
                    EscalationState {
                        level: arm.level,
                        success_streak: 0,
                        split_attempts: 0,
                        has_success: false,
                        last_seen: Instant::now(),
                        cooldown_until: None,
                        sni_key: adaptive::normalize_sni(site),
                    },
                );
                let action = maps.on_client_hello(
                    &ClientHello {
                        flow,
                        sni: Some(site),
                        compat_mode: false,
                        custom_excluded: &[],
                        seq: isn.wrapping_add(1),
                        payload: hello.clone(),
                        cuts: cuts.clone(),
                    },
                    &cfg,
                    Instant::now(),
                );
                if action != ClientHelloAction::Enqueued {
                    fatal = Some(format!(
                        "on_client_hello returned {action:?} for approved site {site}; expected Enqueued"
                    ));
                } else {
                    log.push(format!(
                        "on_client_hello -> Enqueued level={} cuts={cuts:?} order={} delay_ms={} window_override={:?}",
                        level_name(arm.level),
                        order_name(&expected_plan.order),
                        expected_plan.inter_delay.as_secs_f64() * 1000.0,
                        expected_plan.window_override
                    ));
                }
            }
        } else if outcome != "reset" {
            outcome = "timeout".into();
            notes.push("SYN-ACK never arrived (syn-phase timeout)".into());
            log.push("SYN phase timeout".into());
        }
    }

    // Wait for the handshake outcome, measured from the first fragment on the wire.
    if fatal.is_none() && server_isn.is_some() && outcome != "reset" {
        let mut deadline: Option<Instant> = None;
        loop {
            if shared.interference.load(Ordering::SeqCst) {
                fatal = Some("INTERFERENCE: host-originated outbound packet on the measurement flow".into());
                break;
            }
            if let Some(e) = sender.take_error() {
                fatal = Some(format!("fragment send failed: {e}"));
                break;
            }
            let snapshot: Vec<CapturedPacket> = {
                let pkts = shared.packets.lock().unwrap();
                pkts[cursor..].to_vec()
            };
            cursor += snapshot.len();
            for p in &snapshot {
                let Some(parsed) = ParsedPacket::parse(&p.bytes) else { continue };
                if p.outbound {
                    if p.impostor && !parsed.payload.is_empty() && first_frag_qpc.is_none() {
                        first_frag_qpc = Some(p.qpc);
                        deadline = Some(Instant::now() + HANDSHAKE_WINDOW);
                    }
                    continue;
                }
                if parsed.tcp_flags & TCP_FLAG_RST != 0 {
                    outcome = "reset".into();
                    rst_in_window = first_frag_qpc
                        .map(|t| ctx.qpc.ns_between(t, p.qpc) <= HANDSHAKE_WINDOW.as_nanos() as i64)
                        .unwrap_or(true);
                    break;
                }
                if parsed.tcp_ack != 0
                    && parsed.tcp_ack.wrapping_sub(isn.wrapping_add(1)) > 0
                    && parsed.tcp_ack.wrapping_sub(isn.wrapping_add(1)) <= hello.len() as u32
                {
                    server_acked_data = true;
                }
                if !parsed.payload.is_empty() {
                    let rel = parsed.tcp_seq.wrapping_sub(server_isn.unwrap().wrapping_add(1));
                    reassembly.entry(rel).or_insert_with(|| parsed.payload.to_vec());
                    while let Some(chunk) = reassembly.remove(&next_rel_seq) {
                        next_rel_seq = next_rel_seq.wrapping_add(chunk.len() as u32);
                        assembled.extend_from_slice(&chunk);
                    }
                    if assembled.len() >= 6 && assembled[0] == 0x16 && assembled[5] == 0x02 {
                        outcome = "success".into();
                        serverhello_qpc = Some(p.qpc);
                        break;
                    }
                }
            }
            if outcome == "success" || outcome == "reset" {
                break;
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    outcome = "timeout".into();
                    break;
                }
            } else if Instant::now() >= syn_deadline + HANDSHAKE_WINDOW {
                outcome = "timeout".into();
                notes.push("no fragment observed on the wire".into());
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    // Feed the outcome through the merged public API.
    let now = Instant::now();
    if server_isn.is_some() && fatal.is_none() {
        match outcome.as_str() {
            "success" => maps.on_handshake_complete(&flow, now),
            "reset" => maps.on_rst(&flow, rst_in_window, &cfg, now),
            _ => maps.on_handshake_timeout(&flow, now),
        }
    }
    let post_level = if server_isn.is_some() {
        Some(level_name(maps.current_level(&flow, Some(site), &cfg, Instant::now())))
    } else {
        None
    };
    log.push(format!("outcome={outcome} post_level={post_level:?}"));

    // Teardown: RST closes the server side promptly; then drain the capture.
    if server_isn.is_some() && fatal.is_none() {
        let seq = isn.wrapping_add(1).wrapping_add(hello.len() as u32);
        if let Err(e) = sender.send_control(&flow, TCP_FLAG_RST | TCP_FLAG_ACK, seq, &[], "rst") {
            notes.push(format!("teardown RST failed: {e}"));
        } else {
            log.push("teardown RST sent".into());
        }
    }
    std::thread::sleep(DRAIN_AFTER_OUTCOME);
    cleanup(&shared, &shield_stop);
    let _ = cap_thread.join();
    let _ = shield_thread.join();
    if let Some(q) = queue.take() {
        q.shutdown();
    }
    maps.wipe();
    drop(reserve);

    if let Some(e) = fatal {
        return Err(e);
    }

    let packets = shared.packets.lock().unwrap().clone();
    let shielded = shield_count.load(Ordering::Relaxed);
    log.push(format!(
        "captured={} shielded_inbound={shielded} interference={}",
        packets.len(),
        shared.interference.load(Ordering::SeqCst)
    ));

    // ---- Analysis over the capture -------------------------------------
    let base_seq = isn.wrapping_add(1);
    let mut frag_records: Vec<J> = Vec::new();
    let mut frag_offsets: Vec<usize> = Vec::new();
    let mut frag_kinds: Vec<Vec<u8>> = Vec::new();
    let mut frag_qpcs: Vec<i64> = Vec::new();
    let mut min_outbound_window: Option<u16> = None;
    let mut min_inbound_window: Option<u16> = None;
    let mut reassembled_hello: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut packet_records: Vec<J> = Vec::new();

    for (i, p) in packets.iter().enumerate() {
        let Some(parsed) = ParsedPacket::parse(&p.bytes) else { continue };
        let hdr = &p.bytes[parsed.ip_header_len..parsed.ip_header_len + parsed.tcp_header_len];
        let kinds = tcp_option_kinds(hdr);
        let window = u16::from_be_bytes([
            p.bytes[parsed.ip_header_len + 14],
            p.bytes[parsed.ip_header_len + 15],
        ]);
        if p.outbound {
            min_outbound_window = Some(min_outbound_window.map_or(window, |m: u16| m.min(window)));
        } else {
            min_inbound_window = Some(min_inbound_window.map_or(window, |m: u16| m.min(window)));
        }
        packet_records.push(J::O(vec![
            ("i".into(), J::U(i as u64)),
            ("dir".into(), J::s(if p.outbound { "out" } else { "in" })),
            ("impostor".into(), J::B(p.impostor)),
            ("qpc".into(), J::I(p.qpc)),
            ("utc".into(), J::s(format_utc(p.utc))),
            ("seq".into(), J::U(parsed.tcp_seq as u64)),
            ("ack".into(), J::U(parsed.tcp_ack as u64)),
            ("flags".into(), J::s(flags_str(parsed.tcp_flags))),
            ("window".into(), J::U(window as u64)),
            ("payload_len".into(), J::U(parsed.payload.len() as u64)),
            ("option_kinds".into(), J::A(kinds.iter().map(|k| J::U(*k as u64)).collect())),
        ]));
        if p.outbound && p.impostor && !parsed.payload.is_empty() {
            let offset = parsed.tcp_seq.wrapping_sub(base_seq) as usize;
            frag_offsets.push(offset);
            frag_kinds.push(kinds.clone());
            frag_qpcs.push(p.qpc);
            reassembled_hello.push((offset, parsed.payload.to_vec()));
            frag_records.push(J::O(vec![
                ("seq".into(), J::U(parsed.tcp_seq as u64)),
                ("offset".into(), J::U(offset as u64)),
                ("len".into(), J::U(parsed.payload.len() as u64)),
                ("window".into(), J::U(window as u64)),
                ("qpc".into(), J::I(p.qpc)),
                ("option_kinds".into(), J::A(kinds.iter().map(|k| J::U(*k as u64)).collect())),
            ]));
        }
    }

    // Layout cross-check: seq = base + offset, emit order, coverage, options.
    let seg_offsets: Vec<usize> = std::iter::once(0usize)
        .chain(cuts.iter().copied())
        .collect();
    let expected_offsets: Vec<usize> = match expected_plan.order {
        SegmentOrder::InOrder => seg_offsets.clone(),
        SegmentOrder::Reverse => seg_offsets.iter().copied().rev().collect(),
        SegmentOrder::Fixed(arr) => arr
            .iter()
            .take(seg_offsets.len())
            .map(|id| seg_offsets[*id as usize - 1])
            .collect(),
    };
    let order_ok = frag_offsets == expected_offsets;
    let mut sorted_frags = reassembled_hello.clone();
    sorted_frags.sort_by_key(|(off, _)| *off);
    let coverage_ok = sorted_frags
        .iter()
        .enumerate()
        .all(|(i, (off, _))| i == 0 || *off == sorted_frags[i - 1].0 + sorted_frags[i - 1].1.len())
        && sorted_frags.first().map(|(o, _)| *o) == Some(0)
        && sorted_frags.iter().map(|(_, p)| p.len()).sum::<usize>() == hello.len();
    let rebuilt: Vec<u8> = sorted_frags.iter().flat_map(|(_, p)| p.clone()).collect();
    let payload_ok = rebuilt == hello;
    let seq_ok = frag_records.iter().all(|f| {
        let seq = f.get("seq").and_then(|v| v.as_f64()).unwrap_or(0.0) as u32;
        let off = f.get("offset").and_then(|v| v.as_f64()).unwrap_or(0.0) as u32;
        seq == base_seq.wrapping_add(off)
    });
    let options_consistent = !detect_uneven_options(&frag_kinds);

    let gaps_ns: Vec<u64> = frag_qpcs
        .windows(2)
        .map(|w| ctx.qpc.ns_between(w[0], w[1]).max(0) as u64)
        .collect();
    let d2 = detect_regular_gaps(&gaps_ns);
    let d1_flag = detect_uneven_options(&frag_kinds);
    let progress = outcome == "success" || server_acked_data;
    let d3 = detect_window_stall(min_inbound_window, min_outbound_window, progress);

    let latency_ms: Option<f64> = match (first_frag_qpc, serverhello_qpc) {
        (Some(a), Some(b)) => Some(ctx.qpc.ns_between(a, b) as f64 / 1e6),
        _ => None,
    };
    log.push(format!(
        "fragments={} order_ok={order_ok} seq_ok={seq_ok} coverage_ok={coverage_ok} options_consistent={options_consistent}",
        frag_records.len()
    ));
    log.push(format!(
        "detectors d1_uneven_options={} d2_regular_gaps={} d3_window_stall={} latency_ms={latency_ms:?}",
        d1_flag, d2.flag, d3.flag
    ));

    // ---- Artifacts ------------------------------------------------------
    let run_dir = ctx.out_dir.join("runs").join(&run_id);
    std::fs::create_dir_all(&run_dir).map_err(|e| format!("create run dir: {e}"))?;

    let mut pcap = PcapWriter::create(&run_dir.join("capture.pcap"))
        .map_err(|e| format!("pcap create: {e}"))?;
    for p in &packets {
        let dur = p.utc.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        pcap.write_packet(dur.as_secs() as u32, dur.subsec_micros(), &p.bytes)
            .map_err(|e| format!("pcap write: {e}"))?;
    }

    let sent_records: Vec<J> = sender
        .sent
        .lock()
        .unwrap()
        .iter()
        .map(|s| {
            J::O(vec![
                ("kind".into(), J::s(s.kind)),
                ("seq".into(), J::U(s.seq as u64)),
                ("payload_len".into(), J::U(s.len as u64)),
                ("qpc".into(), J::I(s.qpc)),
            ])
        })
        .collect();

    let fragment_count = frag_records.len();

    let run_json = J::O(vec![
        ("run_id".into(), J::s(&run_id)),
        ("kind".into(), J::s(ctx.kind)),
        ("site".into(), J::s(site)),
        ("arm".into(), J::s(arm.name)),
        ("level".into(), J::s(level_name(arm.level))),
        (
            "profile_config".into(),
            J::O(vec![
                ("enabled_max_level".into(), J::s(level_name(cfg.enabled_max_level))),
                ("allow_inter_delay".into(), J::B(cfg.allow_inter_delay)),
                ("allow_window_override".into(), J::B(cfg.allow_window_override)),
                ("balanced_cut_variant".into(), J::U(cfg.balanced_cut_variant as u64)),
            ]),
        ),
        (
            "expected_plan".into(),
            J::O(vec![
                ("order".into(), J::s(order_name(&expected_plan.order))),
                ("inter_delay_ms".into(), J::F(expected_plan.inter_delay.as_secs_f64() * 1000.0)),
                (
                    "window_override".into(),
                    match expected_plan.window_override {
                        Some((mask, win)) => J::A(vec![J::U(mask as u64), J::U(win as u64)]),
                        None => J::Null,
                    },
                ),
            ]),
        ),
        ("cuts".into(), J::A(cuts.iter().map(|c| J::U(*c as u64)).collect())),
        ("client_hello_len".into(), J::U(hello.len() as u64)),
        ("client_hello_hex".into(), J::s(hex_encode(&hello))),
        ("base_sha".into(), J::s(BASE_SHA)),
        ("harness_commit".into(), J::s(&ctx.harness_commit)),
        ("local_ip".into(), J::s(local_ip.to_string())),
        ("remote_ip".into(), J::s(remote.to_string())),
        ("local_port".into(), J::U(local_port as u64)),
        ("if_idx".into(), J::U(if_idx as u64)),
        ("if_idx_source".into(), J::s(if_idx_source)),
        ("isn".into(), J::U(isn as u64)),
        ("server_isn".into(), server_isn.map(|v| J::U(v as u64)).unwrap_or(J::Null)),
        ("started_utc".into(), J::s(format_utc(started))),
        ("qpc_freq".into(), J::I(ctx.qpc.freq)),
        ("qpc_anchor_utc".into(), J::s(format_utc(ctx.anchor_utc))),
        ("qpc_anchor".into(), J::I(ctx.anchor_qpc)),
        ("syn_qpc".into(), J::I(syn_qpc)),
        ("synack_qpc".into(), synack_qpc.map(J::I).unwrap_or(J::Null)),
        ("first_fragment_qpc".into(), first_frag_qpc.map(J::I).unwrap_or(J::Null)),
        ("serverhello_qpc".into(), serverhello_qpc.map(J::I).unwrap_or(J::Null)),
        ("outcome".into(), J::s(&outcome)),
        ("rst_in_window".into(), J::B(rst_in_window)),
        ("latency_ms".into(), latency_ms.map(J::F).unwrap_or(J::Null)),
        ("fragment_count".into(), J::U(fragment_count as u64)),
        ("post_level".into(), post_level.map(J::s).unwrap_or(J::Null)),
        (
            "layout".into(),
            J::O(vec![
                ("expected_order".into(), J::s(order_name(&expected_plan.order))),
                ("expected_offsets".into(), J::A(expected_offsets.iter().map(|o| J::U(*o as u64)).collect())),
                ("observed_offsets".into(), J::A(frag_offsets.iter().map(|o| J::U(*o as u64)).collect())),
                ("order_ok".into(), J::B(order_ok)),
                ("seq_ok".into(), J::B(seq_ok)),
                ("coverage_ok".into(), J::B(coverage_ok)),
                ("payload_ok".into(), J::B(payload_ok)),
                ("options_consistent".into(), J::B(options_consistent)),
                ("fragments".into(), J::A(frag_records)),
            ]),
        ),
        (
            "detectors".into(),
            J::O(vec![
                (
                    "uneven_options".into(),
                    J::O(vec![
                        ("flag".into(), J::B(d1_flag)),
                        ("kinds_per_fragment".into(), J::A(frag_kinds.iter().map(|k| J::A(k.iter().map(|x| J::U(*x as u64)).collect())).collect())),
                    ]),
                ),
                (
                    "regular_gaps".into(),
                    J::O(vec![
                        ("flag".into(), J::B(d2.flag)),
                        ("gaps_ns".into(), J::A(d2.gaps_ns.iter().map(|g| J::U(*g)).collect())),
                        ("mean_ns".into(), J::F(d2.mean_ns)),
                        ("std_ns".into(), J::F(d2.std_ns)),
                        ("cov".into(), J::F(d2.cov)),
                        ("quantized_frac".into(), J::F(d2.quantized_frac)),
                        ("tick_ns".into(), J::U(1_000_000)),
                        ("quantize_tolerance_ns".into(), J::U(100_000)),
                        ("low_cov_min_mean_ns".into(), J::U(500_000)),
                    ]),
                ),
                (
                    "window_stall".into(),
                    J::O(vec![
                        ("flag".into(), J::B(d3.flag)),
                        ("min_inbound_window".into(), d3.min_inbound_window.map(|w| J::U(w as u64)).unwrap_or(J::Null)),
                        ("min_outbound_window".into(), d3.min_outbound_window.map(|w| J::U(w as u64)).unwrap_or(J::Null)),
                        ("zero_window_seen".into(), J::B(d3.zero_window_seen)),
                        ("progress".into(), J::B(d3.progress)),
                        ("handshake_window_ms".into(), J::U(HANDSHAKE_WINDOW.as_millis() as u64)),
                    ]),
                ),
            ]),
        ),
        ("sent".into(), J::A(sent_records)),
        ("packets".into(), J::A(packet_records)),
        ("shielded_inbound".into(), J::U(shielded as u64)),
        ("interference".into(), J::B(shared.interference.load(Ordering::SeqCst))),
        ("notes".into(), J::A(notes.iter().map(J::s).collect())),
    ]);

    std::fs::write(run_dir.join("run.json"), run_json.pretty())
        .map_err(|e| format!("run.json write: {e}"))?;
    log.push(format!("artifacts written to {}", run_dir.display()));
    std::fs::write(run_dir.join("run.log"), log.join("\n") + "\n")
        .map_err(|e| format!("run.log write: {e}"))?;

    let summary = J::O(vec![
        ("run_id".into(), J::s(&run_id)),
        ("kind".into(), J::s(ctx.kind)),
        ("site".into(), J::s(site)),
        ("arm".into(), J::s(arm.name)),
        ("level".into(), J::s(level_name(arm.level))),
        ("outcome".into(), J::s(&outcome)),
        ("latency_ms".into(), latency_ms.map(J::F).unwrap_or(J::Null)),
        ("fragment_count".into(), J::U(fragment_count as u64)),
        ("order_ok".into(), J::B(order_ok)),
        ("seq_ok".into(), J::B(seq_ok)),
        ("options_consistent".into(), J::B(options_consistent)),
        ("d1_uneven_options".into(), J::B(d1_flag)),
        ("d2_regular_gaps".into(), J::B(d2.flag)),
        ("d3_window_stall".into(), J::B(d3.flag)),
        ("started_utc".into(), J::s(format_utc(started))),
        ("base_sha".into(), J::s(BASE_SHA)),
    ]);
    Ok(RunResult { summary, run_id })
}

// ---------------------------------------------------------------------------
// Session driver: master table (JSONL + CSV), session.json, manifest.sha256.
// ---------------------------------------------------------------------------

const CSV_HEADER: &str = "run_id,kind,site,arm,level,outcome,latency_ms,fragment_count,order_ok,seq_ok,options_consistent,d1_uneven_options,d2_regular_gaps,d3_window_stall,started_utc,base_sha";

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_row(summary: &J) -> String {
    let g = |k: &str| summary.get(k);
    let s = |k: &str| g(k).and_then(|v| v.as_str()).unwrap_or("");
    let b = |k: &str| g(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let lat = g("latency_ms").and_then(|v| v.as_f64()).map(|f| format!("{f:.3}")).unwrap_or_default();
    let frag = g("fragment_count").and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
    [
        csv_field(s("run_id")),
        csv_field(s("kind")),
        csv_field(s("site")),
        csv_field(s("arm")),
        csv_field(s("level")),
        csv_field(s("outcome")),
        lat,
        frag.to_string(),
        b("order_ok").to_string(),
        b("seq_ok").to_string(),
        b("options_consistent").to_string(),
        b("d1_uneven_options").to_string(),
        b("d2_regular_gaps").to_string(),
        b("d3_window_stall").to_string(),
        csv_field(s("started_utc")),
        csv_field(s("base_sha")),
    ]
    .join(",")
}

fn append_master(out_dir: &Path, summary: &J) -> Result<(), String> {
    let jsonl_path = out_dir.join("master.jsonl");
    let mut jsonl = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&jsonl_path)
        .map_err(|e| format!("master.jsonl open: {e}"))?;
    writeln!(jsonl, "{}", summary.compact()).map_err(|e| format!("master.jsonl write: {e}"))?;
    let csv_path = out_dir.join("master.csv");
    let new_csv = !csv_path.exists();
    let mut csv = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&csv_path)
        .map_err(|e| format!("master.csv open: {e}"))?;
    if new_csv {
        writeln!(csv, "{CSV_HEADER}").map_err(|e| format!("master.csv header: {e}"))?;
    }
    writeln!(csv, "{}", csv_row(summary)).map_err(|e| format!("master.csv write: {e}"))?;
    Ok(())
}

fn write_manifest(out_dir: &Path) -> Result<usize, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, files)?;
            } else if entry.file_name() != "manifest.sha256" {
                files.push(path);
            }
        }
        Ok(())
    }
    walk(out_dir, &mut files).map_err(|e| format!("manifest walk: {e}"))?;
    files.sort();
    let mut lines = Vec::new();
    for path in &files {
        let data = std::fs::read(path).map_err(|e| format!("manifest read {}: {e}", path.display()))?;
        let rel = path
            .strip_prefix(out_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        lines.push(format!("{}  {}", sha256_hex(&data), rel));
    }
    std::fs::write(out_dir.join("manifest.sha256"), lines.join("\n") + "\n")
        .map_err(|e| format!("manifest write: {e}"))?;
    Ok(files.len())
}

fn git_head() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn run_session(
    kind: &'static str,
    out_dir: &Path,
    site: &str,
    arms: &[Arm],
    count_per_arm: usize,
    session_cap: usize,
) -> Result<(), String> {
    std::fs::create_dir_all(out_dir.join("runs")).map_err(|e| format!("out dir: {e}"))?;
    let dll = levi::ensure_driver_extracted()?;
    let api = Arc::new(WinDivertApi::load(&dll)?);
    let qpc = Arc::new(Qpc::new()?);
    let anchor_utc = SystemTime::now();
    let anchor_qpc = qpc.now();
    let ctx = SessionCtx {
        kind,
        out_dir: out_dir.to_path_buf(),
        api,
        qpc,
        gate: Mutex::new(SafetyGate::new(session_cap)),
        harness_commit: git_head(),
        anchor_utc,
        anchor_qpc,
    };

    println!("[{kind}] session start: site={site} arms={} count_per_arm={count_per_arm} out={}",
        arms.iter().map(|a| a.name).collect::<Vec<_>>().join(","),
        out_dir.display());
    if kind == "SMOKE" {
        println!("[SMOKE] machinery proof only - NOT evidence, outside any evidence manifest.");
    }

    let mut summaries: Vec<J> = Vec::new();
    let mut blockers: Vec<String> = Vec::new();
    let mut seq_no = 0usize;
    'session: for arm in arms {
        for _ in 0..count_per_arm {
            seq_no += 1;
            let mut attempt = 0;
            loop {
                attempt += 1;
                match run_one(&ctx, site, *arm, seq_no) {
                    Ok(r) => {
                        append_master(out_dir, &r.summary)?;
                        println!(
                            "[{kind}] {} outcome={} latency_ms={:?}",
                            r.run_id,
                            r.summary.get("outcome").and_then(|v| v.as_str()).unwrap_or("?"),
                            r.summary.get("latency_ms").and_then(|v| v.as_f64())
                        );
                        summaries.push(r.summary);
                        break;
                    }
                    Err(e) if e == "PORT_COLLISION" && attempt < 3 => {
                        println!("[{kind}] port collision, retrying with a fresh port (attempt {attempt})");
                        continue;
                    }
                    Err(e) => {
                        let is_interference = e.starts_with("INTERFERENCE");
                        blockers.push(format!("{} arm={} seq={seq_no}: {e}", site, arm.name));
                        eprintln!("[{kind}] BLOCKER: {e}");
                        if is_interference {
                            break 'session;
                        }
                        break;
                    }
                }
            }
            // Spacing between handshakes to the same target is enforced by the
            // gate; wait it out here so sequential runs proceed.
            std::thread::sleep(MIN_SPACING);
        }
    }

    let session = J::O(vec![
        ("kind".into(), J::s(kind)),
        ("tool".into(), J::s("levi_measure")),
        ("unit".into(), J::s("L2-unit2")),
        ("base_sha".into(), J::s(BASE_SHA)),
        ("harness_commit".into(), J::s(&ctx.harness_commit)),
        ("site".into(), J::s(site)),
        ("started_utc".into(), J::s(format_utc(anchor_utc))),
        ("finished_utc".into(), J::s(format_utc(SystemTime::now()))),
        ("qpc_freq".into(), J::I(ctx.qpc.freq)),
        ("qpc_anchor_utc".into(), J::s(format_utc(anchor_utc))),
        ("qpc_anchor".into(), J::I(anchor_qpc)),
        (
            "safety".into(),
            J::O(vec![
                ("hourly_cap_per_target".into(), J::U(HOURLY_CAP as u64)),
                ("min_spacing_ms".into(), J::U(MIN_SPACING.as_millis() as u64)),
                ("handshake_window_ms".into(), J::U(HANDSHAKE_WINDOW.as_millis() as u64)),
                ("session_cap".into(), J::U(session_cap as u64)),
            ]),
        ),
        ("runs".into(), J::A(summaries.clone())),
        ("blockers".into(), J::A(blockers.iter().map(J::s).collect())),
        (
            "note".into(),
            J::s(if kind == "SMOKE" {
                "SMOKE: machinery proof, never evidence; kept outside the evidence manifest."
            } else {
                "EVIDENCE session; runs count only under the approved lists and the landing review."
            }),
        ),
    ]);
    std::fs::write(out_dir.join("session.json"), session.pretty())
        .map_err(|e| format!("session.json: {e}"))?;
    let n = write_manifest(out_dir)?;
    println!("[{kind}] session end: {} runs, {} blockers, manifest covers {n} files", summaries.len(), blockers.len());
    if !blockers.is_empty() {
        return Err(format!("session finished with {} blocker(s); see session.json", blockers.len()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// compare: offline re-derivation over the master table (plan section i).
// ---------------------------------------------------------------------------

fn cmd_compare(dir: &Path, site_filter: Option<&str>) -> Result<(), String> {
    let master = std::fs::read_to_string(dir.join("master.jsonl"))
        .map_err(|e| format!("read master.jsonl: {e}"))?;
    let mut runs: Vec<J> = Vec::new();
    for line in master.lines() {
        if line.trim().is_empty() {
            continue;
        }
        runs.push(json_parse(line)?);
    }

    struct ArmStats {
        n: usize,
        successes: usize,
        latencies: Vec<f64>,
        d1: usize,
        d2: usize,
        d3: usize,
        run_ids: Vec<String>,
    }
    let mut groups: BTreeMap<(String, String), ArmStats> = BTreeMap::new();
    for r in &runs {
        let site = r.get("site").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Some(f) = site_filter {
            if site != f {
                continue;
            }
        }
        let arm = r.get("arm").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let st = groups.entry((site, arm)).or_insert(ArmStats {
            n: 0,
            successes: 0,
            latencies: Vec::new(),
            d1: 0,
            d2: 0,
            d3: 0,
            run_ids: Vec::new(),
        });
        st.n += 1;
        if r.get("outcome").and_then(|v| v.as_str()) == Some("success") {
            st.successes += 1;
            if let Some(l) = r.get("latency_ms").and_then(|v| v.as_f64()) {
                st.latencies.push(l);
            }
        }
        if r.get("d1_uneven_options").and_then(|v| v.as_bool()) == Some(true) {
            st.d1 += 1;
        }
        if r.get("d2_regular_gaps").and_then(|v| v.as_bool()) == Some(true) {
            st.d2 += 1;
        }
        if r.get("d3_window_stall").and_then(|v| v.as_bool()) == Some(true) {
            st.d3 += 1;
        }
        st.run_ids.push(r.get("run_id").and_then(|v| v.as_str()).unwrap_or("").to_string());
    }

    let mut sites: Vec<String> = groups.keys().map(|(s, _)| s.clone()).collect();
    sites.sort();
    sites.dedup();

    let mut site_objs = Vec::new();
    for site in &sites {
        let mut arm_objs = Vec::new();
        let fast = groups.get(&(site.clone(), "fast".to_string()));
        let fast_median = fast.and_then(|f| {
            let mut l = f.latencies.clone();
            l.sort_by(|a, b| a.partial_cmp(b).unwrap());
            percentile_nearest_rank(&l, 0.5)
        });
        let fast_p95 = fast.and_then(|f| {
            let mut l = f.latencies.clone();
            l.sort_by(|a, b| a.partial_cmp(b).unwrap());
            percentile_nearest_rank(&l, 0.95)
        });
        for ((s, arm), st) in &groups {
            if s != site {
                continue;
            }
            let mut l = st.latencies.clone();
            l.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let median = percentile_nearest_rank(&l, 0.5);
            let p95 = percentile_nearest_rank(&l, 0.95);
            let is_fast = arm == "fast";
            let delta_median = match (median, fast_median) {
                (Some(m), Some(f)) if !is_fast => Some(m - f),
                _ => None,
            };
            let delta_p95 = match (p95, fast_p95) {
                (Some(m), Some(f)) if !is_fast => Some(m - f),
                _ => None,
            };
            let anomalies = if is_fast {
                J::Null
            } else {
                let (f1, f2, f3) = fast.map(|f| (f.d1, f.d2, f.d3)).unwrap_or((0, 0, 0));
                J::O(vec![
                    ("uneven_options".into(), J::B(new_anomaly(st.d1, f1))),
                    ("regular_gaps".into(), J::B(new_anomaly(st.d2, f2))),
                    ("window_stall".into(), J::B(new_anomaly(st.d3, f3))),
                    ("fast_flag_counts".into(), J::A(vec![J::U(f1 as u64), J::U(f2 as u64), J::U(f3 as u64)])),
                ])
            };
            arm_objs.push(J::O(vec![
                ("arm".into(), J::s(arm)),
                ("n".into(), J::U(st.n as u64)),
                ("successes".into(), J::U(st.successes as u64)),
                ("success_rate".into(), J::F(st.successes as f64 / st.n as f64)),
                ("median_ms".into(), median.map(J::F).unwrap_or(J::Null)),
                ("p95_ms".into(), p95.map(J::F).unwrap_or(J::Null)),
                ("raw_latencies_ms".into(), J::A(l.iter().map(|v| J::F(*v)).collect())),
                ("delta_median_vs_fast_ms".into(), delta_median.map(J::F).unwrap_or(J::Null)),
                ("delta_p95_vs_fast_ms".into(), delta_p95.map(J::F).unwrap_or(J::Null)),
                ("detector_flag_counts".into(), J::A(vec![J::U(st.d1 as u64), J::U(st.d2 as u64), J::U(st.d3 as u64)])),
                ("new_anomalies_vs_fast".into(), anomalies),
                ("run_ids".into(), J::A(st.run_ids.iter().map(J::s).collect())),
            ]));
        }
        site_objs.push(J::O(vec![
            ("site".into(), J::s(site)),
            ("arms".into(), J::A(arm_objs)),
        ]));
    }

    let out = J::O(vec![
        ("source".into(), J::s(dir.join("master.jsonl").to_string_lossy())),
        ("generated_utc".into(), J::s(format_utc(SystemTime::now()))),
        ("percentile_method".into(), J::s("nearest-rank")),
        ("sites".into(), J::A(site_objs)),
    ]);
    let path = dir.join("comparison.json");
    std::fs::write(&path, out.pretty()).map_err(|e| format!("comparison.json: {e}"))?;
    println!("comparison written to {}", path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn usage() {
    eprintln!(
        "levi_measure - Levi Adaptive L2 measurement harness (Unit 2)\n\
         \n\
         USAGE:\n\
         \x20 levi_measure smoke [--out DIR]\n\
         \x20     <=2 handshakes to example.com (fast + hardened). SMOKE, never evidence.\n\
         \x20 levi_measure run --target SITE --arm ARM [--count N] [--out DIR]\n\
         \x20                  [--session-cap N] --confirm-approved\n\
         \x20     Evidence mode. SITE must be on the approved clean-site list.\n\
         \x20     Arms: fast hardened ultra hardened-delay hardened-window ultra-delay ultra-window\n\
         \x20 levi_measure compare --dir DIR [--site SITE]\n\
         \x20     Offline re-derivation over master.jsonl -> comparison.json.\n\
         \n\
         Item 1 (RST-set success rate) has no arm: the RST set is EMPTY pending the\n\
         owner's ruling. balanced_cut_variant has no arm: NO DATA on all items."
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(|s| s.as_str()) {
        Some("smoke") => {
            let out = flag_value(&args, "--out")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\projects\levi-measure-pkg\smoke"));
            run_session(
                "SMOKE",
                &out,
                "example.com",
                &[arm_by_name("fast").unwrap(), arm_by_name("hardened").unwrap()],
                1,
                2,
            )
        }
        Some("run") => {
            if !has_flag(&args, "--confirm-approved") {
                eprintln!("run requires --confirm-approved (attestation that Garen approved the target list).");
                std::process::exit(2);
            }
            let Some(target) = flag_value(&args, "--target") else {
                eprintln!("run requires --target SITE");
                std::process::exit(2);
            };
            if !approved_site(&target) {
                eprintln!("target {target} is not on the approved clean-site list: {}", CLEAN_SITES.join(", "));
                std::process::exit(2);
            }
            let Some(arm_name) = flag_value(&args, "--arm") else {
                eprintln!("run requires --arm ARM");
                std::process::exit(2);
            };
            let Some(arm) = arm_by_name(&arm_name) else {
                eprintln!("unknown arm {arm_name}");
                std::process::exit(2);
            };
            let count = flag_value(&args, "--count")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_N)
                .clamp(1, DEFAULT_N);
            let session_cap = flag_value(&args, "--session-cap")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_SESSION_CAP)
                .clamp(1, MAX_SESSION_CAP);
            let out = flag_value(&args, "--out")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\projects\levi-measure-pkg\evidence"));
            run_session("EVIDENCE", &out, &target, &[arm], count, session_cap)
        }
        Some("compare") => {
            let Some(dir) = flag_value(&args, "--dir") else {
                eprintln!("compare requires --dir DIR");
                std::process::exit(2);
            };
            cmd_compare(Path::new(&dir), flag_value(&args, "--site").as_deref())
        }
        _ => {
            usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests: pcap byte lock, SHA-256 vectors, JSON, safety caps, detectors,
// builder layout, arm plans, pinning through the merged public API.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use levi::adaptive::{EmitSink, OutboundHello, GATED_INTER_DELAY, GATED_WINDOW};

    fn test_flow(n: u16) -> FlowKey {
        flow_key_v4(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            40000 + n,
            443,
        )
    }

    fn sample_hello() -> Vec<u8> {
        build_client_hello("example.com", &mut Rng::new(42))
    }

    // ---- pcap byte lock -------------------------------------------------

    #[test]
    fn pcap_global_header_byte_lock() {
        let h = pcap_global_header();
        let expected: [u8; 24] = [
            0xD4, 0xC3, 0xB2, 0xA1, // magic 0xA1B2C3D4, little-endian on disk
            0x02, 0x00, // version major 2
            0x04, 0x00, // version minor 4
            0x00, 0x00, 0x00, 0x00, // thiszone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0xFF, 0xFF, 0x00, 0x00, // snaplen 65535
            0x65, 0x00, 0x00, 0x00, // network 101 (LINKTYPE_RAW)
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn pcap_record_roundtrip() {
        let path = std::env::temp_dir().join(format!("levi_measure_test_{}.pcap", std::process::id()));
        let mut w = PcapWriter::create(&path).unwrap();
        let pkt1 = vec![0x45u8, 0x00, 0x00, 0x28];
        let pkt2 = vec![0x60u8; 60];
        w.write_packet(1_700_000_000, 123_456, &pkt1).unwrap();
        w.write_packet(1_700_000_001, 654_321, &pkt2).unwrap();
        drop(w);
        let data = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(&data[..24], &pcap_global_header());
        let r1 = &data[24..40];
        assert_eq!(u32::from_le_bytes(r1[0..4].try_into().unwrap()), 1_700_000_000);
        assert_eq!(u32::from_le_bytes(r1[4..8].try_into().unwrap()), 123_456);
        assert_eq!(u32::from_le_bytes(r1[8..12].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(r1[12..16].try_into().unwrap()), 4);
        assert_eq!(&data[40..44], &pkt1);
        let r2 = &data[44..60];
        assert_eq!(u32::from_le_bytes(r2[0..4].try_into().unwrap()), 1_700_000_001);
        assert_eq!(u32::from_le_bytes(r2[4..8].try_into().unwrap()), 654_321);
        assert_eq!(u32::from_le_bytes(r2[8..12].try_into().unwrap()), 60);
        assert_eq!(&data[60..120], &pkt2);
        assert_eq!(data.len(), 24 + 16 + 4 + 16 + 60);
    }

    // ---- SHA-256 NIST vectors -------------------------------------------

    #[test]
    fn sha256_nist_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_nist_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_nist_448bit() {
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_multi_block() {
        let data = vec![0x61u8; 1_000_000];
        assert_eq!(
            sha256_hex(&data),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // ---- JSON -------------------------------------------------------------

    #[test]
    fn json_escape_control_and_quotes() {
        let mut out = String::new();
        json_escape("a\"b\\c\nd\te\u{0001}", &mut out);
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\\u0001\"");
    }

    #[test]
    fn json_roundtrip() {
        let v = J::O(vec![
            ("s".into(), J::s("héllo \"world\"\n")),
            ("i".into(), J::I(-5)),
            ("u".into(), J::U(u64::MAX)),
            ("f".into(), J::F(1.5)),
            ("b".into(), J::B(true)),
            ("n".into(), J::Null),
            ("a".into(), J::A(vec![J::I(1), J::s("x")])),
        ]);
        let parsed = json_parse(&v.compact()).unwrap();
        assert_eq!(parsed.compact(), v.compact());
        let parsed_pretty = json_parse(&v.pretty()).unwrap();
        assert_eq!(parsed_pretty.compact(), v.compact());
    }

    #[test]
    fn json_parse_rejects_garbage() {
        assert!(json_parse("{").is_err());
        assert!(json_parse("[1,]").is_err());
        assert!(json_parse("tru").is_err());
        assert!(json_parse("{} x").is_err());
    }

    // ---- Safety gate ------------------------------------------------------

    #[test]
    fn cap_allows_60_blocks_61() {
        let mut gate = SafetyGate::new(1000);
        let t0 = Instant::now();
        for i in 0..60 {
            gate.check("example.com", t0 + Duration::from_secs(i * 3)).unwrap();
        }
        let err = gate.check("example.com", t0 + Duration::from_secs(180)).unwrap_err();
        assert!(err.contains("hourly cap"));
    }

    #[test]
    fn cap_sliding_window_expires() {
        let mut gate = SafetyGate::new(1000);
        let t0 = Instant::now();
        for i in 0..60 {
            gate.check("example.com", t0 + Duration::from_secs(i * 3)).unwrap();
        }
        // First entry was at t0; one hour + 1 s later it has slid out.
        gate.check("example.com", t0 + Duration::from_secs(3601)).unwrap();
    }

    #[test]
    fn spacing_enforced() {
        let mut gate = SafetyGate::new(1000);
        let t0 = Instant::now();
        gate.check("example.com", t0).unwrap();
        assert!(gate.check("example.com", t0 + Duration::from_millis(1999)).is_err());
        gate.check("example.com", t0 + Duration::from_secs(2)).unwrap();
        // Different target is independent.
        gate.check("google.com", t0 + Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn session_cap_hard_stop() {
        let mut gate = SafetyGate::new(2);
        let t0 = Instant::now();
        gate.check("example.com", t0).unwrap();
        gate.check("example.com", t0 + Duration::from_secs(3)).unwrap();
        let err = gate.check("example.com", t0 + Duration::from_secs(6)).unwrap_err();
        assert!(err.contains("session cap"));
    }

    #[test]
    fn allowlist_enforced() {
        for s in CLEAN_SITES {
            assert!(approved_site(s));
        }
        assert!(!approved_site("bbc.com"));
        assert!(!approved_site("instagram.com"));
        assert!(!approved_site("medium.com"));
        assert!(!approved_site("sub.example.com"));
        assert!(!approved_site("evil-example.com"));
    }

    // ---- ClientHello builder and cuts -------------------------------------

    #[test]
    fn hello_builder_is_parseable() {
        let hello = sample_hello();
        assert!(tls::is_client_hello(&hello));
        let info = tls::parse_client_hello(&hello).unwrap();
        assert_eq!(info.sni, Some("example.com"));
        assert!(info.sni_offset.is_some());
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len + 5, hello.len());
        let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        assert_eq!(hs_len + 9, hello.len());
    }

    #[test]
    fn cuts_three_and_four_segments() {
        let hello = sample_hello();
        let c3 = cuts_for_arm(AdaptiveLevel::Hardened, &hello).unwrap();
        assert_eq!(c3.len(), 2);
        let c4 = cuts_for_arm(AdaptiveLevel::Ultra, &hello).unwrap();
        assert_eq!(c4.len(), 3);
        assert!(c4.windows(2).all(|w| w[0] < w[1]));
        assert!(*c4.last().unwrap() < hello.len());
        assert_eq!(c4[..2], c3[..]);
        // Ultra plan requires exactly 4 segments.
        let cfg = arm_cfg(arm_by_name("ultra").unwrap());
        assert!(adaptive::plan_for(AdaptiveLevel::Ultra, &c4, &cfg).is_some());
        assert!(adaptive::plan_for(AdaptiveLevel::Ultra, &c3, &cfg).is_none());
    }

    // ---- Arm plans match the section g matrix ------------------------------

    #[test]
    fn arm_plans_match_matrix() {
        let hello = sample_hello();
        let expect = |arm: &str, order: SegmentOrder, delay_ms: u64, window: Option<(u16, u8)>| {
            let a = arm_by_name(arm).unwrap();
            let cuts = cuts_for_arm(a.level, &hello).unwrap();
            let plan = adaptive::plan_for(a.level, &cuts, &arm_cfg(a)).unwrap();
            assert_eq!(plan.order, order, "arm {arm} order");
            assert_eq!(plan.inter_delay, Duration::from_millis(delay_ms), "arm {arm} delay");
            assert_eq!(plan.window_override, window, "arm {arm} window");
        };
        expect("fast", SegmentOrder::InOrder, 0, None);
        expect("hardened", SegmentOrder::Reverse, 0, None);
        expect("ultra", SegmentOrder::Fixed([4, 2, 3, 1]), 0, None);
        expect("hardened-delay", SegmentOrder::Reverse, 1, None);
        expect("hardened-window", SegmentOrder::Reverse, 0, Some(GATED_WINDOW));
        expect("ultra-delay", SegmentOrder::Fixed([4, 2, 3, 1]), 1, None);
        expect("ultra-window", SegmentOrder::Fixed([4, 2, 3, 1]), 0, Some(GATED_WINDOW));
        assert_eq!(GATED_INTER_DELAY, Duration::from_millis(1));
        assert_eq!(GATED_WINDOW, (0b0001, 1));
    }

    #[test]
    fn pinning_seed_drives_enqueue_through_public_api() {
        struct RecordingSink(Mutex<Vec<OutboundHello>>);
        impl EmitSink for RecordingSink {
            fn enqueue(&self, hello: OutboundHello) {
                self.0.lock().unwrap().push(hello);
            }
            fn cancel_flow(&self, _: &FlowKey) {}
            fn cancel_all(&self) {}
        }
        let sink = Arc::new(RecordingSink(Mutex::new(Vec::new())));
        let mut maps = AdaptiveMaps::with_sink(sink.clone());
        let hello = sample_hello();
        for arm_name in ["hardened", "ultra", "hardened-window"] {
            let a = arm_by_name(arm_name).unwrap();
            let cfg = arm_cfg(a);
            let cuts = cuts_for_arm(a.level, &hello).unwrap();
            let flow = test_flow(1);
            maps.flow_map.insert(
                flow,
                EscalationState {
                    level: a.level,
                    success_streak: 0,
                    split_attempts: 0,
                    has_success: false,
                    last_seen: Instant::now(),
                    cooldown_until: None,
                    sni_key: adaptive::normalize_sni("example.com"),
                },
            );
            assert_eq!(maps.current_level(&flow, Some("example.com"), &cfg, Instant::now()), a.level);
            let action = maps.on_client_hello(
                &ClientHello {
                    flow,
                    sni: Some("example.com"),
                    compat_mode: false,
                    custom_excluded: &[],
                    seq: 1000,
                    payload: hello.clone(),
                    cuts: cuts.clone(),
                },
                &cfg,
                Instant::now(),
            );
            assert_eq!(action, ClientHelloAction::Enqueued, "arm {arm_name}");
            let recorded = sink.0.lock().unwrap().pop().unwrap();
            let expected = adaptive::plan_for(a.level, &cuts, &cfg).unwrap();
            assert_eq!(recorded.plan.order, expected.order);
            assert_eq!(recorded.plan.inter_delay, expected.inter_delay);
            assert_eq!(recorded.plan.window_override, expected.window_override);
            assert_eq!(recorded.seq, 1000);
            maps.wipe();
        }
    }

    // ---- Segment id / window / seq ----------------------------------------

    #[test]
    fn segment_id_and_window_selection() {
        let cuts = vec![5usize, 118, 200];
        assert_eq!(segment_id_for_offset(&cuts, 0), 1);
        assert_eq!(segment_id_for_offset(&cuts, 5), 2);
        assert_eq!(segment_id_for_offset(&cuts, 118), 3);
        assert_eq!(segment_id_for_offset(&cuts, 200), 4);
        assert_eq!(fragment_window(Some(GATED_WINDOW), 1), 1);
        assert_eq!(fragment_window(Some(GATED_WINDOW), 2), 65535);
        assert_eq!(fragment_window(Some(GATED_WINDOW), 4), 65535);
        assert_eq!(fragment_window(None, 1), 65535);
    }

    #[test]
    fn seq_wrapping_arithmetic() {
        let base = u32::MAX - 10;
        let offset = 20u32;
        let seq = base.wrapping_add(offset);
        assert_eq!(seq, 9);
        assert_eq!(seq.wrapping_sub(base), offset);
    }

    // ---- TCP builder --------------------------------------------------------

    #[test]
    fn tcp_builder_roundtrip() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let payload = b"hello fragment";
        let pkt = build_tcp_packet(
            src, dst, 40000, 443, 12345, 67890, TCP_FLAG_ACK | TCP_FLAG_PSH, 1, 7,
            &ts_opts(111, 222), payload,
        );
        let parsed = ParsedPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.ip_version, 4);
        assert_eq!(parsed.src_port, 40000);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.tcp_seq, 12345);
        assert_eq!(parsed.tcp_ack, 67890);
        assert_eq!(parsed.tcp_flags, TCP_FLAG_ACK | TCP_FLAG_PSH);
        assert_eq!(parsed.payload, payload);
        let hdr = &pkt[parsed.ip_header_len..parsed.ip_header_len + parsed.tcp_header_len];
        assert_eq!(tcp_option_kinds(hdr), vec![1, 1, 8]);
        assert_eq!(tcp_ts_val(hdr), Some(111));
        let window = u16::from_be_bytes([pkt[parsed.ip_header_len + 14], pkt[parsed.ip_header_len + 15]]);
        assert_eq!(window, 1);
    }

    #[test]
    fn syn_option_kinds_and_ts_extraction() {
        let opts = syn_opts(999);
        let mut hdr = vec![0u8; 20];
        hdr.extend_from_slice(&opts);
        assert_eq!(tcp_option_kinds(&hdr), vec![2, 1, 8, 1]);
        assert_eq!(tcp_ts_val(&hdr), Some(999));
        let mut no_ts = vec![0u8; 20];
        no_ts.extend_from_slice(&[1, 1, 0]);
        assert_eq!(tcp_ts_val(&no_ts), None);
    }

    // ---- Detectors -----------------------------------------------------------

    #[test]
    fn d1_consistent_options_no_flag() {
        let kinds = vec![vec![1u8, 1, 8], vec![1, 1, 8], vec![8, 1, 1]];
        assert!(!detect_uneven_options(&kinds));
    }

    #[test]
    fn d1_uneven_options_flag() {
        let kinds = vec![vec![1u8, 1, 8], vec![1, 1, 8, 3]];
        assert!(detect_uneven_options(&kinds));
        let kinds2 = vec![vec![1u8, 1, 8], vec![1, 1]];
        assert!(detect_uneven_options(&kinds2));
    }

    #[test]
    fn d2_fast_back_to_back_no_flag() {
        // Sub-0.5 ms spacing is the Fast signature, even when very regular.
        let gaps = vec![40_000u64, 42_000, 41_000, 40_500];
        let s = detect_regular_gaps(&gaps);
        assert!(!s.flag);
        // Irregular mixed gaps: high CoV, no quantization.
        let gaps2 = vec![300_000u64, 1_700_000, 400_000, 2_300_000];
        assert!(!detect_regular_gaps(&gaps2).flag);
    }

    #[test]
    fn d2_quantized_tick_flag() {
        let gaps = vec![1_000_000u64, 1_010_000, 995_000, 1_005_000];
        let s = detect_regular_gaps(&gaps);
        assert!(s.flag);
        assert!(s.quantized_frac >= 0.8);
    }

    #[test]
    fn d2_low_cov_in_tick_regime_flag() {
        let gaps = vec![5_000_000u64, 5_010_000, 4_990_000, 5_000_000];
        let s = detect_regular_gaps(&gaps);
        assert!(s.flag);
        assert!(s.cov < 0.05);
    }

    #[test]
    fn d2_single_gap_no_flag() {
        assert!(!detect_regular_gaps(&[1_000_000]).flag);
        assert!(!detect_regular_gaps(&[]).flag);
    }

    #[test]
    fn d3_window_stall_logic() {
        let s = detect_window_stall(Some(65535), Some(65535), false);
        assert!(!s.flag && !s.zero_window_seen);
        let s = detect_window_stall(Some(0), Some(65535), false);
        assert!(s.flag && s.zero_window_seen);
        let s = detect_window_stall(Some(0), Some(65535), true);
        assert!(!s.flag);
        // The gated override advertises window=1, not zero: no flag by itself.
        let s = detect_window_stall(Some(64240), Some(1), false);
        assert!(!s.flag && !s.zero_window_seen);
    }

    // ---- Comparison logic ------------------------------------------------------

    #[test]
    fn percentile_nearest_rank_values() {
        let v: Vec<f64> = (1..=10).map(|x| x as f64).collect();
        assert_eq!(percentile_nearest_rank(&v, 0.5), Some(5.0));
        assert_eq!(percentile_nearest_rank(&v, 0.95), Some(10.0));
        assert_eq!(percentile_nearest_rank(&[7.0], 0.5), Some(7.0));
        assert_eq!(percentile_nearest_rank(&[], 0.5), None);
        let w = vec![1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile_nearest_rank(&w, 0.5), Some(2.0));
        assert_eq!(percentile_nearest_rank(&w, 0.95), Some(4.0));
    }

    #[test]
    fn new_anomaly_requires_gated_flag_and_clean_fast() {
        assert!(new_anomaly(3, 0));
        assert!(!new_anomaly(0, 0));
        assert!(!new_anomaly(3, 1));
        assert!(!new_anomaly(0, 2));
    }

    // ---- CSV / manifest -----------------------------------------------------------

    #[test]
    fn csv_row_format_and_quoting() {
        let summary = J::O(vec![
            ("run_id".into(), J::s("r1")),
            ("kind".into(), J::s("SMOKE")),
            ("site".into(), J::s("example.com")),
            ("arm".into(), J::s("fast")),
            ("level".into(), J::s("Fast")),
            ("outcome".into(), J::s("success")),
            ("latency_ms".into(), J::F(12.5)),
            ("fragment_count".into(), J::U(3)),
            ("order_ok".into(), J::B(true)),
            ("seq_ok".into(), J::B(true)),
            ("options_consistent".into(), J::B(true)),
            ("d1_uneven_options".into(), J::B(false)),
            ("d2_regular_gaps".into(), J::B(false)),
            ("d3_window_stall".into(), J::B(false)),
            ("started_utc".into(), J::s("2026-11-12T00:00:00.000Z")),
            ("base_sha".into(), J::s(BASE_SHA)),
        ]);
        let row = csv_row(&summary);
        assert_eq!(row.split(',').count(), CSV_HEADER.split(',').count());
        assert!(row.starts_with("r1,SMOKE,example.com,fast,Fast,success,12.500,3,true,true,true,false,false,false,"));
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn manifest_hash_line_format() {
        let dir = std::env::temp_dir().join(format!("levi_measure_manifest_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("runs")).unwrap();
        std::fs::write(dir.join("session.json"), b"{}").unwrap();
        std::fs::write(dir.join("runs").join("a.json"), b"abc").unwrap();
        let n = write_manifest(&dir).unwrap();
        assert_eq!(n, 2);
        let manifest = std::fs::read_to_string(dir.join("manifest.sha256")).unwrap();
        assert!(manifest.contains(&format!(
            "{}  runs/a.json",
            sha256_hex(b"abc")
        )));
        assert!(manifest.contains(&format!("{}  session.json", sha256_hex(b"{}"))));
        // The manifest never covers itself.
        assert!(!manifest.contains("manifest.sha256"));
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- UTC formatting -------------------------------------------------------------

    #[test]
    fn utc_formatting_known_epochs() {
        assert_eq!(format_utc(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_utc(UNIX_EPOCH + Duration::from_secs(86400)), "1970-01-02T00:00:00.000Z");
        assert_eq!(
            format_utc(UNIX_EPOCH + Duration::from_secs(1_735_689_600)),
            "2025-01-01T00:00:00.000Z"
        );
        assert_eq!(
            format_utc(UNIX_EPOCH + Duration::from_secs(1_735_689_600) + Duration::from_millis(123)),
            "2025-01-01T00:00:00.123Z"
        );
    }

    // ---- End-to-end machinery without the network ------------------------------------

    #[test]
    fn emit_queue_to_layout_expectations() {
        // The merged EmitQueue drives a recording sender; verify the harness's
        // layout expectations (offsets per order) against the real module.
        struct RecSender(Mutex<Vec<Fragment>>);
        impl FragmentSender for RecSender {
            fn send_fragment(&self, f: Fragment) {
                self.0.lock().unwrap().push(f);
            }
        }
        let sender = Arc::new(RecSender(Mutex::new(Vec::new())));
        let queue = EmitQueue::start(sender.clone());
        let hello = sample_hello();
        let flow = test_flow(9);
        let base = 5000u32;
        for (arm_name, expected_offsets) in [
            ("fast", vec![0usize, 5, 118]),
            ("hardened", vec![118, 5, 0]),
        ] {
            let a = arm_by_name(arm_name).unwrap();
            let cuts = cuts_for_arm(a.level, &hello).unwrap();
            let plan = adaptive::plan_for(a.level, &cuts, &arm_cfg(a)).unwrap();
            queue.enqueue(OutboundHello {
                flow,
                seq: base,
                payload: hello.clone(),
                cuts: cuts.clone(),
                plan,
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while sender.0.lock().unwrap().len() < 3 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            let frags: Vec<Fragment> = sender.0.lock().unwrap().drain(..).collect();
            assert_eq!(frags.len(), 3, "arm {arm_name}");
            let offsets: Vec<usize> = frags
                .iter()
                .map(|f| f.seq.wrapping_sub(base) as usize)
                .collect();
            // The SNI midpoint depends on the builder; recompute expected from cuts.
            let seg_offsets: Vec<usize> = std::iter::once(0).chain(cuts.iter().copied()).collect();
            let expected: Vec<usize> = match a.name {
                "fast" => seg_offsets.clone(),
                _ => seg_offsets.iter().copied().rev().collect(),
            };
            assert_eq!(offsets, expected, "arm {arm_name}");
            let _ = expected_offsets;
            for f in &frags {
                let off = f.seq.wrapping_sub(base) as usize;
                assert_eq!(f.seq, base.wrapping_add(off as u32));
            }
        }
        queue.shutdown();
    }
}

//! Levi Adaptive — adaptive TLS ClientHello fragmentation state machine (spec LOCKED).
//!
//! RAM-only, privacy-first: no disk persistence (M7 sticky is lost on restart by
//! design). This module is the adaptive *logic* only; it is not wired into the live
//! engine until the measurement gate (§11) is satisfied. The emit seam ([`EmitSink`])
//! is the single hand-off point to the companion emit layer.

use crate::{PassThroughReason, evaluate_pass_through, is_valid_fqdn_sni};
use std::borrow::Borrow;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Fragmentation aggression level. Ord is manual by discriminant so a variant
/// reorder can never silently flip semantics (§1.2); do not reorder variants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdaptiveLevel {
    Passthrough = -1,
    Fast = 0,
    Balanced = 1,
    Hardened = 2,
    Ultra = 3,
}

impl Ord for AdaptiveLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as i8).cmp(&(*other as i8))
    }
}

impl PartialOrd for AdaptiveLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AdaptiveLevel {
    /// One step up, saturating at Ultra.
    fn raised(self) -> Self {
        match self {
            AdaptiveLevel::Passthrough => AdaptiveLevel::Fast,
            AdaptiveLevel::Fast => AdaptiveLevel::Balanced,
            AdaptiveLevel::Balanced => AdaptiveLevel::Hardened,
            AdaptiveLevel::Hardened | AdaptiveLevel::Ultra => AdaptiveLevel::Ultra,
        }
    }

    /// One step down, flooring at Fast (only called when level > Fast).
    fn lowered(self) -> Self {
        match self {
            AdaptiveLevel::Ultra => AdaptiveLevel::Hardened,
            AdaptiveLevel::Hardened => AdaptiveLevel::Balanced,
            AdaptiveLevel::Balanced => AdaptiveLevel::Fast,
            AdaptiveLevel::Fast | AdaptiveLevel::Passthrough => AdaptiveLevel::Fast,
        }
    }
}

/// Per-flow identity. IPv4 uses the first 4 bytes + 12 zero (spec literal, V1);
/// `family` keeps dual-stack / multi-NIC / VPN flows from colliding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub family: u8,
}

/// Emit order of the original 1-based segment ids. Always a valid permutation of
/// `1..=segment_count` (invariant 4). No `strip_options` anywhere (invariant 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentOrder {
    InOrder,
    Reverse,
    Fixed([u8; 4]),
}

/// Fragmentation plan. `window_override` bitmask indexes ORIGINAL 1-based segment
/// ids (bit 0 = segment 1), never emit order.
#[derive(Debug, Clone)]
pub struct SegPlan {
    pub order: SegmentOrder,
    pub inter_delay: Duration,
    pub window_override: Option<(u16, u8)>,
}

/// Per-flow escalation state. `sni_key` is written at ClientHello and read from
/// state by inbound handlers (inbound packets carry no SNI); preserved on update (N1).
#[derive(Clone, Debug)]
pub struct EscalationState {
    pub level: AdaptiveLevel,
    pub success_streak: u8,
    pub split_attempts: u8,
    pub has_success: bool,
    pub last_seen: Instant,
    pub cooldown_until: Option<Instant>,
    pub sni_key: Option<String>,
}

/// Per-SNI sticky entry: level + decay in a single lookup (no third map).
#[derive(Clone, Copy, Debug)]
pub struct DomainEntry {
    pub level: AdaptiveLevel,
    pub decay: u8,
}

/// Measurement gate as parameters. Every deviation from Fast vanilla (order, delay,
/// window, Balanced cut placement) is gated; missing measurement => safe defaults.
#[derive(Clone, Copy, Debug)]
pub struct ProfileConfig {
    pub enabled_max_level: AdaptiveLevel,
    pub allow_inter_delay: bool,
    pub allow_window_override: bool,
    pub balanced_cut_variant: u8,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            enabled_max_level: AdaptiveLevel::Fast,
            allow_inter_delay: false,
            allow_window_override: false,
            balanced_cut_variant: 0,
        }
    }
}

pub const HANDSHAKE_WINDOW: Duration = Duration::from_millis(3500);
pub const ENTRY_TTL: Duration = Duration::from_secs(60);
pub const COOLDOWN_TTL: Duration = Duration::from_secs(45);
pub const MAX_ATTEMPTS: u8 = 4;
pub const SUCCESS_STREAK_DESCEND: u8 = 3;
pub const DOMAIN_STICKY_CAP: AdaptiveLevel = AdaptiveLevel::Balanced;
pub const DOMAIN_STICKY_DECAY_SUCCESSES: u8 = 5;
pub const FLOW_MAP_CAP: usize = 4096;
pub const DOMAIN_MAP_CAP: usize = 1024;

// Pin the §2 default values at compile time without adding test functions.
const _: () = {
    assert!(HANDSHAKE_WINDOW.as_millis() == 3500);
    assert!(ENTRY_TTL.as_secs() == 60);
    assert!(COOLDOWN_TTL.as_secs() == 45);
    assert!(MAX_ATTEMPTS == 4);
    assert!(SUCCESS_STREAK_DESCEND == 3);
    assert!(DOMAIN_STICKY_DECAY_SUCCESSES == 5);
    assert!(FLOW_MAP_CAP == 4096);
    assert!(DOMAIN_MAP_CAP == 1024);
    assert!(DOMAIN_STICKY_CAP as i8 == AdaptiveLevel::Balanced as i8);
};

/// Gated measurement sentinels (V4). Reachable only when the matching flag is on;
/// defaults keep them inert. The window mask bit 0 = original segment 1.
pub const GATED_INTER_DELAY: Duration = Duration::from_millis(1);
pub const GATED_WINDOW: (u16, u8) = (0b0001, 1);

fn gate_delay(cfg: &ProfileConfig) -> Duration {
    if cfg.allow_inter_delay {
        GATED_INTER_DELAY
    } else {
        Duration::ZERO
    }
}

fn gate_window(cfg: &ProfileConfig) -> Option<(u16, u8)> {
    if cfg.allow_window_override {
        Some(GATED_WINDOW)
    } else {
        None
    }
}

/// Whether the window bitmask includes an ORIGINAL 1-based segment id (bit 0 =
/// segment 1), independent of emit order. Ids outside 1..=16 are never included.
pub fn window_includes_segment(window: (u16, u8), segment_id: u8) -> bool {
    if segment_id == 0 || segment_id > 16 {
        return false;
    }
    (window.0 & (1u16 << (segment_id - 1))) != 0
}

/// Hand-rolled fixed-cap LRU: HashMap + VecDeque, front = MRU, touch = move-to-front.
/// No `lru` crate (M6). Touch is O(cap) worst-case, accepted because cap is bounded (MN1).
pub struct HandLru<K, V> {
    cap: usize,
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Clone + Eq + Hash, V> HandLru<K, V> {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Read without touching recency (used for staleness checks).
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.get(key)
    }

    /// Read and move-to-front.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.touch(key);
        self.map.get_mut(key)
    }

    /// Insert or update. Returns the evicted key (if any) so the caller can cancel
    /// its pending fragments. Updating an existing key never evicts.
    pub fn insert(&mut self, key: K, value: V) -> Option<K> {
        if self.map.contains_key(&key) {
            self.map.insert(key.clone(), value);
            self.touch(&key);
            return None;
        }
        let mut evicted = None;
        if self.map.len() >= self.cap {
            if let Some(old) = self.order.pop_back() {
                self.map.remove(&old);
                evicted = Some(old);
            }
        }
        self.map.insert(key.clone(), value);
        self.order.push_front(key);
        evicted
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let value = self.map.remove(key)?;
        if let Some(pos) = self.order.iter().position(|k| k.borrow() == key) {
            self.order.remove(pos);
        }
        Some(value)
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    fn touch<Q>(&mut self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        if let Some(pos) = self.order.iter().position(|k| k.borrow() == key) {
            if pos != 0 {
                if let Some(k) = self.order.remove(pos) {
                    self.order.push_front(k);
                }
            }
        }
    }
}

/// One enqueued ClientHello handed to the emit layer. `plan` carries the order /
/// delay / window; `cuts` are the payload split offsets. plan_for stays
/// `Option<SegPlan>` with no cuts field — cuts travel here (seam counter).
#[derive(Debug, Clone)]
pub struct OutboundHello {
    pub flow: FlowKey,
    pub seq: u32,
    pub payload: Vec<u8>,
    pub cuts: Vec<usize>,
    pub plan: SegPlan,
}

/// Emit seam. The companion layer owns the timing wheel / seq-offset preservation /
/// non-blocking capture loop; this module only enqueues and cancels.
pub trait EmitSink: Send + Sync {
    fn enqueue(&self, hello: OutboundHello);
    fn cancel_flow(&self, flow: &FlowKey);
    fn cancel_all(&self);
}

/// The two RAM-only maps plus the optional emit sink.
pub struct AdaptiveMaps {
    pub flow_map: HandLru<FlowKey, EscalationState>,
    pub domain_map: HandLru<String, DomainEntry>,
    pub sink: Option<Arc<dyn EmitSink>>,
}

impl Default for AdaptiveMaps {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveMaps {
    pub fn new() -> Self {
        Self {
            flow_map: HandLru::new(FLOW_MAP_CAP),
            domain_map: HandLru::new(DOMAIN_MAP_CAP),
            sink: None,
        }
    }

    pub fn with_sink(sink: Arc<dyn EmitSink>) -> Self {
        let mut maps = Self::new();
        maps.sink = Some(sink);
        maps
    }

    pub fn set_sink(&mut self, sink: Arc<dyn EmitSink>) {
        self.sink = Some(sink);
    }

    /// Dual-path level resolution (§4.1). Existing flow: lazy cooldown reset +
    /// clamp-at-read (BG3/MN3). New flow: read-only sticky capped at DOMAIN_STICKY_CAP,
    /// deliberately NOT clamped by enabled_max (V3); plan_for clamps defensively.
    pub fn current_level(
        &mut self,
        flow: &FlowKey,
        sni: Option<&str>,
        cfg: &ProfileConfig,
        now: Instant,
    ) -> AdaptiveLevel {
        self.expire_flow_if_stale(flow, now);
        if let Some(st) = self.flow_map.get_mut(flow) {
            if cooldown_expired(st, now) {
                st.level = AdaptiveLevel::Fast;
                st.cooldown_until = None;
            }
            st.level = st.level.min(cfg.enabled_max_level);
            return st.level;
        }
        let sticky = sni
            .and_then(normalize_sni)
            .and_then(|key| self.domain_map.get(key.as_str()).map(|e| e.level))
            .unwrap_or(AdaptiveLevel::Fast);
        sticky.min(DOMAIN_STICKY_CAP)
    }

    /// Outbound ClientHello (§4). Single passthrough path via evaluate_pass_through
    /// (§6/R3): Compat | NoSni | Custom | Doh send raw and create no entry.
    pub fn on_client_hello(
        &mut self,
        hello: &ClientHello,
        cfg: &ProfileConfig,
        now: Instant,
    ) -> ClientHelloAction {
        if is_passthrough_reason(hello) || compat_mode_forces_passthrough(hello) {
            return ClientHelloAction::SendRaw;
        }
        let level = self.current_level(&hello.flow, hello.sni, cfg, now);
        let cuts = cuts_for(level, &hello.cuts, cfg);
        match plan_for(level, &cuts, cfg) {
            Some(plan) => {
                self.create_or_update(&hello.flow, level, hello.sni, now);
                self.record_split_attempt(&hello.flow);
                if let Some(sink) = &self.sink {
                    sink.enqueue(OutboundHello {
                        flow: hello.flow,
                        seq: hello.seq,
                        payload: hello.payload.clone(),
                        cuts,
                        plan,
                    });
                }
                ClientHelloAction::Enqueued
            }
            None => ClientHelloAction::SendRaw,
        }
    }

    /// Inbound RST (§4). Companion invariant 6: cancel pending fragments on ANY RST
    /// BEFORE the window check, or the early return drops the cancel. Escalation
    /// itself is window-gated.
    pub fn on_rst(&mut self, flow: &FlowKey, in_window: bool, cfg: &ProfileConfig, now: Instant) {
        if let Some(sink) = &self.sink {
            sink.cancel_flow(flow);
        }
        if !in_window {
            return;
        }
        self.expire_flow_if_stale(flow, now);
        let st = match self.flow_map.get_mut(flow) {
            Some(st) => st,
            None => return, // G2: compat / never-split / expired => invisible
        };
        if st.level == AdaptiveLevel::Passthrough || in_cooldown(st, now) {
            refresh_cooldown(st, now); // G1/m3: absorb, keep hostile domain longer
            return;
        }
        if st.split_attempts >= MAX_ATTEMPTS && !st.has_success {
            set_passthrough(st, now); // MG3: bail never touches domain_map
            return;
        }
        // §4.2 escalate (cap-at-write) + domain raise / decay-reset. flow_map and
        // domain_map are disjoint fields, so both borrows coexist.
        st.level = st.level.raised().min(cfg.enabled_max_level);
        let new_level = st.level;
        if let Some(key) = st.sni_key.as_deref() {
            let capped = new_level.min(DOMAIN_STICKY_CAP);
            if let Some(entry) = self.domain_map.get_mut(key) {
                entry.decay = 0; // BG1: only consecutive successes count
                entry.level = capped;
            } else {
                self.domain_map.insert(
                    key.to_string(),
                    DomainEntry {
                        level: capped,
                        decay: 0,
                    },
                );
            }
        }
    }

    /// Inbound handshake success (§4). Reads sni_key from state. V7: decay sees the
    /// POST-descend level. MG5: decay applies at <= Fast INCLUDING Passthrough.
    pub fn on_handshake_complete(&mut self, flow: &FlowKey, now: Instant) {
        self.expire_flow_if_stale(flow, now);
        let st = match self.flow_map.get_mut(flow) {
            Some(st) => st,
            None => return,
        };
        st.has_success = true;
        if st.level > AdaptiveLevel::Fast {
            // MG2/invariant 8: streak only grows above Fast; saturating, never overflows.
            st.success_streak = st.success_streak.saturating_add(1);
            if st.success_streak >= SUCCESS_STREAK_DESCEND {
                descend(st);
            }
        }
        if let Some(key) = st.sni_key.as_deref() {
            if st.level <= AdaptiveLevel::Fast {
                if let Some(entry) = self.domain_map.get_mut(key) {
                    entry.decay = entry.decay.saturating_add(1);
                    if entry.decay >= DOMAIN_STICKY_DECAY_SUCCESSES {
                        entry.level = entry.level.lowered().max(AdaptiveLevel::Fast);
                        entry.decay = 0;
                    }
                }
            }
        }
    }

    /// Inbound handshake timeout (§4). Never escalates (invariant 5); never touches
    /// domain_map (MN2).
    pub fn on_handshake_timeout(&mut self, flow: &FlowKey, now: Instant) {
        self.expire_flow_if_stale(flow, now);
        let st = match self.flow_map.get_mut(flow) {
            Some(st) => st,
            None => return,
        };
        if st.level > AdaptiveLevel::Fast && st.split_attempts > 0 {
            descend(st);
        } else if st.level == AdaptiveLevel::Fast && st.split_attempts > 0 {
            set_passthrough(st, now);
        }
    }

    /// Engine stop (§4): wipe both RAM-only maps and cancel all pending emits.
    /// Creates no file (invariant 12 / M7).
    pub fn wipe(&mut self) {
        self.flow_map.clear();
        self.domain_map.clear();
        if let Some(sink) = &self.sink {
            sink.cancel_all();
        }
    }

    /// Create or update a flow entry (V2). On update preserve sni_key / success_streak
    /// / has_success / split_attempts, refresh last_seen, clear cooldown. N1: never
    /// overwrite an existing sni_key with None. Eviction cancels the evicted flow.
    fn create_or_update(
        &mut self,
        flow: &FlowKey,
        level: AdaptiveLevel,
        sni: Option<&str>,
        now: Instant,
    ) {
        if let Some(st) = self.flow_map.get_mut(flow) {
            st.level = level;
            st.last_seen = now;
            st.cooldown_until = None;
            if st.sni_key.is_none() {
                st.sni_key = sni.and_then(normalize_sni);
            }
            return;
        }
        let evicted = self.flow_map.insert(
            *flow,
            EscalationState {
                level,
                success_streak: 0,
                split_attempts: 0,
                has_success: false,
                last_seen: now,
                cooldown_until: None,
                sni_key: sni.and_then(normalize_sni),
            },
        );
        if let Some(evicted_flow) = evicted {
            if let Some(sink) = &self.sink {
                sink.cancel_flow(&evicted_flow);
            }
        }
    }

    /// Total emit-attempts in the flow's life; never reset per level (N2), saturating (R9).
    fn record_split_attempt(&mut self, flow: &FlowKey) {
        if let Some(st) = self.flow_map.get_mut(flow) {
            st.split_attempts = st.split_attempts.saturating_add(1);
        }
    }

    /// Lazy TTL expiry on access (R5/G2): an entry older than ENTRY_TTL is dropped
    /// (cancelling pending fragments, V5) and treated as absent. No background thread.
    fn expire_flow_if_stale(&mut self, flow: &FlowKey, now: Instant) {
        let stale = self
            .flow_map
            .get(flow)
            .is_some_and(|st| elapsed(now, st.last_seen) >= ENTRY_TTL);
        if stale {
            self.flow_map.remove(flow);
            if let Some(sink) = &self.sink {
                sink.cancel_flow(flow);
            }
        }
    }
}

/// Normalize an SNI to the domain_map key form (R4/V8/m5): trim, ASCII lowercase,
/// strip ONE trailing dot, then validate with is_valid_fqdn_sni. Punycode kept as-is.
pub fn normalize_sni(sni: &str) -> Option<String> {
    let trimmed = sni.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let stripped = lower.strip_suffix('.').unwrap_or(lower.as_str());
    if !is_valid_fqdn_sni(stripped) {
        return None;
    }
    Some(stripped.to_string())
}

/// An outbound ClientHello presented to the machine.
pub struct ClientHello<'a> {
    pub flow: FlowKey,
    pub sni: Option<&'a str>,
    pub compat_mode: bool,
    pub custom_excluded: &'a [String],
    pub seq: u32,
    pub payload: Vec<u8>,
    pub cuts: Vec<usize>,
}

/// Result of presenting a ClientHello: send the original raw, or fragments enqueued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHelloAction {
    SendRaw,
    Enqueued,
}

/// Single passthrough predicate (§6): delegates to the shared evaluate_pass_through.
pub fn is_passthrough_reason(hello: &ClientHello) -> bool {
    evaluate_pass_through(hello.sni, hello.compat_mode, hello.custom_excluded).is_some()
}

/// Compat-mode forced passthrough, keyed on the Compat reason (not inferred from the
/// SNI string) so it stays on the single path (B2).
pub fn compat_mode_forces_passthrough(hello: &ClientHello) -> bool {
    hello.compat_mode
        && evaluate_pass_through(hello.sni, true, hello.custom_excluded)
            == Some(PassThroughReason::Compat)
}

/// Build the emit plan for a level (§4.3). Defensive clamp so a disabled level is
/// never emitted. Ultra is valid only at exactly 4 segments.
pub fn plan_for(level: AdaptiveLevel, cuts: &[usize], cfg: &ProfileConfig) -> Option<SegPlan> {
    let effective = level.min(cfg.enabled_max_level);
    let segment_count = cuts.len() + 1;
    match effective {
        AdaptiveLevel::Passthrough => None,
        AdaptiveLevel::Fast => Some(SegPlan {
            order: SegmentOrder::InOrder,
            inter_delay: Duration::ZERO,
            window_override: None,
        }),
        AdaptiveLevel::Balanced => Some(SegPlan {
            order: SegmentOrder::InOrder,
            inter_delay: Duration::ZERO,
            window_override: None,
        }),
        AdaptiveLevel::Hardened => Some(SegPlan {
            order: SegmentOrder::Reverse,
            inter_delay: gate_delay(cfg),
            window_override: gate_window(cfg),
        }),
        AdaptiveLevel::Ultra => {
            if segment_count != 4 {
                return None;
            }
            Some(SegPlan {
                order: SegmentOrder::Fixed([4, 2, 3, 1]),
                inter_delay: gate_delay(cfg),
                window_override: gate_window(cfg),
            })
        }
    }
}

/// Measured Balanced cut variants (R6). The table is intentionally EMPTY: no variant
/// has been measured, so placement can never deviate from vanilla. No values invented.
const BALANCED_CUT_VARIANTS: &[u8] = &[];

/// Balanced cut placement is gated like every other deviation; with an empty measured
/// table this is always false (R6).
pub fn balanced_cut_placement_enabled(cfg: &ProfileConfig) -> bool {
    cfg.balanced_cut_variant != 0 && BALANCED_CUT_VARIANTS.contains(&cfg.balanced_cut_variant)
}

/// Inert measured-cut hook: returns vanilla until a variant is actually measured (R6).
fn measured_balanced_cuts(base: &[usize], _variant: u8) -> Vec<usize> {
    base.to_vec()
}

/// Resolve the cuts for a level. Balanced differs from Fast only by cut placement,
/// which stays vanilla unless a measured variant is enabled.
pub fn cuts_for(level: AdaptiveLevel, base: &[usize], cfg: &ProfileConfig) -> Vec<usize> {
    if level == AdaptiveLevel::Balanced && balanced_cut_placement_enabled(cfg) {
        measured_balanced_cuts(base, cfg.balanced_cut_variant)
    } else {
        base.to_vec()
    }
}

fn elapsed(now: Instant, then: Instant) -> Duration {
    now.checked_duration_since(then).unwrap_or(Duration::ZERO)
}

fn cooldown_expired(st: &EscalationState, now: Instant) -> bool {
    st.cooldown_until.is_some_and(|until| now >= until)
}

fn in_cooldown(st: &EscalationState, now: Instant) -> bool {
    st.cooldown_until.is_some_and(|until| now < until)
}

/// V6: refresh the cooldown horizon; no domain_map write.
fn refresh_cooldown(st: &mut EscalationState, now: Instant) {
    st.cooldown_until = Some(now + COOLDOWN_TTL);
}

fn set_passthrough(st: &mut EscalationState, now: Instant) {
    st.level = AdaptiveLevel::Passthrough;
    st.cooldown_until = Some(now + COOLDOWN_TTL);
}

/// Invariant 9: every descend (success or timeout) resets the streak.
fn descend(st: &mut EscalationState) {
    st.level = st.level.lowered();
    st.success_streak = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct RecordingSink {
        enqueued: Mutex<Vec<OutboundHello>>,
        cancelled: Mutex<Vec<FlowKey>>,
        cancel_all_count: AtomicUsize,
    }

    impl EmitSink for RecordingSink {
        fn enqueue(&self, hello: OutboundHello) {
            self.enqueued.lock().unwrap().push(hello);
        }
        fn cancel_flow(&self, flow: &FlowKey) {
            self.cancelled.lock().unwrap().push(*flow);
        }
        fn cancel_all(&self) {
            self.cancel_all_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RecordingSink {
        fn enqueued_count(&self) -> usize {
            self.enqueued.lock().unwrap().len()
        }
        fn cancel_all_count(&self) -> usize {
            self.cancel_all_count.load(Ordering::SeqCst)
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut ip = [0u8; 16];
        ip[0] = a;
        ip[1] = b;
        ip[2] = c;
        ip[3] = d;
        ip
    }

    fn flow(id: u8) -> FlowKey {
        FlowKey {
            src_ip: ipv4(192, 168, 0, id),
            dst_ip: ipv4(93, 184, 216, 34),
            src_port: 40000 + id as u16,
            dst_port: 443,
            family: 4,
        }
    }

    fn hello<'a>(f: FlowKey, sni: Option<&'a str>) -> ClientHello<'a> {
        ClientHello {
            flow: f,
            sni,
            compat_mode: false,
            custom_excluded: &[],
            seq: 100,
            payload: vec![0u8; 64],
            cuts: vec![16, 32],
        }
    }

    fn cfg_max(level: AdaptiveLevel) -> ProfileConfig {
        ProfileConfig {
            enabled_max_level: level,
            ..Default::default()
        }
    }

    fn assert_permutation(order: SegmentOrder, segment_count: usize) {
        let mut ids: Vec<u8> = match order {
            SegmentOrder::InOrder => (1..=segment_count as u8).collect(),
            SegmentOrder::Reverse => (1..=segment_count as u8).rev().collect(),
            SegmentOrder::Fixed(arr) => arr[..segment_count].to_vec(),
        };
        ids.sort_unstable();
        let expected: Vec<u8> = (1..=segment_count as u8).collect();
        assert_eq!(ids, expected);
    }

    // ---- §9.1 Plan / SegPlan ----

    #[test]
    fn passthrough_returns_none() {
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        assert!(plan_for(AdaptiveLevel::Passthrough, &[16, 32], &cfg).is_none());
    }

    #[test]
    fn fast_is_in_order_zero_delay() {
        let cfg = ProfileConfig::default();
        assert_eq!(cfg.enabled_max_level, AdaptiveLevel::Fast);
        assert!(!cfg.allow_inter_delay);
        assert!(!cfg.allow_window_override);
        assert_eq!(cfg.balanced_cut_variant, 0);
        let plan = plan_for(AdaptiveLevel::Fast, &[16, 32], &cfg).unwrap();
        assert_eq!(plan.order, SegmentOrder::InOrder);
        assert_eq!(plan.inter_delay, Duration::ZERO);
        assert_eq!(plan.window_override, None);
    }

    #[test]
    fn balanced_uses_different_cuts_not_order() {
        let cfg = cfg_max(AdaptiveLevel::Balanced);
        let fast = plan_for(AdaptiveLevel::Fast, &[16, 32], &cfg).unwrap();
        let balanced = plan_for(AdaptiveLevel::Balanced, &[16, 32], &cfg).unwrap();
        // Same order: the differentiator is cut placement, not emit order.
        assert_eq!(balanced.order, fast.order);
        assert_eq!(balanced.order, SegmentOrder::InOrder);
        // Placement is the gated axis; with no measured variant it stays vanilla (R6).
        let base = [16usize, 32];
        assert_eq!(
            cuts_for(AdaptiveLevel::Balanced, &base, &cfg),
            base.to_vec()
        );
        assert_eq!(cuts_for(AdaptiveLevel::Fast, &base, &cfg), base.to_vec());
        assert!(!balanced_cut_placement_enabled(&cfg));
    }

    #[test]
    fn hardened_is_reverse_zero_delay_by_default() {
        let cfg = cfg_max(AdaptiveLevel::Hardened);
        let plan = plan_for(AdaptiveLevel::Hardened, &[16, 32], &cfg).unwrap();
        assert_eq!(plan.order, SegmentOrder::Reverse);
        assert_eq!(plan.inter_delay, Duration::ZERO);
        assert_eq!(plan.window_override, None);
    }

    #[test]
    fn ultra_requires_four_segments() {
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        // 3 cuts => 4 segments => Some.
        let plan = plan_for(AdaptiveLevel::Ultra, &[10, 20, 30], &cfg);
        assert!(plan.is_some());
        assert_eq!(plan.unwrap().order, SegmentOrder::Fixed([4, 2, 3, 1]));
        // 2 cuts => 3 segments => None.
        assert!(plan_for(AdaptiveLevel::Ultra, &[16, 32], &cfg).is_none());
    }

    #[test]
    fn property_order_is_permutation() {
        // Exhaustive over the orders plan_for can emit (V8: bounded, no crate).
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        for level in [
            AdaptiveLevel::Fast,
            AdaptiveLevel::Balanced,
            AdaptiveLevel::Hardened,
        ] {
            let plan = plan_for(level, &[16, 32], &cfg).unwrap();
            assert_permutation(plan.order, 3);
        }
        let plan = plan_for(AdaptiveLevel::Ultra, &[10, 20, 30], &cfg).unwrap();
        assert_permutation(plan.order, 4);
    }

    #[test]
    fn window_bitmask_indexes_original_ids() {
        // bits 1 and 3 => original segments 2 and 4.
        let win = (0b1010u16, 0u8);
        assert!(window_includes_segment(win, 2));
        assert!(window_includes_segment(win, 4));
        assert!(!window_includes_segment(win, 1));
        assert!(!window_includes_segment(win, 3));
        // Hardened emits Reverse [3,2,1]; original id 3 is emitted first but is NOT
        // in the mask — indexing follows original id, not emit position.
        let cfg = ProfileConfig {
            enabled_max_level: AdaptiveLevel::Hardened,
            allow_window_override: true,
            ..Default::default()
        };
        let plan = plan_for(AdaptiveLevel::Hardened, &[16, 32], &cfg).unwrap();
        assert_eq!(plan.order, SegmentOrder::Reverse);
        assert!(plan.window_override.is_some());
        assert!(!window_includes_segment(win, 3));
        assert!(window_includes_segment(win, 2));
        assert!(!window_includes_segment(win, 0));
        assert!(!window_includes_segment(win, 17));
    }

    #[test]
    fn plan_for_honours_measurement_flags() {
        let base = cfg_max(AdaptiveLevel::Ultra);
        // Flags off => no delay/window even at Ultra.
        let p = plan_for(AdaptiveLevel::Ultra, &[10, 20, 30], &base).unwrap();
        assert_eq!(p.inter_delay, Duration::ZERO);
        assert_eq!(p.window_override, None);
        // Flags on => gated sentinels appear.
        let gated = ProfileConfig {
            allow_inter_delay: true,
            allow_window_override: true,
            ..base
        };
        let p = plan_for(AdaptiveLevel::Ultra, &[10, 20, 30], &gated).unwrap();
        assert_eq!(p.inter_delay, GATED_INTER_DELAY);
        assert!(p.inter_delay > Duration::ZERO);
        assert_eq!(p.window_override, Some(GATED_WINDOW));
        let h = plan_for(AdaptiveLevel::Hardened, &[16, 32], &gated).unwrap();
        assert_eq!(h.inter_delay, GATED_INTER_DELAY);
        assert_eq!(h.window_override, Some(GATED_WINDOW));
        // Fast/Balanced never get delay/window regardless of flags.
        let f = plan_for(AdaptiveLevel::Fast, &[16, 32], &gated).unwrap();
        assert_eq!(f.inter_delay, Duration::ZERO);
        assert_eq!(f.window_override, None);
    }

    #[test]
    fn balanced_cut_placement_also_gated() {
        // A non-zero variant cannot deviate placement without a measured variant (R6).
        let cfg = ProfileConfig {
            enabled_max_level: AdaptiveLevel::Balanced,
            balanced_cut_variant: 3,
            ..Default::default()
        };
        assert!(!balanced_cut_placement_enabled(&cfg));
        let base = [16usize, 32];
        assert_eq!(
            cuts_for(AdaptiveLevel::Balanced, &base, &cfg),
            base.to_vec()
        );
        let cfg0 = cfg_max(AdaptiveLevel::Balanced);
        assert!(!balanced_cut_placement_enabled(&cfg0));
        assert_eq!(
            cuts_for(AdaptiveLevel::Balanced, &base, &cfg0),
            base.to_vec()
        );
    }

    // ---- §9.2 State machine — RST ----

    #[test]
    fn rst_inside_window_escalates_once() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        let action = m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        assert_eq!(action, ClientHelloAction::Enqueued);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Fast);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Balanced);
    }

    #[test]
    fn rst_outside_window_ignored() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        let before = m.flow_map.get(&f).unwrap().level;
        m.on_rst(&f, false, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, before);
    }

    #[test]
    fn rst_during_cooldown_does_not_escalate() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        // Fast + attempts>0 timeout => Passthrough + cooldown.
        m.on_handshake_timeout(&f, now);
        assert_eq!(
            m.flow_map.get(&f).unwrap().level,
            AdaptiveLevel::Passthrough
        );
        assert!(m.flow_map.get(&f).unwrap().cooldown_until.is_some());
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(
            m.flow_map.get(&f).unwrap().level,
            AdaptiveLevel::Passthrough
        );
    }

    #[test]
    fn rst_on_compat_flow_is_noop() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        let mut h = hello(f, Some("teamviewer.com"));
        h.compat_mode = true;
        assert_eq!(m.on_client_hello(&h, &cfg, now), ClientHelloAction::SendRaw);
        assert!(m.flow_map.get(&f).is_none());
        m.on_rst(&f, true, &cfg, now);
        assert!(m.flow_map.get(&f).is_none());
    }

    #[test]
    fn max_attempts_no_success_passthrough() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        for _ in 0..MAX_ATTEMPTS {
            m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        }
        assert_eq!(m.flow_map.get(&f).unwrap().split_attempts, MAX_ATTEMPTS);
        assert!(!m.flow_map.get(&f).unwrap().has_success);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(
            m.flow_map.get(&f).unwrap().level,
            AdaptiveLevel::Passthrough
        );
        assert!(m.flow_map.get(&f).unwrap().cooldown_until.is_some());
    }

    #[test]
    fn escalate_caps_at_highest_enabled_level() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Balanced);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Balanced);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Balanced);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Balanced);
    }

    // ---- §9.3 State machine — success / descend ----

    #[test]
    fn three_successes_descend_one_level() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Hardened);
        for _ in 0..SUCCESS_STREAK_DESCEND {
            m.on_handshake_complete(&f, now);
        }
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Balanced);
    }

    #[test]
    fn descend_resets_streak() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        for _ in 0..SUCCESS_STREAK_DESCEND {
            m.on_handshake_complete(&f, now);
        }
        assert_eq!(m.flow_map.get(&f).unwrap().success_streak, 0);
    }

    #[test]
    fn streak_not_incremented_at_fast() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        for _ in 0..5 {
            m.on_handshake_complete(&f, now);
        }
        assert_eq!(m.flow_map.get(&f).unwrap().success_streak, 0);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Fast);
    }

    #[test]
    fn success_streak_no_overflow_at_fast() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        for _ in 0..300 {
            m.on_handshake_complete(&f, now);
        }
        assert_eq!(m.flow_map.get(&f).unwrap().success_streak, 0);
    }

    #[test]
    fn handshake_complete_updates_domain_sticky() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(
            m.domain_map.get("example.com").unwrap().level,
            AdaptiveLevel::Balanced
        );
        m.on_handshake_timeout(&f, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Fast);
        let before = m.domain_map.get("example.com").unwrap().decay;
        m.on_handshake_complete(&f, now);
        assert_eq!(m.domain_map.get("example.com").unwrap().decay, before + 1);
    }

    // ---- §9.4 State machine — timeout ----

    #[test]
    fn timeout_does_not_escalate() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        let before = m.flow_map.get(&f).unwrap().level;
        m.on_handshake_timeout(&f, now);
        let after = m.flow_map.get(&f).unwrap().level;
        assert!(after <= before);
        assert_eq!(after, AdaptiveLevel::Fast);
    }

    #[test]
    fn timeout_descends_when_split_used() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Hardened);
        assert!(m.flow_map.get(&f).unwrap().split_attempts > 0);
        m.on_handshake_timeout(&f, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Balanced);
    }

    #[test]
    fn timeout_descend_resets_streak() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_handshake_complete(&f, now);
        assert_eq!(m.flow_map.get(&f).unwrap().success_streak, 1);
        m.on_handshake_timeout(&f, now);
        assert_eq!(m.flow_map.get(&f).unwrap().success_streak, 0);
    }

    #[test]
    fn timeout_does_not_affect_domain_sticky() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        let before = *m.domain_map.get("example.com").unwrap();
        m.on_handshake_timeout(&f, now);
        let after = *m.domain_map.get("example.com").unwrap();
        assert_eq!(before.level, after.level);
        assert_eq!(before.decay, after.decay);
    }

    // ---- §9.5 current_level dual-path + config drift ----

    #[test]
    fn current_level_new_flow_uses_sticky_capped() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        m.domain_map.insert(
            "example.com".to_string(),
            DomainEntry {
                level: AdaptiveLevel::Balanced,
                decay: 0,
            },
        );
        let f = flow(1);
        let level = m.current_level(&f, Some("example.com"), &cfg, now);
        assert_eq!(level, AdaptiveLevel::Balanced);
        assert!(m.flow_map.get(&f).is_none());
        let level2 = m.current_level(&flow(2), Some("other.com"), &cfg, now);
        assert_eq!(level2, AdaptiveLevel::Fast);
    }

    #[test]
    fn current_level_existing_flow_uses_st_level() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        // Domain sticky is capped at Balanced, but the existing flow uses st.level.
        let level = m.current_level(&f, Some("example.com"), &cfg, now);
        assert_eq!(level, AdaptiveLevel::Hardened);
    }

    #[test]
    fn config_drift_clamps_existing_flow_level() {
        let mut m = AdaptiveMaps::new();
        let cfg_high = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg_high, now);
        m.on_rst(&f, true, &cfg_high, now);
        m.on_rst(&f, true, &cfg_high, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Hardened);
        let cfg_low = cfg_max(AdaptiveLevel::Fast);
        let level = m.current_level(&f, Some("example.com"), &cfg_low, now);
        assert_eq!(level, AdaptiveLevel::Fast);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Fast);
    }

    #[test]
    fn cooldown_expiry_restores_fast() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_handshake_timeout(&f, now);
        assert_eq!(
            m.flow_map.get(&f).unwrap().level,
            AdaptiveLevel::Passthrough
        );
        // Advance past cooldown (45s) but within ENTRY_TTL (60s).
        let later = now + COOLDOWN_TTL;
        let level = m.current_level(&f, Some("example.com"), &cfg, later);
        assert_eq!(level, AdaptiveLevel::Fast);
        assert_eq!(m.flow_map.get(&f).unwrap().cooldown_until, None);
    }

    // ---- §9.6 Domain sticky ----

    #[test]
    fn domain_sticky_capped() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Ultra);
        assert_eq!(
            m.domain_map.get("example.com").unwrap().level,
            AdaptiveLevel::Balanced
        );
        let new_level = m.current_level(&flow(2), Some("example.com"), &cfg, now);
        assert!(new_level <= AdaptiveLevel::Balanced);
        assert_eq!(new_level, AdaptiveLevel::Balanced);
    }

    #[test]
    fn domain_sticky_clamped_at_read() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        // Force a stored entry above the cap (drift / pre-cap data).
        m.domain_map.insert(
            "example.com".to_string(),
            DomainEntry {
                level: AdaptiveLevel::Ultra,
                decay: 0,
            },
        );
        let level = m.current_level(&flow(1), Some("example.com"), &cfg, now);
        assert_eq!(level, AdaptiveLevel::Balanced);
    }

    #[test]
    fn domain_sticky_decays_after_sustained_success() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_handshake_timeout(&f, now);
        assert_eq!(m.flow_map.get(&f).unwrap().level, AdaptiveLevel::Fast);
        for _ in 0..DOMAIN_STICKY_DECAY_SUCCESSES {
            m.on_handshake_complete(&f, now);
        }
        assert_eq!(
            m.domain_map.get("example.com").unwrap().level,
            AdaptiveLevel::Fast
        );
        assert_eq!(m.domain_map.get("example.com").unwrap().decay, 0);
    }

    #[test]
    fn decay_counter_resets_on_escalate() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_handshake_timeout(&f, now);
        m.on_handshake_complete(&f, now);
        m.on_handshake_complete(&f, now);
        assert_eq!(m.domain_map.get("example.com").unwrap().decay, 2);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(m.domain_map.get("example.com").unwrap().decay, 0);
    }

    #[test]
    fn domain_entry_holds_level_and_decay() {
        let e = DomainEntry {
            level: AdaptiveLevel::Balanced,
            decay: 3,
        };
        assert_eq!(e.level, AdaptiveLevel::Balanced);
        assert_eq!(e.decay, 3);
        let mut m = AdaptiveMaps::new();
        m.domain_map.insert("example.com".to_string(), e);
        let got = *m.domain_map.get("example.com").unwrap();
        assert_eq!(got.level, AdaptiveLevel::Balanced);
        assert_eq!(got.decay, 3);
        assert_eq!(m.domain_map.len(), 1);
    }

    #[test]
    fn passthrough_bail_does_not_touch_domain_map() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        let before = *m.domain_map.get("example.com").unwrap();
        let len_before = m.domain_map.len();
        for _ in 0..(MAX_ATTEMPTS - 1) {
            m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        }
        assert_eq!(m.flow_map.get(&f).unwrap().split_attempts, MAX_ATTEMPTS);
        m.on_rst(&f, true, &cfg, now);
        assert_eq!(
            m.flow_map.get(&f).unwrap().level,
            AdaptiveLevel::Passthrough
        );
        assert_eq!(m.domain_map.len(), len_before);
        let after = *m.domain_map.get("example.com").unwrap();
        assert_eq!(before.level, after.level);
        assert_eq!(before.decay, after.decay);
    }

    #[test]
    fn domain_map_key_normalized_matches_tracker() {
        // normalize_sni: trim, ASCII lowercase, strip one trailing dot, validate (R4/V8).
        assert_eq!(
            normalize_sni("  Example.COM.  ").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_sni("example.com").as_deref(), Some("example.com"));
        assert_eq!(normalize_sni("EXAMPLE.COM").as_deref(), Some("example.com"));
        assert_eq!(normalize_sni("localhost"), None);
        assert_eq!(normalize_sni("1.2.3.4"), None);
        assert_eq!(normalize_sni(""), None);
        assert_eq!(
            normalize_sni("xn--bcher-kva.example.com").as_deref(),
            Some("xn--bcher-kva.example.com")
        );
        // The normalized key is accepted by the validator on the passthrough path.
        assert!(crate::is_valid_fqdn_sni("example.com"));
        // Equivalent valid spellings resolve to ONE domain entry (tracker host form).
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f1 = flow(1);
        let f2 = flow(2);
        m.on_client_hello(&hello(f1, Some("EXAMPLE.COM")), &cfg, now);
        m.on_rst(&f1, true, &cfg, now);
        assert!(m.domain_map.get("example.com").is_some());
        assert_eq!(m.domain_map.len(), 1);
        let level = m.current_level(&f2, Some("example.com"), &cfg, now);
        assert_eq!(level, AdaptiveLevel::Balanced);
    }

    // ---- §9.7 Compat / passthrough duy nhất ----

    #[test]
    fn client_hello_compat_creates_no_entry() {
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        let mut h = hello(f, Some("teamviewer.com"));
        h.compat_mode = true;
        assert_eq!(m.on_client_hello(&h, &cfg, now), ClientHelloAction::SendRaw);
        assert!(m.flow_map.get(&f).is_none());
        assert!(m.domain_map.is_empty());
        // Other PassThroughReasons also create no entry (single path, §6).
        let f2 = flow(2);
        assert_eq!(
            m.on_client_hello(&hello(f2, Some("dns.google")), &cfg, now),
            ClientHelloAction::SendRaw
        );
        assert!(m.flow_map.get(&f2).is_none());
        let f3 = flow(3);
        assert_eq!(
            m.on_client_hello(&hello(f3, None), &cfg, now),
            ClientHelloAction::SendRaw
        );
        assert!(m.flow_map.get(&f3).is_none());
    }

    #[test]
    fn compat_mode_forces_passthrough() {
        let mut h = hello(flow(1), Some("teamviewer.com"));
        h.compat_mode = true;
        assert!(super::compat_mode_forces_passthrough(&h));
        assert!(is_passthrough_reason(&h));
        let h2 = hello(flow(1), Some("teamviewer.com"));
        assert!(!super::compat_mode_forces_passthrough(&h2));
        let h3 = hello(flow(1), Some("example.com"));
        assert!(!super::compat_mode_forces_passthrough(&h3));
        let mut h4 = hello(flow(1), Some("example.com"));
        h4.compat_mode = true;
        assert!(!super::compat_mode_forces_passthrough(&h4));
    }

    // ---- §9.8 Lifecycle / privacy ----

    #[test]
    fn retransmit_counts_as_separate_attempt() {
        let sink = Arc::new(RecordingSink::default());
        let mut m = AdaptiveMaps::with_sink(sink.clone());
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().split_attempts, 1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().split_attempts, 2);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        assert_eq!(m.flow_map.get(&f).unwrap().split_attempts, 3);
        assert_eq!(
            m.flow_map.get(&f).unwrap().sni_key.as_deref(),
            Some("example.com")
        );
        assert_eq!(sink.enqueued_count(), 3);
    }

    #[test]
    fn wipe_on_engine_stop() {
        let sink = Arc::new(RecordingSink::default());
        let mut m = AdaptiveMaps::with_sink(sink.clone());
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        assert!(!m.flow_map.is_empty());
        assert!(!m.domain_map.is_empty());
        m.wipe();
        assert!(m.flow_map.is_empty());
        assert!(m.domain_map.is_empty());
        assert_eq!(sink.cancel_all_count(), 1);
    }

    #[test]
    fn no_state_persisted_to_disk() {
        // RAM-only: exercising the machine creates no files (invariant 12 / M7).
        let dir = std::env::temp_dir().join(format!("levi_adaptive_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let before = std::fs::read_dir(&dir).unwrap().count();
        let mut m = AdaptiveMaps::new();
        let cfg = cfg_max(AdaptiveLevel::Ultra);
        let now = Instant::now();
        let f = flow(1);
        m.on_client_hello(&hello(f, Some("example.com")), &cfg, now);
        m.on_rst(&f, true, &cfg, now);
        m.on_handshake_complete(&f, now);
        m.on_handshake_timeout(&f, now);
        m.wipe();
        let after = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(before, 0);
        assert_eq!(after, before);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

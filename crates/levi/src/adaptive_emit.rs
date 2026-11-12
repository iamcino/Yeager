//! Levi Adaptive emit layer (companion spec levi-adaptive-emit-tests.md, LOCKED).
//!
//! Implements the [`EmitSink`] seam from [`crate::adaptive`]: an unbounded emit
//! queue, one emit thread, and a hashed timing wheel. The capture side never
//! sleeps or blocks — `enqueue` builds fragments and returns; all delay lives on
//! the emit thread, and the wheel is engaged only when `plan.inter_delay > 0`.
//! Pending fragments are cancelled on RST, LRU eviction, and wipe through the
//! seam. Not wired into the live engine until the measurement gate (§11) passes.

use crate::adaptive::{EmitSink, FlowKey, OutboundHello, SegmentOrder};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// One wire-ready fragment. `seq` is the ORIGINAL seq plus this fragment's payload
/// offset (companion invariant 4), independent of emit order.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub flow: FlowKey,
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// Sender abstraction: the emit thread hands wire-ready fragments here. Tests use
/// a fake sender; the live sender is deferred until the measurement gate.
pub trait FragmentSender: Send + Sync {
    fn send_fragment(&self, fragment: Fragment);
}

const WHEEL_SLOTS: usize = 64;
const TICK_NANOS: u128 = 1_000_000;
const IDLE_POLL: Duration = Duration::from_millis(50);

struct WheelEntry {
    due_tick: u64,
    order: u64,
    fragment: Fragment,
}

/// Hashed timing wheel: slot = due_tick % WHEEL_SLOTS, 1 ms tick. The cursor is an
/// absolute tick count, so entries more than one revolution out simply stay in
/// their slot until the cursor laps them.
struct TimingWheel {
    slots: Vec<Vec<WheelEntry>>,
    cursor: u64,
}

impl TimingWheel {
    fn new() -> Self {
        Self {
            slots: (0..WHEEL_SLOTS).map(|_| Vec::new()).collect(),
            cursor: 0,
        }
    }

    fn schedule(&mut self, entry: WheelEntry) {
        let slot = (entry.due_tick % WHEEL_SLOTS as u64) as usize;
        self.slots[slot].push(entry);
    }

    /// Step the cursor to now_tick, moving every due entry into `ready` sorted by
    /// enqueue order so a plan's fragments keep their send order.
    fn advance(&mut self, now_tick: u64, ready: &mut VecDeque<Fragment>) {
        let mut due = Vec::new();
        while self.cursor < now_tick {
            self.cursor += 1;
            let slot = (self.cursor % WHEEL_SLOTS as u64) as usize;
            for entry in std::mem::take(&mut self.slots[slot]) {
                if entry.due_tick <= self.cursor {
                    due.push(entry);
                } else {
                    self.slots[slot].push(entry);
                }
            }
        }
        due.sort_by_key(|e| e.order);
        ready.extend(due.into_iter().map(|e| e.fragment));
    }

    fn has_due(&self, now_tick: u64) -> bool {
        self.slots.iter().flatten().any(|e| e.due_tick <= now_tick)
    }

    fn next_due_tick(&self) -> Option<u64> {
        self.slots.iter().flatten().map(|e| e.due_tick).min()
    }

    fn count_flow(&self, flow: &FlowKey) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|e| &e.fragment.flow == flow)
            .count()
    }

    fn retain(&mut self, keep: impl Fn(&FlowKey) -> bool) {
        for slot in &mut self.slots {
            slot.retain(|e| keep(&e.fragment.flow));
        }
    }

    fn len(&self) -> usize {
        self.slots.iter().map(Vec::len).sum()
    }

    fn clear(&mut self) {
        for slot in &mut self.slots {
            slot.clear();
        }
    }
}

fn tick_of(epoch: Instant, now: Instant) -> u64 {
    now.checked_duration_since(epoch)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Ceil so a fragment never fires earlier than its inter_delay after enqueue.
fn ceil_tick_of(epoch: Instant, now: Instant) -> u64 {
    let nanos = now
        .checked_duration_since(epoch)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    ((nanos + TICK_NANOS - 1) / TICK_NANOS) as u64
}

/// Split the payload at the cut points into (offset, bytes) segments. Invalid cuts
/// (0, >= len, duplicates, unsorted) are sanitized away; with no valid cut left the
/// whole payload becomes one fragment, so coverage is never lost.
fn split_segments(payload: &[u8], cuts: &[usize]) -> Vec<(usize, Vec<u8>)> {
    let len = payload.len();
    let mut bounds: Vec<usize> = cuts.iter().copied().filter(|&c| c > 0 && c < len).collect();
    bounds.sort_unstable();
    bounds.dedup();
    let mut segments = Vec::with_capacity(bounds.len() + 1);
    let mut start = 0;
    for end in bounds.into_iter().chain(std::iter::once(len)) {
        segments.push((start, payload[start..end].to_vec()));
        start = end;
    }
    segments
}

/// Send order as original 1-based segment ids. Order changes send order only —
/// offsets and seqs always follow the original layout. A malformed Fixed
/// permutation falls back to InOrder so coverage is never lost.
fn emit_order(order: SegmentOrder, segment_count: usize) -> Vec<u8> {
    let ids: Vec<u8> = match order {
        SegmentOrder::InOrder => (1..=segment_count as u8).collect(),
        SegmentOrder::Reverse => (1..=segment_count as u8).rev().collect(),
        SegmentOrder::Fixed(arr) => arr[..segment_count.min(4)].to_vec(),
    };
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    let expected: Vec<u8> = (1..=segment_count as u8).collect();
    if sorted == expected { ids } else { expected }
}

struct QueueState {
    /// Zero-delay FIFO: never touches the wheel (companion invariant 7).
    immediate: VecDeque<Fragment>,
    /// Delayed fragments that came due, in enqueue order.
    ready: VecDeque<Fragment>,
    wheel: TimingWheel,
    order_counter: u64,
    epoch: Instant,
}

impl QueueState {
    fn enqueue(&mut self, hello: OutboundHello, now: Instant, wheel_scheduled: &AtomicUsize) {
        let segments = split_segments(&hello.payload, &hello.cuts);
        let order = emit_order(hello.plan.order, segments.len());
        let delay = hello.plan.inter_delay;
        let now_tick = ceil_tick_of(self.epoch, now);
        let delay_ticks = ((delay.as_nanos() + TICK_NANOS - 1) / TICK_NANOS) as u64;
        let mut slots: Vec<Option<Fragment>> = segments
            .into_iter()
            .map(|(offset, bytes)| {
                Some(Fragment {
                    flow: hello.flow,
                    seq: hello.seq.wrapping_add(offset as u32),
                    payload: bytes,
                })
            })
            .collect();
        for (k, segment_id) in order.iter().enumerate() {
            let fragment = slots[*segment_id as usize - 1]
                .take()
                .expect("emit_order is a permutation");
            self.order_counter += 1;
            let order_no = self.order_counter;
            if delay.is_zero() || k == 0 {
                self.immediate.push_back(fragment);
            } else {
                let due_tick = now_tick + k as u64 * delay_ticks;
                wheel_scheduled.fetch_add(1, Ordering::Relaxed);
                if due_tick <= self.wheel.cursor {
                    self.ready.push_back(fragment);
                } else {
                    self.wheel.schedule(WheelEntry {
                        due_tick,
                        order: order_no,
                        fragment,
                    });
                }
            }
        }
    }

    fn has_ready(&self, now: Instant) -> bool {
        !self.immediate.is_empty()
            || !self.ready.is_empty()
            || self.wheel.has_due(tick_of(self.epoch, now))
    }

    fn pop_due(&mut self, now: Instant) -> Option<Fragment> {
        if let Some(fragment) = self.immediate.pop_front() {
            return Some(fragment);
        }
        if let Some(fragment) = self.ready.pop_front() {
            return Some(fragment);
        }
        self.wheel
            .advance(tick_of(self.epoch, now), &mut self.ready);
        self.ready.pop_front()
    }

    fn next_wait(&self, now: Instant) -> Option<Duration> {
        let now_tick = tick_of(self.epoch, now);
        self.wheel
            .next_due_tick()
            .map(|due| Duration::from_millis(due.saturating_sub(now_tick)))
    }

    fn pending_len(&self) -> usize {
        self.immediate.len() + self.ready.len() + self.wheel.len()
    }

    fn pending_for_flow(&self, flow: &FlowKey) -> usize {
        self.immediate
            .iter()
            .chain(self.ready.iter())
            .filter(|f| &f.flow == flow)
            .count()
            + self.wheel.count_flow(flow)
    }

    fn cancel_flow(&mut self, flow: &FlowKey) {
        self.immediate.retain(|f| &f.flow != flow);
        self.ready.retain(|f| &f.flow != flow);
        self.wheel.retain(|f| f != flow);
    }

    fn cancel_all(&mut self) {
        self.immediate.clear();
        self.ready.clear();
        self.wheel.clear();
    }
}

struct Inner {
    state: Mutex<QueueState>,
    wake: Condvar,
    sender: Arc<dyn FragmentSender>,
    running: AtomicBool,
    wheel_scheduled: AtomicUsize,
}

/// The real [`EmitSink`]: unbounded queue + one emit thread + timing wheel.
/// Capture-side methods only hold the state mutex for O(fragments) bookkeeping —
/// no sleep, no I/O, no capacity wait. The emit thread never holds the lock while
/// delaying or sending. A fragment already dequeued for send completes even if its
/// flow is cancelled mid-send; the spec's cancel guarantee covers pending ones.
pub struct EmitQueue {
    inner: Arc<Inner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl EmitQueue {
    /// Start the emit thread. The thread holds only a Weak reference, so it exits
    /// on its own once every queue handle is dropped; `shutdown`/`Drop` join it.
    pub fn start(sender: Arc<dyn FragmentSender>) -> Arc<Self> {
        let epoch = Instant::now();
        let inner = Arc::new(Inner {
            state: Mutex::new(QueueState {
                immediate: VecDeque::new(),
                ready: VecDeque::new(),
                wheel: TimingWheel::new(),
                order_counter: 0,
                epoch,
            }),
            wake: Condvar::new(),
            sender,
            running: AtomicBool::new(true),
            wheel_scheduled: AtomicUsize::new(0),
        });
        let weak = Arc::downgrade(&inner);
        let handle = std::thread::Builder::new()
            .name("levi-adaptive-emit".into())
            .spawn(move || emit_loop(weak))
            .expect("spawn adaptive emit thread");
        Arc::new(Self {
            inner,
            handle: Mutex::new(Some(handle)),
        })
    }

    /// Stop the emit thread and join it. Idempotent; pending fragments are left
    /// queued (cancellation is the seam's job, via cancel_flow / cancel_all).
    pub fn shutdown(&self) {
        self.inner.running.store(false, Ordering::Release);
        self.inner.wake.notify_all();
        if let Some(handle) = self.handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    /// Fragments still queued (immediate + ready + wheel), excluding any in send.
    pub fn pending_len(&self) -> usize {
        self.inner.state.lock().unwrap().pending_len()
    }

    pub fn pending_for_flow(&self, flow: &FlowKey) -> usize {
        self.inner.state.lock().unwrap().pending_for_flow(flow)
    }

    /// Total fragments ever routed through the timing wheel. Stays 0 while every
    /// plan has inter_delay == 0 (companion invariant 7).
    pub fn wheel_scheduled(&self) -> usize {
        self.inner.wheel_scheduled.load(Ordering::Relaxed)
    }
}

impl Drop for EmitQueue {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl EmitSink for EmitQueue {
    fn enqueue(&self, hello: OutboundHello) {
        let now = Instant::now();
        let mut state = self.inner.state.lock().unwrap();
        state.enqueue(hello, now, &self.inner.wheel_scheduled);
        drop(state);
        self.inner.wake.notify_one();
    }

    fn cancel_flow(&self, flow: &FlowKey) {
        self.inner.state.lock().unwrap().cancel_flow(flow);
    }

    fn cancel_all(&self) {
        self.inner.state.lock().unwrap().cancel_all();
    }
}

fn emit_loop(weak: Weak<Inner>) {
    while let Some(inner) = weak.upgrade() {
        if !inner.running.load(Ordering::Acquire) {
            break;
        }
        let fragment = {
            let mut state = inner.state.lock().unwrap();
            state.pop_due(Instant::now())
        };
        if let Some(fragment) = fragment {
            inner.sender.send_fragment(fragment);
            continue;
        }
        let state = inner.state.lock().unwrap();
        let timeout = state.next_wait(Instant::now()).unwrap_or(IDLE_POLL);
        let running = &inner.running;
        let (guard, _) = inner
            .wake
            .wait_timeout_while(state, timeout, |state| {
                running.load(Ordering::Acquire) && !state.has_ready(Instant::now())
            })
            .unwrap();
        drop(guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::{
        AdaptiveMaps, ClientHello, ClientHelloAction, FLOW_MAP_CAP, ProfileConfig, SegPlan,
    };

    /// Fake sender: records every fragment with its send time, plus raw originals
    /// forwarded by the capture harness.
    #[derive(Default)]
    struct FakeSender {
        fragments: Mutex<Vec<(Fragment, Instant)>>,
        raw: Mutex<Vec<Vec<u8>>>,
    }

    impl FragmentSender for FakeSender {
        fn send_fragment(&self, fragment: Fragment) {
            self.fragments
                .lock()
                .unwrap()
                .push((fragment, Instant::now()));
        }
    }

    impl FakeSender {
        fn send_raw(&self, bytes: Vec<u8>) {
            self.raw.lock().unwrap().push(bytes);
        }

        fn fragments(&self) -> Vec<Fragment> {
            self.fragments
                .lock()
                .unwrap()
                .iter()
                .map(|(f, _)| f.clone())
                .collect()
        }

        fn fragment_count(&self) -> usize {
            self.fragments.lock().unwrap().len()
        }

        fn timestamps_for(&self, flow: FlowKey) -> Vec<Instant> {
            self.fragments
                .lock()
                .unwrap()
                .iter()
                .filter(|(f, _)| f.flow == flow)
                .map(|(_, t)| *t)
                .collect()
        }

        fn raw(&self) -> Vec<Vec<u8>> {
            self.raw.lock().unwrap().clone()
        }
    }

    /// Fake capture harness (companion §2): recv -> on_client_hello; Enqueued drops
    /// the original, SendRaw forwards it byte-identical. Never sleeps.
    struct FakeCapture {
        maps: AdaptiveMaps,
        sender: Arc<FakeSender>,
    }

    impl FakeCapture {
        fn new(sender: Arc<FakeSender>, sink: Arc<EmitQueue>) -> Self {
            Self {
                maps: AdaptiveMaps::with_sink(sink),
                sender,
            }
        }

        fn recv(
            &mut self,
            hello: &ClientHello,
            cfg: &ProfileConfig,
            now: Instant,
        ) -> ClientHelloAction {
            let action = self.maps.on_client_hello(hello, cfg, now);
            if action == ClientHelloAction::SendRaw {
                self.sender.send_raw(hello.payload.clone());
            }
            action
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut ip = [0u8; 16];
        ip[..4].copy_from_slice(&[a, b, c, d]);
        ip
    }

    fn flow_n(n: usize) -> FlowKey {
        let mut src = [0u8; 16];
        src[0] = 10;
        src[2] = (n / 256) as u8;
        src[3] = (n % 256) as u8;
        FlowKey {
            src_ip: src,
            dst_ip: ipv4(93, 184, 216, 34),
            src_port: 40000 + (n % 20000) as u16,
            dst_port: 443,
            family: 4,
        }
    }

    fn flow(id: u8) -> FlowKey {
        flow_n(id as usize)
    }

    /// Byte i = i, so every payload position is identifiable (len <= 256).
    fn patterned(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    fn hello<'a>(flow: FlowKey, sni: Option<&'a str>) -> ClientHello<'a> {
        ClientHello {
            flow,
            sni,
            compat_mode: false,
            custom_excluded: &[],
            seq: 100,
            payload: patterned(64),
            cuts: vec![16, 32],
        }
    }

    fn outbound(
        flow: FlowKey,
        seq: u32,
        payload: Vec<u8>,
        cuts: Vec<usize>,
        order: SegmentOrder,
        delay: Duration,
    ) -> OutboundHello {
        OutboundHello {
            flow,
            seq,
            payload,
            cuts,
            plan: SegPlan {
                order,
                inter_delay: delay,
                window_override: None,
            },
        }
    }

    fn offset_of(original: &[u8], fragment: &Fragment) -> usize {
        original
            .windows(fragment.payload.len())
            .position(|w| w == fragment.payload.as_slice())
            .expect("fragment must be a contiguous slice of the original payload")
    }

    fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        pred()
    }

    #[test]
    fn capture_loop_does_not_block_on_delay() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let mut capture = FakeCapture::new(sender.clone(), queue.clone());
        let cfg = ProfileConfig::default();
        let now = Instant::now();

        // Flow 1 gets a 5 s inter-delay plan; its tail fragments stay pending.
        queue.enqueue(outbound(
            flow(1),
            500,
            patterned(64),
            vec![16, 32],
            SegmentOrder::InOrder,
            Duration::from_secs(5),
        ));
        assert!(wait_until(Duration::from_secs(2), || {
            queue.pending_for_flow(&flow(1)) == 2
        }));

        // Capture keeps recv-ing while flow 1's delay elapses on the emit thread.
        let start = Instant::now();
        let action_b = capture.recv(&hello(flow(2), Some("example.com")), &cfg, now);
        let action_c = capture.recv(&hello(flow(3), None), &cfg, now);
        let elapsed = start.elapsed();

        assert_eq!(action_b, ClientHelloAction::Enqueued);
        assert_eq!(action_c, ClientHelloAction::SendRaw);
        assert!(
            elapsed < Duration::from_millis(500),
            "capture side stalled on delay: {elapsed:?}"
        );
        assert_eq!(queue.pending_for_flow(&flow(1)), 2);

        // Flow 2's zero-delay fragments and flow 3's raw original drain promptly;
        // flow 1's delayed fragments have not been sent.
        assert!(wait_until(Duration::from_secs(2), || sender
            .fragment_count()
            >= 4));
        assert_eq!(sender.raw().len(), 1);
        assert!(
            sender
                .fragments()
                .iter()
                .all(|f| f.seq != 516 && f.seq != 532)
        );
        assert_eq!(queue.pending_for_flow(&flow(1)), 2);
        queue.shutdown();
    }

    #[test]
    fn split_enqueued_original_not_sent() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let mut capture = FakeCapture::new(sender.clone(), queue.clone());
        let cfg = ProfileConfig::default();
        let h = hello(flow(1), Some("example.com"));

        assert_eq!(
            capture.recv(&h, &cfg, Instant::now()),
            ClientHelloAction::Enqueued
        );
        assert!(wait_until(Duration::from_secs(2), || sender
            .fragment_count()
            == 3));
        assert!(
            sender.raw().is_empty(),
            "original must not be send_raw'd once split"
        );
        let frags = sender.fragments();
        assert_eq!(frags.len(), 3);
        assert!(frags.iter().all(|f| f.flow == flow(1)));
        queue.shutdown();
    }

    #[test]
    fn passthrough_sends_original() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let mut capture = FakeCapture::new(sender.clone(), queue.clone());
        let cfg = ProfileConfig::default();
        let now = Instant::now();

        // No SNI -> passthrough: original goes out raw, byte-identical.
        let h = hello(flow(1), None);
        let original = h.payload.clone();
        assert_eq!(capture.recv(&h, &cfg, now), ClientHelloAction::SendRaw);
        assert_eq!(sender.raw(), vec![original]);

        // DoH SNI -> same passthrough path.
        let d = hello(flow(2), Some("dns.google"));
        assert_eq!(capture.recv(&d, &cfg, now), ClientHelloAction::SendRaw);
        assert_eq!(sender.raw()[1], d.payload);

        // Nothing was enqueued and no flow state was created.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(sender.fragment_count(), 0);
        assert_eq!(queue.pending_len(), 0);
        assert!(capture.maps.flow_map.is_empty());
        queue.shutdown();
    }

    #[test]
    fn fragments_preserve_seq_offsets() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let payload = patterned(64);
        let base_seq = 1000u32;
        let cases = [
            (SegmentOrder::InOrder, vec![16, 32], vec![0usize, 16, 32]),
            (SegmentOrder::Reverse, vec![16, 32], vec![32, 16, 0]),
            (
                SegmentOrder::Fixed([4, 2, 3, 1]),
                vec![10, 20, 30],
                vec![30, 10, 20, 0],
            ),
        ];
        for (i, (order, cuts, expected_offsets)) in cases.into_iter().enumerate() {
            let f = flow(i as u8 + 1);
            queue.enqueue(outbound(
                f,
                base_seq,
                payload.clone(),
                cuts,
                order,
                Duration::ZERO,
            ));
            assert!(wait_until(Duration::from_secs(2), || {
                sender.fragments().iter().filter(|fr| fr.flow == f).count()
                    == expected_offsets.len()
            }));
            let frags: Vec<Fragment> = sender
                .fragments()
                .into_iter()
                .filter(|fr| fr.flow == f)
                .collect();
            let offsets: Vec<usize> = frags
                .iter()
                .map(|fr| {
                    let off = offset_of(&payload, fr);
                    assert_eq!(
                        fr.seq,
                        base_seq.wrapping_add(off as u32),
                        "seq must equal original seq + payload offset"
                    );
                    off
                })
                .collect();
            assert_eq!(offsets, expected_offsets, "order changes send order only");
        }
        queue.shutdown();
    }

    #[test]
    fn no_duplicate_original_after_split() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let payload = patterned(64);
        queue.enqueue(outbound(
            flow(1),
            700,
            payload.clone(),
            vec![16, 32],
            SegmentOrder::Reverse,
            Duration::ZERO,
        ));
        assert!(wait_until(Duration::from_secs(2), || sender
            .fragment_count()
            == 3));
        assert!(
            sender.raw().is_empty(),
            "original must never accompany a split"
        );

        let mut with_offsets: Vec<(usize, Vec<u8>)> = sender
            .fragments()
            .iter()
            .map(|f| (offset_of(&payload, f), f.payload.clone()))
            .collect();
        with_offsets.sort_by_key(|(off, _)| *off);
        let total: usize = with_offsets.iter().map(|(_, p)| p.len()).sum();
        assert_eq!(
            total,
            payload.len(),
            "fragments must cover the payload once"
        );
        let reassembled: Vec<u8> = with_offsets.into_iter().flat_map(|(_, p)| p).collect();
        assert_eq!(reassembled, payload);
        assert_eq!(queue.pending_len(), 0);
        queue.shutdown();
    }

    #[test]
    fn pending_fragments_cancelled_on_rst() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let mut maps = AdaptiveMaps::with_sink(queue.clone());
        let cfg = ProfileConfig::default();
        let now = Instant::now();

        // In-window RST: real entry via the Chunk A handler, then long-delay
        // pending fragments (first fragment of a delayed plan sends immediately).
        let f1 = flow(1);
        assert_eq!(
            maps.on_client_hello(&hello(f1, Some("example.com")), &cfg, now),
            ClientHelloAction::Enqueued
        );
        queue.enqueue(outbound(
            f1,
            5000,
            patterned(64),
            vec![16, 32],
            SegmentOrder::InOrder,
            Duration::from_secs(5),
        ));
        assert!(wait_until(Duration::from_secs(2), || queue
            .pending_for_flow(&f1)
            == 2));
        maps.on_rst(&f1, true, &cfg, now);
        assert_eq!(queue.pending_for_flow(&f1), 0);

        // Out-of-window RST: the cancel has no window gate (companion invariant 6).
        let f2 = flow(2);
        assert_eq!(
            maps.on_client_hello(&hello(f2, Some("example.com")), &cfg, now),
            ClientHelloAction::Enqueued
        );
        queue.enqueue(outbound(
            f2,
            6000,
            patterned(64),
            vec![16, 32],
            SegmentOrder::InOrder,
            Duration::from_secs(5),
        ));
        assert!(wait_until(Duration::from_secs(2), || queue
            .pending_for_flow(&f2)
            == 2));
        maps.on_rst(&f2, false, &cfg, now);
        assert_eq!(queue.pending_for_flow(&f2), 0);

        // The cancelled tail fragments never reach the sender.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            sender
                .fragments()
                .iter()
                .all(|f| ![5016, 5032, 6016, 6032].contains(&f.seq))
        );
        queue.shutdown();
    }

    #[test]
    fn delay_only_applied_when_plan_delay_gt_zero() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());

        // Zero delay: no wheel involvement, all fragments out promptly.
        let f1 = flow(1);
        queue.enqueue(outbound(
            f1,
            100,
            patterned(64),
            vec![16, 32],
            SegmentOrder::InOrder,
            Duration::ZERO,
        ));
        assert!(wait_until(Duration::from_secs(2), || {
            sender.timestamps_for(f1).len() == 3
        }));
        assert_eq!(
            queue.wheel_scheduled(),
            0,
            "zero-delay plans must not engage the timing wheel"
        );
        let ts = sender.timestamps_for(f1);
        let span = ts[2].duration_since(ts[0]);
        assert!(
            span < Duration::from_millis(250),
            "zero-delay batch delayed: {span:?}"
        );

        // Positive delay: only the delayed fragments go through the wheel, and
        // successive sends are spaced by at least inter_delay.
        let f2 = flow(2);
        let delay = Duration::from_millis(60);
        queue.enqueue(outbound(
            f2,
            200,
            patterned(64),
            vec![16, 32],
            SegmentOrder::InOrder,
            delay,
        ));
        assert!(wait_until(Duration::from_secs(3), || {
            sender.timestamps_for(f2).len() == 3
        }));
        assert_eq!(queue.wheel_scheduled(), 2);
        let ts = sender.timestamps_for(f2);
        let total = ts[2].duration_since(ts[0]);
        assert!(
            total >= Duration::from_millis(100),
            "inter-delay not applied: {total:?}"
        );
        for w in ts.windows(2) {
            assert!(
                w[1].duration_since(w[0]) >= Duration::from_millis(50),
                "gap below inter_delay: {:?}",
                w[1].duration_since(w[0])
            );
        }
        queue.shutdown();
    }

    #[test]
    fn lru_eviction_cancels_pending_emits() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let mut maps = AdaptiveMaps::with_sink(queue.clone());
        let cfg = ProfileConfig::default();
        let now = Instant::now();

        // Victim: real entry plus long-delay pending fragments.
        let victim = flow_n(0);
        assert_eq!(
            maps.on_client_hello(&hello(victim, Some("example.com")), &cfg, now),
            ClientHelloAction::Enqueued
        );
        queue.enqueue(outbound(
            victim,
            9000,
            patterned(64),
            vec![16, 32],
            SegmentOrder::InOrder,
            Duration::from_secs(30),
        ));
        assert!(wait_until(Duration::from_secs(2), || {
            queue.pending_for_flow(&victim) == 2
        }));

        // Fill the production-cap LRU with fresh flows; the victim is LRU and its
        // eviction must cancel its pending fragments via the Chunk A hook.
        for i in 1..=FLOW_MAP_CAP {
            let action = maps.on_client_hello(&hello(flow_n(i), Some("example.com")), &cfg, now);
            assert_eq!(action, ClientHelloAction::Enqueued);
        }
        assert!(
            maps.flow_map.get(&victim).is_none(),
            "victim must be evicted"
        );
        assert_eq!(queue.pending_for_flow(&victim), 0);

        // All filler fragments drain; the victim's delayed tail never sends.
        assert!(wait_until(Duration::from_secs(10), || {
            sender.fragment_count() >= 3 * FLOW_MAP_CAP
        }));
        assert!(sender.fragments().iter().all(|f| f.seq < 9016));
        queue.shutdown();
    }

    #[test]
    fn concurrent_update_and_read_no_panic() {
        let sender = Arc::new(FakeSender::default());
        let queue = EmitQueue::start(sender.clone());
        let mut handles = Vec::new();
        for t in 0..4usize {
            let q = queue.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..200u32 {
                    let f = flow_n(t * 1000 + i as usize % 8);
                    let delay = if i % 3 == 0 {
                        Duration::from_millis(1)
                    } else {
                        Duration::ZERO
                    };
                    q.enqueue(outbound(
                        f,
                        100 + i,
                        patterned(32),
                        vec![8, 16],
                        SegmentOrder::InOrder,
                        delay,
                    ));
                    if i % 5 == 0 {
                        q.cancel_flow(&f);
                    }
                    if i % 50 == 0 {
                        q.cancel_all();
                    }
                    let _ = q.pending_len();
                    let _ = q.pending_for_flow(&f);
                }
            }));
        }
        for _ in 0..2 {
            let q = queue.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    let _ = q.pending_len();
                    let _ = q.wheel_scheduled();
                    std::thread::yield_now();
                }
            }));
        }
        for h in handles {
            h.join().expect("no panic in concurrent workers");
        }

        // The queue is still functional after the storm.
        let probe = flow_n(99999);
        queue.enqueue(outbound(
            probe,
            1,
            patterned(32),
            vec![8, 16],
            SegmentOrder::InOrder,
            Duration::ZERO,
        ));
        assert!(wait_until(Duration::from_secs(2), || {
            sender.fragments().iter().any(|f| f.flow == probe)
        }));
        queue.shutdown();
    }
}

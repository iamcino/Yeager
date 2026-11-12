# Levi Adaptive — Spec (LOCKED)

**Trạng thái:** Locked. Đồng thuận trước khi implement. Không gắn vào engine thật cho tới khi measurement gate (§11) thỏa.
**Phạm vi file này:** state machine + data structure + invariant + test plan cho phần *adaptive logic*.
**Ngoài phạm vi (companion doc `levi-adaptive-emit-tests.md`):** emit thread, timing wheel, seq-offset preservation, cancel-on-RST, capture-loop non-blocking.

---

## 1. Định nghĩa cơ bản

### 1.1 cuts
- `cuts: &[usize]` = offset cắt trong payload ClientHello (tính từ đầu payload).
- `segment_count = cuts.len() + 1`.
- Fast / Balanced / Hardened: `cuts.len() == 2` → 3 segment.
- Ultra: `cuts.len() == 3` → 4 segment. Ultra **chỉ hợp lệ** khi `segment_count == 4`.

### 1.2 AdaptiveLevel
```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdaptiveLevel {
    Passthrough = -1,
    Fast        = 0,
    Balanced    = 1,
    Hardened    = 2,
    Ultra       = 3,
}
```
- **Ord thủ công theo discriminant:** `Passthrough < Fast < Balanced < Hardened < Ultra`. Không `derive(PartialOrd)` (dựa thứ tự khai báo → reorder sẽ đảo semantics).
- Cấm reorder variant.

### 1.3 FlowKey
```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip:   [u8; 16], // IPv4: 4 byte đầu + 12 zero; IPv6: full 16 byte
    pub dst_ip:   [u8; 16], // IPv4: 4 byte đầu + 12 zero; IPv6: full 16 byte
    pub src_port: u16,
    pub dst_port: u16,
    pub family:   u8,       // 4 hoặc 6
}
```
- `family` phân biệt IPv4/IPv6 → tránh collide dual-stack / multi-NIC / VPN.

### 1.4 SegPlan
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentOrder {
    InOrder,        // [1,2,..,n]
    Reverse,        // [n,..,2,1]
    Fixed([u8; 4]), // chỉ khi segment_count == 4; hoán vị của 1..=4
}

#[derive(Debug, Clone)]
pub struct SegPlan {
    pub order:           SegmentOrder,
    pub inter_delay:     Duration,              // mặc định ZERO
    pub window_override: Option<(u16, u8)>,     // bitmask, mặc định None
}
```
- `window_override` bitmask index theo **segment id gốc 1-based** (bit 0 = segment 1), không theo thứ tự emit.
- **Không có** trường/logic `strip_options` (tiền đề sai: SACK chỉ ở SYN; TS không nhất quán = anomaly).
- Invariant: `order` luôn là hoán vị hợp lệ của `1..=segment_count`.

### 1.5 EscalationState (per-flow)
```rust
#[derive(Clone)]
pub struct EscalationState {
    pub level:          AdaptiveLevel,
    pub success_streak: u8,
    pub split_attempts: u8,
    pub has_success:    bool,
    pub last_seen:      Instant,
    pub cooldown_until: Option<Instant>,
    pub sni_key:        Option<String>, // normalized SNI, ghi lúc tạo entry từ ClientHello
}
```
- `sni_key`: handler inbound (RST / handshake_complete) **đọc từ state**, không parse lại packet (packet inbound không mang SNI).
- **N1:** khi update entry đã tồn tại, giữ `sni_key` cũ (không overwrite bằng `None`).

### 1.6 DomainEntry (per-SNI, gộp level + decay)
```rust
#[derive(Clone, Copy)]
pub struct DomainEntry {
    pub level: AdaptiveLevel, // sticky, đã cap tại lúc ghi
    pub decay: u8,            // counter success liên tiếp ở mức <= Fast
}
```
- Một lookup duy nhất cho sticky + decay. Không map thứ ba.

---

## 2. Hằng số (chốt số; tunable qua config, test assert giá trị mặc định)

| Hằng số                     | Giá trị | Ghi chú |
|-----------------------------|---------|---------|
| `HANDSHAKE_WINDOW`          | 3500 ms | RST ngoài cửa sổ → bỏ qua |
| `ENTRY_TTL`                 | 60 s    | xóa flow không hoạt động |
| `COOLDOWN_TTL`              | 45 s    | ở Passthrough trước khi retry |
| `MAX_ATTEMPTS`              | 4       | total emit-attempts trong đời flow (N2) |
| `SUCCESS_STREAK_DESCEND`    | 3       | success liên tiếp → giảm 1 level |
| `DOMAIN_STICKY_CAP`         | Balanced| connection mới không start cao hơn |
| `DOMAIN_STICKY_DECAY_SUCCESSES` | 5   | success liên tiếp ở <= Fast → hạ sticky 1 |
| `FLOW_MAP_CAP`              | 4096    | hand-roll LRU (xem §5) |
| `DOMAIN_MAP_CAP`            | 1024    | hand-roll LRU |

---

## 3. ProfileConfig (measurement gate thành tham số)

```rust
pub struct ProfileConfig {
    pub enabled_max_level:     AdaptiveLevel, // Fast luôn enabled (baseline vanilla)
    pub allow_inter_delay:     bool,
    pub allow_window_override: bool,
    pub balanced_cut_variant:  u8,            // 0 = vanilla cuts; >0 = variant đã đo
}
```
- Mọi deviation khỏi Fast vanilla (order, delay, window, **cut placement của Balanced**) đều bị gate bởi flag.
- Thiếu measurement → flag = false → plan rơi về hành vi an toàn.
- `plan_for` **không bao giờ** nhận level bị disable (cap-at-write + clamp-at-read, xem §4).

---

## 4. State machine (2 chiều)

Quy tắc nền: **chỉ flow CÓ entry trong `flow_map` mới đi qua machine.** Compat và flow chưa từng split (plan `None`) không tạo entry.

```text
on ClientHello(flow, hello_parse):
    // early-out key on PassThroughReason, KHÔNG suy từ sni string (B2)
    if is_passthrough_reason(hello_parse)        // Compat | NoSni | Custom | Doh
       or compat_mode_forces_passthrough(hello_parse):
        send_raw original
        return                                   // không tạo entry, không vào machine

    level = current_level(flow, hello_parse.sni, cfg)
    plan  = plan_for(level, cuts, cfg)
    if plan.is_some():
        create_or_update entry {                 // N1: giữ sni_key khi update
            level, success_streak, split_attempts, has_success,
            last_seen = now, cooldown_until = None,
            sni_key = hello_parse.sni.map(normalize),
        }
        record_split_attempt(flow)               // total attempts, không reset theo level (N2)
        emit_queue.enqueue(fragments, plan)
    else:
        send_raw original                        // Passthrough


on RST(flow, in_window):
    if !in_window: return
    st = flow_map.get_mut(flow)
    if st is None: return                        // G2: compat / chưa-split / hết TTL → vô hình
    if st.level == Passthrough or in_cooldown(st):
        refresh_cooldown(st)                     // m3: chủ đích giữ hostile domain lâu hơn
        return                                   // G1: hấp thụ, không re-fragment
    if st.split_attempts >= MAX_ATTEMPTS and !st.has_success:
        set_passthrough(flow, COOLDOWN_TTL)      // MG3: không modify domain_map
    else:
        escalate(flow, st.sni_key.as_deref(), cfg)


on handshake_complete(flow):                     // packet inbound, không SNI → đọc sni_key từ state
    st = flow_map.get_mut(flow)
    if st is None: return
    st.has_success = true
    if st.level > Fast:                          // MG2: ở Fast streak luôn 0, không tăng
        st.success_streak += 1
        if st.success_streak >= SUCCESS_STREAK_DESCEND:
            descend(flow)                        // level -= 1 (>= Fast)
            st.success_streak = 0
    // decay domain sticky (MG5: <= Fast BAO GỒM Passthrough)
    if let Some(key) = st.sni_key.as_deref():
        if st.level <= Fast:
            if let Some(entry) = domain_map.get_mut(key):
                entry.decay += 1
                if entry.decay >= DOMAIN_STICKY_DECAY_SUCCESSES:
                    entry.level = max(Fast, prev_level(entry.level))
                    entry.decay = 0


on handshake_timeout(flow):                      // MN2: không touch domain_map, không cần sni
    st = flow_map.get_mut(flow)
    if st is None: return
    if st.level > Fast and st.split_attempts > 0:
        descend(flow); st.success_streak = 0     // m2: nhất quán reset
    else if st.level == Fast and st.split_attempts > 0:
        set_passthrough(flow, COOLDOWN_TTL)
    // KHÔNG escalate (timeout = split có thể gây drop, không phải tín hiệu leo)


on engine_stop:
    flow_map.clear(); domain_map.clear()         // RAM-only, wipe cả hai
```

### 4.1 current_level (dual-path, BG2 + BG3 + MN3)
```text
current_level(flow, sni, cfg):
    if let Some(st) = flow_map.get_mut(flow):
        // flow cũ: lazy side-effect (MN3) — clamp config drift + reset cooldown hết hạn
        if st.cooldown_expired():
            st.level = Fast
            st.cooldown_until = None
        st.level = min(st.level, cfg.enabled_max_level)   // BG3 clamp-at-read
        return st.level
    else:
        // flow mới: chỉ đọc sticky, cap tại read, không mutate
        sticky = domain_map.get(normalize(sni)).map(|e| e.level).unwrap_or(Fast)
        return min(sticky, DOMAIN_STICKY_CAP)
```

### 4.2 escalate (cap-at-write, BG1 + BG3 + B1)
```text
escalate(flow, sni, cfg):
    st.level = min(st.level + 1, cfg.enabled_max_level)   // cap-at-write
    if let Some(key) = sni:
        if let Some(entry) = domain_map.get_mut(key):
            entry.decay = 0                               // BG1: reset, chỉ success LIÊN TIẾP mới đếm
            entry.level = min(st.level, DOMAIN_STICKY_CAP)
        else:
            domain_map.insert(key, DomainEntry {
                level: min(st.level, DOMAIN_STICKY_CAP),
                decay: 0,
            })
```

### 4.3 plan_for (gate, B3 + M4)
```text
plan_for(level, cuts, cfg):
    effective = min(level, cfg.enabled_max_level)         // phòng thủ, không emit level disable
    match effective:
        Passthrough -> None
        Fast        -> SegPlan { InOrder, ZERO, None }    // baseline vanilla, luôn enabled
        Balanced    -> SegPlan { InOrder, ZERO, None }    // khác Fast ở cut placement; variant gate bởi cfg.balanced_cut_variant
        Hardened    -> SegPlan { Reverse, gate_delay(cfg), gate_window(cfg) }
        Ultra       -> SegPlan { Fixed([4,2,3,1]), gate_delay(cfg), gate_window(cfg) }  // chỉ khi segment_count==4
    // gate_delay: !cfg.allow_inter_delay -> ZERO
    // gate_window: !cfg.allow_window_override -> None
```

---

## 5. Hai map + hand-roll LRU (M6)

- `flow_map:   HandLru<FlowKey, EscalationState>` (cap 4096)
- `domain_map: HandLru<String, DomainEntry>`     (cap 1024, key = normalized SNI)
- **Hand-roll LRU:** `HashMap` + `VecDeque` (hoặc intrusive), fixed cap, touch = move-to-front. Không thêm crate `lru`.
- MN1: touch là O(cap) worst-case; cap bounded → chấp nhận.
- Key `domain_map` normalize theo đúng `is_valid_fqdn_sni`: lowercase, strip trailing dot, punycode as-is (m5).
- Eviction phải hủy fragment pending của flow bị evict (companion doc).

---

## 6. Compatibility Mode / Passthrough duy nhất

- Compat và các `PassThroughReason` hiện có (`Compat | NoSni | Custom | Doh`) **phải** trả Passthrough **trước** khi machine chạy, qua cùng một đường `is_passthrough_reason`.
- Không tạo cơ chế passthrough thứ hai. Compat flow không bao giờ có entry trong `flow_map` → vô hình với mọi handler inbound (G2).

---

## 7. Domain sticky (raise / decay / cap)

- Raise: `escalate` ghi `domain_map[key].level = min(st.level, DOMAIN_STICKY_CAP)`.
- Cap: sticky **không bao giờ** cho connection mới start cao hơn Balanced (double clamp: write + read).
- Decay: `handshake_complete` khi `st.level <= Fast` (BAO GỒM Passthrough — MG5) tăng `entry.decay`; chạm `DOMAIN_STICKY_DECAY_SUCCESSES` thì hạ `entry.level` 1 bậc và reset `decay = 0`.
- BG1: `escalate` reset `entry.decay = 0` → chỉ success **liên tiếp** mới đếm.
- MG3: Passthrough **bail** (set từ RST) không modify `domain_map`. Phân biệt: *bail* không đụng domain; *success khi đang Passthrough* có decay.
- M7 (tradeoff chủ đích): sticky là RAM-only, **mất khi restart** → domain khó trả giá escalation mỗi launch. Privacy > convenience. Không persist ra đĩa.

---

## 8. Invariants (chốt, mọi test phải giữ)

1. `inter_delay` mặc định `ZERO`; chỉ > 0 khi `cfg.allow_inter_delay` và measurement chứng minh.
2. `window_override` mặc định `None`; chỉ set khi `cfg.allow_window_override`.
3. Không tồn tại `strip_options` ở bất kỳ dạng nào.
4. `order` luôn là hoán vị hợp lệ của `1..=segment_count`.
5. Timeout **không bao giờ** escalate.
6. Passthrough là thoát cuối cùng khi split liên tục hại; RST/cooldown ở Passthrough bị hấp thụ.
7. Chỉ flow có entry trong `flow_map` đi qua machine; compat / chưa-split không có entry.
8. `success_streak` chỉ tăng khi `level > Fast`; ở Fast luôn 0 (không overflow).
9. Sau mọi `descend` (success hoặc timeout), `success_streak = 0`.
10. `escalate` reset `domain_entry.decay = 0`.
11. Config drift clamp-at-read (`current_level`) + cap-at-write (`escalate`) — cả hai phải có.
12. Mọi map RAM-only; `wipe()` khi stop; không file nào được tạo.
13. `sni_key` ghi từ ClientHello, đọc từ state ở handler inbound; giữ khi update entry.

---

## 9. Bảng test (gom đầy đủ, theo nhóm)

### 9.1 Plan / SegPlan
- `passthrough_returns_none`
- `fast_is_in_order_zero_delay`
- `balanced_uses_different_cuts_not_order`
- `hardened_is_reverse_zero_delay_by_default`
- `ultra_requires_four_segments` (3 cuts → unwrap; 2 cuts → is_none)
- `property_order_is_permutation`
- `window_bitmask_indexes_original_ids`
- `plan_for_honours_measurement_flags`
- `balanced_cut_placement_also_gated`

### 9.2 State machine — RST
- `rst_inside_window_escalates_once`
- `rst_outside_window_ignored`
- `rst_during_cooldown_does_not_escalate`
- `rst_on_compat_flow_is_noop`
- `max_attempts_no_success_passthrough`
- `escalate_caps_at_highest_enabled_level` (cap-at-write)

### 9.3 State machine — success / descend
- `three_successes_descend_one_level`
- `descend_resets_streak`
- `streak_not_incremented_at_fast`
- `success_streak_no_overflow_at_fast`
- `handshake_complete_updates_domain_sticky`

### 9.4 State machine — timeout
- `timeout_does_not_escalate`
- `timeout_descends_when_split_used`
- `timeout_descend_resets_streak`
- `timeout_does_not_affect_domain_sticky`

### 9.5 current_level dual-path + config drift
- `current_level_new_flow_uses_sticky_capped`
- `current_level_existing_flow_uses_st_level`
- `config_drift_clamps_existing_flow_level` (clamp-at-read)
- `cooldown_expiry_restores_fast`

### 9.6 Domain sticky
- `domain_sticky_capped` (connection mới <= Balanced)
- `domain_sticky_clamped_at_read`
- `domain_sticky_decays_after_sustained_success`
- `decay_counter_resets_on_escalate`
- `domain_entry_holds_level_and_decay`
- `passthrough_bail_does_not_touch_domain_map`
- `domain_map_key_normalized_matches_tracker`

### 9.7 Compat / passthrough duy nhất
- `client_hello_compat_creates_no_entry`
- `compat_mode_forces_passthrough`

### 9.8 Lifecycle / privacy
- `retransmit_counts_as_separate_attempt`
- `wipe_on_engine_stop`
- `no_state_persisted_to_disk` (temp dir, không file nào tạo)

### 9.9 Companion doc `levi-adaptive-emit-tests.md` (không trộn ở trên)
- `capture_loop_does_not_block_on_delay`
- `split_enqueued_original_not_sent`
- `passthrough_sends_original`
- `fragments_preserve_seq_offsets`
- `no_duplicate_original_after_split`
- `pending_fragments_cancelled_on_rst`
- `delay_only_applied_when_plan_delay_gt_zero`
- `lru_eviction_cancels_pending_emits`
- `concurrent_update_and_read_no_panic`

---

## 10. ASCII flowchart

```text
                         +----------------------------+
                         |  ClientHello (outbound)    |
                         +--------------+-------------+
                                        |
                       is_passthrough_reason(sni)?  (Compat|NoSni|Custom|Doh)
                          /                         \
                        YES                          NO
                         |                            |
              +----------v-----------+     +----------v---------------+
              | send_raw original    |     | current_level(flow,sni,cfg)|
              | (NO entry created)   |     +----------+---------------+
              +----------------------+                |
                                        +-------------v--------------+
                                        | flow_map has entry?        |
                                        |  YES: lazy clamp+cooldown  |
                                        |        -> st.level         |
                                        |  NO : min(sticky,CAP)      |
                                        +-------------+--------------+
                                                      |
                                        +-------------v--------------+
                                        | plan_for(level,cuts,cfg)   |
                                        +---+------------------+-----+
                                            | plan Some        | plan None
                                  +-----------v-----------+   +-v--------------+
                                  | create/update entry   |   | send_raw       |
                                  | sni_key = normalize   |   | original       |
                                  | record_split_attempt  |   +----------------+
                                  | enqueue(frag,plan)    |
                                  +-----------------------+


   +------------------+     !in_window -> return
   | RST (inbound)    |-----> flow_map.get_mut -> None? -> return (G2)
   +--------+---------+                     |
            | in_window & entry exists      |
            v                               |
   +--------------------+                  |
   | level==Pass OR     |--YES--> refresh_cooldown; return (G1 absorb)
   | in_cooldown?       |                  |
   +--------+-----------+                  |
            | NO                           |
            v                              |
   +--------------------+                  |
   | attempts>=MAX AND  |--YES--> set_passthrough(cooldown)  [no domain_map]
   | !has_success?      |                  |
   +--------+-----------+                  |
            | NO                           |
            v                              |
   +--------------------+                  |
   | escalate(flow,     |                  |
   |   st.sni_key, cfg) |                  |
   +--------+-----------+                  |
            |                              |
            v                              |
   [ st.level=min(+1,cfg.max) ; domain_map raise+decay=0 ]


   +------------------------+   flow_map.get_mut -> None? -> return
   | handshake_complete     |-----------------------------|
   | (inbound, no SNI)      |                             |
   +-----------+------------+                             |
               | entry exists                             |
               v                                          |
   has_success=true                                       |
   if level>Fast: streak+=1; if>=3: descend; streak=0     |
   if let key=st.sni_key:                                 |
       if level<=Fast (incl Pass):                        |
           domain_map[key].decay+=1;                      |
           if decay>=5: level=max(Fast,prev); decay=0     |


   +------------------------+   flow_map.get_mut -> None? -> return
   | handshake_timeout      |-----------------------------|
   | (no domain_map touch)  |                             |
   +-----------+------------+                             |
               | entry exists                             |
               v                                          |
   if level>Fast & attempts>0: descend; streak=0          |
   elif level==Fast & attempts>0: set_passthrough(cooldown)|
   else: noop                                             |


   ENGINE STOP -> flow_map.clear(); domain_map.clear()
```

---

## 11. Measurement gate (điều kiện bật profile)

Hardened / Ultra / bất kỳ `inter_delay > 0`, `window_override`, hoặc `balanced_cut_variant > 0` chỉ được bật trong Adaptive khi có đủ:
- Handshake success rate trên tập domain từng RST.
- Pcap chứng minh layout segment + option presence nhất quán.
- Delta latency trên site sạch.
- Không tạo anomaly mới (option không đều, gap đều đặn, window stall).

Thiếu số liệu → flag tương ứng = false → plan rơi về an toàn. Profile có code nhưng disabled vẫn hợp lệ.

---

## 12. Quyết định tường minh / out-of-scope

- M7: sticky mất khi restart là tradeoff chủ đích (privacy > convenience).
- Compat + Adaptive dùng **một** đường Passthrough duy nhất.
- Không persist state ra đĩa.
- Emit thread / timing / seq-offset / cancel-on-RST / capture non-blocking → companion doc, không implement cùng lúc với state machine.
- Step tiếp theo (theo thứ tự đã chốt): (1) spec locked ← đây; (2) companion doc emit-tests; (3) implement `AdaptiveMaps` + `plan_for` compile được theo §1–§4; (4) measurement harness; (5) chỉ bật profile khi §11 thỏa.
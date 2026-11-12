
```markdown
# Levi Adaptive Emit — Spec (LOCKED)

**Trạng thái:** Locked. Companion của `levi-adaptive.md`.
**Phạm vi:** emit thread, timing, seq-offset, cancel-on-RST, capture-loop non-blocking.
**Không thuộc phạm vi:** Adaptive state machine (đã khóa ở `levi-adaptive.md`).

---

## 1. Nguyên tắc

- Capture loop **không bao giờ** block vì delay hoặc emit.
- Delay (nếu có) chỉ được thực hiện trên emit thread.
- Original packet bị drop khi đã enqueue plan; không gửi trùng với fragment.
- Fragment phải preserve sequence number gốc + offset payload.
- Khi nhận RST của cùng flow → hủy mọi fragment pending chưa gửi.

## 2. Luồng

```text
Capture loop:
  recv → nếu ClientHello mục tiêu và plan = Some:
           enqueue(fragments, plan, flow)
           drop original
         else:
           send_raw original
  continue (không sleep)

Emit thread:
  nhận từ queue → timing wheel (nếu inter_delay > 0)
  gửi fragment theo order, preserve seq + offset
  nếu flow bị RST / eviction / wipe → cancel pending của flow đó
```

## 3. Invariants emit

1. Capture loop không bị stall khi emit queue chậm hoặc plan có delay.
2. Khi plan = Some → original không được `send_raw`.
3. Khi plan = None → original được gửi nguyên.
4. Mỗi fragment có sequence number = seq_gốc + offset_payload.
5. Không gửi trùng original + fragment cùng payload.
6. RST inbound của flow → mọi fragment pending của flow đó bị hủy.
7. Delay chỉ được áp dụng khi `plan.inter_delay > 0`.
8. LRU eviction của flow có fragment pending → cancel các fragment đó.
9. Concurrent update/read không panic.

## 4. Bảng test (nhóm 9.9)

| Test | Kỳ vọng |
|------|---------|
| `capture_loop_does_not_block_on_delay` | Emit queue chậm / plan có delay, capture loop vẫn tiếp tục recv packet khác. |
| `split_enqueued_original_not_sent` | Khi có plan, original không được `send_raw`. |
| `passthrough_sends_original` | Khi plan = None, original được gửi nguyên. |
| `fragments_preserve_seq_offsets` | Fragment[i].seq = original.seq + offset_payload[i]. |
| `no_duplicate_original_after_split` | Không gửi original lẫn fragment trùng payload. |
| `pending_fragments_cancelled_on_rst` | RST cùng flow → hủy fragment chưa gửi. |
| `delay_only_applied_when_plan_delay_gt_zero` | Delay mặc định 0; chỉ timing wheel khi plan có delay. |
| `lru_eviction_cancels_pending_emits` | Evict flow có fragment chờ → hủy pending. |
| `concurrent_update_and_read_no_panic` | Nhiều flow update/read song song không deadlock/panic. |

## 5. Quyết định

- Emit thread + timing wheel là implementation detail của companion này.
- Không gắn vào engine thật cho tới khi measurement gate (`levi-adaptive.md` §11) có số liệu.
- State machine và emit có thể implement song song sau khi cả hai spec locked.
```
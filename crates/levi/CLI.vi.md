# Levi — Engine Ổn định Kết nối & Công cụ Dòng lệnh Headless

[English](CLI.md) · **Tiếng Việt**

`levi` là native connection-resilience engine thuần Rust và công cụ dòng lệnh không giao diện độc lập (`levi.exe`), được thiết kế nhằm bảo vệ tính toàn vẹn và duy trì độ ổn định của các luồng kết nối HTTPS trên các đường truyền mạng hay bị ngắt quãng, mất gói hoặc chèn ép tín hiệu:

- **Công cụ Headless CLI độc lập & Crate nhúng:** Có thể chạy trực tiếp như một tiến trình console daemon siêu nhẹ (`dist/levi.exe`, ~500 KB) hoặc liên kết trực tiếp vào ứng dụng giao diện Yeager.
- **Trong suốt, Không cần cấu hình (Zero-configuration):** Hoạt động trực tiếp tại tầng mạng Windows thông qua driver WinDivert 2.2 đã ký số được nhúng sẵn; không cần cấu hình proxy HTTP/SOCKS cục bộ và không cần cài thêm chứng chỉ CA.
- **Độ chính xác phẫu thuật (Surgical Precision):** Chỉ tác động tối thiểu vào phân đoạn bắt tay TLS `ClientHello`; 100% dữ liệu ứng dụng sau đó truyền trực tiếp ở tốc độ dây phần cứng (hardware line-rate).
- **Fast-Path không cấp phát Heap (Zero-Heap):** Các gói tin không thuộc mục tiêu và lưu lượng DNS mã hóa được chuyển tiếp tức thì không qua cấp phát heap, giữ độ trễ thêm vào dưới 20 microsecond.
- **Worker Pool có giới hạn, triệt tiêu độ trễ:** Phân phối xử lý gói tin qua nhóm 4–6 luồng chuyên trách giao tiếp qua `sync_channel(256)`, loại bỏ hoàn toàn hiện tượng giật do tạo luồng động của hệ điều hành.

---

## 1. Hướng dẫn nhanh Công cụ Dòng lệnh Headless (`levi.exe`)

File thực thi dòng lệnh độc lập nằm tại `dist/levi.exe` hoặc có thể biên dịch trực tiếp bằng lệnh `cargo build -p levi --bin levi --release`.

> [!IMPORTANT]
> Do Levi tương tác trực tiếp với tầng mạng qua driver WinDivert, `levi.exe` bắt buộc phải được chạy từ cửa sổ **Command Prompt (CMD) hoặc PowerShell dưới quyền Administrator**.

### Cách dùng cơ bản

```powershell
# Chạy với cấu hình mặc định (Phạm vi: Toàn bộ HTTPS, Profile: Auto)
.\levi.exe

# Chỉ định rõ ràng xử lý toàn bộ lưu lượng HTTPS ra ngoài (Cổng 443)
.\levi.exe --all

# Chạy với profile Tối ưu tốc độ (In-Order 3-way split, 0ms trễ, tối ưu Gaming & VPN)
.\levi.exe --all --profile fast

# Chạy với profile Tăng cường (Alternative-sequence split kèm timing 3.3ms–3.5ms)
.\levi.exe --all --profile hardened

# Chạy ở chế độ Giám sát (Thu thập dữ liệu đo lường thụ động, không sửa đổi gói tin)
.\levi.exe --all --profile observe

# Chỉ áp dụng cho danh sách tên miền mục tiêu cụ thể
.\levi.exe --profile fast --hosts example.com,cdn.example.org,api.target.net
```

### Bảng tham số dòng lệnh (CLI Options)

| Cờ (Flag) | Tham số | Mô tả |
| :--- | :--- | :--- |
| `--all` | *(không)* | Xử lý toàn bộ lưu lượng HTTPS đi ra trên cổng TCP 443. *(Phạm vi mặc định)* |
| `--profile` | `auto` \| `fast` \| `hardened` \| `observe` | Chọn cấu hình truyền tải ổn định kết nối. Mặc định là `auto`. |
| `--hosts` | `domain1,domain2,...` | Giới hạn phân đoạn gói theo danh sách tên miền ngăn cách bởi dấu phẩy (so khớp SNI). |

### Dừng an toàn & Báo cáo Giám sát Truyền tải (Telemetry Report)

Bấm phím <kbd>Enter</kbd> bất kỳ lúc nào để dừng engine. Levi sẽ ngay lập tức đóng handle WinDivert, gỡ hook tầng nhân, khôi phục luồng truyền dữ liệu sạch và xuất **Báo cáo Giám sát Truyền tải**:

```text
==================================================
   LEVI ENGINE TRANSPORT TELEMETRY REPORT        
==================================================
  Total TLS Handshakes Intercepted : 142
  Sessions Stabilized (Multi-Split): 142
  Inbound Middlebox RSTs Silenced  : 38
  Stabilization Coverage Rate      : 100.0%
==================================================
```

---

## 2. Các Cấu hình Truyền tải (`ResilienceProfile`)

Levi cung cấp 4 cấu hình truyền tải chuẩn hóa qua enum `ResilienceProfile`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResilienceProfile {
    #[default]
    Auto,      // Tự động tối ưu 0ms trễ; thích ứng cả mạng trực tiếp lẫn đường hầm VPN
    Fast,      // In-Order 3-Way Multi-Split (0ms trễ; tối ưu Gaming, Streaming & WireGuard)
    Hardened,  // Alternative-Sequence Multi-Split + Timing chuẩn hóa 3.3ms–3.5ms (cho đường truyền nhiều can thiệp)
    Observe,   // Chế độ Giám sát thụ động (0% sửa đổi gói tin; đếm bắt tay và phát hiện reset bất thường)
}
```

### 2.1. Profile `Fast` (In-Order Multi-Split — 0ms Trễ)
- **Cơ chế:** Phân tách gói TLS `ClientHello` tại 2 điểm phẫu thuật thành 3 đoạn:
  - *Điểm cắt 1:* Ngay sau byte thứ 2 của TLS Record Header (`0x16 0x03`).
  - *Điểm cắt 2:* Điểm chính giữa (midpoint) của Server Name Indication (SNI).
- **Thứ tự truyền:** Đoạn 1 $\rightarrow$ Đoạn 2 $\rightarrow$ Đoạn 3 (**đúng thứ tự tuần tự, 0 ms độ trễ thêm vào**).
- **Ưu điểm:**
  - Giữ nguyên vẹn số thứ tự TCP sequence; tương thích 100% với các đường hầm VPN (WireGuard, NetBird, OpenVPN, MTU 1280).
  - Phù hợp tuyệt đối cho game đối kháng, đàm thoại (Discord) và truyền phát trực tiếp nơi độ trễ phát sinh là điều cấm kỵ.

### 2.2. Profile `Hardened` (Alternative-Sequence Multi-Split + Hybrid Timing)
- **Cơ chế:** Phát các phân đoạn theo thứ tự luân phiên: Đoạn 3 $\rightarrow$ [Hybrid Timing] $\rightarrow$ Đoạn 2 $\rightarrow$ [Hybrid Timing] $\rightarrow$ Đoạn 1.
- **Định thời độ chính xác cao (Hybrid Wait):** Kết hợp `thread::sleep` (tiết kiệm pin và CPU) và vòng lặp CPU cycle spin-loop (`Instant::now()` + `std::hint::spin_loop()`) trong khoảng $[3300\,\mu\text{s} .. 3500\,\mu\text{s}]$.
- **Ứng dụng:** Giúp kết nối vượt qua các hàng đợi thiết bị mạng nghẽn hoặc môi trường mạng hay làm treo gói bắt tay đầu tiên.

### 2.3. Profile `Observe` (Giám sát Thụ động & Đo kiểm)
- **Cơ chế:** Không sửa đổi bất kỳ gói tin nào. 100% bắt tay TLS đi qua nguyên bản.
- **Ứng dụng:** Đo đạc và chẩn đoán mạng an toàn. Giúp kiểm tra xem mạng có xuất hiện các gói TCP RST ngắt kết nối bất thường hay không mà không làm thay đổi cấu trúc gói tin.

### 2.4. Profile `Auto` (Mặc định)
- Tự động ưu tiên chiến lược `Fast` (In-Order) để đem lại sự bảo vệ tức thì với 0ms trễ, tự động thích ứng mượt mà khi người dùng bật/tắt VPN hoặc thay đổi kết nối mạng.

---

## 3. Cơ chế Khử Gói Reset Bất thường (Inbound Reset Silencer)

Một số thiết bị mạng trung gian thường gửi gói tin `TCP RST` bất thường (`SrcPort == 443`) về phía client trước khi máy chủ đích kịp phản hồi. Levi triển khai bộ lọc chặn bắt ở tầng nhân:

```text
(inbound and tcp.SrcPort == 443 and tcp.Rst)
```

- Mọi gói RST bất thường xuất hiện trong giai đoạn thiết lập bắt tay (khoảng 3.5 giây đầu) đều bị âm thầm triệt tiêu (silenced) ngay tại tầng driver, bảo vệ trọn vẹn socket cho đến khi dữ liệu hợp lệ từ máy chủ phản hồi.
- Các gói đóng kết nối bình thường từ máy chủ sau khi phiên đã thiết lập thành công luôn được cho qua bình thường.
- Số lượng gói RST bất thường bị triệt tiêu được thống kê theo thời gian thực tại `STATS_DROPPED_RSTS`.

---

## 4. Bộ đếm Giám sát Thời gian thực

Các atomic counter toàn cục cho phép CLI và UI đọc đồng thời mà không bị nghẽn khóa (lock-free):

- `levi::STATS_HANDSHAKES`: Tổng số phiên bắt tay TLS được tiếp nhận.
- `levi::STATS_STABILIZED`: Tổng số phiên TLS đã được ổn định thành công.
- `levi::STATS_DROPPED_RSTS`: Tổng số gói tin RST bất thường đã triệt tiêu.

---

## 5. Hướng dẫn Tích hợp Thư viện Rust (`crates/app`)

Levi có thể được nhúng vào bất kỳ ứng dụng Rust nào:

```rust
use common::Config;
use levi::ResilienceProfile;
use std::sync::atomic::Ordering;

// 1. Khởi chạy engine với cấu hình mặc định (Profile Auto)
levi::start(&cfg)?;

// 2. Hoặc khởi chạy với profile cụ thể
levi::start_with_profile(&cfg, ResilienceProfile::Fast)?;

// 3. Đọc dữ liệu thống kê thời gian thực (ví dụ cho vòng lặp UI cập nhật)
let handshakes = levi::STATS_HANDSHAKES.load(Ordering::Relaxed);
let stabilized = levi::STATS_STABILIZED.load(Ordering::Relaxed);
let rst_dropped = levi::STATS_DROPPED_RSTS.load(Ordering::Relaxed);

// 4. Dừng engine an toàn (giải phóng driver handle và worker pool trong < 0.1s)
levi::stop();
```

---

## 6. Biên dịch từ Mã nguồn

Để biên dịch file thực thi dòng lệnh headless độc lập:

```powershell
# Từ thư mục gốc của dự án Yeager
cargo build -p levi --bin levi --release

# File thực thi đầu ra:
# target/release/levi.exe (~500 KB)
```

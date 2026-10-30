# Yeager — Tài liệu thiết kế

[English](DESIGN.md) · **Tiếng Việt**

> Phiên bản 1.0.0 · Windows 11 x64 · Rust + Slint + WinDivert

Tài liệu này mô tả cấu trúc của Yeager và các nguyên tắc mã nguồn tuân theo.
Hướng dẫn cài đặt và sử dụng xem ở [README](../README.vi.md).

## 1. Nguyên tắc

Yeager là công cụ hỗ trợ mạng cục bộ, **không phải** VPN, proxy hay công cụ ẩn
danh.

1. **Trong suốt.** Trình duyệt và ứng dụng không cần cấu hình proxy hay cài
   thêm chứng chỉ. Lưu lượng đi thẳng tới đích bằng IP của chính người dùng và
   vẫn được mã hóa đầu cuối.
2. **Chính xác.** Chỉ tác động ở nơi có ích (một cổng, danh sách tên miền tùy
   chọn); mọi thứ khác chạy với tốc độ gốc.
3. **Hoàn tác được.** Mọi thay đổi hệ thống đều được lưu trước, và trả lại khi
   tắt, khi thoát và ở lần mở sau khi bị tắt đột ngột.
4. **Nhẹ.** Một file chạy gốc ở khay hệ thống, tốn ít bộ nhớ khi rảnh, CPU chỉ
   tăng ngắn lúc thiết lập kết nối.
5. **Thân thiện với phần mềm bảo mật.** Dùng Windows API thay vì PowerShell ẩn
   hay ghi registry trực tiếp; không gói tin giả, không cờ TCP bất thường.

## 2. Kiến trúc

Một Cargo workspace với các crate đặt tên theo nhân vật *Attack on Titan*:

```
yeager/
├── Cargo.toml          gốc workspace
├── crates/
│   ├── app/            Yeager: giao diện Slint, khay hệ thống, điều phối (yeager.exe)
│   ├── levi/           Levi:   thư viện engine kết nối + CLI levi.exe
│   ├── erwin/          Erwin:  điều khiển tắc nghẽn TCP, cấu hình, khởi động cùng Windows
│   ├── hange/          Hange:  bộ phân giải DNS over HTTPS/3, thiết lập DoH hệ thống
│   └── common/         kiểu dùng chung, mô hình cấu hình, lỗi, tiện ích tiến trình
├── assets/             file driver, phông chữ, icon
├── installer/          script Inno Setup
├── tools/              tạo icon, script kiểm tra DNS
└── docs/               tài liệu này
```

### Luồng dữ liệu

```
 Trình duyệt / ứng dụng
       │
       ▼
 Ngăn xếp TCP/IP Windows ── Erwin: điều khiển tắc nghẽn (BBRv2 / CUBIC / CTCP)
       │
       ├── DNS (cổng 53) ──► stub Hange 127.0.0.1:53 ──► DoH qua HTTP/3 (→ HTTP/2) ──► nhà cung cấp
       │
       └── HTTPS (443) ────► Levi: Toàn bộ / Theo tên miền ──► Internet
```

### Phụ thuộc giữa các tính năng

- Engine cần DNS mã hóa: bật engine sẽ bật DoH trước; tắt DoH sẽ dừng engine.
- DoH và tối ưu TCP mỗi thứ chạy độc lập.

## 3. Các module

### app — Yeager

- Giao diện Slint gồm các trang Trang chính, Hệ thống, Engine, TCP, DNS và Giao
  diện; có chữ tiếng Việt và tiếng Anh.
- Menu khay hệ thống; đóng cửa sổ là ẩn xuống khay, *Thoát* mới tắt hẳn.
- Thao tác lâu chạy ở luồng nền rồi báo kết quả về luồng giao diện.
- Khi thoát: dừng engine, khôi phục thiết lập TCP, tắt DoH.
- Engine chỉ được gọi qua `crates/app/src/engine.rs` (`start`, `stop`,
  `is_running`).
- Kèm manifest `requireAdministrator` và icon ứng dụng qua `embed-resource`.

### levi — engine kết nối

- Thư viện Rust gốc liên kết vào `yeager.exe`, cùng bản dòng lệnh `levi.exe`
  độc lập (~486 KB).
- Nhúng driver WinDivert 2.2 đã ký số và giải nén khi khởi động; không cần cài
  riêng.
- Hỗ trợ 4 Cấu hình Truyền tải (`ResilienceProfile`):
  - `Auto` (Tự động, mặc định của `start`): chọn `Fast`.
  - `Fast` (Tối ưu tốc độ): Phân mảnh 3 đoạn In-Order, 0ms trễ thêm, tối ưu cho Gaming và WireGuard VPN.
  - `Hardened` (Tăng cường): Phân mảnh chống can thiệp luồng (Disorder + Jitter 3.3ms..3.5ms).
  - `Observe` (Giám sát): thụ động; đếm handshake và gói reset bị chèn, mọi gói
    tin gửi đi nguyên vẹn.
- Phạm vi: `All` (mọi kết nối TCP 443 đi ra) hoặc `HostList` (chỉ tên miền
  trong danh sách và tên miền con).
- Không chặn: nhóm 4 đến 6 worker threads chuyên trách giao tiếp qua hàng đợi
  `sync_channel(256)`, loại bỏ hoàn toàn chi phí cấp phát luồng của Windows.
- Chiều đi chỉ bắt các gói mở đầu kết nối, nên ACK và keepalive không lên tới
  user space; đường xử lý từng gói hoàn toàn không cấp phát bộ nhớ (zero-alloc).
- Chống can thiệp: cơ chế Inbound RST Silencer tự động triệt tiêu các gói reset
  giả mạo từ middlebox trên cổng 443 đến trước phản hồi TLS của máy chủ. Chỉ
  bỏ gói reset khớp với kết nối vừa mở trong 3,5 giây, nên reset thật của máy
  chủ trên kết nối đã thiết lập vẫn đóng được socket.
- Không động tới lưu lượng nội bộ: đích riêng và cục bộ (RFC 1918, loopback,
  link-local, ULA) và đích IPv6 cùng /64 với nguồn đi thẳng.
- Giám sát thời gian thực: công khai các atomic counters (`STATS_HANDSHAKES`,
  `STATS_STABILIZED`, `STATS_DROPPED_RSTS`) cho giao diện người dùng.
- Loại trừ DNS (cổng 53) và các kết nối DoH upstream của chính Yeager, đồng thời
  bỏ qua gói tin do chính engine gửi ra (`!impostor`).
- `start(&Config)`, `start_with_profile(&Config, ResilienceProfile)`, `stop()` và
  `is_running()`; khi dừng, handle driver và worker pool giải phóng trong < 0.1s.
- Do chủ dự án duy trì.

### erwin — tối ưu TCP và cấu hình

- Đặt thuật toán điều khiển tắc nghẽn cho mẫu TCP `internet` của Windows qua
  `netsh int tcp set supplemental`, cùng với pacing profile.
- **Tự động:** ping 1.1.1.1 và 8.8.8.8; đường truyền sạch, ổn định dùng CUBIC;
  mất gói, dao động hoặc đường xa dùng BBRv2.
- **Chẩn đoán:** tải có giới hạn thời gian từ `speed.cloudflare.com` với từng
  thuật toán, so sánh băng thông và độ trễ khi tải, rồi đề xuất thuật toán tốt
  nhất.
- Sao lưu thuật toán và pacing gốc vào `tcp-backup.json` trước lần thay đổi đầu
  tiên; `restore()` trả lại; *Khôi phục mặc định Windows* khôi phục bản sao lưu,
  hoặc nếu không có thì đặt CUBIC và tắt pacing.
- Quản lý `Config` (`%LOCALAPPDATA%\Yeager\config.json`, ghi nguyên tử) và tác
  vụ đăng nhập có quyền quản trị dùng cho khởi động cùng Windows.

### hange — DNS mã hóa

- Stub cục bộ ở `127.0.0.1:53` và `[::1]:53` (UDP và TCP) với cache LRU 4096 bản
  ghi theo TTL. Câu trả lời có kết quả được giữ ít nhất 60 giây (TTL 0 không bao
  giờ được lưu). Máy chủ phân giải được gọi bằng IP nên không có bước khởi tạo
  bằng DNS không mã hóa.
- Giữ kết nối ấm: nếu có truy vấn trong 15 phút gần nhất, kết nối nào rảnh 40
  giây sẽ được gửi một truy vấn nhỏ (kiểm tra mỗi 45 giây), để lần tra cứu sau
  không phải bắt tay TLS/QUIC lại. Khi máy không dùng thì không gửi gì.
- Mỗi kết nối upstream mới được đua cùng lúc trên mọi địa chỉ máy chủ, qua cả
  DNS over HTTP/3 và HTTP/2 (3 giây để kết nối, 1,5 giây mỗi truy vấn). Câu trả
  lời đầu tiên được dùng ngay; trong các đường trả lời thêm trong 1 giây sau đó,
  đường nhanh nhất được giữ lại. HTTP/3 bị loại khỏi cuộc đua 2 phút khi không
  đường nào của nó trả lời, nhân đôi dần tới 30 phút; đường đang dùng được đua
  lại ngầm mỗi 10 phút.
- Khi upstream lỗi hoặc chậm quá 1,5 giây, bản ghi đã hết hạn (trong vòng một
  ngày) được trả với TTL 30 giây rồi làm mới ngầm (RFC 8767).
- Upstream nằm trong một nhóm: nhà cung cấp đã chọn và một dự phòng (AdGuard và
  Google dự phòng bằng Cloudflare, Cloudflare bằng Google), dự phòng trả lời sau
  khi nhà cung cấp chính lỗi quá 10 giây; nhà cung cấp chính được thử lại mỗi 30
  giây. Ở chế độ Tự động, nhóm gồm Cloudflare và Google, chuyển sang bên kia khi
  bên đó nhanh hơn trên 20% (và ít nhất 5 ms) trong 2 lần đo liên tiếp, đo mỗi
  30 phút. AdGuard không bao giờ được chọn tự động vì nó lọc nội dung.
- Ứng dụng hiện đường đi và độ trễ của từng nhà cung cấp: bên đang dùng lấy từ
  chính các truy vấn thật, các bên khác đo bằng một truy vấn nhỏ cho mỗi địa chỉ
  và giao thức khi trang DNS đang mở (tối đa 2 phút một lần).
- Mỗi card mạng đang hoạt động đặt stub lên đầu, sau đó là máy chủ của nhà cung
  cấp với DoH của Windows bắt buộc (không lùi về UDP), nên khi stub dừng thì
  dùng DoH của Windows, không bao giờ là DNS không mã hóa. Nếu cổng 53 đã bị
  chiếm hoặc tắt *DNS cục bộ*, chỉ dùng DoH của Windows. Ở chế độ Tự động,
  Windows đặt Cloudflare phía sau stub.
- DNS của card mạng được đặt qua IP Helper API (`GetAdaptersAddresses`,
  `SetInterfaceDnsSettings` với thuộc tính DoH cho từng máy chủ).
- Dùng kho chứng chỉ Windows nên vẫn chạy khi phần mềm diệt virus quét TLS.
- Khi tắt, card mạng trở về DNS từ DHCP; phần sót lại sau khi bị tắt đột ngột
  được dọn ở lần mở tiếp theo. Bộ kiểm thử nội bộ kiểm tra kết quả từ bên
  ngoài ứng dụng.

### common

`Config`, `Scope`, `Congestion`, `DohProvider`, kiểu `Error` dùng chung và các
tiện ích chạy công cụ hệ thống không bật cửa sổ console.

## 4. Lộ trình

1. **Nền tảng** — workspace, khung Slint, khay hệ thống, điểm tích hợp engine. ✔
2. **Lõi engine** — engine gốc với driver nhúng, phạm vi áp dụng, CLI. ✔
3. **TCP và DNS** — điều khiển tắc nghẽn có chẩn đoán, DoH qua HTTP/3. ✔
4. **1.0.0** — giao diện và tài liệu song ngữ, bản phát hành công khai đầu tiên. ✔
5. **Tiếp theo** — ký số mã nguồn, hỗ trợ Encrypted Client Hello (ECH), màn hình
   thống kê, cấu hình theo từng mạng.

## 5. Ghi chú phát hành cho người duy trì

- Driver `.sys` của WinDivert được tác giả ký số; giữ nguyên bản chính thức
  trong `assets/engine/`.
- Số phiên bản nằm ở `Cargo.toml` (`workspace.package.version`) và
  `installer/setup.iss` (`AppVersion`); cập nhật [CHANGELOG.md](../CHANGELOG.md)
  và [CHANGELOG.vi.md](../CHANGELOG.vi.md) mỗi lần phát hành.
- Trang phát hành phải giữ huy hiệu ghi công "Made with Slint" (xem
  [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md)).

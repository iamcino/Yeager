# Privacy · Quyền riêng tư

**English** · [Tiếng Việt](#tiếng-việt)

_Last updated: 30 October 2026_

Yeager does not collect, store or send any personal data to its authors.
There is no account, telemetry, analytics, crash reporting or advertising.

## What stays on your computer

| Item | Location |
|------|----------|
| Settings (`config.json`) | `%LOCALAPPDATA%\Yeager` |
| TCP settings backup (`tcp-backup.json`) | `%LOCALAPPDATA%\Yeager` |
| Unpacked network driver | Windows temporary folder |
| Launch-at-login task (if enabled) | Windows Task Scheduler, task `Yeager` |

Uninstalling Yeager removes all of these.

## Connections Yeager makes

- **Encrypted DNS** (when DoH is on): your DNS queries go, encrypted, to the
  provider you choose: Cloudflare (`cloudflare-dns.com`, 1.1.1.1), Google
  (`dns.google`, 8.8.8.8) or AdGuard (`dns.adguard-dns.com`, 94.140.14.14).
  This replaces the DNS server your Internet provider would otherwise see. See the
  [Cloudflare](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/),
  [Google](https://developers.google.com/speed/public-dns/privacy) and
  [AdGuard](https://adguard-dns.io/en/privacy.html) resolver privacy policies.
- **TCP Auto and Diagnose** (only when you use them): pings to 1.1.1.1 and
  8.8.8.8, and a short download from `speed.cloudflare.com`.
- **ISP name** (once a few seconds after start, and when you run Diagnose): a
  request to `speed.cloudflare.com/meta`, which answers with the network
  (AS number and its owner) your connection comes from, shown in the sidebar.
- **Network card** (on the home page: when you press Refresh, and at most
  every 10 minutes while the home page shows): one request to
  `speed.cloudflare.com/meta` over IPv4 and one over IPv6, to show your public
  addresses. The local addresses are read from Windows; nothing is sent for
  them.
- **Update check** (at start and every few hours, unless you turn it off under
  General → Updates): a request to `github.com` to read the latest release
  number. Only when you press **Update** is the new `yeager.exe` and its
  checksum list downloaded from GitHub. GitHub sees your IP address, as with
  any visit; see the
  [GitHub privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).

The connection engine works locally on your own traffic and sends nothing
anywhere by itself. Yeager does not read or record the content of your
connections.

---

## Tiếng Việt

_Cập nhật lần cuối: 29/10/2026_

Yeager không thu thập, lưu trữ hay gửi bất kỳ dữ liệu cá nhân nào cho tác giả.
Không có tài khoản, không thu thập dữ liệu sử dụng, không phân tích, không báo
cáo lỗi tự động và không quảng cáo.

### Dữ liệu nằm trên máy bạn

| Mục | Vị trí |
|-----|--------|
| Thiết lập (`config.json`) | `%LOCALAPPDATA%\Yeager` |
| Bản sao lưu thiết lập TCP (`tcp-backup.json`) | `%LOCALAPPDATA%\Yeager` |
| Driver mạng đã giải nén | Thư mục tạm của Windows |
| Tác vụ khởi động cùng Windows (nếu bật) | Task Scheduler, tác vụ `Yeager` |

Gỡ cài đặt Yeager sẽ xoá toàn bộ những mục trên.

### Các kết nối Yeager tạo ra

- **DNS mã hóa** (khi bật DoH): truy vấn DNS của bạn được gửi, đã mã hóa, tới
  nhà cung cấp bạn chọn: Cloudflare (`cloudflare-dns.com`, 1.1.1.1), Google
  (`dns.google`, 8.8.8.8) hoặc AdGuard (`dns.adguard-dns.com`, 94.140.14.14),
  thay cho máy chủ DNS của nhà mạng. Xem chính sách quyền riêng tư của
  [Cloudflare](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/),
  [Google](https://developers.google.com/speed/public-dns/privacy) và
  [AdGuard](https://adguard-dns.io/en/privacy.html).
- **TCP Tự động và Chẩn đoán** (chỉ khi bạn dùng): ping tới 1.1.1.1 và 8.8.8.8,
  và một lần tải ngắn từ `speed.cloudflare.com`.
- **Tên nhà mạng** (một lần vài giây sau khi mở, và khi bạn bấm Chẩn đoán):
  một yêu cầu tới `speed.cloudflare.com/meta`, trả về mạng (số AS và đơn vị sở
  hữu) mà kết nối của bạn đi ra, hiện ở thanh bên.
- **Thẻ thông tin mạng** (ở trang chính: khi bạn bấm Làm mới, và tối đa 10
  phút một lần khi đang mở trang chính): một yêu cầu tới
  `speed.cloudflare.com/meta` qua IPv4 và một qua IPv6, để hiện địa chỉ công
  cộng của bạn. Địa chỉ nội bộ đọc từ Windows, không gửi gì đi.
- **Kiểm tra cập nhật** (khi mở và vài giờ một lần, trừ khi bạn tắt ở Hệ thống
  → Cập nhật): một yêu cầu tới `github.com` để đọc số phiên bản mới nhất. Chỉ
  khi bạn bấm **Cập nhật** thì `yeager.exe` mới và danh sách mã kiểm tra mới
  được tải từ GitHub. GitHub thấy địa chỉ IP của bạn như mọi lần truy cập; xem
  [tuyên bố quyền riêng tư của GitHub](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).

Engine kết nối chỉ làm việc cục bộ trên lưu lượng của chính bạn và không tự gửi
gì đi đâu. Yeager không đọc hay ghi lại nội dung kết nối của bạn.

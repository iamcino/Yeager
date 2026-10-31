# Nhật ký thay đổi

[English](CHANGELOG.md) · **Tiếng Việt**

Mọi thay đổi đáng chú ý của Yeager được ghi lại ở đây, theo định dạng
[Keep a Changelog](https://keepachangelog.com/vi/1.1.0/) và
[Semantic Versioning](https://semver.org/lang/vi/).

## [Unreleased]

## [1.0.9] - 2026-10-31

### Thêm
- **Mỗi lúc chỉ một Yeager.** Mở Yeager khi nó đang chạy, từ menu Start, shortcut ngoài desktop hay bấm đúp thêm lần nữa, sẽ đưa cửa sổ đang chạy lên trước, kể cả khi nó đang ẩn ở khay hệ thống, thay vì mở thêm bản thứ hai tranh nhau cùng thiết lập TCP và DNS.

### Thay đổi
- **Cập nhật hoàn tất gọn gàng.** Sau khi cập nhật trong ứng dụng, bản mới chờ bản cũ đóng hẳn và trả thiết lập mạng về như cũ rồi mới chạy, nên cập nhật xong Yeager luôn chạy lại.
- **Thẻ Mạng:** trên mạng có địa chỉ IPv6 nhưng IPv6 không thông, nút Làm mới báo không lấy được IPv6 công khai sau khoảng 3 giây thay vì tới 10 giây. Mạng chỉ có IPv4 vẫn xong ngay.
- **Độ trễ thấp:** mô tả ngắn gọn hơn, nói rõ chế độ dùng để làm gì (chơi game, remote desktop), mạng ngắt vài giây khi bật/tắt, và một phần chỉ có hiệu lực sau khi khởi động lại máy.
- Thuộc tính file `yeager.exe` giờ mô tả Yeager là ứng dụng tối ưu mạng và tăng độ ổn định đường truyền cho Windows.

## [1.0.8] - 2026-10-30

### Thay đổi
- DNS cục bộ giữ kết nối tới nhà cung cấp luôn sẵn sàng khi bạn đang dùng máy, nên lần tra cứu đầu tiên sau lúc nghỉ không phải chờ bắt tay lại. Khi máy không dùng thì không gửi gì.
- DNS cục bộ giữ câu trả lời ít nhất 60 giây, nên các trang đặt TTL rất ngắn không bị tra cứu lặp lại liên tục.
- Engine: xử lý kết nối mới nhanh hơn ở cấu hình Tự động và Tối ưu tốc độ; lưu lượng DNS của AdGuard được để nguyên như các nhà cung cấp DNS mã hoá khác.
- Thẻ Mạng: không còn tra cứu IPv6 trên mạng không có IPv6, nên nút Làm mới xong ngay trên kết nối chỉ có IPv4.

### Sửa lỗi
- Icon ở thanh bên giờ được vẽ bằng nét vector thay vì ảnh tô màu, nên không còn bị vỡ hay mất nét.

## [1.0.7] - 2026-10-30

### Bổ sung
- Engine: thêm cấu hình truyền tải **Giám sát**, không thay đổi gói tin nào, chỉ đếm kết nối và gói ngắt kết nối bị chèn, để kiểm tra an toàn xem mạng đang hoạt động ra sao.
- Trang chính: thẻ **Mạng** hiện địa chỉ IPv4 và IPv6 nội bộ lẫn công cộng, kèm nút Làm mới.
- Kéo mép và góc cửa sổ để đổi kích thước; lần sau mở lại đúng kích thước đã để.

### Thay đổi
- Engine: gói ngắt kết nối bị chèn chỉ bị bỏ trong lúc kết nối đang được mở (khoảng 3,5 giây), nên máy chủ thật đóng một kết nối đã thiết lập không còn bị giữ lại.
- Engine: kết nối tới địa chỉ riêng, cục bộ và thiết bị IPv6 cùng mạng /64 với máy (NAS, TV…) đi thẳng với tốc độ mạng LAN.
- Cửa sổ mở to hơn (860 × 600).

### Sửa lỗi
- Giá trị dài ở trang chính, như trạng thái DNS mã hoá, được cắt bằng "…" thay vì tràn ra ngoài thẻ.
- Icon ở thanh bên được vẽ màu xám thay vì đen bên dưới màu hiển thị, để không hiện điểm đen.

## [1.0.6] - 2026-10-30

### Bổ sung
- Engine: ba cấu hình truyền tải. **Tự động** (mặc định) chọn **Tối ưu tốc độ**: chia phần mở đầu mỗi kết nối HTTPS thành ba đoạn gửi đúng thứ tự, không thêm độ trễ, chạy tốt cả trên đường truyền trực tiếp lẫn trong đường hầm WireGuard / NetBird. **Tăng cường** gửi các đoạn đảo thứ tự kèm một quãng nghỉ ngắn đã hiệu chỉnh (khoảng 3,4 ms), dành cho mạng can thiệp mạnh hơn. Chọn ở trang Engine; trang chính hiện cấu hình đang dùng.
- Trang Engine: bộ đếm trực tiếp số kết nối đã ổn định và số lần ngắt kết nối bất thường đã chặn; ô trạng thái ở thanh bên cũng hiện số lần đã chặn.
- `levi.exe`: thêm `--profile auto|fast|hardened` và in tóm tắt các bộ đếm khi dừng.

### Thay đổi
- Engine: gói reset giả do mạng chèn vào giờ bị bỏ ngay ở tầng driver, trước khi tới socket của ứng dụng.
- Engine: phần việc của từng kết nối chạy trên một nhóm cố định 4–6 luồng xử lý thay vì tạo luồng mới cho mỗi kết nối, và tắt engine giờ mất chưa tới một giây.

## [1.0.5] - 2026-10-30

### Bổ sung
- Trang DNS: thêm nhà cung cấp **Tự động**, dùng bên trả lời nhanh hơn giữa Cloudflare và Google. AdGuard vẫn là lựa chọn riêng vì nó chặn quảng cáo.
- Mỗi nhà cung cấp DNS hiện giao thức và độ trễ đo được trên mạng của bạn (ví dụ "HTTP/2 · 35 ms"); trang chính hiện độ trễ của DNS đang dùng.
- Nếu nhà cung cấp DNS đã chọn không tới được quá 10 giây, một nhà cung cấp khác tạm thay cho tới khi nó trở lại, và ứng dụng có báo (với AdGuard: trong lúc đó không chặn quảng cáo).
- Khi máy chủ DNS không tới được, các trang vừa vào vẫn mở được nhờ bộ nhớ đệm.

### Thay đổi
- "Tăng tốc bằng HTTP/3" đổi thành **DNS cục bộ**: thử cùng lúc mọi địa chỉ máy chủ qua HTTP/3 và HTTP/2 rồi giữ đường nhanh nhất, thay vì luôn ưu tiên IPv4 và HTTP/3.
- Độ trễ DNS ở trang chính được đo bằng truy vấn DNS thật thay vì ping.

### Sửa lỗi
- AdGuard DNS không còn bị khựng vài giây khi vừa chuyển sang hoặc khoảng mỗi phút một lần, và giờ dùng đường nhanh nhất của nó (thường là IPv6 qua HTTP/2).

## [1.0.4] - 2026-10-29

### Bổ sung
- Thêm AdGuard DNS làm nhà cung cấp DNS thứ ba, để chặn quảng cáo và trình theo dõi. Trang DNS giờ liệt kê Cloudflare, Google và AdGuard kèm logo.
- Icon khay hiện mũi tên nhỏ màu xanh lá khi có bản mới.

### Thay đổi
- Logo đổi màu: cánh trắng phía sau, cánh xanh dương phía trước.
- Engine: kết nối ổn định hơn và nhẹ CPU hơn.
- Nhật ký thay đổi được tách thành bản tiếng Anh (`CHANGELOG.md`) và tiếng Việt (`CHANGELOG.vi.md`).

### Sửa lỗi
- Khi Yeager khởi động cùng Windows, icon khay sáng lên ngay khi thanh tác vụ sẵn sàng, không cần tắt rồi bật lại Yeager.

## [1.0.3] - 2026-10-29

### Thay đổi
- Chẩn đoán đo thêm CTCP, bên cạnh CUBIC và BBRv2.
- "Khôi phục mặc định Windows" tắt luôn chế độ độ trễ thấp và trả các thiết lập đó về như cũ.

### Sửa lỗi
- Nhà mạng phía trên ô trạng thái đã hiện: dò theo số AS mà Cloudflare trả về khi cần, thử lại lúc mạng chưa sẵn sàng và ghi lý do nếu không dò được.
- Viền logo đều cả bốn cạnh.

## [1.0.2] - 2026-10-29

### Bổ sung
- Cập nhật ngay trong ứng dụng, giống EasyKey: Yeager kiểm tra bản mới trên GitHub khi mở và vài giờ một lần, hiện **↑ Cập nhật lên …** ở thanh bên và khay hệ thống, khi bấm **Cập nhật** thì tải `yeager.exe` mới, đối chiếu SHA-256, tự thay file và khởi động lại. Tắt được ở Hệ thống → Cập nhật.
- Bản phát hành kèm thêm file `yeager.exe` riêng, có trong `SHA256SUMS.txt`.
- Chế độ độ trễ thấp (trang TCP): tắt delayed ACK và Nagle trên card mạng đang dùng cùng chế độ tiết kiệm điện của card; tắt công tắc là trả lại như cũ.
- Kiểm tra ping ở trang TCP (router, 1.1.1.1, 8.8.8.8) cho biết độ trễ do mạng nhà hay nhà mạng; trang chính hiện ping tới máy chủ DNS đang dùng.
- Viền icon khay sáng lên theo màu nhấn khi Yeager đang bật; menu khay hiện phạm vi engine, thuật toán TCP và DNS đang dùng, theo giao diện sáng/tối và ngôn ngữ của app.

- Thanh bên hiện nhà mạng, lấy từ Cloudflare một lần khi mở và cập nhật lại khi Chẩn đoán.

### Thay đổi
- Icon mới từ logo Cino hoàn thiện, nét ở mọi cỡ.
- Huy hiệu phiên bản và link tải trong README luôn theo bản phát hành mới nhất.

### Sửa lỗi
- Màu nhấn được giữ lại sau khi mở lại ứng dụng.

## [1.0.1] - 2026-10-28

### Thay đổi
- Cập nhật engine Levi (PR #12).
- Workflow phát hành dùng các action chạy trên Node.js 24 và có thể phát hành từ một lần chạy thủ công.

## [1.0.0] - 2026-10-28

Bản phát hành công khai đầu tiên.

### Bổ sung

**Levi: engine kết nối**
- Engine Rust gốc nằm ngay trong `yeager.exe`, không có tiến trình phụ.
- Nhúng sẵn driver WinDivert 2.2 và tự giải nén, không phải cài thêm gì.
- Phạm vi *Toàn bộ* (mọi kết nối HTTPS đi ra) hoặc *Theo tên miền* (chỉ các tên miền trong danh sách và tên miền con).
- Vòng lặp xử lý gói không chặn và hàng đợi driver lớn, chịu được nhiều kết nối song song và tải nặng.
- Không can thiệp DNS (cổng 53) hay kết nối DNS mã hóa của Yeager; không chèn gói tin giả.
- Bật và tắt dưới hai giây, không để lại tiến trình hay driver.
- Bản dòng lệnh `levi.exe` độc lập để chạy không cần giao diện.

**Erwin: tối ưu TCP**
- Chọn thuật toán điều khiển tắc nghẽn: Tự động, BBRv2, CUBIC, CTCP. Tự động chọn dựa trên ping, độ dao động và mất gói đo được.
- Chẩn đoán: đo băng thông và độ trễ khi tải cho từng thuật toán và đề xuất thuật toán tốt nhất.
- Sao lưu thiết lập trước lần thay đổi đầu tiên, khôi phục khi tắt, thoát hoặc sau khi bị tắt đột ngột; nút "Khôi phục mặc định Windows".
- Chạy độc lập với engine và DNS.

**Hange: DNS mã hóa**
- DNS over HTTPS với Cloudflare hoặc Google, qua bộ phân giải cục bộ có cache dùng HTTP/3, lùi về HTTP/2 khi cần.
- Dùng DoH tích hợp của Windows làm đường dự phòng, không bao giờ lùi về DNS không mã hóa.
- Cấu hình card mạng qua IP Helper API; tin cậy kho chứng chỉ Windows.
- Nút "Kiểm tra" và `tools/test-dns.ps1` để xác minh mã hóa và rò rỉ.

**Ứng dụng**
- Giao diện tiếng Việt và tiếng Anh, có nút chuyển ngôn ngữ.
- Chế độ sáng/tối, màu nhấn, khay hệ thống, tự kết nối khi mở, khởi động cùng Windows.
- Engine cần DNS mã hóa: bật engine sẽ bật DoH, tắt DoH sẽ dừng engine.

**Tài liệu**
- README, tài liệu thiết kế song ngữ, giấy phép, thông báo bên thứ ba, miễn trừ trách nhiệm, quyền riêng tư, bảo mật và hướng dẫn đóng góp.

### Sửa lỗi
- Nút "Khôi phục mặc định Windows" ở trang TCP.

[1.0.9]: https://github.com/iamcino/Yeager/releases/tag/v1.0.9
[1.0.8]: https://github.com/iamcino/Yeager/releases/tag/v1.0.8
[1.0.7]: https://github.com/iamcino/Yeager/releases/tag/v1.0.7
[1.0.6]: https://github.com/iamcino/Yeager/releases/tag/v1.0.6
[1.0.5]: https://github.com/iamcino/Yeager/releases/tag/v1.0.5
[1.0.4]: https://github.com/iamcino/Yeager/releases/tag/v1.0.4
[1.0.3]: https://github.com/iamcino/Yeager/releases/tag/v1.0.3
[1.0.2]: https://github.com/iamcino/Yeager/releases/tag/v1.0.2
[1.0.1]: https://github.com/iamcino/Yeager/releases/tag/v1.0.1
[1.0.0]: https://github.com/iamcino/Yeager/releases/tag/v1.0.0

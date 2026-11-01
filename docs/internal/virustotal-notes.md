# Ghi chú kỹ thuật nội bộ: Phân tích VirusTotal v1.1.2 (Internal Reference Only)

Tài liệu này lưu trữ các thông tin kỹ thuật chuyên sâu từ báo cáo VirusTotal (SHA-256: `eef2d283e4e7a4d702f67324021c5cc51ce9baa622ce9a789a01f15f36f0864a`) để đội ngũ phát triển nắm rõ và phản hồi chính xác khi cộng đồng InfoSec / Reverse Engineers đặt câu hỏi. Không cần đưa toàn bộ vào README để tránh làm loãng tài liệu người dùng.

---

## 1. Nguồn gốc chuỗi X509 Certificates (Sectigo EV & Microsoft WHQL)

### Câu hỏi dự kiến:
*"Tại sao VirusTotal báo `File is not signed`, nhưng trong mục X509 Certificates lại liệt kê chứng chỉ EV của `成都密思听科技有限公司` (Chengdu Misting Technology Co., Ltd.) cùng Microsoft WHQL?"*

### Cơ chế & Bản chất kỹ thuật:
1. **Container vs. Embedded Component:**
   - File thực thi `yeager.exe` (container bên ngoài) **chưa ký số Authenticode riêng** (`File is not signed`).
   - Tuy nhiên, `yeager.exe` nhúng trực tiếp driver mạng nhị phân `assets/engine/WinDivert64.sys` vào section `.rdata` thông qua macro `include_bytes!`.
   - Trình phân tích tĩnh (PE Parser) của VirusTotal khi duyệt đệ quy các section nhị phân đã quét qua khối nhúng này và trích xuất certificate table của `WinDivert64.sys`.
2. **Chống cáo buộc Certificate Laundering / Reuse:**
   - Chứng chỉ `成都密思听科技有限公司` + `Microsoft Windows Hardware Compatibility Publisher` là chữ ký số hợp lệ của **driver con upstream WinDivert (bản phân phối của tác giả basil00)**.
   - Yeager không mạo danh hay tái sử dụng trái phép chữ ký số này cho file `yeager.exe`. Cert hoàn toàn thuộc về component nhúng độc lập.
3. **Bằng chứng tin cậy (Trust Indicator):**
   - Sự hiện diện của chuỗi chứng chỉ EV + WHQL chứng minh rằng driver `WinDivert64.sys` được Yeager đóng gói là **bản phát hành chính thức, có chữ ký số hợp lệ được Microsoft chứng thực nạp kernel**, không phải là driver tự biên dịch hoặc driver trôi nổi không rõ nguồn gốc.

---

## 2. Trạng thái `—` (No result) của engine Zillya

### Câu hỏi dự kiến:
*"Sao Zillya hiển thị gạch ngang `—` thay vì `Undetected`? Có phải thiếu kết quả hoặc bị ẩn đi không?"*

### Bản chất kỹ thuật:
- Trên VirusTotal, ký hiệu `—` biểu thị engine đó tạm thời offline, không phản hồi trong thời gian chờ (timeout), hoặc không khả dụng tại thời điểm phân tích.
- **No-result ≠ Detection:** Engine này hoàn toàn không đưa ra phán quyết độc hại. Logic claim *"0/69 vendor còn lại không ghi nhận dấu hiệu độc hại"* là chính xác và an toàn tuyệt đối.

---

## 3. Mục `Bundled Files (17)` trong tab Relations

### Câu hỏi dự kiến:
*"VirusTotal liệt kê 17 Bundled Files trong tab Relations, có phải file này đính kèm các payload khác không?"*

### Bản chất kỹ thuật:
- Toàn bộ 17 mục được liệt kê đều là các thành phần cấu trúc PE nội tại của chính binary `yeager.exe`:
  - 4 section PE chính: `.text`, `.rdata`, `.data`, `.pdata`.
  - 13 tài nguyên nhúng chuẩn: `.rsrc/MANIFEST/1`, `.rsrc/GROUP_ICON/1`, và 9 sub-icon PNG đa kích thước (`.rsrc/ICON/1` đến `.rsrc/ICON/9`).
- Không có bất kỳ payload ngoài, dropper ngầm hay file thực thi ẩn nào kèm theo.

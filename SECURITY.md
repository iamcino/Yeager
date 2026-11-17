# Security policy · Chính sách bảo mật

**English** · [Tiếng Việt](#tiếng-việt)

## Supported versions

Only the latest release gets security fixes. Yeager tells you when a new
version is out, so please update before reporting.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report them
privately through GitHub's
[private vulnerability reporting](https://github.com/iamcino/Yeager/security/advisories/new),
or as a [confidential issue on GitLab](https://gitlab.com/cino-group/yeager/-/issues/new?issue[confidential]=true).

Include the Yeager version, your Windows version (`winver`), steps to
reproduce and the impact you saw. You should get a first reply within 7 days.
Once a fix is released, the advisory is published and you are credited unless
you prefer otherwise.

In scope: `yeager.exe`, `levi.exe`, the installer, the update process, and
anything that could leak DNS queries, leave system settings changed, let
another program abuse Yeager's administrator rights or network driver, or make
Yeager install a file that is not an official release. Vulnerabilities in
WinDivert, Slint or other dependencies should also be reported upstream.

## Verifying a download

Every release is published on both [GitHub](https://github.com/iamcino/Yeager/releases)
and [GitLab](https://gitlab.com/cino-group/yeager/-/releases), with files you can
check yourself: `SHA256SUMS.txt`, the public certificate `Yeager-codesign.cer`,
and a signature report (`*-signature.json`) for `yeager.exe` and the installer.

**Digital signature.** `yeager.exe` and `Yeager-Setup-<version>.exe` are
Authenticode-signed (ECDSA P-256, SHA-256) and timestamped (RFC 3161). The
certificate is the project's own, self-issued certificate:

| Certificate | Thumbprint (SHA-1) | Used for |
|---|---|---|
| Current: [`docs/signing/Yeager-codesign.cer`](docs/signing/Yeager-codesign.cer) | `9131F99C0B198E81FBA0F5818D0637B4A14D4CF1` | All new releases, and the GitLab release of 1.1.3 |
| Previous (retired) | `0E9C6BBE35AC13E58F951C446F2B524FA7297DCA` | GitHub releases up to and including 1.1.3 |

The previous certificate was retired in November 2026 because its private key
could no longer be used; it was not compromised. Check a file in PowerShell:

```powershell
(Get-AuthenticodeSignature .\yeager.exe).SignerCertificate.Thumbprint
```

The output must match one of the thumbprints above, for the release you
downloaded. The signature status may say it isn't trusted, because the
certificate is not on Microsoft's list; that is expected. **Do not** install
this certificate into your Trusted Root store.

**SHA-256 hashes.** Compare with `SHA256SUMS.txt` from the same release:

```powershell
Get-FileHash .\yeager.exe -Algorithm SHA256
```

Yeager's built-in updater does the same check: it only replaces `yeager.exe`
when the download matches the release's `SHA256SUMS.txt`.

**Virus scan.** GitHub releases include `virustotal-v<version>.json` with the
file's SHA-256, a link to its VirusTotal analysis and the engine counts at scan
time. The figures belong to the signed release files, never to local builds.

Because the certificate is not a commercial one, Windows SmartScreen may still
say "Unknown publisher". See
[Windows and antivirus warnings](README.md#windows-and-antivirus-warnings).

### Why some scanners flag Yeager

- **No commercial reputation yet.** A self-issued certificate proves who built
  the file and that it wasn't changed, but it doesn't carry the reputation of a
  paid OV/EV certificate, so SmartScreen and some heuristic or machine-learning
  engines may flag it.
- **System-level work.** Yeager runs as administrator, loads the WinDivert
  network driver and runs a local DNS resolver, which security products watch
  closely.
- **`obfuscated` tag.** It comes from the high entropy of the `.rsrc` section
  (about 7.9), which is normal for a Rust binary embedding nine multi-size PNG
  icons and a manifest. DetectItEasy finds no packer or protector, and the
  source has no obfuscation or packing.
- Mobile engines that report `Unable to process file type` simply don't parse
  Windows x64 executables.

### Network endpoints

These are all the connections Yeager makes on its own:

| Endpoint | Purpose |
|---|---|
| Your DNS provider (`1.1.1.1` / `1.0.0.1` Cloudflare, Google or AdGuard) | DNS over HTTPS (Hange) |
| `github.com/iamcino/Yeager/releases` and `gitlab.com/cino-group/yeager/-/releases` | Update check, and the update download when you agree |
| `speed.cloudflare.com` | ISP name at start; latency and speed test (Erwin) |
| `1.1.1.1`, `8.8.8.8` (Cloudflare, Google) | Ping tests when you run **Diagnose** or *Auto* (Erwin) |
| `www.ssl.com` and similar | Windows fetching certificate chains (TLS AIA) during validation |

No telemetry, no analytics, no command server and no data leaves your computer
beyond these. See the [privacy policy](PRIVACY.md).

---

## Tiếng Việt

### Phiên bản được hỗ trợ

Chỉ bản phát hành mới nhất được sửa lỗi bảo mật. Yeager tự báo khi có bản mới,
nên hãy cập nhật trước khi báo lỗi.

### Báo cáo lỗ hổng

Vui lòng **không** mở issue công khai cho vấn đề bảo mật. Hãy báo riêng qua
[báo cáo lỗ hổng riêng tư](https://github.com/iamcino/Yeager/security/advisories/new)
của GitHub, hoặc mở một
[issue bí mật trên GitLab](https://gitlab.com/cino-group/yeager/-/issues/new?issue[confidential]=true).

Ghi rõ phiên bản Yeager, phiên bản Windows (`winver`), các bước tái hiện và ảnh
hưởng bạn thấy. Bạn sẽ nhận phản hồi đầu tiên trong vòng 7 ngày. Khi bản sửa
được phát hành, thông báo bảo mật sẽ được công bố và ghi công bạn, trừ khi bạn
không muốn.

Những gì thuộc phạm vi: `yeager.exe`, `levi.exe`, bộ cài, quá trình cập nhật, và
mọi lỗi có thể làm rò rỉ truy vấn DNS, để lại thiết lập hệ thống đã bị đổi, cho
phép chương trình khác lạm dụng quyền Admin hay driver mạng của Yeager, hoặc
khiến Yeager cài một file không phải bản phát hành chính thức. Lỗ hổng trong
WinDivert, Slint hay thư viện phụ thuộc khác cũng nên được báo cho dự án gốc.

### Kiểm tra bản tải về

Mỗi bản phát hành được đăng ở cả [GitHub](https://github.com/iamcino/Yeager/releases)
và [GitLab](https://gitlab.com/cino-group/yeager/-/releases), kèm các file để bạn
tự kiểm chứng: `SHA256SUMS.txt`, chứng chỉ công khai `Yeager-codesign.cer`, và báo
cáo chữ ký (`*-signature.json`) cho `yeager.exe` và bộ cài.

**Chữ ký số.** `yeager.exe` và `Yeager-Setup-<phiên bản>.exe` được ký
Authenticode (ECDSA P-256, SHA-256) và đóng dấu thời gian RFC 3161. Chứng chỉ là
chứng chỉ tự cấp của dự án:

| Chứng chỉ | Thumbprint (SHA-1) | Dùng cho |
|---|---|---|
| Hiện tại: [`docs/signing/Yeager-codesign.cer`](docs/signing/Yeager-codesign.cer) | `9131F99C0B198E81FBA0F5818D0637B4A14D4CF1` | Mọi bản phát hành mới, và bản 1.1.3 trên GitLab |
| Trước đây (đã ngừng) | `0E9C6BBE35AC13E58F951C446F2B524FA7297DCA` | Các bản trên GitHub tới hết 1.1.3 |

Chứng chỉ cũ ngừng dùng từ tháng 11/2026 vì khóa riêng của nó không còn dùng
được; nó không bị lộ. Kiểm tra trong PowerShell:

```powershell
(Get-AuthenticodeSignature .\yeager.exe).SignerCertificate.Thumbprint
```

Kết quả phải trùng một trong các thumbprint ở trên, đúng với bản bạn tải. Trạng
thái chữ ký có thể báo "không tin cậy" vì chứng chỉ không nằm trong danh sách
của Microsoft; điều đó là bình thường. **Đừng** cài chứng chỉ này vào Trusted
Root của Windows.

**Mã SHA-256.** So với `SHA256SUMS.txt` của cùng bản phát hành:

```powershell
Get-FileHash .\yeager.exe -Algorithm SHA256
```

Trình cập nhật trong Yeager cũng kiểm tra đúng như vậy: chỉ thay `yeager.exe`
khi file tải về khớp `SHA256SUMS.txt` của bản phát hành.

**Quét virus.** Bản phát hành trên GitHub có file `virustotal-v<phiên bản>.json`
ghi mã SHA-256, đường dẫn tới kết quả VirusTotal và số engine tại thời điểm
quét. Các số liệu này thuộc về file đã ký của bản phát hành, không phải bản
build tại máy.

Vì chưa dùng chứng chỉ thương mại, Windows SmartScreen vẫn có thể báo
"Unknown publisher". Xem
[Cảnh báo của Windows và phần mềm diệt virus](README.vi.md#cảnh-báo-của-windows-và-phần-mềm-diệt-virus).

#### Vì sao một số trình quét báo Yeager

- **Chưa có uy tín thương mại.** Chứng chỉ tự cấp chứng minh ai build file và
  file không bị sửa, nhưng không có uy tín như chứng chỉ OV/EV trả phí, nên
  SmartScreen và vài engine dựa trên heuristic hay học máy có thể báo.
- **Làm việc ở cấp hệ thống.** Yeager chạy quyền Admin, nạp driver mạng
  WinDivert và chạy bộ phân giải DNS cục bộ, những thứ phần mềm bảo mật theo
  dõi kỹ.
- **Nhãn `obfuscated`.** Do entropy cao của phần `.rsrc` (khoảng 7,9), bình
  thường với file Rust nhúng chín biểu tượng PNG nhiều kích thước và một
  manifest. DetectItEasy không thấy packer hay protector nào, và mã nguồn không
  hề làm rối hay nén.
- Engine di động báo `Unable to process file type` chỉ đơn giản là không đọc
  file thực thi Windows x64.

#### Các địa chỉ mạng

Đây là toàn bộ kết nối Yeager tự tạo:

| Địa chỉ | Mục đích |
|---|---|
| Nhà cung cấp DNS của bạn (`1.1.1.1` / `1.0.0.1` Cloudflare, Google hoặc AdGuard) | DNS over HTTPS (Hange) |
| `github.com/iamcino/Yeager/releases` và `gitlab.com/cino-group/yeager/-/releases` | Kiểm tra cập nhật, và tải bản cập nhật khi bạn đồng ý |
| `speed.cloudflare.com` | Biết nhà mạng khi mở; đo độ trễ và tốc độ (Erwin) |
| `1.1.1.1`, `8.8.8.8` (Cloudflare, Google) | Đo ping khi bạn bấm **Chẩn đoán** hoặc dùng *Tự động* (Erwin) |
| `www.ssl.com` và tương tự | Windows tải chuỗi chứng chỉ (TLS AIA) khi xác thực |

Không telemetry, không phân tích, không máy chủ điều khiển, và không dữ liệu
nào rời máy bạn ngoài những kết nối này. Xem
[chính sách quyền riêng tư](PRIVACY.md#tiếng-việt).

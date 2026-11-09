# Build và phát hành

[English](BUILD.md) · **Tiếng Việt**

Cách build Yeager từ mã nguồn, ký số, và đăng bản phát hành trên GitHub và
GitLab. Muốn biết Yeager hoạt động bên trong ra sao, xem
[tài liệu thiết kế](DESIGN.vi.md).

## Build từ mã nguồn

Cần Windows 11, [bộ công cụ Rust](https://rustup.rs) và một trình biên dịch tài
nguyên để nhúng biểu tượng và manifest quyền Admin: `rc.exe` của Windows SDK
cho toolchain MSVC, hoặc `windres` từ
[w64devkit](https://github.com/skeeto/w64devkit) hay MSYS2 cho toolchain GNU.

```powershell
./build.ps1                      # build và chép ứng dụng ra dist\yeager.exe

cargo build --release            # target\release\yeager.exe
cargo build --release -p levi    # target\release\levi.exe, engine bản dòng lệnh
cargo test --workspace --exclude levi
```

Test của `yeager` cần cửa sổ dòng lệnh có quyền Admin, vì file test mang cùng
manifest quyền Admin như ứng dụng.

Build bộ cài bằng [Inno Setup](https://jrsoftware.org/isinfo.php) 6 trở lên:

```powershell
iscc installer\setup.iss         # dist\Yeager-Setup-<phiên bản>.exe
```

Từ Linux có thể kiểm tra kiểu cho bản Windows bằng
`cargo check --target x86_64-pc-windows-gnu` (cần `mingw-w64`).

Logo là file vector `assets/logo/yeager.svg`. `tools/make_icons.py` vẽ nó ra
ảnh gốc 1024 px và mọi kích thước biểu tượng (cần Pillow, numpy và
`rsvg-convert`).

## Ký số

Bản phát hành được ký bằng chứng chỉ tự cấp của dự án (ECDSA P-256, SHA-256,
dấu thời gian RFC 3161). Chứng chỉ công khai là
[`docs/signing/Yeager-codesign.cer`](signing/Yeager-codesign.cer); thumbprint
của nó được ghim cho mọi chữ ký, nên các script ký từ chối file ký bằng khóa
khác. Thumbprint hiện tại: `9131F99C0B198E81FBA0F5818D0637B4A14D4CF1`.

Các script nằm trong `tools/signing`:

| Script | Việc nó làm |
|---|---|
| `new-cert.ps1` | Tạo chứng chỉ mới: khóa vào `CurrentUser\My` (không xuất ra được), một bản PFX vào `.signing\` (bị git bỏ qua) với mật khẩu ngẫu nhiên lưu ở `%LOCALAPPDATA%\Yeager-signing` (DPAPI), và file `.cer` công khai vào `docs\signing\`. |
| `sign.ps1` | Ký và đóng dấu thời gian một file, bằng khóa trong kho chứng chỉ hoặc `-PfxPath`. |
| `verify.ps1` | Kiểm tra chữ ký với thumbprint đã ghim, có thể ghi báo cáo JSON. |
| `ci-secrets.ps1` | Lần lượt đưa các giá trị cho CI (`CODESIGN_PFX_BASE64`, `CODESIGN_PFX_PASSWORD`, `CODESIGN_EXPECTED_THUMBPRINT`) vào clipboard để dán, rồi xóa clipboard. |
| `trust-dev.ps1` | Cho máy phát triển tin chứng chỉ này. Chỉ dùng trên máy phát triển. |

> [!IMPORTANT]
> Hãy sao lưu file PFX và mật khẩu của nó ở nơi an toàn, ví dụ trình quản lý
> mật khẩu. Bản DPAPI chỉ đọc được bởi đúng user Windows đó trên đúng máy đó,
> và mất mật khẩu nghĩa là phải chuyển sang chứng chỉ mới, như đã xảy ra vào
> tháng 11/2026.

**Đổi chứng chỉ:** chạy `new-cert.ps1 -Force`, commit file `.cer` mới, cập nhật
thumbprint trong `SECURITY.md`, các README và changelog, rồi cập nhật secret
của CI và biến GitHub `CODESIGN_EXPECTED_THUMBPRINT`. Giữ thumbprint cũ trong
`SECURITY.md` để người dùng vẫn kiểm tra được các bản tải cũ.

## Các bước phát hành

1. Đặt phiên bản trong `Cargo.toml` (`[workspace.package] version`).
2. Viết mục mới ở cả `CHANGELOG.md` và `CHANGELOG.vi.md` dưới tiêu đề
   `## [x.y.z] - YYYY-MM-DD`. Ghi chú phát hành được lấy từ đây.
3. Merge vào `master`.
4. Đăng trên GitHub, rồi GitLab, như dưới đây. Cả hai dùng tag `vx.y.z`.

Mỗi bản phát hành có cùng bộ file: `Yeager-Setup-<phiên bản>.exe`,
`Yeager-<phiên bản>-portable-x64.zip`, file `yeager.exe` riêng mà trình cập nhật
trong ứng dụng tải về, `SHA256SUMS.txt`, các báo cáo `*-signature.json`,
`Yeager-codesign.cer`, `LICENSE` và `THIRD-PARTY-NOTICES.md`.

## Đăng trên GitHub

`.github/workflows/release.yml` chạy trên runner `windows-2022`. Đẩy một tag
`v*` lên là nó build, test, ký và đăng bản phát hành; chạy workflow bằng tay
thì ra cùng bộ file dưới dạng artifact, và tick **publish** thì tạo luôn tag.
Workflow cần secret `CODESIGN_PFX_BASE64`, `CODESIGN_PFX_PASSWORD` và biến
`CODESIGN_EXPECTED_THUMBPRINT` của repo. Báo cáo VirusTotal
(`virustotal-v<phiên bản>.json`) được đính kèm sau.

## Đăng trên GitLab

Bản phát hành trên [gitlab.com/cino-group/yeager](https://gitlab.com/cino-group/yeager/-/releases)
được tạo bằng `tools/release-gitlab.ps1`. Script build từ một worktree tạm,
sạch, của ref bạn chỉ định, nên thư mục làm việc của bạn không bị đụng tới, và
luôn ký bằng script ký và chứng chỉ của bản checkout hiện tại. Nó tải file lên
generic package registry của GitLab và tạo bản phát hành với ghi chú lấy từ cả
hai changelog, tiếng Anh trước. `levi.exe` không bao giờ được phát hành kèm.

Đường dẫn cố định tới bộ cài mới nhất là
`https://gitlab.com/cino-group/yeager/-/releases/permalink/latest/downloads/Yeager-Setup.exe`
(và `Yeager-portable-x64.zip` cho bản portable).

**Chạy trên máy của bạn** (đã cài Rust, Inno Setup, Windows SDK và có khóa ký):

```powershell
.\tools\release-gitlab.ps1 -Ref master -DryRun   # chỉ build và ký; file giữ ở target\release-gitlab\out-<phiên bản>
.\tools\release-gitlab.ps1 -Ref v1.2.0           # build, ký và đăng
.\tools\release-gitlab.ps1 -FromGitHub           # đăng đúng các file của bản phát hành GitHub
.\tools\release-gitlab.ps1 -Ref v1.2.0 -AssetsDir D:\yeager-1.2.0   # đăng các file bạn đã có
```

| Tùy chọn | Ý nghĩa |
|---|---|
| `-Ref` | Nhánh, tag hoặc commit cần build. Phiên bản lấy từ `Cargo.toml` của nó; tag là `v<phiên bản>`. |
| `-DryRun` | Build và ký, không tải lên gì. |
| `-SkipTests` | Bỏ qua `cargo test`. Cần khi cửa sổ dòng lệnh không có quyền Admin. |
| `-FromGitHub` / `-AssetsDir` | Không build; kiểm tra rồi đăng lại file phát hành có sẵn (chữ ký và `SHA256SUMS.txt` phải khớp). |
| `-PfxPath` | Ký bằng file PFX này khi khóa không có trong `CurrentUser\My`. |
| `-Prerelease` | Cho phép phiên bản kiểu `1.2.0-rc1`. GitLab không có cờ pre-release, nên nó sẽ thành bản mới nhất. |

Token GitLab (project access token với scope `api`) được đọc từ biến
`GITLAB_TOKEN`, từ `%LOCALAPPDATA%\Yeager-signing\gitlab-token.clixml`, hoặc
được hỏi khi script chạy. Lưu một lần bằng:

```powershell
Read-Host -AsSecureString | Export-Clixml "$env:LOCALAPPDATA\Yeager-signing\gitlab-token.clixml"
```

Script không ghi đè bản phát hành GitLab đã có; hãy xóa nó trước hoặc tăng
phiên bản.

**Chạy trên GitLab CI:** `.gitlab-ci.yml` chạy test và build bản release ở mỗi
lần push và merge request, và job release khi có tag `v*` hoặc khi bấm tay trên
`master`. Nó cần một runner Windows tự host gắn tag `yeager-windows` với đủ các
công cụ trên, và hai biến CI/CD được bảo vệ `CODESIGN_PFX_BASE64`,
`CODESIGN_PFX_PASSWORD`.

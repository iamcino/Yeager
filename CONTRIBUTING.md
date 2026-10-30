# Contributing · Đóng góp

**English** · [Tiếng Việt](#tiếng-việt)

Thanks for your interest in Yeager! Bug reports, translations and pull requests
are all welcome.

## Reporting bugs

Open an [issue](https://github.com/iamcino/Yeager/issues) with:

- Yeager version and Windows version (`winver`)
- which features were on (engine, scope, DoH provider, HTTP/3, TCP algorithm)
- what you expected and what happened, plus the status line or log from the app
- for DNS problems, the result from the in-app Check button

Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Development

1. Install the Rust toolchain and a resource compiler (see
   [Building from source](README.md#building-from-source)).
2. `cargo build` and run `target\debug\yeager.exe` as administrator.
3. Before opening a pull request:
   - `cargo fmt --all`
   - `cargo clippy --workspace --all-targets`
   - `cargo test --workspace` (on Windows; on Linux use
     `cargo check --target x86_64-pc-windows-gnu`)
4. Keep changes focused, and describe what you tested on which Windows build.

Guidelines:

- Every system change must be undoable: save the previous state, restore it on
  disable, exit and the next launch after a crash.
- Use Windows APIs rather than hidden PowerShell or raw registry writes, which
  antivirus products treat as suspicious.
- The interface is bilingual: give every new piece of UI text both a
  Vietnamese and an English version.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(erwin): …`, `fix(ui): …`).
- Add an entry under *Unreleased* in both [CHANGELOG.md](CHANGELOG.md)
  (English) and [CHANGELOG.vi.md](CHANGELOG.vi.md) (Vietnamese) for
  user-visible changes.

The `crates/levi` engine is maintained by the project owner; please open an
issue to discuss engine changes before sending a pull request.

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE).

---

## Tiếng Việt

Cảm ơn bạn đã quan tâm tới Yeager! Mọi báo lỗi, bản dịch và pull request đều
được hoan nghênh.

### Báo lỗi

Mở [issue](https://github.com/iamcino/Yeager/issues) kèm:

- phiên bản Yeager và Windows (`winver`)
- các tính năng đang bật (engine, phạm vi, nhà cung cấp DoH, HTTP/3, thuật toán TCP)
- điều bạn mong đợi và điều đã xảy ra, kèm dòng trạng thái hoặc log trong app
- với lỗi DNS, kết quả từ nút Kiểm tra trong ứng dụng

Vấn đề bảo mật vui lòng báo theo [SECURITY.md](SECURITY.md), không mở issue công khai.

### Phát triển

1. Cài bộ công cụ Rust và trình biên dịch resource (xem
   [Build từ mã nguồn](README.vi.md#build-từ-mã-nguồn)).
2. `cargo build` rồi chạy `target\debug\yeager.exe` với quyền quản trị.
3. Trước khi mở pull request:
   - `cargo fmt --all`
   - `cargo clippy --workspace --all-targets`
   - `cargo test --workspace` (trên Windows; trên Linux dùng
     `cargo check --target x86_64-pc-windows-gnu`)
4. Giữ thay đổi gọn, ghi rõ bạn đã thử trên bản Windows nào.

Nguyên tắc:

- Mọi thay đổi hệ thống phải hoàn tác được: lưu trạng thái cũ, khôi phục khi
  tắt, khi thoát và ở lần mở sau khi bị tắt đột ngột.
- Dùng Windows API thay vì PowerShell ẩn hay ghi registry trực tiếp, vì phần
  mềm diệt virus coi đó là hành vi đáng ngờ.
- Giao diện song ngữ: mọi chữ mới trên giao diện cần có cả bản tiếng Việt và
  tiếng Anh.
- Commit theo [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(erwin): …`, `fix(ui): …`).
- Ghi thay đổi người dùng thấy được vào mục *Unreleased* trong cả
  [CHANGELOG.md](CHANGELOG.md) (tiếng Anh) và [CHANGELOG.vi.md](CHANGELOG.vi.md)
  (tiếng Việt).

Engine `crates/levi` do chủ dự án duy trì; vui lòng mở issue thảo luận trước khi
gửi pull request thay đổi engine.

Khi đóng góp, bạn đồng ý rằng phần đóng góp được cấp phép theo
[Giấy phép MIT](LICENSE).

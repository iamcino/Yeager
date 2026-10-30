# Third-party notices · Thông báo phần mềm bên thứ ba

**English** · [Tiếng Việt](#tiếng-việt)

Yeager's own source code is licensed under the [MIT License](LICENSE). The
Yeager binaries also contain or are built with the third-party components below,
which remain under their own licenses. Full license texts are in the
[`licenses/`](licenses) folder.

## Components shipped inside `yeager.exe`

### WinDivert 2.2

- **Files:** `assets/engine/WinDivert.dll`, `assets/engine/WinDivert64.sys`
  (embedded in `yeager.exe` and `levi.exe` and unpacked at runtime)
- **Copyright:** © basil00 and WinDivert contributors
- **License:** GNU Lesser General Public License v3 (Yeager uses WinDivert under
  the LGPL v3 option of its LGPL v3 / GPL v2 dual license).
  See [`licenses/LGPL-3.0.txt`](licenses/LGPL-3.0.txt) and
  [`licenses/GPL-3.0.txt`](licenses/GPL-3.0.txt).
- **Source:** <https://github.com/basil00/WinDivert>
- WinDivert is used unmodified, as a separate DLL and driver. You may replace
  the embedded copies with your own build of WinDivert by placing your files in
  `assets/engine/` and rebuilding Yeager from source.

### Slint 1.18

- **Use:** user interface toolkit
- **Copyright:** © SixtyFPS GmbH
- **License:** Slint Royalty-free Desktop, Mobile, and Web Applications License
  2.0 (Slint is triple-licensed as GPL-3.0-only, Royalty-free 2.0 or the Slint
  Software License; Yeager uses the Royalty-free 2.0 option). See
  [`licenses/Slint-Royalty-free-2.0.md`](licenses/Slint-Royalty-free-2.0.md).
  The attribution this license requires is the "Made with Slint" badge shown in
  [README.md](README.md) and on the release page.
- **Source:** <https://github.com/slint-ui/slint>

### Be Vietnam Pro

- **Files:** `assets/fonts/BeVietnamPro-Regular.ttf`,
  `assets/fonts/BeVietnamPro-SemiBold.ttf` (subset, embedded)
- **Copyright:** © 2021 The Be Vietnam Pro Project Authors
  (<https://github.com/bettergui/BeVietnamPro>)
- **License:** SIL Open Font License 1.1. See
  [`licenses/OFL-1.1.txt`](licenses/OFL-1.1.txt).

### Rust crates

Yeager links a number of open-source Rust crates from
[crates.io](https://crates.io). At version 1.0.0 their licenses are:

| License | Notable crates |
|---------|----------------|
| MIT OR Apache-2.0 (most crates) | `serde`, `serde_json`, `futures-util`, `hickory-proto`, `hickory-net`, `tray-icon`, `muda`, `windows-sys`, `raw-window-handle`, `rustls-platform-verifier` |
| MIT | `tokio`, `lru` and others |
| Apache-2.0 OR ISC OR MIT | `rustls` |
| Apache-2.0 AND ISC | `ring` |
| ISC | `rustls-webpki`, `untrusted`, `libloading` |
| Apache-2.0 | `winit`, `glutin`, `accesskit_winit`, `unicode-linebreak` |
| BSD-3-Clause | `tiny-skia`, `subtle` |
| Zlib | `foldhash`, `slotmap`, `zlib-rs` |
| BSL-1.0 | `clipboard-win`, `error-code` |
| Unicode-3.0 | `icu_*`, `zerovec`, `tinystr` and related Unicode data crates |
| Unlicense OR MIT | `memchr`, `aho-corasick` |

The license of every crate is recorded in its own package metadata. To produce
a complete, per-crate list with full texts, run
[`cargo about`](https://github.com/EmbarkStudios/cargo-about) or
`cargo license` in the repository root. The Apache License 2.0 text is in
[`licenses/Apache-2.0.txt`](licenses/Apache-2.0.txt); the MIT, BSD, ISC, Zlib
and BSL notices require keeping each crate's copyright line, which these tools
collect.

## Names and artwork

"Yeager", "Levi", "Erwin" and "Hange", and the Wings of Freedom crest used for
the icon, are fan references to *Attack on Titan* (*Shingeki no Kyojin*) by
Hajime Isayama, published by Kodansha. Yeager is an independent project and is
not affiliated with or endorsed by the creator, the publisher or any licensee.
All trademarks belong to their respective owners.

---

## Tiếng Việt

Mã nguồn của Yeager theo [Giấy phép MIT](LICENSE). Các file chạy của Yeager còn
chứa hoặc được build cùng những thành phần bên thứ ba dưới đây, và các thành
phần này giữ nguyên giấy phép riêng. Toàn văn giấy phép nằm trong thư mục
[`licenses/`](licenses).

### Thành phần nằm trong `yeager.exe`

**WinDivert 2.2**
- File: `assets/engine/WinDivert.dll`, `assets/engine/WinDivert64.sys` (nhúng
  trong `yeager.exe` và `levi.exe`, giải nén khi chạy).
- Bản quyền: © basil00 và các tác giả WinDivert.
- Giấy phép: GNU LGPL v3 (WinDivert có giấy phép kép LGPL v3 / GPL v2, Yeager
  dùng theo LGPL v3). Xem [`licenses/LGPL-3.0.txt`](licenses/LGPL-3.0.txt) và
  [`licenses/GPL-3.0.txt`](licenses/GPL-3.0.txt).
- Mã nguồn: <https://github.com/basil00/WinDivert>
- WinDivert được dùng nguyên bản, dưới dạng DLL và driver riêng. Bạn có thể thay
  bằng bản WinDivert tự build bằng cách đặt file vào `assets/engine/` và build
  lại Yeager từ mã nguồn.

**Slint 1.18**
- Dùng cho: giao diện người dùng.
- Bản quyền: © SixtyFPS GmbH.
- Giấy phép: Slint Royalty-free License 2.0 (Slint có ba lựa chọn giấy phép:
  GPL-3.0-only, Royalty-free 2.0 hoặc Slint Software License; Yeager dùng
  Royalty-free 2.0). Xem
  [`licenses/Slint-Royalty-free-2.0.md`](licenses/Slint-Royalty-free-2.0.md).
  Giấy phép này yêu cầu ghi công, được đáp ứng bằng huy hiệu "Made with Slint"
  trong [README](README.vi.md) và trên trang phát hành.
- Mã nguồn: <https://github.com/slint-ui/slint>

**Be Vietnam Pro**
- File: `assets/fonts/BeVietnamPro-Regular.ttf`,
  `assets/fonts/BeVietnamPro-SemiBold.ttf` (đã lược bớt ký tự, nhúng trong app).
- Bản quyền: © 2021 The Be Vietnam Pro Project Authors.
- Giấy phép: SIL Open Font License 1.1. Xem
  [`licenses/OFL-1.1.txt`](licenses/OFL-1.1.txt).

**Các thư viện Rust**

Yeager dùng nhiều thư viện Rust mã nguồn mở từ crates.io, phần lớn theo
MIT hoặc Apache-2.0; một số theo ISC, BSD-3-Clause, Zlib, BSL-1.0, Unicode-3.0
(xem bảng ở phần tiếng Anh). Để có danh sách đầy đủ kèm toàn văn giấy phép của
từng thư viện, chạy `cargo about` hoặc `cargo license` ở thư mục gốc.

### Tên gọi và hình ảnh

Các tên "Yeager", "Levi", "Erwin", "Hange" và biểu tượng Đôi cánh Tự do dùng
làm icon là sự tri ân dành cho *Attack on Titan* (*Shingeki no Kyojin*) của tác
giả Hajime Isayama, do Kodansha phát hành. Yeager là dự án độc lập, không liên
kết và không được tác giả, nhà phát hành hay bên được cấp phép nào bảo trợ. Mọi
nhãn hiệu thuộc về chủ sở hữu tương ứng.

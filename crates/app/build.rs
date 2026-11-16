//! Compiles the Slint UI and, on Windows targets, embeds the application icon,
//! an admin manifest and version info. `embed-resource` picks the resource
//! compiler for the toolchain: `windres` for `*-gnu`, `rc.exe`/`llvm-rc` for
//! `*-msvc`.

use std::path::Path;

/// U09-REV4 item 1: SHA-1 of the DER bytes (the .NET
/// `X509Certificate2.Thumbprint` definition: SHA-1 of the raw cert, uppercase
/// hex). Pure Rust so the build derives the pinned thumbprint from
/// `docs/signing/Yeager-codesign.cer` with no hand-typed constant and no extra
/// dependency.
fn sha1_hex(data: &[u8]) -> String {
    let mut h: [u32; 5] = [
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = ((chunk[4 * i] as u32) << 24)
                | ((chunk[4 * i + 1] as u32) << 16)
                | ((chunk[4 * i + 2] as u32) << 8)
                | (chunk[4 * i + 3] as u32);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &scheduled) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(scheduled);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut s = String::with_capacity(40);
    for v in h {
        s.push_str(&format!("{v:08X}"));
    }
    s
}

/// U09-REV4 item 1: derive the pinned thumbprint from the cert file at build
/// time (same source `tools/signing/common.ps1` `Get-PinnedThumbprint`
/// loads) and emit it as a generated include. The app never hand-types the
/// value; the mechanical test opens the same `.cer` and asserts equality.
fn emit_pinned_thumbprint(out_dir: &str, manifest_dir: &str) {
    let cert = format!("{manifest_dir}/../../docs/signing/Yeager-codesign.cer");
    println!("cargo:rerun-if-changed={cert}");
    let bytes =
        std::fs::read(&cert).unwrap_or_else(|e| panic!("cannot read pinned cert {cert}: {e}"));
    let thumb = sha1_hex(&bytes);
    assert!(
        thumb.len() == 40 && thumb.bytes().all(|b| b.is_ascii_hexdigit()),
        "derived pinned thumbprint is not 40 hex digits"
    );
    let generated = format!(
        "// @generated from docs/signing/Yeager-codesign.cer by crates/app/build.rs — do not edit by hand.\n\
         /// Pinned code-signing cert thumbprint, derived at build time from the cert file.\n\
         pub const PINNED_THUMBPRINT: &str = \"{thumb}\";\n"
    );
    std::fs::write(format!("{out_dir}/pinned_thumbprint.rs"), generated).unwrap();
}

fn main() {
    slint_build::compile("ui/app.slint").expect("Slint UI failed to compile");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // U09-REV4 item 1: always derived (all targets) so `include!` resolves
    // everywhere; only used on Windows.
    emit_pinned_thumbprint(&out_dir, &manifest_dir);

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let icon = format!("{manifest_dir}/../../assets/icons/yeager.ico").replace('\\', "/");
    let rc_path = format!("{out_dir}/yeager.rc");
    // Version info follows the workspace version in Cargo.toml.
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let version_commas = format!("{},0", version.replace('.', ","));

    // The icon lives outside this crate, so Cargo would not rebuild the exe
    // when only the .ico changes (leaving the old icon embedded).
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=ui");
    println!("cargo:rerun-if-changed={icon}");

    let rc = format!(
        r#"#pragma code_page(65001)
1 ICON "{icon}"
1 24
{{
"<assembly xmlns=""urn:schemas-microsoft-com:asm.v1"" manifestVersion=""1.0"">"
"<trustInfo xmlns=""urn:schemas-microsoft-com:asm.v3"">"
"<security><requestedPrivileges>"
"<requestedExecutionLevel level=""requireAdministrator"" uiAccess=""false""/>"
"</requestedPrivileges></security></trustInfo>"
"</assembly>"
}}
1 VERSIONINFO
FILEVERSION {version_commas}
PRODUCTVERSION {version_commas}
{{
BLOCK "StringFileInfo"
{{
BLOCK "000004b0"
{{
VALUE "FileDescription", "Yeager - Modern Windows Network Optimization & Transport Resilience Platform\0"
VALUE "ProductName", "Yeager\0"
VALUE "OriginalFilename", "yeager.exe\0"
VALUE "ProductVersion", "{version}\0"
VALUE "FileVersion", "{version}\0"
}}
}}
BLOCK "VarFileInfo" {{ VALUE "Translation", 0x0, 0x04b0 }}
}}
"#
    );
    std::fs::write(&rc_path, rc).unwrap();

    // Fall back to the w64devkit windres used for local builds when no
    // resource compiler is configured.
    let devkit = "C:\\soft\\w64devkit\\bin\\windres.exe";
    if std::env::var_os("RC").is_none() && Path::new(devkit).exists() && which_windres().is_none() {
        unsafe { std::env::set_var("RC", devkit); }
    }

    match embed_resource::compile(&rc_path, embed_resource::NONE) {
        embed_resource::CompilationResult::Ok | embed_resource::CompilationResult::NotWindows => {}
        other => {
            // Without a resource compiler the binary still builds, just without
            // the icon and admin manifest. Warn so the local build can install one.
            println!("cargo:warning=Không nhúng được icon/manifest ({other}); exe sẽ thiếu icon và quyền admin.");
        }
    }
}

/// Whether a `windres` is reachable on PATH.
fn which_windres() -> Option<()> {
    std::process::Command::new("windres").arg("--version").output().ok().map(|_| ())
}

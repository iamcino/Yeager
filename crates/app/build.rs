//! Compiles the Slint UI and, on Windows targets, embeds the application icon,
//! an admin manifest and version info. `embed-resource` picks the resource
//! compiler for the toolchain: `windres` for `*-gnu`, `rc.exe`/`llvm-rc` for
//! `*-msvc`.

use std::path::Path;

fn main() {
    slint_build::compile("ui/app.slint").expect("Slint UI failed to compile");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
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

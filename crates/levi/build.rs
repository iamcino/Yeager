//! On Windows targets, embeds the application icon, an asInvoker manifest and version info
//! into `levi.exe`. `embed-resource` picks the resource compiler for the toolchain:
//! `windres` for `*-gnu`, `rc.exe`/`llvm-rc` for `*-msvc`.

use std::path::Path;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let icon = format!("{manifest_dir}/../../assets/icons/yeager.ico").replace('\\', "/");
    let rc_path = format!("{out_dir}/levi.rc");
    // Version info follows the workspace version in Cargo.toml.
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let version_commas = format!("{},0", version.replace('.', ","));
    let version_4part = format!("{},0", version.replace('.', ",")).replace(',', ".");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={icon}");

    let rc = format!(
        r#"#pragma code_page(65001)
1 ICON "{icon}"
1 24
{{
"<assembly xmlns=""urn:schemas-microsoft-com:asm.v1"" manifestVersion=""1.0"">"
"<trustInfo xmlns=""urn:schemas-microsoft-com:asm.v3"">"
"<security><requestedPrivileges>"
"<requestedExecutionLevel level=""asInvoker"" uiAccess=""false""/>"
"</requestedPrivileges></security></trustInfo>"
"<compatibility xmlns=""urn:schemas-microsoft-com:compatibility.v1"">"
"<application>"
"<supportedOS Id=""{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}""/>"
"<supportedOS Id=""{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}""/>"
"<supportedOS Id=""{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}""/>"
"<supportedOS Id=""{{35138b9a-5d96-4fbd-8e2d-a2440225f93a}}""/>"
"</application>"
"</compatibility>"
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
VALUE "FileDescription", "Levi - High-Performance Native Transport Resilience Engine\0"
VALUE "ProductName", "Yeager\0"
VALUE "OriginalFilename", "levi.exe\0"
VALUE "ProductVersion", "{version_4part}\0"
VALUE "FileVersion", "{version_4part}\0"
VALUE "CompanyName", "Cino\0"
VALUE "LegalCopyright", "Copyright (c) 2026 Cino. Licensed under MIT.\0"
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
            println!("cargo:warning=Không nhúng được icon/manifest ({other}); exe sẽ thiếu icon và version info.");
        }
    }
}

/// Whether a `windres` is reachable on PATH.
fn which_windres() -> Option<()> {
    std::process::Command::new("windres").arg("--version").output().ok().map(|_| ())
}

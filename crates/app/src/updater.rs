//! Updates `yeager.exe` in place from GitHub Releases, the way EasyKey does.
//!
//! The latest version is the tag `releases/latest` redirects to. The new exe is
//! downloaded over HTTPS (WinHTTP, so the Windows proxy and certificate store
//! apply) and checked against the SHA-256 in the release's `SHA256SUMS.txt`.
//! The running exe is renamed to `yeager.old.exe`, the new one takes its name
//! and starts once this one has put Windows back, and the old file is deleted
//! on the next start. Nothing is installed without asking.

use common::lang::tr;
use common::{t, Error, Result};
use std::path::{Path, PathBuf};

pub const RELEASES_PAGE: &str = "https://github.com/iamcino/Yeager/releases/latest";
const RELEASE_TAG: &str = "https://github.com/iamcino/Yeager/releases/tag/";
const RELEASE_DOWNLOAD: &str = "https://github.com/iamcino/Yeager/releases/download/";
const EXE_NAME: &str = "yeager.exe";
const OLD_EXE: &str = "yeager.old.exe";
const NEW_EXE: &str = "yeager.new.exe";
const MAX_DOWNLOAD: usize = 64 * 1024 * 1024;

/// Passed to the new exe after an update; `--connect` is added when the engine
/// was on, so it comes back on.
pub const UPDATED_ARG: &str = "--updated";
pub const CONNECT_ARG: &str = "--connect";

/// `"1.2.3"` or `"v1.2.3"` as numbers that compare in order. Anything else,
/// such as a pre-release `1.2.3-beta`, is `None`.
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut parts = s.split('.');
    let mut next = || parts.next().filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))?.parse().ok();
    let v = (next()?, next()?, next()?);
    parts.next().is_none().then_some(v)
}

/// The version of this exe.
pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Whether `latest` is newer than this exe.
pub fn is_newer(latest: &str) -> bool {
    match (parse_version(latest), parse_version(current())) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

/// The version in a `…/releases/tag/v1.2.3` URL.
fn version_from_tag_url(url: &str) -> Option<String> {
    let tag = url.trim().rsplit_once("/tag/")?.1;
    let tag = tag.split(['?', '#']).next()?;
    parse_version(tag).map(|(a, b, c)| format!("{a}.{b}.{c}"))
}

/// The checksum of `name` in a `sha256sum`-style list: `<64 hex>  <name>` per line.
fn checksum_for(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, file) = line.trim().split_once(char::is_whitespace)?;
        let file = file.trim().trim_start_matches('*');
        (file.eq_ignore_ascii_case(name) && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The release notes of `version` on GitHub.
pub fn notes_url(version: &str) -> String {
    format!("{RELEASE_TAG}v{version}")
}

/// Asks GitHub for the latest release. Blocking; run it off the UI thread.
pub fn latest() -> Result<String> {
    let location = http::redirect_target(RELEASES_PAGE)?;
    version_from_tag_url(&location)
        .ok_or_else(|| Error::new(tr("GitHub trả về phiên bản không hợp lệ.", "GitHub returned an invalid version.")))
}

/// Why an update did not go through, each with its own advice.
#[derive(Debug)]
pub enum Failure {
    Download(Error),
    Mismatch,
    Install(Error),
}

impl Failure {
    pub fn message(&self) -> String {
        match self {
            Failure::Download(e) => t!(
                "Không tải được bản mới ({e}). Mở trang tải về để tải thủ công?",
                "Could not download the update ({e}). Open the download page to get it yourself?"
            ),
            Failure::Mismatch => tr(
                "File tải về không khớp mã kiểm tra nên chưa được cài. Mở trang tải về?",
                "The download did not match its checksum, so it was not installed. Open the download page?",
            )
            .into(),
            Failure::Install(e) => t!(
                "Không ghi được vào thư mục của Yeager ({e}). Mở trang tải về để tải thủ công?",
                "Could not write to the Yeager folder ({e}). Open the download page to get it yourself?"
            ),
        }
    }
}

/// Downloads `version`, checks it and puts it in place of the running exe.
/// Returns the path to start. Blocking; run it off the UI thread.
pub fn download_and_install(version: &str) -> std::result::Result<PathBuf, Failure> {
    let base = format!("{RELEASE_DOWNLOAD}v{version}/");
    let sums = http::get(&format!("{base}SHA256SUMS.txt"), 64 * 1024).map_err(Failure::Download)?;
    let expected = checksum_for(&String::from_utf8_lossy(&sums), EXE_NAME).ok_or(Failure::Mismatch)?;
    let exe = http::get(&format!("{base}{EXE_NAME}"), MAX_DOWNLOAD).map_err(Failure::Download)?;
    if !exe.starts_with(b"MZ") || sha256_hex(&exe) != expected {
        return Err(Failure::Mismatch);
    }
    let path = std::env::current_exe().map_err(|e| Failure::Install(e.into()))?;
    install(&exe, &path).map_err(|e| Failure::Install(e.into()))?;
    Ok(path)
}

/// Windows lets a running exe be renamed but not overwritten, so the old one
/// steps aside first, and comes back if the new one cannot take its place.
fn install(exe: &[u8], path: &Path) -> std::io::Result<()> {
    let folder = path.parent().unwrap_or(Path::new("."));
    let (new, old) = (folder.join(NEW_EXE), folder.join(OLD_EXE));
    if let Err(e) = std::fs::write(&new, exe) {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(path, &old) {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&new, path) {
        let _ = std::fs::rename(&old, path);
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    Ok(())
}

/// Starts the updated exe. Called last, once this one has put back TCP and
/// DNS, so the two never fight over them.
pub fn restart(path: &Path, connect: bool) {
    let mut cmd = std::process::Command::new(path);
    cmd.arg(UPDATED_ARG);
    if connect {
        cmd.arg(CONNECT_ARG);
    }
    if let Some(dir) = path.parent() {
        cmd.current_dir(dir);
    }
    let _ = cmd.spawn();
}

/// On start: remove the exe an update left behind. After an update the old
/// process may still be exiting, so keep trying for a few seconds, and show
/// the new version under Apps in Windows Settings.
pub fn finish_previous_update(updated: bool) {
    let Ok(exe) = std::env::current_exe() else { return };
    let old = exe.with_file_name(OLD_EXE);
    std::thread::spawn(move || {
        let tries = if updated { 50 } else { 1 };
        for _ in 0..tries {
            if !old.exists() || std::fs::remove_file(&old).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        if updated {
            #[cfg(windows)]
            http::note_installed_version(&exe, current());
        }
    });
}

/// Opens `url` in the default browser.
pub fn open_url(url: &str) {
    #[cfg(windows)]
    http::open_url(url);
    #[cfg(not(windows))]
    let _ = url;
}

#[cfg(windows)]
mod http {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Networking::WinHttp::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn os_error() -> Error {
        Error::new(std::io::Error::last_os_error().to_string())
    }

    /// Closes a WinHTTP handle when it goes out of scope.
    struct Handle(*mut c_void);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle came from WinHTTP and is closed once.
                unsafe { WinHttpCloseHandle(self.0) };
            }
        }
    }

    fn handle(h: *mut c_void) -> Result<Handle> {
        if h.is_null() {
            Err(os_error())
        } else {
            Ok(Handle(h))
        }
    }

    struct Response {
        status: u32,
        request: Handle,
        _connection: Handle,
        _session: Handle,
    }

    /// Sends a GET to an `https://` URL and waits for the headers.
    fn send(url: &str, follow_redirects: bool) -> Result<Response> {
        let rest = url.strip_prefix("https://").ok_or_else(|| Error::new("HTTPS only"))?;
        let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let path = if path.is_empty() { "/" } else { path };
        let (host, path) = (wide(host), wide(path));
        let agent = wide(&format!("Yeager/{}", current()));
        let verb = wide("GET");
        // SAFETY: every pointer passed is a NUL-terminated buffer that lives
        // for the call, and every handle is checked before it is used.
        unsafe {
            let session = handle(WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, null(), null(), 0))?;
            WinHttpSetTimeouts(session.0, 10_000, 10_000, 15_000, 30_000);
            let connection = handle(WinHttpConnect(session.0, host.as_ptr(), 443, 0))?;
            let request = handle(WinHttpOpenRequest(
                connection.0,
                verb.as_ptr(),
                path.as_ptr(),
                null(),
                null(),
                null(),
                WINHTTP_FLAG_SECURE,
            ))?;
            if !follow_redirects {
                let off: u32 = WINHTTP_DISABLE_REDIRECTS;
                WinHttpSetOption(request.0, WINHTTP_OPTION_DISABLE_FEATURE, &off as *const u32 as *const c_void, 4);
            }
            if WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0) == 0
                || WinHttpReceiveResponse(request.0, null_mut()) == 0
            {
                return Err(os_error());
            }
            let mut status: u32 = 0;
            let mut size = 4u32;
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                null(),
                &mut status as *mut u32 as *mut c_void,
                &mut size,
                null_mut(),
            );
            Ok(Response { status, request, _connection: connection, _session: session })
        }
    }

    /// Where `url` redirects to, without following it.
    pub fn redirect_target(url: &str) -> Result<String> {
        let res = send(url, false)?;
        if !(300..400).contains(&res.status) {
            return Err(Error::new(format!("HTTP {}", res.status)));
        }
        let mut buf = vec![0u16; 2048];
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: `buf` holds `size` bytes.
        let ok = unsafe {
            WinHttpQueryHeaders(res.request.0, WINHTTP_QUERY_LOCATION, null(), buf.as_mut_ptr() as *mut c_void, &mut size, null_mut())
        };
        if ok == 0 {
            return Err(os_error());
        }
        Ok(String::from_utf16_lossy(&buf[..size as usize / 2]))
    }

    /// The body of `url`, following redirects (release files live on another
    /// host), as long as it fits in `max` bytes.
    pub fn get(url: &str, max: usize) -> Result<Vec<u8>> {
        let res = send(url, true)?;
        if res.status != 200 {
            return Err(Error::new(format!("HTTP {}", res.status)));
        }
        let mut body = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let mut read = 0u32;
            // SAFETY: `buf` holds `buf.len()` bytes.
            let ok = unsafe { WinHttpReadData(res.request.0, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut read) };
            if ok == 0 {
                return Err(os_error());
            }
            if read == 0 {
                return Ok(body);
            }
            body.extend_from_slice(&buf[..read as usize]);
            if body.len() > max {
                return Err(Error::new(tr("file quá lớn", "file too large")));
            }
        }
    }

    pub fn open_url(url: &str) {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let (verb, url) = (wide("open"), wide(url));
        // SAFETY: both strings are NUL-terminated and live for the call.
        unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), url.as_ptr(), null(), null(), SW_SHOWNORMAL) };
    }

    /// The installer's entry under Apps still names the version it installed;
    /// point it at the new one when this exe is the installed copy.
    pub fn note_installed_version(exe: &Path, version: &str) {
        use windows_sys::Win32::System::Registry::*;
        const KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B7E8C3A1-4F2D-4E8A-9C1B-3D5F7A8E2B4C}_is1";
        let key = wide(KEY);
        // SAFETY: buffers are NUL-terminated or sized as passed; the key is
        // closed before returning.
        unsafe {
            let mut hkey: HKEY = null_mut();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.as_ptr(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &mut hkey) != 0 {
                return;
            }
            let mut buf = vec![0u16; 1024];
            let mut size = (buf.len() * 2) as u32;
            let name = wide("InstallLocation");
            let read = RegGetValueW(hkey, null(), name.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr() as *mut c_void, &mut size);
            let location = String::from_utf16_lossy(&buf[..(size as usize / 2).saturating_sub(1)]);
            let installed = read == 0
                && exe.parent().is_some_and(|dir| {
                    dir.to_string_lossy().trim_end_matches('\\').eq_ignore_ascii_case(location.trim_end_matches('\\'))
                });
            if installed {
                for (name, value) in [("DisplayVersion", version.to_string()), ("DisplayName", format!("Yeager {version}"))] {
                    let (name, value) = (wide(name), wide(&value));
                    RegSetKeyValueW(hkey, null(), name.as_ptr(), REG_SZ, value.as_ptr() as *const c_void, (value.len() * 2) as u32);
                }
            }
            RegCloseKey(hkey);
        }
    }
}

/// Off Windows there is nothing to update; this keeps `cargo test` building.
#[cfg(not(windows))]
mod http {
    use super::*;

    pub fn redirect_target(_url: &str) -> Result<String> {
        Err(Error::new("Windows only"))
    }

    pub fn get(_url: &str, _max: usize) -> Result<Vec<u8>> {
        Err(Error::new("Windows only"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("1.0.1"), Some((1, 0, 1)));
        assert_eq!(parse_version("v10.2.30"), Some((10, 2, 30)));
        assert_eq!(parse_version("1.0"), None);
        assert_eq!(parse_version("1.0.1.2"), None);
        assert_eq!(parse_version("1.0.1-beta"), None);
        assert_eq!(parse_version("1..1"), None);
        assert!(parse_version("1.10.0") > parse_version("1.9.9"));
    }

    #[test]
    fn compares_with_this_exe() {
        assert!(is_newer("999.0.0"));
        assert!(!is_newer(current()));
        assert!(!is_newer("0.0.1"));
        assert!(!is_newer("garbage"));
    }

    #[test]
    fn reads_tag_from_redirect() {
        assert_eq!(
            version_from_tag_url("https://github.com/iamcino/Yeager/releases/tag/v1.0.2").as_deref(),
            Some("1.0.2")
        );
        assert_eq!(version_from_tag_url("https://github.com/iamcino/Yeager/releases"), None);
        assert_eq!(version_from_tag_url("https://github.com/x/releases/tag/v2.0.0-rc1"), None);
    }

    #[test]
    fn finds_checksum() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let sums = format!("{a}  Yeager-Setup-1.0.2.exe\r\n{b}  yeager.exe\r\n");
        assert_eq!(checksum_for(&sums, "yeager.exe"), Some("b".repeat(64)));
        assert_eq!(checksum_for(&sums, "missing.exe"), None);
        assert_eq!(checksum_for("abc  yeager.exe", "yeager.exe"), None);
    }

    #[test]
    fn hashes() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn swaps_the_exe() {
        let dir = std::env::temp_dir().join(format!("yeager-update-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(EXE_NAME);
        std::fs::write(&path, b"old").unwrap();
        install(b"MZnew", &path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"MZnew");
        assert_eq!(std::fs::read(dir.join(OLD_EXE)).unwrap(), b"old");
        assert!(!dir.join(NEW_EXE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

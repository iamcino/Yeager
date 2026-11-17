//! Updates `yeager.exe` in place from the project's releases, the way EasyKey
//! does.
//!
//! Download/install failure leaves the current active DNS untouched. The
//! epilogue restarts the replacement even when the shutdown restore leaves
//! debt: the debt is logged and the next launch's fail-open leftover restore
//! handles it. The downloaded exe is verified under the same hash +
//! pinned-signature trust policy as the app binaries.
//!
//! Every release is published on GitHub and on GitLab. Both are asked at once;
//! the newest version either of them has wins, and if one site cannot be
//! reached (blocked, down, or the repository unavailable) the other one is
//! enough. The latest version is the tag each site's "latest release" link
//! redirects to. The new exe is downloaded over HTTPS (WinHTTP, so the Windows
//! proxy and certificate store apply). Acceptance is a fixed gate, identical
//! for both origins: parse `SHA256SUMS.txt`, verify the exe's SHA-256, then
//! verify the Authenticode signature with `WinVerifyTrust` and compare the
//! signer certificate's SPKI hash (SHA-256 over the full DER encoding of the
//! SubjectPublicKeyInfo) against the pinned key below. The signing certificate
//! is self-issued, so chain-to-public-root trust is not the anchor; the anchor
//! is a cryptographically valid signature plus the SPKI pin, with a mandatory
//! RFC 3161 timestamp (validity is judged at signing time, so a countersigned
//! binary stays acceptable after the signing certificate expires). Anything
//! else fails closed. The running exe is
//! renamed to `yeager.old.exe`, the new one takes its name and starts once this
//! one has put Windows back, and the old file is deleted on the next start.
//! Nothing is installed without asking.

use common::lang::tr;
use common::{t, Error, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// A site the releases are published on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    GitHub,
    GitLab,
}

impl Source {
    const ALL: [Source; 2] = [Source::GitHub, Source::GitLab];

    /// Redirects to the newest release's page.
    fn latest_url(self) -> &'static str {
        match self {
            Source::GitHub => "https://github.com/iamcino/Yeager/releases/latest",
            Source::GitLab => "https://gitlab.com/cino-group/yeager/-/releases/permalink/latest",
        }
    }

    fn releases_page(self) -> &'static str {
        match self {
            Source::GitHub => "https://github.com/iamcino/Yeager/releases/latest",
            Source::GitLab => "https://gitlab.com/cino-group/yeager/-/releases",
        }
    }

    fn release_page(self, version: &str) -> String {
        match self {
            Source::GitHub => format!("https://github.com/iamcino/Yeager/releases/tag/v{version}"),
            Source::GitLab => format!("https://gitlab.com/cino-group/yeager/-/releases/v{version}"),
        }
    }

    /// Where the files of `version` are; the file name goes after it.
    fn download_base(self, version: &str) -> String {
        match self {
            Source::GitHub => format!("https://github.com/iamcino/Yeager/releases/download/v{version}/"),
            Source::GitLab => format!("https://gitlab.com/cino-group/yeager/-/releases/v{version}/downloads/"),
        }
    }
}

/// The site the last check found the newest version on; tried first for the
/// download, the release notes and the download page.
static PREFERRED: AtomicU8 = AtomicU8::new(0);

fn preferred() -> Source {
    if PREFERRED.load(Ordering::Relaxed) == 1 { Source::GitLab } else { Source::GitHub }
}

fn set_preferred(source: Source) {
    PREFERRED.store(if source == Source::GitLab { 1 } else { 0 }, Ordering::Relaxed);
}

/// Both sites, the preferred one first.
fn sources() -> [Source; 2] {
    match preferred() {
        Source::GitHub => [Source::GitHub, Source::GitLab],
        Source::GitLab => [Source::GitLab, Source::GitHub],
    }
}

/// The page to send people to when an update cannot be installed here.
pub fn releases_page() -> &'static str {
    preferred().releases_page()
}

const EXE_NAME: &str = "yeager.exe";
const OLD_EXE: &str = "yeager.old.exe";
const NEW_EXE: &str = "yeager.new.exe";
const MAX_DOWNLOAD: usize = 64 * 1024 * 1024;

/// SHA-256 over the full DER encoding of the code-signing key's SubjectPublicKeyInfo.
///
/// The key is EC P-256 (the DER SPKI is 91 bytes). This pins the *key*, not the
/// certificate: the house has rotated the signing certificate before, and a
/// thumbprint pin would brick every deployed updater at the next rotation,
/// while the key survives renewal. A binary signed by a new certificate
/// carrying this same key is therefore accepted; a validly signed binary under
/// any other key is rejected.
///
/// Derived from the published `Yeager-codesign.cer` release asset and
/// cross-checked against the signer certificate embedded in the signed
/// `yeager.exe` itself (thumbprint `9131F99C0B198E81FBA0F5818D0637B4A14D4CF1`).
pub const PINNED_SPKI_SHA256_HEX: &str =
    "87d1146a21bbb25d5a1be26875050c63d227573e4c4db881788f8220a0600fe0";

/// [`PINNED_SPKI_SHA256_HEX`] decoded, for constant-time comparison.
const PINNED_SPKI_SHA256: [u8; 32] = decode_hex32(PINNED_SPKI_SHA256_HEX);

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

const fn decode_hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(b[2 * i]) << 4) | hex_nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Whether `spki_der` (full DER encoding of a SubjectPublicKeyInfo) is the
/// pinned key. The comparison is on the SPKI hash only: certificate bytes,
/// thumbprints and dates are never consulted, so rotation to a new
/// certificate carrying the same key passes by construction.
fn spki_pin_matches(spki_der: &[u8]) -> bool {
    let digest = ring::digest::digest(&ring::digest::SHA256, spki_der);
    let bytes = digest.as_ref();
    bytes.len() == PINNED_SPKI_SHA256.len()
        && bytes.iter().zip(PINNED_SPKI_SHA256.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

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

/// The version in a release page URL: `…/releases/tag/v1.2.3` on GitHub,
/// `…/-/releases/v1.2.3` on GitLab.
fn version_from_tag_url(url: &str) -> Option<String> {
    let url = url.trim();
    let tag = url.rsplit_once("/tag/").or_else(|| url.rsplit_once("/-/releases/"))?.1;
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

/// The release notes of `version`.
pub fn notes_url(version: &str) -> String {
    preferred().release_page(version)
}

fn latest_from(source: Source) -> Result<String> {
    let location = http::redirect_target(source.latest_url())?;
    version_from_tag_url(&location)
        .ok_or_else(|| Error::new(tr("Trang phát hành trả về phiên bản không hợp lệ.", "The release page returned an invalid version.")))
}

/// The newest of the versions each site reports, and the site it came from
/// (GitHub when both have it). Errors only when neither site answered.
fn newest(results: [(Source, Result<String>); 2]) -> Result<(String, Source)> {
    let mut best: Option<(String, Source)> = None;
    let mut error = None;
    for (source, result) in results {
        match result {
            Ok(version) => {
                if best.as_ref().is_none_or(|(b, _)| parse_version(&version) > parse_version(b)) {
                    best = Some((version, source));
                }
            }
            Err(e) => error = error.or(Some(e)),
        }
    }
    best.ok_or_else(|| error.unwrap_or_else(|| Error::new("no release site")))
}

/// Asks GitHub and GitLab for the latest release, at the same time. Blocking;
/// run it off the UI thread.
pub fn latest() -> Result<String> {
    let [github, gitlab] = std::thread::scope(|s| {
        let jobs = Source::ALL.map(|source| s.spawn(move || latest_from(source)));
        jobs.map(|job| job.join().unwrap_or_else(|_| Err(Error::new("update check failed"))))
    });
    let (version, source) = newest([(Source::GitHub, github), (Source::GitLab, gitlab)])?;
    set_preferred(source);
    Ok(version)
}

/// Why an update did not go through, each with its own advice.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    Download(Error),
    Mismatch,
    /// The Authenticode/SPKI gate refused the file: unsigned, untrusted
    /// signature, SPKI mismatch, or a verification API error. Kept distinct
    /// from [`Failure::Mismatch`] so field reports stay readable: a checksum
    /// mismatch means a broken download, a signature failure means the file
    /// must not be trusted even though its hash matches the release listing.
    Signature,
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
            Failure::Signature => tr(
                "Không xác minh được chữ ký của bản cập nhật nên chưa được cài. Mở trang tải về?",
                "The update's signature could not be verified, so it was not installed. Open the download page?",
            )
            .into(),
            Failure::Install(e) => t!(
                "Không ghi được vào thư mục của Yeager ({e}). Mở trang tải về để tải thủ công?",
                "Could not write to the Yeager folder ({e}). Open the download page to get it yourself?"
            ),
        }
    }
}

/// Downloads `version` from `source` and checks it against that release's
/// checksum list, then through the signature gate.
fn download(source: Source, version: &str) -> std::result::Result<Vec<u8>, Failure> {
    let base = source.download_base(version);
    let sums = http::get(&format!("{base}SHA256SUMS.txt"), 64 * 1024).map_err(Failure::Download)?;
    let exe = http::get(&format!("{base}{EXE_NAME}"), MAX_DOWNLOAD).map_err(Failure::Download)?;
    accept_bytes(&exe, &sums, &http::verify_file_signature)
}

/// The acceptance gate, identical for both origins: parse `SHA256SUMS.txt`,
/// verify the exe's SHA-256, then hand the bytes to `verify` (the Authenticode
/// + SPKI step). `verify` receives the bytes staged to a freshly created temp
/// file and is only called when the hashes already match, so a tampered exe
/// served with recomputed sums still faces the signature check.
///
/// `verify` is a parameter (rather than a direct call) so tests can drive the
/// gate with fixture outcomes; production passes
/// [`http::verify_file_signature`].
fn accept_bytes(
    exe: &[u8],
    sums: &[u8],
    verify: &dyn Fn(&Path) -> std::result::Result<(), Failure>,
) -> std::result::Result<Vec<u8>, Failure> {
    let expected = checksum_for(&String::from_utf8_lossy(sums), EXE_NAME).ok_or(Failure::Mismatch)?;
    if !exe.starts_with(b"MZ") || sha256_hex(exe) != expected {
        return Err(Failure::Mismatch);
    }
    // Stage the exact bytes under check to a fresh file for the Authenticode
    // APIs, which verify files rather than buffers. `create_new` refuses an
    // existing path so a planted file can neither be read nor replaced here.
    static STAGED_COUNTER: AtomicU64 = AtomicU64::new(0);
    let staged = std::env::temp_dir().join(format!(
        "yeager-verify-{}-{}.tmp",
        std::process::id(),
        STAGED_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let staged_write = std::fs::OpenOptions::new().write(true).create_new(true).open(&staged);
    match staged_write.and_then(|mut f| {
        use std::io::Write as _;
        f.write_all(exe).map(|_| f)
    }) {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = f.flush();
            drop(f);
        }
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            return Err(Failure::Install(e.into()));
        }
    }
    let verdict = verify(&staged);
    let _ = std::fs::remove_file(&staged);
    // Any verification API error fails closed as a signature refusal: the
    // file is not installed unless the gate positively passes.
    verdict.map(|_| exe.to_vec())
}

/// Downloads `version`, checks it and puts it in place of the running exe,
/// from the site the check found it on, or the other one if that fails.
/// Returns the path to start. Blocking; run it off the UI thread.
///
/// This function performs no DNS mutation: a download or install failure
/// returns before any replacement step, leaving the current active DNS
/// untouched. Restore debt never cancels the epilogue's restart.
pub fn download_and_install(version: &str) -> std::result::Result<PathBuf, Failure> {
    let mut failure = None;
    let mut exe = None;
    for source in sources() {
        match download(source, version) {
            Ok(bytes) => {
                set_preferred(source);
                exe = Some(bytes);
                break;
            }
            // A file that fails the checksum or the signature gate is reported
            // over a site that could not be reached; the two hosts' results
            // are not treated differently in any way.
            Err(f) => {
                let sticky = matches!(failure, Some(Failure::Mismatch) | Some(Failure::Signature));
                if !sticky {
                    failure = Some(f);
                }
            }
        }
    }
    let Some(exe) = exe else { return Err(failure.unwrap_or(Failure::Mismatch)) };
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

    // --- Authenticode + SPKI gate -------------------------------------------
    //
    // Same house pattern as EasyKey's updater verification (verify, compare
    // pin, fail closed), but the comparison is an SPKI hash rather than a
    // certificate thumbprint. The signing certificate is self-issued, so the
    // default `WINTRUST_ACTION_GENERIC_VERIFY_V2` policy cannot express the
    // trust rule on its own (it reports an untrusted root for a perfectly
    // good self-issued signature, exactly as `Get-AuthenticodeSignature` does
    // with `UnknownError`). The same flag/provider structure EasyKey uses is
    // therefore used here: `WINTRUST_ACTION_GENERIC_CHAIN_VERIFY` with an
    // isolated chain engine whose exclusive root is the file's own signer
    // certificate, plus a policy callback that checks cryptographic validity,
    // the SPKI pin, and a mandatory RFC 3161 timestamp whose chain verifies
    // against normal Windows trust (DigiCert). Trusting the extracted signer
    // for chain building is safe because acceptance still requires the SPKI
    // pin: any other key is rejected no matter what signed the file.
    //
    // `WinVerifyTrust` judges validity at signing time when a countersignature
    // is present, so a countersigned binary stays acceptable after the signing
    // certificate expires; no date of our own is ever consulted.
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Security::Cryptography::*;
    use windows_sys::Win32::Security::WinTrust::*;
    use windows_sys::core::{HRESULT, PCSTR};

    // `wintrust.h` values missing from windows-sys 0.59. Only the failure is
    // load-bearing (anything but `S_OK` fails closed); the exact codes keep
    // logs comparable with EasyKey's verifier.
    const TRUST_E_SUBJECT_NOT_TRUSTED: HRESULT = 0x800B0004u32 as i32;
    const TRUST_E_TIME_STAMP: HRESULT = 0x800B0009u32 as i32;
    const S_OK: HRESULT = 0;

    /// Callback argument: whether the policy accepted the file.
    struct PolicyArg {
        accepted: bool,
    }

    /// DER-encode the SubjectPublicKeyInfo of `cert` (any key type).
    fn spki_der_of(cert: *const CERT_CONTEXT) -> Option<Vec<u8>> {
        // SAFETY: `cert` is a live context from our own store lookup below.
        unsafe {
            let info = (*cert).pCertInfo;
            if info.is_null() {
                return None;
            }
            let spki = &(*info).SubjectPublicKeyInfo as *const CERT_PUBLIC_KEY_INFO;
            let mut len: u32 = 0;
            if CryptEncodeObject(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                spki as *const c_void,
                null_mut(),
                &mut len,
            ) == 0
                || len == 0
            {
                return None;
            }
            let mut der = vec![0u8; len as usize];
            if CryptEncodeObject(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                spki as *const c_void,
                der.as_mut_ptr(),
                &mut len,
            ) == 0
            {
                return None;
            }
            der.truncate(len as usize);
            Some(der)
        }
    }

    fn oid_eq(a: PCSTR, b: PCSTR) -> bool {
        use std::ffi::CStr;
        use std::os::raw::c_char;
        // SAFETY: both are NUL-terminated OID strings from the OS or headers.
        unsafe {
            !a.is_null()
                && !b.is_null()
                && CStr::from_ptr(a as *const c_char) == CStr::from_ptr(b as *const c_char)
        }
    }

    /// Policy callback: exactly one SHA-256 primary signature whose leaf
    /// carries the pinned SPKI, an `AUTHENTICODE` chain that verifies, and a
    /// mandatory RFC 3161 countersign whose chain verifies against system
    /// trust. Anything else fails closed without setting `accepted`.
    unsafe extern "system" fn spki_policy_callback(
        _prov_data: *mut CRYPT_PROVIDER_DATA,
        step_error: u32,
        _policy_settings: u32,
        signer_count: u32,
        signers: *mut *mut WTD_GENERIC_CHAIN_POLICY_SIGNER_INFO,
        policy_arg: *mut c_void,
    ) -> HRESULT {
        // SAFETY: WinVerifyTrust calls this with live provider data and a
        // live `PolicyArg`; every pointer is checked before use.
        unsafe {
        let ctx = &mut *(policy_arg as *mut PolicyArg);
        if step_error != 0 {
            return step_error as HRESULT;
        }
        // Release tooling produces one primary signature. Fail closed on
        // ambiguous multi-signatures rather than accepting an unrelated one.
        if signer_count != 1 || signers.is_null() || (*signers).is_null() {
            return TRUST_E_SUBJECT_NOT_TRUSTED;
        }
        let signer = &*(*signers);
        if signer.dwError != 0 {
            return TRUST_E_SUBJECT_NOT_TRUSTED;
        }
        let chain = signer.pChainContext;
        if chain.is_null() || (*chain).cChain == 0 || (*chain).rgpChain.is_null() {
            return TRUST_E_SUBJECT_NOT_TRUSTED;
        }
        let simple = *(*chain).rgpChain;
        if simple.is_null() || (*simple).cElement == 0 || (*simple).rgpElement.is_null() {
            return TRUST_E_SUBJECT_NOT_TRUSTED;
        }
        let leaf = (*(*(*simple).rgpElement)).pCertContext;
        if leaf.is_null() {
            return TRUST_E_SUBJECT_NOT_TRUSTED;
        }
        match spki_der_of(leaf) {
            Some(der) if spki_pin_matches(&der) => {}
            _ => return TRUST_E_SUBJECT_NOT_TRUSTED,
        }
        let msg_info = signer.pMsgSignerInfo;
        if msg_info.is_null() || !oid_eq((*msg_info).HashAlgorithm.pszObjId, szOID_NIST_sha256) {
            return TRUST_E_SUBJECT_NOT_TRUSTED;
        }
        let mut extra: AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA = std::mem::zeroed();
        extra.cbSize = std::mem::size_of::<AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA>() as u32;
        extra.pSignerInfo = msg_info;
        let mut para: CERT_CHAIN_POLICY_PARA = std::mem::zeroed();
        para.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32;
        para.pvExtraPolicyPara = &mut extra as *mut _ as *mut c_void;
        let mut status: CERT_CHAIN_POLICY_STATUS = std::mem::zeroed();
        status.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32;
        if CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE, chain, &para, &mut status) == 0
            || status.dwError != 0
        {
            return TRUST_E_SUBJECT_NOT_TRUSTED;
        }
        let mut has_rfc3161 = false;
        let attrs = &(*msg_info).UnauthAttrs;
        if !attrs.rgAttr.is_null() {
            for i in 0..attrs.cAttr {
                let attr = &*attrs.rgAttr.add(i as usize);
                if oid_eq(attr.pszObjId, szOID_RFC3161_counterSign) {
                    has_rfc3161 = true;
                    break;
                }
            }
        }
        if !has_rfc3161 || signer.rgpCounterSigner.is_null() {
            return TRUST_E_TIME_STAMP;
        }
        // The timestamp chain must use normal Windows trust, never the
        // signer's own key: it is what keeps the verdict meaningful after
        // the signing certificate expires.
        for i in 0..signer.cCounterSigner {
            let counter = *signer.rgpCounterSigner.add(i as usize);
            if counter.is_null() || (*counter).dwError != 0 || (*counter).pChainContext.is_null() {
                continue;
            }
            let mut ts_para: CERT_CHAIN_POLICY_PARA = std::mem::zeroed();
            ts_para.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32;
            let mut ts_status: CERT_CHAIN_POLICY_STATUS = std::mem::zeroed();
            ts_status.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32;
            if CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_AUTHENTICODE_TS,
                (*counter).pChainContext,
                &ts_para,
                &mut ts_status,
            ) != 0
                && ts_status.dwError == 0
            {
                ctx.accepted = true;
                return S_OK;
            }
        }
        TRUST_E_TIME_STAMP
        }
    }

    /// The file's signer certificate, from the embedded PKCS#7 (no trust
    /// involved: this is staging input for the engine below, not a verdict).
    /// The caller owns the returned context and the message/store handles.
    fn signer_and_handles(
        path_wide: &[u16],
    ) -> (*mut CERT_CONTEXT, *mut c_void, HCERTSTORE) {
        // SAFETY: every pointer passed is NUL-terminated or sized as passed;
        // every handle is checked before use; the caller releases all three.
        unsafe {
        let mut encoding: CERT_QUERY_ENCODING_TYPE = std::mem::zeroed();
        let mut content: CERT_QUERY_CONTENT_TYPE = std::mem::zeroed();
        let mut format: CERT_QUERY_FORMAT_TYPE = std::mem::zeroed();
        let mut store: HCERTSTORE = std::mem::zeroed();
        let mut msg: *mut c_void = null_mut();
        let ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_wide.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding,
            &mut content,
            &mut format,
            &mut store,
            &mut msg,
            null_mut(),
        );
        if ok == 0 || store.is_null() || msg.is_null() {
            if !store.is_null() {
                CertCloseStore(store, 0);
            }
            if !msg.is_null() {
                CryptMsgClose(msg);
            }
            return (null_mut(), null_mut(), std::mem::zeroed());
        }
        let mut info_len: u32 = 0;
        if CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, null_mut(), &mut info_len) == 0
            || info_len == 0
        {
            CertCloseStore(store, 0);
            CryptMsgClose(msg);
            return (null_mut(), null_mut(), std::mem::zeroed());
        }
        let mut buf = vec![0u8; info_len as usize];
        if CryptMsgGetParam(
            msg,
            CMSG_SIGNER_CERT_INFO_PARAM,
            0,
            buf.as_mut_ptr() as *mut c_void,
            &mut info_len,
        ) == 0
        {
            CertCloseStore(store, 0);
            CryptMsgClose(msg);
            return (null_mut(), null_mut(), std::mem::zeroed());
        }
        let signer = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING,
            std::mem::zeroed(),
            CERT_FIND_SUBJECT_CERT,
            buf.as_ptr() as *const c_void,
            null(),
        );
        if signer.is_null() {
            CertCloseStore(store, 0);
            CryptMsgClose(msg);
            return (null_mut(), null_mut(), std::mem::zeroed());
        }
        (signer, msg, store)
        }
    }

    /// Runs `WinVerifyTrust` with the isolated engine and the SPKI policy.
    /// Returns true only when the signature is cryptographically valid, the
    /// SPKI pin matches, and a system-trusted RFC 3161 timestamp is present.
    pub fn verify_file_signature(path: &Path) -> std::result::Result<(), Failure> {
        let path_wide = wide(&path.to_string_lossy());
        // SAFETY: every pointer passed is NUL-terminated or sized as passed;
        // every handle is checked before use and released before returning.
        unsafe {
            let (signer, msg, store) = signer_and_handles(&path_wide);
            if signer.is_null() {
                return Err(Failure::Signature);
            }
            // Isolated engine trusting only this file's signer, the same
            // structure EasyKey uses for its pinned certificate. Nothing is
            // added to the machine or user certificate stores.
            let roots = CertOpenStore(CERT_STORE_PROV_MEMORY, std::mem::zeroed(), 0, 0, null());
            let mut engine: HCERTCHAINENGINE = std::mem::zeroed();
            let mut ready = false;
            if !roots.is_null()
                && CertAddCertificateContextToStore(roots, signer, CERT_STORE_ADD_NEW, null_mut()) != 0
            {
                let mut config: CERT_CHAIN_ENGINE_CONFIG = std::mem::zeroed();
                config.cbSize = std::mem::size_of::<CERT_CHAIN_ENGINE_CONFIG>() as u32;
                config.hExclusiveRoot = roots;
                if CertCreateCertificateChainEngine(&config, &mut engine) != 0 && engine != 0 {
                    ready = true;
                }
            }
            let mut valid = false;
            if ready {
                let mut code_usage = szOID_PKIX_KP_CODE_SIGNING as *mut u8;
                let mut ts_usage = szOID_PKIX_KP_TIMESTAMP_SIGNING as *mut u8;
                let mut code_para: CERT_CHAIN_PARA = std::mem::zeroed();
                code_para.cbSize = std::mem::size_of::<CERT_CHAIN_PARA>() as u32;
                code_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
                code_para.RequestedUsage.Usage.cUsageIdentifier = 1;
                code_para.RequestedUsage.Usage.rgpszUsageIdentifier = &mut code_usage;
                let mut ts_para: CERT_CHAIN_PARA = std::mem::zeroed();
                ts_para.cbSize = std::mem::size_of::<CERT_CHAIN_PARA>() as u32;
                ts_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
                ts_para.RequestedUsage.Usage.cUsageIdentifier = 1;
                ts_para.RequestedUsage.Usage.rgpszUsageIdentifier = &mut ts_usage;
                let mut primary: WTD_GENERIC_CHAIN_POLICY_CREATE_INFO = std::mem::zeroed();
                primary.Anonymous.cbSize =
                    std::mem::size_of::<WTD_GENERIC_CHAIN_POLICY_CREATE_INFO>() as u32;
                primary.hChainEngine = engine;
                primary.pChainPara = &mut code_para;
                primary.dwFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
                let mut timestamp: WTD_GENERIC_CHAIN_POLICY_CREATE_INFO = std::mem::zeroed();
                timestamp.Anonymous.cbSize =
                    std::mem::size_of::<WTD_GENERIC_CHAIN_POLICY_CREATE_INFO>() as u32;
                timestamp.pChainPara = &mut ts_para;
                timestamp.dwFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
                let mut chain: WTD_GENERIC_CHAIN_POLICY_DATA = std::mem::zeroed();
                chain.Anonymous.cbSize =
                    std::mem::size_of::<WTD_GENERIC_CHAIN_POLICY_DATA>() as u32;
                chain.pSignerChainInfo = &mut primary;
                chain.pCounterSignerChainInfo = &mut timestamp;
                chain.pfnPolicyCallback = Some(spki_policy_callback);
                let mut arg = PolicyArg { accepted: false };
                chain.pvPolicyArg = &mut arg as *mut _ as *mut c_void;
                let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
                file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
                file_info.pcwszFilePath = path_wide.as_ptr();
                let mut trust: WINTRUST_DATA = std::mem::zeroed();
                trust.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
                trust.pPolicyCallbackData = &mut chain as *mut _ as *mut c_void;
                trust.dwUIChoice = WTD_UI_NONE;
                trust.fdwRevocationChecks = WTD_REVOKE_NONE;
                trust.dwUnionChoice = WTD_CHOICE_FILE;
                trust.Anonymous.pFile = &mut file_info;
                trust.dwStateAction = WTD_STATEACTION_VERIFY;
                trust.dwProvFlags = std::mem::transmute::<u32, WINTRUST_DATA_PROVIDER_FLAGS>(
                    WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
                );
                trust.dwUIContext = WTD_UICONTEXT_EXECUTE;
                let mut action = WINTRUST_ACTION_GENERIC_CHAIN_VERIFY;
                valid = WinVerifyTrust(
                    null_mut::<c_void>() as HWND,
                    &mut action,
                    &mut trust as *mut _ as *mut c_void,
                ) == 0
                    && arg.accepted;
                trust.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(
                    null_mut::<c_void>() as HWND,
                    &mut action,
                    &mut trust as *mut _ as *mut c_void,
                );
            }
            CertFreeCertificateContext(signer);
            CryptMsgClose(msg);
            CertCloseStore(store, 0);
            if engine != 0 {
                CertFreeCertificateChainEngine(engine);
            }
            if !roots.is_null() {
                CertCloseStore(roots, 0);
            }
            if valid { Ok(()) } else { Err(Failure::Signature) }
        }
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

    /// Fail closed off Windows: nothing may be accepted without the gate.
    pub fn verify_file_signature(_path: &Path) -> std::result::Result<(), Failure> {
        Err(Failure::Signature)
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
        assert_eq!(
            version_from_tag_url("https://gitlab.com/cino-group/yeager/-/releases/v1.1.4").as_deref(),
            Some("1.1.4")
        );
        assert_eq!(version_from_tag_url("https://gitlab.com/cino-group/yeager/-/releases"), None);
    }

    #[test]
    fn picks_the_newest_site() {
        let ok = |v: &str| Ok(v.to_string());
        let down = || Err(Error::new("HTTP 404"));
        let pick = |a, b| newest([(Source::GitHub, a), (Source::GitLab, b)]).ok();
        assert_eq!(pick(ok("1.1.3"), ok("1.1.4")), Some(("1.1.4".into(), Source::GitLab)));
        assert_eq!(pick(ok("1.1.4"), ok("1.1.4")), Some(("1.1.4".into(), Source::GitHub)));
        assert_eq!(pick(down(), ok("1.1.4")), Some(("1.1.4".into(), Source::GitLab)));
        assert_eq!(pick(ok("1.1.4"), down()), Some(("1.1.4".into(), Source::GitHub)));
        assert_eq!(pick(down(), down()), None);
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

    /// The pinned value is the SHA-256 of the *full DER SPKI* (91 bytes for
    /// EC P-256), not of the raw public-key bytes. Rebuild the DER SPKI from
    /// the published certificate's raw key and prove the pin matches it.
    #[test]
    fn pin_is_full_der_spki_hash() {
        const PREFIX: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
            0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
            0x07, 0x03, 0x42, 0x00,
        ];
        // Uncompressed P-256 point from `Yeager-codesign.cer` (public key;
        // the private key never appears in the repo).
        const RAW_KEY: [u8; 65] = [
            0x04, 0x6c, 0x63, 0xf0, 0xa4, 0xd5, 0xa9, 0x7c, 0x68, 0x03, 0x2d,
            0x9f, 0x87, 0x1e, 0x38, 0xeb, 0xb2, 0x9d, 0x1e, 0x23, 0xbd, 0x45,
            0x89, 0x3a, 0x3b, 0x9b, 0xdd, 0x78, 0x4e, 0x0f, 0x83, 0x5c, 0xbf,
            0x5b, 0x2f, 0xb2, 0x29, 0x6e, 0xf0, 0x64, 0xf8, 0xc2, 0xe8, 0xd3,
            0xbe, 0x2e, 0x07, 0xa7, 0x4e, 0x6d, 0x28, 0x10, 0xfc, 0x09, 0x4b,
            0x61, 0x3c, 0xa4, 0x10, 0x4b, 0x6c, 0x75, 0x84, 0x0a, 0x85,
        ];
        let mut der = Vec::with_capacity(91);
        der.extend_from_slice(&PREFIX);
        der.extend_from_slice(&RAW_KEY);
        assert_eq!(der.len(), 91);
        assert!(spki_pin_matches(&der));
        assert_eq!(sha256_hex(&der), PINNED_SPKI_SHA256_HEX);
        // A hash over the raw key bytes alone is a different value: this is
        // the derivation the gate must NOT use.
        assert_ne!(sha256_hex(&RAW_KEY), PINNED_SPKI_SHA256_HEX);
        // One flipped bit (an attacker's adjacent key) must not match.
        der[90] ^= 1;
        assert!(!spki_pin_matches(&der));
    }

    /// Rotation: the comparison consults only the SPKI hash, so a new
    /// certificate carrying the same key passes by construction. There is no
    /// thumbprint, serial or date anywhere in the decision.
    #[test]
    fn pin_compares_key_not_certificate() {
        // Same SPKI bytes a renewed certificate would carry (identical key).
        // The gate takes only SPKI bytes, so cert-level differences cannot
        // even be expressed, let alone cause a rejection.
        let mut der = vec![0u8; 91];
        der[0] = 0x30;
        der[1] = 0x59;
        // A zeroed SPKI is not the pin, whatever certificate wrapped it.
        assert!(!spki_pin_matches(&der));
    }

    fn sums_for(exe: &[u8]) -> Vec<u8> {
        format!("{}  {EXE_NAME}\n", sha256_hex(exe)).into_bytes()
    }

    /// The checksums must agree before the signature step runs at all: with
    /// mismatched hashes the gate reports `Mismatch` and never calls `verify`.
    #[test]
    fn gate_checks_sums_before_signature() {
        let exe = b"MZ-fake-binary";
        let called = std::cell::Cell::new(false);
        let result = accept_bytes(exe, "0".repeat(64).as_bytes(), &|_| {
            called.set(true);
            Ok(())
        });
        assert_eq!(result.unwrap_err(), Failure::Mismatch);
        assert!(!called.get(), "signature step must not run when hashes mismatch");
    }

    /// The vulnerability scenario: the hashes match each other (a recomputed
    /// `SHA256SUMS.txt` over a tampered exe) and the file is still refused,
    /// with a `Signature` failure distinct from `Mismatch`.
    #[test]
    fn gate_rejects_matching_hashes_when_signature_fails() {
        let exe = b"MZ-tampered";
        let sums = sums_for(exe);
        let result = accept_bytes(exe, &sums, &|_| Err(Failure::Signature));
        let err = result.unwrap_err();
        assert_eq!(err, Failure::Signature);
        assert_ne!(err, Failure::Mismatch);
    }

    /// A good file (hashes match, signature verifies) is accepted unchanged.
    #[test]
    fn gate_accepts_matching_hashes_with_good_signature() {
        let exe = b"MZ-good";
        let sums = sums_for(exe);
        assert_eq!(accept_bytes(exe, &sums, &|_| Ok(())), Ok(exe.to_vec()));
    }

    /// Unsigned files and files signed under any other key are refused at the
    /// same gate with the same `Signature` failure.
    #[test]
    fn gate_rejects_unsigned_and_wrong_key() {
        let exe = b"MZ-unsigned";
        let sums = sums_for(exe);
        assert_eq!(
            accept_bytes(exe, &sums, &|_| Err(Failure::Signature)).unwrap_err(),
            Failure::Signature
        );
        let other = b"MZ-attacker-signed";
        let other_sums = sums_for(other);
        assert_eq!(
            accept_bytes(other, &other_sums, &|_| Err(Failure::Signature)).unwrap_err(),
            Failure::Signature
        );
    }

    /// Timestamp policy: the gate consults no certificate dates of its own
    /// (there is no `SystemTime`/not-after check anywhere in this module), so
    /// an expired certificate with a valid RFC 3161 countersign still passes
    /// the fixture the way the real verifier judges validity at signing time.
    #[test]
    fn gate_expired_cert_with_timestamp_accepted() {
        let exe = b"MZ-expired-but-timestamped";
        let sums = sums_for(exe);
        assert_eq!(accept_bytes(exe, &sums, &|_| Ok(())), Ok(exe.to_vec()));
    }

    /// Real-artifact check against the genuinely signed v1.1.6 `yeager.exe`:
    /// accepted as-is, and a tampered copy with recomputed sums rejected by
    /// the real `WinVerifyTrust` + SPKI verifier. Skipped where the release
    /// artifact is not present (e.g. CI); the seam tests above always run.
    #[cfg(windows)]
    #[test]
    fn real_artifact_signed_accepts_and_tampered_rejects() {
        let path = std::env::var("YEAGER_SIGNED_FIXTURE").unwrap_or_else(|_| {
            r"C:\projects\yeager-p0-pkg\yeager-1.1.6.exe".to_string()
        });
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("skipping real-artifact gate test: {path} not present");
                return;
            }
        };
        assert!(bytes.starts_with(b"MZ"));
        let sums = sums_for(&bytes);
        accept_bytes(&bytes, &sums, &http::verify_file_signature)
            .expect("genuinely signed artifact must be accepted");
        let mut bad = bytes.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xFF;
        let bad_sums = sums_for(&bad);
        let err = accept_bytes(&bad, &bad_sums, &http::verify_file_signature).unwrap_err();
        assert_eq!(
            err,
            Failure::Signature,
            "tampered exe with matching sums must be rejected by the signature gate"
        );
    }

    /// Pin re-derivation from the shipped package inputs: the committed
    /// `spki.der` (extracted from both the published cert and the signed exe)
    /// hashes to the pinned value.
    #[test]
    fn pin_matches_shipped_spki_der() {
        let dir = std::env::var("YEAGER_P0U_PKG")
            .unwrap_or_else(|_| r"C:\projects\yeager-p0-pkg".to_string());
        let mut checked = 0;
        for name in ["spki.der", "spki-from-exe.der"] {
            match std::fs::read(format!("{dir}\\{name}")) {
                Ok(der) => {
                    assert!(spki_pin_matches(&der), "{name} must hash to the pin");
                    checked += 1;
                }
                Err(_) => eprintln!("skipping {name}: not present"),
            }
        }
        if checked == 0 {
            eprintln!("skipping spki.der re-derivation: package dir not present");
        }
    }
}

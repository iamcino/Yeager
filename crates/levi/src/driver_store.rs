//! Protected on-disk store for the embedded WinDivert driver files (rev.3).
//!
//! Layout: `%ProgramData%\Yeager\driver`, created with a DACL that is
//! **protected** (`SE_DACL_PROTECTED`, inheritance OFF) granting full control
//! to Administrators and SYSTEM and read + execute to Users. Both the parent
//! (`%ProgramData%\Yeager`) and the leaf are created with SECURITY_ATTRIBUTES
//! carrying that DACL. On every start — even when the directories already
//! exist — the owner and the effective DACL are re-verified; any mismatch
//! fails closed. There is no fallback to a user-writable location.
//!
//! Integrity: hash-first discipline. Before every load, each on-disk file's
//! SHA-256 is compared with the embedded bytes' SHA-256. A match skips the
//! write entirely (the directory is protected, so rewriting is needless
//! risk); a mismatch or a missing file is rewritten, and if that write fails
//! — the file is locked by a second running binary or any other reason —
//! startup fails closed. A file whose hash was not verified in this run is
//! never loaded.
//!
//! Legacy cleanup: the first runs of the fixed build remove the old
//! `%TEMP%\Yeager_bin` directory — safely: a reparse point there is never
//! traversed, only the two known files are deleted, never recursively.
//!
//! LGPLv3 replaceability: `--driver-dir <path>` (a CLI flag accepted by both
//! host binaries) substitutes a personal driver build. The flagged directory
//! is used as-is — the user's deliberate act — with one log line. The override
//! is deliberately NOT readable from `config.json` (medium-IL-writable: a
//! config-read override would reopen this hole through the front door) and NOT
//! from the environment (inherited env is a channel a medium-IL parent
//! controls).

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// File names of the embedded driver binaries.
pub const WINDIVERT_DLL_NAME: &str = "WinDivert.dll";
pub const WINDIVERT_SYS_NAME: &str = "WinDivert64.sys";

/// CLI flag naming the driver-directory override (single source of truth for
/// both host binaries: `yeager.exe` and `levi.exe`).
pub const DRIVER_DIR_ARG: &str = "--driver-dir";

/// Legacy directory used by pre-fix builds. Never used for loading anymore;
/// removed best-effort on start (see [`cleanup_legacy_temp_dir`]).
pub const LEGACY_TEMP_SUBDIR: &str = "Yeager_bin";

/// Builds the protected driver directory under a given ProgramData root.
/// Pure function so the directory selection is unit-testable.
pub fn driver_dir_for(program_data: &OsStr) -> PathBuf {
    let mut dir = PathBuf::from(program_data);
    dir.push("Yeager");
    dir.push("driver");
    dir
}

/// Builds the protected parent (`%ProgramData%\Yeager`) under a given root.
/// Pure function so the directory selection is unit-testable.
pub fn parent_dir_for(program_data: &OsStr) -> PathBuf {
    let mut dir = PathBuf::from(program_data);
    dir.push("Yeager");
    dir
}

/// Resolves the protected driver directory from `%ProgramData%`.
/// Fails closed when the variable is missing or empty: no fallback to a
/// user-writable location.
pub fn get_driver_dir() -> Result<PathBuf, String> {
    match std::env::var_os("ProgramData") {
        Some(root) if !root.is_empty() => Ok(driver_dir_for(&root)),
        _ => Err(
            "ProgramData is not set; refusing to place the WinDivert driver in a user-writable directory"
                .to_string(),
        ),
    }
}

/// Parses `--driver-dir <path>` / `--driver-dir=<path>` out of an argv slice.
///
/// This is the ONLY override channel: neither `config.json` nor the
/// environment is consulted (both are writable/reachable by a medium-IL
/// attacker and would reopen the planting hole through the front door).
/// The last occurrence wins; a missing or empty value is an error.
pub fn parse_driver_dir_arg(args: &[String]) -> Result<Option<PathBuf>, String> {
    let mut selected: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == DRIVER_DIR_ARG {
            let value = args.get(i + 1).ok_or_else(|| {
                format!("{DRIVER_DIR_ARG} needs a directory path, e.g. {DRIVER_DIR_ARG} C:\\Drivers\\WinDivert")
            })?;
            if value.is_empty() {
                return Err(format!("{DRIVER_DIR_ARG} needs a non-empty directory path"));
            }
            selected = Some(PathBuf::from(value));
            i += 2;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--driver-dir=") {
            if rest.is_empty() {
                return Err(format!("{DRIVER_DIR_ARG} needs a non-empty directory path"));
            }
            selected = Some(PathBuf::from(rest));
        }
        i += 1;
    }
    Ok(selected)
}

/// Returns the legacy `%TEMP%\Yeager_bin` directory. It is never loaded from;
/// it is only probed for best-effort cleanup.
pub fn legacy_temp_dir() -> PathBuf {
    std::env::temp_dir().join(LEGACY_TEMP_SUBDIR)
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Returns true when `dest` exists and its SHA-256 matches `embedded`.
/// Missing or unreadable files count as not current, so they get (re)written.
pub fn file_is_current(dest: &Path, embedded: &[u8]) -> bool {
    match std::fs::read(dest) {
        Ok(on_disk) => sha256_of(&on_disk) == sha256_of(embedded),
        Err(_) => false,
    }
}

/// Writes `embedded` to `dest` unless the on-disk content already matches by
/// SHA-256. Returns `Ok(true)` when bytes were written, `Ok(false)` when the
/// file was already in sync (no write, so a concurrently loaded DLL is never
/// disturbed). A post-write re-read guards against torn writes: if the hash
/// still does not match, the error fails the start closed instead of loading
/// an unverified file.
pub fn sync_embedded_file(dest: &Path, embedded: &[u8]) -> Result<bool, String> {
    if file_is_current(dest, embedded) {
        return Ok(false);
    }
    std::fs::write(dest, embedded)
        .map_err(|e| format!("Failed writing {}: {}", dest.display(), e))?;
    if !file_is_current(dest, embedded) {
        return Err(format!(
            "Failed verifying {} after write: on-disk hash does not match the embedded driver; refusing to load",
            dest.display()
        ));
    }
    Ok(true)
}

/// Outcome of the legacy temp-directory cleanup (best-effort, never fatal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyCleanup {
    /// Nothing there (or already gone).
    Gone,
    /// Removed the known files and the now-empty directory.
    Removed,
    /// Directory is a reparse point: skipped without traversing or deleting.
    SkippedReparse,
    /// Directory attributes are unreadable: skipped without traversing or
    /// deleting (fail-closed — an unreadable reparse point must not be
    /// treated as an ordinary directory).
    SkippedUnreadable,
    /// Best-effort removal failed partway; start proceeds anyway.
    Partial,
}

/// Removes the legacy `%TEMP%\Yeager_bin` directory — safely:
///
/// - If the directory itself is a reparse point (junction/symlink planted by
///   an attacker), it is NOT traversed and nothing under it is touched.
/// - Otherwise only the two known files are deleted by name
///   (`WinDivert.dll`, `WinDivert64.sys`), then `RemoveDirectory` on the
///   (now empty) directory.
/// - No recursive deletion anywhere: an Admin recursive delete through a
///   planted junction would be arbitrary file deletion.
///
/// Best-effort and logged, never fatal: failures only produce a log line.
pub fn cleanup_legacy_temp_dir() {
    match cleanup_legacy_temp_dir_at(&std::env::temp_dir()) {
        LegacyCleanup::Gone => {}
        LegacyCleanup::Removed => {
            eprintln!(
                "[*] Removed legacy driver directory {}",
                legacy_temp_dir().display()
            );
        }
        LegacyCleanup::SkippedReparse => {
            eprintln!(
                "[!] Legacy driver directory {} is a reparse point; left alone (not traversed)",
                legacy_temp_dir().display()
            );
        }
        LegacyCleanup::SkippedUnreadable => {
            eprintln!(
                "[!] Legacy driver directory {} attributes unreadable; left alone (not traversed)",
                legacy_temp_dir().display()
            );
        }
        LegacyCleanup::Partial => {
            eprintln!(
                "[!] Legacy driver directory {} could not be fully removed; left alone",
                legacy_temp_dir().display()
            );
        }
    }
}

fn cleanup_legacy_temp_dir_at(temp_root: &Path) -> LegacyCleanup {
    let dir = temp_root.join(LEGACY_TEMP_SUBDIR);
    if !dir.exists() {
        return LegacyCleanup::Gone;
    }
    match is_reparse_point(&dir) {
        // Unreadable attributes fail closed: an unreadable reparse point is
        // indistinguishable from an ordinary directory to a fail-open check,
        // so the cleanup is skipped instead of proceeding into `remove_file`.
        None => return LegacyCleanup::SkippedUnreadable,
        Some(true) => return LegacyCleanup::SkippedReparse,
        Some(false) => {}
    }
    // Delete only the two known files by name. Errors are tolerated: a file
    // may be absent, or locked by a still-running old build.
    for name in [WINDIVERT_DLL_NAME, WINDIVERT_SYS_NAME] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    match std::fs::remove_dir(&dir) {
        Ok(()) => LegacyCleanup::Removed,
        Err(_) => {
            // Gone meanwhile, or non-empty (foreign files we must not touch).
            if !dir.exists() {
                LegacyCleanup::Removed
            } else {
                LegacyCleanup::Partial
            }
        }
    }
}

/// Returns `Some(true)` when `path` itself is a reparse point
/// (junction/symlink), `Some(false)` for an ordinary directory, and `None`
/// when the attributes cannot be read. `None` must be treated as "do not
/// touch": an unreadable reparse point is exactly what a fail-open check
/// would mistake for an ordinary directory.
#[cfg(windows)]
fn is_reparse_point(path: &Path) -> Option<bool> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return None;
    }
    Some((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
}

#[cfg(not(windows))]
fn is_reparse_point(path: &Path) -> Option<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => Some(m.file_type().is_symlink()),
        Err(_) => None,
    }
}

/// Creates the protected driver directory (parent `%ProgramData%\Yeager` and
/// leaf `%ProgramData%\Yeager\driver`) and enforces the admin-only DACL.
/// Fails closed on any error; never falls back to a user-writable location.
///
/// A pre-existing directory is NOT "repaired": it is verified as-is, and any
/// mismatch (wrong owner, unprotected DACL, medium-IL-writable ACEs from any
/// source) fails the start with a clear error.
pub fn ensure_admin_only_dir(dir: &Path) -> Result<(), String> {
    let parent = dir
        .parent()
        .ok_or_else(|| format!("Driver directory {} has no parent", dir.display()))?;
    ensure_one_protected_dir(parent)?;
    ensure_one_protected_dir(dir)?;
    Ok(())
}

/// Verifies that `dir` is a properly protected driver directory:
///
/// - the security descriptor carries a DACL, and the DACL is protected
///   (`SE_DACL_PROTECTED`: no inherited ACEs are in force);
/// - the owner is Administrators or SYSTEM;
/// - no ALLOW ACE grants write/create rights to anyone but Administrators
///   and SYSTEM (covers Users, Everyone, Authenticated Users, CREATOR OWNER…,
///   whether inherited or explicit).
///
/// Any mismatch fails closed with a specific error.
#[cfg(windows)]
pub fn verify_protected_dir(dir: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };
    use windows_sys::core::PCWSTR;

    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr() as PCWSTR,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!(
            "Refusing to use driver directory {}: cannot read its security descriptor (code {}). \
             As an administrator, remove the directory and restart Yeager so it is recreated protected.",
            dir.display(),
            rc
        ));
    }
    struct Guard(*mut std::ffi::c_void);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _sd_guard = Guard(sd);

    if dacl.is_null() {
        return Err(format!(
            "Refusing to use driver directory {}: it has no DACL (null DACL grants everyone full control). \
             As an administrator, remove the directory and restart Yeager so it is recreated protected.",
            dir.display()
        ));
    }
    let dacl_ref: &windows_sys::Win32::Security::ACL = unsafe { &*dacl };

    // 1. Protected flag: no inherited ACEs may be in force.
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    let ok = unsafe {
        windows_sys::Win32::Security::GetSecurityDescriptorControl(sd, &mut control, &mut revision)
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "Refusing to use driver directory {}: cannot read DACL control flags (code {})",
            dir.display(),
            code
        ));
    }
    if (control & SE_DACL_PROTECTED) == 0 {
        return Err(format!(
            "Refusing to use driver directory {}: its DACL is not protected (inheritance is ON, \
             so medium-integrity-writable ACEs from the parent are in force). \
             As an administrator, remove the directory and restart Yeager so it is recreated protected.",
            dir.display()
        ));
    }

    // 2. Owner must be Administrators or SYSTEM.
    if !sid_is_trusted_owner(owner) {
        return Err(format!(
            "Refusing to use driver directory {}: unexpected owner {} (not Administrators or SYSTEM); \
             it may have been pre-created by a lower-privilege user. \
             As an administrator, remove the directory and restart Yeager so it is recreated protected.",
            dir.display(),
            describe_owner_sid(owner)
        ));
    }

    // 3. No ALLOW ACE may grant write/create to anyone but Admin/SYSTEM.
    check_no_foreign_write_aces(dir, dacl_ref)
}

#[cfg(not(windows))]
pub fn verify_protected_dir(dir: &Path) -> Result<(), String> {
    Err(format!(
        "Protected driver directory {} requires Windows security APIs",
        dir.display()
    ))
}

/// Names the SID actually found on a directory for the owner-mismatch error:
/// `DOMAIN\name` when the account resolves, else the `S-1-...` string form,
/// else a placeholder. Never fails — diagnosis must not become a new refusal.
#[cfg(windows)]
fn describe_owner_sid(sid: *mut std::ffi::c_void) -> String {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::LookupAccountSidW;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    if sid.is_null() {
        return "none".to_string();
    }
    unsafe {
        // Account name, two-call sizing first.
        let mut name_len: u32 = 0;
        let mut domain_len: u32 = 0;
        let mut use_kind: i32 = 0;
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut use_kind,
        );
        if name_len > 0 && domain_len > 0 {
            let mut name = vec![0u16; name_len as usize];
            let mut domain = vec![0u16; domain_len as usize];
            if LookupAccountSidW(
                std::ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut use_kind,
            ) != 0
            {
                let trim_nul = |v: &[u16]| {
                    let n = v.iter().position(|&c| c == 0).unwrap_or(v.len());
                    String::from_utf16_lossy(&v[..n])
                };
                return format!("{}\\{}", trim_nul(&domain), trim_nul(&name));
            }
        }
        // Fallback: the SID string form.
        let mut text: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut text) != 0 && !text.is_null() {
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text as *mut std::ffi::c_void);
            return s;
        }
        "unresolvable SID".to_string()
    }
}

/// True when `sid` is Administrators or SYSTEM — the only acceptable owners
/// (or full-control holders) of the protected driver directory.
#[cfg(windows)]
fn sid_is_trusted_owner(sid: *mut std::ffi::c_void) -> bool {
    if sid.is_null() {
        return false;
    }
    fn well_known(kind: i32) -> Vec<u8> {
        use windows_sys::Win32::Security::{CreateWellKnownSid, SECURITY_MAX_SID_SIZE};
        let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = buf.len() as u32;
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut size,
            )
        };
        if ok == 0 {
            Vec::new()
        } else {
            buf.truncate(size as usize);
            buf
        }
    }
    use windows_sys::Win32::Security::{EqualSid, WinBuiltinAdministratorsSid, WinLocalSystemSid};
    for kind in [WinBuiltinAdministratorsSid, WinLocalSystemSid] {
        let known = well_known(kind);
        if !known.is_empty()
            && unsafe { EqualSid(sid, known.as_ptr() as *mut std::ffi::c_void) } != 0
        {
            return true;
        }
    }
    false
}

/// Access-mask bits that let a medium-IL holder plant or replace driver
/// files: generic write/all, delete, DACL/owner takeover, and file/dir
/// creation attributes.
#[cfg(windows)]
const FOREIGN_WRITE_BITS: u32 = 0x4000_0000 // GENERIC_WRITE
    | 0x1000_0000 // GENERIC_ALL
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100; // FILE_WRITE_ATTRIBUTES

/// ACE types carrying (Mask, SidStart) at the same offsets, inspected below.
#[cfg(windows)]
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
#[cfg(windows)]
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;

/// Scans every ACE: an ALLOW ACE granting any [`FOREIGN_WRITE_BITS`] to a SID
/// other than Administrators/SYSTEM fails closed — whether the ACE is
/// inherited or explicit, and whether it names Users, Everyone, Authenticated
/// Users, CREATOR OWNER, or anything else.
#[cfg(windows)]
fn check_no_foreign_write_aces(
    dir: &Path,
    dacl: &windows_sys::Win32::Security::ACL,
) -> Result<(), String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, CreateWellKnownSid, EqualSid, GetAce, SECURITY_MAX_SID_SIZE,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

    fn well_known_sid(kind: i32) -> Vec<u8> {
        let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = buf.len() as u32;
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut size,
            )
        };
        if ok == 0 {
            Vec::new()
        } else {
            buf.truncate(size as usize);
            buf
        }
    }
    let admin = well_known_sid(WinBuiltinAdministratorsSid);
    let system = well_known_sid(WinLocalSystemSid);
    let is_privileged = |sid: *mut std::ffi::c_void| -> bool {
        (!admin.is_empty()
            && unsafe { EqualSid(sid, admin.as_ptr() as *mut std::ffi::c_void) } != 0)
            || (!system.is_empty()
                && unsafe { EqualSid(sid, system.as_ptr() as *mut std::ffi::c_void) } != 0)
    };

    for index in 0..dacl.AceCount {
        let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let ok = unsafe { GetAce(dacl as *const _ as *mut _, index as u32, &mut ace_ptr) };
        if ok == 0 || ace_ptr.is_null() {
            let code = unsafe { GetLastError() };
            return Err(format!(
                "Refusing to use driver directory {}: cannot read ACE {} (code {})",
                dir.display(),
                index,
                code
            ));
        }
        let ace: &ACCESS_ALLOWED_ACE = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
            && ace.Header.AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        {
            continue; // DENY/audit ACEs only restrict; they grant nothing.
        }
        let sid = (&ace.SidStart as *const u32) as *mut std::ffi::c_void;
        if is_privileged(sid) {
            continue;
        }
        if (ace.Mask & FOREIGN_WRITE_BITS) != 0 {
            return Err(format!(
                "Refusing to use driver directory {}: an ACE grants write/create rights (mask {:#x}) \
                 to a SID other than Administrators/SYSTEM (ACE {}); a medium-integrity user could plant driver files. \
                 As an administrator, remove the directory and restart Yeager so it is recreated protected.",
                dir.display(),
                ace.Mask,
                index
            ));
        }
    }
    Ok(())
}

/// Ensures a single directory exists with the protected admin-only DACL.
/// A pre-existing directory is verified as-is and fails closed on mismatch
/// (never silently repaired: repair would turn "exists, therefore use" into
/// "exists, therefore trust").
#[cfg(windows)]
fn ensure_one_protected_dir(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        SECURITY_MAX_SID_SIZE, WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::core::PWSTR;

    fn well_known_sid(kind: i32, buf: &mut [u8]) -> Result<(), String> {
        let mut size = buf.len() as u32;
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut size,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(format!(
                "CreateWellKnownSid({}) failed (code {})",
                kind, code
            ));
        }
        Ok(())
    }

    fn trustee_for(sid: &mut [u8]) -> TRUSTEE_W {
        TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.as_mut_ptr() as PWSTR,
        }
    }

    let mut admin_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut system_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut users_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    well_known_sid(WinBuiltinAdministratorsSid, &mut admin_sid)?;
    well_known_sid(WinLocalSystemSid, &mut system_sid)?;
    well_known_sid(WinBuiltinUsersSid, &mut users_sid)?;

    // Administrators + SYSTEM: full control. Users: read + execute (traverse).
    // ACEs inherit to the driver files written into the directory afterwards.
    // Note: Users — not Everyone — so the grant is exactly the documented set.
    let inheritance = windows_sys::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    let entries = [
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: {
                use windows_sys::Win32::Foundation::GENERIC_ALL;
                GENERIC_ALL
            },
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee_for(&mut admin_sid),
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: {
                use windows_sys::Win32::Foundation::GENERIC_ALL;
                GENERIC_ALL
            },
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee_for(&mut system_sid),
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: {
                use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ};
                GENERIC_READ | GENERIC_EXECUTE
            },
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee_for(&mut users_sid),
        },
    ];

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let rc = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            std::ptr::null(),
            &mut new_acl,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("SetEntriesInAclW failed (code {})", rc));
    }
    if new_acl.is_null() {
        return Err("SetEntriesInAclW returned a null DACL".to_string());
    }
    struct AclGuard(*mut ACL);
    impl Drop for AclGuard {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0 as *mut std::ffi::c_void);
            }
        }
    }
    let _acl_guard = AclGuard(new_acl);

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Create with SECURITY_ATTRIBUTES carrying the protected DACL and an
    // explicit Administrators owner, so the directory is never momentarily
    // left to inherited permissions or the token's default owner. The
    // descriptor only needs to outlive the creation call.
    let created = {
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        let sd = build_protected_security_descriptor(
            new_acl,
            admin_sid.as_mut_ptr() as *mut std::ffi::c_void,
        )?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr() as *mut std::ffi::c_void,
            bInheritHandle: 0,
        };
        let ok = unsafe { CreateDirectoryW(wide.as_ptr(), &sa) };
        if ok != 0 {
            true
        } else {
            let code = unsafe { GetLastError() };
            const ERROR_ALREADY_EXISTS: u32 = 183;
            if code == ERROR_ALREADY_EXISTS {
                false
            } else {
                return Err(format!(
                    "Failed creating protected driver directory {} (code {})",
                    path.display(),
                    code
                ));
            }
        }
    };

    if created {
        // Stamp explicitly as well: the creation path must not be the only
        // thing standing between the files and inherited ACEs.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_acl,
                std::ptr::null(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(format!(
                "SetNamedSecurityInfoW failed for {} (code {}); refusing to use an unprotected directory",
                path.display(),
                rc
            ));
        }
    }

    // Verify the effective state — for a pre-existing directory this is the
    // fail-closed gate; for a fresh one it proves the creation worked.
    verify_protected_dir(path)
}

/// Builds a self-relative SECURITY_DESCRIPTOR holding `acl` as its DACL,
/// marked `SE_DACL_PROTECTED`, with the owner set EXPLICITLY to
/// `owner_sid` (Administrators) — never the creating token's default owner,
/// which is the user SID rather than Administrators on some account classes
/// (notably the built-in Administrator, RID 500). For use in
/// SECURITY_ATTRIBUTES at creation. Returned as bytes that only need to
/// outlive the creation call.
#[cfg(windows)]
fn build_protected_security_descriptor(
    acl: *mut windows_sys::Win32::Security::ACL,
    owner_sid: *mut std::ffi::c_void,
) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, MakeSelfRelativeSD, SE_DACL_PROTECTED,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    };
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    // Absolute SD on the stack, then converted to self-relative for the SA.
    let mut absolute = [0u8; 256];
    let ok = unsafe {
        InitializeSecurityDescriptor(
            absolute.as_mut_ptr() as *mut std::ffi::c_void,
            SECURITY_DESCRIPTOR_REVISION,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "InitializeSecurityDescriptor failed (code {})",
            code
        ));
    }
    let ok = unsafe {
        SetSecurityDescriptorDacl(absolute.as_mut_ptr() as *mut std::ffi::c_void, 1, acl, 0)
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!("SetSecurityDescriptorDacl failed (code {})", code));
    }
    // Explicit owner, NOT defaulted: creation must not depend on the token's
    // default owner (bOwnerDefaulted = FALSE).
    let ok = unsafe {
        SetSecurityDescriptorOwner(
            absolute.as_mut_ptr() as *mut std::ffi::c_void,
            owner_sid,
            0,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!("SetSecurityDescriptorOwner failed (code {})", code));
    }
    let ok = unsafe {
        SetSecurityDescriptorControl(
            absolute.as_mut_ptr() as *mut std::ffi::c_void,
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "SetSecurityDescriptorControl failed (code {})",
            code
        ));
    }
    // Convert to self-relative: query size, allocate, convert.
    let mut needed: u32 = 0;
    unsafe {
        MakeSelfRelativeSD(
            absolute.as_mut_ptr() as *mut std::ffi::c_void,
            std::ptr::null_mut(),
            &mut needed,
        );
        let code = GetLastError();
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
        if code != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(format!(
                "MakeSelfRelativeSD sizing failed (code {}, needed {})",
                code, needed
            ));
        }
        let mut relative = vec![0u8; needed as usize];
        let ok = MakeSelfRelativeSD(
            absolute.as_mut_ptr() as *mut std::ffi::c_void,
            relative.as_mut_ptr() as *mut std::ffi::c_void,
            &mut needed,
        );
        if ok == 0 {
            let code = GetLastError();
            return Err(format!("MakeSelfRelativeSD failed (code {})", code));
        }
        Ok(relative)
    }
}

#[cfg(not(windows))]
fn ensure_one_protected_dir(dir: &Path) -> Result<(), String> {
    Err(format!(
        "Protected driver directory {} requires Windows security APIs",
        dir.display()
    ))
}

/// Name of the kernel service the vendored WinDivert installer manages. An
/// existing record is started as-is by the DLL (no reconfiguration), so a
/// record left by a pre-fix crash still points at the old temp `.sys`.
pub const WINDIVERT_SERVICE_NAME: &str = "WinDivert";

/// Normalizes a service binary path for comparison with the verified `.sys`.
///
/// Kernel ImagePath forms vary in the wild; handled here:
/// - surrounding double quotes (and any trailing arguments past the path);
/// - NT object-manager prefixes `\??\` and `\\?\`;
/// - `%SystemRoot%` (any ASCII case) expanded from the live environment
///   (fallback `C:\Windows`), and a leading `\SystemRoot\` mapped the same way;
/// - forward slashes, and ASCII case (Windows paths compare insensitively).
pub fn normalize_service_binary_path(raw: &str) -> String {
    // Service binary paths take no arguments, but defensively take only the
    // path token: the quoted span, or the first whitespace-delimited token.
    let token = {
        let s = raw.trim();
        if let Some(rest) = s.strip_prefix('"') {
            match rest.find('"') {
                Some(end) => rest[..end].to_string(),
                None => rest.to_string(),
            }
        } else {
            s.split_whitespace().next().unwrap_or("").to_string()
        }
    };
    let mut s = token;
    for prefix in [r"\\?\", r"\??\"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
            break;
        }
    }
    let system_root = std::env::var_os("SystemRoot")
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_else(|| "C:\\Windows".to_string());
    s = replace_ascii_case_insensitive(&s, "%SystemRoot%", &system_root);
    let sysroot_prefix = r"\SystemRoot\";
    if s.len() >= sysroot_prefix.len()
        && s[..sysroot_prefix.len()].eq_ignore_ascii_case(sysroot_prefix)
    {
        s = format!("{}{}", system_root, &s[sysroot_prefix.len() - 1..]);
    }
    s.replace('/', "\\").to_lowercase()
}

/// ASCII case-insensitive substring replacement on bytes (safe: the ASCII
/// needle can never match inside a multi-byte UTF-8 sequence).
fn replace_ascii_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(hb.len());
    let mut i = 0;
    while i + nb.len() <= hb.len() {
        if hb[i..i + nb.len()].eq_ignore_ascii_case(nb) {
            out.extend_from_slice(replacement.as_bytes());
            i += nb.len();
        } else {
            out.push(hb[i]);
            i += 1;
        }
    }
    out.extend_from_slice(&hb[i..]);
    String::from_utf8(out).unwrap_or_else(|_| haystack.to_string())
}

/// True when the recorded service binary path resolves to exactly
/// `expected_sys` (the `.sys` next to the DLL about to be loaded).
fn service_paths_match(recorded: &str, expected_sys: &Path) -> bool {
    normalize_service_binary_path(recorded)
        == normalize_service_binary_path(&expected_sys.to_string_lossy())
}

/// What the SCM seam observed for one service record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceRecord {
    /// No record: the DLL creates one from the loaded DLL's directory.
    Absent,
    /// The record is marked for deletion (`OpenServiceW` failed with
    /// `ERROR_SERVICE_MARKED_FOR_DELETE`). This is the product's own
    /// in-use record: the vendored DLL calls `DeleteService` right after a
    /// successful start, while the driver stays loaded until reboot. A
    /// delete-pending service cannot be started, so it can never load a
    /// planted `.sys`; the DLL opens the already-loaded device directly.
    /// Non-blocking: restarts proceed against it.
    DeletePending,
    /// A record exists. `running` is true unless the service is confirmed
    /// STOPPED — any other state (running, pending, unknown) is fail-closed.
    Present {
        binary_path: String,
        running: bool,
    },
}

/// SCM read/delete operations behind a seam so the stale-record decision is
/// unit-testable with faked records (absent / delete-pending / matching /
/// foreign-stopped / foreign-running / query-error).
pub trait ServiceControl {
    /// Reads the service record: `Absent`, `DeletePending`, or `Present`
    /// with its binary path and whether it is anything but STOPPED. Any
    /// other failure is `Err`.
    fn query(&self, service_name: &str) -> Result<ServiceRecord, String>;
    /// Deletes a STOPPED record; the DLL recreates it from the correct
    /// directory on the next install.
    fn delete(&self, service_name: &str) -> Result<(), String>;
}

/// Rejects a stale `WinDivert` service record before the DLL load step.
///
/// - No record → proceed (the DLL creates it from the loaded DLL's directory).
/// - Delete-pending record → proceed (a delete-pending service cannot be
///   started, so it cannot load a planted `.sys`; the DLL opens the
///   already-loaded device directly, as pre-guard builds did).
/// - Record resolves to exactly `expected_sys` → proceed.
/// - Record points anywhere else: if the service is STOPPED, delete the
///   record and proceed; if it is RUNNING (or its state/deletion fails),
///   fail closed naming the recorded path. The engine never starts against a
///   foreign record.
pub fn ensure_service_record(
    scm: &impl ServiceControl,
    service_name: &str,
    expected_sys: &Path,
) -> Result<(), String> {
    let record = scm.query(service_name).map_err(|e| {
        format!(
            "Refusing to start the engine: the {service_name} service record cannot be read ({e}); \
             a stale record could load a planted driver as SYSTEM. \
             Inspect the record with `sc.exe qc {service_name}` and remove it, then restart."
        )
    })?;
    match record {
        ServiceRecord::Absent => Ok(()),
        ServiceRecord::DeletePending => Ok(()),
        ServiceRecord::Present {
            binary_path,
            running,
        } => {
            if service_paths_match(&binary_path, expected_sys) {
                return Ok(());
            }
            if running {
                return Err(format!(
                    "Refusing to start the engine: the {service_name} service record points at \
                     {binary_path} instead of the verified driver at {}; the old driver is still \
                     running from that path. Stop it (or reboot so it stays stopped), remove the \
                     stale record, then restart — the engine never starts against a foreign record.",
                    expected_sys.display()
                ));
            }
            scm.delete(service_name).map_err(|e| {
                format!(
                    "Refusing to start the engine: the {service_name} service record points at \
                     {binary_path} instead of the verified driver at {}, and the stale record \
                     could not be deleted ({e}). Remove it as an administrator, then restart.",
                    expected_sys.display()
                )
            })?;
            Ok(())
        }
    }
}

/// The live SCM implementation (Windows only).
#[cfg(windows)]
pub struct WindowsServiceControl;

/// RAII guard closing an SCM / service handle on drop.
#[cfg(windows)]
struct ScmHandleGuard(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for ScmHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::System::Services::CloseServiceHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
impl ServiceControl for WindowsServiceControl {
    fn query(&self, service_name: &str) -> Result<ServiceRecord, String> {
        use windows_sys::Win32::Foundation::{
            GetLastError, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE,
        };
        use windows_sys::Win32::System::Services::{
            OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatus,
            SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
            QUERY_SERVICE_CONFIGW, SERVICE_STATUS, SERVICE_STOPPED,
        };
        use windows_sys::Win32::Storage::FileSystem::DELETE;

        let name: Vec<u16> = service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            let code = unsafe { GetLastError() };
            return Err(format!("OpenSCManagerW failed (code {code})"));
        }
        let _manager_guard = ScmHandleGuard(manager);
        // QUERY for config/state plus DELETE so a stopped stale record can be
        // removed in the same decision.
        let service = unsafe {
            OpenServiceW(
                manager,
                name.as_ptr(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | DELETE,
            )
        };
        if service.is_null() {
            let code = unsafe { GetLastError() };
            if code == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(ServiceRecord::Absent);
            }
            if code == ERROR_SERVICE_MARKED_FOR_DELETE {
                // The product's own in-use record: the vendored DLL marks
                // the service delete-pending right after a successful start
                // while the driver stays loaded until reboot. A
                // delete-pending service cannot be started, so it can never
                // load a planted `.sys` — proceed and let the DLL open the
                // already-loaded device directly.
                return Ok(ServiceRecord::DeletePending);
            }
            return Err(format!("OpenServiceW({service_name}) failed (code {code})"));
        }
        let _service_guard = ScmHandleGuard(service);
        // Config: two-call sizing, then read the binary path.
        let mut needed: u32 = 0;
        unsafe {
            QueryServiceConfigW(service, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            let code = unsafe { GetLastError() };
            return Err(format!(
                "QueryServiceConfigW({service_name}) sizing failed (code {code})"
            ));
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            QueryServiceConfigW(
                service,
                buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(format!(
                "QueryServiceConfigW({service_name}) failed (code {code})"
            ));
        }
        let binary_path = unsafe {
            let cfg = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
            pwstr_to_string(cfg.lpBinaryPathName)
        };
        // State: anything but confirmed STOPPED counts as running (fail-closed).
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        let ok = unsafe { QueryServiceStatus(service, &mut status) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(state_undetermined_error(service_name, &binary_path, code));
        }
        Ok(ServiceRecord::Present {
            binary_path,
            running: status.dwCurrentState != SERVICE_STOPPED,
        })
    }

    fn delete(&self, service_name: &str) -> Result<(), String> {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::Storage::FileSystem::DELETE;
        use windows_sys::Win32::System::Services::{
            DeleteService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
        };

        let name: Vec<u16> = service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            let code = unsafe { GetLastError() };
            return Err(format!("OpenSCManagerW failed (code {code})"));
        }
        let _manager_guard = ScmHandleGuard(manager);
        let service = unsafe { OpenServiceW(manager, name.as_ptr(), DELETE) };
        if service.is_null() {
            let code = unsafe { GetLastError() };
            return Err(format!("OpenServiceW({service_name}) failed (code {code})"));
        }
        let _service_guard = ScmHandleGuard(service);
        let ok = unsafe { DeleteService(service) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(format!("DeleteService({service_name}) failed (code {code})"));
        }
        Ok(())
    }
}

/// The state-undetermined refusal: like every other refusal, it names the
/// recorded binary path so the operator can see which record blocked the
/// start. Factored out so the committed suite can assert the path is named.
#[cfg(windows)]
fn state_undetermined_error(service_name: &str, binary_path: &str, code: u32) -> String {
    format!(
        "QueryServiceStatus({service_name}) failed (code {code}) for the record pointing at \
         {binary_path}; the record state cannot be determined, so the engine never starts against it"
    )
}

/// Reads a NUL-terminated UTF-16 Windows string (empty when null).
#[cfg(windows)]
fn pwstr_to_string(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// Fails closed off-Windows: the SCM check requires Windows service APIs.
#[cfg(not(windows))]
pub fn ensure_windivert_service_record(expected_sys: &Path) -> Result<(), String> {
    Err(format!(
        "WinDivert service record check for {} requires Windows service APIs",
        expected_sys.display()
    ))
}

/// The production stale-record check on the `WinDivert` service (Windows).
/// See [`ensure_service_record`] for the decision table.
#[cfg(windows)]
pub fn ensure_windivert_service_record(expected_sys: &Path) -> Result<(), String> {
    ensure_service_record(
        &WindowsServiceControl,
        WINDIVERT_SERVICE_NAME,
        expected_sys,
    )
}

/// Extracts (or SHA-256 re-verifies) the embedded driver files into the
/// protected directory and returns the path of the DLL to load.
///
/// `driver_dir_override` carries the `--driver-dir` CLI flag: when present,
/// that directory is used as-is (the user's deliberate LGPL-substitution
/// act, logged with one line) and no protected-store work happens.
pub fn ensure_driver_extracted(dll_bytes: &[u8], sys_bytes: &[u8]) -> Result<PathBuf, String> {
    ensure_driver_extracted_with_override(dll_bytes, sys_bytes, None)
}

pub fn ensure_driver_extracted_with_override(
    dll_bytes: &[u8],
    sys_bytes: &[u8],
    driver_dir_override: Option<&Path>,
) -> Result<PathBuf, String> {
    // The legacy temp dir is never loaded from; sweep it best-effort first.
    cleanup_legacy_temp_dir();

    if let Some(dir) = driver_dir_override {
        eprintln!("[*] --driver-dir override active: using {}", dir.display());
        return Ok(dir.join(WINDIVERT_DLL_NAME));
    }
    let dir = get_driver_dir()?;
    ensure_admin_only_dir(&dir)?;
    sync_embedded_file(&dir.join(WINDIVERT_DLL_NAME), dll_bytes)?;
    sync_embedded_file(&dir.join(WINDIVERT_SYS_NAME), sys_bytes)?;
    Ok(dir.join(WINDIVERT_DLL_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn unique_dir(tag: &str) -> PathBuf {
        let n = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "yeager-p0driver-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        std::fs::create_dir_all(&dir).expect("test dir must be creatable");
        dir
    }

    /// Removes a scratch test directory without any recursive delete: named
    /// entries first (junctions/symlinks removed as links, never followed),
    /// then `remove_dir` bottom-up. Mirrors the production discipline — this
    /// package never calls `remove_dir_all`, not even in test teardown.
    fn remove_test_tree(path: &Path) {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                let is_real_dir = std::fs::symlink_metadata(&p)
                    .map(|m| m.file_type().is_dir())
                    .unwrap_or(false);
                if is_real_dir {
                    remove_test_tree(&p);
                } else if std::fs::remove_file(&p).is_err() {
                    // Junctions and other reparse points: remove the link
                    // itself (never the target) as a directory.
                    let _ = std::fs::remove_dir(&p);
                }
            }
        }
        let _ = std::fs::remove_dir(path);
    }

    #[test]
    fn driver_dir_is_programdata_yeager_driver() {
        let selected = driver_dir_for(OsStr::new("C:\\ProgramData"));
        assert_eq!(selected, PathBuf::from("C:\\ProgramData\\Yeager\\driver"));
    }

    #[test]
    fn selected_dir_matches_programdata_layout() {
        // No env mutation: the live selection must equal the pure function
        // applied to the real %ProgramData% root.
        let root =
            std::env::var_os("ProgramData").expect("ProgramData must be set on Windows test hosts");
        assert_eq!(
            get_driver_dir().expect("get_driver_dir must succeed"),
            driver_dir_for(&root)
        );
    }

    #[test]
    fn driver_dir_flag_parses_space_and_equals_forms() {
        let argv = vec![
            "levi.exe".to_string(),
            "--driver-dir".to_string(),
            "C:\\Drivers\\WinDivert".to_string(),
        ];
        assert_eq!(
            parse_driver_dir_arg(&argv).unwrap(),
            Some(PathBuf::from("C:\\Drivers\\WinDivert"))
        );
        let argv = vec!["yeager.exe".to_string(), "--driver-dir=C:\\Alt".to_string()];
        assert_eq!(
            parse_driver_dir_arg(&argv).unwrap(),
            Some(PathBuf::from("C:\\Alt"))
        );
        let argv = vec!["levi.exe".to_string(), "--all".to_string()];
        assert_eq!(parse_driver_dir_arg(&argv).unwrap(), None);
    }

    #[test]
    fn driver_dir_flag_rejects_missing_or_empty_value() {
        let argv = vec!["levi.exe".to_string(), "--driver-dir".to_string()];
        assert!(parse_driver_dir_arg(&argv).is_err());
        let argv = vec!["levi.exe".to_string(), "--driver-dir=".to_string()];
        assert!(parse_driver_dir_arg(&argv).is_err());
    }

    #[test]
    fn driver_dir_flag_last_occurrence_wins() {
        let argv = vec![
            "levi.exe".to_string(),
            "--driver-dir".to_string(),
            "C:\\First".to_string(),
            "--driver-dir=C:\\Second".to_string(),
        ];
        assert_eq!(
            parse_driver_dir_arg(&argv).unwrap(),
            Some(PathBuf::from("C:\\Second"))
        );
    }

    #[test]
    fn config_file_cannot_carry_a_driver_dir_override() {
        // Config has no driver-dir field: a hostile config.json entry is
        // ignored by serde instead of redirecting the driver load.
        let cfg: common::Config =
            serde_json::from_str(r#"{"driver_dir": "C:\\evil", "scope": "all"}"#)
                .expect("unknown fields must be ignored");
        let debug = format!("{:?}", cfg);
        assert!(
            !debug.contains("evil"),
            "Config must not retain a driver_dir value"
        );
        assert_eq!(cfg.scope, common::Scope::All);
    }

    #[test]
    fn environment_cannot_carry_a_driver_dir_override() {
        // There is deliberately no env override: setting the rev.2 variable
        // must not change where the driver is resolved.
        unsafe {
            std::env::set_var("YEAGER_WINDIVERT_PATH", "C:\\evil\\WinDivert.dll");
        }
        let dir = get_driver_dir().expect("default must not consult the environment");
        assert!(!dir.to_string_lossy().contains("evil"));
        unsafe {
            std::env::remove_var("YEAGER_WINDIVERT_PATH");
        }
    }

    #[test]
    fn missing_file_is_written() {
        let dir = unique_dir("missing");
        let dest = dir.join("WinDivert.dll");
        let embedded = b"fake-driver-bytes-v1";
        assert!(!dest.exists());
        assert_eq!(
            sync_embedded_file(&dest, embedded).expect("write must succeed"),
            true
        );
        assert_eq!(std::fs::read(&dest).unwrap(), embedded);
        remove_test_tree(&dir);
    }

    #[test]
    fn mismatched_file_is_rewritten() {
        let dir = unique_dir("mismatch");
        let dest = dir.join("WinDivert.dll");
        // Pre-planted hostile content must not survive.
        std::fs::write(&dest, b"hostile-planted-bytes").unwrap();
        let embedded = b"fake-driver-bytes-v1";
        assert!(!file_is_current(&dest, embedded));
        assert_eq!(
            sync_embedded_file(&dest, embedded).expect("rewrite must succeed"),
            true
        );
        assert_eq!(std::fs::read(&dest).unwrap(), embedded);
        remove_test_tree(&dir);
    }

    #[test]
    fn matching_file_is_left_alone() {
        let dir = unique_dir("match");
        let dest = dir.join("WinDivert64.sys");
        let embedded = b"fake-sys-bytes-v1";
        std::fs::write(&dest, embedded).unwrap();
        assert!(file_is_current(&dest, embedded));
        let before = std::fs::metadata(&dest).unwrap().modified().unwrap();
        assert_eq!(
            sync_embedded_file(&dest, embedded).expect("check must succeed"),
            false,
            "hash match must not rewrite"
        );
        // No rewrite means content and mtime are untouched (concurrent case).
        assert_eq!(std::fs::read(&dest).unwrap(), embedded);
        assert_eq!(
            std::fs::metadata(&dest).unwrap().modified().unwrap(),
            before
        );
        remove_test_tree(&dir);
    }

    #[test]
    fn legacy_cleanup_removes_only_the_known_files() {
        let root = unique_dir("legacy");
        let legacy = root.join(LEGACY_TEMP_SUBDIR);
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join(WINDIVERT_DLL_NAME), b"old").unwrap();
        std::fs::write(legacy.join(WINDIVERT_SYS_NAME), b"old").unwrap();
        // A foreign file must survive: no recursive deletion, and the dir is
        // therefore left in place.
        std::fs::write(legacy.join("notes.txt"), b"keep me").unwrap();
        let outcome = cleanup_legacy_temp_dir_at(&root);
        assert_eq!(outcome, LegacyCleanup::Partial);
        assert!(!legacy.join(WINDIVERT_DLL_NAME).exists());
        assert!(!legacy.join(WINDIVERT_SYS_NAME).exists());
        assert!(legacy.join("notes.txt").exists());
        remove_test_tree(&root);
    }

    #[test]
    fn legacy_cleanup_removes_empty_dir() {
        let root = unique_dir("legacy-empty");
        let legacy = root.join(LEGACY_TEMP_SUBDIR);
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join(WINDIVERT_DLL_NAME), b"old").unwrap();
        std::fs::write(legacy.join(WINDIVERT_SYS_NAME), b"old").unwrap();
        assert_eq!(cleanup_legacy_temp_dir_at(&root), LegacyCleanup::Removed);
        assert!(!legacy.exists());
        remove_test_tree(&root);
    }

    #[test]
    fn legacy_cleanup_is_gone_when_absent() {
        let root = unique_dir("legacy-gone");
        assert_eq!(cleanup_legacy_temp_dir_at(&root), LegacyCleanup::Gone);
        remove_test_tree(&root);
    }

    /// Fake SCM for the stale-record decision table: canned query result,
    /// canned delete result, and a log of services it was asked to delete.
    struct FakeScm {
        record: Result<ServiceRecord, String>,
        delete_result: Result<(), String>,
        deleted: std::cell::RefCell<Vec<String>>,
    }

    impl FakeScm {
        fn present(binary_path: &str, running: bool) -> Self {
            Self {
                record: Ok(ServiceRecord::Present {
                    binary_path: binary_path.to_string(),
                    running,
                }),
                delete_result: Ok(()),
                deleted: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl ServiceControl for FakeScm {
        fn query(&self, _service_name: &str) -> Result<ServiceRecord, String> {
            self.record.clone()
        }
        fn delete(&self, service_name: &str) -> Result<(), String> {
            self.deleted.borrow_mut().push(service_name.to_string());
            self.delete_result.clone()
        }
    }

    #[test]
    fn stale_record_absent_proceeds() {
        let scm = FakeScm {
            record: Ok(ServiceRecord::Absent),
            delete_result: Ok(()),
            deleted: std::cell::RefCell::new(Vec::new()),
        };
        let expected = Path::new("C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys");
        assert!(ensure_service_record(&scm, "WinDivert", expected).is_ok());
        assert!(scm.deleted.borrow().is_empty(), "absent record must not delete");
    }

    #[test]
    fn stale_record_matching_path_proceeds() {
        // Exact, quoted, NT-prefixed and differently-cased records of the
        // verified .sys all proceed without touching the record.
        let expected = Path::new("C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys");
        for recorded in [
            "C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys",
            "\"C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys\"",
            "\\??\\C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys",
            "c:\\programdata\\yeager\\driver\\windivert64.sys",
        ] {
            let scm = FakeScm::present(recorded, false);
            assert!(
                ensure_service_record(&scm, "WinDivert", expected).is_ok(),
                "matching record must proceed: {recorded}"
            );
            assert!(
                scm.deleted.borrow().is_empty(),
                "matching record must not delete: {recorded}"
            );
        }
    }

    #[test]
    fn stale_record_foreign_stopped_is_deleted_and_proceeds() {
        let foreign = "C:\\Users\\victim\\AppData\\Local\\Temp\\Yeager_bin\\WinDivert64.sys";
        let scm = FakeScm::present(foreign, false);
        let expected = Path::new("C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys");
        assert!(
            ensure_service_record(&scm, "WinDivert", expected).is_ok(),
            "foreign stopped record must be deleted and proceed"
        );
        assert_eq!(
            scm.deleted.borrow().as_slice(),
            ["WinDivert"],
            "foreign stopped record must be deleted exactly once"
        );
    }

    #[test]
    fn stale_record_delete_pending_proceeds() {
        // The product's own in-use record: the vendored DLL marks the
        // service delete-pending right after a successful start while the
        // driver stays loaded until reboot. It cannot be started, so it can
        // never load a planted `.sys` — restarts must proceed without
        // touching the record.
        let scm = FakeScm {
            record: Ok(ServiceRecord::DeletePending),
            delete_result: Ok(()),
            deleted: std::cell::RefCell::new(Vec::new()),
        };
        let expected = Path::new("C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys");
        assert!(
            ensure_service_record(&scm, "WinDivert", expected).is_ok(),
            "delete-pending record must proceed (restart after first start)"
        );
        assert!(
            scm.deleted.borrow().is_empty(),
            "delete-pending record must never be deleted"
        );
    }

    #[cfg(windows)]
    #[test]
    fn state_undetermined_refusal_names_recorded_path() {
        let err = state_undetermined_error(
            "WinDivert",
            "\\??\\C:\\Temp\\Yeager_bin\\WinDivert64.sys",
            1723,
        );
        assert!(
            err.contains("Yeager_bin\\WinDivert64.sys"),
            "state-undetermined refusal must name the recorded path, got: {err}"
        );
    }

    #[test]
    fn stale_record_foreign_running_refuses_without_delete() {
        let foreign = "\\??\\C:\\Users\\victim\\AppData\\Local\\Temp\\Yeager_bin\\WinDivert64.sys";
        let scm = FakeScm::present(foreign, true);
        let expected = Path::new("C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys");
        let err = ensure_service_record(&scm, "WinDivert", expected)
            .expect_err("foreign running record must fail closed");
        assert!(
            err.contains("Yeager_bin\\WinDivert64.sys"),
            "refusal must name the recorded path, got: {err}"
        );
        assert!(
            scm.deleted.borrow().is_empty(),
            "running record must never be deleted"
        );
    }

    #[test]
    fn stale_record_query_error_refuses() {
        let scm = FakeScm {
            record: Err("OpenServiceW failed (code 5)".to_string()),
            delete_result: Ok(()),
            deleted: std::cell::RefCell::new(Vec::new()),
        };
        let expected = Path::new("C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys");
        let err = ensure_service_record(&scm, "WinDivert", expected)
            .expect_err("unreadable record must fail closed");
        assert!(
            err.contains("cannot be read"),
            "refusal must say the record cannot be read, got: {err}"
        );
        assert!(
            scm.deleted.borrow().is_empty(),
            "unreadable record must not delete"
        );
    }

    #[test]
    fn stale_record_delete_failure_refuses() {
        let foreign = "C:\\Temp\\Yeager_bin\\WinDivert64.sys";
        let mut scm = FakeScm::present(foreign, false);
        scm.delete_result = Err("DeleteService failed (code 5)".to_string());
        let expected = Path::new("C:\\ProgramData\\Yeager\\driver\\WinDivert64.sys");
        let err = ensure_service_record(&scm, "WinDivert", expected)
            .expect_err("undeletable foreign record must fail closed");
        assert!(
            err.contains("could not be deleted"),
            "refusal must say the record could not be deleted, got: {err}"
        );
    }

    #[test]
    fn service_binary_path_normalization_handles_kernel_forms() {
        assert_eq!(
            normalize_service_binary_path("\"C:\\A\\B\\WinDivert64.sys\""),
            "c:\\a\\b\\windivert64.sys"
        );
        assert_eq!(
            normalize_service_binary_path("\\??\\C:\\A\\B\\WinDivert64.sys"),
            "c:\\a\\b\\windivert64.sys"
        );
        assert_eq!(
            normalize_service_binary_path("C:/A/B/WinDivert64.sys"),
            "c:\\a\\b\\windivert64.sys"
        );
        // %SystemRoot% expands from the live environment on the test host.
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let expanded = normalize_service_binary_path("%SystemRoot%\\System32\\drivers\\x.sys");
        assert_eq!(
            expanded,
            format!("{}\\system32\\drivers\\x.sys", sysroot.replace('/', "\\").to_lowercase())
        );
        assert_eq!(
            normalize_service_binary_path("\\SystemRoot\\System32\\drivers\\x.sys"),
            format!("{}\\system32\\drivers\\x.sys", sysroot.replace('/', "\\").to_lowercase())
        );
    }

    #[cfg(windows)]
    #[test]
    fn unprotected_dir_fails_verification() {
        // A fresh temp dir inherits medium-IL-writable ACEs and is not
        // protected: verification must fail closed.
        let dir = unique_dir("unprotected");
        let err = verify_protected_dir(&dir).expect_err("inherited DACL must fail");
        assert!(
            err.contains("not protected") || err.contains("write/create"),
            "unexpected error: {err}"
        );
        remove_test_tree(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn explicit_users_write_grant_fails_verification() {
        // The gate's hostile pre-existing dir, reduced to its essence: owner
        // correct, DACL protected, but an explicit ALLOW ACE still grants
        // Users a write/create right. Must fail closed (never repaired).
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::Security::Authorization::{
            EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW,
            SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
        };
        use windows_sys::Win32::Security::{
            ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_MAX_SID_SIZE,
            WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinLocalSystemSid,
        };
        use windows_sys::core::PWSTR;

        let root = unique_dir("explicit-write");
        let dir = root.join("Yeager");
        std::fs::create_dir_all(&dir).unwrap();

        let mut admin_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut system_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut users_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        for (kind, buf) in [
            (WinBuiltinAdministratorsSid, &mut admin_sid),
            (WinLocalSystemSid, &mut system_sid),
            (WinBuiltinUsersSid, &mut users_sid),
        ] {
            let mut size = buf.len() as u32;
            assert_ne!(
                unsafe {
                    CreateWellKnownSid(
                        kind,
                        std::ptr::null_mut(),
                        buf.as_mut_ptr() as *mut std::ffi::c_void,
                        &mut size,
                    )
                },
                0
            );
        }
        let trustee = |sid: &mut [u8]| TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.as_mut_ptr() as PWSTR,
        };
        let inheritance = windows_sys::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        let entries = [
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: windows_sys::Win32::Foundation::GENERIC_ALL,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: inheritance,
                Trustee: trustee(&mut admin_sid),
            },
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: windows_sys::Win32::Foundation::GENERIC_ALL,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: inheritance,
                Trustee: trustee(&mut system_sid),
            },
            // The hostile grant: Users may create files here.
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: 0x0000_0002, // FILE_WRITE_DATA / FILE_ADD_FILE
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: inheritance,
                Trustee: trustee(&mut users_sid),
            },
        ];
        let mut acl: *mut ACL = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                SetEntriesInAclW(
                    entries.len() as u32,
                    entries.as_ptr(),
                    std::ptr::null(),
                    &mut acl,
                )
            },
            ERROR_SUCCESS
        );
        let wide: Vec<u16> = dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null(),
                )
            },
            ERROR_SUCCESS
        );
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(acl as *mut std::ffi::c_void);
        }

        let err = verify_protected_dir(&dir).expect_err("Users-write grant must fail");
        assert!(
            err.contains("write/create"),
            "must fail on the hostile ACE, got: {err}"
        );
        remove_test_tree(&root);
    }

    /// Enables a process privilege (e.g. `SeRestorePrivilege`) that is
    /// present but disabled by default in elevated test runs, so the test
    /// can assign an arbitrary directory owner.
    #[cfg(windows)]
    fn enable_privilege(name: windows_sys::core::PCWSTR) -> Result<(), String> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            ) == 0
            {
                return Err(format!("OpenProcessToken failed (code {})", GetLastError()));
            }
            struct HandleGuard(*mut std::ffi::c_void);
            impl Drop for HandleGuard {
                fn drop(&mut self) {
                    unsafe {
                        CloseHandle(self.0);
                    }
                }
            }
            let _guard = HandleGuard(token);
            let mut luid = std::mem::zeroed::<windows_sys::Win32::Foundation::LUID>();
            if LookupPrivilegeValueW(std::ptr::null(), name, &mut luid) == 0 {
                return Err(format!(
                    "LookupPrivilegeValueW failed (code {})",
                    GetLastError()
                ));
            }
            let state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            if AdjustTokenPrivileges(
                token,
                0,
                &state,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(format!(
                    "AdjustTokenPrivileges failed (code {})",
                    GetLastError()
                ));
            }
            if GetLastError() != 0 {
                return Err(format!(
                    "privilege not held by the test process (code {})",
                    GetLastError()
                ));
            }
            Ok(())
        }
    }

    #[cfg(windows)]
    #[test]
    fn wrong_owner_fails_verification() {
        // A pre-existing directory whose owner is neither Administrators nor
        // SYSTEM must fail closed with the owner error — even when the DACL
        // is otherwise properly protected (protected flag set, no foreign
        // write ACEs), so this reaches the owner gate that
        // `unprotected_dir_fails_verification` never gets to (it trips the
        // protected-flag gate first).
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::Security::Authorization::{
            EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
            SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
            TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
        };
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_MAX_SID_SIZE, SE_RESTORE_NAME,
            WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinLocalSystemSid,
        };
        use windows_sys::core::PWSTR;

        let root = unique_dir("wrong-owner");
        let dir = root.join("Yeager");
        std::fs::create_dir_all(&dir).unwrap();

        // Protected DACL with the correct shape: Admin + SYSTEM full
        // control, Users read + execute only, inheritance OFF.
        let mut admin_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut system_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut users_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        for (kind, buf) in [
            (WinBuiltinAdministratorsSid, &mut admin_sid),
            (WinLocalSystemSid, &mut system_sid),
            (WinBuiltinUsersSid, &mut users_sid),
        ] {
            let mut size = buf.len() as u32;
            assert_ne!(
                unsafe {
                    CreateWellKnownSid(
                        kind,
                        std::ptr::null_mut(),
                        buf.as_mut_ptr() as *mut std::ffi::c_void,
                        &mut size,
                    )
                },
                0
            );
        }
        let trustee = |sid: &mut [u8]| TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.as_mut_ptr() as PWSTR,
        };
        let inheritance = windows_sys::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        let entries = [
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: windows_sys::Win32::Foundation::GENERIC_ALL,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: inheritance,
                Trustee: trustee(&mut admin_sid),
            },
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: windows_sys::Win32::Foundation::GENERIC_ALL,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: inheritance,
                Trustee: trustee(&mut system_sid),
            },
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: {
                    use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ};
                    GENERIC_READ | GENERIC_EXECUTE
                },
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: inheritance,
                Trustee: trustee(&mut users_sid),
            },
        ];
        let mut acl: *mut ACL = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                SetEntriesInAclW(
                    entries.len() as u32,
                    entries.as_ptr(),
                    std::ptr::null(),
                    &mut acl,
                )
            },
            ERROR_SUCCESS
        );
        let wide: Vec<u16> = dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null(),
                )
            },
            ERROR_SUCCESS
        );
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(acl as *mut std::ffi::c_void);
        }

        // Re-own the directory to Users (neither Administrators nor SYSTEM).
        // Needs SeRestorePrivilege: present but disabled by default in the
        // elevated test runs this suite requires.
        enable_privilege(SE_RESTORE_NAME).expect("test process must hold SeRestorePrivilege");
        let rc = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                users_sid.as_mut_ptr() as *mut std::ffi::c_void,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(
            rc, ERROR_SUCCESS,
            "re-owning the scratch dir to Users must succeed"
        );

        let err = verify_protected_dir(&dir).expect_err("non-admin owner must fail closed");
        assert!(
            err.contains("unexpected owner"),
            "must fail on the owner gate, got: {err}"
        );
        remove_test_tree(&root);
    }

    #[cfg(windows)]
    #[test]
    fn legacy_cleanup_skips_reparse_point_and_keeps_canary() {
        // The legacy dir as a junction (reparse point) with a canary file at
        // the target: cleanup must report `SkippedReparse` and the canary
        // must survive untouched — nothing through the link may be deleted.
        let root = unique_dir("legacy-reparse");
        let target = root.join("real-target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("canary.txt"), b"do not touch").unwrap();
        let legacy = root.join(LEGACY_TEMP_SUBDIR);
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &legacy.to_string_lossy().into_owned(),
                &target.to_string_lossy().into_owned(),
            ])
            .status()
            .expect("mklink must spawn");
        assert!(status.success(), "mklink /J must succeed");
        assert!(
            is_reparse_point(&legacy).unwrap_or(false),
            "legacy dir must read back as a reparse point"
        );

        let outcome = cleanup_legacy_temp_dir_at(&root);
        assert_eq!(outcome, LegacyCleanup::SkippedReparse);

        // The link itself is still there and the target is untouched.
        assert!(
            std::fs::symlink_metadata(&legacy)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false),
            "the junction itself must not have been removed"
        );
        assert_eq!(
            std::fs::read(target.join("canary.txt")).unwrap(),
            b"do not touch",
            "canary behind the junction must survive"
        );

        // Teardown removes the junction itself (never the target), then the
        // named files and directories — no recursive delete.
        std::fs::remove_dir(&legacy).expect("junction removal must succeed");
        remove_test_tree(&root);
    }

    #[cfg(windows)]
    #[test]
    fn protected_dir_passes_verification() {
        // Directories created by the enforcement path verify cleanly.
        let root = unique_dir("protected-root");
        let leaf = root.join("Yeager").join("driver");
        ensure_admin_only_dir(&leaf).expect("admin setup must succeed");
        verify_protected_dir(&root.join("Yeager")).expect("parent must verify");
        verify_protected_dir(&leaf).expect("leaf must verify");
        remove_test_tree(&root);
    }

    #[cfg(windows)]
    #[test]
    fn created_dir_owner_is_administrators() {
        // Creation must not depend on the creating token's default owner:
        // a directory built by the production helper reads back owned by
        // BUILTIN\Administrators and passes verification.
        use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
        use windows_sys::Win32::Security::Authorization::{
            GetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, EqualSid, OWNER_SECURITY_INFORMATION,
            SECURITY_MAX_SID_SIZE, WinBuiltinAdministratorsSid,
        };
        use windows_sys::core::PCWSTR;

        let root = unique_dir("created-owner");
        let leaf = root.join("Yeager").join("driver");
        ensure_admin_only_dir(&leaf).expect("admin setup must succeed");

        let wide: Vec<u16> = leaf
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr() as PCWSTR,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS, "owner read-back must succeed");
        struct Guard(*mut std::ffi::c_void);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _guard = Guard(sd);
        assert!(!owner.is_null(), "created directory must have an owner");
        let mut admin = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = admin.len() as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinBuiltinAdministratorsSid,
                    std::ptr::null_mut(),
                    admin.as_mut_ptr() as *mut std::ffi::c_void,
                    &mut size,
                )
            },
            0,
            "Administrators SID must be constructible"
        );
        assert_ne!(
            unsafe { EqualSid(owner, admin.as_ptr() as *mut std::ffi::c_void) },
            0,
            "created directory owner must be BUILTIN\\Administrators, not the token default"
        );
        verify_protected_dir(&leaf).expect("created directory must verify");
        remove_test_tree(&root);
    }

    #[cfg(windows)]
    #[test]
    fn matching_hash_survives_a_locked_file() {
        // Models the concurrent case: a second binary holds the DLL loaded
        // (reads allowed, writes denied). A hash match must skip the write
        // and proceed instead of failing.
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, OPEN_EXISTING,
        };

        let dir = unique_dir("locked-match");
        let dest = dir.join("WinDivert.dll");
        let embedded = b"fake-driver-locked-v1";
        std::fs::write(&dest, embedded).unwrap();
        let wide: Vec<u16> = dest
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE, "lock handle must open");
        let res = sync_embedded_file(&dest, embedded);
        unsafe {
            CloseHandle(handle);
        }
        assert_eq!(
            res.expect("matching hash must not touch the locked file"),
            false
        );
        remove_test_tree(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn mismatched_hash_with_locked_file_fails_closed() {
        // A locked file with the wrong hash means another build is already
        // running: the write must fail and the start must stop, never load.
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, OPEN_EXISTING,
        };

        let dir = unique_dir("locked-mismatch");
        let dest = dir.join("WinDivert.dll");
        std::fs::write(&dest, b"other-build-bytes").unwrap();
        let wide: Vec<u16> = dest
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE, "lock handle must open");
        let res = sync_embedded_file(&dest, b"fake-driver-v2");
        unsafe {
            CloseHandle(handle);
        }
        assert!(
            res.is_err(),
            "locked mismatch must fail closed, got {res:?}"
        );
        remove_test_tree(&dir);
    }

    #[test]
    fn extraction_step_stays_fast() {
        // Pathology guard for the hash-first extraction step: write, rewrite
        // and skip-write of both files must complete promptly even in debug
        // builds. The owner yardstick (< 0.1 s on the real ~140 KB driver
        // files) is measured in release mode during the gate run, where the
        // `real_extraction_step` lib test prints its elapsed time.
        let dir = unique_dir("timing");
        let dll = dir.join(WINDIVERT_DLL_NAME);
        let sys = dir.join(WINDIVERT_SYS_NAME);
        let embedded = vec![0xABu8; 64 * 1024];
        let t0 = std::time::Instant::now();
        sync_embedded_file(&dll, &embedded).unwrap();
        sync_embedded_file(&sys, &embedded).unwrap();
        sync_embedded_file(&dll, &embedded).unwrap();
        sync_embedded_file(&sys, &embedded).unwrap();
        let elapsed = t0.elapsed();
        eprintln!("extraction step (fake 64 KiB files, debug): {elapsed:?}");
        assert!(
            elapsed.as_secs() < 2,
            "extraction step took {elapsed:?}, expected < 2 s even in debug"
        );
        remove_test_tree(&dir);
    }
}

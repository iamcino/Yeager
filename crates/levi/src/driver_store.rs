//! Protected on-disk store for the embedded WinDivert driver files.
//!
//! Layout: `%ProgramData%\Yeager\driver`, created with a DACL that grants
//! write access only to Administrators and SYSTEM (read + execute for
//! everyone), enforced through Windows security APIs on every engine start.
//!
//! Integrity: before every load, each on-disk file's SHA-256 is compared with
//! the embedded bytes' SHA-256; on mismatch (or absence) the embedded bytes
//! are (over)written. A pre-planted file therefore never survives until load.
//!
//! Failure mode is fail-closed: if the directory cannot be created or its ACL
//! cannot be enforced, startup returns an error. There is no fallback to a
//! user-writable location.
//!
//! LGPLv3 replaceability: setting `YEAGER_WINDIVERT_PATH` to a full
//! `WinDivert.dll` path uses that build as-is (the user's knowing choice) and
//! skips the protected store.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Environment variable holding a full path to a user-supplied `WinDivert.dll`.
pub const WINDIVERT_OVERRIDE_ENV: &str = "YEAGER_WINDIVERT_PATH";

/// File names of the embedded driver binaries.
pub const WINDIVERT_DLL_NAME: &str = "WinDivert.dll";
pub const WINDIVERT_SYS_NAME: &str = "WinDivert64.sys";

/// Builds the protected driver directory under a given ProgramData root.
/// Pure function so the directory selection is unit-testable.
pub fn driver_dir_for(program_data: &OsStr) -> PathBuf {
    let mut dir = PathBuf::from(program_data);
    dir.push("Yeager");
    dir.push("driver");
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

/// Interprets the raw `YEAGER_WINDIVERT_PATH` value: a non-empty value is a
/// full path to a user-supplied `WinDivert.dll` and takes precedence over the
/// protected store. Pure function for testability; the real value is read by
/// [`ensure_driver_extracted`].
pub fn resolve_override(var: Option<OsString>) -> Option<PathBuf> {
    match var {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Returns true when `dest` exists and its SHA-256 matches `embedded`.
/// Missing or unreadable files count as not current, so they get (re)written.
pub fn file_is_current(dest: &Path, embedded: &[u8]) -> bool {
    match std::fs::read(dest) {
        Ok(on_disk) => sha256_hex(&on_disk) == sha256_hex(embedded),
        Err(_) => false,
    }
}

/// Writes `embedded` to `dest` unless the on-disk content already matches by
/// SHA-256. Returns `Ok(true)` when bytes were written, `Ok(false)` when the
/// file was already in sync.
pub fn sync_embedded_file(dest: &Path, embedded: &[u8]) -> Result<bool, String> {
    if file_is_current(dest, embedded) {
        return Ok(false);
    }
    std::fs::write(dest, embedded)
        .map_err(|e| format!("Failed writing {}: {}", dest.display(), e))?;
    Ok(true)
}

/// Creates the protected driver directory and enforces its admin-only DACL.
/// Fails closed on any error; never falls back to a user-writable location.
pub fn ensure_admin_only_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Failed creating protected driver directory {}: {}", dir.display(), e))?;
    enforce_admin_only_dacl(dir)
}

/// Extracts (or re-verifies) the embedded driver files and returns the path of
/// the DLL to load. Honors the `YEAGER_WINDIVERT_PATH` override first.
pub fn ensure_driver_extracted(dll_bytes: &[u8], sys_bytes: &[u8]) -> Result<PathBuf, String> {
    if let Some(path) = resolve_override(std::env::var_os(WINDIVERT_OVERRIDE_ENV)) {
        eprintln!(
            "[*] YEAGER_WINDIVERT_PATH override active: using {}",
            path.display()
        );
        return Ok(path);
    }
    let dir = get_driver_dir()?;
    ensure_admin_only_dir(&dir)?;
    sync_embedded_file(&dir.join(WINDIVERT_DLL_NAME), dll_bytes)?;
    sync_embedded_file(&dir.join(WINDIVERT_SYS_NAME), sys_bytes)?;
    Ok(dir.join(WINDIVERT_DLL_NAME))
}

#[cfg(windows)]
fn enforce_admin_only_dacl(dir: &Path) -> Result<(), String> {
    use windows_sys::core::PWSTR;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_SUCCESS, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ};
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
        NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, WinWorldSid, ACL, SECURITY_MAX_SID_SIZE,
    };

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
            return Err(format!("CreateWellKnownSid({}) failed (code {})", kind, code));
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
    let mut world_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    well_known_sid(WinBuiltinAdministratorsSid, &mut admin_sid)?;
    well_known_sid(WinLocalSystemSid, &mut system_sid)?;
    well_known_sid(WinWorldSid, &mut world_sid)?;

    // Administrators + SYSTEM: full control. Everyone: read + execute (traverse).
    // ACEs inherit to the driver files written into the directory afterwards.
    let inheritance = windows_sys::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    let entries = [
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee_for(&mut admin_sid),
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee_for(&mut system_sid),
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_READ | GENERIC_EXECUTE,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee_for(&mut world_sid),
        },
    ];

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let rc = unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_ptr(), std::ptr::null(), &mut new_acl) };
    if rc != ERROR_SUCCESS {
        return Err(format!("SetEntriesInAclW failed (code {})", rc));
    }
    if new_acl.is_null() {
        return Err("SetEntriesInAclW returned a null DACL".to_string());
    }

    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
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
    unsafe {
        LocalFree(new_acl as *mut std::ffi::c_void);
    }
    if rc != ERROR_SUCCESS {
        return Err(format!(
            "SetNamedSecurityInfoW failed for {} (code {}); refusing to use an unprotected directory",
            dir.display(),
            rc
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn enforce_admin_only_dacl(dir: &Path) -> Result<(), String> {
    Err(format!(
        "Protected driver directory {} requires Windows security APIs",
        dir.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn unique_dir(tag: &str) -> PathBuf {
        let n = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!("yeager-p0driver-{}-{}-{}", std::process::id(), tag, n));
        std::fs::create_dir_all(&dir).expect("test dir must be creatable");
        dir
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
        let root = std::env::var_os("ProgramData").expect("ProgramData must be set on Windows test hosts");
        assert_eq!(get_driver_dir().expect("get_driver_dir must succeed"), driver_dir_for(&root));
    }

    #[test]
    fn override_path_takes_precedence() {
        let custom = OsString::from("C:\\custom\\WinDivert.dll");
        assert_eq!(resolve_override(Some(custom.clone())), Some(PathBuf::from(&custom)));
        assert_eq!(resolve_override(None), None);
        assert_eq!(resolve_override(Some(OsString::new())), None);
    }

    #[test]
    fn missing_file_is_written() {
        let dir = unique_dir("missing");
        let dest = dir.join("WinDivert.dll");
        let embedded = b"fake-driver-bytes-v1";
        assert!(!dest.exists());
        assert_eq!(sync_embedded_file(&dest, embedded).expect("write must succeed"), true);
        assert_eq!(std::fs::read(&dest).unwrap(), embedded);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mismatched_file_is_rewritten() {
        let dir = unique_dir("mismatch");
        let dest = dir.join("WinDivert.dll");
        // Pre-planted hostile content must not survive.
        std::fs::write(&dest, b"hostile-planted-bytes").unwrap();
        let embedded = b"fake-driver-bytes-v1";
        assert!(!file_is_current(&dest, embedded));
        assert_eq!(sync_embedded_file(&dest, embedded).expect("rewrite must succeed"), true);
        assert_eq!(std::fs::read(&dest).unwrap(), embedded);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn matching_file_is_left_alone() {
        let dir = unique_dir("match");
        let dest = dir.join("WinDivert64.sys");
        let embedded = b"fake-sys-bytes-v1";
        std::fs::write(&dest, embedded).unwrap();
        assert!(file_is_current(&dest, embedded));
        assert_eq!(
            sync_embedded_file(&dest, embedded).expect("check must succeed"),
            false,
            "hash match must not rewrite"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), embedded);
        std::fs::remove_dir_all(&dir).ok();
    }
}

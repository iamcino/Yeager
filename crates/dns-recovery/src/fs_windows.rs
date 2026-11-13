//! Real Windows filesystem and machine-lock implementation (U02). Implements
//! the same [`JournalFs`]/[`MachineLock`] contracts as the fakes: CREATE_NEW
//! with a restricted non-inheritable ACL, write-through stage writes, checked
//! reads (reparse/hardlink/security/size), ReplaceFileW with raw error codes,
//! same-volume MoveFileExW(WRITE_THROUGH), and volume flush via the raw volume
//! device. Requires elevation (SeRestore/SeBackup/SeTakeOwnership/SeSecurity).

#![cfg(windows)]

use crate::fs::{join, FsError, JournalFs, StorageKind};
use crate::journal::{BACKUP_PREFIX, MAX_JOURNAL_BYTES, PRIMARY_FILE, STAGE_PREFIX};
use crate::lock::{Acquired, LockError, LockGuard, MachineLock, LOCK_NAME};
use crate::security::{
    validate_journal_security, ObjectKind, SecurityInfo, DIR_SDDL, FILE_SDDL, MUTEX_SDDL,
};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::Duration;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_DISK_FULL,
    ERROR_FILE_NOT_FOUND, ERROR_HANDLE_DISK_FULL, ERROR_INVALID_FUNCTION, ERROR_NOT_ALL_ASSIGNED,
    ERROR_NOT_SUPPORTED, ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_ABANDONED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_BACKUP_NAME,
    SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SE_SECURITY_NAME, SE_TAKE_OWNERSHIP_NAME,
    SECURITY_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FindClose, FindFirstFileW, FindNextFileW,
    FlushFileBuffers, GetDriveTypeW, GetFileAttributesW, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, GetVolumeInformationW, GetVolumePathNameW, MoveFileExW, ReadFile,
    ReplaceFileW, WriteFile, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL,
    SYNCHRONIZE, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Threading::{
    CreateMutexExW, GetCurrentProcess, OpenEventW, OpenMutexW, OpenProcessToken, OpenSemaphoreW,
    ReleaseMutex, WaitForSingleObject, MUTEX_ALL_ACCESS,
};
use windows_sys::Win32::System::WindowsProgramming::{DRIVE_REMOTE};
use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramData};

// ---- helpers ---------------------------------------------------------------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn io_err(context: &str) -> FsError {
    FsError::Io { code: last_error(), context: context.to_string() }
}

fn map_common_error(context: &str) -> FsError {
    match last_error() {
        ERROR_ACCESS_DENIED => FsError::AccessDenied,
        ERROR_SHARING_VIOLATION => FsError::SharingViolation,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => FsError::NotFound,
        ERROR_DISK_FULL | ERROR_HANDLE_DISK_FULL => FsError::DiskFull,
        ERROR_ALREADY_EXISTS => FsError::AlreadyExists,
        _ => io_err(context),
    }
}

fn sa_of(sd: &crate::security::win::Sddl) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.ptr,
        bInheritHandle: 0,
    }
}

fn volume_path_of(path: &str) -> Result<String, FsError> {
    let w = wide(path);
    let mut buf = vec![0u16; 1024];
    if unsafe { GetVolumePathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } == 0 {
        return Err(io_err("GetVolumePathNameW"));
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(String::from_utf16_lossy(&buf[..len]))
}

/// GetFinalPathNameByHandleW returns the `\\?\`-prefixed form, so a volume path
/// derived from it (`\\?\C:\`) must be normalized before comparing against one
/// derived from a plain DOS path (`C:\`).
fn normalize_volume(v: &str) -> String {
    if let Some(rest) = v.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = v.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        v.to_string()
    }
}

fn final_path_of(h: HANDLE) -> Result<String, FsError> {
    let mut buf = vec![0u16; 512];
    loop {
        let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, 0) };
        if n == 0 {
            return Err(io_err("GetFinalPathNameByHandleW"));
        }
        if (n as usize) < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n as usize]));
        }
        buf.resize(n as usize + 1, 0);
    }
}

/// Enable the privileges needed to set owner SYSTEM and read/write protected
/// security. Fails closed when not elevated (ERROR_NOT_ALL_ASSIGNED).
pub fn enable_privileges() -> Result<(), FsError> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return Err(io_err("OpenProcessToken"));
        }
        let result = (|| {
            for name in [SE_RESTORE_NAME, SE_BACKUP_NAME, SE_TAKE_OWNERSHIP_NAME, SE_SECURITY_NAME] {
                let mut luid = std::mem::zeroed();
                if LookupPrivilegeValueW(std::ptr::null(), name, &mut luid) == 0 {
                    return Err(io_err("LookupPrivilegeValueW"));
                }
                let tp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
                };
                if AdjustTokenPrivileges(
                    token,
                    0,
                    &tp,
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ) == 0
                {
                    return Err(io_err("AdjustTokenPrivileges"));
                }
                if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
                    return Err(FsError::AccessDenied);
                }
            }
            Ok(())
        })();
        CloseHandle(token);
        result
    }
}

/// FOLDERID_ProgramData from the shell (never a hardcoded path).
pub fn program_data_dir() -> Result<String, FsError> {
    unsafe {
        let mut p: PWSTR = std::ptr::null_mut();
        let hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut p);
        if hr != 0 || p.is_null() {
            return Err(FsError::InvalidPath(format!("SHGetKnownFolderPath(ProgramData) failed: {hr:#x}")));
        }
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        CoTaskMemFree(p as *const core::ffi::c_void);
        Ok(s)
    }
}

/// Journal directory: `<ProgramData>\Yeager`.
pub fn journal_dir() -> Result<String, FsError> {
    Ok(join(&program_data_dir()?, "Yeager"))
}

// ---- WindowsFs --------------------------------------------------------------

struct OpenFile {
    handle: HANDLE,
}

/// Real NTFS filesystem backend. Handles are process-local ids; every handle
/// is closed exactly once via [`JournalFs::close`].
pub struct WindowsFs {
    handles: RefCell<HashMap<u64, OpenFile>>,
    next_handle: Cell<u64>,
}

impl WindowsFs {
    pub fn new() -> Result<Self, FsError> {
        enable_privileges()?;
        Ok(Self { handles: RefCell::new(HashMap::new()), next_handle: Cell::new(1) })
    }

    fn handle_of(&self, h: u64) -> Result<HANDLE, FsError> {
        self.handles.borrow().get(&h).map(|f| f.handle).ok_or(FsError::NotFound)
    }
}

impl JournalFs for WindowsFs {
    fn ensure_directory(&self, dir: &str) -> Result<(), FsError> {
        let w = wide(dir);
        let attrs = unsafe { GetFileAttributesW(w.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            let sddl = crate::security::win::Sddl::parse(DIR_SDDL)?;
            let sa = sa_of(&sddl);
            if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
                let e = map_common_error("CreateDirectoryW");
                if !matches!(e, FsError::AlreadyExists) {
                    return Err(e);
                }
            }
        } else {
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(FsError::ReparsePoint);
            }
            if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(FsError::InvalidPath(format!("{dir:?} is not a directory")));
            }
        }
        // Existing directories are validated, never silently repaired.
        let sec = crate::security::win::read_named_security(dir)?;
        validate_journal_security(&sec, ObjectKind::Directory)
            .map_err(|e| FsError::BadSecurity(format!("directory {dir:?}: {}", e.0)))
    }

    fn directory_security(&self, dir: &str) -> Result<SecurityInfo, FsError> {
        Ok(crate::security::win::read_named_security(dir)?)
    }

    fn storage_kind(&self, dir: &str) -> Result<StorageKind, FsError> {
        let w = wide(dir);
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(map_common_error("open directory"));
        }
        let result = (|| {
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
                return Err(io_err("GetFileInformationByHandle(dir)"));
            }
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(FsError::ReparsePoint);
            }
            let final_path = final_path_of(h)?;
            let vol_dir = normalize_volume(&volume_path_of(dir)?);
            let vol_final = normalize_volume(&volume_path_of(&final_path)?);
            if !vol_dir.eq_ignore_ascii_case(&vol_final) {
                return Err(FsError::InvalidPath(format!(
                    "{dir:?} resolves to a different volume ({final_path:?})"
                )));
            }
            let root = wide(&vol_dir);
            if unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_REMOTE {
                return Ok(StorageKind::Network);
            }
            let mut fsname = [0u16; 64];
            if unsafe {
                GetVolumeInformationW(
                    root.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    fsname.as_mut_ptr(),
                    fsname.len() as u32,
                )
            } == 0
            {
                return Err(io_err("GetVolumeInformationW"));
            }
            let len = fsname.iter().position(|&c| c == 0).unwrap_or(fsname.len());
            let name = String::from_utf16_lossy(&fsname[..len]);
            if name.eq_ignore_ascii_case("NTFS") {
                Ok(StorageKind::LocalNtfs)
            } else {
                Ok(StorageKind::NonNtfs)
            }
        })();
        unsafe { CloseHandle(h) };
        result
    }

    fn list_candidates(&self, dir: &str) -> Result<Vec<String>, FsError> {
        let pattern = wide(&format!("{dir}\\*"));
        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let h = unsafe { FindFirstFileW(pattern.as_ptr(), &mut data) };
        if h == INVALID_HANDLE_VALUE {
            return match last_error() {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(Vec::new()),
                _ => Err(io_err("FindFirstFileW")),
            };
        }
        let mut out = Vec::new();
        let mut error = None;
        loop {
            let len = data.cFileName.iter().position(|&c| c == 0).unwrap_or(data.cFileName.len());
            let name = String::from_utf16_lossy(&data.cFileName[..len]);
            if data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                && (name == PRIMARY_FILE || name.starts_with(STAGE_PREFIX) || name.starts_with(BACKUP_PREFIX))
            {
                out.push(join(dir, &name));
            }
            if unsafe { FindNextFileW(h, &mut data) } == 0 {
                let e = last_error();
                if e != ERROR_NO_MORE_FILES {
                    error = Some(FsError::Io { code: e, context: "FindNextFileW".into() });
                }
                break;
            }
        }
        unsafe { FindClose(h) };
        if let Some(e) = error {
            return Err(e);
        }
        out.sort();
        Ok(out)
    }

    fn create_new(&self, path: &str) -> Result<u64, FsError> {
        let sddl = crate::security::win::Sddl::parse(FILE_SDDL)?;
        let sa = sa_of(&sddl);
        let w = wide(path);
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_WRITE,
                0,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(map_common_error("CreateFileW(CREATE_NEW)"));
        }
        let sec = match crate::security::win::read_named_security(path) {
            Ok(s) => s,
            Err(e) => {
                unsafe { CloseHandle(h); DeleteFileW(w.as_ptr()) };
                return Err(e.into());
            }
        };
        if let Err(e) = validate_journal_security(&sec, ObjectKind::File) {
            unsafe { CloseHandle(h); DeleteFileW(w.as_ptr()) };
            return Err(FsError::BadSecurity(format!("new stage {path:?}: {}", e.0)));
        }
        let id = self.next_handle.get();
        self.next_handle.set(id + 1);
        self.handles.borrow_mut().insert(id, OpenFile { handle: h });
        Ok(id)
    }

    fn write_all(&self, h: u64, data: &[u8]) -> Result<(), FsError> {
        let handle = self.handle_of(h)?;
        let mut off = 0usize;
        while off < data.len() {
            let chunk = (data.len() - off).min(u32::MAX as usize) as u32;
            let mut written = 0u32;
            if unsafe { WriteFile(handle, data[off..].as_ptr(), chunk, &mut written, std::ptr::null_mut()) } == 0 {
                return Err(map_common_error("WriteFile"));
            }
            if written == 0 {
                return Err(FsError::Io { code: 0, context: "WriteFile wrote 0 bytes".into() });
            }
            off += written as usize;
        }
        Ok(())
    }

    fn flush_file(&self, h: u64) -> Result<(), FsError> {
        let handle = self.handle_of(h)?;
        if unsafe { FlushFileBuffers(handle) } == 0 {
            return Err(map_common_error("FlushFileBuffers(stage)"));
        }
        Ok(())
    }

    fn close(&self, h: u64) -> Result<(), FsError> {
        let f = self.handles.borrow_mut().remove(&h).ok_or(FsError::NotFound)?;
        if unsafe { CloseHandle(f.handle) } == 0 {
            return Err(io_err("CloseHandle"));
        }
        Ok(())
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, FsError> {
        let w = wide(path);
        let attrs = unsafe { GetFileAttributesW(w.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(map_common_error("GetFileAttributesW"));
        }
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(FsError::ReparsePoint);
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(FsError::InvalidPath(format!("{path:?} is a directory")));
        }
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(map_common_error("open for read"));
        }
        let result = (|| {
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
                return Err(io_err("GetFileInformationByHandle"));
            }
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(FsError::ReparsePoint);
            }
            if info.nNumberOfLinks > 1 {
                return Err(FsError::HardLink);
            }
            let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
            if size > MAX_JOURNAL_BYTES as u64 {
                return Err(FsError::Io { code: 0, context: "file exceeds journal size cap".into() });
            }
            let sec = crate::security::win::read_named_security(path)?;
            validate_journal_security(&sec, ObjectKind::File)
                .map_err(|e| FsError::BadSecurity(format!("{path:?}: {}", e.0)))?;
            let mut out = Vec::with_capacity(size as usize);
            let mut buf = [0u8; 65536];
            loop {
                let mut got = 0u32;
                if unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut got, std::ptr::null_mut()) } == 0 {
                    return Err(io_err("ReadFile"));
                }
                if got == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..got as usize]);
                if out.len() > MAX_JOURNAL_BYTES {
                    return Err(FsError::Io { code: 0, context: "file grew past journal size cap".into() });
                }
            }
            if out.len() as u64 != size {
                return Err(FsError::Io { code: 0, context: "file size changed during read".into() });
            }
            Ok(out)
        })();
        unsafe { CloseHandle(h) };
        result
    }

    fn file_security(&self, path: &str) -> Result<SecurityInfo, FsError> {
        Ok(crate::security::win::read_named_security(path)?)
    }

    fn replace(&self, primary: &str, stage: &str, backup: &str) -> Result<(), FsError> {
        let (p, s, b) = (wide(primary), wide(stage), wide(backup));
        if unsafe { ReplaceFileW(p.as_ptr(), s.as_ptr(), b.as_ptr(), 0, std::ptr::null(), std::ptr::null()) } == 0 {
            return Err(match last_error() {
                ERROR_ACCESS_DENIED => FsError::AccessDenied,
                ERROR_SHARING_VIOLATION => FsError::SharingViolation,
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => FsError::NotFound,
                code => FsError::Io { code, context: "ReplaceFileW".into() },
            });
        }
        Ok(())
    }

    fn move_write_through(&self, from: &str, to: &str) -> Result<(), FsError> {
        let vfrom = volume_path_of(from)?;
        let vto = volume_path_of(to)?;
        if !vfrom.eq_ignore_ascii_case(&vto) {
            return Err(FsError::InvalidPath("cross-volume move refused".into()));
        }
        let (f, t) = (wide(from), wide(to));
        if unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err(map_common_error("MoveFileExW"));
        }
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<(), FsError> {
        if unsafe { DeleteFileW(wide(path).as_ptr()) } == 0 {
            return Err(map_common_error("DeleteFileW"));
        }
        Ok(())
    }

    fn flush_volume(&self, path: &str) -> Result<(), FsError> {
        let root = volume_path_of(path)?;
        let device = format!("\\\\.\\{}", root.trim_end_matches('\\'));
        let w = wide(&device);
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(match last_error() {
                ERROR_ACCESS_DENIED => FsError::AccessDenied,
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => FsError::NotFound,
                _ => io_err("open volume"),
            });
        }
        let ok = unsafe { FlushFileBuffers(h) };
        let err = last_error();
        unsafe { CloseHandle(h) };
        if ok == 0 {
            return Err(match err {
                ERROR_ACCESS_DENIED => FsError::AccessDenied,
                ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED => FsError::VolumeFlushUnsupported,
                _ => FsError::Io { code: err, context: "FlushFileBuffers(volume)".into() },
            });
        }
        Ok(())
    }

    fn flush_file_at(&self, path: &str) -> Result<(), FsError> {
        let sec = crate::security::win::read_named_security(path)?;
        validate_journal_security(&sec, ObjectKind::File)
            .map_err(|e| FsError::BadSecurity(format!("{path:?}: {}", e.0)))?;
        let w = wide(path);
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(map_common_error("open primary for flush"));
        }
        let ok = unsafe { FlushFileBuffers(h) };
        let err = last_error();
        unsafe { CloseHandle(h) };
        if ok == 0 {
            return Err(match err {
                ERROR_DISK_FULL | ERROR_HANDLE_DISK_FULL => FsError::DiskFull,
                ERROR_ACCESS_DENIED => FsError::AccessDenied,
                _ => FsError::Io { code: err, context: "FlushFileBuffers(primary)".into() },
            });
        }
        Ok(())
    }
}

// ---- WindowsLock -------------------------------------------------------------

/// Real machine-wide named mutex at [`LOCK_NAME`] with the protected DACL.
/// Wrong-type or security-squatted objects fail closed; WAIT_ABANDONED is
/// reported as [`Acquired::Abandoned`] (caller must rescan the journal).
pub struct WindowsLock;

impl WindowsLock {
    pub fn new() -> Result<Self, LockError> {
        enable_privileges().map_err(|e| LockError::CreateFailed(format!("privileges: {e}")))?;
        Ok(Self)
    }
}

impl MachineLock for WindowsLock {
    fn acquire(&self, budget: Duration) -> Result<(LockGuard, Acquired), LockError> {
        let name = wide(LOCK_NAME);
        let sddl = crate::security::win::Sddl::parse(MUTEX_SDDL).map_err(|e| LockError::BadSecurity(e.0))?;
        let sa = sa_of(&sddl);
        let h = unsafe { CreateMutexExW(&sa, name.as_ptr(), 0, MUTEX_ALL_ACCESS) };
        if h.is_null() {
            return Err(probe_existing(&name, last_error()));
        }
        // Validate whether we created it or opened an existing one: an
        // existing weak-DACL mutex can open successfully and must still fail.
        let sec = match crate::security::win::read_handle_security(h) {
            Ok(s) => s,
            Err(e) => {
                unsafe { CloseHandle(h) };
                return Err(LockError::BadSecurity(e.0));
            }
        };
        if let Err(e) = validate_journal_security(&sec, ObjectKind::Mutex) {
            unsafe { CloseHandle(h) };
            return Err(LockError::BadSecurity(e.0));
        }
        let ms = budget.as_millis().min(u32::MAX as u128) as u32;
        let acquired = match unsafe { WaitForSingleObject(h, ms) } {
            WAIT_OBJECT_0 => Acquired::Fresh,
            WAIT_ABANDONED => Acquired::Abandoned,
            WAIT_TIMEOUT => {
                unsafe { CloseHandle(h) };
                return Err(LockError::Timeout);
            }
            w => {
                unsafe { CloseHandle(h) };
                return Err(LockError::CreateFailed(format!("WaitForSingleObject returned {w}")));
            }
        };
        let guard = LockGuard::from_release(Box::new(move || unsafe {
            ReleaseMutex(h);
            CloseHandle(h);
        }));
        Ok((guard, acquired))
    }
}

fn probe_existing(name: &[u16], create_err: u32) -> LockError {
    unsafe {
        let mh = OpenMutexW(READ_CONTROL | SYNCHRONIZE, 0, name.as_ptr());
        if !mh.is_null() {
            let verdict = match crate::security::win::read_handle_security(mh) {
                Ok(sec) => match validate_journal_security(&sec, ObjectKind::Mutex) {
                    Ok(()) => LockError::AccessDenied,
                    Err(e) => LockError::BadSecurity(e.0),
                },
                Err(e) => LockError::BadSecurity(e.0),
            };
            CloseHandle(mh);
            return verdict;
        }
        let eh = OpenEventW(READ_CONTROL | SYNCHRONIZE, 0, name.as_ptr());
        if !eh.is_null() {
            CloseHandle(eh);
            return LockError::WrongType;
        }
        let sh = OpenSemaphoreW(READ_CONTROL | SYNCHRONIZE, 0, name.as_ptr());
        if !sh.is_null() {
            CloseHandle(sh);
            return LockError::WrongType;
        }
        if create_err == ERROR_ACCESS_DENIED {
            LockError::AccessDenied
        } else {
            LockError::CreateFailed(format!("CreateMutexExW failed: {create_err}"))
        }
    }
}

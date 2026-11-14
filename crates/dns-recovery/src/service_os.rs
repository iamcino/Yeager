//! U05 Windows transport: SCM lifecycle and the secure named-pipe server
//! (SPEC-DNS-FIX.md §8.1–§8.3). Windows only.
//!
//! - Service `YeagerDnsRecovery`, own-process LocalSystem, automatic
//!   NON-delayed start. Failure actions restart at 1 s / 5 s / 30 s
//!   (including non-crash failures) plus a 30 s preshutdown budget.
//! - Pipe `\\.\pipe\Yeager.DnsRecovery.v1`: first-instance,
//!   `PIPE_REJECT_REMOTE_CLIENTS`, protected SYSTEM/Administrators DACL,
//!   byte mode, one u32-LE-framed UTF-8 JSON frame per message, a real 5 s
//!   framing/auth budget (overlapped reads + worker-thread authentication +
//!   per-connection budget; `nDefaultTimeOut` alone is not a deadline). The
//!   server authenticates every peer by impersonation + token inspection
//!   (logon LUID from `TokenStatistics`) + `GetNamedPipeClientProcessId` +
//!   server-observed process image (path, file id, SHA-256) — never from
//!   caller-supplied fields — and reverts before privileged I/O. The client
//!   checks `GetNamedPipeServerProcessId` against the SCM service PID AND the
//!   server process image against the protected image path.
//! - Owner liveness is PID + creation FILETIME over a HELD process handle
//!   (opened at registration, before the reply). The service thread polls
//!   every held handle and the journal's recorded owner about once a second
//!   (`watchdog_poll`); a dead result restores inside the 1 s target with no
//!   GUI relaunch. A service restart that sees a live owner holds that handle
//!   in the monitor before takeover — no blind restore, no mutation lease.
//!   Adapter arrival additionally subscribes `NotifyIpInterfaceChange`
//!   (callback only enqueues; `CancelMibChangeNotify2` on the stop path)
//!   with the 60 s `GetAdaptersAddresses` poll as fallback.
//!
//! Pure policy (leases, epochs, dedup, scheduler) stays in the portable
//! [`crate::service`] host; this module only moves bytes and handles.

use crate::protocol::{self, PeerAuth, Reply, Request, PIPE_NAME, PIPE_SDDL};
use crate::replay::{OwnerLiveness, OwnerProbe};
use crate::service::ScmServiceState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const SERVICE_NAME: &str = "YeagerDnsRecovery";
pub const SERVICE_DISPLAY: &str = "Yeager DNS Recovery";
/// Failure-action restart delays (§8.1): 1 s / 5 s / 30 s.
pub const FAILURE_ACTION_DELAYS_MS: [u32; 3] = [1000, 5000, 30000];
/// SCM preshutdown budget in ms (§8.1/§8.3).
pub const PRESHUTDOWN_TIMEOUT_MS: u32 = 30_000;
/// Per-connection framing/auth budget (§8.2: 5 s). This is the `CreateNamedPipeW`
/// `nDefaultTimeOut` value (the `WaitNamedPipe` default) AND the budget the
/// overlapped reads and `authenticate_peer_deadline` enforce — the former
/// alone is not a read deadline.
pub const PIPE_TIMEOUT_MS: u32 = 5_000;
/// Alias naming the enforced I/O deadline: overlapped `ReadFile`/`WriteFile`
/// + event wait + `CancelIoEx`, and the worker-thread authentication join.
pub const PIPE_IO_DEADLINE_MS: u32 = 5_000;

// ---- small Win32 helpers -------------------------------------------------------

use windows_sys::Win32 as Ws;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> u32 {
    unsafe { Ws::Foundation::GetLastError() }
}

fn pwstr_to_string(p: windows_sys::core::PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

// ---- environment ------------------------------------------------------------------

/// Resolve `%ProgramData%` via SHGetKnownFolderPath (never from client
/// environment), then append the `Yeager` component.
pub fn program_data_dir() -> Result<String, String> {
    unsafe {
        let mut path: windows_sys::core::PWSTR = std::ptr::null_mut();
        let hr = Ws::UI::Shell::SHGetKnownFolderPath(
            &Ws::UI::Shell::FOLDERID_ProgramData,
            0,
            std::ptr::null_mut(),
            &mut path,
        );
        if hr != 0 {
            return Err(format!("SHGetKnownFolderPath failed: HRESULT {hr:#x}"));
        }
        let base = pwstr_to_string(path);
        Ws::Foundation::LocalFree(path as _);
        if base.is_empty() {
            return Err("SHGetKnownFolderPath returned an empty path".into());
        }
        Ok(format!("{base}\\Yeager"))
    }
}

/// Explicit elevation check for administrative CLI modes.
pub fn is_elevated() -> bool {
    unsafe { Ws::UI::Shell::IsUserAnAdmin() != 0 }
}

/// Best-effort service diagnostics log (NOT journal data): timestamped lines
/// appended to `<ProgramData>\Yeager\dns-recovery-service.log`, which inherits
/// the protected directory ACL. Never logs lease tokens or request bodies;
/// failures are silently ignored so diagnostics can never break recovery.
///
/// The logger NEVER creates the directory: `std::fs::create_dir_all` would
/// lay down default (inherited, unprotected) ACLs, and the journal layer
/// validates existing directories without silent repair — a logger-created
/// directory would fail closed on every fresh-machine boot. Directory
/// creation stays with `WindowsFs::ensure_directory` (exact `DIR_SDDL`);
/// when the directory does not exist yet, logging is skipped.
pub fn service_log(note: &str) {
    use std::fmt::Write as _;
    let dir = match program_data_dir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let attrs = unsafe {
        Ws::Storage::FileSystem::GetFileAttributesW(wide(&dir).as_ptr())
    };
    if attrs == Ws::Storage::FileSystem::INVALID_FILE_ATTRIBUTES
        || attrs & Ws::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return;
    }
    let mut line = String::new();
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let _ = write!(line, "{ms} {note}\n");
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{dir}\\dns-recovery-service.log"))
    {
        let _ = f.write_all(line.as_bytes());
    }
}

// ---- SCM query/install/remove -------------------------------------------------------

fn open_manager(access: u32) -> Result<Ws::System::Services::SC_HANDLE, String> {
    unsafe {
        let h = Ws::System::Services::OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            access,
        );
        if h.is_null() {
            return Err(format!("OpenSCManagerW failed: {}", last_error()));
        }
        Ok(h)
    }
}

fn open_service(
    manager: Ws::System::Services::SC_HANDLE,
    access: u32,
) -> Result<Ws::System::Services::SC_HANDLE, String> {
    unsafe {
        let name = wide(SERVICE_NAME);
        let h = Ws::System::Services::OpenServiceW(manager, name.as_ptr(), access);
        if h.is_null() {
            return Err(format!("OpenServiceW failed: {}", last_error()));
        }
        Ok(h)
    }
}

fn close(h: *mut std::ffi::c_void) {
    unsafe {
        Ws::Foundation::CloseHandle(h);
    }
}

/// SCM service state for the offline guard (§8.3): only a proven STOPPED
/// service authorizes the elevated offline helper.
pub fn scm_query_state() -> Result<ScmServiceState, String> {
    use Ws::System::Services as S;
    unsafe {
        let manager = open_manager(S::SC_MANAGER_CONNECT)?;
        let service = match open_service(manager, S::SERVICE_QUERY_STATUS) {
            Ok(h) => h,
            Err(e) => {
                close(manager);
                // Absent service: no authority exists, but the state is
                // *known-absent*, not unknown. The offline helper treats
                // absent as refused (nothing proves STOPPED) — surfaced here
                // as Stopped only when the service record is confirmed gone?
                // No: absent is NOT proven STOPPED. Report Unknown so the
                // guard refuses, and let the message carry the detail.
                let _ = e;
                return Ok(ScmServiceState::Unknown);
            }
        };
        let mut status: S::SERVICE_STATUS = std::mem::zeroed();
        let ok = S::QueryServiceStatus(service, &mut status);
        close(service);
        close(manager);
        if ok == 0 {
            return Err(format!("QueryServiceStatus failed: {}", last_error()));
        }
        Ok(match status.dwCurrentState {
            S::SERVICE_STOPPED => ScmServiceState::Stopped,
            S::SERVICE_RUNNING => ScmServiceState::Running,
            S::SERVICE_START_PENDING => ScmServiceState::StartPending,
            S::SERVICE_STOP_PENDING => ScmServiceState::StopPending,
            _ => ScmServiceState::Unknown,
        })
    }
}

/// SCM service PID (for the client's server-identity check).
pub fn scm_service_pid() -> Result<Option<u32>, String> {
    use Ws::System::Services as S;
    unsafe {
        let manager = open_manager(S::SC_MANAGER_CONNECT)?;
        let service = open_service(manager, S::SERVICE_QUERY_STATUS)?;
        let mut buf = [0u8; 256];
        let mut needed = 0u32;
        let ok = S::QueryServiceStatusEx(
            service,
            S::SC_STATUS_PROCESS_INFO,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut needed,
        );
        close(service);
        close(manager);
        if ok == 0 {
            return Err(format!("QueryServiceStatusEx failed: {}", last_error()));
        }
        let proc = &*(buf.as_ptr() as *const S::SERVICE_STATUS_PROCESS);
        Ok(if proc.dwProcessId == 0 {
            None
        } else {
            Some(proc.dwProcessId)
        })
    }
}

/// Install the service exactly per §8.1 and arm failure actions +
/// preshutdown. The binary must already live at the protected path; the
/// quoted ImagePath carries `--service`.
pub fn install_service(image_path: &str) -> Result<(), String> {
    use Ws::System::Services as S;
    if !is_elevated() {
        return Err("install_service requires elevation".into());
    }
    unsafe {
        let manager = open_manager(S::SC_MANAGER_CREATE_SERVICE)?;
        let name = wide(SERVICE_NAME);
        let display = wide(SERVICE_DISPLAY);
        let bin = wide(&format!("\"{image_path}\" --service"));
        let existing = S::OpenServiceW(manager, name.as_ptr(), S::SERVICE_ALL_ACCESS);
        if !existing.is_null() {
            close(existing);
            close(manager);
            return Err(format!("service {SERVICE_NAME} is already installed"));
        }
        let service = S::CreateServiceW(
            manager,
            name.as_ptr(),
            display.as_ptr(),
            S::SERVICE_ALL_ACCESS,
            S::SERVICE_WIN32_OWN_PROCESS,
            S::SERVICE_AUTO_START,
            S::SERVICE_ERROR_NORMAL,
            bin.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        if service.is_null() {
            let e = last_error();
            close(manager);
            return Err(format!("CreateServiceW failed: {e}"));
        }
        // Failure actions: restart at 1 s / 5 s / 30 s, including
        // non-crash failures.
        let mut actions = FAILURE_ACTION_DELAYS_MS
            .iter()
            .map(|d| S::SC_ACTION {
                Type: S::SC_ACTION_RESTART,
                Delay: *d,
            })
            .collect::<Vec<_>>();
        let failure = S::SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86400,
            lpRebootMsg: std::ptr::null_mut(),
            lpCommand: std::ptr::null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        if S::ChangeServiceConfig2W(
            service,
            S::SERVICE_CONFIG_FAILURE_ACTIONS,
            &failure as *const _ as *const std::ffi::c_void,
        ) == 0
        {
            let e = last_error();
            S::DeleteService(service);
            close(service);
            close(manager);
            return Err(format!("failure-action configuration failed: {e}"));
        }
        let flag = S::SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: 1,
        };
        if S::ChangeServiceConfig2W(
            service,
            S::SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            &flag as *const _ as *const std::ffi::c_void,
        ) == 0
        {
            let e = last_error();
            S::DeleteService(service);
            close(service);
            close(manager);
            return Err(format!("non-crash failure-action flag failed: {e}"));
        }
        let preshutdown = S::SERVICE_PRESHUTDOWN_INFO {
            dwPreshutdownTimeout: PRESHUTDOWN_TIMEOUT_MS,
        };
        if S::ChangeServiceConfig2W(
            service,
            S::SERVICE_CONFIG_PRESHUTDOWN_INFO,
            &preshutdown as *const _ as *const std::ffi::c_void,
        ) == 0
        {
            let e = last_error();
            S::DeleteService(service);
            close(service);
            close(manager);
            return Err(format!("preshutdown configuration failed: {e}"));
        }
        close(service);
        close(manager);
        Ok(())
    }
}

pub fn remove_service() -> Result<(), String> {
    use Ws::System::Services as S;
    if !is_elevated() {
        return Err("remove_service requires elevation".into());
    }
    unsafe {
        let manager = open_manager(S::SC_MANAGER_CONNECT)?;
        let service = open_service(manager, S::SERVICE_ALL_ACCESS)?;
        let ok = S::DeleteService(service);
        let e = last_error();
        close(service);
        close(manager);
        if ok == 0 {
            return Err(format!("DeleteService failed: {e}"));
        }
        Ok(())
    }
}

pub fn start_service() -> Result<(), String> {
    use Ws::System::Services as S;
    if !is_elevated() {
        return Err("start_service requires elevation".into());
    }
    unsafe {
        let manager = open_manager(S::SC_MANAGER_CONNECT)?;
        let service = open_service(manager, S::SERVICE_START | S::SERVICE_QUERY_STATUS)?;
        let ok = S::StartServiceW(service, 0, std::ptr::null());
        let e = last_error();
        close(service);
        close(manager);
        // ERROR_SERVICE_ALREADY_RUNNING (1056) is success for our purposes.
        if ok == 0 && e != 1056 {
            return Err(format!("StartServiceW failed: {e}"));
        }
        Ok(())
    }
}

pub fn stop_service() -> Result<(), String> {
    use Ws::System::Services as S;
    if !is_elevated() {
        return Err("stop_service requires elevation".into());
    }
    unsafe {
        let manager = open_manager(S::SC_MANAGER_CONNECT)?;
        let service = open_service(manager, S::SERVICE_STOP | S::SERVICE_QUERY_STATUS)?;
        let mut status: S::SERVICE_STATUS = std::mem::zeroed();
        let ok = S::ControlService(service, S::SERVICE_CONTROL_STOP, &mut status);
        let e = last_error();
        close(service);
        close(manager);
        // ERROR_SERVICE_NOT_ACTIVE (1062) means already stopped: success.
        if ok == 0 && e != 1062 {
            return Err(format!("ControlService(STOP) failed: {e}"));
        }
        Ok(())
    }
}

// ---- owner probe (held handles) --------------------------------------------------
//
// PID + creation FILETIME over a handle opened at registration and held for
// the lease's lifetime. A matching FILETIME with a nonsignaled handle is
// live; a different FILETIME means PID reuse (recorded owner dead); a
// signaled or missing handle proves death. Access denied / query failure is
// Unknown, never dead. Image fields are never consulted.

struct HeldHandle {
    handle: *mut std::ffi::c_void,
    filetime: u64,
}

// SAFETY: handles are only touched on the service's probe path; the Mutex
// serializes access. The table is Arc-shared so every factory-built probe
// observes the same held handles.
unsafe impl Send for WindowsOwnerProbe {}
unsafe impl Sync for WindowsOwnerProbe {}

pub struct WindowsOwnerProbe {
    handles: Arc<Mutex<HashMap<u32, HeldHandle>>>,
}

impl Clone for WindowsOwnerProbe {
    fn clone(&self) -> Self {
        Self {
            handles: Arc::clone(&self.handles),
        }
    }
}

impl WindowsOwnerProbe {
    pub fn new() -> Self {
        Self {
            handles: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Drop cached handles whose pids no longer hold leases.
    pub fn release_closed(&self, live_pids: &[u32]) {
        let mut map = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|pid, held| {
            if live_pids.contains(pid) {
                return true;
            }
            unsafe {
                Ws::Foundation::CloseHandle(held.handle);
            }
            false
        });
    }

    fn open_handle(pid: u32) -> Result<(*mut std::ffi::c_void, u64), String> {
        unsafe {
            let handle = Ws::System::Threading::OpenProcess(
                Ws::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION
                    | Ws::Storage::FileSystem::SYNCHRONIZE,
                0,
                pid,
            );
            if handle.is_null() {
                return Err(format!("OpenProcess({pid}) failed: {}", last_error()));
            }
            let mut created: Ws::Foundation::FILETIME = std::mem::zeroed();
            let mut exited: Ws::Foundation::FILETIME = std::mem::zeroed();
            let mut kernel: Ws::Foundation::FILETIME = std::mem::zeroed();
            let mut user: Ws::Foundation::FILETIME = std::mem::zeroed();
            if Ws::System::Threading::GetProcessTimes(
                handle, &mut created, &mut exited, &mut kernel, &mut user,
            ) == 0
            {
                let e = last_error();
                Ws::Foundation::CloseHandle(handle);
                return Err(format!("GetProcessTimes({pid}) failed: {e}"));
            }
            let filetime =
                ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
            Ok((handle, filetime))
        }
    }
}

impl Default for WindowsOwnerProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnerProbe for WindowsOwnerProbe {
    fn check(&self, owner: &crate::journal::OwnerIdentity) -> OwnerLiveness {
        let mut map = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        // Reuse the held handle when the recorded FILETIME matches: the
        // handle names the ORIGINAL process object, so PID reuse cannot
        // confuse the WaitForSingleObject poll below.
        if let Some(held) = map.get(&owner.pid) {
            if held.filetime == owner.creation_time_filetime {
                let signaled = unsafe {
                    Ws::System::Threading::WaitForSingleObject(held.handle, 0)
                };
                // WAIT_OBJECT_0 (0) = signaled = process exited.
                if signaled == 0 {
                    return OwnerLiveness::Dead;
                }
                return OwnerLiveness::Live;
            }
            // Same PID, different FILETIME: PID reuse. The recorded owner
            // is dead; drop the stale handle.
            let stale = map.remove(&owner.pid).unwrap();
            unsafe {
                Ws::Foundation::CloseHandle(stale.handle);
            }
            return OwnerLiveness::Dead;
        }
        drop(map);
        match Self::open_handle(owner.pid) {
            Err(detail) => {
                // Access denied or query failure: unknown, never dead.
                // ERROR_FILE_NOT_FOUND (2) / INVALID_PARAMETER (87) mean the
                // PID is gone: proven death.
                let code = detail
                    .rsplit(' ')
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                if code == 2 || code == 87 || code == 128 {
                    return OwnerLiveness::Dead;
                }
                OwnerLiveness::Unknown(detail)
            }
            Ok((handle, filetime)) => {
                if filetime != owner.creation_time_filetime {
                    unsafe {
                        Ws::Foundation::CloseHandle(handle);
                    }
                    return OwnerLiveness::Dead;
                }
                let signaled = unsafe {
                    Ws::System::Threading::WaitForSingleObject(handle, 0)
                };
                if signaled == 0 {
                    unsafe {
                        Ws::Foundation::CloseHandle(handle);
                    }
                    return OwnerLiveness::Dead;
                }
                // Hold the handle: the original process object cannot be
                // confused with a future PID reuse from here on.
                let mut map = self.handles.lock().unwrap_or_else(|e| e.into_inner());
                map.insert(
                    owner.pid,
                    HeldHandle {
                        handle,
                        filetime,
                    },
                );
                OwnerLiveness::Live
            }
        }
    }
}

// ---- peer authentication ------------------------------------------------------------
//
// Derived from impersonation + token inspection + GetNamedPipeClientProcessId.
// Caller-supplied identity fields are never trusted.

fn token_user_sid(token: *mut std::ffi::c_void) -> Result<String, String> {
    unsafe {
        let mut needed = 0u32;
        Ws::Security::GetTokenInformation(
            token,
            Ws::Security::TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        let mut buf = vec![0u8; needed.max(64) as usize];
        if Ws::Security::GetTokenInformation(
            token,
            Ws::Security::TokenUser,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
            &mut needed,
        ) == 0
        {
            return Err(format!("GetTokenInformation(TokenUser) failed: {}", last_error()));
        }
        let user = &*(buf.as_ptr() as *const Ws::Security::TOKEN_USER);
        let mut sid_str: windows_sys::core::PWSTR = std::ptr::null_mut();
        if Ws::Security::Authorization::ConvertSidToStringSidW(user.User.Sid, &mut sid_str)
            == 0
        {
            return Err(format!("ConvertSidToStringSidW failed: {}", last_error()));
        }
        let sid = pwstr_to_string(sid_str);
        Ws::Foundation::LocalFree(sid_str as _);
        Ok(sid)
    }
}

fn token_dword(token: *mut std::ffi::c_void, class: Ws::Security::TOKEN_INFORMATION_CLASS) -> Result<u32, String> {
    unsafe {
        // TokenElevation and TokenSessionId both return a u32.
        let mut value = 0u32;
        let mut got = 0u32;
        if Ws::Security::GetTokenInformation(
            token,
            class,
            &mut value as *mut u32 as *mut std::ffi::c_void,
            4,
            &mut got,
        ) == 0
        {
            return Err(format!(
                "GetTokenInformation(class {class}) failed: {}",
                last_error()
            ));
        }
        Ok(value)
    }
}

fn token_logon_luid(token: *mut std::ffi::c_void) -> Result<u64, String> {
    // TokenStatistics.AuthenticationId is the logon-session LUID the token
    // was minted for — server-observed, never the session id and never a
    // caller-supplied field.
    unsafe {
        let mut stats: Ws::Security::TOKEN_STATISTICS = std::mem::zeroed();
        let mut got = 0u32;
        if Ws::Security::GetTokenInformation(
            token,
            Ws::Security::TokenStatistics,
            &mut stats as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<Ws::Security::TOKEN_STATISTICS>() as u32,
            &mut got,
        ) == 0
        {
            return Err(format!(
                "GetTokenInformation(TokenStatistics) failed: {}",
                last_error()
            ));
        }
        let luid = stats.AuthenticationId;
        Ok(((luid.HighPart as u64) << 32) | luid.LowPart as u64)
    }
}

fn process_image_and_times(
    pid: u32,
) -> Result<(String, u64, u32), String> {
    unsafe {
        let handle = Ws::System::Threading::OpenProcess(
            Ws::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if handle.is_null() {
            return Err(format!("OpenProcess({pid}) failed: {}", last_error()));
        }
        let mut created: Ws::Foundation::FILETIME = std::mem::zeroed();
        let mut exited: Ws::Foundation::FILETIME = std::mem::zeroed();
        let mut kernel: Ws::Foundation::FILETIME = std::mem::zeroed();
        let mut user: Ws::Foundation::FILETIME = std::mem::zeroed();
        if Ws::System::Threading::GetProcessTimes(
            handle, &mut created, &mut exited, &mut kernel, &mut user,
        ) == 0
        {
            let e = last_error();
            Ws::Foundation::CloseHandle(handle);
            return Err(format!("GetProcessTimes({pid}) failed: {e}"));
        }
        let filetime =
            ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
        let mut path = vec![0u16; 1024];
        let mut size = path.len() as u32;
        if Ws::System::Threading::QueryFullProcessImageNameW(
            handle,
            0,
            path.as_mut_ptr(),
            &mut size,
        ) == 0
        {
            let e = last_error();
            Ws::Foundation::CloseHandle(handle);
            return Err(format!("QueryFullProcessImageNameW({pid}) failed: {e}"));
        }
        Ws::Foundation::CloseHandle(handle);
        let image = String::from_utf16_lossy(&path[..size as usize]);
        Ok((image, filetime, pid))
    }
}

/// Server-observed image identity for a PID: the file id (volume serial +
/// file index) and SHA-256 of the executable file backing the process.
/// Never a caller-supplied field.
fn process_image_identity(pid: u32) -> Result<(String, String), String> {
    use Ws::Storage::FileSystem as FS;
    let (image, _, _) = process_image_and_times(pid)?;
    unsafe {
        let path = wide(&image);
        let h = FS::CreateFileW(
            path.as_ptr(),
            Ws::Foundation::GENERIC_READ,
            FS::FILE_SHARE_READ | FS::FILE_SHARE_WRITE | FS::FILE_SHARE_DELETE,
            std::ptr::null(),
            FS::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h == Ws::Foundation::INVALID_HANDLE_VALUE || h.is_null() {
            return Err(format!("cannot open image file {image:?}: {}", last_error()));
        }
        let mut info: FS::BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if FS::GetFileInformationByHandle(h, &mut info) == 0 {
            let e = last_error();
            Ws::Foundation::CloseHandle(h);
            return Err(format!("GetFileInformationByHandle failed: {e}"));
        }
        let file_id = format!(
            "{:08x}-{:08x}-{:08x}",
            info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
        );
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest as _;
        let mut buf = vec![0u8; 65536];
        loop {
            let mut got = 0u32;
            if FS::ReadFile(
                h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            ) == 0
            {
                let e = last_error();
                Ws::Foundation::CloseHandle(h);
                return Err(format!("image file read failed: {e}"));
            }
            if got == 0 {
                break;
            }
            hasher.update(&buf[..got as usize]);
        }
        Ws::Foundation::CloseHandle(h);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        Ok((file_id, hex))
    }
}

/// Protected service image path (`%ProgramFiles%\Yeager\...`), resolved via
/// the known folder — never from caller input or the `ProgramFiles`
/// environment variable.
pub fn protected_service_image() -> Result<String, String> {
    unsafe {
        let mut path: windows_sys::core::PWSTR = std::ptr::null_mut();
        let hr = Ws::UI::Shell::SHGetKnownFolderPath(
            &Ws::UI::Shell::FOLDERID_ProgramFiles,
            0,
            std::ptr::null_mut(),
            &mut path,
        );
        if hr != 0 {
            return Err(format!("SHGetKnownFolderPath(ProgramFiles) failed: HRESULT {hr:#x}"));
        }
        let base = pwstr_to_string(path);
        Ws::Foundation::LocalFree(path as _);
        if base.is_empty() {
            return Err("SHGetKnownFolderPath(ProgramFiles) returned an empty path".into());
        }
        Ok(format!("{base}\\Yeager\\yeager-dns-recovery.exe"))
    }
}

/// Client-side server identity check (after the SCM PID check): the process
/// behind the observed server PID must be the protected service image.
/// Fails closed — an unqueryable server process is rejected.
pub fn verify_server_image(server_pid: u32) -> Result<(), String> {
    let expected = protected_service_image()?;
    let (observed, _, _) = process_image_and_times(server_pid)?;
    if observed.to_lowercase() != expected.to_lowercase() {
        return Err(format!(
            "pipe server image {observed:?} is not the protected service image {expected:?}"
        ));
    }
    Ok(())
}

/// Authenticate one connected pipe instance. Runs inside impersonation and
/// reverts before returning.
fn authenticate_peer(pipe: *mut std::ffi::c_void) -> Result<PeerAuth, String> {
    unsafe {
        let mut pid = 0u32;
        if Ws::System::Pipes::GetNamedPipeClientProcessId(pipe, &mut pid) == 0 {
            return Err(format!("GetNamedPipeClientProcessId failed: {}", last_error()));
        }
        if Ws::System::Pipes::ImpersonateNamedPipeClient(pipe) == 0 {
            return Err(format!("ImpersonateNamedPipeClient failed: {}", last_error()));
        }
        let result = (|| -> Result<PeerAuth, String> {
            let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
            if Ws::System::Threading::OpenThreadToken(
                Ws::System::Threading::GetCurrentThread(),
                Ws::Security::TOKEN_QUERY,
                1,
                &mut token,
            ) == 0
            {
                return Err(format!("OpenThreadToken failed: {}", last_error()));
            }
            let sid = token_user_sid(token)?;
            let elevated = token_dword(token, Ws::Security::TokenElevation)? != 0;
            let session = token_dword(token, Ws::Security::TokenSessionId)?;
            let logon_luid = token_logon_luid(token)?;
            Ws::Foundation::CloseHandle(token);
            let (image, filetime, _) = process_image_and_times(pid)?;
            // Server-side image identity comes from the process itself, not
            // the request: a failure here fails the authentication closed.
            let (image_file_id, image_sha256) = process_image_identity(pid)?;
            Ok(PeerAuth {
                pid,
                creation_filetime: filetime,
                user_sid: sid,
                elevated,
                session_id: session,
                logon_luid,
                image_path: image,
                image_file_id,
                image_sha256,
                remote: false,
                server_pid: None,
                expected_server_pid: None,
            })
        })();
        Ws::Security::RevertToSelf();
        result
    }
}

// ---- pipe server -------------------------------------------------------------------------

fn security_attributes_from_sddl() -> Result<(Ws::Security::SECURITY_ATTRIBUTES, *mut std::ffi::c_void), String> {
    unsafe {
        let sddl = wide(PIPE_SDDL);
        let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
        if Ws::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            Ws::Security::Authorization::SDDL_REVISION,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(format!("pipe DACL conversion failed: {}", last_error()));
        }
        let sa = Ws::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<Ws::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        Ok((sa, sd))
    }
}

fn read_exact(pipe: *mut std::ffi::c_void, n: usize) -> Result<Vec<u8>, String> {
    read_exact_deadline(pipe, n, PIPE_IO_DEADLINE_MS)
}

/// Real per-read I/O deadline (§8.2: 5 s framing budget): overlapped ReadFile
/// + event wait against a total budget. A stalled client is dropped at the
/// deadline instead of pinning the serial worker that also runs the watchdog
/// and the stop path. `PIPE_TIMEOUT_MS` is `CreateNamedPipeW`'s
/// `nDefaultTimeOut` (the `WaitNamedPipe` default) — it is NOT a read
/// deadline, so this function implements an actual one.
fn read_exact_deadline(
    pipe: *mut std::ffi::c_void,
    mut n: usize,
    deadline_ms: u32,
) -> Result<Vec<u8>, String> {
    use Ws::Foundation as F;
    use Ws::System::IO as IO;
    use Ws::System::Threading as T;
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_millis(deadline_ms as u64);
    let mut out = Vec::with_capacity(n);
    while n > 0 {
        let elapsed = start.elapsed();
        if elapsed >= budget {
            return Err("pipe read deadline exceeded (5 s framing budget)".into());
        }
        let remaining = budget - elapsed;
        let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
        let event = unsafe { T::CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(format!("CreateEventW failed: {}", last_error()));
        }
        let mut chunk = vec![0u8; n.min(65536)];
        let mut got = 0u32;
        let mut ov: IO::OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = event;
        let completed = unsafe {
            if Ws::Storage::FileSystem::ReadFile(
                pipe,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut got,
                &mut ov,
            ) != 0
            {
                true
            } else if last_error() != F::ERROR_IO_PENDING {
                let e = last_error();
                F::CloseHandle(event);
                return Err(format!("pipe read failed: {e}"));
            } else {
                false
            }
        };
        if !completed {
            let wait = unsafe { T::WaitForSingleObject(event, wait_ms) };
            if wait == F::WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                let ok = unsafe {
                    IO::GetOverlappedResult(pipe, &ov, &mut transferred, 0)
                };
                unsafe {
                    F::CloseHandle(event);
                }
                if ok == 0 {
                    return Err(format!(
                        "pipe overlapped read failed: {}",
                        last_error()
                    ));
                }
                got = transferred;
            } else {
                unsafe {
                    IO::CancelIoEx(pipe, &ov);
                    F::CloseHandle(event);
                }
                return Err("pipe read deadline exceeded (5 s framing budget)".into());
            }
        } else {
            unsafe {
                F::CloseHandle(event);
            }
        }
        if got == 0 {
            return Err("pipe closed mid-frame".into());
        }
        out.extend_from_slice(&chunk[..got as usize]);
        n -= got as usize;
    }
    Ok(out)
}

/// `authenticate_peer` with a real deadline: the authentication runs on a
/// short-lived worker thread (impersonation is thread-scoped, so this is
/// also cleaner than impersonating the service thread) while the service
/// thread waits at most the remaining framing budget. On expiry the worker
/// is detached and the connection is dropped — the tick and the stop path
/// proceed.
fn authenticate_peer_deadline(
    pipe: *mut std::ffi::c_void,
    deadline_ms: u32,
) -> Result<PeerAuth, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let pipe_addr = pipe as usize;
    std::thread::spawn(move || {
        let pipe = pipe_addr as *mut std::ffi::c_void;
        let _ = tx.send(authenticate_peer(pipe));
    });
    match rx.recv_timeout(std::time::Duration::from_millis(deadline_ms as u64)) {
        Ok(r) => r,
        Err(_) => Err("authenticate_peer deadline exceeded (5 s framing budget)".into()),
    }
}

/// Milliseconds left in the per-connection 5 s budget (`None` when exhausted).
fn budget_left_ms(start: std::time::Instant) -> Option<u32> {
    let elapsed = start.elapsed();
    let budget = std::time::Duration::from_millis(PIPE_IO_DEADLINE_MS as u64);
    if elapsed >= budget {
        None
    } else {
        Some((budget - elapsed).as_millis().min(u32::MAX as u128) as u32)
    }
}

fn write_all(pipe: *mut std::ffi::c_void, data: &[u8]) -> Result<(), String> {
    write_all_deadline(pipe, data, PIPE_IO_DEADLINE_MS)
}

/// Overlapped `WriteFile` with the same 5 s budget (the pipe handles on both
/// ends are overlapped so reads can carry a real deadline; a blocking write
/// with a NULL OVERLAPPED would fail on them).
fn write_all_deadline(
    pipe: *mut std::ffi::c_void,
    mut data: &[u8],
    deadline_ms: u32,
) -> Result<(), String> {
    use Ws::Foundation as F;
    use Ws::System::IO as IO;
    use Ws::System::Threading as T;
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_millis(deadline_ms as u64);
    while !data.is_empty() {
        let elapsed = start.elapsed();
        if elapsed >= budget {
            return Err("pipe write deadline exceeded (5 s framing budget)".into());
        }
        let remaining = budget - elapsed;
        let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
        let event = unsafe { T::CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(format!("CreateEventW failed: {}", last_error()));
        }
        let mut ov: IO::OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = event;
        let mut wrote = 0u32;
        let n = data.len().min(u32::MAX as usize) as u32;
        let completed = unsafe {
            if Ws::Storage::FileSystem::WriteFile(pipe, data.as_ptr(), n, &mut wrote, &mut ov)
                != 0
            {
                true
            } else if last_error() != F::ERROR_IO_PENDING {
                let e = last_error();
                F::CloseHandle(event);
                return Err(format!("pipe write failed: {e}"));
            } else {
                false
            }
        };
        if !completed {
            let wait = unsafe { T::WaitForSingleObject(event, wait_ms) };
            if wait == F::WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                let ok = unsafe { IO::GetOverlappedResult(pipe, &ov, &mut transferred, 0) };
                unsafe {
                    F::CloseHandle(event);
                }
                if ok == 0 {
                    return Err(format!("pipe overlapped write failed: {}", last_error()));
                }
                wrote = transferred;
            } else {
                unsafe {
                    IO::CancelIoEx(pipe, &ov);
                    F::CloseHandle(event);
                }
                return Err("pipe write deadline exceeded (5 s framing budget)".into());
            }
        } else {
            unsafe {
                F::CloseHandle(event);
            }
        }
        if wrote == 0 {
            return Err("pipe write accepted zero bytes".into());
        }
        data = &data[wrote as usize..];
    }
    Ok(())
}

fn serve_one(
    pipe: *mut std::ffi::c_void,
    dispatch: &dyn Fn(&PeerAuth, &Request) -> Reply,
) {
    // One frame: u32 LE length + JSON, bounded by the codec, against a single
    // 5 s per-connection budget shared by the reads and authenticate_peer. A
    // partial frame or a stalled peer is dropped at the deadline; the serial
    // worker (watchdog tick + stop path) is never pinned.
    let start = std::time::Instant::now();
    if budget_left_ms(start).is_none() {
        return;
    }
    let reply_bytes = match read_exact(pipe, 4) {
        Err(e) => {
            let _ = e;
            return;
        }
        Ok(prefix) => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&prefix);
            let len = u32::from_le_bytes(arr) as usize;
            if len > protocol::MAX_FRAME_BYTES {
                return;
            }
            let budget = match budget_left_ms(start) {
                Some(b) => b,
                None => return,
            };
            match read_exact_deadline(pipe, len, budget) {
                Err(_) => return,
                Ok(payload) => {
                    let mut frame = prefix;
                    frame.extend_from_slice(&payload);
                    match protocol::decode_frame(&frame) {
                        Err(_) => return, // unknown version/op: silent refuse
                        Ok(req) => match budget_left_ms(start) {
                            None => return,
                            Some(budget) => match authenticate_peer_deadline(pipe, budget) {
                                Err(_) => {
                                    // Auth failure/timeout: structured rejection
                                    // with no lease or journal access. The codec
                                    // needs a request id to echo; the frame was
                                    // already validated, so re-decode is
                                    // infallible.
                                    let rep = Reply::new(
                                        req.request_id.clone(),
                                        "yeager-dns-recovery".into(),
                                        0,
                                        "auth_rejected",
                                        serde_json::json!({"error": "peer authentication failed"}),
                                    );
                                    protocol::encode_reply(&rep).unwrap_or_default()
                                }
                                Ok(peer) => {
                                    let rep = dispatch(&peer, &req);
                                    service_log(&format!(
                                        "pipe: op={} outcome={} gen={}",
                                        req.operation.as_str(),
                                        rep.outcome,
                                        rep.generation
                                    ));
                                    protocol::encode_reply(&rep).unwrap_or_default()
                                }
                            },
                        },
                    }
                }
            }
        }
    };
    if !reply_bytes.is_empty() {
        let _ = write_all(pipe, &reply_bytes);
        // Delivery barrier: DisconnectNamedPipe may otherwise discard the
        // reply before the client reads it (client would see 233).
        unsafe {
            Ws::Storage::FileSystem::FlushFileBuffers(pipe);
        }
    }
}

/// Run the pipe server until `stop` is set. Each connection is served on
/// this thread, serially — the serial mutation worker. `on_idle` runs
/// between clients (watchdog/scheduler cadence); it also runs when a wakeup
/// connection carries no frame (the tick waker). Returns when the stop flag
/// is observed between clients.
///
/// The pipe is created overlapped so reads carry a real 5 s deadline
/// (overlapped `ReadFile` + event wait + `CancelIoEx`); the connect itself
/// waits in 1 s slices so a stop request is honored promptly even when no
/// client arrives.
pub fn run_pipe_server(
    dispatch: impl Fn(&PeerAuth, &Request) -> Reply,
    mut on_idle: impl FnMut(),
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    use Ws::Storage::FileSystem as FS;
    use Ws::System::Pipes as P;
    let name = wide(PIPE_NAME);
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let (sa, sd) = security_attributes_from_sddl()?;
        let pipe = unsafe {
            P::CreateNamedPipeW(
                name.as_ptr(),
                FS::PIPE_ACCESS_DUPLEX
                    | FS::FILE_FLAG_FIRST_PIPE_INSTANCE
                    | FS::FILE_FLAG_OVERLAPPED,
                P::PIPE_TYPE_BYTE | P::PIPE_READMODE_BYTE | P::PIPE_WAIT | P::PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                PIPE_TIMEOUT_MS,
                &sa,
            )
        };
        unsafe {
            Ws::Foundation::LocalFree(sd);
        }
        if pipe == Ws::Foundation::INVALID_HANDLE_VALUE || pipe.is_null() {
            // ERROR_ACCESS_DENIED here means a squatted pipe name: fail
            // closed rather than serving on another name.
            let e = format!("CreateNamedPipeW failed: {}", last_error());
            service_log(&format!("pipe server: {e}"));
            return Err(e);
        }
        match connect_with_stop(pipe, &stop) {
            ConnectOutcome::Stop => {
                unsafe {
                    Ws::Foundation::CloseHandle(pipe);
                }
                return Ok(());
            }
            ConnectOutcome::Failed(e) => {
                unsafe {
                    Ws::Foundation::CloseHandle(pipe);
                }
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                service_log(&format!("pipe server: {e}"));
                return Err(e);
            }
            ConnectOutcome::Connected => {}
        }
        serve_one(pipe, &dispatch);
        unsafe {
            P::DisconnectNamedPipe(pipe);
            Ws::Foundation::CloseHandle(pipe);
        }
        on_idle();
    }
}

enum ConnectOutcome {
    Connected,
    Stop,
    Failed(String),
}

/// Overlapped `ConnectNamedPipe` with 1 s wait slices: a stop request is
/// honored promptly without relying on the tick waker. ERROR_PIPE_CONNECTED
/// (535) means a client raced us — serve it.
fn connect_with_stop(
    pipe: *mut std::ffi::c_void,
    stop: &Arc<AtomicBool>,
) -> ConnectOutcome {
    use Ws::Foundation as F;
    use Ws::System::IO as IO;
    use Ws::System::Pipes as P;
    use Ws::System::Threading as T;
    unsafe {
        let event = T::CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        if event.is_null() {
            return ConnectOutcome::Failed(format!("CreateEventW failed: {}", last_error()));
        }
        let mut ov: IO::OVERLAPPED = std::mem::zeroed();
        ov.hEvent = event;
        let result = P::ConnectNamedPipe(pipe, &mut ov);
        if result != 0 {
            F::CloseHandle(event);
            return ConnectOutcome::Connected;
        }
        let e = last_error();
        if e == F::ERROR_PIPE_CONNECTED {
            F::CloseHandle(event);
            return ConnectOutcome::Connected;
        }
        if e != F::ERROR_IO_PENDING {
            F::CloseHandle(event);
            return ConnectOutcome::Failed(format!("ConnectNamedPipe failed: {e}"));
        }
        loop {
            let wait = T::WaitForSingleObject(event, 1000);
            if wait == F::WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                if IO::GetOverlappedResult(pipe, &ov, &mut transferred, 0) == 0 {
                    let e = last_error();
                    F::CloseHandle(event);
                    // A raced client may surface here as already connected.
                    if e == F::ERROR_PIPE_CONNECTED {
                        return ConnectOutcome::Connected;
                    }
                    return ConnectOutcome::Failed(format!(
                        "ConnectNamedPipe overlapped wait failed: {e}"
                    ));
                }
                F::CloseHandle(event);
                return ConnectOutcome::Connected;
            }
            if stop.load(Ordering::SeqCst) {
                IO::CancelIoEx(pipe, &ov);
                F::CloseHandle(event);
                return ConnectOutcome::Stop;
            }
            // Slice timeout with no client yet: keep waiting. The tick waker
            // connects once a second and drives the watchdog cadence.
        }
    }
}

/// Wake a pipe server blocked in ConnectNamedPipe (used by the SCM stop
/// path): open + immediately close the pipe.
pub fn wake_pipe_server() {
    use Ws::Foundation as F;
    use Ws::Storage::FileSystem as FS;
    unsafe {
        let name = wide(PIPE_NAME);
        let h = FS::CreateFileW(
            name.as_ptr(),
            0,
            FS::FILE_SHARE_READ | FS::FILE_SHARE_WRITE,
            std::ptr::null(),
            FS::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h != F::INVALID_HANDLE_VALUE && !h.is_null() {
            F::CloseHandle(h);
        }
    }
}

/// Adapter-arrival subscription (§7 step 5): `NotifyIpInterfaceChange` fires
/// on interface add/remove/change. The callback ONLY sets the flag the
/// service thread polls on its ~1 s tick (it never touches the journal, the
/// pipe or the host); the tick then runs the 60 s-inventory diff and
/// `notify_arrival`. The 60 s `GetAdaptersAddresses` poll stays as a
/// fallback. `CancelMibChangeNotify2` runs on the stop path.
unsafe extern "system" fn ip_change_callback(
    caller_context: *const std::ffi::c_void,
    _row: *const Ws::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW,
    _notification_type: Ws::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE,
) {
    if caller_context.is_null() {
        return;
    }
    let flag = unsafe { &*(caller_context as *const AtomicBool) };
    flag.store(true, Ordering::SeqCst);
}

/// Subscribe `NotifyIpInterfaceChange(AF_UNSPEC)` with the flag as context.
/// Returns the notification handle for `CancelMibChangeNotify2`. A failed
/// subscription is NOT fatal: the service keeps the 60 s poll fallback and
/// logs the failure.
fn subscribe_ip_change(flag: &Arc<AtomicBool>) -> Option<*mut std::ffi::c_void> {
    use Ws::NetworkManagement::IpHelper as H;
    use Ws::Networking::WinSock as W;
    unsafe {
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let rc = H::NotifyIpInterfaceChange(
            W::AF_UNSPEC,
            Some(ip_change_callback),
            Arc::as_ptr(flag) as *const std::ffi::c_void,
            0,
            &mut handle,
        );
        if rc != 0 {
            service_log(&format!("NotifyIpInterfaceChange subscribe failed: {rc}"));
            return None;
        }
        if handle.is_null() {
            service_log("NotifyIpInterfaceChange returned a null handle");
            return None;
        }
        Some(handle)
    }
}

fn cancel_ip_change(handle: *mut std::ffi::c_void) {
    use Ws::NetworkManagement::IpHelper as H;
    unsafe {
        H::CancelMibChangeNotify2(handle);
    }
}

// ---- pipe client (installer / offline checks) -------------------------------------------------

/// Enumerate local adapter GUIDs (lowercase brace-free) for the 60 s
/// inventory poll (§7 step 5). Evidence/diagnostics only: arrival never
/// enrolls a GUID the journal does not already record.
pub fn list_adapter_guids() -> Result<Vec<String>, String> {
    use Ws::NetworkManagement::IpHelper as H;
    use Ws::Networking::WinSock as W;
    unsafe {
        let mut size = 0u32;
        let rc = H::GetAdaptersAddresses(
            W::AF_UNSPEC as u32,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        );
        if rc != Ws::Foundation::ERROR_BUFFER_OVERFLOW && rc != 0 {
            return Err(format!("GetAdaptersAddresses sizing failed: {rc}"));
        }
        let mut buf = vec![0u8; size.max(15000) as usize];
        let mut len = buf.len() as u32;
        let rc = H::GetAdaptersAddresses(
            W::AF_UNSPEC as u32,
            0,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut H::IP_ADAPTER_ADDRESSES_LH,
            &mut len,
        );
        if rc != 0 {
            return Err(format!("GetAdaptersAddresses failed: {rc}"));
        }
        let mut out = Vec::new();
        let mut cur = buf.as_ptr() as *mut H::IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let name = (*cur).AdapterName;
            if !name.is_null() {
                let mut n = 0usize;
                while *name.add(n) != 0 {
                    n += 1;
                }
                let raw = String::from_utf8_lossy(std::slice::from_raw_parts(
                    name as *const u8,
                    n,
                ))
                .to_string();
                let guid = raw.trim_matches(|c| c == '{' || c == '}').to_lowercase();
                if !guid.is_empty() && !out.contains(&guid) {
                    out.push(guid);
                }
            }
            cur = (*cur).Next;
        }
        Ok(out)
    }
}

/// One framed round-trip as a pipe client. Verifies the server PID against
/// `expected_server_pid` (SCM record) and the server process image against
/// the protected service image before trusting the reply.
pub fn pipe_roundtrip(
    request: &[u8],
    expected_server_pid: Option<u32>,
) -> Result<Vec<u8>, String> {
    use Ws::Foundation as F;
    use Ws::Storage::FileSystem as FS;
    unsafe {
        let name = wide(PIPE_NAME);
        let mut attempts = 0;
        let pipe = loop {
            let h = FS::CreateFileW(
                name.as_ptr(),
                F::GENERIC_READ | F::GENERIC_WRITE,
                0,
                std::ptr::null(),
                FS::OPEN_EXISTING,
                // Overlapped so the reply reads below carry the real 5 s
                // framing deadline (see read_exact_deadline).
                FS::FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            );
            if h != F::INVALID_HANDLE_VALUE && !h.is_null() {
                break h;
            }
            attempts += 1;
            if attempts >= 10 {
                return Err(format!("pipe connect failed: {}", last_error()));
            }
            Ws::System::Threading::Sleep(500);
        };
        if let Some(expected) = expected_server_pid {
            let mut observed = 0u32;
            if Ws::System::Pipes::GetNamedPipeServerProcessId(pipe, &mut observed) == 0 {
                let e = last_error();
                F::CloseHandle(pipe);
                return Err(format!("GetNamedPipeServerProcessId failed: {e}"));
            }
            if observed != expected {
                F::CloseHandle(pipe);
                return Err(format!(
                    "pipe server PID {observed} does not match SCM record {expected}"
                ));
            }
            // After the SCM PID check, compare the server process image to
            // the protected service image. Fails closed.
            if let Err(e) = verify_server_image(observed) {
                F::CloseHandle(pipe);
                return Err(e);
            }
        }
        if let Err(e) = write_all(pipe, request) {
            F::CloseHandle(pipe);
            return Err(e);
        }
        let prefix = read_exact(pipe, 4);
        let reply = match prefix {
            Err(e) => {
                F::CloseHandle(pipe);
                return Err(e);
            }
            Ok(prefix) => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&prefix);
                let len = u32::from_le_bytes(arr) as usize;
                if len > protocol::MAX_FRAME_BYTES {
                    F::CloseHandle(pipe);
                    return Err("reply frame exceeds 1 MiB".into());
                }
                match read_exact(pipe, len) {
                    Err(e) => {
                        F::CloseHandle(pipe);
                        return Err(e);
                    }
                    Ok(payload) => {
                        let mut frame = prefix;
                        frame.extend_from_slice(&payload);
                        frame
                    }
                }
            }
        };
        F::CloseHandle(pipe);
        Ok(reply)
    }
}

// ---- SCM dispatcher ------------------------------------------------------------------
//
// The --service entry point. Own-process LocalSystem; boot replay before
// accepting takeover; pipe server + 1 s watchdog/scheduler tick; STOP /
// SHUTDOWN / PRESHUTDOWN quiesce, settle and restore with retained debt.
// The control callback never blocks on GUI responses: it dispatches
// PrepareStop on the shared host (worker threads do the pipe/scheduler
// work) and reports STOP_PENDING checkpoints with wait hints.

use crate::clock::SystemClock;
use crate::fs_windows::{WindowsFs, WindowsLock};
use crate::service::{ServiceConfig, ServiceHost};
use crate::windows::{WinSetter, WindowsDnsBackend};
use std::rc::Rc;

type Host = ServiceHost<Rc<WindowsFs>>;

/// Handler-visible state. The control handler runs on an SCM thread and
/// touches ONLY the stop flag (plus the status handle via report_status):
/// the single-threaded [`ServiceHost`] never crosses threads. The service
/// thread observes the flag, runs the stop-path restore itself and reports
/// STOPPED.
struct ServiceGlobals {
    status: Ws::System::Services::SERVICE_STATUS_HANDLE,
    stop: Arc<AtomicBool>,
    /// Set by the handler: which control arrived (STOP/SHUTDOWN/PRESHUTDOWN).
    control: Arc<Mutex<u32>>,
}

static mut GLOBALS: *mut ServiceGlobals = std::ptr::null_mut();

fn report_status(
    state: u32,
    checkpoint: u32,
    wait_hint: u32,
    win32_exit: u32,
    specific_exit: u32,
) {
    use Ws::System::Services as S;
    unsafe {
        if GLOBALS.is_null() {
            return;
        }
        let status = S::SERVICE_STATUS {
            dwServiceType: S::SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == S::SERVICE_RUNNING {
                S::SERVICE_ACCEPT_STOP | S::SERVICE_ACCEPT_SHUTDOWN | S::SERVICE_ACCEPT_PRESHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: win32_exit,
            dwServiceSpecificExitCode: specific_exit,
            dwCheckPoint: checkpoint,
            dwWaitHint: wait_hint,
        };
        S::SetServiceStatus((*GLOBALS).status, &status);
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    use Ws::Foundation as F;
    use Ws::System::Services as S;
    // The handler runs on an SCM thread: record the control, report
    // STOP_PENDING with wait hints and wake the service thread. The service
    // thread runs the stop-path restore itself — the handler never touches
    // the host and never waits on GUI responses.
    let globals: *mut ServiceGlobals = unsafe {
        if GLOBALS.is_null() {
            return F::NO_ERROR;
        }
        GLOBALS
    };
    match control {
        S::SERVICE_CONTROL_STOP | S::SERVICE_CONTROL_SHUTDOWN | S::SERVICE_CONTROL_PRESHUTDOWN => {
            report_status(S::SERVICE_STOP_PENDING, 1, PRESHUTDOWN_TIMEOUT_MS + 30_000, F::NO_ERROR, 0);
            unsafe {
                (*globals).stop.store(true, Ordering::SeqCst);
                if let Ok(mut c) = (*globals).control.lock() {
                    *c = control;
                }
            }
            // Unblock the pipe loop so the service thread observes the stop
            // flag and runs the restore path.
            wake_pipe_server();
            F::NO_ERROR
        }
        S::SERVICE_CONTROL_INTERROGATE => F::NO_ERROR,
        _ => F::NO_ERROR,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    use Ws::Foundation as F;
    use Ws::System::Services as S;
    let name = wide(SERVICE_NAME);
    let status = unsafe {
        S::RegisterServiceCtrlHandlerExW(
            name.as_ptr(),
            Some(control_handler),
            std::ptr::null(),
        )
    };
    if status.is_null() {
        return;
    }
    service_log("service_main: starting");
    // Build the host with the real Windows backends.
    let dir = match program_data_dir() {
        Ok(d) => d,
        Err(_) => {
            let s = S::SERVICE_STATUS {
                dwServiceType: S::SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: S::SERVICE_STOPPED,
                dwControlsAccepted: 0,
                dwWin32ExitCode: F::ERROR_SERVICE_SPECIFIC_ERROR,
                dwServiceSpecificExitCode: 15,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            };
            unsafe {
                S::SetServiceStatus(status, &s);
            }
            return;
        }
    };
    let _ = WindowsLock::new();
    let fs = match WindowsFs::new() {
        Ok(f) => Rc::new(f),
        Err(_) => {
            let s = S::SERVICE_STATUS {
                dwServiceType: S::SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: S::SERVICE_STOPPED,
                dwControlsAccepted: 0,
                dwWin32ExitCode: F::ERROR_SERVICE_SPECIFIC_ERROR,
                dwServiceSpecificExitCode: 13,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            };
            unsafe {
                S::SetServiceStatus(status, &s);
            }
            return;
        }
    };
    service_log("service_main: backends ready, building host");
    let probe = WindowsOwnerProbe::new();
    let probe_factory_probe = probe.clone();
    let fs_build = Rc::clone(&fs);
    let host: Host = ServiceHost::new(
        Rc::new(|| {
            Box::new(WindowsDnsBackend::new(
                crate::backend::FamilySelectorPolicy::VersionGatedException,
            )) as Box<dyn crate::backend::DnsBackend>
        }),
        Rc::new(|| Box::new(WinSetter::new()) as Box<dyn crate::setter::DnsSetter>),
        Rc::new(|| Box::new(WindowsLock) as Box<dyn crate::lock::MachineLock>),
        Box::new(SystemClock),
        Rc::new(|| Box::new(SystemClock) as Box<dyn crate::clock::Clock>),
        Rc::new(move || Rc::clone(&fs_build)),
        Rc::new(move || {
            Box::new(probe_factory_probe.clone()) as Box<dyn OwnerProbe>
        }),
        ServiceConfig {
            dir,
            machine_id: machine_id(),
            service_instance_id: service_instance_id(),
        },
    );
    // The host lives ONLY on the service thread (single-threaded serial
    // worker). The SCM handler thread observes the stop flag + control code
    // through the globals and never touches the host.
    let stop = Arc::new(AtomicBool::new(false));
    let control = Arc::new(Mutex::new(0u32));
    let globals = Box::new(ServiceGlobals {
        status,
        stop: Arc::clone(&stop),
        control: Arc::clone(&control),
    });
    unsafe {
        GLOBALS = Box::into_raw(globals);
    }
    let pending = S::SERVICE_STATUS {
        dwServiceType: S::SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: S::SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: F::NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 30_000,
    };
    unsafe {
        S::SetServiceStatus(status, &pending);
    }

    // Boot replay before accepting any takeover (§8.3).
    let boot_outcome = {
        let r = host.boot_replay();
        format!("{:?}", r.map(|rep| rep.outcome))
    };
    service_log(&format!("service_main: boot replay done: {boot_outcome}"));
    // Restart-with-live-owner monitor: when boot replay reports Busy (a live
    // owner holds the machine lease), hold the recorded owner's handle in the
    // monitor before accepting takeover — no blind restore, no mutation
    // lease. The 1 s watchdog poll below keeps watching it until the owner
    // re-registers (reattach) or dies (restore).
    if let Some(recorded) = host.recorded_owner() {
        let _ = probe.check(&recorded);
    }
    let running = S::SERVICE_STATUS {
        dwServiceType: S::SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: S::SERVICE_RUNNING,
        dwControlsAccepted: S::SERVICE_ACCEPT_STOP
            | S::SERVICE_ACCEPT_SHUTDOWN
            | S::SERVICE_ACCEPT_PRESHUTDOWN,
        dwWin32ExitCode: F::NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    unsafe {
        S::SetServiceStatus(status, &running);
    }
    service_log("service_main: RUNNING, entering pipe loop");

    // Adapter-arrival subscription (§7 step 5): NotifyIpInterfaceChange fires
    // on change; its callback only sets `arrival_pending`, which the service
    // thread polls on its ~1 s tick. The 60 s GetAdaptersAddresses poll below
    // stays as the fallback. The handle is canceled on the stop path.
    let arrival_pending = Arc::new(AtomicBool::new(false));
    let ip_subscription = subscribe_ip_change(&arrival_pending);
    // Tick waker: the pipe loop waits in ConnectNamedPipe, so a helper
    // thread wakes it once per second (open + close, no frame). The wakeup
    // drives the watchdog/scheduler cadence on the service thread without
    // ever sharing the single-threaded host across threads.
    let waker_stop = Arc::clone(&stop);
    let waker = std::thread::spawn(move || {
        while !waker_stop.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            if waker_stop.load(Ordering::SeqCst) {
                break;
            }
            wake_pipe_server();
        }
    });

    // The host is single-threaded by construction (U05 serial worker): the
    // dispatch and tick closures share it through a RefCell on the service
    // thread only. The SCM handler thread never touches it.
    let host = std::cell::RefCell::new(host);
    // Pipe server on the service thread; returns when the stop flag lands.
    let mut ticks: u64 = 0;
    let mut known_adapters: Option<Vec<String>> = None;
    let _ = run_pipe_server(
        |peer, req| {
            let mut h = host.borrow_mut();
            let rep = h.dispatch(peer, req);
            // Hold the owner handle before the register reply (T0); release
            // handles whose leases are gone. Identity is the
            // transport-observed peer, never the request body.
            if req.operation == crate::protocol::Operation::RegisterOwner
                && (rep.outcome == "success")
            {
                if let Some(owner_id) = rep.body.get("owner_id").and_then(|v| v.as_str()) {
                    let identity = crate::journal::OwnerIdentity {
                        owner_id: owner_id.to_string(),
                        pid: peer.pid,
                        creation_time_filetime: peer.creation_filetime,
                        user_sid: peer.user_sid.clone(),
                        logon_luid: peer.logon_luid,
                        session_id: peer.session_id,
                        image_path: peer.image_path.clone(),
                        image_file_id: peer.image_file_id.clone(),
                        image_sha256: peer.image_sha256.clone(),
                    };
                    let _ = probe.check(&identity);
                }
            }
            {
                // Retain handles for live leases AND the journal-recorded
                // owner (restart-with-live-owner monitor): a live owner that
                // has not re-registered yet must stay monitored without a
                // blind restore and without a mutation lease.
                let mut live: Vec<u32> =
                    h.live_owner_ids().iter().map(|(_, pid)| *pid).collect();
                if let Some(recorded) = h.recorded_owner() {
                    if !live.contains(&recorded.pid) {
                        live.push(recorded.pid);
                    }
                }
                probe.release_closed(&live);
            }
            rep
        },
        || {
            // Watchdog/scheduler cadence, ~1 s on the service thread (§8.3):
            // handle-death poll (1 s target), health sweep (6 s expiry),
            // due background passes, arrival triggers (NotifyIpInterfaceChange
            // flag plus the 60 s GetAdaptersAddresses poll fallback).
            let mut h = host.borrow_mut();
            ticks += 1;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            // 1 s watchdog: poll every held owner handle and the journal's
            // recorded owner; a dead result restores inside the target, a
            // live result keeps the handle. Never relaunches a GUI.
            let _ = h.watchdog_poll();
            let _ = h.sweep(now);
            if h.next_wake_ms().is_some_and(|w| w <= now) {
                let _ = h.background_tick();
            }
            let arrival_fired = arrival_pending.swap(false, Ordering::SeqCst);
            if ticks % 60 == 0 || arrival_fired {
                if let Ok(adapters) = list_adapter_guids() {
                    let added: Vec<String> = match &known_adapters {
                        None => Vec::new(),
                        Some(known) => adapters
                            .iter()
                            .filter(|a| !known.contains(a))
                            .cloned()
                            .collect(),
                    };
                    if !added.is_empty() {
                        let _ = h.notify_arrival(&added);
                    }
                    known_adapters = Some(adapters);
                }
            }
        },
        Arc::clone(&stop),
    );
    let _ = waker.join();
    // Stop path: cancel the adapter-arrival subscription first
    // (CancelMibChangeNotify2), so no callback can fire after the host below
    // starts tearing down. The callback only ever set a flag, so there is no
    // in-flight journal or pipe work to drain.
    if let Some(handle) = ip_subscription {
        cancel_ip_change(handle);
    }
    // The stop flag landed: run the SCM stop path on the service thread
    // (quiesce, settle, restore with bounded retry; debt retained) and
    // report STOPPED with a nonzero service-specific exit when recovery is
    // incomplete. The control handler already reported STOP_PENDING.
    let reason = match control.lock().map(|c| *c).unwrap_or(0) {
        c if c == Ws::System::Services::SERVICE_CONTROL_STOP => "scm_stop",
        c if c == Ws::System::Services::SERVICE_CONTROL_SHUTDOWN => "scm_shutdown",
        _ => "scm_preshutdown",
    };
    let stop_req = Request::new(
        crate::journal::new_uuid(),
        crate::protocol::Operation::PrepareStop,
        None,
        None,
        serde_json::json!({"reason": reason}),
    );
    // The SCM identity authorizes the stop path; it is not an owner lease.
    // The stop peer carries no owner image identity (PrepareStop is admin,
    // not owner-bound), so the new fields stay empty here by construction.
    let peer = PeerAuth {
        pid: std::process::id(),
        creation_filetime: 1,
        user_sid: "S-1-5-18".into(),
        elevated: true,
        session_id: 0,
        logon_luid: 999,
        image_path: std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        image_file_id: String::new(),
        image_sha256: String::new(),
        remote: false,
        server_pid: None,
        expected_server_pid: None,
    };
    let reply = host.borrow_mut().dispatch(&peer, &stop_req);
    let specific = protocol::exit_code_for_outcome(&reply.outcome) as u32;
    report_status(
        Ws::System::Services::SERVICE_STOP_PENDING,
        2,
        5_000,
        F::NO_ERROR,
        0,
    );
    if reply.outcome == "verified_restored" {
        report_status(Ws::System::Services::SERVICE_STOPPED, 0, 0, F::NO_ERROR, 0);
    } else {
        // Incomplete recovery: nonzero service-specific result with the debt
        // retained. Windows may still stop us; replay on next start/restart
        // settles it.
        report_status(
            Ws::System::Services::SERVICE_STOPPED,
            0,
            0,
            F::ERROR_SERVICE_SPECIFIC_ERROR,
            specific,
        );
    }
}

/// Stable machine identity for genesis-journal creation. The durable machine
/// id lives in the journal envelope (adopted on every non-genesis commit —
/// the store never rewrites it), so this candidate only matters for the very
/// first journal on a machine: computer name + journal-volume serial hashed
/// into UUID-v4 shape. Stable across reboots and service restarts.
pub fn machine_id() -> String {
    use sha2::{Digest, Sha256};
    let mut seed = Vec::new();
    unsafe {
        let mut name = vec![0u16; 256];
        let mut size = name.len() as u32;
        if Ws::System::WindowsProgramming::GetComputerNameW(name.as_mut_ptr(), &mut size) != 0
        {
            for c in name.iter().take(size as usize) {
                seed.extend_from_slice(&c.to_le_bytes());
            }
        }
        let root = wide("C:\\");
        let mut serial = 0u32;
        if Ws::Storage::FileSystem::GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            seed.extend_from_slice(&serial.to_le_bytes());
        }
    }
    if seed.is_empty() {
        // No stable seed available: random (documented fallback; the first
        // durable journal still pins whatever id it was created with).
        return crate::journal::new_uuid();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"yeager-dns-machine-id-v1");
    hasher.update(&seed);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Fresh service instance id per process start (never persisted, §3.2: no
/// pipe/lease secrets in the journal — the instance id links reports only).
pub fn service_instance_id() -> String {
    crate::journal::new_uuid()
}

/// SCM dispatcher entry for `--service`. Only returns on failure to connect
/// to the SCM (i.e. not started as a service).
pub fn run_service() -> Result<(), String> {
    use Ws::System::Services as S;
    let name = wide(SERVICE_NAME);
    let table = [
        S::SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr() as *mut u16,
            lpServiceProc: Some(service_main),
        },
        S::SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    unsafe {
        if S::StartServiceCtrlDispatcherW(table.as_ptr()) == 0 {
            return Err(format!(
                "StartServiceCtrlDispatcherW failed (not started by SCM?): {}",
                last_error()
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    #[test]
    fn ip_change_callback_only_enqueues_flag() {
        // The NotifyIpInterfaceChange callback must never touch the journal,
        // the pipe or the host: it only sets the flag the service thread
        // polls. Invoke it directly and prove nothing else happens.
        let flag = Arc::new(AtomicBool::new(false));
        let ctx = Arc::as_ptr(&flag) as *const std::ffi::c_void;
        unsafe {
            ip_change_callback(ctx, std::ptr::null(), 0);
        }
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn notify_ip_interface_subscribe_and_cancel_roundtrips() {
        // Subscribe AF_UNSPEC, then cancel on the stop path. A failed
        // subscription is tolerated by the service (60 s poll fallback), but
        // on this machine it must succeed.
        let flag = Arc::new(AtomicBool::new(false));
        let handle = subscribe_ip_change(&flag);
        assert!(
            handle.is_some(),
            "NotifyIpInterfaceChange(AF_UNSPEC) must subscribe"
        );
        if let Some(h) = handle {
            cancel_ip_change(h);
        }
    }

    #[test]
    fn server_image_check_rejects_non_service_image() {
        // Fail-closed comparison: this test binary is not the protected
        // service image, so verification of our own PID must refuse.
        let expected = protected_service_image().expect("program files resolves");
        assert!(
            expected.to_lowercase().ends_with("yeager-dns-recovery.exe"),
            "protected path ends with the service binary: {expected:?}"
        );
        assert!(
            verify_server_image(std::process::id()).is_err(),
            "a non-service image must never pass the server identity check"
        );
    }

    fn test_pipe_name() -> Vec<u16> {
        // Unique local pipe: never the production service pipe.
        let name = format!(
            r"\\.\pipe\Yeager.DnsRecovery.Test.{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        wide(&name)
    }

    #[test]
    fn stalled_partial_frame_dropped_at_deadline_while_stop_proceeds() {
        use Ws::Foundation as F;
        use Ws::Storage::FileSystem as FS;
        use Ws::System::Pipes as P;
        // Server pipe (overlapped, like the service pipe) + a client that
        // connects, sends a partial frame and then stalls for 5 s. The
        // server read must drop the client at the 2 s deadline, and a stop
        // flag set mid-stall must be observed right after — the stop path
        // proceeds instead of waiting out the stalled client.
        let name = test_pipe_name();
        let server = unsafe {
            P::CreateNamedPipeW(
                name.as_ptr(),
                FS::PIPE_ACCESS_DUPLEX | FS::FILE_FLAG_OVERLAPPED,
                P::PIPE_TYPE_BYTE | P::PIPE_READMODE_BYTE | P::PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(server, F::INVALID_HANDLE_VALUE);
        assert!(!server.is_null());
        let client = std::thread::spawn({
            let name = name.clone();
            move || unsafe {
                // Connect and stall: declare a 64-byte frame, deliver 4.
                let h = FS::CreateFileW(
                    name.as_ptr(),
                    F::GENERIC_READ | F::GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    FS::OPEN_EXISTING,
                    FS::FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                );
                assert_ne!(h, F::INVALID_HANDLE_VALUE);
                let prefix = 64u32.to_le_bytes();
                let mut wrote = 0u32;
                let mut ov: Ws::System::IO::OVERLAPPED = std::mem::zeroed();
                assert_ne!(
                    FS::WriteFile(h, prefix.as_ptr(), 4, &mut wrote, &mut ov),
                    0
                );
                let part = [0x7bu8; 4];
                assert_ne!(
                    FS::WriteFile(h, part.as_ptr(), 4, &mut wrote, &mut ov),
                    0
                );
                std::thread::sleep(Duration::from_millis(5000));
                F::CloseHandle(h);
            }
        });
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                std::thread::sleep(Duration::from_millis(500));
                stop.store(true, Ordering::SeqCst);
            }
        });
        let t0 = Instant::now();
        match connect_with_stop(server, &stop) {
            ConnectOutcome::Connected => {}
            other => panic!("test client connect failed: {}", matches!(other, ConnectOutcome::Stop)),
        }
        let err = read_exact_deadline(server, 4 + 64, 2000).expect_err("stall must time out");
        let elapsed = t0.elapsed();
        assert!(
            err.contains("deadline"),
            "stalled frame dropped at the deadline, got: {err}"
        );
        // The deadline (not the 8 s client stall) bounds the read: generous
        // bounds for loaded CI, but far from the stall duration.
        assert!(
            elapsed >= Duration::from_millis(1500),
            "deadline respected, elapsed {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(6000),
            "dropped at the deadline, elapsed {elapsed:?}"
        );
        // The stop set mid-stall is observed right after the drop.
        assert!(
            stop.load(Ordering::SeqCst),
            "stop flag set during the stall is visible after the drop"
        );
        assert!(
            t0.elapsed() < Duration::from_millis(7000),
            "stop path proceeds without waiting out the stalled client"
        );
        unsafe {
            P::DisconnectNamedPipe(server);
            F::CloseHandle(server);
        }
        let _ = stopper.join();
        let _ = client.join();
    }
}

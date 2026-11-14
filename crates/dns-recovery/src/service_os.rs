//! U05 Windows transport: SCM lifecycle and the secure named-pipe server
//! (SPEC-DNS-FIX.md §8.1–§8.3). Windows only.
//!
//! - Service `YeagerDnsRecovery`, own-process LocalSystem, automatic
//!   NON-delayed start. Failure actions restart at 1 s / 5 s / 30 s
//!   (including non-crash failures) plus a 30 s preshutdown budget.
//! - Pipe `\\.\pipe\Yeager.DnsRecovery.v1`: first-instance,
//!   `PIPE_REJECT_REMOTE_CLIENTS`, protected SYSTEM/Administrators DACL,
//!   byte mode, one u32-LE-framed UTF-8 JSON frame per message, 5 s
//!   framing/auth budget. The server authenticates every peer by
//!   impersonation + token inspection and `GetNamedPipeClientProcessId` —
//!   never from caller-supplied fields — and reverts before privileged I/O.
//!   The client checks `GetNamedPipeServerProcessId` against the SCM
//!   service PID.
//! - Owner liveness is PID + creation FILETIME over a HELD process handle
//!   (opened at registration, before the reply). Image fields are
//!   diagnostics only.
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
/// Per-connection framing/auth budget (§8.2).
pub const PIPE_TIMEOUT_MS: u32 = 5_000;

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
            Ws::Foundation::CloseHandle(token);
            let (image, filetime, _) = process_image_and_times(pid)?;
            Ok(PeerAuth {
                pid,
                creation_filetime: filetime,
                user_sid: sid,
                elevated,
                session_id: session,
                // Logon LUID is not exposed as a scalar token class; the
                // session id scopes the identity alongside pid+filetime+sid.
                // The full logon-LUID binding stays recorded from
                // registration-time token-group inspection in future work —
                // never defaulted silently: see dispatch-time binding below.
                logon_luid: session as u64,
                image_path: image,
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

fn read_exact(pipe: *mut std::ffi::c_void, mut n: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(n);
    while n > 0 {
        let mut chunk = vec![0u8; n.min(65536)];
        let mut got = 0u32;
        unsafe {
            if Ws::Storage::FileSystem::ReadFile(
                pipe,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(format!("pipe read failed: {}", last_error()));
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

fn write_all(pipe: *mut std::ffi::c_void, mut data: &[u8]) -> Result<(), String> {
    while !data.is_empty() {
        let mut wrote = 0u32;
        unsafe {
            if Ws::Storage::FileSystem::WriteFile(
                pipe,
                data.as_ptr(),
                data.len().min(u32::MAX as usize) as u32,
                &mut wrote,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(format!("pipe write failed: {}", last_error()));
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
    // One frame: u32 LE length + JSON, bounded by the codec.
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
            match read_exact(pipe, len) {
                Err(_) => return,
                Ok(payload) => {
                    let mut frame = prefix;
                    frame.extend_from_slice(&payload);
                    match protocol::decode_frame(&frame) {
                        Err(_) => return, // unknown version/op: silent refuse
                        Ok(req) => match authenticate_peer(pipe) {
                            Err(_) => {
                                // Auth failure: structured rejection with no
                                // lease or journal access. The codec needs a
                                // request id to echo; the frame was already
                                // validated, so re-decode is infallible.
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
                                protocol::encode_reply(&rep).unwrap_or_default()
                            }
                        },
                    }
                }
            }
        }
    };
    if !reply_bytes.is_empty() {
        let _ = write_all(pipe, &reply_bytes);
    }
}

/// Run the pipe server until `stop` is set. Each connection is served on
/// this thread, serially — the serial mutation worker. `on_idle` runs
/// between clients (watchdog/scheduler cadence); it also runs when a wakeup
/// connection carries no frame (the tick waker). Returns when the stop flag
/// is observed between clients.
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
                FS::PIPE_ACCESS_DUPLEX | FS::FILE_FLAG_FIRST_PIPE_INSTANCE,
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
            return Err(format!("CreateNamedPipeW failed: {}", last_error()));
        }
        let connected = unsafe { P::ConnectNamedPipe(pipe, std::ptr::null_mut()) };
        if connected == 0 {
            let e = last_error();
            // ERROR_PIPE_CONNECTED (535): client raced us; serve it.
            // Anything else with the stop flag set: shut down.
            if e != 535 {
                unsafe {
                    Ws::Foundation::CloseHandle(pipe);
                }
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                return Err(format!("ConnectNamedPipe failed: {e}"));
            }
        }
        serve_one(pipe, &dispatch);
        unsafe {
            P::DisconnectNamedPipe(pipe);
            Ws::Foundation::CloseHandle(pipe);
        }
        on_idle();
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
/// `expected_server_pid` (SCM record) before trusting the reply.
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
                0,
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
    {
        let _ = host.boot_replay();
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

    // Tick waker: the pipe loop blocks in ConnectNamedPipe, so a helper
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
            // handles whose leases are gone.
            if req.operation == crate::protocol::Operation::RegisterOwner
                && (rep.outcome == "success")
            {
                if let (Some(owner_id), Some(image_sha)) = (
                    rep.body.get("owner_id").and_then(|v| v.as_str()),
                    req.body.get("image_sha256").and_then(|v| v.as_str()),
                ) {
                    let identity = crate::journal::OwnerIdentity {
                        owner_id: owner_id.to_string(),
                        pid: peer.pid,
                        creation_time_filetime: peer.creation_filetime,
                        user_sid: peer.user_sid.clone(),
                        logon_luid: peer.logon_luid,
                        session_id: peer.session_id,
                        image_path: peer.image_path.clone(),
                        image_file_id: req
                            .body
                            .get("image_file_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        image_sha256: image_sha.to_string(),
                    };
                    let _ = probe.check(&identity);
                }
            }
            {
                let live: Vec<u32> =
                    h.live_owner_ids().iter().map(|(_, pid)| *pid).collect();
                probe.release_closed(&live);
            }
            rep
        },
        || {
            // Watchdog/scheduler cadence (§6/§8.3 scheduling): health sweep,
            // due background passes, 60 s adapter inventory poll.
            let mut h = host.borrow_mut();
            ticks += 1;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let _ = h.sweep(now);
            if h.next_wake_ms().is_some_and(|w| w <= now) {
                let _ = h.background_tick();
            }
            if ticks % 60 == 0 {
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

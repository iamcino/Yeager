//! Protected ACL contract for the journal directory, journal files and the
//! shared mutex (U02, SPEC-DNS-FIX.md §3.1).
//!
//! Directory: owner/group SYSTEM, protected DACL granting SYSTEM and
//! Builtin\Administrators full control with inheritance (OICI). Journal files
//! and the mutex: the same two principals, full control, protected, and NO
//! inheritance flags. Validation is exact — any extra/missing/different ACE,
//! wrong owner/group, or unprotected DACL fails closed.

pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";

pub const DIR_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
pub const FILE_SDDL: &str = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
pub const MUTEX_SDDL: &str = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)";

pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
pub const MUTEX_ALL_ACCESS: u32 = 0x001F_0001;
/// OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
pub const OICI: u8 = 0x3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    pub allow: bool,
    pub sid: String,
    pub mask: u32,
    pub inherit_flags: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityInfo {
    pub owner: String,
    pub group: String,
    pub protected_dacl: bool,
    pub aces: Vec<Ace>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Directory,
    File,
    Mutex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityError(pub String);

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "security validation failed: {}", self.0)
    }
}

impl std::error::Error for SecurityError {}

/// Exact protected-DACL validation. Order of the two ACEs is irrelevant;
/// anything beyond the two required allow ACEs is a failure.
pub fn validate_journal_security(info: &SecurityInfo, kind: ObjectKind) -> Result<(), SecurityError> {
    let bad = |m: String| SecurityError(m);
    if info.owner != SID_SYSTEM {
        return Err(bad(format!("owner is {}, expected SYSTEM", info.owner)));
    }
    if info.group != SID_SYSTEM {
        return Err(bad(format!("group is {}, expected SYSTEM", info.group)));
    }
    if !info.protected_dacl {
        return Err(bad("DACL is not protected".into()));
    }
    let (mask, inherit) = match kind {
        ObjectKind::Directory => (FILE_ALL_ACCESS, OICI),
        ObjectKind::File => (FILE_ALL_ACCESS, 0),
        ObjectKind::Mutex => (MUTEX_ALL_ACCESS, 0),
    };
    if info.aces.len() != 2 {
        return Err(bad(format!("expected exactly 2 ACEs, found {}", info.aces.len())));
    }
    let mut seen_sy = false;
    let mut seen_ba = false;
    for ace in &info.aces {
        if !ace.allow {
            return Err(bad("deny ACE present".into()));
        }
        if ace.mask != mask || ace.inherit_flags != inherit {
            return Err(bad(format!(
                "ACE for {} has mask {:#x}/inherit {:#x}, expected {:#x}/{:#x}",
                ace.sid, ace.mask, ace.inherit_flags, mask, inherit
            )));
        }
        match ace.sid.as_str() {
            SID_SYSTEM => seen_sy = true,
            SID_ADMINISTRATORS => seen_ba = true,
            other => return Err(bad(format!("unexpected principal {other}"))),
        }
    }
    if !seen_sy || !seen_ba {
        return Err(bad("missing SYSTEM or Administrators ACE".into()));
    }
    Ok(())
}

#[cfg(windows)]
pub mod win {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{LocalFree, BOOL, HLOCAL, WIN32_ERROR};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };

    /// Owned self-relative security descriptor built from an SDDL string.
    pub struct Sddl {
        pub ptr: PSECURITY_DESCRIPTOR,
    }

    impl Sddl {
        pub fn parse(sddl: &str) -> Result<Self, SecurityError> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut ptr: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1, // SDDL_REVISION_1
                    &mut ptr,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || ptr.is_null() {
                return Err(SecurityError(format!("SDDL parse failed for {sddl:?}")));
            }
            Ok(Self { ptr })
        }
    }

    impl Drop for Sddl {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.ptr as HLOCAL);
            }
        }
    }

    fn sid_string(sid: *mut c_void) -> Result<String, SecurityError> {
        let mut p: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 || p.is_null() {
            return Err(SecurityError("ConvertSidToStringSidW failed".into()));
        }
        let s = unsafe {
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        };
        unsafe {
            LocalFree(p as HLOCAL);
        }
        Ok(s)
    }

    fn read_sd(sd: PSECURITY_DESCRIPTOR) -> Result<SecurityInfo, SecurityError> {
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut group: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut present: BOOL = 0;
        let mut defaulted: BOOL = 0;
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        unsafe {
            if GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) == 0 {
                return Err(SecurityError("GetSecurityDescriptorOwner failed".into()));
            }
            if GetSecurityDescriptorGroup(sd, &mut group, &mut defaulted) == 0 {
                return Err(SecurityError("GetSecurityDescriptorGroup failed".into()));
            }
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
                return Err(SecurityError("GetSecurityDescriptorDacl failed".into()));
            }
            if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0 {
                return Err(SecurityError("GetSecurityDescriptorControl failed".into()));
            }
        }
        let owner = if owner.is_null() {
            String::new()
        } else {
            sid_string(owner)?
        };
        let group = if group.is_null() {
            String::new()
        } else {
            sid_string(group)?
        };
        let mut aces = Vec::new();
        if present != 0 && !dacl.is_null() {
            let mut size = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            let ok = unsafe {
                GetAclInformation(
                    dacl,
                    &mut size as *mut _ as *mut c_void,
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            };
            if ok == 0 {
                return Err(SecurityError("GetAclInformation failed".into()));
            }
            for i in 0..size.AceCount {
                let mut raw: *mut c_void = std::ptr::null_mut();
                if unsafe { GetAce(dacl, i, &mut raw) } == 0 || raw.is_null() {
                    return Err(SecurityError("GetAce failed".into()));
                }
                let header = unsafe { &*(raw as *const ACE_HEADER) };
                let allow = match header.AceType {
                    0 => true,  // ACCESS_ALLOWED_ACE_TYPE
                    1 => false, // ACCESS_DENIED_ACE_TYPE
                    t => return Err(SecurityError(format!("unexpected ACE type {t}"))),
                };
                let ace = unsafe { &*(raw as *const ACCESS_ALLOWED_ACE) };
                let sid = sid_string(&ace.SidStart as *const u32 as *mut c_void)?;
                aces.push(Ace {
                    allow,
                    sid,
                    mask: ace.Mask,
                    inherit_flags: header.AceFlags,
                });
            }
        }
        Ok(SecurityInfo {
            owner,
            group,
            protected_dacl: control & SE_DACL_PROTECTED != 0,
            aces,
        })
    }

    /// Read owner/group/DACL of a named file-system object.
    pub fn read_named_security(path: &str) -> Result<SecurityInfo, SecurityError> {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status: WIN32_ERROR = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if status != 0 {
            return Err(SecurityError(format!(
                "GetNamedSecurityInfoW failed for {path:?}: {status}"
            )));
        }
        let result = read_sd(sd);
        unsafe {
            LocalFree(sd as HLOCAL);
        }
        result
    }

    /// Read owner/group/DACL of a kernel object (mutex) from an open handle.
    pub fn read_handle_security(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<SecurityInfo, SecurityError> {
        use windows_sys::Win32::Security::GetKernelObjectSecurity;
        let mut needed: u32 = 0;
        unsafe {
            GetKernelObjectSecurity(
                handle,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed == 0 {
            return Err(SecurityError("GetKernelObjectSecurity size query failed".into()));
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            GetKernelObjectSecurity(
                handle,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                buf.as_mut_ptr() as PSECURITY_DESCRIPTOR,
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(SecurityError("GetKernelObjectSecurity failed".into()));
        }
        read_sd(buf.as_mut_ptr() as PSECURITY_DESCRIPTOR)
    }

    /// Apply owner/group/protected DACL from an SDDL string to a named object.
    /// Setting owner SYSTEM requires SeRestorePrivilege (enabled by callers).
    pub fn apply_named_sddl(path: &str, sddl: &str) -> Result<(), SecurityError> {
        let sd = Sddl::parse(sddl)?;
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut group: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut present: BOOL = 0;
        let mut defaulted: BOOL = 0;
        unsafe {
            if GetSecurityDescriptorOwner(sd.ptr, &mut owner, &mut defaulted) == 0
                || GetSecurityDescriptorGroup(sd.ptr, &mut group, &mut defaulted) == 0
                || GetSecurityDescriptorDacl(sd.ptr, &mut present, &mut dacl, &mut defaulted) == 0
                || present == 0
            {
                return Err(SecurityError("SDDL missing owner/group/DACL".into()));
            }
        }
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                group,
                dacl,
                std::ptr::null(),
            )
        };
        if status != 0 {
            return Err(SecurityError(format!(
                "SetNamedSecurityInfoW failed for {path:?}: {status}"
            )));
        }
        Ok(())
    }
}

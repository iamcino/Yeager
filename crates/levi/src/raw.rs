use std::path::Path;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

pub const INVALID_HANDLE_VALUE: usize = usize::MAX;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SafeHandle(pub usize);

impl SafeHandle {
    pub fn null() -> Self {
        Self(0)
    }

    pub fn is_invalid(self) -> bool {
        self.0 == 0 || self.0 == INVALID_HANDLE_VALUE
    }

    pub fn as_raw(self) -> *mut std::ffi::c_void {
        self.0 as *mut std::ffi::c_void
    }

    pub fn from_raw(raw: *mut std::ffi::c_void) -> Self {
        Self(raw as usize)
    }
}

pub const WINDIVERT_LAYER_NETWORK: u32 = 0;
pub const WINDIVERT_FLAG_SNIFF: u64 = 1;
pub const WINDIVERT_FLAG_DROP: u64 = 2;

pub const WINDIVERT_PARAM_QUEUE_LENGTH: u32 = 0;
pub const WINDIVERT_PARAM_QUEUE_TIME: u32 = 1;
pub const WINDIVERT_PARAM_QUEUE_SIZE: u32 = 2;

/// WinDivert 2.2 Address Structure (80 bytes total).
/// Must match `WINDIVERT_ADDRESS` in WinDivert 2.2 `windivert.h`.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WinDivertAddress {
    pub timestamp: i64,      // 0..8 (8 bytes)
    pub bitfields: u32,      // 8..12 (4 bytes): Layer (8), Event (8), Flags (16)
    pub reserved2: u32,      // 12..16 (4 bytes)
    pub if_idx: u32,         // 16..20 (4 bytes, Network.IfIdx)
    pub sub_if_idx: u32,     // 20..24 (4 bytes, Network.SubIfIdx)
    pub reserved3: [u8; 56], // 24..80 (56 bytes, completes 64-byte union)
}

const _: () = assert!(std::mem::size_of::<WinDivertAddress>() == 80);

impl WinDivertAddress {
    #[inline]
    pub fn is_outbound(&self) -> bool {
        (self.bitfields & (1 << 17)) != 0
    }

    #[inline]
    pub fn set_outbound(&mut self, val: bool) {
        if val {
            self.bitfields |= 1 << 17;
        } else {
            self.bitfields &= !(1 << 17);
        }
    }

    #[inline]
    pub fn is_ipv6(&self) -> bool {
        (self.bitfields & (1 << 20)) != 0
    }

    #[inline]
    pub fn set_ipv6(&mut self, val: bool) {
        if val {
            self.bitfields |= 1 << 20;
        } else {
            self.bitfields &= !(1 << 20);
        }
    }

    #[inline]
    pub fn is_loopback(&self) -> bool {
        (self.bitfields & (1 << 18)) != 0
    }

    #[inline]
    pub fn is_impostor(&self) -> bool {
        (self.bitfields & (1 << 19)) != 0
    }

    #[inline]
    pub fn set_impostor(&mut self, val: bool) {
        if val {
            self.bitfields |= 1 << 19;
        } else {
            self.bitfields &= !(1 << 19);
        }
    }
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

type FnWinDivertOpen = unsafe extern "system" fn(
    filter: *const i8,
    layer: u32,
    priority: i16,
    flags: u64,
) -> *mut std::ffi::c_void;

type FnWinDivertRecv = unsafe extern "system" fn(
    handle: *mut std::ffi::c_void,
    packet: *mut u8,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut WinDivertAddress,
) -> i32;

type FnWinDivertSend = unsafe extern "system" fn(
    handle: *mut std::ffi::c_void,
    packet: *const u8,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const WinDivertAddress,
) -> i32;

type FnWinDivertClose = unsafe extern "system" fn(handle: *mut std::ffi::c_void) -> i32;

type FnWinDivertSetParam = unsafe extern "system" fn(
    handle: *mut std::ffi::c_void,
    param: u32,
    value: u64,
) -> i32;

type FnWinDivertHelperCalcChecksums = unsafe extern "system" fn(
    packet: *mut u8,
    packet_len: u32,
    addr: *mut WinDivertAddress,
    flags: u64,
) -> u32;

pub struct WinDivertApi {
    _module: HMODULE,
    pub open: FnWinDivertOpen,
    pub recv: FnWinDivertRecv,
    pub send: FnWinDivertSend,
    pub close: FnWinDivertClose,
    pub set_param: FnWinDivertSetParam,
    pub calc_checksums: FnWinDivertHelperCalcChecksums,
}

unsafe impl Send for WinDivertApi {}
unsafe impl Sync for WinDivertApi {}

impl WinDivertApi {
    pub fn load(dll_path: &Path) -> Result<Self, String> {
        let wide: Vec<u16> = dll_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let hmod = unsafe { LoadLibraryW(wide.as_ptr()) };
        if hmod.is_null() {
            return Err(format!(
                "Failed to load WinDivert.dll at {:?}",
                dll_path
            ));
        }

        unsafe {
            let open_sym = GetProcAddress(hmod, b"WinDivertOpen\0".as_ptr());
            let recv_sym = GetProcAddress(hmod, b"WinDivertRecv\0".as_ptr());
            let send_sym = GetProcAddress(hmod, b"WinDivertSend\0".as_ptr());
            let close_sym = GetProcAddress(hmod, b"WinDivertClose\0".as_ptr());
            let set_param_sym = GetProcAddress(hmod, b"WinDivertSetParam\0".as_ptr());
            let calc_sym = GetProcAddress(hmod, b"WinDivertHelperCalcChecksums\0".as_ptr());

            if open_sym.is_none() || recv_sym.is_none() || send_sym.is_none() || close_sym.is_none() || set_param_sym.is_none() {
                return Err("Failed to resolve WinDivert function symbols".into());
            }

            Ok(Self {
                _module: hmod,
                open: std::mem::transmute(open_sym),
                recv: std::mem::transmute(recv_sym),
                send: std::mem::transmute(send_sym),
                close: std::mem::transmute(close_sym),
                set_param: std::mem::transmute(set_param_sym),
                calc_checksums: std::mem::transmute(calc_sym),
            })
        }
    }
}

use std::os::windows::ffi::OsStrExt;

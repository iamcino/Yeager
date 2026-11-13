//! Fault-injectable filesystem abstraction for the durable journal (U02,
//! SPEC-DNS-FIX.md §3.3). The store performs every operation through
//! [`JournalFs`]; [`FakeFs`] implements the documented Windows semantics
//! (including all four ReplaceFileW failure layouts) with injectable faults.
//! The real Windows implementation lives in `fs_windows.rs`.
//!
//! No optimistic rename durability: the store always follows write → file
//! flush → replace → primary reopen/verify → primary flush → volume flush.

use crate::journal::MAX_JOURNAL_BYTES;
use crate::security::{
    validate_journal_security, ObjectKind, SecurityError, SecurityInfo, SID_ADMINISTRATORS,
    SID_SYSTEM, FILE_ALL_ACCESS, OICI,
};
use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    AlreadyExists,
    DiskFull,
    SharingViolation,
    AccessDenied,
    NotNtfs,
    NetworkStorage,
    ReparsePoint,
    HardLink,
    BadSecurity(String),
    VolumeFlushUnsupported,
    InvalidPath(String),
    Io { code: u32, context: String },
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsError::NotFound => write!(f, "file not found"),
            FsError::AlreadyExists => write!(f, "file already exists"),
            FsError::DiskFull => write!(f, "disk full"),
            FsError::SharingViolation => write!(f, "sharing violation"),
            FsError::AccessDenied => write!(f, "access denied"),
            FsError::NotNtfs => write!(f, "volume is not NTFS"),
            FsError::NetworkStorage => write!(f, "network storage"),
            FsError::ReparsePoint => write!(f, "reparse point"),
            FsError::HardLink => write!(f, "unexpected hard link"),
            FsError::BadSecurity(m) => write!(f, "bad security: {m}"),
            FsError::VolumeFlushUnsupported => write!(f, "volume flush unsupported"),
            FsError::InvalidPath(m) => write!(f, "invalid path: {m}"),
            FsError::Io { code, context } => write!(f, "I/O error {code}: {context}"),
        }
    }
}

impl std::error::Error for FsError {}

impl From<SecurityError> for FsError {
    fn from(e: SecurityError) -> Self {
        FsError::BadSecurity(e.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageKind {
    LocalNtfs,
    NonNtfs,
    Network,
}

/// Named fault-injection points covering the full durable-write pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    CreateNew,
    Write,
    FileFlush,
    StageReadback,
    Replace,
    Move,
    PrimaryReopen,
    PrimaryFlush,
    VolumeFlush,
    CleanupDelete,
    CleanupVolumeFlush,
}

/// ReplaceFileW documented failure shapes (backup specified, flags = 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplaceFailure {
    /// ERROR_UNABLE_TO_MOVE_REPLACEMENT (1176): primary=old, stage=new, no backup.
    UnableToMoveReplacement,
    /// ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 (1177): primary missing, backup=old,
    /// stage=new.
    UnableToMoveReplacement2,
    /// ERROR_UNABLE_TO_REMOVE_REPLACED (1175): both retain their names.
    UnableToRemoveReplaced,
    /// Any other error: both retain their names, no backup.
    Other(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    Error(FsError),
    /// Write only half the bytes, report success (caught by stage readback).
    PartialWrite,
    ReplaceShape(ReplaceFailure),
}

/// Object-safe filesystem contract. Handles are opaque u64. Purpose-specific
/// read/flush methods exist so faults can target exact pipeline stages.
pub trait JournalFs {
    fn ensure_directory(&self, dir: &str) -> Result<(), FsError>;
    fn directory_security(&self, dir: &str) -> Result<SecurityInfo, FsError>;
    fn storage_kind(&self, dir: &str) -> Result<StorageKind, FsError>;
    /// Primary + stage/backup candidate file names (full paths), sorted.
    fn list_candidates(&self, dir: &str) -> Result<Vec<String>, FsError>;
    /// CREATE_NEW with restricted non-inheritable ACL, exclusive, write-through.
    fn create_new(&self, path: &str) -> Result<u64, FsError>;
    fn write_all(&self, h: u64, data: &[u8]) -> Result<(), FsError>;
    fn flush_file(&self, h: u64) -> Result<(), FsError>;
    fn close(&self, h: u64) -> Result<(), FsError>;
    /// Full security/reparse/hardlink/size-checked read (reconciliation).
    fn read_file(&self, path: &str) -> Result<Vec<u8>, FsError>;
    fn file_security(&self, path: &str) -> Result<SecurityInfo, FsError>;
    /// ReplaceFileW(primary, stage, backup, flags=0).
    fn replace(&self, primary: &str, stage: &str, backup: &str) -> Result<(), FsError>;
    /// MoveFileExW(MOVEFILE_WRITE_THROUGH) — first primary only, same volume.
    fn move_write_through(&self, from: &str, to: &str) -> Result<(), FsError>;
    fn delete(&self, path: &str) -> Result<(), FsError>;
    fn flush_volume(&self, path: &str) -> Result<(), FsError>;
    /// Open/flush/close the primary for the post-replacement barrier.
    fn flush_file_at(&self, path: &str) -> Result<(), FsError>;

    fn read_stage_back(&self, path: &str) -> Result<Vec<u8>, FsError> {
        self.read_file(path)
    }
    fn reopen_primary(&self, path: &str) -> Result<Vec<u8>, FsError> {
        self.read_file(path)
    }
    fn flush_volume_post_cleanup(&self, path: &str) -> Result<(), FsError> {
        self.flush_volume(path)
    }
}

/// Expected protected security for each object kind (used by fakes/tests).
pub fn expected_security(kind: ObjectKind) -> SecurityInfo {
    let (mask, inherit) = match kind {
        ObjectKind::Directory => (FILE_ALL_ACCESS, OICI),
        ObjectKind::File => (FILE_ALL_ACCESS, 0),
        ObjectKind::Mutex => (crate::security::MUTEX_ALL_ACCESS, 0),
    };
    SecurityInfo {
        owner: SID_SYSTEM.to_string(),
        group: SID_SYSTEM.to_string(),
        protected_dacl: true,
        aces: vec![
            crate::security::Ace {
                allow: true,
                sid: SID_SYSTEM.to_string(),
                mask,
                inherit_flags: inherit,
            },
            crate::security::Ace {
                allow: true,
                sid: SID_ADMINISTRATORS.to_string(),
                mask,
                inherit_flags: inherit,
            },
        ],
    }
}

// ---- FakeFs ----------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub creates: u64,
    pub writes: u64,
    pub file_flushes: u64,
    pub reads: u64,
    pub replaces: u64,
    pub moves: u64,
    pub volume_flushes: u64,
    pub deletes: u64,
}

#[derive(Clone, Debug)]
struct FakeFile {
    data: Vec<u8>,
    security: SecurityInfo,
    links: u32,
    reparse: bool,
    file_id: u64,
}

#[derive(Clone, Debug)]
struct FakeHandle {
    path: String,
}

#[derive(Default)]
struct Inner {
    files: HashMap<String, FakeFile>,
    dirs: HashMap<String, SecurityInfo>,
    handles: HashMap<u64, FakeHandle>,
    next_handle: u64,
    next_file_id: u64,
    faults: HashMap<FaultPoint, Fault>,
    once: HashMap<FaultPoint, Fault>,
    storage: Option<StorageKind>,
    storage_overrides: HashMap<String, StorageKind>,
    counters: Counters,
}

/// In-memory filesystem with documented Windows replacement semantics and
/// persistent/one-shot fault injection. All paths are opaque strings; the
/// store joins them with `\` (Windows convention) — tests use the same.
pub struct FakeFs {
    inner: RefCell<Inner>,
}

impl Default for FakeFs {
    fn default() -> Self {
        Self::new()
    }
}

pub fn join(dir: &str, name: &str) -> String {
    format!("{dir}\\{name}")
}

pub fn basename(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

impl FakeFs {
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(Inner {
                storage: Some(StorageKind::LocalNtfs),
                ..Default::default()
            }),
        }
    }

    pub fn inject(&self, point: FaultPoint, fault: Fault) {
        self.inner.borrow_mut().faults.insert(point, fault);
    }

    pub fn inject_once(&self, point: FaultPoint, fault: Fault) {
        self.inner.borrow_mut().once.insert(point, fault);
    }

    pub fn clear_faults(&self) {
        let mut i = self.inner.borrow_mut();
        i.faults.clear();
        i.once.clear();
    }

    pub fn counters(&self) -> Counters {
        self.inner.borrow().counters.clone()
    }

    pub fn set_storage(&self, kind: StorageKind) {
        self.inner.borrow_mut().storage = Some(kind);
    }

    pub fn set_storage_override(&self, dir: &str, kind: StorageKind) {
        self.inner.borrow_mut().storage_overrides.insert(dir.to_string(), kind);
    }

    /// Seed a candidate file with correct protected security (reconcile tests).
    pub fn seed_file(&self, path: &str, data: Vec<u8>) {
        self.seed_file_with_security(path, data, expected_security(ObjectKind::File));
    }

    pub fn seed_file_with_security(&self, path: &str, data: Vec<u8>, security: SecurityInfo) {
        let mut i = self.inner.borrow_mut();
        i.next_file_id += 1;
        let id = i.next_file_id;
        i.files.insert(
            path.to_string(),
            FakeFile {
                data,
                security,
                links: 1,
                reparse: false,
                file_id: id,
            },
        );
    }

    /// Seed a directory with arbitrary security (bad-ACL refusal tests).
    pub fn seed_directory(&self, dir: &str, security: SecurityInfo) {
        self.inner.borrow_mut().dirs.insert(dir.to_string(), security);
    }

    pub fn set_reparse(&self, path: &str, reparse: bool) {
        if let Some(f) = self.inner.borrow_mut().files.get_mut(path) {
            f.reparse = reparse;
        }
    }

    pub fn set_links(&self, path: &str, links: u32) {
        if let Some(f) = self.inner.borrow_mut().files.get_mut(path) {
            f.links = links;
        }
    }

    pub fn file_bytes(&self, path: &str) -> Option<Vec<u8>> {
        self.inner.borrow().files.get(path).map(|f| f.data.clone())
    }

    pub fn file_security_of(&self, path: &str) -> Option<SecurityInfo> {
        self.inner.borrow().files.get(path).map(|f| f.security.clone())
    }

    pub fn file_id_of(&self, path: &str) -> Option<u64> {
        self.inner.borrow().files.get(path).map(|f| f.file_id)
    }

    pub fn exists(&self, path: &str) -> bool {
        self.inner.borrow().files.contains_key(path)
    }

    pub fn all_paths(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.borrow().files.keys().cloned().collect();
        v.sort();
        v
    }

    fn take_fault(i: &mut Inner, point: FaultPoint) -> Option<Fault> {
        if let Some(f) = i.once.remove(&point) {
            return Some(f);
        }
        i.faults.get(&point).cloned()
    }

    fn check_exclusive(i: &Inner, path: &str) -> Result<(), FsError> {
        if i.handles.values().any(|h| h.path == path) {
            return Err(FsError::SharingViolation);
        }
        Ok(())
    }

    fn read_checked(i: &mut Inner, path: &str) -> Result<Vec<u8>, FsError> {
        Self::check_exclusive(i, path)?;
        let f = i.files.get(path).ok_or(FsError::NotFound)?;
        if f.reparse {
            return Err(FsError::ReparsePoint);
        }
        if f.links > 1 {
            return Err(FsError::HardLink);
        }
        validate_journal_security(&f.security, ObjectKind::File)?;
        if f.data.len() > MAX_JOURNAL_BYTES {
            return Err(FsError::Io {
                code: 0,
                context: "file exceeds journal size cap".into(),
            });
        }
        i.counters.reads += 1;
        Ok(f.data.clone())
    }
}

impl JournalFs for FakeFs {
    fn ensure_directory(&self, dir: &str) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        i.dirs
            .entry(dir.to_string())
            .or_insert_with(|| expected_security(ObjectKind::Directory));
        Ok(())
    }

    fn directory_security(&self, dir: &str) -> Result<SecurityInfo, FsError> {
        let i = self.inner.borrow();
        i.dirs.get(dir).cloned().ok_or(FsError::NotFound)
    }

    fn storage_kind(&self, dir: &str) -> Result<StorageKind, FsError> {
        let i = self.inner.borrow();
        if let Some(k) = i.storage_overrides.get(dir) {
            return Ok(*k);
        }
        i.storage.ok_or(FsError::InvalidPath("storage kind unset".into()))
    }

    fn list_candidates(&self, dir: &str) -> Result<Vec<String>, FsError> {
        let i = self.inner.borrow();
        let prefix = format!("{dir}\\");
        let mut out: Vec<String> = i
            .files
            .keys()
            .filter(|p| {
                let Some(name) = p.strip_prefix(&prefix) else {
                    return false;
                };
                !name.contains('\\')
                    && (name == crate::journal::PRIMARY_FILE
                        || name.starts_with(crate::journal::STAGE_PREFIX)
                        || name.starts_with(crate::journal::BACKUP_PREFIX))
            })
            .cloned()
            .collect();
        out.sort();
        Ok(out)
    }

    fn create_new(&self, path: &str) -> Result<u64, FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(f) = Self::take_fault(&mut i, FaultPoint::CreateNew) {
            return match f {
                Fault::Error(e) => Err(e),
                _ => Err(FsError::Io { code: 0, context: "bad fault at CreateNew".into() }),
            };
        }
        if i.files.contains_key(path) {
            return Err(FsError::AlreadyExists);
        }
        Self::check_exclusive(&i, path)?;
        i.next_file_id += 1;
        let file_id = i.next_file_id;
        i.files.insert(
            path.to_string(),
            FakeFile {
                data: Vec::new(),
                security: expected_security(ObjectKind::File),
                links: 1,
                reparse: false,
                file_id,
            },
        );
        i.next_handle += 1;
        let h = i.next_handle;
        i.handles.insert(h, FakeHandle { path: path.to_string() });
        i.counters.creates += 1;
        Ok(h)
    }

    fn write_all(&self, h: u64, data: &[u8]) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        let fault = Self::take_fault(&mut i, FaultPoint::Write);
        let path = i.handles.get(&h).ok_or(FsError::NotFound)?.path.clone();
        match fault {
            Some(Fault::Error(e)) => return Err(e),
            Some(Fault::PartialWrite) => {
                let n = data.len() / 2;
                i.files.get_mut(&path).unwrap().data.extend_from_slice(&data[..n]);
                i.counters.writes += 1;
                return Ok(());
            }
            Some(_) => {
                return Err(FsError::Io { code: 0, context: "bad fault at Write".into() });
            }
            None => {}
        }
        i.files.get_mut(&path).unwrap().data.extend_from_slice(data);
        i.counters.writes += 1;
        Ok(())
    }

    fn flush_file(&self, h: u64) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::FileFlush) {
            return Err(e);
        }
        if !i.handles.contains_key(&h) {
            return Err(FsError::NotFound);
        }
        i.counters.file_flushes += 1;
        Ok(())
    }

    fn close(&self, h: u64) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        i.handles.remove(&h).ok_or(FsError::NotFound)?;
        Ok(())
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, FsError> {
        Self::read_checked(&mut self.inner.borrow_mut(), path)
    }

    fn read_stage_back(&self, path: &str) -> Result<Vec<u8>, FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::StageReadback) {
            return Err(e);
        }
        Self::read_checked(&mut i, path)
    }

    fn reopen_primary(&self, path: &str) -> Result<Vec<u8>, FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::PrimaryReopen) {
            return Err(e);
        }
        Self::read_checked(&mut i, path)
    }

    fn file_security(&self, path: &str) -> Result<SecurityInfo, FsError> {
        let i = self.inner.borrow();
        Ok(i.files.get(path).ok_or(FsError::NotFound)?.security.clone())
    }

    fn replace(&self, primary: &str, stage: &str, backup: &str) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        let fault = Self::take_fault(&mut i, FaultPoint::Replace);
        i.counters.replaces += 1;
        Self::check_exclusive(&i, primary)?;
        Self::check_exclusive(&i, stage)?;
        if !i.files.contains_key(primary) {
            return Err(FsError::NotFound);
        }
        if !i.files.contains_key(stage) {
            return Err(FsError::NotFound);
        }
        if i.files.contains_key(backup) {
            return Err(FsError::AlreadyExists);
        }
        let shape = match fault {
            None => None,
            Some(Fault::ReplaceShape(s)) => Some(s),
            Some(Fault::Error(e)) => return Err(e),
            Some(_) => {
                return Err(FsError::Io { code: 0, context: "bad fault at Replace".into() });
            }
        };
        match shape {
            None => {
                let old = i.files.remove(primary).unwrap();
                let new = i.files.remove(stage).unwrap();
                i.files.insert(backup.to_string(), old);
                i.files.insert(primary.to_string(), new);
                Ok(())
            }
            Some(ReplaceFailure::UnableToMoveReplacement) => Err(FsError::Io {
                code: 1176,
                context: "ERROR_UNABLE_TO_MOVE_REPLACEMENT".into(),
            }),
            Some(ReplaceFailure::UnableToMoveReplacement2) => {
                let old = i.files.remove(primary).unwrap();
                i.files.insert(backup.to_string(), old);
                Err(FsError::Io {
                    code: 1177,
                    context: "ERROR_UNABLE_TO_MOVE_REPLACEMENT_2".into(),
                })
            }
            Some(ReplaceFailure::UnableToRemoveReplaced) => Err(FsError::Io {
                code: 1175,
                context: "ERROR_UNABLE_TO_REMOVE_REPLACED".into(),
            }),
            Some(ReplaceFailure::Other(code)) => Err(FsError::Io {
                code,
                context: "ReplaceFileW failed".into(),
            }),
        }
    }

    fn move_write_through(&self, from: &str, to: &str) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::Move) {
            return Err(e);
        }
        i.counters.moves += 1;
        Self::check_exclusive(&i, from)?;
        Self::check_exclusive(&i, to)?;
        if i.files.contains_key(to) {
            return Err(FsError::AlreadyExists);
        }
        let f = i.files.remove(from).ok_or(FsError::NotFound)?;
        i.files.insert(to.to_string(), f);
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::CleanupDelete) {
            return Err(e);
        }
        Self::check_exclusive(&i, path)?;
        i.files.remove(path).ok_or(FsError::NotFound)?;
        i.counters.deletes += 1;
        Ok(())
    }

    fn flush_volume(&self, path: &str) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::VolumeFlush) {
            return Err(e);
        }
        let kind = i
            .storage_overrides
            .get(path)
            .copied()
            .or(i.storage)
            .unwrap_or(StorageKind::LocalNtfs);
        if kind != StorageKind::LocalNtfs {
            return Err(FsError::VolumeFlushUnsupported);
        }
        i.counters.volume_flushes += 1;
        Ok(())
    }

    fn flush_volume_post_cleanup(&self, path: &str) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::CleanupVolumeFlush) {
            return Err(e);
        }
        let kind = i
            .storage_overrides
            .get(path)
            .copied()
            .or(i.storage)
            .unwrap_or(StorageKind::LocalNtfs);
        if kind != StorageKind::LocalNtfs {
            return Err(FsError::VolumeFlushUnsupported);
        }
        i.counters.volume_flushes += 1;
        Ok(())
    }

    fn flush_file_at(&self, path: &str) -> Result<(), FsError> {
        let mut i = self.inner.borrow_mut();
        if let Some(Fault::Error(e)) = Self::take_fault(&mut i, FaultPoint::PrimaryFlush) {
            return Err(e);
        }
        Self::check_exclusive(&i, path)?;
        let f = i.files.get(path).ok_or(FsError::NotFound)?;
        validate_journal_security(&f.security, ObjectKind::File)?;
        i.counters.file_flushes += 1;
        Ok(())
    }
}

//! Durable journal store: replacement pipeline, candidate reconciliation and
//! clean-tombstone cleanup (U02, SPEC-DNS-FIX.md §3.3).
//!
//! Every commit runs the full barrier — CREATE_NEW stage → write/length check
//! → file flush → close → stage readback/hash/schema → ReplaceFileW (or
//! MoveFileExW WRITE_THROUGH for the first primary) → primary reopen/verify →
//! primary ACL check → primary flush → volume flush. There is no optimistic
//! rename durability: a rename alone never authorizes DNS mutation. Any
//! persistence failure closes admission until a successful reconciliation.
//! Candidates are kept on every error; only a durable clean tombstone's
//! post-barrier cleanup deletes obsolete generations.

use crate::codec;
use crate::fs::{basename, join, FsError, JournalFs, StorageKind};
use crate::journal::{
    self, Envelope, JournalError, Tombstone, BACKUP_PREFIX, PRIMARY_FILE, STAGE_PREFIX,
};
use crate::security::{validate_journal_security, ObjectKind};
use std::cell::Cell;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    Fs(FsError),
    Codec(JournalError),
    /// Corrupt/ambiguous state: refuse writes, retain evidence.
    Integrity(String),
    /// Unknown newer journal version: block, never delete or overwrite.
    UnknownVersion(u32),
    /// Storage/security refusal (ACL, reparse, hardlink, network, non-NTFS).
    Unsafe(String),
    /// The next envelope violates generation/lineage/machine rules.
    InvalidNextGeneration(String),
    /// A persistence failure closed admission; reconcile before any write.
    ReconciliationRequired,
    /// A readback did not match the bytes that were written.
    VerificationMismatch { at: &'static str, detail: String },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Fs(e) => write!(f, "journal fs: {e}"),
            StoreError::Codec(e) => write!(f, "journal codec: {e}"),
            StoreError::Integrity(m) => write!(f, "journal integrity failure: {m}"),
            StoreError::UnknownVersion(v) => write!(f, "unknown journal version {v}: blocked"),
            StoreError::Unsafe(m) => write!(f, "unsafe journal storage: {m}"),
            StoreError::InvalidNextGeneration(m) => write!(f, "invalid next generation: {m}"),
            StoreError::ReconciliationRequired => {
                write!(f, "admission closed: reconciliation required after persistence failure")
            }
            StoreError::VerificationMismatch { at, detail } => {
                write!(f, "readback verification failed at {at}: {detail}")
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<FsError> for StoreError {
    fn from(e: FsError) -> Self {
        StoreError::Fs(e)
    }
}

impl From<JournalError> for StoreError {
    fn from(e: JournalError) -> Self {
        match e {
            JournalError::UnknownVersion(v) => StoreError::UnknownVersion(v),
            other => StoreError::Codec(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateKind {
    Primary,
    Stage,
    Backup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateStatus {
    Valid,
    /// Corrupt/partial/incomplete: a crash artifact, retained as evidence,
    /// never authoritative.
    Invalid(String),
    UnknownVersion(u32),
    Unsafe(String),
}

#[derive(Clone, Debug)]
pub struct CandidateReport {
    pub path: String,
    pub kind: CandidateKind,
    pub status: CandidateStatus,
}

#[derive(Clone, Debug)]
pub struct ValidCandidate {
    pub path: String,
    pub kind: CandidateKind,
    pub env: Envelope,
    pub bytes: Vec<u8>,
    pub digest: String,
}

/// Outcome of a reconciliation. `current` is the highest unambiguous
/// compatible valid generation; `primary` is the valid primary file, if any
/// (it may lag `current` when a replacement never returned).
#[derive(Clone, Debug, Default)]
pub struct Reconciled {
    pub current: Option<ValidCandidate>,
    pub primary: Option<ValidCandidate>,
    pub candidates: Vec<CandidateReport>,
}

#[derive(Clone, Debug, Default)]
pub struct CommitReport {
    pub generation: u64,
    pub digest: String,
    pub backup: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CleanupReport {
    pub deleted: Vec<String>,
    pub retained: Vec<String>,
}

fn classify(path: &str) -> Option<CandidateKind> {
    let name = basename(path);
    if name == PRIMARY_FILE {
        Some(CandidateKind::Primary)
    } else if name.starts_with(STAGE_PREFIX) {
        Some(CandidateKind::Stage)
    } else if name.starts_with(BACKUP_PREFIX) {
        Some(CandidateKind::Backup)
    } else {
        None
    }
}

/// Generation encoded in a stage/backup file name (`<prefix><gen>.<uuid>`).
/// `None` for the primary or malformed names — malformed names are never
/// authoritative and never deleted by cleanup.
fn name_generation(path: &str, kind: CandidateKind) -> Option<u64> {
    let name = basename(path);
    let rest = match kind {
        CandidateKind::Stage => name.strip_prefix(STAGE_PREFIX)?,
        CandidateKind::Backup => name.strip_prefix(BACKUP_PREFIX)?,
        CandidateKind::Primary => return None,
    };
    let (gen_str, uuid) = rest.split_once('.')?;
    if !journal::is_lower_uuid(uuid) {
        return None;
    }
    let g: u64 = gen_str.parse().ok()?;
    if g.to_string() != gen_str {
        return None;
    }
    Some(g)
}

pub struct JournalStore<F: JournalFs> {
    fs: F,
    dir: String,
    dirty: Cell<bool>,
}

impl<F: JournalFs> JournalStore<F> {
    /// Open the journal directory. Refuses bad directory ACLs, reparse
    /// redirection and non-local/non-NTFS storage — unsafe storage never
    /// authorizes takeover.
    pub fn open(fs: F, dir: &str) -> Result<Self, StoreError> {
        fs.ensure_directory(dir)?;
        let sec = fs.directory_security(dir)?;
        validate_journal_security(&sec, ObjectKind::Directory)
            .map_err(|e| StoreError::Unsafe(format!("directory {dir:?}: {}", e.0)))?;
        match fs.storage_kind(dir)? {
            StorageKind::LocalNtfs => {}
            StorageKind::NonNtfs => {
                return Err(StoreError::Unsafe(format!("{dir:?} is not local NTFS")));
            }
            StorageKind::Network => {
                return Err(StoreError::Unsafe(format!("{dir:?} is network storage")));
            }
        }
        Ok(Self { fs, dir: dir.to_string(), dirty: Cell::new(false) })
    }

    pub fn dir(&self) -> &str {
        &self.dir
    }

    pub fn fs(&self) -> &F {
        &self.fs
    }

    /// Admission is closed after any persistence failure until a successful
    /// reconciliation.
    pub fn admission_closed(&self) -> bool {
        self.dirty.get()
    }

    pub fn primary_path(&self) -> String {
        join(&self.dir, PRIMARY_FILE)
    }

    /// Scan primary + controlled stage/backup candidates and resolve the
    /// authoritative state. Success clears the admission-closed flag.
    pub fn reconcile(&self) -> Result<Reconciled, StoreError> {
        let paths = self.fs.list_candidates(&self.dir)?;
        let mut reports = Vec::new();
        let mut valid: Vec<ValidCandidate> = Vec::new();
        let mut unsafe_found: Option<String> = None;
        let mut unknown_version: Option<u32> = None;
        let mut corrupt_primary: Option<String> = None;
        for path in paths {
            let Some(kind) = classify(&path) else { continue };
            let bytes = match self.fs.read_file(&path) {
                Ok(b) => b,
                Err(FsError::NotFound) => {
                    reports.push(CandidateReport {
                        path,
                        kind,
                        status: CandidateStatus::Invalid("vanished during scan".into()),
                    });
                    continue;
                }
                Err(e @ (FsError::ReparsePoint | FsError::HardLink | FsError::BadSecurity(_))) => {
                    let msg = format!("{path:?}: {e}");
                    reports.push(CandidateReport {
                        path,
                        kind,
                        status: CandidateStatus::Unsafe(msg.clone()),
                    });
                    if unsafe_found.is_none() {
                        unsafe_found = Some(msg);
                    }
                    continue;
                }
                Err(e) => {
                    // Cannot verify the candidate at all: fail closed.
                    return Err(StoreError::Unsafe(format!("{path:?}: {e}")));
                }
            };
            match codec::decode(&bytes) {
                Ok(env) => {
                    let digest = codec::envelope_digest(&bytes);
                    reports.push(CandidateReport { path: path.clone(), kind, status: CandidateStatus::Valid });
                    valid.push(ValidCandidate { path, kind, env, bytes, digest });
                }
                Err(JournalError::UnknownVersion(v)) => {
                    reports.push(CandidateReport { path, kind, status: CandidateStatus::UnknownVersion(v) });
                    if unknown_version.is_none() {
                        unknown_version = Some(v);
                    }
                }
                Err(e) => {
                    // A corrupt primary is integrity failure even when an older
                    // backup decodes: do not assume the older backup is complete
                    // (§3.3). A *missing* primary is a documented replacement
                    // shape, not corruption.
                    if kind == CandidateKind::Primary {
                        corrupt_primary = Some(format!("{path:?}: {e}"));
                    }
                    reports.push(CandidateReport { path, kind, status: CandidateStatus::Invalid(e.to_string()) });
                }
            }
        }
        if let Some(msg) = unsafe_found {
            return Err(StoreError::Unsafe(msg));
        }
        if let Some(v) = unknown_version {
            return Err(StoreError::UnknownVersion(v));
        }
        if let Some(msg) = corrupt_primary {
            return Err(StoreError::Integrity(format!(
                "corrupt primary {msg}; older backup is not assumed complete"
            )));
        }
        let reconciled = Self::resolve(valid, reports)?;
        self.dirty.set(false);
        Ok(reconciled)
    }

    fn resolve(valid: Vec<ValidCandidate>, reports: Vec<CandidateReport>) -> Result<Reconciled, StoreError> {
        let integrity = |m: String| StoreError::Integrity(m);
        if valid.is_empty() {
            if !reports.is_empty() {
                return Err(integrity(
                    "no valid envelope; corrupt/ambiguous candidates retained as evidence".into(),
                ));
            }
            return Ok(Reconciled { current: None, primary: None, candidates: reports });
        }
        // One machine only.
        let machine = &valid[0].env.machine_id;
        if valid.iter().any(|c| &c.env.machine_id != machine) {
            return Err(integrity("conflicting machine IDs among valid candidates".into()));
        }
        // Same generation must mean the same envelope.
        let mut by_gen: BTreeMap<u64, Vec<&ValidCandidate>> = BTreeMap::new();
        for c in &valid {
            by_gen.entry(c.env.generation).or_default().push(c);
        }
        for (generation, group) in &by_gen {
            if group.iter().any(|c| c.digest != group[0].digest) {
                return Err(integrity(format!("divergent valid branches at generation {generation}")));
            }
        }
        // Highest generation wins; prefer the primary among identical copies.
        let max_gen = *by_gen.keys().next_back().unwrap();
        let winner_group = &by_gen[&max_gen];
        let winner = winner_group
            .iter()
            .find(|c| c.kind == CandidateKind::Primary)
            .or_else(|| winner_group.iter().find(|c| c.kind == CandidateKind::Stage))
            .unwrap_or(&winner_group[0]);
        let winner = (*winner).clone();
        let primary = valid
            .iter()
            .find(|c| c.kind == CandidateKind::Primary)
            .cloned();

        let active: Vec<&ValidCandidate> = valid
            .iter()
            .filter(|c| c.env.payload.transaction.is_some())
            .collect();
        let cleans: Vec<&ValidCandidate> = valid.iter().filter(|c| c.env.is_clean_tombstone()).collect();

        // Divergent transaction IDs: an active transaction other than the
        // winner's is only compatible when a clean tombstone completed it
        // strictly between the two generations.
        if let Some(wtx) = &winner.env.payload.transaction {
            for c in &active {
                let tx = c.env.payload.transaction.as_ref().unwrap();
                if tx.id == wtx.id {
                    continue;
                }
                let separated = cleans.iter().any(|t| {
                    let done = t.env.payload.last_completed.as_ref().unwrap();
                    done.transaction_id == tx.id
                        && c.env.generation <= done.completed_generation
                        && c.env.generation < t.env.generation
                        && t.env.generation < winner.env.generation
                });
                if !separated {
                    return Err(integrity(format!(
                        "divergent transaction IDs: {} at generation {} vs winner {} at {}",
                        tx.id, c.env.generation, wtx.id, winner.env.generation
                    )));
                }
            }
        }
        // A completed transaction must never be resurrected at a higher
        // generation than its tombstone.
        for t in &cleans {
            let done = t.env.payload.last_completed.as_ref().unwrap();
            for c in &active {
                let tx = c.env.payload.transaction.as_ref().unwrap();
                if tx.id == done.transaction_id && c.env.generation > t.env.generation {
                    return Err(integrity(format!(
                        "transaction {} resurrected at generation {} past clean tombstone {}",
                        tx.id, c.env.generation, t.env.generation
                    )));
                }
            }
        }
        // Originals are immutable within a transaction.
        let mut tx_ids: Vec<&str> = active
            .iter()
            .map(|c| c.env.payload.transaction.as_ref().unwrap().id.as_str())
            .collect();
        tx_ids.sort();
        tx_ids.dedup();
        for id in tx_ids {
            let mut originals: BTreeMap<(&str, crate::model::Family), &str> = BTreeMap::new();
            for c in active.iter().filter(|c| c.env.payload.transaction.as_ref().unwrap().id == id) {
                for e in &c.env.payload.transaction.as_ref().unwrap().entries {
                    let key = (e.adapter_guid.as_str(), e.family);
                    match originals.get(&key) {
                        Some(fp) if *fp != e.original_fingerprint => {
                            return Err(integrity(format!(
                                "conflicting originals for {} {:?} in transaction {id}",
                                e.adapter_guid, e.family
                            )));
                        }
                        _ => {
                            originals.insert(key, e.original_fingerprint.as_str());
                        }
                    }
                }
            }
        }
        // Lineage where the adjacent generation is present. Missing
        // intermediates are acceptable only with an authoritative valid
        // current envelope (the winner) and no conflicting higher candidate.
        for c in &valid {
            let generation = c.env.generation;
            match (generation, &c.env.previous_digest) {
                (1, Some(_)) => {
                    return Err(integrity("genesis envelope carries previous_digest".into()));
                }
                (g, None) if g > 1 => {
                    return Err(integrity(format!("generation {generation} missing previous_digest")));
                }
                (_, Some(d)) => {
                    if let Some(prev_group) = by_gen.get(&(generation - 1)) {
                        if prev_group[0].digest != *d {
                            return Err(integrity(format!(
                                "lineage break: generation {generation} previous_digest does not match generation {}",
                                generation - 1
                            )));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Reconciled { current: Some(winner), primary, candidates: reports })
    }

    /// Commit the next sealed envelope through the full durable barrier.
    /// Keeps every candidate on any error and closes admission until a
    /// successful reconciliation.
    pub fn commit(&self, env: &Envelope) -> Result<CommitReport, StoreError> {
        if self.dirty.get() {
            return Err(StoreError::ReconciliationRequired);
        }
        let reconciled = self.reconcile()?;
        // Validate the next envelope against the reconciled state.
        match &reconciled.current {
            Some(cur) => {
                if env.machine_id != cur.env.machine_id {
                    return Err(StoreError::InvalidNextGeneration(format!(
                        "machine_id {} does not match journal {}",
                        env.machine_id, cur.env.machine_id
                    )));
                }
                if env.generation <= cur.env.generation {
                    return Err(StoreError::InvalidNextGeneration(format!(
                        "generation {} must exceed current {}",
                        env.generation, cur.env.generation
                    )));
                }
                if env.previous_digest.as_deref() != Some(cur.digest.as_str()) {
                    return Err(StoreError::InvalidNextGeneration(format!(
                        "previous_digest {:?} does not match current envelope digest {}",
                        env.previous_digest, cur.digest
                    )));
                }
            }
            None => {
                if env.generation != 1 || env.previous_digest.is_some() {
                    return Err(StoreError::InvalidNextGeneration(
                        "genesis must be generation 1 with previous_digest=null".into(),
                    ));
                }
            }
        }
        if env.payload_digest != codec::compute_payload_digest(env) {
            return Err(StoreError::Codec(JournalError::DigestMismatch));
        }
        journal::validate(env)?;

        let result = self.pipeline(env, &reconciled);
        if result.is_err() {
            self.dirty.set(true);
        }
        result
    }

    fn pipeline(&self, env: &Envelope, reconciled: &Reconciled) -> Result<CommitReport, StoreError> {
        let bytes = codec::encode(env);
        let uuid = journal::new_uuid();
        let stage = join(&self.dir, &format!("{STAGE_PREFIX}{}.{uuid}", env.generation));
        let primary = self.primary_path();

        let h = self.fs.create_new(&stage)?;
        let written = (|| -> Result<(), StoreError> {
            self.fs.write_all(h, &bytes)?;
            self.fs.flush_file(h)?;
            Ok(())
        })();
        // Close our handle on every path; the stage file itself is kept.
        let close_result = self.fs.close(h);
        written?;
        close_result?;

        let back = self.fs.read_stage_back(&stage)?;
        if back != bytes {
            return Err(StoreError::VerificationMismatch {
                at: "stage readback",
                detail: format!("expected {} bytes, read {}", bytes.len(), back.len()),
            });
        }
        codec::decode(&back)?;

        let mut backup = None;
        if let Some(old) = &reconciled.primary {
            let bak = join(
                &self.dir,
                &format!("{BACKUP_PREFIX}{}.{uuid}", old.env.generation),
            );
            self.fs.replace(&primary, &stage, &bak)?;
            backup = Some(bak);
        } else {
            self.fs.move_write_through(&stage, &primary)?;
        }

        let reopened = self.fs.reopen_primary(&primary)?;
        if reopened != bytes {
            return Err(StoreError::VerificationMismatch {
                at: "primary reopen",
                detail: format!("expected {} bytes, read {}", bytes.len(), reopened.len()),
            });
        }
        codec::decode(&reopened)?;
        let sec = self.fs.file_security(&primary)?;
        validate_journal_security(&sec, ObjectKind::File)
            .map_err(|e| StoreError::Unsafe(format!("primary {primary:?}: {}", e.0)))?;
        self.fs.flush_file_at(&primary)?;
        self.fs.flush_volume(&primary)?;

        Ok(CommitReport {
            generation: env.generation,
            digest: codec::envelope_digest(&bytes),
            backup,
        })
    }

    /// Durably republish the reconciled state as generation+1 before any
    /// recovery mutation (a valid newer stage is possible intent even when
    /// the replacement never returned).
    pub fn republish(&self, winner: &ValidCandidate) -> Result<CommitReport, StoreError> {
        let mut env = winner.env.clone();
        env.generation = winner.env.generation + 1;
        env.previous_digest = Some(winner.digest.clone());
        codec::seal(&mut env);
        self.commit(&env)
    }

    /// Delete obsolete candidates after the clean tombstone's volume barrier.
    /// The tombstone itself and anything newer or unparseable are retained;
    /// a cleanup crash leaves the newer clean tombstone authoritative.
    pub fn cleanup_obsolete(&self, tombstone: &Envelope) -> Result<CleanupReport, StoreError> {
        if self.dirty.get() {
            return Err(StoreError::ReconciliationRequired);
        }
        if !tombstone.is_clean_tombstone() {
            return Err(StoreError::Integrity("cleanup requires a clean tombstone envelope".into()));
        }
        let primary = self.primary_path();
        let primary_bytes = self.fs.read_file(&primary)?;
        if primary_bytes != codec::encode(tombstone) {
            return Err(StoreError::Integrity(
                "cleanup requires the durable clean tombstone as primary".into(),
            ));
        }
        let mut report = CleanupReport::default();
        let result = (|| -> Result<(), StoreError> {
            for path in self.fs.list_candidates(&self.dir)? {
                if path == primary {
                    report.retained.push(path);
                    continue;
                }
                let Some(kind) = classify(&path) else {
                    report.retained.push(path);
                    continue;
                };
                let obsolete = match self.fs.read_file(&path) {
                    Ok(bytes) => match codec::decode(&bytes) {
                        Ok(env) => env.generation < tombstone.generation,
                        // Crash artifact: the file-name generation is the only
                        // evidence; delete only clearly superseded names.
                        Err(_) => name_generation(&path, kind).is_some_and(|g| g < tombstone.generation),
                    },
                    Err(_) => name_generation(&path, kind).is_some_and(|g| g < tombstone.generation),
                };
                if obsolete {
                    self.fs.delete(&path)?;
                    report.deleted.push(path);
                } else {
                    report.retained.push(path);
                }
            }
            self.fs.flush_volume_post_cleanup(&primary)?;
            Ok(())
        })();
        if result.is_err() {
            self.dirty.set(true);
        }
        result?;
        Ok(report)
    }
}

/// Build a sealed clean-tombstone envelope (transaction=null, last_completed
/// set). The caller supplies the generation chain; the store enforces it.
pub fn tombstone_envelope(
    machine_id: &str,
    generation: u64,
    previous_digest: Option<String>,
    completed: Tombstone,
) -> Envelope {
    let mut env = Envelope {
        format: journal::JOURNAL_FORMAT.to_string(),
        version: journal::JOURNAL_VERSION,
        machine_id: machine_id.to_string(),
        generation,
        previous_digest,
        payload_digest: String::new(),
        payload: journal::Payload {
            journal_state: journal::JournalState::Clean,
            transaction: None,
            last_completed: Some(completed),
            maintenance: None,
            diagnostics: Vec::new(),
        },
    };
    codec::seal(&mut env);
    env
}

//! Cross-process/cross-session journal lock (U02, SPEC-DNS-FIX.md §3.1).
//!
//! One named mutex, `Global\Yeager.DnsTakeover.v1`, protected DACL (SYSTEM +
//! Administrators full control). A wrong-type or security-squatted object at
//! that name fails closed — a collision is never permission to use another
//! name. `WAIT_ABANDONED` counts as acquisition but mandates a journal rescan
//! before any write. The guard releases on the acquiring thread (RAII, !Send).

use crate::security::{validate_journal_security, ObjectKind, SecurityInfo};
use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Duration;

pub const LOCK_NAME: &str = "Global\\Yeager.DnsTakeover.v1";
pub const LOCK_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockError {
    Timeout,
    AccessDenied,
    WrongType,
    BadSecurity(String),
    CreateFailed(String),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Timeout => write!(f, "journal lock wait timed out"),
            LockError::AccessDenied => write!(f, "journal lock access denied"),
            LockError::WrongType => write!(f, "named object is not a mutex"),
            LockError::BadSecurity(m) => write!(f, "journal lock bad security: {m}"),
            LockError::CreateFailed(m) => write!(f, "journal lock create failed: {m}"),
        }
    }
}

impl std::error::Error for LockError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acquired {
    Fresh,
    /// WAIT_ABANDONED: acquired, but the journal MUST be rescanned.
    Abandoned,
}

/// RAII lock guard. Deliberately !Send/!Sync: release happens on the acquiring
/// thread. Dropping without an explicit release still releases.
pub struct LockGuard {
    release: Option<Box<dyn FnOnce()>>,
    _not_send: PhantomData<*const ()>,
}

impl LockGuard {
    pub fn from_release(release: Box<dyn FnOnce()>) -> Self {
        Self {
            release: Some(release),
            _not_send: PhantomData,
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(r) = self.release.take() {
            r();
        }
    }
}

pub trait MachineLock {
    fn acquire(&self, budget: Duration) -> Result<(LockGuard, Acquired), LockError>;
}

// ---- FakeLock --------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeObjectKind {
    Mutex,
    Event,
    Semaphore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeIdentity {
    pub pid: u32,
    pub session_id: u32,
}

#[derive(Clone, Debug)]
struct FakeObject {
    kind: FakeObjectKind,
    security: SecurityInfo,
    held: bool,
    abandoned: bool,
    owner: Option<FakeIdentity>,
}

#[derive(Default)]
struct Registry {
    objects: HashMap<String, FakeObject>,
}

/// In-memory named-object registry shared by every FakeLock clone, simulating
/// machine-wide namespace contention between processes/sessions.
pub struct FakeLock {
    registry: Rc<RefCell<Registry>>,
    name: String,
    identity: FakeIdentity,
}

impl FakeLock {
    pub fn new() -> Self {
        Self {
            registry: Rc::new(RefCell::new(Registry::default())),
            name: LOCK_NAME.to_string(),
            identity: FakeIdentity { pid: 1, session_id: 0 },
        }
    }

    pub fn with_identity(mut self, pid: u32, session_id: u32) -> Self {
        self.identity = FakeIdentity { pid, session_id };
        self
    }

    /// Another participant sharing the same machine namespace.
    pub fn peer(&self, pid: u32, session_id: u32) -> Self {
        Self {
            registry: Rc::clone(&self.registry),
            name: self.name.clone(),
            identity: FakeIdentity { pid, session_id },
        }
    }

    /// Pre-create a named object of any kind/security at the lock name
    /// (squatting). The lock must fail closed against it.
    pub fn squat(&self, kind: FakeObjectKind, security: SecurityInfo) {
        self.registry.borrow_mut().objects.insert(
            self.name.clone(),
            FakeObject {
                kind,
                security,
                held: false,
                abandoned: false,
                owner: None,
            },
        );
    }

    /// Simulate the holding process dying without releasing: the next
    /// acquisition observes WAIT_ABANDONED.
    pub fn simulate_holder_death(&self) {
        if let Some(o) = self.registry.borrow_mut().objects.get_mut(&self.name) {
            o.held = false;
            o.abandoned = true;
            o.owner = None;
        }
    }

    pub fn is_held(&self) -> bool {
        self.registry
            .borrow()
            .objects
            .get(&self.name)
            .map(|o| o.held)
            .unwrap_or(false)
    }

    pub fn holder(&self) -> Option<FakeIdentity> {
        self.registry
            .borrow()
            .objects
            .get(&self.name)
            .and_then(|o| o.owner.clone())
    }
}

impl Default for FakeLock {
    fn default() -> Self {
        Self::new()
    }
}

impl MachineLock for FakeLock {
    fn acquire(&self, _budget: Duration) -> Result<(LockGuard, Acquired), LockError> {
        let mut reg = self.registry.borrow_mut();
        let name = self.name.clone();
        let obj = reg.objects.entry(name.clone()).or_insert_with(|| FakeObject {
            kind: FakeObjectKind::Mutex,
            security: crate::fs::expected_security(ObjectKind::Mutex),
            held: false,
            abandoned: false,
            owner: None,
        });
        if obj.kind != FakeObjectKind::Mutex {
            return Err(LockError::WrongType);
        }
        validate_journal_security(&obj.security, ObjectKind::Mutex)
            .map_err(|e| LockError::BadSecurity(e.0))?;
        if obj.held {
            return Err(LockError::Timeout);
        }
        let abandoned = obj.abandoned;
        obj.abandoned = false;
        obj.held = true;
        obj.owner = Some(self.identity.clone());
        let registry = Rc::clone(&self.registry);
        let guard = LockGuard::from_release(Box::new(move || {
            if let Some(o) = registry.borrow_mut().objects.get_mut(&name) {
                o.held = false;
                o.owner = None;
            }
        }));
        Ok((guard, if abandoned { Acquired::Abandoned } else { Acquired::Fresh }))
    }
}

//! In-memory fakes for the capture contract (U01 concrete tests). These never
//! touch a real NIC. The settings fake counts get/deep-copy/free, poisons
//! freed handles (use-after-free detection) and can inject errors or a
//! changing-state sequence.

use crate::backend::{
    EffectiveDnsProbe, FamilyProbe, RawProperty, RawSettings, RegistryProvenance, RegistryValue,
    SettingsApi,
};
use crate::model::{CanonicalServer, CaptureError, Family};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

fn utf16le_z(text: &str) -> Vec<u8> {
    let mut v: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

pub fn registry_path(guid: &str, family: Family) -> String {
    format!(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}\\Parameters\\Interfaces\\{guid}",
        family.registry_service()
    )
}

/// Build a REG_SZ NameServer registry value for a static override.
pub fn static_value(guid: &str, family: Family, text: &str) -> RegistryValue {
    RegistryValue {
        path: registry_path(guid, family),
        exists: true,
        value_type: Some(1),
        raw: Some(utf16le_z(text)),
        text: Some(text.to_string()),
    }
}

/// Present-but-empty REG_SZ (raw "0000"): automatic, corroborated by getter.
pub fn empty_value(guid: &str, family: Family) -> RegistryValue {
    RegistryValue {
        path: registry_path(guid, family),
        exists: true,
        value_type: Some(1),
        raw: Some(vec![0, 0]),
        text: Some(String::new()),
    }
}

/// Absent NameServer value: automatic candidate.
pub fn absent_value(guid: &str, family: Family) -> RegistryValue {
    RegistryValue {
        path: registry_path(guid, family),
        exists: false,
        value_type: None,
        raw: None,
        text: None,
    }
}

/// IP address assignment for one interface (fixture input): DHCP-assigned or
/// static. Models the adapter's IP provenance that exists alongside the DNS
/// configuration. The reader's provenance rule follows the NameServer-plus-
/// getter DNS override and never consults this (SPEC-DNS-FIX.md §12 U01).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAssignment {
    Dhcp,
    Static,
}

/// Convenience RawSettings with a server list and DoH properties.
pub fn raw_settings(name_server: Option<&str>, props: Vec<RawProperty>) -> RawSettings {
    RawSettings {
        flags_returned: 0,
        name_server: name_server.map(|s| s.to_string()),
        server_properties: props,
        ..RawSettings::default()
    }
}

pub fn doh_prop(server_index: u32, template: Option<&str>, flags: u64) -> RawProperty {
    RawProperty {
        version: 1,
        server_index,
        prop_type: 1,
        template: template.map(|s| s.to_string()),
        flags,
    }
}

#[derive(Default)]
struct FakeInner {
    next_id: u64,
    live: HashMap<u64, RawSettings>,
    freed: HashSet<u64>,
    responses: HashMap<(String, u64), RawSettings>,
    sequence: Option<VecDeque<RawSettings>>,
    get_error: Option<CaptureError>,
    get_error_by_flags: HashMap<u64, CaptureError>,
    deep_copy_error: Option<CaptureError>,
    gets: u64,
    deep_copies: u64,
    frees: u64,
    writes: u64,
    last_flags: Option<u64>,
}

/// Fake configured-settings API. Handle = u64 id into an owned store.
#[derive(Default)]
pub struct FakeSettingsApi {
    inner: RefCell<FakeInner>,
}

impl FakeSettingsApi {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_response(&self, guid: &str, flags: u64, raw: RawSettings) {
        self.inner.borrow_mut().responses.insert((guid.to_string(), flags), raw);
    }
    /// Program a changing-state sequence consumed one item per `get`.
    pub fn set_sequence(&self, items: Vec<RawSettings>) {
        self.inner.borrow_mut().sequence = Some(items.into());
    }
    pub fn set_get_error(&self, e: CaptureError) {
        self.inner.borrow_mut().get_error = Some(e);
    }
    /// Error only the getter call made with these flags (e.g. the IPv6
    /// selector), leaving other families' getters unaffected. Used to prove the
    /// two-family capture refuses rather than falling back to IPv4-only.
    pub fn set_get_error_for(&self, flags: u64, e: CaptureError) {
        self.inner.borrow_mut().get_error_by_flags.insert(flags, e);
    }
    pub fn set_deep_copy_error(&self, e: CaptureError) {
        self.inner.borrow_mut().deep_copy_error = Some(e);
    }
    pub fn gets(&self) -> u64 {
        self.inner.borrow().gets
    }
    pub fn deep_copies(&self) -> u64 {
        self.inner.borrow().deep_copies
    }
    pub fn frees(&self) -> u64 {
        self.inner.borrow().frees
    }
    /// Always zero: the capture contract performs no writes.
    pub fn writes(&self) -> u64 {
        self.inner.borrow().writes
    }
    pub fn live_handles(&self) -> usize {
        self.inner.borrow().live.len()
    }
    pub fn last_flags(&self) -> Option<u64> {
        self.inner.borrow().last_flags
    }
}

impl SettingsApi for FakeSettingsApi {
    type Handle = u64;

    fn get(&self, guid: &str, flags: u64) -> Result<u64, CaptureError> {
        let mut inner = self.inner.borrow_mut();
        inner.gets += 1;
        inner.last_flags = Some(flags);
        if let Some(e) = &inner.get_error {
            return Err(e.clone());
        }
        if let Some(e) = inner.get_error_by_flags.get(&flags) {
            return Err(e.clone());
        }
        let data = if let Some(seq) = inner.sequence.as_mut() {
            seq.pop_front().unwrap_or_default()
        } else {
            inner.responses.get(&(guid.to_string(), flags)).cloned().unwrap_or_default()
        };
        let id = inner.next_id;
        inner.next_id += 1;
        inner.live.insert(id, data);
        Ok(id)
    }

    fn deep_copy(&self, handle: &u64) -> Result<RawSettings, CaptureError> {
        let mut inner = self.inner.borrow_mut();
        inner.deep_copies += 1;
        if let Some(e) = &inner.deep_copy_error {
            return Err(e.clone());
        }
        if inner.freed.contains(handle) {
            return Err(CaptureError::QueryFailure("deep copy of freed handle".into()));
        }
        inner
            .live
            .get(handle)
            .cloned()
            .ok_or_else(|| CaptureError::QueryFailure("unknown handle".into()))
    }

    fn free(&self, handle: u64) {
        let mut inner = self.inner.borrow_mut();
        inner.frees += 1;
        inner.live.remove(&handle);
        inner.freed.insert(handle);
    }
}

#[derive(Default)]
struct FakeRegInner {
    values: HashMap<(String, Family), RegistryValue>,
    ip_assignments: HashMap<(String, Family), IpAssignment>,
    error: Option<CaptureError>,
    reads: u64,
}

/// Fake registry provenance source.
#[derive(Default)]
pub struct FakeRegistry {
    inner: RefCell<FakeRegInner>,
}

impl FakeRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_value(&self, guid: &str, family: Family, v: RegistryValue) {
        self.inner.borrow_mut().values.insert((guid.to_string(), family), v);
    }
    pub fn set_error(&self, e: CaptureError) {
        self.inner.borrow_mut().error = Some(e);
    }
    pub fn reads(&self) -> u64 {
        self.inner.borrow().reads
    }
    /// Fixture input: the interface's IP address assignment (DHCP vs static).
    pub fn set_ip_assignment(&self, guid: &str, family: Family, assignment: IpAssignment) {
        self.inner.borrow_mut().ip_assignments.insert((guid.to_string(), family), assignment);
    }
    pub fn ip_assignment(&self, guid: &str, family: Family) -> Option<IpAssignment> {
        self.inner.borrow().ip_assignments.get(&(guid.to_string(), family)).copied()
    }
}

impl RegistryProvenance for FakeRegistry {
    fn read_name_server(&self, guid: &str, family: Family) -> Result<RegistryValue, CaptureError> {
        let mut inner = self.inner.borrow_mut();
        inner.reads += 1;
        if let Some(e) = &inner.error {
            return Err(e.clone());
        }
        Ok(inner
            .values
            .get(&(guid.to_string(), family))
            .cloned()
            .unwrap_or_else(|| absent_value(guid, family)))
    }
}

/// Fake effective-address observation source. Models the adapter's currently
/// effective DNS servers (e.g. DHCP-lease-assigned), distinct from the
/// configured baseline. `set_effective` is the lease-change input.
#[derive(Default)]
pub struct FakeEffectiveDns {
    inner: RefCell<HashMap<(String, Family), Vec<CanonicalServer>>>,
}

impl FakeEffectiveDns {
    pub fn new() -> Self {
        Self::default()
    }
    /// Lease-change input: replace the adapter's effective DNS servers.
    pub fn set_effective(&self, guid: &str, family: Family, servers: &[&str]) {
        let parsed = servers.iter().map(|s| CanonicalServer::parse(s).unwrap()).collect();
        self.inner.borrow_mut().insert((guid.to_string(), family), parsed);
    }
    pub fn effective(&self, guid: &str, family: Family) -> Vec<CanonicalServer> {
        self.inner.borrow().get(&(guid.to_string(), family)).cloned().unwrap_or_default()
    }
}

impl EffectiveDnsProbe for FakeEffectiveDns {
    fn effective_servers(&self, guid: &str, family: Family) -> Result<Vec<CanonicalServer>, CaptureError> {
        Ok(self.effective(guid, family))
    }
}

/// Fake family probe; defaults to supported, overridable per adapter/family.
pub struct FakeProbe {
    overrides: RefCell<HashMap<(String, Family), bool>>,
}

impl Default for FakeProbe {
    fn default() -> Self {
        Self { overrides: RefCell::new(HashMap::new()) }
    }
}

impl FakeProbe {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self, guid: &str, family: Family, supported: bool) {
        self.overrides.borrow_mut().insert((guid.to_string(), family), supported);
    }
}

impl FamilyProbe for FakeProbe {
    fn family_supported(&self, guid: &str, family: Family) -> Result<bool, CaptureError> {
        Ok(*self.overrides.borrow().get(&(guid.to_string(), family)).unwrap_or(&true))
    }
}

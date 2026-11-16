//! In-memory fakes for the capture contract (U01 concrete tests). These never
//! touch a real NIC. The settings fake counts get/deep-copy/free, poisons
//! freed handles (use-after-free detection) and can inject errors or a
//! changing-state sequence.
//!
//! U03 adds [`FakeOs`]: a mutable fake OS implementing both [`DnsBackend`]
//! (read, via the same qualified capture pipeline) and [`DnsSetter`] (write),
//! with setter-call recording, request-ID counting, error/death injection and
//! per-adapter readback/capture faults. Clones share one machine state.

use crate::backend::{
    capture_stable, DnsBackend, EffectiveDnsProbe, FamilyProbe, FamilySelectorPolicy, RawProperty,
    RawSettings, RegistryProvenance, RegistryValue, SettingsApi, DNS_SETTING_IPV6,
};
use crate::model::{AdapterIdentity, CanonicalServer, Capability, CaptureError, Family, Snapshot};
use crate::setter::{DnsSetter, SetterError, SetterImage};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;

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

// ---- FakeOs (U03) ----------------------------------------------------------

/// One recorded setter call (evidence for write counts / request-ID dedup).
#[derive(Clone, Debug)]
pub struct SetterCall {
    pub request_id: String,
    pub guid: String,
    pub family: Family,
    pub image: SetterImage,
}

/// Setter fault: numeric status, whether the change lands BEFORE the error is
/// reported, and whether the process dies right after applying the change.
#[derive(Clone, Copy, Debug)]
pub struct FailSpec {
    pub status: u32,
    pub after_change: bool,
    pub die: bool,
}

#[derive(Default)]
struct OsInner {
    /// Configured state per adapter/family. `name_server` None = pristine
    /// automatic (absent registry value, null getter); Some("") = cleared
    /// automatic (present-empty REG_SZ, empty-string getter); Some(list) =
    /// static override. Profile/context fields live in the same RawSettings.
    state: HashMap<(String, Family), RawSettings>,
    identities: Vec<AdapterIdentity>,
    calls: Vec<SetterCall>,
    request_counts: HashMap<String, u32>,
    fail_next: Option<FailSpec>,
    fail_for: HashMap<(String, Family), FailSpec>,
    readback_errors: HashMap<(String, Family), CaptureError>,
    capture_errors: HashMap<(String, Family), CaptureError>,
    /// Link-down markers (U04): a disconnected adapter is still enumerated
    /// and its configured DNS is still readable/writable — link state never
    /// affects capture, readback or the setter. Only full removal
    /// ([`FakeOs::remove_adapter`]) makes an adapter missing/not-ready.
    disconnected: HashSet<String>,
}

/// Mutable fake OS: one shared machine state behind clones. Reads go through
/// the real qualified capture pipeline (registry + getter corroboration, IPv6
/// selector verification); writes apply the full setter image and re-sync both
/// evidence sources. Never touches a real NIC.
#[derive(Clone)]
pub struct FakeOs {
    inner: Rc<RefCell<OsInner>>,
    api: Rc<FakeSettingsApi>,
    reg: Rc<FakeRegistry>,
    probe: Rc<FakeProbe>,
    os_build: String,
}

impl Default for FakeOs {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeOs {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(OsInner::default())),
            api: Rc::new(FakeSettingsApi::new()),
            reg: Rc::new(FakeRegistry::new()),
            probe: Rc::new(FakeProbe::new()),
            os_build: "26300.9974".to_string(),
        }
    }

    pub fn with_os_build(mut self, build: &str) -> Self {
        self.os_build = build.to_string();
        self
    }

    pub fn settings_api(&self) -> Rc<FakeSettingsApi> {
        Rc::clone(&self.api)
    }
    pub fn registry(&self) -> Rc<FakeRegistry> {
        Rc::clone(&self.reg)
    }
    pub fn probe(&self) -> Rc<FakeProbe> {
        Rc::clone(&self.probe)
    }

    /// Register an adapter, pristine automatic on both families.
    pub fn add_adapter(&self, guid: &str, name_hint: &str) {
        let mut inner = self.inner.borrow_mut();
        inner.identities.push(AdapterIdentity {
            adapter_guid: guid.to_string(),
            luid: 1,
            if_index: 12,
            name_hint: name_hint.to_string(),
            device_instance_hint: Some(format!("fake\\{guid}")),
        });
        for family in [Family::Ipv4, Family::Ipv6] {
            inner.state.entry((guid.to_string(), family)).or_default();
            self.sync(&mut inner, guid, family);
        }
    }

    /// Remove an adapter (disconnection / death): reads fail afterwards.
    pub fn remove_adapter(&self, guid: &str) {
        let mut inner = self.inner.borrow_mut();
        inner.identities.retain(|i| i.adapter_guid != guid);
        for family in [Family::Ipv4, Family::Ipv6] {
            inner.state.remove(&(guid.to_string(), family));
        }
    }

    /// Mark an adapter link-down (U04). It stays enumerated and its
    /// configured DNS stays readable/writable: a disconnected-but-
    /// configurable adapter restores now (§7 step 5). Only removal makes an
    /// adapter missing/not-ready (deferred, retried on arrival).
    pub fn set_disconnected(&self, guid: &str, down: bool) {
        let mut inner = self.inner.borrow_mut();
        if down {
            inner.disconnected.insert(guid.to_string());
        } else {
            inner.disconnected.remove(guid);
        }
    }

    pub fn is_disconnected(&self, guid: &str) -> bool {
        self.inner.borrow().disconnected.contains(guid)
    }

    /// Fixture input: set the configured NameServer + properties directly
    /// (bypasses the setter; no call is recorded).
    pub fn set_configured(&self, guid: &str, family: Family, ns: &str, props: Vec<RawProperty>) {
        let mut inner = self.inner.borrow_mut();
        let entry = inner.state.entry((guid.to_string(), family)).or_default();
        entry.name_server = Some(ns.to_string());
        entry.server_properties = props;
        self.sync(&mut inner, guid, family);
    }

    pub fn configured(&self, guid: &str, family: Family) -> (String, Vec<RawProperty>) {
        let inner = self.inner.borrow();
        match inner.state.get(&(guid.to_string(), family)) {
            Some(s) => (s.name_server.clone().unwrap_or_default(), s.server_properties.clone()),
            None => (String::new(), Vec::new()),
        }
    }

    /// Fixture input: an active profile override (capture must refuse).
    pub fn set_profile(&self, guid: &str, family: Family, ns: Option<&str>, props: Vec<RawProperty>) {
        let mut inner = self.inner.borrow_mut();
        let entry = inner.state.entry((guid.to_string(), family)).or_default();
        entry.profile_name_server = ns.map(|s| s.to_string());
        entry.profile_server_properties = props;
        self.sync(&mut inner, guid, family);
    }

    /// Mutate context/profile evidence fields, then re-sync the getter.
    pub fn update_raw(&self, guid: &str, family: Family, f: impl FnOnce(&mut RawSettings)) {
        let mut inner = self.inner.borrow_mut();
        let entry = inner.state.entry((guid.to_string(), family)).or_default();
        f(entry);
        self.sync(&mut inner, guid, family);
    }

    pub fn fail_next_setter(&self, status: u32, after_change: bool) {
        self.inner.borrow_mut().fail_next = Some(FailSpec { status, after_change, die: false });
    }
    pub fn fail_setter_for(&self, guid: &str, family: Family, status: u32, after_change: bool) {
        self.inner.borrow_mut().fail_for.insert(
            (guid.to_string(), family),
            FailSpec { status, after_change, die: false },
        );
    }
    /// The next setter call applies the change, then the process dies (lost
    /// reply): recovery must settle the intent by readback, never re-call.
    pub fn die_after_change(&self) {
        self.inner.borrow_mut().fail_next = Some(FailSpec { status: 0, after_change: true, die: true });
    }

    pub fn set_readback_error(&self, guid: &str, family: Family, e: CaptureError) {
        self.inner.borrow_mut().readback_errors.insert((guid.to_string(), family), e);
    }
    pub fn clear_readback_error(&self, guid: &str, family: Family) {
        self.inner.borrow_mut().readback_errors.remove(&(guid.to_string(), family));
    }
    pub fn set_capture_error(&self, guid: &str, family: Family, e: CaptureError) {
        self.inner.borrow_mut().capture_errors.insert((guid.to_string(), family), e);
    }
    pub fn clear_capture_error(&self, guid: &str, family: Family) {
        self.inner.borrow_mut().capture_errors.remove(&(guid.to_string(), family));
    }
    pub fn clear_failures(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.fail_next = None;
        inner.fail_for.clear();
        inner.readback_errors.clear();
        inner.capture_errors.clear();
    }

    pub fn setter_calls(&self) -> Vec<SetterCall> {
        self.inner.borrow().calls.clone()
    }
    pub fn setter_call_count(&self) -> usize {
        self.inner.borrow().calls.len()
    }
    pub fn calls_for_request(&self, request_id: &str) -> u32 {
        self.inner.borrow().request_counts.get(request_id).copied().unwrap_or(0)
    }

    fn sync(&self, inner: &mut OsInner, guid: &str, family: Family) {
        let flags = match family {
            Family::Ipv4 => 0,
            Family::Ipv6 => DNS_SETTING_IPV6,
        };
        let entry = inner.state.get(&(guid.to_string(), family)).cloned().unwrap_or_default();
        let mut raw = entry.clone();
        raw.flags_returned = flags;
        self.api.set_response(guid, flags, raw);
        let rv = match &entry.name_server {
            None => absent_value(guid, family),
            Some(s) if s.is_empty() => empty_value(guid, family),
            Some(s) => static_value(guid, family, s),
        };
        self.reg.set_value(guid, family, rv);
    }

    fn read(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError> {
        let cap = self.capability(guid, family)?;
        if !cap.family_supported {
            return Err(CaptureError::UnsupportedFamily(family));
        }
        if !self.inner.borrow().state.contains_key(&(guid.to_string(), family)) {
            return Err(CaptureError::QueryFailure(format!("adapter {guid} not present")));
        }
        let now = (crate::backend::system_clock())();
        capture_stable(
            &*self.api,
            &*self.reg,
            guid,
            family,
            &FamilySelectorPolicy::VersionGatedException,
            cap,
            &now,
        )
    }
}

impl DnsBackend for FakeOs {
    fn adapters(&self) -> Result<Vec<AdapterIdentity>, CaptureError> {
        Ok(self.inner.borrow().identities.clone())
    }
    fn capability(&self, guid: &str, family: Family) -> Result<Capability, CaptureError> {
        Ok(Capability {
            os_build: self.os_build.clone(),
            reader_revision: 1,
            api_version: 3,
            family_supported: self.probe.family_supported(guid, family)?,
        })
    }
    fn capture(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError> {
        if let Some(e) = self.inner.borrow().capture_errors.get(&(guid.to_string(), family)) {
            return Err(e.clone());
        }
        self.read(guid, family)
    }
    fn readback(&self, guid: &str, family: Family) -> Result<Snapshot, CaptureError> {
        if let Some(e) = self.inner.borrow().readback_errors.get(&(guid.to_string(), family)) {
            return Err(e.clone());
        }
        self.read(guid, family)
    }
}

impl DnsSetter for FakeOs {
    fn set(
        &self,
        request_id: &str,
        guid: &str,
        family: Family,
        image: &SetterImage,
    ) -> Result<(), SetterError> {
        let mut inner = self.inner.borrow_mut();
        inner.calls.push(SetterCall {
            request_id: request_id.to_string(),
            guid: guid.to_string(),
            family,
            image: image.clone(),
        });
        *inner.request_counts.entry(request_id.to_string()).or_insert(0) += 1;
        let spec = inner
            .fail_next
            .take()
            .or_else(|| inner.fail_for.get(&(guid.to_string(), family)).copied());
        let apply = spec.map(|s| s.status == 0 || s.after_change).unwrap_or(true);
        if apply {
            let entry = inner.state.entry((guid.to_string(), family)).or_default();
            entry.name_server = Some(image.name_server.clone());
            entry.server_properties = image
                .properties
                .iter()
                .map(|p| RawProperty {
                    version: p.version,
                    server_index: p.server_index,
                    prop_type: p.prop_type,
                    template: p.doh.template.clone(),
                    flags: p.doh.flags,
                })
                .collect();
            self.sync(&mut inner, guid, family);
        }
        if let Some(s) = spec {
            if s.die {
                panic!("FakeOs: death injection after change");
            }
            if s.status != 0 {
                return Err(SetterError {
                    status: s.status,
                    message: format!("injected setter failure for {guid} {}", family.as_str()),
                });
            }
        }
        Ok(())
    }
}

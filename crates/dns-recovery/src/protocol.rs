//! U05: authenticated versioned IPC protocol (SPEC-DNS-FIX.md §8.2).
//!
//! Wire form: `u32` little-endian length then UTF-8 JSON, `protocol = 1`,
//! maximum frame 1 MiB. No network listener; the transport (Windows named
//! pipe `\\.\pipe\Yeager.DnsRecovery.v1`) delivers one frame per message.
//!
//! This module is the portable codec + validation core. It never touches a
//! pipe, a process handle or the journal: transports authenticate the peer
//! into [`PeerAuth`] and the [`ServiceHost`](crate::service::ServiceHost)
//! arbitrates leases. Unknown protocol versions and unknown operations are
//! refused without writes; only allowlisted provider/loopback plans are
//! accepted and request IDs are idempotency keys with stored replies.

use crate::journal;
use crate::model::{BoundEndpoint, DesiredPlan, Provider, Transport};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Named-pipe name mandated by §8.2.
pub const PIPE_NAME: &str = r"\\.\pipe\Yeager.DnsRecovery.v1";
/// IPC protocol version. Unknown versions refuse without writes.
pub const PROTOCOL_VERSION: u32 = 1;
/// Maximum frame: framing + UTF-8 JSON payload, 1 MiB total.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Request-ID dedup retention: results live for the transaction lifetime (the
/// host enforces this by matching the stored reply's journal generation
/// against the current generation); the in-memory table is bounded so a
/// flooding client cannot grow it, and overflow is journaled to a durable
/// dedup file so a replayed id is still answered from the stored reply after
/// the in-memory eviction.
pub const MAX_DEDUP_ENTRIES: usize = 512;
/// Durable dedup overflow cap: replayed ids stay answerable from the stored
/// reply long past the 512-entry in-memory eviction.
pub const MAX_PERSISTED_DEDUP_ENTRIES: usize = 10_000;
/// Durable dedup file name inside the service directory.
pub const DEDUP_FILE: &str = "dedup-v1.json";
/// Protected pipe DACL (SYSTEM + Administrators full control). The transport
/// applies this SDDL when creating the pipe instance.
pub const PIPE_SDDL: &str = "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

// ---- operations -------------------------------------------------------------

/// Allowlisted IPC operations (§8.2). Anything else on the wire is
/// [`ProtocolError::UnknownOperation`] — never a guessed dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Hello,
    Inspect,
    RegisterOwner,
    Apply,
    Reconfigure,
    Health,
    Quiesce,
    Restore,
    Status,
    EnterMaintenance,
    LeaveMaintenance,
    PrepareStop,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Hello => "hello",
            Operation::Inspect => "inspect",
            Operation::RegisterOwner => "register_owner",
            Operation::Apply => "apply",
            Operation::Reconfigure => "reconfigure",
            Operation::Health => "health",
            Operation::Quiesce => "quiesce",
            Operation::Restore => "restore",
            Operation::Status => "status",
            Operation::EnterMaintenance => "enter_maintenance",
            Operation::LeaveMaintenance => "leave_maintenance",
            Operation::PrepareStop => "prepare_stop",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "hello" => Operation::Hello,
            "inspect" => Operation::Inspect,
            "register_owner" => Operation::RegisterOwner,
            "apply" => Operation::Apply,
            "reconfigure" => Operation::Reconfigure,
            "health" => Operation::Health,
            "quiesce" => Operation::Quiesce,
            "restore" => Operation::Restore,
            "status" => Operation::Status,
            "enter_maintenance" => Operation::EnterMaintenance,
            "leave_maintenance" => Operation::LeaveMaintenance,
            "prepare_stop" => Operation::PrepareStop,
            _ => return None,
        })
    }

    /// Operations that may mutate DNS or journal state. Everything else is
    /// read-only or lease bookkeeping.
    pub fn mutating(self) -> bool {
        matches!(
            self,
            Operation::Apply
                | Operation::Reconfigure
                | Operation::Restore
                | Operation::EnterMaintenance
                | Operation::LeaveMaintenance
        )
    }

    /// Operations that require an authenticated owner lease
    /// (owner id + token + epoch).
    pub fn requires_owner(self) -> bool {
        matches!(
            self,
            Operation::Apply
                | Operation::Reconfigure
                | Operation::Health
                | Operation::Quiesce
                | Operation::Restore
        )
    }

    /// Operations reserved for an elevated administrator (audited caller).
    pub fn requires_admin(self) -> bool {
        matches!(
            self,
            Operation::EnterMaintenance
                | Operation::LeaveMaintenance
                | Operation::PrepareStop
        )
    }
}

// ---- wire types --------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    protocol: u32,
    request_id: String,
    operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
    #[serde(default)]
    body: serde_json::Value,
}

/// One authenticated request. `body` is operation-specific JSON validated by
/// [`validate_body`] before any dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub request_id: String,
    pub operation: Operation,
    pub owner_id: Option<String>,
    pub epoch: Option<u64>,
    pub body: serde_json::Value,
}

impl Request {
    pub fn new(
        request_id: String,
        operation: Operation,
        owner_id: Option<String>,
        epoch: Option<u64>,
        body: serde_json::Value,
    ) -> Self {
        Self {
            request_id,
            operation,
            owner_id,
            epoch,
            body,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReply {
    protocol: u32,
    request_id: String,
    service_instance: String,
    generation: u64,
    outcome: String,
    #[serde(default)]
    body: serde_json::Value,
}

/// One result. The transport echoes `request_id` verbatim; `generation` is
/// the journal generation the reply was computed against (0 when no journal
/// state was consulted). Replies are serializable so the host can persist
/// the dedup table and answer replayed ids from the stored reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub request_id: String,
    pub service_instance: String,
    pub generation: u64,
    pub outcome: String,
    pub body: serde_json::Value,
}

impl Reply {
    pub fn new(
        request_id: String,
        service_instance: String,
        generation: u64,
        outcome: impl Into<String>,
        body: serde_json::Value,
    ) -> Self {
        Self {
            request_id,
            service_instance,
            generation,
            outcome: outcome.into(),
            body,
        }
    }
}

// ---- errors ------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    OversizedFrame(usize),
    Truncated { declared: usize, actual: usize },
    TrailingBytes(usize),
    BadJson(String),
    UnknownProtocol(u32),
    UnknownOperation(String),
    BadRequestId(String),
    BadOwnerId(String),
    BadBody(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::OversizedFrame(n) => write!(f, "frame of {n} bytes exceeds 1 MiB"),
            ProtocolError::Truncated { declared, actual } => {
                write!(f, "frame declares {declared} bytes but carries {actual}")
            }
            ProtocolError::TrailingBytes(n) => write!(f, "frame has {n} trailing bytes"),
            ProtocolError::BadJson(m) => write!(f, "frame JSON invalid: {m}"),
            ProtocolError::UnknownProtocol(v) => write!(f, "unknown IPC protocol version {v}"),
            ProtocolError::UnknownOperation(o) => write!(f, "unknown IPC operation {o:?}"),
            ProtocolError::BadRequestId(m) => write!(f, "bad request id: {m}"),
            ProtocolError::BadOwnerId(m) => write!(f, "bad owner id: {m}"),
            ProtocolError::BadBody(m) => write!(f, "bad request body: {m}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

// ---- codec -------------------------------------------------------------------

fn check_request_id(id: &str) -> Result<(), ProtocolError> {
    if !journal::is_lower_uuid(id) {
        return Err(ProtocolError::BadRequestId(format!("{id:?} is not a lowercase UUID")));
    }
    Ok(())
}

fn check_owner_id(id: &str) -> Result<(), ProtocolError> {
    if !journal::is_lower_uuid(id) {
        return Err(ProtocolError::BadOwnerId(format!("{id:?} is not a lowercase UUID")));
    }
    Ok(())
}

/// Encode one request frame: u32 LE length + UTF-8 JSON. Refuses to emit
/// unknown protocol versions or oversized frames.
pub fn encode_frame(req: &Request) -> Result<Vec<u8>, ProtocolError> {
    check_request_id(&req.request_id)?;
    if let Some(o) = &req.owner_id {
        check_owner_id(o)?;
    }
    let wire = WireRequest {
        protocol: PROTOCOL_VERSION,
        request_id: req.request_id.clone(),
        operation: req.operation.as_str().to_string(),
        owner_id: req.owner_id.clone(),
        epoch: req.epoch,
        body: req.body.clone(),
    };
    let mut json =
        serde_json::to_vec(&wire).map_err(|e| ProtocolError::BadJson(e.to_string()))?;
    if json.len().checked_add(4).is_none_or(|n| n > MAX_FRAME_BYTES) {
        return Err(ProtocolError::OversizedFrame(json.len() + 4));
    }
    let mut out = Vec::with_capacity(json.len() + 4);
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.append(&mut json);
    Ok(out)
}

/// Decode exactly one frame. Length prefix must match the carried bytes;
/// unknown versions/operations are refused before any other handling.
pub fn decode_frame(bytes: &[u8]) -> Result<Request, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::OversizedFrame(bytes.len()));
    }
    if bytes.len() < 4 {
        return Err(ProtocolError::Truncated {
            declared: 4,
            actual: bytes.len(),
        });
    }
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&bytes[..4]);
    let declared = u32::from_le_bytes(prefix) as usize;
    if declared.checked_add(4).is_none_or(|n| n > MAX_FRAME_BYTES) {
        return Err(ProtocolError::OversizedFrame(declared + 4));
    }
    let actual = bytes.len() - 4;
    if actual != declared {
        if actual < declared {
            return Err(ProtocolError::Truncated { declared, actual });
        }
        return Err(ProtocolError::TrailingBytes(actual - declared));
    }
    let wire: WireRequest =
        serde_json::from_slice(&bytes[4..]).map_err(|e| ProtocolError::BadJson(e.to_string()))?;
    if wire.protocol != PROTOCOL_VERSION {
        return Err(ProtocolError::UnknownProtocol(wire.protocol));
    }
    let Some(operation) = Operation::parse(&wire.operation) else {
        return Err(ProtocolError::UnknownOperation(wire.operation));
    };
    check_request_id(&wire.request_id)?;
    if let Some(o) = &wire.owner_id {
        check_owner_id(o)?;
    }
    Ok(Request {
        request_id: wire.request_id,
        operation,
        owner_id: wire.owner_id,
        epoch: wire.epoch,
        body: wire.body,
    })
}

/// Encode one reply frame (same length-prefixed form).
pub fn encode_reply(rep: &Reply) -> Result<Vec<u8>, ProtocolError> {
    check_request_id(&rep.request_id)?;
    let wire = WireReply {
        protocol: PROTOCOL_VERSION,
        request_id: rep.request_id.clone(),
        service_instance: rep.service_instance.clone(),
        generation: rep.generation,
        outcome: rep.outcome.clone(),
        body: rep.body.clone(),
    };
    let mut json =
        serde_json::to_vec(&wire).map_err(|e| ProtocolError::BadJson(e.to_string()))?;
    if json.len().checked_add(4).is_none_or(|n| n > MAX_FRAME_BYTES) {
        return Err(ProtocolError::OversizedFrame(json.len() + 4));
    }
    let mut out = Vec::with_capacity(json.len() + 4);
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.append(&mut json);
    Ok(out)
}

/// Decode one reply frame. Replies echo the request ID so the client can
/// settle lost replies without inventing a new logical apply.
pub fn decode_reply(bytes: &[u8]) -> Result<Reply, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::OversizedFrame(bytes.len()));
    }
    if bytes.len() < 4 {
        return Err(ProtocolError::Truncated {
            declared: 4,
            actual: bytes.len(),
        });
    }
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&bytes[..4]);
    let declared = u32::from_le_bytes(prefix) as usize;
    let actual = bytes.len() - 4;
    if actual != declared {
        if actual < declared {
            return Err(ProtocolError::Truncated { declared, actual });
        }
        return Err(ProtocolError::TrailingBytes(actual - declared));
    }
    let wire: WireReply =
        serde_json::from_slice(&bytes[4..]).map_err(|e| ProtocolError::BadJson(e.to_string()))?;
    if wire.protocol != PROTOCOL_VERSION {
        return Err(ProtocolError::UnknownProtocol(wire.protocol));
    }
    check_request_id(&wire.request_id)?;
    Ok(Reply {
        request_id: wire.request_id,
        service_instance: wire.service_instance,
        generation: wire.generation,
        outcome: wire.outcome,
        body: wire.body,
    })
}

// ---- plan allowlist -----------------------------------------------------------

fn body_string(body: &serde_json::Value, key: &str) -> Result<String, ProtocolError> {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ProtocolError::BadBody(format!("{key:?} must be a string")))
}

fn body_u64(body: &serde_json::Value, key: &str) -> Result<u64, ProtocolError> {
    body.get(key).and_then(|v| {
        if let Some(n) = v.as_u64() {
            return Some(n);
        }
        v.as_str().and_then(|s| s.parse::<u64>().ok())
    }).ok_or_else(|| ProtocolError::BadBody(format!("{key:?} must be a u64")))
}

/// Parse and allowlist-validate a desired plan from a request body. Only the
/// four providers are accepted; bound endpoints must be loopback port 53; an
/// advertised family requires UDP+TCP readiness (§3.2). No snapshot
/// submission, no paths, no commands.
pub fn parse_plan(body: &serde_json::Value) -> Result<DesiredPlan, ProtocolError> {
    let provider = match body_string(body, "provider")?.as_str() {
        "auto" => Provider::Auto,
        "cloudflare" => Provider::Cloudflare,
        "google" => Provider::Google,
        "adguard" => Provider::Adguard,
        other => {
            return Err(ProtocolError::BadBody(format!(
                "unknown provider {other:?}: only auto/cloudflare/google/adguard are allowlisted"
            )));
        }
    };
    let local_requested = body
        .get("local_requested")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| ProtocolError::BadBody("local_requested must be a bool".into()))?;
    let readiness_generation = body_u64(body, "readiness_generation")?;
    let endpoints = body
        .get("bound_endpoints")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ProtocolError::BadBody("bound_endpoints must be an array".into()))?;
    if endpoints.len() > 8 {
        return Err(ProtocolError::BadBody("bound_endpoints exceeds 8 entries".into()));
    }
    let mut bound_endpoints = Vec::with_capacity(endpoints.len());
    for e in endpoints {
        let ip_text = e
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProtocolError::BadBody("endpoint ip must be a string".into()))?;
        let ip: IpAddr = ip_text
            .parse()
            .map_err(|_| ProtocolError::BadBody(format!("endpoint ip {ip_text:?} invalid")))?;
        if !ip.is_loopback() {
            return Err(ProtocolError::BadBody(format!(
                "endpoint {ip_text:?} is not loopback: only loopback port 53 plans are accepted"
            )));
        }
        let port = e
            .get("port")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ProtocolError::BadBody("endpoint port must be a u64".into()))?;
        if port != 53 {
            return Err(ProtocolError::BadBody(format!(
                "endpoint port {port} rejected: only loopback port 53 plans are accepted"
            )));
        }
        let transport = match e
            .get("transport")
            .and_then(|v| v.as_str())
        {
            Some("udp") => Transport::Udp,
            Some("tcp") => Transport::Tcp,
            other => {
                return Err(ProtocolError::BadBody(format!(
                    "unknown endpoint transport {other:?}"
                )));
            }
        };
        bound_endpoints.push(BoundEndpoint { ip, port: 53, transport });
    }
    // Family readiness rule mirrors journal::check_plan.
    let mut v4_udp = false;
    let mut v4_tcp = false;
    let mut v6_udp = false;
    let mut v6_tcp = false;
    for e in &bound_endpoints {
        match (e.ip.is_ipv4(), e.transport) {
            (true, Transport::Udp) => v4_udp = true,
            (true, Transport::Tcp) => v4_tcp = true,
            (false, Transport::Udp) => v6_udp = true,
            (false, Transport::Tcp) => v6_tcp = true,
        }
    }
    if (v4_udp || v4_tcp) && !(v4_udp && v4_tcp) {
        return Err(ProtocolError::BadBody(
            "advertised IPv4 endpoint family lacks UDP+TCP readiness".into(),
        ));
    }
    if (v6_udp || v6_tcp) && !(v6_udp && v6_tcp) {
        return Err(ProtocolError::BadBody(
            "advertised IPv6 endpoint family lacks UDP+TCP readiness".into(),
        ));
    }
    if local_requested && bound_endpoints.is_empty() {
        return Err(ProtocolError::BadBody(
            "local_requested without bound loopback endpoints".into(),
        ));
    }
    Ok(DesiredPlan {
        provider,
        local_requested,
        bound_endpoints,
        readiness_generation,
    })
}

/// Parse the adapter GUID selection: lowercase brace-free UUIDs, nonempty,
/// deduplicated. Identity is GUID × family, never display name/index.
pub fn parse_selected(body: &serde_json::Value) -> Result<Vec<String>, ProtocolError> {
    let arr = body
        .get("selected")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ProtocolError::BadBody("selected must be an array of adapter GUIDs".into()))?;
    if arr.is_empty() || arr.len() > 1024 {
        return Err(ProtocolError::BadBody(
            "selected must name 1..1024 adapter GUIDs".into(),
        ));
    }
    let mut out: Vec<String> = Vec::with_capacity(arr.len());
    for g in arr {
        let s = g
            .as_str()
            .ok_or_else(|| ProtocolError::BadBody("adapter GUID must be a string".into()))?;
        if !journal::is_lower_uuid(s) {
            return Err(ProtocolError::BadBody(format!(
                "adapter GUID {s:?} is not lowercase brace-free UUID"
            )));
        }
        if !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    Ok(out)
}

// ---- request-ID dedup ----------------------------------------------------------

/// Bounded idempotency table: a duplicate request ID replays the stored
/// reply and MUST NOT repeat the mutation (§8.2). Results are retained while
/// the host lives (the transaction-lifetime rule is enforced by the host's
/// generation check — see service.rs).
pub struct DedupCache {
    map: HashMap<String, Reply>,
    order: VecDeque<String>,
    cap: usize,
}

impl DedupCache {
    pub fn new() -> Self {
        Self::with_cap(MAX_DEDUP_ENTRIES)
    }

    /// Custom bound (tests force eviction with a small table; production
    /// uses [`MAX_DEDUP_ENTRIES`]).
    pub fn with_cap(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// Resize the bound, evicting oldest-first past the new cap.
    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap.max(1);
        while self.map.len() > self.cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.map.remove(&old);
                }
                None => break,
            }
        }
    }

    pub fn lookup(&self, request_id: &str) -> Option<&Reply> {
        self.map.get(request_id)
    }

    pub fn store(&mut self, request_id: String, reply: Reply) {
        if self.map.contains_key(&request_id) {
            return;
        }
        if self.map.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.order.push_back(request_id.clone());
        self.map.insert(request_id, reply);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Ordered snapshot for durable persistence (oldest first).
    pub fn entries(&self) -> Vec<(String, Reply)> {
        self.order
            .iter()
            .filter_map(|k| self.map.get(k).map(|r| (k.clone(), r.clone())))
            .collect()
    }

    /// Rebuild from persisted entries, oldest first; the memory bound still
    /// applies (newest entries win past the cap).
    pub fn restore(entries: Vec<(String, Reply)>) -> Self {
        let mut d = Self::new();
        for (k, r) in entries {
            d.store(k, r);
        }
        d
    }
}

impl Default for DedupCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---- peer authentication -------------------------------------------------------

/// Transport-authenticated caller identity. The pipe server derives this from
/// impersonation + token inspection, `GetNamedPipeClientProcessId` and the
/// *server-side* process image (path, file id, SHA-256 of the image file) —
/// never from caller-supplied fields. The client derives `server_pid` from
/// `GetNamedPipeServerProcessId` and compares it against the SCM service PID
/// plus the protected image identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAuth {
    pub pid: u32,
    pub creation_filetime: u64,
    pub user_sid: String,
    pub elevated: bool,
    pub session_id: u32,
    pub logon_luid: u64,
    pub image_path: String,
    /// Server-observed file id of the caller process image (never caller
    /// supplied). Empty only on non-owner paths that never bind identity.
    pub image_file_id: String,
    /// Server-observed SHA-256 of the caller process image (never caller
    /// supplied). Empty only on non-owner paths that never bind identity.
    pub image_sha256: String,
    /// True when the transport detected a remote (network) client. The pipe
    /// is created with PIPE_REJECT_REMOTE_CLIENTS, so this is defense in
    /// depth: remote is always rejected.
    pub remote: bool,
    /// Server PID observed by the client (None on the server side).
    pub server_pid: Option<u32>,
    /// Expected service PID from SCM (None when the client skips the check,
    /// which only the offline helper may do).
    pub expected_server_pid: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    Remote,
    Unelevated,
    SpoofedServer { observed: Option<u32>, expected: Option<u32> },
    BadIdentity(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Remote => write!(f, "remote IPC client rejected"),
            AuthError::Unelevated => write!(f, "unelevated IPC client rejected"),
            AuthError::SpoofedServer { observed, expected } => write!(
                f,
                "IPC server identity mismatch (observed {observed:?}, expected {expected:?})"
            ),
            AuthError::BadIdentity(m) => write!(f, "IPC peer identity invalid: {m}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl PeerAuth {
    /// Gate every operation. Remote, unelevated, spoofed-PID/server, empty
    /// SID/image or zero PID/filetime callers are rejected before any lease
    /// lookup or journal access.
    pub fn authorize(&self, op: Operation) -> Result<(), AuthError> {
        if self.remote {
            return Err(AuthError::Remote);
        }
        if !self.elevated {
            return Err(AuthError::Unelevated);
        }
        if self.pid == 0 || self.user_sid.is_empty() || self.image_path.is_empty() {
            return Err(AuthError::BadIdentity("pid/sid/image must be present".into()));
        }
        if self.creation_filetime == 0 && op.requires_owner() {
            return Err(AuthError::BadIdentity(
                "owner operations require a creation FILETIME".into(),
            ));
        }
        // Owner identity binds to the server-observed process image: a peer
        // that would bind a lease (registration or an owner operation) must
        // carry the process-derived file id and image hash. The server never
        // accepts these from the request body.
        if op.requires_owner() || op == Operation::RegisterOwner {
            if self.image_file_id.is_empty() || !journal::is_sha256_hex(&self.image_sha256) {
                return Err(AuthError::BadIdentity(
                    "owner identity requires a server-observed image file id and SHA-256".into(),
                ));
            }
        }
        if let (Some(observed), Some(expected)) = (self.server_pid, self.expected_server_pid)
        {
            if observed != expected {
                return Err(AuthError::SpoofedServer {
                    observed: self.server_pid,
                    expected: self.expected_server_pid,
                });
            }
        }
        Ok(())
    }
}

// ---- exit-code mapping ----------------------------------------------------------

/// CLI exit codes (§8.3): 0 verified clean/success; 10 live-owner/busy;
/// 11 pending/unavailable; 12 conflict; 13 privilege/service/auth;
/// 14 integrity/unknown version; 15 unsupported capture/API.
pub fn exit_code_for_outcome(outcome: &str) -> i32 {
    match outcome {
        "active" | "verified_restored" | "success" | "clean" => 0,
        "busy" | "live_owner" => 10,
        "pending" | "unavailable" | "deferred" => 11,
        "conflict" => 12,
        "refused" | "auth_rejected" | "service_unavailable" => 13,
        "integrity_error" | "unknown_version" => 14,
        "unsupported" => 15,
        _ => 11,
    }
}

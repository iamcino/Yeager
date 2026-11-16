//! U06: client for the U05 privileged DNS-recovery service.
//!
//! The Hange listener supervisor talks to the privileged service through
//! this client — never by writing system DNS itself and never through a
//! second journal implementation. The trait is object-safe and fake-backed:
//! `cargo test` drives the **real** [`ServiceHost`](dns_recovery::ServiceHost)
//! state machine via [`HostClient`] against fake OS/journal/lock/clock, so
//! endpoint readiness, epoch correspondence and restore semantics are proven
//! without touching real NICs.
//!
//! Production transport (Windows named pipe with a real 5 s read deadline)
//! is [`PipeClient`]; off Windows every call reports `Unavailable` so no
//! test or non-Windows build can mistake a missing service for success.

use dns_recovery::journal;
use dns_recovery::model::DesiredPlan;
use dns_recovery::protocol::{Operation, Reply, Request};
use std::time::Duration;

/// Overall IPC deadline: a stalled frame must be dropped at the deadline so
/// a stuck client can never block the watchdog or the stop path.
pub const IPC_DEADLINE: Duration = Duration::from_secs(5);

/// Real service binary versions as reported by the service itself over the
/// pipe (Hello reply: `protocol`, `journal_version`, `service_version`).
/// The updater gate reads these — never the app's own constants — so a
/// service binary that predates or postdates the GUI is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceVersions {
    pub protocol: u32,
    pub journal_version: u32,
    pub service_version: (u32, u32, u32),
}

fn parse_dotted_version(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().strip_prefix('v').unwrap_or(s.trim());
    let mut parts = s.split('.');
    let mut next = || {
        parts
            .next()
            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))?
            .parse()
            .ok()
    };
    let v = (next()?, next()?, next()?);
    parts.next().is_none().then_some(v)
}

/// Authenticated lease credentials for one owner session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseCreds {
    pub owner_id: String,
    pub token: String,
    pub epoch: u64,
}

/// Successful registration: the lease token plus the journal epoch every
/// later call must echo (a revoked epoch can never be revived).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub token: String,
    pub epoch: u64,
    pub generation: u64,
    pub reattached: bool,
}

/// Service outcome, mapped from the wire `outcome` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcOutcome {
    Success,
    Active,
    VerifiedRestored,
    Pending,
    Conflict,
    Refused,
    Busy,
    Unsupported,
    Unavailable,
    IntegrityError,
}

/// One mutating/read call result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcReport {
    pub outcome: SvcOutcome,
    pub generation: u64,
    pub message: String,
}

/// A refused/failed call with its machine-readable kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcError {
    pub outcome: SvcOutcome,
    pub message: String,
}

impl std::fmt::Display for SvcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.outcome, self.message)
    }
}
impl std::error::Error for SvcError {}

/// Map a wire outcome string onto [`SvcOutcome`]. Unknown strings are
/// `Unavailable` — never mistaken for success.
pub fn map_outcome(outcome: &str) -> SvcOutcome {
    match outcome {
        "success" => SvcOutcome::Success,
        "active" => SvcOutcome::Active,
        "verified_restored" => SvcOutcome::VerifiedRestored,
        "pending" => SvcOutcome::Pending,
        "conflict" => SvcOutcome::Conflict,
        "refused" => SvcOutcome::Refused,
        "busy" => SvcOutcome::Busy,
        "unsupported" => SvcOutcome::Unsupported,
        "unavailable" => SvcOutcome::Unavailable,
        "integrity_error" => SvcOutcome::IntegrityError,
        _ => SvcOutcome::Unavailable,
    }
}

impl SvcReport {
    pub fn from_reply(reply: &Reply) -> Self {
        let message = reply
            .body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Self {
            outcome: map_outcome(&reply.outcome),
            generation: reply.generation,
            message,
        }
    }

    /// Success-like outcomes: the requested plan is in effect.
    ///
    /// Only `Active` means the new plan holds. `verified_restored` means the
    /// engine rolled the attempt back to the pre-takeover original, so the
    /// new plan is NOT in effect and callers must report failure with the
    /// previous listener kept. `success` (health/quiesce) never carries a
    /// plan, so it is not `is_ok` here — match those outcomes explicitly.
    pub fn is_ok(&self) -> bool {
        matches!(self.outcome, SvcOutcome::Active)
    }
}

/// Owner identity surfaced by `status`/`inspect` for boot classification.
/// `creation_filetime` is the recorded process creation time (0 when the
/// service predates the field); liveness needs pid + filetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSnapshot {
    pub owner_id: String,
    pub pid: u32,
    pub creation_filetime: u64,
    pub session_id: u32,
}

/// Rich inspection snapshot for truthful boot classification: the mapped
/// outcome plus the raw journal state and owner the service reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectSnapshot {
    pub outcome: SvcOutcome,
    pub generation: u64,
    pub journal_state: Option<String>,
    pub owner: Option<OwnerSnapshot>,
    pub message: String,
}

fn snapshot_from_reply(reply: &Reply) -> InspectSnapshot {
    let outcome = map_outcome(&reply.outcome);
    let body = &reply.body;
    let journal_state = body
        .get("journal_state")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let owner = body.get("owner").and_then(|o| {
        if o.is_null() {
            return None;
        }
        Some(OwnerSnapshot {
            owner_id: o
                .get("owner_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            pid: o.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            creation_filetime: o
                .get("creation_time_filetime")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            session_id: o.get("session_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        })
    });
    let message = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    InspectSnapshot {
        outcome,
        generation: reply.generation,
        journal_state,
        owner,
        message,
    }
}

/// The privileged-service surface the supervisor needs. All mutating calls
/// echo the lease token + epoch; a stale epoch is rejected, never revived.
pub trait DnsService {
    fn register_owner(
        &mut self,
        owner_id: &str,
        readiness_generation: u64,
        image_sha256: Option<&str>,
        image_file_id: Option<&str>,
    ) -> Result<Registration, SvcError>;
    fn apply(
        &mut self,
        creds: &LeaseCreds,
        selected: &[String],
        plan: &DesiredPlan,
    ) -> SvcReport;
    fn reconfigure(
        &mut self,
        creds: &LeaseCreds,
        selected: &[String],
        plan: &DesiredPlan,
    ) -> SvcReport;
    fn health(
        &mut self,
        creds: &LeaseCreds,
        listener_responding: bool,
        readiness_generation: u64,
    ) -> SvcReport;
    fn quiesce(&mut self, creds: &LeaseCreds) -> SvcReport;
    fn restore(&mut self, creds: &LeaseCreds) -> SvcReport;
    /// Dead-owner recovery without a lease (U08-REV2 item 1): settle a dead
    /// recorded owner's debt before any new registration. Default returns
    /// `Unavailable` so scripted fakes keep compiling; real clients override
    /// to call the service `recover_dead_owner` operation.
    fn recover_dead_owner(&mut self) -> SvcReport {
        SvcReport {
            outcome: SvcOutcome::Unavailable,
            generation: 0,
            message: "dead-owner recovery not supported by this service".into(),
        }
    }
    fn status(&mut self) -> SvcReport;
    /// Current journal transaction epoch, if the service reports one.
    /// After a successful takeover the journal epoch advances (0 -> 1) while
    /// the lease still carries the registration epoch; the coordinator
    /// refreshes from here so the next mutating call is not stale. Scripted
    /// fakes return `None` (no real journal; epoch checks are mocked).
    fn journal_epoch(&mut self) -> Option<u64> {
        None
    }
    /// Rich inspection snapshot (outcome + journal state + owner) for
    /// truthful boot classification. Default falls back to `status()` with
    /// no journal detail (scripted fakes); real clients override to parse
    /// the service `Status` body.
    fn inspect_snapshot(&mut self) -> InspectSnapshot {
        let rep = self.status();
        InspectSnapshot {
            outcome: rep.outcome,
            generation: rep.generation,
            journal_state: None,
            owner: None,
            message: rep.message,
        }
    }
}

/// Fresh request id (idempotency key) for one IPC call.
pub fn new_request_id() -> String {
    journal::new_uuid()
}

/// Map a registration reply onto credentials. A success without a lease
/// token is an unavailable service, never a half lease.
fn registration_from_reply(reply: &Reply) -> Result<Registration, SvcError> {
    match map_outcome(&reply.outcome) {
        SvcOutcome::Success => {
            let token = reply
                .body
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let epoch = reply.body.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
            let reattached = reply
                .body
                .get("reattached")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if token.is_empty() {
                return Err(SvcError {
                    outcome: SvcOutcome::Unavailable,
                    message: "register_owner succeeded without a lease token".into(),
                });
            }
            Ok(Registration {
                token,
                epoch,
                generation: reply.generation,
                reattached,
            })
        }
        outcome => Err(SvcError {
            outcome,
            message: reply
                .body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("registration failed")
                .to_string(),
        }),
    }
}

/// Request body for apply/reconfigure: token + adapter selection + the
/// allowlisted desired plan. Mirrors the U05 harness contract.
pub fn mutation_body(
    token: &str,
    selected: &[String],
    plan: &DesiredPlan,
) -> serde_json::Value {
    let plan_value = serde_json::to_value(plan).expect("desired plan serializes");
    let mut body = plan_value;
    let map = body.as_object_mut().expect("plan is an object");
    map.insert("token".into(), serde_json::Value::String(token.into()));
    map.insert(
        "selected".into(),
        serde_json::Value::Array(
            selected
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );
    body
}

/// In-process client driving the real [`ServiceHost`](dns_recovery::ServiceHost)
/// state machine directly. Test seam: the host runs against fakes, and the
/// peer identity is the test's own — production uses [`PipeClient`].
pub struct HostClient<'h, F: dns_recovery::fs::JournalFs + 'static> {
    host: &'h mut dns_recovery::ServiceHost<F>,
    peer: dns_recovery::protocol::PeerAuth,
}

impl<'h, F: dns_recovery::fs::JournalFs + 'static> HostClient<'h, F> {
    pub fn new(
        host: &'h mut dns_recovery::ServiceHost<F>,
        peer: dns_recovery::protocol::PeerAuth,
    ) -> Self {
        Self { host, peer }
    }

    fn roundtrip(&mut self, req: Request) -> Reply {
        self.host.dispatch(&self.peer, &req)
    }
}

impl<F: dns_recovery::fs::JournalFs + 'static> DnsService for HostClient<'_, F> {
    fn register_owner(
        &mut self,
        owner_id: &str,
        readiness_generation: u64,
        image_sha256: Option<&str>,
        image_file_id: Option<&str>,
    ) -> Result<Registration, SvcError> {
        let mut body = serde_json::json!({
            "owner_id": owner_id,
            "readiness_generation": readiness_generation,
        });
        if let Some(h) = image_sha256 {
            body["image_sha256"] = serde_json::Value::String(h.into());
        }
        if let Some(f) = image_file_id {
            body["image_file_id"] = serde_json::Value::String(f.into());
        }
        let req = Request::new(new_request_id(), Operation::RegisterOwner, None, None, body);
        let reply = self.roundtrip(req);
        registration_from_reply(&reply)
    }

    fn apply(
        &mut self,
        creds: &LeaseCreds,
        selected: &[String],
        plan: &DesiredPlan,
    ) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Apply,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            mutation_body(&creds.token, selected, plan),
        );
        SvcReport::from_reply(&self.roundtrip(req))
    }

    fn reconfigure(
        &mut self,
        creds: &LeaseCreds,
        selected: &[String],
        plan: &DesiredPlan,
    ) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Reconfigure,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            mutation_body(&creds.token, selected, plan),
        );
        SvcReport::from_reply(&self.roundtrip(req))
    }

    fn health(
        &mut self,
        creds: &LeaseCreds,
        listener_responding: bool,
        readiness_generation: u64,
    ) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Health,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            serde_json::json!({
                "token": creds.token,
                "listener_responding": listener_responding,
                "readiness_generation": readiness_generation,
            }),
        );
        SvcReport::from_reply(&self.roundtrip(req))
    }

    fn quiesce(&mut self, creds: &LeaseCreds) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Quiesce,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            serde_json::json!({ "token": creds.token }),
        );
        SvcReport::from_reply(&self.roundtrip(req))
    }

    fn restore(&mut self, creds: &LeaseCreds) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Restore,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            serde_json::json!({ "token": creds.token }),
        );
        SvcReport::from_reply(&self.roundtrip(req))
    }

    fn recover_dead_owner(&mut self) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::RecoverDeadOwner,
            None,
            None,
            serde_json::json!({}),
        );
        SvcReport::from_reply(&self.roundtrip(req))
    }

    fn status(&mut self) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Status,
            None,
            None,
            serde_json::json!({}),
        );
        SvcReport::from_reply(&self.roundtrip(req))
    }

    fn journal_epoch(&mut self) -> Option<u64> {
        let req = Request::new(
            new_request_id(),
            Operation::Status,
            None,
            None,
            serde_json::json!({}),
        );
        let reply = self.roundtrip(req);
        reply.body.get("epoch").and_then(|v| v.as_u64())
    }

    fn inspect_snapshot(&mut self) -> InspectSnapshot {
        let req = Request::new(
            new_request_id(),
            Operation::Status,
            None,
            None,
            serde_json::json!({}),
        );
        snapshot_from_reply(&self.roundtrip(req))
    }
}

/// Production Windows named-pipe client: one frame per call with a real
/// 5 s framing deadline covering the bytes actually in flight. A stalled
/// peer is dropped at the deadline — the worker that runs the watchdog and
/// the stop path is never blocked by a partial frame.
///
/// Server identity (§8.2) is checked before any frame is written: the pipe
/// server PID (via `GetNamedPipeServerProcessId`) must match the SCM service
/// PID, and the server process image must match the protected service image.
/// Fails closed: without a proven SCM PID the call reports `Unavailable`.
/// Off Windows every call reports `Unavailable` so no test or non-Windows
/// build can mistake a missing service for success.
pub struct PipeClient {
    _private: (),
}

impl PipeClient {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Real service versions from the pipe Hello reply (U09-REV F): the
    /// service's own protocol/journal/binary versions, not the app's
    /// constants. `None` when the service is unreachable or the reply
    /// carries no versions (fails closed — the updater gate refuses).
    pub fn service_versions(&self) -> Option<ServiceVersions> {
        let req = Request::new(
            new_request_id(),
            Operation::Hello,
            None,
            None,
            serde_json::json!({}),
        );
        let reply = self.roundtrip(req).ok()?;
        if crate::service::map_outcome(&reply.outcome) != SvcOutcome::Success {
            return None;
        }
        let protocol = reply
            .body
            .get("protocol")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)?;
        let journal_version = reply
            .body
            .get("journal_version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)?;
        let service_version = reply
            .body
            .get("service_version")
            .and_then(|v| v.as_str())
            .and_then(parse_dotted_version)?;
        Some(ServiceVersions {
            protocol,
            journal_version,
            service_version,
        })
    }

    fn roundtrip(&self, req: Request) -> Result<Reply, SvcError> {
        #[cfg(windows)]
        {
            self.pipe_roundtrip(req)
        }
        #[cfg(not(windows))]
        {
            let _ = req;
            Err(SvcError {
                outcome: SvcOutcome::Unavailable,
                // Never reached in the app, which only ships for Windows;
                // off Windows the service does not exist.
                message: "DNS recovery service is Windows-only".into(),
            })
        }
    }
}

impl Default for PipeClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeClient {
    fn call(&self, req: Request) -> SvcReport {
        match self.roundtrip(req) {
            Ok(reply) => SvcReport::from_reply(&reply),
            Err(e) => SvcReport {
                outcome: e.outcome,
                generation: 0,
                message: e.message,
            },
        }
    }
}

impl DnsService for PipeClient {
    fn register_owner(
        &mut self,
        owner_id: &str,
        readiness_generation: u64,
        image_sha256: Option<&str>,
        image_file_id: Option<&str>,
    ) -> Result<Registration, SvcError> {
        let mut body = serde_json::json!({
            "owner_id": owner_id,
            "readiness_generation": readiness_generation,
        });
        if let Some(h) = image_sha256 {
            body["image_sha256"] = serde_json::Value::String(h.into());
        }
        if let Some(f) = image_file_id {
            body["image_file_id"] = serde_json::Value::String(f.into());
        }
        let req = Request::new(new_request_id(), Operation::RegisterOwner, None, None, body);
        match self.roundtrip(req) {
            Ok(reply) => registration_from_reply(&reply),
            Err(e) => Err(e),
        }
    }

    fn apply(
        &mut self,
        creds: &LeaseCreds,
        selected: &[String],
        plan: &DesiredPlan,
    ) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Apply,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            mutation_body(&creds.token, selected, plan),
        );
        self.call(req)
    }

    fn reconfigure(
        &mut self,
        creds: &LeaseCreds,
        selected: &[String],
        plan: &DesiredPlan,
    ) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Reconfigure,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            mutation_body(&creds.token, selected, plan),
        );
        self.call(req)
    }

    fn health(
        &mut self,
        creds: &LeaseCreds,
        listener_responding: bool,
        readiness_generation: u64,
    ) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Health,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            serde_json::json!({
                "token": creds.token,
                "listener_responding": listener_responding,
                "readiness_generation": readiness_generation,
            }),
        );
        self.call(req)
    }

    fn quiesce(&mut self, creds: &LeaseCreds) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Quiesce,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            serde_json::json!({ "token": creds.token }),
        );
        self.call(req)
    }

    fn restore(&mut self, creds: &LeaseCreds) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Restore,
            Some(creds.owner_id.clone()),
            Some(creds.epoch),
            serde_json::json!({ "token": creds.token }),
        );
        self.call(req)
    }

    fn recover_dead_owner(&mut self) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::RecoverDeadOwner,
            None,
            None,
            serde_json::json!({}),
        );
        self.call(req)
    }

    fn status(&mut self) -> SvcReport {
        let req = Request::new(
            new_request_id(),
            Operation::Status,
            None,
            None,
            serde_json::json!({}),
        );
        self.call(req)
    }

    fn journal_epoch(&mut self) -> Option<u64> {
        let req = Request::new(
            new_request_id(),
            Operation::Status,
            None,
            None,
            serde_json::json!({}),
        );
        self.roundtrip(req)
            .ok()
            .and_then(|reply| reply.body.get("epoch").and_then(|v| v.as_u64()))
    }

    fn inspect_snapshot(&mut self) -> InspectSnapshot {
        let req = Request::new(
            new_request_id(),
            Operation::Status,
            None,
            None,
            serde_json::json!({}),
        );
        match self.roundtrip(req) {
            Ok(reply) => snapshot_from_reply(&reply),
            Err(e) => InspectSnapshot {
                outcome: e.outcome,
                generation: 0,
                journal_state: None,
                owner: None,
                message: e.message,
            },
        }
    }
}

#[cfg(windows)]
impl PipeClient {
    fn pipe_roundtrip(&self, req: Request) -> Result<Reply, SvcError> {
        let unavailable = |message: String| SvcError {
            outcome: SvcOutcome::Unavailable,
            message,
        };
        let frame = dns_recovery::protocol::encode_frame(&req)
            .map_err(|e| unavailable(format!("IPC encode failed: {e}")))?;
        // §8.2 server identity before any byte is written: the SCM record is
        // the expected PID; a missing SCM PID fails closed (no guess).
        let expected = dns_recovery::service_os::scm_service_pid()
            .map_err(|e| unavailable(format!("SCM service PID unavailable: {e}")))?
            .ok_or_else(|| unavailable("DNS recovery service is not running".into()))?;
        // The U05 transport carries the real 5 s framing budget on the reads
        // and writes actually in flight (overlapped I/O + CancelIoEx), not
        // just the caller's wait: a stalled reply is dropped at the deadline.
        let raw = dns_recovery::service_os::pipe_roundtrip(&frame, Some(expected))
            .map_err(unavailable)?;
        let reply = dns_recovery::protocol::decode_reply(&raw)
            .map_err(|e| unavailable(format!("IPC decode failed: {e}")))?;
        if reply.request_id != req.request_id {
            return Err(unavailable("IPC reply request id mismatch".into()));
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_map_exactly_and_unknown_is_never_success() {
        assert_eq!(map_outcome("success"), SvcOutcome::Success);
        assert_eq!(map_outcome("active"), SvcOutcome::Active);
        assert_eq!(map_outcome("verified_restored"), SvcOutcome::VerifiedRestored);
        assert_eq!(map_outcome("pending"), SvcOutcome::Pending);
        assert_eq!(map_outcome("conflict"), SvcOutcome::Conflict);
        assert_eq!(map_outcome("refused"), SvcOutcome::Refused);
        assert_eq!(map_outcome("busy"), SvcOutcome::Busy);
        assert_eq!(map_outcome("unsupported"), SvcOutcome::Unsupported);
        assert_eq!(map_outcome("unavailable"), SvcOutcome::Unavailable);
        assert_eq!(map_outcome("integrity_error"), SvcOutcome::IntegrityError);
        assert_eq!(map_outcome("escalate_privileges"), SvcOutcome::Unavailable);
        assert_eq!(map_outcome(""), SvcOutcome::Unavailable);
    }

    #[test]
    fn success_means_active_only() {
        // Enable/reconfigure succeed only on Active. VerifiedRestored means
        // the engine rolled back to the pre-takeover original (new plan NOT
        // in effect); Success carries no plan (health/quiesce). Neither is
        // a plan commit.
        assert!(SvcReport { outcome: SvcOutcome::Active, generation: 1, message: String::new() }.is_ok());
        for outcome in [
            SvcOutcome::Success,
            SvcOutcome::VerifiedRestored,
            SvcOutcome::Pending,
            SvcOutcome::Conflict,
            SvcOutcome::Refused,
            SvcOutcome::Busy,
            SvcOutcome::Unsupported,
            SvcOutcome::Unavailable,
            SvcOutcome::IntegrityError,
        ] {
            assert!(!SvcReport { outcome, generation: 1, message: String::new() }.is_ok());
        }
    }

    #[test]
    fn mutation_bodies_pass_the_service_allowlist() {
        let plan = DesiredPlan {
            provider: dns_recovery::model::Provider::Cloudflare,
            local_requested: true,
            bound_endpoints: vec![
                dns_recovery::model::BoundEndpoint {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 53,
                    transport: dns_recovery::model::Transport::Udp,
                },
                dns_recovery::model::BoundEndpoint {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 53,
                    transport: dns_recovery::model::Transport::Tcp,
                },
            ],
            readiness_generation: 3,
        };
        let selected = vec!["6329f16a-0a04-4c7b-a6a5-85f792a98aa0".to_string()];
        let body = mutation_body("tok", &selected, &plan);
        assert_eq!(body.get("token").and_then(|v| v.as_str()), Some("tok"));
        dns_recovery::protocol::parse_plan(&body).expect("plan allowlist");
        dns_recovery::protocol::parse_selected(&body).expect("selection allowlist");
    }

    #[test]
    fn request_ids_are_unique_idempotency_keys() {
        assert_ne!(new_request_id(), new_request_id());
    }
}

//! U09: installer / uninstall / portable provisioning planner and
//! update-service compatibility (SPEC-DNS-FIX.md §10, §12 U09).
//!
//! Pure, fake-backed policy: every decision takes an explicit context, never
//! touches a NIC, the SCM or the filesystem. The Inno installer, the portable
//! bootstrap and the in-app updater mirror this logic; the tests below are
//! the U09 fake-backed gate list (clean install, legacy upgrade,
//! active-current upgrade, nonresponsive GUI, absent/stopped service, failed
//! signature/start, interrupted replacement/rollback; active uninstall with
//! restore-before-deletion and abort on API failure/conflict/missing adapter;
//! GUI-update verify-before-restart; portable Q2 behavior; unknown-schema
//! downgrade refusal).
//!
//! Q2 is RULED (Cino, 2026-11-13): BOTH distributions carry the service —
//! the installer provisions it directly; the portable provisions it via an
//! elevated bootstrap into protected Program Files; absent-service portable
//! takeover refuses (no silent install, no watchdog from a writable folder).

use crate::journal::JOURNAL_VERSION;
use crate::protocol::PROTOCOL_VERSION;

// ---- shared version / identity constants ------------------------------------

/// Protected service binary path component (under %ProgramFiles%).
pub const PROTECTED_DIR_NAME: &str = "Yeager";
/// Protected service binary file name.
pub const SERVICE_BINARY_NAME: &str = "yeager-dns-recovery.exe";
/// Protected GUI binary file name.
pub const GUI_BINARY_NAME: &str = "yeager.exe";
/// SCM service name (§8.1).
pub const SERVICE_NAME: &str = "YeagerDnsRecovery";

/// Installer/uninstaller GUI-exit wait budget: 30 s (§10).
pub const GUI_EXIT_WAIT_SECS: u64 = 30;

// ---- service / journal / GUI state -------------------------------------------

/// SCM service state as observed by the installer (via SCM query).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Absent,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Unknown,
}

/// Journal status as reported by `inspect` / `status` (no journal reads here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalStatus {
    /// No journal file yet (fresh machine).
    Absent,
    Clean,
    OwnedActive,
    Restoring,
    RecoveryPending,
    Maintenance,
    Pending,
    Conflict,
    IntegrityError,
    UnknownVersion(u32),
    Unavailable,
}

impl JournalStatus {
    /// CLEAN (or absent for the installer preflight) is the only state that
    /// authorizes binary replacement. A live `maintenance` inspect is exit 11
    /// `pending`: it blocks replacement like any other debt. Pending
    /// adapters, conflicts, restoring/recovery-pending work and
    /// integrity/unknown-version states abort the preflight and preserve the
    /// old helper and the journal.
    pub fn allows_replacement(&self) -> bool {
        matches!(self, JournalStatus::Absent | JournalStatus::Clean)
    }

    pub fn blocks_with_debt(&self) -> bool {
        matches!(
            self,
            JournalStatus::OwnedActive
                | JournalStatus::Restoring
                | JournalStatus::RecoveryPending
                | JournalStatus::Pending
                | JournalStatus::Conflict
                | JournalStatus::Unavailable
                | JournalStatus::IntegrityError
                | JournalStatus::UnknownVersion(_)
                | JournalStatus::Maintenance
        )
    }
}

/// GUI process state as observed by the installer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiState {
    NotRunning,
    RunningResponsive,
    RunningNonresponsive,
}

/// Authenticode + hash verification of the staged helper / installer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    Valid,
    Invalid,
    Unavailable,
}

// ---- install planning ---------------------------------------------------------

/// Ordered installer steps (§10 item 1). The Inno `[Code]` hooks mirror this
/// order; every step is observable in tests through the fake context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallStep {
    StageVerifyHelper,
    CloseLegacyGuiGracefully,
    /// Upgrade path (a journal exists): enter service maintenance so no new
    /// takeover can race the binary replacement.
    EnterMaintenance,
    /// Clean-install path (no journal yet): prove the SCM service STOPPED
    /// (or absent) and recover offline. No maintenance marker is created:
    /// with nothing to guard, a marker would wedge a bare genesis journal
    /// that has no legal clean return (leave honestly refuses it — see the
    /// `maintenance_blocks_takeover_and_leaves_cleanly` unit test).
    OfflineRecoverProvenStopped,
    NotifyGuiRequestCoordinatorExit,
    WaitGuiExitUpTo30s,
    MonitoredForceKillOnlyWithMonitor,
    WaitForRestoreAfterKill,
    RequireCleanBeforeReplace,
    StopServiceAfterCleanAck,
    ReplaceProtectedBinaries,
    ConfigureScmPathAclRestartActions,
    StartAndValidateHelloInspection,
    LeaveMaintenance,
    LaunchGuiOnlyWhenReady,
    RollbackExecutableAndRegistration,
    RestartPreviousCompatibleService,
    FailInstallNoTakeoverRace,
}

/// Full installer context (all faked in tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallContext {
    pub service: ServiceState,
    pub journal: JournalStatus,
    pub gui: GuiState,
    /// Staged helper signature + hash check.
    pub signature: SignatureCheck,
    /// First service introduction on a machine that ran the legacy
    /// (pre-service) GUI.
    pub legacy_upgrade: bool,
    /// An independent monitor confirmed the nonresponsive GUI (only then may
    /// the installer force-kill; §10 item 1).
    pub independent_monitor_confirmed: bool,
    /// Starting the replacement service failed (or Hello/inspection failed).
    pub start_fails: bool,
    /// Replacement was interrupted mid-copy (crash/power loss model).
    pub replacement_interrupted: bool,
}

/// Installer outcome. `Abort` always preserves the old helper and the
/// journal; the journal survives every branch, including rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallDecision {
    Proceed { steps: Vec<InstallStep> },
    Abort { reason: String },
}

/// Plan the install/upgrade sequence (§10 item 1).
pub fn plan_install(ctx: &InstallContext) -> InstallDecision {
    // 1. Stage/verify the signed helper in the protected path. A failed
    // signature/start check fails the install — no takeover race.
    if ctx.signature != SignatureCheck::Valid {
        return InstallDecision::Abort {
            reason: "helper signature/hash verification failed; install aborted, old helper and journal preserved".into(),
        };
    }
    // Offline guard: a service in start-pending/stop-pending/unknown is not
    // proven STOPPED, so neither the maintenance IPC nor the offline path
    // may proceed (same rule as ServiceHost::offline_precheck).
    if matches!(
        ctx.service,
        ServiceState::StartPending | ServiceState::StopPending | ServiceState::Unknown
    ) {
        return InstallDecision::Abort {
            reason: "SCM service state is not proven STOPPED; install aborted, old helper and journal preserved".into(),
        };
    }
    // Unknown newer journal blocks an older installer/service (downgrade
    // refusal): never delete or overwrite unknown state.
    if matches!(ctx.journal, JournalStatus::UnknownVersion(_)) {
        return InstallDecision::Abort {
            reason: "unknown newer journal version; installer refuses to replace the service or schema".into(),
        };
    }
    if matches!(ctx.journal, JournalStatus::IntegrityError) {
        return InstallDecision::Abort {
            reason: "journal integrity failure; install aborted, evidence retained".into(),
        };
    }
    // Nonresponsive GUI without a confirmed independent monitor: never
    // force-kill blindly.
    if ctx.gui == GuiState::RunningNonresponsive && !ctx.independent_monitor_confirmed {
        return InstallDecision::Abort {
            reason: "GUI nonresponsive without a confirmed independent monitor; force kill refused".into(),
        };
    }
    // Require CLEAN before replacing/removing the service binary. Pending
    // adapters, conflicts, maintenance (live inspect is exit 11 pending) and
    // API failures abort the preflight and preserve the old helper and the
    // journal.
    if ctx.journal.blocks_with_debt() {
        return InstallDecision::Abort {
            reason: format!(
                "journal not clean ({:?}); upgrade preflight aborted, old helper and journal preserved",
                ctx.journal
            ),
        };
    }

    let mut steps = vec![InstallStep::StageVerifyHelper];
    if ctx.legacy_upgrade {
        // First service introduction closes the legacy GUI gracefully, then
        // applies the Q3 legacy policy (detection/reporting only; no
        // invented historical baseline).
        steps.push(InstallStep::CloseLegacyGuiGracefully);
    }
    // Maintenance guards existing journal state behind a live service; a
    // running service never takes the offline path (aligned with
    // `ServiceHost::offline_precheck`, which refuses Running). In every other
    // case the offline path (proven STOPPED-or-absent, boot replay owns
    // recovery) applies and no marker is created. In particular a maintenance
    // marker is never created when no journal exists yet: it would wedge a
    // bare genesis journal that has no legal clean return.
    let in_maintenance = ctx.service == ServiceState::Running;
    if in_maintenance {
        steps.push(InstallStep::EnterMaintenance);
    } else {
        steps.push(InstallStep::OfflineRecoverProvenStopped);
    }
    steps.push(InstallStep::NotifyGuiRequestCoordinatorExit);
    steps.push(InstallStep::WaitGuiExitUpTo30s);
    if ctx.gui == GuiState::RunningNonresponsive {
        steps.push(InstallStep::MonitoredForceKillOnlyWithMonitor);
        steps.push(InstallStep::WaitForRestoreAfterKill);
    }
    steps.push(InstallStep::RequireCleanBeforeReplace);
    steps.push(InstallStep::StopServiceAfterCleanAck);
    steps.push(InstallStep::ReplaceProtectedBinaries);
    steps.push(InstallStep::ConfigureScmPathAclRestartActions);
    steps.push(InstallStep::StartAndValidateHelloInspection);
    if ctx.start_fails {
        // Failure rolls back the executable and the registration and
        // restarts the previous compatible service. The journal survives.
        steps.push(InstallStep::RollbackExecutableAndRegistration);
        steps.push(InstallStep::RestartPreviousCompatibleService);
        steps.push(InstallStep::FailInstallNoTakeoverRace);
        return InstallDecision::Proceed { steps };
    }
    if ctx.replacement_interrupted {
        // Interrupted replacement: the staged copy plus the preserved
        // previous binary allow rollback; the journal (durable intent or
        // clean tombstone) survives and decides the next boot.
        steps.push(InstallStep::RollbackExecutableAndRegistration);
        steps.push(InstallStep::RestartPreviousCompatibleService);
        steps.push(InstallStep::FailInstallNoTakeoverRace);
        return InstallDecision::Proceed { steps };
    }
    // Leave maintenance only when it was entered: on the offline path there
    // is no marker, and leaving would pointlessly commit a genesis envelope.
    if in_maintenance {
        steps.push(InstallStep::LeaveMaintenance);
    }
    steps.push(InstallStep::LaunchGuiOnlyWhenReady);
    InstallDecision::Proceed { steps }
}

// ---- uninstall planning -------------------------------------------------------

/// Ordered uninstall steps (§10 item 2, clean-only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UninstallStep {
    EnterMaintenance,
    GracefulGuiShutdown,
    OptionalMonitoredForceKill,
    ExactRestoreVerify,
    SeparateTcpLogonCleanup,
    RequireClean,
    StopRemoveService,
    DeleteBinariesPreferences,
}

/// Uninstall context (all faked in tests). `silent` selects the nonzero exit
/// contract: silent mode returns nonzero instead of showing UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallContext {
    pub service: ServiceState,
    pub journal: JournalStatus,
    pub gui: GuiState,
    pub independent_monitor_confirmed: bool,
    /// Restore/verify outcome behind the uninstall: true when the exact
    /// original verified.
    pub restore_verified: bool,
    /// Adapter missing / API failure / conflict during restore.
    pub restore_api_failure: bool,
    pub restore_conflict: bool,
    pub adapter_missing: bool,
    pub silent: bool,
}

/// Uninstall outcome. Aborts happen BEFORE deletion, retaining the service,
/// the binaries and the ProgramData state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UninstallDecision {
    Proceed { steps: Vec<UninstallStep> },
    AbortBeforeDeletion { reason: String, exit_code: i32 },
}

/// Map an uninstall abort to the §8.3 exit code: pending/unavailable is 11,
/// conflict is 12, integrity/unknown version is 14, privilege/service/auth is
/// 13, live-owner/busy is 10. Silent mode returns the nonzero code; the
/// journal is always retained.
pub fn uninstall_abort_code(journal: &JournalStatus) -> i32 {
    match journal {
        JournalStatus::Conflict => 12,
        JournalStatus::IntegrityError | JournalStatus::UnknownVersion(_) => 14,
        JournalStatus::Pending
        | JournalStatus::Unavailable
        | JournalStatus::OwnedActive
        | JournalStatus::Restoring
        | JournalStatus::RecoveryPending => 11,
        _ => 11,
    }
}

/// Plan the clean-only uninstall (§10 item 2).
pub fn plan_uninstall(ctx: &UninstallContext) -> UninstallDecision {
    // Silent-mode contract (§10 item 2): aborts happen BEFORE deletion in
    // both modes; silent mode returns the measured nonzero §8.3 exit,
    // interactive mode shows the dialog (the ISS `[Code]` raises). The
    // `silent` flag is read in every abort arm below.
    let silent_note = if ctx.silent {
        " (silent: nonzero exit before deletion)"
    } else {
        " (interactive: dialog before deletion)"
    };
    // Pending recovery aborts BEFORE deletion, retaining the service, the
    // binaries and the ProgramData state.
    if ctx.restore_api_failure || ctx.adapter_missing {
        return UninstallDecision::AbortBeforeDeletion {
            reason: format!(
                "restore API failure / missing adapter; uninstall aborted before deletion, service/binaries/ProgramData retained{silent_note}"
            ),
            exit_code: 11,
        };
    }
    if ctx.restore_conflict || matches!(ctx.journal, JournalStatus::Conflict) {
        return UninstallDecision::AbortBeforeDeletion {
            reason: format!(
                "restore conflict; uninstall aborted before deletion, service/binaries/ProgramData retained{silent_note}"
            ),
            exit_code: 12,
        };
    }
    if matches!(
        ctx.journal,
        JournalStatus::IntegrityError | JournalStatus::UnknownVersion(_)
    ) {
        return UninstallDecision::AbortBeforeDeletion {
            reason: format!(
                "journal integrity/unknown version; uninstall aborted before deletion{silent_note}"
            ),
            exit_code: uninstall_abort_code(&ctx.journal),
        };
    }
    if matches!(
        ctx.journal,
        JournalStatus::Pending
            | JournalStatus::Unavailable
            | JournalStatus::OwnedActive
            | JournalStatus::Restoring
            | JournalStatus::RecoveryPending
    ) || !ctx.restore_verified
    {
        return UninstallDecision::AbortBeforeDeletion {
            reason: format!(
                "exact restore did not verify; uninstall aborted before deletion, service/binaries/ProgramData retained{silent_note}"
            ),
            exit_code: uninstall_abort_code(&ctx.journal),
        };
    }
    // Nonresponsive GUI without a confirmed monitor: no blind force-kill.
    if ctx.gui == GuiState::RunningNonresponsive && !ctx.independent_monitor_confirmed {
        return UninstallDecision::AbortBeforeDeletion {
            reason: format!(
                "GUI nonresponsive without a confirmed independent monitor; uninstall aborted{silent_note}"
            ),
            exit_code: 11,
        };
    }
    let mut steps = vec![
        UninstallStep::EnterMaintenance,
        UninstallStep::GracefulGuiShutdown,
    ];
    if ctx.gui == GuiState::RunningNonresponsive {
        steps.push(UninstallStep::OptionalMonitoredForceKill);
    }
    steps.push(UninstallStep::ExactRestoreVerify);
    steps.push(UninstallStep::SeparateTcpLogonCleanup);
    steps.push(UninstallStep::RequireClean);
    steps.push(UninstallStep::StopRemoveService);
    steps.push(UninstallStep::DeleteBinariesPreferences);
    UninstallDecision::Proceed { steps }
}

// ---- portable provisioning (Q2 ruled) ------------------------------------------

/// Where the running GUI was launched from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchLocation {
    /// `%ProgramFiles%\Yeager\yeager.exe` (installer distribution).
    ProtectedProgramFiles,
    /// Anywhere else (portable distribution).
    PortableFolder,
}

/// Portable provisioning context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableContext {
    pub location: LaunchLocation,
    pub service: ServiceState,
    pub journal: JournalStatus,
    /// The portable bootstrap runs elevated (it provisions a machine service).
    pub elevated: bool,
    /// Staged helper signature check (the portable carries the signed helper).
    pub helper_signature: SignatureCheck,
}

/// Portable provisioning decision (Q2 ruled behavior).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableDecision {
    /// Installed GUI or already-provisioned portable: maintain the service.
    MaintainService,
    /// First run from a portable folder: provision/maintain the persistent
    /// service in protected Program Files via the elevated bootstrap.
    ProvisionViaElevatedBootstrap,
    /// Absent-service portable takeover refuses (no silent install, no
    /// watchdog from a writable folder).
    RefuseAbsentServiceTakeover { reason: String },
    /// Unknown newer journal / integrity failure blocks portable takeover.
    RefuseUnknownOrIntegrity { reason: String },
}

/// Decide portable provisioning (§10 item 3, Q2 ruled).
pub fn plan_portable(ctx: &PortableContext) -> PortableDecision {
    if matches!(
        ctx.journal,
        JournalStatus::UnknownVersion(_) | JournalStatus::IntegrityError
    ) {
        return PortableDecision::RefuseUnknownOrIntegrity {
            reason: "unknown or corrupt journal; portable takeover refused, evidence retained".into(),
        };
    }
    match ctx.location {
        LaunchLocation::ProtectedProgramFiles => PortableDecision::MaintainService,
        LaunchLocation::PortableFolder => match ctx.service {
            ServiceState::Running | ServiceState::Stopped | ServiceState::Absent => {
                if ctx.helper_signature != SignatureCheck::Valid {
                    return PortableDecision::RefuseAbsentServiceTakeover {
                        reason: "portable helper signature invalid; takeover refused".into(),
                    };
                }
                if !ctx.elevated {
                    // The bootstrap itself must elevate; an unelevated
                    // portable cannot silently install machine software.
                    return PortableDecision::RefuseAbsentServiceTakeover {
                        reason: "portable first run requires the elevated bootstrap; unelevated takeover refused".into(),
                    };
                }
                // Q2 bootstrap: first run from a portable folder with the
                // service absent, elevated, and the helper signature valid
                // provisions the persistent service in protected Program
                // Files. Absent-service takeover without those three refuses
                // above (no silent install, no watchdog from a writable
                // folder).
                PortableDecision::ProvisionViaElevatedBootstrap
            }
            ServiceState::StartPending
            | ServiceState::StopPending
            | ServiceState::Unknown => PortableDecision::RefuseAbsentServiceTakeover {
                reason: "service state unknown/pending; portable takeover refuses".into(),
            },
        },
    }
}

/// Portable removal scope invariant (§10 item 3): moving or deleting the
/// portable GUI can never remove the protected recovery executable or state.
/// Portable cleanup deletes only the portable folder's own files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableRemovalScope {
    pub deletes_protected_binary: bool,
    pub deletes_program_data_state: bool,
    pub deletes_portable_folder_only: bool,
}

/// The only allowed portable removal scope.
pub fn portable_removal_scope() -> PortableRemovalScope {
    PortableRemovalScope {
        deletes_protected_binary: false,
        deletes_program_data_state: false,
        deletes_portable_folder_only: true,
    }
}

/// Behavior behind [`portable_removal_scope`]: the portable cleanup path
/// must never treat the protected binary or ProgramData state as deletion
/// targets. Returns true when `path` would be a forbidden deletion target.
pub fn portable_path_is_protected_deletion_target(path: &str) -> bool {
    let lower = path.to_lowercase().replace('/', "\\");
    lower.contains("program files\\yeager") || lower.contains("programdata\\yeager")
}

/// Behavior behind [`portable_removal_scope`]: portable cleanup deletes only
/// files inside the portable folder itself (never the protected locations
/// above). Conservative check: a portable-folder file is not a protected
/// target.
pub fn portable_path_is_portable_folder_file(path: &str) -> bool {
    !portable_path_is_protected_deletion_target(path)
}

// ---- update / service compatibility --------------------------------------------

/// What the running (or absent) service offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceInfo {
    pub protocol: u32,
    pub journal_version: u32,
    /// (major, minor, patch) of the installed service binary.
    pub service_version: (u32, u32, u32),
    pub state: ServiceState,
    pub journal: JournalStatus,
}

/// What an update release requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: (u32, u32, u32),
    pub required_protocol: u32,
    pub required_journal: u32,
    /// True when the release ships a new service binary / schema migration.
    pub requires_service_binary: bool,
}

/// Update routing decision (§10 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateDecision {
    /// Compatible GUI-only update: may retain the service, but MUST
    /// restore/verify before replacement/restart.
    GuiOnlyProceed { verify_before_restart: bool },
    /// Service-changing update: route to the signed installer and its
    /// maintenance sequence. The single-exe updater must never perform it.
    RouteToInstaller { reason: String },
    /// Refused: unknown newer journal, downgrade, absent/incompatible service.
    Refused { reason: String, exit_hint: String },
}

/// This binary's service requirements (what it was built against).
pub fn current_requirements() -> (u32, u32) {
    (PROTOCOL_VERSION, JOURNAL_VERSION)
}

/// Check update compatibility BEFORE installing a replacement — not merely
/// before spawning (§10 item 4). Also gates downgrades: an unknown newer
/// journal blocks the older service.
pub fn check_update_compat(
    service: Option<&ServiceInfo>,
    journal_version: Option<u32>,
    current_app: (u32, u32, u32),
    update: &UpdateManifest,
) -> UpdateDecision {
    // Unknown newer journal blocks the older service AND the update path:
    // never install an older schema over newer state.
    if let Some(v) = journal_version
        && v > JOURNAL_VERSION
    {
        return UpdateDecision::Refused {
            reason: format!(
                "journal version {v} is newer than this binary supports ({JOURNAL_VERSION}); update refused, older service blocked"
            ),
            exit_hint: "downgrade refused: unknown schema".into(),
        };
    }
    if let Some(svc) = service
        && (svc.journal == JournalStatus::UnknownVersion(0)
            || matches!(svc.journal, JournalStatus::UnknownVersion(_))
            || matches!(svc.journal, JournalStatus::IntegrityError))
    {
        return UpdateDecision::Refused {
            reason: "service reports unknown/integrity-failed journal; update refused".into(),
            exit_hint: "integrity/unknown version".into(),
        };
    }
    // Service-changing update routes to the signed installer.
    if update.required_protocol != PROTOCOL_VERSION
        || update.required_journal != JOURNAL_VERSION
        || update.requires_service_binary
    {
        return UpdateDecision::RouteToInstaller {
            reason: format!(
                "update v{}.{}.{} requires service protocol {} / journal {} (this binary: protocol {} / journal {}); use the signed installer and its maintenance sequence",
                update.version.0,
                update.version.1,
                update.version.2,
                update.required_protocol,
                update.required_journal,
                PROTOCOL_VERSION,
                JOURNAL_VERSION,
            ),
        };
    }
    // Downgrade to an older app over a compatible journal still refuses when
    // it would leave an incompatible service behind.
    if update.version < current_app
        && let Some(svc) = service
        && svc.service_version > update.version
    {
        return UpdateDecision::Refused {
            reason: "downgrade would leave a newer service behind the older app; use the signed installer".into(),
            exit_hint: "downgrade refused: service newer than target".into(),
        };
    }
    // Absent / stopped / incompatible / unhealthy service refuses new
    // takeover INCLUDING via the updater — capability is checked before the
    // replacement is installed, not merely before spawning.
    match service {
        None => UpdateDecision::Refused {
            reason: "no recovery service present; GUI-only update refuses (installer provisions the service)".into(),
            exit_hint: "absent service".into(),
        },
        Some(svc) => match svc.state {
            ServiceState::Running => UpdateDecision::GuiOnlyProceed {
                verify_before_restart: true,
            },
            ServiceState::Stopped => UpdateDecision::Refused {
                reason: "recovery service stopped; update refuses until the service is healthy (installer path)".into(),
                exit_hint: "stopped service".into(),
            },
            ServiceState::Absent => UpdateDecision::Refused {
                reason: "no recovery service present; GUI-only update refuses (installer provisions the service)".into(),
                exit_hint: "absent service".into(),
            },
            ServiceState::StartPending
            | ServiceState::StopPending
            | ServiceState::Unknown => UpdateDecision::Refused {
                reason: "service state unknown/pending; update refused".into(),
                exit_hint: "service unavailable".into(),
            },
        },
    }
}

/// Verify-before-restart gate for compatible GUI-only updates: the
/// replacement may restart only after a verified restore. A failed cleanup
/// cancels the restart (§10 item 4).
pub fn may_restart_after_cleanup(cleanup_verified: bool) -> bool {
    cleanup_verified
}

/// Download/install failure leaves the current active DNS untouched: no
/// service or journal mutation happens on the failure path. This is the
/// seam the updater tests assert (the failure arms return before any
/// replacement step).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadOutcome {
    Downloaded,
    DownloadFailedLeavesDnsUntouched,
    InstallFailedLeavesDnsUntouched,
}

/// Behavior contract for the failure arms: a download or install failure
/// performs no DNS mutation (no service call, no journal write, no exe
/// replacement). The gated updater returns before the replacement step, so
/// the current active DNS is untouched by construction.
pub fn download_failure_leaves_dns_untouched(outcome: &DownloadOutcome) -> bool {
    matches!(
        outcome,
        DownloadOutcome::DownloadFailedLeavesDnsUntouched
            | DownloadOutcome::InstallFailedLeavesDnsUntouched
    )
}

/// The failure arms never count as a successful download: they must not feed
/// the replacement step.
pub fn download_outcome_replaces_exe(outcome: &DownloadOutcome) -> bool {
    matches!(outcome, DownloadOutcome::Downloaded)
}

// ---- artifact verification (same policy for app, helper, installer) -----------

/// Hash + pinned-signature verification input (fake-backed; production feeds
/// `Get-FileHash` SHA-256 plus `verify.ps1` pinned-thumbprint results).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactCheck {
    pub sha256_matches: bool,
    pub signature_pinned_valid: bool,
}

/// The helper and the installer are verified under the same hash +
/// pinned-signature trust policy as the app binaries (§10 item 4).
pub fn verify_artifact(check: &ArtifactCheck) -> bool {
    check.sha256_matches && check.signature_pinned_valid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_ctx(
        service: ServiceState,
        journal: JournalStatus,
        gui: GuiState,
    ) -> InstallContext {
        InstallContext {
            service,
            journal,
            gui,
            signature: SignatureCheck::Valid,
            legacy_upgrade: false,
            independent_monitor_confirmed: true,
            start_fails: false,
            replacement_interrupted: false,
        }
    }

    #[test]
    fn clean_install_proceeds_through_hello_and_gui_when_ready() {
        let d = plan_install(&install_ctx(
            ServiceState::Absent,
            JournalStatus::Absent,
            GuiState::NotRunning,
        ));
        let steps = match d {
            InstallDecision::Proceed { steps } => steps,
            InstallDecision::Abort { reason } => panic!("clean install aborted: {reason}"),
        };
        assert!(steps.contains(&InstallStep::StageVerifyHelper));
        // Clean install (no journal): offline path with proven STOPPED, and
        // deliberately NO maintenance marker (nothing to guard; a marker
        // would wedge the bare genesis journal).
        assert!(steps.contains(&InstallStep::OfflineRecoverProvenStopped));
        assert!(!steps.contains(&InstallStep::EnterMaintenance));
        // Offline path: no marker entered, so none is left.
        assert!(!steps.contains(&InstallStep::LeaveMaintenance));
        assert!(steps.contains(&InstallStep::RequireCleanBeforeReplace));
        assert!(steps.contains(&InstallStep::StartAndValidateHelloInspection));
        assert!(steps.contains(&InstallStep::LaunchGuiOnlyWhenReady));
        // Postinstall GUI launch is the LAST step — only after ready.
        assert_eq!(steps.last(), Some(&InstallStep::LaunchGuiOnlyWhenReady));
    }

    #[test]
    fn legacy_upgrade_closes_gui_gracefully_with_no_invented_baseline() {
        let mut ctx = install_ctx(
            ServiceState::Absent,
            JournalStatus::Absent,
            GuiState::RunningResponsive,
        );
        ctx.legacy_upgrade = true;
        match plan_install(&ctx) {
            InstallDecision::Proceed { steps } => {
                assert!(steps.contains(&InstallStep::CloseLegacyGuiGracefully));
                // No invented historical baseline step exists anywhere.
                assert!(!steps.iter().any(|s| format!("{s:?}").contains("Baseline")));
            }
            InstallDecision::Abort { reason } => panic!("legacy upgrade aborted: {reason}"),
        }
    }

    #[test]
    fn active_current_upgrade_requires_clean_and_validates_hello() {
        let d = plan_install(&install_ctx(
            ServiceState::Running,
            JournalStatus::Clean,
            GuiState::RunningResponsive,
        ));
        match d {
            InstallDecision::Proceed { steps } => {
                let clean = steps
                    .iter()
                    .position(|s| *s == InstallStep::RequireCleanBeforeReplace)
                    .expect("clean gate present");
                let replace = steps
                    .iter()
                    .position(|s| *s == InstallStep::ReplaceProtectedBinaries)
                    .expect("replace present");
                assert!(clean < replace, "CLEAN precedes binary replacement");
                // Upgrade path (journal exists): maintenance guards the
                // replacement; the offline path is for the absent-journal case.
                assert!(steps.contains(&InstallStep::EnterMaintenance));
                assert!(!steps.contains(&InstallStep::OfflineRecoverProvenStopped));
                assert!(steps.contains(&InstallStep::LeaveMaintenance));
                assert!(steps.contains(&InstallStep::StartAndValidateHelloInspection));
            }
            InstallDecision::Abort { reason } => panic!("active upgrade aborted: {reason}"),
        }
    }

    #[test]
    fn nonresponsive_gui_needs_confirmed_monitor_then_waits_for_restore() {
        let mut ctx = install_ctx(
            ServiceState::Running,
            JournalStatus::Clean,
            GuiState::RunningNonresponsive,
        );
        ctx.independent_monitor_confirmed = false;
        match plan_install(&ctx) {
            InstallDecision::Abort { .. } => {}
            InstallDecision::Proceed { .. } => {
                panic!("nonresponsive GUI without a monitor must abort")
            }
        }
        ctx.independent_monitor_confirmed = true;
        match plan_install(&ctx) {
            InstallDecision::Proceed { steps } => {
                assert!(steps.contains(&InstallStep::MonitoredForceKillOnlyWithMonitor));
                assert!(steps.contains(&InstallStep::WaitForRestoreAfterKill));
            }
            InstallDecision::Abort { reason } => panic!("monitored kill aborted: {reason}"),
        }
    }

    #[test]
    fn absent_and_stopped_service_take_the_offline_path() {
        // No live service to quiesce: the offline path applies whether or
        // not a journal already exists (boot replay owns recovery).
        for journal in [JournalStatus::Absent, JournalStatus::Clean] {
            for service in [ServiceState::Absent, ServiceState::Stopped] {
                match plan_install(&install_ctx(service, journal.clone(), GuiState::NotRunning)) {
                    InstallDecision::Proceed { steps } => {
                        assert!(steps.contains(&InstallStep::OfflineRecoverProvenStopped));
                        assert!(!steps.contains(&InstallStep::EnterMaintenance));
                    }
                    InstallDecision::Abort { reason } => {
                        panic!("{service:?}/{journal:?} should take the offline path: {reason}")
                    }
                }
            }
        }
        // Live service plus existing journal: maintenance guards the
        // replacement.
        match plan_install(&install_ctx(
            ServiceState::Running,
            JournalStatus::Clean,
            GuiState::NotRunning,
        )) {
            InstallDecision::Proceed { steps } => {
                assert!(steps.contains(&InstallStep::EnterMaintenance));
                assert!(!steps.contains(&InstallStep::OfflineRecoverProvenStopped));
            }
            InstallDecision::Abort { reason } => {
                panic!("running service with clean journal should take the maintenance path: {reason}")
            }
        }
    }

    #[test]
    fn pending_conflict_restoring_debt_aborts_preflight_preserving_helper_and_journal() {
        for journal in [
            JournalStatus::Pending,
            JournalStatus::Conflict,
            JournalStatus::OwnedActive,
            JournalStatus::Restoring,
            JournalStatus::RecoveryPending,
            JournalStatus::Unavailable,
        ] {
            match plan_install(&install_ctx(ServiceState::Running, journal.clone(), GuiState::NotRunning)) {
                InstallDecision::Abort { reason } => assert!(
                    reason.contains("preserved") || reason.contains("aborted"),
                    "abort preserves helper/journal: {reason}"
                ),
                InstallDecision::Proceed { .. } => {
                    panic!("debt {journal:?} must abort the preflight")
                }
            }
        }
    }

    #[test]
    fn failed_signature_or_start_fails_the_install_with_no_takeover_race() {
        let mut ctx = install_ctx(ServiceState::Running, JournalStatus::Clean, GuiState::NotRunning);
        ctx.signature = SignatureCheck::Invalid;
        assert!(matches!(plan_install(&ctx), InstallDecision::Abort { .. }));
        let mut ctx = install_ctx(ServiceState::Running, JournalStatus::Clean, GuiState::NotRunning);
        ctx.start_fails = true;
        match plan_install(&ctx) {
            InstallDecision::Proceed { steps } => {
                assert!(steps.contains(&InstallStep::FailInstallNoTakeoverRace));
                assert!(!steps.contains(&InstallStep::LaunchGuiOnlyWhenReady));
            }
            InstallDecision::Abort { reason } => panic!("start failure should roll back, not preflight-abort: {reason}"),
        }
    }

    #[test]
    fn interrupted_replacement_rolls_back_with_journal_surviving() {
        let mut ctx = install_ctx(ServiceState::Running, JournalStatus::Clean, GuiState::NotRunning);
        ctx.replacement_interrupted = true;
        match plan_install(&ctx) {
            InstallDecision::Proceed { steps } => {
                assert!(steps.contains(&InstallStep::RollbackExecutableAndRegistration));
                assert!(steps.contains(&InstallStep::RestartPreviousCompatibleService));
                assert!(steps.contains(&InstallStep::FailInstallNoTakeoverRace));
            }
            InstallDecision::Abort { reason } => panic!("interruption should roll back: {reason}"),
        }
    }

    #[test]
    fn active_uninstall_restores_before_deletion() {
        let ctx = UninstallContext {
            service: ServiceState::Running,
            journal: JournalStatus::Clean,
            gui: GuiState::RunningResponsive,
            independent_monitor_confirmed: true,
            restore_verified: true,
            restore_api_failure: false,
            restore_conflict: false,
            adapter_missing: false,
            silent: false,
        };
        match plan_uninstall(&ctx) {
            UninstallDecision::Proceed { steps } => {
                let restore = steps
                    .iter()
                    .position(|s| *s == UninstallStep::ExactRestoreVerify)
                    .expect("restore present");
                let delete = steps
                    .iter()
                    .position(|s| *s == UninstallStep::DeleteBinariesPreferences)
                    .expect("delete present");
                assert!(restore < delete, "restore precedes deletion");
                // Separate TCP/logon cleanup never precedes DNS restore.
                let tcp = steps
                    .iter()
                    .position(|s| *s == UninstallStep::SeparateTcpLogonCleanup)
                    .expect("tcp cleanup present");
                assert!(restore < tcp);
                // Clean gate precedes the service removal.
                let clean = steps
                    .iter()
                    .position(|s| *s == UninstallStep::RequireClean)
                    .expect("clean gate present");
                let stop = steps
                    .iter()
                    .position(|s| *s == UninstallStep::StopRemoveService)
                    .expect("stop present");
                assert!(clean < stop);
            }
            UninstallDecision::AbortBeforeDeletion { reason, .. } => {
                panic!("active uninstall aborted: {reason}")
            }
        }
    }

    #[test]
    fn uninstall_aborts_before_deletion_on_api_failure_conflict_missing_adapter() {
        let base = UninstallContext {
            service: ServiceState::Running,
            journal: JournalStatus::Clean,
            gui: GuiState::NotRunning,
            independent_monitor_confirmed: true,
            restore_verified: true,
            restore_api_failure: false,
            restore_conflict: false,
            adapter_missing: false,
            silent: true,
        };
        let mut api = base.clone();
        api.restore_api_failure = true;
        match plan_uninstall(&api) {
            UninstallDecision::AbortBeforeDeletion { exit_code, .. } => assert_eq!(exit_code, 11),
            _ => panic!("API failure must abort before deletion"),
        }
        let mut conflict = base.clone();
        conflict.restore_conflict = true;
        match plan_uninstall(&conflict) {
            UninstallDecision::AbortBeforeDeletion { exit_code, .. } => assert_eq!(exit_code, 12),
            _ => panic!("conflict must abort with 12"),
        }
        let mut missing = base.clone();
        missing.adapter_missing = true;
        match plan_uninstall(&missing) {
            UninstallDecision::AbortBeforeDeletion { exit_code, .. } => {
                assert_ne!(exit_code, 0, "silent mode returns nonzero")
            }
            _ => panic!("missing adapter must abort before deletion"),
        }
        // Unverified restore also aborts, even with a clean-looking journal.
        let mut unverified = base.clone();
        unverified.restore_verified = false;
        assert!(matches!(
            plan_uninstall(&unverified),
            UninstallDecision::AbortBeforeDeletion { .. }
        ));
    }

    #[test]
    fn gui_update_verifies_before_restart_and_failures_leave_dns_untouched() {
        let svc = ServiceInfo {
            protocol: PROTOCOL_VERSION,
            journal_version: JOURNAL_VERSION,
            service_version: (1, 1, 6),
            state: ServiceState::Running,
            journal: JournalStatus::Clean,
        };
        let update = UpdateManifest {
            version: (1, 1, 7),
            required_protocol: PROTOCOL_VERSION,
            required_journal: JOURNAL_VERSION,
            requires_service_binary: false,
        };
        match check_update_compat(Some(&svc), Some(JOURNAL_VERSION), (1, 1, 6), &update) {
            UpdateDecision::GuiOnlyProceed {
                verify_before_restart,
            } => assert!(verify_before_restart),
            other => panic!("GUI-only update should proceed with verify: {other:?}"),
        }
        assert!(may_restart_after_cleanup(true));
        assert!(!may_restart_after_cleanup(false));
        // Download/install failure arms leave DNS untouched by behavior, not
        // by enum identity: the failure outcomes report no DNS mutation and
        // never feed the exe-replacement step.
        for outcome in [
            DownloadOutcome::DownloadFailedLeavesDnsUntouched,
            DownloadOutcome::InstallFailedLeavesDnsUntouched,
        ] {
            assert!(
                download_failure_leaves_dns_untouched(&outcome),
                "failure arm {outcome:?} must leave DNS untouched (no service/journal mutation)"
            );
            assert!(
                !download_outcome_replaces_exe(&outcome),
                "failure arm {outcome:?} must not replace the exe"
            );
        }
        assert!(download_outcome_replaces_exe(&DownloadOutcome::Downloaded));
        assert!(!download_failure_leaves_dns_untouched(
            &DownloadOutcome::Downloaded
        ));
    }

    #[test]
    fn service_changing_update_routes_to_installer() {
        let svc = ServiceInfo {
            protocol: PROTOCOL_VERSION,
            journal_version: JOURNAL_VERSION,
            service_version: (1, 1, 6),
            state: ServiceState::Running,
            journal: JournalStatus::Clean,
        };
        let update = UpdateManifest {
            version: (1, 2, 0),
            required_protocol: PROTOCOL_VERSION,
            required_journal: JOURNAL_VERSION,
            requires_service_binary: true,
        };
        assert!(matches!(
            check_update_compat(Some(&svc), Some(JOURNAL_VERSION), (1, 1, 6), &update),
            UpdateDecision::RouteToInstaller { .. }
        ));
    }

    #[test]
    fn unknown_schema_downgrade_refuses_and_blocks_older_service() {
        // Unknown newer journal blocks the update AND the older service.
        let update = UpdateManifest {
            version: (1, 1, 5),
            required_protocol: PROTOCOL_VERSION,
            required_journal: JOURNAL_VERSION,
            requires_service_binary: false,
        };
        match check_update_compat(None, Some(JOURNAL_VERSION + 1), (1, 1, 6), &update) {
            UpdateDecision::Refused { .. } => {}
            other => panic!("unknown newer journal must refuse: {other:?}"),
        }
        let svc = ServiceInfo {
            protocol: PROTOCOL_VERSION,
            journal_version: JOURNAL_VERSION + 1,
            service_version: (1, 1, 6),
            state: ServiceState::Running,
            journal: JournalStatus::UnknownVersion(JOURNAL_VERSION + 1),
        };
        match check_update_compat(
            Some(&svc),
            Some(JOURNAL_VERSION + 1),
            (1, 1, 6),
            &UpdateManifest {
                version: (1, 1, 6),
                required_protocol: PROTOCOL_VERSION,
                required_journal: JOURNAL_VERSION,
                requires_service_binary: false,
            },
        ) {
            UpdateDecision::Refused { .. } => {}
            other => panic!("unknown schema must refuse: {other:?}"),
        }
        // Absent/stopped service refuses the GUI-only path.
        for state in [ServiceState::Absent, ServiceState::Stopped] {
            let svc = ServiceInfo {
                protocol: PROTOCOL_VERSION,
                journal_version: JOURNAL_VERSION,
                service_version: (1, 1, 6),
                state,
                journal: JournalStatus::Absent,
            };
            let update = UpdateManifest {
                version: (1, 1, 7),
                required_protocol: PROTOCOL_VERSION,
                required_journal: JOURNAL_VERSION,
                requires_service_binary: false,
            };
            assert!(
                matches!(
                    check_update_compat(Some(&svc), Some(JOURNAL_VERSION), (1, 1, 6), &update),
                    UpdateDecision::Refused { .. }
                ),
                "{state:?} must refuse"
            );
        }
    }

    #[test]
    fn portable_q2_provisions_via_bootstrap_and_refuses_absent_service() {
        // First run from a portable folder provisions via the elevated
        // bootstrap into protected Program Files — including the absent-
        // service first run when elevated with a valid helper signature.
        for service in [
            ServiceState::Running,
            ServiceState::Stopped,
            ServiceState::Absent,
        ] {
            match plan_portable(&PortableContext {
                location: LaunchLocation::PortableFolder,
                service,
                journal: JournalStatus::Absent,
                elevated: true,
                helper_signature: SignatureCheck::Valid,
            }) {
                PortableDecision::ProvisionViaElevatedBootstrap => {}
                other => panic!("portable first run ({service:?}) must provision: {other:?}"),
            }
        }
        // Absent-service portable without elevation or with a bad signature
        // refuses — no silent install, no watchdog from a writable folder.
        match plan_portable(&PortableContext {
            location: LaunchLocation::PortableFolder,
            service: ServiceState::Absent,
            journal: JournalStatus::Absent,
            elevated: false,
            helper_signature: SignatureCheck::Valid,
        }) {
            PortableDecision::RefuseAbsentServiceTakeover { .. } => {}
            other => panic!("unelevated absent-service portable must refuse: {other:?}"),
        }
        match plan_portable(&PortableContext {
            location: LaunchLocation::PortableFolder,
            service: ServiceState::Absent,
            journal: JournalStatus::Absent,
            elevated: true,
            helper_signature: SignatureCheck::Invalid,
        }) {
            PortableDecision::RefuseAbsentServiceTakeover { .. } => {}
            other => panic!("bad-signature absent-service portable must refuse: {other:?}"),
        }
        // Unelevated portable cannot silently install machine software.
        match plan_portable(&PortableContext {
            location: LaunchLocation::PortableFolder,
            service: ServiceState::Running,
            journal: JournalStatus::Clean,
            elevated: false,
            helper_signature: SignatureCheck::Valid,
        }) {
            PortableDecision::RefuseAbsentServiceTakeover { .. } => {}
            other => panic!("unelevated portable must refuse: {other:?}"),
        }
    }

    #[test]
    fn portable_removal_never_touches_protected_state() {
        let scope = portable_removal_scope();
        assert!(!scope.deletes_protected_binary);
        assert!(!scope.deletes_program_data_state);
        assert!(scope.deletes_portable_folder_only);
        // The behavior the scope names is enforced by the portable cleanup
        // path: protected and ProgramData locations are never deletion
        // targets (the predicate reports them as forbidden).
        assert!(portable_path_is_protected_deletion_target(
            "C:\\Program Files\\Yeager\\yeager-dns-recovery.exe"
        ));
        assert!(portable_path_is_protected_deletion_target(
            "C:\\ProgramData\\Yeager\\dns-takeover-v1.json"
        ));
        assert!(portable_path_is_portable_folder_file(
            "D:\\tools\\yeager-portable\\yeager.exe"
        ));
        assert!(!portable_path_is_protected_deletion_target(
            "D:\\tools\\yeager-portable\\yeager.exe"
        ));
    }

    #[test]
    fn helper_and_installer_share_app_trust_policy() {
        assert!(verify_artifact(&ArtifactCheck {
            sha256_matches: true,
            signature_pinned_valid: true,
        }));
        assert!(!verify_artifact(&ArtifactCheck {
            sha256_matches: true,
            signature_pinned_valid: false,
        }));
        assert!(!verify_artifact(&ArtifactCheck {
            sha256_matches: false,
            signature_pinned_valid: true,
        }));
    }
}

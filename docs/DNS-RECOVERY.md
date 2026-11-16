# DNS recovery, conflicts, legacy limits, provisioning and uninstall

**English** · The Vietnamese operator summary lives in `docs/DESIGN.vi.md`
where the DNS design is concerned; this file is the U09 operator reference
for the recovery service, the installer/portable provisioning and the
uninstall behavior.

How Yeager takes over Windows DNS and puts it back exactly is specified in
`C:\projects\yeager-dns-pkg\SPEC-DNS-FIX.md` (sections 2–8) and ruled by the
U09 envelope (`ENVELOPE-U09.md`). This file is the operator-facing summary:
what the service guarantees, what conflicts and legacy leftovers mean, how
both distributions provision the service, how uninstall works, and how
service-changing updates migrate.

## What the service guarantees

- One machine transaction and one DNS writer. The privileged service
  (`YeagerDnsRecovery`, `yeager-dns-recovery.exe`) is the sole normal DNS
  writer; the GUI supplies allowlisted provider/listener plans and never a
  rollback snapshot. Identity is adapter GUID × address family, never display
  name or interface index.
- Every mutation has a durable exact original baseline plus a durable
  before/target intent BEFORE the OS call. Success is only reported after the
  configured mode, ordered server list and properties are read back and
  compared — API success alone is not proof.
- The journal (`%ProgramData%\Yeager\dns-takeover-v1.json`, ACL
  `O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, same-directory stage/backup
  candidates, full durability barrier) survives crashes, kills and power
  loss. Replay on next boot/start restores the exact original or retains the
  debt — never a heuristic clear.
- Shutdown admission closes before draining: no enable/reconfigure commits
  after the restore barrier. Restore/verify precedes healthy listener stop;
  hard GUI death is covered by the service's held process-handle watchdog
  (restoration starts within ~1 s under normal scheduling).
- Unresolved debt, an unavailable service, an unsupported snapshot, an
  unknown schema, or unsafe storage blocks new takeover — including the
  Windows-only mode, which still changes system DNS.

## Provisioning (Q2 ruled)

Q2 is RULED (Cino, 2026-11-13): BOTH distributions carry the signed
recovery helper.

| Distribution | How the service is provisioned (shipped behavior) |
|---|---|
| Installer (`Yeager-Setup-<version>.exe`) | Provisions through the `--install-service` seam after the copy: verifies the NEW helper under the full `verify.ps1` rule (pinned thumbprint derived at build time from `docs/signing/Yeager-codesign.cer` via `Get-PinnedThumbprint` + RFC 3161 timestamp validity + SHA-256 where supplied — never a thumbprint string compare alone), handles clean install AND upgrade replace. The clean-install seam distinguishes ABSENT (1060, proceed to create; when the running image already IS the target file it adopts in place with no copy) from STOPPED (wait applies only when a record exists). Quoted SCM path, protected binary-dir ACL, 1 s / 5 s / 30 s + non-crash flag + preshutdown, start, Hello, `--inspect` of the NEW binary; on start/Hello failure restores the exe AND the CAPTURED registration (ImagePath, start type, failure actions/flag, preshutdown — written back through the seam's Win32 snapshot, never the canonical values; the service is restarted only when the captured state was running). Pre-copy: backup (seam `--query-service-config` JSON snapshot plus ImagePath/failure sc.exe text as log evidence), `--inspect` CLEAN gate (helper-exists-even-without-service included), `--enter-maintenance "installer-upgrade"` with THAT reason (or `--recover-offline` when STOPPED with proven STOPPED; any other SCM state aborts), graceful GUI exit, `sc stop` + STOPPED poll. The restore wait polls `--inspect` to EXIT_CLEAN or the real 30 s timeout — an unfinished restore holds the installer. |
| Portable (`Yeager-<version>-portable-x64.zip`) | Carries the signed helper inside the zip. `main` runs the Q2 bootstrap on portable first run: service absent + elevated + helper present → computes the helper signature verdict for real (pinned thumbprint + timestamp, the release verify rule — never a hardcoded `Valid`) → `plan_portable` allows `ProvisionViaElevatedBootstrap` → spawns the carried helper's `--install-service` (copies into protected Program Files, ACLs, registers, Hello-validates). Unelevated or bad-signature refuses; no silent install, no watchdog from a writable folder. Stale portable files are removed only through the guarded path (`portable_delete_guarded` refuses protected targets). |

Rules that always hold (enforced by the shipped code, not only the planner):

- Moving or deleting the portable GUI can never remove the protected
  recovery executable (`%ProgramFiles%\Yeager\yeager-dns-recovery.exe`) or
  the ProgramData state. `portable_removal_scope` names the invariant and
  `portable_path_is_protected_deletion_target` + `portable_delete_guarded`
  enforce it in the actual cleanup path (`portable_cleanup_stale` calls the
  predicate; protected targets are refused without touching the filesystem).
- Absent-service portable takeover refuses: `portable_takeover_allowed`
  requires proven Running + Clean from the live pipe probe. Pending,
  conflict and busy pipe outcomes are not healthy; a path-string match is
  not a service check. Both distributions require the same proof. The
  portable bootstrap computes the carried helper's signature verdict for
  real before the planner sees it.
- The installer never force-kills the GUI blindly: already-gone GUI returns
  immediately (tasklist output, not exit 0), graceful first, up to 30 s
   wait, monitored force kill only with proven RUNNING service (not `sc
   query` exit 0), force-kill exit checked, restore polled via `--inspect`
   to EXIT_CLEAN or the real 30 s timeout — an unfinished restore holds the
   installer (the wait returns failure and the install/uninstall aborts).

## Conflicts and recovery debt

- A detectable foreign administrator/policy edit is preserved: the service
  restores independently owned sibling families, retains the conflicted
  baseline and debt, and reports `conflict`. There is no automatic
  discard-original path and no timeout that ages debt out.
- The conflict UI shows original/current/intended per adapter family and
  offers an explicit elevated restore-original after recapture/reconfirmation
  (a new approved intent). Uninstall stays blocked until verified recovery.
- Missing/unavailable adapters defer: their originals are retained and
  retried on arrival (plus the 60 s inventory poll). Arrival of a new GUID
  never inherits old settings, even when it reuses a name or index.
- Unknown journal versions and integrity failures block takeover without
  deleting or overwriting state. An unknown newer journal blocks an older
  service — including across updates and downgrades.

## Legacy pre-journal leftovers

Already-lost pre-Yeager static DNS/DoH settings are **unrecoverable** from
present configuration. A legacy repair can never truthfully claim exact
original restoration.

- Detection is conservative and family-scoped: an exact first loopback
  (`127.0.0.1`/`::1`) followed by the corresponding first Cloudflare/Google/
  AdGuard fallback, with matching explicit DoH template/flags, and only with
  supporting process/listener evidence. Public addresses alone are never
  ownership; loopback-only and provider-only Windows-DoH modes are ambiguous
  diagnostic cases, not automatic repairs.
- Until the Q3 ruling, detection/reporting only: no automatic repair runs
  without explicit elevated approval, and an approved repair warns that
  historical static settings cannot be reconstructed (it restores automatic
  mode as an explicitly tagged `legacy_repair`, never mislabeled as an
  original restoration).

## Install, upgrade and uninstall behavior

Install/upgrade (`installer/setup.iss` `[Code]` calls the helper seams;
the planner `dns_recovery::provision::plan_install` is the fake-backed
policy the `[Code]` mirrors step-for-step):

1. Before any copy: back up the previous helper executable + the COMPLETE
   CAPTURED SCM registration via the seam's Win32 snapshot
   (`--query-service-config` JSON: ImagePath, start type, failure
   reset/actions, non-crash flag, preshutdown; the sc.exe text is log
   evidence only); run `--inspect` whenever the helper file exists
   (including the helper-exists-but-service-absent path) and abort on any
   non-clean exit — Maintenance (live exit 11 pending) blocks like any other
   debt, preserving the old helper and the journal. A failed capture fails
   closed before any change.
2. On upgrade paths: `--enter-maintenance "installer-upgrade"` when RUNNING
   (the seam records THAT reason; rejecting new takeover) or
   `--recover-offline` when STOPPED (proven STOPPED only — Absent maps to
   Unknown and is refused; any other SCM state aborts; Absent on the install
   path is created by the install seam, never offline-recovered); then
   graceful GUI exit (already-gone GUI returns immediately, no 30 s wait),
   `sc stop` with abort on failure and a STOPPED poll before proceeding.
3. Inno copies the new binaries (no raise on a missing helper at `ssInstall`
   — the old raise aborted every clean install before registration).
4. After the copy (`ssPostInstall`): verify the NEW helper under the full
   `verify.ps1` rule (pinned thumbprint derived at build time + timestamp +
   SHA-256 where supplied), then register through the `--install-service`
   seam — which handles clean install (ABSENT creates; installer-flow adopt
   in place when the running image IS the target file) AND upgrade replace
   (quoted SCM path, protected binary-dir ACL, 1 s / 5 s / 30 s restarts,
   non-crash failure flag, preshutdown, start, Hello). `--leave-maintenance`
   when entered (empty-marker clears back to absent with no manual
   `sc delete` + `rmdir`) comes BEFORE the clean gate — the marker still
   holds by design right after replacement, so requiring clean first would
   fail every upgrade that entered maintenance. Then validate `--inspect`
   of the NEW binary in place (must prove clean); on start/Hello/leave/
   inspect failure restore both the executable and the CAPTURED registration
   through the seam (`--restore-service-registration`: ImagePath, start type,
   failure actions/flag, preshutdown — never the canonical values) and restart
   the previous service only when the captured state was running. The journal
   survives every branch.
5. The postinstall GUI launches only when `ServiceReadyCheck` proves RUNNING
   + `--inspect` clean. A failed service installation/start fails the
   install — no takeover race. Raise texts name only what was restored
   (upgrade: previous binary + captured registration; clean: no previous state,
   fresh registration removed). No cleanup error is hidden through installer flags.

Uninstall (clean-only; `[Code]` drives result-checked seams):

1. `--enter-maintenance "installer-uninstall"` first when RUNNING (the seam
   records THAT reason) → graceful GUI shutdown (proven-RUNNING monitor
   required for any force kill; force-kill exit checked; restore polled via
   `--inspect` to EXIT_CLEAN, not a fixed 2 s sleep) → exact
   restore/verify (`--cleanup` when the GUI exists, else `--cleanup`
   through the helper — which replays the journal to an exact-original
   restore, never skipped when `yeager.exe` is absent) → `--leave-maintenance`
   for the marker this uninstall entered (empty clears to absent, no wedge
   for future installs; a pre-existing payload leaves RecoveryPending and
   still refuses below) → separate TCP/logon cleanup → `--remove-service`
   (refuses debt) → delete binaries/preferences.
2. Pending recovery aborts BEFORE deletion, retaining the service, the
   binaries and the ProgramData state. Silent mode (`/SILENT`/`/VERYSILENT`)
   exits the uninstaller process NONZERO before any deletion (Inno's
   two-phase uninstall protocol maps every second-phase abort to the first
   phase's generic failure code 1 — no message box can hang automation).
   The §8.3 code for the aborting arm (11 pending/unavailable, 12 conflict,
   13 service/auth, 14 integrity/unknown version) is the planner's contract
   (`plan_uninstall`, unit-tested), the helper seam's measured exit, and the
   uninstall log line. A helper-missing path with an SCM entry still aborts
   (unverifiable cleanup) instead of running `sc stop`/`sc delete` with
   ignored exits and deleting.
3. No unconditional taskkill/`--cleanup` chain with ignored failures;
   `ProgramData\Yeager` is never deleted by the uninstaller.

## Updates and migration

- The single-exe in-app updater (`crates/app/src/updater.rs` +
  `LiveServiceProbe` in `crates/app/src/main.rs`) checks service capability
  and compatibility BEFORE installing a replacement. The probe reads the
  service's actual protocol/journal/binary versions from the pipe Hello
  reply (never this binary's constants); an unreachable service reads as
  absent. The target release's requirements come from its published
  `manifest.json` sidecar (fail-closed to the installer when unavailable) —
  never a hardcoded `false` or this binary's own protocol/journal. A
  compatible GUI-only update restores/verifies BEFORE the exe replacement
  (`verify_restore`: only Running + Clean proceeds) and again before the
  restart; a failed cleanup cancels the restart and download/install
  failures leave the current active DNS untouched (no service/journal/exe
  mutation on the failure path).
- A service-changing update (new service binary, protocol or journal schema
  per the release manifest) routes to the signed installer and its
  maintenance sequence before any replacement — the single-exe updater never
  leaves an incompatible service or schema behind.
- Protocol/schema compatibility is checked before updates AND downgrades;
  an unknown newer journal blocks the older service. The helper and the
  installer are verified under the same hash + pinned-signature trust policy
  as the app binaries (`SHA256SUMS.txt` plus `verify.ps1`; the installer
  `[Code]` pins the same thumbprint after the copy).

**Migration note (existing users):** if your installed Yeager predates the
recovery service, the next update is service-changing: use the signed
installer (`Yeager-Setup-<version>.exe`) rather than the in-app single-exe
update. The installer closes the legacy GUI gracefully, provisions the
service, and validates Hello/inspection before finishing. The in-app updater
will refuse a service-changing replacement and direct you to the installer.

## Evidence and limits

- U09 evidence is fake-backed first (installer logic seams, updater state
  machine, provisioning planner, schema checks in
  `dns-recovery/src/provision.rs` and `crates/app/src/updater.rs`), plus one
  controlled real cycle of the product's OWN service on garen-pc (install →
  Hello/inspection → maintenance enter/leave → upgrade-replace → clean
  uninstall) WITHOUT ever applying DNS takeover to the machine's real NICs.
  The cycle log lives in `C:\projects\yeager-dns-pkg\` (see `U09-EVIDENCE.md`).
- Anything needing real NIC mutation, destructive faults or power-loss
  simulation is U10's disposable-VM gate, not this unit.

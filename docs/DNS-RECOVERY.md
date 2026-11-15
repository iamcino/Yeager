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
| Installer (`Yeager-Setup-<version>.exe`) | Provisions through the `--install-service` seam after the copy: verifies the NEW helper's pinned signature, handles clean install AND upgrade replace (quoted SCM path, protected binary-dir ACL, 1 s / 5 s / 30 s + non-crash flag + preshutdown, start, Hello), validates `--inspect` of the NEW binary, rolls back exe + registration on failure. Pre-copy: backup, `--inspect` CLEAN gate (helper-exists-even-without-service included), `--enter-maintenance`/`--recover-offline` with proven STOPPED, graceful GUI exit, `sc stop` + STOPPED poll. |
| Portable (`Yeager-<version>-portable-x64.zip`) | Carries the signed helper inside the zip. `main` runs the Q2 bootstrap on portable first run: service absent + elevated + helper present → `plan_portable` allows `ProvisionViaElevatedBootstrap` → spawns the carried helper's `--install-service` (copies into protected Program Files, ACLs, registers, Hello-validates). Unelevated or bad-signature refuses; no silent install, no watchdog from a writable folder. |

Rules that always hold (enforced by the shipped code, not only the planner):

- Moving or deleting the portable GUI can never remove the protected
  recovery executable (`%ProgramFiles%\Yeager\yeager-dns-recovery.exe`) or
  the ProgramData state. `portable_removal_scope` names the invariant and
  `portable_path_is_protected_deletion_target` enforces it in the cleanup
  path: protected and ProgramData locations are never deletion targets.
- Absent-service portable takeover refuses: `portable_takeover_allowed`
  requires proven Running + Clean from the live pipe probe. Pending,
  conflict and busy pipe outcomes are not healthy; a path-string match is
  not a service check. Both distributions require the same proof.
- The installer never force-kills the GUI blindly: already-gone GUI returns
  immediately (tasklist output, not exit 0), graceful first, up to 30 s
  wait, monitored force kill only with proven RUNNING service (not `sc
  query` exit 0), force-kill exit checked, restore polled via `--inspect`.

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

1. Before any copy: back up the previous helper executable + SCM registration;
   run `--inspect` whenever the helper file exists (including the
   helper-exists-but-service-absent path) and abort on any non-clean exit —
   Maintenance (live exit 11 pending) blocks like any other debt, preserving
   the old helper and the journal.
2. On upgrade paths: `--enter-maintenance` when RUNNING (rejecting new
   takeover) or `--recover-offline` when STOPPED (proven STOPPED; any other
   SCM state aborts); then graceful GUI exit (already-gone GUI returns
   immediately, no 30 s wait), `sc stop` with abort on failure and a
   STOPPED poll before proceeding.
3. Inno copies the new binaries (no raise on a missing helper at `ssInstall`
   — the old raise aborted every clean install before registration).
4. After the copy (`ssPostInstall`): verify the NEW helper's Authenticode
   thumbprint against the pinned certificate, then register through the
   `--install-service` seam — which handles clean install AND upgrade replace
   (quoted SCM path, protected binary-dir ACL, 1 s / 5 s / 30 s restarts,
   non-crash failure flag, preshutdown, start, Hello). Validate Hello +
   `--inspect` of the NEW binary in place; on start/Hello failure restore
   both the executable and the registration and restart the previous
   service. The journal survives every branch.
5. `--leave-maintenance` when entered (empty-marker clears back to absent
   with no manual `sc delete` + `rmdir`); the postinstall GUI launches only
   when `ServiceReadyCheck` proves RUNNING + `--inspect` clean. A failed
   service installation/start fails the install — no takeover race. No
   cleanup error is hidden through installer flags.

Uninstall (clean-only; `[Code]` drives result-checked seams):

1. `--enter-maintenance` first when RUNNING → graceful GUI shutdown
   (proven-RUNNING monitor required for any force kill; force-kill exit
   checked; restore polled via `--inspect`, not a fixed 2 s sleep) →
   exact restore/verify (`--cleanup` when the GUI exists, else
   `--inspect` through the helper — never skipped when `yeager.exe` is
   absent) → separate TCP/logon cleanup → `--remove-service` (refuses debt)
   → delete binaries/preferences.
2. Pending recovery aborts BEFORE deletion, retaining the service, the
   binaries and the ProgramData state. Silent mode (`/SILENT`/`/VERYSILENT`)
   returns the measured §8.3 nonzero exit (11 pending/unavailable, 12
   conflict, 14 integrity/unknown version). A helper-missing path with an
   SCM entry still aborts (unverifiable cleanup) instead of running
   `sc stop`/`sc delete` with ignored exits and deleting.
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

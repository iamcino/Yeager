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

| Distribution | How the service is provisioned |
|---|---|
| Installer (`Yeager-Setup-<version>.exe`) | Provisions the service directly: stages/verifies the signed helper in the protected path, enters service maintenance (or offline-recovers with proven STOPPED), requires CLEAN before replacing the binary, configures the quoted SCM path/ACL/restart actions, starts and validates Hello/inspection. |
| Portable (`Yeager-<version>-portable-x64.zip`) | Carries the signed helper inside the zip. First run provisions/maintains the persistent service in protected Program Files via the elevated bootstrap. |

Rules that always hold:

- Moving or deleting the portable GUI can never remove the protected
  recovery executable (`%ProgramFiles%\Yeager\yeager-dns-recovery.exe`) or
  the ProgramData state. Portable cleanup deletes only the portable folder's
  own files (`dns_recovery::provision::portable_removal_scope`).
- Absent-service portable takeover refuses: with no installed recovery
  service the portable GUI stays diagnostic-only. No silent persistent
  software is installed from a portable run except through the elevated
  bootstrap, and no watchdog runs from a writable folder.
- The installer never force-kills the GUI blindly: graceful shutdown first,
  up to 30 s wait, and a monitored force kill only with a confirmed
  independent monitor (the service watchdog), followed by waiting for the
  restore.

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

Install/upgrade (`installer/setup.iss` `[Code]`, mirroring
`dns_recovery::provision::plan_install`):

1. Stage/verify the signed helper in the protected path.
2. First service introduction closes the legacy GUI gracefully (Q3 legacy
   policy: detection/reporting only).
3. Enter service maintenance (or offline-recover with proven STOPPED),
   reject new takeover, notify the GUI, request coordinator exit, wait up to
   30 s. Force kill only with a confirmed independent monitor, then wait for
   the restore.
4. Require CLEAN before replacing/removing the service binary. Pending
   adapters, conflicts and API failures abort the preflight and preserve the
   old helper and the journal. No cleanup error is hidden through installer
   flags.
5. Stop the service only after the clean/maintenance acknowledgement,
   replace the protected binaries, configure the quoted SCM path, ACL and
   restart actions (1 s / 5 s / 30 s plus preshutdown), start and validate
   Hello/inspection. Failure rolls back the executable and the registration
   and restarts the previous compatible service. The journal survives every
   branch.
6. Leave maintenance; the postinstall GUI launches only after ready. A
   failed service installation/start fails the install — no takeover race.

Uninstall (clean-only, mirroring `plan_uninstall`):

1. Maintenance → graceful GUI shutdown → optional monitored force kill →
   exact restore/verify → separate TCP/logon cleanup → require clean →
   stop/remove service → delete binaries/preferences.
2. Pending recovery aborts BEFORE deletion, retaining the service, the
   binaries and the ProgramData state. Silent mode returns the §8.3 nonzero
   exit (11 pending/unavailable, 12 conflict, 14 integrity/unknown version).
3. No unconditional taskkill/`--cleanup` chain with ignored failures;
   `ProgramData\Yeager` is never deleted by the uninstaller.

## Updates and migration

- The single-exe in-app updater checks service capability and compatibility
  BEFORE installing a replacement (`crates/app/src/updater.rs` gate). A
  compatible GUI-only update may retain the service but must restore/verify
  before replacement/restart; a failed cleanup cancels the restart and the
  current active DNS is untouched by download/install failures.
- A service-changing update (new service binary, protocol or journal schema)
  routes to the signed installer and its maintenance sequence — the
  single-exe updater never leaves an incompatible service or schema behind.
- Protocol/schema compatibility is checked before updates AND downgrades;
  an unknown newer journal blocks the older service. The helper and the
  installer are verified under the same hash + pinned-signature trust policy
  as the app binaries (`SHA256SUMS.txt` plus `verify.ps1`).

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

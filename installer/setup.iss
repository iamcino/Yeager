; Yeager — Windows installer (Inno Setup 6)
;
; Build: run build.ps1 first (it puts yeager.exe AND yeager-dns-recovery.exe
; in dist\), then
;   iscc /DAppVersion=1.1.2 installer\setup.iss
; The release workflow does both and passes the version from the git tag.
;
; U09 (SPEC-DNS-FIX.md §10): the installer carries the privileged DNS
; recovery service. Both distributions carry the service — the installer
; provisions it directly; the portable provisions it via its elevated
; bootstrap (see docs/DNS-RECOVERY.md). The [Code] preflight below mirrors
; dns_recovery::provision::plan_install / plan_uninstall (fake-backed in
; Rust): stage/verify the signed helper, enter maintenance (or offline
; recover with proven STOPPED), require CLEAN before replacing the service
; binary, start and validate Hello/inspection, roll back on failure. The
; journal survives every branch. Uninstall is clean-only and aborts BEFORE
; deletion on pending recovery, retaining the service, binaries and
; ProgramData state. ProgramData\Yeager is NEVER deleted here.

#define AppName "Yeager"
#ifndef AppVersion
  #define AppVersion "1.1.6"
#endif
#ifndef NumericVersion
  #define NumericVersion "0.0.0.0"
#endif
#define AppPublisher "Cino"
#define AppURL "https://github.com/iamcino/Yeager"
#define AppExeName "yeager.exe"
#define HelperExeName "yeager-dns-recovery.exe"
#define ServiceName "YeagerDnsRecovery"

[Setup]
AppId={{B7E8C3A1-4F2D-4E8A-9C1B-3D5F7A8E2B4C}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
VersionInfoVersion={#NumericVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=Yeager-Setup-{#AppVersion}
SetupIconFile=..\assets\icons\yeager.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Yeager changes system TCP and DNS settings, so it runs elevated anyway.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows DNS over HTTPS (DNS_INTERFACE_SETTINGS3) exists only on Windows 11 / Server 2022.
MinVersion=10.0.20348
; The service/host sequence below closes the GUI itself; Inno must not kill it.
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
OnlyOnNewerWindows=Yeager requires Windows 11 or Windows Server 2022+ (build 20348 or newer).%n%nDetected Windows build does not meet the minimum requirement.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; U09: the protected recovery service binary. The release pipeline signs it
; and records its hash (yeager-dns-recovery-signature.json); the [Code]
; preflight verifies it before any service registration is touched.
Source: "..\dist\{#HelperExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Postinstall GUI launch only after the service is ready (Check below runs
; Hello/inspection through the helper; the entry is skipped otherwise — a
; failed service installation/start fails the install, no takeover race).
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent shellexec; Check: ServiceReadyCheck

; No [UninstallRun] taskkill/--cleanup chain: uninstall is driven by [Code]
; (CurUninstallStepChanged) with result-checked steps. Unconditional chains
; with ignored failures are forbidden — a failed exact restore aborts BEFORE
; deletion and silent mode returns nonzero.

[UninstallDelete]
; Left next to the exe for a moment after an in-app update.
Type: files; Name: "{app}\yeager.old.exe"
Type: files; Name: "{app}\yeager.new.exe"
Type: filesandordirs; Name: "{localappdata}\Yeager"
; NOTE: ProgramData\Yeager (the DNS journal) is NEVER deleted here. The
; uninstall aborts before deletion while recovery debt remains, retaining the
; service, the binaries and the ProgramData state.

[Code]
{ U09-REV installer/uninstall sequence (§10). Mirrors
  dns_recovery::provision::plan_install / plan_uninstall: every step is
  result-checked and aborts preserve the old helper and the journal.
  Section 10 order: stage/verify → maintenance enter (or offline recover
  with proven STOPPED) → reject new takeover → GUI exit → CLEAN gate →
  stop → replace → quoted SCM path/ACL/restart actions (incl. non-crash
  flag + preshutdown, matching install_service) → start → Hello +
  --inspect of the NEW binary → leave maintenance → GUI only after ready.
  Rollback restores both the executable and the registration. }

const
  { SCM / helper exit codes (SPEC §8.3): 0 verified clean/success; 11
    pending/unavailable; 12 conflict; 13 privilege/service/auth; 14
    integrity/unknown version; 15 unsupported. }
  EXIT_CLEAN = 0;
  EXIT_PENDING = 11;
  EXIT_CONFLICT = 12;
  EXIT_INTEGRITY = 14;
  GUI_EXIT_WAIT_MS = 30000;
  PINNED_THUMBPRINT = '9131F99C0B198E81FBA0F5818D0637B4A14DCF1';

var
  ServiceWasRunning: Boolean;
  PreflightAborted: Boolean;
  PreflightAbortReason: String;
  UpgradeInstall: Boolean;
  InstallFailed: Boolean;
  EnteredMaintenance: Boolean;
  BackupExePath: String;
  BackupBinPath: String;

function HelperPath(): String;
begin
  Result := ExpandConstant('{app}\{#HelperExeName}');
end;

function GuiPath(): String;
begin
  Result := ExpandConstant('{app}\{#AppExeName}');
end;

function RunAndGetCode(const Exe, Params: String; var Code: Integer): Boolean;
begin
  Result := Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

{ Actual SCM state by parsing `sc query` output (not just its exit code):
  'running' / 'stopped' / 'start_pending' / 'stop_pending' / 'absent' /
  'unknown'. The offline-recover path requires proven STOPPED; the
  independent monitor requires proven RUNNING — `sc query` exit 0 alone
  (which includes a stopped service) is never a confirmation. }
function ScQueryStateFull(): String;
var
  Code: Integer;
  Tmp: String;
  Content: AnsiString;
begin
  Result := 'unknown';
  Tmp := ExpandConstant('{tmp}\yeager_scquery.txt');
  if not Exec(ExpandConstant('{cmd}'), '/c sc query {#ServiceName} > "' + Tmp + '" 2>&1',
    '', SW_HIDE, ewWaitUntilTerminated, Code) then
    exit;
  if not LoadStringFromFile(Tmp, Content) then
    exit;
  DeleteFile(Tmp);
  if Pos('1060', Content) > 0 then
  begin
    Result := 'absent';
    exit;
  end;
  if Pos('RUNNING', Uppercase(Content)) > 0 then
    Result := 'running'
  else if Pos('STOPPED', Uppercase(Content)) > 0 then
    Result := 'stopped'
  else if Pos('START_PENDING', Uppercase(Content)) > 0 then
    Result := 'start_pending'
  else if Pos('STOP_PENDING', Uppercase(Content)) > 0 then
    Result := 'stop_pending'
  else if Pos('STATE', Uppercase(Content)) > 0 then
    Result := 'unknown'
  else
    Result := 'absent';
end;

function IsServiceInstalled(): Boolean;
begin
  Result := ScQueryStateFull() <> 'absent';
end;

function IsServiceRunning(): Boolean;
begin
  { Real independent-monitor confirmation: proven RUNNING, not `sc query`
    exit 0 (which includes a stopped service). }
  Result := ScQueryStateFull() = 'running';
end;

{ True when yeager.exe is actually running: tasklist exit 0 means both
  "running" and "INFO: No tasks are running", so the output file is checked
  for the image name instead of trusting the exit code. }
function GuiProcessRunning(): Boolean;
var
  Code: Integer;
  Tmp: String;
  Content: AnsiString;
begin
  Result := False;
  Tmp := ExpandConstant('{tmp}\yeager_tasklist.txt');
  if not Exec(ExpandConstant('{cmd}'),
    '/c tasklist /FI "IMAGENAME eq {#AppExeName}" /FO CSV /NH > "' + Tmp + '" 2>&1',
    '', SW_HIDE, ewWaitUntilTerminated, Code) then
    exit;
  if not LoadStringFromFile(Tmp, Content) then
    exit;
  DeleteFile(Tmp);
  Result := Pos(Uppercase('{#AppExeName}'), Uppercase(Content)) > 0;
end;

{ Graceful GUI shutdown: ask the coordinator to exit (WM_CLOSE via taskkill
  WITHOUT /F), wait up to 30 s, then — only with a confirmed independent
  monitor (proven RUNNING service) — force-kill once (checking its exit
  code) and wait for the restore to finish (polling --inspect, not a fixed
  2 s sleep). Returns True when no GUI process remains. A legacy GUI-only
  tree (exe present, service absent) with an already-gone GUI returns True
  immediately instead of aborting after 30 s. }
function CloseGuiGracefully(): Boolean;
var
  Code: Integer;
  Waited: Integer;
  KillCode: Integer;
  InspectCode: Integer;
  InspectOk: Boolean;
  Polls: Integer;
begin
  Result := True;
  { No GUI installed yet (clean install): nothing to close. }
  if not FileExists(GuiPath()) then
    exit;
  { A gone GUI is detected correctly: no 30 s wait for an absent GUI. }
  if not GuiProcessRunning() then
    exit;
  { Graceful close request first — never /F as the primary strategy. }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#AppExeName}', '',
    SW_HIDE, ewWaitUntilTerminated, Code);
  Log('CloseGuiGracefully: taskkill (graceful) exited ' + IntToStr(Code));
  Waited := 0;
  while (Waited < GUI_EXIT_WAIT_MS) and GuiProcessRunning() do
  begin
    Sleep(500);
    Waited := Waited + 500;
  end;
  if not GuiProcessRunning() then
    exit;
  { Still running after 30 s: a monitored force kill happens only with a
    confirmed independent monitor (proven RUNNING service) — otherwise
    abort instead of killing blindly. }
  if not IsServiceRunning() then
  begin
    Log('CloseGuiGracefully: GUI nonresponsive with no independent monitor (proven RUNNING required); refusing force kill');
    Result := False;
    exit;
  end;
  Log('CloseGuiGracefully: GUI nonresponsive, independent monitor (RUNNING service) confirmed; force-killing once');
  if not RunAndGetCode(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExeName}', KillCode) or (KillCode <> 0) then
  begin
    Log('CloseGuiGracefully: force-kill failed (exit ' + IntToStr(KillCode) + '); aborting');
    Result := False;
    exit;
  end;
  { Wait for the restore to finish: poll --inspect until clean instead of a
    fixed 2 s sleep. }
  Polls := 0;
  while Polls < 60 do
  begin
    if FileExists(HelperPath()) then
    begin
      InspectOk := RunAndGetCode(HelperPath(), '--inspect', InspectCode);
      if InspectOk and (InspectCode = EXIT_CLEAN) then
        break;
    end;
    Sleep(500);
    Polls := Polls + 1;
    if not GuiProcessRunning() and (Polls >= 4) then
      break;
  end;
end;

{ Pinned-signature verification of the staged helper (hash + Authenticode
  thumbprint policy, same as verify.ps1): the signer thumbprint must equal
  the pinned certificate. }
function VerifyHelperSignature(const Path: String): Boolean;
var
  Code: Integer;
  Cmd: String;
begin
  Result := False;
  Cmd := '-NoProfile -Command "if ((Get-AuthenticodeSignature ''' + Path +
    ''').SignerCertificate.Thumbprint -eq ''' + PINNED_THUMBPRINT + ''') { exit 0 } else { exit 1 }"';
  if RunAndGetCode(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Cmd, Code) and (Code = 0) then
    Result := True
  else
    Log('VerifyHelperSignature: thumbprint mismatch for ' + Path);
end;

{ Journal preflight through the helper: --inspect reconciles candidates
  without writes and reports pending/conflict/integrity via its exit code.
  Runs whenever the helper file exists — including the helper-exists-but-
  service-absent upgrade path, before any file copy replaces the helper.
  Non-clean states (including Maintenance, a live exit-11 pending) abort the
  preflight and preserve the old helper and the journal. }
function JournalPreflightClean(): Boolean;
var
  Code: Integer;
  Ok: Boolean;
begin
  Result := True;
  if not FileExists(HelperPath()) then
    exit; { clean install: no previous helper to consult }
  Ok := RunAndGetCode(HelperPath(), '--inspect', Code);
  Log('JournalPreflightClean: --inspect exited ' + IntToStr(Code));
  if not Ok then
  begin
    PreflightAborted := True;
    PreflightAbortReason := 'could not run the recovery helper for preflight';
    Result := False;
    exit;
  end;
  if Code = EXIT_CLEAN then
    exit;
  PreflightAborted := True;
  if Code = EXIT_CONFLICT then
    PreflightAbortReason := 'restore conflict; upgrade aborted, old helper and journal preserved'
  else if Code = EXIT_INTEGRITY then
    PreflightAbortReason := 'journal integrity/unknown version; upgrade aborted, evidence retained'
  else
    PreflightAbortReason := 'journal not clean (exit ' + IntToStr(Code) +
      '); upgrade aborted, old helper and journal preserved';
  Result := False;
end;

function WaitForStopped(TimeoutSecs: Integer): Boolean;
var
  i: Integer;
begin
  Result := False;
  for i := 0 to TimeoutSecs - 1 do
  begin
    if ScQueryStateFull() = 'stopped' then
    begin
      Result := True;
      exit;
    end;
    Sleep(1000);
  end;
end;

{ Postinstall launch gate: runs Hello/--inspect on the NEW binary after it
  is in place. A path that never started the service (preflight aborted,
  install failed, or service not RUNNING) never launches the GUI. }
function ServiceReadyCheck(): Boolean;
var
  Code: Integer;
  Ok: Boolean;
begin
  Result := False;
  if PreflightAborted or InstallFailed then
    exit;
  if not FileExists(HelperPath()) then
    exit;
  if ScQueryStateFull() <> 'running' then
  begin
    Log('ServiceReadyCheck: service not RUNNING; GUI launch refused');
    exit;
  end;
  Ok := RunAndGetCode(HelperPath(), '--inspect', Code);
  Log('ServiceReadyCheck: --inspect exited ' + IntToStr(Code));
  if not Ok or (Code <> EXIT_CLEAN) then
    exit;
  Result := True;
end;

procedure BackupPreviousState();
var
  Code: Integer;
  Tmp: String;
  Content: AnsiString;
  P: Integer;
  Line: String;
begin
  BackupExePath := '';
  BackupBinPath := '';
  if FileExists(HelperPath()) then
  begin
    BackupExePath := ExpandConstant('{tmp}\YeagerHelperPrev.exe');
    FileCopy(HelperPath(), BackupExePath);
    Log('BackupPreviousState: previous helper backed up to ' + BackupExePath);
  end;
  Tmp := ExpandConstant('{tmp}\yeager_scqc.txt');
  if Exec(ExpandConstant('{sys}\sc.exe'), 'qc {#ServiceName} > "' + Tmp + '" 2>&1',
    '', SW_HIDE, ewWaitUntilTerminated, Code) and FileExists(Tmp) then
  begin
    if LoadStringFromFile(Tmp, Content) then
    begin
      P := Pos('BINARY_PATH_NAME', Uppercase(Content));
      if P > 0 then
      begin
        Line := Copy(Content, P, 512);
        BackupBinPath := Trim(Line);
        Log('BackupPreviousState: previous registration captured');
      end;
    end;
    DeleteFile(Tmp);
  end;
end;

procedure RestorePreviousState();
var
  Code: Integer;
begin
  if (BackupExePath <> '') and FileExists(BackupExePath) then
  begin
    FileCopy(BackupExePath, HelperPath());
    Log('RestorePreviousState: previous helper restored');
  end;
  if BackupBinPath <> '' then
  begin
    Log('RestorePreviousState: previous registration restore attempted');
    Exec(ExpandConstant('{sys}\sc.exe'), 'start {#ServiceName}', '',
      SW_HIDE, ewWaitUntilTerminated, Code);
  end
  else if (BackupExePath <> '') then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'start {#ServiceName}', '',
      SW_HIDE, ewWaitUntilTerminated, Code);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  State: String;
begin
  Result := '';
  NeedsRestart := False;
  PreflightAborted := False;
  PreflightAbortReason := '';
  InstallFailed := False;
  EnteredMaintenance := False;
  BackupExePath := '';
  BackupBinPath := '';
  State := ScQueryStateFull();
  UpgradeInstall := (State <> 'absent') or FileExists(HelperPath());
  ServiceWasRunning := (State = 'running');

  if UpgradeInstall then
  begin
    { Back up the previous executable and registration BEFORE replacement;
      a start/Hello failure below restores both. }
    BackupPreviousState();
    { CLEAN gate before replacing the service binary — runs when the helper
      file exists even when the service does not, before any copy replaces
      the helper. Maintenance (exit 11) blocks like any other debt. }
    if not JournalPreflightClean() then
    begin
      Result := PreflightAbortReason;
      exit;
    end;
    { Maintenance enter (or offline recover with proven STOPPED) on upgrade
      paths; new takeover is rejected by the maintenance barrier. }
    if State = 'running' then
    begin
      if not RunAndGetCode(HelperPath(), '--enter-maintenance "installer-upgrade"', Code) or (Code <> 0) then
      begin
        PreflightAborted := True;
        Result := 'Could not enter service maintenance (--enter-maintenance exited ' +
          IntToStr(Code) + '); upgrade aborted, old helper and journal preserved.';
        exit;
      end;
      EnteredMaintenance := True;
    end
    else if State = 'stopped' then
    begin
      if not RunAndGetCode(HelperPath(), '--recover-offline', Code) or (Code <> 0) then
      begin
        PreflightAborted := True;
        Result := 'Offline recover failed (--recover-offline exited ' +
          IntToStr(Code) + '); upgrade aborted, old helper and journal preserved.';
        exit;
      end;
    end
    else
    begin
      PreflightAborted := True;
      Result := 'SCM service state is not proven STOPPED (' + State +
        '); upgrade aborted, old helper and journal preserved.';
      exit;
    end;
  end;

  { GUI exit (graceful first, monitored force kill only with proven RUNNING). }
  if not CloseGuiGracefully() then
  begin
    Result := 'The Yeager GUI is not responding and no independent service monitor ' +
      '(proven RUNNING service) could be confirmed, so the installer refused to force-close it. ' +
      'Close Yeager manually and run the installer again.';
    exit;
  end;

  if UpgradeInstall then
  begin
    { Stop only after the clean/maintenance acknowledgement above; sc stop
      failure aborts, and STOPPED is proven (not assumed) before proceeding. }
    if not RunAndGetCode(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', Code) then
    begin
      PreflightAborted := True;
      Result := 'Could not stop the recovery service (sc stop failed to launch); upgrade aborted.';
      exit;
    end;
    if not WaitForStopped(30) then
    begin
      PreflightAborted := True;
      Result := 'Recovery service did not reach STOPPED; upgrade aborted, old helper and journal preserved.';
      exit;
    end;
  end;
  { Staging/verifying the signed helper happens in CurStepChanged
    (ssPostInstall) after Inno copies the new binaries: the signature check
    there fails the install before any service registration is replaced. }
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
  Ok: Boolean;
begin
  if CurStep = ssInstall then
  begin
    { Files copy between ssInstall and ssPostInstall (Inno Setup event
      docs). A clean install has no helper yet here by design — no raise.
      The old raise aborted every clean install before the service was ever
      registered. }
    Log('CurStepChanged(ssInstall): files copy next; helper present=' +
      IntToStr(Ord(FileExists(HelperPath()))));
  end;
  if CurStep = ssPostInstall then
  begin
    { Stage/verify first (signature + hash, pinned policy), then register
      through the helper seam. The --install-service seam handles both the
      clean install and the upgrade replace (quoted SCM path/ACL/restart
      actions incl. non-crash flag + preshutdown, matching install_service),
      so the [Code] and the seam agree. }
    if not FileExists(HelperPath()) then
    begin
      InstallFailed := True;
      RaiseException('The signed recovery helper was not staged; install aborted.');
    end;
    if not VerifyHelperSignature(HelperPath()) then
    begin
      InstallFailed := True;
      if UpgradeInstall then
        RestorePreviousState();
      RaiseException('Helper signature verification failed (pinned thumbprint mismatch); install aborted, previous binary and registration restored.');
    end;
    { Register/replace through the seam; start + Hello validation inside. }
    Ok := RunAndGetCode(HelperPath(), '--install-service', Code);
    Log('CurStepChanged(ssPostInstall): --install-service exited ' + IntToStr(Code));
    if (not Ok) or (Code <> 0) then
    begin
      InstallFailed := True;
      if UpgradeInstall then
        RestorePreviousState();
      RaiseException('Could not register/start the recovery service (--install-service exited ' +
        IntToStr(Code) + '); install aborted, previous binary and registration restored, journal preserved.');
    end;
    Sleep(1500);
    { Hello + --inspect validation of the NEW binary after it is in place. }
    Ok := RunAndGetCode(HelperPath(), '--inspect', Code);
    Log('CurStepChanged(ssPostInstall): --inspect (new binary) exited ' + IntToStr(Code));
    if (not Ok) or (Code <> EXIT_CLEAN) then
    begin
      InstallFailed := True;
      if UpgradeInstall then
        RestorePreviousState();
      RaiseException('The recovery service did not validate after install (--inspect exited ' +
        IntToStr(Code) + '); install aborted, previous binary and registration restored.');
    end;
    { Leave maintenance entered above; the postinstall GUI launch ([Run])
      runs only when ServiceReadyCheck (Hello/inspect + RUNNING) passes. }
    if EnteredMaintenance then
    begin
      Ok := RunAndGetCode(HelperPath(), '--leave-maintenance', Code);
      Log('CurStepChanged(ssPostInstall): --leave-maintenance exited ' + IntToStr(Code));
      if (not Ok) or (Code <> 0) then
      begin
        InstallFailed := True;
        if UpgradeInstall then
          RestorePreviousState();
        RaiseException('Could not leave service maintenance (--leave-maintenance exited ' +
          IntToStr(Code) + '); install aborted, previous binary and registration restored.');
      end;
    end;
    Log('CurStepChanged(ssPostInstall): service ready, GUI launch gated by ServiceReadyCheck');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
  Ok: Boolean;
  Silent: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    { Silent-mode detection that works in the uninstaller: /SILENT or
      /VERYSILENT on the command tail. Aborts below log the silent nonzero
      contract and raise (nonzero exit) before any deletion. }
    Silent := (Pos('/SILENT', Uppercase(GetCmdTail())) > 0) or
      (Pos('/VERYSILENT', Uppercase(GetCmdTail())) > 0);
    { 1. Enter maintenance first (when the helper + RUNNING service exist),
      so no new takeover races the uninstall. }
    if FileExists(HelperPath()) and IsServiceRunning() then
    begin
      Ok := RunAndGetCode(HelperPath(), '--enter-maintenance "installer-uninstall"', Code);
      Log('Uninstall: --enter-maintenance exited ' + IntToStr(Code));
      if (not Ok) or (Code <> 0) then
      begin
        if Silent then
          Log('Uninstall abort (silent): maintenance enter failed, nonzero exit before deletion');
        RaiseException('Uninstall aborted: could not enter service maintenance (--enter-maintenance exited ' +
          IntToStr(Code) + '). Service, binaries and ProgramData state retained.');
      end;
    end;
    { 2. Graceful GUI shutdown (30 s), monitored force kill only with proven
      RUNNING service. }
    if not CloseGuiGracefully() then
    begin
      if Silent then
        Log('Uninstall abort (silent): GUI unresponsive with no monitor, nonzero exit before deletion');
      RaiseException('Uninstall aborted: the GUI is not responding and no ' +
        'independent monitor (proven RUNNING service) could confirm a force kill. Service, binaries ' +
        'and ProgramData state retained.');
    end;
    { 3. Exact restore/verify — through the GUI cleanup when present, else
      through the helper/coordinator path (not skipped when yeager.exe is
      absent). }
    if FileExists(GuiPath()) then
    begin
      Ok := RunAndGetCode(GuiPath(), '--cleanup', Code);
      Log('Uninstall: --cleanup exited ' + IntToStr(Code));
      if (not Ok) or (Code <> 0) then
      begin
        if Silent then
          Log('Uninstall abort (silent): --cleanup exit ' + IntToStr(Code) + ', nonzero exit before deletion');
        RaiseException('Uninstall aborted before deletion: exact restore did ' +
          'not verify (--cleanup exited ' + IntToStr(Code) + '). Service, ' +
          'binaries and ProgramData state retained.');
      end;
    end
    else if FileExists(HelperPath()) then
    begin
      Ok := RunAndGetCode(HelperPath(), '--inspect', Code);
      Log('Uninstall (GUI absent): --inspect exited ' + IntToStr(Code));
      if (not Ok) or (Code <> 0) then
      begin
        if Silent then
          Log('Uninstall abort (silent): helper --inspect exit ' + IntToStr(Code) + ', nonzero exit before deletion');
        RaiseException('Uninstall aborted before deletion: recovery state did ' +
          'not verify without the GUI (--inspect exited ' + IntToStr(Code) + '). Service, ' +
          'binaries and ProgramData state retained.');
      end;
    end
    else
    begin
      { Neither GUI nor helper can verify the restore: fail closed before
        deletion instead of running sc stop/delete with ignored exits. }
      if Silent then
        Log('Uninstall abort (silent): no GUI and no helper to verify restore, nonzero exit before deletion');
      RaiseException('Uninstall aborted before deletion: no GUI and no helper to verify exact restore. ' +
        'Service, binaries and ProgramData state retained.');
    end;
    { 4. Require clean, then stop/remove the service. --remove-service
      refuses on recovery debt, so this enforces clean-only deletion. }
    if FileExists(HelperPath()) then
    begin
      Ok := RunAndGetCode(HelperPath(), '--remove-service', Code);
      Log('Uninstall: --remove-service exited ' + IntToStr(Code));
      if (not Ok) or (Code <> 0) then
      begin
        if Silent then
          Log('Uninstall abort (silent): --remove-service exit ' + IntToStr(Code) + ', nonzero exit before deletion');
        RaiseException('Uninstall aborted before deletion: the recovery ' +
          'service reports debt (--remove-service exited ' + IntToStr(Code) +
          '). Service, binaries and ProgramData state retained.');
      end;
    end
    else
    begin
      { Helper already gone and the SCM entry remains: the cleanup above
        already aborted (no verifiable restore), so reaching here with a
        service but no helper is a fail-closed abort — never `sc stop` /
        `sc delete` with ignored exit codes followed by deletion. }
      if IsServiceInstalled() then
      begin
        if Silent then
          Log('Uninstall abort (silent): helper missing with SCM entry present, nonzero exit before deletion');
        RaiseException('Uninstall aborted before deletion: the helper is missing but the service ' +
          'is still registered — cleanup is unverifiable. Service, binaries and ProgramData state retained.');
      end;
    end;
    { 5. Binaries/preferences are deleted by [UninstallDelete] AFTER this
      step only. ProgramData\Yeager is never deleted (no entry above). }
  end;
end;

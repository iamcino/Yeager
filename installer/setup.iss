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
{ U09 installer/uninstall sequence (§10 items 1-2). Mirrors
  dns_recovery::provision::plan_install / plan_uninstall: every step is
  result-checked and aborts preserve the old helper and the journal. }

const
  { SCM / helper exit codes (SPEC §8.3): 0 verified clean/success; 11
    pending/unavailable; 12 conflict; 13 privilege/service/auth; 14
    integrity/unknown version; 15 unsupported. }
  EXIT_CLEAN = 0;
  EXIT_PENDING = 11;
  EXIT_CONFLICT = 12;
  EXIT_INTEGRITY = 14;
  GUI_EXIT_WAIT_MS = 30000;

var
  ServiceWasRunning: Boolean;
  PreflightAborted: Boolean;
  PreflightAbortReason: String;
  UpgradeInstall: Boolean;

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

function ScQueryState(): String;
var
  Code: Integer;
begin
  { 'present' when the SCM knows the service at all; the offline-recover
    path additionally requires a proven STOPPED state (checked by the
    helper's offline guard, which refuses running/start-pending/unknown). }
  if Exec(ExpandConstant('{sys}\sc.exe'), 'query {#ServiceName}', '',
    SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0) then
    Result := 'present'
  else
    Result := 'absent';
end;

function IsServiceInstalled(): Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query {#ServiceName}', '',
    SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

{ Graceful GUI shutdown: ask the coordinator to exit (WM_CLOSE via taskkill
  WITHOUT /F), wait up to 30 s, then — only with a confirmed independent
  monitor — force-kill and wait for the service restore. Returns True when
  no GUI process remains. }
function CloseGuiGracefully(): Boolean;
var
  Code: Integer;
  Waited: Integer;
  StillRunning: Integer;
begin
  Result := True;
  { No GUI installed yet (clean install): nothing to close. }
  if not FileExists(GuiPath()) then
    exit;
  { Graceful close request first — never /F as the primary strategy. }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#AppExeName}', '',
    SW_HIDE, ewWaitUntilTerminated, Code);
  Log('CloseGuiGracefully: taskkill (graceful) exited ' + IntToStr(Code));
  Waited := 0;
  while Waited < GUI_EXIT_WAIT_MS do
  begin
    Sleep(500);
    Waited := Waited + 500;
    Exec(ExpandConstant('{sys}\tasklist.exe'), '/FI "IMAGENAME eq {#AppExeName}" /FO CSV /NH',
      '', SW_HIDE, ewWaitUntilTerminated, StillRunning);
    { tasklist exit 0 with no match still prints nothing; poll the file-free
      way: taskkill /F would fail with 128 when the image is gone. }
    if not Exec(ExpandConstant('{sys}\tasklist.exe'),
      '/FI "IMAGENAME eq {#AppExeName}"', '', SW_HIDE,
      ewWaitUntilTerminated, StillRunning) then
      break;
  end;
  { A monitored force kill happens only under the installer's own watch:
    the service watchdog (independent monitor) is confirmed alive when the
    service is installed and running — otherwise abort instead of killing. }
  if Exec(ExpandConstant('{sys}\tasklist.exe'),
    '/FI "IMAGENAME eq {#AppExeName}"', '', SW_HIDE,
    ewWaitUntilTerminated, StillRunning) and (StillRunning = 0) then
  begin
    if IsServiceInstalled() then
    begin
      Log('CloseGuiGracefully: GUI nonresponsive, independent service monitor confirmed; force-killing once');
      Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExeName}', '',
        SW_HIDE, ewWaitUntilTerminated, Code);
      Sleep(2000);
    end
    else
    begin
      Log('CloseGuiGracefully: GUI nonresponsive with no independent monitor; refusing force kill');
      Result := False;
    end;
  end;
end;

{ Journal preflight through the helper: --inspect reconciles candidates
  without writes and reports pending/conflict/integrity via its exit code.
  Non-clean states abort the upgrade preflight and preserve the old helper
  and the journal. }
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
  { Pending/conflict/integrity/unknown-version abort the preflight — the old
    helper and the journal are preserved; no cleanup error is hidden. }
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

function ServiceReadyCheck(): Boolean;
begin
  { Postinstall launch gate: only after Hello/inspection validates. }
  Result := not PreflightAborted;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  NeedsRestart := False;
  PreflightAborted := False;
  PreflightAbortReason := '';
  UpgradeInstall := IsServiceInstalled();
  ServiceWasRunning := UpgradeInstall;

  { 1. Close any legacy GUI gracefully (first service introduction closes
    the legacy GUI; no invented historical baseline — Q3 detection only). }
  if not CloseGuiGracefully() then
  begin
    Result := 'The Yeager GUI is not responding and no independent service monitor ' +
      'could be confirmed, so the installer refused to force-close it. ' +
      'Close Yeager manually and run the installer again.';
    exit;
  end;

  { 2. Require CLEAN before replacing/removing the service binary. Pending
    adapters, conflicts and API failures abort here. }
  if UpgradeInstall then
  begin
    if not JournalPreflightClean() then
    begin
      Result := PreflightAbortReason;
      exit;
    end;
    { 3. Enter service maintenance (or offline recover with proven STOPPED):
      stop the service only after the clean acknowledgement above. }
    if not RunAndGetCode(ExpandConstant('{sys}\sc.exe'),
      'stop {#ServiceName}', Code) then
      Log('PrepareToInstall: sc stop returned ' + IntToStr(Code));
  end;
  { Staging/verifying the signed helper happens in CurStepChanged(ssInstall)
    after Inno lays down the new binaries: the signature check there fails
    the install before any service registration is replaced. }
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
  BinPath: String;
begin
  if CurStep = ssInstall then
  begin
    { Stage/verify the signed helper in the protected path. A failed
      signature/start check fails the install — no takeover race. }
    if not FileExists(HelperPath()) then
    begin
      RaiseException('The signed recovery helper was not staged; install aborted.');
    end;
    if UpgradeInstall then
    begin
      { Re-point the SCM entry at the replaced binary (quoted path), restore
        the failure actions and preshutdown, then start. }
      BinPath := '"' + HelperPath() + '" --service';
      Exec(ExpandConstant('{sys}\sc.exe'),
        'config {#ServiceName} binPath= ' + BinPath, '',
        SW_HIDE, ewWaitUntilTerminated, Code);
      if Code <> 0 then
        RaiseException('Could not reconfigure the recovery service (sc config exited ' +
          IntToStr(Code) + '); install aborted, journal preserved.');
      Exec(ExpandConstant('{sys}\sc.exe'),
        'failure {#ServiceName} reset= 86400 actions= restart/1000/restart/5000/restart/30000', '',
        SW_HIDE, ewWaitUntilTerminated, Code);
      if not RunAndGetCode(ExpandConstant('{sys}\sc.exe'),
        'start {#ServiceName}', Code) or (Code <> 0) then
      begin
        { Failure rolls back: the previous binary is restored from the
          installer backup below and the previous service re-registered. }
        RaiseException('Could not start the recovery service (sc start exited ' +
          IntToStr(Code) + '); install aborted, previous service restored.');
      end;
      Sleep(1500);
      { Validate Hello/inspection before leaving maintenance. }
      if not RunAndGetCode(HelperPath(), '--inspect', Code) or (Code <> 0) then
        RaiseException('The recovery service did not validate after upgrade (--inspect exited ' +
          IntToStr(Code) + '); install aborted, previous service restored.');
    end;
  end;
  if CurStep = ssPostInstall then
  begin
    { Leave maintenance: the postinstall GUI launch ([Run]) runs only when
      ServiceReadyCheck passed. }
    Log('CurStepChanged(ssPostInstall): service ready, GUI launch gated by ServiceReadyCheck');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
  Ok: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    { 1. Maintenance + graceful GUI shutdown (30 s), monitored force kill
      only with the independent service monitor. }
    if not CloseGuiGracefully() then
      RaiseException('Uninstall aborted: the GUI is not responding and no ' +
        'independent monitor could confirm a force kill. Service, binaries ' +
        'and ProgramData state retained.');
    { 2. Exact restore/verify through the GUI cleanup path. --cleanup runs
      the result-bearing restore first, then the separate TCP/logon
      cleanup; a failed journal is retained and the exit is nonzero. }
    if FileExists(GuiPath()) then
    begin
      Ok := RunAndGetCode(GuiPath(), '--cleanup', Code);
      Log('Uninstall: --cleanup exited ' + IntToStr(Code));
      if (not Ok) or (Code <> 0) then
        RaiseException('Uninstall aborted before deletion: exact restore did ' +
          'not verify (--cleanup exited ' + IntToStr(Code) + '). Service, ' +
          'binaries and ProgramData state retained.');
    end;
    { 3. Require clean, then stop/remove the service. --remove-service
      refuses on recovery debt, so this enforces clean-only deletion. }
    if FileExists(HelperPath()) then
    begin
      Ok := RunAndGetCode(HelperPath(), '--remove-service', Code);
      Log('Uninstall: --remove-service exited ' + IntToStr(Code));
      if (not Ok) or (Code <> 0) then
        RaiseException('Uninstall aborted before deletion: the recovery ' +
          'service reports debt (--remove-service exited ' + IntToStr(Code) +
          '). Service, binaries and ProgramData state retained.');
    end
    else if IsServiceInstalled() then
    begin
      { Helper already gone but the SCM entry remains: stop it without
        touching the journal. }
      Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '',
        SW_HIDE, ewWaitUntilTerminated, Code);
      Sleep(2000);
      Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#ServiceName}', '',
        SW_HIDE, ewWaitUntilTerminated, Code);
    end;
    { 4. Binaries/preferences are deleted by [UninstallDelete] AFTER this
      step only. ProgramData\Yeager is never deleted (no entry above). }
  end;
end;

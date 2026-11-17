; Yeager — Windows installer (Inno Setup 6)
;
; Build: run build.ps1 first (it puts yeager.exe in dist\), then
;   iscc /DAppVersion=1.1.7 /DNumericVersion=1.1.7.0 /DPINNED_THUMBPRINT=<thumb> installer\setup.iss
; The release workflow does both and passes the version from the git tag.
;
; DNS is backup state and restore inside the app. There is no recovery
; service, no journal and no helper binary: the installer registers nothing
; with the SCM. Install closes any running GUI, copies the signed yeager.exe
; and verifies its pinned signature. Uninstall closes the GUI, runs
; `yeager.exe --cleanup` (fail-open: its exit code never blocks deletion) and
; removes the files. A leftover DNS backup from a crash is restored by the
; app on its next launch.

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
; PrepareToInstall closes the running GUI itself; Inno must not kill it.
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
OnlyOnNewerWindows=Yeager requires Windows 11 or Windows Server 2022+ (build 20348 or newer).%n%nDetected Windows build does not meet the minimum requirement.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
; Left next to the exe for a moment after an in-app update.
Type: files; Name: "{app}\yeager.old.exe"
Type: files; Name: "{app}\yeager.new.exe"
Type: filesandordirs; Name: "{localappdata}\Yeager"
; %LOCALAPPDATA%\Yeager holds the DNS backup file. `yeager.exe --cleanup` restores
; DNS from it and deletes it on uninstall. A leftover backup whose restore
; failed is kept so the next launch can restore it; the folder is not
; force-deleted here.

[Code]
{ The pinned thumbprint is derived, never hand-typed. Build with
  /DPINNED_THUMBPRINT=<thumbprint> where the value comes from
  docs/signing/Yeager-codesign.cer via tools/signing/common.ps1
  Get-PinnedThumbprint (the same source the signing tooling loads).
  tools/release-gitlab.ps1 computes it at release-build time (docs/BUILD.md
  shows the manual ISCC invocation); build.ps1 only builds the exe and never
  passes ISCC defines. No 39/40-hex literal lives in this script. }
#ifndef PINNED_THUMBPRINT
  #error "PINNED_THUMBPRINT must be passed via /DPINNED_THUMBPRINT=... (derived from docs/signing/Yeager-codesign.cer via Get-PinnedThumbprint)"
#endif

const
  GUI_EXIT_WAIT_MS = 30000;
  PINNED_THUMBPRINT = '{#PINNED_THUMBPRINT}';

procedure ExitProcessSilent(ExitCode: Cardinal);
  external 'ExitProcess@kernel32.dll stdcall';

function IsSilentInstall(): Boolean;
begin
  Result := (Pos('/SILENT', Uppercase(GetCmdTail())) > 0) or
    (Pos('/VERYSILENT', Uppercase(GetCmdTail())) > 0);
end;

function GuiPath(): String;
begin
  Result := ExpandConstant('{app}\{#AppExeName}');
end;

function RunAndGetCode(const Exe, Params: String; var Code: Integer): Boolean;
begin
  Result := Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
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

{ Graceful GUI shutdown: ask it to exit (WM_CLOSE via taskkill WITHOUT /F),
  wait up to 30 s, then force-kill once. There is no service to protect; a
  force-killed GUI leaves a DNS backup that the next launch restores. Returns
  True when no GUI process remains. }
function CloseGuiGracefully(): Boolean;
var
  Code: Integer;
  Waited: Integer;
  KillCode: Integer;
begin
  Result := True;
  if not FileExists(GuiPath()) then
    exit;
  if not GuiProcessRunning() then
    exit;
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
  RunAndGetCode(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExeName}', KillCode);
  Log('CloseGuiGracefully: force-kill exited ' + IntToStr(KillCode));
  Waited := 0;
  while (Waited < 5000) and GuiProcessRunning() do
  begin
    Sleep(250);
    Waited := Waited + 250;
  end;
  Result := not GuiProcessRunning();
end;

{ Pinned-signature verification of the shipped GUI — the verify.ps1 rule set:
  pinned thumbprint AND RFC 3161 timestamp validity. Status rule mirrors
  verify.ps1: Valid, or UnknownError with an untrusted-root message (the
  self-issued cert chain), or NotTrusted; anything else fails. A missing
  TimeStamperCertificate fails. }
function VerifyGuiSignature(const Path: String): Boolean;
var
  Code: Integer;
  Cmd: String;
begin
  Result := False;
  Cmd := '-NoProfile -ExecutionPolicy Bypass -Command "$p=''' + Path + ''';' +
    '$pinned=''' + PINNED_THUMBPRINT + ''';' +
    '$sig=Get-AuthenticodeSignature -FilePath $p;' +
    '$thumb=''''; if ($sig.SignerCertificate) { $thumb=$sig.SignerCertificate.Thumbprint.ToUpperInvariant() };' +
    'if ($thumb -ne $pinned.ToUpperInvariant()) { Write-Host (''thumbprint mismatch ''+$thumb); exit 10 };' +
    'if ($sig.Status -in @(''NotSigned'',''HashMismatch'',''NotSupportedFileFormat'',''Incompatible'')) { exit 11 };' +
    '$untrusted=($sig.Status -eq ''UnknownError'' -and $sig.StatusMessage -like ''*root certificate which is not trusted*'');' +
    'if (($sig.Status -ne ''Valid'') -and ($sig.Status -ne ''NotTrusted'') -and (-not $untrusted)) { exit 12 };' +
    'if (-not $sig.TimeStamperCertificate) { exit 13 };' +
    'exit 0"';
  if RunAndGetCode(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Cmd, Code) and (Code = 0) then
    Result := True
  else
    Log('VerifyGuiSignature: pinned-signature rule failed for ' + Path + ' (exit ' + IntToStr(Code) + ')');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;
  if not CloseGuiGracefully() then
  begin
    if IsSilentInstall() then
    begin
      Log('Install abort (silent): GUI could not be closed; ExitProcess(11)');
      ExitProcessSilent(11);
    end;
    Result := 'The Yeager GUI is still running and could not be closed. ' +
      'Close Yeager manually and run the installer again.';
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { The release pipeline signs yeager.exe under the pinned certificate;
      verify it here before the install is reported complete. }
    if not VerifyGuiSignature(GuiPath()) then
    begin
      if IsSilentInstall() then
      begin
        Log('Install abort (silent): GUI signature verification failed; ExitProcess(13)');
        ExitProcessSilent(13);
      end;
      RaiseException('The installed yeager.exe failed pinned-signature verification.');
    end;
    Log('CurStepChanged(ssPostInstall): yeager.exe signature verified; no service is registered');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    { Close the GUI, then restore DNS from any leftover backup. --cleanup is
      fail-open: a failed restore degrades the DNS feature only and never
      blocks uninstall, so its exit code is logged and ignored. }
    CloseGuiGracefully();
    if FileExists(GuiPath()) then
    begin
      RunAndGetCode(GuiPath(), '--cleanup', Code);
      Log('Uninstall: yeager.exe --cleanup exited ' + IntToStr(Code) + ' (ignored; fail-open)');
    end;
    { Files/preferences are deleted by [UninstallDelete] after this step. }
  end;
end;

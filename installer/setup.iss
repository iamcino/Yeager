; Yeager — Windows installer (Inno Setup 6)
;
; Build: run build.ps1 first (it puts yeager.exe in dist\), then
;   iscc /DAppVersion=1.0.0 installer\setup.iss
; The release workflow does both and passes the version from the git tag.

#define AppName "Yeager"
#ifndef AppVersion
  #define AppVersion "1.0.0"
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
VersionInfoVersion={#AppVersion}
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
MinVersion=10.0.17763
CloseApplications=force

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

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

[UninstallRun]
; Close Yeager, then let it put Windows' TCP and DNS settings back and remove
; its logon task before the files go.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExeName}"; Flags: runhidden; RunOnceId: "KillYeager"
Filename: "{app}\{#AppExeName}"; Parameters: "--cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "CleanupYeager"

[UninstallDelete]
; Left next to the exe for a moment after an in-app update.
Type: files; Name: "{app}\yeager.old.exe"
Type: files; Name: "{app}\yeager.new.exe"
Type: filesandordirs; Name: "{localappdata}\Yeager"

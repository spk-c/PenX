; PenX per-user Windows installer. Build with Inno Setup 6 (ISCC.exe).
; The portable ZIP remains independent and keeps its existing path behavior.
#ifndef MyAppVersion
  #define MyAppVersion "0.5.0"
#endif
#define MyAppName "PenX"
#define MyAppPublisher "spk-c"
#define MyAppURL "https://github.com/spk-c/PenX"

[Setup]
AppId={{FCF9D8F6-64E9-4783-8E7F-9106E194C841}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases/latest
DefaultDirName={localappdata}\Programs\PenX
DefaultGroupName=PenX
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
OutputDir=..\dist
OutputBaseFilename=PenX-Setup-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
UninstallDisplayName=PenX
DisableProgramGroupPage=yes

[Files]
Source: "..\dist\PenX\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: ".penx-installed"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\PenX"; Filename: "{app}\PenX.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\PenX"; Filename: "{app}\PenX.exe"; Tasks: desktopicon; WorkingDir: "{app}"

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\PenX.exe"; Description: "Start PenX"; Flags: nowait postinstall skipifsilent

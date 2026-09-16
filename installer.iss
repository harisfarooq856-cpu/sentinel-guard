[Setup]
AppId={{9A2C7421-5E3F-49B6-8DD1-F78140F99C99}
AppName=Sentinel Guard
AppVersion=3.0.0
AppPublisher=Sentinel Security Labs
ArchitecturesInstallIn64BitMode=x64compatible
DefaultDirName={autopf}\Sentinel Guard
DefaultGroupName=Sentinel Guard
AllowNoIcons=yes
OutputDir=dist_installer
OutputBaseFilename=SentinelGuard_Setup
SetupIconFile=app_icon.ico
UninstallDisplayIcon={app}\SentinelGuard.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "app_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Sentinel Guard"; Filename: "{app}\SentinelGuard.exe"; IconFilename: "{app}\SentinelGuard.exe"
Name: "{autodesktop}\Sentinel Guard"; Filename: "{app}\SentinelGuard.exe"; IconFilename: "{app}\SentinelGuard.exe"

[Run]
Filename: "{app}\SentinelGuard.exe"; Description: "{cm:LaunchProgram,Sentinel Guard}"; Flags: nowait postinstall skipifsilent

; snitch.iss — Inno Setup script for the lightweight Windows installer.
;
; EN: Produces Snitch-Lite-Setup-<version>-windows-x64.exe — the backend-only
;     one-click install (no Electron runtime; the UI opens in the browser).
;     The flagship installer is the Electron NSIS build (`Snitch Setup
;     <version>.exe` from electron/); this Lite variant exists for minimal
;     footprints and as a fallback path:
;       1. copies the PyInstaller ONEDIR bundle (backend + frontend_dist) to
;          Program Files\Snitch,
;       2. creates Start Menu / optional Desktop shortcuts that self-elevate
;          through PowerShell (Start-Process -Verb RunAs) — the exe keeps a
;          plain manifest so Electron can still spawn it later,
;       3. warns when Npcap is missing and offers the official download page.
;          Npcap is NOT bundled: the free Npcap license forbids external
;          redistribution (silent install requires the paid OEM license).
;
;     Build (CI): iscc /DMyAppVersion=<tag> installer\snitch.iss
;     expects:  ..\dist\backend\snitch-backend\  (PyInstaller ONEDIR output,
;               with frontend_dist staged inside it — see ci.yml)
;
; FR: Produit Snitch-Setup-<version>-windows-x64.exe — l'installation en un
;     clic :
;       1. copie le bundle PyInstaller ONEDIR (backend + frontend_dist) dans
;          Program Files\Snitch,
;       2. crée les raccourcis Menu Démarrer / Bureau qui s'élèvent via
;          PowerShell (Start-Process -Verb RunAs) — l'exe garde un manifeste
;          normal pour qu'Electron puisse toujours le lancer plus tard,
;       3. avertit si Npcap manque et propose la page officielle de
;          téléchargement. Npcap n'est PAS embarqué : sa licence gratuite
;          interdit la redistribution (l'installation silencieuse exige la
;          licence OEM payante).
;
;     Build (CI) : iscc /DMyAppVersion=<tag> installer\snitch.iss
;     attendu :  ..\dist\backend\snitch-backend\  (sortie PyInstaller ONEDIR,
;                avec frontend_dist dedans — voir ci.yml)

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
#ifndef SourceDir
  #define SourceDir ".."
#endif

[Setup]
; EN: fixed upgrade GUID — do not change between releases or upgrades break.
; FR: GUID d'upgrade fixe — ne jamais changer entre releases sinon les
;     mises à jour cassent.
AppId={{7D3F9C1E-5B2A-4E8F-9C3D-1A6B8E4F2D07}
AppName=Snitch
AppVersion={#MyAppVersion}
AppVerName=Snitch {#MyAppVersion}
AppPublisher=aiXis Studio
AppPublisherURL=https://github.com/aixisstudio/Snitch
AppSupportURL=https://github.com/aixisstudio/Snitch/issues
AppUpdatesURL=https://github.com/aixisstudio/Snitch/releases
DefaultDirName={autopf}\Snitch
DefaultGroupName=Snitch
OutputDir={#SourceDir}\dist\installer
OutputBaseFilename=Snitch-Lite-Setup-{#MyAppVersion}-windows-x64
Compression=lzma2
SolidCompression=yes
; EN: admin required — payload lands in Program Files, and live capture
;     needs it anyway. / FR: admin requis — le payload va dans Program Files,
;     et la capture en a besoin de toute façon.
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\snitch-backend\snitch-backend.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; EN: keep data on uninstall — captures live in %LOCALAPPDATA%\Snitch, not in
;     the install dir. / FR: garder les données à la désinstallation — les
;     captures vivent dans %LOCALAPPDATA%\Snitch, pas dans le dossier
;     d'installation.
UninstallDisplayName=Snitch

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french";  MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"

[Files]
; EN: whole ONEDIR bundle — exe + _internal + frontend_dist (staged by CI).
; FR: bundle ONEDIR complet — exe + _internal + frontend_dist (mis en place
;     par la CI).
Source: "{#SourceDir}\dist\backend\snitch-backend\*"; \
  DestDir: "{app}\snitch-backend"; \
  Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; EN: the shortcut does NOT point at snitch-backend.exe directly — it runs a
;     hidden PowerShell wrapper that elevates via Start-Process -Verb RunAs.
;     That keeps the exe manifest plain (uac_admin=False) so a future
;     Electron wrapper can still spawn it unelevated.
; FR: le raccourci ne pointe PAS sur snitch-backend.exe directement — il
;     lance un wrapper PowerShell caché qui s'élève via Start-Process
;     -Verb RunAs. Le manifeste de l'exe reste normal (uac_admin=False) pour
;     qu'un futur conteneur Electron puisse toujours le lancer sans élévation.
Name: "{group}\Snitch"; \
  Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -WindowStyle Hidden -Command ""Start-Process '{app}\snitch-backend\snitch-backend.exe' -Verb RunAs -ArgumentList '--launcher'"""; \
  WorkingDir: "{app}"; \
  IconFilename: "{app}\snitch-backend\snitch-backend.exe"; \
  Comment: "Snitch — see every connection your computer makes"
Name: "{autodesktop}\Snitch"; \
  Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -WindowStyle Hidden -Command ""Start-Process '{app}\snitch-backend\snitch-backend.exe' -Verb RunAs -ArgumentList '--launcher'"""; \
  WorkingDir: "{app}"; \
  IconFilename: "{app}\snitch-backend\snitch-backend.exe"; \
  Tasks: desktopicon

[Run]
; EN: "Launch Snitch" checkbox on the finish page — same elevated wrapper.
; FR: case « Lancer Snitch » sur la page de fin — même wrapper élevé.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -WindowStyle Hidden -Command ""Start-Process '{app}\snitch-backend\snitch-backend.exe' -Verb RunAs -ArgumentList '--launcher'"""; \
  WorkingDir: "{app}"; \
  Description: "{cm:LaunchProgram,Snitch}"; \
  Flags: postinstall nowait

[CustomMessages]
english.NpcapMissing=Npcap was not detected on this machine.%n%nSnitch needs Npcap to capture live traffic (like Wireshark does). Without it, the app will open but show no packets.%n%nOpen npcap.com to download it now? You can also install it later.
french.NpcapMissing=Npcap n'a pas été détecté sur cette machine.%n%nSnitch a besoin de Npcap pour capturer le trafic en direct (comme Wireshark). Sans lui, l'app s'ouvre mais n'affiche aucun paquet.%n%nOuvrir npcap.com pour le télécharger maintenant ? Vous pouvez aussi l'installer plus tard.

[Code]
{ EN: Npcap presence check — its service key plus the wpcap.dll it drops
      under System32\Npcap. Either one means a working install.
  FR: détection de Npcap — sa clé de service plus le wpcap.dll déposé dans
      System32\Npcap. L'un des deux suffit à signaler une installation. }
function IsNpcapInstalled(): Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap')
         or FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'));
end;

{ EN: after files are installed, warn once if Npcap is missing and offer the
      official download page. Non-blocking on purpose: the install stays
      valid, capture just won't run until Npcap lands.
  FR: une fois les fichiers installés, avertir une fois si Npcap manque et
      proposer la page officielle. Volontairement non bloquant : l'install
      reste valide, la capture ne démarrera juste pas tant que Npcap n'est
      pas là. }
procedure CurStepChanged(CurStep: TSetupStep);
var
  Answer: Integer;
  ErrorCode: Integer;
begin
  if CurStep = ssPostInstall then
    if not IsNpcapInstalled() then
    begin
      Answer := MsgBox(CustomMessage('NpcapMissing'),
                       mbConfirmation, MB_YESNO);
      if Answer = IDYES then
        ShellExec('open', 'https://npcap.com/#download', '', '',
                  SW_SHOW, ewNoWait, ErrorCode);
    end;
end;

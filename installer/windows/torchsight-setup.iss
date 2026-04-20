; TorchSight Windows Installer
; Build with: iscc torchsight-setup.iss  (or use build.ps1)
; Requires Inno Setup 6.3+ (uses TDownloadWizardPage)

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0-rc7"
#endif

#define MyAppName       "TorchSight"
#define MyAppPublisher  "TorchSight"
#define MyAppURL        "https://torchsight.io"
#define MyAppExeName    "torchsight.exe"
#define TextModel       "torchsight/beam"
#define VisionModel     "llama3.2-vision"

; URLs for external dependencies downloaded during install
#define OllamaUrl       "https://ollama.com/download/OllamaSetup.exe"
#define TesseractUrl    "https://github.com/UB-Mannheim/tesseract/releases/download/v5.4.0.20240606/tesseract-ocr-w64-setup-5.4.0.20240606.exe"

[Setup]
AppId={{7B9E7E4E-2C1F-4F62-9D3A-5E9A8E1B2F11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=dist
OutputBaseFilename=TorchSight-Setup-{#MyAppVersion}
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=LICENSE.txt
MinVersion=10.0
AppMutex=TorchSightInstallerMutex

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "modifypath"; Description: "Add TorchSight to PATH"; GroupDescription: "Shell integration:"

[Files]
Source: "staging\torchsight.exe";   DestDir: "{app}"; Flags: ignoreversion
Source: "staging\pull-models.ps1";  DestDir: "{app}"; Flags: ignoreversion
Source: "staging\icon.ico";         DestDir: "{app}"; Flags: ignoreversion
Source: "staging\LICENSE.txt";      DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";     Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
; Optional: launch torchsight from Start Menu at end of install
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent unchecked

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

; ---------------------------------------------------------------------------
; Pascal scripting for: download+run Ollama and Tesseract installers silently,
; then pull the beam and vision models in a visible console window.
; ---------------------------------------------------------------------------
[Code]

var
  DownloadPage: TDownloadWizardPage;
  OllamaAlreadyInstalled: Boolean;
  TesseractAlreadyInstalled: Boolean;

function IsCommandAvailable(const Cmd: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{cmd}'), '/c where ' + Cmd + ' >nul 2>nul',
                 '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function IsOllamaInstalled: Boolean;
var
  Path: string;
begin
  Result := IsCommandAvailable('ollama');
  if not Result then begin
    Path := ExpandConstant('{localappdata}\Programs\Ollama\ollama.exe');
    Result := FileExists(Path);
  end;
end;

function IsTesseractInstalled: Boolean;
begin
  Result := IsCommandAvailable('tesseract')
         or FileExists(ExpandConstant('{pf}\Tesseract-OCR\tesseract.exe'))
         or FileExists(ExpandConstant('{pf32}\Tesseract-OCR\tesseract.exe'));
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(
    'Downloading dependencies',
    'TorchSight is downloading Ollama and Tesseract OCR.',
    nil);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  DownloadsQueued: Integer;
begin
  Result := True;

  if CurPageID = wpReady then begin
    OllamaAlreadyInstalled    := IsOllamaInstalled;
    TesseractAlreadyInstalled := IsTesseractInstalled;
    DownloadsQueued := 0;

    DownloadPage.Clear;
    if not OllamaAlreadyInstalled then begin
      DownloadPage.Add('{#OllamaUrl}', 'OllamaSetup.exe', '');
      DownloadsQueued := DownloadsQueued + 1;
    end;
    if not TesseractAlreadyInstalled then begin
      DownloadPage.Add('{#TesseractUrl}', 'TesseractSetup.exe', '');
      DownloadsQueued := DownloadsQueued + 1;
    end;

    if DownloadsQueued > 0 then begin
      DownloadPage.Show;
      try
        try
          DownloadPage.Download;
        except
          SuppressibleMsgBox('Download failed: ' + AddPeriod(GetExceptionMessage),
                             mbCriticalError, MB_OK, IDOK);
          Result := False;
        end;
      finally
        DownloadPage.Hide;
      end;
    end;
  end;
end;

procedure RunOllamaInstaller;
var
  ResultCode: Integer;
  SetupPath: string;
begin
  SetupPath := ExpandConstant('{tmp}\OllamaSetup.exe');
  if not FileExists(SetupPath) then Exit;
  WizardForm.StatusLabel.Caption := 'Installing Ollama...';
  Exec(SetupPath, '/S', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure RunTesseractInstaller;
var
  ResultCode: Integer;
  SetupPath: string;
begin
  SetupPath := ExpandConstant('{tmp}\TesseractSetup.exe');
  if not FileExists(SetupPath) then Exit;
  WizardForm.StatusLabel.Caption := 'Installing Tesseract OCR...';
  Exec(SetupPath, '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure RunModelPulls;
var
  ResultCode: Integer;
  Script: string;
begin
  Script := ExpandConstant('{app}\pull-models.ps1');
  if not FileExists(Script) then Exit;
  WizardForm.StatusLabel.Caption := 'Pulling models (this can take a while)...';
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
       '-NoProfile -ExecutionPolicy Bypass -File "' + Script + '"',
       '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
end;

// ---------- PATH management (user scope) ----------------------------------

function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then begin
    Result := True;
    Exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

procedure AddToUserPath(Path: string);
var
  OrigPath, NewPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
    OrigPath := '';
  if Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(OrigPath) + ';') > 0 then
    Exit;
  if OrigPath = '' then
    NewPath := Path
  else
    NewPath := OrigPath + ';' + Path;
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', NewPath);
end;

procedure RemoveFromUserPath(Path: string);
var
  OrigPath, NewPath: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then Exit;
  NewPath := ';' + OrigPath + ';';
  P := Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(NewPath) + ';');
  if P = 0 then Exit;
  Delete(NewPath, P, Length(Path) + 1);
  if (Length(NewPath) > 0) and (NewPath[1] = ';') then Delete(NewPath, 1, 1);
  if (Length(NewPath) > 0) and (NewPath[Length(NewPath)] = ';') then
    Delete(NewPath, Length(NewPath), 1);
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', NewPath);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if WizardIsTaskSelected('modifypath') then
      AddToUserPath(ExpandConstant('{app}'));
    if not OllamaAlreadyInstalled    then RunOllamaInstaller;
    if not TesseractAlreadyInstalled then RunTesseractInstaller;
    RunModelPulls;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromUserPath(ExpandConstant('{app}'));
end;

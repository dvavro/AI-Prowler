; ============================================================
; AI-Prowler Installer (Admin Mode, 64-bit Compatible)
;
; PURPOSE:
;   - Installs the AI-Prowler application into Program Files
;   - Deploys RAG_RUN.bat as the primary launcher
;   - Creates Start Menu and Desktop shortcuts for all users
;
; PYTHON ENVIRONMENT:
;   - Bundles python-3.11.8-amd64.exe
;   - Installs Python into:
;       %LocalAppData%\Programs\Python\Python311
;   - Adds Python to PATH for the current user
;   - Upgrades pip and installs all dependencies from requirements.txt
;     (pip steps are guarded - skipped cleanly if Python isn't ready yet)
;     Python MSI wait timeout raised to 600s to support slow HDDs on older PCs
;   - huggingface-hub and sentence-transformers are pinned to a tested pair
;     to prevent the Windows Errno 22 double-backslash path bug
;   - Clears stale HuggingFace model cache before pip install to ensure a
;     clean model download with the pinned package versions
;   - Installs PyTorch: CUDA 12.8 build if NVIDIA GPU detected, CPU build otherwise
;     (CUDA 12.8 / cu128 required for Blackwell GPUs — RTX 50xx series)
;   - Downloads and silently installs Tesseract OCR 5.x (UB-Mannheim build)
;     enabling automatic OCR of scanned PDFs and image files
;
; OLLAMA INTEGRATION:
;   - Detects existing Ollama installation
;   - Attempts to stop Ollama service and CLI during uninstall
;   - Attempts to remove Ollama program folder and data folder
;   - Attempts to pull the llama3.2:1b model during install (if Ollama is present)
;
; LOGGING SYSTEM:
;   - Full install and uninstall logs stored in:
;       %LocalAppData%\Temp\AI-Prowler\
;   - Logs include:
;       * Return codes
;       * STDOUT and STDERR capture via temp files
;       * Folder existence checks
;       * Uninstaller presence checks
;       * Final uninstall summary
;
; UNINSTALL BEHAVIOR:
;   - Attempts to run Python and Ollama uninstallers if present
;   - Attempts to delete Python, Ollama, and Ollama data folders
;   - Prompts user whether to delete the RAG database folder
;
; FILE ORGANIZATION:
;   - All source files (RAG_RUN.bat, requirements.txt, python installer)
;     must reside in the same directory as this .iss file at compile time.
;
; NOTES:
;   - Installer requires admin privileges
;   - Installer is fully self-contained and does not require internet
;     except for optional Ollama model pulls
; ============================================================

[Setup]
AppName=AI-Prowler
AppVersion=3.0.0
DefaultDirName={autopf}\AI-Prowler
DefaultGroupName=AI-Prowler
OutputBaseFilename=AI-Prowler_INSTALL
Compression=lzma
SolidCompression=yes
DisableDirPage=yes
DisableProgramGroupPage=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\rag_icon.ico
LicenseFile=AI-Prowler Setup License.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; --- Application files ---
Source: "rag_gui.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "rag_preprocessor.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "RAG_RUN.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "requirements.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "create_shortcut.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "rag_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "COMPLETE_USER_GUIDE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
; --- Full Python installer bundled into {app} so Exec() can find it ---
Source: "python-3.11.8-amd64.exe"; DestDir: "{app}"; Flags: ignoreversion
; NOTE: Ollama is downloaded from the internet at install time, not bundled here

[Icons]
Name: "{commonprograms}\AI-Prowler"; Filename: "{app}\RAG_RUN.bat"; IconFilename: "{app}\rag_icon.ico"
Name: "{commondesktop}\AI-Prowler"; Filename: "{app}\RAG_RUN.bat"; IconFilename: "{app}\rag_icon.ico"

[Run]
Filename: "{app}\RAG_RUN.bat"; Description: "Run AI-Prowler"; Flags: postinstall nowait shellexec skipifsilent

[Code]

// Win32 imports — used to bring the installer window to the foreground.
//
// SetForegroundWindow() alone does NOT work for UAC-elevated processes —
// Windows deliberately blocks it.  The reliable workaround is the
// 'flash topmost' technique:
//   1. SetWindowPos(..., HWND_TOPMOST, ...)   → always-on-top (allowed)
//   2. SetWindowPos(..., HWND_NOTOPMOST, ...) → remove always-on-top
// The window ends up in front without being permanently pinned.
//
// The licence page needs special treatment: Inno Setup's RichEdit control
// inside the licence page grabs focus AFTER CurPageChanged fires, pushing
// the window back down.  We handle this by calling BringToFront twice for
// wpLicense — once immediately, and once via a tiny Sleep to let the
// RichEdit finish initialising before we re-assert the foreground.
function SetWindowPos(hWnd: HWND; hWndInsertAfter: HWND;
                      X, Y, cx, cy: Integer; uFlags: UINT): BOOL;
  external 'SetWindowPos@user32.dll stdcall';

// SendMessageTimeoutA — used to broadcast WM_SETTINGCHANGE to all top-level
// windows (including Explorer) so they pick up new HKCU environment variables
// immediately without requiring a reboot or re-login.
// Without this broadcast, Explorer keeps its login-time environment copy and
// any process it launches (including AI-Prowler via the desktop shortcut) will
// not see env vars written to HKCU\Environment during the install session.
// Note: return type is DWORD rather than LRESULT — Inno Setup Pascal does not
// have LRESULT as a built-in type. DWORD is the correct size on Win32 and we
// do not use the return value here, so this is a safe substitution.
function SendMessageTimeoutA(hWnd: HWND; Msg: UINT; wParam: Integer;
  lParam: AnsiString; fuFlags: UINT; uTimeout: UINT;
  out lpdwResult: DWORD): DWORD;
  external 'SendMessageTimeoutA@user32.dll stdcall';

const
  HWND_TOPMOST    = -1;
  HWND_NOTOPMOST  = -2;
  // HWND_BROADCAST ($FFFF) is a built-in constant in Inno Setup 6.7+
  // — defining it here causes a 'Duplicate identifier' compile error.
  SWP_NOMOVE      = $0002;
  SWP_NOSIZE      = $0001;
  SWP_SHOWWINDOW  = $0040;
  WM_SETTINGCHANGE = $001A;
  SMTO_ABORTIFHUNG = $0002;

procedure BringToFront(hWnd: HWND);
begin
  // Step 1 — set TOPMOST (permitted without the foreground lock)
  SetWindowPos(hWnd, HWND_TOPMOST,   0, 0, 0, 0,
               SWP_NOMOVE or SWP_NOSIZE or SWP_SHOWWINDOW);
  // Step 2 — immediately clear TOPMOST so it isn't permanently on top
  SetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0,
               SWP_NOMOVE or SWP_NOSIZE or SWP_SHOWWINDOW);
end;

const
  LOG_FOLDER      = '{%LOCALAPPDATA}\Temp\AI-Prowler';
  INSTALL_LOG     = '{%LOCALAPPDATA}\Temp\AI-Prowler\install_log.txt';
  UNINSTALL_LOG   = '{%LOCALAPPDATA}\Temp\AI-Prowler\uninstall_log.txt';

  PY_FOLDER       = '{%LOCALAPPDATA}\Programs\Python\Python311';
  // NOTE: Python's real uninstaller is found via registry at runtime,
  // not at a hardcoded path. See GetPythonUninstallString() below.

  OLLAMA_FOLDER      = '{%LOCALAPPDATA}\Programs\Ollama';
  OLLAMA_UNINSTALLER = '{%LOCALAPPDATA}\Programs\Ollama\unins000.exe';

  // Tesseract installed per-user alongside Ollama and Python  -  no UAC needed.
  TESSERACT_FOLDER   = '{%LOCALAPPDATA}\Programs\Tesseract-OCR';

  OLLAMA_DATA_FOLDER = '{%USERPROFILE}\.ollama';
  RAG_DB_FOLDER      = '{%USERPROFILE}\AI-Prowler\rag_database';

  OLLAMA_URL     = 'https://ollama.com/download/OllamaSetup.exe';
  TESSERACT_URL  = 'https://github.com/UB-Mannheim/tesseract/releases/download/v5.4.0.20240606/tesseract-ocr-w64-setup-5.4.0.20240606.exe';


// ============================================================
// HELPER: BoolToStr
// Inno Setup's Pascal does not have a built-in BoolToStr.
// Used in diagnostic log lines to print YES/NO for file/folder checks.
// ============================================================
function BoolToStr(B: Boolean): String;
begin
  if B then Result := 'YES' else Result := 'NO';
end;

// ============================================================
// FIXED FUNCTION: MakeTempFile (correct line continuation)
// ============================================================
function MakeTempFile(const Prefix: String): String;
begin
  Result := ExpandConstant(LOG_FOLDER) + '\\' + Prefix + '_' +
            IntToStr(Random($7FFFFFFF)) + '.log';
end;

procedure EnsureLogFolder;
var
  Folder: String;
begin
  Folder := ExpandConstant(LOG_FOLDER);
  if not DirExists(Folder) then
    ForceDirectories(Folder);
end;

procedure AppendLog(IsInstall: Boolean; const Line: String);
var
  FileName: String;
  FullLine: String;
begin
  EnsureLogFolder;
  if IsInstall then
    FileName := ExpandConstant(INSTALL_LOG)
  else
    FileName := ExpandConstant(UNINSTALL_LOG);

  FullLine := Line + #13#10;
  SaveStringToFile(FileName, FullLine, True);
end;

procedure AppendInstallLog(const Line: String);
begin
  AppendLog(True, Line);
end;

procedure AppendUninstallLog(const Line: String);
begin
  AppendLog(False, Line);
end;

function ReadFileIfExists(const FileName: String): String;
var
  S: AnsiString;
begin
  Result := '';
  if FileExists(FileName) then
    if LoadStringFromFile(FileName, S) then
      Result := S;
end;

procedure DeleteFileIfExists(const FileName: String);
begin
  if FileExists(FileName) then
    DeleteFile(FileName);
end;

procedure ExecWithLogging(IsInstall: Boolean; const Tag, Command, Params: String);
var
  ResultCode: Integer;
  StdOutFile, StdErrFile, CmdLine, StdOutText, StdErrText: String;
begin
  EnsureLogFolder;

  StdOutFile := MakeTempFile('stdout');
  StdErrFile := MakeTempFile('stderr');

  // Double-outer-quote syntax: cmd /C ""path with spaces\prog.exe" args"
  // This is required when the executable path contains spaces (e.g. Program Files)
  CmdLine := '/C ""' + Command + '" ' + Params + ' >"' + StdOutFile + '" 2>"' + StdErrFile + '""';

  if IsInstall then
    AppendInstallLog(Tag + ' Exec: cmd.exe ' + CmdLine)
  else
    AppendUninstallLog(Tag + ' Exec: cmd.exe ' + CmdLine);

  if Exec(ExpandConstant('{cmd}'), CmdLine, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if IsInstall then
    begin
      AppendInstallLog(Tag + ' Return code: ' + IntToStr(ResultCode));
      if ResultCode = 0 then
        AppendInstallLog(Tag + ' Status: SUCCESS')
      else
        AppendInstallLog(Tag + ' Status: FAILURE');
    end
    else
    begin
      AppendUninstallLog(Tag + ' Return code: ' + IntToStr(ResultCode));
      if ResultCode = 0 then
        AppendUninstallLog(Tag + ' Status: SUCCESS')
      else
        AppendUninstallLog(Tag + ' Status: FAILURE');
    end;
  end
  else
  begin
    if IsInstall then
      AppendInstallLog(Tag + ' Exec failed to start.')
    else
      AppendUninstallLog(Tag + ' Exec failed to start.');
  end;

  StdOutText := ReadFileIfExists(StdOutFile);
  StdErrText := ReadFileIfExists(StdErrFile);

  if StdOutText <> '' then
  begin
    if IsInstall then
      AppendInstallLog(Tag + ' STDOUT: ' + StdOutText)
    else
      AppendUninstallLog(Tag + ' STDOUT: ' + StdOutText);
  end;

  if StdErrText <> '' then
  begin
    if IsInstall then
      AppendInstallLog(Tag + ' STDERR: ' + StdErrText)
    else
      AppendUninstallLog(Tag + ' STDERR: ' + StdErrText);
  end;

  DeleteFileIfExists(StdOutFile);
  DeleteFileIfExists(StdErrFile);
end;

procedure LogPythonState;
var
  Folder, RegStr: String;
begin
  Folder := ExpandConstant(PY_FOLDER);

  if DirExists(Folder) then
    AppendUninstallLog('[Python] Program folder exists: ' + Folder)
  else
    AppendUninstallLog('[Python] Program folder NOT found: ' + Folder);

  // Python uninstaller is in registry, not a file on disk
  if RegQueryStringValue(HKCU,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)',
    'UninstallString', RegStr) then
    AppendUninstallLog('[Python] Registry uninstall entry FOUND: ' + RegStr)
  else
    AppendUninstallLog('[Python] Registry uninstall entry NOT found (already removed or never installed).');
end;

procedure LogOllamaState;
var
  Folder, Uninstaller: String;
begin
  Folder := ExpandConstant(OLLAMA_FOLDER);
  Uninstaller := ExpandConstant(OLLAMA_UNINSTALLER);

  if DirExists(Folder) then
    AppendUninstallLog('[Ollama] Program folder exists: ' + Folder)
  else
    AppendUninstallLog('[Ollama] Program folder NOT found: ' + Folder);

  if FileExists(Uninstaller) then
    AppendUninstallLog('[Ollama] Uninstaller FOUND: ' + Uninstaller)
  else
    AppendUninstallLog('[Ollama] Uninstaller NOT found: ' + Uninstaller);
end;


procedure EnsurePythonRegistryEntry;
// Python's MSI background process sometimes completes file extraction but
// fails to write the HKCU uninstall registry entry before our 180s wait
// expires. This procedure checks for the entry and writes it manually if
// missing, so uninstall can always find and run the Python uninstaller.
// The bundled installer in {app} supports /uninstall to remove Python cleanly.
var
  RegKey, ExistingVal: String;
begin
  RegKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)';

  if RegQueryStringValue(HKCU, RegKey, 'UninstallString', ExistingVal) then
  begin
    AppendInstallLog('[Python] Registry uninstall entry already present: ' + ExistingVal);
    Exit;
  end;

  // Entry missing  -  write it manually using the bundled installer path
  AppendInstallLog('[Python] Registry uninstall entry missing  -  writing manually...');
  RegWriteStringValue(HKCU, RegKey, 'DisplayName',     'Python 3.11.8 (64-bit)');
  RegWriteStringValue(HKCU, RegKey, 'DisplayVersion',  '3.11.8');
  RegWriteStringValue(HKCU, RegKey, 'Publisher',       'Python Software Foundation');
  RegWriteStringValue(HKCU, RegKey, 'InstallLocation', ExpandConstant('{%LOCALAPPDATA}\Programs\Python\Python311'));
  // Store bare path ONLY  -  no surrounding quotes, no /uninstall flag.
  // ExecWithLogging wraps the Command in its own double-quote syntax and
  // passes /uninstall /quiet as Params. Pre-baking them here causes
  // triple-quoting which breaks cmd.exe parsing entirely.
  RegWriteStringValue(HKCU, RegKey, 'UninstallString',
    ExpandConstant('{app}') + '\python-3.11.8-amd64.exe');
  RegWriteStringValue(HKCU, RegKey, 'NoModify', '1');
  RegWriteStringValue(HKCU, RegKey, 'NoRepair',  '1');
  AppendInstallLog('[Python] Registry uninstall entry written successfully.');
end;

procedure InitializeWizard;
begin
  // Bring the first installer page to the front using the flash-topmost
  // technique (SetForegroundWindow is blocked for UAC-elevated processes).
  BringToFront(WizardForm.Handle);

  EnsureLogFolder;
  // Delete old log so each install run starts fresh (not appended)
  DeleteFileIfExists(ExpandConstant(INSTALL_LOG));
  AppendInstallLog('=== INSTALL START ===');
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  // Bring every page to the front using the flash-topmost technique.
  BringToFront(WizardForm.Handle);

  // Extra handling for the licence/EULA page: Inno Setup's RichEdit
  // control grabs focus AFTER this event fires, which pushes the window
  // back behind.  A short Sleep lets the RichEdit finish initialising
  // so the second BringToFront call wins the focus race.
  if CurPageID = wpLicense then
  begin
    Sleep(150);
    BringToFront(WizardForm.Handle);
  end;
end;

procedure ExecPython(const Tag, PyFolder, Args: String);
// Writes a temporary .cmd file and executes it instead of building an inline
// cmd /C "..." string. This completely eliminates cmd.exe quoting issues that
// arise when combining PYTHONHOME=, quoted exe paths, args, and >redirects
// in a single command line. The .cmd file has no quoting constraints.
var
  ResultCode: Integer;
  CmdFile, StdOutFile, StdErrFile, StdOutText, StdErrText: String;
  CmdContents: String;
begin
  EnsureLogFolder;
  CmdFile    := MakeTempFile('pycmd');
  // Rename extension from .log to .cmd
  CmdFile    := Copy(CmdFile, 1, Length(CmdFile) - 4) + '.cmd';
  StdOutFile := MakeTempFile('stdout');
  StdErrFile := MakeTempFile('stderr');

  // Write a clean batch file - no inline quoting issues
  CmdContents :=
    '@echo off' + #13#10 +
    'set PYTHONHOME=' + PyFolder + #13#10 +
    'set PYTHONPATH=' + #13#10 +
    // PYTHONNOUSERSITE=1: prevents Python from adding Roaming site-packages
    // to sys.path. Without this, old package versions in Roaming show as
    // "already satisfied" and pip skips reinstalling our pinned versions.
    'set PYTHONNOUSERSITE=1' + #13#10 +
    // HF_HUB_CACHE: huggingface_hub reads this at module-import time.
    // Setting it here ensures any pip step that triggers an HF import
    // uses a clean path — no trailing backslash, no Errno 22.
    'set HF_HUB_CACHE=%USERPROFILE%\.cache\huggingface\hub' + #13#10 +
    '"' + PyFolder + '\python.exe" ' + Args +
    ' >"' + StdOutFile + '" 2>"' + StdErrFile + '"' + #13#10;

  SaveStringToFile(CmdFile, CmdContents, False);
  AppendInstallLog(Tag + ' Exec batch: ' + CmdFile);
  AppendInstallLog(Tag + ' Contents: ' + CmdContents);

  if Exec(ExpandConstant('{cmd}'), '/C "' + CmdFile + '"',
      PyFolder, SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    AppendInstallLog(Tag + ' Return code: ' + IntToStr(ResultCode));
    if ResultCode = 0 then
      AppendInstallLog(Tag + ' Status: SUCCESS')
    else
      AppendInstallLog(Tag + ' Status: FAILURE');
  end
  else
    AppendInstallLog(Tag + ' Exec failed to start.');

  StdOutText := ReadFileIfExists(StdOutFile);
  StdErrText := ReadFileIfExists(StdErrFile);

  if StdOutText <> '' then
    AppendInstallLog(Tag + ' STDOUT: ' + StdOutText);
  if StdErrText <> '' then
    AppendInstallLog(Tag + ' STDERR: ' + StdErrText);

  DeleteFileIfExists(CmdFile);
  DeleteFileIfExists(StdOutFile);
  DeleteFileIfExists(StdErrFile);
end;

procedure SetProgress(Pct: Integer; const Msg: String);
// Manually drives the wizard progress bar and both status labels.
// FilenameLabel is the large prominent label (normally shows current file being copied).
// StatusLabel is the smaller label below it.
// Both are updated so the user always has a clear visual cue of what is happening.
begin
  WizardForm.ProgressGauge.Position :=
    WizardForm.ProgressGauge.Min +
    (WizardForm.ProgressGauge.Max - WizardForm.ProgressGauge.Min) * Pct div 100;
  WizardForm.FilenameLabel.Caption := 'Step: ' + Msg;
  WizardForm.StatusLabel.Caption   := IntToStr(Pct) + '% complete';
  AppendInstallLog('[Progress ' + IntToStr(Pct) + '%] ' + Msg);
end;

procedure WaitForFolderCreation(const Folder: String; const Tag: String; MaxWaitMs: Integer);
// Polls until the folder appears or timeout is reached.
// Used after launching a task-scheduler job to know when NSIS has finished.
var
  Elapsed: Integer;
begin
  Elapsed := 0;
  while not DirExists(Folder) and (Elapsed < MaxWaitMs) do
  begin
    Sleep(500);
    Elapsed := Elapsed + 500;
  end;
  if DirExists(Folder) then
    AppendInstallLog(Tag + ' Folder confirmed created after ~' + IntToStr(Elapsed) + 'ms.')
  else
    AppendInstallLog(Tag + ' Folder NOT found after ' + IntToStr(MaxWaitMs) + 'ms wait: ' + Folder);
end;


procedure CurStepChanged(CurStep: TSetupStep);
var
  PyFolder, OllamaFolder, OllamaSetup, ModelPath, TessSetup, TessFolder, TessTask, TessBat, RoamingPython: String;
  CfgFile: String;
  Elapsed, WaitSeconds, TessElapsed, TessResultCode: Integer;
  MsgDummy: DWORD;
  PythonReady: Boolean;
begin
  if CurStep = ssPostInstall then
  begin
    // ----------------------------------------------------------
    // PYTHON INSTALL  (progress 10 -> 30)
    // ----------------------------------------------------------
    // IMPORTANT: Assign PyFolder before the install block so the pre-install
    // cleanup check can use it.
    PyFolder := ExpandConstant(PY_FOLDER);

    // ---- PRE-INSTALL STATE CHECK ----
    // If python.exe already exists and the install is complete, skip the
    // installer entirely - no need to reinstall.
    // If the Python folder exists but python.exe is MISSING, a previous install
    // attempt left a broken partial state on disk. The Windows MSI engine sees
    // its own cached database entry, returns exit code 0 instantly without
    // writing any new files, and our wait loop then spins for the full timeout
    // finding nothing. Fix: delete the broken folder so the MSI is forced to
    // perform a genuine fresh installation.
    if FileExists(PyFolder + '\python.exe') and
       FileExists(PyFolder + '\python311.dll') and
       DirExists(PyFolder + '\Lib\encodings') then
    begin
      AppendInstallLog('[Python] Already fully installed at: ' + PyFolder);
      AppendInstallLog('[Python] Skipping installer, proceeding directly to pip steps.');
      EnsurePythonRegistryEntry;
    end
    else
    begin
      if DirExists(PyFolder) then
      begin
        AppendInstallLog('[Python] WARNING: Broken partial install detected at: ' + PyFolder);
        AppendInstallLog('[Python] python.exe present:      ' + BoolToStr(FileExists(PyFolder + '\python.exe')));
        AppendInstallLog('[Python] python311.dll present:   ' + BoolToStr(FileExists(PyFolder + '\python311.dll')));
        AppendInstallLog('[Python] Lib\encodings present:   ' + BoolToStr(DirExists(PyFolder + '\Lib\encodings')));
        AppendInstallLog('[Python] Deleting broken folder to force a clean MSI install...');
        if DelTree(PyFolder, True, True, True) then
          AppendInstallLog('[Python] Broken folder deleted successfully.')
        else
          AppendInstallLog('[Python] WARNING: Could not fully delete broken folder - install may still fail.');
        // Also remove the stale registry uninstall key that made the MSI think
        // Python was already present and return 0 without writing any files.
        if RegKeyExists(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)') then
        begin
          RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)');
          AppendInstallLog('[Python] Stale registry uninstall key removed from HKCU.');
        end;
      end
      else
        AppendInstallLog('[Python] No existing Python folder found - fresh install.');

      SetProgress(10, 'Installing Python 3.11.8...');
      ExecWithLogging(True, '[Python]',
        ExpandConstant('{app}\python-3.11.8-amd64.exe'),
        '/quiet InstallAllUsers=0 PrependPath=1 Include_pip=1');

    // Poll up to 600s for Python to be fully ready - not just folder present.
    // The MSI background process continues writing Lib\ files after returning.
    // We verify Python can actually execute by checking for python311.dll and
    // the encodings module directory which is the first thing Python loads.
    // 600s (10 min) is required for slow HDDs on older machines — the previous
    // 180s limit caused all pip steps to fail with 'Exec failed to start'
    // because python.exe had not yet appeared on disk when they ran.
    AppendInstallLog('[Python] Waiting for Python installation to fully complete (up to 600s)...');
    PythonReady := False;
    WaitSeconds := 0;
    while (WaitSeconds < 600) and not PythonReady do
    begin
      if DirExists(PyFolder) and
         FileExists(PyFolder + '\python.exe') and
         FileExists(PyFolder + '\python311.dll') and
         DirExists(PyFolder + '\Lib\encodings') then
      begin
        PythonReady := True;
        AppendInstallLog('[Python] Ready after ' + IntToStr(WaitSeconds) + 's - all required files present.');
      end
      else
      begin
        Sleep(1000);
        WaitSeconds := WaitSeconds + 1;
        // Cap progress at 29% so this bar segment never overflows into the
        // pip/requirements segment regardless of how long the wait takes.
        if (10 + (WaitSeconds div 3)) < 29 then
          SetProgress(10 + (WaitSeconds div 3), 'Waiting for Python to finish installing... (' + IntToStr(WaitSeconds) + 's)')
        else
          SetProgress(29, 'Waiting for Python to finish installing... (' + IntToStr(WaitSeconds) + 's)');
      end;
    end;

    if not PythonReady then
    begin
      // Log exactly which files are present/missing to make the next
      // troubleshooting step obvious from the log alone.
      AppendInstallLog('[Python] TIMEOUT - Python not ready after 600s. Diagnosing...');
      AppendInstallLog('[Python]   Folder exists:          ' + BoolToStr(DirExists(PyFolder)));
      AppendInstallLog('[Python]   python.exe present:     ' + BoolToStr(FileExists(PyFolder + '\python.exe')));
      AppendInstallLog('[Python]   python311.dll present:  ' + BoolToStr(FileExists(PyFolder + '\python311.dll')));
      AppendInstallLog('[Python]   Lib\encodings present:  ' + BoolToStr(DirExists(PyFolder + '\Lib\encodings')));
      SetProgress(30, 'Python install timed out after 600s - pip steps may fail.');
    end
    else
    begin
      // Extra 2s buffer for DLL registration to complete after files appear
      Sleep(2000);
      // Ensure the registry uninstall entry exists for clean uninstall
      EnsurePythonRegistryEntry;
    end;
    end; // end install-branch (else block from pre-install check)

    // ----------------------------------------------------------
    // PIP UPGRADE  (progress 30 -> 45)
    // Guard: skip all pip steps if python.exe is still missing after the
    // wait loop. Without this guard every ExecPython call silently reports
    // 'Exec failed to start' with no explanation, which is hard to diagnose.
    // This guard also covers torch and torchvision below.
    // ----------------------------------------------------------
    if not FileExists(PyFolder + '\python.exe') then
    begin
      AppendInstallLog('[Python] python.exe NOT FOUND at: ' + PyFolder + '\python.exe');
      AppendInstallLog('[Python] Skipping pip upgrade, requirements, torch, and torchvision steps.');
      AppendInstallLog('[Python] ACTION REQUIRED: Re-run the installer. The broken Python folder');
      AppendInstallLog('[Python] will be cleaned up automatically on the next install attempt.');
      SetProgress(75, 'Python missing - pip steps skipped. Re-run installer to fix.');
    end
    else
    begin
      SetProgress(30, 'Upgrading pip...');
      ExecPython('[Python] Pip upgrade', PyFolder, '-m pip install --upgrade pip');

      // ----------------------------------------------------------
      // ROAMING PYTHON PACKAGES CLEANUP
      // Old package versions (e.g. huggingface-hub) installed by previous
      // AI-Prowler versions accumulate in %APPDATA%\Roaming\Python\Python311\
      // and survive a full Python uninstall + reinstall because the uninstaller
      // only removes the Local Python folder. Python searches Roaming BEFORE
      // Local in sys.path when PYTHONNOUSERSITE is not set - and even though
      // we set PYTHONNOUSERSITE=1 in the registry and broadcast WM_SETTINGCHANGE,
      // Explorer may not have processed the broadcast before the user first
      // launches the app. Old Roaming packages then override our freshly
      // installed pinned versions, causing the Errno 22 double-backslash bug
      // to reappear on the very first run after a clean reinstall.
      // Deleting the Roaming Python 3.11 folder here removes all stale packages
      // before we install the correct pinned versions to Local site-packages.
      // ----------------------------------------------------------
      RoamingPython := GetEnv('APPDATA') + '\Python\Python311';
      if DirExists(RoamingPython) then
      begin
        AppendInstallLog('[Roaming] Removing stale Roaming Python packages: ' + RoamingPython);
        if DelTree(RoamingPython, True, True, True) then
          AppendInstallLog('[Roaming] Roaming Python packages removed successfully.')
        else
          AppendInstallLog('[Roaming] WARNING: Could not fully remove Roaming Python packages.');
      end
      else
        AppendInstallLog('[Roaming] No Roaming Python packages found - nothing to clean.');

      // ----------------------------------------------------------
      // HUGGINGFACE CACHE CLEANUP  (before requirements install)
      // A corrupted or incompatible cached model from a previous install
      // causes Errno 22 Invalid argument on Windows — huggingface_hub
      // returns a path with a trailing backslash and sentence-transformers
      // appends another one, producing a double-backslash path that Windows
      // rejects. Deleting the cached model here forces a clean re-download
      // using the pinned package versions in requirements.txt.
      // Only the sentence-transformers model subfolder is deleted — the rest
      // of the HuggingFace cache (e.g. other models) is left untouched.
      // ----------------------------------------------------------
      ModelPath := ExpandConstant('{%USERPROFILE}') +
        '\.cache\huggingface\hub\models--sentence-transformers--all-MiniLM-L6-v2';
      if DirExists(ModelPath) then
      begin
        AppendInstallLog('[Cache] Deleting stale HuggingFace model cache: ' + ModelPath);
        if DelTree(ModelPath, True, True, True) then
          AppendInstallLog('[Cache] HuggingFace model cache deleted - will re-download clean copy.')
        else
          AppendInstallLog('[Cache] WARNING: Could not fully delete HuggingFace cache - Errno 22 may persist.');
      end
      else
        AppendInstallLog('[Cache] No stale HuggingFace model cache found - nothing to clean.');

      // ----------------------------------------------------------
      // SET HF_HUB_CACHE USER ENVIRONMENT VARIABLE
      // On some Windows configurations huggingface-hub derives the cache path
      // via string operations that leave a trailing backslash on the snapshot
      // directory. sentence-transformers then appends a filename using
      // os.path.join, producing "...\<hash>\\filename" — the double backslash
      // that Windows rejects with Errno 22 Invalid argument.
      // Setting HF_HUB_CACHE bypasses that code path entirely: huggingface-hub
      // reads the env var directly and uses it as-is, with no home-dir
      // expansion or string concatenation that could introduce a trailing slash.
      // Stored as REG_EXPAND_SZ so %USERPROFILE% expands correctly at runtime.
      // ----------------------------------------------------------
      RegWriteExpandStringValue(HKCU, 'Environment', 'HF_HUB_CACHE',
        '%USERPROFILE%\.cache\huggingface\hub');
      AppendInstallLog('[Cache] Set HF_HUB_CACHE env var -> %USERPROFILE%\.cache\huggingface\hub');

      // ----------------------------------------------------------
      // SET PYTHONNOUSERSITE USER ENVIRONMENT VARIABLE
      // This machine has packages in BOTH Local and Roaming site-packages.
      // Python searches both and Roaming (old pre-existing versions) can
      // silently override the pinned versions we just installed.
      // PYTHONNOUSERSITE=1 tells Python to ignore Roaming site-packages.
      // ----------------------------------------------------------
      RegWriteStringValue(HKCU, 'Environment', 'PYTHONNOUSERSITE', '1');
      AppendInstallLog('[Env] Set PYTHONNOUSERSITE=1 to prevent Roaming site-packages interference.');

      // ----------------------------------------------------------
      // BROADCAST WM_SETTINGCHANGE  (critical - do this after ALL env writes)
      // Env vars written to HKCU\Environment are only picked up by running
      // processes if they receive WM_SETTINGCHANGE. Without this, Explorer
      // keeps its login-time env copy and AI-Prowler launched from the desktop
      // shortcut won't see HF_HUB_CACHE or PYTHONNOUSERSITE until reboot.
      // Inno Setup only auto-broadcasts this for its own PATH changes - NOT
      // for arbitrary env var writes like ours.
      // ----------------------------------------------------------
      SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
        'Environment', SMTO_ABORTIFHUNG, 5000, MsgDummy);
      AppendInstallLog('[Env] Broadcast WM_SETTINGCHANGE - running processes will now see new env vars.');

      // ----------------------------------------------------------
      // REQUIREMENTS  (progress 45 -> 65)
      // ----------------------------------------------------------
      SetProgress(45, 'Installing Python dependencies...');
      ExecPython('[Python] Requirements', PyFolder,
        '-m pip install -r "' + ExpandConstant('{app}\requirements.txt') + '"');

      // ----------------------------------------------------------
      // PYTORCH  (progress 65 -> 75)
      // Detect NVIDIA GPU via registry  -  install CUDA build if found,
      // CPU-only build otherwise. This keeps the install lean on machines
      // without a GPU while still giving CUDA acceleration where available.
      // ----------------------------------------------------------
      if RegKeyExists(HKLM, 'SOFTWARE\NVIDIA Corporation\Global') or
         RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\nvlddmkm') then
      begin
        AppendInstallLog('[Torch] NVIDIA GPU detected - installing CUDA 12.8 build (cu128)...');
        SetProgress(65, 'NVIDIA GPU detected - installing PyTorch (CUDA 12.8)...');
        ExecPython('[Python] Torch', PyFolder,
          '-m pip install torch --index-url https://download.pytorch.org/whl/cu128 --force-reinstall --no-deps');
        // pytesseract pulls torchvision in via sentence-transformers deps.
        // That PyPI build is compiled against a different torch version and
        // causes 'Entry Point Not Found' (torchvision\_C.pyd) on launch.
        // Force-reinstall from the same CUDA 12.8 index so both match.
        // cu128 also provides full Blackwell (RTX 50xx) kernel support.
        AppendInstallLog('[Torch] Reinstalling torchvision from CUDA 12.8 index to match torch...');
        SetProgress(70, 'Reinstalling torchvision to match CUDA 12.8 PyTorch...');
        ExecPython('[Python] Torchvision', PyFolder,
          '-m pip install torchvision --index-url https://download.pytorch.org/whl/cu128 --force-reinstall --no-deps');
      end
      else
      begin
        AppendInstallLog('[Torch] No NVIDIA GPU detected - installing CPU build...');
        SetProgress(65, 'No GPU detected - installing PyTorch (CPU)...');
        ExecPython('[Python] Torch', PyFolder,
          '-m pip install torch');
        // Reinstall torchvision to ensure it matches the CPU torch version.
        AppendInstallLog('[Torch] Reinstalling torchvision to match CPU torch...');
        SetProgress(70, 'Reinstalling torchvision to match CPU PyTorch...');
        ExecPython('[Python] Torchvision', PyFolder,
          '-m pip install torchvision --force-reinstall --no-deps');
      end;
    end; // end python.exe guard (pip + requirements + torch + torchvision)

    // ----------------------------------------------------------
    // TESSERACT OCR  (progress 55 -> 65)
    // Download and silently install UB-Mannheim Tesseract 5.x.
    // Required for OCR of scanned PDFs and image files.
    // Skipped if already installed (registry key check).
    // ----------------------------------------------------------
    if not RegKeyExists(HKCU, 'SOFTWARE\Tesseract-OCR') and
       not RegKeyExists(HKLM, 'SOFTWARE\Tesseract-OCR') and
       not RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Tesseract-OCR') then
    begin
      SetProgress(55, 'Downloading Tesseract OCR...');
      AppendInstallLog('[Tesseract] Not found  -  downloading installer...');
      TessSetup := ExpandConstant('{tmp}\tesseract-setup.exe');

      Exec('powershell.exe',
        '-NoProfile -Command "' +
          '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ' +
          '$wc = New-Object System.Net.WebClient; ' +
          '$task = $wc.DownloadFileTaskAsync(''' + TESSERACT_URL + ''', ''' + TessSetup + '''); ' +
          'while (-not $task.IsCompleted) { Start-Sleep -Milliseconds 300 }; ' +
          'Write-Host ''Tesseract download complete.''"'  ,
        '', SW_HIDE, ewWaitUntilTerminated, TessElapsed);
      AppendInstallLog('[Tesseract] Download exit code: ' + IntToStr(TessElapsed));

      if FileExists(TessSetup) then
      begin
        SetProgress(60, 'Installing Tesseract OCR...');
        AppendInstallLog('[Tesseract] Running installer silently...');
        // NSIS silent install flags:
        //   /S       = fully silent  -  suppresses ALL pages including license
        //              and install location dialogs
        //   /D=path  = destination directory  -  MUST be the last argument
        //              and MUST NOT be quoted (NSIS requirement)
        // The old Inno flags (/VERYSILENT /NORESTART /SP- /COMPONENTS) were
        // silently ignored by NSIS, which is why both the license agreement
        // and 'Choose Install Location' dialogs appeared and the install
        // fell back to C:\Program Files.
        // ROOT CAUSE FIX: Do NOT use Exec/ExecWithLogging here.
        // This installer runs elevated (PrivilegesRequired=admin).  NSIS
        // detects an elevated parent and silently ignores /D= paths pointing
        // into C:\Users\..., falling back to C:\Program Files every time.
        // Solution: use Task Scheduler to launch the NSIS installer under the
        // original non-elevated user token.  Without /RL HIGHEST the task runs
        // at the user's normal privilege level, so NSIS respects /D=.
        TessFolder := ExpandConstant(TESSERACT_FOLDER);
        TessTask   := 'AI-Prowler-TesseractInstall';
        TessBat    := ExpandConstant('{tmp}') + '\tess_install.bat';

        // Write a batch file that sets __COMPAT_LAYER=RunAsInvoker before
        // launching the NSIS installer.  This shim tells Windows to ignore
        // the manifest's RequestExecutionLevel=admin declaration and run the
        // process at the current (non-elevated) token -- no UAC prompt, and
        // NSIS sees a non-elevated parent so it honours /D= and installs to
        // LocalAppData instead of C:\Program Files.
        SaveStringToFile(TessBat,
          '@echo off' + #13#10 +
          'set __COMPAT_LAYER=RunAsInvoker' + #13#10 +
          'start /wait "" "' + TessSetup + '" /S /D=' + TessFolder + #13#10,
          False);
        AppendInstallLog('[Tesseract] Wrote RunAsInvoker batch: ' + TessBat);

        // Register a one-shot scheduled task to run the batch as the current
        // user WITHOUT /RL HIGHEST  ->  non-elevated token.
        Exec(ExpandConstant('{sys}\schtasks.exe'),
          '/Create /F /RU "' + GetEnv('USERNAME') + '"' +
          ' /SC ONCE /TN "' + TessTask + '"' +
          ' /ST 00:00' +
          ' /TR "cmd /C \"' + TessBat + '\""',
          '', SW_HIDE, ewWaitUntilTerminated, TessResultCode);
        AppendInstallLog('[Tesseract] schtasks /Create exit code: ' + IntToStr(TessResultCode));

        // Trigger immediately
        Exec(ExpandConstant('{sys}\schtasks.exe'),
          '/Run /TN "' + TessTask + '"',
          '', SW_HIDE, ewWaitUntilTerminated, TessResultCode);
        AppendInstallLog('[Tesseract] schtasks /Run exit code: ' + IntToStr(TessResultCode));

        // Poll until the Tesseract folder appears (NSIS has finished extracting)
        WaitForFolderCreation(TessFolder, '[Tesseract]', 120000);

        // Clean up scheduled task and temp batch regardless of outcome.
        Exec(ExpandConstant('{sys}\schtasks.exe'),
          '/Delete /F /TN "' + TessTask + '"',
          '', SW_HIDE, ewWaitUntilTerminated, TessResultCode);
        AppendInstallLog('[Tesseract] schtasks /Delete exit code: ' + IntToStr(TessResultCode));
        DeleteFile(TessBat);

        // Only write PATH and declare success if the folder actually exists.
        // Previously this block ran unconditionally, logging 'Install complete'
        // even when WaitForFolderCreation had already logged 'Folder NOT found'.
        // That false-success caused a non-existent path to be added to the user
        // PATH and masked the real failure from the install log summary.
        if DirExists(TessFolder) then
        begin
          // Add Tesseract to user PATH so pytesseract finds it without
          // a hardcoded path  -  same pattern as Python's own installer.
          RegWriteExpandStringValue(HKCU, 'Environment', 'Path',
            ExpandConstant(TESSERACT_FOLDER) + ';%Path%');
          AppendInstallLog('[Tesseract] Added to user PATH: '
            + ExpandConstant(TESSERACT_FOLDER));
          AppendInstallLog('[Tesseract] Install complete.');
        end
        else
        begin
          AppendInstallLog('[Tesseract] FAILED - folder never appeared after 120s wait.');
          AppendInstallLog('[Tesseract] OCR of scanned PDFs will be unavailable.');
          AppendInstallLog('[Tesseract] To fix: download and install Tesseract manually from:');
          AppendInstallLog('[Tesseract]   ' + TESSERACT_URL);
          SetProgress(62, 'Tesseract install failed - OCR unavailable. See install_log.txt.');
        end;
      end
      else
      begin
        AppendInstallLog('[Tesseract] Download FAILED  -  OCR unavailable.');
        SetProgress(60, 'Tesseract download failed  -  continuing...');
      end;
    end
    else
    begin
      AppendInstallLog('[Tesseract] Already installed  -  skipping.');
      SetProgress(62, 'Tesseract already installed  -  skipping...');
    end;

    // ----------------------------------------------------------
    // OLLAMA DOWNLOAD + INSTALL  (progress 75 -> 90)
    // Always download and run the latest OllamaSetup.exe.
    // Running it on an existing install performs a silent in-place
    // upgrade (models are preserved).  This ensures Blackwell/newer
    // GPU architectures get CUDA support even on reinstall.
    // ----------------------------------------------------------
    SetProgress(75, 'Downloading latest Ollama...');
    OllamaSetup := ExpandConstant('{tmp}\OllamaSetup.exe');
    AppendInstallLog('[Ollama] Downloading from: ' + OLLAMA_URL);

    // Kill any running Ollama before upgrading so the installer
    // can replace its files without a file-in-use error.
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM ollama.exe /T',
      '', SW_HIDE, ewWaitUntilTerminated, Elapsed);
    Sleep(1000);

    Exec('powershell.exe',
      '-NoProfile -Command "' +
        '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ' +
        '$wc = New-Object System.Net.WebClient; ' +
        'Register-ObjectEvent $wc DownloadProgressChanged -Action { ' +
          'Write-Progress -Activity ''Downloading Ollama'' -Status (''$($EventArgs.ProgressPercentage)% - $([math]::Round($EventArgs.BytesReceived/1MB,1)) MB of $([math]::Round($EventArgs.TotalBytesToReceive/1MB,1)) MB'') ' +
          '-PercentComplete $EventArgs.ProgressPercentage } | Out-Null; ' +
        '$task = $wc.DownloadFileTaskAsync(''' + OLLAMA_URL + ''', ''' + OllamaSetup + '''); ' +
        'while (-not $task.IsCompleted) { Start-Sleep -Milliseconds 200 }; ' +
        'Write-Progress -Activity ''Downloading Ollama'' -Completed; ' +
        'Write-Host ''Download complete.''; Start-Sleep 1"',
      '', SW_SHOWNORMAL, ewWaitUntilTerminated, Elapsed);
    AppendInstallLog('[Ollama] Download exit code: ' + IntToStr(Elapsed));

    if not FileExists(OllamaSetup) then
    begin
      AppendInstallLog('[Ollama] Download FAILED - file not found: ' + OllamaSetup);
      SetProgress(90, 'Ollama download failed, skipping...');
    end
    else
    begin
      SetProgress(85, 'Installing / upgrading Ollama...');
      AppendInstallLog('[Ollama] Running installer (install or upgrade): ' + OllamaSetup);
      ExecWithLogging(True, '[Ollama] Installer', OllamaSetup, '/SILENT');

      // OllamaSetup is async - poll up to 30s for folder to appear
      OllamaFolder := ExpandConstant(OLLAMA_FOLDER);
      Elapsed := 0;
      while (not DirExists(OllamaFolder)) and (Elapsed < 30000) do
      begin
        Sleep(500);
        Elapsed := Elapsed + 500;
      end;
      SetProgress(90, 'Ollama ready, pulling llama3.2:1b model...');
    end;

    // ----------------------------------------------------------
    // ----------------------------------------------------------
    // WRITE DEFAULT CONFIG  (first-install only)
    // Write ~/.rag_config.json with auto_start_ollama=true so the
    // GUI starts Ollama automatically on first launch.  We only
    // write this if the file doesn't already exist (preserves any
    // existing user settings on reinstall).
    // ----------------------------------------------------------
    begin
      CfgFile := ExpandConstant('{%USERPROFILE}\.rag_config.json');
      if not FileExists(CfgFile) then
      begin
        SaveStringToFile(CfgFile,
          '{"auto_start_ollama": true}',
          False);
        AppendInstallLog('[Config] Wrote default config: ' + CfgFile);
      end
      else
        AppendInstallLog('[Config] Config already exists, skipping default write: ' + CfgFile);
    end;

    // OLLAMA PULL  (progress 90 -> 99)
    // Only pull if the model is not already present.
    // Model manifests live at: %USERPROFILE%\.ollama\models\manifests\...
    // ----------------------------------------------------------
    OllamaFolder := ExpandConstant(OLLAMA_FOLDER);
    if DirExists(OllamaFolder) then
    begin
      ModelPath := ExpandConstant('{%USERPROFILE}') +
        '\.ollama\models\manifests\registry.ollama.ai\library\llama3.2';

      if DirExists(ModelPath) then
      begin
        AppendInstallLog('[Ollama] llama3.2:1b model already present at: ' + ModelPath + ' - skipping pull.');
        SetProgress(99, 'llama3.2:1b model already present, skipping pull.');
      end
      else
      begin
        // Kill any running Ollama server before pulling.
        // When no server is running, 'ollama pull' (elevated) starts its own
        // elevated server — both sides share the same token so the id_ed25519
        // key check passes, and the original blue Ollama progress window appears.
        AppendInstallLog('[Ollama] Stopping any running Ollama server before pull...');
        Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM ollama.exe /T',
          '', SW_HIDE, ewWaitUntilTerminated, TessResultCode);
        Sleep(2000);

        SetProgress(90, 'Downloading llama3.2:1b AI model (~1.3 GB) — please wait...');
        AppendInstallLog('[Ollama] Pulling llama3.2:1b model...');
        Exec(OllamaFolder + '\ollama.exe', 'pull llama3.2:1b',
          OllamaFolder, SW_SHOWNORMAL, ewWaitUntilTerminated, TessResultCode);
        AppendInstallLog('[Ollama] Pull exit code: ' + IntToStr(TessResultCode));

        if DirExists(ModelPath) then
          AppendInstallLog('[Ollama] llama3.2:1b pulled successfully.')
        else
          AppendInstallLog('[Ollama] Pull failed - model can be downloaded later from the Browse & Install tab.');
      end;
    end
    else
      AppendInstallLog('[Ollama] Folder not found after install attempt, skipping pull.');

  end
  else if CurStep = ssDone then
  begin
    SetProgress(100, 'Installation complete.');
    AppendInstallLog('=== INSTALL FINISHED ===');
  end;
end;

function InitializeUninstall: Boolean;
begin
  EnsureLogFolder;
  // Delete old log so each uninstall run starts fresh (not appended)
  DeleteFileIfExists(ExpandConstant(UNINSTALL_LOG));
  AppendUninstallLog('=== UNINSTALL START ===');
  Result := True;
end;

function SanitizeUninstallPath(const Raw: String): String;
// The UninstallString in the registry may have been written by an older
// installer as:  "C:\path\python.exe" /uninstall
// ExecWithLogging expects a bare path with no surrounding quotes and no
// flags (flags go in Params). This function strips both so the caller
// always gets a clean exe path regardless of how the entry was written.
var
  S: String;
begin
  S := Trim(Raw);
  // Strip leading quote if present
  if (Length(S) > 0) and (S[1] = '"') then
    Delete(S, 1, 1);
  // Strip everything from the closing quote onwards (removes " /uninstall etc.)
  if Pos('"', S) > 0 then
    S := Copy(S, 1, Pos('"', S) - 1);
  // If no quotes were present, strip any trailing flags after a space
  // e.g. "C:\path\python.exe /uninstall" written without outer quotes
  if Pos(' /', S) > 0 then
    S := Copy(S, 1, Pos(' /', S) - 1);
  Result := Trim(S);
end;

function GetPythonUninstallString: String;
// Python does NOT have an uninstall.exe in its folder.
// Its real uninstaller is registered in the Windows registry as:
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)
// Returns a sanitized bare exe path suitable for passing to ExecWithLogging.
var
  UninstallStr: String;
begin
  Result := '';
  // Try current user first (InstallAllUsers=0 registers under HKCU)
  if RegQueryStringValue(HKCU,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)',
    'UninstallString', UninstallStr) then
  begin
    AppendUninstallLog('[Python] Registry uninstall string found (HKCU): ' + UninstallStr);
    Result := SanitizeUninstallPath(UninstallStr);
    AppendUninstallLog('[Python] Sanitized path: ' + Result);
    Exit;
  end;
  // Fall back to HKLM in case it was installed system-wide
  if RegQueryStringValue(HKLM,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)',
    'UninstallString', UninstallStr) then
  begin
    AppendUninstallLog('[Python] Registry uninstall string found (HKLM): ' + UninstallStr);
    Result := SanitizeUninstallPath(UninstallStr);
    AppendUninstallLog('[Python] Sanitized path: ' + Result);
    Exit;
  end;
  AppendUninstallLog('[Python] Registry uninstall string NOT found in HKCU or HKLM.');
end;

procedure WaitForFolderRemoval(const Folder: String; const Tag: String; MaxWaitMs: Integer);
// Polls until the folder is gone or timeout is reached.
// Handles the race condition where uninstallers return before actually finishing.
var
  Elapsed: Integer;
begin
  Elapsed := 0;
  while DirExists(Folder) and (Elapsed < MaxWaitMs) do
  begin
    Sleep(500);
    Elapsed := Elapsed + 500;
  end;
  if DirExists(Folder) then
    AppendUninstallLog(Tag + ' Folder still present after ' + IntToStr(MaxWaitMs) + 'ms wait: ' + Folder)
  else
    AppendUninstallLog(Tag + ' Folder confirmed removed after ~' + IntToStr(Elapsed) + 'ms.');
end;


procedure DeferredDeleteFolder(const Folder: String);
// {app} contains unins000.exe which is Inno Setup's own uninstaller binary.
// Windows holds a handle on this file (and therefore the folder) until the
// uninstaller process fully exits  -  so DelTree always fails synchronously
// even in usPostUninstall. Fix: write a tiny batch file to {tmp} and launch
// it with ewNoWait. By the time it wakes up the uninstaller has fully exited.
var
  BatFile, BatContents: String;
  ResultCode: Integer;
begin
  BatFile := ExpandConstant('{tmp}') + '\prowler_cleanup.bat';
  BatContents :=
    '@echo off' + #13#10 +
    // ping -n 8 gives ~7 second delay without needing timeout.exe
    'ping -n 8 127.0.0.1 > nul' + #13#10 +
    'rd /s /q "' + Folder + '"' + #13#10 +
    'del "%~f0"' + #13#10;
  SaveStringToFile(BatFile, BatContents, False);
  AppendUninstallLog('[App] Spawning deferred cleanup for: ' + Folder);
  Exec(ExpandConstant('{cmd}'), '/C "' + BatFile + '"', '', SW_HIDE, ewNoWait, ResultCode);
  AppendUninstallLog('[App] Deferred cleanup launched (will run after uninstaller exits).');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Folder: String;
  DeleteRagDB: Boolean;
  PyUninstallStr: String;
  TessUninstaller: String;
  CurrentPath: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    LogOllamaState;
    LogPythonState;

    // ----------------------------------------------------------------
    // OLLAMA: Force-kill process first, then stop service, then uninstall
    // Fix: sc stop is best-effort; taskkill /F ensures the process
    // is actually dead before the uninstaller tries to remove locked files.
    // ----------------------------------------------------------------
    AppendUninstallLog('[Ollama] Force-killing ollama.exe process...');
    ExecWithLogging(False, '[Ollama] taskkill', 'taskkill', '/F /IM ollama.exe');
    Sleep(2000); // Wait for process to fully die before stopping service

    ExecWithLogging(False, '[Ollama] sc stop', 'sc', 'stop ollama');
    Sleep(2000); // Give the service time to stop before deleting it
    ExecWithLogging(False, '[Ollama] sc delete', 'sc', 'delete ollama');
    Sleep(1000);

    if FileExists(ExpandConstant(OLLAMA_UNINSTALLER)) then
    begin
      AppendUninstallLog('[Ollama] Running uninstaller...');
      ExecWithLogging(False, '[Ollama] Uninstaller', ExpandConstant(OLLAMA_UNINSTALLER), '/SILENT');
      // Fix: /SILENT uninstallers spawn child processes and return immediately.
      // Poll up to 30 seconds for the folder to actually disappear.
      AppendUninstallLog('[Ollama] Waiting for uninstaller to complete...');
      WaitForFolderRemoval(ExpandConstant(OLLAMA_FOLDER), '[Ollama]', 30000);
    end
    else
      AppendUninstallLog('[Ollama] Uninstaller not found, skipping unins000.exe run.');

    // Force-delete any remnants the uninstaller left behind
    Folder := ExpandConstant(OLLAMA_FOLDER);
    if DirExists(Folder) then
    begin
      AppendUninstallLog('[Ollama] Remnants found, force-deleting: ' + Folder);
      if DelTree(Folder, True, True, True) then
        AppendUninstallLog('[Ollama] DelTree succeeded.')
      else
        AppendUninstallLog('[Ollama] DelTree returned FALSE for: ' + Folder);
    end
    else
      AppendUninstallLog('[Ollama] Folder clean after uninstaller: ' + Folder);

    if DirExists(Folder) then
      AppendUninstallLog('[Ollama] Folder still exists after all delete attempts.')
    else
      AppendUninstallLog('[Ollama] Folder successfully removed.');

    // ----------------------------------------------------------------
    // PYTHON: Force-kill processes, then uninstall via registry string
    // The real Python uninstaller is found in the registry, not at a
    // hardcoded path. Running it properly cleans up registry entries
    // so Settings > Apps stays consistent after uninstall.
    // ----------------------------------------------------------------
    LogPythonState;
    AppendUninstallLog('[Python] Force-killing python.exe processes...');
    ExecWithLogging(False, '[Python] taskkill', 'taskkill', '/F /IM python.exe');
    ExecWithLogging(False, '[Python] taskkill pythonw', 'taskkill', '/F /IM pythonw.exe');
    Sleep(2000);

    PyUninstallStr := GetPythonUninstallString;
    if PyUninstallStr <> '' then
    begin
      AppendUninstallLog('[Python] Running uninstaller from registry: ' + PyUninstallStr);
      // /uninstall flag triggers silent removal; /quiet suppresses MSI UI
      ExecWithLogging(False, '[Python] Uninstaller', PyUninstallStr, '/uninstall /quiet');
      AppendUninstallLog('[Python] Waiting for uninstaller to complete...');
      WaitForFolderRemoval(ExpandConstant(PY_FOLDER), '[Python]', 60000);
    end
    else
      AppendUninstallLog('[Python] No registry uninstall string found, skipping clean uninstall.');

    // Force-delete any remnants the Python uninstaller left behind
    Folder := ExpandConstant(PY_FOLDER);
    if DirExists(Folder) then
    begin
      AppendUninstallLog('[Python] Remnants found, force-deleting: ' + Folder);
      if DelTree(Folder, True, True, True) then
        AppendUninstallLog('[Python] DelTree succeeded.')
      else
        AppendUninstallLog('[Python] DelTree returned FALSE for: ' + Folder);
    end
    else
      AppendUninstallLog('[Python] Folder clean after uninstaller: ' + Folder);

    if DirExists(Folder) then
      AppendUninstallLog('[Python] Folder still exists after all delete attempts.')
    else
      AppendUninstallLog('[Python] Folder successfully removed.');

    // ----------------------------------------------------------------
    // TESSERACT: Remove binary, PATH entry, and registry key.
    // Mirrors the Ollama uninstall pattern exactly.
    // ----------------------------------------------------------------
    TessUninstaller := ExpandConstant(TESSERACT_FOLDER) + '\unins000.exe';
    AppendUninstallLog('[Tesseract] Uninstaller path: ' + TessUninstaller);

    if FileExists(TessUninstaller) then
    begin
      AppendUninstallLog('[Tesseract] Running uninstaller...');
      ExecWithLogging(False, '[Tesseract] Uninstaller',
        TessUninstaller, '/S');
      AppendUninstallLog('[Tesseract] Waiting for uninstaller to complete...');
      WaitForFolderRemoval(ExpandConstant(TESSERACT_FOLDER), '[Tesseract]', 30000);
    end
    else
      AppendUninstallLog('[Tesseract] unins000.exe not found  -  skipping.');

    // Force-delete any remnants the uninstaller left behind
    Folder := ExpandConstant(TESSERACT_FOLDER);
    if DirExists(Folder) then
    begin
      AppendUninstallLog('[Tesseract] Remnants found, force-deleting: ' + Folder);
      if DelTree(Folder, True, True, True) then
        AppendUninstallLog('[Tesseract] DelTree succeeded.')
      else
        AppendUninstallLog('[Tesseract] DelTree returned FALSE for: ' + Folder);
    end
    else
      AppendUninstallLog('[Tesseract] Folder clean after uninstaller.');

    // Remove Tesseract from user PATH
    if RegQueryStringValue(HKCU, 'Environment', 'Path', CurrentPath) then
    begin
      StringChangeEx(CurrentPath,
        ExpandConstant(TESSERACT_FOLDER) + ';', '', True);
      StringChangeEx(CurrentPath,
        ';' + ExpandConstant(TESSERACT_FOLDER), '', True);
      RegWriteExpandStringValue(HKCU, 'Environment', 'Path', CurrentPath);
      AppendUninstallLog('[Tesseract] Removed from user PATH.');
    end
    else
      AppendUninstallLog('[Tesseract] PATH entry not found  -  nothing to remove.');

    // Remove HKCU registry key (written by per-user install)
    if RegKeyExists(HKCU, 'SOFTWARE\Tesseract-OCR') then
    begin
      if RegDeleteKeyIncludingSubkeys(HKCU, 'SOFTWARE\Tesseract-OCR') then
        AppendUninstallLog('[Tesseract] HKCU registry key removed.')
      else
        AppendUninstallLog('[Tesseract] Failed to remove HKCU registry key.');
    end
    else
      AppendUninstallLog('[Tesseract] HKCU registry key not found (already clean).');

    // ----------------------------------------------------------------
    // REGISTRY CLEANUP: Remove Python and AI-Prowler uninstall entries.
    // The Python MSI uninstaller does not know about our manually-written
    // HKCU key so it leaves it behind. AI-Prowler's own Inno key may also
    // linger if {app} was forcibly deleted. Clean both here explicitly.
    // ----------------------------------------------------------------

    // Python 3.11.8 uninstall key (written manually by EnsurePythonRegistryEntry)
    if RegKeyExists(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)') then
    begin
      if RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)') then
        AppendUninstallLog('[Registry] Python 3.11.8 uninstall key removed from HKCU.')
      else
        AppendUninstallLog('[Registry] Failed to remove Python 3.11.8 key from HKCU.');
    end
    else
      AppendUninstallLog('[Registry] Python 3.11.8 key not found in HKCU (already clean).');

    // Also check HKLM in case it was installed system-wide
    if RegKeyExists(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)') then
    begin
      if RegDeleteKeyIncludingSubkeys(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)') then
        AppendUninstallLog('[Registry] Python 3.11.8 uninstall key removed from HKLM.')
      else
        AppendUninstallLog('[Registry] Failed to remove Python 3.11.8 key from HKLM (may need elevation).');
    end;

    // AI-Prowler uninstall keys  -  Inno writes these under both the app GUID and name.
    // Check all common patterns to catch any version that was ever installed.
    if RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Prowler_is1') then
      AppendUninstallLog('[Registry] AI-Prowler HKCU key (is1) removed.')
    else if RegKeyExists(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Prowler_is1') then
      AppendUninstallLog('[Registry] AI-Prowler HKCU key (is1) could not be removed.');

    if RegDeleteKeyIncludingSubkeys(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Prowler_is1') then
      AppendUninstallLog('[Registry] AI-Prowler HKLM key (is1) removed.')
    else if RegKeyExists(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Prowler_is1') then
      AppendUninstallLog('[Registry] AI-Prowler HKLM key (is1) could not be removed.');

    // WOW6432Node variants (32-bit view on 64-bit Windows)
    if RegDeleteKeyIncludingSubkeys(HKLM, 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AI-Prowler_is1') then
      AppendUninstallLog('[Registry] AI-Prowler WOW6432Node key removed.');

    Folder := ExpandConstant(OLLAMA_DATA_FOLDER);
    if DirExists(Folder) then
    begin
      AppendUninstallLog('[Data] Deleting: ' + Folder);
      if DelTree(Folder, True, True, True) then
        AppendUninstallLog('[Data] Ollama data delete requested.')
      else
        AppendUninstallLog('[Data] DelTree returned FALSE for: ' + Folder);
    end
    else
      AppendUninstallLog('[Data] Ollama data folder not found: ' + Folder);

    // ----------------------------------------------------------------
    // SETTINGS CONFIG  -  always delete on uninstall.
    // This is the file that causes the 'wrong model on reinstall' bug.
    // It must never survive into a fresh install.
    // ----------------------------------------------------------------
    DeleteFileIfExists(ExpandConstant('{%USERPROFILE}\.rag_config.json'));
    AppendUninstallLog('[Config] Deleted .rag_config.json (always removed)');

    DeleteFileIfExists(ExpandConstant('{%USERPROFILE}\.rag_license.key'));
    AppendUninstallLog('[Config] Deleted .rag_license.key (always removed)');

    // ----------------------------------------------------------------
    // RAG DATABASE + TRACKING FILES
    // Ask the user.  If they keep the database, the tracking files
    // (.rag_file_tracking.json, .rag_email_index.json,
    //  .rag_auto_update_dirs.json) are also kept  -  they record which
    // files are already indexed and which folders are watched, so
    // after reinstall the app knows the database is already up to date
    // and does not re-index everything from scratch.
    // If they delete the database, those files are meaningless and go too.
    // ----------------------------------------------------------------
    DeleteRagDB := MsgBox(
      'Delete the AI-Prowler RAG database and index tracking files?' + #13#10 +
      '' + #13#10 +
      'YES - delete the database and all tracking files (clean slate)' + #13#10 +
      'NO  - keep the database and tracking files (faster re-index after reinstall)' + #13#10 +
      '' + #13#10 +
      'Database folder: ' + ExpandConstant(RAG_DB_FOLDER),
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;

    if DeleteRagDB then
    begin
      // Delete the vector database
      Folder := ExpandConstant(RAG_DB_FOLDER);
      if DirExists(Folder) then
      begin
        AppendUninstallLog('[RAG] Deleting database: ' + Folder);
        if DelTree(Folder, True, True, True) then
          AppendUninstallLog('[RAG] Database deleted.')
        else
          AppendUninstallLog('[RAG] DelTree returned FALSE for: ' + Folder);
      end
      else
        AppendUninstallLog('[RAG] Database folder not found: ' + Folder);

      // Delete tracking files  -  useless without the database
      DeleteFileIfExists(ExpandConstant('{%USERPROFILE}\.rag_file_tracking.json'));
      AppendUninstallLog('[RAG] Deleted .rag_file_tracking.json');
      DeleteFileIfExists(ExpandConstant('{%USERPROFILE}\.rag_email_index.json'));
      AppendUninstallLog('[RAG] Deleted .rag_email_index.json');
      DeleteFileIfExists(ExpandConstant('{%USERPROFILE}\.rag_auto_update_dirs.json'));
      AppendUninstallLog('[RAG] Deleted .rag_auto_update_dirs.json');
    end
    else
    begin
      AppendUninstallLog('[RAG] User chose to keep database and tracking files.');
      AppendUninstallLog('[RAG]   Kept: ' + ExpandConstant(RAG_DB_FOLDER));
      AppendUninstallLog('[RAG]   Kept: .rag_file_tracking.json');
      AppendUninstallLog('[RAG]   Kept: .rag_email_index.json');
      AppendUninstallLog('[RAG]   Kept: .rag_auto_update_dirs.json');
    end;

    AppendUninstallLog('=== UNINSTALL SUMMARY ===');

    if DirExists(ExpandConstant(OLLAMA_FOLDER)) then
      AppendUninstallLog('[Summary] Ollama folder: STILL PRESENT')
    else
      AppendUninstallLog('[Summary] Ollama folder: REMOVED');

    if DirExists(ExpandConstant(PY_FOLDER)) then
      AppendUninstallLog('[Summary] Python folder: STILL PRESENT')
    else
      AppendUninstallLog('[Summary] Python folder: REMOVED');

    if DirExists(ExpandConstant(OLLAMA_DATA_FOLDER)) then
      AppendUninstallLog('[Summary] Ollama data folder: STILL PRESENT')
    else
      AppendUninstallLog('[Summary] Ollama data folder: REMOVED');

    if DirExists(ExpandConstant(TESSERACT_FOLDER)) then
      AppendUninstallLog('[Summary] Tesseract folder: STILL PRESENT')
    else
      AppendUninstallLog('[Summary] Tesseract folder: REMOVED');

    if DirExists(ExpandConstant(RAG_DB_FOLDER)) then
      AppendUninstallLog('[Summary] RAG database folder: STILL PRESENT')
    else
      AppendUninstallLog('[Summary] RAG database folder: REMOVED or NOT FOUND');

    // Registry summary
    if RegKeyExists(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Python 3.11.8 (64-bit)') then
      AppendUninstallLog('[Summary] Python registry key: STILL PRESENT')
    else
      AppendUninstallLog('[Summary] Python registry key: REMOVED');

    if RegKeyExists(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Prowler_is1') or
       RegKeyExists(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Prowler_is1') then
      AppendUninstallLog('[Summary] AI-Prowler registry key: STILL PRESENT')
    else
      AppendUninstallLog('[Summary] AI-Prowler registry key: REMOVED');

    AppendUninstallLog('=== UNINSTALL FINISHED ===');
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    // ----------------------------------------------------------------
    // POST-UNINSTALL: Remove {app} folder using a deferred batch file.
    // Cannot use DelTree here  -  unins000.exe lives in {app} and Windows
    // holds a handle on the folder until the uninstaller process exits.
    // DeferredDeleteFolder launches a batch with ewNoWait that wakes up
    // ~7 seconds later (after full process exit) and runs rd /s /q.
    // ----------------------------------------------------------------
    Folder := ExpandConstant('{app}');
    if DirExists(Folder) then
      DeferredDeleteFolder(Folder)
    else
      AppendUninstallLog('[App] App folder already clean.');
  end;
end;
@echo off
REM ============================================================
REM AI-Prowler - Launch GUI
REM ============================================================

set "INSTALL_DIR=C:\Program Files\AI-Prowler"
set "LOCAL_PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
set "LOCAL_PYTHONW_EXE=%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe"

REM ── Roaming site-packages fix ─────────────────────────────────────────────────
set PYTHONNOUSERSITE=1

REM ── Errno 22 / double-backslash path fix ─────────────────────────────────────
if not defined HF_HUB_CACHE (
    set "HF_HUB_CACHE=%USERPROFILE%\.cache\huggingface\hub"
)

if not exist "%LOCAL_PYTHON_EXE%" (
    echo ERROR: Python not found at:
    echo %LOCAL_PYTHON_EXE%
    pause
    exit /b 1
)

if not exist "%INSTALL_DIR%\rag_gui.py" (
    echo ERROR: rag_gui.py not found in %INSTALL_DIR%
    pause
    exit /b 1
)

if not exist "%INSTALL_DIR%\rag_preprocessor.py" (
    echo ERROR: rag_preprocessor.py not found in %INSTALL_DIR%
    pause
    exit /b 1
)

REM ── Check for pending update ──────────────────────────────────────────────────
REM If AI-Prowler downloaded an update during the previous session, the staged
REM files sit in pending_update and a flag file signals they are ready to apply.
REM We apply BEFORE launching so the new code runs immediately.
set "UPDATE_DIR=%LOCALAPPDATA%\AI-Prowler\pending_update"
set "UPDATE_FLAG=%LOCALAPPDATA%\AI-Prowler\update_ready.txt"
set "BACKUP_DIR=%LOCALAPPDATA%\AI-Prowler\update_backup"

if exist "%UPDATE_FLAG%" (
    REM ── Self-elevate if needed ──────────────────────────────────────────────
    REM Writing into "C:\Program Files\AI-Prowler" requires Administrator rights.
    REM Detect elevation with "net session" (succeeds only when elevated). If we
    REM are NOT elevated, relaunch this script via PowerShell's RunAs verb, which
    REM triggers the UAC prompt. The "%~1"=="ELEVATED" guard prevents an infinite
    REM relaunch loop: the elevated copy is started with that marker argument and
    REM therefore skips the relaunch and proceeds straight to the copy.
    net session >nul 2>&1
    if errorlevel 1 (
        if not "%~1"=="ELEVATED" (
            echo Requesting Administrator rights to apply the update ...
            REM Spawn an elevated copy that ONLY applies the update, and WAIT
            REM for it to finish (-Wait). Then this non-elevated instance falls
            REM through to launch the GUI without elevation — we never want the
            REM GUI (and its child MCP server) running as Administrator.
            powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'ELEVATED' -Verb RunAs -Wait"
            REM Elevated updater has finished. Skip the (now-complete) update
            REM block and jump straight to launch.
            goto :launch
        )
    )

    echo ============================================================
    echo   Applying AI-Prowler update ...
    echo ============================================================

    REM Back up current files before overwriting
    if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
    xcopy /Y /Q "%INSTALL_DIR%\*.py"  "%BACKUP_DIR%\" >nul 2>&1
    xcopy /Y /Q "%INSTALL_DIR%\*.bat" "%BACKUP_DIR%\" >nul 2>&1
    xcopy /Y /Q "%INSTALL_DIR%\*.ico" "%BACKUP_DIR%\" >nul 2>&1
    xcopy /Y /Q "%INSTALL_DIR%\*.md"  "%BACKUP_DIR%\" >nul 2>&1

    REM Copy staged update files over the install directory. /E includes any
    REM subdirectories present in the staging area; /Y overwrites silently.
    xcopy /Y /Q /E "%UPDATE_DIR%\*.*" "%INSTALL_DIR%\" >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Some files could not be copied even with elevation.
        echo          The install directory may be locked by a running copy
        echo          of AI-Prowler. Close all AI-Prowler windows and retry.
        pause
    ) else (
        echo   Update applied successfully.
    )

    REM Clean up staging area and flag
    del "%UPDATE_FLAG%" >nul 2>&1
    rmdir /S /Q "%UPDATE_DIR%" >nul 2>&1
    echo ============================================================
    echo.

    REM If this is the ELEVATED updater instance, its only job was to apply
    REM the update. Exit now so the GUI is launched by the original
    REM non-elevated instance (which is waiting on us), never as Administrator.
    if "%~1"=="ELEVATED" exit /b 0
)

REM ── Launch AI-Prowler ─────────────────────────────────────────────────────────
:launch
if exist "%LOCAL_PYTHONW_EXE%" (
    start "" "%LOCAL_PYTHONW_EXE%" "%INSTALL_DIR%\rag_gui.py"
) else (
    start "" "%LOCAL_PYTHON_EXE%" "%INSTALL_DIR%\rag_gui.py"
)
exit

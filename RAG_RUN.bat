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
    echo ============================================================
    echo   Applying AI-Prowler update ...
    echo ============================================================

    REM Back up current files before overwriting
    if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
    xcopy /Y /Q "%INSTALL_DIR%\*.py"  "%BACKUP_DIR%\" >nul 2>&1
    xcopy /Y /Q "%INSTALL_DIR%\*.bat" "%BACKUP_DIR%\" >nul 2>&1
    xcopy /Y /Q "%INSTALL_DIR%\*.ico" "%BACKUP_DIR%\" >nul 2>&1

    REM Copy staged update files over the install directory
    xcopy /Y /Q "%UPDATE_DIR%\*.*" "%INSTALL_DIR%\" >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Some files could not be copied. You may need to run
        echo          this launcher as Administrator.
        pause
    ) else (
        echo   Update applied successfully.
    )

    REM Clean up staging area and flag
    del "%UPDATE_FLAG%" >nul 2>&1
    rmdir /S /Q "%UPDATE_DIR%" >nul 2>&1
    echo ============================================================
    echo.
)

REM ── Launch AI-Prowler ─────────────────────────────────────────────────────────
if exist "%LOCAL_PYTHONW_EXE%" (
    start "" "%LOCAL_PYTHONW_EXE%" "%INSTALL_DIR%\rag_gui.py"
) else (
    start "" "%LOCAL_PYTHON_EXE%" "%INSTALL_DIR%\rag_gui.py"
)
exit

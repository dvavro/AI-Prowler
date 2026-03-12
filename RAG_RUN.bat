@echo off
REM ============================================================
REM AI-Prowler - Launch GUI
REM ============================================================

set "INSTALL_DIR=C:\Program Files\AI-Prowler"
set "LOCAL_PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

REM ── Roaming site-packages fix ─────────────────────────────────────────────────
REM Prevents Python from loading old package versions from Roaming site-packages.
REM The PYTHONNOUSERSITE=1 env var written to the registry by the installer
REM requires Explorer to process WM_SETTINGCHANGE before it takes effect.
REM Setting it explicitly here ensures it is always active, even when the app
REM is launched immediately after install before Explorer has seen the broadcast.
set PYTHONNOUSERSITE=1

REM ── Errno 22 / double-backslash path fix ─────────────────────────────────────
REM huggingface_hub on some Windows 10 builds derives its cache path with a
REM trailing backslash. Setting HF_HUB_CACHE explicitly here gives the library
REM a clean, pre-built path with no trailing backslash, preventing the
REM double-backslash Errno 22 Invalid argument error on indexing.
REM Only set if not already set (respects user custom HF cache locations).
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

"%LOCAL_PYTHON_EXE%" "%INSTALL_DIR%\rag_gui.py"

echo.
echo --- Python exited with code %errorlevel% ---
echo.
pause
exit /b 0
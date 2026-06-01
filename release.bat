@echo off
REM ──────────────────────────────────────────────────────────────────────────
REM  release.bat — thin wrapper around scripts\release.py
REM
REM  Usage from the AI-Prowler repo root:
REM      release 7.0.0
REM      release --check
REM      release --remanifest
REM      release 7.0.0 --skip-tests
REM
REM  Lives in the repo root so it's discoverable. All real logic is in
REM  scripts\release.py.
REM ──────────────────────────────────────────────────────────────────────────

setlocal

REM Always run from THIS bat's folder (the repo root), regardless of where
REM the user invoked it from. This pairs with release.py's Option B repo
REM resolution: the file's location IS the repo.
cd /d "%~dp0"

REM Prefer `py` (the Windows Python launcher) — same convention used
REM throughout the AI-Prowler test/release notes. Fall back to `python`.
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py "scripts\release.py" %*
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        python "scripts\release.py" %*
    ) else (
        echo.
        echo ERROR: neither `py` nor `python` is on PATH.
        echo Install Python 3.11+ and re-run.
        echo.
        pause
        exit /b 1
    )
)

set _rc=%ERRORLEVEL%

REM Pause so the console doesn't slam shut if the user double-clicked.
REM Skip pause if -y / --yes was passed (CI / scripted use).
echo %* | findstr /i /c:"-y" /c:"--yes" >nul
if errorlevel 1 (
    echo.
    pause
)

endlocal & exit /b %_rc%

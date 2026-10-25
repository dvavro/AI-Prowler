@echo off
REM ============================================================
REM  AI-Prowler — remove E2E test data ON THIS MACHINE (the server)
REM ============================================================
REM  Run this on the AI-Prowler SERVER, signed in as the Windows
REM  account AI-Prowler runs under (AI-Prowler-Server), after a
REM  server-mode E2E run. It removes what the Jobs app itself can't:
REM  mileage test records (IRS log: never deleted by the app) and
REM  uploaded "ztest" photo files. See ztest_server_cleanup.py.
REM
REM  1. Shows what it would remove (changes nothing).
REM  2. Asks; on "y" it backs up the job database and removes it.
REM  Then on David's PC run server_cleanup_done.bat.
REM ============================================================
setlocal
cd /d "%~dp0"
set "PY=python"
where py >nul 2>nul && set "PY=py -3"

%PY% ztest_server_cleanup.py
if errorlevel 1 goto :end
echo.
set /p GO="Remove this test data now (a backup is made first)? [y/N] "
if /i not "%GO%"=="y" (
    echo Nothing was changed.
    goto :end
)
%PY% ztest_server_cleanup.py --apply

:end
echo.
pause
endlocal

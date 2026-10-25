@echo off
REM Run on David's PC AFTER running run_ztest_server_cleanup.bat on the
REM AI-Prowler Server: clears the "server cleanup is due" reminder that
REM every test run prints.
setlocal
cd /d "%~dp0"
set "PY=python"
where py >nul 2>nul && set "PY=py -3"
%PY% -c "import pending; n = pending.clear(); print(f'Cleared {n} pending server-cleanup item(s). Test runs will show the short reminder only.')"
pause
endlocal

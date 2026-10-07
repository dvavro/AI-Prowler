@echo off
REM =====================================================================
REM  run_all_gui_e2e_suites.bat — every E2E GUI PWA regression, back to back
REM  (added 2026-10-01). Safe tier only: no real email, SMS or AI credits.
REM
REM    1. Jobs app, personal mode   tests\gui_jobs_e2e\artifacts\latest\SUMMARY.txt
REM    2. Jobs app, server mode     tests\gui_jobs_e2e_server\artifacts\latest\SUMMARY.txt
REM    3. Remote PWA                tests\gui_remote_e2e\artifacts\latest\SUMMARY.txt
REM
REM  Headless (fast) by default. Add --human to watch every suite, e.g.
REM    run_all_gui_e2e_suites.bat --human
REM  Each suite runs even if an earlier one failed; the exit code is 1 if any
REM  suite failed. Each suite sweeps leftover ZTEST data before and after.
REM =====================================================================
setlocal
set "HERE=%~dp0"
set "RC=0"

echo.
echo ===== 1/3  Jobs app — personal mode =====
call "%HERE%run_tests_gui_jobs_e2e.bat" --no-open %*
if errorlevel 1 set "RC=1"

echo.
echo ===== 2/3  Jobs app — server mode (AI-Prowler Server) =====
call "%HERE%run_tests_gui_jobs_e2e.bat" --server --no-open %*
if errorlevel 1 set "RC=1"

echo.
echo ===== 3/3  Remote PWA =====
call "%HERE%run_tests_gui_jobs_e2e.bat" --remote --no-open %*
if errorlevel 1 set "RC=1"

echo.
echo ===== All E2E GUI suites finished (exit %RC%) =====
echo   %HERE%gui_jobs_e2e\artifacts\latest\SUMMARY.txt
echo   %HERE%gui_jobs_e2e_server\artifacts\latest\SUMMARY.txt
echo   %HERE%gui_remote_e2e\artifacts\latest\SUMMARY.txt
exit /b %RC%

@echo off
REM =====================================================================
REM  run_tests_gui_jobs_e2e.bat — AI-Prowler Jobs app end-to-end tests
REM  (Playwright + Microsoft Edge against the LIVE Jobs app, ZTEST data on
REM  sandbox date = TODAY (+/- a few days), guarded writes, cleans up after itself).
REM
REM  Spec:     tests\JOBS_APP_E2E_TEST_SPEC.md
REM  Options:  run_tests_gui_jobs_e2e.bat --help
REM  Results:  tests\gui_jobs_e2e\artifacts\latest\SUMMARY.txt / report.html
REM
REM  One-time setup:
REM    tests\install_gui_jobs_e2e_deps.bat
REM    setx AIPROWLER_JOBS_TOKEN "<Bearer Token from Settings -> Remote Access>"
REM
REM  Never part of the normal run_tests.bat (pytest marker jobs_gui_e2e is
REM  excluded there).
REM =====================================================================
setlocal
set "PY=%LocalAppData%\Programs\Python\Python311\python.exe"
if not exist "%PY%" set "PY=python"
set "HERE=%~dp0"

if /i "%~1"=="--background" (
    REM Relaunch minimized in its own window; a notification appears when done.
    start "AI-Prowler Jobs E2E" /min "%PY%" "%HERE%run_gui_jobs_e2e.py" %*
    echo Started in the background. A notification will appear when it finishes.
    echo Results: %HERE%gui_jobs_e2e\artifacts\latest\SUMMARY.txt
    exit /b 0
)

"%PY%" "%HERE%run_gui_jobs_e2e.py" %*
exit /b %errorlevel%

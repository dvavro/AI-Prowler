@echo off
REM =====================================================================
REM  run_tests_estimator.bat - AI-Prowler ESTIMATOR regression runner
REM
REM  The Estimator has its own runner; run_tests.bat is NOT used for the
REM  Estimator regressions (2026-11-07, Vicki - Coder 2 / Tester 2).
REM
REM  USAGE
REM    run_tests_estimator.bat                 all Estimator tests (Coder 1 + Coder 2)
REM    run_tests_estimator.bat coder1          Coder 1 track only   (tests\estimator\unit)
REM    run_tests_estimator.bat coder2          Coder 2 track only   (tests\estimator\webapp + plan_engine)
REM    run_tests_estimator.bat webapp          web app + JSON API   (tests\estimator\webapp)
REM    run_tests_estimator.bat planengine      plan engine only     (tests\estimator\plan_engine)
REM    run_tests_estimator.bat -k login        any pytest args, applied to all Estimator tests
REM    run_tests_estimator.bat coder2 -k sse   a track plus pytest args
REM
REM  SAFETY
REM    Every run uses a throwaway data folder (ESTIMATOR_DATA_DIR and
REM    AIPROWLER_TEST_STATE_DIR point into %%TEMP%%), so the real
REM    %%USERPROFILE%%\AI-Prowler\Estimator\estimator.db is never touched.
REM    No browser is launched for bid PDFs and the Director watcher is off
REM    (tests\estimator\conftest.py) unless a test turns them on itself.
REM
REM  OUTPUT
REM    Screen + a UTF-8 log in test_logs\estimator_<date>_<time>.log.
REM    The exit code is pytest's own (0 = all passed), so release_gate.bat
REM    or a nightly job can read %%ERRORLEVEL%%.
REM =====================================================================
setlocal
cd /d "%~dp0"

set "AIPROWLER_TEST_STATE_DIR=%TEMP%\ai_prowler_est_test_%RANDOM%%RANDOM%"
set "ESTIMATOR_DATA_DIR=%AIPROWLER_TEST_STATE_DIR%\estimator"
set "ESTIMATOR_WATCHER=off"
set "ESTIMATOR_PDF_BROWSER=none"
echo [run_tests_estimator] Sandbox data folder: %ESTIMATOR_DATA_DIR%

set "PYTHON=%LocalAppData%\Programs\Python\Python311\python.exe"
if not exist "%PYTHON%" (
    echo WARNING: Python not found at %PYTHON% - trying python on PATH
    set "PYTHON=python"
)
"%PYTHON%" -c "import pytest" 2>nul || "%PYTHON%" -m pip install pytest --quiet
REM PyYAML: the Director playbooks are YAML (same check as Jamie's run_tests_estimate.bat).
"%PYTHON%" -c "import yaml" 2>nul || "%PYTHON%" -m pip install pyyaml --quiet

REM ---- pick the test folder from the first argument ----------------------
set "TARGET=tests\estimator"
set "TRACK=all"
if /i "%~1"=="coder1" (set "TARGET=tests\estimator\unit"& set "TRACK=coder1"& shift)
REM coder2 = the web app and the plan engine. TARGET goes inside '...' in the PowerShell line below, so two folders
REM are written as  first' 'second .
if /i "%~1"=="coder2" (set "TARGET=tests\estimator\webapp' 'tests\estimator\plan_engine"& set "TRACK=coder2"& shift)
if /i "%~1"=="webapp" (set "TARGET=tests\estimator\webapp"& set "TRACK=webapp"& shift)
if /i "%~1"=="planengine" (set "TARGET=tests\estimator\plan_engine"& set "TRACK=planengine"& shift)

REM Collect the remaining arguments (SHIFT doesn't change %%*).
set "REST="
:collect
if "%~1"=="" goto :run
set "REST=%REST% %1"
shift
goto :collect

:run
set "LOGDIR=%~dp0test_logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>&1
set "STAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "STAMP=%STAMP: =0%"
set "LOGFILE=%LOGDIR%\estimator_%TRACK%_%STAMP%.log"
set "LOGFILE_RAW=%LOGFILE%.rawutf16"

echo [run_tests_estimator] Track: %TRACK%   Tests: %TARGET%  %REST%
REM pytest runs inside PowerShell so output is tee'd to the log AND pytest's
REM real exit code survives the pipe (same technique as run_tests.bat).
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%PYTHON%' -m pytest '%TARGET%' -v -p no:cacheprovider --rootdir '%~dp0.' %REST% 2>&1 | Tee-Object -FilePath '%LOGFILE_RAW%'; exit $LASTEXITCODE"
set "TEST_RC=%ERRORLEVEL%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content -Path '%LOGFILE_RAW%' -Encoding Unicode) | Set-Content -Path '%LOGFILE%' -Encoding utf8" >nul 2>&1
del "%LOGFILE_RAW%" >nul 2>&1
rmdir /s /q "%AIPROWLER_TEST_STATE_DIR%" >nul 2>&1

echo.
if "%TEST_RC%"=="0" (echo [run_tests_estimator] PASSED) else (echo [run_tests_estimator] FAILED - exit code %TEST_RC%)
echo [run_tests_estimator] Full log saved to: %LOGFILE%
endlocal & exit /b %TEST_RC%

@echo off
REM =====================================================================
REM  run_tests_estimate.bat - Estimator regression tests only
REM
REM    run_tests_estimate.bat                 all Estimator tests (tests\estimator\)
REM    run_tests_estimate.bat setup           + AI-Prowler's Setup / switch tests the Estimator hooks into
REM    run_tests_estimate.bat full            + the whole GUI suite too (about 20 minutes)
REM    run_tests_estimate.bat -k sprint16     keyword filter (any pytest option works, in any mode)
REM    run_tests_estimate.bat setup -x        stop at the first failure
REM
REM  Safe: the Estimator database goes to a throwaway temp folder, the background
REM  watcher is off, and AI-Prowler's own database is sandboxed like run_tests.bat.
REM  No real API calls, emails or texts. Every run is also saved to
REM  test_logs\estimate_run_<date_time>.log next to this file.
REM =====================================================================
setlocal

set "PYTHON=%LocalAppData%\Programs\Python\Python311\python.exe"
if not exist "%PYTHON%" (
    echo WARNING: Python not found at %PYTHON%
    echo Trying python on PATH...
    set PYTHON=python
)
"%PYTHON%" -c "import pytest" 2>nul || "%PYTHON%" -m pip install pytest pytest-mock --quiet
"%PYTHON%" -c "import yaml" 2>nul || "%PYTHON%" -m pip install pyyaml --quiet

REM ── Sandboxes ────────────────────────────────────────────────────────────
set "AIPROWLER_TEST_STATE_DIR=%TEMP%\ai_prowler_test_%RANDOM%"
set "ESTIMATOR_DATA_DIR=%TEMP%\ai_prowler_estimator_test_%RANDOM%"
set "ESTIMATOR_WATCHER=off"
echo [estimate tests] Sandbox AI-Prowler DB: %AIPROWLER_TEST_STATE_DIR%
echo [estimate tests] Sandbox Estimator DB:  %ESTIMATOR_DATA_DIR%

REM ── What to run ──────────────────────────────────────────────────────────
set "SUITE=tests\estimator"
set "SETUP_TESTS=tests\test_setup_wizard.py tests\unit\test_setup_choices_are_switches.py tests\unit\test_desk_wizard.py tests\unit\test_group_switch_one_truth.py tests\gui\test_setup_choices_on_screen.py tests\gui\test_setup_goes_to_the_right_place.py"
set "MODE=estimator"
if /i "%~1"=="setup" (set "MODE=estimator + Setup" & set "SUITE=%SUITE% %SETUP_TESTS%" & shift)
if /i "%~1"=="full" (set "MODE=estimator + Setup + GUI" & set "SUITE=%SUITE% %SETUP_TESTS% tests\gui" & shift)
set "REST="
:args
if "%~1"=="" goto :run
set "REST=%REST% %1"
shift
goto :args

:run
echo [estimate tests] Running: %MODE%
cd /d "%~dp0"
set "LOGDIR=%~dp0test_logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>&1
set "STAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "STAMP=%STAMP: =0%"
set "LOGFILE=%LOGDIR%\estimate_run_%STAMP%.log"
set "LOGFILE_RAW=%LOGFILE%.rawutf16"

REM Same tee as run_tests.bat: screen + log file, and pytest's real exit code is kept.
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%PYTHON%' -m pytest %SUITE% -q -p no:cacheprovider -rfs %REST% 2>&1 | Tee-Object -FilePath '%LOGFILE_RAW%'; exit $LASTEXITCODE"
set "TEST_RC=%ERRORLEVEL%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content -Path '%LOGFILE_RAW%' -Encoding Unicode) | Set-Content -Path '%LOGFILE%' -Encoding utf8" >nul 2>&1
del "%LOGFILE_RAW%" >nul 2>&1
rmdir /s /q "%ESTIMATOR_DATA_DIR%" >nul 2>&1

echo.
if "%TEST_RC%"=="0" (echo [estimate tests] PASSED - %MODE%) else (echo [estimate tests] FAILED - %MODE% ^(exit code %TEST_RC%^))
echo [estimate tests] Full log saved to: %LOGFILE%
endlocal & exit /b %TEST_RC%

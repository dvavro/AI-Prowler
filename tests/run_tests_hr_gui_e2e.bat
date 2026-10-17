@echo off
REM =====================================================================
REM  run_tests_hr_gui_e2e.bat - HR Admin + HR Portal in a real browser
REM  (Playwright / Chromium) against SANDBOX AI-Prowler servers: their own
REM  temporary data folders and ZTEST users. Real HR data is never touched.
REM
REM  Both suites are also part of the normal run_tests.bat run
REM  (pytest markers hr_gui_e2e and hr_gui_timemachine).
REM
REM  Options:
REM    (none)         both suites
REM    --buttons      only tests\gui_hr_e2e (every screen + several users at once)
REM    --timemachine  only tests\gui_hr_timemachine (onboarding -> offboarding,
REM                   walked day by day with a movable clock)
REM    --headed       show the browser windows while the tests run
REM    -k NAME        only tests whose name contains NAME (any pytest option works)
REM
REM  One-time setup on a new PC:
REM    python -m pip install playwright time-machine
REM    python -m playwright install chromium
REM =====================================================================
setlocal
set "PY=%LocalAppData%\Programs\Python\Python311\python.exe"
if not exist "%PY%" set "PY=python"
set "HERE=%~dp0"
set "HR_GUI_HEADED="
set "SUITES=tests\gui_hr_e2e tests\gui_hr_timemachine"
:args
if /i "%~1"=="--headed"      ( set "HR_GUI_HEADED=1" & shift & goto args )
if /i "%~1"=="--buttons"     ( set "SUITES=tests\gui_hr_e2e" & shift & goto args )
if /i "%~1"=="--timemachine" ( set "SUITES=tests\gui_hr_timemachine" & shift & goto args )
pushd "%HERE%.."
"%PY%" -m pytest %SUITES% -v -p no:cacheprovider %1 %2 %3 %4 %5 %6
set "RC=%errorlevel%"
popd
exit /b %RC%

@echo off
REM =====================================================================
REM  run_live_api_cost_server.bat — the PAID live agent cost tests on the AI-Prowler SERVER
REM  (2026-11-03, David). Same tests as "run_tests.bat live-api-cost" on the dev PC.
REM  Copy this folder (conftest.py, live_lib.py, test_live_api_cost.py, live_pytest.ini, this .bat) to the
REM  server (e.g. the owner's private folder) and run it there.
REM
REM    run_live_api_cost_server.bat                 all five, asks before each one, browser on
REM    run_live_api_cost_server.bat -k test_4       just one (test_1 .. test_5)
REM    run_live_api_cost_server.bat --dry           free trial run: no AI call, checks setup + cleanup
REM    run_live_api_cost_server.bat --no-human      no browser
REM    run_live_api_cost_server.bat --yes           don't ask (already agreed)
REM
REM  Run it signed in to Windows as AI-Prowler-Server, with AI-Prowler running.
REM  It spends REAL API credits on the server's Agent API Key (practice mode: nothing is
REM  sent, booked or changed; test records are removed afterwards; your saved settings
REM  are never changed). Results: results\live_cost_<PC>_<time>.md next to this file.
REM =====================================================================
setlocal
cd /d "%~dp0"
set "PYTHON=%LocalAppData%\Programs\Python\Python311\python.exe"
if not exist "%PYTHON%" set PYTHON=python
set "AIPROWLER_LIVE_API_COST=1"
set "AIPROWLER_TEST_STATE_DIR="

REM Where AI-Prowler's code is on this PC (the folder with desk_agent.py).
if not defined AIPROWLER_CODE_DIR (
  for %%D in ("%USERPROFILE%\Documents\AI-Prowler" "%ProgramFiles%\AI-Prowler" "%LocalAppData%\Programs\AI-Prowler" "%USERPROFILE%\AI-Prowler") do (
    if not defined AIPROWLER_CODE_DIR if exist "%%~D\desk_agent.py" set "AIPROWLER_CODE_DIR=%%~D"
  )
)
if not defined AIPROWLER_CODE_DIR (
  echo Can't find AI-Prowler's code folder ^(desk_agent.py^). Run:  set AIPROWLER_CODE_DIR=^<folder^>  then try again.
  pause
  exit /b 2
)
echo [live cost] AI-Prowler code: %AIPROWLER_CODE_DIR%

set "LC_YES="
set "LC_HUMAN=--live-human"
set "LC_REST="
:lc_loop
if "%~1"=="" goto :lc_go
if /i "%~1"=="--yes" (set "LC_YES=--live-yes"& shift & goto :lc_loop)
if /i "%~1"=="--no-human" (set "LC_HUMAN="& shift & goto :lc_loop)
if /i "%~1"=="--human" (shift & goto :lc_loop)
if /i "%~1"=="--dry" (set "LC_YES=--live-dry"& set "LC_HUMAN="& shift & goto :lc_loop)
set "LC_REST=%LC_REST% %1"
shift
goto :lc_loop
:lc_go
"%PYTHON%" -c "import pytest" 2>nul || "%PYTHON%" -m pip install pytest --quiet
if defined LC_HUMAN (
  "%PYTHON%" -c "import playwright" 2>nul || "%PYTHON%" -m pip install playwright --quiet
  "%PYTHON%" -m playwright install chromium >nul 2>&1
)
echo [live cost] PAID live agent cost tests on this server's real AI-Prowler (practice mode, test data removed)
"%PYTHON%" -m pytest "%~dp0." -c "%~dp0live_pytest.ini" --rootdir "%~dp0." -m live_api_cost -s -v -p no:cacheprovider %LC_YES% %LC_HUMAN% %LC_REST%
set "TEST_RC=%ERRORLEVEL%"
echo.
echo [live cost] Results are in %~dp0results
pause
endlocal & exit /b %TEST_RC%

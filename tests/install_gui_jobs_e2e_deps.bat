@echo off
REM One-time setup for the Jobs-app Playwright E2E suite (spec §8.4).
REM Uses the SAME Python as run_tests.bat so the packages are where the tests look.
setlocal
set "PY=%LocalAppData%\Programs\Python\Python311\python.exe"
if not exist "%PY%" set "PY=python"
echo Using Python: %PY%
"%PY%" --version

echo.
echo === Installing pytest-playwright, pytest-html, pytest-rerunfailures, time-machine ===
REM time-machine: only the time-machine suite (tests\gui_jobs_timemachine) uses it,
REM to move a SANDBOXED test server's clock. It never touches the real server.
"%PY%" -m pip install --disable-pip-version-check pytest-playwright pytest-html pytest-rerunfailures time-machine
if errorlevel 1 (
    echo [FAILED] pip install
    exit /b 1
)

echo.
echo === Installed versions ===
"%PY%" -m pip show playwright pytest-playwright pytest-html pytest-rerunfailures 2>nul | findstr /b /c:"Name:" /c:"Version:"

echo.
echo === Browser: Microsoft Edge (default) or Google Chrome — both are Chromium, no download needed ===
set "BROWSER="
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "BROWSER=msedge"
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "BROWSER=msedge"
if not defined BROWSER if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "BROWSER=chrome"
if not defined BROWSER if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "BROWSER=chrome"
if not defined BROWSER if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" set "BROWSER=chrome"
if not defined BROWSER (
    echo [FAILED] Neither Microsoft Edge nor Google Chrome was found.
    exit /b 1
)
echo Using browser channel: %BROWSER%

echo.
echo === Smoke test: can Playwright drive it? (headless, about:blank) ===
"%PY%" -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(channel='%BROWSER%', headless=True); pg=b.new_page(); pg.goto('about:blank'); print('Playwright OK ->', '%BROWSER%', b.version); b.close(); p.stop()"
if errorlevel 1 (
    echo [FAILED] Playwright could not launch %BROWSER%
    exit /b 1
)
echo.
echo All set.
exit /b 0

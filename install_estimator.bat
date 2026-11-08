@echo off
rem Installs the Estimator into C:\Program Files\AI-Prowler. Asks for administrator permission.
rem Python is found BEFORE asking for admin (the admin window may not have your PATH) and passed
rem along as the first argument, as a short 8.3 path so spaces never need quoting.
setlocal
set "PY=%~1"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python311\python.exe" set "PY=%LocalAppData%\Programs\Python\Python311\python.exe"
if not defined PY for /f "delims=" %%P in ('py -3.11 -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%P"
if not defined PY for /f "delims=" %%P in ('where python 2^>nul ^| findstr /v /i "WindowsApps"') do if not defined PY set "PY=%%P"
if not defined PY (
    echo Couldn't find Python 3.11. Install it from python-3.11.8-amd64.exe in this folder, then run this again.
    pause
    exit /b 1
)
for %%I in ("%PY%") do set "PY=%%~sI"

net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%PY%' -Verb RunAs"
    exit /b
)
echo Using Python: %PY%
"%PY%" "%~dp0install_estimator.py"
echo.
pause

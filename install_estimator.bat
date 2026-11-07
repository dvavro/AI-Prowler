@echo off
rem Installs the Estimator into C:\Program Files\AI-Prowler. Asks for administrator permission.
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
set PY=C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe
if not exist "%PY%" set PY=python
"%PY%" "%~dp0install_estimator.py"
echo.
pause

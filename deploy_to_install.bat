@echo off
rem Copy AI-Prowler's program files from this working folder to C:\Program Files\AI-Prowler.
rem   deploy_to_install.bat             copy changed files
rem   deploy_to_install.bat --dry-run   only list what would change
rem   deploy_to_install.bat --restore   undo the last deploy
rem Program Files needs administrator rights, so this asks for them (the Windows Yes/No prompt).

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Asking for administrator rights to write to C:\Program Files\AI-Prowler ...
    if "%~1"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

cd /d "%~dp0"
set "PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" "%~dp0deploy_to_install.py" %*
echo.
pause

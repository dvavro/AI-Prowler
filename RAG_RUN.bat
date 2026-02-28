@echo off
REM ============================================================
REM AI Prowler - Launch GUI
REM Starts the graphical interface for AI Prowler
REM ============================================================

REM Change to the directory where this script is located
cd /d "%~dp0"

echo Starting AI Prowler GUI...
echo.

REM Use Python 3.11 if available (best AI package compatibility), else default
set "PYTHON_CMD=python"
py -3.11 --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py -3.11"
)

REM Check if Python is available
%PYTHON_CMD% --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found
    echo.
    echo Please run INSTALL.bat first to install Python and AI Prowler
    echo.
    pause
    exit /b 1
)

REM Check if rag_gui.py exists
if not exist "rag_gui.py" (
    echo [ERROR] rag_gui.py not found
    echo.
    echo Please make sure you're running this from the AI Prowler installation directory
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

REM Check if rag_preprocessor.py exists
if not exist "rag_preprocessor.py" (
    echo [ERROR] rag_preprocessor.py not found
    echo.
    echo Please make sure all AI Prowler files are in this directory
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

REM Launch GUI (use pythonw to hide console)
start "" %PYTHON_CMD% "%~dp0rag_gui.py"

REM Exit immediately (GUI is running in background)
exit /b 0

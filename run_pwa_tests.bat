@echo off
REM run_pwa_tests.bat — Run PWA feature tests
REM Usage:
REM   run_pwa_tests.bat              — offline tests only (no server needed)
REM   run_pwa_tests.bat live         — live tests (AI-Prowler must be running)
REM   run_pwa_tests.bat all          — all tests

set PYTHON=%LocalAppData%\Programs\Python\Python311\python.exe
if not exist "%PYTHON%" set PYTHON=python

"%PYTHON%" -c "import pytest" 2>nul || "%PYTHON%" -m pip install pytest pyflakes --quiet

if "%~1"=="live" (
    echo Running LIVE PWA tests - AI-Prowler must be running on port 8000...
    "%PYTHON%" -m pytest "tests\mcp\test_pwa_features.py" -v -m "live_pwa" --tb=short
) else if "%~1"=="all" (
    echo Running ALL PWA tests...
    "%PYTHON%" -m pytest "tests\mcp\test_pwa_features.py" -v --tb=short
) else (
    echo Running offline PWA tests - no server needed...
    "%PYTHON%" -m pytest "tests\mcp\test_pwa_features.py" -v -m "not live_pwa" --tb=short
)

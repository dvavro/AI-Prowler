@echo off
cd /d "%~dp0"
git reset -- _git_stage.bat
echo.
echo === final staged for commit ===
git status --porcelain

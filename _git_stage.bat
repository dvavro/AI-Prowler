@echo off
cd /d "%~dp0"
git add -A
git reset -- count_tools_v817.py _git_status_check.bat
echo.
echo === staged for commit ===
git status --porcelain

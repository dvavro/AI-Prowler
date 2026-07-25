@echo off
cd /d "%~dp0"
echo === git status --porcelain ===
git status --porcelain
echo.
echo === git status (full) ===
git status

@echo off
cd /d "%~dp0"
git commit -m "Release v8.1.9"
echo.
echo === git log -1 ===
git log -1 --stat

@echo off
cd /d "%~dp0"
echo === git add -A ===
git add -A
if errorlevel 1 exit /b 1

echo.
echo === git commit ===
git commit -m "Release v8.1.5"
if errorlevel 1 exit /b 1

echo.
echo === git push origin main ===
git push origin main
if errorlevel 1 exit /b 1

echo.
echo === git tag -a v8.1.5 ===
git tag -a v8.1.5 -m "Release v8.1.5"
if errorlevel 1 exit /b 1

echo.
echo === git push origin v8.1.5 ===
git push origin v8.1.5
if errorlevel 1 exit /b 1

echo.
echo === DONE ===
git log -1 --oneline
git tag --points-at HEAD

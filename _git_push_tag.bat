@echo off
cd /d "%~dp0"
echo === git push origin main ===
git push origin main
echo.
echo === git tag -a v8.1.9 ===
git tag -a v8.1.9 -m "Release v8.1.9"
echo.
echo === git push origin v8.1.9 ===
git push origin v8.1.9
echo.
echo === git log -1 / tags ===
git log -1 --oneline
git tag --points-at HEAD

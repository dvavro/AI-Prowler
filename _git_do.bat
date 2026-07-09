@echo off
cd /d C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler
del /q "_git_check.bat" 2>nul
del /q "_git_check2.bat" 2>nul

echo === git add -A ===
git add -A
echo.
echo === git status after add ===
git status --short
echo.
echo === git commit ===
git commit -F "_commit_msg.txt"
echo.
echo === git push origin main ===
git push origin main
echo.
echo === move tag v8.0.0 to new HEAD (force, local) ===
git tag -f v8.0.0
echo.
echo === push moved tag to origin (force) ===
git push origin v8.0.0 --force
echo.
echo === verify: tag now points to ===
git show v8.0.0 --no-patch --format="tag v8.0.0 -> %%H (%%ci)"
echo === verify: HEAD is ===
git log --oneline -1

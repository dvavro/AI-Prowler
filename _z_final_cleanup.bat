@echo off
cd /d "C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
del /q _git_push.bat _git_final.bat _cleanup_last.bat 2>nul
echo === final status ===
git status --short
echo === latest tags ===
git log -1 --decorate --oneline

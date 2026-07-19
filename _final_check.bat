@echo off
cd /d "C:\Users\david\AI-Prowler-ADMIN-V8\ai-prowler-subs"
echo === ai-prowler-subs ===
git status --short
git log --oneline -2
echo.
cd /d "C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
echo === AI-Prowler (main) ===
git status --short
git log --oneline -3

@echo off
cd /d "C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
py -m pytest tests -q
exit /b %ERRORLEVEL%

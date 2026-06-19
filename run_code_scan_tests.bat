@echo off
cd /d "C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
py -m pytest tests\unit\test_code_scan_truncation.py -v
exit /b %ERRORLEVEL%

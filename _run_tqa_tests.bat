@echo off
cd /d "C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
py -m pytest tests\analysis\test_task_queue_automation.py -v
exit /b %ERRORLEVEL%

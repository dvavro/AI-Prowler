@echo off
REM ============================================================================
REM run_release_gate_remaining_tools.bat
REM ============================================================================
REM One-command release-requirement validation for the previously-untested
REM job tracker tools: email_receipt, text_invoice, text_receipt,
REM schedule_next_recurring_job, get_weather, geocode_address,
REM get_ar_aging_report.
REM
REM Run this before shipping any change that touches any of those 7 tools,
REM or the Customers-sheet "Frequency" column, or any HTML email template.
REM
REM WARNING: test_01 sends a REAL email to david.vavro1@gmail.com (the
REM email_receipt test). Expect an actual inbox delivery each run.
REM
REM SAFETY — same pattern as the other release-gate suites:
REM   - Auto-backs up before the first write.
REM   - Uses a synthetic test customer ("ZTEST Remaining Tools").
REM   - Restores the pre-suite backup automatically ONLY if every test passes.
REM   - On ANY failure, the spreadsheet is left AS-IS for failure analysis.
REM
REM REQUIREMENTS
REM   pip install openpyxl  (ANTHROPIC_API_KEY NOT required — this suite
REM   calls tools directly, it does not exercise Claude's tool selection)
REM
REM USAGE
REM   run_release_gate_remaining_tools.bat
REM   run_release_gate_remaining_tools.bat -x   (stop on first failure)
REM ============================================================================

setlocal

if "%AI_PROWLER_SRC%"=="" set AI_PROWLER_SRC=C:\Program Files\AI-Prowler
if "%AI_PROWLER_JOB_TRACKER_PATH%"=="" set AI_PROWLER_JOB_TRACKER_PATH=C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx

echo ============================================================================
echo  AI-Prowler Release Gate — Remaining Job Tracker Tools
echo  (email_receipt, text_invoice, text_receipt,
echo   schedule_next_recurring_job, get_weather, geocode_address,
echo   get_ar_aging_report)
echo ============================================================================
echo  Source   : %AI_PROWLER_SRC%
echo  Data file: %AI_PROWLER_JOB_TRACKER_PATH%
echo  Test email will be sent to: david.vavro1@gmail.com
echo ============================================================================
echo.

"%LocalAppData%\Programs\Python\Python311\python.exe" -m pytest ^
    "%~dp0test_job_tracker_remaining_tools_e2e.py" ^
    -v -s -m "job_sheet_e2e" ^
    -p no:cacheprovider ^
    %*

set EXIT_CODE=%ERRORLEVEL%

echo.
if %EXIT_CODE% EQU 0 (
    echo ============================================================================
    echo  RELEASE GATE: PASSED — spreadsheet restored to pre-test state.
    echo ============================================================================
) else (
    echo ============================================================================
    echo  RELEASE GATE: FAILED — spreadsheet LEFT AS-IS for failure analysis.
    echo ============================================================================
)

endlocal
exit /b %EXIT_CODE%

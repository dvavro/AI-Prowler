@echo off
REM ============================================================================
REM run_release_gate_contractor_workflow.bat
REM ============================================================================
REM One-command release-requirement validation for the broader contractor
REM workflow: customer lifecycle, route planning, quoting, invoicing (with a
REM REAL email send), and time logging.
REM
REM Run this before shipping any change that touches:
REM   create_customer, create_quote, update_job_spreadsheet (Customers/Quotes
REM   sheets), optimize_route, build_maps_url, get_home_address, create_invoice,
REM   email_invoice, log_time_entry, or the Customers/Quotes sheet schemas.
REM
REM WARNING: This suite sends a REAL email to david.vavro1@gmail.com
REM (TEST_EMAIL_TO in the test file) as part of the invoice-send stage.
REM Expect an actual email each time this runs. Change TEST_EMAIL_TO in
REM test_contractor_workflow_e2e.py if you need a different test inbox.
REM
REM SAFETY
REM   - Auto-backs up the spreadsheet before the first write (tool default).
REM   - Uses synthetic test customers ("ZTEST Route Contractor QA",
REM     "ZTEST Old Customer QA") — never touches real customer/quote rows.
REM   - Restores the pre-suite backup automatically ONLY if every test passes.
REM   - On ANY failure, the spreadsheet is left AS-IS with the test data
REM     still in it, for failure analysis.
REM
REM REQUIREMENTS
REM   - ANTHROPIC_API_KEY must be set in the environment.
REM   - Email must be configured in AI-Prowler Settings (SMTP or Outlook) —
REM     the invoice-send stage will fail without it.
REM   - pip install anthropic pytest openpyxl  (one-time)
REM
REM AFTER A FAILURE — same procedure as run_release_gate_job_tracker.bat:
REM   1. Read the pytest output to see which stage failed and why.
REM   2. Inspect the ZTEST rows directly in the spreadsheet if useful.
REM   3. Fix the bug, copy to the install directory, restart AI-Prowler.
REM   4. Manually restore the pre-suite backup from
REM        <spreadsheet folder>\_backups\
REM      before re-running.
REM   5. Re-run this script.
REM
REM USAGE
REM   run_release_gate_contractor_workflow.bat
REM   run_release_gate_contractor_workflow.bat -x   (stop on first failure)
REM ============================================================================

setlocal

if "%ANTHROPIC_API_KEY%"=="" (
    echo.
    echo ERROR: ANTHROPIC_API_KEY is not set in this shell.
    echo Set it first, e.g.:
    echo     set ANTHROPIC_API_KEY=sk-ant-...
    echo.
    exit /b 1
)

if "%AI_PROWLER_SRC%"=="" set AI_PROWLER_SRC=C:\Program Files\AI-Prowler
if "%AI_PROWLER_JOB_TRACKER_PATH%"=="" set AI_PROWLER_JOB_TRACKER_PATH=C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx

echo ============================================================================
echo  AI-Prowler Release Gate — Contractor Workflow E2E
echo  (customers, routing, quoting, invoicing w/ real email send, time log)
echo ============================================================================
echo  Source   : %AI_PROWLER_SRC%
echo  Data file: %AI_PROWLER_JOB_TRACKER_PATH%
echo  Test email will be sent to: david.vavro1@gmail.com
echo ============================================================================
echo.

"%LocalAppData%\Programs\Python\Python311\python.exe" -m pytest ^
    "%~dp0test_contractor_workflow_e2e.py" ^
    -v -s -m "job_sheet_e2e" ^
    -p no:cacheprovider ^
    %*

set EXIT_CODE=%ERRORLEVEL%

echo.
if %EXIT_CODE% EQU 0 (
    echo ============================================================================
    echo  RELEASE GATE: PASSED — spreadsheet restored to pre-test state.
    echo  Check david.vavro1@gmail.com for the test invoice email.
    echo ============================================================================
) else (
    echo ============================================================================
    echo  RELEASE GATE: FAILED — spreadsheet LEFT AS-IS for failure analysis.
    echo  See "AFTER A FAILURE" instructions at the top of this script.
    echo ============================================================================
)

endlocal
exit /b %EXIT_CODE%

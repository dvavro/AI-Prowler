@echo off
REM ============================================================================
REM run_release_gate_job_tracker.bat
REM ============================================================================
REM One-command release-requirement validation for the Job Tracker spreadsheet
REM MCP tools. Run this before shipping any change that touches:
REM   create_job, update_job_spreadsheet, log_time_entry, create_invoice,
REM   read_job_spreadsheet, or the Jobs_Schedule sheet schema.
REM
REM WHAT IT DOES
REM   Drives the full contractor lifecycle (create job -> schedule -> notes ->
REM   clock in/out -> complete -> invoice -> payment -> recurrence) through
REM   real natural-language prompts sent to the live Anthropic API, using the
REM   ACTUAL installed ai_prowler_mcp.py and the REAL configured job tracker
REM   spreadsheet. This is an integration/eval test, not a mock.
REM
REM SAFETY
REM   - Auto-backs up the spreadsheet before the first write (tool default).
REM   - Uses a synthetic test customer ("ZTEST Contractor QA") — never
REM     touches real customer rows.
REM   - Restores the pre-suite backup automatically ONLY if every test passes.
REM   - On ANY failure, the spreadsheet is left AS-IS with the test data
REM     still in it, for failure analysis. Re-run this script again after
REM     fixing the bug — it will re-backup and re-test from a fresh state
REM     as long as you've manually restored the previous failed run's mess
REM     first (see "AFTER A FAILURE" below).
REM
REM REQUIREMENTS
REM   - ANTHROPIC_API_KEY must be set in the environment (this script does
REM     NOT hardcode one — set it in your shell or a .env loader first).
REM   - pip install anthropic pytest  (one-time)
REM
REM AFTER A FAILURE
REM   1. Read the pytest output above to see which stage failed and why.
REM   2. Open the spreadsheet and inspect the ZTEST Contractor QA row(s)
REM      directly if useful.
REM   3. Fix the bug in ai_prowler_mcp.py, copy it to the install directory,
REM      restart AI-Prowler.
REM   4. Manually restore the pre-suite backup before re-running — find the
REM      backup timestamped just before this script's failed run in:
REM        <spreadsheet folder>\_backups\
REM      and copy it back over the live spreadsheet. This script does not
REM      auto-restore on failure by design (see SAFETY above).
REM   5. Re-run this script.
REM
REM USAGE
REM   run_release_gate_job_tracker.bat
REM   run_release_gate_job_tracker.bat -x     (stop on first failure — recommended)
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

REM Point the test suite at the real install + real spreadsheet.
REM Override these if your setup differs from the defaults baked into the
REM test file itself.
if "%AI_PROWLER_SRC%"=="" set AI_PROWLER_SRC=C:\Program Files\AI-Prowler
if "%AI_PROWLER_JOB_TRACKER_PATH%"=="" set AI_PROWLER_JOB_TRACKER_PATH=C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx

echo ============================================================================
echo  AI-Prowler Release Gate — Job Tracker Spreadsheet E2E
echo ============================================================================
echo  Source   : %AI_PROWLER_SRC%
echo  Data file: %AI_PROWLER_JOB_TRACKER_PATH%
echo ============================================================================
echo.

"%LocalAppData%\Programs\Python\Python311\python.exe" -m pytest ^
    "%~dp0test_job_tracker_e2e.py" ^
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
    echo  See "AFTER A FAILURE" instructions at the top of this script.
    echo ============================================================================
)

endlocal
exit /b %EXIT_CODE%

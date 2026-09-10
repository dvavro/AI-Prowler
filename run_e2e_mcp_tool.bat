@echo off
REM ============================================================================
REM run_e2e_mcp_tool.bat
REM ============================================================================
REM Runs AI-Prowler's MCP tool E2E release-gate suites -- separate, on
REM purpose, from run_tests.bat.
REM
REM WHY THIS IS A SEPARATE FILE
REM ------------------------------
REM 1. TOKEN COST: some of these tests hit the real Anthropic API for
REM    tool-selection evals and consume real API credits. run_tests.bat's
REM    normal suite is free (mocked/offline) and should never be blocked by,
REM    or accidentally trigger, real API spend. Running this file is a
REM    deliberate choice you make when you have credits to spend on it.
REM    (Not every file here needs credits -- see the table below.)
REM
REM 2. REAL STATE: these tests operate on REAL AI-Prowler state -- the real
REM    job tracker spreadsheet, the real learnings store, the real indexed
REM    knowledge base, real email. They must run with real ~/.ai-prowler
REM    state, never run_tests.bat's sandboxed AIPROWLER_TEST_STATE_DIR (which
REM    would break them with a confusing "not configured" error rather than
REM    a real regression -- see tests/e2e/conftest.py for the guard that
REM    catches this if it ever happens by accident).
REM
REM 3. NO CLOUDFLARE TESTS, EVER: tests/e2e/ ALSO contains a completely
REM    unrelated category of tests -- ones marked "e2e" (not "job_sheet_e2e"
REM    or "mcp_tool_e2e") that mint REAL licenses and create REAL Cloudflare
REM    tunnels, needing manual cleanup in the Cloudflare dashboard and KV
REM    store afterward. This file NEVER targets tests/e2e/ as a whole and
REM    NEVER passes "-m e2e" -- it names every file explicitly by filename
REM    and filters strictly to "job_sheet_e2e or mcp_tool_e2e", so a
REM    Cloudflare test living in the same folder can never be picked up
REM    here, today or if more files are added to any category later.
REM
REM WHAT'S INCLUDED (grows over time -- see tests/pytest.ini's marker docs
REM for the full phased rollout plan and the risk reasoning behind it)
REM ---------------------------------------------------------------------
REM   File                                          Needs API key?  Sends real msg?
REM   test_job_tracker_e2e.py                        Yes              -
REM   test_contractor_workflow_e2e.py                Yes              1 email
REM   test_route_scheduling_e2e.py                    No              -
REM   test_job_tracker_remaining_tools_e2e.py          No              1 email
REM   test_learnings_and_retrieval_e2e.py              No              1 email
REM   test_communications_e2e.py                        No              4 emails
REM   test_dev_tools_e2e.py                              No              -
REM   test_file_editing_e2e.py                           No              -
REM   test_indexing_admin_e2e.py                          No              -
REM   test_file_transfer_e2e.py                          No              -
REM   test_agentic_tasks_e2e.py                          No              -
REM   test_str_line_replace_filetypes_e2e.py             No              -
REM
REM   Phase 3 (dev tools / file editing / indexing) never touches real
REM   project files or real tracked/writable directories -- each file
REM   creates and destroys its own dedicated _e2e_sandbox_* subdirectory.
REM   reindex_all is deliberately EXCLUDED from all of Phase 3 -- see
REM   test_indexing_admin_e2e.py's module docstring for the documented
REM   ChromaDB race-condition risk that exists elsewhere in this project's
REM   own test suite (tests/pytest.ini's live_db marker).
REM
REM   SMS/text tests are intentionally NOT included -- Twilio/SMS is not
REM   configured on this machine. text_invoice/text_receipt are covered only
REM   as far as "reaches the SMS-provider-not-configured check cleanly", in
REM   test_job_tracker_remaining_tools_e2e.py.
REM
REM SAFETY
REM ---------
REM   - Every write auto-backs up first (tool default) or uses a proper
REM     dedicated delete/cleanup tool where one exists (e.g. delete_learning
REM     for the self-learning memory tests).
REM   - Uses synthetic ZTEST-prefixed / ztest_e2e-tagged data -- never
REM     touches real customer rows or real learnings.
REM   - Each suite restores/cleans up its own test data automatically, but
REM     ONLY if every test in that suite passed. On any failure, that
REM     suite's data is left AS-IS for inspection -- fix the bug, then
REM     re-run just that file.
REM
REM REQUIREMENTS
REM ---------------
REM   pip install anthropic pytest openpyxl
REM   set ANTHROPIC_API_KEY=sk-ant-...   (only needed for the 2 files above
REM     marked "Yes" -- the other 3 run fine without it)
REM   Email configured in AI-Prowler Settings (SMTP or Outlook).
REM   AIPROWLER_TEST_STATE_DIR must NOT be set in this shell.
REM
REM USAGE
REM --------
REM   run_e2e_mcp_tool.bat                        -- run everything
REM   run_e2e_mcp_tool.bat -x                     -- stop on first failure
REM   run_e2e_mcp_tool.bat -k email                 -- keyword filter (pytest -k)
REM   run_e2e_mcp_tool.bat -k learnings_and_retrieval
REM                                                -- narrow to one file's tests
REM     (all files are always collected -- -k filters WITHIN that collection,
REM     it does not add a new target)
REM ============================================================================

setlocal

REM Refuse to run under run_tests.bat's sandbox env var -- fail here, fast,
REM rather than let pytest's own conftest guard produce a wall of output.
if not "%AIPROWLER_TEST_STATE_DIR%"=="" (
    echo.
    echo ERROR: AIPROWLER_TEST_STATE_DIR is set to "%AIPROWLER_TEST_STATE_DIR%"
    echo These tests need REAL AI-Prowler state and must not run sandboxed.
    echo Open a fresh shell ^(not one that ran run_tests.bat^) and try again.
    echo.
    exit /b 1
)

if "%AI_PROWLER_SRC%"=="" set AI_PROWLER_SRC=C:\Program Files\AI-Prowler
if "%AI_PROWLER_JOB_TRACKER_PATH%"=="" set AI_PROWLER_JOB_TRACKER_PATH=C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx

echo ============================================================================
echo  AI-Prowler MCP Tool E2E  (separate from run_tests.bat)
echo ============================================================================
echo  Source   : %AI_PROWLER_SRC%
echo  Data file: %AI_PROWLER_JOB_TRACKER_PATH%
echo  2 of 5 files need ANTHROPIC_API_KEY and use real API credits.
echo  Sends up to 3 real emails per full run (invoice, receipt, learnings report).
echo  NEVER touches Cloudflare/licensing "e2e" tests.
echo ============================================================================
echo.

REM Always target every file explicitly by name -- NEVER fall back to
REM scanning tests\ as a whole, even when extra pytest flags are passed
REM through (e.g. -x, -k, --collect-only). A directory-wide scan would
REM import every test module in the repo, including unrelated GUI/unit
REM tests that call sys.exit() at import time outside their normal harness
REM context, crashing pytest's own collector -- confirmed the hard way
REM during this file's own testing.
set FILES=tests\e2e\test_job_tracker_e2e.py tests\e2e\test_contractor_workflow_e2e.py tests\e2e\test_route_scheduling_e2e.py tests\e2e\test_job_tracker_remaining_tools_e2e.py tests\e2e\test_learnings_and_retrieval_e2e.py tests\e2e\test_communications_e2e.py tests\e2e\test_dev_tools_e2e.py tests\e2e\test_file_editing_e2e.py tests\e2e\test_indexing_admin_e2e.py tests\e2e\test_file_transfer_e2e.py tests\e2e\test_agentic_tasks_e2e.py tests\e2e\test_str_line_replace_filetypes_e2e.py

cd /d "%~dp0"

"%LocalAppData%\Programs\Python\Python311\python.exe" -m pytest ^
    %FILES% ^
    -v -s -m "job_sheet_e2e or mcp_tool_e2e" -p no:cacheprovider ^
    %*

set EXIT_CODE=%ERRORLEVEL%
cd /d "%~dp0"

echo.
if %EXIT_CODE% EQU 0 (
    echo ============================================================================
    echo  ALL SUITES PASSED
    echo ============================================================================
) else (
    echo ============================================================================
    echo  SOME TESTS FAILED -- see output above. Failed suites left their test
    echo  data in place for inspection; fix the bug, then re-run.
    echo ============================================================================
)

endlocal
exit /b %EXIT_CODE%

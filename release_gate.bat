@echo off
REM ════════════════════════════════════════════════════════════════════════
REM AI-Prowler -- RELEASE GATE
REM ════════════════════════════════════════════════════════════════════════
REM
REM Runs every automated test in BOTH repos and reports a single verdict.
REM Use this BEFORE building or releasing a new version of AI-Prowler.
REM
REM What's covered:
REM   1. AI-Prowler main suite      (tests/ directory)      ~637 tests
REM      Includes: unit, mcp-tool, GUI, learning, reindex,
REM      v7.0.1 capability-matrix tests (test_role_tool_matrix.py), and
REM      installer script tests (tests/installer/test_installer_scripts.py)
REM   2. ai-prowler-subs CLI suite  (test_business_cli.py)  ~34 tests
REM
REM What is NOT covered (manual checks still required even on green):
REM   - Live Worker /license/* endpoints (wrangler deploy + curl)
REM   - GUI visual rendering (Tk widgets, no headless harness)
REM   - Inno Setup installer behavior on a fresh VM
REM   - End-to-end mint/revoke round-trip through the GUI
REM
REM Exit codes:
REM   0 = ALL test suites passed       --> safe to release
REM   1 = at least one test failed     --> DO NOT release
REM   2 = environment problem          --> fix paths/python before retrying
REM
REM Usage:
REM   release_gate.bat                 (run all tests, print verdict, exit)
REM
REM No flags. By design. Release gate is uncompromising; if you want to skip
REM a suite you can run it directly. Add this to git so future-you and any
REM future collaborator have one canonical answer to "what do I run before
REM tagging a release?"
REM ════════════════════════════════════════════════════════════════════════

setlocal

REM ── Path configuration ───────────────────────────────────────────────────
REM Edit these two lines if you move either repo.
set "AIPROWLER_ROOT=C:\Users\david\AI-Prowler_V700_to_V701_work\AI-Prowler"
set "SUBS_ROOT=C:\Users\david\AI-Prowler-ADMIN-V7\ai-prowler-subs"

REM ── Environment sanity checks (fail fast with clear messages) ────────────
if not exist "%AIPROWLER_ROOT%\rag_preprocessor.py" (
    echo [ERROR] AI-Prowler work tree not found at:
    echo         %AIPROWLER_ROOT%
    echo         Edit AIPROWLER_ROOT at the top of this script.
    exit /b 2
)
if not exist "%SUBS_ROOT%\manage_subscriptions.py" (
    echo [ERROR] ai-prowler-subs repo not found at:
    echo         %SUBS_ROOT%
    echo         Edit SUBS_ROOT at the top of this script.
    exit /b 2
)
where py >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 'py' launcher not found on PATH.
    echo         Install Python from python.org or fix your PATH.
    exit /b 2
)

REM ── Header ───────────────────────────────────────────────────────────────
set "START_TIME=%TIME%"
echo ============================================================
echo  AI-Prowler -- RELEASE GATE
echo  Started: %DATE% %TIME%
echo ============================================================
echo.

REM ── Suite 1: AI-Prowler main test suite ──────────────────────────────────
echo [1/3] Running AI-Prowler main test suite ...
echo       Expected: ~637 tests (unit, mcp, gui, learning, reindex, installer)
echo.
cd /d "%AIPROWLER_ROOT%"
py -m pytest tests -m "not e2e" -v
set "SUITE1_RC=%ERRORLEVEL%"
echo.
if "%SUITE1_RC%"=="0" (
    echo [1/3] AI-Prowler main suite: PASSED
) else (
    echo [1/3] AI-Prowler main suite: FAILED ^(exit code %SUITE1_RC%^)
)
echo.

REM ── Suite 2: subscription manager CLI test suite ─────────────────────────
echo [2/3] Running ai-prowler-subs CLI test suite ...
echo       Expected: ~34 tests, ~0:01 runtime
echo.
cd /d "%SUBS_ROOT%"
py -m pytest test_business_cli.py -v
set "SUITE2_RC=%ERRORLEVEL%"
echo.
if "%SUITE2_RC%"=="0" (
    echo [2/3] ai-prowler-subs CLI suite: PASSED
) else (
    echo [2/3] ai-prowler-subs CLI suite: FAILED ^(exit code %SUITE2_RC%^)
)
echo.

REM ── Suite 3: E2E server isolation tests ──────────────────────────────────
echo [3/3] Running E2E server isolation tests ...
echo       Spawns a real AI-Prowler Server subprocess, probes over HTTP.
echo       Covers: auth/identity (ST1), scope isolation (ST2), concurrent (ST3)
echo       Requires: pip install mcp[cli]
echo.
cd /d "%AIPROWLER_ROOT%"
py -m pytest tests/e2e -v -m e2e
set "SUITE3_RC=%ERRORLEVEL%"
echo.
if "%SUITE3_RC%"=="0" (
    echo [3/3] E2E server isolation suite: PASSED
) else (
    echo [3/3] E2E server isolation suite: FAILED ^(exit code %SUITE3_RC%^)
)
echo.

REM ── Verdict ──────────────────────────────────────────────────────────────
echo ============================================================
echo  RELEASE GATE VERDICT
echo ============================================================
echo  Started: %START_TIME%
echo  Ended  : %TIME%
echo.
if "%SUITE1_RC%"=="0" (
    echo   Suite 1 ^(AI-Prowler main^):         PASS
) else (
    echo   Suite 1 ^(AI-Prowler main^):         FAIL
)
if "%SUITE2_RC%"=="0" (
    echo   Suite 2 ^(ai-prowler-subs CLI^):     PASS
) else (
    echo   Suite 2 ^(ai-prowler-subs CLI^):     FAIL
)
if "%SUITE3_RC%"=="0" (
    echo   Suite 3 ^(E2E server isolation^):    PASS
) else (
    echo   Suite 3 ^(E2E server isolation^):    FAIL
)
echo.

if "%SUITE1_RC%"=="0" if "%SUITE2_RC%"=="0" if "%SUITE3_RC%"=="0" (
    echo  [OK] ALL TESTS PASSED -- safe to release.
    echo.
    echo  MANUAL CHECKS STILL REQUIRED before tagging:
    echo    - Live Worker endpoints  ^(wrangler deploy + curl test^)
    echo    - GUI visual rendering   ^(launch RUN_SUBS_GUI.bat, click each tab^)
    echo    - Installer test         ^(install on a clean VM, run end-to-end^)
    echo    - Git working tree clean ^(git status, all changes pushed^)
    exit /b 0
)

echo  [FAIL] RELEASE GATE FAILED -- DO NOT release this build.
echo         Review the suite output above for the specific failures.
exit /b 1

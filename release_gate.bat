@echo off
REM ════════════════════════════════════════════════════════════════════════
REM AI-Prowler -- RELEASE GATE
REM ════════════════════════════════════════════════════════════════════════
REM
REM Runs every automated test across all repos and reports a single verdict.
REM Use this BEFORE building or releasing a new version of AI-Prowler.
REM
REM What's covered:
REM   1. AI-Prowler main suite            (tests/ directory)      ~1980+ tests
REM      Includes: unit, mcp-tool, GUI, learning, reindex,
REM      v8.0.0 capability-matrix tests (test_role_tool_matrix.py), and
REM      installer script tests (tests/installer/test_installer_scripts.py).
REM      Also covers everything added since v8.0.0: list_analysis_tasks,
REM      cleanup_job_logs, and the Proactive Alerts auto-save redesign.
REM   2. ai-prowler-subscription Worker suite (Vitest)             ~50 tests
REM      provision.test.js, subscription_flow.test.js (the real end-to-end
REM      mint/upgrade/downgrade/over-quota/seat-suspension flow coverage),
REM      and newsletter_send.test.js (admin "send to all subscribers").
REM   3. ai-prowler-telemetry Worker suite (Vitest)                 ~20 tests
REM      newsletter.test.js — subscribe/unsubscribe endpoints (the desktop
REM      Home-tab opt-in banner posts here) and the admin subscriber list.
REM   4. E2E server isolation tests       (tests/e2e)
REM      Spawns a real AI-Prowler Server subprocess, probes over HTTP.
REM      Covers: auth/identity (ST1), scope isolation (ST2), concurrent (ST3)
REM
REM KNOWN GAP — flagged deliberately rather than silently ignored:
REM   ai-prowler-subs (the Python Subscription Manager GUI/CLI at
REM   %SUBS_ROOT%) has NO automated test suite of any kind right now.
REM   An earlier version of this script referenced a test_business_cli.py
REM   that does not exist in this repo (likely a leftover from an earlier
REM   CLI-only design, before subscription_manager_gui.py existed) — that
REM   phantom suite has been removed rather than left silently broken.
REM   subs_client.py / subscription_manager_gui.py are covered only by the
REM   manual GUI check below. Build a real suite for this repo eventually.
REM
REM What is NOT covered (manual checks still required even on green):
REM   - Live Worker /license/* and /newsletter/* endpoints (wrangler deploy
REM     + curl) — the Vitest suites above test Worker LOGIC against mocked
REM     bindings, not the actually-deployed Worker.
REM   - ai-prowler-subs — no automated suite exists (see KNOWN GAP above).
REM   - GUI visual rendering (Tk widgets, no headless harness)
REM   - Inno Setup installer behavior on a fresh VM
REM   - End-to-end mint/revoke round-trip through the GUI itself
REM
REM Exit codes:
REM   0 = ALL test suites passed       --> safe to release
REM   1 = at least one test failed     --> DO NOT release
REM   2 = environment problem          --> fix paths/python/node before retrying
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
REM Edit these lines if you move any repo.
set "AIPROWLER_ROOT=C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
set "SUBS_ROOT=C:\Users\david\AI-Prowler-ADMIN-V8\ai-prowler-subs"
set "SUBSCRIPTION_ROOT=C:\Users\david\AI-Prowler-ADMIN-V8\ai-prowler-subscription"
set "TELEMETRY_ROOT=C:\Users\david\AI-Prowler-ADMIN-V8\ai-prowler-telemetry"

REM ── Environment sanity checks (fail fast with clear messages) ────────────
if not exist "%AIPROWLER_ROOT%\rag_preprocessor.py" (
    echo [ERROR] AI-Prowler work tree not found at:
    echo         %AIPROWLER_ROOT%
    echo         Edit AIPROWLER_ROOT at the top of this script.
    exit /b 2
)
if not exist "%SUBS_ROOT%\subs_client.py" (
    echo [ERROR] ai-prowler-subs repo not found at:
    echo         %SUBS_ROOT%
    echo         Edit SUBS_ROOT at the top of this script.
    exit /b 2
)
if not exist "%SUBSCRIPTION_ROOT%\package.json" (
    echo [ERROR] ai-prowler-subscription repo not found at:
    echo         %SUBSCRIPTION_ROOT%
    echo         Edit SUBSCRIPTION_ROOT at the top of this script.
    exit /b 2
)
if not exist "%TELEMETRY_ROOT%\package.json" (
    echo [ERROR] ai-prowler-telemetry repo not found at:
    echo         %TELEMETRY_ROOT%
    echo         Edit TELEMETRY_ROOT at the top of this script.
    exit /b 2
)
where py >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 'py' launcher not found on PATH.
    echo         Install Python from python.org or fix your PATH.
    exit /b 2
)
where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 'npm' not found on PATH.
    echo         Required for the ai-prowler-subscription and
    echo         ai-prowler-telemetry Worker test suites. Install
    echo         Node.js from nodejs.org or fix your PATH.
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
echo [1/4] Running AI-Prowler main test suite ...
echo       Expected: ~1980+ tests (unit, mcp, gui, learning, reindex, installer)
echo.
cd /d "%AIPROWLER_ROOT%"
py -m pytest tests -m "not e2e" -v -p no:logging --tb=short --junit-xml="%TEMP%\suite1_results.xml"
REM Parse the JUnit XML for pass/fail — immune to teardown crashes since
REM pytest writes the XML before teardown. Zero failures = PASS.
py -c "import sys,xml.etree.ElementTree as ET; r=ET.parse(r'%TEMP%\suite1_results.xml').getroot(); f=int(r.get('failures',0))+int(r.get('errors',0)); sys.exit(0 if f==0 else 1)"
set "SUITE1_RC=%ERRORLEVEL%"
echo.
if "%SUITE1_RC%"=="0" (
    echo [1/4] AI-Prowler main suite: PASSED
) else (
    echo [1/4] AI-Prowler main suite: FAILED ^(exit code %SUITE1_RC%^)
)
echo.

REM ── Suite 2: ai-prowler-subscription Worker suite (Vitest) ───────────────
REM provision.test.js + subscription_flow.test.js (mint/upgrade/downgrade/
REM over-quota/seat-suspension end-to-end flow) + newsletter_send.test.js
REM (admin "send to all subscribers" endpoint).
echo [2/4] Running ai-prowler-subscription Worker suite ...
echo       Expected: ~50 tests, 3 files, ~0:01 runtime
echo.
cd /d "%SUBSCRIPTION_ROOT%"
call npm install --silent
call npm test
set "SUITE2_RC=%ERRORLEVEL%"
echo.
if "%SUITE2_RC%"=="0" (
    echo [2/4] ai-prowler-subscription Worker suite: PASSED
) else (
    echo [2/4] ai-prowler-subscription Worker suite: FAILED ^(exit code %SUITE2_RC%^)
)
echo.

REM ── Suite 3: ai-prowler-telemetry Worker suite (Vitest) ───────────────────
REM newsletter.test.js — subscribe/unsubscribe endpoints (the desktop Home
REM tab opt-in banner posts here) and the admin subscriber-list endpoint.
echo [3/4] Running ai-prowler-telemetry Worker suite ...
echo       Expected: ~20 tests, 1 file, ~0:01 runtime
echo.
cd /d "%TELEMETRY_ROOT%"
call npm install --silent
call npm test
set "SUITE3_RC=%ERRORLEVEL%"
echo.
if "%SUITE3_RC%"=="0" (
    echo [3/4] ai-prowler-telemetry Worker suite: PASSED
) else (
    echo [3/4] ai-prowler-telemetry Worker suite: FAILED ^(exit code %SUITE3_RC%^)
)
echo.

REM ── Suite 4: E2E server isolation tests ──────────────────────────────────
echo [4/4] Running E2E server isolation tests ...
echo       Spawns a real AI-Prowler Server subprocess, probes over HTTP.
echo       Covers: auth/identity (ST1), scope isolation (ST2), concurrent (ST3)
echo       Requires: pip install mcp[cli]
echo.
cd /d "%AIPROWLER_ROOT%"
py -m pytest tests/e2e -v -m e2e
set "SUITE4_RC=%ERRORLEVEL%"
echo.
if "%SUITE4_RC%"=="0" (
    echo [4/4] E2E server isolation suite: PASSED
) else (
    echo [4/4] E2E server isolation suite: FAILED ^(exit code %SUITE4_RC%^)
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
    echo   Suite 1 ^(AI-Prowler main^):                 PASS
) else (
    echo   Suite 1 ^(AI-Prowler main^):                 FAIL
)
if "%SUITE2_RC%"=="0" (
    echo   Suite 2 ^(ai-prowler-subscription Worker^):  PASS
) else (
    echo   Suite 2 ^(ai-prowler-subscription Worker^):  FAIL
)
if "%SUITE3_RC%"=="0" (
    echo   Suite 3 ^(ai-prowler-telemetry Worker^):     PASS
) else (
    echo   Suite 3 ^(ai-prowler-telemetry Worker^):     FAIL
)
if "%SUITE4_RC%"=="0" (
    echo   Suite 4 ^(E2E server isolation^):            PASS
) else (
    echo   Suite 4 ^(E2E server isolation^):            FAIL
)
echo.

if "%SUITE1_RC%"=="0" if "%SUITE2_RC%"=="0" if "%SUITE3_RC%"=="0" if "%SUITE4_RC%"=="0" (
    echo  [OK] ALL TESTS PASSED -- safe to release.
    echo.
    echo  MANUAL CHECKS STILL REQUIRED before tagging:
    echo    - Live Worker endpoints  ^(wrangler deploy + curl test, including
    echo      /newsletter/subscribe, /newsletter/unsubscribe, /newsletter/send^)
    echo    - GUI visual rendering   ^(launch RUN_SUBS_GUI.bat, click each tab,
    echo      including the new Newsletter tab^)
    echo    - Proactive Alerts panel ^(launch AI-Prowler, confirm per-job
    echo      toggles auto-save and the engine auto-starts/stops correctly^)
    echo    - Installer test         ^(install on a clean VM, run end-to-end^)
    echo    - Git working tree clean ^(git status, all changes pushed, in ALL
    echo      FOUR repos: AI-Prowler, ai-prowler-subs, ai-prowler-subscription,
    echo      ai-prowler-telemetry^)
    exit /b 0
)

echo  [FAIL] RELEASE GATE FAILED -- DO NOT release this build.
echo         Review the suite output above for the specific failures.
exit /b 1

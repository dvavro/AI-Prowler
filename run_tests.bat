@echo off
echo [run_tests] Loading token...
if not defined AIPROWLER_JOBS_TOKEN for /f "delims=" %%T in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content $env:USERPROFILE\.ai-prowler\config.json | ConvertFrom-Json).remote_token"') do set AIPROWLER_JOBS_TOKEN=%%T
REM Load AIPROWLER_JOBS_TOKEN from config.json if not set
if not defined AIPROWLER_JOBS_TOKEN (
    for /f "delims=" %%T in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=$env:APPDATA+'\AI-Prowler\config.json'; (Get-Content $p | ConvertFrom-Json).bearer_token"') do set AIPROWLER_JOBS_TOKEN=%%T
)
REM =====================================================================
REM  run_tests.bat — AI-Prowler test runner
REM
REM  Uses "python -m pytest" instead of "pytest" directly to avoid the
REM  common Windows PATH issue where pytest.exe is not found even after
REM  install (Scripts folder not on PATH, Windows Store Python alias
REM  conflicts, etc.).
REM
REM  DEFAULT RUN (safe — no real Cloudflare tunnels or live Worker):
REM    run_tests.bat                                        — run all safe tests
REM    run_tests.bat tests\gui\                             — run GUI tests only
REM    run_tests.bat tests\mcp_tests\                             — run MCP tests only
REM    run_tests.bat tests\unit\                            — run unit tests only
REM    run_tests.bat tests\subscription\                    — subscription mocks only
REM    run_tests.bat tests\analysis\                        — AI analysis tests
REM    run_tests.bat tests\unit\messaging\                  — SMS/WhatsApp tests
REM    run_tests.bat tests\ -k encoding                     — keyword filter
REM    run_tests.bat tests\ -m "not slow"                   — skip slow tests
REM
REM  *** EXCLUDED FROM DEFAULT RUN (pytest.ini: -m "not e2e and not live_worker") ***
REM
REM    e2e — MINTS REAL LICENSES + CREATES REAL CLOUDFLARE TUNNELS.
REM    Only run when explicitly testing the provisioning flow.
REM    NEVER run by accident — pollutes Cloudflare tunnel list and KV store.
REM
REM      run_tests.bat tests\test_tunnel_ingress_e2e.py -m e2e -v
REM      run_tests.bat tests\e2e\ -m e2e -v
REM
REM    live_worker — hits the LIVE production Worker at api.ai-prowler.com.
REM    Only run when explicitly validating the Worker API contract.
REM
REM      run_tests.bat tests\subscription\test_worker_api.py -v -m live_worker
REM =====================================================================
setlocal

REM ── Database sandbox ──────────────────────────────────────────────────────────
REM AIPROWLER_TEST_STATE_DIR is read by rag_preprocessor.py at module import
REM time to redirect CHROMA_DB_PATH away from ~/AI-Prowler/rag_database to a
REM throwaway temp directory.  Without this, any test that bypasses isolated_env
REM (or that loses the monkeypatch through a subprocess boundary) writes to the
REM real production database and can corrupt it via the ChromaDB HNSW cold-init
REM race condition (v9.0.1 — see rag_preprocessor.get_chroma_client() docstring).
set AIPROWLER_TEST_STATE_DIR=%TEMP%\ai_prowler_test_%RANDOM%
echo [run_tests] Sandbox DB: %AIPROWLER_TEST_STATE_DIR%

set PYTHON=%LocalAppData%\Programs\Python\Python311\python.exe

REM Fall back to "python" on PATH only if the explicit path doesn't exist.
REM Using the explicit path avoids the Windows Store Python alias and
REM any PATH ordering issues entirely.
if not exist "%PYTHON%" (
    echo WARNING: Python not found at %PYTHON%
    echo Trying python on PATH...
    set PYTHON=python
)

REM Auto-install pytest and pyflakes if missing (gets uninstalled with AI-Prowler).
"%PYTHON%" -c "import pytest" 2>nul || "%PYTHON%" -m pip install pytest pytest-mock pytest-asyncio pyflakes --quiet
"%PYTHON%" -c "import playwright" 2>nul || "%PYTHON%" -m pip install playwright --quiet

REM Default to tests\ with verbose output if no args given.
REM Deliberately NOT passing an explicit -m here — pytest.ini's own addopts
REM already carries the full, current exclusion list (e2e, manual,
REM live_remote, live_pwa, live_db, job_sheet_e2e, mcp_tool_e2e). A second
REM hardcoded -m HERE used to override that list on the command line
REM (pytest takes the last -m it sees), and this one had drifted stale —
REM missing job_sheet_e2e and mcp_tool_e2e entirely, so real-API-cost /
REM real-state MCP tool E2E tests silently ran every time run_tests.bat
REM was invoked with no arguments, alongside AIPROWLER_TEST_STATE_DIR
REM sandboxing that makes those specific tests hang instead of failing
REM cleanly. Single source of truth for the exclusion list is now
REM pytest.ini alone — update it there, never re-add an -m here.
REM ── Log file (2026-09-24) ────────────────────────────────────────────────
REM Screen output was the ONLY record of a test run — closed the window or
REM scrolled past it and it was gone. Every run now ALSO writes a full copy
REM to test_logs\ next to this script, timestamped so runs don't overwrite
REM each other. %~dp0 (this script's own directory) is used rather than a
REM hardcoded path so this works identically whether run from the dev
REM working copy or a real install — it never needs its own entry in
REM update_install.bat/MANIFEST_FILES/AI-Prowler-Setup.iss the way an
REM app source file would, since it's a dev-only tool, not something an
REM end-user install ships (see run_tests.bat's absence from those three
REM lists — deliberate, not an oversight of the kind mcp_tool_catalog.py
REM was).
REM
REM Piped through PowerShell's Tee-Object for simultaneous screen+file
REM output (cmd.exe has no built-in tee). This is NOT a naive
REM "pytest | powershell" pipe, which would silently lose pytest's real
REM exit code (a plain pipe's errorlevel reflects the LAST stage, i.e.
REM Tee-Object's, not pytest's) — that would be a serious regression,
REM since release_gate.bat's Suite 4 calls this script and reads
REM %ERRORLEVEL% immediately after to decide pass/fail. Instead, a single
REM PowerShell invocation runs pytest itself via the native call operator
REM (&), pipes ITS OWN output to Tee-Object, then explicitly
REM "exit $LASTEXITCODE". $LASTEXITCODE is only ever set by a native
REM executable (pytest.exe/python.exe here) — Tee-Object is a cmdlet and
REM never touches it — so it still holds pytest's real exit code right up
REM until powershell.exe exits with it, which is exactly the value
REM run_tests.bat's own caller sees in %ERRORLEVEL% afterward. Verified
REM against release_gate.bat's own Suite 4 usage before shipping this.
set "LOGDIR=%~dp0test_logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>&1
set "STAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "STAMP=%STAMP: =0%"
set "LOGFILE=%LOGDIR%\test_run_%STAMP%.log"

REM 2026-09-24, second fix: the ForEach-Object + per-line Add-Content
REM approach above (kept here in this comment for the record) turned out to
REM have a real problem on a full, verbose, 5000+-test run: Add-Content
REM opens, seeks-to-end, writes, and closes the file EVERY SINGLE LINE —
REM for thousands of lines that's thousands of file-handle round trips,
REM slow enough that the run appeared to never print its final summary at
REM all (reported directly: "did not print the end result"). Tee-Object
REM keeps ONE file handle open for the whole pipeline — dramatically
REM cheaper — so it's back in use for the live tee; its missing -Encoding
REM parameter (confirmed absent on this machine's PowerShell, see the
REM earlier comment in git history) is instead solved by a single,
REM one-time UTF-16LE -> UTF-8 conversion pass AFTER the run finishes,
REM rather than per-line during it.
set "LOGFILE_RAW=%LOGFILE%.rawutf16"
if "%~1"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%PYTHON%' -m pytest tests\ -v -m 'not live_worker' --ignore=tests/e2e --ignore=tests/gui_remote_e2e 2>&1 | Tee-Object -FilePath '%LOGFILE_RAW%'; exit $LASTEXITCODE"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%PYTHON%' -m pytest %* 2>&1 | Tee-Object -FilePath '%LOGFILE_RAW%'; exit $LASTEXITCODE"
)
set "TEST_RC=%ERRORLEVEL%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content -Path '%LOGFILE_RAW%' -Encoding Unicode) | Set-Content -Path '%LOGFILE%' -Encoding utf8" >nul 2>&1
del "%LOGFILE_RAW%" >nul 2>&1

echo.
echo [run_tests] Full log saved to: %LOGFILE%

endlocal & exit /b %TEST_RC%

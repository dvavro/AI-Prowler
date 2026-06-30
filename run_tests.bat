@echo off
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
REM    run_tests.bat tests\mcp\                             — run MCP tests only
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

set PYTHON=%LocalAppData%\Programs\Python\Python311\python.exe

REM Fall back to "python" on PATH only if the explicit path doesn't exist.
REM Using the explicit path avoids the Windows Store Python alias and
REM any PATH ordering issues entirely.
if not exist "%PYTHON%" (
    echo WARNING: Python not found at %PYTHON%
    echo Trying python on PATH...
    set PYTHON=python
)

REM Default to tests\ with verbose output if no args given.
if "%~1"=="" (
    "%PYTHON%" -m pytest tests\ -v
) else (
    "%PYTHON%" -m pytest %*
)

endlocal

@echo off
REM =====================================================================
REM  run_tests.bat — AI-Prowler test runner
REM
REM  Uses "python -m pytest" instead of "pytest" directly to avoid the
REM  common Windows PATH issue where pytest.exe is not found even after
REM  install (Scripts folder not on PATH, Windows Store Python alias
REM  conflicts, etc.).
REM
REM  Usage:
REM    run_tests.bat                                        — run all tests
REM    run_tests.bat tests\gui\                             — run GUI tests only
REM    run_tests.bat tests\mcp\                             — run MCP tests only
REM    run_tests.bat tests\unit\                            — run unit tests only
REM    run_tests.bat tests\unit\test_pdf_extraction.py      — PDF table extraction tests
REM    run_tests.bat tests\unit\test_image_formats.py       — HEIC/WebP image OCR tests
REM    run_tests.bat tests\unit\test_contractor_tools.py    — email/SMS/scheduling/time/AR tests
REM    run_tests.bat tests\mcp\test_fuzzy_and_line_replace.py  — fuzzy_replace / line_replace tests
REM    run_tests.bat tests\unit\messaging\                  — two-way SMS / WhatsApp tests
REM    run_tests.bat tests\subscription\                    — Stripe, activation, seats, worker API
REM    run_tests.bat tests\analysis\                        — AI analysis queue and custom tasks
REM    run_tests.bat tests\gui\test_config_encoding.py      — single file
REM    run_tests.bat tests\ -k encoding                     — run tests matching a keyword
REM    run_tests.bat tests\ -k PDF                          — run all PDF-* tests
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

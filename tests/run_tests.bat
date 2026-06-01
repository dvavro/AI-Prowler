@echo off
REM ──────────────────────────────────────────────────────────────────────────
REM AI-Prowler 6.0.0 — Windows test runner (Phase 2)
REM
REM Run from your AI-Prowler source root:
REM     C:\Users\david\AI-Prowler> tests\run_tests.bat
REM
REM Flags:
REM     unit     run only the functional unit tests (Section 4-6 of test plan)
REM     mcp      run only the MCP-tool tests (Section G-MCP-*)
REM     gui      run only the GUI tests (Section G-IDX/G-UPD/G-DB)
REM     fast     skip @pytest.mark.slow tests (no embedding-model load)
REM     bugs     run only the bug-exercising tests (now expected to pass)
REM     <name>   pass through to pytest -k (substring match)
REM ──────────────────────────────────────────────────────────────────────────

setlocal

if not exist rag_preprocessor.py (
    echo [ERROR] rag_preprocessor.py not found in current directory.
    echo         Run this from your AI-Prowler source root, or set AI_PROWLER_SRC.
    exit /b 1
)

if "%1"=="unit" (
    py -m pytest tests\unit
    goto :end
)

if "%1"=="mcp" (
    py -m pytest tests\mcp
    goto :end
)

if "%1"=="gui" (
    py -m pytest tests\gui
    goto :end
)

if "%1"=="fast" (
    py -m pytest tests -m "not slow"
    goto :end
)

if "%1"=="bugs" (
    py -m pytest tests -k "B_01 or B_02 or B_03 or B_04 or B_05 or B_07 or B_08 or F_TRK_04 or F_TRK_05 or F_TRK_15 or F_UPD_07 or C_REINDEX"
    goto :end
)

if not "%1"=="" (
    py -m pytest tests -k "%1"
    goto :end
)

REM Default: run everything
py -m pytest tests

:end
endlocal
exit /b %ERRORLEVEL%

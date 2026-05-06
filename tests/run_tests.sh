#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# AI-Prowler 6.0.0 — Linux/macOS test runner
#
# Run from the AI-Prowler source root, e.g.:
#     ~/AI-Prowler$ ./tests/run_tests.sh
#
# Flags:
#     fast    skip @pytest.mark.slow tests (no embedding model load)
#     bugs    run only the bug-exercising tests
#     <name>  pass through to pytest -k (substring match)
# ──────────────────────────────────────────────────────────────────────────

set -e

if [ ! -f "rag_preprocessor.py" ]; then
    echo "[ERROR] rag_preprocessor.py not found in current directory."
    echo "        Run this from your AI-Prowler source root, or set AI_PROWLER_SRC."
    exit 1
fi

case "$1" in
    fast)
        exec python3 -m pytest tests -m "not slow"
        ;;
    bugs)
        exec python3 -m pytest tests -k "B_01 or B_02 or B_03 or B_04 or B_05 or B_07 or B_08 or F_TRK_04 or F_TRK_05 or F_TRK_15 or F_UPD_07"
        ;;
    "")
        exec python3 -m pytest tests
        ;;
    *)
        exec python3 -m pytest tests -k "$1"
        ;;
esac

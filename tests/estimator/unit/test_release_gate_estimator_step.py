"""Coder 1 Sprint 27: the release gate's Estimator step (release_gate.bat Suite 5).

Planned Sprint 18 (Tester 1) asked for release_gate.bat to be updated for the
Estimator. The gate's Suite 5 used to call run_tests_estimate.bat, the runner
from before the Coder 1 and Coder 2 tracks were unified into
run_tests_estimator.bat, and still advertised the suite at ~630 tests. These
tests pin the gate to the unified runner so it cannot quietly drift back.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GATE = REPO_ROOT / "release_gate.bat"


def _gate_text():
    return GATE.read_text(encoding="utf-8", errors="replace")


def test_s27_g01_gate_calls_the_unified_estimator_runner():
    assert "call run_tests_estimator.bat" in _gate_text()


def test_s27_g02_gate_does_not_call_the_old_runner():
    assert "call run_tests_estimate.bat" not in _gate_text()


def test_s27_g03_the_runner_the_gate_calls_exists():
    assert (REPO_ROOT / "run_tests_estimator.bat").is_file()

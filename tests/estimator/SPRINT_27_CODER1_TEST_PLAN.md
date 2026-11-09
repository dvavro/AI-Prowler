# Sprint 27 (Coder 1) — Test Plan

**Sprint:** 27 (Coder 1 part of planned Sprint 18, Phase 8 — the Tester 1 item: `release_gate.bat` updated for the Estimator)
**Date:** 2026-11-09

## Scope

The release gate's Estimator step (Suite 5 of `release_gate.bat`). Out of scope: running the full release gate end to end (all five suites) — that stays a release-time activity; this sprint verifies the Estimator step the gate now calls, by calling the same runner the same way.

## How to run

- Guard tests only: `run_tests_estimator.bat coder1 -k release_gate`
- Full Estimator suite: `run_tests_estimator.bat`

## What was built

- `release_gate.bat` Suite 5 now calls `run_tests_estimator.bat`, the unified Coder 1 + Coder 2 runner. It previously called `run_tests_estimate.bat`, the older runner from before the two tracks were unified, and advertised the Estimator suite at ~630 tests; the count is corrected to ~1,300 in the header, the Suite 5 comment and the Expected echo. A dated comment in Suite 5 records the change and why.
- Guard tests in `tests/estimator/unit/test_release_gate_estimator_step.py` pin the gate to the unified runner so it cannot quietly drift back.

## Tests

| ID | Test | What it proves |
| --- | --- | --- |
| S27-G01 | test_s27_g01_gate_calls_the_unified_estimator_runner | release_gate.bat calls run_tests_estimator.bat |
| S27-G02 | test_s27_g02_gate_does_not_call_the_old_runner | release_gate.bat no longer calls run_tests_estimate.bat |
| S27-G03 | test_s27_g03_the_runner_the_gate_calls_exists | run_tests_estimator.bat exists at the repo root |

## Results

- Guard tests: 3 passed (Coder 1 track, 702 deselected).
- Full Estimator suite: 1300 passed, 14 skipped (run_tests_estimator.bat, 2026-11-09).

## Manual check

Run `release_gate.bat` end to end before the V10.0.0 release build and confirm Suite 5 runs the Estimator step through `run_tests_estimator.bat`. Still open from Sprint 26: Inno Setup (ISCC.exe) is not installed on this PC, so the .iss compile / clean-install check waits on installing it.

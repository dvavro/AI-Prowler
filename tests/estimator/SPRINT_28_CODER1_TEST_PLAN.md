# Sprint 28 (Coder 1) — Test Plan

**Sprint:** 28 (Coder 1 part of planned Sprint 18, Phase 8 — the rest of the Estimator tab and the full setup wizard)
**Date:** 2026-11-09

## Scope

The pieces of the planned Sprint 18 Coder 1 row still open after Sprints 26–27, checked against the Spec: the setup wizard's Team and approvals step (Spec wizard step 8), the tab's CAD and tools section (Spec tab table), and the Phone and web app section, which still described the web app as "coming next" even though it is built. Out of scope: starting/stopping the web app from the tab and changing its port or network binding — that stays with the web app (Coder 2's api/server); the tab reports the address and the sign-in rules.

## How to run

- Sprint 28 tests: `run_tests_estimator.bat coder1 -k sprint28`
- Full Estimator suite: `run_tests_estimator.bat`

## What was built

- `estimator/estimating/setup.py`: new wizard step `team_approvals`, "Team and approvals (who can estimate, review, approve and send)", between Bid template and AI connection check — the wizard now has the Spec's 10 steps. Who can do what is set by AI-Prowler's users and roles (with the Estimating scope, per the roles sign-off recorded in Sprint 26); the step applies the Estimator-side approval settings: `review_required_over` / `quick_send_limit` (dollars or cents) go to the Director settings through `director.settings.update_settings`. No data = record-only, like Bid template. Unknown fields and non-money amounts are refused with InvalidInput.
- `estimator/ui/model.py`: `tool_status()` (DXF via ezdxf; the ODA DWG converter via PATH and its usual install folders; Tesseract OCR via PATH) and `web_app_access()` (the web app URL from ESTIMATOR_WEB_PORT, default 8770, plus the sign-in rules).
- `estimator/ui/gui_tab.py`: new "🔧 CAD and tools" section rendering `tool_status()` with ✅/❌ and the ODA guidance; the Phone and web app section now shows the real web app address and who can sign in instead of the stale "Coming next" note; the setup checklist's Set up shortcut for Team and approvals scrolls to the Director section, where the approval limits are edited.
- Older tests updated for the bigger wizard and tab: `test_est_setup_wizard.py` (total 9 → 10), `test_sprint16_tab.py` (the "cad" section; checklist "0 of 10" / "2 of 10"), `test_sprint16_ui.py` and `test_web_router.py` (setup total 9 → 10).

## Tests

| ID | Test | What it proves |
| --- | --- | --- |
| S28-W01 | test_step_is_listed | setup_status lists team_approvals; the wizard totals 10 steps |
| S28-W02 | test_review_threshold_is_applied | review_required_over $750 lands in the Director settings as 75000 cents, and the step is marked done |
| S28-W03 | test_record_only_and_validation | no data records the step without changing settings; unknown fields and a non-money amount are refused |
| S28-T01 | test_tools_all_present | with a faked environment, all three tools report ok, in order |
| S28-T02 | test_tools_missing_gives_guidance | with nothing found, all three report missing and the DWG line carries the free ODA guidance |
| S28-T03 | test_web_app_access | the URL/port follow ESTIMATOR_WEB_PORT (default 8770) and the lines state the Estimating scope / field crew rules |

## Results

- Sprint 28 tests: 6 passed.
- Full Estimator suite: 1306 passed, 14 skipped (run_tests_estimator.bat, 2026-11-09). The first full run had 4 failures, all older tests pinning the 9-step wizard / 9-section tab; updated as listed above and re-run green.

## Manual check

Open AI-Prowler → 🏗 Estimator tab: the setup checklist shows 10 steps including Team and approvals; the new 🔧 CAD and tools section shows this PC's real DXF / DWG / OCR status; 📱 Phone and web app shows the localhost:8770 address and the sign-in rules. Still open from Sprint 26: the Inno compile / clean-install check (Inno Setup is not installed on this PC).

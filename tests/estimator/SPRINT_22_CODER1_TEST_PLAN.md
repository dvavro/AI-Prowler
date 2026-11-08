# Sprint 22 — Coder 1 (Jamie) test plan: measurements, approval locks and takeoff_* tools

**Scope:** The Coder 1 work from planned Sprint 6 (Phase 2, takeoff): the `measurements` table, the approval lock (only a person approves; approved numbers can't be changed by an agent), the `takeoff_*` tools, and feeding approved measurements into the runner. It sits on top of the Sprint 21 drawing model, so measurements come straight from the objects David's plan engine saves.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
Then start AI-Prowler again. The database upgrades itself to version 12. There are 83 Estimator tools (8 new).

## What was built

**Measurements** (`estimator/takeoff/measurements.py`, migration v12). Each measurement records what it feeds (a trade and question, e.g. roofing → roof_area_sqft), its quantity and unit, the drawing objects and viewport it came from, how it was measured (cad, vector, raster, ai, manual, typed), a confidence, and its status (proposed, approved, rejected).

**Proposing** (`takeoff_propose`). The agent picks drawing objects and a question. The quantity is worked out from the objects' real units: area in sq ft, length and perimeter in feet, count in each. One measurement for all of them, or one per object. Objects that can't be measured (unscaled viewport, NTS, a point asked for an area) are refused and say why, e.g. "set the scale with plan_set_scale first". It asks first.

**Approving** (`takeoff_confirm`). Only a person can approve; an agent is refused. A person can approve several at once, or everything above a confidence (e.g. 0.9). Approved measurements are locked.

**The lock.** An agent can't edit, delete or overwrite an approved number. It can only suggest a change with a reason (`takeoff_suggest_change`). The suggestion sits beside the approved number until a person accepts it. A person can still edit or reject anything.

**Typed and drawn measurements** (`takeoff_manual`). A person can type a number ("22.5 lf of valley") or draw a shape in a viewport, which is measured at that viewport's scale. A person can approve a typed number straight away; drawn ones are proposed. An agent can't approve.

**Feeding the estimate.** `runner_submit_takeoff from_measurements=true` uses the approved measurements for that trade. Each question gets the total of its approved measurements, converted to the question's unit. Proposed and rejected ones are never priced. Answers typed in the same call win over measurements.

**When the drawings change:**
- **Scale changed** (`plan_set_scale`): unlocked measurements re-measure themselves. Approved ones keep their number and get a suggested change ("the viewport scale changed"). If the objects can no longer be measured (e.g. set to NTS), the measurement is flagged to re-measure.
- **Plans read again**: proposed measurements are rejected ("the plans were read again"). Approved ones are kept and flagged to re-measure. Where they came from (sheet, viewport, calculation) is kept.

**Checks** (`est_validate`): warnings for measurements waiting for approval, flagged to re-measure, and suggested changes waiting.

**Tools** (`takeoff_propose`, `takeoff_manual`, `takeoff_list`, `takeoff_confirm`, `takeoff_edit`, `takeoff_delete`, `takeoff_detail`, `takeoff_suggest_change`).
- `takeoff_list` gives counts, a review queue (lowest confidence first), the approved answers per trade, and what needs re-measuring or has suggestions waiting.
- `takeoff_detail` shows the calculation, sheet, viewport, source objects and the full history.
- Everything is logged on the estimate (`measurement_proposed`, `_added`, `_approved`, `_edited`, `_rejected`, `_change_suggested`, `_suggestion_accepted`, `_remeasured`, `_flagged`).

## Test cases (tests/estimator/unit/test_sprint22_takeoff.py)

Test drawing: sheet A-301 at 1/8" = 1'-0". Main roof 1280 sq ft, garage roof 640 sq ft, eave 40 ft, ridge 20 ft, 2 vents, and a cricket in an unscaled viewport.

| ID | Test | Checks |
|---|---|---|
| S22-P01 | Propose | asks first with the total (1920 sq ft); area, length (40 lf), count (2 ea), one per object (1280 + 640), perimeter (144 ft); method, confidence and source objects recorded |
| S22-P02 | Refusals | unscaled viewport points to plan_set_scale; unknown question, a length for an area question, a non-number question, unknown trade, mixed shapes, field role, missing objects, another company; nothing saved |
| S22-C01 | Only a person approves | an agent is refused; bulk approve above 0.9 takes only the 0.95 one; approved is locked with the approver; already approved ones are skipped |
| S22-C02 | Lock | an agent can't edit or delete an approved number and is pointed to takeoff_suggest_change; a suggestion never overwrites; a person accepts it; a person can still edit and reject |
| S22-M01 | Typed and drawn | a person's typed 22.5 lf is approved; a drawn 8 x 8 ft square at 1/8" is 64 sq ft and proposed; drawing in an unscaled viewport, wrong unit, negative, no unit refused; an agent can't approve |
| S22-L01 | List | counts, review queue lowest confidence first, approved answers per trade, status filter |
| S22-R01 | Runner | from_measurements fills roof area and edges from approved measurements only; nothing approved and no answers is refused |
| S22-S01 | Scale changed | proposed re-measures (160 sq ft); approved keeps 1280 with a suggested 320 and the reason; NTS flags both to re-measure |
| S22-S02 | Plans read again | proposed rejected "read again"; approved kept at 1280 and flagged; sheet A-301 still shown |
| S22-D01 | Detail and checks | scale, sheet, source object area, history in order; est_validate warns about waiting and suggested |
| S22-T01 | Tools | the whole flow through the JSON tools; all 8 tools answer bad input with JSON |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 650 passed, 1 skipped (11 new) |
| Windows 11, Python 3.11.8 (Jamie's PC) | 659 passed, 0 failed (2026-11-07) |
| File check | All 11 files match the tested copies (zip SHA-256 checked on the PC) |

## Manual check after deploying

In chat, on an estimate with plans read: "Measure the main roof area for roofing". It should ask first, then propose a measurement. Ask it to approve: Claude should say a person has to approve it. Approve it yourself ("yes, approve measurement 1"), then ask Claude to change it: it should offer a suggested change instead.

## For David (Coder 2)

Nothing changes in the result format your engine returns. When your engine re-reads a plan set, approved measurements are kept and flagged automatically; you don't need to do anything. If your engine has a confidence per object, put it in the object's `confidence` field and the Takeoff agent will pass it on.

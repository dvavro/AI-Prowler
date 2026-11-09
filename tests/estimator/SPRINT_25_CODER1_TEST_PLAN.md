# Sprint 25 — Coder 1 (Jamie) test plan: plan quantities into takeoffs, the design firm, assemblies and line edits

**Scope:** The items Coder 2 (David) was waiting on:
- the Runner's trade tasks and `takeoff_propose` use the plans' answers (`plan_trade_answers`);
- symbol counts go into `takeoff_propose`;
- each plan set records its design firm (for the symbol library's per-firm profile);
- `est_update_line_item` and `est_apply_assembly` for the Estimates screen, with `est_get_assemblies`;
- `est_add_trade` and `est_remove_trade` for the Projects screen.

The web app's parity list of tools a screen names but that aren't built is now empty.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
Then start AI-Prowler again. The database upgrades itself to version 17. There are 108 Estimator tools (6 new).

## What was built

**Takeoffs from the plans** (`estimator/takeoff/from_plans.py`; `takeoff_propose from_plans=true`)
- The plans' answers for a trade (Coder 2's `estimator.building.trades`) become proposed measurements, one per question:
  - the wall-and-room model: framing, drywall, painting, insulation, flooring;
  - the schedules and elevations: windows and doors, siding;
  - approved symbol counts: electrical, plumbing, hvac. `include_proposed=true` also counts unchecked symbols.
- Each measurement says where it came from (`calc.from = "plans"`, how, the plan sets, the model key) and, for counts, which symbol detections were counted.
- Choice answers (the water heater kind, siding stories) aren't quantities: they come back as `choices`.
- It asks first, listing each one. Nothing is priced until a person approves.
- Running it again keeps one measurement per question:
  - same number: unchanged;
  - proposed with a new number: updated, with the event logged;
  - approved with a new number: left alone (it's locked), with a suggested change beside it that only a person can accept;
  - rejected: left rejected and reported.

**The Runner** (`runner_submit_takeoff from_plans=true`)
- A plan trade's task takes its answers from the plans.
- Approved measurements (`from_measurements=true`) win over the plans' numbers, and answers typed in the call win over both.
- A trade's task "next" step mentions `from_plans` for trades the plans answer.
- Counts that include symbols nobody has checked never auto-advance, even when the owner turned auto-advance on.

**Design firm** (migration v17: `plan_sets.design_firm`, `design_firm_source`)
- `plan_upload design_firm=` records it. A revised set keeps the firm of the set it replaces.
- `plan_set_design_firm`:
  - records, changes or clears it (owner, estimator; asks first);
  - with no plan set, lists the firms on file with their plan sets and estimates.
- The same firm typed differently keeps its first spelling, so a firm's profile stays one profile.

**Assemblies** (`estimator/estimating/assemblies.py`; migration v17 `assembly_uses`)
- `est_get_assemblies`: a trade's inputs (which ones a measurement can fill), the lines it makes (formula, waste, price key), its good/better/best options, and whether the plans answer it.
- `est_apply_assembly`:
  - Each quantity comes from the trade's approved measurements, or the `measurement_ids` you pick (they must be approved).
  - The other answers come from, in order: `params`, then `option` (good/better/best), then the answers already on the estimate, then defaults.
  - A typed answer over a measured one is allowed and recorded as "typed over measured".
  - Proposed measurements are never priced; they're listed as waiting.
  - It asks first, showing every answer with where it came from and the lines it makes.
  - It records what was used (`assembly_uses`), and each line points at it.

**Line edits** (`est_update_line_item`; `line_items.override_reason`, `override_at`)
- Change a line's quantity, cost, waste or description. On a line the trade's pricing made, that's an override and needs a reason. It's kept with who, when and the original values.
- `revert=true` puts it back; `remove=true` takes a line off (a priced line needs a reason).
- Re-applying the assembly keeps cost, waste and description overrides on lines made by the same rule. Quantity overrides are dropped, since the quantity comes from the measurements. It says which. `keep_overrides=false` drops all of them.
- `est_quick_answer` and the Runner say when re-pricing replaced hand changes.
- A new revision of the estimate keeps them.
- Everything asks first.

**Trades** (`est_add_trade`, `est_remove_trade`)
- Adds an empty trade section, or takes one off (asks first, with its lines and total).
- A trade's measurements stay with the plans.

## Test cases (tests/estimator/unit/test_sprint25_plans_assemblies.py)

The test house is Coder 2's Sprint 12 house: LIVING 10 x 12 ft and BEDROOM 9.5 x 12 ft at 1/4" = 1'-0", two doors and a window, read by the real plan engine.

| ID | Test | Checks |
|---|---|---|
| S25-P01 | Plan answers to measurements | asks first listing flooring's 234 sqft; two proposed measurements (area, length) with where they came from; not priced; asking again with the same numbers changes nothing; windows and doors (1 small window, 1 exterior and 1 interior door) and siding (wall area; stories and walls returned as choices) the same way |
| S25-P02 | Re-running | painting at 9 ft updates the two proposed height-dependent ones and leaves the other three; one per question; approved then 10 ft gives a suggested change with the reason, the proposed one updates; the same suggestion again changes nothing; a rejected one is left and reported; events logged |
| S25-P03 | Symbol counts | 2 approved and 1 unchecked outlet, a rejected switch: outlets = 2 with the 2 detection ids and a "still to check" note; with include_proposed it updates to 3; plumbing gives toilets and returns the water heater kind as a choice |
| S25-P04 | Refusals | field role; a trade the plans don't answer; no approved symbols; a plan set from another estimate; the tool with both object_ids and from_plans; the tool asks first |
| S25-R01 | Runner from the plans | the next step says from_plans for plan trades only; flooring needs its material too; from the plans 234 sqft with the material given; roofing refused; an approved 240 sqft wins over the plans; a typed 250 wins over both |
| S25-R02 | No auto-advance on unchecked counts | auto-advance on at 80%: with 2 unchecked outlets a 95% submission waits for review with the note; once they're approved it auto-approves with 6 |
| S25-F01 | Design firm | recorded on upload; a revision keeps it (source "plan set N"); setting it asks first and uses the spelling on file; the firm list counts plan sets and estimates; setting the same firm changes nothing; clearing; field role, too long and a missing plan set refused; events logged |
| S25-A01 | est_get_assemblies | flooring's inputs, components, options and plans_answer_it; a service trade isn't a plan trade; unknown module refused |
| S25-A02 | Apply from measurements | asks with each answer's source (measured with ids, typed, default) and the waiting measurement; lines point at the recorded use; the "best" option with kept answers; typed over measured recorded; only picked measurements; all approved ones added up |
| S25-A03 | Apply refusals | unknown question, unknown option, unapproved or missing measurements, a missing required answer, nothing to price, field role, stale rev, measurement ids with use_measurements=false |
| S25-L01 | Override a priced line | needs a reason; asks first; cost and quantity changed with who, why and the originals; the total goes up; re-applying keeps the cost change and drops the quantity one (and says so); revert puts it back; nothing to revert refused; keep_overrides=false drops all |
| S25-L02 | Hand lines and refusals | a hand line changes without a reason; removing asks; a priced line needs a reason to come off; two actions at once, negative quantity, waste over 100%, no change, reviewer role, stale rev and a line from another estimate refused |
| S25-L03 | Other pricing paths | est_quick_answer warns that hand changes were replaced; a new revision keeps an override and its reason |
| S25-T01 | Tools | est_add_trade (and twice refused), est_remove_trade asks then removes (and a missing trade refused), est_get_assemblies, est_apply_assembly asks then applies, est_update_line_item needs a reason then changes, bad JSON refused, plan_set_design_firm lists and asks, runner_submit_takeoff from_plans, all six tools registered |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | all Estimator tests pass except the 2 OCR tests that need Tesseract (not in that container); Sprint 25: 14 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | PC_RESULT |
| File check | FILE_RESULT |

## Manual check after deploying

With a read plan set on an estimate, say:
1. "take off the flooring from the plans". It should ask first, list the area and baseboard, and propose them.
2. Approve them in Takeoffs, then "price flooring with LVP from the measurements". `est_apply_assembly` should ask first, showing each answer and where it came from, then price it.
3. "the LVP line should be $3.25 a foot, supplier quote". `est_update_line_item` should ask first, then show the line as changed by you with that reason.
4. "who drew these plans? It's Hart Architects". It should ask first, then record the firm.

## For David (Coder 2)

- **Firm profiles:**
  - `plan_sets.design_firm` is filled from upload, a revision, or `plan_set_design_firm`.
  - `store.set_design_firm(conn, ctx, plan_set_id, name, source="title block", confirm=True)` is there if your title-block reader finds the firm.
  - The same firm with different capitalisation is stored as one spelling.
- **Estimates screen:** both tools are ready.
  - `est_apply_assembly`: ConfirmationRequired details are `answers`, `sources`, `lines`, `waiting`, `overrides_kept`, `overrides_dropped` and `measurement_ids`.
  - `est_update_line_item`: each line in `est_get_estimate` now has `assembly_use_id` and `override` (`by`, `reason`, `at`, `changed`).
- **Projects screen:** `est_add_trade` and `est_remove_trade` are ready.
- **Parity list:** `PENDING` in `test_web_parity.py` is empty now.
- **Plan trades:** the Runner and `takeoff_propose` read your `trades.TRADES` and `feeds_of`, so new plan trades and symbols you add work without a change on my side.

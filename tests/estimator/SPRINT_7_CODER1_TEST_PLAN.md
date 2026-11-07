# Sprint 7 — Coder 1 (Jamie) test plan

**Scope:** the first construction trades, priced from measurements you type in (no plans needed): Concrete, Flooring and Roofing. The Director's standard-estimate lane is now live: collect measurements, price, Reviewer check by job size, approve, bid, follow up. Also new: `est_validate` (Reviewer QA checks) and `est_director_change_lane`.
**Why the change of order:** this is Phase 3 Coder 1 work pulled forward. Plan-reading and takeoff from drawings still wait on David's track; when they arrive, plan measurements feed the same module questions.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should list 30 Estimator tools and 11 modules (8 services, 3 construction trades).

## What was built

| Trade | Asked for | Priced by (spec formulas) | Minimum |
|---|---|---|---|
| Concrete | area, thickness (4/5/6 in), edge length, reinforcement (none/mesh/rebar), finish (broom/stamped/exposed), gravel base, removal, footing length, pump | cubic yards = sq ft × in / 12 / 27 (+ footing lf / 27), 5% waste; rebar lf from 18 in spacing, 10% waste; forms from the edge, or estimated as a square pour | $1,200 |
| Flooring | area, type (LVP, laminate, tile, hardwood, carpet), layout, removal, subfloor prep, baseboard, stairs, transitions | material sq ft × (1 + waste): LVP/laminate 7%, tile 12%, hardwood 8%, carpet 10%, diagonal +5%; underlayment, pad, tile setting materials, install labor by type | $500 |
| Roofing | top-down roof area, pitch, shape (gable/hip), material (3-tab, architectural, tile, metal, TPO), layers to tear off, edges, ridges, decking sheets, stories, permit | squares = plan area × pitch factor / 100; waste 10% gable, 15% hip; tile gets two-layer underlayment; starter for shingles; ridge cap; two-story access | $1,500 |

Concrete and roofing carry hot-weather reminders that the Reviewer shows (morning pours; tile underlayment).

**Director standard lane:** "replace the roof on the Smith house" → asks pitch and material → prices → Reviewer check → approve → bid → follow up.
- **Review by job size:** new setting `review_required_over_cents`, default $500 (0 = review everything). Under the limit the check runs automatically and its notes are shown. Over it, the estimate moves to "in review" and waits for an owner or reviewer (`reviewed=true`). An owner can review and approve in one step.
- **Approval:** standard estimates are approved by an owner or reviewer (no one-tap).
- **Changed answers** send the job back through pricing and the review.
- **Trades without a module yet** (fence, HVAC…) say which trades can be priced now. The estimate is kept for hand-entered lines, or you can pick a module.
- **Change lane:** a quick quote that turns out bigger can become a standard estimate. It keeps the estimate, the answers and the customer.

**`est_validate`:**
- Errors: no line items (this blocks approval).
- Warnings: sample prices; a unit cost more than 3× (or under ⅓) the usual; margin under 10%; $0 lines.
- Info: minimum charge applied; trade notes.

Not in this sprint (next): good/better/best scenarios, combined multi-trade estimates and bid scope by trade, company playbook changes (`est_playbook_update`), site-visit booking on the calendar.

## Test cases

| ID | Test | Expected |
|---|---|---|
| Golden | 10 new cases (concrete 3, flooring 4, roofing 3) | Exact cents: 400 sq ft patio $2,549.56; stamped 600 sq ft driveway $9,748.63; 40 sq ft pad at the $1,200 minimum; 500 sq ft LVP $2,471.25; diagonal tile job $4,489.50; carpet with stairs $5,346.00; hardwood $7,747.50; 2,000 sq ft architectural 5/12 $7,817.10; 2,400 sq ft hip tile two-story $18,274.68; flat TPO $5,974.88 |
| S7-M01/02 | Modules load; bad notes rejected | 3 construction modules, no load errors |
| S7-T01/02 | 9 plain-language requests | Roof, LVP, carpet, patio slab, stamped concrete → the right trade; "soft wash the roof" and "pressure wash the concrete patio" stay pressure washing; fence → standard with no module |
| S7-D01 | Roof job start to approved | Asks pitch and material; $7,817.10; waits for reviewer with findings; owner reviews and approves together |
| S7-D02 | Roles | Estimator can't sign off a review or approve; reviewer can do both |
| S7-D03/04 | Review limit | Under the limit: automatic check with hot-weather note; limit 0: always reviewed |
| S7-D05 | Change answers in review | Re-priced and re-checked; after approval, changes need a revision |
| S7-D06 | Fence job, then pick concrete | Waits listing the trades available; picking a module continues the job |
| S7-D07/08 | Change lane | Quick → standard keeps estimate, total and answers, and logs the reason; roofing can't become a quick quote; no lane change after approval |
| S7-D09 | Office staff start a carpet job | Flooring, customer-voice questions |
| S7-V01–03 | `est_validate` | No lines is an error; minimum, samples and notes found; outlier price flagged; margin warning gone once markups are set; a failing check blocks the Director |
| S7-S01, B01 | Setting and briefing | Default $500, validated; briefing counts estimates waiting for a reviewer |
| S7-T03 | MCP tools | 30 tools; standard lane, validate and change lane over MCP |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 372 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 372 passed in 12.3 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy (test_database.py differs only by blank lines, as before) |

## Still open (not Estimator code)

- Run `install_estimator.bat` and restart AI-Prowler. It is still on the Sprint 4 install.
- Make a new Gmail app password so quote Q-0001-1 can be sent.

## Self-review checklist

- [ ] Every formula matches the spec's trade table
- [ ] Sample prices are labelled "(sample)"
- [ ] Nothing over the review limit reaches approval without a reviewer
- [ ] Changing lanes never loses answers or the estimate

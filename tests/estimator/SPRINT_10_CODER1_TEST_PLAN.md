# Sprint 10 — Coder 1 (Jamie) test plan

**Scope:** three more construction trades, priced from measurements you type in: Framing and Drywall (planned Sprint 12) and Painting (planned Sprint 13). The Director's standard lane, review, good/better/best options and multi-trade jobs all work with them straight away. With these, a room addition (frame it, drywall it, paint it) can be one estimate and one bid.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should show 14 modules: 8 services and 6 construction trades.

## What was built

| Trade | Asked for | Priced by (spec formulas) | Options | Minimum |
|---|---|---|---|---|
| Framing | wall length, height (8/9/10 ft), 2x4 or 2x6, 16 or 24 in spacing, corners, openings, exterior (sheathing), floor area, trusses | studs = wall lf × 12 / spacing + 2 per corner + 2 per opening, times wall height in lf, 10% waste; plates = wall lf × 3; sheathing sheets = wall area / 32; headers per opening; joists and subfloor sheets = floor / 32; trusses set | — | $1,500 |
| Drywall | wall length, height, ceiling area, openings to leave out, board (standard, 5/8 in Type X, moisture-resistant), finish level 3/4/5, tear-out | board sq ft = wall lf × height + ceiling − openings, 12% waste; mud, tape and screws; hang; extra for ceilings; finish by level | finish level 3 / 4 / 5 | $750 |
| Painting | interior wall and ceiling area, exterior area, trim, doors, coats, primer, standard or premium paint | gallons = area × coats / 375 (inside) or 350 (outside), +7%, rounded up; primer at 300 sq ft per gallon; labor per sq ft per coat; prep and supplies; trim per ft, doors each | standard 1 coat / standard 2 coats / premium 2 coats | $400 |

**Reminders the reviewer sees:**
- Framing: check headers, spacing and shear walls against local code or engineered plans.
- Drywall: garages next to living space usually need fire-rated board.
- Painting: paint outside in the mornings in hot weather.

**Triage fix:** "carpet cleaning" now goes to a service quote instead of Flooring.

## Test cases

| ID | Test | Expected |
|---|---|---|
| Golden | 9 new cases | 100 ft 2x4 wall $1,596.24; 160 ft 9 ft 2x6 exterior with 8 openings $4,600.54; 400 sq ft floor + 20 trusses $6,447.60; drywall room 1,260 sq ft $2,342.80; moisture-resistant level 5 bath $1,065.60; small patch $750 minimum; interior 1,600 sq ft 2 coats $2,476.00; premium primed exterior $5,358.00; 2 doors $400 minimum |
| S10-M01 | Modules load | Framing, drywall, painting with notes; drywall and painting have options |
| S10-T01/02 | 10 plain-language requests | "frame a new interior wall", "sheetrock the basement", "tape and mud", "repaint the outside" go to the right trade; carpet cleaning is a service |
| S10-D01 | Framing with nothing to frame | Asks for walls, floor or trusses; then $1,596.24 and on to review |
| S10-D02 | Room addition | Framing + drywall + painting on one estimate; total equals the three trade subtotals; review shows all three reminders |
| S10-O01 | Drywall options | Level 3 is $189.00 less, level 5 is $378.00 more on 1,260 sq ft |
| S10-O02 | Painting options | Good < better ($2,476.00) < best; choosing best switches to premium paint |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 431 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 431 passed in 16.6 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy |
| Live check | After reinstalling, AI-Prowler showed the Sprint 9 tools; the watcher was running, checking every 15 minutes, and had put the first briefing in the inbox |

## Self-review checklist

- [ ] Every formula matches the spec's trade table
- [ ] Sample prices are labelled "(sample)"
- [ ] Openings can't make the drywall area negative
- [ ] Paint gallons round up to whole gallons

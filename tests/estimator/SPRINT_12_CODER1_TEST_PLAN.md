# Sprint 12 — Coder 1 (Jamie) test plan

**Scope:** The planned Sprint 14 expansion trades: HVAC, Windows and Doors, Siding, and Insulation, priced from typed counts and areas (no plans needed). There are now **12 construction trades** and 20 modules in all. An "energy upgrade" (new heat pump, attic insulation and new windows) can be one estimate.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should show 20 modules: 8 services and 12 construction trades.

## What was built

| Trade | Asked for | Priced by | Options | Minimum |
|---|---|---|---|---|
| HVAC | system (split, heat pump, package, mini-split), area or tons, zones, ducts (reuse, seal, new), returns, thermostats, remove old, permit | Tons = area ÷ 500 sq ft per ton, rounded up to the half ton, never under 1.5 (or the tons typed in). Equipment per ton; install hours by system. New ducts: trunk = area ÷ 25, registers = area ÷ 150, 20 ft branch each, 2 hr per register and return. Mini-split per head. | — | $500 |
| Windows and doors | retrofit or new construction; small and large windows, patio doors, exterior, interior and garage doors; vinyl or fiberglass; casing; remove old; permit | Unit price by type and size; install hours (small window 1.5, large 2.5, patio 4, exterior door 3, interior 1.5, garage 6); flashing on new construction, sealant on retrofit; casing by opening perimeter + 5% | Good vinyl / Better fiberglass | $300 |
| Siding | wall area, openings, material (vinyl, fiber cement, wood, stucco, stone), simple or complex walls, stories, corners, eaves and soffit depth, house wrap, remove old | Squares = (wall − 15 sq ft per opening) ÷ 100, never below zero; waste 10% simple / 15% complex; corners × wall height; J-channel or casing bead 16 ft per opening; soffit = eave × depth | Good vinyl / Better fiber cement / Best wood | $1,500 |
| Insulation | attic area and R-value, remove old, air seal; open wall area and R-value, vapor barrier; spray foam area and thickness | Blown bags = attic × R ÷ 1,500, +5%, rounded up; batts by wall area +5%; foam board feet = area × inches | Good R-30 / Better R-38 / Best R-49 | $500 |

**Triage:** AC, heat pump, furnace and mini-split go to HVAC; windows, doors, sliders and garage doors go to Windows and Doors; siding, stucco, soffit and fascia go to Siding; attic insulation and spray foam go to Insulation. "Clean the windows" and "pressure wash the stucco" still go to the service quotes.

## Test cases

| ID | Test | Expected |
|---|---|---|
| Golden | 12 new cases | HVAC: heat pump 1,800 sq ft $9,245.00; split with new ducts $15,877.00; 3-head mini-split $8,295.00; 4-ton package with sealing $8,760.00. Windows: 6 small + 4 large vinyl $7,191.05; new-construction set $6,468.70; garage door $1,806.25. Siding: fiber cement $15,806.60; two-story stucco $19,550.25. Insulation: R-38 attic 1,500 sq ft $2,325.00; R-49 with removal and air seal $4,710.00; walls and foam $2,052.00 |
| S12-M01 | The 4 new trades load | Yes, with notes and their options lists |
| S12-T01 | 13 requests | Each goes to the right new trade |
| S12-T02 | Cleaning look-alikes | "clean the windows" → window cleaning; "pressure wash the stucco" → pressure washing |
| S12-H01 | HVAC sizing | 1,800 ÷ 400 = 4.5 tons; 600 sq ft stays at 1.5 tons; typed tons win; mini-split has no duct lines |
| S12-H02 | HVAC with no size | The Director asks for an area or tons before pricing |
| S12-S01 | Openings larger than the wall | Siding squares drop to zero (no siding line); trim around openings still priced |
| S12-O01 | Options | Siding and insulation good < better < best; R-38 attic is $2,325.00 |
| S12-D01 | Energy upgrade | HVAC + insulation + windows on one estimate; the windows options are offered |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 489 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 489 passed in 19.5 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy |

## Self-review checklist

- [ ] Sizing rules (sq ft per ton, bags per R-value, squares) are in the manifest comments
- [ ] Sample prices are labelled "(sample)"
- [ ] Typed tons override the area rule
- [ ] Siding never goes negative when openings are large
- [ ] Cleaning and washing requests aren't taken by the new trades

# Sprint 13 — Coder 1 (Jamie) test plan

**Scope:** The last three planned trades (the trade part of planned Sprint 15): Fencing, Landscaping (installs) and Demolition, priced from typed lengths, areas and counts. **All 15 construction trades in the plan now exist**, so there are 23 modules: 8 services and 15 trades. A remodel can start with demolition and carry on through every trade on one estimate.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should show 23 modules: 8 services and 15 construction trades.

## What was built

| Trade | Asked for | Priced by | Options | Minimum |
|---|---|---|---|---|
| Fencing | length, material (wood, vinyl, chain link, block wall, wrought iron), height 4–8 ft, walk and drive gates, remove old, permit | Fence face = length × height, 5% waste; posts every 8 ft plus one; install hours per foot by material, scaled by height. Block wall: footing per foot, 1.125 blocks per sq ft, grout and labor per sq ft. Gates 2 hr walk, 4 hr drive. | Good wood / Better vinyl / Best block wall | $500 |
| Landscaping | area to clear, grading, sod, artificial turf, rock (2 or 3 in) with weed barrier, pavers, shrubs, trees, drip and sprinkler zones, edging | Rock tons = area × depth ÷ 12 ÷ 27 × 1.4, rounded up to ½ ton. Turf and paver base 4 in deep, rounded up to ½ cu yd. Emitters: 1 per shrub, 4 per tree. One timer if there's any irrigation. | — | $500 |
| Demolition | interior area (selective or gut), walls, cabinets, fixtures, flooring by type, concrete, small structures, dust protection, hazard test, permit | Labor hours per sq ft, foot or item. Concrete broken out per sq ft and hauled by weight (0.025 ton per sq ft). Other debris goes in 20 cu yd dumpsters, counted from the volume. | — | $400 |

Landscaping here is for new installs. Mowing and upkeep stay with the Landscaping Maintenance service.

**Triage:** fence, gate, block wall and chain link requests go to Fencing; turf, rock, pavers, sod, drip and trees go to Landscaping; demo, gut, tear out, knock out a wall, tear down and break out concrete go to Demolition. Mowing, pressure washing a fence, and junk hauling still go to the service quotes.

**Hand pricing still works:** if a company turns a trade module off, the Director still makes the estimate and asks for line items or another module (tested with fencing turned off).

## Test cases

| ID | Test | Expected |
|---|---|---|
| Golden | 9 new cases | Fencing: 120 ft wood with a gate and removal $6,612.00; 160 ft block wall with drive gate and permit $17,388.50; 150 ft of 4 ft chain link $2,540.00. Landscaping: desert front yard $4,929.00; turf and paver patio $8,140.00; sod on 3 sprinkler zones $4,090.00. Demolition: kitchen gut $2,422.50; 600 sq ft concrete patio $2,400.00; shed tear-down $2,950.00 |
| S13-M01 | Every planned trade has a module | 15 construction trades, matching the Director's trade list |
| S13-T01 | 14 requests | Each goes to Fencing, Landscaping or Demolition |
| S13-T02 | Service look-alikes | Mowing, landscaping maintenance, pressure washing a fence and junk hauling stay with the services |
| S13-F01 | Posts and height | 100 ft = 14 posts; 8 ft vinyl install = 26.67 hr; block wall has no posts, 675 blocks |
| S13-O01 | Fence options | Wood < vinyl < block wall |
| S13-L01 | Landscaping needs real work | Clearing alone isn't enough to price |
| S13-D01 | Dumpsters | 10 ft of wall = 1 dumpster plus protection; concrete alone needs no dumpster or protection |
| S13-D02 | Bathroom remodel | Demolition then plumbing on one estimate; review shows the asbestos and bearing-wall notes |
| S3-D18, S7-D06 | Updated | Use a registry with fencing turned off for the hand-pricing path |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 522 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 522 passed in 24.0 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy |

## Self-review checklist

- [ ] Waste, post spacing, rock weight and debris volumes are in the manifest comments
- [ ] Sample prices are labelled "(sample)"
- [ ] Landscaping installs and Landscaping Maintenance don't take each other's requests
- [ ] Concrete demo is charged by weight, not dumpsters

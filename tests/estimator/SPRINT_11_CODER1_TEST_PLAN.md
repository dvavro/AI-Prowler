# Sprint 11 — Coder 1 (Jamie) test plan

**Scope:** Plumbing and Electrical (the rest of planned Sprint 13), priced from fixture and device counts. **All 8 core trades now exist:** concrete, framing, roofing, flooring, drywall, painting, plumbing and electrical. A whole bathroom remodel can be one estimate. Pricing from plan sheets (fixture and device symbols) still waits on David's track.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should show 16 modules: 8 services and 8 construction trades.

## What was built

| Trade | Asked for | Priced by (spec: labor by fixture or device × hours) | Minimum |
|---|---|---|---|
| Plumbing | new/remodel or replace-only; counts of toilets, bathroom sinks, kitchen sinks, showers/tubs, dishwashers, washer boxes, hose bibs; water heater (tank / tankless); supply, drain and gas pipe lengths; fixtures supplied or by the customer; permit | Rough-in hours per fixture (toilet 3, sink 3, kitchen 3.5, shower 5, dishwasher 1.5, washer 2.5, hose bib 1.5) on new work. Trim hours per fixture on all work. Half an hour to remove each old fixture on replacements. PEX and drain pipe by length (or 25 ft and 15 ft per fixture), 10% waste, plus fittings. Water heater 4 hr (tank) or 8 hr (tankless). Gas line per ft. | $250 |
| Electrical | new work, old work (finished walls) or swap only; outlets, switches, GFCIs, lights, fans, dedicated circuits (range, dryer, AC, EV), data/TV drops, average run; subpanel or 200 A upgrade; permit | Hours per device (outlet and switch 0.5, GFCI and light 0.75, fan 1.5, circuit 3) × 1.0 new / 1.6 old work / 0.5 swap. Wire = devices × average run, 15% waste. A box per device. Breakers: one per circuit plus one per 10 devices. Panel work priced as installed packages. | $200 |

**Engine fix:** a "None" choice (no water heater, no panel work) no longer counts as an answer when the Director checks whether there's anything to price.

**Triage:** "install lights in the kitchen" now goes to Electrical instead of the general service quote.

## Test cases

| ID | Test | Expected |
|---|---|---|
| Golden | 8 new cases | New bathroom (toilet, 2 sinks, shower) $2,440.00; replace 2 toilets + 2 sinks with fixtures $1,530.00; tankless + 20 ft gas $3,610.00; hose bib at the $250 minimum; 10 outlets, 4 switches, 6 lights $1,737.25; old-work fans, GFCIs and a circuit $1,646.20; 200 A upgrade $3,700.00; swap 5 outlets at the $200 minimum |
| S11-M01 | All 8 core trades load | Yes, with notes; water heater and panel count as "something to price" |
| S11-T01 | 11 requests | Toilet, water heater, repipe, gas line → Plumbing; fan, outlets, panel, EV charger, recessed and kitchen lights → Electrical |
| S11-D01/02 | Water heater only; panel only | "None" isn't enough to price; a tank heater alone prices at $1,690.00; a panel upgrade alone at $3,700.00 |
| S11-P01 | Old work vs new | 10 outlets: 5 hr new, 8 hr old work |
| S11-P02 | Replace a toilet | No pipe lines, only removal and trim (comes to the minimum) |
| S11-D03 | Bathroom remodel | Plumbing + electrical + drywall + painting + tile flooring on one estimate; total equals the five subtotals; review shows permit and fire-rated reminders |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 456 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 456 passed in 17.0 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy |

## Self-review checklist

- [ ] Hours per fixture or device are in the manifest comments, so they can be checked
- [ ] Sample prices are labelled "(sample)"
- [ ] Replace-only work never adds pipe or wire
- [ ] Fixtures the customer supplies aren't charged

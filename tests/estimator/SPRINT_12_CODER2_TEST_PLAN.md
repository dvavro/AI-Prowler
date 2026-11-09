# Sprint 12 — Coder 2 (David) test plan: shared wall-and-room model; electrical and plumbing symbol libraries

**Scope:** The Coder 2 Sprint 12 row is "Shared wall-and-room model; electrical and plumbing symbol libraries".

- **Wall-and-room model:** one model of the building from the plans (rooms, walls, doors and windows, ceiling heights), and every wall-and-room trade (framing, drywall, painting, insulation, flooring) takes its answers from it, so the trades agree.
- **Electrical and plumbing:** the standard symbol library is fuller, and each symbol says which trade question it counts toward, so approved symbols become electrical and plumbing answers.
- **Plan quantities page:** the model and each trade's answers, linked from Blueprint Review.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat browser         Playwright (add --human to watch)
deploy_to_install.bat                   then restart AI-Prowler
```
- **No new database migration and no new tables.** The model is worked out from the drawing model each time (read only).
- **New MCP tools (2):** `plan_get_rooms_walls`, `plan_trade_answers` (98 tools in all).
- **Standard symbol library version 2:** each company's copy is refreshed the next time plans are read (`ensure_standard`).
- **No new libraries.**

## What was built

**Wall-and-room model** (`estimator/building/model.py`, `build`):
- **Which plans:** the project's current plan sets (superseded revisions left out), or one plan set.
- **Which sheets:** architectural floor plans first; other disciplines are listed as skipped. A sheet whose rooms are at least 80% already counted (a ceiling plan, an enlarged plan) is skipped as a repeat view. Unscaled views can't be measured and say so.
- **Rooms:** name, floor area and perimeter (inner face), ceiling height, where the height came from (`finish schedule`, `given`, `standard 8 ft`), walls, openings, wall area less openings, ceiling area, baseboard length (perimeter less door widths).
- **Heights:** from the room finish schedule (NAME column first, then ROOM/SPACE, then the mark; CLG HT / CEILING / HEIGHT columns). Otherwise the height given (4–40 ft), otherwise 8 ft. Mixed heights get a note.
- **Walls:** each wall centre line with length and thickness; **interior** (rooms on both sides), **exterior** (a room on one side) or **other**, from points just off each side.
- **Openings:** door and window tags (D1, W1) with sizes from the door and window schedules (`3070`, `2868`, `4'-0" x 3'-0"`, W/H columns), otherwise standard sizes (door 3' x 6'-8", window 3' x 5'). Each attaches to the nearest wall within 3 ft and to that wall's rooms.
- **Totals:** rooms, floor, ceiling, room perimeters, wall faces, openings, base, exterior / interior / other wall lf, exterior wall area, doors, windows, corners, the most common height.
- **Known approximation:** exterior wall length is along centre lines and doesn't add the corner overlaps (the test house is 63 lf, not 66). Framing gets corners separately.
- **`model_key`:** a short hash of the rooms, walls and openings, the same in every trade's answers, so a reader can see they came from one model.

**Trade answers** (`model.answers_for`, `estimator/building/trades.py`):

| Trade | Answers from the model |
| --- | --- |
| framing | wall_lf (exterior + interior), wall_height ("8"/"9"/"10", the nearest choice), corners, openings, exterior, floor_sqft |
| drywall | wall_lf (room perimeters: both faces of a partition), wall_height, ceiling_sqft, openings_sqft |
| painting | wall_sqft (wall faces less openings), ceiling_sqft, exterior_sqft, trim_lf, doors |
| insulation | wall_sqft (exterior walls less openings), attic_sqft (ceilings) |
| flooring | area_sqft, baseboard_lf |

- **Electrical and plumbing:** counts of **approved** symbols by `FEEDS` (item type → module question). Proposed ones are listed as `waiting`; `include_proposed` counts them too. Rejected ones never count. A tankless water heater sets `water_heater` to `tankless`. Symbols found but not an answer for the trade (e.g. smoke detectors) and unidentified symbols get notes.
- **Fit:** answers are only given for questions the trade module has, and choice answers are valid choices.
- **Nothing is saved.** Pricing still goes through `est_quick_answer` (or the Estimate page).

**Symbol library v2** (`plan_engine/symbol_library.py`, `legends.py`):
- **Electrical (+12):** USB duplex, dedicated receptacle, EV charger, disconnect, occupancy switch, wall, pendant, under-cabinet and exterior lights, smoke/CO detector, doorbell, speaker.
- **Plumbing (+13):** kitchen, bar, laundry and mop sinks, urinal, dishwasher, washer box, ice maker box, tub/shower, tankless water heater, gas outlet, drinking fountain, water meter.
- **Legend words:** the specific types are matched before the general ones ("Kitchen sink" before "Sink", "Smoke/CO detector" before "Smoke detector"); "gas" alone is a gas outlet, checked last.
- **FEEDS:** every symbol that answers a trade question names it; a test checks each question exists in the module registry.

**MCP tools** (`est_tools.py`):
- `plan_get_rooms_walls(estimate_id | plan_set_id, height_ft?)`
- `plan_trade_answers(module_id?, estimate_id | plan_set_id, height_ft?, include_proposed?)`: one trade, or all of them.

**API** (`estimator/api/quantities_api.py`): `GET /estimates/<id>/quantities?height=&proposed=1` (owner, estimator, reviewer).

**Web** (`quantities.js`, page `quantities` from Takeoffs): `#/quantities/<estimate id>`; summary, totals tiles, rooms, doors and windows, sheets not counted, each trade's answers with where each came from; ceiling height and "count symbols still to check" settings. Linked from the Blueprint Review header (📐 Plan quantities). New guide: "See every trade's quantities from the plans".

## Automated tests

`tests/estimator/plan_engine/test_plan_engine_sprint12.py` (test house: LIVING 10 x 12 ft and BEDROOM 9.5 x 12 ft with 6" walls at 1/4" = 1'-0"; door schedule D1 3070, D2 2868; window schedule W1 4'-0" x 3'-0"):

| ID | Test | Checks |
| --- | --- | --- |
| C2S12-B01 | test_rooms_walls_and_openings | Rooms 120 / 114 sq ft, perimeters 44 / 43; one interior partition (12 ft, 6", two rooms); door and window sizes from the schedules; D2 on the partition between both rooms; totals 2 doors, 1 window, 6 corners, 8 ft |
| C2S12-B02 | test_room_surfaces_take_off_their_openings | Openings per room; wall area = perimeter x height − openings; base less door widths only; exterior wall area |
| C2S12-B03 | test_every_trade_agrees | Drywall hangs what painting paints; framing wall lf = exterior + interior; floor = ceiling = attic; baseboard = trim; same model_key in all five |
| C2S12-B04 | test_ceiling_heights_from_the_finish_schedule | 9'-0" from the finish schedule by room name → framing "9"; a given height for rooms without one; bad heights refused |
| C2S12-B05 | test_rooms_drawn_again_on_other_sheets_arent_counted_twice | A ceiling plan (repeat view) and an E-sheet skipped with reasons; 2 rooms, 234 sq ft |
| C2S12-B06 | test_unscaled_views_and_no_plans | Unscaled note; no plans note; no estimate refused; another company not found; an unknown trade refused |
| C2S12-B07 | test_trade_answers_fit_the_trade_modules | Every answer is a question of its module; choice answers are valid choices |
| C2S12-L01 | test_legend_words_name_the_new_symbols (20 cases) | Legend wording → new item types, and the general ones still work |
| C2S12-L02 | test_every_symbol_feeds_a_real_trade_question | FEEDS questions and choices exist in the registry; trades match; codes unique; block names and codes for new types |
| C2S12-L03 | test_electrical_and_plumbing_answers_count_approved_symbols | Approved count, waiting, include_proposed, tankless, a smoke detector note, a taken-out symbol not counted |
| C2S12-T01 | test_the_mcp_tools | Both tools, one trade and all; errors as JSON |
| C2S12-L04 | test_all_trades_at_once | Seven trades; electrical says to approve in Reviews |

`tests/estimator/webapp/test_web_sprint12.py`:

| ID | Test | Checks |
| --- | --- | --- |
| C2S12-W01 | test_quantities_for_a_project | The model and seven trades; height=10 → framing "10"; reviewer yes; office and field 403; another company 404 |
| C2S12-W02 | test_bad_requests | height text, too low, too high → 400; POST refused; unknown estimate 404 |
| C2S12-W03 | test_the_page_is_wired | nav page, PAGES.quantities, parseHash, script order, Blueprint Review link, no inline styles, the guide is found by search |

`tests/estimator/browser/test_browser_sprint12.py` (`run_tests_estimator.bat browser [--human]`):

| ID | Test | Checks |
| --- | --- | --- |
| C2S12-B07 | test_plan_quantities_from_blueprint_review | From Blueprint Review to the page; 2 rooms, 3 openings; drywall ceiling = flooring area = 234; a 10 ft height changes framing and the rooms table |
| C2S12-B08 | test_a_project_without_plans_says_so | The empty message and seven trade cards |

Also updated: `tests/estimator/unit/test_est_mcp_tools.py` (98 tools).

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | A real house plan set (architectural floor plan with a finish schedule): open 📐 Plan quantities | Rooms match the plan's room names; areas are within a few percent of the plan's written areas |
| M2 | A plan set with a reflected ceiling plan and electrical sheets | Those sheets are under "Sheets not counted"; floor area isn't doubled |
| M3 | Doors and windows on a real plan | Sizes match the schedules; doors between rooms show 2 rooms |
| M4 | Change the ceiling height to 9 | Drywall and painting wall areas go up by perimeter x 1 ft; framing says "9" |
| M5 | Approve some outlets in Reviews, then reload | Electrical outlets = approved count; the rest "still to check"; tick the box to count them |
| M6 | A plan with a tankless water heater in the legend | Plumbing water_heater "tankless" once it's approved |
| M7 | Ask the AI "give me the drywall quantities from the plans" | It uses plan_trade_answers and quotes where each answer came from |
| M8 | Compare drywall and painting answers | Drywall wall_lf x height + ceiling − openings = painting wall + ceiling |

## Notes for Coder 1 (Jamie)

- **FEEDS** (`plan_engine/symbol_library.py`) maps symbol item types to your module questions. If a module question is renamed, the FEEDS test (C2S12-L02) fails and says which one.
- **Not wired yet:** the Runner's trade tasks and `takeoff_propose` don't use these answers. `plan_trade_answers` is ready for that: each answer has `from`, and the wall trades share `model_key`.
- **No changes to Coder 1 files** this sprint except `est_tools.py` (the 2 tools) and the tool count in `test_est_mcp_tools.py`.

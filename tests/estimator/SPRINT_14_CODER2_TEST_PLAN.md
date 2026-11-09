# Sprint 14 — Coder 2 (David) test plan: elevations, door/window schedule linking, HVAC symbol library

**Scope:** The Coder 2 Sprint 14 row is "Elevation-sheet support; door/window schedule linking; HVAC symbol library". These feed Jamie's expansion trades (HVAC, windows and doors, siding) and exterior paint.

- **Elevations:** each exterior elevation's wall (floor line to plate line, gables left out) and its doors and windows.
- **Schedule linking:** each door and window mark with its size and type, how many are tagged on the floor plans, and the windows and doors trade's counts by kind.
- **HVAC:** a fuller HVAC symbol library; registers, returns, thermostats, mini-split heads and the system type from approved symbols; the area to heat and cool from the rooms.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat browser         Playwright (add --human to watch)
deploy_to_install.bat                   then restart AI-Prowler
```
- **No new database migration, tables or MCP tools.** `plan_get_rooms_walls` and `plan_trade_answers` return more and their descriptions say so.
- **Standard symbol library version 3:** each company's copy is refreshed the next time plans are read.
- **Plans read before this sprint** must be read again (Plans screen) to get their elevations: the elevation wall and openings are found when the sheet is read.
- **No new libraries** (shapely, already required).

## What was built

**Elevations, plan engine** (`plan_engine/elevations.py`, called from `pdf_objects.find`):
- **Which views:** a view titled "… ELEVATION(S)" that isn't interior, cabinet, kitchen, bath, vanity, fireplace or stair. Walls and rooms are no longer looked for in these views (lap-siding courses were being read as walls).
- **Needs a scale;** without one the view says so.
- **Outline:** the line work is joined into closed areas; the building's outline is the biggest joined area that isn't the view's frame. An outline no bigger than an opening (150 sq ft) is refused with "no wall outline found", so a drawing cut off at the view's edge never counts a door as the wall.
- **Wall band:** from the floor line ("FIN. FLR", "F.F.", "T.O. SLAB", "GRADE", …) up to the highest plate line ("T.O. PLATE", "PLATE HT", "TOP OF WALL", "BRG", "EAVE"), each read from the horizontal line the mark sits on. No plate mark: the band is the whole outline, confidence 0.4 and "may include the roof or gable - check it". Stories = plate lines more than 0.2" apart.
- **Openings:** rectangles inside the wall band at least 1'-3" each way, at most 150 sq ft and narrower than 60% of the wall (so siding courses aren't openings); a window's frame and glass are one opening. A door reaches the floor line and is 6 ft or taller; a garage door is such a door 7 ft or wider; the rest are windows.
- **Saved as:** a polygon on layer ELEVATION-WALL labelled "<view> wall · N story/stories", and "opening" polygons on layer ELEVATION-OPENING, measured with the view's scale. The story count is in the label, never in `tag` (tags are linked to schedule marks).

**Elevations, model** (`building/elevations.py`):
- **Each side:** wall sq ft, openings (kind, width, height, area), openings sq ft, net, stories. A side drawn twice (same view title) counts once.
- **Totals:** elevations, elevation_wall_sqft, elevation_openings, elevation_net_sqft, stories.
- **Siding and exterior paint** use the elevations when all four sides are found; otherwise they use the floor plans' outside walls, with a note.

**Door and window schedule linking** (`building/model.py`):
- **Each schedule row:** mark, kind, width and height, type (TYPE / DESCRIPTION / REMARKS / OPERATION / STYLE / MATERIAL columns), QTY, and how many are tagged on the floor plans (`schedule_marks`).
- **Notes:** marks not tagged on the plans aren't counted; a tagged count that differs from QTY is flagged.
- **Openings** carry their type and the type of wall they're in.
- **Windows and doors:** windows under 15 sq ft / 15 and over; garage doors (typed garage, overhead, roll-up, or 8 ft and wider); patio doors (sliding, French, patio, glider, or 5 ft and wider in an outside wall); exterior doors (in an outside wall, or typed EXT); the rest interior.

**Building outline** (siding corners): the rooms of the largest floor plan, each grown by a wall's thickness and joined. Each turn of more than 20° is an outside or inside corner. "simple" walls: at most 6 outside corners and 1 inside.

**HVAC:**
- **Library:** 12 new types. Linear diffuser, floor register, transfer grille, mini-split head, condensing unit, heat pump, air handler, furnace, package unit, duct smoke detector, range hood, dryer vent.
- **Legend words:** specific before general (duct smoke detector before smoke detector, linear diffuser before diffuser).
- **FEEDS:** diffusers and registers → registers, return grille → returns, thermostat → thermostats. A mini-split head feeds two questions: zones and system = mini_split. Heat pump → heat_pump, package unit → package, condensing unit → split; the more particular system wins (`CHOICE_ORDER`).
- **Trade names:** HVAC symbols stay filed under trade "mechanical"; `TRADE_MODULES` maps it to the hvac module.
- **conditioned_sqft:** room floor areas, not counting garages, porches, patios, decks, lanais, carports, attics and similar (noted).

**Trades:** the model answers 8 trades (`MODEL_TRADES`). HVAC gets the model's area plus the symbols' counts. Plan quantities shows 10 trade cards, the door and window schedule table and the exterior elevations table.

## Automated tests

`tests/estimator/plan_engine/test_plan_engine_sprint14.py` (a house front at 1/4": a 40 x 9 ft wall with a 6 ft gable, lap siding courses, two 3 x 5 ft windows with mullions, a 3 x 6'-8" door, plate and floor marks):

| ID | Test | Checks |
| --- | --- | --- |
| C2S14-E01 | test_which_views_are_exterior_elevations (8 cases) | North/front/exterior yes; kitchen/interior/plan/section no |
| C2S14-E02 | test_the_wall_and_its_openings_from_an_elevation | 360 sq ft (no gable), "1 story", door 20 + windows 15 + 15, no walls or rooms from siding lines |
| C2S14-E03 | test_without_a_plate_line_the_gable_is_in_and_it_says_so | 480 sq ft with the gable and a check note; a two-story front says "2 stories" |
| C2S14-E04 | test_four_sides_give_siding_and_exterior_paint | 4 sides, 1440 sq ft, 12 openings, net 1240; siding and exterior paint from them; 4 outside corners, simple; rooms unchanged |
| C2S14-E06 | test_a_view_cut_off_at_its_edge_counts_no_wall | A drawing running into the title block: no wall saved (not the door) |
| C2S14-E05 | test_fewer_sides_fall_back_to_the_floor_plan | 1 side: note; siding and exterior paint from the floor plans |
| C2S14-W01 | test_doors_and_windows_by_kind_from_the_linked_schedule | Marks with type, QTY, on the plans; untagged D3 and W2 noted; D2 count differs noted; 1 small window, 1 exterior and 1 interior door |
| C2S14-W02 | test_which_door_is_which (7 cases) | Sliding, French, overhead, 9 ft, EXT., inside, 6 ft outside |
| C2S14-H01 | test_legend_words_name_the_hvac_symbols (18 cases) | HVAC words, and smoke detector / ceiling fan still right |
| C2S14-H02 | test_the_hvac_library | Version 3, mechanical → hvac, two feeds for a mini-split head, codes and block names |
| C2S14-H03 | test_hvac_answers_from_symbols_and_the_rooms | 234 sq ft, 3 registers, 1 return, 1 thermostat, 2 zones, mini_split |
| C2S14-H04 | test_garages_and_porches_arent_heated_or_cooled | LIVING 120 counted, GARAGE 114 noted |
| C2S14-T01 | test_every_model_trade_fits_its_module | All trades' answers are questions of their module with valid choices; one model_key |

`tests/estimator/webapp/test_web_sprint14.py`: C2S14-P01 (the API returns the schedule marks, the 4 elevations, and windows and doors, siding, HVAC and exterior paint answers) and C2S14-P02 (the page's new tables and trade cards, no inline styles).

Also updated: Sprint 12 tests for the 10 trades and for symbols that feed two questions; browser test B08 counts 10 trade cards.

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | A real elevation sheet (4 sides) | 4 sides listed; each wall within 5% of a hand measure (floor to plate, less gables) |
| M2 | An elevation without plate marks | The note says the roof may be included |
| M3 | Window counts on an elevation | Every window and door found once; mullions don't split a window |
| M4 | A real door and window schedule | Every mark listed with size and type; untagged marks shown in yellow and noted |
| M5 | Windows and doors trade | Small/large windows, patio, exterior, interior and garage doors match a hand count |
| M6 | An L-shaped house | Siding: 5 outside, 1 inside corner; walls simple |
| M7 | A mechanical plan with a legend | Diffusers, returns, thermostats counted after approval; mini-split heads set the system |
| M8 | A plan with a garage | HVAC area leaves the garage out and says so |

## Notes for Coder 1 (Jamie)

- **New FEEDS rows:** HVAC symbols now answer `hvac` questions. A FEEDS value can be a tuple of feeds (`feeds_of()`); `TRADE_MODULES` maps a symbol trade to a module.
- **Read plans again:** existing plan sets need reading again to get elevations.
- **Not wired yet:** the Runner's trade tasks and `takeoff_propose` still don't use `plan_trade_answers`.

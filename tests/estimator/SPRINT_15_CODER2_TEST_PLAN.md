# Sprint 15 — Coder 2 (David) test plan: site-plan zones for fencing and landscaping

**Scope:** The Coder 2 Sprint 15 row is "Site-plan zones for fencing and landscaping". These feed Jamie's Fencing and Landscaping trades (Coder 1 Sprint 13) and, through his `takeoff/from_plans.py`, their proposed measurements.

- **Zones:** sod/lawn, artificial turf, rock/gravel/decomposed granite, mulch, pavers and planting beds, each area named by its note (or the note whose leader points into it).
- **Fences and gates:** fence lines followed from their notes (PDF) or read from fence layers (DXF), with material and height; walk and drive gates.
- **Plants:** trees and shrubs from the plant schedule, or from the new landscape symbols when there's no schedule.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat browser         Playwright (add --human to watch)
deploy_to_install.bat                   then restart AI-Prowler
```
- **No new database migration, tables or MCP tools.** `plan_get_rooms_walls` / `plan_trade_answers` return the site and answer fencing and landscaping.
- **Standard symbol library version 4:** each company's copy is refreshed the next time plans are read.
- **Plans read before this sprint** must be read again (Plans screen) to get their zones, fences and gates.
- **No new libraries** (shapely and ezdxf, already required).

## What was built

**Plan engine** (`plan_engine/site.py`, called from `pdf_objects.find` and `dxf_reader.read`):
- **Which views:** SITE / PLOT / LANDSCAPE / PLANTING / HARDSCAPE / IRRIGATION / FENCE / YARD PLAN, or any view on a site or landscape sheet (the title block's discipline is now passed in) that isn't an elevation, section, detail, schedule, legend, notes, key plan or vicinity map. Walls and rooms aren't looked for there.
- **Needs a scale;** without one the view says so and nothing is saved.
- **Zones (PDF):** a zone word in a note of at most 60 characters (fence and gate notes excluded) names the smallest closed area round it, or round the end of a leader drawn from it. Hatching (lines at one slanted angle on 6 or more separate parallel lines) is taken out first, so the area isn't one hatch strip. Areas with holes (lawn round the house) are saved as one outline with zero-width cuts to the holes, so the measured area leaves the holes out. "EXISTING … TO REMAIN" isn't counted. Two notes in one area: the first wins, noted if they differ.
- **Fences (PDF):** a fence note (FENCE, FENCING, BLOCK/CMU/MASONRY/GARDEN/SCREEN WALL) finds the nearest line (along its leader, or within about three text heights of the note's box), and the line is followed end to end through dashes and corners (0.12" gaps) until it ends or forks. Confidence 0.5 and a note to check each run. Runs under 4 ft are dropped.
- **Gates:** a GATE note or block: drive if DOUBLE / DBL / DRIVE / VEHICULAR / ROLLING / SLIDING / AUTO or 8 ft and wider, else walk; "(2) 4' GATES" is 2. "12 FT GATE" is a 12 ft gate, not 12 gates.
- **DXF:** closed polylines and hatches on zone layers (TURF/SOD/LAWN/GRASS, ARTIF/SYNTH, ROCK/GRAV/DG/STONE, MULCH, PAVER, PLNT/SHRUB/BED) or with a GRASS/GRAVEL hatch pattern are zones (a hatch's islands are holes); notes inside closed areas are used when a site or landscape drawing has no zone layers. Every line on a FENC layer is a fence run, named by the nearest fence note within 20 ft (or its layer). GATE blocks and notes are gates. Hatch outlines count toward the drawing's extents.
- **Saved as:** zones = polygons on layer SITE-ZONE labelled "<zone> · <note>"; fences = polylines on SITE-FENCE labelled "fence · <note>"; gates = text points on SITE-GATE labelled "<n> walk|drive gate(s) · <note>".

**Schedules:** "PLANT SCHEDULE" / "PLANTING SCHEDULE" / "LANDSCAPE (PLANT) SCHEDULE" tables are read as schedule type `plant` (added to the drawing model's schedule types).

**Landscape symbol library (v4):** tree, palm, shrub, drip_valve, irrigation_valve, irrigation_controller (trade "landscape", priced in landscaping). Legend words first in the list; codes DCV, RCV, ZV (DV stays the dryer vent). FEEDS: tree and palm → trees, shrub → shrubs, drip valve → drip_zones, irrigation valve → sprinkler_zones. The company library accepts the "landscape" trade.

**Model** (`building/site.py`, in `building.build` as `site`):
- **Counted once:** zones from one sheet (landscape sheets first, then the most area), fences from the sheet with the most fence, gates from the fence sheet (else the most gates); the others are noted.
- **Totals:** zone sq ft by kind, rock depth from the rock note ("3\" DEEP"), bed/rock/mulch outline lf, fence groups by material and height, fence lf, old fence to remove, walk and drive gates, trees and shrubs from the plant schedule (ground cover by the flat or square foot, sod and seed aren't plant counts; rows with no QTY are noted).
- **Fencing answers:** the longest material-and-height group gives length_lf, material and height (nearest of 4/5/6/8, noted if not exact); other fence kinds are noted for a second line; remove_old; walk_gates, drive_gates.
- **Landscaping answers:** sod_sqft, turf_sqft, rock_sqft (+ rock_depth), pavers_sqft, trees, shrubs; mulch and planting beds noted (the trade has no question for them); trees, shrubs and zone valves also from approved symbols when the schedule doesn't give them.
- `MODEL_TRADES` has 10 trades (+ fencing, landscaping); `trades.TRADES` 12; landscaping is also a symbol trade. Site trades' notes are the site's, not the house's.

**Web:** Plan quantities shows a "Site and landscape" section (zones table, fences table, gates), says "site and landscape plans" instead of "no rooms found" for a yard-only project, and has Fencing and Landscaping trade cards (12 in all). Guide step 10.

## Automated tests

`tests/estimator/plan_engine/test_plan_engine_sprint15.py` (a yard at 1/8": a 96 x 80 ft lot, a 40 x 32 ft house, a 16 x 16 ft paver patio against it, a 32 x 16 ft hatched rock bed, the rest lawn = 5632 sq ft; a dashed 6 ft wood fence of 92 + 22 ft; a walk gate and a double drive gate; a plant schedule):

| ID | Test | Checks |
| --- | --- | --- |
| C2S15-W01 | test_which_views_are_site_plans (12 cases) | Site/landscape/planting/irrigation/fence plans and site-sheet views yes; floor plans, details, fence elevations, schedules no |
| C2S15-W02 | test_zone_words (20 cases) | Sod, turf, rock, mulch, pavers, beds; fence, gate, house, driveway and a long spec note aren't zones |
| C2S15-W03 | test_fence_and_gate_notes | Materials, heights, removal, walk/drive gates, counts, existing, rock depth |
| C2S15-S01 | test_zones_by_kind_with_the_house_left_out | Lawn 5632, pavers 256, rock 512; no walls or rooms on a site plan |
| C2S15-S02 | test_hatching_doesnt_cut_a_zone_into_strips | Rock 512 with or without hatching |
| C2S15-S03 | test_a_fence_line_through_its_dashes_and_corner_and_the_gates | One run, 114 ft, 3 points; 1 walk and 1 drive gate |
| C2S15-S04 | test_a_note_with_a_leader_names_the_area_it_points_to | A sod note outside the lot with a leader: lawn 5632 |
| C2S15-S05 | test_existing_areas_and_unscaled_views_arent_counted | "EXISTING LAWN TO REMAIN" not counted; no scale, no zones |
| C2S15-S06 | test_the_plant_schedule | Type plant; 5 trees (oaks and palms), 14 shrubs; liriope flats left out |
| C2S15-T01 | test_fencing_and_landscaping_answers | Fencing 114 lf wood 6 ft, 1 + 1 gates; landscaping sod, rock + depth 3, pavers, trees, shrubs; 12 trades |
| C2S15-T02 | test_a_second_kind_of_fence_and_an_old_fence_to_remove | 52 lf of 4 ft chain link noted; "REMOVE EXISTING FENCE" → remove_old, no new length |
| C2S15-T03 | test_the_same_yard_on_two_sheets_is_counted_once | Site plan + landscape plan: lawn and fence once, noted; no rooms |
| C2S15-T04 | test_no_site_plans_say_so | No fence lines / no zones notes; no symbol noise |
| C2S15-T05 | test_measurements_from_the_site_plan | Jamie's from_plans.propose makes sod, trees, shrubs measurements; rock depth as a choice; fencing length and gates |
| C2S15-D01 | test_dxf_fence_layers_zone_hatches_and_gate_blocks | DXF in feet: hatch lawn with a hole 1400, rock layer 200, 100 ft fence on L-FENC, vinyl 6 ft, a GATE block |
| C2S15-L01 | test_the_landscape_symbol_library | Legend words, block names, feeds, landscape → landscaping, DV still the dryer vent |

`tests/estimator/webapp/test_web_sprint15.py`: C2S15-P01 (the API returns the site, fencing and landscaping answers, 12 trades, no rooms) and C2S15-P02 (the page's site tables and trade cards, no inline styles; the guide's step).

Also updated: earlier tests that counted 10 trades now count 12 (see the run).

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | Upload a real residential landscape plan (PDF) and read it | The lawn, rock and mulch areas show on Plan quantities with sensible sq ft; each area matches the plan when opened in Blueprint Review (SITE-ZONE layer) |
| M2 | A real site plan with a fence note | The fence run starts and stops where the plan's fence does; if it runs along the property line too far, it's noted for checking and can be corrected in Blueprint Review |
| M3 | A plant schedule on a real landscape sheet | Trees and shrubs match the schedule's QTY column; ground covers aren't counted |
| M4 | A CAD landscape plan (DXF) with L-TURF / L-ROCK hatches and an L-FENC layer | Zones and fence length match the CAD measurements |
| M5 | A plan set with both a site plan and a landscape plan | Each zone and fence counted once; the note says which sheet was used |
| M6 | Propose measurements from the plans for Landscaping and Fencing (chat: takeoff_propose / Jamie's from-plans) | Proposed measurements for sod, rock, pavers, trees, shrubs, fence length and gates; approve them and price |
| M7 | Plan quantities in the Jobs app (phone) for a yard-only project | "Site and landscape" section and the Fencing and Landscaping cards show; no "no rooms found" box |
| M8 | Re-read a plan set read before this sprint | Its zones and fences appear after reading again |

## Known limits

- Zones need a note inside the area or a leader into it; unlabelled areas aren't counted (draw them in Blueprint Review). Areas shown only by a hatch pattern in a PDF, with no note, aren't found.
- Fence lines in PDFs are followed by joining line ends, so a fence drawn right on top of a property line can follow the property line; each run is marked to check.
- Edging, clearing and irrigation heads aren't read yet; drip and sprinkler zones come from approved valve symbols.
- Mulch has no question in the Landscaping trade, so it's noted to price by hand.

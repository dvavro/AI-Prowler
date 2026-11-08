# Sprint 6 — Coder 2 (David) test plan: plan engine v0.6 (vector line work, walls, rooms, DXF)

**Scope:** The Coder 2 Sprint 6 row is "Vector extraction from PDF line work, DXF import (`ezdxf`), wall and room detection (`shapely`)". It's built into the plan engine package `estimator/plan_engine/` (now version 0.6). What the engine finds is saved as drawing objects through Jamie's drawing model, so `plan_get_objects` and the takeoff tools can use it. The web sheet page now says what was found.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat planengine      plan engine only
pip install -r requirements.txt         (or install_estimator.py) for ezdxf and shapely
deploy_to_install.bat                   then restart AI-Prowler
```
No new tools or tables. **New libraries:** `ezdxf==1.4.5` and `shapely==2.2.0`. They're in a new Estimator section of `requirements.txt`, along with `PyYAML==6.0.3`, which the Director already needed. `install_estimator.py` notes it if either is missing, and it doesn't stop.

## What was built

**PDF line work** (`pdf_pages.py` → `page.segments`; `vectors.py`; `pdf_objects.py`):
- Lines, rectangle edges and curves come out of each page in inches from the top-left, the same frame as the image. There are at most 120,000 a page.
- Each viewport is worked on separately, with its own scale (from `parse_scale`). The title block's strip is left alone.
- **Walls**: two parallel lines 3–16 in apart (real size) that overlap for at least 24 in.
  - A line pairs with its closest partner. A long line pairs with each piece across a door.
  - Horizontal, vertical and angled walls are all found.
  - The wall object is the centerline, with its thickness in inches.
  - On an unscaled view, paper thresholds are used (1/32"–1/4" apart, 1/4" long). The walls are counted but not measured.
- **Rooms**: closed areas from the line work (`shapely` polygonize). A room name inside an area makes it a room, using the smallest area around the name.
  - A room name is upper case or title case and not a stop word ("NOTE", "SCALE"…). Sheet numbers, tags and dimensions aren't room names.
  - Rooms must be at least 12 sq ft. That keeps closet symbols out. An area bigger than 70% of the view (the view's frame) doesn't count.
  - With double wall lines, the room is the inside.
  - Too much line work (over 25,000 segments in a view) skips rooms and says so in the sheet note.
- At most 5,000 objects a sheet.

**DXF** (`dxf_reader.py`, `ezdxf`):
- **Size and units:**
  - One sheet per drawing, the size of its contents in real units from INSUNITS: in, ft, mm, cm or m.
  - With no units, inches are assumed and the sheet says so.
  - The y axis is flipped to top-left, like the PDFs.
- **What's read:**
  - Lines, polylines, arcs, circles and splines become line/polyline/polygon objects. A closed polyline's repeated first point is dropped.
  - TEXT and MTEXT become text objects.
  - Block inserts become symbols with the block name and a tag from their attributes.
  - Dimensions are kept with their text.
  - Hidden and frozen layers are skipped.
- **Walls** come from layers named WALL when there are any, otherwise from parallel lines.
- **Rooms** come from closed polylines on ROOM/AREA/SPACE layers first, otherwise from closed areas and room names.
- No scale is needed, since the drawing is already real size. The viewport is "model" and is measured as-is. Setting a scale on it is refused.
- **Rendering and discipline:**
  - A PNG is rendered so the sheet page has an image.
  - The discipline comes from the file name, then the layer prefixes (A-, E-, M-…).
- **Problems:** an empty or broken DXF gives a plain message.

**DWG**: there's still no free reader. The message says to save as DXF or print to PDF.

**Web sheet page**: GET `/sheets/<id>` now returns `found`, which has, by kind, the count, how many are measured, and the total length (ft) or area (sq ft). The page shows a "Found on this sheet" card with one line per kind, e.g. "12 walls · 186 ft", "5 rooms · 742 sq ft", "40 notes". Walls and rooms on an unscaled view add "N not measured yet — set the scale". Checking and approving them comes with Blueprint Review (Sprint 7). The guide "Upload plans and check the scale" covers it, along with DXF and DWG.

## Test cases

`tests/estimator/plan_engine/test_plan_engine_sprint6.py` (PDFs from `pdfmaker.py`, which now draws lines; DXFs built with `ezdxf`):

| ID | Test | Checks |
|---|---|---|
| C2S6-W01 | `test_a_wall_is_two_parallel_lines` | 0.125" at 1/4" → a 6" wall, 16 ft, centerline |
| C2S6-W02 | `test_not_walls` | 1/2" and 24" apart aren't walls |
| C2S6-W03 | `test_short_lines_and_lines_that_dont_overlap_arent_walls` | too short; side by side but not overlapping |
| C2S6-W04 | `test_vertical_and_diagonal_walls` | both found with the right length |
| C2S6-W05 | `test_a_long_line_pairs_with_each_piece_across_a_door` | two walls, either side of the door |
| C2S6-W06 | `test_unscaled_view_still_finds_walls_on_paper` | found, not measured |
| C2S6-W07 | `test_title_block_line_work_is_left_alone` | no walls in the title block strip |
| C2S6-W08 | `test_dashed_lines_and_hatching_stay_fast` | a 4,000-dash line + 2,000 hatch lines in under 5 s, and the real wall is still found |
| C2S6-R01 | `test_a_room_is_a_name_inside_a_closed_area` | KITCHEN, 144 sq ft |
| C2S6-R02 | `test_double_wall_lines_the_room_is_the_inside` | the inner area |
| C2S6-R03 | `test_names_outside_or_in_tiny_areas_are_not_rooms` | closet-sized box; name outside |
| C2S6-R04 | `test_the_view_title_is_not_a_room` | a box around the title isn't a room |
| C2S6-R05 | `test_room_names` | upper/title case yes; dimensions, tags, sheet numbers, lower case, NOTE no |
| C2S6-R06 | `test_too_much_line_work_skips_rooms_and_says_so` | note on the sheet |
| C2S6-X01 | `test_dxf_real_size_units_and_top_left_origin` | size, units, y flipped |
| C2S6-X02 | `test_dxf_units` | ft, mm, cm, m |
| C2S6-X03 | `test_dxf_without_units_says_inches_were_assumed` | note |
| C2S6-X04 | `test_dxf_walls_rooms_symbols_text_dimensions` | WALL layer walls, a room, a symbol with its tag, text, a dimension |
| C2S6-X05 | `test_dxf_room_layer_polylines_are_rooms` | ROOM layer polyline with its name |
| C2S6-X06 | `test_dxf_hidden_layers_are_skipped` | a layer that's off is left out (frozen is handled by the same check) |
| C2S6-X07 | `test_dxf_discipline_from_layers` | E- layers → electrical |
| C2S6-X08 | `test_empty_and_broken_dxf` | plain messages |
| C2S6-D01 | `test_pdf_walls_and_rooms_are_measured_with_the_views_scale` | end to end through the store: objects saved and measured |
| C2S6-D02 | `test_dxf_is_measured_without_a_scale` | end to end: DXF objects measured with no scale |
| C2S5-F01 (changed) | `test_dwg_says_how_to_get_it_read` (in the Sprint 5 file) | DWG → "save as DXF or print to PDF" |

`tests/estimator/webapp/test_web_sprint6.py`:

| ID | Test | Checks |
|---|---|---|
| C2S6-A01 | `test_sheet_says_what_was_found_and_measured` | `found` counts, lengths and areas at 1/4" |
| C2S6-A02 | `test_unscaled_finds_are_counted_but_not_measured` | counted; after setting a scale through the API, measured |
| C2S6-A03 | `test_dxf_through_the_plans_pages` | upload → read → sheet with walls/rooms; setting a scale on the CAD view refused |
| C2S6-A04 | `test_web_page_shows_the_found_summary` | the page has the card and no innerHTML/style attributes |

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), all Estimator tests | 1020 passed (2026-11-08) |
| Windows 11, Python 3.11.8, Coder 2 track (webapp + plan engine) | 347 passed (2026-11-08) |
| Real PDF smoke test (57-page spec PDF) | still 0.18 s a page; no walls or rooms on text pages |

## Manual checks

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | `pip install -r requirements.txt` (or run install_estimator.py), deploy, restart | no ezdxf/shapely note | |
| M2 | A real floor plan PDF → Read the plans → open the floor plan sheet | "Found on this sheet" shows walls and rooms | |
| M3 | Compare a few rooms with the plan | names right; areas close to the plan's own room areas | |
| M4 | A sheet with no scale → note the card → set a scale | "counted" becomes measured lengths and areas | |
| M5 | Upload a DXF floor plan exported from CAD | one sheet with an image, walls and rooms measured, no scale needed | |
| M6 | Upload a DWG | the "save as DXF or print to PDF" message | |
| M7 | In chat: `plan_get_objects` on the sheet | the same walls and rooms | |

## Notes for Jamie

- The engine now saves walls (centerline + `thickness_in`), rooms (polygon + name) and DXF symbols/text/dimensions through your `_check_results`. The sources are `vector` for PDFs and `cad` for DXF. Nothing in the drawing model changed.
- DXF sheets use real units (`in`/`ft`/`mm`/`cm`/`m`) and one "model" viewport with no scale. Your store already measures those as-is.
- The router still reads sheet sizes with `store._load_sheet`. It would be nice if `sheets()`/`viewports()` returned width and height.

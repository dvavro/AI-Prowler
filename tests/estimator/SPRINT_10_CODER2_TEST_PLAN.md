# Sprint 10 — Coder 2 (David) test plan: Symbol Recognition Engine v1, Jobs board for all lanes

**Scope:** The Coder 2 Sprint 10 row is "Symbol Recognition Engine v1: template/feature matching, OCR fusion, standard symbol library, fused results (`symbol_detections_*`); Jobs board for all lanes".

- **Symbols:** every symbol in the plan set's legend is searched for on every sheet. Each hit is checked against the codes beside it, and the result is saved as one standardized detection.
- **Jobs board:** jobs in the standard and plan-takeoff lanes show where they stand.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
deploy_to_install.bat                   then restart AI-Prowler
```
- **New database migration:** 14 (symbol tables).
- **New MCP tool:** `symbol_detections_list`.
- **No new libraries:** it uses numpy and scipy, which are already installed (OpenCV isn't needed).

## What was built

**Plan engine 0.8** (`estimator/plan_engine/symbols.py`, `symbol_library.py`):

**Vector sheets (template matching):**
- **Template:** the legend symbol's line work.
- **Finding copies:** its longest stroke is laid on every stroke of about the same length on the sheet. That gives any rotation, mirrored or not, within 10% of the size.
- **Scoring:** a hit needs at least 80% of the template on line work (forward). The line work there must also be explained by the template (reverse), so a symbol with extra strokes is the richer legend entry. A wall running through an outlet doesn't count against it.
- **Excluded:** the legend's own samples, schedules and the title block.

**Raster sheets (scans):**
- **Matching:** normalized cross-correlation of the legend's picture over the sheet image at 60 px/in. It tries 4 turns, mirrored and not, on a slightly blurred image.
- **Ink check:** a hit must have about as much ink as the symbol, so a box that shares one stroke isn't a hit.
- **Review:** always marked to check.

**CAD:** block names map through the standard library (DUPLEX_OUTLET_GFI → GFCI receptacle). Unknown blocks (doors, furniture) stay plain CAD blocks.

**OCR fusion:**
- **Look-alikes:** a code beside a hit (GFI, WP) picks between legend entries that look the same. If no code is there, the plain entry wins.
- **Refining from the standard library:** a code can refine a plain legend symbol, e.g. a receptacle with "GFI" beside it becomes a GFCI receptacle.
- **Code-only legend entries** (e.g. "SD — smoke detector") are counted where the code stands on its own. A code inside a sentence doesn't count.

**Standard library:** 37 item types with trade, OCR codes and CAD block words. Each company gets a copy in estimator.db.

**Results:**
- **Engine output:** each symbol becomes a `symbol` drawing object with a `symbol` record: legend entry or standard type, item type, trade, scores (legend / vision / ocr / ai / cad), confidence, rotation, mirrored, bbox, method, needs_review. `results["symbol_dictionary"]` lists the legend entries.
- **Never approved automatically.** AI crop reasoning (the fourth technology) is left empty for now.

**Saving** (`estimator/symbols/`, migration 14):
- **Tables:** `symbol_libraries`, `symbol_definitions`, `symbol_examples` and `symbol_detections`, as in the spec's data model.
- **Plan-set dictionary:** legend entries become definitions with a `legend_id` (and their cropped picture as a `symbol_examples` row). They're replaced when the plan set is read again.
- **Detections:** each detection gets its sheet, viewport and room (found by point-in-room), status `proposed`, and `needs_review`.
- **Where:** saved in `store.save_results`' transaction (a small hook in Jamie's store).
- **`plan_get_legends`** now reads the dictionary from the table, with how many of each entry were found. The Sprint 9 file is only a fallback.

**API, tool and pages:**
- **`symbol_detections_list`** (MCP) and `GET /plan-sets/<id>/symbols?type=&sheet=&room=&status=&min=&review=`:
  - Filters: plan set or estimate, item type, sheet, room, status, min_confidence, needs_review.
  - Returns detections with counts by type, sheet and room.
  - Anyone who can open plans can use it; field staff count devices too.
- **Plan set page:** a **Symbols found from the legend** table (type, trade, found, to check, per sheet). The legend tables gain a **Found** column.
- **Blueprint Review:** symbols sit in their trade's layer (Electrical, Plumbing...) and carry what was found.
- **Jobs board (all lanes):**
  - **Summary:** jobs per lane and "waiting on you".
  - **Every job:** step n of N and the next step, from the lane's playbook.
  - **Standard and plan-takeoff jobs:** plans (sheets, reading, failed, need a scale), symbols (found, to check), measurements (approved, waiting, suggested changes), the latest runner run (trades done / to review / failed) and open reviews. Links to the project, Blueprint Review and the estimate follow the role. (`estimator/api/jobs_board.py`: a few grouped queries for the whole board.)
- **Guide:** "Count symbols from the plan's legend".

## Test cases

`tests/estimator/plan_engine/test_plan_engine_sprint10.py`, `tests/estimator/webapp/test_web_sprint10.py`:

| ID | Test | Checks |
|---|---|---|
| C2S10-E01 | Any turn, mirrored | 0°, 90°, 45°, 1.05×; triangle at 30°; flags mirrored and at 200°; 1.5× not taken; legend samples not counted; unnamed entry needs review; sheet note |
| C2S10-E02 | Look-alikes by code | plain, GFI and WP copies of one shape → the right entries; OCR score |
| C2S10-E03 | Extra strokes | a quad (receptacle + a bar) is the quad entry, not a duplex |
| C2S10-E04 | Busy surroundings | a wall through the outlets and hatching nearby |
| C2S10-E05 | Standard library refines | plain legend receptacle + "GFI" beside it → GFCI from the standard library |
| C2S10-E06 | Code-only entries | "SD" counted where it stands alone, not inside a note |
| C2S10-E07 | Block names and codes | 8 block names; GFI and $3 codes |
| C2S10-E08 | CAD | DUPLEX_OUTLET_GFI blocks become detections; DOOR_36 doesn't |
| C2S10-E09 | Raster | flags on a scan, one turned, a box not taken |
| C2S10-E10 | Speed | 6,000 random strokes + 40 symbols under 60 s, ≥ 38 found |
| C2S10-E11 | Saved | definitions, detections, room (KITCHEN), counts by type and room, filters, object label, dictionary with found counts and picture |
| C2S10-E12 | Read again | replaced, not doubled; standard library kept once; refined detection uses the standard definition |
| C2S10-E13 | MCP tool | list, estimate filter, errors, registered |
| C2S10-W01 | Symbols API | counts, filters, limit, bad status 400 |
| C2S10-W02 | Legends | found counts per entry |
| C2S10-W03 | Roles and errors | reviewer/field read; office 403; another company 404; unknown 404 |
| C2S10-W04 | Jobs board | summary by lane and waiting on; links; full-takeoff progress (plans, symbols, step 3 of 8); quick lane step only |
| C2S10-W05 | Measurements and runner | approved / waiting / suggested; trades done and to review |
| C2S10-W06 | Links by role | field: plans yes, takeoffs no |
| C2S10-W07 | Pages | the calls and labels; no innerHTML or style attributes |
| C2S10-W08 | Guide | names what's on the page |
| C2S10-W09 | Review layers | symbols in the Electrical group with what was found |

Changed (Jamie's files, reasons in the spec's Change log):
- `migrations.py` gains migration 14.
- `store.save_results` keeps the new object and legend ids and calls `estimator/symbols/results.save`. It also deletes the old plan-set dictionary on a re-read.
- `est_tools.py` gains `symbol_detections_list`.
- `test_est_database.py` and `test_est_mcp_tools.py` are updated for migration 14 and 92 tools.

Also fixed:
- A device code (GFI, WP) is no longer taken for a room name.
- The 1'-0" in a scale note is no longer a dimension.

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), Coder 2 track | 476 passed (2026-11-08) |
| Same PC, all Estimator tests | see the Implementation Plan progress row |
| Browser smoke test (scratch `symbols_smoke.py`, headless Chromium) | symbol counts, legend Found, Jobs board progress, Electrical layer: no problems |

## Manual checks (David)

| # | Check | Expect | Result |
|---|---|---|---|
| M1 | A real electrical plan with a legend sheet | outlets, switches, lights found; counts close to a hand count | |
| M2 | GFI / WP codes beside receptacles | counted as GFCI / weatherproof | |
| M3 | A real DXF with device blocks | blocks named, doors and furniture left alone | |
| M4 | A scanned plan with a legend | symbols found, all marked to check | |
| M5 | Plan set page and Blueprint Review | counts table; symbols in the trade's layer | |
| M6 | Jobs board with a plan takeoff job | progress line, links work for owner and field | |
| M7 | Ask Claude "how many GFCI outlets are on the plans?" | answers from symbol_detections_list | |

## Notes for Jamie

- **Migration 14** (symbol tables) is mine. If you've added a 14 too, whichever of us merges second renumbers. Neither has shipped.
- **`store.save_results`** has a small hook: it records the ids it inserts and calls `estimator.symbols.results.save` in the same transaction. Bad symbol data is skipped, never fatal.
- **`reviews.start("detection_set", …)`** still says the symbol engine isn't installed. The detections now exist (`symbol_detections`, status proposed). Approving, relabelling and find-similar (`symbol_detection_review`, `symbol_find_similar`) are my Sprint 11, with the Reviews screen.
- **Counts for the trade agents:** `symbol_detections_list(estimate_id=…)` gives counts by type and room. Feeding them into `takeoff_propose` (one count measurement per type) is yours or the Runner's.

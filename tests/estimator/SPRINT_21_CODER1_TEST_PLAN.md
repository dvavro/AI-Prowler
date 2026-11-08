# Sprint 21 — Coder 1 (Jamie) test plan: the shared drawing model and plan_* tools

**Scope:** The Coder 1 work from planned Sprint 5 (Phase 2, Plan engine MVP): the drawing model tables (`plan_sets`, `sheets`, `viewports`, `drawing_objects`, `schedules`, `schedule_rows`, `legends`) and the `plan_*` tools. The plan engine that reads PDFs and CAD files is Coder 2's (David). This sprint builds where its results go and everything the Estimator does with them, so his engine plugs straight in.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
Then start AI-Prowler again. The database upgrades itself to version 11. There are 75 Estimator tools (11 new).

## What was built

**Uploads** (`estimator/drawing_model/uploads.py`, `plan_upload`). It takes the full path of a file on the PC and checks it before attaching it to an estimate:
- the file is a real PDF, PNG, JPG, TIFF, DXF or DWG (its contents are checked, not only the name)
- it isn't empty and is under 300 MB
- it isn't a password-protected PDF
- it isn't already on that estimate
- images under 150 DPI get a warning; DWG gets a note that it needs a converter

The original is copied to `projects\estimate_NNNN\plans\`. A revised set points at the set it replaces (revision 2, 3, ...). Owner, estimator and office can upload. It asks first.

**Measuring** (`estimator/drawing_model/geometry.py`). Exact decimal math, results in feet, square feet and counts:
- scale notes: 1/4" = 1'-0" → 48, 3/16" → 64, 1" = 20' → 240, 1:100, NTS
- typed distances: 12'-6", 12.5 ft, 150 in, 3.5 m
- line and path lengths, polygon area (shoelace) and perimeter
- two-point calibration
- Paper geometry is measured with the scale of the viewport it sits in. CAD sheets in real units need no scale. NTS viewports and unscaled paper geometry are never measured; they say why instead.

**The drawing model** (`estimator/drawing_model/store.py`). The plan engine's results are checked completely before anything is written. A bad result never leaves half a model, and the old model stays. Saving does three things:
- measures every object
- links schedule rows to plan tags by mark ("D3" finds both "D3" and "d 3")
- records the page count and engine name

Reading the plans again replaces the model, so it asks first.

**The plan engine hook** (`estimator/drawing_model/engine.py`). David's engine is a package `estimator.plan_engine` with `process(file_path, file_type, info) -> dict`. It is found automatically. The exact result format is written at the top of `engine.py`. Processing runs in a background thread with its own database connection. Engine errors set the plan set to failed with the reason. Until the engine exists, `plan_process` says so and points to `runner_submit_takeoff`.

**Tools** (`plan_upload`, `plan_process`, `plan_status`, `plan_get_sheets`, `plan_get_sheet_image`, `plan_get_viewports`, `plan_set_scale`, `plan_get_objects`, `plan_get_schedules`, `plan_update_schedule_row`, `plan_get_legends`).
- `plan_get_objects` filters by plan set, sheet, kind (several allowed), layer, tag, viewport or an area of a sheet. It pages up to 1000 objects and gives totals by kind.
- `plan_set_scale` takes a note, a ratio or two points and a distance, then re-measures that viewport.
- Changes ask first and are logged on the estimate (`plan_uploaded`, `plan_processed`, `plan_scale_set`, `schedule_row_corrected`).

**Also:**
- The Plan Reader and Takeoff agent instructions now use these tools.
- The pack-up (`est_data_export`) says plan sets are left behind (re-upload on the other PC) instead of silently dropping them.
- A deleted practice project takes its plan sets with it.

## Test cases (tests/estimator/unit/test_sprint21_plans.py)

| ID | Test | Checks |
|---|---|---|
| S21-G01 | Scale notes | 1/4", 1/8", 3/16", 1-1/2", 1" = 20', 1:100, NTS, N.T.S.; nonsense refused |
| S21-G02 | Typed distances | feet-inches, inches, metres, plain numbers; nonsense refused |
| S21-G03 | Math | area either direction, perimeter, 3-4-5 length, calibration to 48, unknown scale never guessed, bad shapes refused |
| S21-U01 | Upload | asks first; copied into estimate_NNNN\plans; still works after the original is deleted; duplicate refused with its plan set number |
| S21-U02 | Refusals | a program renamed .pdf, password-protected PDF, empty file, .docx, PNG named .jpg, relative path, missing file, over the size limit; nothing saved |
| S21-U03 | Kinds and roles | DXF, PNG (low-DPI warning), DWG as revision 2 with converter note; field can't upload; another company can't see it; a revision must be on the same estimate |
| S21-M01 | Saved and measured | 5 x 4 in kitchen at 1/4" = 20 x 16 ft = 320 sq ft, 72 ft perimeter; wall 20 ft; NTS, unscaled and no-viewport objects say why; CAD slab 100 sq ft; needs_scale on the right sheet |
| S21-M02 | Bad results | 8 different mistakes (bad kind, page twice, missing viewport, confidence 1.5, bad discipline, bad scale note, list in a schedule cell, no sheets) all refused, old model untouched |
| S21-M03 | Set scale | asks first; 1/2" re-measures the bath to 80 sq ft; calibration back to 320; NTS stops measuring and clears needs_scale; one input only; field can't; events logged |
| S21-M04 | CAD sheets | a sheet in real feet refuses a scale |
| S21-Q01 | Queries | kind, several kinds, tag (case and spaces ignored), layer, area, paging with geometry, totals; area needs a sheet; legends; sheet image missing then found; another company can't read |
| S21-S01 | Schedules | D3 linked to both tags, D4 unlinked; correction asks first, re-links, marks reviewed; field can't; empty correction refused |
| S21-E01 | No engine | says so, points to runner_submit_takeoff, status stays uploaded |
| S21-E02 | Engine runs | asks first; gets the file, type and info; re-reading asks first; an engine crash → failed with the reason; sloppy results → failed "didn't pass the checks"; field can't |
| S21-E03 | Background and discovery | a dropped-in `plan_engine` module is found by name; background run finishes as processed |
| S21-T01 | Tools | the whole flow through the JSON tools (upload, process, status, sheets, viewports, calibration, area query, totals, schedule fix, legends, image); all 11 tools answer bad input with JSON |
| S21-T02 | Pack-up | export lists plan sets under left_out; import still works |
| S21-T03 | Practice | deleting the practice project removes its plan sets |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 639 passed, 1 skipped (18 new) |
| Windows 11, Python 3.11.8 (Jamie's PC) | 648 passed, 0 failed (2026-11-07) |
| File check | All 15 files match the tested copies (zip SHA-256 checked on the PC) |

## Manual check after deploying

In chat: "Attach C:\...\some plans.pdf to estimate 1". It should ask first, then attach it. `plan_status` should show it uploaded and say the plan engine isn't installed. `plan_process` should say the same and suggest typing the measurements.

## For David (Coder 2)

The result format your engine returns is at the top of `estimator/drawing_model/engine.py`. Put your engine in a package `estimator.plan_engine` with `process(file_path, file_type, info)`. You don't need to open the database. To test without the Estimator, call `store.save_results(conn, ctx, plan_set_id, results)` on a test database (see `RESULTS()` in this sprint's test file for a full example). Anything your engine returns that doesn't fit is refused with the exact field named.

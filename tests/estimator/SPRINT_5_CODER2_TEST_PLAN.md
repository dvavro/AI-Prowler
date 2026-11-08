# Sprint 5 — Coder 2 (David) test plan: plan engine v0.5 (sheets, title blocks, viewports, scales) and the Plans screen

**Scope:** The Coder 2 Sprint 5 row is "Sheet splitting and rendering (`pypdfium2`), title-block reading, sheet classification; viewport detection, per-viewport scale parsing, two-point calibration". It's built as the plan engine package `estimator/plan_engine/`, which plugs into Jamie's drawing model (`estimator/drawing_model/engine.py`; it's found by name). The Plans screen in the web app reads plans, shows sheets and their views, and sets or calibrates scales.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat planengine      plan engine only
deploy_to_install.bat                   then restart AI-Prowler
```
No new tools or tables. Uses `pypdfium2`, `pdfplumber` and Pillow (already installed with AI-Prowler).

## What was built

**Plan engine** (`estimator/plan_engine/`; `process(file_path, file_type, info)` → the drawing model's results):
- **Sheets and renders** (`pdf_pages.py`). Each PDF page becomes a sheet with its paper size in inches; a page's rotation is applied. Each page is rendered to a PNG (at most 4000 px on the long side, 40–150 DPI) in the plan set's `_sheets` folder. Words (with font size) and drawn rectangles come back in inches from the top-left corner, the same frame as the image, including on rotated pages. Limits: more pages than the drawing model allows, or a broken PDF, gives a plain message.
- **Title block** (`titleblock.py`): searched in the right strip, then the bottom strip, keeping whichever finds more.
  - Sheet number: the big code like A-101, E1.01 or S2 near "SHEET NO.". Small tags like D3 lose.
  - Title: plan words near "SHEET TITLE", with two-line titles joined.
  - Revision ("REV: B") and the latest date.
  - Confidence goes up with each thing found.
- **Discipline**:
  - From the sheet-number prefix (US National CAD Standard: A, S, P, E, M, L, C, FP, G…).
  - Refined by the title: A-501 ROOF PLAN → roof; SITE PLAN → site.
  - With no prefix, from the title alone: ELECTRICAL PLAN → electrical.
- **Viewports and scales** (`viewports.py`). Each readable scale note in the drawing area is one view.
  - **Label:** the text before "SCALE" on the same line, or the title just above.
  - **Box:** a drawn frame around it if there is one (confidence 0.9). Otherwise the views are laid out in rows, and each gets the part of the sheet above its title, split halfway between neighbours (0.65).
  - **NTS** views are marked.
  - **Fallbacks:** with no view scales, there's one "main" viewport with the title block's scale (0.7), or no scale.
- **Scale safety.** Every note is checked with the drawing model's own `parse_scale`, so "AS NOTED" is skipped, never guessed. A scale written without the word SCALE only counts when it's nearly the whole line, so words like "components" (nts) or a time like "1:30" in a note don't become scales. That was found by running the engine on a real 57-page PDF.
- **Images** (`images.py`): PNG, JPG and TIFF (each page) become one sheet each. The size comes from the DPI, or 150 DPI is assumed and the sheet says so. There's no scale, so they need setting or calibrating.
- **DXF/DWG**: a plain message — they come with the next plan-engine release (Sprint 6); print to PDF for now.
- **Speed:** 0.18 s a page on David's PC (57 pages in 10 s), in the background.

**Two-point calibration**: Jamie's `plan_set_scale(calibration={p1, p2, distance})` does the math. The web sheet page adds the clicks.

**Plans screen** (`#/plans`, `#/plan-sets/<id>`, `#/sheets/<id>`; router `/plans`, `/plan-sets/…`, `/sheets/…`, `/viewports/…/scale`):
- **Plans** lists every plan set on the company's projects. Project page plan sets link to it.
- **Plan set**:
  - 📖 Read the plans… (`plan_process`, asks first; asking again warns that it replaces). The page refreshes itself while reading.
  - The sheet list: sheet number, title, discipline, scales, and a "needs a scale" tag.
- **Sheet**:
  - The rendered image, with each view outlined: blue = has a scale, dashed yellow = none, dotted grey = NTS.
  - The views table: scale, how it was found, and confidence.
  - Set a scale from a note (Set…), or 📏 Calibrate…: click both ends of a known distance, type the real length, Set the scale…. Both ask first.
  - The image comes through the API with the same sign-in, so it works in the Jobs app too, and only from the Estimator's data folder.
- **Roles:**
  - Owner, estimator, reviewer and field can look.
  - Only owner and estimator read plans or set scales (`store.EDIT_ROLES`).
  - Office doesn't see Plans.
- **Help:** a new guide, "Upload plans and check the scale", and a "?" on the plan pages.
- `run_tests_estimator.bat coder2` now runs `tests\estimator\webapp` and `tests\estimator\plan_engine`. There's a new `planengine` option.

## Test cases

`tests/estimator/plan_engine/test_plan_engine_sprint5.py` (PDFs are made by `pdfmaker.py`, no PDF library needed):

| ID | Test | Checks |
|---|---|---|
| C2S5-E01 | Sheet | A-101 / FIRST FLOOR PLAN / architectural / rev B / 2026-10-01; 36×24 in; render ≤ 4000 px, same shape |
| C2S5-E02 | Many pages | each page a sheet with its own number, discipline and image |
| C2S5-E03 | Disciplines | 15 prefix/title cases incl. roof, site, no prefix, unknown |
| C2S5-E04 | Bottom title block | sheet number and title found along the bottom |
| C2S5-E05 | Tags | small door/window tags in the strip don't win |
| C2S5-E06 | Scan page | no text: still a sheet with an image, a note, low confidence, one unscaled viewport |
| C2S5-E07 | Rotated | /Rotate 90 → landscape; words in the same frame as the image |
| C2S5-V01 | Scale notes | 9 forms (1/4", 1/8"=, 3/16" after a title, 1"=20', 1:100, NTS, NOT TO SCALE, 1 1/2", "UNLESS NOTED") |
| C2S5-V02 | Not scales | AS NOTED, AS SHOWN, room names, dimensions, "components", "requirements", "1:30 PM", NTS in a sentence |
| C2S5-V03 | One view | "main", label, note, box stops at the title block |
| C2S5-V04 | Side by side | two views, own scales, split between the titles |
| C2S5-V05 | Rows | a top row above a bottom row; a view alone in its row gets the full width |
| C2S5-V06 | Frame | a drawn rectangle is the box (0.9); the border and small boxes aren't frames |
| C2S5-V07 | NTS / same line / title block / none | NTS view; label on the scale line; title-block scale (0.7); no scale → method none |
| C2S5-F01 | Bad files | too many pages; broken PDF; DXF later |
| C2S5-I01 | Images | DPI → inches; no DPI → 150 assumed with a note; 2-page TIFF |
| C2S5-D01 | Found by name | `engine_info()` installed with the engine's name |
| C2S5-D02 | End to end | upload → read → sheets and disciplines saved; 1/4" → 48; NTS; image; E-101 calibrated 2" = 16' → 96 |

`tests/estimator/webapp/test_web_sprint5.py`:

| ID | Test | Checks |
|---|---|---|
| C2S5-W01 | Plans list | the set with its project, file, status; engine installed; can_edit |
| C2S5-W02 | Read | asks first (nothing done); then processed; sheets and disciplines; needs_scale; "need a scale" |
| C2S5-W03 | Read again | asks, saying it replaces |
| C2S5-W04 | No engine | page told; process → not_available |
| C2S5-W05 | Sheet | paper size, viewports with boxes and scales, no file path |
| C2S5-W06 | Image | PNG with nosniff; a path outside the data folder → 404 |
| C2S5-W07 | Note | asks first (96); then set; needs_scale clears |
| C2S5-W08 | Calibration | 5 paper inches = 20' → 48, method calibration |
| C2S5-W09 | Bad scales | calibration not an object, none or two given, same point twice, AS NOTED |
| C2S5-W10 | Roles | reviewer and field look but can't read or set; office 403; another company 404; CSRF |
| C2S5-W11 | Unknown | 404s |
| C2S5-W12 | Page and guide | Plans ready with its pages; page calls; no innerHTML/style attributes; the guide's buttons are on the page |

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), Coder 2 track (webapp + plan engine) | 298 passed (2026-11-08) |
| Real PDF smoke test (57-page spec PDF, text not plans) | 57 sheets and images in 10 s; no false scales after the fix |

## Manual checks

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | Upload a real plan set PDF to a project → open it from Plans → 📖 Read the plans… → Yes | "processing" then the sheet list by itself | |
| M2 | Sheet numbers, titles, disciplines in the list | match the title blocks; note any that are wrong | |
| M3 | Open a sheet with several views (plan + details) | boxes on the right views; scales as written | |
| M4 | A sheet with no scale → 📏 Calibrate… on a known dimension | the scale matches the drawing's own scale | |
| M5 | Set… with 1/8" = 1'-0" | 1″ = 96″; boxes turn blue | |
| M6 | A phone photo of a plan | one sheet, "150 DPI was assumed", calibrate works | |
| M7 | Jobs app (port 8000) → Estimates tab → Plans → a sheet | the image shows (token sign-in) | |
| M8 | Sign in as field (test session) | Plans visible; no Read or Set buttons | |

## Notes for Jamie

- The engine is `estimator/plan_engine` and is picked up by your `ENGINE_MODULES` lookup. Your Sprint 21 tests point the lookup at a test-only name, so they're unaffected. With the engine installed, `plan_process` now reads PDFs and images for real.
- The router reads a sheet's width and height with `store._load_sheet` (your `sheets()` doesn't return them). Could `sheets()` / `viewports()` include width and height, so I can stop calling the private function?
- **Not done in this release:**
  - Reading scale bars and dimensions.
  - OCR for scans (planned for Sprint 9).
  - Objects, schedules and legends — the engine returns none yet (vector extraction is Sprint 6).
- No changes to your files this sprint.

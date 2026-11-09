# Sprint 9 — Coder 2 (David) test plan: OCR, dimensions, schedules with tag linking, legends and the symbol dictionary

**Scope:** The Coder 2 Sprint 9 row is "Text and dimension OCR (Tesseract); legend detection and plan-set symbol dictionary; schedule extraction with tag linking".

- **OCR:** scanned PDF pages and images get their words read, so everything that reads text works on scans too.
- **Dimensions:** dimension strings become objects and check each view's scale.
- **Schedules:** door, window, finish, fixture, panel, equipment and wall-type tables are read as rows by mark, and each row is linked to its tags on the plans.
- **Legends:** legend blocks are found, their entries read into a symbol dictionary with item types, and each drawn symbol is cropped as a picture.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
deploy_to_install.bat                   then restart AI-Prowler
```
No new tools or tables. OCR uses Tesseract 5 (pytesseract), which AI-Prowler's OCR setup already installs. Without it the plans are still read and the sheets say OCR isn't installed; the OCR tests skip.

## What was built

**Plan engine 0.7** (`estimator/plan_engine/`). Each page goes through one analysis: title block, viewports, line work, schedules, legends, dimensions. Then a pass over the whole set adds the tags and writes the dictionary.

- **OCR** (`ocr.py`):
  - **Where it runs:** on PDF pages with no text (a scan saved as PDF) and on every image.
  - **Finding Tesseract:** `ESTIMATOR_TESSERACT` (a path, or `off`), then the PATH, then `%LOCALAPPDATA%\Programs\Tesseract-OCR`, then Program Files.
  - **Settings:** pages are read at 300 DPI, up to 7,000 px on the long side. Words below 55% confidence are dropped. Typographic quotes become ' and ".
  - **Output:** words come back in sheet inches, the same as PDF text.
  - **Labelling:** a sheet read this way says "text read by OCR - check the sheet number and scale", and its objects are `source: raster`.
- **Dimensions** (`dimensions.py`):
  - **What counts:** 12'-6", 3'-0 1/2", 24', 24'-0 and 8" are dimension strings. Each becomes a `dimension` object: its dimension line when one is found just above or below it, otherwise a point.
  - **Voting:** each matched line votes for the nearest standard scale (architectural, engineering or metric, within 4%).
  - **No scale written:** the view gets the winning scale (`scale_method: dimension`) when two or more agree and they're at least half of the votes.
  - **Scale written but disagreeing:** the view keeps its scale, and the sheet gets a "check it" note.
  - **Scale written and agreeing:** the view's confidence goes up.
- **Schedules** (`schedules.py`):
  - **Title:** a short all-capitals line ending in SCHEDULE(S), so "SEE DOOR SCHEDULE ON A-601" isn't one. The type comes from the title.
  - **Columns:** taken from the header row, using the table's vertical rules when it has them, otherwise the gaps between words. A second header row (FRAME over TYPE) is merged into the column above.
  - **Rows:** a line with an empty mark cell is the rest of the row above.
  - **Exclusions:** title-block text is left out. Nothing found inside a schedule or legend counts as drawing (rooms, dimensions, tags).
- **Tags** (`tags.py`):
  - **Which words:** a word on any sheet that matches a schedule mark becomes a text object with `tag`, e.g. "door tag". The drawing model then links rows to tags (`store._link_rows`).
  - **Which marks:** a mark needs a letter or at least 3 characters, so a bare "1" never becomes a tag.
  - **Series:** a word in the same series as two or more marks (D3 next to D1, D2, D4) is a tag too, at confidence 0.55. The schedule may have missed it, and a corrected row then links.
- **Legends** (`legends.py`):
  - **Title:** LEGEND, SYMBOLS or ABBREVIATIONS titles (not schedules).
  - **Rows:** each row's code (GFI, WP) or drawn symbol, then its description.
  - **Item types:** descriptions map to a standard item type and trade (about 50 types: receptacles, switches, lights, detectors, panels, fans, diffusers, plumbing fixtures, sprinklers). An entry with no item type, or with low confidence, has `needs_confirming`.
  - **Symbol pictures:** drawn symbols are cropped at 300 DPI as `legend_pNNN_i_j.png`, the templates for Sprint 10's symbol matching.
- **Symbol dictionary:**
  - **Where it lives:** `symbol_dictionary.json` beside the sheet images, until the spec's symbol_definitions table exists.
  - **What reads it:** `store.legends` (and so `plan_get_legends`) returns its entries as `symbol_dictionary`, without file names.
- **Images:** `images.read(..., ocr_words=True)` reads the words, and the image sheet goes through the same analysis as a PDF page.

**Plan set page** (`app.js`; API in `router.py`):
- **API:**
  - `GET /plan-sets/<id>/schedules?type=` returns the rows, how many plan tags each is linked to, and "Not found on the plans" for unlinked marks.
  - `GET /plan-sets/<id>/legends` returns the legends with their dictionary entries. Entries without an item type say "needs a person".
  - `POST /schedule-rows/<id> {mark?, fields?, confirm?}` corrects a row (`plan_update_schedule_row`). It asks first, then re-links the row.
- **Page:** each row has **Correct…**, which opens an inline form with **Save…**.
- **Roles:** reviewer and field can look but not correct. Office can't open plans.

## Test cases

`tests/estimator/plan_engine/test_plan_engine_sprint9.py` and `tests/estimator/webapp/test_web_sprint9.py`:

| ID | Test | Checks |
|---|---|---|
| C2S9-E01 | Door schedule | rows D1-D3 by mark, fields by column, wrapped remark joined, only the keys the store saves |
| C2S9-E02 | Ruled table | columns from vertical rules; FRAME / TYPE header merged |
| C2S9-E03 | Titles | DOOR / LIGHT FIXTURE / PANEL SCHEDULES / ROOM FINISH found; a note and mixed case not |
| C2S9-E04 | Tags | tags across sheets; none in the schedule's own cells; a bare "1" isn't a tag; a D3 in a D series is found (0.55) |
| C2S9-E05 | Legend | title and discipline; code GFI; drawn symbol cropped; WP; unknown entry needs confirming; dictionary file |
| C2S9-E06 | Item types | 12 descriptions → item type and trade ("Outvent" isn't a TV outlet) |
| C2S9-E07 | Abbreviations + store | ABBREVIATIONS legend (codes, no item types); `store.legends` returns the dictionary |
| C2S9-E08 | Dimension strings | 8 strings: which are dimensions and their inches |
| C2S9-E09 | No scale written | 3 dimensions agree on 1/4" = 1'-0" → `scale_method: dimension`, ratio 48, note; dimension lines |
| C2S9-E10 | Written scale | agreeing raises confidence; 1/8" with 1/4" dimensions keeps the note and says "check it" |
| — | Text with no line | a point, and no vote |
| C2S9-E11 | OCR words | position in inches and size in points (skips without Tesseract) |
| C2S9-E12 | Scanned image | schedule rows and a raster tag read by OCR |
| C2S9-E13 | Scan saved as PDF | read by OCR, schedule found |
| C2S9-E14 | No Tesseract | images and blank pages are still read and say Tesseract isn't installed |
| C2S9-E15 | Saved by the drawing model | rows linked to tags (D3 twice); the view's scale from dimensions saved; empty dictionary |
| C2S9-W01 | Schedules API | rows with link counts, unlinked marks, `?type=` |
| C2S9-W02 | Correct a row | asks first; D4 → D3 links to the plan's D3; bad bodies 400 |
| C2S9-W03 | Legends API | dictionary entries, needs confirming, no file names |
| C2S9-W04 | Roles and errors | reviewer/field look but get 403 on correcting; office 403; another company 404; unknown 404; CSRF |
| C2S9-W05 | Page | the calls, Correct…, "Not found on the plans", "needs a person"; no innerHTML or style attributes |

Changed: `store.legends` reads the dictionary (it returned `symbol_dictionary: None` with a "planned Phase 4" note). The router docstring lists the new routes.

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8, Tesseract 5.4.0 (David's PC), Coder 2 track | 447 passed (2026-11-08) |
| Same PC, all Estimator tests | see the Implementation Plan progress row |
| Browser smoke test (scratch `tables_smoke.py`, headless Chromium) | schedules, legends, correcting D4 → D3: no problems |

## Manual checks (David)

| # | Check | Expect | Result |
|---|---|---|---|
| M1 | Read a real plan set with a door schedule | rows by mark; tags on the floor plans linked | |
| M2 | A real scanned set (TIFF or image PDF) | sheet numbers, scales and schedules read by OCR; notes say to check | |
| M3 | A view with no scale note but dimensions | scale from dimensions; measure a wall and compare with its dimension | |
| M4 | An electrical legend sheet | entries, item types; unknown ones marked "needs a person" | |
| M5 | Correct… a misread row on the plan set page | asks first; the row is linked and checked | |
| M6 | Reviewer / field sign-in | sees schedules and legends; no Correct… | |

## Notes for Jamie

- **Symbol dictionary storage.** The dictionary is in `symbol_dictionary.json` beside the sheet images, one per reading. The spec's `symbol_definitions` table isn't built, and I didn't add a migration so our migration numbers don't clash. When you build the table, `store._symbol_dictionary` is the one place to change, and the engine can return the entries in its results instead.
- **`store.legends` changed** to read that file (it said "planned Phase 4"). It's recorded in the spec's Change log.
- **Dimension objects** are saved as `kind: dimension` with their label (12'-6"). The drawing model measures their line like any other line.
- **Series tags** (D3 when the schedule has D1, D2, D4) are saved at confidence 0.55, so `plan_update_schedule_row` can link a corrected mark.

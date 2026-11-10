# Sprint 19 — Coder 2 (David) test plan: revision clouds drawn + Price Book file import

**Scope:** Sprint 19 has no new Coder 2 feature row in the plan — it is beta work ("fix beta bugs; performance tuning"), and the buildable Coder 2 work was the two known partials left over from Sprint 17. (1) Revision clouds and deltas: Spec:452 — the comparison covers "added, removed and moved geometry, changed dimensions, new or changed schedule rows, **and cloud/delta revision marks**" and produces "a visual overlay". Sprint 17 counted the marks but only printed the count; now they are drawn. (2) Price Book file import: Spec:918 — "import a supplier price list **(CSV/Excel)**". Sprint 17 was paste-only; now a file can be chosen. Both partials are pure Coder 2 surfaces (plan engine, web API, web app) — no Coder 1 dependency.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat                 every Estimator test
deploy_to_install.bat                   then restart AI-Prowler
```

- **No new database migration, tables, MCP tools or libraries.** openpyxl was already a declared dependency (it reads the Excel files); no new production `.py` files were added.
- **New files** (`tests/estimator/webapp/test_web_sprint19.py`, this plan) need no installer entry — no new production files ship.
- **Phase 7 gate:** still open (G0 waits on David's code review of the Coder 2 track). This sprint's evidence feeds the gate rather than closing it: the revision overlay is checked against real plan pairs (M1), the Price Book file import against real supplier files (M7).

## What was built

**Revision clouds and deltas** (`estimator/drawing_model/revisions.py`, `estimator/ui/web/reports.js`, `estimator/ui/web/app.css`):
- The comparison already counted marks on the new set (`REV_MARK` on label, layer or block name). Now each sheet also carries them: `entry["marks"]` and `entry["marks_items"]` (the mark's box from `_item()`, `old: None`), and marks count toward `changed_anything`, so a sheet with only a cloud no longer reads "(no change)" in the picker. The whole-set count query is untouched.
- No API change: the per-sheet entries ride inside `diff["sheets"]` → `summary["sheets"]` → `summary_json` → `GET /reports/revisions/<id>`. A report saved before Sprint 19 simply has no `marks_items` on its sheets, and the overlay tolerates that (`s[k + "_items"] || []`).
- The overlay draws marks as purple boxes (`#7c3aed` fill, `#6d28d9` stroke — the builder's pick; the spec pins no color for marks, only "red = removed, green = added"): a fifth `REV_KINDS` entry ("Revision clouds", `rev-marks`) wires the toggle checkbox, the SVG rects and the "Changes on this sheet" rows; the tile row shows the whole-set count; the picker lists marks; the caption says "purple outlines revision clouds". The old-sheet view is unaffected (marks have `old: None`, so the `:287` guard skips them there).

**Price Book file import** (`estimator/api/router.py`, `estimator/api/staging.py`, `estimator/pricing/importer.py`, `estimator/ui/web/app.js`):
- `POST /price-book/import/stage?name=<file>` stages a price list the way plan uploads are staged: owner/estimator only, extension in `importer.SUFFIXES` (.csv, .txt, .xlsx, .xlsm), size ≤ 5 MB (`MAX_BYTES`, not the plans' 300 MB), the file is read up front so a bad file fails at upload, and it returns `{stage_id, file, sheets, columns, row_count}`. `staging.new/get` were generalized to accept `estimate_id=None` — a price-list stage belongs to no estimate — while plan stages still carry their estimate id.
- `POST /price-book/import/preview` and `POST /price-book/import` accept **either** `csv_text` **or** `file_path` (+ `sheet`); a `file_path` is the stage id, resolved only through `staging.get` (ownership-checked; never an arbitrary server path). Preview gains an additive `sheets` field for workbooks. After a **confirmed** import the stage is dropped; asking first leaves it in place for the confirm round-trip. The paste flow is byte-identical.
- The import box (`importBox`) has a file picker (`#pb-file`, `.csv,.txt,.xlsx,.xlsm`) and a sheet picker (`#pb-sheet`, shown when the workbook has more than one sheet). CSV/.txt files are read in the browser into the existing textarea; .xlsx/.xlsm files go up through `uploadPriceList` (the `uploadRaw` pattern: raw body, `X-Estimator-Request` header), then preview and import send `file_path`/`sheet`. Typing in the textarea clears the staged file.

## Automated tests

`tests/estimator/webapp/test_web_sprint19.py` (15 tests; the W08 refusal test runs 3 cases, so 17 cases):

| ID | Test | Checks |
| --- | --- | --- |
| C2S19-W01 | test_revision_marks_have_boxes_on_the_sheet | Engine, Sprint 17 fixture: sheet E-101 `marks` 1, `marks_items` holds the REV CLOUD polyline with bbox [11, 2, 13, 4], `old` None; whole-set count still 1; totals unchanged; the cloud is also in `added_items` |
| C2S19-W02 | test_marks_alone_mark_a_sheet_changed | Engine, minimal pair: the same DELTA cloud on both revisions, nothing else changed — moved/changed/removed/added all 0, `marks` 1, `changed_anything` true, bbox [2, 2, 4, 3] |
| C2S19-W03 | test_revision_detail_returns_marks_items | API: `GET /reports/revisions/<id>` returns the sheet's `marks_items` with the cloud's bbox |
| C2S19-W04 | test_old_report_without_marks_still_loads | API: a saved report with per-sheet `marks`/`marks_items` stripped (the pre–Sprint 19 shape) still loads; whole-set `revision_marks` still 1 |
| C2S19-W05 | test_revision_clouds_are_drawn_in_the_overlay | `reports.js`: `REV_KINDS` has marks, the tile, the picker label list, the purple caption, the `|| []` guard; `app.css`: `.rev-marks` in all four places (overlay rect, tile number, label, tag) |
| C2S19-W06 | test_stage_excel_price_list | Stage a real two-sheet .xlsx (openpyxl): `stage_id`, `sheets` ["Prices", "Cover"], Prices columns, row count 2, staged folder exists |
| C2S19-W07 | test_stage_csv_price_list | Stage a CSV: `sheets` [], the columns, row count 2 |
| C2S19-W08 | test_stage_refuses_bad_files (×3) | Wrong extension is 400 "cannot be used"; empty file is 400 "is empty"; a corrupt .xlsx is 500 `server_error` — and nothing is kept in any case (see Known limits) |
| C2S19-W09 | test_stage_refuses_too_big_wrong_role_and_missing_name | Over 5 MB is 413 "the limit is 5 MB"; reviewer is 403; no `?name=` is 400 "the file name is missing" |
| C2S19-W10 | test_preview_from_a_staged_file_picks_the_sheet | Preview defaults to the first sheet (Prices columns, guessed mapping, first rows); `sheet: "Cover"` previews the cover; an unknown sheet is 400 "no sheet called" |
| C2S19-W11 | test_import_from_a_staged_csv_saves_and_drops_the_stage | Ask-first: 1 update, 1 skipped, the stage still resolvable; confirm: saved 1, 19¢ in the book, the stage gone (`staging.get` raises, folder gone, count 0) |
| C2S19-W12 | test_import_from_a_staged_workbook_and_bad_sources | Import from the .xlsx with `sheet: "Prices"` saves 1 at 19¢; pasted CSV *and* a staged file together is 400 "not both"; an unknown stage id is 404 on import and preview |
| C2S19-W13 | test_paste_csv_preview_and_import_still_work | The Sprint 3/17 paste flow unchanged: preview guesses the columns, no `sheets` field, import asks first then saves 1 at 19¢ |
| C2S19-W14 | test_stages_keep_their_estimate | `staging.new/get`: a plan stage (estimate 7) is only reachable with 7; a price-list stage (`None`) is only reachable with `None` — neither is reachable with the other's id |
| C2S19-W15 | test_price_book_upload_is_wired_in_the_page | `app.js`: `uploadPriceList`, the stage URL, `#pb-file` with the four extensions, `#pb-sheet`, `file_path: staged.stage_id`, the "(CSV or Excel file)" summary |

The revision fixture (`revs`, copied from Sprint 17) is two fake plan sets: Rev A with 5 outlets, a slab, a porch, door D1 and a GFI; Rev B with outlet 3 moved, a bigger slab, the GFI removed, a floor box, a revision cloud, a changed D1 size and a new sheet E-102 — plus 6 measurements, 3 of them approved. The .xlsx fixture is built with openpyxl in the test (`pytest.importorskip`, the same pattern as the Sprint 17 unit tests): sheet "Prices" with the Sprint 17 CSV rows, sheet "Cover" with one note row.

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | On a real plan pair (Rev A → Rev B from the architect, with the architect's clouds/deltas): upload B as a revision of A, read both, compare from Reports → Plan revisions (extends Sprint 17 M1) | Purple boxes sit on the clouds/deltas on the new sheet; the "Revision clouds" checkbox hides and shows them; they are listed in "Changes on this sheet"; "Show Rev A (old)" is unaffected (no purple boxes on the old sheet); a sheet with only clouds shows as changed in the picker, not "(no change)" |
| M7 | Price Book: choose a supplier .xlsx file with more than one sheet, then a .csv file (extends Sprint 17 M7) | The sheet picker offers the workbook's sheets and preview shows the picked sheet's columns with the mapping guesses; the import saves; the .csv file imports the same way; a file over 5 MB and a wrong-extension file are refused with a clear message; the staged file is gone from `cache/web_uploads` after the import; pasting CSV still works exactly as before |

M2–M6 and M8 from the Sprint 17 plan still stand unchanged for their screens (measurements to re-measure, win/loss, takeoff/actuals, exports, Settings, role gates).

## Known limits

- The overlay draws each mark as a bounding-box rect, the same pattern as added/removed/changed/moved — not the cloud's scalloped polyline (the cloud *is* a polyline in the drawing model, so a faithful outline is possible later; the spec only asks for a "visual overlay").
- A corrupt .xlsx fails the stage with a 500 `server_error`, not a 400: `openpyxl` raises `BadZipFile`, which nothing converts to `InvalidInput`. The file is still refused at upload and nothing is kept — but the message is the generic server error, not "this file can't be read". Worth a follow-up to map it to a 400.
- `app.js` `importBox` lists the textarea, check button and mapping twice (lines 859–860 repeat 859's children). The same nodes are appended twice, so they render once — cosmetic only — but the duplicate line should be removed.
- `.xls` (old binary Excel) is still refused — it is not in `importer.SUFFIXES` and openpyxl can't read it. No PWA/mobile import UI was added (none exists there); the MCP `pricebook_import` tool already took files and is unchanged.
- The automated revision tests use seeded fake plan sets; real-plan accuracy and the box positions on a real sheet are M1's job.

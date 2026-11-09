# Sprint 17 — Coder 2 (David) test plan: Reports, Settings and the full Price Book

**Scope:** The Coder 2 Sprint 17 row is "Revision overlay UI; Reports, Settings and full Price Book screens". Spec: Screens and controls (Reports, Settings, Price Book) and Plan revisions (the overlay: red removed, green added, orange changed or moved; unchanged measurements carry over, the rest are flagged to re-measure). The revision compare itself is Coder 1's `plan_compare_revisions` (Sprint 24); this sprint puts it behind the Reports screen and draws it over the sheets.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat                 every Estimator test
deploy_to_install.bat                   then restart AI-Prowler
```

- **No new database migration, tables, MCP tools or libraries.**
- **New files** (`estimator/api/reports_api.py`, `estimator/api/settings_api.py`, `estimator/ui/web/reports.js`, `estimator/ui/web/settings.js`, the guides `use_reports.md`, `change_your_settings.md`, `compare_plan_revisions.md`, plus the price-book additions in `estimator/api/router.py` and the wiring in `estimator/ui/web/app.js`) must be in `AI-Prowler-Setup.iss`.
- **Phase 7 gate:** Sprints 16–17 close Phase 7 ("Scans, CAD, revisions, learning, polish") when the revision overlay is checked against real plan pairs (M1–M2), the Reports/Settings screens pass Tester 2's browser checks (M3–M6), the Price Book checks pass (M7), the role gates hold in the browser (M8), and the automated suite is green. No phase gate has passed yet — G0 still waits on David's code review of the Coder 2 track — so this sprint's evidence feeds the gate rather than closing it.

## What was built

**Reports screen** (`estimator/ui/web/reports.js`, `estimator/api/reports_api.py` — owner, estimator, reviewer, office; read only unless noted):
- **🏆 Win / loss:** `GET /reports/summary?months=12` — estimates by status, win rate, value won and lost, by month and by trade. Practice estimates are left out; a bid lands in the month it was marked won or lost.
- **📏 Takeoff report:** `GET /reports/takeoff/<estimate_id>` — every measurement by trade, approved (priced) and waiting totals per question, what needs re-measuring, what came from scans or photos; rejected ones listed apart.
- **💵 Estimate vs actual:** `GET /reports/actuals?estimate_id=` — `est_compare_history`: unit costs against past estimates and what jobs really paid. Costs only for roles with `see_margins`.
- **⬇ Exports:** `POST /reports/export {estimate_id?, status?, format: csv|xlsx}` writes a file to the exports folder; `GET /reports/files/<name>` downloads it (that folder only, plain names only — traversal is refused).
- **🔀 Plan revisions:** `GET /reports/revisions?estimate_id=` (saved reports + revised plan sets not compared yet), `GET /reports/revisions/<id>` (what the overlay needs: both sheets' sizes, the changed boxes, the measurements flagged to re-measure, schedule changes), `POST /reports/revisions {new_plan_set_id, old_plan_set_id?, confirm}` (asks first; owner and estimator only).

**Revision overlay** (`reports.js` `renderRevision`, page `#/revisions/<report id>?sheet=<n>&old=1`): the report drawn over the sheets as SVG — green boxes for added, red outlines for removed, orange for changed or moved; tick each kind to show or hide it; "Show Rev A (old)" shows the old sheet; "Changes on this sheet" lists the changes with any size change; "Measurements to re-measure" links each one into Blueprint Review.

**Settings screen** (`estimator/ui/web/settings.js`, `estimator/api/settings_api.py` — owner only): `GET /settings` (company profile, tax, markups, labor rates, bid template, approval rules, AI and privacy, users and roles, data folder and backups, sample prices still in use); `POST /settings/<section> {data, confirm}` — company_profile, tax, markups, bid_template, approvals, ai_privacy, labor_rates — the first call answers `needs_confirmation` with each change as "field: old → new", the second (`confirm=true`) saves it; `POST /settings/backup {confirm}` backs up `estimator.db` now (newest 30 kept); `GET /settings/audit?limit=&action=&estimate_id=` is the audit log, newest first. Everything is saved through the same service calls the AI's tools use (`est_setup_step`, Director settings, `est_ai_privacy`, `pricebook_update`), so the web app and chat stay the same. Percentages are typed as percents and stored as fractions ("7" → "0.07").

**Full Price Book** (additions in `estimator/api/router.py` `_price_book`, drawn in `app.js`):
- `POST /price-book/import/preview {csv_text}` — the columns, the fields, the guessed mapping, the first 5 rows and the row count, before anything is saved.
- `GET /price-book/history/<price_key>` — every dated price for one key (newest first), what jobs really paid for it, suggestions, and "Not saved yet: the trade's sample price is used until you set your own." when nothing is saved.
- `GET /price-book/markups` — overhead, profit, labor burden and tax as percents, taxable kinds, tax base, minimum charge, and `can_change` (true only for the owner, who can change them in Settings).

**Guides:** "Use the reports", "Change your settings", "Compare plan revisions".

## Automated tests

`tests/estimator/webapp/test_web_sprint17.py` (32 tests; the W18 role test runs once per role, so 35 cases):

| ID | Test | Checks |
| --- | --- | --- |
| C2S17-W01 | test_summary_starts_empty | Empty shape: no estimates, win rate null, 12 months, the "No won or lost" note |
| C2S17-W02 | test_summary_counts_won_lost_and_approved | Won 1, lost 1, approved 1; win rate 0.5; equal won/lost value; roofing by trade; this month |
| C2S17-W03 | test_summary_months_window | months=3/60 give 3/60 months; 0, 61, abc are 400 |
| C2S17-W04 | test_takeoff_report_lists_measurements_by_trade | 6 measurements, 3 approved / 3 waiting, per-question quantities, the waiting note |
| C2S17-W05 | test_takeoff_report_unknown_estimate_is_404 | Unknown estimate is 404 |
| C2S17-W06 | test_actuals_open_to_the_roles_that_see_margins | Owner, reviewer, office get 200; "No job costs recorded yet" with no jobs |
| C2S17-W07 | test_actuals_refuses_field_and_a_role_without_margins | Field gets 403 at the Reports gate; a reviewer with see_margins off gets 403 "can't see costs" |
| C2S17-W08 | test_actuals_for_one_estimate | One estimate's lines, no flags with no actuals |
| C2S17-W09 | test_export_csv_downloads | CSV export, then the file downloads with the right type and filename |
| C2S17-W10 | test_export_bad_format | format=pdf is 400 |
| C2S17-W11 | test_export_files_refuse_traversal | `..`, `..%2F..`, a missing file, a .txt name are all 404 |
| C2S17-W12 | test_reports_posts_need_the_app_header | A Reports POST without the app header is 403 csrf |
| C2S17-W13 | test_revisions_list_shows_uncompared_set | Rev B waiting, ready, A → B; the estimate filter; nothing for another estimate |
| C2S17-W14 | test_revision_compare_asks_first_then_saves | Ask-first totals {unchanged 6, moved 1, changed 1, removed 1, added 3}, carry 2, flag 3; confirm saves the report; the detail has A → B, 3 flagged, sheet E-101 36 in; the takeoff then shows 3 to re-measure |
| C2S17-W15 | test_revision_compare_bad_input | No plan set is 400; an unknown plan set or report is 404 |
| C2S17-W16 | test_revision_compare_is_owner_or_estimator_only | Reviewer and field get 403; the estimator gets the ask-first question |
| C2S17-W17 | test_settings_reads_everything | Every section present with the right defaults (tax 0, kinds, approvals, roles, backups, setup) |
| C2S17-W18 | test_settings_is_owner_only (×4 roles) | Reviewer, estimator, office, field get 403 on GET and POST; no Settings in their menus or permissions |
| C2S17-W19 | test_settings_company_profile_asks_first_then_saves | "name: (blank) → Acme Estimating LLC"; nothing saved until confirm; then saved |
| C2S17-W20 | test_settings_tax_asks_first_then_saves | "tax: 0 → 7"; bad percents, bases and kinds are 400 |
| C2S17-W21 | test_settings_unknown_section_and_no_change | An unknown section is 404; an empty change is 400 "nothing changed" |
| C2S17-W22 | test_settings_backup_asks_first | "Back up the Estimator database now? The newest 30 backups are kept." |
| C2S17-W23 | test_settings_audit_lists_changes | The estimate_created event, newest first; limit, action and bad-input filters |
| C2S17-W24 | test_settings_labor_rate_round_trip | A labor rate asks first, saves, and reads back $1 higher; a material price is refused here |
| C2S17-W25 | test_price_history_before_and_after_a_change | "Not saved yet" before, one dated 25¢ row after; an unknown price is 404 |
| C2S17-W26 | test_price_book_markups_follow_settings | Markups read, estimator can_change false, field 403, tax 7 in Settings shows as 7 here |
| C2S17-W27 | test_import_preview_guesses_the_columns | Columns, fields, the guessed mapping (Item Code → price key, Unit Price → cost), the first rows |
| C2S17-W28 | test_import_preview_mapping_round_trip | The preview's mapping drives the import: 1 update, 1 skipped, saved, 19¢ in the book |
| C2S17-W29 | test_price_history_shows_what_jobs_paid | After recording actuals, the shingle history names the job that paid |
| C2S17-W30 | test_reports_and_settings_are_ready_in_the_menu | Nav entries ready, sprint 17; the owner menu has both; reviewer/estimator/office have Reports only; field has neither |
| C2S17-W31 | test_reports_settings_and_revision_pages_are_wired | reports.js/settings.js/app.js call the Sprint 17 routes; index.html loads both new scripts |
| C2S17-W32 | test_guides_cover_reports_settings_and_revisions | The three guides exist with their titles and key lines |

The revision fixture (`revs`, copied from Coder 1's `test_sprint24_revisions_server.py`) is two fake plan sets: Rev A with 5 outlets, a slab, a porch, door D1 and a GFI; Rev B with outlet 3 moved, a bigger slab, the GFI removed, a floor box, a revision cloud, a changed D1 size and a new sheet E-102 — plus 6 measurements, 3 of them approved.

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | On a real plan pair (Rev A → Rev B from the architect): upload B as a revision of A, read both, compare from Reports → Plan revisions | Green boxes sit on what was added, orange on what changed or moved, red outlines what was removed; the sheet picker switches sheets; "Show Rev A (old)" shows the old sheet with what was removed or changed on it |
| M2 | After comparing, open "Measurements to re-measure" | Each flagged measurement opens in Blueprint Review; re-measuring it clears the flag; measurements on unchanged work kept their approval |
| M3 | Reports → Win / loss: mark one bid won and one lost | Win rate, value won and lost, by month and by trade all move; practice estimates stay out |
| M4 | Reports → Takeoff report and Estimate vs actual on a real project | Approved vs waiting totals match Blueprint Review; a finished job's recorded actuals show against the estimate lines |
| M5 | Reports → Exports: export one estimate and every estimate, as CSV and as Excel | Each file downloads and opens with the right rows; the file is also kept in the Estimator's exports folder |
| M6 | Settings as the owner: change the company name, the tax rate, a markup, a labor rate and a bid-template line | Each Save lists every change as old → new and saves on Yes; sign in as estimator, reviewer, office and field and confirm Settings is not in the menu and the screen refuses |
| M7 | Price Book: change a price, open its history; open Markups; import a supplier CSV | The history shows the dated change; Markups matches Settings; the import mapping guesses the columns, a wrong guess can be fixed, and the import saves |
| M8 | Role gates in the browser: reviewer and office open Reports; field opens neither Reports nor Settings | Reviewer and office see Reports but not Settings or the Price Book; field sees neither; the revision Compare button only appears for owner and estimator |

## Known limits

- The revision overlay draws boxes from the comparison; a sheet with no saved image shows the boxes without the plan underneath until the sheet image is read.
- Excel export needs openpyxl on the PC; without it the export says so and CSV still works.
- Win/loss by month reads the month a bid was marked won or lost, not the month it was sent.
- Settings changes go through the same service calls as the AI's tools, so a change made in chat shows up on the screen (and vice versa).
- The automated revision tests use seeded fake plan sets; real-plan accuracy is M1–M2's job, and the overlay's box positions on a real sheet are only proven there.

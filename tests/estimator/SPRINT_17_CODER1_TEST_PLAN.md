# Sprint 17 — Coder 1 (Jamie) test plan

**Scope:** The Coder 1 work from planned Sprint 17 that doesn't need the Plan Engine:
- the **actual-vs-estimate learning loop** (`est_record_actuals`, `est_compare_history`)
- **price book import** with column mapping (`pricebook_import`)
- **estimate export** to CSV or Excel (`est_export`)

Server mode multi-user, the processing-PC queue and Personal → Server export wait for a later sprint.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
Then start AI-Prowler again. The database upgrades itself to version 9. There are 59 Estimator tools (4 new).

## What was built

**Learning loop** (`estimator/learning/history.py`, database v9 table `estimate_actuals`)
- `est_record_actuals`: after a sold job (approved, sent, won), record what it really cost. You can record it four ways: per line item (`line_id`), per price (`price_key`), per kind of cost (all labor, all material), or the whole job (`total`). Hours and quantities are optional. `replace=true` clears earlier records. The estimate itself never changes. Owner, estimator and office roles can record.
- Actual costs are compared with the estimate's **cost** (with waste and labor burden), not its price to the customer. A whole-job record also shows the estimated and the real margin.
- `est_compare_history`:
  - **With an estimate:** each line is checked against your usual unit cost from past sent or won estimates. It's flagged when it's 25% off and there are at least 3 past estimates, or when it's under what past jobs really paid.
  - **With a price key:** that price's history.
  - **With neither:** every price with job costs, biggest gaps first. It suggests a `pricebook_update` call when 2 or more jobs show your price is 10% or more off. It never changes a price itself.
- The Reviewer agent's context now includes these history flags.

**Price book import** (`estimator/pricing/importer.py`)
- The price list can be a .csv or .xlsx file on the PC (5 MB, 5,000 rows at most), or CSV pasted into chat. Comma, semicolon and tab files all work, and an Excel sheet can be chosen by name.
- Columns are found by name (Item Code / SKU, Unit Price / Cost / Net Price, Description, UOM, Kind, Vendor) or by a `mapping` you give.
- A row matches a price by its key, or failing that by its exact description. `add_new=true` adds unmatched rows as `custom_...` prices; they need a unit.
- Safety:
  - A row whose unit doesn't match the price's unit (box vs lin ft) is skipped, never converted.
  - Costs that aren't dollar amounts are skipped, and so are duplicate rows.
  - Nothing is saved without `confirm=true`. The first call shows every change and every skipped row with its reason.
  - Owner and estimator only. The import is logged, and the supplier is saved.

**Export** (`estimator/exports.py`): `est_export` writes to the Estimator's `exports` folder.
- One estimate: its line items (trade, kind, description, quantity, unit, unit cost, waste, cost, price, price key) and totals.
- No estimate: a list of estimates, optionally for one status.
- CSV opens cleanly in Excel. Excel files get money formats and column widths.

**Tab:** the ❓ Help section has four new example prompts.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S17-A01 | Record every way | Line ($3,300 vs $2,978.25, 10.8% over), price key, all labor ($3,032.40 estimated), whole job ($8,600 vs $7,817.10, 10.0% over); quantity stored with waste (23.826 sq); estimate unchanged |
| S17-A02 | Replace and margin | Second record replaces the first; with 10% overhead / 15% profit, estimated margin 21.0% and real margin 29.2% |
| S17-A03 | Bad actuals (7 cases) | Unknown line, no target, bad kind, negative or non-dollar costs, negative hours, empty list: each refused |
| S17-A04 | Sold jobs and roles | Draft refused; field and reviewer roles refused |
| S17-H01 | Suggests a price | Two jobs at about $140/sq for $125/sq shingles → actual $140.60, "over the estimate", suggestion `{"rf_arch_sq": "140.60"}` (12.5% more); price book unchanged |
| S17-H02 | One job isn't enough | No suggestion from one job |
| S17-H03 | Lines vs history | $200/sq against 3 past estimates at $125 → "higher_than_usual", 60.0% above; other lines not flagged |
| S17-H04 | Under real cost | A line below what a past job really paid ($120.04/sq) is flagged |
| S17-H05 | Empty history | A note explains how to start; unknown price key → not found |
| S17-I01 | Import preview, then save | Columns found by name; 3 updates, 3 skipped (unit box vs lf, no match, "call" isn't a cost); nothing saved until confirm; then saved with the date, a description match, the supplier, and a log entry |
| S17-I02 | Add new prices | Ice and water shield added as `custom_ice_and_water_shield_roll`, $95/roll |
| S17-I03 | Mapping | Semicolon file with odd headers needs a mapping; a wrong column name or field name is refused |
| S17-I04 | Files | CSV file; Excel file with a blank first row and a named sheet; a missing sheet is refused |
| S17-I05 | Bad requests (4 cases) | Neither source; missing file; .exe; bad date |
| S17-I06 | Safety | Field role refused; duplicate row skipped (first used); same price again → nothing to save |
| S17-E01 | Export one estimate | CSV with line items (shingles 21.66 sq at $125.00, 10% waste, cost $2,978.25) and Total $7,817.10 |
| S17-E02 | Export a list, Excel | Won-only list; Excel workbook with an Estimates sheet; pdf refused |
| S17-T01 | MCP tools | Record (JSON text or one object), compare, import (needs confirmation, then saves), export |
| S17-R01 | Reviewer agent | The history flag ("really paid $120.04") is in the Reviewer's context |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 599 passed, 1 skipped (the GUI test file, no tkinter) |
| Windows 11, Python 3.11.8 (Jamie's PC), `run_tests_estimate.bat` | 608 passed in 29 s (2026-11-07) |
| File check | All Sprint 17 files on the PC match the tested copy (test_est_database.py differs only by blank lines, as before) |

## Manual check after deploying (in chat)

1. "Import my price list" with a small CSV saved from a supplier. You should see the changes and the skipped rows first; say yes, and they're saved.
2. Mark a test roof estimate won. Then: "the roof really cost $8,600; shingles were $3,300". It records the costs and shows the job over or under, with the real margin.
3. "Where do my prices run high or low?" shows `est_compare_history`. After two jobs it suggests a price update.
4. "Export that estimate to Excel." The file appears in `%USERPROFILE%\AI-Prowler\Estimator\exports`.

## Self-review checklist

- [x] Actual costs never change an estimate or a price; suggestions need pricebook_update with confirm
- [x] Costs are compared with cost (waste and burden included), not with the customer's price
- [x] Import never converts units and never saves without confirm; files are size- and type-limited
- [x] Every write is role-checked and logged
- [ ] Later: Server multi-user (roles in the GUI, "is editing", assignments), processing-PC queue, Personal → Server export

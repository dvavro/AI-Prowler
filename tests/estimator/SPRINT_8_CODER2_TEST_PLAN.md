# Sprint 8 — Coder 2 (David) test plan: two-way linking, the Estimates screen, takeoff tool polish

**Scope:** The Coder 2 Sprint 8 row is "Two-way linking (material ↔ measurement); Estimates screen; manual takeoff tool polish".

- **Linking:** every priced line knows the measurements behind its quantity, and every measurement knows the lines it drives. Both screens show this and link to each other.
- **Estimates screen:** it's built on Jamie's estimate services.
- **Drawing tools in Blueprint Review:** snapping, straight lines with Shift, take back a point, perimeter of a drawn area, and typing a number in.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
deploy_to_install.bat                   then restart AI-Prowler
```
No new tools, tables or libraries.

## What was built

**Linking** (`estimator/api/links.py`, read only):
- **The rule.** A line's quantity comes from its trade's formula; quick.py keeps the formula on the line. The formula's variables are the trade's questions, and a measurement feeds one question. So a line is linked to every measurement of its trade that feeds a question its formula uses. Approved measurements are priced; proposed ones are listed as waiting. Hand-entered lines link to nothing.
- **For each question,** it shows where the priced answer came from:
  - **measured:** the answer matches the approved total.
  - **differs:** the answer and the measured total disagree.
  - **typed:** an answer with no measurements behind it.
  - **waiting:** measured, but the trade isn't priced with it yet.
- **Use the measurements.** It works out the trade's answers with the approved totals in place.

**Estimates screen** (`estimator/ui/web/estimates.js`; `#/estimates`, `#/estimates/<id>?line=<line>`; API in `estimator/api/estimate_api.py`):
- **List:** all estimates by status, with their totals.
- **Estimate page:**
  - **Header:** total, margin (roles that see margins), trades, and approved measurements.
  - **Where the quantities come from,** for each trade, using the states above.
  - **Price it with the approved measurements…** re-prices the trade with the measured totals. It asks first and shows each change, e.g. "Roof area: 2000 → 144". It uses `est_quick_answer` with the totals from `takeoff_list`. Owner and estimator only.
  - **Lines:** quantity, unit cost and waste (roles that see margins), and price.
  - **📏 n** on a line lists its measurements, with **show on the plan** for one and **Show all of them on the plan** for all. Lines with no measurements say "not measured" or "entered by hand".
  - **✓ Check it:** `est_validate`.
  - **Compare with past jobs:** `est_compare_history`. Margin roles only; the API refuses others.
  - **Good / better / best options:** **Price the options** (`est_scenarios`) and **Use this one…** (`est_choose_scenario`, asks first).
  - **＋ Add a line by hand:** `est_add_line_item`, with a unit cost in dollars or a price book key.
  - **Recalculate:** `est_calculate`.
  - **New version…** (`est_create_revision`) for an approved or sent estimate. It asks first, says the open quotes will be voided, then opens the new version.
- **Links:** the project page has **🧮 Open the estimate**.
- **Guide:** a new one, "Check an estimate against the plans".
- **Roles:**
  - Everyone sees the screen.
  - Field staff see prices but never costs, margins or calc.
  - Owner and estimator change things; office can price options.
  - Every write goes through the service layer's role and rev checks.

**Blueprint Review side of the links** (`review.js`):
- **Lines tab:** the estimate's priced lines by trade, with how many measurements are behind each and how many are on this sheet. Click one to highlight all its measurements; it switches to their sheet if needed and zooms to them. Each line links to the estimate.
- **`?line=<id>`** (from the estimate page) opens with that line picked.
- **Detail:** **Priced lines it feeds**, or **Lines it will feed once approved**, each linking to the estimate. If none, it says why: not approved yet, not priced yet, or not linked to a question.
- `GET /estimates/<id>/takeoff` now includes `links`.

**Tool polish** (`review.js`):
- **Snap:** points snap to the corners of what's shown on the plan within 10 px, and to the shape being drawn. A red ring shows the snap. **Alt** places a point freely.
- **Shift** keeps a segment straight across or down, and snaps only in line with it.
- **Backspace / Delete** takes back the last point.
- **Perimeter:** a drawn area or rectangle can be saved as its **perimeter** (e.g. baseboard round a room).
- **＋ Type a number in…** adds a typed measurement (from a site visit or a schedule). The unit follows the question picked.
- The guide "Measure and approve on the plans" has these.

## Test cases

`tests/estimator/webapp/test_web_sprint8.py` (a roof priced at 2,000 sq ft; 1,200 sq ft approved, 900 waiting, 180 lf of edges approved):

| ID | Test | Checks |
|---|---|---|
| C2S8-L01 | Line ↔ measurements | drip edge ← edges; shingles ← area approved + area waiting; permit links to nothing; measurement → lines |
| C2S8-L02 | Where answers came from | roof area and edges differ; pitch and layers typed; a measured trade not on the estimate is waiting |
| C2S8-L03 | Hand-entered line | custom, no questions, no measurements |
| C2S8-E01 | Estimate page | estimate, can_* for owner, costs and calc shown |
| C2S8-E02 | Field | no key anywhere with cost, margin or calc; prices shown; history 403; checks without costs |
| C2S8-U01 | Use the measurements | asks with "2000 → 1200.0" and the edges; answers replaced, pitch kept; states become measured; old rev 409 |
| C2S8-U02 | Refusals | no approved measurements 400; reviewer/office 403; unknown trade 400; no rev 400 |
| C2S8-E03 | Add a line, recalculate | the custom section; old rev 409; bad cost/kind/rev 400; field 403 |
| C2S8-E04 | Checks and history | measurements_waiting found; history lines and summary |
| C2S8-E05 | Options | priced and saved; choose asks with the option's name; unknown option 400 |
| C2S8-E06 | New version | draft refused; approved → asks ("Make version 2", "voided") → new draft v2 |
| C2S8-E07 | Roles and errors | every role opens it; another company 404; CSRF; unknown 404; bad JSON 400 |
| C2S8-R01 | Review page | links in the takeoff answer, measurement → lines |
| C2S8-W01 | Pages | screen ready, page in nav, estimates.js after review.js, every call on the page, no innerHTML/style attributes, review.js has the Lines tab, snap, Alt, Shift, Backspace, typed number, perimeter, `?line=` |
| C2S8-W02 | Guides | every button the guides name is on the pages |
| C2S8-W03 | One global scope | no function or variable defined twice across the web scripts |

Changed: `test_web_parity.py` PENDING adds `est_apply_assembly` and `est_update_line_item`. The Estimates screen lists them, but they aren't built yet; they come with Coder 1's assemblies work.

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), Coder 2 track | 402 passed (2026-11-08) |
| Windows 11, Python 3.11.8, all Estimator tests | 1075 passed (2026-11-08) |
| Browser smoke test, Sprint 8 (headless Chromium, scratch `estimate_smoke.py`) | Estimates list → roof area "differs" → Price it with the approved measurements (asks "2000 → 144") → measured → 📏 on a line → Show all of them on the plan → Blueprint Review with the line picked and its room highlighted → Detail lists 7 lines it feeds → snap to both room corners (exactly [5,5] and [8,5], ≈ 12 ft) → Backspace → Shift keeps it level → typed 50 lf ridge (unit followed the question) → Check it → Compare with past jobs → options priced; no browser errors. It found a name clash: `lineMeasurements` was defined in both review.js and estimates.js, so the later one replaced the other. That's fixed, with test C2S8-W03. |
| Browser smoke test, Sprint 7 (`review_smoke.py`) again | no problems |

## Manual checks

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | Deploy, restart → Estimates | the list; open one | |
| M2 | A priced trade with approved measurements | "Where the quantities come from" is right; Price it with the approved measurements… → the totals change as shown | |
| M3 | 📏 on a line → Show all of them on the plan | Blueprint Review with them highlighted, Lines tab open | |
| M4 | In Blueprint Review, a measurement's Detail → a line link | back to the estimate with that line highlighted | |
| M5 | Draw a room with Area, clicking near its corners | the points land exactly on the corners (red ring); Alt places freely | |
| M6 | Shift while drawing a wall length | straight across or down | |
| M7 | Draw an area, save as perimeter | perimeter in lf | |
| M8 | Options, Add a line by hand, Recalculate, New version… on an approved estimate | each works and asks where it should | |
| M9 | Sign in as field (test session) → an estimate | prices only, no unit costs or margin, no Compare | |

## Notes for Jamie

- **`est_update_line_item` and `est_apply_assembly`** are on the Estimates screen's tool list in the spec but not built. They're on the parity PENDING list. A hand line can't be edited on the page until `est_update_line_item` exists.
- **Line formulas.** Linking reads each line's `calc.formula` (quick.py keeps it). If another pricing path ever writes lines without it, those lines will show as "entered by hand".
- **Using the measurements re-prices with `quick.answer`,** with the trade's current answers and the approved totals on top, the same as `runner_submit_takeoff(from_measurements)` does without a runner task.

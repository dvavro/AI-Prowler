# Sprint 11 — Coder 2 (David) test plan: visual verification, company symbol library and learning, Agents screen

**Scope:** The Coder 2 Sprint 11 row is "Visual verification UI (detection panel, bulk approve/reject/relabel, find similar), company library and learning workflow; Reviews, Symbol Library and Agents screens".

- **Reviews:** a person checks every symbol the plan engine counted before it's priced: approve, take out, relabel, reset, add a missed one, find more like one.
- **Learning:** approved, relabelled and added symbols become company examples, so the next plan set finds them with no legend.
- **Symbol Library and Agents:** the two screens that were "coming" are now ready.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
deploy_to_install.bat                   then restart AI-Prowler
```
- **New database migration:** 15 (`symbol_detections.origin`, `original_json`; `symbol_examples.template_json`, `detection_id`, `added_by`).
- **New MCP tools (4):** `symbol_detection_review`, `symbol_find_similar`, `symbol_library_list`, `symbol_define` (96 tools in all).
- **No new libraries.**

## What was built

**Review** (`estimator/symbols/review.py`):
- **Actions:** approve, reject (take out of the count: still listed, not counted), relabel (give an item type), reset (back to proposed) and add (a missed symbol at a point on a sheet: approved, origin manual).
- **apply_to_matches:** relabel, approve or reject every detection on the plan set with the same definition and item type.
- **History:** each detection keeps its first result (`original_json`: item type, definition, status, origin); lists show `original` when it changed.
- **Who:** owner, estimator, reviewer; never an agent; every action asks first and is logged (`symbols_reviewed`).
- **Find similar:** the line work in the selected symbol's box (or a box a person draws) is the template; every sheet is searched (vector, or raster on scans). Hits within 0.15" of a symbol already found are skipped, and so are hits inside legends and schedules. It asks first with the count by sheet; new hits are proposed, origin `similar`.
- **Thumbnails:** a small crop of each detection from its sheet image, cached in `data/symbol_crops/` (local only, never sent to an AI provider).

**Company library and learning** (`estimator/symbols/library.py`, plan engine):
- **Learning:** approve, relabel and add save up to 3 shapes per action as `symbol_examples` (source `confirmed`, the line work as `template_json`) on the company definition for that item type (made if needed). At most 12 examples per definition.
- **Next plan set:** Jamie's `drawing_model.engine` passes the company templates to the engine (`info["symbol_library"]`). The engine searches for them alongside the legend's. A plan-set legend entry wins over a library entry at the same spot. Library hits are saved with `origin: library` and "company library" as where the definition came from. They are still proposals.
- **Library screen calls:** list (company, firm, standard; by trade; examples and found counts), define and version a company symbol (the standard library can't be edited), export / import (`ai-prowler-symbol-library` file).

**Counts:** rejected detections are listed but not counted; `needs_review` counts only proposed ones.

**API** (`estimator/api/symbols_api.py`):
- `GET /symbol-reviews`
- `POST /symbol-detections/review`, `POST /symbol-detections/similar`
- `GET /symbol-detections/<id>/crop.png`
- `GET /symbol-library`, `POST /symbol-library/define`, `GET /symbol-library/export`, `POST /symbol-library/import`
- `GET /agents`, `POST /agents/<module_id>`
- `GET /runs/<id>`, `POST /runs`, `POST /runner-tasks/<id>/retry`

Every write answers `needs_confirmation` first. Starting a run and retrying a task ask first in the web app, though the MCP tools don't.

**Screens** (`estimator/ui/web/verify.js`; Reviews, Symbol Library and Agents are now ready):
- **Reviews:** plan sets with symbols, those to check first. One plan set's detection panel (`#/reviews/<id>`) has:
  - type tiles with counts
  - filters (status, sheet) and sort (least sure first)
  - a thumbnail grid: click to select, "N matches, M selected"
  - Select all / none, ✓ Approve, ✗ Take out, Relabel… (with every identical match), Back to "to check", Find similar…
  - "open on the plan" (Blueprint Review)
  - Add a symbol the engine missed
  - Field staff look; they can't decide.
- **Symbol Library:** your company's symbols, then the standard ones, by trade. New symbol… / Edit… (a new version), Export, Import….
- **Agents:** each trade agent's settings (on, sure enough at, approve by itself; owner only) and the takeoff runs with each trade's state, next step and Try again….
- **Guides:** "Check the symbol counts before they're priced", "Teach AI-Prowler your company's symbols", "Set up the trade agents and watch takeoff runs".

## Test cases

`tests/estimator/plan_engine/test_plan_engine_sprint11.py`, `tests/estimator/webapp/test_web_sprint11.py`:

| ID | Test | Checks |
|---|---|---|
| C2S11-S01 | approve and take out | asks first with counts by type; approved/rejected/proposed counts; taken-out not counted; history kept; reset |
| C2S11-S02 | relabel all matches | both unknown flags become floor boxes; trade and label from the standard type; company definition with 2 examples of 3 strokes |
| C2S11-S03 | who can review | office, field, agents refused; reviewer can; bad action, relabel with no type, no ids refused |
| C2S11-S04 | add a missed symbol | asks first; approved, origin manual, at the point; counted; point off the sheet refused |
| C2S11-S05 | find similar | box round one triangle finds 4 on 2 sheets (turned too); adds proposed; again finds 0; empty box refused |
| C2S11-S06 | learned on the next plan set | a new plan set with no legend finds the 2 floor boxes from the company library (proposed, origin library) |
| C2S11-S07 | legend wins | a legend saying the flag is a thermostat beats the company's floor box |
| C2S11-S08 | library list | company then standard; 37+ standard types with aliases; trade filter; bad level refused |
| C2S11-S09 | define and version | asks first; v1 with examples and code; v2 with assembly; duplicates, the standard library, bad names and trades, field refused |
| C2S11-S10 | export / import | the file has examples; another company imports it and its engine gets the templates; wrong format refused |
| C2S11-S11 | thumbnail | a small PNG, cached |
| C2S11-S12 | a broken library | the plans are still read, with the legend alone |
| C2S11-W01 | Reviews list | counts per plan set; field can look, not decide; office refused; another company sees nothing |
| C2S11-W02 | approve / take out over the API | needs_confirmation without the AI wording; nothing changes until confirm; history |
| C2S11-W03 | relabel, add, find similar over the API | counts follow; Find similar skips the legend's own samples |
| C2S11-W04 | refusals | roles, bad ids, bad action, bad point and box, unknown and other-company ids |
| C2S11-W05 | thumbnail over the API | PNG with nosniff; field yes, office no; unknown 404 |
| C2S11-W06 | Symbol Library API | list, define asks first, trade filter, export as a download, import into another company |
| C2S11-W07 | Symbol Library roles | reviewer yes; field, office no; bad item types refused |
| C2S11-W08 | Agent Manager | settings ask first and change nothing until confirm; owner only; reviewer, field, office can't open; unknown setting / trade refused |
| C2S11-W09 | takeoff runs | start asks first; drywall waits for framing; listed on /agents; status; retry asks, a running task can't be retried |
| C2S11-W10 | screens and page | three screens ready, symbol_review page listed, renderers present, verify.js after review.js, no inline styles |

Also fixed: Find similar no longer finds the legend's own sample as a new symbol.

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), Coder 2 track | 497 passed (2026-11-08) |
| Same PC, all Estimator tests | see the Implementation Plan progress row |
| Browser smoke test (scratch `verify_smoke.py`, headless Chromium) | Reviews list, 5 thumbnails load, select 2 → "3 matches, 2 selected", approve, relabel all matches, library shows the learned floor box, new company symbol, Agents threshold saved, run trades shown: no problems |

## Manual checks (David)

| # | Check | Expect | Result |
|---|---|---|---|
| M1 | A real electrical plan in Reviews | thumbnails readable; least-sure-first puts the doubtful ones first | |
| M2 | Relabel an unknown symbol with every match | all identical ones change; counts follow | |
| M3 | Read the next plan set from the same architect | the relabelled symbol is found from the company library, marked to check | |
| M4 | Find similar on a symbol the legend missed | finds the others on every sheet; nothing in the legend or schedules | |
| M5 | Symbol Library export, import on another PC | the symbols and examples arrive | |
| M6 | Agents: turn a trade off, start a run with it | skipped, with the warning | |
| M7 | Ask Claude "those three are floor boxes" | symbol_detection_review relabel, asks first | |
| M8 | Phone (field role) | Reviews opens and shows the thumbnails; no action buttons | |

## Notes for Jamie

- **Migration 15** is mine (symbol review columns). Renumber if you've added a 15.
- **`drawing_model/engine.py`:** `_run_engine` now sets `info["symbol_library"] = symbols.library.engine_templates(conn, company)` so plan reading uses the company's learned symbols. It's one line, and errors are caught (an empty list).
- **`est_tools.py`:** 4 new tools (96 in all); `test_est_mcp_tools` updated.
- **`reviews.start("detection_set")`** still says the symbol engine isn't installed. Symbol review is done through `symbol_detection_review`; your review sessions could now point at it.
- **Counts aren't fed into `takeoff_propose` yet.** `symbol_detections_list(estimate_id=…)` gives approved counts by type and room.
- **Firm profiles** (`level = 'firm'`) are listed but never filled, because plan sets don't record their design firm. If you add `plan_sets.design_firm`, I'll learn per firm too.
- **Blueprint Review:** the "open on the plan" link opens the sheet (`?sheet=`); `&symbol=` is passed but doesn't highlight yet. That's for Sprint 12, with a Symbols tab.

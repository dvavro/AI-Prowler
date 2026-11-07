# Sprint 2 — Coder 1 (Jamie) test plan

**Scope:** module registry and manifest validation, estimate service layer, price book, quick-estimate engine, the first two service modules (pressure washing, house cleaning) and the Estimator MCP tools.
**Team note:** David (Coder 2) is not available right now. His Sprint 2 items (plan engine, web app, GUI tab) are on hold. Jamie builds and tests the Coder 1 track alone. Code review: Jamie reviews her own work with a checklist, and the review by David is deferred until he's back.

## How to run

```
cd C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler
python tests\estimator\run_estimator_tests.py
```

Tests use a throwaway data folder, so they never touch a real `estimator.db`.

## What was built

| Area | File | What it does |
|---|---|---|
| Errors | `estimator/errors.py` | One error type per failure, each with a machine code and a plain message: not_found, invalid_input, stale_revision, not_editable, permission_denied |
| Context | `estimator/context.py` | Who is acting (company, user, role, mode, agent), so Personal and Server mode run the same code |
| Registry | `estimator/modules/registry.py` | Finds `modules/<category>/<id>/manifest.yaml` files and checks them; a bad module is skipped and its error is reported |
| Price book | `estimator/pricing/price_book.py` | Uses the latest price on or before today. Copies in a module's sample prices (flagged as samples) when the company has none |
| Service | `estimator/estimating/service.py` | create, get, list, add_trade, add_line_item, calculate, set_status and save_markups, with rev checks, the finalized lock, roles, company scoping and the audit log |
| Quick estimate | `estimator/estimating/quick.py` | Checks the answers, works out each line with the sandboxed formula engine and replaces that module's section |
| Modules | `modules/services/pressure_washing`, `house_cleaning` | manifest.yaml, sample prices and golden cases |
| MCP tools | `estimator/mcp_tools/est_tools.py` | est_list_modules, est_create_estimate, est_get_estimate, est_list_estimates, est_add_line_item, est_calculate, est_quick_questions, est_quick_answer, and `register(mcp)` |

## Test cases

| ID | Test | Expected |
|---|---|---|
| S2-R01 | The shipped modules load | No errors; pressure_washing and house_cleaning are present |
| S2-R02 | A good manifest loads | Minimum charge, choice factors and sample prices are parsed |
| S2-R03 | 11 kinds of bad manifest (wrong id, category, question type, unknown variable, unsafe formula, syntax error, missing price, bad kind, bad unit, unit mismatch, bad default) | Each is rejected with a clear message |
| S2-R04 | A choice question with fewer than 2 options, or duplicate options | Rejected |
| S2-R05 | A price CSV with a negative or duplicate price | Rejected |
| S2-R06 | Invalid YAML, or a missing manifest | Rejected |
| S2-R07 | One bad module beside good ones | The bad one is skipped and reported; the good ones still load |
| S2-R08 | A module in the wrong category folder | Reported |
| S2-R09 | Asking for an unknown module | not_found, with a list of the modules that exist |
| S2-S01 | Create and get an estimate | Draft, rev 1 |
| S2-S02 | Add a line | Priced with waste; rev goes to 2 |
| S2-S03 | Write with an old rev | stale_revision; nothing is written |
| S2-S04 | Save markups, then recalculate | 100.00 cost becomes 137.00 (10% overhead, 20% profit, 5% tax on cost) |
| S2-S05 | Look up a price key; a missing key; a unit mismatch | Works; not_found; invalid_input |
| S2-S06 | Several effective dates | Latest date on or before today wins; future prices are ignored |
| S2-S07 | 7 bad line inputs | invalid_input, naming the field |
| S2-S08 | An approved estimate | Locked; can't go back to draft; can move to won |
| S2-S09 | Another company's estimate | Not found, and not listed |
| S2-S10 | Reviewer, office and field roles | Can read; can't write |
| S2-S11 | An agent writes | Event actor is agent:…, on behalf of the user |
| S2-S12 | List with a status filter; add_trade; duplicate trade | Works; duplicate rejected |
| S2-S13 | A failure part-way through a write | Rolled back; rev unchanged |
| S2-Q01 | Golden cases from each module's tests/golden.yaml | Exact cents match |
| S2-Q02 | Every quick-estimate module has golden cases | Yes |
| S2-Q03 | Question list | In order; choices are shown without their pricing factors |
| S2-Q04 | Missing required answers; unknown questions | invalid_input, listing what's missing |
| S2-Q05 | 6 bad answers (negative, not a number, fraction for a whole number, over the max, bad choice, bad yes/no) | Rejected |
| S2-Q06 | Answers given as text ("1,000", "yes") | Accepted |
| S2-Q07 | Answering again | Replaces the lines (doesn't add to them) |
| S2-Q08 | Sample prices, then the company's own price | Sample warning first; the company price is used after it's set |
| S2-Q09 | Company minimum higher than the module minimum | The higher minimum wins |
| S2-Q10 | Quick estimate with markups | 267.50 becomes 353.10 |
| S2-Q11 | Unknown module | not_found |
| S2-Q12 | All answers zero | No lines; the minimum charge only |
| S2-T01..T07 | MCP tool contract | Tools return JSON text; errors come back as JSON (never a crash); answers can be an object or JSON text; all 8 tools register on FastMCP with the right inputs |

## Golden cases (sample prices, no markups)

| Module | Case | Total |
|---|---|---|
| Pressure washing | 800 sq ft driveway, normal condition: $138.00, raised to the minimum | **$150.00** |
| Pressure washing | 1,000 sq ft driveway plus 2,000 sq ft of two-story siding, heavy condition, 2 oil stains, sealing | **$1,328.75** |
| House cleaning | 3 bed / 2 bath / 1,800 sq ft, average, one time (5.35 hrs) | **$267.50** |
| House cleaning | 2 bed / 1 bath / 1,000 sq ft, dirty, pets, every 2 weeks, oven, 10 windows | **$284.13** |
| House cleaning | 1 bed / 1 bath / 500 sq ft, clean, monthly: $106.20, raised to the minimum | **$120.00** |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13, mcp 1.28.1 | 205 passed (135 Sprint 1 + 70 Sprint 2) |
| Windows 11, Python 3.11.8 (Jamie's PC) | 205 passed in 3.9 s (2026-11-05) |

## Manual check (after the MCP hook is added)

- S2-X01: In Claude, ask "make a pressure washing estimate for a 1,000 sq ft driveway, heavy, with sealing". Claude should call est_list_modules, then est_create_estimate, est_quick_questions and est_quick_answer, show the total, and say the prices are samples.

## Self-review checklist (in place of David's review)

- [ ] Every write goes through `service.transaction` and checks rev
- [ ] No floats in money paths
- [ ] Every MCP tool returns JSON text, including when it fails
- [ ] Formulas run only through the sandboxed engine
- [ ] Every query filters on company_id

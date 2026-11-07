# Estimator — Sprint 1 Test Plan (Coder 1: Jamie)

Phase 0 Foundations · Weeks 1–2 · Spec v1.0 · Owner: Tester 1 (until testers join, Coder 1 runs it) · Reviewer: Coder 2 (David)

## Scope

| Area | Code | Design spec section |
| --- | --- | --- |
| Package and data folder | `estimator/__init__.py`, `estimator/config.py` | Directory structure → Runtime work directory |
| Money (integer cents) and units | `estimator/core/units/` | MCP tool catalog → Conventions |
| Sandboxed formula engine | `estimator/core/formula_engine/` | Trade module framework |
| Pricing stack | `estimator/pricing/` | Trade module framework → Pricing stack |
| Database, migrations, backups | `estimator/database/` | Data model |

Out of scope this sprint (Coder 2 / later sprints): web app shell, MCP tools, module registry.

## How to run

```
python -m pip install "pytest>=7.4" "pytest-timeout>=2.1"     (once, if pytest is missing)
python tests\estimator\run_estimator_tests.py
```

Runs only the Estimator tests, in a throwaway data folder (`ESTIMATOR_DATA_DIR` is set to a temp folder for every test), so a real `estimator.db` is never touched. The full AI-Prowler suite (`run_tests.bat`) also picks them up.

## Test cases

| ID | Area | What is checked | Test | Status |
| --- | --- | --- | --- | --- |
| S1-M01 | Money | Dollar → cents rounds half-up (1.005 → 101) | `test_cents_from_decimal_rounds_half_up` | Automated |
| S1-M02 | Money | Floats, booleans, NaN, Infinity and junk are rejected | `test_cents_from_decimal_rejects_floats_and_junk` | Automated |
| S1-M03 | Money | Parse "$1,234.56", "(45.00)", "-12" | `test_parse_money` | Automated |
| S1-M04 | Money | Format cents, including negatives | `test_format_cents` | Automated |
| S1-M05 | Money | Format → parse round trip on 2,000 random amounts | `test_format_parse_round_trip_random` | Automated |
| S1-M06 | Money | Bid rounding to $1/$5/$10 increments, up/down/half-up | `test_round_cents_to`, `test_round_cents_to_validates` | Automated |
| S1-M07 | Money | 10 × $0.10 = $1.00 exactly; percentages round to the cent | `test_money_arithmetic_is_exact` | Automated |
| S1-U01 | Units | Aliases (SF, CY, Squares, LF) map to canonical codes | `test_normalize_unit_aliases` | Automated |
| S1-U02 | Units | Conversions (27 cu ft = 1 CY, 1 square = 100 sq ft…) | `test_convert` | Automated |
| S1-U03 | Units | Area can't be converted to length | `test_convert_refuses_mixed_dimensions` | Automated |
| S1-U04 | Units | Round-trip conversions on 500 random values | `test_convert_round_trip_random` | Automated |
| S1-F01 | Formulas | Spec formulas: concrete CY, framing studs, roof squares, paint gallons | `test_concrete_slab_cubic_yards` and 3 more | Automated |
| S1-F02 | Formulas | Arithmetic, comparisons, and/or/not, functions, exact decimals (0.1 + 0.2 = 0.3) | `test_arithmetic` | Automated |
| S1-F03 | Formulas | **Security**: `__import__`, `open`, attributes, subscripts, lambdas, comprehensions, strings, eval/exec, keyword args, `_names` are all rejected | `test_rejects_unsafe_or_unsupported` (22 cases) | Automated |
| S1-F04 | Formulas | Division by zero, huge exponents, sqrt(-1), unknown variables fail with a clear message | `test_runtime_errors_are_clean` | Automated |
| S1-F05 | Formulas | Length and size limits | `test_size_limits` | Automated |
| S1-F06 | Formulas | 3,000 random junk formulas: result is a number or a FormulaError, never anything else | `test_fuzzed_formulas_never_escape` | Automated |
| S1-P01 | Pricing | Material line hand-calculated: base, waste, overhead, profit, tax | `test_material_line_hand_calculated` | Automated |
| S1-P02 | Pricing | Labor gets burden and no tax | `test_labor_gets_burden_and_no_tax` | Automated |
| S1-P03 | Pricing | Tax on price option | `test_tax_on_price_option` | Automated |
| S1-P04 | Pricing | Estimate totals, rounding to $10, minimum job charge | `test_estimate_totals_rounding_and_minimum` | Automated |
| S1-P05 | Pricing | Margin calculation | `test_margin` | Automated |
| S1-P06 | Pricing | Steps always add up to the total, all cents non-negative (3,000 random lines) | `test_sum_of_steps_always_equals_total_random` | Automated |
| S1-P07 | Pricing | Bad markups and line inputs are rejected | `test_markups_validation`, `test_line_validation` | Automated |
| S1-D01 | Database | Data folder and sub-folders created in the sandbox | `test_data_folder_and_db_created_in_sandbox` | Automated |
| S1-D02 | Database | Migrations apply once; rerun does nothing | `test_migrations_apply_once` | Automated |
| S1-D03 | Database | A newer database is refused by older software | `test_newer_database_is_refused` | Automated |
| S1-D04 | Database | A failed migration rolls back completely | `test_failed_migration_rolls_back` | Automated |
| S1-D05 | Database | Every business table has `company_id` (Server mode ready) | `test_every_business_table_has_company_or_parent` | Automated |
| S1-D06 | Database | Constraints: no negative money, valid kinds and statuses, foreign keys | `test_constraints` | Automated |
| S1-D07 | Database | Deleting an estimate removes its sections and line items | `test_deleting_estimate_cascades` | Automated |
| S1-D08 | Backups | Backup, change, restore returns the earlier data; old file kept | `test_backup_and_restore` | Automated |
| S1-D09 | Backups | Pruning keeps the newest backups | `test_prune_keeps_newest` | Automated |
| S1-D10 | Backups | A damaged backup is never restored | `test_restore_refuses_damaged_backup` | Automated |
| S1-X01 | Windows | All tests pass on Windows 11 with AI-Prowler's Python 3.11 | `run_estimator_tests.py` on Jamie's PC | **Pass** (135/135) |
| S1-X02 | Windows | Default data folder is `%USERPROFILE%\AI-Prowler\Estimator\` when no override is set | `manual_checks_sprint1.py` | **Pass** |
| S1-X03 | Windows | Backup while another connection has `estimator.db` open with a write in progress (WAL) | `manual_checks_sprint1.py` | **Pass** |

## Results

| Date | Platform | Result |
| --- | --- | --- |
| 2026-11-05 | Linux, Python 3.13, pytest 9.1 | 135 passed |
| 2026-11-05 | Windows 11, Python 3.11.8, pytest 9.2 (Jamie's PC) | 135 passed in 3.5 s; S1-X02 and S1-X03 pass |

## Gate G0 contribution (Coder 1 part)

- [x] All automated tests above pass on Windows 11 (S1-X01)
- [x] Manual checks S1-X02 and S1-X03 done
- [ ] Code reviewed by Coder 2 (David)
- [x] Design spec updated (Change log entry, Sprint 1)
- [ ] Remaining G0 item for Sprint 2: an estimate calculates correctly through MCP from Claude (needs `est_*` tools)

## Looking ahead: Sprint 2 test prep (Coder 1)

Tests to write before or alongside Sprint 2 code:
- Module registry: valid manifest loads; missing fields, bad formulas, unknown units and duplicate ids rejected with clear errors.
- MCP contract tests for `est_create_estimate`, `est_get_estimate`, `est_add_line_item`, `est_calculate`, `est_list_modules`: schema-valid output, units explicit, money in cents, `estimate_rev` returned, stale `rev` rejected.
- Quick estimates: golden cases for pressure washing and house cleaning (Tester 2 drafts the module content and expected prices).

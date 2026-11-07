# Sprint 3 — Coder 1 (Jamie) test plan

**Scope:** Estimating Director foundation (job file, playbooks, triage, settings, quick-quote lane up to approval), generic service module, setup wizard backend, and 9 new MCP tools.
**Not in this sprint (moved to Sprint 4 with bids):** links to AI-Prowler's customers, quotes and jobs (`create_customer`, `create_quote`, `create_job`).
**Team note:** David (Coder 2) is still unavailable; Jamie self-reviews with the checklist below.

## How to run

```
cd C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler
python tests\estimator\run_estimator_tests.py
```

Then run `install_estimator.bat` (it now also copies the Director) and restart AI-Prowler.

## What was built

| Area | File | What it does |
|---|---|---|
| Database v2 | `estimator/database/migrations.py` | `director_jobs`, `director_steps`, `playbook_overrides`, `director_settings`; v1 databases upgrade in place |
| Playbooks | `estimator/director/playbooks.py`, `playbooks/*.yaml` | Quick quote (live), standard estimate and full plan takeoff (shown as coming in Phase 3 and 4). Rejects bad playbooks; anything sent to a customer must come after an approval checkpoint |
| Triage | `estimator/director/triage.py` | Picks the lane and service from plain words using module keywords; plans mean full takeoff; trade words mean standard estimate; unclear requests get one question |
| Settings | `estimator/director/settings.py` | Quick-send (one-tap) limit $100, calendar booking off, customer intake off, follow-up 5 days, review reminder 2 days, briefing 07:00 chat. Owner only, every change logged |
| Job file | `estimator/director/jobs.py` | One record per job every agent shares; steps logged |
| Engine | `estimator/director/engine.py` | Runs a job forward: ask questions, price (through the quick-estimate engine only), approval checkpoint, then waits for bids (Sprint 4). Speaks to office and field staff as "ask the customer…" |
| Generic service | `modules/services/generic_service` | Hours × crew × urgency, materials at cost, trip fee, $100 minimum |
| Setup wizard | `estimator/estimating/setup.py` | 9 steps; company profile, tax, markups and prices are applied for real; tracks sample prices still in use |
| Roles | `estimator/estimating/service.py` | Office and field can start and price quick quotes; hand-entered lines stay owner/estimator |
| MCP tools | `estimator/mcp_tools/est_tools.py` | `est_director_start`, `est_director_next`, `est_job_status`, `est_jobs_board`, `est_director_settings_get/update`, `est_playbook_list`, `est_setup_status`, `est_setup_step` (17 tools total) |

## Test cases

| ID | Test | Expected |
|---|---|---|
| S3-B01 | Director tables exist, company-scoped, limit can't be negative | Yes |
| S3-B02 | A Sprint 2 (v1) database upgrades to v2 | Data kept |
| S3-D01 | Shipped playbooks load, cover all 3 lanes, each has an approval checkpoint | Yes |
| S3-D02 | 7 kinds of bad playbook | Rejected with a clear message |
| S3-D03 | Wrong file name; a lane missing | Rejected |
| S3-D04 | 11 plain-language requests | Right lane and service each time |
| S3-D05 | Plans attached; module given; unclear request; unknown module | Full takeoff; that module; one question; not_found |
| S3-D06 | Settings defaults and update | $100 limit, booking off; update logged with before/after |
| S3-D07 | 7 bad settings | Rejected |
| S3-D08 | Office tries to change settings | Permission denied |
| S3-D09 | Pressure washing with no surfaces | Director asks; nothing priced |
| S3-D10 | House cleaning required questions | Asks for exactly the missing ones |
| S3-D11 | Office quotes a $100 handyman job | One-tap approval by office; waits for bids |
| S3-D12 | $267.50 cleaning quote by office | Needs owner or reviewer; reviewer approves |
| S3-D13 | Quote using sample prices | Approval blocked until confirm_sample_prices |
| S3-D14 | Limit set to $500, then $0 | One tap, then full approval |
| S3-D15 | New answers after pricing; after approval | Re-priced; locked once approved |
| S3-D16 | Unknown and bad answers | Unknown ignored with a note; bad one asked again |
| S3-D17 | Unclear request, then module chosen | Moves into the quick lane |
| S3-D18 | Roof job; plans attached | Waits, with Phase 3 / Phase 4 message |
| S3-D19 | Status, board, my jobs, other company, audit | Steps listed; scoped; events logged |
| S3-D20 | Old job rev | stale_revision |
| S3-D21 | Reviewer starts a job | Permission denied |
| S3-D22 | Pricing engine broken | Director produces no number of its own |
| S3-W01..W07 | Setup wizard: fresh status, profile, skip, tax+markups merge, price review clears samples, services check, owner only | All pass |
| S3-T01..T03 | MCP tools for Director, settings, playbooks, setup | JSON results; errors as JSON |
| Golden | Generic service: 2 hrs = $165.00; 3 hrs × 2 crew next day + $85.50 materials = $499.50; ½ hr = $100.00 minimum | Exact cents |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 264 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 264 passed in 6.1 s (2026-11-06) |

## Manual check (after running install_estimator.bat and restarting AI-Prowler)

- S3-X01: Ask Claude "customer wants their driveway pressure washed and sealed, about 1,000 sq ft, pretty dirty". Claude should call `est_director_start`, then report the price, say it uses sample prices, and wait for your OK before approving.
- S3-X02: Ask Claude "set my one-tap quote limit to $150". Claude should confirm with you, then call `est_director_settings_update`.

## Self-review checklist (in place of David's review)

- [ ] The Director never calculates a price itself (S3-D22)
- [ ] Every approval goes through a role check and the quick-send limit
- [ ] Every new query filters on company_id
- [ ] Every MCP tool returns JSON text, including errors
- [ ] No floats in money paths

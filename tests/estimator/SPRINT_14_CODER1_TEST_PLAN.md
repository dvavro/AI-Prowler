# Sprint 14 — Coder 1 (Jamie) test plan

**Scope:** The Coder 1 part of planned Sprint 9 that doesn't need the Plan Engine: the **Estimate Runner** (one takeoff task per trade, with dependencies and task states), **Agent Manager** settings per trade, and the **Director's full plan takeoff lane** (it hands the trades to the Runner and takes the approved quantities back). Until David's Plan Engine is built, each trade is measured from the plans by a person or by their AI in chat and handed to the Runner.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. The database upgrades itself to version 7. There are 46 Estimator tools (8 new).

## What was built

**Estimate Runner** (`estimator/runner/`)

- A run makes one task per trade. Task states: queued → running → needs review → completed, or blocked / failed with a reason.
- Drywall, painting and insulation wait for framing when framing is in the same run.
- A trade is measured and submitted (`runner_submit_takeoff`), then a person approves it (`runner_review_task`), optionally correcting a number, or sends it back with a note. **Only approved quantities are priced.**
- A trade that can't be measured fails with the reason (`cannot_measure`). Trades that wait on it are blocked; the other trades carry on. `runner_retry_task` restarts it and unblocks the trades waiting on it.
- The run ends completed (all trades), partial (some) or failed (none). The estimate total is always the sum of the approved trades.
- One open run per estimate; trades can be added to a run (it reopens).
- `est_project_status`: total, each trade's subtotal and three biggest lines, the run's tasks, and the Director job's stage.

**Agent Manager** (`estimator/agent_manager/`, `agent_config_get` / `agent_config_update`)

- Per trade: enabled (off = skipped by the Runner and the Director), confidence threshold (default 85), auto-advance (default off: a submission at or above the threshold is approved without a person), sheet rules (which plan sheets the trade reads, for the Plan Engine later), and default answers the company always uses.
- Owner only. Nothing changes without `confirm=true`, and every change is logged.

**Director full plan takeoff lane**

- `est_director_start(..., has_plans=true)` picks the trades named in the request ("framing, drywall and a new roof"), or asks which trades are in the bid (`est_director_next(job_id, trades=[...])`).
- It starts a Runner run and waits, saying what to measure and what to approve. When the run is settled, it prices the approved trades, leaves out failed ones (with a note), then goes to review → approve → bid like a standard estimate.
- Adding a trade to a plan job adds it to the run.
- The daily briefing counts plan takeoffs in progress, and the watcher reminds you when a takeoff has waited too long.

**Database v7:** `runs`, `takeoff_tasks`, `agent_configs`.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S14-R01 | Tasks and dependencies | Framing and roofing start; drywall and painting wait for framing |
| S14-R02 | Approve framing | Nothing is priced until it's approved; then framing is $1,596.24 and drywall starts |
| S14-R03 | Failed trade | Framing fails → drywall blocked, roofing carries on ($7,817.10, run partial); retry framing → drywall waits again; all done → completed, total = sum of trades |
| S14-R04 | Every trade fails | Run failed, with a retry hint |
| S14-R05 | Bad submissions | Unknown question, nothing to price, missing required answer, trade still waiting, confidence over 100, review before submit: all refused, nothing changes |
| S14-R06 | Send back and correct | A note is required to send back; a reviewer can approve with a corrected number |
| S14-R07 | Roles and companies | Reviewer can't start or submit; office can't review; another company can't see the run |
| S14-R08 | One open run; adding trades | A second run is refused; adding painting reopens a finished run |
| S14-R09 | Approved estimate | Can't start a run (needs a revision) |
| S14-P01/02 | Project status; audit | Subtotals, three headline lines, task counts; every step logged, pricing recorded as the Runner |
| S14-A01 | Agent settings | 15 trades with defaults; changes need confirm; owner only; bad values refused |
| S14-A02 | Turned-off trades | Skipped with a warning; a run of only turned-off trades is refused |
| S14-A03 | Company defaults | Fence height 8 ft and vinyl filled in under the submitted length |
| S14-A04 | Auto-advance | 80% stays for review; no confidence stays for review; 95% is approved automatically |
| S14-D01 | Director plan job end to end | Three trades → takeoff → approvals → priced → review → approved → write bid |
| S14-D02 | Which trades? | Asks when none are named; refuses non-trades; `trades` only on plan jobs |
| S14-D03/04 | Failed trades in a plan job | Left out with a note; if all fail, the job says so |
| S14-D05/06 | Adding and turned-off trades | Added trade joins the run; turned-off trade is left out with a note |
| S14-T01/02 | MCP tools | Runner and Agent Manager tools work through MCP, including JSON and comma lists |
| S14-W01 | Briefing and watcher | Briefing counts the takeoff; watcher reminds after 2 days |
| S3-D01, S3-D18 | Updated | The full takeoff lane is now available; "bid this house" asks which trades |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 546 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 546 passed in 31.1 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy (test_database.py differs only by blank lines, as before) |

## Waiting on other tracks

- Reading the plans automatically (sheet classification, measurements, `takeoff_propose`) waits for David's Plan Engine. The sheet rules are stored now so it can use them.
- API-key agents that do takeoffs unattended come in planned Sprint 10.

## Self-review checklist

- [ ] Nothing is priced until a person (or auto-advance, if the owner turned it on) approves it
- [ ] A failed trade never stops the others
- [ ] Every Runner and Agent Manager change is in the audit log
- [ ] Settings changes need the owner and confirm=true

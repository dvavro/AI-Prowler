# Sprint 9 — Coder 1 (Jamie) test plan

**Scope:** the Director now works on its own while AI-Prowler is open. This is the "unattended loop, stall watcher and daily briefing" part of planned Sprint 10, pulled forward. It runs as a light background check (a few database reads per company), so it also runs in Server mode.

**Still to come from planned Sprints 9–10:**
- the Estimate Runner for full plan takeoffs
- AI agents that use your Claude or Grok API keys
- switching to a backup AI provider when one fails

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should list 38 Estimator tools. Its log should say "Estimator Director watcher started".

## What was built

Every 15 minutes (the `watch_interval_minutes` setting), the Director checks each company and:

| It notices | What happens |
|---|---|
| A sent quote past its follow-up days | One notice: "Follow up on quote Q-0003-1 (…) sent to … 5 days ago" |
| A quote expiring within 3 days | One notice |
| A sent quote past its valid-until date | Marked **expired** (the estimate too) with a notice to revise it. Turn this off with `auto_expire_bids: false` |
| A job waiting on a reviewer or approval past `review_reminder_days` | A reminder, repeated once each period |
| A job that hasn't moved | A "hasn't moved in N days" notice |
| A job due within `due_soon_days` (2), or overdue, before its quote is out | "Due soon" or "overdue" notice |
| It's past `briefing_time` (07:00) | Once a day, the briefing goes to the inbox. If `briefing_channel` is `email` (needs `briefing_email`), it's also emailed through AI-Prowler, and a failed email is retried up to 5 times |

**How it behaves:**
- It never sends anything to a customer and never approves anything.
- Each event makes one notice at most, however often it runs.
- Its actions are logged as `agent:director`.
- Turn it off with `watcher_enabled: false`, or set `ESTIMATOR_WATCHER=off` before starting AI-Prowler.

**New tools:**
- `est_director_inbox`: "what did the Director notice?" `mark_read=true` marks them read.
- `est_director_watch_now`: run the check right away.
- `est_director_watch_status`: on/off, the last run and what it found, the next run, and the briefing settings.

Database v6 adds the watcher settings and the `director_notices` and `director_watch_runs` tables.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S9-W01 | Briefing schedule | Nothing at 6:30; the briefing at 7:05; not twice the same day; again the next day; none when turned off |
| S9-W02 | Emailed briefing | A failed send is recorded and shown in the inbox; retried and delivered on the next check; not sent twice |
| S9-W03 | Follow-up | Not on day 1; one notice on day 5; not repeated |
| S9-W04/05 | Expiry | "Expiring" 2 days before; expired the day after valid-until (bid and estimate); left alone when `auto_expire_bids` is off |
| S9-W06 | Review reminder | On day 2, not day 3, again on day 4 |
| S9-W07 | Stuck job | "hasn't moved in 2 days" |
| S9-W08 | Due dates | Due soon the day before; overdue once after |
| S9-W09 | Sent jobs | No due, stuck or review notices once the quote is out with the customer |
| S9-I01 | Inbox | Unread count; mark read; show all |
| S9-S01 | Settings | Email channel needs an address; bad address and interval refused |
| S9-R01/02 | Scheduling | Runs, skips inside the interval, runs again after it, stops when off; every company checked; a fresh install still checked |
| S9-R03 | Background thread | Off in tests; starts once, runs, stops cleanly |
| S9-A01 | Audit | Auto-expiry logged as `agent:director` |
| S9-T01 | MCP tools | 38 tools; status, check now and inbox over MCP |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 407 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 407 passed in 15.2 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy (test_database.py differs only by blank lines, as before) |

## Still open (not Estimator code)

- Run `install_estimator.bat` and restart AI-Prowler to start the watcher.
- Email delivery needs AI-Prowler's email fixed (a new Gmail app password). Until then, keep the briefing on `chat`, which is the default.

## Self-review checklist

- [ ] The watcher never contacts a customer
- [ ] Running it twice in a row creates nothing new
- [ ] One company's error doesn't stop the others
- [ ] AI-Prowler starts normally even if the watcher can't

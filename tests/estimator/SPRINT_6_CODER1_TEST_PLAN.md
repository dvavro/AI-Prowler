# Sprint 6 — Coder 1 (Jamie) test plan

**Scope:** the everyday tools a service business needs after the first quote: set your own prices by chat, change a quote the customer already has (revisions), see which quotes need a follow-up and get a daily briefing, and make won repeat-service quotes into repeating jobs in AI-Prowler. Also fixes dates so they follow your local time, not UTC.
**Why the change of order:** plan-reading work still waits on David's track, so this sprint stays on Coder 1 work that Jamie can finish alone.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should list 28 Estimator tools and 8 services.

## What was built

| Feature | How you use it in chat | Tools |
|---|---|---|
| Price book | "What are my pressure washing prices?" / "Set driveway washing to 18 cents a square foot" — shows old → new and asks before saving; each change is logged; bids already made keep their prices | `pricebook_get`, `pricebook_update` |
| Revisions | "The customer wants the back patio added" — makes version 2 of a sent or approved quote, keeps the original, voids the old open bid, and goes back to the questions | `est_create_revision`, `est_director_next(revise=true, change_summary=...)` |
| Re-price | After a price change, "re-price that quote" updates a quote that isn't approved yet | `est_director_next(reprice=true)` |
| Follow-ups | "What follow-ups are due?" — sent quotes past the follow-up days (setting, default 3), quotes expiring within 3 days, jobs stuck past the review reminder days | `est_followups_due` |
| Daily briefing | "Give me my estimator briefing" — sent since yesterday, won/lost this week, approvals waiting, ready to send, follow-ups, expiring, out with customers | `est_director_briefing` |
| Repeating jobs | A won weekly/biweekly/monthly quote becomes an AI-Prowler job with Recurrence set and "Weekly service." in the notes | house cleaning (frequency), pool (visits), landscaping (visits), pest control (quarterly/monthly plan) |
| Local dates | Dates on quotes, follow-ups and the briefing use the PC's local time, so a quote sent at 7 pm isn't dated tomorrow | `estimator/core/dates.py` |

Scheduled delivery of the briefing (for example 7:00 am by email) comes with the unattended Director loop in Sprint 10.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S6-P01 | List prices before any quote | Module samples shown as "sample (not used yet)"; 7 pressure-washing samples left |
| S6-P02 | Change two prices | First call asks "$0.15 → $0.18"; with confirm both saved as "yours"; logged as prices_changed |
| S6-P03 | Quote after a price change | New price used: 2,000 sq ft × $0.20 = $400.00 |
| S6-P04 | Bad price changes | Unknown key, "lots", negative, empty → clear errors, nothing saved |
| S6-P05 | Office staff changes prices | Refused (owner or estimator only) |
| S6-R01 | Revise a sent quote | Version 2 draft, same total $267.50, old bid void, original still "sent"; a second revision of the same original refused |
| S6-R02 | Revise a draft / no reason given | Refused with "edit it directly" / "say what's changing" |
| S6-R03 | Director: change answers after sending | Tells you to use revise; with revise the job gets a new estimate and goes back to approval |
| S6-R04 | Director re-price | $150 minimum → $250 after driveway price set to $0.25; no sample-price warning |
| S6-F01 | Follow-ups | None on day 0; due on day 5 with days-since-sent; expiring 2 days before valid-until; follow-up days setting respected; briefing shows "1 quote(s) sent since yesterday ($267.50)" |
| S6-F02 | Briefing counts Director work | 1 waiting for approval, 1 waiting for answers; both stuck after 3 days |
| S6-F03 | Empty briefing | "Nothing waiting. All quiet." |
| S6-F04 | UTC timestamp at 1:30 am UTC | Shown as the local date (Nov 6 in Arizona) |
| S6-C01 | Won biweekly pool quote → job | Job Recurrence "Biweekly", notes start "Biweekly service." |
| S6-C02 | One-time house cleaning → job | No Recurrence |
| S6-C03 | Bad recurrence block in a manifest | Rejected: unknown Recurrence value; question that isn't a choice |
| S6-T01 | MCP tools | 28 tools register; price, briefing, follow-up and revision tools return JSON and needs_confirmation as expected |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 335 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 335 passed in 10.6 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy (test_database.py differs only by blank lines, as before) |

## Still open (not Estimator code)

AI-Prowler's email still needs a new Gmail app password before quote Q-0001-1 ($502.50) can be sent. AI-Prowler on the PC is still running the Sprint 4 install until `install_estimator.bat` is run again.

## Self-review checklist

- [ ] Every price change asks first and is logged
- [ ] Bids already made never change when prices change
- [ ] A revision never edits the original estimate
- [ ] Recurrence values match AI-Prowler's list (One-time, Weekly, Biweekly, Monthly, Bimonthly, Quarterly, Semi-Annually, Annually)
- [ ] Dates shown to people are local

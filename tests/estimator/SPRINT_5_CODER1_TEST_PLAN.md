# Sprint 5 — Coder 1 (Jamie) test plan

**Scope:** five more quick-quote services pulled forward from Phase 6 (window cleaning, pool service, pest control, junk removal, landscaping maintenance), smarter Director triage across 8 services, and a fix so a failed step (like email) is recorded clearly and can be retried.
**Why the change of order:** the next planned sprint is plan-reading work that depends on David's track, which is on hold. These services are Coder 1 work Jamie can finish alone, and they make the service-quote side sellable sooner.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler.

## What was built

| Service | Priced by | Minimum | Sample prices |
|---|---|---|---|
| Window Cleaning | windows × inside/out (1.8) × height (+20% per story), screens, skylights, hard water | $125 | $6/window, $3/screen, $15/skylight, $4/window hard water |
| Pool Service (monthly) | visits (weekly 4 / biweekly 2) × spa (1.3) × size, chemicals, filter clean, one-time cleanup | $100 | $30/visit, $10 chemicals/visit, $75 filter, $100 cleanup unit (green = 2.5) |
| Pest Control (per visit) | service call + home sq ft × level × plan discount, termite inspection, rodent stations, yard | $99 | $60 call, $0.04/sq ft, $95 termite, $35/station, $0.01/sq ft yard |
| Junk Removal | share of a truck (⅛ to full), mattresses, appliances, stairs, same day | $95 | $600 full truck, $25 mattress, $40 appliance, $25/flight, $50 same day |
| Landscaping Maintenance (monthly) | lawn sq ft × visits, edging, hedges, bed weeding, leaf cleanup | $80 | $0.01/sq ft/visit, $10 edging/visit, $1.50/ft hedge, $0.02/sq ft beds, $150 leaves |

Required questions so the Director never prices an empty job: windows (window cleaning), how often (pool), home size (pest), load size (junk), at least one of lawn/hedges/beds (landscaping).

**Director fixes:** a failed step (for example the email server refusing) now leaves the job showing "didn't work: … fix that, then ask me to try again" and is logged as failed; asking again retries. Triage keywords were rebalanced so specific words decide (pool, windows, bedrooms) instead of general words like "clean"; "replace the windows" goes to the windows trade, "gutters" to the general service job, and a bare "cleaning" gets a question.

## Test cases

| ID | Test | Expected |
|---|---|---|
| Golden | 11 new cases (window 2, pool 2, pest 2, junk 3, landscaping 2) | Exact cents, e.g. window 25 × inside/out × 2 stories + extras = $454.00; pool biweekly large + spa + filter + green = $422.50; pest quarterly moderate + termite + 3 stations = $353.75; junk half + extras = $490.00; landscaping weekly full service = $616.00 |
| S5-T | 17 new plain-language requests | Right service each time (window, pool, pest, junk, landscaping, pressure washing for "pool deck pressure washing", house cleaning for "cleaners for a 2 bedroom apartment", general service for gutters, windows trade for "replace the windows") |
| S5-D01 | Email fails during send | Job shows the error and "try again"; step logged failed; retry sends and moves to follow-up |
| Registry | All 8 service modules load with no errors | Yes |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 315 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 315 passed in 8.9 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy |

## Known issue found while testing (not Estimator code)

AI-Prowler's own email can't send right now: Gmail drops the connection at login on both ports 587 and 465 (connect and TLS work). Likely a revoked Gmail app password or an antivirus mail shield. Fix: make a new app password at myaccount.google.com/apppasswords and update AI-Prowler's email settings. Quote Q-0001-1 ($502.50) is approved and waiting; "send quote 1" will send it once email works.

## Self-review checklist

- [ ] Every new module has golden cases and required questions
- [ ] Sample prices are labelled "(sample)"
- [ ] Triage never guesses between two services with equal scores (asks instead)

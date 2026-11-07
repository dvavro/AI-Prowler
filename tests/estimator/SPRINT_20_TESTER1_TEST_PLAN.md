# Sprint 20 — Tester 1 (Jamie) test plan: scripted chat runs and performance

**Scope:** Tester 1 work from planned Sprint 19 (beta preparation):
- whole jobs run only through the AI tools, the way Claude, Grok or Muse do in chat
- a check that every tool answers a bad call with JSON
- a performance check with 300 estimates

Also in this sprint: the quote PDF step tries again with its own Edge profile when the first try makes no PDF. That fixes `test_pdf_with_real_browser` failing when tests run as Administrator with Edge open.

## How to run

```
run_tests_estimate.bat -k sprint20 -s
```
`-s` prints the timings.

## Test cases (tests/estimator/unit/test_sprint20_scenarios.py)

| ID | Scenario | Checks |
|---|---|---|
| S20-C01 | First day by chat | Company, tax, markups saved; a price change asks first, then saves; setup progress shows them done; practice project made and ticks "Try a sample quote" |
| S20-C02 | Driveway call → quote → won → job → real cost | Quick lane; one approval sends the email to the customer; won; converted to a job with a date; real cost recorded with the real margin; history shows it; export works |
| S20-C03 | Roof over the review limit | Standard lane; the Reviewer warns about sample prices; approved and quoted to the customer; a revision (v2, draft) points at the original |
| S20-C04 | Team and moving | Assigned to maria with a note; supplier list imported (asks first); packed up and loaded into a "server" folder |
| S20-C05 | Bad calls | 11 tools given bad input all answer `{"ok": false, "error", "message"}`, never a crash |
| S20-P01 | Performance | 300 priced estimates (roofs and washes), 100 won with real costs; the list, board, history, one estimate, compare, validate, export, pack-up and briefing each take under 2 seconds |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 621 passed, 1 skipped. Timings with 300 estimates: list 0.003 s, board 0.001 s, history 0.001 s, export 0.003 s, pack-up 0.03 s (all far under 2 s) |
| Windows 11, Python 3.11.8 (Jamie's PC) | 630 passed, 0 failed (run with Sprints 18, 19 and 20 together, 2026-11-07). `test_pdf_with_real_browser` passes now |

## Still to do by hand (needs a real AI)

The same scenarios typed in chat with Claude, then Grok, on the deployed AI-Prowler. Note any step where the AI calls the wrong tool or misreads `next_step`.

### Chat check results

| Date | AI | Steps | Result |
|---|---|---|---|
| 2026-11-07 | Claude (Opus 5.5) on the deployed build, through the AI-Prowler connector | setup status, list service trades, practice project create, get estimate, validate, compare history, assign to maria, maria's my work, pack-up, practice delete | All passed. Roof math checked by hand. Reviewer flagged sample prices and the 0% margin (markups not set). Practice job left out of my work and the pack-up as designed; delete asked first and removed the job and the notice. One `est_assign` call lost the connection (Bad Gateway, nothing saved); the retry worked. No emails sent, no prices changed. |
| — | Grok | the five prompts: set up my company; 1200 sq ft driveway wash; Miller roof; assign to Maria; pack up my data | to do (Jamie) |

Notes: assigning a practice job gave a notice but the job was not listed in "my work". Fixed the same day: `est_my_work` now returns practice jobs under `practice`, labelled "🎓 practice (not a real job)", kept apart from real estimates, and the summary says "plus N practice" (S18-P02 checks it; 630 passed on Jamie's PC). Using the practice project adds the roofing and pressure-washing sample prices to the price book; they stay after the delete.

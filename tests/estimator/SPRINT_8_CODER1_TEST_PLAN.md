# Sprint 8 — Coder 1 (Jamie) test plan

**Scope:** the rest of the Phase 3 Coder 1 work (planned Sprint 8):
- good/better/best options
- several trades or services on one estimate, with the bid shown by trade
- company changes to the Director's playbooks (limits and an approval checklist)
- optional site-visit booking (off by default)

Still waiting on David's track: plan reading, takeoff from drawings, two-way linking to measurements, and the Estimates screen.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe" tests\estimator\run_estimator_tests.py
install_estimator.bat
```
Then restart AI-Prowler. It should list 35 Estimator tools.

## What was built

| Feature | How you use it in chat | Tools |
|---|---|---|
| Good/better/best | "Give me good/better/best on that roof." Each option shows the total job price. Nothing on the quote changes until you pick one. The options print on the bid in an "Options" table, with the quoted one marked. Built in for roofing (3-tab / architectural / metal), flooring (laminate / LVP / hardwood), concrete (broom + mesh / broom + rebar / stamped + rebar), window cleaning (outside / inside and out / plus hard water) and pressure washing (wash / wash and seal). Any trade can take your own 2–4 options. | `est_scenarios`, `est_choose_scenario`, Director `scenarios=true`, `choose_scenario=` |
| Customer picks after sending | "They want the metal roof." The Director makes a new version (revise) and switches it to that option. The priced options carry over to the new version. | `est_director_next(revise=true, change_summary=..., choose_scenario="best")` |
| Several trades on one job | "Add window cleaning, 20 windows" or "add new LVP in the kitchen." The trades are priced, reviewed, approved and bid together. Call it again to change a trade's answers; `remove=true` takes it off. Adding a construction trade to a quick quote makes it a standard estimate. | `est_director_add_trade` |
| Bid by trade | The bid template setting `price_detail: "trade_totals"` (or per bid) shows one price per trade with the scope listed. `"lines"` (the default) prices every line and now shows a subtotal for each trade. | `bid_generate(price_detail=...)`, `est_setup_step("bid_template", {...})` |
| Playbook changes | "Skip the reviewer for roofs under $10,000," or "always require a site photo before approving roofs." The owner only, and every change is logged. You can set a review limit for standard estimates, a one-tap limit for quick quotes, and a checklist that must be confirmed (`checklist_done=true`) before approval. | `est_playbook_update`, `est_playbook_list` |
| Site visits | "Book a site visit Thursday at 9." It only works when the owner turns on `calendar_booking_enabled`, which is off by default. It asks first, then creates the customer if needed and a scheduled job ("Site visit (estimate: Roofing)") in AI-Prowler. | `est_director_book_site_visit` |

Database v5 adds the `estimate_scenarios` table and stores a job's extra trades.

## Test cases

| ID | Test | Expected |
|---|---|---|
| S8-O01/02 | Built-in options load; bad options rejected | 5 modules with options; a wrong choice or unknown question stops the module loading |
| S8-O03 | Price roofing options | Better is the current quote at $7,817.10; Good $7,102.32 ($714.78 less); Best is higher; the estimate is unchanged |
| S8-O04 | Choose Best | Total equals the Best price; only Best marked chosen; an unknown option says to price first |
| S8-O05 | Your own options | House cleaning standard vs deep; unknown questions and a single option are refused |
| S8-O06 | Options on the bid | HTML "Options" table with "(quoted above)"; text lists each option |
| S8-O07/08 | Director options | Approval message offers options; `scenarios=true` lists 3; `choose_scenario="good"` re-prices to $7,102.32; after approval the change needs `revise`; after sending, revise + choose switches to metal |
| S8-M01 | Pressure washing + window cleaning | Asks for the window count, then $225 + $120 = $345.00 on one quote |
| S8-M02 | Add concrete to a quick quote | Becomes a standard estimate with a Reviewer check |
| S8-M03 | Add and remove flooring on a roof job | $7,817.10 + $2,471.25, then back to $7,817.10; main trade, missing trade and after-approval changes refused |
| S8-M04 | Bid by trade | Trade totals: Roofing $7,817.10, Flooring $2,471.25, total $10,288.35, no line prices; itemised bid still shows lines |
| S8-P01 | Company review limit | $10,000 limit for standard estimates; the roof job skips the reviewer; the quick lane is unaffected |
| S8-P02 | Required checklist | Approval held until `checklist_done=true`; roofing gets both items, flooring only the "*" item |
| S8-P03 | Playbook rules | Owner only; lane-specific keys; module ids checked; null removes; reset clears; every change logged |
| S8-V01/02 | Site visits | Refused while off; asks first; creates the customer once and a Scheduled job with date and time; bad date/time and missing customer refused |
| S8-T01 | MCP tools | 35 tools; options, add trade, playbook update and site visit work over MCP |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 391 passed |
| Windows 11, Python 3.11.8 (Jamie's PC) | 391 passed in 13.5 s (2026-11-06) |
| File check | All Estimator source files on the PC match the tested copy (test_database.py differs only by blank lines, as before) |

## Still open (not Estimator code)

- Run `install_estimator.bat` and restart AI-Prowler.
- Make a new Gmail app password so quote Q-0001-1 can be sent.
- Site visits show up as scheduled jobs in AI-Prowler. Check they appear in your calendar sync the way you expect.

## Self-review checklist

- [ ] Pricing options never changes the estimate
- [ ] Choosing an option after approval always needs a revision
- [ ] Nothing reaches a customer or creates AI-Prowler records without a yes
- [ ] Playbook changes can't remove the approval checkpoint

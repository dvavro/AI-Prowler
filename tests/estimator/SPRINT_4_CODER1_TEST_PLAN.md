# Sprint 4 — Coder 1 (Jamie) test plan

**Scope:** bids (generate, preview, send, status, convert to job), links to AI-Prowler's customers, quotes, jobs and email, and the Director running a quick quote from request to signed job.
**Team note:** David (Coder 2) is still unavailable; Jamie self-reviews with the checklist below. The Bids and Jobs board *screens* are Coder 2 work and stay on hold; everything works through chat.

## How to run

```
cd C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler
python tests\estimator\run_estimator_tests.py
```

Then run `install_estimator.bat` and restart AI-Prowler to use it in chat.

## What was built

| Area | File | What it does |
|---|---|---|
| Database v3 | `estimator/database/migrations.py` | `bids` table (frozen snapshot, number, status, files, sent info, AI-Prowler quote and job ids); customer on Director jobs |
| AI-Prowler link | `estimator/integrations/host.py` | Calls AI-Prowler's own `create_customer`, `create_quote`, `create_job`, `send_email`, so AI-Prowler's rules still apply. Clear error if they aren't available |
| Bid layout | `estimator/bids/render.py` | Branded HTML quote (company, customer, scope, line prices, tax, total, terms, signature line). PDF printed by Microsoft Edge (built into Windows 11) — nothing to install. Customers never see costs or margins |
| Bids | `estimator/bids/service.py` | Generate (approved estimates only, prices frozen, Q-0001-1, Q-0001-2…), preview, send (needs confirm; PDF attached when AI-Prowler allows, otherwise quote in the email body), viewed/won/lost/expired/void, convert to job (needs confirm: customer if new → Approved quote → job) |
| Director | `estimator/director/engine.py` | Write-and-send stage (makes the bid, asks for the email if missing, sends on the user's word) and follow-up stage (follow-up date from settings, won → make it a job, lost → close). Approve and send can be one tap |
| MCP tools | `estimator/mcp_tools/est_tools.py` | `bid_generate`, `bid_preview`, `bid_send`, `bid_set_status`, `bid_convert_to_job`, `bid_list`; Director tools take customer, send, outcome, convert, service date (23 tools total) |

## Test cases

| ID | Test | Expected |
|---|---|---|
| S4-B01 | Bid from a draft estimate; unknown estimate | Refused ("approve first"); not found |
| S4-B02 | Generate; price change afterwards; second bid | $267.50 frozen; numbered Q-…-1 then -2 |
| S4-B03 | Bid with markups and 8% tax | Lines + tax + adjustments = total; tax shown separately; no costs or "overhead" in the HTML |
| S4-B04 | Bid template terms and valid days | Used; 999 days refused |
| S4-B05 | Send without an address; without confirm | Asks for email; needs_confirmation, nothing sent |
| S4-B06 | Send | Email has subject with number and total, HTML body, message; bid and estimate marked sent |
| S4-B07 | AI-Prowler refuses the PDF attachment | Sent again without it, with a warning |
| S4-B08 | Email not configured | Clear error; bid stays draft |
| S4-B09 | Viewed → lost; then won; set "sent" by hand | Estimate follows to lost; won refused; invalid |
| S4-B10 | Convert a sent bid | Asks first; then creates CUST, Approved QTE ($267.50) and JOB with date; bid won; estimate linked; second convert does nothing |
| S4-B11 | Convert for an existing customer | No new customer; uses CUST-0042 |
| S4-B12 | Convert a draft; no customer; bad date | Refused each time |
| S4-B13 | AI-Prowler tools missing | host_unavailable |
| S4-B14 | Bad email; unknown customer field; reviewer makes a bid | Refused |
| S4-B15 | Dollars text; list and company scoping | "267.50", "0.05", "-1.50"; scoped |
| S4-B16 | Reading AI-Prowler ids | NEW_CUST_ID line and plain JOB-#### both read |
| S4-B17 | Real PDF with Edge/Chrome | Valid PDF (ran on Windows with Edge and on Linux with Chrome) |
| S4-D01 | Office: handyman request → one tap approve + send → won → convert with date | Email sent, follow-up date shown, job created, Director job done |
| S4-D02 | No email on file | Asks; send refused politely; sends after email given |
| S4-D03 | Customer says no | Bid and estimate lost; job closed; bad outcome refused |
| S4-D04 | Reviewer approves a large quote | Waits for staff to send; office sends |
| S4-T01 | Bid tools through MCP | Confirmations as needs_confirmation; job created |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 (Chrome for PDF) | 286 passed |
| Windows 11, Python 3.11.8 (Jamie's PC, Edge for PDF) | 286 passed in 9.2 s (2026-11-06) |
| File check | Every Estimator file on the PC matches the tested copy (short SHA-256 compare) |

## Manual checks (after install_estimator.bat and an AI-Prowler restart)

- S4-X01: In Claude: "Quote a 1,000 sq ft driveway pressure wash for Jane Smith, jane@yourmail.com." Approve, then say "send it". Check the email arrives with the quote, and the PDF if AI-Prowler allowed the attachment.
- S4-X02: Say "Jane accepted, make it a job for next Friday." Check the customer, quote and job appear in the AI-Prowler Jobs app.

## Self-review checklist (in place of David's review)

- [ ] Nothing reaches a customer or creates AI-Prowler records without an explicit yes
- [ ] Bids never show costs, overhead or profit
- [ ] Sent bids never change when prices change
- [ ] All writes to AI-Prowler's job data go through AI-Prowler's own tools
- [ ] No floats in money paths (dollars text is made from integer cents)

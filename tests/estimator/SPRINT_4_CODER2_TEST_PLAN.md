# Sprint 4 — Coder 2 (David) test plan: Bids screen, Jobs board, how-to guides

**Scope:** The Coder 2 Sprint 4 row is "Bids screen; sample service quote in the wizard; how-to guide panel (first guides); Jobs board screen (quick lane)". The web app parts are built here. The **sample service quote in the setup wizard** belongs to the desktop wizard in the 🏗 Estimator tab, which Jamie built (his Sprint 16), so it's left for him (see Notes).

## How to run

```
run_tests_estimator.bat coder2
deploy_to_install.bat            then restart AI-Prowler
```
Open the web app: Dashboard → **📋 Jobs board**, **📨 Bids** and **❓ Help** in the left menu. No new tools or tables.

## What was built

**Quick quote → Director job.** A new quick estimate (`POST /quick` with no estimate_id) is now started with `est_director_start` (quick quote lane), so it lands on the Jobs board and the page carries on with **Next: approve and send →**. The response is the same estimate as before plus `job` and `next_step`. Quick answers on an existing project still use `est_quick_answer` and don't make a job.

**Jobs board** (`#/jobs`; `GET /jobs?mine=&done=` → `est_jobs_board`): jobs grouped by lane, with each job's step, who it's waiting on, and when it was updated. There are Mine only and Show finished filters, and a ⚡ New quick quote button for the quoting roles. It updates live.

**Job page** (`#/jobs/<id>`; `GET /jobs/<id>` → `est_job_status` plus the estimate and its latest bid; `POST /jobs/<id>/next` → `est_director_next`). The Next step box shows what the Director says and the controls for it:
- the Director's questions (the same form as the quick estimate) or a choice of service,
- ✓ Approve, with the checklist and "Use the sample prices anyway" boxes when they apply. The button is greyed out for roles that can't approve that amount.
- Sign off the review (owner, reviewer),
- 📨 Send the quote… with the customer's email,
- 👍 Customer said yes / Customer said no,
- Make it a job in AI-Prowler…, with the customer name and service date.
- The Director's notes (e.g. "Not approved: it still uses sample prices") show on top after each step.

**Safety on the job page.** In the Director, `send=true` emails the customer and `convert=true` creates the customer, quote and job straight away. So the web API asks first: without `confirm: true` it returns `needs_confirmation` and a question ("Email the $172.50 quote to jane@example.com?", "Turn this … quote into a job for 2026-12-01? …"). Only **Yes** repeats the step with confirm. Other rules:
- Only known fields are accepted.
- Flags must be literal true or false.
- `rev` catches a job changed in chat (409).

**Bids screen** (`#/bids`, `#/bids/<id>`; owner, estimator, office):
- **List** (`bid_list`), with a status filter.
- **Preview** (`bid_preview`). The quote shows as the customer sees it: its own HTML in a sandboxed frame from `/bids/<id>/file?kind=html`. That file is served with CSP `default-src 'none'; sandbox`, so no scripts and nothing from outside. There's also a plain-text copy.
- **PDF download** (`kind=pdf`, as an attachment).
- **Actions:**
  - Send (`bid_send`, asks first).
  - Won / Lost / Viewed / Void (`bid_set_status`).
  - Make it a job (`bid_convert_to_job`, asks first, with the customer name and service date).
- **Paths.** Files are served only from inside the Estimator's data folder. Local file paths (`html_path`, `pdf_path`) are never sent to the browser; `has_pdf` says whether there's a PDF.
- **Inside the Jobs app** (Bearer token), a frame or plain link can't sign in. The page shows the text copy and fetches the PDF with the token.

**Help screen** (`#/help`, `#/help/<guide>`; every role):
- **Guides.** Five first how-to guides as Markdown in `estimator/ui/help/guides/`:
  - quote a service job in 2 minutes
  - send and follow up a quote
  - turn a won quote into a job
  - set up your price book
  - use the Jobs board
- **Listing and search.** They're listed and searchable (`/help/guides?q=`), and filtered per screen (`?screen=`).
- **"?" button.** Each new screen and the Quick estimate and Price Book screens have a "?" that opens their guides.
- **Display.** Guides are drawn with a small text-only Markdown reader (never as HTML).

## Test cases (tests/estimator/webapp/test_web_sprint4.py)

| ID | Test | Checks |
|---|---|---|
| C2S4-Q01 | Quick → job | new quick quote is a quick-lane Director job on the board; title "<service> – <address>"; sample warning |
| C2S4-Q02 | Existing project | quick answers on a project don't make a job |
| C2S4-J01 | Start | `POST /jobs` from words; nothing to go on → 400 |
| C2S4-J02 | Roles | reviewer can't start but sees the board |
| C2S4-J03 | Filters | mine / done |
| C2S4-J04 | Job page | next step, estimate, triage step logged; unknown job 404 |
| C2S4-J05 | Approve | sample prices need the extra OK; then approved and a bid is made |
| C2S4-J06 | No paths | no `html_path`/`pdf_path`/data folder in what the browser gets |
| C2S4-J07 | Send | asks first with who and how much; nothing emailed until yes; then sent |
| C2S4-J08 | Won → job | convert asks first (with the date); then one job with the service date; bid shows JOB-0001 |
| C2S4-J09 | Lost | bid lost |
| C2S4-J10 | Bad input | "yes"/1 flags, unknown field, answers/customer/rev types; outcome must be won or lost |
| C2S4-J11 | Stale | old rev → 409 |
| C2S4-J12 | Field | sees the job, never costs |
| C2S4-J13 | CSRF | no app header → refused |
| C2S4-B01 | Bids list | status filter, bad status 400, preview text and lines, no paths |
| C2S4-B02 | Roles | owner, estimator, office 200; reviewer, field 403; another company 404 |
| C2S4-B03 | HTML file | served with sandbox CSP and nosniff |
| C2S4-B04 | PDF | missing PDF explained; PDF served as an attachment; bad kind 400 |
| C2S4-B05 | Outside folder | a bid path outside the data folder is never served |
| C2S4-B06 | Send | asks first (AI wording cut off); then sent |
| C2S4-B07 | Status, convert | status needs a value; viewed; convert asks, then once only |
| C2S4-H01 | Guides | five guides; open one (no meta comment); unknown 404; no path tricks |
| C2S4-H02 | Search | "send a quote" → send guide; "supplier csv" → price book; screen filter |
| C2S4-H03 | Roles | every role reads Help |
| C2S4-H04 | Guides vs page | each guide belongs to a real screen or page; every button a guide names is really on the page |
| C2S4-W01 | Nav and page | Bids and Help ready; new pages and tools listed; page has the new calls; no innerHTML/eval |

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), Coder 2 track | 221 passed (40 new) (2026-11-08) |

## Manual checks

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | Dashboard → ⚡ Quick estimate → pressure washing 1000 sq ft → Price it | price, sample warning, **Next: approve and send →** | |
| M2 | Click it → ✓ Approve without the sample box | note "Not approved: it still uses sample prices" | |
| M3 | Tick "Use the sample prices anyway" → ✓ Approve | approved; quote made; Send to box shows | |
| M4 | Your own email → 📨 Send the quote… | question with your email and the total; **Cancel** sends nothing; **Yes** emails it (check the inbox) | |
| M5 | 👍 Customer said yes → name + date → Make it a job… → Yes | customer, quote and job created; job visible in the Jobs app | |
| M6 | 📋 Jobs board | the job under Quick quotes; "Show finished" shows it when done; a job started in chat shows up without reloading | |
| M7 | 📨 Bids → open the quote | quote looks right in the frame; PDF downloads (if Edge/Chrome made one); plain-text copy | |
| M8 | Jobs app (port 8000) → Estimates tab → a quote | text copy shown instead of the frame; PDF downloads | |
| M9 | ❓ Help → search "send quote"; "?" on the Jobs board | right guide first; "?" shows the Jobs board guides | |
| M10 | Sign in as field (test session) | no Bids in the menu; job pages show prices, never costs | |

## Notes for Jamie

- **Sample service quote in the setup wizard** (this row) is in your desktop wizard (Estimator tab, Sprint 16). The web app's Quick estimate and the "Quote a service job" guide cover the same thing, so the wizard's "Try it" step could open `#/quick?module=pressure_washing`.
- **`how_to_estimate` and the guides.** The spec says the tool also returns the how-to guides "by topic or question". The guides and a search are now in `estimator/ui/help` (`list_guides()`, `get_guide(id)`, `search(question)`). Could `how_to_estimate(topic=...)` use them, so chat and the Help screen give the same steps? I didn't change your tool.
- **Field and sending.** `bids.send` lets field send quotes (`QUICK_ROLES`), but my nav permission `send_bids` says no and the Bids screen is owner/estimator/office. On the job page, field can still send through the Director (your rule). Is that what you want?
- **Director send/convert don't ask.** `est_director_next(send=true)` emails straight away, and `convert=true` creates records straight away. The web page asks first; in chat it's up to the AI. Maybe the tool should ask too?
- **Director title.** `director.start` cuts the project title to 80 characters (from the request's first line). Quick quotes with long addresses get a shortened name.
- No changes to your files this sprint.

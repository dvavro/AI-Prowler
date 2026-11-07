# AI-Prowler Agents — GUI E2E Test Spec (human mode, $0 API cost)

Phase 1 deliverable of the plan "AI-Prowler Agents — No-Cost GUI Test Plan" (3 Nov 2026).
Status: **Phase 1 written; Phase 2a harness and 2b settings and review screens mostly written** (see §13).

Decisions taken (3 Nov 2026, David):
- Sandbox only — every test runs on throwaway sandbox servers on the dev PC, never on the real Local or Server install.
- Stand-in AI — approved. *Phase 1 finding:* no product change is needed (see §1.3); the stand-in is wired in inside
  the sandbox process, the way `tests/gui_jobs_timemachine/tm_server.py` already swaps out email and SMS.
- Matrix depth — 5 sections × 4 states × 2 editions, plus the named cross combinations (§5).
- Server edition — a server-mode sandbox on the dev PC; one check on the real server box at sign-off (Phase 4).

---

## 0. Conventions

| Item | Rule |
| --- | --- |
| Test IDs | `AG-<area>-<nn>`. Areas: `ENV` harness, `KEY` Agent API Key, `SD` Service Desk agent settings, `BK` Booking settings, `JB` Jobs settings, `RT` Route flow settings, `HR` HR settings, `RV` review screens, `MX` on/off/practice matrix, `X` cross-agent, `GR` guardrails, `CP` customer pages, `WF` workflows, `SAFE` cost and leftovers |
| Editions | `S` = Solo sandbox (personal edition, owner token) · `B` = Business sandbox (server edition). A test marked `S+B` runs in both. |
| Human mode | Default. Browser visible, Playwright `slow_mo` 300 ms, typing 55 ms per key; the Tk window visible with a 400 ms pause after each step. `--fast` = headless, no pauses. |
| Test data | Every record the tests create carries `ZAG-` in its ID, name or title. |
| "Refused" | The value is not saved, a plain message is shown (GUI: message box; PWA: toast or inline error), and a reload shows the old value. |
| "Saved" | The value is shown after a desktop restart of the panel (rebuild) or a PWA page reload, and `get_settings()` returns it. |
| Outbox | Everything the sandbox "sends" (email, SMS, WhatsApp) — read with `GET /outbox` on the control port. |
| AI log | Every request the stand-in AI received — `GET /ai-calls` on the control port. |

Run:

```
run_tests.bat agents-gui                 all suites, human mode, both editions
run_tests.bat agents-gui -k settings     one suite (settings / matrix / guardrails / customer / workflows)
run_tests.bat agents-gui --fast          headless, no pauses
```

`agents-gui` is excluded from the normal regression run.

---

## 1. Harness (Phase 2a)

### 1.1 Sandbox server — `ag_server.py`

Built on `tests/gui_jobs_timemachine/tm_server.py` (reuse its `_prepare_home`, `_block_outbound`, `_patch_app`,
clock and outbox; import rather than copy). One process per edition:

```
python ag_server.py --home <temp> --port <p> --control-port <c> --token <t> --date 2026-11-09 --mode personal|server
```

Additions over `tm_server.py`:

1. **Stand-in AI.** Replace `desk_agent_providers._post` in-process with `ai_standin.answer(url, body, headers)`.
   It records the request (agent kind, stage, model, full prompt) and returns a Claude- or Grok-shaped reply from
   the active script. No product code changes.
2. **urllib guard.** `tm_server.py` blocks `requests` only; the agent providers use `urllib.request.urlopen`.
   Wrap `urllib.request.urlopen` the same way: any host outside `ALLOWED_HOSTS` is recorded as `blocked_http` and
   raises. (This also closes the same gap in the existing time-machine suites — see §11.)
3. **API keys.** Save a fake Claude key `sk-ant-ZAG-standin` and a fake Grok key `xai-ZAG-standin` in the sandbox so
   `claude_api` and `grok_api` runners are allowed.
4. **Agent runs at the test's command.** The automatic agent runner thread is captured, not started (like
   `desk_scheduler` today). `POST /run {"job": "agents"}` does one full agent pass (scan + work the queue) at the
   simulated time; `{"job": "agents", "force": true}` ignores working hours (= the app's Run now).
5. **Control API additions:** `GET /ai-calls`, `POST /ai-script {"name": …}`, `POST /ai-reset`, `GET /agent-db`
   (row counts and the last 50 rows of `agent_queue`, `agent_proposals` and `agent_runs` from all three agent
   databases).

### 1.2 Chat runner path (Solo only)

For `chat_only`, the test plays the chat AI through the real MCP tools on the sandbox:
`desk_agent_next` → script → `desk_agent_submit(item_id, actions, summary)`. Same scripts as the stand-in
(§1.4), so a story can run on either runner.

### 1.3 Why no product change is needed

The sandbox server is our own process wrapping `ai_prowler_mcp.py`, so it can replace `_post` before the app
starts. The approved test-only switch in `desk_agent_providers.py` is therefore **not** added. If Phase 2 finds a
path that bypasses `_post` (for example the HR agent calling the API another way), that path gets the same
in-process replacement; a product change is the last resort and would come back to David first.

### 1.4 Stand-in AI scripts — `ai_standin.py`

A script is a list of rules: `match` (agent kind, stage, and optionally a ref such as `ZAG-T-3`) → `reply`
(the actions the agent should return). Each action names one of the stage's allowed actions
(`desk_agent.ALLOWED[(kind, stage)]`) with `confidence`, `why`, and its fields.

Script families:

| Family | Purpose |
| --- | --- |
| `good` | Believable answers with confidence 0.9 — the normal path |
| `low` | Same answers with confidence 0.55 (below the 0.6 minimum) and 0.75 (below the 0.8 booking-confirm minimum) |
| `messy` | Missing fields, an unknown action, an action not allowed in the stage, a reply over 1,200 characters, a reply with a link that isn't allowed, bad JSON, an empty reply, a refusal |
| `slow` / `error` | A timeout, an HTTP 429 and an HTTP 500 from the "API" |

### 1.5 Desktop GUI driver — `tk_driver.py`

In-process Tk, the same way `tests/unit/test_agent_api_keys_gui.py` builds `build_agent_key_section` — but the
window is shown, sized 1100×800, and every set/click is followed by `update()` and a 400 ms pause in human mode.
Helpers: `find(label)`, `set_entry`, `set_spin`, `pick(combo, label)`, `tick`, `click(button text)`,
`messagebox` capture (records the text, answers OK). The panel under test points at the sandbox's databases
through `AIPROWLER_TEST_STATE_DIR` (no real `~/.ai-prowler` access — guarded by `installed_files_guard.py`).

### 1.6 Seed business — `seed_business.py`

"ZAG Blue Wave Window Cleaning", Daytona area. Created through the app's own MCP tools (never raw SQL):

| Kind | Records |
| --- | --- |
| Customers | ZAG-C-1 … ZAG-C-6 (one opted out of messages; one outside the service area) |
| Services | 8 — 5 bookable, 3 outdoor (pressure wash, gutter, exterior windows) |
| Products | 2 (squeegee kit, gift card), max quantity per order 5 |
| Jobs | 10 across the simulated week Mon 9 – Fri 13 Nov 2026: 2 fixed-time (Hard), 1 today, 2 unscheduled, 1 completed with time logged, 1 completed with no time logged |
| Quotes | 1 approved, 1 open 6 days (past the 5-day follow-up) |
| Invoices | 1 unpaid 8 days old, 1 for $1,250 (over the $1,000 default max) |
| Crews | 2 (Cris Crew, Dee Crew) |
| Employees (B only) | ZAG-E-1 (PTO balance 40 h), ZAG-E-2 (balance 4 h), ZAG-E-3 (licence expiring in 30 days); HR Admin user; a manager over ZAG-E-1 |

### 1.7 Harness tests

| ID | Ed. | Check | Expected |
| --- | --- | --- | --- |
| AG-ENV-01 | S+B | Sandbox starts | Control port answers `/state`; the marker file exists; refuses to start in a non-empty, non-sandbox folder |
| AG-ENV-02 | S+B | Real home untouched | `~/.ai-prowler` modification times identical before and after the run |
| AG-ENV-03 | S+B | Network guard | A test call to `https://api.anthropic.com/v1/messages` through `urllib` and through `requests` is recorded as `blocked_http` and raises |
| AG-ENV-04 | S+B | Stand-in wired | A Service Desk ticket with `claude_api` produces exactly 1 AI-log entry and 0 `blocked_http` entries |
| AG-ENV-05 | S | Chat path | `desk_agent_next` returns the queued item; `desk_agent_submit` with the `good` script creates the proposal |
| AG-ENV-06 | S+B | Clock | `POST /clock` to Fri 13 Nov 16:00 changes `datetime.now()` inside the app |
| AG-ENV-07 | S+B | Seed | Every record in §1.6 exists; every one carries `ZAG-` |
| AG-ENV-08 | S+B | Smoke, one per agent | Service Desk, Bookings, Jobs, Route flow and HR (B) each make one practice proposal from one trigger |

---

## 2. Desktop GUI and PWA settings (Phase 2b)

Every field gets the seven standard checks from the plan (default, valid, edges, bad input, same in both places,
effect, who can see it). The tables list what is specific to each field. Limits are from
`desk_agent_settings.py` (RANGES, validate, validate_jb, validate_hr) as of 3 Nov 2026.

### 2.1 Agent API Key (desktop, Small Business tab) — S+B

| ID | Field | Valid | Refused / edge | Effect |
| --- | --- | --- | --- | --- |
| AG-KEY-01 | Claude API key | Save, shows "Saved", masked | Blank save; remove → "Not saved" | Runner `claude_api` allowed only when saved |
| AG-KEY-02 | Grok API key | As above | As above | Runner `grok_api` allowed only when saved |
| AG-KEY-03 | Claude model — complex & customer | Each listed model | — | Stand-in AI log shows that model on a customer reply |
| AG-KEY-04 | Claude model — internal steps | Each listed model | — | AI log shows it on intake / check stages |
| AG-KEY-05 | Grok model | Each listed model | — | AI log shows it with `grok_api` |
| AG-KEY-06 | Monthly budget $ | 0, 20, 10000 | −1, 10001, "abc", 12.5 | Spent line shows "of $<budget>" |
| AG-KEY-07 | Alert level % | 0, 80, 100 | −1, 101 | — |
| AG-KEY-08 | Spent this month line | — | — | After a stand-in run tagged as test spend, the line still shows $0.00; with the refresh interval set to 1 s for the test, a recorded run appears without any click |
| AG-KEY-09 | Cost analysis popup | Opens; rows for each model, AI tasks, total | Close; reopen | Closing refreshes the forecast line |

### 2.2 Service Desk agent — desktop and `/desk/` → Settings → 🤖 Agent

| ID | Field | Valid | Refused / edge | Effect |
| --- | --- | --- | --- | --- |
| AG-SD-01 | Agent on | On / off | — | 🤖 Agent tab shows for owner and manager only when on |
| AG-SD-02 | Practice mode | On (default) / off | — | §5 |
| AG-SD-03 | Which AI runs it | S: Chat, Claude API, Grok API | B: Chat refused with the "chat isn't allowed on a server" message; the removed Claude CLI value refused | AI log / chat queue |
| AG-SD-04 | 5 stage modes | Off, Suggest, Auto each | — | Flow diagram redraws; §5 |
| AG-SD-05 | Name | "", "Sam", "O'Brien-Lee", 40 letters | 41 letters; "Sam2"; "-Sam"; "Sam!" | Customer reply shows "Sam · Virtual assistant" |
| AG-SD-06 | Shown as | Virtual / AI / Digital assistant | Any other text (API call) | Label on every customer message; cannot be blank |
| AG-SD-07 | Photo | JPG, PNG, WebP, HEIC; 8 MB exactly | 8 MB + 1 byte; a .txt renamed .jpg; an empty file | Shown on the customer ticket page, 256 px square; Remove photo clears it |
| AG-SD-08 | Sign-off | "", "— Sam, Blue Wave", 80 characters | 81 characters | Blank = business name at the end of replies |
| AG-SD-09 | Works from / until | 0–24, 9–17, 23–24 | 17–9, 5–5, 24–24, −1, 25 | Automatic runs only inside the hours (§6 AG-GR-30) |
| AG-SD-10 | Monthly AI budget $ | 0, 10000 | −1, 10001 | Same value as AG-KEY-06 (shared) |
| AG-SD-11 | Nudge when a customer waits (hours) | 1, 4, 168 | 0, 169, "x" | Follow-through timing (WF2) |
| AG-SD-12 | Add the request-service link | On / off | — | Link in first replies only when on (WF1) |
| AG-SD-13 | Server lock | — | B: PWA Save and photo upload/delete refused with the server-lock message | B: the same change made on the desktop shows in the PWA after reload |

### 2.3 Booking & scheduling — desktop and `/desk/` → Settings

| ID | Field | Valid | Refused / edge | Effect |
| --- | --- | --- | --- | --- |
| AG-BK-01 | Booking & scheduling on | On / off | — | Works only with Agent on (X2) |
| AG-BK-02 | Practice for bookings | On / off | — | Independent of the ticket practice switch (X3) |
| AG-BK-03 | 6 stage modes | Off, Suggest, Auto each | — | Flow diagram redraws |
| AG-BK-04 | Let the agent confirm bookings | On / off | — | Confirms only with Decide on Auto and practice off (AG-GR-10…18) |
| AG-BK-05 | At most this many a day | 1, 5, 50 | 0, 51 | Daily confirm cap (AG-GR-16) |
| AG-BK-06 | Weather check for outdoor services | On / off | — | WF5 |
| AG-BK-07 | Check hour | 0, 16, 23 | −1, 24 | Tomorrow's check runs at that simulated hour |

### 2.4 Jobs agent — desktop and `/jobs/` → 🤖 Agent → settings

| ID | Field | Valid | Refused / edge | Effect |
| --- | --- | --- | --- | --- |
| AG-JB-01 | Jobs agent on | On / off | — | Works with Service Desk off (X4) |
| AG-JB-02 | Practice for jobs | On / off | — | — |
| AG-JB-03 | 8 stage modes | Off, Suggest, Auto (On site defaults to Auto) | — | Jobs flow diagram redraws; the "redraw for unsaved choices" call updates it before Save |
| AG-JB-04 | Let the agent send invoices | On / off | — | AG-GR-20…27 |
| AG-JB-05 | Invoice max $ | 0, 1000, 100000 | −1, 100001, 12.50 ("must be a whole number"), "abc" | — |
| AG-JB-06 | Invoices per day | 1, 10, 100 | 0, 101 | — |
| AG-JB-07 | Quote follow-up days | 1, 5, 60 | 0, 61 | WF6 |
| AG-JB-08 | Reminder days | "7", "7, 14, 30", "1, 120" | "30, 7" (not smallest first), "7, 7" (repeat), "7, 14, 30, 60" (4 days), "0", "121", "" , "7 x" | WF8 reminder dates |
| AG-JB-09 | Weather for outdoor jobs | On / off | — | WF7 |
| AG-JB-10 | Prep hour | 0, 16, 23 | −1, 24 | WF7 |
| AG-JB-11 | Who can change it | S: owner in the Jobs app. B: owner at the server PC (desktop); the Jobs app settings are read-only or refused for everyone | Manager and crew: no settings | — |

### 2.5 Route flow — desktop and `/jobs/` → 🤖 Agent → settings

| ID | Field | Valid | Refused / edge | Effect |
| --- | --- | --- | --- | --- |
| AG-RT-01 | Route flow on | On / off | — | Works whether the Jobs agent is on or off |
| AG-RT-02 | Practice for routes | On / off | — | Independent of jobs practice (X5, X6) |
| AG-RT-03 | 5 stage modes | Off, Suggest, Auto | — | Route diagram redraws |
| AG-RT-04 | Route scope | Each day / The whole week | — | Diagram and WF9 |
| AG-RT-05 | Sort weekday | Each of Monday … Sunday | 7 (API call) | WF9 sorts on that simulated day |
| AG-RT-06 | Send hour | 0, 18, 23 | −1, 24 | Crews get routes at that simulated hour |

### 2.6 HR agent — desktop and `/hr_admin/` → 🤖 Agent — B (and S where HR is enabled)

| ID | Field | Valid | Refused / edge | Effect |
| --- | --- | --- | --- | --- |
| AG-HR-01 | HR agent on | On / off | — | — |
| AG-HR-02 | Practice for HR | On / off | — | — |
| AG-HR-03 | 9 stage modes | Off, Suggest, Auto (Time clock defaults to Auto) | — | HR diagram redraws |
| AG-HR-04 | Runner | Claude API, Grok API | Chat is not offered; an API call with `chat_only` is refused | X7 |
| AG-HR-05 | Let the agent approve time off | On / off | — | AG-GR-40…51 |
| AG-HR-06 | Up to (days) | 1, 2, 10 | 0, 11 | — |
| AG-HR-07 | Notice (days) | 0, 14, 90 | −1, 91 | — |
| AG-HR-08 | Most off a day | 1, 20 | 0, 21 | — |
| AG-HR-09 | Approvals a day | 1, 5, 50 | 0, 51 | — |
| AG-HR-10 | Reviewers | Owner and HR Admin / …and managers | — | AG-RV-06 |
| AG-HR-11 | Incident access | Type only / Read the report | — | WF12 (AI log) |
| AG-HR-12 | Overtime warning (hours) | 20, 36, 60 | 19, 61 | Time clock flag |
| AG-HR-13 | Message hours (stored as `agent_hr_quiet_hours`) | "8-18", "0-24", "7-8" | "18-8" (start must be before end), "8-8", "8", "8-25" | Messages to employees go out only between these hours |
| AG-HR-14 | Expiry warning days | "60, 30, 7", "30", "365" | "7, 30" (must be largest first), "30, 30", "400", 4 values, "" | ZAG-E-3 warnings on those days |
| AG-HR-15 | Acknowledge sensitive messages | On / off | — | WF11 |
| AG-HR-16 | Unknown setting | — | `POST /agent/settings {"agent_hr_bogus": 1}` refused | — |
| AG-HR-17 | Who can see it | HR Admin only = owner and manager (`can_manage_hr`) | Staff, field crew, employee: 403 `admin_only` | — |

### 2.7 Same value in both places

| ID | Check |
| --- | --- |
| AG-SYNC-01 | S: change each Service Desk and Booking field in the PWA → desktop panel shows it after rebuild |
| AG-SYNC-02 | S+B: change each field on the desktop → PWA shows it after reload |
| AG-SYNC-03 | The shared runner and budget, changed in one section, show in every section (`sync_shared`) |

---

## 3. Review screens — every PWA with a 🤖 Agent tab (Phase 2b)

| ID | Ed. | Screen | Steps | Expected |
| --- | --- | --- | --- | --- |
| AG-RV-01 | S+B | `/desk/` Agent tab | Owner opens with 2 pending, 2 practice | Two lists; pending show the hold reason; practice show 👍/👎 |
| AG-RV-02 | S+B | `/desk/` | Approve a reply | Status applied; the customer gets it in the outbox; history shows 🤖 and who approved |
| AG-RV-03 | S+B | `/desk/` | Edit the reply text, then approve | The edited text is what is sent |
| AG-RV-04 | S+B | `/desk/` | Reject | Status rejected; nothing sent |
| AG-RV-05 | S+B | `/desk/` | 👍 and 👎 on practice items | Feedback stored; nothing applied |
| AG-RV-06 | B | All three | Staff and crew sign in | No 🤖 Agent tab; the API refuses review with "only the owner or a manager" |
| AG-RV-07 | S+B | `/desk/` | Run now | "Started" toast; after the pass the lists update on ↻ |
| AG-RV-08 | S+B | `/desk/` booking card | A booking with a suggestion | "🤖 suggests …" line with Use this; "(practice)" and 👍/👎 in practice |
| AG-RV-09 | S+B | `/jobs/` Agent tab | Same as RV-01…05 and RV-07 for a jobs proposal | Same; status line shows waiting and pending counts |
| AG-RV-10 | B | `/hr_admin/` Agent tab | Status, pending, practice, Run now, approve, reject | Same; badge count on the sidebar |
| AG-RV-11 | B | `/hr_admin/` time-off rows | A request with a recommendation | "🤖 suggests approve/deny — why" line; "(practice)" in practice |
| AG-RV-12 | B | `/hr_admin/` | Reviewers = …and managers; the manager signs in | Sees only their own team's time off and swaps; never documents, incidents, offboarding or their own request |
| AG-RV-13 | S+B | `/desk/` | Status lines for the other agents | "Jobs agent: N waiting · N for your OK" and "HR agent: N for your OK" when those agents are on |
| AG-RV-14 | S+B | All | Approve a proposal already decided (two windows) | Refused: "proposal N is applied, not waiting" |

---

## 4. Customer pages — `/support/` (Phase 2d) — S+B

Limits from `desk_portal.py`: code valid 10 minutes, 5 wrong tries, 5 codes an hour, 5 requests an hour.

| ID | Path | Steps | Expected |
| --- | --- | --- | --- |
| AG-CP-01 | Report a problem | Fill title, details, name, phone, email → Send me a code → enter the code from the outbox → Submit | Ticket created; the customer lands on the ticket view |
| AG-CP-02 | Report a problem | Title 200 characters; 201 | 200 accepted; the box stops at 200 |
| AG-CP-03 | Request service | Pick a service; then "Other" with "What would you like" 120 characters; address; preferred days 120 characters | Quote request created with the address and preferences |
| AG-CP-04 | Book | Pick a service, an open time, address, details | Booking request shows on `/desk/` and the customer's booking card |
| AG-CP-05 | Book | "Ask us to call you instead" | Switches to the request path, details kept |
| AG-CP-06 | Buy | Pick a product, quantity 1 and 5, shipping address | Order card with the right total |
| AG-CP-07 | Buy | Quantity 0, 6, "x" | Refused with a message |
| AG-CP-08 | All | Name blank, phone "abc", email "x@", ZIP "ABCDE" | Each refused with its message before a code is sent |
| AG-CP-09 | All | "Send my code by" SMS and email | Code arrives on that channel in the outbox |
| AG-CP-10 | All | Wrong code 5 times | 5th try locks the code; a new code is needed |
| AG-CP-11 | All | Move the clock 11 minutes, then enter the code | "Code expired" |
| AG-CP-12 | All | Ask for a 6th code within an hour | Refused by the rate limit |
| AG-CP-13 | All | Honeypot (hidden Website) filled | Silently dropped: success shown, no ticket, no code sent |
| AG-CP-14 | Book / request | ZIP of ZAG-C-6 (outside the area) | "We don't usually cover that area yet" card |
| AG-CP-15 | All | Unicode, emoji, 2,000-character text and `<script>alert(1)</script>` in every text box | Stored and shown as plain text; no script runs |
| AG-CP-16 | Ticket view | Reply; add 2 photos and a PDF | Shown on the ticket and in `/desk/`; file checks pass (`desk_files.verify`) |
| AG-CP-17 | Ticket view | "Is it fixed?" Yes / No | Yes closes it; No reopens it with a note |
| AG-CP-18 | Ticket view | My part is done; Reopen | State changes as labelled |
| AG-CP-19 | Ticket view | Stars 1 and 5 with a note | Rating saved and shown as stars |
| AG-CP-20 | Booking card | Accept / Pick another time / Call me | Each updates the booking and `/desk/` |
| AG-CP-21 | Booking card | Add to calendar | A valid `.ics` downloads |
| AG-CP-22 | Booking card | Reschedule; Cancel | Booking moved / cancelled; the slot opens again |
| AG-CP-23 | Booking card | Join the wait list; Take an earlier time; Stop waiting | WF5 |
| AG-CP-24 | Order card | Pay now (payment stub) | Order marked paid |
| AG-CP-25 | Agent on the page | First reply from the agent | Shows name · label, the photo and the sign-off; never presented as a person |
| AG-CP-26 | Agent on the page | Practice mode | The customer sees no agent message at all |

---

## 5. On/off and practice matrix (Phase 2c)

### 5.1 Single-agent states — `AG-MX-<section>-<state>-<edition>`

Sections and the one trigger each uses:

| Section | Trigger | Main stage checked |
| --- | --- | --- |
| SD | ZAG customer reports a problem on `/support/` | Intake + First reply |
| BK | ZAG customer asks to book without a date | Check + Offer times |
| JB | Job ZAG-J-6 marked Completed with time logged | Close out (invoice draft) |
| RT | Clock to the sort weekday at 09:00 | Sort the week |
| HR (B) | ZAG-E-1 asks for 1 day off, 20 days ahead | Time off |

States: `OFF`, `PRAC` (on + practice), `SUG` (on, practice off, stage on Suggest), `AUTO` (on, practice off, stage on
Auto, guardrails holding). 5 × 4 × 2 editions = 40 runs (HR in S only where HR is enabled on personal).

| State | `agent_queue` | `agent_proposals` | Data | Outbox | PWA |
| --- | --- | --- | --- | --- | --- |
| OFF | 0 rows for the trigger | 0 | Unchanged | Nothing from the agent | Agent tab hidden (Service Desk) or "off" status; no suggestion lines |
| PRAC | 1 item, done | Status `practice` | Unchanged | Nothing from the agent | Under "Practice — what it would have done", with 👍/👎 |
| SUG | 1 item, done | `pending`, hold reason "stage is on Suggest" | Unchanged until approved | Only after approval | Pending list |
| AUTO | 1 item, done | `applied` (or `pending` with its guardrail reason) | Changed | Sent, signed by the assistant | History; held items show "waiting because …" |

Each run also checks: the AI log has exactly the expected calls (0 for OFF), and `blocked_http` is empty.

### 5.2 Cross-agent combinations

| ID | Ed. | Setup | Expected |
| --- | --- | --- | --- |
| AG-X-01 | S+B | Everything off; all 5 triggers fired | 0 queue rows in all 3 databases; 0 AI calls; Spent unchanged |
| AG-X-02 | S+B | Agent off, Booking on | No booking items (`_scan_all` needs both); the settings screen says Booking needs Agent on |
| AG-X-03 | S+B | Agent on in practice, Booking live (Suggest) | Ticket proposals `practice`; booking proposals `pending` |
| AG-X-04 | S+B | Service Desk off, Jobs on | Jobs works; the Jobs app's tab works. (Service Desk Agent tab hidden: not tested, cosmetic, dropped by David 4 Nov) |
| AG-X-05 | S+B | Jobs live, Route flow practice | Invoice proposal live; route proposals `practice`; no route in the crew outbox or `/remote/` |
| AG-X-06 | S+B | Jobs practice, Route flow live | Reverse of X-05 |
| AG-X-07 | S+B | HR on with the runner set to Chat | Refused at save (HR runners are API only); no HR item ever reaches `desk_agent_next` |
| AG-X-08 | B | Runner Chat for any agent | Refused with the server message |
| AG-X-09 | S+B | Practice proposals exist, then practice off | Old practice proposals stay `practice` and can't be approved |
| AG-X-10 | S+B | Pending proposals exist, then that agent's switch off (repeat for each agent) | Approve and Edit refused: "<agent> is off — tick "<switch>" to approve its suggestions, or reject them"; Reject still works; switch back on → approvable again (David 3 Nov; `desk_agent.agent_off_reason`). In `/desk/`, `/jobs/` and `/hr_admin/` the cards show "⏸ Paused — …" with only Reject; the Service Desk 🤖 tab stays visible while suggestions wait, with the "The agent is off" banner |
| AG-X-11 | B | All four live for one simulated day | Each item in its own database; correct sign-off and channel; no cross-talk |
| AG-X-12 | S+B | One stage Off, the rest Suggest | Off stage: proposals `rejected` "stage is off" or none; the others pending |
| AG-X-13 | S | Runner switched Chat → Claude API with items waiting for chat | Waiting items are worked by the next automatic pass; none worked twice |

### 5.3 Stage grid — every stage × every mode (`AG-ST-<kind>-<stage>-<mode>`)

The matrix above uses one trigger per agent. The grid tests **every one of the 33 stages on its own**: only that
stage is set to the mode under test (all others Off), its own trigger is fired, and one agent pass runs.

Modes per stage: `off`, `suggest`, `auto`, plus two overlays: `practice` (section practice on — overrides Suggest and
Auto) and `inactive` (section switch off). 33 stages × 5 = 165 runs per edition.

| Mode | Queue | Proposal | AI calls |
| --- | --- | --- | --- |
| off | No item for that stage | — | 0 |
| inactive | No item | — | 0 |
| practice | 1 item | `practice` | 1 |
| suggest | 1 item | `pending`, "stage is on Suggest" (or a guardrail reason) | 1 |
| auto | 1 item | `applied`, or `pending` with the guardrail / high-risk reason | 1 |

Trigger per stage (each fixture queues exactly one item for that stage):

| Kind | Stage | Trigger |
| --- | --- | --- |
| ticket | intake, first_reply | Customer reports a problem on `/support/` |
| ticket | resolution | Owner moves the ticket to In Progress |
| ticket | follow_through | Clock past the wait hours with no customer answer |
| ticket | learn | Ticket closed |
| booking | check, decide | Customer books a time |
| booking | offer | Customer asks for a visit with no date |
| booking | reply | Customer writes on their booking |
| booking | track | Clock to the check hour, outdoor visit tomorrow |
| booking | learn | Visit marked done with time logged |
| job | quotes | Quote open past the follow-up days; quote approved |
| job | schedule | Unscheduled job exists at pass time |
| job | prep | Clock to the prep hour, jobs tomorrow |
| job | onsite | Job past its estimate, crew still clocked in |
| job | closeout | Job marked Completed |
| job | collect | Clock to the first reminder day of an unpaid invoice |
| job | repeat | Recurring job completed; customer quiet past the win-back time |
| job | learn | Completed job with logged time |
| route | sort, plan, route, send | Clock to the sort weekday / the send hour |
| route | replan | Tomorrow's job cancelled after routes were sent |
| hr | recruit | New applicant |
| hr | onboard | New hire |
| hr | timeoff | Employee asks for time off |
| hr | timeclock | Missed punch; hours past the overtime warning |
| hr | compliance | Clock to an expiry warning day |
| hr | answer | Employee asks a question |
| hr | incidents | Incident report filed |
| hr | offboard | Termination started |
| hr | learn | Onboarding step finished late |

Run level: the full grid runs in fast mode against the sandbox control API (no browser). A human-mode slice sets the
modes **through the GUI** — desktop and each PWA settings screen — for one stage per agent per mode (5 agents × 3
modes = 15 visible runs), and checks the flow diagram shows that stage in the Off / Suggest / Auto colour.

### 5.4 Which AI model each step uses (`AG-MD-nn`)

Every request to the stand-in AI records the `model` it asked for, with the kind and stage. That log is the check.
The expected model comes from this table, **written out here on purpose rather than imported from
`desk_agent_providers.COMPLEX_STEPS`**, so a change to the code's mapping makes the test fail and is seen.

| Group | Uses | Steps |
| --- | --- | --- |
| Complex (12) | Main model ("complex & customer") | ticket resolution · booking decide, offer · job schedule · all 5 route steps · hr timeoff, answer, incidents |
| Customer message (7) | Main model — in practice, Suggest and Auto alike | ticket first_reply, follow_through · booking reply, track · job quotes, collect, repeat |
| Internal (14) | Light model ("internal steps"); the main model when Light is blank | ticket intake, learn · booking check, learn · job prep, onsite, closeout, learn · hr recruit, onboard, timeclock, compliance, offboard, learn |

| ID | Ed. | Setup | Expected |
| --- | --- | --- | --- |
| AG-MD-01 | S+B | Claude API; main Sonnet 5.5, light Haiku 5.5; every stage once (Suggest) | Each AI-log entry's model matches the table: 19 Sonnet, 14 Haiku |
| AG-MD-02 | S+B | Main Opus 5.5, light Haiku 5.5 | Same split with Opus |
| AG-MD-03 | S+B | Light blank (and, separately, light = main) | All 33 on the main model |
| AG-MD-04 | S+B | Grok API, Grok model set | All 33 on the Grok model; no Claude model in the log |
| AG-MD-05 | S | Chat runner | 0 API calls; items wait for the chat (the model is whatever chat the person uses — not recorded) |
| AG-MD-06 | S+B | Same stage in practice, Suggest and Auto | Same model in all three (customer messages stay on the main model in practice) |
| AG-MD-07 | S+B | Change the models in the desktop GUI between two passes | The next pass uses the new models; no restart needed |
| AG-MD-08 | S+B | After MD-01 | Recorded spend per model (`agent_runs`, Cost analysis "per model" rows) matches the AI-log counts and token numbers at the price table's rates |
| AG-MD-09 | S+B | Off and inactive stages | No AI-log entries for them under any model setting |
| AG-MD-10 | B | HR with a Claude key but Chat selected for the others | HR still uses the API runner and its models; never the chat queue |

---

## 6. Guardrails (Phase 2c) — S+B unless marked

Each test sets the stage to Auto, practice off, and the permission switch on, then breaks one condition.
Expected = `pending` with the quoted hold reason (from `desk_agent.decide`, `_confirm_guardrails` and the
agent modules), and nothing applied or sent.

| ID | Agent | Broken condition | Hold reason contains |
| --- | --- | --- | --- |
| AG-GR-01 | SD | Ticket is P1 | "P1 — a person sees it first" |
| AG-GR-02 | SD | Agent lowers the priority | "lowers the priority" |
| AG-GR-03 | SD | Confidence 0.59 (and 0.60 passes) | "confidence 0.59 < 0.6" |
| AG-GR-04 | SD | Reply over 1,200 characters; a link not on the allowed list | the text problem |
| AG-GR-05 | SD | Private ticket | Never queued; 0 AI calls for it |
| AG-GR-06 | SD/BK | Customer opted out | "the customer opted out of messages" |
| AG-GR-07 | SD | Action not allowed in the stage (`messy` script) | Proposal `rejected`: "isn't allowed in" |
| AG-GR-08 | SD | High-risk action on Auto | "needs a person's OK (high risk)" |
| AG-GR-10 | BK | Let the agent confirm off | "isn't allowed to confirm bookings" |
| AG-GR-11 | BK | Decide on Suggest | same as GR-10 |
| AG-GR-12 | BK | Practice on | `practice` |
| AG-GR-13 | BK | Time not the customer's choice or backup | "not the customer's own time or backup" |
| AG-GR-14 | BK | Address outside the area | "outside the service area" |
| AG-GR-15 | BK | Flagged at Check | "flagged at Check" |
| AG-GR-16 | BK | Daily cap reached (cap 1, second booking) | "daily limit is reached" |
| AG-GR-17 | BK | Confidence 0.75 | "confidence 0.75 < 0.8" |
| AG-GR-18 | BK | Instant-booking limits | the limit's own reason |
| AG-GR-19 | BK | Weather suggestion when the forecast isn't bad | "the forecast isn't bad enough" |
| AG-GR-20 | JB | Send invoices off | a person sends |
| AG-GR-21 | JB | Close out on Suggest; practice on | pending / practice |
| AG-GR-22 | JB | Invoice $1,250 with max $1,000 | over the amount limit |
| AG-GR-23 | JB | Daily invoice count reached | daily limit |
| AG-GR-24 | JB | Draft changed from the job, or amount not matching job or quote | mismatch reason |
| AG-GR-25 | JB | Customer opted out or unreachable | reach / opt-out reason |
| AG-GR-26 | JB | No time logged | no time logged |
| AG-GR-27 | JB | All conditions hold | Applied; the invoice email is in the outbox |
| AG-GR-28 | RT | Re-plan would move a Hard (fixed-time) job | The Hard job keeps its time |
| AG-GR-29 | RT | Urgent job for today | Never added to today automatically; waits for a person |
| AG-GR-30 | All | Automatic pass outside Works from / until | Nothing worked; Run now (force) still works |
| AG-GR-40 | HR (B) | Approve time off off | recommendation only |
| AG-GR-41 | HR | Time off on Suggest; practice on | pending / practice |
| AG-GR-42 | HR | Unpaid, FMLA, jury duty or "other" leave | never auto-approved |
| AG-GR-43 | HR | Balance too small (ZAG-E-2) | balance reason |
| AG-GR-44 | HR | More than Up to (days) | max days reason |
| AG-GR-45 | HR | Less notice than Notice (days) | notice reason |
| AG-GR-46 | HR | Blackout or holiday clash | clash reason |
| AG-GR-47 | HR | Most off a day reached | limit reason |
| AG-GR-48 | HR | Employee has booked jobs that day | jobs reason |
| AG-GR-49 | HR | Something flagged on the employee | flag reason |
| AG-GR-50 | HR | Approvals a day reached | daily limit |
| AG-GR-51 | HR | All conditions hold | Approved; the employee sees it in `/hr_portal/` |
| AG-GR-52 | HR | Any denial | Always a person — never auto-denied |
| AG-GR-60 | All | `messy` scripts: bad JSON, empty, refusal, unknown action | Item marked failed or skipped with a reason; nothing applied; the next item still runs |
| AG-GR-61 | All (API) | `error` scripts: timeout, 429, 500 | Item retried or left waiting; no crash; no spend recorded for a failed call |

---

## 7. Workflows (Phase 2e)

Each runs three times — `PRAC`, `SUG` (the test approves in the PWA), `AUTO` — except where marked. Edition in
brackets. The clock moves with `POST /clock`; agent passes run with `POST /run {"job": "agents"}`.

### AG-WF-01 — Customer problem to first reply (S+B)
1. Customer ZAG-C-1 on `/support/` reports "ZAG streaks on the front windows"; verifies the code.
2. Agent pass. Intake proposes type Complaint, P3, owner; First reply drafts an apology and a revisit offer.
3. SUG: the owner approves both in `/desk/` → Agent tab.
4. Customer reloads the ticket: the reply shows "Sam · Virtual assistant", the photo and the sign-off; with the
   request-service link only when AG-SD-12 is on.
- PRAC: steps 3–4 show nothing to the customer; outbox empty.

### AG-WF-02 — Follow-through and learning (S+B)
1. Continue WF-01. Move the clock past the wait hours (4 h) with no customer answer.
2. Agent pass → follow-through nudge (SUG: approve).
3. Customer answers "Yes, all good" → ticket closes.
4. Agent pass → Learn proposes a learning; it is saved only after approval (check `search_learnings` in the sandbox).

### AG-WF-03 — P1 and private tickets (S+B, AUTO only)
1. A P1 ticket and a private ticket arrive with every stage on Auto.
2. P1: pending with "P1 — a person sees it first". Private: never queued, 0 AI calls.

### AG-WF-04 — Booking without a date to confirmed (S+B)
1. ZAG-C-2 asks for exterior windows "next week, mornings", no date.
2. Agent pass → Check passes, Offer times proposes 3 real open windows.
3. Customer accepts one on the booking card.
4. Agent pass → Decide recommends a crew; AUTO with Let the agent confirm on → confirmed; the confirmation is in
   the outbox and on the booking card.

### AG-WF-05 — Weather and the wait list (S+B)
1. Booking for an outdoor service tomorrow; stand-in weather says heavy rain.
2. At the check hour, Keep on track offers a new time — only an offer; the visit stays unless accepted.
3. Another customer cancels an earlier slot → the wait-listed customer is offered it on the booking card and takes it.

### AG-WF-06 — Quote to scheduled job (S+B)
1. Quote ZAG-Q-1 approved in the Jobs app → Quotes stage turns it into a job.
2. Schedule suggests a date; it never moves a Hard job or anything today.
3. SUG: approve in `/jobs/` → Agent tab. The quote open 6 days gets a follow-up proposal.

### AG-WF-07 — Prep and on site (S+B)
1. Clock to the prep hour the day before → Prep checks tomorrow's route, details and weather.
2. Next day: a job runs past its estimate and a crew is still clocked in → On site flags it (Auto by default).
3. `/remote/` as Cris Crew: the crew sees no agent controls.

### AG-WF-08 — Close out, get paid, repeat (S+B)
1. Job completed with time logged → invoice drafted; sent on AUTO with Send invoices on.
2. Clock +7 days unpaid → 1st reminder; +14 → 2nd; then marked paid → no 3rd reminder.
3. Repeat proposes the next recurring visit.

### AG-WF-09 — The week's routes (S+B)
1. Clock to Friday 09:00 (sort weekday) → Sort the week, then Schedule the week.
2. Route each day (then repeat with scope = the whole week).
3. Send routes at 18:00 → each crew gets only its own route (outbox and `/remote/`).
4. A cancellation tomorrow → Re-plan the day re-orders the rest and tells the crew; Hard jobs keep their times.

### AG-WF-10 — Time off (B)
1. ZAG-E-1 asks for 2 days off in `/hr_portal/`, 20 days ahead.
2. Agent pass → recommendation (SUG) or approval (AUTO with all checks holding).
3. The employee sees the result in the portal; the HR Admin time-off row shows the 🤖 line.

### AG-WF-11 — Employee questions (B)
1. ZAG-E-2 asks "How many sick days do I get?" → the assistant drafts an answer from the handbook; HR approves.
2. The employee sees "HR's virtual assistant".
3. A sensitive message ("I need to report my manager") → "a person will follow up" when Acknowledge is on; nothing
   drafted when it is off.
4. A question sent outside the message hours is answered when the hours open.

### AG-WF-12 — Onboarding, expiring licence, incident (B)
1. New hire ZAG-E-4 → onboarding checklist proposals (I-9, W-4, new-hire report, first week).
2. Clock to 30 days before ZAG-E-3's licence expires → warning on the 30-day mark.
3. Injury report with incident access "Type only" → the AI log shows the type and dates but not the report text.
   Repeat with "Read the report" → the text is in the AI log.

### AG-WF-13 — A live week, all four agents (B, AUTO with guardrails on)
Mon–Fri with WF-01, WF-04, WF-08, WF-09 and WF-10 triggers spread over the week. Checks AG-X-11, the Spent line
(test-tagged spend only), the AI-log count per agent, and an empty `blocked_http` list.

---

## 8. Cost and leftovers

| ID | Check |
| --- | --- |
| AG-SAFE-01 | After every test: `blocked_http` is empty (or contains only the hosts that test meant to block) |
| AG-SAFE-02 | After every suite: AI-log count equals the count the tests expected |
| AG-SAFE-03 | The real `~/.ai-prowler` and `C:\Program Files\AI-Prowler` are unchanged (`installed_files_guard.py`) |
| AG-SAFE-04 | Sandbox folders are deleted; no `ZAG-` record exists outside them |
| AG-SAFE-05 | After every test: `desk_files.verify()` for tickets, plus job and HR equivalents |

---

## 9. Counts

| Area | Tests |
| --- | --- |
| Harness (ENV) | 8 × 2 editions |
| Settings (KEY, SD, BK, JB, RT, HR, SYNC) | 66 |
| Review screens (RV) | 14 |
| Customer pages (CP) | 26 |
| Matrix (MX) | 40 |
| Cross (X) | 13 |
| Stage grid (ST) | 165 per edition (fast) + 15 human-mode GUI runs |
| Models (MD) | 10 |
| Guardrails (GR) | 44 |
| Workflows (WF) | 13 stories, 35 runs |
| Safety (SAFE) | 5, run after every test or suite |
| **Total** | **about 600 test runs** (most of the stage grid in fast mode) |

---

## 10. Files (Phase 2)

```
tests/gui_agents_e2e/
  AGENTS_GUI_E2E_TEST_SPEC.md     this file
  conftest.py                     two sandboxes, browser contexts per person, human mode
  ag_server.py                    sandbox server (built on gui_jobs_timemachine/tm_server.py)
  ai_standin.py                   scripted Claude / Grok, call log
  seed_business.py                §1.6
  tk_driver.py                    visible in-process Tk driver
  test_env.py                     AG-ENV
  test_settings_desktop.py        AG-KEY, AG-SD/BK/JB/RT/HR (desktop), AG-SYNC
  test_settings_pwa.py            the same fields in the PWAs
  test_review.py                  AG-RV
  test_customer_pages.py          AG-CP
  test_matrix.py                  AG-MX, AG-X
  test_guardrails.py              AG-GR
  test_workflows_desk.py          WF-01…03
  test_workflows_bookings.py      WF-04…05
  test_workflows_jobs.py          WF-06…08
  test_workflows_routes.py        WF-09
  test_workflows_hr.py            WF-10…12
  test_workflows_week.py          WF-13
  results/                        run reports
```

---

## 11. Phase 1 findings for David

1. **No product change needed for the stand-in AI** (§1.3).
2. **Gap in the existing time-machine sandboxes:** `tm_server.py` and `hr_tm_server.py` block outbound `requests`
   calls only. The agents' AI calls use `urllib`, so they are not blocked there. Today that is safe only because a
   fresh sandbox has no API key saved; if a test ever saved a real key, its agent runs would reach the real API and
   cost money. The new harness blocks `urllib` too; the same small guard should go into both time-machine servers.
3. **Turning the agent off now stops approvals (X-10) — fixed 3 Nov.** `desk_agent.review()` refuses Approve and
   Edit while the suggesting agent's own switch is off; Reject still works. Unit tests in
   `tests/unit/test_desk_agent_core.py`. Same day: the Service Desk 🤖 tab now stays visible while suggestions
   wait (`/me` → `agent_pending`), and all three apps show such cards as "⏸ Paused" with only Reject.
   The two time-machine servers now block `urllib` as well (finding 2).
4. **HR "quiet hours" are message hours.** `agent_hr_quiet_hours` (default 8–18) is the window when messages *may*
   go out, and it can't cross midnight. The plan's "20-7" example was wrong; the label in the GUI should be checked
   for clarity in AG-HR-13.
5. **Private tickets are never given to the AI** — they are skipped, not held for a person (AG-GR-05).
6. **Jobs agent settings on a server:** the Jobs app comment says settings are changed by the owner at the server
   PC. AG-JB-11 records what the Jobs app actually allows on a server.

## 12. Phase 2b findings (settings) — open, recorded as strict xfails

| # | Where | What happens | Test |
| --- | --- | --- | --- |
| F-1 | Service Desk app, budget | −1 or letters silently saved as $0 | test_settings_desk_pwa.py |
| F-2 | Service Desk app, wait hours | 0 silently saved as 4 | test_settings_desk_pwa.py |
| F-3 | Jobs app, invoice max | −1 silently saved as $0 (`Math.max(0, …)`) | test_settings_jobs_pwa.py |
| F-4 | Jobs app, invoice max | 12.50 silently saved as 12 (desktop refuses: "whole number") | test_settings_jobs_pwa.py |
| F-5 | Jobs app, per day / quote days | 0 silently saved as 10 / 5 (an "or default" fallback in jobs/index.html) | test_settings_jobs_pwa.py |
| F-6 | Jobs app, HR desktop (and HR Admin's API) | One refused field half-saves the Save: settings are stored key by key, so fields before the bad one are kept while the message says it failed. Jobs app: `desk_tools.py` jobs_agent "set"; desktop HR: `desk_gui_agent.save_hr`; HR Admin: `_hr_agent_route` POST /settings (server-locked, so only reachable in code) | test_settings_jobs_pwa.py, test_settings_desktop_hr.py |

Also found: the HR apps run on a server only, and on a server their agent settings are locked, so HR Admin's
settings box is always greyed out. AG-HR-01…15 run against the desktop 👥 HR Agent & settings section instead
(test_settings_desktop_hr.py, personal and server). AG-HR-17 corrected: managers are HR Admin (`can_manage_hr`).

Added 3 Nov (desktop run, test_settings_desktop.py):

| # | Where | What happens | Test |
| --- | --- | --- | --- |
| F-6 | Desktop Service Desk and Jobs too | The same half-save: `desk_gui_agent.save` and `save_jobs` keep the valid fields while the box says it failed | test_sd_refused_value_saves_nothing_else, test_jb_refused_value_saves_nothing_else |
| F-7 | 🔑 Agent API Key, budget Save | A refused alert % still saves the budget: `save_agent_budget` stores the budget first, and the box says it failed | test_key_06_07_refused_alert_saves_nothing |

Spec corrections from the same runs:

- **AG-RT-04.** Switching the route scope doesn't change the route diagram's boxes. It changes the line under the diagram
  ("routes each day" / "routes the whole week"), and that line is what the test checks.
- **§5 SUG row and the stand-in.** Notes and flags are applied even on Suggest, by design (`FREE` in the Jobs and HR agents:
  `jb_note`, `jb_flag`, `jb_call_customer`, `rt_propose_week`, `hr_note`, `hr_flag`, `hr_recommend`, `hr_draft_email`).
  The `good` script answers with notes, so it can't produce a `pending` proposal for Jobs or HR. Phase 2c tests of `SUG`
  need a per-stage rule with a real action, as test_review.py does.
- **Prep only queues a job with a problem** (no address, bad weather, overfull day), not every job tomorrow. The §5.3 trigger
  for `job:prep` needs one of those.

## 13. Progress

| Phase | State |
| --- | --- |
| 1. Test spec | Written. The X-10 decision is made and built (§11 finding 3) |
| 2a. Harness | ag_server, ai_standin, conftest and test_env run, with a smoke test per agent. **Not built:** `seed_business.py` (tests create their own data, so AG-ENV-07 has no test) and a separate `tk_driver.py` (the driver is inside the desktop test files). Each sandbox also keeps its log in results\ |
| 2b. Settings | Written: desktop (KEY, SD, BK, JB, RT, HR), apps, server read-only and SYNC. **Open:** findings F-1 to F-7, marked as strict xfails, wait for David's decision |
| 2b. Review screens | Written: AG-RV-01 to 07, 09, 10, 13, 14. **Not written:** AG-RV-08, 11, 12 |
| 2c. Matrix and cross | Written: test_matrix.py, AG-MX (36 runs: HR on the Business sandbox only) and AG-X-01 to 13. test_models.py: AG-MD table for all 33 stages against the code, live AI-log runs for one stage per agent; MD-08 and MD-10 not written. **Not written:** AG-ST stage grid. AG-X-07 is thin: HR only runs on a server, and a server refuses Chat |
| 2c. Guardrails | Written: test_guardrails.py, GR-01 to 05, 07, 20 to 23, 25 to 27, 30, 60, 61; Booking and HR in §16. **Not written:** the list in §16 |
| 2d. Customer pages, 2e. Workflows, 3. Debug, 4. Sign-off | Not started |

F-1 to F-7 were fixed on 3 Nov; their strict xfail marks are gone.

## 14. Agent settings: app and desktop (David, 3 Nov) — test_settings_app_vs_desktop.py

- **Personal, fixed:** a setting changed in an app reached the database, but an open Small Business tab kept showing the old
  value until AI-Prowler restarted. Each section now re-reads what's saved every 5 s (`desk_gui_agent.live_sync`). A box with
  an unsaved edit keeps that edit. Covers Service Desk, Booking, Jobs, Route flow and HR.
- **Server, checked, no change needed:** Service Desk, Jobs and HR routes and the `jobs_agent` tool refuse every agent setting
  change, for owner, manager, staff and crew. The only other way a value changes is the desktop on the server PC.
- **Not covered by live_sync:** the Service Desk tabs General, Data, Web forms and Team, and the budget box on 🔑 Agent API Key.
- **Desktop to app, added 4 Nov (test_settings_desktop_to_app.py):** the open Service Desk card and Jobs settings re-read every
  5 s and follow, leaving a box the person is in or has edited. HR Admin and the Jobs app on a server follow too, read-only.
  The Service Desk 🤖 tab follows Agent on / off. The ↻ controls on Service Desk, Jobs and HR Admin fetch at once and the
  Remote app's ↻ fetches again. **HR Portal:** only checked that its three ↻ handlers exist; it needs an employee sign-in.
- **Service Desk card's Jobs boxes, fixed 4 Nov:** they had missed F-3 to F-6 (silent changes, half-saves on `/agent/jobs`).

## 15. Customer code and "ask us to call" (David, 4 Nov) — test_customer_code.py, test_customer_book_quote.py

New `nosms` sandbox: email set up, SMS never set up, SMS group off, matching David's personal install except that its mail
goes to the catcher by SMTP.

- **Fixed:** "please ask us to call you" in the "No open times" and "no services yet" lines was plain text. It's now a link to
  Get a quote, or "please call or text us" when that path isn't offered. Open times arriving after the customer moved to
  another form threw a JavaScript error.
- **Not reproduced:** in the sandbox the code goes by email on Report a problem, Book and Get a quote. David's install is
  `outlook+smtp`, which the sandbox can't run. A failed Service Desk send now logs its reason ("Service Desk email not sent").
- **Rate limit to remember:** 5 codes an hour counts per IP address as well as per customer. It says "too many codes".
- **Real install, 4 Nov:** David confirmed the code now sends on his personal install (not reproduced in the sandbox; the cause
  of the earlier failure wasn't found).

## 16. Booking and HR guardrails, 4 Nov — test_guardrails_booking.py, test_guardrails_hr.py

Written: GR-08, 10 to 13, 16, 17 (both editions) and GR-40 to 52 (Business), plus the 0.8 confidence floor for HR
and "a sick day needs no notice".

**F-8, fixed 4 Nov (David): GR-46.** HR Admin → Settings → Time Off Policy has a Blackout dates box (`/pto/policy`
`blackout_dates`, one date or range per line). `timeoff_checks` holds a request touching a blackout date or a paid company
holiday for a person. Unpaid holidays don't hold. An error in the holiday or booked-jobs lookup counts as a clash. Employees
can still ask for those days. Tested in test_guardrails_hr.py, including the HR Admin box.

**F-9, fixed 4 Nov: GR-48.** The booked-jobs check compared the whole crew cell to one name, so someone on a shared crew
("Pat Other, Jamie Lee") didn't count as booked. It now uses `_crew_name_in_cell`, as the rest of the app does.

**F-10, fixed 4 Nov: GR-06.** `opted_out` was read by the policy but never set, so a customer who had texted STOP wasn't held.
Now set for tickets and bookings with the Jobs agent's check; it holds only what reaches the customer.

GR-19, 24, 28, 29 are in test_guardrails_last.py. GR-19 runs with no forecast available (the sandbox can't fetch one), not a real mild
forecast. GR-28 and 29 use the Schedule stage; the Route agent's week plan and re-plan have the same rule, not separately tested.
Jobs learn needs real time entries (time_on_site), not the Actual Duration field.

## 17. 4 Nov: stage grid, customer pages, settings changes

**Stage grid (test_stage_grid.py), 27 of 33 stages:** everything except job learn,
route plan, send, replan, hr timeclock and offboard. Some triggers set state directly where the app's own flow needs more set-up:
booking learn and job collect use a database update; hr answer and incidents are filed as HR Admin, not an employee.

**F-12, fixed 4 Nov (David said build it): Follow-through.** `desk_agent.scan_tickets` queues a customer waiting past
`agent_wait_hours`, On Hold past its due date or 7 days, and a question after Fixed. Once per wait, at most 20 a pass, never private,
never over 30 days old. Same holds as First reply. Tested in test_follow_through.py, with WF-02.

**F-13, fixed 4 Nov: approving a suggested learning saved nothing.** It only wrote a note on the ticket. It now calls
`self_learning.record_learning`. WF-02 checks it isn't saved before approval and is after.

**Fixed 4 Nov (David said yes):** approving "propose_job" makes the job (Unscheduled with no date) and "propose_merge" merges, refused
across customers and for private tickets. `create_job_from_ticket` was also dropping its text (it sent "Notes", which jobs don't have). Both stay high risk, so a person always approves. test_agent_job_and_merge.py.

**Weather, 4 Nov (test_weather_switch.py).** F-15: with agent_jb_weather off, Prep's pack still fetched the forecast and gave it to the AI.
F-16: `_outdoor` asked for booking_services.name, which doesn't exist, so the owner's Outdoor tick was ignored for words in the name.

**test_workflows_2.py, 4 Nov:** WF-06, 08, parts of 11 and 12, by route. WF-11 doesn't yet check the "HR's virtual assistant" label or HR
approving a draft; WF-12's "licence" step uses overdue training, not an expiring document, and onboarding isn't in it.
F-17, fixed: a job set to repeat for a one-time customer was proposed, then failed on approval (`db_schedule_next` read only the customer).
F-18, decided 4 Nov: answers to what someone just asked go out at any hour; reminders keep to the hours. This replaces WF-11 step 4.

**Security changes (reply limit, daily AI cap, /hold limit, visitor IP check): dropped by David, 4 Nov. Not done, not planned for this release.**

**test_workflows_3.py, 4 Nov:** WF-04, WF-05 without the wait list, WF-07 without the /remote/ check, and GR-19 with a real mild forecast (the
sandbox now has POST /weather). WF-04 step 4 differs from the product by design: see F-19.
F-19, fixed 4 Nov (David chose to follow the setting): an accepted new-visit offer the agent made on its own goes through Decide or a person; one a person approved still books at once. A move of an already confirmed visit stays customer-accepts-it.

**test_workflows_routes.py, 4 Nov (WF-09):** F-20 the agent's route email went to the owner, not the crew; each person now gets their own. F-21 a
failed send was logged as sent; now it fails visibly. F-22 re-planning cleared the approval and told nobody; an approved route is re-approved and
the crew emailed. F-23 a shared job made a crew called "A, B"; it now goes on each person's route. Routes also carry unfinished jobs from earlier
days by design (R-058).

**test_workflow_live_week.py, 4 Nov (WF-13):** F-24 a new request with no date got a Service Desk reply on top of the booking flow, and customer messages on
it went to the Service Desk too (`_booking_of_ticket` only knew path 'book'). F-25 an action the rules refused left no trace. David chose option A: it shows in the approval list with the reason, Approve and Edit are refused, Reject clears it; none for a stage off or in practice.

**Small gaps closed, 4 Nov:** test_customer_more.py (CP-18 Reopen, CP-23 and the WF-05 wait list, CP-24, 25, 26), test_customer_business.py (customer page on
Business), test_small_gaps.py (RV-08, 11, 12; MD-08, 10), test_stage_grid_last.py (JB-learn, HR-timeclock, HR-offboard), test_workflows_routes.py (the Route stages).
Not tested: CP-18 "My part is done" (subcontractor), the rest of RV-12 (own request, and documents / incidents / offboarding shown on screen), WF-07's /remote/ check.
Spec differs from the product: MD-10's "Chat for the others" can't exist on Business (X-08). Fixed at David's request: CP-25, the agent's messages now show its name, label and photo; RV-11, the suggestion line is on the Time Off tab as well as Attendance.

**Phase 3 and 4, 4-5 Nov:** agents suite three clean fast runs in a row (1,093 passed each). Full normal regression: 7,702 passed, 1 failed, a test weakness
(test_owner_name_not_preselected picked a read-only box); test fixed, regression rerun. Default regression is `run_tests.bat` with NO arguments: passing `tests\` pulls in tests/e2e and its guard stops the run.

**Human-mode smoke, 5 Nov:** CP-23, CP-25, RV-08, RV-11: 11 passed; David watched and said the windows look good. Refusal cards (F-25) weren't shown in it. Regression rerun stopped at David's request; the fixed test passed alone (2 of 2). Left, all David's: refusal cards on a real screen, the real-server check, Save really restarting the app, the server cleanup script.

**F-26, 5 Nov, found by David on his Solo install:** an old saved `claude_code` runner showed "runner removed" and the agent never ran, with API keys saved. A saved value now reads as the saved key's runner (Claude first). Agents and AI tasks only run on API keys.

**5 Nov, David's decisions:** **Final rule (David, 5 Nov 15:37):** an agent needs a saved API key, on every install, or it doesn't run and nothing is queued. With no agent there's no AI answering customers or employees; the four apps work as before the agents (the apps, and a chat with the normal tools). The owner pays for the credits on a server. Chat isn't a runner; desk_agent_next / submit are gone from a chat. A chat's agent tools (status, review, run now) and the 🤖 tab follow role and scope. The HR Portal's fixed-answer chat is now called Help. Refusal cards: their own ⛔ line, Reject only, on all three screens. SMS: an opt-out ignores punctuation around it ("Stop."), an opt-in doesn't.

**Final gap review, 5 Nov (test_final_gaps.py):** HR Portal assistant signed in as an employee; a real MCP session with each person's own token; manager scope on the 🤖 tab; an old CLI setting; Chat on a server; Bookings and Routes totals on screen; "My part is done"; crew see no Agent button; AG-SAFE-05. Found F-27: a ticket outside a manager's scope came along inside another ticket's context (similar_resolved); now scoped. Not tested: a real incoming SMS "Stop." end to end (the keyword is unit-tested; the webhook's call to it was read in the code), ENV-07's seed list, a manager's own request (RV-12).

**F-28, 5 Nov, found by David (test_settings_live_sync.py):** a change on the desktop panels showed at once but only saved on Save, so it never reached the apps, which save on change. The panels now save themselves 0.6 s after the last change; a bad number waits with a note and no popup. Written first and confirmed failing (18 of 26 before the fix). The refresh buttons already worked: a probe with the page's timers stopped passed on all three apps before any change; they're now bigger, with a label.

**Workflows (test_workflows.py):** WF-01 (three modes), WF-03, WF-10 (three modes) by route, not clicks; test_review.py covers the
buttons. WF-02 is in test_follow_through.py. WF-04 to 09, 11 to 13 not written. On Suggest and Auto the check is "ran, nothing failed", not `pending` / `applied`.
Spec correction: `resolution` is queued by a customer reply after the first response, not by moving to In Progress.

**Customer pages (test_customer_pages.py):** CP-02 to 08, 11, 14 to 17, 19 to 22. **Not yet:** CP-18, 23, 24, 25, 26.
CP-07: the limit is 20, not 5 (`max_qty`). Found and fixed: the form took a blank name, a bad email and a bad ZIP; "ask us to
call" lost what was typed. All customer pages ran on the Solo-style sandbox only; Business isn't covered yet.

**MCP Tool Configuration:** Save is now "Save and restart": it asks, No saves nothing, nothing changed means no restart. The
panel follows the saved Job Tracker, SMS and Service Desk switches, so a Setup Center change shows and Save can't undo it. The
Setup Center and the panel were already one switch. The real restart hasn't been run in a test (`_on_window_close` is stubbed).

**F-11, fixed 4 Nov:** the Schedule stage's scan had LIMIT 20, so with 20 jobs left unscheduled job 21 was never queued. Found by the grid.

**Setup Center and tool switches (David, 4 Nov):** "File and track tickets" is the Service Desk switch; "Run my service business" and
"Plan routes" are the Job Tracker & Routing switch (on while either is ticked), in the picker and in Add more. Leaving Setup after
a change asks once whether to restart; No keeps the choice for the next start. SMS stays manual. Tested in tests/test_setup_wizard.py.

**Setup rows follow the truth, 4 Nov (David's screenshot):** a row's real check now wins both ways (it used to win only for
"done", so anything once saved as done stayed green). The list follows the Service Desk and Job Tracker switches wherever they were
changed. `connect_ai` is the one row with no check. Skipped stays the person's choice.

**Setup goes to the right place, 4 Nov:** "Open this tab" selects the tab and scrolls to the step's section (`setup_wizard.SECTIONS`);
a step's window closes when it sends you there. "Check again" opens the step's popup. Tested on the real pages in
tests/gui/test_setup_goes_to_the_right_place.py (personal mode; on a server some sections differ and aren't tested).

**F-14, fixed 4 Nov: three screens disagreed on Service Desk.** `optional_groups` said on, while `disabled_tools` listed all 39 off (the
list decides at startup). Turning a group on now clears a whole-group listing, and a group with every tool listed off reads as off.

**how_to_use_ai_prowler:** 35 tools were missing, including all the agents. Now named; test_howto_names_every_tool.py fails if
a new tool isn't in the guide or the catalog.

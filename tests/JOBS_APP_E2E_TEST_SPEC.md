# Jobs App — End-to-End GUI Test Plan & Implementation Spec

**Suite name:** `jobs_gui_e2e`
**Runner:** `tests\run_tests_gui_jobs_e2e.bat`
**Tool:** Microsoft Playwright (Python, via `pytest-playwright`) driving the installed **Microsoft Edge** (`--browser-channel msedge`, the browser David uses; Chromium-based like Chrome). Google Chrome can be used instead with `--browser chrome` if it's installed. Found 2026-09-25: Chrome is not installed on the dev PC; Playwright 1.63 drives Edge 152 fine.
**Target:** the LIVE Jobs PWA (default `https://ap-david-vavro1-2836dfdf.ai-prowler.com/jobs/`), real server, real database
**Status:** Draft 4 — 2026-09-26 — personal mode: Phases 0–4 done (harness, Route, every screen incl. Database + price list, security/login/nav, mobile + PWA); R-001..R-037 all fixed and verified. Button sweep of every screen done (BTN-JOBS/ROUTE/OTHER/DB). Open: Phase 5 (release gate: one full green run + deploy-notes step), server mode. See **§0** for what's done / not done and how to run each part.
**Scope now:** personal mode done. **Next: server mode on the server machine** — 6 users, role & scope rules, plan written in **§6.11** (2026-09-26), not started.
**Run mode:** David watches the tests — **every E2E run is done in human mode** (`--human`): visible Edge window, ~0.6 s before each click, typing key by key (including the login password).

---

## 0. Status & how to run (quick reference)

### 0.1 How to run each part in human mode

Open a **Command Prompt**, then:

```
cd /d C:\Users\david\AI-Prowler-V910_to_V920_work\AI-Prowler\tests
```

| What | Command | Tests |
|---|---|---|
| **Everything** | `run_tests_gui_jobs_e2e.bat --human` | all |
| Security checks (run first in every full run) | `run_tests_gui_jobs_e2e.bat --human -k SEC` | SEC-01..07, SEC-10 |
| Login | `run_tests_gui_jobs_e2e.bat --human -k AUTH` | AUTH-01..06 |
| Screen-by-screen tour | `run_tests_gui_jobs_e2e.bat --human -k NAV` | NAV-01, NAV-03 |
| Harness self-checks (guard, cleanup) | `run_tests_gui_jobs_e2e.bat --human -k HARNESS` | 4 |
| **Getting-started wizard** | `run_tests_gui_jobs_e2e.bat --human -k WIZ` | WIZ-01..07 |
| **Button sweep** (Jobs + Route screens) | `run_tests_gui_jobs_e2e.bat --human -k BTN` | BTN-00, coverage ×2, 11 buttons |
| All Route page tests | `run_tests_gui_jobs_e2e.bat --human -k route` | RB, RE, PS |
| Route building | `run_tests_gui_jobs_e2e.bat --human -k RB_` | RB-01..08 |
| Route editing (▲▼✋✏️🗑️, help) | `run_tests_gui_jobs_e2e.bat --human -k RE_` | RE-01..13 |
| Prescreen | `run_tests_gui_jobs_e2e.bat --human -k prescreen` | PS-01..15 |
| Approve / Un-approve + phone link | `run_tests_gui_jobs_e2e.bat --human -k approve_link` | RA-01..03, PL-01..07 |
| Regression catalog | `run_tests_gui_jobs_e2e.bat --human -k regressions` | R-004, R-006, R-013 (index of all R-### in the file) |
| The one real route email (rarely) | `run_tests_gui_jobs_e2e.bat --human --tier email -k RA_05` | sends ONE email to david.vavro1@gmail.com |
| One single test | `run_tests_gui_jobs_e2e.bat --human -k "RE_08"` | — |
| Several areas | `run_tests_gui_jobs_e2e.bat --human -k "AUTH or WIZ"` | quotes needed when there are spaces |

Slower / faster: `--human --slowmo 1200 --type-delay 300` (slower), `--headed` (visible, full speed), no option (no window, fastest).
Other: `--background` (minimized, notification when done), `--cleanup-only`, `--keep-data`, `--help`.
Results: `gui_jobs_e2e\artifacts\latest\SUMMARY.txt` and `report.html` (opens automatically). While it runs, **don't click inside the test's Edge window**.

### 0.2 Done / not done (2026-09-26)

| Area | Status | Notes |
|---|---|---|
| Phase 0 — `data-testid`s in `index.html`, pytest markers, `.gitignore`, guard test | ✅ Done, deployed | `tests\mcp_tests\test_jobs_pwa_testids.py` keeps them from disappearing |
| Phase 1 — harness: runner, human mode, login, write guard, sweep/cleanup, logs, SUMMARY | ✅ Done | Every run so far: **0 ZTEST rows left** |
| Security (§6.13) SEC-01..10 | ✅ Done, passing — SEC-08/09 added 2026-09-26 (`test_session_nav.py`, all pass live 19:50, no bugs) | SEC-11 server mode deferred |
| Login / navigation (§6.1–6.2) AUTH-01..06, NAV-01..04 | ✅ Done, passing — NAV-02/04 added 2026-09-26 (`test_session_nav.py`, all pass live 19:50, no bugs) | AUTH-07/08 deferred (server mode). NAV-04 triggers the banner with the app's own `_showUpdateBanner()` (service workers are blocked in test browsers, R-015); a real service-worker update is PWA-02 |
| Route build / edit / prescreen (§6.5) | ✅ **Phase 2 complete** (2026-09-26) — all passing in `--human` | RB, RE, PS (36) + **RA-01..03** Approve/Un-approve + **PL-01..07** phone link (6, RA-05 real email runs only with `--tier email`) + **regression file** R-004/R-006/R-013 (3); RA-04/RA-06 are covered by BTN / PL-07 |
| Getting-started wizard (§6.14) WIZ-01..07 | ✅ Done, passing | |
| Button sweep (§6.15) — Jobs + Route screens | ✅ Done; 4 guarded-button tests fixed 2026-09-26 for human mode | Other screens not yet |
| **Typical-day flow following the wizard** (§6.14 WIZ-10) + CLK-01, INV-01 | ✅ **Done 2026-09-26** (`test_typical_day.py`) — all 8 steps pass live in `--human` (13:13 run, 4/4 passed, 0 ZTEST rows left). Found **R-020** (CLK-01), **R-021** (INV-01), **R-022** and **R-023** (step 4) — all fixed, deployed, verified live | `run_tests_gui_jobs_e2e.bat --human -k typical_day` |
| Button sweep — Board, Calendar, Clock, Photos, Messages, Reports, Profile (BTN-OTHER) | ✅ Done 2026-09-26 (`test_buttons_other.py`, 22 tests) — all pass live 20:36, no app bugs. The coverage check caught 2 Calendar controls the first inventory missed (day tap, job chip) — added with their own tests | `run_tests_gui_jobs_e2e.bat --human -k BTN_OTHER` |
| **Database screen (§6.16)** incl. BTN-DB | ✅ Done 2026-09-26 (`test_database.py`, DB-01..14, 15 tests) — all 15 pass live (19:45 run, 0 ZTEST rows left). Found **R-033**, **R-034**, **R-035** — fixed, deployed, verified. (Table cells aren't clickable — only the per-row buttons — so BTN-DB is covered here, not by a cell-by-cell sweep) | `run_tests_gui_jobs_e2e.bat --human -k test_database` |
| **Jobs screen (§6.3)** — Add/Edit Job form | ✅ Done 2026-09-26: JOBS-01, 03, 04, 05, 06, 07 + validation V1–V3 (10 tests; JOBS-02 = BTN card test) — all passing live; JOBS-07 found **R-016** (fixed, deployed, verified) | `run_tests_gui_jobs_e2e.bat --human -k jobs_screen` |
| **Job detail screen** | ✅ Done 2026-09-26: DET-01..04 — all passing live; found **R-017** (apostrophe breaks buttons), **R-018** (security: code in job text ran), **R-019** (wrong tab lit) — all fixed, deployed, verified | `run_tests_gui_jobs_e2e.bat --human -k job_detail` |
| **Board screen (§6.4)** | ✅ Done 2026-09-26: BRD-01..09 — all 9 pass live (13:34 run); BRD-08 found **R-024** (deleted jobs stay on the board) — fixed, deployed, verified | `run_tests_gui_jobs_e2e.bat --human -k BRD_` |
| **Calendar screen (§6.6)** | ✅ Done 2026-09-26: CAL-01..08 — all pass live, no bugs found | `run_tests_gui_jobs_e2e.bat --human -k test_calendar` |
| **Clock screen (§6.7)** | ✅ Done 2026-09-26: CLK-02..06 — all 5 pass live (14:11 run); CLK-04 found **R-025**, CLK-05 found **R-026** — both fixed, deployed, verified | `run_tests_gui_jobs_e2e.bat --human -k test_clock` |
| **Photos & files screen (§6.8)** | ✅ Done 2026-09-26 (personal mode): PH-01..09 — all 11 pass live (14:48 run); found **R-028 (security)**, **R-029**, **R-030** — fixed, deployed, verified. Server-mode upload handler has the same fix, to be verified in §6.11 | `run_tests_gui_jobs_e2e.bat --human -k test_photos` |
| **Messages screen (§6.8)** | ✅ Done 2026-09-26: MSG-01..08 — all 8 pass live, no bugs found; nothing texted (guard records `send_sms`) | `run_tests_gui_jobs_e2e.bat --human -k test_messages` |
| **Reports screen (§6.8)** | ✅ Done 2026-09-26: REP-01..05 — all 5 pass live (15:27 run); REP-02 found **R-031** (weekly revenue $0 unless invoiced) — fixed with David's revenue definitions (actual = collected, projected = still owed), deployed, verified | `run_tests_gui_jobs_e2e.bat --human -k test_reports` |
| **Profile screen (§6.8)** | ✅ Done 2026-09-26 (personal mode): PRO-01..04 — all 4 pass live (15:29 run), no bugs found | `run_tests_gui_jobs_e2e.bat --human -k test_profile` |
| Price list via the UI (§6.12 PR-01..16) | ✅ done 2026-09-26 — `test_price_list.py`, 14 tests, all pass (run 20260926_183947 + PR-04 recheck). PR-07 / PR-14 not reachable from the screen → covered by `tests\mcp_tests\test_live_findings_2026_09_25.py` | found R-032 (Database-tab Edit never sent the version → stale edits silently overwrote). The 15:42 run's PR-02/03/09 failures were NOT app bugs: another run deleted the ZTEST rows mid-test — never run two E2E/ZTEST runs at once |
| **Mobile layouts (§6.9)** — Phase 4 | ✅ Done 2026-09-26 (`test_mobile_layouts.py`, MOB-01..05 × Pixel 5 + iPhone size = 10 tests + 1) — all 11 pass live 20:22 (incl. a **real touch drag** of ✋). MOB-02 found **R-037** (↻ buttons 35 px tall) — fixed, deployed, verified | `run_tests_gui_jobs_e2e.bat --human --mobile` |
| **Six-week schedule + customer reminders (§6.17)** | ✅ Added 2026-09-28: 15 customers (8 NSB, 7 Daytona; 8 Weekly, 7 Biweekly), 69 jobs over 6 weeks; PSCHED-01..05 + REM-01..04 — 7 pass, 2 skipped (reminder sending: "Customer Reminder Email Enabled" is Disabled on the personal database) | `run_tests_gui_jobs_e2e.bat --human -k test_six_week_schedule` (add `--tier email` for one real reminder to David) |
| **PWA behavior (§6.10)** — Phase 4 | ✅ Done 2026-09-26 (`test_pwa_behavior.py`, PWA-01..03) — all pass live 20:16, no bugs | `run_tests_gui_jobs_e2e.bat --human -k test_pwa_behavior` |
| **Server mode (§6.11)** — roles & multi-user | 🟡 **Started 2026-09-26.** Runs on **David's PC against the server's public Jobs app** (`AIPROWLER_SRV_URL`, like a phone would) — not on the server machine; only deploys + restarts happen there. Suite `tests\gui_jobs_e2e_server\` (own folder so the personal suite's setup never touches the PC's database), `--server` runner flag, one browser window per user. **2 users for now: David Vavro (owner), Vicki Vavro (manager)**; tokens only in Windows user env vars `AIPROWLER_SRV_TOKEN_U1/_U2`; no traces/videos, masked screenshots. **3rd user added 2026-09-27: Samual Cronin (field_crew, scopes sales+field), `AIPROWLER_SRV_TOKEN_U3`.** `test_srv_auth.py` 9/9 pass (05:57, incl. R-038 verified). `test_srv_multi.py` 4/4 pass (06:01): SRV-MULTI-03 same price edited by David + Vicki → Vicki's save refused "updated by David Vavro … reload and try again", David's change kept (R-032 proven with two real users); SRV-SCR-01/02 Reports owner-only on screen AND server. `test_srv_crew.py` (06:19): CREW-02..06 pass — crew edits own job not others', no Reports, Invoices/Quotes/Pricing/Settings refused and not offered as Database tabs, own customer's gate code editable but price/status not, can't invoice another crew's job; CREW-01 test fixed (both test jobs share one test customer name — now compares job IDs). SRV-AUTH-04 answered from the code: names match ignoring case and surrounding spaces | `run_tests_gui_jobs_e2e.bat --server --human` (all) or `-k test_srv_auth` / `test_srv_multi` / `test_srv_crew` |
| Route date dropdown: days whose jobs are ALL cancelled | ✅ Answered 2026-09-26 by RD-01 (`test_route_dates.py`): yes — cancelled jobs were counted and an all-cancelled day was offered → **R-036**, fixed, deployed, verified live 19:55 | `run_tests_gui_jobs_e2e.bat --human -k test_route_dates` |
| Calendar screen intermittent HTTP 503 | 🔎 Watching | seen once (NAV-03, 2026-09-25); the harness now logs the failing URL so the next occurrence names it |
| **Write-guard bypass through the service worker** (found 2026-09-26) | ✅ Fixed in the harness | Once the Jobs app's service worker controls the page (always in `--human` mode), its API requests skipped Playwright's page-level interception and reached the real server unchecked. No email was sent (checked the inbox), but it was a real hole. Now: test browsers **block service workers**, and a **bypass alarm** fails any test where a `/pwa-api` request left the browser without passing the guard. See R-015. |

---

## 1. Purpose

The Jobs app has grown past the point where it can be checked by hand. On 2026-09-24/25 alone, seven real bugs were found only by clicking through the app on real data (see §9, Regression Catalog). The existing ~3,000 pytest tests exercise the Python tools and do static checks of `jobs/index.html`, but **nothing presses the real buttons in a real browser** and confirms the screen shows the right thing.

This suite does that:

1. **Self-test** — a one-command run that logs into the live Jobs app in Chrome, walks every screen, presses the buttons, and verifies both what the screen shows and what the database now contains.
2. **Regression lock** — every bug found in the app gets a named test (`R-###`) that reproduces the original failure, so it can never silently come back.
3. **Release gate** — run after every `update_install.bat` deploy, before the crew uses the new build.

### Out of scope

- The Remote PWA (`/remote/`) — **now its own suite (2026-09-29)**: spec `tests\REMOTE_PWA_E2E_TEST_SPEC.md`, suite `tests\gui_remote_e2e\`, run with the same runner: `run_tests_gui_jobs_e2e.bat --remote --human`. Part of the E2E GUI PWA regressions alongside this Jobs suite and the server suite (`--server`).
- The desktop GUI (`rag_gui.py`).
- Load/performance testing.
- Anything that needs a real phone. (Mobile *layouts* are covered by Chrome device emulation, §6.9.)

---

## 2. Guiding principles

| # | Principle | Why |
|---|---|---|
| P1 | **Real app, real data, real clicks.** No mocking of the app itself. | The bugs we're catching live in the wiring between screen, API and database. |
| P2 | **The suite may only write data it created.** | It runs against the live production database. |
| P3 | **Nothing leaves the building by default.** No email, SMS, WhatsApp, or AI-credit spend unless the run explicitly opts in. | Real customers and a real bill are on the other end. |
| P4 | **Verify twice: the screen AND the database.** | A screen can look right while the DB is wrong (and vice versa). |
| P5 | **Every failure leaves evidence.** Trace, screenshot, video, and the list of API calls made. | So a failure can be diagnosed without re-running. |
| P6 | **Excluded from the default `run_tests.bat`.** | It's slow, needs the live server, and touches live data. |

---

## 3. Architecture

```
run_tests_gui_jobs_e2e.bat
        │  (sets env, picks tier, calls pytest -m jobs_gui_e2e)
        ▼
pytest  +  pytest-playwright  ──►  Google Chrome (channel="chrome")
        │                                   │
        │  fixtures: auth, safety guard,    │  loads LIVE /jobs/ PWA
        │  ZTEST data, artifacts            │
        ▼                                   ▼
tests\gui_jobs_e2e\*.py            AI-Prowler server  ──►  live SQLite job DB
                                     (PWA API: POST {tool, args})
```

### 3.1 Why Python + pytest-playwright (not Node/TypeScript)

- Every other AI-Prowler test is Python/pytest; same runner, markers, `pytest.ini`, CI habits.
- `pytest-playwright` gives, out of the box: `--browser-channel chrome` (use the installed Chrome, not a bundled Chromium), `--headed`, `--slowmo`, `--tracing retain-on-failure`, `--video retain-on-failure`, `--screenshot only-on-failure`.
- Playwright's **codegen** (`python -m playwright codegen <url>`) records clicks into Python, which is the fastest way to turn "I just found a bug by clicking X, Y, Z" into a regression test (§10).

### 3.2 How the suite talks to the app

Every button in the Jobs app ends in one call: `mcpCall(tool, args)`, which POSTs `{"tool": ..., "args": ...}` as JSON to the PWA API (`MCP_URL`). The suite uses that in two ways:

1. **Observe / guard (network layer).** A Playwright `page.route()` handler sees every PWA-API request the UI makes. It logs it (evidence, P5), and enforces the safety rules (§4).
2. **Set up / verify (same channel as the app).** Test setup and database checks call the page's own `mcpCall` through `page.evaluate(...)`. This means setup and verification use exactly the auth, endpoint, and crew scoping the real user has. No separate API client to maintain, no backdoor into the database.

### 3.3 Authentication

The app keeps its login in `localStorage['ap_auth']`:

- **Personal mode:** `{"mode": "personal", "token": <Bearer Token>}`. Token is in AI-Prowler → Settings → Remote Access.
- **Server mode:** `{"mode": "server", "access_token": ..., "userName": ..., "userRole": ...}`, obtained from `POST /pwa-login {name, token}`.

The suite logs in **once through the real login screen** (test `AUTH-01`, which also tests login itself), then saves Playwright's `storage_state` to a file that later tests reuse, so each test doesn't repeat the login.

Credentials come from **environment variables only**, never written into a test file:

| Variable | Meaning |
|---|---|
| `AIPROWLER_JOBS_URL` | Jobs app URL (default: the live tunnel URL above) |
| `AIPROWLER_JOBS_TOKEN` | Personal-mode Bearer Token, or server-mode personal token |
| `AIPROWLER_JOBS_USER` | Server mode only: the crew/user name to log in as |

The runner script refuses to start if the token isn't set.

---

## 4. Safety model (running against live data)

This is the most important section. The suite runs on the **real production database** while the business is operating.

### 4.1 Test data isolation — the ZTEST sandbox

| Rule | Detail |
|---|---|
| **Sandbox date** | **Today**, recalculated every run (run it tomorrow and it tests tomorrow), so the suite is a true daily regression of "today" as a user sees it. Tests that need other days use `sandbox_day(offset)` inside a **window of −3 … +7 days**; the guard, the cleanup sweep and the pre-flight all cover the whole window. *(Changed 2026-09-25 from the original far-future `2030-01-07`: several views only show dates near today — e.g. the Calendar loads a rolling 12-month range, job lists hide older items. Override: `E2E_SANDBOX_DATE=YYYY-MM-DD`.)* **Safety:** this runs against a validation database with no real work; the pre-flight **stops the run if any non-ZTEST job is inside the sandbox window**, because the cleanup sweep deletes every job on those days. |
| **ZTEST names** | Every customer/job the suite creates is named `ZTEST E2E …`, making them easy to spot on the Board/Database tab and easy to clean up. |
| **Dedicated customer** | Setup creates (or reuses) one customer, `ZTEST E2E Customer`. |
| **Known addresses** | Test jobs use real, public, geocodable New Smyrna Beach addresses (e.g. city hall, library, a public park), **not** real customers' addresses. Coordinates are set explicitly on creation so routing doesn't depend on the geocoder, except in the one test that tests geocoding itself. |
| **Created-ID registry** | Every `create_*` call's returned ID (`JOB-####`, `CUST-####`, route stop IDs) is recorded in a per-run registry. |

### 4.2 The write guard

A `page.route()` handler inspects **every** PWA-API call, whether made by the UI or by test code, and classifies the tool:

| Class | Examples | Default behavior |
|---|---|---|
| **Read** | `read_job_spreadsheet`, `prescreen_route_jobs`, `get_route_start_options` | Allowed. |
| **Scoped write** | `update_job_spreadsheet`, `delete_route_stop`, `reorder_route_stop`, `replan_route_day`, `suggest_route_schedule`, `approve_route_schedule`, `delete_job` | Allowed **only** if its target (job ID, stop ID, or `route_date`) belongs to the registry or the sandbox date. Anything else **aborts the request and fails the test immediately**, before it reaches the server. |
| **Create** | `create_job`, `create_customer`, `create_quote` | Allowed; the response ID is added to the registry. |
| **Outbound** | `email_route_now`, `send_email`, `send_sms`, `send_whatsapp`, `email_invoice`, `text_invoice`, `email_receipt`, `text_receipt`, `send_customer_reminders` | **Blocked by default** (see tiers, §4.3). |
| **Costs money** | `start_ai_routing` (AI credits) | **Blocked by default.** |
| **Destructive/admin** | `restore_job_database`, `delete_customer` on non-registry IDs, anything not on the known list | **Always blocked**, in every tier. |
| **Unknown** | A tool name not in the classification table | **Fails the test** with "unclassified tool: X — add it to safety.py". New buttons can't slip past the guard unnoticed. |

For a **blocked** call, the guard doesn't just drop it. It **records the exact tool and arguments** and answers with a canned success response. The test can then assert "pressing 📧 Email Route called `email_route_now` with `route_date=2030-01-07`", which tests the button's wiring without sending anything.

### 4.3 Run tiers

| Tier | Flag | Adds | Use when |
|---|---|---|---|
| **safe** (default) | *(none)* | — | Every deploy, anytime. Sends nothing. |
| **email** | `--tier email` | Lets **exactly one** real email through per run, from test RA-05 (📧 Email Route), to `david.vavro1@gmail.com` only — plus (added 2026-09-28) **one customer reminder** from REM-04 (§6.17), only to a ZTEST customer whose email is David's/Vicki's in `AIPROWLER_E2E_COMMS_TO`. Every other outbound call stays blocked-and-recorded. The guard keeps a counter and fails the run if a second real email would be sent. | Rarely, only when a release changed how route emails are built or sent. Once it's been seen to arrive, the safe tier's wiring checks are enough (*"it worked once, it'll work again"*). |
| **full** | `--tier full` | Email tier + allows `start_ai_routing` (spends AI credits) for RB-06 only. | Only before a release that changed AI Routing. |
| **comms** *(server mode only, added 2026-09-27)* | `--server --tier comms` | Lets real **email and SMS** through **only to David Vavro and Vicki Vavro** (David's decision 2026-09-27 — nobody else, not Samual, not customers). At most **2 real emails + 2 real texts per run**; the guard counts them and fails the run if one more would go out. A send to any other recipient — or through a tool whose recipient the guard can't see (e.g. `email_invoice` / `send_customer_reminders`, which look the recipient up server-side) — stays blocked-and-recorded. Recipients come from the Windows user env var `AIPROWLER_E2E_COMMS_TO` (their emails / phone numbers, comma-separated), never from a file. | After a release that changed email or SMS sending, or to confirm the server's email/SMS setup still delivers. Normal regression runs stay on **safe** and send nothing. |

SMS and WhatsApp are never really sent in the personal suite, in any tier. In server mode, only the **comms** tier sends, and only to David and Vicki. WhatsApp is never really sent.

### 4.4 Server-side sends the guard can't see

Some emails are sent by the **server itself** as a side effect of another action, so no outbound call ever crosses the browser guard. The known cases are Settings → **"Email Route On Build"** (when Enabled, every route build — Route Today / Route Selected Date (`suggest_route_schedule`), `build_daily_route`, and the AI Route worker — emails the route; Approve does not) and **"Customer Reminder Daily Digest"**.

**"Email Route On Build" — tested, not avoided (R-059, David 2026-09-29: "we need to test this as it's a test gap").** The pre-flight reads the setting. When **Enabled**, the run carries on and the guard handles every route build:
- each build's own switch is set to "don't email" before the request reaches the server (`email_route=False` for `suggest_route_schedule` — new, R-059 — and `email_link=False` for `build_daily_route`), for browser clicks and API calls alike;
- the **one** exception per run: tier email/full/comms, a sandbox route date, and the recipient is David or Vicki (`AIPROWLER_E2E_COMMS_TO`). Personal mode's recipient is the SMTP config's default_to/username (read from `~/.ai-prowler/email_config.json`); on the server the email goes to whoever built the route, so the server suite never lets a real one through;
- AI Route (credits, tier full only) has no per-call switch, so with the setting on it runs only if it can be that one allowed email;
- the server's reply is checked: "📧 Route link and results emailed to …" on a build the guard switched off is a **violation**.
PSCHED-06 (API: an explicit `email_route=False` build sends nothing; a plain build is either the one real email to David — tier email/full — or switched off) and PSCHED-07 (the Route button on the Route tab with the setting on: the route is built, its email handled by the guard) test it, and PSCHED-08 (setting Disabled: the guard leaves the build alone and the server itself sends nothing). Since R-060 they switch the setting themselves (§4.6) instead of skipping.

**"Customer Reminder Daily Digest" Enabled still stops the run** before anything is touched — it is not one of the toggles the suite may flip (§4.6). Any server-side send found later gets added here.

### 4.5 Backup and cleanup — leave nothing behind

David's rule: **the database must not accumulate test junk.** Cleanup is therefore continuous, not a single sweep at the end.

1. **Backup before the first write:** call `backup_job_database` and log the backup path. This is a safety net only (see 5).
2. **Clean up at the smallest scope that works.** Each test module creates only the data it needs in a module-scoped fixture, and **deletes it when that module finishes**, pass or fail. Only a few items live for the whole run: the one `ZTEST E2E Customer` and the logged-in session.
3. **Delete in reverse order of creation:** route stops → jobs → customer. Uses the same delete tools the app uses (`delete_route_stop`, `delete_job`, `delete_customer`), with `confirm=True`, limited to registry IDs.
4. **Final sweep (always runs, even after a crash):** delete anything named `ZTEST E2E` anywhere, plus any route stops left on the sandbox date. This catches data orphaned by an interrupted run. Then **verify zero remain** and print the result: `Cleanup: 0 ZTEST rows left ✅`, or list what's left and mark the run **failed**, even if every test passed.
5. **Start-of-run sweep:** the same sweep runs first, so leftovers from a killed run are removed before new data is created.
6. **`--keep-data`** skips steps 2 and 4 so a failure can be looked at in the app. The next normal run's start-of-run sweep removes it.
7. **No automatic restore.** Restoring the backup would also wipe any real work the crew did during the run. It exists only for a manual restore in an emergency.
8. **IDs get reused, so dependents must go too.** New IDs are "highest existing + 1". Test jobs are always the newest, so after cleanup the next **real** job reuses a test job's number. Any leftover row that points at a test job ID (route stop, time entry, photo, invoice, SMS log) would silently attach itself to that future real job. So:
   - cleanup deletes a job's **dependents first** (route stops, time entries, photos, invoices created by the test), then the job;
   - the final sweep also checks those tables for references to any registry ID and deletes them;
   - a test that creates a dependent type the cleanup doesn't know how to delete **fails at write time** through the guard (unclassified → fail), so this can't be forgotten when new tests are added.

### 4.6 Operational rules

- Personal-mode runs never touch server-mode users. Server mode (6 users, role/crew-scoping) is specified in §6.11 and runs only with `--server` on the server machine, with its own stricter token rules (§6.11.3).
- Don't run while someone is actively editing the sandbox date (nobody should be).
- **Settings — one narrow exception (R-060, David 2026-09-29).** The personal suite may flip exactly four settings: **Email Route On Build**, **Customer Reminder Email Enabled**, **Customer Reminder SMS Enabled** (Enabled/Disabled) and — added by R-061 — **Route Origin Mode** (Jobs Only / Company Location); only to those values (or the row's own original value), never its name or note. The four **Start/End Address** rows are saved too but may only be re-saved **unchanged** (the app's Route Origin Mode form re-saves them with their current values); the suite never changes the business address. Every other setting is still never changed (the guard blocks it; SET-02 proves it). How it stays safe (`tests\gui_jobs_e2e\settings_switch.py`):
  1. the pre-flight saves the originals (the four switches + the four Start/End Address rows) to `gui_jobs_e2e\artifacts\settings_to_restore.json` before any test; until then no Settings write is allowed at all;
  2. tests flip a toggle only through the `toggles` fixture, which puts every toggle back as soon as that test ends (pass or fail);
  3. the end of the run puts them back again and reads them back; any toggle not as it was is listed as a leftover → **the run FAILS** and SUMMARY.txt shows "Settings toggles NOT back ❌";
  4. a run killed half-way leaves the file behind; the next run's pre-flight puts those originals back first (logged), then saves afresh;
  5. flipping a toggle never widens what may be really sent: tier safe sends nothing; tier email/full one route email and one reminder email, to David only; SMS is never really sent in the personal suite; the guard assumes "Email Route On Build" is ON until a change to Disabled has been read back.
  The server suite does not flip Settings (it runs against the business's live server).
- Tests that depend on any other setting read it and adapt, or skip with a clear reason.

---

## 5. File layout

All under `C:\Users\david\AI-Prowler-V910_to_V920_work\AI-Prowler\tests\`:

```
tests\
  JOBS_APP_E2E_TEST_SPEC.md          ← this document
  run_tests_gui_jobs_e2e.bat         ← one-command runner (§8)
  gui_jobs_e2e\
    conftest.py                      ← fixtures: browser/auth, safety guard, ZTEST data, artifacts
    safety.py                        ← tool classification table + write guard (§4.2)
    app.py                           ← page objects: JobsApp, RouteScreen, BoardScreen, … (§5.1)
    data.py                          ← ZTEST data builders + sandbox addresses
    links.py                         ← Google Maps link parser/validators (R-001 family)
    test_auth.py
    test_navigation.py
    test_jobs_screen.py
    test_board.py
    test_route_build.py              ← Route Selected Date, AI Route (tier-gated), empty states
    test_route_prescreen.py          ← prescreen panel, errors vs warnings, highlight, fix, re-check
    test_route_edit_controls.py      ← ▲ ▼ ✋ ✏️ 🗑️, help panel, tooltips
    test_route_approve_email.py      ← Approve / Un-approve / Email Route (guarded)
    test_route_phone_link.py         ← the saved link, parsed and validated
    test_calendar.py
    test_clock.py
    test_photos.py
    test_messages.py
    test_database_tab.py
    test_reports.py
    test_profile.py
    test_pwa_behavior.py             ← service worker / update banner / session expiry
    test_mobile_layouts.py           ← phone-sized viewports (§6.9)
    test_regressions.py              ← R-### catalog (§9)
    artifacts\                       ← git-ignored; one folder per run (§7)
```

`pytest.ini` gets one new marker, `jobs_gui_e2e`, added to the `-m "not …"` exclusion in `addopts`, the same way `job_sheet_e2e` is excluded today.

### 5.1 Page objects (`app.py`)

Tests call intent-level methods, not raw selectors, so a markup change is fixed in one place:

```python
app.goto("route")
route.pick_date(SANDBOX_DATE)
route.press_route_selected_date()          # handles the prescreen confirm() dialog
route.expect_prescreen(errors=2, warnings=1)
route.tap_prescreen_item(0)
route.expect_highlighted_jobs(["JOB-0123"])
route.stop(2).move_up()
route.stop("JOB-0123").remove(confirm=True)
route.expect_not_on_route(["JOB-0123"])
```

### 5.2 Selector strategy

Priority order:

1. **Stable IDs already in the app:** `#screen-route`, `#routeDatePicker`, `#routePrescreen`, `#routeStopsList`, `#routeApproveBtn`, `#authCode`, …
2. **Data attributes already in the app:** `[data-jobid]`, `[data-stopid]`, `.ps-item[data-idx]`.
3. **New `data-testid` attributes** (Phase 0, §11). A small, behavior-free change to `index.html` for controls that today have only an emoji or text: nav buttons, ▲▼✏️🗑️✋, Approve, Email Route, Re-check, and so on.
4. **Accessible role + name** (`get_by_role("button", name="Approve")`) as a fallback.
5. **Never** CSS layout selectors or nth-child positions. They break on every styling change.

### 5.3 Dialogs, waits, and flakiness

- The app uses native `confirm()` in several places (prescreen errors, 🗑️). Page objects register `page.once("dialog", ...)` **before** clicking, accepting or dismissing on purpose and **asserting the dialog text**.
- No fixed `sleep()`s. Wait on real signals: the PWA-API response for the tool just triggered (`page.expect_response`), a toast, or the list re-rendering.
- Live routing depends on external drive-time services, so route-building tests get a longer timeout (60 s) and **one automatic retry** for network-type failures only (`pytest-rerunfailures`, scoped by marker). Assertion failures are never retried.

---

## 6. Test catalog

IDs are stable and referenced from failure reports and the regression catalog. Each case lists **what's pressed** and **what's verified** (UI = screen, DB = database check through `mcpCall`, API = the recorded PWA-API call).

> Screens marked *(outline)* haven't been code-reviewed for this spec yet. Their cases are a starting list and will be finalized in Phase 3 after reading each screen's code, the same way the Route cases below were written.

### 6.1 Authentication — `test_auth.py`

| ID | Scenario | Verify |
|---|---|---|
| AUTH-01 | Fresh browser → login screen → enter valid token → Log in | UI: app shell visible, `#authScreen` hidden; `localStorage.ap_auth` set with the right mode |
| AUTH-02 | Wrong token | UI: error message shown, field marked invalid, field cleared, still on login |
| AUTH-03 | Empty token | UI: "Please enter your password." |
| AUTH-04 | Show/hide password eye button | `#authCode` type toggles password ↔ text; aria-label updates |
| AUTH-05 | Reload after login | Goes straight into the app (resume from `ap_auth`) |
| AUTH-06 | Sign out (Profile) | `ap_auth` removed; login screen shown |
| AUTH-07 | *(server mode — deferred)* Stale session: server rejects token | App clears session and returns to login instead of a dead-end error |
| AUTH-08 | *(server mode — deferred)* Right token, wrong name | Rejected |

### 6.2 Navigation & shell — `test_navigation.py`

| ID | Scenario | Verify |
|---|---|---|
| NAV-01 | Tap each bottom-nav item (Jobs, Board, Route, Calendar, Clock, Photos, Messages, Database, Reports, Profile) | Exactly one `.screen.active`, matching `#screen-<name>`; no console errors |
| NAV-02 | Connection indicator | Green dot while the API answers; red when it fails (503 faked in the browser, ↻); green again after the next ↻ ✅ |
| NAV-03 | **Console-error sweep** | Visit every screen; fail on any `pageerror` or `console.error`. This cheaply catches broken JS after every deploy |
| NAV-04 | Update banner | When a new version is reported, the banner appears; **Later** hides it; the next screen change shows it again; **Refresh Now** reloads and the session resumes (the real service-worker trigger: PWA-02) ✅ |

### 6.3 Jobs screen — `test_jobs_screen.py`

| ID | Scenario | Verify |
|---|---|---|
| JOBS-01 | Job cards render for a date with ZTEST jobs | UI: one `.job-card[data-jobid]` per job; customer, time, and status visible |
| JOBS-02 | Tap a card | Detail modal opens for that job |
| JOBS-03 | Create a job through the form | UI: form closes, card appears. DB: row exists with the entered fields. Registry: ID recorded |
| JOBS-04 | Edit a job (time, Hard/Soft, duration) | DB: fields updated; `Original Start/End Time` rules respected |
| JOBS-05 | Cancel a job | DB: status Cancelled. **Route: its stop removed; prescreen/routing skip it** (R-006) |
| JOBS-06 | Move a job to another date | DB: new date. **Old date's route no longer has its stop** (R-004) |
| JOBS-07 | Jobs-page route buttons + prescreen box | Same prescreen behavior as the Route page, shown in `#jobsPrescreen` |
| JOBS-08 | Late/overdue styling | Past-time soft job shows late class |

### 6.4 Board — `test_board.py`

Cards are dragged with the real mouse (the app's own pointer-drag code runs), always between neighbouring columns. "Another device" = a change made straight through the API while the board is open. Note: a card shows the **customer record's** name (joined live), not the name typed on the job.

| ID | Scenario | Verify | Status |
|---|---|---|---|
| BRD-01 | Open the board | 5 columns; the job's card in **Scheduled** exactly once, with customer, crew, date, time | ✅ |
| BRD-02 | Drag Scheduled → In Progress → Complete | "Moved to …" toast each time; card moves; DB Job Status matches; ↻ shows the same | ✅ |
| BRD-03 | Drop on **Unscheduled** | Refused with "clear its Service Date" toast; **no write sent**; DB unchanged | ✅ |
| BRD-04 | Undated job (in Unscheduled) dragged to Scheduled | "Scheduled for today (date)"; DB Service Date = today | ✅ |
| BRD-05 | Tap a card | Edit form opens for that job (job number, notes) | ✅ |
| BRD-06 | Other device sets In Progress; board's 60 s poll runs | Card moves to In Progress | ✅ |
| BRD-07 | Other device cancels the job; this board (not refreshed) drags it | Server refuses (version conflict), ❌ toast, board reloads showing **Cancelled**; DB still Cancelled | ✅ |
| BRD-08 | Other device **deletes** a job; user leaves the Board and comes back | The deleted job's card is gone | ✅ (found **R-024**, fixed, verified live) |
| BRD-09 | Markup in the crew field | Shown as text, never run | ✅ |

### 6.5 Route — the heaviest area

#### 6.5.1 Building — `test_route_build.py`

| ID | Scenario | Verify |
|---|---|---|
| RB-01 | Sandbox date, **no route yet**, 4 jobs | UI: amber "4 jobs on this date, not routed yet" + 4 rows with ✏️ (R-003) |
| RB-02 | A day whose only job gets **cancelled** while it's on screen, then ↻ | The day drops out of the date list; the cancelled job isn't shown; if nothing is scheduled anywhere, "No jobs on this date". *(Rewritten 2026-09-26 for R-036 — a no-live-job day can't be picked any more, so the old "cancel it, then pick the day" setup is gone)* |
| RB-03 | Press **Route Selected Date** (clean data) | API: `prescreen_route_jobs` **before** `suggest_route_schedule`; UI: prescreen "no job problems found", numbered stops, Start/End rows, map markers; DB: route stops exist on the sandbox date |
| RB-04 | Route header counts | "N jobs" matches DB count, excluding cancelled |
| RB-05 | **Run AI Route** — safe tier | API: prescreen then `start_ai_routing` attempted and **blocked**; UI shows the guard's canned result without errors |
| RB-06 | **Run AI Route** — full tier | Real run completes; `poll_ai_routing` progresses; stops written |
| RB-07 | Change the date picker | Route, prescreen results, and warnings for the old date are cleared; the new day shows its own not-yet-routed job *(second day now has a live job — R-036)* |
| RB-08 | Re-route after manual changes | Confirms intended behavior: a fresh build replaces the manual order |

#### 6.5.2 Prescreen — `test_route_prescreen.py`

Setup builds a sandbox date with one of each problem.

| ID | Scenario | Verify |
|---|---|---|
| PS-01 | Duplicate job (same customer + address) | ❌ "Possible duplicate job: A, B" |
| PS-02 | Two customers, same address written differently ("SR 44" / "State Road 44") | ❌ "2 jobs at the same address" |
| PS-03 | **Neighbors 1730 vs 1755 State Road 44** with near-identical coordinates | **No** duplicate error (R-002) |
| PS-04 | Job with no street address | ❌ "has no street address"; after routing, it is **not** a stop (R-008) |
| PS-05 | Hard job with no Start Time | ⚠️ warning, listed after errors |
| PS-06 | Overlapping Hard appointments | ⚠️ HARD_OVERLAP naming both |
| PS-07 | Cancelled job at a duplicate address | Not reported, not routed |
| PS-08 | Errors present → press route → **dialog text asserted** → Cancel | API: `suggest_route_schedule` **not** called; toast "Routing stopped…" |
| PS-09 | Same, but OK (route anyway) | Route builds; the phone link has **no back-to-back duplicate address** (R-001) |
| PS-10 | Warnings only | No dialog; route builds; warnings remain visible |
| PS-11 | Tap each prescreen item | Matching `[data-jobid]` rows pulse (`.ps-highlight`) and scroll into view; on the Route page the stop is also selected on the map |
| PS-12 | Tap a problem whose job is only in the "not on this route" list | That row highlights (R-004 × prescreen) |
| PS-13 | ✏️ chip on a problem | Job edit form opens for that job |
| PS-14 | Fix the problem → 🔄 Re-check | Item disappears; counts update |
| PS-15 | ✕ closes the panel | Panel empty/hidden |
| PS-16 | **3+ problems → the list scrolls inside its box** | `.prescreen-list` has `scrollHeight > clientHeight`; page layout below doesn't jump |
| PS-17 | Prescreen API failure (guard returns error) | Routing still proceeds (the check must never block routing on its own failure) |

#### 6.5.3 Editing the route — `test_route_edit_controls.py`

| ID | Scenario | Verify |
|---|---|---|
| RE-01 | ▲ on stop 3 | API: `reorder_route_stop` → position 2; UI: order changed, times recomputed; DB: `stop_number`s match; **link updated to the new order** |
| RE-02 | ▼ on stop 1, and ▲ disabled on first / ▼ disabled on last | Same checks; disabled states correct |
| RE-03 | ✋ drag stop 4 to position 1 | Same as RE-01; **dropping below the last stop never lands among "not on this route" rows** |
| RE-04 | Move a stop, then move it back | Times and warnings identical to the start (documented guarantee) |
| RE-05 | Move a Hard job so it can't make its time | ⚠️ "off schedule" warning shown; row gets `hard-violation` style |
| RE-06 | ✏️ on a stop → change duration → Save | API: `replan_route_day`; later stops' times shift; order unchanged; link refreshed |
| RE-07 | 🗑️ → dialog text says the job is kept → Cancel | Nothing changes |
| RE-08 | 🗑️ → OK | Stop gone; **job still exists** (DB); job appears under "➕ not on this route"; remaining stops re-timed; **link no longer includes it** (R-007) |
| RE-09 | "➕ N jobs not on this route" after adding a job to an already-routed date | New job listed under the route (R-005) |
| RE-10 | Re-route after RE-08 | Removed job comes back as a stop |
| RE-11 | "ⓘ What do these buttons do?" | Opens/closes by tap; text mentions all four controls and Email/Approve |
| RE-12 | Tooltips | ▲ ▼ ✏️ 🗑️ ✋ each have a non-empty, correct `title` |
| RE-13 | Tap a stop row | Row outlined, map leg highlighted; tap again clears |

#### 6.5.4 Approve & email — `test_route_approve_email.py`

| ID | Scenario | Verify |
|---|---|---|
| RA-01 | ✅ Approve | DB: soft jobs' Start/End updated to the planned times; Hard jobs untouched; UI state updates |
| RA-02 | ↩️ Un-approve | DB: times restored to Original Start/End |
| RA-03 | Approve visibility | Hidden when no soft job with a job ID is on the route |
| RA-04 | 📧 Email Route — safe tier | API: `email_route_now(route_date=sandbox)` recorded and blocked; UI shows confirmation |
| RA-05 | 📧 Email Route — email tier | Real email to `AIPROWLER_E2E_EMAIL` only; response names that recipient |
| RA-06 | Email after manual edits | The emailed link (captured from args/response) equals the link currently saved on the jobs, i.e. **the edits are what gets sent** |

#### 6.5.5 Phone link — `test_route_phone_link.py`

`links.py` parses a saved `Route Map URL` and checks the invariants from this week's bugs:

| ID | Invariant |
|---|---|
| PL-01 | No `origin=` parameter (the start is left open, "from current location") |
| PL-02 | Destination = the configured end address (home, when that option is selected) |
| PL-03 | Waypoints = the route's stops **in stop order** |
| PL-04 | **No two consecutive waypoints are the same place** (R-001) |
| PL-05 | Waypoint count ≤ 9 (Google's limit for the Maps app); flag if > 3 (mobile-browser limit) |
| PL-06 | Every job on the route has the **same** link saved |
| PL-07 | After reorder / edit / delete, the link changes to match (R-007). *2026-09-26: one flaky failure — the test read the stop list while it was still redrawing; it now refreshes first, like RE-01* |

### 6.6 Calendar — `test_calendar.py`

Agenda row 0 is always today (= sandbox date), row N is today+N. Chips are found by the job number they open.

| ID | Scenario | Verify | Status |
|---|---|---|---|
| CAL-01 | Hard 9 AM + Soft 1 PM job today | Both chips on the "Today" row, 9 AM first, 🔒 / ☁️, two blocks on the time bar; not on tomorrow | ✅ |
| CAL-02 | Tap today → tap the job in the day list | Day list shows the job and "10:30 AM"; job detail opens for that job | ✅ |
| CAL-03 | A Complete and a Cancelled job | Complete shown as done; Cancelled left off | ✅ |
| CAL-04 | 3-day job (+1 … +3) | On rows +1, +2, +3 only | ✅ |
| CAL-05 | Tap an empty day (+5) | Add New Job opens with that date filled in | ✅ |
| CAL-06 | 4 jobs today, month grid | Today's cell: 3 names (8 AM first) + "+1 more"; tapping it lists all 4 | ✅ |
| CAL-07 | Build today's route on the Route screen | 📍 Google Maps link on today's row only; day list shows "Route for this day" | ✅ |
| CAL-08 | Job added elsewhere, tap ↻ | New job appears on its day | ✅ |

### 6.7 Clock — `test_clock.py`

These are payroll hours, so every step is checked in the database's **TimeLog** too. CLK-01 (a refused clock-out is shown as refused) lives in `test_typical_day.py`.

| ID | Scenario | Verify | Status |
|---|---|---|---|
| CLK-02 | Pick job → ▶ Clock In → wait → ■ Clock Out | "Clocked in: JOB", Clock In greyed, timer visibly running, banner; TimeLog has an open entry → after Clock Out: "Not clocked in", Recent Entries lists the job, TimeLog entry closed | ✅ |
| CLK-03 | Clocked in, pick a different job | Clock In stays greyed — no second clock-in; clock out of the first works | ✅ |
| CLK-04 | Clocked in, **app closed and re-opened** (phone) | Still shows "Clocked in: JOB", Clock Out works, TimeLog entry closed | ✅ (found **R-025**, fixed, verified live) |
| CLK-05 | Clock-in already open on the server (another device / voice), tap Clock In | Shows the existing clock-in with its real start time — not a fresh 00:00:00 timer | ✅ (found **R-026**, fixed, verified live) |
| CLK-06 | Clock In with no job picked | "Select a job first", nothing sent | ✅ |

### 6.8 Photos, Messages, Database, Reports, Profile *(outlines)*

- **Photos & files — `test_photos.py` (written 2026-09-26, personal mode).** The screen's two pickers (📷 Add Photos = images, 📎 Add Files = any file) feed one upload; files are handed to the real hidden file inputs, the real Upload button sends them, and every upload is checked on disk byte-for-byte in `Documents\AI-Prowler\JobPhotos\<JobID>\` (the test deletes only the files it created).

  | ID | Scenario | Verify | Status |
  |---|---|---|---|
  | PH-01 | One photo | thumbnail, "1 / 10", Upload enabled → "✓ 1 photo(s) saved", grid cleared, file on disk identical | ✅ |
  | PH-02 | PDF + TXT + CSV via 📎 Add Files | 📄 + name shown (no image preview); saved with their own extensions, content identical | ✅ |
  | PH-03 | 2 photos + 1 file, remove one (✕), notes | "3 / 10" → "2 / 10"; exactly the 2 kept files saved; notes cleared | ✅ |
  | PH-04 | Pick 12 files | only 10 kept, "10 / 10" | ✅ |
  | PH-05 | Upload button rules | disabled until a job is chosen AND a file is added; disabled again when the last file is removed | ✅ |
  | PH-06 | Job detail → 📎 Add Files | Photos screen opens with that job chosen, Photos tab lit | ✅ |
  | PH-07 | File name with markup | shown as text, never run | ✅ (found **R-030**, fixed, verified live) |
  | PH-08 | Upload URL called with job number `../x`, `..\x`, `JOB-0001/../../x` | refused; **nothing written outside JobPhotos** | ✅ (found **R-028**, security, fixed, verified live) |
  | PH-09 | Upload for a job that doesn't exist | refused, no folder created | ✅ (found **R-029**, fixed, verified live) |

  Note: the older `live_pwa` tests 4.13/4.14 in `tests\mcp_tests\test_pwa_features.py` (excluded from normal runs) upload to a made-up job `JOB-TEST-PWA-UPLOAD`; since R-029 that is correctly refused — they need a real job if they're ever run again. Server-mode upload handler got the same R-028/R-029 fix — **to be verified in the server-mode test run (§6.11)**.
- **Messages — `test_messages.py` (done 2026-09-26, personal mode, all 8 pass live, no bugs found).** Nothing is ever texted: `send_sms` is recorded by the guard (with the exact To/Message), and because SMS isn't set up on the test install, the app's "is SMS set up?" check is answered in the browser with a faked ✅ (new harness feature `page.e2e_fakes[tool] = reply` — a faked call never reaches the server, still counted by the bypass alarm, logged as FAKED).

  | ID | Scenario | Verify | Status |
  |---|---|---|---|
  | MSG-01 | Open Messages | To / Message / Send / Check shown, Messages tab lit | ✅ |
  | MSG-02 | SMS not set up, tap Send | "SMS is not configured yet" alert; nothing sent or recorded | ✅ |
  | MSG-03 | Send with To and/or Message empty | "Enter a recipient and a message."; nothing sent | ✅ |
  | MSG-04 | Send | exactly one `send_sms` with the typed To + Message; "✓ Sent", toast, message cleared, recipient kept | ✅ |
  | MSG-05 | Server refuses (❌ invalid number) | "Failed: ❌ …", "Send failed" toast, message kept, Send re-enabled | ✅ |
  | MSG-06 | 🔄 Check (real `check_sms_inbox`) | replies box filled, no error | ✅ |
  | MSG-07 | Reply text containing markup | shown as text, never run | ✅ |
  | MSG-08 | Job → 💬 Text Customer, customer "O'Brien's Café" | Messages opens, **Messages** tab lit, To = "ZTEST E2E O'Brien's Café" — completes the R-017 / R-019 check that DET-01 couldn't do while SMS was off | ✅ |
- **Database tab:** each sheet loads; edit a ZTEST row inline → DB updated; editing a non-ZTEST row is **blocked by the guard** (this also proves the guard works).
- **Reports — `test_reports.py` (written 2026-09-26, personal mode).** Numbers are checked as a CHANGE in the current week's row (jobs with known amounts/hours added, ↻ tapped) so other jobs in the database don't matter. Customer Reminders never send: `send_customer_reminders` is recorded by the guard; the two "Customer Reminder … Enabled" switches (both Disabled on this install) are answered in the browser only (faked Settings read — Settings itself is never changed).

  | ID | Scenario | Verify | Status |
  |---|---|---|---|
  | REP-01 | Open Reports; weeks selector 8 → 4 | two charts; table 17 rows → 9; "(this week)" row | ✅ |
  | REP-02 | Add this week: a Complete job never invoiced ($150, 90 min actual); a Complete job invoiced $100 (0% tax) with $40 paid (60 min actual); a Scheduled job ($200, 30 min); a Cancelled job ($999) | this week: **actual revenue +$40** (only money collected), **projected +$410** (150 + 60 + 200 still owed); actual +2.5 h, projected +0.5 h; cancelled not counted | ❌→ first run: revenue $0 → **R-031**; revenue redefined per David, fixed, deployed → ✅ 15:27 |
  | REP-03 | 🔍 Find (0 days) → only our customer checked → custom message → ✉️ Email Selected | our customer listed (markup in name shown as text, email shown); exactly one recorded send with our id, channel email, the typed message | ✅ |
  | REP-04 | Nobody checked → 💬 Text Selected | "Select at least one customer first"; nothing sent | ✅ |
  | REP-05 | Both reminder channels off in Settings | "Email Disabled" / "Text Disabled" shown greyed out; no send buttons | ✅ |
- **Profile — `test_profile.py` (written 2026-09-26, personal mode).**

  | ID | Scenario | Verify | Status |
  |---|---|---|---|
  | PRO-01 | Open Profile | Name = owner name from Settings (`/pwa-token` owner_name, else "Owner"), same as the top bar; "Mode: Personal"; Code row hidden; Sign Out shown | ✅ |
  | PRO-02 | Add 2 Scheduled + 1 Complete job, reload jobs | "Jobs Loaded" goes up by exactly 2 (Complete isn't open) | ✅ |
  | PRO-03 | Clock in and out on a test job | "Clock Entries" goes up by 1 | ✅ |
  | PRO-04 | Sign in → Sign Out (Profile button) → reload → sign in again | login screen after sign-out AND after the reload (no silent sign-in); saved sign-in removed; signing back in works | ✅ |

### 6.9 Mobile layouts — `test_mobile_layouts.py`

Re-run a smoke subset (NAV-01, RB-03, PS-11, RE-01, RE-11) under Chrome device emulation for a small Android phone (Pixel 5) and an iPhone-sized viewport. Verify: no horizontal page scroll; bottom nav reachable; the prescreen and stop lists scroll inside their boxes; touch drag (✋) works with emulated touch; buttons at least ~40 px tall. Each test runs on both sizes (Edge with phone size + touch; a real iPhone's Safari engine isn't covered — layout only). Run: `run_tests_gui_jobs_e2e.bat --human --mobile`.

| ID | Scenario | Verify | Status |
|---|---|---|---|
| MOB-01 | Every screen from the bottom nav (NAV-01 on a phone) | No sideways page scroll; the tapped nav button is on screen | ✅ both |
| MOB-02 | Tap targets | Bottom-nav buttons, ↻ buttons, Route Selected Date ≥ 40 px tall. *Found 2026-09-26: ↻ on Jobs / Route 35 px — R-037, fixed & verified live* | ✅ both |
| MOB-03 | Route on a phone (RB-03 / RE-01 / RE-11) | Builds; ▲ moves stop 3 to 2; help panel opens/closes; no sideways scroll | ✅ both |
| MOB-04 | PS-11 on a phone | Tapping a prescreen card's title highlights that job, no edit form opens. *(First run tapped the card's centre, which on a narrow screen is the "✏️ JOB-…" button inside it — test fixed)* | ✅ both |
| MOB-05 | **Real touch drag** of ✋ (Chromium touch events, not a mouse) | Dragging stop 1 below stop 3 makes it 3rd | ✅ both |

### 6.10 PWA behavior — `test_pwa_behavior.py`

| ID | Scenario | Verify |
|---|---|---|
| PWA-01 | Service worker registers | `navigator.serviceWorker.controller` present after reload; scope `/jobs/` ✅ |
| PWA-02 | New build detection | The cache name in the served `sw.js` equals the content hash of the `sw.js` / `index.html` / `manifest.json` being served right now (recomputed by the test) — so any deploy that changes `index.html` gets a new name; the installed worker's cache holds exactly the served `index.html` ✅ |
| PWA-03 | Offline shell | With the network cut (`context.set_offline(True)`), a reload still shows the app (login screen) ✅ |

These are the only tests that let the service worker run (R-015). To stay safe they never log in (the login screen makes no `/pwa-api` calls) and the bypass alarm still applies. Run: `run_tests_gui_jobs_e2e.bat --human -k test_pwa_behavior`.

### 6.11 Server mode — multi-user, role & scope (`tests\gui_jobs_e2e\server\`)

*Written 2026-09-26, not started. Runs on the **server machine** (the installed AI-Prowler Server with its 6 registered users), against that machine's Jobs PWA. Replaces the earlier one-crew-user placeholder.*

#### 6.11.1 What "access rules" means for the Jobs app (from the code, 2026-09-26)

Two separate things decide what a server-mode user can do. The tests must keep them apart:

| Axis | Set where | Governs | Jobs app effect |
|---|---|---|---|
| **Role** (`owner` / `manager` / `staff` / `field_crew`) | Admin tab → user | Which tools and screens a user gets, and whether their **job data** is filtered | See matrix below |
| **Scope** (shared + assigned + private knowledge-base scopes) | Admin tab → scopes | Which **indexed documents** `search_documents` etc. return | **None.** Job data is not scoped by knowledge-base scope. SRV-KB-01 checks this stays true |

There is **one job database** (`<state dir>\jobs_database\ai_prowler_jobs.db`) shared by every user and role; only the role decides whose rows a user sees. (Per-user job files — the old "Model B" of the spreadsheet era — are gone; R-046 removed the last code for them.)

**Role matrix — job data**

| Rule | owner | manager | staff | field_crew | Where enforced |
|---|---|---|---|---|---|
| Sees every crew's jobs (Jobs, Board, Calendar, Route) | ✅ | ✅ | ✅ | ❌ own jobs only (Crew = their name; blank Crew = not theirs) | server, `_job_crew_scope` |
| Edits / deletes any job | ✅ | ✅ | ✅ | ❌ own jobs only | server |
| Customers sheet | ✅ | ✅ | ✅ | ✅ read (gate codes, access notes); edits limited to their customers' non-locked fields | server |
| Settings, Services_Pricing, Quotes, Invoices sheets | ✅ | ✅ | ✅ | ❌ hidden in the Database tab **and** refused by the server | client + server `_FIELD_CREW_BLOCKED_SHEETS` |
| Reports screen, `find_stale_customers`, `send_customer_reminders` | ✅ | ❌ | ❌ | ❌ | client (nav hidden) + server `_owner_only_denied` |
| Clock / time entries | ✅ any | ✅ any | ✅ any | own entries | server (advisory — see G-05) |
| 📧 Email Route | any crew | any crew | any crew | forced to themselves | server |
| Tier A tools (`run_script`, `check_sms_inbox`, file tools…) | hidden in server mode for every role | | | | server allow-list `_srv_pa_allowed` |

A missing role in the `/pwa-login` reply makes the app treat the user as `field_crew` (safe default) — SRV-AUTH-05 checks the server always sends one.

#### 6.11.2 Suspected gaps (found reading the code — each gets an expected-to-fail test until decided)

| ID | Suspected gap | Test | If confirmed |
|---|---|---|---|
| G-01 | `build_daily_route`, `suggest_route_schedule`, `approve_route_schedule`, `unapprove_route_schedule` have **no crew scope** — a field_crew user can build/approve another crew's route | SRV-SCOPE-08 | ✅ **Confirmed → R-039** (2026-09-27, David: fix it; `prescreen_route_jobs` included) |
| G-02 | `read_job_spreadsheet` / `get_board_updates` only filter **Jobs_Schedule**; **TimeLog** and **Route_Planner** come back unfiltered for field_crew | SRV-SCOPE-06/07 | ✅ **Confirmed live → R-039** (SRV-SCR-06 06:52, SRV-SCR-07 07:18) |
| G-03 | `record_learning(supersedes_id=…)` can deprecate **another user's** learning | SRV-API-12 | ✅ **Confirmed in code → R-042** (2026-09-27; deployed ~16:00, verified live 20:13) |
| G-04 | `create_customer` ignores the locked-field rules; `create_job` accepts **any** Crew (a field_crew user can create a job for someone else) | SRV-SCOPE-09/10 | ✅ **David's decision (2026-09-27): allowed.** Field crew may create a job for anyone and add a new customer, including the locked fields (Frequency, Standard Quote, Discount…) — **only when creating it; after that those fields are locked for crew, even on a customer they created themselves** (David, 16:04); deleting customers stays owner / manager / staff only (already enforced in `delete_customer`). Current code already matches — no change. Locked in by `test_srv_crew_create.py`. **Closed (by design)** |
| G-05 | `log_time_entry` crew scope is advisory only — field_crew can log time on another crew's job | SRV-SCOPE-11 | ✅ **Confirmed live 2026-09-27 15:01** (Samual clocked in on Vicki's job: "⏱️ Clocked IN"). The code calls it deliberate ("Crew / Technician is scheduling reference, not access control" — e.g. helping on a co-worker's job). **David's decision (2026-09-27): keep — allowed.** A crew member helping on a co-worker's job logs their own time on it. SRV-SCOPE-11 now checks it works **and** the entry is under the person who clocked in. **Closed (by design)** |
| G-06 | `search_learnings` and `geocode_address` take no ctx — in server mode they may **fail with HTTP 400** through `/pwa-api` | SRV-API-10/11 | ✅ **Confirmed live → R-041** (SRV-API-01, 08:30 — HTTP 400 for every role); fixed, deployed, verified live 14:39 — **closed** |
| G-07 | `send_sms` / `email_invoice(to=…)` accept **any** recipient for any role | SRV-API-13 (recorded by the guard, nothing sent) | ✅ **David's decision (2026-09-27): allowed** — any role may text or email any recipient. Current behaviour; the test guard keeps real sends to David + Vicki only. **Closed (by design)** |
| G-08 | Per-user job databases ("Model B"): `_resolve_job_db_path` still picked `<state dir>\jobs_database\<uid>.db` for a user if that file existed, and `_job_crew_scope` still skipped the crew filter for a user's "own file" | — (SRV-DB dropped) | ✅ **David (2026-09-28): there is only one job database** — per-user files were the spreadsheet era. The leftovers were a latent risk (a stray file named after a user would silently give them a separate, empty set of jobs) → **R-046** removes them. **Closed** |
| G-09 | Profile "Code" row shows the literal text `local` in server mode (harmless, confusing) | SRV-SCR-09 | ✅ **Confirmed → R-040** (2026-09-27; fixed, deployed, verified live 08:23) |
| G-10 | Jobs app sessions (`/pwa-login` access tokens) **never expire** — they live in server memory until Sign Out or a restart. A copied session (shared/lost phone, old browser profile) keeps working indefinitely unless the user signs out on that device or the server restarts. Suspending or removing the user in users.json does cut it off (checked in code: every call re-resolves the user). Options: idle timeout (e.g. 30 days since last use), absolute lifetime, or keep as is | SRV-API-06 (found while building it, 2026-09-27) | ✅ **David (2026-09-27): 30-day idle timeout → R-043** (deployed ~16:00, verified live) |
| G-11 | **Job numbers are reused, and a deleted job's photo folder stays behind.** The next JobID is "highest existing + 1" (`db_write_ops.generate_next_id`), so deleting the newest job frees its number; `delete_job` doesn't touch `JobPhotos\<JobID>`. The next job created gets that number — and shows the deleted job's photos/files. Seen live 2026-09-27: every test run's jobs were JOB-0001 / JOB-0002 again, and uploads from one run sat in the next run's job folders. Options: delete/archive the photo folder when a job is deleted (e.g. move it to `JobPhotos\_deleted\JOB-0001_<date>`), and/or never reuse a number | SRV-SCOPE-12 (found while building it) | ✅ **David (2026-09-27): never reuse a number** ("that way you can review a cancelled job") **→ R-044** (deployed ~16:00, verified live) |
| G-12 | **A job re-assigned away from a field crew member stays on their open Board** until they tap refresh. The Board's 60-second poll only adds/updates rows that changed and are visible; a job that stops being visible never comes back to say "drop me". Same for a **deleted** job, for everyone. Your own change reaches another person's open Board in one poll (SRV-MULTI-01: 62 s) — only removals were missed | SRV-MULTI-02 (found live 15:17) | ✅ **→ R-045** (bug fix; deployed ~16:00, verified live 16:10) |
| G-13 | **Learnings have no per-user privacy.** `search_learnings` is on the Jobs app allow-list and takes no caller at all (`_sl.check_learned` searches the one shared store), so **any role — field crew included — can read every learning**, including the owner's. Editing/retiring is ownership-checked (R-042); *reading* is not. Same through a direct MCP connection | SRV-KB-03 (found 2026-09-28 09:10: a field crew search returned 20 hits, all recorded by other people) | ✅ **David's decision (2026-09-28): keep as is** — learnings are company-wide by design. SRV-KB-03 now checks it stays that way. **Closed (by design)** |
| G-14 | `get_route_drive_matrix` and `apply_route_order` had **no crew check** — R-039 covered the five other route tools but not these two, which are exactly what a Claude chat ("route today's jobs and email me the link") and the AI Routing run use. Field crew could read every crew's job addresses (drive matrix) or reorder another crew's day (blank crew = every crew) | found in code 2026-09-28 while reviewing server-mode AI Routing | ✅ **→ R-047** (fixed, awaiting deploy) |

Checked and **fine** in the code (tests confirm them rather than hunt): photo upload/delete scoping, `delete_route` / `delete_route_stop` / `reorder_route_stop` / `replan_route_day` scoping, `email_route_now` recipient forced for crew, `start_ai_routing` scoping.

#### 6.11.3 Setup on the server machine (one time)

1. Copy the `tests\` folder (incl. `gui_jobs_e2e\`) to the server machine and install the same Python + Playwright (§8.4).
2. **User file** `tests\gui_jobs_e2e\server\users.local.json` (git-ignored, never copied into artifacts) — names only, **no tokens**:
   ```json
   {"url": "https://<server tunnel>/jobs/",
    "users": [
      {"key": "U1", "name": "<login name>", "token_env": "AIPROWLER_SRV_TOKEN_U1"},
      ... six entries ...
    ]}
   ```
3. Tokens go in environment variables only (`setx AIPROWLER_SRV_TOKEN_U1 …`, one per user). The runner refuses to start if one is missing.
4. **Sandbox users:** the 6 real users are used for **reading and logging in**. Anything that writes uses ZTEST jobs assigned (Crew =) to the user under test, created and deleted by the **owner** session. If none of the 6 is a `field_crew` or `staff` user, create one throw-away `ZTEST Crew` user of that role in the Admin tab and remove it afterwards.
5. The personal-mode rules still apply: human mode, sandbox window, no real email/SMS, cleanup to 0 ZTEST rows, the §4.4 server-side-send handling (Email Route On Build switched off per call; on the server no real route email ever).

**Token / session hygiene (server mode is stricter):**
- Playwright **tracing and video are off** for server tests (a trace stores the page DOM and every request, including the `access_token`). Screenshots on failure stay on, with the login fields and Profile code row masked.
- Each user's saved login (`storage_state`, which holds the `access_token`) lives in a temp folder that is deleted at the end of the run and is never copied to `artifacts\`.
- Logs name users by `key` + name + role, never a token or access token (the existing log scrubber also scrubs every `AIPROWLER_SRV_TOKEN_*` value).

#### 6.11.4 Harness changes

| Piece | Change |
|---|---|
| `server\conftest.py` | Reads `users.local.json`; **pre-flight** logs every user in via `POST /pwa-login` (no browser), records each user's `role`, and prints a table: `U1 · Alice · owner`. Stops if a login fails or no owner is found |
| Fixture `as_user(role or key)` | Opens a **separate browser context** per user, logs in through the real login screen (name + token, typed in human mode), saves that context's session. Tests that need a role that doesn't exist are skipped with the reason |
| Fixture `owner_api` | Direct `/pwa-api` calls with the owner's access token — used for setup/cleanup of ZTEST jobs with Crew set to each user |
| Fixture `api_as(key)` | Direct `/pwa-api` calls as any user — for the permission matrix (SRV-API), still passing through the write guard |
| Write guard | Same classes; adds the **acting user** to every record. Scoped writes are allowed only on ZTEST rows, whoever makes them |
| Parametrise | Tests marked `@per_role` run once per role present; `@per_user` once per each of the 6 users |
| Marker | `jobs_gui_e2e_server` — never runs in personal-mode runs |
| Runner | `run_tests_gui_jobs_e2e.bat --server --human` (new `--server` flag selects `server\`, reads `users.local.json`, checks the token variables) |

#### 6.11.5 Test catalog

**Login & session — `test_srv_auth.py`**

| ID | Scenario | Verify |
|---|---|---|
| SRV-AUTH-01 | Each of the 6 users logs in (name + token) | Lands on Jobs; top bar shows their name; Profile shows their role; `ap_auth.mode = server` |
| SRV-AUTH-02 | Right token, wrong name (user A's token under B's name) | Refused, "Name or password not recognized"; no session saved |
| SRV-AUTH-03 | Wrong token / blank name | Refused, fields cleared |
| SRV-AUTH-04 | Name in different case / extra spaces | Behaviour recorded and matches what the Admin tab promises (decide expected result on first run) |
| SRV-AUTH-05 | `/pwa-login` reply | Always contains `role`; never contains the personal token |
| SRV-AUTH-06 | Sign out, then Back button | Login screen; `/pwa-api` with the old access token → 401 |
| SRV-AUTH-07 | Owner revokes/changes a user's token in the Admin tab while they're logged in (throw-away ZTEST user only) | Next call → 401 and the app returns to login |
| SRV-AUTH-08 | Owner changes a ZTEST user's role | After re-login the new role applies |

**Screens by role — `test_srv_screens.py`** (`@per_role`)

| ID | Scenario | owner | manager | staff | field_crew |
|---|---|---|---|---|---|
| SRV-SCR-01 | Bottom nav tabs | all incl. Reports | no Reports | no Reports | no Reports |
| SRV-SCR-02 | Typing `#reports` / calling the Reports tools directly | works | ❌ denied | ❌ denied | ❌ denied |
| SRV-SCR-03 | Database tab sheet list | all | all | all | no Settings / Services_Pricing / Quotes / Invoices |
| SRV-SCR-04 | Customers sheet | read + edit | read + edit | read + edit | read; edit only allowed fields on their customers |
| SRV-SCR-05 | Jobs / Board / Calendar lists | all crews | all | all | own ZTEST jobs only; another crew's ZTEST job absent |
| SRV-SCR-06 | Route screen crew picker / route shown | any crew | any | any | only their own route |
| SRV-SCR-07 | Clock screen | clocks in as themselves; open clock-in pick-up shows only their entry (R-025 carry-over) | | | |
| SRV-SCR-08 | Button sweep (BTN-JOBS/ROUTE/OTHER re-run per role) | no button errors; buttons that call a denied tool show a clear message, not a crash | | | |
| SRV-SCR-09 | Profile screen | name, role; "Code" row never shows a real token (G-09) | | | |

**Job-data scope (field_crew and staff) — `test_srv_scope.py`**

Setup (owner): ZTEST job **J-A** Crew = user under test, **J-B** Crew = another user, both on the sandbox date, same customer.

| ID | Scenario | Expected |
|---|---|---|
| SRV-SCOPE-01 | field_crew opens J-B by URL / job detail | Not shown ("not found" / no access) |
| SRV-SCOPE-02 | field_crew edits J-B via the API (`update_job_spreadsheet`) | ❌ refused; J-B unchanged |
| SRV-SCOPE-03 | field_crew deletes J-B / its route stop / reorders it | ❌ refused |
| SRV-SCOPE-04 | field_crew edits J-A (status, notes, completion) | ✅ works |
| SRV-SCOPE-05 | staff edits J-B | ✅ works (staff are unrestricted) |
| SRV-SCOPE-06 | field_crew reads **TimeLog** | Only their own entries (G-02) |
| SRV-SCOPE-07 | field_crew reads **Route_Planner** / `get_board_updates` | Only their own rows (G-02) |
| SRV-SCOPE-08 | field_crew builds / suggests / approves / un-approves **another crew's** route for the sandbox date | ❌ refused (G-01) |
| SRV-SCOPE-09 | field_crew `create_job` with Crew = someone else | Decision needed (G-04) |
| SRV-SCOPE-10 | field_crew `create_customer` filling locked fields | Decision needed (G-04) |
| SRV-SCOPE-11 | field_crew `log_time_entry` on J-B | ❌ refused (G-05) |
| SRV-SCOPE-12 | field_crew uploads / deletes a photo on J-B | ❌ refused; on J-A ✅ (R-028/R-029 carry-over for the server upload handler) |
| SRV-SCOPE-13 | 📧 Email Route as field_crew for another crew | Recipient forced to themselves (recorded by guard) |
| SRV-SCOPE-14 | Same address on two **different** crews' jobs | No duplicate-address prescreen error |
| SRV-SCOPE-15 | Owner routes every crew for the sandbox date | One route per crew; prescreen groups problems per crew |

**Tool permission matrix — `test_srv_api.py`** (`@per_role`, direct `/pwa-api` calls, all writes on ZTEST rows only, outbound calls recorded by the guard, nothing sent)

| ID | Check |
|---|---|
| SRV-API-01 | Every tool the PWA uses: call it once per role and record allowed / denied → the table is written to `artifacts\latest\server_role_matrix.md` and compared with §6.11.1. Any difference fails |
| SRV-API-02 | Tier A tools (`run_script`, `check_sms_inbox`, `write_file`, `read_file_lines`…) → refused for **every** role incl. owner (R-027 carry-over) |
| SRV-API-03 | `check_sms_replies` works where `check_sms_inbox` is hidden |
| SRV-API-04 | Blocked sheets for field_crew through every read/write tool (`read_job_spreadsheet`, `update_job_spreadsheet`, `export_to_csv`…) |
| SRV-API-05 | Owner-only tools refused for manager/staff/field_crew |
| SRV-API-06 | No access token / expired / another user's token → 401. **Built 2026-09-27 (`test_srv_api_tokens.py`), passes live 14:50:** no header, empty Bearer, Basic scheme, made-up token and one-character-changed session → 401 with no data; a signed-out session → 401 for all three users; Samual's own session can't borrow the owner's identity through arguments (`user`/`role` → HTTP 400; `ctx` → stripped, still refused) or headers (`X-User`/`X-Role`/`X-Forwarded-User` → ignored, still refused), with David's own session as the control. "Expired" is tested as "ended" because sessions have no expiry — see G-10 |
| SRV-API-07 | A tool not on the server allow-list → refused with a clear message (not 500) |
| SRV-API-10 | `search_learnings` in server mode → works, or HTTP 400 (G-06). **HTTP 400 at 08:30 (G-06 → R-041); works for all three roles after R-041, verified live 14:39.** |
| SRV-API-11 | `geocode_address` in server mode → works, or HTTP 400 (G-06). **HTTP 400 at 08:30 (G-06 → R-041); works for all three roles after R-041, verified live 14:39.** Probe address is now "Canal Street, New Smyrna Beach, FL 32168"; the old one (210 Sams Ave) isn't in OpenStreetMap, and a geocoder "Address not found" now counts as the tool having run, not a role refusal. |
| SRV-API-12 | `record_learning(supersedes_id=<another user's learning>)` → refused (G-03; uses a ZTEST learning made by a second user, deleted after) |
| SRV-API-13 | `send_sms` / `email_invoice(to=…)` with an arbitrary recipient — record which roles may do it (G-07) |

**Several users at once — `test_srv_multi.py`**

| ID | Scenario | Verify |
|---|---|---|
| SRV-MULTI-01 | Owner and a field_crew user logged in side by side (two windows) | Owner moves J-A on the Board → crew's Board shows it within one poll (≤ 60 s) |
| SRV-MULTI-02 | Owner re-assigns J-A to another crew | J-A disappears from the first crew's lists after refresh |
| SRV-MULTI-03 | Two users edit the same job | Second save gets the stale-version message (R-032 carry-over), no silent overwrite |
| SRV-MULTI-04 | All 6 users logged in at once, each loads Jobs + Board | No errors, each sees their own correct set; response times logged |
| SRV-MULTI-05 | Two users clock in at the same time | Two separate entries, each on the right person |

**Knowledge-base scope stays separate — `test_srv_kb.py`**

| ID | Scenario | Verify |
|---|---|---|
| SRV-KB-01 | A user whose KB scope excludes a folder still sees their jobs normally | Job data unaffected by KB scope |
| SRV-KB-02 | The Jobs PWA never offers document search tools to roles the allow-list excludes | Matches §6.11.1 |
| SRV-KB-03 | Field crew searches learnings through the Jobs app | Sees everyone's learnings — company-wide by design (G-13, David 2026-09-28: keep). Guards the decision: fails if learnings ever become private without the spec being updated |

**One job database.** Every server-mode user — every role — works in the one shared SQLite database, `<state dir>\jobs_database\ai_prowler_jobs.db`; field crew see their rows through the Crew / Technician filter, nothing else. Per-user job files (the old "Model B" `<user_id>.xlsx` of the spreadsheet era) no longer exist. The planned SRV-DB tests were dropped (2026-09-28); the code's leftovers from per-user files were removed as **R-046**.

#### 6.11.6 Order of work

1. Setup (§6.11.3) and the pre-flight table → David confirms the 6 users' roles.
2. SRV-AUTH, SRV-SCR (read-only, safest).
3. SRV-API-01 matrix (produces the evidence for G-01..G-07).
4. SRV-SCOPE, SRV-MULTI, SRV-KB.
5. David decides each G-### → becomes an R-### fix or an accepted rule (then the guide is updated).

Run commands (once built): `run_tests_gui_jobs_e2e.bat --server --human` (all), `… --server --human -k SRV_AUTH`, `-k SRV_SCR`, `-k SRV_API`, `-k SRV_SCOPE`, `-k SRV_MULTI`.

#### 6.11.7 Progress & regression commands (updated 2026-09-27)

**How it actually runs (differs from §6.11.3):** from **David's PC** against the server's public Jobs app (`AIPROWLER_SRV_URL`), not on the server machine. Suite folder `tests\gui_jobs_e2e_server\` (not `gui_jobs_e2e\server\`), so the personal suite's setup never touches the PC's database. Users in `tests\gui_jobs_e2e_server\users.local.json` (names only); tokens only in Windows user env vars `AIPROWLER_SRV_TOKEN_U1/U2/U3`. Fixes are deployed on the server with `update_install_server.bat` (copies from the server's shared work folder) + restart.

**Users (3):** U1 David Vavro — owner · U2 Vicki Vavro — manager · U3 Samual Cronin — field_crew (scopes sales, field). **No staff user yet** → staff columns not tested.

**Regression commands** (all human mode, run from `tests\`; each cleans up to 0 ZTEST rows; results in `tests\gui_jobs_e2e_server\artifacts\latest\SUMMARY.txt`):

| What | Command | Last result |
|---|---|---|
| **Whole server suite** | `run_tests_gui_jobs_e2e.bat --server --human` | — (run after each server deploy) |
| Login & session | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_auth` | ✅ 9/9 (2026-09-27 05:57) |
| Two users at once + owner-only screens | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_multi` | ✅ 4/4 (06:01) |
| Field crew restrictions | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_crew` | ✅ 6/6 (06:23) |
| Route / Clock / Profile per role (R-039) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_screens` | ✅ 6/6 (08:23) — SCR-06, SCR-07, SCOPE-08, SCR-09 ×3 |
| Button sweep per role (SRV-SCR-08) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_buttons` | ✅ 3/3 (08:17) — David 28 · Vicki 26 · Samual 22 buttons clicked, no JS errors / 5xx / "Unknown tool" / silent refusals |
| Board & Calendar per role (SRV-SCR-05) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_board_calendar` | ✅ 3/3 (08:29) |
| Role matrix (SRV-API-01/02/07/10/11) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_api_matrix` | ✅ (14:39) after R-041 deployed; again 16:07 after the R-042..R-045 deploy; every cell as §6.11.1. (08:30 ❌ was G-06 → R-041.) Table: `artifacts\latest\server_role_matrix.md` |
| Tokens & sessions (SRV-API-06) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_api_tokens` | ✅ 13/13 (14:50; again 16:01 after the R-042..R-045 deploy) — no browser windows; sessions it makes are signed out after |
| Sign-in & sessions (SRV-AUTH) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_auth` | ✅ 9/9 (16:06, after deploy; AUTH-05 needed Samual added to the test's role list) |
| Field crew create / delete (G-04) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_crew_create` | ✅ 3/3 (16:08) |
| Several people at once (SRV-MULTI-01/02/04/05) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_live_multi` | ✅ 4/4 (16:11, after deploy) |
| Crew vs another crew's job / stop (SRV-SCOPE-03, -11) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_scope` (also runs SCOPE-08) | ✅ SCOPE-03 5/5 (15:01 + stop tests 15:02), SCOPE-11 control ✅, SCOPE-11 xfail = G-05 confirmed live (David decides) |
| Email / SMS — safe (nothing sent) | `run_tests_gui_jobs_e2e.bat --server --human -k test_srv_comms` | ✅ 1 pass, 3 skip as designed (06:35) |
| Email / SMS — **REAL** to David + Vicki only | `run_tests_gui_jobs_e2e.bat --server --human --tier comms -k test_srv_comms` | ✅ 3 pass, 1 skip as designed (06:40 + COMMS-02 06:47): real text Vicki → David via Twilio; real receipt email → Vicki; texts/emails to anyone else stopped |
| Faster, no visible windows | add nothing / drop `--human` | same tests, headless |

**Built tests → spec IDs** (the file/test names are what `-k` matches):

| Test (file · function) | Covers spec | Status |
|---|---|---|
| `test_srv_auth` · SRV_AUTH_01 (×2: David, Vicki) | SRV-AUTH-01 | ✅ |
| `test_srv_auth` · SRV_AUTH_02 | SRV-AUTH-02 | ✅ |
| `test_srv_auth` · SRV_AUTH_03 (wrong token, blank name) | SRV-AUTH-03 | ✅ |
| (code reading) | SRV-AUTH-04 — names match ignoring case / surrounding spaces | ✅ answered |
| `test_srv_auth` · SRV_AUTH_05 | SRV-AUTH-05 | ✅ |
| `test_srv_auth` · SRV_AUTH_06 + SRV_AUTH_06b | SRV-AUTH-06 (06b found **R-038**, fixed + verified) | ✅ |
| `test_srv_auth` · SRV_MULTI_01 — two users side by side, one signs out, other unaffected | *new* (session independence; spec's SRV-MULTI-01 Board poll is still to build) | ✅ |
| `test_srv_multi` · SRV_MULTI_03 — same price, David then Vicki | SRV-MULTI-03 (R-032 with two real users) | ✅ |
| `test_srv_multi` · SRV_SCR_01 / SRV_SCR_02 | SRV-SCR-01/02 (owner vs manager) | ✅ |
| `test_srv_crew` · SRV_CREW_01 | SRV-SCR-05 (Jobs list) + SRV-SCOPE-01 | ✅ |
| `test_srv_crew` · SRV_CREW_02 | SRV-SCOPE-02 + SRV-SCOPE-04 | ✅ |
| `test_srv_crew` · SRV_CREW_03 | SRV-SCR-01/02 (field_crew column) | ✅ |
| `test_srv_crew` · SRV_CREW_04 | SRV-SCR-03 + SRV-API-04 (read) | ✅ |
| `test_srv_crew` · SRV_CREW_05 | SRV-SCR-04 (customer fields) | ✅ |
| `test_srv_crew` · SRV_CREW_06 | *new* — crew can't invoice another crew's job | ✅ |
| `test_srv_screens` · SRV_SCR_06 | SRV-SCR-06 + SRV-SCOPE-07 (Route_Planner scope) — found **R-039**, fixed + verified | ✅ |
| `test_srv_screens` · SRV_SCR_07 | SRV-SCR-07 (R-025 carry-over: Samual's clock-in is under his name) + SRV-SCOPE-06 (TimeLog scope) — found **R-039**, fixed + verified | ✅ |
| `test_srv_screens` · SRV_SCOPE_08 | SRV-SCOPE-08 (G-01 → **R-039**): all five route tools refuse field crew on another crew's route | ✅ |
| `test_srv_screens` · SRV_SCR_09 (×3 users) | SRV-SCR-09 — Profile "Code" row shows `local` (**G-09 → R-040**, fixed + verified) | ✅ |
| `test_srv_buttons` · SRV_SCR_08 (×3 users) | SRV-SCR-08 — every read-only button on every screen the role sees (the personal sweep's SAFE lists + Database tabs / Refresh / Hide Completed); write / send / credit buttons have their own tests. First run found that server mode's Messages → "Check replies" (`check_sms_replies`) **marks the user's texts as read** — the guard now records it instead of sending (`safety.py` `MARKS_READ`). **David's decision (2026-09-27): intended** — the replies are shown on screen, so the person who tapped has read them. The guard keeps recording it so an automated run never marks real messages read that nobody actually saw | ✅ |
| `test_srv_board_calendar` · SRV_SCR_05 (×3 users) | SRV-SCR-05 Board + Calendar (Jobs list part = SRV_CREW_01): owner/manager see both crews' ZTEST jobs; field crew only their own — on the Board, in its live-update feed (`get_board_updates`) and on the Calendar | ✅ |
| `test_srv_api_matrix` · SRV_API_01 | SRV-API-01 role matrix (33 read-only probes × 3 users, straight to `/pwa-api`) + SRV-API-02 (Tier A `run_script` / `check_sms_inbox` / `read_file_lines` / `write_file` → "Unknown tool" for every role incl. owner) + SRV-API-07 (made-up tool → clear 400, not 500) + SRV-API-10/11 (G-06 → **R-041**). Owner-only `find_stale_customers` refused for manager + crew; field crew refused all four blocked sheets via both read paths | ✅ (R-041 deployed + verified 14:39) |
| `test_srv_api_tokens` · SRV_API_06 (×13) | SRV-API-06 — bad / missing credentials (5 kinds) → 401; signed-out session → 401 (×3 users); field crew's session can't pose as the owner via arguments or headers (×4, with an owner-session control). Found **G-10** (sessions never expire) | ✅ |
| `test_srv_scope` · SRV_SCOPE_03 (×5), SRV_SCOPE_11 (+control) | SRV-SCOPE-03 — Samual (own session) tries `delete_job`, `delete_route_stop`, `reorder_route_stop`, `delete_route` (Vicki's crew) and `replan_route_day` (Vicki's crew) on Vicki's job/stop: each refused with a clear message, and the owner's read-back shows Vicki's job, her stop **and Samual's own stop** unchanged. SRV-SCOPE-11 — clock-in on Vicki's job **succeeds** (G-05, `xfail(strict)` until David decides); clock-in on his own job works. Building it found a **test-harness gap**: the server suite never gave the guard a route-stop lookup, so every stop-level action was blocked before reaching the server — fixed in `gui_jobs_e2e_server\conftest.py` (`owner_api` sets `guard.stop_resolver`, owner read, sandbox dates only) | ✅ |
| `test_srv_scope` · SRV_SCOPE_14 (+control), SRV_SCOPE_15 | SRV-SCOPE-14 — two jobs at the same address on **different** crews: prescreen raises no DUPLICATE_ADDRESS; control: same address on **one** crew is flagged, under that crew. SRV-SCOPE-15 — the owner routes each crew: each job gets exactly one stop, on its own crew's route; prescreen reports nothing for crewed jobs as "(unassigned)". **Updated 2026-09-29 for R-055** (a blank crew now means *the caller's own jobs*, for every role including the owner): the tests used to build/prescreen with crew blank and expected every crew — the full run 12:29 failed the control + SCOPE-15 ("No jobs scheduled … for crew 'David Vavro'"). They now name each crew explicitly (prescreen per crew; `build_daily_route(crew=…)` per crew). | ✅ 4 passed + 1 xfail (15:04); after the R-055 update `-k srv_scope` **PASS 13:02** (suite 17 passed / 3 skipped, 0 ZTEST rows left) |
| `test_srv_photos` · SRV_SCOPE_12, SRV_PH_08/09 | SRV-SCOPE-12 — Samual's upload to Vicki's job refused ("not assigned to you"); **accepted** uploads (his own job; owner/manager to any job) ran once at 15:10 and **passed**, but the server runs as its own Windows account (`C:\Users\AI-Prowler-Server\…\JobPhotos`), which this account can't reach to clean up — **8 small `*_ztest_photo.txt` files were left in `JobPhotos\JOB-0001` (6) and `JOB-0002` (2)**, to delete by hand. The accepted-upload tests now **skip** unless that folder is reachable (`E2E_SERVER_JOBPHOTOS`); refusal tests always run. SRV-PH-08/09 (server side of R-028/R-029, as the owner so the folder check — not the crew check — must stop them): `../`, `..\`, `JOB-0001/../../` and a made-up job number are all refused. No photo **delete** exists in the app, so nothing to test there. Found **G-11** | ✅ 6 passed, 3 skipped (15:12) |
| `test_srv_live_multi` · SRV_MULTI_01/02/04/05 | SRV-MULTI-01 — owner sets Samual's job In Progress; his untouched open Board shows it in the right column in **62 s** (one poll). SRV-MULTI-02 — owner re-assigns Samual's job to Vicki: gone from his Board + Jobs list after a refresh, but **stayed through the automatic update** → **G-12 → R-045**. SRV-MULTI-04 — David, Vicki and Samual signed in at once: each Jobs list + Board correct for their role; loads ≈0.7 s (Jobs) / 1.2 s (Board) each. SRV-MULTI-05 — Samual and Vicki clock in at the same instant (two threads): two separate TimeLog entries, each under the right person | ✅ 4/4 after deploy (16:11) — MULTI-02: re-assigned card gone from Samual's open Board after 62 s (R-045) |
| `test_srv_crew_create` · SRV_SCOPE_09, SRV_SCOPE_10, SRV_G04 | G-04 as decided by David. SRV-SCOPE-09 — Samual creates a job with Crew = Vicki: allowed. SRV-SCOPE-10 — Samual adds a customer with Frequency / Standard Quote / Discount filled in: allowed; then (with a job linking him to it) he may edit the gate code but **not** Frequency — "These Customers fields require staff/manager/owner access". SRV-G04 — Samual's `delete_customer` refused; customer still there. Note (David confirmed 16:10, intended): crew can't edit a customer they just added until it's linked to one of their jobs | ✅ 3/3 (16:08) |
| `test_srv_email_route` · SRV_SCOPE_13 (×2 + owner control) | 📧 Email Route: Samual asking for Vicki's route (or blank) is looked up as **his own** route ("no route is saved for … (samual cronin)"); the owner asking for Vicki's gets Vicki's. **Zero-send design:** asserts no route exists on the sandbox date before every call, so the server can only answer "Nothing to email" — the crew named in that reply shows whose route it used | ✅ 3/3 (20:10) |
| `test_srv_owner_only` · SRV_API_05 (×4 + owner control ×2) | `send_customer_reminders` (email + sms): manager and field crew → "Only the owner has access to this"; owner passes the gate. **Zero-send design:** every call passes an empty customer list, which can never send even if the gate were broken | ✅ 6/6 (20:10) |
| **Full server suite after R-042..R-045 deploy** (`--server --human`, safe tier, 20:15–20:36) | Every server-mode file in one run | ✅ **78 passed, 0 failed, 10 skipped** (21 min); cleanup 0 ZTEST rows left. Skips as expected: 3 comms (safe tier), 3 accepted-photo uploads (server photo folder unreachable), 2 SRV-API-12 (owner learning not set up), 2 AUTH-07/08 (no throw-away user). **Test-side bug found:** the SRV-API-12 *control* test didn't depend on the setup fixture, so it ran anyway and left 2 learnings ("ZTEST E2E R-042 crew original" / "… crew replacement") — deleted by hand 20:40; the control now takes the `owner_learning` fixture and skips with the rest |
| `test_srv_kb` · SRV_KB_01, SRV_KB_02 (×3 + page), SRV_KB_03 | SRV-KB-01 — each user's real scopes read from `/whoami` (owner/manager: field, office, ops, sales, shared, own private; **Samual: field, sales, shared, own private — no office/ops**); jobs still follow crew only (owner + manager see both ZTEST jobs, Samual his own). SRV-KB-02 — 14 document tools (`search_documents`, `read_document`, `grep_documents`, `reindex_*`, …) → "Unknown tool" for all three roles; the app page references none. SRV-KB-03 — found **G-13**: field crew's learning searches returned 20 hits, all recorded by other people (David: keep — now guards that decision) | ✅ 6/6 (09:23, 2026-09-28) |
| `test_srv_three_week_schedule` · SRV_SCHED_01..09 (11 tests; 07 added for R-055, 08/09 for R-055-all-roles + R-056 — see those rows) | **Realistic 3-week window-cleaning schedule** (David, 2026-09-28). David (owner) creates 10 ZTEST customers at real public addresses — New Smyrna Beach: 105 S Riverside Dr, 210 Sams Ave, 1001 S Dixie Fwy, 1 Flagler Ave, 201 Sports Complex Dr; Daytona Beach: 1200 Main St, 301 S Ridgewood Ave, 352 S Nova Rd, 1801 W International Speedway Blvd, 105 E Magnolia Ave — 5 Weekly, 5 Biweekly, each on its own weekday, no email/phone (nothing can be sent), and schedules 3 weeks of Window jobs: 25 jobs, 13 Samual / 12 Vicki. Vicki keeps her **manager** role but works as crew. SCHED-01 schedule exactly as planned (dates, crews, 7-/14-day repeats, addresses). SCHED-02 Samual sees exactly his 13; Vicki sees all of hers; both read every customer. SCHED-03 (×2) each crew member, in their own session, builds their own day-1 route, clocks in/out (entries under their own name), notes + completes the job. SCHED-04 (×2) each adds a job and edits a later own job; control: Samual can't edit Vicki's job, Vicki (manager) can edit his. SCHED-05 owner routes every other week-1 day inside the sandbox window per crew — each route holds exactly that crew's jobs. SCHED-06 (browser, visible in --human) Samual's and Vicki's Jobs screens each show their own work, Samual's none of Vicki's. Routes only on sandbox-window days; weeks 2–3 are scheduled and checked, not routed. Module-scoped data, swept before and after | ✅ **8/8** (17:27–17:28, 66 s, 2026-09-28): 10 customers / 25 jobs 09-28..10-16, day-1 routes built by Samual and Vicki themselves, owner routed 09-29..10-02 for both crews; cleanup removed 5 route days + 10 customers (cascading every job), 0 ZTEST rows left |
| **Full server suite after R-046 deploy** (`--server --human`, safe tier, 2026-09-28 09:48–10:09) | Every server-mode file in one run | ✅ **83 passed, 0 failed, 11 skipped** (20.6 min); cleanup 0 ZTEST rows left, no stray learnings (the SRV-API-12 control now skips with its setup). Skips as expected: 3 comms (safe tier), 3 accepted-photo uploads (photo folder unreachable), 3 SRV-API-12 (owner learning not set up), 2 AUTH-07/08 (no throw-away user) |
| **Full server suite after R-047..R-051 deploy** (`--server --human`, safe tier, 2026-09-28 14:13–14:34) | Every server-mode file in one run — first run with R-047 (route matrix/apply crew rule), R-048, R-049 (tool panel honoured by the Jobs app), R-050 (field crew export/backup/restore refused), R-051 live | ✅ **83 passed, 0 failed, 11 skipped** (21.2 min); cleanup 0 ZTEST rows left. Same 11 expected skips as above. Nothing regressed from the tool-panel or role changes |
| **Full server suite after R-052..R-054 deploy** (`--server --human`, safe tier, 2026-09-28 16:09–16:30) | Every server-mode file in one run, with default Settings rows seeded (R-052 — verified live 16:09: the 16 rows appeared, edited by "system", invoicing values untouched), Outlook email UI in server mode (R-053) and the no-launch page load (R-054) | ✅ **83 passed, 0 failed, 11 skipped** (21.2 min); cleanup 0 ZTEST rows left. Same 11 expected skips |
| **Full server suite with the 3-week schedule test** (`--server --human`, safe tier, 2026-09-28 17:33–17:56) | Every server-mode file, now including `test_srv_three_week_schedule` (+8) | ✅ **91 passed, 0 failed, 11 skipped** (22.3 min); cleanup 0 ZTEST rows left. Same 11 expected skips; the 3-week module ran alongside the rest without interference |

**Still to build, in the spec's order (§6.11.6):**
1. ~~SRV-SCR-05, SRV-SCR-06, SRV-SCR-07, SRV-SCR-08, SRV-SCR-09~~ (all built 2026-09-27).
2. ~~SRV-API-01, -02, -06, -07, -10, -11~~ (built 2026-09-27); still to build: SRV-API-03 (`check_sms_replies` — marking read is intended, David 2026-09-27; test only on a throw-away ZTEST user's thread so no real message is marked), ~~-05~~ (built 20:10, `test_srv_owner_only.py`, empty-list no-send design), ~~-12~~ (built 20:13, `test_srv_learnings.py`; needs the owner learning "ZTEST E2E R-042 owner learning" created first and every "ZTEST E2E R-042 …" learning deleted after — done as the owner, since the Jobs app can't delete learnings). ~~-13 (G-07)~~ closed by David's decision (any role may text/email anyone).
3. ~~SRV-SCOPE-03, -06/07 (G-02), -08 (G-01), -09/10 (G-04), -11 (G-05), -12 (photos), -14, -15~~ ~~-13~~ (all built 2026-09-27; -13 = `test_srv_email_route.py`, 20:10).
4. ~~SRV-MULTI-01, -02, -04, -05~~ (built 2026-09-27, `test_srv_live_multi.py`; -03 is `test_srv_multi.py`).
5. SRV-AUTH-07/08 — **written 2026-09-27, `test_srv_ztest_user.py` (guided; not yet run)**: needs a throw-away user "ZTEST E2E User" (field_crew) added in the Admin tab and its token in `AIPROWLER_ZTEST_USER_TOKEN`; skipped otherwise. During the run David changes its role to staff (AUTH-08), then revokes it (AUTH-07); the test polls up to 5 min per step. SRV-API-03 (check replies on that user's own thread) would also need a real reply text to it — not built. (David 2026-09-28: skip AUTH-07/08 for now.) ~~SRV-KB-01/02~~ (built 2026-09-28, `test_srv_kb.py`, + SRV-KB-03 → G-13, closed by design). ~~SRV-DB~~ dropped 2026-09-28 — there is only one job database (David; code leftovers removed as **R-046**).
6. ✅ **Real email / SMS on the server — built 2026-09-27** (`test_srv_comms.py`, `--tier comms`, §4.3; David's decision: David + Vicki only). SRV-COMMS-01 safe tier sends nothing · -02 real **receipt email** to Vicki (the Jobs app has no general `send_email` — its server allow-list answers "Unknown tool", so email is tested through the app's own receipt feature) · -03 real **text** Vicki → David (Twilio SID confirmed) · -04 comms tier still stops texts/emails to anyone else and `email_invoice` without an explicit David/Vicki address. **G-07 evidence:** any role can text a saved contact by *name* (the server looked David's phone up from the user list) — allowed by David's decision (2026-09-27): any role may text or email anyone.

### 6.12 Price list (Services_Pricing) — `test_price_list.py`

Users maintain the price list themselves (Database tab → Services_Pricing), so add / change / delete get full coverage. Test codes are named `ZTEST-…`; cleanup deletes every `ZTEST-` code (case-insensitive) at module end and in the final sweep. Cases marked **(open)** reproduce bugs found on 2026-09-25 that aren't fixed yet; they're expected to fail until the fix lands, then become permanent regressions.

| ID | Scenario | Verify |
|---|---|---|
| PR-01 | Add an entry with every field (code, category, name with "&", base price, unit basis, min charge, commission, tax category, notes) | UI: row appears; DB: all 9 fields read back exactly; Version 1 |
| PR-02 | Add with a code that already exists | Refused with "use update instead"; nothing written |
| PR-03 | Add `ztest-win` when `ZTEST-WIN` exists (case-only difference) | Refused as a duplicate. *Found 2026-09-25 (was accepted); fixed & verified live 2026-09-25 (R-010)* |
| PR-04 | Add with no code / all-spaces code | Refused: "'Service Code' is required and cannot be blank"; nothing written |
| PR-05 | Change price and notes | DB updated; other fields untouched; Version +1 |
| PR-06 | Change with an out-of-date version (someone else saves while this Edit form is open) | Refused, "reload and try again", names who/when; the other person's change survives. *Found 2026-09-26 via the UI (silently overwritten); fixed & verified live (R-032)* |
| PR-07 | Change a code that doesn't exist | Clear "not found" |
| PR-08 | Change code `ztest-win` when `ZTEST-WIN` also exists | Edits **exactly** `ztest-win`; a partial text matching several codes is refused, listing them. *Found 2026-09-25 (silently edited `ZTEST-WIN`); fixed & verified live 2026-09-25 (R-011)* |
| PR-09 | Change code `1` when codes `1` and `10` both exist | Edits exactly `1`. Same root cause as PR-08 (fixed, R-011) |
| PR-10 | Enter `abc` as Base Price, Min Charge, or Commission | Refused with "must be a number"; `$1,200` accepted and stored as 1200. *Found 2026-09-25 (stored as text); fixed & verified live (R-012)* |
| PR-11 | Enter a negative Base Price / Min Charge | Refused. *Found 2026-09-25 (−50 accepted); fixed & verified live (R-012)* |
| PR-12 | Delete without confirm | Preview names the exact row; nothing deleted |
| PR-13 | Delete with confirm | Row gone; safety backup path reported |
| PR-14 | Delete a code that doesn't exist | Clear error |
| PR-15 | Delete uses the exact code | Deleting `ztest-win` removes only that row, never `ZTEST-WIN` (verified correct 2026-09-25) |
| PR-16 | Deleting a price that a job/invoice already used | Job and invoice keep their own copied amounts (documented: no link back to the price list) |

### 6.13 Security — `test_security.py` (runs FIRST in every suite run)

Found 2026-09-25: in personal mode `/pwa-token` handed the Bearer Token to anyone, both PWAs "logged in" by comparing against that copy in the browser, and `/pwa-api` / `/photos/upload` needed no token. Fixed the same day (server-side `/pwa-verify`, token required on every request). These cases talk to the **public address with plain HTTP, outside the browser** — exactly what a stranger could do — plus the browser-side login. They are read-only (only `check_ai_prowler_status`) and never log the token. Standalone version: `tests\live_security_check.py`. **If any SEC case fails, the runner stops the whole run** — nothing else should run against an unprotected server.

| ID | Scenario | Verify |
|---|---|---|
| SEC-01 | `GET /pwa-token` | 200, `token` field **empty**; mode + owner name present |
| SEC-02 | `POST /pwa-api` with **no** token | **401**, no tool ran |
| SEC-03 | `POST /pwa-api` with a **wrong** token | **401** |
| SEC-04 | `POST /photos/upload` with no token | **401**, nothing saved |
| SEC-05 | `POST /pwa-verify` wrong token / right token | **401** (after ~1 s) / **200** |
| SEC-06 | `POST /pwa-api` with the right token | 200, `ok: true` |
| SEC-07 | Jobs app login screen, wrong token | Refused; the page never received the real token (no `/pwa-token` response contains it; `BEARER_TOKEN` empty) |
| SEC-08 | Jobs app, saved session with a token that's since been rotated (simulated with a token the server refuses — rotating the real one would break everything else) | First API call → 401 → back to the login screen, dead session removed; logging in again works ✅ |
| SEC-09 | Remote PWA login (`/remote/`) wrong / right token | `/remote-api` without / with a wrong token → 401; wrong token refused (field cleared, nothing saved); right token boots; reload resumes only after the server's `/pwa-verify` says 200; a stale saved token → 401 → login screen, session removed ✅. The Remote app's own `/remote-api` calls are answered in the browser (the Jobs write guard doesn't cover them) |
| SEC-10 | Static files: `/jobs/../remote/index.html`, `/jobs/..%2F..%2Fconfig.json`, a sibling-prefix folder path | 403 or 404 — never another folder's file |
| SEC-11 | *(server mode — deferred)* `/pwa-api` with no/other user's token | 401 / crew-scoped |

---

### 6.14 Getting-started wizard — `test_wizard.py`

The wizard (🧙 next to "+ Add" on the Jobs screen) is 12 steps whose middle steps **are the app's typical day**: *add a customer → record a quote → add a job → build the route → clock in & out → add photos / text the customer → invoice → send the receipt*. Step titles are read from the running app (`WIZ_STEPS`), so editing the wizard doesn't make the tests stale. Run: `run_tests_gui_jobs_e2e.bat --human -k WIZ`.

| ID | Scenario | Verify | Status |
|---|---|---|---|
| WIZ-01 | Open from the Jobs screen | Modal open at "STEP 1/12", first title, rail 12 dots (1 current), **Next** + **Skip** shown, no **Back** | ✅ |
| WIZ-02 | **Next** through every step, **Done** on the last | Tag, title, rail (done/current dots) correct at each step; "🎤 Try saying" on steps with a voice example; **Back** from step 2 on; last step shows **Done**, hides **Skip**; Done closes | ✅ |
| WIZ-03 | **Back** | Returns to the previous step | ✅ |
| WIZ-04 | **Skip for now**, then reopen | Closes; reopening starts again at step 1 | ✅ |
| WIZ-05 | Tap outside the wizard | Closes | ✅ |
| WIZ-06 | Step 1's day plan | Exactly: customer, quote, job, route, clock in & out, photos, invoice, receipt | ✅ |
| WIZ-07 | Every place the wizard sends a user exists | Route and Job Board screens; Database screen's **Customers**, **Quotes**, **Pricing** and **Commands** tabs; "+ Add" on the Jobs screen | ✅ |
| WIZ-10 | **Typical day, following the wizard in the real UI** — one test step per wizard step: add a ZTEST customer → record a quote → add the job from it → build the route → open the job, clock in, clock out → add a photo (text-customer: recorded, not sent) → create the invoice → send the receipt (recorded, not sent) | Each step checked on screen **and** in the database | ✅ Done 2026-09-26 — `test_typical_day.py` (see §0) |

### 6.15 Button sweep — `test_buttons.py`

Simple, systematic: **every button on a screen is clicked for real** and checked for the reaction it should cause. Each button is classified **SAFE** (opens / refreshes / navigates), **WRITE** (changes test data on the sandbox date) or **GUARDED** (AI credits / outbound email — clicked for real, but the write guard *records* the call instead of letting it reach the server; the test checks it was the right call with the right date). Run: `run_tests_gui_jobs_e2e.bat --human -k BTN`.

| ID | Scenario | Verify | Status |
|---|---|---|---|
| BTN-00 | **Inventory**: every visible clickable on every screen (label, id, data-testid, title, function called) | Writes `buttons_inventory.json` to the run folder — the list sweeps are built from, and a diff between runs shows what changed | ✅ |
| BTN-COVERAGE | Jobs and Route screens: every button found must be classified in the sweep | **Fails if a screen gains a button nobody tested** — new buttons can't slip past | ✅ |
| BTN-JOBS | 🧙 → wizard opens · **+ Add** → new-job form opens/closes · ↻ → job list reloads (right number of cards) · job card → that job opens, tap outside closes · **Route Today** → today's route built (checked on the Route screen) · **AI Route** → `start_ai_routing` for today, recorded not run · **Email Route** → `email_route_now` for today, recorded not sent | as listed | ✅ |
| BTN-ROUTE | ↻ → reloads · **Route Selected Date** → route with both jobs · **AI Route** / **Email Route** → recorded, right date · map **+ / −** → the map's real zoom level goes up / down · map **🏠 / 🏁** markers → respond without errors · **✏️ on a job that isn't a stop yet** → opens that job | as listed | ✅ (all 17 BTN tests pass in `--human`, 2026-09-26) |
| BTN-OTHER | Board, Calendar, Clock, Photos, Messages, Reports, Profile (`test_buttons_other.py`) | **Coverage** per screen (fails on any unclassified button) · Board ↻ → both cards · Board card → that job's edit form · Calendar ↻ · Calendar job chip → that job (not the day) · day with jobs → its job list, tap outside closes · empty day → Add Job with that date · Clock In / Out → TimeLog entry opened and closed · 📷 Add Photos / 📎 Add Files → the file picker opens, pick counts · ⬆ Upload → saved (test file removed after) · 💬 Send → `send_sms` recorded, not sent · 🔄 Check → replies load · Reports ↻ · 🔍 Find Customers → results, no error · Sign Out → login screen, session removed | ✅ (22 pass, 2026-09-26) |
| BTN-DB | Database screen | Covered by §6.16 (`test_database.py`): table cells aren't clickable, every per-row and toolbar button is exercised there | see §6.16 |

*Found 2026-09-26:* the 4 GUARDED tests passed headless but failed in `--human` mode. Real cause: the app's **service worker** had taken control of the page, so its API requests bypassed the write guard entirely (R-015) — not the tests' waiting method, which was changed first and didn't help. Fixed by blocking service workers in test browsers, plus a bypass alarm. The guarded tests now also wait on the actual network request and log a step line before and after each click.

### 6.16 Database screen — `test_database.py`

The owner's view of every table: 9 tabs, **+ Add** / **Edit** / **Delete**, and each tab's own filters. Every change is checked on screen **and** read back from the database. The Pricing tab has its own file (§6.12). Settings are only opened here, never saved; the three email/SMS toggles are flipped (and put back) by `test_settings_toggles.py` — SET-01 flips each one in the Settings screen and back, read back from the database each time; SET-02 checks every other setting, a non-on/off value and a changed note are still blocked (§4.6). Run: `run_tests_gui_jobs_e2e.bat --human -k test_database`.

| ID | Scenario | Verify | Status |
|---|---|---|---|
| DB-01 | Open every tab | Each loads without error; **+ Add** only on Jobs/Customers/Invoices/Quotes/Pricing; each tab's own controls (Show Inactive, Show Declined + quote search/range, Hide Completed + sort, TimeLog search/range, Invoice search/range/Unpaid) appear **only** on that tab; Settings card and Commands list render | ✅ |
| DB-02 | ↻ after another device adds a row | New row appears | ✅ |
| DB-03 | **+ Add** a customer whose name has `'`, `&` and `<b>` | No CustomerID box (auto-assigned); saved exactly; shown as text (no HTML); Edit form shows the same name | ✅ |
| DB-04 | Edit a customer (phone, gate notes) | DB updated; other fields untouched | ✅ |
| DB-05 | Edit form: the row's own ID (CustomerID / Service Code) | Shown locked, not an editable box. *Found 2026-09-26 (editable, change silently ignored) — R-033, fixed & verified live* | ✅ |
| DB-06 | Stale edit on Customers (another device saves while the form is open) | Refused, the other change survives. *Found 2026-09-26 (silently wiped) — R-034, fixed & verified live* | ✅ |
| DB-07 | Customer → Inactive → hidden; **Show Inactive** → Delete (Cancel, then OK) | Active rows have no Delete; hidden by default; Cancel keeps it; OK deletes it (DB) | ✅ |
| DB-08 | **+ Add** a quote with the customer picker, then Delete | Name follows the picked customer; saved with the right CustomerID; Delete removes it | ✅ (first run failed on a harness gap: the guard didn't register `NEW_QTE_ID` — fixed) |
| DB-09 | Quote filters | Declined hidden until **Show Declined**; a 40-day-old quote hidden until **All time**; search narrows / "matching …" message | ✅ |
| DB-10 | Jobs tab | Completed hidden by default, **Show Completed** reveals; sort Soonest first / last; Delete only on the Cancelled job, deletes only it | ✅ |
| DB-11 | TimeLog | No + Add; the entry shows; search narrows and clears | ✅ |
| DB-12 | Route tab: **Delete Stop**, then **Delete Route** | Only that stop goes; then the whole day; the jobs stay | ✅ |
| DB-13 | Invoices: Unpaid Only, search, **+ Add** job picker | Picker lists un-invoiced Scheduled **and Completed** jobs, not invoiced or Cancelled ones. *Found 2026-09-26 (picker always empty) — R-035, fixed & verified live* | ✅ |
| DB-14 | Settings: tap a setting, close without saving | Form opens with a Value field; nothing written | ✅ |

### 6.17 Six-week schedule + customer reminders (personal mode) — `test_six_week_schedule.py`

Requested by David 2026-09-28. **David Vavro** (personal mode = the owner, one person) creates **15 ZTEST customers at real public addresses** — New Smyrna Beach (8): 105 S Riverside Dr, 210 Sams Ave, 1001 S Dixie Fwy, 1 Flagler Ave, 201 Sports Complex Dr, 300 Canal St, 115 Canal St, 3500 S Atlantic Ave; Daytona Beach (7): 1200 Main St, 301 S Ridgewood Ave, 352 S Nova Rd, 1801 W International Speedway Blvd, 105 E Magnolia Ave, 100 N Beach St, 250 N Atlantic Ave — **8 Weekly, 7 Biweekly**, three per weekday at 9:00 / 11:00 / 1:30, no email/phone. He schedules **6 weeks of Window jobs: 8×6 + 7×3 = 69 jobs**. Module-scoped data, swept before and after; routes only on sandbox-window days. Note: this harness runs the browser tests before the API-only ones, so each browser test makes whatever it needs itself.

| ID | Scenario | Expected | Status |
|---|---|---|---|
| PSCHED-01 | Schedule exactly as planned | 15 customers, 69 jobs; dates, Window service, crew David; Weekly every 7 days ×6, Biweekly every 14 ×3, always the same weekday; ≤3 jobs a day, no weekends; 8 NSB + 7 Daytona addresses, Frequency set, no contact details | ✅ |
| PSCHED-02 | Calendar, next 2 weeks (browser) | Every schedule job in the next 14 days is a chip on its own day's row | ✅ |
| PSCHED-03 | Work day 1 | Clock in/out and Complete + note on each of today's jobs; statuses Complete, one time entry per job | ✅ |
| PSCHED-04 | Route every in-window workday | `build_daily_route` (accepting the faster order) per day; each route holds that day's jobs and nothing outside the schedule | ✅ |
| PSCHED-05 | Jobs screen + Route tab (browser) | The Jobs screen lists the schedule; the Route tab for the 2nd workday shows exactly that day's 3 stops | ✅ |
| REM-01 | Who is due (60 days) | Lapsed (last Complete job 90 days ago) and "Reminder To David" (75) listed, most-overdue first; Recent (10 days) not; **Inactive never**; day-1 customers (serviced today) not; the other schedule customers "never serviced — no contact on file". A job counts as service only when its status is exactly `Complete` | ✅ |
| REM-02 | Threshold boundary | 10 days since service is due at 10, not at 11; 90 due at 90, not 91; Inactive not even at 0 | ✅ |
| REM-03 | Reports → Customer Reminders (browser): tick only Lapsed → ✉️ Email Selected | The guard lets it through (no email on file — nothing can be sent); the **server** replies "emailed to 0 … no email on file" | ⏭ skipped 21:11 — Settings "Customer Reminder Email Enabled" is **Disabled** on the personal database, so the app shows "✉️ Email Disabled" (correct behaviour). Turn it on to run |
| REM-04 | Same, only "Reminder To David", custom message with {name}/{date} | Tier safe: recorded, not sent — the recorded call carries that customer, channel email and the custom message. Tier email/full: **the one real reminder of the run, to David's own address** (`AIPROWLER_E2E_COMMS_TO`) — "emailed to 1 customer(s)" | ⏭ skipped (same setting) |

**Guard change (2026-09-28):** `send_customer_reminders` looks each recipient up server-side, so the guard now resolves the customers first (`customer_resolver`, set by `conftest.py`): allowed only when every id is a ZTEST customer this run created AND either none has a contact for the channel (nothing can be sent), or — tier email/full/comms — it is ONE customer whose contact is David's or Vicki's (max 1 real reminder per run). Anything else stays recorded.

**Results:** 21:07 run 6/9 — two test-side fixes (browser tests run first, so PSCHED-05 builds its own route; the Email button is found by its action and a disabled channel skips with the reason). 21:11 run ✅ **7 passed, 2 skipped**, cleanup 0 ZTEST rows left.

### 6.18 Route mileage — `test_route_mileage.py` (personal mode, R-063)

David 2026-09-29 05:42: "test the routing (non-AI Routing and AI-Routing) and determine if the total miles driven is correct for both route modes". Three ZTEST jobs on the sandbox date (same places as ROM); Settings → Route Origin Mode is switched per case and Email Route On Build is switched off (both put back after every test, R-060/R-061).

**What "correct" means.** Company Location: business → jobs → business; the business start row has no leg into it; the last row is back at the business. Jobs Only: home → jobs → home; home is not a start stop — the first job's own leg is the drive from home; a hidden "Home" row at the end holds the drive back (no Home row = the drive home isn't counted = FAIL). The day's total = the sum of every row's Drive Miles, and the day must end where it started.

**How it's judged (independent of the app).** Every leg is looked up again by the test itself, straight from the public OSRM road map for the same two points (±0.05 mi + 2 % per leg, ±0.15 mi + 1 % for the day), and must not be shorter than the straight-line distance (−5 %). A leg with no miles stored is a FAIL ("left out of the total"). The per-leg table (app / road / straight line) goes to the run log. If this PC can't reach OSRM the test skips (not judged) instead of failing.

| ID | Case | Pass criteria |
|---|---|---|
| MILES-01 [company, jobs_only] | Route Today (`suggest_route_schedule`, API) | all legs + day total correct, as above |
| MILES-02 [company, jobs_only] | Route tab (human mode): route the day, then press ↓ on the first job (`reorder_route_stop`) | the order really changed; every leg recomputed for the new order and correct; the shown total (after Refresh) = the sum of the legs. (First written against `apply_route_order` — the Jobs-app API answers "Unknown tool": only the AI worker calls it, so that writer is covered by MILES-04.) |
| MILES-03 [company, jobs_only] | Route tab (human mode): Route Selected Date | legs correct; the total the person sees (Company: the last stop's "Total …/N mi"; Jobs Only: the End line's "Total for the day") = the sum of the legs (±0.1 mi); the first job shows a non-zero "Drove …" |
| MILES-04 [company, jobs_only] | **Real AI Routing** (`start_ai_routing` → Claude worker → `apply_route_order`), then the Route tab | `--tier full` only (uses Claude credits; skipped otherwise); finishes ✅ within 15 min; all 3 jobs placed; legs + total correct; the Route tab total matches |

### 6.19 Time machine — six weeks lived day by day (`tests\gui_jobs_timemachine`)

David 2026-09-29 08:51: "make a test like the 6 week test and simulate the passing of days so that the full jobs features show up through time". The live-server six-week test (§6.x PSCHED) can only schedule *into* the future; the features that depend on days actually passing — the recurring-job sweep, overdue invoices, stale-customer reminders, the morning briefing, multi-day jobs, a job that overruns — only show up if the clock moves. So this suite runs **its own copy of the app with a fake clock** and walks it through six weeks.

**Run — both modes (David 2026-09-29 09:39: "make sure you test both the Jobs server and jobs personal modes with the time machine testing"):**
- personal: `tests\run_tests_gui_jobs_e2e.bat --timemachine --human [--no-open]`
- server: `tests\run_tests_gui_jobs_e2e.bat --server --timemachine --human [--no-open]` — the time machine's own copy runs as a Business **server** install; it never talks to the real AI-Prowler Server (with `--timemachine`, `--server` picks the mode of the throwaway copy, not the live server suite).

Marker `jobs_gui_timemachine`, excluded from normal runs. Needs `time-machine` (installed by `install_gui_jobs_e2e_deps.bat`). Results: `tests\gui_jobs_timemachine\artifacts\<personal|server>\latest\SUMMARY.txt` (mode + outbox counts). No-browser self-check: `tm_smoke.py` → `tm_smoke_report.txt`.

**Server mode — a made-up company inside the sandbox.** `tm_server.py --mode server` writes a Business/server `config.json` with `test_mode: true` (the app's own sandbox switch: no license network calls; login, roles and crew scoping run for real) and a `users.json` with four made-up users — ZT Owner (owner), ZT Manager (manager), ZT Crew Alex and ZT Crew Bea (field_crew), all `@time-machine.test` / `+1555…` — and starts `_run_server_mode`. The suite logs each one in through `/pwa-login` like the app does and works as that person: Alex does customers A, C, E; Bea does B, D, F.
- **Setup** as the owner; the **recurring sweep's new visits** are assigned a crew and booked by the **manager** (the sweep creates them with no crew — checked).
- **Every morning, each crew as themselves**: sees its own jobs and none of the other crew's (Jobs sheet), presses Route Today (routes only its own day, stops = exactly its jobs); the owner then sees both crews' stops = the day's jobs. The morning-briefing email is a personal-mode desktop feature, so server mode checks the crews' own views instead.
- **Work**: each crew clocks in/out and completes its own jobs as itself; TM-07 checks every time entry is stamped with the crew that did the job and that a crew reads only its own time entries.
- **Browser**: TM-02 and TM-04 are logged in as Alex (his stops shown, none of Bea's; the overrun job on Thursday); TM-06 as the owner (Reports).
- **Overdue invoice**: the overdue *alert* is the desktop scheduler's (personal). Server mode tries the owner's AR aging report — the Jobs app's server API has none ("Unknown tool"), so the run records **GAP G-TM-1: in server mode nobody is told about an overdue invoice** (David to decide whether the server Jobs app should get an overdue view/alert) and checks the unpaid invoice is still on the Invoices sheet.

**Added after R-068/R-069 (2026-09-29 11:00):** a staff user (ZT Office Sam) joins the made-up company. **TM-05b** — Sam signed in on day 0 and never used the app; on day 39 his session answers 401 "Session expired" (R-043's 30-day idle rule, checked on the simulated clock) and signing in again works. **TM-06 / 06b / 06c / 06d** — the Reports screen as owner (AR card with the 38-day invoice, charts, Customer Reminders with send controls), manager (AR card + list only), staff (list only), field crew (no Reports tab). **TM-07** — the same rules through the API (AR: owner+manager; list: owner+manager+staff; send: owner only). Server run 11:00 → **11/11 PASS**.

**Results 2026-09-29:** personal 7/7 PASS (09:40, found R-067 on the way); server 7/7 PASS (09:57, 6 min 50 s) — for six simulated weeks each crew saw only its own jobs and routes, the manager booked every sweep visit, the overrun carried to Alex's Thursday route, every time entry carried the right crew, 20 emails caught in the outbox, nothing real sent.

**Safety — nothing real is touched:**
- `tm_server.py` starts the work-copy app in-process with `HOME`/`USERPROFILE`/`Path.home()` = `<run folder>\sandbox_home` and `AIPROWLER_TEST_STATE_DIR` = its `.ai-prowler` — a brand-new empty database, settings, email and SMS config (R-066 made the SMS config honour this). It refuses to start on the real home folder or on any folder without its `TIME_MACHINE_SANDBOX` marker.
- Email goes to a fake SMTP host and SMS/WhatsApp to fake backends; everything "sent" is recorded in an **outbox**, and the run fails if anything is addressed outside the test addresses (`@time-machine.test`, fake numbers). All other network calls are blocked except the public OSRM/Nominatim map lookups and localhost. AI Routing is switched off (it would start a real Claude session); weather is stubbed.
- The live Jobs server, David's database and the real calendar are never used; nothing needs cleaning up afterwards (the sandbox folder is thrown away with the run folder).

**The clock:** the server runs under `time_machine.travel(..., tick=True)` and a small control API (`/clock` move-to, `/run` a scheduler job such as `morning_briefing` / `overdue_invoice_alert`, `/outbox`, `/state`, `/stop`). The browser gets the same date through Playwright `page.clock.install(...)`, so the app's own "today" in the page agrees with the server. Day 0 = the next Monday (first run: Mon 2026-10-05); the walk ends Fri of week 6 (D0+39). The once-a-day hooks (recurring sweep, stale-customer digest) fire on the first read of each new day, exactly as in the field.

**The world (all names start "ZT "):** A Riverside Cafe — Weekly, Mon; B Library Annex — Biweekly, Tue; C Flagler Ave Shops — Weekly, Wed; D Sports Complex — Monthly, Thu; E Canal Street Gallery — one visit, Wed, then never again; F Beachside Condos — one 3-day job starting Thu. Settings: Company Location start 210 Sams Ave, Stale Days 21, stale digest on, recurring lead 5 days. A test-side **oracle** (`World`) knows, for every day, which jobs should exist, be due and be on the route.

**Each working day:** open the app/API as that morning → the sweep's new visits must appear on the expected day with the right "due ~date" (weekly +7, biweekly +14, monthly = same day next month; a weekend due date is booked on the Monday) → the morning briefing must name exactly the expected jobs → Route Today's stops must be exactly the expected job IDs → the crew logs time and completes (or, once, leaves one In Progress) → the day's stale-customer list is recorded.

| ID | What | Pass criteria |
|---|---|---|
| TM-01 | Day 0 setup (API): settings, 6 customers, first jobs | all created in the sandbox; the 3-day job starting Thu has End Date = the following Mon (weekend skipped) |
| TM-02 | Day 1 in the browser (human mode) | board/Route tab show the day's jobs at the fake date; invoice for A's first visit created with 1-day terms |
| TM-03 | Walk to the overrun | every morning's briefing + route exact; C's week-2 visit is left In Progress; on the Saturday F is **not** in the briefing |
| TM-04 | Browser, the day after the overrun | the unfinished job is carried onto the next day's route |
| TM-05 | Walk to the end (D0+39) | every morning's briefing + route exact; F worked Thu, Fri, Mon only |
| TM-06 | Browser Reports | E (one visit, never again) is listed as stale |
| TM-07 | Six-week totals | sweep timing and due dates right; never two pending visits for one customer; visit counts A 6, C 6, B 3, D 2, E 1, F 1, all Complete; TimeLog dates match the days worked; overdue-invoice alert empty on day 29 and naming A's invoice on the last day; E stale exactly from 21 days after its visit, A–D never stale; the first digest naming E arrives ≥ 21 days after its visit; outbox only to test addresses |

**First runs (2026-09-29):** the first run exposed only test-side problems (the browser tests ran ahead of the walk — pytest-playwright groups `[chromium]` tests first; fixed by making every step request `browser_name` and skipping later steps once one fails; and the Jobs sheet's column is "End Date (blank = single-day job)"). Even that out-of-order run confirmed every morning Oct 6 – Nov 13: exact briefings and routes, the 3-day job skipping the weekend, the weekly/biweekly/monthly chains (monthly D due Sun 11/08 booked Mon 11/09), 21 digest emails caught in the outbox.



## 7. Logs, evidence and results

Every run creates its own folder, `tests\gui_jobs_e2e\artifacts\<YYYYMMDD_HHMMSS>\`, and **keeps it whether the run passed or failed**. The latest run is also reachable as `artifacts\latest\` (a copy of the most recent folder's summary and report), so the results are always in the same place.

| File | What it holds | Look here when… |
|---|---|---|
| `SUMMARY.txt` | One screen: PASS/FAIL, counts, duration, tier, URL, sandbox date, backup path, **cleanup result** (`0 ZTEST rows left`), and one line per failed test with its ID, the first error line, and the path to its evidence | …you want the answer in 10 seconds |
| `report.html` | Clickable pass/fail table per test ID with durations; failed rows link to the screenshot and trace (`pytest-html`, self-contained) | …you want to browse the results |
| `run.log` | **Full timestamped log of the whole run**: every step the page objects take ("Route → pick date 2030-01-07", "press ▲ on stop 3"), every PWA-API call with tool, args, response status and duration, guard decisions (allowed / blocked / recorded), setup and cleanup actions with IDs | …you're debugging *what happened, in what order* |
| `console.log` | Everything the Jobs app wrote to the browser console, plus page errors, per test | …a screen misbehaved and you suspect the app's JavaScript |
| `api_calls.jsonl` | One JSON line per PWA-API call (test ID, tool, args, response excerpt, ms) | …you want to grep or replay calls |
| `pytest_output.txt` | The raw pytest console output (also shown live on screen) | …anything else |
| `failures\<TEST-ID>\` | For each failed test: `trace.zip`, `screenshot.png`, `video.webm`, and that test's slice of `run.log` / `console.log` / `api_calls.jsonl` | …debugging one failure |

**Viewing a failure step by step:** `python -m playwright show-trace failures\<TEST-ID>\trace.zip` opens Playwright's trace viewer. It lets you scrub through every click with the screen as it was, the DOM, the network calls, and the console at each moment.

**At the end of every run** the runner prints `SUMMARY.txt` to the console and opens `report.html` in the browser, unless it was started in background mode (§8), where it only writes the files. Old run folders beyond the last 20 are deleted automatically so they don't pile up either. The artifacts folder is git-ignored.

---

## 8. The runner — `run_tests_gui_jobs_e2e.bat`

Modeled on `run_tests.bat` (same Python discovery, same conventions). Double-click it, or run it from a Command Prompt in the `tests` folder. It is always a **manual, on-demand** script; nothing runs it automatically unless you choose to schedule it later.

### 8.1 Two ways to run

| Mode | Command | What you see |
|---|---|---|
| **Watch** | `run_tests_gui_jobs_e2e.bat --headed` | A real Chrome window opens and you watch every click happen. Progress prints live in the console. At the end, `SUMMARY.txt` prints and `report.html` opens. Add `--slowmo 500` to slow each action to half a second so it's easy to follow. |
| **Background** | `run_tests_gui_jobs_e2e.bat --background` | No browser window (headless Chrome). The run starts minimized in its own console and writes everything to the run folder (§7). When it finishes, a Windows notification (toast) says PASS/FAIL with the counts; `SUMMARY.txt` and `report.html` are waiting in `artifacts\latest\`. You can keep using the PC, including Chrome. |

With neither flag, it runs headless in the current console: no window, live progress, summary and report at the end.

### 8.2 All options

```
run_tests_gui_jobs_e2e.bat                        headless, this console, everything (safe tier)
run_tests_gui_jobs_e2e.bat --headed               watch in a real Chrome window
run_tests_gui_jobs_e2e.bat --headed --slowmo 500  watch, slowed down
run_tests_gui_jobs_e2e.bat --background           headless, minimized, toast when done
run_tests_gui_jobs_e2e.bat -k route               only tests whose name/ID matches "route"
run_tests_gui_jobs_e2e.bat -k "RE-08"             one specific test
run_tests_gui_jobs_e2e.bat -k R_                  only regression tests
run_tests_gui_jobs_e2e.bat --mobile               mobile-layout suite only
run_tests_gui_jobs_e2e.bat --tier email           also send ONE real route email to david.vavro1@gmail.com
run_tests_gui_jobs_e2e.bat --tier full            email tier + one real AI Routing run (spends credits)
run_tests_gui_jobs_e2e.bat --keep-data            don't clean up; inspect a failure in the app
run_tests_gui_jobs_e2e.bat --cleanup-only         just run the ZTEST sweep (§4.5) and report
run_tests_gui_jobs_e2e.bat --help                 print all of the above
```

Options combine, e.g. `--headed --slowmo 500 -k prescreen`.

### 8.3 What the script does

1. **Pre-flight** (stops with a plain-English message on any failure): `AIPROWLER_JOBS_TOKEN` set; Python + `pytest-playwright` installed; Google Chrome installed; the live Jobs app URL answers; the token logs in; "Customer Reminder Daily Digest" is Disabled; "Email Route On Build" noted (Enabled = the guard switches route emails off per call, §4.4).
2. **Start-of-run ZTEST sweep** (§4.5 step 5) and **database backup**.
3. Runs `python -m pytest tests\gui_jobs_e2e -m jobs_gui_e2e --browser-channel chrome --tracing retain-on-failure --video retain-on-failure --screenshot only-on-failure …`, teeing output to `pytest_output.txt`.
4. **Final ZTEST sweep** and zero-left verification.
5. Writes `SUMMARY.txt`, refreshes `artifacts\latest\`, prunes old runs, prints or notifies.
6. **Exit code 0 only if every test passed AND cleanup left zero ZTEST rows**, so it can serve as a release gate.

### 8.4 One-time setup

```
python -m pip install pytest-playwright pytest-html pytest-rerunfailures
setx AIPROWLER_JOBS_TOKEN "<your Bearer Token from Settings → Remote Access>"
```

`setx` stores the token for your Windows user only, so it's never written into a file in the project. Open a new Command Prompt after running it. Google Chrome is already installed, so with `--browser-channel chrome` no browser download is needed.

---

## 9. Regression catalog (seeded from 2026-09-24/25)

Each entry becomes a test in `test_regressions.py`, named `test_R_###_<slug>`, with the original symptom in its docstring.

| ID | Bug | Test |
|---|---|---|
| R-001 | Two jobs at one address routed back-to-back → phone link opened as a stop list | Route a sandbox day with a same-address pair (route anyway) → PL-04 holds |
| R-002 | 1730 vs 1755 State Road 44 geocoded 6 m apart → false "same address" error | PS-03 |
| R-003 | Jobs moved to a date with no route → header "5 jobs" but "No route for this date" | RB-01 |
| R-004 | Moved jobs left their old stops behind on the old date | Move a routed job → old date has no stop for it |
| R-005 | Jobs added after the route was built were invisible on the Route page | RE-09 |
| R-006 | Cancelled jobs were still routed | JOBS-05 + PS-07 |
| R-007 | 🗑️ didn't re-plan the day or refresh the phone link | RE-08 + PL-07 |
| R-008 | Jobs with no street address could be routed to the middle of town | PS-04 |
| R-009 | Stale-stop cleanup deleted stops of jobs with no Service Date | Undated ZTEST job placed on a route by hand survives a re-route |
| R-010 | Price list / Settings: uniqueness was case-sensitive (`ztest-win` accepted beside `ZTEST-WIN`). *Fixed 2026-09-25* | PR-03 |
| R-011 | Editing a row by its key silently changed a *different* row (case-insensitive "contains" match, first row wins; `_`/`%` acted as wildcards). Affected every sheet the Database tab edits. *Fixed 2026-09-25: most-exact match wins; several matches → refused, listing them* | PR-08, PR-09 |
| R-012 | Price list: text ("abc") and negative amounts accepted as prices. *Fixed 2026-09-25* | PR-10, PR-11 |
| R-013 | When every job left a date's route, its "Home" start/end rows were orphaned (3 found during the 2026-09-25 wipe). *Fixed 2026-09-25* | Cancel/move/delete every job on a routed sandbox date → zero route rows remain on that date |
| R-014 | Removing the last stop reported "Route re-planned…; phone link updated" although no route was left. *Fixed 2026-09-25* | Message says the route is now empty |
| R-015 | **Harness:** the write guard could be bypassed — once the app's service worker controlled the page (always in `--human` mode), API requests went to the real server without passing the guard. *Fixed 2026-09-26 in the harness* | Test browsers block service workers; the bypass alarm (page fixture) fails any test in which a `/pwa-api` request left the browser unchecked |
| R-016 | **First app bug found by the E2E suite.** The Add/Edit Job form's Save ignored the server's answer: a refused save (reply starting "❌", e.g. the customer was deleted after the form opened) closed the form exactly like a successful one — the job was never created, and nobody was told. *Fixed 2026-09-26 in `saveJobForm()` (create and edit): a refusal keeps the form open and shows the server's reason. Verified live.* | JOBS-07 |
| R-017 | **Job detail: 💬 Text Customer did nothing** when the customer's name had an apostrophe (O'Brien's, Crabby's…): the name was placed inside the button's code, and the apostrophe broke it. The Email/Text Receipt buttons had the same pattern with the payment text. *Fixed 2026-09-26: those buttons pass only the job id and look the rest up when tapped.* | DET-01 |
| R-018 | **Security — stored cross-site scripting.** The job detail, the Jobs list card and the Clock/Photos job picker inserted customer name, notes, address, service, crew etc. as raw HTML, so markup typed into a job RAN as code on the phone of whoever viewed it (in server mode: any crew member → the owner's or another crew member's phone). *Fixed 2026-09-26: every such value is escaped with `esc()`. (The Board and Calendar already escaped.) Verified live (DET-02, DET-03).* | DET-02, DET-03 |
| R-019 | **Wrong tab lit up.** 📷 Add Photos from a job opened the Photos screen with the **Route** tab highlighted, and 💬 Text Customer opened Messages with the **Calendar** tab highlighted — both picked the tab by position (`.nav-btn[2]`, `[3]`), which went stale when the bottom bar was reordered. *Fixed 2026-09-26: tabs are found by their id.* Note: on this install SMS isn't configured, so Text Customer correctly shows "SMS is not configured yet" instead of opening Messages. | DET-04 (Photos), DET-01 (Messages, when SMS is set up) |
| R-020 | **Clock In / Clock Out ignored the server's answer.** Clocking out of a job never clocked in to was refused ("❌ No open clock-in found") but the app said **"Clocked out!"** — payroll hours looked recorded when they weren't (same pattern as R-016). *Fixed 2026-09-26 in `clockAction()`: a refusal is shown, the clock state is left unchanged.* | CLK-01 |
| R-021 | **After Create Invoice the job detail stayed stale** — it still offered "Create Invoice" and the send buttons stayed dimmed: `submitInvoiceForm()` cleared the job id (closing the form) before using it to re-open the job. *Fixed 2026-09-26.* | INV-01 |
| R-022 | **A job added through the app's own + Add form could not be routed** — it was never given a map location, so Route Selected Date / AI Route refused it ("None of 1 job(s) have a geocoded address yet"); and **editing a job's address kept its OLD map location** (it would be routed to where it used to be). Only the older build_daily_route filled locations in. *Fixed 2026-09-26 in `db_write_ops.py`: a new job with an address gets looked up; an edit that changes the address is looked up again (compared before/after — the edit form always resends the address). Best effort: a failed lookup never blocks the save. Off under the offline test runner.* | WIZ-10 step 4; server tests `tests\\mcp\\test_job_auto_geocode.py` |
| R-023 | **Address lookups silently failed about half the time.** The free map-lookup service (Nominatim) often drops the connection ("forcibly closed by the remote host") when two lookups land close together — e.g. the app looking up your home address while a job is being saved. One dropped call and the job was left with no map location, so it couldn't be routed. *Fixed 2026-09-26 in `db_write_ops._geocode` and the `geocode_address` tool: a dropped connection is retried (3 tries, ~1.2 s apart); a real "address not found" is not retried.* Also found: **"210 Sams Ave" (city hall) is not in OpenStreetMap** — a test-data problem, not an app bug; UI-typed test addresses now use 105 S Riverside Dr. | WIZ-10 step 4; server tests `test_R_023_*` in `tests\\mcp\\test_job_auto_geocode.py` |
| R-024 | **A deleted job stayed on the Job Board as a ghost card.** The board's 60-second poll only asks for jobs that *changed*, and a deleted job never comes back in that answer — so a job deleted on another device (or on the Database tab) stayed on the board, even after leaving and re-opening the Board screen, until ↻ was tapped. Tapping it opened a job that no longer exists. *Fixed 2026-09-26 in `index.html`: opening the Board screen does a full reload (quietly — the cards stay on screen while it loads, no spinner flash).* | BRD-08 |
| R-025 | **Payroll: the app forgot you were clocked in.** Whether you were clocked in lived only in the open page's memory. A phone closes background apps all the time; re-opening the app showed "Not clocked in" with **Clock Out greyed out** — the crew member couldn't clock out and the hours stayed open on the server. *Fixed 2026-09-26 in `index.html`: an open clock-in (TimeLog entry with no Clock Out) is picked up from the server when the app starts and whenever the Clock screen is opened, with its real start time; in server mode only the user's own entry.* | CLK-04 |
| R-026 | **Clock In on a job already clocked in elsewhere restarted the timer.** The server answered "⚠️ A clock-in … is already open" (another device, or by voice) and the app took that as a NEW clock-in — timer back to 00:00:00, while the server kept the original start time. *Fixed 2026-09-26: the app shows the existing clock-in and its real start time.* | CLK-05 |
| R-027 | **Server froze while the `run_script` dev tool ran a script.** Not a Jobs-app bug — found while running unit tests during this work: `run_script` was a plain (sync) MCP tool, which the MCP library runs on the server's one event loop, so for the whole run the server answered nothing (/health, the Jobs app, other tools). Measured with `tests\probe_server_health.py`: a 15 s script → **14.8 s unanswered**; the desktop app's LED showed "Stopped" until it finished. *Fixed 2026-09-26 in `ai_prowler_mcp.py`: the tool is now async and waits on a worker thread. Two problems found in the shared tool wrapper along the way, also fixed: it couldn't handle async tools at all, and it identified tools by Python function name — the renamed wrapper would have slipped past the server-mode rule that hides `run_script` from crew.* *Verified live 14:10 after deploy: same 15 s script → 80 of 80 health checks answered, longest gap 0.0 s, slowest 31 ms. Full `tests\mcp_tests\` suite: 2,999 passed.* | `tests\\mcp\\test_run_script_nonblocking.py` (6 tests); live: `tests\\probe_server_health.py` + `tests\\probe_sleep.py` |
| R-028 | **Security — uploads could be written outside the JobPhotos folder.** `/photos/upload` built its save folder straight from the job number the browser sent, so a job number like `..\Desktop` or `JOB-0001/../../x` saved files anywhere under the user's profile (needs the password, but in server mode every crew member has one). Proven live: files landed in `Documents\AI-Prowler\ZTEST_E2E_escape_…`. *Fixed 2026-09-26 in `ai_prowler_mcp.py` (personal AND server-mode handlers, shared `_job_photo_dir()`): a job number may only contain letters, digits, `-` and `_`, and the folder must be inside JobPhotos. The saved extension is also reduced to letters/digits (`_safe_upload_ext()` — no `:` NTFS streams).* | PH-08; `tests\mcp_tests\test_job_upload_paths.py` |
| R-029 | **Uploads accepted for a job that doesn't exist** — any made-up job number created a new folder. *Fixed 2026-09-26: the job must exist in the database.* | PH-09; `tests\mcp_tests\test_job_upload_paths.py` |
| R-030 | **A picked file's name was inserted into the Photos screen as HTML** (only for non-image files). Low risk — you'd have to pick a maliciously named file yourself — but a file name is text. *Fixed 2026-09-26: escaped with `esc()`.* | PH-07 |
| R-031 | **Reports: weekly revenue was $0 unless a job had been invoiced.** The report read only "Actual Amount", which the server fills in from the job's invoice — so a Complete-but-not-yet-invoiced job counted $0, and **projected revenue (Scheduled / In Progress) was always $0**: work that hasn't happened is never invoiced, so the hatched "projected" revenue bars could never appear. Hours were right. *Fixed 2026-09-26 in `index.html` (`loadReports`), using David's definitions: **actual revenue = money already collected** (the job's invoice "Amount Paid"); **projected revenue = everything still owed** — Scheduled, In Progress and unpaid Completed work alike (invoice TOTAL DUE − Amount Paid, or Quote − Discount if not invoiced yet). Actual + projected = each job's full charge. The report now also reads the Invoices sheet. Hours unchanged (actual = Completed, projected = Scheduled/In Progress).* | REP-02 |
| R-032 | **Database tab: a stale Edit silently overwrote someone else's change.** The generic Edit form (price list, Settings, Customers, Quotes…) never sent the row's Version with its save, so the server's "changed since you opened it" check never ran: if another device saved the row while your form was open, your save wiped their change without a word. *Fixed 2026-09-26 in `index.html`: `_openGenericEditModal` remembers the row's Version (`window._jfCurrentVersion`) and `saveJobForm` sends it as `expected_version` (−1 only when the sheet has no Version). Verified live 2026-09-26 (run 20260926_183947).* | PR-06 |
| R-033 | **Database tab Edit form offered to change a row's own ID** (CustomerID, Service Code, Setting name) as an ordinary box; the server always ignores the ID on update, so a change was silently thrown away on Save (the code's own comment said it was locked). *Fixed 2026-09-26 in `index.html` (`_openGenericEditModal`): the ID of an existing row is shown locked.* | DB-05 |
| R-034 | **Stale edits on Customers / Quotes / Invoices still silently overwrote another device's change** — R-032 only works where the read includes a Version, and these three tables' reads didn't (the database has the column). *Fixed 2026-09-26 in `db_write_ops.py`: Version added to the three header maps (shown read-only; `db_create_row` now also ignores a caller-supplied Version, as updates already did).* | DB-06; `tests\mcp_tests\test_r034_version_on_reads.py` (7 tests) |
| R-035 | **Invoices tab "+ Add" job picker was always empty** ("Every job already has an invoice…"): it loaded the Jobs list, then re-drew the Invoices tab, which resets that list to empty. It would also have hidden Completed jobs (the Jobs tab hides them by default) — the very jobs you invoice. *Fixed 2026-09-26 in `index.html` (`_openInvoicePickerModal`): list captured before re-drawing, Completed included, Cancelled left out.* *R-033..R-035 verified live 2026-09-26 19:45 (15/15 DB tests); `tests\mcp_tests` 3,003 passed.* | DB-13 |
| R-036 | **Route date dropdown counted cancelled jobs** ("Wed, Sep 30 — 2 jobs" for a day with one real job) and **offered a day whose jobs were all cancelled**, which can only route to an empty day. *Fixed 2026-09-26 in `index.html` (`_populateRouteDateOptions`): cancelled jobs are left out of the list and its counts (the Calendar still shows them). Verified live 2026-09-26 19:55. Route regression run 20:03: RB-02 / RB-07 used the old "cancel the only job, then pick the day" setup and were rewritten; PL-07 was a flaky read — all three pass after the test fixes.* | RD-01 (`test_route_dates.py`) |
| R-037 | **↻ refresh buttons too small for a finger on a phone** — 35 px tall on the Jobs and Route screens (≈40 px is the minimum comfortable tap). *Fixed 2026-09-26 in `index.html` (CSS): every ↻ button (Jobs, Board, Route, Calendar, Reports, Database) is at least 40 × 40 px, same look. Verified live 2026-09-26 20:22 (11/11 phone tests).* | MOB-02 |
| R-038 | **(security, server mode) Sign Out didn't end the session on the server.** It only forgot the session in the browser; the server kept accepting that access token (HTTP 200, full job data) until its next restart — anyone with a copy (shared or lost phone) kept access. *Found 2026-09-26 22:38 by SRV-AUTH-06b. Fixed in `ai_prowler_mcp.py` (new `POST /pwa-logout` — removes exactly that /pwa-login session, never a user's real token; always 200) and `index.html` (`signOut()` calls it with keepalive before clearing the browser). Deployed to the server 2026-09-27; verified live 05:57 run — SRV-AUTH-06b passes (old session → 401 after Sign Out).* | SRV-AUTH-06b |
| R-039 | **(security, server mode) Field crew could see and change other crews' routes and clock-ins** (was gaps **G-02** + **G-01**). *Read side (G-02):* `read_job_spreadsheet` and `get_board_updates` crew-filtered only Jobs_Schedule, so a field_crew user got every crew's **TimeLog** clock-ins and **Route_Planner** stops. *Write side (G-01):* `build_daily_route`, `suggest_route_schedule`, `approve_route_schedule`, `unapprove_route_schedule` and `prescreen_route_jobs` ignored the caller's role — field crew could build, re-time, approve or un-approve another crew's route, and a blank crew meant **every** crew. *Found 2026-09-27 06:52 by SRV-SCR-06 (Samual saw Vicki's stop) and 07:18 by SRV-SCR-07 (Samual saw David's clock-in). Fixed in `ai_prowler_mcp.py`: one shared list `_CREW_SCOPED_READ_SHEETS` (Jobs_Schedule, TimeLog, Route_Planner) used by both read tools — TimeLog matches the person who **clocked in**, not the job's crew; new `_route_crew_for_caller()` used by all five route tools — for field crew a blank crew means their own route and any other crew is refused ("Field crew can only work on their own route"); owner / manager / staff / personal mode unchanged. `index.html`: field crew's Route crew picker hidden and holds only their own name (no "All crews"). Unit tests `tests\mcp_tests\test_r039_crew_read_scope.py` 40/40; route/crew/board regression `tests\mcp_tests -k "route or crew or r039 or board or field"` 780 passed. Deployed to the server 2026-09-27 07:44; verified live 07:45 run (`test_srv_screens.py`) — SRV-SCR-06 (Samual sees only his route stop), SRV-SCR-07 (Samual's TimeLog no longer includes David's clock-in) and SRV-SCOPE-08 (all five route tools refuse Samual on Vicki's route with "Field crew can only work on their own route"; her stop unchanged) pass.* | SRV-SCR-06, SRV-SCR-07, SRV-SCOPE-08 |
| R-040 | **(server mode, cosmetic) Profile "Code" row showed the literal text `local`** for every user (was gap **G-09**). The row printed the app's internal token variable, which in server mode only ever holds that placeholder — meaningless to the user, and a credential-shaped value on screen in principle. *Found 2026-09-27 06:52 by SRV-SCR-09 (all three users). Fixed in `index.html`: the Code row stays hidden in every mode and is never filled. Deployed to the server 2026-09-27 08:21; verified live 08:23 run — SRV-SCR-09 passes for David, Vicki and Samual (and SRV-SCR-06/07, SRV-SCOPE-08 still pass).* | SRV-SCR-09 |
| R-041 | **(server mode) `geocode_address` and `search_learnings` failed for every role** with HTTP 400 "unexpected keyword argument 'ctx'" (was gap **G-06**). The server's `/pwa-api` passed `ctx=` to every tool, and these two take none. User-visible: the Route screen's start/end home marker (placed with `geocode_address`) never appeared in server mode. *Found 2026-09-27 08:30 by SRV-API-01 (all three users). Fixed in `ai_prowler_mcp.py` (`/pwa-api` dispatcher): `ctx` is passed only to a tool whose signature takes it (a `ctx` parameter or `**kwargs`) — so any tool added to the allow-list later can't hit the same wall; tools with role checks still get `ctx`. Unit tests `tests\mcp_tests\test_r041_pwa_api_ctx.py`. Deployed to the server 2026-09-27 (live by the 14:36 run); verified live 14:39 — SRV-API-01 passes, both tools answer for David, Vicki and Samual. (The 14:36 run still failed only because the geocode probe address wasn't in OpenStreetMap; probe address changed and the test fixed.)* | SRV-API-01 (SRV-API-10/11) |
| R-042 | **(security, server mode) Any user could retire anyone's learning** through `record_learning(supersedes_id=…)` (was gap **G-03**). Superseding marks the old learning deprecated, but unlike `update_learning` / `delete_learning` it had no ownership check — field crew could retire the owner's or a co-worker's learnings. *Confirmed in code 2026-09-27 (`self_learning.record_learning` deprecates whatever id it's given). Fixed in `ai_prowler_mcp.py` (`record_learning`): a `supersedes_id` goes through the same `_can_modify_learning` rules — crew only their own (or an unattributed legacy one), managers any employee's but never the owner's, owner any; an unknown id is refused in server mode. Checked before anything is written, so a refused call records nothing. Personal mode unchanged. Unit tests `tests\mcp_tests\test_r042_supersedes_ownership.py` 11/11; learning tool regression (`test_learning_mcp_tools`, `test_recorded_by`) 27/27. Deployed 2026-09-27 ~16:00; verified live 20:13 (`test_srv_learnings.py`, 3/3) — Samual and Vicki each refused superseding the owner's learning ("only the owner may modify their own learnings. Nothing was recorded."), the owner's learning stayed active, and Samual could still retire his own. The 3 ZTEST learnings were deleted afterwards as the owner.* | SRV-API-12 |
| R-043 | **(security, server mode) Jobs app sessions never expired** (was gap **G-10**) — a copied session worked until Sign Out on that device or a server restart. *David's decision 2026-09-27: 30-day idle timeout. Fixed in `ai_prowler_mcp.py`: new pure helper `_pwa_session_touch()` + `PWA_SESSION_IDLE_SECS` (30 days); `/pwa-login` starts the clock, every use restarts it, `/pwa-logout` clears it; a session idle past 30 days is ended on its next use and answered 401 ("Session expired — please sign in again."), which the Jobs app already turns into its sign-in screen. Applied everywhere a session is checked: `/pwa-api`, `/photos/upload` and the main MCP handler (one helper, `_srv_raw_token_for`). OAuth connector tokens and raw users.json tokens are not affected. Sessions still also end on a server restart. Unit tests `tests\mcp_tests\test_r043_pwa_session_idle_timeout.py` 10/10; server / PWA / auth regression (`tests\mcp_tests -k "r043 or r042 or r041 or r038 or pwa or server_mode or auth or login or logout"`) 705 passed. Deployed 2026-09-27 ~16:00; verified live 16:01 — SRV-API-06 13/13 and sign-in tests 9/9 still pass (the 30-day expiry itself is unit-tested; it can't be waited out live).* | SRV-API-06 |
| R-044 | **Job (and other) numbers were reused after a delete** (was gap **G-11**). New IDs were "highest existing + 1", so deleting the newest job freed its number — and the next job inherited the old job's `JobPhotos\<JobID>` folder. *David's decision 2026-09-27: never reuse a number, so a cancelled job can still be reviewed. Fixed in `db_write_ops.generate_next_id`: the highest number ever issued is kept per prefix in a new `id_counters` table; the next id is one past the larger of that and what exists (older databases continue from their highest; numbers deleted before the fix can't be known). Applies to JOB, CUST, QTE, INV and TE ids. The counter bump commits/rolls back with the new row. Unit tests `tests\mcp_tests\test_r044_ids_never_reused.py` 7/7. Deployed 2026-09-27 ~16:00; verified live 16:07 — JOB-0001 was created then swept, and the next run's job was JOB-0002 (not reused); customers continued at CUST-0004.* | test_srv_crew_create (job numbers in run.log) |
| R-045 | **A re-assigned or deleted job stayed on an open Job Board** until a manual refresh (was gap **G-12**) — the 60-second poll only adds/updates changed, visible rows, so nothing told the Board to drop a card. *Found live 2026-09-27 15:17 by SRV-MULTI-02. Fixed: `db_read_ops.db_visible_job_ids` + `get_board_updates(with_ids=True)` returns every JobID the caller may see (same crew rule); `jobs\index.html` `loadBoard` asks for it and drops any card not listed, falling back to the old call on a server without `with_ids`. Unit tests `tests\mcp_tests\test_r045_board_visible_ids.py` 6. Full `tests\mcp_tests` regression with R-042..R-045: **3,088 passed, 0 failed** (15:31). Deployed 2026-09-27 ~16:00; verified live 16:10 — SRV-MULTI-02 passes: the re-assigned job left Samual's untouched open Board after 62 s (one poll).* | SRV-MULTI-02 |
| R-046 | **Leftover per-user job-database code** (was gap **G-08**). There is only one job database (David, 2026-09-28), but `_resolve_job_db_path` still switched a user to `<state dir>\jobs_database\<user id>.db` whenever such a file existed — a stray file with a user's id as its name would silently have given that user a separate, empty set of jobs — and `_job_crew_scope` still skipped the crew filter for a user's "own file" (dead since the database moved, but misleading). *Found 2026-09-28 while reviewing SRV-DB. Fixed: both removed; the unused spreadsheet-era `_resolve_job_spreadsheet_path` (per-user `<user id>.xlsx`) deleted with its tests; stale comments updated. Every server-mode user now always resolves to the one `ai_prowler_jobs.db`. Unit tests `tests\mcp_tests\test_r046_single_job_database.py` 7/7; full `tests\mcp_tests` regression **3,086 passed, 0 failed** (09:34, 2026-09-28 — 3,088 before, −9 removed per-user resolver tests, +7 new). User guide (`COMPLETE_USER_GUIDE.md`) updated to match: Section 9 note, Section 10 "Server Mode: One Shared Job Database" (was "Which Job Database Gets Used"), the `send_email` row, the removed Default-database-folder setting, and the Jobs App sign-in now mentioning the 30-day idle sign-out (R-043). Deployed 2026-09-28 09:48 (code + guide in both installed copies); verified by the full server suite 09:48–10:09 — 83 passed, 0 failed, every role still sees exactly its jobs.* | unit + full server suite |
| R-047 | **(security, server mode) Field crew could read or rewrite another crew's route through a Claude chat** (was gap **G-14**). `get_route_drive_matrix` and `apply_route_order` ignored the caller's crew — R-039 had missed them. *Found in code 2026-09-28. Fixed: both now use `_route_crew_for_caller` like the other route tools — blank = the caller's own route, another crew is refused and nothing is written/returned; owner/manager/staff and personal mode unchanged. The AI Routing run itself is unaffected (it talks to AI-Prowler over the local connection, and `start_ai_routing` already forces field crew to their own day). Unit tests `tests\mcp_tests\test_r047_route_matrix_apply_scope.py` 13/13. Awaiting deploy.* | unit (live: SRV-SCOPE-03 family, to add) |
| R-048 | **An admin-saved AI Route token could go missing after a rename.** The Admin tab saved/looked up a user's Claude token under a slug of their *current name*; the server looks it up by their users.json *id*. Same value until a user is renamed. *Found 2026-09-28 reviewing how admins set up users' Claude accounts. Fixed (`rag_gui.py`): one helper `_admin_ai_token_key(u)` — the id, name slug only as fallback — used by the 🤖 AI Route Token dialog, the users table's AI-token column and the AI Route runner panel's "users connected" count. Unit tests in `tests\mcp_tests\test_admin_ai_route_runner.py` (+4). Awaiting deploy.* | unit |
| R-049 | **The Jobs app ignored Settings → MCP Tool Configuration**, so it couldn't be made optional. The panel only kept tools out of Claude's tool list; `/pwa-api` called them directly — unticking "Job Tracker & Routing" left the whole Jobs app working, unticking SMS still let it text. Also: only 7 of the ~47 tools the app uses were flagged as Jobs-app dependencies (so the panel rarely warned); `list_outlook_accounts` was counted in server mode though it refuses to run there; and `prescreen_route_jobs` (2026-09-25) had no catalog row at all. *Found 2026-09-28 reviewing the server-mode tool panel. Fixed: both `/pwa-api` handlers refuse a turned-off tool (403 + "“<tool>” is turned off on this AI-Prowler…"; locked tools can never be off); server `/pwa-login` refuses sign-in with a plain message when the Jobs app's core read is off (Job Tracker & Routing unticked) — checked before any credential; `mcp_tool_catalog.JOBS_APP_TOOLS` = both allow-lists, every one flagged (the panel now warns); `list_outlook_accounts` personal-only (Tier A + catalog); `prescreen_route_jobs` catalogued. New guards: every `@mcp.tool()` must have a catalog row, every personal-only catalog tool must be Tier A, JOBS_APP_TOOLS must equal the allow-lists. Unit tests `tests\mcp_tests\test_r049_jobs_app_honours_tool_panel.py` 14/14. Full `tests\mcp_tests` regression with R-047..R-049 (11:26): **3,120 passed, 2 failed** — both old source-window checks in `test_server_mode_jobs_pwa.py` (the new lines pushed the phrase they look for past their fixed window; nothing regressed); windows widened, file 23/23. Awaiting deploy.* | unit (live: SRV test with a disabled tool, to add) |
| R-050 | **Field crew could export, back up and restore the whole company database, and restore could wipe a working database.** In server mode none of `export_to_excel` / `export_to_csv` / `export_to_quickbooks_csv` / `backup_job_database` / `restore_job_database` checked the caller's role — a field_crew account could take a full copy of every customer/invoice, or replace the shared database with `confirm=True` as the only guard. *Found 2026-09-28 from David's review of the server "Job Tracker & Routing" tool panel. Decision (David): owner/manager/staff may export and restore; field crew never. Restore is essentially for moving to a new PC. Fixed: `_field_crew_data_admin_denied()` refuses field crew on all five tools before anything runs ("❌ … field crew can't use it. Nothing was done."). `db_restore_database` gained `require_replace`/`replace_existing` and business-record counts (jobs, customers, invoices, quotes, time entries, route stops — settings/pricing are ignored because a fresh install already has rows there). Every unconfirmed warning shows live-vs-backup counts. In server mode (`require_replace=_IS_SERVER_MODE`) a confirmed restore onto a non-empty database is refused unless `replace_existing=True`; it is refused before the safety backup, so nothing changes. An empty or missing live database (the new-PC case) restores with `confirm=True` alone. The safety backup is still taken first. GUI ♻️ Restore from Backup shows both counts; in server mode with a non-empty database you must type REPLACE. Catalog descriptions updated (the old "no role gate" note is gone); user guide §6 and §10 updated. Unit tests `tests\\mcp\\test_r050_data_admin_role_and_restore_safety.py` 25/25, plus phase-8 portability tests 21/21 unchanged. Personal mode unchanged. Awaiting deploy.* | unit |
| R-051 | **AI Route result shown as raw JSON.** First live server-mode AI Route (David's own Claude token, 2026-09-28 13:3x): the runner worked end to end — Claude Code started, reached the tools, 13 turns, no permission denials — and correctly reported the job database empty (it is: no jobs or customers on the server right now). But Claude Code printed "Ignoring 2 permissions.allow entries from .claude/settings.json: this workspace has not been trusted…" ahead of its JSON; the wrapper merges stderr into `last_ai_routing_run.json`, `json.loads` failed, and the Jobs app showed the whole raw payload (usage, cost, session id). Nothing was blocked — the wrapper passes `--allowedTools` and `--permission-mode bypassPermissions`. *Fixed (`task_queue_automation.py`, `ai_prowler_mcp.py`): `parse_claude_json_output()` finds the Claude result object even with warning lines around it (the worker now uses it); `_ensure_workspace_trusted()` — run from `generate_mcp_config()`, i.e. before every run — sets `projects["C:/Users/<account>/.ai-prowler"].hasTrustDialogAccepted = true` in that account's `~/.claude.json` (only that key; the rest of the file kept; skipped if already set or the file is unreadable), which is the setting the warning names. Unit tests `tests\\mcp\\test_r051_ai_route_output_and_trust.py` 11/11; `tests\\analysis\\test_task_queue_automation.py` 225/225 unchanged. Awaiting deploy. Live re-check: an AI Route run on a day with ZTEST jobs should show just the summary.* | unit + live |
| R-052 | **Server Jobs app Settings card was missing most settings.** Personal mode shows 23 rows (Route Origin Mode + its 4 Start/End Address rows, Email Route On Build, Workday Start/End, Lunch Break Start/Duration, Hard Time Tolerance, Recurring Job Lead Time, Stale Customer Reminder Days, Customer Reminder Daily Digest / Email Enabled / SMS Enabled, plus the 7 invoicing rows); the server showed only the 7 invoicing rows (+ 2 internal markers). Not a mode split in the app — the card lists whatever rows exist, and nothing ever created these 16 rows: every reader has a built-in default for a missing row, the personal database just got them as each feature was added. So on the server they couldn't be seen or edited, and the Route Origin popup's Start/End Address save would fail ("key doesn't exist"). *Found 2026-09-28 by David. Fixed: `db_write_ops.DEFAULT_SETTINGS` + `db_seed_default_settings()` add any missing row with the value its reader already falls back to (behaviour unchanged — tested reader-by-reader), never touching an existing row; called from `read_job_spreadsheet(Settings)` and `update_job_spreadsheet(Settings)` after the field-crew denial (field crew still get nothing and trigger no seeding). Route Origin Mode's note mentions the server-mode Home Address (Admin → Users). The card also hides the `internal_*` bookkeeping rows ("do not edit by hand"). Unit tests `tests\\mcp\\test_r052_default_settings.py` 13/13. Awaiting deploy (`db_write_ops.py`, `ai_prowler_mcp.py`, `jobs\\index.html`).* | unit (live: open Settings on the server app) |
| R-053 | **Server Settings → Email Configuration had no Outlook support.** Personal mode shows Outlook detection/status, "Send via" Outlook/SMTP checkboxes (Outlook first, SMTP fallback), 🔍 Check / 🔄 Refresh Outlook Accounts, the default-account picker and the Classic-Outlook help; server mode hid all of it and Save / Test Connection forced SMTP. No real reason: `_send_smtp()` already routes an Outlook backend in both modes (and passes the employee's Reply-To), and the HTTP MCP server is a child of the GUI in the same desktop session, so Outlook COM works on the server PC. *Found 2026-09-28 by David. Fixed (`rag_gui.py`): the email section is identical in both modes — every `if not _settings_is_server_mode` gate removed, Save/Test honour the checkboxes; only the intro text differs (server: company sending account, name/Reply-To from the Admin tab; with Outlook the message goes out under the account's own name, Reply-To still the employee's). New guard (`ai_prowler_mcp.py`): in server mode `send_email` ignores `from_account` — the server's Outlook profile may hold other mailboxes (e.g. the owner's own), so every signed-in user sends from the company account chosen in Settings. `list_outlook_accounts` / `configure_email` stay personal-only on purpose (an employee must not list or change the company account from Claude — the owner does it at the server). Unit tests `tests\\mcp\\test_r053_outlook_email_both_modes.py`. Deployed 2026-09-28 ~15:00 — see R-054.* | unit (live: Check for Outlook on the server + Test Connection) |
| R-054 | **Opening AI-Prowler on the server popped Outlook 2016's "Welcome to Outlook" setup wizard** (regression from R-053, found live by David 15:03 right after deploying). When the Settings page is built it fills the Outlook account picker; if Outlook isn't already running that refresh fell back to `Dispatch("Outlook.Application")`, which STARTS Outlook — and on a PC with Classic Outlook installed but no mail profile, starting it opens the first-run wizard. R-053 removed the server-mode gate that had been hiding this; it was always latent in personal mode too (any PC with an unconfigured Classic Outlook). *Fixed (`rag_gui.py`): `_refresh_ol_accounts(allow_launch=False)` at page build only reads accounts from an Outlook that's already running and never starts it; only the explicit 🔍 Check / 🔄 Refresh Outlook Accounts click may launch Outlook. A saved Outlook account stays in the picker when Outlook isn't running yet. Regression tests added to `test_r053_outlook_email_both_modes.py` (13/13). Awaiting deploy (`rag_gui.py` only).* | unit (live: restart AI-Prowler on the server — no Outlook window) |
| R-055 | **A manager doing crew work got every crew's jobs in her route.** Vicki (manager, works as crew) may see all jobs, but Route Today / Email Route on the Jobs page send no crew, and for a manager/staff member no crew meant EVERY crew — so her "Route Today" merged Samual's jobs into her route; the Route tab defaulted to "All crews" too. *Found 2026-09-28 by David while reviewing the 3-week schedule test. Decision (David): route your OWN assigned jobs by default and you may still pick another person to plan that person's day. **Extended the same day (David 18:20) to EVERY role, the owner included** — "the admin won't be doing the routing for the users, they self-serve it". Fixed: `_route_default_crew()` + `_route_crew_for_caller()` — in server mode any signed-in caller's blank crew -> their own name (build, suggest, approve, unapprove, prescreen, drive matrix, apply order); `email_route_now` and `start_ai_routing` the same; field crew unchanged (locked to their own); personal mode unchanged (one route). Jobs app Route tab: for every server role the default choice reads "My jobs (<name>)" and lists only their stops; other people stay pickable. Unit tests `tests\\mcp\\test_r055_manager_routes_own_jobs.py` 17/17 (owner blank now = own name); `test_r047_route_matrix_apply_scope.py` and `test_r039_crew_read_scope.py` updated (blank = own route for owner/manager/staff); `test_build_daily_route_phase1_mcp_wiring.py` and `test_phase7_fresh_install_smoke.py` now assign their owner-routed job to the owner. Regression `tests\\mcp` + `tests\\gui` (18:30–18:48): 3863 passed, 7 failed — all 7 were those old "owner/manager blank = every crew" expectations, fixed and re-run 50/50. E2E: SRV-SCHED-07 (Vicki routes with no crew — only her jobs), SRV-SCHED-08 (owner self-routes too), SRV-SCHED-06/09 check the Route-tab default for Vicki and David. Awaiting deploy (`ai_prowler_mcp.py`, `jobs\\index.html`).* | unit + SRV-SCHED-06..09 |
| R-056 | **A job can be assigned to several people, picked from the team list, and is on each one's route.** *Asked by David 2026-09-28 18:20: assigning by typed name risked misspellings (a misspelled name silently drops the job from that person's route), and some jobs need two people. Fixed: (1) new read-only tool `list_team_members` — names + roles of ACTIVE users only (never tokens, emails, phones; a name containing a comma is skipped; duplicates collapsed), any signed-in role, empty in personal mode; added to the server `/pwa-api` allow-list, `mcp_tool_catalog` (row + JOBS_APP_TOOLS) and the E2E guard's READ set. (2) Jobs app job form: in server mode the Crew / Technician box becomes a tick-list of the team (`#jfCrewPicker`); ticked people are saved as "A, B"; a name already on a job that isn't a current user is kept as its own ticked box (never silently dropped); falls back to typing if the list can't load; personal mode unchanged. (3) Routing (`db_route_ops.py`): the crew filter is a case-insensitive membership test on the job's comma list (`_crew_names` / `_crew_match`) in `db_get_jobs_for_route`, unapprove and prescreen; a matched job is routed under the ROUTING person's own (route_date, crew_id) — never an "A, B" route; a blank-crew server suggest expands a shared job to one copy per person; `db_write_route_stops` splits any stop still reading "A, B" onto each person's route (personal mode still one route); approve matches the route name case-insensitively; prescreen's same-address / hard-overlap checks run per person. (4) Route tab: person options are one per person (shared jobs split), and stops / day-jobs filter by membership (`_crewHas`); open-clock-in lookup too. Known behaviour: approving a shared job writes that person's ETA to the job's Start Time — the last person to approve wins; unapprove by either person reverts it. Unit tests `tests\\mcp\\test_r056_shared_jobs_and_team_picker.py` 17/17. E2E: SRV-SCHED-08 (owner adds a Samual+Vicki shared job and his own job; Vicki, Samual and David each run Route Today with no crew; exactly three routes, the shared job on both crew routes, David's only on his; both clock the shared job) and SRV-SCHED-09 (owner's add-job form shows the team tick-list; ticking two people saves "Samual Cronin, Vicki Vavro"). Awaiting deploy (`ai_prowler_mcp.py`, `db_route_ops.py`, `mcp_tool_catalog.py`, `jobs\\index.html`).* | unit + SRV-SCHED-08/09 |
| R-057 | **Fixed-choice fields accepted any text outside the Jobs app — so "Completed" jobs never counted as serviced.** In the app these fields are dropdowns, but Claude (voice/chat), imports and the API write through the same server code, which stored whatever word it was given. *Found 2026-09-28 by the E2E suite (SRV-SCHED-03 saved "Completed"; the app's value is "Complete") and David's follow-up review of every such field. Consequences found: a "Completed" job looked done but still counted as **never serviced** (customer reminders), wasn't protected from deletion and was left out of reports; a customer Frequency of "Semi-Annual"/"Annual"/"Bi-weekly" — the Jobs app's own Recurrence wording, or natural speech — was "Unrecognised" by the recurring scheduler, so their next visit was **never created**; "2 hrs" was timed as **2 minutes** on routes; a Route Origin Mode of "office" silently stayed Jobs Only. Fixed (`db_write_ops.py`, both modes): every create/update of Job Status, Payment Status (jobs + invoices), Recurrence, customer Frequency, Schedule Type, Est./Actual Duration Unit, Customer Type (jobs/customers/quotes/invoices), customer Status, quote Status, and the Route Origin Mode + 4 Enabled/Disabled settings is mapped to the field's own canonical value (ignoring case, spaces, punctuation; common words like done/finished, every other week, twice a year, hrs, fixed/flexible, accepted/rejected, on/off) — or **refused with the list of allowed values, nothing saved**. Blank still clears. The recurring scheduler reads every accepted wording. A one-time cleanup (first read after deploy, marker `internal_choice_fields_normalized_v1`, hidden like other internal_* rows) rewrites existing recognised variants; unrecognised values are left untouched and listed in the marker's note. Unit tests `tests\\mcp\\test_r057_choice_fields.py` 38/38, incl. checks that the Jobs-app dropdowns and the Database-tab dropdown lists equal the server's lists. SRV-SCHED-03 now saves "Complete". The Duration Unit "day" question was answered by David — see R-058. Awaiting deploy (`db_write_ops.py`, `db_read_ops.py`).* | unit |
| R-058 | **Multi-day jobs were routed on their first day only, and a job that ran over its estimate fell off the route.** *David 2026-09-28: "10 days" means 10 WORKING days, and the job is on its assignee's route every one of them. Follow-ups the same evening: a job that isn't marked Complete by its last planned day keeps being routed on the following working days until it is — for every job, including one-day and part-day ones ("as long as that job isn't marked complete"). Before: the "day" unit was understood nowhere (a 10-day job was timed as 10 minutes and routed once); jobs with an explicit End Date had the same first-day-only routing; an unfinished job simply disappeared after its date. Fixed (`db_write_ops.py`, `db_route_ops.py`, `db_read_ops.py`, `scheduler_jobs.py`, `jobs\\index.html`): (1) a day-unit Est. Duration sets End Date = the Nth working day (Mon–Fri) from the Service Date, on create and whenever the duration, unit or Service Date is edited; (2) every route engine, the prescreen and unapprove (`_jobs_worked_on`) see the job on each working day of its span — weekends inside the span skipped, the Service Date always counts — timed as a full workday (Workday Start→End minus lunch; a final part-day as its share); each assignee (R-056) gets it every day; (3) **overrun:** any job whose status isn't Complete/Cancelled (any accepted wording, R-057) **and whose last planned day is already past** is also worked on each working day after its planned end (today's own jobs aren't late yet, so they never pre-fill tomorrow's route — found 2026-09-29 04:17 by PSCHED-05, where tomorrow's route showed today's three open jobs too), back through past days and forward to the next working day after today (so an overdue job is on both today's and tomorrow's plan); an overrun day is timed like one of the job's own days (a full day, ½ day for a ½-day job; hour/minute jobs keep their hours); route rows carry `day_no`, `job_days` and `overrun`; (4) route clean-up keeps an open job's overrun stops, and when the job is marked Complete keeps the days already worked (up to today) and drops later ones; (5) the Calendar, the Jobs date filter and the morning "today's jobs" list follow the same rules. Unit tests `tests\\mcp\\test_r058_multi_day_jobs.py` 20/20 (working-day arithmetic; End Date sync; 10-day job routed on all 10 working days and not weekends; explicit End Date jobs; shared multi-day job; suggest on day 3; day-2 routing keeps day 1; prescreen/unapprove; overrun of a 3-day job to day 4 and next Monday, gone once Complete; one-day and ½-day overrun; overrun stops kept while open, past kept/future dropped on Complete; date filter shows an overrun job until Complete; app calendar). Awaiting deploy.* | unit |
| R-059 | **"Email Route On Build" was never tested — the E2E pre-flight stopped the run whenever it was Enabled.** *Found 2026-09-29 04:46 when David turned it on and the personal six-week run refused to start; David: "we need to test this as its a test gap". Fixed: (1) product (`ai_prowler_mcp.py`, both modes): `suggest_route_schedule` — the Route Today / Route Selected Date button and Claude's "route today" — takes `email_route` (unset = follow the setting, `False` = build without the automatic email this one time; "route today but don't email me"; the setting is unchanged). `build_daily_route` already had `email_link`. (2) harness (`safety.py`, both `conftest.py`, `api.py`): the pre-flight no longer stops on this setting (the Daily Digest still stops it); with it Enabled the guard rewrites every route build's switch to "don't email" before the request leaves the browser/API client, except the ONE real route email per run (tier email/full/comms, sandbox date, recipient David/Vicki — personal mode reads the SMTP default recipient; the server suite never sends one because the email goes to whoever built the route); AI Route (no switch) runs with the setting on only as that one email; a "📧 Route link and results emailed to" reply the guard didn't allow is a violation. Unit tests `tests\\mcp\\test_r059_route_email_on_build.py` 16/16. E2E: PSCHED-06 (API) and PSCHED-07 (Route button, human mode). Awaiting deploy (`ai_prowler_mcp.py`) — until then the server rejects `email_route` and route builds fail safe (no email).* | unit + PSCHED-06/07 |
| R-060 | **Tests may flip the email/SMS switches — and always put them back.** *David 2026-09-29 05:00: "can your tests change the settings sheet values and turn on and off email send with route or the customer reminders emails or SMS?" → "Yes". Before, the suite never changed Settings, so each switch was only tested in whatever state David had left it (REM-03/04 skipped while reminder email was Disabled; route email untested). Now (harness only, no app change): `settings_switch.py` + a guard rule allow writes to exactly Email Route On Build / Customer Reminder Email Enabled / Customer Reminder SMS Enabled, only to Enabled/Disabled, only after the pre-flight has saved the originals (to `artifacts\settings_to_restore.json`); the `toggles` fixture restores after every test; the run restores and reads back at the end — a toggle not back fails the run ("Settings toggles NOT back ❌"); a killed run's file is put back by the next pre-flight. Sending limits unchanged (§4.6). New/changed E2E: PSCHED-06/07 set the route email on, PSCHED-08 sets it off (server must send nothing, guard must not rewrite); REM-03/04 turn reminder email on instead of skipping; REM-05 [email, sms] — off: grayed '… Disabled' button and the server refuses the send; on: the real button is back; SET-01 [3 toggles] — flip in the Settings screen and back, read back each time (human mode); SET-02 — Tax Rate, a 'Maybe' value and a changed note are still blocked. Unit tests `tests\\mcp\\test_r060_settings_toggles.py` 7/7 (fake API: nothing writable before the snapshot; set/restore/verify; other settings blocked; the edit form's unchanged Setting+Notes allowed; killed-run recovery restores the true original; Disabled believed only after read-back).* | unit + PSCHED-06..08, REM-03..05, SET-01/02 |
| R-061 | **Route start/end mode tested in both modes.** *David 2026-09-29 05:10: "add the route start/end mode control to be able to turn it on and off … expand the testing with those different route modes and … add more tests". Settings → Route Origin Mode joins the switches the suite may set (Jobs Only / Company Location; saved first, put back after every test and at the end of the run). The Start/End Address stays as David set it: the four rows may only be re-saved unchanged (the app's mode form does that); a test skips if no Start/End Street Address is configured. New `test_route_origin_modes.py` (ZTEST jobs on the sandbox date): **ROM-01** Company Location (API) — first stop = the business address at Workday Start Time, last stop = back at the business, the 3 jobs in between; **ROM-02** Jobs Only (API) — no business stops, the route starts with a job, at most one hidden "Home" return row at the end; **ROM-03** switch Company → Jobs Only → Company and re-route each time — the business stops come and go, jobs unchanged; **ROM-04** Route tab, Company Location (human mode) — the first stop shown is the business; **ROM-05** Route tab, Jobs Only — no business stop and no bookend row shown; **ROM-06** Route tab, Company Location — non-job rows are only first/last. SET-01 gains a 4th case (flip the mode in the Settings screen and back). Harness: `RouteScreen` now counts only job stops (`data-jobid` not empty), so route tests don't break when the business start/end stops are shown. Unit tests `test_r060_settings_toggles.py` 9/9 (+ mode switch, mode values only, Start/End Address re-save-unchanged only).* | unit + ROM-01..06, SET-01 |
| R-062 | **One dropped map-lookup connection failed the whole route build.** *Found 2026-09-29 05:25 (personal six-week run, human mode): PSCHED-04 and PSCHED-05 both failed routing 2026-09-30 with "❌ Could not geocode starting address: ('Connection aborted.', ConnectionResetError(10054 …))". `build_daily_route` looked up the start/end address on Nominatim with a single try every time it built a day (the one lookup R-023's retry missed); building days back-to-back made Nominatim cut the connection. Fix (app, `ai_prowler_mcp.py` + `db_write_ops.py`): the start address now goes through `db_write_ops._geocode` (3 tries, 1.2 s apart), and `_geocode` keeps successful answers for the life of the server, so the same start address is looked up once, not once per day. Misses and outages are not kept. The error text now says "address not found, or the map lookup service did not answer after 3 tries". Unit tests `tests\mcp_tests\test_r062_route_origin_geocode_retry.py` 4/4 (hit cached incl. spacing/case, drop-then-answer retried and cached, misses not cached, build_daily_route uses the retrying lookup); `tests\mcp_tests\conftest.py` clears the cache before every unit test.* | unit + PSCHED-04/05 |
| R-063 | **A dropped map connection left a drive leg's miles blank — and the day's total quietly came out short.** *Found 2026-09-29 reviewing the mileage path for David's request (05:42: "test the routing (non-AI Routing and AI-Routing) and determine if the total miles driven is correct for both route modes"). Every leg Route Today, AI Routing (apply_route_order) and reorder write comes from `db_write_ops._osrm_leg`, which asked the public OSRM server once; a dropped connection gave (None, None), the route row got no Drive Miles, and the Route tab's "Total …/N mi" and "Total for the day" simply skipped it (the only warning said DRIVE TIME UNKNOWN, nothing about miles). Fix (`db_write_ops.py`, `db_route_ops.py`): `_osrm_leg` retries a dropped connection (3 tries, 1.2 s apart; a real non-"Ok" answer is not retried), and both DRIVE TIME UNKNOWN warnings now also say "its miles are missing from the day's total". Unit tests `tests\mcp_tests\test_r063_osrm_leg_retry.py` 4/4. New E2E `test_route_mileage.py` (see §6.18).* | unit + MILES-01..04 |
| R-064 | **AI Routing chose the visit order without seeing the drive from the day's start and back.** *Found 2026-09-29 05:51 by MILES-04 (real AI Routing, tier full). The miles AI Routing wrote were exactly right in both modes (Company Location 15.92 mi, Jobs Only 16.16 mi, every leg matching an independent road lookup) — but in Jobs Only the AI explained its order as "7.4 vs 7.6 minutes" of job-to-job driving: the `get_route_drive_matrix` table it reasons from held job-to-job legs only, so the home→first-job and last-job→home legs were invisible and it picked a day 0.24 mi longer than the order it chose in Company Location from the same point. Fix (`db_route_ops.py`, `ai_prowler_mcp.py`): the matrix now adds the day's START/END point as row/column 1, resolved exactly as `apply_route_order` resolves it with no coordinates (Company Location → the Start/End Address; Jobs Only → the home point), with a note to compare orders by the whole day; the AI Routing prompt says the same and that START/END is not a stop. No start point configured → the matrix is unchanged. Unit tests `tests\mcp_tests\test_r064_ai_matrix_start_end.py` 4/4; two test doubles (R-047, R-055) accept the new `single_crew` argument.* | unit + MILES-04 |
| R-065 | **AI Routing said "✅ DONE" when Claude never ran.** *Found 2026-09-29 08:47 by MILES-04 (tier full, right after David deployed R-062..064): Claude replied "You've hit your session limit · resets 8:50am", no route was written, yet `poll_ai_routing` returned ✅ DONE — in the app, the Route tab shows success over an unchanged or empty route. Fix (`ai_prowler_mcp.py`, `_ai_routing_worker`): when THIS run saved no route AND Claude's reply is an error (`is_error`) or a usage/session/weekly limit, rate limit, low credit balance or overloaded message, the run ends as ❌ ERROR "AI Routing did not run — Claude replied: …. No route was changed; try again later or use Route Today." A run that saved a route is unaffected. E2E: MILES-04 now skips (with Claude's reason) on a usage limit and fails if DONE comes back with no route. Unit tests `tests\mcp_tests\test_r065_ai_routing_limit_not_done.py` 3/3.* | unit + MILES-04 |
| R-066 | **The SMS/WhatsApp settings ignored the test sandbox.** *Found 2026-09-29 building the time machine (§6.19): with `AIPROWLER_TEST_STATE_DIR` pointing at a sandbox, email/database/state went to the sandbox but `sms_backends.load_sms_config` still read the real `~/.ai-prowler/config.json` (Twilio credentials) — a sandboxed server could have texted real numbers. Fix (`sms_backends.py`): `load_sms_config` reads `<AIPROWLER_TEST_STATE_DIR>\config.json` when that variable is set, the real file otherwise (no change for the shipped app). Unit tests `tests\mcp_tests\test_r066_sms_config_sandbox.py` 2/2.* | unit + TM smoke |
| R-067 | **The Overdue Invoice Alert never fired for invoices 31–90 days overdue.** *Found 2026-09-29 09:24 by the time machine (TM-07): an invoice due Tue 10/06 and never paid was 38 days overdue on Fri 11/13, the AR aging report listed it under "31 – 60 days overdue", yet `overdue_invoice_alert` returned nothing — and the morning briefing's "Overdue Invoices" section was empty too. Both looked for the literal text "31-60" / "61-90" on a line, but the report writes "31 – 60 days overdue" (en dash, spaces) as a header with each invoice on its own line below; only "90+" ever matched, and then only the header, never the invoices. The old unit tests passed because they mocked a made-up one-line report. Fix (`scheduler_jobs.py`): new `_overdue_ar_lines()` reads the real layout — each 31+-day bucket's header plus its invoice rows (no rulers, column heads or subtotals) — and still accepts a one-line "31-60 …" form; both the alert and the briefing use it. Unit tests `tests\mcp_tests\test_r067_overdue_alert_reads_real_report.py` 5/5 feed the REAL report text from a temp database (31–60 alerts with the invoice row; 61–90 and 90+ rows; 1–30 and not-yet-due stay silent; mixed buckets list only the 31+ rows; one-line form); `tests\analysis\test_scheduler.py` still 83/83.* | unit + TM-07 |
| R-068 | **Server mode had no overdue-invoice view, and the AR aging report had no role check at all.** *David 2026-09-29 10:07: "In the server mode, we need AR report aging report to be visible by the owner And manager" (after the server time machine recorded gap G-TM-1: the overdue alert is the personal desktop scheduler's, and the Jobs app had no AR report — "Unknown tool"). Found on the way: `get_ar_aging_report` checked no role — any signed-in server user, field crew included, could read every customer's balance through Claude. Fix (`ai_prowler_mcp.py`, `jobs\index.html`): new `_owner_or_manager_denied()`; `get_ar_aging_report` is owner + managers only (staff, field crew → ❌ "for the owner and managers only"; personal mode unchanged); added to both Jobs `/pwa-api` allow-lists and to `mcp_tool_catalog.JOBS_APP_TOOLS` (R-049's tool-panel list — the full unit run caught it missing there); the Reports screen gets a "💰 AR Aging — unpaid invoices" card at the top, and the Reports tab now shows for managers — who see only the AR card and Customer Reminders; the revenue/hours charts stay owner-only (David 2026-09-23). Unit tests `tests\mcp_tests\test_r068_ar_aging_owner_manager.py` (owner/manager see it, staff/crew/unknown refused, personal unrestricted, both allow-lists, the page's role logic); `test_ar_aging_report_phase2.py::test_server_mode_ar_report_not_crew_scoped` updated (manager sees every invoice, crew refused). E2E: time machine server TM-06/06b (owner and manager see the 38-day invoice in "31 – 60 days overdue"), TM-07 (API by role); live SRV-API-01 matrix row, SRV-SCR-01/02.* | unit + TM + SRV-API-01, SRV-SCR-01/02 |
| R-069 | **Customer Reminders: visible to owner, managers and staff.** *David 2026-09-29 10:43: "For the server mode, Customer reminders should be visible for owner, managers, and staff as it's only informational". Change (`ai_prowler_mcp.py`, `jobs\index.html`): `find_stale_customers` uses the owner/manager/staff check (field crew → ❌); SENDING (`send_customer_reminders`) stays owner-only; the Reports tab shows for owner, manager and staff (not field crew); the Customer Reminders card is outside the owner-only block; managers/staff get the list without checkboxes, send buttons or the message box ("Sending reminders is done by the owner."). Unit tests: `test_stale_customer_reminders.py` (manager/staff allowed, crew refused, send still owner-only for manager/staff), `test_r068_…::test_r069_…` (page roles). E2E: time machine server TM-06/06b/06c/06d (owner / manager / staff / field crew Reports screens) and TM-07 (API by role, incl. send refused for manager/staff/crew); live SRV-API-01 (crew_no), SRV-SCR-01/02.* | unit + TM + SRV-API-01, SRV-SCR-01/02 |

Entries marked **(open)** are known bugs not fixed yet. Their tests are written anyway and marked `xfail(strict=True)`: they're reported as "expected failure" until the fix lands, and the moment a fix makes one pass, pytest flags it so the marker gets removed and the test becomes a normal regression guard. (None are open as of 2026-09-25; R-010..R-014 also have server-level tests in `tests\mcp_tests\test_live_findings_2026_09_25.py`.)

---

## 10. Adding a regression test when a new bug is found

1. Reproduce it on the **sandbox date** with ZTEST data. If it only shows on real data, copy the relevant rows' shape (not the real customer) into `data.py`.
2. Optionally record the clicks: `python -m playwright codegen --channel chrome <jobs url>`, then translate the recording into page-object calls.
3. Add `test_R_###_<slug>` to `test_regressions.py` with the symptom, date found, and fix reference in its docstring. Add the row to §9.
4. Confirm it **fails on the unfixed build** (or at least on a build where the fix is reverted locally) and **passes on the fixed build**.

---

## 11. Implementation plan

| Phase | Deliverable | Contents | Done when |
|---|---|---|---|
| **0 — Groundwork** | Small `index.html` PR + `pytest.ini` marker | Add `data-testid` to the controls in §5.2 (no behavior change); add the `jobs_gui_e2e` marker and default exclusion; git-ignore `artifacts\` | Existing 3,000 tests still pass; static test asserts the test IDs exist |
| **1 — Harness** | `conftest.py`, `safety.py`, `data.py`, runner `.bat` | Chrome launch (headed / headless / background), login + saved storage state, pre-flight checks, write guard with full tool classification, ZTEST setup and continuous cleanup with zero-left verification, backup, all logs and artifacts from §7 | AUTH-01..06 and NAV-01..03 pass in both `--headed` and `--background`; a deliberate write to a non-ZTEST job is **blocked** by the guard (guard self-test); `SUMMARY.txt` reports `0 ZTEST rows left`; a deliberately failing test produces a complete `failures\<ID>\` folder |
| **2 — Route (highest value)** | `test_route_*.py`, `links.py`, `test_regressions.py` | §6.5 in full + R-001..R-009 | All route tests pass headless on the live app twice in a row (flakiness check) |
| **3 — Other screens** | Jobs, Board, Calendar, Clock, Photos, Messages, Database, Reports, Profile | Code-review each screen, finalize its *(outline)* cases, implement | Every screen has at least a render + main-action test; console-error sweep clean |
| **4 — Mobile + PWA** | `test_mobile_layouts.py`, `test_pwa_behavior.py` | §6.9, §6.10 | Pass on both emulated devices |
| **5 — Release gate** | Doc + habit | Add "run `run_tests_gui_jobs_e2e.bat`" as a step after `update_install.bat` in the deploy notes / user guide | First release shipped with a green E2E report attached |

Rough effort: Phase 0–1 about one session; Phase 2 one to two sessions; Phase 3 two to three sessions, depending on how many screens need code review first; Phases 4–5 one session.

---

## 12. Decisions (David, 2026-09-25)

| # | Question | Decision | Where it's applied |
|---|---|---|---|
| 1 | Sandbox date | ~~2030-01-07~~ → **today, recalculated each run**, ± a few days when a test needs other dates (David, 2026-09-25: views hide dates far from today; this is a validation database; the suite must work as a daily regression) | §4.1 |
| 2 | Mode | **Personal mode only for now.** Server-mode tests stay specified for later. | §4.6, §6.1 (AUTH-07/08), §6.11 |
| 3 | Test addresses | **Public New Smyrna Beach landmarks** (city hall, library, parks) | §4.1, `data.py` |
| 4 | Real-email recipient | **david.vavro1@gmail.com**, and **as few emails as possible**: safe tier sends none; email tier sends exactly one per run; "it worked once, it'll work again" | §4.3, §4.4 |
| 5 | `data-testid` in `index.html` | **Approved** (Phase 0). **Plus: leave no junk.** Clean up test data as soon as it's no longer needed, and verify zero left at the end. | §4.5, §11 |
| 6 | How to run | **Watch it live** (`--headed`) **or in the background** (`--background`); **always manual**; full logs so errors can be debugged; final results always visible | §7, §8 |
| 7 | Watching the tests (2026-09-25/26) | **Always run in human mode** (`--human`): visible browser, slowed clicks, key-by-key typing including the login password — including every run Claude starts. **Start simple:** page-by-page button tests, and follow the Getting-started wizard's flow. | §0.1, §6.14, §6.15 |

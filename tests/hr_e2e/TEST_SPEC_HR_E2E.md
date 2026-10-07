# AI-Prowler HR — End-to-End Test Specification (HR E2E)

**Apps under test:** the real, installed HR Admin PWA (`/hr_admin/`) and Employee Portal PWA (`/hr_portal/`), hosted by AI-Prowler on this PC
**Backend:** `ai_prowler_mcp.py` HR API (`/hr-api/...`) + `hr_db.json`
**Test tool:** Playwright (real Chrome browser — real mouse clicks, typing, scrolling, dragging)
**Run by:** AI-Prowler `run_script` → `run_tests_hr_e2e.py` — **only when Jamie starts it** (no schedule, no Claude Code)
**Location:** `AI-Prowler\tests\hr_e2e\` (part of the repo, pushed to GitHub)
**Version:** 1.3 — September 25, 2026

**Changes in 1.3 (spec review):** brought the spec in line with what's actually built — real file layout (§2, §22), runner options marked built vs planned (§2.2), config no longer holds a token or password (§3.2), messages and incident reports clean up through the existing admin delete route (§3.4, §3.6), AUTH-03 uses the one-time PIN, X-MSG-01 steps and outbox exclusion documented (§8), new messaging/security findings added to Known Issues (§19.5) with new tests PRT-MSG-02 and PRT-SEC-02/03, test-writing lessons learned (§19.6), phone-view testing plan added (§24), status updated (§23).

**Changes in 1.2:** added **Part II — Test Plan** (Sections 14–19: scope, approach, test data, per-app plans, integrated plan, schedule, entry/exit criteria, risks) and **Part III — Implementation Plan** (Sections 20–23: phases, file layout, backend test support, definition of done, status). Test Tester signs in with a one-time PIN (portal logins use each employee's own token/PIN, not the AI-Prowler token).

**Changes in 1.1:** moved into the repo; script renamed `run_tests_hr_e2e`; tests run against the real installed apps; every test cleans up its own data **and verifies** the cleanup; database backup is an emergency snapshot only (not auto-restored); Test Tester uses a Gmail plus-address; `.gitignore` added; test cleanup API added to the build list.

---

## 1. Goals

1. Click through **every page and feature** of both apps like a real person — mouse clicks, typing, picking dates, dragging.
2. Test the two apps **together**: an action in the Portal must show up correctly in HR Admin, and the other way around.
3. Be **watchable**: visible browser, slowed down, red dot on every click, video + screenshots of every step.
4. Write a **log file** for every run (results, errors, console errors, failed server calls) for later debugging.
5. **Leave no trace:** every test deletes the test data it created and then **checks it's really gone**.
6. Catch bugs we already fixed if they ever come back (Section 9).

---

## 2. Tooling & Folder Layout

**Built so far (Sept 25):**

| File | What it does |
|---|---|
| `run_tests_hr_e2e.py` | Runner: snapshot, token, pre-flight, Test Tester + one-time PIN, Playwright install, run, log, summary |
| `playwright.config.js` | Visible browser, slow motion, video, screenshots, traces, service workers blocked |
| `helpers/common.js` | Settings, red click dot, console-error/failed-call watcher, Portal sign-in, Getting Started pop-up closer, bad-text check |
| `helpers/admin.js` | HR Admin sign-in; open menu pages (opens ☰ Menu when the sidebar is off-screen) |
| `helpers/api.js` | Admin API client, `ZZTEST` tags, message lookups, **Cleanup** tracker (record → delete → verify) |
| `specs/01_portal_layout.spec.js` | **PRT-LAY-01** ✅ passing |
| `specs/30_cross_messaging.spec.js` | **X-MSG-01** ✅ passing |
| `README.md`, `.gitignore`, `package.json`, `test_config.example.json` | How to run; secrets/logs kept out of GitHub |

The tree below is the **target** layout; §22 has the full plan. Planned helpers `login.js`, `nav.js`, `checks.js`, `tags.js` are currently combined in `common.js` / `api.js` and may stay that way.

```
C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\
└── tests\
    └── hr_e2e\
        ├── TEST_SPEC_HR_E2E.md        ← this document
        ├── README.md                  ← how to install & run (short)
        ├── .gitignore                 ← keeps secrets, logs, videos out of GitHub
        ├── run_tests_hr_e2e.py        ← the ONE script you run
        ├── test_config.example.json   ← template (committed)
        ├── test_config.json           ← real URL + tokens (NOT committed)
        ├── package.json               ← Playwright install
        ├── playwright.config.js       ← browser settings (visible, slow-mo, video)
        ├── helpers\
        │   ├── login.js               ← log into Admin / Portal
        │   ├── nav.js                 ← open a sidebar page and wait for it
        │   ├── checks.js              ← layout, console-error, toast, "undefined" checks
        │   ├── cleanup.js             ← delete this test's data + verify it's gone
        │   └── tags.js                ← unique ZZTEST names per run/test
        ├── specs\
        │   ├── 01_smoke.spec.js
        │   ├── 02_auth.spec.js
        │   ├── 10_portal_profile.spec.js
        │   ├── 11_portal_workspace.spec.js
        │   ├── 12_portal_company.spec.js
        │   ├── 13_portal_money_timeoff.spec.js
        │   ├── 14_portal_hr.spec.js
        │   ├── 20_admin_employees.spec.js
        │   ├── 21_admin_recruiting.spec.js
        │   ├── 22_admin_timeoff.spec.js
        │   ├── 23_admin_offboarding.spec.js
        │   ├── 30_cross_app.spec.js
        │   └── 90_regression.spec.js
        └── logs\                       ← NOT committed
            └── run_2026-09-25_14-30-05\
                ├── run_tests_hr_e2e.log   ← human-readable log
                ├── results.json           ← machine-readable results
                ├── cleanup_report.txt     ← what was deleted + verification
                ├── hr_db.snapshot.json    ← emergency backup (not auto-restored)
                ├── report\index.html      ← click-through HTML report
                ├── screenshots\
                ├── videos\
                └── traces\                ← step-by-step replays
```

### 2.1 `.gitignore`

```
test_config.json
logs/
node_modules/
test-results/
playwright-report/
```

### 2.2 `run_tests_hr_e2e.py` — what it does

A plain Python script, so AI-Prowler's `run_script` can start it. It **only runs when started by hand**. Steps:

1. Creates `logs\run_<date>_<time>\`.
2. Saves an **emergency snapshot** of `hr_db.json` to `hr_db.snapshot.json`. This is **not** restored automatically (restoring could erase real work done during the run). It's there only if cleanup ever goes badly wrong — see 2.4.
3. **Pre-flight checks** (stops with a clear message if any fail):
   - AI-Prowler is running and `/hr_admin/`, `/hr_portal/`, `/hr-api/` answer.
   - `test_config.json` exists and the admin token works.
   - **No leftover test data** from an earlier run (runs the leftover check from 3.4). If leftovers exist, it cleans them and verifies before starting.
4. Makes sure the **Test Tester** employee exists (creates it once if missing) and saves its current profile as the **baseline**.
5. Runs Playwright with the chosen options.
6. After all tests: **final cleanup sweep + verification** (3.4), and restores Test Tester's profile to the baseline.
7. Writes everything to `run_tests_hr_e2e.log` as it goes and prints a summary:
   `48 passed, 2 failed, 1 skipped · Cleanup VERIFIED (0 leftovers) · log: logs\run_...\run_tests_hr_e2e.log`

**Options:**

| Option | What it does | Status |
|---|---|---|
| `--test "PTO"` | Run only tests whose name contains the text | ✅ built |
| `--watch` | Visible browser, slowed down (**default**) | ✅ built (default) |
| `--fast` | Hidden browser, full speed | ✅ built |
| `--slow 800` | Milliseconds per action in watch mode | ✅ built |
| `--no-pause` | Don't wait for Enter at the end (used when AI-Prowler runs it) | ✅ built |
| `--suite smoke` | Run one group: `smoke`, `auth`, `portal`, `admin`, `cross`, `regression` | ⏳ planned (use `--test` meanwhile) |
| `--priority P1` | Run only P1 tests (quick pre-deploy check) | ⏳ planned |
| `--no-cleanup` | Keep test data for debugging (log warns loudly; next run's pre-flight cleans it) | ⏳ planned |
| `--cleanup-only` | Don't test — just find, delete, and verify any leftover test data | ⏳ planned (each test pre-sweeps its own leftovers meanwhile) |

### 2.3 Watching the tests (screen movements)

| Setting | Value | Why |
|---|---|---|
| `headless` | `false` (watch mode) | A real Chrome window opens on the Game PC screen |
| `slowMo` | 400 ms per action | Slow enough to follow each click and keystroke |
| Click marker | Red dot drawn where each click lands | See exactly what's being clicked |
| Side-by-side | Cross-app tests open Portal (left) + Admin (right) | Watch data travel between apps |
| `video` | On for every test | Saved in `videos\` |
| `screenshot` | After each major step + on failure | `screenshots\<test-id>_<step>.png` |
| `trace` | On | Replay: `npx playwright show-trace <file>` |
| Viewport | 1280×900; 390×844 for phone layout tests | |

> `run_script` starts scripts in the background. First setup task: confirm the Chrome window appears on screen. If it can't, videos and traces still record every movement.

### 2.4 Emergency restore (manual only)

If a run crashes badly and leaves a mess that `--cleanup-only` can't fix:
1. Quit AI-Prowler.
2. Copy `logs\run_...\hr_db.snapshot.json` over `C:\Users\jamie\.ai-prowler\hr\hr_db.json`.
3. Start AI-Prowler.
⚠️ This undoes **all** HR changes made since that run started — real ones too.

### 2.5 What gets logged for every test

- Test ID, name, suite, start/end time, duration, PASS / FAIL / SKIP
- On failure: error, the step it failed on, page URL, screenshot, video, trace path
- **Browser console errors** — any red error fails the test (small allow-list for harmless extension noise)
- **Failed server calls** — any `/hr-api/` response ≥ 400 with URL and status
- Any red error toast shown by the app
- **Cleanup result** for that test: what was created, what was deleted, and `CLEANUP VERIFIED` or `CLEANUP FAILED: <leftovers>`
- Emails the test triggered (to the Test Tester inbox) — see 3.5

---

## 3. Environment, Test Account & Cleanup

### 3.1 Target

Tests run against the **real installed apps** that AI-Prowler hosts on this PC, e.g. `https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com`. Deploy the latest code (`deploy_hr.py`, restart AI-Prowler if the backend changed) **before** running tests — the tests check what's installed, not the dev folder.

### 3.2 `test_config.json` (optional — stays on this PC, never pushed)

**No secrets go in this file.** The admin token is read at run time from AI-Prowler's own `C:\Users\jamie\.ai-prowler\config.json` (`remote_token`), and Test Tester gets a fresh random 8-digit PIN every run (set through `POST /portal/set-pin`). Both are masked as `********` in every log.

`test_config.example.json` (committed) shows the shape — copy it to `test_config.json` only to change a setting:

```json
{
  "base_url": "https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com",
  "test_employee": {
    "first_name": "Test",
    "last_name": "Tester",
    "email": "jamievavroaiprowler+hrtest@gmail.com"
  },
  "watch": true,
  "slow_mo_ms": 400
}
```

### 3.3 The Test Tester account

- A **permanent** employee: **Test Tester**, title `QA Test Account`, department `Testing`.
- Email: **`jamievavroaiprowler+hrtest@gmail.com`**.
  - Why the `+hrtest`: Jamie's own employee record already uses `jamievavroaiprowler@gmail.com`, and the Portal logs people in by email — two employees with the same email would clash at login. Gmail delivers anything sent to `name+anything@gmail.com` to the same inbox, so every Test Tester email still lands in **jamievavroaiprowler@gmail.com**, while the login stays separate.
  - If the server ever rejects the `+`, fall back to a separate test mailbox (decide with Jamie).
- Tests **only** log into the Portal as Test Tester. They never log in as, edit, approve, or message anything for a real person.
- Test Tester is never deleted; its profile is reset to the baseline at the end of each run.

### 3.4 Cleanup rules (every test)

**Tagging.** Everything a test creates is named with a unique tag:
`ZZTEST-<runId>-<testId>` — e.g. `ZZTEST-0925-1430-PRT-TSK-02 Send weekly report`.
Records that can't hold a name (clock-ins, attendance days, time-off requests) are tied to **Test Tester's employee ID**.

**Each test must:**
1. **Record** everything it creates (IDs) as it goes.
2. **Delete** it in its cleanup step — this runs even if the test fails.
3. **Verify** it's gone by asking the server again (and checking the screen where it showed up). If anything remains, the test is marked **CLEANUP FAILED** in the log with the leftover IDs, even if the test itself passed.
4. **Restore** anything it changed on an existing record (e.g. Test Tester's phone number, a manager toggle) and verify the original value is back.

**Final sweep (end of run, and pre-flight at start):** search every data area for `ZZTEST` names and for Test Tester activity; delete anything found; verify **zero** remain; write `cleanup_report.txt`.

**Data areas checked:**

| Area | Created by tests | How it's cleaned |
|---|---|---|
| Employees | `ZZTEST Helper`, imported contacts | Admin delete employee |
| Time-off requests | Test Tester requests | `/pto/<id>/delete` (admin) |
| Attendance days | Approved test PTO | Removed with the request |
| Clock-ins / time entries | Test Tester clock in/out | **Test cleanup API** (3.6) |
| Directory contacts | `ZZTEST Contact` | Directory delete |
| Recruiting | `ZZTEST` positions, candidates, interviews, offers | Remove from recruiting bundle and save |
| Messages | Test Tester ↔ HR (subject starts `ZZTEST`) | Existing admin `POST /messages/delete` ✅ (used by X-MSG-01) |
| Incident reports | Test Tester reports | Same `POST /messages/delete` — incident reports are stored as messages (`message_type: incident_report`) |
| Calendar events | `ZZTEST` events | Delete event |
| Offboarding / termination | `ZZTEST Helper` | Deleted with the employee |
| Test Tester profile | About Me, emergency contacts, photo, manager flag | Reset to baseline |
| Browser-only data | Tasks, reminders, photos in localStorage | Each test starts with a **fresh browser profile**, so nothing carries over |

### 3.5 Emails

Any email the apps send to Test Tester goes to **jamievavroaiprowler@gmail.com** (via the `+hrtest` address). Tests that trigger an email log the subject and time. Checking the email arrived is **manual** for now (Section 11); later, Claude can check the inbox after a run on request.

### 3.6 Test cleanup API (to build — backend)

Some records have no delete route (clock-ins / time entries, schedule-change requests). Messages and incident reports **don't** need this — they use the existing admin `POST /messages/delete`. Add two **admin-only** routes to `ai_prowler_mcp.py`:

- `POST /hr-api/test/cleanup` — deletes **only** records that (a) belong to the Test Tester's employee ID, or (b) have a name/title starting with `ZZTEST`. Returns counts per area.
- `GET /hr-api/test/leftovers` — returns anything still matching those rules (should be empty).

Safety: requires the admin token **and** a header `X-HR-Test-Mode: 1`; refuses to touch any employee other than Test Tester and `ZZTEST` helpers; logs every deletion.

---

## 4. Test ID Format & Priority

`<APP>-<AREA>-<NN>` — e.g. `PRT-PTO-03`, `ADM-TOF-02`, `X-PTO-01`

| Prefix | Meaning |
|---|---|
| `SMK` | Smoke (is everything alive) |
| `AUTH` | Login / logout |
| `PRT` | Employee Portal |
| `ADM` | HR Admin |
| `X` | Cross-app (Portal ↔ Admin) |
| `REG` | Regression (fixed bugs stay fixed) |
| `CLN` | Cleanup verification |

**P1** = run before every deploy (`--priority P1`) · **P2** = regular full run · **P3** = occasional / nice to have.

---

## 5. Smoke, Login & Cleanup Tests

| ID | Pri | Test | Steps | Expected |
|---|---|---|---|---|
| SMK-01 | P1 | Admin loads | Open `/hr_admin/` | Loads, no console errors |
| SMK-02 | P1 | Portal loads | Open `/hr_portal/` | Login screen, no console errors |
| SMK-03 | P1 | API reachable | Call `/hr-api/` | Answers within 5 s |
| AUTH-01 | P1 | Admin login | Enter token → submit | Employees list appears |
| AUTH-02 | P1 | Admin bad token | Wrong token | Error, stays on login |
| AUTH-03 | P1 | Portal login | Test Tester email + one-time PIN → Sign in → close 🚀 Getting Started pop-up (✕) | Sidebar shows **Test Tester** (not "Employee") — ✅ covered inside PRT-LAY-01 and X-MSG-01 |
| AUTH-04 | P1 | Portal bad password | Wrong password | Error, stays on login |
| AUTH-05 | P1 | Session restore | Log in → reload | Still logged in; Portfolio boxes filled |
| AUTH-06 | P1 | Sign out | Click **Sign out** | Back to login; no console error |
| CLN-01 | P1 | Pre-flight clean | Start of run | Zero leftovers before tests begin |
| CLN-02 | P1 | Final sweep | End of run | Zero `ZZTEST` records and zero Test Tester activity remain; Test Tester profile equals baseline |

---

## 6. Employee Portal Tests

### 6.1 Layout — every page (P1)

**PRT-LAY-01 — Every sidebar page opens inside the layout.** For **each** sidebar item (Welcome, About, Portfolio, Details, Emergency Contacts, Daily News, Home/Feed, Schedule, Time Clock, Pay & Benefits, Tasks/Projects, Directory, Documents, Help/Support, Messages, Payroll, Deposits, Calendar, Company Calendar, PTO/Time Off, HR Handbook, Write-Ups, Trainings, Incident Reports, My Team if shown):
1. Click it. 2. Header text visible. 3. Page sits **inside** the main area (right of the sidebar, not below). 4. Sidebar full height. 5. No sideways window scrollbar. 6. Screenshot.

**PRT-LAY-02 — Phone size:** repeat at 390×844.
**PRT-LAY-03 — Back button:** open 3 pages → **← Back** twice → correct pages.

### 6.2 My Profile

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| PRT-WEL-01 | P2 | Welcome cards | Click each Quick Tour card | Opens matching page | — |
| PRT-POR-01 | P1 | Portfolio filled | Open Portfolio | Name, title, dept, ID, start date, status, email, type, manager — no `—` | — |
| PRT-POR-02 | P1 | Portfolio header | Open Portfolio | "My Portfolio" + subtitle | — |
| PRT-POR-03 | P2 | Daily quote | Open Portfolio | ✨ Daily Inspiration has text | — |
| PRT-POR-04 | P2 | Quote changes | Portfolio → other page → Portfolio | Different quote | — |
| PRT-POR-05 | P1 | Days Clocked real | Open Portfolio | Number + "X in · Y out" matching `/timeclock/summary` | — |
| PRT-POR-06 | P2 | Add daily reminder | `ZZTEST… Check email` → 🔁 Daily → 9:00 → + Add | 🔁 Daily tag, ⏰ 9:00 AM | Delete (×) → verify gone |
| PRT-POR-07 | P2 | Add one-time task | `ZZTEST… Submit form` → ✅ Task | ✅ Task tag | Delete → verify |
| PRT-POR-08 | P2 | Check/uncheck | Click circle twice | Done then open again | (from POR-06) |
| PRT-POR-09 | P2 | Reminder survives reload | Add → reload → Portfolio | Still there | Delete → verify |
| PRT-POR-10 | P2 | Delete reminder | × | Gone | — |
| PRT-POR-11 | P3 | Photo upload | Avatar → test image | Shows in Portfolio, sidebar, header | Restore baseline photo |
| PRT-ABT-01 | P1 | About view mode | Open About | Banner + 3 cards with ✏️ Edit | — |
| PRT-ABT-02 | P1 | Save Personal Info | Edit → Preferred Name `ZZTEST… Name` → Save | "Saved" toast; card updated | Restore baseline → verify |
| PRT-ABT-03 | P1 | Persists | Leave → return → reload | Still new name | (ABT-02) |
| PRT-ABT-04 | P2 | Cancel discards | Edit → change → Cancel | Old value | — |
| PRT-ABT-05 | P2 | Fun Stuff save | Edit → Fun Fact + Coffee → Save | Tiles updated | Restore baseline |
| PRT-ABT-06 | P2 | Work Style save | Edit → dropdowns → Save | Tiles updated | Restore baseline |
| PRT-ABT-07 | P2 | Email locked | Edit Personal Info | Personal Email not editable | — |
| PRT-ABT-08 | P2 | Date picker | Click Date of Birth | Pop-up calendar | — |
| PRT-EMC-01 | P1 | Emergency page | Open 🚨 Emergency Contacts | Page + status banner | — |
| PRT-EMC-02 | P1 | Save contacts | Edit → `ZZTEST…` primary + backup → Save | "Sent to HR"; banner green | Restore baseline → verify |
| PRT-EMC-03 | P1 | Empty warning | Clear contacts → view | Red "No emergency contact" banner | Restore baseline |
| PRT-DTL-01 | P3 | Details | Open Details | Loads with data | — |

### 6.3 Workspace

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| PRT-NEWS-01 | P2 | Daily News | Open 📰 Daily News | Masthead, today's date, Tip filled | — |
| PRT-FEED-01 | P3 | Home / Feed | Open | Feed loads | — |
| PRT-SCH-01 | P1 | Schedule | Open | Week shifts, Requests, time-off lists | — |
| PRT-SCH-02 | P1 | Day counts | View requests | "N days", never "undefined" | — |
| PRT-SCH-03 | P1 | Delete (hide) | 🗑 on a Test Tester request → confirm | Gone from Portal lists; **still in Admin** | Admin delete → verify |
| PRT-SCH-04 | P3 | Swap a Shift | Fill → submit | Confirmation | Test cleanup API |
| PRT-TC-01 | P1 | Clock in | Time Clock → Clock In | Clocked-in status; new entry | Test cleanup API → verify |
| PRT-TC-02 | P1 | Clock out | Clock Out | In/out times + hours | (TC-01) |
| PRT-TC-03 | P2 | Running Late / Out Today | Click each | Confirmation (location stays locked) | Test cleanup API |
| PRT-PAY-01 | P2 | Pay charts | Open Pay & Benefits | 6 bars + DEMO tag; benefits ring drawn | — |
| PRT-PAY-02 | P3 | Hourly calculator | Type a rate | Numbers update | — |
| PRT-TSK-01 | P1 | Tasks page | Open | 4 boxes, task list, 3 projects | — |
| PRT-TSK-02 | P1 | Add task | `ZZTEST… Task` → date via calendar → High → + Add | Red High tag; counts update | Delete → verify |
| PRT-TSK-03 | P1 | Complete + Oops | Tick → Oops in toast | Back to open | Delete → verify |
| PRT-TSK-04 | P2 | Oops in Done tab | Done tab → ↩ Oops | Back in All Open | Delete → verify |
| PRT-TSK-05 | P2 | Filter tabs | Each tab | Lists/counts match | — |
| PRT-TSK-06 | P2 | Drag → Due Today | Drag task onto box | Due today; Oops toast | Delete → verify |
| PRT-TSK-07 | P2 | Drag → Completed | Drag onto box | Done | Delete → verify |
| PRT-TSK-08 | P3 | Project countdown | View projects | "N days left", right colors | — |
| PRT-TSK-09 | P2 | Survives reload | Add → reload | Still there | Delete → verify |

### 6.4 Company

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| PRT-DIR-01 | P2 | Search | Type "Vavro" | Filters list | — |
| PRT-DIR-02 | P2 | Add contact | + Add Contact `ZZTEST… Contact` | Listed | Delete → verify |
| PRT-DIR-03 | P2 | Edit/delete | ✏️ → save; 🗑 | Updated; removed | Verify gone |
| PRT-DOC-01 | P2 | Documents | Click a document | Opens / downloads | — |
| PRT-HLP-01 | P2 | Help cards | Open Help / Support | 4 cards | — |
| PRT-HLP-02 | P3 | AI Assistant | Ask a question | Answer appears | — |
| PRT-MSG-01 | P1 | Message HR | `ZZTEST…` subject + text → Send | Confirmation; in list | Test cleanup API → verify |

### 6.5 Money & Time Off

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| PRT-PRL-01 | P3 | Payroll | Open | Loads | — |
| PRT-DEP-01 | P2 | Deposits | Update Bank Account with test numbers | Only last 4 digits shown/stored | Restore baseline |
| PRT-CAL-01 | P2 | My Calendar | Open | 12 months; holidays, PTO, birthdays | — |
| PRT-CAL-02 | P2 | Calendar reminder | Add `ZZTEST…` reminder | Listed | Delete → verify |
| PRT-CCAL-01 | P2 | Company Calendar | Open | Events shown | — |
| PRT-PTO-01 | P1 | Balances | Open PTO / Time Off | 3 boxes with numbers | — |
| PRT-PTO-02 | P1 | Date pickers | Click Start, then End | Pop-up calendar each | — |
| PRT-PTO-03 | P1 | Submit request | Vacation → dates → note `ZZTEST…` → Submit | Pending in history | Admin delete → verify |
| PRT-PTO-04 | P2 | Half day | Tick Half day → submit | 0.5 days | Admin delete → verify |
| PRT-PTO-05 | P2 | End before start | Invalid dates → Submit | Blocked with message | Verify nothing created |

### 6.6 HR & Manager

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| PRT-HB-01 | P2 | Handbook | Open → a section | Section opens | — |
| PRT-WU-01 | P3 | Write-Ups | Open | List or empty message | — |
| PRT-TRN-01 | P2 | Trainings | Open | Content in main area; Optional box **below** Required | — |
| PRT-INC-01 | P1 | Incident report | + New → `ZZTEST…` → submit | Listed as Pending | Test cleanup API → verify |
| PRT-MGR-01 | P3 | My Team | Test Tester as manager of Helper | Helper listed | Reset manager flag; delete Helper → verify |

---

## 7. HR Admin Tests

### 7.1 Layout (P1)

**ADM-LAY-01** — open every Menu page; header visible; no console errors; screenshot.
**ADM-LAY-02** — primary buttons are cyan, not plain white (Recruiting → Interviews, Time Off).

### 7.2 Employees

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| ADM-EMP-01 | P1 | List | Employees, All | Everyone listed with badges | — |
| ADM-EMP-02 | P1 | Filter chips | Hiring / Onboarding / Active / Terminated | Correct people (case-insensitive; Hiring incl. Pre-Start) | — |
| ADM-EMP-03 | P1 | Add employee | + → `ZZTEST… Helper` | Under Onboarding with tasks | Delete → verify |
| ADM-EMP-04 | P2 | Search | Type name | Filters | — |
| ADM-EMP-05 | P1 | Employee sheet | Open Test Tester; every tab | All tabs open, no errors | — |
| ADM-EMP-06 | P2 | Edit Info | Change phone → save → reopen | Saved | Restore baseline → verify |
| ADM-EMP-07 | P1 | Emergency edit | 🚨 → Edit → Save | Toast; "Last updated … by HR Admin" | Restore baseline |
| ADM-EMP-08 | P2 | Change photo | Test image | Shows on card | Restore baseline |
| ADM-EMP-09 | P2 | Direct reports | Is a Manager → add Helper → Remove | Added then removed | Reset flag; delete Helper |
| ADM-EMP-10 | P2 | Onboarding task | Helper → tick task | Progress up | Delete Helper |
| ADM-EMP-11 | P2 | Import from Directory | Add `ZZTEST… Contact` → 📇 Import → Create | Becomes employee; others "already an employee" | Delete employee + contact → verify |
| ADM-EMP-12 | P3 | Delete employee | ⋮ → Delete Helper | Removed | Verify gone |

### 7.3 Recruiting

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| ADM-REC-01 | P2 | Tabs | All 6 tabs | Each loads | — |
| ADM-REC-02 | P2 | Add position | `ZZTEST… Role` | Listed; Open Roles +1 | Remove → verify |
| ADM-REC-03 | P2 | Add candidate | `ZZTEST… Candidate` | Listed | Remove → verify |
| ADM-REC-04 | P1 | Schedule interview | Date + time via pop-ups → Schedule | Listed under Interviews | Remove → verify |
| ADM-REC-05 | P1 | Interview sheet | Click interview | 15 questions, 4 groups | — |
| ADM-REC-06 | P1 | Rate & save | Notes on 2 Qs, stars, 👍 Hire, overall → Save | "📝 2/15 answered ★… 👍 Hire" | (REC-04) |
| ADM-REC-07 | P2 | Persists | Reload → reopen | All still there | (REC-04) |
| ADM-REC-08 | P2 | Custom question | + Add own → Save | Under "My Questions" | (REC-04) |
| ADM-REC-09 | P3 | Mark Done | Done | Marked done | (REC-04) |
| ADM-REC-10 | P3 | Offer | Create offer | Offers Out +1 | Remove → verify |
| ADM-REC-11 | P3 | Wizard Hire | Walk through with `ZZTEST…` | Employee created | Delete employee + records → verify |

### 7.4 Time Off

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| ADM-TOF-01 | P1 | Calendar | Open Time Off | Month view, PTO bars, holidays | — |
| ADM-TOF-02 | P1 | Approve pending | ✅ Approve | To Approved; on calendar | Delete → verify (incl. attendance days) |
| ADM-TOF-03 | P1 | Deny pending | ❌ Deny | To Denied | Delete → verify |
| ADM-TOF-04 | P1 | Approved → Denied | ❌ Deny → confirm | Denied; days **removed** from calendar | Delete → verify |
| ADM-TOF-05 | P1 | Denied → Approved | ✅ Approve → confirm | Approved; days on calendar **once** | Delete → verify |
| ADM-TOF-06 | P1 | Remove | Remove → confirm → leave → return | Stays gone | Verify |
| ADM-TOF-07 | P2 | Add event | Date via pop-up → save | On calendar | Delete → verify |
| ADM-TOF-08 | P3 | Sub-tabs | 6 sub-tabs | Each shows list | — |

### 7.5 Offboarding & Termination Records

| ID | Pri | Test | Steps | Expected | Cleanup |
|---|---|---|---|---|---|
| ADM-OFF-01 | P2 | Start offboarding | Pick Helper → type + last day | In offboarding list | Delete Helper → verify |
| ADM-OFF-02 | P2 | Checklist | Tick items | Saved | (OFF-01) |
| ADM-OFF-03 | P1 | Terminate | Complete termination | In 📋 Termination Records; no data deleted | Delete Helper → verify |
| ADM-OFF-04 | P1 | Saved File | 📁 Saved File | 6 sections shown | (OFF-03) |
| ADM-OFF-05 | P2 | Print / PDF | 🖨 Print | Print window opens, no buttons | Close window |
| ADM-OFF-06 | P3 | Termination letter | 📄 Letter | Generated | (OFF-03) |

---

## 8. Cross-App Tests (Portal ↔ Admin side by side)

| ID | Pri | Flow | Expected | Cleanup |
|---|---|---|---|---|
| X-PTO-01 | P1 | Portal submits PTO → Admin Pending | Same dates, type, note | Admin delete → verify both apps |
| X-PTO-02 | P1 | Admin Approves → Portal refresh | Portal: Approved + Upcoming; Admin calendar has days | Admin delete → verify |
| X-PTO-03 | P1 | Admin → Denied → Portal refresh | Portal: Denied; days gone | Admin delete → verify |
| X-PTO-04 | P1 | Portal 🗑 hide → Admin | Still in Admin, unchanged | Admin delete → verify |
| X-PTO-05 | P1 | Admin Remove → Portal refresh | Gone in Portal | Verify |
| X-EMC-01 | P1 | Portal saves Emergency → Admin 🚨 tab | Same data; "by employee" | Restore baseline → verify |
| X-EMC-02 | P1 | Admin edits Emergency → Portal | Portal shows HR's version; green | Restore baseline → verify |
| X-TC-01 | P1 | Portal Clock In/Out → Admin Attendance | Correct times | Test cleanup API → verify |
| X-TC-02 | P2 | Clock-ins → Portfolio Days Clocked | Count goes up correctly | Test cleanup API → verify count back |
| X-PRO-01 | P1 | Admin changes title/dept → Portal Portfolio | New values shown | Restore baseline → verify |
| X-PRO-02 | P2 | Portal DOB → Admin Info + calendars | Birthday shows | Restore baseline |
| X-MSG-01 | P1 | Portal (Messages page) sends → server: saved, tied to Test Tester, unread → Admin 💬 Messages: card shows **NEW**, open, text matches → **Send Reply** → card shows "↩ Replied", not NEW → server: reply stored, read → Portal **↻ Refresh**: "Re: <subject>" + reply shown → Admin 🗑 delete (accepts confirm box) | Every hand-off checked on screen **and** on the server | Admin 🗑 in the test itself; finally-block `POST /messages/delete` + verify; pre-sweep of old `ZZTEST` messages. **Built** (`specs/30_cross_messaging.spec.js`) |
| — | — | *Not tested on purpose:* HR **broadcast outbox** (`/messages/hr-outbox`) — broadcasts are shown to **every** employee, so a test broadcast would reach the real team | — | — |
| X-INC-01 | P1 | Portal incident → Admin status → Portal | Status updates | `POST /messages/delete` → verify |
| X-DIR-01 | P2 | Portal Directory contact → Admin Import list | Listed for import | Delete contact → verify |
| X-MGR-01 | P3 | Admin sets manager → Portal My Team | Helper listed | Reset flag; delete Helper |

---

## 9. Regression Tests (fixed bugs stay fixed)

| ID | Bug that was fixed | Check |
|---|---|---|
| REG-01 | Stray `</div>` pushed pages below the layout (Documents onward) | PRT-LAY-01 passes for every page |
| REG-02 | Stray `</div>` before Trainings | Trainings content in main area |
| REG-03 | Startup crash on missing `ai-chat` → Portfolio dashes, sidebar "Employee" | Real name in sidebar; Portfolio filled; no console error |
| REG-04 | Sign out crashed on missing `ai-chat` | AUTH-06 |
| REG-05 | Blue "DEBUG:" box on Portfolio | No text starting "DEBUG" on Portfolio |
| REG-06 | Days Clocked read old browser data | PRT-POR-05 |
| REG-07 | "undefined days" on Schedule | PRT-SCH-02 |
| REG-08 | Admin Remove said success but request came back | ADM-TOF-06 |
| REG-09 | Admin Approve/Deny ignored server errors | Simulated server error → red toast, card doesn't move |
| REG-10 | Emergency contacts never reached HR | X-EMC-01 |
| REG-11 | Onboarding chip showed nobody (case mismatch) | ADM-EMP-02 |
| REG-12 | Admin buttons plain white | ADM-LAY-02 |
| REG-13 | Invisible calendar icon on date boxes | PRT-PTO-02, ADM-REC-04 |
| REG-14 | Pay & Benefits charts empty | PRT-PAY-01 |
| REG-15 | Approve→Deny left days on calendar / re-approve duplicated days | ADM-TOF-04, ADM-TOF-05 |
| REG-16 | "undefined", "NaN", "[object Object]" in visible text | Scan every page (Section 10) |

---

## 10. Checks Applied to Every Test Automatically

1. No red console errors (small allow-list for extension noise).
2. No failed `/hr-api/` calls (≥ 400) unless the test expects one.
3. No "undefined", "NaN", or "[object Object]" in visible text.
4. Screenshot on failure; video + trace always.
5. Cleanup ran **and was verified** (Section 3.4).

---

## 11. Out of Scope (manual for now)

- Checking that emails actually arrived in jamievavroaiprowler@gmail.com
- Real GPS location on clock-in (browser permission prompt)
- Real printing (tests only confirm the print window opens)
- Contents of downloaded files (tests confirm the download starts)
- AI Assistant answer quality (tests confirm an answer appears)
- Phone "Add to Home Screen" install and offline mode

---

## 12. Build Order

1. **Setup:** folder, `.gitignore`, `README.md`, Playwright install, `test_config.example.json` + `test_config.json`, `run_tests_hr_e2e.py` with snapshot, pre-flight, logging, summary. Confirm the Chrome window shows on screen.
2. **Test cleanup API** (Section 3.6) + `helpers\cleanup.js`; CLN-01 / CLN-02.
3. **Test Tester** account creation + baseline save/restore.
4. **Smoke + Auth** (SMK, AUTH).
5. **Layout** (PRT-LAY-01, ADM-LAY-01) + REG-01 … REG-05.
6. **P1 cross-app** (X-PTO, X-EMC, X-TC, X-MSG, X-INC).
7. Remaining **P1**, then **P2**, then **P3**.

---

## 13. Decisions (answered by Jamie, Sept 25, 2026)

| Question | Decision |
|---|---|
| Where do tests live? | `AI-Prowler\tests\hr_e2e\` — pushed to GitHub (secrets and logs ignored) |
| What do tests run against? | The real installed PWAs hosted by AI-Prowler on this PC |
| Test data cleanup | Every test deletes its own data and **verifies** it's gone; final sweep verifies zero leftovers |
| Test account | **Test Tester**, email `jamievavroaiprowler+hrtest@gmail.com` (arrives in Jamie's inbox) |
| When do tests run? | **Only** when Jamie runs `run_tests_hr_e2e` |
| Who runs them? | AI-Prowler `run_script` — not Claude Code |

**Resolved Sept 25:** Portal logins use each employee's **own** token or PIN (never the AI-Prowler token). `run_tests_hr_e2e.py` reads the AI-Prowler token from `config.json` to act as admin, then sets a **fresh random 8-digit PIN** for Test Tester via `POST /portal/set-pin` at the start of every run. Nothing is stored; the log masks both as `********`.
**Still to confirm:** whether the Chrome window appears on screen when started through AI-Prowler's `run_script` (videos and traces record either way).

---
---

# PART II — TEST PLAN

## 14. Scope & Approach

### 14.1 What's in scope

| App | Scope |
|---|---|
| **HR Admin** (`/hr_admin/`) | Every menu page; employee records (list, filters, sheet tabs, add/edit/import/delete); recruiting (positions → candidates → interviews → offers → hire); time off (approve/deny/change/remove, calendar, balances, holidays); attendance; documents; onboarding tasks; offboarding & termination records (saved file, print); emergency contacts; direct reports |
| **Employee Portal** (`/hr_portal/`) | Sign-in/out; every sidebar page; profile (About, Portfolio, Details, Emergency Contacts); time clock; schedule; PTO requests; tasks/projects; reminders; directory; documents; messages; help/AI assistant; payroll/deposits; calendars; handbook; write-ups; trainings; incident reports; Daily News; My Team |
| **Both together** | Every flow where one app writes data the other must show: time off, emergency contacts, clock-ins/attendance, profile changes, messages, incident reports, directory → import, manager/direct reports, onboarding status |

### 14.2 What's out of scope
Section 11 (real email delivery, GPS prompts, real printing, file contents, AI answer quality, offline/install). Load/performance testing and security penetration testing are separate efforts.

### 14.3 Test levels

| Level | What it proves | Where |
|---|---|---|
| **Smoke** | Both apps and the API are alive; sign-in works | `specs/01_*`, `02_*` |
| **Layout** | Every page renders inside the layout, no broken text, no console errors | `specs/portal/…layout`, `specs/admin/…layout` |
| **Functional — single app** | Each feature works start to finish inside one app | `specs/portal/*`, `specs/admin/*` |
| **Integrated — both apps** | Data created in one app appears correctly in the other, both directions | `specs/cross/*` |
| **Regression** | Bugs we fixed stay fixed | `specs/regression/*` (and tagged inside other specs) |
| **Cleanup verification** | Zero test data left behind | `specs/99_cleanup.spec.js` + per-test checks |

### 14.4 How tests interact

- **Act through the UI** — every user action (click, type, pick a date, drag) is done in the browser, the way a person would.
- **Set up and check through the API** — to keep tests fast and independent, *preparing* data (e.g. "an approved PTO request already exists") and *verifying* the server state is done through the HR API with the admin token. A test never uses the API to do the thing it's testing.
- **Every test is independent** — it creates its own data, cleans it, and verifies. Tests can run alone (`--test "X-PTO-02"`) or in any order.
- **Two windows for integrated tests** — Portal (as a test employee) and Admin (as admin) in separate browser contexts, side by side.

### 14.5 Roles used

| Role | Who | How it signs in |
|---|---|---|
| Admin | HR Admin | AI-Prowler token (read from `config.json`) |
| Employee | **Test Tester** (permanent) | Email + one-time PIN |
| Employee | ZZTEST personas (Section 15) | Email + one-time PIN set when seeded |
| Manager | ZZTEST Kevin Park | Email + one-time PIN; flagged "Is a Manager" |

Real employees (David, Jamie, Rebecca, Samantha, Christina, Vicki) are **never** signed in as, edited, approved, messaged, or deleted. Tests may only *read* the employee list (e.g. "the list shows at least 6 people").

---

## 15. Test Data Plan

Tests need **realistic** data to exercise real features — real-looking names, pay rates, dates, documents — but **never real people's information**. All test data is fictional, marked `ZZTEST`, created by the tests, and removed by the tests.

### 15.1 Test personas (employees)

| Persona | Status / dates | Job | Pay | Used for |
|---|---|---|---|---|
| **Test Tester** *(permanent)* | Active · started 30 days ago | QA Test Account · Testing | Hourly $18.50 · full-time | Every Portal test; baseline restored after each run |
| **ZZTEST Maria Lopez** | Active · started 90 days ago | Operations Associate · Operations | Hourly $19.25 · full-time | Second employee for PTO, attendance, directory, calendars |
| **ZZTEST Kevin Park** | Active · started 1 year ago · **Manager** | Shift Supervisor · Operations | Salary $52,000 | Manager / My Team / direct reports / approvals |
| **ZZTEST Dana Brooks** | **Pre-Start** · starts in 14 days | Customer Service Rep · Support | Hourly $17.00 · part-time | Hiring chip, onboarding tasks, start-date logic |
| **ZZTEST Sam Rivera** | Active → **terminated** during the test | Warehouse Associate · Operations | Hourly $18.00 | Offboarding, termination records, saved file, print |

Emails: `jamievavroaiprowler+zz-<name>@gmail.com` (all land in Jamie's inbox; all separate logins). Phones: `(480) 555-01xx` (reserved fictional range). Addresses: `123 Test St, Chandler, AZ 85226`.

### 15.2 Profile data (Test Tester baseline → test values)

| Field | Test value |
|---|---|
| Preferred name / pronouns | `ZZTEST Tess` · she/her |
| Date of birth | Oct 16, 1990 (birthday shows on calendars) |
| Emergency contact | `ZZTEST Alex Tester` · Spouse · (480) 555-0142 · backup `ZZTEST Jordan Tester` (480) 555-0143 |
| Fun Stuff / Work Style | Fun fact, "☕ Coffee — always!", "🌅 Morning", "📋 Planner" |
| Bank (Deposits) | Routing `110000000` (standard test routing number) · account `000123456789` → only `6789` shown/stored |
| Photo | `fixtures/test_photo.png` (generated avatar, no real face) |

### 15.3 Time & attendance data

| Data | Values | Used for |
|---|---|---|
| Past shifts (seeded) | Test Tester: last Mon–Fri, 8:00 AM – 4:30 PM (5 clock-ins, 5 clock-outs, 42.5 h) | Days Clocked = 5, "5 in · 5 out"; Admin Attendance; hours math |
| Live clock-in/out | Now → +2 minutes | Clock In/Out buttons, Recent Entries |
| Open shift | Clocked in, not out | "in" is one higher than "out" |
| Running Late / Out Today | Today | Self-reported section in Admin |

### 15.4 Time-off data

| Request | Dates (relative to today) | Type | Used for |
|---|---|---|---|
| Vacation (pending) | +21 → +23 days (3 days) | PTO (Vacation) | Submit, approve, deny, change decision |
| Sick day (approved) | Yesterday | Sick Day | Upcoming vs past, hide-from-my-view |
| Half day | +10 days | Personal Day, half | 0.5-day math |
| Holiday overlap | Nearest federal holiday ± 1 day | PTO | Business-day counting |
| Invalid | End before start | — | Validation message; nothing created |
| Maria's vacation | +30 → +34 days | PTO | Company calendar shows other people's time off |

### 15.5 Recruiting data

| Item | Values |
|---|---|
| Position | `ZZTEST Warehouse Associate` · Operations · $18–20/h · full-time · Open |
| Candidates | `ZZTEST Jordan Ellis` (Applied), `ZZTEST Priya Shah` (Applied) · fictional emails/phones |
| Interview | Jordan · tomorrow 10:00 AM · In-person · with Kevin Park |
| Interview answers | Notes on 3 questions, ratings 4/5/3, overall ★★★★, 👍 Hire |
| Offer | Jordan · $19/h · start in 21 days |
| Hire | Wizard Hire converts Jordan → employee `ZZTEST Jordan Ellis` |

### 15.6 Other content

| Area | Test data |
|---|---|
| Tasks (Portal) | `ZZTEST Send weekly report` (High, today), `ZZTEST Restock supplies` (Medium, +3), `ZZTEST Update contact list` (Low, overdue −2) |
| Reminders | `ZZTEST Check email` (🔁 Daily, 9:00 AM), `ZZTEST Submit form` (✅ Task) |
| Directory | `ZZTEST Contact Morgan Lee` · Facilities · morgan.lee.zztest@example.com |
| Messages | Subject `ZZTEST Schedule question`, body 2 sentences; Admin reply `ZZTEST Reply` |
| Incident report | `ZZTEST` minor slip near loading dock, no injury, witness `ZZTEST Maria Lopez` |
| Documents | `fixtures/ZZTEST_offer_letter.pdf` (1 page), `fixtures/ZZTEST_w4_sample.pdf` — generated, fictional |
| Calendar events | `ZZTEST Team Meeting` (+2 days 2:00 PM), `ZZTEST Safety Training` (+7 days) |
| Offboarding | Sam Rivera · Voluntary Resignation · last day today · final pay +3 days · checklist 5/9 |

### 15.7 How test data is created and removed

1. **Fixtures file:** all values above live in `fixtures/test_data.js` (dates computed from today, so data never goes stale).
2. **Factories:** `helpers/data.js` builds each record with the run's unique tag (`ZZTEST-<runId>-<testId>`).
3. **Seeding:** a test creates what it needs in its setup — through the API for "already exists" data, through the UI for the action under test.
4. **Tracking:** every created ID is recorded by `helpers/cleanup.js`.
5. **Cleanup + verify:** at the end of each test (even on failure) → delete → re-query the server → `CLEANUP VERIFIED` or `CLEANUP FAILED: <ids>` in the log.
6. **Final sweep:** `99_cleanup.spec.js` searches every data area for `ZZTEST` and Test Tester activity → must be zero; Test Tester profile must equal baseline.

---

## 16. HR Admin — Test Plan

### 16.1 Features and test coverage

| Feature area | Key risks | Tests (Section 7 + new) |
|---|---|---|
| Sign-in & navigation | Token rejected; page doesn't open; console errors | AUTH-01/02, ADM-LAY-01/02 |
| Employee list & filters | Wrong people in chips; search misses | ADM-EMP-01/02/04 |
| Employee records | Edits not saved; tabs crash; photo lost | ADM-EMP-03/05/06/08/12 |
| Emergency contacts | Not saved; stale view | ADM-EMP-07 |
| Direct reports / managers | Flag not saved; reports list wrong | ADM-EMP-09 |
| Onboarding tasks | Progress not updating | ADM-EMP-10 |
| Import from Directory | Duplicates; bad emails | ADM-EMP-11 |
| Recruiting pipeline | Candidate lost between stages; interview answers not saved | ADM-REC-01…11 |
| Time off | Wrong status; calendar days wrong or duplicated; Remove not persisted | ADM-TOF-01…08 |
| Attendance | Clock-ins missing or wrong hours | **ADM-ATT-01** (new, below) |
| Documents | Upload/download fail | **ADM-DOC-01** (new) |
| Offboarding & termination | Record lost; saved file incomplete | ADM-OFF-01…06 |

### 16.2 New Admin tests

| ID | Pri | Test | Data | Expected |
|---|---|---|---|---|
| ADM-ATT-01 | P1 | Attendance shows seeded shifts | Test Tester's 5 seeded shifts | 5 rows, 8:00 AM–4:30 PM, 8.5 h each, 42.5 h total |
| ADM-ATT-02 | P2 | Late / Out Today appear | Test Tester self-report | Listed under Self-Reported with today's date |
| ADM-DOC-01 | P2 | Upload employee document | `ZZTEST_offer_letter.pdf` → Test Tester | Listed in Documents tab; download starts |
| ADM-DOC-02 | P2 | Document in Saved File | Upload to Sam Rivera → terminate | Listed in 📁 Saved File with ⬇ Download |
| ADM-PAY-01 | P2 | Pay info saved | Maria: hourly $19.25 | Shows on Info tab and Saved File |
| ADM-REC-12 | P2 | Full hire pipeline | Jordan: Applied → Interview → Offer → Hire | Jordan becomes an employee; recruiting records linked |

### 16.3 Admin run order
Smoke/auth → layout → employees → emergency/direct reports → recruiting → time off → attendance/documents → offboarding → cleanup sweep.

---

## 17. Employee Portal — Test Plan

### 17.1 Features and test coverage

| Feature area | Key risks | Tests (Section 6 + new) |
|---|---|---|
| Sign-in / session | Can't sign in; session lost on reload; sign-out crash | AUTH-03…06 |
| Layout | Pages pushed out of layout; blank pages | PRT-LAY-01/02/03 ✅ *built* |
| Profile (About, Portfolio, Details) | Details show dashes; edits lost | PRT-POR-*, PRT-ABT-*, PRT-DTL-01 |
| Emergency contacts | Not sent to HR | PRT-EMC-01…03 |
| Time clock | Clock-in lost; hours wrong | PRT-TC-01…03 |
| Schedule & PTO | Wrong day counts; validation missing; hide not working | PRT-SCH-*, PRT-PTO-* |
| Tasks & reminders | Drag/undo broken; lost on reload | PRT-TSK-*, PRT-POR-06…10 |
| Company pages | Directory edits lost; messages not sent | PRT-DIR-*, PRT-MSG-01, PRT-DOC-01, PRT-HLP-* |
| Money | Bank numbers exposed; charts empty | PRT-DEP-01, PRT-PAY-*, PRT-PRL-01 |
| Calendars | Missing PTO/holidays/birthdays | PRT-CAL-*, PRT-CCAL-01 |
| HR pages | Incident not filed; trainings layout | PRT-INC-01, PRT-TRN-01, PRT-HB-01, PRT-WU-01 |
| News | Date/tip not filled | PRT-NEWS-01 |

### 17.2 New Portal tests

| ID | Pri | Test | Data | Expected |
|---|---|---|---|---|
| PRT-TC-04 | P1 | Hours math | Seeded 5 shifts | Recent Entries show 8.5 h each; weekly total 42.5 h |
| PRT-TC-05 | P2 | Open shift | Clock in, don't clock out | Portfolio shows "6 in · 5 out" |
| PRT-PTO-06 | P2 | Holiday overlap | Request spanning a federal holiday | Day count skips the holiday (or shows it clearly) |
| PRT-CAL-03 | P2 | Birthday on calendars | Test Tester DOB Oct 16 | 🎂 on Oct 16 in My Calendar and Company Calendar |
| PRT-DEP-02 | P1 | Bank privacy | Account `000123456789` | Only `6789` visible anywhere; full number never in page text or API response |
| PRT-MGR-02 | P2 | My Team as manager | Sign in as Kevin Park | Maria and Test Tester listed |
| PRT-SEC-01 | P1 | Employee can't see admin data | Signed in as Test Tester, call admin-only routes | 403 for `/employees` list, other people's PTO, other people's profiles |
| PRT-SEC-02 | P1 | Incident reports need sign-in | With **no** session, `POST /messages/my-reports` with `sender_name: "a"`; then as Test Tester, ask for another employee's name | 401/403 without a session; signed in, only **Test Tester's own** reports come back (uses a `ZZTEST` report as the probe — real reports are never printed to the log, only counted) |
| PRT-SEC-03 | P1 | Messages need sign-in | With no session, `POST /messages` (`ZZTEST` subject) and `GET /messages/outbox` | Both refused (401/403). If accepted, the test deletes the probe message and fails with a clear note |
| PRT-MSG-02 | P1 | Second "Send Message to HR" form | Find the page with `#msg-subject` / `#msg-body`, send a `ZZTEST` message as Test Tester → check in HR Admin → reply → check Portal | HR sees **Test Tester** (not "Employee") and the reply reaches Test Tester's Portal; cleanup via `/messages/delete` |

### 17.3 Portal run order
Smoke/auth → layout → profile → time clock → schedule/PTO → tasks/reminders → company → money → calendars → HR pages → cleanup sweep.

---

## 18. Both Apps Together — Integrated Test Plan

### 18.1 Data flows under test

```
PORTAL (employee)                         HR ADMIN
─────────────────                         ────────
Submit PTO request      ───────────────►  Pending list, calendar
                        ◄───────────────  Approve / Deny / change / Remove
Clock in / out          ───────────────►  Attendance, hours
Running Late / Out      ───────────────►  Self-reported list
Emergency contacts      ◄──────────────►  🚨 Emergency tab (both can edit)
About Me / DOB          ───────────────►  Info tab, calendars
Profile shown           ◄───────────────  Title, department, pay, manager
Message HR              ◄──────────────►  Inbox + reply
Incident report         ───────────────►  Incident list → status update ► back
Directory contact       ───────────────►  Import from Directory
My Team                 ◄───────────────  Manager flag + direct reports
Onboarding status       ◄───────────────  Onboarding tasks / start date
```

### 18.2 Integrated scenarios (end-to-end stories)

Each scenario runs with **Portal on the left, Admin on the right**, and checks both sides after every hand-off.

| ID | Pri | Story | Steps | Checks |
|---|---|---|---|---|
| **E2E-01** | P1 | **Time-off lifecycle** | Test Tester requests 3 vacation days → Admin approves → Portal sees Approved → Admin changes to Denied → Portal sees Denied → Test Tester re-requests → Admin approves → Test Tester hides it → Admin removes it | Status on both sides at each step; calendar days added, removed, never duplicated; hidden request still in Admin until removed; nothing left after cleanup |
| **E2E-02** | P1 | **A workday** | Clock in → Running Late → clock out → Admin Attendance → Portal Portfolio | Times match on both sides; hours correct; Days Clocked and in/out counts update |
| **E2E-03** | P1 | **New hire to first login** | Admin recruits Jordan (position → candidate → interview with answers → offer → Wizard Hire) → Admin sets PIN → Jordan signs into Portal | Jordan's Portfolio shows title, department, start date from Admin; onboarding tasks exist; Getting Started pop-up appears |
| **E2E-04** | P1 | **Safety info** | Test Tester adds emergency contacts → Admin sees them → Admin corrects phone → Portal shows HR's version | Banner states and "last updated by" on both sides |
| **E2E-05** | P1 | **HR conversation** | Test Tester messages HR → Admin replies → Portal shows reply | Both messages both sides, in order |
| **E2E-06** | P1 | **Incident** | Test Tester files incident (Maria as witness) → Admin reviews → status changes → Portal shows new status | Status and details match |
| **E2E-07** | P2 | **Manager view** | Admin makes Kevin a manager of Maria + Test Tester → Kevin signs in → My Team → Maria requests PTO → Admin approves | Kevin sees both reports and their approved time off |
| **E2E-08** | P2 | **Profile sync** | Admin changes Test Tester's title/department → Portal Portfolio; Test Tester updates DOB → Admin Info + calendars | Both directions reflect within one reload |
| **E2E-09** | P2 | **Leaving the company** | Admin offboards Sam (checklist, final pay) → terminates → Saved File → print | Sam can no longer sign into Portal (or sees terminated state); Saved File complete; nothing deleted until cleanup |
| **E2E-10** | P2 | **Directory to employee** | Test Tester adds `ZZTEST Contact Morgan Lee` in Portal Directory → Admin Import from Directory → Morgan created | Morgan listed as employee; no duplicates of real people |

Existing X-* tests (Section 8) become the individual checkpoints inside these stories.

---

## 19. Schedule, Entry/Exit Criteria & Risks

### 19.1 When each level runs (always started by Jamie)

| Moment | Command | Time (approx.) |
|---|---|---|
| Quick check after a small change | `run_tests_hr_e2e.py --fast --priority P1` | 3–5 min |
| Before pushing to GitHub / after a feature | `run_tests_hr_e2e.py --fast` | 15–25 min |
| Watching / demoing / debugging | `run_tests_hr_e2e.py --test "<ID>"` (visible, slow) | 1–5 min per test |
| Leftover cleanup only | `run_tests_hr_e2e.py --cleanup-only` | < 1 min |

### 19.2 Entry criteria (before a run)
- Latest code deployed with `deploy_hr.py`; AI-Prowler restarted if `ai_prowler_mcp.py` changed.
- Pre-flight passes: apps load, admin token works, zero leftovers.
- No one doing real HR work in the apps during the run.

### 19.3 Exit criteria (a run "passes")
- **All P1 tests pass.**
- **Cleanup VERIFIED** — zero `ZZTEST` records, zero Test Tester activity, profile = baseline.
- No new console errors or failed API calls (known issues in 19.5 are listed, not ignored).
- Any P2/P3 failure has a note in `known_issues.md` or a fix planned.

### 19.4 Risks & how we handle them

| Risk | Mitigation |
|---|---|
| Tests change real data | Only Test Tester + ZZTEST personas; real employees read-only; cleanup verified; emergency snapshot |
| Cleanup misses something | Per-test verify + final sweep + pre-flight sweep next run; `--cleanup-only` |
| Flaky timing (data loads slowly) | Wait for real signals (element visible, API answered), never fixed sleeps longer than 1 s; one automatic re-check for known-slow pages |
| Pop-ups/overlays block clicks | Shared `closeGettingStarted()` and dialog handlers (confirm boxes auto-accepted only where the test expects them) |
| Service worker serves old files | `serviceWorkers: 'block'` in config |
| Web filter blocks scripts (403) | Runner identifies as a browser |
| Someone uses the apps during a run | Run when idle; tests only touch their own data |
| Emails pile up in Jamie's inbox | Gmail filter on `+hrtest` / `+zz-` → label "HR Tests", skip inbox |

### 19.5 Known issues found by tests

| Found | Issue | Status |
|---|---|---|
| Sept 25 (manual console) · **confirmed by PRT-LAY-01 run 2** | `GET /hr-api/employees/birthdays` returns **403** for employees → birthdays may not show on Portal calendars. **Cause:** the `GET /employees/<id>` route matched `/employees/birthdays` first and treated "birthdays" as an employee ID | **Fixed & verified** (PRT-LAY-01 run 3, Sept 25) — deployed; no 403 |
| Sept 25 · **PRT-LAY-01 run 2** | Portal HTML contains **two** `#page-pto` sections (live lines 1527 and 3093). Browser shows the first; the duplicate can confuse edits and tests | **Fixed & verified** (PRT-LAY-01 run 3, Sept 25) — duplicate removed and deployed |
| Sept 25 · **code review while building X-MSG-01** | **Privacy — incident reports readable without signing in.** `POST /hr-api/messages/my-reports` sits *before* the server's sign-in check and returns every incident report whose sender name partly matches the name sent (matching works both ways, so even one letter like `"a"` matches most names). Anyone who can reach the site could read other people's incident reports | **Fixed & verified Sept 28** (PRT-SEC-02 after deploy: 401 without sign-in; signed-in employees get only their own reports). Was CONFIRMED earlier the same day (answered 200 without sign-in) |
| Sept 25 · code review | **Messages can be sent without signing in, as anyone.** `POST /hr-api/messages` is also before the sign-in check and trusts the `employee_id` and `sender_name` the page sends, so a message could be posted to HR pretending to be any employee. `GET /messages/outbox` (HR broadcasts) is also readable without signing in | **CONFIRMED Sept 28 by PRT-SEC-03** (probe message accepted under a made-up name; broadcasts readable). **Fixed in dev:** sign-in required for both; employee sender name/ID/email now taken from the sign-in; **anonymous feedback stays anonymous** (no name/email/ID stored — new test **PRT-SEC-04**). Portal now attaches the employee session to every HR request automatically (7 features were calling without it). **Deployed & verified Sept 28** (PRT-SEC-03/04 pass; X-MSG-01 still passes) |
| Sept 25 · code review | **Second "Send Message to HR" form may lose HR's replies.** | **Not a bug (Sept 28).** The function `sendMsgToHR` is unused leftover code — the form it expects (`#msg-subject`) doesn't exist and nothing calls it. The only send form is on the Messages page, proven by X-MSG-01. PRT-MSG-02 closed. Leftover function can be removed during cleanup |
| Sept 25 · code review | `/messages/mine` also matches messages by **exact sender name** as a fallback, so two employees with the same full name could see each other's HR replies | Low — note for later; fix alongside the item above |
| Sept 28 · **ADM-LAY-01** | **HR Admin 📚 Training page crashed every time it opened** — old `loadTraining()` still ran after the tab was rebuilt as "Training Portfolios" and wrote to a removed `#training-list` box | **Fixed & deployed Sept 28** (old loader skips when its box isn't there) |
| Sept 28 · code review while building E2E-01 | **Portal PTO balances are hard-coded** — the PTO / Time Off page always shows "8.5d PTO · 3d sick · 4d holidays" for every employee, not their real balance or what they've used | **Open — feature gap, needs Jamie's decision** (how PTO accrues / sick-day policy). PRT-PTO-01 currently only proves the boxes show numbers |
| Sept 28 · **E2E-01** | **Record IDs get reused after deletions.** The first time-off request after all were deleted got `PTOREQ-00001` — numbering restarts from the highest ID still present, so a deleted request's ID can be given to a new one. An old email, note, or log mentioning that ID would then point at a different request | **Low — open.** Fix later: keep a running counter per record type so IDs are never reused |
| Sept 28 · **E2E-06** | **Employees never saw HR's progress on their incident reports.** HR Admin sets Open / Under Review / Resolved (saved on the server), but the Portal's "My Submitted Reports" badge only ever showed "Pending" or "↩ HR Replied" | **Fixed, deployed & verified Sept 28** (E2E-06 passes: Portal shows Under Review, then Resolved) — badge now shows HR's real status plus "↩ HR Replied"; detail box shows "HR status" |
| Sept 28 · **watch-mode full run** | **Getting Started pop-up reopened right after ✕** — startup runs twice on a page reload and each run scheduled its own pop-up timer | **Fixed, deployed & verified Sept 28** — scheduled once per page load; guarded by REG-17 |
| Sept 28 · code review while building ADM-REC | **Recruiting edits can overwrite each other.** HR Admin sends the *whole* recruiting bundle (positions, candidates, interviews, offers) on every save, and the server replaces it. If two people (or two devices) edit recruiting at the same time, whoever saves last silently erases the other's changes | **Fixed, deployed & verified Sept 28** (approved by Jamie) — version number; out-of-date saves refused (409); guarded by ADM-REC-13 |
| Sept 28 · code review while building ADM-TOF | **Bug #12 — HR Admin "+ Add Event to Calendar" → Time off crashed.** It called `saveTimeOffRequests()`, which doesn't exist anywhere, so nothing was saved and no message appeared | **Fixed in dev** — server now lets HR create a time-off request on an employee's behalf (`POST /pto/request` with `employee_id`, admin only); the button creates a real server request (shows under Pending and in the Portal). **Deploy + restart needed** |
| Sept 28 · code review while building ADM-TOF | **HR Admin calendar events (meetings, reminders, holidays you add) are saved only in that browser** (`localStorage hr_biz_reminders`) — not on the server, so they don't show on other computers/phones and vanish if the browser's data is cleared | **Open — proposed fix:** store them on the server like time off. Needs Jamie's OK |
| Sept 28 · code review while building ADM-TOF | **HR Admin PTO Balances likely always show 0 days used** — the Balances tab counts approved requests of type `vacation` / `sick` / `personal`, but the Portal saves types like `PTO (Vacation)`, `Sick Day`, `Personal Day`, so nothing matches | **Open — to confirm with a test (ADM-TOF-09), then fix** |

### 19.6 Test-writing lessons learned (Sept 25)

| Lesson | Rule for all future tests |
|---|---|
| New employees get a 🚀 **Getting Started** pop-up that blocks clicks | Sign-in helper closes it with ✕ and verifies it's gone (`closeGettingStarted`) |
| Sidebar items can contain **hidden badges** (e.g. Messages "!"), so matching by visible text fails | Find sidebar items by `data-page` (Portal) / `data-tab` (Admin), never by label text |
| HR Admin's sidebar **slides in from off-screen** — it counts as "visible" while parked off-screen | `openAdminPage` checks the item is actually **on screen** and opens ☰ Menu if not |
| Playwright already records traces for every window (`trace: 'on'`) | Never start tracing manually in a test |
| The public address refuses "Python"/"script" requests (403) | Runner and API helper identify as a normal browser |
| Typing long text key-by-key in watch mode is very slow (each key waits `slowMo`) | Type short fields; **paste** (`fill`) long text like message bodies — still a real input event |
| `confirm()` boxes are auto-**cancelled** by Playwright unless handled | Register `page.once('dialog', d => d.accept())` right before clicking a button that asks "Are you sure?" |
| (Sept 28) Recruiting hides the normal page area and draws into its own containers | Layout test measures `#rec-scroll-body` for Recruiting |
| (Sept 28) Long HR Admin menu — bottom items (Incident Reports) are below the fold | `openAdminPage` scrolls the menu to the item before clicking |
| (Sept 28) An unlabeled console error can't be traced to a page | `watchForProblems(...).at('<page name>')` tags every error with the current page + code location |
| (Sept 28) **Network blip:** the Portal once showed "Could not reach HR server" on a correct sign-in (tunnel hiccup) | Sign-in helper clicks **Sign in** again once, like a person, and logs `⚠ NETWORK BLIP` so blips stay visible |

---
---

# PART III — IMPLEMENTATION PLAN

## 20. Phases

| Phase | Deliverables | Definition of done |
|---|---|---|
| **0 — Harness** ✅ | `run_tests_hr_e2e.py` (pre-flight, snapshot, token, Test Tester + PIN, install, run, log, summary), `playwright.config.js`, `helpers/common.js`, README, `.gitignore`, **PRT-LAY-01** | Runs from Command Prompt and AI-Prowler; log + report + video + trace produced ✅ |
| **1 — Test infrastructure** | `helpers/api.js` (Node API client, admin + employee), `helpers/admin.js` (Admin sign-in), `helpers/data.js` + `fixtures/test_data.js` (Section 15), `helpers/cleanup.js` (track → delete → verify), page objects for each app, `fixtures/` PDFs + photo, **backend test API** (21.1), `--priority` / `--cleanup-only` options, `known_issues.md` | A sample test seeds a persona + PTO, cleans up, and logs `CLEANUP VERIFIED`; `--cleanup-only` removes planted leftovers |
| **2 — Smoke, auth, layout (both apps)** | SMK-01…03, AUTH-01…06, ADM-LAY-01/02, PRT-LAY-02/03, REG-01…05, REG-16, CLN-01/02 | All pass on current build (or failures logged as known issues) |
| **3 — Portal functional P1** | PRT-POR-01/02/05, PRT-ABT-01…03, PRT-EMC-01…03, PRT-TC-01/02/04, PRT-SCH-01…03, PRT-TSK-01…03, PRT-PTO-01…03, PRT-MSG-01, PRT-INC-01, PRT-DEP-02, PRT-SEC-01 | All P1 Portal tests pass; each verifies its own cleanup |
| **4 — Admin functional P1** | ADM-EMP-01/02/03/05/07, ADM-REC-04…06, ADM-TOF-01…06, ADM-OFF-03/04, ADM-ATT-01 | All P1 Admin tests pass; cleanup verified |
| **5 — Integrated P1** | E2E-01…06 (with X-* checkpoints) | All six stories pass side by side; zero leftovers |
| **6 — P2 / P3 + phone** | Remaining Section 6–8, 16–18 tests; 390×844 layout runs | Full suite ≤ 25 min in `--fast`; failures triaged |
| **7 — Hardening & GitHub** | Flake review (run full suite 3× clean), timing tidy-up, README final, spec status table updated, push to GitHub | 3 clean consecutive runs; repo contains no secrets/logs |

## 21. Backend Test Support (`ai_prowler_mcp.py`)

### 21.1 Routes (admin-only, test mode only)
All require the admin token **and** header `X-HR-Test-Mode: 1`. They refuse any record that doesn't belong to Test Tester or a `ZZTEST` persona, and write each action to the audit log.

| Route | Purpose |
|---|---|
| `POST /hr-api/test/seed` | Create history the UI can't back-date: past clock-ins/outs, past attendance, past-dated PTO. Body: `{ "employee_id", "kind": "time_entries" \| "attendance" \| "pto", "records": [...] }` — IDs returned for cleanup |
| `POST /hr-api/test/cleanup` | Delete by `{ "ids": [...] }` (per test) or `{ "sweep": true }` (all ZZTEST + Test Tester activity). Returns counts per area |
| `GET /hr-api/test/leftovers` | List anything still matching the test rules — must be empty |

### 21.2 Data areas the cleanup covers
Employees (ZZTEST personas only), `pto_requests`, `attendance`, `time_entries`, `schedule_change_requests`, messages, incident reports, directory contacts, recruiting bundle (positions, candidates, interviews, offers), calendar events, documents (+ files in the persona's doc folder), onboarding tasks, audit entries are **kept** (history).

### 21.3 Safety tests for the test API
| ID | Check |
|---|---|
| TAPI-01 | Without `X-HR-Test-Mode` header → 403 |
| TAPI-02 | With employee session instead of admin token → 403 |
| TAPI-03 | Cleanup request containing a real employee's ID → refused, nothing deleted |
| TAPI-04 | Sweep leaves all 6 real employees and their records untouched (compare counts before/after) |

## 22. File Layout (target)

```
tests\hr_e2e\
├── run_tests_hr_e2e.py
├── playwright.config.js · package.json · README.md · TEST_SPEC_HR_E2E.md · known_issues.md · .gitignore
├── test_config.example.json
├── fixtures\
│   ├── test_data.js              ← Section 15 personas & data (dates from today)
│   ├── ZZTEST_offer_letter.pdf · ZZTEST_w4_sample.pdf · test_photo.png
├── helpers\
│   ├── common.js                 ← settings, click dot, problem watcher, text checks ✅
│   ├── api.js                    ← HR API client (admin + employee sessions)
│   ├── admin.js                  ← HR Admin sign-in + navigation
│   ├── data.js                   ← factories that tag records ZZTEST-<run>-<test>
│   └── cleanup.js                ← track → delete → verify, CLEANUP VERIFIED/FAILED
├── pages\                        ← page objects: one file per screen, all selectors live here
│   ├── portal\  login.js · sidebar.js · portfolio.js · about.js · emergency.js · timeclock.js
│   │            schedule.js · pto.js · tasks.js · directory.js · messages.js · incidents.js …
│   └── admin\   login.js · menu.js · employees.js · employeeSheet.js · recruiting.js
│                interviewSheet.js · timeoff.js · offboarding.js · terminations.js …
└── specs\
    ├── 01_smoke.spec.js · 02_auth.spec.js
    ├── portal\   01_portal_layout.spec.js ✅ (moves here) · profile · timeclock · pto · tasks · company · money · hr
    ├── admin\    layout · employees · recruiting · timeoff · attendance · documents · offboarding
    ├── cross\    e2e_01_timeoff … e2e_10_directory
    ├── regression\ reg.spec.js
    └── 99_cleanup.spec.js
```

**Page objects:** every selector (`#login-email`, `.nav-item[data-page=…]`, etc.) lives in one page file, so when the app's HTML changes, only one file needs updating — not every test.

## 23. Status

| Item | Status |
|---|---|
| Spec v1.2 (plan + implementation plan) | ✅ Written |
| Phase 0 harness + PRT-LAY-01 | ✅ Built · run 1 blocked by Getting Started pop-up → fixed · run 2 found 2 real app issues (19.5) · **run 3 (Sept 25, 14:15) after fixes deployed: PASS — 24 pages, 0 layout problems, 0 console errors, 63 s** |
| Test Tester account | ✅ Created (EMP-00008), PIN set per run |
| **X-MSG-01** messaging between both apps | ✅ **PASS** (Sept 25, 15:31) — send → server → Admin NEW → open → reply → server → Portal reply → Admin 🗑 → gone everywhere; 0 console errors; **CLEANUP VERIFIED** (1 message deleted, 0 left); 28 s. Earlier runs failed only on test code (double trace start, hidden "!" badge on Messages, off-screen Admin sidebar) — all fixed, see §19.6 |
| `helpers/admin.js`, `helpers/api.js` (Cleanup tracker) | ✅ Built — first pieces of Phase 1 |
| Spec review v1.3 | ✅ Done — corrections applied; 3 new messaging/security findings in §19.5 |
| **Next up** | PRT-SEC-02 / PRT-SEC-03 / PRT-MSG-02 (confirm the §19.5 findings) → fix → re-test; then rest of Phase 1 (test cleanup API, personas) |
| Phase 1 infrastructure + backend test API | ⏳ In progress (helpers done; backend test API + personas next) |
| Phases 2–7 | Planned |

### 23.1 Implementation tracker (updated as tests are built)

**Legend:** ✅ passing · ❌ failing (real bug, see §19.5) · 🔧 built, waiting on a deploy · ⏳ not built yet

| Batch | Test IDs | File | Status (Sept 28) |
|---|---|---|---|
| 0 | PRT-LAY-01 (+AUTH-03, REG-01/02/03/05/16) | `specs/01_portal_layout.spec.js` | ✅ 24 pages, 0 problems |
| 0 | X-MSG-01 | `specs/30_cross_messaging.spec.js` | ✅ cleanup verified |
| 1 | SMK-01, SMK-02, SMK-03 | `specs/02_smoke_auth.spec.js` | ✅ |
| 1 | AUTH-01, AUTH-02, AUTH-04 | `specs/02_smoke_auth.spec.js` | ✅ |
| 1 | AUTH-05, AUTH-06 | `specs/02_smoke_auth.spec.js` | ✅ |
| 1 | ADM-LAY-01, ADM-LAY-02 | `specs/20_admin_layout.spec.js` | ✅ **verified Sept 28 after the Training fix: 21 pages, 0 problems, 0 console errors, all buttons styled** |
| 1 | PRT-SEC-01 | `specs/40_security.spec.js` | ✅ employees refused admin data |
| 1 | PRT-SEC-02, PRT-SEC-03 | `specs/40_security.spec.js` | ✅ **fixed, deployed & verified Sept 28** (all 401 without sign-in) |
| 1 | **PRT-SEC-04** *(new — gap found)* | `specs/40_security.spec.js` | ✅ sender identity from sign-in; anonymous feedback stores no identity |
| 1 | PRT-MSG-02 | — | Closed — not a bug (unused leftover code) |
| 2 | **X-EMC-01** (+E2E-04, PRT-EMC-01/02) | `specs/31_cross_emergency.spec.js` | ✅ Portal save → green banner → server (6 fields + time stamp) → HR Admin 🚨 tab; baseline restored & verified |
| 2 | **E2E-01** time-off lifecycle (X-PTO-01…05, PRT-PTO-02/03/05, PRT-SCH-03, ADM-TOF-02…06, REG-15) | `specs/32_cross_timeoff.spec.js` | ✅ first run: invalid dates blocked → submit → approve (3 days) → deny (0 days) → re-approve (3, no duplicates) → employee hides (HR keeps it) → HR removes (stays gone); cleanup verified |
| 2 | **E2E-06** incident report round trip (X-INC-01, PRT-INC-01) | `specs/33_cross_incident.spec.js` | ✅ **found + fixed a real bug (Portal never showed HR's status); deployed & verified Sept 28** — file → server (tied to sign-in) → listed → Under Review → Resolved (Portal shows each) → HR deletes; cleanup verified |
| 2 | **PRT-ABT-01…05, 07** About Me | `specs/10_portal_about.spec.js` | ✅ cards + Edit, locked login email, Cancel discards, Preferred Name saves + persists after reload, Fun Stuff saves; profile restored & verified |
| 2 | **Backend test support** `/test/cleanup` + `/test/leftovers` (§21) | `ai_prowler_mcp.py` | ✅ deployed Sept 28 — admin-only, can only match the `+hrtest@` QA account; covers clock entries, attendance, shift swaps |
| 2 | **TAPI-01/02/04** *(safety of the above)* | `specs/40_security.spec.js` | ✅ signed-out 401, employee 403, real employees' attendance unchanged by a cleanup run |
| 2 | **E2E-02** a workday (X-TC-01/02, PRT-TC-01/02, PRT-POR-05) | `specs/34_cross_timeclock.spec.js` | ✅ clock in → server (1 open shift) → clock out → Portfolio "1 in · 1 out" matches server → HR Admin Clock Log lists it; cleanup verified (0 left) |
| 2 | **PRT-TSK-01…07, 09** Tasks / Projects | `specs/11_portal_tasks.spec.js` | ✅ first run: boxes load → add High task due today (count +1) → complete + Oops bar undo → Done-tab Oops → Today/All Open filters → drag to Due Today → drag to Completed → survives reload |
| 2 | **REG-17** *(new — found by the watch-mode full run)* Getting Started pop-up reopened after ✕ | `specs/03_regression.spec.js` | ✅ **real bug (#9) fixed, deployed & verified Sept 28 in watch mode** — closed pop-up stays closed 3 s; "Don't show again" sticks after reload. AUTH-05, PRT-ABT, PRT-TSK, E2E-01 now pass at human speed too |
| 2 | **ADM-EMP-01/02/03/05/12** (+REG-11) HR Admin employees | `specs/21_admin_employees.spec.js` | ✅ first run: list shows all 7; 5 filter chips correct; + Add Employee → helper with 33 onboarding tasks; 8 record tabs open, 0 errors; delete removes the helper **and** its tasks (no orphans); cleanup verified |
| 2 | **ADM-REC-04…08** recruiting interview sheet (+ **REG-19**) | `specs/22_admin_recruiting.spec.js` | ✅ **bug #10 fixed, deployed & verified Sept 28 (watch mode)** — Interviews tab stays selected after loading; 15 questions / 4 groups; answers + stars + own question + ★★★★ + 👍 Hire saved to server (16 Qs); card shows "3/16 answered … Hire"; persists after reload; real recruiting data untouched |
| 2 | **ADM-REC-13** *(new — Jamie approved the fix Sept 28)* recruiting edits can't overwrite each other | `specs/22_admin_recruiting.spec.js` + server + HR Admin | ✅ **deployed & verified Sept 28** — person A saves (v0 → v1); person B's out-of-date save refused (409); A's change intact; cleanup verified |
| 2 | **REG-18** *(new — Jamie approved Sept 28)* **Quiet retry on network hiccups** | `specs/03_regression.spec.js` + Portal | ✅ **deployed & verified Sept 28 (watch mode)** — simulated blip: profile load retried quietly → Portfolio filled; message send NOT retried (1 try, no duplicates); cleanup verified |
| 2 | **ADM-OFF-01/03/04/05** offboard a ZZTEST helper → terminate → records → Saved File → Print | `specs/23_admin_offboarding.spec.js` | ✅ **bug #11 fixed, deployed & verified Sept 28 (watch mode)** — termination pop-up now on top of the record; terminated (type, last day, notes saved; record + emergency contact kept); listed on Offboarding + Termination Records; Saved File shows all 6 sections; Print opens a clean copy; helper deleted, cleanup verified |
| 2 | **ADM-TOF-07** calendar events on the server *(improvement approved Sept 28)* | `specs/24_admin_timeoff_tools.spec.js` | ✅ event added in one browser shows in a second, separate browser; existing browser-only events move up automatically; cleanup verified |
| 2 | **ADM-TOF-10** bug #12: + Add Event → Time off | `specs/24_admin_timeoff_tools.spec.js` | ✅ **fixed, deployed & verified** — creates a real Pending request (used to crash) |
| 2 | **ADM-TOF-09 / ADM-TOF-08 / REG-20** Balances + sub-tabs + day counter | `specs/24_admin_timeoff_tools.spec.js` | ✅ **bugs #13 + #14 fixed, deployed & verified Sept 29 (watch mode)** — Balances shows 3/10 used; day counter Mon–Wed 3, Fri–Mon 2, Tue 1; all 6 sub-tabs open; pre-sweeps leftovers |
| 2 | **ADM-TOF-11** accepted Running Late / Out Today reports on the server *(improvement approved Sept 29)* | `specs/25_admin_selfreports.spec.js` + server + HR Admin | ✅ **deployed & verified Sept 29 (watch mode)** — Portal Running Late → server report (not accepted) → HR Accept → server marked accepted → a second, separate browser sees it accepted; cleanup verified |
| — | **🎉 FULL REGRESSION — Sept 29, 19:44** | all specs | ✅ **31 passed, 0 failed, 17 cleanups verified, 284 s** (fast mode). First clean full run with every fix live |
| 2 | **MOB-LAY-01** Portal on phones (iPhone 14 + Pixel 7) | `specs/50_phone_view.spec.js` | ✅ **bugs #15, #16, #17 fixed, deployed & verified Sept 30** — top bar fits (412 of 412 px), ☰ 44×44, all 24 pages open through ☰, 0 problems, 0 errors. Small tap targets listed as warnings |
| 2 | **ADM-PIN-01** employee Portal sign-in with their own PIN | `specs/26_admin_portal_pin.spec.js` | ✅ **bug #18 (reported by Jamie) fixed, deployed & verified Sept 30** — HR sets PIN in Direct Reports → 🔑 Portal Sign-in; employee signs in with email + PIN; shared bearer token refused (401); Test Tester PIN restored |
| 2 | **MOB-LAY-02** HR Admin on iPhone 14 | `specs/51_phone_admin.spec.js` | ✅ first run (Sept 30): top bar fits (390 of 390 px); 21 pages open through ☰; no sideways scroll, nothing blank, 0 errors. **Warnings:** small tap targets on 17 pages — Jamie approved enlarging the too-small ones (compact, 36 px minimum on phones) |
| — | **🎉 FULL REGRESSION — Sept 30, 05:05** | all specs | ✅ **36 passed, 0 failed, 19 cleanups verified, 351 s** (fast mode) — first full run including phones (iPhone 14, Pixel 7, HR Admin phone) and Portal PIN sign-in, with all 18 bug fixes live |
| 2 | **Phone tap targets** *(improvement approved Sept 30 — compact, not oversized)* | Portal + HR Admin CSS; `specs/50_phone_view.spec.js`, `51_phone_admin.spec.js` | ✅ **deployed & verified Sept 30 (watch mode)** — phones only: buttons ≥ 36×36, HR Admin filter chips ≥ 36 px tall, Tasks checkboxes 28×28. Pages with small targets: **HR Admin 17 → 0, Portal 17 → 3** (remaining = intentional 28 px checkboxes + full-width text links). Tests now **fail** any button under 28 px |
| 2 | **PRT-DIR-01…03** Portal Directory: search, add, edit, delete | `specs/12_portal_directory.spec.js` | ✅ Sept 30 — lists all 6 real contacts; + Add → saved (DIR-00007); search filters; ✎ edit saved on screen + server; 🗑 remove gone everywhere; all 6 real contacts untouched; 0 errors; cleanup verified |
| 3 | **PRT-DEP-01/02** Deposits bank-details privacy | `specs/13_portal_deposits.spec.js` | ✅ **bug #19 fixed, deployed & verified Sept 30** — full account/routing numbers never sent over the network, never in browser storage, never on screen (shows •••• 6789); server stores only last 4; a tampered request with a full number is cut to "6789"; real data checked — nothing had been exposed |
| 3 | **CLN-01 / CLN-02** pre-flight + final sweep (first and last test of every full run) | `specs/00_cleanup_preflight.spec.js`, `specs/99_cleanup_final.spec.js`, `helpers/sweep.js` | ✅ Sept 30 — searches 7 areas (employees, messages + incident reports, time off, directory, calendar events, recruiting, clock-ins/attendance/shift swaps); 0 test items anywhere; final sweep names any test whose own cleanup missed something |
| 3 | **REG-21** "today" is the local date in both apps | `specs/03_regression.spec.js` | ✅ **bug #20 fixed, deployed & verified Sept 30, 9 PM** — 44 UTC-"today" spots (3 Portal, 41 HR Admin) switched to a local-date helper; at 8 PM Arizona both apps say Sept 30 (UTC would say Oct 1); test fails if any UTC "today" creeps back |
| 3 | **PRT-CCAL-01** Company Calendar: birthday + time off on the right day | `specs/14_portal_calendar.spec.js` | ✅ Sept 30 — 🎂 Oct 16 only (not 15/17); day off Oct 21 only (not 20/22); birthday restored, time off removed |
| — | **🎉 FULL REGRESSION — Sept 30, 21:14** | all specs | ✅ **42 passed, 0 failed, 24 cleanups verified, 373 s** (fast mode) — all 20 bug fixes live; bookended by CLN-01 (no leftovers before) and CLN-02 ("every test cleaned up after itself", 0 test items in 7 areas) |
| 3 | **ADM-DOC-01** HR uploads a document from the employee record; it downloads back intact | `specs/27_admin_documents.spec.js` | ✅ **bugs #21, #22, #23 fixed, deployed & verified Oct 1 (watch mode)** — employee pre-selected; file shows in the record right away; record now has a ⬇ Download button; test PDF with binary marker + `\r\n` ending downloads back byte-for-byte (423 bytes); cleanup verified. Sweeps now also check documents (8 areas) |
| 3 | **PRT-LINK-01 / PRT-TRN-02** no broken document, training, or handbook links; training viewer opens + closes | `specs/15_portal_links.spec.js` | ✅ Oct 1 — 19 links found across the whole Portal (9 trainings, handbook, documents), every one opens; viewer shows the training and closes with ✕; 0 errors |
| — | **🎉 FULL REGRESSION — Oct 1, 00:06** | all specs | ✅ **44 passed, 0 failed, 25 cleanups verified, 383 s** (fast mode) — all 23 bug fixes live; bookended by CLN-01 / CLN-02 ("every test cleaned up after itself", 0 test items in 8 areas) |
| — | **Payroll / Write-Ups** | covered by PRT-LAY-01 + MOB-LAY-01 every run | Page opens, not blank, no broken text, 0 errors on desktop + phones. Payroll figures are demo data — deeper Payroll test to be added **when real payroll is connected** |
| 4 | **E2E-03** new hire → first login (gap #24) | `specs/35_cross_newhire.spec.js` | ✅ **deployed & verified Oct 1 (watch mode)** — ✓ accept → pre-filled "Create employee?" → record opens with their own AI-Prowler token → server: EMP + 32 onboarding tasks, linked to offer + candidate (Hired) → Offers shows "✓ Employee", no duplicate button → new hire signs into the Portal and sees their name + title; cleanup verified |
| 4 | **ADM-TOK-01** each employee's own AI-Prowler token (Option B) | `specs/26_admin_portal_pin.spec.js` | ✅ **deployed & verified Oct 1** — HR makes a token (shown once, 📋 Copy) → Portal "AI-Prowler Access Token" sign-in works → a newer token shuts off the old one (401) → shared HR Admin token refused (401) → optional PIN works |
| — | *Cleanup item (low):* HR Admin has duplicate element ids in Recruiting (e.g. two `#rec-view-offers`: the live list inside `#rec-scroll-body` + an empty leftover in `#tab-recruiting`) | — | Harmless today (the app writes into the first, visible one), but duplicate ids can confuse future edits — remove the empty leftovers when convenient |
| 4 | **X-SWP-01** coworker-to-coworker shift swaps *(new feature, designed by Jamie Oct 1)* | `specs/36_cross_shiftswap.spec.js` + server `/swaps…` + Portal Schedule | ✅ **deployed & verified Oct 1 (watch mode, first run)** — click a coworker's name → short message (≤300 chars) → coworker gets a Schedule badge + request in 🔁 Shift Swaps → ✓ Approve / ✗ Deny (final, no HR step); **when approved, HR Admin → 💬 Messages gets a NEW "🔁 Shift swap approved: A ↔ B" notice (server-created; denied swaps don't notify)**; test accounts never see or are seen by real staff; sender can't answer own (403); answered swap can't be re-answered (409); cleanup verified |
| 4 | **E2E-07** manager view (+ bug #25 guard) | `specs/37_cross_manager.spec.js` | ✅ **bug #25 fixed, deployed & verified Oct 1** — manager signs in → My Team: Team Members 1 · Out / PTO 1 · Active Today 0 · report shows "🏖 Out today"; a non-manager doesn't see My Team; cleanup verified |
| — | **🎉 FINAL FULL REGRESSION — Oct 1, 17:56** | all specs | ✅ **46 passed, 0 failed, 27 cleanups verified, 437 s** (fast mode) — all 23 bug fixes + hiring flow + Option B tokens + shift swaps (with HR notice) live; bookended by CLN-01 / CLN-02 ("every test cleaned up after itself", 0 test items in any area) |

**Product decision (Jamie, Sept 30) — Directory permissions:** any signed-in employee can add, edit, and delete any Directory contact. This is **intentional**: the Directory is a shared, coworker-to-coworker contact list inside one small business. Not a bug — do not "fix". Revisit later as a polish item if customers ask (e.g. employees edit only their own entries; HR edits all).

**Product context (Jamie, Sept 30):** AI-Prowler HR is a product sold to **small business owners**, and AI-Prowler uses it internally too — so everything must work properly for customers as well as for us.

**Hiring flow — built Oct 1 (gap #24, approved by Jamie):** accepting an offer opens **"Create an employee record?"** pre-filled from recruiting (name, email, phone, title, department, start date) → creates the employee with onboarding tasks, links it to the offer + candidate (no duplicates), and opens their record on 🔑 Portal Sign-in showing **their new AI-Prowler token** to copy. Accepted offers without an employee keep a **👤 Create employee** button for later. The Wizard Hire now says honestly that it created an **offer**, not an employee. Guarded by **E2E-03**.

**Hiring roadmap (Jamie, Oct 1 — later):**
1. **Offer letter** — generate it from the offer and **email it** to the candidate.
2. Candidate **replies** to accept → HR sets their **first start date**.
3. **On the start date** they're hired in and get **their own employee app access** with a **work email** and **their own AI-Prowler bearer token**.
4. **Admin walkthrough** — HR is guided step by step through getting the new hire signed into the employee app.

**Product decision (Jamie, Oct 1) — Employee sign-in = Option B:** each employee signs into the Portal with their email + **their own AI-Prowler bearer token**, generated by AI-Prowler (not one shared token — a shared token would let anyone sign in as any coworker, and would also open HR Admin). Tokens are stored only as a hash, so HR sees a token **once** — when the employee is created (hiring flow shows it immediately) or when HR clicks **🔑 Make a new AI-Prowler token** in the employee's record (the old one stops working). A short PIN remains available as an optional alternative. Guarded by **ADM-TOK-01** and **E2E-03**.

**Totals (Oct 1, 7:12 PM — round complete):** 52 tests built, all passing · **final full regression 46 of 46 groups, 27 cleanups verified, 0 test data left in any area** (+ E2E-07 passed after) · **25 bugs found, all fixed & verified live** (3 security/privacy: incident-report exposure, message impersonation, full bank numbers storable; plus document integrity: uploads trimmed) · **5 improvements live** (quiet retry, recruiting overwrite protection, calendar events on server, accepted self-reports on server, phone tap targets) · every bug is written up in `BUG_WALKTHROUGH.md`.

---

## 24. Phone View Testing (planned)

The same tests can run on **emulated phones** — real phone screen size, touch taps, phone browser identity. iPhone runs use Safari's engine (WebKit); Android runs use Chrome.

| Item | Plan |
|---|---|
| Devices | iPhone 14 (390×844, WebKit) · Pixel 7 (Chrome) · desktop stays the default |
| How to run | New runner option `--device iphone` / `android` / `desktop` / `all` |
| First test | **MOB-LAY-01** — Portal layout on a phone: open every page through the ☰ menu; no sideways scrolling; nothing cut off; tap targets ≥ 44 px; pop-ups fit and close |
| Then | **MOB-LAY-02** HR Admin on a phone · **MOB-MSG-01** X-MSG-01 with the Portal on a phone · portrait + landscape |
| PWA basics | Manifest and icons load; page is "Add to Home Screen" ready |
| Can't test (emulation limits) | On-screen keyboard covering fields, notch/home-bar spacing, real installing to the home screen, push notifications, offline mode, real-device speed |
| Later option | Real Android phone over USB, or a paid device-testing service |

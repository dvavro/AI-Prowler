# AI-Prowler Remote PWA — End-to-End GUI Test Spec

**Status:** Draft 1 — 2026-09-28 · **Owner:** David Vavro · **Modeled on:** `tests\JOBS_APP_E2E_TEST_SPEC.md`

---

## 0. Status & regression commands

| Area | Status | Command (from `tests\`) |
|---|---|---|
| Harness (runner flag, guard, page objects, sandbox) | ✅ built 2026-09-29 — `tests\gui_remote_e2e\` (conftest, `remote_safety.py`, `remote_app.py`), sandbox **`C:\Users\david\AI-Prowler-E2E-Remote-Sandbox`** (own tracked folder, read-only between runs), runner `--remote`, pytest marker `remote_gui_e2e` (excluded from the default run). Every browser call and upload passes the write guard; each run sweeps to 0 ZTEST items and restores the sandbox's write setting | — |
| **All Remote PWA tests** (the regression) | ✅ **56/56 — full run 2026-09-30 05:53–06:04 (11 min 23 s, human mode)**, 0 ZTEST items left. History: 2026-09-29 21:16–21:28 was 54/56 — both failures were *test* problems left over from moving the sandbox (RF-01 writable check → now the `[W]` rule; RF-02 had no folder to browse into → now a `ZTEST_E2E_sub` folder; the sweep also removes ZTEST folders) | `run_tests_gui_jobs_e2e.bat --remote --human` (≈ 11–20 min; without `--human` it runs headless and faster) |
| Login & session (RA) | ✅ 7/7 (13:32) | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_auth` |
| Dashboard & System (RD / RY) | ✅ **4/4 (21:08)** — tiles fill in, quick-access rows open their screens, ↻ reloads with no errors, System status + stats | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_dash` |
| Files, download, upload (RF) | ✅ **6/6 (2026-09-30 05:51)** — RF-01 tracked folders (read-only sandbox shows "Read only"), RF-02 open a folder + ← Back, RF-03 👁 View text + ✕, RF-08 👁 View image (no token in the URL), RF-09 View only on previewable files, RF-04 ⬇ Get exact bytes. Upload RF-05/06 in `test_remote_perms.py` | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_files` |
| Search (RS) | ✅ **4/4 (21:07)** — finds the sandbox seed file, Enter key, nonsense → no results, empty query | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_search` |
| Permissions (RP) + Upload (RF-05/06) | ✅ **7/7 (19:49)** — grant with token, wrong token, Cancel, instant revoke, upload byte-for-byte, no Upload when read-only; RM-R-007 verified. Sandbox moved to `C:\Users\david\AI-Prowler-E2E-Remote-Sandbox` (own tracked folder, read-only) | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_perms` |
| Learnings (RL) | ✅ 6/6 (19:03) — RM-R-004 verified | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_learn` |
| Tasks (RT) | ✅ **7/7 (21:15)** — after the RM-R-008 deploy: RT-10 (refusal shown, nothing saved), RT-02 create, RT-03 weekly pinned to Tuesday + daily ×3 cost warning, RT-05 edit (no duplicate), RT-06 Run now (never really queued), RT-08 delete with confirm, RT-09 required fields | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_tasks` |
| Security (RX) — runs first | ✅ RX-02/03/05/06/07/08 pass (13:32); RX-01 test corrected; **RX-04 → RM-R-001**, fixed and verified live 18:31 | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_security` |
| Phone layouts (RM) | ✅ **4/4 (full run 2026-09-29 21:16–21:28)** — RM-01 no sideways scroll on any screen + bottom nav fully on screen; RM-02 nav + top-bar ↻ ≥ 40 px on Pixel 7 and iPhone 13 → **RM-R-009 verified live** | `run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_mobile` |

Results: `tests\gui_remote_e2e\artifacts\latest\SUMMARY.txt` + `report.html`. Every run must end with **0 ZTEST items left** (learnings, tasks, sandbox files, write grants).

---

## 1. What the Remote PWA is

A **personal-mode only** phone/browser companion to AI-Prowler, served by the personal install at `https://<tunnel>/remote/` (same tunnel as the Jobs app). One page (`remote\index.html`, ~2,200 lines) + `sw.js` + `manifest.json`.

**Sign-in:** the owner types the **Bearer Token** (Settings → Remote Access). `/pwa-verify` checks it server-side (security fix 2026-09-25 — `/pwa-token` no longer hands the token out). The token is kept in `sessionStorage['ap_remote']` (gone when the tab closes) and sent as `Authorization: Bearer` on every call.

**Screens (bottom nav):**

| Screen | What a person does | Server calls |
|---|---|---|
| Dashboard | Tiles: chunks, tracked paths, indexed docs, status; quick links | `check_ai_prowler_status` |
| Files | Browse tracked folders, preview a file, **Download** a file, **Upload** a file/photo to a writable folder | `list_tracked_directories`, `list_writable_directories`, `list_directory`, `read_file_lines`, `GET /remote/download`, `POST /remote/upload` |
| Search | Full-text RAG search of the knowledge base | `search_documents` (30 s timeout) |
| Permissions | Per tracked folder: toggle write access. **Grant** needs the token re-typed (modal); **Revoke** is instant | `list_tracked_directories`, `list_writable_directories`, `grant_write_access`, `revoke_write_access` |
| Learnings | Stats, list, search, **Add Learning** form, delete | `get_learning_stats`, `list_learnings`, `search_learnings`, `record_learning`, `delete_learning` |
| Tasks | Custom AI analysis tasks: list, **New Custom AI Task** form, edit, delete, "run now" (queue), queue panel, clear queue | `list_analysis_tasks`, `get_all_queued_tasks`, `create_analysis_task`, `update_analysis_task`, `delete_analysis_task`, `queue_single_task`, `sync_due_tasks_to_queue` |
| System | Status + database stats | `check_ai_prowler_status`, `get_database_stats` |

Also: top-bar ↻ refresh-all, connection dot, "update available" banner (service worker), a debug log panel (`#debugLog`).

**Not in scope:** server mode — the Remote PWA is personal-only (David, 2026-09-28). One check (RX-08) only confirms a **server** install doesn't serve it as a working app.

---

## 2. Suspected issues from reading the code (each has a test)

| # | Suspicion | Test |
|---|---|---|
| RQ-01 | Tasks screen calls **`sync_due_tasks_to_queue`**, which the server documents as removed ("there is no bulk sync tool") — that button/refresh path may error silently | RT-07 |
| RQ-02 | `api()` logs **the first 8 characters of the Bearer token** into `#debugLog` on every call (`BEARER.slice(0,8)`) — visible on screen if the panel shows, and it's a real part of the password | RX-03 |
| RQ-03 | **Download puts the full token in the URL** (`/remote/download?path=…&token=…`) — lands in server access logs, proxy logs and browser history | RX-04 |
| RQ-04 | Upload sends the token **in the JSON body** instead of the Authorization header (works, but inconsistent) | RX-05 (record only) |
| RQ-05 | **Revoke** has no confirmation ("Revoking is instant") — one mis-tap removes write access | RP-04 (record, David's call) |
| RQ-06 | "Run now" **queues a real task** — if the Autonomous AI Task Queue is on, it may actually run and spend AI credits | guard: `queue_single_task` never sent (RT-06 wiring only) |
| RQ-07 | Date handling: weekly/monthly `next_due` shown a day early west of UTC (fixed 2026-09 per code comment) | RT-04 |
| RQ-08 | **The file preview was unreachable** — `previewFile()` existed but nothing called it (file rows only had "⬇ Get"). **David's decision 2026-09-29: add a Preview button.** Built: a **👁 View** button on text files (`.txt .md .log .json .py .js .html .css .csv`) and images (`.png .jpg .jpeg .gif .webp`) in the Files browser; opens the preview panel, scrolls to it, ✕ closes it. `.svg` left out on purpose — it isn't on the server's download allow-list, so its preview could never load. Awaiting deploy. | RF-03 / RF-08 |

---

## 3. Safety rules

Same philosophy as the Jobs app spec §4: **the live personal install, real data, nothing real is harmed.**

1. **Test data is named `ZTEST E2E …`** — learnings (title), analysis tasks (label), uploaded files (`ZTEST_E2E_*.txt`).
2. **Write guard** (`gui_remote_e2e\remote_safety.py`) sees every `/remote-api`, `/remote/upload` call from the browser *and* from test setup:
   - **reads** → allowed;
   - **creates** (`record_learning`, `create_analysis_task`) → allowed only with a ZTEST title/label; the new id is registered;
   - **scoped** (`delete_learning`, `delete_analysis_task`, `update_analysis_task`, `grant_write_access`, `revoke_write_access`, upload) → allowed **only** for things this run created, or the **sandbox folder**; anything else is **blocked and fails the test**;
   - **`queue_single_task`, `sync_due_tasks_to_queue`** → never sent (recorded; a canned reply is returned) — RQ-06;
   - anything unknown → blocked.
3. **Sandbox folder: `C:\Users\david\AI-Prowler-E2E-Remote-Sandbox\`** — tracked as its **own** folder, **outside every writable folder**, normally **read-only** (moved 2026-09-29 with David's OK, from `tests\gui_remote_e2e\sandbox\`, which is now untracked). Uploads and write-grant tests touch only this folder; the guard blocks grant / revoke / upload anywhere else. Every run deletes its `ZTEST_E2E_*` files and restores its write setting to what it was before the run. It keeps a `README.txt` explaining what it is.
   *Why it moved:* inside the writable work folder it was writable *through its parent* and could never be read-only (RM-R-007), so grant / wrong-token / Cancel / "no Upload when read-only" couldn't be tested — and the tests must never upload into, or toggle, the whole work folder.
4. **Pre-flight:** reachable, **personal** mode, token valid, sandbox exists and is tracked; else stop.
5. **Cleanup:** start-of-run and end-of-run sweeps delete every ZTEST learning and task and every sandbox file; SUMMARY must say 0 left.
6. **No traces / videos** of sign-in with the token typed visibly; screenshots mask `#authInput`, `#raInput`, `#debugLog`.

---

## 4. Architecture

- **Suite folder:** `tests\gui_remote_e2e\` (own `conftest.py`, own artifacts).
- **Runner:** the existing `run_tests_gui_jobs_e2e.bat` gains `--remote` (like `--server`): picks the suite + marker `remote_gui_e2e`, same `--human`, `--slowmo`, `--headed`, `-k`, `--keep-data`.
- **Target URL:** `AIPROWLER_REMOTE_URL` (Windows user env var), default = the Jobs app URL's origin + `/remote/`. **Token:** the same `AIPROWLER_JOBS_TOKEN` the Jobs suite uses (it is the personal Bearer Token).
- **Setup/cleanup API:** direct `/remote-api` calls to **`http://127.0.0.1:8000`** (Jobs spec: avoids Cloudflare timing, and never blocks the server).
- **Page objects** (`remote_app.py`): `RemoteApp` (login, nav, refresh), `FilesScreen`, `SearchScreen`, `PermsScreen`, `LearnScreen`, `TasksScreen`, `SystemScreen`.
- **Human mode:** typed token and form text character by character, visible pauses, `--slowmo`.

---

## 5. Test catalog

### 5.1 Login & session — `test_remote_auth.py` (RA)
| ID | Scenario | Verify |
|---|---|---|
| RA-01 | Type the right token, tap Unlock | app shows; top bar "‹owner› · Personal"; token NOT in localStorage; sessionStorage holds the session |
| RA-02 | Wrong token | "Incorrect token" shown; field cleared; still on login |
| RA-03 | Empty token, tap Unlock | nothing happens (no call, no error) |
| RA-04 | 👁 show/hide | field type flips password ↔ text and back |
| RA-05 | Reload while signed in | resumes without re-typing (server re-verifies) |
| RA-06 | Saved session no longer valid (sessionStorage edited) | back to the login screen, bad session removed |
| RA-07 | New tab / closed tab | new tab must sign in again (sessionStorage is per tab) |

### 5.2 Dashboard & System — `test_remote_dash.py` (RD, RY)
| ID | Scenario | Verify |
|---|---|---|
| RD-01 | Open Dashboard | 4 tiles filled with numbers/status (not "—"); connection dot live |
| RD-02 | Quick-access rows | each opens its screen |
| RD-03 | Top-bar ↻ | every screen reloads, no errors |
| RY-01 | System screen | status + DB stats shown; numbers match the Dashboard tiles |

### 5.3 Files — `test_remote_files.py` (RF)
| ID | Scenario | Verify |
|---|---|---|
| RF-01 | Files lists tracked folders; writable ones show Upload | matches `list_tracked_directories` / `list_writable_directories` |
| RF-02 | Browse into the sandbox, breadcrumb back | listing correct |
| RF-03 | Tap a text file → preview | first lines shown |
| RF-04 | Download a sandbox file | browser download fires; bytes equal the file on disk |
| RF-05 | Upload `ZTEST_E2E_upload.txt` to the sandbox (writable) | "✅ Uploaded … indexed"; file on disk with same bytes; listing refreshes |
| RF-06 | Upload to a **non-writable** folder (sandbox with write revoked) | refused with a clear message; nothing written |
| RF-07 | Download a path outside tracked folders (URL edited) | refused (403/404), nothing leaked |

### 5.4 Search — `test_remote_search.py` (RS)
| ID | Scenario | Verify |
|---|---|---|
| RS-01 | Search a word known to be in an indexed doc (the sandbox seed file) | result card with that file |
| RS-02 | Enter key searches | same as button |
| RS-03 | Nonsense query | friendly "no results" |
| RS-04 | Empty query | nothing / prompt, no error |

### 5.5 Permissions — `test_remote_perms.py` (RP)
| ID | Scenario | Verify |
|---|---|---|
| RP-01 | List | every tracked folder with its R/W state; matches the server |
| RP-02 | Grant write on the sandbox: modal → re-type token → Grant | sandbox becomes writable (server confirms) |
| RP-03 | Grant with the wrong token | refused in the modal; nothing changes |
| RP-04 | Revoke on the sandbox | instant; server confirms read-only. Records RQ-05 (no confirm) |
| RP-05 | Cancel the grant modal | nothing changes |

### 5.6 Learnings — `test_remote_learn.py` (RL)
| ID | Scenario | Verify |
|---|---|---|
| RL-01 | Stats + list load | count matches `get_learning_stats` |
| RL-02 | + Add Learning with every field | saved; appears in list; server has title/content/category/outcome/tags/context |
| RL-03 | Required fields empty | inline error; nothing saved |
| RL-04 | Search finds the ZTEST learning | shown |
| RL-05 | Delete it (confirm) | gone from list and server |
| RL-06 | Cancel the form | hidden, nothing saved |

### 5.7 Tasks — `test_remote_tasks.py` (RT)
| ID | Scenario | Verify |
|---|---|---|
| RT-01 | List + queue panel load | counts match the server |
| RT-02 | + New Custom AI Task, schedule "none" | created; card shows it |
| RT-03 | Weekly with a day of week; daily with 3 runs/day | preview text right; server has the schedule |
| RT-04 | Weekly task's next due date | shown on the right day (RQ-07) |
| RT-05 | Edit the task (label, prompt) | server updated, not duplicated |
| RT-06 | "Run now" | **never really queued** (guard) — wiring only: the app sends `queue_single_task` for THIS task id |
| RT-07 | Refresh / due-task sync | no error from `sync_due_tasks_to_queue` (RQ-01) |
| RT-08 | Delete the task (confirm) | gone |
| RT-09 | Required fields empty / bad daily times | inline error |
| RT-10 | Weekly task with **First due left empty** (server refuses) | the server's reason ("first due date is required") shown in the form, form stays open, nothing saved — never "✅ Task created" (RM-R-008) |

### 5.8 Security — `test_remote_security.py` (RX) — runs FIRST
| ID | Scenario | Verify |
|---|---|---|
| RX-01 | `/pwa-token` | never contains a token |
| RX-02 | `/remote-api` without / with a wrong token | 401, no data |
| RX-03 | Debug log after normal use | **no part of the token** anywhere on the page or in `#debugLog` (RQ-02) |
| RX-04 | Download request | token not in the URL (RQ-03) — expected to fail until fixed |
| RX-05 | Upload without / with a wrong token | refused |
| RX-06 | Path tricks in download/upload (`..\`, absolute path outside tracked, UNC) | refused |
| RX-07 | Every `/remote-api` call passed the guard | request count = guard count |
| RX-08 | Server install's `/remote/` | not a working app on a server install (personal-only) |

### 5.9 Phone layouts — `test_remote_mobile.py` (RM)
| ID | Scenario | Verify |
|---|---|---|
| RM-01 | Pixel 7 / iPhone 13 viewports, every screen | no sideways scroll; bottom nav fully visible |
| RM-02 | Buttons | ≥ 40 px tap size (as R-037 for Jobs) |

---

## 6. Implementation plan

1. **Harness** — `gui_remote_e2e\`: `conftest.py` (pre-flight, sandbox, guard route on `**/remote-api` + `**/remote/upload`, sweeps, SUMMARY), `remote_safety.py`, `remote_app.py`, runner `--remote`, pytest marker `remote_gui_e2e`, sandbox seed file.
2. **RX + RA** first (security & login), human mode.
3. **RD/RY, RS, RF**, then **RP**, **RL**, **RT**, **RM**.
4. Each finding → **RM-R-###** row in §7 with test id; fix in `remote\index.html` / `ai_prowler_mcp.py`, deploy with `update_install.bat`, rerun.
5. Keep §0 table current after every run.

## 7. Bugs found (RM-R-###)

| # | Bug | Test | Status |
|---|---|---|---|
| RM-R-001 | **(security) Download put the full Bearer token in the URL** (`/remote/download?path=…&token=…`) **and the server logged the raw query string** — so the token landed in AI-Prowler's own log, tunnel/proxy access logs and browser history. *Found 2026-09-29 13:32 by RX-04. Fixed: `remote\index.html` — new `_fetchDownload()` sends `Authorization: Bearer`; `ai_prowler_mcp.py` `/remote/download` — reads the header first (`?token=` still accepted only for ready-made `get_file_download_url` links), logs `path` + "token via header/query", never the query string. Deployed; **verified live 2026-09-29 18:31 — RX-04 passes.*** | RX-04 | ✅ fixed + verified |
| RM-R-002 | **Image preview always broken** — `<img src="/remote/download?path=…">` sent no token → 401. *Fixed (fetch with header → blob URL), deployed.* **Correction 2026-09-29: `previewFile()` is never called anywhere in the app — there is no Preview button (file rows only offer Download), so this code is unreachable dead code.** | — | ✅ fixed, but dead code — see RQ-08 |
| RM-R-003 | **Preview ✕ didn't close** — `closePreview()` was empty. *Fixed, deployed.* Same correction: the preview panel can't be opened from the UI. | — | ✅ fixed, but dead code — see RQ-08 |
| RM-R-004 | **Learnings search never worked** — the app sent `top_k`, but `search_learnings` takes `n_results` → "unexpected keyword argument 'top_k'" → "Search error" for every search. *Found 2026-09-29 13:49 by RL-04. Fixed in `remote\index.html`.* | RL-04 | ✅ fixed + verified (RL 6/6, 19:03) |
| RM-R-005 | **Text-file preview never worked** — `read_file_lines` was called without its required `start_line` → "Could not preview file" for every .txt/.md/.py/…  *Found 2026-09-29 by the argument audit (below). Fixed: `start_line: 1`. Now reachable through the new 👁 View button (RQ-08).* | RF-03 | ✅ fixed + verified (RF-03, 19:18) |
| RM-R-006 | **Tasks "Sync" always failed** — it called `sync_due_tasks_to_queue`, which the server removed (RQ-01 confirmed). *Found 2026-09-29 by the argument audit. Fixed: Sync now reloads the task list + queue (the queue is filled per task with Run now).* **Correction 2026-09-29: no button calls `syncTasks()` — like the old preview, it's unreachable code, so this fix has no user-visible effect; RT-07 dropped.** **David's decision 2026-09-30: leave Sync out — `syncTasks()` deleted** (a bulk "queue every due task" could start several AI runs, spending credits, from one tap; the queue is filled per task with Run now, and ↻ refreshes the lists). A comment in its place explains why. | — | ✅ removed (awaiting deploy with RM-R-010) |
| RM-R-007 | **A folder inside a writable folder showed as read-only.** The server decides "writable?" by *inside a writable folder*, but `list_writable_directories` labelled each tracked folder only by its own entry — so the sandbox (inside the writable work folder) showed **[R]** in Permissions and had **no Upload** in Files, although it was writable; granting answered "already in the write zone — no change" (the app showed R+W, then R again after a refresh), and revoking answered "not in the write zone — nothing to revoke" (the app showed R, but it stayed writable). *Found 2026-09-29 19:24 by RP-02/RP-04/RF-05. Fixed: `ai_prowler_mcp.py` — `list_writable_directories` lists such folders under **Writable** (same `✅ [W]  <path>` line the app parses) plus a "↳ writable because it is inside …" note; `revoke_write_access` refuses with "❌ … is inside the writable folder '…' — revoke that folder instead"; `remote\index.html` — Permissions treats a ❌ answer as a refusal (toggle stays, message shown) for both revoke and grant.* | RP-02 / RP-04 / RF-05; nested case: `tests\mcp_tests\test_rm_r007_r008_remote_write_zone.py` | ✅ fixed, deployed, verified live (Permissions 7/7, 19:49). **The live tests no longer have a nested folder** (the sandbox moved out, and no tracked folder on David's install sits inside a writable one), so the nested case is covered offline: 5 unit tests on temp folders — listed under Writable with the "↳ inside" note, revoke refused naming the parent (nothing saved), grant = "already in the write zone", an unrelated folder still "nothing to revoke", revoking the parent still works. 5/5 (21:10) |
| RM-R-008 | **A server refusal looked like success — "✅ Task created" when nothing was saved.** The server wraps a tool's own refusal as `{ok:true, result:"❌ …"}`, and every screen only checked `ok`. Seen live: Tasks → Weekly with **First due** left empty → the server said "❌ A first due date is required for scheduled tasks.", the app toasted "✅ Task created", closed the form, and no task existed. *Found 2026-09-29 19:57 by RT-03. Fixed in `remote\index.html`: one helper `_asResult()`, used by `api()` and `apiSlow()`, turns a ❌ result into `ok:false` with the server's message as `error` — the task form stays open and shows the reason, and every other screen (learnings, deletes, permissions) gets the same treatment. Permissions' own RM-R-007 ❌ handling still works (its else-branch shows `r.error`).* Tests: RT-10 (live, new) + 3 offline checks in `test_rm_r007_r008_remote_write_zone.py` (3/3). RT-03 itself now fills First due (the test was also wrong). | RT-03 / RT-10 | ✅ fixed, deployed, **verified live** — Tasks 7/7 (21:15) incl. RT-10 |
| RM-R-009 | **The top-bar ↻ (refresh all) was too small to tap reliably** — 38 × 30 px on Pixel 7 and iPhone 13, below the 40 px finger-size bar (same rule as the Jobs app, R-037). The bottom-nav buttons are fine. *Found 2026-09-29 21:09 by RM-02. Fixed in `remote\index.html`: `.topbar-refresh` gets `min-width/min-height: 44px` (icon centred; the top bar uses min-height, so nothing is clipped).* Not in scope of RM-02 but noted: the login screen's 👁 show/hide button is 34 × 34 px. | RM-02 | ✅ fixed, deployed, **verified live** — RM-02 passes on both phones (full run 2026-09-29 21:16–21:28) |
| RM-R-010 | **Both 👁 show/hide buttons were under finger size** — the login screen's was 34 × 34 px, and the grant-write-access modal's had no size at all (just the emoji, ≈ 20 px). *Noted 2026-09-29 by RM-02; David's decision 2026-09-30: enlarge. Fixed in `remote\index.html` (CSS only): both 44 × 44 px, and both text boxes' right padding widened to 54 px so typed text never runs under the button.* New test **RM-03** (both buttons ≥ 40 px, on Pixel 7 and iPhone 13). | RM-03 | 🔧 fixed, **awaiting deploy** (`remote\index.html` only, no restart) |

**Argument audit (2026-09-29)** — `tests\_audit_remote_api_args.py` compares every `api('tool', {…})` call in `remote\index.html` with the server tool's real parameters. 21 distinct calls: 1 missing tool (RM-R-006), plus RM-R-005 found by hand (a *missing required* argument, which the audit doesn't detect). Task create/update and record_learning argument names checked by hand — all valid. Re-run after any change to the Remote app. **Latest (2026-09-30 06:21, after `syncTasks()` was removed): 20 distinct calls, 0 problems.**

**Suspicions resolved so far:** RQ-02 (token fragment in `#debugLog`) — the panel isn't in the page, RX-03 ✅; the logger no longer copies any of the token anyway. RQ-03 → **RM-R-001**. RX-01 first run failed on the *test* (it flagged the always-empty `"token": ""` field `/pwa-token` keeps for old app versions) — test corrected: the field must be empty.

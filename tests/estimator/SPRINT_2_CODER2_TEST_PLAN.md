# Sprint 2 — Coder 2 (David) test plan: documents, Dashboard, Projects and Quick estimate screens

**Scope:** The Coder 2 Sprint 2 row: "Documents: upload and validation, file storage in the project folder; Dashboard and Projects screens; Quick estimate screen". Jamie's Sprint 21 had already built the checks and storage behind `plan_upload` (real file type, 300 MB limit, no password-protected PDFs, no duplicates, copied to `projects\estimate_NNNN\plans\`). This sprint brings that to the browser and builds the screens. The full Plans screen (sheets, scales, schedules) stays in Sprint 5.

## How to run

```
cd /d "C:\Users\david\AI-Prowler_V971_to_V1000_work\AI-Prowler"
run_tests_estimator.bat coder2      the web app tests
run_tests_estimator.bat             all Estimator tests
install_estimator.bat               then restart AI-Prowler
```
Open http://localhost:8770/estimator/. There are no new tools or tables.

## What was built

**Plan uploads from the browser** (`estimator/api/staging.py`, router `/estimates/<id>/plans/...`). A browser can't give a file path, and `plan_upload` asks before attaching, so uploads take two steps:
1. **Stage.** `POST /estimates/<id>/plans/stage?name=<file>` sends the raw file. The server streams it to `<data>\cache\web_uploads\<stage id>\` and never holds it in memory, so files up to 300 MB work. The JSON request limit is still 2 MB. It then runs `plan_upload` with confirm=false, which does the same checks and duplicate test, and returns the question to ask ("Attach X (PDF, 2.1 MB) to estimate 4?") plus any warnings. Nothing is attached yet.
2. **Attach or Cancel.** `POST .../plans/attach {stage_id}` runs `plan_upload` with confirm=true on the staged copy. The project gets its own copy and the staged one is deleted. `DELETE .../plans/stage/<id>` cancels.

These refusals happen **before the body is read**: wrong role (only owner, estimator and office upload, as in `store.UPLOAD_ROLES`), another company's or a missing estimate, a file type that isn't allowed, over 300 MB, an empty file, the missing anti-CSRF header, and not signed in. A refused upload closes the connection instead of waiting for the rest of the file. File names are cleaned (no folders, no odd characters, extension kept). Only the person who staged a file can attach or cancel it, and only on that estimate. Stages expire after 1 hour, and leftover folders (e.g. after a restart) are swept. A revised set ("This is: Revised set — replaces #N") becomes revision N+1.

**Project page** (`#/projects/<id>`, `GET /estimates/<id>/project`). It shows:
- the status, due date and address
- tiles for the total, the number of trades and the plan sets
- each trade's subtotal and its biggest lines, from `est_project_status`
- the takeoff run's tasks, and the Director lane, stage and who it's waiting on
- the plan sets with their warnings and status, plus the upload box
- the history (audit trail)
- the practice-project and "someone else is editing" notes

Field users see totals but no costs and no upload box.

**Dashboard.** A "⚡ Quick estimate" button for quoting roles. Status tiles open Projects filtered to that status. "Needs attention" lists estimates waiting for review, my assigned estimates and my unread notices (`est_my_work`).

**Projects.** A status filter (server side), a find box (on the page), clickable rows, and "Create project" opens the new project.

**Quick estimate** (`#/quick`, or `#/quick/<id>` to add to an existing project). It has a service picker (services first, then trades with quick questions) and a form built from the module's questions: numbers with their min, max and unit; choices; yes/no. "Price it" runs `POST /quick`:
- **New project:** the answers are checked first, so bad answers never leave an empty project. Then the project is created (named "<service> – <address>" unless named) and priced with `est_quick_answer`.
- **Existing project:** it needs the estimate's `rev`, so a change made meanwhile is refused (409) rather than overwritten.

The result shows the total, the lines and the sample-price warnings, with "Open the project". Turning it into a quote is done in chat for now; the Bids screen comes in Coder 2 Sprint 4. Owner, estimator, office and field can quote (`service.QUICK_ROLES`); reviewer can't.

**Permissions sent to the page:** `upload_plans` and `quick_estimate`, so buttons only show where the server will allow them. A test keeps these lists equal to the service layer's own.

**Parity:** the off-menu pages are listed in `nav.PAGES` with their tools (`est_project_status`, `est_get_estimate`, `plan_upload`, `plan_status`; `est_list_modules`, `est_quick_questions`, `est_quick_answer`, `est_create_estimate`), and the tests check those tools exist and that app.js draws each page.

## Test cases (tests/estimator/webapp/test_web_sprint2.py, plus parity additions)

| ID | Test | Checks |
|---|---|---|
| C2S2-P01 | Project page | address, due date, per-trade subtotal after a quick estimate, empty plan sets, owner's rights |
| C2S2-P02 | Field | no costs, no upload, still the total, can quick-quote |
| C2S2-P03 | Company | another company's project is not found |
| C2S2-U01 | Stage then attach | nothing attached until Attach; question names the file; attached copy is the uploaded bytes, in estimate_NNNN not web_uploads; staged copy removed; `plan_uploaded` reaches live updates |
| C2S2-U02 | Revision | revised set is revision 2 and the question names the set it replaces |
| C2S2-U03 | Cancel | staged folder removed; can't attach afterwards |
| C2S2-U04 | Bad files | program renamed .pdf, password-protected PDF, .docx, no extension, empty, JPEG named .png: refused with the reason, nothing kept |
| C2S2-U05 | Duplicate | same file twice refused, staging cleaned |
| C2S2-U06 | Names | `../`, `<script>` and folders stripped; extension kept |
| C2S2-U07 | Refuse before reading | over 300 MB, field, reviewer, other company, missing estimate, .exe, no CSRF header, not signed in from another PC: the body is never read |
| C2S2-U08 | Cut off | fewer bytes than announced → `upload_incomplete` |
| C2S2-U09 | Who | office can upload; another user or another estimate can't attach or cancel |
| C2S2-U10 | Expiry | expired stage can't be attached; old leftover folders swept, fresh ones kept |
| C2S2-H01 | Over HTTP | a file bigger than the 2 MB JSON limit streams through the real server; a refused upload answers without waiting for the body and closes the connection |
| C2S2-Q01 | Modules | quick list has only quick modules, services first; questions for a service; unknown module 404 |
| C2S2-Q02 | New project | named "<service> – <address>", priced, sample warning |
| C2S2-Q03 | Existing project | needs rev; a stale rev is refused (409) |
| C2S2-Q04 | Bad answers | missing, unknown, not an object, no service, unknown module: refused and no project created |
| C2S2-Q05 | Roles | office, field, estimator can; reviewer can't; field sees no costs; CSRF header needed |
| C2S2-D01 | Dashboard | waiting-for-review list, my work, quick button flag |
| C2S2-W01 | Page | app.js has the new pages, uses XMLHttpRequest for upload progress, never innerHTML |
| C2S2-X01 | Parity | pages' tools exist; page buttons use the same role lists as the service layer; app.js PAGES = nav.PAGES; permission keys |

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC) | **818 passed, 0 failed** (Coder 2: 145; 37 new) (2026-11-08) |

## Manual checks (David, on the PC after install_estimator.bat and a restart)

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | Dashboard → ⚡ Quick estimate → Pressure Washing → driveway 1000 → Price it | a total, the lines, the sample-price warning; "Open the project" shows it with one trade | |
| M2 | On that project → ⚡ Add a quick estimate → House Cleaning → Price it | project now has two trades; total is the sum | |
| M3 | Ask Claude to change that estimate while the page is open | page refreshes; a second "Price it" on the old screen is refused as changed meanwhile | |
| M4 | Project → Upload plans → a real 20–50 MB PDF set | progress bar; question with the file name and size; Attach → listed as uploaded, rev 1 | |
| M5 | Upload the same file again; then a .docx; then Cancel on a third | "already on this estimate"; "can't be used"; "Cancelled — nothing was attached" | |
| M6 | Projects → filter "draft", type part of a name | list narrows; clicking a row opens the project | |
| M7 | Phone (with `--network` and sign-in) | dashboard, quick estimate and project page usable on the phone | |

## Notes for Jamie

- No changes to your files this sprint. `plan_upload`, `est_quick_answer` and `est_project_status` are used as they are.
- A quick estimate on a *new* project checks the answers before creating the project. If pricing still fails afterwards (e.g. a price-book unit mismatch), an empty draft is left behind. Tell me if you'd rather have a service function that creates and prices in one transaction.
- `est_add_trade` / `est_remove_trade` are still pending. Projects add trades through the quick estimate for now.

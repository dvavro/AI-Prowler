# Sprint 24 — Coder 1 (Jamie) test plan: plan revisions and Server mode compute limits

**Scope:** The Coder 1 work from planned Sprint 11 (Phase 7): `plan_compare_revisions` with saved revision reports, and the Server mode compute limits: the processing-PC queue (`plan_processing_queue`), publishing results to the server (`plan_publish_to_server`), the heavy-job guard and the owner's "small plan processing on the server" setting (`est_server_compute`). The plan engine and the revision overlay drawing are Coder 2's (David); this sprint gives them the data.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
Then start AI-Prowler again. The database upgrades itself to version 16 (David's symbol migrations are 14 and 15). There are 102 Estimator tools (4 new from this sprint).

## What was built

**Plan revisions** (`estimator/drawing_model/revisions.py`, `plan_compare_revisions`, migration v16 `revision_reports`). Rev A → Rev B through the drawing model:
- Sheets are matched by sheet number, then title, then page. New and dropped sheets are listed.
- On each sheet, objects are matched by what they are (kind, label, tag, block, layer) and where they are:
  - **unchanged**: same shape, same place, same real size
  - **moved**: same shape somewhere else
  - **changed**: different size or shape, or the same lines at a new scale
  - **removed** / **added**
- Schedule rows are matched by type and mark (added, removed, which fields changed). Revision clouds and deltas on the new set are counted.
- The report lists boxes for the overlay (red = removed, green = added) and says it in one line ("Rev 1 → Rev 2: 3 added, 1 removed, ...").

**What happens to measurements (flag only):**
- Every source object unchanged → the measurement carries over: it points at the new set's objects, sheet and viewport, keeps its quantity and status, and notes where it came from.
- Any source object changed, moved or removed → flagged "re-measure" with the reason. The quantity is never changed.
- Typed measurements aren't touched.
- The old plan set stays on file. It asks first, showing the counts and how many measurements carry over or get flagged. `report_id` shows a saved report again.

**Server mode compute limits** (`estimator/drawing_model/server_jobs.py`). The server does light work only. The server and the estimators' PCs share one exchange folder (`ESTIMATOR_EXCHANGE_DIR`, a network share):
- **Upload on the server** → queued for a processing PC, the uploader's own first. The job and a copy of the plan file go into the shared folder. If no PC is online, the uploader gets an inbox message.
- `plan_process` on the server doesn't run the engine. It says whose PC it's waiting for and why.
- `plan_status` and the Director's full takeoff lane say "Waiting for plan processing on Maria's PC", with whether it's been picked up.
- **On a processing PC**, `plan_processing_queue(claim=true)`:
  - takes the next job (your own uploads first; others after 15 minutes or with `any_job`)
  - puts the plan file into that PC's Estimator
  - two PCs can never take the same job
- `plan_process` reads it there, and progress is shown on the server.
- `plan_publish_to_server` (asks first) sends the drawing model, viewports, schedules, sheet images and proposed measurements. Only the PC that took the job can publish it.
- **The server takes it in** on `plan_processing_queue` or the Director's watcher:
  - it checks that the results come from the same file and the same company
  - it saves the sheet images, the drawing model and the proposed measurements (proposed by "pc:maria-laptop")
  - it marks the plan set published, tells the uploader it's ready to review and clears the job
  - a bad result is set aside in `failed\` with the reason
- A claim with no progress for 2 hours goes back to the queue.
- **Heavy-job guard** (`est_server_compute`, owner only, asks first): small plan processing on the server is off by default. When it's on, the server reads vector PDF or DXF sets of up to 10 sheets (setting, 1–50), one at a time. Anything else still goes to a processing PC.
- Comparing revisions on the server is refused over 20,000 drawing objects.
- Personal mode is unchanged: one PC does everything.

**Also:** the Plan Reader agent's instructions cover revisions and the queue.

## Test cases (tests/estimator/unit/test_sprint24_revisions_server.py)

Test drawing: E-101 at 1/4" with 5 outlets, a 320 sq ft slab, a porch, door D1 and a GFI. Rev B moves outlet 4, makes the slab 384 sq ft, removes the GFI, adds a floor box and a revision cloud, changes D1's size in the schedule and adds sheet E-102.

| ID | Test | Checks |
|---|---|---|
| S24-C01 | Compare | asks first with 6 unchanged, 1 moved, 1 changed, 1 removed, 3 added, 2 carry, 3 flag; report on E-101 lists the changed slab (sizes differ), the removed GFI with its box, the floor box and cloud added; E-102 added; 1 revision mark; D1's size change; the sentence; flagged and carried ids; the saved report reads back |
| S24-C02 | Measurements | the approved count on unchanged outlets carries over (new objects and sheet, still approved and locked); the slab flagged "changed" and still 320 and approved; GFI "removed"; the count with the moved outlet "moved"; the typed one untouched; the old set still processed; events logged |
| S24-C03 | Refusals | no earlier set, same set, an unread set, sets on different estimates, field role, a missing report |
| S24-C04 | Server cap | a comparison over the cap is refused on the server, under it runs |
| S24-Q01 | Server upload | queued for Maria with no PC online; job and plan copy in the shared folder; status says "maria's PC"; one inbox message; plan_process on the server only queues ("small plan processing is off"); the queue lists it; Personal mode has no server queue |
| S24-Q02 | Claim, read, publish | Maria's PC claims it; the server shows it claimed on maria-laptop with 1 PC online; nothing else to claim; read with the engine; a proposed measurement; publish asks (1 sheet, 9 objects, 1 measurement), then sends with the image; the server takes it in: processed, 9 objects, "read on maria-laptop", the image saved, the measurement proposed by pc:maria-laptop at 320, job cleared, "ready to review" message |
| S24-Q03 | Order and races | Bob's job waits for Bob's PC; Maria's own job comes first; any_job takes Bob's; another PC can't take a claimed job |
| S24-Q04 | Stale claims | a claim with no progress for 2 hours goes back to waiting |
| S24-Q05 | Publish checks | not read yet; not a server job; another PC can't publish; a result from a different file is set aside with the reason; another company refused |
| S24-G01 | Small processing | off by default; only the owner; asks first; limit 1–50; 25 sheets over the limit; PNG always to a PC; one at a time; an 8-sheet PDF is read on the server and leaves the queue; page counting |
| S24-D01 | Director | the full takeoff lane waits on "processing_pc" with "maria's PC"; after the PC publishes, the watcher takes it in and the Director moves on |
| S24-T01 | Tools | compare asks, runs and reads a report back; server compute shows Personal mode and asks before changing; the queue says Personal mode; claim finds nothing; publish refuses a local set; bad input answers with JSON |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 676 passed, 1 skipped (12 new), before the merge; after merging Coder 2 Sprints 1-14: all Estimator tests pass except the 2 OCR tests that need Tesseract (not in that container) |
| Windows 11, Python 3.11.8 (Jamie's PC) | All Estimator tests (Coder 1 + Coder 2) on top of Coder 2's latest (Sprint 14, the office role change and the docs status, 46242e7): 1280 passed, 14 skipped (the browser tests, run with `run_tests_estimator.bat browser`), 0 failed. The first run on Sprint 13 had 9 failures and 19 errors in Coder 2's room tests because shapely and ezdxf (in requirements.txt since Coder 2 Sprint 6) weren't installed on this PC; installed shapely 2.2.0 and ezdxf 1.4.5, then 1228 passed. Coder 2 pushed three more commits meanwhile; the commit was rebased each time (no conflicts) and run again: 1273, then 1280 passed |
| File check | Sent as a git bundle of the one commit on top of Coder 2's 0a8c7d3: sha256 2d57f0abffc7ab9cee039dac7b9fee4561062a144f8ecc37be9a239c3682d5d1 matched, `git bundle verify` OK, commit 21e18ee; then rebased on the PC onto 46242e7 |

## Manual check after deploying

Personal mode: upload a revised plan set as a revision of the first ("this replaces plan set 1"), have it read, and say "what changed in the new plans?". It should ask first, then list the changes and which measurements need re-measuring. Server mode needs the server and a second PC sharing a folder (set `ESTIMATOR_EXCHANGE_DIR` on both, and `ESTIMATOR_SERVER_USER` on the PC); that's part of the server beta.

## For David (Coder 2)

- Your engine runs on the processing PC exactly as in Personal mode; nothing changes in what it returns.
- The revision report's `sheets[].added_items` / `removed_items` / `moved_items` / `changed_items` carry `bbox` in sheet units (origin top-left) for the overlay; red for removed, green for added.
- If your engine makes sheet images, they travel to the server with the published results and become the server's sheet images.

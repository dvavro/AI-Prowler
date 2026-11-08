# Sprint 23 — Coder 1 (Jamie) test plan: reviews, highlighting and what is sent to the AI

**Scope:** The Coder 1 work from planned Sprint 8 (Phase 4, AI detection): the `review_*` tools with versioned reviews (the spec's "Visual verification of counts and detections"), quotes that wait for approved counts, and the privacy rules for sending plan crops to the AI provider. The symbol engine that finds symbols is Coder 2's (David); reviews of its detection sets plug in when it arrives.

## How to run

```
cd /d "C:\Users\jamie\Documents\AI-Prowler_V970_to_V1000\AI-Prowler"
run_tests_estimate.bat
deploy_to_install.bat
```
Then start AI-Prowler again. The database upgrades itself to version 13. There are 91 Estimator tools (8 new).

## What was built

**Reviews** (`estimator/takeoff/reviews.py`, migration v13 `reviews`). History is never rewritten:
- The first time a count or measurement is reviewed, its result is kept as **version 0 (original)**.
- `review_start` opens version 1. If a review is already open, it returns that one.
- Every `review_save` is a **new version**; the one before it is kept as superseded. A save can:
  - add missed items (drawing object ids)
  - remove false hits
  - relabel a wrong match (it leaves the count; `relabel_matching` does the same to every identical symbol in it)
  - correct an area or length by hand (`qty`; counts change only by adding or removing items)
- Nothing is priced until a person approves. Agents can open and save reviews, never approve.
- `review_approve` (a person, asks first) makes that version the number used for pricing. The measurement takes the approved quantity and items and is locked; relabels are applied to the plan's objects. An optional **second check** must be a different person.
- `review_history` shows every version with who changed what ("+1 added, −2 removed, 1 relabelled").
- Review status per count: unreviewed → in review → approved. `takeoff_list` now shows it per measurement.
- Schedule rows can be reviewed too (which door tags belong to mark D1).
- Detection sets say they wait for the symbol engine.

**Highlighting** (`review_highlight`). Every item behind a count, sheet by sheet, with its box on the sheet, numbered top to bottom for next/previous, plus a per-sheet breakdown ("E-101: 5"). Any earlier version can be shown, including the original.

**Quotes wait for approved counts** (`review_require_before_send`, owner, asks first, off by default). When it's on, `bid_send` refuses while any measurement on the estimate isn't approved, needs re-measuring, has a suggested change waiting, or has an open review. It lists what's left. `est_validate` also warns about open reviews.

**What is sent to the AI** (`estimator/drawing_model/crops.py`, `plan_get_crop`, `est_ai_privacy`):
- Only small crops: at most 15% of the sheet, scaled to 1024 px. Crops can go around a drawing object or an area of the sheet.
- A whole sheet only when a person asked the AI to look at it. An agent working on its own can never send one.
- Symbol-crop sending is **on by default**. The first crop returns a **one-time notice** explaining what is sent and leaves it in the owner's inbox.
- The owner can turn crop sending off (asks first). Then no crop is made at all.
- Every crop or sheet prepared for the AI is **logged** (`ai_send_log`): kind, sheet, area, size in pixels and bytes, fingerprint, why, provider and who asked. The image itself is kept in `projects\estimate_NNNN\ai_sent\`. `est_ai_privacy show_log=N` lists them.
- Owner, estimator, reviewer and office can prepare crops; field staff can't.

**Also:**
- The Takeoff agent's instructions now use measurements, reviews and crops.
- The plan engine's notes (`drawing_model/engine.py`) now say coordinates have their origin at the top-left like the sheet image, and that every image sent to an AI must go through `crops.prepare`.

## Test cases (tests/estimator/unit/test_sprint23_reviews.py)

Test drawing: sheet E-101 (36 x 24 in, with a rendered image) at 1/4" = 1'-0": 6 duplex outlets counted plus one missed, a GFI, three door tags (D1, D1, D2) and a door schedule, a 320 sq ft slab and a 128 sq ft porch.

| ID | Test | Checks |
|---|---|---|
| S23-R01 | Start | unreviewed before; version 0 kept at 6; version 1 open with 6 highlighted; "count" and "measurement" find the same review; starting again returns the open one; field refused; another company can't see it |
| S23-R02 | Save | an agent's save is version 2: 5 ("+1 added, −2 removed") with a note; the measurement still 6 (nothing priced); old version can't be saved; not-in-count, already-in, add and remove at once, empty, typed qty on a count, blank relabel, missing object and another estimate's object all refused; an item removed then put back isn't a change |
| S23-R03 | Relabel | one relabel leaves the count (5); relabel_matching relabels all six; relabelling an object not in the count refused |
| S23-A01 | Approve | agent and field refused; asks first with was 6 → now 4; approved by the reviewer; measurement 4, approved, locked, new items, review recorded in its calculation; relabel applied to the plan; can't approve twice; second check by the approver refused, by the owner accepted, not twice; the next review builds on it; events logged in order |
| S23-A02 | Area feeds pricing | slab + porch 448 → remove porch 320 → hand edit 330 → approved; the runner's roof area answer is 330; takeoff_list shows review status; an area can't be reviewed as a count |
| S23-H01 | History and highlight | approved version 2 at 5; summaries per version; 5 hits on E-101 numbered 1–5 with boxes; the sheet has an image; the original version shows 6; a missing version refused |
| S23-S01 | Schedule row | D1's tags reviewed: one removed, D2 added, approved; the schedule row's links change and it's marked reviewed by the reviewer |
| S23-D01 | Can't review | detection sets wait for the symbol engine; unknown type; missing schedule row; a rejected measurement |
| S23-V01 | Checks | est_validate warns about an open review |
| S23-B01 | Review before send | off by default (send asks as usual); estimator can't change it; the owner's change asks first; on: send refused naming the unapproved measurement, no email; approved: send asks as usual |
| S23-P01 | Crops | on by default; the first crop (around an object, by an agent, for claude_api) is a real file under ai_sent with the notice and one inbox message; second crop no notice; over 15% refused; purpose needed; whole sheet refused when nobody asked and for an agent; field refused; a person's whole sheet with user_asked is scaled; the log lists all three with who, provider, user_asked, fingerprint and size; field can't read the log |
| S23-P02 | Crop sending off | only the owner, asks first; off: crop refused, nothing logged, no file made; back on: works |
| S23-P03 | No image | a sheet without an image says so; another company can't; a backwards box refused; nothing logged |
| S23-T01 | Tools | the whole flow through the JSON tools (start, save with relabel, approve asks then approves, history, highlight now and original, the send setting, a crop with the notice, the privacy settings and log, turning off asks, an area crop); bad input answers with JSON |

## Results

| Run | Result |
|---|---|
| Linux, Python 3.13 | 664 passed, 1 skipped (14 new) |
| Windows 11, Python 3.11.8 (Jamie's PC) | 673 passed, 0 failed (2026-11-07) |
| File check | All 13 files match the tested copies (zip SHA-256 checked on the PC) |

## Manual check after deploying

In chat, on an estimate with plans read and a count measured: "Show me where the outlets are" (review_highlight). Then "Remove outlet 12 and add 31" (review_start, review_save): it should say the new number and that a person has to approve it. Say "approve it": it should ask first, then lock the count. Ask "What have you sent to the AI?" (est_ai_privacy show_log).

## For David (Coder 2)

- When your symbol engine looks at a doubtful symbol with the AI, get the image with `estimator.drawing_model.crops.prepare(conn, ctx, object_id=..., purpose=..., provider=...)`. It handles the size limit, the company's crop setting (it raises `NotAvailable` when sending is off, so leave the symbol for a person) and the one-time notice, and logs it. Don't read sheet images for the AI any other way.
- Coordinates: origin at the top-left of the sheet, the same way up as `image_path`.
- `reviews` already accepts `target_type="detection_set"` in the table; `reviews._target` raises `NotAvailable` for it until your `symbol_detections` table exists. That's the one place to connect it.

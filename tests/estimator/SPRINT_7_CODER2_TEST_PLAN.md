# Sprint 7 — Coder 2 (David) test plan: Blueprint Review v1

**Scope:** The Coder 2 Sprint 7 row is "Blueprint Review v1: tiled viewer, overlays, tool palette, layers, measurement list, detail panel, approve/correct". It's built as the **Takeoffs** screen and one project's **Blueprint Review** page in the web app, on top of Jamie's measurement service (`estimator/takeoff/measurements.py`, the `takeoff_*` tools). The page follows the same rules as chat:

- Only approved measurements are priced.
- Approved ones are locked.
- Agents never approve.
- Every change asks first and is logged.

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
deploy_to_install.bat                   then restart AI-Prowler
```
No new tools, tables or libraries.

## What was built

**Tiled viewer** (`estimator/plan_engine/tiles.py`; GET `/sheets/<id>/tiles/<level>/<x>/<y>.png`):
- **Tiles and levels.** Tiles are 512 px. Level 0 fits the whole sheet in one tile, and each level doubles it.
- **PDF sheets** render only the tile's part of the original page with pypdfium2, up to 300 DPI (level 4 on a 36″ sheet). Small text is sharp when zoomed in, unlike the 4000 px sheet image. The crop was checked against full renders, rotated pages included.
- **Images and DXF** are cut from their saved image.
- **Cache.** Tiles are kept in the data folder under `tiles/`, keyed by when the plans were read, so re-reading never shows old tiles. They're only served from the Estimator's data folder.
- **Shared pdfium lock.** pdfium isn't thread-safe, so `pdf_pages.PDFIUM_LOCK` is shared by plan reading (held per page) and tiles.
- GET `/sheets/<id>` now also returns `tiles` (zoom levels).

**Overlays and layers:**
- GET `/sheets/<id>/objects` returns up to 5,000 drawing objects with their shapes and a layer group (`plan_engine/layers.py`).
- **Groups:** Rooms, Walls, Doors & windows, Electrical, Plumbing, Mechanical, Furniture, Other symbols, Dimensions, Text and Floor plan line work, by kind and by CAD layer name (A-WALL, E-LITE, P-FIXT, I-FURN…).
- **Rooms** are shaded and labelled with their area. Walls are lines and symbols are dots.
- **Layers tab:** show/hide and lock each group (a locked group can't be clicked). The browser remembers the choice. Text, dimensions and line work are hidden at first, since the image already shows them.

**The page** (`estimator/ui/web/review.js`, loaded after app.js; `#/takeoffs` and `#/takeoffs/<estimate>?sheet=&m=`):
- **Takeoffs screen:** projects with plans or measurements, plans read, to review, approved.
- **Viewing:** sheet picker with previous/next. Wheel zoom on the cursor, drag to pan, pinch on touch, ＋/－/Fit/Zoom to selection/Full screen, and the keys + − 0 Esc Enter.
- **Tools:**
  - **Select:** click or Shift-click rooms, walls and symbols, then **Make a measurement from these…**. The size comes from the drawing, and the room fills in from the plan.
  - **Drawing tools:** **Length**, **Area**, **Rectangle**, **Count**. They show a live size and have Finish / Undo point. The server measures the shape with the view's scale when it's saved.
  - **Calibrate:** two clicks and a real length set the view's scale.
  - A view with no scale says "set the scale first".
- **Save form:**
  - Trade: the project's trades first, then all others.
  - The question it answers, guessed from the unit.
  - Label, room, and one measurement per item.
  - **Approve it now** (approvers only).
- **Measurements tab:**
  - Grouped by trade and room, with running totals and the totals priced from approved measurements.
  - Filters: To review / Approved / Rejected / All, and this sheet only.
  - **Review queue** puts the lowest confidence first.
  - Notes for suggestions waiting and for measurements that need measuring again.
  - **Approve all…** at or above 95/90/80/70%.
- **Detail tab:**
  - **What it shows:** quantity (with any suggestion), trade and question, status and lock, how it was worked out (and any correction), sheet, view and scale, method, confidence, who proposed and approved it, the drawing objects it came from, and its history.
  - **Actions:** **✓ Approve…**, **Correct…** (quantity, label, room), **Reject…** (with a reason), **Suggest a change…**, and **Accept the suggestion…**.
  - **Linking:** clicking a measurement on the plan or in the list highlights its shape or objects and zooms to it. Clicking an object a measurement uses opens that measurement.
- **Links:** the project page and the sheet page link to Blueprint Review.
- **Help:** a new guide, "Measure and approve on the plans".
- **Roles:**
  - Owner and estimator measure.
  - Owner, estimator and reviewer approve, correct and reject.
  - Office and field don't see Takeoffs.

**API** (`estimator/api/takeoff_api.py`):
- GET `/takeoffs`
- GET `/estimates/<id>/takeoff`
- POST `/estimates/<id>/measurements` (`takeoff_manual`)
- POST `/estimates/<id>/measurements/propose` (`takeoff_propose`, plus `takeoff_confirm` with approve)
- GET `/measurements/<id>` (`takeoff_detail`)
- POST `/measurements/approve` (`takeoff_confirm`)
- POST `/measurements/<id>/edit|reject|suggest`

All writes ask first.

## Test cases

`tests/estimator/webapp/test_web_sprint7.py`:

| ID | Test | Checks |
|---|---|---|
| C2S7-T01 | Tiles | PDF source, max level 4; 0/0/0 is 512×341; deep and edge tile sizes; cached |
| C2S7-T02 | Tile errors | wrong level/place 404; another company 404; office 403 |
| C2S7-O01 | Objects | room and wall with shapes, real size and group; layers panel; kind filter |
| C2S7-P01 | Screen and page | project listed; sheets; no trades → other trades with their questions; can_* |
| C2S7-M01 | From the drawing | asks first with 144.00 sqft; proposed, vector, 0.75, room; review queue; approve → locked, priced |
| C2S7-M02 | Approve in one step | question says so; approved; 16 ft wall |
| C2S7-M03 | Drawn | 2″ square = 64 sqft, polyline 5″ = 20 ft approved; shape comes back for drawing |
| C2S7-M04 | Typed | 1200 sqft, method typed |
| C2S7-M05 | No scale | refused with the reason |
| C2S7-A01 | Correct, suggest, accept, reject | person's correction on a locked one; suggestion waiting → accepted; rejected with reason; history |
| C2S7-A02 | Bulk approve | only those at or above the confidence; nothing to do → 400 |
| C2S7-D01 | Detail | calc, sheet, view scale 48, source object, proposer |
| C2S7-R01 | Roles | reviewer approves but can't measure; office/field 403; another company 404; CSRF |
| C2S7-B01 | Bad requests | ids not a list, booleans, no trade, long label, geometry not an object, unknown question, bad confidence |
| C2S7-W01 | Page | screen ready; page in nav; review.js after app.js; every call on the page; no innerHTML/style attributes; links |
| C2S7-W02 | Guide | every button the guide names is on the page |

`tests/estimator/plan_engine/test_plan_engine_sprint7.py`:

| ID | Test | Checks |
|---|---|---|
| C2S7-E01 | Grid | columns, rows, edge boxes, portrait |
| C2S7-E02 | PDF tiles | four level-1 tiles put together = the level-0 tile, normal and rotated pages |
| C2S7-E03 | Image tiles | cut from the saved image; no image → nothing |
| C2S7-E04 | Cache | new key after re-reading; bad levels/places refused |
| C2S7-E05 | Lock | reading a PDF while tiles render in another thread |
| C2S7-E06 | Layer groups | 17 kind/layer/block cases |
| C2S7-E07 | Panel | only groups present, Measurements first |

Changed: `test_web_parity.py` also counts screens and pages that a web script registers itself (`SCREENS.x =`, `PAGES.x =`). `test_web_router.py`'s "no internet" check allows the SVG namespace name.

## Results

| Run | Result |
|---|---|
| Windows 11, Python 3.11.8 (David's PC), Coder 2 track | 386 passed (2026-11-08) |
| Windows 11, Python 3.11.8, all Estimator tests | 1059 passed (2026-11-08) |
| Browser smoke test (headless Chromium, scratch `review_smoke.py`) | Takeoffs list → review page → tiles → KITCHEN 144 sq ft → measure from the room → ask → approve → locked → draw an 8 × 8 ft area (live "≈ 64 sq ft") → level-4 tiles on zoom → hide rooms → second sheet → review queue; no browser errors. It found that the detail panel didn't refresh after Approve (fixed). |

## Manual checks

| ID | Step | Expected | Result |
|---|---|---|---|
| M1 | Deploy, restart, open a project with read plans → **📏 Blueprint Review** | the sheet fills the viewer; Takeoffs is in the menu | |
| M2 | Zoom in on small text on a real PDF | sharp at full zoom; panning is smooth | |
| M3 | Click a room → Make a measurement from these… → Roofing (or Flooring) → Save… → Yes | the size matches the room; it shows in the list under its room | |
| M4 | Draw an area round a room you know | about the same as the plan's own area | |
| M5 | Approve, then Correct… the quantity, then Reject… | locked 🔒; the correction and rejection are in History | |
| M6 | Layers: hide Rooms, lock Walls; reload the page | still hidden/locked (this browser) | |
| M7 | A sheet with no scale → draw | "set the scale first"; 📐 Calibrate → then drawing works | |
| M8 | Sign in as reviewer (test session) | no drawing tools; can approve, correct and reject | |
| M9 | Jobs app (port 8000) → Estimates tab → Takeoffs | tiles load with the token sign-in | |
| M10 | Phone or tablet | pinch zoom and drag; the panel goes under the viewer | |

## Notes for Jamie

- **Layers table.** The spec's `layers` table (estimate_id, name, color, visible, locked, is_system) isn't in the migrations yet. For now the groups are worked out from the drawing and the browser keeps show/lock. Saved and user-made layers need the table: your call when.
- **Counts need a scale.** `measurements.manual` refuses a drawn count on an unscaled view, because `geometry.measure` returns None. A count doesn't need a scale; could points skip that check?
- **New routes, no service changes.** The web app calls your measurement service directly: no changes to it, no new tools.
- **Sheet sizes.** The router still reads sheet sizes with `store._load_sheet`.

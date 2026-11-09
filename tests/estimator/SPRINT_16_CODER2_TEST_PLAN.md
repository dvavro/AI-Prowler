# Sprint 16 — Coder 2 (David) test plan: scans and photos, DWG

**Scope:** The Coder 2 Sprint 16 row is "Raster pipeline for scans and photos ('needs review' handling); DWG via a user-installed converter (detection and guidance)". Spec: Blueprint processing stages 1 and 4 (raster: deskew, denoise, binarize, lines), Accuracy targets ("on scanned or photo plans the engine labels results as 'needs review' and never auto-confirms"), and Target hardware and third-party components (DWG converters are not bundled).

## How to run

```
run_tests_estimator.bat coder2          web app + plan engine
run_tests_estimator.bat                 every Estimator test
deploy_to_install.bat                   then restart AI-Prowler
```
- **No new database migration, tables, MCP tools or libraries** (numpy and scipy are already used for raster symbol matching; no OpenCV).
- **Plan engine 0.9.** Scans and photos read before this sprint must be read again (Plans screen) to get their walls, rooms and the straightened sheet image.
- **Two new files** (`plan_engine/raster.py`, `plan_engine/dwg.py`) are in `AI-Prowler-Setup.iss`.

## What was built

**Raster pipeline** (`plan_engine/raster.py`, used for images and for PDF pages with no text and under 20 pieces of line work):
- **Photos:** when a light page sits on a darker background, its four corners are found and the page is squared up (perspective). A picture is a photo when its EXIF names a camera, or it's a JPEG with no DPI; a photo's own DPI is ignored (150 assumed) and it always says to calibrate. When the page edges aren't found, the photo says it wasn't squared up.
- **Blueprints:** light lines on a dark sheet are inverted (noted).
- **Binarize and denoise:** Otsu's threshold (lifted halfway to the paper so shrunk thin lines stay), specks of 3 pixels or fewer dropped.
- **Deskew:** the projection-profile angle within ±5° (0.02° steps); 0.15° or more is turned back. The saved sheet image (also the review picture of a scanned PDF page) and the OCR words are the straightened ones, so every box lands on the drawing.
- **Lines:** horizontal and vertical runs of ink of 0.4" or more (at 100 px per inch) become line work in sheet inches; a filled wall (thicker than 0.06") gives both edges; anything thicker than 0.5" (a stamp, a logo) is left out. So walls, rooms (with OCR'd names), elevations and site objects are found on scans the same way as on PDFs.
- **Needs review:** every object from a scan or photo is source `raster` with confidence at most 0.5, and the sheet note says "scan or photo: everything found here is marked to check" (with what was done: straightened by n degrees, squared up, read inverted). Raster symbol hits were already always to check (Sprint 10).

**Model and measurements:**
- `building.plan_method`: `raster` when a plan set is an image or any of its objects are raster, `cad` when every set is DXF/DWG, else `vector`. The model, every trade's answers (`plan_trade_answers`) and the Plan quantities page carry `method` and `needs_review`, with the note "read from scanned or photographed plans: every quantity is marked to check…"; the page shows a **Needs review** badge.
- Jamie's `takeoff/from_plans.py` (change recorded in the spec): measurements proposed from raster plans have method `raster` and confidence 0.5 (on re-read too), and the ask says "from scanned or photographed plans: check each one before approving". DXF/DWG plans now give method `cad` (was always `vector`). As before, nothing is approved without a person.

**DWG** (`plan_engine/dwg.py`):
- **Finding a converter:** `ESTIMATOR_DWG_CONVERTER` (a path, or "off"), the ODA File Converter on the PATH or in `Program Files\ODA\ODAFileConverter*` (newest), then LibreDWG's `dwg2dxf`.
- **Converting:** ODA works on folders, so the DWG is copied into a folder of its own and converted to an ACAD2018 DXF in the plan set's `converted` folder; LibreDWG writes `dwg2dxf -y -o`. 5-minute limit, no console window. The DXF is read like any DXF and each sheet says "converted from DWG with the …". Failures say why (the converter's last error line, stopped after 5 minutes, couldn't be started) and to save as DXF instead.
- **No converter:** reading says how to get the free ODA File Converter, or to save as DXF or PDF. The upload warning (Jamie's `uploads.py`) only appears when no converter is installed, and the Estimator tab's CAD and tools line (Jamie's `ui/model.tool_status`) uses the same search, so LibreDWG counts too.

**Guides:** "Upload plans and check the scale" (scans, photos, DWG) and "Plan quantities" (the Needs review badge).

## Automated tests

`tests/estimator/plan_engine/test_plan_engine_sprint16.py` (a scanned floor plan drawn at 150 DPI: two rooms in double-line walls 1/8" apart, 2..10 x 2..7 in with a wall at 6 in, a notes column of text):

| ID | Test | Checks |
| --- | --- | --- |
| C2S16-R01 | test_ink_and_a_blank_page | A blank page has no ink; a plan has a little; Otsu between paper and ink |
| C2S16-R02 | test_specks_are_dropped_and_lines_kept | Specks gone, the line kept |
| C2S16-R03 | test_skew_is_found_and_straightened (2.5°, -1.2°, 4°) | Angle within 0.15°; the top wall back at y = 2 in |
| C2S16-R04 | test_a_straight_scan_is_left_alone | No turn, no notes |
| C2S16-L01 | test_double_line_walls_become_line_work_and_text_doesnt | Both lines of each wall; nothing from the notes column |
| C2S16-L02 | test_a_filled_wall_gives_both_its_edges | Two edges 1/8" apart |
| C2S16-L03 | test_a_solid_block_is_not_line_work | A 3 x 2 in stamp gives nothing |
| C2S16-P01 | test_a_photographed_page_is_squared_up | Corners found; squared up to within 5% of the page; the long walls straight |
| C2S16-P02 | test_a_scan_that_fills_the_picture_isnt_cropped | No page edges on a scan; a photo without them says so |
| C2S16-P03 | test_a_blueprint_is_read_inverted | Inverted, lines found, light paper |
| C2S16-P04 | test_raster_confidence_is_capped | 0.5 at most |
| C2S16-E01 | test_a_scanned_image_gives_walls_marked_to_check | 4+ walls, all raster ≤ 0.5, the sheet note (no OCR) |
| C2S16-E02 | test_a_tilted_scan_is_saved_straight | "straightened by 3.0 degrees"; the saved image is straight; same size |
| C2S16-E03 | test_a_phone_photo_is_squared_up_and_says_so | JPEG with a camera in EXIF: squared up, "a photo has no true size", walls |
| C2S16-E04 | test_a_scan_saved_as_pdf_is_straightened_and_traced | Scanned PDF: straightened, raster walls, the review picture straightened |
| C2S16-E05 | test_a_vector_pdf_without_text_isnt_taken_for_a_scan | Line work only: not a scan |
| C2S16-E06 | test_a_scanned_plan_with_names_gives_rooms_to_check (needs Tesseract) | KITCHEN and LIVING rooms from a tilted scan, raster ≤ 0.5 |
| C2S16-N01 | test_plans_from_a_scan_are_marked_needs_review | Model method raster + note; electrical (symbols) and framing answers too; every saved object raster |
| C2S16-N02 | test_vector_and_cad_plans_are_not | PDF → vector, DXF → cad, no note |
| C2S16-N03 | test_measurements_from_a_scan_say_raster_and_ask_to_check | The ask says to check; method raster, confidence 0.5, proposed; still raster on re-read |
| C2S16-D01 | test_finding_a_converter | ODA first, LibreDWG, none; the setting wins; "off" |
| C2S16-D02 | test_a_dwg_is_converted_and_read (ODA, LibreDWG) | Converted (stand-in converter), read as DXF, sheet note, converted_with |
| C2S16-D03 | test_a_dwg_the_converter_cant_read | The converter's error line in the message |
| C2S16-D04 | test_a_converter_that_hangs_or_wont_start | Stopped after the limit; couldn't be started |
| C2S16-D05 | test_without_a_converter_the_plans_say_how_to_get_one | ODA guidance and "save the drawing as DXF"; the upload warning |
| C2S16-D06 | test_upload_and_tab_follow_the_converter | No upload warning when installed; the tab finds LibreDWG |

Also updated: Sprint 5's DWG test sets `ESTIMATOR_DWG_CONVERTER=off` (so it passes on a PC with ODA installed).

## Manual checks (Tester 2)

| # | Check | Expected |
| --- | --- | --- |
| M1 | Upload a real scanned floor plan (TIFF or PDF scan) and read it | Sheet note says scan or photo (and straightened if it was tilted); walls and named rooms appear in Blueprint Review; Plan quantities shows **Needs review** |
| M2 | Calibrate the scan's scale from a known dimension | Walls and rooms measured; the numbers are close to the plan's own dimensions (spec target: flagged for review, not ±2%) |
| M3 | Take a phone photo of a printed sheet on a dark desk and upload it | Squared up in the sheet image; note says to calibrate |
| M4 | A blueprint scan (white on blue) | Read inverted; the sheet image is dark-on-light |
| M5 | Propose measurements from a scan (chat: takeoff_propose) | The ask says to check each one; in Blueprint Review the measurements show method raster |
| M6 | Without the ODA File Converter: upload a DWG and read it | Upload warns; reading fails with the ODA download guidance; Estimator tab, CAD and tools shows "Not installed" |
| M7 | Install the free ODA File Converter, restart AI-Prowler, read the DWG again | Tab shows it found; the sheets read like the DXF of the same drawing; note "converted from DWG with the ODA File Converter" |
| M8 | Re-read a scan read before this sprint | Its walls and the needs-review notes appear |

## Known limits

- Only horizontal and vertical lines are traced on scans; slanted walls, curves (arcs, door swings) and dashed lines (fences) aren't, so rooms with slanted walls aren't closed. Draw them in Blueprint Review.
- Room names, scale notes, schedules and tags on scans need Tesseract (OCR). Without it, walls are found but rooms aren't.
- Squaring up a photo needs the whole page on a darker background; a curled or folded page, or one cut off by the frame, isn't squared up (noted). A photo always needs calibrating.
- The DWG converter isn't run in the automated tests (a stand-in writes the DXF); M6–M7 check the real ODA File Converter.

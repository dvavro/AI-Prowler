# E2E test drawings — Smith Residence, sheet A-101 (First Floor Plan)

Real drawings the Estimator E2E GUI tests upload and take off — no agent API key
needed, the plan engine reads them deterministically. Regenerate with
`coder2_scratch/make_fixtures.py` (uses the plan-engine test builders
`tests/estimator/plan_engine/pdfmaker.py` + `test_plan_engine_sprint10.py`).

## The plan

40 ft x 28 ft house, 1/4" = 1'-0" (1 paper inch = 4 ft), 5 rooms, 8 walls
(6" walls = parallel line pairs 0.125" apart), 4 duplex receptacles + legend,
40'-0" / 28'-0" dimensions, north arrow, title block A-101.

| Room | Nominal size | Nominal area |
| --- | --- | --- |
| LIVING | 24 x 18 ft | 432 sqft |
| KITCHEN | 16 x 18 ft | 288 sqft |
| BED 1 | 20 x 10 ft | 200 sqft |
| BED 2 | 10 x 10 ft | 100 sqft |
| BATH | 10 x 10 ft | 100 sqft |
| **Total** | 40 x 28 ft | **1120 sqft** |

Walls: exterior 136 ft + interior 78 ft = **214 ft** centreline.

## Files

- `smith_residence_A101_revA.pdf` — Rev A. Sheet A-101, scale detected
  `1/4" = 1'-0"`.
- `smith_residence_A101_revB.pdf` — Rev B. Bed 2/Bath partition moved 1 ft
  (Bed 2 10 ft -> 9 ft wide, Bath 10 ft -> 11 ft), "REV B - DELTA 1" note, and a
  flag symbol on the moved wall labelled "REVISION CLOUD" by the legend — that
  symbol is the revision mark the overlay draws.
- `smith_residence_A101.dxf` — Rev A as DXF, real feet (`$INSUNITS` = 2),
  layers A-WALL / A-AREA / A-ANNO-TEXT / A-DIMS / A-TTL. No "REV: A" text in
  the title block on purpose: DXF text objects are stored, so it would match
  REV_MARK and report a phantom revision mark.
- `smith_residence_A101_scan.png` — Rev A rendered to raster, 7200x4800 px
  (200 dpi), for the scans/photo path (OCR).

## Verified takeoff (real web path: upload -> process -> sheet "found", 2026-11-09)

### Rev A PDF

- rooms: count 5, measured 5, **area 1048.25 sqft**
- walls: count 28, measured 28, **length 434.00 ft**
- symbols: count 4, measured 4
- dimensions: count 2, measured 2, length 40.00 ft
- revision marks: none

### Rev B PDF

- rooms: count 5, measured 5, **area 1048.17 sqft**
- walls: count 28, measured 28, **length 434.00 ft**
- symbols: count 5, measured 5 (the 5th is the REVISION CLOUD flag)
- dimensions: count 2, measured 2, length 40.00 ft
- revision marks: **1** — symbol "REV REVISION CLOUD"

### Rev A DXF

- rooms: count 5, measured 5, **area 1120.00 sqft**
- walls: count 8, measured 8, **length 214.00 ft**
- texts: 11; polygons: 5, area 1120.00; lines: 16, length 428.00 ft
- revision marks: none
- Sheet title comes from the filename ("3 smith residence A101", sheet_no
  empty) — the DXF reader does not pick the title block up as a sheet number.

## Why the PDF and DXF numbers differ

- PDF rooms measure to the **inner face** of the 6" walls, so the PDF room
  total is 1048.25, not the nominal 1120. The DXF rooms are the full polygons,
  so the DXF total is exactly 1120.00.
- PDF walls are split into 28 segments at junctions (length 434.00 ft = both
  lines of each pair plus small fragments); the DXF groups each pair into one
  wall (8 walls, 214.00 ft centreline).
- Assert the numbers above per format — they are deterministic for these files.

## Two things that were tried and dropped

- A scalloped revision-cloud polyline around the moved wall: its short
  segments got absorbed into the room polygons and corrupted the Rev B room
  areas (total fell 36 sqft). The flag symbol + legend is the mark instead.
- A "REV: A" text in the DXF title block: it matched REV_MARK by itself.

## designscad_25x25_2bhk.dwg
Free 25' x 25' 2BHK ground-floor plan from designscad.com
(https://designscad.com/downloads/25-x-25-small-2bhk-residential-ground-floor-plan/,
$0.00, English, Imperial). Real-world DWG used by the deep-zoom drag
regression test: its sheet is 219,791 units wide while the plan is 300,
and a drag across its ENTRY label selects the label text. Reading it
needs the ODA File Converter installed (the test skips without it).

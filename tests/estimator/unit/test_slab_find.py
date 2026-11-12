"""Concrete auto-run Phase 1: slab rectangles from line geometry (pure geometry, no LLM, no cost)."""
import json

import pytest

from estimator.context import personal_context
from estimator.errors import NotFound
from estimator.takeoff import slab_find

NOW = "2026-11-12T10:00:00+00:00"
PAPER_W = 547 / 84.3225      # 45'-7" at the live slab's scale (the plan's ~6.49" is 45'-7 1/2")
PAPER_H = 559 / 84.3225      # 46'-7"


def _line(oid, x1, y1, x2, y2, kind="wall"):
    return {"id": oid, "kind": kind,
            "geometry": {"type": "line", "points": [[x1, y1], [x2, y2]]}}


def _rect(oid, x1, y1, x2, y2, kind="wall"):
    """Four lines closing a rectangle (counter-clockwise from the top-left)."""
    return [_line(oid, x1, y1, x2, y1, kind), _line(oid + 1, x2, y1, x2, y2, kind),
            _line(oid + 2, x2, y2, x1, y2, kind), _line(oid + 3, x1, y2, x1, y1, kind)]


# ---------------------------------------------------------------- find_rectangles

def test_exact_rectangle_found_with_corners_and_size():                                   # AR-S01
    got = slab_find.find_rectangles(_rect(1, 0, 0, 6, 4))
    assert len(got) == 1
    r = got[0]
    assert r["corners"] == [[0, 0], [6, 0], [6, 4], [0, 4]]
    assert r["object_ids"] == [1, 2, 3, 4]
    assert (r["width"], r["height"], r["area"], r["perimeter"]) == (6, 4, 24, 20)


def test_split_collinear_segments_still_close():                                          # AR-S02
    objs = [_line(1, 0, 0, 3, 0), _line(2, 3.05, 0, 6, 0),        # top, split with a small gap
            _line(3, 6, 0, 6, 4), _line(4, 6, 4, 0, 4), _line(5, 0, 4, 0, 0)]
    got = slab_find.find_rectangles(objs)
    assert len(got) == 1 and got[0]["object_ids"] == [1, 2, 3, 4, 5]
    assert got[0]["area"] == 24


def test_near_axis_lines_count_diagonals_do_not():                                        # AR-S03
    tilted = [_line(1, 0, 0, 6, 0.1), _line(2, 6, 0, 6, 4),       # top tilted ~1 degree
              _line(3, 6, 4, 0, 4), _line(4, 0, 4, 0, 0)]
    assert len(slab_find.find_rectangles(tilted)) == 1
    diagonal = [_line(1, 0, 0, 6, 6), _line(2, 6, 6, 6, 0),
                _line(3, 6, 0, 0, 0), _line(4, 0, 0, 0, 6)]
    assert slab_find.find_rectangles(diagonal) == []              # the 45-degree side breaks it


def test_polyline_sides_and_line_kind():                                                  # AR-S04
    objs = [{"id": 1, "kind": "polyline",
             "geometry": {"type": "polyline", "points": [[0, 0], [6, 0], [6, 4]]}},
            _line(2, 6, 4, 0, 4, kind="line"), _line(3, 0, 4, 0, 0, kind="line")]
    got = slab_find.find_rectangles(objs)
    assert len(got) == 1 and got[0]["object_ids"] == [1, 2, 3]


def test_largest_first_and_nested_rectangles():                                           # AR-S05
    objs = _rect(1, 0, 0, 10, 8) + _rect(10, 2, 2, 6, 5)
    got = slab_find.find_rectangles(objs)
    assert [r["area"] for r in got] == [80, 12]


def test_no_rectangle_returns_empty_not_an_error():                                       # AR-S06
    assert slab_find.find_rectangles(_rect(1, 0, 0, 6, 4)[:3]) == []   # three sides don't close
    assert slab_find.find_rectangles([_line(1, 0, 0, 6, 0), _line(2, 0, 4, 6, 4)]) == []
    assert slab_find.find_rectangles([]) == []
    assert slab_find.find_rectangles([{"id": 1, "kind": "room",
                                       "geometry": {"type": "polygon",
                                                    "points": [[0, 0], [6, 0], [6, 4], [0, 4]]}}]) == []


def test_other_kinds_ignored_but_text_and_symbols_do_not_break_it():                      # AR-S07
    objs = _rect(1, 0, 0, 6, 4) + [{"id": 9, "kind": "text",
                                    "geometry": {"type": "line", "points": [[0, 0], [6, 0]]}},
                                   {"id": 10, "kind": "dimension",
                                    "geometry": {"type": "line", "points": [[0, 0], [6, 0]]}}]
    got = slab_find.find_rectangles(objs)
    assert len(got) == 1 and got[0]["object_ids"] == [1, 2, 3, 4]


# ---------------------------------------------------------------- label parsing

@pytest.mark.parametrize("label,inches", [("45'-7\"", 547.0), ("12'", 144.0), ("6\"", 6.0),
                                          ("18'-3 1/2\"", 219.5), ("7 1/2\"", 7.5),
                                          ("45'7\"", 547.0), ("45'-7", 547.0)])
def test_parse_feet_inches(label, inches):                                                # AR-S08
    assert slab_find.parse_feet_inches(label) == inches


@pytest.mark.parametrize("label", ["", "KITCHEN", "45", "12 ft", None, 42, "0'", "3'-x\""])
def test_parse_feet_inches_rejects_non_lengths(label):                                    # AR-S09
    assert slab_find.parse_feet_inches(label) is None


@pytest.mark.parametrize("feet,label", [(45.5833, "45'-7\""), (46.0, "46'"), (7.5, "7'-6\""),
                                        (0.625, "0'-7 1/2\"")])
def test_format_feet_inches(feet, label):                                                 # AR-S10
    assert slab_find.format_feet_inches(feet) == label


# ---------------------------------------------------------------- calibration dimensions

def test_calibration_dimension_matches_width_and_reads_label():                           # AR-S11
    rect = slab_find.find_rectangles(_rect(1, 0, 0, 6.49, 6.63))[0]
    objs = [{"id": 9, "kind": "dimension", "label": "45'-7\"",
             "geometry": {"type": "line", "points": [[0, 8], [6.49, 8]]}}]
    got = slab_find.find_calibration_dimension(objs, rect)
    assert got == {"points": [[0, 8], [6.49, 8]], "label": "45'-7\"", "real_inches": 547.0}


def test_calibration_dimension_no_match_returns_none():                                   # AR-S12
    rect = slab_find.find_rectangles(_rect(1, 0, 0, 6.49, 6.63))[0]
    assert slab_find.find_calibration_dimension([], rect) is None
    wrong_length = [{"id": 9, "kind": "dimension", "label": "12'",
                     "geometry": {"type": "line", "points": [[0, 8], [3.0, 8]]}}]
    assert slab_find.find_calibration_dimension(wrong_length, rect) is None
    no_label = [{"id": 9, "kind": "dimension", "label": "SECTION A",
                 "geometry": {"type": "line", "points": [[0, 8], [6.49, 8]]}}]
    assert slab_find.find_calibration_dimension(no_label, rect) is None


# ---------------------------------------------------------------- from the database

def _viewport(db, scale_ratio="84.3225", is_nts=0):
    """An estimate with one sheet and one viewport, returning (estimate_id, sheet_id, viewport_id)."""
    ctx = personal_context()
    est = db.execute("INSERT INTO estimates (company_id, title, status, created_at, updated_at)"
                     " VALUES (?, 'Shed', 'draft', ?, ?)",
                     (ctx.company_id, NOW, NOW)).lastrowid
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES (?, ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (ctx.company_id, est, NOW)).lastrowid
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no)"
                       " VALUES (?, ?, 1, 'A-101')", (ctx.company_id, ps)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES (?, ?, 'Foundation plan', ?, ?)",
                    (ctx.company_id, sheet, scale_ratio, is_nts)).lastrowid
    return est, sheet, vp


def _store(db, viewport_id, sheet_id, objs):
    for o in objs:
        db.execute("INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json,"
                   " label, source) VALUES ('default', ?, ?, ?, ?, ?, 'cad')",
                   (sheet_id, viewport_id, o["kind"], json.dumps(o["geometry"]), o.get("label")))


def test_slab_candidates_from_db_in_feet(db):                                             # AR-S13
    est, sheet, vp = _viewport(db)
    _store(db, vp, sheet, _rect(1, 0, 0, PAPER_W, PAPER_H))
    got = slab_find.find_slab_candidates(db, "default", vp)
    assert got["viewport_id"] == vp and got["calibrated"] is True
    assert got["scale_ratio"] == 84.3225
    assert len(got["candidates"]) == 1
    c = got["candidates"][0]
    assert c["id"] == "c1" and c["label"] == "45'-7\" x 46'-7\""
    assert abs(c["area_sqft"] - PAPER_W * PAPER_H * (84.3225 / 12) ** 2) < 0.01
    assert abs(c["perimeter_lf"] - (2 * (PAPER_W + PAPER_H)) * 84.3225 / 12) < 0.01
    assert c["object_ids"] == [1, 2, 3, 4] and c["width"] == PAPER_W


def test_slab_candidates_unscaled_viewport_has_paper_units_only(db):                     # AR-S14
    est, sheet, vp = _viewport(db, scale_ratio=None, is_nts=1)
    _store(db, vp, sheet, _rect(1, 0, 0, PAPER_W, PAPER_H))
    got = slab_find.find_slab_candidates(db, "default", vp)
    assert got["calibrated"] is False and got["scale_ratio"] is None
    c = got["candidates"][0]
    assert c["width_ft"] is None and c["area_sqft"] is None and c["label"] is None
    assert c["width"] == PAPER_W and c["area"] == pytest.approx(PAPER_W * PAPER_H)


def test_slab_candidates_empty_and_missing_viewport(db):                                  # AR-S15
    est, sheet, vp = _viewport(db)
    assert slab_find.find_slab_candidates(db, "default", vp)["candidates"] == []
    with pytest.raises(NotFound):
        slab_find.find_slab_candidates(db, "default", 9999)

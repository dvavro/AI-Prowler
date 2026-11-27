"""AI Auto Measure/Count's measurements on the drawing, and areas a person adds or takes away (2026-11-16, David).

"Is it possible that when you click on the equations to compute the volume say of the footer or the base or the slab
area ... it would select it and highlight the area in the drawing" - and "I want the user to be able to add area to be
included in the calculation, for example the sloped edge ... by adding three points" - "the user should be able to
subtract area that wasn't accounted for by the AI as well."

The plan here is David's NSB shed: a 45'-7" x 46'-7" slab whose drawing has only its bottom and right edges as lines
(each broken in two), at the calibrated scale; and a footer detail drawn "not to scale" beside it.
"""
import json
from decimal import Decimal

import pytest

from estimator.api import autorun_api
from estimator.context import personal_context
from estimator.estimating import service
from estimator.takeoff import footer_section as fs
from estimator.takeoff import takeoff_shapes as ts

API = "/estimator-api"
CTX = personal_context()
NOW = "2026-11-16T10:00:00+00:00"
RATIO = 83.1838                                   # the plan's calibrated scale (real in per paper in)
W, H = 547 / RATIO, 559 / RATIO                   # 45'-7" across, 46'-7" up, on the paper
X1, Y1 = 14.3125, 10.1438                         # the drawn right and bottom edges (as on David's sheet)


def _line(db, sheet, vp, a, b, kind="wall"):
    db.execute("INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json, source)"
               " VALUES ('default', ?, ?, ?, ?, 'vector')", (sheet, vp, kind, json.dumps({"type": "line", "points": [a, b]})))


@pytest.fixture
def shed(db):
    est = service.create_estimate(db, CTX, "NSB Shed slab")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                    " sha256, status, uploaded_by, created_at) VALUES ('default', ?, 'x.pdf', 'x.pdf', 'pdf', 1, 'aa',"
                    " 'processed', 'owner', ?)", (est, NOW)).lastrowid
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                       " VALUES ('default', ?, 1, 'S-1', 'FOUNDATION PLAN')", (ps,)).lastrowid
    plan = db.execute("INSERT INTO viewports (company_id, sheet_id, label, bbox_json, scale_ratio, is_nts)"
                      " VALUES ('default', ?, 'FOUNDATION PLAN SCALE :', '[7.567, 2.873, 14.568, 10.75]', ?, 0)",
                      (sheet, str(RATIO))).lastrowid
    detail = db.execute("INSERT INTO viewports (company_id, sheet_id, label, bbox_json, scale_ratio, scale_note, is_nts)"
                        " VALUES ('default', ?, '12\"X20\" MONO. FOOTER BASE RAIL ANCHORAGE', '[3.65, 0.25, 7.994, 5.09]',"
                        " NULL, 'NTS', 1)", (sheet,)).lastrowid
    # The plan's own lines: the bottom and the right edge, each broken by a gap - nothing on the top or left.
    _line(db, sheet, plan, [7.7692, Y1], [10.9108, Y1])
    _line(db, sheet, plan, [11.2642, Y1], [14.2542, Y1])
    _line(db, sheet, plan, [X1, 3.4642], [X1, 6.5317])
    _line(db, sheet, plan, [X1, 6.8858], [X1, 10.1042])
    _line(db, sheet, plan, [7.77, 10.104], [14.25, 10.104], kind="dimension")      # a dimension line is not an edge
    return {"est": est, "sheet": sheet, "plan": plan, "detail": detail}


def _finished_run(db, seed):
    """A finished AI run: slab, footer, footer cross-section and forms, the footer as read off David's detail."""
    run = autorun_api.create_run(db, CTX, seed["est"], seed["sheet"], seed["plan"], "concrete", [])
    read = {"detail_found": True, "outside_face": ['3-1/2"', '6-1/2"', '12"'], "slab_thickness": '4"', "footer_width": '12"'}
    calc = {"source": "llm", "auto_run_id": run, "candidate_id": "llm", "slab_width": "45'-7\"",
            "slab_length": "46'-7\"", "footer_size": "12x20", "perimeter_lf": "184.33", "area_read": "2123.42",
            "footer_section": fs.from_read(read, "12x20")}
    ids = []
    for feeds, kind, label, qty, unit in (("area_sqft", "area", "Slab (AI)", "2123.42", "sqft"),
                                          ("footing_lf", "length", "Footer (AI)", "180.33", "lf"),
                                          ("footing_section_sqft", "area", "Footer cross-section (AI)", "1.5000", "sqft/lf"),
                                          ("perimeter_lf", "perimeter", "Forms (AI)", "184.33", "lf")):
        ids.append(db.execute(
            "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label,"
            " qty, unit, source_object_ids, calc_json, method, status, proposed_by, created_at, updated_at)"
            " VALUES ('default', ?, 'concrete', ?, ?, ?, ?, ?, ?, ?, '[]', ?, 'ai', 'proposed', 'llm-takeoff', ?, ?)",
            (seed["est"], feeds, seed["sheet"], seed["plan"], kind, label, qty, unit, json.dumps(calc), NOW, NOW)).lastrowid)
    autorun_api.update_run(db, run, status="done", step="done", measurement_ids=ids)
    return run, ids


def _concrete(call, run):
    return call("GET", f"{API}/auto-run/{run}").json()["run"]["results"]["concrete"]


# ---------------------------------------------------------------- placing the slab on the drawing

def test_the_slab_is_placed_on_the_plans_own_edges(db, shed):
    fit = ts.fit_slab(db, "default", shed["plan"], 547, 559)
    assert fit["ok"] and fit["sides"] == ["bottom", "right"]
    (x0, y0), (x1, _), (_, y1), _ = fit["points"]
    assert (x1, y1) == (X1, Y1)                                    # anchored on the drawn right and bottom edges
    assert x1 - x0 == pytest.approx(W, abs=1e-3) and y1 - y0 == pytest.approx(H, abs=1e-3)
    assert 40 <= fit["cover_pct"] <= 55                            # about half the outline is drawn


def test_the_slab_turned_the_other_way_is_still_found(db, shed):
    """The width may run up the sheet: 46'-7" read first, 45'-7" second - the same outline is found."""
    fit = ts.fit_slab(db, "default", shed["plan"], 559, 547)
    assert fit["ok"] and fit["points"][2] == [X1, Y1]
    assert fit["points"][1][0] - fit["points"][0][0] == pytest.approx(W, abs=1e-3)


def test_no_outline_is_guessed_when_the_edges_dont_line_up(db, shed):
    assert not ts.fit_slab(db, "default", shed["plan"], 300, 300)["ok"]          # a 25 ft slab: no edges that long
    db.execute("UPDATE viewports SET scale_ratio = NULL, is_nts = 1 WHERE id = ?", (shed["plan"],))
    out = ts.fit_slab(db, "default", shed["plan"], 547, 559)
    assert not out["ok"] and "no scale" in out["reason"]


def test_footer_band_and_middle_line_sit_inside_the_slab():
    pts = [[0, 0], [10, 0], [10, 8], [0, 8]]
    band = ts.footer_band(pts, 12, 12)                              # a 12 in footer at 12 real in per paper in = 1 paper in
    assert band["type"] == "polygon" and band["points"][:5] == [*pts, pts[0]]
    assert band["points"][5:] == [[1, 1], [1, 7], [9, 7], [9, 1], [1, 1]]      # the inner ring, the other way round
    assert ts.footer_middle(pts, 12, 12)["points"][0] == [0.5, 0.5]
    assert ts.area_sqin([[0, 0], [1, 0], [0, 1]], 12) == pytest.approx(72)     # 1/2 sq paper in x 12 x 12


def test_points_must_make_a_shape():
    for bad in (None, [[0, 0], [1, 1]], [[0, 0], [1, 1], [2, 2]], [["a", 0], [1, 0], [0, 1]]):
        with pytest.raises(ValueError):
            ts.clean_points(bad)


# ---------------------------------------------------------------- formulas -> shapes

def test_each_formula_lists_what_it_highlights(call, db, shed):
    run, _ = _finished_run(db, shed)
    c = _concrete(call, run)
    assert c["slab_fit"]["ok"] and c["total_cuyd"] == "36.24"
    sh = c["shapes"]
    assert sh["slab"]["points"][2] == [X1, Y1] and sh["slab"]["type"] == "polygon"
    assert sh["forms"]["type"] == "polyline" and sh["forms"]["points"][0] == sh["forms"]["points"][-1]
    assert sh["footer"]["type"] == "polygon" and len(sh["footer"]["points"]) == 10
    assert sh["detail"]["viewport_id"] == shed["detail"] and sh["detail"]["points"][0] == [3.65, 0.25]
    steps = {s["what"]: s["shapes"] for s in c["steps"]}
    assert steps["Slab area"] == ["slab"] and steps["Slab perimeter"] == ["forms"]
    assert steps["Footer depth below the slab"] == ["detail"] and steps["Footer cross-section"] == ["detail"]
    assert steps["Footer length (middle line)"] == ["footer_middle", "footer"]
    assert steps["Footer concrete"] == ["footer"] and steps["Total concrete"] == ["slab", "footer"]
    assert c["detail"] == {"viewport_id": shed["detail"], "sheet_id": shed["sheet"],
                           "label": '12"X20" MONO. FOOTER BASE RAIL ANCHORAGE', "scaled": False, "scale_ratio": None,
                           "placed": False, "anchor": None, "calibration": None}


def test_a_plan_without_matching_edges_says_why_and_keeps_the_numbers(call, db, shed):
    db.execute("DELETE FROM drawing_objects WHERE viewport_id = ?", (shed["plan"],))
    run, _ = _finished_run(db, shed)
    c = _concrete(call, run)
    assert not c["slab_fit"]["ok"] and "no drawn edges" in c["slab_fit"]["reason"]
    assert "slab" not in c["shapes"] and c["total_cuyd"] == "36.24"
    assert {s["what"]: s["shapes"] for s in c["steps"]}["Slab area"] == []


# ---------------------------------------------------------------- adding and taking away areas

TRIANGLE = [[4.5, 3.0], [5.5, 3.0], [4.5, 4.0]]                    # half a square paper inch, on the detail
SQUARE = [[9.0, 5.0], [9.5, 5.0], [9.5, 5.5], [9.0, 5.5]]          # a quarter square paper inch, on the plan


def test_a_detail_with_no_scale_says_so(call, db, shed):
    run, _ = _finished_run(db, shed)
    r = call("POST", f"{API}/auto-run/{run}/adjust", {"target": "footer", "sign": "add", "points": TRIANGLE,
                                                      "viewport_id": shed["detail"], "label": "sloped edge"})
    assert r.status == 400 and "has no scale yet" in r.json()["message"] and "calibrate it" in r.json()["message"]


def test_add_the_sloped_edge_to_the_footer_section_then_remove_it(call, db, shed):
    run, ids = _finished_run(db, shed)
    db.execute("UPDATE viewports SET scale_ratio = '12', is_nts = 0 WHERE id = ?", (shed["detail"],))
    body = {"target": "footer", "sign": "add", "points": TRIANGLE, "viewport_id": shed["detail"], "label": "sloped edge"}
    ask = call("POST", f"{API}/auto-run/{run}/adjust", body).json()
    # 1/2 sq paper in x 12 x 12 = 72 sq in; 12 x 18 + 72 = 288 sq in; 180.33 x 288 / 144 / 27 = 13.36 cu yd
    assert ask["needs_confirmation"] and "Add 72.00 sq in (sloped edge) to the footer cross-section" in ask["question"]
    assert "= 288 sq in" in ask["question"] and "13.36 cu yd" in ask["question"]
    assert db.execute("SELECT qty FROM measurements WHERE id = ?", (ids[2],)).fetchone()[0] == "1.5000"   # nothing yet
    c = call("POST", f"{API}/auto-run/{run}/adjust", {**body, "confirm": True}).json()["results"]["concrete"]
    assert c["footer_section_sqin"] == "288" and c["footer_cuyd"] == "13.36" and c["total_cuyd"] == "39.58"
    steps = {s["what"]: s for s in c["steps"]}
    assert steps["Footer cross-section"]["formula"] == "12 in x 18 in + 72.00 sq in (sloped edge)"
    assert steps["Footer cross-section"]["shapes"] == ["detail", "adj:a1"]
    assert c["shapes"]["adj:a1"]["points"] == TRIANGLE and c["shapes"]["adj:a1"]["sign"] == 1
    assert c["drawn_areas"] == [{"id": "a1", "key": "adj:a1", "target": "footer", "sign": 1, "label": "sloped edge",
                                 "view": '12"X20" MONO. FOOTER BASE RAIL ANCHORAGE', "amount": "72.00 sq in"}]
    assert db.execute("SELECT qty FROM measurements WHERE id = ?", (ids[2],)).fetchone()[0] == "2.0000"   # priced from it
    assert db.execute("SELECT qty FROM measurements WHERE id = ?", (ids[1],)).fetchone()[0] == "180.33"   # length as was
    # A correction to the section keeps the drawn area.
    c2 = call("POST", f"{API}/auto-run/{run}/footer", {"section": {"ledge_w_in": 4, "ledge_d_in": 2},
                                                       "confirm": True}).json()["results"]["concrete"]
    assert c2["footer_section_sqin"] == "280"                          # 216 - 8 + 72
    # Removing it asks first, then puts the section back.
    rm = call("POST", f"{API}/auto-run/{run}/adjust", {"remove": "a1"}).json()
    assert "Remove 72.00 sq in (sloped edge) from the footer cross-section" in rm["question"]
    c3 = call("POST", f"{API}/auto-run/{run}/adjust", {"remove": "a1", "confirm": True}).json()["results"]["concrete"]
    assert c3["footer_section_sqin"] == "208" and c3["drawn_areas"] == []
    log = db.execute("SELECT action FROM estimate_events WHERE action IN ('area_adjusted', 'area_removed') ORDER BY id").fetchall()
    assert [r[0] for r in log] == ["area_adjusted", "area_removed"]


def test_take_away_slab_area_drawn_on_the_plan(call, db, shed):
    run, ids = _finished_run(db, shed)
    body = {"target": "slab", "sign": "subtract", "points": SQUARE, "viewport_id": shed["plan"], "label": "column pocket"}
    sqft = (Decimal("0.25") * Decimal(str(RATIO)) ** 2 / 144).quantize(Decimal("0.01"))          # 12.01 sq ft
    ask = call("POST", f"{API}/auto-run/{run}/adjust", body).json()
    assert f"Take away {sqft} sq ft (column pocket) from the slab area" in ask["question"]
    c = call("POST", f"{API}/auto-run/{run}/adjust", {**body, "confirm": True}).json()["results"]["concrete"]
    left = Decimal("2123.42") - sqft
    assert db.execute("SELECT qty FROM measurements WHERE id = ?", (ids[0],)).fetchone()[0] == str(left)
    steps = {s["what"]: s for s in c["steps"]}
    assert steps["Slab area"]["formula"] == f"45'-7\" x 46'-7\" (2,123.42 sq ft) - {sqft} sq ft (column pocket)"
    assert steps["Slab area"]["result"] == f"{left:,} sq ft" and steps["Slab area"]["shapes"] == ["slab", "adj:a1"]
    assert c["shapes"]["adj:a1"]["sign"] == -1
    # Another area is numbered after it; the slab's own reading is kept as the base.
    c2 = call("POST", f"{API}/auto-run/{run}/adjust", {**body, "sign": "add", "label": "porch", "confirm": True}).json()
    assert [a["id"] for a in c2["results"]["concrete"]["drawn_areas"]] == ["a1", "a2"]
    assert db.execute("SELECT qty FROM measurements WHERE id = ?", (ids[0],)).fetchone()[0] == "2123.42"


def test_approved_measurements_are_never_changed(call, db, shed):
    run, ids = _finished_run(db, shed)
    db.execute("UPDATE measurements SET status = 'approved', locked = 1 WHERE id = ?", (ids[0],))
    r = call("POST", f"{API}/auto-run/{run}/adjust", {"target": "slab", "sign": "add", "points": SQUARE,
                                                      "viewport_id": shed["plan"], "confirm": True})
    assert r.status == 400 and "approved and locked" in r.json()["message"]


def test_bad_requests_are_refused(call, db, shed):
    run, _ = _finished_run(db, shed)
    base = {"target": "slab", "sign": "add", "points": SQUARE, "viewport_id": shed["plan"]}
    for change, words in (({"target": "roof"}, "target must be"), ({"sign": "maybe"}, "sign must be"),
                          ({"points": SQUARE[:2]}, "at least 3 points"), ({"viewport_id": 99999}, "inside a view"),
                          ({"sign": "subtract", "points": [[7.6, 2.9], [14.5, 2.9], [14.5, 10.7], [7.6, 10.7]]},
                           "no slab area")):                    # 53.8 sq paper in = 2,586 sq ft, more than the slab
        r = call("POST", f"{API}/auto-run/{run}/adjust", {**base, **change, "confirm": True})
        assert r.status == 400 and words in r.json()["message"], change
    assert call("POST", f"{API}/auto-run/{run}/adjust", {"remove": "a9"}).status == 400


def test_the_section_is_placed_on_its_detail_and_its_parts_drawn_to_scale(call, db, shed):
    """David's detail, calibrated by hand at 1 paper in = 12 real in: one click on the footer's bottom outside corner
    puts the parts the cross-section is worked out from on the drawing."""
    run, ids = _finished_run(db, shed)
    # Not placed yet: the cross-section points at the detail's frame; the detail has no scale.
    c0 = _concrete(call, run)
    assert c0["detail"]["scaled"] is False and c0["detail"]["placed"] is False
    assert {s["what"]: s["shapes"] for s in c0["steps"]}["Footer cross-section"] == ["detail"]
    db.execute("UPDATE viewports SET scale_ratio = '12', is_nts = 0 WHERE id = ?", (shed["detail"],))
    db.execute("UPDATE measurements SET calc_json = json_set(calc_json, '$.footer_section.ledge_w_in', 4,"
               " '$.footer_section.ledge_d_in', 2) WHERE id IN (?, ?, ?, ?)", ids)
    r = call("POST", f"{API}/auto-run/{run}/section-place", {"viewport_id": shed["detail"], "point": [4.7, 4.2], "dir": 1})
    c = r.json()["results"]["concrete"]
    assert c["detail"]["placed"] and c["detail"]["scale_ratio"] == 12.0
    sh = c["shapes"]
    # 12 in wide = 1 paper in to the right; 18 in below the slab = 1.5 paper in up; the slab's 4 in above it.
    assert sh["part:below"]["points"] == [[4.7, 4.2], [5.7, 4.2], [5.7, 2.7], [4.7, 2.7]]
    assert sh["part:below"]["label"] == "12 x 18 = 216 sq in"
    assert sh["part:slab"]["points"][2] == [5.7, round(4.2 - 22 / 12, 4)] and sh["part:slab"]["part"] == "slab"
    assert sh["part:ledge"]["points"] == [[4.7, round(4.2 - 20 / 12, 4)], [round(4.7 + 4 / 12, 4), round(4.2 - 20 / 12, 4)],
                                          [round(4.7 + 4 / 12, 4), round(4.2 - 22 / 12, 4)], [4.7, round(4.2 - 22 / 12, 4)]]
    assert sh["part:ledge"]["sign"] == -1 and "haunch" not in " ".join(sh)
    steps = {s["what"]: s["shapes"] for s in c["steps"]}
    assert steps["Footer cross-section"] == ["part:below", "part:slab", "part:ledge"]
    assert steps["Footer depth below the slab"] == ["part:below", "part:slab"]
    # The inside the other way: the parts go to the left; quantities never change.
    c2 = call("POST", f"{API}/auto-run/{run}/section-place", {"viewport_id": shed["detail"], "point": [4.7, 4.2],
                                                              "dir": -1}).json()["results"]["concrete"]
    assert c2["shapes"]["part:below"]["points"][1] == [3.7, 4.2] and c2["total_cuyd"] == c["total_cuyd"]
    # A correction to the section keeps where it sits, and the parts follow the new numbers.
    c3 = call("POST", f"{API}/auto-run/{run}/footer", {"section": {"width_in": 18}, "confirm": True}).json()["results"]["concrete"]
    assert c3["detail"]["placed"] and c3["shapes"]["part:below"]["label"] == "18 x 18 = 324 sq in"
    # Placing it on another project's view is refused; clearing it takes it off.
    assert call("POST", f"{API}/auto-run/{run}/section-place", {"viewport_id": 99999, "point": [1, 1]}).status == 400
    c4 = call("POST", f"{API}/auto-run/{run}/section-place", {"clear": True}).json()["results"]["concrete"]
    assert not c4["detail"]["placed"] and "part:below" not in c4["shapes"]


def test_a_detail_the_calibrator_gave_up_on_says_why(call, db, shed):
    run, _ = _finished_run(db, shed)
    db.execute("UPDATE viewports SET calibration_json = ? WHERE id = ?", (json.dumps(
        {"status": "manual_required", "reason": "the written dimensions don't agree on one scale"}), shed["detail"]))
    det = _concrete(call, run)["detail"]
    assert det["calibration"] == {"status": "manual_required", "reason": "the written dimensions don't agree on one scale"}


def test_footer_section_maths_with_drawn_areas():
    sec = {"outside_in": 22, "slab_in": 4, "width_in": 12, "adjust": [
        {"id": "a1", "sign": 1, "sqin": "18.50", "label": "sloped edge"},
        {"id": "a2", "sign": -1, "sqin": "6.00", "label": "conduit"}]}
    w = fs.compute(sec, "184.33")
    assert w["section_sqin"] == "228.5"                                # 216 + 18.5 - 6
    assert w["steps"][1]["formula"] == "12 in x 18 in + 18.50 sq in (sloped edge) - 6.00 sq in (conduit)"
    assert "plus the area(s) drawn" in w["steps"][1]["note"] and "less the area(s) drawn" in w["steps"][1]["note"]
    assert fs.edit(sec, {"outside_in": 20})["adjust"] == sec["adjust"]

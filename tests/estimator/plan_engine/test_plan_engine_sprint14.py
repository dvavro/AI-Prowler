"""Coder 2 Sprint 14: exterior elevations (the outside wall and its openings, for siding and exterior paint), door and
window schedule linking (windows and doors by size and type, for the windows and doors trade) and the HVAC symbol
library (registers, returns, thermostats, mini-split heads and the system)."""
import json

import pytest

from estimator.building import model as building
from estimator.building import trades
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator.plan_engine import elevations as elev
from estimator.plan_engine import legends
from estimator.plan_engine import symbol_library as lib
from estimator.symbols import review
from estimator.symbols import service as sym

from pdfmaker import make_pdf, title_block
from test_plan_engine_sprint10 import legend, plan, shape
from test_plan_engine_sprint12 import HOUSE, NAMES, SCHEDULES, TAGS, page

CTX = personal_context()
QUARTER = 'SCALE: 1/4" = 1\'-0"'


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def rect(x0, y0, x1, y1):
    return [(x0, y0, x1, y0), (x1, y0, x1, y1), (x1, y1, x0, y1), (x0, y1, x0, y0)]


def front(x=5.0, floor=10.0, wide=10.0, plate_mark=True, title="NORTH ELEVATION", stories=1):
    """A house front at 1/4" = 1'-0": a 40 ft x 9 ft wall (10" x 2.25") with a 6 ft gable above, lap siding courses,
    two 3 x 5 ft windows with a mullion each, a 3 x 6'-8" door, and the plate and floor level marks. stories=2: an
    18 ft wall with a plate mark at each floor."""
    plate = floor - 2.25 * stories
    lines = rect(x, plate, x + wide, floor) + [(x, plate, x + wide / 2, plate - 1.5), (x + wide / 2, plate - 1.5, x + wide, plate)]
    plate_low = floor - 2.25
    if stories == 2:
        lines.append((x + wide, plate_low, x + wide + 1.5, plate_low))
    lines += [(x, plate + 0.125 * i, x + wide, plate + 0.125 * i) for i in range(1, 4)]          # siding courses (6")
    for wx in (x + 1.5, x + 7.0):                                                              # windows
        lines += rect(wx, plate + 0.5, wx + 0.75, plate + 1.75) + [(wx + 0.375, plate + 0.5, wx + 0.375, plate + 1.75)]
    lines += rect(x + 4.5, floor - 1.667, x + 5.25, floor)                                     # door
    lines += [(x + wide, floor, x + wide + 1.5, floor), (x - 1, floor, x, floor)]              # grade line
    texts = [(x + 3, floor + 0.8, 14, title), (x + 3, floor + 1.15, 9, QUARTER), (x + wide + 0.2, floor - 0.05, 7, "FIN. FLR")]
    if plate_mark:
        lines.append((x + wide, plate, x + wide + 1.5, plate))
        texts.append((x + wide + 0.2, plate - 0.05, 7, "T.O. PLATE"))
        if stories == 2:
            texts.append((x + wide + 0.2, plate_low - 0.05, 7, "T.O. PLATE"))
    return lines, texts


SIDES = ("NORTH ELEVATION", "SOUTH ELEVATION", "EAST ELEVATION", "WEST ELEVATION")


def four_sides():
    """All four sides on one sheet, two rows of two (views are split halfway between their titles, so each view's
    level marks stay on its own side of the split)."""
    return elev_page([front(x=1, floor=9, title=SIDES[0]), front(x=16, floor=9, title=SIDES[1]),
                      front(x=1, floor=19, title=SIDES[2]), front(x=16, floor=19, title=SIDES[3])])


# A door and window schedule with types and quantities: D1 entry (outside wall), D2 bedroom (2 in the schedule, 1 on
# the plan), D3 sliding glass door (not tagged), W1 4 x 3 ft, W2 5 x 4 ft (not tagged).
LINKED = [(20, 2.0, 12, "DOOR SCHEDULE"), (20, 2.5, 8, "MARK"), (21.5, 2.5, 8, "SIZE"), (23, 2.5, 8, "TYPE"), (25.5, 2.5, 8, "QTY"),
          (20, 2.8, 8, "D1"), (21.5, 2.8, 8, "3070"), (23, 2.8, 8, "EXTERIOR"), (25.5, 2.8, 8, "1"),
          (20, 3.1, 8, "D2"), (21.5, 3.1, 8, "2868"), (23, 3.1, 8, "INTERIOR"), (25.5, 3.1, 8, "2"),
          (20, 3.4, 8, "D3"), (21.5, 3.4, 8, "6068"), (23, 3.4, 8, "SLIDING GLASS"), (25.5, 3.4, 8, "1"),
          (20, 5.0, 12, "WINDOW SCHEDULE"), (20, 5.5, 8, "MARK"), (21.5, 5.5, 8, "WIDTH"), (23, 5.5, 8, "HEIGHT"),
          (20, 5.8, 8, "W1"), (21.5, 5.8, 8, '4\'-0"'), (23, 5.8, 8, '3\'-0"'),
          (20, 6.1, 8, "W2"), (21.5, 6.1, 8, '5\'-0"'), (23, 6.1, 8, '4\'-0"')]


def elev_page(views, sheet_no="A-201", title="EXTERIOR ELEVATIONS"):
    lines, texts = [], []
    for ls, ts in views:
        lines += ls
        texts += ts
    return {"w": 36, "h": 24, "texts": title_block(sheet_no, title) + texts, "lines": lines}


def read(db, tmp_path, pages, title="Smith house", name="house.pdf"):
    est = service.create_estimate(db, CTX, title)
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / name, pages)), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    return est["id"], ps


def objects(db, ps, kind=None):
    sql = ("SELECT o.* FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id WHERE s.plan_set_id = ?" +
           (" AND o.kind = ?" if kind else ""))
    return [dict(r) for r in db.execute(sql, (ps, kind) if kind else (ps,))]


# ---------------------------------------------------------------- elevations                      C2S14-E01..E04

@pytest.mark.parametrize("label, yes", [("NORTH ELEVATION", True), ("Front Elevation", True), ("EXTERIOR ELEVATIONS", True),
                                        ("KITCHEN ELEVATION", False), ("INTERIOR ELEVATION A", False), ("FLOOR PLAN", False),
                                        ("BUILDING SECTION", False), (None, False)])
def test_which_views_are_exterior_elevations(label, yes):                       # C2S14-E01
    assert elev.is_exterior_elevation(label) is yes


def test_the_wall_and_its_openings_from_an_elevation(db, tmp_path):            # C2S14-E02
    _eid, ps = read(db, tmp_path, [elev_page([front()])])
    walls = [o for o in objects(db, ps, "polygon") if o["layer"] == "ELEVATION-WALL"]
    assert len(walls) == 1 and walls[0]["label"] == "NORTH ELEVATION wall · 1 story"
    real = json.loads(walls[0]["real_units_json"])
    assert float(real["area_sqft"]) == pytest.approx(360, abs=2)                  # 40 x 9 ft: the gable is left out
    ops = sorted((o["label"], round(float(json.loads(o["real_units_json"])["area_sqft"]))) for o in objects(db, ps, "opening"))
    assert ops == [("door", 20), ("window", 15), ("window", 15)]                  # a window and its mullion are one
    assert not objects(db, ps, "wall") and not objects(db, ps, "room")           # siding lines aren't walls


def test_without_a_plate_line_the_gable_is_in_and_it_says_so(db, tmp_path):    # C2S14-E03
    eid, ps = read(db, tmp_path, [elev_page([front(plate_mark=False)])])
    wall = next(o for o in objects(db, ps, "polygon") if o["layer"] == "ELEVATION-WALL")
    assert float(json.loads(wall["real_units_json"])["area_sqft"]) == pytest.approx(480, abs=3)   # 360 + the 120 gable
    m = building.build(db, CTX, estimate_id=eid)
    assert any("may include the roof" in n for n in m["notes"]) or wall["confidence"] == "0.4"
    two = read(db, tmp_path, [elev_page([front(stories=2)])], title="Two story", name="two.pdf")[1]
    label = next(o for o in objects(db, two, "polygon") if o["layer"] == "ELEVATION-WALL")["label"]
    assert label.endswith("2 stories")


def test_four_sides_give_siding_and_exterior_paint(db, tmp_path):               # C2S14-E04
    eid, _ = read(db, tmp_path, [page(NAMES + SCHEDULES + TAGS, HOUSE), four_sides()])
    m = building.build(db, CTX, estimate_id=eid)
    assert sorted(e["view"] for e in m["elevations"]) == sorted(SIDES)
    t = m["totals"]
    assert (t["elevations"], t["elevation_openings"]) == (4, 12)
    assert t["elevation_wall_sqft"] == pytest.approx(1440, abs=8) and t["elevation_net_sqft"] == pytest.approx(1240, abs=8)
    siding = building.answers_for(m, "siding")["answers"]
    assert siding["wall_sqft"] == t["elevation_wall_sqft"] and siding["openings"] == 12 and siding["stories"] == "one"
    assert (siding["outside_corners"], siding["inside_corners"], siding["walls"]) == (4, 0, "simple")   # a plain box
    assert building.answers_for(m, "painting")["answers"]["exterior_sqft"] == t["elevation_net_sqft"]
    assert len(m["rooms"]) == 2 and m["totals"]["floor_sqft"] == 234.0             # elevations don't change the rooms


def test_a_view_cut_off_at_its_edge_counts_no_wall(db, tmp_path):              # C2S14-E06
    # The drawing runs into the title block strip, so the view's box cuts the outline: only the door is closed. That
    # must not be counted as the wall.
    _eid, ps = read(db, tmp_path, [elev_page([front(x=21)])])
    assert not [o for o in objects(db, ps, "polygon") if o["layer"] == "ELEVATION-WALL"]
    notes = json.loads(db.execute("SELECT notes_json FROM sheets s WHERE s.plan_set_id = ?", (ps,)).fetchone()[0] or "[]") \
        if "notes_json" in [c[1] for c in db.execute("PRAGMA table_info(sheets)")] else None
    assert notes is None or any("no wall outline found" in n for n in notes)


def test_fewer_sides_fall_back_to_the_floor_plan(db, tmp_path):                 # C2S14-E05
    eid, _ = read(db, tmp_path, [page(NAMES + SCHEDULES + TAGS, HOUSE), elev_page([front()])])
    m = building.build(db, CTX, estimate_id=eid)
    t = m["totals"]
    assert t["elevations"] == 1 and any("only 1 exterior elevation" in n for n in m["notes"])
    siding = building.answers_for(m, "siding")
    assert siding["answers"]["wall_sqft"] == round(t["exterior_wall_sqft"] + t["exterior_openings_sqft"], 1)
    assert "floor plans" in siding["from"]["wall_sqft"]
    assert building.answers_for(m, "painting")["answers"]["exterior_sqft"] == t["exterior_wall_sqft"]


# ---------------------------------------------------------------- door and window schedule linking   C2S14-W01..W02

def test_doors_and_windows_by_kind_from_the_linked_schedule(db, tmp_path):     # C2S14-W01
    eid, _ = read(db, tmp_path, [page(NAMES + LINKED + TAGS, HOUSE)])
    m = building.build(db, CTX, estimate_id=eid)
    marks = {k["mark"]: k for k in m["schedule_marks"]}
    assert (marks["D1"]["on_plans"], marks["D1"]["type"], marks["D1"]["width_ft"]) == (1, "EXTERIOR", 3.0)
    assert (marks["D2"]["on_plans"], marks["D2"]["schedule_qty"]) == (1, 2)
    assert marks["D3"]["on_plans"] == 0 and marks["W2"]["on_plans"] == 0
    assert any("D3 (1 in the schedule)" in n and "W2" in n for n in m["notes"])
    assert any(n.startswith("D2: 1 tagged on the plans but 2 in the schedule") for n in m["notes"])
    wd = building.answers_for(m, "windows_doors")["answers"]
    assert wd == {"windows_small": 1, "exterior_doors": 1, "interior_doors": 1}      # W1 is 12 sq ft


@pytest.mark.parametrize("op, want", [
    ({"type": "SLIDING GLASS", "mark": "D3", "width_ft": 6, "wall_type": "exterior"}, "patio_doors"),
    ({"type": "FRENCH", "mark": "D4", "width_ft": 5, "wall_type": None}, "patio_doors"),
    ({"type": "OVERHEAD", "mark": "D5", "width_ft": 16, "wall_type": "exterior"}, "garage_doors"),
    ({"type": None, "mark": "D6", "width_ft": 9, "wall_type": "exterior"}, "garage_doors"),
    ({"type": "EXT. ENTRY", "mark": "D7", "width_ft": 3, "wall_type": None}, "exterior_doors"),
    ({"type": None, "mark": "D8", "width_ft": 2.67, "wall_type": "interior"}, "interior_doors"),
    ({"type": None, "mark": "D9", "width_ft": 6, "wall_type": "exterior"}, "patio_doors")])
def test_which_door_is_which(op, want):                                          # C2S14-W02
    assert building._door_class(op) == want


# ---------------------------------------------------------------- HVAC                             C2S14-H01..H04

@pytest.mark.parametrize("words, item", [
    ("Linear slot diffuser", "linear_diffuser"), ("Ceiling supply diffuser", "supply_diffuser"),
    ("Floor register", "floor_register"), ("Return air grille", "return_grille"), ("Transfer grille", "transfer_grille"),
    ("Thermostat", "thermostat"), ("Ductless mini-split indoor unit", "mini_split_head"), ("Heat pump", "heat_pump"),
    ("Condensing unit", "condensing_unit"), ("Air handler", "air_handler"), ("Gas furnace", "furnace"),
    ("Rooftop unit", "package_unit"), ("Duct smoke detector", "duct_smoke_detector"), ("Smoke detector", "smoke_detector"),
    ("Range hood", "range_hood"), ("Bath exhaust fan", "exhaust_fan"), ("Ceiling fan", "ceiling_fan"),
    ("Dryer vent", "dryer_vent")])
def test_legend_words_name_the_hvac_symbols(words, item):                       # C2S14-H01
    assert legends.item_type(words)[0] == item


def test_the_hvac_library():                                                      # C2S14-H02
    assert lib.VERSION >= 3 and lib.module_of_trade("mechanical") == "hvac" and lib.module_of_trade("plumbing") == "plumbing"
    assert lib.feeds_of("mini_split_head") == [("hvac", "zones"), ("hvac", "system", "mini_split")]
    assert lib.feeds_of("supply_diffuser") == [("hvac", "registers")] and lib.feeds_of("air_handler") == []
    assert lib.by_alias("AHU")["item_type"] == "air_handler" and lib.by_block_name("M-MINISPLIT")["item_type"] == "mini_split_head"
    assert lib.BY_TYPE["condensing_unit"]["trade"] == "mechanical"


def test_hvac_answers_from_symbols_and_the_rooms(db, tmp_path):                # C2S14-H03
    lt, ll = legend([("recept", None, "SUPPLY DIFFUSER"), ("tri", None, "RETURN AIR GRILLE"), ("flag", None, "THERMOSTAT"),
                     ("quad", None, "DUCTLESS MINI-SPLIT INDOOR UNIT")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("tri", 12, 5) + \
        shape("flag", 14, 5) + shape("quad", 16, 5) + shape("quad", 18, 5)
    eid, ps = read(db, tmp_path, [plan(lt, lines), page(NAMES, HOUSE, sheet_no="A-101")], title="HVAC job", name="m.pdf")
    dets = sym.detections_list(db, CTX, plan_set_id=ps)["detections"]
    review.review(db, CTX, [d["id"] for d in dets if d["item_type"]], "approve", confirm=True)
    h = trades.answers(db, CTX, "hvac", estimate_id=eid)
    assert h["answers"] == {"conditioned_sqft": 234.0, "registers": 3, "returns": 1, "thermostats": 1, "zones": 2,
                            "system": "mini_split"}
    assert h["source"] == "wall-and-room model and symbols counted on the plans" and "1 thermostat" in h["from"]["thermostats"]


def test_garages_and_porches_arent_heated_or_cooled(db, tmp_path):             # C2S14-H04
    names = [(5.8, 6.5, 10, "LIVING"), (8.3, 6.5, 10, "GARAGE")]
    eid, _ = read(db, tmp_path, [page(names, HOUSE)])
    out = building.answers_for(building.build(db, CTX, estimate_id=eid), "hvac")
    assert out["answers"] == {"conditioned_sqft": 120.0} and any("114 sq ft of garages" in n for n in out["notes"])


# ---------------------------------------------------------------- every trade fits its module      C2S14-T01

def test_every_model_trade_fits_its_module(db, tmp_path):                       # C2S14-T01
    from estimator.modules import get_registry
    reg = get_registry()
    eid, _ = read(db, tmp_path, [page(NAMES + LINKED + TAGS, HOUSE), four_sides()])
    out = trades.all_answers(db, CTX, estimate_id=eid)
    assert set(out["trades"]) == set(trades.TRADES) and {"windows_doors", "siding", "hvac"} <= set(trades.TRADES)
    for t, a in out["trades"].items():
        qs = {q.id: q for q in reg.get(t).questions}
        assert set(a["answers"]) <= set(qs), t
        for k, v in a["answers"].items():
            if qs[k].type == "choice":
                assert v in {c["value"] if isinstance(c, dict) else c.value for c in qs[k].choices}, (t, k, v)
    keys = {out["trades"][t]["model_key"] for t in building.MODEL_TRADES}
    assert len(keys) == 1                                                       # one model behind every trade

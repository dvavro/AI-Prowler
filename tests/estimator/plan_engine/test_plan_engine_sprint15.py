"""Coder 2 Sprint 15: site-plan zones for fencing and landscaping - lawn, rock, mulch, pavers and planting beds from the
site and landscape plans, fence lines and gates, the plant schedule and the landscape symbol library, and the fencing
and landscaping trades' answers from them."""
import json
import math

import pytest

from estimator.building import model as building
from estimator.building import trades
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator.plan_engine import legends
from estimator.plan_engine import site
from estimator.plan_engine import symbol_library as lib
from estimator.takeoff import from_plans

from pdfmaker import make_pdf, title_block

CTX = personal_context()
EIGHTH = 'SCALE: 1/8" = 1\'-0"'                 # 1 paper inch = 8 ft


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def rect(x0, y0, x1, y1):
    return [(x0, y0, x1, y0), (x1, y0, x1, y1), (x1, y1, x0, y1), (x0, y1, x0, y0)]


def dashed(x0, y0, x1, y1, dash=0.5, gap=0.08):
    """A dashed line (how a fence is drawn): dashes of `dash` with `gap` between, paper inches."""
    L = math.hypot(x1 - x0, y1 - y0)
    ux, uy = (x1 - x0) / L, (y1 - y0) / L
    out, t = [], 0.0
    while t < L - 1e-9:
        e = min(t + dash, L)
        out.append((x0 + ux * t, y0 + uy * t, x0 + ux * e, y0 + uy * e))
        t = e + gap
    return out


def hatch45(x0, y0, x1, y1, step=0.25):
    """45-degree hatching inside a rectangle (how rock is drawn)."""
    out = []
    c = x0 - (y1 - y0)
    while c < x1:
        pts = []
        for x in (x0, x1):                                  # y = x - c on the box edges
            y = x - c
            if y0 <= y <= y1:
                pts.append((x, y))
        for y in (y0, y1):
            x = y + c
            if x0 <= x <= x1:
                pts.append((x, y))
        pts = sorted(set((round(px, 4), round(py, 4)) for px, py in pts))
        if len(pts) >= 2 and pts[0] != pts[-1]:
            out.append((pts[0][0] + 0.02, pts[0][1] + 0.02, pts[-1][0] - 0.02, pts[-1][1] - 0.02))
        c += step
    return out


# The yard at 1/8" = 1'-0": a 96 x 80 ft lot (2,3)-(14,13); a 40 x 32 ft house (5,5)-(10,9); a 16 x 16 ft paver patio
# against it (10,6)-(12,8); a 32 x 16 ft rock bed in the corner (2,11)-(6,13), hatched; the rest lawn:
# 7680 - 1280 - 256 - 512 = 5632 sq ft. A dashed 6 ft wood fence 0.25" inside the back and right lot lines:
# 11.5" + 2.75" = 114 ft. A walk gate, a double drive gate and a plant schedule.
LOT = rect(2, 3, 14, 13)
HOUSE = rect(5, 5, 10, 9)
PATIO = [(10, 6, 12, 6), (12, 6, 12, 8), (12, 8, 10, 8)]
ROCK = [(2, 11, 6, 11), (6, 11, 6, 13)]
FENCE = dashed(2.25, 3.25, 13.75, 3.25) + dashed(13.75, 3.25, 13.75, 6.0)
SOD = (3.0, 4.2, 9, "BERMUDA SOD")
YARD_TEXTS = [SOD, (2.4, 12.2, 7, '3/4" RIVER ROCK 3" DEEP'), (10.4, 7.1, 8, "PAVERS"),
              (6.0, 3.35, 7, "6' WOOD PRIVACY FENCE"), (8.5, 3.85, 7, "4' GATE"), (11.0, 5.2, 7, "12' DOUBLE DRIVE GATE"),
              (6.5, 7.0, 10, "HOUSE")]
PLANTS = [(20, 3.0, 12, "PLANT SCHEDULE"), (20, 3.5, 8, "SYM"), (21.2, 3.5, 8, "QTY"), (22.4, 3.5, 8, "COMMON NAME"),
          (25.5, 3.5, 8, "SIZE"),
          (20, 3.8, 8, "T1"), (21.2, 3.8, 8, "3"), (22.4, 3.8, 8, "LIVE OAK"), (25.5, 3.8, 8, '2" CAL'),
          (20, 4.1, 8, "P1"), (21.2, 4.1, 8, "2"), (22.4, 4.1, 8, "SABAL PALM"), (25.5, 4.1, 8, "12' CT"),
          (20, 4.4, 8, "S1"), (21.2, 4.4, 8, "14"), (22.4, 4.4, 8, "DWARF YAUPON"), (25.5, 4.4, 8, "3 GAL"),
          (20, 4.7, 8, "G1"), (21.2, 4.7, 8, "60"), (22.4, 4.7, 8, "LIRIOPE"), (25.5, 4.7, 8, "1 GAL FLATS")]


def yard(title="LANDSCAPE PLAN", sheet_no="L-101", sheet_title="LANDSCAPE PLAN", texts=None, lines=None, hatch=True,
         fence=True, schedule=True, scale=EIGHTH):
    ls = LOT + HOUSE + PATIO + ROCK + (hatch45(2, 11, 6, 13) if hatch else []) + (FENCE if fence else []) + (lines or [])
    ts = list(YARD_TEXTS if texts is None else texts) + [(5.0, 14.2, 14, title)] + ([(5.0, 14.55, 9, scale)] if scale else [])
    if not fence:
        ts = [t for t in ts if "FENCE" not in t[3] and "GATE" not in t[3]]
    if schedule:
        ts += PLANTS
    return {"w": 36, "h": 24, "texts": title_block(sheet_no, sheet_title) + ts, "lines": ls}


def read(db, tmp_path, pages, title="Lopez yard", name="yard.pdf"):
    est = service.create_estimate(db, CTX, title)
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / name, pages)), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    return est["id"], ps


def objects(db, ps, layer=None, kind=None):
    sql = "SELECT o.* FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id WHERE s.plan_set_id = ?"
    args = [ps]
    if layer:
        sql += " AND o.layer = ?"
        args.append(layer)
    if kind:
        sql += " AND o.kind = ?"
        args.append(kind)
    out = [dict(r) for r in db.execute(sql, args)]
    for o in out:
        o["real"] = json.loads(o["real_units_json"]) if o["real_units_json"] else {}
    return out


def zones(db, ps):
    return {o["label"].split(" · ")[0]: round(float(o["real"]["area_sqft"])) for o in objects(db, ps, "SITE-ZONE")}


# ---------------------------------------------------------------- words                            C2S15-W01..W03

@pytest.mark.parametrize("label, discipline, yes", [
    ("SITE PLAN", "architectural", True), ("Landscape Plan", None, True), ("PLANTING PLAN", None, True),
    ("IRRIGATION PLAN", "landscape", True), ("FENCE PLAN", None, True), ("FLOOR PLAN", "landscape", True),
    ("FLOOR PLAN", "architectural", False), ("PLANTING DETAIL", "landscape", False), ("FENCE ELEVATION", "site", False),
    ("PLANT SCHEDULE", "landscape", False), (None, "site", True), (None, "architectural", False)])
def test_which_views_are_site_plans(label, discipline, yes):                  # C2S15-W01
    assert site.is_site_view(label, discipline) is yes


@pytest.mark.parametrize("text, kind", [
    ("BERMUDA SOD", "sod"), ("NEW LAWN", "sod"), ("ST. AUGUSTINE", "sod"), ("TURF", "sod"),
    ("ARTIFICIAL TURF", "turf"), ("SYNTHETIC GRASS", "turf"), ('3/4" RIVER ROCK 3" DEEP', "rock"),
    ("DECOMPOSED GRANITE", "rock"), ("D.G. PATH", "rock"), ("STONE MULCH", "rock"), ("PINE STRAW", "mulch"),
    ("SHREDDED BARK MULCH", "mulch"), ("CONCRETE PAVERS", "pavers"), ("PLANTING BED", "bed"), ("GROUNDCOVER", "bed"),
    ("6' WOOD FENCE", None), ("4' GATE", None), ("HOUSE", None), ("DRIVEWAY", None),
    ("ALL DISTURBED AREAS TO RECEIVE BERMUDA SOD PER SPECIFICATION SECTION 32 92 23", None)])
def test_zone_words(text, kind):                                                 # C2S15-W02
    assert site.zone_kind(text) == kind


def test_fence_and_gate_notes():                                                 # C2S15-W03
    assert site.fence_info("6' WOOD PRIVACY FENCE") == {"material": "wood", "height_ft": 6.0, "remove": False}
    assert site.fence_info('4\'-0" HIGH CHAIN LINK FENCE')["material"] == "chain_link"
    assert site.fence_info("5' BLACK ALUMINUM FENCE") == {"material": "iron", "height_ft": 5.0, "remove": False}
    assert site.fence_info("6' VINYL FENCE")["material"] == "vinyl"
    assert site.fence_info("8' CMU SCREEN WALL") == {"material": "block", "height_ft": 8.0, "remove": False}
    assert site.fence_info("REMOVE EXISTING FENCE")["remove"] is True and site.fence_info("FENCE")["height_ft"] is None
    assert site.gate_info("4' GATE") == {"kind": "walk", "count": 1, "width_ft": 4.0}
    assert site.gate_info("12' DOUBLE DRIVE GATE")["kind"] == "drive"
    assert site.gate_info("10' GATE")["kind"] == "drive"                          # 8 ft and wider
    assert site.gate_info("(2) 4' GATES") == {"kind": "walk", "count": 2, "width_ft": 4.0}
    assert site.gate_info("12 FT GATE")["count"] == 1                            # "12 FT" is a width, not a count
    assert site.gate_info("FENCE") is None
    assert site.is_existing("EXISTING LAWN TO REMAIN") and not site.is_existing("REMOVE EXISTING FENCE")
    assert site.rock_depth('3/4" ROCK 3" DEEP') == 3 and site.rock_depth("ROCK 2 IN DEPTH") == 2


# ---------------------------------------------------------------- the yard (PDF)                   C2S15-S01..S06

def test_zones_by_kind_with_the_house_left_out(db, tmp_path):                   # C2S15-S01
    _eid, ps = read(db, tmp_path, [yard()])
    assert zones(db, ps) == {"sod": 5632, "pavers": 256, "rock": 512}            # the house and patio are a hole in the lawn
    rock = next(o for o in objects(db, ps, "SITE-ZONE") if o["label"].startswith("rock"))
    assert rock["label"] == 'rock · 3/4" RIVER ROCK 3" DEEP' and rock["kind"] == "polygon"
    assert not objects(db, ps, kind="wall") and not objects(db, ps, kind="room")   # a site plan has no rooms or walls


def test_hatching_doesnt_cut_a_zone_into_strips(db, tmp_path):                  # C2S15-S02
    with_hatch = zones(db, read(db, tmp_path, [yard()])[1])["rock"]
    without = zones(db, read(db, tmp_path, [yard(hatch=False)], title="No hatch", name="plain.pdf")[1])["rock"]
    assert with_hatch == without == 512


def test_a_fence_line_through_its_dashes_and_corner_and_the_gates(db, tmp_path):   # C2S15-S03
    _eid, ps = read(db, tmp_path, [yard()])
    fences = objects(db, ps, "SITE-FENCE")
    assert len(fences) == 1 and fences[0]["label"].startswith("fence · 6") and fences[0]["kind"] == "polyline"
    assert float(fences[0]["real"]["length_ft"]) == pytest.approx(114, abs=1)     # 92 ft back + 22 ft side
    assert len(json.loads(fences[0]["geometry_json"])["points"]) == 3             # the dashes are one run with a corner
    gates = sorted(o["label"].split(" · ")[0] for o in objects(db, ps, "SITE-GATE"))
    assert gates == ["1 drive gate", "1 walk gate"]


def test_a_note_with_a_leader_names_the_area_it_points_to(db, tmp_path):        # C2S15-S04
    texts = [t for t in YARD_TEXTS if t is not SOD] + [(0.3, 7.0, 7, "BERMUDA SOD")]     # outside the lot
    _eid, ps = read(db, tmp_path, [yard(texts=texts, lines=[(0.6, 7.05, 3.5, 7.05)])])
    assert zones(db, ps)["sod"] == 5632


def test_existing_areas_and_unscaled_views_arent_counted(db, tmp_path):         # C2S15-S05
    texts = [t for t in YARD_TEXTS if t is not SOD] + [(3.0, 4.2, 9, "EXISTING LAWN TO REMAIN")]
    eid, ps = read(db, tmp_path, [yard(texts=texts)])
    assert "sod" not in zones(db, ps) and zones(db, ps)["rock"] == 512
    m = building.build(db, CTX, estimate_id=eid)
    assert m["site"]["zone_sqft"]["sod"] == 0
    eid2, ps2 = read(db, tmp_path, [yard(scale=None)], title="No scale", name="ns.pdf")
    assert not objects(db, ps2, "SITE-ZONE")


def test_the_plant_schedule(db, tmp_path):                                        # C2S15-S06
    eid, ps = read(db, tmp_path, [yard()])
    row = db.execute("SELECT c.schedule_type FROM schedules c JOIN sheets s ON s.id = c.sheet_id WHERE s.plan_set_id = ?",
                     (ps,)).fetchone()
    assert row["schedule_type"] == "plant"
    plants = building.build(db, CTX, estimate_id=eid)["site"]["plants"]
    assert (plants["trees"], plants["shrubs"]) == (5, 14)                       # oaks and palms; the liriope flats aren't


# ---------------------------------------------------------------- trade answers                    C2S15-T01..T05

def test_fencing_and_landscaping_answers(db, tmp_path):                         # C2S15-T01
    eid, _ = read(db, tmp_path, [yard()])
    f = trades.answers(db, CTX, "fencing", estimate_id=eid)
    assert f["answers"] == {"length_lf": 114.0, "material": "wood", "height": "6", "walk_gates": 1, "drive_gates": 1}
    assert "fence note" in f["from"]["material"]
    land = trades.answers(db, CTX, "landscaping", estimate_id=eid)["answers"]
    assert land == {"sod_sqft": 5632.0, "rock_sqft": 512.0, "rock_depth": "3", "pavers_sqft": 256.0, "trees": 5,
                    "shrubs": 14}
    every = trades.all_answers(db, CTX, estimate_id=eid)["trades"]
    assert {"fencing", "landscaping"} <= set(every) and len(every) == len(trades.TRADES) == 12


def test_a_second_kind_of_fence_and_an_old_fence_to_remove(db, tmp_path):     # C2S15-T02
    chain = dashed(2.25, 4.0, 2.25, 10.5)                                         # 6.5" = 52 ft on the left side
    texts = YARD_TEXTS + [(2.45, 7.0, 7, "4' CHAIN LINK FENCE")]
    eid, _ = read(db, tmp_path, [yard(texts=texts, lines=chain)])
    out = trades.answers(db, CTX, "fencing", estimate_id=eid)
    assert out["answers"]["length_lf"] == 114.0 and out["answers"]["material"] == "wood"
    assert any("52 lf of 4 ft chain link" in n for n in out["notes"])
    old = [t for t in YARD_TEXTS if "FENCE" not in t[3]] + [(6.0, 3.35, 7, "REMOVE EXISTING FENCE")]
    eid2, _ = read(db, tmp_path, [yard(texts=old)], title="Old fence", name="old.pdf")
    out2 = trades.answers(db, CTX, "fencing", estimate_id=eid2)
    assert out2["answers"]["remove_old"] is True and "length_lf" not in out2["answers"]


def test_the_same_yard_on_two_sheets_is_counted_once(db, tmp_path):            # C2S15-T03
    eid, _ = read(db, tmp_path, [yard(title="SITE PLAN", sheet_no="A-001", sheet_title="SITE PLAN", schedule=False),
                                 yard()])
    m = building.build(db, CTX, estimate_id=eid)
    assert m["site"]["zone_sqft"]["sod"] == 5632.0 and m["site"]["fence_lf"] == 114.0
    assert any("counted once" in n for n in m["site"]["notes"])
    assert m["rooms"] == []                                                      # a site plan's house isn't a floor plan


def test_no_site_plans_say_so(db, tmp_path):                                     # C2S15-T04
    eid, _ = read(db, tmp_path, [yard(fence=False, texts=[(6.5, 7.0, 10, "HOUSE")], schedule=False)])
    f = trades.answers(db, CTX, "fencing", estimate_id=eid)
    land = trades.answers(db, CTX, "landscaping", estimate_id=eid)
    assert f["answers"] == {} and any("no fence lines" in n for n in f["notes"])
    assert land["answers"] == {} and any("no landscape zones" in n for n in land["notes"])
    assert not any("symbols" in n for n in land["notes"])                        # no symbols at all: nothing to say


def test_measurements_from_the_site_plan(db, tmp_path):                          # C2S15-T05
    eid, _ = read(db, tmp_path, [yard()])
    out = from_plans.propose(db, CTX, eid, "landscaping", confirm=True)
    got = {m["feeds"]: (float(m["qty"]), m["unit"]) for m in out["measurements"]}
    assert got["sod_sqft"] == (5632.0, "sqft") and got["trees"] == (5.0, "ea") and got["shrubs"] == (14.0, "ea")
    assert out["choices"].get("rock_depth") == "3"
    fence = from_plans.propose(db, CTX, eid, "fencing", confirm=True)
    assert {m["feeds"] for m in fence["measurements"]} == {"length_lf", "walk_gates", "drive_gates"}


# ---------------------------------------------------------------- CAD                              C2S15-D01

def test_dxf_fence_layers_zone_hatches_and_gate_blocks(db, tmp_path):            # C2S15-D01
    ezdxf = pytest.importorskip("ezdxf")
    doc = ezdxf.new()
    doc.header["$INSUNITS"] = 2                                                  # feet
    msp = doc.modelspace()
    for name in ("L-FENC", "L-TURF", "L-ROCK"):
        doc.layers.add(name)
    msp.add_lwpolyline([(0, 0), (60, 0), (60, 40)], dxfattribs={"layer": "L-FENC"})          # 100 ft of fence
    msp.add_text("6' VINYL FENCE", dxfattribs={"layer": "L-ANNO", "insert": (20, 2), "height": 1})
    h = msp.add_hatch(dxfattribs={"layer": "L-TURF"})                            # a 50 x 30 lawn with a 10 x 10 hole
    h.paths.add_polyline_path([(5, 5), (55, 5), (55, 35), (5, 35)], is_closed=True)
    h.paths.add_polyline_path([(20, 15), (30, 15), (30, 25), (20, 25)], is_closed=True)
    msp.add_lwpolyline([(70, 0), (80, 0), (80, 20), (70, 20)], close=True, dxfattribs={"layer": "L-ROCK"})   # 200
    blk = doc.blocks.new("GATE_4FT")
    blk.add_line((0, 0), (4, 0))
    msp.add_blockref("GATE_4FT", (30, 0), dxfattribs={"layer": "L-FENC"})
    path = tmp_path / "yard.dxf"
    doc.saveas(path)
    est = service.create_estimate(db, CTX, "CAD yard")
    ps = store.upload(db, CTX, est["id"], str(path), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    assert zones(db, ps) == {"sod": 1400, "rock": 200}                           # 1500 less the 100 sq ft hole
    fence = objects(db, ps, "SITE-FENCE")
    assert len(fence) == 1 and float(fence[0]["real"]["length_ft"]) == pytest.approx(100, abs=0.5)
    out = trades.answers(db, CTX, "fencing", estimate_id=est["id"])["answers"]
    assert (out["material"], out["height"], out["walk_gates"]) == ("vinyl", "6", 1)


# ---------------------------------------------------------------- landscape symbols                C2S15-L01

def test_the_landscape_symbol_library():                                          # C2S15-L01
    assert lib.VERSION >= 4
    for desc, it in (("SHADE TREE", "tree"), ("SABAL PALM", "palm"), ("FLOWERING SHRUB", "shrub"),
                     ("DRIP VALVE ASSEMBLY", "drip_valve"), ("REMOTE CONTROL VALVE", "irrigation_valve"),
                     ("IRRIGATION CONTROLLER", "irrigation_controller")):
        assert legends.item_type(desc) == (it, "landscape"), desc
    assert legends.item_type("STREET LIGHT")[0] != "tree"
    assert lib.by_block_name("TREE-OAK-24")["item_type"] == "tree" and lib.by_block_name("PALM_SABAL")["item_type"] == "palm"
    assert lib.feeds_of("palm") == [("landscaping", "trees")] and lib.feeds_of("drip_valve") == [("landscaping", "drip_zones")]
    assert lib.module_of_trade("landscape") == "landscaping" and lib.by_alias("DV")["item_type"] == "dryer_vent"
    assert "landscaping" in trades.SYMBOL_TRADES

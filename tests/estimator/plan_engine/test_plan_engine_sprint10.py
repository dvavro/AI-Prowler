"""Coder 2 Sprint 10: the Symbol Recognition Engine v1 - legend symbols found on the plans (any rotation, mirrored),
look-alikes told apart by the codes beside them, the standard library, CAD block names, scans, and the fused results
saved as symbol_detections and listed with counts."""
import json
import math
import time
from decimal import Decimal  # noqa: F401

import pytest

import estimator.plan_engine as pe
from estimator.drawing_model import engine, store
from estimator.plan_engine import symbol_library as lib
from estimator.plan_engine import symbols

from pdfmaker import make_pdf, title_block      # this folder

W, H = 36, 24
QUARTER = 'SCALE: 1/4" = 1\'-0"'

SHAPES = {
    "recept": [(-.1, -.1, .1, -.1), (.1, -.1, .1, .1), (.1, .1, -.1, .1), (-.1, .1, -.1, -.1),
               (-.04, -.06, -.04, .06), (.04, -.06, .04, .06)],
    "quad": [(-.1, -.1, .1, -.1), (.1, -.1, .1, .1), (.1, .1, -.1, .1), (-.1, .1, -.1, -.1),
             (-.04, -.06, -.04, .06), (.04, -.06, .04, .06), (-.07, 0, .07, 0)],
    "flag": [(-.1, -.12, -.1, .12), (-.1, -.12, .1, -.06), (.1, -.06, -.1, 0)],
    "tri": [(-.1, .08, .1, .08), (.1, .08, 0, -.1), (0, -.1, -.1, .08)],
}


def shape(kind, x, y, rot=0, mirror=False, s=1.0):
    out, a = [], math.radians(rot)
    for (x0, y0, x1, y1) in SHAPES[kind]:
        pts = []
        for (px, py) in ((x0, y0), (x1, y1)):
            py = -py if mirror else py
            px, py = px * s, py * s
            pts.append((x + px * math.cos(a) - py * math.sin(a), y + px * math.sin(a) + py * math.cos(a)))
        out.append((*pts[0], *pts[1]))
    return out


def legend(rows, x=20, y=12, title="ELECTRICAL LEGEND"):
    """rows: [(shape or None, code or None, description)] -> texts, lines."""
    texts, lines = [(x, y, 12, title)], []
    for i, (kind, code, desc) in enumerate(rows):
        top = y + 0.45 + 0.3 * i
        if kind:
            lines += shape(kind, x + 0.2, top + 0.05)
        if code:
            texts.append((x + 0.5, top, 9, code))
        texts.append((x + 1.0, top, 9, desc))
    return texts, lines


def plan(texts=(), lines=(), sheet_no="E-101", title="POWER PLAN", scale=QUARTER):
    t = title_block(sheet_no, title) + [(4, 21, 14, "POWER PLAN")] + list(texts)
    if scale:
        t.append((4, 21.35, 9, scale))
    return {"w": W, "h": H, "texts": t, "lines": list(lines)}


def run(tmp_path, pages, name="e.pdf"):
    return pe.process(make_pdf(tmp_path / name, pages), "pdf", {"work_dir": str(tmp_path / ("work_" + name))})


def found(sheet):
    return [o for o in sheet["objects"] if o.get("symbol")]


BASIC = [("recept", None, "DUPLEX RECEPTACLE"), ("tri", None, "THERMOSTAT"), ("flag", None, "SPECIAL DEVICE")]


# ---------------------------------------------------------------- vector matching                     C2S10-E01..E04

def test_legend_symbols_found_at_any_turn_and_mirrored(tmp_path):                    # C2S10-E01
    lt, ll = legend(BASIC)
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5, 90) + shape("recept", 9, 6, 45) + \
        shape("recept", 11, 6, 0, False, 1.05) + shape("tri", 12, 5, 30) + shape("flag", 13, 9, 0, True) + \
        shape("flag", 15, 9, 200) + shape("recept", 17, 6, 0, False, 1.5)       # 1.5x is too big: not this symbol
    out = run(tmp_path, [plan(lt, lines)])
    s = out["sheets"][0]
    by_type = {}
    for o in found(s):
        by_type.setdefault(o["symbol"]["item_type"], []).append(o)
    assert len(by_type["duplex_receptacle"]) == 4 and len(by_type["thermostat"]) == 1 and len(by_type[None]) == 2
    rots = sorted(o["symbol"]["rotation"] % 90 for o in by_type["duplex_receptacle"])
    assert rots[-1] == pytest.approx(45, abs=1)
    assert [o["symbol"]["mirrored"] for o in sorted(by_type[None], key=lambda o: o["geometry"]["points"][0][0])] == [
        True, False]                                                                # the mirrored flag is found as one
    assert all(not (20 <= o["geometry"]["points"][0][0] <= 23) for o in found(s))   # the legend's own samples aren't
    assert all(o["kind"] == "symbol" and o["geometry"]["type"] == "point" for o in found(s))
    assert all(o["symbol"]["needs_review"] for o in by_type[None])                 # no item type: a person names it
    assert "7 symbol(s) found from the legend" in s["note"]


def test_codes_tell_look_alikes_apart(tmp_path):                                     # C2S10-E02
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("recept", "GFI", "DUPLEX RECEPTACLE, GFCI"),
                     ("recept", "WP", "DUPLEX RECEPTACLE, WEATHERPROOF")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5) + shape("recept", 11, 5)
    texts = lt + [(7.15, 4.95, 7, "GFI"), (9.15, 4.95, 7, "WP"), (11.15, 4.95, 7, "GFI")]
    s = run(tmp_path, [plan(texts, lines)])["sheets"][0]
    types = sorted(o["symbol"]["item_type"] for o in found(s))
    assert types == ["duplex_receptacle", "duplex_receptacle_gfci", "duplex_receptacle_gfci", "duplex_receptacle_wp"]
    gfci = next(o for o in found(s) if o["symbol"]["item_type"] == "duplex_receptacle_gfci")
    assert gfci["symbol"]["scores"]["ocr"] == 0.95 and gfci["symbol"]["scores"]["vision"] >= 0.95


def test_a_symbol_with_extra_strokes_is_the_richer_entry(tmp_path):                  # C2S10-E03
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("quad", None, "QUAD RECEPTACLE")])
    lines = ll + shape("quad", 5, 5) + shape("quad", 7, 5, 90) + shape("recept", 9, 5)
    s = run(tmp_path, [plan(lt, lines)])["sheets"][0]
    assert sorted(o["symbol"]["item_type"] for o in found(s)) == ["duplex_receptacle", "quad_receptacle", "quad_receptacle"]


def test_symbols_on_walls_and_amid_line_work(tmp_path):                              # C2S10-E04
    lt, ll = legend(BASIC)
    walls = [(2, 4.9, 20, 4.9), (2, 5.025, 20, 5.025)]                     # a wall runs right through the outlets
    hatch = [(14 + i * 0.05, 14, 14 + i * 0.05 + 0.4, 14.4) for i in range(60)]   # hatching nearby
    lines = ll + walls + hatch + shape("recept", 5, 5) + shape("recept", 9, 5) + shape("tri", 14.5, 13.5)
    s = run(tmp_path, [plan(lt, lines)])["sheets"][0]
    assert sorted(o["symbol"]["item_type"] or "" for o in found(s)) == ["duplex_receptacle", "duplex_receptacle",
                                                                         "thermostat"]


# ---------------------------------------------------------------- OCR fusion and the standard library   C2S10-E05..E07

def test_a_code_beside_a_plain_symbol_refines_it_from_the_standard_library(tmp_path):    # C2S10-E05
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    s = run(tmp_path, [plan(lt + [(7.15, 4.95, 7, "GFI")], ll + shape("recept", 5, 5) + shape("recept", 7, 5))])["sheets"][0]
    by = {o["geometry"]["points"][0][0]: o["symbol"] for o in found(s)}
    assert by[5.0]["item_type"] == "duplex_receptacle" and by[5.0]["standard"] is None
    assert by[7.0]["item_type"] == "duplex_receptacle_gfci" and by[7.0]["standard"] == "duplex_receptacle_gfci"
    assert by[7.0]["scores"]["ocr"] == 0.8


def test_code_only_legend_entries_counted_where_the_code_stands_alone(tmp_path):     # C2S10-E06
    lt, ll = legend([(None, "SD", "SMOKE DETECTOR"), ("recept", None, "DUPLEX RECEPTACLE")])
    texts = lt + [(6, 8, 8, "SD"), (9, 8, 8, "SD"), (4, 15, 8, "PROVIDE SD IN EVERY BEDROOM PER CODE")]
    s = run(tmp_path, [plan(texts, ll)])["sheets"][0]
    sd = [o for o in found(s) if o["symbol"]["item_type"] == "smoke_detector"]
    assert len(sd) == 2 and all(o["symbol"]["method"] == "ocr" for o in sd)        # not the one inside the note


@pytest.mark.parametrize("name, item", [("DUPLEX_OUTLET", "duplex_receptacle"), ("DUPLEX_OUTLET_GFI", "duplex_receptacle_gfci"),
                                        ("REC-WP", "duplex_receptacle_wp"), ("SWITCH_3WAY", "switch_3way"),
                                        ("E-SMOKE-DET", "smoke_detector"), ("P_TOILET", "water_closet"),
                                        ("DOOR_36", "door"), ("NORTH_ARROW", None),   # doors count since 2026-11-13
                                        ("DOORBELL", "doorbell"), ("DOOR_CONTACT", "door_contact"),
                                        ("DOUBLE_DOOR_72", "door_double"), ("SKYLIGHT_2X4", "skylight"),
                                         # 2026-11-19: the house electrical test plan's blocks
                                         ("FAN", "ceiling_fan"), ("FAN_EXH", "exhaust_fan"), ("EXHAUST_FAN", "exhaust_fan"),
                                         ("SWITCH_DIM", "switch_dimmer"), ("LIGHT_WALL", "light_wall"),
                                         ("LIGHT_CEIL", "light_fixture"), ("DIM_ARROW", None),
                                          # 2026-11-20: a recessed can is its own light type, not a plain fixture
                                          ("LIGHT_REC", "light_recessed"), ("LIGHT_PEND", "light_pendant"),
                                          ("LIGHT_UC", "light_undercabinet"), ("LIGHT_EXT", "light_exterior")])
def test_block_names(name, item):                                                    # C2S10-E07
    got = lib.by_block_name(name)
    assert (got["item_type"] if got else None) == item
    assert lib.by_alias("gfi")["item_type"] == "duplex_receptacle_gfci" and lib.by_alias("$3")["item_type"] == "switch_3way"
    assert lib.by_alias("XYZ") is None


def _cad_sheet(objects, w=108.0, h=64.0):
    return {"width": w, "height": h, "discipline": "electrical", "objects": objects}


def _blk(name, x, y):
    return {"kind": "symbol", "block_name": name, "geometry": {"type": "point", "points": [[x, y]]}}


def _txt(label, x, y):
    return {"kind": "text", "label": label, "geometry": {"type": "point", "points": [[x, y]]}}


def _room(x0, y0, x1, y1, label="ROOM"):
    return {"kind": "room", "label": label,
            "geometry": {"type": "polygon", "points": [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]}}


def test_cad_legend_samples_are_not_devices():                                       # 2026-11-20
    """David: "your counts include the legend itself". The LEGEND title and its rows below the plan make a legend box;
    its samples stay plain blocks. The sheet border read as a room doesn't hide it."""
    from estimator.plan_engine import symbols
    objs = [_room(0, 0, 108, 64, "AC 30A"),                       # the sheet's border, read as a room
            _room(4, 4, 44, 34, "LIVING"), _room(64, 4, 104, 34, "BEDROOM"),
            _blk("LIGHT_CEIL", 10, 10), _blk("LIGHT_CEIL", 70, 10), _blk("LIGHT_REC", 20, 20), _blk("LIGHT_WALL", 4.3, 15),
            _txt("LEGEND", 6, 45),
            _blk("LIGHT_CEIL", 8, 50), _txt("CEILING LIGHT", 10, 50),
            _blk("LIGHT_REC", 58, 47.5), _txt("RECESSED LIGHT", 60, 47.5),
            _blk("LIGHT_WALL", 58, 49.2), _txt("WALL LIGHT", 60, 49.2)]
    sheet = _cad_sheet(objs)
    assert symbols.cad_symbols(sheet) == 4                        # the 4 on the plan, not the 3 samples
    got = sorted((o["symbol"]["item_type"], o["geometry"]["points"][0][1]) for o in objs if o.get("symbol"))
    assert got == [("light_fixture", 10), ("light_fixture", 10), ("light_recessed", 20), ("light_wall", 15)]
    (lg,) = sheet["legends"]
    assert lg["bbox"][1] < 45 < 50 < lg["bbox"][3] and lg["bbox"][1] > 34   # below the plan, round the rows


def test_wall_lights_outside_the_building_are_exterior_lights():                     # 2026-11-20
    """David: exterior lights found 2 but lit up nothing. His plan draws the porch lights with the plain wall-light
    block, just outside the outside walls; those are exterior lights. Wall lights inside (even on the inside face of an
    outside wall, or in a hall no room was read for) stay wall lights. Two floors side by side are two buildings."""
    from estimator.plan_engine import symbols
    objs = [_room(0, 0, 108, 64, "AC 30A"),                       # the sheet's border, read as a room: not a building
            _room(4, 16, 23, 34, "FAMILY"), _room(4, 4, 23, 19, "LIVING"), _room(25, 4, 44, 34, "KITCHEN"),
            _room(64, 6.5, 104, 34, "BEDROOM"),
            _blk("LIGHT_WALL", 10, 34.7), _blk("LIGHT_WALL", 10, 3.3),          # outside the ground floor: porch lights
            _blk("LIGHT_WALL", 24, 15), _blk("LIGHT_WALL", 64.7, 17),            # inside (a hall gap; an outside wall)
            _blk("LIGHT_WALL", 54, 20)]                                          # between the floors: outside both
    sheet = _cad_sheet(objs)
    assert symbols.cad_symbols(sheet) == 5
    got = sorted((o["symbol"]["item_type"], tuple(o["geometry"]["points"][0])) for o in objs if o.get("symbol"))
    assert got == [("light_exterior", (10, 3.3)), ("light_exterior", (10, 34.7)), ("light_exterior", (54, 20)),
                   ("light_wall", (24, 15)), ("light_wall", (64.7, 17))]
    assert all(o["symbol"]["method"] == "cad" for o in objs if o.get("symbol"))   # a method the store keeps
    # No rooms read: nothing to tell inside from outside, so wall lights stay wall lights.
    bare = [_blk("LIGHT_WALL", 10, 34.7)]
    symbols.cad_symbols(_cad_sheet(bare))
    assert bare[0]["symbol"]["item_type"] == "light_wall"


def test_cad_legend_beside_the_plan_doesnt_swallow_it():                             # 2026-11-20
    from estimator.plan_engine import symbols
    objs = [_room(4, 4, 60, 60, "LIVING"),
            _blk("LIGHT_CEIL", 10, 50), _blk("LIGHT_CEIL", 50, 52),           # devices low on the plan
            _txt("ELECTRICAL LEGEND", 80, 40),
            _blk("LIGHT_CEIL", 80, 42), _txt("CEILING LIGHT", 82, 42), _blk("LIGHT_REC", 80, 43.7),
            _txt("RECESSED LIGHT", 82, 43.7)]
    sheet = _cad_sheet(objs)
    assert symbols.cad_symbols(sheet) == 2
    assert all(o["geometry"]["points"][0][0] < 60 for o in objs if o.get("symbol"))


def test_no_legend_title_no_legend():                                                 # 2026-11-20
    from estimator.plan_engine import symbols
    sheet = _cad_sheet([_room(4, 4, 44, 34), _blk("LIGHT_CEIL", 10, 10), _blk("LIGHT_CEIL", 10, 50)])
    assert symbols.cad_symbols(sheet) == 2 and not sheet.get("legends")


def test_cad_blocks_become_detections(tmp_path):                                     # C2S10-E08
    ezdxf = pytest.importorskip("ezdxf")
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2
    for name in ("DUPLEX_OUTLET_GFI", "NORTH_ARROW"):
        b = doc.blocks.new(name=name)
        b.add_line((0, 0), (1, 0))
    msp = doc.modelspace()
    for x in (1, 3, 5):
        msp.add_blockref("DUPLEX_OUTLET_GFI", (x, 1))
    msp.add_blockref("NORTH_ARROW", (8, 1))                # not a symbol to count
    path = tmp_path / "e.dxf"
    doc.saveas(path)
    s = pe.process(path, "dxf", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    recs = [o["symbol"] for o in s["objects"] if o.get("symbol")]
    assert len(recs) == 3 and {r["item_type"] for r in recs} == {"duplex_receptacle_gfci"}
    assert all(r["method"] == "cad" and r["scores"]["cad"] == 0.95 for r in recs)


# ---------------------------------------------------------------- raster matching                     C2S10-E09

def test_raster_symbols_on_a_scan(tmp_path):                                         # C2S10-E09
    from PIL import Image, ImageDraw
    dpi = 100
    img = Image.new("L", (11 * dpi, 8 * dpi), 255)
    d = ImageDraw.Draw(img)

    def flag(x, y, turn=0):
        pts = [(-.1, -.12), (-.1, .12), (-.1, -.12), (.1, -.06), (-.1, 0)]
        rot = {0: lambda p: p, 90: lambda p: (-p[1], p[0])}[turn]
        q = [((x + rot(p)[0]) * dpi, (y + rot(p)[1]) * dpi) for p in pts]
        d.line(q[:2], fill=0, width=2)
        d.line(q[2:], fill=0, width=2)
    flag(1, 1)                                            # the legend's sample
    for (x, y, t) in ((3, 3, 0), (5, 3, 0), (7, 5, 90)):
        flag(x, y, t)
    d.rectangle((8 * dpi, 2 * dpi, 8.3 * dpi, 2.3 * dpi), outline=0, width=2)    # something else
    path = tmp_path / "scan.png"
    img.save(path)
    sheet = {"image_path": str(path), "width": 11, "height": 8}
    tpl = symbols.raster_template(sheet, [0.85, 0.83, 1.15, 1.17])
    hits = symbols.match_raster(tpl, sheet, exclude=[[0.5, 0.5, 1.5, 1.5]])
    centres = sorted((round(h["centre"][0]), round(h["centre"][1])) for h in hits)
    assert centres == [(3, 3), (5, 3), (7, 5)]


def test_matching_stays_fast_on_busy_sheets(tmp_path):                               # C2S10-E10
    import random
    rnd = random.Random(7)
    lt, ll = legend(BASIC)
    noise = [(x, y, x + rnd.uniform(-.2, .2), y + rnd.uniform(-.2, .2))
             for x, y in ((rnd.uniform(2, 18), rnd.uniform(2, 18)) for _ in range(6000))]
    lines = ll + noise + [seg for i in range(40) for seg in shape("recept", 2 + (i % 8) * 2, 19 + (i // 8) * 0.5)]
    t0 = time.time()
    s = run(tmp_path, [plan(lt, lines)])["sheets"][0]
    assert time.time() - t0 < 60
    assert sum(1 for o in found(s) if o["symbol"]["item_type"] == "duplex_receptacle") >= 38


# ---------------------------------------------------------------- saved and listed                    C2S10-E11..E13

@pytest.fixture
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _read(db, path):
    from estimator.context import personal_context
    from estimator.estimating import service
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    ps = store.upload(db, ctx, est["id"], str(path), confirm=True)["plan_set_id"]
    out = engine.start(db, ctx, ps, confirm=True)
    assert out.get("ok", True), out
    return ctx, ps, est["id"], out


def _square(x, y, size):
    return [(x, y, x + size, y), (x + size, y, x + size, y + size), (x + size, y + size, x, y + size), (x, y + size, x, y)]


def test_saved_with_definitions_rooms_and_counts(db, tmp_path, real_engine):         # C2S10-E11
    from estimator.symbols import service as sym
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("recept", "GFI", "DUPLEX RECEPTACLE, GFCI"),
                     ("flag", None, "SPECIAL DEVICE")])
    texts = lt + [(5, 6.4, 10, "KITCHEN"), (7.15, 5.95, 7, "GFI")]
    lines = ll + _square(4, 4, 4) + shape("recept", 5, 6) + shape("recept", 7, 6) + shape("recept", 12, 6) + \
        shape("flag", 13, 9)
    pdf = make_pdf(tmp_path / "e.pdf", [plan(texts, lines)])
    ctx, ps, eid, out = _read(db, pdf)
    assert out["symbol_detections"] == 4 and out["symbol_definitions"] == 3
    r = sym.detections_list(db, ctx, plan_set_id=ps)
    by = {t["item_type"]: t for t in r["counts"]["by_type"]}
    assert by["duplex_receptacle"]["count"] == 2 and by["duplex_receptacle_gfci"]["count"] == 1
    assert by[None]["needs_review"] == 1 and all(t["proposed"] == t["count"] for t in by.values())
    rooms = {m["room"]: m["by_type"] for m in r["counts"]["by_room"]}
    assert rooms["KITCHEN"] == {"duplex_receptacle": 1, "duplex_receptacle_gfci": 1}
    assert rooms[None] == {"duplex_receptacle": 1, "unknown": 1}
    d = next(x for x in r["detections"] if x["item_type"] == "duplex_receptacle_gfci")
    assert d["definition_from"] == "plan-set legend" and d["room"] == "KITCHEN" and d["code"] == "GFI"
    assert d["status"] == "proposed" and d["scores"]["vision"] >= 0.95 and d["method"] == "vector"
    obj = db.execute("SELECT kind, label FROM drawing_objects WHERE id = ?", (d["drawing_object_id"],)).fetchone()
    assert obj["kind"] == "symbol" and obj["label"] == "DUPLEX RECEPTACLE, GFCI"
    assert sym.detections_list(db, ctx, estimate_id=eid, room="kitchen")["count"] == 2
    assert sym.detections_list(db, ctx, plan_set_id=ps, needs_review=True)["count"] == 1
    assert sym.detections_list(db, ctx, plan_set_id=ps, item_type="duplex_receptacle", limit=1)["returned"] == 1
    legends = store.legends(db, ctx, ps)
    entries = {e["description"]: e for e in legends["symbol_dictionary"]}
    assert entries["DUPLEX RECEPTACLE"]["found"] == 2 and entries["SPECIAL DEVICE"]["needs_confirming"]
    assert entries["DUPLEX RECEPTACLE"]["has_symbol"]                              # its picture was kept


def test_reading_again_replaces_and_the_standard_library_is_kept_once(db, tmp_path, real_engine):   # C2S10-E12
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    pdf = make_pdf(tmp_path / "e.pdf", [plan(lt + [(7.15, 4.95, 7, "GFI")], ll + shape("recept", 5, 5) + shape("recept", 7, 5))])
    ctx, ps, _eid, _ = _read(db, pdf)
    engine.start(db, ctx, ps, confirm=True)
    assert db.execute("SELECT COUNT(*) FROM symbol_detections WHERE plan_set_id = ?", (ps,)).fetchone()[0] == 2
    assert db.execute("SELECT COUNT(*) FROM symbol_definitions WHERE plan_set_id = ?", (ps,)).fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM symbol_libraries WHERE level = 'standard'").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM symbol_definitions WHERE library_id IS NOT NULL").fetchone()[0] == len(lib.STANDARD)
    std = db.execute("SELECT d.definition_id, f.library_id FROM symbol_detections d JOIN symbol_definitions f"
                     " ON f.id = d.definition_id WHERE d.item_type = 'duplex_receptacle_gfci'").fetchone()
    assert std["library_id"] is not None                                            # from the standard library


def test_symbol_detections_list_tool(db, tmp_path, real_engine):                     # C2S10-E13
    from estimator.mcp_tools import est_tools as t
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    ctx, ps, eid, _ = _read(db, make_pdf(tmp_path / "e.pdf", [plan(lt, ll + shape("recept", 5, 5))]))
    j = lambda s: json.loads(s)  # noqa: E731
    got = j(t.symbol_detections_list(plan_set_id=ps))
    assert got["count"] == 1 and got["counts"]["by_type"][0]["item_type"] == "duplex_receptacle"
    assert j(t.symbol_detections_list(estimate_id=eid, needs_review="false"))["count"] == 1
    assert j(t.symbol_detections_list())["error"] == "invalid_input"
    assert j(t.symbol_detections_list(plan_set_id=ps, status="maybe"))["error"] == "invalid_input"
    assert j(t.symbol_detections_list(plan_set_id=999))["error"] == "not_found"
    assert "symbol_detections_list" in {fn.__name__ for fn in t.TOOLS}

"""Coder 2 Sprint 6: walls and rooms from PDF line work, and DXF drawings (ezdxf) read at real size - then saved and
measured by the drawing model."""
from decimal import Decimal
from pathlib import Path

import pytest

import estimator.plan_engine as pe
from estimator.drawing_model import engine, store
from estimator.plan_engine import vectors

from pdfmaker import make_pdf, title_block      # this folder

ezdxf = pytest.importorskip("ezdxf")
W, H = 36, 24
QUARTER = 'SCALE: 1/4" = 1\'-0"'                  # 1 paper inch = 4 feet


def _plan(tmp_path, lines=(), texts=(), scale=QUARTER, name="plan.pdf"):
    t = title_block("A-101", "FIRST FLOOR PLAN") + [(4, 21, 14, "FLOOR PLAN")] + list(texts)
    if scale:
        t.append((4, 21.35, 9, scale))
    pdf = make_pdf(tmp_path / name, [{"w": W, "h": H, "texts": t, "lines": list(lines)}])
    out = pe.process(pdf, "pdf", {"work_dir": str(tmp_path / "work")})
    return out["sheets"][0]


def _of(sheet, kind):
    return [o for o in sheet["objects"] if o["kind"] == kind]


def _square(x, y, size):
    return [(x, y, x + size, y), (x + size, y, x + size, y + size), (x + size, y + size, x, y + size),
            (x, y + size, x, y)]


def _length(points):
    (ax, ay), (bx, by) = points
    return ((bx - ax) ** 2 + (by - ay) ** 2) ** 0.5


# ---------------------------------------------------------------- walls from PDF line work

def test_a_wall_is_two_parallel_lines(tmp_path):
    s = _plan(tmp_path, lines=[(5, 5, 9, 5), (5, 5.125, 9, 5.125)])          # 0.125" at 1/4" = a 6" wall, 16 ft
    walls = _of(s, "wall")
    assert len(walls) == 1
    w = walls[0]
    assert w["label"] == '6" wall' and w["viewport"] == "main" and w["source"] == "vector"
    assert abs(_length(w["geometry"]["points"]) - 4) < 0.01                    # centerline over the overlap
    assert abs(w["geometry"]["points"][0][1] - 5.0625) < 0.001                  # halfway between the lines


@pytest.mark.parametrize("gap", [0.01, 0.5])            # 1/2" thick and 24" thick: neither is a wall
def test_not_walls(tmp_path, gap):
    assert _of(_plan(tmp_path, lines=[(5, 5, 9, 5), (5, 5 + gap, 9, 5 + gap)]), "wall") == []


def test_short_lines_and_lines_that_dont_overlap_arent_walls(tmp_path):
    lines = [(5, 5, 5.3, 5), (5, 5.125, 5.3, 5.125),                         # 1.2 ft long: too short
             (10, 5, 12, 5), (13, 5.125, 15, 5.125)]                         # parallel but side by side
    assert _of(_plan(tmp_path, lines=lines), "wall") == []


def test_vertical_and_diagonal_walls(tmp_path):
    lines = [(20, 3, 20, 8), (20.125, 3, 20.125, 8),
             (5, 10, 8, 13), (5.088, 9.912, 8.088, 12.912)]                   # 45 degrees, 0.125" apart
    walls = _of(_plan(tmp_path, lines=lines), "wall")
    assert len(walls) == 2 and {w["label"] for w in walls} == {'6" wall'}


def test_a_long_line_pairs_with_each_piece_across_a_door(tmp_path):
    lines = [(5, 5, 13, 5), (5, 5.125, 8, 5.125), (9, 5.125, 13, 5.125)]
    walls = _of(_plan(tmp_path, lines=lines), "wall")
    assert sorted(round(_length(w["geometry"]["points"]), 2) for w in walls) == [3.0, 4.0]


def test_unscaled_view_still_finds_walls_on_paper(tmp_path):
    s = _plan(tmp_path, lines=[(5, 5, 9, 5), (5, 5.125, 9, 5.125)], scale=None)
    walls = _of(s, "wall")
    assert len(walls) == 1 and walls[0]["label"] == "wall"


def test_title_block_line_work_is_left_alone(tmp_path):
    s = _plan(tmp_path, lines=[(30, 5, 34, 5), (30, 5.1, 34, 5.1)])           # in the right strip
    assert _of(s, "wall") == []


def test_dashed_lines_and_hatching_stay_fast():
    import time
    dashes = [((x * 0.05, 3.0), (x * 0.05 + 0.03, 3.0)) for x in range(4000)]          # one long dashed line
    hatch = [((0.0, 5 + i * 0.05), (20.0, 5 + i * 0.05)) for i in range(2000)]         # 2000 hatch lines
    wall = [((1.0, 2.0), (9.0, 2.0)), ((1.0, 2.125), (9.0, 2.125))]
    t0 = time.time()
    walls = vectors.find_walls(vectors.clean_segments(dashes + hatch + wall), 48.0)
    assert time.time() - t0 < 5, "the wall finder is too slow on dashed lines and hatching"
    assert any(abs(w.a[1] - 2.0625) < 0.001 for w in walls)


# ---------------------------------------------------------------- rooms

def test_a_room_is_a_name_inside_a_closed_area(tmp_path):
    s = _plan(tmp_path, lines=_square(5, 5, 3), texts=[(6, 6.4, 10, "KITCHEN")])   # 3" square = 12 x 12 ft
    rooms = _of(s, "room")
    assert len(rooms) == 1 and rooms[0]["label"] == "KITCHEN" and rooms[0]["geometry"]["type"] == "polygon"
    xs = [p[0] for p in rooms[0]["geometry"]["points"]]
    assert abs(min(xs) - 5) < 0.01 and abs(max(xs) - 8) < 0.01


def test_double_wall_lines_the_room_is_the_inside(tmp_path):
    lines = _square(5, 5, 3.25) + _square(5.125, 5.125, 3)                   # 6" walls all round
    s = _plan(tmp_path, lines=lines, texts=[(6, 6.4, 10, "BEDROOM 2")])
    rooms = _of(s, "room")
    assert [r["label"] for r in rooms] == ["BEDROOM 2"]
    xs = [p[0] for p in rooms[0]["geometry"]["points"]]
    assert abs(min(xs) - 5.125) < 0.01 and abs(max(xs) - 8.125) < 0.01        # the inner face, not the outer
    assert len(_of(s, "wall")) >= 4


def test_names_outside_or_in_tiny_areas_are_not_rooms(tmp_path):
    lines = _square(5, 5, 0.5)                                                # 2 x 2 ft: a closet symbol, not a room
    texts = [(5.05, 5.2, 6, "TOILET"), (15, 10, 10, "PATIO")]                 # PATIO isn't inside anything
    assert _of(_plan(tmp_path, lines=lines, texts=texts), "room") == []


def test_the_view_title_is_not_a_room(tmp_path):
    s = _plan(tmp_path, lines=_square(3, 19.5, 6))                            # a box round the view title
    assert _of(s, "room") == []


@pytest.mark.parametrize("text, ok", [("KITCHEN", True), ("BEDROOM 2", True), ("MASTER BATH", True),
                                      ("W.I.C.", True), ("FLOOR PLAN", False), ("SCALE: 1/4\"", False),
                                      ("A-101", False), ("D3", False), ("UP", False), ("TYP.", False),
                                      ("12'-6\"", False), ("kitchen", False), ("NOTE", False)])
def test_room_names(text, ok):
    assert vectors.is_room_name(text) is ok


def test_too_much_line_work_skips_rooms_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(vectors, "MAX_SEGMENTS_FOR_ROOMS", 3)
    s = _plan(tmp_path, lines=_square(5, 5, 3), texts=[(6, 6.4, 10, "KITCHEN")])
    assert _of(s, "room") == [] and "too much line work" in s["note"]


# ---------------------------------------------------------------- DXF

def _dxf(tmp_path, build, units=1, name="plan.dxf"):
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = units
    build(doc, doc.modelspace())
    path = tmp_path / name
    doc.saveas(path)
    return pe.process(path, "dxf", {"work_dir": str(tmp_path / "dxfwork")})["sheets"][0]


def test_dxf_real_size_units_and_top_left_origin(tmp_path):
    def build(doc, msp):
        msp.add_line((0, 0), (240, 0))                                          # 20 ft along the bottom
        msp.add_line((0, 0), (0, 120))                                          # 10 ft up the left side
    s = _dxf(tmp_path, build)
    assert (s["units"], s["width"], s["height"]) == ("in", 240.0, 120.0)
    assert s["viewports"][0]["scale_method"] == "cad" and s["viewports"][0]["key"] == "model"
    lines = _of(s, "line")
    bottom = next(o for o in lines if o["geometry"]["points"][0][1] == o["geometry"]["points"][1][1])
    assert bottom["geometry"]["points"][0][1] == 120.0                         # CAD y-up -> top-left, y-down
    assert "note" not in s


@pytest.mark.parametrize("code, units", [(2, "ft"), (4, "mm"), (5, "cm"), (6, "m")])
def test_dxf_units(tmp_path, code, units):
    assert _dxf(tmp_path, lambda d, m: m.add_line((0, 0), (10, 5)), units=code)["units"] == units


def test_dxf_without_units_says_inches_were_assumed(tmp_path):
    s = _dxf(tmp_path, lambda d, m: m.add_line((0, 0), (10, 5)), units=0)
    assert s["units"] == "in" and "inches were assumed" in s["note"]


def test_dxf_walls_rooms_symbols_text_dimensions(tmp_path):
    def build(doc, msp):
        doc.layers.add("A-WALL")
        doc.layers.add("E-POWR")
        for (a, b) in [((0, 0), (240, 0)), ((0, 6), (240, 6))]:               # a 6" wall, 20 ft long
            msp.add_line(a, b, dxfattribs={"layer": "A-WALL"})
        msp.add_lwpolyline([(10, 10), (130, 10), (130, 130), (10, 130)], close=True)   # 10 x 10 ft
        msp.add_text("BEDROOM", dxfattribs={"insert": (50, 70), "height": 6})
        blk = doc.blocks.new("DUPLEX_OUTLET")
        blk.add_circle((0, 0), 3)
        blk.add_attdef("TAG", (0, 0))
        ins = msp.add_blockref("DUPLEX_OUTLET", (200, 50), dxfattribs={"layer": "E-POWR"})
        ins.add_attrib("TAG", "R1", (200, 50))
        dim = msp.add_linear_dim(base=(0, -20), p1=(0, 0), p2=(240, 0))
        dim.render()
    s = _dxf(tmp_path, build)
    walls = _of(s, "wall")
    assert any(w["label"] == '6" wall' and abs(_length(w["geometry"]["points"]) - 240) < 0.1 for w in walls)
    rooms = _of(s, "room")
    assert [r["label"] for r in rooms] == ["BEDROOM"]
    sym = _of(s, "symbol")[0]
    assert (sym["block_name"], sym["tag"], sym["layer"]) == ("DUPLEX_OUTLET", "R1", "E-POWR")
    assert any(t["label"] == "BEDROOM" for t in _of(s, "text"))
    dims = _of(s, "dimension")
    assert dims and dims[0]["label"] == "20'-0\""
    from PIL import Image
    with Image.open(s["image_path"]) as img:
        w, h = img.size
    assert max(w, h) <= 4000 and abs(w / h - s["width"] / s["height"]) < 0.02


def test_dxf_room_layer_polylines_are_rooms(tmp_path):
    def build(doc, msp):
        doc.layers.add("A-AREA")
        msp.add_lwpolyline([(0, 0), (144, 0), (144, 144), (0, 144)], close=True, dxfattribs={"layer": "A-AREA"})
        msp.add_text("OFFICE", dxfattribs={"insert": (60, 70), "height": 6})
    rooms = _of(_dxf(tmp_path, build), "room")
    assert [r["label"] for r in rooms] == ["OFFICE"] and len(rooms[0]["geometry"]["points"]) == 4


def test_dxf_hidden_layers_are_skipped(tmp_path):
    def build(doc, msp):
        doc.layers.add("HIDDEN").off()
        msp.add_line((0, 0), (100, 0))
        msp.add_line((0, 50), (100, 50), dxfattribs={"layer": "HIDDEN"})
    s = _dxf(tmp_path, build)
    assert len(_of(s, "line")) == 1


def test_dxf_discipline_from_layers(tmp_path):
    def build(doc, msp):
        for i in range(3):
            msp.add_line((0, i * 10), (100, i * 10), dxfattribs={"layer": "E-LITE"})
        msp.add_line((0, 50), (100, 50), dxfattribs={"layer": "A-WALL"})
    assert _dxf(tmp_path, build, name="drawing.dxf")["discipline"] == "electrical"


def test_empty_and_broken_dxf(tmp_path):
    with pytest.raises(ValueError, match="nothing drawn"):
        _dxf(tmp_path, lambda d, m: None)
    bad = tmp_path / "bad.dxf"
    bad.write_text("this is not a dxf", encoding="utf-8")
    with pytest.raises(ValueError, match="can't be read"):
        pe.process(bad, "dxf", {"work_dir": str(tmp_path / "w")})


# ---------------------------------------------------------------- saved and measured by the drawing model

@pytest.fixture
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _read_into_store(db, tmp_path, path):
    from estimator.context import personal_context
    from estimator.estimating import service
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    ps = store.upload(db, ctx, est["id"], str(path), confirm=True)["plan_set_id"]
    out = engine.start(db, ctx, ps, confirm=True)
    assert out.get("ok", True), out
    return ctx, ps


def test_pdf_walls_and_rooms_are_measured_with_the_views_scale(db, tmp_path, real_engine):
    t = title_block("A-101", "FIRST FLOOR PLAN") + [(4, 21, 14, "FLOOR PLAN"), (4, 21.35, 9, QUARTER),
                                                    (6, 6.4, 10, "KITCHEN")]
    pdf = make_pdf(tmp_path / "smith.pdf", [{"w": W, "h": H, "texts": t,
                                             "lines": _square(5, 5, 3) + [(10, 5, 14, 5), (10, 5.125, 14, 5.125)]}])
    ctx, ps = _read_into_store(db, tmp_path, pdf)
    objs = store.objects(db, ctx, plan_set_id=ps)["objects"]
    room = next(o for o in objs if o["kind"] == "room")
    wall = next(o for o in objs if o["kind"] == "wall")
    assert Decimal(room["real_units"]["area_sqft"]) == 144 and Decimal(room["real_units"]["perimeter_ft"]) == 48
    assert Decimal(wall["real_units"]["length_ft"]) == 16


def test_dxf_is_measured_without_a_scale(db, tmp_path, real_engine):
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2                                                  # feet
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (12, 0), (12, 10), (0, 10)], close=True)
    msp.add_text("LIVING ROOM", dxfattribs={"insert": (4, 5), "height": 0.5})
    path = tmp_path / "living.dxf"
    doc.saveas(path)
    ctx, ps = _read_into_store(db, tmp_path, path)
    sheet = store.sheets(db, ctx, ps)["sheets"][0]
    assert sheet["units"] == "ft" and sheet["needs_scale"] is False
    room = next(o for o in store.objects(db, ctx, plan_set_id=ps)["objects"] if o["kind"] == "room")
    assert room["label"] == "LIVING ROOM" and Decimal(room["real_units"]["area_sqft"]) == 120

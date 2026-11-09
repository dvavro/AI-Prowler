"""Coder 2 Sprint 16: the raster pipeline for scans and photos (squared up, inverted, straightened, line work traced,
"needs review" all the way to the measurements) and DWG through a converter the user installed."""
import json
import math
import shutil
from pathlib import Path

import pytest

import estimator.plan_engine as pe
from estimator.building import model as building
from estimator.building import trades
from estimator.context import personal_context
from estimator.drawing_model import engine, store, uploads
from estimator.errors import ConfirmationRequired
from estimator.estimating import service
from estimator.plan_engine import dwg, ocr, raster
from estimator.takeoff import from_plans

from pdfmaker import make_pdf, title_block

np = pytest.importorskip("numpy")
pytest.importorskip("scipy")
Image = pytest.importorskip("PIL.Image")
from PIL import ImageDraw, ImageFont  # noqa: E402

CTX = personal_context()
DPI = 150
needs_ocr = pytest.mark.skipif(not ocr.available(), reason="Tesseract isn't installed on this PC")


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def no_ocr(monkeypatch):
    monkeypatch.setenv("ESTIMATOR_TESSERACT", "off")
    ocr.reset()
    yield
    monkeypatch.delenv("ESTIMATOR_TESSERACT")
    ocr.reset()


@pytest.fixture
def no_dwg(monkeypatch):
    monkeypatch.setenv("ESTIMATOR_DWG_CONVERTER", "off")


# ---------------------------------------------------------------- a scanned floor plan

def _font(pt):
    try:
        return ImageFont.truetype("arial.ttf", int(pt / 72 * DPI))
    except OSError:
        return ImageFont.load_default()


def floor_plan(w_in=17, h_in=11, names=True, fill=False, dpi=DPI):
    """Two rooms drawn as double-line walls 1/8" apart (6" at 1/4" = 1'-0"): outside 2..10 x 2..7 in, a wall at x=6."""
    img = Image.new("L", (int(w_in * dpi), int(h_in * dpi)), 255)
    d = ImageDraw.Draw(img)
    p = lambda v: int(round(v * dpi))                                     # noqa: E731
    t = 0.125
    if fill:                                                              # solid (poché) walls
        for x0, y0, x1, y1 in ((2, 2, 10, 2 + t), (2, 7 - t, 10, 7), (2, 2, 2 + t, 7), (10 - t, 2, 10, 7),
                               (6, 2, 6 + t, 7)):
            d.rectangle([p(x0), p(y0), p(x1), p(y1)], fill=0)
    else:
        d.rectangle([p(2), p(2), p(10), p(7)], outline=0, width=2)
        d.rectangle([p(2 + t), p(2 + t), p(10 - t), p(7 - t)], outline=0, width=2)
        d.line([p(6), p(2 + t), p(6), p(7 - t)], fill=0, width=2)
        d.line([p(6 + t), p(2 + t), p(6 + t), p(7 - t)], fill=0, width=2)
    if names:
        d.text((p(3.2), p(4.3)), "KITCHEN", fill=0, font=_font(18))
        d.text((p(7.2), p(4.3)), "LIVING", fill=0, font=_font(18))
        d.text((p(2), p(8.2)), "FLOOR PLAN", fill=0, font=_font(22))
        d.text((p(2), p(8.7)), "SCALE: 1/4\" = 1'-0\"", fill=0, font=_font(14))
    for i in range(12):                                                   # notes: text, never line work
        d.text((p(12), p(2 + i * 0.3)), f"NOTE {i + 1}: VERIFY IN FIELD", fill=0, font=_font(9))
    return img


def save(img, path, dpi=DPI, **kw):
    img.save(path, dpi=(dpi, dpi), **kw)
    return path


def near(a, b, tol=0.05):
    return all(abs(x - y) <= tol for x, y in zip(a, b))


def has_segment(segs, a, b, tol=0.05):
    return any(near((*s[0], *s[1]), (*a, *b), tol) or near((*s[1], *s[0]), (*a, *b), tol) for s in segs)


# ---------------------------------------------------------------- binarize, denoise, deskew      C2S16-R01..R04

def test_ink_and_a_blank_page():                                                  # C2S16-R01
    blank = np.full((200, 300), 250, dtype=np.uint8)
    assert not raster.ink_of(blank).any()
    arr = np.asarray(floor_plan(names=False), dtype=np.uint8)
    ink = raster.ink_of(arr)
    assert 0.001 < ink.mean() < 0.2
    assert 100 < raster.otsu(arr) < 200


def test_specks_are_dropped_and_lines_kept():                                     # C2S16-R02
    ink = np.zeros((100, 200), dtype=bool)
    ink[50, 10:190] = True                                                        # a line
    ink[10, 10] = ink[80, 150] = True                                             # specks
    ink[20, 30:32] = True
    out = raster.denoise(ink)
    assert out[50, 10:190].all() and not out[10, 10] and not out[80, 150] and not out[20, 30:32].any()


@pytest.mark.parametrize("turn", [2.5, -1.2, 4.0])
def test_skew_is_found_and_straightened(turn):                                    # C2S16-R03
    img = floor_plan().rotate(turn, fillcolor=255, resample=Image.Resampling.BICUBIC)
    p = raster.prepare(img, DPI)
    assert abs(p.angle - turn) <= 0.15 and "straightened" in p.notes[0]
    assert has_segment(p.segments, (2, 2), (10, 2), tol=0.06)                      # back where it was drawn


def test_a_straight_scan_is_left_alone():                                         # C2S16-R04
    p = raster.prepare(floor_plan(), DPI)
    assert p.angle == 0 and not p.changed and p.notes == []


# ---------------------------------------------------------------- line work                       C2S16-L01..L03

def test_double_line_walls_become_line_work_and_text_doesnt():                   # C2S16-L01
    segs = raster.prepare(floor_plan(), DPI).segments
    for a, b in [((2, 2), (10, 2)), ((2.125, 2.125), (9.875, 2.125)), ((2, 2), (2, 7)), ((6, 2.125), (6, 6.875))]:
        assert has_segment(segs, a, b), (a, b)
    assert not [s for s in segs if s[0][0] > 11.5]                                # the notes column gave nothing


def test_a_filled_wall_gives_both_its_edges():                                    # C2S16-L02
    segs = raster.prepare(floor_plan(fill=True, names=False), DPI).segments
    top = sorted(s[0][1] for s in segs if abs(s[0][1] - s[1][1]) < 0.01 and s[0][1] < 2.5 and s[1][0] - s[0][0] > 7)
    assert len(top) == 2 and abs(top[1] - top[0] - 0.125) < 0.03


def test_a_solid_block_is_not_line_work():                                        # C2S16-L03
    img = Image.new("L", (6 * DPI, 4 * DPI), 255)
    ImageDraw.Draw(img).rectangle([DPI, DPI, 4 * DPI, 3 * DPI], fill=0)           # a 3" x 2" stamp
    assert raster.prepare(img, DPI).segments == []


# ---------------------------------------------------------------- photos and blueprints           C2S16-P01..P03

def photo_of(img, tilt=60):
    """The page on a dark table, photographed a little from the side (a keystone)."""
    bg = Image.new("L", (img.size[0] + 400, img.size[1] + 400), 40)
    bg.paste(img, (200, 200))
    w, h = bg.size
    return bg.transform(bg.size, Image.Transform.QUAD, (tilt, 0, 0, h, w, h, w - tilt, 0), fillcolor=40)


def test_a_photographed_page_is_squared_up():                                     # C2S16-P01
    page = floor_plan(names=False)
    quad = raster.find_paper(np.asarray(photo_of(page), dtype=np.uint8))
    assert quad is not None and len(quad) == 4
    p = raster.prepare(photo_of(page), DPI, photo=True)
    assert p.squared_up and "squared up" in p.notes[0] and "calibrate" in p.notes[0]
    assert abs(p.image.size[0] / page.size[0] - 1) < 0.05 and abs(p.image.size[1] / page.size[1] - 1) < 0.05
    horiz = [s for s in p.segments if abs(s[0][1] - s[1][1]) < 0.05 and s[1][0] - s[0][0] > 7]
    assert len(horiz) >= 4                                                        # the long walls, straight again


def test_a_scan_that_fills_the_picture_isnt_cropped():                           # C2S16-P02
    assert raster.find_paper(np.asarray(floor_plan(), dtype=np.uint8)) is None
    p = raster.prepare(Image.new("L", (900, 600), 255), DPI, photo=True)
    assert not p.squared_up and "weren't found" in p.notes[0]


def test_a_blueprint_is_read_inverted():                                          # C2S16-P03
    blue = Image.eval(floor_plan(names=False), lambda v: 255 - v)
    p = raster.prepare(blue, DPI)
    assert p.inverted and "blueprint" in p.notes[0]
    assert has_segment(p.segments, (2, 2), (10, 2))
    assert np.asarray(p.image).mean() > 200                                       # dark lines on light paper now


def test_raster_confidence_is_capped():                                           # C2S16-P04
    assert raster.confidence(0.92) == 0.5 and raster.confidence(0.3) == 0.3 and raster.confidence(None) == 0.5


# ---------------------------------------------------------------- the engine on scans             C2S16-E01..E05

def test_a_scanned_image_gives_walls_marked_to_check(tmp_path, no_ocr):          # C2S16-E01
    path = save(floor_plan(), tmp_path / "scan.png")
    s = pe.process(path, "image", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert "_segments" not in s and "_words" not in s
    walls = [o for o in s["objects"] if o["kind"] == "wall"]
    assert len(walls) >= 4
    assert all(o["source"] == "raster" and o["confidence"] <= 0.5 for o in s["objects"])
    assert pe.RASTER_NOTE in s["note"] and "Tesseract" in s["note"]


def test_a_tilted_scan_is_saved_straight(tmp_path, no_ocr):                      # C2S16-E02
    path = save(floor_plan().rotate(3, fillcolor=255, resample=Image.Resampling.BICUBIC), tmp_path / "tilt.png")
    s = pe.process(path, "image", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert "straightened by 3.0 degrees" in s["note"]
    with Image.open(s["image_path"]) as saved:
        again = raster.skew_angle(raster.ink_of(np.asarray(saved.convert("L"), dtype=np.uint8)))
    assert abs(again) < 0.2
    assert near((s["width"], s["height"]), (17.0, 11.0), 0.01)                   # same size, only turned


def test_a_phone_photo_is_squared_up_and_says_so(tmp_path, no_ocr):              # C2S16-E03
    exif = Image.Exif()
    exif[271] = "TestPhone"
    path = tmp_path / "photo.jpg"
    photo_of(floor_plan(names=False)).convert("RGB").save(path, "JPEG", exif=exif, quality=92)
    s = pe.process(path, "image", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert "photo: the page's edges were found" in s["note"] and "a photo has no true size" in s["note"]
    assert any(o["kind"] == "wall" for o in s["objects"])


def test_a_scan_saved_as_pdf_is_straightened_and_traced(tmp_path, no_ocr):       # C2S16-E04
    pdf = tmp_path / "scan.pdf"
    floor_plan().rotate(-2, fillcolor=255, resample=Image.Resampling.BICUBIC).convert("RGB").save(
        pdf, "PDF", resolution=DPI)
    s = pe.process(pdf, "pdf", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert "straightened by 2.0 degrees" in s["note"] and pe.RASTER_NOTE in s["note"]
    walls = [o for o in s["objects"] if o["kind"] == "wall"]
    assert walls and all(o["source"] == "raster" for o in walls)
    with Image.open(s["image_path"]) as saved:
        again = raster.skew_angle(raster.ink_of(np.asarray(saved.convert("L"), dtype=np.uint8)))
    assert abs(again) < 0.25                                                      # the review picture too


def test_a_vector_pdf_without_text_isnt_taken_for_a_scan(tmp_path):              # C2S16-E05
    lines = [(1 + i * 0.5, 1, 1 + i * 0.5, 6) for i in range(30)]
    pdf = make_pdf(tmp_path / "lines.pdf", [{"w": 17, "h": 11, "texts": [], "lines": lines}])
    s = pe.process(pdf, "pdf", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert pe.RASTER_NOTE not in (s.get("note") or "")


@needs_ocr
def test_a_scanned_plan_with_names_gives_rooms_to_check(tmp_path):               # C2S16-E06
    path = save(floor_plan().rotate(1.5, fillcolor=255, resample=Image.Resampling.BICUBIC), tmp_path / "plan.png")
    s = pe.process(path, "image", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    rooms = {o["label"]: o for o in s["objects"] if o["kind"] == "room"}
    assert {"KITCHEN", "LIVING"} <= set(rooms)
    assert all(o["source"] == "raster" and o["confidence"] <= 0.5 for o in rooms.values())


# ---------------------------------------------------------------- needs review in the model     C2S16-N01..N03

def upload_read(db, tmp_path, path, title="Scan job"):
    est = service.create_estimate(db, CTX, title)
    ps = store.upload(db, CTX, est["id"], str(path), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    return est["id"], ps


def test_plans_from_a_scan_are_marked_needs_review(db, tmp_path, no_ocr):       # C2S16-N01
    eid, ps = upload_read(db, tmp_path, save(floor_plan(), tmp_path / "scan.png"))
    m = building.build(db, CTX, estimate_id=eid)
    assert m["method"] == "raster" and m["needs_review"] is True and building.RASTER_NOTE in m["notes"]
    a = trades.answers(db, CTX, "electrical", estimate_id=eid)
    assert a["method"] == "raster" and a["needs_review"] and a["notes"][0] == building.RASTER_NOTE
    f = trades.answers(db, CTX, "framing", estimate_id=eid)
    assert f["needs_review"] and building.RASTER_NOTE in f["notes"]
    srcs = {r[0] for r in db.execute("SELECT o.source FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
                                    " WHERE s.plan_set_id = ?", (ps,))}
    assert srcs == {"raster"}


def test_vector_and_cad_plans_are_not(db, tmp_path):                             # C2S16-N02
    pdf = make_pdf(tmp_path / "v.pdf", [{"w": 36, "h": 24, "texts": title_block("A-101", "FLOOR PLAN"),
                                         "lines": [(2, 2, 10, 2), (10, 2, 10, 7)]}])
    eid, ps = upload_read(db, tmp_path, pdf, "Vector job")
    m = building.build(db, CTX, estimate_id=eid)
    assert m["method"] == "vector" and not m["needs_review"] and building.RASTER_NOTE not in m["notes"]
    ezdxf = pytest.importorskip("ezdxf")
    doc = ezdxf.new()
    doc.modelspace().add_line((0, 0), (120, 0))
    doc.saveas(tmp_path / "c.dxf")
    eid2, _ = upload_read(db, tmp_path, tmp_path / "c.dxf", "CAD job")
    assert building.build(db, CTX, estimate_id=eid2)["method"] == "cad"


def test_measurements_from_a_scan_say_raster_and_ask_to_check(db, tmp_path, monkeypatch):   # C2S16-N03
    eid = service.create_estimate(db, CTX, "Scan measure")["id"]
    found = {"ok": True, "module_id": "flooring", "answers": {"area_sqft": 234.0}, "from": {"area_sqft": "room floor areas"},
             "notes": [building.RASTER_NOTE], "plan_set_ids": [], "source": "wall-and-room model", "model_key": "k1",
             "method": "raster", "needs_review": True}
    monkeypatch.setattr(from_plans, "plan_answers", lambda *a, **k: json.loads(json.dumps(found)))
    with pytest.raises(ConfirmationRequired) as ask:
        from_plans.propose(db, CTX, eid, "flooring")
    assert "scanned or photographed plans: check each one" in ask.value.message
    from_plans.propose(db, CTX, eid, "flooring", confirm=True)
    row = db.execute("SELECT method, confidence, status FROM measurements WHERE estimate_id = ? AND feeds = 'area_sqft'",
                     (eid,)).fetchone()
    assert (row["method"], row["confidence"], row["status"]) == ("raster", "0.5", "proposed")
    found["answers"]["area_sqft"] = 240.0
    from_plans.propose(db, CTX, eid, "flooring", confirm=True)                    # re-read: still raster, still to check
    row = db.execute("SELECT qty, method, status FROM measurements WHERE estimate_id = ? AND feeds = 'area_sqft'",
                     (eid,)).fetchone()
    assert (row["qty"], row["method"], row["status"]) == ("240.00", "raster", "proposed")


# ---------------------------------------------------------------- DWG                             C2S16-D01..D06

def test_finding_a_converter(tmp_path, monkeypatch):                              # C2S16-D01
    monkeypatch.delenv("ESTIMATOR_DWG_CONVERTER", raising=False)
    oda = lambda n: r"C:\ODA\ODAFileConverter.exe" if n == "ODAFileConverter" else None    # noqa: E731
    lib = lambda n: "/usr/bin/dwg2dxf" if n == "dwg2dxf" else None                         # noqa: E731
    both = lambda n: oda(n) or lib(n)                                                      # noqa: E731
    assert dwg.find_converter(which=oda, search_installs=False)["kind"] == "oda"
    assert dwg.find_converter(which=both, search_installs=False)["kind"] == "oda"          # ODA first
    got = dwg.find_converter(which=lib, search_installs=False)
    assert got["kind"] == "libredwg" and got["name"] == "LibreDWG (dwg2dxf)"
    assert dwg.find_converter(which=lambda n: None, search_installs=False) is None
    exe = tmp_path / "dwg2dxf.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("ESTIMATOR_DWG_CONVERTER", str(exe))
    assert dwg.find_converter(which=oda)["path"] == str(exe)                               # the setting wins
    monkeypatch.setenv("ESTIMATOR_DWG_CONVERTER", "off")
    assert dwg.find_converter(which=oda) is None


def fake_converter(monkeypatch, writes=True, err=b""):
    """Stands in for the converter program: writes a DXF where the real one would (or nothing, with an error)."""
    ezdxf = pytest.importorskip("ezdxf")
    calls = []

    class Res:
        stdout, stderr = b"", err

    def run(cmd):
        calls.append(cmd)
        if writes:
            if "-o" in cmd:                                                       # LibreDWG: dwg2dxf -y -o out in
                out = Path(cmd[cmd.index("-o") + 1])
            else:                                                                 # ODA: exe in_dir out_dir ver DXF 0 1 name
                assert cmd[4] == "DXF" and (Path(cmd[1]) / cmd[7]).is_file()
                out = Path(cmd[2]) / (Path(cmd[7]).stem + ".dxf")
            doc = ezdxf.new()
            doc.units = 1                                                         # inches
            msp = doc.modelspace()
            for a, b in (((0, 0), (240, 0)), ((240, 0), (240, 144)), ((240, 144), (0, 144)), ((0, 144), (0, 0))):
                msp.add_line(a, b)
            doc.saveas(out)
        return Res()

    monkeypatch.setattr(dwg, "_run", run)
    return calls


@pytest.mark.parametrize("kind", ["oda", "libredwg"])
def test_a_dwg_is_converted_and_read(tmp_path, monkeypatch, kind):               # C2S16-D02
    calls = fake_converter(monkeypatch)
    exe = tmp_path / ("ODAFileConverter.exe" if kind == "oda" else "dwg2dxf.exe")
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("ESTIMATOR_DWG_CONVERTER", str(exe))
    src = tmp_path / "house.dwg"
    src.write_bytes(b"AC1032" + b"\x00" * 64)
    out = pe.process(src, "dwg", {"work_dir": str(tmp_path / "w")})
    name = "ODA File Converter" if kind == "oda" else "LibreDWG (dwg2dxf)"
    assert out["converted_with"] == name and len(calls) == 1
    s = out["sheets"][0]
    assert f"converted from DWG with the {name}" in s["note"] and s["units"] != "paper_in"
    assert (tmp_path / "w" / "converted" / "house.dxf").is_file()


def test_a_dwg_the_converter_cant_read(tmp_path, monkeypatch):                   # C2S16-D03
    fake_converter(monkeypatch, writes=False, err=b"Error: unsupported file version\n")
    exe = tmp_path / "ODAFileConverter.exe"
    exe.write_bytes(b"MZ")
    src = tmp_path / "bad.dwg"
    src.write_bytes(b"AC1099")
    conv = {"kind": "oda", "path": str(exe), "name": "ODA File Converter"}
    with pytest.raises(ValueError, match="couldn't convert this drawing: Error: unsupported file version"):
        dwg.convert(src, tmp_path / "out", conv)


def test_a_converter_that_hangs_or_wont_start(tmp_path, monkeypatch):          # C2S16-D04
    import subprocess
    src = tmp_path / "a.dwg"
    src.write_bytes(b"AC1032")
    conv = {"kind": "libredwg", "path": str(tmp_path / "dwg2dxf.exe"), "name": "LibreDWG (dwg2dxf)"}

    def slow(cmd):
        raise subprocess.TimeoutExpired(cmd, dwg.TIMEOUT_S)

    real_run = dwg._run
    monkeypatch.setattr(dwg, "_run", slow)
    with pytest.raises(ValueError, match="was stopped"):
        dwg.convert(src, tmp_path / "o", conv)
    monkeypatch.setattr(dwg, "_run", real_run)
    with pytest.raises(ValueError, match="couldn't be started"):                 # the exe isn't there
        dwg.convert(src, tmp_path / "o", conv)


def test_without_a_converter_the_plans_say_how_to_get_one(tmp_path, no_dwg):    # C2S16-D05
    src = tmp_path / "a.dwg"
    src.write_bytes(b"AC1032" + b"\x00" * 64)
    with pytest.raises(ValueError, match="ODA File Converter") as e:
        pe.process(src, "dwg", {"work_dir": str(tmp_path / "w")})
    assert "save the drawing as DXF" in str(e.value)
    assert "converter" in uploads.check_file(str(src))["warnings"][0]


def test_upload_and_tab_follow_the_converter(tmp_path, monkeypatch):             # C2S16-D06
    from estimator.ui import model as ui_model
    exe = tmp_path / "ODAFileConverter.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("ESTIMATOR_DWG_CONVERTER", str(exe))
    src = tmp_path / "a.dwg"
    src.write_bytes(b"AC1032" + b"\x00" * 64)
    assert uploads.check_file(str(src))["warnings"] == []                         # it will be converted
    tools = ui_model.tool_status(which=lambda n: "/usr/bin/dwg2dxf" if n == "dwg2dxf" else None,
                                 find_spec=lambda n: object())
    d = next(t for t in tools if "DWG" in t["tool"])
    assert d["ok"] and "LibreDWG" in d["detail"]

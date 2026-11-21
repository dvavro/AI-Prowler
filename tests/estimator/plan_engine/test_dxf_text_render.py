"""DXF sheet images carry the drawing's text (legend labels, room names, notes): the AI reads the
image, so text that only lives in the objects table is invisible to it (the first live electrical
run's note was "a legend that has no text labels")."""
from collections import Counter
from pathlib import Path

import pytest
from PIL import Image

import estimator.plan_engine as pe
from estimator.plan_engine import dxf_reader

ezdxf = pytest.importorskip("ezdxf")

WIRING_DXF = Path(r"C:\Users\david\Estimate_test_data\house_wiring_2300sf_2story_electrical.dxf")
SMITH_DXF = Path(__file__).parent.parent / "browser" / "fixtures" / "smith_residence_A101.dxf"


def _dark_pixels(img, box):
    """Non-white pixels in a (left, top, right, bottom) pixel box."""
    left, top, right, bottom = box
    crop = img.crop((max(0, left), max(0, top), min(img.width, right), min(img.height, bottom)))
    return sum(1 for px in crop.convert("L").tobytes() if px < 128)


def _dxf(tmp_path, build, units=1, name="plan.dxf"):
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = units
    build(doc, doc.modelspace())
    path = tmp_path / name
    doc.saveas(path)
    return pe.process(path, "dxf", {"work_dir": str(tmp_path / "dxfwork")})["sheets"][0]


def _outline(msp):
    msp.add_line((0, 0), (100, 0))
    msp.add_line((100, 0), (100, 10))
    msp.add_line((100, 10), (0, 10))
    msp.add_line((0, 10), (0, 0))


def test_render_draws_text_at_its_anchor(tmp_path):                                    # C2DXT-01
    def build(doc, msp):
        _outline(msp)
        msp.add_text("LEGEND", dxfattribs={"insert": (10, 5), "height": 2})
    s = _dxf(tmp_path, build)
    scale = (dxf_reader.RENDER_PX - 1) / max(s["width"], s["height"])
    # The text sits at (10, 5) in drawing units; the image flips y, so its baseline is at (10, 10-5).
    x0, y0 = int(10 * scale), int(5 * scale)
    with Image.open(s["image_path"]) as img:
        assert _dark_pixels(img, (x0, y0 - 90, x0 + 400, y0 + 5)) > 100
    # The same drawing without the text has nothing in that box: the pixels are the text.
    s2 = _dxf(tmp_path, lambda d, m: _outline(m), name="plain.dxf")
    with Image.open(s2["image_path"]) as img:
        assert _dark_pixels(img, (x0, y0 - 90, x0 + 400, y0 + 5)) == 0


def test_render_falls_back_when_no_font_exists(tmp_path, monkeypatch):                 # C2DXT-02
    from PIL import ImageFont
    # Block only the fonts the chain looks for: load_default's own bundled font still loads,
    # so this exercises the full chain (listed paths -> system Arial -> PIL default).
    real_truetype = ImageFont.truetype
    blocked = set(dxf_reader._FONT_PATHS) | {"arial.ttf"}
    def _blocked_truetype(path, *args, **kwargs):
        if str(path) in blocked:
            raise OSError("no such font")
        return real_truetype(path, *args, **kwargs)
    monkeypatch.setattr(ImageFont, "truetype", _blocked_truetype)

    def build(doc, msp):
        _outline(msp)
        msp.add_text("LEGEND", dxfattribs={"insert": (10, 5), "height": 2})
    s = _dxf(tmp_path, build)                       # must not raise: PIL's default font draws it
    scale = (dxf_reader.RENDER_PX - 1) / max(s["width"], s["height"])
    x0, y0 = int(10 * scale), int(5 * scale)
    with Image.open(s["image_path"]) as img:
        assert _dark_pixels(img, (x0, y0 - 90, x0 + 400, y0 + 5)) > 0


def test_render_ignores_bad_text(tmp_path):                                            # C2DXT-03
    work = tmp_path / "w"
    work.mkdir()                                    # _render writes sheet_001.png into work
    out = dxf_reader._render(work, [[(0, 0), (100, 0), (100, 10), (0, 10), (0, 0)]], [], 100, 10,
                             [("", 10, 5, 2, "ls", 0), ("   ", 10, 5, 2, "ls", 0),
                              ("ZERO", 10, 5, 0, "ls", 0), ("NEG", 10, 5, -1, "ls", 0),
                              ("BADANCHOR", 10, 5, 2, "xx", 0), ("SHORT", 10, 5),
                              None, ("GOOD", 10, 5, 2, "ls", 0)])
    scale = (dxf_reader.RENDER_PX - 1) / 100
    x0, y0 = int(10 * scale), int(5 * scale)
    with Image.open(out) as img:
        assert _dark_pixels(img, (x0, y0 - 90, x0 + 400, y0 + 5)) > 100


@pytest.mark.skipif(not WIRING_DXF.is_file(), reason="house wiring test DXF not on this machine")
def test_house_wiring_legend_text_is_in_the_render(tmp_path):                          # C2DXT-04
    s = pe.process(WIRING_DXF, "dxf", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert (s["discipline"], s["units"]) == ("electrical", "ft")
    assert len([o for o in s["objects"] if o["kind"] == "symbol"]) == 135
    # 2026-11-20 (David): 17 - "AC 30A" (a 6,912 sq ft 'room' round the whole sheet) and "DRYER 30A" were circuit
    # labels, not rooms.
    rooms = [o["label"] for o in s["objects"] if o["kind"] == "room"]
    assert len(rooms) == 17 and "AC 30A" not in rooms and "DRYER 30A" not in rooms
    texts = {o["label"]: o["geometry"]["points"][0] for o in s["objects"] if o["kind"] == "text"}
    scale = (dxf_reader.RENDER_PX - 1) / max(s["width"], s["height"])
    with Image.open(s["image_path"]) as img:
        for label in ("DUPLEX RECEPTACLE", "GFCI RECEPTACLE"):
            x, y = texts[label]
            px, py = int(x * scale), int(y * scale)
            assert _dark_pixels(img, (px, py - 45, px + 400, py + 5)) > 100, label


def test_smith_dxf_fixture_unchanged(tmp_path):                                        # C2DXT-05
    s = pe.process(SMITH_DXF, "dxf", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert (s["discipline"], s["units"]) == ("architectural", "ft")
    assert dict(Counter(o["kind"] for o in s["objects"])) == {
        "polygon": 5, "line": 16, "text": 11, "wall": 8, "room": 5}
    assert Path(s["image_path"]).is_file()


def test_render_text_anchor_for_centred_text():                                        # C2DXT-06
    doc = ezdxf.new("R2010")
    e = doc.modelspace().add_text("ROOM", dxfattribs={"insert": (50, 70), "height": 6, "halign": 1})
    got = dxf_reader._render_text(e, "ROOM")
    assert got is not None
    text, x, y, height, anchor, rotation = got
    assert (text, height, anchor, rotation) == ("ROOM", 6, "ms", 0)
    assert (x, y) == (50, 70)

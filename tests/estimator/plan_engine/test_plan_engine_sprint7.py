"""Coder 2 Sprint 7 plan-engine parts: viewer tiles (PDF pages rendered per tile, images cut), the layer groups for
the Blueprint Review layers panel, and the pdfium lock shared by plan reading and tiles."""
import threading

import pytest

from estimator.plan_engine import layers, pdf_pages, tiles
from pdfmaker import make_pdf


def _sheet(**kw):
    s = {"id": 7, "page_no": 1, "width": "36", "height": "24", "units": "paper_in", "image_path": None}
    s.update(kw)
    return s


def test_grid_and_boxes():                                                          # C2S7-E01
    assert tiles.grid(36, 24, 0) == (1, 1, 36)
    assert tiles.grid(36, 24, 2) == (4, 3, 9)                                         # 24/9 -> 3 rows
    assert tiles.tile_box(36, 24, 2, 3, 2) == (27, 18, 36, 24)                        # bottom-right, 9 x 6
    assert tiles.tile_box(36, 24, 2, 4, 0) is None and tiles.tile_box(36, 24, 2, 0, 3) is None
    assert tiles.grid(24, 36, 1) == (2, 2, 18)                                        # portrait: 18 + 6 across
    assert tiles.tile_box(24, 36, 1, 1, 1) == (18, 18, 24, 36)


def test_pdf_tiles_match_the_page(tmp_path):                                        # C2S7-E02
    from PIL import Image, ImageChops, ImageStat
    lines = [(1, 1, 30, 1), (1, 1, 1, 20), (5, 5, 25, 18)]
    for rot in (0, 90):
        pdf = make_pdf(tmp_path / f"p{rot}.pdf", [{"w": 36, "h": 24, "lines": lines, "rotate": rot}])
        w, h = (24, 36) if rot else (36, 24)
        s, ps = _sheet(width=str(w), height=str(h)), {"id": rot + 1, "file_type": "pdf", "file_path": str(pdf),
                                                    "processed_at": "t"}
        meta = tiles.info(s, ps)
        assert meta["source"] == "pdf" and meta["max_level"] == 5          # up to 600 DPI since 2026-11-13
        whole = Image.open(tiles.render(s, ps, 0, 0, 0, tmp_path)).convert("L")
        # The four level-1 tiles, put back together and shrunk, are the level-0 tile.
        cols, rows, size = tiles.grid(w, h, 1)
        big = Image.new("L", (round(w * 1024 / max(w, h)), round(h * 1024 / max(w, h))), 255)
        for x in range(cols):
            for y in range(rows):
                t = Image.open(tiles.render(s, ps, 1, x, y, tmp_path)).convert("L")
                big.paste(t, (x * 512, y * 512))
        diff = ImageStat.Stat(ImageChops.difference(big.resize(whole.size), whole)).mean[0]
        assert diff < 3, (rot, diff)
        assert 255 - ImageStat.Stat(whole).mean[0] > 0.5                               # there is line work


def test_image_sheets_cut_from_the_saved_image(tmp_path):                           # C2S7-E03
    from PIL import Image
    png = tmp_path / "scan.png"
    img = Image.new("RGB", (3000, 2000), "white")
    img.paste((255, 0, 0), (1500, 0, 3000, 1000))                                   # top-right quarter red
    img.save(png)
    s = _sheet(width="20", height="13.333", image_path=str(png))
    meta = tiles.info(s, {"id": 1, "file_type": "image", "file_path": None})
    assert meta["source"] == "image" and meta["max_level"] == 3                     # 3000 px -> up to 4096
    t = Image.open(tiles.render(s, {"id": 1, "file_type": "image"}, 1, 1, 0, tmp_path))
    assert t.getpixel((256, 200))[:3] == (255, 0, 0)
    assert tiles.info(_sheet(), {"id": 1, "file_type": "image"}) is None              # no image, nothing to show


def test_cache_is_per_reading_and_bad_tiles_refused(tmp_path):                      # C2S7-E04
    pdf = make_pdf(tmp_path / "c.pdf", [{"w": 36, "h": 24, "lines": [(1, 1, 30, 20)]}])
    s = _sheet()
    a = tiles.render(s, {"id": 1, "file_type": "pdf", "file_path": str(pdf), "processed_at": "one"}, 0, 0, 0, tmp_path)
    b = tiles.render(s, {"id": 1, "file_type": "pdf", "file_path": str(pdf), "processed_at": "two"}, 0, 0, 0, tmp_path)
    assert a != b and a.parent.parent == tmp_path / "tiles"
    for level, x, y in ((6, 0, 0), (-1, 0, 0), (1, 2, 0)):                         # top is 5 at 600 DPI
        with pytest.raises(ValueError):
            tiles.render(s, {"id": 1, "file_type": "pdf", "file_path": str(pdf)}, level, x, y, tmp_path)
    with pytest.raises(ValueError):
        tiles.render(_sheet(width=None), {"id": 1, "file_type": "pdf", "file_path": str(pdf)}, 0, 0, 0, tmp_path)


def test_pdf_reading_and_tiles_share_one_lock(tmp_path):                            # C2S7-E05
    assert isinstance(pdf_pages.PDFIUM_LOCK, type(threading.RLock()))
    pdf = make_pdf(tmp_path / "many.pdf", [{"w": 11, "h": 8.5, "lines": [(1, 1, 9, 7)]}] * 6)
    s = _sheet(width="11", height="8.5")
    errors = []

    def tiles_loop():
        try:
            for i in range(12):
                tiles.render(s, {"id": 1, "file_type": "pdf", "file_path": str(pdf), "processed_at": str(i)},
                             1, 0, 0, tmp_path)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t = threading.Thread(target=tiles_loop)
    t.start()
    count, pages = pdf_pages.read(pdf, tmp_path, 10)
    t.join()
    assert not errors and count == 6 and all(p.image_path for p in pages)


@pytest.mark.parametrize("kind, layer, block, group", [
    ("wall", None, None, "walls"), ("room", None, None, "rooms"), ("opening", None, None, "doors_windows"),
    ("dimension", "A-ANNO-DIMS", None, "dimensions"), ("text", None, None, "text"),
    ("line", "A-WALL", None, "walls"), ("polyline", "A-DOOR", None, "doors_windows"),
    ("symbol", "E-LITE", "LIGHT", "electrical"), ("symbol", "E-POWR", "DUPLEX_OUTLET", "electrical"),
    ("symbol", "P-FIXT", "WC", "plumbing"), ("symbol", "I-FURN", "CHAIR", "furniture"),
    ("symbol", "0", "DOOR_36", "doors_windows"), ("symbol", "A-ANNO-TEXT", "NORTH", "symbols"),
    ("symbol", None, None, "symbols"), ("line", "0", None, "floor_plan"), ("polygon", None, None, "floor_plan"),
    ("line", "M-HVAC-DUCT", None, "mechanical"),
])
def test_layer_groups(kind, layer, block, group):                                   # C2S7-E06
    assert layers.group_for(kind, layer, block) == group


def test_layers_panel_lists_what_is_there():                                        # C2S7-E07
    objs = [{"group": "walls"}, {"group": "walls"}, {"group": "rooms"}]
    panel = layers.panel(objs)
    assert [(g["id"], g["count"]) for g in panel] == [("measurements", 0), ("rooms", 1), ("walls", 2)]
    assert set(layers.GROUP_IDS) >= {g["id"] for g in panel}

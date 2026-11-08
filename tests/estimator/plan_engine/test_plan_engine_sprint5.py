"""Coder 2 Sprint 5: the plan engine reads PDF plan sets (sheets, renders, title blocks, disciplines, viewports and
scales) and scans/photos, in the drawing model's format; then the drawing model saves and measures with it."""
from decimal import Decimal
from pathlib import Path

import pytest

import estimator.plan_engine as pe
from estimator.drawing_model import engine, store
from estimator.plan_engine import pdf_pages, titleblock, viewports

from pdfmaker import make_pdf, title_block      # this folder (pytest puts it on the path)

W, H = 36, 24                                   # ARCH D sheet, inches


def _process(tmp_path, pages, name="plans.pdf"):
    pdf = make_pdf(tmp_path / name, pages)
    work = tmp_path / "work"
    return pe.process(pdf, "pdf", {"work_dir": str(work), "plan_set_id": 1, "estimate_id": 1,
                                   "original_name": name, "revision": 1})


def floor_plan_page(sheet_no="A-101", title="FIRST FLOOR PLAN", views=None, rects=None, tb_scale=None):
    texts = title_block(sheet_no, title, scale=tb_scale)
    for (x, y, label, scale) in (views if views is not None else [(10, 20, "FLOOR PLAN", 'SCALE: 1/4" = 1\'-0"')]):
        texts.append((x, y, 14, label))
        if scale:
            texts.append((x, y + 0.35, 9, scale))
    return {"w": W, "h": H, "texts": texts, "rects": rects or []}


# ---------------------------------------------------------------- sheets, renders, title blocks

def test_sheet_title_block_and_render(tmp_path):
    out = _process(tmp_path, [floor_plan_page()])
    assert out["page_count"] == 1 and len(out["sheets"]) == 1
    s = out["sheets"][0]
    assert (s["sheet_no"], s["title"], s["discipline"]) == ("A-101", "FIRST FLOOR PLAN", "architectural")
    assert (s["revision"], s["revision_date"]) == ("B", "2026-10-01")
    assert (s["units"], s["width"], s["height"]) == ("paper_in", 36.0, 24.0)
    assert s["confidence"] >= 0.8
    from PIL import Image
    with Image.open(s["image_path"]) as img:
        w, h = img.size
    assert max(w, h) <= pdf_pages.MAX_RENDER_PX and abs(w / h - 1.5) < 0.01   # same shape as the sheet


def test_many_pages_each_a_sheet(tmp_path):
    pages = [floor_plan_page("A-101", "FIRST FLOOR PLAN"), floor_plan_page("A-102", "SECOND FLOOR PLAN"),
             floor_plan_page("E-101", "FIRST FLOOR ELECTRICAL PLAN")]
    out = _process(tmp_path, pages)
    assert [s["page_no"] for s in out["sheets"]] == [1, 2, 3]
    assert [s["sheet_no"] for s in out["sheets"]] == ["A-101", "A-102", "E-101"]
    assert out["sheets"][2]["discipline"] == "electrical"
    assert len({s["image_path"] for s in out["sheets"]}) == 3


@pytest.mark.parametrize("sheet_no, title, want", [
    ("A-101", "FLOOR PLAN", "architectural"), ("A-501", "ROOF PLAN", "roof"), ("A-001", "SITE PLAN", "site"),
    ("S-201", "FOUNDATION PLAN", "structural"), ("S2", "FRAMING PLAN", "structural"), ("P-101", "PLUMBING PLAN", "plumbing"),
    ("M1.01", "HVAC PLAN", "mechanical"), ("E-201", "LIGHTING PLAN", "electrical"), ("L-100", "PLANTING PLAN", "landscape"),
    ("C-1", "GRADING PLAN", "civil"), ("FP-101", "SPRINKLER PLAN", "fire"), ("G-001", "COVER SHEET", "general"),
    (None, "ELECTRICAL PLAN", "electrical"), (None, "SOMETHING", "other"), ("Q-1", None, "other"),
])
def test_discipline(sheet_no, title, want):
    assert titleblock.discipline_for(sheet_no, title) == want


def test_title_block_along_the_bottom(tmp_path):
    texts = [(26, 22.6, 8, "SHEET NO."), (26, 22.9, 24, "S-201"), (14, 22.6, 8, "SHEET TITLE"),
             (14, 22.9, 14, "FOUNDATION PLAN"), (10, 12, 14, "FOUNDATION PLAN"), (10, 12.35, 9, 'SCALE: 1/4" = 1\'-0"')]
    s = _process(tmp_path, [{"w": W, "h": H, "texts": texts}])["sheets"][0]
    assert (s["sheet_no"], s["title"], s["discipline"]) == ("S-201", "FOUNDATION PLAN", "structural")


def test_door_tags_dont_win_over_the_sheet_number(tmp_path):
    page = floor_plan_page()
    page["texts"] += [(31, 3, 9, "D3"), (30, 8, 9, "W12")]          # tags inside the right strip, small
    assert _process(tmp_path, [page])["sheets"][0]["sheet_no"] == "A-101"


def test_blank_or_scanned_page_still_a_sheet(tmp_path):
    s = _process(tmp_path, [{"w": 11, "h": 8.5, "texts": [], "rects": [(1, 1, 5, 5)]}])["sheets"][0]
    assert s["sheet_no"] is None and s["title"] is None and s["confidence"] == 0.1 and "scan" in s["note"]
    assert Path(s["image_path"]).is_file()
    assert s["viewports"] == [{"key": "main", "label": None, "bbox": [0.25, 0.25, 10.75, 8.25],
                               "scale_method": "none", "scale_confidence": 0.0}]


def test_rotated_page_is_landscape(tmp_path):
    page = {"w": 24, "h": 36, "texts": [(2, 30, 20, "A-101")], "rotate": 90}
    s = _process(tmp_path, [page])["sheets"][0]
    assert (s["width"], s["height"]) == (36.0, 24.0)
    # Words are in the same (turned) frame as the image, so boxes land on the picture.
    count, pages = pdf_pages.read(tmp_path / "plans.pdf", None, 10, render=False)
    w = pages[0].words[0]
    assert 0 <= w.x0 < w.x1 <= 36 and 0 <= w.top < w.bottom <= 24, (w.x0, w.top, w.x1, w.bottom)


# ---------------------------------------------------------------- viewports and scales

@pytest.mark.parametrize("text, note, ratio, nts", [
    ('SCALE: 1/4" = 1\'-0"', '1/4" = 1\'-0"', Decimal(48), False),
    ('SCALE 1/8"=1\'-0"', '1/8"=1\'-0"', Decimal(96), False),
    ('FLOOR PLAN SCALE: 3/16" = 1\'-0"', '3/16" = 1\'-0"', Decimal(64), False),
    ('1" = 20\'', '1" = 20\'', Decimal(240), False),
    ("SCALE: 1:100", "1:100", Decimal(100), False),
    ("SCALE: NTS", "NTS", None, True),
    ("NOT TO SCALE", "NOT TO SCALE", None, True),
    ('SCALE: 1 1/2" = 1\'-0"', '1 1/2" = 1\'-0"', Decimal(8), False),
    ('SCALE: 1/4" = 1\'-0" UNLESS NOTED', '1/4" = 1\'-0"', Decimal(48), False),
])
def test_scale_from_text(text, note, ratio, nts):
    got = viewports.scale_from_text(text)
    assert got is not None, text
    assert got[0] == note and got[1] == ratio and got[2] is nts


@pytest.mark.parametrize("text", ["SCALE: AS NOTED", "SCALE: AS SHOWN", "KITCHEN", "ROOM 101", "12'-6\"", "SEE A-501",
                                  # found on a real text-heavy PDF: words ending in "nts", and times in notes
                                  "all components and points are listed", "requirements", "MEETING AT 1:30 PM",
                                  "SEE NTS DETAIL ON SHEET A-501", 'WALL IS 1" = 12\' FROM THE CURB PER CIVIL'])
def test_unreadable_or_no_scale_is_skipped(text):
    assert viewports.scale_from_text(text) is None


def test_one_view_is_the_main_viewport(tmp_path):
    vps = _process(tmp_path, [floor_plan_page()])["sheets"][0]["viewports"]
    assert len(vps) == 1
    v = vps[0]
    assert v["key"] == "main" and v["label"] == "FLOOR PLAN" and v["scale_note"] == '1/4" = 1\'-0"'
    assert v["scale_method"] == "note" and v["bbox"][2] <= 36 * 0.78 + 0.01        # stops at the title block


def test_views_side_by_side_get_their_own_scales(tmp_path):
    views = [(4, 20, "POWER PLAN", 'SCALE: 1/8" = 1\'-0"'), (18, 20, "ENLARGED KITCHEN PLAN", 'SCALE: 1/2" = 1\'-0"')]
    vps = _process(tmp_path, [floor_plan_page("E-201", "POWER PLAN", views=views)])["sheets"][0]["viewports"]
    assert [(v["key"], v["label"], v["scale_note"]) for v in vps] == [
        ("v1", "POWER PLAN", '1/8" = 1\'-0"'), ("v2", "ENLARGED KITCHEN PLAN", '1/2" = 1\'-0"')]
    left, right = vps[0]["bbox"], vps[1]["bbox"]
    assert left[2] == right[0] and left[0] < 5 < left[2] < 19 < right[2]               # split between the titles


def test_rows_of_views(tmp_path):
    views = [(4, 9, "DETAIL 1", 'SCALE: 1" = 1\'-0"'), (16, 9, "DETAIL 2", 'SCALE: 1-1/2" = 1\'-0"'),
             (4, 20, "SECTION A", 'SCALE: 1/2" = 1\'-0"')]
    vps = _process(tmp_path, [floor_plan_page("A-501", "DETAILS", views=views)])["sheets"][0]["viewports"]
    by = {v["label"]: v for v in vps}
    assert by["DETAIL 1"]["bbox"][3] <= by["SECTION A"]["bbox"][1] + 0.01          # top row above the bottom row
    assert by["SECTION A"]["bbox"][0] == 0.25 and by["SECTION A"]["bbox"][2] > 25    # alone in its row: full width


def test_a_drawn_frame_is_the_viewport(tmp_path):
    views = [(4, 20, "FLOOR PLAN", 'SCALE: 1/4" = 1\'-0"'), (20, 10, "DETAIL 3", 'SCALE: 1" = 1\'-0"')]
    page = floor_plan_page(views=views, rects=[(18, 2, 27, 11)])
    vps = _process(tmp_path, [page])["sheets"][0]["viewports"]
    detail = next(v for v in vps if v["label"] == "DETAIL 3")
    assert detail["bbox"] == [18.0, 2.0, 27.0, 11.0] and detail["scale_confidence"] == 0.9
    plan = next(v for v in vps if v["label"] == "FLOOR PLAN")
    assert plan["scale_confidence"] < 0.9                                           # laid out, not framed


def test_border_and_small_boxes_are_not_frames(tmp_path):
    page = floor_plan_page(rects=[(0.2, 0.2, 35.8, 23.8), (9.5, 19.8, 13, 20.8)])  # sheet border, a text box
    v = _process(tmp_path, [page])["sheets"][0]["viewports"][0]
    assert v["scale_confidence"] < 0.9


def test_nts_view(tmp_path):
    views = [(4, 20, "FLOOR PLAN", 'SCALE: 1/4" = 1\'-0"'), (20, 20, "WALL TYPES", "SCALE: NTS")]
    vps = _process(tmp_path, [floor_plan_page(views=views)])["sheets"][0]["viewports"]
    walls = next(v for v in vps if v["label"] == "WALL TYPES")
    assert walls["is_nts"] is True and walls["scale_note"] == "NTS"


def test_label_on_the_same_line(tmp_path):
    views = [(4, 20, 'GARAGE PLAN   SCALE: 1/8" = 1\'-0"', None)]
    v = _process(tmp_path, [floor_plan_page(views=views)])["sheets"][0]["viewports"][0]
    assert v["label"] == "GARAGE PLAN" and v["scale_note"] == '1/8" = 1\'-0"'


def test_title_block_scale_when_views_have_none(tmp_path):
    page = floor_plan_page(views=[(10, 20, "FLOOR PLAN", None)], tb_scale='1/8" = 1\'-0"')
    v = _process(tmp_path, [page])["sheets"][0]["viewports"][0]
    assert v["key"] == "main" and v["scale_note"] == '1/8" = 1\'-0"' and v["scale_confidence"] == 0.7


def test_no_scale_anywhere_needs_a_person(tmp_path):
    page = floor_plan_page(views=[(10, 20, "FLOOR PLAN", "SCALE: AS NOTED")])
    v = _process(tmp_path, [page])["sheets"][0]["viewports"][0]
    assert v["scale_method"] == "none" and "scale_note" not in v


# ---------------------------------------------------------------- bad files and other types

def test_too_many_pages(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "MAX_SHEETS", 2)
    with pytest.raises(ValueError, match="at most 2"):
        _process(tmp_path, [floor_plan_page()] * 3)


def test_broken_pdf(tmp_path):
    bad = tmp_path / "bad.pdf"
    bad.write_bytes(b"%PDF-1.4\nthis is not really a pdf")
    with pytest.raises(ValueError, match="can't be opened"):
        pe.process(bad, "pdf", {"work_dir": str(tmp_path / "w")})


def test_dwg_says_how_to_get_it_read(tmp_path):
    # Sprint 6 reads DXF (test_plan_engine_sprint6.py); DWG still needs a converter.
    with pytest.raises(ValueError, match="save the drawing as DXF"):
        pe.process(tmp_path / "a.dwg", "dwg", {"work_dir": str(tmp_path / "w")})


def test_scan_with_dpi(tmp_path):
    from PIL import Image
    p = tmp_path / "scan.png"
    Image.new("RGB", (2400, 1600), "white").save(p, dpi=(200, 200))
    s = pe.process(p, "image", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert (s["width"], s["height"]) == (12.0, 8.0) and "note" not in s
    assert s["viewports"][0]["scale_method"] == "none" and Path(s["image_path"]).is_file()


def test_photo_without_dpi_says_so(tmp_path):
    from PIL import Image
    p = tmp_path / "photo.jpg"
    Image.new("RGB", (1500, 1200), "white").save(p, "JPEG")
    s = pe.process(p, "image", {"work_dir": str(tmp_path / "w")})["sheets"][0]
    assert s["width"] == 10.0 and "150 DPI was assumed" in s["note"]


def test_multipage_tiff(tmp_path):
    from PIL import Image
    p = tmp_path / "set.tif"
    frames = [Image.new("L", (900, 600), 255), Image.new("L", (900, 600), 200)]
    frames[0].save(p, save_all=True, append_images=frames[1:], dpi=(150, 150))
    out = pe.process(p, "image", {"work_dir": str(tmp_path / "w")})
    assert [s["page_no"] for s in out["sheets"]] == [1, 2] and out["sheets"][1]["width"] == 6.0


# ---------------------------------------------------------------- with the drawing model (Jamie's store)

@pytest.fixture
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def test_the_estimator_finds_the_engine_by_itself(real_engine):
    info = engine.engine_info()
    assert info == {"installed": True, "name": pe.ENGINE_NAME}


def test_end_to_end_saved_measured_and_calibrated(db, tmp_path, real_engine):
    from estimator.context import personal_context
    from estimator.estimating import service
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    views = [(4, 20, "FLOOR PLAN", 'SCALE: 1/4" = 1\'-0"'), (20, 20, "WALL TYPES", "SCALE: NTS")]
    pdf = make_pdf(tmp_path / "smith.pdf", [floor_plan_page(views=views), floor_plan_page("E-101", "POWER PLAN",
                                                                                           views=[(10, 20, "POWER PLAN", None)])])
    ps = store.upload(db, ctx, est["id"], str(pdf), confirm=True)["plan_set_id"]
    out = engine.start(db, ctx, ps, confirm=True)
    assert out.get("ok", True) and store.status(db, ctx, ps)["status"] == "processed"
    sheets = store.sheets(db, ctx, ps)["sheets"]
    a101 = next(s for s in sheets if s["sheet_no"] == "A-101")
    e101 = next(s for s in sheets if s["sheet_no"] == "E-101")
    assert a101["discipline"] == "architectural" and e101["discipline"] == "electrical"
    vps = store.viewports(db, ctx, a101["id"])["viewports"]
    plan = next(v for v in vps if v["label"] == "FLOOR PLAN")
    assert Decimal(plan["scale_ratio"]) == 48 and next(v for v in vps if v["label"] == "WALL TYPES")["is_nts"]
    assert Path(store.sheet_image(db, ctx, a101["id"])["path"]).is_file()
    # E-101 has no scale: two-point calibration - 2 inches on the paper is 16 feet -> 1/8" = 1'-0" (96).
    e_vp = store.viewports(db, ctx, e101["id"])["viewports"][0]
    assert e_vp["scale_ratio"] in (None, "")
    done = store.set_scale(db, ctx, e_vp["id"], calibration={"p1": [5, 10], "p2": [7, 10], "distance": "16'"},
                           confirm=True)
    assert Decimal(str(done.get("scale_ratio") or store.viewports(db, ctx, e101["id"])["viewports"][0]["scale_ratio"])) == 96

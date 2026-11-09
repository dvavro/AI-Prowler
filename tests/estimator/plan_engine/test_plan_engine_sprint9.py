"""Coder 2 Sprint 9: OCR (Tesseract) for scans, dimension strings that check each view's scale, schedule tables as
rows by mark, plan tags linked to those rows, and legends with the plan-set symbol dictionary."""
import json
from pathlib import Path

import pytest

import estimator.plan_engine as pe
from estimator.drawing_model import engine, store
from estimator.plan_engine import dimensions, legends, ocr, schedules, tags

from pdfmaker import make_pdf, title_block      # this folder

W, H = 36, 24
QUARTER = 'SCALE: 1/4" = 1\'-0"'
EIGHTH = 'SCALE: 1/8" = 1\'-0"'


def _page(texts=(), lines=(), scale=QUARTER, sheet_no="A-101", title="FIRST FLOOR PLAN"):
    t = title_block(sheet_no, title) + [(4, 21, 14, "FLOOR PLAN")] + list(texts)
    if scale:
        t.append((4, 21.35, 9, scale))
    return {"w": W, "h": H, "texts": t, "lines": list(lines)}


def _process(tmp_path, pages, name="plans.pdf"):
    pdf = make_pdf(tmp_path / name, pages)
    return pe.process(pdf, "pdf", {"work_dir": str(tmp_path / "work")})


DOOR_SCHEDULE = [(20, 2.0, 12, "DOOR SCHEDULE"),
                 (20, 2.5, 8, "MARK"), (21.5, 2.5, 8, "SIZE"), (23, 2.5, 8, "TYPE"), (24.5, 2.5, 8, "REMARKS"),
                 (20, 2.8, 8, "D1"), (21.5, 2.8, 8, "3070"), (23, 2.8, 8, "A"), (24.5, 2.8, 8, "ENTRY"),
                 (20, 3.1, 8, "D2"), (21.5, 3.1, 8, "2868"), (23, 3.1, 8, "B"), (24.5, 3.1, 8, "BEDROOM"),
                 (20, 3.4, 8, "D3"), (21.5, 3.4, 8, "2668"), (23, 3.4, 8, "B"), (24.5, 3.4, 8, "BATH"),
                 (24.5, 3.7, 8, "SELF CLOSING")]
TAGS = [(6, 10, 9, "D1"), (8, 10, 9, "D2"), (10, 10, 9, "D3"), (12, 10, 9, "D3"), (14, 10, 9, "1")]


def _sym(x, y):                                   # a small drawn symbol: a box with a cross
    return [(x, y, x + 0.3, y), (x + 0.3, y, x + 0.3, y + 0.15), (x + 0.3, y + 0.15, x, y + 0.15), (x, y + 0.15, x, y),
            (x, y, x + 0.3, y + 0.15)]


LEGEND = [(20, 12.0, 12, "ELECTRICAL LEGEND"),
          (20, 12.5, 9, "GFI"), (21, 12.5, 9, "DUPLEX RECEPTACLE, GFCI"),
          (21, 12.8, 9, "RECESSED LIGHT FIXTURE"),
          (20, 13.1, 9, "WP"), (21, 13.1, 9, "DUPLEX RECEPTACLE, WEATHERPROOF"),
          (20, 13.4, 9, "XQ"), (21, 13.4, 9, "SPECIAL DEVICE")]
LEGEND_LINES = _sym(20, 12.82)


# ---------------------------------------------------------------- schedules                           C2S9-E01..E03

def test_door_schedule_rows_by_mark(tmp_path):                                       # C2S9-E01
    s = _process(tmp_path, [_page(DOOR_SCHEDULE)])["sheets"][0]
    assert len(s["schedules"]) == 1
    sc = s["schedules"][0]
    assert (sc["schedule_type"], sc["title"]) == ("door", "DOOR SCHEDULE")
    assert [r["mark"] for r in sc["rows"]] == ["D1", "D2", "D3"]
    assert sc["rows"][0]["fields"] == {"MARK": "D1", "SIZE": "3070", "TYPE": "A", "REMARKS": "ENTRY"}
    assert sc["rows"][2]["fields"]["REMARKS"] == "BATH SELF CLOSING"          # the wrapped remark joins its row
    assert all(0 < r["confidence"] <= 0.95 for r in sc["rows"])
    assert set(sc) == {"schedule_type", "title", "bbox", "confidence", "rows"}   # what the drawing model saves


def test_ruled_schedule_and_second_header_row(tmp_path):                             # C2S9-E02
    texts = [(20, 2.0, 12, "WINDOW SCHEDULE"),
             (20.1, 2.5, 8, "MARK"), (21.6, 2.5, 8, "FRAME"), (23.1, 2.5, 8, "WIDTH"),
             (21.6, 2.65, 8, "TYPE"),
             (20.1, 2.95, 8, "W1"), (21.6, 2.95, 8, "VINYL"), (23.1, 2.95, 8, "36"),
             (20.1, 3.25, 8, "W2"), (21.6, 3.25, 8, "ALUM"), (23.1, 3.25, 8, "48")]
    rules = [(x, 2.4, x, 3.5) for x in (20.0, 21.5, 23.0, 24.5)]
    sc = _process(tmp_path, [_page(texts, rules)])["sheets"][0]["schedules"][0]
    assert sc["schedule_type"] == "window"
    assert sc["rows"][1]["fields"] == {"MARK": "W2", "FRAME TYPE": "ALUM", "WIDTH": "48"}


@pytest.mark.parametrize("text, found", [("DOOR SCHEDULE", True), ("LIGHT FIXTURE SCHEDULE", True),
                                         ("PANEL SCHEDULES", True), ("SEE DOOR SCHEDULE ON A-601", False),
                                         ("Door Schedule", False), ("ROOM FINISH SCHEDULE", True)])
def test_schedule_titles(tmp_path, text, found):                                     # C2S9-E03
    texts = [(20, 2.0, 12, text), (20, 2.5, 8, "MARK"), (22, 2.5, 8, "NOTE"), (20, 2.8, 8, "X1"), (22, 2.8, 8, "OK")]
    got = _process(tmp_path, [_page(texts)])["sheets"][0]["schedules"]
    assert bool(got) is found


# ---------------------------------------------------------------- tags                                C2S9-E04

def test_tags_match_schedule_marks_across_the_set(tmp_path):                         # C2S9-E04
    out = _process(tmp_path, [_page(DOOR_SCHEDULE, sheet_no="A-601", title="SCHEDULES"),
                              _page(TAGS, sheet_no="A-101")])
    sched_sheet, plan = out["sheets"]
    assert not [o for o in sched_sheet["objects"] if o.get("tag")]             # schedule cells aren't tags
    found = [o for o in plan["objects"] if o.get("tag")]
    assert sorted(o["tag"] for o in found) == ["D1", "D2", "D3", "D3"]          # a bare "1" isn't a tag
    assert all(o["kind"] == "text" and o["label"] == "door tag" and o["geometry"]["type"] == "point" for o in found)
    assert tags.usable("101") and tags.usable("D3") and not tags.usable("1") and not tags.usable("")


def test_a_tag_in_the_marks_series_is_found_too(tmp_path):
    sched = [t for t in DOOR_SCHEDULE if t[3] not in ("D3", "2668", "BATH", "SELF CLOSING")] + [
        (20, 3.4, 8, "D4"), (21.5, 3.4, 8, "2668")]
    plan = _process(tmp_path, [_page(sched + [(10, 10, 9, "D3"), (12, 10, 9, "W3")])])["sheets"][0]
    found = {o["tag"]: o["confidence"] for o in plan["objects"] if o.get("tag")}
    assert found == {"D3": 0.55}                       # D1, D2, D4 make a "D" series; W has no marks
    assert tags.series_of({"D1": "door", "D2": "door", "W1": "window", "101": "finish"}) == {"D": "door"}


# ---------------------------------------------------------------- legends and the dictionary          C2S9-E05..E07

def test_legend_entries_codes_symbols_and_item_types(tmp_path):                      # C2S9-E05
    out = _process(tmp_path, [_page(LEGEND, LEGEND_LINES, sheet_no="E-001", title="ELECTRICAL LEGEND AND NOTES")])
    s = out["sheets"][0]
    assert [(lg["title"], lg["discipline"]) for lg in s["legends"]] == [("ELECTRICAL LEGEND", "electrical")]
    assert set(s["legends"][0]) == {"title", "discipline", "bbox", "confidence"}
    d = json.loads((tmp_path / "work" / "symbol_dictionary.json").read_text(encoding="utf-8"))
    entries = d["legends"][0]["entries"]
    assert d["engine"] == pe.ENGINE_NAME and d["legends"][0]["sheet_no"] == "E-001"
    by_desc = {e["description"]: e for e in entries}
    assert by_desc["DUPLEX RECEPTACLE, GFCI"]["code"] == "GFI"
    assert by_desc["DUPLEX RECEPTACLE, GFCI"]["item_type"] == "duplex_receptacle_gfci"
    light = by_desc["RECESSED LIGHT FIXTURE"]
    assert light["has_symbol"] and light["item_type"] == "light_recessed" and light["code"] is None
    assert (tmp_path / "work" / light["template"]).is_file()                    # the cropped symbol picture
    assert by_desc["DUPLEX RECEPTACLE, WEATHERPROOF"]["item_type"] == "duplex_receptacle_wp"
    special = by_desc["SPECIAL DEVICE"]
    assert special["item_type"] is None and special["trade"] == "electrical" and special["needs_confirming"]
    assert not by_desc["DUPLEX RECEPTACLE, GFCI"]["needs_confirming"]


@pytest.mark.parametrize("desc, item, trade", [
    ("Duplex receptacle", "duplex_receptacle", "electrical"), ("GFCI receptacle", "duplex_receptacle_gfci", "electrical"),
    ("Single pole switch", "switch", "electrical"), ("3-WAY SWITCH", "switch_3way", "electrical"),
    ("Smoke detector", "smoke_detector", "electrical"), ("Panelboard", "panel", "electrical"),
    ("Junction box, ceiling", "junction_box", "electrical"), ("Water closet", "water_closet", "plumbing"),
    ("Floor drain", "floor_drain", "plumbing"), ("Supply diffuser", "supply_diffuser", "mechanical"),
    ("Outvent", None, None), ("Sprinkler head", "sprinkler_head", "fire")])
def test_item_types(desc, item, trade):                                              # C2S9-E06
    assert legends.item_type(desc) == (item, trade)


def test_abbreviations_and_store_dictionary(db, tmp_path, real_engine):              # C2S9-E07
    texts = LEGEND + [(14, 2, 12, "ABBREVIATIONS"), (14, 2.5, 8, "AFF"), (15, 2.5, 8, "ABOVE FINISHED FLOOR"),
                      (14, 2.8, 8, "TYP"), (15, 2.8, 8, "TYPICAL")]
    pdf = make_pdf(tmp_path / "e.pdf", [_page(texts, LEGEND_LINES, sheet_no="E-001", title="ELECTRICAL NOTES")])
    ctx, ps = _read_into_store(db, pdf)
    out = store.legends(db, ctx, ps)
    assert {lg["title"] for lg in out["legends"]} == {"ELECTRICAL LEGEND", "ABBREVIATIONS"}
    d = out["symbol_dictionary"]
    abbr = [e for e in d if e["legend"] == "ABBREVIATIONS"]
    assert [(e["code"], e["description"], e["item_type"]) for e in abbr] == [("AFF", "ABOVE FINISHED FLOOR", None),
                                                                             ("TYP", "TYPICAL", None)]
    assert any(e["item_type"] == "light_recessed" and e["sheet_no"] == "E-001" for e in d)


# ---------------------------------------------------------------- dimensions                          C2S9-E08..E10

DIMS = [(5, 7.75, 9, "10'-0\""), (6, 9.75, 9, "20'-0\""), (5, 11.75, 9, "5'-0\"")]
DIM_LINES = [(4, 8, 6.5, 8), (4, 10, 9, 10), (4, 12, 5.25, 12)]


@pytest.mark.parametrize("text, ok, inches", [("12'-6\"", True, 150), ("3'-0 1/2\"", True, 36.5), ("24'", True, 288),
                                               ("8\"", True, 8), ("24'-0", True, 288), ("A-101", False, None),
                                               ("1/4\"", False, None), ("3070", False, None)])
def test_dimension_strings(text, ok, inches):                                        # C2S9-E08
    assert dimensions.is_dimension(text) is ok
    if ok:
        assert float(dimensions.value_inches(text)) == inches


def test_a_view_with_no_scale_gets_one_from_its_dimensions(tmp_path):                # C2S9-E09
    s = _process(tmp_path, [_page(DIMS, DIM_LINES, scale=None)])["sheets"][0]
    vp = s["viewports"][0]
    assert (vp["scale_method"], vp["scale_ratio"]) == ("dimension", 48)
    assert 0.55 < vp["scale_confidence"] <= 0.85 and "agree on 1/4\" = 1'-0\"" in s["note"]
    dims = [o for o in s["objects"] if o["kind"] == "dimension"]
    assert sorted(o["label"] for o in dims) == ["10'-0\"", "20'-0\"", "5'-0\""]
    assert all(o["geometry"]["type"] == "line" for o in dims)


def test_dimensions_check_the_written_scale(tmp_path):                               # C2S9-E10
    agree = _process(tmp_path, [_page(DIMS, DIM_LINES, scale=QUARTER)])["sheets"][0]
    assert agree["viewports"][0]["scale_method"] == "note" and agree["viewports"][0]["scale_confidence"] > 0.7
    wrong = _process(tmp_path, [_page(DIMS, DIM_LINES, scale=EIGHTH)], name="b.pdf")["sheets"][0]
    assert wrong["viewports"][0]["scale_method"] == "note"                         # what was drawn is kept...
    assert "check it" in wrong["note"]                                             # ...but a person is told


def test_a_dimension_without_a_line_is_a_point_and_doesnt_vote(tmp_path):
    s = _process(tmp_path, [_page([(5, 7.75, 9, "10'-0\"")], scale=None)])["sheets"][0]
    d = next(o for o in s["objects"] if o["kind"] == "dimension")
    assert d["geometry"]["type"] == "point" and s["viewports"][0]["scale_method"] == "none"


# ---------------------------------------------------------------- OCR                                 C2S9-E11..E13

needs_ocr = pytest.mark.skipif(not ocr.available(), reason="Tesseract isn't installed on this PC")


def _scan(path: Path, lines, w_in=11, h_in=8.5, dpi=200, fmt="PNG"):
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("L", (int(w_in * dpi), int(h_in * dpi)), 255)
    draw = ImageDraw.Draw(img)
    for (x, y, pt, text) in lines:
        try:
            font = ImageFont.truetype("arial.ttf", int(pt / 72 * dpi))
        except OSError:
            font = ImageFont.load_default()
        draw.text((x * dpi, y * dpi), text, fill=0, font=font)
    img.save(path, fmt, dpi=(dpi, dpi), **({"resolution": dpi} if fmt == "PDF" else {}))
    return path


SCAN_TEXT = [(1, 1, 24, "DOOR SCHEDULE"), (1, 1.6, 14, "MARK"), (3, 1.6, 14, "SIZE"), (5, 1.6, 14, "REMARKS"),
             (1, 2.0, 14, "D1"), (3, 2.0, 14, "3070"), (5, 2.0, 14, "ENTRY"),
             (1, 2.4, 14, "D2"), (3, 2.4, 14, "2868"), (5, 2.4, 14, "BEDROOM"),
             (1, 6, 24, "FLOOR PLAN"), (6, 6, 24, "D1")]


@needs_ocr
def test_ocr_words_land_in_sheet_inches(tmp_path):                                   # C2S9-E11
    from PIL import Image
    path = _scan(tmp_path / "a.png", [(2, 3, 30, "KITCHEN")], dpi=150)
    with Image.open(path) as img:
        words = ocr.words_from_image(img, 150)
    w = next(w for w in words if w.text == "KITCHEN")
    assert abs(w.x0 - 2) < 0.15 and 2.9 < w.top < 3.4 and 20 < w.size < 40


@needs_ocr
def test_scanned_image_reads_schedule_and_tags(tmp_path):                            # C2S9-E12
    out = pe.process(_scan(tmp_path / "scan.png", SCAN_TEXT), "image", {"work_dir": str(tmp_path / "work")})
    s = out["sheets"][0]
    assert "_words" not in s and "OCR" in s["note"]
    sc = s["schedules"][0]
    assert sc["schedule_type"] == "door" and [r["mark"] for r in sc["rows"]] == ["D1", "D2"]
    tagged = [o for o in s["objects"] if o.get("tag")]
    assert [o["tag"] for o in tagged] == ["D1"] and tagged[0]["source"] == "raster"


@needs_ocr
def test_scan_saved_as_pdf_is_read_by_ocr(tmp_path):                                 # C2S9-E13
    pdf = _scan(tmp_path / "scan.pdf", SCAN_TEXT, fmt="PDF")
    s = pe.process(pdf, "pdf", {"work_dir": str(tmp_path / "work")})["sheets"][0]
    assert "text read by OCR" in s["note"] and s["schedules"][0]["rows"][0]["mark"] == "D1"


@pytest.fixture
def no_ocr(monkeypatch):
    monkeypatch.setenv("ESTIMATOR_TESSERACT", "off")
    ocr.reset()
    yield
    monkeypatch.delenv("ESTIMATOR_TESSERACT")
    ocr.reset()


def test_without_tesseract_scans_still_read_and_say_so(tmp_path, no_ocr):            # C2S9-E14
    assert not ocr.available()
    img = pe.process(_scan(tmp_path / "scan.png", SCAN_TEXT), "image", {"work_dir": str(tmp_path / "w1")})["sheets"][0]
    assert "Tesseract" in img["note"] and img["viewports"][0]["scale_method"] == "none" and "schedules" not in img
    pdf = make_pdf(tmp_path / "blank.pdf", [{"w": 11, "h": 8.5, "texts": []}])
    s = pe.process(pdf, "pdf", {"work_dir": str(tmp_path / "w2")})["sheets"][0]
    assert "scan" in s["note"] and "Tesseract" in s["note"]


# ---------------------------------------------------------------- saved by the drawing model           C2S9-E15

@pytest.fixture
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _read_into_store(db, path):
    from estimator.context import personal_context
    from estimator.estimating import service
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    ps = store.upload(db, ctx, est["id"], str(path), confirm=True)["plan_set_id"]
    out = engine.start(db, ctx, ps, confirm=True)
    assert out.get("ok", True), out
    return ctx, ps


def test_schedule_rows_are_linked_to_plan_tags(db, tmp_path, real_engine):           # C2S9-E15
    pdf = make_pdf(tmp_path / "set.pdf", [_page(DOOR_SCHEDULE, sheet_no="A-601", title="SCHEDULES"),
                                          _page(TAGS + DIMS, DIM_LINES, scale=None, sheet_no="A-101")])
    ctx, ps = _read_into_store(db, pdf)
    sc = store.schedules(db, ctx, ps)["schedules"][0]
    links = {r["mark"]: len(r["linked_object_ids"]) for r in sc["rows"]}
    assert links == {"D1": 1, "D2": 1, "D3": 2} and sc["unlinked_marks"] == []
    plan = next(s for s in store.sheets(db, ctx, ps)["sheets"] if s["sheet_no"] == "A-101")
    vp = store.viewports(db, ctx, plan["id"])["viewports"][0]
    assert vp["scale_method"] == "dimension"
    assert store.legends(db, ctx, ps)["symbol_dictionary"] == []                # read, but no legends in this set

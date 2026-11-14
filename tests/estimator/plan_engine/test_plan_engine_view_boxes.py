"""2026-11-13 (David): the NTS box on the slab sheet. The title block (drawn down the right edge) was guessed to be a
bottom strip, and a lone "SCALE: NTS" under the footer detail got the whole sheet - cut off above the slab's bottom
and running over the real title block. Now the title block is found by its border line, and each view's box is the
line work above its title; line work outside every view becomes an unscaled "main" view."""
from estimator.plan_engine import pdf_objects, pdf_pages, titleblock, viewports

from pdfmaker import make_pdf      # this folder (pytest puts it on the path)

W, H = 17, 11


def _box(x0, y0, x1, y1):
    return [(x0, y0, x1, y0), (x1, y0, x1, y1), (x1, y1, x0, y1), (x0, y1, x0, y0)]


def _tb_texts():
    return [(15.4, 1.0, 9, "BUILDING CO."), (15.4, 8.6, 8, "SHEET NO."), (15.4, 8.9, 24, "S-1"),
            (15.4, 7.6, 8, "SHEET TITLE"), (15.4, 7.9, 12, "FOUNDATION")]


def _page(tmp_path, lines, texts, name="p.pdf"):
    pdf = make_pdf(tmp_path / name, [{"w": W, "h": H, "lines": lines, "texts": texts}])
    _, pages = pdf_pages.read(pdf, None, 10, render=False)
    return pages[0]


def _footer():
    """A footing detail at the top left, cross-hatched so it is one group of lines."""
    lines = _box(4, 0.6, 7.5, 3.8) + [(4 + k * 0.5, 0.6, 4 + k * 0.5, 3.8) for k in range(1, 7)]
    texts = [(4.8, 4.0, 12, "12X20 MONO FOOTER DETAIL"), (5.4, 4.35, 9, "SCALE: NTS")]
    return lines, texts


def _slab():
    """A slab plan on the right that reaches down past where the old bottom strip started (9.02")."""
    lines = _box(8, 2.8, 14.5, 10.1) + [(8, 6.0, 14.5, 6.0), (11.2, 2.8, 11.2, 10.1)]
    return lines


BORDER = [(15.1, 0.3, 15.1, 10.7)]                     # the title block's left edge
SHEET_EDGE = _box(0.25, 0.25, 16.75, 10.75)            # the sheet's own border: never the title block


# ---------------------------------------------------------------- fix 1: title block by its border line

def test_title_block_found_by_its_border_line(tmp_path):
    page = _page(tmp_path, BORDER + SHEET_EDGE + _slab(), _tb_texts())
    assert titleblock.border_zone(page) == [15.1, 0.0, W, H]
    tb = titleblock.read(page)
    assert tb.zone == [15.1, 0.0, W, H] and tb.sheet_no == "S-1"
    assert viewports.drawing_area(page, tb.zone) == [0.25, 0.25, 15.1, 10.75]    # full height, stops at the block


def test_border_drawn_in_pieces_counts(tmp_path):
    pieces = [(15.1, 0.3, 15.1, 4.0), (15.1, 4.0, 15.1, 7.5), (15.1, 7.5, 15.1, 10.7)]
    page = _page(tmp_path, pieces + _slab(), _tb_texts())
    assert titleblock.border_zone(page) == [15.1, 0.0, W, H]


def test_walls_stacked_at_one_x_are_not_a_border(tmp_path):
    # The same 4" wall drawn three times (a thick wall, a hatch edge): 12" of line, but only 4" of the sheet covered.
    walls = [(13.0, 1.0, 13.0, 5.0)] * 3 + [(13.0, 5.5, 13.0, 9.0)]
    page = _page(tmp_path, walls, [])
    assert titleblock.border_zone(page) is None


def test_a_framed_notes_column_is_not_the_title_block(tmp_path):
    # A full-height frame 7" from the right edge holds general notes - far too wide to be a title block strip.
    page = _page(tmp_path, [(10.0, 0.3, 10.0, 10.7)], [])
    assert titleblock.border_zone(page) is None


def test_no_border_keeps_the_text_guess(tmp_path):
    page = _page(tmp_path, _slab(), _tb_texts())
    assert titleblock.border_zone(page) is None
    assert titleblock.read(page).sheet_no == "S-1"


# ---------------------------------------------------------------- fix 2: each view's box is its own drawing

def test_footer_detail_and_slab_plan_get_their_own_boxes(tmp_path):
    f_lines, f_texts = _footer()
    texts = _tb_texts() + f_texts + [(10.0, 10.2, 12, "FOUNDATION PLAN"), (10.6, 10.5, 9, "SCALE: NTS")]
    page = _page(tmp_path, BORDER + f_lines + _slab(), texts)
    vps = viewports.find(page, titleblock.read(page).zone)
    assert len(vps) == 2, vps
    footer = next(v for v in vps if "FOOTER" in (v["label"] or ""))
    slab = next(v for v in vps if v["label"] == "FOUNDATION PLAN")
    fb, sb = footer["bbox"], slab["bbox"]
    assert fb[0] <= 4 and fb[1] <= 0.6 and fb[2] >= 7.5 and fb[3] < 5          # the detail, and only the detail
    assert sb[0] <= 8 and sb[1] <= 2.8 and sb[2] >= 14.5 and sb[3] >= 10.1      # the whole slab, bottom included
    assert sb[2] <= 15.1                                                        # never over the title block
    assert footer["scale_confidence"] == 0.75


def test_lone_nts_detail_leaves_the_rest_unscaled(tmp_path):
    f_lines, f_texts = _footer()
    page = _page(tmp_path, BORDER + f_lines + _slab(), _tb_texts() + f_texts)
    vps = viewports.find(page, titleblock.read(page).zone)
    assert [v["key"] for v in vps] == ["v1", "main"], vps
    detail, rest = vps
    assert detail["is_nts"] and detail["scale_note"] == "NTS" and detail["bbox"][3] < 5
    assert rest["scale_method"] == "none" and rest["scale_confidence"] == 0.0 and "scale_note" not in rest
    assert rest["bbox"] == [0.25, 0.25, 15.1, 10.75]
    # The slab's lines are read once, by the main view; the detail's only by the detail.
    assert pdf_objects._nested(detail["bbox"], rest["bbox"])
    assert not pdf_objects._nested(rest["bbox"], detail["bbox"])


def test_lone_title_under_the_whole_plan_keeps_the_whole_sheet(tmp_path):
    lines = BORDER + _box(1, 0.6, 14, 9.6) + [(7.5, 0.6, 7.5, 9.6), (1, 5, 14, 5)]
    texts = _tb_texts() + [(6, 9.8, 12, "FLOOR PLAN"), (6.3, 10.15, 9, 'SCALE: 1/4" = 1\'-0"')]
    page = _page(tmp_path, lines, texts)
    vps = viewports.find(page, titleblock.read(page).zone)
    assert len(vps) == 1 and vps[0]["key"] == "main" and vps[0]["bbox"] == [0.25, 0.25, 15.1, 10.75]
    assert vps[0]["scale_note"] == '1/4" = 1\'-0"'


def test_lines_inside_a_nested_detail_are_not_read_twice(tmp_path, monkeypatch):
    f_lines, f_texts = _footer()
    page = _page(tmp_path, BORDER + f_lines + _slab(), _tb_texts() + f_texts)
    vps = viewports.find(page, titleblock.read(page).zone)
    seen = []
    real = pdf_objects.vectors.find_walls
    monkeypatch.setattr(pdf_objects.vectors, "find_walls", lambda segs, ratio: seen.append(list(segs)) or real(segs, ratio))
    pdf_objects.find(page, vps)
    detail_segs, main_segs = seen
    assert detail_segs and main_segs
    d = vps[0]["bbox"]

    def in_detail(s):
        return all(d[0] - 0.02 <= x <= d[2] + 0.02 and d[1] - 0.02 <= y <= d[3] + 0.02 for x, y in s)
    assert all(in_detail(s) for s in detail_segs)
    assert not any(in_detail(s) for s in main_segs)                   # the main view got the slab, not the detail
    assert any(max(s[0][1], s[1][1]) >= 10 for s in main_segs)        # ...including its bottom edge

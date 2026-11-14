"""Find the views on a sheet (main plan, enlarged plans, details) and each one's scale note.

How a view is found: drawings put a title under each view with its scale ("FLOOR PLAN  SCALE: 1/4" = 1'-0"" or
the title with the scale on the line below). Each readable scale note in the drawing area is one view.
- If the view sits inside a drawn frame (a rectangle around it), the frame is its box.
- Otherwise views are laid out in rows (titles at the same height) and each gets the part of the sheet above its
  title, split halfway between neighbours.
- No view scale on the sheet: one "main" viewport over the whole drawing area, with the title block's scale if it has
  one ("SCALE: 1/8" = 1'-0""), otherwise no scale - a person sets it or calibrates from two points.

Every note is checked with the drawing model's own parse_scale, so only scales the Estimator can measure with are
passed on; "AS NOTED" and other unreadable notes are skipped, never guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from estimator.drawing_model import geometry as geo
from estimator.errors import InvalidInput
from estimator.plan_engine.pdf_pages import Line, Page
from estimator.plan_engine.titleblock import _inside, _is_plan_title

# Text after "SCALE" (with or without a colon), or a scale written on its own: 1/4" = 1'-0", 1" = 20', 1:100, NTS.
SCALE_AFTER = re.compile(r"\bSCALE\b\s*[:=]?\s*(.+)$", re.I)
SCALE_ALONE = re.compile(
    r"(\bN\.?\s?T\.?\s?S\b\.?|\bNOT\s+TO\s+SCALE\b|\bFULL\s+SIZE\b"
    r"|\b\d+(?:\s*-\s*\d+/\d+|\s+\d+/\d+|/\d+)?\s*(?:\"|”|''|IN\.?)\s*=\s*\d+(?:\.\d+)?\s*(?:'|’|FT\.?)(?:\s*-?\s*\d+(?:\s*\d+/\d+)?\s*(?:\"|”))?"
    r"|\b1\s*:\s*\d+(?:\.\d+)?\b)", re.I)
# A scale written without the word SCALE only counts when it's (nearly) the whole line, as under a view title - so
# "components", "points" (nts) or "meet at 1:30" in a note never become scales.
ALONE_SLACK = 3
ROW_GAP_IN = 1.5                 # titles within this height of each other are one row of views
LABEL_LOOKUP_IN = 0.9            # a view title is at most this far above its scale line


@dataclass
class ScaleNote:
    note: str
    ratio: object                 # Decimal or None
    is_nts: bool
    line: Line
    with_word_scale: bool         # "SCALE:" was written (more certain than a bare 1/4" = 1'-0")
    label: str | None = None


def _clean(note: str) -> str:
    note = note.replace("”", '"').replace("’", "'").replace("''", '"')
    note = re.sub(r"\s+", " ", note).strip(" .;,")
    return note


def scale_from_text(text: str) -> tuple[str, object, bool, bool] | None:
    """(note, ratio, is_nts, said_scale) for the first readable scale in a line of text, or None."""
    m = SCALE_AFTER.search(text)
    candidates = []
    if m:
        candidates.append((m.group(1), True))
    else:
        for mm in SCALE_ALONE.finditer(text):
            if len(text.strip()) - len(mm.group(1)) <= ALONE_SLACK:
                candidates.append((mm.group(1), False))
    for raw, said in candidates:
        note = _clean(raw)
        for attempt in (note, note.split("  ")[0], note.split(" ")[0]):
            try:
                ratio, nts = geo.parse_scale(attempt)
            except InvalidInput:
                continue
            return attempt, ratio, nts, said
        # e.g. "1/4" = 1'-0" UNLESS NOTED": take the scale part only
        alone = SCALE_ALONE.search(note)
        if alone:
            try:
                ratio, nts = geo.parse_scale(_clean(alone.group(1)))
                return _clean(alone.group(1)), ratio, nts, said
            except InvalidInput:
                pass
    return None


def find_notes(lines: list[Line]) -> list[ScaleNote]:
    out = []
    for ln in lines:
        got = scale_from_text(ln.text)
        if got:
            note, ratio, nts, said = got
            out.append(ScaleNote(note, ratio, nts, ln, said))
    return out


def _label_for(note: ScaleNote, lines: list[Line]) -> str | None:
    """The view's title: text before "SCALE" on the same line, or the title line just above."""
    text = note.line.text
    before = re.split(r"\bSCALE\b", text, maxsplit=1, flags=re.I)[0].strip(" :-")
    if before and not SCALE_ALONE.fullmatch(before.strip()) and re.search(r"[A-Za-z]{3}", before):
        return re.sub(r"\s+", " ", before)[:120]
    best = None
    for ln in lines:
        if ln is note.line:
            continue
        gap = note.line.top - ln.bottom
        overlap = min(ln.x1, note.line.x1) - max(ln.x0, note.line.x0)
        if 0 <= gap <= LABEL_LOOKUP_IN and (overlap > 0 or abs(ln.cx - note.line.cx) < 2.0) \
                and re.search(r"[A-Za-z]{3}", ln.text) and not scale_from_text(ln.text):
            score = (_is_plan_title(ln.text) * 10) + ln.size - gap
            if best is None or score > best[0]:
                best = (score, ln)
    return re.sub(r"\s+", " ", best[1].text)[:120] if best else None


def drawing_area(page: Page, zone: list[float] | None) -> list[float]:
    """The sheet minus its title-block strip, with a small margin."""
    x0, top, x1, bottom = 0.25, 0.25, page.width - 0.25, page.height - 0.25
    if zone:
        if zone[1] <= 0.01:                       # right strip
            x1 = min(x1, zone[0])
        else:                                     # bottom strip
            bottom = min(bottom, zone[1])
    return [round(x0, 3), round(top, 3), round(x1, 3), round(bottom, 3)]


def _frame_for(note: ScaleNote, page: Page, area: list[float]) -> list[float] | None:
    """The smallest drawn rectangle around the note that's big enough to be a view (not a text box, not the border)."""
    sheet_area = page.width * page.height
    best = None
    for r in page.rects:
        x0, top, x1, bottom = r
        a = (x1 - x0) * (bottom - top)
        if a < sheet_area * 0.03 or a > sheet_area * 0.85:
            continue
        if not _inside(note.line.bbox(), [x0, top, x1, bottom]):
            continue
        if not _inside([x0, top, x1, bottom], area):
            continue
        if best is None or a < best[0]:
            best = (a, [round(x0, 3), round(top, 3), round(x1, 3), round(bottom, 3)])
    return best[1] if best else None


def _layout_boxes(notes: list[ScaleNote], area: list[float]) -> list[list[float]]:
    """Each view gets the part of the drawing area above its title, split halfway between the views in its row."""
    order = sorted(range(len(notes)), key=lambda i: notes[i].line.bottom)
    rows: list[list[int]] = []
    for i in order:
        if rows and abs(notes[i].line.bottom - notes[rows[-1][0]].line.bottom) <= ROW_GAP_IN:
            rows[-1].append(i)
        else:
            rows.append([i])
    boxes: list[list[float] | None] = [None] * len(notes)
    top = area[1]
    for ri, row in enumerate(rows):
        bottom = area[3] if ri == len(rows) - 1 else max(notes[i].line.bottom for i in row) + 0.2
        row.sort(key=lambda i: notes[i].line.cx)
        for k, i in enumerate(row):
            left = area[0] if k == 0 else (notes[row[k - 1]].line.cx + notes[i].line.cx) / 2
            right = area[2] if k == len(row) - 1 else (notes[i].line.cx + notes[row[k + 1]].line.cx) / 2
            boxes[i] = [round(left, 3), round(top, 3), round(right, 3), round(min(bottom, area[3]), 3)]
        top = bottom
    return boxes  # type: ignore[return-value]


CELL_IN = 0.1                    # line work is grouped on a grid of this size
DETAIL_ABOVE_IN = 1.5            # a detail's drawing ends at most this far above its title
DETAIL_PAD_IN = 0.15
SPLIT_SHARE = 0.25               # split only when this much of the sheet's line work is outside the detail


def _components(segs: list, area: list[float]) -> list[tuple[list[float], int]]:
    """Groups of touching line work: (bbox, segment count) each. Lines are walked on a 0.1" grid; lines in the same
    or neighbouring cells are one group."""
    parent = list(range(len(segs)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[tuple[int, int], int] = {}
    for i, ((x0, y0), (x1, y1)) in enumerate(segs):
        n = max(1, int(max(abs(x1 - x0), abs(y1 - y0)) / (CELL_IN / 2)))
        for k in range(n + 1):
            t = k / n
            c = (int((x0 + (x1 - x0) * t) / CELL_IN), int((y0 + (y1 - y0) * t) / CELL_IN))
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    j = owner.get((c[0] + dx, c[1] + dy))
                    if j is not None:
                        a, b = root(i), root(j)
                        if a != b:
                            parent[a] = b
            owner.setdefault(c, i)
    groups: dict[int, list[float]] = {}
    counts: dict[int, int] = {}
    for i, ((x0, y0), (x1, y1)) in enumerate(segs):
        r = root(i)
        b = groups.get(r)
        lo_x, hi_x, lo_y, hi_y = min(x0, x1), max(x0, x1), min(y0, y1), max(y0, y1)
        groups[r] = [lo_x, lo_y, hi_x, hi_y] if b is None else [min(b[0], lo_x), min(b[1], lo_y),
                                                                 max(b[2], hi_x), max(b[3], hi_y)]
        counts[r] = counts.get(r, 0) + 1
    return [(groups[r], counts[r]) for r in groups]


def _seg_box(s) -> list[float]:
    return [min(s[0][0], s[1][0]), min(s[0][1], s[1][1]), max(s[0][0], s[1][0]), max(s[0][1], s[1][1])]


def _work_segments(page: Page, area: list[float]) -> list:
    """The drawing's line work: lines in the drawing area, without sheet-long border lines."""
    w, h = page.width, page.height
    return [s for s in (getattr(page, "segments", None) or [])
            if _inside(_seg_box(s), area) and abs(s[1][0] - s[0][0]) < 0.8 * w and abs(s[1][1] - s[0][1]) < 0.8 * h]


def _detail_box(note: ScaleNote, comps: list, area: list[float]) -> list[float] | None:
    """The box around the drawing a view title belongs to (2026-11-13, David): the line work just above the title,
    plus anything wholly inside it. An "NTS" footing detail used to get the whole sheet - or, with two titles, a row
    split halfway between them that cut the slab plan in two."""
    ln = note.line
    picked = [b for b, _ in comps
              if ln.top - DETAIL_ABOVE_IN <= b[3] <= ln.bottom + 0.3
              and b[0] <= ln.x1 + 1.0 and b[2] >= ln.x0 - 1.0]
    if not picked:
        return None
    box = [min(ln.x0, *(b[0] for b in picked)), min(ln.top, *(b[1] for b in picked)),
           max(ln.x1, *(b[2] for b in picked)), max(ln.bottom, *(b[3] for b in picked))]
    for _ in range(2):                              # pieces wholly inside the detail are part of it
        grown = [b for b, _ in comps if b[0] >= box[0] - 0.3 and b[1] >= box[1] - 0.3
                 and b[2] <= box[2] + 0.3 and b[3] <= box[3] + 0.3]
        box = [min(box[0], *(b[0] for b in grown)), min(box[1], *(b[1] for b in grown)),
               max(box[2], *(b[2] for b in grown)), max(box[3], *(b[3] for b in grown))]
    box = [max(area[0], box[0] - DETAIL_PAD_IN), max(area[1], box[1] - DETAIL_PAD_IN),
           min(area[2], box[2] + DETAIL_PAD_IN), min(area[3], box[3] + DETAIL_PAD_IN)]
    return [round(v, 3) for v in box]


def _size(b: list[float]) -> float:
    return max(0.0, b[2] - b[0]) * max(0.0, b[3] - b[1])


def _overlap(a: list[float], b: list[float]) -> float:
    return _size([max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])])


def _cluster_boxes(notes: list[ScaleNote], frames: list, segs: list, area: list[float]) -> dict[int, list] | None:
    """A box from the line work for every view without a frame, or None when that doesn't give clean, separate views
    (then the row layout is used, as before)."""
    unframed = [i for i, f in enumerate(frames) if not f]
    if not unframed or len(segs) < 4:
        return None
    comps = _components(segs, area)
    boxes = {i: _detail_box(notes[i], comps, area) for i in unframed}
    if not all(boxes.values()):
        return None
    every = list(boxes.values()) + [f for f in frames if f]
    for a in range(len(every)):
        for b in range(a + 1, len(every)):
            if _overlap(every[a], every[b]) > 0.2 * min(_size(every[a]), _size(every[b])):
                return None
    return boxes  # type: ignore[return-value]


def find(page: Page, zone: list[float] | None) -> list[dict]:
    """The viewports for the drawing model (engine contract: key, label, bbox, scale_note, scale_method, ...)."""
    area = drawing_area(page, zone)
    drawing_lines = [ln for ln in page.lines if zone is None or not _inside(ln.bbox(), zone)]
    notes = find_notes(drawing_lines)
    if not notes:
        sheet_note = None
        if zone:
            tb_notes = find_notes([ln for ln in page.lines if _inside(ln.bbox(), zone)])
            sheet_note = tb_notes[0] if tb_notes else None
        vp = {"key": "main", "label": None, "bbox": area}
        if sheet_note:
            vp.update(scale_note=sheet_note.note, scale_method="note", scale_confidence=0.7)
        else:
            vp.update(scale_method="none", scale_confidence=0.0)
        return [vp]
    for n in notes:
        n.label = _label_for(n, drawing_lines)
    frames = [_frame_for(n, page, area) for n in notes]
    segs = _work_segments(page, area)
    clustered = _cluster_boxes(notes, frames, segs, area)
    leftover = False
    if clustered:
        views = [f for f in frames if f] + list(clustered.values())
        outside = sum(1 for s in segs if not any(_inside(_seg_box(s), v) for v in views))
        leftover = outside >= SPLIT_SHARE * len(segs)
        # A lone title whose drawing is (nearly) the whole sheet keeps the whole drawing area, as before.
        if len(notes) == 1 and not frames[0] and (not leftover or _size(clustered[0]) > 0.6 * _size(area)):
            clustered, leftover = None, False
    layout = _layout_boxes(notes, area)
    out = []
    for i, n in enumerate(sorted(range(len(notes)), key=lambda j: (notes[j].line.top, notes[j].line.x0))):
        note = notes[n]
        if frames[n]:
            bbox, conf = frames[n], 0.9
        elif clustered:
            bbox, conf = clustered[n], 0.75
        else:
            bbox, conf = layout[n], 0.65
        if not note.with_word_scale:
            conf -= 0.1
        out.append({"key": "main" if len(notes) == 1 and not leftover else f"v{i + 1}", "label": note.label,
                    "bbox": bbox, "scale_note": note.note, "scale_method": "note", "scale_confidence": round(conf, 2),
                    **({"is_nts": True} if note.is_nts else {})})
    if leftover:
        # The rest of the sheet has no scale of its own: a person sets it or calibrates (details inside it are
        # read by their own view, not this one).
        out.append({"key": "main", "label": None, "bbox": area, "scale_method": "none", "scale_confidence": 0.0})
    return out

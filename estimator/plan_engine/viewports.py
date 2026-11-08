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
    layout = _layout_boxes(notes, area)
    out = []
    for i, n in enumerate(sorted(range(len(notes)), key=lambda j: (notes[j].line.top, notes[j].line.x0))):
        note = notes[n]
        frame = _frame_for(note, page, area)
        bbox, conf = (frame, 0.9) if frame else (layout[n], 0.65)
        if not note.with_word_scale:
            conf -= 0.1
        out.append({"key": "main" if len(notes) == 1 else f"v{i + 1}", "label": note.label, "bbox": bbox,
                    "scale_note": note.note, "scale_method": "note", "scale_confidence": round(conf, 2),
                    **({"is_nts": True} if note.is_nts else {})})
    return out

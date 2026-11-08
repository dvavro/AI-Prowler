"""Drawing objects on a PDF sheet: walls and rooms in each viewport, measured later with that viewport's own scale.

Each viewport is read on its own: only the line work inside its box, its own scale for the wall-thickness check,
and the room names written inside it. The title block and anything outside a viewport are left alone.
"""
from __future__ import annotations

from estimator.drawing_model import geometry as geo
from estimator.errors import InvalidInput
from estimator.plan_engine import vectors
from estimator.plan_engine.pdf_pages import Page
from estimator.plan_engine.titleblock import _inside

MAX_OBJECTS_PER_SHEET = 5000


def _ratio(vp: dict) -> float | None:
    """Real inches per paper inch for this viewport, or None (no scale, or NTS)."""
    if vp.get("is_nts") or not vp.get("scale_note"):
        return None
    try:
        ratio, nts = geo.parse_scale(vp["scale_note"])
    except InvalidInput:
        return None
    return None if nts or ratio is None else float(ratio)


def _room_labels(page: Page, box: list[float], skip: set[str]) -> list[tuple[str, tuple[float, float]]]:
    out = []
    for ln in page.lines:
        if not _inside(ln.bbox(), box):
            continue
        text = ln.text.strip()
        if text.upper() in skip or not vectors.is_room_name(text):
            continue
        out.append((text, ((ln.x0 + ln.x1) / 2, (ln.top + ln.bottom) / 2)))
    return out


def find(page: Page, viewports: list[dict]) -> tuple[list[dict], list[str]]:
    """(objects, notes) for one sheet."""
    segments = vectors.clean_segments(page.segments)
    objects: list[dict] = []
    notes: list[str] = []
    for vp in viewports:
        box = vp.get("bbox")
        if not box:
            continue
        segs = [s for s in segments if vectors.inside(s, box, pad=0.02)]
        if not segs:
            continue
        ratio = _ratio(vp)
        walls = vectors.find_walls(segs, ratio)
        objects += vectors.wall_objects(walls, vp["key"], "vector")
        # Room-sized: at least 12 sq ft real (or 1/4 sq in on unscaled paper), at most 70% of the view.
        min_area = vectors.ROOM_MIN_SQFT * 144 / (ratio * ratio) if ratio else 0.25
        max_area = (box[2] - box[0]) * (box[3] - box[1]) * 0.7
        skip = {(vp.get("label") or "").upper()}
        rooms, note = vectors.find_rooms(segs, _room_labels(page, box, skip), min_area, max_area, simplify=0.01)
        objects += vectors.room_objects(rooms, vp["key"], "vector")
        if note:
            notes.append(f"{vp.get('label') or vp['key']}: {note}")
        if len(objects) >= MAX_OBJECTS_PER_SHEET:
            notes.append(f"stopped at {MAX_OBJECTS_PER_SHEET} objects on this sheet")
            return objects[:MAX_OBJECTS_PER_SHEET], notes
    return objects, notes

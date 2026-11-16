"""Where the AI's concrete measurements are on the drawing, and areas a person adds or takes away (2026-11-16, David).

"Is it possible that when you click on the equations to compute the volume say of the footer or the base or the slab
area in the equation that it would select it and highlight the area in the drawing so that the user could visually
inspect the area?" ... "I want the user to be able to add area to be included in the calculation, for example the
sloped edge ... by adding three points and assuming to scale drawing" ... "the user should be able to subtract area
that wasn't accounted for by the AI as well."

The AI reads the slab's dimensions as text, so its measurements have no shape. The app places them:

* fit_slab - the slab rectangle (width x length at the view's calibrated scale) slid onto the drawing's own edges:
  the placement whose four sides lie along the most drawn line length wins. A plan whose drawn edges don't line up
  with the read dimensions gets no outline (and says so) instead of a guess.
* the footer is a band inside that outline, the footer's width wide; its middle line is what the footer length runs
  along; the forms are the outline itself; the footer section is shown by its detail's frame.
* area_of - a polygon a person clicked (3+ points) in real square inches, from the view's scale. A view drawn "not to
  scale" (a detail) needs its own scale first - the auto calibrator sets it from the detail's written dimensions.

The app does the geometry; nothing here is AI.
"""
from __future__ import annotations

import json
import math

from estimator.takeoff import slab_find

LINE_KINDS = ("line", "polyline", "polygon", "wall")   # drawn edges (not dimensions, text or symbols)
STRAIGHT = 0.02                 # a segment is horizontal / vertical when it leans less than this (paper in)
ON_EDGE = 0.04                  # a drawn segment lies on a side of the slab when within this (paper in)
MIN_COVER = 0.30                # the four sides must lie on drawn lines for at least this share of the perimeter
OVERSHOOT = 0.10                # a drawn edge may run this far past a corner (paper in, or 2% of the side)


def _r(v: float) -> float:
    return round(float(v), 4)


def segments(conn, company_id: str, viewport_id: int) -> list[tuple]:
    """The view's drawn straight segments ((x0, y0), (x1, y1)) in sheet units."""
    out = []
    for r in conn.execute(f"SELECT geometry_json FROM drawing_objects WHERE company_id = ? AND viewport_id = ? AND kind IN"
                          f" ({','.join('?' * len(LINE_KINDS))})", (company_id, int(viewport_id), *LINE_KINDS)):
        try:
            g = json.loads(r["geometry_json"] or "{}")
            pts = [(float(p[0]), float(p[1])) for p in g.get("points") or []]
        except (TypeError, ValueError, IndexError):
            continue
        if len(pts) < 2:
            continue
        closed = [pts[0]] if g.get("type") == "polygon" else []
        out += list(zip(pts, pts[1:] + closed))
    return out


def _cover(segs_h, segs_v, x0, y0, w, h) -> tuple[float, set] | None:
    """How much drawn line lies along the four sides of the rectangle, and which sides it is on. None when a drawn line
    on a side runs on past the corner - a slab's edge stops at its corner, so that rectangle is too small for it."""
    x1, y1 = x0 + w, y0 + h
    total, sides = 0.0, set()
    for segs, lo, hi, size, axis_sides in ((segs_h, x0, x1, w, (("top", y0), ("bottom", y1))),
                                           (segs_v, y0, y1, h, (("left", x0), ("right", x1)))):
        over = max(OVERSHOOT, 0.02 * size)
        for (ax, ay), (bx, by) in segs:
            at_line = (ay + by) / 2 if segs is segs_h else (ax + bx) / 2
            a, b = (min(ax, bx), max(ax, bx)) if segs is segs_h else (min(ay, by), max(ay, by))
            for side, at in axis_sides:
                if abs(at_line - at) > ON_EDGE:
                    continue
                got = min(b, hi) - max(a, lo)
                if got <= 0:
                    continue
                if a < lo - over or b > hi + over:
                    return None
                total += got
                if got >= 0.25 * size:
                    sides.add(side)
    return total, sides


def fit_slab(conn, company_id: str, viewport_id: int, width_in: float, length_in: float) -> dict:
    """Place a width x length (real inches) slab on the view's drawn edges.

    {"ok": True, "points": 4 corners, "w": paper width, "h": paper height, "ratio", "cover_pct", "sides"} or
    {"ok": False, "reason": ...}. Both ways round are tried (the width may run up the sheet)."""
    vp = conn.execute("SELECT * FROM viewports WHERE id = ? AND company_id = ?", (int(viewport_id), company_id)).fetchone()
    ratio = slab_find._scale_ratio(vp)
    if not ratio:
        return {"ok": False, "reason": "the plan view has no scale yet, so the slab can't be placed on it"}
    segs = segments(conn, company_id, viewport_id)
    best = None
    for w, h in ((width_in / ratio, length_in / ratio), (length_in / ratio, width_in / ratio)):
        least = 0.15 * min(w, h)
        hs = [s for s in segs if abs(s[0][1] - s[1][1]) <= STRAIGHT and abs(s[0][0] - s[1][0]) >= least]
        vs = [s for s in segs if abs(s[0][0] - s[1][0]) <= STRAIGHT and abs(s[0][1] - s[1][1]) >= least]
        xs = {round((a[0] + b[0]) / 2, 4) for a, b in vs}
        ys = {round((a[1] + b[1]) / 2, 4) for a, b in hs}
        for x0 in {x for v in xs for x in (v, v - w)}:
            for y0 in {y for v in ys for y in (v, v - h)}:
                got = _cover(hs, vs, x0, y0, w, h)
                if got is None:
                    continue
                total, sides = got
                if (best is None or total > best[0] + 1e-9) and {"top", "bottom"} & sides and {"left", "right"} & sides:
                    best = (total, x0, y0, w, h, sides)
    if best is None:
        return {"ok": False, "reason": "no drawn edges on the plan line up with the slab's written dimensions"}
    total, x0, y0, w, h, sides = best
    pct = total / (2 * (w + h))
    if pct < MIN_COVER:
        return {"ok": False, "reason": f"only {round(pct * 100)}% of the slab's outline lies on drawn lines - not enough"
                                      " to place it surely"}
    pts = [[_r(x0), _r(y0)], [_r(x0 + w), _r(y0)], [_r(x0 + w), _r(y0 + h)], [_r(x0), _r(y0 + h)]]
    return {"ok": True, "points": pts, "w": _r(w), "h": _r(h), "ratio": ratio, "cover_pct": round(pct * 100),
            "sides": sorted(sides)}


def _inset(pts, d: float) -> list:
    (x0, y0), (x1, _), (_, y1) = pts[0], pts[1], pts[2]
    return [[_r(x0 + d), _r(y0 + d)], [_r(x1 - d), _r(y0 + d)], [_r(x1 - d), _r(y1 - d)], [_r(x0 + d), _r(y1 - d)]]


def footer_band(pts, footer_width_in: float, ratio: float) -> dict:
    """The footer as a band just inside the slab outline: the outer ring one way round, the inner ring the other way, so
    the middle shows through."""
    inner = _inset(pts, footer_width_in / ratio)
    ring = [*pts, pts[0], inner[0], inner[3], inner[2], inner[1], inner[0]]
    return {"type": "polygon", "points": ring}


def footer_middle(pts, footer_width_in: float, ratio: float) -> dict:
    """The footer's middle line, the line its length is measured along."""
    mid = _inset(pts, footer_width_in / ratio / 2)
    return {"type": "polyline", "points": [*mid, mid[0]]}


def outline(pts) -> dict:
    return {"type": "polyline", "points": [*pts, pts[0]]}


def frame(bbox) -> dict:
    x0, y0, x1, y1 = (float(v) for v in bbox)
    return {"type": "polyline", "points": [[x0, y0], [x1, y0], [x1, y1], [x0, y1], [x0, y0]]}


def footer_viewport(conn, sheet_id: int):
    """The footer / footing section detail on the sheet (its view's label names it), else None."""
    rows = conn.execute("SELECT * FROM viewports WHERE sheet_id = ? ORDER BY id", (int(sheet_id),)).fetchall()
    for words in (("FOOTER", "FOOTING"), ("SECTION", "DETAIL")):
        for r in rows:
            if any(w in (r["label"] or "").upper() for w in words) and r["bbox_json"]:
                return r
    return None


def shapes_for(conn, company_id: str, sheet_id: int, viewport_id: int | None, width_in, length_in,
               footer_width_in) -> dict:
    """Every shape the run's formulas point at: {"slab", "forms", "footer", "footer_middle", "detail"} (each
    {sheet_id, viewport_id, type, points}), plus "slab_fit": how the slab was placed or why it couldn't be."""
    out = {}
    if viewport_id and width_in and length_in:
        fit = fit_slab(conn, company_id, viewport_id, float(width_in), float(length_in))
        out["slab_fit"] = {k: fit[k] for k in ("ok", "reason", "cover_pct", "sides") if k in fit}
        if fit["ok"]:
            pts, ratio = fit["points"], fit["ratio"]
            where = {"sheet_id": int(sheet_id), "viewport_id": int(viewport_id)}
            out["slab"] = {**where, "type": "polygon", "points": pts}
            out["forms"] = {**where, **outline(pts)}
            if footer_width_in:
                out["footer"] = {**where, **footer_band(pts, float(footer_width_in), ratio)}
                out["footer_middle"] = {**where, **footer_middle(pts, float(footer_width_in), ratio)}
    det = footer_viewport(conn, sheet_id)
    if det is not None:
        try:
            out["detail"] = {"sheet_id": int(sheet_id), "viewport_id": det["id"], **frame(json.loads(det["bbox_json"]))}
        except (TypeError, ValueError):
            pass
    return out


# ------------------------------------------------------------------ the footer section's parts on its detail

def _num(v) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def section_parts(sec: dict, ratio: float, sheet_id: int) -> dict:
    """The parts the footer cross-section is worked out from, drawn to the detail's scale from where a person placed the
    section (its bottom outside corner, and which way the inside is) - 2026-11-16, David: "the user needs to see the area
    parts to be able to add/sub and make adjustments visually". Each part {type, points, part, label, sign?}:
      below - the footer below the slab (width x depth below the slab): what the footer volume counts
      slab  - the top of the footer that is already in the slab's volume (the slab is measured to its outside edge)
      ledge - the ledge notch at the top outside corner, taken away
      haunch - the sloped haunch under the slab's inside edge, when it is dimensioned
    Drawn to scale, so a part that doesn't sit on the drawing shows a number that is wrong."""
    a = sec.get("anchor") or {}
    try:
        ox, oy = float(a["point"][0]), float(a["point"][1])
        d = 1 if int(a.get("dir", 1)) >= 0 else -1
    except (KeyError, TypeError, ValueError, IndexError):
        return {}
    if not ratio:
        return {}
    H, t, w = _num(sec.get("outside_in")), _num(sec.get("slab_in")), _num(sec.get("width_in"))
    lw, ld, hw, hh = (_num(sec.get(k)) for k in ("ledge_w_in", "ledge_d_in", "haunch_w_in", "haunch_h_in"))
    below = max(0.0, H - t)
    if not (w and H):
        return {}

    def pt(xr, yr):            # real inches from the bottom outside corner: x toward the inside, y up
        return [_r(ox + d * xr / ratio), _r(oy - yr / ratio)]

    def rect(x0, y0, x1, y1):
        return [pt(x0, y0), pt(x1, y0), pt(x1, y1), pt(x0, y1)]

    where = {"sheet_id": int(sheet_id), "viewport_id": a.get("viewport_id")}
    n = lambda v: f"{v:g}"  # noqa: E731
    parts = {"below": {**where, "type": "polygon", "points": rect(0, 0, w, below), "part": "below",
                       "label": f"{n(w)} x {n(below)} = {n(w * below)} sq in"}}
    if t:
        parts["slab"] = {**where, "type": "polygon", "points": rect(0, below, w, H), "part": "slab",
                         "label": f"in the slab ({n(t)} in)"}
    if lw and ld:
        parts["ledge"] = {**where, "type": "polygon", "points": rect(0, H - ld, lw, H), "part": "ledge", "sign": -1,
                          "label": f"ledge -{n(lw * ld)}"}
    if hw and hh:
        parts["haunch"] = {**where, "type": "polygon", "points": [pt(w, below), pt(w + hw, below), pt(w, below - hh)],
                           "part": "haunch", "sign": 1, "label": f"haunch +{n(hw * hh / 2)}"}
    return parts


# ------------------------------------------------------------------ an area a person draws

def paper_area(points) -> float:
    a = 0.0
    for i, (x0, y0) in enumerate(points):
        x1, y1 = points[(i + 1) % len(points)]
        a += x0 * y1 - x1 * y0
    return abs(a) / 2


def clean_points(points) -> list:
    """3+ [x, y] numbers, or ValueError."""
    if not isinstance(points, list) or len(points) < 3:
        raise ValueError("draw at least 3 points around the area")
    try:
        pts = [[_r(p[0]), _r(p[1])] for p in points]
    except (TypeError, ValueError, IndexError):
        raise ValueError("each point must be [x, y]") from None
    if any(not math.isfinite(v) for p in pts for v in p) or len(pts) > 200:
        raise ValueError("those points aren't a shape on the sheet")
    if paper_area(pts) <= 0:
        raise ValueError("those points don't enclose any area")
    return pts


def area_sqin(points, ratio: float) -> float:
    """The real area of a clicked polygon, square inches."""
    return paper_area(points) * ratio * ratio

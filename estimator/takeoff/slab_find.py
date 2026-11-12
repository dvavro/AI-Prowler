"""Find slab rectangles in a viewport's drawing objects - pure geometry, no LLM, no cost.

Phase 1 of the Concrete agent auto-run: the slab outline on a foundation plan is
usually drawn as single LINEs (walls), not a closed polygon, so the outline is
found from line geometry. Near-axis segments are merged into edges, and two
horizontal edges crossed by the same two vertical edges make a rectangle.

Everything here works in paper inches (the units drawing_objects store). The
viewport's scale turns paper inches into feet: feet = paper_inches * scale_ratio / 12.

Corner order is TL, TR, BR, BL with y increasing downwards (screen convention);
a rectangle's corners are cyclic, so the polygon renders the same either way.
"""
from __future__ import annotations

import json
import math
import re

from estimator.errors import NotFound

SEGMENT_KINDS = ("wall", "line", "polyline")
ANGLE_TOL_DEG = 2.0        # a line this close to axis-aligned still counts as an edge
COORD_TOL = 0.05           # paper inches: two lines this close are on the same line
GAP_TOL = 0.1              # paper inches: collinear segments this close merge into one edge
MIN_SIDE = 0.1             # paper inches: shorter sides are draughting noise, not a slab
MAX_CANDIDATES = 50        # the biggest rectangles win; the rest are almost never the slab

_DIM_RE = re.compile(
    r"""^\s*(?:(\d+)\s*'\s*-?\s*)?(?:(\d+)(?:\s+(\d+)\s*/\s*(\d+))?|(\d+)\s*/\s*(\d+))?\s*"?\s*$""")


def _segments(objects: list[dict]) -> list[dict]:
    """Every line piece from wall/line/polyline objects, as {x1, y1, x2, y2, ids}."""
    out = []
    for obj in objects:
        if obj.get("kind") not in SEGMENT_KINDS:
            continue
        geom = obj.get("geometry") or {}
        pts = geom.get("points") or []
        if geom.get("type") == "line" and len(pts) >= 2:
            pairs = [pts[0], pts[-1]]
        elif geom.get("type") == "polyline" and len(pts) >= 2:
            pairs = pts
        else:
            continue
        for (ax, ay), (bx, by) in zip(pairs, pairs[1:]):
            try:
                ax, ay, bx, by = float(ax), float(ay), float(bx), float(by)
            except (TypeError, ValueError):
                continue
            if abs(bx - ax) < 1e-9 and abs(by - ay) < 1e-9:
                continue
            out.append({"x1": ax, "y1": ay, "x2": bx, "y2": by, "ids": {obj["id"]}})
    return out


def _axis(seg: dict, angle_tol_deg: float) -> str | None:
    """'h' or 'v' for a near-axis segment, else None (diagonals are not slab edges)."""
    dx, dy = abs(seg["x2"] - seg["x1"]), abs(seg["y2"] - seg["y1"])
    angle = math.degrees(math.atan2(dy, dx))
    if angle <= angle_tol_deg:
        return "h"
    if angle >= 90.0 - angle_tol_deg:
        return "v"
    return None


def _merge(runs: list[dict], tol: float, gap_tol: float) -> list[dict]:
    """Merge collinear runs on the same line: {at, lo, hi, ids}.

    `runs` are {at (the line's coordinate), lo, hi (the span), ids}. Runs whose
    `at` is within tol share a line; on a line, spans that overlap or nearly
    touch (gap <= gap_tol) become one edge.
    """
    lines: list[dict] = []
    for r in sorted(runs, key=lambda r: (r["at"], r["lo"])):
        line = next((ln for ln in lines if abs(ln["at"] - r["at"]) <= tol), None)
        if line is None:
            line = {"at": r["at"], "spans": []}
            lines.append(line)
        line["spans"].append(r)
    out = []
    for line in lines:
        ats, merged = [], []
        for r in sorted(line["spans"], key=lambda r: r["lo"]):
            ats.append(r["at"])
            if merged and r["lo"] - merged[-1]["hi"] <= gap_tol:
                merged[-1]["hi"] = max(merged[-1]["hi"], r["hi"])
                merged[-1]["ids"] |= r["ids"]
            else:
                merged.append({"lo": r["lo"], "hi": r["hi"], "ids": set(r["ids"])})
        out.append({"at": sum(ats) / len(ats), "spans": merged})
    return out


def _covers(spans: list[dict], lo: float, hi: float, tol: float) -> set | None:
    """The ids of a span covering [lo, hi] (within tol), else None."""
    for s in spans:
        if s["lo"] - tol <= lo and s["hi"] + tol >= hi:
            return s["ids"]
    return None


def find_rectangles(objects: list[dict], tol: float = COORD_TOL, gap_tol: float = GAP_TOL,
                    angle_tol_deg: float = ANGLE_TOL_DEG) -> list[dict]:
    """Rectangles formed by the objects' wall/line edges, biggest first.

    Each candidate: {corners [[x, y] x 4] TL, TR, BR, BL, object_ids [int],
    width, height, area, perimeter} in paper units. [] when nothing closes.
    """
    h_runs, v_runs = [], []
    for seg in _segments(objects):
        axis = _axis(seg, angle_tol_deg)
        if axis == "h":
            h_runs.append({"at": (seg["y1"] + seg["y2"]) / 2, "lo": min(seg["x1"], seg["x2"]),
                           "hi": max(seg["x1"], seg["x2"]), "ids": seg["ids"]})
        elif axis == "v":
            v_runs.append({"at": (seg["x1"] + seg["x2"]) / 2, "lo": min(seg["y1"], seg["y2"]),
                           "hi": max(seg["y1"], seg["y2"]), "ids": seg["ids"]})
    horizontals = _merge(h_runs, tol, gap_tol)
    verticals = _merge(v_runs, tol, gap_tol)
    if len(horizontals) < 2 or len(verticals) < 2:
        return []

    # Which vertical lines cross each horizontal line (and vice versa), by index.
    cross_h: list[set] = [set() for _ in horizontals]
    for i, h in enumerate(horizontals):
        for j, v in enumerate(verticals):
            if _covers(v["spans"], h["at"], h["at"], tol) is not None and \
                    _covers(h["spans"], v["at"], v["at"], tol) is not None:
                cross_h[i].add(j)

    found = []
    for i1 in range(len(horizontals)):
        for i2 in range(i1 + 1, len(horizontals)):
            y1, y2 = sorted((horizontals[i1]["at"], horizontals[i2]["at"]))
            if y2 - y1 < MIN_SIDE:
                continue
            shared = sorted(cross_h[i1] & cross_h[i2])
            for k1 in range(len(shared)):
                for k2 in range(k1 + 1, len(shared)):
                    j1, j2 = shared[k1], shared[k2]
                    x1, x2 = sorted((verticals[j1]["at"], verticals[j2]["at"]))
                    if x2 - x1 < MIN_SIDE:
                        continue
                    top = _covers(horizontals[i1]["spans"], x1, x2, tol)
                    bottom = _covers(horizontals[i2]["spans"], x1, x2, tol)
                    left = _covers(verticals[j1]["spans"], y1, y2, tol)
                    right = _covers(verticals[j2]["spans"], y1, y2, tol)
                    if None in (top, bottom, left, right):
                        continue
                    w, h = x2 - x1, y2 - y1
                    found.append({"corners": [[x1, y1], [x2, y1], [x2, y2], [x1, y2]],
                                  "object_ids": sorted(top | bottom | left | right),
                                  "width": w, "height": h, "area": w * h, "perimeter": 2 * (w + h)})
    found.sort(key=lambda r: r["area"], reverse=True)
    return found[:MAX_CANDIDATES]


def format_feet_inches(feet: float) -> str:
    """45.5833 -> 45'-7" (nearest half inch)."""
    inches = round(feet * 12 * 2) / 2
    whole = int(inches // 12)
    rem = inches - whole * 12
    if rem >= 12:                      # rounding carried over a foot
        whole, rem = whole + 1, rem - 12
    if rem == 0:
        return f"{whole}'"
    if rem == int(rem):
        return f"{whole}'-{int(rem)}\""
    return f"{whole}'-{int(rem)} 1/2\""


def parse_feet_inches(label) -> float | None:
    """45'-7" -> 547.0, 12' -> 144.0, 6" -> 6.0, 18'-3 1/2" -> 219.5. None when not a length."""
    if not isinstance(label, str):
        return None
    if "'" not in label and '"' not in label:
        return None
    m = _DIM_RE.match(label)
    if not m or not any(m.groups()):
        return None
    feet, whole, num, den, fnum, fden = m.groups()
    try:
        total = float(feet or 0) * 12 + float(whole or 0)
        if num:
            total += int(num) / int(den)
        elif fnum:
            total += int(fnum) / int(fden)
    except (ValueError, ZeroDivisionError):
        return None
    return total if total > 0 else None


def find_calibration_dimension(objects: list[dict], rectangle: dict,
                               tol: float = COORD_TOL) -> dict | None:
    """A dimension line as long as the rectangle's width or length, with a real length in its label.

    Returns {points [[x, y], [x, y]], label, real_inches} or None. The closest
    length match wins; a dimension whose label isn't a length (45'-7", 12', 6")
    can't calibrate anything.
    """
    width, height = rectangle["width"], rectangle["height"]
    best = None
    for obj in objects:
        if obj.get("kind") != "dimension":
            continue
        geom = obj.get("geometry") or {}
        if geom.get("type") != "line" or len(geom.get("points") or []) < 2:
            continue
        label = obj.get("label") or geom.get("label")
        real = parse_feet_inches(label)
        if real is None:
            continue
        pts = geom["points"]
        (ax, ay), (bx, by) = pts[0], pts[-1]
        length = math.hypot(float(bx) - float(ax), float(by) - float(ay))
        for side in (width, height):
            if abs(length - side) <= max(tol, 0.01 * side):
                err = abs(length - side) / side
                if best is None or err < best[0]:
                    best = (err, {"points": [[ax, ay], [bx, by]], "label": label, "real_inches": real})
    return best[1] if best else None


def _scale_ratio(row) -> float | None:
    """The viewport's scale as a number, or None when it has no usable scale."""
    if row is None or row["is_nts"]:
        return None
    try:
        ratio = float(row["scale_ratio"]) if row["scale_ratio"] not in (None, "") else None
    except (TypeError, ValueError):
        return None
    return ratio if ratio and ratio > 0 else None


def _llm_takeoff(conn, company_id: str) -> dict:
    """Whether the LLM fallback would run when no outline is found (for the review page's status line)."""
    try:
        from estimator.takeoff import llm_takeoff
        s = llm_takeoff.llm_setting(conn, company_id)
        return {"enabled": s["enabled"], "ready": s["ready"], "provider": s["provider"],
                "provider_label": s["provider_label"]}
    except Exception:  # noqa: BLE001 - an old DB or a missing roles table just means no LLM fallback
        return {"enabled": False, "ready": False, "provider": None, "provider_label": None}


def find_slab_candidates(conn, company_id: str, viewport_id: int) -> dict:
    """Slab rectangles on a viewport, biggest first, in feet when the viewport is scaled.

    {viewport_id, calibrated, scale_ratio, candidates: [{id "c1", corners,
    object_ids, width, height, area, perimeter (paper units), width_ft,
    height_ft, area_sqft, perimeter_lf, label "45'-7\\" x 46'-7\\""}]}.
    Unscaled viewports still return candidates, with the feet values None.
    """
    vp = conn.execute("SELECT * FROM viewports WHERE id = ? AND company_id = ?",
                      (int(viewport_id), company_id)).fetchone()
    if vp is None:
        raise NotFound(f"viewport {viewport_id} not found", viewport_id=viewport_id)
    ratio = _scale_ratio(vp)
    objects = []
    for r in conn.execute("SELECT id, kind, geometry_json, label FROM drawing_objects"
                          " WHERE company_id = ? AND viewport_id = ?",
                          (company_id, int(viewport_id))):
        try:
            geom = json.loads(r["geometry_json"])
        except (TypeError, ValueError):
            continue
        objects.append({"id": r["id"], "kind": r["kind"], "geometry": geom, "label": r["label"]})
    out = []
    for i, rect in enumerate(find_rectangles(objects), start=1):
        cand = {"id": f"c{i}", **rect}
        if ratio:
            per_ft = ratio / 12
            w_ft, h_ft = rect["width"] * per_ft, rect["height"] * per_ft
            cand.update(width_ft=w_ft, height_ft=h_ft, area_sqft=w_ft * h_ft,
                        perimeter_lf=rect["perimeter"] * per_ft,
                        label=f"{format_feet_inches(w_ft)} x {format_feet_inches(h_ft)}")
        else:
            cand.update(width_ft=None, height_ft=None, area_sqft=None, perimeter_lf=None, label=None)
        out.append(cand)
    return {"viewport_id": int(viewport_id), "calibrated": ratio is not None,
            "scale_ratio": ratio, "candidates": out, "llm_takeoff": _llm_takeoff(conn, company_id)}

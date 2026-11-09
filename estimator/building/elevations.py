"""Exterior elevations in the shared model (Coder 2 Sprint 14): each side's outside wall area and its openings, as the
plan engine saved them (plan_engine/elevations.py: layer ELEVATION-WALL polygons and ELEVATION-OPENING openings),
measured with each view's scale. A side drawn twice (the same view title on two sheets) is counted once."""
from __future__ import annotations

import json
import re

STORIES_RE = re.compile(r"·\s*(\d+)\s*stor", re.I)
VIEW_RE = re.compile(r"\s*wall\s*·.*$", re.I)


def _r(v: float, nd: int = 1) -> float:
    return round(float(v) + 0.0, nd)


def read(conn, sheets: list[dict], factors_of) -> dict:
    """{"elevations": [...], "notes": [...]}. sheets: the plan sets' sheet rows; factors_of(sheet) -> {viewport id:
    real feet per drawing unit}."""
    out, notes, seen, unmeasured = [], [], set(), 0
    for s in sheets:
        rows = [dict(r) for r in conn.execute(
            "SELECT id, viewport_id, kind, label, layer, geometry_json, real_units_json FROM drawing_objects"
            " WHERE sheet_id = ? AND layer IN ('ELEVATION-WALL', 'ELEVATION-OPENING') ORDER BY id", (s["id"],))]
        if not rows:
            continue
        factors = factors_of(s)
        by_view: dict[int, dict] = {}
        for r in rows:
            real = json.loads(r["real_units_json"]) if r["real_units_json"] else None
            f = factors.get(r["viewport_id"])
            if not real or "area_sqft" not in real or not f:
                unmeasured += 1
                continue
            v = by_view.setdefault(r["viewport_id"], {"walls": [], "openings": []})
            if r["layer"] == "ELEVATION-WALL":
                v["walls"].append((r, float(real["area_sqft"])))
            else:
                pts = json.loads(r["geometry_json"])["points"]
                xs, ys = [p[0] for p in pts], [p[1] for p in pts]
                v["openings"].append({"id": r["id"], "kind": r["label"] or "window",
                                      "width_ft": _r((max(xs) - min(xs)) * f, 2), "height_ft": _r((max(ys) - min(ys)) * f, 2),
                                      "area_sqft": _r(float(real["area_sqft"]))})
        for vp_id, v in by_view.items():
            if not v["walls"]:
                continue
            label = v["walls"][0][0]["label"] or "Elevation wall"
            view = VIEW_RE.sub("", label).strip() or "Elevation"
            key = re.sub(r"[^A-Z0-9]+", " ", view.upper()).strip()
            if key in seen:
                notes.append(f"{view} on {s['sheet_no'] or 'another sheet'} is drawn again; it's counted once")
                continue
            seen.add(key)
            m = STORIES_RE.search(label)
            gross = sum(a for _, a in v["walls"])
            open_sqft = sum(o["area_sqft"] for o in v["openings"])
            out.append({"sheet_id": s["id"], "sheet_no": s["sheet_no"], "viewport_id": vp_id, "view": view,
                        "wall_sqft": _r(gross), "openings": v["openings"], "openings_sqft": _r(open_sqft),
                        "net_sqft": _r(max(gross - open_sqft, 0)), "stories": int(m.group(1)) if m else 1})
    if unmeasured:
        notes.append(f"{unmeasured} elevation wall(s) or opening(s) are on unscaled views and aren't counted")
    return {"elevations": out, "notes": notes}

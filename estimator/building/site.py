"""The site in the shared model (Coder 2 Sprint 15): landscape zones, fence lines, gates and plants, as the plan engine
saved them (plan_engine/site.py: SITE-ZONE polygons, SITE-FENCE polylines, SITE-GATE notes) and measured with each
view's scale, plus the plant schedule's trees and shrubs.

Counted once: a site plan and a landscape plan often show the same lawn and the same fence. Zones come from one sheet
(a landscape sheet first, then the one with the most zone area), fences from one sheet (the one with the most fence),
gates from the fence sheet when it has any. The others are listed in the notes.
"""
from __future__ import annotations

import json
import re

from estimator.plan_engine import site as words

ZONE_KINDS = words.ZONE_KINDS
QTY_KEYS = re.compile(r"^(?:QTY|QUANT(?:ITY)?\.?|NO\.?|COUNT|#)$", re.I)
TREE_RE = re.compile(r"\bTREES?\b|\bPALMS?\b|\bBOX\b|\bB\s*&\s*B\b|\bCAL(IPER)?\.?\b|\b\d+\s*['’]\s*(HT|CT|OA|C\.T\.)", re.I)
COVER_RE = re.compile(r"\bGROUND\s*COVER\b|\bFLATS?\b|\bPLUGS?\b|\bSOD\b|\bSEED\b|\bVINES?\b|\bANNUALS?\b|\bS\.?F\.?\b", re.I)
SHRUB_RE = re.compile(r"\bSHRUBS?\b|\bGAL(LON)?\.?\b|\b\d+\s*G\b|#\s*\d+\b|\bHEDGE\b|\bGRASSES\b", re.I)
GATE_LABEL_RE = re.compile(r"^(\d+)\s+(walk|drive)\s+gate", re.I)
FENCE_HEIGHTS = (4, 5, 6, 8)


def _r(v: float, nd: int = 1) -> float:
    return round(float(v) + 0.0, nd)


def _kind(label: str | None) -> str:
    return (label or "").split(" · ", 1)[0].strip().lower()


def _note(label: str | None) -> str:
    parts = (label or "").split(" · ", 1)
    return parts[1].strip() if len(parts) == 2 else ""


def _plants(rows: list[dict]) -> tuple[dict, list[str]]:
    trees = shrubs = 0
    notes, unknown, no_qty = [], [], 0
    found = False
    for r in rows:
        if r["schedule_type"] != "plant":
            continue
        found = True
        qty = None
        for k, v in r["fields"].items():
            if QTY_KEYS.match(k.strip()) and re.fullmatch(r"\d{1,4}", str(v or "").strip()):
                qty = int(str(v).strip())
        text = " ".join(str(v) for v in r["fields"].values() if v) + " " + (r["mark"] or "")
        if qty is None:
            no_qty += 1
            continue
        if COVER_RE.search(text) and not TREE_RE.search(text):
            continue                                   # ground cover by the flat or the square foot: not a plant count
        if TREE_RE.search(text):
            trees += qty
        elif SHRUB_RE.search(text):
            shrubs += qty
        else:
            unknown.append(r["mark"] or text[:30])
    if no_qty:
        notes.append(f"{no_qty} plant schedule row(s) have no quantity, so they aren't counted")
    if unknown:
        notes.append("plant schedule rows not known as a tree or shrub (not counted): " + ", ".join(unknown[:8]))
    return ({"trees": trees, "shrubs": shrubs, "from": "plant schedule"} if found else {}), notes


def read(conn, sheets: list[dict], factors_of, rows: list[dict]) -> dict:
    """{"zones", "zone_sqft", "fences", "fence_lf", "gates", "plants", "notes"...}. sheets: the plan sets' sheet rows;
    factors_of(sheet) -> {viewport id: real feet per drawing unit}; rows: their schedule rows."""
    per_sheet: dict[int, dict] = {}
    unmeasured = 0
    for s in sheets:
        objs = [dict(r) for r in conn.execute(
            "SELECT id, viewport_id, kind, label, layer, geometry_json, real_units_json FROM drawing_objects"
            " WHERE sheet_id = ? AND layer IN ('SITE-ZONE', 'SITE-FENCE', 'SITE-GATE') ORDER BY id", (s["id"],))]
        if not objs:
            continue
        factors = factors_of(s)
        got = per_sheet.setdefault(s["id"], {"sheet": s, "zones": [], "fences": [], "gates": []})
        for o in objs:
            real = json.loads(o["real_units_json"]) if o["real_units_json"] else None
            if o["layer"] == "SITE-GATE":
                m = GATE_LABEL_RE.match(o["label"] or "")
                if m:
                    got["gates"].append({"id": o["id"], "kind": m.group(2).lower(), "count": int(m.group(1)),
                                         "note": _note(o["label"])})
                continue
            if not real or o["viewport_id"] not in factors:
                unmeasured += 1
                continue
            if o["layer"] == "SITE-ZONE" and "area_sqft" in real:
                kind = _kind(o["label"])
                if kind in ZONE_KINDS:
                    got["zones"].append({"id": o["id"], "kind": kind, "note": _note(o["label"]),
                                         "area_sqft": _r(real["area_sqft"]),
                                         "perimeter_ft": _r(real.get("perimeter_ft", 0))})
            elif o["layer"] == "SITE-FENCE" and "length_ft" in real:
                note = _note(o["label"])
                info = words.fence_info(note)
                got["fences"].append({"id": o["id"], "note": note, "length_ft": _r(real["length_ft"]), **info})
    notes = []
    if unmeasured:
        notes.append(f"{unmeasured} site zone(s) or fence line(s) are on unscaled views and aren't counted; set the scale")

    def pick(key, size, prefer=None):
        have = [g for g in per_sheet.values() if g[key]]
        if not have:
            return None
        if prefer:
            pref = [g for g in have if prefer(g["sheet"])]
            have = pref or have
        best = max(have, key=size)
        others = [g for g in per_sheet.values() if g[key] and g is not best]
        if others:
            notes.append(f"{key} also drawn on " + ", ".join(g["sheet"]["sheet_no"] or f"sheet {g['sheet']['id']}"
                                                           for g in others)
                         + f"; counted once, from {best['sheet']['sheet_no'] or 'sheet ' + str(best['sheet']['id'])}")
        return best

    zs = pick("zones", lambda g: sum(z["area_sqft"] for z in g["zones"]),
              prefer=lambda s: (s.get("discipline") or "") == "landscape")
    fs = pick("fences", lambda g: sum(f["length_ft"] for f in g["fences"]))
    gate_sheet = fs if fs and fs["gates"] else pick("gates", lambda g: sum(x["count"] for x in g["gates"]))
    zones = zs["zones"] if zs else []
    fences = fs["fences"] if fs else []
    gates = gate_sheet["gates"] if gate_sheet else []

    zone_sqft = {k: _r(sum(z["area_sqft"] for z in zones if z["kind"] == k)) for k in ZONE_KINDS}
    depths = [words.rock_depth(z["note"]) for z in zones if z["kind"] == "rock"]
    depths = [d for d in depths if d]

    # Fences by what they are: the longest kind is the fence; others are listed for a second fencing line.
    groups: dict[tuple, dict] = {}
    for f in fences:
        key = (f["material"], f["height_ft"])
        g = groups.setdefault(key, {"material": f["material"], "height_ft": f["height_ft"], "length_ft": 0.0, "runs": 0})
        g["length_ft"] = _r(g["length_ft"] + f["length_ft"])
        g["runs"] += 1
    fence_groups = sorted(groups.values(), key=lambda g: -g["length_ft"])
    plants, pnotes = _plants(rows)
    notes += pnotes
    return {"zones": zones, "zone_sqft": zone_sqft, "rock_depth_in": max(depths) if depths else None,
            "bed_perimeter_lf": _r(sum(z["perimeter_ft"] for z in zones if z["kind"] in ("bed", "mulch", "rock"))),
            "fences": fences, "fence_groups": fence_groups, "fence_lf": _r(sum(f["length_ft"] for f in fences)),
            "remove_old_fence": any(f["remove"] for f in fences),
            "gates": {"walk": sum(g["count"] for g in gates if g["kind"] == "walk"),
                      "drive": sum(g["count"] for g in gates if g["kind"] == "drive")},
            "plants": plants, "sheet_ids": sorted({g["sheet"]["id"] for g in (zs, fs, gate_sheet) if g}),
            "notes": notes}


def _height_choice(h: float | None) -> tuple[str | None, str | None]:
    if h is None:
        return None, None
    best = min(FENCE_HEIGHTS, key=lambda o: abs(o - h))
    return str(best), (None if abs(best - h) < 0.01 else f"the fence is {h:g} ft high; the nearest choice is {best} ft")


def fencing_answers(s: dict) -> tuple[dict, dict, list[str]]:
    ans, src, notes = {}, {}, []
    new = [f for f in s["fences"] if not f["remove"]]
    if new:
        kinds: dict[tuple, dict] = {}
        for f in new:
            g = kinds.setdefault((f["material"], f["height_ft"]), {"material": f["material"], "height_ft": f["height_ft"],
                                                                  "length_ft": 0.0})
            g["length_ft"] = _r(g["length_ft"] + f["length_ft"])
        groups = sorted(kinds.values(), key=lambda g: -g["length_ft"])
        main = groups[0]
        ans["length_lf"] = _r(main["length_ft"])
        src["length_lf"] = f"fence lines on the site plan ({sum(1 for f in new if (f['material'], f['height_ft']) == (main['material'], main['height_ft']))} run(s))"
        if main["material"]:
            ans["material"] = main["material"]
            src["material"] = "the fence note"
        else:
            notes.append("the fence note doesn't say the material; choose it")
        h, hn = _height_choice(main["height_ft"])
        if h:
            ans["height"] = h
            src["height"] = "the fence note"
        notes += [hn] if hn else []
        for g in groups[1:]:
            what = " ".join(x for x in (f"{g['height_ft']:g} ft" if g["height_ft"] else "",
                                        (g["material"] or "fence").replace("_", " ")) if x)
            notes.append(f"also {g['length_ft']:g} lf of {what}: price it as a second fencing line")
    removed = [f for f in s["fences"] if f["remove"]]
    if removed:
        ans["remove_old"] = True
        src["remove_old"] = "a 'remove existing fence' note"
        notes.append(f"{_r(sum(f['length_ft'] for f in removed)):g} lf of old fence to remove")
    if s["gates"]["walk"]:
        ans["walk_gates"] = s["gates"]["walk"]
        src["walk_gates"] = "gate notes and gate blocks"
    if s["gates"]["drive"]:
        ans["drive_gates"] = s["gates"]["drive"]
        src["drive_gates"] = "gate notes and gate blocks (double, drive or 8 ft and wider)"
    if not s["fences"]:
        notes.append("no fence lines found on the site plans: a fence note (\"6' WOOD FENCE\") or a fence layer finds them")
    return ans, src, notes


def landscaping_answers(s: dict) -> tuple[dict, dict, list[str]]:
    ans, src, notes = {}, {}, []
    z = s["zone_sqft"]
    for kind, qid, what in (("sod", "sod_sqft", "areas noted sod or lawn"), ("turf", "turf_sqft", "artificial turf areas"),
                            ("rock", "rock_sqft", "rock, gravel and decomposed granite areas"),
                            ("pavers", "pavers_sqft", "paver areas")):
        if z.get(kind):
            ans[qid] = z[kind]
            src[qid] = f"{what} on the site or landscape plan"
    if z.get("rock") and s.get("rock_depth_in"):
        ans["rock_depth"] = str(s["rock_depth_in"])
        src["rock_depth"] = "the rock note's depth"
    p = s.get("plants") or {}
    for k in ("trees", "shrubs"):
        if p.get(k):
            ans[k] = p[k]
            src[k] = "the plant schedule's quantities"
    if z.get("mulch"):
        notes.append(f"{z['mulch']:g} sq ft of mulch beds: the Landscaping trade has no mulch question, so price it by hand")
    if z.get("bed"):
        notes.append(f"{z['bed']:g} sq ft of planting beds (their plants come from the plant schedule or the symbols)")
    if s.get("bed_perimeter_lf"):
        notes.append(f"bed, rock and mulch areas have {s['bed_perimeter_lf']:g} lf of outline, if they get edging")
    if not any(z.values()):
        notes.append("no landscape zones found: a zone note (SOD, ROCK, MULCH, PAVERS) inside a closed area, or a zone "
                     "layer or hatch in CAD, finds them")
    return ans, src, notes

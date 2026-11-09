"""Site and landscape plans (Coder 2 Sprint 15): the areas by zone (sod, artificial turf, rock, mulch, pavers, planting
beds), the fence lines and the gates, for the fencing and landscaping trades.

Which views: a view titled "SITE PLAN", "PLOT PLAN", "LANDSCAPE PLAN", "PLANTING PLAN", "HARDSCAPE PLAN", "IRRIGATION
PLAN" or "FENCE PLAN", or any view on a site or landscape sheet that isn't an elevation, section, detail or table.
Walls and rooms aren't looked for there (a site plan's house outline isn't the floor plan).

Zones (PDF and DXF): a zone word written inside an area ("BERMUDA SOD", "3/4\\" RIVER ROCK 3\\" DEEP", "PAVERS") names
the smallest closed area around it, or the area its leader points into. Hatching is taken out of the line work first
(many parallel lines at one angle), so the area is the whole zone and not one hatch strip. An area with a hole (a lawn
round the house or a patio) keeps the hole out of its area. Existing areas ("EXISTING LAWN TO REMAIN") aren't counted.
DXF also gives zones directly: closed polylines and hatches on zone layers (L-TURF, L-ROCK, L-MULCH, L-PAVER, L-PLNT...)
or with a zone hatch pattern (GRASS, GRAVEL).

Fences: in a PDF, a fence note ("6' WOOD PRIVACY FENCE") is followed to its line (along a leader if there is one), and
the line is followed through its dashes and corners until it ends or meets another line (a junction stops it); these
are marked for checking. In a DXF, every line on a fence layer (L-FENC, C-FENCE...) is a fence run. The note gives the
material (wood, vinyl, chain link, block, iron/aluminum) and the height; "REMOVE EXISTING FENCE" means the old fence goes.

Gates: a gate note ("4' GATE", "(2) 12' DBL DRIVE GATE") or a GATE block: a drive gate is double, drive, rolling or
sliding, or 8 ft and wider; the rest are walk gates.

Saved as drawing objects so they're measured with the view's scale: zones are polygons on layer SITE-ZONE labelled
"<zone> · <note>", fences are polylines on layer SITE-FENCE labelled "fence · <note>", gates are text points on layer
SITE-GATE labelled "<n> walk|drive gate(s) · <note>".
"""
from __future__ import annotations

import math
import re

SITE_VIEW_RE = re.compile(r"\b(SITE|PLOT|LANDSCAPE|PLANTING|HARDSCAPE|IRRIGATION|FENCE|FENCING|YARD|LOT)\s+"
                          r"(PLAN|LAYOUT)S?\b|\bLANDSCAPE\b|\bPLANTING\b", re.I)
NOT_SITE_RE = re.compile(r"\b(ELEVATIONS?|SECTIONS?|DETAILS?|SCHEDULES?|LEGEND|NOTES|KEY\s*PLAN|VICINITY|LOCATION\s+MAP)\b",
                         re.I)
SITE_DISCIPLINES = ("site", "landscape")

# Zone words, first match wins (artificial turf before lawn, stone mulch before mulch).
ZONES = (
    ("turf", re.compile(r"\b(ARTIFICIAL|SYNTHETIC)\s+(TURF|GRASS|LAWN)\b|\bFAKE\s+GRASS\b", re.I)),
    ("pavers", re.compile(r"\bPAVERS?\b|\bPAVING\s+STONES?\b|\bFLAGSTONES?\b", re.I)),
    ("rock", re.compile(r"\bROCK\b|\bGRAVEL\b|\bDECOMPOSED\s+GRANITE\b|\bD\.G\.|\bDG\b|\bRIVER\s+STONE\b|\bCRUSHED\s+STONE\b"
                        r"|\bSTONE\s+MULCH\b|\bPEBBLES?\b", re.I)),
    ("mulch", re.compile(r"\bMULCH\b|\bPINE\s+STRAW\b|\bBARK\b", re.I)),
    ("sod", re.compile(r"\bSOD\b|\bLAWN\b|\bTURF\b|\bGRASS\b|\bBERMUDA\b|\bZOYSIA\b|\bST\.?\s*AUGUSTINE\b|\bBAHIA\b"
                       r"|\bFESCUE\b", re.I)),
    ("bed", re.compile(r"\b(PLANTING|PLANT|SHRUB|FLOWER)\s+BEDS?\b|\bGROUND\s*COVER\b", re.I)),
)
ZONE_KINDS = tuple(k for k, _ in ZONES)
LAYER_ZONES = (("turf", re.compile(r"ARTIF|SYNTH", re.I)), ("pavers", re.compile(r"PAVER|PAVR", re.I)),
               ("rock", re.compile(r"ROCK|GRAV|GRVL|STONE|(^|[-_ ])DG($|[-_ ])", re.I)),
               ("mulch", re.compile(r"MULCH|MLCH", re.I)), ("sod", re.compile(r"SOD|LAWN|TURF|GRASS|GRSS", re.I)),
               ("bed", re.compile(r"PLNT|PLANT|SHRB|SHRUB|(^|[-_ ])BEDS?($|[-_ ])", re.I)))
HATCH_PATTERNS = (("sod", re.compile(r"GRASS|TURF|LAWN", re.I)), ("rock", re.compile(r"GRAVEL|ROCK|STONE", re.I)))
EXISTING_RE = re.compile(r"\bEXIST(ING)?\b|\bEXIST\.|\(E\)|\bTO\s+REMAIN\b", re.I)
REMOVE_RE = re.compile(r"\bREMOVE\b|\bDEMO(LISH)?\b", re.I)
FENCE_RE = re.compile(r"\bFENC(E|ES|ING)\b|\b(BLOCK|CMU|MASONRY|GARDEN|SCREEN)\s+WALL\b", re.I)
FENCE_LAYER_RE = re.compile(r"FENC", re.I)
MATERIALS = (("block", re.compile(r"\bBLOCK\b|\bCMU\b|\bMASONRY\b|\bGARDEN\s+WALL\b|\bSCREEN\s+WALL\b", re.I)),
             ("chain_link", re.compile(r"CHAIN[\s-]*LINK|\bC\.?L\.?\s+FENCE", re.I)),
             ("vinyl", re.compile(r"\bVINYL\b|\bPVC\b", re.I)),
             ("iron", re.compile(r"\bIRON\b|\bALUM(INUM|\.)?\b|\bORNAMENTAL\b|\bSTEEL\b|\bMETAL\b", re.I)),
             ("wood", re.compile(r"\bWOOD\b|\bCEDAR\b|\bPRIVACY\b|\bSHADOW\s*BOX\b|\bBOARD\b|\bPICKET\b", re.I)))
FEET_RE = re.compile(r"(\d{1,2}(?:\.\d)?)\s*(?:'|’|FT\b|FOOT\b|FEET\b)(?:\s*-?\s*0\s*(?:\"|”|IN\b))?", re.I)
HT_FIRST_RE = re.compile(r"\b(?:HT|HEIGHT|HGT)\.?\s*[:=]?\s*(\d{1,2}(?:\.\d)?)\s*(?:'|’|FT\b)?", re.I)
DEPTH_RE = re.compile(r"(\d(?:\.\d)?)\s*(?:\"|”|IN\b|INCH(ES)?\b)\s*(?:DEEP|DEPTH|THICK|MIN)", re.I)
GATE_RE = re.compile(r"\bGATES?\b", re.I)
DRIVE_GATE_RE = re.compile(r"\bDOUBLE\b|\bDBL\.?|\bDRIVE(WAY)?\b|\bVEHICUL|\bROLLING\b|\bSLIDING\b|\bSLIDE\b|\bAUTO", re.I)
COUNT_RE = re.compile(r"^\s*\(\s*(\d{1,2})\s*\)\s*|^\s*(\d{1,2})\s*(?:X|×|EA\.?)\s+", re.I)   # "(2) 4' GATE", "2 X GATE"
DRIVE_GATE_FT = 8.0
MIN_ZONE_SQFT = 4.0
MIN_FENCE_FT = 4.0
MAX_LABEL = 60
MAX_SEGMENTS = 25000
HATCH_MIN_LINES = 6                    # parallel lines at one angle on this many separate lines = hatching


# ---------------------------------------------------------------------------------------------------- words

def is_site_view(label: str | None, discipline: str | None = None) -> bool:
    lab = label or ""
    if NOT_SITE_RE.search(lab):
        return False
    if SITE_VIEW_RE.search(lab):
        return True
    return (discipline or "") in SITE_DISCIPLINES


def zone_kind(text: str | None) -> str | None:
    t = (text or "").strip()
    if not t or len(t) > MAX_LABEL or FENCE_RE.search(t) or GATE_RE.search(t):
        return None
    for kind, rx in ZONES:
        if rx.search(t):
            return kind
    return None


def layer_zone(layer: str | None, pattern: str | None = None) -> str | None:
    for kind, rx in LAYER_ZONES:
        if layer and rx.search(layer):
            return kind
    for kind, rx in HATCH_PATTERNS:
        if pattern and rx.search(pattern):
            return kind
    return None


def is_existing(text: str | None) -> bool:
    return bool(text and EXISTING_RE.search(text) and not REMOVE_RE.search(text))


def feet_in(text: str | None) -> float | None:
    """The first height or width written in feet ("6'", "6'-0\\"", "6 FT", "HT 6")."""
    t = text or ""
    m = HT_FIRST_RE.search(t) or FEET_RE.search(t)
    return float(m.group(1)) if m else None


def fence_info(text: str | None) -> dict:
    """{"material", "height_ft", "remove"} from a fence note; missing parts are None."""
    t = text or ""
    material = next((k for k, rx in MATERIALS if rx.search(t)), None)
    h = feet_in(t)
    return {"material": material, "height_ft": h if h and 2 <= h <= 12 else None, "remove": bool(REMOVE_RE.search(t))}


def gate_info(text: str | None) -> dict | None:
    """{"kind": walk|drive, "count", "width_ft"} from a gate note, or None."""
    t = text or ""
    if not GATE_RE.search(t):
        return None
    m = COUNT_RE.match(t)
    n = int(m.group(1) or m.group(2)) if m else 1
    w = feet_in(t)
    w = w if w and 2 <= w <= 40 else None
    drive = bool(DRIVE_GATE_RE.search(t)) or (w is not None and w >= DRIVE_GATE_FT)
    return {"kind": "drive" if drive else "walk", "count": max(1, min(n, 20)), "width_ft": w}


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def rock_depth(text: str | None) -> int | None:
    m = DEPTH_RE.search(text or "")
    if not m:
        return None
    d = float(m.group(1))
    return 3 if d >= 2.5 else 2


# ---------------------------------------------------------------------------------------------------- geometry

def _len(s) -> float:
    (x0, y0), (x1, y1) = s
    return math.hypot(x1 - x0, y1 - y0)


def drop_hatching(segments: list) -> list:
    """The line work less hatching: for each angle that isn't level or plumb, lines on HATCH_MIN_LINES or more separate
    parallel lines are hatching (a dashed property line is many pieces on one line, so it stays)."""
    groups: dict[int, list[int]] = {}
    for i, ((x0, y0), (x1, y1)) in enumerate(segments):
        ang = round(math.degrees(math.atan2(y1 - y0, x1 - x0))) % 180
        if ang in (0, 90, 180) or ang in (1, 89, 91, 179):
            continue
        groups.setdefault(ang, []).append(i)
    drop: set[int] = set()
    for ang, ids in groups.items():
        if len(ids) < HATCH_MIN_LINES:
            continue
        a = math.radians(ang)
        lines: dict[float, list[int]] = {}
        for i in ids:
            (x0, y0), (x1, y1) = segments[i]
            off = round((x0 * math.sin(a) - y0 * math.cos(a)) / 0.01) * 0.01
            lines.setdefault(off, []).append(i)
        if len(lines) >= HATCH_MIN_LINES:
            drop.update(ids)
    return [s for i, s in enumerate(segments) if i not in drop]


def _ring(poly, simplify: float) -> list[list[float]]:
    """One outline for a polygon: each hole joined to the outside by a zero-width cut, so a lawn round the house is
    measured without the house (the outside runs one way, the holes the other)."""
    from shapely.geometry.polygon import orient
    p = orient(poly.simplify(simplify, preserve_topology=True), sign=1.0)
    ext = [tuple(c) for c in list(p.exterior.coords)[:-1]]
    for hole in p.interiors:
        h = [tuple(c) for c in list(hole.coords)[:-1]]
        if len(h) < 3 or len(ext) < 3:
            continue
        best = min(((math.dist(e, q), i, j) for i, e in enumerate(ext) for j, q in enumerate(h)), key=lambda x: x[0])
        _, i, j = best
        ext = ext[:i + 1] + h[j:] + h[:j + 1] + ext[i:]
    return [[round(x, 4), round(y, 4)] for x, y in ext]


def _leader_points(segments, box, near: float, max_len: float) -> list[tuple[float, float]]:
    """Where the leaders drawn from a note point: the far end of each line that starts at the note's box."""
    x0, y0, x1, y1 = box
    out = []
    for s in segments:
        L = _len(s)
        if L < near * 2 or L > max_len:
            continue
        for a, b in ((s[0], s[1]), (s[1], s[0])):
            if x0 - near <= a[0] <= x1 + near and y0 - near <= a[1] <= y1 + near and \
                    not (x0 - near <= b[0] <= x1 + near and y0 - near <= b[1] <= y1 + near):
                dx, dy = (b[0] - a[0]) / L, (b[1] - a[1]) / L
                out.append((b[0] + dx * near * 0.5, b[1] + dy * near * 0.5))
    return out


def find_zones(segments, notes_in: list[tuple[str, tuple, tuple]], *, k2: float, view_area: float, viewport, source: str,
               simplify: float, near: float, leader_max: float, label: str) -> tuple[list[dict], list[str]]:
    """Zone polygons. notes_in: (text, (x, y) middle, (x0, y0, x1, y1) box); k2: real sq ft per drawing unit²."""
    cands = [(t, p, b, zone_kind(t)) for t, p, b in notes_in]
    cands = [c for c in cands if c[3]]
    if not cands:
        return [], []
    notes = []
    existing = [c for c in cands if is_existing(c[0])]
    if existing:
        notes.append(f"{label}: {len(existing)} existing area(s) to remain aren't counted")
    cands = [c for c in cands if not is_existing(c[0])]
    if not cands:
        return [], notes
    segs = drop_hatching(segments)
    if len(segs) > MAX_SEGMENTS:
        return [], notes + [f"{label}: too much line work ({len(segs)} lines) to find the zones automatically"]
    if len(segs) < 3:
        return [], notes + [f"{label}: no closed areas round the zone notes"]
    try:
        from shapely.geometry import LineString, Point
        from shapely.ops import polygonize, unary_union
    except ImportError:
        return [], notes + [f"{label}: site zones need the 'shapely' package"]
    merged = unary_union([LineString(s) for s in segs])
    polys = [p for p in polygonize(merged) if p.area * k2 >= MIN_ZONE_SQFT and p.area <= 0.95 * view_area]
    objects, taken, missed = [], {}, []
    for text, p, box, kind in cands:
        around = []
        for q in [p] + _leader_points(segs, box, near, leader_max):
            pt = Point(q)
            around = [(poly.area, i) for i, poly in enumerate(polys) if poly.contains(pt)]
            if around:
                break
        if not around:
            missed.append(text)
            continue
        _, i = min(around)
        if i in taken:
            if taken[i] != kind:
                notes.append(f"{label}: one area is noted both {taken[i]} and {kind}; it's counted as {taken[i]}")
            continue
        taken[i] = kind
        pts = _ring(polys[i], simplify)
        if len(pts) >= 3:
            objects.append({"viewport": viewport, "kind": "polygon", "layer": "SITE-ZONE",
                            "label": f"{kind} · {_clean(text)}"[:100],
                            "geometry": {"type": "polygon", "points": pts}, "source": source, "confidence": 0.6})
    if missed:
        notes.append(f"{label}: no closed area found for " + ", ".join(f"'{t.strip()}'" for t in missed[:6])
                     + (" ..." if len(missed) > 6 else "") + " - draw it in Blueprint Review")
    return objects, notes


def _follow(segs, seed: int, gap: float, used: set) -> list[tuple[float, float]]:
    """The run of line work through segment `seed`: joined end to end (dashes and corners within `gap`), stopping
    where it ends or forks."""
    used.add(seed)
    pts = [segs[seed][0], segs[seed][1]]
    for end in (1, 0):                                   # grow forward from the last point, then back from the first
        while True:
            tip = pts[-1] if end else pts[0]
            nxt = []
            for i, s in enumerate(segs):
                if i in used:
                    continue
                d0, d1 = math.dist(tip, s[0]), math.dist(tip, s[1])
                if min(d0, d1) <= gap:
                    nxt.append((i, s if d0 <= d1 else (s[1], s[0])))
            if len(nxt) != 1 or len(used) > 2000:
                break
            i, s = nxt[0]
            used.add(i)
            if end:
                pts += [s[0], s[1]] if math.dist(s[0], pts[-1]) > 1e-9 else [s[1]]
            else:
                pts = ([s[1], s[0]] if math.dist(s[0], pts[0]) > 1e-9 else [s[1]]) + pts
    return pts


def find_fences(segments, notes_in, *, kf: float, viewport, source: str, near: float, gap: float, min_piece: float,
                leader_max: float, label: str) -> tuple[list[dict], list[str]]:
    """Fence polylines followed from fence notes (PDF). kf: real feet per drawing unit."""
    cands = [(t, p, b) for t, p, b in notes_in if FENCE_RE.search(t or "") and len(t) <= 80]
    if not cands:
        return [], []
    notes = []
    segs = [s for s in drop_hatching(segments) if _len(s) >= min_piece]
    objects, runs = [], []
    for text, p, box in cands:
        if is_existing(text):
            notes.append(f"{label}: existing fence to remain isn't counted ('{text.strip()}')")
            continue
        leaders = _leader_points(segs, box, near, leader_max)
        leader_ids = set()
        x0, y0, x1, y1 = box
        for i, s in enumerate(segs):
            if any(x0 - near <= a[0] <= x1 + near and y0 - near <= a[1] <= y1 + near for a in s) and _len(s) <= leader_max:
                leader_ids.add(i)
        seed = None
        targets = leaders or [p]
        reach = near * 2 if leaders else max(near * 4, (y1 - y0) * 3)      # a note written beside its line
        for q in targets:
            best = None
            for i, s in enumerate(segs):
                if i in leader_ids and leaders:
                    continue
                d = _point_seg(q, s) if leaders else _box_seg((x0, y0, x1, y1), s)
                if d <= reach and (best is None or d < best[0]):
                    best = (d, i)
            if best:
                seed = best[1]
                break
        if seed is None:
            notes.append(f"{label}: the fence line for '{text.strip()}' wasn't found - draw it in Blueprint Review")
            continue
        if any(seed in r for r in runs):
            continue                                    # a second note on a run already counted
        used = set(leader_ids) if leaders else set()
        pts = _follow(segs, seed, gap, used)
        runs.append(used)
        length_ft = sum(math.dist(a, b) for a, b in zip(pts, pts[1:])) * kf
        if length_ft < MIN_FENCE_FT:
            continue
        objects.append({"viewport": viewport, "kind": "polyline", "layer": "SITE-FENCE",
                        "label": f"fence · {_clean(text)}"[:100],
                        "geometry": {"type": "polyline", "points": [[round(x, 4), round(y, 4)] for x, y in _thin(pts)]},
                        "source": source, "confidence": 0.5})
    if objects:
        notes.append(f"{label}: fence lines were followed from their notes - check where each one starts and stops")
    return objects, notes


def _thin(pts):
    """Drop points that sit on a straight run (the dashes of one fence side)."""
    out = [pts[0]]
    for i in range(1, len(pts) - 1):
        a, b, c = out[-1], pts[i], pts[i + 1]
        cross = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
        if abs(cross) > 1e-6 * max(1.0, math.dist(a, c)) or math.dist(a, b) < 1e-9:
            if math.dist(a, b) > 1e-9:
                out.append(b)
    out.append(pts[-1])
    return out


def _box_seg(box, s) -> float:
    """How far a line is from a note's box (0 if it crosses it)."""
    x0, y0, x1, y1 = box
    if any(x0 <= a[0] <= x1 and y0 <= a[1] <= y1 for a in s):
        return 0.0
    edges = [((x0, y0), (x1, y0)), ((x1, y0), (x1, y1)), ((x1, y1), (x0, y1)), ((x0, y1), (x0, y0))]
    d = min(min(_point_seg(c, s) for c in (e[0],)) for e in edges)
    d = min(d, min(_point_seg(a, e) for a in s for e in edges))
    return d


def _point_seg(p, s) -> float:
    (ax, ay), (bx, by) = s
    dx, dy = bx - ax, by - ay
    L2 = dx * dx + dy * dy
    t = 0.0 if L2 == 0 else max(0.0, min(1.0, ((p[0] - ax) * dx + (p[1] - ay) * dy) / L2))
    return math.hypot(p[0] - (ax + t * dx), p[1] - (ay + t * dy))


def gate_objects(notes_in, viewport, source: str) -> list[dict]:
    out = []
    for text, p, _box in notes_in:
        g = gate_info(text)
        if not g or is_existing(text):
            continue
        n = g["count"]
        out.append({"viewport": viewport, "kind": "text", "layer": "SITE-GATE",
                    "label": f"{n} {g['kind']} gate{'s' if n > 1 else ''} · {_clean(text)}"[:100],
                    "geometry": {"type": "point", "points": [[round(p[0], 4), round(p[1], 4)]]}, "source": source,
                    "confidence": 0.6})
    return out


# ---------------------------------------------------------------------------------------------------- PDF views

def find(page, vp: dict, segments, ratio: float | None) -> tuple[list[dict], list[str]]:
    """(objects, notes) for one site view of a PDF page. ratio: real inches per paper inch."""
    label = (vp.get("label") or vp.get("key") or "site plan").strip()
    if not ratio:
        return [], [f"{label}: no scale, so its areas and fence lines can't be measured; set the scale"]
    vb = vp["bbox"]
    notes_in = []
    for ln in page.lines:
        cx, cy = (ln.x0 + ln.x1) / 2, (ln.top + ln.bottom) / 2
        if vb[0] <= cx <= vb[2] and vb[1] <= cy <= vb[3] and ln.text.strip():
            notes_in.append((ln.text.strip(), (cx, cy), (ln.x0, ln.top, ln.x1, ln.bottom)))
    k2, kf = ratio * ratio / 144.0, ratio / 12.0
    view_area = (vb[2] - vb[0]) * (vb[3] - vb[1])
    zones, zn = find_zones(segments, notes_in, k2=k2, view_area=view_area, viewport=vp["key"], source="vector",
                           simplify=0.005, near=0.06, leader_max=4.0, label=label)
    fences, fn = find_fences(segments, notes_in, kf=kf, viewport=vp["key"], source="vector", near=0.06, gap=0.12,
                             min_piece=0.04, leader_max=4.0, label=label)
    return zones + fences + gate_objects(notes_in, vp["key"], "vector"), zn + fn


# ---------------------------------------------------------------------------------------------------- DXF

def dxf_objects(paths, texts, inserts, hatches, tr, k: float, discipline: str | None,
                width: float, height: float) -> tuple[list[dict], list[str]]:
    """Site objects from a DXF (model space at real size; k = real inches per drawing unit; tr = to the drawing
    model's top-left frame). paths: (type, layer, pts, closed); texts: (text, layer, pt); inserts: (name, layer, pt,
    tags); hatches: (layer, pattern, [boundary point lists])."""
    objects, notes = [], []
    k2, kf = k * k / 144.0, k / 12.0
    try:
        from shapely.geometry import Polygon
        have_shapely = True
    except ImportError:
        have_shapely = False
    tnotes = [(t, tr(p)) for t, _layer, p in texts]

    # Zones on zone layers (closed polylines) and hatches.
    zone_polys = []
    for t, layer, pts, closed in paths:
        kind = layer_zone(layer)
        if kind and closed and len(pts) >= 3:
            zone_polys.append((kind, layer, [tr(p) for p in pts]))
    for layer, pattern, loops in hatches:
        kind = layer_zone(layer, pattern)
        if not kind or not loops:
            continue
        rings = [[tr(p) for p in lp] for lp in loops if len(lp) >= 3]
        if not rings:
            continue
        if have_shapely:
            try:
                polys = sorted((Polygon(r).buffer(0) for r in rings), key=lambda g: -g.area)
                shape = polys[0]
                for h in polys[1:]:
                    if shape.contains(h.representative_point()):
                        shape = shape.difference(h)
                for g in getattr(shape, "geoms", [shape]):
                    if g.area * k2 >= MIN_ZONE_SQFT:
                        zone_polys.append((kind, layer, _ring(g, 0.25 / k)))
                continue
            except Exception:  # noqa: BLE001 - a broken hatch boundary is skipped
                continue
        zone_polys.append((kind, layer, rings[0]))
    for kind, layer, pts in zone_polys:
        objects.append({"viewport": "model", "kind": "polygon", "layer": "SITE-ZONE",
                        "label": f"{kind} · {layer}"[:100], "geometry": {"type": "polygon", "points": [list(p) for p in pts]},
                        "source": "cad", "confidence": 0.9})

    # Zones from notes inside closed areas (site and landscape drawings only).
    if (discipline or "") in SITE_DISCIPLINES and not zone_polys:
        from estimator.plan_engine import vectors
        segs = []
        for _t, _layer, pts, closed in paths:
            tp = [tr(p) for p in pts]
            segs += list(zip(tp, tp[1:] + ([tp[0]] if closed else [])))
        notes_in = [(t, p, (p[0], p[1], p[0] + 1e-6, p[1] + 1e-6)) for t, p in tnotes]
        found, zn = find_zones(vectors.clean_segments(segs), notes_in, k2=k2, view_area=width * height * 1.01,
                               viewport="model", source="cad", simplify=0.25 / k, near=6.0 / k, leader_max=240.0 / k,
                               label="Model space")
        objects += found
        notes += zn

    # Fences: every line on a fence layer; the nearest fence note (within 20 ft) says what it is.
    fence_notes = [(t, p) for t, p in tnotes if FENCE_RE.search(t)]
    reach = 20.0 * 12.0 / k
    for t, layer, pts, closed in paths:
        if not FENCE_LAYER_RE.search(layer) or len(pts) < 2:
            continue
        tp = [tr(p) for p in pts] + ([tr(pts[0])] if closed else [])
        best = None
        for text, p in fence_notes:
            d = min(_point_seg(p, (a, b)) for a, b in zip(tp, tp[1:]))
            if d <= reach and (best is None or d < best[0]):
                best = (d, text)
        name = best[1] if best else layer
        if is_existing(name):
            continue
        if sum(math.dist(a, b) for a, b in zip(tp, tp[1:])) * kf < MIN_FENCE_FT:
            continue
        objects.append({"viewport": "model", "kind": "polyline", "layer": "SITE-FENCE",
                        "label": f"fence · {_clean(name)}"[:100],
                        "geometry": {"type": "polyline", "points": [list(p) for p in tp]}, "source": "cad",
                        "confidence": 0.9})

    # Gates: GATE blocks and gate notes.
    gate_in = [(t, p, None) for t, p in tnotes if GATE_RE.search(t)]
    gate_in += [(name.replace("_", " ").replace("-", " "), tr(p), None) for name, _layer, p, _tags in inserts
                if GATE_RE.search(name.replace("_", " ").replace("-", " "))]
    objects += gate_objects(gate_in, "model", "cad")
    return objects, notes

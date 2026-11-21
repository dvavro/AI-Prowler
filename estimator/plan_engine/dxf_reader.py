"""DXF drawings (ezdxf): model space at real size, so nothing needs a scale.

- Units come from the drawing's $INSUNITS (inches, feet, mm, cm, m); a drawing with no units is read as inches and
  says so.
- Coordinates are turned to the drawing model's convention: origin at the top-left of the drawing's extents, y down,
  the same way up as the rendered image.
- Objects: every line, polyline, arc and circle (as line/polyline/polygon with its layer), blocks (INSERT -> symbol,
  with the block name and its tag attribute), text, dimensions (with their measurement), walls (pairs of parallel
  lines 3" to 16" apart, on WALL layers when the drawing has them), and rooms (a room name inside a closed area;
  closed polylines on ROOM/AREA/SPACE layers first).
- Layers that are off or frozen are skipped, like they're hidden in CAD.
- Paper space layouts aren't read in this version: model space has the real-size drawing.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from estimator.plan_engine import vectors
from estimator.plan_engine.titleblock import PREFIX, discipline_for

INSUNITS = {1: "in", 2: "ft", 4: "mm", 5: "cm", 6: "m"}
REAL_IN = {"in": 1.0, "ft": 12.0, "mm": 1 / 25.4, "cm": 1 / 2.54, "m": 39.37007874}
MAX_LINEWORK = 20000
MAX_TEXT = 5000
MAX_SYMBOLS = 20000
MAX_DIMS = 5000
MAX_SEGMENTS = 200000
RENDER_PX = 4000
_FONT_PATHS = (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\calibri.ttf",
               "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
_MAX_FONT_PX = 400                       # a huge title never makes a huge font
TAG_ATTRIBS = ("TAG", "MARK", "NO", "NUMBER", "NUM", "ID", "TYPE")
WALL_LAYER = re.compile(r"WALL", re.I)
ROOM_LAYER = re.compile(r"ROOM|AREA|SPACE", re.I)
# 2026-11-20 (David: on the panel drawing "the table has lines through the wording"): a schedule's row lines, a riser
# diagram's boxes, a panel elevation's breakers, the title block and the legend frame aren't walls or rooms - read as
# walls (rows 1.1 ft apart look like a wall's two faces) they were drawn as thick bands over every other row's text,
# and their cells and boxes came out as "rooms" (DESCRIPTION 18 sq ft, LEGEND 115 sq ft).
NOT_PLAN_LAYER = re.compile(r"SCHED|TABLE|RISER|BREAKER|PANEL|TITLE|BORDER|LEGEND|DIAGRAM|ONE.?LINE|TBLK|FRAME|TEXT|ANNO"
                            # ... nor a wiring schematic's conductors (hot, neutral and ground drawn side by side)
                            r"|HOT|NEUTRAL|GROUND|CONDUCTOR|WIRE|CIRC|DEVICE|FLAG", re.I)


def _hidden_layers(doc) -> set[str]:
    out = set()
    for layer in doc.layers:
        try:
            if layer.is_off() or layer.is_frozen():
                out.add(layer.dxf.name.upper())
        except Exception:  # noqa: BLE001 - odd layer tables: show everything
            continue
    return out


def _text_of(e) -> str:
    t = e.dxftype()
    if t == "MTEXT":
        return e.plain_text().strip()
    return (e.dxf.text or "").strip()


def _render_text(e, text):
    """What the sheet image draws for one TEXT/MTEXT entity: (text, x, y, height, anchor, rotation).

    (x, y) is the anchor point in CAD coords (y up): the insertion point for left-aligned text, the
    alignment point for centred/right-aligned text. The anchor is a PIL anchor ("ls" = left-baseline,
    "ms" = middle-baseline ...); MTEXT uses its attachment point. Rotation is carried for the record -
    _render draws rotated text unrotated at its anchor (PIL has no rotated draw.text).
    Returns None when the entity has no usable height.
    """
    t = e.dxftype()
    try:
        if t == "MTEXT":
            height = float(e.dxf.char_height or 0)
            att = int(getattr(e.dxf, "attachment_point", 1) or 1)
            anchor = {1: "lt", 2: "mt", 3: "rt", 4: "lm", 5: "mm", 6: "rm",
                      7: "ls", 8: "ms", 9: "rs"}.get(att, "lt")
            p = e.dxf.insert
        else:
            height = float(e.dxf.height or 0)
            halign = int(getattr(e.dxf, "halign", 0) or 0)
            valign = int(getattr(e.dxf, "valign", 0) or 0)
            h = {0: "l", 1: "m", 2: "r", 3: "l", 4: "m", 5: "l"}.get(halign, "l")
            v = {0: "s", 1: "b", 2: "m", 3: "t"}.get(valign, "s")
            anchor = h + v
            p = e.dxf.insert
            if halign in (1, 2):
                ap = e.dxf.align_point
                if ap is not None and (ap.x, ap.y) != (0.0, 0.0):
                    p = ap               # no alignment point stored: the insertion point is the anchor
        rotation = float(getattr(e.dxf, "rotation", 0) or 0)
    except Exception:  # noqa: BLE001 - an odd text entity renders nothing, it never breaks the read
        return None
    if not height or height <= 0:
        return None
    return (text, float(p.x), float(p.y), height, anchor, rotation)


def read(path: Path, work: Path | None, max_sheets: int) -> dict:
    try:
        import ezdxf
        from ezdxf import path as ezpath
        from ezdxf import recover
    except ImportError:
        raise ValueError("reading DXF drawings needs the 'ezdxf' package. Install it with:  pip install ezdxf") from None
    try:
        doc, _auditor = recover.readfile(str(path))
    except (OSError, ezdxf.DXFStructureError) as exc:
        raise ValueError(f"this DXF can't be read ({exc})") from None

    code = int(doc.header.get("$INSUNITS", 0) or 0)
    units = INSUNITS.get(code, "in")
    notes = [] if code in INSUNITS else ["the drawing has no units set, so inches were assumed; check one dimension"]
    k = REAL_IN[units]                                 # real inches per drawing unit
    tol = 0.5 / k                                      # arcs flattened to within half an inch
    hidden = _hidden_layers(doc)
    msp = doc.modelspace()

    paths, texts, inserts, dims, render_extra, hatches = [], [], [], [], [], []
    render_texts = []                     # (text, x, y, height, anchor, rotation): what _render draws
    for e in msp:
        layer = (e.dxf.layer or "0") if e.dxf.hasattr("layer") else "0"
        if layer.upper() in hidden:
            continue
        t = e.dxftype()
        if t in ("LINE", "LWPOLYLINE", "POLYLINE", "ARC", "CIRCLE", "ELLIPSE", "SPLINE"):
            try:
                pts = [(v.x, v.y) for v in ezpath.make_path(e).flattening(distance=tol)]
            except Exception:  # noqa: BLE001 - 3D or broken entities are skipped
                continue
            if len(pts) < 2:
                continue
            closed = t in ("CIRCLE",) or (t in ("LWPOLYLINE", "POLYLINE") and bool(getattr(e, "closed", False)
                                                                                 or getattr(e, "is_closed", False)))
            if closed and len(pts) > 2 and pts[0] == pts[-1]:
                pts = pts[:-1]                         # the flattened path repeats its start; a polygon doesn't
            paths.append((t, layer, pts, closed))
        elif t in ("TEXT", "MTEXT"):
            text = _text_of(e)
            if text:
                ins = e.dxf.insert
                texts.append((text, layer, (ins.x, ins.y)))
                rt = _render_text(e, text)
                if rt is not None:
                    render_texts.append(rt)
        elif t == "INSERT":
            ins = e.dxf.insert
            tags = {}
            for a in getattr(e, "attribs", []) or []:
                tags[(a.dxf.tag or "").upper()] = (a.dxf.text or "").strip()
            inserts.append((e.dxf.name, layer, (ins.x, ins.y), tags))
            if len(render_extra) < 50000:
                try:
                    for ve in e.virtual_entities():
                        if ve.dxftype() in ("LINE", "LWPOLYLINE", "POLYLINE", "ARC", "CIRCLE"):
                            render_extra.append([(v.x, v.y) for v in ezpath.make_path(ve).flattening(distance=tol)])
                except Exception:  # noqa: BLE001
                    pass
        elif t == "HATCH":
            # Sprint 15: a hatch's boundary is an area (a sod or rock zone on a landscape plan); its pattern isn't drawn.
            try:
                loops = [[(v.x, v.y) for v in p.flattening(distance=tol)] for p in ezpath.from_hatch(e)]
                loops = [lp[:-1] if len(lp) > 3 and lp[0] == lp[-1] else lp for lp in loops]
                if any(len(lp) >= 3 for lp in loops) and len(hatches) < MAX_SYMBOLS:
                    hatches.append((layer, str(getattr(e.dxf, "pattern_name", "") or ""), loops))
            except Exception:  # noqa: BLE001 - odd hatch boundaries are skipped
                continue
        elif t == "DIMENSION":
            try:
                value = e.get_measurement()
                a, b = e.dxf.defpoint2, e.dxf.defpoint3
                text = (e.dxf.text or "").strip()
                if not text or text == "<>":
                    text = _dim_text(float(value), units) if isinstance(value, (int, float)) else ""
                dims.append((text, layer, (a.x, a.y), (b.x, b.y)))
            except Exception:  # noqa: BLE001 - angular and odd dimensions are skipped
                continue

    xs, ys = [], []
    for _, _, pts, _ in paths:
        xs += [p[0] for p in pts]
        ys += [p[1] for p in pts]
    for _, _, p, *_ in texts + inserts:
        xs.append(p[0])
        ys.append(p[1])
    for _, _, loops in hatches:
        for lp in loops:
            xs += [p[0] for p in lp]
            ys += [p[1] for p in lp]
    if not xs:
        raise ValueError("this DXF has nothing drawn in model space (the drawing may be in a paper-space layout only)")
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    w, h = max(maxx - minx, 1e-6), max(maxy - miny, 1e-6)

    def tr(p):                                          # y up (CAD) -> y down from the top-left
        return (round(p[0] - minx, 4), round(maxy - p[1], 4))

    objects: list[dict] = []
    segments: list = []
    wall_segments: list = []
    has_wall_layers = any(WALL_LAYER.search(layer) for _, layer, _, _ in paths)
    room_polys = []
    for t, layer, pts, closed in paths:
        tp = [tr(p) for p in pts]
        plan_line = has_wall_layers or not NOT_PLAN_LAYER.search(layer or "")
        for a, b in zip(tp, tp[1:] + ([tp[0]] if closed else [])):
            if len(segments) < MAX_SEGMENTS and plan_line:
                segments.append((a, b))
                if not has_wall_layers or WALL_LAYER.search(layer):
                    wall_segments.append((a, b))
        if closed and ROOM_LAYER.search(layer) and len(tp) >= 3:
            room_polys.append(tp)
        if len(objects) < MAX_LINEWORK:
            kind, gtype = ("line", "line") if len(tp) == 2 else (("polygon", "polygon") if closed and len(tp) >= 3
                                                                 else ("polyline", "polyline"))
            objects.append({"viewport": "model", "kind": kind, "layer": layer[:100],
                            "geometry": {"type": gtype, "points": [list(p) for p in tp]}, "source": "cad",
                            "confidence": 1})
    if len(objects) >= MAX_LINEWORK:
        notes.append(f"only the first {MAX_LINEWORK} lines and shapes were kept")

    for name, layer, p, tags in inserts[:MAX_SYMBOLS]:
        tag = next((tags[t] for t in TAG_ATTRIBS if tags.get(t)), None)
        objects.append({"viewport": "model", "kind": "symbol", "layer": layer[:100], "block_name": name[:100],
                        "tag": (tag or None) and tag[:60], "label": name[:100],
                        "geometry": {"type": "point", "points": [list(tr(p))]}, "source": "cad", "confidence": 1})
    for text, layer, p in texts[:MAX_TEXT]:
        objects.append({"viewport": "model", "kind": "text", "layer": layer[:100], "label": text[:300],
                        "geometry": {"type": "point", "points": [list(tr(p))]}, "source": "cad", "confidence": 1})
    for text, layer, a, b in dims[:MAX_DIMS]:
        objects.append({"viewport": "model", "kind": "dimension", "layer": layer[:100], "label": text[:100] or None,
                        "geometry": {"type": "line", "points": [list(tr(a)), list(tr(b))]}, "source": "cad",
                        "confidence": 1})

    walls = vectors.find_walls(vectors.clean_segments(wall_segments), k)
    objects += vectors.wall_objects(walls, "model", "cad")

    # 2026-11-20: text on a circuit layer (E-CIRCUIT "C-1", "AC 30A") labels the designer's circuits, never a room.
    from estimator.plan_engine.layers import CIRCUIT_LAYER
    labels = [(text, tr(p)) for text, layer, p in texts
              if vectors.is_room_name(text) and not CIRCUIT_LAYER.search(layer or "")]
    rooms = _rooms_from_layers(room_polys, labels)
    named = {r["label"] for r in rooms}
    min_area = vectors.ROOM_MIN_SQFT * 144 / (k * k)
    found, note = vectors.find_rooms(vectors.clean_segments(segments), [lb for lb in labels if lb[0] not in named],
                                     min_area, w * h * 1.01, simplify=0.5 / k)   # a room can be the whole drawing
    rooms += vectors.drop_enclosing(found, rooms)
    if note:
        notes.append(note)
    objects += vectors.room_objects(rooms, "model", "cad")

    # Sprint 15: site and landscape drawings - zones (zone layers, hatches, notes), fence lines and gates.
    from estimator.plan_engine import site
    title_guess = Path(path).stem.replace("_", " ")[:120]
    site_objs, site_notes = site.dxf_objects(paths, texts, inserts, hatches, tr, k,
                                             _discipline([layer for _, layer, _, _ in paths], title_guess), w, h)
    objects += site_objs
    notes += site_notes

    image_path = None
    if work is not None:
        texts_for_render = [(text, *tr((x, y)), height, anchor, rotation)
                            for text, x, y, height, anchor, rotation in render_texts[:MAX_TEXT]]
        image_path = _render(work, [[tr(p) for p in pts] for _, _, pts, _ in paths],
                             [[tr(p) for p in pts] for pts in render_extra], w, h, texts_for_render)
    layers = [layer for _, layer, _, _ in paths]
    title = Path(path).stem.replace("_", " ")[:120]
    sheet = {"page_no": 1, "sheet_no": None, "title": title, "discipline": _discipline(layers, title),
             "units": units, "width": round(w, 4), "height": round(h, 4), "image_path": image_path,
             "confidence": 0.9, "viewports": [{"key": "model", "label": "Model space", "bbox": [0, 0, round(w, 4),
                                                                                                   round(h, 4)],
                                                  "scale_method": "cad", "scale_confidence": 1}],
             "objects": objects}
    if notes:
        sheet["note"] = "; ".join(notes)
    return {"page_count": 1, "sheets": [sheet]}


def _dim_text(value: float, units: str) -> str:
    inches = value * REAL_IN[units]
    if units in ("in", "ft"):
        ft, rest = divmod(round(inches * 16) / 16, 12)
        return f"{int(ft)}'-{rest:g}\""
    return f"{value:g} {units}"


def _rooms_from_layers(polys, labels) -> list[dict]:
    """Closed polylines on ROOM/AREA/SPACE layers, named by the room name written inside each."""
    if not polys or not labels:
        return []
    try:
        from shapely.geometry import Point, Polygon
    except ImportError:
        return []
    out, used = [], set()
    for pts in polys:
        poly = Polygon(pts)
        if not poly.is_valid or poly.area <= 0:
            continue
        for i, (name, p) in enumerate(labels):
            if i not in used and poly.contains(Point(p)):
                used.add(i)
                out.append({"label": re.sub(r"\s+", " ", name.strip())[:100], "points": [tuple(q) for q in pts]})
                break
    return out


def _discipline(layers: list[str], title: str) -> str:
    """From the file name, else the layers' prefixes (A-WALL, E-POWR... NCS): the prefix most of the lines use."""
    d = discipline_for(None, title.upper())
    if d != "other":
        return d
    counts: dict[str, int] = {}
    for layer in layers:
        m = re.match(r"^([A-Z]{1,2})-", layer.upper())
        if m and (PREFIX.get(m.group(1)) or PREFIX.get(m.group(1)[:1])):
            disc = PREFIX.get(m.group(1)) or PREFIX[m.group(1)[:1]]
            counts[disc] = counts.get(disc, 0) + 1
    return max(counts, key=counts.get) if counts else "other"


def _font_for(size: int, cache: dict):
    """A TrueType font at this pixel size, cached per size: Arial on Windows, then DejaVu, then PIL's default.

    Never raises: if every font is missing, the caller passes None and draw.text falls back to its own default.
    """
    if size in cache:
        return cache[size]
    from PIL import ImageFont
    font = None
    for path in _FONT_PATHS:
        try:
            font = ImageFont.truetype(path, size)
            break
        except Exception:  # noqa: BLE001 - missing font: try the next one
            continue
    if font is None:
        try:
            font = ImageFont.truetype("arial.ttf", size)      # the system font search (Windows)
        except Exception:  # noqa: BLE001 - no system Arial either
            font = None
    if font is None:
        try:
            font = ImageFont.load_default(size=size)
        except Exception:  # noqa: BLE001 - old Pillow (no size arg) or a broken bundled font
            try:
                font = ImageFont.load_default()
            except Exception:  # noqa: BLE001 - no font at all: draw.text falls back to its own default
                font = None
    cache[size] = font
    return font


def _draw_texts(draw, texts, scale: float) -> None:
    """Draw each string at its anchor point, sized from its height in drawing units.

    Rotated text is drawn unrotated at its anchor (PIL has no rotated draw.text) - the string stays
    readable. One bad string never breaks the sheet: it is skipped and the rest still draw.
    """
    cache: dict = {}
    for item in texts:
        try:
            text, x, y, height, anchor, _rotation = item
            if not text or not text.strip() or not height or height <= 0:
                continue
            size = max(1, min(_MAX_FONT_PX, int(round(height * scale))))
            draw.text((x * scale, y * scale), text, font=_font_for(size, cache),
                      anchor=anchor, fill=(0, 0, 0))
        except Exception:  # noqa: BLE001 - a bad string/position skips itself, not the sheet
            continue


def _render(work: Path, shapes: list, extra: list, w: float, h: float, texts: list | None = None) -> str:
    """A plain black-on-white picture of the line work and its text, for review and the web app."""
    from PIL import Image, ImageDraw

    # The picture covers exactly [0, w] x [0, h] (no margin), so outlines drawn over it in drawing units line up.
    scale = (RENDER_PX - 1) / max(w, h)
    size = (max(1, int(round(w * scale)) + 1), max(1, int(round(h * scale)) + 1))
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    for pts in shapes + extra:
        if len(pts) >= 2:
            draw.line([(x * scale, y * scale) for x, y in pts], fill=(0, 0, 0), width=1)
    _draw_texts(draw, texts or [], scale)
    out = Path(work) / "sheet_001.png"
    img.save(out, "PNG", optimize=True)
    return str(out)

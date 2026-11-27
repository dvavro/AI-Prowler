"""Draw a described job as plan sheets (2026-11-24, David: "the user can just describe the plans and have AI Design it
for him" - estimator/design/describe.py makes the design, this draws it).

One DXF per sheet, at full size in feet ($INSUNITS = 2), named the way plan sets are ("C-101 SITE PLAN.dxf"), on the
layers the plan engine already reads, so the plan readers and AI Auto Measure/Count measure it like any designer's set:

  site        C-101 SITE PLAN: the lot, the building's footprint, fences on L-FENCE with their notes ("6' WOOD PRIVACY
              FENCE"), gates as notes ("4' WALK GATE", "12' DBL DRIVE GATE"), landscape zones as closed outlines on zone
              layers (L-SOD, L-MULCH ...) with notes, concrete flatwork outlines with thickness and area, trees and shrubs.
  floor       A-101 FLOOR PLAN: walls as two parallel faces on A-WALL-EXT / A-WALL-INT (door openings left open), rooms
              as closed outlines on A-AREA with their names, door and window tags (D1, W1) beside each opening, the
              door, window and room finish schedules, plumbing and HVAC fixtures as named blocks.
  foundation  S-101 FOUNDATION PLAN: the slab outline with its thickness, area and thickened edge.
  roof        A-201 ROOF PLAN: the eaves (the walls plus the overhang), ridge and hips, pitch, roof area and squares.
  demolition  D-101 DEMOLITION PLAN: what comes out, with its quantity.

Every quantity the AI readers need is printed on its sheet (lengths of each fence run and wall, areas, thicknesses), so a
reader that works from printed dimensions gets the same numbers the geometry gives.
"""
from __future__ import annotations

import math
from pathlib import Path

from estimator.design import describe as dsc

SHEETS = {"site": "C-101 SITE PLAN", "floor": "A-101 FLOOR PLAN", "foundation": "S-101 FOUNDATION PLAN",
          "roof": "A-201 ROOF PLAN", "demolition": "D-101 DEMOLITION PLAN"}
TEXT_H = 0.75
SMALL_H = 0.5
# Block names the symbol library knows (plan_engine/symbol_library.py: block words).
BLOCKS = {"water_closet": "TOILET", "lavatory": "LAVATORY", "kitchen_sink": "KITCHENSINK", "laundry_sink": "LAUNDRYSINK",
          "shower": "SHOWER", "tub": "BATHTUB", "tub_shower": "TUBSHOWER", "dishwasher": "DISHWASHER",
          "washer_box": "WASHERBOX", "hose_bibb": "HOSEBIB", "water_heater": "WATERHEATER", "tankless_water_heater": "TANKLESS",
          "floor_drain": "FLOORDRAIN", "condensing_unit": "CONDENSER", "heat_pump": "HEATPUMP", "air_handler": "AIRHANDLER",
          "furnace": "FURNACE", "mini_split_head": "MINISPLIT", "supply_diffuser": "DIFFUSER", "return_grille": "RETURN",
          "thermostat": "TSTAT", "exhaust_fan": "EXHFAN", "tree": "TREE", "palm": "PALM", "shrub": "SHRUB"}
FIXTURE_LAYER = {"tree": "L-TREE", "palm": "L-TREE", "shrub": "L-TREE"}
ZONE_LAYERS = {"sod": "L-SOD", "turf": "L-TURF-ARTIF", "mulch": "L-MULCH", "rock": "L-ROCK", "pavers": "L-PAVER",
               "bed": "L-BED"}
ZONE_WORDS = {"sod": "SOD", "turf": "ARTIFICIAL TURF", "mulch": "MULCH", "rock": "RIVER ROCK", "pavers": "PAVERS",
              "bed": "PLANTING BED"}
FENCE_WORDS = {"wood": "WOOD", "vinyl": "VINYL", "chain_link": "CHAIN LINK", "aluminum": "ALUMINUM", "iron": "WROUGHT IRON",
               "block": "BLOCK WALL"}


def ft_in(x: float) -> str:
    """12.5 -> 12'-6\" """
    inches = round(abs(x) * 12)
    return f"{'-' if x < 0 else ''}{inches // 12}'-{inches % 12}\""


def _new(title: str):
    import ezdxf
    doc = ezdxf.new("R2010", setup=True)
    doc.header["$INSUNITS"] = 2            # feet
    doc.header["$MEASUREMENT"] = 0
    return doc, doc.modelspace()


def _layer(doc, name, color=7):
    if name not in doc.layers:
        doc.layers.add(name, color=color)
    return name


def _text(msp, s, x, y, h=TEXT_H, layer="A-ANNO-TEXT", align="LEFT", rot=0.0):
    from ezdxf.enums import TextEntityAlignment
    al = {"LEFT": TextEntityAlignment.LEFT, "CENTER": TextEntityAlignment.MIDDLE_CENTER,
          "RIGHT": TextEntityAlignment.RIGHT}[align]
    t = msp.add_text(str(s), height=h, rotation=rot, dxfattribs={"layer": layer})
    t.set_placement((x, y), align=al)
    return t


def _poly(msp, pts, layer, closed=False):
    return msp.add_lwpolyline([tuple(p) for p in pts], close=closed, dxfattribs={"layer": layer})


def _bounds(pts):
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    return min(xs), min(ys), max(xs), max(ys)


def _title(doc, msp, sheet_key, project, extents):
    """A title block under the drawing: the sheet's title, the project and who drew it."""
    x0, y0, x1, _y1 = extents
    lay = _layer(doc, "A-ANNO-TTLB", 7)
    y = y0 - 6
    _text(msp, SHEETS[sheet_key], x0, y, 1.4, lay)
    _text(msp, f"{project}  -  drawn by AI design (AI-Prowler) from the customer's description - check before building",
          x0, y - 2.2, SMALL_H, lay)
    _poly(msp, [(x0 - 2, y - 3.2), (max(x1, x0 + 60) + 2, y - 3.2), (max(x1, x0 + 60) + 2, y + 2.2), (x0 - 2, y + 2.2)],
          lay, closed=True)


NOTE_WIDTH = 95           # characters on one line of a note; a longer note wraps (it used to be cut off mid-word)


def _notes(doc, msp, lines, x, y, head="NOTES", numbered=True):
    import textwrap
    lay = _layer(doc, "A-ANNO-NOTE", 7)
    _text(msp, head, x, y, TEXT_H, lay)
    at = y
    for i, ln in enumerate(lines):
        first = f"{i + 1}. {ln}" if numbered else ln
        rows = textwrap.wrap(first, NOTE_WIDTH, subsequent_indent="   ")[:14] or [first]
        for k, part in enumerate(rows):
            at -= 1.3 if k == 0 else 0.9          # a note's next line sits closer under it than the next note does
            _text(msp, part, x, at, SMALL_H, lay)
    return at - 1.3


def _table(doc, msp, title, cols, rows, x, y, widths):
    """A schedule: its title, a header row and the rows, as text in columns (the plan engine reads it as a schedule)."""
    lay = _layer(doc, "A-ANNO-SCHD", 7)
    _text(msp, title, x, y, TEXT_H, lay)
    yy = y - 1.6
    cx = x
    for c, w in zip(cols, widths):
        _text(msp, c, cx, yy, SMALL_H, lay)
        cx += w
    for r in rows:
        yy -= 1.1
        cx = x
        for v, w in zip(r, widths):
            _text(msp, v, cx, yy, SMALL_H, lay)
            cx += w
    return yy - 2.5


def _offset_seg(a, b, d):
    dx, dy = b[0] - a[0], b[1] - a[1]
    L = math.hypot(dx, dy) or 1e-9
    nx, ny = -dy / L, dx / L
    return (a[0] + nx * d, a[1] + ny * d), (b[0] + nx * d, b[1] + ny * d)


def _gaps(a, b, openings, kinds=("door", "overhead_door", "opening")):
    """Where along wall a-b (0..1) its door openings are."""
    dx, dy = b[0] - a[0], b[1] - a[1]
    L2 = dx * dx + dy * dy or 1e-12
    out = []
    for op in openings:
        if op["kind"] not in kinds:
            continue
        ts = []
        for p in (op["a"], op["b"]):
            t = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / L2
            px, py = a[0] + t * dx, a[1] + t * dy
            if math.dist(p, (px, py)) > 1.0:
                break
            ts.append(t)
        if len(ts) == 2:
            t0, t1 = sorted(ts)
            if t1 > 0 and t0 < 1:
                out.append((max(t0, 0.0), min(t1, 1.0)))
    return sorted(out)


def _wall(msp, a, b, t_ft, layer, openings):
    """A wall as its two faces, open where its doors are."""
    pieces, s = [], 0.0
    for t0, t1 in _gaps(a, b, openings):
        if t0 > s:
            pieces.append((s, t0))
        s = max(s, t1)
    if s < 1:
        pieces.append((s, 1.0))
    for t0, t1 in pieces:
        p0 = (a[0] + (b[0] - a[0]) * t0, a[1] + (b[1] - a[1]) * t0)
        p1 = (a[0] + (b[0] - a[0]) * t1, a[1] + (b[1] - a[1]) * t1)
        if math.dist(p0, p1) < 0.2:
            continue
        for side in (t_ft / 2, -t_ft / 2):
            q0, q1 = _offset_seg(p0, p1, side)
            msp.add_line(q0, q1, dxfattribs={"layer": layer})


def _inward(a, b, poly):
    """The unit normal of wall a-b pointing into the building."""
    mid = ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
    dx, dy = b[0] - a[0], b[1] - a[1]
    L = math.hypot(dx, dy) or 1e-9
    n = (-dy / L, dx / L)
    probe = (mid[0] + n[0] * 1.5, mid[1] + n[1] * 1.5)
    return n if dsc._inside(probe, poly) else (-n[0], -n[1])


def _blocks(doc):
    for kind, name in BLOCKS.items():
        if name in doc.blocks:
            continue
        blk = doc.blocks.new(name=name)
        if kind in ("tree", "palm"):
            blk.add_circle((0, 0), 4 if kind == "tree" else 3)
            blk.add_line((-1, 0), (1, 0))
            blk.add_line((0, -1), (0, 1))
        elif kind == "shrub":
            blk.add_circle((0, 0), 1.5)
        else:
            blk.add_lwpolyline([(-0.8, -0.8), (0.8, -0.8), (0.8, 0.8), (-0.8, 0.8)], close=True)
            blk.add_line((-0.8, -0.8), (0.8, 0.8))


def _fixture(doc, msp, fx):
    lay = _layer(doc, FIXTURE_LAYER.get(fx["type"]) or ("P-FIXT" if fx["type"] in (
        "water_closet", "lavatory", "kitchen_sink", "laundry_sink", "shower", "tub", "tub_shower", "dishwasher",
        "washer_box", "hose_bibb", "water_heater", "tankless_water_heater", "floor_drain") else "M-EQPM"), 3)
    msp.add_blockref(BLOCKS[fx["type"]], (fx["x"], fx["y"]), dxfattribs={"layer": lay})


def _gate_where(doc, msp, g, fences):
    """2026-11-27 (David: "the image did not show the new dimensions of the gate location"): where a gate is on its fence
    - a post mark at each side of the opening and a dimension from the nearer end of that fence line (the house tie-in or
    a corner) to the opening. The dimension says only the distance (4'-0"): a word like GATE there would be counted as
    another gate by the plan reader."""
    best = None
    for fe in fences:
        pts = fe["points"]
        for j, (a, b) in enumerate(zip(pts, pts[1:])):
            L = math.dist(a, b)
            if L < 1e-6:
                continue
            ux, uy = (b[0] - a[0]) / L, (b[1] - a[1]) / L
            s = max(0.0, min(L, (g["at"][0] - a[0]) * ux + (g["at"][1] - a[1]) * uy))
            off = math.dist(g["at"], (a[0] + ux * s, a[1] + uy * s))
            if best is None or off < best[0]:
                # an end of the whole fence line (a house tie-in) wins over a corner when the gate is as close to both
                ends = (j == 0, j == len(pts) - 2)
                best = (off, a, b, L, s, ux, uy, ends)
    if not best or best[0] > 3.0:
        return                                     # not on a drawn fence: the gate's note says where it is
    _off, a, b, L, s, ux, uy, (a_end, b_end) = best
    w = float(g.get("width_ft") or 0) or 4.0
    s0, s1 = max(0.0, s - w / 2), min(L, s + w / 2)
    gate_l, dim_l = _layer(doc, "L-GATE", 2), _layer(doc, "L-ANNO-DIMS", 7)
    nx, ny = -uy, ux
    for t in (s0, s1):                              # the posts at each side of the opening
        p = (a[0] + ux * t, a[1] + uy * t)
        msp.add_line((p[0] - nx * 0.9, p[1] - ny * 0.9), (p[0] + nx * 0.9, p[1] + ny * 0.9), dxfattribs={"layer": gate_l})
    side = _gate_swing(doc, msp, g, a, ux, uy, s0, s1)   # +1 / -1: the side it opens into; 0: not known
    from_a, from_b = s0, L - s1
    # from the end of the fence line (where it ties into the house) when only one side is one; else from the nearer side
    use_a = a_end if a_end != b_end else from_a <= from_b
    d, t0, t1 = (from_a, 0.0, s0) if use_a else (from_b, s1, L)
    if d < 0.05:
        return                                      # the opening starts right at the end: nothing to dimension
    sd = -side if side else 1                       # the dimension sits on the side the gate doesn't swing into
    k = 2.6 * sd                                    # beside the fence line
    p0 = (a[0] + ux * t0 + nx * k, a[1] + uy * t0 + ny * k)
    p1 = (a[0] + ux * t1 + nx * k, a[1] + uy * t1 + ny * k)
    msp.add_line(p0, p1, dxfattribs={"layer": dim_l})
    for p in (p0, p1):                              # the dimension's end ticks
        msp.add_line((p[0] - nx * 0.5, p[1] - ny * 0.5), (p[0] + nx * 0.5, p[1] + ny * 0.5), dxfattribs={"layer": dim_l})
    m = ((p0[0] + p1[0]) / 2 + nx * 0.8 * sd, (p0[1] + p1[1]) / 2 + ny * 0.8 * sd)
    _text(msp, ft_in(d), m[0], m[1], 0.45, dim_l, "CENTER")


def _gate_swing(doc, msp, g, a, ux, uy, s0, s1) -> int:
    """2026-11-27 (David: "add those changes to show more fence details"): which post the gate latches at and which it
    hangs on ("LATCH" / "HINGE" beside them), and its swing - the leaf drawn open at 90 degrees with its arc, on the side
    it opens into. A double drive gate (no latch post) swings from both posts. From the design's latch_at and
    opens_toward; without them nothing is guessed. Returns the side it opens into (+1 / -1 across the fence line, 0 when
    not known). The words never say GATE: that would be counted as another gate by the plan reader."""
    nx, ny = -uy, ux
    p0 = (a[0] + ux * s0, a[1] + uy * s0)
    p1 = (a[0] + ux * s1, a[1] + uy * s1)
    mid = ((p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2)
    side = 0
    tw = g.get("opens_toward")
    if tw:
        dot = (tw[0] - mid[0]) * nx + (tw[1] - mid[1]) * ny
        side = 1 if dot > 0.05 else -1 if dot < -0.05 else 0
    la = g.get("latch_at")
    lay, txt_l = _layer(doc, "L-GATE", 2), _layer(doc, "L-ANNO-GATE", 7)
    if la:
        latch, hinge = (p0, p1) if math.dist(la, p0) <= math.dist(la, p1) else (p1, p0)
        leaves = [(hinge, latch)]                   # one leaf: hung on the hinge post, closing to the latch post
    elif g.get("kind") == "drive" and side:         # a double gate - only when it's said to swing (it may slide)
        latch, hinge = None, None
        leaves = [(p0, mid), (p1, mid)]             # a double gate: a leaf from each post, meeting in the middle
    else:
        return side                                 # which end latches isn't known: no swing drawn
    lab = side or -1                                # the post words go on the swing side (or below the line)

    def word(post, s, out_dir):
        x = post[0] + out_dir[0] * 1.9 + nx * 1.0 * lab
        y = post[1] + out_dir[1] * 1.9 + ny * 1.0 * lab
        _text(msp, s, x, y, 0.4, txt_l, "CENTER")

    def away(post, other):                          # along the fence, away from the opening
        L = math.dist(post, other) or 1.0
        return ((post[0] - other[0]) / L, (post[1] - other[1]) / L)

    if latch:
        word(latch, "LATCH", away(latch, hinge))
        word(hinge, "HINGE", away(hinge, latch))
    else:
        word(p0, "HINGE", away(p0, p1))
        word(p1, "HINGE", away(p1, p0))
    if not side:
        return side
    for h, tip in leaves:
        r = math.dist(h, tip)
        if r < 0.3:
            continue
        shut = math.degrees(math.atan2(tip[1] - h[1], tip[0] - h[0]))
        swung = math.degrees(math.atan2(ny * side, nx * side))
        msp.add_line(h, (h[0] + nx * side * r, h[1] + ny * side * r), dxfattribs={"layer": lay})   # the leaf, open
        start, end = (shut, swung) if (swung - shut) % 360 <= 180 else (swung, shut)
        msp.add_arc(h, r, start, end, dxfattribs={"layer": lay})                                   # its swing
    return side


TBS = "TO BE SELECTED"


def _fence_schedule(design: dict) -> list[str]:
    """2026-11-27 (David: "we're gonna need to know the actual fence model in size on the drawing ... when we order the
    fence size and style and type it conforms to ... what he has picked"): one row per fence run and per gate (G1, G2 -
    marked beside each gate on the plan) with what gets ordered: the length, height, material and style, and the maker,
    model, panel size and color the customer chose - TO BE SELECTED where nothing was chosen, never a guess. On the
    general-notes layer, so the plan reader doesn't take a row for a fence or a gate."""
    rows = []
    for i, fe in enumerate(design.get("fences") or [], 1):
        p = fe.get("product") or {}
        maker = " ".join(x for x in (p.get("manufacturer"), p.get("model")) if x) or TBS
        what = f"{ft_in(fe['height_ft'])} {FENCE_WORDS[fe['material']]} {(fe.get('style') or '').upper()}".strip()
        bits = [f"RUN {i}: {dsc.poly_len(fe['points']):.1f} LF - {what}", f"PRODUCT: {maker}",
                f"PANELS: {p.get('panel') or TBS}", f"COLOR: {p.get('color') or TBS}"]
        if p.get("details"):
            bits.append(p["details"])
        rows.append(" - ".join(bits).upper())
    for i, g in enumerate(design.get("gates") or [], 1):
        p = g.get("product") or {}
        maker = " ".join(x for x in (p.get("manufacturer"), p.get("model")) if x) or TBS
        kind = "DOUBLE DRIVE" if g["kind"] == "drive" and not g.get("latch_at") else g["kind"].upper()
        bits = [f"G{i}: {g['width_ft']:g}' {kind} GATE", f"PRODUCT: {maker}", f"COLOR: {p.get('color') or TBS}",
                f"HINGES: {p.get('hinges') or TBS}"]
        if g["kind"] != "drive" or g.get("latch_at"):
            bits.append(f"LATCH: {p.get('latch') or TBS}")
        rows.append(" - ".join(bits).upper())
    return rows


# ------------------------------------------------------------------ the sheets
def draw_site(design: dict, out_path: str, project: str) -> dict:
    doc, msp = _new(SHEETS["site"])
    _blocks(doc)
    pts_all = []
    lot = design.get("lot")
    if lot:
        W, D = lot["width_ft"], lot["depth_ft"]
        lp = [(0, 0), (W, 0), (W, D), (0, D)]
        _poly(msp, lp, _layer(doc, "C-PROP", 1), closed=True)
        dl = _layer(doc, "C-ANNO-DIMS", 7)
        _text(msp, f"LOT {ft_in(W)} x {ft_in(D)}", W / 2, -3, TEXT_H, dl, "CENTER")
        _text(msp, "FRONT (STREET)", W / 2, -5, SMALL_H, dl, "CENTER")
        pts_all += lp
    b = design.get("building")
    if b:
        foot = b["floors"][0]["outline"]
        _poly(msp, foot, _layer(doc, "C-BLDG", 5), closed=True)
        x0, y0, x1, y1 = _bounds(foot)
        _text(msp, f"{b['name'].upper()} ({ft_in(x1 - x0)} x {ft_in(y1 - y0)})", (x0 + x1) / 2, (y0 + y1) / 2, SMALL_H,
              _layer(doc, "C-ANNO-TEXT", 7), "CENTER")
        pts_all += foot
    fl = _layer(doc, "L-FENCE", 2)
    nl = _layer(doc, "L-ANNO-FENC", 7)
    total = 0.0
    for i, fe in enumerate(design.get("fences") or [], 1):
        _poly(msp, fe["points"], fl)
        L = dsc.poly_len(fe["points"])
        total += L
        a, bb = max(zip(fe["points"], fe["points"][1:]), key=lambda s: math.dist(*s))
        mid = ((a[0] + bb[0]) / 2, (a[1] + bb[1]) / 2)
        n = _offset_seg(a, bb, 1.6)[0]
        off = (n[0] - a[0], n[1] - a[1])
        words = (f"{ft_in(fe['height_ft'])} {FENCE_WORDS[fe['material']]} {fe['style'].upper()} FENCE".replace("  ", " ")
                 .replace("BLOCK WALL FENCE", "BLOCK WALL"))
        if fe["remove_existing"]:
            words = "REMOVE EXISTING FENCE; NEW " + words
        _text(msp, f"{words} - RUN {i}: {L:.1f} LF", mid[0] + off[0], mid[1] + off[1], SMALL_H, nl)
        dl = _layer(doc, "L-ANNO-DIMS", 7)
        for p, q in zip(fe["points"], fe["points"][1:]):
            m = ((p[0] + q[0]) / 2, (p[1] + q[1]) / 2)
            o = _offset_seg(p, q, -1.4)[0]
            _text(msp, ft_in(math.dist(p, q)), m[0] + o[0] - p[0], m[1] + o[1] - p[1], 0.4, dl, "CENTER")
        pts_all += fe["points"]
    gl = _layer(doc, "L-ANNO-GATE", 7)
    for gi, g in enumerate(design.get("gates") or [], 1):
        words = f"{g['width_ft']:g}' " + ("DBL DRIVE GATE" if g["kind"] == "drive" else "WALK GATE")
        _text(msp, words, g["at"][0] + 0.8, g["at"][1] + 0.8, SMALL_H, gl)
        _text(msp, f"G{gi}", g["at"][0] + 0.8, g["at"][1] + 0.8 + SMALL_H * 1.6, SMALL_H, gl)   # its schedule row
        msp.add_circle(tuple(g["at"]), 0.6, dxfattribs={"layer": _layer(doc, "L-GATE", 2)})
        _gate_where(doc, msp, g, design.get("fences") or [])
        pts_all.append(g["at"])
    for z in design.get("zones") or []:
        lay = _layer(doc, ZONE_LAYERS[z["kind"]], 3)
        _poly(msp, z["points"], lay, closed=True)
        x0, y0, x1, y1 = _bounds(z["points"])
        words = (z["description"] or ZONE_WORDS[z["kind"]]).upper()
        if z["kind"] not in ("pavers",) and ZONE_WORDS[z["kind"]] not in words:
            words += " " + ZONE_WORDS[z["kind"]]
        if z.get("depth_in"):
            words += f' {z["depth_in"]:g}" DEEP'
        c = (sum(p[0] for p in z["points"]) / len(z["points"]), sum(p[1] for p in z["points"]) / len(z["points"]))
        _text(msp, words[:50], c[0], c[1], SMALL_H, _layer(doc, "L-ANNO-ZONE", 7), "CENTER")
        _text(msp, f"{dsc.poly_area(z['points']):,.0f} SF", c[0], c[1] - 1.0, 0.4, _layer(doc, "L-ANNO-ZONE", 7), "CENTER")
        pts_all += z["points"]
    for z in design.get("flatwork") or []:
        lay = _layer(doc, "C-CONC", 4)
        _poly(msp, z["points"], lay, closed=True)
        c = (sum(p[0] for p in z["points"]) / len(z["points"]), sum(p[1] for p in z["points"]) / len(z["points"]))
        x0, y0, x1, y1 = _bounds(z["points"])
        al = _layer(doc, "C-ANNO-CONC", 7)
        _text(msp, f'{z["thickness_in"]:g}" CONCRETE {z["kind"].upper()}', c[0], c[1] + 0.6, SMALL_H, al, "CENTER")
        _text(msp, f"{ft_in(x1 - x0)} x {ft_in(y1 - y0)} = {dsc.poly_area(z['points']):,.0f} SF", c[0], c[1] - 0.6, 0.4,
              al, "CENTER")
        pts_all += z["points"]
    for fx in design.get("fixtures") or []:
        if fx["type"] in ("tree", "palm", "shrub"):
            _fixture(doc, msp, fx)
            pts_all.append((fx["x"], fx["y"]))
    if not pts_all:
        pts_all = [(0, 0), (20, 20)]
    ext = _bounds(pts_all)
    # General notes: on the general-notes layer, and kept more than 20 ft from the drawing (a fence takes the nearest fence
    # note within 20 ft as its label).
    lines = []
    if design.get("fences"):
        lines.append(f"TOTAL OF ALL NEW RUNS: {total:.1f} LF IN {len(design['fences'])} RUN(S); POSTS 8' O.C. MAX")
    # 2026-11-27 (David: "the image did not show the new dimensions of the gate location or the new notes"): every note
    # goes on the sheet - the gate, latch and fence notes too. They're on the general-notes layer (A-ANNO-NOTE), which
    # the plan reader never takes for a fence, a gate or a zone (plan_engine/site.py GENERAL_NOTE_LAYER_RE).
    lines += [n.upper() for n in design.get("notes") or []]
    top = ext[3]
    sched = _fence_schedule(design)
    if sched:
        top = _notes(doc, msp, sched, ext[2] + 30, top, "FENCE AND GATE SCHEDULE", numbered=False) - 1.5
    if lines:
        _notes(doc, msp, lines, ext[2] + 30, top)
    _title(doc, msp, "site", project, ext)
    doc.saveas(out_path)
    return {"sheet": "site", "path": out_path, "fence_lf": round(total, 1)}


def draw_floor(design: dict, out_path: str, project: str) -> dict:
    b = design["building"]
    doc, msp = _new(SHEETS["floor"])
    _blocks(doc)
    t_ft = b["wall_thickness_in"] / 12.0
    ext_l, int_l = _layer(doc, "A-WALL-EXT", 7), _layer(doc, "A-WALL-INT", 8)
    area_l, room_t = _layer(doc, "A-AREA", 9), _layer(doc, "A-AREA-IDEN", 7)
    door_l, glaz_l = _layer(doc, "A-DOOR", 8), _layer(doc, "A-GLAZ", 8)
    dtag_l, wtag_l = _layer(doc, "A-DOOR-IDEN", 7), _layer(doc, "A-GLAZ-IDEN", 7)
    dims_l = _layer(doc, "A-ANNO-DIMS", 7)
    ox, pts_all = 0.0, []
    for fl in b["floors"]:
        sx = ox                                        # floors side by side, 25 ft apart
        poly = [(p[0] + sx, p[1]) for p in fl["outline"]]
        ops = [{**o, "a": (o["a"][0] + sx, o["a"][1]), "b": (o["b"][0] + sx, o["b"][1])} for o in fl["openings"]]
        for a, c in zip(poly, poly[1:] + poly[:1]):
            _wall(msp, a, c, t_ft, ext_l, ops)
            m = ((a[0] + c[0]) / 2, (a[1] + c[1]) / 2)
            n = _inward(a, c, poly)
            _text(msp, ft_in(math.dist(a, c)), m[0] - n[0] * 2.2, m[1] - n[1] * 2.2, 0.45, dims_l, "CENTER")
        for w in fl["interior_walls"]:
            a, c = (w[0][0] + sx, w[0][1]), (w[1][0] + sx, w[1][1])
            _wall(msp, a, c, t_ft * (4.5 / 6.0) if b["wall_thickness_in"] >= 6 else t_ft, int_l, ops)
        for rm in fl["rooms"]:
            r = [(rm["x0"] + sx, rm["y0"]), (rm["x1"] + sx, rm["y0"]), (rm["x1"] + sx, rm["y1"]), (rm["x0"] + sx, rm["y1"])]
            _poly(msp, r, area_l, closed=True)
            c = ((rm["x0"] + rm["x1"]) / 2 + sx, (rm["y0"] + rm["y1"]) / 2)
            _text(msp, rm["name"], c[0], c[1] + 0.5, TEXT_H * 0.8, room_t, "CENTER")
            _text(msp, f"{ft_in(rm['x1'] - rm['x0'])} x {ft_in(rm['y1'] - rm['y0'])}", c[0], c[1] - 0.6, 0.4, dims_l,
                  "CENTER")
        for op in ops:
            a, c = op["a"], op["b"]
            mid = ((a[0] + c[0]) / 2, (a[1] + c[1]) / 2)
            walls = list(zip(poly, poly[1:] + poly[:1]))
            near = min(walls, key=lambda s: dsc._seg_dist(mid, s[0], s[1]))
            on_ext = dsc._seg_dist(mid, near[0], near[1]) <= 1.0
            n = _inward(near[0], near[1], poly) if on_ext else _offset_seg(a, c, 1)[0]
            if not on_ext:
                n = (n[0] - a[0], n[1] - a[1])
            if op["kind"] == "window":
                for d in (-t_ft / 2, 0, t_ft / 2):
                    q0, q1 = _offset_seg(a, c, d)
                    msp.add_line(q0, q1, dxfattribs={"layer": glaz_l})
            else:
                w = math.dist(a, c)
                if op["kind"] == "door" and w <= 4.5:
                    tip = (a[0] + n[0] * w, a[1] + n[1] * w)
                    msp.add_line(a, tip, dxfattribs={"layer": door_l})
                else:
                    msp.add_line(a, c, dxfattribs={"layer": door_l})
            if op.get("mark"):
                # beside the jamb on a wide opening: the plan reader puts a tag on the wall within 3 ft of it, and a
                # door opening has no wall in its middle
                L = math.dist(a, c) or 1
                k = min(L / 2, 1.5) / L
                at = (a[0] + (c[0] - a[0]) * k, a[1] + (c[1] - a[1]) * k)
                tp = (at[0] + n[0] * 1.3, at[1] + n[1] * 1.3)
                _text(msp, op["mark"], tp[0], tp[1], SMALL_H, wtag_l if op["kind"] == "window" else dtag_l, "CENTER")
        for fx in design.get("fixtures") or []:
            if fx["type"] not in ("tree", "palm", "shrub") and fl is b["floors"][0]:
                _fixture(doc, msp, {**fx, "x": fx["x"] + sx})
        _text(msp, f"{fl['name']} FLOOR PLAN - {dsc.poly_area(fl['outline']):,.0f} SF", _bounds(poly)[0],
              _bounds(poly)[1] - 4.5, TEXT_H, _layer(doc, "A-ANNO-TEXT", 7))
        pts_all += poly
        ox = _bounds(poly)[2] + 25
    ext = _bounds(pts_all)
    # the schedules, to the right of the plan
    x, y = ext[2] + 10, ext[3]
    if design.get("doors"):
        y = _table(doc, msp, "DOOR SCHEDULE", ["MARK", "WIDTH", "HEIGHT", "TYPE", "QTY"],
                   [[d["mark"], ft_in(d["width_ft"]), ft_in(d["height_ft"]), (d["description"] or d["type"]).upper()[:28],
                     str(sum(1 for f in b["floors"] for o in f["openings"] if o.get("mark") == d["mark"]))]
                    for d in design["doors"]], x, y, (3.5, 4, 4, 14, 3))
    if design.get("windows"):
        y = _table(doc, msp, "WINDOW SCHEDULE", ["MARK", "WIDTH", "HEIGHT", "TYPE", "QTY"],
                   [[w["mark"], ft_in(w["width_ft"]), ft_in(w["height_ft"]), (w["description"] or "WINDOW").upper()[:28],
                     str(sum(1 for f in b["floors"] for o in f["openings"] if o.get("mark") == w["mark"]))]
                    for w in design["windows"]], x, y, (3.5, 4, 4, 14, 3))
    rows = [[rm["name"], (rm.get("floor") or "").upper()[:14], ft_in(rm.get("ceiling_ft") or fl["ceiling_ft"])]
            for fl in b["floors"] for rm in fl["rooms"]]
    y = _table(doc, msp, "ROOM FINISH SCHEDULE", ["ROOM NAME", "FLOOR", "CEILING HEIGHT"], rows, x, y, (12, 8, 8))
    lines = [f"WALLS {b['wall_thickness_in']:g}\" THICK (EXTERIOR); INTERIOR 4-1/2\""]
    if b.get("siding"):
        lines.append(f"EXTERIOR: {b['siding'].upper()}")
    lines += [a.upper() for a in design.get("assumptions") or []][:6]
    _notes(doc, msp, lines, x, y)
    _title(doc, msp, "floor", project, ext)
    doc.saveas(out_path)
    return {"sheet": "floor", "path": out_path}


def draw_foundation(design: dict, out_path: str, project: str) -> dict:
    b = design["building"]
    f = b["foundation"]
    doc, msp = _new(SHEETS["foundation"])
    poly = b["floors"][0]["outline"]
    _poly(msp, poly, _layer(doc, "S-SLAB-EDGE", 4), closed=True)
    inner = []
    for p in poly:                                     # the thickened edge's inside line, ~ the footing width in
        c = (sum(q[0] for q in poly) / len(poly), sum(q[1] for q in poly) / len(poly))
        L = math.dist(p, c) or 1
        k = (f["footing_in"] / 12.0) / L
        inner.append((p[0] + (c[0] - p[0]) * k, p[1] + (c[1] - p[1]) * k))
    if f["footing_in"]:
        _poly(msp, inner, _layer(doc, "S-FOOT", 8), closed=True)
    dl = _layer(doc, "S-ANNO-DIMS", 7)
    for a, c in zip(poly, poly[1:] + poly[:1]):
        m = ((a[0] + c[0]) / 2, (a[1] + c[1]) / 2)
        n = _inward(a, c, poly)
        _text(msp, ft_in(math.dist(a, c)), m[0] - n[0] * 2.2, m[1] - n[1] * 2.2, 0.45, dl, "CENTER")
    area = dsc.poly_area(poly)
    perim = dsc.poly_len(poly, True)
    x0, y0, x1, y1 = _bounds(poly)
    nl = _layer(doc, "S-ANNO-NOTE", 7)
    _text(msp, f'{f["thickness_in"]:g}" CONCRETE SLAB ON GRADE', (x0 + x1) / 2, (y0 + y1) / 2 + 0.8, TEXT_H * 0.8, nl, "CENTER")
    _text(msp, f"SLAB AREA {area:,.0f} SF ({ft_in(x1 - x0)} x {ft_in(y1 - y0)})", (x0 + x1) / 2, (y0 + y1) / 2 - 0.6,
          SMALL_H, nl, "CENTER")
    cy = area * f["thickness_in"] / 12.0 / 27.0 + (perim * (f["footing_in"] / 12.0) ** 2 / 27.0 if f["footing_in"] else 0)
    lines = [f'{f["thickness_in"]:g}" CONCRETE SLAB ON GRADE, 3000 PSI, ON 6 MIL VAPOR BARRIER',
             f"SLAB AREA: {area:,.0f} SF; PERIMETER {perim:.1f} LF",
             (f'THICKENED EDGE FOOTING {f["footing_in"]:g}" WIDE x {f["footing_in"]:g}" DEEP: {perim:.1f} LF'
              if f["footing_in"] else "NO THICKENED EDGE"),
             f"CONCRETE: ABOUT {cy:.1f} CY (BEFORE WASTE)", "WWF 6x6 W1.4xW1.4 OR #3 BARS 18\" O.C. EACH WAY"]
    _notes(doc, msp, lines, x1 + 8, y1)
    _title(doc, msp, "foundation", project, (x0, y0, x1, y1))
    doc.saveas(out_path)
    return {"sheet": "foundation", "path": out_path, "slab_sqft": round(area, 1), "concrete_cy": round(cy, 2)}


def draw_roof(design: dict, out_path: str, project: str) -> dict:
    b = design["building"]
    r = b["roof"]
    doc, msp = _new(SHEETS["roof"])
    x0, y0, x1, y1 = _bounds(b["floors"][0]["outline"])
    o = r["overhang_ft"]
    E = [(x0 - o, y0 - o), (x1 + o, y0 - o), (x1 + o, y1 + o), (x0 - o, y1 + o)]
    rl = _layer(doc, "A-ROOF", 6)
    _poly(msp, E, rl, closed=True)
    _poly(msp, b["floors"][0]["outline"], _layer(doc, "A-ROOF-WALL", 8), closed=True)
    ex0, ey0, ex1, ey1 = E[0][0], E[0][1], E[2][0], E[2][1]
    cx, cy = (ex0 + ex1) / 2, (ey0 + ey1) / 2
    if r["style"] == "gable":
        msp.add_line((ex0, cy) if r["ridge"] == "x" else (cx, ey0), (ex1, cy) if r["ridge"] == "x" else (cx, ey1),
                     dxfattribs={"layer": rl})
    elif r["style"] == "hip":
        h = min(ex1 - ex0, ey1 - ey0) / 2
        if r["ridge"] == "x":
            a, c = (ex0 + h, cy), (ex1 - h, cy)
        else:
            a, c = (cx, ey0 + h), (cx, ey1 - h)
        msp.add_line(a, c, dxfattribs={"layer": rl})
        for corner, end in (((ex0, ey0), a), ((ex0, ey1), a), ((ex1, ey0), c), ((ex1, ey1), c)):
            msp.add_line(corner, end, dxfattribs={"layer": rl})
    nums = dsc.roof_numbers(b)
    nl = _layer(doc, "A-ANNO-NOTE", 7)
    _text(msp, f"{r['pitch']} PITCH" if r["style"] != "flat" else "FLAT ROOF (1/4\" PER FT)", cx, cy + 1.2, TEXT_H * 0.8,
          nl, "CENTER")
    _text(msp, f"ROOF AREA {nums['roof_sqft']:,.0f} SF = {nums['squares']:g} SQ", cx, cy - 1.2, SMALL_H, nl, "CENTER")
    lines = [f"{r['style'].upper()} ROOF, {r['pitch']} PITCH, {ft_in(o)} OVERHANG",
             f"ROOFING: {r['material'].upper()} OVER SYNTHETIC UNDERLAYMENT",
             f"ROOF AREA (SLOPED): {nums['roof_sqft']:,.0f} SF = {nums['squares']:g} SQUARES; PLAN AREA {nums['plan_sqft']:,.0f} SF",
             f"EAVES {nums.get('eave_lf', 0):.1f} LF" + (f"; RAKES {nums['rake_lf']:.1f} LF" if nums.get("rake_lf") else "")
             + (f"; RIDGE {nums['ridge_lf']:.1f} LF" if nums.get("ridge_lf") else "")
             + (f"; HIPS {nums['hip_lf']:.1f} LF" if nums.get("hip_lf") else ""),
             "DRIP EDGE AT EAVES AND RAKES; RIDGE VENT FULL LENGTH OF RIDGE"]
    _notes(doc, msp, lines, ex1 + 8, ey1)
    _title(doc, msp, "roof", project, (ex0, ey0, ex1, ey1))
    doc.saveas(out_path)
    return {"sheet": "roof", "path": out_path, **nums}


def draw_demolition(design: dict, out_path: str, project: str) -> dict:
    doc, msp = _new(SHEETS["demolition"])
    lines = [f"{d['what'].upper()}: {d['qty']:g} {d['unit'].upper()}" for d in design["demolition"]]
    _notes(doc, msp, lines + ["HAUL AWAY AND DISPOSE OF ALL DEBRIS; PROTECT WHAT STAYS"], 0, 0, "DEMOLITION")
    _title(doc, msp, "demolition", project, (0, -1.3 * (len(lines) + 2), 60, 0))
    doc.saveas(out_path)
    return {"sheet": "demolition", "path": out_path}


DRAW = {"site": draw_site, "floor": draw_floor, "foundation": draw_foundation, "roof": draw_roof,
        "demolition": draw_demolition}


def draw_all(design: dict, folder: Path, project: str, prefix: str) -> list[dict]:
    """Every sheet the design needs, as DXF files in folder (prefix_<sheet>.dxf). Returns [{sheet, path, ...}]."""
    out = []
    for key in dsc.sheets_for(design):
        out.append(DRAW[key](design, str(Path(folder) / f"{prefix}_{key}.dxf"), project))
    return out

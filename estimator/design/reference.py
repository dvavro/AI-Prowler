"""The AI's reference picture of a design (2026-11-23, David: "is it possible to add screenshots to the AI Design to give
geometric guidance to the AI, for example move this here").

When the person attaches screenshots (a marked-up view of the plan, an arrow drawn on a photo), the AI also gets this
picture, drawn by the app with PIL: the building in feet with a 5 ft grid labelled every 10 ft, its doors, windows and
room names, the panel, and every device of the current design as a numbered dot (number = its place in the design's
device list, 1-based). So "move this one here" on a screenshot becomes "device 12 to x 30, y 44" - the AI matches the
screenshot to the reference picture and reads the coordinates off the grid.
"""
from __future__ import annotations

import io

from estimator.design.draw_electrical import DEVICES

PX_MAX = 1500                     # the picture's long side
MARGIN = 70
GRID_FT = 5
CODES = {"outlet": "R", "outlet_gfci": "GF", "outlet_wp": "WP", "outlet_usb": "U", "outlet_quad": "Q", "outlet_240": "240",
         "range_outlet": "RNG", "dryer_outlet": "DRY", "ev_charger": "EV", "disconnect": "DS", "switch": "S",
         "switch_3way": "S3", "switch_4way": "S4", "switch_dimmer": "SD", "light": "L", "light_led": "LED",
         "light_recessed": "RL", "light_pendant": "PL", "light_wall": "WL", "light_undercabinet": "UC",
         "light_exterior": "XL", "fan": "F", "exhaust_fan": "EF", "smoke": "SM", "smoke_co": "SC", "junction_box": "J",
         "data": "D", "tv": "TV"}
COLORS = {"wall": (37, 99, 235), "ceiling": (234, 88, 12), "exterior": (22, 163, 74)}


def render(building: dict, design: dict | None = None) -> bytes:
    """PNG bytes of the reference picture: every floor side by side, x along the front, y toward the rear (up)."""
    from PIL import Image, ImageDraw, ImageFont
    floors = building["floors"]
    spans = []
    for f in floors:
        xs, ys = [p[0] for p in f["outline"]], [p[1] for p in f["outline"]]
        spans.append((min(xs), min(ys), max(xs), max(ys)))
    gap = 12.0
    width_ft = sum(s[2] - s[0] for s in spans) + gap * (len(spans) - 1) + 8      # + room for outside devices
    height_ft = max(s[3] - s[1] for s in spans) + 8
    k = (PX_MAX - 2 * MARGIN) / max(width_ft, height_ft)
    W, H = int(width_ft * k + 2 * MARGIN), int(height_ft * k + 2 * MARGIN)
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 13)
        small = ImageFont.truetype("arial.ttf", 11)
        big = ImageFont.truetype("arialbd.ttf", 16)
    except OSError:
        font = small = big = ImageFont.load_default()
    offs, at = [], 4.0
    for s in spans:
        offs.append(at - s[0])
        at += s[2] - s[0] + gap

    def P(fi, x, y):                                       # feet on floor fi -> pixels (y up)
        return (MARGIN + (x + offs[fi]) * k, H - MARGIN - (y - spans[fi][1] + 4) * k)

    for fi, f in enumerate(floors):
        x0, y0, x1, y1 = spans[fi]
        # the grid, in this floor's own feet (the coordinates the design uses)
        gx = int(x0 // GRID_FT) * GRID_FT - GRID_FT
        while gx <= x1 + GRID_FT:
            a, b = P(fi, gx, y0 - 3), P(fi, gx, y1 + 3)
            d.line([a, b], fill=(225, 225, 225) if gx % 10 else (200, 200, 200), width=1)
            if gx % 10 == 0:
                d.text((a[0] - 6, H - MARGIN + 6), f"{gx:g}", fill=(90, 90, 90), font=small)
            gx += GRID_FT
        gy = int(y0 // GRID_FT) * GRID_FT - GRID_FT
        while gy <= y1 + GRID_FT:
            a, b = P(fi, x0 - 3, gy), P(fi, x1 + 3, gy)
            d.line([a, b], fill=(225, 225, 225) if gy % 10 else (200, 200, 200), width=1)
            if gy % 10 == 0 and fi == 0:
                d.text((MARGIN - 34, a[1] - 7), f"{gy:g}", fill=(90, 90, 90), font=small)
            gy += GRID_FT
        pts = [P(fi, *p) for p in f["outline"]]
        d.line(pts + [pts[0]], fill=(20, 20, 20), width=5)
        for w in f.get("interior_walls") or []:
            d.line([P(fi, *w[0]), P(fi, *w[1])], fill=(60, 60, 60), width=3)
        for o in f.get("openings") or []:
            a, b = P(fi, *o["a"]), P(fi, *o["b"])
            if o["kind"] == "window":
                d.line([a, b], fill=(56, 189, 248), width=5)
            else:
                d.line([a, b], fill="white", width=7)
                d.line([a, b], fill=(160, 160, 160), width=1)
                lab = o.get("label") or o["kind"].replace("_", " ")
                d.text(((a[0] + b[0]) / 2 - 3 * len(lab), (a[1] + b[1]) / 2 + 6), lab, fill=(110, 110, 110), font=small)
        for r in f.get("rooms") or []:
            c = P(fi, (r["x0"] + r["x1"]) / 2, (r["y0"] + r["y1"]) / 2)
            d.text((c[0] - 4 * len(r["name"]), c[1] - 8), r["name"], fill=(150, 150, 150), font=big)
        name = (f.get("name") or f"FLOOR {fi + 1}") + " FLOOR"
        t = P(fi, x0, y1 + 3)
        d.text((t[0], t[1] - 18), name, fill=(20, 20, 20), font=big)
    if design:
        p = design.get("panel") or {}
        fi = int(p.get("floor") or 0)
        if fi < len(floors) and p.get("x") is not None:
            c = P(fi, float(p["x"]), float(p["y"]))
            d.rectangle([c[0] - 14, c[1] - 9, c[0] + 14, c[1] + 9], fill=(30, 30, 30))
            d.text((c[0] - 4, c[1] - 7), "P", fill="white", font=font)
        for i, dev in enumerate(design.get("devices") or []):
            fi = int(dev.get("floor") or 0)
            if fi >= len(floors) or dev.get("type") not in DEVICES:
                continue
            c = P(fi, float(dev["x"]), float(dev["y"]))
            col = COLORS[DEVICES[dev["type"]][2]]
            d.ellipse([c[0] - 5, c[1] - 5, c[0] + 5, c[1] + 5], fill=col)
            d.text((c[0] + 6, c[1] - 14), f"{i + 1}:{CODES.get(dev['type'], '?')}", fill=col, font=small)
    d.text((MARGIN, 14), "REFERENCE (feet): x along the front wall from the front-left corner, y toward the rear. Grid 5 ft, "
                         "labels every 10 ft." + ("  Dots: devices, numbered as in the design's list (number:code); P = panel."
                                                  if design else ""), fill=(20, 20, 20), font=font)
    d.text((MARGIN, 32), "Blue dots: wall devices · orange: ceiling · green: outside.  FRONT is at the bottom.",
           fill=(90, 90, 90), font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def legend_text(design: dict | None) -> str:
    return ", ".join(f"{v}={k}" for k, v in CODES.items()) if design else ""

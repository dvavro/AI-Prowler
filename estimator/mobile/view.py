"""A picture of one symbol or measurement in place on its sheet, outlined in red: the phone's highlight, without the
tiled viewer. Cut from the sheet image the plan engine saved (local only; nothing is sent to an AI provider) and cached
in the data folder."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from estimator.context import RequestContext
from estimator.errors import NotFound

MIN_SPAN_IN = 6.0        # show at least 6 x 6 sheet inches, so the item is seen with what's round it
PAD_IN = 1.5             # sheet inches added round the item
OUT_W = 900              # pixels across at most
RED = (220, 38, 38)


def _points(geom) -> tuple[str, list[tuple[float, float]]]:
    if not isinstance(geom, dict):
        return "", []
    pts = geom.get("points")
    if pts is None and geom.get("point") is not None:
        pts = [geom["point"]]
    try:
        return str(geom.get("type") or ""), [(float(p[0]), float(p[1])) for p in pts or []]
    except (TypeError, ValueError, IndexError):
        return "", []


def _sheet(conn, ctx: RequestContext, sheet_id: int) -> dict:
    r = conn.execute("SELECT id, image_path, width, height FROM sheets WHERE company_id = ? AND id = ?",
                     (ctx.company_id, sheet_id)).fetchone()
    if not r or not r["image_path"] or not Path(r["image_path"]).is_file() or not r["width"]:
        raise NotFound("this sheet has no picture", sheet_id=sheet_id)
    return dict(r)


def _shapes(conn, ctx: RequestContext, kind: str, item_id: int) -> tuple[int, list[tuple[str, list]]]:
    """(sheet_id, [(type, points)]) in sheet inches."""
    if kind == "symbol":
        from estimator.symbols import review
        d = review.load_detections(conn, ctx, [item_id])[0]
        x0, y0, x1, y1 = review._box(d, pad=0.08)
        return d["sheet_id"], [("box", [(x0, y0), (x1, y1)])]
    m = conn.execute("SELECT sheet_id, geometry_json, source_object_ids FROM measurements WHERE company_id = ? AND id = ?",
                     (ctx.company_id, item_id)).fetchone()
    if not m:
        raise NotFound(f"measurement {item_id} not found", measurement_id=item_id)
    if not m["sheet_id"]:
        raise NotFound("this measurement isn't on a sheet (it was typed in)", measurement_id=item_id)
    shapes = []
    if m["geometry_json"]:
        t, pts = _points(json.loads(m["geometry_json"]))
        if pts:
            shapes.append((t, pts))
    if not shapes:
        ids = [int(i) for i in json.loads(m["source_object_ids"] or "[]")][:500]
        if ids:
            for r in conn.execute(f"SELECT geometry_json FROM drawing_objects WHERE company_id = ? AND sheet_id = ?"
                                  f" AND id IN ({','.join('?' for _ in ids)})", (ctx.company_id, m["sheet_id"], *ids)):
                t, pts = _points(json.loads(r["geometry_json"]))
                if pts:
                    shapes.append((t, pts))
    if not shapes:
        raise NotFound("this measurement has no shape on the plan", measurement_id=item_id)
    return m["sheet_id"], shapes


def view_png(conn, ctx: RequestContext, kind: str, item_id: int, data_dir: Path) -> Path:
    from PIL import Image, ImageDraw
    sheet_id, shapes = _shapes(conn, ctx, kind, int(item_id))
    s = _sheet(conn, ctx, sheet_id)
    img_path = Path(s["image_path"])
    key = hashlib.sha1(json.dumps([shapes, str(img_path), img_path.stat().st_mtime_ns]).encode()).hexdigest()[:12]
    out_dir = Path(data_dir) / "review_views"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{ctx.company_id}_{kind}_{int(item_id)}_{key}.png"
    if out.is_file():
        return out
    xs = [p[0] for _, pts in shapes for p in pts]
    ys = [p[1] for _, pts in shapes for p in pts]
    sw, sh = float(s["width"]), float(s["height"] or 0) or float(s["width"])
    span = max(max(xs) - min(xs) + 2 * PAD_IN, max(ys) - min(ys) + 2 * PAD_IN, MIN_SPAN_IN)
    cx, cy = (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2
    fx0 = min(max(0.0, cx - span / 2), max(0.0, sw - span))
    fy0 = min(max(0.0, cy - span / 2), max(0.0, sh - span))
    fx1, fy1 = min(sw, fx0 + span), min(sh, fy0 + span)
    with Image.open(img_path) as src:
        k = src.size[0] / sw
        box = (int(fx0 * k), int(fy0 * k), max(int(fx0 * k) + 1, int(fx1 * k)), max(int(fy0 * k) + 1, int(fy1 * k)))
        crop = src.crop(box).convert("RGB")
    scale = min(1.0, OUT_W / max(1, crop.size[0]))
    if scale < 1.0:
        crop = crop.resize((max(1, int(crop.size[0] * scale)), max(1, int(crop.size[1] * scale))))
    f = k * scale

    def px(p):
        return ((p[0] - fx0) * f, (p[1] - fy0) * f)

    overlay = Image.new("RGBA", crop.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    w = max(3, int(round(crop.size[0] / 180)))
    for t, pts in shapes:
        q = [px(p) for p in pts]
        if t == "box":
            (x0, y0), (x1, y1) = q
            pad = w * 2
            d.rectangle((x0 - pad, y0 - pad, x1 + pad, y1 + pad), outline=RED + (255,), width=w)
        elif t in ("polygon", "room") and len(q) >= 3:
            d.polygon(q, fill=RED + (48,))
            d.line(q + [q[0]], fill=RED + (255,), width=w, joint="curve")
        elif len(q) >= 2 and t in ("line", "polyline", "wall", "dimension"):
            d.line(q, fill=RED + (255,), width=w, joint="curve")
        else:
            r = w * 4
            for x, y in q:
                d.ellipse((x - r, y - r, x + r, y + r), outline=RED + (255,), width=w)
    Image.alpha_composite(crop.convert("RGBA"), overlay).convert("RGB").save(out, "PNG", optimize=True)
    return out

"""Symbol Recognition Engine v1 (spec: legend-first workflow, steps 3-5; "four technologies, one result").

The plan set's own legend comes first: every legend entry with a drawn symbol is a template, and every sheet is
searched for it. Each hit is then checked against the words around it and fused into one result per symbol.

- Vector sheets (PDF line work): the template is the legend symbol's line work. A copy on the plans is found by
  laying the template's longest stroke on every stroke of about the same length (any rotation, mirrored or not,
  within 10% of the size) and scoring how much of the template lands on line work (forward) and how much of the
  line work there is explained by the template (reverse), so a symbol with extra strokes isn't taken for a simpler one.
- Raster sheets (scans, photos): normalized cross-correlation of the legend's picture over the sheet image, at four
  rotations and mirrored (numpy/scipy FFT; no OpenCV needed).
- CAD (DXF): a block's name says what it is (DUPLEX_OUTLET_GFI); the standard library maps block-name words.
- OCR fusion: codes next to a symbol (GFI, WP, $3) choose between look-alike legend entries, and a code from the
  standard library can refine the type when the legend has no such entry (a plain receptacle with "GFI" beside it).
  Legend entries that are only a code (no drawn symbol) are counted where the code stands on its own on the plans.
- AI reasoning on a crop (the fourth technology) comes later; its score is left empty, and anything unsure is left
  "proposed" for the Blueprint Review queue.

Every result: definition (legend entry key, or "std:<item type>"), item type, trade, location, rotation, mirrored,
each technology's score and one combined confidence. The drawing model saves them as symbol objects plus
symbol_detections rows (estimator/symbols/results.py). Nothing here is ever approved automatically.
"""
from __future__ import annotations

import math

STEP = 0.008                 # inches between sample points along line work
MIN_DIAG, MAX_DIAG = 0.06, 1.5
LONG = 1.5                   # line work longer than this x the symbol's size is a wall or a leader, not a symbol
MIN_FORWARD = 0.8
MIN_SCORE = 0.78
SCALE_TOL = 0.10
MAX_CANDIDATES = 20000       # anchor tries per template per sheet
MAX_DETECTIONS = 3000        # per sheet
RASTER_PX = 60               # pixels per inch for raster matching
RASTER_MIN = 0.7


# ---------------------------------------------------------------- templates from the legend

def _seg_len(s):
    (ax, ay), (bx, by) = s
    return math.hypot(bx - ax, by - ay)


def _inside(p, box, pad=0.0) -> bool:
    return box[0] - pad <= p[0] <= box[2] + pad and box[1] - pad <= p[1] <= box[3] + pad


def _sample(segs, step=STEP):
    import numpy as np
    out = []
    for (a, b) in segs:
        n = max(1, int(math.ceil(_seg_len((a, b)) / step)))
        t = np.linspace(0.0, 1.0, n + 1)
        out.append(np.column_stack([a[0] + t * (b[0] - a[0]), a[1] + t * (b[1] - a[1])]))
    return np.vstack(out) if out else np.zeros((0, 2))


def template_from(segments, box) -> dict | None:
    """The line work of one legend symbol, centred on (0, 0). None when there's nothing usable in the box."""
    segs = [s for s in segments if _inside(s[0], box, 0.02) and _inside(s[1], box, 0.02) and _seg_len(s) > 1e-4]
    if not segs:
        return None
    return _build(segs)


def _build(segs) -> dict | None:
    xs = [p[0] for s in segs for p in s]
    ys = [p[1] for s in segs for p in s]
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    diag = math.hypot(x1 - x0, y1 - y0)
    if not MIN_DIAG <= diag <= MAX_DIAG:
        return None
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    rel = [((a[0] - cx, a[1] - cy), (b[0] - cx, b[1] - cy)) for a, b in segs]
    anchor = max(rel, key=_seg_len)
    return {"segs": rel, "pts": _sample(rel), "diag": diag, "w": x1 - x0, "h": y1 - y0, "anchor": anchor,
            "n_segs": len(rel)}


MAX_TEMPLATE_SEGS = 400


def template_to_json(tpl: dict) -> dict:
    """A vector template as plain data (kept with a confirmed example in estimator.db, Sprint 11)."""
    return {"kind": "vector", "segs": [[round(a[0], 5), round(a[1], 5), round(b[0], 5), round(b[1], 5)]
                                       for a, b in tpl["segs"][:MAX_TEMPLATE_SEGS]]}


def template_from_json(data) -> dict | None:
    try:
        segs = [((float(s[0]), float(s[1])), (float(s[2]), float(s[3]))) for s in data["segs"][:MAX_TEMPLATE_SEGS]]
    except (KeyError, TypeError, ValueError, IndexError):
        return None
    segs = [s for s in segs if _seg_len(s) > 1e-4]
    t = _build(segs) if segs else None
    return {**t, "kind": "vector"} if t else None


# ---------------------------------------------------------------- vector matching

class PageIndex:
    """The short line work of one sheet, sampled into points with a KD-tree for fast "is there ink here?" lookups."""

    def __init__(self, segments, max_len: float):
        import numpy as np
        from scipy.spatial import cKDTree
        self.segs = [s for s in segments if 1e-4 < _seg_len(s) <= max_len]
        self.lens = np.array([_seg_len(s) for s in self.segs]) if self.segs else np.zeros(0)
        pts, owner = [], []
        for i, s in enumerate(self.segs):
            p = _sample([s])
            pts.append(p)
            owner.append(np.full(len(p), i))
        self.pts = np.vstack(pts) if pts else np.zeros((0, 2))
        self.owner = np.concatenate(owner) if owner else np.zeros(0, dtype=int)
        self.tree = cKDTree(self.pts) if len(self.pts) else None


def _angle(s):
    (ax, ay), (bx, by) = s
    return math.atan2(by - ay, bx - ax)


def _transform(pts, theta, mirror, scale, t):
    import numpy as np
    p = pts.copy()
    if mirror:
        p[:, 1] = -p[:, 1]
    c, s = math.cos(theta), math.sin(theta)
    out = np.empty_like(p)
    out[:, 0] = scale * (c * p[:, 0] - s * p[:, 1]) + t[0]
    out[:, 1] = scale * (s * p[:, 0] + c * p[:, 1]) + t[1]
    return out


def match_vector(tpl: dict, index: PageIndex, exclude=()) -> list[dict]:
    """Every place the template's line work appears on the sheet: [{centre, score, rotation, mirrored, bbox}]."""
    import numpy as np
    if index.tree is None:
        return []
    diag = tpl["diag"]
    tol = max(0.006, 0.04 * diag)
    a = tpl["anchor"]
    la, ang_a = _seg_len(a), _angle(a)
    mid_a = ((a[0][0] + a[1][0]) / 2, (a[0][1] + a[1][1]) / 2)
    cand = np.nonzero(np.abs(index.lens - la) <= SCALE_TOL * la + 0.004)[0][:MAX_CANDIDATES]
    hits = []
    long_limit = LONG * diag * (1 + SCALE_TOL)
    for ci in cand:
        seg = index.segs[ci]
        lc = index.lens[ci]
        scale = lc / la
        mid_c = ((seg[0][0] + seg[1][0]) / 2, (seg[0][1] + seg[1][1]) / 2)
        best = None
        for mirror in (False, True):
            a0 = -ang_a if mirror else ang_a
            for flip in (0.0, math.pi):
                theta = _angle(seg) + flip - a0
                c, s = math.cos(theta), math.sin(theta)
                mx, my = mid_a[0], (-mid_a[1] if mirror else mid_a[1])
                t = (mid_c[0] - scale * (c * mx - s * my), mid_c[1] - scale * (s * mx + c * my))
                tp = _transform(tpl["pts"], theta, mirror, scale, t)
                d, _ = index.tree.query(tp, distance_upper_bound=tol * 1.01)
                fwd = float(np.mean(d <= tol))
                if fwd < MIN_FORWARD:
                    continue
                centre = (t[0], t[1])
                r = 0.55 * diag * scale + tol
                near = index.tree.query_ball_point(centre, r)
                if near:
                    near = np.array(near)
                    near = near[index.lens[index.owner[near]] <= long_limit]
                if len(near):
                    pp = index.pts[near]
                    dd = np.sqrt(((pp[:, None, :] - tp[None, :, :]) ** 2).sum(axis=2)).min(axis=1)
                    rev = float(np.mean(dd <= tol * 1.5))
                else:
                    rev = 0.0
                score = fwd * math.sqrt(rev)
                if best is None or score > best["score"]:
                    xs, ys = tp[:, 0], tp[:, 1]
                    centre = (float(xs.mean()), float(ys.mean()))     # the same spot whichever way it's turned
                    best = {"centre": centre, "score": score, "fwd": fwd, "rev": rev,
                            "rotation": round(math.degrees(theta) % 360, 1), "mirrored": mirror,
                            "bbox": [float(xs.min()), float(ys.min()), float(xs.max()), float(ys.max())]}
        if best and best["score"] >= MIN_SCORE and not any(_inside(best["centre"], b) for b in exclude):
            hits.append(best)
    return _nms(hits, 0.5 * diag)


def _nms(hits, radius):
    hits = sorted(hits, key=lambda h: -h["score"])
    kept = []
    for h in hits:
        if all(math.hypot(h["centre"][0] - k["centre"][0], h["centre"][1] - k["centre"][1]) > radius for k in kept):
            kept.append(h)
    return kept


# ---------------------------------------------------------------- raster matching

def _ink(img, w_in, h_in, px=RASTER_PX):
    import numpy as np
    from scipy.ndimage import gaussian_filter
    g = img.convert("L").resize((max(1, int(w_in * px)), max(1, int(h_in * px))), resample=3)   # 3 = bicubic
    # A slight blur so a stroke a pixel off (scan jitter, a turned copy) still lines up.
    return gaussian_filter(1.0 - np.asarray(g, dtype="float32") / 255.0, 0.8)


def raster_template(sheet: dict, box) -> dict | None:
    """The legend symbol cut from a scanned sheet's image, as ink (1) on paper (0) at RASTER_PX."""
    from PIL import Image
    if not sheet.get("image_path"):
        return None
    try:
        with Image.open(sheet["image_path"]) as src:
            k = src.size[0] / float(sheet["width"])
            crop = src.crop(tuple(int(round(v * k)) for v in box)).copy()
    except Exception:  # noqa: BLE001 - no picture, no raster template
        return None
    w, h = box[2] - box[0], box[3] - box[1]
    ink = _ink(crop, w, h)
    if ink.size < 16 or ink.sum() < 4 or math.hypot(w, h) > MAX_DIAG:
        return None
    return {"ink": ink, "diag": math.hypot(w, h), "w": w, "h": h}


def match_raster(tpl: dict, sheet: dict, exclude=(), sheet_ink=None) -> list[dict]:
    import numpy as np
    from scipy.ndimage import maximum_filter
    from scipy.signal import fftconvolve
    from PIL import Image
    if sheet_ink is None:
        with Image.open(sheet["image_path"]) as src:
            sheet_ink = _ink(src, float(sheet["width"]), float(sheet["height"]))
    img = sheet_ink
    hits = []
    seen = []
    for mirror in (False, True):
        for k in range(4):
            t = np.rot90(np.fliplr(tpl["ink"]) if mirror else tpl["ink"], k)
            if any(t.shape == s.shape and np.allclose(t, s) for s in seen):
                continue                                   # a symmetric symbol: this turn was already tried
            seen.append(t)
            th, tw = t.shape
            if th > img.shape[0] or tw > img.shape[1]:
                continue
            n = th * tw
            t0 = t - t.mean()
            tnorm = math.sqrt(float((t0 ** 2).sum()))
            if tnorm < 1e-6:
                continue
            num = fftconvolve(img, t0[::-1, ::-1], mode="valid")
            ones = np.ones((th, tw), dtype="float32")
            s1 = fftconvolve(img, ones, mode="valid")
            s2 = fftconvolve(img * img, ones, mode="valid")
            var = np.maximum(s2 - s1 * s1 / n, 1e-6)
            ncc = num / (np.sqrt(var) * tnorm)
            ink = float(t.sum())
            # About as much ink as the symbol, not a wall or a box that happens to share one of its strokes.
            similar = (s1 >= 0.6 * ink) & (s1 <= 1.6 * ink)
            peaks = (ncc >= RASTER_MIN) & similar & (ncc == maximum_filter(ncc, size=max(3, min(th, tw) // 2)))
            for y, x in zip(*np.nonzero(peaks)):
                cx, cy = (x + tw / 2) / RASTER_PX, (y + th / 2) / RASTER_PX
                if any(_inside((cx, cy), b) for b in exclude):
                    continue
                hits.append({"centre": (cx, cy), "score": float(min(1.0, ncc[y, x])), "rotation": 90.0 * k,
                             "mirrored": mirror, "bbox": [x / RASTER_PX, y / RASTER_PX, (x + tw) / RASTER_PX,
                                                          (y + th) / RASTER_PX]})
    return _nms(hits, 0.5 * tpl["diag"])


# ---------------------------------------------------------------- one sheet: scan, then fuse with the words

def _words_near(page, centre, radius, skip):
    from estimator.plan_engine import symbol_library as lib
    out = []
    for w in page.words:
        p = ((w.x0 + w.x1) / 2, (w.top + w.bottom) / 2)
        if math.hypot(p[0] - centre[0], p[1] - centre[1]) <= radius and not any(_inside(p, b) for b in skip):
            out.append(lib.norm_code(w.text))
    return out


def scan_sheet(page, sheet: dict, entries: list[dict], templates: dict, skip=(), source="vector") -> list[dict]:
    """Detections on one sheet. entries: the plan set's dictionary; templates: {entry key: template}.
    Returns symbol objects for the drawing model, each with a "symbol" record."""
    from estimator.plan_engine import symbol_library as lib
    import numpy as np  # noqa: F401 - fail early if numpy is missing

    by_key = {e["key"]: e for e in entries}
    raw = []                                               # (entry key, hit)
    if source == "vector" and templates:
        vec = {k: t for k, t in templates.items() if t.get("kind") == "vector"}
        if vec and page.segments:
            index = PageIndex(page.segments, min(2.25, LONG * max(t["diag"] for t in vec.values()) * 1.2))
            for k, t in vec.items():
                raw += [(k, h) for h in match_vector(t, index, skip)]
    elif source == "raster" and templates and sheet.get("image_path"):
        ras = {k: t for k, t in templates.items() if t.get("kind") == "raster"}
        if ras:
            from PIL import Image
            try:
                with Image.open(sheet["image_path"]) as src:
                    ink = _ink(src, float(sheet["width"]), float(sheet["height"]))
            except Exception:  # noqa: BLE001
                ink = None
            if ink is not None:
                for k, t in ras.items():
                    raw += [(k, h) for h in match_raster(t, sheet, skip, ink)]

    # Group hits that are the same symbol (look-alike entries match the same spot).
    groups = []
    for k, h in sorted(raw, key=lambda kh: -kh[1]["score"]):
        r = 0.5 * templates[k]["diag"]
        g = next((g for g in groups if math.hypot(g["centre"][0] - h["centre"][0],
                                                  g["centre"][1] - h["centre"][1]) <= r), None)
        if g is None:
            groups.append({"centre": h["centre"], "hits": [(k, h)], "diag": templates[k]["diag"]})
        else:
            g["hits"].append((k, h))

    out = []
    for g in groups:
        # Resolution order: the plan set's own legend, then the company library (Sprint 11), then the standard library.
        legend_hits = [kh for kh in g["hits"] if not by_key[kh[0]].get("library")]
        if legend_hits:
            g["hits"] = legend_hits
        words = _words_near(page, g["centre"], 0.6 * g["diag"] + 0.2, skip)
        best_score = max(h["score"] for _, h in g["hits"])
        coded = [(k, h) for k, h in g["hits"] if by_key[k].get("code") and lib.norm_code(by_key[k]["code"]) in words]
        if coded:
            k, h = max(coded, key=lambda kh: kh[1]["score"])
            ocr = 0.95
        else:
            plain = [(k, h) for k, h in g["hits"] if not by_key[k].get("code") and h["score"] >= best_score - 0.05]
            k, h = max(plain or g["hits"], key=lambda kh: kh[1]["score"])
            ocr = None if not by_key[k].get("code") else 0.3      # its code should be beside it and isn't
        e = by_key[k]
        item_type, trade, standard = e.get("item_type"), e.get("trade"), None
        if item_type and ocr is None:                     # a plain symbol with a code beside it: GFI -> GFCI
            for wcode in words:
                std = lib.by_alias(wcode)
                if std and std["item_type"].startswith(item_type + "_"):
                    item_type, trade, standard, ocr = std["item_type"], std["trade"], std["item_type"], 0.8
                    break
        vision = round(h["score"], 3)
        conf = vision if ocr is None else 0.7 * vision + 0.3 * ocr
        if e.get("needs_confirming"):
            conf *= 0.85
        if source == "raster":
            conf *= 0.9
        out.append(_object(sheet, g["centre"], e, item_type, trade, standard, source,
                           {"legend": e.get("confidence"), "vision": vision, "ocr": ocr, "ai": None, "cad": None},
                           conf, h, "vector" if source == "vector" else "raster"))

    # Legend entries that are only a code: count the code where it stands alone on the plans.
    found = [o["geometry"]["points"][0] for o in out]
    for e in entries:
        if e.get("abbreviations") or e.get("has_symbol") or not e.get("code") or not e.get("item_type"):
            continue
        code = lib.norm_code(e["code"])
        for ln in page.lines:
            ws = ln.words
            if len(ws) > 2 or not any(lib.norm_code(w.text) == code for w in ws):
                continue
            w = next(w for w in ws if lib.norm_code(w.text) == code)
            p = ((w.x0 + w.x1) / 2, (w.top + w.bottom) / 2)
            if any(_inside(p, b) for b in skip) or any(math.hypot(p[0] - q[0], p[1] - q[1]) < 0.4 for q in found):
                continue
            found.append(p)
            out.append(_object(sheet, p, e, e["item_type"], e.get("trade"), None, source,
                               {"legend": e.get("confidence"), "vision": None, "ocr": 0.8, "ai": None, "cad": None},
                               0.6, {"rotation": 0.0, "mirrored": False,
                                     "bbox": [w.x0, w.top, w.x1, w.bottom]}, "ocr"))

    return out[:MAX_DETECTIONS]


def cad_symbols(sheet: dict) -> int:
    """CAD blocks: the block name says what it is. Adds a "symbol" record to each block object; returns how many."""
    from estimator.plan_engine import symbol_library as lib
    n = 0
    for o in sheet.get("objects") or []:
        if o.get("kind") != "symbol" or not o.get("block_name") or o.get("symbol"):
            continue
        std = lib.by_block_name(o["block_name"])
        if std is None:                 # doors, furniture, north arrows...: stay plain CAD blocks (Sprint 11 learns them)
            continue
        o["symbol"] = {"entry": None, "standard": std["item_type"], "item_type": std["item_type"], "trade": std["trade"],
                       "scores": {"legend": None, "vision": None, "ocr": None, "ai": None, "cad": 0.95},
                       "confidence": 0.95, "rotation": None, "mirrored": False, "bbox": None,
                       "method": "cad", "needs_review": False}
        n += 1
    return n


def _object(sheet, centre, entry, item_type, trade, standard, source, scores, conf, hit, method):
    from estimator.plan_engine import dimensions
    vp = dimensions._viewport_at(sheet.get("viewports") or [], centre)
    conf = round(max(0.0, min(conf, 0.99)), 3)
    o = {"kind": "symbol", "label": entry.get("description") if not standard else standard.replace("_", " "),
         "source": source, "confidence": conf,
         "geometry": {"type": "point", "points": [[round(float(centre[0]), 4), round(float(centre[1]), 4)]]},
         "symbol": {"entry": entry["key"], "standard": standard, "item_type": item_type, "trade": trade,
                    "scores": scores, "confidence": conf, "rotation": hit.get("rotation"),
                    "mirrored": bool(hit.get("mirrored")),
                    "bbox": [round(float(v), 4) for v in hit["bbox"]] if hit.get("bbox") else None,
                    "method": method,
                    "needs_review": conf < 0.8 or source == "raster" or not item_type or bool(entry.get("needs_confirming"))}}
    if vp is not None:
        o["viewport"] = vp["key"]
    return o


# ---------------------------------------------------------------- the plan set

def dictionary(legends_by_page: dict) -> list[dict]:
    """The plan-set symbol dictionary from the legends found: one entry per legend row, with a key the detections use."""
    out = []
    for page_no in sorted(legends_by_page):
        for li, lg in enumerate(legends_by_page[page_no]):
            for ei, e in enumerate(lg["entries"]):
                out.append({"key": f"p{page_no}-l{li}-e{ei}", "page_no": page_no, "legend_index": li, "entry_index": ei,
                            "legend": lg["title"], "abbreviations": bool(lg.get("abbreviations")),
                            **{k: e.get(k) for k in ("code", "description", "item_type", "trade", "confidence",
                                                      "needs_confirming", "has_symbol", "symbol_bbox", "template")}})
    return out


def templates_for(entries: list[dict], pages: dict, sheets: dict) -> dict:
    """{entry key: template} for every entry with a drawn symbol: vector line work, or a raster picture for scans."""
    out = {}
    for e in entries:
        if not e.get("has_symbol") or not e.get("symbol_bbox") or e.get("abbreviations"):
            continue
        page, sheet = pages.get(e["page_no"]), sheets.get(e["page_no"])
        box = e["symbol_bbox"]
        if page is not None and page.segments:
            t = template_from(page.segments, box)
            if t:
                out[e["key"]] = {**t, "kind": "vector"}
                continue
        if sheet is not None:
            t = raster_template(sheet, box)
            if t:
                out[e["key"]] = {**t, "kind": "raster"}
    return out


def library_entries(library: list | None) -> tuple[list[dict], dict]:
    """The company library's learned symbols (Sprint 11), passed in by the drawing model as info["symbol_library"]:
    [{"key": "lib:<definition id>", "item_type", "trade", "description", "code", "template": {...vector json}}].
    Returns (dictionary entries, {key: template})."""
    entries, templates = [], {}
    for d in (library or [])[:500]:
        if not isinstance(d, dict) or not str(d.get("key", "")).startswith("lib:"):
            continue
        t = template_from_json(d.get("template") or {})
        if t is None:
            continue
        templates[d["key"]] = t
        entries.append({"key": d["key"], "library": True, "page_no": None, "legend": "company library",
                        "abbreviations": False, "code": d.get("code"), "description": d.get("description"),
                        "item_type": d.get("item_type"), "trade": d.get("trade"), "confidence": 0.85,
                        "needs_confirming": False, "has_symbol": True})
    return entries, templates


def find_similar(file_path, file_type: str, sheets: list[dict], source_page: int, box, skip_by_page=None) -> dict:
    """Find similar (spec: "searches all sheets for more of the same shape"): the line work (or picture) inside box on
    source_page is the template; returns {"template": json or None, "kind", "hits": {page_no: [hit, ...]}}.
    sheets: [{"page_no", "width", "height", "image_path"}]."""
    from estimator.plan_engine import pdf_pages
    skip_by_page = skip_by_page or {}
    by_page = {s["page_no"]: s for s in sheets}
    out = {"template": None, "kind": None, "hits": {}}
    tpl = None
    if (file_type or "").lower() == "pdf":
        seg_cache = {}

        def segs_of(p):
            if p not in seg_cache:
                seg_cache[p] = pdf_pages.page_segments(file_path, p)
            return seg_cache[p]
        tpl = template_from(segs_of(source_page), box)
        if tpl is not None:
            out.update(template=template_to_json(tpl), kind="vector")
            for p in sorted(by_page):
                index = PageIndex(segs_of(p), min(2.25, LONG * tpl["diag"] * 1.2))
                out["hits"][p] = match_vector(tpl, index, skip_by_page.get(p, ()))
            return out
    src = by_page.get(source_page)
    rt = raster_template(src, box) if src else None
    if rt is not None:
        out["kind"] = "raster"
        for p, s in sorted(by_page.items()):
            if s.get("image_path"):
                try:
                    out["hits"][p] = match_raster(rt, s, skip_by_page.get(p, ()))
                except Exception:  # noqa: BLE001 - a sheet without a picture is skipped
                    out["hits"][p] = []
    return out


def counts(sheets: list[dict]) -> dict:
    """{item type: count} over the plan set (unknown CAD blocks counted by block name)."""
    out: dict[str, int] = {}
    for s in sheets:
        for o in s["objects"]:
            rec = o.get("symbol")
            if rec:
                k = rec.get("item_type") or ("block " + (o.get("block_name") or "?"))
                out[k] = out.get(k, 0) + 1
    return out

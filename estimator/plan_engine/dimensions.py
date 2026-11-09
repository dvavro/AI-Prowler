"""Dimension strings, and checking each view's scale with them (spec: "Dimension strings are cross-checked against
measured geometry to verify scale").

A dimension string (12'-6", 3'-0 1/2", 24'-0") usually sits just above its dimension line. When the line is found,
the real length / the paper length is the scale it implies. Each view's dimensions vote for the nearest standard
scale (1/4" = 1'-0", 1" = 20', 1:100 ...):
  - a view with no scale gets the winner (scale_method "dimension") when at least two dimensions agree on it and
    they're at least half of the ones matched;
  - a view whose scale note disagrees with them gets a note to check it (never changed: the note is what was drawn);
  - agreeing dimensions raise the view's scale confidence.
Every dimension string becomes a "dimension" object (its line when found, else a point at the text).
"""
from __future__ import annotations

import re
from decimal import Decimal

# Real inches per paper inch for the scales plans are drawn at.
ARCH = {"1/32\" = 1'-0\"": 384, "1/16\" = 1'-0\"": 192, "3/32\" = 1'-0\"": 128, "1/8\" = 1'-0\"": 96,
        "3/16\" = 1'-0\"": 64, "1/4\" = 1'-0\"": 48, "3/8\" = 1'-0\"": 32, "1/2\" = 1'-0\"": 24, "3/4\" = 1'-0\"": 16,
        "1\" = 1'-0\"": 12, "1 1/2\" = 1'-0\"": 8, "3\" = 1'-0\"": 4}
ENG = {f"1\" = {n}'": n * 12 for n in (10, 20, 30, 40, 50, 60, 100, 200)}
METRIC = {f"1:{n}": n for n in (20, 25, 50, 75, 100, 200, 250, 500)}
STANDARD = {**ARCH, **ENG, **{k: v for k, v in METRIC.items() if v not in ARCH.values() and v not in ENG.values()}}
AGREE = 0.04                     # within 4% of a standard scale counts as a vote for it
MIN_VOTES = 2
MAX_DIMENSIONS = 1500

_DIM = re.compile(r"""^(?:\d{1,4}'\s*-?\s*\d{1,2}(?:\s+\d{1,2}/\d{1,2})?"?        # 12'-6"  3'-0 1/2"
                     |\d{1,4}'(?:\s*-\s*0"?)?                                    # 24'  24'-0
                     |\d{1,3}(?:\s+\d{1,2}/\d{1,2})?")$""", re.X)


_QUOTES = str.maketrans({"’": "'", "‘": "'", "′": "'", "”": '"', "“": '"', "″": '"'})


def _plain(text: str) -> str:
    """Typographic feet and inch marks as plain ' and " (PDF fonts often draw ' as a right quote)."""
    return (text or "").translate(_QUOTES)


def is_dimension(text: str) -> bool:
    t = _plain(text).strip()
    return bool(_DIM.match(t)) and ("'" in t or '"' in t)


def value_inches(text: str) -> Decimal | None:
    from estimator.drawing_model.geometry import parse_length
    from estimator.errors import InvalidInput
    try:
        ft = parse_length(text.strip())                  # 12'-6", 24'-0, 3'-0 1/2", 8" (the drawing model's reader)
    except (InvalidInput, Exception):  # noqa: BLE001
        return None
    v = ft * 12
    return v if v > 0 else None


def candidates(page) -> list[dict]:
    """Dimension strings on a page: a word, or a word plus the fraction after it (3'-0 1/2")."""
    # The 1'-0" in "SCALE: 1/4" = 1'-0"" is part of a scale note, not a dimension.
    in_notes = {id(w) for ln in page.lines if re.search(r"=|\bSCALE\b", ln.text, re.I) for w in ln.words}
    words = sorted((w for w in page.words if id(w) not in in_notes), key=lambda w: ((w.top + w.bottom) / 2, w.x0))
    out, used = [], set()
    for i, w in enumerate(words):
        if i in used:
            continue
        text, box = _plain(w.text), [w.x0, w.top, w.x1, w.bottom]
        nxt = words[i + 1] if i + 1 < len(words) else None
        if nxt and re.fullmatch(r"\d{1,2}/\d{1,2}\"?", nxt.text) and abs(nxt.top - w.top) < 0.05 and 0 <= nxt.x0 - w.x1 < 0.15:
            joined = text + " " + _plain(nxt.text)
            if is_dimension(joined):
                text, box = joined, [w.x0, min(w.top, nxt.top), nxt.x1, max(w.bottom, nxt.bottom)]
                used.add(i + 1)
        if not is_dimension(text):
            continue
        v = value_inches(text)
        if v is None:
            continue
        out.append({"text": text, "bbox": box, "inches": v})
        if len(out) >= MAX_DIMENSIONS:
            break
    return out


def _line_for(d: dict, segments, horizontal_text: bool = True):
    """The dimension line the text labels: parallel to the text, just above or below it, spanning its middle."""
    x0, top, x1, bottom = d["bbox"]
    cx, h = (x0 + x1) / 2, max(bottom - top, 0.04)
    best, best_d = None, None
    for (a, b) in segments:
        dx, dy = b[0] - a[0], b[1] - a[1]
        length = (dx * dx + dy * dy) ** 0.5
        if length < max(x1 - x0, 0.2) or abs(dy) > 0.01 * length:
            continue                                     # horizontal lines at least as long as the text
        lo, hi = min(a[0], b[0]), max(a[0], b[0])
        if not lo <= cx <= hi:
            continue
        y = (a[1] + b[1]) / 2
        gap = top - y if y <= top else y - bottom if y >= bottom else 0.0
        if gap > max(2.5 * h, 0.2):
            continue
        key = (round(gap, 3), length)                   # nearest, then the shortest (not a long wall line)
        if best_d is None or key < best_d:
            best, best_d = ((lo, y), (hi, y)), key
    return best


def nearest_standard(ratio: float) -> tuple[str, int] | None:
    name, value = min(STANDARD.items(), key=lambda kv: abs(kv[1] - ratio) / kv[1])
    return (name, value) if abs(value - ratio) / value <= AGREE else None


def check(page, viewports: list[dict], zone=None) -> tuple[list[dict], list[str]]:
    """Dimension objects for the page, with each viewport's scale checked (viewports are updated in place).
    Returns (objects, notes)."""
    objs, notes, votes = [], [], {}
    dims = candidates(page)
    for d in dims:
        x0, top, x1, bottom = d["bbox"]
        if zone is not None and _in_box(((x0 + x1) / 2, (top + bottom) / 2), zone):
            continue                                     # the title block's own numbers
        vp = _viewport_at(viewports, ((x0 + x1) / 2, (top + bottom) / 2))
        line = _line_for(d, page.segments) if page.segments else None
        o = {"kind": "dimension", "label": d["text"], "source": "vector" if page.segments else "raster",
             "confidence": 0.75 if line else 0.5,
             "geometry": {"type": "line", "points": [list(line[0]), list(line[1])]} if line else
             {"type": "point", "points": [[round((x0 + x1) / 2, 4), round((top + bottom) / 2, 4)]]}}
        if vp is not None:
            o["viewport"] = vp["key"]
        objs.append(o)
        if line and vp is not None:
            paper = line[1][0] - line[0][0]
            if paper > 0.05:
                votes.setdefault(vp["key"], []).append(float(d["inches"]) / paper)
    for vp in viewports:
        ratios = votes.get(vp["key"], [])
        if not ratios:
            continue
        tally: dict[str, list[float]] = {}
        for r in ratios:
            hit = nearest_standard(r)
            if hit:
                tally.setdefault(hit[0], []).append(r)
        if not tally:
            continue
        name, hits = max(tally.items(), key=lambda kv: len(kv[1]))
        if len(hits) < MIN_VOTES or len(hits) < len(ratios) / 2:
            continue
        value = STANDARD[name]
        label = vp.get("label") or "a view"
        current = _current_ratio(vp)
        if vp.get("is_nts"):
            continue
        if current is None:
            vp["scale_ratio"] = value
            vp["scale_method"] = "dimension"
            vp["scale_confidence"] = round(min(0.85, 0.55 + 0.1 * len(hits)), 2)
            notes.append(f"{label}: no scale written; {len(hits)} dimensions agree on {name}")
        elif abs(current - value) / value > AGREE:
            notes.append(f"{label}: the scale says 1:{_fmt(current)} but {len(hits)} dimensions measure as {name} - check it")
        else:
            conf = float(vp.get("scale_confidence") or 0.7)
            vp["scale_confidence"] = round(min(0.98, conf + 0.05 * min(len(hits), 4)), 2)
    return objs, notes


def _fmt(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else f"{v:.2f}"


def _current_ratio(vp: dict) -> float | None:
    if vp.get("scale_ratio") not in (None, ""):
        return float(vp["scale_ratio"])
    note = vp.get("scale_note")
    if note:
        from estimator.drawing_model.geometry import parse_scale
        try:
            ratio, nts = parse_scale(note)
        except Exception:  # noqa: BLE001
            return None
        return None if nts or ratio is None else float(ratio)
    return None


def _in_box(p, box) -> bool:
    return box[0] <= p[0] <= box[2] and box[1] <= p[1] <= box[3]


def _viewport_at(viewports, p):
    hits = [v for v in viewports if v.get("bbox") and _in_box(p, v["bbox"])]
    if hits:
        return min(hits, key=lambda v: (v["bbox"][2] - v["bbox"][0]) * (v["bbox"][3] - v["bbox"][1]))
    return viewports[0] if len(viewports) == 1 else None

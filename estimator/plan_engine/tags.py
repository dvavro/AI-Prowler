"""Tags on the plans that match a schedule's marks (door D3, window W2, fixture A, room 101), so the drawing model can
link each schedule row to where it's used (store._link_rows matches an object's tag to a row's mark).

A word is a tag when, once spaces are dropped and letters are made capitals, it equals a mark from any schedule in the
plan set - except inside a schedule or legend, in the title block, or as part of a dimension. Marks need a letter or
at least three characters (101), so a schedule numbered 1, 2, 3 doesn't turn every stray "1" into a tag. A word in
the same series as two or more marks (D3 when the schedule has D1, D2, D4) is a tag too, at lower confidence: the
schedule may have missed it, and a person who corrects a row to D3 then finds it linked.
"""
from __future__ import annotations

import json
import re

from estimator.plan_engine import dimensions


def norm(text: str | None) -> str:
    return "".join((text or "").split()).upper()


def usable(mark: str) -> bool:
    m = norm(mark)
    return bool(m) and len(m) <= 12 and (bool(re.search(r"[A-Z]", m)) or len(m) >= 3)


def marks_of(schedules_by_page: dict) -> dict[str, str]:
    """{normalised mark: schedule type} for every row in the plan set."""
    out = {}
    for scheds in schedules_by_page.values():
        for sc in scheds:
            for r in sc["rows"]:
                if r.get("mark") and usable(r["mark"]):
                    out.setdefault(norm(r["mark"]), sc["schedule_type"])
    return out


def _in(p, box) -> bool:
    return box[0] <= p[0] <= box[2] and box[1] <= p[1] <= box[3]


_SERIES = re.compile(r"^([A-Z]{1,3})-?(\d{1,3}[A-Z]?)$")


def series_of(marks: dict[str, str]) -> dict[str, str]:
    """{prefix: schedule type} for mark series with at least two members (D1, D2, D4 -> "D"), so a tag such as D3 that
    the schedule missed (or that a person adds later) is still found on the plans."""
    count: dict[str, list[str]] = {}
    for m, kind in marks.items():
        hit = _SERIES.match(m)
        if hit:
            count.setdefault(hit.group(1), []).append(kind)
    return {p: kinds[0] for p, kinds in count.items() if len(kinds) >= 2}


def find(page, marks: dict[str, str], viewports: list[dict], skip=(), zone=None, source="vector") -> list[dict]:
    out = []
    if not marks:
        return out
    series = series_of(marks)
    for w in page.words:
        key = norm(w.text).strip(".,;:()")
        if dimensions.is_dimension(w.text):
            continue
        kind, conf = marks.get(key), 0.7
        if kind is None:
            hit = _SERIES.match(key)
            kind, conf = (series.get(hit.group(1)), 0.55) if hit else (None, 0)
        if kind is None:
            continue
        p = ((w.x0 + w.x1) / 2, (w.top + w.bottom) / 2)
        if (zone is not None and _in(p, zone)) or any(_in(p, b) for b in skip):
            continue
        vp = dimensions._viewport_at(viewports, p)
        o = {"kind": "text", "label": f"{kind} tag", "tag": w.text.strip(".,;:()"), "source": source,
             "confidence": conf, "geometry": {"type": "point", "points": [[round(p[0], 4), round(p[1], 4)]]}}
        if vp is not None:
            o["viewport"] = vp["key"]
        out.append(o)
    return out


def write_dictionary(work, engine_name: str, legends_by_page: dict, sheets: dict) -> str | None:
    """symbol_dictionary.json beside the sheet images: every legend found and its entries."""
    from pathlib import Path
    if work is None:
        return None
    data = {"engine": engine_name, "legends": []}
    for page_no in sorted(legends_by_page):
        s = sheets.get(page_no) or {}
        for lg in legends_by_page[page_no]:
            data["legends"].append({"page_no": page_no, "sheet_no": s.get("sheet_no"), **lg})
    path = Path(work) / "symbol_dictionary.json"
    path.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    return str(path)

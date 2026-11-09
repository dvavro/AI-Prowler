"""Schedule tables on sheets: door, window, room finish, plumbing fixture, light fixture, panel, equipment and wall-type
schedules (spec "Legend and schedule extraction"), turned into rows of {column: value} with the row's mark.

How a table is read (vector text, or OCR words on scans):
1. The title: a short line such as "DOOR SCHEDULE" or "LIGHT FIXTURE SCHEDULE" (the type comes from its words).
2. The header: the first row of words below the title. Its words are grouped into column headings - by the table's
   vertical rules when the PDF has them, otherwise by the gaps between words; a second header row (e.g. "FRAME" over
   "TYPE") is merged into the column above it.
3. The rows: each row of words below, cut into the columns. A row with nothing in the first (mark) column is the rest
   of the row above (a wrapped remark). The table ends at a big gap, another title, or text outside its columns.
The drawing model then links each row's mark to the plan's tags (store._link_rows), so door tag D3 knows its row.
"""
from __future__ import annotations

import re

TITLE = re.compile(r"\b(?:(DOOR|WINDOW|ROOM\s+FINISH|FINISH|PLUMBING(?:\s+FIXTURE)?|LIGHT(?:ING)?(?:\s+FIXTURE)?|"
                   r"LUMINAIRE|FIXTURE|PANEL(?:BOARD)?|(?:MECHANICAL\s+|HVAC\s+)?EQUIPMENT|WALL\s+TYPE|PARTITION)S?\s+)?"
                   r"SCHEDULES?\b", re.I)
TYPE_OF = (("door", r"DOOR"), ("window", r"WINDOW"), ("finish", r"FINISH"), ("plumbing", r"PLUMBING"),
           ("lighting", r"LIGHT|LUMINAIRE"), ("panel", r"PANEL"), ("equipment", r"EQUIPMENT|HVAC"),
           ("wall-type", r"WALL\s+TYPE|PARTITION"), ("plumbing", r"FIXTURE"))
MARK_HEAD = re.compile(r"^(MARK|NO\.?|NUMBER|TAG|TYPE|SYM(BOL)?|ID|DOOR|WINDOW|ROOM|FIXTURE|PANEL|ITEM|KEY)$", re.I)
ROW_TOL = 0.06               # words whose middles are this close (inches) are one row
CELL_GAP = 0.18              # a bigger gap between header words starts a new column
MAX_ROWS = 300
MAX_TABLE_H = 30.0


def _rows(words, tol=ROW_TOL):
    rows = []
    for w in sorted(words, key=lambda w: ((w.top + w.bottom) / 2, w.x0)):
        mid = (w.top + w.bottom) / 2
        if rows and abs(mid - rows[-1]["mid"]) <= max(tol, (w.bottom - w.top) * 0.45):
            rows[-1]["words"].append(w)
            n = len(rows[-1]["words"])
            rows[-1]["mid"] = rows[-1]["mid"] + (mid - rows[-1]["mid"]) / n
        else:
            rows.append({"mid": mid, "words": [w]})
    for r in rows:
        r["words"].sort(key=lambda w: w.x0)
        r["top"] = min(w.top for w in r["words"])
        r["bottom"] = max(w.bottom for w in r["words"])
    return rows


def _type(title: str) -> str:
    for t, rx in TYPE_OF:
        if re.search(rx, title, re.I):
            return t
    return "other"


def _titles(page, zone):
    out = []
    for ln in page.lines:
        text = ln.text.strip()
        words = text.split()
        if not (1 <= len(words) <= 6) or not TITLE.search(text) or not re.search(r"SCHEDULES?\s*$", text, re.I):
            continue                                      # "DOOR SCHEDULE", not a note like "SEE SCHEDULE ON A-601"
        if text.upper() != text:                          # schedule titles are written in capitals
            continue
        if zone is not None and _inside((ln.cx, (ln.top + ln.bottom) / 2), zone):
            continue
        out.append(ln)
    return out


def _inside(p, box) -> bool:
    return box[0] <= p[0] <= box[2] and box[1] <= p[1] <= box[3]


def _vertical_rules(page, x0, x1, top, bottom):
    xs = []
    for (a, b) in page.segments or []:
        if abs(a[0] - b[0]) > 0.01:
            continue
        lo, hi = min(a[1], b[1]), max(a[1], b[1])
        if x0 - 0.05 <= a[0] <= x1 + 0.05 and lo <= top + 0.02 and hi >= bottom - 0.02:
            xs.append(round(a[0], 3))
    xs = sorted(set(xs))
    merged = []
    for x in xs:
        if not merged or x - merged[-1] > 0.05:
            merged.append(x)
    return merged


def _columns(header_rows, page, top, bottom_guess):
    """Column headings with their x spans: [{"name", "x0", "x1"}]."""
    words = header_rows[0]["words"]
    x0, x1 = min(w.x0 for w in words), max(w.x1 for w in words)
    rules = _vertical_rules(page, x0 - 0.6, x1 + 0.6, top, bottom_guess)
    cells = []
    if len(rules) >= 3:
        for a, b in zip(rules, rules[1:]):
            ws = [w for w in words if a <= (w.x0 + w.x1) / 2 <= b]
            if ws:
                cells.append({"words": ws, "x0": a, "x1": b})
        ruled = True
    else:
        for w in words:
            if cells and w.x0 - cells[-1]["words"][-1].x1 <= CELL_GAP:
                cells[-1]["words"].append(w)
            else:
                cells.append({"words": [w]})
        for c in cells:
            c["x0"], c["x1"] = c["words"][0].x0, c["words"][-1].x1
        for a, b in zip(cells, cells[1:]):                # boundaries halfway between headings
            mid = (a["x1"] + b["x0"]) / 2
            a["x1"], b["x0"] = mid, mid
        cells[0]["x0"] -= 0.4
        cells[-1]["x1"] += 2.0
        ruled = False
    for extra in header_rows[1:]:                         # FRAME over TYPE -> "FRAME TYPE"
        for w in extra["words"]:
            c = next((c for c in cells if c["x0"] <= (w.x0 + w.x1) / 2 <= c["x1"]), None)
            if c:
                c["words"].append(w)
    cols = []
    for c in cells:
        name = " ".join(w.text for w in sorted(c["words"], key=lambda w: (round(w.top, 1), w.x0))).strip()
        cols.append({"name": name, "x0": c["x0"], "x1": c["x1"]})
    seen = {}
    for c in cols:                                        # two columns with one name stay apart
        n = c["name"] or "column"
        seen[n] = seen.get(n, 0) + 1
        c["name"] = n if seen[n] == 1 else f"{n} {seen[n]}"
    return cols, ruled


def _is_header_like(row) -> bool:
    return all(w.text.upper() == w.text and not re.search(r"\d", w.text) for w in row["words"])


def find(page, zone=None, others=None) -> list[dict]:
    """Schedules on a page, in the drawing model's format, with "bbox" for each (the area the table covers)."""
    words = page.words
    found = []
    titles = _titles(page, zone)
    for t in titles:
        below = [w for w in words if w.top >= t.bottom - 0.02 and w.top <= t.bottom + MAX_TABLE_H
                 and w.x1 >= t.x0 - 1.0
                 and (zone is None or not _inside(((w.x0 + w.x1) / 2, (w.top + w.bottom) / 2), zone))]
        rows = _rows(below)
        if not rows:
            continue
        first = next((i for i, r in enumerate(rows[:3]) if len(r["words"]) >= 2), None)
        if first is None or rows[first]["top"] - t.bottom > 1.2:
            continue
        header = [rows[first]]
        nxt = rows[first + 1] if first + 1 < len(rows) else None
        if nxt and nxt["top"] - header[0]["bottom"] < 0.25 and _is_header_like(nxt) and len(rows) > first + 2:
            header.append(nxt)
        cols, ruled = _columns(header, page, header[0]["top"], header[-1]["bottom"] + 1.0)
        if len(cols) < 2:
            continue
        tx0, tx1 = cols[0]["x0"], cols[-1]["x1"]
        data_rows, last_bottom, pitch = [], header[-1]["bottom"], None
        stop_at = min((o.top for o in titles if o is not t and o.top > t.bottom and o.x0 < tx1 and o.x1 > tx0),
                      default=None)
        for r in rows[first + len(header):]:
            if stop_at is not None and r["top"] >= stop_at - 0.02:
                break
            gap = r["top"] - last_bottom
            limit = max(0.6, 3 * pitch) if pitch else 1.0
            if gap > limit:
                break
            inside = [w for w in r["words"] if tx0 - 0.1 <= (w.x0 + w.x1) / 2 <= tx1 + 0.1]
            if not inside:
                break
            cells = {}
            for w in inside:
                c = next((c for c in cols if c["x0"] <= (w.x0 + w.x1) / 2 <= c["x1"]), None)
                if c:
                    cells.setdefault(c["name"], []).append(w.text)
            mark = " ".join(cells.get(cols[0]["name"], [])).strip()
            if not mark and data_rows:                    # a wrapped line: the rest of the row above
                for k, v in cells.items():
                    prev = data_rows[-1]["fields"].get(k)
                    data_rows[-1]["fields"][k] = ((prev + " ") if prev else "") + " ".join(v)
            elif mark:
                fields = {c["name"]: " ".join(cells.get(c["name"], [])) or None for c in cols}
                data_rows.append({"mark": mark, "fields": fields, "_bottom": r["bottom"]})
            pitch = (r["top"] - last_bottom) if pitch is None else (pitch + (r["top"] - last_bottom)) / 2
            pitch = max(pitch, 0.05)
            last_bottom = r["bottom"]
            if len(data_rows) >= MAX_ROWS:
                break
        if not data_rows:
            continue
        filled_share = []
        for d in data_rows:
            d.pop("_bottom", None)
            filled = sum(1 for v in d["fields"].values() if v)
            share = filled / len(cols)
            filled_share.append(share)
            d["confidence"] = round(min(0.95, 0.45 + 0.45 * share + (0.05 if ruled else 0)), 2)
        mark_head = bool(MARK_HEAD.match(cols[0]["name"].split()[0])) if cols[0]["name"] else False
        conf = 0.55 + 0.05 * min(len(data_rows), 4) + (0.1 if ruled else 0) + (0.05 if mark_head else 0)
        found.append({"schedule_type": _type(t.text), "title": t.text, "columns": [c["name"] for c in cols],
                      "bbox": [round(min(tx0, t.x0), 3), round(t.top, 3), round(max(tx1, t.x1), 3), round(last_bottom, 3)],
                      "confidence": round(min(0.95, conf), 2), "rows": data_rows})
    return found

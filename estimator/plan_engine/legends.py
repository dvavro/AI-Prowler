"""Symbol legends and the plan-set symbol dictionary (spec: Symbol Recognition Engine steps 1-2).

1. Find the legends: short capital titles such as ELECTRICAL LEGEND, SYMBOL LEGEND, PLUMBING FIXTURE LEGEND,
   SYMBOLS or ABBREVIATIONS, on any sheet (often E-0.1, P-0.1, G-sheets).
2. Read each row: the symbol (drawn to the left of the words, or a short code such as WP, GFI, $3) and its
   description. Each entry is mapped to a standard item type and trade by its words (e.g. "duplex receptacle,
   GFCI" -> duplex_receptacle_gfci, electrical) and gets a confidence; low ones are for a person to confirm.
   The symbol's area is cropped as a picture (the template the Symbol Recognition Engine matches, Sprint 10).

The legends themselves (title, discipline, area) go into the drawing model; the dictionary entries are written to
symbol_dictionary.json beside the sheet images, one file per reading of the plan set, until the spec's
symbol_definitions table exists (see the Sprint 9 notes for Jamie).
"""
from __future__ import annotations

import re

TITLE = re.compile(r"^(?:[A-Z&/ -]{0,30}\b)?(LEGEND|SYMBOLS?(?:\s+LIST)?|ABBREVIATIONS?)(?:\s+AND\s+[A-Z ]{2,30})?$")
ROW_TOL = 0.06
MAX_ROWS = 80
MAX_BLOCK_W = 9.0
SYMBOL_GAP = 0.25            # a gap this big after the first words separates the code from the description

# Standard item types (the start of the spec's standard symbol library): (item type, trade, words that must all appear)
ITEM_TYPES = (
    ("duplex_receptacle_gfci", "electrical", ("receptacle", "gfci")), ("duplex_receptacle_gfci", "electrical", ("outlet", "gfci")),
    ("duplex_receptacle_gfci", "electrical", ("receptacle", "ground fault")),
    ("duplex_receptacle_wp", "electrical", ("receptacle", "weather")),
    ("quad_receptacle", "electrical", ("quad",)), ("quad_receptacle", "electrical", ("fourplex",)),
    ("receptacle_240v", "electrical", ("receptacle", "240")), ("receptacle_240v", "electrical", ("range",)),
    ("floor_box", "electrical", ("floor box",)), ("duplex_receptacle", "electrical", ("duplex",)),
    ("duplex_receptacle", "electrical", ("receptacle",)), ("duplex_receptacle", "electrical", ("convenience outlet",)),
    ("switch_3way", "electrical", ("three", "way", "switch")), ("switch_3way", "electrical", ("3-way",)),
    ("switch_4way", "electrical", ("4-way",)), ("switch_dimmer", "electrical", ("dimmer",)),
    ("switch", "electrical", ("switch",)), ("light_recessed", "electrical", ("recessed",)),
    ("light_recessed", "electrical", ("can light",)), ("exit_sign", "electrical", ("exit",)),
    ("emergency_light", "electrical", ("emergency",)), ("smoke_detector", "electrical", ("smoke",)),
    ("co_detector", "electrical", ("carbon monoxide",)), ("data_outlet", "electrical", ("data",)),
    ("phone_outlet", "electrical", ("telephone",)), ("tv_outlet", "electrical", ("tv",)),
    ("ceiling_fan", "electrical", ("ceiling fan",)), ("panel", "electrical", ("panel",)),
    ("junction_box", "electrical", ("junction",)), ("light_fixture", "electrical", ("light",)),
    ("light_fixture", "electrical", ("luminaire",)), ("light_fixture", "electrical", ("fixture", "ceiling")),
    ("thermostat", "mechanical", ("thermostat",)), ("exhaust_fan", "mechanical", ("exhaust",)),
    ("supply_diffuser", "mechanical", ("supply",)), ("supply_diffuser", "mechanical", ("diffuser",)),
    ("return_grille", "mechanical", ("return",)), ("water_closet", "plumbing", ("water closet",)),
    ("water_closet", "plumbing", ("toilet",)), ("lavatory", "plumbing", ("lavatory",)),
    ("sink", "plumbing", ("sink",)), ("floor_drain", "plumbing", ("floor drain",)),
    ("hose_bibb", "plumbing", ("hose bib",)), ("water_heater", "plumbing", ("water heater",)),
    ("cleanout", "plumbing", ("cleanout",)), ("cleanout", "plumbing", ("clean out",)),
    ("shower", "plumbing", ("shower",)), ("tub", "plumbing", ("tub",)),
    ("sprinkler_head", "fire", ("sprinkler",)), ("fire_extinguisher", "fire", ("extinguisher",)),
)
DISCIPLINE_WORDS = (("electrical", r"ELECTRICAL|POWER|LIGHTING"), ("plumbing", r"PLUMBING"),
                    ("mechanical", r"MECHANICAL|HVAC"), ("fire", r"FIRE"), ("architectural", r"ARCHITECTURAL|DOOR|WINDOW"))


def item_type(description: str) -> tuple[str | None, str | None]:
    d = " " + re.sub(r"[^a-z0-9/ -]+", " ", (description or "").lower()) + " "
    for it, trade, need in ITEM_TYPES:          # each word must start a word: "tv" isn't in "outvent"
        if all(re.search(r"(?<![a-z0-9])" + re.escape(n), d) for n in need):
            return it, trade
    return None, None


def _discipline(title: str, sheet_discipline: str | None) -> str | None:
    for d, rx in DISCIPLINE_WORDS:
        if re.search(rx, title, re.I):
            return d
    return sheet_discipline if sheet_discipline and sheet_discipline != "other" else None


def _rows(words):
    rows = []
    for w in sorted(words, key=lambda w: ((w.top + w.bottom) / 2, w.x0)):
        mid = (w.top + w.bottom) / 2
        if rows and abs(mid - rows[-1]["mid"]) <= max(ROW_TOL, (w.bottom - w.top) * 0.45):
            rows[-1]["words"].append(w)
        else:
            rows.append({"mid": mid, "words": [w]})
    for r in rows:
        r["words"].sort(key=lambda w: w.x0)
        r["top"] = min(w.top for w in r["words"])
        r["bottom"] = max(w.bottom for w in r["words"])
    return rows


def _has_line_work(page, box) -> bool:
    x0, y0, x1, y1 = box
    for (a, b) in page.segments or []:
        if x0 <= (a[0] + b[0]) / 2 <= x1 and y0 <= (a[1] + b[1]) / 2 <= y1:
            return True
    return False


def find(page, sheet_discipline: str | None = None, zone=None, skip=()) -> list[dict]:
    """Legends on a page: [{"title", "discipline", "bbox", "confidence", "abbreviations", "entries": [...]}].
    skip: boxes already used by schedules."""
    out = []
    titles = [ln for ln in page.lines if 1 <= len(ln.text.split()) <= 6 and TITLE.match(ln.text.strip())
              and not re.search(r"SCHEDULE", ln.text, re.I)
              and not (zone is not None and _in(((ln.x0 + ln.x1) / 2, ln.top), zone))
              and not any(_in(((ln.x0 + ln.x1) / 2, ln.top), b) for b in skip)]
    for t in titles:
        abbreviations = bool(re.search(r"ABBREVIATION", t.text))
        left = t.x0 - 1.5
        others = [o for o in titles if o is not t and o.top > t.bottom and abs(o.x0 - t.x0) < 3]
        stop = min((o.top for o in others), default=t.bottom + 40)
        words = [w for w in page.words if t.bottom - 0.01 <= w.top < stop and left <= w.x0 <= t.x0 + MAX_BLOCK_W
                 and not any(_in(((w.x0 + w.x1) / 2, w.top), b) for b in skip)
                 and not (zone is not None and _in(((w.x0 + w.x1) / 2, w.top), zone))]
        entries, last = [], t.bottom
        for r in _rows(words):
            if r["top"] - last > 0.8 or len(entries) >= MAX_ROWS:
                break
            ws = r["words"]
            # The code (or nothing, when the symbol is drawn) is what comes before the first big gap.
            split = next((i for i in range(1, len(ws)) if ws[i].x0 - ws[i - 1].x1 > SYMBOL_GAP), None)
            if abbreviations:
                code_words, desc_words = ws[:1], ws[1:]
                if split is not None:
                    code_words, desc_words = ws[:split], ws[split:]
            elif split is not None and split <= 2 and len(" ".join(w.text for w in ws[:split])) <= 8:
                code_words, desc_words = ws[:split], ws[split:]
            else:
                code_words, desc_words = [], ws
            description = " ".join(w.text for w in desc_words).strip(" -–:")
            if not description:
                last = r["bottom"]
                continue
            code = " ".join(w.text for w in code_words) or None
            sym_box = [round(left, 3), round(r["top"] - 0.06, 3), round(desc_words[0].x0 - 0.05, 3), round(r["bottom"] + 0.06, 3)]
            drawn = sym_box[2] - sym_box[0] > 0.15 and _has_line_work(page, sym_box)
            it, trade = (None, None) if abbreviations else item_type(description)
            conf = 0.45 + (0.25 if (drawn or code) else 0) + (0.2 if it else 0)
            entries.append({"code": code, "description": description, "item_type": it,
                            "trade": trade or (None if abbreviations else _discipline(t.text, sheet_discipline)),
                            "symbol_bbox": sym_box if drawn else None, "has_symbol": drawn,
                            "confidence": round(min(conf, 0.95), 2),
                            # a symbol with no standard item type is for a person to name, however clear it is
                            "needs_confirming": conf < 0.7 or (not abbreviations and it is None)})
            last = r["bottom"]
        if not entries:
            continue
        x1 = max(max(w.x1 for w in words), t.x1)
        conf = min(0.95, 0.5 + 0.05 * min(len(entries), 6) + (0.1 if any(e["item_type"] for e in entries) else 0))
        out.append({"title": t.text.strip(), "discipline": _discipline(t.text, sheet_discipline),
                    "bbox": [round(min(left, t.x0), 3), round(t.top, 3), round(x1, 3), round(last, 3)],
                    "confidence": round(conf, 2), "abbreviations": abbreviations, "entries": entries})
    return out


def _in(p, box) -> bool:
    return box[0] <= p[0] <= box[2] and box[1] <= p[1] <= box[3]


def crop_templates(legends_by_page: dict, pdf_path, sheets: dict, work) -> None:
    """Save each drawn symbol as a picture (the template for symbol matching): rendered from the PDF at 300 DPI, or
    cut from the saved image for scans. Adds "template" (a file name in work) to each entry."""
    from pathlib import Path

    from PIL import Image

    if work is None:
        return
    work = Path(work)
    for page_no, legends in legends_by_page.items():
        sheet = sheets.get(page_no) or {}
        for li, lg in enumerate(legends):
            for ei, e in enumerate(lg["entries"]):
                box = e.get("symbol_bbox")
                if not box:
                    continue
                name = f"legend_p{page_no:03d}_{li + 1}_{ei + 1}.png"
                try:
                    if pdf_path is not None:
                        from estimator.plan_engine.tiles import _pdf_tile
                        img = _pdf_tile(str(pdf_path), page_no, float(sheet["width"]), float(sheet["height"]), box, 300)
                    else:
                        with Image.open(sheet["image_path"]) as src:
                            rx = src.size[0] / float(sheet["width"])
                            img = src.crop(tuple(int(round(v * rx)) for v in box)).copy()
                    img.convert("RGB").save(work / name, "PNG")
                    e["template"] = name
                except Exception:  # noqa: BLE001 - a missing crop never stops the plans being read
                    e["template"] = None

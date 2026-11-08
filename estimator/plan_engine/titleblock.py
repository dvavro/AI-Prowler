"""Read a sheet's title block (sheet number, title, revision, date) and say which discipline the sheet is.

Title blocks sit along the right edge or the bottom of a sheet. The sheet number is the big code like A-101, E1.01
or S2 near "SHEET" / "SHEET NO"; the title is the plan-like words nearby ("FIRST FLOOR PLAN"). Nothing here guesses
when it isn't sure: a value that isn't found stays None and the confidence says how much was found.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from estimator.plan_engine.pdf_pages import Line, Page, Word

SHEET_NO_RE = re.compile(r"^(?:[A-Z]{1,3})[-. ]?\d{1,3}(?:\.\d{1,3})?[A-Z]?$")
SHEET_LABEL_RE = re.compile(r"\b(SHEET|SHT|DWG|DRAWING)\s*(NO|NUMBER|#)?\.?\b", re.I)
TITLE_LABEL_RE = re.compile(r"\b(SHEET|DRAWING|DWG)\s+TITLE\b", re.I)
REV_RE = re.compile(r"\bREV(?:ISION)?\.?\s*(?:NO\.?)?\s*[:#]?\s*([A-Z]|\d{1,2})\b", re.I)
DATE_RES = (
    (re.compile(r"\b(20\d\d)-(\d{1,2})-(\d{1,2})\b"), ("y", "m", "d")),
    (re.compile(r"\b(\d{1,2})[/.-](\d{1,2})[/.-](20\d\d|\d\d)\b"), ("m", "d", "y")),
)
PLAN_WORDS = ("PLAN", "PLANS", "ELEVATION", "ELEVATIONS", "SECTION", "SECTIONS", "DETAIL", "DETAILS", "SCHEDULE",
              "SCHEDULES", "NOTES", "COVER", "TITLE SHEET", "LAYOUT", "DIAGRAM", "RISER", "LEGEND", "INDEX")

# Sheet number prefixes (US National CAD Standard) -> discipline.
PREFIX = {"A": "architectural", "AD": "architectural", "ID": "architectural", "I": "architectural",
          "S": "structural", "SD": "structural",
          "P": "plumbing", "PD": "plumbing",
          "E": "electrical", "ED": "electrical", "EL": "electrical", "EP": "electrical",
          "M": "mechanical", "MD": "mechanical", "H": "mechanical",
          "L": "landscape", "LA": "landscape", "LP": "landscape",
          "C": "civil", "CS": "civil", "CG": "civil", "CU": "civil", "V": "civil",
          "F": "fire", "FP": "fire", "FA": "fire",
          "G": "general", "GI": "general", "T": "general", "CV": "general", "X": "general"}
# Title words beat a missing or unknown prefix (checked in order).
TITLE_DISCIPLINE = (("ROOF PLAN", "roof"), ("ROOFING", "roof"), ("SITE PLAN", "site"), ("PLOT PLAN", "site"),
                    ("GRADING", "civil"), ("UTILITY", "civil"), ("LANDSCAPE", "landscape"), ("PLANTING", "landscape"),
                    ("IRRIGATION", "landscape"), ("FOUNDATION", "structural"), ("FRAMING", "structural"),
                    ("STRUCTURAL", "structural"), ("ELECTRICAL", "electrical"), ("LIGHTING", "electrical"),
                    ("POWER", "electrical"), ("PLUMBING", "plumbing"), ("SANITARY", "plumbing"),
                    ("MECHANICAL", "mechanical"), ("HVAC", "mechanical"), ("DUCT", "mechanical"),
                    ("FIRE", "fire"), ("SPRINKLER", "fire"), ("COVER", "general"), ("TITLE SHEET", "general"),
                    ("FLOOR PLAN", "architectural"), ("ELEVATION", "architectural"), ("SECTION", "architectural"))


@dataclass
class TitleBlock:
    sheet_no: str | None = None
    title: str | None = None
    revision: str | None = None
    revision_date: str | None = None
    discipline: str = "other"
    zone: list[float] | None = None          # [x0, top, x1, bottom] of the title-block strip, inches
    found: int = 0                           # how many of sheet_no / title / discipline were found

    @property
    def confidence(self) -> float:
        return round(0.3 + 0.2 * self.found, 2)


def zones(page: Page) -> dict[str, list[float]]:
    """Where title blocks usually are: a strip down the right edge, or along the bottom."""
    w, h = page.width, page.height
    return {"right": [w * 0.78, 0.0, w, h], "bottom": [0.0, h * 0.82, w, h]}


def _inside(box: list[float], zone: list[float]) -> bool:
    cx, cy = (box[0] + box[2]) / 2, (box[1] + box[3]) / 2
    return zone[0] <= cx <= zone[2] and zone[1] <= cy <= zone[3]


def _near(a: list[float], b: list[float], dist: float) -> bool:
    """True when the boxes are within dist inches of each other."""
    dx = max(0.0, max(a[0], b[0]) - min(a[2], b[2]))
    dy = max(0.0, max(a[1], b[1]) - min(a[3], b[3]))
    return dx <= dist and dy <= dist


def _norm_sheet_no(text: str) -> str:
    return text.strip().upper().replace(" ", "")


def prefix_of(sheet_no: str | None) -> str:
    m = re.match(r"^([A-Z]{1,3})", sheet_no or "")
    return m.group(1) if m else ""


def discipline_for(sheet_no: str | None, title: str | None) -> str:
    """Discipline from the sheet number's prefix (A-101 -> architectural), refined by the title (A-501 ROOF PLAN -> roof;
    a sheet with no prefix titled ELECTRICAL PLAN -> electrical)."""
    t = (title or "").upper()
    from_title = next((d for words, d in TITLE_DISCIPLINE if words in t), None)
    p = prefix_of(sheet_no)
    from_prefix = PREFIX.get(p) or PREFIX.get(p[:1]) if p else None
    if from_prefix == "architectural" and from_title in ("roof", "site"):
        return from_title
    return from_prefix or from_title or "other"


def _sheet_no(page: Page, zone: list[float]) -> tuple[str | None, Word | None]:
    labels = [ln for ln in page.lines if SHEET_LABEL_RE.search(ln.text) and _inside(ln.bbox(), zone)]
    best, best_score = None, 0.0
    for w in page.words:
        text = _norm_sheet_no(w.text)
        if not SHEET_NO_RE.match(text) or not _inside([w.x0, w.top, w.x1, w.bottom], zone):
            continue
        score = w.size + (6 if prefix_of(text) in PREFIX or prefix_of(text)[:1] in PREFIX else 0)
        if any(_near([w.x0, w.top, w.x1, w.bottom], ln.bbox(), 0.8) for ln in labels):
            score += 10
        if score > best_score:
            best, best_score = w, score
    return (_norm_sheet_no(best.text), best) if best else (None, None)


def _is_plan_title(text: str) -> bool:
    t = text.upper()
    return any(re.search(rf"\b{re.escape(w)}\b", t) for w in PLAN_WORDS) and not t.startswith("SCALE")


def _title(page: Page, zone: list[float], near: Word | None) -> str | None:
    labelled = [ln for ln in page.lines if TITLE_LABEL_RE.search(ln.text) and _inside(ln.bbox(), zone)]
    cands = []
    for ln in page.lines:
        if not _inside(ln.bbox(), zone) or not _is_plan_title(ln.text) or TITLE_LABEL_RE.search(ln.text):
            continue
        score = ln.size
        if any(_near(ln.bbox(), lab.bbox(), 0.8) for lab in labelled):
            score += 10
        if near is not None and _near(ln.bbox(), [near.x0, near.top, near.x1, near.bottom], 2.0):
            score += 4
        cands.append((score, ln))
    if not cands:
        return None
    cands.sort(key=lambda c: -c[0])
    best = cands[0][1]
    # A two-line title ("FIRST FLOOR" / "PLAN") is joined when the next line is right under it in the same size.
    parts = [best]
    for ln in page.lines:
        if ln is best or not _inside(ln.bbox(), zone):
            continue
        if abs(ln.size - best.size) < 0.6 and 0 <= ln.top - best.bottom <= best.size / 72 * 0.8 \
                and abs(ln.x0 - best.x0) < 0.5 and not SHEET_NO_RE.match(_norm_sheet_no(ln.text)):
            parts.append(ln)
    text = " ".join(p.text for p in sorted(parts, key=lambda p: p.top))
    return re.sub(r"\s+", " ", text).strip()[:200]


def _revision(page: Page, zone: list[float]) -> tuple[str | None, str | None]:
    rev = None
    dates: list[date] = []
    for ln in page.lines:
        if not _inside(ln.bbox(), zone):
            continue
        m = REV_RE.search(ln.text)
        if m and rev is None:
            rev = m.group(1).upper()
        for rx, order in DATE_RES:
            for dm in rx.finditer(ln.text):
                parts = dict(zip(order, dm.groups()))
                y = int(parts["y"])
                y = y + 2000 if y < 100 else y
                try:
                    dates.append(date(y, int(parts["m"]), int(parts["d"])))
                except ValueError:
                    continue
    return rev, (max(dates).isoformat() if dates else None)


def read(page: Page) -> TitleBlock:
    """The title block of one page: tries the right strip, then the bottom strip, and keeps whichever found more."""
    best = TitleBlock()
    for name, zone in zones(page).items():
        sheet_no, word = _sheet_no(page, zone)
        title = _title(page, zone, word)
        if not sheet_no and not title:
            continue
        tb = TitleBlock(sheet_no=sheet_no, title=title, zone=zone)
        tb.revision, tb.revision_date = _revision(page, zone)
        tb.discipline = discipline_for(sheet_no, title)
        tb.found = sum(1 for x in (sheet_no, title, tb.discipline != "other") if x)
        if tb.found > best.found:
            best = tb
    return best


def lines_outside(page: Page, zone: list[float] | None) -> list[Line]:
    """Text lines in the drawing area (not in the title block)."""
    return [ln for ln in page.lines if zone is None or not _inside(ln.bbox(), zone)]

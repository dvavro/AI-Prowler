"""Read a PDF plan set page by page: size, a rendered image, the words with their positions, and drawn rectangles.

Everything comes back in INCHES ON THE PAPER with the origin at the TOP-LEFT corner (the drawing model's convention),
so a box found here lands on the same spot of the rendered image.

- pypdfium2 renders the pages (fast, no external programs).
- pdfplumber gives each word's box and font size, and the rectangles drawn on the page (viewport frames).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

PT = 72.0                         # PDF points per inch
MAX_RENDER_PX = 4000              # longest side of a rendered sheet image
MAX_DPI = 150
MIN_DPI = 40


@dataclass
class Word:
    text: str
    x0: float
    top: float
    x1: float
    bottom: float
    size: float                   # font size in points

    @property
    def cx(self) -> float:
        return (self.x0 + self.x1) / 2


@dataclass
class Line:
    """Words on one text line, left to right."""
    words: list[Word]

    @property
    def text(self) -> str:
        return " ".join(w.text for w in self.words)

    @property
    def x0(self) -> float:
        return min(w.x0 for w in self.words)

    @property
    def x1(self) -> float:
        return max(w.x1 for w in self.words)

    @property
    def top(self) -> float:
        return min(w.top for w in self.words)

    @property
    def bottom(self) -> float:
        return max(w.bottom for w in self.words)

    @property
    def size(self) -> float:
        return max(w.size for w in self.words)

    @property
    def cx(self) -> float:
        return (self.x0 + self.x1) / 2

    def bbox(self) -> list[float]:
        return [self.x0, self.top, self.x1, self.bottom]


@dataclass
class Page:
    page_no: int
    width: float                  # inches
    height: float
    words: list[Word] = field(default_factory=list)
    lines: list[Line] = field(default_factory=list)
    rects: list[list[float]] = field(default_factory=list)     # [x0, top, x1, bottom] in inches
    image_path: str | None = None


def render_dpi(width_in: float, height_in: float) -> int:
    """Sharp enough to read, small enough to load on a phone: at most 4000 px on the long side."""
    longest = max(width_in, height_in, 1.0)
    return int(max(MIN_DPI, min(MAX_DPI, MAX_RENDER_PX / longest)))


def group_lines(words: list[Word]) -> list[Line]:
    """Words whose vertical middles are close and that sit near each other become one line."""
    lines: list[Line] = []
    for w in sorted(words, key=lambda w: ((w.top + w.bottom) / 2, w.x0)):
        mid = (w.top + w.bottom) / 2
        h = max(w.bottom - w.top, 0.05)
        for ln in lines:
            last = ln.words[-1]
            lmid = (ln.top + ln.bottom) / 2
            gap = w.x0 - last.x1
            if abs(mid - lmid) <= h * 0.5 and -0.05 <= gap <= max(h * 3, 0.4):
                ln.words.append(w)
                break
        else:
            lines.append(Line([w]))
    for ln in lines:
        ln.words.sort(key=lambda w: w.x0)
    return lines


def read(path: Path, work_dir: Path | None, max_pages: int, render: bool = True) -> tuple[int, list[Page]]:
    """(page_count, pages). Raises a plain ValueError when the file can't be read."""
    import logging

    import pdfplumber
    import pypdfium2 as pdfium

    logging.getLogger("pdfminer").setLevel(logging.ERROR)     # "Could not get FontBBox..." on many real PDFs

    try:
        doc = pdfium.PdfDocument(str(path))
    except Exception as exc:  # noqa: BLE001 - pdfium's own errors are cryptic
        raise ValueError(f"this PDF can't be opened ({exc})") from None
    count = len(doc)
    if count == 0:
        doc.close()
        raise ValueError("this PDF has no pages")
    if count > max_pages:
        doc.close()
        raise ValueError(f"this PDF has {count} pages; a plan set can have at most {max_pages}. Split it into smaller "
                         "sets (for example by discipline) and upload each one")
    pages: list[Page] = []
    try:
        with pdfplumber.open(str(path)) as plumb:
            for i in range(count):
                pdf_page = doc[i]
                w_pt, h_pt = pdf_page.get_size()          # already turned by the page's /Rotate, like the render
                page = Page(page_no=i + 1, width=round(w_pt / PT, 3), height=round(h_pt / PT, 3))
                if render and work_dir is not None:
                    dpi = render_dpi(page.width, page.height)
                    img = pdf_page.render(scale=dpi / PT).to_pil()
                    out = Path(work_dir) / f"sheet_{i + 1:03d}.png"
                    img.convert("RGB").save(out, "PNG", optimize=True)
                    page.image_path = str(out)
                pdf_page.close()
                pp = plumb.pages[i]
                for w in pp.extract_words(keep_blank_chars=False, use_text_flow=False, extra_attrs=["size"]):
                    text = (w.get("text") or "").strip()
                    if text:
                        page.words.append(Word(text, w["x0"] / PT, w["top"] / PT, w["x1"] / PT, w["bottom"] / PT,
                                               float(w.get("size") or 0)))
                for r in pp.rects:
                    page.rects.append([r["x0"] / PT, r["top"] / PT, r["x1"] / PT, r["bottom"] / PT])
                page.lines = group_lines(page.words)
                pages.append(page)
                pp.flush_cache() if hasattr(pp, "flush_cache") else None
    finally:
        doc.close()
    return count, pages

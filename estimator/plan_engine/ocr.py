"""Reading text from scanned sheets and photos with Tesseract (spec: "Tesseract, already bundled with AI-Prowler, for
raster; native text for vector and CAD").

Vector PDFs already carry their text, so OCR only runs where a page has none (a scan saved as PDF) and on images.
Words come back as pdf_pages.Word objects in sheet inches from the top-left - the same frame as PDF text - so the
title block, viewports, schedules, legends and dimensions read them the same way.

Tesseract is found the way AI-Prowler's own OCR setup finds it: ESTIMATOR_TESSERACT (a full path, or "off"), then the
PATH, then the per-user install (%LOCALAPPDATA%\\Programs\\Tesseract-OCR) and Program Files. Without it the sheets are
still read; they just say OCR isn't installed.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

MIN_CONFIDENCE = 55            # Tesseract's own 0-100 word confidence
OCR_DPI = 300
MAX_OCR_PX = 7000              # long side; a 36" sheet is read at about 194 DPI
TIMEOUT_S = 180                # per page
_QUOTES = str.maketrans({"’": "'", "‘": "'", "′": "'", "”": '"', "“": '"', "″": '"', "—": "-", "–": "-"})
_cached: dict = {}


def tesseract_path() -> str | None:
    if "path" in _cached:
        return _cached["path"]
    env = os.environ.get("ESTIMATOR_TESSERACT", "").strip()
    found = None
    if env.lower() in ("off", "none", "0"):
        found = None
    elif env:
        found = env if Path(env).is_file() else None
    else:
        local = os.environ.get("LOCALAPPDATA", "")
        for c in (shutil.which("tesseract"), os.path.join(local, "Programs", "Tesseract-OCR", "tesseract.exe") if local else None,
                  r"C:\Program Files\Tesseract-OCR\tesseract.exe", r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"):
            if c and Path(c).is_file():
                found = c
                break
    _cached["path"] = found
    return found


def available() -> bool:
    if "ok" in _cached:
        return _cached["ok"]
    ok = False
    exe = tesseract_path()
    if exe:
        try:
            import pytesseract
            pytesseract.pytesseract.tesseract_cmd = exe
            pytesseract.get_tesseract_version()
            ok = True
        except Exception:  # noqa: BLE001 - not installed or won't run
            ok = False
    _cached["ok"] = ok
    return ok


def reset() -> None:
    """Forget what was found (tests, or after installing Tesseract)."""
    _cached.clear()


def status_note() -> str:
    return "" if available() else "OCR (Tesseract) isn't installed, so text on scans can't be read; install it from AI-Prowler's OCR settings"


def words_from_image(img, px_per_in: float, offset=(0.0, 0.0)) -> list:
    """The words Tesseract is sure of, as pdf_pages.Word in inches (offset = where the image's corner sits)."""
    import pytesseract

    from estimator.plan_engine.pdf_pages import Word

    if not available():
        return []
    gray = img.convert("L")
    try:
        data = pytesseract.image_to_data(gray, config="--oem 1 --psm 11", output_type=pytesseract.Output.DICT,
                                         timeout=TIMEOUT_S)
    except RuntimeError:                                      # Tesseract timed out on a very busy page
        return []
    out = []
    ox, oy = offset
    for i, text in enumerate(data["text"]):
        t = (text or "").strip().translate(_QUOTES)
        try:
            conf = float(data["conf"][i])
        except (TypeError, ValueError):
            conf = -1
        if not t or conf < MIN_CONFIDENCE:
            continue
        left, top, w, h = (data[k][i] for k in ("left", "top", "width", "height"))
        if w <= 0 or h <= 0:
            continue
        out.append(Word(t, ox + left / px_per_in, oy + top / px_per_in, ox + (left + w) / px_per_in,
                        oy + (top + h) / px_per_in, round(h / px_per_in * 72, 1)))
    return out


def ocr_dpi(width_in: float, height_in: float) -> float:
    return max(72.0, min(float(OCR_DPI), MAX_OCR_PX / max(width_in, height_in, 1.0)))


def pdf_page_words(pdf_path, page_no: int, width_in: float, height_in: float) -> list:
    """Render one PDF page for OCR (a scan saved as PDF) and read its words."""
    import pypdfium2 as pdfium

    from estimator.plan_engine.pdf_pages import PDFIUM_LOCK

    dpi = ocr_dpi(width_in, height_in)
    with PDFIUM_LOCK:
        doc = pdfium.PdfDocument(str(pdf_path))
        try:
            page = doc[page_no - 1]
            try:
                img = page.render(scale=dpi / 72).to_pil().convert("L")
            finally:
                page.close()
        finally:
            doc.close()
    return words_from_image(img, dpi)

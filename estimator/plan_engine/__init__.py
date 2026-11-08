"""AI-Prowler Plan Engine (Coder 2 track) - reads plan files for the drawing model.

The Estimator finds this package by name and calls process() (see estimator/drawing_model/engine.py for the
contract). The engine never opens estimator.db: it returns plain results, and the drawing model checks, measures and
saves them.

Sprint 5 (this version):
- PDF: every page becomes a sheet, rendered to a PNG for review and AI vision; the title block gives the sheet
  number, title, revision and date, and the sheet number and title give the discipline; each view's scale note
  becomes a viewport (see viewports.py). Text and frames are read from the PDF itself - scanned pages with no text
  get a sheet and an image but no title or scale (OCR comes in a later sprint).
- Images (PNG, JPG, TIFF scans and photos): one sheet per image or TIFF page, no scale - a person sets the scale or
  calibrates from two points (plan_set_scale).

Sprint 6:
- PDF line work (pdfplumber): walls (pairs of parallel lines a wall's thickness apart, checked with each view's own
  scale) and rooms (a room name inside a closed area), per viewport - see vectors.py and pdf_objects.py.
- DXF (ezdxf, see dxf_reader.py): model space at real size - lines and shapes by layer, blocks as symbols with their
  tags, text, dimensions, walls and rooms - plus a rendered picture for review.
- DWG still needs a converter (a later release): save as DXF or print to PDF.
"""
from __future__ import annotations

from pathlib import Path

ENGINE_NAME = "AI-Prowler Plan Engine 0.6 (PDF, images, DXF)"
VERSION = "0.6"


def _max_sheets() -> int:
    from estimator.drawing_model import store
    return int(getattr(store, "MAX_SHEETS", 500))


def process(file_path: Path, file_type: str, info: dict) -> dict:
    """Read one plan file. Returns {"page_count", "sheets": [...]} in the drawing model's format."""
    file_path = Path(file_path)
    work = Path(info["work_dir"]) if info.get("work_dir") else None
    if work is not None:
        work.mkdir(parents=True, exist_ok=True)
    kind = (file_type or "").lower()
    if kind == "pdf":
        return _pdf(file_path, work)
    if kind == "image":
        from estimator.plan_engine import images
        return images.read(file_path, work, _max_sheets())
    if kind == "dxf":
        from estimator.plan_engine import dxf_reader
        return dxf_reader.read(file_path, work, _max_sheets())
    if kind == "dwg":
        raise ValueError("DWG drawings need a converter, which comes in a later release. For now, save the drawing as "
                         "DXF from your CAD program (Save As > DXF) and upload that, or print the sheets to PDF")
    raise ValueError(f"the plan engine can't read '{file_type}' files")


def _pdf(path: Path, work: Path | None) -> dict:
    from estimator.plan_engine import pdf_objects, pdf_pages, titleblock, viewports

    count, pages = pdf_pages.read(path, work, _max_sheets())
    sheets = []
    for page in pages:
        tb = titleblock.read(page)
        vps = viewports.find(page, tb.zone)
        objects, notes = pdf_objects.find(page, vps)
        sheet = {"page_no": page.page_no, "sheet_no": tb.sheet_no, "title": tb.title, "discipline": tb.discipline,
                 "revision": tb.revision, "revision_date": tb.revision_date, "units": "paper_in",
                 "width": page.width, "height": page.height, "image_path": page.image_path,
                 "confidence": tb.confidence if page.words else 0.1, "viewports": vps, "objects": objects}
        if not page.words:
            notes.insert(0, "no text on this page (a scan?): the title and scale need a person or OCR")
        if notes:
            sheet["note"] = "; ".join(notes)
        sheets.append(sheet)
    return {"page_count": count, "sheets": sheets, "engine": ENGINE_NAME}

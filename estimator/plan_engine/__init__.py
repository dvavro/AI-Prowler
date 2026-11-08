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
- DXF and DWG are read from the next plan-engine release (vector and CAD import).
"""
from __future__ import annotations

from pathlib import Path

ENGINE_NAME = "AI-Prowler Plan Engine 0.5 (PDF and images)"
VERSION = "0.5"


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
    if kind in ("dxf", "dwg"):
        raise ValueError(f"{kind.upper()} drawings are read from the next plan-engine release. For now, print the "
                         "sheets to PDF from your CAD program and upload the PDF")
    raise ValueError(f"the plan engine can't read '{file_type}' files")


def _pdf(path: Path, work: Path | None) -> dict:
    from estimator.plan_engine import pdf_pages, titleblock, viewports

    count, pages = pdf_pages.read(path, work, _max_sheets())
    sheets = []
    for page in pages:
        tb = titleblock.read(page)
        vps = viewports.find(page, tb.zone)
        sheet = {"page_no": page.page_no, "sheet_no": tb.sheet_no, "title": tb.title, "discipline": tb.discipline,
                 "revision": tb.revision, "revision_date": tb.revision_date, "units": "paper_in",
                 "width": page.width, "height": page.height, "image_path": page.image_path,
                 "confidence": tb.confidence if page.words else 0.1, "viewports": vps}
        if not page.words:
            sheet["note"] = "no text on this page (a scan?): the title and scale need a person or OCR"
        sheets.append(sheet)
    return {"page_count": count, "sheets": sheets, "engine": ENGINE_NAME}

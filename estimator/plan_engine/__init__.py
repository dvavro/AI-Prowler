"""AI-Prowler Plan Engine (Coder 2 track) - reads plan files for the drawing model.

The Estimator finds this package by name and calls process() (see estimator/drawing_model/engine.py for the
contract). The engine never opens estimator.db: it returns plain results, and the drawing model checks, measures and
saves them.

Sprint 5:
- PDF: every page becomes a sheet, rendered to a PNG for review and AI vision; the title block gives the sheet
  number, title, revision and date, and the sheet number and title give the discipline; each view's scale note
  becomes a viewport (see viewports.py).
- Images (PNG, JPG, TIFF scans and photos): one sheet per image or TIFF page.

Sprint 6:
- PDF line work (pdfplumber): walls and rooms per viewport - see vectors.py and pdf_objects.py.
- DXF (ezdxf, see dxf_reader.py): model space at real size. DWG still needs a converter.

Sprint 7: viewer tiles (tiles.py) and layer groups (layers.py) for Blueprint Review.

Sprint 9 (this version):
- OCR (ocr.py, Tesseract): scanned PDF pages and images get their words read, so the title block, scales, schedules,
  legends and dimensions work on scans too.
- Dimensions (dimensions.py): dimension strings become objects; each view's scale is checked against them, and a
  view with no scale gets one when its dimensions agree on a standard scale.
- Schedules (schedules.py): door, window, finish, fixture, panel, equipment and wall-type tables as rows by mark.
- Tags (tags.py): words on the plans matching a schedule mark, so the drawing model links rows to plan tags.
- Legends (legends.py): legend blocks and the plan-set symbol dictionary (entries, item types, template crops),
  written to symbol_dictionary.json beside the sheet images.
"""
from __future__ import annotations

from pathlib import Path

ENGINE_NAME = "AI-Prowler Plan Engine 0.7 (PDF, images, DXF, OCR, schedules, legends)"
VERSION = "0.7"
DICTIONARY_FILE = "symbol_dictionary.json"


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
        return _images(file_path, work)
    if kind == "dxf":
        from estimator.plan_engine import dxf_reader
        return dxf_reader.read(file_path, work, _max_sheets())
    if kind == "dwg":
        raise ValueError("DWG drawings need a converter, which comes in a later release. For now, save the drawing as "
                         "DXF from your CAD program (Save As > DXF) and upload that, or print the sheets to PDF")
    raise ValueError(f"the plan engine can't read '{file_type}' files")


def _analyze(page, source: str) -> tuple[dict, dict]:
    """One page -> (sheet in the drawing model's format, what the plan-set pass needs)."""
    from estimator.plan_engine import dimensions, legends, pdf_objects, schedules, titleblock, viewports

    tb = titleblock.read(page)
    vps = viewports.find(page, tb.zone)
    objects, notes = pdf_objects.find(page, vps)
    scheds = schedules.find(page, tb.zone)
    tables = [s["bbox"] for s in scheds]
    legs = legends.find(page, tb.discipline, tb.zone, skip=tables)
    tables += [lg["bbox"] for lg in legs]
    # A schedule's grid with "KITCHEN" in a cell isn't a room: nothing found inside a table counts as drawing.
    objects = [o for o in objects if not any(_inside(_centre(o["geometry"]), b) for b in tables)]
    dims, dim_notes = dimensions.check(page, vps, tb.zone)
    dims = [d for d in dims if not any(_inside(_centre(d["geometry"]), b) for b in tables)]
    notes += dim_notes
    sheet = {"page_no": page.page_no, "sheet_no": tb.sheet_no, "title": tb.title, "discipline": tb.discipline,
             "revision": tb.revision, "revision_date": tb.revision_date, "units": "paper_in",
             "width": page.width, "height": page.height, "image_path": page.image_path,
             "confidence": tb.confidence if page.words else 0.1, "viewports": vps, "objects": objects + dims,
             "schedules": [{k: s[k] for k in ("schedule_type", "title", "bbox", "confidence", "rows")} for s in scheds],
             "legends": [{k: lg[k] for k in ("title", "discipline", "bbox", "confidence")} for lg in legs]}
    if source == "raster" and page.words:
        for o in sheet["objects"]:
            o["source"] = "raster"
    return sheet, {"page": page, "zone": tb.zone, "tables": tables, "schedules": scheds, "legends": legs,
                   "notes": notes, "source": source}


def _finish(sheets: list[dict], extras: list[dict], work, pdf_path=None) -> None:
    """The plan-set pass: tags matching any schedule's marks, the symbol dictionary, and the sheet notes."""
    from estimator.plan_engine import legends, pdf_objects, tags

    marks = tags.marks_of({e["page"].page_no: e["schedules"] for e in extras})
    for sheet, e in zip(sheets, extras):
        found = tags.find(e["page"], marks, sheet["viewports"], skip=e["tables"], zone=e["zone"], source=e["source"])
        room = pdf_objects.MAX_OBJECTS_PER_SHEET - len(sheet["objects"])
        if room < len(found):
            e["notes"].append(f"only the first {max(room, 0)} of {len(found)} tags were kept")
        sheet["objects"] += found[:max(room, 0)]
        sheet["objects"] = sheet["objects"][:pdf_objects.MAX_OBJECTS_PER_SHEET]
        if e["notes"]:
            sheet["note"] = "; ".join(dict.fromkeys(e["notes"]))
    by_page = {e["page"].page_no: e["legends"] for e in extras if e["legends"]}
    if by_page:
        legends.crop_templates(by_page, pdf_path, {s["page_no"]: s for s in sheets}, work)
    tags.write_dictionary(work, ENGINE_NAME, by_page, {s["page_no"]: s for s in sheets})


def _pdf(path: Path, work: Path | None) -> dict:
    from estimator.plan_engine import ocr, pdf_pages

    count, pages = pdf_pages.read(path, work, _max_sheets())
    sheets, extras = [], []
    for page in pages:
        source = "vector"
        if not page.words and ocr.available():               # a scan saved as PDF: read its words
            page.words = ocr.pdf_page_words(path, page.page_no, page.width, page.height)
            page.lines = pdf_pages.group_lines(page.words)
            source = "raster"
        sheet, e = _analyze(page, source)
        if not page.words:
            e["notes"].insert(0, "no text on this page (a scan?): " + (ocr.status_note() or "OCR found no words")
                              + "; the title and scale need a person")
        elif source == "raster":
            e["notes"].insert(0, "text read by OCR - check the sheet number and scale")
        sheets.append(sheet)
        extras.append(e)
    _finish(sheets, extras, work, pdf_path=path)
    return {"page_count": count, "sheets": sheets, "engine": ENGINE_NAME}


def _images(path: Path, work: Path | None) -> dict:
    from estimator.plan_engine import images, ocr, pdf_pages

    out = images.read(path, work, _max_sheets(), ocr_words=ocr.available())
    sheets, extras = [], []
    for s in out["sheets"]:
        words = s.pop("_words", None)
        if not words:
            note = s.get("note")
            s["note"] = "; ".join(x for x in (note, ocr.status_note()) if x) or None
            if not s["note"]:
                s.pop("note")
            sheets.append(s)
            extras.append(None)
            continue
        page = pdf_pages.Page(page_no=s["page_no"], width=s["width"], height=s["height"], words=words,
                              lines=pdf_pages.group_lines(words), image_path=s["image_path"])
        sheet, e = _analyze(page, "raster")
        if s.get("note"):
            e["notes"].insert(0, s["note"])
        e["notes"].insert(1 if s.get("note") else 0, "text read by OCR - check the sheet number and scale")
        sheets.append(sheet)
        extras.append(e)
    read = [(s, e) for s, e in zip(sheets, extras) if e is not None]
    if read:
        _finish([s for s, _ in read], [e for _, e in read], work)
    return {"page_count": out["page_count"], "sheets": sheets, "engine": ENGINE_NAME}


def _centre(geometry: dict) -> tuple[float, float]:
    pts = geometry["points"]
    return (sum(float(p[0]) for p in pts) / len(pts), sum(float(p[1]) for p in pts) / len(pts))


def _inside(p, box) -> bool:
    return box[0] <= p[0] <= box[2] and box[1] <= p[1] <= box[3]


def dictionary_path(sheet_image_path: str | None) -> Path | None:
    """Where a plan set's symbol dictionary was written (beside its sheet images)."""
    if not sheet_image_path:
        return None
    p = Path(sheet_image_path).parent / DICTIONARY_FILE
    return p if p.is_file() else None

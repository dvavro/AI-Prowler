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

Sprint 10 (this version): the Symbol Recognition Engine v1 (symbols.py, symbol_library.py). Every legend symbol is
searched for on every sheet (vector line work, or the scan's picture), fused with the codes beside each hit, and
returned as symbol objects with a "symbol" record plus results["symbol_dictionary"]; CAD blocks are named from their
block names. The drawing model saves them in symbol_definitions / symbol_detections (estimator/symbols/).

Sprint 9:
- OCR (ocr.py, Tesseract): scanned PDF pages and images get their words read, so the title block, scales, schedules,
  legends and dimensions work on scans too.
- Dimensions (dimensions.py): dimension strings become objects; each view's scale is checked against them, and a
  view with no scale gets one when its dimensions agree on a standard scale.
- Schedules (schedules.py): door, window, finish, fixture, panel, equipment and wall-type tables as rows by mark.
- Tags (tags.py): words on the plans matching a schedule mark, so the drawing model links rows to plan tags.
- Legends (legends.py): legend blocks and the plan-set symbol dictionary (entries, item types, template crops),
  written to symbol_dictionary.json beside the sheet images.

Sprint 16 (this version, 0.9):
- Scans and photos (raster.py): photos squared up, blueprints inverted, tilted scans straightened (the saved sheet image
  and the OCR words with them), and the line work traced, so walls, rooms, elevations and site objects are found on
  scans too. Everything found on a scan or photo is source "raster", confidence 0.5 at most, and the sheet says it's
  to check; the building model and the measurements made from it carry "needs review" (method raster).
- DWG (dwg.py): converted to DXF by the ODA File Converter or LibreDWG when the user installed one; otherwise the
  plans say how to get one, or to save the drawing as DXF or PDF.
"""
from __future__ import annotations

import contextvars
from pathlib import Path

_LIBRARY: contextvars.ContextVar = contextvars.ContextVar("symbol_library", default=[])
ENGINE_NAME = "AI-Prowler Plan Engine 0.9 (PDF, scans and photos, DXF, DWG, OCR, schedules, legends, symbols)"
VERSION = "0.9"
DICTIONARY_FILE = "symbol_dictionary.json"
RASTER_NOTE = "scan or photo: everything found here is marked to check"
SCAN_MAX_SEGMENTS = 20          # a PDF page with no text and less line work than this is a scan


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
    token = _LIBRARY.set(info.get("symbol_library") or [])     # Sprint 11: the company's learned symbols
    try:
        if kind == "pdf":
            return _pdf(file_path, work)
        if kind == "image":
            return _images(file_path, work)
    finally:
        _LIBRARY.reset(token)
    if kind == "dxf":
        return _dxf(file_path, work)
    if kind == "dwg":
        return _dwg(file_path, work)
    raise ValueError(f"the plan engine can't read '{file_type}' files")


def _dxf(file_path: Path, work: Path | None) -> dict:
    from estimator.plan_engine import dxf_reader, symbols
    out = dxf_reader.read(file_path, work, _max_sheets())
    for s in out["sheets"]:                              # Sprint 10: CAD block names say what each symbol is
        symbols.cad_symbols(s)
    return out


def _dwg(file_path: Path, work: Path | None) -> dict:
    """Sprint 16: a DWG is converted to DXF by the converter the user installed, then read like any DXF."""
    import tempfile

    from estimator.plan_engine import dwg

    conv = dwg.find_converter()
    if conv is None:
        raise ValueError(dwg.GUIDANCE)
    if work is not None:
        dxf = dwg.convert(file_path, work / "converted", conv)
        out = _dxf(dxf, work)
    else:
        with tempfile.TemporaryDirectory(prefix="dwg_") as tmp:
            out = _dxf(dwg.convert(file_path, Path(tmp), conv), None)
    note = f"converted from DWG with the {conv['name']}"
    for s in out["sheets"]:
        s["note"] = "; ".join(x for x in (note, s.get("note")) if x)
    out["converted_with"] = conv["name"]
    return out


def _analyze(page, source: str) -> tuple[dict, dict]:
    """One page -> (sheet in the drawing model's format, what the plan-set pass needs)."""
    from estimator.plan_engine import dimensions, legends, pdf_objects, schedules, titleblock, viewports

    tb = titleblock.read(page)
    vps = viewports.find(page, tb.zone)
    objects, notes = pdf_objects.find(page, vps, tb.discipline)
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
    if source == "raster":                               # Sprint 16: marked to check, never trusted like line work
        from estimator.plan_engine import raster
        for o in sheet["objects"]:
            o["source"] = "raster"
            o["confidence"] = raster.confidence(o.get("confidence"))
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
    return _symbols(sheets, extras, by_page)


def _symbols(sheets: list[dict], extras: list[dict], by_page: dict) -> list[dict]:
    """Sprint 10: search every sheet for the legend's symbols and fuse each hit with the words around it."""
    from estimator.plan_engine import pdf_objects, symbols

    entries = symbols.dictionary(by_page)
    lib_entries, lib_templates = symbols.library_entries(_LIBRARY.get())
    if not entries and not lib_entries:
        return []
    by_sheet = {s["page_no"]: s for s in sheets}
    templates = symbols.templates_for(entries, {e["page"].page_no: e["page"] for e in extras}, by_sheet)
    templates.update(lib_templates)
    entries = entries + lib_entries
    for sheet, e in zip(sheets, extras):
        skip = list(e["tables"]) + ([e["zone"]] if e["zone"] else [])
        try:
            found = symbols.scan_sheet(e["page"], sheet, entries, templates, skip, e["source"])
        except ImportError as exc:                       # numpy/scipy missing: say so, read everything else
            sheet["note"] = "; ".join(x for x in (sheet.get("note"), f"symbols weren't searched ({exc})") if x)
            found = []
        room = max(pdf_objects.MAX_OBJECTS_PER_SHEET - len(sheet["objects"]), 0)
        if found:
            sheet["objects"] += found[:room]
            n = min(len(found), room)
            unsure = sum(1 for o in found[:room] if o["symbol"]["needs_review"])
            msg = f"{n} symbol(s) found from the legend" + (f", {unsure} to check" if unsure else "")
            sheet["note"] = "; ".join(x for x in (sheet.get("note"), msg) if x)
    return entries


def _pdf(path: Path, work: Path | None) -> dict:
    from estimator.plan_engine import ocr, pdf_pages

    count, pages = pdf_pages.read(path, work, _max_sheets())
    sheets, extras = [], []
    for page in pages:
        source = "vector"
        prep_notes: list[str] = []
        if not page.words and len(page.segments) < SCAN_MAX_SEGMENTS:     # a scan saved as PDF
            source = "raster"
            prep_notes = _scan_page(path, page)
        sheet, e = _analyze(page, source)
        if not page.words:
            e["notes"].insert(0, "no text on this page (a scan?): " + (ocr.status_note() or "OCR found no words")
                              + "; the title and scale need a person")
        elif source == "raster":
            e["notes"].insert(0, "text read by OCR - check the sheet number and scale")
        if source == "raster":
            e["notes"][1:1] = prep_notes + [RASTER_NOTE]
        sheets.append(sheet)
        extras.append(e)
    entries = _finish(sheets, extras, work, pdf_path=path)
    return {"page_count": count, "sheets": sheets, "engine": ENGINE_NAME, "symbol_dictionary": entries}


def _scan_page(path: Path, page) -> list[str]:
    """Sprint 16: a scanned PDF page through the raster pipeline - straightened (and the review image with it), its
    line work traced, then its words read by OCR from the straightened picture. Returns the notes."""
    from estimator.plan_engine import ocr, pdf_pages

    try:
        img, dpi = ocr.render_pdf_page(path, page.page_no, page.width, page.height)
    except Exception as exc:  # noqa: BLE001 - the page can't be drawn: read nothing more from it
        return [f"the scan couldn't be drawn for reading ({exc})"]
    notes: list[str] = []
    try:
        from estimator.plan_engine import raster
        prep = raster.prepare(img, dpi)
    except ImportError as exc:
        prep = None
        notes.append(f"the line work wasn't traced ({exc})")
    if prep is not None:
        notes += prep.notes
        page.segments = prep.segments
        img = prep.image
        if prep.squared_up:
            page.width, page.height = round(img.size[0] / dpi, 3), round(img.size[1] / dpi, 3)
        if prep.changed and page.image_path:                 # the review picture shows the straightened sheet
            try:
                from PIL import Image
                with Image.open(page.image_path) as old:
                    size = (old.size[0], max(1, round(old.size[0] * img.size[1] / img.size[0])))
                img.resize(size, Image.Resampling.LANCZOS).convert("RGB").save(page.image_path, "PNG", optimize=True)
            except Exception:  # noqa: BLE001 - keep the original picture
                pass
    if ocr.available():
        page.words = ocr.words_from_image(img, dpi)
        page.lines = pdf_pages.group_lines(page.words)
    return notes


def _images(path: Path, work: Path | None) -> dict:
    from estimator.plan_engine import images, ocr, pdf_pages

    out = images.read(path, work, _max_sheets(), ocr_words=ocr.available())
    sheets, extras = [], []
    for s in out["sheets"]:
        words = s.pop("_words", None) or []
        segments = s.pop("_segments", None) or []                # Sprint 16: the traced line work
        if not words and not segments:
            note = s.get("note")
            s["note"] = "; ".join(x for x in (note, ocr.status_note()) if x) or None     # nothing found: nothing to check
            if not s["note"]:
                s.pop("note")
            sheets.append(s)
            extras.append(None)
            continue
        page = pdf_pages.Page(page_no=s["page_no"], width=s["width"], height=s["height"], words=words,
                              lines=pdf_pages.group_lines(words), segments=segments, image_path=s["image_path"])
        sheet, e = _analyze(page, "raster")
        first = [s["note"]] if s.get("note") else []
        first.append("text read by OCR - check the sheet number and scale" if words else
                     (ocr.status_note() or "OCR found no words"))
        e["notes"][:0] = first + [RASTER_NOTE]
        sheets.append(sheet)
        extras.append(e)
    read = [(s, e) for s, e in zip(sheets, extras) if e is not None]
    entries = _finish([s for s, _ in read], [e for _, e in read], work) if read else []
    return {"page_count": out["page_count"], "sheets": sheets, "engine": ENGINE_NAME, "symbol_dictionary": entries}


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

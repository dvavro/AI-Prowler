"""Scans and photos of plans (PNG, JPG, TIFF): one sheet per image (or per TIFF page).

The paper size comes from the image's DPI when it has one (a scanner records it), otherwise 150 DPI is assumed and the
sheet says so. When Tesseract is installed (Sprint 9) the words are read too, so the engine finds the title block,
scale notes, schedules, legends and dimensions the same way as on a PDF; otherwise a person sets the scale from a note
or calibrates from two points on the image.

Sprint 16: each image goes through the raster pipeline first (raster.py): a photo's page is squared up, a blueprint is
turned the right way round, a tilted scan is straightened, and the line work is traced (under "_segments"), so walls and
rooms are found on scans too. The saved sheet image and the OCR words are the prepared ones, so boxes line up.
"""
from __future__ import annotations

from pathlib import Path

ASSUMED_DPI = 150
MAX_PIXELS = 20000 * 20000       # refuse decompression bombs, allow big E-size scans
EXIF_MAKE, EXIF_MODEL = 271, 272


def is_photo(img) -> bool:
    """Taken with a camera: the picture names the camera, or it's a JPEG with no DPI."""
    try:
        exif = img.getexif()
        if exif.get(EXIF_MAKE) or exif.get(EXIF_MODEL):
            return True
    except Exception:  # noqa: BLE001 - no EXIF
        pass
    return (img.format or "").upper() == "JPEG" and not img.info.get("dpi")


def read(path: Path, work: Path | None, max_sheets: int, ocr_words: bool = False) -> dict:
    """ocr_words=True adds each sheet's OCR words under "_words"; the traced line work is under "_segments" (the engine
    reads both and removes the keys)."""
    from PIL import Image, ImageSequence

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        img = Image.open(path)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"this image can't be opened ({exc})") from None
    sheets = []
    with img:
        photo = is_photo(img)
        frames = list(ImageSequence.Iterator(img))
        if len(frames) > max_sheets:
            raise ValueError(f"this image has {len(frames)} pages; a plan set can have at most {max_sheets}")
        for i, frame in enumerate(frames):
            dpi = frame.info.get("dpi") or img.info.get("dpi")
            try:
                dpi_x = float(dpi[0]) if dpi else 0.0
            except (TypeError, ValueError, IndexError):
                dpi_x = 0.0
            assumed = photo or not (30 <= dpi_x <= 2400)          # a camera's "72 DPI" says nothing about the page
            use_dpi = ASSUMED_DPI if assumed else dpi_x
            notes = []
            if photo:
                notes.append(f"a photo has no true size, so {ASSUMED_DPI} DPI was assumed; calibrate the scale")
            elif assumed:
                notes.append(f"the image has no DPI, so {ASSUMED_DPI} DPI was assumed; calibrate the scale")
            prep, segments = _prepare(frame, use_dpi, photo, notes)
            base = prep.image if prep is not None and prep.changed else frame
            w_px, h_px = base.size
            image_path = None
            if work is not None:
                out = Path(work) / f"sheet_{i + 1:03d}.png"
                rgb = base.convert("RGB")
                longest = max(w_px, h_px)
                if longest > 6000:                       # keep review images loadable on a phone
                    k = 6000 / longest
                    rgb = rgb.resize((max(1, int(w_px * k)), max(1, int(h_px * k))))
                rgb.save(out, "PNG", optimize=True)
                image_path = str(out)
            w_in, h_in = round(w_px / use_dpi, 3), round(h_px / use_dpi, 3)
            sheet = {"page_no": i + 1, "sheet_no": None, "title": None, "discipline": "other", "units": "paper_in",
                     "width": w_in, "height": h_in, "image_path": image_path, "confidence": 0.1,
                     "viewports": [{"key": "main", "label": None, "bbox": [0, 0, w_in, h_in],
                                    "scale_method": "none", "scale_confidence": 0}],
                     "_segments": segments}
            if notes:
                sheet["note"] = "; ".join(notes)
            if ocr_words:
                sheet["_words"] = _ocr(base, use_dpi)
            sheets.append(sheet)
    return {"page_count": len(sheets), "sheets": sheets}


def _prepare(frame, dpi: float, photo: bool, notes: list):
    """(raster.Prepared or None, traced line work). Without numpy/scipy the image is read as it is, and says so."""
    try:
        from estimator.plan_engine import raster
        prep = raster.prepare(frame, dpi, photo=photo)
    except ImportError as exc:
        notes.append(f"the line work wasn't traced ({exc})")
        return None, []
    notes += prep.notes
    return prep, prep.segments


def _ocr(frame, dpi: float) -> list:
    """The frame's words in sheet inches; a very large scan is read at a lower resolution."""
    from estimator.plan_engine import ocr

    img = frame.convert("L")
    longest = max(img.size)
    px_per_in = dpi
    if longest > ocr.MAX_OCR_PX:
        k = ocr.MAX_OCR_PX / longest
        img = img.resize((max(1, int(img.size[0] * k)), max(1, int(img.size[1] * k))))
        px_per_in = dpi * k
    return ocr.words_from_image(img, px_per_in)

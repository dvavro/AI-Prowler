"""Scans and photos of plans (PNG, JPG, TIFF): one sheet per image (or per TIFF page).

The paper size comes from the image's DPI when it has one (a scanner records it), otherwise 150 DPI is assumed and the
sheet says so. There's no scale: a person sets it from a note or calibrates from two points on the image. Reading text
from images (OCR) comes in a later sprint.
"""
from __future__ import annotations

from pathlib import Path

ASSUMED_DPI = 150
MAX_PIXELS = 20000 * 20000       # refuse decompression bombs, allow big E-size scans


def read(path: Path, work: Path | None, max_sheets: int) -> dict:
    from PIL import Image, ImageSequence

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        img = Image.open(path)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"this image can't be opened ({exc})") from None
    sheets = []
    with img:
        frames = list(ImageSequence.Iterator(img))
        if len(frames) > max_sheets:
            raise ValueError(f"this image has {len(frames)} pages; a plan set can have at most {max_sheets}")
        for i, frame in enumerate(frames):
            dpi = frame.info.get("dpi") or img.info.get("dpi")
            try:
                dpi_x = float(dpi[0]) if dpi else 0.0
            except (TypeError, ValueError, IndexError):
                dpi_x = 0.0
            assumed = not (30 <= dpi_x <= 2400)
            use_dpi = ASSUMED_DPI if assumed else dpi_x
            w_px, h_px = frame.size
            image_path = None
            if work is not None:
                out = Path(work) / f"sheet_{i + 1:03d}.png"
                rgb = frame.convert("RGB")
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
                                    "scale_method": "none", "scale_confidence": 0}]}
            if assumed:
                sheet["note"] = f"the image has no DPI, so {ASSUMED_DPI} DPI was assumed; calibrate the scale"
            sheets.append(sheet)
    return {"page_count": len(sheets), "sheets": sheets}

"""Tiles for the Blueprint Review viewer (Coder 2 Sprint 7: "tiled viewer").

The sheet image the plan engine saves is at most 4000 px on its long side, which is too soft to read small text on a
36" sheet when zoomed in. The viewer asks for 512 px square tiles instead, at a zoom level:

- level 0: the whole sheet fits one tile; each level doubles it (level L is 512 * 2**L px on the long side);
- a PDF sheet is rendered from the original page (pypdfium2, only the tile's part of the page), up to MAX_PDF_DPI;
- an image or DXF sheet is cut from its saved image, up to about its own size (zooming further only enlarges).

Tiles are in sheet units from the top-left, the same frame as the drawing model and the overlays: tile (x, y) at
level L covers [x * size, (x + 1) * size) across and the same down, where size = long side / 2**L. Edge tiles are
smaller. Rendered tiles are kept in the Estimator data folder (tiles/sheet<id>_<key>/), keyed by when the plans were
read, so reading the plans again never shows old tiles.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path

TILE = 512
MAX_PDF_DPI = 300
MAX_LEVEL = 8


def _size(sheet: dict) -> tuple[float, float]:
    try:
        w, h = float(sheet["width"]), float(sheet["height"])
    except (TypeError, ValueError, KeyError):
        raise ValueError("this sheet has no size yet; read the plans first") from None
    if not (w > 0 and h > 0):
        raise ValueError("this sheet has no size yet; read the plans first")
    return w, h


def _image_px(sheet: dict) -> int | None:
    path = sheet.get("image_path")
    if not path or not Path(path).is_file():
        return None
    from PIL import Image
    with Image.open(path) as img:
        return max(img.size)


def _is_pdf(sheet: dict, plan_set: dict) -> bool:
    return (plan_set.get("file_type") == "pdf" and sheet.get("units") == "paper_in"
            and bool(plan_set.get("file_path")) and Path(plan_set["file_path"]).is_file())


def info(sheet: dict, plan_set: dict) -> dict | None:
    """What the viewer needs to ask for tiles, or None when the sheet has nothing to show yet."""
    try:
        w, h = _size(sheet)
    except ValueError:
        return None
    if _is_pdf(sheet, plan_set):
        top = math.floor(math.log2(max(1.0, max(w, h) * MAX_PDF_DPI / TILE)))
        source = "pdf"
    else:
        px = _image_px(sheet)
        if not px:
            return None
        top = math.ceil(math.log2(max(1.0, px / TILE)))
        source = "image"
    return {"tile": TILE, "max_level": max(0, min(MAX_LEVEL, top)), "width": w, "height": h,
            "units": sheet.get("units"), "source": source}


def grid(width: float, height: float, level: int) -> tuple[int, int, float]:
    """(columns, rows, tile size in sheet units) at a level."""
    size = max(width, height) / (2 ** level)
    return math.ceil(width / size - 1e-9), math.ceil(height / size - 1e-9), size


def tile_box(width: float, height: float, level: int, x: int, y: int) -> tuple[float, float, float, float] | None:
    cols, rows, size = grid(width, height, level)
    if not (0 <= x < cols and 0 <= y < rows):
        return None
    x0, y0 = x * size, y * size
    return x0, y0, min(width, x0 + size), min(height, y0 + size)


def _cache_dir(sheet: dict, plan_set: dict, root: Path) -> Path:
    key = hashlib.sha1("|".join(str(v) for v in (plan_set.get("id"), plan_set.get("processed_at"),
                                                 sheet.get("image_path"), sheet.get("width"),
                                                 sheet.get("height"))).encode()).hexdigest()[:12]
    return Path(root) / "tiles" / f"sheet{int(sheet['id'])}_{key}"


def render(sheet: dict, plan_set: dict, level: int, x: int, y: int, root: Path) -> Path:
    """The PNG for one tile (rendered once, then served from the cache). Raises ValueError for a tile that doesn't
    exist (wrong level or position, or a sheet with nothing to show)."""
    meta = info(sheet, plan_set)
    if meta is None:
        raise ValueError("this sheet has no image yet; read the plans first")
    if not (0 <= int(level) <= meta["max_level"]):
        raise ValueError(f"zoom level must be 0 to {meta['max_level']}")
    w, h = meta["width"], meta["height"]
    box = tile_box(w, h, int(level), int(x), int(y))
    if box is None:
        raise ValueError("there's no tile there")
    out = _cache_dir(sheet, plan_set, root) / f"{int(level)}_{int(x)}_{int(y)}.png"
    if out.is_file():
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    x0, y0, x1, y1 = box
    px_per_unit = TILE / (max(w, h) / (2 ** int(level)))
    size_px = (max(1, round((x1 - x0) * px_per_unit)), max(1, round((y1 - y0) * px_per_unit)))
    if meta["source"] == "pdf":
        img = _pdf_tile(plan_set["file_path"], int(sheet["page_no"]), w, h, box, px_per_unit)
    else:
        img = _image_tile(sheet["image_path"], w, h, box)
    if img.size != size_px:
        img = img.resize(size_px)
    tmp = out.with_suffix(f".{os.getpid()}.tmp")
    img.convert("RGB").save(tmp, "PNG", optimize=True)
    os.replace(tmp, out)
    return out


def _pdf_tile(path: str, page_no: int, w: float, h: float, box, px_per_unit: float):
    """Render only the tile's part of the page. crop is (left, bottom, right, top) in points, applied after the
    page's /Rotate - the same turned frame as the sheet's size (checked against full renders, rotated pages too)."""
    import pypdfium2 as pdfium

    from estimator.plan_engine.pdf_pages import PDFIUM_LOCK

    x0, y0, x1, y1 = box
    with PDFIUM_LOCK:
        doc = pdfium.PdfDocument(str(path))
        try:
            page = doc[page_no - 1]
            try:
                crop = (x0 * 72, (h - y1) * 72, (w - x1) * 72, y0 * 72)
                return page.render(scale=px_per_unit / 72, crop=crop).to_pil().convert("RGB")   # a copy, in the lock
            finally:
                page.close()
        finally:
            doc.close()


def _image_tile(path: str, w: float, h: float, box):
    from PIL import Image

    x0, y0, x1, y1 = box
    with Image.open(path) as img:
        rx, ry = img.size[0] / w, img.size[1] / h
        return img.crop((round(x0 * rx), round(y0 * ry), max(round(x0 * rx) + 1, round(x1 * rx)),
                         max(round(y0 * ry) + 1, round(y1 * ry)))).copy()

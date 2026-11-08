"""Checking a plan file before it is attached to an estimate (spec: Blueprint processing, stage 1 "Upload and validate").

A file is accepted only when its contents match its type (a renamed .exe never passes as a .pdf), it isn't empty or
too big, and it isn't a password-protected PDF. Every refusal says why in plain words. The original is copied into the
Estimator's projects folder, so moving or deleting the file the user picked doesn't break the estimate.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from estimator import config
from estimator.errors import InvalidInput

MAX_BYTES = 300 * 1024 * 1024
EXTENSIONS = {".pdf": "pdf", ".png": "image", ".jpg": "image", ".jpeg": "image", ".tif": "image", ".tiff": "image",
              ".dxf": "dxf", ".dwg": "dwg"}
LOW_DPI = 150
SAFE_NAME = re.compile(r"[^A-Za-z0-9 _.()-]+")


def _magic_ok(file_type: str, ext: str, head: bytes) -> bool:
    if file_type == "pdf":
        return head.lstrip()[:5] == b"%PDF-"
    if file_type == "dwg":
        return head[:4] == b"AC10"
    if file_type == "dxf":
        if head.startswith(b"AutoCAD Binary DXF"):
            return True
        lines = [ln.strip() for ln in head[:400].decode("latin-1").splitlines() if ln.strip()]
        return len(lines) >= 2 and lines[0] == "0" and lines[1].upper() == "SECTION"
    if ext == ".png":
        return head[:8] == b"\x89PNG\r\n\x1a\n"
    if ext in (".jpg", ".jpeg"):
        return head[:3] == b"\xff\xd8\xff"
    if ext in (".tif", ".tiff"):
        return head[:4] in (b"II*\x00", b"MM\x00*")
    return False


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _pdf_encrypted(path: Path, size: int) -> bool:
    with open(path, "rb") as f:
        head = f.read(min(size, 2 * 1024 * 1024))
        f.seek(max(0, size - 2 * 1024 * 1024))
        tail = f.read()
    return b"/Encrypt" in head or b"/Encrypt" in tail


def _image_warnings(path: Path) -> list[str]:
    try:
        from PIL import Image          # optional; AI-Prowler usually has Pillow
    except ImportError:
        return []
    try:
        with Image.open(path) as im:
            dpi = im.info.get("dpi")
            width, height = im.size
    except Exception:
        raise InvalidInput("the image can't be opened; it may be damaged") from None
    out = []
    if dpi and min(float(dpi[0]), float(dpi[1])) < LOW_DPI:
        out.append(f"the image is {int(min(float(dpi[0]), float(dpi[1])))} DPI; under {LOW_DPI} DPI small text and "
                   "symbols may be hard to read")
    elif max(width, height) < 1500:
        out.append(f"the image is only {width}x{height} pixels; small text and symbols may be hard to read")
    return out


def check_file(file_path: str) -> dict:
    """Validate a plan file. Returns {path, name, file_type, size, sha256, warnings} or raises InvalidInput."""
    if not file_path or not str(file_path).strip():
        raise InvalidInput("give the full path of the plan file")
    path = Path(str(file_path).strip().strip('"')).expanduser()
    if not path.is_absolute():
        raise InvalidInput("give the full path of the plan file, e.g. C:\\Users\\you\\Documents\\plans.pdf")
    if not path.is_file():
        raise InvalidInput(f"there's no file at {path}")
    ext = path.suffix.lower()
    file_type = EXTENSIONS.get(ext)
    if file_type is None:
        raise InvalidInput(f"{ext or 'files without an extension'} can't be used; plans can be PDF, PNG, JPG, TIFF, "
                           "DXF or DWG", file=path.name)
    size = path.stat().st_size
    if size == 0:
        raise InvalidInput(f"{path.name} is empty", file=path.name)
    if size > MAX_BYTES:
        raise InvalidInput(f"{path.name} is {size // (1024 * 1024)} MB; the limit is {MAX_BYTES // (1024 * 1024)} MB. "
                           "Split the set or upload the sheets you need", file=path.name)
    with open(path, "rb") as f:
        head = f.read(4096)
    if not _magic_ok(file_type, ext, head):
        raise InvalidInput(f"{path.name} doesn't look like a real {ext[1:].upper()} file; it may be damaged or renamed",
                           file=path.name)
    warnings = []
    if file_type == "pdf" and _pdf_encrypted(path, size):
        raise InvalidInput(f"{path.name} is password-protected. Save an unlocked copy (Print to PDF works) and upload "
                           "that", file=path.name)
    if file_type == "image":
        warnings += _image_warnings(path)
    if file_type == "dwg":
        warnings.append("DWG needs a DWG-to-DXF converter installed on this PC before it can be processed")
    return {"path": path, "name": path.name, "file_type": file_type, "size": size, "sha256": _sha256(path),
            "warnings": warnings}


def plans_folder(estimate_id: int) -> Path:
    folder = config.data_dir() / "projects" / f"estimate_{int(estimate_id):04d}" / "plans"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def stored_name(plan_set_id: int, original: str) -> str:
    stem = SAFE_NAME.sub("_", Path(original).stem).strip(" ._") or "plans"
    return f"{int(plan_set_id)}_{stem[:80]}{Path(original).suffix.lower()}"

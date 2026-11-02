"""
desk_product_media.py — product photos for the customer page's 🛒 Shop (2026-11-02).

David: "we need to be able to show the products (pictures and specs)". Up to MAX_PHOTOS
pictures per product, made into JPEGs of at most SIDE px (no EXIF — phone photos carry
GPS), kept next to the page look in the Service Desk folder:

    <tickets root>/page/products/<product code>/<1..4>.jpg

The specs and the short description live with the product's other online settings
(booking_services.specs / .description in the Jobs database).
"""
from __future__ import annotations

import hashlib
import io
import re
from pathlib import Path

MAX_PHOTOS = 4
SIDE = 1200


def _folder(db_path: str, code: str) -> Path:
    import desk_db
    safe = code if re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", code or "") and code not in (".", "..") else \
        "x" + hashlib.sha256(str(code).encode("utf-8")).hexdigest()[:16]
    return desk_db.root_for(db_path) / "page" / "products" / safe


def make_photo(data: bytes) -> bytes:
    """Any picture → a JPEG at most SIDE px on its long side, no EXIF."""
    import desk_page_look as pl
    from PIL import Image
    img = pl._open(data).convert("RGB")          # size limit, HEIC, rotation as the page look does
    img.thumbnail((SIDE, SIDE), Image.Resampling.LANCZOS)
    out = io.BytesIO()
    img.save(out, "JPEG", quality=84, optimize=True, progressive=True)
    return out.getvalue()


def photos(db_path: str, code: str) -> list:
    """The photo numbers on file for a product, in order: [1, 2, …]."""
    d = _folder(db_path, code)
    if not d.exists():
        return []
    return sorted(int(p.stem) for p in d.glob("*.jpg") if p.stem.isdigit())


def add_photo(db_path: str, code: str, data: bytes) -> int:
    """Adds one photo at the end. Returns its number. DeskError when full or not a picture."""
    import desk_db
    have = photos(db_path, code)
    if len(have) >= MAX_PHOTOS:
        raise desk_db.DeskError(f"a product can have up to {MAX_PHOTOS} photos — remove one first")
    try:
        jpg = make_photo(data)
    except ValueError as e:
        raise desk_db.DeskError(str(e)) from e
    n = (have[-1] + 1) if have else 1
    d = _folder(db_path, code)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f"{n}.tmp"
    tmp.write_bytes(jpg)
    tmp.replace(d / f"{n}.jpg")
    return n


def remove_photo(db_path: str, code: str, n: int) -> None:
    """Removes one photo; the rest move up so they stay 1, 2, 3 …"""
    d = _folder(db_path, code)
    (d / f"{int(n)}.jpg").unlink(missing_ok=True)
    for i, old in enumerate(photos(db_path, code), start=1):
        if old != i:
            (d / f"{old}.jpg").replace(d / f"{i}.jpg")


def make_first(db_path: str, code: str, n: int) -> None:
    """The chosen photo becomes the one shown on the product's card."""
    d = _folder(db_path, code)
    have = photos(db_path, code)
    if int(n) not in have or int(n) == 1:
        return
    tmp = d / "swap.tmp"
    (d / "1.jpg").replace(tmp)
    (d / f"{int(n)}.jpg").replace(d / "1.jpg")
    tmp.replace(d / f"{int(n)}.jpg")


def photo_bytes(db_path: str, code: str, n: int) -> bytes | None:
    p = _folder(db_path, code) / f"{int(n)}.jpg"
    return p.read_bytes() if p.exists() else None


def photo_urls(db_path: str, code: str) -> list:
    """Addresses the customer page uses (/support-api/product/<code>/photo/<n>?v=<changed>)."""
    from urllib.parse import quote
    d = _folder(db_path, code)
    return [f"/support-api/product/{quote(code, safe='')}/photo/{n}?v={(d / f'{n}.jpg').stat().st_mtime_ns}"
            for n in photos(db_path, code)]

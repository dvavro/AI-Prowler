"""
desk_attachments.py — AI-Prowler Service Desk, Phase 1.

Turns an uploaded file (PWA camera shot, gallery photo, document, short
video, or a file Claude passes along) into a stored ticket attachment:

  photos     JPEG/PNG/HEIC/HEIF/WebP -> upright JPEG, longest side 2560 px,
             400 px thumbnail; HEIC converted (pillow-heif); GPS removed
             unless the caller keeps it (crew proof-of-service, Owner switch)
  documents  PDF, Word, Excel, PowerPoint, TXT, CSV — stored as-is
  video      MP4/MOV up to 100 MB — stored as-is

Limits (spec): 25 MB per photo or document, 100 MB per video, 500 MB per
ticket. Every stored file gets a SHA-256 for verify() and duplicate checks.
The permission check runs BEFORE anything is written, and the file is
removed again if the database refuses the record, so a refused upload
never leaves an orphan file behind.
"""
from __future__ import annotations

import datetime
import io
import mimetypes
import re
from pathlib import Path

import desk_db
import desk_files
import desk_rules as rules

PHOTO_EXT = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv"}
VIDEO_EXT = {".mp4", ".mov"}

MB = 1024 * 1024
MAX_FILE_BYTES = 25 * MB
MAX_VIDEO_BYTES = 100 * MB
MAX_TICKET_BYTES = 500 * MB
PHOTO_MAX_SIDE = 2560
THUMB_MAX_SIDE = 400
JPEG_QUALITY = 85


class AttachmentError(desk_db.DeskError):
    """The file was refused (type, size, unreadable image)."""


def classify(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in PHOTO_EXT:
        return "photo"
    if ext in DOC_EXT:
        return "document"
    if ext in VIDEO_EXT:
        return "video"
    allowed = ", ".join(sorted(PHOTO_EXT | DOC_EXT | VIDEO_EXT))
    raise AttachmentError(f"files of type {ext or '(none)'} are not accepted; allowed: {allowed}")


def _safe_stem(filename: str) -> str:
    stem = Path(filename).stem
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-._")
    return (stem or "file")[:60]


def _next_seq(folder: Path) -> int:
    best = 0
    if folder.exists():
        for p in folder.iterdir():
            m = re.match(r"(\d{4})_", p.name)
            if m:
                best = max(best, int(m.group(1)))
    return best + 1


def _open_image(data: bytes):
    from PIL import Image, ImageOps
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
    except Exception:  # noqa: BLE001 — HEIC simply won't open without it
        pass
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as e:  # noqa: BLE001
        raise AttachmentError(f"that photo could not be read ({type(e).__name__})") from e
    exif = img.getexif()
    try:
        sub_ifd = exif.get_ifd(0x8769)       # phones keep DateTimeOriginal here
    except Exception:  # noqa: BLE001
        sub_ifd = {}
    taken = sub_ifd.get(36867) or exif.get(36867) or exif.get(306)  # DateTimeOriginal / DateTime
    taken_at = None
    if taken:
        try:
            taken_at = datetime.datetime.strptime(str(taken), "%Y:%m:%d %H:%M:%S").isoformat()
        except ValueError:
            taken_at = None
    raw_exif = img.info.get("exif")
    img = ImageOps.exif_transpose(img)
    return img, taken_at, raw_exif


def _fit(img, side):
    from PIL import Image
    img = img.copy()
    img.thumbnail((side, side), Image.Resampling.LANCZOS)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    return img


def _gps_free_exif(raw_exif):
    """EXIF with the GPS block removed and orientation reset (pixels are
    already upright). None when there was no EXIF."""
    if not raw_exif:
        return None
    from PIL import Image
    ex = Image.Exif()
    ex.load(raw_exif)
    ex.pop(0x8825, None)       # GPSInfo
    ex[0x0112] = 1             # Orientation: normal
    return ex.tobytes()


def store_attachment(db_path: str, ticket_id: str, data: bytes, filename: str, *,
                     actor=None, edition: str = rules.BUSINESS, message_id: int | None = None,
                     visibility: str = "public", keep_gps: bool = False) -> dict:
    """Save one file into the ticket's attachments folder and record it.
    Returns the attachment row. keep_gps only applies to internal uploaders
    (customers and subcontractors always have GPS removed)."""
    kind = classify(filename)
    limit = MAX_VIDEO_BYTES if kind == "video" else MAX_FILE_BYTES
    if len(data) > limit:
        raise AttachmentError(f"{filename} is {len(data) / MB:.1f} MB; the limit for a "
                              f"{kind} is {limit // MB} MB")
    if not data:
        raise AttachmentError(f"{filename} is empty")

    # permission first — nothing is written for a caller who may not attach
    conn = desk_db.get_connection(db_path)
    try:
        row = desk_db._load_visible(conn, ticket_id, actor, edition)
        used = conn.execute("SELECT COALESCE(SUM(bytes), 0) FROM ticket_attachments "
                            "WHERE ticket_id = ?", (ticket_id,)).fetchone()[0]
    finally:
        conn.close()
    d = rules.can(actor, "attach", row, edition=edition)
    if not d:
        raise desk_db.DeskError(d.reason)
    if used + len(data) > MAX_TICKET_BYTES:
        raise AttachmentError(f"{ticket_id} already holds {used / MB:.0f} MB of files; "
                              f"the limit per ticket is {MAX_TICKET_BYTES // MB} MB")
    if rules.is_external(actor):
        keep_gps = False

    folder = desk_files.ticket_folder(desk_db.root_for(db_path), row) / desk_files.ATTACHMENTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    seq = _next_seq(folder)
    stem = _safe_stem(filename)
    written: list[Path] = []
    info = {"kind": kind, "taken_at": None, "thumb_path": None}
    try:
        if kind == "photo":
            img, taken_at, raw_exif = _open_image(data)
            exif = raw_exif if keep_gps else _gps_free_exif(raw_exif)
            name = f"{seq:04d}_{stem}.jpg"
            full = _fit(img, PHOTO_MAX_SIDE)
            buf = io.BytesIO()
            kw = {"quality": JPEG_QUALITY, "optimize": True}
            if exif:
                kw["exif"] = exif
            full.save(buf, "JPEG", **kw)
            out = buf.getvalue()
            (folder / name).write_bytes(out)
            written.append(folder / name)
            thumb = f"{seq:04d}_{stem}_thumb.jpg"
            tb = io.BytesIO()
            _fit(img, THUMB_MAX_SIDE).save(tb, "JPEG", quality=80)
            (folder / thumb).write_bytes(tb.getvalue())
            written.append(folder / thumb)
            info.update(filename=name, mime="image/jpeg", taken_at=taken_at,
                        thumb_path=f"{desk_files.ATTACHMENTS_DIR}/{thumb}")
        else:
            ext = Path(filename).suffix.lower()
            name = f"{seq:04d}_{stem}{ext}"
            (folder / name).write_bytes(data)
            written.append(folder / name)
            info.update(filename=name,
                        mime=mimetypes.guess_type(name)[0] or "application/octet-stream")
        stored = folder / info["filename"]
        info["path"] = f"{desk_files.ATTACHMENTS_DIR}/{info['filename']}"
        info["bytes"] = stored.stat().st_size
        info["sha256"] = desk_files.sha256_file(stored)
        return desk_db.add_attachment(db_path, ticket_id, info, actor=actor, edition=edition,
                                      message_id=message_id, visibility=visibility)
    except Exception:
        for p in written:
            try:
                p.unlink()
            except OSError:
                pass
        raise

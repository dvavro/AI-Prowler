"""
desk_page_look.py — the look of the customer pages (David 2026-10-30): "add a user configurable
(icon and web background) for the booking and scheduling web form page and also the service
ticket processing web form."

One look for every customer page: the booking / request form (/book, /support/new) and the
ticket status page (/support/t/<token>), which are the same page (desk/support.html).

  • Icon        — the business's logo or icon, shown at the top of the page and used as the
                  browser-tab and home-screen icon. Any picture → a 256 px square PNG (kept
                  transparent, padded not cropped), no EXIF.
  • Background  — Plain (the standard light grey) · a colour · a picture. A picture becomes a
                  JPEG of at most 1920 px, no EXIF. The form cards stay white, so text stays
                  readable on any background.
  • Accent      — the colour of buttons, links and the chosen times. It must be dark enough for
                  white button text (contrast ≥ 3:1).

Files live under <tickets root>/page/. Settings: page_logo, page_bg_mode, page_bg_color,
page_background, page_accent (desk_db.SETTING_DEFAULTS). Set in AI-Prowler → Service Desk →
🌐 Web forms → Page look. No module-level import of desk_db (desk_db imports this file).
"""
from __future__ import annotations

import io
import re
from pathlib import Path

LOGO_REL = "page/logo.png"
BG_REL = "page/background.jpg"
LOGO_SIDE = 256
BG_MAX_SIDE = 1920
MAX_BYTES = 12 * 1024 * 1024
BG_MODES = ("plain", "color", "picture")
DEFAULT_BG = "#f6f7fb"
DEFAULT_ACCENT = "#0b7fab"
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")

DEFAULTS = {
    "page_logo": "",                  # "" or LOGO_REL (set by set_logo)
    "page_bg_mode": "plain",          # plain | color | picture
    "page_bg_color": DEFAULT_BG,
    "page_background": "",            # "" or BG_REL (set by set_background)
    "page_accent": DEFAULT_ACCENT,
}
CHOICES = {"page_logo": ("", LOGO_REL), "page_background": ("", BG_REL), "page_bg_mode": BG_MODES}

HELP = {
    "logo": ("Your logo or icon. It shows at the top of the customer pages (booking, requests and the ticket "
             "status page) and as the icon on the browser tab and phone home screen. Square pictures look best; "
             "others are padded, never cropped."),
    "background": ("Behind the page: the standard light grey, a colour you pick, or a picture (a photo of your "
                   "work, your van…). The form itself stays on white cards, so it's always easy to read."),
    "accent": ("The colour of buttons, links and the times a customer picks. It has to be dark enough for white "
               "writing on the buttons."),
}


# ── colours ──────────────────────────────────────────────────────────────────

def _lum(hex_: str) -> float:
    def ch(c):
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def validate(key: str, value, edition: str | None = None) -> None:
    """Extra checks for page_* settings (desk_db does the type check). Raises ValueError."""
    if key in CHOICES and value not in CHOICES[key]:
        raise ValueError(f"{key} must be one of: {', '.join(repr(c) for c in CHOICES[key])}")
    if key in ("page_bg_color", "page_accent"):
        if not HEX.match(str(value)):
            raise ValueError(f"{key} must be a colour like #0b7fab")
        if key == "page_accent" and contrast(value, "#ffffff") < 3.0:
            raise ValueError("that accent colour is too light for white button text — pick a darker one")


def text_on(bg_hex: str) -> str:
    """Dark or light text for the page heading on a plain colour background."""
    return "#1a1d29" if contrast(bg_hex, "#1a1d29") >= contrast(bg_hex, "#ffffff") else "#ffffff"


# ── pictures ─────────────────────────────────────────────────────────────────

def _open(data: bytes):
    if not data:
        raise ValueError("the file is empty")
    if len(data) > MAX_BYTES:
        raise ValueError(f"the picture is too big (max {MAX_BYTES // (1024 * 1024)} MB)")
    from PIL import Image, ImageOps, UnidentifiedImageError
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
    except Exception:  # noqa: BLE001 — HEIC is a bonus
        pass
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError) as e:
        raise ValueError("that file isn't a picture we can read (use JPG, PNG, WebP or HEIC)") from e
    return ImageOps.exif_transpose(img)


def make_logo(data: bytes) -> bytes:
    """Any picture → a 256 px square PNG: fitted inside (padded with transparency), no EXIF."""
    from PIL import Image
    img = _open(data).convert("RGBA")
    img.thumbnail((LOGO_SIDE, LOGO_SIDE), Image.Resampling.LANCZOS)
    square = Image.new("RGBA", (LOGO_SIDE, LOGO_SIDE), (0, 0, 0, 0))
    square.paste(img, ((LOGO_SIDE - img.width) // 2, (LOGO_SIDE - img.height) // 2), img)
    out = io.BytesIO()
    square.save(out, "PNG", optimize=True)
    return out.getvalue()


def make_background(data: bytes) -> bytes:
    """Any picture → a JPEG of at most 1920 px on its long side, no EXIF."""
    from PIL import Image
    img = _open(data).convert("RGB")
    img.thumbnail((BG_MAX_SIDE, BG_MAX_SIDE), Image.Resampling.LANCZOS)
    out = io.BytesIO()
    img.save(out, "JPEG", quality=82, optimize=True, progressive=True)
    return out.getvalue()


def _root(db_path: str) -> Path:
    import desk_db
    return desk_db.root_for(db_path)


def _owner_only(actor, edition):
    import desk_db
    import desk_rules as rules
    desk_db._check(rules.can(actor, "manage_settings", edition=edition))


def _save(db_path: str, rel: str, data: bytes) -> None:
    p = _root(db_path) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(p)


def set_logo(db_path: str, data: bytes, *, actor=None, edition: str = "business") -> dict:
    import desk_db
    _owner_only(actor, edition)
    try:
        png = make_logo(data)
    except ValueError as e:
        raise desk_db.DeskError(str(e)) from e
    _save(db_path, LOGO_REL, png)
    return desk_db.set_setting(db_path, "page_logo", LOGO_REL, actor=actor, edition=edition)


def clear_logo(db_path: str, *, actor=None, edition: str = "business") -> dict:
    import desk_db
    _owner_only(actor, edition)
    (_root(db_path) / LOGO_REL).unlink(missing_ok=True)
    return desk_db.set_setting(db_path, "page_logo", "", actor=actor, edition=edition)


def set_background(db_path: str, data: bytes, *, actor=None, edition: str = "business") -> dict:
    import desk_db
    _owner_only(actor, edition)
    try:
        jpg = make_background(data)
    except ValueError as e:
        raise desk_db.DeskError(str(e)) from e
    _save(db_path, BG_REL, jpg)
    desk_db.set_setting(db_path, "page_background", BG_REL, actor=actor, edition=edition)
    return desk_db.set_setting(db_path, "page_bg_mode", "picture", actor=actor, edition=edition)


def clear_background(db_path: str, *, actor=None, edition: str = "business") -> dict:
    import desk_db
    _owner_only(actor, edition)
    (_root(db_path) / BG_REL).unlink(missing_ok=True)
    s = desk_db.set_setting(db_path, "page_background", "", actor=actor, edition=edition)
    if s.get("page_bg_mode") == "picture":
        s = desk_db.set_setting(db_path, "page_bg_mode", "plain", actor=actor, edition=edition)
    return s


def file_bytes(db_path: str, which: str) -> tuple[bytes, str] | None:
    """(data, mime) for 'logo' / 'background', or None when not set."""
    import desk_db
    s = desk_db.get_settings(db_path)
    rel, key, mime = {"logo": (LOGO_REL, "page_logo", "image/png"),
                      "background": (BG_REL, "page_background", "image/jpeg")}[which]
    if s.get(key) != rel:
        return None
    p = _root(db_path) / rel
    return (p.read_bytes(), mime) if p.exists() else None


def public_look(db_path: str) -> dict:
    """What the customer page needs (/support-api/info → look)."""
    import desk_db
    s = desk_db.get_settings(db_path)
    root = _root(db_path)

    def url(rel, key, route):
        p = root / rel
        if s.get(key) != rel or not p.exists():
            return ""
        return f"/support-api/page/{route}?v={int(p.stat().st_mtime)}"
    mode = s.get("page_bg_mode") or "plain"
    bg_url = url(BG_REL, "page_background", "background")
    if mode == "picture" and not bg_url:
        mode = "plain"
    color = s.get("page_bg_color") or DEFAULT_BG
    return {"logo_url": url(LOGO_REL, "page_logo", "logo"), "bg_mode": mode,
            "bg_color": color if mode == "color" else DEFAULT_BG,
            "bg_url": bg_url if mode == "picture" else "", "accent": s.get("page_accent") or DEFAULT_ACCENT,
            "heading_color": text_on(color) if mode == "color" else "#1a1d29"}

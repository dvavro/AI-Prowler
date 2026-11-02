"""The customer pages' look (2026-10-30): icon, background and accent — desk_page_look,
its /support-api routes, the page's applyLook and AI-Prowler's Page look section.
Run: run_tests.bat tests\\unit\\test_desk_page_look.py
"""
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_db  # noqa: E402
import desk_page_look as pl  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402


def png(w, h, color=(200, 30, 30, 255)):
    out = io.BytesIO()
    Image.new("RGBA", (w, h), color).save(out, "PNG")
    return out.getvalue()


def jpg(w, h):
    out = io.BytesIO()
    Image.new("RGB", (w, h), (20, 120, 200)).save(out, "JPEG")
    return out.getvalue()


@pytest.fixture
def db(tmp_path):
    d = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(d)
    desk_db.set_setting(d, "portal_enabled", True, edition=r.SOLO)
    p.channels_fn = lambda: {"email": True, "sms": False}
    yield d
    p.channels_fn = None


def info(db):
    st, ct, out = p.route("GET", "/support-api/info", query={}, body=b"", content_type="", ip="1.1.1.1",
                          db_path=db, edition=r.SOLO, base_url="https://x", business="Blue Wave")
    return json.loads(out)["look"]


def get(db, path):
    return p.route("GET", "/support-api" + path, query={}, body=b"", content_type="", ip="1.1.1.1",
                   db_path=db, edition=r.SOLO, base_url="https://x", business="Blue Wave")


def test_defaults_are_the_standard_look(db):
    look = info(db)
    assert look == {"logo_url": "", "bg_mode": "plain", "bg_color": pl.DEFAULT_BG, "bg_url": "",
                    "accent": pl.DEFAULT_ACCENT, "heading_color": "#1a1d29"}
    assert get(db, "/page/logo")[0] == 404


def test_icon_is_made_square_and_served(db):
    pl.set_logo(db, png(400, 100), edition=r.SOLO)
    look = info(db)
    assert look["logo_url"].startswith("/support-api/page/logo?v=")
    st, ct, data = get(db, "/page/logo")
    img = Image.open(io.BytesIO(data))
    assert st == 200 and ct == b"image/png" and img.size == (256, 256)
    assert img.getpixel((128, 2))[3] == 0 and img.getpixel((128, 128))[3] == 255   # padded, not cropped
    pl.clear_logo(db, edition=r.SOLO)
    assert info(db)["logo_url"] == "" and get(db, "/page/logo")[0] == 404


def test_background_picture_and_colour(db):
    pl.set_background(db, jpg(4000, 2000), edition=r.SOLO)
    look = info(db)
    assert look["bg_mode"] == "picture" and look["bg_url"].startswith("/support-api/page/background")
    st, ct, data = get(db, "/page/background")
    assert st == 200 and ct == b"image/jpeg" and max(Image.open(io.BytesIO(data)).size) == 1920
    pl.clear_background(db, edition=r.SOLO)
    assert info(db)["bg_mode"] == "plain"
    desk_db.set_setting(db, "page_bg_color", "#0B3D5C", edition=r.SOLO)
    desk_db.set_setting(db, "page_bg_mode", "color", edition=r.SOLO)
    look = info(db)
    assert look["bg_color"] == "#0b3d5c" and look["heading_color"] == "#ffffff"   # dark colour → light heading


def test_colours_are_checked(db):
    with pytest.raises(desk_db.DeskError, match="too light"):
        desk_db.set_setting(db, "page_accent", "#ffee88", edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="colour like"):
        desk_db.set_setting(db, "page_bg_color", "blue", edition=r.SOLO)
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(db, "page_bg_mode", "video", edition=r.SOLO)
    desk_db.set_setting(db, "page_accent", "#7A1F5C", edition=r.SOLO)
    assert info(db)["accent"] == "#7a1f5c"
    with pytest.raises(desk_db.DeskError, match="isn't a picture"):
        pl.set_logo(db, b"not a picture", edition=r.SOLO)


def test_only_the_owner_changes_it(db):
    with pytest.raises(desk_db.DeskError):
        pl.set_logo(db, png(64, 64), actor={"id": "sam", "role": "staff"}, edition=r.BUSINESS)


def test_ai_prowler_page_look_section(db, tmp_path):
    import desk_gui_settings as g
    f = tmp_path / "logo.png"
    f.write_bytes(png(64, 64))
    ok, msg = g.save_look(db, "solo", logo_file=str(f))
    assert ok and g.look_status(db)["logo"]
    ok, msg = g.save_look(db, "solo", bg_mode="picture")
    assert not ok and "picture first" in msg
    ok, msg = g.save_look(db, "solo", accent="#ffffff")
    assert not ok and "too light" in msg
    ok, msg = g.save_look(db, "solo", bg_color="#e8f4f8", bg_mode="color")
    assert ok and g.look_status(db)["bg_mode"] == "color"
    assert "_build_look(app, f, db, edition)" in Path(g.__file__).read_text(encoding="utf-8")


def test_the_page_applies_the_look():
    html = (ROOT / "desk" / "support.html").read_text(encoding="utf-8")
    assert "function applyLook(L)" in html and "applyLook(i.look)" in html
    assert 'id="logo"' in html and "rel=\"apple-touch-icon\"" in html

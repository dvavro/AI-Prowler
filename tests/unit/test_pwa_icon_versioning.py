"""
App icons are served under versioned addresses (2026-10-28).

The Service Desk icon changed (b0da7ec) but David's iPhone kept showing the
old picture, even after deleting the home-screen icon and all Safari website
data: Cloudflare's edge, Safari and iOS's own home-screen icon cache all key
the icon by its address, and /desk/icon-192.png never changed. Every icon*.png
a served page or manifest references now carries ?v=<hash of that file>, so a
new picture is a new address everywhere. The customer page (/support/...) also
had no icon at all, so iOS made one from a snapshot of the page.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

APPS = ["jobs", "remote", "desk", "hr_admin", "hr_portal"]
VREF = re.compile(rb"icon(?:-\d+)?\.png(\?v=[0-9a-f]{8})?")


@pytest.fixture(scope="module")
def mcp():
    return pytest.importorskip("ai_prowler_mcp")


def _h8(p: Path) -> bytes:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:8].encode()


def test_page_icon_links_get_the_files_hash(mcp, tmp_path):
    (tmp_path / "icon-192.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"pic-1")
    page = (b'<link rel="icon" href="/desk/icon-192.png">'
            b'<link rel="apple-touch-icon" href="/desk/icon-192.png">')
    out = mcp._version_pwa_icons(str(tmp_path), page)
    want = b"icon-192.png?v=" + _h8(tmp_path / "icon-192.png")
    assert out.count(want) == 2
    assert mcp._version_pwa_icons(str(tmp_path), out) == out          # applying twice changes nothing


def test_a_new_picture_is_a_new_address(mcp, tmp_path):
    ico = tmp_path / "icon-192.png"
    page = b'<link rel="apple-touch-icon" href="/desk/icon-192.png">'
    ico.write_bytes(b"\x89PNG\r\n\x1a\nold")
    old = mcp._version_pwa_icons(str(tmp_path), page)
    ico.write_bytes(b"\x89PNG\r\n\x1a\nnew picture")                   # size and time change
    new = mcp._version_pwa_icons(str(tmp_path), page)
    assert old != new and b"?v=" + _h8(ico) in new


def test_manifest_icons_are_versioned(mcp, tmp_path):
    (tmp_path / "icon-512.png").write_bytes(b"\x89PNG\r\n\x1a\n512")
    man = json.dumps({"icons": [{"src": "/desk/icon-512.png", "sizes": "512x512"}]}).encode()
    out = json.loads(mcp._version_pwa_icons(str(tmp_path), man))
    assert out["icons"][0]["src"] == "/desk/icon-512.png?v=" + _h8(tmp_path / "icon-512.png").decode()


def test_leaves_other_things_alone(mcp, tmp_path):
    (tmp_path / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\nx")
    png = b"\x89PNG\r\n\x1a\n...icon.png'..."
    assert mcp._version_pwa_icons(str(tmp_path), png) == png            # an icon file itself
    other = b'<link href="/favicon.png"><img src="/x/icon-999.png">'
    assert mcp._version_pwa_icons(str(tmp_path), other) == other        # not ours / no such file


@pytest.mark.parametrize("app", APPS)
def test_every_app_serves_versioned_icons(mcp, app):
    root = ROOT / app
    page = mcp._patch_sw_cache_version("index.html", str(root), (root / "index.html").read_bytes())
    refs = VREF.findall(page)
    assert refs, f"{app}/index.html references no icon"
    assert all(refs), f"{app}: an icon reference was served without ?v="
    assert b"icon-192.png?v=" + _h8(root / "icon-192.png") in page
    for man in root.glob("*manifest.json"):
        served = mcp._patch_sw_cache_version(man.name, str(root), man.read_bytes())
        for ic in json.loads(served)["icons"]:
            assert "?v=" in ic["src"], (app, man.name, ic)


def test_service_worker_version_changes_with_the_icon(mcp, tmp_path):
    (tmp_path / "index.html").write_bytes(b'<link rel="apple-touch-icon" href="/desk/icon-192.png">')
    (tmp_path / "icon-192.png").write_bytes(b"\x89PNG\r\n\x1a\nA")
    sw = b"const CACHE = 'auto';"
    a = mcp._compute_pwa_sw_cache_version(str(tmp_path), sw)
    (tmp_path / "icon-192.png").write_bytes(b"\x89PNG\r\n\x1a\nB-new")
    assert mcp._compute_pwa_sw_cache_version(str(tmp_path), sw) != a     # update banner fires


def test_customer_page_has_an_icon_and_the_server_versions_it():
    html = (ROOT / "desk" / "support.html").read_text(encoding="utf-8")
    assert '<link rel="apple-touch-icon" href="/desk/icon-192.png">' in html
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("async def _desk_portal(")
    assert "_version_pwa_icons(" in src[i:i + 900]

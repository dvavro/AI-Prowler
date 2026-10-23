"""
2026-10-22 (David): jobs/index.html had TWO copies of Cloudflare's Web
Analytics beacon (<script ... static.cloudflareinsights.com/beacon.min.js ...>)
at the end of the file — since the 2026-10-11 "pre-merge snapshot" commit. They
came from saving the page AS SERVED through the Cloudflare tunnel back into the
source: Cloudflare adds that tag itself to every page it serves (when Web
Analytics is on for the domain), so a saved copy carries it, and a second save
added another. Every page then loaded the beacon two or three times (double
counting) with a pinned, eventually stale script version.

The source must never contain anything Cloudflare (or any CDN) injects — it
adds its own at serve time. This guards every web app AI-Prowler ships.

Run: run_tests.bat tests\\unit\\test_no_cdn_injected_scripts.py -v
"""
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
PAGES = sorted(p for p in _SRC.glob("*/index.html") if ".bak" not in p.name)
INJECTED = ("static.cloudflareinsights.com", "data-cf-beacon", "/cdn-cgi/", "rocket-loader")


def test_the_shipped_web_apps_are_found():
    names = {p.parent.name for p in PAGES}
    assert {"jobs", "remote", "hr_admin", "hr_portal"} <= names, names


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.parent.name)
def test_no_cdn_injected_tags_in_the_source(page):
    text = page.read_text(encoding="utf-8", errors="replace")
    for marker in INJECTED:
        assert marker not in text, f"{page.parent.name}/index.html contains '{marker}' — " \
                                   "a copy of the page as served by Cloudflare was saved into the source"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.parent.name)
def test_nothing_follows_the_closing_html(page):
    # (a page may hold "</html>" inside JS print templates; the real one is last)
    text = page.read_text(encoding="utf-8", errors="replace")
    assert text.rstrip().endswith("</html>")

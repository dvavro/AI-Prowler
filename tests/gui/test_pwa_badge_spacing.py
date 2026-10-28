"""The version badge must not sit on top of anything you tap (David 2026-10-28:
"on the jobs app the version number and the refresh selection are on top of
each other. We need a little bit space between them" — seen on an iPhone).

Each app page is opened straight from disk in a phone and a desktop window, the
signed-in screen and the "new version — Refresh Now" banner are shown, the
badge gets a full-length label, and every visible button, link and the banner
must keep at least GAP px clear of it. Badge and top bars are both placed from
the top safe-area inset, so the gap measured here is the same on a notched
iPhone.

Run: run_tests.bat tests\\gui\\test_pwa_badge_spacing.py -v
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
APPS = ["jobs", "desk", "remote", "hr_admin", "hr_portal"]
GAP = 4

SHOW_JS = """() => {
  for (const id of ['authScreen', 'auth-screen', 'loginScreen', 'login']) {
    const e = document.getElementById(id); if (e) { e.style.display = 'none'; e.classList.add('hidden'); }
  }
  const app = document.getElementById('app'); if (app) app.style.display = 'flex';
  for (const id of ['refreshBtn', 'signOutBtn', 'bell', 'tabs']) { const e = document.getElementById(id); if (e) e.classList.remove('hide'); }
  for (const id of ['updateBanner', 'update-banner']) {
    const e = document.getElementById(id); if (e) { e.classList.add('show'); e.classList.remove('hidden'); e.style.display = 'flex'; }
  }
  const b = document.getElementById('apPwaVer');
  b.textContent = 'v9.6.0 · a1b2c3 ✓ latest';           // the longest label it shows
  const r = b.getBoundingClientRect(), g = %d, out = [];
  for (const e of document.querySelectorAll('button, a, .conn-dot, [onclick], #updateBanner, #update-banner')) {
    if (e === b || b.contains(e)) continue;
    const s = getComputedStyle(e), q = e.getBoundingClientRect();
    if (!q.width || !q.height || s.visibility === 'hidden' || s.display === 'none' || +s.opacity === 0) continue;
    if (q.bottom < 0 || q.top > 200) continue;                       // only the top of the screen
    if (q.left < r.right + g && q.right > r.left - g && q.top < r.bottom + g && q.bottom > r.top - g)
      out.push((e.id || e.className || e.tagName) + ' "' + (e.textContent || '').trim().slice(0, 24) + '" '
               + [q.left, q.top, q.right, q.bottom].map(Math.round).join(','));
  }
  return {badge: [r.left, r.top, r.right, r.bottom].map(Math.round), clash: out};
}""" % GAP


@pytest.fixture(scope="module")
def pw():
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"playwright not installed: {e}")
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield p, b
        b.close()


@pytest.mark.parametrize("device", ["iPhone 13", "Pixel 7", "desktop"])
@pytest.mark.parametrize("app", APPS)
def test_badge_keeps_clear_of_buttons(pw, app, device):
    p, browser = pw
    page_file = ROOT / app / "index.html"
    if not page_file.exists():
        pytest.skip(f"no {app}/index.html")
    opts = p.devices[device] if device != "desktop" else {"viewport": {"width": 1280, "height": 800}}
    ctx = browser.new_context(**opts)
    try:
        pg = ctx.new_page()
        pg.route("http*://**", lambda r: r.abort())          # opened from disk: no network
        pg.goto(page_file.as_uri())
        pg.wait_for_timeout(300)
        res = pg.evaluate(SHOW_JS)
        assert not res["clash"], f"{app} on {device}: version badge {res['badge']} is on top of {res['clash']}"
    finally:
        ctx.close()

"""PWA behaviour (spec §6.10) — the service worker, build detection, offline.

These are the ONLY tests that let the Jobs app's service worker run (every
other test blocks it: requests made by a service worker slip past the
page-level write guard, R-015). To stay safe they never log in: the login
screen makes no /pwa-api calls at all, and the page fixture's bypass alarm
still fails the test if a single /pwa-api request leaves the browser.

PWA-01  the service worker registers and controls the page after a reload
PWA-02  build detection: the cache name the server puts into sw.js is the
        content hash of the sw.js / index.html / manifest.json it is serving
        RIGHT NOW (recomputed here from the served files) — so any deploy
        that changes index.html gets a new cache name, which is what makes an
        installed app pick the new build up; and the installed worker's cache
        holds exactly the index.html being served
PWA-03  offline: with the network cut, a reload still shows the app (login
        screen) from the cache

Run: run_tests_gui_jobs_e2e.bat --human -k test_pwa_behavior
"""
import hashlib
import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.no_login


@pytest.fixture
def browser_context_args(browser_context_args):
    return {**browser_context_args, "service_workers": "allow"}


def _get(page, url) -> bytes:
    r = page.request.get(url)
    assert r.ok, f"GET {url} -> {r.status}"
    return r.body()


def _served_cache_name(page, app_url):
    sw = _get(page, app_url + "sw.js")
    m = re.search(rb"const CACHE = '([^']*)';", sw)
    assert m, "sw.js has no CACHE line"
    return sw, m.group(1).decode()


def _controlled(page, app_url):
    """Open the login screen and wait until the service worker controls the page."""
    page.goto(app_url, wait_until="domcontentloaded")
    expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)
    page.evaluate("() => navigator.serviceWorker.ready")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_function("() => !!navigator.serviceWorker.controller", timeout=30_000)
    expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)


def test_PWA_01_service_worker_registers_and_controls(page, app_url):
    _controlled(page, app_url)
    scope = page.evaluate("async () => (await navigator.serviceWorker.getRegistration()).scope")
    assert scope.rstrip("/").endswith("/jobs"), f"unexpected service-worker scope: {scope}"
    assert page.evaluate("() => navigator.serviceWorker.controller.scriptURL").endswith("/jobs/sw.js")


def test_PWA_02_cache_name_tracks_the_served_build(page, app_url):
    sw, name = _served_cache_name(page, app_url)
    assert name != "auto" and re.fullmatch(r"[0-9a-f]{12}", name), f"cache name not a build hash: {name!r}"
    index = _get(page, app_url + "index.html")
    manifest = _get(page, app_url + "manifest.json")
    raw_sw = sw.replace(f"const CACHE = '{name}';".encode(), b"const CACHE = 'auto';", 1)
    expected = hashlib.sha256(raw_sw + index + manifest).hexdigest()[:12]
    assert name == expected, (f"sw.js cache name {name} isn't the hash of the files being served ({expected}) — "
                              "a deploy might not be detected")
    assert _served_cache_name(page, app_url)[1] == name, "cache name changes between two requests"
    _controlled(page, app_url)
    keys = page.evaluate("() => caches.keys()")
    assert name in keys, f"installed worker's caches {keys} don't include the served build {name}"
    cached = page.evaluate("""async n => {
        const c = await caches.open(n);
        const r = (await c.match('/jobs/index.html')) || (await c.match('/jobs/'));
        return r ? await r.text() : null; }""", name)
    assert cached is not None, "index.html isn't in the installed cache"
    assert hashlib.sha256(cached.encode()).hexdigest() == hashlib.sha256(index.decode().encode()).hexdigest(), \
        "the installed cache holds a different index.html than the one being served"


def test_PWA_03_offline_shell_loads(page, app_url):
    _controlled(page, app_url)
    page.context.set_offline(True)
    try:
        page.reload(wait_until="domcontentloaded")
        expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)
        expect(page.locator("#authCode")).to_be_visible()
    finally:
        page.context.set_offline(False)

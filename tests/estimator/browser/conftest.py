"""Estimator browser tests (Playwright, Chromium) - Coder 2 / Tester 2.

They run only on the browser track, so the normal Estimator runs stay fast and never open a browser:

    run_tests_estimator.bat browser            headless
    run_tests_estimator.bat browser --human    visible browser, slowed down, to watch it like a person

Each test gets the usual throwaway data folder (tests/estimator/conftest.py) and its own Estimator web server on a free
port, on this PC (same-PC sign-in = owner). Skipped when Playwright or its Chromium isn't installed.
"""
import os
import sys
from pathlib import Path

import pytest

HUMAN = os.environ.get("ESTIMATOR_BROWSER_HUMAN") == "1"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))


def pytest_collection_modifyitems(config, items):
    if os.environ.get("ESTIMATOR_BROWSER") == "1":
        return
    skip = pytest.mark.skip(reason="browser test: run with run_tests_estimator.bat browser")
    for item in items:
        if "tests" + os.sep + "estimator" + os.sep + "browser" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture(scope="module")
def browser():
    if os.environ.get("ESTIMATOR_BROWSER") != "1":
        pytest.skip("browser test: run with run_tests_estimator.bat browser")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("Playwright isn't installed (pip install playwright; python -m playwright install chromium)")
    pw = sync_playwright().start()
    try:
        b = pw.chromium.launch(headless=not HUMAN, slow_mo=250 if HUMAN else 0)
    except Exception as e:  # noqa: BLE001
        pw.stop()
        pytest.skip(f"Chromium for Playwright isn't installed ({e})")
    yield b
    b.close()
    pw.stop()


@pytest.fixture
def site(estimator_sandbox, monkeypatch):
    """The Estimator web server for this test; returns its base URL (http://localhost:<port>/estimator/)."""
    from estimator.api import server
    from estimator.drawing_model import engine
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    base = server.start(port=0, host="127.0.0.1").replace("127.0.0.1", "localhost")
    yield base
    server.stop()
    engine.clear_engine()


@pytest.fixture
def page(browser, site):
    yield from _watched_page(browser, site, viewport={"width": 1400, "height": 950})


@pytest.fixture
def phone(browser, site):
    """A phone-sized touch screen (Sprint 13 mobile reviews): 390 x 844, touch, mobile."""
    yield from _watched_page(browser, site, viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True,
                             device_scale_factor=2)


def _watched_page(browser, site, **context_args):
    ctx = browser.new_context(**context_args)
    pg = ctx.new_page()
    pg.set_default_timeout(15000)
    problems = []
    pg.on("pageerror", lambda e: problems.append("page error: " + str(e)))
    # A failed request is reported with its URL (the console message alone doesn't say which file).
    pg.on("response", lambda r: r.status >= 400 and problems.append(f"HTTP {r.status}: {r.url}"))
    pg.on("console", lambda m: m.type == "error" and problems.append("console error: " + m.text))
    pg.problems = problems
    pg.base = site
    yield pg
    ctx.close()
    assert not problems, problems

"""Remote PWA — Search (REMOTE_PWA_E2E_TEST_SPEC.md §5.4, RS). Read-only.

The known document is the sandbox's README.txt (indexed when the sandbox was
tracked): "Sandbox for the AI-Prowler Remote PWA E2E tests …".

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_search
"""
import re

from playwright.sync_api import expect

from app import type_text
from remote_safety import SANDBOX

QUERY = "Sandbox for the AI-Prowler Remote PWA E2E tests"


def _search(remote, text, enter=False):
    screen = remote.goto("search")
    box = remote.page.locator("#searchInput")
    box.click()
    box.fill("")
    if text:
        remote.step(f"type the search: {text!r}")
        type_text(remote.page, box, text)
    if enter:
        remote.step("press Enter")
        box.press("Enter")
    else:
        remote.step("tap Search")
        screen.get_by_role("button", name=re.compile("Search", re.I)).first.click()
    return screen


def test_RS_01_search_finds_the_known_document(remote):
    screen = _search(remote, QUERY)
    expect(screen).to_contain_text("README.txt", timeout=40_000)
    expect(screen).to_contain_text(SANDBOX.name, timeout=5_000)


def test_RS_02_enter_key_searches_too(remote):
    screen = _search(remote, QUERY, enter=True)
    expect(screen).to_contain_text("README.txt", timeout=40_000)


def test_RS_03_nonsense_query_says_no_results(remote):
    errors = []
    remote.page.on("pageerror", lambda e: errors.append(str(e)))
    screen = _search(remote, "zzqqxx-no-such-words-anywhere-9137")
    remote.page.wait_for_timeout(8000)
    text = screen.inner_text().lower()
    assert "error" not in text, f"the screen shows an error: {text[:200]!r}"
    assert not errors, f"page errors: {errors}"


def test_RS_04_empty_query_does_nothing(remote):
    calls = []
    remote.page.on("request", lambda r: calls.append(r.url)
                   if "/remote-api" in r.url and "search_documents" in (r.post_data or "") else None)
    _search(remote, "")
    remote.page.wait_for_timeout(1500)
    assert not calls, "an empty search was sent to the server"

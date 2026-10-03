"""Remote PWA — Dashboard & System (REMOTE_PWA_E2E_TEST_SPEC.md §5.2, RD / RY). Read-only.

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_dash
"""
import re

from playwright.sync_api import expect

EMPTY = "\u2014"          # the "—" a tile shows before it loads


def _tiles(remote):
    p = remote.page
    return {k: (p.locator(f"#{k}").inner_text() or "").strip() for k in ("dChunks", "dPaths", "dDocs", "dStatus")}


def test_RD_01_dashboard_tiles_fill_in(remote):
    remote.goto("dash")
    for k in ("dChunks", "dPaths", "dDocs", "dStatus"):
        expect(remote.page.locator(f"#{k}")).not_to_have_text(EMPTY, timeout=20_000)
    t = _tiles(remote)
    remote.step(f"tiles: {t}")
    for k in ("dChunks", "dPaths", "dDocs"):
        assert re.search(r"\d", t[k]), f"{k} tile isn't a number: {t[k]!r}"
    expect(remote.page.locator("#connDot")).to_be_visible()


def test_RD_02_quick_access_rows_open_their_screens(remote):
    for label, screen in (("File Browser", "Files"), ("Search", "Search"),
                          ("Permissions", "Perms"), ("System", "System")):
        remote.goto("dash")
        remote.step(f"tap Quick Access → {label}")
        remote.page.locator("#screenDash .row", has_text=label).first.click()
        expect(remote.page.locator(f"#screen{screen}")).to_have_class("screen active")


def test_RD_03_refresh_all_reloads_without_errors(remote):
    errors = []
    remote.page.on("pageerror", lambda e: errors.append(str(e)))
    remote.refresh_all()
    remote.goto("dash")
    for k in ("dChunks", "dPaths", "dDocs", "dStatus"):
        expect(remote.page.locator(f"#{k}")).not_to_have_text(EMPTY, timeout=20_000)
    assert not errors, f"page errors after refresh-all: {errors}"


def test_RY_01_system_screen_shows_status_and_stats(remote, rapi):
    screen = remote.goto("system")
    expect(remote.page.locator("#sysStatus .spinner")).to_have_count(0, timeout=20_000)
    expect(remote.page.locator("#sysDb .spinner")).to_have_count(0, timeout=20_000)
    status, db = remote.page.locator("#sysStatus").inner_text(), remote.page.locator("#sysDb").inner_text()
    remote.step(f"System: status={status[:80]!r} db={db[:80]!r}")
    assert status.strip() and db.strip(), "System panels are empty"
    assert re.search(r"\d", db), f"database stats show no numbers: {db[:120]!r}"
    # same chunk count as the Dashboard tile
    remote.goto("dash")
    chunks = re.sub(r"\D", "", _tiles(remote)["dChunks"])
    assert chunks and chunks in re.sub(r"[,\s]", "", status + db), \
        f"Dashboard says {chunks} chunks but System doesn't show that number"

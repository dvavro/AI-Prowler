"""Remote PWA — Permissions + Upload (REMOTE_PWA_E2E_TEST_SPEC.md §5.5 RP, §5.3 RF-05/06).

Acts ONLY on the sandbox's own tracked row (tests\\gui_remote_e2e\\sandbox,
tracked by itself 2026-09-29 with David's OK) — never on any other folder.
The guard blocks grant/revoke/upload anywhere else; the session fixture
restores the sandbox's write setting to what it was before the run.

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_perms
"""
import pytest
from playwright.sync_api import expect

from app import type_text
from remote_safety import SANDBOX

SB = str(SANDBOX)


def _cb(page):
    return page.locator(f'xpath=//input[contains(@class,"perm-cb") and @data-path="{SB}"]')


def _badge(page):
    return _cb(page).locator("xpath=ancestor::div[contains(@class,'ra')]//span[contains(@class,'badge')]")


def _tap_toggle(remote):
    remote.step("tap the sandbox's write toggle")
    _cb(remote.page).locator("xpath=..").click()


@pytest.fixture
def read_only(rapi):
    """Start with the sandbox read-only."""
    if rapi.sandbox_writable():
        rapi.call("revoke_write_access", {"directory": SB})
    assert not rapi.sandbox_writable()


@pytest.fixture
def writable(rapi):
    """Start with the sandbox writable."""
    if not rapi.sandbox_writable():
        rapi.call("grant_write_access", {"directory": SB})
    assert rapi.sandbox_writable()


def _perms(remote):
    # The app loads Permissions / Files once at sign-in; the test changed the
    # sandbox's write setting after that — tap ↻ like a person would.
    remote.refresh_all()
    remote.goto("perms")
    expect(_cb(remote.page)).to_have_count(1, timeout=20_000)


def _cancel(remote):
    """Tap the modal's Cancel — after any toast (which covers the bottom of
    the screen) has cleared."""
    remote.step("tap Cancel")
    toast = remote.page.locator("#toast.show")
    if toast.count():
        expect(toast).to_have_count(0, timeout=8_000)
    remote.page.locator("#reAuthModal .btn-cancel").click()


# ── RP-01: the list matches the server ────────────────────────────────────────
def test_RP_01_sandbox_row_matches_the_server(remote, rapi, read_only):
    _perms(remote)
    expect(_badge(remote.page)).to_have_text("R")
    expect(_cb(remote.page)).not_to_be_checked()


# ── RP-02: grant with the token re-typed ──────────────────────────────────────
def test_RP_02_grant_write_with_token(remote, rapi, token, read_only):
    _perms(remote)
    _tap_toggle(remote)
    modal = remote.page.locator("#reAuthModal")
    expect(modal).to_be_visible()
    expect(remote.page.locator("#raPath")).to_have_text(SB)
    remote.step("re-type the Bearer token (not logged) and tap Grant")
    type_text(remote.page, remote.page.locator("#raInput"), token)
    remote.page.locator("#raConfirm").click()
    expect(modal).to_be_hidden(timeout=20_000)
    expect(_badge(remote.page)).to_have_text("R+W", timeout=20_000)
    assert rapi.sandbox_writable(), "the server doesn't show the sandbox as writable"


# ── RP-03: wrong token in the grant modal ─────────────────────────────────────
def test_RP_03_grant_with_wrong_token_is_refused(remote, rapi, read_only):
    _perms(remote)
    _tap_toggle(remote)
    remote.step("type a wrong token and tap Grant")
    type_text(remote.page, remote.page.locator("#raInput"), "definitely-not-the-token")
    remote.page.locator("#raConfirm").click()
    expect(remote.page.locator("#raErr")).to_have_text("Incorrect token (1/3)")
    expect(remote.page.locator("#raInput")).to_have_value("")
    _cancel(remote)
    expect(remote.page.locator("#reAuthModal")).to_be_hidden()
    assert not rapi.sandbox_writable(), "write access was granted with a wrong token"


# ── RP-04: revoke is instant (RQ-05: no confirmation) ─────────────────────────
def test_RP_04_revoke_is_instant(remote, rapi, writable):
    _perms(remote)
    expect(_badge(remote.page)).to_have_text("R+W")
    _tap_toggle(remote)
    expect(_badge(remote.page)).to_have_text("R", timeout=20_000)
    assert not rapi.sandbox_writable(), "the server still shows the sandbox writable"
    remote.step("RQ-05 recorded: revoke happened with no confirmation (David's call)")


# ── RP-05: cancel the grant modal ─────────────────────────────────────────────
def test_RP_05_cancel_grant_changes_nothing(remote, rapi, read_only):
    _perms(remote)
    _tap_toggle(remote)
    expect(remote.page.locator("#reAuthModal")).to_be_visible()
    _cancel(remote)
    expect(remote.page.locator("#reAuthModal")).to_be_hidden()
    expect(_cb(remote.page)).not_to_be_checked()
    assert not rapi.sandbox_writable()


# ── RF-05: upload a file into the (writable) sandbox ─────────────────────────
def test_RF_05_upload_into_the_sandbox(remote, rapi, writable, tmp_path):
    src = tmp_path / "ZTEST_E2E_upload.txt"
    src.write_text("ZTEST E2E upload from the Remote PWA test — safe to delete.\n", encoding="utf-8")
    remote.refresh_all()
    remote.goto("files")
    inp = remote.page.locator(f'xpath=//input[@type="file" and @data-dir="{SB}"]')
    expect(inp).to_have_count(1, timeout=20_000)
    remote.step("tap 📷 Upload on the sandbox and choose ZTEST_E2E_upload.txt")
    with remote.page.expect_response(lambda r: "/remote/upload" in r.url, timeout=60_000) as resp:
        inp.set_input_files(str(src))
    assert resp.value.status == 200, f"upload answered {resp.value.status}"
    landed = SANDBOX / "ZTEST_E2E_upload.txt"
    assert landed.exists() and landed.read_bytes() == src.read_bytes(), "the file on disk differs"


# ── RF-06: no Upload on a read-only folder ───────────────────────────────────
def test_RF_06_no_upload_when_read_only(remote, rapi, read_only):
    remote.refresh_all()
    screen = remote.goto("files")
    row = screen.locator(".row", has=remote.page.locator(".rs", has_text=SB)).first
    expect(row).to_be_visible(timeout=20_000)
    expect(row.get_by_text("Read only")).to_be_visible()
    expect(remote.page.locator(f'xpath=//input[@type="file" and @data-dir="{SB}"]')).to_have_count(0)

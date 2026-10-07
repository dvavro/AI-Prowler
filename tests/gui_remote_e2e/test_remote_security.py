"""Remote PWA — security (REMOTE_PWA_E2E_TEST_SPEC.md §5.8, RX). Runs first.

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_security
"""
import json
import os
import urllib.parse

import pytest
from playwright.sync_api import expect

from api import http, local_api_origin
from remote_safety import SANDBOX

ORIGIN = local_api_origin()


def test_RX_01_pwa_token_never_hands_out_a_token(token):
    st, body = http("GET", ORIGIN + "/pwa-token", timeout=30)
    assert st == 200
    # The reply keeps an (always empty) "token" field for older app versions — it must stay empty.
    assert token not in body, "/pwa-token contains the Bearer token"
    assert not json.loads(body).get("token"), f"/pwa-token hands out a token: {body[:120]!r}"


@pytest.mark.parametrize("case", ["no_token", "wrong_token"])
def test_RX_02_remote_api_refuses_without_the_token(case):
    tok = None if case == "no_token" else "definitely-not-the-token"
    st, body = http("POST", ORIGIN + "/remote-api", {"tool": "list_tracked_directories", "args": {}},
                    token=tok, timeout=30)
    assert st == 401, f"/remote-api answered {st} without a valid token: {body[:120]!r}"
    assert ":\\" not in body, "folder names came back without a valid token"


def test_RX_03_no_part_of_the_token_shows_on_the_page(remote, token):
    """RQ-02: api() writes BEARER.slice(0,8) into #debugLog on every call."""
    for tab in ("files", "search", "perms", "learn", "tasks", "system", "dash"):
        remote.goto(tab)
    page_text = remote.page.evaluate("() => document.body.innerText")
    debug = remote.page.evaluate("() => (document.getElementById('debugLog') || {}).textContent || ''")
    assert token[:8] not in debug, "RQ-02: the first 8 characters of the Bearer token are in the debug log"
    assert token[:8] not in page_text, "part of the Bearer token is visible on the page"


def test_RX_04_download_does_not_put_the_token_in_the_url(remote, token):
    """RQ-03: /remote/download?path=…&token=<full token> — ends up in access logs and history."""
    urls = []
    remote.page.on("request", lambda r: urls.append(r.url) if "/remote/download" in r.url else None)
    remote.page.evaluate("(p) => downloadFile(p)", str(SANDBOX / "ZTEST_E2E_seed.txt"))
    remote.page.wait_for_timeout(2500)
    assert urls, "the app made no download request"
    leaked = [u for u in urls if urllib.parse.quote(token, safe="") in u or token in u]
    assert not leaked, "RQ-03: the full Bearer token is in the download URL (access logs, browser history)"


@pytest.mark.parametrize("case", ["no_token", "wrong_token"])
def test_RX_05_upload_refuses_without_the_token(case):
    body = {"file_data": "WlRFU1Q=", "filename": "ZTEST_E2E_rx05.txt", "dir": str(SANDBOX)}
    if case == "wrong_token":
        body["token"] = "definitely-not-the-token"
    st, raw = http("POST", ORIGIN + "/remote/upload", body, timeout=30)
    written = (SANDBOX / "ZTEST_E2E_rx05.txt")
    try:
        assert st in (401, 403), f"upload answered {st} without a valid token: {raw[:120]!r}"
        assert not written.exists(), "a file was written without a valid token"
    finally:
        if written.exists():
            written.unlink()


@pytest.mark.parametrize("path", [r"C:\Windows\win.ini",
                                  str(SANDBOX) + r"\..\..\..\..\..\..\Windows\win.ini"],
                         ids=["outside_tracked", "dotdot_escape"])
def test_RX_06_download_refuses_paths_outside_tracked_folders(token, path):
    q = urllib.parse.urlencode({"path": path, "token": token})
    st, body = http("GET", ORIGIN + "/remote/download?" + q, timeout=30)
    assert st in (400, 403, 404), f"download of {path!r} answered {st}"
    assert "[fonts]" not in body.lower() and "for 16-bit app support" not in body.lower(), \
        "the contents of win.ini came back"


def test_RX_07_every_app_call_passed_the_guard(remote, guard):
    """The page fixture fails the test if any /remote-api or upload request skipped the guard;
    this makes the app do a full round of calls so that check has something to count."""
    before = guard.allowed_count
    remote.refresh_all()
    assert guard.allowed_count > before, "refresh-all made no guarded calls"


def test_RX_08_server_install_does_not_run_the_remote_app():
    """Personal-only (David 2026-09-28): the AI-Prowler SERVER must not run /remote-api tools."""
    url = os.environ.get("AIPROWLER_SRV_URL", "")
    if not url:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                url = str(winreg.QueryValueEx(k, "AIPROWLER_SRV_URL")[0])
        except Exception:
            pytest.skip("AIPROWLER_SRV_URL not set — no server to check")
    origin = url.split("/jobs")[0]
    st, body = http("POST", origin + "/remote-api", {"tool": "list_tracked_directories", "args": {}},
                    token="definitely-not-the-token", timeout=30)
    assert st != 200 or '"ok": true' not in body.replace(" ", "").lower(), \
        f"the server install answered /remote-api: {st} {body[:120]!r}"

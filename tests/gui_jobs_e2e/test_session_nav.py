"""SEC-08, SEC-09 (spec §6.13) and NAV-02, NAV-04 (spec §6.2).

SEC-08  a saved Jobs-app session whose token no longer works (rotated in
        Settings) — the app must drop back to the login screen, not a dead end.
        Simulated with a saved session holding a token the server refuses:
        rotating the real token would break every other test and David's own
        devices, and to the server the two are the same thing.
SEC-09  the Remote PWA (/remote/) login: wrong token refused, right token
        boots, a reload resumes only because the SERVER still accepts the
        saved token, a stale saved token goes back to the login screen. The
        Remote app's own API (/remote-api) isn't covered by the Jobs-app write
        guard, so in the browser every /remote-api call is answered here and
        never reaches the server; only its 401 gate is checked with plain HTTP.
NAV-02  the connection dot: green while the API answers, red when it fails,
        green again after ↻ (the failure is faked in the browser).
NAV-04  the "new version available" banner. Test browsers block service
        workers (R-015), so the app's own _showUpdateBanner() stands in for
        "the service worker reports a new version"; a real service-worker
        update is PWA-02 (§6.10).

Run: run_tests_gui_jobs_e2e.bat --human -k test_session_nav
"""
import json
import re

import pytest
from playwright.sync_api import expect

from api import http, origin_of
from app import JobsApp, type_text

STALE = "rotated-away-" + "x" * 20


# ── SEC-08 ───────────────────────────────────────────────────────────────────
@pytest.mark.no_login
def test_SEC_08_saved_session_with_a_rotated_token_goes_back_to_login(page, app_url, token):
    page.add_init_script(
        "try{if(!sessionStorage.getItem('e2e_stale_set')){sessionStorage.setItem('e2e_stale_set','1');"
        "localStorage.setItem('ap_auth'," + json.dumps(json.dumps({"mode": "personal", "token": STALE}))
        + ")}}catch(e){}")
    a = JobsApp(page, app_url)
    a.step("open the app with a saved session whose token was rotated away")
    page.goto(app_url, wait_until="domcontentloaded")
    # 2026-10-02: the login screen is visible (and #app hidden) in the page's
    # own HTML before any script runs, so those two checks passed instantly —
    # before the app had even tried the stale token — and the storage check
    # raced the app. Wait for the app to actually refuse the token and erase
    # the dead session (handleAuthExpired); if it never does, this times out
    # with the same message.
    try:
        page.wait_for_function("() => localStorage.getItem('ap_auth') === null",
                               timeout=30_000)
    except Exception:
        pass
    expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)   # not a dead end
    expect(page.locator("#app")).to_be_hidden()
    assert a.saved_auth() is None, "the dead session is still saved"
    a.step("log in again with the current token")
    a.login(token)
    expect(page.locator("#app")).to_be_visible(timeout=30_000)
    expect(page.locator("#authScreen")).to_be_hidden()
    assert json.loads(a.saved_auth())["token"] == token


# ── SEC-09 ───────────────────────────────────────────────────────────────────
@pytest.fixture
def remote(page, app_url):
    """The Remote PWA, with its own API answered in the browser (never sent)."""
    page.route("**/remote-api", lambda route: route.fulfill(
        status=200, content_type="application/json",
        body=json.dumps({"ok": True, "result": "E2E: not sent"})))
    return origin_of(app_url) + "/remote/"


def _remote_saved(page):
    return page.evaluate("() => sessionStorage.getItem('ap_remote')")


def _remote_unlock(page, text):
    inp = page.locator("#authInput")
    inp.fill("")
    type_text(page, inp, text)
    page.get_by_role("button", name="Unlock Remote").click()


def test_SEC_09_remote_api_refuses_missing_or_wrong_token(api):
    body = {"tool": "check_ai_prowler_status", "args": {}}
    assert http("POST", api.origin + "/remote-api", body, timeout=30)[0] == 401
    assert http("POST", api.origin + "/remote-api", body, token="wrong-" + "x" * 24, timeout=30)[0] == 401


@pytest.mark.no_login
def test_SEC_09_remote_login_wrong_right_resume_stale(page, remote, token):
    log = JobsApp(page, remote).step
    log("REMOTE open the login screen")
    page.goto(remote, wait_until="domcontentloaded")
    expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)

    log("REMOTE wrong token")
    _remote_unlock(page, "wrong-token-" + "x" * 12)
    expect(page.locator("#authErr")).to_be_visible()
    expect(page.locator("#authInput")).to_have_value("")
    assert _remote_saved(page) is None

    log("REMOTE right token")
    _remote_unlock(page, token)
    expect(page.locator("#app")).to_be_visible(timeout=30_000)
    expect(page.locator("#authScreen")).to_be_hidden()
    assert json.loads(_remote_saved(page))["token"] == token

    log("REMOTE reload — resumes only if the server still accepts the saved token")
    with page.expect_response(lambda r: "/pwa-verify" in r.url, timeout=30_000) as v:
        page.reload(wait_until="domcontentloaded")
    assert v.value.status == 200
    expect(page.locator("#app")).to_be_visible(timeout=30_000)

    log("REMOTE saved token no longer valid (rotated) → back to login")
    page.evaluate("t => sessionStorage.setItem('ap_remote', JSON.stringify({token: t}))", STALE)
    with page.expect_response(lambda r: "/pwa-verify" in r.url, timeout=30_000) as v:
        page.reload(wait_until="domcontentloaded")
    assert v.value.status == 401
    expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)
    expect(page.locator("#app")).to_be_hidden()
    assert _remote_saved(page) is None, "the dead remote session is still saved"


# ── NAV-02 ───────────────────────────────────────────────────────────────────
def test_NAV_02_connection_dot(app, page):
    dot = page.locator("#connDot")
    expect(dot).to_be_visible()
    expect(dot).not_to_have_class(re.compile(r"\boffline\b"), timeout=30_000)
    app.step("the server stops answering (faked in the browser) — tap ↻")
    page.e2e_fakes["read_job_spreadsheet"] = {"http_status": 503}
    page.locator("#refreshJobsBtn").click()
    expect(dot).to_have_class(re.compile(r"\boffline\b"), timeout=20_000)
    app.step("the server answers again — tap ↻")
    del page.e2e_fakes["read_job_spreadsheet"]
    expect(page.locator("#refreshJobsBtn")).to_be_enabled(timeout=20_000)
    page.locator("#refreshJobsBtn").click()
    expect(dot).not_to_have_class(re.compile(r"\boffline\b"), timeout=30_000)


# ── NAV-04 ───────────────────────────────────────────────────────────────────
def test_NAV_04_update_banner_later_reshow_refresh(app, page):
    banner = page.locator("#updateBanner")
    expect(banner).not_to_have_class(re.compile(r"\bshow\b"))
    app.step("a new version is reported")
    page.evaluate("_showUpdateBanner()")
    expect(banner).to_have_class(re.compile(r"\bshow\b"))
    expect(banner).to_be_visible()
    expect(banner).to_contain_text("new version")
    app.step("tap Later")
    banner.get_by_role("button", name="Later").click()
    expect(banner).not_to_have_class(re.compile(r"\bshow\b"))
    app.goto("board")                                    # still pending → asks again
    expect(banner).to_have_class(re.compile(r"\bshow\b"))
    app.step("tap Refresh Now")
    with page.expect_event("load", timeout=30_000):
        banner.get_by_role("button", name="Refresh Now").click()
    expect(page.locator("#app")).to_be_visible(timeout=30_000)          # session resumed
    expect(page.locator("#authScreen")).to_be_hidden()
    expect(banner).not_to_have_class(re.compile(r"\bshow\b"))

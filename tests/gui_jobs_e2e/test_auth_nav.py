"""AUTH-01..06 and NAV-01/NAV-03 (spec §6.1, §6.2)."""
import json
import re

import pytest
from playwright.sync_api import expect

from app import JobsApp, _screen_id


# ── AUTH ─────────────────────────────────────────────────────────────────────
@pytest.mark.no_login
def test_AUTH_01_login_with_valid_token(page, app_url, token):
    a = JobsApp(page, app_url).open_login_screen()
    a.login(token)
    expect(page.locator("#app")).to_be_visible()
    expect(page.locator("#authScreen")).to_be_hidden()
    saved = json.loads(a.saved_auth())
    assert saved["mode"] == "personal" and saved["token"] == token


@pytest.mark.no_login
def test_AUTH_02_wrong_token_is_refused(page, app_url):
    a = JobsApp(page, app_url).open_login_screen()
    a.login("wrong-token-" + "x" * 12)
    expect(a.auth_error()).to_be_visible()
    expect(a.auth_error()).to_contain_text("Incorrect")
    expect(page.locator("#authCode")).to_have_value("")
    expect(page.locator("#authCode")).to_have_class(re.compile(r"auth-input-invalid"))
    assert a.saved_auth() is None


@pytest.mark.no_login
def test_AUTH_03_empty_token(page, app_url):
    a = JobsApp(page, app_url).open_login_screen()
    page.get_by_test_id("auth-unlock").click()
    expect(a.auth_error()).to_contain_text("Please enter your password")


@pytest.mark.no_login
def test_AUTH_04_show_hide_password(page, app_url):
    JobsApp(page, app_url).open_login_screen()
    code, eye = page.locator("#authCode"), page.get_by_test_id("auth-eye")
    expect(code).to_have_attribute("type", "password")
    eye.click()
    expect(code).to_have_attribute("type", "text")
    expect(eye).to_have_attribute("aria-label", "Hide password")
    eye.click()
    expect(code).to_have_attribute("type", "password")


def test_AUTH_05_reload_resumes_the_session(app, page):
    page.reload(wait_until="domcontentloaded")
    expect(page.locator("#app")).to_be_visible()
    expect(page.locator("#authScreen")).to_be_hidden()


@pytest.mark.no_login
def test_AUTH_06_sign_out(page, app_url, token):
    a = JobsApp(page, app_url).open_login_screen()
    a.login(token)
    expect(page.locator("#app")).to_be_visible()
    a.sign_out()
    expect(page.locator("#authScreen")).to_be_visible()
    assert a.saved_auth() is None


# ── NAV ──────────────────────────────────────────────────────────────────────
def test_NAV_01_every_visible_screen_opens(app):
    screens = app.visible_screens()
    assert {"jobs", "route", "profile"} <= set(screens), screens
    for s in screens:
        app.goto(s)
        assert app.active_screens() == [_screen_id(s)], f"after tapping {s}: {app.active_screens()}"


def test_NAV_03_no_javascript_errors_on_any_screen(app, page):
    errors, current = [], {"screen": "(start)"}
    page.on("pageerror", lambda e: errors.append(f"[{current['screen']}] pageerror: {e}"))
    page.on("console", lambda m: errors.append(f"[{current['screen']}] console.error: {m.text}")
            if m.type == "error" else None)
    page.on("response", lambda r: errors.append(f"[{current['screen']}] HTTP {r.status} {r.url}")
            if r.status >= 400 else None)
    for s in app.visible_screens():
        current["screen"] = s
        app.goto(s)
        page.wait_for_timeout(800)          # let each screen's loaders settle
    assert not errors, "\n".join(errors)

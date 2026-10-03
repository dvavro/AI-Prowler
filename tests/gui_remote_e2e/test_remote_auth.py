"""Remote PWA — sign-in & session (REMOTE_PWA_E2E_TEST_SPEC.md §5.1, RA).

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_auth
"""
import json

from playwright.sync_api import expect


def test_RA_01_right_token_signs_in(ui, token):
    ui.login(token).signed_in()
    expect(ui.page.locator("#topbarSub")).to_contain_text("Personal")
    saved = json.loads(ui.session() or "{}")
    assert saved.get("token") == token, "no session kept for this tab"
    local = ui.page.evaluate("() => JSON.stringify(Object.assign({}, localStorage))")
    assert token not in local, "the Bearer token was saved in localStorage (survives closing the tab)"


def test_RA_02_wrong_token_is_refused(ui):
    ui.login("definitely-not-the-token")
    expect(ui.page.locator("#authErr")).to_be_visible()
    expect(ui.page.locator("#authInput")).to_have_value("")
    expect(ui.page.locator("#app")).to_be_hidden()
    assert ui.session() is None


def test_RA_03_empty_token_does_nothing(ui):
    calls = []
    ui.page.on("request", lambda r: calls.append(r.url) if "/pwa-verify" in r.url else None)
    ui.step("tap Unlock Remote with the box empty")
    ui.page.get_by_role("button", name="Unlock Remote").click()
    ui.page.wait_for_timeout(800)
    assert not calls, "an empty token was sent to the server"
    expect(ui.page.locator("#authErr")).to_be_hidden()
    expect(ui.page.locator("#authScreen")).to_be_visible()


def test_RA_04_show_hide_token(ui):
    box, eye = ui.page.locator("#authInput"), ui.page.locator("#authEyeBtn")
    expect(box).to_have_attribute("type", "password")
    ui.step("tap 👁 (show)")
    eye.click()
    expect(box).to_have_attribute("type", "text")
    ui.step("tap again (hide)")
    eye.click()
    expect(box).to_have_attribute("type", "password")


def test_RA_05_reload_resumes_without_retyping(remote):
    remote.step("reload the page")
    remote.page.reload(wait_until="domcontentloaded")
    remote.signed_in()


def test_RA_06_invalid_saved_session_goes_back_to_login(remote):
    remote.step("replace this tab's saved session with a bad token, then reload")
    remote.page.evaluate("() => sessionStorage.setItem('ap_remote', JSON.stringify({token: 'stale-token'}))")
    remote.page.reload(wait_until="domcontentloaded")
    expect(remote.page.locator("#authScreen")).to_be_visible(timeout=30_000)
    expect(remote.page.locator("#app")).to_be_hidden()
    assert remote.session() is None, "the bad session wasn't removed"


def test_RA_07_new_tab_must_sign_in_again(remote):
    remote.step("open the Remote PWA in a second tab")
    tab2 = remote.page.context.new_page()
    try:
        tab2.goto(remote.url, wait_until="domcontentloaded")
        expect(tab2.locator("#authScreen")).to_be_visible(timeout=30_000)
        expect(tab2.locator("#app")).to_be_hidden()
    finally:
        tab2.close()

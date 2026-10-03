"""Server mode — sign-in & sessions (spec §6.11.5, SRV-AUTH), with two real
users in two separate browser windows.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_auth
"""
import json

import pytest
from playwright.sync_api import expect

from api import http
from srv_helpers import srv_login

ROLE_OF = {"U1": "owner", "U2": "manager", "U3": "field_crew"}   # what the Admin tab should have them as


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


# ── SRV-AUTH-01: each user signs in and sees themselves ──────────────────────
@pytest.mark.parametrize("key", ["U1", "U2"])
def test_SRV_AUTH_01_user_signs_in_and_sees_own_name_and_role(windows, key):
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    expect(w.page.locator("#topbarRole")).to_have_text(w.user.name)
    w.app.goto("profile")
    expect(w.page.locator("#profileName")).to_have_text(w.user.name)
    expect(w.page.locator("#profileRoleLabel")).to_have_text("Role")
    expect(w.page.locator("#profileRole")).to_have_text(ROLE_OF[key])
    saved = json.loads(w.app.saved_auth() or "{}")
    assert saved.get("mode") == "server", f"saved session isn't server mode: {list(saved)}"
    assert saved.get("userName") == w.user.name and saved.get("userRole") == ROLE_OF[key]
    assert saved.get("access_token") and saved["access_token"] != w.user.token, \
        "the saved session holds the personal token itself instead of a session token"
    assert "token" not in saved, "the personal token was saved in the browser"


# ── SRV-AUTH-02: right token, wrong name ─────────────────────────────────────
def test_SRV_AUTH_02_right_token_wrong_name_is_refused(windows, srv):
    david, vicki = srv["users"]["U1"], srv["users"]["U2"]
    (w,) = windows("U2")
    w.log_in(name=vicki.name, token=david.token)        # Vicki's name, David's token
    err = w.page.locator("#authError")
    expect(err).to_be_visible()
    expect(err).to_contain_text("not recognized")
    expect(w.page.locator("#authScreen")).to_be_visible()
    assert w.app.saved_auth() is None, "a session was saved for a refused login"
    expect(w.page.locator("#authCode")).to_have_value("")          # password box cleared


# ── SRV-AUTH-03: wrong token / blank name ────────────────────────────────────
@pytest.mark.parametrize("case", ["wrong_token", "blank_name"])
def test_SRV_AUTH_03_wrong_token_or_blank_name_is_refused(windows, case):
    (w,) = windows("U2")
    if case == "wrong_token":
        w.log_in(token="definitely-not-the-token")
    else:
        w.log_in(name="")
    expect(w.page.locator("#authError")).to_be_visible()
    expect(w.page.locator("#authScreen")).to_be_visible()
    assert w.app.saved_auth() is None


# ── SRV-AUTH-05: what the sign-in reply contains ─────────────────────────────
def test_SRV_AUTH_05_login_reply_has_role_and_no_personal_token(srv):
    for key, u in srv["users"].items():
        st, d = srv_login(srv["origin"], u.name, u.token)
        assert st == 200, f"{key} login HTTP {st}"
        assert d.get("role") == ROLE_OF[key], f"{key}: role {d.get('role')!r}"
        assert "token" not in d and u.token not in json.dumps(d), f"{key}: reply echoes the personal token"
        assert d.get("access_token") and d["access_token"] != u.token


# ── SRV-AUTH-06: sign out, then Back / Forward ───────────────────────────────
def test_SRV_AUTH_06_after_sign_out_back_and_forward_show_login(windows):
    (w,) = windows("U2")
    w.log_in()
    _signed_in(w)
    w.app.goto("jobs")
    w.app.goto("profile")
    w.app.sign_out()
    expect(w.page.locator("#authScreen")).to_be_visible(timeout=30_000)
    assert w.app.saved_auth() is None
    # Back may leave the app (a freshly opened window has nothing before it) —
    # whatever it lands on, coming back to the app must show the login screen.
    w.app.step("press the browser Back button")
    w.page.go_back(wait_until="domcontentloaded")
    if "/jobs" not in w.page.url:
        w.app.step(f"Back left the app ({w.page.url or 'blank'}) — press Forward to return")
        w.page.go_forward(wait_until="domcontentloaded")
    assert "/jobs" in w.page.url, f"not back on the app: {w.page.url}"
    expect(w.page.locator("#authScreen")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#app")).to_be_hidden()
    assert w.app.saved_auth() is None


# ── SRV-AUTH-06b: the signed-out session must stop working on the server ─────
def test_SRV_AUTH_06b_signed_out_session_is_dead_on_the_server(windows, srv):
    (w,) = windows("U2")
    w.log_in()
    _signed_in(w)
    old = json.loads(w.app.saved_auth())["access_token"]
    w.app.sign_out()
    expect(w.page.locator("#authScreen")).to_be_visible(timeout=30_000)
    w.app.step("ask the server directly with the session the browser just threw away")
    st, body = http("POST", srv["origin"] + "/pwa-api",
                    {"tool": "read_job_spreadsheet", "args": {"sheet_name": "Jobs_Schedule", "max_rows": 1}},
                    token=old, timeout=30)
    assert st == 401, (f"after Sign Out the old session still works on the server (HTTP {st}) — "
                       "signing out only forgets it in the browser; anyone holding a copy (a shared "
                       "or lost phone) keeps full access until the server restarts")


# ── SRV-MULTI-01: two people at once, independent sessions ───────────────────
def test_SRV_MULTI_01_two_users_side_by_side_independent(windows):
    david, vicki = windows("U1", "U2")
    david.log_in()
    vicki.log_in()
    _signed_in(david)
    _signed_in(vicki)
    expect(david.page.locator("#topbarRole")).to_have_text(david.user.name)
    expect(vicki.page.locator("#topbarRole")).to_have_text(vicki.user.name)
    # both can load the job list at the same time
    for w in (david, vicki):
        w.app.goto("jobs")
        res = w.app.mcp("read_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "max_rows": 5})
        assert isinstance(res, str) and not res.startswith("❌"), f"{w.user.key}: {res!r}"
    # David signs out; Vicki is unaffected
    david.app.sign_out()
    expect(david.page.locator("#authScreen")).to_be_visible(timeout=30_000)
    vicki.app.goto("profile")
    expect(vicki.page.locator("#profileName")).to_have_text(vicki.user.name)
    res = vicki.app.mcp("read_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "max_rows": 5})
    assert isinstance(res, str) and not res.startswith("❌"), f"Vicki lost her session when David signed out: {res!r}"
    assert json.loads(vicki.app.saved_auth() or "{}").get("userName") == vicki.user.name

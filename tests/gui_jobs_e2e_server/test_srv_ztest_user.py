"""Server mode — SRV-AUTH-08 (role change) and SRV-AUTH-07 (token revoked while
signed in), on a THROW-AWAY user. GUIDED: David makes the Admin-tab change
while the test waits (it polls, up to 5 minutes per step, and logs what to do).

One-time setup (David, on the server):
  1. Admin tab → add user  Name: "ZTEST E2E User"   Role: field_crew
  2. On this PC:  setx AIPROWLER_ZTEST_USER_TOKEN "<that user's token>"
Skipped entirely when AIPROWLER_ZTEST_USER_TOKEN isn't set, so normal runs
never need this user. It is NOT in users.local.json.

Order matters — run both in one go:
  AUTH-08 first: when the log says so, change ZTEST E2E User's role to "staff".
  AUTH-07 next:  when the log says so, revoke (or delete) ZTEST E2E User.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_ztest_user
"""
import json
import logging
import time

import pytest

from api import http
from srv_helpers import srv_login

log = logging.getLogger("e2e_srv")

NAME = "ZTEST E2E User"
WAIT_S = 300


def _token():
    import conftest   # the server suite's own env reader (also checks the registry)
    return conftest._user_env("AIPROWLER_ZTEST_USER_TOKEN")


pytestmark = pytest.mark.skipif(not _token(), reason="AIPROWLER_ZTEST_USER_TOKEN not set — throw-away user not set up")


def _read(srv, access):
    st, _ = http("POST", srv["origin"] + "/pwa-api",
                 {"tool": "read_job_spreadsheet", "args": {"sheet_name": "Jobs_Schedule", "max_rows": 1}},
                 token=access, timeout=30)
    return st


def _say(msg):
    log.info(f"[ZTEST-USER] >>> {msg}")
    print(f"\n>>> {msg}\n", flush=True)


def test_SRV_AUTH_08_role_change_applies_after_re_login(srv):
    st, d = srv_login(srv["origin"], NAME, _token())
    assert st == 200, f"{NAME} can't sign in (HTTP {st}) — is the user added with exactly this name?"
    assert d.get("role") == "field_crew", f"{NAME} should start as field_crew, is {d.get('role')!r}"
    _say(f"NOW: Admin tab → change {NAME}'s role to 'staff' (waiting up to {WAIT_S // 60} min)")
    t0 = time.time()
    while time.time() - t0 < WAIT_S:
        st, d = srv_login(srv["origin"], NAME, _token())
        if st == 200 and d.get("role") == "staff":
            log.info(f"[SRV-AUTH-08] new role seen at sign-in after {round(time.time() - t0)} s")
            http("POST", srv["origin"] + "/pwa-logout", {}, token=d["access_token"], timeout=30)
            return
        time.sleep(5)
    pytest.fail(f"{NAME}'s role never became 'staff' at sign-in within {WAIT_S} s")


def test_SRV_AUTH_07_revoked_user_is_cut_off_while_signed_in(srv):
    st, d = srv_login(srv["origin"], NAME, _token())
    assert st == 200, f"{NAME} can't sign in (HTTP {st})"
    access = d["access_token"]
    assert _read(srv, access) == 200, "the fresh session doesn't work — setup problem"
    _say(f"NOW: Admin tab → revoke (or delete) {NAME} (waiting up to {WAIT_S // 60} min)")
    t0 = time.time()
    while time.time() - t0 < WAIT_S:
        if _read(srv, access) == 401:
            log.info(f"[SRV-AUTH-07] signed-in session refused (401) {round(time.time() - t0)} s after the prompt")
            st, _ = srv_login(srv["origin"], NAME, _token())
            assert st == 401, f"a revoked user can still sign in again (HTTP {st})"
            return
        time.sleep(5)
    pytest.fail(f"{NAME}'s open session still worked {WAIT_S} s after the revoke prompt")

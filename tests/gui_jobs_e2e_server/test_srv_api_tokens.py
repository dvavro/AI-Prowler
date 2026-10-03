"""Server mode — SRV-API-06: requests to /pwa-api without a valid session
must get HTTP 401, and a session can only ever act as the user it belongs to.

Straight HTTP to the live server (no browser windows). Every call is a
read-only probe (read one row of Jobs_Schedule / Invoices, or the owner-only
Reports read find_stale_customers), so nothing changes even if a probe were
wrongly let through. Sessions this test creates are signed out at the end.

What "expired" means here: /pwa-login sessions have NO expiry — they live in
the server's memory until Sign Out (R-038) or a restart. So the expired-token
case is covered as "a session that has been ended" (signed out). Whether a
session should also time out on its own is gap G-10 (David decides).

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_api_tokens
"""
import json
import logging
import urllib.error
import urllib.request

import pytest

from api import USER_AGENT, http
from srv_helpers import srv_login

log = logging.getLogger("e2e_srv")

READ_JOBS = {"tool": "read_job_spreadsheet", "args": {"sheet_name": "Jobs_Schedule", "max_rows": 1}}
READ_INVOICES = {"tool": "read_job_spreadsheet", "args": {"sheet_name": "Invoices", "max_rows": 1}}
STALE = {"tool": "find_stale_customers", "args": {}}


def _raw(origin: str, body: dict, headers: dict) -> tuple[int, str]:
    """POST /pwa-api with exactly these extra headers (http() only knows 'Bearer <x>')."""
    req = urllib.request.Request(origin + "/pwa-api", data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", USER_AGENT)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _refused(result: str) -> bool:
    return result.lstrip().startswith("❌") or ('"error"' in result and "access" in result.lower())


def _call(srv, body, token) -> tuple[int, dict]:
    st, raw = http("POST", srv["origin"] + "/pwa-api", body, token=token, timeout=30)
    try:
        return st, json.loads(raw)
    except ValueError:
        return st, {"raw": raw[:200]}


@pytest.fixture
def fresh_sessions(srv):
    """Log each user in once more (a session only this test holds); sign them all out after."""
    made = {}

    def make(key):
        u = srv["users"][key]
        st, d = srv_login(srv["origin"], u.name, u.token)
        assert st == 200 and d.get("access_token"), f"{key}: /pwa-login HTTP {st}"
        made[key] = d["access_token"]
        return d["access_token"]

    yield make
    for tok in made.values():
        http("POST", srv["origin"] + "/pwa-logout", {}, token=tok, timeout=30)


# ── SRV-API-06a: no / broken / made-up credentials → 401 ─────────────────────
@pytest.mark.parametrize("case", [
    "no_header", "empty_bearer", "basic_scheme", "made_up_token", "one_char_changed",
])
def test_SRV_API_06_bad_credentials_get_401(srv, case):
    good = srv["users"]["U2"].access_token
    headers = {
        "no_header":        {},
        "empty_bearer":     {"Authorization": "Bearer "},
        "basic_scheme":     {"Authorization": "Basic " + good},        # right secret, wrong scheme
        "made_up_token":    {"Authorization": "Bearer ZTEST-not-a-real-session-0123456789"},
        "one_char_changed": {"Authorization": "Bearer " + good[:-1] + ("A" if good[-1] != "A" else "B")},
    }[case]
    st, raw = _raw(srv["origin"], READ_JOBS, headers)
    log.info(f"[SRV-API-06 {case}] /pwa-api -> HTTP {st}")
    assert st == 401, f"{case}: expected 401, got HTTP {st}: {raw[:160]}"
    assert "Jobs_Schedule" not in raw and "Customer" not in raw, f"{case}: 401 reply leaked data: {raw[:160]}"


# ── SRV-API-06b: an ended session → 401 (the "expired" case) ─────────────────
@pytest.mark.parametrize("key", ["U1", "U2", "U3"])
def test_SRV_API_06_ended_session_gets_401(srv, fresh_sessions, key):
    tok = fresh_sessions(key)
    st, d = _call(srv, READ_JOBS, tok)
    assert st == 200 and d.get("ok"), f"{key}: brand-new session didn't work (HTTP {st}) — test setup problem"
    st, _ = http("POST", srv["origin"] + "/pwa-logout", {}, token=tok, timeout=30)
    assert st == 200, f"{key}: /pwa-logout HTTP {st}"
    st, d = _call(srv, READ_JOBS, tok)
    log.info(f"[SRV-API-06 ended {key}] /pwa-api after sign-out -> HTTP {st}")
    assert st == 401, f"{key}: an ended session still works (HTTP {st})"


# ── SRV-API-06c: a session acts only as its own user ─────────────────────────
# Samual (field_crew) holds his own valid session and tries to borrow someone
# else's identity through the request itself. Identity must come from the
# session alone: the owner-only read and the blocked sheet stay refused.
SPOOFS = {
    "plain":              ({}, {}),
    "args_claim_owner":   ({"user": "David Vavro", "role": "owner", "user_name": "David Vavro"}, {}),
    "args_supply_ctx":    ({"ctx": {"user": {"name": "David Vavro", "role": "owner"}}}, {}),
    "headers_claim_owner": ({}, {"X-User": "David Vavro", "X-Role": "owner",
                                 "X-Forwarded-User": "David Vavro"}),
}


@pytest.mark.parametrize("spoof", list(SPOOFS))
def test_SRV_API_06_session_cannot_act_as_another_user(srv, fresh_sessions, spoof):
    extra_args, extra_headers = SPOOFS[spoof]
    samual = fresh_sessions("U3")
    for label, base in (("find_stale_customers (owner only)", STALE),
                        ("read Invoices (blocked for field crew)", READ_INVOICES)):
        body = {"tool": base["tool"], "args": dict(base["args"], **extra_args)}
        st, raw = _raw(srv["origin"], body, dict({"Authorization": "Bearer " + samual}, **extra_headers))
        try:
            d = json.loads(raw)
        except ValueError:
            d = {}
        res = str(d.get("result", ""))
        verdict = ("rejected (4xx)" if 400 <= st < 500 else
                   "refused" if _refused(res) else "NOT refused")
        log.info(f"[SRV-API-06 spoof {spoof}] Samual {label} -> HTTP {st} {verdict}")
        # Refused may come back as a tool-level ❌ (HTTP 200) or as a 4xx for an
        # argument the tool doesn't accept — both are fine; data is not.
        if st == 200:
            assert d.get("ok") is not False and _refused(res), \
                f"{spoof}: Samual's session got {label} data: {res[:160]}"
        else:
            assert 400 <= st < 500, f"{spoof}: {label} -> HTTP {st} (server error): {raw[:160]}"


def test_SRV_API_06_control_owner_session_is_allowed(srv, fresh_sessions):
    """Control for 06c: the same owner-only read works with David's own session,
    so Samual's refusals above are about identity, not a broken tool."""
    st, d = _call(srv, STALE, fresh_sessions("U1"))
    assert st == 200 and d.get("ok") and not _refused(str(d.get("result", ""))), \
        f"David's own session can't run find_stale_customers (HTTP {st}): {str(d)[:160]}"

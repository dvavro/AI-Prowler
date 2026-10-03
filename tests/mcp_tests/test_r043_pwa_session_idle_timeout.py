"""
tests/mcp_tests/test_r043_pwa_session_idle_timeout.py
================================================
R-043 (was gap G-10, 2026-09-27 — David chose 30 days): Jobs app sessions
(/pwa-login access tokens) end after 30 days without use. Every use restarts
the clock. Only /pwa-login sessions are tracked — OAuth connector tokens and
raw users.json tokens never time out here.

The rule lives in the pure helper _pwa_session_touch(); the server-mode
wiring (_srv_raw_token_for inside _run_server_mode) is checked at source
level so no session lookup can skip the timeout.
"""
from __future__ import annotations

import re

DAY = 86400


def test_R043_01_idle_limit_is_30_days(mcp_module):
    assert mcp_module.PWA_SESSION_IDLE_SECS == 30 * DAY


def test_R043_02_fresh_session_ok_and_clock_restarts(mcp_module):
    last = {"s": 1000.0}
    assert mcp_module._pwa_session_touch("s", last, now=1000.0 + 5 * DAY) == "ok"
    assert last["s"] == 1000.0 + 5 * DAY, "a use must restart the idle clock"


def test_R043_03_regular_use_never_expires(mcp_module):
    """Using the app every 29 days keeps the same session alive for a year."""
    last, t = {"s": 0.0}, 0.0
    for _ in range(13):
        t += 29 * DAY
        assert mcp_module._pwa_session_touch("s", last, now=t) == "ok"


def test_R043_04_idle_past_30_days_expires_and_is_removed(mcp_module):
    last = {"s": 0.0}
    assert mcp_module._pwa_session_touch("s", last, now=30 * DAY + 1) == "expired"
    assert "s" not in last
    # and it stays dead — the next use isn't a session any more
    assert mcp_module._pwa_session_touch("s", last, now=30 * DAY + 2) == "not_session"


def test_R043_05_exactly_30_days_is_still_ok(mcp_module):
    last = {"s": 0.0}
    assert mcp_module._pwa_session_touch("s", last, now=30 * DAY) == "ok"


def test_R043_06_untracked_tokens_never_time_out(mcp_module):
    """OAuth tokens / raw users.json tokens aren't in last_used → no timeout."""
    last = {"session": 0.0}
    for tok in ("oauth-token", "raw-users-json-token", "", None):
        assert mcp_module._pwa_session_touch(tok, last, now=10_000 * DAY) == "not_session"
    assert last == {"session": 0.0}, "checking other tokens must not touch the session"


def test_R043_07_custom_limit(mcp_module):
    last = {"s": 0.0}
    assert mcp_module._pwa_session_touch("s", last, now=11.0, idle_secs=10) == "expired"


# ── wiring (source level) ─────────────────────────────────────────────────────
def _server_mode_source(mcp_module) -> str:
    import inspect
    return inspect.getsource(mcp_module._run_server_mode)


def test_R043_08_every_session_lookup_goes_through_the_timeout(mcp_module):
    """Outside the helper itself and /pwa-logout, nothing may map a presented
    bearer with _srv_access_tokens.get(...) directly — that would skip R-043."""
    src = _server_mode_source(mcp_module)
    helper = src.split("def _srv_raw_token_for", 1)[1].split("\n    _local_host", 1)[0]
    rest = src.replace(helper, "")
    direct = [m.group(0) for m in re.finditer(r"_srv_access_tokens\.get\([^)]*\)", rest)]
    # /pwa-logout's own check is allowed (it only decides whether to end a session)
    direct = [d for d in direct if "_srv_lo_tok" not in d]
    assert not direct, f"session lookups bypassing the idle timeout: {direct}"
    assert src.count("_srv_raw_token_for(") >= 4, "helper + /pwa-api + photos + MCP handler"


def test_R043_09_login_starts_and_logout_clears_the_clock(mcp_module):
    src = _server_mode_source(mcp_module)
    assert "_srv_pwa_last_used[_srv_pl_access] = _srv_time.time()" in src
    assert "_srv_pwa_last_used.pop(_srv_lo_tok, None)" in src


def test_R043_10_expired_session_answers_401_with_clear_message(mcp_module):
    src = _server_mode_source(mcp_module)
    assert src.count("Session expired — please sign in again.") >= 2, "/pwa-api and /photos/upload"

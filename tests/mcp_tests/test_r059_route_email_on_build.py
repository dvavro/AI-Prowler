"""
R-059 (2026-09-29, David): "Email Route On Build" was a test gap — the E2E
pre-flight simply stopped the run when it was Enabled, so the automatic route
email was never exercised. Now:

  * suggest_route_schedule (the Route Today / Route Selected Date button) takes
    email_route: None (default) follows the setting; False = build without the
    automatic email this one time. The setting itself is never changed.
    (build_daily_route already had email_link.)
  * the E2E guard lets route builds through with the setting on, switching each
    build's auto-email off — except the ONE real route email per run (tier
    email/full/comms, sandbox date, recipient David/Vicki). A route email the
    server reports that the guard didn't allow is a violation.

Run: run_tests.bat tests\\mcp\\test_r059_route_email_on_build.py -v
"""
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# the E2E guard, loaded by path (its folder isn't put on sys.path: it has
# modules named api/data/app that must not shadow anything in this session)
import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location("e2e_safety_r059", _SRC / "tests" / "gui_jobs_e2e" / "safety.py")
safety = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(safety)

DAY = safety.SANDBOX_DATE
DAVID = "david.vavro1@gmail.com"


# ── the server switch ────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def seen(tmp_path, monkeypatch, mcp_mod):
    from db_access import init_db
    import db_route_ops
    p = str(tmp_path / "jobs.db")
    init_db(p)
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": p)
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(db_route_ops, "db_suggest_route_schedule", lambda *a, **k: "✅ route built")
    calls = {}

    def fake_link(result, db_path, route_date, crew, ctx, actor, email=False):
        calls["email"] = email
        return result
    monkeypatch.setattr(mcp_mod, "_with_route_link", fake_link)
    return calls


@pytest.mark.parametrize("arg,want_email", [
    ({}, True),                          # default: follow the setting (the helper decides)
    ({"email_route": None}, True),
    ({"email_route": False}, False),     # this call: no automatic email
    ({"email_route": "false"}, False),   # the way a JSON/voice caller may send it
    ({"email_route": True}, True),
])
def test_suggest_route_schedule_email_switch(arg, want_email, seen, mcp_mod):
    out = mcp_mod.suggest_route_schedule(route_date=DAY, ctx=None, **arg)
    assert out.startswith("✅")
    assert seen["email"] is want_email


def test_email_route_documented():
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("def suggest_route_schedule(")
    assert "email_route" in src[i:i + 6000]


# ── the E2E guard ────────────────────────────────────────────────────────────
@pytest.fixture
def guard(monkeypatch):
    monkeypatch.setenv("AIPROWLER_E2E_COMMS_TO", DAVID)
    g = safety.Guard(tier="safe")
    g.route_email_on, g.route_email_to = True, DAVID
    return g


def test_setting_off_changes_nothing(guard):
    guard.route_email_on = False
    a, note = guard.route_email_args("suggest_route_schedule", {"route_date": DAY})
    assert a == {"route_date": DAY} and note == ""


def test_safe_tier_switches_every_route_email_off(guard):
    for tool, key in safety.ROUTE_EMAIL_ARG.items():
        a, _ = guard.route_email_args(tool, {"route_date": DAY})
        assert a[key] is False
    assert guard.real_route_emails == 0 and guard.route_emails_suppressed == 2


def test_explicit_opt_out_is_left_alone(guard):
    a, note = guard.route_email_args("build_daily_route", {"route_date": DAY, "email_link": False})
    assert a["email_link"] is False and "already" in note and guard.route_emails_suppressed == 0


def test_email_tier_allows_exactly_one_to_david(guard):
    guard.tier = "email"
    a1, n1 = guard.route_email_args("suggest_route_schedule", {"route_date": DAY})
    a2, _ = guard.route_email_args("suggest_route_schedule", {"route_date": DAY})
    assert "email_route" not in a1 and "ONE real" in n1          # sent as the setting says
    assert a2["email_route"] is False                             # the second is switched off
    assert guard.real_route_emails == 1


def test_email_tier_never_to_anyone_else(guard):
    guard.tier = "email"
    guard.route_email_to = "someone.else@example.com"
    a, _ = guard.route_email_args("suggest_route_schedule", {"route_date": DAY})
    assert a["email_route"] is False
    guard.route_email_to = ""                                     # unknown recipient (server mode)
    a, _ = guard.route_email_args("suggest_route_schedule", {"route_date": DAY})
    assert a["email_route"] is False and guard.real_route_emails == 0


def test_email_tier_only_on_sandbox_dates(guard):
    guard.tier = "email"
    a, _ = guard.route_email_args("suggest_route_schedule", {"route_date": "2020-01-01"})
    assert a["email_route"] is False


def test_unallowed_route_email_reported_by_server_is_a_violation(guard):
    guard.route_email_args("suggest_route_schedule", {"route_date": DAY})     # switched off
    guard.note_result("suggest_route_schedule", "✅ built\n\n📧 " + safety.ROUTE_EMAILED_MARK + " x@y.z")
    v = guard.take_violations()
    assert v and "didn't allow" not in v[0]["reason"] and "switched off" in v[0]["reason"]


def test_allowed_route_email_is_not_a_violation(guard):
    guard.tier = "email"
    guard.route_email_args("suggest_route_schedule", {"route_date": DAY})
    guard.note_result("suggest_route_schedule", "✅ built\n\n📧 " + safety.ROUTE_EMAILED_MARK + " " + DAVID)
    assert guard.take_violations() == []


def test_ai_routing_with_auto_email_on_needs_the_one_email(guard):
    guard.tier = "full"
    d, _ = guard.check("start_ai_routing", {"route_date": DAY})
    assert d == "allow"
    guard.enforce("start_ai_routing", {"route_date": DAY}, "test")          # uses the one email
    d, why = guard.check("start_ai_routing", {"route_date": DAY})
    assert d == "record" and "auto-email" in why


def test_preflights_no_longer_stop_on_email_route_on_build():
    for rel in ("gui_jobs_e2e", "gui_jobs_e2e_server"):
        src = (_SRC / "tests" / rel / "conftest.py").read_text(encoding="utf-8")
        assert 'for key in ("Email Route On Build"' not in src
        # personal: the toggles snapshot tells the guard the real value (R-060);
        # server: marked on (the email would reach whoever built the route)
        assert ("guard.route_email_on = True" in src) or ("SettingsSwitch(api, guard" in src)
        assert "route_email_args(tool, args)" in src

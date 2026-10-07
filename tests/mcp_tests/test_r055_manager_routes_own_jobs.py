"""
R-055 (2026-09-28, David): whoever routes with no crew picked — the Jobs app's
Route Today / Email Route / AI Route, or the Route tab's default — gets a route
holding only the jobs assigned to THEM. Everyone may still SEE every job, and
may name another person to plan that person's day. First written for managers
and staff (Vicki); extended the same day to EVERY role, the owner included —
"the admin won't be doing the routing for the users, they self-serve it".
Field crew are unchanged (always their own, may not pick another).

Before: a manager's (and the owner's) blank crew meant every crew, so Vicki's
"Route Today" merged Samual's jobs into her route.

Run: run_tests.bat tests\\mcp\\test_r055_manager_routes_own_jobs.py -v
"""
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

VICKI, SAM, DAVID = "Vicki Vavro", "Samual Cronin", "David Vavro"
DAY = "2026-09-29"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def db(tmp_path, monkeypatch, mcp_mod):
    from db_access import init_db
    p = str(tmp_path / "jobs.db")
    init_db(p)
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": p)
    return p


def _as(mcp_mod, monkeypatch, role, name):
    monkeypatch.setattr(mcp_mod, "_current_user",
                        lambda ctx: None if role is None else {"id": "u", "name": name, "role": role,
                                                               "email": ""})


# ── the shared rule ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("role,name,asked,want", [
    ("manager", VICKI, "", VICKI),          # blank -> own
    ("staff", "Stan Staff", "", "Stan Staff"),
    ("manager", VICKI, SAM, SAM),           # may still pick someone else
    ("owner", DAVID, "", DAVID),            # owner blank = own too (extended R-055)
    ("owner", DAVID, VICKI, VICKI),
    ("field_crew", SAM, "", SAM),           # unchanged (R-039)
    (None, "", "", ""),                     # personal mode unchanged
])
def test_route_crew_for_caller(role, name, asked, want, db, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, role, name)
    crew, err = mcp_mod._route_crew_for_caller(None, db, asked)
    assert err == "" and crew == want


def test_field_crew_still_refused_for_another_crew(db, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, "field_crew", SAM)
    crew, err = mcp_mod._route_crew_for_caller(None, db, VICKI)
    assert err.startswith("❌")


# ── tools that use it receive the caller's own crew ──────────────────────────
@pytest.fixture
def spy(monkeypatch):
    import db_route_ops
    seen = {}
    monkeypatch.setattr(db_route_ops, "db_route_drive_matrix",
                        lambda db_path, route_date, crew, **k: seen.setdefault("matrix", crew) or "M")
    monkeypatch.setattr(db_route_ops, "db_apply_route_order",
                        lambda db_path, route_date, stop_order, crew, actor, **k: seen.setdefault("apply", crew) and "✅ ok")
    return seen


@pytest.mark.parametrize("role,name,want", [("manager", VICKI, VICKI), ("owner", DAVID, DAVID)])
def test_matrix_and_apply_with_blank_crew(role, name, want, db, spy, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, role, name)
    mcp_mod.get_route_drive_matrix(route_date=DAY, crew="", ctx=None)
    mcp_mod.apply_route_order(route_date=DAY, stop_order="JOB-0001", crew="", ctx=None)
    assert spy["matrix"] == want and spy["apply"] == want


@pytest.mark.parametrize("role,name,asked,want", [
    ("manager", VICKI, "", VICKI), ("manager", VICKI, SAM, SAM), ("owner", DAVID, "", DAVID),
    ("owner", DAVID, SAM, SAM),
])
def test_email_route_now_blank_crew(role, name, asked, want, db, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, role, name)
    seen = {}

    def fake(db_path, route_date, crew, caller_email, *a, **k):
        seen["crew"] = crew
        return "sent"
    monkeypatch.setattr(mcp_mod, "_email_route_results", fake)
    mcp_mod.email_route_now(route_date=DAY, crew=asked, ctx=None)
    assert seen["crew"] == want


def test_ai_route_blank_crew_is_manager_own_day():
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("def start_ai_routing(")
    body = src[i:i + 12000]
    j = body.index('if _role == "field_crew":')
    assert "elif not crew:" in body[j:j + 400] and "_route_default_crew(ctx)" in body[j:j + 400]


def test_app_route_tab_labels_my_jobs_for_manager():
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    assert "function _routeOwnDefaultName()" in html
    i = html.index("var _ownDefault = _routeOwnDefaultName();")
    seg = html[i:i + 1200]
    assert "My jobs (" in seg and "All crews" in seg
    assert "else if (_ownDefault) stops = stops.filter" in seg


def test_app_own_default_covers_every_server_role():
    """Extended R-055: the Route tab's "My jobs" default is for any signed-in
    server role (owner included), not only manager/staff."""
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    i = html.index("function _routeOwnDefaultName()")
    body = html[i:html.index("}", i) + 1]
    assert "_isFieldCrewRestricted()" in body and "state.serverMode" in body
    assert "'manager'" not in body and "'staff'" not in body

"""Route prescreen (2026-09-25) — prescreen_route_jobs / db_prescreen_route_jobs.

Found live 2026-09-24: two jobs at 1755 State Road 44 routed back-to-back put
the same address in the Google Maps link twice in a row, and the phone link
opened as a stop list instead of a route. The prescreen runs before Route
Today and Run AI Route and flags that (and other job-data problems) first.
"""
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DATE = "2026-09-24"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path / "ai_prowler_jobs.db"


def _make_job(mcp_mod, customer, street, lat=None, lon=None, **extra):
    cust = mcp_mod.create_customer({"Company Name": customer}, filepath="", backup=False, ctx=None)
    cust_id = cust.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {"CustomerID": cust_id, "Customer Name / Company": customer, "Service Date": DATE,
              "Street Address": street, "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168"}
    if lat is not None:
        fields["Latitude (AI Geocode)"] = lat
        fields["Longitude (AI Geocode)"] = lon
    fields.update(extra)
    out = mcp_mod.create_job(fields, filepath="", backup=False, ctx=None)
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _run(mcp_mod):
    res = json.loads(mcp_mod.prescreen_route_jobs(DATE, output="json", ctx=None))
    assert res["ok"] is True
    return res


def _codes(res):
    return [i["code"] for i in res["issues"]]


# ── helpers ──────────────────────────────────────────────────────────────────
def test_street_key_treats_abbreviations_as_same_place():
    from db_route_ops import _ps_street_key
    assert _ps_street_key("1755 State Road 44") == _ps_street_key("1755 State Rd. 44")
    assert _ps_street_key("1755 State Road 44") == _ps_street_key("1755 SR 44")
    assert _ps_street_key("500 Canal Street") == _ps_street_key("500 canal st")
    assert _ps_street_key("500 Canal St") != _ps_street_key("501 Canal St")


def test_minutes_parser_accepts_both_formats():
    from db_route_ops import _ps_minutes
    assert _ps_minutes("13:05") == 13 * 60 + 5
    assert _ps_minutes("1:05 PM") == 13 * 60 + 5
    assert _ps_minutes("12:00 am") == 0
    assert _ps_minutes("9am") == 9 * 60
    assert _ps_minutes("") is None
    assert _ps_minutes("noonish") is None


# ── the live bug ─────────────────────────────────────────────────────────────
def test_two_jobs_same_address_is_an_error_naming_both(env, mcp_mod):
    a = _make_job(mcp_mod, "SR44 Auto Repair", "1755 State Road 44", 29.03, -80.95)
    b = _make_job(mcp_mod, "SR44 Auto Repair", "1755 State Road 44", 29.03, -80.95)
    _make_job(mcp_mod, "Pine Tree Cafe", "1730 State Road 44", 29.031, -80.948)
    res = _run(mcp_mod)
    dup = [i for i in res["issues"] if i["code"] == "DUPLICATE_ADDRESS"]
    assert len(dup) == 1
    assert dup[0]["severity"] == "error"
    assert sorted(dup[0]["job_ids"]) == sorted([a, b])      # the cafe next door is NOT flagged
    assert "Possible duplicate job" in dup[0]["title"]      # same customer -> duplicate entry
    assert res["errors"] >= 1


def test_same_place_written_differently_is_caught(env, mcp_mod):
    _make_job(mcp_mod, "Shop A", "1755 State Road 44", 29.03, -80.95)
    _make_job(mcp_mod, "Shop B", "1755 SR 44", 29.03, -80.95)
    res = _run(mcp_mod)
    dup = [i for i in res["issues"] if i["code"] == "DUPLICATE_ADDRESS"]
    assert len(dup) == 1 and "same address" in dup[0]["title"]   # different customers


def test_neighbors_geocoded_meters_apart_are_not_duplicates(env, mcp_mod):
    # Found live 2026-09-25: these two real 9/25 jobs geocoded ~6 m apart and
    # were flagged "same address". Different house numbers = different stops.
    _make_job(mcp_mod, "SR44 Auto Repair", "1755 State Road 44", 29.0143984, -80.9421393)
    _make_job(mcp_mod, "Pine Tree Cafe", "1730 State Road 44", 29.0144235, -80.9420821)
    res = _run(mcp_mod)
    assert "DUPLICATE_ADDRESS" not in _codes(res)


def test_same_address_is_caught_even_when_geocodes_differ(env, mcp_mod):
    # The address decides, not the map point — both directions.
    _make_job(mcp_mod, "Shop A", "1755 State Road 44", 29.0143984, -80.9421393)
    _make_job(mcp_mod, "Shop B", "1755 SR 44", 29.0200000, -80.9500000)
    assert "DUPLICATE_ADDRESS" in _codes(_run(mcp_mod))


def test_job_without_street_is_an_error_and_is_never_routed(env, mcp_mod):
    from db_route_ops import db_get_jobs_for_route
    j = _make_job(mcp_mod, "No Street", "", 29.02, -80.92)      # city/state/ZIP only
    res = _run(mcp_mod)
    hit = [i for i in res["issues"] if i["code"] == "NO_ADDRESS"]
    assert hit and hit[0]["job_ids"] == [j] and hit[0]["severity"] == "error"
    assert j not in [x["job_id"] for x in db_get_jobs_for_route(str(env), DATE)]


def test_clean_day_has_no_issues(env, mcp_mod):
    _make_job(mcp_mod, "Riverside Grill", "300 Riverside Dr", 29.02, -80.92)
    _make_job(mcp_mod, "Downtown Boutique", "500 Canal St", 29.025, -80.925)
    res = _run(mcp_mod)
    assert res["issues"] == [] and res["errors"] == 0 and res["warnings"] == 0
    assert "no problems found" in mcp_mod.prescreen_route_jobs(DATE, ctx=None)


# ── other checks ─────────────────────────────────────────────────────────────
def test_job_without_map_location_is_an_error(env, mcp_mod):
    j = _make_job(mcp_mod, "No Geo", "4711 S Atlantic Ave")
    res = _run(mcp_mod)
    hit = [i for i in res["issues"] if i["code"] == "NOT_GEOCODED"]
    assert hit and hit[0]["job_ids"] == [j] and hit[0]["severity"] == "error"


def test_errors_sort_before_warnings_and_text_output_lists_them(env, mcp_mod):
    _make_job(mcp_mod, "Dup", "1755 State Road 44", 29.03, -80.95)
    _make_job(mcp_mod, "Dup", "1755 State Road 44", 29.03, -80.95)
    res = _run(mcp_mod)
    sev = [i["severity"] for i in res["issues"]]
    assert sev == sorted(sev, key=lambda s: 0 if s == "error" else 1)
    txt = mcp_mod.prescreen_route_jobs(DATE, ctx=None)
    assert txt.startswith("🔎 Prescreen") and "❌" in txt


def test_tool_is_on_both_pwa_allow_lists(mcp_mod):
    src = Path(mcp_mod.__file__).read_text(encoding="utf-8")
    assert src.count('"prescreen_route_jobs"') >= 2          # personal-mode + server-mode


def test_pwa_runs_prescreen_before_both_route_buttons():
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    rt = html[html.index("async function routeToday("):]
    assert rt.index("_prescreenRoute(") < rt.index("mcpCall('suggest_route_schedule'")
    ai = html[html.index("async function runAiRouting("):]
    assert ai.index("_prescreenRoute(") < ai.index("mcpCall('start_ai_routing'")
    assert 'id="routePrescreen"' in html and 'id="jobsPrescreen"' in html
    assert 'data-jobid="${j.id}"' in html                   # job cards findable by warning


def test_route_page_lists_unrouted_jobs_instead_of_no_route():
    # 2026-09-25: jobs moved to a date with no route yet showed "5 jobs" in the
    # header but "No route for this date" under the map.
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    assert "state.route.dayJobs = jobRows" in html
    body = html[html.index("function renderRouteMapAndList("):]
    empty = body[:body.index("} else {\n    // Start/End Address bookends")]
    assert "state.route.dayJobs" in empty and "not routed yet" in empty
    assert "dayJobs.map(_unroutedJobRowHtml)" in empty           # shared row renderer...
    helper = html[html.index("function _unroutedJobRowHtml("):html.index("function renderRouteMapAndList(")]
    assert 'data-jobid="' in helper                              # ...carries data-jobid for prescreen
    assert "No route for this date" not in empty


def test_route_page_lists_jobs_added_after_the_route_was_built():
    # 2026-09-25: JOB-0030/0031 were added to a date that already had a route
    # and didn't appear anywhere on the Route page.
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    body = html[html.index("function renderRouteMapAndList("):]
    assert "not on this route" in body
    assert "notOnRoute.map(_unroutedJobRowHtml)" in body
    assert "function _unroutedJobRowHtml(" in html
    # drag-to-reorder must only count real stops, not the unrouted job rows
    assert "querySelectorAll('.route-stop[data-stopid]')" in html

"""Fixes for bugs found in live testing on 2026-09-25 (R-010 .. R-014).

R-010  Price-list / Settings uniqueness was case-sensitive ('ztest-win' was
       accepted beside 'ZTEST-WIN').
R-011  The shared edit lookup (update_job_spreadsheet -> db_update_row) used
       LIKE '%value%' ... LIMIT 1: it silently edited the FIRST row whose key
       merely contained the text, even when an exact match existed, and treated
       '_' / '%' as wildcards.
R-012  'abc' and negative amounts were accepted as prices.
R-013  When every job left a day's route, its Start/End "Home" rows were
       orphaned.
R-014  Removing the last job stop still said "Route re-planned…; phone link
       updated".
"""
import sqlite3
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


def _price(mcp_mod, code, **extra):
    fields = {"Service Code": code, "Name": f"Test {code}", "Base Price ($)": 100}
    fields.update(extra)
    return mcp_mod.create_service_pricing(fields, filepath="", backup=False, ctx=None)


def _edit_price(mcp_mod, code, updates):
    return mcp_mod.update_job_spreadsheet(code, updates, id_column="Service Code",
                                          sheet_name="Services_Pricing",
                                          filepath="", backup=False, ctx=None)


def _prices(db):
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        return {r["service_code"]: dict(r) for r in con.execute("SELECT * FROM service_pricing")}
    finally:
        con.close()


def _insert_price_raw(db, code, price):
    """Simulates a duplicate that already exists in an older database (create
    now refuses it)."""
    con = sqlite3.connect(str(db))
    try:
        con.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES (?, ?, ?)",
                    (code, f"Raw {code}", price))
        con.commit()
    finally:
        con.close()


# ── R-010: uniqueness ignores case ───────────────────────────────────────────
def test_R_010_price_code_duplicate_by_case_is_refused(env, mcp_mod):
    assert _price(mcp_mod, "ZTEST-WIN").startswith("✅")
    out = _price(mcp_mod, "ztest-win")
    assert out.startswith("❌") and "already exists" in out and "ZTEST-WIN" in out
    assert list(_prices(env)) == ["ZTEST-WIN"]


def test_R_010_setting_duplicate_by_case_is_refused(env, mcp_mod):
    first = mcp_mod.create_setting({"Setting": "ZTEST Key", "Value": "1"}, filepath="", backup=False, ctx=None)
    assert first.startswith("✅")
    out = mcp_mod.create_setting({"Setting": "ztest key", "Value": "2"}, filepath="", backup=False, ctx=None)
    assert out.startswith("❌") and "already exists" in out


# ── R-011: edits hit exactly the row meant, or refuse ────────────────────────
def test_R_011_exact_code_wins_over_case_variant(env, mcp_mod):
    _price(mcp_mod, "ZTEST-WIN")
    _insert_price_raw(env, "ztest-win", 999)             # legacy duplicate
    out = _edit_price(mcp_mod, "ztest-win", {"Notes": "hit me"})
    assert out.startswith("✅")
    p = _prices(env)
    assert p["ztest-win"]["notes"] == "hit me"
    assert (p["ZTEST-WIN"]["notes"] or "") != "hit me"   # the live bug: this row got it


def test_R_011_code_1_does_not_hit_code_10(env, mcp_mod):
    _price(mcp_mod, "10", **{"Base Price ($)": 10})
    _price(mcp_mod, "1", **{"Base Price ($)": 1})
    assert _edit_price(mcp_mod, "1", {"Base Price ($)": 111}).startswith("✅")
    p = _prices(env)
    assert p["1"]["base_price"] == 111 and p["10"]["base_price"] == 10


def test_R_011_ambiguous_partial_match_is_refused_and_changes_nothing(env, mcp_mod):
    _price(mcp_mod, "WIN-IN")
    _price(mcp_mod, "WIN-OUT")
    out = _edit_price(mcp_mod, "WIN", {"Notes": "which one?"})
    assert out.startswith("❌") and "more than one" in out
    assert "WIN-IN" in out and "WIN-OUT" in out
    assert all((r["notes"] or "") != "which one?" for r in _prices(env).values())


def test_R_011_unique_partial_match_still_works(env, mcp_mod):
    _price(mcp_mod, "PRESS-DRIVEWAY")
    assert _edit_price(mcp_mod, "driveway", {"Notes": "found"}).startswith("✅")
    assert _prices(env)["PRESS-DRIVEWAY"]["notes"] == "found"


def test_R_011_underscore_is_not_a_wildcard(env, mcp_mod):
    _price(mcp_mod, "WIN-EXT")
    out = _edit_price(mcp_mod, "WIN_EXT", {"Notes": "wildcard?"})
    assert out.startswith("❌") and "No row found" in out
    assert (_prices(env)["WIN-EXT"]["notes"] or "") != "wildcard?"


def test_R_011_job_edit_by_customer_name_refuses_when_two_jobs_match(env, mcp_mod):
    cust = mcp_mod.create_customer({"Company Name": "ZTEST Twin"}, filepath="", backup=False, ctx=None)
    cid = cust.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    for d in ("2026-10-01", "2026-10-02"):
        mcp_mod.create_job({"CustomerID": cid, "Customer Name / Company": "ZTEST Twin",
                            "Service Date": d}, filepath="", backup=False, ctx=None)
    out = mcp_mod.update_job_spreadsheet("ZTEST Twin", {"Notes": "x"}, id_column="Customer Name / Company",
                                         filepath="", backup=False, ctx=None)
    assert out.startswith("❌") and "more than one" in out and "JOB-" in out   # lists JobIDs to pick from


# ── R-012: price numbers ─────────────────────────────────────────────────────
@pytest.mark.parametrize("field", ["Base Price ($)", "Min Charge ($)", "Commission Multiplier"])
def test_R_012_text_price_refused_on_edit(env, mcp_mod, field):
    _price(mcp_mod, "ZTEST-NUM")
    out = _edit_price(mcp_mod, "ZTEST-NUM", {field: "abc"})
    assert out.startswith("❌") and "must be a number" in out


def test_R_012_negative_and_text_refused_on_create(env, mcp_mod):
    assert _price(mcp_mod, "ZTEST-NEG", **{"Min Charge ($)": -50}).startswith("❌")
    assert _price(mcp_mod, "ZTEST-TXT", **{"Base Price ($)": "abc"}).startswith("❌")
    assert _prices(env) == {}


def test_R_012_friendly_number_formats_are_stored_as_numbers(env, mcp_mod):
    assert _price(mcp_mod, "ZTEST-FMT", **{"Base Price ($)": "$1,200"}).startswith("✅")
    assert _prices(env)["ZTEST-FMT"]["base_price"] == 1200
    assert _edit_price(mcp_mod, "ZTEST-FMT", {"Min Charge ($)": ""}).startswith("✅")   # blank clears
    assert _prices(env)["ZTEST-FMT"]["min_charge"] is None


# ── R-013 / R-014: orphaned Home rows, "route is now empty" ─────────────────
def _job(mcp_mod, name, street):
    cust = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=None)
    cid = cust.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    out = mcp_mod.create_job({"CustomerID": cid, "Customer Name / Company": name, "Service Date": DATE,
                              "Street Address": street, "City": "New Smyrna Beach", "State": "FL",
                              "ZIP": "32168", "Latitude (AI Geocode)": 29.02,
                              "Longitude (AI Geocode)": -80.92}, filepath="", backup=False, ctx=None)
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _route_with_home(db, job_ids):
    from db_route_ops import db_write_route_stops
    stops = [{"crew": "", "job_id": j, "cust_id": None, "address": f"{i} Main St", "lat": 29.02,
              "lon": -80.92, "arrival": "08:00", "map_url": None} for i, j in enumerate(job_ids, 1)]
    stops.append({"crew": "", "job_id": None, "cust_id": None, "address": "Home", "lat": 29.05,
                  "lon": -80.99, "arrival": "17:00", "map_url": None})
    db_write_route_stops(str(db), DATE, stops, "test", single_crew=True)


def _rows(db):
    con = sqlite3.connect(str(db))
    try:
        return [(r[0], r[1]) for r in con.execute(
            "SELECT id, COALESCE(job_id, '') FROM route_stops WHERE route_date = ? ORDER BY stop_number", (DATE,))]
    finally:
        con.close()


def _cancel(mcp_mod, jid):
    return mcp_mod.update_job_spreadsheet(jid, {"Job Status": "Cancelled"}, id_column="JobID (JOB-####)",
                                          filepath="", backup=False, ctx=None)


def test_R_013_home_row_removed_when_last_job_leaves(env, mcp_mod):
    a = _job(mcp_mod, "ZTEST A", "1 Main St")
    _route_with_home(env, [a])
    assert [j for _, j in _rows(env)] == [a, ""]
    assert _cancel(mcp_mod, a).startswith("✅")
    assert _rows(env) == []                                      # Home row gone too


def test_R_013_home_row_kept_while_a_job_remains(env, mcp_mod):
    a = _job(mcp_mod, "ZTEST A", "1 Main St")
    b = _job(mcp_mod, "ZTEST B", "2 Main St")
    _route_with_home(env, [a, b])
    _cancel(mcp_mod, a)
    assert [j for _, j in _rows(env)] == [b, ""]


def test_R_013_deleting_the_last_job_clears_its_home_row(env, mcp_mod):
    a = _job(mcp_mod, "ZTEST A", "1 Main St")
    _route_with_home(env, [a])
    _cancel(mcp_mod, a)
    _route_with_home(env, [])                                   # (cancel already cleared it; rebuild a stray Home)
    mcp_mod.delete_job(a, confirm=True, ctx=None)
    assert _rows(env) == []


def test_R_014_removing_last_stop_says_route_is_empty(env, mcp_mod, monkeypatch):
    a = _job(mcp_mod, "ZTEST A", "1 Main St")
    _route_with_home(env, [a])
    calls = []
    monkeypatch.setattr(mcp_mod, "replan_route_day",
                        lambda *a_, **k: calls.append(1) or "✅ re-planned")
    stop_id = _rows(env)[0][0]
    out = mcp_mod.delete_route_stop(str(stop_id), confirm=True, ctx=None)
    assert out.startswith("✅") and "now empty" in out and "re-planned" not in out
    assert calls == [] and _rows(env) == []


def test_R_014_removing_a_middle_stop_still_replans(env, mcp_mod, monkeypatch):
    a = _job(mcp_mod, "ZTEST A", "1 Main St")
    b = _job(mcp_mod, "ZTEST B", "2 Main St")
    _route_with_home(env, [a, b])
    calls = []
    monkeypatch.setattr(mcp_mod, "replan_route_day",
                        lambda *a_, **k: calls.append(1) or "✅ re-planned")
    out = mcp_mod.delete_route_stop(str(_rows(env)[0][0]), confirm=True, ctx=None)
    assert "phone link updated" in out and calls == [1]
    assert [j for _, j in _rows(env)] == [b, ""]

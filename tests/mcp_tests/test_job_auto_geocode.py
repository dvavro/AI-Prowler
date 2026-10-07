"""R-022 (found by the Jobs-app E2E suite, 2026-09-26): a job added through the
app's own + Add form was never geocoded, so Route Selected Date / AI Route
couldn't place it; and editing a job's address kept the OLD coordinates.
Now a job save looks the address up when needed. The lookup is faked here —
these tests never touch the internet."""
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    import db_write_ops as dbw
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    calls = []

    def fake_geocode(addr):
        calls.append(addr)
        return None if "NOWHERE" in addr else (29.0 + len(calls) / 1000, -80.9)
    monkeypatch.setattr(dbw, "_geocode", fake_geocode)
    monkeypatch.setattr(dbw, "AUTO_GEOCODE_ENABLED", True)
    return {"db": tmp_path / "ai_prowler_jobs.db", "calls": calls}


def _cust(mcp_mod):
    out = mcp_mod.create_customer({"Company Name": "Geo Test"}, filepath="", backup=False, ctx=None)
    return out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def _job(mcp_mod, **extra):
    f = {"CustomerID": _cust(mcp_mod), "Customer Name / Company": "Geo Test", "Service Date": "2026-10-01",
         "Street Address": "210 Sams Ave", "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168"}
    f.update(extra)
    out = mcp_mod.create_job(f, filepath="", backup=False, ctx=None)
    return out, out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _coords(db, jid):
    con = sqlite3.connect(str(db))
    try:
        return con.execute("SELECT latitude, longitude FROM jobs WHERE job_id = ?", (jid,)).fetchone()
    finally:
        con.close()


def _edit(mcp_mod, jid, updates):
    return mcp_mod.update_job_spreadsheet(jid, updates, id_column="JobID (JOB-####)",
                                          filepath="", backup=False, ctx=None)


def test_new_job_without_coordinates_gets_a_map_location(env, mcp_mod):
    out, jid = _job(mcp_mod)
    assert out.startswith("✅") and "Map location found" in out
    lat, lon = _coords(env["db"], jid)
    assert lat is not None and lon is not None
    assert env["calls"] == ["210 Sams Ave, New Smyrna Beach, FL 32168"]


def test_new_job_that_already_has_coordinates_is_not_looked_up(env, mcp_mod):
    _, jid = _job(mcp_mod, **{"Latitude (AI Geocode)": 29.5, "Longitude (AI Geocode)": -80.5})
    assert env["calls"] == [] and _coords(env["db"], jid) == (29.5, -80.5)


def test_editing_other_fields_with_the_same_address_does_not_look_up_again(env, mcp_mod):
    _, jid = _job(mcp_mod)
    n = len(env["calls"])
    # the app's edit form ALWAYS resends the address fields, unchanged
    assert _edit(mcp_mod, jid, {"Service Details / Notes": "gate code 42", "Street Address": "210 Sams Ave",
                                "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168"}).startswith("✅")
    assert len(env["calls"]) == n


def test_changing_the_address_replaces_the_old_location(env, mcp_mod):
    _, jid = _job(mcp_mod)
    old = _coords(env["db"], jid)
    assert _edit(mcp_mod, jid, {"Street Address": "105 S Riverside Dr"}).startswith("✅")
    assert env["calls"][-1].startswith("105 S Riverside Dr")
    assert _coords(env["db"], jid) != old


def test_a_failed_lookup_never_blocks_the_save(env, mcp_mod):
    out, jid = _job(mcp_mod, **{"Street Address": "1 NOWHERE Rd"})
    assert out.startswith("✅") and "Map location found" not in out
    assert _coords(env["db"], jid) == (None, None)


def test_switched_off_under_the_offline_test_runner(env, mcp_mod, monkeypatch):
    import db_write_ops as dbw
    monkeypatch.setattr(dbw, "AUTO_GEOCODE_ENABLED", False)
    _, jid = _job(mcp_mod)
    assert env["calls"] == [] and _coords(env["db"], jid) == (None, None)


# ── R-023: Nominatim drops about half of close-together connections ──────────
class _Resp:
    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


def _flaky_get(fail_times, answer):
    state = {"n": 0}

    def get(url, *a, **k):
        state["n"] += 1
        if state["n"] <= fail_times:
            raise ConnectionResetError(10054, "An existing connection was forcibly closed by the remote host")
        return _Resp(answer)
    return get, state


def test_R_023_geocode_retries_a_dropped_connection(monkeypatch):
    import db_write_ops as dbw
    get, state = _flaky_get(2, [{"lat": "29.02", "lon": "-80.92"}])
    monkeypatch.setattr(dbw.requests, "get", get)
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert dbw._geocode("105 S Riverside Dr, New Smyrna Beach, FL 32168") == (29.02, -80.92)
    assert state["n"] == 3


def test_R_023_geocode_gives_up_after_three_drops(monkeypatch):
    import db_write_ops as dbw
    get, state = _flaky_get(99, [])
    monkeypatch.setattr(dbw.requests, "get", get)
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert dbw._geocode("anywhere") is None and state["n"] == 3


def test_R_023_not_found_is_not_retried(monkeypatch):
    import db_write_ops as dbw
    get, state = _flaky_get(0, [])
    monkeypatch.setattr(dbw.requests, "get", get)
    assert dbw._geocode("1 NOWHERE Rd") is None and state["n"] == 1


def test_R_023_geocode_address_tool_retries_too(monkeypatch, mcp_mod):
    import requests
    get, state = _flaky_get(1, [{"lat": "29.02", "lon": "-80.92", "display_name": "105, South Riverside Drive"}])
    monkeypatch.setattr(requests, "get", get)
    monkeypatch.setattr("time.sleep", lambda s: None)
    out = mcp_mod.geocode_address("105 S Riverside Dr, New Smyrna Beach, FL 32168")
    assert out.startswith("📍") and state["n"] == 2

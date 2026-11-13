"""Per-trade sheet activation for takeoff: the toggle, plan-set states, and the auto-run honouring them."""
import json
from pathlib import Path

import pytest

from estimator.api import autorun_api
from estimator.context import personal_context
from estimator.estimating import service
from estimator.takeoff import sheet_trades

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
NOW = "2026-11-12T10:00:00+00:00"


@pytest.fixture
def plans(db):
    """An estimate with one plan set and two sheets: an elevation and the foundation plan."""
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Shed slab")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    elev = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                      " VALUES ('default', ?, 1, 'A-201', 'LEFT SIDE ELEVATION')", (ps,)).lastrowid
    found = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                       " VALUES ('default', ?, 2, 'S-101', 'FOUNDATION PLAN')", (ps,)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Foundation plan', '84.3225', 0)", (found,)).lastrowid
    return {"est": est, "ps": ps, "elev": elev, "found": found, "vp": vp}


def _walls(db, vp, sheet, rects):
    for (x1, y1, x2, y2) in rects.values():
        for (ax, ay), (bx, by) in [((x1, y1), (x2, y1)), ((x2, y1), (x2, y2)),
                                   ((x2, y2), (x1, y2)), ((x1, y2), (x1, y1))]:
            db.execute(
                "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json, source)"
                " VALUES ('default', ?, ?, 'wall', ?, 'cad')",
                (sheet, vp, json.dumps({"type": "line", "points": [[ax, ay], [bx, by]]})))


def _states(call, ps, module="concrete"):
    got = call("GET", f"{API}/plan-sets/{ps}?module_id={module}")
    assert got.status == 200, got.json()
    assert got.json()["trade_module_id"] == module
    return {s["id"]: s["active_for_trade"] for s in got.json()["sheets"]}


# ---------------------------------------------------------------- toggle

def test_toggle_off_and_on_via_api(call, db, plans):                                        # ST-A01
    assert _states(call, plans["ps"]) == {plans["elev"]: True, plans["found"]: True}
    r = call("POST", f"{API}/sheets/{plans['elev']}/trade-active",
             {"module_id": "concrete", "active": False})
    assert r.status == 200, r.json()
    assert r.json() == {"ok": True, "sheet_id": plans["elev"], "module_id": "concrete", "active": False}
    assert sheet_trades.is_active(db, "default", plans["elev"], "concrete") is False
    assert sheet_trades.is_active(db, "default", plans["found"], "concrete") is True
    assert _states(call, plans["ps"]) == {plans["elev"]: False, plans["found"]: True}
    r = call("POST", f"{API}/sheets/{plans['elev']}/trade-active",
             {"module_id": "concrete", "active": True})
    assert r.status == 200 and r.json()["active"] is True
    assert _states(call, plans["ps"]) == {plans["elev"]: True, plans["found"]: True}


def test_plan_set_without_a_trade_has_no_active_flags(call, plans):                         # ST-A02
    got = call("GET", f"{API}/plan-sets/{plans['ps']}").json()
    assert got["sheets"] and all("active_for_trade" not in s for s in got["sheets"])
    assert "trade_module_id" not in got


def test_toggle_unknown_sheet_is_404(call):                                                 # ST-A03
    r = call("POST", f"{API}/sheets/9999/trade-active", {"module_id": "concrete", "active": False})
    assert r.status == 404, r.json()


def test_toggle_unknown_module_is_400(call, plans):                                         # ST-A04
    r = call("POST", f"{API}/sheets/{plans['elev']}/trade-active",
             {"module_id": "nope", "active": False})
    assert r.status == 400, r.json()
    assert "no trade named 'nope'" in r.json()["message"]
    assert call("GET", f"{API}/plan-sets/{plans['ps']}?module_id=nope").status == 400


def test_toggle_needs_a_boolean(call, plans):                                               # ST-A05
    assert call("POST", f"{API}/sheets/{plans['elev']}/trade-active",
                {"module_id": "concrete"}).status == 400
    assert call("POST", f"{API}/sheets/{plans['elev']}/trade-active",
                {"module_id": "concrete", "active": "yes"}).status == 400


def test_reviewer_cannot_toggle(call, plans, session_for):                                  # ST-A06
    r = call("POST", f"{API}/sheets/{plans['elev']}/trade-active",
             {"module_id": "concrete", "active": False}, headers=session_for("reviewer"))
    assert r.status == 403, r.json()


def test_no_row_means_active_and_list_for_plan_set(db, plans):                              # ST-A07
    ctx = personal_context()
    assert sheet_trades.is_active(db, "default", plans["elev"], "concrete") is True
    assert sheet_trades.inactive_for_sheet(db, "default", plans["elev"]) == []
    assert sheet_trades.list_for_plan_set(db, "default", plans["ps"], "concrete") == [
        {"sheet_id": plans["elev"], "active": True}, {"sheet_id": plans["found"], "active": True}]
    sheet_trades.set_active(db, ctx, plans["elev"], "concrete", False)
    assert sheet_trades.inactive_for_sheet(db, "default", plans["elev"]) == ["concrete"]
    assert sheet_trades.list_for_plan_set(db, "default", plans["ps"], "concrete") == [
        {"sheet_id": plans["elev"], "active": False}, {"sheet_id": plans["found"], "active": True}]
    with pytest.raises(Exception, match="no trade named"):
        sheet_trades.list_for_plan_set(db, "default", plans["ps"], "nope")


def test_sheet_carries_inactive_trades(call, plans):                                        # ST-A08
    assert call("GET", f"{API}/sheets/{plans['elev']}").json()["inactive_trades"] == []
    call("POST", f"{API}/sheets/{plans['elev']}/trade-active",
         {"module_id": "concrete", "active": False})
    got = call("GET", f"{API}/sheets/{plans['elev']}").json()
    assert got["inactive_trades"] == ["concrete"]
    assert got["sheet"]["id"] == plans["elev"]              # the sheet itself still opens


# ---------------------------------------------------------------- the auto-run honours it

def test_auto_run_refuses_a_deactivated_sheet(call, db, plans):                             # ST-A09
    call("POST", f"{API}/sheets/{plans['found']}/trade-active",
         {"module_id": "concrete", "active": False})
    r = call("POST", f"{API}/auto-run", {"estimate_id": plans["est"], "sheet_id": plans["found"],
                                         "viewport_id": plans["vp"], "module_id": "concrete"})
    assert r.status == 400, r.json()
    assert "switched off for Concrete" in r.json()["message"]
    assert db.execute("SELECT COUNT(*) FROM auto_runs").fetchone()[0] == 0   # no run was started


def test_candidates_empty_for_a_deactivated_sheet(call, db, plans):                         # ST-A10
    _walls(db, plans["vp"], plans["found"], {"slab": (0, 0, 12, 10)})
    before = call("GET", f"{API}/viewports/{plans['vp']}/slab-candidates").json()
    assert len(before["candidates"]) == 1 and before["calibrated"] is True
    call("POST", f"{API}/sheets/{plans['found']}/trade-active",
         {"module_id": "concrete", "active": False})
    after = call("GET", f"{API}/viewports/{plans['vp']}/slab-candidates").json()
    assert after["candidates"] == [] and after["calibrated"] is True


def test_rerun_refuses_a_deactivated_sheet(call, db, plans):                                # ST-A11
    ctx = personal_context()
    rid = autorun_api.create_run(db, ctx, plans["est"], plans["found"], plans["vp"], "concrete", [])
    autorun_api.update_run(db, rid, status="done", step="done")
    call("POST", f"{API}/sheets/{plans['found']}/trade-active",
         {"module_id": "concrete", "active": False})
    r = call("POST", f"{API}/auto-run/{rid}/rerun", {})
    assert r.status == 400, r.json()
    assert "switched off" in r.json()["message"]


# ---------------------------------------------------------------- UI markers

def test_plan_set_detail_has_the_trade_selector_and_toggle():                               # ST-A12
    app = (WEB / "app.js").read_text(encoding="utf-8")
    for needle in ('id: "plan-trade"', "sheet-trade-toggle", "/trade-active", "active_for_trade",
                   "Takeoff for", "planTradeId"):
        assert needle in app, needle


def test_blueprint_review_marks_a_deactivated_sheet():                                      # ST-A13
    review = (WEB / "review.js").read_text(encoding="utf-8")
    for needle in ("inactiveTrades", "inactive_trades", "bp-auto-off", "bp-guide-off-",
                   "switched off for Concrete"):
        assert needle in review, needle

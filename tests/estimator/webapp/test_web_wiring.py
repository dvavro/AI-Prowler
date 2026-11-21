"""The Wiring run's web calls (Measure screen, 2026-11-19, David): see what it would use, run it, download the DXF."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("ezdxf")
from estimator.api import auth  # noqa: E402
from estimator.context import personal_context  # noqa: E402
from estimator.drawing_model import engine, store  # noqa: E402
from estimator.estimating import service  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from test_wiring import _panel, _plan  # noqa: E402

API = "/estimator-api"


@pytest.fixture
def job(db, tmp_path):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Wired house")
    service.add_trade(db, ctx, est["id"], "electrical", est.get("rev", 1))
    for f in (_plan(tmp_path), _panel(tmp_path)):
        ps = store.upload(db, ctx, est["id"], f, confirm=True)["plan_set_id"]
        engine.start(db, ctx, ps, confirm=True)
    db.commit()
    return est["id"]


def test_wiring_status_run_and_download(call, job):                                      # WRW-01
    r = call("GET", f"{API}/wiring/{job}").json()
    assert r["run"] is None and r["can_run"] is True
    assert r["sources"]["plan"]["name"] == "plan.dxf" and r["sources"]["panel"]["name"] == "panel.dxf"
    assert "path" not in r["sources"]["plan"]                                            # no file paths to the browser
    assert call("GET", f"{API}/wiring/{job}/dxf").status == 404                         # nothing run yet

    r = call("POST", f"{API}/wiring/{job}", {"settings": {"ceiling_ft": 9, "route": {"0": "walls"}},
                                              "overrides": {"OUTLET@12.0,0.5": "C-2"}})
    assert r.status == 200, r.body
    run = r.json()["run"]
    assert run["settings"]["route"] == {"0": "walls"} and run["overrides"] == {"OUTLET@12.0,0.5": "C-2"}
    assert len(run["measurement_ids"]) == 6 and run["overlay"]["circuits"]   # 4 cable sizes + circuit/receptacle counts
    assert call("GET", f"{API}/wiring/{job}").json()["run"]["ran_at"] == run["ran_at"]

    d = call("GET", f"{API}/wiring/{job}/dxf")
    assert d.status == 200 and d.content_type == "application/dxf"
    assert 'filename="estimate_' in d.headers["Content-Disposition"] and b"E-WIRE-SCHEDULE" in d.body
    # 2026-11-20 (David): the wiring schematic - the panel and every circuit's conductors - is a second download.
    assert run["schematic"] is True
    s = call("GET", f"{API}/wiring/{job}/schematic")
    assert s.status == 200 and s.content_type == "application/dxf"
    assert f'filename="estimate_{job}_schematic.dxf"' in s.headers["Content-Disposition"]
    assert b"WIRING SCHEMATIC" in s.body and b"S-NEUTRAL" in s.body


def test_routing_options_and_saved_defaults(call, job):                                  # WRW-04
    """2026-11-21 (David: "I like the user setting defaults for routing wires"): the options box opens with the
    project's settings; Save as my defaults keeps them for every new project."""
    from estimator.takeoff import wiring_run
    try:
        o = call("GET", f"{API}/wiring/{job}").json()["options"]
        assert o["from"] == "built in" and o["current"]["foundation"] == "basement"
        assert o["current"]["outlets_via"] == "walls" and o["builtin"]["panel_in_basement"] is True
        r = call("POST", f"{API}/wiring/defaults", {"settings": {"foundation": "crawlspace", "ceiling_ft": 8}})
        assert r.status == 200, r.body
        assert r.json()["saved"] == {"foundation": "crawlspace", "ceiling_ft": 8.0}
        assert call("GET", f"{API}/wiring/defaults").json()["from"] == "your defaults"
        assert call("GET", f"{API}/wiring/{job}").json()["options"]["current"]["foundation"] == "crawlspace"
        bad = call("POST", f"{API}/wiring/defaults", {"settings": {"foundation": "mud"}})
        assert bad.status == 400 and "foundation" in bad.json()["message"]
    finally:
        wiring_run._defaults_path(personal_context()).unlink(missing_ok=True)


def test_bad_settings_are_a_400(call, job):                                              # WRW-02
    r = call("POST", f"{API}/wiring/{job}", {"settings": {"ceiling_ft": "high"}})
    assert r.status == 400 and "ceiling ft" in r.json()["message"]


def test_a_reviewer_sees_it_but_cannot_run_it(call, job, session_for):                    # WRW-03
    auth.configure(mode="server")
    h = session_for("reviewer")
    r = call("GET", f"{API}/wiring/{job}", headers=h)
    assert r.status == 200 and r.json()["can_run"] is False
    assert call("POST", f"{API}/wiring/{job}", {}, headers=h).status == 403

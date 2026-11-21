"""Audit & clean up's web calls (Measure screen, 2026-11-20, David): audit, then apply the ticked fixes in one go."""
import sys
from pathlib import Path

from estimator.api import auth

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from test_audit import est9  # noqa: E402,F401 - the fixture

API = "/estimator-api"


def test_audit_then_apply_everything_ticked(call, est9):  # noqa: F811
    r = call("GET", f"{API}/estimates/{est9['est']}/audit")
    assert r.status == 200, r.body
    a = r.json()
    assert a["can_apply"] is True and "priced twice" in a["summary"]
    ticked = [f["id"] for f in a["findings"] if f["selected"]]
    ask = call("POST", f"{API}/estimates/{est9['est']}/audit/apply", {"finding_ids": ticked}).json()
    assert ask["needs_confirmation"] and ask["question"].startswith("Apply ")
    done = call("POST", f"{API}/estimates/{est9['est']}/audit/apply", {"finding_ids": ticked, "confirm": True})
    assert done.status == 200, done.body
    assert "approved" in done.json()["summary"]
    left = {f["kind"] for f in call("GET", f"{API}/estimates/{est9['est']}/audit").json()["findings"]}
    assert left == {"waiting", "rerun"}


def test_bad_input_and_who_may_apply(call, est9, session_for):  # noqa: F811
    bad = call("POST", f"{API}/estimates/{est9['est']}/audit/apply", {"finding_ids": "all", "confirm": True})
    assert bad.status == 400
    assert call("POST", f"{API}/estimates/{est9['est']}/audit/apply", {"finding_ids": ["x:1"]},
                write_header=False).status == 403                                       # CSRF
    auth.configure(mode="server")
    field = session_for("field")
    assert call("GET", f"{API}/estimates/{est9['est']}/audit", headers=field).status == 403   # can't open Measure

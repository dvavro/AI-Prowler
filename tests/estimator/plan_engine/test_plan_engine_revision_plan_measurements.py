"""A plan revision and the measurements made from the plans' wall-and-room model (2026-11-15, Jamie).

Measurements from takeoff_propose / the Runner (from_plans) keep no drawing objects or sheet of their own, only the
plan sets they were read from, so revisions.compare skipped them: after Rev B of the Smith plan the approved
flooring and siding numbers from Rev A stayed as they were, with "0 measurement(s) carry over, 0 need re-measuring".
Now a change on the set's sheets flags them, and running the takeoff from the plans again clears the flag when the
number is the same (an approved number that changed becomes a suggested change, as before).
"""
from pathlib import Path

import pytest

from estimator.context import personal_context
from estimator.drawing_model import engine, revisions, store
from estimator.estimating import service
from estimator.takeoff import from_plans
from estimator.takeoff import measurements as takeoffs

CTX = personal_context()
FIX = Path(__file__).resolve().parents[1] / "browser" / "fixtures"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def meas(db, eid):
    return {m["feeds"]: m for m in takeoffs.list_measurements(db, CTX, eid)["measurements"]}


@pytest.fixture
def revised(db):
    pytest.importorskip("shapely")
    eid = service.create_estimate(db, CTX, "Smith residence")["id"]
    a = store.upload(db, CTX, eid, str(FIX / "smith_residence_A101_revA.pdf"), confirm=True)["plan_set_id"]
    engine.start(db, CTX, a, confirm=True)
    for mod in ("flooring", "siding"):
        from_plans.propose(db, CTX, eid, mod, confirm=True)
    takeoffs.confirm_measurements(db, CTX, [m["id"] for m in meas(db, eid).values()], confirm=True)
    b = store.upload(db, CTX, eid, str(FIX / "smith_residence_A101_revB.pdf"), supersedes_plan_set_id=a, keep_old=True,
                     confirm=True)["plan_set_id"]
    engine.start(db, CTX, b, confirm=True)
    return eid, a, b


def test_a_revision_flags_measurements_from_the_plans(db, revised):  # RPM-01
    eid, a, b = revised
    out = revisions.compare(db, CTX, b, confirm=True)
    assert "4 need re-measuring" in out["said"]
    assert sorted(out["flagged_measurement_ids"]) == sorted(m["id"] for m in meas(db, eid).values())
    assert all(m["needs_remeasure"] for m in meas(db, eid).values())


def test_running_the_takeoff_again_clears_the_flag_when_the_number_is_the_same(db, revised):  # RPM-02
    eid, a, b = revised
    revisions.compare(db, CTX, b, confirm=True)
    out = from_plans.propose(db, CTX, eid, "siding", confirm=True)
    assert {p["feeds"]: p["action"] for p in out["plan"]} == {"wall_sqft": "rechecked", "outside_corners": "rechecked"}
    m = meas(db, eid)
    assert not m["wall_sqft"]["needs_remeasure"] and not m["outside_corners"]["needs_remeasure"]
    fl = {p["feeds"]: p for p in from_plans.propose(db, CTX, eid, "flooring", confirm=True)["plan"]}
    assert fl["area_sqft"]["action"] == "rechecked"
    assert fl["baseboard_lf"]["action"] == "suggest" and fl["baseboard_lf"]["was"] == "282.00"   # Rev B moved a wall
    assert meas(db, eid)["baseboard_lf"]["needs_remeasure"]          # until a person takes the suggestion

"""Sprint 18 (Coder 1, without the Plan Engine): assignments, "my work", personal notices, the "someone else is
editing" warning, the practice project, and the tab's Modules section (S18-..)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from estimator import practice, team
from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.director import engine, watch
from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied
from estimator.estimating import quick, service, setup
from estimator.learning import history
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
MARIA = RequestContext(user_id="maria", role="estimator")
OFFICE = RequestContext(user_id="olga", role="office")
FIELD = RequestContext(user_id="fred", role="field")


def _roof(db, ctx=CTX, title="roof"):
    e = service.create_estimate(db, ctx, title)
    return quick.answer(db, ctx, e["id"], "roofing", ROOF, e["rev"], REG)


# ---------------------------------------------------------------- assignments

def test_assign_notifies_and_shows_in_my_work(db):  # S18-W01
    e = _roof(db, title="Garcia roof")
    out = team.assign(db, CTX, "maria", estimate_id=e["id"], note="Customer wants it by Friday")
    assert out["assigned_to"] == "maria" and service.get_estimate(db, CTX, e["id"])["assigned_to"] == "maria"
    work = team.my_work(db, MARIA)
    assert [x["id"] for x in work["estimates"]] == [e["id"]]
    assert "assigned to you by owner" in work["notices"][0]["message"] and "Friday" in work["notices"][0]["message"]
    inbox = watch.inbox(db, MARIA)                                 # maria sees her notice...
    assert inbox["count"] == 1 and inbox["notices"][0]["kind"] == "assigned"
    assert watch.inbox(db, OFFICE)["count"] == 0                   # ...nobody else does
    assert watch.unread_count(db, OFFICE) == 0 and watch.unread_count(db, MARIA) == 1


def test_assign_follows_the_director_job(db):  # S18-W02
    job = engine.start(db, CTX, "replace the roof", answers=ROOF, registry=REG)["job"]
    out = team.assign(db, OFFICE, "maria", job_id=job["id"])
    assert out["estimate_id"] == job["estimate_id"]
    assert db.execute("SELECT assigned_to FROM director_jobs WHERE id = ?", (job["id"],)).fetchone()[0] == "maria"
    assert [j["id"] for j in team.my_work(db, MARIA)["jobs"]] == [job["id"]]
    team.assign(db, CTX, "", estimate_id=job["estimate_id"])                       # clear it
    assert team.my_work(db, MARIA)["jobs"] == [] and team.my_work(db, MARIA)["estimates"] == []


def test_assign_rules(db):  # S18-W03
    e = _roof(db)
    with pytest.raises(PermissionDenied):
        team.assign(db, FIELD, "maria", estimate_id=e["id"])
    with pytest.raises(InvalidInput, match="sign-in name"):
        team.assign(db, CTX, "maria; DROP TABLE", estimate_id=e["id"])
    with pytest.raises(InvalidInput):
        team.assign(db, CTX, "maria")
    with pytest.raises(NotFound):
        team.assign(db, CTX, "maria", job_id=999)
    team.assign(db, CTX, "owner", estimate_id=e["id"])                             # to yourself: no notice
    assert db.execute("SELECT COUNT(*) FROM director_notices WHERE kind = 'assigned'").fetchone()[0] == 0
    with pytest.raises(PermissionDenied):
        team.my_work(db, MARIA, "olga")                                            # an estimator can't look at others
    assert team.my_work(db, OFFICE, "maria")["user"] == "maria"


# ---------------------------------------------------------------- "someone else is editing"

def test_editing_warning(db):  # S18-W04
    e = _roof(db, MARIA)                                                           # maria just changed it
    seen = service.get_estimate(db, CTX, e["id"])
    assert "maria changed this estimate just now" in seen["editing_warning"]
    assert "editing_warning" not in service.get_estimate(db, MARIA, e["id"])        # not about your own changes
    old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(timespec="seconds")
    db.execute("UPDATE estimates SET updated_at = ? WHERE id = ?", (old, e["id"]))
    assert "editing_warning" not in service.get_estimate(db, CTX, e["id"])          # half an hour ago: not "now"
    five = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="seconds")
    db.execute("UPDATE estimates SET updated_at = ? WHERE id = ?", (five, e["id"]))
    assert "5 minutes ago" in service.get_estimate(db, CTX, e["id"])["editing_warning"]


# ---------------------------------------------------------------- practice project

def test_practice_project(db):  # S18-P01
    out = practice.create(db, CTX, REG)
    assert out["created"] and out["trades"] == ["roofing", "pressure_washing"] and out["total_cents"] > 0
    est = service.get_estimate(db, CTX, out["estimate_id"])
    assert est["practice"] and est["title"] == "Practice: Garcia house"
    assert practice.create(db, CTX, REG)["created"] is False                         # only one at a time
    steps = {s["step"]: s["status"] for s in setup.setup_status(db, CTX)["steps"]}
    assert steps["sample_quote"] == "done"
    listed = service.list_estimates(db, CTX)["estimates"]
    assert listed[0]["practice"] is True


def test_practice_stays_out_of_history_and_my_work(db):  # S18-P02
    out = practice.create(db, CTX, REG)
    e = service.get_estimate(db, CTX, out["estimate_id"])
    e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
    history.record_actuals(db, CTX, e["id"], [{"total": "1"}])
    assert history.compare_history(db, CTX)["jobs_with_actuals"] == 0
    team.assign(db, CTX, "maria", estimate_id=e["id"])
    assert team.my_work(db, MARIA)["estimates"] == []


def test_practice_delete_removes_what_was_made(db, fake_host):  # S18-P03
    out = practice.create(db, CTX, REG)
    e = service.get_estimate(db, CTX, out["estimate_id"])
    e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
    bids.generate(db, CTX, e["id"], customer={"name": "Garcia"}, registry=REG)
    history.record_actuals(db, CTX, e["id"], [{"total": "100"}])
    real = _roof(db, title="real job")
    with pytest.raises(ConfirmationRequired):
        practice.delete(db, CTX)
    assert practice.delete(db, CTX, confirm=True)["deleted"] == 1
    for table in ("bids", "estimate_actuals"):
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    assert [x["id"] for x in service.list_estimates(db, CTX)["estimates"]] == [real["id"]]       # real work untouched
    assert practice.delete(db, CTX, confirm=True)["deleted"] == 0
    with pytest.raises(PermissionDenied):
        practice.create(db, FIELD, REG)
    with pytest.raises(InvalidInput):
        practice.run(db, CTX, "explode")


# ---------------------------------------------------------------- tab and tools

def test_modules_list_for_the_tab(db):  # S18-M01
    from estimator.ui import model
    mods = model.modules()
    assert len(mods) == 23 and {m["category"] for m in mods} == {"construction", "service"}
    roof = next(m for m in mods if m["id"] == "roofing")
    assert roof["how"] == "quick or plans" and roof["version"]
    ok, msg = model.practice_create()
    assert ok and "Practice: Garcia house" in msg and model.practice_id()
    ok, msg = model.practice_delete()
    assert ok and model.practice_id() is None


def test_tools(db):  # S18-T01
    j = lambda s: json.loads(s)                                                      # noqa: E731
    r = j(t.est_sample_project())
    assert r["created"]
    assert j(t.est_assign("maria", estimate_id=r["estimate_id"]))["assigned_to"] == "maria"
    assert j(t.est_my_work())["user"] == "owner"
    assert j(t.est_sample_project("delete"))["error"] == "needs_confirmation"
    assert j(t.est_sample_project("delete", confirm=True))["deleted"] == 1

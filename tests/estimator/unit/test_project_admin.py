"""Archive, restore and delete a project (2026-11-12, David)."""
import pytest

from estimator.context import RequestContext, personal_context
from estimator.director import engine
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable, PermissionDenied
from estimator.estimating import project_admin, quick, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
EST = RequestContext(role="estimator", user_id="erin", mode="server")


def _project(db, title="Test 25X25"):
    est = service.create_estimate(db, CTX, title)
    engine.adopt(db, CTX, est["id"], registry=REG)
    cur = service.get_estimate(db, CTX, est["id"])
    quick.answer(db, CTX, est["id"], "concrete", {"area_sqft": 625}, cur["rev"], REG)
    return service.get_estimate(db, CTX, est["id"])


def _status(db, eid):
    return db.execute("SELECT status FROM estimates WHERE id = ?", (eid,)).fetchone()[0]


def test_archive_asks_hides_and_restore_brings_it_back(db):  # PA-01
    est = _project(db)
    db.execute("UPDATE estimates SET status = 'approved' WHERE id = ?", (est["id"],))
    with pytest.raises(ConfirmationRequired) as q:
        project_admin.archive(db, CTX, est["id"])
    assert "approved -> archived" in q.value.details["changes"][0] and _status(db, est["id"]) == "approved"
    r = project_admin.archive(db, CTX, est["id"], confirm=True)
    assert r["archived"] == 1 and _status(db, est["id"]) == "archived"
    assert engine.project_job_for(db, CTX, est["id"])["state"] == "cancelled"
    assert project_admin.archive(db, CTX, est["id"], confirm=True)["archived"] == 0    # already archived
    r = project_admin.restore(db, CTX, est["id"], confirm=True)
    assert r["restored"] == 1 and _status(db, est["id"]) == "approved"                # its status before
    assert engine.project_job_for(db, CTX, est["id"])["state"] == "active"


def test_delete_needs_the_name_and_removes_everything(db):  # PA-02
    est = _project(db)
    eid = est["id"]
    with pytest.raises(ConfirmationRequired) as q:
        project_admin.delete(db, CTX, eid, backup=False)
    assert any("estimate version" in c for c in q.value.details["changes"])
    with pytest.raises(InvalidInput, match="type the project's name"):
        project_admin.delete(db, CTX, eid, confirm=True, title="wrong", backup=False)
    assert _status(db, eid) == "draft"
    r = project_admin.delete(db, CTX, eid, confirm=True, title="  test 25x25 ", backup=False)
    assert r["deleted"] == 1
    for table in ("estimates", "trade_sections", "director_jobs", "estimate_events"):
        col = "id" if table == "estimates" else "estimate_id"
        assert db.execute(f"SELECT COUNT(*) FROM {table} WHERE {col} = ?", (eid,)).fetchone()[0] == 0, table
    assert db.execute("SELECT COUNT(*) FROM estimate_events WHERE action = 'project_deleted'").fetchone()[0] == 1
    assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_delete_takes_every_revision(db):  # PA-03
    est = _project(db, "Slab")
    db.execute("UPDATE estimates SET status = 'approved' WHERE id = ?", (est["id"],))
    v2 = service.create_revision(db, CTX, est["id"], "thicker slab")
    r = project_admin.delete(db, CTX, v2["id"], confirm=True, title="Slab", backup=False)
    assert sorted(r["estimate_ids"]) == sorted([est["id"], v2["id"]])
    assert db.execute("SELECT COUNT(*) FROM estimates WHERE id IN (?, ?)", (est["id"], v2["id"])).fetchone()[0] == 0


def test_a_quoted_project_can_only_be_archived(db):  # PA-04
    est = _project(db, "David Vavro")
    db.execute("UPDATE estimates SET status = 'sent' WHERE id = ?", (est["id"],))
    with pytest.raises(NotEditable, match="archive it instead"):
        project_admin.delete(db, CTX, est["id"], confirm=True, title="David Vavro", backup=False)
    assert project_admin.archive(db, CTX, est["id"], confirm=True)["archived"] == 1


def test_only_the_owner(db):  # PA-05
    est = _project(db)
    for fn in (project_admin.archive, project_admin.restore, project_admin.delete):
        with pytest.raises(PermissionDenied):
            fn(db, EST, est["id"], confirm=True)


def test_archived_project_gets_no_new_director_job(db):  # PA-06
    est = service.create_estimate(db, CTX, "No job yet")
    project_admin.archive(db, CTX, est["id"], confirm=True)
    assert engine.adopt(db, CTX, est["id"], registry=REG) is None

"""Messages name a plan set by its number within its project (#1, as the project page's "#" column shows it), never
by its global id (2026-11-20, David: "Why does it say plan set 4 when for this project it's plan set 1 ... all
numbering of plans should be based on the project")."""
import pytest

from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.errors import ConfirmationRequired
from estimator.estimating import service
from estimator.takeoff import plan_delete

CTX = personal_context()
NOW = "2026-11-20T00:00:00+00:00"


def _plan_set(db, est, name, status="processed"):
    return db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                      " sha256, status, uploaded_by, created_at) VALUES ('default', ?, ?, ?, 'dxf', 1, ?, ?, 'owner', ?)",
                      (est, name, name, name, status, NOW)).lastrowid


@pytest.fixture
def two_projects(db):
    """Project A has three plan sets, so project B's first plan set has global id 4 - David's house case."""
    a = service.create_estimate(db, CTX, "Project A")["id"]
    for n in range(3):
        _plan_set(db, a, f"a{n}.dxf")
    b = service.create_estimate(db, CTX, "House Electrical Test")["id"]
    first = _plan_set(db, b, "house_wiring_electrical.dxf")
    second = _plan_set(db, b, "house_wiring_panel.dxf")
    db.commit()
    return {"b": b, "first": first, "second": second}


def test_label_is_the_project_number(db, two_projects):
    assert two_projects["first"] == 4                                  # its global id
    assert store.plan_set_label(db, store.load_plan_set(db, CTX, two_projects["first"])) == "#1"
    assert store.plan_set_label(db, store.load_plan_set(db, CTX, two_projects["second"])) == "#2"
    listed = {p["id"]: p["number"] for p in store.list_plan_sets(db, CTX, two_projects["b"])["plan_sets"]}
    assert listed == {two_projects["first"]: 1, two_projects["second"]: 2}


def test_reading_again_asks_with_the_project_number(db, two_projects):
    if engine._discover() is None:
        pytest.skip("the plan engine isn't installed here")
    with pytest.raises(ConfirmationRequired) as asked:
        engine.start(db, CTX, two_projects["first"])
    msg = asked.value.message
    assert "Plan set #1 (house_wiring_electrical.dxf) was already read" in msg, msg
    assert "Plan set 4" not in msg and "#4" not in msg


def test_removing_asks_with_the_project_number(db, two_projects):
    with pytest.raises(ConfirmationRequired) as asked:
        plan_delete.delete_plan_set(db, CTX, two_projects["second"])
    assert "plan set #2 (house_wiring_panel.dxf)" in asked.value.message, asked.value.message

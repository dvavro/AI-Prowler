"""Removing plan sets and sheets through the web API: ask-first with the approved-measurement warning,
then the delete, 404s for unknown ids, and the owner/estimator-only role check."""
import sys
from pathlib import Path

import pytest

from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402  (shared with the plan engine tests)

API = "/estimator-api"
NOW = "2026-11-12T12:00:00+00:00"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)       # read in the request, not a background thread
    yield
    engine.clear_engine()


def _page(sheet_no, title, views):
    texts = title_block(sheet_no, title)
    for (x, y, label, scale) in views:
        texts.append((x, y, 14, label))
        if scale:
            texts.append((x, y + 0.35, 9, scale))
    return {"w": 36, "h": 24, "texts": texts}


@pytest.fixture
def read_plan_set(db, tmp_path):
    """A processed two-sheet plan set, the way the Plans screen sees it."""
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    pdf = make_pdf(tmp_path / "smith plans.pdf", [
        _page("A-101", "FIRST FLOOR PLAN", [(4, 20, "FLOOR PLAN", 'SCALE: 1/4" = 1\'-0"')]),
        _page("E-101", "POWER PLAN", [(10, 20, "POWER PLAN", None)])])
    ps = store.upload(db, ctx, est["id"], str(pdf), confirm=True)["plan_set_id"]
    return {"estimate_id": est["id"], "plan_set_id": ps}


def _read(call, ps):
    r = call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True})
    assert r.status == 200, r.body
    return call("GET", f"{API}/plan-sets/{ps}").json()


def _sheet(call, ps, sheet_no):
    sheets = call("GET", f"{API}/plan-sets/{ps}").json()["sheets"]
    return next(s for s in sheets if s["sheet_no"] == sheet_no)


def _measure(db, estimate_id, sheet_id, status):
    return db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, sheet_id, kind, label, qty, unit,"
        " method, status, proposed_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("default", estimate_id, "concrete", sheet_id, "area", "slab", "100", "sqft", "manual",
         status, "owner", NOW, NOW)).lastrowid


# ------------------------------------------------------------------ plan sets


def test_remove_plan_set_asks_first_then_deletes(call, db, read_plan_set):
    ps = read_plan_set["plan_set_id"]
    est = read_plan_set["estimate_id"]
    _read(call, ps)
    a101 = _sheet(call, ps, "A-101")
    _measure(db, est, a101["id"], "approved")
    _measure(db, est, a101["id"], "proposed")
    file_path = db.execute("SELECT file_path FROM plan_sets WHERE id = ?", (ps,)).fetchone()["file_path"]
    assert Path(file_path).is_file()

    ask = call("POST", f"{API}/plan-sets/{ps}/remove", {}).json()
    assert ask["needs_confirmation"] is True
    assert "1 approved measurement" in ask["question"]
    assert "smith plans.pdf" in ask["question"]
    assert "2 sheets" in ask["changes"]
    assert "2 measurements (1 approved, 1 proposed)" in ask["changes"]
    assert ask["approved_measurements"] == 1
    assert call("GET", f"{API}/plan-sets/{ps}").status == 200     # asking changes nothing

    done = call("POST", f"{API}/plan-sets/{ps}/remove", {"confirm": True}).json()
    assert done["ok"] is True
    assert done["deleted"]["sheets"] == 2
    assert done["deleted"]["measurements"] == 2
    assert done["deleted"]["measurements_approved"] == 1
    assert "Removed Plan set" in done["summary"]
    assert call("GET", f"{API}/plan-sets/{ps}").status == 404
    assert call("GET", f"{API}/plans").json()["count"] == 0
    assert not Path(file_path).exists()


def test_remove_sheet_asks_first_then_deletes(call, db, read_plan_set):
    ps = read_plan_set["plan_set_id"]
    est = read_plan_set["estimate_id"]
    _read(call, ps)
    a101 = _sheet(call, ps, "A-101")
    _measure(db, est, a101["id"], "approved")

    ask = call("POST", f"{API}/sheets/{a101['id']}/remove", {}).json()
    assert ask["needs_confirmation"] is True
    assert "1 approved measurement" in ask["question"]
    assert "A-101" in ask["question"]
    assert "1 measurement (1 approved)" in ask["changes"]

    done = call("POST", f"{API}/sheets/{a101['id']}/remove", {"confirm": True}).json()
    assert done["ok"] is True
    assert done["deleted"]["measurements"] == 1
    assert call("GET", f"{API}/sheets/{a101['id']}").status == 404
    # The plan set and its other sheet survive.
    rest = call("GET", f"{API}/plan-sets/{ps}").json()
    assert rest["plan_set"]["id"] == ps
    assert [s["sheet_no"] for s in rest["sheets"]] == ["E-101"]


def test_remove_unknown_ids_404(call, read_plan_set):
    r = call("POST", f"{API}/plan-sets/99999/remove", {"confirm": True})
    assert r.status == 404 and r.json()["error"] == "not_found"
    r = call("POST", f"{API}/sheets/99999/remove", {"confirm": True})
    assert r.status == 404 and r.json()["error"] == "not_found"
    # Asking about a missing id 404s too (nothing to ask about).
    r = call("POST", f"{API}/plan-sets/99999/remove", {})
    assert r.status == 404 and r.json()["error"] == "not_found"


def test_remove_refuses_roles_that_cannot_edit(call, read_plan_set, session_for):
    ps = read_plan_set["plan_set_id"]
    _read(call, ps)
    a101 = _sheet(call, ps, "A-101")
    for role in ("reviewer", "office", "field"):
        headers = session_for(role)
        r = call("POST", f"{API}/plan-sets/{ps}/remove", {"confirm": True}, headers=headers)
        assert r.status == 403 and r.json()["error"] == "permission_denied", role
        r = call("POST", f"{API}/sheets/{a101['id']}/remove", {"confirm": True}, headers=headers)
        assert r.status == 403 and r.json()["error"] == "permission_denied", role
    assert call("GET", f"{API}/plan-sets/{ps}").status == 200     # nothing was removed

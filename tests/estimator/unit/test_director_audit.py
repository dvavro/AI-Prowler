"""The Director runs the measurement audit (2026-11-20, David: "allow the director to run [it] whenever the user decides
or as a last check before moving from estimating or at the correct flow stage").

- On the estimating stage the to-do list carries a 🧹 Audit & clean up step with a link that opens it on Measure.
- "The estimate is ready" stops when the audit finds a count priced twice (or out of step with the drawing) ...
- ... unless the person chooses Move on anyway (skip_audit), which is noted on the job.
- Once the fixes are applied the estimate moves on as before.
"""
import json

from estimator.context import personal_context
from estimator.director import engine
from estimator.estimating import quick, service
from estimator.modules.registry import ModuleRegistry
from estimator.symbols import results
from estimator.takeoff import audit

CTX = personal_context()
REG = ModuleRegistry().load()
NOW = "2026-11-20T00:00:00+00:00"


def _m(db, est, sheet, feeds, qty, status):
    return db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label, qty,"
        " unit, source_object_ids, calc_json, method, status, locked, reject_reason, proposed_by, created_at, updated_at)"
        " VALUES ('default', ?, 'electrical', ?, ?, NULL, 'count', ?, ?, 'ea', '[]', ?, 'ai', ?, ?, NULL, 'llm-takeoff',"
        " ?, ?)", (est, feeds, sheet, feeds + " (AI)", str(qty), json.dumps({"source": "llm"}), status,
                   1 if status == "approved" else 0, NOW, NOW)).lastrowid


def _job(db):
    """A priced project whose outlets are approved twice: once from before the plans were read again, once after."""
    est = service.create_estimate(db, CTX, "House Electrical Test", address="1 Main St")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                    " sha256, status, uploaded_by, created_at) VALUES ('default', ?, 'x.dxf', 'x.dxf', 'dxf', 1, 'aa',"
                    " 'processed', 'owner', ?)", (est, NOW)).lastrowid
    sheet = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, title, discipline, units, width, height)"
                       " VALUES ('default', ?, 1, 'E-1', 'electrical', 'ft', '108', '64')", (ps,)).lastrowid
    for i in range(41):
        results.insert_detection(db, "default", ps, sheet_id=sheet, object_id=None, definition_id=None, viewport_id=None,
                                 room_id=None, item_type="duplex_receptacle", trade="electrical", label="outlet",
                                 point=(i, 1), bbox=None, rotation=None, mirrored=False, method="cad",
                                 scores={"cad": 0.95}, confidence=0.95, needs_review=False, origin="engine", now=NOW)
    old = _m(db, est, None, "outlets", 41, "approved")
    _m(db, est, sheet, "outlets", 41, "approved")
    db.commit()
    est_row = service.get_estimate(db, CTX, est)
    quick.answer(db, CTX, est, "concrete", {"area_sqft": 400}, est_row["rev"], REG)
    r = engine.adopt(db, CTX, est, registry=REG)
    jid = r["job"]["id"]
    engine.next_step(db, CTX, jid, customer={"name": "Pat Lee", "email": "pat@example.com"}, registry=REG)
    return est, jid, old


def test_the_build_checklist_offers_the_audit_any_time(db):
    est, jid, _old = _job(db)
    ns = engine.adopt(db, CTX, est, registry=REG)["next_step"]
    item = next(t for t in ns["todo"] if t["key"] == "audit")
    assert not item["done"] and "priced twice" in item["text"] and item["link"] == f"#/takeoffs/{est}?audit=1"
    assert ns["audit"]["can_run"] and ns["audit"]["problems"] >= 1 and ns["audit"]["link"] == f"#/takeoffs/{est}?audit=1"
    assert ns["audit_blocked"] is False


def test_ready_stops_on_a_count_priced_twice(db):
    est, jid, _old = _job(db)
    r = engine.next_step(db, CTX, jid, ready=True, registry=REG)
    ns = r["next_step"]
    assert r["job"]["stage"] == "build" and ns["audit_blocked"] is True
    assert "measurement audit found" in json.dumps(r) and "Move on anyway" in json.dumps(r)


def test_move_on_anyway_is_the_persons_choice_and_is_noted(db):
    est, jid, _old = _job(db)
    engine.next_step(db, CTX, jid, ready=True, registry=REG)
    r = engine.next_step(db, CTX, jid, ready=True, skip_audit=True, registry=REG)
    assert r["job"]["stage"] in ("review", "approve")
    logged = [row[0] or "" for row in db.execute(
        "SELECT result_json FROM director_steps WHERE job_id = ? AND stage = 'build'", (jid,)).fetchall()]
    assert any("audit_skipped" in s and "priced twice" in s for s in logged)


def test_after_the_fixes_the_estimate_moves_on(db):
    est, jid, old = _job(db)
    out = audit.audit(db, CTX, est)
    audit.apply(db, CTX, est, [x["id"] for x in out["findings"] if x["selected"]], confirm=True)
    gone = db.execute("SELECT status FROM measurements WHERE id = ?", (old,)).fetchone()
    assert gone is None or gone["status"] == "rejected"          # off the price (kept as history unless removed)
    ns = engine.adopt(db, CTX, est, registry=REG)["next_step"]
    assert next(t for t in ns["todo"] if t["key"] == "audit")["done"]
    r = engine.next_step(db, CTX, jid, ready=True, registry=REG)
    assert r["job"]["stage"] in ("review", "approve")


def test_a_project_without_plans_or_measurements_has_no_audit_step(db):
    est = service.create_estimate(db, CTX, "Slab", address="1 Main St")["id"]
    ns = engine.adopt(db, CTX, est, registry=REG)["next_step"]
    assert "audit" not in {t["key"] for t in ns["todo"]} and ns["audit"]["can_run"] is False

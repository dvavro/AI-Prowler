"""Updated plans, the simple way (2026-11-21, David: keeping Rev 1 and Rev 2 side by side "is too complex and
problematic for most users and confusing"; 2026-11-20: "add a button to update the estimate").

- Uploading a new revision of a plan set REMOVES the old set with its sheets and every measurement on it (approved or
  not), after asking and saying exactly what goes. The estimate's prices stay until the person updates them.
- The person measures the new plans from scratch, approves, and clicks 🔄 Update from the plans: POST
  /estimates/<id>/update-from-plans re-prices every trade from its approved measurements, reopening an approved
  estimate first (it asks first and says both).
"""
import pytest

from estimator.api import router, staging
from estimator.context import personal_context
from estimator.drawing_model import store
from estimator.errors import ConfirmationRequired, PermissionDenied
from estimator.estimating import quick, service
from estimator.takeoff import measurements as ms
from estimator.takeoff import wiring_run

API = "/estimator-api"
CTX = personal_context()
PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


@pytest.fixture(autouse=True)
def fresh_staging():
    staging.reset()
    yield
    staging.reset()


def _file(tmp_path, name, extra=b""):
    p = tmp_path / name
    p.write_bytes(PDF + extra)
    return str(p)


def _sheet(db, plan_set_id):
    return db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                      " VALUES ('default', ?, 1, 'R-1', 'ROOF PLAN', '')", (plan_set_id,)).lastrowid


def _measure(db, eid, feeds, qty, sheet, unit="sqft", approve=True):
    m = ms.manual(db, CTX, eid, "roofing", feeds=feeds, qty=str(qty), unit=unit, approve=approve,
                  confirm=True)["measurement"]
    db.execute("UPDATE measurements SET sheet_id = ? WHERE id = ?", (sheet, m["id"]))
    return m["id"]


@pytest.fixture
def rev1(db, tmp_path):
    """A roof estimate priced at 2,000 sq ft and approved, with Rev 1 plans: one sheet, 2,000 sq ft and 180 lf approved
    and 50 sq ft waiting on it, plus a hand measurement that isn't on any sheet."""
    e = service.create_estimate(db, CTX, "Smith roof")
    e = quick.answer(db, CTX, e["id"], "roofing", {**ROOF, "edges_lf": 180}, e["rev"])
    ps = store.upload(db, CTX, e["id"], _file(tmp_path, "roof.pdf"), confirm=True)["plan_set_id"]
    sheet = _sheet(db, ps)
    on_sheet = [_measure(db, e["id"], "roof_area_sqft", 2000, sheet), _measure(db, e["id"], "edges_lf", 180, sheet, "lf"),
                _measure(db, e["id"], "roof_area_sqft", 50, sheet, approve=False)]
    by_hand = ms.manual(db, CTX, e["id"], "roofing", feeds="ridge_lf", qty="40", unit="lf", approve=True,
                        confirm=True)["measurement"]["id"]
    est = service.get_estimate(db, CTX, e["id"])
    est = service.set_status(db, CTX, e["id"], est["rev"], "approved")
    return {"id": e["id"], "rev": est["rev"], "ps": ps, "sheet": sheet, "on_sheet": on_sheet, "by_hand": by_hand}


def _ids(db, table, eid=None):
    if table == "measurements":
        return {r[0] for r in db.execute("SELECT id FROM measurements WHERE estimate_id = ?", (eid,))}
    return {r[0] for r in db.execute(f"SELECT id FROM {table}")}


# ---------------------------------------------------------------- a new revision replaces the old plans

def test_new_revision_asks_and_says_what_goes(db, rev1, tmp_path):                         # UP-01
    with pytest.raises(ConfirmationRequired) as q:
        store.upload(db, CTX, rev1["id"], _file(tmp_path, "roof_rev2.pdf", b"% rev 2\n"), rev1["ps"])
    msg = q.value.message
    assert "as revision 2, replacing plan set" in msg and "(roof.pdf)" in msg
    assert "1 sheet, 3 measurements (2 approved)" in msg and "can't be undone" in msg
    assert "measure the new plans from scratch" in msg and "Update from the plans" in msg
    assert q.value.details["replaces"] == {"plan_set_id": rev1["ps"], "file": "roof.pdf", "sheets": 1,
                                           "measurements": 3, "measurements_approved": 2}
    assert rev1["ps"] in _ids(db, "plan_sets")                                    # asking removed nothing


def test_new_revision_removes_the_old_plans_and_their_measurements(db, rev1, tmp_path):  # UP-02
    out = store.upload(db, CTX, rev1["id"], _file(tmp_path, "roof_rev2.pdf", b"% rev 2\n"), rev1["ps"], confirm=True)
    assert out["revision"] == 2 and "3 measurements" in out["replaced"] and "measure them again" in out["next"]
    assert rev1["ps"] not in _ids(db, "plan_sets") and rev1["sheet"] not in _ids(db, "sheets")
    left = _ids(db, "measurements", rev1["id"])
    assert not set(rev1["on_sheet"]) & left and rev1["by_hand"] in left          # hand measurements aren't the plans'
    new = store.load_plan_set(db, CTX, out["plan_set_id"])
    assert new["supersedes_plan_set_id"] is None and new["revision"] == 2       # nothing left to compare with
    est = service.get_estimate(db, CTX, rev1["id"])
    assert est["status"] == "approved" and float(est["sections"][0]["answers"]["roof_area_sqft"]) == 2000
    assert ms.approved_answers(db, CTX, rev1["id"])["roofing"] == {"ridge_lf": 40.0}


def test_replacing_needs_a_role_that_may_remove_plans(db, rev1, tmp_path):                 # UP-03
    import dataclasses
    office = dataclasses.replace(CTX, role="office")
    with pytest.raises(PermissionDenied):
        store.upload(db, office, rev1["id"], _file(tmp_path, "r2.pdf", b"% 2\n"), rev1["ps"], confirm=True)
    store.upload(db, office, rev1["id"], _file(tmp_path, "extra.pdf", b"% x\n"), confirm=True)   # a new set is fine


def test_new_dxf_revision_forgets_the_old_wiring_run(db, tmp_path, monkeypatch):            # UP-04
    monkeypatch.setattr(wiring_run, "_folder", lambda: tmp_path)
    e = service.create_estimate(db, CTX, "Wired house")
    db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size, sha256,"
               " status, uploaded_by, created_at) VALUES ('default', ?, '', 'house.dxf', 'dxf', 1, 'aa', 'processed',"
               " 'owner', '2026-11-21')", (e["id"],))
    old = db.execute("SELECT id FROM plan_sets WHERE estimate_id = ?", (e["id"],)).fetchone()[0]
    for p in (wiring_run.result_path(e["id"]), wiring_run.dxf_path(e["id"]), wiring_run.schematic_path(e["id"])):
        p.write_text("old run")
    store.upload(db, CTX, e["id"], _file(tmp_path, "house_rev2.pdf"), old, confirm=True)
    assert not wiring_run.result_path(e["id"]).exists() and not wiring_run.schematic_path(e["id"]).exists()


def test_the_upload_screen_asks_before_replacing(call, db, rev1):                          # UP-05
    s = call("POST", f"{API}/estimates/{rev1['id']}/plans/stage?name=roof%20rev2.pdf&supersedes={rev1['ps']}",
             raw=PDF + b"% rev 2\n").json()
    assert s["needs_confirmation"] and s["details"]["replaces"]["measurements_approved"] == 2
    a = call("POST", f"{API}/estimates/{rev1['id']}/plans/attach",
             {"stage_id": s["stage_id"], "supersedes_plan_set_id": rev1["ps"]}).json()
    assert a["revision"] == 2 and a["replaced"] and rev1["ps"] not in _ids(db, "plan_sets")
    app = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for needed in ("New revision of #", "(removes the old one)", "!d.replaces", "Replace the old plans and read the new ones",
                   "measure the new plans from scratch"):
        assert needed in app, needed


# ---------------------------------------------------------------- 🔄 Update from the plans

@pytest.fixture
def remeasured(db, rev1, tmp_path):
    """Rev 2 uploaded (Rev 1 and its measurements gone) and measured again: 2,400 sq ft approved on the new sheet."""
    out = store.upload(db, CTX, rev1["id"], _file(tmp_path, "roof_rev2.pdf", b"% rev 2\n"), rev1["ps"], confirm=True)
    _measure(db, rev1["id"], "roof_area_sqft", 2400, _sheet(db, out["plan_set_id"]))
    return {**rev1, "rev": service.get_estimate(db, CTX, rev1["id"])["rev"]}


def test_update_from_plans_reopens_and_reprices(call, db, remeasured):                      # UP-06
    path = f"{API}/estimates/{remeasured['id']}/update-from-plans"
    ask = call("POST", path, {"rev": remeasured["rev"]})
    assert ask.status == 200 and ask.json()["needs_confirmation"] is True, ask.json()
    q = ask.json()["question"]
    assert "2000 → 2400.0" in q and "goes back to draft" in q and ask.json()["reopens"] is True
    assert service.get_estimate(db, CTX, remeasured["id"])["status"] == "approved"   # asking changed nothing
    done = call("POST", path, {"rev": remeasured["rev"], "confirm": True})
    assert done.status == 200, done.json()
    d = done.json()
    assert d["reopened"] is True and d["status"] == "draft" and d["updated"][0]["module_id"] == "roofing"
    answers = d["sections"][0]["answers"]
    assert float(answers["roof_area_sqft"]) == 2400 and answers["pitch"] == "5/12"
    detail = call("GET", f"{API}/estimates/{remeasured['id']}/detail").json()
    assert detail["links"]["trades"][0]["can_use_measurements"] is False
    again = call("POST", path, {"rev": d["rev"]})
    assert again.status == 400 and "already matches" in again.json()["message"]


def test_update_from_plans_on_a_draft_doesnt_reopen(call, db):                              # UP-07
    e = service.create_estimate(db, CTX, "Draft roof")
    e = quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"])
    ms.manual(db, CTX, e["id"], "roofing", feeds="roof_area_sqft", qty="1500", unit="sqft", approve=True, confirm=True)
    rev = service.get_estimate(db, CTX, e["id"])["rev"]
    ask = call("POST", f"{API}/estimates/{e['id']}/update-from-plans", {"rev": rev}).json()
    assert ask["reopens"] is False and "draft first" not in ask["question"]
    done = call("POST", f"{API}/estimates/{e['id']}/update-from-plans", {"rev": rev, "confirm": True}).json()
    assert done["reopened"] is False and float(done["sections"][0]["answers"]["roof_area_sqft"]) == 1500


def test_update_from_plans_refusals(call, remeasured, session_for):                          # UP-08
    path = f"{API}/estimates/{remeasured['id']}/update-from-plans"
    for role in ("reviewer", "office"):
        assert call("POST", path, {"rev": remeasured["rev"]}, headers=session_for(role)).status == 403
    assert call("POST", path, {}).status == 400                                          # no rev
    assert call("POST", path, {"rev": remeasured["rev"] - 1, "confirm": True}).status == 409   # stale


def test_estimates_screen_has_the_update_button():                                          # UP-09
    js = (router.WEB_DIR / "estimates.js").read_text(encoding="utf-8")
    for needed in ("estimate-update-plans", "/update-from-plans", "Update from the plans", "update-plans-ask",
                   "d.can_edit || d.can_reopen", "can_use_measurements"):
        assert needed in js, needed

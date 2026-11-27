"""The Director as the master guide (2026-11-21, David: "my director list did not follow me, so the user gets lost";
"I don't think it makes sense to measure manually anymore ... he can push AI Auto Measure/Count").

- Measuring means 🤖 AI Auto Measure/Count (and ⚡ Run wiring for Electrical), then approving what it found.
- Priced trades behind their approved measurements: the Director says 🔄 Update from the plans.
- After approval, plans measured again come first: approve the new counts, then update (POST /director plans_changed).
- The Director panel is on Measure and the plan-set page too, and looks again when the project changes.
"""
from estimator.api import router
from estimator.context import personal_context
from estimator.estimating import quick, service
from estimator.takeoff import measurements as ms

API = "/estimator-api"
CTX = personal_context()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


def _plans(db, eid):
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size, sha256,"
                    " status, uploaded_by, created_at) VALUES ('default', ?, '', 'house.dxf', 'dxf', 1, ?, 'processed',"
                    " 'owner', '2026-11-21')", (eid, f"sha{eid}")).lastrowid
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 1, 'E-1', 'ELECTRICAL', '')", (ps,))
    return ps


def _todo(call, eid):
    d = call("POST", f"{API}/estimates/{eid}/director", {}).json()
    return d, {t["key"]: t for t in d["next_step"]["todo"]}


def test_measuring_means_ai_auto_run_and_the_wiring_run(call, db):                        # DG-01
    e = call("POST", f"{API}/estimates", {"title": "House", "trades": ["electrical"]}).json()
    _plans(db, e["id"])
    _, todo = _todo(call, e["id"])
    m = todo["measure"]
    assert not m["done"] and "AI Auto Measure/Count" in m["text"] and "Run wiring" in m["text"]
    assert m["link"] == f"#/takeoffs/{e['id']}" and "measures and counts everything" in m["why"]
    # A trade with no wiring run doesn't mention it.
    e2 = call("POST", f"{API}/estimates", {"title": "Roof", "trades": ["roofing"]}).json()
    _plans(db, e2["id"])
    _, todo2 = _todo(call, e2["id"])
    assert "AI Auto Measure/Count" in todo2["measure"]["text"] and "Run wiring" not in todo2["measure"]["text"]
    assert "AI Auto Measure/Count" in todo2["price_roofing"]["text"] and "Update from the plans" in todo2["price_roofing"]["text"]


def test_then_approve_what_it_found(call, db):                                             # DG-02
    e = call("POST", f"{API}/estimates", {"title": "Roof", "trades": ["roofing"]}).json()
    _plans(db, e["id"])
    ms.manual(db, CTX, e["id"], "roofing", feeds="roof_area_sqft", qty="1800", unit="sqft", confirm=True)
    _, todo = _todo(call, e["id"])
    assert todo["measure"]["text"].startswith("Approve the 1 measurement(s) 🤖 AI Auto Measure/Count found")


def test_prices_behind_the_measurements_say_update_from_the_plans(call, db):             # DG-03
    e = service.create_estimate(db, CTX, "Roof")
    e = quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"])
    ms.manual(db, CTX, e["id"], "roofing", feeds="roof_area_sqft", qty="2400", unit="sqft", approve=True, confirm=True)
    d, todo = _todo(call, e["id"])
    assert not todo["price"]["done"] and "🔄 Update from the plans" in todo["price"]["text"]
    assert d["plans_changed"] is None                                          # a draft: the checklist says it
    rev = service.get_estimate(db, CTX, e["id"])["rev"]
    assert call("POST", f"{API}/estimates/{e['id']}/update-from-plans", {"rev": rev, "confirm": True}).status == 200
    _, todo = _todo(call, e["id"])
    assert todo["price"]["done"] and todo["price"]["text"].startswith("Trades priced")


def test_after_approval_new_counts_come_first(call, db):                                   # DG-04
    e = service.create_estimate(db, CTX, "Roof")
    e = quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"])
    service.set_status(db, CTX, e["id"], service.get_estimate(db, CTX, e["id"])["rev"], "approved")
    assert call("POST", f"{API}/estimates/{e['id']}/director", {}).json()["plans_changed"] is None
    m = ms.manual(db, CTX, e["id"], "roofing", feeds="roof_area_sqft", qty="2400", unit="sqft",
                  confirm=True)["measurement"]
    pc = call("POST", f"{API}/estimates/{e['id']}/director", {}).json()["plans_changed"]
    assert pc["waiting"] == 1 and pc["status"] == "approved"                  # approve them first
    db.execute("UPDATE measurements SET status = 'approved' WHERE id = ?", (m["id"],))
    pc = call("POST", f"{API}/estimates/{e['id']}/director", {}).json()["plans_changed"]
    assert pc["waiting"] == 0 and pc["trades"]
    done = call("POST", f"{API}/estimates/{e['id']}/update-from-plans", {"rev": pc["rev"], "confirm": True})
    assert done.status == 200, done.json()
    assert done.json()["reopened"] is True
    assert call("POST", f"{API}/estimates/{e['id']}/director", {}).json()["plans_changed"] is None


def test_the_director_follows_the_user():                                                    # DG-05
    app = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    review = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
    for needed in ("function directorGuide(", "function projectChanged(", "estimator:changed", "followChanges(card, eid)",
                   "parts.splice(2, 0, directorGuide(r.estimate.id))", "director-plans-update", "director-plans-approve",
                   "/\\/director$/.test(path)"):
        assert needed in app, needed
    assert "head.push(directorGuide(estimateId))" in review
    assert "Click 🤖 AI Auto Measure/Count" in review and "Pick a tool (📏 Length" not in review

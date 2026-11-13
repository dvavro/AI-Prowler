"""Web app: every project gets a Director job, the Director panel on the project and estimate pages, and the
Dashboard's "Start a new quote or estimate" (2026-11-12, David)."""
from estimator.api import router

API = "/estimator-api"


def test_new_project_gets_a_director_job_and_panel(call):
    e = call("POST", f"{API}/estimates", {"title": "NSB Slab", "address": "1 Main St"}).json()
    assert e["director_job_id"]
    r = call("POST", f"{API}/estimates/{e['id']}/director", {})
    assert r.status == 200, r.body
    d = r.json()
    assert d["job"]["id"] == e["director_job_id"] and d["job"]["lane"] == "project"
    assert d["next_step"]["stage"] == "build" and d["next_step"]["why"] and d["next_step"]["todo"]
    assert d["bid"] is None
    # Asking again (the page opening again) is the same job, unchanged.
    again = call("POST", f"{API}/estimates/{e['id']}/director", {}).json()
    assert again["job"]["rev"] == d["job"]["rev"]


def test_ready_flag_goes_through_the_jobs_api(call):
    e = call("POST", f"{API}/estimates", {"title": "Slab"}).json()
    r = call("POST", f"{API}/quick", {"estimate_id": e["id"], "rev": e["rev"], "module_id": "concrete",
                                       "answers": {"area_sqft": 400}})
    assert r.status == 200, r.body
    jid = e["director_job_id"]
    assert call("POST", f"{API}/jobs/{jid}/next", {"ready": "yes"}).status == 400       # flags are true/false only
    r = call("POST", f"{API}/jobs/{jid}/next", {"ready": True})
    assert r.status == 200, r.body
    assert r.json()["job"]["stage"] in ("review", "approve")


def test_start_a_new_quote_or_estimate(call):
    p = call("POST", f"{API}/director/intake", {"request": "pour a concrete slab for a shed", "preview": True})
    assert p.status == 200 and p.json()["ask_plans"] is True and p.json()["kind"] == "trade"
    r = call("POST", f"{API}/director/intake", {"request": "pour a concrete slab for a shed", "has_plans": True,
                                                "customer": {"name": "Pat", "email": "pat@example.com"}})
    assert r.status == 201, r.body
    out = r.json()
    assert out["job"]["lane"] == "project" and out["route"] == f"#/projects/{out['estimate']['id']}"
    r = call("POST", f"{API}/director/intake", {"request": "wash my driveway", "has_plans": False})
    assert r.status == 201 and r.json()["job"]["lane"] == "quick_quote"
    assert call("POST", f"{API}/director/intake", {"request": "x", "has_plans": "maybe"}).status == 400
    assert call("POST", f"{API}/director/intake", {"request": ""}).status == 400


def test_guided_tours_can_be_turned_off_per_user(call):
    assert call("GET", f"{API}/help/tours/auto").json()["enabled"] is True          # on by default
    assert call("GET", f"{API}/help/tours/progress").json()["auto"] is True
    assert call("POST", f"{API}/help/tours/auto", {"enabled": "no"}).status == 400
    assert call("POST", f"{API}/help/tours/auto", {"enabled": False}).json()["enabled"] is False
    prog = call("GET", f"{API}/help/tours/progress").json()
    assert prog["auto"] is False and "_auto_tours" not in prog["tours"]             # not listed as a tour
    assert call("POST", f"{API}/help/tours/auto", {"enabled": True}).json()["enabled"] is True
    tour = (router.WEB_DIR / "tour.js").read_text(encoding="utf-8")
    assert "if (!tourAuto) return;" in tour and 'id: "tour-stop-all"' in tour
    settings = (router.WEB_DIR / "settings.js").read_text(encoding="utf-8")
    assert '["tours", "🎓 Guided tours"]' in settings and 'id: "set-tours-auto"' in settings


def test_archive_restore_and_delete_a_project(call):
    e = call("POST", f"{API}/estimates", {"title": "Test 25X25"}).json()
    ask = call("POST", f"{API}/estimates/{e['id']}/archive", {}).json()
    assert ask["needs_confirmation"] and "Archive 'Test 25X25'" in ask["question"]
    assert call("POST", f"{API}/estimates/{e['id']}/archive", {"confirm": True}).json()["archived"] == 1
    assert call("GET", f"{API}/estimates/{e['id']}").json()["status"] == "archived"
    assert call("POST", f"{API}/estimates/{e['id']}/restore", {"confirm": True}).json()["restored"] == 1
    ask = call("POST", f"{API}/estimates/{e['id']}/delete", {}).json()
    assert ask["needs_confirmation"] and ask["changes"]
    assert call("POST", f"{API}/estimates/{e['id']}/delete", {"confirm": True, "title": "nope"}).status == 400
    r = call("POST", f"{API}/estimates/{e['id']}/delete", {"confirm": True, "title": "Test 25X25"})
    assert r.status == 200, r.body
    assert call("GET", f"{API}/estimates/{e['id']}").status == 404
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "function projectAdminBox(" in js and 'id: "proj-delete"' in js and 'id: "proj-archive"' in js


def _price(call, key):
    return next(p for p in call("GET", f"{API}/price-book").json()["prices"] if p["price_key"] == key)


def test_price_edit_changes_the_cost_and_takes_a_sample_as_yours(call):
    # 2026-11-12, David: Edit said "Nothing to change" and the sample tag stayed. Every field is editable now.
    p = _price(call, "cc_fill_load")
    assert p["sample"] is True and p["description"].endswith("(sample)")
    base = {"description": p["description"], "kind": p["kind"], "unit": p["unit"], "module_id": p["module_id"]}
    # Accept the sample's price as it is: untick Sample, change nothing else.
    ask = call("POST", f"{API}/price-book/cc_fill_load/edit", {**base, "cost": "250.00", "sample": False}).json()
    assert ask["needs_confirmation"] and any("your own price" in c for c in ask["changes"])
    assert any(c.startswith("Description") for c in ask["changes"])            # the "(sample)" tag comes off
    call("POST", f"{API}/price-book/cc_fill_load/edit", {**base, "cost": "250.00", "sample": False, "confirm": True})
    p = _price(call, "cc_fill_load")
    assert p["sample"] is False and p["cost_cents"] == 25000 and p["description"] == "Fill dirt delivered per truck load"
    # Change the cost from the Edit row.
    base["description"] = p["description"]
    ask = call("POST", f"{API}/price-book/cc_fill_load/edit", {**base, "cost": "260", "sample": False}).json()
    assert ask["changes"] == ["Cost: $250.00 -> $260.00 per ea"]
    call("POST", f"{API}/price-book/cc_fill_load/edit", {**base, "cost": "260", "sample": False, "confirm": True})
    assert _price(call, "cc_fill_load")["cost_cents"] == 26000
    nothing = call("POST", f"{API}/price-book/cc_fill_load/edit", {**base, "cost": "260.00", "sample": False}).json()
    assert nothing["message"] == "Nothing to change."
    assert call("POST", f"{API}/price-book/cc_fill_load/edit", {**base, "cost": "lots"}).status == 400
    assert call("POST", f"{API}/price-book/cc_fill_load/edit", {**base, "sample": "no"}).status == 400
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert 'id: "pb-edit-cost"' in js and 'id: "pb-edit-sample"' in js and ".filter(Boolean)" in js
    # The table's cost can't be typed in: a price changes only through Edit (2026-11-12).
    assert 'class: "cost", readonly: true' in js and 'id: "pb-save"' not in js


def test_pages_have_the_director_panel_and_start_page():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "function directorPanel(" in js and "/director/intake" in js and 'id: "dash-start"' in js
    assert "AI Director Agent" in js and '"❓ Help"' in js
    css = (router.WEB_DIR / "app.css").read_text(encoding="utf-8")
    assert "a.primary.button { color: var(--brand-ink); background: var(--brand);" in css
    est = (router.WEB_DIR / "estimates.js").read_text(encoding="utf-8")
    assert "directorPanel(est.id)" in est

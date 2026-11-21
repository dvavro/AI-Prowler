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


def test_new_project_takes_its_trades(call):  # 2026-11-14, David: a new project asks which trades it quotes
    e = call("POST", f"{API}/estimates", {"title": "Shed", "trades": ["concrete", "framing"]})
    assert e.status == 201, e.body
    d = call("POST", f"{API}/estimates/{e.json()['id']}/director", {}).json()
    ns = d["next_step"]
    assert ns["trades_wanted"] == ["concrete", "framing"] and ns["pick_trades"] is False
    assert {"price_concrete", "price_framing"} <= {t["key"] for t in ns["todo"]}
    # Changed later on the project page.
    r = call("POST", f"{API}/estimates/{e.json()['id']}/trades", {"trades": ["drywall"]})
    assert r.status == 200, r.body
    assert r.json()["next_step"]["trades_wanted"] == ["drywall"]
    assert call("POST", f"{API}/estimates/{e.json()['id']}/trades", {"trades": "drywall"}).status == 400
    assert call("POST", f"{API}/estimates/{e.json()['id']}/trades", {"trades": ["nope"]}).status == 400
    assert call("POST", f"{API}/estimates", {"title": "x", "trades": "concrete"}).status == 400
    # No trades picked: the panel asks for them.
    e2 = call("POST", f"{API}/estimates", {"title": "Bare"}).json()
    ns2 = call("POST", f"{API}/estimates/{e2['id']}/director", {}).json()["next_step"]
    assert ns2["pick_trades"] is True and ns2["say"].startswith("Pick the trades")


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
    # 2026-11-21: tours never start on their own now, so the web app no longer offers the switch ("Don't show tours",
    # Settings > Guided tours). The endpoint stays, harmless, for older clients.
    tour = (router.WEB_DIR / "tour.js").read_text(encoding="utf-8")
    assert "tourAuto" not in tour and "tour-stop-all" not in tour and "Don't show tours" not in tour
    settings = (router.WEB_DIR / "settings.js").read_text(encoding="utf-8")
    assert '"🎓 Guided tours"]' not in settings and "set-tours-auto" not in settings


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


def test_project_page_head_has_a_delete_button_that_reuses_the_delete_flow():
    # 2026-11-17, David: the only Delete button sat at the bottom of the project page (in the
    # admin box) and could not be found. A second button in the page-head scrolls to the admin
    # box and clicks the existing #proj-delete, so the endpoint and the type-the-name confirm
    # are the same flow, not a copy of it.
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    render = js[js.index("function renderProject("):js.index("function topDeleteButton(")]
    assert "topDeleteButton(est)" in render                    # called from the project page-head
    assert render.index("topDeleteButton(est)") < render.index('class: "tiles"')
    fn = js[js.index("function topDeleteButton("):js.index("function projectAdminBox(")]
    assert 'id: "proj-delete-top"' in fn and "🗑 Delete…" in fn
    assert '$("proj-delete")' in fn and "del.click()" in fn   # reuses the existing delete button
    assert '$("project-admin")' in fn and "scrollIntoView" in fn
    assert 'role !== "owner"' in fn and "est.practice" in fn  # same gate as the admin box
    assert '"/delete"' not in fn                             # the top button posts nothing itself
    assert js.count('"/delete"') == 2                        # ask + confirm, both in projectAdminBox


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


def test_edit_project_fixes_the_title_in_place(call):
    # 2026-11-17, David: "NSB" was typed "NSM" in project 7's title and there was no way to fix
    # it, so re-running the quick estimate made a duplicate project 8. The edit fixes the header
    # in place; lines, totals, status, rev and the Director job are untouched.
    e = call("POST", f"{API}/estimates",
             {"title": "Electrical - 1500 shadow pines dr, NSM FL 32168",
              "address": "1500 shadow pines dr, NSM FL 32168"}).json()
    r = call("POST", f"{API}/quick", {"estimate_id": e["id"], "rev": e["rev"], "module_id": "concrete",
                                      "answers": {"area_sqft": 400}})
    assert r.status == 200, r.body
    before = call("GET", f"{API}/estimates/{e['id']}").json()
    assert before["sections"] and before["totals"] and before["totals"]["total_cents"] > 0
    job = call("POST", f"{API}/estimates/{e['id']}/director", {}).json()["job"]
    r = call("POST", f"{API}/estimates/{e['id']}/edit",
             {"title": "Electrical - 1500 shadow pines dr, NSB FL 32168",
              "address": "1500 Shadow Pines Dr, NSB FL 32168",
              "due_date": "2026-12-01", "customer_id": "CUST-1"})
    assert r.status == 200, r.body
    out = r.json()
    assert out["title"] == "Electrical - 1500 shadow pines dr, NSB FL 32168"
    assert out["address"] == "1500 Shadow Pines Dr, NSB FL 32168"
    assert out["due_date"] == "2026-12-01" and out["customer_id"] == "CUST-1"
    after = call("GET", f"{API}/estimates/{e['id']}").json()
    assert after["sections"] == before["sections"] and after["totals"] == before["totals"]
    assert after["status"] == before["status"] and after["rev"] == before["rev"]
    again = call("POST", f"{API}/estimates/{e['id']}/director", {}).json()["job"]
    assert again["id"] == job["id"] and again["rev"] == job["rev"]
    events = call("GET", f"{API}/estimates/{e['id']}/events").json()["events"]
    assert "estimate_edited" in [ev["action"] for ev in events]
    assert call("POST", f"{API}/estimates/99999/edit", {"title": "x"}).status == 404
    assert call("POST", f"{API}/estimates/{e['id']}/edit", {}).status == 200   # nothing to change


def test_edit_project_refuses_an_empty_title_and_a_bad_due_date(call):
    e = call("POST", f"{API}/estimates", {"title": "Shed slab", "due_date": "2026-11-30"}).json()
    r = call("POST", f"{API}/estimates/{e['id']}/edit", {"title": "   "})
    assert r.status == 400 and r.json()["error"] == "invalid_input"
    for bad in ("next Friday", "2026-02-30", "30/11/2026", "2026-13-01"):
        r = call("POST", f"{API}/estimates/{e['id']}/edit", {"due_date": bad})
        assert r.status == 400 and r.json()["error"] == "invalid_input", bad
    # Nothing changed, and clearing the due date works.
    again = call("GET", f"{API}/estimates/{e['id']}").json()
    assert again["title"] == "Shed slab" and again["due_date"] == "2026-11-30"
    r = call("POST", f"{API}/estimates/{e['id']}/edit", {"due_date": None})
    assert r.status == 200 and r.json()["due_date"] is None


def test_edit_project_refuses_roles_that_cannot_edit(call, session_for):
    e = call("POST", f"{API}/estimates", {"title": "Shed slab"}).json()
    for role in ("reviewer", "office", "field"):
        r = call("POST", f"{API}/estimates/{e['id']}/edit", {"title": "Nope"},
                 headers=session_for(role))
        assert r.status == 403 and r.json()["error"] == "permission_denied", role
    r = call("POST", f"{API}/estimates/{e['id']}/edit", {"title": "Estimator fixed it"},
             headers=session_for("estimator"))
    assert r.status == 200, r.body
    assert call("GET", f"{API}/estimates/{e['id']}").json()["title"] == "Estimator fixed it"


def test_project_page_has_an_edit_button_in_the_page_head():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    start = js.index("async function renderProject(")
    end = js.index("main.replaceChildren(...parts);", start)
    assert "projectEditButton(est)" in js[start:end]      # the button sits by the title, no scrolling
    assert 'id: "proj-edit-top"' in js and "function projectEditButton(" in js
    assert 'id: "proj-edit"' in js and 'id: "proj-edit-title"' in js
    assert 'id: "proj-edit-address"' in js and 'id: "proj-edit-due"' in js
    assert '"/estimates/" + est.id + "/edit"' in js


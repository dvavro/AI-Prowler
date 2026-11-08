"""Coder 2 Sprint 8: two-way linking (priced lines <-> measurements), the Estimates screen, and manual takeoff tool
polish in Blueprint Review."""
import pytest

from estimator.api import links, nav, router
from estimator.context import personal_context
from estimator.estimating import quick, service
from estimator.takeoff import measurements as ms

API = "/estimator-api"
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


@pytest.fixture
def roof(db):
    """A roof priced at 2,000 sq ft, with 1,200 sq ft approved, 900 waiting, and 180 lf of edges approved."""
    ctx = personal_context()
    e = service.create_estimate(db, ctx, "Smith roof")
    e = quick.answer(db, ctx, e["id"], "roofing", ROOF, e["rev"])
    area = ms.manual(db, ctx, e["id"], "roofing", feeds="roof_area_sqft", qty="1200", unit="sqft", approve=True,
                     confirm=True)["measurement"]
    waiting = ms.manual(db, ctx, e["id"], "roofing", feeds="roof_area_sqft", qty="900", unit="sqft",
                        confirm=True)["measurement"]
    edges = ms.manual(db, ctx, e["id"], "roofing", feeds="edges_lf", qty="180", unit="lf", approve=True,
                      confirm=True)["measurement"]
    est = service.get_estimate(db, ctx, e["id"])
    lines = {ln["description"]: ln for s in est["sections"] for ln in s["lines"]}
    return {"id": e["id"], "rev": est["rev"], "area": area["id"], "waiting": waiting["id"], "edges": edges["id"],
            "lines": lines}


def _yes(call, path, body, **kw):
    ask = call("POST", path, body, **kw)
    assert ask.status == 200 and ask.json()["needs_confirmation"] is True, ask.json()
    done = call("POST", path, {**body, "confirm": True}, **kw)
    assert done.status == 200, done.json()
    return ask.json(), done.json()


# ---------------------------------------------------------------- the links

def test_lines_link_to_the_measurements_behind_them(db, roof):                      # C2S8-L01
    out = links.estimate_links(db, personal_context(), roof["id"])
    by = {ln["description"]: ln for ln in out["lines"]}
    drip = next(ln for d, ln in by.items() if "drip" in d.lower())
    assert "edges_lf" in drip["questions"] and roof["edges"] in drip["measurement_ids"]
    shingles = by[next(d for d in by if "shingle" in d.lower())]
    assert shingles["measurement_ids"] == [roof["area"]] and shingles["proposed_ids"] == [roof["waiting"]]
    permit = next(ln for d, ln in by.items() if "permit" in d.lower())
    assert permit["questions"] == [] and permit["measurement_ids"] == []              # no formula over a measured question
    back = {m["id"]: m for m in out["measurements"]}
    assert shingles["line_id"] in back[roof["area"]]["line_ids"] and drip["line_id"] in back[roof["edges"]]["line_ids"]
    assert back[roof["area"]]["status"] == "approved" and back[roof["waiting"]]["qty"] == "900.00"


def test_where_each_answer_came_from(db, roof):                                     # C2S8-L02
    ctx = personal_context()
    qs = {q["id"]: q for q in links.estimate_links(db, ctx, roof["id"])["trades"][0]["questions"]}
    assert qs["roof_area_sqft"]["state"] == "differs" and qs["roof_area_sqft"]["measured"] == 1200.0
    assert qs["edges_lf"]["state"] == "differs"                                       # priced at 0, measured 180
    assert qs["pitch"]["state"] == "typed" and qs["layers"]["state"] == "typed"
    # A measured trade not on the estimate yet is "waiting".
    ms.manual(db, ctx, roof["id"], "flooring", feeds=_area_question("flooring"), qty="300", unit="sqft", approve=True,
              confirm=True)
    out = links.estimate_links(db, ctx, roof["id"])
    floor = next(t for t in out["trades"] if t["module_id"] == "flooring")
    assert floor["can_use_measurements"] and {q["state"] for q in floor["questions"]} == {"waiting"}


def _area_question(module_id):
    from estimator.modules import get_registry
    return next(q.id for q in get_registry().get(module_id).questions if q.unit == "sqft")


def test_hand_entered_lines_link_to_nothing(db, roof):                              # C2S8-L03
    ctx = personal_context()
    service.add_line_item(db, ctx, roof["id"], roof["rev"], kind="equipment", description="Dumpster", quantity="1",
                          unit="ea", unit_cost_cents=45000)
    ln = next(x for x in links.estimate_links(db, ctx, roof["id"])["lines"] if x["description"] == "Dumpster")
    assert ln["module_id"] == "custom" and ln["questions"] == [] and ln["measurement_ids"] == []


# ---------------------------------------------------------------- the Estimates screen

def test_estimate_page(call, roof):                                                  # C2S8-E01
    r = call("GET", f"{API}/estimates/{roof['id']}/detail").json()
    assert r["estimate"]["title"] == "Smith roof" and r["see_margins"] is True
    assert (r["can_edit"], r["can_options"], r["can_revise"], r["can_review"]) == (True, True, False, True)
    assert r["links"]["trades"][0]["can_use_measurements"] is True and "material" in r["line_kinds"]
    line = r["estimate"]["sections"][0]["lines"][0]
    assert "unit_cost_cents" in line and line["calc"]


def test_field_sees_prices_but_no_costs(call, roof, session_for):                   # C2S8-E02
    h = session_for("field")
    r = call("GET", f"{API}/estimates/{roof['id']}/detail", headers=h).json()
    assert r["see_margins"] is False and (r["can_edit"], r["can_review"]) == (False, False)
    assert not [k for k in _keys(r) if k != "see_margins" and ("cost" in k or "margin" in k or k == "calc")]
    assert r["estimate"]["sections"][0]["lines"][0]["total_cents"] > 0
    assert call("GET", f"{API}/estimates/{roof['id']}/history", headers=h).status == 403
    v = call("GET", f"{API}/estimates/{roof['id']}/validate", headers=h)
    assert v.status == 200 and not [k for k in _keys(v.json()) if "cost" in k or "margin" in k]


def _keys(value):
    """Every key anywhere in a JSON answer."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _keys(v)
    elif isinstance(value, list):
        for v in value:
            yield from _keys(v)


def test_price_a_trade_with_its_approved_measurements(call, roof):                  # C2S8-U01
    body = {"module_id": "roofing", "rev": roof["rev"]}
    ask, done = _yes(call, f"{API}/estimates/{roof['id']}/use-measurements", body)
    assert "2000 → 1200.0" in ask["question"] and "180" in ask["question"]
    assert done["changes"]["roof_area_sqft"] == {"from": 2000, "to": 1200.0}
    answers = done["sections"][0]["answers"]
    assert float(answers["roof_area_sqft"]) == 1200 and float(answers["edges_lf"]) == 180 and answers["pitch"] == "5/12"
    r = call("GET", f"{API}/estimates/{roof['id']}/detail").json()
    states = {q["id"]: q["state"] for q in r["links"]["trades"][0]["questions"]}
    assert states["roof_area_sqft"] == "measured" and states["edges_lf"] == "measured"
    assert r["links"]["trades"][0]["can_use_measurements"] is False
    stale = call("POST", f"{API}/estimates/{roof['id']}/use-measurements", {**body, "confirm": True})
    assert stale.status == 409                                                      # the old rev


def test_use_measurements_refusals(call, roof, session_for):                        # C2S8-U02
    e = roof["id"]
    none = call("POST", f"{API}/estimates/{e}/use-measurements", {"module_id": "concrete", "rev": roof["rev"]})
    assert none.status == 400 and "no approved measurements" in none.json()["message"]
    for role in ("reviewer", "office"):
        r = call("POST", f"{API}/estimates/{e}/use-measurements", {"module_id": "roofing", "rev": roof["rev"]},
                 headers=session_for(role))
        assert r.status == 403
    assert call("POST", f"{API}/estimates/{e}/use-measurements", {"module_id": "nope", "rev": roof["rev"]}).status == 400
    assert call("POST", f"{API}/estimates/{e}/use-measurements", {"module_id": "roofing"}).status == 400        # no rev


def test_add_a_line_and_recalculate(call, roof, session_for):                       # C2S8-E03
    e = roof["id"]
    r = call("POST", f"{API}/estimates/{e}/lines", {"rev": roof["rev"], "kind": "equipment", "description": "Dumpster",
                                                   "quantity": "1", "unit": "ea", "unit_cost_cents": 45000})
    assert r.status == 200
    custom = next(s for s in r.json()["sections"] if s["module_id"] == "custom")
    assert custom["lines"][0]["description"] == "Dumpster"
    rev = r.json()["rev"]
    assert call("POST", f"{API}/estimates/{e}/calculate", {"rev": rev}).status == 200
    assert call("POST", f"{API}/estimates/{e}/calculate", {"rev": rev}).status == 409                    # rev moved on
    bad = [{"unit_cost_cents": 12.5}, {"unit_cost_cents": True}, {"kind": "nonsense", "unit_cost_cents": 1},
           {"rev": "x", "unit_cost_cents": 1}]
    for b in bad:
        body = {"rev": rev + 1, "kind": "equipment", "description": "x", "quantity": "1", "unit": "ea", **b}
        assert call("POST", f"{API}/estimates/{e}/lines", body).status == 400, b
    field = call("POST", f"{API}/estimates/{e}/lines", {"rev": rev + 1, "kind": "equipment", "description": "x",
                                                         "quantity": "1", "unit": "ea", "unit_cost_cents": 1},
                 headers=session_for("field"))
    assert field.status == 403


def test_checks_and_history(call, roof):                                            # C2S8-E04
    v = call("GET", f"{API}/estimates/{roof['id']}/validate").json()
    assert any(f["code"] == "measurements_waiting" for f in v["findings"])
    h = call("GET", f"{API}/estimates/{roof['id']}/history").json()
    assert h["lines"] and "summary" in h


def test_options_then_choose_one(call, roof):                                       # C2S8-E05
    opts = call("POST", f"{API}/estimates/{roof['id']}/options", {"module_id": "roofing"}).json()
    assert len(opts["options"]) >= 2
    other = next(o for o in opts["options"] if not o["current"])
    detail = call("GET", f"{API}/estimates/{roof['id']}/detail").json()
    assert {o["id"] for o in detail["options"]} == {o["id"] for o in opts["options"]}
    ask, done = _yes(call, f"{API}/estimates/{roof['id']}/options/choose",
                     {"option_id": other["id"], "module_id": "roofing", "rev": detail["estimate"]["rev"]})
    assert other["label"] in ask["question"]
    assert call("POST", f"{API}/estimates/{roof['id']}/options/choose",
                {"option_id": "nope", "module_id": "roofing", "rev": done["rev"]}).status == 400


def test_new_version(call, db, roof):                                               # C2S8-E06
    e = roof["id"]
    still = call("POST", f"{API}/estimates/{e}/revision", {"change_summary": "patio", "confirm": True})
    assert still.status == 400                                                       # a draft is edited directly
    service.set_status(db, personal_context(), e, roof["rev"], "approved")
    page = call("GET", f"{API}/estimates/{e}/detail").json()
    assert page["can_revise"] and not page["can_edit"]
    assert call("POST", f"{API}/estimates/{e}/revision", {"change_summary": ""}).status == 400
    ask, done = _yes(call, f"{API}/estimates/{e}/revision", {"change_summary": "customer added the patio"})
    assert "Make version 2" in ask["question"] and "voided" in ask["question"]
    assert done["id"] != e and done["status"] == "draft" and done["revision"] == 2


def test_roles_and_errors(call, roof, session_for):                                 # C2S8-E07
    e = roof["id"]
    for role in ("owner", "estimator", "reviewer", "office", "field"):
        assert call("GET", f"{API}/estimates/{e}/detail", headers=session_for(role)).status == 200
    assert call("GET", f"{API}/estimates/{e}/detail", headers=session_for("owner", company="acme")).status == 404
    assert call("GET", f"{API}/estimates/999999/detail").status == 404
    assert call("POST", f"{API}/estimates/{e}/calculate", {"rev": roof["rev"]}, write_header=False).status == 403
    assert call("GET", f"{API}/estimates/{e}/lines").status == 404
    assert call("POST", f"{API}/estimates/{e}/revision", raw=b"[1]").status == 400


# ---------------------------------------------------------------- Blueprint Review side of the links

def test_review_page_has_the_links(call, roof):                                     # C2S8-R01
    r = call("GET", f"{API}/estimates/{roof['id']}/takeoff").json()
    back = {m["id"]: m["line_ids"] for m in r["links"]["measurements"]}
    assert back[roof["area"]] and back[roof["edges"]]
    assert {ln["line_id"] for ln in r["links"]["lines"]} >= set(back[roof["area"]])


# ---------------------------------------------------------------- the pages

def test_screen_pages_and_scripts():                                                # C2S8-W01
    screen = next(s for s in nav.SCREENS if s["id"] == "estimates")
    assert screen["status"] == "ready" and screen["roles"] == nav.ALL
    page = next(p for p in nav.PAGES if p["id"] == "estimate")
    assert page["from"] == "estimates" and "est_quick_answer" in page["tools"]
    html = (router.WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert html.index('src="review.js"') < html.index('src="estimates.js"')
    js = (router.WEB_DIR / "estimates.js").read_text(encoding="utf-8")
    for needed in ("SCREENS.estimates = renderEstimates", "PAGES.estimate = renderEstimate", "/detail", "/validate",
                   "/history", "/options", "/options/choose", "/lines", "/calculate", "/revision", "/use-measurements",
                   "?line=", "?m=", "askThen("):
        assert needed in js, needed
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", 'style="', "eval(", "document.write"):
        assert bad not in js, bad
    app = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert 'page: "estimate"' in app and "project-estimate" in app
    rv = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
    for needed in ('tabButton("lines", "Lines")', "drawLinesPanel", "linesFor(", "snapPoint(", "Backspace",
                   "ev.altKey", "ev.shiftKey", "bp-type-number", '"perimeter"', 'q.get("line")'):
        assert needed in rv, needed


def test_no_name_is_defined_twice_across_the_web_scripts():                         # C2S8-W03
    """The web scripts share one global scope: a second `function x` silently replaces the first (this broke the
    line -> plan link in the browser smoke test until estimates.js's lineMeasurements was renamed)."""
    import re
    seen: dict[str, str] = {}
    for f in sorted(router.WEB_DIR.glob("*.js")):
        text = f.read_text(encoding="utf-8")
        for name in re.findall(r"^(?:async\s+)?(?:function|class)\s+(\w+)|^(?:const|let|var)\s+(\w+)", text, re.M):
            n = name[0] or name[1]
            assert n not in seen, f"{n} is defined in both {seen[n]} and {f.name}"
            seen[n] = f.name
    assert {"lineMeasurements", "lineMeasurementList", "renderReview", "renderEstimate"} <= set(seen)


def test_guides_name_buttons_that_exist():                                          # C2S8-W02
    from estimator.ui import help as guides
    g = guides.get_guide("check_an_estimate_against_the_plans")
    assert g["screen"] == "estimates"
    js = (router.WEB_DIR / "estimates.js").read_text(encoding="utf-8")
    for label in ("Price it with the approved measurements", "show on the plan", "Show all of them on the plan",
                  "Check it", "Compare with past jobs", "Price the options", "Use this one", "Add a line by hand",
                  "Recalculate", "New version"):
        assert label in js and label in g["text"], label
    rv = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
    assert "Type a number in" in rv and "Type a number in" in guides.get_guide("measure_and_approve_on_the_plans")["text"]

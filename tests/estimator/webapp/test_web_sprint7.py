"""Coder 2 Sprint 7: Blueprint Review v1 - tiled viewer, overlays and layers, tools (drawn and from the drawing),
the measurement list, the detail panel, and approve / correct / reject / suggest, all through the takeoff service."""
import io
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from estimator.api import nav, router
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402

API = "/estimator-api"
QUARTER = 'SCALE: 1/4" = 1\'-0"'


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _square(x, y, size):
    return [(x, y, x + size, y), (x + size, y, x + size, y + size), (x + size, y + size, x, y + size),
            (x, y + size, x, y)]


@pytest.fixture
def plan(call, db, tmp_path):
    """A read 36 x 24 sheet at 1/4" = 1'-0": a 12 x 12 ft KITCHEN and a 16 ft wall."""
    texts = title_block("A-101", "FIRST FLOOR PLAN") + [(4, 21, 14, "FLOOR PLAN"), (4, 21.35, 9, QUARTER),
                                                        (6, 6.4, 10, "KITCHEN")]
    lines = _square(5, 5, 3) + [(10, 5, 14, 5), (10, 5.125, 14, 5.125)]
    pdf = make_pdf(tmp_path / "smith.pdf", [{"w": 36, "h": 24, "texts": texts, "lines": lines}])
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    ps = store.upload(db, ctx, est["id"], str(pdf), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    sheet = call("GET", f"{API}/plan-sets/{ps}").json()["sheets"][0]
    objs = call("GET", f"{API}/sheets/{sheet['id']}/objects").json()["objects"]
    room = next(o for o in objs if o["kind"] == "room")
    wall = next(o for o in objs if o["kind"] == "wall")
    vp = call("GET", f"{API}/sheets/{sheet['id']}").json()["viewports"][0]
    return {"est": est["id"], "ps": ps, "sheet": sheet["id"], "room": room, "wall": wall, "vp": vp}


def _yes(call, path, body, **kw):
    """The page's two steps: the question (nothing done), then the same call with confirm=true."""
    ask = call("POST", path, body, **kw)
    assert ask.status == 200 and ask.json()["needs_confirmation"] is True, ask.json()
    done = call("POST", path, {**body, "confirm": True}, **kw)
    assert done.status == 200, done.json()
    return ask.json(), done.json()


def _png_size(body):
    from PIL import Image
    with Image.open(io.BytesIO(body)) as img:
        return img.size


# ---------------------------------------------------------------- tiled viewer

def test_sheet_has_tiles_rendered_from_the_pdf(call, plan):                         # C2S7-T01
    t = call("GET", f"{API}/sheets/{plan['sheet']}").json()["tiles"]
    assert t["source"] == "pdf" and t["tile"] == 512 and t["max_level"] == 4         # 36" at up to 300 DPI
    r = call("GET", f"{API}/sheets/{plan['sheet']}/tiles/0/0/0.png")
    assert r.status == 200 and r.content_type == "image/png" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert _png_size(r.body) == (512, 341)                                           # the whole 36 x 24 sheet
    deep = call("GET", f"{API}/sheets/{plan['sheet']}/tiles/4/0/0.png")              # 4096 px... per 2.25" tile
    assert deep.status == 200 and _png_size(deep.body) == (512, 512)
    edge = call("GET", f"{API}/sheets/{plan['sheet']}/tiles/1/1/0.png")              # right half, top: 18 x 18"
    assert _png_size(edge.body) == (512, 512)
    bottom = call("GET", f"{API}/sheets/{plan['sheet']}/tiles/1/0/1.png")            # bottom row is 6" tall
    assert _png_size(bottom.body) == (512, 171)
    again = call("GET", f"{API}/sheets/{plan['sheet']}/tiles/4/0/0.png")
    assert again.body == deep.body                                                    # served from the cache


def test_tile_errors(call, plan, session_for):                                      # C2S7-T02
    s = plan["sheet"]
    for bad in ("5/0/0", "1/2/0", "1/0/2", "0/1/0"):                                   # no such level or place
        assert call("GET", f"{API}/sheets/{s}/tiles/{bad}.png").status == 404
    assert call("GET", f"{API}/sheets/{s}/tiles/a/0/0.png").status == 404
    assert call("GET", f"{API}/sheets/{s}/tiles/0/0/0.png", headers=session_for("owner", company="acme")).status == 404
    assert call("GET", f"{API}/sheets/{s}/tiles/0/0/0.png", headers=session_for("office")).status == 200   # 2026-11-09


def test_objects_with_shapes_and_layer_groups(call, plan):                          # C2S7-O01
    r = call("GET", f"{API}/sheets/{plan['sheet']}/objects").json()
    assert plan["room"]["label"] == "KITCHEN" and plan["room"]["group"] == "rooms"
    assert plan["room"]["geometry"]["type"] == "polygon" and Decimal(plan["room"]["real_units"]["area_sqft"]) == 144
    assert plan["wall"]["group"] == "walls"
    ids = [g["id"] for g in r["layers"]]
    assert ids[0] == "measurements" and {"rooms", "walls"} <= set(ids)
    assert all(g["color"].startswith("#") for g in r["layers"])
    walls_only = call("GET", f"{API}/sheets/{plan['sheet']}/objects?kind=wall").json()
    assert {o["kind"] for o in walls_only["objects"]} == {"wall"}


# ---------------------------------------------------------------- the Takeoffs screen and the review page

def test_takeoffs_list_and_review_page(call, plan):                                 # C2S7-P01
    lst = call("GET", f"{API}/takeoffs").json()
    p = next(x for x in lst["projects"] if x["estimate_id"] == plan["est"])
    assert p["read"] == 1 and p["plan_sets"] == 1 and p["to_review"] == 0
    r = call("GET", f"{API}/estimates/{plan['est']}/takeoff").json()
    assert r["estimate"]["title"] == "Smith house" and [s["id"] for s in r["sheets"]] == [plan["sheet"]]
    assert r["trades"] == []                                                          # no trades on it yet
    roof = next(t for t in r["other_trades"] if t["module_id"] == "roofing")
    assert "roof_area_sqft" in [q["id"] for q in roof["questions"]]
    assert r["takeoff"]["count"] == 0 and r["can_measure"] and r["can_approve"] and r["can_correct"]


def test_measure_from_the_drawing_then_approve(call, plan):                         # C2S7-M01
    body = {"module_id": "roofing", "feeds": "roof_area_sqft", "object_ids": [plan["room"]["id"]], "room": "KITCHEN"}
    ask, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements/propose", body)
    assert "144.00 sqft" in ask["question"] and "confirm" not in ask["question"].lower()
    m = done["proposed"][0]
    assert (m["qty"], m["unit"], m["status"], m["room"], m["method"]) == ("144.00", "sqft", "proposed", "KITCHEN", "vector")
    assert m["source_object_ids"] == [plan["room"]["id"]] and Decimal(m["confidence"]) == Decimal("0.75")
    page = call("GET", f"{API}/estimates/{plan['est']}/takeoff").json()
    assert page["takeoff"]["review_queue"] == [m["id"]] and page["takeoff"]["approved_answers"] == {}
    _yes(call, f"{API}/measurements/approve", {"measurement_ids": [m["id"]]})
    page = call("GET", f"{API}/estimates/{plan['est']}/takeoff").json()
    row = page["takeoff"]["measurements"][0]
    assert row["status"] == "approved" and row["locked"] is True
    assert page["takeoff"]["approved_answers"] == {"roofing": {"roof_area_sqft": 144.0}}


def test_measure_and_approve_in_one_step(call, plan):                               # C2S7-M02
    body = {"module_id": "roofing", "feeds": "edges_lf", "object_ids": [plan["wall"]["id"]], "approve": True}
    ask, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements/propose", body)
    assert "approved and locked" in ask["question"]
    assert done["approved"] == [done["proposed"][0]["id"]] and done["proposed"][0]["qty"] == "16.00"
    assert call("GET", f"{API}/takeoffs").json()["projects"][0]["measurements"]["approved"] == 1


def test_drawn_shapes_are_measured_with_the_views_scale(call, plan):                # C2S7-M03
    square = {"type": "polygon", "points": [[20, 5], [22, 5], [22, 7], [20, 7]]}     # 2" = 8 ft at 1/4"
    body = {"module_id": "roofing", "feeds": "roof_area_sqft", "viewport_id": plan["vp"]["id"], "geometry": square,
            "kind": "area", "label": "Porch roof"}
    ask, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements", body)
    m = done["measurement"]
    assert (m["qty"], m["unit"], m["method"], m["sheet_id"], m["label"]) == ("64.00", "sqft", "manual", plan["sheet"], "Porch roof")
    line = {"type": "polyline", "points": [[20, 10], [23, 10], [23, 12]]}            # 5" = 20 ft
    _, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements",
                   {"module_id": "roofing", "feeds": "edges_lf", "viewport_id": plan["vp"]["id"], "geometry": line,
                    "approve": True})
    assert done["measurement"]["qty"] == "20.00" and done["measurement"]["status"] == "approved"
    page = call("GET", f"{API}/estimates/{plan['est']}/takeoff").json()
    shapes = {x["id"]: x["geometry"] for x in page["takeoff"]["measurements"]}
    assert shapes[m["id"]] == square                                                  # the page can draw it back


def test_typed_measurement(call, plan):                                             # C2S7-M04
    _, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements",
                   {"module_id": "roofing", "feeds": "roof_area_sqft", "qty": "1200", "unit": "sqft"})
    assert done["measurement"]["method"] == "typed" and done["measurement"]["qty"] == "1200.00"


def test_unscaled_view_cant_be_measured(call, db, tmp_path):                        # C2S7-M05
    pdf = make_pdf(tmp_path / "noscale.pdf", [{"w": 36, "h": 24, "texts": title_block("A-101", "PLAN"),
                                               "lines": _square(5, 5, 3)}])
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "No scale")
    ps = store.upload(db, ctx, est["id"], str(pdf), confirm=True)["plan_set_id"]
    call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True})
    sid = call("GET", f"{API}/plan-sets/{ps}").json()["sheets"][0]["id"]
    vp = call("GET", f"{API}/sheets/{sid}").json()["viewports"][0]
    r = call("POST", f"{API}/estimates/{est['id']}/measurements",
             {"module_id": "roofing", "viewport_id": vp["id"],
              "geometry": {"type": "line", "points": [[1, 1], [2, 1]]}, "confirm": True})
    assert r.status == 400 and "no scale" in r.json()["message"]


def test_correct_reject_suggest_and_accept(call, plan):                             # C2S7-A01
    _, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements/propose",
                   {"module_id": "roofing", "feeds": "roof_area_sqft", "object_ids": [plan["room"]["id"]], "approve": True})
    mid = done["proposed"][0]["id"]
    ask, out = _yes(call, f"{API}/measurements/{mid}/edit", {"qty": "150", "room": "Kitchen"})
    assert "person's correction" in ask["question"]
    assert out["measurement"]["qty"] == "150.00" and out["measurement"]["status"] == "approved"
    _yes(call, f"{API}/measurements/{mid}/suggest", {"qty": "148", "reason": "measured on site"})
    page = call("GET", f"{API}/estimates/{plan['est']}/takeoff").json()
    assert page["takeoff"]["suggestions_waiting"] == [mid]
    _yes(call, f"{API}/measurements/approve", {"measurement_ids": [mid], "accept_suggestion": True})
    d = call("GET", f"{API}/measurements/{mid}").json()
    assert d["measurement"]["qty"] == "148.00" and d["measurement"]["suggested_qty"] is None
    _yes(call, f"{API}/measurements/{mid}/reject", {"reason": "double counted"})
    d = call("GET", f"{API}/measurements/{mid}").json()
    assert d["measurement"]["status"] == "rejected" and d["measurement"]["reject_reason"] == "double counted"
    actions = [h["action"] for h in d["history"]]
    assert actions[0] == "measurement_proposed" and "measurement_suggestion_accepted" in actions and actions[-1] == "measurement_rejected"


def test_detail_panel(call, plan):                                                  # C2S7-D01
    _, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements/propose",
                   {"module_id": "roofing", "feeds": "roof_area_sqft", "object_ids": [plan["room"]["id"]]})
    d = call("GET", f"{API}/measurements/{done['proposed'][0]['id']}").json()
    assert d["calc"]["how"] == "area of 1 drawing object(s)" and d["sheet"]["sheet_no"] == "A-101"
    assert Decimal(d["viewport"]["scale_ratio"]) == 48 and d["source_objects"][0]["label"] == "KITCHEN"
    assert d["measurement"]["proposed_by"] and d["measurement"]["approved_by"] is None


def test_bulk_approve_by_confidence(call, plan):                                    # C2S7-A02
    _yes(call, f"{API}/estimates/{plan['est']}/measurements/propose",
         {"module_id": "roofing", "feeds": "roof_area_sqft", "object_ids": [plan["room"]["id"]]})       # 0.75
    _yes(call, f"{API}/estimates/{plan['est']}/measurements/propose",
         {"module_id": "roofing", "feeds": "edges_lf", "object_ids": [plan["wall"]["id"]]})             # 0.7
    ask, done = _yes(call, f"{API}/measurements/approve", {"estimate_id": plan["est"], "above_confidence": "0.72"})
    assert len(done["done"]) == 1
    nothing = call("POST", f"{API}/measurements/approve", {"estimate_id": plan["est"], "above_confidence": 0.9})
    assert nothing.status == 400 and "nothing to do" in nothing.json()["message"]


def test_roles(call, plan, session_for):                                            # C2S7-R01
    reviewer = session_for("reviewer")
    page = call("GET", f"{API}/estimates/{plan['est']}/takeoff", headers=reviewer).json()
    assert (page["can_measure"], page["can_approve"], page["can_correct"]) == (False, True, True)
    body = {"module_id": "roofing", "feeds": "roof_area_sqft", "object_ids": [plan["room"]["id"]], "confirm": True}
    assert call("POST", f"{API}/estimates/{plan['est']}/measurements/propose", body, headers=reviewer).status == 403
    _, done = _yes(call, f"{API}/estimates/{plan['est']}/measurements/propose",
                   {k: v for k, v in body.items() if k != "confirm"})
    mid = done["proposed"][0]["id"]
    _yes(call, f"{API}/measurements/approve", {"measurement_ids": [mid]}, headers=reviewer)          # reviewers approve
    assert call("GET", f"{API}/takeoffs", headers=session_for("field")).status == 403
    # Office (the Jobs app's managers and staff) approve, but don't measure or correct (David, 2026-11-09).
    office = session_for("office")
    page = call("GET", f"{API}/estimates/{plan['est']}/takeoff", headers=office).json()
    assert (page["can_measure"], page["can_approve"], page["can_correct"]) == (False, True, False)
    assert call("POST", f"{API}/estimates/{plan['est']}/measurements/propose", body, headers=office).status == 403
    other = session_for("owner", company="acme")
    assert call("GET", f"{API}/measurements/{mid}", headers=other).status == 404
    assert call("GET", f"{API}/estimates/{plan['est']}/takeoff", headers=other).status == 404
    assert call("POST", f"{API}/measurements/{mid}/reject", {"confirm": True}, write_header=False).status == 403   # CSRF


def test_bad_requests(call, plan):                                                  # C2S7-B01
    e = plan["est"]
    cases = [
        (f"/estimates/{e}/measurements/propose", {"module_id": "roofing", "object_ids": "1,2"}),
        (f"/estimates/{e}/measurements/propose", {"module_id": "roofing", "object_ids": [True]}),
        (f"/estimates/{e}/measurements/propose", {"object_ids": [plan["room"]["id"]]}),
        (f"/estimates/{e}/measurements/propose", {"module_id": "roofing", "object_ids": [plan["room"]["id"]], "label": "x" * 201}),
        (f"/estimates/{e}/measurements", {"module_id": "roofing", "geometry": "polygon"}),
        (f"/estimates/{e}/measurements", {"module_id": "roofing", "feeds": "no_such", "qty": "1", "unit": "sqft"}),
        ("/measurements/approve", {"measurement_ids": ["1"]}),
        ("/measurements/approve", {"estimate_id": e, "above_confidence": True}),
    ]
    for path, body in cases:
        r = call("POST", API + path, {**body, "confirm": True})
        assert r.status == 400, (path, body, r.json())
    assert call("GET", f"{API}/measurements/999999").status == 404
    assert call("POST", f"{API}/measurements/999999/edit", {"qty": "1", "confirm": True}).status == 404
    assert call("GET", f"{API}/estimates/{e}/takeoff/nope").status == 404


# ---------------------------------------------------------------- the page

def test_screen_and_page_are_built():                                               # C2S7-W01
    screen = next(s for s in nav.SCREENS if s["id"] == "takeoffs")
    assert screen["status"] == "ready" and screen["roles"] == ("owner", "estimator", "reviewer", "office")
    page = next(p for p in nav.PAGES if p["id"] == "takeoff")
    assert page["from"] == "takeoffs" and "takeoff_confirm" in page["tools"]
    html = (router.WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert html.index('src="app.js"') < html.index('src="review.js"') and 'review.js" defer' in html
    js = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
    for needed in ("SCREENS.takeoffs = renderTakeoffs", "PAGES.takeoff = renderReview", "/tiles/", "/objects",
                   "/measurements/propose", "/measurements/approve", "/edit", "/reject", "/suggest", "/takeoff\"",
                   "above_confidence", "accept_suggestion", "/viewports/", "calibration"):
        assert needed in js, needed
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", 'style="', "eval(", "document.write"):
        assert bad not in js, bad
    app = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert 'page: "takeoff"' in app and "project-review" in app and "sheet-review" in app
    assert router.static("/estimator/review.js").status == 200


def test_page_buttons_named_in_the_guide_exist():                                   # C2S7-W02
    from estimator.ui import help as guides
    g = guides.get_guide("measure_and_approve_on_the_plans")
    assert g["screen"] == "takeoffs"
    js = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
    for label in ("Make a measurement from these", "Approve it now", "Approve all", "Correct…", "Reject…",
                  "Suggest a change", "Accept the suggestion", "Calibrate", "Fit", "Review queue"):
        assert label in js, label
        assert label.rstrip("…") in g["text"], label

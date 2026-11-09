"""Coder 2 Sprint 13: reviews on a phone or tablet - one review queue of symbols to check and measurements waiting,
least sure first (GET /mobile/reviews); each item in place on its sheet, outlined (the highlight); the touch page
(#/m/reviews) and the Jobs app's Estimates tab switch; pictures sent with the Jobs app's token."""
import io
import sys
from pathlib import Path

import pytest

from estimator.api import nav
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402
from test_plan_engine_sprint10 import legend, plan, shape  # noqa: E402
from test_web_sprint7 import QUARTER, _square, _yes  # noqa: E402

API = "/estimator-api"
REPO = Path(__file__).resolve().parents[3]
WEB = REPO / "estimator" / "ui" / "web"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def job(call, db, tmp_path):
    """Two projects: Smith house (a 12 x 12 ft KITCHEN with three measurements waiting: from the room, drawn, typed)
    and Jones power (3 receptacles and 2 symbols the legend doesn't name, all to check)."""
    ctx = personal_context()
    texts = title_block("A-101", "FIRST FLOOR PLAN") + [(4, 21, 14, "FLOOR PLAN"), (4, 21.35, 9, QUARTER),
                                                        (6, 6.4, 10, "KITCHEN")]
    pdf = make_pdf(tmp_path / "smith.pdf", [{"w": 36, "h": 24, "texts": texts, "lines": _square(5, 5, 3)}])
    smith = service.create_estimate(db, ctx, "Smith house")
    ps = store.upload(db, ctx, smith["id"], str(pdf), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    sheet = call("GET", f"{API}/plan-sets/{ps}").json()["sheets"][0]
    room = next(o for o in call("GET", f"{API}/sheets/{sheet['id']}/objects").json()["objects"] if o["kind"] == "room")
    vp = call("GET", f"{API}/sheets/{sheet['id']}").json()["viewports"][0]
    from_room = _yes(call, f"{API}/estimates/{smith['id']}/measurements/propose",
                     {"module_id": "flooring", "feeds": "area_sqft", "object_ids": [room["id"]], "room": "KITCHEN"})[1]
    drawn = _yes(call, f"{API}/estimates/{smith['id']}/measurements",
                 {"module_id": "flooring", "feeds": "baseboard_lf", "viewport_id": vp["id"],
                  "geometry": {"type": "polyline", "points": [[20, 10], [23, 10], [23, 12]]}})[1]
    typed = _yes(call, f"{API}/estimates/{smith['id']}/measurements",
                 {"module_id": "flooring", "feeds": "area_sqft", "qty": "300", "unit": "sqft"})[1]

    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("flag", 12, 8) + \
        shape("flag", 14, 8, 30)
    jones = service.create_estimate(db, ctx, "Jones power")
    ps2 = store.upload(db, ctx, jones["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps2}/process", {"confirm": True}).status == 200
    dets = call("GET", f"{API}/plan-sets/{ps2}/symbols").json()["detections"]
    return {"smith": smith["id"], "jones": jones["id"], "room_m": from_room["proposed"][0]["id"],
            "drawn_m": drawn["measurement"]["id"], "typed_m": typed["measurement"]["id"],
            "recept": [d["id"] for d in dets if d["item_type"] == "duplex_receptacle"],
            "unknown": [d["id"] for d in dets if d["item_type"] is None]}


def _png(body):
    import numpy as np
    from PIL import Image
    img = Image.open(io.BytesIO(body)).convert("RGB")
    a = np.asarray(img)
    reds = int(((a[..., 0] > 200) & (a[..., 1] < 80) & (a[..., 2] < 80)).sum())
    return img.size, reds


# ---------------------------------------------------------------- the queue                        C2S13-Q01..Q03

def test_one_queue_least_sure_first(call, job):                                     # C2S13-Q01
    r = call("GET", f"{API}/mobile/reviews").json()
    assert (r["counts"], r["waiting"], r["count"]) == ({"symbols": 5, "measurements": 3}, 8, 8)
    confs = [float(x["confidence"] or 0) for x in r["items"]]
    assert confs == sorted(confs)                                                   # least sure first
    kinds = {(x["kind"], x["id"]) for x in r["items"]}
    assert {("measurement", job["room_m"]), ("measurement", job["drawn_m"]), ("measurement", job["typed_m"])} <= kinds
    assert {("symbol", i) for i in job["recept"] + job["unknown"]} <= kinds
    rec = next(x for x in r["items"] if x["kind"] == "symbol" and x["id"] == job["recept"][0])
    assert rec["title"] == "Duplex receptacle" and rec["estimate_title"] == "Jones power" and rec["sheet_no"]
    assert rec["picture"] == f"/estimator-api/mobile/symbols/{rec['id']}/view.png"
    assert rec["plan_link"].startswith(f"#/takeoffs/{job['jones']}?sheet=") and rec["plan_link"].endswith(f"&symbol={rec['id']}")
    unk = next(x for x in r["items"] if x["id"] == job["unknown"][0] and x["kind"] == "symbol")
    assert unk["title"] in ("Special device", "Unidentified symbol")
    room = next(x for x in r["items"] if x["kind"] == "measurement" and x["id"] == job["room_m"])
    assert room["detail"].startswith("144.00 sqft") and "Flooring" in room["detail"] and room["room"] == "KITCHEN"
    typed = next(x for x in r["items"] if x["kind"] == "measurement" and x["id"] == job["typed_m"])
    assert typed["picture"] is None and typed["sheet_no"] is None                   # typed: nothing to show on a plan
    assert r["can"] == {"symbol": True, "measurement": True, "review_symbols": True, "approve_measurements": True}
    assert {p["title"] for p in r["projects"]} == {"Smith house", "Jones power"}
    assert any(t["item_type"] == "kitchen_sink" for t in r["item_types"])           # for Relabel…


def test_filters(call, job):                                                         # C2S13-Q02
    sym = call("GET", f"{API}/mobile/reviews?kind=symbol").json()
    assert {x["kind"] for x in sym["items"]} == {"symbol"} and sym["counts"]["measurements"] == 0
    smith = call("GET", f"{API}/mobile/reviews?estimate_id={job['smith']}").json()
    assert {x["estimate_id"] for x in smith["items"]} == {job["smith"]} and smith["counts"] == {"symbols": 0, "measurements": 3}
    assert call("GET", f"{API}/mobile/reviews?limit=2").json()["count"] == 2
    for bad in ("kind=photos", "estimate_id=x", "limit=lots"):
        assert call("GET", f"{API}/mobile/reviews?{bad}").status == 400, bad
    assert call("POST", f"{API}/mobile/reviews", {}).status in (404, 405)


def test_who_sees_what(call, job, session_for):                                     # C2S13-Q03
    field = call("GET", f"{API}/mobile/reviews", headers=session_for("field")).json()
    assert {x["kind"] for x in field["items"]} == {"symbol"}                        # field: symbols, look only
    assert field["can"]["review_symbols"] is False and field["can"]["measurement"] is False
    rev = call("GET", f"{API}/mobile/reviews", headers=session_for("reviewer")).json()
    assert rev["can"]["review_symbols"] and rev["can"]["approve_measurements"] and rev["waiting"] == 8
    assert call("GET", f"{API}/mobile/reviews", headers=session_for("office")).status == 403
    other = call("GET", f"{API}/mobile/reviews", headers=session_for("owner", company="acme")).json()
    assert other["waiting"] == 0 and other["items"] == []


# ---------------------------------------------------------------- pictures in place                C2S13-V01..V02

def test_each_item_in_place_outlined(call, job):                                    # C2S13-V01
    r = call("GET", f"{API}/mobile/symbols/{job['recept'][0]}/view.png")
    assert r.status == 200 and r.content_type == "image/png" and r.headers["X-Content-Type-Options"] == "nosniff"
    (w, h), reds = _png(r.body)
    assert w <= 900 and h > 100 and reds > 200                                      # the sheet round it, outlined in red
    thumb = call("GET", f"{API}/symbol-detections/{job['recept'][0]}/crop.png")
    assert w > _png(thumb.body)[0][0]                                               # more than the thumbnail: in place
    for mid in (job["room_m"], job["drawn_m"]):                                      # from the room object; drawn shape
        r = call("GET", f"{API}/mobile/measurements/{mid}/view.png")
        assert r.status == 200 and _png(r.body)[1] > 200, mid
    again = call("GET", f"{API}/mobile/measurements/{job['drawn_m']}/view.png")
    assert again.body == r.body                                                     # the same cached picture


def test_pictures_are_refused_where_they_should_be(call, job, session_for):        # C2S13-V02
    assert call("GET", f"{API}/mobile/measurements/{job['typed_m']}/view.png").status == 404   # typed in
    assert call("GET", f"{API}/mobile/measurements/999999/view.png").status == 404
    assert call("GET", f"{API}/mobile/symbols/999999/view.png").status == 404
    acme = session_for("owner", company="acme")
    assert call("GET", f"{API}/mobile/symbols/{job['recept'][0]}/view.png", headers=acme).status == 404
    field = session_for("field")
    assert call("GET", f"{API}/mobile/symbols/{job['recept'][0]}/view.png", headers=field).status == 200
    assert call("GET", f"{API}/mobile/measurements/{job['room_m']}/view.png", headers=field).status == 403


# ---------------------------------------------------------------- deciding from the phone           C2S13-D01

def test_decisions_leave_the_queue(call, job, session_for):                         # C2S13-D01
    _yes(call, f"{API}/symbol-detections/review", {"detection_ids": [job["recept"][0]], "action": "approve"})
    _yes(call, f"{API}/symbol-detections/review", {"detection_ids": [job["unknown"][0]], "action": "relabel",
                                                   "item_type": "floor_box"})
    _yes(call, f"{API}/measurements/approve", {"measurement_ids": [job["room_m"]]})
    _yes(call, f"{API}/measurements/{job['drawn_m']}/reject", {"reason": "taken out on the phone"})
    r = call("GET", f"{API}/mobile/reviews").json()
    left = {(x["kind"], x["id"]) for x in r["items"]}
    assert ("symbol", job["recept"][0]) not in left and ("measurement", job["room_m"]) not in left
    assert ("measurement", job["drawn_m"]) not in left and r["waiting"] == 4
    relabelled = call("GET", f"{API}/mobile/reviews?kind=symbol").json()["items"]
    assert all(x["id"] != job["unknown"][0] for x in relabelled) or \
        next(x for x in relabelled if x["id"] == job["unknown"][0])["item_type"] == "floor_box"
    # Field staff look only: the service refuses their decision.
    f = call("POST", f"{API}/symbol-detections/review", {"detection_ids": [job["recept"][1]], "action": "approve",
                                                        "confirm": True}, headers=session_for("field"))
    assert f.status == 403


# ---------------------------------------------------------------- the page and the Jobs app          C2S13-W01..W02

def test_the_touch_page_is_wired():                                                  # C2S13-W01
    assert any(p["id"] == "mobile_reviews" and p["from"] == "reviews" for p in nav.PAGES)
    js = (WEB / "mobile.js").read_text(encoding="utf-8")
    for part in ("PAGES.mobile_reviews = renderMobileReviews", "mrev-approve", "mrev-reject", "mrev-relabel", "mrev-skip",
                 "pointerdown", "askThen(", "apiImage("):
        assert part in js, part
    assert 'style="' not in js and ".style." not in js                             # CSP: no inline styles
    app = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'parts[0] === "m" && parts[1] === "reviews"' in app and "function apiImage(" in app
    assert "apiImage(img" in (WEB / "verify.js").read_text(encoding="utf-8")       # Reviews thumbnails too
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert html.index("review.js") < html.index("mobile.js")                       # uses review.js's pct()
    css = (WEB / "app.css").read_text(encoding="utf-8")
    assert "button.big { min-height: 56px" in css                                  # thumb-sized targets


def test_the_jobs_app_estimates_tab_has_reviews():                                  # C2S13-W02
    jobs = (REPO / "jobs" / "index.html").read_text(encoding="utf-8")
    for part in ('data-testid="est-mode-quick"', 'data-testid="est-mode-reviews"', 'data-testid="est-review-count"',
                 "'/estimator/?embed=1#/m/reviews'", "'/estimator-api/mobile/reviews?limit=1'",
                 "s.mode === 'server' ? s.access_token : s.token"):
        assert part in jobs, part

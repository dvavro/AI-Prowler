"""Coder 2 Sprint 5: the Plans screen, a plan set's sheets (read by the plan engine), and a sheet's viewports with
setting a scale and two-point calibration. Every call goes through the same functions as the plan_* MCP tools."""
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from estimator.api import nav, router
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402  (shared with the plan engine tests)

API = "/estimator-api"


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
def plan_set(db, tmp_path):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    pdf = make_pdf(tmp_path / "smith plans.pdf", [
        _page("A-101", "FIRST FLOOR PLAN", [(4, 20, "FLOOR PLAN", 'SCALE: 1/4" = 1\'-0"'),
                                            (20, 20, "WALL TYPES", "SCALE: NTS")]),
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


# ---------------------------------------------------------------- Plans screen and plan sets

def test_plans_screen_lists_every_plan_set(call, plan_set):
    r = call("GET", f"{API}/plans").json()
    assert r["count"] == 1 and r["engine"]["installed"] is True and r["can_edit"] is True
    p = r["plan_sets"][0]
    assert (p["id"], p["estimate_title"], p["file"], p["status"]) == (plan_set["plan_set_id"], "Smith house",
                                                                      "smith plans.pdf", "uploaded")


def test_reading_asks_first_then_finds_the_sheets(call, plan_set):
    ps = plan_set["plan_set_id"]
    ask = call("POST", f"{API}/plan-sets/{ps}/process", {}).json()
    assert ask["needs_confirmation"] is True and "smith plans.pdf" in ask["question"]
    assert call("GET", f"{API}/plan-sets/{ps}").json()["plan_set"]["status"] == "uploaded"     # nothing done yet
    r = _read(call, ps)
    assert r["plan_set"]["status"] == "processed" and r["estimate"] == {"id": plan_set["estimate_id"], "title": "Smith house"}
    by = {s["sheet_no"]: s for s in r["sheets"]}
    assert set(by) == {"A-101", "E-101"}
    assert by["A-101"]["discipline"] == "architectural" and by["E-101"]["discipline"] == "electrical"
    assert by["A-101"]["needs_scale"] is False and by["E-101"]["needs_scale"] is True
    assert "need a scale" in r["plan_set"]["say"]


def test_reading_again_asks_because_it_replaces(call, plan_set):
    ps = plan_set["plan_set_id"]
    _read(call, ps)
    again = call("POST", f"{API}/plan-sets/{ps}/process", {}).json()
    assert again["needs_confirmation"] is True and "replaces" in again["question"]


def test_without_the_engine_the_page_is_told(call, plan_set, monkeypatch):
    monkeypatch.setattr(engine, "ENGINE_MODULES", ("estimator.no_such_engine",))
    engine.clear_engine()
    assert call("GET", f"{API}/plans").json()["engine"]["installed"] is False
    r = call("POST", f"{API}/plan-sets/{plan_set['plan_set_id']}/process", {"confirm": True})
    assert r.json()["error"] == "not_available" and "isn't installed" in r.json()["message"]


# ---------------------------------------------------------------- one sheet: image, viewports, scales

def test_sheet_page_has_its_size_and_viewports(call, plan_set):
    ps = plan_set["plan_set_id"]
    _read(call, ps)
    a101 = _sheet(call, ps, "A-101")
    r = call("GET", f"{API}/sheets/{a101['id']}").json()
    assert Decimal(r["sheet"]["width"]) == 36 and Decimal(r["sheet"]["height"]) == 24 and r["sheet"]["has_image"]
    assert r["plan_set"]["id"] == ps and r["can_edit"] is True
    vps = {v["label"]: v for v in r["viewports"]}
    assert Decimal(vps["FLOOR PLAN"]["scale_ratio"]) == 48 and vps["WALL TYPES"]["is_nts"] is True
    assert all(len(v["bbox"]) == 4 for v in r["viewports"])
    assert "image_path" not in r["sheet"]                                     # the PC's file path stays on the PC


def test_sheet_image_is_served_from_the_data_folder_only(call, plan_set, db, tmp_path):
    ps = plan_set["plan_set_id"]
    _read(call, ps)
    a101 = _sheet(call, ps, "A-101")
    img = call("GET", f"{API}/sheets/{a101['id']}/image")
    assert img.status == 200 and img.content_type == "image/png" and img.body[:8] == b"\x89PNG\r\n\x1a\n"
    assert img.headers["X-Content-Type-Options"] == "nosniff"
    outside = tmp_path / "secret.png"
    outside.write_bytes(b"\x89PNG\r\n\x1a\nsecret")
    db.execute("UPDATE sheets SET image_path = ? WHERE id = ?", (str(outside), a101["id"]))
    db.commit()
    assert call("GET", f"{API}/sheets/{a101['id']}/image").status == 404


def test_set_a_scale_from_a_note_asks_first(call, plan_set):
    ps = plan_set["plan_set_id"]
    _read(call, ps)
    e101 = _sheet(call, ps, "E-101")
    vp = call("GET", f"{API}/sheets/{e101['id']}").json()["viewports"][0]
    ask = call("POST", f"{API}/viewports/{vp['id']}/scale", {"scale_note": '1/8" = 1\'-0"'}).json()
    assert ask["needs_confirmation"] is True and "96" in ask["question"]
    done = call("POST", f"{API}/viewports/{vp['id']}/scale", {"scale_note": '1/8" = 1\'-0"', "confirm": True}).json()
    assert Decimal(done["viewport"]["scale_ratio"]) == 96 and done["viewport"]["scale_method"] == "note"
    assert _sheet(call, ps, "E-101")["needs_scale"] is False


def test_two_point_calibration(call, plan_set):
    ps = plan_set["plan_set_id"]
    _read(call, ps)
    e101 = _sheet(call, ps, "E-101")
    vp = call("GET", f"{API}/sheets/{e101['id']}").json()["viewports"][0]
    cal = {"p1": [5, 10], "p2": [8, 14], "distance": "20'"}                  # 5 paper inches = 20 feet -> 1:48
    done = call("POST", f"{API}/viewports/{vp['id']}/scale", {"calibration": cal, "confirm": True}).json()
    assert Decimal(done["viewport"]["scale_ratio"]) == 48 and done["viewport"]["scale_method"] == "calibration"


@pytest.mark.parametrize("body, words", [
    ({"calibration": "5,10 8,14"}, "calibration must be"),
    ({}, "exactly one"),
    ({"scale_note": "1:50", "scale_ratio": 48}, "exactly one"),
    ({"calibration": {"p1": [5, 10], "p2": [5, 10], "distance": "10'"}, "confirm": True}, "same point"),
    ({"scale_note": "AS NOTED", "confirm": True}, "can't read the scale"),
])
def test_bad_scales_are_refused(call, plan_set, body, words):
    ps = plan_set["plan_set_id"]
    _read(call, ps)
    vp = call("GET", f"{API}/sheets/{_sheet(call, ps, 'E-101')['id']}").json()["viewports"][0]
    r = call("POST", f"{API}/viewports/{vp['id']}/scale", body)
    assert r.status == 400 and words in r.json()["message"], r.body


# ---------------------------------------------------------------- who can do what

def test_roles(call, plan_set, session_for, db):
    ps = plan_set["plan_set_id"]
    _read(call, ps)
    a101 = _sheet(call, ps, "A-101")
    vp = call("GET", f"{API}/sheets/{a101['id']}").json()["viewports"][0]
    for role in ("reviewer", "field"):                        # look, but not change
        h = session_for(role)
        assert call("GET", f"{API}/plans", headers=h).json()["can_edit"] is False
        assert call("GET", f"{API}/sheets/{a101['id']}", headers=h).status == 200
        assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}, headers=h).status == 403
        assert call("POST", f"{API}/viewports/{vp['id']}/scale", {"scale_note": "1:50", "confirm": True},
                    headers=h).status == 403
    assert call("GET", f"{API}/plans", headers=session_for("office")).status == 200   # office look (2026-11-09)
    assert call("GET", f"{API}/sheets/{a101['id']}", headers=session_for("owner", company="acme")).status == 404
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}, write_header=False).status == 403


def test_unknown_things_are_404(call):
    for path in ("/plan-sets/999", "/sheets/999", "/sheets/999/image"):
        assert call("GET", API + path).status == 404, path
    assert call("POST", f"{API}/viewports/999/scale", {"scale_note": "1:50"}).status == 404


# ---------------------------------------------------------------- nav, page and guide

def test_plans_screen_ready_with_its_pages():
    plans = next(s for s in nav.SCREENS if s["id"] == "plans")
    assert plans["status"] == "ready" and set(plans["roles"]) == {"owner", "estimator", "reviewer", "office", "field"}
    assert {"plan_set", "sheet"} <= {p["id"] for p in nav.PAGES}


def test_web_page_has_the_plans_pages():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for needle in ("/plan-sets/", "/process", "/sheets/", "/image", "/viewports/", "calibration", "#/plan-sets/", "#/sheets/"):
        assert needle in js, needle
    assert "innerHTML" not in js and "setAttribute(\"style\"" not in js     # CSP: styles only through the DOM


def test_plans_guide_names_real_buttons():
    from estimator.ui import help as guides
    g = guides.get_guide("upload_plans_and_check_the_scale")
    assert g["screen"] == "plans" and g["steps"] >= 6
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for label in ("Upload and check", "Attach", "📖 Read the plans…", "Set…", "📏 Calibrate…", "Set the scale…"):
        assert label in js and label in g["text"], label

"""Sheet viewer (2026-11-13, David): anyone who can open the plans can zoom and pan a sheet to read details on the job;
field crew (and reviewers / office) only look - every change to the plans is refused by the server, not just hidden."""
import sys
from pathlib import Path

import pytest

from estimator.api import router
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402

API = "/estimator-api"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def sheet(db, tmp_path, call):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Shed slab")
    texts = title_block("S-101", "FOUNDATION PLAN") + [(4, 20, 14, "FOUNDATION PLAN"), (4, 20.35, 9, 'SCALE: 1/4" = 1\'-0"')]
    pdf = make_pdf(tmp_path / "shed.pdf", [{"w": 36, "h": 24, "texts": texts}])
    ps = store.upload(db, ctx, est["id"], str(pdf), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    s = call("GET", f"{API}/plan-sets/{ps}").json()["sheets"][0]
    vp = call("GET", f"{API}/sheets/{s['id']}").json()["viewports"][0]
    return {"plan_set_id": ps, "sheet_id": s["id"], "viewport_id": vp["id"]}


def test_field_crew_can_view_the_sheet_and_its_picture(call, sheet, session_for):
    h = session_for("field")
    ps = call("GET", f"{API}/plan-sets/{sheet['plan_set_id']}", headers=h)
    assert ps.status == 200 and ps.json()["can_edit"] is False
    s = call("GET", f"{API}/sheets/{sheet['sheet_id']}", headers=h)
    assert s.status == 200 and s.json()["can_edit"] is False and s.json()["sheet"]["has_image"] is True
    img = call("GET", f"{API}/sheets/{sheet['sheet_id']}/image", headers=h)
    assert img.status == 200 and img.content_type == "image/png"


@pytest.mark.parametrize("role", ["field", "reviewer", "office"])
def test_every_plan_change_is_refused_for_view_only_roles(call, sheet, session_for, role):
    h = session_for(role)
    ps, sid, vp = sheet["plan_set_id"], sheet["sheet_id"], sheet["viewport_id"]
    changes = [
        (f"{API}/plan-sets/{ps}/process", {"confirm": True}),                         # read the plans again
        (f"{API}/plan-sets/{ps}/remove", {"confirm": True}),                          # remove the plan set
        (f"{API}/sheets/{sid}/remove", {"confirm": True}),                            # remove a sheet
        (f"{API}/sheets/{sid}/trade-active", {"module_id": "concrete", "active": False}),   # takeoff on/off
        (f"{API}/viewports/{vp}/scale", {"scale_note": "1/8\" = 1'-0\"", "confirm": True}),   # set a scale
        (f"{API}/viewports/{vp}/scale", {"calibration": {"p1": [1, 1], "p2": [5, 1], "distance": "16'"},
                                          "confirm": True}),                          # calibrate
    ]
    before = call("GET", f"{API}/sheets/{sid}").json()["viewports"][0]
    for url, body in changes:
        r = call("POST", url, body, headers=h)
        assert r.status == 403, (role, url, r.body)
    # Nothing changed: the sheet, its scale and its takeoff switch are as they were.
    s = call("GET", f"{API}/sheets/{sid}").json()
    assert s["inactive_trades"] == []
    assert (s["viewports"][0]["scale_note"], s["viewports"][0]["scale_ratio"]) == (before["scale_note"], before["scale_ratio"])
    assert call("GET", f"{API}/plan-sets/{ps}").json()["sheets"][0]["id"] == sid


def test_owner_still_can_change_the_plans(call, sheet):
    r = call("POST", f"{API}/sheets/{sheet['sheet_id']}/trade-active", {"module_id": "concrete", "active": False})
    assert r.status == 200, r.body


def test_sheet_page_has_the_zoom_viewer_and_hides_changes_from_view_only_roles():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for part in ("function makeZoomable(viewer, stage, img, sharp)", "function zoomBar(zoom)", 'id: "sheet-viewer"',
                 "{ tiles: r.tiles, sheetId: id }", '"/tiles/"', 'class: "sheet-tile"',              # sharp when zoomed
                 'btn("zoom-in"', 'btn("zoom-out"', 'btn("zoom-fit"', 'btn("zoom-full"', '"wheel"', '"pointerdown"',
                 'id: "sheet-view-only"'):
        assert part in js, part
    # The change controls on the plan set and sheet pages only appear with can_edit.
    assert "r.can_edit && paper ? el(\"td\", {}, scaleControls(" in js
    assert "if (r.can_edit && ps.status !== \"processing\")" in js
    assert "if (!r.can_edit) return el(\"td\", {});" in js
    css = (router.WEB_DIR / "app.css").read_text(encoding="utf-8")
    assert ".sheet-viewer" in css and "transform-origin: 0 0" in css
    assert "will-change: transform;" not in css.split(".sheet-viewer .sheet-stage")[1].split("}")[0]   # would blur


def test_view_only_hides_the_view_boxes():
    """2026-11-13: "View only" hides the boxes drawn over the sheet (views with their scale / NTS); on by default for
    people who can't change the plans, and each person's choice is remembered."""
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "function viewOnlyButton(stage, defaultOn)" in js and "viewOnlyButton(stage, !r.can_edit)" in js
    assert 'stage.classList.toggle("views-hidden", on)' in js and '"est_sheet_view_only"' in js
    css = (router.WEB_DIR / "app.css").read_text(encoding="utf-8")
    assert ".sheet-stage.views-hidden .vp-box { display: none; }" in css


def test_phone_sideways_gives_the_plans_the_room():
    """2026-11-13: in the Jobs app's Estimates tab, a phone turned sideways hides the Quick estimate / Reviews
    buttons and the frame takes the space."""
    from pathlib import Path
    page = (Path(router.WEB_DIR).parents[2] / "jobs" / "index.html").read_text(encoding="utf-8")
    assert '<div class="est-modes"' in page and 'id="estModeQuick"' in page
    rule = page.split("@media (orientation: landscape) and (max-height: 540px){", 1)[1].split("}\n}", 1)[0]
    assert "#screen-estimates .est-modes{display:none !important}" in rule and "#estimatesFrame{height:" in rule


def test_field_crew_can_load_the_sharp_tiles(call, sheet, session_for):
    s = call("GET", f"{API}/sheets/{sheet['sheet_id']}", headers=session_for("field")).json()
    t = s["tiles"]
    assert t and t["max_level"] >= 1
    r = call("GET", f"{API}/sheets/{sheet['sheet_id']}/tiles/{t['max_level']}/0/0.png", headers=session_for("field"))
    assert r.status == 200 and r.content_type == "image/png"

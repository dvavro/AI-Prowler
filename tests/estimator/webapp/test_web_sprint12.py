"""Coder 2 Sprint 12: the Plan quantities page - the shared wall-and-room model of a project and each trade's answers
from it (GET /estimates/<id>/quantities), linked from Blueprint Review."""
import sys
from pathlib import Path

import pytest

from estimator.api import nav
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf  # noqa: E402
from test_plan_engine_sprint12 import HOUSE, NAMES, SCHEDULES, TAGS, page  # noqa: E402

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
GUIDES = WEB.parent / "help" / "guides"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def house(db, tmp_path, call):
    est = service.create_estimate(db, personal_context(), "Smith house")
    ps = store.upload(db, personal_context(), est["id"], str(make_pdf(tmp_path / "house.pdf", [page(NAMES + SCHEDULES + TAGS, HOUSE)])),
                      confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    return est["id"]


def test_quantities_for_a_project(call, house, session_for):                      # C2S12-W01
    r = call("GET", f"{API}/estimates/{house}/quantities")
    assert r.status == 200
    b = r.json()
    assert b["estimate_title"] == "Smith house" and b["include_proposed"] is False
    assert b["model"]["totals"]["floor_sqft"] == 234.0 and len(b["model"]["rooms"]) == 2
    assert set(b["trades"]) == {"framing", "drywall", "painting", "insulation", "flooring", "electrical", "plumbing"}
    assert b["trades"]["drywall"]["answers"]["ceiling_sqft"] == b["trades"]["flooring"]["answers"]["area_sqft"]
    tall = call("GET", f"{API}/estimates/{house}/quantities?height=10&proposed=1").json()
    assert tall["model"]["totals"]["height_ft"] == 10.0 and tall["include_proposed"] is True
    assert tall["trades"]["framing"]["answers"]["wall_height"] == "10"
    # Roles: the Takeoffs roles look; office and field don't; another company can't see it.
    assert call("GET", f"{API}/estimates/{house}/quantities", headers=session_for("reviewer")).status == 200
    for role in ("office", "field"):
        assert call("GET", f"{API}/estimates/{house}/quantities", headers=session_for(role)).status == 403
    assert call("GET", f"{API}/estimates/{house}/quantities", headers=session_for("owner", company="acme")).status == 404


def test_bad_requests(call, house):                                              # C2S12-W02
    for q in ("height=tall", "height=2", "height=99"):
        r = call("GET", f"{API}/estimates/{house}/quantities?{q}")
        assert r.status == 400, q
    assert call("POST", f"{API}/estimates/{house}/quantities", {}).status in (404, 405)
    assert call("GET", f"{API}/estimates/999999/quantities").status == 404


def test_the_page_is_wired(call):                                                # C2S12-W03
    assert any(p["id"] == "quantities" and p["from"] == "takeoffs" for p in nav.PAGES)
    js = (WEB / "quantities.js").read_text(encoding="utf-8")
    assert "PAGES.quantities = renderQuantities" in js
    assert 'style="' not in js and ".style." not in js                             # CSP: no inline styles
    assert '"quantities"' in (WEB / "app.js").read_text(encoding="utf-8")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert html.index("app.js") < html.index("quantities.js")
    assert 'id: "bp-quantities", href: "#/quantities/"' in (WEB / "review.js").read_text(encoding="utf-8")
    guide = (GUIDES / "plan_quantities.md").read_text(encoding="utf-8")
    assert "screen: takeoffs" in guide and "Plan quantities" in guide
    found = call("GET", f"{API}/help/guides?q=drywall+quantities").json()
    assert any(g["id"] == "plan_quantities" for g in found.get("guides", found.get("results", [])))

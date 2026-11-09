"""Coder 2 Sprint 14: the Plan quantities page shows the door and window schedule (each mark linked to its tags) and
the exterior elevations, and answers windows and doors, siding and HVAC."""
import sys
from pathlib import Path

import pytest

from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf  # noqa: E402
from test_plan_engine_sprint12 import HOUSE, NAMES, TAGS, page  # noqa: E402
from test_plan_engine_sprint14 import LINKED, SIDES, four_sides  # noqa: E402

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def house(db, tmp_path, call):
    est = service.create_estimate(db, personal_context(), "Smith house")
    pdf = make_pdf(tmp_path / "house.pdf", [page(NAMES + LINKED + TAGS, HOUSE), four_sides()])
    ps = store.upload(db, personal_context(), est["id"], str(pdf), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    return est["id"]


def test_quantities_show_the_schedule_and_the_elevations(call, house):          # C2S14-P01
    b = call("GET", f"{API}/estimates/{house}/quantities").json()
    m = b["model"]
    assert {k["mark"]: k["on_plans"] for k in m["schedule_marks"]} == {"D1": 1, "D2": 1, "D3": 0, "W1": 1, "W2": 0}
    assert sorted(e["view"] for e in m["elevations"]) == sorted(SIDES)
    assert b["trades"]["windows_doors"]["answers"] == {"windows_small": 1, "exterior_doors": 1, "interior_doors": 1}
    s = b["trades"]["siding"]["answers"]
    assert s["openings"] == 12 and s["stories"] == "one" and s["walls"] == "simple"
    assert b["trades"]["hvac"]["answers"]["conditioned_sqft"] == 234.0
    assert b["trades"]["painting"]["answers"]["exterior_sqft"] == m["totals"]["elevation_net_sqft"]


def test_the_page_has_the_new_tables():                                          # C2S14-P02
    js = (WEB / "quantities.js").read_text(encoding="utf-8")
    for part in ('"qty-marks"', '"qty-elevations"', "Door and window schedule", "Exterior elevations",
                 'windows_doors: "', 'siding: "', 'hvac: "'):
        assert part in js, part
    assert 'style="' not in js and ".style." not in js

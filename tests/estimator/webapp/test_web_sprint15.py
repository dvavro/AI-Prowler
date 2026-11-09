"""Coder 2 Sprint 15: the Plan quantities page shows the site (landscape zones, fences, gates) and answers fencing and
landscaping from the site and landscape plans."""
import sys
from pathlib import Path

import pytest

from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf  # noqa: E402
from test_plan_engine_sprint15 import yard  # noqa: E402

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
HELP = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "help" / "guides"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def lopez(db, tmp_path, call):
    est = service.create_estimate(db, personal_context(), "Lopez yard")
    pdf = make_pdf(tmp_path / "yard.pdf", [yard()])
    ps = store.upload(db, personal_context(), est["id"], str(pdf), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    return est["id"]


def test_quantities_show_the_site_and_answer_fencing_and_landscaping(call, lopez):   # C2S15-P01
    b = call("GET", f"{API}/estimates/{lopez}/quantities").json()
    s = b["model"]["site"]
    assert {k: v for k, v in s["zone_sqft"].items() if v} == {"sod": 5632.0, "rock": 512.0, "pavers": 256.0}
    assert s["fence_groups"] == [{"material": "wood", "height_ft": 6.0, "length_ft": 114.0, "runs": 1}]
    assert s["gates"] == {"walk": 1, "drive": 1} and (s["plants"]["trees"], s["plants"]["shrubs"]) == (5, 14)
    assert b["trades"]["fencing"]["answers"]["length_lf"] == 114.0
    assert b["trades"]["landscaping"]["answers"]["sod_sqft"] == 5632.0
    assert b["model"]["rooms"] == [] and len(b["trades"]) == 12


def test_the_page_and_guide_have_the_site():                                         # C2S15-P02
    js = (WEB / "quantities.js").read_text(encoding="utf-8")
    for part in ('"qty-zones"', '"qty-fences"', '"qty-gates"', '"qty-site-only"', "Site and landscape",
                 'fencing: "', 'landscaping: "'):
        assert part in js, part
    assert 'style="' not in js and ".style." not in js
    guide = (HELP / "plan_quantities.md").read_text(encoding="utf-8")
    assert "**Site and landscape**" in guide and "fence" in guide

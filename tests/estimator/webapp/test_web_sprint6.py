"""Coder 2 Sprint 6 in the web app: a sheet says what the plan engine found (walls, rooms, symbols...) with measured
totals, and DXF drawings go through the Plans pages at real size (no scale to set)."""
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from estimator.api import router
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402

ezdxf = pytest.importorskip("ezdxf")
API = "/estimator-api"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _upload(db, path):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    return store.upload(db, ctx, est["id"], str(path), confirm=True)["plan_set_id"]


def _read_and_open_first_sheet(call, ps):
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    sheet = call("GET", f"{API}/plan-sets/{ps}").json()["sheets"][0]
    return call("GET", f"{API}/sheets/{sheet['id']}").json()


def _square(x, y, size):
    return [(x, y, x + size, y), (x + size, y, x + size, y + size), (x + size, y + size, x, y + size),
            (x, y + size, x, y)]


def _pdf(tmp_path, scale):
    texts = title_block("A-101", "FIRST FLOOR PLAN") + [(4, 21, 14, "FLOOR PLAN"), (6, 6.4, 10, "KITCHEN")]
    if scale:
        texts.append((4, 21.35, 9, scale))
    lines = _square(5, 5, 3) + [(10, 5, 14, 5), (10, 5.125, 14, 5.125)]
    return make_pdf(tmp_path / "smith.pdf", [{"w": 36, "h": 24, "texts": texts, "lines": lines}])


def test_sheet_says_what_was_found_and_measured(call, db, tmp_path):
    r = _read_and_open_first_sheet(call, _upload(db, _pdf(tmp_path, 'SCALE: 1/4" = 1\'-0"')))
    by = {f["kind"]: f for f in r["found"]}
    assert by["room"]["count"] == 1 and Decimal(by["room"]["area_sqft"]) == 144 and by["room"]["measured"] == 1
    assert by["wall"]["count"] == 1 and Decimal(by["wall"]["length_ft"]) == 16
    assert [f["kind"] for f in r["found"]][:2] == ["room", "wall"]                 # rooms first, then walls


def test_unscaled_finds_are_counted_but_not_measured(call, db, tmp_path):
    r = _read_and_open_first_sheet(call, _upload(db, _pdf(tmp_path, None)))
    by = {f["kind"]: f for f in r["found"]}
    assert by["wall"]["count"] == 1 and by["wall"]["measured"] == 0
    # Setting the scale measures them.
    vp = r["viewports"][0]
    call("POST", f"{API}/viewports/{vp['id']}/scale", {"scale_note": '1/4" = 1\'-0"', "confirm": True})
    again = call("GET", f"{API}/sheets/{r['sheet']['id']}").json()
    assert Decimal({f["kind"]: f for f in again["found"]}["wall"]["length_ft"]) == 16


def test_dxf_through_the_plans_pages(call, db, tmp_path):
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2                                                  # feet
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (20, 0), (20, 15), (0, 15)], close=True)
    msp.add_text("GARAGE", dxfattribs={"insert": (8, 7), "height": 1})
    blk = doc.blocks.new("LIGHT")
    blk.add_circle((0, 0), 0.5)
    msp.add_blockref("LIGHT", (5, 5))
    msp.add_blockref("LIGHT", (15, 5))
    path = tmp_path / "garage.dxf"
    doc.saveas(path)
    ps = _upload(db, path)
    r = _read_and_open_first_sheet(call, ps)
    assert r["sheet"]["units"] == "ft" and r["sheet"]["has_image"]
    by = {f["kind"]: f for f in r["found"]}
    assert Decimal(by["room"]["area_sqft"]) == 300 and by["symbol"]["count"] == 2
    img = call("GET", f"{API}/sheets/{r['sheet']['id']}/image")
    assert img.status == 200 and img.body[:4] == b"\x89PNG"
    # A CAD drawing is already real size: setting a scale is refused.
    vp = r["viewports"][0]
    bad = call("POST", f"{API}/viewports/{vp['id']}/scale", {"scale_note": "1:50", "confirm": True})
    assert bad.status == 400 and "doesn't need a scale" in bad.json()["message"]
    assert call("GET", f"{API}/plan-sets/{ps}").json()["sheets"][0]["needs_scale"] is False


def test_web_page_shows_the_found_summary():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "Found on this sheet" in js and "foundSummary" in js

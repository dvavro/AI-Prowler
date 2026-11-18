"""The Bill of Materials on the Estimates screen: read it, tick items ordered (web API + JS markers)."""
import pytest

from estimator.api import router
from estimator.context import personal_context
from estimator.estimating import quick, service

API = "/estimator-api"
CTX = personal_context()
ELEC = {"outlets": 10, "switches": 4, "lights": 6}


@pytest.fixture
def elec(db):
    e = service.create_estimate(db, CTX, "Electrical test")
    return quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])


def _section_id(est, module_id):
    return next(s["id"] for s in est["sections"] if s["module_id"] == module_id)


def _item(items, item_key):
    return next(i for i in items if i["item_key"] == item_key)


# ------------------------------------------------------------------ read

def test_get_bom_shape(call, elec):
    r = call("GET", f"{API}/estimates/{elec['id']}/bom")
    assert r.status == 200, r.json()
    out = r.json()
    assert out["ok"] and [b["module_id"] for b in out["bom"]] == ["electrical"]
    entry = out["bom"][0]
    assert entry["section_id"] == _section_id(elec, "electrical")
    assert [i["item_key"] for i in entry["items"]] == ["el_outlet_ea", "el_switch_ea",
                                                       "el_box_plastic_ea", "el_wire_lf",
                                                       "el_breaker_ea"]
    wire = _item(entry["items"], "el_wire_lf")
    assert wire["quantity"] == "500" and wire["order_quantity"] == "575.00"
    assert wire["unit"] == "lf" and wire["unit_cost_cents"] > 0 and wire["ordered"] is False


def test_get_bom_excludes_services(call, db):
    e = service.create_estimate(db, CTX, "Pressure wash")
    e = quick.answer(db, CTX, e["id"], "pressure_washing", {"driveway_sqft": 1000}, e["rev"])
    assert call("GET", f"{API}/estimates/{e['id']}/bom").json() == {"ok": True, "bom": []}
    # Mixed: the service trade stays out, the construction trade stays in.
    e = quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])
    out = call("GET", f"{API}/estimates/{e['id']}/bom").json()
    assert [b["module_id"] for b in out["bom"]] == ["electrical"]


def test_get_bom_on_an_unknown_estimate_is_404(call):
    r = call("GET", f"{API}/estimates/99999/bom")
    assert r.status == 404 and r.json()["error"] == "not_found"


def test_detail_includes_the_bom(call, elec):
    detail = call("GET", f"{API}/estimates/{elec['id']}/detail").json()
    assert [b["module_id"] for b in detail["bom"]] == ["electrical"]
    assert _item(detail["bom"][0]["items"], "el_wire_lf")["order_quantity"] == "575.00"


def test_bom_hides_costs_from_a_role_that_cannot_see_margins(call, elec, session_for):
    out = call("GET", f"{API}/estimates/{elec['id']}/bom", headers=session_for("field")).json()
    assert out["ok"] and out["bom"]
    assert all("unit_cost_cents" not in i for b in out["bom"] for i in b["items"])
    detail = call("GET", f"{API}/estimates/{elec['id']}/detail", headers=session_for("field")).json()
    assert detail["see_margins"] is False
    assert all("unit_cost_cents" not in i for b in detail["bom"] for i in b["items"])


# ------------------------------------------------------------------ tick ordered

def test_post_ordered_toggles_on_and_off(call, elec):
    sid = _section_id(elec, "electrical")
    r = call("POST", f"{API}/estimates/{elec['id']}/bom/ordered",
             {"section_id": sid, "item_key": "el_wire_lf", "ordered": True})
    assert r.status == 200, r.json()
    assert r.json() == {"ok": True, "ordered": True, "section_id": sid, "item_key": "el_wire_lf"}
    got = call("GET", f"{API}/estimates/{elec['id']}/bom").json()
    assert _item(got["bom"][0]["items"], "el_wire_lf")["ordered"] is True
    r = call("POST", f"{API}/estimates/{elec['id']}/bom/ordered",
             {"section_id": sid, "item_key": "el_wire_lf", "ordered": False})
    assert r.status == 200 and r.json()["ordered"] is False
    got = call("GET", f"{API}/estimates/{elec['id']}/bom").json()
    assert _item(got["bom"][0]["items"], "el_wire_lf")["ordered"] is False


def test_post_ordered_validation_errors(call, elec):
    sid = _section_id(elec, "electrical")
    base = f"{API}/estimates/{elec['id']}/bom/ordered"
    r = call("POST", base, {"section_id": 99999, "item_key": "el_wire_lf", "ordered": True})
    assert r.status == 404 and r.json()["error"] == "not_found"
    r = call("POST", base, {"section_id": sid, "item_key": "no-such-item", "ordered": True})
    assert r.status == 404 and r.json()["error"] == "not_found"
    r = call("POST", base, {"item_key": "el_wire_lf", "ordered": True})
    assert r.status == 400 and "section_id" in r.json()["message"]
    r = call("POST", base, {"section_id": sid, "ordered": True})
    assert r.status == 400 and "item_key" in r.json()["message"]
    r = call("POST", f"{API}/estimates/99999/bom/ordered",
             {"section_id": sid, "item_key": "el_wire_lf", "ordered": True})
    assert r.status == 404 and r.json()["error"] == "not_found"


# ------------------------------------------------------------------ the page

def test_estimates_page_has_the_bom_markers():
    js = (router.WEB_DIR / "estimates.js").read_text(encoding="utf-8")
    for needed in ("bomBlock", "Bill of Materials (", "Qty to order", "Copy list", "Download CSV",
                   "bom-copy-", "bom-csv-", "bom-table-", "data-bom-item", "data-bom-ordered",
                   "/bom/ordered", "navigator.clipboard.writeText", "Bill of materials copied"):
        assert needed in js, needed

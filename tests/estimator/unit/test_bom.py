"""The Bill of Materials: aggregation, waste math, the construction-only gate, hand lines, ordered flags.

(2026-11-18, David): every construction trade on an estimate gets a
shopping list - its material lines aggregated by price book item, with
the quantity to order (waste included), the supplier, and a checklist
of what is ordered already. The flags survive a re-price because they
key on the item, not the line.
"""
import json

import pytest

from estimator.context import personal_context
from estimator.errors import NotFound
from estimator.estimating import bom, quick, service

CTX = personal_context()
ELEC = {"outlets": 10, "switches": 4, "lights": 6}
# 10 outlets + 4 switches + 6 lights at 25 ft a run: 500 lf of wire at 15% waste,
# 20 boxes, 2 breakers. Labor and the permit are not materials, so they stay out.
# 2026-11-20 (David): the light fixtures are the owner's by default (labor only, not on the list), the breakers are
# AFCI by default, and the small parts (wire nuts, staples, clamps) are on the list - one set a box.
# 2026-11-20 (David: "we have to charge something for the light fixture install boxes"): each light has a fixture-rated
# box on the list; the device boxes are for outlets and switches only.
KEYS = ["el_outlet_ea", "el_switch_ea", "el_fixture_box_ea", "el_box_plastic_ea", "el_wire_lf", "el_breaker_afci_ea",
        "el_small_parts_ea"]


@pytest.fixture
def elec(db):
    e = service.create_estimate(db, CTX, "Electrical test")
    return quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])


def _section(est, module_id):
    return next(s for s in est["sections"] if s["module_id"] == module_id)


def _item(items, item_key):
    return next(i for i in items if i["item_key"] == item_key)


# ------------------------------------------------------------------ the list itself

def test_bom_lists_material_lines_only(db, elec):
    items = bom.bom_for_section(db, "default", _section(elec, "electrical")["id"])
    assert [i["item_key"] for i in items] == KEYS
    assert [i["quantity"] for i in items] == ["10", "4", "6", "14", "500", "2", "20"]
    assert [i["order_quantity"] for i in items] == ["10", "4", "6", "14", "575.00", "2", "20"]
    assert [i["unit"] for i in items] == ["ea", "ea", "ea", "ea", "lf", "ea", "ea"]
    for i in items:
        assert i["price_key"] == i["item_key"] and i["ordered"] is False
        assert i["supplier"] is None                    # sample prices carry no supplier
        assert i["unit_cost_cents"] > 0                 # every item on the list is priced
        assert len(i["line_ids"]) == 1


def test_fixtures_we_supply_are_on_the_list(db):                                    # 2026-11-20
    """David: fixtures the owner supplies take labor to hang and wire; when we supply them they're on the list too."""
    e = service.create_estimate(db, CTX, "We buy the fixtures")
    e = quick.answer(db, CTX, e["id"], "electrical", {**ELEC, "fans": 2, "fixtures": "us"}, e["rev"])
    sec = _section(e, "electrical")
    items = bom.bom_for_section(db, "default", sec["id"])
    assert _item(items, "el_light_ceiling_ea")["quantity"] == "6" and _item(items, "el_fan_unit_ea")["quantity"] == "2"
    hang = next(ln for ln in sec["lines"] if ln["calc"]["rule"] == "fixture_labor")
    assert float(hang["quantity"]) == 6 * 0.75 + 2 * 1.5                              # the same labor either way
    owner = service.create_estimate(db, CTX, "Owner buys the fixtures")
    owner = quick.answer(db, CTX, owner["id"], "electrical", {**ELEC, "fans": 2}, owner["rev"])
    sec = _section(owner, "electrical")
    assert float(next(ln for ln in sec["lines"] if ln["calc"]["rule"] == "fixture_labor")["quantity"]) == 7.5
    keys = [i["item_key"] for i in bom.bom_for_section(db, "default", sec["id"])]
    assert "el_light_ceiling_ea" not in keys and "el_fan_unit_ea" not in keys
    assert any("supplied by the owner" in ln["description"] for ln in sec["lines"])


def test_bom_for_estimate_lists_construction_sections_only(db, elec):
    out = bom.bom_for_estimate(db, "default", elec["id"])
    assert [b["module_id"] for b in out] == ["electrical"]
    assert out[0]["section_id"] == _section(elec, "electrical")["id"]
    assert [i["item_key"] for i in out[0]["items"]] == KEYS


def test_bom_for_estimate_includes_empty_construction_sections(db):
    e = service.create_estimate(db, CTX, "Roof, not priced yet")
    e = service.add_trade(db, CTX, e["id"], "roofing", e["rev"])
    sid = _section(e, "roofing")["id"]
    assert bom.bom_for_estimate(db, "default", e["id"]) == [{"module_id": "roofing", "section_id": sid,
                                                             "items": []}]
    assert bom.bom_for_section(db, "default", sid) == []


def test_bom_for_unknown_estimate_or_section_is_not_found(db, elec):
    with pytest.raises(NotFound):
        bom.bom_for_estimate(db, "default", 99999)
    with pytest.raises(NotFound):
        bom.bom_for_section(db, "default", 99999)


# ------------------------------------------------------------------ aggregation and waste

def test_bom_aggregates_lines_sharing_a_price_key(db, elec):
    sid = _section(elec, "electrical")["id"]
    rev = elec["rev"]
    # Two more runs of the same wire, with different waste: the order quantity
    # adds each line's waste (500 x 1.15 + 10 x 1.10 + 5 x 1.00 = 591.00).
    rev = service.add_line_item(db, CTX, elec["id"], rev, kind="material", description="Extra wire run",
                                quantity="10", unit="lf", waste_pct="0.10", price_key="el_wire_lf",
                                module_id="electrical")["rev"]
    service.add_line_item(db, CTX, elec["id"], rev, kind="material", description="Short wire run",
                          quantity="5", unit="lf", waste_pct="0", price_key="el_wire_lf",
                          module_id="electrical")
    items = bom.bom_for_section(db, "default", sid)
    wire = _item(items, "el_wire_lf")
    assert wire["quantity"] == "515" and wire["order_quantity"] == "591.00"
    assert wire["description"] == "Branch circuit wire (12/2)"   # the first line's
    assert len(wire["line_ids"]) == 3
    assert [i["item_key"] for i in items].count("el_wire_lf") == 1


def test_bom_ea_rounds_up_and_other_units_round_to_two_decimals(db, elec):
    sid = _section(elec, "electrical")["id"]
    rev = elec["rev"]
    adds = [("Cable clips", "10.2", "ea", "0.05", "11"),          # 10.71 -> 11
            ("Mounting screws", "10", "ea", "0", "10"),           # already whole
            ("Conduit", "33.333", "lf", "0", "33.33"),
            ("Junction box seals", "10.005", "lf", "0", "10.01")]  # half up
    for desc, qty, unit, waste, _order in adds:
        rev = service.add_line_item(db, CTX, elec["id"], rev, kind="material", description=desc,
                                    quantity=qty, unit=unit, unit_cost_cents=100, waste_pct=waste,
                                    module_id="electrical")["rev"]
    items = bom.bom_for_section(db, "default", sid)
    for desc, qty, _unit, _waste, order in adds:
        row = _item(items, "hand:" + desc)
        assert row["quantity"] == qty and row["order_quantity"] == order, desc


# ------------------------------------------------------------------ hand lines and the gate

def test_bom_hand_lines_group_by_description_and_unit(db, elec):
    sid = _section(elec, "electrical")["id"]
    rev = elec["rev"]
    for qty, cost in (("3", 500), ("4", 600)):
        rev = service.add_line_item(db, CTX, elec["id"], rev, kind="material",
                                    description="Special junction box", quantity=qty, unit="ea",
                                    unit_cost_cents=cost, module_id="electrical")["rev"]
    rev = service.add_line_item(db, CTX, elec["id"], rev, kind="material",
                                description="Special junction box", quantity="2", unit="lf",
                                unit_cost_cents=700, module_id="electrical")["rev"]
    items = bom.bom_for_section(db, "default", sid)
    ea = _item(items, "hand:Special junction box")
    assert ea["quantity"] == "7" and ea["order_quantity"] == "7" and ea["unit"] == "ea"
    assert ea["price_key"] is None and ea["supplier"] is None and len(ea["line_ids"]) == 2
    assert ea["unit_cost_cents"] == 500                          # the first line's
    lf = [i for i in items if i["item_key"] == "hand:Special junction box" and i["unit"] == "lf"]
    assert len(lf) == 1 and lf[0]["quantity"] == "2"             # another unit, another row


def test_bom_excludes_service_and_custom_sections(db, elec):
    e = service.create_estimate(db, CTX, "Pressure wash")
    e = quick.answer(db, CTX, e["id"], "pressure_washing", {"driveway_sqft": 1000}, e["rev"])
    sid = _section(e, "pressure_washing")["id"]
    assert bom.bom_for_section(db, "default", sid) == []
    assert bom.bom_for_estimate(db, "default", e["id"]) == []
    # A hand material line in "Other lines" is not a trade's list either.
    e = service.add_line_item(db, CTX, e["id"], e["rev"], kind="material", description="Detergent",
                              quantity="2", unit="ea", unit_cost_cents=1500)
    custom = _section(e, "custom")
    assert custom["lines"] and bom.bom_for_section(db, "default", custom["id"]) == []
    assert bom.bom_for_estimate(db, "default", e["id"]) == []


def test_bom_supplier_comes_from_the_price_book(db, elec):
    db.execute("UPDATE price_book SET supplier = 'City Electric Supply'"
               " WHERE company_id = 'default' AND price_key = 'el_outlet_ea'")
    db.commit()
    items = bom.bom_for_section(db, "default", _section(elec, "electrical")["id"])
    assert _item(items, "el_outlet_ea")["supplier"] == "City Electric Supply"
    assert _item(items, "el_switch_ea")["supplier"] is None


def test_bom_includes_the_subpanel_now_it_is_a_material(db):
    e = service.create_estimate(db, CTX, "Subpanel job")
    e = quick.answer(db, CTX, e["id"], "electrical",
                     {**ELEC, "panel": "subpanel", "subpanel_amps": "100"}, e["rev"])
    line = next(ln for ln in _section(e, "electrical")["lines"] if ln["price_key"] == "el_subpanel_100a_ea")
    assert line["kind"] == "material"
    items = bom.bom_for_section(db, "default", _section(e, "electrical")["id"])
    sub = _item(items, "el_subpanel_100a_ea")
    assert sub["quantity"] == "1" and sub["order_quantity"] == "1" and sub["unit"] == "ea"


def test_smoke_detectors_and_the_main_panel_are_priced(db):                       # 2026-11-20
    """David: "the panel and the 2 smoke detectors on the plan aren't part of any count" - fix it. Smoke detectors are
    their own BOM line with labor, a box and wire each; a new build's main panel is priced once, never as well as a
    Panel work 'Upgrade' (that line already is the panel and service)."""
    e = service.create_estimate(db, CTX, "Smoke and panel job")
    e = quick.answer(db, CTX, e["id"], "electrical", {**ELEC, "smoke_detectors": 2, "main_panels": 1}, e["rev"])
    sec = _section(e, "electrical")
    items = bom.bom_for_section(db, "default", sec["id"])
    smoke = _item(items, "el_smoke_detector_ea")
    assert smoke["quantity"] == "2" and smoke["unit_cost_cents"] > 0
    assert _item(items, "el_box_plastic_ea")["quantity"] == "16"                # 14 devices + 2 detectors
    assert _item(items, "el_fixture_box_ea")["quantity"] == "6"                 # one fixture-rated box a light
    # 2026-11-20 (David: "there is no panel" in the BOM): the panel and meter base are parts on the list, with the
    # hours to set them as their own labor line.
    assert _item(items, "el_main_panel_ea")["quantity"] == "1" and _item(items, "el_meter_base_ea")["quantity"] == "1"
    rules = {ln["calc"]["rule"]: ln for ln in sec["lines"]}
    assert float(rules["panel_labor"]["quantity"]) == 12
    assert float(rules["device_labor"]["quantity"]) == 10 * 0.5 + 4 * 0.5 + 2 * 0.75   # 0.75 hr a detector
    assert float(rules["fixture_labor"]["quantity"]) == 6 * 0.75                         # the lights: their own line
    # With Panel work "Upgrade", the upgrade line is the panel: the main panel isn't priced again.
    e2 = service.create_estimate(db, CTX, "Upgrade job")
    e2 = quick.answer(db, CTX, e2["id"], "electrical", {**ELEC, "main_panels": 1, "panel": "upgrade"}, e2["rev"])
    keys = [ln["price_key"] for ln in _section(e2, "electrical")["lines"]]
    assert "el_panel_upgrade_ea" in keys and "el_main_panel_ea" not in keys


# ------------------------------------------------------------------ ordered flags

def test_set_ordered_toggles_on_and_off(db, elec):
    sid = _section(elec, "electrical")["id"]
    out = bom.set_ordered(db, CTX, elec["id"], sid, "el_wire_lf", True)
    assert out == {"ordered": True, "section_id": sid, "item_key": "el_wire_lf"}
    items = bom.bom_for_section(db, "default", sid)
    assert _item(items, "el_wire_lf")["ordered"] is True
    assert _item(items, "el_outlet_ea")["ordered"] is False
    assert db.execute("SELECT COUNT(*) FROM bom_ordered").fetchone()[0] == 1
    bom.set_ordered(db, CTX, elec["id"], sid, "el_wire_lf", True)   # ticking twice is fine
    assert db.execute("SELECT COUNT(*) FROM bom_ordered").fetchone()[0] == 1
    out = bom.set_ordered(db, CTX, elec["id"], sid, "el_wire_lf", False)
    assert out["ordered"] is False
    assert db.execute("SELECT COUNT(*) FROM bom_ordered").fetchone()[0] == 0
    assert _item(bom.bom_for_section(db, "default", sid), "el_wire_lf")["ordered"] is False


def test_ordered_flag_survives_a_reprice(db, elec):
    sid = _section(elec, "electrical")["id"]
    bom.set_ordered(db, CTX, elec["id"], sid, "el_wire_lf", True)
    # Price again with two more outlets: the wire lines are deleted and remade
    # (550 lf now, not 500), but the flag keys on the item, so it stays.
    repriced = quick.answer(db, CTX, elec["id"], "electrical", {**ELEC, "outlets": 12}, elec["rev"])
    after = _item(bom.bom_for_section(db, "default", sid), "el_wire_lf")
    assert after["quantity"] == "550" and after["order_quantity"] == "632.50"
    assert after["ordered"] is True
    assert repriced["sections"] and db.execute("SELECT COUNT(*) FROM bom_ordered").fetchone()[0] == 1


def test_set_ordered_validates_section_and_item(db, elec):
    sid = _section(elec, "electrical")["id"]
    with pytest.raises(NotFound):
        bom.set_ordered(db, CTX, 99999, sid, "el_wire_lf", True)
    with pytest.raises(NotFound):
        bom.set_ordered(db, CTX, elec["id"], 99999, "el_wire_lf", True)
    with pytest.raises(NotFound):
        bom.set_ordered(db, CTX, elec["id"], sid, "no-such-item", True)


# ------------------------------------------------------------------ the MCP tool

def test_est_bom_tool_returns_the_same_lists(db, elec):
    from estimator.mcp_tools import est_tools as t

    out = json.loads(t.est_bom(elec["id"]))
    assert out["ok"] and out["estimate_id"] == elec["id"]
    assert [b["module_id"] for b in out["bom"]] == ["electrical"]
    assert [i["item_key"] for i in out["bom"][0]["items"]] == KEYS
    assert json.loads(t.est_bom(99999))["error"] == "not_found"

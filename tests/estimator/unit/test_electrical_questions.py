"""Electrical module: voltage/phase, circuit amperage, box material, underground
runs and subpanel size (Part C, 2026-11-17). Each new question must change the
price; old appliance_circuits answers still price (as 30 Amp circuits)."""
import pytest

from estimator.context import personal_context
from estimator.estimating import quick, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()


def _price(db, answers):
    e = service.create_estimate(db, CTX, "electrical")
    return quick.answer(db, CTX, e["id"], "electrical", answers, e["rev"], REG)


def _lines(e):
    return {ln["calc"]["rule"]: ln["total_cents"] for ln in e["sections"][0]["lines"]}


BASE = {"outlets": 10, "switches": 4, "lights": 6}


def test_new_questions_are_asked_with_sane_defaults(db):  # C-Q01
    q = {x["id"]: x for x in quick.questions("electrical", REG)["questions"]}
    assert [c["value"] for c in q["voltage"]["choices"]] == ["110", "220", "220_3ph"]
    assert q["voltage"]["default"] == "110"
    assert [c["value"] for c in q["box_material"]["choices"]] == ["plastic", "metal"]
    assert q["box_material"]["default"] == "plastic"
    assert q["circuits_15a"]["type"] == "integer" and q["circuits_15a"]["default"] == 0
    assert q["underground_ft"]["type"] == "number" and q["underground_ft"]["default"] == 0
    assert [c["value"] for c in q["subpanel_amps"]["choices"]] == ["100", "200"]
    assert q["subpanel_amps"]["default"] == "100"
    assert q["appliance_circuits"]["label"].startswith("Dedicated 30 Amp")


def test_required_any_includes_new_counts():  # C-Q02
    req = REG.get("electrical").required_any
    assert "circuits_15a" in req and "underground_ft" in req and "panel" in req


def test_voltage_220_changes_wire_and_breakers(db):  # C-V01
    std, v220 = _price(db, BASE), _price(db, {**BASE, "voltage": "220"})
    assert _lines(std)["wire"] == 31625 and _lines(std)["breakers"] == 7000
    lines = _lines(v220)
    assert "wire" not in lines and "breakers" not in lines
    assert lines["wire_220"] == 48875 and lines["breakers_2pole"] == 14000
    assert v220["totals"]["total_cents"] == 197975 > std["totals"]["total_cents"]


def test_three_phase_costs_more_labor_and_uses_3pole(db):  # C-V02
    std, ph3 = _price(db, BASE), _price(db, {**BASE, "voltage": "220_3ph"})
    lines = _lines(ph3)
    assert lines["device_labor"] == 129375            # 11.5 hr x 1.25 x $90
    assert lines["device_labor"] > _lines(std)["device_labor"]
    assert lines["wire_3ph"] == 69000 and lines["breakers_3pole"] == 21000
    assert "wire" not in lines and "breakers" not in lines
    assert ph3["totals"]["total_cents"] == 250975


def test_15a_and_30a_circuits_price_differently(db):  # C-A01
    a15 = _price(db, {"circuits_15a": 1, "avg_run_ft": 30})
    a30 = _price(db, {"appliance_circuits": 1, "avg_run_ft": 30})
    l15, l30 = _lines(a15), _lines(a30)
    assert l15["wire_15a"] == 1898 and l15["breakers"] == 3500      # 12/2 + single-pole
    assert l30["heavy_wire"] == 8625 and l30["breakers_2pole"] == 7000
    assert "wire_15a" not in l30 and "heavy_wire" not in l15
    assert l15["circuit_labor"] == l30["circuit_labor"] == 27000   # same 3 hr each
    assert a30["totals"]["total_cents"] > a15["totals"]["total_cents"]


def test_old_appliance_circuits_answers_still_price_as_30a(db):  # C-A02
    e = _price(db, {"work": "remodel", "fans": 2, "gfci": 2,
                    "appliance_circuits": 1, "avg_run_ft": 40})
    lines = _lines(e)
    assert lines["heavy_wire"] == 11500 and lines["breakers_2pole"] == 7000
    assert e["totals"]["total_cents"] == 168120


def test_metal_boxes_cost_more_than_plastic(db):  # C-B01
    plastic = _price(db, {"outlets": 10})
    metal = _price(db, {"outlets": 10, "box_material": "metal"})
    assert _lines(plastic)["boxes_plastic"] == 3000
    assert _lines(metal)["boxes_metal"] == 6000 and "boxes_plastic" not in _lines(metal)
    assert metal["totals"]["total_cents"] - plastic["totals"]["total_cents"] == 3000


def test_underground_run_adds_its_own_line(db):  # C-U01
    assert "underground_wire" not in _lines(_price(db, {"outlets": 2}))
    e = _price(db, {"outlets": 2, "underground_ft": 100})
    assert _lines(e)["underground_wire"] == 47250              # 100 ft x 1.05 x $4.50
    assert e["totals"]["total_cents"] == 84313


def test_subpanel_100a_vs_200a(db):  # C-S01
    s100 = _price(db, {"panel": "subpanel"})
    s200 = _price(db, {"panel": "subpanel", "subpanel_amps": "200"})
    assert _lines(s100) == {"subpanel_100a": 90000, "permit": 20000}
    assert _lines(s200) == {"subpanel_200a": 150000, "permit": 20000}
    assert s200["totals"]["total_cents"] - s100["totals"]["total_cents"] == 60000


def test_subpanel_amps_is_ignored_without_a_subpanel(db):  # C-S02
    e = _price(db, {"subpanel_amps": "200"})
    assert _lines(e) == {"permit": 20000}


def test_every_new_price_key_has_a_sample_price():  # C-P01
    keys = REG.get("electrical").sample_prices
    for key in ("el_box_plastic_ea", "el_box_metal_ea", "el_wire_220_lf", "el_wire_3ph_lf",
                "el_breaker_2pole_ea", "el_breaker_3pole_ea", "el_underground_lf",
                "el_subpanel_100a_ea", "el_subpanel_200a_ea"):
        assert key in keys, key
    assert "el_box_ea" not in keys and "el_subpanel_ea" not in keys

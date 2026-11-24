"""AI design (2026-11-21, David: "the user has a shed drawing or house drawing and wants AI to do the addition of the
electrical work ... design me the lighting and receptacles ... then review"). The AI is never called: the design is a
fixed answer (the NSB shed, laid out as it was by hand) and the provider is a fake."""
import json

import pytest

ezdxf = pytest.importorskip("ezdxf")
from estimator.design import building as bmod  # noqa: E402
from estimator.design import draw_electrical as dr  # noqa: E402
from estimator.design import electrical  # noqa: E402
from estimator.plan_engine import symbol_library as lib  # noqa: E402
from estimator.takeoff import wiring, wiring_schematic  # noqa: E402

SHED = {"name": "NSB shed", "kind": "accessory", "floors": [{
    "name": "GROUND", "ceiling_ft": 15, "outline": [[0, 0], [46, 0], [46, 45], [0, 45]],
    "openings": [{"kind": "overhead_door", "a": [2, 0], "b": [14, 0], "label": "12x12 roll-up"},
                 {"kind": "overhead_door", "a": [16, 0], "b": [28, 0], "label": "12x12 roll-up"},
                 {"kind": "overhead_door", "a": [30, 0], "b": [44, 0], "label": "14x14 roll-up"},
                 {"kind": "overhead_door", "a": [17, 45], "b": [29, 45], "label": "12x12 roll-up"},
                 {"kind": "door", "a": [7, 45], "b": [10, 45], "label": "walk door"},
                 {"kind": "door", "a": [0, 1], "b": [0, 4], "label": "walk door"},
                 {"kind": "window", "a": [0, 11.25], "b": [0, 13.75]}, {"kind": "window", "a": [46, 11.25], "b": [46, 13.75]}],
    "interior_walls": [], "rooms": [{"name": "SHOP", "x0": 0, "y0": 0, "x1": 46, "y1": 45}]}]}


def shed_design():
    circ = [{"id": "C-1", "description": "Left wall receptacles - GFCI", "amps": 20, "poles": 1, "wire": "12/2"},
            {"id": "C-2", "description": "Rear wall receptacles", "amps": 20, "poles": 1, "wire": "12/2"},
            {"id": "C-3", "description": "Right wall receptacles", "amps": 20, "poles": 1, "wire": "12/2"},
            {"id": "C-4", "description": "Front receptacles", "amps": 20, "poles": 1, "wire": "12/2"},
            {"id": "C-5", "description": "Shop lighting", "amps": 20, "poles": 1, "wire": "12/2"},
            {"id": "240V", "description": "240V receptacle NEMA 6-30R", "amps": 30, "poles": 2, "wire": "10/2"}]
    dev = [("outlet_gfci", 0, 13, "C-1"), ("outlet", 0, 21, "C-1"), ("outlet", 0, 29, "C-1"), ("outlet", 0, 38, "C-1"),
           ("outlet_gfci", 13, 45, "C-2"), ("outlet", 35, 45, "C-2"), ("outlet", 42, 45, "C-2"), ("outlet_wp", 32, 45, "C-2"),
           ("outlet_gfci", 46, 6, "C-3"), ("outlet", 46, 16, "C-3"), ("outlet", 46, 24, "C-3"), ("outlet", 46, 34, "C-3"),
           ("outlet", 46, 42, "C-3"), ("outlet_gfci", 15, 0, "C-4"), ("outlet", 29, 0, "C-4"), ("outlet_wp", 15, 0, "C-4"),
           ("outlet_240", 46, 38, "240V"), ("switch_3way", 0, 4.8, "C-5"), ("switch", 0, 5.6, "C-5"),
           ("switch_3way", 10.8, 45, "C-5")]
    dev += [("light_led", x, y, "C-5") for x in (5.75, 17.25, 28.75, 40.25) for y in (4.5, 13.5, 22.5, 31.5, 40.5)]
    dev += [("light_exterior", x, y, "C-5") for x, y in ((1, 0), (29, 0), (45, 0), (11.5, 45), (30, 45), (0, 5))]
    return {"summary": "shed", "panel": {"kind": "subpanel", "amps": 100, "floor": 0, "x": 0.9, "y": 8.0,
                                         "fed_from": "100A subpanel in the house garage", "feeder": "4-wire underground",
                                         "feeder_breaker_amps": 60},
            "circuits": [{**c, "floor": 0} for c in circ],
            "devices": [{"type": t, "x": x, "y": y, "floor": 0, "circuit": c, "note": ""} for t, x, y, c in dev],
            "assumptions": ["feeder breaker 60 A"], "code_notes": ["All 120 V receptacles GFCI protected"], "changes": []}


def test_every_device_type_is_a_block_the_symbol_library_reads():                       # AD-01
    want = {"outlet": "duplex_receptacle", "outlet_gfci": "duplex_receptacle_gfci", "outlet_wp": "duplex_receptacle_wp",
            "outlet_usb": "duplex_receptacle_usb", "outlet_quad": "quad_receptacle", "outlet_240": "receptacle_240v",
            "range_outlet": "range_receptacle", "dryer_outlet": "dryer_receptacle", "ev_charger": "ev_charger",
            "disconnect": "disconnect", "switch": "switch", "switch_3way": "switch_3way", "switch_4way": "switch_4way",
            "switch_dimmer": "switch_dimmer", "light": "light_fixture", "light_led": "light_fixture",
            "light_recessed": "light_recessed", "light_pendant": "light_pendant", "light_wall": "light_wall",
            "light_undercabinet": "light_undercabinet", "light_exterior": "light_exterior", "fan": "ceiling_fan",
            "exhaust_fan": "exhaust_fan", "smoke": "smoke_detector", "smoke_co": "smoke_co_detector",
            "junction_box": "junction_box", "data": "data_outlet", "tv": "tv_outlet"}
    assert set(want) == set(dr.DEVICES)
    for t, it in want.items():
        assert lib.by_block_name(dr.DEVICES[t][0])["item_type"] == it, t
    assert lib.by_block_name(dr.panel_block({"kind": "subpanel", "amps": 100}))["item_type"] == "panel_sub"
    assert lib.by_block_name(dr.panel_block({"kind": "main", "amps": 200}))["item_type"] == "panel"


def test_the_drawn_design_reads_back_device_for_device(tmp_path):                        # AD-02
    d = shed_design()
    out = dr.draw_plan(SHED, d, str(tmp_path / "p.dxf"), "NSB shed")
    dr.draw_panel(d, str(tmp_path / "s.dxf"), "NSB shed")
    assert out["counts"]["light_led"] == 20 and out["counts"]["outlet"] == 10
    plan = wiring.read_floor_plan(str(tmp_path / "p.dxf"))
    sched = wiring.read_panel_schedule(str(tmp_path / "s.dxf"))
    assert len(plan["floors"]) == 1 and plan["panel"] is not None
    assert [c.id for c in sched["circuits"]] == ["C-1", "C-2", "C-3", "C-4", "C-5", "240V"]
    assert wiring_schematic.is_subpanel(sched["main"]) and sched["main"]["amps"] == 100
    assert wiring.assign(plan, sched) == []
    by = {c.id: c for c in sched["circuits"]}
    # every device on the circuit the design gave it (the CIRCUIT attribute), not the nearest tag
    assert len(by["C-1"].devices) == 4 and len(by["C-2"].devices) == 4 and len(by["C-3"].devices) == 5
    assert len(by["C-4"].devices) == 3 and len(by["C-5"].devices) == 29
    assert [a.item_type for a in by["240V"].devices] == ["appliance"]
    assert all(dev.why == "circuit on the drawing" for c in sched["circuits"] for dev in c.devices
               if dev.item_type != "appliance")
    chk = wiring.drawing_check(plan, sched)
    assert chk["differ"] == [] and chk["not_in_schedule"] == []


def test_wall_devices_go_on_their_wall_facing_it_and_out_of_doorways():                  # AD-03
    f = SHED["floors"][0]
    p = dr.place({"type": "outlet", "x": 0.2, "y": 20}, f)                  # left wall, inside, facing -x
    assert (p["x"], p["y"]) == (0.7, 20.0) and p["rot"] == 90.0
    p = dr.place({"type": "outlet_wp", "x": 15, "y": 0.3}, f)               # exterior: outside the front wall
    assert p["y"] == -0.7 and p["rot"] == 0.0
    p = dr.place({"type": "outlet", "x": 8, "y": 0.2}, f)                   # in the roll-up door: slid out of it
    assert not 2 <= p["x"] <= 14 and "opening" in p["moved"]
    p = dr.place({"type": "light_led", "x": 20, "y": 20}, f)                # ceiling: where it was put
    assert (p["x"], p["y"], p["moved"]) == (20, 20, "")
    p = dr.place({"type": "outlet", "x": 23, "y": 22}, f)                   # mid-floor: left, flagged
    assert p["moved"].startswith("not on a wall")


def test_the_code_check(tmp_path):                                                      # AD-04
    d = shed_design()
    assert [f for f in electrical.check(SHED, d) if f["level"] == "error"] == []
    bad = shed_design()
    bad["devices"] = [x for x in bad["devices"] if not (x["type"] == "outlet_gfci" and x["circuit"] == "C-3")]
    bad["circuits"][5].update(poles=1)
    bad["circuits"][0].update(wire="14/2")
    bad["devices"].append({"type": "outlet", "x": 60, "y": 60, "floor": 0, "circuit": "C-1"})
    codes = {f["code"] for f in electrical.check(SHED, bad) if f["level"] == "error"}
    assert codes == {"gfci", "pole", "wire", "outside"}
    bad = shed_design()
    bad["panel"]["feeder_breaker_amps"] = 125
    assert any(f["code"] == "feeder" and f["level"] == "error" for f in electrical.check(SHED, bad))


def test_an_ai_answer_is_checked_before_anything_is_drawn():                             # AD-05
    good = json.dumps(shed_design())
    d = electrical.parse_design("```json\n" + good + "\n```", SHED)
    assert len(d["devices"]) == 46 and d["panel"]["kind"] == "subpanel"
    for broken, says in (({"devices": [{"type": "toaster", "x": 1, "y": 1, "circuit": "C-1"}]}, "toaster"),
                         ({"devices": [{"type": "outlet", "x": 1, "y": 1, "circuit": "C-9"}]}, "C-9"),
                         ({"devices": [{"type": "outlet", "x": "near the door", "y": 1, "circuit": "C-1"}]}, "not a number"),
                         ({"panel": None}, "no panel"), ({"circuits": []}, "no circuits")):
        obj = {**shed_design(), **broken}
        with pytest.raises(electrical.DesignError, match=says):
            electrical.parse_design(json.dumps(obj), SHED)


def test_a_building_read_by_the_ai_is_checked(tmp_path):                                 # AD-06
    b = bmod.parse_reading(json.dumps({**SHED, "confidence": 0.8}))
    assert b["source"] == "ai" and b["kind"] == "accessory" and bmod.size_line(b) == "46' x 45'"
    assert [o["kind"] for o in b["floors"][0]["openings"]].count("overhead_door") == 4
    with pytest.raises(bmod.BuildingError, match="outline"):
        bmod.parse_reading(json.dumps({"floors": [{"outline": [[0, 0], [10, 0]]}]}))
    with pytest.raises(bmod.BuildingError, match="under 4 ft"):
        bmod.parse_reading(json.dumps({"floors": [{"outline": [[0, 0], [1, 0], [1, 1]]}]}))


def test_a_building_from_a_cad_drawing(tmp_path):                                        # AD-07
    dr.draw_plan(SHED, shed_design(), str(tmp_path / "p.dxf"))
    b = bmod.from_dxf(str(tmp_path / "p.dxf"), "shed")
    f = b["floors"][0]
    assert b["source"] == "dxf" and bmod.size_line(b) == "46' x 45'"
    doors = sorted((o["a"], o["b"]) for o in f["openings"] if o["kind"] == "overhead_door")
    assert len(doors) == 4
    assert sum(o["kind"] == "door" for o in f["openings"]) == 2
    assert [r["name"] for r in f["rooms"]] == ["SHOP"]

"""A detached building fed from a subpanel (2026-11-21, David's NSB shed: "lighting, 110 outlets, 20A, 30A, and a 100A
sub panel ... pulled from another 100-amp sub panel in the house garage and buried underground"). A small shed is
drawn here with ezdxf - never the live plans."""
import pytest

ezdxf = pytest.importorskip("ezdxf")
from estimator.plan_engine import symbol_library as lib  # noqa: E402
from estimator.takeoff import wiring, wiring_schematic  # noqa: E402


def _shed(tmp_path):
    """A 30 x 20 ft shed: a 12 ft roll-up door in the front wall (a wall gap wider than 5 ft, bridged by the door
    drawn across it), a subpanel, a 240 V receptacle with its "240V 30A" label, receptacles near two circuit tags."""
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2
    for name in ("OUTLET", "OUTLET_GFCI", "LIGHT_LED", "SWITCH", "SUBPANEL_100A", "PWR_240"):
        doc.blocks.new(name=name).add_circle((0, 0), 0.3)
    msp = doc.modelspace()
    for a, b in (((0, 0), (9, 0)), ((21, 0), (30, 0)), ((30, 0), (30, 20)), ((30, 20), (0, 20)), ((0, 20), (0, 0))):
        msp.add_line(a, b, dxfattribs={"layer": "A-WALL-EXT"})
    msp.add_lwpolyline([(9, 0.3), (21, 0.3), (21, 0), (9, 0)], close=True, dxfattribs={"layer": "A-DOOR"})

    def put(name, x, y, layer="E-POWER"):
        msp.add_blockref(name, (x, y), dxfattribs={"layer": layer})

    def txt(t, x, y, layer="E-CIRCUIT"):
        msp.add_text(t, height=0.5, dxfattribs={"layer": layer, "insert": (x, y)})
    txt("SHOP", 15, 10, "A-TEXT")
    put("SUBPANEL_100A", 0.9, 5, "E-PANEL")
    put("OUTLET_GFCI", 0.7, 12)
    put("OUTLET", 0.7, 18)
    put("OUTLET_GFCI", 25, 0.7)                    # right of the roll-up door
    put("OUTLET", 29.3, 6)
    put("LIGHT_LED", 15, 14, "E-LIGHT")
    put("SWITCH", 0.7, 3, "E-SWITCH")
    put("PWR_240", 29.3, 15)
    txt("C-1", 3, 15)
    txt("C-2", 26, 4)
    txt("240V 30A", 26, 15)
    p = tmp_path / "shed.dxf"
    doc.saveas(p)
    return str(p)


def _schedule(tmp_path, main_desc="100A main bkr - subpanel disconnect", main_wire="4-wire UG feeder"):
    doc = ezdxf.new("R2010")
    msp = doc.modelspace()

    def txt(t, x, y):
        msp.add_text(t, height=0.3, dxfattribs={"insert": (x, y)})
    for x in (24, 30, 48, 52, 56, 64):
        msp.add_line((x, 30), (x, 40), dxfattribs={"layer": "E-SCHEDULE"})
    for t, x in (("CIRCUIT", 27), ("DESCRIPTION", 38), ("AMPS", 50), ("POLES", 54), ("WIRE", 60)):
        txt(t, x, 39.5)
    rows = [("C-1", "Left wall receptacles", "20", "1", "12/2"), ("C-2", "Right wall receptacles", "20", "1", "12/2"),
            ("C-3", "Shop lighting - ground floor", "20", "1", "12/2"),
            ("240V", "240V receptacle NEMA 6-30R", "30", "2", "10/2"), ("MAIN", main_desc, "100", "2", main_wire)]
    y = 38.4
    for r in rows:
        txt(r[0], 27, y)
        txt(r[1], 30.5, y - 0.25)
        txt(r[2], 50, y)
        txt(r[3], 54, y)
        txt(r[4], 60, y)
        y -= 1.1
    p = tmp_path / "sched.dxf"
    doc.saveas(p)
    return str(p)


def test_a_subpanel_symbol_answers_panel_work_subpanel():                               # SP-01
    e = lib.by_block_name("SUBPANEL_100A")
    assert e["item_type"] == "panel_sub"                    # not the main panel: SUBPANEL beats PANEL
    assert lib.feeds_of("panel_sub") == [("electrical", "panel", "subpanel")]
    assert lib.by_block_name("PANEL_200A")["item_type"] == "panel"
    assert lib.by_block_name("PWR_240")["item_type"] == "receptacle_240v"


def test_the_subpanel_is_where_the_circuits_start_and_a_roll_up_door_is_not_two_buildings(tmp_path):  # SP-02
    plan = wiring.read_floor_plan(_shed(tmp_path))
    assert len(plan["floors"]) == 1                         # the 12 ft door gap is bridged by the door
    assert plan["panel"] == {"x": 0.9, "y": 5.0, "floor": 0}
    assert [r["name"] for r in plan["rooms"]] == ["SHOP"]
    assert "panel_sub" not in {d.item_type for d in plan["devices"]}


def test_a_240v_receptacle_is_the_end_of_its_own_30a_circuit(tmp_path):                 # SP-03
    plan = wiring.read_floor_plan(_shed(tmp_path))
    assert "receptacle_240v" not in {d.item_type for d in plan["devices"]}   # not a device on a 20 A circuit
    (a,) = plan["appliances"]
    assert (a.room, a.x, a.y) == ("240V", 29.3, 15.0) and "240 v receptacle" in a.why
    sched = wiring.read_panel_schedule(_schedule(tmp_path))
    assert wiring.assign(plan, sched) == []
    by = {c.id: c for c in sched["circuits"]}
    assert [d.item_type for d in by["240V"].devices] == ["appliance"]
    assert {d.item_type for d in by["C-1"].devices} == {"duplex_receptacle", "duplex_receptacle_gfci"}
    assert len(by["C-2"].devices) == 2
    assert {d.item_type for d in by["C-3"].devices} == {"light_fixture", "switch"}


def test_the_subpanel_schematic_has_a_4_wire_feeder_and_no_bond(tmp_path):             # SP-04
    res = wiring.takeoff(_shed(tmp_path), _schedule(tmp_path), out_path=str(tmp_path / "w.dxf"))
    assert wiring_schematic.is_subpanel(res["main"])
    out = wiring_schematic.write(res, str(tmp_path / "s.dxf"), "SHED")
    msp = ezdxf.readfile(out).modelspace()
    texts = [e.dxf.text for e in msp.query("TEXT")]
    assert "MBJ" not in texts and "UTILITY" not in texts and "METER" not in texts
    assert "100 A SUBPANEL" in texts and "SUPPLY" in texts
    assert any(t.startswith("FEEDER:") and "G (GRN)" in t for t in texts)
    # the feeder's ground comes in with it, above the panel, and never crosses the neutral on the way
    g_in = [e for e in msp.query("LINE") if e.dxf.layer == "S-GROUND" and e.dxf.start.y > -1 and e.dxf.start.x < 8]
    assert g_in


def test_a_main_panel_schematic_is_unchanged(tmp_path):                                  # SP-05
    res = wiring.takeoff(_shed(tmp_path), _schedule(tmp_path, "100A main breaker", "Service entrance"),
                         out_path=str(tmp_path / "w.dxf"))
    assert not wiring_schematic.is_subpanel(res["main"])
    out = wiring_schematic.write(res, str(tmp_path / "s.dxf"), "")
    texts = [e.dxf.text for e in ezdxf.readfile(out).modelspace().query("TEXT")]
    assert "MBJ" in texts and "UTILITY" in texts and "100 A PANEL" in texts

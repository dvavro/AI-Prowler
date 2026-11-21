"""Wiring takeoff (2026-11-19, David): wire lengths and sizes from the electrical floor plan + the panel schedule,
and the wiring DXF it writes. A small two-storey house is drawn here with ezdxf - never the live plans."""
import pytest

ezdxf = pytest.importorskip("ezdxf")
from estimator.takeoff import wiring  # noqa: E402


def _plan(tmp_path):
    """Ground floor 20 x 10 ft at x 0..20 (KITCHEN | LIVING), second floor beside it at x 30..50 (BEDROOM 2), in feet.
    The panel on the ground floor's east wall; the legend (one of each symbol) far below the floors."""
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2
    for name in ("OUTLET", "OUTLET_GFCI", "SWITCH", "SWITCH_3WAY", "LIGHT_CEIL", "PANEL_200A", "DATA"):
        doc.blocks.new(name=name).add_circle((0, 0), 0.3)
    msp = doc.modelspace()
    for x0 in (0, 30):
        for a, b in (((0, 0), (20, 0)), ((20, 0), (20, 10)), ((20, 10), (0, 10)), ((0, 10), (0, 0))):
            msp.add_line((a[0] + x0, a[1]), (b[0] + x0, b[1]), dxfattribs={"layer": "A-WALL-EXT"})
    def put(name, x, y, layer="E-OUTLET"):
        msp.add_blockref(name, (x, y), dxfattribs={"layer": layer})
    def txt(t, x, y, layer="A-TEXT"):
        msp.add_text(t, height=0.5, dxfattribs={"layer": layer, "insert": (x, y)})
    txt("GROUND FLOOR", 10, 12)
    txt("SECOND FLOOR", 40, 12)
    txt("KITCHEN", 5, 5)
    txt("LIVING", 15, 5)
    txt("BEDROOM 2", 40, 5)
    put("PANEL_200A", 19.7, 5, "E-PANEL")
    put("OUTLET_GFCI", 2, 0.5)
    put("OUTLET_GFCI", 8, 0.5)                    # kitchen: 2 GFCI on C-2
    put("OUTLET", 12, 0.5)
    put("OUTLET", 18, 9.5)                        # living: 2 on C-1
    put("SWITCH_3WAY", 11, 9.5, "E-SWITCH")
    put("SWITCH_3WAY", 19.5, 1, "E-SWITCH")       # a 3-way pair
    put("LIGHT_CEIL", 15, 5, "E-LIGHT")           # lighting C-3
    put("DATA", 14, 9.5, "E-LOWVOLT")             # low voltage: not on a power circuit
    put("OUTLET", 32, 0.5)
    put("OUTLET", 48, 0.5)                        # bedroom 2: C-4, upstairs
    put("LIGHT_CEIL", 40, 5, "E-LIGHT")           # second floor lighting C-5
    msp.add_lwpolyline([(32, 0.5), (40, 8)], dxfattribs={"layer": "E-CIRCUIT"})   # home runs meet at the riser
    msp.add_lwpolyline([(48, 0.5), (40, 8)], dxfattribs={"layer": "E-CIRCUIT"})
    txt("RISER TO 200A PANEL", 40, 9, "E-CIRCUIT")
    txt("RANGE 30A", 3, 3, "E-CIRCUIT")
    put("OUTLET", 5, -20)                         # the legend: left out
    p = tmp_path / "plan.dxf"
    doc.saveas(p)
    return str(p)


def _panel(tmp_path):
    doc = ezdxf.new("R2010")
    msp = doc.modelspace()
    def txt(t, x, y):
        msp.add_text(t, height=0.3, dxfattribs={"insert": (x, y)})
    for x in (24, 30, 46, 51, 56, 62):
        msp.add_line((x, 30), (x, 40), dxfattribs={"layer": "E-SCHEDULE"})
    for t, x in (("CIRCUIT", 27), ("DESCRIPTION", 38), ("AMPS", 48.5), ("POLES", 53.5), ("WIRE", 59)):
        txt(t, x, 39.5)
    rows = [("C-1", "Living receptacles", "20", "1", "12/2"), ("C-2", "Kitchen receptacles", "20", "1", "12/2"),
            ("C-3", "Ground floor lighting", "15", "1", "12/2"), ("C-4", "Bedroom 2", "20", "1", "12/2"),
            ("C-5", "Second floor lighting", "15", "1", "14/2"), ("RANGE", "Kitchen range", "30", "2", "10/2"),
            ("MAIN", "200A main breaker", "200", "2", "Service entrance")]
    y = 38.4
    for r in rows:
        txt(r[0], 27, y)
        txt(r[1], 30.5, y - 0.25)
        txt(r[2], 48.5, y)
        txt(r[3], 53.5, y)
        txt(r[4], 59, y)
        y -= 1.1
    txt("200A MAIN PANEL", 3, 38.6)                # the panel elevation beside the table: not a row
    txt("GROUND FLOOR", 55, 20.2)
    txt("C-1  C-2  C-3", 55, 19.1)
    txt("SECOND FLOOR", 55, 11.2)
    txt("C-4  C-5", 55, 10.1)
    p = tmp_path / "panel.dxf"
    doc.saveas(p)
    return str(p)


def test_panel_schedule_is_read(tmp_path):                                               # WR-01
    got = {c.id: c for c in wiring.read_panel_schedule(_panel(tmp_path))["circuits"]}
    assert list(got) == ["C-1", "C-2", "C-3", "C-4", "C-5", "RANGE"]                     # no MAIN
    assert got["C-1"].description == "Living receptacles" and got["C-1"].amps == 20 and got["C-1"].wire == "12/2"
    assert got["RANGE"].poles == 2 and got["RANGE"].wire == "10/2"
    assert [got[c].floor for c in ("C-1", "C-3", "C-4", "C-5", "RANGE")] == [0, 0, 1, 1, 0]


def test_floor_plan_is_read(tmp_path):                                                   # WR-02
    plan = wiring.read_floor_plan(_plan(tmp_path))
    assert [(f.index, f.name) for f in plan["floors"]] == [(0, "Ground floor"), (1, "Second floor")]
    assert plan["panel"] == {"x": 19.7, "y": 5.0, "floor": 0}
    assert plan["riser"] == {"x": 40.0, "y": 8.0, "floor": 1}                              # where the home runs meet
    assert len(plan["devices"]) == 10                                                      # no legend, no data drop
    assert [a.room for a in plan["appliances"]] == ["RANGE"]
    rooms = {d.id: d.room for d in plan["devices"]}
    assert rooms["OUTLET_GFCI@2.0,0.5"] == "KITCHEN" and rooms["OUTLET@48.0,0.5"] == "BEDROOM 2"


def test_takeoff_assigns_routes_and_sizes(tmp_path):                                     # WR-03
    out = tmp_path / "wiring.dxf"
    r = wiring.takeoff(_plan(tmp_path), _panel(tmp_path), out_path=str(out))
    assert r["unassigned"] == []
    c = {x["id"]: x for x in r["circuits"]}
    assert c["C-1"]["devices"] == 2 and c["C-2"]["devices"] == 2 and c["C-3"]["devices"] == 3   # light + 3-way pair
    assert c["C-4"]["devices"] == 2 and c["C-5"]["devices"] == 1 and c["RANGE"]["devices"] == 1
    # 2026-11-21 (David: "all get routed from basement ceiling"): the built-in house has a basement with the panel in it
    # (center 5 ft up a 8 ft basement): the ground floor's runs leave the panel up to the basement ceiling (half the
    # 1 ft floor framing under the ground floor: 8 + 0.5 - 5 = 3.5 ft) and come up into the walls.
    assert c["C-1"]["home_run_ft"] == pytest.approx(3.5) and c["C-1"]["run_ft"] > 0
    # Upstairs circuits: along the basement ceiling to the riser, then up the chase to the framing under the second
    # floor (from -0.5 to 9 + 1 - 0.5 = 9.5 ft: 10 ft).
    assert c["C-4"]["home_run_ft"] == pytest.approx(3.5 + abs(49.7 - 40) + abs(5 - 8) + 10, abs=0.2)
    # Sizes: the schedule's, checked against the breaker; the 3-way pair gets 12/3 travelers.
    assert c["C-3"]["flags"] == ["schedule says 12/2 on a 15 A breaker; 14/2 is the usual size - check"]
    # 2026-11-20 (David): a range on 10/2 has no neutral - priced as 10/3, and flagged for the designer.
    assert c["RANGE"]["flags"] == ["the panel schedule says 10/2, priced as 10/3: a kitchen range needs a neutral"
                                   " (NEC 250.140) - check with the designer"]
    assert c["C-3"]["travelers_ft"] > 0
    bom = {b["cable"]: b for b in r["bom"]}
    assert set(bom) == {"10/3 NM-B", "12/2 NM-B", "12/3 NM-B", "14/2 NM-B"}
    b = bom["12/2 NM-B"]
    assert b["order_ft"] >= b["measured_ft"] * 1.1 and b["rolls"] == -(-b["order_ft"] // 250)
    # The wiring drawing: one layer per circuit with its route and label, and the wire schedule under the plan.
    doc = ezdxf.readfile(out)
    layers = {l.dxf.name for l in doc.layers}
    assert {"E-WIRE-C-1", "E-WIRE-C-4", "E-WIRE-RANGE", "E-WIRE-SCHEDULE"} <= layers
    msp = doc.modelspace()
    assert len(msp.query('LWPOLYLINE[layer=="E-WIRE-C-1"]')) == 2                        # panel -> outlet -> outlet
    texts = [t.dxf.text for t in msp.query('TEXT[layer=="E-WIRE-SCHEDULE"]')]
    assert any(t.startswith("WIRE SCHEDULE") for t in texts) and any(t.startswith("12/2 NM-B:") for t in texts)


def test_marks_what_the_drawing_has_no_symbol_for(tmp_path):                             # WR-11
    """2026-11-20 (David: "3 of these items don't have symbols, can they be added to the drawing"): the range receptacle
    goes at the range the RANGE circuit feeds, the branch breakers at the panel - on the wiring drawing's own layer
    (E-WIRE-ADDED), never in the designer's plan."""
    plan = _plan(tmp_path)
    out = tmp_path / "wiring.dxf"
    r = wiring.takeoff(plan, _panel(tmp_path), out_path=str(out))
    added = {a["kind"]: a for a in r["added"]}
    assert set(added) == {"range_receptacle", "branch_breakers"}                         # no dryer on this plan
    rng = next(c for c in r["circuits"] if c["id"] == "RANGE")
    assert (added["range_receptacle"]["x"], added["range_receptacle"]["y"]) == (rng["assigned"][0]["x"],
                                                                               rng["assigned"][0]["y"])
    assert added["range_receptacle"]["feeds"] == "range_receptacles" and "14-50R" in added["range_receptacle"]["label"]
    branch = [c["id"] for c in r["circuits"] if c["amps"] < 30 and c["devices"]]
    b = added["branch_breakers"]
    assert b["circuits"] == branch and (b["x"], b["y"]) == (r["panel"]["x"], r["panel"]["y"])
    assert f"{len(branch)} BRANCH BREAKERS" in b["label"]
    msp = ezdxf.readfile(out).modelspace()
    texts = [t.dxf.text for t in msp.query('TEXT[layer=="E-WIRE-ADDED"]')]
    assert len(texts) == 2 and any("RANGE RECEPTACLE" in t for t in texts)
    assert len(msp.query('CIRCLE[layer=="E-WIRE-ADDED"]')) == 1
    assert not ezdxf.readfile(plan).modelspace().query('*[layer=="E-WIRE-ADDED"]')       # the designer's plan untouched


def test_walls_route_when_there_is_no_ceiling(tmp_path):                                 # WR-04
    plan, panel = _plan(tmp_path), _panel(tmp_path)
    ceil = {c["id"]: c for c in wiring.takeoff(plan, panel)["circuits"]}
    walls = {c["id"]: c for c in wiring.takeoff(plan, panel, {"route": {0: "walls"}})["circuits"]}
    # Outlets to outlets through the studs: no climb to the ceiling and back, but a longer way round.
    assert walls["C-1"]["run_ft"] != ceil["C-1"]["run_ft"]
    assert walls["C-4"]["run_ft"] == ceil["C-4"]["run_ft"]                                # upstairs unchanged


def test_no_panel_is_a_clear_error(tmp_path):                                            # WR-05
    doc = ezdxf.new("R2010")
    msp = doc.modelspace()
    for a, b in (((0, 0), (10, 0)), ((10, 0), (10, 10)), ((10, 10), (0, 10)), ((0, 10), (0, 0))):
        msp.add_line(a, b, dxfattribs={"layer": "A-WALL-EXT"})
    p = tmp_path / "nopanel.dxf"
    doc.saveas(p)
    with pytest.raises(ValueError, match="no panel"):
        wiring.takeoff(str(p), _panel(tmp_path))


def _plan_with_circuits(tmp_path):
    """The house above, plus the designer's labelled circuit lines (each line, then its label, the usual way):
    C-1 from a living outlet to the panel (the run agrees), C-2 from the other living outlet (the run says C-1),
    C-4 from the bedroom 2 outlet up to the riser (agrees) and a C-9 the panel schedule doesn't have."""
    path = _plan(tmp_path)
    doc = ezdxf.readfile(path)
    msp = doc.modelspace()
    for pts, label, at in (([(12, 0.5), (19.7, 5)], "C-1", (15, 2)), ([(18, 9.5), (19.7, 5)], "C-2", (19, 8)),
                           ([(48, 0.5), (40, 8)], "C-4", (45, 4)), ([(2, 9), (19.7, 5)], "C-9", (6, 8))):
        msp.add_lwpolyline(pts, dxfattribs={"layer": "E-CIRCUIT"})
        msp.add_text(label, height=0.5, dxfattribs={"layer": "E-CIRCUIT", "insert": at})
    doc.saveas(path)
    return path


def test_circuit_names_from_labels():                                                    # WR-08
    assert wiring._circuit_name("C-3") == "C-3" and wiring._circuit_name("c-12") == "C-12"
    assert wiring._circuit_name("RANGE 30A") == "RANGE" and wiring._circuit_name("WTR HTR 30A") == "WTR HTR"
    assert wiring._circuit_name("RISER TO 200A PANEL") is None and wiring._circuit_name("KITCHEN") is None


def test_the_run_is_checked_against_the_drawn_circuits(tmp_path):                         # WR-09
    """2026-11-20 (David: use the designer's circuit lines to check the wiring run)."""
    plan_path = _plan_with_circuits(tmp_path)
    drawn = {d["label"] for d in wiring.read_floor_plan(plan_path)["drawn"]}
    assert drawn == {"C-1", "C-2", "C-4", "C-9"}                       # the riser home runs have no label: not checked
    r = wiring.takeoff(plan_path, _panel(tmp_path))
    ck = r["drawing_check"]
    assert ck["lines"] == 4 and ck["matched"] == 2 and ck["not_in_schedule"] == ["C-9"]
    assert ck["differ"] == [{"circuit": "C-2", "what": "device", "device": "OUTLET@18.0,9.5", "item_type": "duplex_receptacle",
                             "room": "LIVING", "run_circuit": "C-1"}]
    assert set(ck["not_drawn"]) == {"C-3", "C-5", "RANGE"}
    c2 = next(c for c in r["circuits"] if c["id"] == "C-2")
    assert any("the drawing starts C-2 at the outlet in Living; the wiring run has it on C-1" in f for f in c2["flags"])
    # "Move to C-2" is a device move: the run then agrees with the drawing.
    again = wiring.takeoff(plan_path, _panel(tmp_path), overrides={"OUTLET@18.0,9.5": "C-2"})
    assert again["drawing_check"]["differ"] == [] and again["drawing_check"]["matched"] == 3


def test_no_circuit_lines_no_check(tmp_path):                                            # WR-10
    r = wiring.takeoff(_plan(tmp_path), _panel(tmp_path))
    assert r["drawing_check"]["lines"] == 0 and r["drawing_check"]["differ"] == []


def test_no_panel_drawing_lays_the_circuits_out(tmp_path):                               # WR-12
    """2026-11-21 (David: "Add the fall back"): with no panel drawing the circuits are laid out from the floor plan -
    lighting on 15 A 14/2, the kitchen counter on at least two 20 A circuits, each appliance on its own circuit, every
    circuit on one floor and flagged to check against the electrician's layout."""
    out = tmp_path / "wiring.dxf"
    r = wiring.takeoff(_plan(tmp_path), None, out_path=str(out))
    assert r["circuits_from"] == "laid_out" and r["unassigned"] == []
    assert r["main"]["amps"] == 200 and r["drawing_check"]["lines"] == 0
    c = {x["description"]: x for x in r["circuits"]}
    assert sum(x["devices"] for x in r["circuits"]) == 11                                 # 10 devices + the range
    kitchen = [x for d, x in c.items() if d.startswith("Kitchen small appliance")]
    assert len(kitchen) >= 2 and all(x["amps"] == 20 and x["wire"] == "12/2" for x in kitchen)
    lights = [x for d, x in c.items() if "lighting" in d]
    assert lights and all(x["amps"] == 15 and x["wire"] == "14/2" for x in lights)
    assert c["Ground floor lighting"]["devices"] == 3                                     # the light + its 3-way pair
    assert c["Range"]["amps"] == 50 and c["Range"]["devices"] == 1
    assert all(any(wiring.LAID_OUT in f for f in x["flags"]) for x in r["circuits"])
    assert any(a["kind"] == "range_receptacle" for a in r["added"])
    assert out.exists()


def test_laid_out_circuits_take_a_hand_move_on_the_same_floor(tmp_path):                 # WR-13
    plan = wiring.read_floor_plan(_plan(tmp_path))
    first = wiring.layout_circuits(plan)
    assert first["generated"] is True
    kit = [c for c in first["circuits"] if c.description.startswith("Kitchen small appliance")]
    dev = kit[0].devices[0].id
    plan = wiring.read_floor_plan(_plan(tmp_path))
    moved = wiring.layout_circuits(plan, {dev: kit[1].id, "OUTLET@48.0,0.5": kit[0].id})   # 2nd: other floor, ignored
    got = {c.id: [d.id for d in c.devices] for c in moved["circuits"]}
    assert dev in got[kit[1].id] and "OUTLET@48.0,0.5" not in got[kit[0].id]

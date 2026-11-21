"""2026-11-20 (David): "add the 3 new symbols in the CAD drawing ... and any new symbols needed", "fix the 2 exterior lights
as separate from the interior wall lights", "fix the way the panel drawing looks - the table has lines through the
wording", and "make a wiring schematic diagram that shows wires, and save it as a DXF". Small drawings built here with
ezdxf - never the live plans."""
import pytest

ezdxf = pytest.importorskip("ezdxf")
from estimator.context import personal_context  # noqa: E402
from estimator.estimating import quick, service  # noqa: E402
from estimator.plan_engine import dxf_reader, symbols  # noqa: E402
from estimator.plan_engine import symbol_library as lib  # noqa: E402
from estimator.takeoff import wiring, wiring_schematic  # noqa: E402
from test_wiring import _panel, _plan  # noqa: E402

CTX = personal_context()


def _read(path):
    got = dxf_reader.read(str(path), None, 5)
    sheets = got if isinstance(got, list) else got.get("sheets", [got])
    return sheets[0]


def test_the_new_symbols_have_block_names_and_counts():                                # DS-01
    assert lib.by_block_name("RANGE_RECEPT")["item_type"] == "range_receptacle"
    assert lib.by_block_name("DRYER_RECEPT")["item_type"] == "dryer_receptacle"
    assert lib.by_block_name("LIGHT_EXT")["item_type"] == "light_exterior"
    assert lib.by_block_name("DISCONNECT")["item_type"] == "disconnect"
    assert lib.by_block_name("LIGHT_WALL")["item_type"] == "light_wall"                  # unchanged
    assert lib.FEEDS["range_receptacle"] == ("electrical", "range_receptacles")
    assert lib.FEEDS["dryer_receptacle"] == ("electrical", "dryer_receptacles")
    assert lib.FEEDS["disconnect"] == ("electrical", "disconnects")
    assert lib.FEEDS["light_exterior"] == ("electrical", "exterior_lights")


def test_disconnects_are_priced(db):                                                   # DS-02
    e = service.create_estimate(db, CTX, "Disconnects")
    e = quick.answer(db, CTX, e["id"], "electrical", {"disconnects": 2}, e["rev"])
    lines = {ln["calc"]["rule"]: ln for ln in e["sections"][0]["lines"]}
    assert lines["disconnects"]["quantity"] == "2" and lines["disconnects"]["total_cents"] == 7000   # 2 x $35
    assert float(lines["device_labor"]["quantity"]) == 2.0                                          # 1 hr each


def _schedule_sheet(tmp_path, layer_rows="E-SCHEDULE", layer_box="E-RISER"):
    """A panel schedule (row lines 1.1 ft apart, like the house's), a riser box and a legend frame - no walls."""
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2
    msp = doc.modelspace()
    for i in range(8):
        y = 40 - i * 1.1
        msp.add_line((24, y), (62, y), dxfattribs={"layer": layer_rows})
    for x in (24, 30, 46, 62):
        msp.add_line((x, 40 - 7 * 1.1), (x, 40), dxfattribs={"layer": layer_rows})
    for t, x in (("CIRCUIT", 25), ("DESCRIPTION", 31), ("AMPS", 47)):
        msp.add_text(t, height=0.5, dxfattribs={"layer": "E-TEXT", "insert": (x, 39.3)})
    for i in range(6):
        msp.add_text(f"C-{i + 1}", height=0.5, dxfattribs={"layer": "E-TEXT", "insert": (25, 38.2 - i * 1.1)})
        msp.add_text("Living receptacles", height=0.5, dxfattribs={"layer": "E-TEXT", "insert": (31, 38.2 - i * 1.1)})
    msp.add_lwpolyline([(48, 8), (62, 8), (62, 12), (48, 12)], close=True, dxfattribs={"layer": layer_box})
    msp.add_text("SECOND FLOOR", height=0.5, dxfattribs={"layer": "E-TEXT", "insert": (50, 10)})
    msp.add_lwpolyline([(2, 4.8), (20, 4.8), (20, 11.2), (2, 11.2)], close=True, dxfattribs={"layer": "A-TITLE"})
    msp.add_text("LEGEND", height=0.7, dxfattribs={"layer": "E-TEXT", "insert": (3, 10.3)})
    p = tmp_path / f"schedule_{layer_rows}.dxf"
    doc.saveas(p)
    return p


def test_a_panel_schedule_is_not_read_as_walls_and_rooms(tmp_path):                    # DS-03
    """The schedule's rows are drawn as they are - no wall bands over every other row's text, no "rooms" made of its
    cells, the riser's boxes or the legend frame (DESCRIPTION 18 sq ft, LEGEND 115 sq ft)."""
    s = _read(_schedule_sheet(tmp_path))
    kinds = [o["kind"] for o in s["objects"]]
    assert "wall" not in kinds and "room" not in kinds
    assert kinds.count("line") >= 12                                       # the table's lines are still drawn
    # Lines on layers that don't say what they are (layer 0) are still read as a floor plan's would be.
    s0 = _read(_schedule_sheet(tmp_path, layer_rows="0", layer_box="0"))
    assert any(o["kind"] == "wall" for o in s0["objects"])


def _plan_with_new_symbols(tmp_path):
    """The test house (test_wiring._plan) revised the way the real one was: a range receptacle at the range, an exterior
    wall light outside the ground floor, an A/C disconnect."""
    src = _plan(tmp_path)
    doc = ezdxf.readfile(src)
    for name in ("RANGE_RECEPT", "LIGHT_EXT", "LIGHT_WALL", "DISCONNECT"):
        doc.blocks.new(name=name).add_circle((0, 0), 0.4)
    msp = doc.modelspace()
    msp.add_blockref("RANGE_RECEPT", (3, 1), dxfattribs={"layer": "E-OUTLET"})     # by "RANGE 30A" (3, 3)
    msp.add_blockref("LIGHT_EXT", (10, -0.7), dxfattribs={"layer": "E-LIGHT"})     # outside the front wall
    msp.add_blockref("LIGHT_WALL", (0.6, 5), dxfattribs={"layer": "E-LIGHT"})      # inside: a sconce
    p = tmp_path / "plan_rev2.dxf"
    doc.saveas(p)
    return str(p)


def test_the_plan_reader_counts_the_new_symbols(tmp_path):                             # DS-04
    s = _read(_plan_with_new_symbols(tmp_path))
    symbols.cad_symbols(s)
    types = [(o.get("symbol") or {}).get("item_type") for o in s["objects"] if o["kind"] == "symbol"]
    assert types.count("range_receptacle") == 1
    assert types.count("light_exterior") == 1 and types.count("light_wall") == 1         # each its own count


def test_a_range_receptacle_on_the_plan_is_where_the_range_circuit_ends(tmp_path):     # DS-05
    """It's the end of the RANGE circuit (not a C-2 kitchen outlet), and the wiring run then marks no range receptacle
    of its own - the drawing has one."""
    path = _plan_with_new_symbols(tmp_path)
    plan = wiring.read_floor_plan(path)
    assert plan["drawn_ends"] == ["range_receptacle"]
    rng = next(a for a in plan["appliances"] if a.room == "RANGE")
    assert (rng.x, rng.y) == (3.0, 1.0) and "range receptacle" in rng.why
    assert not any(d.item_type == "range_receptacle" for d in plan["devices"])
    r = wiring.takeoff(path, _panel(tmp_path))
    assert [a["kind"] for a in r["added"]] == ["branch_breakers"]
    assert r["main"]["amps"] == 200                                                     # the MAIN row, kept aside


def _crossed(msp, layers):
    """Texts on S-DEVICE that a conductor line runs through."""
    lines = [(e.dxf.start, e.dxf.end) for e in msp.query("LINE") if e.dxf.layer in layers]
    out = []
    for t in msp.query('TEXT[layer=="S-DEVICE"]'):
        p = t.dxf.align_point if t.dxf.hasattr("align_point") else t.dxf.insert
        for a, b in lines:
            if abs(a.y - b.y) < 1e-6 and abs(a.y - p.y) < 0.25 and min(a.x, b.x) < p.x < max(a.x, b.x):
                out.append(t.dxf.text)
    return out


def test_the_wiring_schematic(tmp_path):                                                # DS-06
    """The panel, each circuit's breaker and every conductor of its cable in its colour out to its devices: a 2-wire
    120 V circuit is black, white and ground; the range (2-pole, 10/3 - a neutral) is black, red, white and ground.
    No conductor runs through a device's code."""
    r = wiring.takeoff(_plan(tmp_path), _panel(tmp_path))
    out = tmp_path / "schematic.dxf"
    wiring_schematic.write(r, str(out), "Test house")
    doc = ezdxf.readfile(out)
    msp = doc.modelspace()
    layers = {l.dxf.name for l in doc.layers}
    assert {"S-PANEL", "S-BREAKER", "S-HOT-L1", "S-HOT-L2", "S-NEUTRAL", "S-GROUND", "S-DEVICE"} <= layers
    texts = [t.dxf.text for t in msp.query("TEXT")]
    assert texts[0].startswith("WIRING SCHEMATIC - Test house")
    assert "MAIN 200A" in texts and all(c["id"] in texts for c in r["circuits"])
    assert "RNG" in texts and texts.count("R") >= 2 and "GF" in texts                    # the devices, coded
    assert wiring_schematic.conductors({"amps": 20, "poles": 1, "wire": "12/2"}) == [("L1", ""), ("N", ""), ("G", "")]
    assert [b for b, _ in wiring_schematic.conductors({"amps": 30, "poles": 2, "wire": "10/3"})] == ["L1", "L2", "N", "G"]
    assert [b for b, _ in wiring_schematic.conductors({"amps": 30, "poles": 2, "wire": "10/2"})] == ["L1", "L2", "G"]
    red = [e for e in msp.query('LINE[layer=="S-HOT-L2"]')]
    assert red, "the range's red conductor and the L2 bus are drawn"
    assert _crossed(msp, {"S-HOT-L1", "S-HOT-L2", "S-NEUTRAL", "S-GROUND"}) == []
    # Every circuit row has its conductors: 3 for a /2 120 V circuit, out past its first device.
    c1 = next(c for c in r["circuits"] if c["id"] == "C-1")
    assert c1["devices"] == 2

"""Plans from a description (estimator/design/describe.py + draw_plans.py), 2026-11-24 (David: "If the user does not
have plans I want the user to be able to use AI Design button so the user can just describe the plans and have AI
Design it for him" - every trade, as a drawn plan).

The round trip: a design (what the AI answers) is drawn as CAD sheets, the sheets go through the real plan engine, and
each trade's plan reader must measure what the design says - the same numbers the drawing prints."""
import json
import shutil

import pytest

ezdxf = pytest.importorskip("ezdxf")
pytest.importorskip("shapely")
from estimator.building import trades  # noqa: E402
from estimator.context import personal_context  # noqa: E402
from estimator.design import describe as dsc  # noqa: E402
from estimator.design import draw_plans as dp  # noqa: E402
from estimator.drawing_model import engine, store  # noqa: E402
from estimator.estimating import service  # noqa: E402

CTX = personal_context()


def fence_job():
    """A back yard on a 100 x 150 lot behind a 40 x 30 house: fence on three sides, a walk gate and a drive gate."""
    return {
        "summary": "6 ft wood privacy fence around the back yard with a walk gate and a drive gate",
        "assumptions": ["posts 8 ft on center", "house at 30-70 x 40-70"],
        "lot": {"width_ft": 100, "depth_ft": 150},
        "building": None,
        "fences": [{"points": [[30, 70], [0, 70], [0, 150], [100, 150], [100, 70], [70, 70]], "material": "wood",
                    "style": "privacy", "height_ft": 6}],
        "gates": [{"at": [15, 70], "kind": "walk", "width_ft": 4}, {"at": [85, 70], "kind": "drive", "width_ft": 12}],
        "zones": [{"kind": "sod", "points": [[0, 70], [100, 70], [100, 150], [0, 150]], "description": "St Augustine sod"}],
        "flatwork": [{"kind": "patio", "points": [[40, 72], [60, 72], [60, 84], [40, 84]], "thickness_in": 4}],
        "notes": ["call 811 before digging"],
    }


def shed_job():
    """A 20 x 30 shed with a shop and a half bath, a slab, a gable roof, a roll-up door, an entry door and windows."""
    return {
        "summary": "20 x 30 shed: shop and half bath, 4 in slab, gable roof 4:12",
        "assumptions": ["9 ft walls"],
        "building": {
            "name": "SHED", "kind": "accessory", "wall_thickness_in": 6,
            "floors": [{"name": "GROUND", "ceiling_ft": 9,
                        "outline": [[0, 0], [30, 0], [30, 20], [0, 20]],
                        "openings": [{"kind": "overhead_door", "a": [8, 0], "b": [18, 0], "mark": "D1"},
                                     {"kind": "door", "a": [24, 0], "b": [27, 0], "mark": "D2"},
                                     {"kind": "door", "a": [24, 13], "b": [24, 15.5], "mark": "D3"},
                                     {"kind": "window", "a": [0, 8], "b": [0, 11], "mark": "W1"},
                                     {"kind": "window", "a": [10, 20], "b": [13, 20], "mark": "W1"},
                                     {"kind": "window", "a": [30, 15], "b": [30, 17], "mark": "W2"}],
                        "interior_walls": [[[24, 10], [24, 20]], [[24, 10], [30, 10]]],
                        "rooms": [{"name": "SHOP", "x0": 0, "y0": 0, "x1": 24, "y1": 20, "floor": "concrete"},
                                  {"name": "HALF BATH", "x0": 24, "y0": 10, "x1": 30, "y1": 20, "floor": "LVP",
                                   "ceiling_ft": 8}]}],
            "foundation": {"kind": "slab", "thickness_in": 4, "footing_in": 12},
            "roof": {"style": "gable", "pitch": "4:12", "overhang_ft": 1, "ridge": "x", "material": "architectural shingle"},
            "siding": "metal panels"},
        "doors": [{"mark": "D1", "width_ft": 10, "height_ft": 10, "type": "garage", "description": "10x10 roll-up"},
                  {"mark": "D2", "width_ft": 3, "height_ft": 6.67, "type": "exterior", "description": "36in steel entry"},
                  {"mark": "D3", "width_ft": 2.5, "height_ft": 6.67, "type": "interior", "description": "30in hollow core"}],
        "windows": [{"mark": "W1", "width_ft": 3, "height_ft": 4, "description": "single hung vinyl"},
                    {"mark": "W2", "width_ft": 2, "height_ft": 2, "description": "bath awning"}],
        "fixtures": [{"type": "water_closet", "x": 28, "y": 18}, {"type": "lavatory", "x": 26, "y": 18.5},
                     {"type": "water_heater", "x": 28.5, "y": 11.5}, {"type": "hose_bibb", "x": 30.2, "y": 5}],
        "fences": [], "gates": [], "zones": [], "flatwork": [], "demolition": [{"what": "remove old slab", "qty": 200,
                                                                                "unit": "sqft"}],
    }


@pytest.fixture(autouse=True)
def inline(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _read(db, tmp_path, design):
    """Draw the design, upload every sheet to a new project and read it with the plan engine."""
    est = service.create_estimate(db, CTX, "Described job")["id"]
    d = dsc.parse_design(json.dumps(design))
    drawn = dp.draw_all(d, tmp_path, "Described job", "t")
    ids = {}
    for s in drawn:
        nice = tmp_path / f"{dp.SHEETS[s['sheet']]}.dxf"
        shutil.copyfile(s["path"], nice)
        ps = store.upload(db, CTX, est, str(nice), confirm=True)["plan_set_id"]
        engine.start(db, CTX, ps, confirm=True)
        ids[s["sheet"]] = ps
    return est, d, ids


def test_the_ai_answer_is_checked_and_tidied():                                         # DS-01
    d = dsc.parse_design("```json\n" + json.dumps(shed_job()) + "\n```")
    assert d["building"]["floors"][0]["openings"][0]["mark"] == "D1"
    assert d["building"]["roof"]["pitch"] == "4:12" and d["building"]["foundation"]["thickness_in"] == 4
    assert {r["name"]: r["floor"] for r in d["building"]["floors"][0]["rooms"]} == {"SHOP": "concrete", "HALF BATH": "LVP"}
    assert dsc.sheets_for(d) == ["floor", "foundation", "roof", "demolition"]
    assert dsc.sheets_for(dsc.parse_design(json.dumps(fence_job()))) == ["site"]
    assert [f for f in dsc.check(d) if f["level"] == "error"] == []
    with pytest.raises(dsc.DesignError):
        dsc.parse_design(json.dumps({"summary": "nothing"}))
    with pytest.raises(dsc.DesignError):
        dsc.parse_design("not json")


def test_the_check_finds_what_cant_be_built():                                          # DS-02
    bad = fence_job()
    bad["gates"].append({"at": [50, 20], "kind": "walk", "width_ft": 4})                  # not on a fence
    bad["fences"].append({"points": [[0, 0], [2, 0]], "material": "vinyl", "height_ft": 4})  # 2 ft
    codes = {f["code"] for f in dsc.check(dsc.parse_design(json.dumps(bad)))}
    assert {"gate_off_fence", "short_fence"} <= codes


def test_a_fence_design_is_measured_from_its_site_plan(db, tmp_path):                  # DS-03
    est, d, ids = _read(db, tmp_path, fence_job())
    a = trades.answers(db, CTX, "fencing", estimate_id=est)["answers"]
    assert a["length_lf"] == 320.0                                          # 30 + 80 + 100 + 80 + 30
    assert a["material"] == "wood" and a["height"] == "6" and a["walk_gates"] == 1 and a["drive_gates"] == 1
    assert trades.answers(db, CTX, "landscaping", estimate_id=est)["answers"]["sod_sqft"] == 8000.0
    # the site plan's areas are not rooms: nothing for flooring, drywall or painting
    m = trades.all_answers(db, CTX, estimate_id=est)["model"]["totals"]
    assert m["rooms"] == 0 and m["floor_sqft"] == 0


def test_fence_notes_read_aluminum_and_feet_and_inches():                               # DS-05
    """2026-11-25 (David: a pool fence "needs Aluminum Power coted Black fence type ... 4' 6" high not 4' ft high")."""
    from estimator.plan_engine import site as pe_site
    f = pe_site.fence_info
    assert f("4'-6\" ALUMINUM POOL BARRIER FENCE") == {"material": "aluminum", "height_ft": 4.5, "remove": False}
    assert f("4' 6\" BLACK POWDER COATED FENCE")["material"] == "aluminum"
    assert f("HT 4'-6\" ORNAMENTAL FENCE") == {"material": "iron", "height_ft": 4.5, "remove": False}
    assert f("5' WROUGHT IRON FENCE")["material"] == "iron"
    assert f("6'-0\" WOOD PRIVACY FENCE")["height_ft"] == 6.0 and f("6' WOOD FENCE")["height_ft"] == 6.0
    assert f("4 FT 6 IN ALUM. FENCE") == {"material": "aluminum", "height_ft": 4.5, "remove": False}


def test_an_aluminum_pool_fence_is_drawn_read_and_priced(db, tmp_path):                 # DS-06
    from estimator.estimating import quick
    from estimator.modules import get_registry
    job = fence_job()
    job["fences"][0].update(material="aluminum", style="pool barrier", height_ft=4.5)
    est, d, ids = _read(db, tmp_path, job)
    a = trades.answers(db, CTX, "fencing", estimate_id=est)["answers"]
    assert a["material"] == "aluminum" and a["height"] == "4.5" and a["length_lf"] == 320.0
    rev = service.get_estimate(db, CTX, est)["rev"]
    quick.answer(db, CTX, est, "fencing", {k: a[k] for k in ("length_lf", "material", "height", "walk_gates", "drive_gates")},
                 int(rev), get_registry())
    lines = {ln["description"]: ln for s in service.get_estimate(db, CTX, est)["sections"] for ln in s["lines"]}
    assert "Aluminum fence panels (powder coated)" in lines and "Wrought iron panels" not in lines
    assert float(lines["Aluminum fence panels (powder coated)"]["quantity"]) == 1440.0       # 320 lf x 4.5 ft


def test_a_shed_design_is_measured_from_its_floor_plan(db, tmp_path):                  # DS-04
    est, d, ids = _read(db, tmp_path, shed_job())
    allx = trades.all_answers(db, CTX, estimate_id=est, include_proposed=True)
    m, t = allx["model"]["totals"], {k: v["answers"] for k, v in allx["trades"].items()}
    assert m["rooms"] == 2 and m["floor_sqft"] == 540.0                    # SHOP 24 x 20 + HALF BATH 6 x 10
    assert m["doors"] == 3 and m["windows"] == 3 and m["stories"] == 1
    # every opening is sized from the drawn schedules, on the right kind of wall
    ops = {(o["mark"], o["wall_type"]) for o in allx["model"]["openings"]}
    assert ops == {("D1", "exterior"), ("D2", "exterior"), ("D3", "interior"), ("W1", "exterior"), ("W2", "exterior")}
    assert all(o["size_from"] == "schedule" for o in allx["model"]["openings"])
    d1 = next(o for o in allx["model"]["openings"] if o["mark"] == "D1")
    assert (d1["width_ft"], d1["height_ft"]) == (10.0, 10.0)
    # ceiling heights come from the room finish schedule
    assert {r["name"]: r["height_ft"] for r in allx["model"]["rooms"]} == {"SHOP": 9.0, "HALF BATH": 8.0}
    assert t["windows_doors"] == {"windows_small": 3, "exterior_doors": 1, "interior_doors": 1, "garage_doors": 1}
    assert t["flooring"]["area_sqft"] == 540.0 and t["framing"]["wall_height"] == "9"
    assert t["plumbing"] == {"hose_bibs": 1, "sinks": 1, "toilets": 1, "water_heater": "tank"}
    assert t["hvac"]["conditioned_sqft"] == 540.0

"""Coder 2 Sprint 12: the shared wall-and-room model (rooms, walls, openings, heights; every wall-and-room trade's answers
from one model, so they agree), and the fuller electrical and plumbing symbol libraries with what each symbol counts
toward in its trade."""
from dataclasses import replace

import pytest

from estimator.building import model as building
from estimator.building import trades
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.errors import InvalidInput, NotFound
from estimator.estimating import service
from estimator.plan_engine import legends
from estimator.plan_engine import symbol_library as lib
from estimator.symbols import review
from estimator.symbols import service as sym

from pdfmaker import make_pdf, title_block
from test_plan_engine_sprint10 import legend, plan, shape

CTX = personal_context()
QUARTER = 'SCALE: 1/4" = 1\'-0"'


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def choice_values(q):
    """A module question's choice values (the registry keeps choices as dicts or as objects)."""
    return {c["value"] if isinstance(c, dict) else c.value for c in q.choices}


def rect(x0, y0, x1, y1):
    return [(x0, y0, x1, y0), (x1, y0, x1, y1), (x1, y1, x0, y1), (x0, y1, x0, y0)]


# Two rooms with 6" walls at 1/4" = 1'-0": LIVING 10 x 12 ft, BEDROOM 9.5 x 12 ft, a partition between them.
HOUSE = rect(5, 5, 10.25, 8.25) + rect(5.125, 5.125, 7.625, 8.125) + rect(7.75, 5.125, 10.125, 8.125)
NAMES = [(5.8, 6.5, 10, "LIVING"), (8.3, 6.5, 10, "BEDROOM")]
SCHEDULES = [(20, 2.0, 12, "DOOR SCHEDULE"), (20, 2.5, 8, "MARK"), (21.5, 2.5, 8, "SIZE"), (23, 2.5, 8, "TYPE"),
             (20, 2.8, 8, "D1"), (21.5, 2.8, 8, "3070"), (23, 2.8, 8, "A"),
             (20, 3.1, 8, "D2"), (21.5, 3.1, 8, "2868"), (23, 3.1, 8, "B"),
             (20, 5.0, 12, "WINDOW SCHEDULE"), (20, 5.5, 8, "MARK"), (21.5, 5.5, 8, "WIDTH"), (23, 5.5, 8, "HEIGHT"),
             (20, 5.8, 8, "W1"), (21.5, 5.8, 8, '4\'-0"'), (23, 5.8, 8, '3\'-0"')]
TAGS = [(6.2, 7.95, 9, "D1"), (7.6, 7.0, 9, "D2"), (9.85, 6.0, 9, "W1")]       # entry door, bedroom door, window


def page(texts=(), lines=(), sheet_no="A-101", title="FIRST FLOOR PLAN", scale=QUARTER):
    t = title_block(sheet_no, title) + [(4, 21, 14, "FLOOR PLAN")] + list(texts)
    if scale:
        t.append((4, 21.35, 9, scale))
    return {"w": 36, "h": 24, "texts": t, "lines": list(lines)}


def read(db, tmp_path, pages, title="Smith house", name="house.pdf"):
    est = service.create_estimate(db, CTX, title)
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / name, pages)), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    return est["id"], ps


@pytest.fixture
def house(db, tmp_path):
    eid, ps = read(db, tmp_path, [page(NAMES + SCHEDULES + TAGS, HOUSE)])
    return {"estimate_id": eid, "plan_set_id": ps, "model": building.build(db, CTX, estimate_id=eid)}


# ---------------------------------------------------------------- the model                       C2S12-B01..B06

def test_rooms_walls_and_openings(house):                                        # C2S12-B01
    m = house["model"]
    rooms = {r["name"]: r for r in m["rooms"]}
    assert (rooms["LIVING"]["area_sqft"], rooms["LIVING"]["perimeter_ft"]) == (120.0, 44.0)
    assert (rooms["BEDROOM"]["area_sqft"], rooms["BEDROOM"]["perimeter_ft"]) == (114.0, 43.0)
    kinds = sorted(w["type"] for w in m["walls"])
    assert kinds.count("interior") == 1 and kinds.count("exterior") >= 4 and "other" not in kinds
    partition = next(w for w in m["walls"] if w["type"] == "interior")
    assert (partition["length_ft"], partition["thickness_in"], len(partition["rooms"])) == (12.0, 6.0, 2)
    ops = {o["mark"]: o for o in m["openings"]}
    assert (ops["D1"]["width_ft"], ops["D1"]["height_ft"], ops["D1"]["size_from"]) == (3.0, 7.0, "schedule")   # 3070
    assert (ops["D2"]["width_ft"], ops["D2"]["height_ft"]) == (2.67, 6.67)                                      # 2868
    assert (ops["W1"]["width_ft"], ops["W1"]["height_ft"], ops["W1"]["kind"]) == (4.0, 3.0, "window")
    assert ops["D2"]["wall_id"] == partition["id"] and len(ops["D2"]["rooms"]) == 2          # the door between rooms
    assert len(ops["D1"]["rooms"]) == 1 and len(ops["W1"]["rooms"]) == 1                     # on outside walls
    t = m["totals"]
    assert (t["doors"], t["windows"], t["openings"], t["corners"], t["height_ft"]) == (2, 1, 3, 6, 8.0)


def test_room_surfaces_take_off_their_openings(house):                           # C2S12-B02
    rooms = {r["name"]: r for r in house["model"]["rooms"]}
    lv, bd = rooms["LIVING"], rooms["BEDROOM"]
    assert lv["openings_sqft"] == 38.8                 # entry door 21 + bedroom door 17.8
    assert bd["openings_sqft"] == 29.8                 # bedroom door 17.8 + window 12
    assert lv["wall_sqft"] == round(44 * 8 - 38.8, 1) and bd["wall_sqft"] == round(43 * 8 - 29.8, 1)
    assert lv["base_lf"] == round(44 - 3 - 2.67, 1)     # the window doesn't cut the baseboard
    t = house["model"]["totals"]
    assert t["exterior_wall_sqft"] == round(t["exterior_wall_lf"] * 8 - 21 - 12, 1)


def test_every_trade_agrees(house):                                              # C2S12-B03
    m = house["model"]
    a = {t: building.answers_for(m, t)["answers"] for t in building.WALL_TRADES}
    t = m["totals"]
    # Drywall hangs what painting paints: wall faces x height + ceilings - openings.
    assert round(a["drywall"]["wall_lf"] * 8 + a["drywall"]["ceiling_sqft"] - a["drywall"]["openings_sqft"], 1) == \
        round(a["painting"]["wall_sqft"] + a["painting"]["ceiling_sqft"], 1)
    assert a["framing"]["wall_lf"] == t["exterior_wall_lf"] + t["interior_wall_lf"]
    assert a["drywall"]["wall_lf"] == 87.0                 # both faces of the partition: the rooms' perimeters
    assert a["flooring"]["area_sqft"] == a["drywall"]["ceiling_sqft"] == a["insulation"]["attic_sqft"] == 234.0
    assert a["flooring"]["baseboard_lf"] == a["painting"]["trim_lf"]
    assert (a["framing"]["openings"], a["painting"]["doors"], a["framing"]["exterior"]) == (3, 2, True)
    assert len({building.answers_for(m, x)["model_key"] for x in building.WALL_TRADES}) == 1


def test_ceiling_heights_from_the_finish_schedule(db, tmp_path):                 # C2S12-B04
    finish = [(20, 8.0, 12, "ROOM FINISH SCHEDULE"), (20, 8.5, 8, "ROOM"), (21.5, 8.5, 8, "NAME"), (23.5, 8.5, 8, "CLG HT"),
              (20, 8.8, 8, "101"), (21.5, 8.8, 8, "LIVING"), (23.5, 8.8, 8, "9'-0\""),
              (20, 9.1, 8, "102"), (21.5, 9.1, 8, "BEDROOM"), (23.5, 9.1, 8, "9'-0\"")]
    eid, _ps = read(db, tmp_path, [page(NAMES + finish, HOUSE)])
    m = building.build(db, CTX, estimate_id=eid)
    assert {r["name"]: (r["height_ft"], r["height_from"]) for r in m["rooms"]} == \
        {"LIVING": (9.0, "finish schedule"), "BEDROOM": (9.0, "finish schedule")}
    assert building.answers_for(m, "framing")["answers"]["wall_height"] == "9"
    # Given a height for the project, rooms the schedule doesn't cover use it; the schedule still wins.
    eid2, _ = read(db, tmp_path, [page(NAMES, HOUSE)], title="Jones", name="j.pdf")
    m2 = building.build(db, CTX, estimate_id=eid2, height_ft=10)
    assert {r["height_from"] for r in m2["rooms"]} == {"given"} and m2["totals"]["height_ft"] == 10.0
    for bad in (3, 50, "tall"):
        with pytest.raises(InvalidInput):
            building.build(db, CTX, estimate_id=eid2, height_ft=bad)


def test_rooms_drawn_again_on_other_sheets_arent_counted_twice(db, tmp_path):    # C2S12-B05
    pages = [page(NAMES, HOUSE), page(NAMES, HOUSE, sheet_no="A-102", title="REFLECTED CEILING PLAN"),
             page(NAMES, HOUSE, sheet_no="E-101", title="POWER PLAN")]
    eid, _ = read(db, tmp_path, pages)
    m = building.build(db, CTX, estimate_id=eid)
    assert m["totals"]["rooms"] == 2 and m["totals"]["floor_sqft"] == 234.0
    why = {s["sheet_no"]: s["why"] for s in m["skipped_sheets"]}
    assert "repeat view" in why["A-102"] and "electrical sheet" in why["E-101"]


def test_unscaled_views_and_no_plans(db, tmp_path):                              # C2S12-B06
    eid, _ = read(db, tmp_path, [page(NAMES, HOUSE, scale=None)])
    m = building.build(db, CTX, estimate_id=eid)
    assert m["rooms"] == [] and any("unscaled" in n for n in m["notes"])
    empty = service.create_estimate(db, CTX, "No plans")
    m2 = building.build(db, CTX, estimate_id=empty["id"])
    assert m2["rooms"] == [] and "read the plans" in m2["notes"][0]
    with pytest.raises(InvalidInput):
        building.build(db, CTX)
    with pytest.raises(NotFound):
        building.build(db, replace(CTX, company_id="acme"), estimate_id=eid)
    with pytest.raises(InvalidInput):
        building.answers_for(m, "roofing")


# ---------------------------------------------------------------- answers through trades          C2S12-B07

def test_trade_answers_fit_the_trade_modules(db, house):                         # C2S12-B07
    from estimator.modules import get_registry
    reg = get_registry()
    for t in building.WALL_TRADES:
        out = trades.answers(db, CTX, t, estimate_id=house["estimate_id"])
        qs = {q.id: q for q in reg.get(t).questions}
        assert set(out["answers"]) <= set(qs) and out["answers"], t
        for k, v in out["answers"].items():
            if qs[k].type == "choice":
                assert v in choice_values(qs[k]), (t, k, v)
    with pytest.raises(InvalidInput):
        trades.answers(db, CTX, "roofing", estimate_id=house["estimate_id"])


# ---------------------------------------------------------------- electrical and plumbing          C2S12-L01..L04

@pytest.mark.parametrize("words, item", [
    ("USB duplex receptacle", "duplex_receptacle_usb"), ("Smoke/CO detector", "smoke_co_detector"),
    ("Combination smoke and carbon monoxide alarm", "smoke_co_detector"), ("Smoke detector", "smoke_detector"),
    ("Wall sconce", "light_wall"), ("Pendant light", "light_pendant"), ("Dedicated receptacle", "receptacle_dedicated"),
    ("EV charger", "ev_charger"), ("Occupancy sensor switch", "switch_occupancy"), ("Kitchen sink", "kitchen_sink"),
    ("Washer box", "washer_box"), ("Dishwasher", "dishwasher"), ("Gas water heater", "water_heater"),
    ("Tankless water heater", "tankless_water_heater"), ("Gas outlet", "gas_outlet"), ("Tub/shower", "tub_shower"),
    ("Laundry sink", "laundry_sink"), ("Urinal", "urinal"), ("Sink", "sink"), ("Duplex receptacle", "duplex_receptacle")])
def test_legend_words_name_the_new_symbols(words, item):                       # C2S12-L01
    assert legends.item_type(words)[0] == item


def test_every_symbol_feeds_a_real_trade_question():                           # C2S12-L02
    from estimator.modules import get_registry
    reg = get_registry()
    assert lib.VERSION >= 2 and len(lib.STANDARD) >= 60
    assert {e["item_type"] for e in lib.STANDARD} >= set(lib.FEEDS)
    for it in lib.FEEDS:
        for feed in lib.feeds_of(it):                          # Sprint 14: a symbol can answer two questions
            qs = {q.id: q for q in reg.get(feed[0]).questions}
            assert feed[1] in qs, (it, feed)
            if len(feed) == 3:
                assert feed[2] in choice_values(qs[feed[1]]), (it, feed)
            assert lib.module_of_trade(lib.BY_TYPE[it]["trade"]) == feed[0], it   # mechanical symbols price in hvac
    aliases = [a for e in lib.STANDARD for a in e["aliases"]]
    assert len(aliases) == len(set(aliases)), "a short code may name only one symbol"
    assert lib.by_block_name("KITCHENSINK")["item_type"] == "kitchen_sink"
    assert lib.by_block_name("P-DISHWASHER")["item_type"] == "dishwasher"
    assert lib.by_alias("DW")["item_type"] == "dishwasher" and lib.by_alias("USB")["item_type"] == "duplex_receptacle_usb"


def test_electrical_and_plumbing_answers_count_approved_symbols(db, tmp_path):   # C2S12-L03
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("tri", None, "WATER CLOSET"),
                     ("flag", None, "TANKLESS WATER HEATER"), ("quad", None, "SMOKE DETECTOR")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("tri", 12, 5) + \
        shape("flag", 14, 5) + shape("quad", 16, 5)
    est = service.create_estimate(db, CTX, "Bath remodel")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "e.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    dets = sym.detections_list(db, CTX, plan_set_id=ps)["detections"]
    rec = [d["id"] for d in dets if d["item_type"] == "duplex_receptacle"]
    review.review(db, CTX, rec[:2], "approve", confirm=True)
    review.review(db, CTX, [d["id"] for d in dets if d["item_type"] != "duplex_receptacle"], "approve", confirm=True)
    el = trades.answers(db, CTX, "electrical", estimate_id=est["id"])
    assert el["answers"] == {"outlets": 2} and el["waiting"] == {"outlets": 1}
    assert any("smoke detector" in n for n in el["notes"])                   # found, but not an electrical question
    assert trades.answers(db, CTX, "electrical", estimate_id=est["id"], include_proposed=True)["answers"] == {"outlets": 3}
    pl = trades.answers(db, CTX, "plumbing", estimate_id=est["id"])
    assert pl["answers"] == {"toilets": 1, "water_heater": "tankless"} and pl["source"] == "symbols counted on the plans"
    review.review(db, CTX, rec[:1], "reject", confirm=True)                  # taken out: not counted
    assert trades.answers(db, CTX, "electrical", estimate_id=est["id"])["answers"] == {"outlets": 1}


def test_the_mcp_tools(db, house):                                               # C2S12-T01
    import json
    from estimator.mcp_tools import est_tools as t
    j = json.loads
    m = j(t.plan_get_rooms_walls(estimate_id=house["estimate_id"]))
    assert m["totals"]["floor_sqft"] == 234.0 and m["model_key"] == house["model"]["model_key"]
    assert j(t.plan_get_rooms_walls(plan_set_id=house["plan_set_id"], height_ft=9))["totals"]["height_ft"] == 9.0
    one = j(t.plan_trade_answers("drywall", estimate_id=house["estimate_id"]))
    assert one["answers"]["wall_lf"] == 87.0 and one["source"] == "wall-and-room model"
    every = j(t.plan_trade_answers(estimate_id=house["estimate_id"]))
    assert every["trades"]["painting"]["answers"] == building.answers_for(house["model"], "painting")["answers"]
    assert j(t.plan_get_rooms_walls())["error"] == "invalid_input"
    assert j(t.plan_get_rooms_walls(estimate_id=house["estimate_id"], height_ft="tall"))["error"] == "invalid_input"
    assert j(t.plan_trade_answers("roofing", estimate_id=house["estimate_id"]))["error"] == "invalid_input"
    assert j(t.plan_get_rooms_walls(estimate_id=999999))["error"] == "not_found"
    assert {"plan_get_rooms_walls", "plan_trade_answers"} <= {fn.__name__ for fn in t.TOOLS}


def test_all_trades_at_once(db, house):                                          # C2S12-L04
    out = trades.all_answers(db, CTX, estimate_id=house["estimate_id"])
    assert set(out["trades"]) == set(trades.TRADES)
    assert out["trades"]["drywall"]["answers"]["ceiling_sqft"] == out["trades"]["flooring"]["answers"]["area_sqft"]
    assert out["trades"]["electrical"]["answers"] == {} and "approve them in Reviews" in out["trades"]["electrical"]["notes"][-1]

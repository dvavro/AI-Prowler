"""Coder 2 Sprint 11: visual verification of symbol detections (approve, take out, relabel, add, find similar), the
company symbol library, and the learning workflow (a person's corrections are found on the next plan set)."""
import json
from dataclasses import replace

import pytest

from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied
from estimator.estimating import service
from estimator.symbols import library, review
from estimator.symbols import service as sym

from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

CTX = personal_context()


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


def _read(db, tmp_path, pages, name="e.pdf", title="Smith house"):
    est = service.create_estimate(db, CTX, title)
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / name, pages)), confirm=True)["plan_set_id"]
    out = engine.start(db, CTX, ps, confirm=True)
    assert out.get("ok", True), out
    return est["id"], ps


@pytest.fixture
def plans(db, tmp_path):
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + \
        shape("flag", 12, 8) + shape("flag", 14, 8, 30)
    eid, ps = _read(db, tmp_path, [plan(lt, lines)])
    dets = sym.detections_list(db, CTX, plan_set_id=ps)["detections"]
    return {"estimate_id": eid, "plan_set_id": ps, "dets": dets,
            "recept": [d["id"] for d in dets if d["item_type"] == "duplex_receptacle"],
            "flag": [d["id"] for d in dets if d["item_type"] is None]}


def _counts(db, ps):
    return {t["item_type"]: t for t in sym.detections_list(db, CTX, plan_set_id=ps)["counts"]["by_type"]}


# ---------------------------------------------------------------- approve, take out, reset            C2S11-S01..S03

def test_approve_and_take_out_ask_first_and_keep_the_history(db, plans):           # C2S11-S01
    ps, r = plans["plan_set_id"], plans["recept"]
    with pytest.raises(ConfirmationRequired) as ask:
        review.review(db, CTX, r[:2], "approve")
    assert "Approve 2 symbol(s)" in ask.value.message and ask.value.details["by_type"] == {"duplex_receptacle": 2}
    review.review(db, CTX, r[:2], "approve", confirm=True)
    review.review(db, CTX, [r[2]], "reject", confirm=True)
    c = _counts(db, ps)["duplex_receptacle"]
    assert (c["count"], c["approved"], c["rejected"], c["proposed"]) == (2, 2, 1, 0)
    out = {d["id"]: d for d in sym.detections_list(db, CTX, plan_set_id=ps)["detections"]}
    assert out[r[2]]["status"] == "rejected" and out[r[2]]["original"]["status"] == "proposed"
    assert out[r[0]]["reviewed_by"] and out[r[0]]["needs_review"] is False
    review.review(db, CTX, [r[2]], "reset", confirm=True)
    assert _counts(db, ps)["duplex_receptacle"]["count"] == 3
    log = db.execute("SELECT COUNT(*) FROM activity_log WHERE action = 'symbols_reviewed'").fetchone()[0] \
        if db.execute("SELECT name FROM sqlite_master WHERE name = 'activity_log'").fetchone() else 3
    assert log >= 3


def test_relabel_all_matches_and_learn(db, plans):                                  # C2S11-S02
    ps = plans["plan_set_id"]
    with pytest.raises(ConfirmationRequired) as ask:
        review.review(db, CTX, plans["flag"][:1], "relabel", item_type="floor box", apply_to_matches=True)
    assert ask.value.details["detections"] == 2 and ask.value.details["item_type"] == "floor_box"
    out = review.review(db, CTX, plans["flag"][:1], "relabel", item_type="floor_box", apply_to_matches=True, confirm=True)
    assert out["changed"] == 2 and out["learned_definition_id"]
    c = _counts(db, ps)
    assert None not in c and c["floor_box"]["count"] == 2 and c["floor_box"]["approved"] == 2
    d = next(x for x in sym.detections_list(db, CTX, plan_set_id=ps)["detections"] if x["item_type"] == "floor_box")
    assert d["original"]["item_type"] is None and d["trade"] == "electrical" and d["label"] == "Floor box"
    lib = library.list_library(db, CTX, level="company")["libraries"][0]
    fb = lib["by_trade"]["electrical"][0]
    assert (fb["item_type"], fb["examples"], fb["status"]) == ("floor_box", 2, "approved")
    ex = db.execute("SELECT template_json FROM symbol_examples WHERE definition_id = ?", (fb["id"],)).fetchone()
    assert len(json.loads(ex["template_json"])["segs"]) == 3                       # the flag's three strokes


def test_who_can_review(db, plans):                                                # C2S11-S03
    # Field crews look only; office (the Jobs app's managers and staff) approve too (David, 2026-11-09).
    with pytest.raises(PermissionDenied):
        review.review(db, replace(CTX, role="field"), plans["recept"], "approve", confirm=True)
    office = replace(CTX, role="office")
    assert review.review(db, office, plans["recept"][1:2], "approve", confirm=True)["changed"] == 1
    agent = replace(CTX, role="estimator", agent="takeoff")
    with pytest.raises(PermissionDenied, match="agent"):
        review.review(db, agent, plans["recept"], "approve", confirm=True)
    reviewer = replace(CTX, role="reviewer")
    assert review.review(db, reviewer, plans["recept"][:1], "approve", confirm=True)["changed"] == 1
    with pytest.raises(InvalidInput):
        review.review(db, CTX, plans["recept"], "explode", confirm=True)
    with pytest.raises(InvalidInput):
        review.review(db, CTX, plans["recept"], "relabel", confirm=True)
    with pytest.raises(InvalidInput):
        review.review(db, CTX, [], "approve", confirm=True)


# ---------------------------------------------------------------- add a missed one, find similar       C2S11-S04..S05

def test_add_a_missed_symbol(db, plans, tmp_path):                                  # C2S11-S04
    ps = plans["plan_set_id"]
    sheet = store.sheets(db, CTX, ps)["sheets"][0]
    with pytest.raises(ConfirmationRequired):
        review.review(db, CTX, action="add", sheet_id=sheet["id"], point=[16, 5], item_type="duplex_receptacle")
    out = review.review(db, CTX, action="add", sheet_id=sheet["id"], point=[16, 5], item_type="duplex_receptacle",
                        confirm=True)
    d = next(x for x in sym.detections_list(db, CTX, plan_set_id=ps)["detections"] if x["id"] == out["detection_id"])
    assert (d["origin"], d["status"], d["method"], d["point"]) == ("manual", "approved", "manual", [16, 5])
    assert _counts(db, ps)["duplex_receptacle"]["count"] == 4
    with pytest.raises(InvalidInput):
        review.review(db, CTX, action="add", sheet_id=sheet["id"], point=[999, 5], item_type="duplex_receptacle",
                      confirm=True)


def test_find_similar_adds_the_ones_not_found_yet(db, tmp_path):                    # C2S11-S05
    # No legend: a person boxes one triangle and asks for more like it.
    lines = shape("tri", 5, 5) + shape("tri", 7, 5, 90) + shape("tri", 9, 6, 200) + shape("recept", 11, 5)
    _eid, ps = _read(db, tmp_path, [plan([], lines), plan([], shape("tri", 4, 4), sheet_no="E-102", title="POWER 2")])
    sheet = store.sheets(db, CTX, ps)["sheets"][0]
    box = [4.85, 4.85, 5.15, 5.15]
    with pytest.raises(ConfirmationRequired) as ask:
        review.find_similar(db, CTX, sheet_id=sheet["id"], box=box, item_type="thermostat")
    assert ask.value.details["found"] == 4 and ask.value.details["by_page"] == {"1": 3, "2": 1}
    out = review.find_similar(db, CTX, sheet_id=sheet["id"], box=box, item_type="thermostat", confirm=True)
    assert out["added"] == 4
    c = _counts(db, ps)["thermostat"]
    assert c["count"] == 4 and c["proposed"] == 4 and c["needs_review"] == 4
    # again from one of them: nothing new
    first = sym.detections_list(db, CTX, plan_set_id=ps)["detections"][0]
    with pytest.raises(ConfirmationRequired) as again:
        review.find_similar(db, CTX, detection_id=first["id"])
    assert again.value.details["found"] == 0
    with pytest.raises(InvalidInput, match="no line work"):
        review.find_similar(db, CTX, sheet_id=sheet["id"], box=[20, 20, 20.3, 20.3], item_type="thermostat")


# ---------------------------------------------------------------- learning: found on the next plan set   C2S11-S06

def test_a_relabelled_symbol_is_found_on_the_next_plan_set(db, plans, tmp_path):    # C2S11-S06
    review.review(db, CTX, plans["flag"][:1], "relabel", item_type="floor_box", apply_to_matches=True, confirm=True)
    # A new job from the same architect: no legend at all, two flags (one turned).
    _eid2, ps2 = _read(db, tmp_path, [plan([], shape("flag", 6, 6) + shape("flag", 9, 6, 90) + shape("recept", 12, 6))],
                       name="next.pdf", title="Jones house")
    d = sym.detections_list(db, CTX, plan_set_id=ps2)
    assert {t["item_type"]: t["count"] for t in d["counts"]["by_type"]} == {"floor_box": 2}
    assert all(x["origin"] == "library" and x["definition_from"] == "company library" for x in d["detections"])
    assert all(x["status"] == "proposed" for x in d["detections"])                 # still a proposal


def test_the_plan_sets_legend_wins_over_the_company_library(db, plans, tmp_path):   # C2S11-S07
    review.review(db, CTX, plans["flag"][:1], "relabel", item_type="floor_box", apply_to_matches=True, confirm=True)
    lt, ll = legend([("flag", None, "THERMOSTAT")])
    _e, ps2 = _read(db, tmp_path, [plan(lt, ll + shape("flag", 6, 6))], name="other.pdf", title="Lee house")
    d = sym.detections_list(db, CTX, plan_set_id=ps2)["detections"]
    assert [x["item_type"] for x in d] == ["thermostat"] and d[0]["definition_from"] == "plan-set legend"


# ---------------------------------------------------------------- the library                           C2S11-S08..S10

def test_library_list_has_standard_and_company(db, plans):                          # C2S11-S08
    out = library.list_library(db, CTX)
    levels = [lb["level"] for lb in out["libraries"]]
    assert levels == ["company", "standard"] and out["can_define"] is True
    std = out["libraries"][1]
    assert std["count"] >= 37 and "electrical" in std["by_trade"]
    rec = next(d for d in std["by_trade"]["electrical"] if d["item_type"] == "duplex_receptacle_gfci")
    assert "GFI" in rec["aliases"]
    assert library.list_library(db, CTX, level="standard", trade="plumbing")["libraries"][0]["by_trade"].keys() == {"plumbing"}
    with pytest.raises(InvalidInput):
        library.list_library(db, CTX, level="cosmic")


def test_define_and_version_a_company_symbol(db, plans):                            # C2S11-S09
    with pytest.raises(ConfirmationRequired):
        library.define(db, CTX, "floor_box", description="Floor box, flush", trade="electrical", code="FB",
                       from_detection_ids=plans["flag"])
    out = library.define(db, CTX, "floor_box", description="Floor box, flush", trade="electrical", code="FB",
                         from_detection_ids=plans["flag"], confirm=True)["definition"]
    assert (out["version"], out["examples"], out["code"], out["aliases"]) == (1, 2, "FB", ["FB"])
    v2 = library.define(db, CTX, "floor_box", description="Floor box", definition_id=out["id"], assembly_id="elec_device",
                        confirm=True)["definition"]
    assert (v2["version"], v2["assembly_id"], v2["description"]) == (2, "elec_device", "Floor box")
    with pytest.raises(InvalidInput, match="already has"):
        library.define(db, CTX, "floor_box", confirm=True)
    std_id = library.ensure_standard(db, CTX.company_id)["switch"]
    with pytest.raises(InvalidInput, match="standard library"):
        library.define(db, CTX, "switch", definition_id=std_id, confirm=True)
    with pytest.raises(InvalidInput):
        library.define(db, CTX, "Floor Box!!", confirm=True)
    with pytest.raises(InvalidInput):
        library.define(db, CTX, "floor_plate", trade="spaceship", confirm=True)
    with pytest.raises(PermissionDenied):
        library.define(db, replace(CTX, role="field"), "floor_plate", confirm=True)


def test_export_and_import_the_company_library(db, plans):                          # C2S11-S10
    library.define(db, CTX, "floor_box", trade="electrical", from_detection_ids=plans["flag"], confirm=True)
    data = library.export_library(db, CTX)
    assert data["definitions"][0]["item_type"] == "floor_box" and len(data["definitions"][0]["examples"]) == 2
    other = replace(CTX, company_id="acme")
    with pytest.raises(ConfirmationRequired):
        library.import_library(db, other, data)
    assert library.import_library(db, other, data, confirm=True)["imported"] == 1
    assert len(library.engine_templates(db, "acme")) == 2
    with pytest.raises(InvalidInput):
        library.import_library(db, other, {"format": "something else"}, confirm=True)


def test_same_firm_plan_pair_the_second_set_is_counted_from_what_was_learned(db, plans, tmp_path):   # C2S11-S13
    """Tester 2's learning test: a person checks the first plan set from an architect (approves the receptacles, names
    the unknown special devices floor boxes); the firm's next plan set has no legend at all, a different layout, two
    sheets, the symbols turned, mirrored and 5% bigger, a wall through a receptacle, and look-alikes that must not be
    counted. Every learned symbol is found (recall) and nothing else is (precision)."""
    review.review(db, CTX, plans["recept"], "approve", confirm=True)
    review.review(db, CTX, plans["flag"][:1], "relabel", item_type="floor_box", apply_to_matches=True, confirm=True)
    wall = [(2, 6, 20, 6)]                                                # a wall line through the receptacle at (9, 6)
    p1 = (shape("flag", 4, 4) + shape("flag", 8, 4, 90) + shape("flag", 12, 4, mirror=True) +
          shape("recept", 5, 6) + shape("recept", 9, 6) + wall +
          shape("tri", 15, 9) + shape("quad", 17, 9))                      # not learned / a receptacle with an extra bar
    p2 = shape("flag", 6, 12, 200, s=1.05) + shape("recept", 10, 12, 45, s=1.05) + shape("tri", 14, 12)
    _e, ps2 = _read(db, tmp_path, [plan([], p1), plan([], p2, sheet_no="E-102", title="POWER PLAN 2")],
                    name="firm2.pdf", title="Same architect, next job")
    d = sym.detections_list(db, CTX, plan_set_id=ps2)
    found = {t["item_type"]: t["count"] for t in d["counts"]["by_type"]}
    assert found == {"floor_box": 4, "duplex_receptacle": 3}                # 100% recall, nothing extra
    assert {s["sheet_no"]: s["count"] for s in d["counts"]["by_sheet"]} == {"E-101": 5, "E-102": 2}
    assert all(x["origin"] == "library" and x["status"] == "proposed" for x in d["detections"])
    near = lambda x, y: any(abs(q["point"][0] - x) < 0.15 and abs(q["point"][1] - y) < 0.15 for q in d["detections"])
    assert near(9, 6) and not near(17, 9) and not near(15, 9) and not near(14, 12)


def test_a_broken_library_never_stops_the_plans_being_read(db, tmp_path, monkeypatch):   # C2S11-S12
    def boom(conn, company_id):
        raise RuntimeError("bad library row")
    monkeypatch.setattr(library, "engine_templates", boom)
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    _e, ps = _read(db, tmp_path, [plan(lt, ll + shape("recept", 5, 5))], name="b.pdf", title="Broken library")
    assert _counts(db, ps)["duplex_receptacle"]["count"] == 1                    # read with the legend alone


def test_thumbnail_of_a_detection(db, plans, tmp_path):                             # C2S11-S11
    p = review.crop_png(db, CTX, plans["recept"][0], tmp_path / "data")
    from PIL import Image
    with Image.open(p) as img:
        assert 4 <= img.size[0] <= 160 and 4 <= img.size[1] <= 160
    assert review.crop_png(db, CTX, plans["recept"][0], tmp_path / "data") == p      # cached

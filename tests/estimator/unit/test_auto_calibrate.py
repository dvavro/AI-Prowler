"""Auto calibrator (2026-11-13, David): calibrate a view from its written dimensions, or say a person must.

A fake provider stands in for Claude: no real API calls. The sheet is 17 x 11 in, its picture 1700 x 1100 px
(100 px an inch), and the slab is drawn at the live plan's scale, 1 paper inch = 84.3225 real inches: 45'-7" is
6.487 in across, 46'-7" is 6.629 in down.
"""
import json

import pytest

from estimator.agents import providers, roles
from estimator.context import personal_context
from estimator.drawing_model import store
from estimator.errors import ConfirmationRequired
from estimator.estimating import service
from estimator.takeoff import auto_calibrate as ac

CTX = personal_context()
NOW = "2026-11-13T10:00:00+00:00"
RATIO = 84.3225
W_IN, L_IN = 547 / RATIO, 559 / RATIO          # 45'-7" and 46'-7" on paper
H1, H2 = (2.0, 8.5), (2.0 + W_IN, 8.5)         # the horizontal dimension's ends (inches)
V1, V2 = (12.0, 1.0), (12.0, 1.0 + L_IN)       # the vertical one's


class Fake:
    def __init__(self):
        self.replies, self.calls = [], []

    def ready(self, provider):
        return True, ""

    def model_for(self, provider):
        return {"claude_api": "claude-opus-5-5", "grok_api": "grok-4.3"}[provider]

    def light_model(self):
        return "claude-haiku-5-5"

    def ask_vision(self, provider, system, user, images, model=""):
        self.calls.append({"user": user, "model": model, "system": system})
        r = self.replies.pop(0) if self.replies else "{}"
        return (r if isinstance(r, str) else json.dumps(r)), {"input": 1500, "output": 80}

    def cost(self, model, usage):
        return 0.001


@pytest.fixture
def fake():
    f = Fake()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


@pytest.fixture
def sheet(db, tmp_path):
    from PIL import Image
    img = tmp_path / "s.png"
    Image.new("RGB", (1700, 1100), "white").save(img)
    est = service.create_estimate(db, CTX, "Shed slab")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size,"
                    " sha256, status, uploaded_by, created_at) VALUES ('default', ?, 'x.png', 'x.png', 'image', 1,"
                    " 'aa', 'processed', 'owner', ?)", (est, NOW)).lastrowid
    sid = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, units, width, height,"
                     " image_path) VALUES ('default', ?, 1, 'S-1', 'FOUNDATION PLAN', 'paper_in', '17', '11', ?)",
                     (ps, str(img))).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, bbox_json, scale_note, scale_method, is_nts)"
                    " VALUES ('default', ?, 'FOUNDATION PLAN', '[0.25, 0.25, 15.1, 10.75]', 'NTS', 'note', 0)",
                    (sid,)).lastrowid
    return {"est": est, "sheet": sid, "vp": vp}


def _ai_on(db):
    roles.update_role(db, CTX, "llm_takeoff", {"provider": "claude_api"}, confirm=True)


def _px(p):
    return [round(p[0] * 100), round(p[1] * 100)]


def _pin_centre():
    return {"x": 60, "y": 60}                          # a 1.2" close-up is 120 px: its middle is the end itself


def _found(*dims):
    return {"dimensions": [{"text": t, "end1": _px(a), "end2": _px(b)} for t, a, b in dims], "notes": "two found"}


def _vp(db, vp):
    return store._vp_out(store._load_viewport(db, CTX, vp))


# ---------------------------------------------------------------- the AI reads the written dimensions

def test_ai_calibrates_from_two_dimensions_that_agree(db, fake, sheet):                         # AC-01
    _ai_on(db)
    fake.replies = [_found(("45'-7\"", H1, H2), ("46'-7\"", V1, V2))] + [_pin_centre()] * 4
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "calibrated" and got["method"] == "ai"
    assert abs(float(got["scale_ratio"]) - RATIO) < 0.05
    assert got["used"]["label"] == "46'-7\""                                     # the longer line calibrates
    assert got["check"][0]["label"] == "45'-7\"" and got["check"][0]["off_pct"] < 0.5
    v = _vp(db, sheet["vp"])
    assert v["measurable"] and v["scale_method"] == "calibration" and v["scale_set_by"] == "auto-calibrator"
    assert v["auto_calibration"]["status"] == "calibrated"
    assert len(fake.calls) == 5                                                  # find + 2 ends x 2 dimensions
    assert {c["model"] for c in fake.calls} == {"claude-opus-5-5"}              # complex steps: the strong model
    logged = db.execute("SELECT COUNT(*) FROM ai_log WHERE role = 'llm_takeoff'").fetchone()[0]
    assert logged == 5


def test_a_close_up_corrects_a_rough_end(db, fake, sheet):                                       # AC-02
    _ai_on(db)
    off = (V2[0], V2[1] - 0.1)                                                   # the sheet-wide read is 0.1" short
    fake.replies = [_found(("46'-7\"", V1, off), ("45'-7\"", H1, H2)),
                    _pin_centre(), {"x": 60, "y": 70},                         # 10 px = 0.1" lower: the true end
                    _pin_centre(), _pin_centre()]
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "calibrated" and abs(float(got["scale_ratio"]) - RATIO) < 0.05


def test_dimensions_that_disagree_need_a_person(db, fake, sheet):                                # AC-03
    _ai_on(db)
    fake.replies = [_found(("45'-7\"", H1, H2), ("30'-0\"", V1, V2))] + [_pin_centre()] * 4
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "manual_required" and "don't agree" in got["reason"]
    assert "Calibrate" in got["how"]
    v = _vp(db, sheet["vp"])
    assert not v["measurable"] and v["auto_calibration"]["status"] == "manual_required"


def test_no_written_dimensions_needs_a_person(db, fake, sheet):                                  # AC-04
    _ai_on(db)
    fake.replies = [{"dimensions": [], "notes": "only notes and a section mark"}]
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "manual_required"
    assert got["reason"].startswith("No written dimensions were found in FOUNDATION PLAN")
    assert "only notes" in got["reason"] and len(fake.calls) == 1


def test_one_dimension_alone_is_used_but_marked_unchecked(db, fake, sheet):                      # AC-05
    _ai_on(db)
    fake.replies = [_found(("45'-7\"", H1, H2)), _pin_centre(), _pin_centre()]
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "calibrated_unchecked" and "couldn't be cross-checked" in got["reason"]
    assert abs(float(got["scale_ratio"]) - RATIO) / RATIO < 0.002     # whole pixels at 100 px an inch: ~0.1%


def test_ai_off_and_no_drawn_dimensions_needs_a_person_without_calling(db, fake, sheet):         # AC-06
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "manual_required" and "AI takeoff is off" in got["reason"]
    assert fake.calls == []


def test_unreadable_ai_answer_needs_a_person(db, fake, sheet):                                   # AC-07
    _ai_on(db)
    fake.replies = ["I can't see any dimensions, sorry"]
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "manual_required" and "couldn't read the plan" in got["reason"]


# ---------------------------------------------------------------- the drawing's own lines (no AI, no cost)

def _dim_obj(db, sheet, label, a, b):
    db.execute("INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, label, geometry_json, source)"
               " VALUES ('default', ?, ?, 'dimension', ?, ?, 'vector')",
               (sheet["sheet"], sheet["vp"], label, json.dumps({"type": "line", "points": [list(a), list(b)]})))


def test_two_drawn_dimensions_that_agree_calibrate_without_the_ai(db, fake, sheet):              # AC-08
    _ai_on(db)
    _dim_obj(db, sheet, "45'-7\"", H1, H2)
    _dim_obj(db, sheet, "46'-7\"", V1, V2)
    got = ac.auto_calibrate(db, CTX, sheet["vp"])
    assert got["status"] == "calibrated" and got["method"] == "drawing" and fake.calls == []
    assert abs(float(got["scale_ratio"]) - RATIO) < 0.01


def test_a_line_with_two_lengths_is_not_trusted(db, fake, sheet):                                # AC-09
    _dim_obj(db, sheet, "45'-7\"", H1, H2)
    _dim_obj(db, sheet, "6\"", H1, H2)                     # the same line also carries 6" (a mis-paired label)
    _dim_obj(db, sheet, "46'-7\"", V1, V2)
    assert [d["label"] for d in ac.vector_dimensions(db, "default", dict(store._load_viewport(db, CTX, sheet["vp"])))] \
        == ["46'-7\""]
    got = ac.auto_calibrate(db, CTX, sheet["vp"])        # one left, AI off: a person must
    assert got["status"] == "manual_required" and "1 written dimension" in got["reason"]


# ---------------------------------------------------------------- asking first, and a person's own calibration

def test_replacing_a_scale_asks_first(db, fake, sheet):                                          # AC-10
    store.set_scale(db, CTX, sheet["vp"], scale_ratio="48", confirm=True)
    with pytest.raises(ConfirmationRequired, match="already has a scale"):
        ac.auto_calibrate(db, CTX, sheet["vp"])
    _dim_obj(db, sheet, "45'-7\"", H1, H2)
    _dim_obj(db, sheet, "46'-7\"", V1, V2)
    assert ac.auto_calibrate(db, CTX, sheet["vp"], confirm=True)["status"] == "calibrated"


def test_a_hand_calibration_clears_the_manual_flag(db, fake, sheet):                             # AC-11
    assert ac.auto_calibrate(db, CTX, sheet["vp"])["status"] == "manual_required"
    store.set_scale(db, CTX, sheet["vp"], calibration={"p1": list(H1), "p2": list(H2), "distance": "45'-7\""},
                    confirm=True)
    v = _vp(db, sheet["vp"])
    assert v["auto_calibration"] is None and v["scale_set_by"] == "owner"


def test_snap_moves_an_end_onto_its_extension_line():                                            # AC-12
    segs = [((2.03, 8.0), (2.03, 9.0)), ((5.0, 8.0), (5.0, 9.0))]                # extension lines
    assert ac.snap([2.0, 8.5], [8.5, 8.5], segs) == ([2.03, 8.5], True)
    assert ac.snap([2.0, 8.5], [8.5, 8.5], [((2.2, 8.0), (2.2, 9.0))]) == ([2.0, 8.5], False)   # too far


def test_models_follow_the_step_groups(fake):                                                    # AC-13
    assert providers.model_for_step("claude_api", "llm_takeoff", "read") == "claude-opus-5-5"
    assert providers.model_for_step("claude_api", "llm_takeoff", "classify") == "claude-haiku-5-5"
    assert providers.model_for_step("claude_api", "auto_calibrate", "pinpoint") == "claude-opus-5-5"
    assert providers.model_for_step("claude_api", "reviewer") == "claude-haiku-5-5"
    assert providers.model_for_step("claude_api", "bid_writer") == "claude-opus-5-5"      # a customer message
    assert providers.model_for_step("grok_api", "llm_takeoff", "classify") == "grok-4.3"
    assert providers.model_for_step("claude_api", "something_new") == "claude-opus-5-5"   # unknown: the safe side

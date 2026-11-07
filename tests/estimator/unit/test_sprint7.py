"""Sprint 7: construction trades from measurements and the Director's standard lane (S7-..)."""
import pytest

from estimator.context import RequestContext, personal_context
from estimator.director import briefing, engine
from estimator.director.settings import get_settings, update_settings
from estimator.director.triage import triage
from estimator.errors import InvalidInput, NotEditable, PermissionDenied
from estimator.estimating import service, validate
from estimator.modules.registry import ManifestError, ModuleRegistry, load_module
from estimator.pricing.price_book import set_price

CTX = personal_context()
REG = ModuleRegistry().load()
ESTIMATOR = RequestContext(role="estimator", user_id="ed", mode="server")
REVIEWER = RequestContext(role="reviewer", user_id="rita", mode="server")
OFFICE = RequestContext(role="office", user_id="sue", mode="server")
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


def _start(db, text, ctx=CTX, **kw):
    return engine.start(db, ctx, text, registry=REG, **kw)


def _next(db, r, ctx=CTX, **kw):
    return engine.next_step(db, ctx, r["job"]["id"], registry=REG, **kw)


# ---------------------------------------------------------------- modules

def test_construction_modules_load():  # S7-M01
    mods = {m.id: m for m in REG.list() if m.category == "construction"}
    assert {"concrete", "flooring", "roofing"} <= set(mods) and not REG.errors
    assert all(m.path == "both" for m in mods.values())
    assert any("Hot weather" in n for n in mods["concrete"].notes) and mods["roofing"].notes
    assert mods["roofing"].question("pitch").required and mods["flooring"].question("material").required


def test_bad_notes_rejected(tmp_path):  # S7-M02
    import shutil
    dst = tmp_path / "construction" / "concrete"
    shutil.copytree(REG.get("concrete").folder, dst)
    mf = dst / "manifest.yaml"
    mf.write_text(mf.read_text(encoding="utf-8").replace('notes:\n  - "Hot', 'notes: "Hot'), encoding="utf-8")
    with pytest.raises((ManifestError, Exception)):
        load_module(dst)


# ---------------------------------------------------------------- triage

@pytest.mark.parametrize("text, lane, module", [
    ("re-roof the house with tile", "standard_estimate", "roofing"),
    ("replace the roof", "standard_estimate", "roofing"),
    ("new LVP in the kitchen and hall", "standard_estimate", "flooring"),
    ("install carpet in 3 bedrooms", "standard_estimate", "flooring"),
    ("pour a patio slab out back", "standard_estimate", "concrete"),
    ("stamped concrete patio", "standard_estimate", "concrete"),
    ("soft wash the roof please", "quick_quote", "pressure_washing"),
    ("pressure wash the concrete patio", "quick_quote", "pressure_washing"),
    ("install a new fence", "standard_estimate", "fencing"),
])
def test_triage_construction(text, lane, module):  # S7-T01
    r = triage(text, REG)
    assert (r.lane, r.module_id) == (lane, module), r.as_dict()


def test_triage_module_choice_and_plans():  # S7-T02
    assert triage("", REG, module_id="roofing").lane == "standard_estimate"
    r = triage("bid it", REG, module_id="concrete", has_plans=True)
    assert r.lane == "full_takeoff" and r.module_id == "concrete"


# ---------------------------------------------------------------- standard lane

def test_roof_job_start_to_reviewed_and_approved(db):  # S7-D01
    r = _start(db, "replace the roof on the Smith house", answers={"roof_area_sqft": 2000})
    assert r["job"]["lane"] == "standard_estimate" and r["job"]["stage"] == "collect_job"
    assert set(r["job"]["open_questions"]) == {"pitch", "material"} and "Roofing estimate" in r["next_step"]["say"]
    r = _next(db, r, answers={"pitch": "5/12", "material": "architectural"})
    assert r["job"]["stage"] == "review" and r["job"]["waiting_on"] == "reviewer"
    assert r["estimate"]["total_cents"] == 781710 and r["estimate"]["status"] == "in_review"
    codes = {f["code"] for f in r["next_step"]["findings"]}
    assert {"sample_prices", "low_margin", "module_note"} <= codes
    assert "over the review limit of $500.00" in r["next_step"]["say"]
    r = _next(db, r, reviewed=True, approve=True, confirm_sample_prices=True)    # owner: review + approve
    assert r["estimate"]["status"] == "approved" and r["job"]["stage"] == "write_bid"
    steps = [s["stage"] for s in engine.status(db, CTX, r["job"]["id"])["steps"]]
    assert steps[:4] == ["triage", "collect_job", "price", "review"] and "approve" in steps


def test_review_roles(db):  # S7-D02
    r = _start(db, "replace the roof", ESTIMATOR, answers=ROOF)
    assert r["job"]["stage"] == "review"
    with pytest.raises(PermissionDenied, match="sign off"):
        _next(db, r, ESTIMATOR, reviewed=True)
    r = _next(db, r, REVIEWER, reviewed=True)
    assert r["job"]["stage"] == "approve" and "checked and ready" in r["next_step"]["say"]
    with pytest.raises(PermissionDenied, match="owner or reviewer"):
        _next(db, r, ESTIMATOR, approve=True, confirm_sample_prices=True)
    r = _next(db, r, REVIEWER, approve=True, confirm_sample_prices=True)
    assert r["estimate"]["status"] == "approved"


def test_small_job_checked_automatically(db):  # S7-D03
    update_settings(db, CTX, {"review_required_over_cents": 2_000_000})
    r = _start(db, "pour a patio slab", answers={"area_sqft": 400})
    assert r["job"]["stage"] == "approve" and r["estimate"]["status"] == "draft"
    assert any("Hot weather" in n for n in r["notes"]) and any("sample" in n for n in r["notes"])
    review = [s for s in engine.status(db, CTX, r["job"]["id"])["steps"] if s["stage"] == "review"][0]
    assert "automatic check" in review["input_summary"]


def test_review_limit_zero_reviews_everything(db):  # S7-D04
    update_settings(db, CTX, {"review_required_over_cents": 0})
    r = _start(db, "new LVP flooring", answers={"area_sqft": 100, "material": "lvp"})
    assert r["job"]["stage"] == "review" and r["job"]["waiting_on"] == "reviewer"


def test_changed_answers_go_back_and_recheck(db):  # S7-D05
    r = _start(db, "replace the roof", answers=ROOF)
    assert r["job"]["stage"] == "review"
    r = _next(db, r, answers={"material": "metal"})
    assert r["job"]["stage"] == "review" and r["estimate"]["total_cents"] > 781710
    r = _next(db, r, reviewed=True, approve=True, confirm_sample_prices=True)
    with pytest.raises(NotEditable, match="revise=true"):
        _next(db, r, answers={"layers": 2})


def test_trade_without_module_then_module_chosen(db):  # S7-D06 (updated Sprint 13: fencing turned off)
    no_fence = ModuleRegistry().load()
    no_fence.modules.pop("fencing")
    r = engine.start(db, CTX, "install a new fence", registry=no_fence)
    assert r["job"]["state"] == "waiting_on_feature" and r["job"]["module_id"] is None
    r = engine.next_step(db, CTX, r["job"]["id"], module_id="concrete", registry=no_fence)
    assert r["job"]["lane"] == "standard_estimate" and r["job"]["module_id"] == "concrete"
    assert r["job"]["open_questions"] == ["area_sqft"]


def test_change_lane_quick_to_standard_keeps_everything(db):  # S7-D07
    r = _start(db, "pressure wash my driveway", answers={"driveway_sqft": 6000}, customer={"email": "a@b.com"})
    assert r["job"]["lane"] == "quick_quote" and r["job"]["stage"] == "approve"
    est_id, total = r["estimate"]["id"], r["estimate"]["total_cents"]
    r = engine.change_lane(db, CTX, r["job"]["id"], "standard_estimate", reason="commercial lot", registry=REG)
    assert r["job"]["lane"] == "standard_estimate" and r["estimate"]["id"] == est_id
    assert r["estimate"]["total_cents"] == total and r["job"]["answers"]["driveway_sqft"] == 6000
    assert r["job"]["stage"] == "review"                 # $1,035 is over the $500 review limit
    steps = engine.status(db, CTX, r["job"]["id"])["steps"]
    assert any(s["stage"] == "change_lane" and "commercial lot" in s["input_summary"] for s in steps)


def test_change_lane_rules(db):  # S7-D08
    r = _start(db, "replace the roof", answers=ROOF)
    with pytest.raises(InvalidInput, match="can't be a quick quote"):
        engine.change_lane(db, CTX, r["job"]["id"], "quick_quote", registry=REG)
    with pytest.raises(InvalidInput, match="lane must be one of"):
        engine.change_lane(db, CTX, r["job"]["id"], "moon", registry=REG)
    r = _next(db, r, reviewed=True, approve=True, confirm_sample_prices=True)
    with pytest.raises(NotEditable, match="revision"):
        engine.change_lane(db, CTX, r["job"]["id"], "quick_quote", module_id="pressure_washing", registry=REG)


def test_office_starts_construction_job_in_customer_voice(db):  # S7-D09
    r = _start(db, "customer wants new carpet", OFFICE)
    assert r["job"]["module_id"] == "flooring" and r["next_step"]["say"].startswith("Ask the customer")


# ---------------------------------------------------------------- est_validate

def test_validate_findings(db):  # S7-V01
    e = service.create_estimate(db, CTX, "empty")
    out = validate.validate(db, CTX, e["id"], registry=REG)
    assert not out["passed"] and out["findings"][0]["code"] == "no_lines"
    r = _start(db, "pour a patio slab", answers={"area_sqft": 40})
    out = validate.validate(db, CTX, r["estimate"]["id"], registry=REG)
    codes = {f["code"] for f in out["findings"]}
    assert out["passed"] and {"minimum_applied", "sample_prices", "module_note"} <= codes and "low_margin" not in codes


def test_validate_outlier_and_margin(db):  # S7-V02
    set_price(db, "default", "cc_concrete_cy", description="Concrete", kind="material", unit="cuyd",
              cost_cents=100000)
    service.save_markups(db, CTX, overhead_pct="0.10", profit_pct="0.15")
    e = service.create_estimate(db, CTX, "slab")
    from estimator.estimating import quick
    e = quick.answer(db, CTX, e["id"], "concrete", {"area_sqft": 400}, e["rev"], REG)
    out = validate.validate(db, CTX, e["id"], registry=REG)
    codes = [f["code"] for f in out["findings"]]
    assert "unit_cost_outlier" in codes and "low_margin" not in codes


def test_review_blocks_when_nothing_to_price(db, monkeypatch):  # S7-V03
    r = _start(db, "replace the roof", answers=ROOF)
    real = validate.validate

    def broken(conn, ctx, eid, registry=None):
        out = real(conn, ctx, eid, registry)
        out["passed"] = False
        out["findings"].insert(0, {"level": "error", "code": "no_lines", "message": "The estimate has no line items yet."})
        return out
    monkeypatch.setattr(validate, "validate", broken)
    r = _next(db, r, reviewed=True)
    assert r["next_step"]["error"] == "review_failed" and "can't be approved yet" in r["next_step"]["say"]


# ---------------------------------------------------------------- settings and briefing

def test_review_limit_setting(db):  # S7-S01
    assert get_settings(db, "default")["review_required_over_cents"] == 50000
    assert update_settings(db, CTX, {"review_required_over_cents": "125000"})["settings"]["review_required_over_cents"] == 125000
    with pytest.raises(InvalidInput):
        update_settings(db, CTX, {"review_required_over_cents": -1})


def test_briefing_counts_reviews(db):  # S7-B01
    _start(db, "replace the roof", answers=ROOF)
    out = briefing.briefing(db, CTX)
    assert out["counts"]["awaiting_review"] == 1 and "waiting for a reviewer" in out["text"]

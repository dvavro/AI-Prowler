"""Sprint 2: quick-estimate engine and golden cases (S2-Q01..).

Golden cases live with each module in tests/golden.yaml, so a module author
adds cases next to the manifest and this test picks them up automatically.
"""
import pytest
import yaml

from estimator.context import personal_context
from estimator.errors import InvalidInput, NotFound
from estimator.estimating import quick, service
from estimator.modules.registry import ModuleRegistry
from estimator.pricing.price_book import get_price, set_price

CTX = personal_context()
REG = ModuleRegistry().load()


def _golden():
    for mod in REG.list():
        f = mod.folder / "tests" / "golden.yaml"
        if f.exists():
            for case in yaml.safe_load(f.read_text(encoding="utf-8")) or []:
                yield pytest.param(mod.id, case, id=f"{mod.id}: {case['name']}")


def _answer(db, module_id, answers):
    e = service.create_estimate(db, CTX, "golden")
    return quick.answer(db, CTX, e["id"], module_id, answers, e["rev"], REG)


@pytest.mark.parametrize("module_id, case", list(_golden()))
def test_golden_cases(db, module_id, case):  # S2-Q01
    e = _answer(db, module_id, case["answers"])
    totals = e["totals"]
    assert totals["total_cents"] == case["expected_total_cents"]
    if "expected_subtotal_cents" in case:
        assert totals["subtotal_cents"] == case["expected_subtotal_cents"]
    if "expected_lines" in case:
        got = {ln["calc"]["rule"]: ln["total_cents"] for ln in e["sections"][0]["lines"]}
        assert got == case["expected_lines"]


def test_every_shipped_module_has_golden_cases():  # S2-Q02
    for mod in REG.list():
        if mod.path in ("quick_estimate", "both"):
            assert (mod.folder / "tests" / "golden.yaml").exists(), mod.id


def test_questions_list(db):  # S2-Q03
    q = quick.questions("house_cleaning", REG)
    ids = [x["id"] for x in q["questions"]]
    assert ids[:3] == ["bedrooms", "bathrooms", "sqft"]
    cond = next(x for x in q["questions"] if x["id"] == "condition")
    assert [c["value"] for c in cond["choices"]] == ["1", "2", "3", "4", "5"]
    assert "factor" not in cond["choices"][0]   # factors are pricing internals


def test_required_and_unknown_answers(db):  # S2-Q04
    with pytest.raises(InvalidInput) as exc:
        _answer(db, "house_cleaning", {"bedrooms": 2})
    assert set(exc.value.details["missing"]) == {"bathrooms", "sqft"}
    with pytest.raises(InvalidInput, match="unknown questions"):
        _answer(db, "pressure_washing", {"driveway": 100})


@pytest.mark.parametrize("answers, msg", [
    ({"driveway_sqft": -5}, "at least"),
    ({"driveway_sqft": "lots"}, "must be a number"),
    ({"stories": 1.5}, "whole number"),
    ({"stories": 9}, "at most"),
    ({"condition": "filthy"}, "must be one of"),
    ({"seal_driveway": "maybe"}, "yes or no"),
])
def test_bad_answers(db, answers, msg):  # S2-Q05
    with pytest.raises(InvalidInput, match=msg):
        _answer(db, "pressure_washing", answers)


def test_answer_forms_accepted(db):  # S2-Q06
    e = _answer(db, "pressure_washing", {"driveway_sqft": "1,000", "seal_driveway": "yes", "stories": "1"})
    rules = [ln["calc"]["rule"] for ln in e["sections"][0]["lines"]]
    assert rules == ["driveway", "sealer"]
    assert e["sections"][0]["answers"]["seal_driveway"] is True
    assert e["sections"][0]["answers"]["driveway_sqft"] == 1000


def test_reanswer_replaces_lines_not_appends(db):  # S2-Q07
    e = service.create_estimate(db, CTX, "x")
    e = quick.answer(db, CTX, e["id"], "pressure_washing", {"driveway_sqft": 2000}, e["rev"], REG)
    e = quick.answer(db, CTX, e["id"], "pressure_washing", {"deck_sqft": 300}, e["rev"], REG)
    lines = e["sections"][0]["lines"]
    assert [ln["calc"]["rule"] for ln in lines] == ["deck"]
    assert len(e["sections"]) == 1


def test_sample_price_warning_and_company_price_used(db):  # S2-Q08
    e = _answer(db, "pressure_washing", {"driveway_sqft": 2000})
    assert e["warnings"] and "pw_driveway_sqft" in e["warnings"][0]
    assert get_price(db, "default", "pw_driveway_sqft").is_sample
    set_price(db, "default", "pw_driveway_sqft", description="mine", kind="other", unit="sqft", cost_cents=20)
    e2 = _answer(db, "pressure_washing", {"driveway_sqft": 2000})
    # 2000 x 1.15 x $0.20 = $460.00, no warning
    assert e2["totals"]["total_cents"] == 46000 and e2["warnings"] == []


def test_company_minimum_beats_module_minimum(db):  # S2-Q09
    service.save_markups(db, CTX, minimum_charge_cents=25000)
    e = _answer(db, "pressure_washing", {"driveway_sqft": 800})
    assert e["totals"]["total_cents"] == 25000


def test_quick_with_markups(db):  # S2-Q10
    service.save_markups(db, CTX, overhead_pct="0.10", profit_pct="0.20")
    e = _answer(db, "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800})
    # 267.50 cost -> +26.75 overhead -> +58.85 profit = 353.10 ("other" isn't taxable by default)
    assert e["totals"]["total_cents"] == 35310


def test_unknown_module(db):  # S2-Q11
    with pytest.raises(NotFound):
        _answer(db, "roof_painting", {})


def test_all_zero_answers_give_minimum_only(db):  # S2-Q12
    e = _answer(db, "pressure_washing", {})
    assert e["sections"][0]["lines"] == []
    assert e["totals"]["total_cents"] == 15000

"""The Inspector's reference lists: every construction trade is covered, either
with a checklist or with a stated reason for having none, and no service trade
has a list. The lists are the reference the AI matches the estimate against -
it must not invent code sections, so each item carries a real one."""
from estimator.estimating import inspection_refs as refs
from estimator.modules import get_registry

EXPECTED_COUNTS = {"electrical": 18, "concrete": 8, "demolition": 4, "drywall": 4,
                   "fencing": 3, "flooring": 3, "framing": 7, "hvac": 6,
                   "insulation": 5, "landscaping": 3, "plumbing": 8, "roofing": 7,
                   "siding": 4, "windows_doors": 7, "garage_doors": 3}     # garage_doors 2026-11-27


def _trades(category):
    return sorted(m.id for m in get_registry().list() if m.category == category)


def test_every_construction_trade_is_covered():
    construction = _trades("construction")
    assert len(construction) == 16          # + garage_doors (2026-11-27)
    covered = set(refs.REFERENCE_REQUIREMENTS) | set(refs.NO_CHECKLIST)
    assert covered == set(construction)
    assert not (set(refs.REFERENCE_REQUIREMENTS) & set(refs.NO_CHECKLIST))


def test_no_service_trade_has_a_list():
    services = _trades("service")
    assert len(services) == 10              # + carpet_cleaning (2026-11-27)
    for mid in services:
        assert mid not in refs.REFERENCE_REQUIREMENTS
        assert not refs.has_references(mid)


def test_every_item_has_an_id_a_description_and_a_code_ref():
    for mid, items in refs.REFERENCE_REQUIREMENTS.items():
        ids = [i["id"] for i in items]
        assert len(ids) == len(set(ids)), f"{mid}: duplicate item ids"
        for i in items:
            assert i["id"] and i["description"] and i["code_ref"], f"{mid}: {i}"
            assert set(i) <= {"id", "description", "code_ref", "note"}, f"{mid}: {i}"


def test_item_counts_per_trade():
    assert {mid: len(items) for mid, items in refs.REFERENCE_REQUIREMENTS.items()} == EXPECTED_COUNTS


def test_electrical_list_is_the_18_known_items():
    got = {r["id"]: r for r in refs.REFERENCE_REQUIREMENTS["electrical"]}
    assert len(got) == 18
    assert got["gfci"]["code_ref"] == "210.8"
    assert got["surge_protection"]["code_ref"] == "230.67"
    assert got["kitchen_circuits"]["code_ref"] == "210.11(C)(1)"
    assert got["wire_gauge"]["code_ref"].startswith("240.4")
    assert got["smoke_co"]["code_ref"] == "NFPA 72"


def test_painting_is_the_only_trade_without_a_list_and_says_why():
    assert refs.NO_CHECKLIST == {"painting": refs.NO_CHECKLIST["painting"]}
    reason = refs.NO_CHECKLIST["painting"]
    assert "no building-code inspection requirements" in reason
    assert "40 CFR 745" in reason
    assert not refs.has_references("painting")


def test_helpers_agree_with_the_lists():
    assert refs.reviewable_trades() == sorted(EXPECTED_COUNTS)
    assert all(refs.has_references(mid) for mid in EXPECTED_COUNTS)
    assert refs.reviewable_trades() == sorted(refs.REFERENCE_REQUIREMENTS)


def test_every_reviewable_trade_names_its_code():
    for mid in refs.REFERENCE_REQUIREMENTS:
        assert refs.TRADE_CODE[mid], mid
    assert refs.TRADE_CODE["electrical"] == "the National Electrical Code (NEC)"
    assert refs.TRADE_CODE["plumbing"] == "the Florida Plumbing Code"

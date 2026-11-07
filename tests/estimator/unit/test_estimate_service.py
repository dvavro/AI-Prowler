"""Sprint 2: estimate service layer (S2-S01..)."""
import json
from decimal import Decimal

import pytest

from estimator.context import RequestContext, personal_context
from estimator.errors import InvalidInput, NotEditable, NotFound, PermissionDenied, StaleRevision
from estimator.estimating import service
from estimator.pricing.price_book import get_price, set_price

CTX = personal_context()


def test_create_and_get(db):  # S2-S01
    e = service.create_estimate(db, CTX, "Smith job", customer_id="C1", address="1 Main St")
    assert e["status"] == "draft" and e["rev"] == 1 and e["sections"] == []
    got = service.get_estimate(db, CTX, e["id"])
    assert got["title"] == "Smith job" and got["address"] == "1 Main St"


def test_add_line_prices_it_and_bumps_rev(db):  # S2-S02
    e = service.create_estimate(db, CTX, "x")
    e = service.add_line_item(db, CTX, e["id"], e["rev"], kind="material", description="Concrete",
                              quantity="2.5", unit="cuyd", unit_cost_cents=15000, waste_pct="0.10")
    assert e["rev"] == 2
    line = e["sections"][0]["lines"][0]
    assert e["sections"][0]["module_id"] == "custom"
    assert line["quantity"] == "2.5"
    # 2.5 x 150.00 = 375.00; +10% waste = 412.50
    assert line["total_cents"] == 41250 and e["totals"]["total_cents"] == 41250
    assert line["calc"]["price"]["waste_cents"] == 3750


def test_stale_rev_rejected_and_nothing_written(db):  # S2-S03
    e = service.create_estimate(db, CTX, "x")
    service.add_line_item(db, CTX, e["id"], e["rev"], kind="other", description="a", quantity="1", unit="ea",
                          unit_cost_cents=100)
    with pytest.raises(StaleRevision) as exc:
        service.add_line_item(db, CTX, e["id"], e["rev"], kind="other", description="b", quantity="1",
                              unit="ea", unit_cost_cents=100)
    assert exc.value.details["current_rev"] == 2
    assert len(service.get_estimate(db, CTX, e["id"])["sections"][0]["lines"]) == 1


def test_markups_flow_into_totals_and_calculate(db):  # S2-S04
    e = service.create_estimate(db, CTX, "x")
    e = service.add_line_item(db, CTX, e["id"], e["rev"], kind="material", description="m", quantity="10",
                              unit="ea", unit_cost_cents=1000)
    assert e["totals"]["total_cents"] == 10000
    service.save_markups(db, CTX, overhead_pct="0.10", profit_pct="0.20", tax_pct="0.05")
    e = service.calculate(db, CTX, e["id"], e["rev"])
    # cost 100.00, overhead 10.00, profit 22.00, tax on cost 5.00 -> 137.00
    assert e["totals"]["total_cents"] == 13700 and e["totals"]["tax_cents"] == 500


def test_price_key_lookup_and_missing_price(db):  # S2-S05
    set_price(db, "default", "conc_cuyd", description="Concrete", kind="material", unit="cuyd", cost_cents=14000)
    e = service.create_estimate(db, CTX, "x")
    e = service.add_line_item(db, CTX, e["id"], e["rev"], kind="material", description="c", quantity="3",
                              unit="cuyd", price_key="conc_cuyd")
    assert e["totals"]["total_cents"] == 42000 and e["warnings"] == []
    with pytest.raises(NotFound):
        service.add_line_item(db, CTX, e["id"], e["rev"], kind="material", description="c", quantity="3",
                              unit="cuyd", price_key="nope")
    with pytest.raises(InvalidInput, match="per cuyd"):
        service.add_line_item(db, CTX, e["id"], e["rev"], kind="material", description="c", quantity="3",
                              unit="ton", price_key="conc_cuyd")


def test_latest_effective_price_wins(db):  # S2-S06
    set_price(db, "default", "k", description="", kind="other", unit="ea", cost_cents=100, effective_date="2025-01-01")
    set_price(db, "default", "k", description="", kind="other", unit="ea", cost_cents=200, effective_date="2026-01-01")
    set_price(db, "default", "k", description="", kind="other", unit="ea", cost_cents=999, effective_date="2999-01-01")
    assert get_price(db, "default", "k").cost_cents == 200
    assert get_price(db, "default", "k", as_of="2025-06-01").cost_cents == 100


@pytest.mark.parametrize("kwargs, field", [
    ({"kind": "snacks"}, "kind"),
    ({"quantity": "-1"}, "quantity"),
    ({"quantity": "abc"}, "quantity"),
    ({"unit": "furlong"}, "unit"),
    ({"waste_pct": "1.5"}, "waste_pct"),
    ({"unit_cost_cents": 1.5}, "unit_cost_cents"),
    ({"unit_cost_cents": None}, "unit_cost_cents"),
])
def test_bad_line_input_rejected(db, kwargs, field):  # S2-S07
    e = service.create_estimate(db, CTX, "x")
    args = dict(kind="other", description="d", quantity="1", unit="ea", unit_cost_cents=100)
    args.update(kwargs)
    with pytest.raises(InvalidInput) as exc:
        service.add_line_item(db, CTX, e["id"], e["rev"], **args)
    assert exc.value.details.get("field") == field


def test_finalized_estimate_is_locked(db):  # S2-S08
    e = service.create_estimate(db, CTX, "x")
    e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
    with pytest.raises(NotEditable):
        service.add_line_item(db, CTX, e["id"], e["rev"], kind="other", description="d", quantity="1",
                              unit="ea", unit_cost_cents=1)
    with pytest.raises(NotEditable):
        service.set_status(db, CTX, e["id"], e["rev"], "draft")
    e = service.set_status(db, CTX, e["id"], e["rev"], "won")
    assert e["status"] == "won"


def test_other_company_cannot_see_estimate(db):  # S2-S09
    e = service.create_estimate(db, CTX, "x")
    other = RequestContext(company_id="acme", user_id="u2", mode="server")
    with pytest.raises(NotFound):
        service.get_estimate(db, other, e["id"])
    assert service.list_estimates(db, other)["count"] == 0
    assert service.list_estimates(db, CTX)["count"] == 1


@pytest.mark.parametrize("role", ["reviewer", "office", "field"])
def test_read_only_roles_cannot_write(db, role):  # S2-S10 (Sprint 3: office and field may start quick quotes)
    e = service.create_estimate(db, CTX, "x")
    ro = RequestContext(role=role, user_id="u3", mode="server")
    assert service.get_estimate(db, ro, e["id"])["id"] == e["id"]
    if role == "reviewer":
        with pytest.raises(PermissionDenied):
            service.create_estimate(db, ro, "y")
    else:
        assert service.create_estimate(db, ro, "y")["status"] == "draft"
    with pytest.raises(PermissionDenied):
        service.add_line_item(db, ro, e["id"], e["rev"], kind="other", description="d", quantity="1",
                              unit="ea", unit_cost_cents=1)


def test_events_record_actor_and_agent(db):  # S2-S11
    agent = RequestContext(agent="agent:quick_pricer")
    e = service.create_estimate(db, CTX, "x")
    service.add_line_item(db, agent, e["id"], e["rev"], kind="other", description="d", quantity="1",
                          unit="ea", unit_cost_cents=1)
    ev = service.events(db, CTX, e["id"])
    assert [x["action"] for x in ev] == ["estimate_created", "line_added"]
    assert ev[1]["actor"] == "agent:quick_pricer" and ev[1]["on_behalf_of"] == "owner"


def test_list_filters_and_add_trade(db):  # S2-S12
    a = service.create_estimate(db, CTX, "a")
    service.create_estimate(db, CTX, "b")
    service.set_status(db, CTX, a["id"], a["rev"], "in_review")
    assert service.list_estimates(db, CTX, status="in_review")["count"] == 1
    with pytest.raises(InvalidInput):
        service.list_estimates(db, CTX, status="nope")
    b = service.list_estimates(db, CTX, status="draft")["estimates"][0]
    e = service.add_trade(db, CTX, b["id"], "pressure_washing", b["rev"])
    assert e["sections"][0]["module_id"] == "pressure_washing"
    with pytest.raises(InvalidInput, match="already has"):
        service.add_trade(db, CTX, b["id"], "pressure_washing", e["rev"])


def test_failed_write_rolls_back(db, monkeypatch):  # S2-S13
    e = service.create_estimate(db, CTX, "x")

    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(service, "_recalculate", boom)
    with pytest.raises(RuntimeError):
        service.add_line_item(db, CTX, e["id"], e["rev"], kind="other", description="d", quantity="1",
                              unit="ea", unit_cost_cents=1)
    monkeypatch.undo()
    got = service.get_estimate(db, CTX, e["id"])
    assert got["rev"] == 1 and got["sections"] == []

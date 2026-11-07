"""Sprint 3: setup wizard backend (S3-W..)."""
import pytest

from estimator.context import RequestContext, personal_context
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import quick, service, setup
from estimator.modules.registry import ModuleRegistry
from estimator.pricing.price_book import get_price

CTX = personal_context()
REG = ModuleRegistry().load()


def test_fresh_status(db):  # S3-W01
    s = setup.setup_status(db, CTX)
    assert s["done"] == 0 and s["total"] == 9 and s["next_step"] == "company_profile"
    assert s["ready_for_first_bid"] is False


def test_company_profile_and_resume(db):  # S3-W02
    s = setup.setup_step(db, CTX, "company_profile", {"name": "Sparkle Wash LLC", "phone": "480-555-0100"})
    assert s["done"] == 1 and s["next_step"] == "services"
    row = db.execute("SELECT name, phone FROM company_profile WHERE company_id = 'default'").fetchone()
    assert row["name"] == "Sparkle Wash LLC"
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "company_profile", {"name": " "})
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "company_profile", {"name": "x", "ssn": "1"})


def test_skip_and_unknown_step(db):  # S3-W03
    s = setup.setup_step(db, CTX, "bid_template", status="skipped")
    assert next(x for x in s["steps"] if x["step"] == "bid_template")["status"] == "skipped"
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "launch_rockets")
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "tax", status="maybe")


def test_tax_and_markups_merge(db):  # S3-W04
    setup.setup_step(db, CTX, "markups", {"overhead_pct": "0.10", "profit_pct": "0.20", "minimum_charge": "125"})
    setup.setup_step(db, CTX, "tax", {"tax_pct": "0.08"})
    m, settings = service.company_markups(db, "default")
    assert str(m.overhead_pct) == "0.10" and str(m.tax_pct) == "0.08" and settings["minimum_charge_cents"] == 12500
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "tax", {"profit_pct": "0.5"})


def test_price_review_clears_samples(db):  # S3-W05
    e = service.create_estimate(db, CTX, "x")
    quick.answer(db, CTX, e["id"], "pressure_washing", {"driveway_sqft": 1000}, e["rev"], REG)
    s = setup.setup_status(db, CTX)
    assert s["sample_prices_in_use"] == 7
    s = setup.setup_step(db, CTX, "price_book_review", {"prices": {"pw_driveway_sqft": "0.18"}})
    assert get_price(db, "default", "pw_driveway_sqft").cost_cents == 18
    assert s["sample_prices_in_use"] == 6 and not s["ready_for_first_bid"]
    s = setup.setup_step(db, CTX, "price_book_review", {"keep_samples": True})
    assert s["sample_prices_in_use"] == 0 and s["ready_for_first_bid"]
    with pytest.raises(NotFound):
        setup.setup_step(db, CTX, "labor_rates", {"prices": {"nope": "1"}})
    with pytest.raises(InvalidInput):
        setup.setup_step(db, CTX, "labor_rates", {"prices": {"pw_deck_sqft": "lots"}})


def test_services_step_checks_modules(db):  # S3-W06
    setup.setup_step(db, CTX, "services", {"modules": ["pressure_washing", "house_cleaning"]})
    with pytest.raises(NotFound):
        setup.setup_step(db, CTX, "services", {"modules": ["unicorn_grooming"]})


def test_only_owner_runs_setup(db):  # S3-W07
    with pytest.raises(PermissionDenied):
        setup.setup_step(db, RequestContext(role="estimator", user_id="e", mode="server"), "tax", {"tax_pct": "0"})

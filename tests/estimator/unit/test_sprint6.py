"""Sprint 6: price book tools, estimate revisions, follow-ups and briefing, recurring jobs (S6-..)."""
import json
from datetime import date, timedelta

import pytest

from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.director import briefing, engine
from estimator.director.settings import update_settings
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.estimating import quick, service
from estimator.modules.registry import ManifestError, ModuleRegistry, load_module
from estimator.pricing import price_book

CTX = personal_context()
REG = ModuleRegistry().load()
OFFICE = RequestContext(role="office", user_id="sue", mode="server")


# ---------------------------------------------------------------- price book

def test_list_prices_shows_module_samples_before_use(db):  # S6-P01
    out = price_book.list_prices(db, "default", "pressure_washing", registry=REG)
    keys = {p["price_key"]: p for p in out["prices"]}
    assert keys["pw_driveway_sqft"]["source"] == "sample (not used yet)" and out["samples_left"] == 7
    assert price_book.list_prices(db, "default", registry=REG)["count"] == sum(len(m.sample_prices) for m in REG.list())


def test_update_prices_needs_confirm_then_applies(db):  # S6-P02
    with pytest.raises(ConfirmationRequired) as exc:
        price_book.update_prices(db, CTX, {"pw_driveway_sqft": "0.18"}, registry=REG)
    assert "$0.15 → $0.18" in exc.value.message
    out = price_book.update_prices(db, CTX, {"pw_driveway_sqft": "$0.18", "hc_labor_hr": "45"}, confirm=True,
                                   registry=REG)
    assert len(out["changed"]) == 2
    rows = {p["price_key"]: p for p in price_book.list_prices(db, "default", registry=REG)["prices"]}
    assert rows["pw_driveway_sqft"]["cost_cents"] == 18 and rows["pw_driveway_sqft"]["source"] == "yours"
    assert rows["hc_labor_hr"]["cost_cents"] == 4500
    ev = db.execute("SELECT after_json FROM estimate_events WHERE action = 'prices_changed'").fetchone()
    assert json.loads(ev["after_json"])["changes"][0]["old_cents"] == 15


def test_new_price_used_by_next_quote_not_old_bids(db):  # S6-P03
    price_book.update_prices(db, CTX, {"pw_driveway_sqft": "0.20"}, confirm=True, registry=REG)
    e = service.create_estimate(db, CTX, "x")
    e = quick.answer(db, CTX, e["id"], "pressure_washing", {"driveway_sqft": 2000, "condition": "light"},
                     e["rev"], REG)
    assert e["totals"]["total_cents"] == 40000 and "pw_driveway_sqft" not in (e["warnings"][0] if e["warnings"] else "")


@pytest.mark.parametrize("prices, err", [({"nope": "1"}, NotFound), ({"pw_deck_sqft": "lots"}, InvalidInput),
                                         ({"pw_deck_sqft": "-1"}, InvalidInput), ({}, InvalidInput)])
def test_bad_price_updates(db, prices, err):  # S6-P04
    with pytest.raises(err):
        price_book.update_prices(db, CTX, prices, confirm=True, registry=REG)


def test_office_cannot_change_prices(db):  # S6-P05
    with pytest.raises(PermissionDenied):
        price_book.update_prices(db, OFFICE, {"pw_deck_sqft": "1"}, confirm=True, registry=REG)


# ---------------------------------------------------------------- revisions

def _approved(db, answers=None, module="house_cleaning"):
    e = service.create_estimate(db, CTX, "Smith clean")
    e = quick.answer(db, CTX, e["id"], module, answers or {"bedrooms": 3, "bathrooms": 2, "sqft": 1800},
                     e["rev"], REG)
    return service.set_status(db, CTX, e["id"], e["rev"], "approved")


def test_revision_copies_and_voids_open_bids(db, fake_host):  # S6-R01
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer={"email": "a@b.com"})
    bids.send(db, CTX, b["id"], confirm=True)
    new = service.create_revision(db, CTX, e["id"], "customer added a bathroom")
    assert new["revision"] == 2 and new["parent_estimate_id"] == e["id"] and new["status"] == "draft"
    assert new["totals"]["total_cents"] == 26750 and new["voided_bids"] == [b["number"]]
    assert bids.preview(db, CTX, b["id"])["status"] == "void"
    assert service.get_estimate(db, CTX, e["id"])["status"] == "sent"         # original unchanged
    with pytest.raises(InvalidInput, match="newer revision"):
        service.create_revision(db, CTX, e["id"], "again")


def test_revision_rules(db):  # S6-R02
    d = service.create_estimate(db, CTX, "draft")
    with pytest.raises(InvalidInput, match="edit it directly"):
        service.create_revision(db, CTX, d["id"], "x")
    e = _approved(db)
    with pytest.raises(InvalidInput, match="change_summary"):
        service.create_revision(db, CTX, e["id"], " ")


def test_director_revise_after_send(db, fake_host):  # S6-R03
    r = engine.start(db, CTX, "clean a house", answers={"bedrooms": 2, "bathrooms": 1, "sqft": 1000},
                     customer={"email": "kim@example.com"}, registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, send=True, confirm=True, registry=REG)
    assert r["job"]["stage"] == "follow_up"
    with pytest.raises(NotEditable, match="revise=true"):
        engine.next_step(db, CTX, r["job"]["id"], answers={"bathrooms": 2}, registry=REG)
    old_est = r["estimate"]["id"]
    r = engine.next_step(db, CTX, r["job"]["id"], revise=True, change_summary="second bathroom",
                         answers={"bathrooms": 2}, registry=REG)
    assert r["estimate"]["id"] != old_est and r["job"]["stage"] == "approve"
    assert r["estimate"]["total_cents"] > 0 and r["estimate"]["status"] == "draft"


def test_director_reprice_after_price_change(db):  # S6-R04
    r = engine.start(db, CTX, "pressure wash", answers={"driveway_sqft": 1000, "condition": "light"}, registry=REG)
    assert r["estimate"]["total_cents"] == 15000                                # $150 at the minimum
    price_book.update_prices(db, CTX, {"pw_driveway_sqft": "0.25"}, confirm=True, registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], reprice=True, registry=REG)
    assert r["estimate"]["total_cents"] == 25000 and r["next_step"]["sample_prices"] == []


# ---------------------------------------------------------------- follow-ups and briefing

def test_followups_and_briefing(db, fake_host):  # S6-F01
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer={"email": "a@b.com"})
    bids.send(db, CTX, b["id"], confirm=True)
    today = date.today()
    assert briefing.followups_due(db, CTX, today)["follow_ups"] == []
    later = today + timedelta(days=5)
    due = briefing.followups_due(db, CTX, later)
    assert due["follow_ups"][0]["number"] == b["number"] and due["follow_ups"][0]["days_since_sent"] == 5
    near_expiry = date.fromisoformat(b["valid_until"]) - timedelta(days=2)
    assert briefing.followups_due(db, CTX, near_expiry)["expiring_soon"][0]["days_left"] == 2
    update_settings(db, CTX, {"follow_up_days": 10})
    assert briefing.followups_due(db, CTX, later)["follow_ups"] == []
    text = briefing.briefing(db, CTX, today)["text"]
    assert "1 quote(s) sent since yesterday ($267.50)" in text


def test_briefing_counts_director_work(db):  # S6-F02
    engine.start(db, CTX, "clean a house", answers={"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, registry=REG)
    engine.start(db, CTX, "pressure wash please", registry=REG)
    out = briefing.briefing(db, CTX)
    assert out["counts"]["awaiting_approval"] == 1 and out["counts"]["needs_answers"] == 1
    assert "waiting for your approval" in out["text"]
    stuck = briefing.followups_due(db, CTX, date.today() + timedelta(days=3))["stuck_jobs"]
    assert len(stuck) == 2


def test_empty_briefing(db):  # S6-F03
    assert "All quiet" in briefing.briefing(db, CTX)["text"]


# ---------------------------------------------------------------- recurring jobs

def test_recurring_quote_becomes_repeating_job(db, fake_host):  # S6-C01
    e = _approved(db, {"visits": "biweekly"}, "pool_service")
    b = bids.generate(db, CTX, e["id"], customer={"name": "Pat Pool", "email": "p@x.com"})
    bids.send(db, CTX, b["id"], confirm=True)
    out = bids.convert_to_job(db, CTX, b["id"], confirm=True)
    job = fake_host.named("create_job")[0]["updates"]
    assert job["Recurrence"] == "Biweekly" and job["Service Details / Notes"].startswith("Biweekly service.")
    assert out["recurrence"] == "Biweekly"


def test_one_time_quote_has_no_recurrence(db, fake_host):  # S6-C02
    e = _approved(db)                      # house cleaning, default frequency one_time
    b = bids.generate(db, CTX, e["id"], customer={"name": "Al", "email": "al@x.com"})
    bids.send(db, CTX, b["id"], confirm=True)
    bids.convert_to_job(db, CTX, b["id"], confirm=True)
    assert "Recurrence" not in fake_host.named("create_job")[0]["updates"]


def test_bad_recurrence_blocks_rejected(tmp_path):  # S6-C03
    import shutil
    src = REG.get("pool_service").folder
    dst = tmp_path / "services" / "pool_service"
    shutil.copytree(src, dst)
    mf = dst / "manifest.yaml"
    text = mf.read_text(encoding="utf-8")
    mf.write_text(text.replace("biweekly: Biweekly}", "biweekly: Fortnightly}"), encoding="utf-8")
    with pytest.raises(ManifestError, match="recurrence values"):
        load_module(dst)
    mf.write_text(text.replace("question: visits", "question: chemicals"), encoding="utf-8")
    with pytest.raises(ManifestError, match="choice question"):
        load_module(dst)


def test_local_dates_from_utc_timestamps():  # S6-F04
    from datetime import datetime, timezone
    from estimator.core.dates import local_date, local_date_text
    ts = "2026-11-07T01:30:00+00:00"           # 6:30 pm on Nov 6 in Arizona
    expected = datetime(2026, 11, 7, 1, 30, tzinfo=timezone.utc).astimezone().date()
    assert local_date(ts) == expected and local_date_text(ts) == expected.isoformat()
    assert local_date("2026-11-06") == date(2026, 11, 6) and local_date(None) is None and local_date("junk") is None

"""David's decisions A and B (2026-11-22) for Make it a job.

A: the quote total already includes the Estimator's tax, so the job is No Sales Tax and its invoice equals the
   accepted quote (the invoice used to add tax again).
B: a monthly-priced repeating quote (pool, landscaping maintenance) becomes a job billed per visit (month / visits),
   and its one-time work becomes a job of its own, so a weekly job isn't billed the whole month every week.
"""
import shutil

import pytest

from estimator.bids import service as bids
from estimator.context import personal_context
from estimator.estimating import quick, service
from estimator.modules.registry import ManifestError, ModuleRegistry, load_module

CTX = personal_context()
REG = ModuleRegistry().load()


def _won(db, module, answers, name="Pat Pool"):
    e = service.create_estimate(db, CTX, f"{name} {module}")
    e = quick.answer(db, CTX, e["id"], module, answers, e["rev"], REG)
    e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
    b = bids.generate(db, CTX, e["id"], customer={"name": name, "email": "p@x.com"})
    bids.send(db, CTX, b["id"], confirm=True)
    return e, b


def _cents(text):
    return round(float(str(text).replace("$", "").replace(",", "")) * 100)


def test_A_job_is_no_sales_tax_at_the_quote_total(db, fake_host):  # JTV-A01
    e, b = _won(db, "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, "Al")
    bids.convert_to_job(db, CTX, b["id"], confirm=True)
    job = fake_host.named("create_job")[0]["updates"]
    assert job["No Sales Tax"] == 1
    assert _cents(job["Quote Amount ($)"]) == b["total_cents"]


def test_B_weekly_pool_job_is_billed_per_visit(db, fake_host):  # JTV-B01
    e, b = _won(db, "pool_service", {"visits": "weekly"})
    out = bids.convert_to_job(db, CTX, b["id"], confirm=True)
    jobs = fake_host.named("create_job")
    assert len(jobs) == 1                                             # no one-time work, no second job
    job = jobs[0]["updates"]
    assert job["Recurrence"] == "Weekly" and job["No Sales Tax"] == 1
    assert _cents(job["Quote Amount ($)"]) == round(b["total_cents"] / 4)
    assert "a month / 4 visits" in job["Service Details / Notes"]
    assert out["per_visit"]["visits_a_month"] == 4 and out["per_visit"]["one_time_job_id"] is None


def test_B_one_time_work_gets_its_own_job(db, fake_host):  # JTV-B02
    e, b = _won(db, "pool_service", {"visits": "biweekly", "cleanup": "green", "acid_wash": True})
    out = bids.convert_to_job(db, CTX, b["id"], confirm=True)
    jobs = [j["updates"] for j in fake_host.named("create_job")]
    assert len(jobs) == 2
    once = next(j for j in jobs if "Recurrence" not in j)
    repeat = next(j for j in jobs if j.get("Recurrence") == "Biweekly")
    assert once["Service Details / Notes"].startswith("One-time work from Estimator quote")
    assert "cleanup" in once["Service Details / Notes"].lower() and "acid wash" in once["Service Details / Notes"].lower()
    assert once["No Sales Tax"] == 1
    # the month's work plus the one-time work is the whole quote (per-visit rounding within a cent a visit)
    month = _cents(repeat["Quote Amount ($)"]) * 2
    assert abs(month + _cents(once["Quote Amount ($)"]) - b["total_cents"]) <= 2
    assert out["created"]["once_job_id"] == out["per_visit"]["one_time_job_id"]


def test_B_per_visit_modules_keep_the_quote_price(db, fake_host):  # JTV-B03
    # House cleaning already prices one visit: a weekly plan keeps the quote total on the repeating job.
    e, b = _won(db, "house_cleaning", {"bedrooms": 2, "bathrooms": 1, "sqft": 1000, "frequency": "weekly"}, "Kim")
    out = bids.convert_to_job(db, CTX, b["id"], confirm=True)
    job = fake_host.named("create_job")[0]["updates"]
    assert job["Recurrence"] == "Weekly" and _cents(job["Quote Amount ($)"]) == b["total_cents"]
    assert "per_visit" not in out


def test_B_landscaping_monthly_tasks_stay_in_the_month(db, fake_host):  # JTV-B04
    e, b = _won(db, "landscaping_maintenance", {"yard_size": "standard", "visits": "weekly", "hedges": "few",
                                                "leaf_cleanup": True}, "Lee")
    out = bids.convert_to_job(db, CTX, b["id"], confirm=True)
    jobs = [j["updates"] for j in fake_host.named("create_job")]
    once = [j for j in jobs if "Recurrence" not in j]
    assert len(once) == 1 and "leaf cleanup" in once[0]["Service Details / Notes"].lower()
    assert "hedge" not in once[0]["Service Details / Notes"].lower()     # monthly hedges are part of the month
    assert out["per_visit"]["visits_a_month"] == 4


def test_B_old_quotes_without_line_rules_are_not_split():  # JTV-B05
    snap = {"sections": [{"module_id": "pool_service", "lines": [{"description": "x", "quantity": 4, "unit": "ea",
                                                                   "price_cents": 40000}]}],
            "totals": {"total_cents": 40000, "tax_cents": 0}}
    assert bids.split_month(snap, {"module_id": "pool_service", "visits": 4, "once": set()}) is None


def test_B_split_shares_the_minimum_charge_adjustment():  # JTV-B06
    snap = {"sections": [{"module_id": "pool_service", "lines": [
        {"rule": "service", "price_cents": 6000, "tax_cents": 0},
        {"rule": "acid_wash", "price_cents": 2000, "tax_cents": 0}]}],
        "totals": {"total_cents": 10000, "tax_cents": 0}}                   # $20 minimum-charge top-up
    s = bids.split_month(snap, {"module_id": "pool_service", "visits": 1, "once": {"acid_wash"}})
    assert s["month_cents"] + s["once_cents"] == 10000
    assert s["month_cents"] == 7500 and s["once_cents"] == 2500 and s["visit_cents"] == 7500


@pytest.mark.parametrize("old, new, match", [
    ("per_month: {weekly: 4,", "per_month: {daily: 4, weekly: 4,", "don't repeat"),
    ("per_month: {weekly: 4,", "per_month: {weekly: 0,", "whole numbers"),
    ("once: [one_time,", "once: [nope, one_time,", "unknown lines"),
])
def test_B_manifest_checks(tmp_path, old, new, match):  # JTV-B07
    src = REG.get("pool_service").folder
    dst = tmp_path / "services" / "pool_service"
    shutil.copytree(src, dst)
    mf = dst / "manifest.yaml"
    text = mf.read_text(encoding="utf-8")
    assert old in text
    mf.write_text(text.replace(old, new), encoding="utf-8")
    with pytest.raises(ManifestError, match=match):
        load_module(dst)


def test_B_pool_and_landscaping_declare_their_month():  # JTV-B08
    for mid in ("pool_service", "landscaping_maintenance"):
        rec = REG.get(mid).recurrence
        assert rec["per_month"] == {"weekly": 4, "biweekly": 2, "monthly": 1} and rec["once"]
    assert not REG.get("house_cleaning").recurrence.get("per_month")

"""Sprint 20 (Tester 1 work for the beta): whole jobs run only through the AI tools, the way Claude, Grok or Muse
would in chat, plus a performance check with a few hundred estimates (S20-..).

Every step uses the JSON the AI sees, never the service layer directly, so a change that breaks what the AI gets
back fails here. AI-Prowler's own tools (customers, quotes, jobs, email) are the test stand-in (fake_host).
"""
import json
import time

import pytest

from estimator.context import personal_context
from estimator.database import open_database
from estimator.estimating import quick, service
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()


def j(text: str) -> dict:
    out = json.loads(text)
    assert isinstance(out, dict)
    return out


def ok(text: str) -> dict:
    out = j(text)
    assert out.get("ok") is not False, out
    return out


# ---------------------------------------------------------------- whole jobs by chat

def test_first_day_setup_by_chat(db):  # S20-C01
    """A new owner sets up by chat: company, tax, markups, a price, then tries the practice project."""
    ok(t.est_setup_step("company_profile", {"name": "Vavro Exteriors", "phone": "480-555-0100"}))
    ok(t.est_setup_step("tax", {"tax_pct": "0.086"}))
    ok(t.est_setup_step("markups", {"overhead_pct": "0.10", "profit_pct": "0.15", "minimum_charge": "150"}))
    ask = j(t.pricebook_update({"pw_driveway_sqft": "0.20"}))
    assert ask["error"] == "needs_confirmation"
    ok(t.pricebook_update({"pw_driveway_sqft": "0.20"}, confirm=True))
    st = ok(t.est_setup_status())
    assert {s["step"] for s in st["steps"] if s["status"] == "done"} >= {"company_profile", "tax", "markups"}
    p = ok(t.est_sample_project())
    assert p["created"] and ok(t.est_get_estimate(p["estimate_id"]))["practice"] is True
    assert {s["step"]: s["status"] for s in ok(t.est_setup_status())["steps"]}["sample_quote"] == "done"


def test_quick_quote_from_call_to_job_costs(db, fake_host):  # S20-C02
    """Customer calls about a driveway; the quote goes out, is won, becomes a job, and the real cost is recorded."""
    ok(t.est_setup_step("markups", {"overhead_pct": "0.10", "profit_pct": "0.20"}))
    ok(t.pricebook_update({"pw_driveway_sqft": "0.18"}, confirm=True))
    r = ok(t.est_director_start("customer wants their driveway pressure washed", answers={"driveway_sqft": 1200},
                                customer={"name": "Rosa Garcia", "email": "rosa@example.com"}))
    job = r["job"]["id"]
    assert r["job"]["lane"] == "quick_quote" and r["next_step"]["say"]
    r = ok(t.est_director_next(job, approve=True, confirm_sample_prices=True, send=True, confirm=True))
    assert fake_host.named("send_email")[0]["to"] == "rosa@example.com"
    assert r["job"]["stage"] == "follow_up"
    r = ok(t.est_director_next(job, outcome="won"))
    r = ok(t.est_director_next(job, convert=True, confirm=True, service_date="2026-11-20"))
    assert r["job"]["state"] == "done" and r["estimate"]["status"] == "won"
    est_id = r["estimate"]["id"]
    rec = ok(t.est_record_actuals(est_id, [{"total": "180"}], note="two hours, one tech"))
    assert rec["job"]["actual_cost"] == "$180.00" and rec["job"]["real_margin"]
    cmp = ok(t.est_compare_history(estimate_id=est_id))
    assert cmp["this_job"]["job"]["actual_cost"] == "$180.00"
    x = ok(t.est_export(est_id))
    assert x["path"].endswith(".csv")


def test_standard_roof_with_review_and_revision(db, fake_host):  # S20-C03
    """A roof over the review limit waits for a reviewer, is approved, quoted, then revised when the customer asks."""
    r = ok(t.est_director_start("replace the roof on the Miller house",
                                answers={"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"},
                                customer={"name": "Dan Miller", "email": "dan@example.com"}))
    job, est_id = r["job"]["id"], r["job"]["estimate_id"]
    assert r["job"]["lane"] == "standard_estimate"
    v = ok(t.est_validate(est_id))
    assert v["warnings"] >= 1                                    # sample prices are still in use
    r = ok(t.est_director_next(job, approve=True, confirm_sample_prices=True, reviewed=True))
    est = ok(t.est_get_estimate(est_id))
    assert est["status"] in ("approved", "sent")
    if r["job"]["stage"] == "write_bid":
        r = ok(t.est_director_next(job, send=True, confirm=True))
    assert fake_host.named("send_email") and fake_host.named("send_email")[-1]["to"] == "dan@example.com"
    rev = ok(t.est_create_revision(est_id, "customer added gutters"))
    assert rev["parent_estimate_id"] == est_id and rev["revision"] == 2 and rev["status"] == "draft"


def test_team_work_and_moving_to_the_server(db, monkeypatch, tmp_path):  # S20-C04
    """The owner assigns work, imports a supplier list, then packs everything up for AI-Prowler Server."""
    r = ok(t.est_director_start("pressure wash a 900 sq ft driveway", answers={"driveway_sqft": 900}))
    ok(t.est_assign("maria", estimate_id=r["job"]["estimate_id"], note="call her back Monday"))
    assert any("maria" in (e.get("assigned_to") or "") for e in ok(t.est_list_estimates())["estimates"])
    assert j(t.pricebook_import(csv_text="Item Code,Unit Price\npw_driveway_sqft,0.19\n"))["error"] == "needs_confirmation"
    ok(t.pricebook_import(csv_text="Item Code,Unit Price\npw_driveway_sqft,0.19\n", confirm=True))
    pack = ok(t.est_data_export())
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(tmp_path / "server"))
    done = ok(t.est_data_import(pack["path"], confirm=True))
    assert done["imported"]["estimates"] == 1 and done["imported"]["price_book"] >= 1


def test_every_tool_answers_in_json(db):  # S20-C05
    """A wrong call to any tool comes back as JSON the AI can explain, never a crash."""
    bad = {"est_get_estimate": (999,), "est_validate": (999,), "est_job_status": (999,), "est_compare_history": (999,),
           "est_export": (999,), "est_record_actuals": (999, "[]"), "est_assign": ("x", 999), "bid_preview": (999,),
           "runner_status": (999,), "est_data_import": ("C:/nope.zip",), "pricebook_import": ()}
    for name, args in bad.items():
        out = j(getattr(t, name)(*args))
        assert out["ok"] is False and out["error"] and out["message"], (name, out)


# ---------------------------------------------------------------- performance

def test_performance_with_300_estimates(db):  # S20-P01
    """A busy company: 300 priced estimates (roofs and washes) with job costs. Everyday reads stay quick."""
    from estimator.learning import history
    start = time.perf_counter()
    for i in range(300):
        e = service.create_estimate(db, CTX, f"job {i}")
        if i % 2:
            e = quick.answer(db, CTX, e["id"], "roofing", {"roof_area_sqft": 1500 + i, "pitch": "6/12",
                                                          "material": "architectural"}, e["rev"], REG)
        else:
            e = quick.answer(db, CTX, e["id"], "pressure_washing", {"driveway_sqft": 600 + i}, e["rev"], REG)
        if i % 3 == 0:
            e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
            e = service.set_status(db, CTX, e["id"], e["rev"], "won")
            history.record_actuals(db, CTX, e["id"], [{"total": str(500 + i)}])
    build = time.perf_counter() - start
    timings = {}
    for name, call in {"list": lambda: t.est_list_estimates(limit=500), "board": lambda: t.est_jobs_board(),
                       "history": lambda: t.est_compare_history(), "one_estimate": lambda: t.est_get_estimate(299),
                       "compare_one": lambda: t.est_compare_history(estimate_id=299),
                       "validate": lambda: t.est_validate(299), "export_list": lambda: t.est_export(),
                       "pack_up": lambda: t.est_data_export(), "briefing": lambda: t.est_director_briefing()}.items():
        s = time.perf_counter()
        ok(call())
        timings[name] = time.perf_counter() - s
    print({k: round(v, 3) for k, v in timings.items()}, "build", round(build, 1))
    assert ok(t.est_list_estimates(limit=500))["count"] == 300
    slow = {k: v for k, v in timings.items() if v > 2.0}
    assert not slow, f"slower than 2 seconds: {slow}"

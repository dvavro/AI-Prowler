"""Sprint 2: Estimator MCP tool contract (S2-T01..).

Tools return JSON strings; errors are {"ok": false, "error": code, "message": ...}.
"""
import json

import pytest

from estimator.mcp_tools import est_tools as t


def j(s):
    assert isinstance(s, str)
    return json.loads(s)


def test_list_modules():  # S2-T01
    r = j(t.est_list_modules())
    assert r["ok"] and {m["id"] for m in r["modules"]} >= {"pressure_washing", "house_cleaning"}
    assert j(t.est_list_modules("construction"))["count"] == 15


def test_full_quick_flow():  # S2-T02
    e = j(t.est_create_estimate("Jones house clean", customer_id="C9"))
    q = j(t.est_quick_questions("house_cleaning"))
    assert q["ok"] and q["questions"]
    r = j(t.est_quick_answer(e["id"], "house_cleaning",
                             {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, e["rev"]))
    assert r["ok"] and r["totals"]["total_cents"] == 26750
    got = j(t.est_get_estimate(e["id"]))
    assert got["rev"] == r["rev"]
    lst = j(t.est_list_estimates())
    assert lst["estimates"][0]["total_cents"] == 26750


def test_answers_accepted_as_json_text():  # S2-T03
    e = j(t.est_create_estimate("x"))
    r = j(t.est_quick_answer(e["id"], "pressure_washing", '{"driveway_sqft": 800}', e["rev"]))
    assert r["totals"]["total_cents"] == 15000
    bad = j(t.est_quick_answer(e["id"], "pressure_washing", "{not json", r["rev"]))
    assert bad["ok"] is False and bad["error"] == "invalid_input"


@pytest.mark.parametrize("call, code", [
    (lambda: t.est_get_estimate(999), "not_found"),
    (lambda: t.est_quick_questions("nope"), "not_found"),
    (lambda: t.est_list_estimates(status="bogus"), "invalid_input"),
])
def test_errors_are_json(call, code):  # S2-T04
    r = j(call())
    assert r["ok"] is False and r["error"] == code and r["message"]


def test_stale_rev_and_manual_line():  # S2-T05
    e = j(t.est_create_estimate("x"))
    r = j(t.est_add_line_item(e["id"], e["rev"], "labor", "Helper", "4", "hr", unit_cost_cents=3000))
    assert r["totals"]["total_cents"] == 12000
    stale = j(t.est_add_line_item(e["id"], e["rev"], "labor", "Helper", "4", "hr", unit_cost_cents=3000))
    assert stale["error"] == "stale_revision" and stale["current_rev"] == r["rev"]
    calc = j(t.est_calculate(e["id"], r["rev"]))
    assert calc["rev"] == r["rev"] + 1


def test_internal_errors_dont_crash(monkeypatch):  # S2-T06
    monkeypatch.setattr(t.service, "list_estimates", lambda *a, **k: 1 / 0)
    r = j(t.est_list_estimates())
    assert r["error"] == "internal_error"


def test_register_on_fastmcp():  # S2-T07
    pytest.importorskip("mcp")
    from mcp.server.fastmcp import FastMCP
    import asyncio
    server = FastMCP("estimator-test")
    names = t.register(server)
    listed = {tool.name for tool in asyncio.run(server.list_tools())}
    assert set(names) <= listed and len(names) == len(t.TOOLS) == 92        # 92: symbol_detections_list (Coder 2 S10)
    tool = next(x for x in asyncio.run(server.list_tools()) if x.name == "est_quick_answer")
    assert {"estimate_id", "module_id", "answers", "rev"} <= set(tool.inputSchema["properties"])


def test_director_tools_flow():  # S3-T01
    r = j(t.est_director_start("Customer wants their driveway pressure washed", answers={"driveway_sqft": 1000}))
    assert r["ok"] and r["job"]["lane"] == "quick_quote" and r["job"]["stage"] == "approve"
    jid = r["job"]["id"]
    r = j(t.est_director_next(jid, approve=True, confirm_sample_prices=True))
    assert r["estimate"]["status"] == "approved"
    st = j(t.est_job_status(jid))
    assert st["steps"] and st["job"]["stage"] == "write_bid"
    assert j(t.est_jobs_board())["count"] == 1
    assert j(t.est_director_next(999))["error"] == "not_found"
    assert j(t.est_director_start(""))["error"] == "invalid_input"


def test_director_settings_and_playbook_tools():  # S3-T02
    assert j(t.est_director_settings_get())["settings"]["quick_send_limit_cents"] == 10000
    r = j(t.est_director_settings_update('{"quick_send_limit_cents": 20000}'))
    assert r["settings"]["quick_send_limit_cents"] == 20000
    assert j(t.est_director_settings_update({"nope": 1}))["error"] == "invalid_input"
    books = j(t.est_playbook_list())["playbooks"]
    assert {b["lane"] for b in books} == {"quick_quote", "standard_estimate", "full_takeoff"}


def test_setup_tools():  # S3-T03
    assert j(t.est_setup_status())["next_step"] == "company_profile"
    r = j(t.est_setup_step("company_profile", {"name": "Jamie's Wash Co"}))
    assert r["done"] == 1
    assert j(t.est_setup_step("nope"))["error"] == "invalid_input"


def test_bid_tools(fake_host):  # S4-T01
    r = j(t.est_director_start("clean my house", answers={"bedrooms": 2, "bathrooms": 1, "sqft": 900},
                               customer={"name": "Lee", "email": "lee@example.com"}))
    r = j(t.est_director_next(r["job"]["id"], approve=True, confirm_sample_prices=True))
    bid_id = r["next_step"]["bid_id"]
    assert j(t.bid_preview(bid_id))["text"].startswith("Quote") or "TOTAL" in j(t.bid_preview(bid_id))["text"]
    assert j(t.bid_send(bid_id))["error"] == "needs_confirmation"
    assert j(t.bid_send(bid_id, confirm=True))["status"] == "sent"
    assert j(t.bid_convert_to_job(bid_id))["error"] == "needs_confirmation"
    out = j(t.bid_convert_to_job(bid_id, confirm=True))
    assert out["job_id"] == "JOB-0001" and j(t.bid_list(status="won"))["count"] == 1
    assert j(t.bid_set_status(bid_id, "sent"))["error"] == "invalid_input"


def test_sprint6_tools(fake_host):  # S6-T01
    assert j(t.pricebook_get(module_id="pool_service"))["samples_left"] == 4
    assert j(t.pricebook_update({"ps_visit_ea": "35"}))["error"] == "needs_confirmation"
    assert j(t.pricebook_update('{"ps_visit_ea": "35"}', confirm=True))["changed"][0]["new_cents"] == 3500
    assert "All quiet" in j(t.est_director_briefing())["text"]
    assert j(t.est_followups_due())["count"] == 0
    e = j(t.est_create_estimate("x"))
    assert j(t.est_create_revision(e["id"], "x"))["error"] == "invalid_input"


def test_sprint7_tools():  # S7-T03
    r = j(t.est_director_start("replace the roof", answers={"roof_area_sqft": 2000, "pitch": "5/12",
                                                              "material": "architectural"}))
    assert r["job"]["lane"] == "standard_estimate" and r["job"]["stage"] == "review"
    v = j(t.est_validate(r["estimate"]["id"]))
    assert v["passed"] and v["warnings"] >= 1
    r = j(t.est_director_next(r["job"]["id"], reviewed=True, approve=True, confirm_sample_prices=True))
    assert r["estimate"]["status"] == "approved"
    q = j(t.est_director_start("pressure wash", answers={"driveway_sqft": 1000}))
    assert j(t.est_director_change_lane(q["job"]["id"], "standard_estimate"))["job"]["lane"] == "standard_estimate"
    assert j(t.est_director_change_lane(q["job"]["id"], "moon"))["error"] == "invalid_input"
    assert j(t.est_validate(999))["error"] == "not_found"


def test_sprint8_tools(fake_host):  # S8-T01
    r = j(t.est_director_start("replace the roof", answers={"roof_area_sqft": 2000, "pitch": "5/12",
                                                              "material": "architectural"},
                               customer={"name": "Pat", "address": "1 Elm"}))
    eid, jid = r["estimate"]["id"], r["job"]["id"]
    opts = j(t.est_scenarios(eid))
    assert [o["id"] for o in opts["options"]] == ["good", "better", "best"]
    custom = j(t.est_scenarios(eid, options='[{"id": "a", "answers": {"layers": 1}}, {"id": "b", "answers": {"layers": 2}}]'))
    assert len(custom["options"]) == 2
    rev = j(t.est_get_estimate(eid))["rev"]
    assert j(t.est_choose_scenario(eid, "b", rev))["chosen_option"]["id"] == "b"
    added = j(t.est_director_add_trade(jid, "flooring", {"area_sqft": 100, "material": "lvp"}))
    assert added["job"]["trades"] == {"flooring": {"area_sqft": 100, "material": "lvp"}}
    assert j(t.est_playbook_update("standard_estimate", {"checklist": {"roofing": ["Photo"]}}))["ok"]
    books = {b["id"]: b for b in j(t.est_playbook_list())["playbooks"]}
    assert books["standard_estimate"]["overrides"]["checklist"] == {"roofing": ["Photo"]}
    assert j(t.est_director_book_site_visit(jid, "2026-11-12"))["error"] == "invalid_input"     # turned off
    j(t.est_director_settings_update({"calendar_booking_enabled": True}))
    assert j(t.est_director_book_site_visit(jid, "2026-11-12"))["error"] == "needs_confirmation"
    assert j(t.est_director_book_site_visit(jid, "2026-11-12", confirm=True))["visit_job_id"] == "JOB-0001"


def test_sprint9_tools():  # S9-T01
    st = j(t.est_director_watch_status())
    assert st["enabled"] and st["interval_minutes"] == 15 and st["last_run"] is None
    run = j(t.est_director_watch_now())
    assert run["ok"] and "new_notices" in run
    assert j(t.est_director_watch_status())["last_run"]
    box = j(t.est_director_inbox(unread_only=False))
    assert box["ok"] and isinstance(box["notices"], list)

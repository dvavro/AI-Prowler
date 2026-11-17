"""Reopen an approved estimate for changes; the next approval checks only what changed (2026-11-16, David).

"I just realized that I needed to revise the questions after approval and now it will not let me make changes, can we
make changes to approved estimate and then force a new approval only on items that changed."
"""
import pytest

from estimator.bids import service as bids
from estimator.context import personal_context
from estimator.errors import ConfirmationRequired, NotEditable
from estimator.estimating import quick, reopen, service

API = "/estimator-api"
CTX = personal_context()


@pytest.fixture
def approved(db):
    eid = service.create_estimate(db, CTX, "Patio slab")["id"]
    est = quick.answer(db, CTX, eid, "concrete", {"area_sqft": 400}, service.get_estimate(db, CTX, eid)["rev"])
    service.add_line_item(db, CTX, eid, est["rev"], kind="sub", description="Pump truck (subcontract)", quantity="1",
                          unit="ea", unit_cost_cents=62500)
    est = service.get_estimate(db, CTX, eid)
    service.set_status(db, CTX, eid, est["rev"], "approved")
    return eid


def _detail(call, eid):
    return call("GET", f"{API}/estimates/{eid}/detail").json()


def test_an_approved_estimate_can_be_reopened_after_asking(db, call, approved):
    d = _detail(call, approved)
    assert d["can_reopen"] and not d["can_edit"] and d["since_approval"] is None
    with pytest.raises(NotEditable, match="reopen it for changes"):          # the error says how
        service.add_line_item(db, CTX, approved, d["estimate"]["rev"], kind="material", description="x", quantity="1",
                              unit="ea", unit_cost_cents=100)
    ask = call("POST", f"{API}/estimates/{approved}/reopen", {"rev": d["estimate"]["rev"]}).json()
    assert ask["needs_confirmation"] and "goes back to draft" in ask["question"]
    assert service.get_estimate(db, CTX, approved)["status"] == "approved"   # nothing yet
    out = call("POST", f"{API}/estimates/{approved}/reopen",
               {"rev": d["estimate"]["rev"], "reason": "revise the answers", "confirm": True}).json()
    assert out["status"] == "draft" and out["reopened"]
    d = _detail(call, approved)
    assert d["can_edit"] and not d["can_reopen"]
    assert d["since_approval"]["count"] == 0 and "Nothing has changed" in d["since_approval"]["summary"]


def test_only_what_changed_is_listed_for_the_next_approval(db, call, approved):
    rev = service.get_estimate(db, CTX, approved)["rev"]
    reopen.reopen(db, CTX, approved, rev, confirm=True)
    est = service.get_estimate(db, CTX, approved)
    lines_before = sum(len(s["lines"]) for s in est["sections"])
    est = quick.answer(db, CTX, approved, "concrete", {"area_sqft": 400, "thickness_in": "5"}, est["rev"])
    s = _detail(call, approved)["since_approval"]
    thick = [a for a in s["answers"] if a["question"] == "thickness_in"]
    assert len(thick) == 1 and thick[0]["to"] == "5" and thick[0]["from"] in ("4", None)
    assert thick[0]["label"] != "thickness_in"                               # the question's own label
    changed = [ln for ln in s["lines"] if ln["change"] == "changed"]
    assert changed and all(ln["trade"] == "Concrete" for ln in changed)       # the concrete got thicker
    assert not any("Pump truck" in ln["description"] for ln in s["lines"])    # the hand line didn't change
    assert s["unchanged_lines"] == lines_before - len(changed)
    assert s["total_from"] != s["total_to"]
    # Approved again: nothing is listed any more.
    service.set_status(db, CTX, approved, service.get_estimate(db, CTX, approved)["rev"], "approved")
    assert reopen.changes_since_approval(db, CTX, approved) is None


def test_added_and_removed_lines_are_listed(db, call, approved):
    reopen.reopen(db, CTX, approved, service.get_estimate(db, CTX, approved)["rev"], confirm=True)
    est = service.get_estimate(db, CTX, approved)
    pump = next(ln for s in est["sections"] for ln in s["lines"] if ln["description"].startswith("Pump"))
    from estimator.estimating import assemblies
    assemblies.update_line_item(db, CTX, approved, est["rev"], pump["id"], remove=True, reason="no pump", confirm=True)
    est = service.get_estimate(db, CTX, approved)
    service.add_line_item(db, CTX, approved, est["rev"], kind="equipment", description="Bobcat day", quantity="1",
                          unit="ea", unit_cost_cents=40000)
    s = reopen.changes_since_approval(db, CTX, approved)
    got = {(ln["change"], ln["description"]) for ln in s["lines"]}
    assert ("removed", "Pump truck (subcontract)") in got and ("added", "Bobcat day") in got


# ---------------------------------------------------------------- after the quote went out (2026-11-16, David)
# "We also will need the option to submit and update the bid/quote/estimate when the customer asks for additional
# work or changes his mind on what he wants. It's got to be flexible."

CUSTOMER = {"name": "Pat Smith", "email": "pat@example.com", "address": "1 Main St"}


def _sent(db, eid):
    b = bids.generate(db, CTX, eid, customer=CUSTOMER)
    bids.send(db, CTX, b["id"], confirm=True)
    return bids._load(db, CTX, b["id"])


def test_a_sent_quote_is_replaced_by_an_updated_one_that_says_what_changed(db, call, approved, fake_host):
    first = _sent(db, approved)
    assert service.get_estimate(db, CTX, approved)["status"] == "sent"
    d = _detail(call, approved)
    assert d["can_reopen"]
    ask = call("POST", f"{API}/estimates/{approved}/reopen", {"rev": d["estimate"]["rev"]}).json()
    assert first["number"] in ask["question"] and "replaced" in ask["question"]
    out = reopen.reopen(db, CTX, approved, d["estimate"]["rev"], reason="customer wants it thicker", confirm=True)
    assert out["status"] == "draft" and out["replaced_bids"] == [first["number"]]
    assert bids._load(db, CTX, first["id"])["status"] == "void"
    # Change it, approve it again, and make the new quote.
    est = service.get_estimate(db, CTX, approved)
    quick.answer(db, CTX, approved, "concrete", {"area_sqft": 400, "thickness_in": "5"}, est["rev"])
    service.set_status(db, CTX, approved, service.get_estimate(db, CTX, approved)["rev"], "approved")
    new = bids.generate(db, CTX, approved, customer=CUSTOMER)
    assert new["number"].endswith("-2")
    snap = bids._load(db, CTX, new["id"])["snapshot"]
    assert snap["replaces"]["number"] == first["number"] and snap["replaces"]["total_cents"] == first["total_cents"]
    assert any(c["change"] == "changed" for c in snap["replaces"]["changes"])           # the concrete line went up
    html = open(new["html_path"], encoding="utf-8").read()
    assert f"Updated quote: this replaces quote {first['number']}" in html and "What changed" in html
    bids.send(db, CTX, new["id"], confirm=True)
    assert "updated quote" in fake_host.named("send_email")[-1]["subject"]
    assert service.get_estimate(db, CTX, approved)["status"] == "sent"


# ---------------------------------------------------------------- change orders after the customer accepted

def test_after_the_customer_accepts_more_work_is_a_change_order(db, call, approved, fake_host):
    first = _sent(db, approved)
    done = bids.convert_to_job(db, CTX, first["id"], confirm=True, customer=CUSTOMER)
    job_id = done["job_id"]
    assert job_id and service.get_estimate(db, CTX, approved)["status"] == "won"
    d = _detail(call, approved)
    assert not d["can_reopen"] and d["can_change_order"]
    with pytest.raises(NotEditable, match="change order"):
        reopen.reopen(db, CTX, approved, d["estimate"]["rev"], confirm=True)
    # Make it: it asks first, then a new estimate just for the extra work, pointing at the accepted one.
    ask = call("POST", f"{API}/estimates/{approved}/change-order", {"change_summary": "extend the patio 10 ft"}).json()
    assert ask["needs_confirmation"] and first["number"] in ask["question"]
    co = call("POST", f"{API}/estimates/{approved}/change-order",
              {"change_summary": "extend the patio 10 ft", "confirm": True}).json()
    assert co["title"].endswith("Change order 1") and co["status"] == "draft"
    assert co["change_order"]["of_estimate_id"] == approved and co["change_order"]["job_id"] == job_id
    # Price the extra work, approve it, and make its quote: in addition to the accepted quote.
    service.add_line_item(db, CTX, co["id"], co["rev"], kind="material", description="Extra 10 ft of patio",
                          quantity="1", unit="ea", unit_cost_cents=50000)
    service.set_status(db, CTX, co["id"], service.get_estimate(db, CTX, co["id"])["rev"], "approved")
    cb = bids.generate(db, CTX, co["id"], customer=CUSTOMER)
    snap = bids._load(db, CTX, cb["id"])["snapshot"]
    assert snap["change_order"]["n"] == 1 and snap["change_order"]["of_number"] == first["number"]
    assert snap["change_order"]["job_total_cents"] == first["total_cents"] + cb["total_cents"]
    assert "Change order 1 to your accepted quote" in open(cb["html_path"], encoding="utf-8").read()
    bids.send(db, CTX, cb["id"], confirm=True)
    assert "change order" in fake_host.named("send_email")[-1]["subject"]
    # Accepted: an approved quote for it, and the same job's amount goes up - no second job.
    with pytest.raises(ConfirmationRequired, match=job_id):
        bids.convert_to_job(db, CTX, cb["id"], confirm=False)
    jobs_before = len(fake_host.named("create_job"))
    out = bids.convert_to_job(db, CTX, cb["id"], confirm=True)
    assert len(fake_host.named("create_job")) == jobs_before
    upd = fake_host.named("update_job_spreadsheet")[-1]
    assert upd["job_identifier"] == job_id and upd["id_column"] == "JobID"
    assert upd["updates"]["Quote Amount ($)"] == bids.dollars(first["total_cents"] + cb["total_cents"])
    assert out["change_order"]["job_total_cents"] == first["total_cents"] + cb["total_cents"]
    listed = _detail(call, approved)["change_orders"]
    assert [(c["n"], c["status"]) for c in listed] == [(1, "won")]


# ---------------------------------------------------------------- the quote's scope matches what's priced (2026-11-17)
# "The estimate for Quote Q-0004-2 does not match the quote sent with what's not included list. Vapor Barrier is
# priced in but listed as not included." The Bid Writer's draft was written before the estimate was reopened.

def _draft(db, eid, exclusions, created="2026-01-01T00:00:00+00:00"):
    import json
    return db.execute(
        "INSERT INTO agent_tasks (company_id, role, dedupe_key, estimate_id, state, result_json, created_at, updated_at)"
        " VALUES ('default', 'bid_writer', ?, ?, 'done', ?, ?, ?)",
        (f"bid:{eid}:test:{created}", eid, json.dumps({"actions": [{"action": "draft_bid", "scope_text": "Old scope",
                                                                    "exclusions": exclusions}]}), created, created)
    ).lastrowid


def test_a_draft_written_before_a_reopen_is_not_used(db, call, approved):
    from estimator.agents import queue
    task = _draft(db, approved, "- Vapor barrier")
    assert queue.latest_draft(db, CTX, approved)["task_id"] == task             # fresh: it would be used
    reopen.reopen(db, CTX, approved, service.get_estimate(db, CTX, approved)["rev"], confirm=True)
    assert queue.latest_draft(db, CTX, approved) is None                         # stale after the reopen
    with pytest.raises(Exception, match="before the estimate was reopened"):
        queue.apply_draft(db, CTX, task, confirm=True)
    newer = _draft(db, approved, "- Permits", created=service._now())            # written after: used again
    assert queue.latest_draft(db, CTX, approved)["task_id"] == newer


def test_not_included_never_lists_something_the_quote_prices(db, approved):
    snap = {"sections": [{"lines": [{"description": "Vapor barrier 10 mil poly"},
                                    {"description": "Pump truck (subcontract)"}]}]}
    excl = "- Permits and fees\n- Vapor barrier\n- Removal or demolition of existing concrete or structures\n- Pump truck"
    kept, dropped = bids.drop_priced_exclusions(excl, snap)
    assert dropped == ["Vapor barrier", "Pump truck"]
    assert "Permits" in kept and "Removal or demolition" in kept and "Vapor" not in kept
    # On a real quote: the dropped item is off the "Not included" list and the person is told.
    out = bids.generate(db, CTX, approved, exclusions="- Pump truck (subcontract)\n- Permits")
    assert any("Pump truck" in w for w in out["warnings"])
    assert "Pump truck" not in (bids._load(db, CTX, out["id"])["exclusions"] or "")


def test_a_change_order_needs_an_accepted_quote(db, call, approved):
    body = call("POST", f"{API}/estimates/{approved}/change-order", {"change_summary": "more", "confirm": True}).json()
    assert not body.get("ok") and "reopen it for changes" in str(body)
    assert not _detail(call, approved)["can_change_order"]

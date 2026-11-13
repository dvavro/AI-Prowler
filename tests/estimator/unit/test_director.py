"""Sprint 3: Estimating Director — playbooks, triage, settings, quick-quote lane (S3-D..)."""
import json

import pytest

from estimator.context import RequestContext, personal_context
from estimator.director import engine
from estimator.director.playbooks import PlaybookError, get_playbooks, load_playbooks, parse_playbook
from estimator.director.settings import DEFAULTS, get_settings, update_settings
from estimator.director.triage import triage
from estimator.errors import InvalidInput, NotEditable, NotFound, PermissionDenied, StaleRevision
from estimator.estimating import service
from estimator.modules.registry import ModuleRegistry
from estimator.pricing.price_book import get_price, set_price

CTX = personal_context()
REG = ModuleRegistry().load()
OFFICE = RequestContext(role="office", user_id="sue", mode="server")
REVIEWER = RequestContext(role="reviewer", user_id="rita", mode="server")


# ---------------------------------------------------------------- playbooks

def test_shipped_playbooks_load_and_cover_every_lane():  # S3-D01
    books = load_playbooks()
    # 2026-11-12: the project lane - every project made on the Projects screen gets a Director job.
    assert {pb.lane for pb in books.values()} == {"quick_quote", "standard_estimate", "full_takeoff", "project"}
    assert all(pb.available for pb in books.values())        # the full takeoff lane works from Sprint 14
    for pb in books.values():
        assert any(s.action == "approve" and s.checkpoint for s in pb.stages)


GOOD = {"id": "x", "lane": "quick_quote", "stages": [
    {"id": "a", "agent": "intake", "action": "collect_answers"},
    {"id": "b", "agent": "director", "action": "approve", "checkpoint": True},
    {"id": "c", "agent": "bid_writer", "action": "write_bid"}]}


@pytest.mark.parametrize("mutate, msg", [
    (lambda r: r.update(lane="moon"), "lane must be one of"),
    (lambda r: r["stages"][0].update(agent="wizard"), "agent must be one of"),
    (lambda r: r["stages"][0].update(action="dance"), "action must be one of"),
    (lambda r: r["stages"][1].update(checkpoint=False), "must be a checkpoint"),
    (lambda r: r["stages"].pop(1), "needs an approval checkpoint before it"),
    (lambda r: r["stages"][1].update(id="a"), "duplicate stage id"),
    (lambda r: r.pop("stages"), "missing required field"),
])
def test_bad_playbooks_rejected(mutate, msg):  # S3-D02
    raw = json.loads(json.dumps(GOOD))
    mutate(raw)
    with pytest.raises(PlaybookError, match=msg):
        parse_playbook(raw, "test.yaml")


def test_playbook_file_name_must_match_and_all_lanes_needed(tmp_path):  # S3-D03
    (tmp_path / "wrong.yaml").write_text(json.dumps(GOOD), encoding="utf-8")
    with pytest.raises(PlaybookError, match="must match the file name"):
        load_playbooks(tmp_path)
    (tmp_path / "wrong.yaml").unlink()
    (tmp_path / "x.yaml").write_text(json.dumps(GOOD), encoding="utf-8")
    with pytest.raises(PlaybookError, match="no playbook for lanes"):
        load_playbooks(tmp_path)


# ---------------------------------------------------------------- triage

TRIAGE_CASES = [
    ("Customer wants their driveway pressure washed and sealed", "quick_quote", "pressure_washing"),
    ("wash my house and driveway", "quick_quote", "pressure_washing"),
    ("soft wash the roof please", "quick_quote", "pressure_washing"),
    ("need a quote to clean a 3 bedroom house", "quick_quote", "house_cleaning"),
    ("move-out clean for an apartment", "quick_quote", "house_cleaning"),
    ("biweekly maid service, 2 bed 1 bath", "quick_quote", "house_cleaning"),
    ("handyman to hang shelves and fix a door", "quick_quote", "generic_service"),
    ("replace the roof on the Smith house", "standard_estimate", "roofing"),
    ("pour a concrete slab for a shed", "standard_estimate", "concrete"),
    ("new hardwood flooring in the living room", "standard_estimate", "flooring"),
    ("install a new fence along the back yard", "standard_estimate", "fencing"),
    # Sprint 5 services
    ("clean the windows on my 2 story house", "quick_quote", "window_cleaning"),
    ("wash my windows", "quick_quote", "window_cleaning"),
    ("pool cleaning every week", "quick_quote", "pool_service"),
    ("my pool is green", "quick_quote", "pool_service"),
    ("we have ants and spiders", "quick_quote", "pest_control"),
    ("need an exterminator for roaches", "quick_quote", "pest_control"),
    ("haul away an old couch and fridge", "quick_quote", "junk_removal"),
    ("garage clean out, about half a truck", "quick_quote", "junk_removal"),
    ("mow my lawn every two weeks", "quick_quote", "landscaping_maintenance"),
    ("lawn care and hedge trimming", "quick_quote", "landscaping_maintenance"),
    ("pool deck pressure washing", "quick_quote", "pressure_washing"),
    ("clean out the gutters", "quick_quote", "generic_service"),
    ("my pool needs weekly cleaning", "quick_quote", "pool_service"),
    ("clean my house every two weeks", "quick_quote", "house_cleaning"),
    ("need cleaners for a 2 bedroom apartment", "quick_quote", "house_cleaning"),
    ("replace the windows", "standard_estimate", "windows_doors"),
    ("new landscaping with pavers", "standard_estimate", "landscaping"),
]


@pytest.mark.parametrize("text, lane, module", TRIAGE_CASES)
def test_triage_lanes(text, lane, module):  # S3-D04
    r = triage(text, REG)
    assert r.lane == lane and r.module_id == module, r.as_dict()


def test_triage_plans_module_and_unclear():  # S3-D05
    assert triage("anything", REG, has_plans=True).lane == "full_takeoff"
    assert triage("", REG, module_id="house_cleaning").module_id == "house_cleaning"
    r = triage("can you help with this job?", REG)
    assert r.lane is None and r.question and "pressure_washing" in r.candidates
    with pytest.raises(NotFound):
        triage("x", REG, module_id="unicorn_grooming")


# ---------------------------------------------------------------- settings

def test_settings_defaults_and_update(db):  # S3-D06
    s = get_settings(db, "default")
    assert s["quick_send_limit_cents"] == 10000 and s["calendar_booking_enabled"] is False
    assert s["customer_intake_enabled"] is False and s == DEFAULTS
    out = update_settings(db, CTX, {"quick_send_limit_cents": "25000", "calendar_booking_enabled": "yes",
                                    "briefing_time": "06:30"})
    assert out["settings"]["quick_send_limit_cents"] == 25000 and out["settings"]["calendar_booking_enabled"] is True
    assert get_settings(db, "default")["briefing_time"] == "06:30"
    ev = db.execute("SELECT action, before_json FROM estimate_events WHERE action = 'director_settings_changed'").fetchone()
    assert json.loads(ev["before_json"])["quick_send_limit_cents"] == 10000


@pytest.mark.parametrize("changes", [
    {"quick_send_limit_cents": -1}, {"quick_send_limit_cents": 1.5}, {"follow_up_days": 0},
    {"briefing_time": "7am"}, {"briefing_channel": "fax"}, {"calendar_booking_enabled": "maybe"}, {"colour": "red"},
])
def test_bad_settings_rejected(db, changes):  # S3-D07
    with pytest.raises(InvalidInput):
        update_settings(db, CTX, changes)


def test_only_owner_changes_settings(db):  # S3-D08
    with pytest.raises(PermissionDenied):
        update_settings(db, OFFICE, {"quick_send_limit_cents": 0})


# ---------------------------------------------------------------- quick-quote lane

def _start(db, text, ctx=CTX, **kw):
    return engine.start(db, ctx, text, registry=REG, **kw)


def test_director_asks_before_pricing_an_empty_job(db):  # S3-D09
    r = _start(db, "pressure wash please")
    assert r["job"]["lane"] == "quick_quote" and r["job"]["stage"] == "collect_answers"
    assert r["job"]["state"] == "waiting_on_user" and r["next_step"]["at_least_one"]
    assert r["estimate"]["total_cents"] == 0      # nothing priced yet


def test_director_required_questions(db):  # S3-D10
    r = _start(db, "clean a 3 bedroom house")
    assert set(r["job"]["open_questions"]) == {"bedrooms", "bathrooms", "sqft"}
    r = engine.next_step(db, CTX, r["job"]["id"], answers={"bedrooms": 3}, registry=REG)
    assert set(r["job"]["open_questions"]) == {"bathrooms", "sqft"}


def test_full_quick_flow_under_limit_one_tap_by_office(db):  # S3-D11
    set_price(db, "default", "gs_labor_hr", description="mine", kind="labor", unit="hr", cost_cents=4000)
    set_price(db, "default", "gs_trip_ea", description="mine", kind="other", unit="ea", cost_cents=3000)
    r = _start(db, "handyman service call to fix a door", OFFICE, answers={"hours": "1.5"})
    # 1.5 x $40 + $30 trip = $90, raised to the module's $100 minimum -> at the $100 one-tap limit
    assert r["job"]["stage"] == "approve" and r["estimate"]["total_cents"] == 10000
    assert r["next_step"]["approval"] == "one_tap" and "Tell the customer" in r["next_step"]["say"]
    r = engine.next_step(db, OFFICE, r["job"]["id"], approve=True, registry=REG)
    assert r["estimate"]["status"] == "approved" and r["job"]["stage"] == "write_bid"
    assert r["job"]["state"] == "waiting_on_user" and "email" in r["next_step"]["say"]   # Sprint 4: bid made


def test_over_limit_needs_owner_or_reviewer(db):  # S3-D12
    r = _start(db, "clean a house", OFFICE,
               answers={"bedrooms": 3, "bathrooms": 2, "sqft": 1800})
    assert r["estimate"]["total_cents"] == 26750 and r["next_step"]["approval"] == "full"
    with pytest.raises(PermissionDenied):
        engine.next_step(db, OFFICE, r["job"]["id"], approve=True, registry=REG)
    r = engine.next_step(db, REVIEWER, r["job"]["id"], approve=True, confirm_sample_prices=True, registry=REG)
    assert r["estimate"]["status"] == "approved"


def test_sample_prices_block_approval_until_confirmed(db):  # S3-D13
    r = _start(db, "pressure wash", answers={"driveway_sqft": 1000})
    assert r["next_step"]["sample_prices"] == ["pw_driveway_sqft"]
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, registry=REG)
    assert r["estimate"]["status"] == "draft" and "sample prices" in r["notes"][0]
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, registry=REG)
    assert r["estimate"]["status"] == "approved"


def test_limit_setting_changes_the_checkpoint(db):  # S3-D14
    update_settings(db, CTX, {"quick_send_limit_cents": 50000})
    r = _start(db, "clean a house", OFFICE, answers={"bedrooms": 3, "bathrooms": 2, "sqft": 1800})
    assert r["next_step"]["approval"] == "one_tap"
    update_settings(db, CTX, {"quick_send_limit_cents": 0})
    r = _start(db, "clean a house", OFFICE, answers={"bedrooms": 3, "bathrooms": 2, "sqft": 1800})
    assert r["next_step"]["approval"] == "full"


def test_new_answers_reprice_and_approved_is_locked(db):  # S3-D15
    r = _start(db, "pressure wash", answers={"driveway_sqft": 2000})
    first = r["estimate"]["total_cents"]
    r = engine.next_step(db, CTX, r["job"]["id"], answers={"deck_sqft": 300}, registry=REG)
    assert r["estimate"]["total_cents"] > first and r["job"]["stage"] == "approve"
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, registry=REG)
    with pytest.raises(NotEditable):
        engine.next_step(db, CTX, r["job"]["id"], answers={"deck_sqft": 0}, registry=REG)


def test_bad_and_unknown_answers(db):  # S3-D16
    r = _start(db, "pressure wash", answers={"driveway_sqft": 500, "colour": "blue", "condition": "filthy"})
    assert r["job"]["state"] == "waiting_on_user" and "condition" not in r["job"]["answers"]
    assert any("colour" in n for n in r["notes"]) and "didn't work" in r["next_step"]["say"]
    r = engine.next_step(db, CTX, r["job"]["id"], answers={"condition": "heavy"}, registry=REG)
    assert r["job"]["stage"] == "approve"


def test_unclear_request_then_module_chosen(db):  # S3-D17
    r = _start(db, "can you help me with a quote")
    assert r["job"]["lane"] is None and r["job"]["stage"] == "triage" and r["next_step"]["ask"]
    r = engine.next_step(db, CTX, r["job"]["id"], module_id="house_cleaning", registry=REG)
    assert r["job"]["lane"] == "quick_quote" and r["job"]["open_questions"]

def _title(db, estimate_id):
    return db.execute("SELECT title FROM estimates WHERE id = ?", (estimate_id,)).fetchone()[0]


def test_start_titles_job_by_chosen_service_not_stale_request(db):  # Bugfix 2026-11-11
    # A house-cleaning quote started with the stale request text "window cleaning"
    # used to show up in Projects as "window cleaning".
    r = _start(db, "window cleaning", module_id="house_cleaning")
    assert r["job"]["module_id"] == "house_cleaning"
    assert _title(db, r["job"]["estimate_id"]) == "House Cleaning"
    # The request text still names the service it mentions.
    r = _start(db, "clean a 3 bedroom house")
    assert r["job"]["module_id"] == "house_cleaning"
    assert _title(db, r["job"]["estimate_id"]) == "clean a 3 bedroom house"
    # No request text at all: the title is the service name, not its id.
    r = _start(db, "", module_id="house_cleaning")
    assert _title(db, r["job"]["estimate_id"]) == "House Cleaning"


def test_trades_without_modules_and_full_lane_wait_for_feature(db):  # S3-D18 (updated Sprints 7, 13, 14)
    # every planned trade has a module now; a company that turned one off still gets the hand-pricing path
    no_fence = ModuleRegistry().load()
    no_fence.modules.pop("fencing")
    r = engine.start(db, CTX, "install a new fence along the back", registry=no_fence)
    assert r["job"]["lane"] == "standard_estimate" and r["job"]["state"] == "waiting_on_feature"
    assert "fencing job" in r["next_step"]["say"] and "roofing" in r["next_step"]["ask"] and r["estimate"]["id"]
    r = _start(db, "bid this house", has_plans=True)
    assert r["job"]["lane"] == "full_takeoff" and r["job"]["open_questions"] == ["trades"]
    assert "Which trades" in r["next_step"]["say"]


def test_job_status_board_scoping_and_audit(db):  # S3-D19
    a = _start(db, "pressure wash", answers={"driveway_sqft": 900})
    _start(db, "clean a house", OFFICE)
    st = engine.status(db, CTX, a["job"]["id"])
    assert [s["stage"] for s in st["steps"]][:2] == ["triage", "collect_answers"]
    assert engine.board(db, CTX)["count"] == 2
    assert engine.board(db, OFFICE, mine=True)["count"] == 1
    other = RequestContext(company_id="acme", user_id="z", mode="server")
    with pytest.raises(NotFound):
        engine.status(db, other, a["job"]["id"])
    assert engine.board(db, other)["count"] == 0
    acts = [e["action"] for e in service.events(db, CTX, a["estimate"]["id"])]
    assert "director_job_started" in acts and "quick_estimate_answered" in acts


def test_stale_job_rev_rejected(db):  # S3-D20
    r = _start(db, "clean a house")
    old = r["job"]["rev"]
    engine.next_step(db, CTX, r["job"]["id"], answers={"bedrooms": 2}, registry=REG)
    with pytest.raises(StaleRevision):
        engine.next_step(db, CTX, r["job"]["id"], answers={"bathrooms": 1}, rev=old, registry=REG)


def test_reviewer_cannot_start_jobs(db):  # S3-D21
    with pytest.raises(PermissionDenied):
        _start(db, "clean a house", REVIEWER)


def test_director_never_prices_on_its_own(db, monkeypatch):  # S3-D22
    """Totals come only from the quick-estimate engine: break the engine and the Director has no number."""
    from estimator.estimating import quick
    monkeypatch.setattr(quick, "answer", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("engine down")))
    with pytest.raises(RuntimeError):
        _start(db, "pressure wash", answers={"driveway_sqft": 900})


# ---------------------------------------------------------------- Sprint 4: write, send, follow up

def test_quick_lane_end_to_end_one_tap_send_win_convert(db, fake_host):  # S4-D01
    set_price(db, "default", "gs_labor_hr", description="mine", kind="labor", unit="hr", cost_cents=4000)
    set_price(db, "default", "gs_trip_ea", description="mine", kind="other", unit="ea", cost_cents=3000)
    r = _start(db, "handyman to fix a door", OFFICE, answers={"hours": "1.5"},
               customer={"name": "Bo Diaz", "email": "bo@example.com"})
    assert r["next_step"]["approval"] == "one_tap"
    r = engine.next_step(db, OFFICE, r["job"]["id"], approve=True, send=True, confirm=True, registry=REG)   # one tap
    assert fake_host.named("send_email")[0]["to"] == "bo@example.com"
    assert r["job"]["stage"] == "follow_up" and r["job"]["state"] == "waiting_on_customer"
    assert r["next_step"]["follow_up_on"]
    r = engine.next_step(db, OFFICE, r["job"]["id"], outcome="won", registry=REG)
    assert r["job"]["state"] == "waiting_on_user" and "Make it a job" in r["next_step"]["say"]
    r = engine.next_step(db, OFFICE, r["job"]["id"], convert=True, confirm=True, service_date="2026-11-21", registry=REG)
    assert r["job"]["state"] == "done" and r["estimate"]["status"] == "won"
    assert fake_host.named("create_job")[0]["updates"]["Service Date"] == "2026-11-21"
    assert any("JOB-0001" in n for n in r["notes"])


def test_send_waits_for_email_then_sends(db, fake_host):  # S4-D02
    r = _start(db, "pressure wash", answers={"driveway_sqft": 1000})
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, registry=REG)
    assert r["job"]["stage"] == "write_bid" and "email" in r["next_step"]["say"]
    r = engine.next_step(db, CTX, r["job"]["id"], send=True, confirm=True, registry=REG)
    assert any("email address" in n for n in r["notes"]) and fake_host.named("send_email") == []
    r = engine.next_step(db, CTX, r["job"]["id"], customer={"email": "pat@example.com"}, registry=REG)
    assert "pat@example.com" in r["next_step"]["say"]
    r = engine.next_step(db, CTX, r["job"]["id"], send=True, confirm=True, registry=REG)
    assert r["job"]["stage"] == "follow_up" and fake_host.named("send_email")[0]["to"] == "pat@example.com"


def test_lost_quote_closes_job(db, fake_host):  # S4-D03
    r = _start(db, "pressure wash", answers={"driveway_sqft": 1000}, customer={"name": "Al", "email": "al@x.com"})
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, send=True, confirm=True, registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], outcome="lost", registry=REG)
    assert r["job"]["state"] == "done" and r["estimate"]["status"] == "lost"
    with pytest.raises(InvalidInput):
        engine.next_step(db, CTX, r["job"]["id"], outcome="maybe", registry=REG)


def test_reviewer_approves_then_staff_sends(db, fake_host):  # S4-D04
    r = _start(db, "clean a house", OFFICE, answers={"bedrooms": 3, "bathrooms": 2, "sqft": 1800},
               customer={"email": "kim@example.com"})
    r = engine.next_step(db, REVIEWER, r["job"]["id"], approve=True, confirm_sample_prices=True, registry=REG)
    assert r["job"]["waiting_on"] == "staff"
    r = engine.next_step(db, OFFICE, r["job"]["id"], send=True, confirm=True, registry=REG)
    assert r["job"]["stage"] == "follow_up"


def test_failed_step_is_recorded_not_stale(db, fake_host):  # S5-D01
    from estimator.integrations import host
    fake_host.fail["send_email"] = "❌ SMTP error: Connection unexpectedly closed"
    host.set_host(fake_host.funcs())
    r = _start(db, "pressure wash", answers={"driveway_sqft": 1000}, customer={"email": "al@x.com"})
    with pytest.raises(host.HostError):
        engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, send=True, confirm=True, registry=REG)
    st = engine.status(db, CTX, r["job"]["id"])
    assert st["job"]["stage"] == "write_bid" and st["job"]["state"] == "waiting_on_user"
    assert st["next_step"]["error"] == "host_error" and "didn't work" in st["next_step"]["say"]
    assert st["steps"][-1]["state"] == "failed"
    fake_host.fail.clear()
    r = engine.next_step(db, CTX, r["job"]["id"], send=True, confirm=True, registry=REG)       # retry once email works
    assert r["job"]["stage"] == "follow_up"

"""Sprint 9 (re-ordered, Director part of planned Sprint 10): the watcher, notices, scheduled briefing (S9-..)."""
import time
from datetime import date, datetime, timedelta

import pytest

from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.director import engine, watch
from estimator.director.settings import get_settings, update_settings
from estimator.errors import InvalidInput
from estimator.estimating import quick, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


def at(days=0, hour=8, minute=0):
    """A local time `days` from today."""
    d = date.today() + timedelta(days=days)
    return datetime(d.year, d.month, d.day, hour, minute).astimezone()


def kinds(result):
    return [n["kind"] for n in result["new_notices"]]


def _sent_bid(db):
    e = service.create_estimate(db, CTX, "Smith clean")
    e = quick.answer(db, CTX, e["id"], "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, e["rev"], REG)
    e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
    b = bids.generate(db, CTX, e["id"], customer={"email": "a@b.com"}, registry=REG)
    return bids.send(db, CTX, b["id"], confirm=True)


# ---------------------------------------------------------------- briefing on a schedule

def test_briefing_once_a_day_after_its_time(db):  # S9-W01
    r = watch.tick(db, CTX, at(0, 6, 30))
    assert r["briefing"] is None and r["new_notices"] == []
    r = watch.tick(db, CTX, at(0, 7, 5))
    assert r["briefing"]["via"] == "chat"
    box = watch.inbox(db, CTX)
    assert box["notices"][0]["kind"] == "briefing" and "All quiet" in box["notices"][0]["message"]
    assert watch.tick(db, CTX, at(0, 9))["briefing"] is None                 # not twice the same day
    assert watch.tick(db, CTX, at(1, 7, 1))["briefing"] is not None          # next day
    update_settings(db, CTX, {"briefing_enabled": False})
    assert watch.tick(db, CTX, at(2, 8))["briefing"] is None


def test_emailed_briefing_with_retry(db, fake_host):  # S9-W02
    update_settings(db, CTX, {"briefing_channel": "email", "briefing_email": "jamie@example.com"})
    fake_host.fail["send_email"] = "❌ SMTP login failed"
    r = watch.tick(db, CTX, at(0, 7, 30))
    assert r["briefing"]["via"] == "email" and "SMTP" in r["briefing"]["error"]
    note = watch.inbox(db, CTX)["notices"][0]
    assert note["kind"] == "briefing" and "SMTP" in note["delivery_error"]
    fake_host.fail.clear()
    r = watch.tick(db, CTX, at(0, 7, 45))
    assert r["email_retries"][0]["to"] == "jamie@example.com"
    sent = fake_host.named("send_email")
    assert sent[-1]["to"] == "jamie@example.com" and sent[-1]["subject"].startswith("Estimator briefing for")
    assert watch.tick(db, CTX, at(0, 8))["email_retries"] == []              # delivered, not sent again


# ---------------------------------------------------------------- quotes

def test_follow_up_notice_once(db, fake_host):  # S9-W03
    b = _sent_bid(db)
    assert "follow_up" not in kinds(watch.tick(db, CTX, at(1)))
    r = watch.tick(db, CTX, at(5))
    assert kinds(r).count("follow_up") == 1 and b["number"] in r["new_notices"][0]["message"]
    assert "follow_up" not in kinds(watch.tick(db, CTX, at(6)))


def test_expiring_then_auto_expired(db, fake_host):  # S9-W04
    b = _sent_bid(db)
    valid = date.fromisoformat(b["valid_until"])
    days = (valid - date.today()).days
    assert "expiring" in kinds(watch.tick(db, CTX, at(days - 2)))
    r = watch.tick(db, CTX, at(days + 1))
    assert r["expired_bids"] == [{"bid_id": b["id"], "number": b["number"]}]
    assert bids.preview(db, CTX, b["id"])["status"] == "expired"
    assert service.get_estimate(db, CTX, b["estimate_id"])["status"] == "expired"
    assert any(n["kind"] == "expired" for n in watch.inbox(db, CTX)["notices"])


def test_auto_expire_can_be_turned_off(db, fake_host):  # S9-W05
    update_settings(db, CTX, {"auto_expire_bids": False})
    b = _sent_bid(db)
    r = watch.tick(db, CTX, at(40))
    assert r["expired_bids"] == [] and bids.preview(db, CTX, b["id"])["status"] == "sent"


# ---------------------------------------------------------------- jobs

def test_review_reminder_repeats_each_period(db):  # S9-W06
    r = engine.start(db, CTX, "replace the roof", answers=ROOF, registry=REG)
    assert r["job"]["waiting_on"] == "reviewer"
    assert "review_reminder" not in kinds(watch.tick(db, CTX, at(1)))
    first = watch.tick(db, CTX, at(2))
    assert "review_reminder" in kinds(first) and "waited 2 days for a reviewer" in first["new_notices"][0]["message"]
    assert "review_reminder" not in kinds(watch.tick(db, CTX, at(3)))
    assert "review_reminder" in kinds(watch.tick(db, CTX, at(4)))           # reminded again after another period


def test_stuck_job(db):  # S9-W07
    r = engine.start(db, CTX, "pressure wash please", registry=REG)
    assert r["job"]["waiting_on"] == "user"
    out = watch.tick(db, CTX, at(2))
    assert "stuck" in kinds(out) and "hasn't moved in 2 days" in out["new_notices"][0]["message"]


def test_due_soon_and_overdue(db):  # S9-W08
    due = (date.today() + timedelta(days=1)).isoformat()
    engine.start(db, CTX, "replace the roof", answers=ROOF, due_date=due, registry=REG)
    assert "due_soon" in kinds(watch.tick(db, CTX, at(0)))
    assert "overdue" in kinds(watch.tick(db, CTX, at(2)))
    assert "overdue" not in kinds(watch.tick(db, CTX, at(3)))


def test_finished_and_sent_jobs_left_alone(db, fake_host):  # S9-W09
    due = (date.today() + timedelta(days=1)).isoformat()
    r = engine.start(db, CTX, "clean a house", answers={"bedrooms": 2, "bathrooms": 1, "sqft": 1000},
                     customer={"email": "kim@example.com"}, due_date=due, registry=REG)
    engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, send=True, confirm=True, registry=REG)
    out = watch.tick(db, CTX, at(3))
    assert not {"overdue", "due_soon", "stuck", "review_reminder"} & set(kinds(out))


# ---------------------------------------------------------------- inbox, settings, status

def test_inbox_read_and_unread(db):  # S9-I01
    engine.start(db, CTX, "pressure wash please", registry=REG)
    watch.tick(db, CTX, at(2, 8))
    box = watch.inbox(db, CTX)
    assert box["count"] == 2 and box["unread_left"] == 2                    # stuck + briefing
    box = watch.inbox(db, CTX, mark_read=True)
    assert box["unread_left"] == 0 and watch.inbox(db, CTX)["count"] == 0
    assert watch.inbox(db, CTX, unread_only=False)["count"] == 2


def test_watcher_settings(db):  # S9-S01
    s = get_settings(db, "default")
    assert s["watcher_enabled"] and s["watch_interval_minutes"] == 15 and s["auto_expire_bids"]
    with pytest.raises(InvalidInput, match="briefing_email"):
        update_settings(db, CTX, {"briefing_channel": "email"})
    with pytest.raises(InvalidInput, match="email address"):
        update_settings(db, CTX, {"briefing_email": "not-an-email"})
    with pytest.raises(InvalidInput):
        update_settings(db, CTX, {"watch_interval_minutes": 1})
    assert update_settings(db, CTX, {"due_soon_days": 5})["settings"]["due_soon_days"] == 5


def test_run_due_respects_interval_and_switch(db):  # S9-R01
    now = datetime.now().astimezone()
    assert [r["company_id"] for r in watch.run_due(now, conn=db)] == ["default"]
    assert watch.run_due(now + timedelta(minutes=5), conn=db) == []
    assert len(watch.run_due(now + timedelta(minutes=16), conn=db)) == 1
    update_settings(db, CTX, {"watcher_enabled": False})
    assert watch.run_due(now + timedelta(hours=2), conn=db) == []
    st = watch.status(db, CTX)
    assert st["last_run"] and st["enabled"] is False and st["running_in_background"] is False


def test_run_due_covers_every_company(db):  # S9-R02
    other = RequestContext(company_id="acme", user_id="ann", role="owner", mode="server")
    assert watch.companies(db) == ["default"]                                # a fresh install still gets checked
    engine.start(db, other, "pressure wash please", registry=REG)
    engine.start(db, CTX, "pressure wash please", registry=REG)
    done = {r["company_id"] for r in watch.run_due(conn=db)}
    assert done == {"default", "acme"}
    assert watch.inbox(db, other)["count"] >= 0 and watch.inbox(db, CTX)["count"] == watch.unread_count(db, CTX)


def test_background_thread(monkeypatch):  # S9-R03
    assert watch.start_background() is False                                # ESTIMATOR_WATCHER=off in tests
    calls = []
    monkeypatch.setattr(watch, "run_due", lambda *a, **k: calls.append(1) or [])
    monkeypatch.setenv("ESTIMATOR_WATCHER", "on")
    try:
        assert watch.start_background(poll_seconds=0.02) is True and watch.is_running()
        assert watch.start_background(poll_seconds=0.02) is True             # only one thread
        for _ in range(100):
            if calls:
                break
            time.sleep(0.02)
        assert calls
    finally:
        watch.stop_background()
    assert not watch.is_running()


def test_watcher_acts_as_director_in_audit(db, fake_host):  # S9-A01
    b = _sent_bid(db)
    days = (date.fromisoformat(b["valid_until"]) - date.today()).days
    watch.run_due(at(days + 1), conn=db)
    actors = {r["actor"] for r in db.execute("SELECT actor FROM estimate_events WHERE action = 'bid_status'")}
    assert actors == {"agent:director"}

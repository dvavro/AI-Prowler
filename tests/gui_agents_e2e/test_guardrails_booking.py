"""AG-GR-08, 10–13, 16, 17: Booking guardrails. A customer really books through the page's API (hold, code, verify), then the
Decide stage runs on Auto with one condition broken. The agent confirms only when every one holds.
"""
from __future__ import annotations

import datetime as dt
import itertools

import pytest

from conftest import START, code_from, http
from test_customer_book_quote import _services
from test_matrix import BK_STAGES, SD_STAGES, _marks, _new, all_off, off_stages

_n = itertools.count(1)
CODE = "ZAG-WIN"


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.clock(START + dt.timedelta(days=300 + next(_n)), "10:00")     # the code limit counts per hour and per IP
    b.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"], "booking_approval": "approve_all"})
    _services(b)
    yield b
    all_off(b)


def _setup(box, *, mode="auto", practice=False, can_confirm=True, per_day=50):
    box.settings(desk={"agent_enabled": True, "agent_shadow": False, "agent_bk_enabled": True, "agent_bk_shadow": practice,
                       "agent_bk_can_confirm": can_confirm, "agent_bk_confirm_per_day": per_day,
                       **off_stages("agent_stage_", SD_STAGES),
                       **off_stages("agent_bk_stage_", BK_STAGES, "decide", mode)})


def _windows(box):
    st, d = http("GET", box.base + f"/support-api/windows?service={CODE}")
    assert st == 200 and d["windows"], (st, d)
    return [w["key"] for w in d["windows"]]


def _book(box, key):
    n = next(_n)
    email = f"bk{n}@time-machine.test"
    st, h = http("POST", box.base + "/support-api/hold", {"service_code": CODE, "window_key": key})
    assert st == 200, (st, h)
    st, d = http("POST", box.base + "/support-api/start", {"name": f"ZAG Guard Booker {n}", "phone": f"386557{n:04d}",
                                                           "email": email, "send_by": "email"})
    assert st == 200, (st, d)
    code = code_from([m for m in box.outbox() if m.get("to") == email and "request code" in str(m.get("subject"))][-1]["body"])
    st, v = http("POST", box.base + "/support-api/verify", {
        "contact_id": d["contact_id"], "code": code, "path": "book", "service_code": CODE, "service": "ZAG Exterior windows",
        "address": {"street": "300 Flagler Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"},
        "window_key": key, "hold_id": h.get("hold_id", ""), "backups": [], "description": "ZAG"})
    assert st == 201, (st, v)
    box.last_token = v.get("token")
    box.last_job = v.get("job_id")
    return email


def _approve(key, conf=0.9):
    return [{"action": "bk_approve", "window_key": key, "why": "ZAG fits", "confidence": conf}]


def _run(box, rule, key=None, required=True):
    keys = _windows(box)
    key = key or keys[0]
    box.ai_reset("good", {"booking:decide": rule(keys)})
    marks = _marks(box)
    email = _book(box, key)
    props = []
    for _ in range(5):          # other tests' bookings can take the first passes; only this booking's answer counts
        box.agents_pass()
        props = [p for p in _new(box, marks, "BK")[1] if p["stage"] == "decide" and p["ref"] == box.last_job]
        if props:
            break
    assert props or not required, (_new(box, marks, "BK"), box.ai_calls())
    return (props[0] if props else None), email, keys


FIRST = lambda keys: _approve(keys[0])          # noqa: E731


def test_gr_all_conditions_hold_it_confirms(box):
    _setup(box)
    p, email, _ = _run(box, FIRST)
    assert p["status"] == "applied", p


@pytest.mark.parametrize("kw,why", [({"can_confirm": False}, "isn't allowed to confirm"),
                                    ({"mode": "suggest"}, "isn't allowed to confirm")], ids=["gr10-switch-off", "gr11-suggest"])
def test_gr_10_11_a_person_confirms(box, kw, why):
    _setup(box, **kw)
    p, *_ = _run(box, FIRST)
    assert p["status"] == "pending" and why in p["hold_reason"], p


def test_gr_12_practice_only_shows(box):
    _setup(box, practice=True)
    p, *_ = _run(box, FIRST)
    assert p["status"] == "practice", p


def test_gr_13_not_the_customers_time(box):
    _setup(box)
    p, *_ = _run(box, lambda keys: _approve(keys[1]), required=False)
    if p is None or "Refused by the rules" in (p["hold_reason"] or ""):   # that time had closed: refused, nothing done (F-25 shows it)
        return
    assert p["status"] == "pending" and "not the customer's own time" in p["hold_reason"], p


def test_gr_16_daily_cap(box):
    _setup(box, per_day=1)
    first, _, keys = _run(box, FIRST)
    assert first["status"] == "applied", first
    second, *_ = _run(box, lambda ks: _approve(ks[0]))
    assert second["status"] == "pending" and "daily limit" in second["hold_reason"], second


def test_gr_17_confidence_075_waits(box):
    _setup(box)
    p, *_ = _run(box, lambda keys: _approve(keys[0], 0.75))
    assert p["status"] == "pending" and "confidence 0.75" in p["hold_reason"], p


def test_gr_08_declining_is_high_risk_and_waits(box):
    _setup(box)
    p, *_ = _run(box, lambda keys: [{"action": "bk_decline", "body": "ZAG sorry", "why": "ZAG", "confidence": 0.9}])
    assert p["status"] == "pending" and "high risk" in p["hold_reason"], p

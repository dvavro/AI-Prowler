"""AG-GR-06, 14, 15, 18: a customer who texted STOP, an address outside the area, a booking flagged at Check, instant-booking limits."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_guardrails_booking import _approve, _book, _run, _setup, _windows, box  # noqa: F401 — the fixture
from test_matrix import SD_STAGES, _marks, _new, off_stages


def _stop(box, phone):
    """What the SMS webhook leaves behind when a number replies STOP."""
    p = Path(box.control("GET", "/state")["sandbox"]) / "sms_consent.json"
    p.write_text(json.dumps({"consents": [{"phone": phone, "consented": False, "name": "ZAG"}]}), encoding="utf-8")
    return p


def test_gr_06_ticket_reply_waits(box):
    f = _stop(box, "+13865550142")
    try:
        box.settings(desk={"agent_enabled": True, "agent_shadow": False, **off_stages("agent_stage_", SD_STAGES, "first_reply", "auto")})
        box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": "ZAG hello", "why": "ZAG", "confidence": 0.9}]})
        marks = _marks(box)
        st, d = box.desk("POST", "/tickets", {"kind": "external", "title": "ZAG opted out", "contact_name": "ZAG Stop",
                                              "contact_phone": "386-555-0142", "contact_email": "stop@time-machine.test"})
        assert st == 201, d
        box.agents_pass()
        props = [p for p in _new(box, marks, "SD")[1] if p["action"] == "reply"]
        assert props and props[0]["status"] == "pending" and "opted out" in props[0]["hold_reason"], props
    finally:
        f.unlink()


def test_gr_06_someone_else_is_not_held(box):
    f = _stop(box, "+13865559999")
    try:
        box.settings(desk={"agent_enabled": True, "agent_shadow": False, **off_stages("agent_stage_", SD_STAGES, "first_reply", "auto")})
        box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": "ZAG hello", "why": "ZAG", "confidence": 0.9}]})
        marks = _marks(box)
        st, d = box.desk("POST", "/tickets", {"kind": "external", "title": "ZAG not opted out", "contact_name": "ZAG Fine",
                                              "contact_phone": "386-555-0142", "contact_email": "fine@time-machine.test"})
        assert st == 201, d
        box.agents_pass()
        props = [p for p in _new(box, marks, "SD")[1] if p["action"] == "reply"]
        assert props and props[0]["status"] == "applied", props
    finally:
        f.unlink()


def test_gr_14_outside_the_area(box):
    _setup(box)
    keys = _windows(box)
    box.ai_reset("good", {"booking:decide": _approve(keys[0])})
    marks = _marks(box)
    _book(box, keys[0])                                         # in the area when booked: the page takes out-of-area as a call-back
    box.settings(desk={"booking_area_zips": ["90210"]})         # then the owner narrows the area
    try:
        box.agents_pass()
        props = [p for p in _new(box, marks, "BK")[1] if p["stage"] == "decide"]
        assert props and props[0]["status"] == "pending" and "outside the service area" in props[0]["hold_reason"], props
    finally:
        box.settings(desk={"booking_area_zips": []})


def test_gr_15_flagged_at_check(box):
    _setup(box)
    box.settings(desk={"agent_bk_stage_check": "auto"})
    keys = _windows(box)
    box.ai_reset("good", {"booking:check": [{"action": "bk_flag", "flag": "address_not_found", "why": "ZAG", "confidence": 0.9}],
                          "booking:decide": _approve(keys[0])})
    marks = _marks(box)
    _book(box, keys[0])
    props = []
    for _ in range(5):          # other tests' bookings can take the first passes
        box.agents_pass()
        props = [p for p in _new(box, marks, "BK")[1] if p["stage"] == "decide" and p["ref"] == box.last_job]
        if props:
            break
    assert props and props[0]["status"] == "pending" and "flagged at Check" in props[0]["hold_reason"], (props, _new(box, marks, "BK")[1])


def test_gr_18_instant_booking_limits(box):
    _setup(box)
    box.settings(desk={"booking_pre_min_days": 60})
    try:
        p, *_ = _run(box, lambda keys: _approve(keys[0]))
        assert p["status"] == "pending" and "instant-booking limits" in p["hold_reason"], p
    finally:
        box.settings(desk={"booking_pre_min_days": 0})

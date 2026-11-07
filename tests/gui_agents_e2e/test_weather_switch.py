"""David 4 Nov: an owner can ignore weather, with the agents on. Off means no forecast is fetched and the AI never sees one."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_customer_book_quote import _services
from test_env import CUST_RE, JOB_RE
from test_matrix import BK_STAGES, JB_STAGES, _marks, _new, all_off, off_stages
from test_guardrails_booking import _book, _windows
from test_stage_grid import _sql

_n = itertools.count(1)


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=8000 + 7 * next(_n))
    b.clock(b.today, "17:00")
    b.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"], "booking_approval": "approve_all"})
    _services(b)
    _sql(b, "UPDATE booking_services SET outdoor = 1")
    yield b
    all_off(b)


def _forecast_calls(box, since):
    return [m for m in box.blocked()[since:] if "open-meteo" in str(m)]


def _overfull_outdoor_job(box, service=None):
    """Scheduled tomorrow, an outdoor service, and an over-full day: Prep runs for a reason that isn't weather."""
    n = next(_n)
    service = service or _sql(box, "SELECT p.name FROM booking_services b JOIN service_pricing p ON p.service_code = b.service_code LIMIT 1")[0][0]
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Wx {n}", "Phone": "386-555-0179"})
    cid = re.search(CUST_RE, r).group(0)
    day = (box.today + dt.timedelta(days=1)).isoformat()
    r = box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": f"ZAG Wx {n}", "Service Type": service,
                                        "Street Address": "100 Flagler Ave", "Job Status": "Scheduled", "Service Date": day})
    jid = re.search(JOB_RE, r).group(0)
    _sql(box, "UPDATE jobs SET latitude = 29.03, longitude = -80.92, est_duration = 20, est_duration_unit = 'Hours' WHERE job_id = ?", (jid,))
    return jid


@pytest.mark.parametrize("on", [True, False], ids=["weather on", "weather off"])
def test_jobs_agent_prep_obeys_the_switch(box, on):
    box.ai_reset("good", {"job:prep": [{"action": "jb_note", "body": "ZAG", "why": "ZAG", "confidence": 0.9}]})
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False, "agent_jb_weather": on,
                       **off_stages("agent_jb_stage_", JB_STAGES, "prep", "auto")})
    marks, since = _marks(box), len(box.blocked())
    jid = _overfull_outdoor_job(box)
    box.agents_pass()
    assert [q for q in _new(box, marks, "JB")[0] if q["ref"] == jid and q["stage"] == "prep"], "Prep didn't run"
    assert bool(_forecast_calls(box, since)) is on, box.blocked()[since:]


def _renamed_service(box, name, outdoor):
    code = _sql(box, "SELECT service_code FROM booking_services LIMIT 1")[0][0]
    _sql(box, "UPDATE service_pricing SET name = ? WHERE service_code = ?", (name, code))
    _sql(box, "UPDATE booking_services SET outdoor = ?, label = NULL WHERE service_code = ?", (outdoor, code))
    return name


@pytest.mark.parametrize("name,outdoor,forecast", [("Window Cleaning", 0, False), ("Fountain Service", 1, True)],
                         ids=["unticked, name sounds outdoor", "ticked, name doesn't"])
def test_the_owners_outdoor_tick_decides_not_the_words_in_the_name(box, name, outdoor, forecast):
    """F-16: the tick was ignored."""
    box.ai_reset("good", {"job:prep": [{"action": "jb_note", "body": "ZAG", "why": "ZAG", "confidence": 0.9}]})
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False, "agent_jb_weather": True,
                       **off_stages("agent_jb_stage_", JB_STAGES, "prep", "auto")})
    since = len(box.blocked())
    _overfull_outdoor_job(box, _renamed_service(box, name, outdoor))
    box.agents_pass()
    assert bool(_forecast_calls(box, since)) is forecast, box.blocked()[since:]


@pytest.mark.parametrize("on", [True, False], ids=["weather on", "weather off"])
def test_booking_agent_obeys_its_switch(box, on):
    box.ai_reset("good", {"booking:track": [{"action": "no_action", "why": "ZAG", "confidence": 0.9}]})
    box.settings(desk={"agent_enabled": True, "agent_shadow": False, "agent_bk_enabled": True, "agent_bk_shadow": False,
                       "agent_bk_weather": on, "agent_bk_check_hour": 9, **off_stages("agent_bk_stage_", BK_STAGES, "track", "auto")})
    _book(box, _windows(box)[0])
    jid = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
    tomorrow = (box.today + dt.timedelta(days=1)).isoformat()
    _sql(box, "UPDATE booking_requests SET status = 'scheduled' WHERE job_id = ?", (jid,))
    _sql(box, "UPDATE jobs SET job_status = 'Scheduled', service_date = ?, latitude = 29.03, longitude = -80.92 WHERE job_id = ?", (tomorrow, jid))
    marks = _marks(box)
    box.agents_pass()
    queued = [q for q in _new(box, marks, "BK")[0] if q["ref"] == jid and q["stage"] == "track"]
    assert bool(queued) is on, queued

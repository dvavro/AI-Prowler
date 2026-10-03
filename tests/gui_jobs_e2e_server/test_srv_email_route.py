"""Server mode — SRV-SCOPE-13: 📧 Email Route as field crew for another crew.

Rule (email_route_now docstring): a field_crew caller can only email their OWN
route — any crew they pass is replaced with their own name — and it goes to
their own email. Owner / manager / staff may email any crew's route.

How this is tested with ZERO chance of a real email: the test first makes
sure NO route exists on the sandbox date. email_route_now then can only reply
"⚠️ Nothing to email — no route is saved for <date> (<crew>)", and the crew
named in that reply shows whose route the server looked up. So these calls go
straight to the server (the write guard would otherwise record, not send,
email_route_now) — the empty-route precondition is asserted before every call.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_email_route
"""
import json
import logging

import pytest

from api import http, iso_date, parse_records
from safety import SANDBOX_DATE

log = logging.getLogger("e2e_srv")

CREW = "Samual Cronin"
OTHER = "Vicki Vavro"


def _no_route_on_sandbox_date(owner_api):
    rows = parse_records(owner_api.call("read_job_spreadsheet",
                                        {"sheet_name": "Route_Planner", "max_rows": 1000}, expect_ok=False))
    return not [r for r in rows if iso_date(r.get("Route Date", "")) == SANDBOX_DATE]


def _email_route(srv, key, crew):
    st, raw = http("POST", srv["origin"] + "/pwa-api",
                   {"tool": "email_route_now", "args": {"route_date": SANDBOX_DATE, "crew": crew}},
                   token=srv["users"][key].access_token, timeout=60)
    try:
        return st, str(json.loads(raw).get("result", ""))
    except ValueError:
        return st, raw[:200]


@pytest.fixture
def empty_day(clean_slate, owner_api):
    if not _no_route_on_sandbox_date(owner_api):
        pytest.fail(f"SAFETY: a route exists on {SANDBOX_DATE} — email_route_now could send a real "
                    "email. Not calling it.")
    yield


@pytest.mark.parametrize("asked", [OTHER, ""])
def test_SRV_SCOPE_13_crew_email_route_is_forced_to_own_route(srv, owner_api, empty_day, asked):
    assert _no_route_on_sandbox_date(owner_api)          # re-checked right before the call
    st, res = _email_route(srv, "U3", asked)
    log.info(f"[SRV-SCOPE-13] Samual email_route_now(crew={asked!r}) -> HTTP {st}: {res.splitlines()[0][:160]}")
    assert st == 200 and res.lstrip().startswith("⚠️") and "Nothing to email" in res, res[:200]
    # the server lower-cases the crew name in this message ("(samual cronin)")
    assert f"({CREW})".lower() in res.lower(), f"Samual's request wasn't limited to his own route: {res[:200]!r}"
    assert OTHER.lower() not in res.lower(), f"the server looked up Vicki's route for Samual: {res[:200]!r}"


def test_SRV_SCOPE_13_control_owner_can_ask_for_another_crews_route(srv, owner_api, empty_day):
    assert _no_route_on_sandbox_date(owner_api)
    st, res = _email_route(srv, "U1", OTHER)
    log.info(f"[SRV-SCOPE-13] David email_route_now(crew='{OTHER}') -> HTTP {st}: {res.splitlines()[0][:160]}")
    assert st == 200 and "Nothing to email" in res and f"({OTHER})".lower() in res.lower(), \
        f"owner's request for Vicki's route wasn't honoured: {res[:200]!r}"

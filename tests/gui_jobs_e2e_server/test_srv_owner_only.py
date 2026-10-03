"""Server mode — SRV-API-05: owner-only writes are refused for manager / staff /
field crew.

The only owner-only WRITE tool is send_customer_reminders (the Reports screen's
"remind these customers" send). find_stale_customers, its read-only partner, is
already covered by the role matrix (test_srv_api_matrix).

How this is tested with ZERO chance of a real message: every call passes an
EMPTY customer list. The owner check runs first; after it, an empty list is
refused ("customer_ids is required") before anything is looked up or sent. So:
  • manager / crew → "Only the owner has access to this"   (refused at the gate)
  • owner          → "customer_ids is required"            (passed the gate, sent nothing)
Even if the gate were broken, an empty list can never send. Calls go straight
to the server (the write guard would otherwise record, not send, this tool).

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_owner_only
"""
import json
import logging

import pytest

from api import http

log = logging.getLogger("e2e_srv")

ROLE = {"U1": "owner", "U2": "manager", "U3": "field_crew"}


def _remind(srv, key, channel):
    st, raw = http("POST", srv["origin"] + "/pwa-api",
                   {"tool": "send_customer_reminders", "args": {"customer_ids": "", "channel": channel}},
                   token=srv["users"][key].access_token, timeout=60)
    try:
        return st, str(json.loads(raw).get("result", ""))
    except ValueError:
        return st, raw[:200]


@pytest.mark.parametrize("channel", ["email", "sms"])
@pytest.mark.parametrize("key", ["U2", "U3"])
def test_SRV_API_05_non_owner_cannot_send_customer_reminders(srv, key, channel):
    st, res = _remind(srv, key, channel)
    log.info(f"[SRV-API-05] {ROLE[key]} send_customer_reminders({channel}) -> HTTP {st}: {res[:120]}")
    assert st == 200 and "Only the owner" in res, f"{ROLE[key]} got past the owner-only gate: {res[:200]!r}"


@pytest.mark.parametrize("channel", ["email", "sms"])
def test_SRV_API_05_control_owner_passes_the_gate(srv, channel):
    st, res = _remind(srv, "U1", channel)
    log.info(f"[SRV-API-05] owner send_customer_reminders({channel}) -> HTTP {st}: {res[:120]}")
    assert st == 200 and "customer_ids is required" in res, \
        f"owner's call didn't reach the send step's own checks: {res[:200]!r}"

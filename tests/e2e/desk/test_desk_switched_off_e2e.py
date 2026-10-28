"""Service Desk E2E — the owner turns Service Desk OFF (personal AND server).

David 2026-10-28: "make sure that the MCP tools can be turned off if the user
decides to not use the helpdesk for both server and personal mode".

The switch is the "Service Desk (tickets)" group in Settings → MCP Tool
Configuration (tool_config_store.set_group_enabled(mode, "service_desk", ...)),
saved separately for personal and server mode. These servers are started with
that switch OFF — and with tickets already in the database, so the "already in
use" rule can't turn it back on by itself. Then, for each mode:

X1  Claude/Muse/Grok are not offered a single Service Desk tool (the rest of
    AI-Prowler's tools still are), and calling one by name does nothing
X2  the Service Desk app, its API and the customer request pages are closed —
    a person opening the app in a browser (human mode) is told it's turned off
X3  nothing runs in the background: no ticket alerts, digests or texts go out

Run: tests\\run_desk_e2e.py -k X
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conftest import SOLO_TOKEN, TOKEN_OF, http  # noqa: E402

pytestmark = pytest.mark.e2e


def _client(server, name="Olive Owner"):
    import task_queue_automation as tqa
    c = tqa._HttpMCPClient(SOLO_TOKEN if server.kind == "solo" else TOKEN_OF[name],
                           url=server.base + "/mcp")
    c.initialize(timeout=60)
    return c


@pytest.fixture(params=["server", "personal"])
def off(request, business_off, solo_off):
    return business_off if request.param == "server" else solo_off


def test_X1_no_service_desk_tools_for_claude(off):
    import mcp_tool_catalog as tc
    desk_tools = set(tc.tools_in_category("service_desk"))
    assert len(desk_tools) >= 29, desk_tools
    c = _client(off)
    try:
        offered = {t["name"] for t in c.list_tools()}
        leaked = sorted(desk_tools & offered)
        assert not leaked, f"{off.kind}: Service Desk is off but Claude still sees {leaked}"
        assert "search_documents" in offered, "turning Service Desk off must not hide the rest"
        # "Open a ticket: the pump is leaking" — the tool isn't there, so nothing is filed
        try:
            out = c.call_tool("create_ticket", {"title": "ZTEST X1 should not exist"}, timeout=60)
        except Exception as e:                         # unknown tool → protocol error
            out = f"error: {e}"
        assert not str(out).startswith("✅"), out
    finally:
        try:
            c.close()
        except Exception:
            pass
    import sqlite3
    con = sqlite3.connect(off.db)
    try:
        rows = con.execute("SELECT ticket_id FROM tickets").fetchall()
    finally:
        con.close()
    assert rows == [("T-0001",)], f"a ticket was filed while Service Desk was off: {rows}"


def test_X2_app_api_and_customer_pages_are_closed(off, people):
    st, body = http("GET", f"{off.base}/desk/")
    assert st == 404, (st, body)
    login = {"name": "Olive Owner", "token": TOKEN_OF["Olive Owner"]} if off.kind == "business" \
        else {"token": SOLO_TOKEN}
    st, d = http("POST", f"{off.base}/desk-api/auth/login", login)
    assert st == 403 and d.get("error") == "desk_off", (st, d)
    st, d = http("GET", f"{off.base}/desk-api/tickets",
                 token=SOLO_TOKEN if off.kind == "solo" else TOKEN_OF["Olive Owner"])
    assert st == 403 and d.get("error") == "desk_off", (st, d)
    for path in ("/support/new", "/support-api/request-code"):
        st, _ = http("GET" if path.endswith("new") else "POST", f"{off.base}{path}",
                     None if path.endswith("new") else {"email": "x@example.test"})
        assert st == 404, (path, st)
    # A person opens the app on their phone (human mode)
    p = people(off, f"{off.kind} owner", phone=True)
    p.page.goto(f"{off.base}/desk/")
    p.page.get_by_text("Service Desk is turned off").wait_for()
    assert p.page.locator("#lgGo").count() == 0, "the sign-in screen showed while Service Desk is off"


def test_X3_nothing_runs_in_the_background(off):
    time.sleep(5)                          # several scheduler passes
    sent = off.messages()
    assert sent == [], f"{off.kind}: Service Desk is off but it sent {sent}"
    log = (off.state / "server.log").read_text(encoding="utf-8", errors="replace")
    assert "Service Desk email intake started" not in log, "email intake ran while off"

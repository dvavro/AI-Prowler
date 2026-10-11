"""Server mode — Access-Only Folders are NOT available (spec §6.11, SRV-AO).

David 2026-10-09: access-only folders (readable, never indexed) are a
personal-mode feature. On the live AI-Prowler Server:

  SRV-AO-01  no user's Claude is offered grant_access / revoke_access over MCP
             (David, Vicki, Samual)
  SRV-AO-02  the Jobs app's /pwa-api refuses both ("Unknown tool") — sent with a
             folder that doesn't exist, so even a wrong answer couldn't change
             anything
  SRV-AO-03  list_tracked_directories has no access-only section (owner)

Nothing is written: only tool lists and a refused call.
Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_access_only
"""
import json

import pytest

from ai_client import AiClient
from api import http

AO_TOOLS = ("grant_access", "revoke_access")
USERS = ["U1", "U2", "U3"]
NO_SUCH_DIR = r"C:\ZTEST-E2E-access-only-does-not-exist"


@pytest.mark.parametrize("key", USERS)
def test_SRV_AO_01_not_offered_to_claude(srv, guard, key):
    u = srv["users"][key]
    tools = AiClient(srv["origin"], u.token, guard, key).list_tools()
    assert "read_job_spreadsheet" in tools, f"{u}: tool list looks wrong ({len(tools)} tools)"
    offered = [t for t in AO_TOOLS if t in tools]
    assert not offered, f"{u}: the server offers {offered} — access-only folders are personal-mode only"


@pytest.mark.parametrize("tool", AO_TOOLS)
def test_SRV_AO_02_jobs_app_api_refuses(srv, tool):
    st, body = http("POST", srv["origin"] + "/pwa-api",
                    {"tool": tool, "args": {"directory": NO_SUCH_DIR}},
                    token=srv["owner"].access_token, timeout=30)
    try:
        data = json.loads(body)
    except ValueError:
        data = {"raw": body[:200]}
    assert not data.get("ok"), f"/pwa-api accepted {tool} on the server: HTTP {st} {data}"
    assert "Unknown tool" in str(data.get("error", "")), f"HTTP {st} {data}"


def test_SRV_AO_03_no_access_only_section(srv, guard):
    out = AiClient(srv["origin"], srv["owner"].token, guard, "U1").call_read("list_tracked_directories")
    assert "Access-only" not in out and "grant_access" not in out, out[:500]

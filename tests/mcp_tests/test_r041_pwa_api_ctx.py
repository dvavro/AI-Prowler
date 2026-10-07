"""
tests/mcp_tests/test_r041_pwa_api_ctx.py
==================================
R-041 (2026-09-27, was gap G-06, found live by SRV-API-01): the server-mode
Jobs app endpoint /pwa-api called every tool with ctx=…, but search_learnings
and geocode_address take no ctx — every call failed with HTTP 400
"unexpected keyword argument 'ctx'" for every role.

The dispatcher now passes ctx only when the tool's signature accepts it
(a `ctx` parameter or **kwargs). These tests pin that rule to the real tool
objects (as decorated — the counting wrapper uses functools.wraps, so the
signature seen is the tool's own) and to the dispatcher source.
"""
import inspect
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _takes_ctx(fn) -> bool:
    """Same rule as the /pwa-api dispatcher."""
    params = inspect.signature(fn).parameters
    return "ctx" in params or any(p.kind == p.VAR_KEYWORD for p in params.values())


@pytest.mark.parametrize("tool", ["search_learnings", "geocode_address"])
def test_tools_without_ctx_are_detected(mcp_mod, tool):
    assert not _takes_ctx(getattr(mcp_mod, tool)), f"{tool} now takes ctx — update R-041 notes"


@pytest.mark.parametrize("tool", ["read_job_spreadsheet", "get_board_updates", "log_time_entry",
                                  "update_job_spreadsheet", "build_daily_route", "approve_route_schedule",
                                  "find_stale_customers", "check_sms_replies"])
def test_ctx_tools_still_get_ctx(mcp_mod, tool):
    # The crew / owner-only checks depend on ctx — these must keep receiving it.
    assert _takes_ctx(getattr(mcp_mod, tool)), f"{tool} would lose its ctx (and its role checks)"


def test_dispatcher_no_longer_forces_ctx(mcp_mod):
    src = inspect.getsource(mcp_mod)
    assert "_srv_pa_fn(**_srv_pa_args, ctx=_srv_pa_ctx)" not in src, \
        "the /pwa-api dispatcher forces ctx= again (R-041)"
    assert "_srv_pa_takes_ctx" in src

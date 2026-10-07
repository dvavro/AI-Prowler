"""
R-049 (2026-09-28): the Jobs app honours Settings → MCP Tool Configuration.

Before: the panel only kept tools out of Claude's MCP tool list. The Jobs app
(/pwa-api, both modes) calls tool functions directly, so switching off
"Job Tracker & Routing" left the whole Jobs app working, and switching off SMS
still let the app text. Also only 7 of the ~47 tools the app uses were marked
as Jobs-app dependencies, and list_outlook_accounts was counted in server mode
although it refuses to run there.

Now:
  * both /pwa-api handlers refuse a tool the owner turned off (403 + a clear
    message); locked tools can never be off;
  * server /pwa-login refuses sign-in when the Jobs app's core read is off
    (normally: Job Tracker & Routing unticked) — the Jobs app is optional;
  * mcp_tool_catalog.JOBS_APP_TOOLS == the union of the two allow-lists, and
    every one is marked pwa_dependency (the panel warns before disabling);
  * list_outlook_accounts is personal-only (Tier A + catalog).

Run: run_tests.bat tests\\mcp\\test_r049_jobs_app_honours_tool_panel.py -v
"""
import ast
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_MCP_SRC = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture(scope="module")
def cat():
    import mcp_tool_catalog as c
    return c


def _allow_list(var_name: str) -> set:
    """The string-set literal assigned to var_name inside ai_prowler_mcp.py."""
    for node in ast.walk(ast.parse(_MCP_SRC)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == var_name
                and isinstance(node.value, ast.Set)):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    raise AssertionError(f"{var_name} set literal not found")


# ── the check itself ────────────────────────────────────────────────────────

def test_enabled_tool_is_allowed(mcp_mod):
    assert mcp_mod._pwa_tool_disabled_message("send_sms", disabled=frozenset()) == ""


def test_disabled_tool_is_refused_with_its_label(mcp_mod, cat):
    msg = mcp_mod._pwa_tool_disabled_message("send_sms", disabled=frozenset({"send_sms"}))
    assert msg and cat.TOOL_CATALOG["send_sms"].label in msg and "turned off" in msg


def test_locked_tool_can_never_be_off(mcp_mod):
    # check_ai_prowler_status is locked — a hand-edited config can't switch it off.
    assert mcp_mod._pwa_tool_disabled_message(
        "check_ai_prowler_status", disabled=frozenset({"check_ai_prowler_status"})) == ""


def test_jobs_app_off_only_when_core_read_is_off(mcp_mod, cat):
    assert not mcp_mod._jobs_app_turned_off(disabled=frozenset({"send_sms"}))
    group = frozenset(n for n in cat.tools_in_category("job_tracker") if not cat.is_locked(n))
    assert mcp_mod._jobs_app_turned_off(disabled=group)          # whole group unticked
    assert "Job Tracker" in mcp_mod._JOBS_APP_OFF_MESSAGE


def test_live_default_is_nothing_disabled(mcp_mod):
    # Test runs have no tool_config.json — the real app must be unaffected.
    assert mcp_mod._pwa_tool_disabled_message("read_job_spreadsheet") == ""
    assert not mcp_mod._jobs_app_turned_off()


# ── wiring (source level: the ASGI handlers aren't importable on their own) ──

def test_server_pwa_api_checks_the_panel_after_the_allow_list():
    i = _MCP_SRC.index('f"Unknown tool: {_srv_pa_tool}"')
    j = _MCP_SRC.index("_pwa_tool_disabled_message(_srv_pa_tool)")
    k = _MCP_SRC.index("_srv_pa_fn = _srv_pa_g[_srv_pa_tool]")
    assert i < j < k, "server /pwa-api must refuse a disabled tool before calling it"
    assert "await _send_json(send, 403, {\"ok\": False, \"error\": _srv_pa_off})" in _MCP_SRC


def test_personal_pwa_api_checks_the_panel():
    j = _MCP_SRC.index("_pwa_tool_disabled_message(_tool)")
    k = _MCP_SRC.index("_fn = _g[_tool]")
    assert j < k
    assert "elif _pa_off:" in _MCP_SRC


def test_server_sign_in_refused_when_jobs_app_is_off():
    login = _MCP_SRC[_MCP_SRC.index('if path == "/pwa-login" and method == "POST":'):]
    off = login.index("if _jobs_app_turned_off():")
    creds = login.index("_resolve_user(_hot_reload_users(users_data), _srv_pl_entered)")
    assert off < creds, "Jobs-app-off must be answered before any credential check"


# ── catalog ─────────────────────────────────────────────────────────────────

def test_jobs_app_tools_match_both_allow_lists(cat):
    union = _allow_list("_srv_pa_allowed") | _allow_list("_allowed_tools")
    assert set(cat.JOBS_APP_TOOLS) == union, (
        f"missing from JOBS_APP_TOOLS: {sorted(union - set(cat.JOBS_APP_TOOLS))}; "
        f"extra: {sorted(set(cat.JOBS_APP_TOOLS) - union)}")


def test_every_jobs_app_tool_is_marked_as_a_dependency(cat):
    unmarked = [n for n in cat.JOBS_APP_TOOLS
                if n in cat.TOOL_CATALOG and not cat.TOOL_CATALOG[n].pwa_dependency]
    assert not unmarked, unmarked
    assert all(n in cat.TOOL_CATALOG for n in cat.JOBS_APP_TOOLS)


def test_existing_notes_are_kept(cat):
    assert "Board" in cat.TOOL_CATALOG["read_job_spreadsheet"].pwa_dependency_note
    assert "Jobs app" in cat.TOOL_CATALOG["build_daily_route"].pwa_dependency_note


def _registered_tool_names() -> set:
    """Every @mcp.tool() in ai_prowler_mcp.py, by its registered name."""
    names = set()
    for node in ast.walk(ast.parse(_MCP_SRC)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in node.decorator_list:
            call = d if isinstance(d, ast.Call) else None
            target = call.func if call else d
            if isinstance(target, ast.Attribute) and target.attr == "tool" \
                    and isinstance(target.value, ast.Name) and target.value.id == "mcp":
                name = node.name
                for kw in (call.keywords if call else []):
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        name = kw.value.value
                names.add(name)
    return names


def test_every_registered_tool_has_a_catalog_row(cat):
    # prescreen_route_jobs shipped 2026-09-25 with no row — it couldn't be
    # switched off in the panel and the counts were one short. Never again.
    registered = _registered_tool_names()
    assert len(registered) > 90
    missing = sorted(registered - set(cat.TOOL_CATALOG))
    stale = sorted(set(cat.TOOL_CATALOG) - registered)
    assert not missing, f"@mcp.tool() with no mcp_tool_catalog row: {missing}"
    assert not stale, f"catalog rows for tools that no longer exist: {stale}"


# ── list_outlook_accounts is personal-only ───────────────────────────────────

def test_list_outlook_accounts_personal_only(mcp_mod, cat):
    assert "list_outlook_accounts" in mcp_mod._TIER_A_SUPPRESSED
    assert cat.modes_of("list_outlook_accounts") == frozenset({"personal"})


def test_every_personal_only_catalog_tool_is_hidden_in_server_mode(mcp_mod, cat):
    # The panel's server-mode counts come from the catalog; what the server
    # actually registers comes from Tier A. They must agree.
    personal_only = {n for n, m in cat.TOOL_CATALOG.items() if m.modes == frozenset({"personal"})}
    missing = personal_only - set(mcp_mod._TIER_A_SUPPRESSED)
    assert not missing, f"catalog says personal-only but server still registers: {sorted(missing)}"

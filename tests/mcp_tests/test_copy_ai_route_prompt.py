"""
"📋 Copy AI Route for Any AI" (2026-10-22, David) — route with any AI chat.

The Jobs app's new Route-tab button gets a ready-to-paste prompt from
get_ai_route_prompt. The user pastes it into Claude, Muse, Grok or any chat
that has this AI-Prowler connected; the chat plans the route live with the
same steps as 🧠 AI Route — no Claude CLI, no Claude Pro token.

A person may have TWO AI-Prowlers connected (their Personal PC and the company
Server), each with its own Jobs app, so every prompt carries a one-time route
code from the machine that made it:
  * confirm_route_code answers MATCH only on that machine;
  * apply_route_order(route_code=...) refuses a code it didn't make, or one for
    another date/crew — nothing is written to the wrong Jobs app.

Also here: the background AI Route run now passes --strict-mcp-config, so a
connector saved in that Windows account's own Claude settings (which could
point at the OTHER AI-Prowler) is never loaded.

  CR-01  personal prompt: route code, MADE_BY, confirm step, route_code passed
         to apply_route_order, settings filled in (no Settings read)
  CR-02  the background (CLI) prompt still reads Settings itself
  CR-03  pins appear in the copied prompt, same wording as the CLI prompt
  CR-04  confirm_route_code: MATCH for its own code (any case), NO MATCH otherwise
  CR-05  apply_route_order refuses an unknown code — nothing reaches the DB
  CR-06  ... refuses a code for another date / another crew
  CR-07  ... accepts its own code; no code = unchanged behaviour
  CR-08  codes older than 24 hours no longer match
  CR-09  server mode: field_crew always gets their own day; another crew refused
  CR-10  bad date refused; codes saved to a file (survive a restart)
  CR-11  the AI Route wrapper passes --strict-mcp-config; no literal {placeholders}
  CR-12  Jobs app: the button sits between Route and Email on the Route tab (it
         replaced the 🧠 AI Route / Claude CLI button, 2026-10-22) and is in
         both allow-lists

Run: run_tests.bat tests\\mcp_tests\\test_copy_ai_route_prompt.py -v
"""
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from db_access import init_db

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DAY = "2026-10-22"
CREW = "Sam Crew"
OTHER = "Val Other"
TS = "2026-10-22T12:00:00+00:00"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    conn = sqlite3.connect(path)
    for jid, crew in (("JOB-0101", CREW), ("JOB-0202", OTHER)):
        conn.execute("INSERT INTO jobs (job_id, crew, service_date, last_edited_at) VALUES (?,?,?,?)",
                     (jid, crew, DAY, TS))
    conn.commit()
    conn.close()
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": path)
    codes = tmp_path / "ai_routing" / "route_codes.json"
    monkeypatch.setattr(mcp_mod, "_route_codes_path", lambda: codes)
    monkeypatch.setattr(mcp_mod, "_route_machine_label", lambda: "AI-Prowler Personal on TESTPC")
    return {"db": path, "codes": codes}


@pytest.fixture
def spy(monkeypatch):
    """Records what reaches the database layer of apply_route_order."""
    import db_route_ops
    seen = []

    def fake_apply(db_path, route_date, stop_order, crew, actor, **k):
        seen.append((route_date, stop_order, crew))
        return "✅ applied"
    monkeypatch.setattr(db_route_ops, "db_apply_route_order", fake_apply)
    return seen


def _as(mcp_mod, monkeypatch, role, name=CREW):
    monkeypatch.setattr(mcp_mod, "_current_user",
                        lambda ctx: {"id": "u-test", "name": name, "role": role})


def _prompt(mcp_mod, crew=""):
    out = mcp_mod.get_ai_route_prompt(route_date=DAY, crew=crew, ctx=None)
    m = re.match(r"ROUTE_CODE: (RT-[A-Z0-9]{6})\nMADE_BY: ([^\n]+)\n\n", out)
    assert m, out[:300]
    return m.group(1), m.group(2), out[m.end():]


def test_CR01_personal_prompt(mcp_mod, env):
    code, made_by, text = _prompt(mcp_mod)
    assert made_by == "AI-Prowler Personal on TESTPC"
    assert text.startswith(f"AI-PROWLER ROUTE REQUEST -- made by {made_by} for {DAY}")
    assert f'confirm_route_code(code="{code}")' in text
    assert re.search(r'apply_route_order\(route_date="' + DAY + r'", stop_order="[^"]*", route_code="'
                     + code + r'"\)', text), text
    assert "do NOT read the Settings sheet" in text
    assert re.search(r"Workday Start Time \d\d?:\d\d", text) and "Hard Time Tolerance" in text
    assert 'read_job_spreadsheet(sheet_name="Settings")' not in text
    assert "Do NOT use suggest_route_schedule" in text            # same reasoning steps as AI Route
    assert "tap Refresh" in text


def test_CR02_cli_prompt_still_reads_settings(mcp_mod):
    p = mcp_mod._RUN_AI_ROUTING_PROMPT_TEMPLATE.format(
        route_date=DAY, crew_clause="", crew_arg="", origin_arg="", pin_clause="",
        settings_step=mcp_mod._AI_ROUTE_SETTINGS_STEP_READ)
    assert 'read_job_spreadsheet(sheet_name="Settings")' in p
    assert "route_code" not in p and "confirm_route_code" not in p


def test_CR03_pins_in_copied_prompt(mcp_mod, env, monkeypatch):
    import db_route_ops
    monkeypatch.setattr(db_route_ops, "_read_route_pins", lambda db, d, c: {"JOB-0101": 1})
    _, _, text = _prompt(mcp_mod)
    assert "JOB-0101 MUST be stop #1" in text
    assert mcp_mod._ai_route_pin_clause(None, DAY) in text


def test_CR04_confirm_route_code(mcp_mod, env):
    code, _, _ = _prompt(mcp_mod)
    assert mcp_mod.confirm_route_code(code).startswith("MATCH — this is AI-Prowler Personal on TESTPC")
    assert mcp_mod.confirm_route_code("  " + code.lower() + " ").startswith("MATCH")
    assert mcp_mod.confirm_route_code("RT-ZZZZZZ").startswith("NO MATCH")
    assert mcp_mod.confirm_route_code("").startswith("NO MATCH")


def test_CR05_unknown_code_refused(mcp_mod, env, spy):
    out = mcp_mod.apply_route_order(route_date=DAY, stop_order="JOB-0101",
                                    route_code="RT-ABCDEF", ctx=None)
    assert out.startswith("❌ WRONG AI-PROWLER") and "Nothing was written" in out, out
    assert spy == []


def test_CR06_code_for_other_date_or_crew_refused(mcp_mod, env, spy, monkeypatch):
    code, _, _ = _prompt(mcp_mod)
    out = mcp_mod.apply_route_order(route_date="2026-10-23", stop_order="JOB-0101",
                                    route_code=code, ctx=None)
    assert out.startswith("❌") and "Nothing was written" in out and spy == []
    _as(mcp_mod, monkeypatch, "owner", name="Owen Owner")
    code2, _, _ = _prompt(mcp_mod, crew=CREW)
    out = mcp_mod.apply_route_order(route_date=DAY, stop_order="JOB-0202", crew=OTHER,
                                    route_code=code2, ctx=None)
    assert out.startswith("❌") and "Nothing was written" in out and spy == []


def test_CR07_own_code_accepted_and_no_code_unchanged(mcp_mod, env, spy):
    code, _, _ = _prompt(mcp_mod)
    out = mcp_mod.apply_route_order(route_date=DAY, stop_order="JOB-0101,JOB-0202",
                                    route_code=code, ctx=None)
    assert "✅ applied" in out and spy[-1][:2] == (DAY, "JOB-0101,JOB-0202")
    out = mcp_mod.apply_route_order(route_date=DAY, stop_order="JOB-0101", ctx=None)
    assert "✅ applied" in out and len(spy) == 2


def test_CR08_codes_expire(mcp_mod, env, spy):
    code, _, _ = _prompt(mcp_mod)
    data = json.loads(env["codes"].read_text(encoding="utf-8"))
    data[code]["made_at"] = time.time() - mcp_mod._ROUTE_CODE_TTL_S - 5
    env["codes"].write_text(json.dumps(data), encoding="utf-8")
    assert mcp_mod.confirm_route_code(code).startswith("NO MATCH")
    out = mcp_mod.apply_route_order(route_date=DAY, stop_order="JOB-0101", route_code=code, ctx=None)
    assert out.startswith("❌ WRONG AI-PROWLER") and spy == []


def test_CR09_field_crew_own_day_only(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    code, _, text = _prompt(mcp_mod)                # blank crew -> their own day
    assert f"crew '{CREW}'" in text and f'crew="{CREW}"' in text
    assert mcp_mod.confirm_route_code(code).endswith(f"crew '{CREW}'. Use this AI-Prowler connector for every step.")
    out = mcp_mod.get_ai_route_prompt(route_date=DAY, crew=OTHER, ctx=None)
    assert out.startswith("❌") and "ROUTE_CODE" not in out, out


def test_CR10_bad_date_and_codes_persist(mcp_mod, env):
    assert mcp_mod.get_ai_route_prompt(route_date="10/22/2026", ctx=None).startswith("❌")
    assert not env["codes"].exists()
    code, _, _ = _prompt(mcp_mod)
    saved = json.loads(env["codes"].read_text(encoding="utf-8"))
    assert saved[code]["route_date"] == DAY and saved[code]["crew"] == ""


def test_CR11_claude_cli_wrappers_are_strict(tmp_path, monkeypatch):
    # The Claude CLI AI Route wrapper is gone (2026-10-22); the task-queue
    # wrappers that remain use ONLY AI-Prowler's own config, never also the
    # user's other Claude MCP servers (which may hold a second AI-Prowler).
    import task_queue_automation as tqa
    assert not hasattr(tqa, "build_ai_routing_wrapper_content")
    cfg = str(tmp_path / "claude_mcp_config.json")
    q = tqa.build_wrapper_script_content(cfg, "mcp__ai-prowler__*")
    assert "--strict-mcp-config" in q and '--mcp-config "%AIP_MCP_CONFIG%"' in q
    for use_key in (False, True):
        s = tqa.build_single_prompt_wrapper_content("hi", cfg, "mcp__ai-prowler__*", use_api_key=use_key)
        assert "--strict-mcp-config" in s
        assert "{mcp_config_path}" not in s and "{allowed_tools}" not in s


def test_CR12_jobs_app_button_and_allow_lists():
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    # 2026-10-22: the 🧠 AI Route (CLI) button is gone; Copy AI Route takes its spot
    assert 'id="routeAiSuggestBtn"' not in html
    rt = html.index('id="routeTodayBtnRoute"')
    cp = html.index('id="routeCopyAiBtn"')
    em = html.index('id="routeEmailRouteBtn"')
    assert rt < cp < em, "Copy AI Route must sit between Route and Email"
    tag = html[html.rindex("<button", 0, cp):html.index(">", cp)]
    assert 'onclick="copyAiRoutePrompt()"' in tag
    assert "async function copyAiRoutePrompt()" in html
    assert "mcpCall('get_ai_route_prompt'" in html
    from mcp_tool_catalog import JOBS_APP_TOOLS, TOOL_CATALOG
    assert "get_ai_route_prompt" in JOBS_APP_TOOLS
    assert "get_ai_route_prompt" in TOOL_CATALOG and "confirm_route_code" in TOOL_CATALOG
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert src.count('"get_ai_route_prompt",') >= 2, "missing from a /pwa-api allow-list"

"""
tests/mcp_tests/test_cli_ai_routing_removed.py
==============================================
2026-10-22 (David): the Claude CLI AI routing is gone, in personal AND server
mode. AI routing happens in any AI chat connected to AI-Prowler (Jobs app →
Route tab → 📋 Copy AI Route / 🗓️ Plan Week), so:

  A. the server tools are gone (start_ai_routing, poll_ai_routing,
     get_route_start_options, the four "Connect your Claude account" tools) and
     the Jobs app never calls them;
  B. the desktop app has no CLI routing panels — Small Business tab "🧭 AI Route
     Optimizer Task" / "Set Up On-Demand AI Routing", Admin tab "🧠 AI Route
     runner", "🤖 AI Route Token" button and "AI Route" column. An admin no
     longer manages any Claude passwords;
  C. retire_cli_ai_routing() cleans up what an older version left: the "AI Route
     Optimizer (full reasoning)" custom analysis (and queued copies), the
     on-demand Windows task, ~/.ai-prowler/ai_routing (incl. per-user tokens);
  D. every task-queue run (Claude scheduled / NOW, and Grok) uses the
     AI-Prowler that's already running (localhost, with this install's Bearer
     Token so the server knows it's the owner) and never starts a second copy:
     no token or nothing answering means the run is skipped and says why;
  E. the home-address resolver the removed picker used is still used by route
     building — its rules are kept under test here;
  F. Personal Links & Analysis 📋 Copy / ✉ Email Token buttons (the task
     queue's own token — unrelated to routing) are unchanged.

Every test runs against temp folders — never this computer's ~/.ai-prowler.

Run: run_tests.bat tests\\mcp_tests\\test_cli_ai_routing_removed.py -v
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_HTML = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
_MCP = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
_GUI = (_SRC / "rag_gui.py").read_text(encoding="utf-8")
_TQA = (_SRC / "task_queue_automation.py").read_text(encoding="utf-8")
_CAT = (_SRC / "mcp_tool_catalog.py").read_text(encoding="utf-8")

REMOVED_TOOLS = ("start_ai_routing", "poll_ai_routing", "get_route_start_options",
                 "start_cli_signin", "submit_cli_signin_code", "cancel_cli_signin", "save_my_cli_token")
LABEL = "AI Route Optimizer (full reasoning)"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


# ══════════════════════════════════════════════════════════════════════════
# A. server tools + Jobs app
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("tool", REMOVED_TOOLS)
def test_A1_tool_is_gone_everywhere(tool, mcp_mod):
    assert not hasattr(mcp_mod, tool), tool
    assert not re.search(rf"def {tool}\(", _MCP), tool
    assert f"('{tool}'," not in _CAT, tool                          # tool catalog
    assert f"mcpCall('{tool}'" not in _HTML, tool                    # Jobs app


def test_A2_jobs_app_allowlists_offer_the_any_ai_tools_only():
    for name in ("_srv_pa_allowed = {", "_allowed_tools = {"):
        i = _MCP.index(name, _MCP.index('"get_ai_route_prompt"') - 4000 if name == "_allowed_tools = {" else 0)
        block = re.sub(r"#[^\n]*", "", _MCP[i:_MCP.index("}", i)])
        for tool in REMOVED_TOOLS:
            assert f'"{tool}"' not in block, (name, tool)
        for tool in ("get_ai_route_prompt", "get_week_plan_prompt", "get_week_proposal",
                     "apply_week_moves", "dismiss_week_proposal"):
            assert f'"{tool}"' in block, (name, tool)


def test_A3_sign_in_helper_files_are_gone_and_removed_on_upgrade():
    assert not (_SRC / "cli_signin_relay.py").exists()
    assert not (_SRC / "console_inject.py").exists()
    iss = (_SRC / "AI-Prowler-Setup.iss").read_text(encoding="utf-8", errors="replace")
    assert 'Source: "cli_signin_relay.py"' not in iss and 'Source: "console_inject.py"' not in iss
    deletes = iss[iss.index("[InstallDelete]"):iss.index("[Files]")]
    assert 'Name: "{app}\\cli_signin_relay.py"' in deletes and 'Name: "{app}\\console_inject.py"' in deletes
    rel = (_SRC / "scripts" / "release.py").read_text(encoding="utf-8")
    assert '"cli_signin_relay.py",' not in rel and '"console_inject.py",' not in rel


def test_A4_week_plan_module_ships_with_updates_too():
    """Found while removing the CLI files: week_plan.py was in the installer
    but not in the auto-update list — an updated install would have broken
    🗓️ Plan Week."""
    rel = (_SRC / "scripts" / "release.py").read_text(encoding="utf-8")
    iss = (_SRC / "AI-Prowler-Setup.iss").read_text(encoding="utf-8", errors="replace")
    assert '"week_plan.py",' in rel and 'Source: "week_plan.py"' in iss


def test_A5_copy_prompt_template_survives(mcp_mod):
    # the reasoning steps are still used by 📋 Copy AI Route
    assert "{settings_step}" in mcp_mod._RUN_AI_ROUTING_PROMPT_TEMPLATE
    assert "_AI_ROUTING_JOBS" not in _MCP and "_ai_routing_worker(" not in _MCP


# ══════════════════════════════════════════════════════════════════════════
# B. desktop GUI
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("gone", [
    "🧭 AI Route Optimizer Task", "Build / Recreate AI Route Optimizer Task",
    "Set Up On-Demand AI Routing (one-time)", "_setup_ai_routing_runner_gui",
    "🧠 AI Route runner", "⬇ Install Claude Code CLI\",\n                                             command=self._admin_ai",
    "🔧 Set Up AI Route Runner", "🤖 AI Route Token", "_admin_set_ai_route_token",
    "_admin_ai_route_refresh_status", "_admin_ai_token_key", "has_user_oauth_token",
    "'airoute'", "cli_signin_relay.py", "install_ai_routing_task", "ai_routing_task_exists",
])
def test_B1_cli_routing_panels_are_gone(gone):
    code = re.sub(r"#[^\n]*", "", _GUI)            # comments may explain what was removed
    assert gone not in code, gone


def test_B2_small_business_tab_points_to_the_jobs_app_instead():
    i = _GUI.index("# ── 4. AI ROUTING (2026-10-22, David)")
    note = _GUI[i:_GUI.index("# ── 5. ONLINE PAYMENT LINKS", i)]
    assert "📋 Copy AI Route for Any AI" in note and "🗓️ Plan Week with Any AI" in note
    assert ".pack(" in note                      # shown in personal AND server mode


def test_B3_admin_table_columns_line_up_with_the_row_values():
    cols = re.search(r"columns = \(('name'.*?)\)\n", _GUI).group(1)
    n_cols = cols.count("'")//2
    import ast
    row = _GUI[_GUI.index("values=(u.get(\"name\", \"(unnamed)\")") + len("values="):]
    row = row[:row.index("tok_display))") + len("tok_display)")]
    n_vals = len(ast.parse(row, mode="eval").body.elts)
    assert n_cols == 11 and n_vals == n_cols, (n_cols, n_vals, row)


def test_B4_home_address_is_still_shown_as_a_flag_only():
    row = _GUI[_GUI.index("home_flag ="):_GUI.index("seat, status, tok_display))")]
    assert 'home_flag = "✓" if' in row and "ai_flag" not in row
    assert 'text="Home address:"' in _GUI


def test_B5_cleanup_runs_at_startup_but_never_in_tests():
    init = _GUI[_GUI.index("class RAGGui:"):_GUI.index("# ── Hide window during construction")]
    assert "retire_cli_ai_routing()" in init
    assert 'os.environ.get("PYTEST_CURRENT_TEST")' in init and 'os.environ.get("AIPROWLER_TEST_STATE_DIR")' in init


# ══════════════════════════════════════════════════════════════════════════
# C. retire_cli_ai_routing()
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def home(tmp_path, monkeypatch):
    import task_queue_automation as t
    import custom_tasks_manager as ctm
    h = tmp_path / ".ai-prowler"
    h.mkdir()
    monkeypatch.setattr(t, "AI_PROWLER_HOME", h)
    monkeypatch.setattr(t, "RETIRED_AI_ROUTING_DIR", h / "ai_routing")
    monkeypatch.setattr(t, "RETIRED_AI_ROUTING_MARKER", h / "cli_ai_routing_retired.marker")
    monkeypatch.setattr(ctm, "CUSTOM_TASKS_PATH", h / "custom_analysis_tasks.json")
    calls = []

    def fake_run(cmd, **k):
        calls.append(cmd)
        return MagicMock(returncode=1, stdout="", stderr="")          # task not there
    monkeypatch.setattr(t.subprocess, "run", fake_run)
    return t, ctm, h, calls


def _task(tid, label):
    return {"task_id": tid, "label": label, "prompt": "p", "schedule": "none", "next_due": None}


def test_C1_removes_the_route_optimizer_task_and_its_queued_runs_only(home):
    t, ctm, h, _ = home
    tasks = [_task("custom_001", "Weekly Big Tech/Semi Earnings Watch"), _task("custom_007", LABEL),
             _task("custom_008", "Check NSB")]
    (h / "custom_analysis_tasks.json").write_text(json.dumps(tasks), encoding="utf-8")
    queue = [{"task_id": "custom_007_x", "source_id": "custom_007", "label": LABEL},
             {"task_id": "custom_008_x", "source_id": "custom_008", "label": "Check NSB"},
             {"task_id": "builtin_1", "type": "analyze_business"}]
    (h / "pending_tasks.json").write_text(json.dumps(queue), encoding="utf-8")
    done = t.retire_cli_ai_routing()
    left = json.loads((h / "custom_analysis_tasks.json").read_text(encoding="utf-8"))
    assert [x["label"] for x in left] == ["Weekly Big Tech/Semi Earnings Watch", "Check NSB"]
    q = json.loads((h / "pending_tasks.json").read_text(encoding="utf-8"))
    assert [x["task_id"] for x in q] == ["custom_008_x", "builtin_1"]
    assert any("custom task" in d for d in done) and any("queued" in d for d in done)


def test_C2_removes_the_ai_routing_folder_with_the_user_tokens(home):
    t, _, h, _ = home
    tok = h / "ai_routing" / "user_tokens" / "jake-r.txt"
    tok.parent.mkdir(parents=True)
    tok.write_text("sk-ant-oat01-xxxxxxxxxxxx", encoding="utf-8")
    (h / "ai_routing" / "run_ai_routing_ondemand.bat").write_text("@echo off", encoding="utf-8")
    t.retire_cli_ai_routing()
    assert not (h / "ai_routing").exists()


def test_C3_other_tasks_and_files_are_untouched(home):
    t, _, h, _ = home
    tasks = [_task("custom_001", "AI Route Optimizer (my own copy)")]          # renamed by the user: kept
    (h / "custom_analysis_tasks.json").write_text(json.dumps(tasks), encoding="utf-8")
    (h / "claude_oauth_token.txt").write_text("sk-ant-oat01-owner", encoding="utf-8")
    before = (h / "custom_analysis_tasks.json").read_text(encoding="utf-8")
    assert t.retire_cli_ai_routing() == []
    assert (h / "custom_analysis_tasks.json").read_text(encoding="utf-8") == before
    assert (h / "claude_oauth_token.txt").exists()                            # the task queue's own token


def test_C4_once_clean_it_only_checks_a_marker(home):
    t, ctm, h, calls = home
    t.retire_cli_ai_routing()
    assert (h / "cli_ai_routing_retired.marker").exists()
    (h / "custom_analysis_tasks.json").write_text(json.dumps([_task("c9", LABEL)]), encoding="utf-8")
    n = len(calls)
    assert t.retire_cli_ai_routing() == [] and len(calls) == n               # no schtasks, no file work
    assert json.loads((h / "custom_analysis_tasks.json").read_text(encoding="utf-8"))[0]["label"] == LABEL


@pytest.mark.skipif(os.name != "nt", reason="Windows Task Scheduler")
def test_C5_windows_task_is_deleted_when_present(home, monkeypatch):
    t, _, h, calls = home
    monkeypatch.setattr(t.subprocess, "run", lambda cmd, **k: (calls.append(cmd), MagicMock(returncode=0))[1])
    done = t.retire_cli_ai_routing()
    assert ["schtasks", "/delete", "/tn", "AI-Prowler-AIRoutingRunner", "/f"] in calls
    assert any("scheduled task" in d for d in done)


@pytest.mark.skipif(os.name != "nt", reason="Windows Task Scheduler")
def test_C6_task_that_needs_admin_is_left_and_not_retried(home, monkeypatch):
    t, _, h, calls = home
    monkeypatch.setattr(t.subprocess, "run",
                        lambda cmd, **k: MagicMock(returncode=0 if "/query" in cmd else 1))
    done = t.retire_cli_ai_routing()
    assert any("needs admin rights" in d for d in done)
    assert (h / "cli_ai_routing_retired.marker").exists()


def test_C7_an_unreadable_task_file_is_never_overwritten(home):
    t, _, h, _ = home
    (h / "custom_analysis_tasks.json").write_text("{not json", encoding="utf-8")
    t.retire_cli_ai_routing()
    assert (h / "custom_analysis_tasks.json").read_text(encoding="utf-8") == "{not json"


# ══════════════════════════════════════════════════════════════════════════
# D. scheduled queue run uses the AI-Prowler that's already running
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tq(tmp_path, monkeypatch):
    import task_queue_automation as t
    h = tmp_path / ".ai-prowler"
    h.mkdir()
    monkeypatch.setattr(t, "AI_PROWLER_HOME", h)
    monkeypatch.setattr(t, "RUNNING_SERVER_MCP_CONFIG_PATH", h / "claude_mcp_config_running.json")
    monkeypatch.setattr(t, "AI_PROWLER_CONFIG_PATH", h / "config.json")
    monkeypatch.setattr(t, "STATUS_PATH", h / "task_automation_last_run.json")
    monkeypatch.setattr(t, "AUDIT_LOG_PATH", h / "autonomous_run_audit.log")
    # Never start the real app from a test; never wait for real.
    monkeypatch.setattr(t, "_ai_prowler_app_running", lambda: False)
    monkeypatch.setattr(t, "_start_ai_prowler_app", lambda: (False, "mocked"))
    _fake_clock(monkeypatch, t)
    return t, h


def _fake_clock(monkeypatch, t):
    """time.sleep advances a fake clock, so 5-minute waits finish instantly."""
    now = [1_000_000.0]
    monkeypatch.setattr(t.time, "time", lambda: now[0])
    monkeypatch.setattr(t.time, "sleep", lambda s: now.__setitem__(0, now[0] + s))


def test_D1_running_server_is_used_with_the_owners_bearer_token(tq, monkeypatch):
    t, h = tq
    (h / "config.json").write_text(json.dumps({"remote_token": "OWNER-TOKEN"}), encoding="utf-8")

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
    seen = []
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=0: (seen.append(req), _Resp())[1])
    path = t.scheduled_run_mcp_config()
    assert path == str(h / "claude_mcp_config_running.json")
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))["mcpServers"]["ai-prowler"]
    assert cfg["url"] == "http://localhost:8000/mcp" and cfg["headers"]["Authorization"] == "Bearer OWNER-TOKEN"
    assert "command" not in cfg                                    # never a second copy
    assert seen and seen[0].full_url == "http://localhost:8000/health"
    assert seen[0].get_header("Authorization") == "Bearer OWNER-TOKEN"
    assert not (h / "claude_mcp_config_now.json").exists()          # the ▶ NOW file is left alone


def test_D2_nothing_running_means_skipped_not_a_second_copy(tq, monkeypatch):
    t, h = tq
    (h / "config.json").write_text(json.dumps({"remote_token": "T"}), encoding="utf-8")
    import urllib.request

    def refuse(*a, **k):
        raise OSError("refused")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(t, "SERVER_START_WAIT_SEC", 0)
    ok, why = t.connect_to_running_ai_prowler(wait_sec=0)
    assert ok is False and "isn't running" in why
    assert t.scheduled_run_mcp_config() == "NO_SERVER"
    assert "skipped" in (h / "last_headless_run.json").read_text(encoding="utf-8").lower()


def test_D3_no_bearer_token_means_no_run(tq):
    t, h = tq
    assert t.scheduled_run_mcp_config() == "NO_SERVER"               # no config.json at all
    assert "Bearer Token" in json.loads((h / "task_automation_last_run.json").read_text(encoding="utf-8"))["detail"]


def test_D4_no_stdio_path_is_left_in_the_code():
    """The stdio config writers and the stdio Grok client are gone for good."""
    import task_queue_automation as t
    for gone in ("_generate_local_mcp_config", "_generate_localhost_mcp_config",
                 "_generate_remote_mcp_config", "runtime_mcp_config", "_StdioMCPClient"):
        assert not hasattr(t, gone), gone


def test_D5_queue_wrapper_picks_the_config_at_run_time(tq):
    t, h = tq
    bat = t.build_wrapper_script_content(r"C:\cfg\stdio.json", "mcp__ai-prowler__*")
    assert "stdio.json" not in bat                                  # no fixed file baked in
    assert "_t.scheduled_run_mcp_config()" in bat
    assert '--mcp-config "%AIP_MCP_CONFIG%"' in bat and "--strict-mcp-config" in bat
    assert bat.index("AIP_MCP_CONFIG=%%M") < bat.index("NO_SERVER") < bat.index("-p \"")


@pytest.mark.skipif(os.name != "nt", reason="runs the generated line through cmd.exe")
def test_D6_the_generated_lines_really_work_in_cmd(tmp_path):
    """Runs the wrapper's AIP_MCP_CONFIG lines through cmd.exe with a fake
    empty home (no config.json -> no Bearer Token -> NO_SERVER, nothing
    started). Catches quoting mistakes the text checks above can't."""
    import task_queue_automation as t
    bat = t.build_wrapper_script_content(r"C:\cfg\stdio.json", "mcp__ai-prowler__*")
    lines = [l for l in bat.splitlines()
             if "AIP_MCP_CONFIG" in l and l.lstrip().lower().startswith(("set ", "for "))]
    script = tmp_path / "pick.bat"
    script.write_text("@echo off\r\n" + "\r\n".join(lines) + "\r\necho PICKED=%AIP_MCP_CONFIG%\r\n",
                      encoding="utf-8")
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    env = dict(os.environ, USERPROFILE=str(fake_home), HOME=str(fake_home))
    env.pop("AIPROWLER_TEST_STATE_DIR", None)
    r = subprocess.run(["cmd", "/c", str(script)], capture_output=True, text=True, env=env, timeout=120)
    assert "PICKED=NO_SERVER" in r.stdout, (r.stdout, r.stderr)
    # the skip was recorded in the FAKE home, never the real one
    assert (fake_home / ".ai-prowler" / "last_headless_run.json").exists()


def test_D7_now_button_uses_the_running_server_and_never_starts_it():
    i = _TQA.index("def generate_mcp_config_for_now_button")
    body = _TQA[i:_TQA.index("\ndef ", i + 10)]
    assert "connect_to_running_ai_prowler(" in body and "start_app=False" in body


# ── the Grok runner's HTTP client, against a tiny local MCP-like server ───

class _FakeMCPServer:
    """Answers JSON-RPC POSTs like AI-Prowler's /mcp: initialize issues a
    session id (sent back as Mcp-Session-Id) and replies over SSE."""

    def __init__(self, sse=True):
        import http.server
        import threading
        outer = self
        self.requests, self.deleted = [], []
        self.sse = sse

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((dict(self.headers), body))
                if "id" not in body:                       # a notification
                    self.send_response(202); self.end_headers(); return
                m = body["method"]
                if m == "initialize":
                    result = {"serverInfo": {"name": "AI-Prowler"}, "capabilities": {}}
                elif m == "tools/list":
                    result = {"tools": [{"name": "get_pending_analysis_tasks", "inputSchema": {"type": "object"}}]}
                elif m == "tools/call" and body["params"]["name"] == "bad":
                    result = {"isError": True, "content": [{"type": "text", "text": "nope"}]}
                else:
                    result = {"content": [{"type": "text", "text": "line1"}, {"type": "text", "text": "line2"}]}
                msg = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result})
                self.send_response(200)
                if m == "initialize":
                    self.send_header("Mcp-Session-Id", "SESSION-42")
                if outer.sse:
                    self.send_header("Content-Type", "text/event-stream")
                    out = f"event: message\r\ndata: {msg}\r\n\r\n".encode()
                else:
                    self.send_header("Content-Type", "application/json")
                    out = msg.encode()
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_DELETE(self):
                outer.deleted.append(self.headers.get("Mcp-Session-Id"))
                self.send_response(200); self.end_headers()

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()


@pytest.mark.parametrize("sse", [True, False], ids=["sse", "json"])
def test_D8_http_client_talks_to_a_running_server(sse):
    import task_queue_automation as t
    srv = _FakeMCPServer(sse=sse)
    try:
        c = t._HttpMCPClient("OWNER-TOKEN", url=srv.url)
        assert c.initialize()["serverInfo"]["name"] == "AI-Prowler"
        assert [x["name"] for x in c.list_tools()] == ["get_pending_analysis_tasks"]
        assert c.call_tool("get_pending_analysis_tasks", {}) == "line1\nline2"
        with pytest.raises(RuntimeError, match="nope"):
            c.call_tool("bad")
        c.close()
    finally:
        srv.stop()
    hdrs = [h for h, _ in srv.requests]
    assert all(h.get("Authorization") == "Bearer OWNER-TOKEN" for h in hdrs)
    assert "Mcp-Session-Id" not in hdrs[0]                         # initialize: no session yet
    assert all(h.get("Mcp-Session-Id") == "SESSION-42" for h in hdrs[1:])
    assert [b.get("method") for _, b in srv.requests][:2] == ["initialize", "notifications/initialized"]
    assert srv.deleted == ["SESSION-42"]                           # session closed at the end


def test_D9_http_client_defaults_to_the_local_connection():
    import task_queue_automation as t
    assert t._HttpMCPClient("x")._url == "http://localhost:8000/mcp"


def test_D10_http_client_reports_a_dead_server():
    import socket
    import task_queue_automation as t
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    c = t._HttpMCPClient("x", url=f"http://127.0.0.1:{port}/mcp")
    with pytest.raises(Exception):
        c.initialize(timeout=5)


# ══════════════════════════════════════════════════════════════════════════
# E. home address for a route's start/end (was get_route_start_options)
# ══════════════════════════════════════════════════════════════════════════

def _ctx(user):
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(uid="jake-r", name="Jake R", role="field_crew", home=""):
    return {"id": uid, "name": name, "role": role, "status": "active", "email": "j@example.com",
            "home_address": home, "scopes": []}


@pytest.fixture
def as_user(monkeypatch, mcp_mod):
    def _set(user):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        return _ctx(user) if user else None
    return _set


def test_E1_personal_mode_uses_the_owner_address_from_settings(mcp_mod, as_user, monkeypatch):
    ctx = as_user(None)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "1 Main St", "city": "New Smyrna Beach", "state": "FL", "zip": "32168"})
    addr, label = mcp_mod._resolve_route_home(ctx)
    assert addr == "1 Main St, New Smyrna Beach FL 32168" and "Settings" in label


def test_E2_server_field_crew_gets_their_own_address(mcp_mod, as_user):
    addr, label = mcp_mod._resolve_route_home(as_user(_user(home="9 Palm Ave, Edgewater FL")))
    assert addr == "9 Palm Ave, Edgewater FL" and "Jake R" in label


def test_E3_server_never_falls_back_to_the_host_owners_address(mcp_mod, as_user, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "OWNER HOME", "city": "", "state": "", "zip": ""})
    assert mcp_mod._resolve_route_home(as_user(_user(home="")))[0] == ""


def test_E4_staff_can_use_a_crew_members_address(mcp_mod, as_user, monkeypatch):
    ctx = as_user(_user("dave", "Dave O", "owner", home="Dave's House"))
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: {"users": {
        "tok1": {"name": "Sam Crew", "role": "field_crew", "status": "active", "home_address": "5 Oak St"},
        "tok2": {"name": "Sam Crew", "role": "field_crew", "status": "suspended", "home_address": "OLD"}}})
    addr, label = mcp_mod._resolve_route_home(ctx, "sam crew")
    assert addr == "5 Oak St" and "Sam Crew" in label


def test_E5_field_crew_cannot_use_a_colleagues_address(mcp_mod, as_user, monkeypatch):
    ctx = as_user(_user(home="MY HOME"))
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: {"users": {
        "t": {"name": "Sam Crew", "role": "field_crew", "status": "active", "home_address": "SAMS HOME"}}})
    assert mcp_mod._resolve_route_home(ctx, "Sam Crew")[0] == "MY HOME"


# ══════════════════════════════════════════════════════════════════════════
# F. Personal Links & Analysis 📋 Copy / ✉ Email Token (unchanged)
# ══════════════════════════════════════════════════════════════════════════

_LA = _GUI[_GUI.index("def _tqa_copy_token"):_GUI.index("def _tqa_on_auth_change")]


def test_F1_copy_and_email_buttons_exist_next_to_get_renew():
    assert 'text="📋 Copy Token"' in _LA and 'text="✉ Email Token to Me"' in _LA
    assert _LA.index("_tqa_btn_get_token = ttk.Button") < _LA.index("_tqa_btn_copy_token = ttk.Button")


def test_F2_copy_reads_the_saved_token_and_handles_none():
    body = _LA[_LA.index("def _tqa_copy_token"):_LA.index("def _tqa_email_token")]
    assert "_tqa.load_oauth_token()" in body and "clipboard_append(tok)" in body
    assert "No Token Yet" in body and body.index("No Token Yet") < body.index("clipboard_append")


def test_F3_email_asks_first_and_goes_only_to_the_installs_own_address():
    body = _LA[_LA.index("def _tqa_email_token"):_LA.index("_tqa_btn_row = tk.Frame")]
    assert "askyesno" in body and body.index("askyesno") < body.index("_send_smtp(")
    assert '_ecfg.get("default_to")' in body and "_send_smtp(_to," in body
    for line in body.splitlines():
        if "messagebox." in line:
            assert "tok" not in line.replace("Token", "")

"""
tests/unit/test_task_queue_api.py — analysis tasks that each run on their own schedule, on the Agent API Key
(2026-11-01, David: "remove the CLI token method ... only use API tokens ... the same API token that the agents
use", then "get rid of the task queue and make every task have its own schedule").

  TQ-01..04  settings: the Agent API Key, the agents' complex model, a per-task AI override, exact cost
  TQ-05..09  one run = one task: key / budget / connection checks, the Claude tool loop with prompt caching
             and exact cost recorded on the task, web-search fallback, the spending ceiling, Grok
  TQ-10..12  AI-Prowler's own scheduler: due auto-run tasks only, one call each, paused, retry after an hour,
             ▶ Run now from the phone vs. from a chat
  TQ-13..14  the old queue / CLI are cleaned up once; no CLI anything is left

No network, no real AI calls, never this computer's ~/.ai-prowler.
Run: run_tests.bat tests\\unit\\test_task_queue_api.py -v
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import custom_tasks_manager as ctm  # noqa: E402
import desk_agent_providers as prov  # noqa: E402
import task_queue_automation as tqa  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / ".ai-prowler"
    h.mkdir()
    for name, rel in (("AI_PROWLER_HOME", ""), ("CONFIG_PATH", "task_automation_config.json"),
                      ("STATUS_PATH", "task_automation_last_run.json"),
                      ("AUDIT_LOG_PATH", "autonomous_run_audit.log"),
                      ("AI_PROWLER_CONFIG_PATH", "config.json")):
        monkeypatch.setattr(tqa, name, h / rel if rel else h)
    monkeypatch.setattr(ctm, "CUSTOM_TASKS_PATH", h / "custom_analysis_tasks.json")
    monkeypatch.setattr(ctm, "LEGACY_QUEUE_PATH", h / "pending_tasks.json")
    monkeypatch.setattr(ctm, "QUEUE_RETIRED_MARKER", h / "task_queue_retired.marker")
    (h / "config.json").write_text(json.dumps({"remote_token": "OWNER-TOKEN"}), encoding="utf-8")
    monkeypatch.setattr(tqa, "budget_left", lambda now=None: (5.0, 20.0))
    alerts = []
    monkeypatch.setattr(tqa, "_alert_budget", lambda model: alerts.append(model))
    monkeypatch.setattr(tqa, "_server_answers", lambda token, timeout=3: True)
    monkeypatch.setattr(tqa, "http_post", None)
    return {"h": h, "alerts": alerts}


def _task(label="Weekly AR check", schedule="weekly", due="2026-10-05", auto_run=True, **kw):
    """Add a task and back-date it so it's due (create_task only takes future first dates)."""
    tasks = ctm.load_custom_tasks()
    t = ctm.create_task(label=label, prompt="Summarize overdue invoices.", scope_dirs=[],
                        schedule=schedule, first_due=None if schedule == "none" else "2027-01-04",
                        auto_run=auto_run, **kw)
    if schedule != "none" and due:
        t["next_due"] = due if schedule != "daily" else due + "T09:00:00"
    tasks.append(t)
    ctm.save_custom_tasks(tasks)
    return t["task_id"]


def _get(task_id):
    return ctm.get_task(ctm.load_custom_tasks(), task_id)


class FakeClient:
    calls: list = []

    def __init__(self, token, url=None):
        self.token = token
        FakeClient.calls = []

    def initialize(self, timeout=60):
        return {}

    def list_tools(self):
        return [{"name": "search_documents", "description": "d", "inputSchema": {"type": "object"}},
                {"name": "record_learning", "description": "d", "inputSchema": {"type": "object"}},
                {"name": "complete_analysis_task", "description": "AI-Prowler records runs", "inputSchema": {"type": "object"}},
                {"name": "write_file", "description": "never offered", "inputSchema": {"type": "object"}}]

    def call_tool(self, name, arguments=None, timeout=300):
        FakeClient.calls.append((name, arguments))
        return "ok: " + name

    def close(self):
        pass


def _claude_replies(*replies):
    seen = []

    def post(url, body, headers):
        seen.append((url, json.loads(json.dumps(body)), headers))
        return replies[len(seen) - 1]
    return post, seen


TOOL_TURN = {"content": [{"type": "tool_use", "id": "u1", "name": "search_documents", "input": {"query": "AR"}}],
             "stop_reason": "tool_use",
             "usage": {"input_tokens": 500, "cache_creation_input_tokens": 10_000, "cache_read_input_tokens": 0,
                       "output_tokens": 100}}
DONE_TURN = {"content": [{"type": "text", "text": "Two invoices are overdue."}], "stop_reason": "end_turn",
             "usage": {"input_tokens": 300, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 10_500,
                       "output_tokens": 200, "server_tool_use": {"web_search_requests": 1}}}


# ── settings ─────────────────────────────────────────────────────────────────────────

def test_TQ_01_default_ai_is_the_agents_complex_model_on_the_agent_key(home):
    cfg = {"provider": "claude", "agent_claude_model": "claude-opus-5-5", "agent_claude_model_light": "claude-haiku-5-5"}
    assert tqa.runner(cfg) == "claude_api" and tqa.model_for(cfg) == "claude-opus-5-5"   # never the light model
    assert tqa.model_for({"provider": "grok"}) == "grok-4.3"
    assert not tqa.has_key(cfg)
    prov.store_agent_key("sk-ant-api03-agents", "anthropic")
    assert tqa.has_key(cfg) and tqa._load_key(cfg) == "sk-ant-api03-agents"
    c = tqa.load_config()
    assert c["paused"] is False and "enabled" not in c and "schedule_time" not in c


def test_TQ_02_a_task_can_override_the_ai(home):
    cfg = {"provider": "claude"}
    assert tqa.runner(cfg, {"ai_provider": "grok"}) == "grok_api"
    assert tqa.model_for(cfg, {"ai_provider": "claude", "ai_model": "claude-opus-5-5"}) == "claude-opus-5-5"
    assert tqa.model_for(cfg, {"ai_provider": ""}) == tqa.model_for(cfg)            # "" = the default
    tid = _task(ai_provider="grok")
    assert _get(tid)["ai_provider"] == "grok" and ctm.ai_label(_get(tid)) == "Grok"
    with pytest.raises(ValueError):
        _task(label="bad", ai_provider="claude", ai_model="gpt-9")
    with pytest.raises(ValueError):
        _task(label="bad time", run_time="8.30")


def test_TQ_03_why_not_ready_names_what_is_missing(home, monkeypatch):
    assert "Agent API Key" in tqa.why_not_ready({"provider": "claude"})
    prov.store_agent_key("xai-k", "grok")
    assert tqa.why_not_ready({"provider": "grok"}) == ""
    assert "Agent API Key" in tqa.why_not_ready({"provider": "grok"}, {"ai_provider": "claude"})   # the task's AI
    monkeypatch.setattr(tqa, "budget_left", lambda now=None: (0.0, 20.0))
    assert "used up" in tqa.why_not_ready({"provider": "grok"})
    monkeypatch.setattr(tqa, "budget_left", lambda now=None: (0.0, 0.0))
    assert "$0" in tqa.why_not_ready({"provider": "grok"})
    (home["h"] / "config.json").write_text("{}", encoding="utf-8")
    assert "Bearer Token" in tqa.why_not_ready({"provider": "grok"})


def test_TQ_04_exact_cost_counts_caching_and_web_searches():
    u = {"input": 1_000, "cache_write": 20_000, "cache_read": 100_000, "output": 2_000}
    # Sonnet $2/$10, cache reads $0.10 per 1M since Oct 2026 (2026-11-03 live cost test):
    # 1k*2 + 20k*2.5 + 100k*0.1 + 2k*10 = 82,000 / 1M = $0.082, + 2 searches = $0.102
    assert tqa.run_cost("claude-sonnet-5-5", u, 2) == pytest.approx(0.102)
    # Haiku 5.5: a prompt over 100K tokens (new + cache) pays 5x on everything
    big = {"input": 1_000, "cache_write": 0, "cache_read": 120_000, "output": 1_000}
    assert tqa.run_cost("claude-haiku-5-5", big) == pytest.approx((1_000 * 0.5 + 120_000 * 0.05 + 1_000 * 2.5) / 1e6)


# ── a run ────────────────────────────────────────────────────────────────────────────

def test_TQ_05_missing_key_skips_leaves_it_due_and_waits_an_hour(home):
    tid = _task()
    ok, why = tqa.run_task(tid, "schedule")
    t = _get(tid)
    assert not ok and "Agent API Key" in why and tqa.load_last_run()["status"] == "skipped"
    assert t["next_due"] == "2026-10-05" and "Agent API Key" in t["last_skip"]["why"]
    assert ctm.skipped_recently(t)
    ok, _ = tqa.run_task("nope", "manual")
    assert not ok


def test_TQ_06_claude_run_uses_tools_caching_and_records_cost_on_the_task(home, monkeypatch):
    prov.store_agent_key("sk-ant-api03-k", "anthropic")
    tid = _task()
    monkeypatch.setattr(tqa, "_HttpMCPClient", FakeClient)
    post, seen = _claude_replies(TOOL_TURN, DONE_TURN)
    monkeypatch.setattr(tqa, "http_post", post)
    ok, detail = tqa.run_task(tid, "schedule")
    assert ok and "Two invoices are overdue." in detail and "Cost of this run" in detail
    url, body, headers = seen[0]
    assert url == tqa.CLAUDE_URL and headers["x-api-key"] == "sk-ant-api03-k"
    assert body["model"] == "claude-sonnet-5-5"
    names = [t.get("name") for t in body["tools"]]
    assert "write_file" not in names and "complete_analysis_task" not in names    # AI-Prowler records the run
    assert names[:2] == ["search_documents", "record_learning"]
    assert body["tools"][-1]["type"] == tqa.WEB_SEARCH_TOOL["type"]
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}         # system cached
    prompt = json.dumps(body["messages"])
    assert "Weekly AR check" in prompt and "Summarize overdue invoices." in prompt
    msgs = seen[1][1]["messages"]                    # round 2: the breakpoint is on the newest block only
    assert msgs[-1]["content"][-1]["type"] == "tool_result" and "cache_control" in msgs[-1]["content"][-1]
    assert "cache_control" not in json.dumps(msgs[:-1])
    assert FakeClient.calls == [("search_documents", {"query": "AR"})]
    expect = (800 * 2 + 10_000 * 2.5 + 10_500 * 0.1 + 300 * 10) / 1_000_000 + 0.01     # Sonnet cache read $0.10/1M
    con = sqlite3.connect(tqa.runs_db_path())
    row = con.execute("SELECT provider, model, items, ok, cost_usd FROM agent_runs").fetchone()
    con.close()
    assert row[:4] == ("claude_api", "claude-sonnet-5-5", 1, 1) and row[4] == pytest.approx(expect, abs=1e-5)
    t = _get(tid)                                                    # recorded on the task, moved on
    assert t["last_status"] == "completed" and t["last_summary"].startswith("Two invoices")
    assert t["last_cost_usd"] == pytest.approx(expect, abs=1e-5) and t["next_due"] > "2026-10-05"
    assert t["next_due"] >= datetime.now().date().isoformat()        # missed weeks don't pile up
    assert "Last: ✅" in ctm.last_run_text(t) and "$0.0" in ctm.last_run_text(t)
    assert home["alerts"] == ["claude-sonnet-5-5"] and not Path(tqa.RUN_LOCK_PATH).exists()


def test_TQ_07_web_search_is_dropped_when_the_key_cant_use_it(home, monkeypatch):
    prov.store_agent_key("sk-ant-api03-k", "anthropic")
    tid = _task()
    monkeypatch.setattr(tqa, "_HttpMCPClient", FakeClient)
    bodies = []

    def post(url, body, headers):
        bodies.append(body)
        if len(bodies) == 1:
            raise tqa.RunError('HTTP 400: {"error": "web_search is not enabled"}')
        return DONE_TURN
    monkeypatch.setattr(tqa, "http_post", post)
    ok, _ = tqa.run_task(tid)
    assert ok and len(bodies) == 2
    assert all(t.get("type") != tqa.WEB_SEARCH_TOOL["type"] for t in bodies[1]["tools"])


def test_TQ_08_a_run_stops_at_its_spending_ceiling(home, monkeypatch):
    prov.store_agent_key("sk-ant-api03-k", "anthropic")
    tid = _task()
    monkeypatch.setattr(tqa, "_HttpMCPClient", FakeClient)
    monkeypatch.setattr(tqa, "budget_left", lambda now=None: (0.03, 20.0))      # 3¢ left this month
    expensive = dict(TOOL_TURN, usage={"input_tokens": 20_000, "output_tokens": 0})   # 4¢ a round
    monkeypatch.setattr(tqa, "http_post", lambda *a: expensive)
    ok, detail = tqa.run_task(tid)
    assert not ok and "spending limit" in detail
    assert _get(tid)["last_status"] == "failed"                 # it cost money: recorded, not retried


def test_TQ_09_grok_task_on_a_claude_default(home, monkeypatch):
    prov.store_agent_key("xai-k", "grok")
    tid = _task(ai_provider="grok")
    monkeypatch.setattr(tqa, "_HttpMCPClient", FakeClient)
    replies = [
        {"choices": [{"message": {"tool_calls": [{"id": "c1", "function": {
            "name": "search_documents", "arguments": '{"query": "AR"}'}}]}}],
         "usage": {"prompt_tokens": 1000, "completion_tokens": 50}},
        {"choices": [{"message": {"content": "Done."}}], "usage": {"prompt_tokens": 1200, "completion_tokens": 40}},
    ]
    seen = []
    monkeypatch.setattr(tqa, "http_post", lambda url, body, headers: (seen.append((url, headers)), replies[len(seen) - 1])[1])
    ok, detail = tqa.run_task(tid)
    assert ok and "Done." in detail
    assert seen[0][0] == tqa.XAI_API_URL and seen[0][1]["Authorization"] == "Bearer xai-k"
    assert FakeClient.calls == [("search_documents", {"query": "AR"})]


# ── AI-Prowler's own scheduler ───────────────────────────────────────────────────────

def test_TQ_10_only_due_auto_run_tasks_run_one_call_each(home):
    a = _task("A")
    b = _task("B")
    off = _task("Chat runs me", auto_run=False)
    _task("Not yet", due="2099-01-05")
    once = _task("One-off", schedule="none")
    ran = []
    out = tqa.scheduler_tick(run_fn=lambda tid: (ran.append(tid), (True, ""))[1])
    assert sorted(ran) == sorted([a, b]) and sorted(out) == sorted([(a, True), (b, True)])
    assert [t["task_id"] for t in ctm.chat_due_tasks(ctm.load_custom_tasks())] == [off]   # nothing runs twice
    assert once not in ran
    tqa.save_config(dict(tqa.load_config(), paused=True))
    assert tqa.scheduler_tick(run_fn=lambda tid: pytest.fail("paused")) == ["paused"]


def test_TQ_11_a_task_that_couldnt_start_waits_an_hour(home):
    tid = _task()
    tqa.run_task(tid, "schedule")                                    # no key → skipped
    assert tqa.scheduler_tick(run_fn=lambda t: pytest.fail("tried again too soon")) == []
    t = _get(tid)
    later = datetime.fromisoformat(t["last_skip"]["at"]).replace(microsecond=0)
    from datetime import timedelta
    ran = []
    tqa.scheduler_tick(now=later + timedelta(minutes=61), run_fn=lambda x: (ran.append(x), (False, ""))[1])
    assert ran == [tid]


def test_TQ_12_run_now_from_the_phone_or_from_a_chat(home, monkeypatch):
    tid = _task("Later", due="2099-01-05")
    tasks = ctm.load_custom_tasks()
    ctm.request_run(tasks, tid, by=ctm.BY_AI_PROWLER)                  # phone ▶ Run now
    ctm.save_custom_tasks(tasks)
    assert ctm.chat_due_tasks(ctm.load_custom_tasks()) == []
    ran = []
    tqa.scheduler_tick(run_fn=lambda x: (ran.append(x), (True, ""))[1])
    assert ran == [tid]
    tasks = ctm.load_custom_tasks()
    ctm.record_run(tasks, tid, "completed", "ok", 0.01)
    assert tasks[0]["next_due"] == "2099-01-05" and not tasks[0]["run_requested"]   # not due: schedule kept
    ctm.request_run(tasks, tid, by="chat")                             # "run it now" in a chat
    ctm.save_custom_tasks(tasks)
    assert [t["task_id"] for t in ctm.chat_due_tasks(ctm.load_custom_tasks())] == [tid]
    assert tqa.scheduler_tick(run_fn=lambda x: pytest.fail("the chat runs it")) == []
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(home["h"]))
    assert tqa.start_scheduler() is False                     # never in a test server / the test suite


# ── the old queue / CLI ──────────────────────────────────────────────────────────────

def test_TQ_13_old_queue_moves_into_the_tasks_once(home):
    keep = _task("Kept", due="2099-01-05", auto_run=False)
    (home["h"] / "pending_tasks.json").write_text(json.dumps([
        {"task_id": "q1", "source_id": keep, "label": "Kept", "schedule": "weekly", "status": "pending"},
        {"task_id": "q2", "type": "ar_aging", "label": "AR Aging Review", "prompt": "Review AR.",
         "schedule": "none", "status": "pending"},
        {"task_id": "q3", "label": "Done one", "prompt": "x", "schedule": "none", "status": "completed"},
    ]), encoding="utf-8")
    tqa.CONFIG_PATH.write_text(json.dumps({"enabled": True, "schedule_time": "07:15", "check_times_per_day": 3}))
    done = tqa.retire_queue()
    tasks = ctm.load_custom_tasks()
    labels = sorted(t["label"] for t in tasks)
    assert labels == ["AR Aging Review", "Kept"]
    ar = next(t for t in tasks if t["label"] == "AR Aging Review")
    assert ar["run_requested"] and not ar["auto_run"]                 # a chat runs the queued one-off
    assert next(t for t in tasks if t["label"] == "Kept")["auto_run"]  # the queue was on → runs on its own
    c = tqa.load_config()
    assert c["paused"] is False and "enabled" not in c and "schedule_time" not in c
    assert (home["h"] / "pending_tasks.json.retired").exists() and not (home["h"] / "pending_tasks.json").exists()
    assert any("set to run on their own" in d for d in done)
    assert tqa.retire_queue() == []                                   # once only


def test_TQ_13b_old_keys_token_and_wrappers_are_removed_once(home, tmp_path):
    legacy = Path(tqa.LEGACY_HOME)
    legacy.mkdir(parents=True, exist_ok=True)
    for name in ("claude_api_key.txt", "grok_api_key.txt", "claude_oauth_token.json", "claude_oauth_token.txt",
                 "run_ai_prowler_queue.bat", "claude_mcp_config.json"):
        (legacy / name).write_text("old", encoding="utf-8")
    (legacy / "manual_run").mkdir()
    (legacy / "agent_claude_api_key.txt").write_text("keep", encoding="utf-8")      # the agents' key stays
    (legacy / "task_automation_config.json").write_text("{}", encoding="utf-8")
    done = tqa.retire_legacy_queue()
    assert any("claude_api_key.txt" in d for d in done) and any("manual_run" in d for d in done)
    left = sorted(p.name for p in legacy.iterdir())
    assert left == sorted(["agent_claude_api_key.txt", tqa.LEGACY_MARKER_NAME, "task_automation_config.json"])
    (legacy / "claude_api_key.txt").write_text("again", encoding="utf-8")
    assert tqa.retire_legacy_queue() == [] and (legacy / "claude_api_key.txt").exists()   # marker: once only


def test_TQ_14_no_cli_or_queue_anything_is_left():
    for gone in ("claude_code_cli_installed", "install_claude_code_cli", "open_setup_token_terminal",
                 "check_token_expiry", "build_wrapper_script_content", "install_scheduled_task",
                 "uninstall_scheduled_task", "grant_batch_logon_right", "dry_run_check", "save_api_key",
                 "load_api_key", "load_oauth_token", "generate_mcp_config", "_get_claude_exe",
                 "run_queue", "check_times", "due_tasks", "run_single_prompt"):
        assert not hasattr(tqa, gone), gone
    assert "mcp__ai-prowler__" not in tqa.TASK_RUN_PROMPT
    src = (ROOT / "task_queue_automation.py").read_text(encoding="utf-8")
    assert "claude -p" not in src and "schtasks /create" not in src.lower()
    iss = (ROOT / "AI-Prowler-Setup.iss").read_text(encoding="utf-8", errors="replace")
    assert "claude.ai/install.ps1" not in iss and "\n    GrantBatchLogonRight();" not in iss
    mcp = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = mcp.index("Starting SERVER-MODE HTTP transport")
    assert "_tqa_sched.start_scheduler()" in mcp[i:i + 2000]                 # personal HTTP server only
    assert "_save_pending_tasks" not in mcp and "_PENDING_TASKS_FILE" not in mcp
    sj = (ROOT / "scheduler_jobs.py").read_text(encoding="utf-8")
    assert "pending_tasks.json" not in sj
    gui = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
    assert "Show Queue (" not in gui and "_ANALYSIS_TASKS = [" not in gui and "tasks_to_queue_entries" not in gui
    assert "_tqg.build_section(" in gui and "retire_queue()" in gui


# ── the section (🧠 AI Analysis Tasks) ─────────────────────────────────────────────────

@pytest.fixture
def tkroot():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    yield root
    root.destroy()


class _MB:
    def __init__(self, yes=True):
        self.said = []
        self.yes = yes

    def __getattr__(self, name):
        def f(title, msg, **k):
            self.said.append((name, msg))
            return self.yes
        return f


def _section(tkroot, run_fn=None, legacy=False, yes=True):
    import task_queue_gui as tqg
    mb = _MB(yes)
    clipped = []
    frame = __import__("tkinter").Frame(tkroot)
    frame.pack()
    p = tqg.build_section(frame, root=tkroot, messagebox=mb, run_fn=run_fn, legacy_check_fn=lambda: legacy,
                          legacy_remove_fn=lambda: (True, "removed"), clipboard_fn=clipped.append,
                          dirs_fn=lambda: [])
    return p, mb, clipped


def _texts(w):
    out = []
    for c in w.winfo_children():
        try:
            out.append(str(c.cget("text")))
        except Exception:
            pass
        out += _texts(c)
    return out


def _wait(tkroot, cond, n=60):
    import time
    for _ in range(n):
        tkroot.update()
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_TQ_15_one_section_no_queue_no_cli_and_the_key_line(home, tkroot):
    p, _, _ = _section(tkroot)
    texts = " ".join(_texts(p["banner"]))
    for gone in ("Install Claude Code", "Get / Renew Token", "Dry Run", "Show Queue", "▶ Queue", "Task Queue",
                 "times/day"):
        assert gone not in texts, gone
    assert "AI Analysis Tasks" in texts and "+ New Task" in texts and "Automatic runs ON" in texts
    assert "📊 Analyze My Business" in texts                      # the starters
    assert "No Claude (Anthropic) API key saved" in p["key_var"].get()
    prov.store_agent_key("sk-ant-api03-k", "anthropic")
    p["refresh"]()
    assert "Claude Sonnet 5.5" in p["key_var"].get()
    p["toggle"]()
    assert tqa.load_config()["paused"] is True and "PAUSED" in p["btn_toggle"].cget("text")


def test_TQ_16_a_starter_opens_a_prefilled_editor_and_saves_a_scheduled_task(home, tkroot):
    import task_queue_gui as tqg
    p, mb, _ = _section(tkroot)
    ed = p["open_editor"](tqg.starter_task_fields(tqg.STARTERS[0]))
    assert ed["name_var"].get() == "📊 Analyze My Business" and "complete_analysis_task" not in tqg.STARTERS[0]["prompt"]
    body = ed["prompt_box"].get("1.0", "end-1c")
    assert body.startswith("DATA SOURCES") and "spreadsheet" not in body.lower().replace("read_job_spreadsheet", "")
    for tool in ("list_tickets", "review_booking", "hr_get_task_digest", "find_stale_customers"):
        assert tool in tqg.STARTERS[2]["prompt"], tool                 # Find Problems covers every app
    assert ctm.load_custom_tasks() == []                             # nothing saved until Save
    ed["sched_var"].set("Weekly")
    ed["due_var"].set("2027-01-04")
    ed["dow_var"].set("Monday")
    ed["run_time_var"].set("08:00")
    ed["ai_var"].set("Grok")
    tkroot.update()
    assert ed["time_row"].winfo_manager() == "pack" and ed["auto_cb"].winfo_manager() == "pack"
    ed["save"]()
    (t,) = ctm.load_custom_tasks()
    assert t["schedule"] == "weekly" and t["run_time"] == "08:00" and t["schedule_day_of_week"] == 0
    assert t["auto_run"] is True and t["ai_provider"] == "grok"
    assert p["count_var"].get() == f"1 / {ctm.MAX_CUSTOM_TASKS}"
    assert "Weekly · Mon · 08:00  ·  Grok" in " ".join(_texts(p["list_frame"]))
    ed2 = p["open_editor"](t)
    ed2["run_time_var"].set("8.30")
    assert ed2["save"]() is None and mb.said[-1][0] == "showwarning"   # bad time: nothing saved
    assert ctm.load_custom_tasks()[0]["run_time"] == "08:00"


def test_TQ_17_run_now_copy_for_chat_auto_run_and_delete(home, tkroot):
    tid = _task("Row task", due="2099-01-05")
    ran = []
    p, mb, clipped = _section(tkroot, run_fn=lambda i: ran.append(i) or (True, "Done. (Cost of this run: $0.0123)"))
    p["run_now"](tid)                                     # no key: offers a chat instead
    assert ran == [] and "Agent API Key" in mb.said[-1][1]
    assert clipped and "complete_analysis_task(task_id=\"%s\"" % tid in clipped[-1]
    assert "Summarize overdue invoices." in clipped[-1]
    prov.store_agent_key("sk-ant-api03-k", "anthropic")
    p["run_now"](tid)
    assert _wait(tkroot, lambda: mb.said and mb.said[-1][0] == "showinfo")
    assert ran == [tid] and "$0.0123" in mb.said[-1][1] and not p["running"]
    p["delete"](tid)
    assert ctm.load_custom_tasks() == [] and p["count_var"].get().startswith("0 /")


def test_TQ_18_old_windows_task_gets_a_one_time_remove_button(home, tkroot):
    p, mb, _ = _section(tkroot, legacy=True)
    assert _wait(tkroot, lambda: p["legacy_row"].winfo_manager() == "pack")
    p["remove_legacy"]()
    tkroot.update()
    assert p["legacy_row"].winfo_manager() == "" and mb.said[-1][0] == "showinfo"


def test_TQ_20_every_field_saves_and_reopens(home, tkroot):
    """David 2026-11-01: 'I changed my output setting to send email and saved it ... it did not save when I
    reopened it' — every editor field round-trips, and a starter you saved reopens YOUR task."""
    import task_queue_gui as tqg
    p, mb, _ = _section(tkroot)
    ed = p["open_starter"](tqg.STARTERS[0])
    ed["sched_var"].set("Monthly")
    ed["due_var"].set("2027-02-01")
    ed["run_time_var"].set("07:45")
    ed["dow_var"].set("Friday")
    ed["auto_var"].set(False)
    ed["ai_var"].set("Claude")
    tkroot.update()
    assert "Claude Opus 5.5" in ed["model_combo"].cget("values")             # friendly names, not 5-5
    ed["model_var"].set("Claude Opus 5.5")
    ed["learn_var"].set(False)
    ed["report_var"].set(True)
    ed["email_var"].set(True)
    ed["folder_var"].set("C:/Reports")
    assert ed["save"]() and not mb.said
    (t,) = ctm.load_custom_tasks()
    want = dict(schedule="monthly", run_time="07:45", schedule_day_of_week=4, auto_run=False,
                ai_provider="claude", ai_model="claude-opus-5-5", output_learnings=False, output_report=True,
                output_email=True, report_folder="C:/Reports")
    assert {k: t[k] for k in want} == want
    assert ctm.ai_label(t) == "Claude Opus 5.5"
    ed2 = p["open_starter"](tqg.STARTERS[0])                                  # reopens the saved task
    got = dict(sched=ed2["sched_var"].get(), time=ed2["run_time_var"].get(), dow=ed2["dow_var"].get(),
               auto=ed2["auto_var"].get(), ai=ed2["ai_var"].get(), model=ed2["model_var"].get(),
               learn=ed2["learn_var"].get(), report=ed2["report_var"].get(), email=ed2["email_var"].get(),
               folder=ed2["folder_var"].get())
    assert got == dict(sched="Monthly", time="07:45", dow="Friday", auto=False, ai="Claude",
                       model="Claude Opus 5.5", learn=False, report=True, email=True, folder="C:/Reports")
    ed2["daily_row"]                                                          # daily fields round-trip too
    ed2["sched_var"].set("Daily")
    ed2["start_var"].set("06:00"); ed2["end_var"].set("18:00"); ed2["times_var"].set("3")
    ed2["ai_var"].set("Default AI")
    assert ed2["save"]()
    t = ctm.load_custom_tasks()[0]
    assert (t["schedule"], t["daily_start_time"], t["daily_end_time"], t["daily_times_per_day"],
            t["ai_provider"], t["ai_model"]) == ("daily", "06:00", "18:00", 3, "", "")
    assert len(ctm.load_custom_tasks()) == 1


def test_TQ_21_popup_draws_at_once_and_scrolls_with_the_wheel(home, tkroot):
    import tkinter as tk
    p, _, _ = _section(tkroot)
    ed = p["open_editor"](None)
    win = ed["win"]
    canvas = next(w for w in win.winfo_children() if isinstance(w, tk.Canvas))
    item = canvas.find_all()[0]
    assert int(float(canvas.itemcget(item, "width"))) >= 400          # never 1 pixel wide (the blank popup)
    assert canvas.bind("<MouseWheel>") and ed["model_combo"].bind("<MouseWheel>")
    assert not ed["prompt_box"].bind("<MouseWheel>")                   # the prompt box keeps its own scroll
    win.destroy()


def test_TQ_19_a_task_a_chat_creates_shows_up_by_itself(home, tkroot):
    p, _, _ = _section(tkroot)
    assert p["count_var"].get().startswith("0 /")
    _task("From a chat")
    p["poll_file"]()
    assert p["count_var"].get().startswith("1 /") and "From a chat" in " ".join(_texts(p["list_frame"]))


# ── run log size control (2026-11-02, David: "make sure they have size control") ──────────────────

def _log_sizes():
    return [p.stat().st_size if p.exists() else None for p in tqa.audit_log_files()]


def test_TQ_22_run_log_starts_a_new_file_past_the_limit(home, monkeypatch):
    monkeypatch.setattr(tqa, "AUDIT_LOG_MAX_BYTES", 2000)
    for i in range(200):                                    # ~13 KB of lines
        tqa._audit(f"tool call number {i:04d} …")
    sizes = _log_sizes()
    assert all(s is not None for s in sizes)               # current + .1 + .2
    assert all(s <= 2000 + 200 for s in sizes)             # none grows past the limit (+ one line)
    assert len(tqa.audit_log_files()) == 3                  # never more than 2 backups
    assert not Path(str(tqa.AUDIT_LOG_PATH) + ".3").exists()


def test_TQ_22_run_log_view_reads_back_into_the_older_file(home, monkeypatch):
    monkeypatch.setattr(tqa, "AUDIT_LOG_MAX_BYTES", 2000)
    for i in range(80):
        tqa._audit(f"line {i:04d}")
    tail = tqa.read_audit_log_tail(60).splitlines()
    assert len(tail) == 60 and tail[-1].endswith("line 0079")
    nums = [int(l.rsplit(" ", 1)[1]) for l in tail]
    assert nums == list(range(20, 80))                      # in order, across the file boundary


def test_TQ_22_a_task_run_no_longer_wipes_the_log(home):
    src = (ROOT / "task_queue_automation.py").read_text(encoding="utf-8")
    body = src[src.index("def run_task("):src.index("def run_task(") + 4000]
    assert "rotate_audit_log()" not in body


def test_TQ_22_mcp_server_caps_the_same_log():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("def _append_audit_log(")
    assert "_cap_audit_log()" in src[i:i + 2500]
    assert "_AUDIT_LOG_MAX_BYTES = 512 * 1024" in src and tqa.AUDIT_LOG_MAX_BYTES == 512 * 1024


def test_TQ_22_clear_log_asks_and_empties_the_backups_too(home, tkroot):
    for p in tqa.audit_log_files():
        p.write_text("old line\n", encoding="utf-8")
    p, mb, _ = _section(tkroot, yes=False)
    assert p["clear_log"]() is False                        # said No → nothing touched
    assert all(f.read_text(encoding="utf-8") == "old line\n" for f in tqa.audit_log_files())
    p2, mb2, _ = _section(tkroot, yes=True)
    assert p2["clear_log"]() is True
    assert any(n == "askyesno" for n, _ in mb2.said)
    assert "Log cleared" in tqa.AUDIT_LOG_PATH.read_text(encoding="utf-8")
    assert not any(f.exists() for f in tqa.audit_log_files()[1:])


def test_TQ_22_tests_never_touch_the_real_run_log():
    real = Path.home() / ".ai-prowler" / "autonomous_run_audit.log"
    assert tqa.AUDIT_LOG_PATH != real

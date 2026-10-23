"""TIME MACHINE — the Autonomous AI Task Queue through time (no real AI).

David 2026-10-22: "is it possible to use a Time Machine to test more of the
task Q out?" … "I don't think we should have real Claude or Grok runs because
that depends on having credits, but do everything else you can in the Time
Machine."

The time machine's throwaway AI-Prowler (tm_server.py) plays the AI-Prowler
that's running on David's PC: the task queue connects to it over its local
connection with its Bearer Token — exactly the way a real scheduled run
connects to the real one (2026-10-22: queue runs never start their own copy).
The AI is a scripted stand-in (tm_standin_ai.py) that does what the
queue-runner prompt says; everything else is the real code:

  * task_queue_automation: connect_to_running_ai_prowler, scheduled_run_mcp_config,
    the skipped-run record, the generated scheduled .bat (run through cmd.exe,
    with a fake `claude` where claude.exe would be), the Grok runner and its
    HTTP MCP client, the active-days / time-window self-gate;
  * the server: create_analysis_task, get_pending_analysis_tasks (due filter),
    complete_analysis_task (re-arm / next due), queue_single_task (Run now),
    save_analysis_report, send_email (caught in the outbox), record_learning.

The story (M = a Monday well after the other time-machine tests' dates):
  M 07:00   five ZTEST tasks are created and queued (one-off, daily 9am, three
            times a day, weekly Wednesday, monthly first Tuesday)
  M 07:00   scheduled Claude run (the real .bat + fake claude) -> just the one-off
  M 09:30   scheduled Grok run (real runner, scripted brain)  -> daily + 3x-a-day
  M 10:00   nothing due; noon and 16:30: only the 3x-a-day task
  Tue       the PC is off all day (no runs)
  Wed 07:00 each overdue task runs ONCE (no pile-up) + the weekly one
  Wed 08:30 AI-Prowler isn't running -> the run is skipped and says why, the
            task waits, and the next run picks it up
  next Wed  the weekly task again; the monthly one the day before / on the day
  Run now   queue_single_task puts a finished one-off back; a queued task isn't doubled
  Checks    definitions and queue agree; the window self-gate at fake times;
            nothing left the sandbox; the real ~/.ai-prowler was never touched.

Run: python tests\\run_gui_jobs_e2e.py --timemachine --human -k TQ
"""
from __future__ import annotations

import calendar
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
APP_ROOT = HERE.parents[1]
for _p in (str(APP_ROOT), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import logging                              # noqa: E402

import custom_tasks_manager as ctm          # noqa: E402  (tasks_to_queue_entries — the GUI's Queue button)
import task_queue_automation as tqa         # noqa: E402
import tm_standin_ai as ai                  # noqa: E402

_e2e_log = logging.getLogger("e2e")         # conftest writes it to <run folder>\run.log


def _log(msg: str):
    _e2e_log.info(f"[TQ] {msg}")

MODE = (os.environ.get("E2E_TM_MODE") or "personal").strip().lower()
pytestmark = pytest.mark.skipif(MODE == "server", reason="the task queue runs on the owner's own PC (personal mode)")

L = {  # label -> what it is
    "oneoff":  "ZTEST TQ one-off report",
    "daily":   "ZTEST TQ daily 9am",
    "thrice":  "ZTEST TQ three times a day",
    "weekly":  "ZTEST TQ weekly Wednesday",
    "monthly": "ZTEST TQ monthly first Tuesday",
}
# The real install's queue files — only ever stat()ed, to prove the story never wrote them.
REAL_HOME_FILES = ("pending_tasks.json", "custom_analysis_tasks.json", "claude_mcp_config_running.json")

S: dict = {"ok": [], "emails_expected": 0, "runs": []}     # the story's state + the oracle


def _need(*steps):
    missing = [s for s in steps if s not in S["ok"]]
    if missing:
        pytest.skip(f"needs earlier step(s) {missing}")


def _done(step):
    S["ok"].append(step)


# ── dates ──────────────────────────────────────────────────────────────────────
def _monday_after(d: dt.date) -> dt.date:
    return d + dt.timedelta(days=(7 - d.weekday()) % 7)


def _first_of_next_month(d: dt.date) -> dt.date:
    return dt.date(d.year + (d.month == 12), d.month % 12 + 1, 1)


def _first_weekday_on_or_after(d: dt.date, wd: int) -> dt.date:
    return d + dt.timedelta(days=(wd - d.weekday()) % 7)


# ── the sandbox side: MCP calls into the time machine's AI-Prowler ───────────
def _client(tm, token=None):
    c = tqa._HttpMCPClient(tm.token if token is None else token, url=tm.origin + "/mcp")
    c.initialize(timeout=60)
    return c


def _call(tm):
    c = _client(tm)

    def call(name, args):
        r = c.call_tool(name, args)
        _log(f"MCP {name} -> {str(r)[:160]!r}")
        return r
    call.close = c.close
    return call


def _sandbox_state(tm) -> Path:
    return tm.home / ".ai-prowler"


def _queue_entries(tm) -> list[dict]:
    p = _sandbox_state(tm) / "pending_tasks.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _entry(tm, key) -> dict:
    hits = [e for e in _queue_entries(tm) if e.get("label") == L[key] and e.get("status") == "pending"]
    assert len(hits) == 1, f"{key}: expected exactly one pending queue entry, found {len(hits)}"
    return hits[0]


def _definition(tm, key) -> dict:
    call = _call(tm)
    try:
        data = json.loads(call("list_analysis_tasks", {}))
    finally:
        call.close()
    return next(t for t in data["tasks"] if t["label"] == L[key])


# ── the PC side: task_queue_automation pointed at the time machine ───────────
@pytest.fixture
def pc(tm, monkeypatch):
    """This PC's AI-Prowler home for the queue (a folder in the run folder —
    never the real ~/.ai-prowler), with remote access set up (the time
    machine's Bearer Token), and the 'running AI-Prowler' = the time machine.
    Starting the app is recorded, never done."""
    home = tm.home.parent / "queue_pc_home"          # beside sandbox_home, in this run's folder
    state = home / ".ai-prowler"
    state.mkdir(parents=True, exist_ok=True)
    (state / "config.json").write_text(json.dumps({"remote_token": tm.token}), encoding="utf-8")
    for name, rel in (("AI_PROWLER_HOME", ""), ("AI_PROWLER_CONFIG_PATH", "config.json"),
                      ("CONFIG_PATH", "task_automation_config.json"),
                      ("STATUS_PATH", "task_automation_last_run.json"),
                      ("AUDIT_LOG_PATH", "autonomous_run_audit.log"),
                      ("RUNNING_SERVER_MCP_CONFIG_PATH", "claude_mcp_config_running.json"),
                      ("GENERATED_MCP_CONFIG_PATH", "claude_mcp_config.json"),
                      ("OAUTH_TOKEN_PLAIN_PATH", "claude_oauth_token.txt"),
                      ("GROK_API_KEY_PATH", "grok_api_key.txt"),
                      ("API_KEY_PATH", "claude_api_key.txt")):
        monkeypatch.setattr(tqa, name, state / rel if rel else state)
    monkeypatch.setattr(tqa, "LOCAL_SERVER_URL", tm.origin)
    starts = []
    monkeypatch.setattr(tqa, "_start_ai_prowler_app", lambda: starts.append(1) or (False, "test: never started"))
    monkeypatch.setattr(tqa, "_ai_prowler_app_running", lambda: False)
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    return {"home": home, "state": state, "starts": starts}


def _record_run(how, when, done):
    S["runs"].append((how, when, sorted(done)))
    _log(f"RUN {how} @ {when}: {sorted(done)}")
    S["emails_expected"] += sum(1 for lbl in done if lbl in (L["daily"], L["oneoff"]))


def _standin_run(tm, pc, when):
    """A scheduled run: connect the way the queue does, then the stand-in AI."""
    ok, cfg = tqa.connect_to_running_ai_prowler(wait_sec=0, start_app=False)
    assert ok, cfg
    entry = json.loads(Path(cfg).read_text(encoding="utf-8"))["mcpServers"]["ai-prowler"]
    assert entry["url"] == tm.origin + "/mcp" and "command" not in entry
    c = tqa._HttpMCPClient(entry["headers"]["Authorization"].split(" ", 1)[1], url=entry["url"])
    c.initialize(timeout=60)
    try:
        run = ai.work_the_queue(lambda n, a: c.call_tool(n, a), when)
    finally:
        c.close()
    _record_run("stand-in", when, run["done"])
    return run


def _at(tm, day: dt.date, hhmm: str) -> str:
    tm.set_clock(day, hhmm)
    return f"{day:%a %Y-%m-%d} {hhmm}"


# ══════════════════════════════════════════════════════════════════════════════
def test_TQ_00_story_dates(tm):
    """M is a Monday well past the other time-machine stories' dates."""
    S["real_home"] = Path(os.path.expanduser("~")) / ".ai-prowler"
    S["real_before"] = {n: (S["real_home"] / n).stat().st_mtime_ns if (S["real_home"] / n).exists() else None
                        for n in REAL_HOME_FILES}
    m = _monday_after(tm.start_day + dt.timedelta(days=70))
    first = _first_of_next_month(m + dt.timedelta(days=16))
    # Not a 28-day month: there "same date next month" is the same weekday by
    # luck, which would hide a lost weekday pin.
    while calendar.monthrange(first.year, first.month)[1] == 28:
        first = _first_of_next_month(first)
    S.update(M=m, X=_first_weekday_on_or_after(first, 1), FIRST=first)
    _log(f"story: M={m}  monthly first Tuesday X={S['X']}")
    assert m.weekday() == 0 and S["X"].weekday() == 1 and S["X"] > m + dt.timedelta(days=16)
    _done("dates")


def test_TQ_01_connects_to_the_running_ai_prowler(tm, pc):
    """The queue's own connect step finds the running AI-Prowler (the time
    machine) with this PC's Bearer Token and writes Claude a config for it —
    a URL with the token, never a program to start."""
    _need("dates")
    ok, path = tqa.connect_to_running_ai_prowler(wait_sec=0, start_app=False)
    assert ok, path
    assert Path(path) == pc["state"] / "claude_mcp_config_running.json"
    entry = json.loads(Path(path).read_text(encoding="utf-8"))["mcpServers"]["ai-prowler"]
    assert entry == {"type": "http", "url": tm.origin + "/mcp",
                     "headers": {"Authorization": "Bearer " + tm.token}}
    c = _client(tm)
    try:
        names = {t["name"] for t in c.list_tools()}
    finally:
        c.close()
    for needed in ("get_pending_analysis_tasks", "complete_analysis_task", "save_analysis_report",
                   "record_learning", "send_email", "create_analysis_task", "queue_single_task"):
        assert needed in names, needed
    assert pc["starts"] == []
    _done("connect")


def test_TQ_02_a_wrong_token_is_refused(tm):
    """The running AI-Prowler only lets the owner's token in."""
    _need("connect")
    c = tqa._HttpMCPClient("ZTEST-not-the-token", url=tm.origin + "/mcp")
    with pytest.raises(Exception):
        c.initialize(timeout=30)
        c.list_tools()


def test_TQ_03_create_and_queue_five_tasks(tm, pc):
    """Monday 07:00: five tasks made with create_analysis_task (as from chat),
    then queued the way the Links & Analysis 'Queue' button does it."""
    _need("connect")
    m = S["M"]
    _at(tm, m, "07:00")
    call = _call(tm)
    try:
        specs = {
            "oneoff":  dict(schedule="none", output_learnings=False, output_report=True, output_email=True),
            "daily":   dict(schedule="daily", first_due=m.isoformat(), daily_start_time="09:00",
                            output_learnings=False, output_email=True),
            "thrice":  dict(schedule="daily", first_due=m.isoformat(), daily_start_time="08:00",
                            daily_end_time="16:00", daily_times_per_day=3,
                            output_learnings=False, output_report=True),
            "weekly":  dict(schedule="weekly", first_due=m.isoformat(), schedule_day_of_week=2,
                            output_learnings=True),
            "monthly": dict(schedule="monthly", first_due=S["FIRST"].isoformat(), schedule_day_of_week=1,
                            output_learnings=False, output_report=True),
        }
        for key, kw in specs.items():
            r = call("create_analysis_task", dict(label=L[key], prompt=f"ZTEST time-machine check: {key}.", **kw))
            assert r.startswith("✅"), r
        defs = [t for t in json.loads(call("list_analysis_tasks", {}))["tasks"] if t["label"] in L.values()]
    finally:
        call.close()
    assert len(defs) == 5
    by = {t["label"]: t for t in defs}
    assert by[L["daily"]]["next_due"] == f"{m}T09:00:00"
    assert by[L["thrice"]]["next_due"] == f"{m}T08:00:00"
    assert by[L["weekly"]]["next_due"] == (m + dt.timedelta(days=2)).isoformat()        # snapped to Wed
    assert by[L["monthly"]]["next_due"] == S["X"].isoformat()                           # first Tue
    assert by[L["oneoff"]]["next_due"] is None
    # Queue them (what the GUI's Queue / Save & Queue does).
    p = _sandbox_state(tm) / "pending_tasks.json"
    existing = _queue_entries(tm)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(existing + ctm.tasks_to_queue_entries(defs), indent=1), encoding="utf-8")
    os.replace(tmp, p)
    assert {e["label"] for e in _queue_entries(tm) if e["status"] == "pending"} >= set(L.values())
    _done("queued")


@pytest.mark.skipif(os.name != "nt", reason="runs the generated .bat through cmd.exe")
def test_TQ_04_scheduled_claude_run_through_the_real_bat(tm, pc, monkeypatch):
    """Monday 07:00, the scheduled run: the REAL generated .bat runs through
    cmd.exe — its active-days gate, scheduled_run_mcp_config() (connects to the
    running AI-Prowler), the OAuth-token read — and starts `claude` with the
    config it got. A fake claude (tm_fake_claude.py) stands where claude.exe
    would be. Only the one-off is due."""
    _need("queued")
    when = _at(tm, S["M"], "07:00")
    fake_oauth = "ZTEST-fake-oauth-not-a-real-token"
    pc["state"].joinpath("claude_oauth_token.txt").write_text(fake_oauth, encoding="utf-8")
    fake_cmd = pc["home"] / "fake_claude.cmd"
    fake_cmd.write_text(f'@echo off\r\n"{tqa._get_python_exe()}" "{HERE / "tm_fake_claude.py"}" %*\r\n',
                        encoding="utf-8")
    monkeypatch.setattr(tqa, "_get_claude_exe", lambda: str(fake_cmd))
    bat = tqa.build_wrapper_script_content(
        "", "mcp__ai-prowler__*", active_days=["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
    # The scheduled run's own Python (a fresh process) would look for AI-Prowler
    # on localhost:8000 — point that one line at the time machine instead, and
    # make sure it could never start the real app.
    hook = "import task_queue_automation as _t; "
    assert bat.count(hook) == 1
    bat = bat.replace(hook, hook + f"_t.LOCAL_SERVER_URL=r'{tm.origin}'; "
                                   "_t._start_ai_prowler_app=lambda: (False, 'test'); ")
    script = pc["home"] / "run_ai_prowler_queue_TEST.bat"
    script.write_text(bat, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in ("AIPROWLER_TEST_STATE_DIR", "CLAUDE_CODE_OAUTH_TOKEN")}
    env.update(USERPROFILE=str(pc["home"]), HOME=str(pc["home"]), TQ_WHEN=when, TQ_EXPECT_OAUTH=fake_oauth)
    r = subprocess.run(["cmd", "/c", str(script)], capture_output=True, text=True, env=env, timeout=600)
    out_file = pc["state"] / "last_headless_run.json"
    assert out_file.exists(), (r.returncode, r.stdout[-800:], r.stderr[-800:])
    text = out_file.read_text(encoding="utf-8", errors="replace").strip()
    _log(f"fake claude said: {text[-600:]}")
    res = json.loads(text.splitlines()[-1])
    assert "error" not in res, res
    assert r.returncode == 0, (r.returncode, text)
    assert res["mcp_config"] == str(pc["state"] / "claude_mcp_config_running.json")
    assert res["servers"] == ["ai-prowler"] and res["url"] == tm.origin + "/mcp"
    assert res["has_command"] is False                    # never a second AI-Prowler
    assert res["strict"] is True                          # only that server, not the user's own
    assert res["oauth_env"] is True                       # the .bat read the Claude token file
    assert res["prompt_starts"].startswith("Run AI-Prowler's pending analysis task queue")
    assert Path(res["cwd"]).resolve() == pc["state"].resolve()     # cd /d AI_PROWLER_HOME
    assert res["server"] == "AI-Prowler"
    assert res["done"] == [L["oneoff"]], res["done"]
    _record_run("claude .bat", when, res["done"])
    _done("claude-run")


def test_TQ_05_scheduled_grok_run_with_a_scripted_brain(tm, pc, monkeypatch):
    """Monday 09:30: the Grok runner (real code: connect, HTTP MCP client, tool
    selection, tool loop) with a scripted stand-in for the xAI API. The daily
    9am task and the 08:00 slot of the three-times-a-day task are due."""
    _need("queued")
    if "claude-run" not in S["ok"]:                       # non-Windows: do Monday 07:00 with the stand-in
        _at(tm, S["M"], "07:00")
        assert _standin_run(tm, pc, "Mon 07:00")["done"] == [L["oneoff"]]
    when = _at(tm, S["M"], "09:30")
    brain = ai.ScriptedGrok(when)
    monkeypatch.setattr(tqa, "_grok_chat", brain)
    monkeypatch.setattr(tqa, "load_api_key", lambda provider="anthropic": "ZTEST-fake-xai-key")
    monkeypatch.setattr(tqa, "load_config", lambda: {"allowed_tools": "mcp__ai-prowler__*"})
    ok, detail = tqa._run_grok_headless(tqa.GROK_QUEUE_RUNNER_PROMPT, 600, "queue run", wait_sec=0, start_app=False)
    assert ok, detail
    for t in ("get_pending_analysis_tasks", "complete_analysis_task", "save_analysis_report",
              "record_learning", "send_email"):
        assert t in brain.offered, f"Grok wasn't offered {t}"
    assert sorted(brain.done) == sorted([L["daily"], L["thrice"]]), brain.done
    assert tqa.load_last_run()["status"] == "success"
    _record_run("grok", when, brain.done)
    m = S["M"]
    assert _entry(tm, "daily")["next_due"] == f"{m + dt.timedelta(days=1)}T09:00:00"
    assert _entry(tm, "thrice")["next_due"] == f"{m}T12:00:00"
    assert pc["starts"] == []
    _done("grok-run")


def test_TQ_06_nothing_due_means_nothing_runs(tm, pc):
    _need("grok-run")
    run = _standin_run(tm, pc, _at(tm, S["M"], "10:00"))
    assert run["done"] == []
    assert "not yet due" in run["raw"] or "No tasks are due" in run["raw"], run["raw"]


def test_TQ_07_three_times_a_day(tm, pc):
    """Noon and 16:30: only the three-times-a-day task, once each time."""
    _need("grok-run")
    m = S["M"]
    assert _standin_run(tm, pc, _at(tm, m, "12:05"))["done"] == [L["thrice"]]
    assert _entry(tm, "thrice")["next_due"] == f"{m}T16:00:00"
    assert _standin_run(tm, pc, _at(tm, m, "16:30"))["done"] == [L["thrice"]]
    assert _entry(tm, "thrice")["next_due"] == f"{m + dt.timedelta(days=1)}T08:00:00"
    _done("monday")


def test_TQ_08_pc_off_tuesday_no_pile_up_on_wednesday(tm, pc):
    """No runs at all on Tuesday. Wednesday 07:00 each overdue task runs ONCE
    (not once per missed slot), plus the weekly Wednesday task — then a second
    run a minute later finds nothing."""
    _need("monday")
    m, wed = S["M"], S["M"] + dt.timedelta(days=2)
    run = _standin_run(tm, pc, _at(tm, wed, "07:00"))
    assert sorted(run["done"]) == sorted([L["daily"], L["thrice"], L["weekly"]]), run["done"]
    assert _entry(tm, "daily")["next_due"] == f"{wed}T09:00:00"
    assert _entry(tm, "thrice")["next_due"] == f"{wed}T08:00:00"
    assert _entry(tm, "weekly")["next_due"] == (m + dt.timedelta(days=9)).isoformat()
    assert _standin_run(tm, pc, _at(tm, wed, "07:01"))["done"] == []
    _done("wednesday")


def test_TQ_09_ai_prowler_not_running_skips_and_nothing_is_lost(tm, pc, monkeypatch):
    """Wednesday 08:30 the 08:00 slot is due, but AI-Prowler isn't running: the
    scheduled run starts the normal app (recorded here, never really), waits,
    gives up, records why — and never starts its own copy. The task stays due
    and the next run (AI-Prowler back) does it."""
    _need("wednesday")
    wed = S["M"] + dt.timedelta(days=2)
    when = _at(tm, wed, "08:30")
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
    monkeypatch.setattr(tqa, "LOCAL_SERVER_URL", f"http://127.0.0.1:{dead}")
    # The real probe, with a short timeout (a refused localhost connect costs
    # ~2 s on Windows; the 5-minute wait polls every 5 s = 61 probes).
    real_probe, probes = tqa._server_answers, []
    monkeypatch.setattr(tqa, "_server_answers",
                        lambda tok, *a, **k: probes.append(tok) or real_probe(tok, timeout=0.2))
    now = [1_000_000.0]                                   # the 5-minute wait, instantly
    monkeypatch.setattr(tqa.time, "time", lambda: now[0])
    monkeypatch.setattr(tqa.time, "sleep", lambda sec: now.__setitem__(0, now[0] + sec))
    assert tqa.scheduled_run_mcp_config() == "NO_SERVER"
    waited = now[0] - 1_000_000.0
    monkeypatch.undo()                                    # real clock back (tqa isn't used again in this test)
    _log(f"not running: {len(probes)} probes over {waited:.0f} s of (fake) waiting")
    assert 300 <= waited <= 310 and len(probes) >= 60
    assert set(probes) == {tm.token}                      # always with this PC's token
    assert pc["starts"] == [1]                            # tried to start the normal app, once
    last = json.loads((pc["state"] / "task_automation_last_run.json").read_text(encoding="utf-8"))
    assert last["status"] == "failure" and "isn't running" in last["detail"] and "5 minute" in last["detail"]
    assert "Skipped" in (pc["state"] / "last_headless_run.json").read_text(encoding="utf-8")
    assert "scheduled run skipped" in (pc["state"] / "autonomous_run_audit.log").read_text(encoding="utf-8")
    # Nothing lost: still due, and the next run picks it up.
    assert _entry(tm, "thrice")["next_due"] == f"{wed}T08:00:00"
    _log(f"skipped run at {when} recorded; AI-Prowler back")
    _done("skip")


def test_TQ_09b_the_next_run_catches_up(tm, pc):
    _need("skip")
    wed = S["M"] + dt.timedelta(days=2)
    assert _standin_run(tm, pc, _at(tm, wed, "08:40"))["done"] == [L["thrice"]]
    assert _entry(tm, "thrice")["next_due"] == f"{wed}T12:00:00"
    _done("caught-up")


def test_TQ_10_weekly_task_the_next_wednesday(tm, pc):
    _need("caught-up")
    m = S["M"]
    run = _standin_run(tm, pc, _at(tm, m + dt.timedelta(days=9), "06:00"))
    assert sorted(run["done"]) == sorted([L["daily"], L["thrice"], L["weekly"]]), run["done"]
    nxt = dt.date.fromisoformat(_entry(tm, "weekly")["next_due"])
    assert nxt == m + dt.timedelta(days=16) and nxt.weekday() == 2
    _done("weekly")


def test_TQ_11_monthly_first_tuesday(tm, pc):
    """Not due the evening before; due on the day; and its next run is again a
    Tuesday in the following month (the weekday pin is kept)."""
    _need("weekly")
    x = S["X"]
    before = _standin_run(tm, pc, _at(tm, x - dt.timedelta(days=1), "23:00"))
    assert L["monthly"] not in before["done"], before["done"]
    on = _standin_run(tm, pc, _at(tm, x, "07:00"))
    assert L["monthly"] in on["done"], on["done"]
    nxt = dt.date.fromisoformat(_entry(tm, "monthly")["next_due"])
    expected = dt.date.fromisoformat(ctm._advance_date(x.isoformat(), "monthly", 1))
    _log(f"monthly: ran {x}, next {nxt} (expected {expected})")
    assert nxt.weekday() == 1, f"monthly task pinned to Tuesday moved to a {calendar.day_name[nxt.weekday()]}: {nxt}"
    assert (nxt.year, nxt.month) == (_first_of_next_month(x).year, _first_of_next_month(x).month)
    assert nxt == expected
    _done("monthly")


def test_TQ_12_run_now_puts_a_finished_one_off_back(tm, pc):
    """▶ Run now (queue_single_task): a finished one-off goes back in and is
    due at once; a task that's already queued isn't doubled."""
    _need("monthly")
    x = S["X"]
    _at(tm, x, "07:30")
    call = _call(tm)
    try:
        defs = {t["label"]: t for t in json.loads(call("list_analysis_tasks", {}))["tasks"]}
        r1 = call("queue_single_task", {"task_id": defs[L["oneoff"]]["task_id"]})
        r2 = call("queue_single_task", {"task_id": defs[L["weekly"]]["task_id"]})
    finally:
        call.close()
    assert "queued for immediate execution" in r1, r1
    assert "already pending" in r2, r2
    assert len([e for e in _queue_entries(tm) if e.get("label") == L["weekly"] and e["status"] == "pending"]) == 1
    run = _standin_run(tm, pc, _at(tm, x, "07:31"))
    assert run["done"] == [L["oneoff"]], run["done"]
    _done("run-now")


def test_TQ_13_task_list_and_queue_agree(tm):
    """The My Custom AI Analyses list shows the same next run as the queue."""
    _need("run-now")
    for key in ("daily", "thrice", "weekly", "monthly"):
        assert _definition(tm, key)["next_due"] == _entry(tm, key)["next_due"], key
    assert _definition(tm, "monthly")["last_status"] == "completed"


def test_TQ_14_outputs_landed_in_the_sandbox_and_nothing_got_out(tm):
    """Reports in the sandbox's report folder, one email per run that asked for
    one — caught in the outbox, to the test address only — and the real
    ~/.ai-prowler untouched."""
    _need("run-now")
    reports = list((tm.home / "Documents" / "AI-Prowler_tasks_reports").glob("ZTEST_TQ_*.docx"))
    assert any("one-off" in r.name for r in reports) and any("three_times" in r.name for r in reports), \
        [r.name for r in reports]
    from email.header import decode_header, make_header
    outbox = tm.outbox()
    for m in outbox:
        m["subject"] = str(make_header(decode_header(m.get("subject", ""))))
    mails = [m for m in outbox if m.get("kind") == "email" and "ZTEST TQ" in m["subject"]]
    _log(f"queue emails in the outbox: {len(mails)} (expected {S['emails_expected']}): "
         f"{[m['subject'] for m in mails]}")
    assert len(mails) == S["emails_expected"], [m["subject"] for m in mails]
    assert all(m.get("to", "").endswith("@time-machine.test") for m in mails)
    assert not [m for m in outbox if m.get("kind") in ("sms", "whatsapp")]
    # The only thing that tried to go out was the learnings' embedding model
    # checking for an update online — and the sandbox blocked it.
    blocked = {m.get("to") for m in outbox if m.get("kind") == "blocked_http"}
    _log(f"blocked outbound attempts: {sorted(blocked) or 'none'}")
    assert blocked <= {"huggingface.co", "cdn-lfs.huggingface.co", "cas-bridge.xethub.hf.co"}, blocked
    after = {n: (S["real_home"] / n).stat().st_mtime_ns if (S["real_home"] / n).exists() else None
             for n in REAL_HOME_FILES}
    assert after == S["real_before"], "the real ~/.ai-prowler queue files changed during the story"


@pytest.mark.parametrize("when,expect", [
    ("2026-11-02 08:00", "RUN"),     # Monday inside 07:00-22:00
    ("2026-11-02 06:59", "SKIP"),    # too early
    ("2026-11-06 22:00", "RUN"),     # Friday, last minute of the window
    ("2026-11-06 22:01", "SKIP"),
    ("2026-11-07 10:00", "SKIP"),    # Saturday
], ids=["mon-0800", "mon-0659", "fri-2200", "fri-2201", "sat"])
def test_TQ_15_window_self_gate_interval_mode(when, expect):
    """The scheduled .bat's own day/time gate (interval mode, Mon-Fri
    07:00-22:00), run as the .bat runs it, at fake times."""
    import time_machine
    bat = tqa.build_wrapper_script_content("", "mcp__*", check_mode="interval",
                                           active_days=["mon", "tue", "wed", "thu", "fri"],
                                           active_start_time="07:00", active_end_time="22:00")
    py = _gate_python(bat)
    with time_machine.travel(_local_time(when), tick=False):
        assert _run_gate(py) == expect


def test_TQ_16_window_self_gate_daily_mode_skips_weekends():
    import time_machine
    bat = tqa.build_wrapper_script_content("", "mcp__*", active_days=["mon", "tue", "wed", "thu", "fri"])
    py = _gate_python(bat)
    for when, expect in (("2026-11-08 06:00", "SKIP"), ("2026-11-09 06:00", "RUN")):   # Sun / Mon
        with time_machine.travel(_local_time(when), tick=False):
            assert _run_gate(py) == expect, when


def _local_time(when: str) -> dt.datetime:
    """'YYYY-MM-DD HH:MM' on this PC's clock (a naive time would be taken as UTC)."""
    return dt.datetime.fromisoformat(when).astimezone()


def _gate_python(bat: str) -> str:
    line = next(l for l in bat.splitlines() if "AIP_WINDOW_CHECK=%%R" in l)
    code = line.split(' -c "', 1)[1].rsplit("\"') do", 1)[0]
    return code.replace("%%", "%")                        # what cmd.exe hands python


def _run_gate(code: str) -> str:
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(code, {})
    return buf.getvalue().strip()

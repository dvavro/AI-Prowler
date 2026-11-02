"""
tests/mcp_tests/test_analysis_tasks_per_task.py — the analysis-task MCP tools after the queue was removed
(2026-11-01, David: "get rid of the task queue and make every task have its own schedule").

  AT-01  create_analysis_task stores auto_run / run_time / ai_provider and says how it will run
  AT-02  get_pending_analysis_tasks = what a CHAT should run: due + Auto-run off, or asked from a chat;
         Auto-run tasks are left to AI-Prowler (nothing runs twice)
  AT-03  complete_analysis_task records the run and moves the task on (missed runs don't pile up);
         an old queue-entry id maps back to its task
  AT-04  queue_single_task asks AI-Prowler to run one task now (the phone's ▶ Run now)
  AT-05  get_all_queued_tasks lists scheduled / due / running-soon tasks for the phone
  AT-06  delete_analysis_task deletes the task
  AT-07  update_analysis_task changes auto_run / run_time / AI
  AT-08  the session briefing and the due-tasks alert follow the same split

Never this computer's ~/.ai-prowler (conftest points the task file into tmp).
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import custom_tasks_manager as ctm  # noqa: E402


@pytest.fixture(scope="module")
def mcp():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def tasks_file(tmp_path, monkeypatch):
    p = tmp_path / "custom_analysis_tasks.json"
    monkeypatch.setattr(ctm, "CUSTOM_TASKS_PATH", p)
    return p


def _put(tasks_file, *tasks):
    tasks_file.write_text(json.dumps(list(tasks)), encoding="utf-8")


def _load():
    return {t["task_id"]: t for t in ctm.load_custom_tasks()}


YESTERDAY = (dt.date.today() - dt.timedelta(days=1)).isoformat()
NEXT_YEAR = (dt.date.today() + dt.timedelta(days=365)).isoformat()


def _t(tid, label, due=YESTERDAY, auto=False, schedule="weekly", **kw):
    return dict(task_id=tid, label=label, prompt=f"Do {label}.", schedule=schedule, next_due=due,
                first_due=due, auto_run=auto, output_learnings=True, **kw)


def test_AT_01_create_stores_the_new_fields(mcp, tasks_file):
    first = (dt.date.today() + dt.timedelta(days=3)).isoformat()
    r = mcp.create_analysis_task(label="Monday AR", prompt="Check AR.", schedule="weekly", first_due=first,
                                 schedule_day_of_week=0, run_time="08:00", ai_provider="grok")
    assert "✅" in r and "Auto-run is on" in r and "Agent API Key" in r
    (t,) = ctm.load_custom_tasks()
    assert t["auto_run"] is True and t["run_time"] == "08:00" and t["ai_provider"] == "grok"
    r = mcp.create_analysis_task(label="Chat one", prompt="x", schedule="weekly", first_due=first, auto_run=False)
    assert "Auto-run is off" in r
    assert "one-off" in mcp.create_analysis_task(label="Once", prompt="x")
    assert "❌" in mcp.create_analysis_task(label="Bad", prompt="x", schedule="weekly", first_due=first,
                                           run_time="8.30")


def test_AT_02_pending_is_what_a_chat_should_run(mcp, tasks_file):
    assert "Nothing needs running" in mcp.get_pending_analysis_tasks()
    _put(tasks_file, _t("c1", "Chat due"), _t("a1", "Auto due", auto=True), _t("f1", "Later", due=NEXT_YEAR),
         _t("r1", "Asked in chat", due=NEXT_YEAR, run_requested=True, requested_by="chat"),
         _t("p1", "Phone run, no key", due=NEXT_YEAR, auto=True, run_requested=True, requested_by="ai-prowler",
            last_skip={"at": "2026-11-01T09:00:00", "why": "no key"}))
    data = json.loads(mcp.get_pending_analysis_tasks())
    got = {t["task_id"]: t["why"] for t in data["tasks"]}
    assert got == {"c1": "due", "r1": "asked to run now", "p1": "asked to run now"}
    assert "complete_analysis_task" in data["instruction"]
    assert "Do Chat due." in next(t for t in data["tasks"] if t["task_id"] == "c1")["prompt"]
    _put(tasks_file, _t("a1", "Auto due", auto=True))
    r = mcp.get_pending_analysis_tasks()
    assert "Nothing needs running" in r and "run on their own" in r


def test_AT_03_complete_records_the_run_and_moves_it_on(mcp, tasks_file):
    long_ago = (dt.date.today() - dt.timedelta(days=30)).isoformat()
    _put(tasks_file, _t("c1", "Chat due", due=long_ago), _t("o1", "Once", schedule="none", due=None))
    r = mcp.complete_analysis_task("c1", "3 overdue invoices")
    t = _load()["c1"]
    assert "✅" in r and "Next scheduled run" in r
    assert t["last_status"] == "completed" and t["last_summary"] == "3 overdue invoices"
    assert t["next_due"] >= dt.date.today().isoformat()            # missed weeks don't pile up
    assert "Chat due" not in mcp.get_pending_analysis_tasks()
    r = mcp.complete_analysis_task("o1_20261101_090000", "done", failed=True)      # an old queue-entry id
    assert "(failed)" in r and _load()["o1"]["last_status"] == "failed"
    assert "⚠️" in mcp.complete_analysis_task("nope", "x")


def test_AT_04_run_now_asks_ai_prowler(mcp, tasks_file):
    _put(tasks_file, _t("a1", "Later", due=NEXT_YEAR, auto=True,
                        last_skip={"at": "2026-11-01T09:00:00", "why": "no key"}))
    r = mcp.queue_single_task("a1")
    t = _load()["a1"]
    assert "✅" in r and t["run_requested"] and t["requested_by"] == ctm.BY_AI_PROWLER and "last_skip" not in t
    assert ctm.auto_runs_now(t)
    assert "already set to run" in mcp.queue_single_task("a1")
    assert "not found" in mcp.queue_single_task("nope")
    assert not (tasks_file.parent / "pending_tasks.json").exists()


def test_AT_05_the_phone_list(mcp, tasks_file):
    _put(tasks_file, _t("c1", "Due"), _t("f1", "Later", due=NEXT_YEAR),
         _t("r1", "Run soon", due=NEXT_YEAR, run_requested=True, requested_by="ai-prowler"),
         _t("o1", "Once", schedule="none", due=None))
    items = {t["task_id"]: t for t in json.loads(mcp.get_all_queued_tasks())}
    assert {k: v["status"] for k, v in items.items()} == {"c1": "due", "f1": "scheduled", "r1": "running soon"}
    assert items["c1"]["source_id"] == "c1"


def test_AT_06_delete(mcp, tasks_file):
    _put(tasks_file, _t("c1", "Gone"), _t("c2", "Stays"))
    assert "Deleted" in mcp.delete_analysis_task("c1")
    assert list(_load()) == ["c2"]
    assert "⚠️" in mcp.delete_analysis_task("c1")


def test_AT_07_update_the_new_fields(mcp, tasks_file):
    first = (dt.date.today() + dt.timedelta(days=3)).isoformat()
    mcp.create_analysis_task(label="Weekly", prompt="x", schedule="weekly", first_due=first)
    tid = ctm.load_custom_tasks()[0]["task_id"]
    r = mcp.update_analysis_task(tid, auto_run=False, run_time="07:30", ai_provider="claude",
                                 ai_model="claude-opus-5-5")
    t = _load()[tid]
    assert "✅" in r and t["auto_run"] is False and t["run_time"] == "07:30"
    assert (t["ai_provider"], t["ai_model"]) == ("claude", "claude-opus-5-5")


def test_AT_08_briefing_and_alert_follow_the_split(mcp, tasks_file):
    import scheduler_jobs as sj
    _put(tasks_file, _t("c1", "Chat report"), _t("a1", "Auto report", auto=True))
    text = mcp.how_to_use_ai_prowler()
    i = text.find("ANALYSIS BRIEFING")
    assert i > 0
    brief = text[i:]
    assert "For this chat" in brief and "Chat report" in brief
    assert "running 1 task itself" in brief and "Auto report" in brief
    subject, body = sj.job_due_analysis_tasks({})
    assert "Chat report" in body and "Auto report" not in body
    assert "pending_tasks.json" not in text and "There is no queue" in text

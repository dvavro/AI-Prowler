"""Remote PWA — Tasks (REMOTE_PWA_E2E_TEST_SPEC.md §5.7, RT).

Every task is labelled 'ZTEST E2E …' and deleted by the sweep. "Run now"
(queue_single_task) is NEVER really sent — the guard answers it, so no AI task
is queued and no credits are spent (RQ-06); RT-06 checks the app asked to queue
exactly this task.

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_tasks
"""
import json
import re

import pytest
from playwright.sync_api import expect

from app import type_text

LABEL = "ZTEST E2E remote task"
PROMPT = "Automated Remote PWA test task — do nothing. Safe to delete."


def _tasks(rapi) -> list[dict]:
    try:
        return json.loads(rapi.text("list_analysis_tasks")).get("tasks", [])
    except (ValueError, AttributeError):
        return []


def _task(rapi, label) -> dict | None:
    return next((t for t in _tasks(rapi) if t.get("label") == label), None)


def _type(remote, sel, text):
    remote.step(f"type into {sel}: {text[:40]!r}")
    box = remote.page.locator(sel)
    box.click()
    box.fill("")
    type_text(remote.page, box, text)


def _open_form(remote):
    remote.goto("tasks")
    remote.step("tap + New Custom AI Task")
    remote.page.get_by_role("button", name=re.compile(r"New Custom AI Task")).click()
    expect(remote.page.locator("#ntLabel")).to_be_visible()


def _submit(remote):
    remote.step("tap Save / Create")
    remote.page.locator("#taskFormSubmitBtn").click()


def _make(rapi, label, **extra):
    args = {"label": label, "prompt": PROMPT, "schedule": "none", "output_learnings": True, **extra}
    rapi.call("create_analysis_task", args)
    t = _task(rapi, label)
    assert t, f"setup couldn't create {label!r}"
    rapi.guard.register(t["task_id"], "(test setup)")
    return t


def _refresh_tasks(remote):
    remote.refresh_all()
    remote.goto("tasks")
    expect(remote.page.locator("#taskList .spinner")).to_have_count(0, timeout=20_000)


def _next_tuesday() -> str:
    import datetime as dt
    d = dt.date.today() + dt.timedelta(days=1)
    while d.weekday() != 1:
        d += dt.timedelta(days=1)
    return d.isoformat()


def _btn(remote, action, tid):
    return remote.page.locator(f'#taskList button[data-action="{action}"][data-id="{tid}"]')


# ── RT-10: a server refusal is shown, not reported as success (RM-R-008) ─────
def test_RT_10_scheduled_task_without_due_date_is_refused_visibly(remote, rapi):
    _open_form(remote)
    _type(remote, "#ntLabel", LABEL + " no due date")
    _type(remote, "#ntPrompt", PROMPT)
    remote.step("Schedule = Weekly, leave First due EMPTY")
    remote.page.locator("#ntSchedule").select_option("weekly")
    remote.page.locator("#ntFirstDue").fill("")
    _submit(remote)
    err = remote.page.locator("#ntError")
    expect(err).to_be_visible(timeout=20_000)
    expect(err).to_contain_text("first due date")
    expect(remote.page.locator("#ntLabel")).to_be_visible()      # the form stays open
    assert _task(rapi, LABEL + " no due date") is None
    remote.page.get_by_role("button", name="Cancel").first.click()


# ── RT-01 / RT-02: list loads; create a one-off task ─────────────────────────
def test_RT_02_create_a_one_off_task(remote, rapi, clean_slate):
    _open_form(remote)
    _type(remote, "#ntLabel", LABEL)
    _type(remote, "#ntPrompt", PROMPT)
    remote.page.locator("#ntSchedule").select_option("none")
    _submit(remote)
    expect(remote.page.locator("#taskList")).to_contain_text(LABEL, timeout=20_000)
    t = _task(rapi, LABEL)
    assert t and t.get("schedule") == "none" and t.get("output_learnings") is True, f"server has {t}"


# ── RT-03: weekly on a weekday; daily 3× preview ─────────────────────────────
def test_RT_03_weekly_pinned_day_and_daily_preview(remote, rapi, clean_slate):
    _open_form(remote)
    _type(remote, "#ntLabel", LABEL + " weekly")
    _type(remote, "#ntPrompt", PROMPT)
    remote.step("Schedule = Daily, 3 runs a day → preview + cost warning")
    remote.page.locator("#ntSchedule").select_option("daily")
    expect(remote.page.locator("#ntDailyRow")).to_be_visible()
    remote.page.locator("#ntDailyTimes").fill("3")
    remote.page.locator("#ntDailyTimes").dispatch_event("input")
    expect(remote.page.locator("#ntDailyPreview")).not_to_be_empty()
    expect(remote.page.locator("#ntDailyCostWarn")).to_be_visible()
    remote.step("switch to Weekly, pinned to Tuesday, first due next Tuesday")
    remote.page.locator("#ntSchedule").select_option("weekly")
    expect(remote.page.locator("#ntDowRow")).to_be_visible()
    remote.page.locator("#ntDayOfWeek").select_option("1")
    remote.page.locator("#ntFirstDue").fill(_next_tuesday())
    _submit(remote)
    expect(remote.page.locator("#taskList")).to_contain_text(LABEL + " weekly", timeout=20_000)
    t = _task(rapi, LABEL + " weekly")
    assert t and t.get("schedule") == "weekly", f"server has {t}"
    assert t.get("schedule_day_of_week") == 1, f"not pinned to Tuesday: {t.get('schedule_day_of_week')!r}"


# ── RT-05: edit changes the task, doesn't duplicate it ───────────────────────
def test_RT_05_edit_updates_not_duplicates(remote, rapi, clean_slate):
    t = _make(rapi, LABEL + " edit")
    _refresh_tasks(remote)
    remote.step("tap Edit on the ZTEST task")
    _btn(remote, "edit", t["task_id"]).click()
    expect(remote.page.locator("#ntLabel")).to_have_value(LABEL + " edit", timeout=20_000)
    _type(remote, "#ntLabel", LABEL + " edited")
    _submit(remote)
    expect(remote.page.locator("#taskList")).to_contain_text(LABEL + " edited", timeout=20_000)
    mine = [x for x in _tasks(rapi) if x.get("label", "").startswith(LABEL + " ed")]
    assert [x["label"] for x in mine] == [LABEL + " edited"], f"edit duplicated or failed: {mine}"
    assert mine[0]["task_id"] == t["task_id"], "a new task was created instead of updating"


# ── RT-06: Run now — asks to queue THIS task (never really sent) ─────────────
def test_RT_06_run_now_asks_to_queue_this_task(remote, rapi, guard, clean_slate):
    t = _make(rapi, LABEL + " run")
    _refresh_tasks(remote)
    before = len(guard.recorded)
    remote.step("tap Run now on the ZTEST task (the guard answers; nothing is queued)")
    _btn(remote, "queue", t["task_id"]).click()
    remote.page.wait_for_timeout(1500)
    new = guard.recorded[before:]
    assert any(e["tool"] == "queue_single_task" and e["args"].get("task_id") == t["task_id"] for e in new), \
        f"the app didn't ask to queue this task: {new}"
    queued = rapi.text("get_all_queued_tasks")
    assert t["task_id"] not in queued, "the task really got queued"


# ── RT-08: delete with confirmation ──────────────────────────────────────────
def test_RT_08_delete_the_task(remote, rapi, clean_slate):
    t = _make(rapi, LABEL + " delete")
    _refresh_tasks(remote)
    said = []
    remote.page.once("dialog", lambda d: (said.append(d.message), d.accept()))
    remote.step("tap Delete on the ZTEST task and confirm")
    _btn(remote, "delete", t["task_id"]).click()
    expect(_btn(remote, "delete", t["task_id"])).to_have_count(0, timeout=20_000)
    assert said and "cannot be undone" in said[0], f"no confirmation asked: {said}"
    assert _task(rapi, LABEL + " delete") is None, "still on the server"


# ── RT-09: required fields ───────────────────────────────────────────────────
def test_RT_09_required_fields(remote, rapi):
    _open_form(remote)
    err = remote.page.locator("#ntError")
    _submit(remote)
    expect(err).to_have_text("Label is required")
    _type(remote, "#ntLabel", LABEL + " invalid")
    _submit(remote)
    expect(err).to_have_text("Prompt is required")
    _type(remote, "#ntPrompt", PROMPT)
    remote.step("untick every output")
    for cb in ("#ntLearnings", "#ntReport", "#ntEmail"):
        if remote.page.locator(cb).is_checked():
            remote.page.locator(cb).uncheck()
    _submit(remote)
    expect(err).to_contain_text("at least one output")
    assert _task(rapi, LABEL + " invalid") is None, "an invalid task was saved"
    remote.page.get_by_role("button", name="Cancel").first.click()

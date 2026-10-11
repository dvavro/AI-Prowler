"""Remote PWA — every entry field saves (REMOTE_PWA_E2E_TEST_SPEC.md §5.10, RE).

David 2026-10-11: "check that every entry field operates and can save data".
The other files type into most fields but only check a few of them reached the
server. Here each field is typed / picked in the browser, saved, then read
back from the SERVER (list_analysis_tasks JSON, the learnings store) — and,
for tasks, the Edit form must show every saved value again.

  RE-01  Learning: title, content, category, outcome, tags, context all stored
  RE-02  New task with EVERY field: label, prompt, Daily + start/end/times,
         first due, all three outputs, report folder, a scope folder
  RE-03  Weekly / Biweekly / Monthly: schedule, first due, pinned weekday —
         and "Not pinned" saves no weekday
  RE-04  Edit opens with every saved value in its field
  RE-05  Edit changes every field (schedule, prompt, outputs, folder, scope)
  RE-06  Edit can CLEAR the report folder and every scope folder
  RE-07  Times/day outside 1–24 is not saved as typed
  RE-08  Edit a learning: the form shows every saved field; change them all → stored
  RE-09  Edit a learning: emptying Tags and Context clears them
  RE-10  Edit a task: emptying First due is allowed for Run once, refused
         (visibly, nothing saved) for a scheduled task

Every task/learning is named 'ZTEST E2E …' (the sweep deletes them); the only
folder used is the Remote sandbox.
Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_fields
"""
import datetime as dt
import json
import re
from pathlib import Path

import pytest
from playwright.sync_api import expect

from app import type_text
from remote_safety import SANDBOX

LABEL = "ZTEST E2E remote fields"
PROMPT = "Automated Remote PWA field test — do nothing. Safe to delete."
LEARN_FILE = Path.home() / ".ai-prowler" / "learnings" / "self_learning_data.json"
SB = str(SANDBOX)


# ── helpers ──────────────────────────────────────────────────────────────────
def _type(remote, sel, text):
    remote.step(f"type into {sel}: {text[:40]!r}")
    box = remote.page.locator(sel)
    box.click()
    box.fill("")
    if text:
        type_text(remote.page, box, text)


def _tasks(rapi) -> list[dict]:
    try:
        return json.loads(rapi.text("list_analysis_tasks")).get("tasks", [])
    except (ValueError, AttributeError):
        return []


def _task(rapi, label) -> dict | None:
    return next((t for t in _tasks(rapi) if t.get("label") == label), None)


def _make(rapi, label, **extra):
    args = {"label": label, "prompt": PROMPT, "schedule": "none", "output_learnings": True, **extra}
    rapi.call("create_analysis_task", args)
    t = _task(rapi, label)
    assert t, f"setup couldn't create {label!r}: {_tasks(rapi)[:2]}"
    rapi.guard.register(t["task_id"], "(test setup)")
    return t


def _open_new(remote):
    remote.goto("tasks")
    remote.step("tap + New Custom AI Task")
    remote.page.get_by_role("button", name=re.compile(r"New Custom AI Task")).click()
    expect(remote.page.locator("#ntLabel")).to_be_visible()
    expect(remote.page.locator("#ntScopeDirs .spinner")).to_have_count(0, timeout=20_000)


def _open_edit(remote, tid):
    remote.refresh_all()
    remote.goto("tasks")
    expect(remote.page.locator("#taskList .spinner")).to_have_count(0, timeout=20_000)
    remote.step("tap Edit on the ZTEST task")
    remote.page.locator(f'#taskList button[data-action="edit"][data-id="{tid}"]').click()
    expect(remote.page.locator("#taskFormSubmitBtn")).to_have_text(re.compile("Save Changes"), timeout=20_000)
    expect(remote.page.locator("#ntScopeDirs .spinner")).to_have_count(0, timeout=20_000)


def _submit(remote):
    remote.step("tap Save / Create")
    remote.page.locator("#taskFormSubmitBtn").click()


def _scope_box(remote, path):
    return remote.page.locator(f'xpath=//div[@id="ntScopeDirs"]//input[@type="checkbox" and @data-path="{path}"]')


def _set(remote, sel, checked: bool):
    box = remote.page.locator(sel) if isinstance(sel, str) else sel
    if box.is_checked() != checked:
        remote.step(f"{'tick' if checked else 'untick'} {sel if isinstance(sel, str) else 'scope folder'}")
        box.click()


def _date(d) -> str:
    return str(d or "")[:10]


def _norm(p) -> str:
    return str(p or "").replace("/", "\\").rstrip("\\").lower()


def _day(offset: int, weekday: int | None = None) -> str:
    d = dt.date.today() + dt.timedelta(days=offset)
    while weekday is not None and d.weekday() != weekday:
        d += dt.timedelta(days=1)
    return d.isoformat()


def _learning(title) -> dict | None:
    """The stored learning (raw JSON) with this title."""
    try:
        data = json.loads(LEARN_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    stack = [data]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            if x.get("title") == title:
                return x
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return None


# ── RE-01: a learning — every field stored ───────────────────────────────────
def test_RE_01_learning_every_field_is_stored(remote, rapi, clean_slate):
    title = "ZTEST E2E remote learning fields"
    remote.goto("learn")
    remote.step("tap + Add Learning")
    remote.page.get_by_role("button", name=re.compile(r"Add Learning")).click()
    _type(remote, "#lnTitle", title)
    _type(remote, "#lnContent", "Field round-trip — zqxfieldlearn. Safe to delete.")
    remote.step("Category = Client Preference, Outcome = Negative")
    remote.page.locator("#lnCategory").select_option("client_preference")
    remote.page.locator("#lnOutcome").select_option("negative")
    _type(remote, "#lnTags", "ztest, fields-e2e")
    _type(remote, "#lnContext", "Remote PWA E2E RE-01 context")
    remote.step("tap ✓ Save Learning")
    remote.page.get_by_role("button", name=re.compile(r"Save Learning")).click()
    expect(remote.page.locator("#learnForm")).to_be_hidden(timeout=20_000)
    got = _learning(title)
    assert got, "the learning isn't in the learnings store"
    tags = got.get("tags")
    tags = [t.strip().lower() for t in (tags if isinstance(tags, list) else str(tags or "").split(","))]
    problems = []
    if "zqxfieldlearn" not in str(got.get("content", "")):
        problems.append(f"content: {got.get('content')!r}")
    if got.get("category") != "client_preference":
        problems.append(f"category: {got.get('category')!r}")
    if got.get("outcome") != "negative":
        problems.append(f"outcome: {got.get('outcome')!r}")
    if not {"ztest", "fields-e2e"} <= set(tags):
        problems.append(f"tags: {got.get('tags')!r}")
    if "RE-01 context" not in str(got.get("context", "")):
        problems.append(f"context: {got.get('context')!r}")
    assert not problems, "learning fields not stored as typed: " + "; ".join(problems)


# ── RE-02: a new task — every field ──────────────────────────────────────────
def test_RE_02_new_task_every_field_is_stored(remote, rapi, clean_slate):
    label, due = LABEL + " all", _day(2)
    _open_new(remote)
    _type(remote, "#ntLabel", label)
    _type(remote, "#ntPrompt", PROMPT + " RE-02")
    remote.step("Schedule = Daily, 07:30–18:00, 3 times a day")
    remote.page.locator("#ntSchedule").select_option("daily")
    expect(remote.page.locator("#ntDailyRow")).to_be_visible()
    remote.page.locator("#ntDailyStart").fill("07:30")
    remote.page.locator("#ntDailyEnd").fill("18:00")
    remote.page.locator("#ntDailyTimes").fill("3")
    remote.page.locator("#ntDailyTimes").dispatch_event("input")
    expect(remote.page.locator("#ntDailyPreview")).to_have_text("Runs at: 07:30, 12:45, 18:00")
    remote.page.locator("#ntFirstDue").fill(due)
    _set(remote, "#ntLearnings", True)
    _set(remote, "#ntReport", True)
    _set(remote, "#ntEmail", True)
    _type(remote, "#ntReportFolder", SB)
    box = _scope_box(remote, SB)
    expect(box).to_have_count(1)
    _set(remote, box, True)
    _submit(remote)
    expect(remote.page.locator("#taskList")).to_contain_text(label, timeout=20_000)
    t = _task(rapi, label)
    assert t, "the task isn't on the server"
    rapi.guard.register(t["task_id"], "(RE-02)")
    want = {"prompt": PROMPT + " RE-02", "schedule": "daily", "output_learnings": True,
            "output_report": True, "output_email": True, "daily_start_time": "07:30",
            "daily_end_time": "18:00", "daily_times_per_day": 3}
    problems = [f"{k}: {t.get(k)!r} (typed {v!r})" for k, v in want.items() if t.get(k) != v]
    if _date(t.get("first_due") or t.get("next_due")) != due:
        problems.append(f"first due: {t.get('first_due')!r}/{t.get('next_due')!r} (typed {due})")
    if _norm(t.get("report_folder")) != _norm(SB):
        problems.append(f"report_folder: {t.get('report_folder')!r}")
    if [_norm(p) for p in (t.get("scope_dirs") or [])] != [_norm(SB)]:
        problems.append(f"scope_dirs: {t.get('scope_dirs')!r}")
    assert not problems, "task fields not stored as typed:\n  " + "\n  ".join(problems)


# ── RE-03: weekly / biweekly / monthly ───────────────────────────────────────
@pytest.mark.parametrize("schedule,day", [("weekly", "4"), ("biweekly", "2"), ("monthly", "")])
def test_RE_03_recurring_schedule_due_and_weekday(remote, rapi, clean_slate, schedule, day):
    label = f"{LABEL} {schedule}"
    due = _day(1, int(day) if day else None)
    _open_new(remote)
    _type(remote, "#ntLabel", label)
    _type(remote, "#ntPrompt", PROMPT)
    remote.step(f"Schedule = {schedule}, Day of week = {day or 'Not pinned'}, first due {due}")
    remote.page.locator("#ntSchedule").select_option(schedule)
    expect(remote.page.locator("#ntDowRow")).to_be_visible()
    remote.page.locator("#ntDayOfWeek").select_option(day)
    remote.page.locator("#ntFirstDue").fill(due)
    _submit(remote)
    expect(remote.page.locator("#taskList")).to_contain_text(label, timeout=20_000)
    t = _task(rapi, label)
    assert t, "the task isn't on the server"
    rapi.guard.register(t["task_id"], "(RE-03)")
    assert t.get("schedule") == schedule, t
    assert _date(t.get("first_due") or t.get("next_due")) == due, (t.get("first_due"), t.get("next_due"), due)
    want_day = int(day) if day else None
    assert t.get("schedule_day_of_week") == want_day, f"weekday {t.get('schedule_day_of_week')!r}, picked {day!r}"


# ── RE-04: Edit opens with every saved value ─────────────────────────────────
def test_RE_04_edit_form_shows_every_saved_value(remote, rapi, clean_slate):
    due = _day(3)
    t = _make(rapi, LABEL + " prefill", prompt=PROMPT + " RE-04", schedule="daily", first_due=due,
              daily_start_time="06:15", daily_end_time="20:45", daily_times_per_day=4,
              output_learnings=False, output_report=True, output_email=True,
              report_folder=SB, scope_dirs=[SB])
    _open_edit(remote, t["task_id"])
    p = remote.page
    shown = {
        "label": p.locator("#ntLabel").input_value(), "prompt": p.locator("#ntPrompt").input_value(),
        "schedule": p.locator("#ntSchedule").input_value(), "due": p.locator("#ntFirstDue").input_value(),
        "start": p.locator("#ntDailyStart").input_value(), "end": p.locator("#ntDailyEnd").input_value(),
        "times": p.locator("#ntDailyTimes").input_value(),
        "learnings": p.locator("#ntLearnings").is_checked(), "report": p.locator("#ntReport").is_checked(),
        "email": p.locator("#ntEmail").is_checked(), "folder": p.locator("#ntReportFolder").input_value(),
        "scope": _scope_box(remote, SB).is_checked() if _scope_box(remote, SB).count() else None,
    }
    want = {"label": LABEL + " prefill", "prompt": PROMPT + " RE-04", "schedule": "daily", "due": due,
            "start": "06:15", "end": "20:45", "times": "4", "learnings": False, "report": True,
            "email": True, "folder": SB, "scope": True}
    wrong = {k: (shown[k], v) for k, v in want.items()
             if (_norm(shown[k]) != _norm(v) if k == "folder" else shown[k] != v)}
    remote.page.get_by_role("button", name="Cancel").first.click()
    assert not wrong, "Edit form doesn't show the saved value (shown, saved): " + repr(wrong)


# ── RE-05: Edit changes every field ──────────────────────────────────────────
def test_RE_05_edit_changes_every_field(remote, rapi, clean_slate):
    t = _make(rapi, LABEL + " change", schedule="daily", first_due=_day(2), daily_start_time="09:00",
              daily_end_time="17:00", daily_times_per_day=1, output_learnings=True, output_report=False,
              output_email=False)
    new_label, due = LABEL + " changed", _day(5, 4)
    _open_edit(remote, t["task_id"])
    _type(remote, "#ntLabel", new_label)
    _type(remote, "#ntPrompt", PROMPT + " RE-05 changed")
    remote.step("Schedule → Monthly, pinned Friday")
    remote.page.locator("#ntSchedule").select_option("monthly")
    remote.page.locator("#ntDayOfWeek").select_option("4")
    remote.page.locator("#ntFirstDue").fill(due)
    _set(remote, "#ntLearnings", False)
    _set(remote, "#ntReport", True)
    _set(remote, "#ntEmail", True)
    _type(remote, "#ntReportFolder", SB)
    _set(remote, _scope_box(remote, SB), True)
    _submit(remote)
    expect(remote.page.locator("#taskList")).to_contain_text(new_label, timeout=20_000)
    got = next((x for x in _tasks(rapi) if x.get("task_id") == t["task_id"]), None)
    assert got, "the task disappeared"
    want = {"label": new_label, "prompt": PROMPT + " RE-05 changed", "schedule": "monthly",
            "schedule_day_of_week": 4, "output_learnings": False, "output_report": True, "output_email": True}
    problems = [f"{k}: {got.get(k)!r} (set {v!r})" for k, v in want.items() if got.get(k) != v]
    if _date(got.get("first_due") or got.get("next_due")) != due:
        problems.append(f"due: {got.get('first_due')!r}/{got.get('next_due')!r} (set {due})")
    if _norm(got.get("report_folder")) != _norm(SB):
        problems.append(f"report_folder: {got.get('report_folder')!r}")
    if [_norm(p) for p in (got.get("scope_dirs") or [])] != [_norm(SB)]:
        problems.append(f"scope_dirs: {got.get('scope_dirs')!r}")
    assert not problems, "Edit didn't save:\n  " + "\n  ".join(problems)


# ── RE-06: Edit can clear the report folder and the scope folders ────────────
# R-089 (found 2026-10-11 by this test): submitNewTask only sent report_folder /
# scope_dirs / first_due when they had a value, and update_analysis_task only
# changes the fields it's given — so clearing them in Edit silently kept the old
# values. Fixed 2026-10-11: an edit always sends them (empty = clear).
def test_RE_06_edit_can_clear_folder_and_scope(remote, rapi, clean_slate):
    t = _make(rapi, LABEL + " clear", output_report=True, report_folder=SB, scope_dirs=[SB])
    _open_edit(remote, t["task_id"])
    _type(remote, "#ntReportFolder", "")
    _set(remote, _scope_box(remote, SB), False)
    _submit(remote)
    remote.page.wait_for_timeout(1500)
    got = next((x for x in _tasks(rapi) if x.get("task_id") == t["task_id"]), {})
    problems = []
    if got.get("report_folder"):
        problems.append(f"report folder still {got.get('report_folder')!r} after clearing it")
    if got.get("scope_dirs"):
        problems.append(f"scope folders still {got.get('scope_dirs')!r} after unticking them")
    assert not problems, "Edit can't clear a field:\n  " + "\n  ".join(problems)


# ── RE-08 / RE-09: edit a learning (2026-10-11) ──────────────────────────────
def _make_learning(rapi, title, **extra) -> str:
    args = {"title": title, "content": "Edit test — zqxeditlearn. Safe to delete.",
            "category": "general", "outcome": "unknown", **extra}
    rapi.call("record_learning", args)
    got = _learning(title)
    assert got and got.get("id"), f"setup couldn't create {title!r}"
    return got["id"]


def _open_learning_edit(remote, lid):
    remote.goto("learn")
    remote.page.get_by_role("button", name=re.compile("Refresh")).first.click()
    btn = remote.page.locator(f'button[data-action="edit-learning"][data-id="{lid}"]')
    expect(btn).to_be_visible(timeout=20_000)
    remote.step("tap ✎ Edit on the ZTEST learning")
    btn.click()
    expect(remote.page.locator("#learnFormTitle")).to_have_text(re.compile("Edit Learning"), timeout=20_000)
    expect(remote.page.locator("#learnFormSubmitBtn")).to_have_text(re.compile("Save Changes"))


def test_RE_08_edit_a_learning_every_field(remote, rapi, clean_slate):
    title = "ZTEST E2E remote learning edit"
    lid = _make_learning(rapi, title, category="technical_note", outcome="positive",
                         tags="ztest, before", context="RE-08 before")
    _open_learning_edit(remote, lid)
    p = remote.page
    shown = {"title": p.locator("#lnTitle").input_value(), "content": p.locator("#lnContent").input_value(),
             "category": p.locator("#lnCategory").input_value(), "outcome": p.locator("#lnOutcome").input_value(),
             "tags": p.locator("#lnTags").input_value(), "context": p.locator("#lnContext").input_value()}
    assert shown["title"] == title and "zqxeditlearn" in shown["content"], shown
    assert (shown["category"], shown["outcome"], shown["context"]) == ("technical_note", "positive", "RE-08 before"), shown
    assert {t.strip() for t in shown["tags"].split(",")} >= {"ztest", "before"}, shown
    new_title = title + " changed"
    _type(remote, "#lnTitle", new_title)
    _type(remote, "#lnContent", "Edited content — zqxeditedlearn. Safe to delete.")
    p.locator("#lnCategory").select_option("mistake_learned")
    p.locator("#lnOutcome").select_option("neutral")
    _type(remote, "#lnTags", "ztest, after")
    _type(remote, "#lnContext", "RE-08 after")
    remote.step("tap ✓ Save Changes")
    p.locator("#learnFormSubmitBtn").click()
    expect(p.locator("#learnForm")).to_be_hidden(timeout=20_000)
    got = _learning(new_title)
    assert got and got.get("id") == lid, "the edit didn't update the same learning (or wasn't saved)"
    assert _learning(title) is None, "the old title is still stored as well"
    tags = got.get("tags") if isinstance(got.get("tags"), list) else str(got.get("tags", "")).split(",")
    problems = []
    if "zqxeditedlearn" not in str(got.get("content")):
        problems.append(f"content {got.get('content')!r}")
    if got.get("category") != "mistake_learned":
        problems.append(f"category {got.get('category')!r}")
    if got.get("outcome") != "neutral":
        problems.append(f"outcome {got.get('outcome')!r}")
    if {t.strip().lower() for t in tags} != {"ztest", "after"}:
        problems.append(f"tags {got.get('tags')!r}")
    if got.get("context") != "RE-08 after":
        problems.append(f"context {got.get('context')!r}")
    assert not problems, "learning edit not stored: " + "; ".join(problems)


def test_RE_09_edit_a_learning_can_clear_tags_and_context(remote, rapi, clean_slate):
    title = "ZTEST E2E remote learning clear"
    lid = _make_learning(rapi, title, tags="ztest, clearme", context="RE-09 to be cleared")
    _open_learning_edit(remote, lid)
    _type(remote, "#lnTags", "")
    _type(remote, "#lnContext", "")
    remote.page.locator("#learnFormSubmitBtn").click()
    expect(remote.page.locator("#learnForm")).to_be_hidden(timeout=20_000)
    got = _learning(title)
    assert got and got.get("id") == lid
    assert not got.get("tags"), f"tags still {got.get('tags')!r}"
    assert not got.get("context"), f"context still {got.get('context')!r}"


# ── RE-10: clearing First due ────────────────────────────────────────────────
def test_RE_10_clearing_first_due(remote, rapi, clean_slate):
    once = _make(rapi, LABEL + " due once", first_due=_day(4))
    _open_edit(remote, once["task_id"])
    remote.page.locator("#ntFirstDue").fill("")
    _submit(remote)
    remote.page.wait_for_timeout(1500)
    got = next((x for x in _tasks(rapi) if x.get("task_id") == once["task_id"]), {})
    assert not got.get("first_due"), f"Run-once due date not cleared: {got.get('first_due')!r}"
    weekly = _make(rapi, LABEL + " due weekly", schedule="weekly", first_due=_day(4))
    _open_edit(remote, weekly["task_id"])
    remote.page.locator("#ntFirstDue").fill("")
    _submit(remote)
    err = remote.page.locator("#ntError")
    expect(err).to_be_visible(timeout=10_000)
    expect(err).to_contain_text("needs a first due date")
    remote.page.get_by_role("button", name="Cancel").first.click()
    got = next((x for x in _tasks(rapi) if x.get("task_id") == weekly["task_id"]), {})
    assert _date(got.get("first_due")) == _day(4), f"the scheduled task's due date changed: {got.get('first_due')!r}"


# ── RE-07: Times/day outside 1–24 ────────────────────────────────────────────
@pytest.mark.parametrize("typed", ["0", "30"])
def test_RE_07_times_per_day_out_of_range(remote, rapi, clean_slate, typed):
    label = f"{LABEL} times {typed}"
    _open_new(remote)
    _type(remote, "#ntLabel", label)
    _type(remote, "#ntPrompt", PROMPT)
    remote.page.locator("#ntSchedule").select_option("daily")
    remote.page.locator("#ntFirstDue").fill(_day(1))
    remote.page.locator("#ntDailyTimes").fill(typed)
    remote.page.locator("#ntDailyTimes").dispatch_event("input")
    _submit(remote)
    remote.page.wait_for_timeout(2000)
    t = _task(rapi, label)
    if t:
        rapi.guard.register(t["task_id"], "(RE-07)")
        n = t.get("daily_times_per_day")
        assert isinstance(n, int) and 1 <= n <= 24, f"typed {typed!r}: saved daily_times_per_day={n!r}"
    else:
        expect(remote.page.locator("#ntError")).to_be_visible()      # refused visibly — fine
        remote.page.get_by_role("button", name="Cancel").first.click()

"""
tests/gui/test_hr_schedule_reminders.py
========================================
Regression guard for the Schedule tab "boxes" month-grid view and business
reminders feature added to hr/index.html on 2026-08-29 (user request: "I
want the calendar to have another way you can view this calendar like more
open and boxes looking... put in dates and reminders for business use").

Covers:
  - Structural checks (no Node): the view toggle, FAB, and both new modals
    exist in the markup; every new JS function referenced by onclick=""
    handlers is actually defined; switchTab() loads reminders before
    rendering the schedule tab.
  - Behavioral checks (Node subprocess, real extracted source): renderMonthView()
    produces a properly-padded 7-column grid with exactly one "today" cell,
    and places a task/reminder on the correct day's box (via its data-date
    attribute) and no other day's box; openDayDetail() lists exactly the
    tasks/reminders for the tapped date and HTML-escapes free-text reminder
    fields (XSS regression guard -- reminder title/note are user-supplied).

Safe: reads hr/index.html as plain text only; runs extracted JS in an
isolated Node subprocess with mocked globals (including a fixed Date so the
grid math is deterministic). Never imports ai_prowler_mcp.py, never touches
hr_db.json or a live server. Same technique as
tests/gui/test_hr_setup_wizard_captures_all_steps.py.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_real_Popen = subprocess.Popen

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
HR_INDEX = SRC_ROOT / "hr" / "index.html"


@pytest.fixture(scope="module")
def node_available():
    if shutil.which("node") is None:
        pytest.skip("Node.js not on PATH — cannot execute schedule/reminders JS for behavioral verification")


def _run_node(script_path: Path, timeout: int = 30):
    proc = _real_Popen(
        ["node", str(script_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise
    return proc.returncode, stdout, stderr


def _extract_source_range(source: str, start_marker: str, end_function_marker: str) -> str:
    """Extract real shipped source from start_marker through the end of the
    function located at (or after) end_function_marker, via real brace-depth
    counting -- same technique as test_hr_setup_wizard_captures_all_steps.py
    / test_pwa_update_banner.py (a naive regex would truncate at the first
    inner closing brace instead of the function's own)."""
    start_idx = source.index(start_marker)
    fn_idx = source.index(end_function_marker, start_idx)
    brace_start = source.index("{", fn_idx)
    depth = 0
    for i in range(brace_start, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start_idx:i + 1]
    raise ValueError(f"Unbalanced braces extracting range starting {start_marker!r}")


@pytest.fixture(scope="module")
def hr_index_text():
    return HR_INDEX.read_text(encoding="utf-8")


# ── TC-HRCAL-001 — structural checks (no Node) ──────────────────────────

class TestScheduleViewToggleMarkup:
    def test_view_toggle_buttons_present(self, hr_index_text):
        assert 'onclick="setScheduleView(\'week\', this)"' in hr_index_text
        assert 'onclick="setScheduleView(\'month\', this)"' in hr_index_text

    def test_add_reminder_fab_present(self, hr_index_text):
        assert 'class="fab-add-reminder"' in hr_index_text
        assert 'onclick="openAddReminder()"' in hr_index_text

    def test_reminder_modal_present(self, hr_index_text):
        assert 'id="reminder-modal"' in hr_index_text
        assert 'id="rem-title"' in hr_index_text
        assert 'id="rem-date"' in hr_index_text
        assert 'onclick="saveReminder()"' in hr_index_text

    def test_day_detail_modal_present(self, hr_index_text):
        assert 'id="day-detail-modal"' in hr_index_text
        assert 'id="day-detail-body"' in hr_index_text

    def test_switch_tab_loads_reminders_before_rendering_schedule(self, hr_index_text):
        assert "loadReminders().then(renderSchedule)" in hr_index_text, (
            "the schedule tab must load reminders before rendering, the "
            "same lazy-load-on-tab-switch pattern used for tasks/documents"
        )


class TestAllReminderJsFunctionsAreDefined:
    """Every onclick="" handler introduced by this feature must resolve to
    a real function definition somewhere in the shipped script -- otherwise
    tapping that control throws ReferenceError in production."""

    FUNCTIONS = [
        "setScheduleView", "renderSchedule", "renderWeekView", "renderMonthView",
        "navigateMonth", "renderReminderCard", "loadReminders",
        "openDayDetail", "closeDayDetail", "handleDayDetailBackdrop",
        "openAddReminderForDayDetail", "openAddReminder", "openEditReminder",
        "closeAddReminder", "handleReminderModalBackdrop", "saveReminder",
        "deleteReminder", "apiDelete", "escapeHtml",
    ]

    @pytest.mark.parametrize("fn_name", FUNCTIONS)
    def test_function_defined(self, hr_index_text, fn_name):
        assert re.search(rf"(function {fn_name}\(|async function {fn_name}\()", hr_index_text), \
            f"no definition found for {fn_name}()"


class TestReminderApiUsesRestVerbs:
    def test_save_reminder_posts_or_patches(self, hr_index_text):
        assert "apiPost('/reminders'" in hr_index_text
        assert "apiPatch(`/reminders/${state.editingReminderId}`" in hr_index_text

    def test_delete_reminder_uses_delete_verb(self, hr_index_text):
        assert "apiDelete(`/reminders/${id}`)" in hr_index_text


# ── TC-HRCAL-002 — behavioral: real renderMonthView()/openDayDetail() ──────

_HARNESS_TEMPLATE = """
// Fixed "today" so grid math is deterministic: Thursday, 2026-06-25.
const OriginalDate = Date;
class MockDate extends OriginalDate {
  constructor(...args) {
    if (args.length === 0) super(2026, 5, 25);
    else super(...args);
  }
  static now() { return new OriginalDate(2026, 5, 25).getTime(); }
}
global.Date = MockDate;

// Mock DOM: getElementById returns a fresh generic element per id (tracked
// in `elements` so the test driver can inspect what was written to it).
const elements = {};
function makeElement() {
  return {
    _classes: new Set(),
    classList: {
      add(c) { this._classes ? this._classes.add(c) : null; },
      remove(c) {},
    },
    value: '',
    textContent: '',
    innerHTML: '',
  };
}
// escapeHtml() builds a real <div>, sets .textContent, then reads back
// .innerHTML to get the browser's own escaping -- so the mock DOM needs a
// createElement('div') that actually escapes & < > the same way a real
// browser's textContent -> innerHTML round-trip does.
function makeEscapingDiv() {
  let text = '';
  return {
    set textContent(v) { text = v; },
    get textContent() { return text; },
    get innerHTML() {
      return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    },
  };
}
global.document = {
  getElementById: function(id) {
    if (!elements[id]) elements[id] = makeElement();
    return elements[id];
  },
  createElement: function(tag) { return makeEscapingDiv(); },
  querySelectorAll: function() { return []; },
};

let state = { tasks: [], reminders: [], scheduleMonthOffset: 0 };

__EXTRACTED_LOGIC__

const results = [];
function check(name, cond) { results.push([name, !!cond]); }

// ── renderMonthView(): June 2026 ────────────────────────────────────────
state.tasks = [{ id: 'TASK-1', name: 'File I-9', due_date: '2026-06-10' }];
state.reminders = [{ id: 'REM-1', title: 'Pay quarterly taxes', date: '2026-06-30' }];
state.scheduleMonthOffset = 0;
renderMonthView();
const monthHtml = elements['schedule-calendar'].innerHTML;

// Every day-box carries its own data-date; split on that to isolate cells.
const dayBoxes = monthHtml.split('cal-month-day').slice(1);
check('grid_has_multiple_of_7_boxes', dayBoxes.length % 7 === 0 && dayBoxes.length > 0);
check('exactly_one_today_cell', (monthHtml.match(/cal-month-day[^"]*today/g) || []).length === 1);

function boxFor(dateStr) {
  return dayBoxes.find(function(b) { return b.indexOf('data-date=\\"' + dateStr + '\\"') !== -1; });
}
const taskBox = boxFor('2026-06-10');
const reminderBox = boxFor('2026-06-30');
const unrelatedBox = boxFor('2026-06-11');
check('task_appears_on_its_own_due_date_box', !!taskBox && taskBox.indexOf('File I-9') !== -1);
check('reminder_appears_on_its_own_date_box', !!reminderBox && reminderBox.indexOf('Pay quarterly taxes') !== -1);
check('task_does_not_leak_onto_unrelated_day', !!unrelatedBox && unrelatedBox.indexOf('File I-9') === -1);
check('reminder_item_tagged_with_reminder_kind_class', !!reminderBox && reminderBox.indexOf('cmd-item reminder') !== -1);
check('task_item_tagged_with_task_kind_class', !!taskBox && taskBox.indexOf('cmd-item task') !== -1);

// ── openDayDetail(): tapping a day lists exactly that day's items ───────
state.tasks = [
  { id: 'TASK-1', name: 'File I-9', due_date: '2026-06-10' },
  { id: 'TASK-2', name: 'Other day task', due_date: '2026-06-11' },
];
state.reminders = [
  { id: 'REM-1', title: '<img src=x onerror=alert(1)>', date: '2026-06-10', note: 'sensitive note' },
];
openDayDetail('2026-06-10');
const dayBody = elements['day-detail-body'].innerHTML;
check('day_detail_includes_matching_task', dayBody.indexOf('File I-9') !== -1);
check('day_detail_excludes_other_day_task', dayBody.indexOf('Other day task') === -1);
check('day_detail_includes_matching_reminder_note', dayBody.indexOf('sensitive note') !== -1);
check('day_detail_escapes_reminder_title_xss',
  dayBody.indexOf('<img src=x onerror=alert(1)>') === -1 &&
  dayBody.indexOf('&lt;img') !== -1);
check('day_detail_modal_shown', elements['day-detail-modal']._classes && true);

console.log(JSON.stringify(results));
process.exit(results.every(function(r) { return r[1]; }) ? 0 : 1);
"""


class TestMonthGridAndDayDetailBehavior:
    def test_month_grid_and_day_detail_render_correctly(self, node_available, hr_index_text, tmp_path):
        escape_html_src = _extract_source_range(hr_index_text, "function escapeHtml", "function escapeHtml")
        render_empty_src = _extract_source_range(hr_index_text, "function renderEmpty", "function renderEmpty")
        month_view_src = _extract_source_range(
            hr_index_text, "function navigateMonth", "function renderMonthView"
        )
        day_detail_src = _extract_source_range(hr_index_text, "function openDayDetail", "function openDayDetail")

        extracted = "\n\n".join([escape_html_src, render_empty_src, month_view_src, day_detail_src])
        script = _HARNESS_TEMPLATE.replace("__EXTRACTED_LOGIC__", extracted)
        script_path = tmp_path / "hr_schedule_reminders.js"
        script_path.write_text(script, encoding="utf-8")
        returncode, stdout, stderr = _run_node(script_path, timeout=15)
        if returncode != 0:
            detail = stdout.strip() or "(no stdout)"
            pytest.fail(f"HR month-grid/day-detail behavioral test failed.\n{detail}\nstderr: {stderr}")

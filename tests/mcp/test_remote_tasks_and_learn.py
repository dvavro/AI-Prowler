"""
test_remote_tasks_and_learn.py
================================
Offline tests for Tasks and Learn tabs in the Remote PWA.
Run: pytest tests/mcp/test_remote_tasks_and_learn.py -v
"""
from __future__ import annotations
import re, os
from pathlib import Path
import pytest

_SRC     = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parents[2]
INDEX_HTML = SRC_ROOT / "remote" / "index.html"
MCP_FILE   = SRC_ROOT / "ai_prowler_mcp.py"


@pytest.fixture(scope="module")
def html():
    assert INDEX_HTML.exists()
    return INDEX_HTML.read_text(encoding="utf-8")

@pytest.fixture(scope="module")
def js(html):
    start = html.rfind("<script>") + len("<script>")
    end   = html.rfind("</script>")
    assert end > start
    return html[start:end]

@pytest.fixture(scope="module")
def mcp():
    assert MCP_FILE.exists()
    return MCP_FILE.read_text(encoding="utf-8")

def _fn(js, name):
    start = js.find(f"function {name}(")
    if start == -1: return ""
    depth, i, n = 0, start, len(js)
    while i < n:
        if js[i] == "{": depth += 1
        elif js[i] == "}":
            depth -= 1
            if depth == 0: return js[start:i+1]
        i += 1
    return js[start:]

def _allowed(mcp):
    idx = mcp.find("_REMOTE_ALLOWED")
    return mcp[idx:idx+3000]


# ── TASKS: Functions ──────────────────────────────────────────────────────────

class TestTasksFunctions:
    def test_loadTasks(self, js):            assert "async function loadTasks(" in js
    def test_loadAllTasks(self, js):         assert "async function loadAllTasks(" in js
    def test_renderTaskCard(self, js):       assert "function renderTaskCard(" in js
    def test_renderQueuePanel(self, js):     assert "function renderQueuePanel(" in js
    def test_runTaskNow(self, js):           assert "async function runTaskNow(" in js
    def test_editTask(self, js):             assert "async function editTask(" in js
    def test_deleteTask(self, js):           assert "async function deleteTask(" in js
    def test_removeFromQueue(self, js):      assert "async function removeFromQueue(" in js
    def test_clearQueue(self, js):           assert "async function clearQueue(" in js
    def test_showNewTaskForm(self, js):      assert "function showNewTaskForm(" in js
    def test_cancelNewTask(self, js):        assert "function cancelNewTask(" in js
    def test_submitNewTask(self, js):        assert "async function submitNewTask(" in js
    def test_timeAgo(self, js):              assert "function _timeAgo(" in js


# ── TASKS: HTML ───────────────────────────────────────────────────────────────

class TestTasksHTML:
    def test_screenTasks(self, html):    assert 'id="screenTasks"' in html
    def test_navTasks(self, html):       assert 'id="navTasks"' in html
    def test_taskList(self, html):       assert 'id="taskList"' in html
    def test_queuePanel(self, html):     assert 'id="queuePanel"' in html
    def test_queueItems(self, html):     assert 'id="queueItems"' in html
    def test_queueCount(self, html):     assert 'id="queueCount"' in html
    def test_queueClearBtn(self, html):  assert 'id="queueClearBtn"' in html
    def test_newTaskForm(self, html):    assert 'id="newTaskForm"' in html
    def test_taskFormTitle(self, html):  assert 'id="taskFormTitle"' in html
    def test_taskFormSubmitBtn(self, html): assert 'id="taskFormSubmitBtn"' in html
    def test_taskCount(self, html):      assert 'id="taskCount"' in html

    def test_form_fields(self, html):
        for fid in ["ntLabel","ntPrompt","ntSchedule","ntFirstDue","ntLearnings","ntReport","ntError"]:
            assert f'id="{fid}"' in html, f"#{fid} missing"

    def test_schedule_options(self, html):
        for opt in ["Run once","Daily","Weekly","Monthly"]:
            assert opt in html, f"Schedule option '{opt}' missing"


# ── TASKS: Event delegation ───────────────────────────────────────────────────

class TestEventDelegation:
    def test_boot_has_inline_delegation(self, js):
        fn = _fn(js, "boot")
        assert "screenTasks" in fn and "data-action" in fn, \
            "boot() must have inline delegation — _setupTaskDelegation was removed"

    def test_boot_routes_queue(self, js):       assert "runTaskNow" in _fn(js, "boot")
    def test_boot_routes_edit(self, js):        assert "editTask" in _fn(js, "boot")
    def test_boot_routes_delete(self, js):      assert "deleteTask" in _fn(js, "boot")
    def test_boot_routes_remove(self, js):      assert "removeFromQueue" in _fn(js, "boot")

    def test_switchTab_loads_tasks(self, js):
        assert "loadTasks" in _fn(js, "switchTab"), \
            "switchTab must call loadTasks() when tasks tab activated"

    def test_switchTab_loads_learn(self, js):
        assert "loadLearnings" in _fn(js, "switchTab"), \
            "switchTab must call loadLearnings() when learn tab activated"


# ── TASKS: renderTaskCard buttons ─────────────────────────────────────────────

class TestRenderTaskCard:
    def test_queue_data_action(self, js):
        assert 'data-action="queue"' in _fn(js, "renderTaskCard"), \
            "Queue button must use data-action not inline onclick"

    def test_edit_data_action(self, js):
        assert 'data-action="edit"' in _fn(js, "renderTaskCard")

    def test_delete_data_action(self, js):
        assert 'data-action="delete"' in _fn(js, "renderTaskCard")

    def test_buttons_have_data_id(self, js):
        assert 'data-id="' in _fn(js, "renderTaskCard")

    def test_no_json_stringify_onclick(self, js):
        fn = _fn(js, "renderTaskCard")
        assert "JSON.stringify(t.task_id)" not in fn, \
            "JSON.stringify in onclick creates double-quoted string that breaks HTML attribute"

    def test_no_inline_onclick(self, js):
        fn = _fn(js, "renderTaskCard")
        bad = re.findall(r'onclick="(?:runTaskNow|editTask|deleteTask)\(', fn)
        assert not bad, f"Inline onclick found: {bad}"

    def test_overdue_badge(self, js):      assert "OVERDUE" in _fn(js, "renderTaskCard")
    def test_in_queue_banner(self, js):
        fn = _fn(js, "renderTaskCard")
        assert "In queue" in fn or "inQueue" in fn
    def test_output_badges(self, js):
        fn = _fn(js, "renderTaskCard")
        assert "output_email" in fn and "output_learnings" in fn
    def test_remove_queue_action(self, js):
        fn = _fn(js, "renderTaskCard")
        assert 'data-action="remove"' in fn or 'data-action="remove-queue"' in fn


# ── TASKS: loadAllTasks ───────────────────────────────────────────────────────

class TestLoadAllTasks:
    def test_calls_list_analysis_tasks(self, js):
        assert "list_analysis_tasks" in _fn(js, "loadAllTasks")
    def test_parses_json(self, js):
        assert "JSON.parse" in _fn(js, "loadAllTasks"), \
            "list_analysis_tasks returns JSON string that must be parsed"
    def test_groups_by_due(self, js):
        fn = _fn(js, "loadAllTasks")
        assert "overdue" in fn or "isDue" in fn or "is_due" in fn
    def test_updates_count(self, js):
        fn = _fn(js, "loadAllTasks")
        assert "taskCount" in fn or "countEl" in fn
    def test_has_debug_log(self, js):
        assert "dbg(" in _fn(js, "loadAllTasks")


# ── TASKS: Queue panel ────────────────────────────────────────────────────────

class TestQueuePanel:
    def test_uses_get_all_queued_tasks(self, js):
        fn = _fn(js, "loadTasks")
        assert "get_all_queued_tasks" in fn, \
            "Must use get_all_queued_tasks (returns JSON) not get_pending_analysis_tasks (plain text)"

    def test_populates_pending_source_id(self, js):
        assert "_pendingBySourceId" in _fn(js, "loadTasks")

    def test_shows_due_date(self, js):       assert "next_due" in _fn(js, "renderQueuePanel")
    def test_shows_queued_ago(self, js):
        fn = _fn(js, "renderQueuePanel")
        assert "_timeAgo" in fn or "queued_at" in fn
    def test_has_remove_button(self, js):
        fn = _fn(js, "renderQueuePanel")
        assert "remove-queue" in fn or "removeFromQueue" in fn
    def test_mcp_defined(self, mcp):         assert "def get_all_queued_tasks(" in mcp
    def test_in_allowed(self, mcp):          assert "get_all_queued_tasks" in _allowed(mcp)


# ── TASKS: Queue button ───────────────────────────────────────────────────────

class TestQueueButton:
    def test_calls_queue_single_task(self, js):
        fn = _fn(js, "runTaskNow")
        assert "queue_single_task" in fn, "Must use queue_single_task not sync_due"
    def test_no_sync_all(self, js):
        assert "sync_due_tasks_to_queue" not in _fn(js, "runTaskNow")
    def test_refreshes(self, js):    assert "loadTasks" in _fn(js, "runTaskNow")
    def test_toast(self, js):        assert "toast(" in _fn(js, "runTaskNow")
    def test_mcp_defined(self, mcp): assert "def queue_single_task(" in mcp
    def test_writes_pending(self, mcp):
        idx = mcp.find("def queue_single_task(")
        fn = mcp[idx:idx+2000]
        assert '"pending"' in fn, "Must write status=pending so GUI shows it"
    def test_in_allowed(self, mcp):  assert "queue_single_task" in _allowed(mcp)


# ── TASKS: Edit button ────────────────────────────────────────────────────────

class TestEditButton:
    def test_is_async(self, js):     assert "async function editTask(" in js
    def test_uses_apislow(self, js):
        assert "apiSlow" in _fn(js, "editTask"), "Must use apiSlow — list_analysis_tasks blocks"
    def test_no_bare_api(self, js):
        bare = re.findall(r"\bapi\s*\(", _fn(js, "editTask"))
        assert not bare, f"Bare api() found: {bare}"
    def test_prefills_label(self, js):   assert "ntLabel" in _fn(js, "editTask")
    def test_prefills_prompt(self, js):  assert "ntPrompt" in _fn(js, "editTask")
    def test_sets_editing_id(self, js):  assert "_editingTaskId" in _fn(js, "editTask")
    def test_submit_update(self, js):    assert "update_analysis_task" in _fn(js, "submitNewTask")
    def test_submit_create(self, js):    assert "create_analysis_task" in _fn(js, "submitNewTask")
    def test_cancel_resets(self, js):    assert "_editingTaskId" in _fn(js, "cancelNewTask")
    def test_no_time_component_sent(self, js, html):
        # ntFirstDue is a plain type="date" input (not datetime-local), so
        # its .value is always a bare YYYY-MM-DD with no time component to
        # strip — submitNewTask() sends it straight through as first_due.
        assert 'id="ntFirstDue" type="date"' in html, "ntFirstDue must be a plain date input"
        assert "args.first_due = firstDue;" in _fn(js, "submitNewTask")
        assert "split('T')" not in _fn(js, "submitNewTask"), \
            "No time component to strip anymore — a stray split('T') would be dead code"
    def test_in_allowed(self, mcp):  assert "update_analysis_task" in _allowed(mcp)


# ── TASKS: Delete button ──────────────────────────────────────────────────────

class TestDeleteTaskButton:
    def test_is_async(self, js):     assert "async function deleteTask(" in js
    def test_has_confirm(self, js):  assert "confirm(" in _fn(js, "deleteTask")
    def test_calls_tool(self, js):   assert "delete_analysis_task" in _fn(js, "deleteTask")
    def test_refreshes(self, js):    assert "loadTasks" in _fn(js, "deleteTask")
    def test_in_allowed(self, mcp):  assert "delete_analysis_task" in _allowed(mcp)


# ── LEARN: Functions ──────────────────────────────────────────────────────────

class TestLearnFunctions:
    def test_loadLearnings(self, js):    assert "async function loadLearnings(" in js
    def test_loadLearnList(self, js):    assert "async function loadLearnList(" in js
    def test_loadLearnStats(self, js):   assert "async function loadLearnStats(" in js
    def test_searchLearnings(self, js):  assert "async function searchLearnings(" in js
    def test_renderLearnings(self, js):  assert "function renderLearnings(" in js
    def test_deleteLearning(self, js):   assert "async function deleteLearning(" in js
    def test_submitLearning(self, js):   assert "async function submitLearning(" in js
    def test_toggleLearnForm(self, js):  assert "function toggleLearnForm(" in js
    def test_cancelLearnForm(self, js):  assert "function cancelLearnForm(" in js


# ── LEARN: HTML ───────────────────────────────────────────────────────────────

class TestLearnHTML:
    def test_screenLearn(self, html):    assert 'id="screenLearn"' in html
    def test_navLearn(self, html):       assert 'id="navLearn"' in html
    def test_learnSearch(self, html):    assert 'id="learnSearch"' in html
    def test_learnList(self, html):      assert 'id="learnList"' in html
    def test_learnForm(self, html):      assert 'id="learnForm"' in html
    def test_learnStats(self, html):     assert 'id="learnStats"' in html

    def test_form_fields(self, html):
        for fid in ["lnTitle","lnContent","lnCategory","lnOutcome","lnTags","lnContext","lnError"]:
            assert f'id="{fid}"' in html, f"#{fid} missing"

    def test_categories(self, html):
        for c in ["general","business_lesson","client_preference","best_practice","technical_note"]:
            assert c in html, f"Category '{c}' missing"

    def test_outcomes(self, html):
        for o in ["positive","negative","neutral","unknown"]:
            assert o in html, f"Outcome '{o}' missing"


# ── LEARN: renderLearnings ────────────────────────────────────────────────────

class TestRenderLearnings:
    def test_parses_numbered_format(self, js):
        fn = _fn(js, "renderLearnings")
        assert r"\[\d+" in fn or "[\\d+" in fn or "\\[\\d" in fn or "\\d]" in fn or "\d+" in fn, \
            "Must split on [N] numbered format — list_learnings returns '[1] ✅ Title'"

    def test_extracts_id(self, js):
        assert "ID:" in _fn(js, "renderLearnings"), "Must extract ID: field"

    def test_extracts_arrow_content(self, js):
        fn = _fn(js, "renderLearnings")
        assert "\u2192" in fn or "\\u2192" in fn or "->" in fn

    def test_extracts_category(self, js):
        assert "category" in _fn(js, "renderLearnings").lower()

    def test_delete_data_action(self, js):
        fn = _fn(js, "renderLearnings")
        assert 'data-action="delete-learning"' in fn, \
            "Delete must use data-action not inline onclick"

    def test_delete_has_data_id(self, js):
        assert "data-id=" in _fn(js, "renderLearnings")

    def test_delete_has_data_title(self, js):
        assert "data-title=" in _fn(js, "renderLearnings")

    def test_shows_category_badge(self, js):
        fn = _fn(js, "renderLearnings")
        assert "catColor" in fn or "category" in fn.lower()

    def test_shows_created_date(self, js):
        fn = _fn(js, "renderLearnings")
        assert "Created:" in fn or "created" in fn.lower()

    def test_no_inline_onclick(self, js):
        fn = _fn(js, "renderLearnings")
        assert "onclick" not in fn, "Must use data-action not inline onclick"


# ── LEARN: API calls ──────────────────────────────────────────────────────────

class TestLearnAPICalls:
    def test_list_learnings(self, js):      assert "list_learnings" in _fn(js, "loadLearnList")
    def test_search_apislow(self, js):
        assert "apiSlow" in _fn(js, "searchLearnings"), "searchLearnings must use apiSlow"
    def test_search_tool(self, js):         assert "search_learnings" in _fn(js, "searchLearnings")
    def test_record_learning(self, js):     assert "record_learning" in _fn(js, "submitLearning")
    def test_validate_title(self, js):      assert "lnTitle" in _fn(js, "submitLearning")
    def test_validate_content(self, js):    assert "lnContent" in _fn(js, "submitLearning")
    def test_delete_confirm(self, js):
        assert "confirm(" in _fn(js, "deleteLearning"), "deleteLearning must confirm"
    def test_delete_tool(self, js):         assert "delete_learning" in _fn(js, "deleteLearning")
    def test_delete_id_param(self, js):     assert "learning_id" in _fn(js, "deleteLearning")
    def test_tools_in_allowed(self, mcp):
        allowed = _allowed(mcp)
        for t in ["list_learnings","search_learnings","record_learning","delete_learning","get_learning_stats"]:
            assert t in allowed, f"'{t}' not in _REMOTE_ALLOWED"


class TestLearnDelegation:
    def test_delete_learning_action_in_js(self, js):
        assert "delete-learning" in js, "delete-learning must be handled"
    def test_no_inline_onclick_in_render(self, js):
        assert "onclick" not in _fn(js, "renderLearnings")


# ── Navigation ────────────────────────────────────────────────────────────────

class TestNavigation:
    TABS = ["Dash","Files","Search","Perms","Learn","Tasks","System"]

    def test_tabs_array(self, js):
        for t in self.TABS: assert f"'{t}'" in js, f"'{t}' missing from TABS"

    def test_screens_exist(self, html):
        for t in self.TABS: assert f'id="screen{t}"' in html, f"#screen{t} missing"

    def test_nav_buttons(self, html):
        for t in self.TABS: assert f'id="nav{t}"' in html, f"#nav{t} missing"

    def test_boot_loads_learn(self, js):   assert "loadLearnings" in _fn(js, "boot")
    def test_boot_loads_tasks(self, js):   assert "loadTasks" in _fn(js, "boot")

"""
test_remote_task_buttons.py — Offline tests for Task tab buttons.
Reads work-tree source only, never touches installed AI-Prowler.
Run: pytest tests/mcp/test_remote_task_buttons.py -v
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
    m = re.search(r"<script>(.*?)</script>", html, re.DOTALL)
    assert m
    return m.group(1)

@pytest.fixture(scope="module")
def mcp():
    assert MCP_FILE.exists()
    return MCP_FILE.read_text(encoding="utf-8")

def _fn(js, name):
    start = js.find(f"function {name}")
    if start == -1: return ""
    end = len(js)
    for marker in ["\nasync function ", "\nfunction "]:
        idx = js.find(marker, start + 1)
        if 0 < idx < end: end = idx
    return js[start:end]

def _allowed(mcp):
    return mcp[mcp.find("_REMOTE_ALLOWED"):mcp.find("_REMOTE_ALLOWED")+2500]


class TestRenderTaskCardButtons:
    def test_queue_button_present(self, js):
        # Uses data-action="queue" — routed to runTaskNow() by event delegation
        assert 'data-action="queue"' in _fn(js, "renderTaskCard")
    def test_edit_button_present(self, js):
        # Uses data-action="edit" — routed to editTask() by event delegation
        assert 'data-action="edit"' in _fn(js, "renderTaskCard")
    def test_delete_button_present(self, js):
        # Uses data-action="delete" — routed to deleteTask() by event delegation
        assert 'data-action="delete"' in _fn(js, "renderTaskCard")
    def test_edit_labeled(self, js):
        assert "Edit" in _fn(js, "renderTaskCard")
    def test_delete_labeled(self, js):
        assert "Delete" in _fn(js, "renderTaskCard")
    def test_json_stringify_task_id_not_used(self, js):
        # Correct impl uses data-action + data-id, NOT JSON.stringify in onclick
        assert "JSON.stringify(t.task_id)" not in _fn(js, "renderTaskCard"), \
            "Must NOT use JSON.stringify — causes double-quoted string breaking onclick"
    def test_edit_accent_delete_red(self, js):
        fn = _fn(js, "renderTaskCard")
        assert "var(--accent)" in fn and "var(--red)" in fn
    def test_requeue_when_in_queue(self, js):
        assert "Re-Queue" in _fn(js, "renderTaskCard")


class TestQueueButton:
    def test_is_async(self, js):
        assert "async function runTaskNow" in js
    def test_calls_queue_single_task(self, js):
        assert "queue_single_task" in _fn(js, "runTaskNow"),             "Must use queue_single_task not sync_due_tasks_to_queue"
    def test_no_sync_all(self, js):
        assert "sync_due_tasks_to_queue" not in _fn(js, "runTaskNow")
    def test_passes_task_id(self, js):
        assert "task_id" in _fn(js, "runTaskNow")
    def test_refreshes(self, js):
        assert "loadTasks" in _fn(js, "runTaskNow")
    def test_toast(self, js):
        assert "toast(" in _fn(js, "runTaskNow")
    def test_mcp_defined(self, mcp):
        assert "def queue_single_task(" in mcp
    def test_in_allowed(self, mcp):
        assert "queue_single_task" in _allowed(mcp)


class TestEditButton:
    def test_is_async(self, js):
        assert "async function editTask" in js,             "editTask MUST be async — sync .then() never fires when api() blocks ASGI loop"
    def test_uses_apislow(self, js):
        assert "apiSlow" in _fn(js, "editTask"),             "editTask MUST use apiSlow() — list_analysis_tasks is blocking"
    def test_no_bare_api(self, js):
        bare = re.findall(r"\bapi\s*\(", _fn(js, "editTask"))
        assert not bare, f"editTask has bare api() calls that block: {bare}"
    def test_sets_editing_id(self, js):
        assert "_editingTaskId" in _fn(js, "editTask")
    def test_editing_id_declared(self, js):
        assert "let _editingTaskId" in js
    def test_prefills_label(self, js):
        assert "ntLabel" in _fn(js, "editTask")
    def test_prefills_prompt(self, js):
        assert "ntPrompt" in _fn(js, "editTask")
    def test_prefills_schedule(self, js):
        assert "ntSchedule" in _fn(js, "editTask")
    def test_prefills_checkboxes(self, js):
        fn = _fn(js, "editTask")
        assert "ntLearnings" in fn and "ntReport" in fn
    def test_shows_form(self, js):
        assert "newTaskForm" in _fn(js, "editTask")
    def test_loading_toast(self, js):
        assert "toast(" in _fn(js, "editTask")
    def test_updates_title(self, js):
        assert "taskFormTitle" in _fn(js, "editTask")
    def test_form_title_id(self, html):
        assert 'id="taskFormTitle"' in html
    def test_submit_btn_id(self, html):
        assert 'id="taskFormSubmitBtn"' in html
    def test_submit_update_in_edit_mode(self, js):
        assert "update_analysis_task" in _fn(js, "submitNewTask")
    def test_submit_create_in_new_mode(self, js):
        assert "create_analysis_task" in _fn(js, "submitNewTask")
    def test_cancel_resets_id(self, js):
        assert "_editingTaskId = null" in _fn(js, "cancelNewTask")
    def test_update_in_allowed(self, mcp):
        assert "update_analysis_task" in _allowed(mcp)


class TestDeleteButton:
    def test_is_async(self, js):
        assert "async function deleteTask" in js
    def test_confirm_guard(self, js):
        assert "confirm(" in _fn(js, "deleteTask"), "Missing confirm() guard"
    def test_calls_delete_tool(self, js):
        assert "delete_analysis_task" in _fn(js, "deleteTask")
    def test_task_id(self, js):
        assert "task_id" in _fn(js, "deleteTask")
    def test_refreshes(self, js):
        assert "loadTasks" in _fn(js, "deleteTask")
    def test_in_allowed(self, mcp):
        assert "delete_analysis_task" in _allowed(mcp)


class TestQueuePanel:
    def test_panel_exists(self, html):
        assert 'id="queuePanel"' in html
    def test_items_exists(self, html):
        assert 'id="queueItems"' in html
    def test_count_exists(self, html):
        assert 'id="queueCount"' in html
    def test_clear_btn_exists(self, html):
        assert 'id="queueClearBtn"' in html
    def test_uses_get_all_queued_tasks(self, js):
        assert "get_all_queued_tasks" in _fn(js, "loadTasks"),             "Must use get_all_queued_tasks not get_pending_analysis_tasks"
    def test_render_panel_defined(self, js):
        assert "function renderQueuePanel" in js
    def test_shows_due_date(self, js):
        assert "next_due" in _fn(js, "renderQueuePanel")
    def test_shows_queued_ago(self, js):
        fn = _fn(js, "renderQueuePanel")
        assert "queued_at" in fn or "_timeAgo" in fn
        # Uses data-action="remove-queue" via event delegation — not inline removeFromQueue()
        assert "remove-queue" in fn or "removeFromQueue" in fn, \
            "renderQueuePanel must have a remove button per item"
    def test_clear_queue_defined(self, js):
        assert "async function clearQueue" in js
    def test_mcp_defined(self, mcp):
        assert "def get_all_queued_tasks(" in mcp
    def test_in_allowed(self, mcp):
        assert "get_all_queued_tasks" in _allowed(mcp)
    def test_reads_pending_json(self, mcp):
        idx = mcp.find("def get_all_queued_tasks(")
        assert "pending_tasks" in mcp[idx:idx+1500] or "_load_pending" in mcp[idx:idx+1500]

    # NOTE: JSON.stringify in onclick breaks HTML — use single quotes

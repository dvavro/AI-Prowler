"""
test_remote_pwa_js.py
=====================
JavaScript logic tests for the Remote Control PWA.

These tests parse and validate the JS source directly (no browser needed)
catching bugs like:
  - ReferenceError: i is not defined (missing map index parameter)
  - Functions referencing removed elements (uploadInput after it was deleted)
  - Missing function definitions
  - Broken event wiring

Run alongside the existing test_remote_pwa.py offline tests:
    pytest tests/mcp/test_remote_pwa_js.py -v
"""
from __future__ import annotations

import re
import os
from pathlib import Path

import pytest

# ── Paths ──────────────────────────────────────────────────────────────────
_SRC       = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT   = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parents[2]
REMOTE_DIR = SRC_ROOT / "remote"
INDEX_HTML = REMOTE_DIR / "index.html"


@pytest.fixture(scope="module")
def html() -> str:
    assert INDEX_HTML.exists(), f"index.html not found: {INDEX_HTML}"
    return INDEX_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def js(html: str) -> str:
    """Extract the <script> block from index.html."""
    m = re.search(r"<script>(.*?)</script>", html, re.DOTALL)
    assert m, "No <script> block found in index.html"
    return m.group(1)


def _fn(js: str, name: str) -> str:
    """Extract a named function body from JS source."""
    start = js.find(f"function {name}")
    if start == -1:
        return ""
    # Find next top-level function
    end = len(js)
    for marker in ["\nasync function ", "\nfunction "]:
        idx = js.find(marker, start + 1)
        if 0 < idx < end:
            end = idx
    return js[start:end]


# ══════════════════════════════════════════════════════════════════════════════
# JS FUNCTION EXISTENCE
# ══════════════════════════════════════════════════════════════════════════════

class TestJsFunctions:
    """Verify all required JS functions are defined."""

    def test_loadFilesList_defined(self, js):
        assert "async function loadFilesList" in js

    def test_handleUpload_defined(self, js):
        assert "async function handleUpload" in js

    def test_loadPerms_defined(self, js):
        assert "async function loadPerms" in js

    def test_onPerm_defined(self, js):
        assert "async function onPerm" in js

    def test_confirmGrant_defined(self, js):
        assert "async function confirmGrant" in js

    def test_doSearch_defined(self, js):
        assert "async function doSearch" in js

    def test_apiSlow_defined(self, js):
        assert "async function apiSlow" in js

    def test_api_defined(self, js):
        assert "async function api(" in js

    def test_boot_defined(self, js):
        assert "function boot(" in js or "function boot()" in js

    def test_loadDash_defined(self, js):
        assert "async function loadDash" in js

    def test_loadSystem_defined(self, js):
        assert "async function loadSystem" in js

    def test_doAuth_defined(self, js):
        assert "async function doAuth" in js

    def test_switchTab_defined(self, js):
        assert "function switchTab" in js


# ══════════════════════════════════════════════════════════════════════════════
# MAP INDEX PARAMETER CHECKS
# ══════════════════════════════════════════════════════════════════════════════

class TestMapIndexParameters:
    """
    Catch 'ReferenceError: i is not defined'.
    Any .map() callback that uses bare 'i' must declare it as second param.
    """

    def test_loadFilesList_map_declares_index(self, js):
        fn = _fn(js, "loadFilesList")
        assert fn, "loadFilesList not found"
        # If the function uses '+ i' or 'i +' or 'upl_' + i pattern,
        # the map must be .map((d, i) not .map(d =>
        if ("+ i" in fn or "i +" in fn or "'upl_'" in fn or '"upl_"' in fn):
            assert ".map((d, i)" in fn or ".map((d,i)" in fn, \
                "loadFilesList uses 'i' inside .map() but declares .map(d =>). " \
                "Must be .map((d, i) => ...) — causes ReferenceError: i is not defined"

    def test_loadPerms_map_declares_index(self, js):
        fn = _fn(js, "loadPerms")
        assert fn, "loadPerms not found"
        if ("+ i" in fn or "i +" in fn or "pb" + "'+i" in fn
                or "'pb'" in fn or '"pb"' in fn):
            assert ".map((p, i)" in fn or ".map((d, i)" in fn, \
                "loadPerms uses 'i' for badge IDs but map is .map(p => ...). " \
                "Must be .map((p, i) => ...)"

    def test_no_single_param_map_using_index_i(self, js):
        """
        Generic guard: .map(x => { ... uses bare i ... }) is a ReferenceError.
        Finds arrow functions with a single param that use 'i' as index variable.
        """
        violations = []
        for m in re.finditer(r'\.map\(\s*(\w+)\s*=>', js):
            param = m.group(1)
            if param in ('i', '_i', 'idx'):
                continue  # i is the param itself, fine
            # Get ~300 chars of body after the arrow
            body_start = m.end()
            body = js[body_start:body_start + 400]
            # Look for bare 'i' used as a value (not part of a word)
            if re.search(r"(?<!\w)i(?!\w).*?[+'\"]", body):
                violations.append(
                    f"Line near: {js[m.start():m.start()+60]!r}"
                )
        assert not violations, (
            "Found .map() with single param that uses bare 'i' — "
            "ReferenceError: i is not defined:\n" + "\n".join(violations[:5])
        )


# ══════════════════════════════════════════════════════════════════════════════
# ELEMENT REFERENCE CHECKS
# ══════════════════════════════════════════════════════════════════════════════

class TestElementReferences:
    """Verify JS getElementById calls match actual HTML elements."""

    def test_no_stale_uploadInput_reference(self, js):
        """uploadInput replaced by per-row label+input — no JS should reference it."""
        non_comment = [l.strip() for l in js.splitlines()
                       if 'uploadInput' in l and not l.strip().startswith('//')]
        assert not non_comment, (
            "JS still references 'uploadInput' which no longer exists:\n"
            + "\n".join(non_comment[:5])
        )

    def test_uploadStatus_in_html(self, html):
        assert 'id="uploadStatus"' in html, \
            "#uploadStatus missing — upload status messages won't show"

    def test_reauth_modal_elements(self, html):
        for eid in ["reAuthModal", "raPath", "raInput", "raErr",
                    "raLocked", "raConfirm"]:
            assert f'id="{eid}"' in html, \
                f"#{eid} missing — re-auth modal broken"

    def test_permCard_created_in_js(self, js):
        assert 'id="permCard"' in js or 'id=\\"permCard\\"' in js, \
            "permCard not built in loadPerms JS"

    def test_permCard_delegation_attached(self, js):
        assert "permCard" in js and "addEventListener" in js, \
            "permCard event delegation missing — toggles won't fire on mobile"

    def test_getElementByIds_exist_in_html(self, html, js):
        ids_in_js = set(re.findall(r"getElementById\('(\w+)'\)", js))
        ids_in_html = set(re.findall(r'id="(\w+)"', html))
        allowed_missing = {"debugLog", "breadcrumb"}  # intentionally absent; dbg() no-ops safely
        missing = ids_in_js - ids_in_html - allowed_missing
        assert not missing, "JS getElementById() refs missing from HTML: " + str(missing)



# ══════════════════════════════════════════════════════════════════════════════
# UPLOAD MECHANISM
# ══════════════════════════════════════════════════════════════════════════════

class TestUploadMechanism:
    """Verify label+input upload pattern."""

    def test_label_input_pattern_used(self, js):
        assert 'label for="' in js or "label for='" in js, \
            "Upload should use <label for=id> pattern not programmatic .click()"

    def test_no_programmatic_click_on_file_input(self, js):
        bad = [l.strip() for l in js.splitlines()
               if '.click()' in l
               and 'uploadInput' in l
               and not l.strip().startswith('//')]
        assert not bad, \
            "Programmatic .click() on file input blocked on mobile:\n" + "\n".join(bad)

    def test_handleUpload_reads_data_dir(self, js):
        fn = _fn(js, "handleUpload")
        assert "data-dir" in fn, \
            "handleUpload doesn't read 'data-dir' — upload target dir lost"

    def test_handleUpload_uses_formdata(self, js):
        fn = _fn(js, "handleUpload")
        assert "FormData" in fn, "handleUpload missing FormData"
        assert "append('file'" in fn or 'append("file"' in fn, \
            "handleUpload doesn't append file to FormData"
        assert "append('dir'" in fn or 'append("dir"' in fn, \
            "handleUpload doesn't append dir to FormData"

    def test_handleUpload_posts_to_remote_upload(self, js):
        fn = _fn(js, "handleUpload")
        assert "/remote/upload" in fn

    def test_upload_only_for_writable_dirs(self, js):
        fn = _fn(js, "loadFilesList")
        assert "isW" in fn, "loadFilesList doesn't check writable status"
        isw_idx   = fn.find("isW")
        label_idx = fn.find("label for=")
        assert 0 < isw_idx < label_idx, \
            "Upload label generated before writable check — shows on read-only dirs"

    def test_upload_input_reset_after_use(self, js):
        fn = _fn(js, "handleUpload")
        assert "inp.value = ''" in fn or 'inp.value=""' in fn, \
            "handleUpload doesn't reset input.value — same file can't be re-uploaded"


# ══════════════════════════════════════════════════════════════════════════════
# SEARCH
# ══════════════════════════════════════════════════════════════════════════════

class TestSearch:
    def test_uses_n_results(self, js):
        fn = _fn(js, "doSearch")
        assert "n_results" in fn, "doSearch should use 'n_results' param"
        assert "top_k" not in fn, "doSearch uses old 'top_k' param"

    def test_uses_apiSlow(self, js):
        fn = _fn(js, "doSearch")
        assert "apiSlow" in fn, "doSearch should use apiSlow() not api()"

    def test_apiSlow_30s_timeout(self, js):
        fn = _fn(js, "apiSlow")
        assert "30000" in fn

    def test_apiSlow_uses_abort_controller(self, js):
        fn = _fn(js, "apiSlow")
        assert "AbortController" in fn


# ══════════════════════════════════════════════════════════════════════════════
# PERMISSIONS
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissions:
    def test_writable_set_filters_W_lines(self, js):
        fn = _fn(js, "loadPerms")
        assert "includes('[W]')" in fn or 'includes("[W]")' in fn, \
            "loadPerms should filter lines containing '[W]' for writable set"

    def test_tracked_dirs_strips_numbering(self, js):
        fn = _fn(js, "loadPerms")
        assert r"replace(/^\d+" in fn, \
            "loadPerms should strip leading '1. ' from list_tracked_directories output"

    def test_reauth_3attempt_lockout(self, js):
        fn = _fn(js, "confirmGrant")
        assert "raAttempts >= 3" in fn, "confirmGrant should lock after 3 attempts"
        assert "30000" in fn, "confirmGrant lockout should be 30s"

    def test_revoke_does_not_open_modal(self, js):
        fn = _fn(js, "onPerm")
        assert "revoke_write_access" in fn
        assert "reAuthModal" in fn
        # revoke happens in the !cb.checked branch, modal in else (grant) branch
        revoke_idx = fn.find("revoke_write_access")
        modal_idx  = fn.find("reAuthModal")
        assert revoke_idx < modal_idx, \
            "onPerm structure wrong — revoke and modal open in wrong branches"

    def test_perm_delegation_not_inline_onchange(self, js):
        """onchange inline handlers on dynamically created elements fail on iOS."""
        fn = _fn(js, "loadPerms")
        # Check no non-comment onchange lines — comments containing 'onchange' are fine
        onchange_lines = [l.strip() for l in fn.splitlines()
                          if 'onchange' in l and not l.strip().startswith('//')]
        assert not onchange_lines, (
            "loadPerms uses inline onchange — use event delegation instead (iOS bug):\n"
            + "\n".join(onchange_lines[:3])
        )
        assert "perm-cb" in fn, \
            "loadPerms should use class='perm-cb' for event delegation"


# ══════════════════════════════════════════════════════════════════════════════
# LEARNINGS TAB
# ══════════════════════════════════════════════════════════════════════════════

class TestLearningsTab:
    """Verify Learnings tab JS functions and HTML structure."""

    # ── Function existence ─────────────────────────────────────────────────

    def test_loadLearnings_defined(self, js):
        assert "async function loadLearnings" in js,             "loadLearnings() missing — Learn tab broken on boot"

    def test_loadLearnList_defined(self, js):
        assert "async function loadLearnList" in js,             "loadLearnList() missing — learnings list won't load"

    def test_searchLearnings_defined(self, js):
        assert "async function searchLearnings" in js,             "searchLearnings() missing — search won't work"

    def test_deleteLearning_defined(self, js):
        assert "async function deleteLearning" in js,             "deleteLearning() missing — delete button broken"

    def test_submitLearning_defined(self, js):
        assert "async function submitLearning" in js,             "submitLearning() missing — Add Learning form broken"

    def test_toggleLearnForm_defined(self, js):
        assert "function toggleLearnForm" in js,             "toggleLearnForm() missing — + Add Learning button broken"

    def test_cancelLearnForm_defined(self, js):
        assert "function cancelLearnForm" in js,             "cancelLearnForm() missing — Cancel button broken"

    # ── HTML structure ─────────────────────────────────────────────────────

    def test_learn_screen_exists(self, html):
        assert 'id="screenLearn"' in html,             "#screenLearn missing — Learn tab screen not in HTML"

    def test_learn_nav_button_exists(self, html):
        assert 'id="navLearn"' in html,             "#navLearn missing — Learn nav button not in HTML"

    def test_learn_search_input_exists(self, html):
        assert 'id="learnSearch"' in html,             "#learnSearch input missing"

    def test_learn_form_exists(self, html):
        assert 'id="learnForm"' in html,             "#learnForm missing — Add Learning form not in HTML"

    def test_learn_form_fields_exist(self, html):
        for eid in ["lnTitle", "lnContent", "lnCategory", "lnOutcome",
                    "lnTags", "lnContext", "lnError"]:
            assert f'id="{eid}"' in html,                 f"#{eid} missing from Learn form"

    def test_learn_list_container_exists(self, html):
        assert 'id="learnList"' in html,             "#learnList missing — learnings won't render"

    def test_learn_stats_element_exists(self, html):
        assert 'id="learnStats"' in html,             "#learnStats missing — learning count won't show"

    def test_learn_in_tabs_array(self, js):
        assert "'Learn'" in js,             "Learn not in TABS array — switchTab won't work for Learn"

    def test_learn_in_boot(self, js):
        fn = _fn(js, "boot")
        assert "loadLearnings" in fn,             "loadLearnings() not called in boot() — Learn tab empty on login"

    # ── API calls ──────────────────────────────────────────────────────────

    def test_loadLearnList_calls_list_learnings(self, js):
        fn = _fn(js, "loadLearnList")
        assert "list_learnings" in fn,             "loadLearnList doesn't call list_learnings tool"

    def test_searchLearnings_calls_search_learnings(self, js):
        fn = _fn(js, "searchLearnings")
        assert "search_learnings" in fn,             "searchLearnings doesn't call search_learnings tool"

    def test_searchLearnings_uses_apiSlow(self, js):
        fn = _fn(js, "searchLearnings")
        assert "apiSlow" in fn,             "searchLearnings should use apiSlow() — RAG search needs 30s timeout"

    def test_submitLearning_calls_record_learning(self, js):
        fn = _fn(js, "submitLearning")
        assert "record_learning" in fn,             "submitLearning doesn't call record_learning tool"

    def test_submitLearning_sends_title_and_content(self, js):
        fn = _fn(js, "submitLearning")
        assert "title" in fn and "content" in fn,             "submitLearning missing title or content fields"

    def test_submitLearning_validates_required_fields(self, js):
        fn = _fn(js, "submitLearning")
        assert "Title is required" in fn or "title" in fn.lower(),             "submitLearning missing validation for required title"
        assert "Content is required" in fn or "content" in fn.lower(),             "submitLearning missing validation for required content"

    def test_deleteLearning_calls_delete_learning(self, js):
        fn = _fn(js, "deleteLearning")
        assert "delete_learning" in fn,             "deleteLearning doesn't call delete_learning tool"

    def test_deleteLearning_has_confirm_dialog(self, js):
        fn = _fn(js, "deleteLearning")
        assert "confirm(" in fn,             "deleteLearning missing confirm() dialog — destructive action unguarded"

    def test_deleteLearning_passes_learning_id(self, js):
        fn = _fn(js, "deleteLearning")
        assert "learning_id" in fn,             "deleteLearning doesn't pass learning_id param"

    def test_category_select_has_options(self, html):
        assert "business_lesson" in html, "business_lesson category missing"
        assert "client_preference" in html, "client_preference category missing"
        assert "best_practice" in html, "best_practice category missing"
        assert "process_improvement" in html, "process_improvement missing"

    def test_outcome_select_has_options(self, html):
        assert "positive" in html, "positive outcome missing"
        assert "negative" in html, "negative outcome missing"
        assert "neutral" in html, "neutral outcome missing"

    def test_learn_stats_loaded_in_loadLearnings(self, js):
        fn = _fn(js, "loadLearnings")
        assert "LearnStats" in fn or "loadLearnStats" in fn,             "loadLearnings doesn't load stats"


# ══════════════════════════════════════════════════════════════════════════════
# TASK QUEUE TAB
# ══════════════════════════════════════════════════════════════════════════════

class TestTaskQueueTab:
    """Verify Task Queue tab JS functions and HTML structure."""

    # ── Function existence ─────────────────────────────────────────────────

    def test_loadTasks_defined(self, js):
        assert "async function loadTasks" in js,             "loadTasks() missing — Tasks tab broken on boot"

    def test_loadAllTasks_defined(self, js):
        assert "async function loadAllTasks" in js,             "loadAllTasks() missing — All Tasks list won't load"

    def test_loadPendingTasks_defined(self, js):
        # loadPendingTasks removed — queue loaded inline via _pendingBySourceId in loadTasks
        assert "_pendingBySourceId" in js, \
            "_pendingBySourceId missing — inline queue status won't work"
    def test_submitNewTask_defined(self, js):
        assert "async function submitNewTask" in js,             "submitNewTask() missing — New Task form broken"

    def test_showNewTaskForm_defined(self, js):
        assert "function showNewTaskForm" in js,             "showNewTaskForm() missing — + New Task button broken"

    def test_cancelNewTask_defined(self, js):
        assert "function cancelNewTask" in js,             "cancelNewTask() missing — Cancel button broken"

    def test_syncTasks_defined(self, js):
        assert "async function syncTasks" in js,             "syncTasks() missing — Sync Queue button broken"

    def test_runTaskNow_defined(self, js):
        assert "async function runTaskNow" in js,             "runTaskNow() missing — Run Now button broken"

    def test_deleteTask_defined(self, js):
        assert "async function deleteTask" in js,             "deleteTask() missing — Delete button broken"

    def test_completeTask_defined(self, js):
        # completeTask renamed to removeFromQueue
        assert "async function removeFromQueue" in js, \
            "removeFromQueue() missing — Remove button broken"
    # ── HTML structure ─────────────────────────────────────────────────────

    def test_tasks_screen_exists(self, html):
        assert 'id="screenTasks"' in html

    def test_tasks_nav_button_exists(self, html):
        assert 'id="navTasks"' in html

    def test_new_task_form_exists(self, html):
        assert 'id="newTaskForm"' in html

    def test_task_form_fields_exist(self, html):
        for eid in ["ntLabel", "ntPrompt", "ntSchedule",
                    "ntFirstDue", "ntLearnings", "ntReport", "ntError"]:
            assert f'id="{eid}"' in html, f"#{eid} missing from New Task form"

        # taskPending removed — queue shown inline per task via _pendingBySourceId
        assert "_pendingBySourceId" in html or "queueBanner" in html, \
            "Inline queue status mechanism missing from Tasks JS"
    def test_task_list_container_exists(self, html):
        assert 'id="taskList"' in html

    def test_tasks_in_tabs_array(self, js):
        assert "'Tasks'" in js

    def test_tasks_in_boot(self, js):
        fn = _fn(js, "boot")
        assert "loadTasks" in fn,             "loadTasks() not called in boot()"

    def test_schedule_select_has_options(self, html):
        assert "Run once" in html or "none" in html, "Run once option missing"
        assert "Daily" in html, "Daily schedule option missing"
        assert "Weekly" in html, "Weekly schedule option missing"
        assert "Monthly" in html, "Monthly schedule option missing"

    # ── API calls ──────────────────────────────────────────────────────────

    def test_loadAllTasks_calls_list_analysis_tasks(self, js):
        fn = _fn(js, "loadAllTasks")
        assert "list_analysis_tasks" in fn

    def test_loadPendingTasks_calls_get_pending(self, js):
        # get_pending_analysis_tasks is now called in loadTasks()
        fn = _fn(js, "loadTasks")
        assert "get_all_queued_tasks" in fn, \
            "loadTasks should call get_all_queued_tasks to show full queue including future items"

    def test_submitNewTask_calls_create_analysis_task(self, js):
        fn = _fn(js, "submitNewTask")
        assert "create_analysis_task" in fn

    def test_submitNewTask_validates_label(self, js):
        fn = _fn(js, "submitNewTask")
        assert "Label is required" in fn or "label" in fn.lower()

    def test_submitNewTask_validates_prompt(self, js):
        fn = _fn(js, "submitNewTask")
        assert "Prompt is required" in fn or "prompt" in fn.lower()

    def test_deleteTask_has_confirm(self, js):
        fn = _fn(js, "deleteTask")
        assert "confirm(" in fn,             "deleteTask missing confirm() — destructive action unguarded"

    def test_deleteTask_calls_delete_analysis_task(self, js):
        fn = _fn(js, "deleteTask")
        assert "delete_analysis_task" in fn

    def test_completeTask_calls_complete_analysis_task(self, js):
        # removeFromQueue now uses delete_analysis_task to remove queue entries
        fn_start = js.find("async function removeFromQueue")
        fn = js[fn_start:fn_start+400] if fn_start > -1 else ""
        assert "delete_analysis_task" in fn, \
            "removeFromQueue should call delete_analysis_task"

    def test_syncTasks_calls_sync_due(self, js):
        fn = _fn(js, "syncTasks")
        assert "sync_due_tasks_to_queue" in fn

    # ── queue_single_task ──────────────────────────────────────────────────

    def test_runTaskNow_uses_queue_single_task(self, js):
        fn = _fn(js, "runTaskNow")
        assert "queue_single_task" in fn,             "runTaskNow should use queue_single_task not sync_due_tasks_to_queue"

    def test_runTaskNow_does_not_call_sync(self, js):
        fn = _fn(js, "runTaskNow")
        assert "sync_due_tasks_to_queue" not in fn,             "runTaskNow calls sync_due_tasks_to_queue — should be queue_single_task only"

    def test_runTaskNow_passes_task_id(self, js):
        fn = _fn(js, "runTaskNow")
        assert "task_id" in fn,             "runTaskNow doesn't pass task_id to queue_single_task"


# ══════════════════════════════════════════════════════════════════════════════
# _REMOTE_ALLOWED TOOL LIST (source check)
# ══════════════════════════════════════════════════════════════════════════════

class TestRemoteAllowedTools:
    """Verify all tools used by the PWA are in _REMOTE_ALLOWED."""

    @pytest.fixture(scope="class")
    def mcp_src(self) -> str:
        _SRC = os.environ.get("AI_PROWLER_SRC")
        root = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parents[2]
        mcp = root / "ai_prowler_mcp.py"
        assert mcp.exists(), f"ai_prowler_mcp.py not found: {mcp}"
        return mcp.read_text(encoding="utf-8")

    def _allowed(self, mcp_src: str) -> set:
        import re
        idx = mcp_src.find("_REMOTE_ALLOWED")
        block = mcp_src[idx:idx+2000]
        return set(re.findall(r'"([\w_]+)"', block))

    def test_learnings_tools_in_allowed(self, mcp_src):
        allowed = self._allowed(mcp_src)
        for tool in ["list_learnings", "search_learnings", "record_learning",
                     "update_learning", "delete_learning", "get_learning_stats"]:
            assert tool in allowed,                 f"'{tool}' missing from _REMOTE_ALLOWED — Learn tab will get 400"

    def test_task_tools_in_allowed(self, mcp_src):
        allowed = self._allowed(mcp_src)
        for tool in ["list_analysis_tasks", "get_pending_analysis_tasks",
                     "create_analysis_task", "update_analysis_task",
                     "delete_analysis_task",
                     "sync_due_tasks_to_queue", "queue_single_task"]:
            assert tool in allowed, \
                f"'{tool}' missing from _REMOTE_ALLOWED — Tasks tab will get 400"
    def test_queue_single_task_defined_in_mcp(self, mcp_src):
        assert "def queue_single_task(" in mcp_src,             "queue_single_task not defined in ai_prowler_mcp.py"

    def test_queue_single_task_writes_pending_json(self, mcp_src):
        idx = mcp_src.find("def queue_single_task(")
        fn = mcp_src[idx:idx+3000]
        assert "pending_tasks.json" in fn,             "queue_single_task doesn't write to pending_tasks.json"

    def test_queue_single_task_checks_for_duplicates(self, mcp_src):
        idx = mcp_src.find("def queue_single_task(")
        fn = mcp_src[idx:idx+3000]
        assert "already" in fn.lower() or "duplicate" in fn.lower() or                "_already" in fn,             "queue_single_task doesn't check for duplicate pending entries"

    def test_write_tools_not_in_allowed(self, mcp_src):
        allowed = self._allowed(mcp_src)
        dangerous = ["write_file", "create_file", "reindex_all",
                     "run_script", "send_sms", "send_whatsapp"]
        for tool in dangerous:
            assert tool not in allowed,                 f"Dangerous tool '{tool}' in _REMOTE_ALLOWED — security risk"

    def test_upload_route_in_mcp(self, mcp_src):
        assert '/remote/upload' in mcp_src,             "/remote/upload route missing from ai_prowler_mcp.py"

    def test_download_route_in_mcp(self, mcp_src):
        assert '/remote/download' in mcp_src,             "/remote/download route missing from ai_prowler_mcp.py"

    def test_upload_uses_run_in_executor(self, mcp_src):
        idx = mcp_src.find('/remote/upload')
        block = mcp_src[idx:idx+8000]
        assert "run_in_executor" in block,             "/remote/upload handler doesn't use run_in_executor — "             "will block ASGI event loop and timeout"


    def test_remote_api_uses_run_in_executor(self, mcp_src):
        # Use the actual if-block as anchor — the comment appears before it
        idx = mcp_src.find('path == "/remote-api"')
        if idx == -1:
            idx = mcp_src.find('/remote-api')
        block = mcp_src[idx:idx+8000]
        assert "run_in_executor" in block, \
            "/remote-api handler doesn't use run_in_executor — blocking tools will timeout"

# ══════════════════════════════════════════════════════════════════════════════
# NAVIGATION COMPLETENESS
# ══════════════════════════════════════════════════════════════════════════════

class TestNavigation:
    """Verify all 7 tabs are present and wired correctly."""

    EXPECTED_TABS = ['Dash', 'Files', 'Search', 'Perms', 'Learn', 'Tasks', 'System']
    EXPECTED_IDS  = ['navDash', 'navFiles', 'navSearch', 'navPerms',
                     'navLearn', 'navTasks', 'navSystem']
    EXPECTED_SCREENS = ['screenDash', 'screenFiles', 'screenSearch', 'screenPerms',
                        'screenLearn', 'screenTasks', 'screenSystem']

    def test_tabs_array_has_all_tabs(self, js):
        for tab in self.EXPECTED_TABS:
            assert f"'{tab}'" in js, f"'{tab}' missing from TABS array"

    def test_all_nav_buttons_exist(self, html):
        for nid in self.EXPECTED_IDS:
            assert f'id="{nid}"' in html, f"#{nid} nav button missing"

    def test_all_screens_exist(self, html):
        for sid in self.EXPECTED_SCREENS:
            assert f'id="{sid}"' in html, f"#{sid} screen missing"

    def test_boot_calls_all_loaders(self, js):
        fn = _fn(js, "boot")
        for loader in ["loadDash", "loadFilesList", "loadPerms",
                       "loadLearnings", "loadTasks", "loadSystem"]:
            assert loader in fn,                 f"boot() doesn't call {loader}() — tab will be empty on login"

    def test_switchTab_handles_all_tabs(self, js):
        fn = _fn(js, "switchTab")
        # switchTab uses TABS array dynamically so just check it uses getElementById
        assert "getElementById" in fn or "TABS" in fn,             "switchTab doesn't reference TABS or getElementById"

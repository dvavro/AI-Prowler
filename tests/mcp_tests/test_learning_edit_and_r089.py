"""
2026-10-11 (David): edit learnings on the Remote app, and R-089 (Edit couldn't
clear an optional task field).

  • get_learning(learning_id) returns ONE learning's full record as JSON —
    tags always a list — or ❌ when it doesn't exist; offered to the Remote
    app (/remote-api) and listed in the tool catalog.
  • remote\\index.html: a learning card has ✎ Edit; Edit fills the form from
    get_learning and saves with update_learning (tags as a list, every field
    sent so emptying clears); a task edit ALWAYS sends first_due /
    report_folder / scope_dirs (R-089) and refuses a scheduled task with no
    first due date.
End-to-end: tests\\gui_remote_e2e\\test_remote_fields.py RE-06, RE-08..RE-10.

Run: run_tests.bat tests\\mcp_tests\\test_learning_edit_and_r089.py -v
"""
import ast
import json
import re
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
_MCP = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
_JS = (_SRC / "remote" / "index.html").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    i = _JS.index(f"function {name}(")
    j = _JS.find("\nfunction ", i + 10)
    k = _JS.find("\nasync function ", i + 10)
    ends = [x for x in (j, k) if x != -1]
    return _JS[i:min(ends) if ends else len(_JS)]


@pytest.fixture()
def ap(monkeypatch):
    import ai_prowler_mcp as _ap
    _ap._prewarm_event.set()
    monkeypatch.setattr(_ap, "_telemetry_increment_tool_count", lambda *a, **k: None)
    return _ap


# ── get_learning ─────────────────────────────────────────────────────────────
def test_get_learning_returns_the_full_record(ap, monkeypatch):
    rec = {"id": "abc-1", "title": "T", "content": "C full text", "context": "why",
           "category": "client_preference", "outcome": "negative", "tags": ["a", "b"],
           "confidence": 0.8, "status": "active", "created_at": "x", "updated_at": "y",
           "recorded_by_id": "secret-internal"}
    monkeypatch.setattr(ap._sl, "get_learning_by_id", lambda i: rec if i == "abc-1" else None)
    out = json.loads(ap.get_learning("abc-1"))
    for k in ("id", "title", "content", "context", "category", "outcome", "tags", "status"):
        assert out[k] == rec[k], k
    assert "recorded_by_id" not in out


def test_get_learning_tags_are_always_a_list(ap, monkeypatch):
    monkeypatch.setattr(ap._sl, "get_learning_by_id", lambda i: {"id": i, "title": "T", "tags": "x, y ,"})
    assert json.loads(ap.get_learning("z"))["tags"] == ["x", "y"]
    monkeypatch.setattr(ap._sl, "get_learning_by_id", lambda i: {"id": i, "title": "T", "tags": None})
    assert json.loads(ap.get_learning("z"))["tags"] == []


def test_get_learning_missing_and_blank(ap, monkeypatch):
    monkeypatch.setattr(ap._sl, "get_learning_by_id", lambda i: None)
    assert ap.get_learning("nope").startswith("❌")
    assert ap.get_learning("  ").startswith("❌")


def test_get_learning_offered_to_remote_and_in_catalog():
    remote = None
    for node in ast.walk(ast.parse(_MCP)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "_REMOTE_ALLOWED"
                and isinstance(node.value, ast.Set)):
            remote = {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    assert remote and "get_learning" in remote and "update_learning" in remote
    import mcp_tool_catalog as cat
    assert set(cat.modes_of("get_learning")) == {"personal", "server"}, cat.modes_of("get_learning")


# ── Remote app: learning Edit ────────────────────────────────────────────────
def test_learning_card_has_edit_button_and_handler():
    assert 'data-action="edit-learning"' in _fn("renderLearnings")
    assert "editLearning(ed.getAttribute('data-id'))" in _JS


def test_edit_fills_from_get_learning_and_saves_with_update_learning():
    ed = _fn("editLearning")
    assert "api('get_learning', { learning_id: id })" in ed
    for fid in ("lnTitle", "lnContent", "lnCategory", "lnOutcome", "lnTags", "lnContext"):
        assert fid in ed, f"{fid} not filled by Edit"
    sub = _fn("submitLearning")
    assert "api('update_learning', { learning_id: _editingLearningId, updates: updates })" in sub
    assert "split(',')" in sub, "tags must be sent as a list"
    assert "api('record_learning', args)" in sub, "+ New Learning must still create one"


def test_cancel_resets_the_form_to_new_learning():
    assert "_setLearnFormMode(null)" in _fn("cancelLearnForm")
    mode = _fn("_setLearnFormMode")
    assert "Edit Learning" in mode and "New Learning" in mode and "Save Changes" in mode


# ── Remote app: R-089 ────────────────────────────────────────────────────────
def test_r089_task_edit_always_sends_the_optional_fields():
    sub = _fn("submitNewTask")
    i = sub.index("if (_editingTaskId) {")
    block = sub[i:sub.index("} else {", i)]
    for line in ("args.first_due = firstDue;", "args.report_folder = reportFolder;",
                 "args.scope_dirs = scopeDirs;"):
        assert line in block, f"edit doesn't always send: {line}"
    assert "needs a first due date" in block, "a scheduled task with no due date must be refused"


def test_r089_new_task_still_omits_empty_fields():
    sub = _fn("submitNewTask")
    tail = sub[sub.index("} else {", sub.index("if (_editingTaskId) {")):]
    assert "if (firstDue) args.first_due = firstDue;" in tail
    assert "if (scopeDirs.length) args.scope_dirs = scopeDirs;" in tail

"""
Remote PWA regressions that the live E2E suite can no longer reach
(REMOTE_PWA_E2E_TEST_SPEC.md §7).

RM-R-007 — a tracked folder INSIDE a writable folder is writable through its
parent. The live sandbox was moved OUT of the writable work folder (so grant /
revoke could be tested for real), and no tracked folder on David's install sits
inside a writable one any more — so the "nested folder" case is checked here,
offline, against temp folders and a patched allow-list (nothing real touched):
  * list_writable_directories lists it under Writable, in the exact
    "  ✅ [W]  <path>" line the Remote app parses, plus a "↳ … inside …" note;
  * revoke_write_access refuses with a ❌ that names the parent, and changes nothing;
  * grant_write_access says "already in the write zone" and changes nothing;
  * a folder that is NOT inside a writable one still says "nothing to revoke".

RM-R-008 — the server wraps a tool's own refusal as {ok:true, result:"❌ …"};
the Remote app's api()/apiSlow() must turn that into ok:false (one helper for
every screen), so "Task created" is never shown for a task that wasn't saved.

Run:  run_tests.bat tests\\mcp\\test_rm_r007_r008_remote_write_zone.py -v
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import ai_prowler_mcp as mcp_mod

SRC = Path(mcp_mod.__file__).resolve().parent
REMOTE_HTML = SRC / "remote" / "index.html"


@pytest.fixture
def zone(tmp_path, monkeypatch):
    parent = tmp_path / "Work"
    child = parent / "tests"
    outside = tmp_path / "Elsewhere"
    for d in (child, outside):
        d.mkdir(parents=True)
    state = {"writable": [str(parent.resolve())],
             "read": [str(parent.resolve()), str(child.resolve()), str(outside.resolve())],
             "saves": 0}

    def _save(lst):
        state["saves"] += 1
        state["writable"] = list(lst)
        return True

    monkeypatch.setattr(mcp_mod, "_writable_allowlist_load", lambda: list(state["writable"]))
    monkeypatch.setattr(mcp_mod, "_writable_allowlist_save", _save)
    monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: list(state["read"]))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)      # personal mode
    return {"parent": str(parent.resolve()), "child": str(child.resolve()),
            "outside": str(outside.resolve()), "state": state}


def _writable_paths(listing: str) -> list[str]:
    """Same parse the Remote app does: every '✅ [W]  <path>' line."""
    return [m.group(1).strip() for m in re.finditer(r"✅ \[W\]\s+(.+)", listing)]


def test_rm_r007_nested_folder_listed_as_writable(zone):
    out = mcp_mod.list_writable_directories()
    ws = _writable_paths(out)
    assert zone["child"] in ws, f"nested folder not under Writable:\n{out}"
    assert zone["outside"] not in ws
    assert f"↳ writable because it is inside {zone['parent']}" in out
    ro = out.split("Read-only directories", 1)[1]
    assert zone["child"] not in ro, "nested folder also listed as read-only"
    assert zone["outside"] in ro


def test_rm_r007_revoke_nested_folder_is_refused(zone):
    out = mcp_mod.revoke_write_access(directory=zone["child"])
    assert out.strip().startswith("❌"), out
    assert zone["parent"] in out and "Revoke" in out
    assert zone["state"]["saves"] == 0 and zone["state"]["writable"] == [zone["parent"]]


def test_rm_r007_grant_nested_folder_changes_nothing(zone):
    out = mcp_mod.grant_write_access(directory=zone["child"])
    assert "already in the write zone" in out, out
    assert zone["state"]["saves"] == 0


def test_rm_r007_revoke_unrelated_folder_still_nothing_to_revoke(zone):
    out = mcp_mod.revoke_write_access(directory=zone["outside"])
    assert "nothing to revoke" in out and not out.strip().startswith("❌"), out
    assert zone["state"]["saves"] == 0


def test_rm_r007_revoke_the_parent_still_works(zone):
    out = mcp_mod.revoke_write_access(directory=zone["parent"])
    assert out.strip().startswith("✅"), out
    assert zone["state"]["writable"] == []


# ── RM-R-008: the Remote app turns a ❌ result into a real error ────────────────
def _page() -> str:
    return REMOTE_HTML.read_text(encoding="utf-8")


def test_rm_r008_helper_exists_and_both_callers_use_it():
    html = _page()
    assert "function _asResult(d)" in html
    body = html.split("function _asResult(d)", 1)[1].split("\n}", 1)[0]
    assert "\\u274C" in body and "ok: false" in body and "error:" in body
    api = html.split("async function api(tool, args)", 1)[1].split("\nasync function", 1)[0]
    assert "_asResult(JSON.parse(txt))" in api, "api() doesn't route through _asResult"
    slow = html.split("async function apiSlow(tool, args)", 1)[1].split("\n}", 1)[0]
    assert "_asResult(" in slow, "apiSlow() doesn't route through _asResult"


def test_rm_r008_task_form_shows_the_servers_refusal():
    html = _page()
    sub = html.split("async function submitNewTask()", 1)[1].split("\n}", 1)[0]
    # success toast only on r.ok; otherwise the form's error line gets r.error
    assert re.search(r"if \(r\.ok\) \{\s*toast\('✅ Task '", sub)
    assert "errEl.textContent = r.error" in sub


def test_rm_r008_permissions_still_show_the_refusal_text():
    """After _asResult a ❌ arrives as ok:false — the revoke/grant else-branches
    must still show the server's reason (r.error), and put the toggle back."""
    html = _page()
    perm = html.split("async function onPerm(", 1)[1].split("\n}", 1)[0]
    assert "cb.checked = true" in perm and "r.error" in perm
    grant = html.split("async function confirmGrant()", 1)[1].split("\n}", 1)[0]
    assert "r.error" in grant

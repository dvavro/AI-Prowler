"""
R-071 (2026-10-08): Access-only folder listing.

Access-only folders (~/.rag_access_only_dirs.json) are READABLE but never
indexed: the read-path gate allows them without requiring tracking, writes
stay gated by the writable allowlist, and the hard blocklist still wins.

Covers:
    1. access_allowlist_save/load round-trip (+ missing/corrupt -> [])
    2. Read gate allows access-only paths without indexing
    3. Write gate still denies access-only paths (not in writable list)
    4. grant_write_access accepts access-only entries
    5. Hard blocklist overrides access-only (Windows-only)
    6. New-tool checklist: catalog entries, JOBS_APP_TOOLS, both /pwa-api
       allowlists (server _srv_pa_allowed + personal _allowed_tools)
    + grant_access / revoke_access tool behavior (validate dir, idempotent,
      revoke round-trip)

Run: run_tests.bat tests\\mcp_tests\\test_r071_access_only.py -v
"""
import ast
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_MCP_SRC = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ap():
    import ai_prowler_mcp as _ap
    _ap._prewarm_event.set()
    return _ap


@pytest.fixture(scope="module")
def cat():
    import mcp_tool_catalog as _c
    return _c


@pytest.fixture()
def acc(ap, tmp_path, monkeypatch):
    """ai_prowler_mcp with all home-dir state files redirected into tmp_path,
    the tracked read list stubbed empty, and telemetry silenced."""
    monkeypatch.setattr(ap, "_ACCESS_ONLY_DIRS_FILE",
                        tmp_path / ".rag_access_only_dirs.json")
    monkeypatch.setattr(ap, "_WRITABLE_DIRS_FILE",
                        tmp_path / ".rag_writable_dirs.json")
    monkeypatch.setattr(ap, "_WRITE_APPROVAL_QUEUE_FILE",
                        tmp_path / ".rag_writable_pending.json")
    monkeypatch.setattr(ap, "_telemetry_increment_tool_count",
                        lambda *a, **k: None)
    # _is_path_under_tracked_roots / _iter_allowlisted_files import
    # load_auto_update_list from rag_preprocessor at CALL time ...
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "load_auto_update_list", lambda: [])
    # ... while grant_write_access uses ai_prowler_mcp's module-level import.
    monkeypatch.setattr(ap, "load_auto_update_list", lambda: [])
    return ap


def _allow_list(var_name: str) -> set:
    """The string-set literal assigned to var_name inside ai_prowler_mcp.py."""
    for node in ast.walk(ast.parse(_MCP_SRC)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == var_name
                and isinstance(node.value, ast.Set)):
            return {e.value for e in node.value.elts
                    if isinstance(e, ast.Constant)}
    raise AssertionError(f"{var_name} set literal not found")


# ── 1. save/load round-trip ───────────────────────────────────────────────

def test_access_allowlist_save_load_round_trip(acc, tmp_path):
    dirs = [str(tmp_path / "docs"), str(tmp_path / "manuals")]
    assert acc.access_allowlist_save(dirs) is True
    assert acc.access_allowlist_load() == sorted(set(dirs))


def test_access_allowlist_load_missing_and_corrupt(acc, tmp_path):
    assert acc.access_allowlist_load() == []
    bad = tmp_path / ".rag_access_only_dirs.json"
    bad.write_text("not json{{{", encoding="utf-8")
    assert acc.access_allowlist_load() == []
    bad.write_text('{"a": 1}', encoding="utf-8")
    assert acc.access_allowlist_load() == []


# ── 2. read gate allows access-only paths without indexing ────────────────

def test_read_gate_allows_access_only_path(acc, tmp_path):
    ao = tmp_path / "access_only"
    ao.mkdir()
    target = ao / "notes.txt"
    target.write_text("hello", encoding="utf-8")

    assert acc.access_allowlist_save([str(ao)]) is True

    allowed, info = acc._is_path_under_tracked_roots(str(target))
    assert allowed is True, info
    assert Path(info).name == "notes.txt"

    # A path outside every list is still denied.
    allowed2, info2 = acc._is_path_under_tracked_roots(
        str(tmp_path / "elsewhere" / "x.txt"))
    assert allowed2 is False
    assert "access-only folder" in info2


# ── 3. write gate still denies access-only paths ──────────────────────────

def test_write_gate_denies_access_only_path(acc, tmp_path):
    ao = tmp_path / "ao_nowrite"
    ao.mkdir()
    target = ao / "f.txt"
    target.write_text("x", encoding="utf-8")

    assert acc.access_allowlist_save([str(ao)]) is True

    resolved, err = acc._resolve_writable_path(str(target), queue_approval=True)
    assert resolved is None
    assert err is not None
    # Denied at the WRITABLE-allowlist step (with GUI approval queued),
    # not at the read step: access-only must never imply write.
    assert "Write needs approval" in err


# ── 4. grant_write_access accepts access-only entries ─────────────────────

def test_grant_write_access_accepts_access_only(acc, tmp_path):
    ao = tmp_path / "ao_writable"
    ao.mkdir()
    assert acc.access_allowlist_save([str(ao)]) is True

    msg = acc.grant_write_access(str(ao))
    assert msg.startswith("✅"), msg
    assert str(ao.resolve()) in acc._writable_allowlist_load()

    # Idempotent — second grant is a no-op notice.
    msg2 = acc.grant_write_access(str(ao))
    assert "already in the write zone" in msg2


def test_grant_write_access_rejects_unlisted_path(acc, tmp_path):
    stranger = tmp_path / "stranger"
    stranger.mkdir()
    msg = acc.grant_write_access(str(stranger))
    assert "not in the read allowlist" in msg


# ── 5. hard blocklist overrides access-only ───────────────────────────────

@pytest.mark.skipif(sys.platform != "win32",
                    reason="hard blocklist paths are Windows-specific")
def test_blocklist_overrides_access_only(acc):
    ao = r"C:\Windows\Temp\ao_probe_r071"  # resolve(strict=False): need not exist
    assert acc.access_allowlist_save([ao]) is True

    allowed, info = acc._is_path_under_tracked_roots(ao + r"\file.txt")
    assert allowed is False
    assert "blocklist" in info.lower(), info


@pytest.mark.skipif(sys.platform != "win32",
                    reason="hard blocklist paths are Windows-specific")
def test_grep_enumeration_skips_blocklisted_access_only(acc):
    ao = r"C:\Windows\Temp\ao_probe_r071"
    assert acc.access_allowlist_save([ao]) is True
    assert list(acc._iter_allowlisted_files()) == []


def test_grep_enumeration_includes_access_only_files(acc, tmp_path):
    ao = tmp_path / "ao_grep"
    ao.mkdir()
    (ao / "matchme.txt").write_text("r071 unique needle xyz", encoding="utf-8")
    assert acc.access_allowlist_save([str(ao)]) is True

    seen = [fp for fp, _ext in acc._iter_allowlisted_files(filter_ext=".txt")]
    assert any(Path(fp).name == "matchme.txt" for fp in seen), seen


# ── 6. new-tool checklist ─────────────────────────────────────────────────

def test_catalog_entries(cat):
    for name in ("grant_access", "revoke_access"):
        assert name in cat.TOOL_CATALOG, name
        meta = cat.TOOL_CATALOG[name]
        assert meta.category == "file_code_tools"
        # 2026-10-09 (David): personal mode only — see test_access_only_server_blocked.py
        assert "personal" in cat.modes_of(name) and "server" not in cat.modes_of(name)
        assert meta.pwa_dependency  # the Remote Control PWA's Permissions screen uses it


def test_jobs_app_tools(cat):
    # 2026-10-09: the Jobs app never called these; the Remote PWA does.
    assert "grant_access" not in cat.JOBS_APP_TOOLS
    assert "revoke_access" not in cat.JOBS_APP_TOOLS


def test_pwa_api_allowlists_include_new_tools():
    # 2026-10-09: off both Jobs-app /pwa-api lists, on the Remote PWA's /remote-api.
    srv = _allow_list("_srv_pa_allowed")
    pers = _allow_list("_allowed_tools")
    remote = _allow_list("_REMOTE_ALLOWED")
    assert not ({"grant_access", "revoke_access"} & srv)
    assert not ({"grant_access", "revoke_access"} & pers)
    assert {"grant_access", "revoke_access"} <= remote


# ── grant_access / revoke_access tool behavior ────────────────────────────

def test_grant_access_tool_round_trip(acc, tmp_path):
    d = tmp_path / "grantme"
    d.mkdir()
    msg = acc.grant_access(str(d))
    assert msg.startswith("✅"), msg
    assert acc.access_allowlist_load() == [str(d.resolve())]

    # 2026-10-10 (David): a duplicate is refused (was an ℹ️ no-op) — list unchanged.
    msg2 = acc.grant_access(str(d))
    assert msg2.startswith("❌") and "already an access-only folder" in msg2, msg2
    assert acc.access_allowlist_load() == [str(d.resolve())]


def test_grant_access_rejects_missing_and_file(acc, tmp_path):
    msg = acc.grant_access(str(tmp_path / "does_not_exist"))
    assert msg.startswith("❌"), msg
    f = tmp_path / "afile.txt"
    f.write_text("x", encoding="utf-8")
    msg2 = acc.grant_access(str(f))
    assert msg2.startswith("❌"), msg2
    # 2026-10-10: folders only (always recursive) — a file says so
    assert "is a file" in msg2 and "folders only" in msg2, msg2


def test_revoke_access_tool_round_trip(acc, tmp_path):
    d = tmp_path / "revokeme"
    d.mkdir()
    assert acc.grant_access(str(d)).startswith("✅")
    msg = acc.revoke_access(str(d))
    assert msg.startswith("✅"), msg
    assert acc.access_allowlist_load() == []

    # Revoking something not listed is a no-op notice.
    msg2 = acc.revoke_access(str(d))
    assert "nothing to revoke" in msg2

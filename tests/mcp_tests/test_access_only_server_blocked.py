"""
Access-only folders are a PERSONAL-mode feature (David, 2026-10-09).

A server install must not be able to use them in any way:
    1. grant_access / revoke_access are Tier A suppressed — the MCP decorator
       never registers them when server_mode is on.
    2. Called anyway (e.g. as plain Python), both refuse on a server and the
       access-only list file is left untouched.
    3. A ~/.rag_access_only_dirs.json left on a server makes nothing readable:
       access_allowlist_load() is [] and the read gate denies those paths.
    4. list_tracked_directories shows no access-only section on a server.
    5. Neither Jobs-app /pwa-api allow-list offers them (server or personal);
       the Remote Control PWA's /remote-api does (the Remote app is personal-only).
    6. The tool catalog marks both personal-only.
Personal mode keeps working (see test_r071_access_only.py / test_grant_revoke_access.py).

Run: run_tests.bat tests\\mcp_tests\\test_access_only_server_blocked.py -v
"""
import ast
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_MCP_SRC = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
TOOLS = ("grant_access", "revoke_access")


@pytest.fixture(scope="module")
def ap():
    import ai_prowler_mcp as _ap
    _ap._prewarm_event.set()
    return _ap


@pytest.fixture()
def acc(ap, tmp_path, monkeypatch):
    monkeypatch.setattr(ap, "_ACCESS_ONLY_DIRS_FILE", tmp_path / ".rag_access_only_dirs.json")
    monkeypatch.setattr(ap, "_WRITABLE_DIRS_FILE", tmp_path / ".rag_writable_dirs.json")
    monkeypatch.setattr(ap, "_telemetry_increment_tool_count", lambda *a, **k: None)
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "load_auto_update_list", lambda: [])
    monkeypatch.setattr(ap, "load_auto_update_list", lambda: [])
    return ap


@pytest.fixture()
def server(acc, monkeypatch):
    monkeypatch.setattr(acc, "_IS_SERVER_MODE", True)
    return acc


def _set_literal(var_name: str) -> set:
    for node in ast.walk(ast.parse(_MCP_SRC)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == var_name and isinstance(node.value, ast.Set)):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    raise AssertionError(f"{var_name} set literal not found")


# ── 1. never registered on a server ─────────────────────────────────────────
def test_tier_a_lists_both_tools(ap):
    for t in TOOLS:
        assert t in ap._TIER_A_SUPPRESSED, t


@pytest.mark.parametrize("tool", TOOLS)
def test_decorator_skips_registration_in_server_mode(ap, monkeypatch, tool):
    registered = []

    def spy(*a, **k):
        def deco(fn):
            registered.append(fn.__name__)
            return fn
        return deco

    monkeypatch.setattr(ap, "_orig_mcp_tool", spy)
    monkeypatch.setattr(ap, "_IS_SERVER_MODE", True)

    def _fn(directory: str) -> str:
        return "ran"
    _fn.__name__ = tool
    ap._counting_mcp_tool()(_fn)
    assert tool not in registered, f"{tool} was registered with MCP in server mode"


# ── 2. refuses when called on a server; the list file is untouched ──────────
def test_grant_access_refused_on_server(server, tmp_path):
    d = tmp_path / "share"
    d.mkdir()
    msg = server.grant_access(str(d))
    assert msg.startswith("❌") and "personal-mode feature" in msg, msg
    assert not server._ACCESS_ONLY_DIRS_FILE.exists(), "grant_access wrote the list on a server"


def test_revoke_access_refused_on_server(server, tmp_path):
    d = tmp_path / "share"
    d.mkdir()
    server._ACCESS_ONLY_DIRS_FILE.write_text(json.dumps([str(d.resolve())]), encoding="utf-8")
    before = server._ACCESS_ONLY_DIRS_FILE.read_text(encoding="utf-8")
    msg = server.revoke_access(str(d))
    assert msg.startswith("❌") and "personal-mode feature" in msg, msg
    assert server._ACCESS_ONLY_DIRS_FILE.read_text(encoding="utf-8") == before


# ── 3. a stray list file grants nothing on a server ──────────────────────────
def test_stray_list_file_makes_nothing_readable_on_server(server, tmp_path):
    d = tmp_path / "secret"
    d.mkdir()
    (d / "notes.txt").write_text("x", encoding="utf-8")
    server._ACCESS_ONLY_DIRS_FILE.write_text(json.dumps([str(d.resolve())]), encoding="utf-8")
    assert server.access_allowlist_load() == []
    ok, why = server._is_path_under_tracked_roots(str(d / "notes.txt"))
    assert not ok, f"server read an access-only path: {why}"


def test_same_file_is_readable_in_personal_mode(acc, tmp_path):
    d = tmp_path / "secret"
    d.mkdir()
    (d / "notes.txt").write_text("x", encoding="utf-8")
    acc._ACCESS_ONLY_DIRS_FILE.write_text(json.dumps([str(d.resolve())]), encoding="utf-8")
    ok, _ = acc._is_path_under_tracked_roots(str(d / "notes.txt"))
    assert ok, "personal mode lost access-only reads"


def test_denial_message_does_not_suggest_grant_access_on_server(server, tmp_path, monkeypatch):
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "load_auto_update_list", lambda: [str(tmp_path / "tracked")])
    _p, err = server._resolve_allowlisted_path(str(tmp_path / "elsewhere" / "f.txt"))
    assert err and "grant_access" not in err, err


# ── 4. no access-only section in list_tracked_directories ────────────────────
def test_list_tracked_directories_has_no_access_only_section_on_server(server):
    out = server.list_tracked_directories(None)
    assert "Access-only" not in out and "grant_access" not in out, out


def test_list_tracked_directories_keeps_section_in_personal_mode(acc):
    out = acc.list_tracked_directories(None)
    assert "Access-only folders" in out, out


def test_list_tracked_directories_server_description_never_mentions_access_only(ap):
    """2026-10-10 (David: "the server should not offer any access-only tools"):
    on a server the tool registers with a description that never mentions them."""
    d = ap._LTD_SERVER_DESCRIPTION.lower()
    assert "access" not in d and "grant_access" not in d, ap._LTD_SERVER_DESCRIPTION
    assert "@mcp.tool(description=_LTD_SERVER_DESCRIPTION if _IS_SERVER_MODE else None)\n" \
           "def list_tracked_directories(" in _MCP_SRC


@pytest.mark.parametrize("server_mode", [False, True])
def test_list_tracked_directories_registered_description(ap, monkeypatch, server_mode):
    """Run the real registration path (with a spy for FastMCP's decorator):
    a server registers the server text, a personal install the docstring."""
    seen = {}

    def spy(*a, **k):
        def deco(fn):
            seen.update(k)
            return fn
        return deco
    monkeypatch.setattr(ap, "_orig_mcp_tool", spy)
    monkeypatch.setattr(ap, "_IS_SERVER_MODE", server_mode)
    desc = ap._LTD_SERVER_DESCRIPTION if server_mode else None

    def list_tracked_directories(ctx=None):
        """List … PLUS the access-only folders."""
    ap._counting_mcp_tool(description=desc)(list_tracked_directories)
    if server_mode:
        assert "access" not in (seen.get("description") or "").lower(), seen
    else:
        assert seen.get("description") is None, seen     # the docstring is used


# ── 5. allow-lists ───────────────────────────────────────────────────────────
def test_not_offered_to_the_jobs_app():
    for var in ("_srv_pa_allowed", "_allowed_tools"):
        lst = _set_literal(var)
        assert not (set(TOOLS) & lst), f"{var} still offers {set(TOOLS) & lst}"


def test_offered_to_the_remote_control_pwa():
    assert set(TOOLS) <= _set_literal("_REMOTE_ALLOWED")


# ── 6b. how_to_use_ai_prowler describes them as personal-only ───────────────
def test_how_to_use_describes_access_only_as_personal_only(acc):
    body = acc.how_to_use_ai_prowler(None)
    i = body.find("Access-only folders (personal mode only")
    assert i != -1, "how_to_use_ai_prowler has no personal-only Access-only folders section"
    section = body[i:i + 2400]          # 2026-10-10: the section grew (add rules)
    for t in ("grant_access(directory)", "revoke_access(directory)", "READ", "WITHOUT indexing",
              "Remote Control app (Perms tab)"):
        assert t in section, f"{t!r} missing from the section:\n{section}"
    assert "C:\\Manuals" in section and "C:\\\\Manuals" not in section, section


def test_guide_has_the_decision_rule(acc):
    """2026-10-11 (David): so Claude isn't confused across connectors — decide
    by the connector's TOOLS; a server has none, offer index_path; with both
    attached, use the personal one."""
    body = acc.how_to_use_ai_prowler(None)
    i = body.find("DECISION RULE")
    assert i != -1, "no decision rule in the guide"
    rule = " ".join(body[i:i + 900].split())
    for t in ("decide by the connector's TOOLS", "only on a connector that actually lists them",
              "it's an AI-Prowler SERVER", "offer to index the folder instead (index_path)",
              "always goes to the personal one", "never report it unavailable"):
        assert t in rule, f"{t!r} missing from: {rule}"


def test_guide_body_identical_in_both_modes(ap, monkeypatch):
    """The main guide must not vary per connector (only the computed THIS
    CONNECTION footer does) — the access-only section included."""
    monkeypatch.setattr(ap, "_IS_SERVER_MODE", False)
    personal = ap._ACCESS_ONLY_GUIDE
    monkeypatch.setattr(ap, "_IS_SERVER_MODE", True)
    assert ap._ACCESS_ONLY_GUIDE == personal
    src = _MCP_SRC
    assert "+ _ACCESS_ONLY_GUIDE +" in src and '("" if _IS_SERVER_MODE else _ACCESS_ONLY_GUIDE)' not in src


def test_server_footer_says_not_available():
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert 'footer_lines.append("Access-only folders (grant_access, revoke_access):")' in src
    i = src.index('footer_lines.append("Access-only folders (grant_access, revoke_access):")')
    footer = src[i:i + 900]
    # 2026-10-11: same rule as the guide — not on THIS connector, offer
    # index_path, and use a personal connector's grant_access if one is attached
    for t in ("Not available on THIS connector (an AI-Prowler server)",
              "Offer instead: index the folder (index_path)",
              "If a PERSONAL AI-Prowler connector is also attached",
              "don't call it unavailable"):
        assert t in footer, f"{t!r} missing from the server footer"


# ── 7. Remote Files tab: upload / download in access-only folders (2026-10-10) ─
def test_upload_should_index_rules(acc, tmp_path, monkeypatch):
    tracked, ao, other = tmp_path / "tracked", tmp_path / "ao", tmp_path / "other"
    for d in (tracked / "sub", ao / "sub", other, tracked / "ao_inside"):
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(acc, "load_auto_update_list", lambda: [str(tracked)])
    acc._ACCESS_ONLY_DIRS_FILE.write_text(
        json.dumps([str(ao).replace("\\", "/"), str(tracked / "ao_inside")]), encoding="utf-8")
    assert acc._upload_should_index(str(tracked)) is True               # an indexed folder
    assert acc._upload_should_index(str(tracked / "sub")) is True       # inside one
    assert acc._upload_should_index(str(ao)) is False                   # access-only: saved, not indexed
    assert acc._upload_should_index(str(ao / "sub")) is False           # inside one (stored with '/')
    assert acc._upload_should_index(str(tracked / "ao_inside")) is True  # access-only INSIDE tracked → tracked wins
    assert acc._upload_should_index(str(other)) is True                 # neither: unchanged old behaviour
    assert acc._upload_should_index(str(tmp_path / "aox")) is True      # a sibling that only starts with "ao"


def test_upload_should_index_on_server_ignores_any_access_only_list(server, tmp_path, monkeypatch):
    ao = tmp_path / "ao"
    ao.mkdir()
    monkeypatch.setattr(server, "load_auto_update_list", lambda: [])
    server._ACCESS_ONLY_DIRS_FILE.write_text(json.dumps([str(ao)]), encoding="utf-8")
    assert server._upload_should_index(str(ao)) is True     # no access-only folders on a server


def test_remote_download_and_upload_handlers():
    src = _MCP_SRC
    i = src.index('if path == "/remote/download":')
    dl = src[i:i + 6000]
    assert "_readable += list(access_allowlist_load()" in dl, "download must allow access-only folders"
    assert "_path_is_inside(_abs_dl" in dl, "download must use a folder-boundary check, not a text prefix"
    j = src.index('if path == "/remote/upload":')
    up = src[j:j + 7000]
    assert "_up_index = _upload_should_index(_up_dir_abs)" in up
    assert '"indexed": bool(_up_index)' in up
    assert "if not _up_index:" in up


# ── 6. catalog ──────────────────────────────────────────────────────────────
def test_catalog_marks_both_personal_only():
    import mcp_tool_catalog as cat
    for t in TOOLS:
        assert cat.modes_of(t) == frozenset({"personal"}) or set(cat.modes_of(t)) == {"personal"}, \
            (t, cat.modes_of(t))
        assert t not in cat.JOBS_APP_TOOLS

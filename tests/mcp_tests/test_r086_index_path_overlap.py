"""
R-086 (2026-10-09): Claude's index_path must surface the R-070 overlap warning.

R-070 warns when a newly indexed folder sits INSIDE an already-tracked folder,
or CONTAINS one (tracked folders are scanned recursively, so the files would
be indexed twice). The desktop shows it as a popup and red rows; index_path —
the only way in on a server — lost it: index_directory added the path itself,
so index_path's own add_to_auto_update_list() call answered "already tracked"
and the reply said "Directory was already in the tracking list" with no warning.

Every case runs in PERSONAL mode and in SERVER mode (as owner, manager and
field crew — indexing is open to every role there).

    1. subfolder of a tracked folder  -> warning "is inside already-indexed",
                                         reply says "added", the path IS tracked
    2. parent of a tracked folder     -> warning "contains already-indexed"
    3. unrelated folder               -> no warning, "added"
    4. the same folder again          -> "already in the tracking list", no warning
    5. a single FILE inside a tracked folder -> warning
    6. index_directory prints the warning instead of treating it as success
    7. tracked_path_overlap() itself

Run: run_tests.bat tests\\mcp_tests\\test_r086_index_path_overlap.py -v
"""
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

MODES = [
    pytest.param(None, id="personal"),
    pytest.param({"id": "u-owner", "name": "ZT Owner", "role": "owner"}, id="server-owner"),
    pytest.param({"id": "u-mgr", "name": "ZT Manager", "role": "manager"}, id="server-manager"),
    pytest.param({"id": "u-crew", "name": "ZT Crew", "role": "field_crew"}, id="server-field_crew"),
]


@pytest.fixture()
def rag(tmp_path, monkeypatch):
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "AUTO_UPDATE_LIST", tmp_path / "auto_update_dirs.json")
    monkeypatch.setattr(_rag, "generate_auto_update_script", lambda: None)
    return _rag


@pytest.fixture()
def mcp(rag, monkeypatch, request):
    """ai_prowler_mcp with indexing faked: the fake index_directory does what
    the real one does to the tracked list (adds the folder, prints a warning
    string) without loading any model or touching ChromaDB."""
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    user = request.param
    monkeypatch.setattr(ap, "_IS_SERVER_MODE", user is not None)
    monkeypatch.setattr(ap, "_current_user", lambda ctx: user)
    monkeypatch.setattr(ap, "_owner_user_id", lambda: "u-owner")
    monkeypatch.setattr(ap, "load_config", lambda: None)
    monkeypatch.setattr(ap, "_db_write", lambda fn, timeout=None: fn())

    def fake_index_directory(directory, recursive=True, track=True, **kw):
        print(f"indexed {directory}")
        if track:
            res = rag.add_to_auto_update_list(directory)
            if isinstance(res, str):
                print(f"⚠️  {res}")

    def fake_index_file_list(paths, **kw):
        return {"chunks": 1}

    monkeypatch.setattr(ap, "index_directory", fake_index_directory)
    monkeypatch.setattr(rag, "index_file_list", fake_index_file_list)
    ap._mode_label = "personal" if user is None else f"server/{user['role']}"
    return ap


def _tracked(rag):
    return rag.load_auto_update_list()


def _norm(rag, p):
    return rag.normalise_path(str(Path(p).resolve()))


@pytest.fixture()
def tree(tmp_path):
    root = tmp_path / "r086"
    for p in ("Docs/Sub", "Other"):
        (root / p).mkdir(parents=True)
    (root / "Docs" / "Sub" / "note.txt").write_text("x", encoding="utf-8")
    return root


# ── 1. subfolder ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mcp", MODES, indirect=True)
def test_subfolder_of_tracked_folder_warns(mcp, rag, tree):
    assert rag.add_to_auto_update_list(str(tree / "Docs")) is True
    out = mcp.index_path(str(tree / "Docs" / "Sub"))
    assert "is inside already-indexed" in out, f"[{mcp._mode_label}] no overlap warning:\n{out}"
    assert "added to auto-update tracking" in out, out
    assert "already in the tracking list" not in out, f"[{mcp._mode_label}] misleading note:\n{out}"
    assert out.count("is inside already-indexed") == 1, f"warning shown twice:\n{out}"
    assert _norm(rag, tree / "Docs" / "Sub") in _tracked(rag), "warning must not block"


# ── 2. parent ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mcp", MODES, indirect=True)
def test_parent_of_tracked_folder_warns(mcp, rag, tree):
    assert rag.add_to_auto_update_list(str(tree / "Docs" / "Sub")) is True
    out = mcp.index_path(str(tree / "Docs"))
    assert "contains already-indexed" in out, f"[{mcp._mode_label}] no overlap warning:\n{out}"
    assert "untrack_directory" in out, out


# ── 3. unrelated ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mcp", MODES, indirect=True)
def test_unrelated_folder_no_warning(mcp, rag, tree):
    assert rag.add_to_auto_update_list(str(tree / "Docs")) is True
    out = mcp.index_path(str(tree / "Other"))
    assert "Warning" not in out and "already-indexed" not in out, out
    assert "added to auto-update tracking" in out, out


# ── 4. same folder again ─────────────────────────────────────────────────────
@pytest.mark.parametrize("mcp", MODES, indirect=True)
def test_reindex_same_folder_says_already_tracked(mcp, rag, tree):
    assert rag.add_to_auto_update_list(str(tree / "Docs")) is True
    out = mcp.index_path(str(tree / "Docs"))
    assert "already in the tracking list" in out, out
    assert "already-indexed" not in out, out


# ── 5. single file inside a tracked folder ───────────────────────────────────
@pytest.mark.parametrize("mcp", MODES, indirect=True)
def test_file_inside_tracked_folder_warns(mcp, rag, tree):
    assert rag.add_to_auto_update_list(str(tree / "Docs")) is True
    out = mcp.index_path(str(tree / "Docs" / "Sub" / "note.txt"))
    assert "is inside already-indexed" in out, f"[{mcp._mode_label}]\n{out}"
    assert "File added to auto-update tracking" in out, out


# ── 6. index_directory prints the warning ────────────────────────────────────
def test_index_directory_prints_warning_strings():
    src = (_SRC / "rag_preprocessor.py").read_text(encoding="utf-8")
    i = src.index("is_new = add_to_auto_update_list(directory)")
    assert "isinstance(is_new, str)" in src[i:i + 600], \
        "index_directory must print a warning string, not treat it as plain success"


# ── 7. the helper ────────────────────────────────────────────────────────────
def test_tracked_path_overlap(rag, tree):
    rag.add_to_auto_update_list(str(tree / "Docs"))
    assert "is inside already-indexed" in rag.tracked_path_overlap(str(tree / "Docs" / "Sub"))
    assert "contains already-indexed" in rag.tracked_path_overlap(str(tree))
    assert rag.tracked_path_overlap(str(tree / "Other")) is None
    assert rag.tracked_path_overlap(str(tree / "Docs")) is None          # exact = "already tracked"
    if sys.platform == "win32":
        assert "is inside already-indexed" in rag.tracked_path_overlap(
            str(tree).upper() + "\\DOCS\\SUB")

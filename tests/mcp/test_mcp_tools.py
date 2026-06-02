"""
MCP-tool tests (Section G-MCP-* of the test plan)
==================================================

These tests call the @mcp.tool()-decorated functions from ai_prowler_mcp
directly as Python callables. The decorator only registers them with the
FastMCP dispatcher — the underlying functions are ordinary Python and
behave identically whether invoked over JSON-RPC or in-process.

What we DO test:
  • Argument validation (non-existent paths, missing args)
  • Code-path branching (file vs directory, with/without `track`,
    with/without `directory` argument)
  • Cross-state consistency (MCP write → MCP read sees the change;
    rag_preprocessor write → MCP read sees the change)
  • Output formatting (the human-readable strings, since that's what
    users actually see)

What we DON'T test here:
  • JSON-RPC wire encoding — that's the MCP SDK's responsibility
  • Stdio transport — same
  • Tool registration / discovery — also SDK
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Path helpers
#
# Path comparison across the test boundary is annoyingly subtle:
#   • normalise_path() in rag_preprocessor returns forward slashes
#   • add_to_auto_update_list() stores paths AS-PASSED, which on Windows
#     means whatever os.path.abspath / Path.resolve produced (backslashes)
#   • So the auto-update list can hold backslash paths that don't string-
#     compare equal to normalise_path() output, even though they refer to
#     the same file.
#
# The pragmatic fix: compare paths via os.path.normcase + os.path.abspath,
# which on Windows lowercases AND normalises separators, and on POSIX is
# essentially identity. (Note in your code base this is also a real but
# minor inconsistency worth flagging — store paths consistently, either
# always normalised or always native, not "depends which function called it".)
# ──────────────────────────────────────────────────────────────────────────────
def _canon(path: str) -> str:
    """Canonicalise a path for cross-platform comparison."""
    return os.path.normcase(os.path.abspath(path))


def _path_in_list(path: str, path_list: list) -> bool:
    """True iff `path` is present in `path_list` regardless of separator/case."""
    target = _canon(path)
    return any(_canon(p) == target for p in path_list)


def _path_in_text(path: str, text: str) -> bool:
    """True iff `path` appears in `text` (e.g. tool output) regardless of
    separator. We try both the forward-slash and backslash forms because
    text output isn't normalised at all."""
    p = str(Path(path).resolve())
    return p in text or p.replace("\\", "/") in text or p.replace("/", "\\") in text


# ──────────────────────────────────────────────────────────────────────────────
# G-MCP-01 — directory mode: add, index, track in one call
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_MCP_01_index_path_directory(mcp_env, sample_files):
    """index_path on a folder: indexes every supported file,
    adds the folder to the auto-update list, and returns a non-empty
    human-readable summary."""
    folder = mcp_env.sample_root

    output = mcp_env.mcp.index_path(
        directory=str(folder), recursive=True, track=True)

    assert isinstance(output, str)
    assert output.strip(), "Tool returned an empty string"
    # Either of two acceptable phrasings depending on whether the folder was
    # already in the list (it shouldn't be in a fresh test, but be tolerant).
    assert ("added to auto-update tracking" in output.lower()
            or "already in the tracking list" in output.lower()), (
        f"Output should mention tracking status. Got: {output!r}"
    )

    # The folder should now be in the auto-update list (path comparison is
    # separator-agnostic — see _path_in_list helper above)
    auto_update = json.loads(mcp_env.auto_update.read_text(encoding="utf-8"))
    assert _path_in_list(str(folder.resolve()), auto_update["directories"]), (
        f"Folder not added to auto-update list. List: {auto_update['directories']}"
    )

    # ChromaDB has chunks for at least one of the sample files
    client, ef = mcp_env.rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=mcp_env.rag.COLLECTION_NAME, embedding_function=ef)
    assert coll.count() > 0


# ──────────────────────────────────────────────────────────────────────────────
# G-MCP-02 — single-file path mode (different code path than directory)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_MCP_02_index_path_single_file(mcp_env, small_text_file):
    """When given a file path instead of a directory, the tool should route
    to index_file_list (not index_directory) and add the file (not its
    parent) to the auto-update list."""
    output = mcp_env.mcp.index_path(
        directory=str(small_text_file), recursive=True, track=True)

    assert isinstance(output, str) and output.strip()
    assert "file" in output.lower(), (
        f"Output for single-file should mention 'file'. Got: {output!r}"
    )

    # The file itself (not the parent dir) should be tracked
    auto_update = json.loads(mcp_env.auto_update.read_text(encoding="utf-8"))
    assert _path_in_list(str(small_text_file.resolve()),
                         auto_update["directories"]), (
        f"File path not added to auto-update list. Got: {auto_update['directories']}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# G-MCP-03 — update_tracked_directories: scoped vs unscoped
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_MCP_03a_update_all_tracked(mcp_env, sample_files):
    """update_tracked_directories() with no argument: iterates every entry
    in the auto-update list. We confirm by tracking two folders and
    observing both are visited (output mentions both paths)."""
    from tests.helpers import sample_files as builders

    folder_a = mcp_env.sample_root / "alpha"
    folder_b = mcp_env.sample_root / "bravo"
    builders.make_txt(folder_a / "a.txt", "alpha " * 30)
    builders.make_txt(folder_b / "b.txt", "bravo " * 30)

    mcp_env.mcp.index_path(str(folder_a), recursive=True, track=True)
    mcp_env.mcp.index_path(str(folder_b), recursive=True, track=True)

    output = mcp_env.mcp.update_tracked_directories()

    assert isinstance(output, str)
    # Both folder names should appear somewhere in the captured output
    # (could be in scan reports, no-change messages, etc.)
    assert "alpha" in output.lower() and "bravo" in output.lower(), (
        f"update_tracked_directories() should visit both folders. Output: {output!r}"
    )


@pytest.mark.slow
def test_G_MCP_03b_update_specific_directory(mcp_env, sample_files):
    """update_tracked_directories(directory=...) updates only that one path,
    even if other paths are also tracked."""
    from tests.helpers import sample_files as builders

    folder_a = mcp_env.sample_root / "alpha"
    folder_b = mcp_env.sample_root / "bravo"
    builders.make_txt(folder_a / "a.txt", "alpha " * 30)
    builders.make_txt(folder_b / "b.txt", "bravo " * 30)

    mcp_env.mcp.index_path(str(folder_a), recursive=True, track=True)
    mcp_env.mcp.index_path(str(folder_b), recursive=True, track=True)

    output = mcp_env.mcp.update_tracked_directories(directory=str(folder_a))

    assert isinstance(output, str) and output.strip()
    assert "alpha" in output.lower(), (
        f"Scoped update should mention the targeted folder. Got: {output!r}"
    )
    # And it should NOT mention bravo (we only asked for alpha)
    assert "bravo" not in output.lower(), (
        f"Scoped update wrongly visited the other folder. Got: {output!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# G-MCP-04 — get_database_stats reflects ChromaDB reality
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_MCP_04_get_database_stats(mcp_env, sample_files):
    """After indexing, stats output should report the right total chunks,
    the right unique-document count, and the database path the test fixture
    redirected to."""
    folder = mcp_env.sample_root
    mcp_env.mcp.index_path(str(folder), recursive=True, track=False)

    stats = mcp_env.mcp.get_database_stats()

    assert isinstance(stats, str)
    assert "Total chunks" in stats
    assert "Unique documents" in stats
    assert "Database path" in stats

    # Verify against the source of truth — the actual ChromaDB
    client, ef = mcp_env.rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=mcp_env.rag.COLLECTION_NAME, embedding_function=ef)
    chroma_count = coll.count()

    # Extract the chunk number from the stats output
    import re
    m = re.search(r"Total chunks\s*:\s*([\d,]+)", stats)
    assert m, f"Couldn't parse chunk count from stats: {stats!r}"
    reported = int(m.group(1).replace(",", ""))
    assert reported == chroma_count, (
        f"Stats says {reported} chunks but ChromaDB says {chroma_count}"
    )


def test_G_MCP_04b_stats_on_empty_database(mcp_env):
    """Stats on a fresh, empty database should return a friendly message,
    not a stack trace or numeric output."""
    stats = mcp_env.mcp.get_database_stats()
    assert isinstance(stats, str)
    assert "empty" in stats.lower(), (
        f"Empty-database stats should say so. Got: {stats!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# G-MCP-05 — list_tracked_directories: icons + missing paths
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_MCP_05_list_tracked_with_icons(mcp_env, small_text_file):
    """list_tracked_directories should annotate each entry with an icon:
       📁 for existing directories
       📄 for individually-tracked files
       ❓ for paths that no longer exist on disk
    """
    from tests.helpers import sample_files as builders

    folder = mcp_env.sample_root / "tracked_folder"
    builders.make_txt(folder / "x.txt", "x " * 30)

    file_path = small_text_file
    missing_path = mcp_env.sample_root / "deleted_folder"
    builders.make_txt(missing_path / "ghost.txt", "ghost " * 30)

    # Track all three
    mcp_env.mcp.index_path(str(folder), recursive=True, track=True)
    mcp_env.mcp.index_path(str(file_path), recursive=True, track=True)
    mcp_env.mcp.index_path(str(missing_path), recursive=True, track=True)

    # Now delete the third one from disk to test the missing-path icon
    import shutil
    shutil.rmtree(str(missing_path))

    output = mcp_env.mcp.list_tracked_directories()

    assert isinstance(output, str)
    # Folder icon for the surviving directory
    assert "📁" in output, f"Should show 📁 for directory. Output: {output!r}"
    # File icon for the individually-tracked file
    assert "📄" in output, f"Should show 📄 for tracked file. Output: {output!r}"
    # Question-mark icon for the path that no longer exists
    assert "❓" in output, f"Should show ❓ for missing path. Output: {output!r}"


def test_G_MCP_05b_list_when_nothing_tracked(mcp_env):
    """When no paths are tracked, list_tracked_directories should return a
    helpful message that suggests the next step."""
    output = mcp_env.mcp.list_tracked_directories()
    assert isinstance(output, str)
    assert "no paths" in output.lower() or "no directories" in output.lower(), (
        f"Empty-list output should be informative. Got: {output!r}"
    )
    # The message should mention index_path as the next step
    assert "index_path" in output, (
        f"Empty-list message should reference the indexing tool. Got: {output!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# G-MCP-06 — untrack_directory output reports correct counts
#
# This was the test that was blocked by Bug B-03 in the original review. With
# B-03 fixed, the underlying remove_directory_from_index() now returns a
# files_removed count, and the MCP wrapper passes it through. We verify the
# wrapper is reading the right key.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_MCP_06_untrack_directory_reports_real_counts(mcp_env):
    """After indexing 3 files in a directory then calling untrack_directory,
    the human-readable output should mention 3 files (not 'unknown' or '1')."""
    from tests.helpers import sample_files as builders

    folder = mcp_env.sample_root / "to_remove"
    n_files = 3
    for i in range(n_files):
        builders.make_txt(folder / f"f{i}.txt", f"content {i} " * 30)

    mcp_env.mcp.index_path(str(folder), recursive=True, track=True)

    output = mcp_env.mcp.untrack_directory(directory=str(folder))

    assert isinstance(output, str) and output.strip()
    assert "unknown" not in output.lower(), (
        "untrack_directory output still says 'unknown' — B-03 regression. "
        f"Got: {output!r}"
    )
    # The file count should appear as a real number, and it should match n_files
    import re
    m = re.search(r"from\s+(\d+)\s+file", output, re.IGNORECASE)
    assert m, f"Couldn't find 'from N file(s)' in output: {output!r}"
    reported_files = int(m.group(1))
    assert reported_files == n_files, (
        f"Expected files removed = {n_files}, output says {reported_files}. "
        f"Full output: {output!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# G-MCP-07 — error handling for non-existent paths
# ──────────────────────────────────────────────────────────────────────────────
def test_G_MCP_07a_index_nonexistent_path(mcp_env):
    """index_path on a path that doesn't exist returns a
    well-formed error string — never crashes, never mutates state."""
    fake = mcp_env.sample_root / "this_definitely_does_not_exist"
    output = mcp_env.mcp.index_path(directory=str(fake))

    assert isinstance(output, str)
    assert "not found" in output.lower() or "❌" in output, (
        f"Should report path-not-found. Got: {output!r}"
    )

    # No state mutation
    auto_update = json.loads(mcp_env.auto_update.read_text(encoding="utf-8"))
    assert auto_update["directories"] == [], (
        f"Failed indexing should not mutate auto-update list. Got: {auto_update}"
    )


def test_G_MCP_07b_untrack_nonexistent_path(mcp_env):
    """untrack_directory on a path that was never indexed returns gracefully."""
    fake = mcp_env.sample_root / "never_indexed"
    output = mcp_env.mcp.untrack_directory(directory=str(fake))
    assert isinstance(output, str)
    # Should produce SOME output, no exception leak
    assert output.strip()


# ──────────────────────────────────────────────────────────────────────────────
# G-CRO-01 — Cross-component consistency
#
# Whatever rag_preprocessor reads, MCP reads. Whatever MCP writes,
# rag_preprocessor sees. (This is a structural test — proves the two layers
# share the same on-disk state, which is what we'd want for the GUI and the
# scheduled batch script to see consistent data.)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_CRO_01_rag_writes_visible_to_mcp(mcp_env, sample_files):
    """Index via rag_preprocessor directly. MCP's get_database_stats and
    list_tracked_directories should immediately see the new state."""
    folder = mcp_env.sample_root
    files = [mcp_env.rag.normalise_path(str(p)) for p in sample_files.values()]

    # Direct call to the engine — bypass MCP entirely
    mcp_env.rag.index_file_list(files, label="cross-test", root_directory=str(folder))
    mcp_env.rag.add_to_auto_update_list(str(folder.resolve()))

    # Now ask MCP — it should see what we just wrote
    list_out = mcp_env.mcp.list_tracked_directories()
    assert _path_in_text(str(folder.resolve()), list_out), (
        f"MCP doesn't see the folder rag_preprocessor just tracked. Output: {list_out!r}"
    )

    stats_out = mcp_env.mcp.get_database_stats()
    assert "Total chunks" in stats_out
    assert "empty" not in stats_out.lower()

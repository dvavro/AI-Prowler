"""
Functional tests — Remove / untrack workflow

Covers remove_directory_from_index across both code paths (per-file fast
path, and full-directory scan path), plus the two bugs in this area:

  • B-03: return dict missing the 'files_removed' key
  • B-08: directory branch always reports files_removed == 1 regardless of
          how many files were actually removed
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# F-UPD-05 — full directory removal: chunks, tracking, auto-update list all clean
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_UPD_05_remove_directory_full_cleanup(isolated_env):
    """Track and index a folder, call remove_directory_from_index → chunks
    gone from ChromaDB, tracking DB entry gone, auto-update list entry gone."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "to_remove"
    files = [
        builders.make_txt(folder / f"file{i}.txt", f"content {i} " * 30)
        for i in range(5)
    ]

    rag.add_to_auto_update_list(str(folder))
    rag.index_file_list(
        [rag.normalise_path(str(p)) for p in files],
        label="initial",
        root_directory=str(folder),
    )

    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    assert coll.count() > 0, "Pre-condition: chunks should exist in ChromaDB"

    result = rag.remove_directory_from_index(str(folder))

    # ChromaDB chunks gone
    coll = client.get_or_create_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    surviving = coll.get(
        where={"filepath": {"$in": [rag.normalise_path(str(p)) for p in files]}},
        include=["metadatas"],
    )
    assert not surviving.get("ids"), "Chunks survived directory removal"

    # Tracking DB stripped
    import json
    tracking = json.loads(isolated_env.tracking_db.read_text(encoding="utf-8"))
    folder_key = rag.normalise_path(str(folder.resolve()))
    assert folder_key not in tracking, (
        f"Tracking DB still has entry for removed folder: keys={list(tracking)}"
    )

    # Auto-update list stripped
    auto = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    assert folder_key not in auto["directories"], (
        f"Auto-update list still has removed folder: {auto['directories']}"
    )

    # Result dict structure
    assert "chunks_removed" in result
    assert result["chunks_removed"] > 0
    assert "errors" in result


# ──────────────────────────────────────────────────────────────────────────────
# F-UPD-06 — single-file removal
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_UPD_06_remove_individual_file(isolated_env):
    """Track and index a single file, then remove it → fast path runs,
    chunks for that file are gone, but other files in the same parent dir
    are untouched."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "mixed_removal"
    target = builders.make_txt(folder / "to_remove.txt", "delete me " * 30)
    bystander = builders.make_txt(folder / "stays.txt", "i remain " * 30)

    rag.index_file_list(
        [rag.normalise_path(str(target)), rag.normalise_path(str(bystander))],
        label="initial",
        root_directory=str(folder),
    )

    result = rag.remove_directory_from_index(str(target))

    assert result["chunks_removed"] > 0

    # Bystander chunks must survive
    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    surviving = coll.get(where={"filepath": rag.normalise_path(str(bystander))},
                         include=["metadatas"])
    assert surviving.get("ids"), "Bystander chunks were wrongly removed"

    # Target chunks gone
    target_remaining = coll.get(where={"filepath": rag.normalise_path(str(target))},
                                include=["metadatas"])
    assert not target_remaining.get("ids"), "Target file's chunks survived removal"


# ──────────────────────────────────────────────────────────────────────────────
# Bug B-03: remove_directory_from_index now returns 'files_removed'   [FIXED]
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_B_03_remove_returns_files_removed_key(isolated_env):
    """The return dict must include the documented 'files_removed' key so the
    MCP tool can report it accurately (was previously always 'unknown')."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "files_removed_test"
    files = [
        builders.make_txt(folder / f"f{i}.txt", f"text {i} " * 30)
        for i in range(3)
    ]

    rag.index_file_list(
        [rag.normalise_path(str(p)) for p in files],
        label="initial",
        root_directory=str(folder),
    )

    result = rag.remove_directory_from_index(str(folder))

    assert "files_removed" in result, (
        "Bug B-03: return dict is missing 'files_removed' key. "
        f"Returned keys: {list(result.keys())}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Bug B-08: directory branch now reports the correct files_removed count   [FIXED]
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_B_08_directory_files_removed_counter_correct(isolated_env):
    """Index 5 files in a directory, remove the directory, verify
    files_removed == 5 (not 1)."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "count_test"
    n_files = 5
    files = [
        builders.make_txt(folder / f"file{i:02d}.txt", f"content {i} " * 30)
        for i in range(n_files)
    ]

    rag.index_file_list(
        [rag.normalise_path(str(p)) for p in files],
        label="initial",
        root_directory=str(folder),
    )

    result = rag.remove_directory_from_index(str(folder))

    # If B-03 isn't fixed yet, skip the count check (xfail wins on the
    # first missing-key assertion). If it IS fixed, this should still fail
    # until B-08 is fixed.
    files_removed = result.get("files_removed")
    assert files_removed == n_files, (
        f"Expected files_removed == {n_files}; got {files_removed!r}. "
        f"Bug B-08: the set comprehension at rag_preprocessor.py:5206 "
        f"iterates an empty list and always falls through to 1."
    )


# ──────────────────────────────────────────────────────────────────────────────
# Edge case: remove on a non-existent path
# ──────────────────────────────────────────────────────────────────────────────
def test_remove_nonexistent_path_does_not_crash(isolated_env):
    """Calling remove on a path that was never tracked should produce a
    well-formed result dict, not raise."""
    rag = isolated_env.rag

    fake = isolated_env.sample_root / "never_existed"
    result = rag.remove_directory_from_index(str(fake))

    assert isinstance(result, dict)
    assert result.get("chunks_removed", 0) == 0
    # errors list may or may not be populated — both are acceptable
    assert isinstance(result.get("errors", []), list)

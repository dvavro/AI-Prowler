"""
tests/mcp/test_reindex_after_write.py — C-REINDEX-NN: auto-reindex coverage

Exercises the REAL `_reindex_file_after_write` code path against a REAL
(isolated) ChromaDB. Does NOT monkey-patch the reindex helper — these tests
exist precisely to catch silent-failure modes the existing test_write_tools.py
suite can't see because it stubs reindexing out for speed.

Test plan IDs in this file begin with `C-REINDEX-NN`, grouped:

    Group A — Smoking-gun  C-REINDEX-01 … C-REINDEX-05
              The user's reported scenario: modify a file via Claude, search
              for the change, expect the change to be found.

    Group B — Stale chunks purged  C-REINDEX-06 … C-REINDEX-10
              After a modification, the OLD content must NOT come back in
              search results — the delete-then-add must actually delete.

    Group C — Filepath metadata     C-REINDEX-11 … C-REINDEX-14
              The metadata.filepath on every chunk must equal the
              normalised path the purge query uses, otherwise purge silently
              matches nothing and stale chunks accumulate.

    Group D — Backup files          C-REINDEX-15 … C-REINDEX-17
              .bak<N> files created by the write tools must never be indexed,
              and copy_to_backup must not affect the active file's chunks.

    Group E — Multi-file isolation  C-REINDEX-18 … C-REINDEX-19
              Reindexing file A must not affect file B in the same dir.

    Group F — Edge cases            C-REINDEX-20 … C-REINDEX-24
              Empty content, unicode, CRLF, very short / very long files.

    Group G — restore_backup        C-REINDEX-25
              After restore, the index reflects the restored content.

Mark: @pytest.mark.slow — these tests load the real embedding model
(all-MiniLM-L6-v2, ~3-8 seconds first time, faster on warm restart).

Runtime budget: ~60-90 seconds for the whole file on a cold cache,
~10-20 seconds warm.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Module-level fixture: import ai_prowler_mcp once per session
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def mcp_mod():
    """Import ai_prowler_mcp exactly once per session."""
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


# ──────────────────────────────────────────────────────────────────────────────
# Per-test fixture: reindex_env
#
# Builds a writable project directory wired into BOTH the read and writable
# allowlists. Unlike `writable_env` in test_write_tools.py, this fixture
# does NOT monkey-patch `_reindex_file_after_write` — the whole point of this
# file is to exercise the real auto-reindex code path against the real
# (isolated) ChromaDB.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def reindex_env(isolated_env, mcp_mod, monkeypatch, tmp_path):
    """Yield a namespace with a writable project, wired into all allowlists."""
    rag = isolated_env.rag
    root = isolated_env.sample_root

    project = root / "project"
    project.mkdir()

    # Wire into READ allowlist via the production function
    rag.add_to_auto_update_list(str(project))

    # Wire into WRITABLE allowlist via a temp file we control
    writable_file = tmp_path / "rag_writable_dirs.json"
    writable_file.write_text(json.dumps([str(project)]), encoding="utf-8")
    pending_file = tmp_path / "rag_writable_pending.json"
    monkeypatch.setattr(mcp_mod, "_WRITABLE_DIRS_FILE", writable_file)
    monkeypatch.setattr(mcp_mod, "_WRITE_APPROVAL_QUEUE_FILE", pending_file)

    # Reset write counter so a fresh test starts at 0/20
    mcp_mod._reset_write_counter_internal()

    # NOTE: we INTENTIONALLY do NOT monkey-patch _reindex_file_after_write.
    # The whole point of these tests is to exercise it for real.

    class E:
        pass
    e = E()
    e.rag = rag
    e.root = root
    e.project = project
    return e


# ──────────────────────────────────────────────────────────────────────────────
# Helpers — small, well-named, reused across many tests
# ──────────────────────────────────────────────────────────────────────────────
def _chunks_for_file(rag, filepath):
    """Return the ChromaDB get() result restricted to chunks for `filepath`.

    Returns a dict with 'ids', 'documents', and 'metadatas' lists. If nothing
    matches, all three are empty lists.
    """
    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=ef,
    )
    fp_norm = rag.normalise_path(filepath)
    out = coll.get(
        where={"filepath": fp_norm},
        include=["documents", "metadatas"],
    )
    return {
        "ids":       out.get("ids", []) or [],
        "documents": out.get("documents", []) or [],
        "metadatas": out.get("metadatas", []) or [],
    }


def _chunk_count_for_file(rag, filepath):
    """Number of chunks currently in ChromaDB for `filepath`."""
    return len(_chunks_for_file(rag, filepath)["ids"])


def _search_finds(rag, query, expected_substring, n=10):
    """True if any chunk in the top-N nearest-neighbour search results
    contains `expected_substring`. Substring is case-sensitive."""
    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=ef,
    )
    if coll.count() == 0:
        return False
    res = coll.query(query_texts=[query], n_results=min(n, coll.count()))
    docs = (res.get("documents") or [[]])[0]
    return any(expected_substring in d for d in docs)


def _search_returns_anything_for_file(rag, query, filepath, n=20):
    """True if any chunk in the top-N nearest-neighbour search results comes
    FROM the given filepath (regardless of content match). Useful for asserting
    'this file is searchable at all'."""
    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=ef,
    )
    if coll.count() == 0:
        return False
    fp_norm = rag.normalise_path(filepath)
    res = coll.query(
        query_texts=[query],
        n_results=min(n, coll.count()),
        include=["metadatas"],
    )
    metas = (res.get("metadatas") or [[]])[0]
    return any((m or {}).get("filepath") == fp_norm for m in metas)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP A — Smoking-gun: the user's reported scenario
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.slow
def test_C_REINDEX_01_create_file_indexes_new_content(reindex_env, mcp_mod):
    """create_file: new file is searchable immediately after creation.

    Bare-minimum end-to-end check. If this fails, the auto-reindex helper
    isn't running at all (e.g. the import-error silent-failure regression)."""
    fp = reindex_env.project / "note_about_purple_zebras.md"
    content = "Purple zebras are a fictional creature invented for testing. " * 20
    result = mcp_mod.create_file(filepath=str(fp), content=content)
    assert "✅" in result or "Created" in result, f"create_file did not report success: {result!r}"
    assert _chunk_count_for_file(reindex_env.rag, str(fp)) > 0, (
        "create_file claimed success but no chunks were added to ChromaDB. "
        "_reindex_file_after_write is not running. Check the import statement."
    )


@pytest.mark.slow
def test_C_REINDEX_02_write_file_indexes_new_content(reindex_env, mcp_mod):
    """write_file: after overwriting an existing file, NEW content is searchable.

    This is the exact scenario the user reported: modify a file via Claude,
    then search for the change, expect a hit."""
    fp = reindex_env.project / "scratch.md"
    mcp_mod.create_file(filepath=str(fp), content="Original baseline content. " * 10)
    new_content = "Magenta walruses sing at sunset in the test environment. " * 15
    result = mcp_mod.write_file(filepath=str(fp), content=new_content)
    assert "✅" in result or "Wrote" in result, f"write_file did not report success: {result!r}"
    assert _search_finds(reindex_env.rag, "magenta walrus sunset", "Magenta walruses"), (
        "After write_file, the NEW content is not searchable. "
        "The reindex either didn't run or didn't add the new chunks."
    )


@pytest.mark.slow
def test_C_REINDEX_03_str_replace_indexes_new_content(reindex_env, mcp_mod):
    """str_replace_in_file: after a surgical edit, NEW content is searchable."""
    fp = reindex_env.project / "story.md"
    mcp_mod.create_file(
        filepath=str(fp),
        content=("The quick brown fox jumps over the lazy dog. " * 10
                 + "The lazy dog yawns and falls asleep. "
                 + "Filler text to give the embedding something to work with. " * 10),
    )
    result = mcp_mod.str_replace_in_file(
        filepath=str(fp),
        old_str="The lazy dog yawns and falls asleep.",
        new_str="A turquoise armadillo dances the tango under a glittering disco ball.",
    )
    assert "✅" in result or "Replaced" in result, f"str_replace did not report success: {result!r}"
    assert _search_finds(reindex_env.rag, "turquoise armadillo disco", "turquoise armadillo"), (
        "After str_replace_in_file, the NEW string is not searchable. "
        "The reindex either didn't run or didn't add the new chunks."
    )


@pytest.mark.slow
def test_C_REINDEX_04_create_file_chunk_metadata_has_filepath(reindex_env, mcp_mod):
    """create_file: every chunk written has metadata.filepath set to the
    normalised path. Without this, the delete-where clause in subsequent
    purges can't find the chunks and stale data accumulates."""
    fp = reindex_env.project / "metadata_check.md"
    content = "Indexed content for the metadata-filepath check. " * 30
    mcp_mod.create_file(filepath=str(fp), content=content)
    chunks = _chunks_for_file(reindex_env.rag, str(fp))
    assert len(chunks["metadatas"]) > 0, "No chunks found by where={filepath:...}"
    expected = reindex_env.rag.normalise_path(str(fp))
    for m in chunks["metadatas"]:
        assert m.get("filepath") == expected, (
            f"Chunk has metadata.filepath={m.get('filepath')!r}, "
            f"expected {expected!r}. Purge query will miss these chunks."
        )


@pytest.mark.slow
def test_C_REINDEX_05_search_finds_file_via_metadata_route(reindex_env, mcp_mod):
    """create_file: the file is reachable in a nearest-neighbour search
    query that returns the file's chunks (verified via metadata)."""
    fp = reindex_env.project / "marker.md"
    mcp_mod.create_file(
        filepath=str(fp),
        content="A unique sentinel phrase indigo jaguar cathedral. " * 12,
    )
    assert _search_returns_anything_for_file(
        reindex_env.rag, "indigo jaguar cathedral", str(fp)
    ), "Search did not return any chunks belonging to the newly-created file"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP B — Stale chunks correctly purged on modification
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.slow
def test_C_REINDEX_06_write_file_purges_old_chunks(reindex_env, mcp_mod):
    """write_file: after overwriting, search for the OLD content returns
    nothing — the previous chunks must have been deleted."""
    fp = reindex_env.project / "replaceme.md"
    mcp_mod.create_file(
        filepath=str(fp),
        content="A cyan octopus juggles seven coconuts on Tuesdays. " * 12,
    )
    # Sanity: the original phrase IS searchable.
    assert _search_finds(reindex_env.rag, "cyan octopus coconut", "cyan octopus"), (
        "Setup precondition failed: original content not searchable"
    )
    # Replace the whole file.
    mcp_mod.write_file(
        filepath=str(fp),
        content="The new content has nothing in common with the old. " * 12,
    )
    # Now the OLD phrase must be gone.
    assert not _search_finds(reindex_env.rag, "cyan octopus coconut", "cyan octopus"), (
        "After write_file, the OLD chunks were NOT purged. The delete-where "
        "clause is silently matching nothing — likely a filepath-metadata "
        "mismatch or the purge step is failing silently."
    )


@pytest.mark.slow
def test_C_REINDEX_07_str_replace_purges_old_chunks(reindex_env, mcp_mod):
    """str_replace_in_file: after the surgical edit, the OLD string is not
    searchable any more — the whole file was re-chunked."""
    fp = reindex_env.project / "oldstring.md"
    # NOTE: tokens deliberately use no markdown-special characters (no
    # underscores, no asterisks). The markdown loader processes those during
    # ingestion, which would cause our literal-substring assertions to miss
    # even though semantic search returns the chunk. Use plain ASCII words.
    mcp_mod.create_file(
        filepath=str(fp),
        content=("UNIQUEOLDTOKENvermillionstarfish appears here once. "
                 + "Filler content surrounding it. " * 20),
    )
    assert _search_finds(reindex_env.rag, "vermillion starfish",
                         "UNIQUEOLDTOKENvermillionstarfish"), (
        "Setup precondition failed: OLD token not searchable"
    )
    mcp_mod.str_replace_in_file(
        filepath=str(fp),
        old_str="UNIQUEOLDTOKENvermillionstarfish",
        new_str="UNIQUENEWTOKENamberpuffin",
    )
    assert not _search_finds(reindex_env.rag, "vermillion starfish",
                             "UNIQUEOLDTOKENvermillionstarfish"), (
        "After str_replace_in_file, the OLD token is still searchable. "
        "Stale chunks were not purged."
    )
    # And the new token IS searchable (sanity: reindex actually completed)
    assert _search_finds(reindex_env.rag, "amber puffin",
                         "UNIQUENEWTOKENamberpuffin"), (
        "After str_replace_in_file, the NEW token is not searchable either. "
        "The reindex did not complete end-to-end."
    )


@pytest.mark.slow
def test_C_REINDEX_08_repeated_writes_no_chunk_accumulation(reindex_env, mcp_mod):
    """Sequential write_file calls on the same file must NOT accumulate
    chunks. After N writes, chunk count for the file == chunks for the
    final content only."""
    fp = reindex_env.project / "loop.md"
    mcp_mod.create_file(
        filepath=str(fp),
        content="Initial content with some bulk. " * 20,
    )
    initial = _chunk_count_for_file(reindex_env.rag, str(fp))
    for i in range(5):
        mcp_mod.write_file(
            filepath=str(fp),
            content=f"Iteration {i}: " + ("brief content " * 20),
        )
    final = _chunk_count_for_file(reindex_env.rag, str(fp))
    # Each iteration's content is similar in length to the initial — chunk
    # counts should be within 1-2 of each other, certainly not 5x the initial.
    assert final < initial * 3, (
        f"Chunk count exploded after 5 writes: initial={initial}, final={final}. "
        f"The purge step is not deleting stale chunks between writes."
    )


@pytest.mark.slow
def test_C_REINDEX_09_empty_overwrite_purges_all_chunks(reindex_env, mcp_mod):
    """write_file with empty content: all of the file's chunks must be gone
    (since the file has no content to index)."""
    fp = reindex_env.project / "emptyme.md"
    mcp_mod.create_file(
        filepath=str(fp),
        content="Plenty of content here. " * 20,
    )
    assert _chunk_count_for_file(reindex_env.rag, str(fp)) > 0, (
        "Setup precondition failed: file should have chunks initially"
    )
    mcp_mod.write_file(filepath=str(fp), content="")
    # After emptying, zero or near-zero chunks. (Some chunkers may produce
    # one empty chunk; both are acceptable. What's NOT acceptable is having
    # the OLD content still present.)
    chunks = _chunks_for_file(reindex_env.rag, str(fp))
    # Old text must not be in any remaining chunk
    for doc in chunks["documents"]:
        assert "Plenty of content here" not in doc, (
            "After emptying the file, OLD content is still in ChromaDB chunks"
        )


@pytest.mark.slow
def test_C_REINDEX_10_modified_content_replaces_search_results(reindex_env, mcp_mod):
    """End-to-end: identical search query returns different top-1 chunk
    before vs after modification (proves the index actually swapped)."""
    fp = reindex_env.project / "swap.md"
    mcp_mod.create_file(
        filepath=str(fp),
        content="Penguins waddle through arctic snow. " * 20,
    )
    client, ef = reindex_env.rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=reindex_env.rag.COLLECTION_NAME, embedding_function=ef,
    )
    before = coll.query(query_texts=["arctic animals"], n_results=1)
    before_doc = (before.get("documents") or [[]])[0][0] if (
        before.get("documents") and before["documents"][0]
    ) else ""
    assert "Penguins" in before_doc, "Setup: penguin query did not match penguin file"
    mcp_mod.write_file(
        filepath=str(fp),
        content="Camels traverse desert dunes under harsh sun. " * 20,
    )
    after = coll.query(query_texts=["arctic animals"], n_results=3)
    after_docs = (after.get("documents") or [[]])[0]
    # The old penguin chunks should NOT be in the search results any more
    assert not any("Penguins" in d for d in after_docs), (
        "After modifying the file, OLD content (penguins) still appears in search results"
    )


# ══════════════════════════════════════════════════════════════════════════════
# GROUP C — Filepath metadata correctness (the invariant that makes purge work)
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.slow
def test_C_REINDEX_11_write_file_metadata_filepath_correct(reindex_env, mcp_mod):
    """write_file: every chunk's metadata.filepath equals normalise_path(filepath).
    Without this invariant, the purge query in step 1 of _reindex_file_after_write
    can't find the chunks to delete."""
    fp = reindex_env.project / "meta_after_write.md"
    mcp_mod.create_file(filepath=str(fp), content="initial content " * 30)
    mcp_mod.write_file(filepath=str(fp), content="replacement content " * 30)
    chunks = _chunks_for_file(reindex_env.rag, str(fp))
    expected = reindex_env.rag.normalise_path(str(fp))
    assert len(chunks["metadatas"]) > 0, "No chunks for file after write"
    for m in chunks["metadatas"]:
        assert m.get("filepath") == expected, (
            f"Chunk metadata.filepath={m.get('filepath')!r}, expected {expected!r}"
        )


@pytest.mark.slow
def test_C_REINDEX_12_str_replace_metadata_filepath_correct(reindex_env, mcp_mod):
    """str_replace_in_file: chunks after the edit have correct metadata.filepath."""
    fp = reindex_env.project / "meta_after_strr.md"
    mcp_mod.create_file(
        filepath=str(fp),
        content="A UNIQUE_OLD pattern appears in the text. " * 12,
    )
    mcp_mod.str_replace_in_file(
        filepath=str(fp), old_str="UNIQUE_OLD", new_str="UNIQUE_NEW",
    )
    chunks = _chunks_for_file(reindex_env.rag, str(fp))
    expected = reindex_env.rag.normalise_path(str(fp))
    for m in chunks["metadatas"]:
        assert m.get("filepath") == expected, (
            f"After str_replace, chunk metadata.filepath={m.get('filepath')!r}, "
            f"expected {expected!r}"
        )


@pytest.mark.slow
def test_C_REINDEX_13_purge_where_clause_finds_chunks(reindex_env, mcp_mod):
    """Direct check: after a write, calling coll.delete(where={"filepath": ...})
    actually deletes chunks (i.e. the where clause matches). This is the
    mechanism the purge step relies on."""
    fp = reindex_env.project / "where_test.md"
    mcp_mod.create_file(filepath=str(fp), content="some content " * 30)
    initial_count = _chunk_count_for_file(reindex_env.rag, str(fp))
    assert initial_count > 0, "Setup failed: no chunks to delete"

    # Now directly purge using the same mechanism the reindex helper uses
    client, ef = reindex_env.rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=reindex_env.rag.COLLECTION_NAME, embedding_function=ef,
    )
    fp_norm = reindex_env.rag.normalise_path(str(fp))
    coll.delete(where={"filepath": fp_norm})
    after_count = _chunk_count_for_file(reindex_env.rag, str(fp))
    assert after_count == 0, (
        f"Direct coll.delete(where={{filepath: {fp_norm!r}}}) didn't delete "
        f"chunks: before={initial_count}, after={after_count}. "
        f"The purge mechanism the reindex helper depends on is broken."
    )


@pytest.mark.slow
def test_C_REINDEX_14_path_normalization_is_consistent(reindex_env, mcp_mod):
    """The normalised path used at write time must match the normalised path
    used at search time. (On Windows, this means backslashes are converted
    to forward slashes consistently.)"""
    fp = reindex_env.project / "norm_test.md"
    mcp_mod.create_file(filepath=str(fp), content="path normalization content " * 20)
    # Round-trip through normalise_path twice — must be idempotent.
    once = reindex_env.rag.normalise_path(str(fp))
    twice = reindex_env.rag.normalise_path(once)
    assert once == twice, f"normalise_path not idempotent: {once!r} != {twice!r}"
    # Chunk metadata uses this normalised form
    chunks = _chunks_for_file(reindex_env.rag, str(fp))
    assert len(chunks["metadatas"]) > 0, "No chunks found via the normalised path"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP D — Backup files are NEVER indexed (Layer 2 enforcement)
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.slow
def test_C_REINDEX_15_str_replace_does_not_index_backup(reindex_env, mcp_mod):
    """str_replace_in_file creates a .bak<N> alongside the file. That .bak
    file must NEVER be indexed in ChromaDB."""
    fp = reindex_env.project / "backup_check.py"
    # IMPORTANT: str_replace_in_file requires old_str to appear EXACTLY ONCE.
    # Earlier version of this test used a token repeated 15x, which made
    # str_replace fail (and therefore skip the backup step), masking the
    # actual behavior we want to test. Use a one-of-a-kind sentinel here.
    mcp_mod.create_file(
        filepath=str(fp),
        content=(
            "# Unique sentinel block for the backup-is-never-indexed test.\n"
            "BackupCheckSentinelLineUniqueExactlyOnce = 'preedit'\n"
            "# Filler so the file is more than just the sentinel line.\n"
            + "filler_line_for_padding = True\n" * 20
        ),
    )
    mcp_mod.str_replace_in_file(
        filepath=str(fp),
        old_str="BackupCheckSentinelLineUniqueExactlyOnce = 'preedit'",
        new_str="BackupCheckSentinelLineUniqueExactlyOnce = 'postedit'",
    )
    # A .bak<N> file should now exist next to the original
    bak_files = list(reindex_env.project.glob("backup_check.py.bak*"))
    assert len(bak_files) >= 1, "No .bak<N> file produced by str_replace_in_file"
    # NONE of them should have chunks in ChromaDB
    for bf in bak_files:
        assert _chunk_count_for_file(reindex_env.rag, str(bf)) == 0, (
            f"Backup file {bf} was indexed! Layer 2 (is_backup_filename) failed."
        )


@pytest.mark.slow
def test_C_REINDEX_16_write_file_does_not_index_backup(reindex_env, mcp_mod):
    """write_file also creates a .bak<N>. Same invariant: never indexed."""
    fp = reindex_env.project / "wf_backup_check.md"
    mcp_mod.create_file(filepath=str(fp), content="initial " * 30)
    mcp_mod.write_file(filepath=str(fp), content="replacement " * 30)
    bak_files = list(reindex_env.project.glob("wf_backup_check.md.bak*"))
    assert len(bak_files) >= 1, "No .bak<N> file produced by write_file"
    for bf in bak_files:
        assert _chunk_count_for_file(reindex_env.rag, str(bf)) == 0, (
            f"Backup file {bf} was indexed! Layer 2 failed for write_file."
        )


@pytest.mark.slow
def test_C_REINDEX_17_copy_to_backup_does_not_change_active_chunks(reindex_env, mcp_mod):
    """copy_to_backup is a soft-snapshot — it should NOT change the active
    file's chunk count (no purge, no re-index)."""
    fp = reindex_env.project / "snap_check.md"
    mcp_mod.create_file(filepath=str(fp), content="stable content " * 30)
    before = _chunk_count_for_file(reindex_env.rag, str(fp))
    mcp_mod.copy_to_backup(filepath=str(fp))
    after = _chunk_count_for_file(reindex_env.rag, str(fp))
    assert before == after, (
        f"copy_to_backup changed chunk count: before={before}, after={after}. "
        f"It should be a pure soft-snapshot with no index side effects."
    )


# ══════════════════════════════════════════════════════════════════════════════
# GROUP E — Multi-file isolation
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.slow
def test_C_REINDEX_18_modifying_file_A_does_not_affect_file_B(reindex_env, mcp_mod):
    """Reindexing file A must leave file B's chunks completely untouched."""
    # Plain-ASCII tokens (no markdown-special chars like underscores) so the
    # markdown loader keeps them intact and our substring checks survive.
    fp_a = reindex_env.project / "file_a.md"
    fp_b = reindex_env.project / "file_b.md"
    mcp_mod.create_file(filepath=str(fp_a),
                        content="A-content with PhraseAlphaQuokka. " * 15)
    mcp_mod.create_file(filepath=str(fp_b),
                        content="B-content with PhraseBetaNumbat. " * 15)
    b_count_before = _chunk_count_for_file(reindex_env.rag, str(fp_b))
    # Now modify A
    mcp_mod.write_file(filepath=str(fp_a),
                       content="A-replaced with PhraseGammaDunnart. " * 15)
    # B should be untouched
    b_count_after = _chunk_count_for_file(reindex_env.rag, str(fp_b))
    assert b_count_after == b_count_before, (
        f"File B's chunks changed when only file A was modified: "
        f"before={b_count_before}, after={b_count_after}"
    )
    # And B's original content is still searchable
    assert _search_finds(reindex_env.rag, "phrase beta numbat", "PhraseBetaNumbat"), (
        "File B's content was wiped out when file A was modified"
    )


@pytest.mark.slow
def test_C_REINDEX_19_modify_file_A_does_not_purge_subdir_file(reindex_env, mcp_mod):
    """Reindexing file A in the project root must leave a file in a
    subdirectory completely untouched (no recursive purge by accident)."""
    sub = reindex_env.project / "subdir"
    sub.mkdir()
    fp_root = reindex_env.project / "root.md"
    fp_sub = sub / "nested.md"
    mcp_mod.create_file(filepath=str(fp_root),
                        content="root file content " * 15)
    mcp_mod.create_file(filepath=str(fp_sub),
                        content="nested file content with UNIQUE_NESTED " * 15)
    sub_before = _chunk_count_for_file(reindex_env.rag, str(fp_sub))
    mcp_mod.write_file(filepath=str(fp_root),
                       content="root file replaced " * 15)
    sub_after = _chunk_count_for_file(reindex_env.rag, str(fp_sub))
    assert sub_after == sub_before, (
        f"Nested file's chunks changed when only root file was modified: "
        f"before={sub_before}, after={sub_after}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# GROUP F — Edge cases
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.slow
def test_C_REINDEX_20_empty_create_file_has_zero_or_minimal_chunks(reindex_env, mcp_mod):
    """create_file with empty content should not error and should produce
    either 0 chunks or a single trivial chunk — never an unbounded number."""
    fp = reindex_env.project / "empty.md"
    result = mcp_mod.create_file(filepath=str(fp), content="")
    assert "✅" in result or "Created" in result, f"empty create_file failed: {result!r}"
    count = _chunk_count_for_file(reindex_env.rag, str(fp))
    assert count <= 1, f"Empty file produced {count} chunks (expected 0 or 1)"


@pytest.mark.slow
def test_C_REINDEX_21_unicode_content_searchable(reindex_env, mcp_mod):
    """Files with unicode characters are indexed correctly and searchable."""
    fp = reindex_env.project / "unicode.md"
    content = (
        "Voici un café français avec des accents é à ç ñ. " * 5
        + "中文测试: 这是一个测试句子。 " * 5
        + "Эмодзи и кириллица работают вместе. " * 5
    )
    mcp_mod.create_file(filepath=str(fp), content=content)
    # The file IS searchable at all (via metadata)
    assert _search_returns_anything_for_file(
        reindex_env.rag, "café français accents", str(fp)
    ), "Unicode file is not searchable after indexing"


@pytest.mark.slow
def test_C_REINDEX_22_crlf_line_endings_searchable(reindex_env, mcp_mod):
    """Files written via create_file on Windows get CRLF line endings. Those
    must not break chunking or search."""
    fp = reindex_env.project / "crlf.md"
    content = "First line of the test file.\nSecond line follows.\nThird line.\n" * 10
    mcp_mod.create_file(filepath=str(fp), content=content)
    assert _search_returns_anything_for_file(
        reindex_env.rag, "First line of the test file", str(fp)
    ), "CRLF file is not searchable after indexing"


@pytest.mark.slow
def test_C_REINDEX_23_very_short_file_has_chunks(reindex_env, mcp_mod):
    """A file shorter than the chunk size should still produce at least one
    chunk (not get filtered out as 'too small')."""
    fp = reindex_env.project / "tiny.md"
    mcp_mod.create_file(filepath=str(fp), content="A tiny but very distinctive HUMMINGBIRD sentence.")
    count = _chunk_count_for_file(reindex_env.rag, str(fp))
    assert count >= 1, f"Very short file produced 0 chunks (expected >= 1)"
    assert _search_finds(reindex_env.rag, "hummingbird tiny", "HUMMINGBIRD"), (
        "Short file's distinctive token isn't searchable"
    )


@pytest.mark.slow
def test_C_REINDEX_24_long_file_replace_all_chunks(reindex_env, mcp_mod):
    """A long file that produces multiple chunks must have ALL chunks replaced
    on write_file, not just some of them."""
    fp = reindex_env.project / "long.md"
    # Long enough to produce multiple chunks. Token uses plain ASCII (no
    # markdown-special chars) so the literal-substring assertion below holds.
    mcp_mod.create_file(
        filepath=str(fp),
        content="OriginalBanner paragraph content. " * 200,
    )
    initial_count = _chunk_count_for_file(reindex_env.rag, str(fp))
    assert initial_count >= 2, (
        f"Setup precondition failed: long file produced only {initial_count} chunk(s); "
        f"test needs >= 2 to be meaningful"
    )
    # Overwrite with completely different content
    mcp_mod.write_file(
        filepath=str(fp),
        content="ReplacementBanner different paragraph content. " * 200,
    )
    # NONE of the resulting chunks should contain the ORIGINAL banner
    chunks = _chunks_for_file(reindex_env.rag, str(fp))
    for doc in chunks["documents"]:
        assert "OriginalBanner" not in doc, (
            "After write_file, some OLD chunks survived. The purge did not "
            "delete every stale chunk for this file."
        )


# ══════════════════════════════════════════════════════════════════════════════
# GROUP G — restore_backup
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.slow
def test_C_REINDEX_25_restore_backup_reflects_restored_content(reindex_env, mcp_mod):
    """After restore_backup, the index reflects the restored (backup) content,
    not the temporarily-written intermediate content."""
    fp = reindex_env.project / "restoreme.md"
    # Plain-ASCII tokens (no markdown emphasis underscores) so the substring
    # assertions hold after the markdown loader processes the file.
    mcp_mod.create_file(
        filepath=str(fp),
        content="ORIGINAL state with StarlightFalcon token. " * 12,
    )
    # Now modify it — this creates a .bak1 of the ORIGINAL
    mcp_mod.write_file(
        filepath=str(fp),
        content="MODIFIED state with MoonbeamRaven token. " * 12,
    )
    # Find the .bak file and restore it. restore_backup() takes (filepath, N)
    # where filepath is the ACTIVE file and N is the integer suffix of the
    # .bak<N> backup to restore, NOT the backup path itself.
    baks = sorted(reindex_env.project.glob("restoreme.md.bak*"))
    assert len(baks) >= 1, "No .bak file produced by write_file"
    # Extract the integer N from .bakN
    import re as _re_local
    m = _re_local.search(r'\.bak(\d+)$', baks[0].name)
    assert m, f"Backup filename {baks[0].name!r} does not match .bak<N> pattern"
    backup_n = int(m.group(1))
    result = mcp_mod.restore_backup(filepath=str(fp), backup_number=backup_n)
    assert "✅" in result or "Restored" in result, f"restore_backup failed: {result!r}"
    # NOW the index should have the ORIGINAL content, not the MODIFIED content
    assert _search_finds(reindex_env.rag, "starlight falcon", "StarlightFalcon"), (
        "After restore_backup, the ORIGINAL content is not searchable. "
        "The reindex after restore did not run or did not run correctly."
    )
    assert not _search_finds(reindex_env.rag, "moonbeam raven", "MoonbeamRaven"), (
        "After restore_backup, the MODIFIED (intermediate) content is still "
        "searchable. Stale chunks from the pre-restore state were not purged."
    )

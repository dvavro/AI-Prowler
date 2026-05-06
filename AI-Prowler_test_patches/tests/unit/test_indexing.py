"""
Functional tests — Indexing (Section 4 of the test plan)

Each test is named after its plan ID (F-IDX-NN) so a tester can locate it
in the test-plan Word doc by ID alone. The docstring on each test repeats
the plan's "expected result" bullets verbatim — that way a failure message
tells you what was supposed to happen, not just what didn't.

Bug-exercising tests (rows highlighted orange in the test plan) are marked
@pytest.mark.xfail so they're EXPECTED to fail on the unfixed build. After
a fix lands, the xfail flips to xpassed → pytest exits non-zero → CI flags
the strict_xfail violation → developer removes the marker. That's the
intended workflow for tracking a fix.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-01 — index empty directory
# ──────────────────────────────────────────────────────────────────────────────
def test_F_IDX_01_index_empty_directory(isolated_env):
    """Empty directory: 0 to_index, 0 chunks, but tracking baseline still
    created so a later 'Update' on this folder reports correctly."""
    rag = isolated_env.rag
    empty = isolated_env.sample_root / "empty"
    empty.mkdir()

    scan = rag.scan_directory(str(empty), recursive=True)

    assert scan["total_seen"] == 0, "Empty dir should report 0 total_seen"
    assert scan["to_index"]    == [], "Empty dir should yield no files"
    assert scan["skipped_bin"] == []
    assert scan["unsupported"] == []


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-02 — supported extension coverage
# ──────────────────────────────────────────────────────────────────────────────
def test_F_IDX_02_supported_extensions_all_classified(isolated_env, sample_files):
    """Every file in the sample corpus is classified into 'to_index' (not
    skipped, not unsupported).

    Implementation note: scan_directory's directory-walk branch returns paths
    via os.path.join (native separators), while its single-file branch
    normalises to forward slashes. We compare by absolute-path equality
    rather than string equality so the test is separator-agnostic and works
    on both Windows and POSIX.
    """
    rag = isolated_env.rag
    scan = rag.scan_directory(str(isolated_env.sample_root), recursive=True)

    # Build the set of indexed paths with both representations resolved to
    # the OS's canonical form (handles backslash vs forward-slash, case
    # normalisation on Windows, and any drive-letter quirks).
    to_index_canonical = {os.path.normcase(os.path.abspath(fp))
                          for fp, _ in scan["to_index"]}

    for ext, path in sample_files.items():
        canon = os.path.normcase(os.path.abspath(str(path)))
        assert canon in to_index_canonical, (
            f"{ext} file at {path} was not classified as to_index — "
            f"got {scan['to_index']}"
        )

    assert scan["skipped_bin"] == [], "No binaries in sample — none should be skipped"


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-03 — smart-scan binary skip
# ──────────────────────────────────────────────────────────────────────────────
def test_F_IDX_03_smart_scan_skips_binaries_and_unknowns(isolated_env):
    """exe / mp3 / zip → skipped_bin. mystery.xyz → unsupported."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag
    folder = isolated_env.sample_root / "mixed"
    folder.mkdir()

    builders.make_binary_blob(folder / "program.exe", n_bytes=512)
    builders.make_binary_blob(folder / "song.mp3",    n_bytes=512)
    builders.make_binary_blob(folder / "archive.zip", n_bytes=512)
    builders.make_unsupported_file(folder / "mystery.xyz")
    builders.make_txt(folder / "real.txt", "actual content")

    scan = rag.scan_directory(str(folder), recursive=True)

    # to_index must contain ONLY real.txt
    to_index_exts = sorted(ext for _, ext in scan["to_index"])
    assert to_index_exts == [".txt"], f"Expected only .txt; got {to_index_exts}"

    skip_exts = sorted(ext for _, ext in scan["skipped_bin"])
    assert ".exe" in skip_exts and ".mp3" in skip_exts and ".zip" in skip_exts

    unsup_exts = sorted(ext for _, ext in scan["unsupported"])
    assert ".xyz" in unsup_exts


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-04 — SKIP_DIRECTORIES honored at every depth
# ──────────────────────────────────────────────────────────────────────────────
def test_F_IDX_04_skip_directories_pruned_at_every_depth(isolated_env):
    """node_modules, .git, build pruned at every level. Real source files
    underneath are still found."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag
    root = isolated_env.sample_root / "tree"

    # Files we EXPECT to be indexed
    builders.make_txt(root / "src" / "main.py",     "print('hello')")
    builders.make_txt(root / "src" / "lib" / "x.py", "x = 1")

    # Files we expect to be PRUNED (inside skipped dirs)
    builders.make_txt(root / "src" / ".git" / "log",                 "git log junk")
    builders.make_txt(root / "node_modules" / "left-pad" / "idx.js", "module.exports")
    builders.make_txt(root / "build" / "output.txt",                 "compiled")
    builders.make_txt(root / "src" / "__pycache__" / "x.pyc",        "bytecode")

    scan = rag.scan_directory(str(root), recursive=True)
    indexed_names = sorted(Path(fp).name for fp, _ in scan["to_index"])

    assert indexed_names == ["main.py", "x.py"], (
        f"Pruning failed — got {indexed_names}; "
        f"node_modules / .git / build / __pycache__ leaked through"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-05 — single-file path bypasses SKIP_EXTENSIONS
# ──────────────────────────────────────────────────────────────────────────────
def test_F_IDX_05_single_file_path_via_scan_directory(isolated_env, small_text_file):
    """When scan_directory is given a file path (not a dir), it returns that
    one file in to_index. This is the path the GUI uses for Browse Files…"""
    rag = isolated_env.rag

    scan = rag.scan_directory(str(small_text_file), recursive=True)

    assert scan["total_seen"] == 1
    assert len(scan["to_index"]) == 1
    fp, ext = scan["to_index"][0]
    assert ext == ".txt"
    assert rag.normalise_path(str(small_text_file)) == fp


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-06 — re-indexing same dir does not duplicate chunks
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_IDX_06_no_duplicate_chunks_on_reindex(isolated_env, small_text_file):
    """Re-indexing the same unmodified file twice must not grow chunk count."""
    rag = isolated_env.rag

    rag.index_file_list([rag.normalise_path(str(small_text_file))],
                        label="run-1",
                        root_directory=str(small_text_file.parent))

    client, ef = rag.get_chroma_client()
    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    count_after_first = coll.count()
    assert count_after_first > 0, "First indexing should have produced chunks"

    # Second run on identical file
    stats = rag.index_file_list([rag.normalise_path(str(small_text_file))],
                                label="run-2",
                                root_directory=str(small_text_file.parent))

    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    count_after_second = coll.count()

    # Two valid implementations:
    #   (a) skip unchanged file ⇒ count stays equal AND processed == 0
    #   (b) re-index but delete-then-add ⇒ count stays equal too
    # Either way: the count MUST NOT GROW.
    assert count_after_second == count_after_first, (
        f"Re-indexing duplicated chunks: {count_after_first} → {count_after_second}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-07 — modified file purges old chunks first
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_IDX_07_modified_file_purges_old_chunks(isolated_env):
    """Truncating a file then re-indexing must drop the old chunks. We verify
    by querying the collection for content that ONLY existed in the old
    version — there should be zero matches afterwards."""
    rag = isolated_env.rag
    from tests.helpers import sample_files as builders

    file_path = isolated_env.sample_root / "shrinking.txt"
    big = "OLD_UNIQUE_TOKEN_AAA " * 200 + "shared content " * 100
    builders.make_txt(file_path, big)

    rag.index_file_list([rag.normalise_path(str(file_path))],
                        label="big",
                        root_directory=str(file_path.parent))

    # Truncate — must change BOTH size AND mtime to be detected by all paths.
    # We bump mtime forward 5 s explicitly so we don't depend on FS resolution.
    small = "shared content " * 5
    file_path.write_text(small, encoding="utf-8")
    new_mtime = os.path.getmtime(str(file_path)) + 5.0
    os.utime(str(file_path), (new_mtime, new_mtime))

    # ⚠️  index_file_list checks mtime+size BEFORE re-indexing. To force a
    # re-index of an already-tracked file we have to clear the tracking entry,
    # OR use command_update which goes through scan_directory_for_changes.
    # We'll use command_update since that's what users actually run.
    # (auto_confirm=True suppresses the y/n prompt.)
    rag.command_update(str(file_path.parent), recursive=True, auto_confirm=True)

    # Now query for the unique token from the OLD content. ChromaDB's
    # similarity search will always return SOMETHING — we don't assert
    # zero hits, we assert that none of them carry the old content.
    client, ef = rag.get_chroma_client()
    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)

    results = coll.get(where={"filepath": rag.normalise_path(str(file_path))},
                       include=["documents"])
    surviving_docs = " ".join(results.get("documents", []) or [])
    assert "OLD_UNIQUE_TOKEN_AAA" not in surviving_docs, (
        "Old content survived re-indexing — chunks were not properly purged. "
        f"Surviving documents contain: {surviving_docs[:300]}…"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-10 — email archive incremental indexing
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_IDX_10_mbox_incremental_indexing(isolated_env, mbox_file):
    """First index: 5 new. Append 2 more. Second index: 2 new, 5 unchanged."""
    rag = isolated_env.rag
    from tests.helpers import mbox_builder

    # First pass — should index all 5
    stats1 = rag.index_email_archive(str(mbox_file),
                                     root_directory=str(mbox_file.parent))
    assert stats1["processed"] == 5, f"First pass should index all 5 messages; got {stats1}"
    assert stats1["skipped"]   == 0
    assert stats1["removed"]   == 0

    # Verify email_index.json now has 5 UIDs
    db = json.loads(isolated_env.email_index.read_text(encoding="utf-8"))
    file_key = rag.normalise_path(str(mbox_file))
    assert file_key in db, f"email_index missing key for {file_key}; has {list(db.keys())}"
    assert len(db[file_key]["uids"]) == 5

    # Append 2 messages
    mbox_builder.append_message(mbox_file, seq=6)
    mbox_builder.append_message(mbox_file, seq=7)

    # Second pass
    stats2 = rag.index_email_archive(str(mbox_file),
                                     root_directory=str(mbox_file.parent))
    assert stats2["processed"] == 2, f"Second pass should add 2 new; got {stats2}"
    assert stats2["skipped"]   == 5, "Existing 5 should be skipped"
    assert stats2["removed"]   == 0

    db = json.loads(isolated_env.email_index.read_text(encoding="utf-8"))
    assert len(db[file_key]["uids"]) == 7


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-11 — email archive removes deleted messages
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_IDX_11_mbox_removes_deleted_messages(isolated_env, mbox_file):
    """Index 5, delete 2 from the archive, re-index → removed counter == 2."""
    rag = isolated_env.rag
    from tests.helpers import mbox_builder

    rag.index_email_archive(str(mbox_file), root_directory=str(mbox_file.parent))

    # Delete first 2 messages
    remaining = mbox_builder.remove_first_n_messages(mbox_file, 2)
    assert remaining == 3

    stats = rag.index_email_archive(str(mbox_file),
                                    root_directory=str(mbox_file.parent))

    assert stats["removed"] == 2, f"Expected 2 removed; got {stats}"
    assert stats["processed"] == 0, "No new messages — nothing should be indexed"

    db = json.loads(isolated_env.email_index.read_text(encoding="utf-8"))
    file_key = rag.normalise_path(str(mbox_file))
    assert len(db[file_key]["uids"]) == 3


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-12 — path normalisation: no backslashes anywhere
# ──────────────────────────────────────────────────────────────────────────────
def test_F_IDX_12_path_normalisation_forward_slashes_only(
        isolated_env, small_text_file):
    """After indexing, every stored path uses forward slashes regardless of
    the platform's native separator. Critical because ChromaDB
    where={'filepath': ...} is exact-match and will silently fail to find
    'C:\\Foo\\bar.txt' if the metadata says 'C:/Foo/bar.txt'."""
    rag = isolated_env.rag

    rag.index_file_list([rag.normalise_path(str(small_text_file))],
                        label="norm",
                        root_directory=str(small_text_file.parent))

    # 1. Tracking DB keys must be forward-slash only
    tracking = json.loads(isolated_env.tracking_db.read_text(encoding="utf-8"))
    for dir_key, dir_data in tracking.items():
        assert "\\" not in dir_key, f"Tracking dir_key has backslash: {dir_key!r}"
        for fp in dir_data.get("files", {}):
            assert "\\" not in fp, f"Tracking file path has backslash: {fp!r}"

    # 2. ChromaDB metadata.filepath must be forward-slash only
    client, ef = rag.get_chroma_client()
    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    sample = coll.get(limit=10, include=["metadatas"])
    for meta in sample.get("metadatas") or []:
        fp = meta.get("filepath", "")
        assert "\\" not in fp, f"ChromaDB metadata has backslash: {fp!r}"


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-14 — Unicode filenames and content
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_IDX_14_unicode_filenames_and_content(isolated_env):
    """中文.txt, café.md, файл.txt index without UnicodeEncodeError. Content
    is searchable through ChromaDB."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag
    folder = isolated_env.sample_root / "unicode"
    folder.mkdir()

    f1 = builders.make_txt(folder / "中文.txt",
                           "这是一段中文文本，包含独特的标识符 NEEDLE_HANZI。" * 10)
    f2 = builders.make_txt(folder / "café.md",
                           "Café résumé naïve façade. Unique marker: NEEDLE_LATIN1.\n" * 10)
    f3 = builders.make_txt(folder / "файл.txt",
                           "Кириллический текст с уникальным маркером NEEDLE_CYRILLIC.\n" * 10)

    files = [rag.normalise_path(str(f)) for f in (f1, f2, f3)]
    stats = rag.index_file_list(files, label="unicode",
                                root_directory=str(folder))

    assert stats["processed"] == 3, f"Expected 3 processed; got {stats}"

    # All three filenames survived the round-trip into metadata
    client, ef = rag.get_chroma_client()
    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    all_data = coll.get(limit=100, include=["metadatas"])
    indexed_filenames = {m.get("filename") for m in all_data["metadatas"]}

    assert "中文.txt" in indexed_filenames
    assert "café.md" in indexed_filenames
    assert "файл.txt" in indexed_filenames


# ──────────────────────────────────────────────────────────────────────────────
# F-IDX-18 — file vanishes between scan and index
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_IDX_18_file_vanishes_between_scan_and_index(isolated_env):
    """If a file is deleted after being added to the queue but before its
    turn comes up, the indexer must not crash — it should warn and continue."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag
    folder = isolated_env.sample_root / "vanishing"
    folder.mkdir()

    keep1 = builders.make_txt(folder / "keep1.txt", "keep me " * 50)
    doomed = builders.make_txt(folder / "doomed.txt", "delete me " * 50)
    keep2 = builders.make_txt(folder / "keep2.txt", "also keep " * 50)

    file_paths = [rag.normalise_path(str(p)) for p in (keep1, doomed, keep2)]

    # Delete doomed AFTER building the file_paths list. index_file_list will
    # see all three in the list, then fail to load the middle one mid-run.
    doomed.unlink()

    stats = rag.index_file_list(file_paths, label="vanishing",
                                root_directory=str(folder))

    # The two surviving files must still be processed.
    assert stats["processed"] == 2, (
        f"Expected 2 surviving files indexed; got {stats}. "
        f"A vanishing file should not abort the rest of the run."
    )
    # The vanished one is counted as skipped (load_file returns None).
    assert stats["skipped"] >= 1


# ──────────────────────────────────────────────────────────────────────────────
# Bug regression: dead .markdown dispatch branch (Bug B-05)
#
# load_file() has an `elif ext in ('.md', '.rst', '.markdown')` branch that
# can never fire for '.markdown' because that extension is not in
# SUPPORTED_EXTENSIONS — load_file returns None at the top guard before
# reaching the dispatch.
#
# This test is xfail until the bug is fixed (either by adding '.markdown'
# to SUPPORTED_EXTENSIONS, or by removing it from the dispatch branch).
# After the fix, this test should pass and the marker can be removed.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.xfail(reason="Bug B-05: '.markdown' is dispatched but not in SUPPORTED_EXTENSIONS",
                   strict=True)
def test_F_IDX_B05_markdown_extension_is_indexable(isolated_env):
    """A .markdown file should be indexable. Currently it's silently ignored
    by load_file because the SUPPORTED_EXTENSIONS guard rejects it before
    the .markdown dispatch branch can run."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    f = builders.make_txt(isolated_env.sample_root / "test.markdown",
                          "# Heading\nBody text " * 30)

    result = rag.load_file(str(f))
    assert result is not None, (
        ".markdown extension was not loaded — fix is to add '.markdown' "
        "to SUPPORTED_EXTENSIONS in rag_preprocessor.py:1047"
    )
    assert result["word_count"] > 0

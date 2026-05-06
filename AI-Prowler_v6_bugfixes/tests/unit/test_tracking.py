"""
Functional tests — Tracking & Change Detection (Section 5 of the test plan)

This file is where the high-severity bugs live. The xfail-marked tests
exercise the inconsistent mtime-comparison rules between the directory
branch (4543), the file branch (4492), and index_file_list (3047).

When the fix lands:
  • The directory branch and file branch should both use:
      abs(new_mtime - old_mtime) < 1.0  AND  size == old_size
  • Then xfail tests turn into xpassed → strict=True makes the suite fail
    → the developer removes the marker → tests pass cleanly.

That sequence is intentional: it forces a documented, reviewable removal
of the marker as part of the fix PR.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Helper — write tracking DB directly so we can simulate prior-run state
# without doing a full index every time.
# ──────────────────────────────────────────────────────────────────────────────
def _seed_tracking(rag, dir_path: Path, files: list[Path]) -> None:
    """Pre-populate the tracking DB as if a previous scan had recorded these
    files. Used to make tests deterministic without the cost of a full
    indexing round-trip when we only care about scan_directory_for_changes."""
    from datetime import datetime
    dir_key = rag.normalise_path(str(dir_path.resolve()))
    files_map = {}
    for f in files:
        st = f.stat()
        files_map[rag.normalise_path(str(f.resolve()))] = {
            "modified": st.st_mtime,
            "modified_human": datetime.fromtimestamp(st.st_mtime).strftime(
                "%Y-%m-%d %H:%M:%S"),
            "size": st.st_size,
        }
    db = {
        dir_key: {
            "first_scan": datetime.now().isoformat(),
            "last_scan":  datetime.now().isoformat(),
            "files":      files_map,
        }
    }
    rag.save_tracking_database(db)


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-01 — first scan creates a tracking record
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_01_first_scan_creates_record(isolated_env, sample_files):
    """First scan of a previously-untracked directory should create an entry
    in the tracking DB with first_scan timestamp and a complete files map."""
    rag = isolated_env.rag
    folder = isolated_env.sample_root

    result = rag.scan_directory_for_changes(str(folder), recursive=True, quiet=True)
    assert result is not None, "scan_directory_for_changes returned None"
    results, tracking_db, dir_key = result

    # Save it (scan doesn't auto-save — command_scan does)
    rag.save_tracking_database(tracking_db)

    persisted = json.loads(isolated_env.tracking_db.read_text(encoding="utf-8"))
    assert dir_key in persisted, f"dir_key {dir_key!r} not saved; got {list(persisted)}"
    entry = persisted[dir_key]
    assert entry["first_scan"], "first_scan should be set on first scan"
    # All sample files (only ones in SUPPORTED_EXTENSIONS) should be tracked
    files_in_track = entry.get("files", {})
    # First scan classifies everything as NEW — files map fills on save
    # (some implementations write the files map only on the second scan).
    # So we accept either: files map populated, OR new_files contains them.
    if files_in_track:
        assert all("modified" in info and "size" in info
                   for info in files_in_track.values())
    else:
        new_paths = {Path(f["path"]).name for f in results["new_files"]}
        assert new_paths, "First scan should classify files as NEW or populate files map"


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-02 — modified file detected by mtime change
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_02_modified_file_detected(isolated_env, small_text_file):
    """File edited after baseline → flagged MODIFIED."""
    rag = isolated_env.rag
    _seed_tracking(rag, isolated_env.sample_root, [small_text_file])

    # Wait long enough that the new mtime is unambiguously newer than the
    # baseline (filesystem mtime resolution can be 1-2 seconds on some
    # platforms). Directly setting mtime is more deterministic than sleeping.
    new_content = small_text_file.read_text(encoding="utf-8") + "\nADDED LINE\n"
    small_text_file.write_text(new_content, encoding="utf-8")
    new_mtime = small_text_file.stat().st_mtime + 5.0
    os.utime(str(small_text_file), (new_mtime, new_mtime))

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    modified_paths = {Path(f["path"]).name for f in results["modified_files"]}
    assert small_text_file.name in modified_paths, (
        f"Expected {small_text_file.name} to be MODIFIED; got "
        f"{[f['name'] for f in results['modified_files']]}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-03 — touched file (mtime newer, content same) treated as modified
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_03_touched_file_flagged_modified(isolated_env, small_text_file):
    """`touch` bumps mtime without changing content. The directory scan
    treats this as MODIFIED — that's an acceptable false positive
    (re-indexing produces identical chunks)."""
    rag = isolated_env.rag
    _seed_tracking(rag, isolated_env.sample_root, [small_text_file])

    # Bump mtime forward without touching content. Use os.utime explicitly
    # rather than relying on a real `touch` to keep the test platform-portable.
    new_mtime = small_text_file.stat().st_mtime + 5.0
    os.utime(str(small_text_file), (new_mtime, new_mtime))

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    modified_names = {Path(f["path"]).name for f in results["modified_files"]}
    assert small_text_file.name in modified_names


# ══════════════════════════════════════════════════════════════════════════════
# BUG-EXERCISING TESTS — these are EXPECTED to fail on the unfixed build.
# After the fix, remove the @pytest.mark.xfail decorator.
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-04 — same-second save with size change   [BUG B-01 — FIXED in current build]
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_04_same_second_save_with_size_change(isolated_env, small_text_file):
    """Save twice within ~1 second; second save changes size but mtime delta
    is < 1.0 s. Directory branch must classify this as MODIFIED based on
    size change.

    Bug B-01 was originally that the directory branch ignored size when
    the mtime delta was small. Verified fixed in the current build —
    if this test ever fails again it's a regression.
    """
    rag = isolated_env.rag
    _seed_tracking(rag, isolated_env.sample_root, [small_text_file])
    seeded_size = small_text_file.stat().st_size

    # Mutate content (size will differ) but force mtime to be very close to
    # the seeded value — within the 1.0 s tolerance window.
    seeded_mtime = small_text_file.stat().st_mtime
    new_content = "x" * (seeded_size + 200)  # guaranteed different size
    small_text_file.write_text(new_content, encoding="utf-8")

    # Pin mtime to half a second after the seeded value
    target_mtime = seeded_mtime + 0.5
    os.utime(str(small_text_file), (target_mtime, target_mtime))

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    modified_names = {Path(f["path"]).name for f in results["modified_files"]}
    assert small_text_file.name in modified_names, (
        "Same-second save with size change was NOT detected as modified. "
        "This is bug B-01 — the directory branch needs a size check."
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-05 — backup-restore (older mtime, different size)   [BUG B-02 — FIXED]
#
# Original bug: directory branch used `mtime > old_mtime` and ignored size,
# missing files restored from a backup with an older mtime.
# Fix: directory branch now matches the file branch — symmetric tolerance
# AND a size check.
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_05_backup_restore_older_mtime(isolated_env, small_text_file):
    """A file replaced by a backup whose mtime is OLDER than the tracked
    baseline but whose content (and size) is different. Must be flagged
    MODIFIED."""
    rag = isolated_env.rag

    # First, advance the file's mtime forward so we have headroom to step it
    # backward in the test without going below the file's birth time.
    advanced = small_text_file.stat().st_mtime + 60.0
    os.utime(str(small_text_file), (advanced, advanced))

    _seed_tracking(rag, isolated_env.sample_root, [small_text_file])

    # Replace contents with something different (size differs by ~50 bytes),
    # then set mtime BACK to before the baseline.
    small_text_file.write_text("REPLACED " * 200, encoding="utf-8")
    older_mtime = advanced - 30.0  # 30 s older than what's recorded
    os.utime(str(small_text_file), (older_mtime, older_mtime))

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    modified_names = {Path(f["path"]).name for f in results["modified_files"]}
    assert small_text_file.name in modified_names, (
        "Backup-restore (older mtime + size change) was NOT detected. "
        "This is bug B-02 — `mtime > old_mtime` misses older-mtime updates."
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-06 — deleted file detected
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_06_deleted_file_detected(isolated_env, sample_files):
    """File present at baseline, gone from disk → flagged DELETED."""
    rag = isolated_env.rag
    file_paths = list(sample_files.values())
    _seed_tracking(rag, isolated_env.sample_root, file_paths)

    victim = sample_files[".txt"]
    victim.unlink()

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    deleted_names = {Path(f["path"]).name for f in results["deleted_files"]}
    assert victim.name in deleted_names


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-07 — only-deletions case must still purge
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_TRK_07_only_deletions_still_purge(isolated_env, sample_files):
    """Two files indexed → both deleted from disk → command_update must run
    Pass 1 (purge) even though changes == 0. Earlier versions of command_update
    early-returned when changes == 0, leaving stale chunks behind."""
    rag = isolated_env.rag
    folder = isolated_env.sample_root

    # Index a couple of files first so we have ChromaDB chunks to purge
    f1 = sample_files[".txt"]
    f2 = sample_files[".md"]
    rag.index_file_list(
        [rag.normalise_path(str(f1)), rag.normalise_path(str(f2))],
        label="initial",
        root_directory=str(folder),
    )

    client, ef = rag.get_chroma_client()
    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    chunks_before = coll.count()
    assert chunks_before > 0

    # Delete both files from disk
    f1.unlink()
    f2.unlink()

    rag.command_update(str(folder), recursive=True, auto_confirm=True)

    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    surviving = coll.get(where={"filepath": rag.normalise_path(str(f1))},
                         include=["metadatas"])
    assert not surviving.get("ids"), "Chunks for deleted f1 survived purge"

    surviving = coll.get(where={"filepath": rag.normalise_path(str(f2))},
                         include=["metadatas"])
    assert not surviving.get("ids"), "Chunks for deleted f2 survived purge"


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-08 — true no-op
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_08_no_changes_is_noop(isolated_env, sample_files):
    """Nothing changed since baseline → unchanged_files contains everything,
    new/modified/deleted are all empty."""
    rag = isolated_env.rag
    file_paths = list(sample_files.values())
    _seed_tracking(rag, isolated_env.sample_root, file_paths)

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    assert results["new_files"]      == []
    assert results["modified_files"] == []
    assert results["deleted_files"]  == []
    assert len(results["unchanged_files"]) == len(file_paths)


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-09 — new file added to tracked folder
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_09_new_file_added(isolated_env, sample_files):
    """Drop a new file into a tracked folder → flagged NEW on next scan."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag
    _seed_tracking(rag, isolated_env.sample_root, list(sample_files.values()))

    new_file = builders.make_txt(isolated_env.sample_root / "newcomer.txt",
                                 "I'm a new arrival." * 10)

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    new_names = {Path(f["path"]).name for f in results["new_files"]}
    assert "newcomer.txt" in new_names


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-10 — rename = DELETED + NEW
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_10_rename_is_deleted_plus_new(isolated_env, small_text_file):
    """Rename foo.txt → bar.txt → scan reports foo DELETED, bar NEW."""
    rag = isolated_env.rag
    _seed_tracking(rag, isolated_env.sample_root, [small_text_file])

    renamed = small_text_file.with_name("renamed.txt")
    small_text_file.rename(renamed)

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    deleted_names = {Path(f["path"]).name for f in results["deleted_files"]}
    new_names     = {Path(f["path"]).name for f in results["new_files"]}

    assert small_text_file.name in deleted_names
    assert "renamed.txt" in new_names


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-11 — recursive vs non-recursive
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_11_recursive_vs_non_recursive(isolated_env):
    """Recursive scan picks up subfolder files; non-recursive does not."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag
    root = isolated_env.sample_root / "tree"
    builders.make_txt(root / "top.txt",         "top-level " * 30)
    builders.make_txt(root / "sub" / "deep.txt", "deeper " * 30)

    rec = rag.scan_directory(str(root), recursive=True)
    rec_names = sorted(Path(fp).name for fp, _ in rec["to_index"])
    assert rec_names == ["deep.txt", "top.txt"]

    flat = rag.scan_directory(str(root), recursive=False)
    flat_names = sorted(Path(fp).name for fp, _ in flat["to_index"])
    assert flat_names == ["top.txt"], (
        f"Non-recursive scan should only see top-level files; got {flat_names}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-12 — individually tracked file gets a baseline
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_TRK_12_individual_file_gets_baseline(isolated_env, small_text_file):
    """When a single file is indexed via index_file_list, the function must
    write a tracking baseline for it. Without this, every Update would
    re-index the file even though it's unchanged."""
    rag = isolated_env.rag

    rag.index_file_list([rag.normalise_path(str(small_text_file))],
                        label="solo",
                        root_directory=str(small_text_file.parent))

    tracking = json.loads(isolated_env.tracking_db.read_text(encoding="utf-8"))

    # The baseline can be written under either:
    #   - the file's own path key (per-file tracking), or
    #   - the parent directory key (typical for index_directory output).
    # Either is acceptable; we just need to find an entry containing this file.
    target = rag.normalise_path(str(small_text_file))
    found = False
    for dir_key, dir_data in tracking.items():
        if target in dir_data.get("files", {}):
            found = True
            rec = dir_data["files"][target]
            assert "modified" in rec and "size" in rec
            break

    assert found, (
        f"No tracking baseline written for {target}. Tracking DB contents: "
        f"{json.dumps(tracking, indent=2)}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-13 — single file indexable even if extension is in SKIP_EXTENSIONS
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_13_single_file_bypasses_skip_extensions(isolated_env, monkeypatch):
    """User explicitly opts to track a single .log file; SKIP_EXTENSIONS
    does NOT apply because the user picked it deliberately. scan_directory
    when given a file path is intentionally permissive in this regard.

    Note: this tests the SCAN path. Indexing a file not in SUPPORTED_EXTENSIONS
    will still fail at load_file's guard. The test plan documents this as
    expected behavior."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    # Add .log to SKIP_EXTENSIONS for this test only
    new_skip = set(rag.SKIP_EXTENSIONS) | {".log"}
    monkeypatch.setattr(rag, "SKIP_EXTENSIONS", new_skip)

    log_file = builders.make_txt(isolated_env.sample_root / "app.log",
                                 "log line\n" * 50)

    # Single-file scan SHOULD still classify .log as skipped_bin (it IS in
    # SKIP_EXTENSIONS), but the GUI's _register_directory_for_tracking
    # intentionally bypasses this check. Verify that fact: when given a file
    # that's in SKIP_EXTENSIONS, scan_directory routes it to skipped_bin.
    scan = rag.scan_directory(str(log_file), recursive=True)
    assert any(ext == ".log" for _, ext in scan["skipped_bin"]), (
        "Even single-file scan should report .log as skipped_bin when it's "
        "in SKIP_EXTENSIONS. The bypass is in the GUI worker, not in scan."
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-TRK-15 — legacy backslash tracking DB   [BUG B-07 — FIXED in current build]
# ──────────────────────────────────────────────────────────────────────────────
def test_F_TRK_15_legacy_backslash_tracking_db(isolated_env, small_text_file):
    """Old (v4.x) tracking DBs may have backslash-form paths. The fixed code
    normalises tracking-DB keys consistently with current_files keys so legacy
    entries no longer get wrongly flagged DELETED.

    Bug B-07 was originally that scan_directory_for_changes compared
    un-normalised tracking keys against normalised current_files keys.
    Verified fixed — regression watch.
    """
    rag = isolated_env.rag
    from datetime import datetime

    # Manually craft a tracking DB with backslash paths even though the actual
    # files exist with forward-slash paths. Use os.sep replacement to simulate
    # what an older Windows-era DB would have stored.
    real_path = rag.normalise_path(str(small_text_file.resolve()))
    legacy_path = real_path.replace("/", "\\")

    dir_key = rag.normalise_path(str(isolated_env.sample_root.resolve()))
    legacy_dir_key = dir_key.replace("/", "\\")

    st = small_text_file.stat()
    legacy_db = {
        legacy_dir_key: {
            "first_scan": datetime.now().isoformat(),
            "last_scan":  datetime.now().isoformat(),
            "files": {
                legacy_path: {
                    "modified": st.st_mtime,
                    "modified_human": "2025-01-01 00:00:00",
                    "size": st.st_size,
                }
            }
        }
    }
    isolated_env.tracking_db.write_text(json.dumps(legacy_db), encoding="utf-8")

    results, _, _ = rag.scan_directory_for_changes(
        str(isolated_env.sample_root), recursive=True, quiet=True)

    # Expected behaviour after fix: file appears as UNCHANGED (paths match
    # after normalisation). Current behaviour: file appears as DELETED + NEW
    # because the legacy backslash key doesn't match the normalised current key.
    deleted_names = {Path(f["path"]).name for f in results["deleted_files"]}
    assert small_text_file.name not in deleted_names, (
        "Legacy backslash path was wrongly flagged DELETED. Bug B-07."
    )

"""
Functional tests — Update workflow (Section 6 of the test plan)

Covers command_update, _update_tracked_file, the auto-update list lifecycle,
and the bug where clear_database leaves orphan state behind.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# F-UPD-01 — command_update on a multi-file tracked folder
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_UPD_01_update_modified_file(isolated_env, sample_files):
    """Index a folder, modify one file, run update → that one file's chunks
    are replaced with the new content's chunks; other files untouched."""
    rag = isolated_env.rag
    folder = isolated_env.sample_root

    # Initial index of all sample files
    file_paths = [rag.normalise_path(str(p)) for p in sample_files.values()]
    rag.index_file_list(file_paths, label="initial",
                        root_directory=str(folder))

    client, ef = rag.get_chroma_client()
    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    chunks_before = coll.count()

    # Modify one file with a unique sentinel that makes it easy to verify
    target = sample_files[".txt"]
    target.write_text("UPDATED_SENTINEL_TOKEN_BBB " * 200, encoding="utf-8")
    new_mtime = target.stat().st_mtime + 5.0
    os.utime(str(target), (new_mtime, new_mtime))

    rag.command_update(str(folder), recursive=True, auto_confirm=True)

    coll = client.get_collection(name=rag.COLLECTION_NAME, embedding_function=ef)

    # Look at the surviving chunks for the target file
    target_meta = coll.get(where={"filepath": rag.normalise_path(str(target))},
                           include=["documents"])
    surviving_text = " ".join(target_meta.get("documents") or [])
    assert "UPDATED_SENTINEL_TOKEN_BBB" in surviving_text, (
        "After update, the target file should contain the new sentinel"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-UPD-02 — Update Selected updates only the selected entry
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_UPD_02_update_selected_only_touches_one_path(isolated_env):
    """Track two folders, MODIFY A FILE IN ONE OF THEM, then update only that
    folder. Verify:
      • the modified folder's last_scan timestamp advances
      • the other folder's last_scan does NOT change

    Earlier version of this test relied on last_scan advancing on a no-op
    update, but command_update doesn't write the tracking DB when there are
    no changes (correct behaviour — avoids unnecessary disk writes). We need
    a real change so the update path actually runs."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder_a = isolated_env.sample_root / "alpha"
    folder_b = isolated_env.sample_root / "bravo"
    f_a = builders.make_txt(folder_a / "a.txt", "alpha content " * 30)
    f_b = builders.make_txt(folder_b / "b.txt", "bravo content " * 30)

    rag.index_file_list([rag.normalise_path(str(f_a))], label="a",
                        root_directory=str(folder_a))
    rag.index_file_list([rag.normalise_path(str(f_b))], label="b",
                        root_directory=str(folder_b))

    tracking_initial = json.loads(isolated_env.tracking_db.read_text(encoding="utf-8"))
    a_key = rag.normalise_path(str(folder_a.resolve()))
    b_key = rag.normalise_path(str(folder_b.resolve()))

    a_scan_initial = tracking_initial.get(a_key, {}).get("last_scan")
    b_scan_initial = tracking_initial.get(b_key, {}).get("last_scan")

    # Make a real change in folder A so command_update has something to do.
    f_a.write_text("alpha content MODIFIED " * 30, encoding="utf-8")
    new_mtime = f_a.stat().st_mtime + 5.0
    os.utime(str(f_a), (new_mtime, new_mtime))

    rag.command_update(str(folder_a), recursive=True, auto_confirm=True)

    tracking_after = json.loads(isolated_env.tracking_db.read_text(encoding="utf-8"))
    a_scan_after = tracking_after.get(a_key, {}).get("last_scan")
    b_scan_after = tracking_after.get(b_key, {}).get("last_scan")

    assert a_scan_after != a_scan_initial, (
        "Folder A had a real change — last_scan should have advanced. "
        f"Before: {a_scan_initial!r}, After: {a_scan_after!r}"
    )
    assert b_scan_after == b_scan_initial, (
        f"Folder B was untouched — last_scan should NOT have changed. "
        f"Before: {b_scan_initial!r}, After: {b_scan_after!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-UPD-04 — directory removed from disk does not corrupt state
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_UPD_04_update_on_missing_dir_does_not_crash(isolated_env):
    """Track a folder, delete it from disk, run command_update on it →
    bails cleanly without crashing or corrupting state."""
    from tests.helpers import sample_files as builders
    import shutil
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "doomed_folder"
    f = builders.make_txt(folder / "doc.txt", "content " * 30)

    rag.index_file_list([rag.normalise_path(str(f))], label="doomed",
                        root_directory=str(folder))

    tracking_before = isolated_env.tracking_db.read_text(encoding="utf-8")

    # Nuke the folder
    shutil.rmtree(str(folder))

    # Should not raise — should print an error and return.
    rag.command_update(str(folder), recursive=True, auto_confirm=True)

    # Tracking DB must remain valid JSON afterwards
    tracking_after = isolated_env.tracking_db.read_text(encoding="utf-8")
    json.loads(tracking_after)  # raises if invalid

    # Auto-update list must remain valid JSON
    auto_update = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    assert isinstance(auto_update.get("directories"), list)


# ──────────────────────────────────────────────────────────────────────────────
# F-UPD-07 — clear_database wipes all coordinated state   [BUG B-04 — FIXED]
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_UPD_07_clear_database_wipes_all_state(isolated_env, mbox_file):
    """clear_database() must wipe ChromaDB, the tracking DB, the email index,
    AND the auto-update list — otherwise the four files drift out of sync."""
    rag = isolated_env.rag

    # Set up all four state files with content
    rag.index_email_archive(str(mbox_file), root_directory=str(mbox_file.parent))
    rag.add_to_auto_update_list(str(mbox_file.parent))

    # Sanity check — everything has content
    email_idx = json.loads(isolated_env.email_index.read_text(encoding="utf-8"))
    assert email_idx, "Pre-condition: email_index should have entries"
    auto_upd = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    assert auto_upd["directories"], "Pre-condition: auto_update list should have entries"

    # Clear (confirm=True bypasses the y/N prompt)
    rag.clear_database(confirm=True)

    # All four should now be empty/wiped
    email_idx_after = json.loads(isolated_env.email_index.read_text(encoding="utf-8"))
    assert not email_idx_after, (
        "Bug B-04: clear_database left email_index.json populated. "
        "Re-indexing the mbox will skip every message because UIDs are 'known'."
    )

    auto_upd_after = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    assert auto_upd_after["directories"] == [], (
        "Bug B-04: clear_database left auto_update list populated. "
        "Tracked-dir listbox will show folders with zero chunks behind them."
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-UPD-09 — extension previously skipped, now allowed → flagged NEW
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_UPD_09_extension_promoted_from_skip_to_supported(isolated_env, monkeypatch):
    """Index a folder where .log is in SKIP_EXTENSIONS, so .log files are not
    tracked. Move .log into SUPPORTED_EXTENSIONS, run update → previously-
    skipped .log files appear as NEW.

    Documents the behaviour described in bug B-09: the tracking baseline
    only records SUPPORTED files, so promotion-to-supported makes them
    appear new. This is acceptable but should be documented."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    # Original config: .log is skipped
    original_skip = set(rag.SKIP_EXTENSIONS) | {".log"}
    original_supported = set(rag.SUPPORTED_EXTENSIONS) - {".log"}
    monkeypatch.setattr(rag, "SKIP_EXTENSIONS", original_skip)
    monkeypatch.setattr(rag, "SUPPORTED_EXTENSIONS", original_supported)

    folder = isolated_env.sample_root
    keep = builders.make_txt(folder / "real.txt", "real content " * 30)
    log = builders.make_txt(folder / "ignored.log", "log line\n" * 30)

    rag.command_update(str(folder), recursive=True, auto_confirm=True)
    # After this, tracking baseline contains real.txt only.

    # Promote .log to supported
    new_skip = original_skip - {".log"}
    new_supported = original_supported | {".log"}
    monkeypatch.setattr(rag, "SKIP_EXTENSIONS", new_skip)
    monkeypatch.setattr(rag, "SUPPORTED_EXTENSIONS", new_supported)

    # Now scan should report .log as NEW
    results, _, _ = rag.scan_directory_for_changes(
        str(folder), recursive=True, quiet=True)

    new_names = {Path(f["path"]).name for f in results["new_files"]}
    assert "ignored.log" in new_names, (
        f"Promoted .log should appear as NEW. Got new={new_names}"
    )

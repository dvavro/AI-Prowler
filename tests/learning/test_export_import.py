"""
Functional tests — Learning Pack export / import (L-PACK-*)

Learning packs (.aiplearn files) are JSON serialisations of one or more
learnings. They let users back up, share, or merge knowledge bases.

Three import modes:
  • merge   — id-by-id; collisions resolved via on_conflict policy
  • append  — always add with fresh UUIDs (lossless backup-style import)
  • replace — wipe local and take the pack as-is (destructive)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# L-PACK-01 — round-trip export and import preserves content
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PACK_01_export_import_roundtrip(sl_env, seeded_learnings):
    """Export 4 seeded learnings, wipe local state, import them back —
    the resulting database matches the original."""
    sl = sl_env.sl
    pack_path = sl_env.tmp_path / "test_pack.aiplearn"

    # Export
    summary = sl.export_learnings(str(pack_path))
    assert summary["exported"] == 4
    assert pack_path.exists()

    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    assert pack["count"] == 4
    assert len(pack["learnings"]) == 4

    # Wipe local
    from rag_preprocessor import get_chroma_client
    sl._save_db({"version": sl.SCHEMA_VERSION, "learnings": []})
    client, _ = get_chroma_client()
    try:
        client.delete_collection(name=sl.LEARNINGS_COLLECTION)
    except Exception:
        pass

    # Import back
    result = sl.import_learnings(str(pack_path), mode="merge",
                                 on_conflict="take_incoming")
    # First import after wipe: every record is 'added' (no collisions)
    assert result["added"] == 4
    assert result["errors"] == []

    # Confirm restored state
    restored = sl.list_learnings(status="active")
    assert len(restored) == 4
    restored_ids = {l["id"] for l in restored}
    original_ids = {l["id"] for l in seeded_learnings}
    assert restored_ids == original_ids


# ──────────────────────────────────────────────────────────────────────────────
# L-PACK-02 — append mode always assigns fresh UUIDs
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PACK_02_append_creates_new_ids(sl_env, seeded_learnings):
    """Append mode gives every imported learning a brand-new UUID and leaves
    the existing records alone — the database grows by len(pack)."""
    sl = sl_env.sl
    pack_path = sl_env.tmp_path / "append.aiplearn"
    sl.export_learnings(str(pack_path))

    original_ids = {l["id"] for l in seeded_learnings}

    result = sl.import_learnings(str(pack_path), mode="append")
    assert result["added"] == 4

    db = sl._load_db()
    assert len(db["learnings"]) == 8   # 4 original + 4 appended

    # The 4 new IDs are different from the originals
    new_records = [l for l in db["learnings"] if l["id"] not in original_ids]
    assert len(new_records) == 4
    new_ids = {l["id"] for l in new_records}
    assert new_ids.isdisjoint(original_ids)


# ──────────────────────────────────────────────────────────────────────────────
# L-PACK-03 — replace mode wipes and takes the pack as-is
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PACK_03_replace_mode_wipes_then_imports(sl_env, seeded_learnings):
    """Replace mode discards local records and replaces them with the pack.
    Total ends up as len(pack); the original IDs that weren't in the pack
    are gone."""
    sl = sl_env.sl
    pack_path = sl_env.tmp_path / "replace_pack.aiplearn"

    # Build a smaller pack with just 2 records — fewer than what's local
    sample = seeded_learnings[:2]
    sl.export_learnings(str(pack_path), include_ids=[l["id"] for l in sample])

    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    assert pack["count"] == 2

    result = sl.import_learnings(str(pack_path), mode="replace")
    assert result.get("replaced_total") == 2
    assert result["added"] == 2

    db = sl._load_db()
    assert len(db["learnings"]) == 2   # wiped + replaced


# ──────────────────────────────────────────────────────────────────────────────
# L-PACK-04 — merge with keep_local skips collisions
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PACK_04_merge_keep_local_skips_collisions(sl_env, seeded_learnings):
    """Merge mode with on_conflict='keep_local' adds new IDs but leaves
    collisions untouched."""
    sl = sl_env.sl
    pack_path = sl_env.tmp_path / "merge.aiplearn"
    sl.export_learnings(str(pack_path))

    # Modify a local record so we can see if it's preserved (kept) or
    # overwritten (taken)
    target = seeded_learnings[0]
    sl.update_learning(target["id"], {"title": "LOCAL_MODIFIED_TITLE"})

    result = sl.import_learnings(str(pack_path), mode="merge",
                                 on_conflict="keep_local")

    # All 4 incoming IDs collide with local → all skipped
    assert result["added"] == 0
    assert result["skipped"] == 4

    # And the local modification was preserved
    db = sl._load_db()
    saved = next(l for l in db["learnings"] if l["id"] == target["id"])
    assert saved["title"] == "LOCAL_MODIFIED_TITLE"


@pytest.mark.slow
def test_L_PACK_05_merge_take_incoming_overwrites(sl_env, seeded_learnings):
    """Merge with on_conflict='take_incoming' overwrites local records on
    ID collision."""
    sl = sl_env.sl
    pack_path = sl_env.tmp_path / "merge2.aiplearn"
    sl.export_learnings(str(pack_path))

    target = seeded_learnings[0]
    sl.update_learning(target["id"], {"title": "LOCAL_TITLE_BEFORE_IMPORT"})

    result = sl.import_learnings(str(pack_path), mode="merge",
                                 on_conflict="take_incoming")
    assert result["updated"] == 4

    db = sl._load_db()
    saved = next(l for l in db["learnings"] if l["id"] == target["id"])
    # The incoming pack had the ORIGINAL title (before our local edit), so
    # the import should have overwritten our local change
    assert saved["title"] != "LOCAL_TITLE_BEFORE_IMPORT"
    assert saved["title"] == target["title"]


# ──────────────────────────────────────────────────────────────────────────────
# L-PACK-06 — merge with supersede mode creates a chain
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PACK_06_merge_supersede_creates_link(sl_env, seeded_learnings):
    """on_conflict='supersede' keeps both: local becomes deprecated and is
    linked to the incoming version via superseded_by."""
    sl = sl_env.sl
    pack_path = sl_env.tmp_path / "merge3.aiplearn"
    sl.export_learnings(str(pack_path))

    target = seeded_learnings[0]
    original_id = target["id"]

    result = sl.import_learnings(str(pack_path), mode="merge",
                                 on_conflict="supersede")
    assert result["superseded"] == 4

    db = sl._load_db()
    # We expect 4 original + 4 newly-added supersedors = 8 total
    assert len(db["learnings"]) == 8

    # Original is now deprecated and has superseded_by filled in
    old = next(l for l in db["learnings"] if l["id"] == original_id)
    assert old["status"] == "deprecated"
    assert old["superseded_by"] != ""


# ──────────────────────────────────────────────────────────────────────────────
# L-PACK-07 — import validates pack structure
# ──────────────────────────────────────────────────────────────────────────────
def test_L_PACK_07_invalid_pack_rejected(sl_env):
    """Malformed pack files are rejected cleanly with an error message,
    not a stack trace."""
    sl = sl_env.sl
    bad_path = sl_env.tmp_path / "bad.aiplearn"

    # Wrong top-level shape
    bad_path.write_text(json.dumps({"not": "a learning pack"}),
                        encoding="utf-8")
    result = sl.import_learnings(str(bad_path))
    assert result["added"] == 0
    assert result["errors"], "Should report an error"
    assert "learnings" in result["errors"][0].lower()


def test_L_PACK_08_missing_file_rejected(sl_env):
    """Importing a non-existent file returns an error in the result dict,
    not an exception."""
    sl = sl_env.sl
    result = sl.import_learnings(str(sl_env.tmp_path / "nope.aiplearn"))
    assert result["added"] == 0
    assert result["errors"]
    assert "not found" in result["errors"][0].lower()


# ──────────────────────────────────────────────────────────────────────────────
# L-PACK-09 — export filters by ID list
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PACK_09_export_with_id_filter(sl_env, seeded_learnings):
    """When include_ids is provided, export_learnings only includes those
    specific IDs, regardless of status."""
    sl = sl_env.sl
    pack_path = sl_env.tmp_path / "filtered.aiplearn"

    wanted = [seeded_learnings[1]["id"], seeded_learnings[3]["id"]]
    summary = sl.export_learnings(str(pack_path), include_ids=wanted)
    assert summary["exported"] == 2

    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    exported_ids = {l["id"] for l in pack["learnings"]}
    assert exported_ids == set(wanted)


@pytest.mark.slow
def test_L_PACK_10_export_excludes_inactive_by_default(sl_env, seeded_learnings):
    """Default export only includes active learnings. Deprecated/archived
    are excluded unless include_inactive=True."""
    sl = sl_env.sl
    sl.update_learning(seeded_learnings[0]["id"], {"status": "deprecated"})
    sl.update_learning(seeded_learnings[1]["id"], {"status": "archived"})

    # Default export
    pack_path = sl_env.tmp_path / "active_only.aiplearn"
    summary = sl.export_learnings(str(pack_path))
    assert summary["exported"] == 2   # only the 2 active ones

    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    statuses = {l["status"] for l in pack["learnings"]}
    assert statuses == {"active"}

    # With include_inactive=True
    pack_path2 = sl_env.tmp_path / "all.aiplearn"
    summary2 = sl.export_learnings(str(pack_path2), include_inactive=True)
    assert summary2["exported"] == 4

"""
Functional tests — Self-Learning engine (Section L-CRUD-*)

Covers the CRUD lifecycle of a learning: record, list, update, delete,
and the persistence guarantees that come with each.

Conventions
-----------
Test IDs prefix with L- (Learning). Sub-prefixes:
  L-CRUD-*  basic create/read/update/delete
  L-PERS-*  persistence — JSON file survives, reindex rebuilds ChromaDB
  L-SEARCH-* semantic search (check_learned)
  L-SUPER-*  supersession chains
  L-COUNT-*  applied_count tracking

Each test is named test_L_<sub>_NN_descriptive_name. The L- prefix shows
up clearly in pytest output so you can filter with `-k L_CRUD`.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# L-CRUD-01 — record a single learning end-to-end
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_CRUD_01_record_learning_basic(sl_env):
    """record_learning() creates a learning with all required fields, writes
    it to the JSON file, and indexes it for semantic search."""
    sl = sl_env.sl
    learning = sl.record_learning(
        title="Test learning one",
        content="The capital of testing is repeatability.",
        category="general",
    )

    # Returned dict has all the documented fields
    required_fields = {
        "id", "title", "content", "category", "context", "source",
        "confidence", "tags", "supersedes", "superseded_by", "status",
        "created_at", "updated_at", "applied_count", "last_applied",
        "outcome", "dismissed_conflicts",
    }
    missing = required_fields - set(learning.keys())
    assert not missing, f"Learning missing fields: {missing}"

    # ID is a valid UUID, status defaults to active, applied_count == 0
    import uuid as _uuid
    _uuid.UUID(learning["id"])   # raises if not a valid UUID
    assert learning["status"] == "active"
    assert learning["applied_count"] == 0
    assert learning["last_applied"] is None

    # JSON file exists and contains the record
    assert sl_env.learnings_file.exists()
    on_disk = json.loads(sl_env.learnings_file.read_text(encoding="utf-8"))
    assert on_disk["version"] == sl.SCHEMA_VERSION
    assert len(on_disk["learnings"]) == 1
    assert on_disk["learnings"][0]["id"] == learning["id"]


def test_L_CRUD_02_record_normalises_invalid_category(sl_env):
    """An invalid category silently falls back to 'general' rather than
    raising — this is documented behaviour."""
    sl = sl_env.sl
    learning = sl.record_learning(
        title="bad category test",
        content="any content",
        category="not_a_real_category_at_all",
    )
    assert learning["category"] == "general"


def test_L_CRUD_03_record_clamps_confidence_to_unit_interval(sl_env):
    """confidence outside [0, 1] is clamped, not rejected."""
    sl = sl_env.sl

    high = sl.record_learning(title="hi", content="x", confidence=99.0)
    assert high["confidence"] == 1.0

    low = sl.record_learning(title="lo", content="x", confidence=-5.0)
    assert low["confidence"] == 0.0


def test_L_CRUD_04_record_normalises_tags(sl_env):
    """Tags are lowercased and stripped of whitespace."""
    sl = sl_env.sl
    learning = sl.record_learning(
        title="tagged",
        content="x",
        tags=["  Foo  ", "BAR", " baz"],
    )
    assert learning["tags"] == ["foo", "bar", "baz"]


def test_L_CRUD_05_record_rejects_empty_title_or_content(sl_env):
    """The engine accepts empty strings but only after strip(). Confirm that
    the stripped form is what's stored — empty after strip is allowed at
    the engine level, but the MCP tool wrapper rejects it. We test engine
    behaviour here."""
    sl = sl_env.sl
    learning = sl.record_learning(title="  ", content="real content")
    assert learning["title"] == ""   # stripped, not rejected by engine


# ──────────────────────────────────────────────────────────────────────────────
# L-CRUD-06 through L-CRUD-09 — list_learnings filtering
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_CRUD_06_list_returns_all_active(sl_env, seeded_learnings):
    """Default list_learnings() with no filters returns all active learnings."""
    sl = sl_env.sl
    rows = sl.list_learnings()
    assert len(rows) == 4
    assert {l["status"] for l in rows} == {"active"}


@pytest.mark.slow
def test_L_CRUD_07_list_filter_by_category(sl_env, seeded_learnings):
    sl = sl_env.sl
    rows = sl.list_learnings(category="client_preference")
    assert len(rows) == 1
    assert rows[0]["title"] == "Client Alpha prefers email over phone"


@pytest.mark.slow
def test_L_CRUD_08_list_filter_by_tag(sl_env, seeded_learnings):
    sl = sl_env.sl
    rows = sl.list_learnings(tag="hvac")
    assert len(rows) == 1
    assert "hvac" in rows[0]["tags"]


@pytest.mark.slow
def test_L_CRUD_09_list_filter_by_status(sl_env, seeded_learnings):
    """Filter on deprecated status — no seeded records have it yet, so the
    list should be empty. Then deprecate one and confirm the filter picks
    it up."""
    sl = sl_env.sl
    assert sl.list_learnings(status="deprecated") == []

    target = seeded_learnings[0]["id"]
    sl.update_learning(target, {"status": "deprecated"})
    deprecated = sl.list_learnings(status="deprecated")
    assert len(deprecated) == 1
    assert deprecated[0]["id"] == target


# ──────────────────────────────────────────────────────────────────────────────
# L-CRUD-10 — update_learning happy path
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_CRUD_10_update_learning_changes_fields(sl_env):
    """update_learning() applies field changes, bumps updated_at, and
    persists to JSON."""
    sl = sl_env.sl
    learning = sl.record_learning(title="old title", content="old content")
    original_updated = learning["updated_at"]

    # Sleep just enough that the iso-second timestamp differs
    time.sleep(1.1)

    result = sl.update_learning(
        learning["id"],
        {"title": "new title", "confidence": 0.5, "status": "deprecated"},
    )
    assert result is not None
    assert result["title"] == "new title"
    assert result["confidence"] == 0.5
    assert result["status"] == "deprecated"
    assert result["updated_at"] != original_updated

    # Persisted to JSON
    on_disk = json.loads(sl_env.learnings_file.read_text(encoding="utf-8"))
    saved = next(l for l in on_disk["learnings"] if l["id"] == learning["id"])
    assert saved["title"] == "new title"


def test_L_CRUD_11_update_disallows_unknown_fields(sl_env):
    """update_learning() silently ignores fields not in the allow-list. This
    is the engine's defence-in-depth against a caller trying to corrupt the
    id, created_at, or other immutable fields."""
    sl = sl_env.sl
    learning = sl.record_learning(title="t", content="c")
    original_id = learning["id"]
    original_created = learning["created_at"]

    result = sl.update_learning(
        learning["id"],
        {
            "title": "renamed",       # allowed
            "id": "haha-stole-the-id",      # NOT allowed
            "created_at": "1999-01-01",     # NOT allowed
            "applied_count": 99999,         # NOT allowed
        },
    )
    assert result["title"] == "renamed"
    assert result["id"] == original_id
    assert result["created_at"] == original_created
    assert result["applied_count"] == 0


def test_L_CRUD_12_update_missing_id_returns_none(sl_env, seeded_learnings):
    """Updating an id that doesn't exist returns None (not an exception)."""
    sl = sl_env.sl
    result = sl.update_learning("00000000-0000-0000-0000-000000000000",
                                {"title": "ghost"})
    assert result is None


# ──────────────────────────────────────────────────────────────────────────────
# L-CRUD-13 / 14 — delete_learning
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_CRUD_13_delete_learning_removes_from_json_and_index(sl_env):
    """delete_learning() returns True, removes the record from JSON, and
    purges its embedding from ChromaDB so check_learned no longer finds it."""
    sl = sl_env.sl
    learning = sl.record_learning(
        title="WIDGET_DOOMED_UNIQUE_TOKEN_FOO",
        content="This learning is about to be deleted. Unique token: WIDGET_DOOMED_UNIQUE_TOKEN_FOO.",
    )

    # Confirm it's findable via semantic search first
    pre = sl.check_learned("WIDGET_DOOMED_UNIQUE_TOKEN_FOO",
                           track_application=False)
    assert any(m["learning_id"] == learning["id"] for m in pre)

    deleted = sl.delete_learning(learning["id"])
    assert deleted is True

    # JSON no longer contains it
    on_disk = json.loads(sl_env.learnings_file.read_text(encoding="utf-8"))
    assert all(l["id"] != learning["id"] for l in on_disk["learnings"])

    # Semantic search no longer finds it
    post = sl.check_learned("WIDGET_DOOMED_UNIQUE_TOKEN_FOO",
                            track_application=False)
    assert not any(m["learning_id"] == learning["id"] for m in post)


def test_L_CRUD_14_delete_unknown_id_returns_false(sl_env):
    """Deleting a non-existent id returns False with no exception. The
    ChromaDB cleanup branch still runs (best-effort) but reports nothing."""
    sl = sl_env.sl
    result = sl.delete_learning("00000000-0000-0000-0000-000000000000")
    assert result is False


# ──────────────────────────────────────────────────────────────────────────────
# L-PERS-01 — persistence across module reload
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PERS_01_learnings_survive_module_state_reset(sl_env, seeded_learnings):
    """Self-learning state lives on disk, not in memory. After indexing a
    handful of records, a fresh _load_db() call (simulating a process
    restart) returns exactly the same content."""
    sl = sl_env.sl

    # Capture IDs before
    before_ids = {l["id"] for l in seeded_learnings}

    # Force a reload from disk — this simulates a fresh process start
    fresh = sl._load_db()
    after_ids = {l["id"] for l in fresh["learnings"]}

    assert before_ids == after_ids
    assert fresh["version"] == sl.SCHEMA_VERSION


# ──────────────────────────────────────────────────────────────────────────────
# L-PERS-02 — corrupt JSON file is handled gracefully
# ──────────────────────────────────────────────────────────────────────────────
def test_L_PERS_02_corrupt_json_starts_fresh(sl_env):
    """If the learnings JSON file is unreadable / not valid JSON, _load_db
    returns a default empty structure rather than crashing. Subsequent
    writes succeed and overwrite the corrupt content."""
    sl = sl_env.sl
    sl_env.learnings_file.write_text("{ this is not valid json",
                                     encoding="utf-8")

    db = sl._load_db()
    assert db == {"version": sl.SCHEMA_VERSION, "learnings": []}

    # Recording works afterwards — the corrupt content is replaced cleanly
    sl.record_learning(title="recovery", content="x")
    fresh = json.loads(sl_env.learnings_file.read_text(encoding="utf-8"))
    assert len(fresh["learnings"]) == 1


# ──────────────────────────────────────────────────────────────────────────────
# L-PERS-03 — atomic save (tmp file + replace)
# ──────────────────────────────────────────────────────────────────────────────
def test_L_PERS_03_save_does_not_leave_tmp_files(sl_env, seeded_learnings):
    """The atomic save uses .tmp + os.replace. After a successful save no
    .tmp file should remain in the learnings directory."""
    tmp_files = list(sl_env.learnings_dir.glob("*.tmp"))
    assert tmp_files == [], (
        f"Stray .tmp files found after save: {[t.name for t in tmp_files]}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# L-PERS-04 — reindex_all_learnings rebuilds ChromaDB from JSON
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_PERS_04_reindex_rebuilds_collection(sl_env, seeded_learnings):
    """reindex_all_learnings() reads the JSON file and rebuilds the entire
    ChromaDB collection. After deleting the collection externally, a
    reindex restores semantic searchability without re-running record_learning."""
    sl = sl_env.sl

    # Sanity — search works initially
    pre = sl.check_learned("client communication", n_results=3,
                           track_application=False)
    assert pre, "Pre-reindex search should find at least one match"

    # Wipe the ChromaDB collection externally (simulate corruption / manual
    # delete by user)
    from rag_preprocessor import get_chroma_client
    client, _ = get_chroma_client()
    try:
        client.delete_collection(name=sl.LEARNINGS_COLLECTION)
    except Exception:
        pass

    # Search now returns nothing — the JSON is intact but the index is gone
    empty = sl.check_learned("client communication", n_results=3,
                             track_application=False)
    assert not empty

    # Reindex restores searchability
    count = sl.reindex_all_learnings()
    assert count == 4, f"Should have reindexed all 4 seeded learnings; got {count}"

    restored = sl.check_learned("client communication", n_results=3,
                                track_application=False)
    assert restored, "Search should work again after reindex"


# ──────────────────────────────────────────────────────────────────────────────
# L-STATS-01 — get_learning_stats reports correct counts
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_STATS_01_stats_counts_match_db(sl_env, seeded_learnings):
    """get_learning_stats() returns counts that match the actual DB state."""
    sl = sl_env.sl
    stats = sl.get_learning_stats()

    assert stats["total"]      == 4
    assert stats["active"]     == 4
    assert stats["deprecated"] == 0
    assert stats["archived"]   == 0

    # by_category breakdown matches what we seeded
    assert stats["by_category"]["client_preference"] == 1
    assert stats["by_category"]["best_practice"]     == 1
    assert stats["by_category"]["project_insight"]   == 1
    assert stats["by_category"]["technical_note"]    == 1

    # by_source
    assert stats["by_source"]["operator"]        == 1
    assert stats["by_source"]["post_mortem"]     == 1
    assert stats["by_source"]["project_review"]  == 1
    assert stats["by_source"]["claude_detected"] == 1

    # by_outcome includes the positive/negative ones we seeded
    assert stats["by_outcome"]["positive"] == 1
    assert stats["by_outcome"]["negative"] == 1


def test_L_STATS_02_stats_on_empty_database(sl_env):
    """Stats on a fresh empty DB returns zeros, not None or KeyError."""
    sl = sl_env.sl
    stats = sl.get_learning_stats()
    assert stats["total"] == 0
    assert stats["active"] == 0
    assert stats["by_category"] == {}
    assert stats["most_applied"] == []

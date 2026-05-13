"""
Functional tests — Self-Learning semantic search (Section L-SEARCH-*)

These tests exercise check_learned(). Because check_learned is the function
Claude calls before answering anything, its correctness is the most
user-visible part of the self-learning system. A regression here means
Claude could fail to surface a known correction or apply a stored business
lesson.

What we verify
--------------
  • Semantic matching (not keyword matching) finds related content
  • Filters (category, active_only, n_results) work correctly
  • Returned similarity scores are sane and ordered descending
  • applied_count increments on real applications but NOT on browsing
  • Empty database returns empty list, never raises
"""
from __future__ import annotations

import time

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# L-SEARCH-01 — semantic match on related but not-quite-keyword query
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_SEARCH_01_semantic_match_paraphrase(sl_env, seeded_learnings):
    """Searching for a paraphrase of a known learning still finds it. The
    seeded "Client Alpha prefers email over phone" learning should surface
    when we ask "how should we contact Alpha" — different wording, same
    semantic content."""
    sl = sl_env.sl

    matches = sl.check_learned("how should we contact Alpha",
                               n_results=3, track_application=False)

    assert matches, "Semantic search should find related learnings"
    titles = [m["title"] for m in matches]
    assert "Client Alpha prefers email over phone" in titles, (
        f"Expected the Alpha learning in results. Got: {titles}"
    )


@pytest.mark.slow
def test_L_SEARCH_02_results_ordered_by_similarity(sl_env, seeded_learnings):
    """check_learned returns results in descending similarity order — the
    most relevant match first."""
    sl = sl_env.sl
    matches = sl.check_learned("HVAC permit timeline", n_results=4,
                               track_application=False)

    assert matches, "Should return at least one match"
    sims = [m["similarity"] for m in matches]
    assert sims == sorted(sims, reverse=True), (
        f"Similarities not in descending order: {sims}"
    )

    # The 'permits' learning should be the top hit
    assert matches[0]["title"] == "Always submit permits 2 weeks ahead", (
        f"Wrong top match. Order: {[m['title'] for m in matches]}"
    )


@pytest.mark.slow
def test_L_SEARCH_03_similarity_scores_in_unit_interval(sl_env, seeded_learnings):
    """All returned similarity scores are in [0, 1]. The engine uses a
    cosine-equivalent transform on ChromaDB's squared-L2 distance, and
    clamps to [0, 1] for edge cases — confirm this clamping works."""
    sl = sl_env.sl
    matches = sl.check_learned("any query about anything", n_results=10,
                               track_application=False)
    for m in matches:
        assert 0.0 <= m["similarity"] <= 1.0, (
            f"Similarity out of range: {m['similarity']} on {m['title']!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# L-SEARCH-04 — filters: category, active_only
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_SEARCH_04_filter_by_category(sl_env, seeded_learnings):
    """Category filter restricts results to the chosen category."""
    sl = sl_env.sl
    matches = sl.check_learned("project budget overrun", n_results=10,
                               category="project_insight",
                               track_application=False)

    assert matches, "Should find the Smith project lesson"
    for m in matches:
        assert m["category"] == "project_insight", (
            f"Category filter leaked: {m['title']!r} is {m['category']}"
        )


@pytest.mark.slow
def test_L_SEARCH_05_active_only_excludes_deprecated(sl_env, seeded_learnings):
    """active_only=True (the default) excludes deprecated learnings. Verify
    by deprecating one and confirming it disappears from results."""
    sl = sl_env.sl
    target = seeded_learnings[0]   # "Client Alpha prefers email"
    sl.update_learning(target["id"], {"status": "deprecated"})

    matches = sl.check_learned("contact Alpha", n_results=5,
                               active_only=True,
                               track_application=False)
    assert all(m["learning_id"] != target["id"] for m in matches), (
        "Deprecated learning leaked through active_only filter"
    )

    # But with active_only=False we should see it
    all_matches = sl.check_learned("contact Alpha", n_results=5,
                                   active_only=False,
                                   track_application=False)
    deprecated_ids = {m["learning_id"] for m in all_matches}
    assert target["id"] in deprecated_ids


# ──────────────────────────────────────────────────────────────────────────────
# L-SEARCH-06 — n_results boundary handling
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_SEARCH_06_n_results_clamped_to_valid_range(sl_env, seeded_learnings):
    """n_results is clamped to [1, 20] per the docstring."""
    sl = sl_env.sl
    # Asking for 100 should silently cap at 20 (or however many learnings
    # exist if fewer than 20)
    many = sl.check_learned("any query", n_results=100,
                            track_application=False)
    assert len(many) <= 20

    # Asking for 0 or negative gets at least 1 result if any exist
    one = sl.check_learned("any query", n_results=0,
                           track_application=False)
    assert len(one) == 1


# ──────────────────────────────────────────────────────────────────────────────
# L-SEARCH-07 — empty database returns empty list
# ──────────────────────────────────────────────────────────────────────────────
def test_L_SEARCH_07_empty_database_returns_empty_list(sl_env):
    """check_learned on an empty database returns [] without raising."""
    sl = sl_env.sl
    matches = sl.check_learned("anything", track_application=False)
    assert matches == []


# ──────────────────────────────────────────────────────────────────────────────
# L-SEARCH-08 — empty query string handled
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_SEARCH_08_empty_query_does_not_crash(sl_env, seeded_learnings):
    """Searching with an empty query string does not raise. Behaviour is
    'return whatever ChromaDB ranks closest to empty' — usually a list
    of arbitrary matches. The point is no exception."""
    sl = sl_env.sl
    matches = sl.check_learned("", n_results=3, track_application=False)
    assert isinstance(matches, list)


# ══════════════════════════════════════════════════════════════════════════════
# applied_count tracking — verifies the "did we actually use this" metric
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
# L-COUNT-01 — applied_count increments on retrieval by default
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_COUNT_01_applied_count_increments(sl_env, seeded_learnings):
    """When Claude calls check_learned in an application context (the
    default), each match's applied_count is bumped by 1 and last_applied
    is set to the current time."""
    sl = sl_env.sl

    # The permits learning starts at 0
    permits = next(l for l in seeded_learnings
                   if "permits" in l["title"].lower())
    assert permits["applied_count"] == 0

    # Run check_learned that should match it
    matches = sl.check_learned("permits lead time", n_results=5)
    assert any(m["learning_id"] == permits["id"] for m in matches), (
        "Search did not match the permits learning — pre-condition failure"
    )

    # Reload and confirm the counter advanced
    db = sl._load_db()
    updated = next(l for l in db["learnings"] if l["id"] == permits["id"])
    assert updated["applied_count"] == 1
    assert updated["last_applied"] is not None


# ──────────────────────────────────────────────────────────────────────────────
# L-COUNT-02 — track_application=False suppresses the counter bump
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_COUNT_02_browsing_does_not_inflate_counter(sl_env, seeded_learnings):
    """The GUI Learnings tab uses track_application=False so that just
    browsing the knowledge base doesn't inflate applied_count. Verify
    that calling check_learned with the flag off leaves the counters
    at 0."""
    sl = sl_env.sl
    permits = next(l for l in seeded_learnings
                   if "permits" in l["title"].lower())

    matches = sl.check_learned("permits lead time", n_results=5,
                               track_application=False)
    assert any(m["learning_id"] == permits["id"] for m in matches)

    db = sl._load_db()
    updated = next(l for l in db["learnings"] if l["id"] == permits["id"])
    assert updated["applied_count"] == 0, (
        "Browsing should not bump applied_count"
    )
    assert updated["last_applied"] is None


# ──────────────────────────────────────────────────────────────────────────────
# L-COUNT-03 — applied_count accumulates across multiple searches
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_COUNT_03_applied_count_accumulates(sl_env, seeded_learnings):
    """Multiple check_learned() calls each increment applied_count by 1
    per match. After three calls all matching the same learning, the
    count is 3."""
    sl = sl_env.sl
    permits = next(l for l in seeded_learnings
                   if "permits" in l["title"].lower())

    for _ in range(3):
        sl.check_learned("permits lead time", n_results=5)

    db = sl._load_db()
    updated = next(l for l in db["learnings"] if l["id"] == permits["id"])
    assert updated["applied_count"] == 3


# ──────────────────────────────────────────────────────────────────────────────
# L-COUNT-04 — most_applied stats reflect the counters
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_COUNT_04_most_applied_in_stats(sl_env, seeded_learnings):
    """get_learning_stats()['most_applied'] returns the top-5 most-used
    active learnings. After hitting a single learning twice, it should
    appear in most_applied with count=2."""
    sl = sl_env.sl
    permits = next(l for l in seeded_learnings
                   if "permits" in l["title"].lower())

    # Bump permits to applied_count=2
    sl.check_learned("permits lead time")
    sl.check_learned("when to submit permits")

    stats = sl.get_learning_stats()
    most_applied = stats["most_applied"]
    assert most_applied, "most_applied should not be empty"

    permits_entry = next((m for m in most_applied if m["id"] == permits["id"]),
                         None)
    assert permits_entry is not None, (
        f"Permits learning not in most_applied. Got: {most_applied}"
    )
    assert permits_entry["applied_count"] >= 2

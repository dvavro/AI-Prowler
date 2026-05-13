"""
Functional tests — Supersession & Conflict Detection (L-SUPER-* / L-CONF-*)

When a learning is replaced by a newer one (the "supersession" workflow),
the old one becomes a historical record but stops affecting active
searches. Conflict detection flags pairs that look like they might be
duplicates or contradictions so the user can review them.

These two features are operationally connected: a conflict can be
resolved EITHER by superseding one with the other, OR by explicitly
dismissing the pair as "not actually a conflict, we know about both."
"""
from __future__ import annotations

import json

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# L-SUPER-01 — supersedes_id deprecates the old learning
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_SUPER_01_supersedes_id_deprecates_old(sl_env):
    """When record_learning is called with supersedes_id, the old learning's
    status flips to deprecated and superseded_by is filled in. The new
    learning has supersedes pointing back."""
    sl = sl_env.sl

    old = sl.record_learning(
        title="Old phone for Bob: 555-0100",
        content="Bob's phone number is 555-0100.",
        category="fact_correction",
    )
    assert old["status"] == "active"

    new = sl.record_learning(
        title="Bob's phone number is 555-0200",
        content="Updated 2026-03-15: Bob's phone is 555-0200 (was 555-0100).",
        category="fact_correction",
        supersedes_id=old["id"],
    )
    assert new["status"] == "active"
    assert new["supersedes"] == old["id"]

    # Reload and check the old record
    db = sl._load_db()
    old_now = next(l for l in db["learnings"] if l["id"] == old["id"])
    assert old_now["status"] == "deprecated"
    assert old_now["superseded_by"] == new["id"]


@pytest.mark.slow
def test_L_SUPER_02_active_search_only_returns_newest(sl_env):
    """After supersession, active-only search returns only the new learning,
    never the old one — even though both still exist on disk."""
    sl = sl_env.sl

    old = sl.record_learning(
        title="Old phone for Bob 555-0100 UNIQUE_LATIN_TOKEN_OLD",
        content="Bob's phone is 555-0100. Token: UNIQUE_LATIN_TOKEN_OLD.",
        category="fact_correction",
    )
    new = sl.record_learning(
        title="Bob's phone updated UNIQUE_LATIN_TOKEN_NEW",
        content="Bob's phone is 555-0200. Token: UNIQUE_LATIN_TOKEN_NEW.",
        category="fact_correction",
        supersedes_id=old["id"],
    )

    matches = sl.check_learned("Bob phone number",
                               active_only=True, n_results=5,
                               track_application=False)
    ids = {m["learning_id"] for m in matches}
    assert new["id"] in ids
    assert old["id"] not in ids, (
        "Deprecated learning leaked into active search"
    )


# ──────────────────────────────────────────────────────────────────────────────
# L-SUPER-03 — supersession history is preserved
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_SUPER_03_supersession_chain_visible_with_inactive_filter(sl_env):
    """include_deprecated/active_only=False returns the full chain. A user
    auditing the history of a fact can see all versions in chronological
    order."""
    sl = sl_env.sl

    v1 = sl.record_learning(
        title="Estimate process v1 UNIQUE_CHAIN_TOKEN",
        content="Send estimates within 48 hours. Token UNIQUE_CHAIN_TOKEN.",
        category="best_practice",
    )
    v2 = sl.record_learning(
        title="Estimate process v2 UNIQUE_CHAIN_TOKEN",
        content="Send estimates within 24 hours. Token UNIQUE_CHAIN_TOKEN.",
        category="best_practice",
        supersedes_id=v1["id"],
    )
    v3 = sl.record_learning(
        title="Estimate process v3 UNIQUE_CHAIN_TOKEN",
        content="Send estimates same-day when possible. Token UNIQUE_CHAIN_TOKEN.",
        category="best_practice",
        supersedes_id=v2["id"],
    )

    # All three versions visible when active_only=False
    matches = sl.check_learned("estimate process",
                               active_only=False, n_results=10,
                               track_application=False)
    ids = {m["learning_id"] for m in matches}
    assert {v1["id"], v2["id"], v3["id"]}.issubset(ids), (
        f"Not all chain versions returned. Got: {ids}"
    )

    # And only v3 visible when active_only=True
    active = sl.check_learned("estimate process",
                              active_only=True, n_results=10,
                              track_application=False)
    active_ids = {m["learning_id"] for m in active}
    assert active_ids == {v3["id"]}


# ══════════════════════════════════════════════════════════════════════════════
# Conflict detection
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
# L-CONF-01 — semantically similar pairs get flagged above threshold
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_CONF_01_similar_pairs_flagged(sl_env):
    """Two learnings about the same topic with different statements get
    flagged by find_conflicts() because their semantic similarity is high."""
    sl = sl_env.sl

    a = sl.record_learning(
        title="Always use Phillips screwdriver for Client X panels",
        content="When working on Client X's electrical panels, ALWAYS use "
                "a Phillips head screwdriver. The screws are #2 Phillips and "
                "stripping them with a flathead is a known failure mode.",
        category="technical_note",
        tags=["client-x", "tools"],
    )
    b = sl.record_learning(
        title="Use a flathead screwdriver on Client X panels",
        content="Client X's electrical panels use slotted screws — always "
                "bring a flathead. Phillips will not fit and risks damaging "
                "the screw heads.",
        category="technical_note",
        tags=["client-x", "tools"],
    )

    conflicts = sl.find_conflicts(threshold=0.6)
    pair_ids = [{c["a"]["id"], c["b"]["id"]} for c in conflicts]
    assert {a["id"], b["id"]} in pair_ids, (
        f"Contradictory pair should have been flagged. Got: {pair_ids}"
    )


@pytest.mark.slow
def test_L_CONF_02_unrelated_pairs_not_flagged(sl_env):
    """Two learnings about unrelated topics don't get flagged at the
    default threshold."""
    sl = sl_env.sl

    sl.record_learning(
        title="HVAC filter brand recommendation",
        content="For residential systems, install Filtrete MPR 1500 every "
                "90 days. Higher MPR ratings restrict airflow.",
        category="best_practice",
        tags=["hvac"],
    )
    sl.record_learning(
        title="Slack timezone for team standups",
        content="All standups occur at 09:00 Eastern. Update your Slack "
                "profile to display Eastern Time so reminders fire correctly.",
        category="process_improvement",
        tags=["team", "comms"],
    )

    conflicts = sl.find_conflicts()   # default threshold
    assert conflicts == [], (
        f"Unrelated pair was flagged as a conflict. Got: {conflicts}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# L-CONF-03 — supersession-linked pairs are excluded
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_CONF_03_supersession_link_excludes_from_conflicts(sl_env):
    """If two learnings are linked via supersedes/superseded_by, they
    should NOT show up in conflict results. The link means the user has
    already resolved the relationship between them."""
    sl = sl_env.sl

    old = sl.record_learning(
        title="Old phone for Bob: 555-0100 PHONE_CONFLICT_UNIQUE",
        content="Bob 555-0100. PHONE_CONFLICT_UNIQUE.",
        category="fact_correction",
    )
    new = sl.record_learning(
        title="Bob's phone is 555-0200 PHONE_CONFLICT_UNIQUE",
        content="Bob 555-0200 — updated. PHONE_CONFLICT_UNIQUE.",
        category="fact_correction",
        supersedes_id=old["id"],
    )

    # The deprecated old learning is filtered out by active-only at the
    # conflict-detection level anyway, but we want to confirm the link
    # behaviour even with active_only=False semantics here. find_conflicts
    # only looks at active learnings (per its implementation), so we
    # reactivate the old one to expose the linkage suppression.
    sl.update_learning(old["id"], {"status": "active"})

    conflicts = sl.find_conflicts(threshold=0.5)
    pair_ids = [{c["a"]["id"], c["b"]["id"]} for c in conflicts]
    assert {old["id"], new["id"]} not in pair_ids, (
        "Supersession link should suppress conflict flag, but pair was reported"
    )


# ──────────────────────────────────────────────────────────────────────────────
# L-CONF-04 — dismissed pairs stay dismissed
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_CONF_04_dismissed_pair_not_reflagged(sl_env):
    """After a user dismisses a flagged pair (saying "we know about both,
    leave us alone"), future find_conflicts() calls don't report it again."""
    sl = sl_env.sl

    a = sl.record_learning(
        title="Use Phillips on Client X panels DISMISS_TOKEN",
        content="Phillips screwdriver for Client X. DISMISS_TOKEN.",
        category="technical_note",
    )
    b = sl.record_learning(
        title="Use flathead on Client X panels DISMISS_TOKEN",
        content="Flathead screwdriver for Client X. DISMISS_TOKEN.",
        category="technical_note",
    )

    # First scan picks it up
    pre = sl.find_conflicts(threshold=0.5)
    assert any({c["a"]["id"], c["b"]["id"]} == {a["id"], b["id"]}
               for c in pre)

    # Dismiss it
    result = sl.dismiss_conflict(a["id"], b["id"])
    assert result is True

    # Future scans don't report it
    post = sl.find_conflicts(threshold=0.5)
    assert not any({c["a"]["id"], c["b"]["id"]} == {a["id"], b["id"]}
                   for c in post), (
        "Dismissed pair was re-flagged"
    )


@pytest.mark.slow
def test_L_CONF_05_clear_dismissal_restores_flag(sl_env):
    """clear_conflict_dismissal undoes a dismissal — the pair shows up again."""
    sl = sl_env.sl

    a = sl.record_learning(
        title="Statement A CLEAR_DISMISS_TOKEN",
        content="A says one thing. CLEAR_DISMISS_TOKEN.",
        category="technical_note",
    )
    b = sl.record_learning(
        title="Statement B CLEAR_DISMISS_TOKEN",
        content="B says the opposite thing. CLEAR_DISMISS_TOKEN.",
        category="technical_note",
    )

    sl.dismiss_conflict(a["id"], b["id"])
    pre = sl.find_conflicts(threshold=0.5)
    assert not any({c["a"]["id"], c["b"]["id"]} == {a["id"], b["id"]}
                   for c in pre)

    sl.clear_conflict_dismissal(a["id"], b["id"])
    post = sl.find_conflicts(threshold=0.5)
    assert any({c["a"]["id"], c["b"]["id"]} == {a["id"], b["id"]}
               for c in post), (
        "After clearing dismissal, pair should be flagged again"
    )


# ──────────────────────────────────────────────────────────────────────────────
# L-CONF-06 — threshold is configurable and persists
# ──────────────────────────────────────────────────────────────────────────────
def test_L_CONF_06_threshold_persists(sl_env):
    """set_conflict_threshold writes to disk; get_conflict_threshold reads
    it back correctly. Clamped to the supported range."""
    sl = sl_env.sl

    # Round-trip
    saved = sl.set_conflict_threshold(0.85)
    assert saved == 0.85
    assert sl.get_conflict_threshold() == 0.85

    # Clamping above max
    saved = sl.set_conflict_threshold(1.5)
    assert saved == sl.MAX_CONFLICT_THRESHOLD

    # Clamping below min
    saved = sl.set_conflict_threshold(0.0)
    assert saved == sl.MIN_CONFLICT_THRESHOLD


# ──────────────────────────────────────────────────────────────────────────────
# L-CONF-07 — empty database / single-record DB returns no conflicts
# ──────────────────────────────────────────────────────────────────────────────
def test_L_CONF_07_empty_db_no_conflicts(sl_env):
    sl = sl_env.sl
    assert sl.find_conflicts() == []


@pytest.mark.slow
def test_L_CONF_08_single_record_no_conflicts(sl_env):
    """Can't conflict with yourself."""
    sl = sl_env.sl
    sl.record_learning(title="solo", content="alone in the world",
                       category="general")
    assert sl.find_conflicts(threshold=0.5) == []

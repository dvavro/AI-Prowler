"""
test_learning_ownership.py — Learning ownership & modification gate tests
=========================================================================
Tests for the per-learning ownership model added in v7.0.1:

  • recorded_by_id is stamped on each learning at record time (the bearer
    token ID of the recording user, distinct from the display name).
  • delete_learning / update_learning enforce:
      - Personal mode (no user) → always allowed.
      - Owner role              → may modify ANY learning.
      - Manager (can_manage_users=True) → may modify any EMPLOYEE learning
                                         but NEVER the owner's learning.
      - Staff / field_crew      → may only modify their OWN learnings.
      - Nobody except the owner → may touch a learning recorded by the owner.

New helpers tested:
  _can_modify_learning(actor, learning, owner_id) → (bool, reason)
  self_learning.get_learning_by_id(id)             → dict | None
  self_learning._save_db_for_learning(learning)    → persists a single record

Run:
    pytest tests/test_learning_ownership.py -v
"""

import sys
import pytest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ai_prowler_mcp import (
    _can_modify_learning,
    _user_has_role,
)


# ═══════════════════════════════════════════════════════════════════════════
# Shared user fixtures (match users.json schema; id = bearer token key)
# ═══════════════════════════════════════════════════════════════════════════

OWNER_ID   = "tok-owner-david"
MANAGER_ID = "tok-manager-jamie"
STAFF_ID   = "tok-staff-alice"
CREW_ID    = "tok-crew-bob"

OWNER = {
    "id": OWNER_ID, "role": "owner", "name": "David Vavro",
    "status": "active", "can_manage_users": True,
}
MANAGER = {
    "id": MANAGER_ID, "role": "manager", "name": "Jamie V",
    "status": "active", "can_manage_users": True,
}
STAFF = {
    "id": STAFF_ID, "role": "staff", "name": "Alice Smith",
    "status": "active", "can_manage_users": False,
}
CREW = {
    "id": CREW_ID, "role": "field_crew", "name": "Bob Jones",
    "status": "active", "can_manage_users": False,
}


def _make_learning(recorded_by_id: str, title: str = "Test learning") -> dict:
    """Build a minimal learning dict with the given owner id."""
    return {
        "id":             "fake-uuid-1234",
        "title":          title,
        "content":        "Some content.",
        "recorded_by":    "Display Name",
        "recorded_by_id": recorded_by_id,
        "status":         "active",
    }


# ════════════════════════════════════════════════════════════════════════════
# SECTION A — Personal mode (no user context)
# ════════════════════════════════════════════════════════════════════════════

class TestPersonalMode:
    """In personal mode actor=None — all operations allowed."""

    def test_none_actor_can_modify_unattributed_learning(self):
        learning = _make_learning(recorded_by_id="")
        allowed, reason = _can_modify_learning(None, learning, None)
        assert allowed, f"Personal mode must always allow. reason={reason}"

    def test_none_actor_can_modify_attributed_learning(self):
        learning = _make_learning(recorded_by_id=STAFF_ID)
        allowed, _ = _can_modify_learning(None, learning, OWNER_ID)
        assert allowed

    def test_none_actor_can_modify_owner_learning(self):
        learning = _make_learning(recorded_by_id=OWNER_ID)
        allowed, _ = _can_modify_learning(None, learning, OWNER_ID)
        assert allowed

    def test_none_actor_allowed_even_with_none_learning(self):
        """Personal mode short-circuits before checking the learning."""
        allowed, _ = _can_modify_learning(None, None, None)
        assert allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION B — Owner role: unrestricted
# ════════════════════════════════════════════════════════════════════════════

class TestOwnerModifyLearning:

    def test_owner_can_modify_own_learning(self):
        learning = _make_learning(OWNER_ID)
        allowed, _ = _can_modify_learning(OWNER, learning, OWNER_ID)
        assert allowed

    def test_owner_can_modify_staff_learning(self):
        learning = _make_learning(STAFF_ID)
        allowed, _ = _can_modify_learning(OWNER, learning, OWNER_ID)
        assert allowed

    def test_owner_can_modify_manager_learning(self):
        learning = _make_learning(MANAGER_ID)
        allowed, _ = _can_modify_learning(OWNER, learning, OWNER_ID)
        assert allowed

    def test_owner_can_modify_crew_learning(self):
        learning = _make_learning(CREW_ID)
        allowed, _ = _can_modify_learning(OWNER, learning, OWNER_ID)
        assert allowed

    def test_owner_can_modify_unattributed_learning(self):
        learning = _make_learning(recorded_by_id="")
        allowed, _ = _can_modify_learning(OWNER, learning, OWNER_ID)
        assert allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION C — Manager: employee learnings yes, owner learning NO
# ════════════════════════════════════════════════════════════════════════════

class TestManagerModifyLearning:

    def test_manager_can_modify_staff_learning(self):
        """Offboarding: manager edits/deletes departing employee's learnings."""
        learning = _make_learning(STAFF_ID)
        allowed, _ = _can_modify_learning(MANAGER, learning, OWNER_ID)
        assert allowed

    def test_manager_can_modify_crew_learning(self):
        learning = _make_learning(CREW_ID)
        allowed, _ = _can_modify_learning(MANAGER, learning, OWNER_ID)
        assert allowed

    def test_manager_can_modify_own_learning(self):
        learning = _make_learning(MANAGER_ID)
        allowed, _ = _can_modify_learning(MANAGER, learning, OWNER_ID)
        assert allowed

    def test_manager_can_modify_unattributed_learning(self):
        learning = _make_learning(recorded_by_id="")
        allowed, _ = _can_modify_learning(MANAGER, learning, OWNER_ID)
        assert allowed

    def test_rogue_manager_cannot_modify_owner_learning(self):
        """
        CRITICAL: A manager must NEVER be able to delete or update the
        owner's learning. This is the rogue-admin protection for the
        learning store — mirrors _can_manage_user_data's owner protection.
        """
        learning = _make_learning(OWNER_ID)
        allowed, reason = _can_modify_learning(MANAGER, learning, OWNER_ID)
        assert not allowed, (
            f"SECURITY VIOLATION: manager was permitted to modify owner's "
            f"learning. reason='{reason}'"
        )

    def test_manager_denied_when_owner_id_unknown(self):
        """
        Fail-closed: if owner_id is None, manager cannot modify ANY
        attributed learning — we can't rule out it belongs to the owner.
        """
        learning = _make_learning(STAFF_ID)
        allowed, reason = _can_modify_learning(MANAGER, learning, owner_id=None)
        assert not allowed, (
            f"Manager should be denied when owner_id is unknown (fail-closed). "
            f"reason='{reason}'"
        )

    def test_manager_denied_unattributed_when_owner_unknown(self):
        """Even an unattributed learning should be denied when we can't
        determine the owner — fail-closed consistency."""
        learning = _make_learning(recorded_by_id=STAFF_ID)
        allowed, _ = _can_modify_learning(MANAGER, learning, owner_id=None)
        assert not allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION D — Staff: own learnings only
# ════════════════════════════════════════════════════════════════════════════

class TestStaffModifyLearning:

    def test_staff_can_modify_own_learning(self):
        learning = _make_learning(STAFF_ID)
        allowed, _ = _can_modify_learning(STAFF, learning, OWNER_ID)
        assert allowed

    def test_staff_cannot_modify_another_staff_learning(self):
        """Alice cannot edit or delete Carol's learning."""
        other_staff_id = "tok-staff-carol"
        learning = _make_learning(other_staff_id)
        allowed, reason = _can_modify_learning(STAFF, learning, OWNER_ID)
        assert not allowed, (
            f"Staff should not modify another employee's learning. "
            f"reason='{reason}'"
        )

    def test_staff_cannot_modify_crew_learning(self):
        learning = _make_learning(CREW_ID)
        allowed, _ = _can_modify_learning(STAFF, learning, OWNER_ID)
        assert not allowed

    def test_staff_cannot_modify_manager_learning(self):
        learning = _make_learning(MANAGER_ID)
        allowed, _ = _can_modify_learning(STAFF, learning, OWNER_ID)
        assert not allowed

    def test_staff_cannot_modify_owner_learning(self):
        learning = _make_learning(OWNER_ID)
        allowed, reason = _can_modify_learning(STAFF, learning, OWNER_ID)
        assert not allowed, (
            f"Staff must never modify owner's learning. reason='{reason}'"
        )

    def test_staff_can_modify_unattributed_learning(self):
        """Legacy / personal-mode learnings with no recorded_by_id
        are not claimed by anyone — staff may touch them."""
        learning = _make_learning(recorded_by_id="")
        allowed, _ = _can_modify_learning(STAFF, learning, OWNER_ID)
        assert allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION E — Field crew: same "own only" rules as staff
# ════════════════════════════════════════════════════════════════════════════

class TestFieldCrewModifyLearning:

    def test_crew_can_modify_own_learning(self):
        learning = _make_learning(CREW_ID)
        allowed, _ = _can_modify_learning(CREW, learning, OWNER_ID)
        assert allowed

    def test_crew_cannot_modify_staff_learning(self):
        learning = _make_learning(STAFF_ID)
        allowed, _ = _can_modify_learning(CREW, learning, OWNER_ID)
        assert not allowed

    def test_crew_cannot_modify_manager_learning(self):
        learning = _make_learning(MANAGER_ID)
        allowed, _ = _can_modify_learning(CREW, learning, OWNER_ID)
        assert not allowed

    def test_crew_cannot_modify_owner_learning(self):
        learning = _make_learning(OWNER_ID)
        allowed, _ = _can_modify_learning(CREW, learning, OWNER_ID)
        assert not allowed

    def test_crew_can_modify_unattributed_learning(self):
        learning = _make_learning(recorded_by_id="")
        allowed, _ = _can_modify_learning(CREW, learning, OWNER_ID)
        assert allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION F — None / missing learning edge cases
# ════════════════════════════════════════════════════════════════════════════

class TestMissingLearning:

    def test_none_learning_is_denied_for_staff(self):
        """If the learning doesn't exist, the gate denies rather than crashing."""
        allowed, reason = _can_modify_learning(STAFF, None, OWNER_ID)
        assert not allowed
        assert "not found" in reason.lower()

    def test_none_learning_is_denied_for_manager(self):
        allowed, _ = _can_modify_learning(MANAGER, None, OWNER_ID)
        assert not allowed

    def test_none_learning_is_denied_for_owner(self):
        """Even the owner gets a clean denial (not a crash) on missing learning."""
        allowed, reason = _can_modify_learning(OWNER, None, OWNER_ID)
        assert not allowed
        assert "not found" in reason.lower()


# ════════════════════════════════════════════════════════════════════════════
# SECTION G — self_learning helpers: get_learning_by_id + _save_db_for_learning
# ════════════════════════════════════════════════════════════════════════════

class TestSelfLearningHelpers:
    """Verify the new helpers in self_learning.py.
    Uses a temp file; no ChromaDB connection needed."""

    def _setup_db(self, tmp_path, learnings: list, monkeypatch):
        import json, self_learning as sl
        db_file = tmp_path / "self_learning_data.json"
        db_file.write_text(
            json.dumps({"version": "1.0", "learnings": learnings}),
            encoding="utf-8")
        monkeypatch.setattr(sl, "LEARNINGS_FILE", db_file)
        monkeypatch.setattr(sl, "LEARNINGS_DIR",  tmp_path)
        monkeypatch.setattr(sl, "_index_learning", lambda l: None)
        return db_file

    def test_get_learning_by_id_finds_record(self, tmp_path, monkeypatch):
        import self_learning as sl
        sample = {
            "id": "abc-123", "title": "Test", "content": "x",
            "recorded_by": "Alice", "recorded_by_id": STAFF_ID, "status": "active",
        }
        self._setup_db(tmp_path, [sample], monkeypatch)
        result = sl.get_learning_by_id("abc-123")
        assert result is not None
        assert result["id"] == "abc-123"
        assert result["recorded_by_id"] == STAFF_ID

    def test_get_learning_by_id_returns_none_for_missing(self, tmp_path, monkeypatch):
        import self_learning as sl
        self._setup_db(tmp_path, [], monkeypatch)
        assert sl.get_learning_by_id("does-not-exist") is None

    def test_get_learning_by_id_correct_record_among_multiple(self, tmp_path, monkeypatch):
        import self_learning as sl
        learnings = [
            {"id": "aaa", "title": "A", "content": "x",
             "recorded_by": "Alice", "recorded_by_id": STAFF_ID, "status": "active"},
            {"id": "bbb", "title": "B", "content": "y",
             "recorded_by": "Bob",   "recorded_by_id": CREW_ID,  "status": "active"},
        ]
        self._setup_db(tmp_path, learnings, monkeypatch)
        result = sl.get_learning_by_id("bbb")
        assert result is not None
        assert result["recorded_by_id"] == CREW_ID

    def test_save_db_for_learning_persists_recorded_by_id(self, tmp_path, monkeypatch):
        import json, self_learning as sl
        learning = {
            "id": "stamp-uuid", "title": "Stamp test", "content": "x",
            "recorded_by": "Alice", "recorded_by_id": "",
            "status": "active", "tags": [], "dismissed_conflicts": [],
        }
        db_file = self._setup_db(tmp_path, [learning], monkeypatch)

        # Stamp the owner id and persist
        learning["recorded_by_id"] = STAFF_ID
        sl._save_db_for_learning(learning)

        saved = json.loads(db_file.read_text(encoding="utf-8"))
        found = next(
            (l for l in saved["learnings"] if l["id"] == "stamp-uuid"), None)
        assert found is not None
        assert found["recorded_by_id"] == STAFF_ID, (
            "_save_db_for_learning must persist recorded_by_id to JSON"
        )

    def test_save_db_for_learning_noop_on_missing_id(self, tmp_path, monkeypatch):
        """Saving a learning whose id doesn't exist in the DB is a silent noop."""
        import json, self_learning as sl
        db_file = self._setup_db(tmp_path, [], monkeypatch)
        ghost = {"id": "ghost-id", "title": "Ghost", "recorded_by_id": STAFF_ID}
        sl._save_db_for_learning(ghost)  # must not raise
        saved = json.loads(db_file.read_text(encoding="utf-8"))
        assert saved["learnings"] == []

    def test_new_learning_has_recorded_by_id_field(self, tmp_path, monkeypatch):
        """record_learning() must include recorded_by_id in the returned dict."""
        import self_learning as sl
        db_file = tmp_path / "self_learning_data.json"
        monkeypatch.setattr(sl, "LEARNINGS_FILE", db_file)
        monkeypatch.setattr(sl, "LEARNINGS_DIR",  tmp_path)
        monkeypatch.setattr(sl, "_index_learning", lambda l: None)

        result = sl.record_learning(title="Schema check", content="Test.")
        assert "recorded_by_id" in result, (
            "recorded_by_id must be present in every new learning record"
        )
        assert result["recorded_by_id"] == "", (
            "recorded_by_id defaults to empty string (personal mode)"
        )


# ════════════════════════════════════════════════════════════════════════════
# SECTION H — Denial reason string quality
# ════════════════════════════════════════════════════════════════════════════

class TestDenialReasons:
    """Denied decisions must have clear, human-readable reason strings."""

    def test_manager_denied_owner_reason_mentions_owner(self):
        learning = _make_learning(OWNER_ID)
        _, reason = _can_modify_learning(MANAGER, learning, OWNER_ID)
        assert "owner" in reason.lower()

    def test_staff_denied_other_user_reason_is_descriptive(self):
        learning = _make_learning("tok-some-other-user")
        _, reason = _can_modify_learning(STAFF, learning, OWNER_ID)
        assert reason  # non-empty
        assert any(w in reason.lower() for w in ("author", "another user", "belongs"))

    def test_fail_closed_reason_mentions_owner_id_unknown(self):
        learning = _make_learning(STAFF_ID)
        _, reason = _can_modify_learning(MANAGER, learning, owner_id=None)
        assert "owner" in reason.lower()

    def test_none_learning_reason_says_not_found(self):
        _, reason = _can_modify_learning(STAFF, None, OWNER_ID)
        assert "not found" in reason.lower()

    def test_all_allowed_decisions_have_non_empty_reason(self):
        cases = [
            (None,    _make_learning(""),       None),
            (OWNER,   _make_learning(STAFF_ID), OWNER_ID),
            (MANAGER, _make_learning(STAFF_ID), OWNER_ID),
            (STAFF,   _make_learning(STAFF_ID), OWNER_ID),
            (CREW,    _make_learning(CREW_ID),  OWNER_ID),
        ]
        for actor, learning, oid in cases:
            allowed, reason = _can_modify_learning(actor, learning, oid)
            role = (actor or {}).get("role", "personal")
            assert allowed,  f"Expected allowed for {role}"
            assert reason,   f"Allowed decision for {role} must include a reason"

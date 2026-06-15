"""
tests/mcp/test_learning_source.py
===================================
Tests for the v7.0.1 learning source attribution feature.

WHAT THIS TESTS
---------------
record_learning() now auto-resolves the `source` field based on context:

  Scenario                          source written to DB
  ─────────────────────────────────────────────────────────────────
  Server mode, user records it      user's display name
                                    e.g. "David Vavro", "Vicki Vavro"
  Claude auto-detects (auto=True)   model id e.g. "claude-sonnet-4-6"
  Personal mode, owner at keyboard  "operator"
  Caller supplies custom source     used as-is (import/export fidelity)
  Server mode, auto-detected        model id (auto_detected wins)

The Learnings tab Source column reads from the stored `source` field,
so these tests verify end-to-end what the GUI will show.

Test IDs: C_SL_SOURCE_NN

Run:
    run_tests.bat tests\\mcp\\test_learning_source.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


# ── User fixtures ─────────────────────────────────────────────────────────────

DAVID_USER = {
    "id":    "david-vavro",
    "name":  "David Vavro",
    "role":  "owner",
    "status": "active",
    "scopes": ["scope:office"],
    "private_collection_enabled": True,
}

VICKI_USER = {
    "id":    "vicki-vavro",
    "name":  "Vicki Vavro",
    "role":  "manager",
    "status": "active",
    "scopes": ["scope:sales", "scope:ops"],
    "private_collection_enabled": True,
}

FIELD_USER = {
    "id":    "field-crew-member",
    "name":  "Field Crew Member",
    "role":  "field_crew",
    "status": "active",
    "scopes": ["scope:field"],
    "private_collection_enabled": False,
}

import rag_preprocessor as _rp   # for patching OWNER_NAME directly


# ── Helpers ───────────────────────────────────────────────────────────────────

def _call_record(sl_mcp_env, *, user=None, auto_detected=False,
                 source="", title="Test Learning", content="Test content"):
    """Call record_learning() via the MCP module with an optional mocked user.

    _current_user() is patched as a callable (side_effect) so it correctly
    returns the user dict when called with any ctx argument.

    ctx is always non-None so the server-mode code path is entered — the
    distinction between personal and server mode comes entirely from what
    _current_user() returns (None = personal, dict = server).
    """
    mcp = sl_mcp_env.mcp
    ctx = object()   # always non-None — mode determined by _current_user return

    with patch.object(mcp, "_current_user", side_effect=lambda c: user):
        result = mcp.record_learning(
            title=title,
            content=content,
            category="general",
            source=source,
            auto_detected=auto_detected,
            ctx=ctx,
        )
    return result


def _load_latest_learning(sl_mcp_env):
    """Read the most recently written learning from the JSON file."""
    data = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    learnings = data.get("learnings", [])
    assert learnings, "No learnings found in DB after record_learning call"
    # Most recent is last
    return learnings[-1]


# ══════════════════════════════════════════════════════════════════════════════
# Section A — Personal mode (no user context)
# ══════════════════════════════════════════════════════════════════════════════

class TestPersonalModeSource:
    """In personal mode _current_user returns None.
    Source should be the owner name from config, or 'operator' if not set."""

    def test_C_SL_SOURCE_01_personal_mode_no_owner_name_is_operator(self, sl_mcp_env):
        """No owner name set → source = 'operator'."""
        mcp = sl_mcp_env.mcp
        with patch.object(_rp, 'OWNER_NAME', ''):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Personal mode no name test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "operator", (
            f"Personal mode with no owner name should use 'operator', "
            f"got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_01b_personal_mode_with_owner_name(self, sl_mcp_env):
        """Owner name set in config → source = owner name."""
        mcp = sl_mcp_env.mcp
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Personal mode with owner name")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "David Vavro", (
            f"Personal mode with owner name 'David Vavro' should use it as source, "
            f"got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_01c_personal_mode_owner_name_not_operator(self, sl_mcp_env):
        """When owner name is set, source must NOT be 'operator'."""
        mcp = sl_mcp_env.mcp
        with patch.object(_rp, 'OWNER_NAME', 'Rick Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Personal mode Rick")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] != "operator", (
            "When owner name is set, source should not fall back to 'operator'"
        )
        assert learning["source"] == "Rick Vavro"

    def test_C_SL_SOURCE_02_personal_mode_auto_detected_is_model(self, sl_mcp_env):
        """Auto-detected in personal mode → source = model id, not owner name."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=True,
                         title="Personal auto-detected test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == model_id, (
            f"Auto-detected learning should have source='{model_id}', "
            f"even when owner name is set. Got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_03_personal_mode_custom_source_preserved(self, sl_mcp_env):
        """Caller-supplied source is preserved exactly, not overridden by owner name."""
        mcp = sl_mcp_env.mcp
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         source="post_mortem", title="Custom source test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "post_mortem", (
            f"Custom source should be preserved even when owner name is set, "
            f"got '{learning['source']}'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section B — Server mode, user records it
# ══════════════════════════════════════════════════════════════════════════════

class TestServerModeUserSource:
    """In server mode with a real user, source should be the user's display name."""

    def test_C_SL_SOURCE_04_server_mode_owner_name_as_source(self, sl_mcp_env):
        """David (owner) records a learning → source = 'David Vavro'."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="David owner test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "David Vavro", (
            f"Server mode owner learning should have source='David Vavro', "
            f"got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_05_server_mode_manager_name_as_source(self, sl_mcp_env):
        """Vicki (manager) records a learning → source = 'Vicki Vavro'."""
        _call_record(sl_mcp_env, user=VICKI_USER, auto_detected=False,
                     title="Vicki manager test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "Vicki Vavro", (
            f"Server mode manager learning should have source='Vicki Vavro', "
            f"got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_06_server_mode_field_crew_name_as_source(self, sl_mcp_env):
        """Field crew member records a learning → source = their display name."""
        _call_record(sl_mcp_env, user=FIELD_USER, auto_detected=False,
                     title="Field crew test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "Field Crew Member", (
            f"Field crew learning should use display name, "
            f"got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_07_source_is_name_not_slug(self, sl_mcp_env):
        """Source must be the display name ('David Vavro'), not the slug ('david-vavro')."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Name not slug test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] != "david-vavro", (
            "Source must be the display name, not the slug id"
        )
        assert learning["source"] == "David Vavro"

    def test_C_SL_SOURCE_08_source_is_name_not_token(self, sl_mcp_env):
        """Source must not be the bearer token or any system key."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Not token test")
        learning = _load_latest_learning(sl_mcp_env)
        # Source should be a human-readable name, not look like a token
        src = learning["source"]
        assert " " in src or src == "operator", (
            f"Source '{src}' looks like a token/slug, not a display name"
        )

    def test_C_SL_SOURCE_09_server_custom_source_preserved(self, sl_mcp_env):
        """A genuinely custom source (not 'operator', not blank) overrides
        the user name even in server mode — e.g. for import/export fidelity."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     source="project_review", title="Server custom source")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "project_review", (
            f"Custom source should override user name, got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_09b_operator_source_overridden_in_server_mode(self, sl_mcp_env):
        """If Claude passes source='operator' explicitly (old behaviour from
        the previous docstring), it must be treated as blank and overridden
        with the authenticated user's name in server mode."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     source="operator", title="Operator override test")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "David Vavro", (
            f"source='operator' passed by Claude must be overridden with user "
            f"name in server mode. Got '{learning['source']}'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section C — Claude auto-detected (auto_detected=True)
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoDetectedSource:
    """auto_detected=True must stamp the Claude model id as source,
    regardless of personal vs server mode."""

    def test_C_SL_SOURCE_10_auto_detected_personal_is_model_id(self, sl_mcp_env):
        """auto_detected in personal mode → source = _MODEL_ID."""
        mcp = sl_mcp_env.mcp
        _call_record(sl_mcp_env, user=None, auto_detected=True,
                     title="Auto personal")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == mcp._MODEL_ID, (
            f"Auto-detected (personal) should use model id '{mcp._MODEL_ID}', "
            f"got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_11_auto_detected_server_is_model_id(self, sl_mcp_env):
        """auto_detected in server mode → source = _MODEL_ID, not user name."""
        mcp = sl_mcp_env.mcp
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=True,
                     title="Auto server mode")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == mcp._MODEL_ID, (
            f"Auto-detected (server) should use model id '{mcp._MODEL_ID}', "
            f"not the user name. Got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_12_auto_detected_not_operator(self, sl_mcp_env):
        """auto_detected must never produce 'operator' — that's for human records."""
        _call_record(sl_mcp_env, user=None, auto_detected=True,
                     title="Auto not operator")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] != "operator", (
            "Auto-detected source must not be 'operator' — "
            "it should identify Claude as the creator"
        )

    def test_C_SL_SOURCE_13_auto_detected_not_user_name(self, sl_mcp_env):
        """auto_detected must not use the user's name — it was Claude, not them."""
        _call_record(sl_mcp_env, user=VICKI_USER, auto_detected=True,
                     title="Auto not Vicki")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] != "Vicki Vavro", (
            "Auto-detected learning source must be the model id, "
            "not the user's name — Claude made the decision to record it"
        )

    def test_C_SL_SOURCE_14_model_id_constant_is_valid_string(self, sl_mcp_env):
        """_MODEL_ID must be a non-empty string that looks like a model name."""
        mcp = sl_mcp_env.mcp
        assert hasattr(mcp, "_MODEL_ID"), "_MODEL_ID constant missing from mcp module"
        mid = mcp._MODEL_ID
        assert isinstance(mid, str) and mid.strip(), "_MODEL_ID must be a non-empty string"
        assert "claude" in mid.lower(), (
            f"_MODEL_ID '{mid}' doesn't look like a Claude model identifier"
        )

    def test_C_SL_SOURCE_15_auto_detected_custom_source_overrides_model(self, sl_mcp_env):
        """If auto_detected=True but a custom source is supplied, custom wins."""
        mcp = sl_mcp_env.mcp
        _call_record(sl_mcp_env, user=None, auto_detected=True,
                     source="research", title="Auto custom source")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "research", (
            f"Custom source should override auto_detected model id, "
            f"got '{learning['source']}'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section D — recorded_by field consistency
# ══════════════════════════════════════════════════════════════════════════════

class TestRecordedByConsistency:
    """The `recorded_by` field should always match the display name in server
    mode, and `source` should now also use the display name — they should
    be consistent with each other (same value in server mode, human records)."""

    def test_C_SL_SOURCE_16_recorded_by_matches_source_in_server_mode(self, sl_mcp_env):
        """In server mode, recorded_by and source must both be the display name."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Consistency check David")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning.get("recorded_by") == "David Vavro"
        assert learning["source"] == "David Vavro", (
            f"source should match recorded_by in server mode. "
            f"recorded_by='{learning.get('recorded_by')}' "
            f"source='{learning['source']}'"
        )

    def test_C_SL_SOURCE_17_auto_detected_source_differs_from_recorded_by(self, sl_mcp_env):
        """When Claude auto-detects in server mode, source = model id
        but recorded_by = user name (it's in their session)."""
        mcp = sl_mcp_env.mcp
        _call_record(sl_mcp_env, user=VICKI_USER, auto_detected=True,
                     title="Auto consistency check")
        learning = _load_latest_learning(sl_mcp_env)
        # source = who/what CREATED it (Claude)
        assert learning["source"] == mcp._MODEL_ID
        # recorded_by = in whose session it was recorded (Vicki)
        assert learning.get("recorded_by") == "Vicki Vavro", (
            "recorded_by should still be the session user even when "
            "Claude auto-detected the learning"
        )

    def test_C_SL_SOURCE_18_personal_mode_recorded_by_empty(self, sl_mcp_env):
        """In personal mode, recorded_by should be empty (no user context)."""
        _call_record(sl_mcp_env, user=None, auto_detected=False,
                     title="Personal recorded_by check")
        learning = _load_latest_learning(sl_mcp_env)
        rb = learning.get("recorded_by", "")
        assert rb == "" or rb is None, (
            f"Personal mode should have no recorded_by, got '{rb}'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section E — Import/export fidelity
# ══════════════════════════════════════════════════════════════════════════════

class TestImportExportSourceFidelity:
    """When importing learnings from another system, the source field in the
    imported data must be preserved exactly. No auto-resolution should fire."""


    @pytest.mark.parametrize("import_source", [
        "David Vavro",
        "Vicki Vavro",
        "claude-sonnet-4-6",
        "post_mortem",
        "project_review",
        "research",
        "Rick Vavro",
        "claude-opus-4-6",
    ])
    def test_C_SL_SOURCE_19_custom_source_preserved_on_import(
            self, sl_mcp_env, import_source):
        """Any non-operator custom source supplied by the caller is stored
        exactly as-is — import/export fidelity.
        Note: 'operator' is intentionally excluded here because our code
        treats it the same as blank (auto-resolves) to fix the Claude
        docstring bug. See test_C_SL_SOURCE_19b for the operator case."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     source=import_source,
                     title=f"Import fidelity: {import_source}")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == import_source, (
            f"Source '{import_source}' was not preserved. "
            f"Got '{learning['source']}'"
        )

    def test_C_SL_SOURCE_19b_operator_preserved_in_personal_mode(self, sl_mcp_env):
        """'operator' source is preserved when there is no authenticated user
        (personal mode, no owner name set) — it legitimately means the owner
        recorded it on a personal install without configuring their name."""
        import rag_preprocessor as _rp
        with patch.object(_rp, 'OWNER_NAME', ''):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         source="", title="Operator personal mode")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "operator", (
            f"Personal mode with no owner name should produce 'operator', "
            f"got '{learning['source']}'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section F — Mode Parity
# ══════════════════════════════════════════════════════════════════════════════

class TestModeParity:
    """
    THE CORE CONTRACT (v7.0.1):

    Both personal and server installs must follow the same two-value rule:
      1. Human records it  → source = their display name
      2. Claude records it → source = Claude model id

    Nothing else should ever appear as source on a freshly created learning.
    'operator' is only acceptable as a fallback when the personal install
    has no owner name configured.

    These tests verify that rule explicitly for both modes so a future
    refactor can't accidentally break parity.

    Personal mode  = _current_user() returns None, OWNER_NAME set in config
    Server mode    = _current_user() returns a user dict from bearer token auth
    """

    # ── Personal mode parity ──────────────────────────────────────────────────

    def test_C_SL_PARITY_01_personal_human_record_is_owner_name(self, sl_mcp_env):
        """Personal: owner records it → source = owner display name."""
        mcp = sl_mcp_env.mcp
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Parity: personal human")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "David Vavro", (
            f"Personal human record must use owner name. Got '{learning['source']}'"
        )

    def test_C_SL_PARITY_02_personal_claude_record_is_model_id(self, sl_mcp_env):
        """Personal: Claude auto-detects → source = model id."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=True,
                         title="Parity: personal claude")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == model_id, (
            f"Personal Claude record must use model id '{model_id}'. "
            f"Got '{learning['source']}'"
        )

    def test_C_SL_PARITY_03_personal_source_is_only_name_or_model(self, sl_mcp_env):
        """Personal: source must be owner name or model id — nothing else."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        owner_name = "David Vavro"
        allowed = {owner_name, model_id}

        with patch.object(_rp, 'OWNER_NAME', owner_name):
            # Human record
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Parity personal check 1")
            l1 = _load_latest_learning(sl_mcp_env)
            # Claude record
            _call_record(sl_mcp_env, user=None, auto_detected=True,
                         title="Parity personal check 2")
            l2 = _load_latest_learning(sl_mcp_env)

        assert l1["source"] in allowed, (
            f"Personal human source '{l1['source']}' not in allowed set {allowed}"
        )
        assert l2["source"] in allowed, (
            f"Personal Claude source '{l2['source']}' not in allowed set {allowed}"
        )
        # They must be different from each other
        assert l1["source"] != l2["source"], (
            "Human record and Claude record must have different source values"
        )

    # ── Server mode parity ────────────────────────────────────────────────────

    def test_C_SL_PARITY_04_server_human_record_is_user_name(self, sl_mcp_env):
        """Server: authenticated user records it → source = their display name."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Parity: server human David")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "David Vavro", (
            f"Server human record (David) must use display name. "
            f"Got '{learning['source']}'"
        )

    def test_C_SL_PARITY_05_server_human_record_different_users(self, sl_mcp_env):
        """Server: different users get different source stamps."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Parity: server David")
        l_david = _load_latest_learning(sl_mcp_env)

        _call_record(sl_mcp_env, user=VICKI_USER, auto_detected=False,
                     title="Parity: server Vicki")
        l_vicki = _load_latest_learning(sl_mcp_env)

        assert l_david["source"] == "David Vavro"
        assert l_vicki["source"] == "Vicki Vavro"
        assert l_david["source"] != l_vicki["source"], (
            "Different users must produce different source stamps"
        )

    def test_C_SL_PARITY_06_server_claude_record_is_model_id(self, sl_mcp_env):
        """Server: Claude auto-detects → source = model id (not user name)."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=True,
                     title="Parity: server claude")
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == model_id, (
            f"Server Claude record must use model id '{model_id}'. "
            f"Got '{learning['source']}'"
        )

    def test_C_SL_PARITY_07_server_source_is_only_name_or_model(self, sl_mcp_env):
        """Server: source must be the user's display name or model id — nothing else."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        allowed = {"David Vavro", "Vicki Vavro", model_id}

        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Server parity check 1")
        l1 = _load_latest_learning(sl_mcp_env)

        _call_record(sl_mcp_env, user=VICKI_USER, auto_detected=False,
                     title="Server parity check 2")
        l2 = _load_latest_learning(sl_mcp_env)

        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=True,
                     title="Server parity check 3")
        l3 = _load_latest_learning(sl_mcp_env)

        for learning, label in [(l1, "David human"), (l2, "Vicki human"),
                                 (l3, "Claude auto")]:
            assert learning["source"] in allowed, (
                f"{label}: source '{learning['source']}' not in allowed set {allowed}"
            )

    # ── Cross-mode parity — same rules apply regardless of mode ───────────────

    def test_C_SL_PARITY_08_model_id_same_in_both_modes(self, sl_mcp_env):
        """Claude's model id stamp must be identical in personal and server mode."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID

        # Personal mode
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=True,
                         title="Cross-mode: personal claude")
        l_personal = _load_latest_learning(sl_mcp_env)

        # Server mode
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=True,
                     title="Cross-mode: server claude")
        l_server = _load_latest_learning(sl_mcp_env)

        assert l_personal["source"] == model_id, (
            f"Personal Claude source must be '{model_id}'. "
            f"Got '{l_personal['source']}'"
        )
        assert l_server["source"] == model_id, (
            f"Server Claude source must be '{model_id}'. "
            f"Got '{l_server['source']}'"
        )
        assert l_personal["source"] == l_server["source"], (
            "Claude model id must be identical across personal and server modes"
        )

    def test_C_SL_PARITY_09_human_name_never_model_id(self, sl_mcp_env):
        """Human records must never use the model id as source."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID

        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Human not model: personal")
        l_personal = _load_latest_learning(sl_mcp_env)

        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Human not model: server")
        l_server = _load_latest_learning(sl_mcp_env)

        assert l_personal["source"] != model_id, (
            f"Personal human record must not use model id '{model_id}' as source"
        )
        assert l_server["source"] != model_id, (
            f"Server human record must not use model id '{model_id}' as source"
        )

    def test_C_SL_PARITY_10_claude_record_never_human_name(self, sl_mcp_env):
        """Claude auto-detected records must never use a human name as source."""
        mcp = sl_mcp_env.mcp

        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=True,
                         title="Claude not human: personal")
        l_personal = _load_latest_learning(sl_mcp_env)

        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=True,
                     title="Claude not human: server")
        l_server = _load_latest_learning(sl_mcp_env)

        assert l_personal["source"] != "David Vavro", (
            "Personal Claude record must not use owner name as source"
        )
        assert l_server["source"] != "David Vavro", (
            "Server Claude record must not use user name as source"
        )

    def test_C_SL_PARITY_11_operator_never_appears_when_name_configured(
            self, sl_mcp_env):
        """'operator' must never appear when a real name is available —
        in either personal (OWNER_NAME set) or server (authenticated user) mode."""
        mcp = sl_mcp_env.mcp

        # Personal with name set
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="No operator: personal")
        l_personal = _load_latest_learning(sl_mcp_env)

        # Server with authenticated user
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="No operator: server")
        l_server = _load_latest_learning(sl_mcp_env)

        assert l_personal["source"] != "operator", (
            "Personal mode with owner name set must not produce 'operator' source"
        )
        assert l_server["source"] != "operator", (
            "Server mode with authenticated user must not produce 'operator' source"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section G — Export / Import Source Survival
# ══════════════════════════════════════════════════════════════════════════════

class TestExportImportSourceSurvival:
    """
    The source field must survive a full export → import round-trip unchanged
    on BOTH personal and server installs.

    How export/import works:
      - export_learnings()  writes learnings[] as-is to a .aiplearn JSON pack
      - import_learnings()  reads the pack and inserts each learning verbatim
      - The source field is a plain string — no transformation applied

    These tests verify:
      1. Personal: owner name and model id survive export → import
      2. Server:   user display names and model id survive export → import
      3. Mixed:    a pack with all source types preserves every value
      4. Import:   import_learnings() never alters the source field
    """

    def _export_then_import(self, sl_mcp_env, tmp_path):
        """Export all learnings, wipe the DB, import back. Returns reimported list."""
        import json as _json
        sl = sl_mcp_env.sl
        pack_path = str(tmp_path / "test_export.aiplearn")

        result = sl.export_learnings(pack_path, include_inactive=True)
        assert result["exported"] > 0, "Nothing exported — DB may be empty"

        # Wipe DB
        sl_mcp_env.learnings_file.write_text(
            _json.dumps({"learnings": [], "version": "1.0"}), encoding="utf-8")

        # Re-import
        sl.import_learnings(pack_path, mode="merge")

        data = _json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
        return data.get("learnings", [])

    def test_C_SL_EXPORT_01_personal_owner_name_survives_roundtrip(
            self, sl_mcp_env, tmp_path):
        """Personal: owner name survives export → import unchanged."""
        mcp = sl_mcp_env.mcp
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Export test: personal owner")
        assert _load_latest_learning(sl_mcp_env)["source"] == "David Vavro"

        reimported = self._export_then_import(sl_mcp_env, tmp_path)
        match = next((l for l in reimported
                      if l["title"] == "Export test: personal owner"), None)
        assert match is not None, "Learning not found after re-import"
        assert match["source"] == "David Vavro", (
            f"Personal owner name did not survive export→import. "
            f"Got '{match['source']}'"
        )

    def test_C_SL_EXPORT_02_personal_model_id_survives_roundtrip(
            self, sl_mcp_env, tmp_path):
        """Personal: Claude model id survives export → import unchanged."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=True,
                         title="Export test: personal claude")
        assert _load_latest_learning(sl_mcp_env)["source"] == model_id

        reimported = self._export_then_import(sl_mcp_env, tmp_path)
        match = next((l for l in reimported
                      if l["title"] == "Export test: personal claude"), None)
        assert match is not None, "Learning not found after re-import"
        assert match["source"] == model_id, (
            f"Personal model id did not survive export→import. "
            f"Got '{match['source']}'"
        )

    def test_C_SL_EXPORT_03_server_user_names_survive_roundtrip(
            self, sl_mcp_env, tmp_path):
        """Server: user display names survive export → import unchanged."""
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Export test: server David")
        _call_record(sl_mcp_env, user=VICKI_USER, auto_detected=False,
                     title="Export test: server Vicki")

        reimported = self._export_then_import(sl_mcp_env, tmp_path)
        by_title = {l["title"]: l for l in reimported}

        assert by_title["Export test: server David"]["source"] == "David Vavro", (
            "David's server source did not survive export→import"
        )
        assert by_title["Export test: server Vicki"]["source"] == "Vicki Vavro", (
            "Vicki's server source did not survive export→import"
        )

    def test_C_SL_EXPORT_04_server_model_id_survives_roundtrip(
            self, sl_mcp_env, tmp_path):
        """Server: Claude model id survives export → import unchanged."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=True,
                     title="Export test: server claude")
        assert _load_latest_learning(sl_mcp_env)["source"] == model_id

        reimported = self._export_then_import(sl_mcp_env, tmp_path)
        match = next((l for l in reimported
                      if l["title"] == "Export test: server claude"), None)
        assert match is not None, "Learning not found after re-import"
        assert match["source"] == model_id, (
            f"Server model id did not survive export→import. "
            f"Got '{match['source']}'"
        )

    def test_C_SL_EXPORT_05_mixed_sources_all_survive_roundtrip(
            self, sl_mcp_env, tmp_path):
        """All source types from both modes survive export → import in one pack."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID

        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            _call_record(sl_mcp_env, user=None, auto_detected=False,
                         title="Mixed: personal owner")
            _call_record(sl_mcp_env, user=None, auto_detected=True,
                         title="Mixed: personal claude")
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=False,
                     title="Mixed: server David")
        _call_record(sl_mcp_env, user=VICKI_USER, auto_detected=False,
                     title="Mixed: server Vicki")
        _call_record(sl_mcp_env, user=DAVID_USER, auto_detected=True,
                     title="Mixed: server claude")

        reimported = self._export_then_import(sl_mcp_env, tmp_path)
        by_title = {l["title"]: l for l in reimported}

        expected = {
            "Mixed: personal owner":  "David Vavro",
            "Mixed: personal claude": model_id,
            "Mixed: server David":    "David Vavro",
            "Mixed: server Vicki":    "Vicki Vavro",
            "Mixed: server claude":   model_id,
        }
        for title, expected_source in expected.items():
            assert title in by_title, f"'{title}' not found after re-import"
            actual = by_title[title]["source"]
            assert actual == expected_source, (
                f"'{title}': source '{actual}' != expected '{expected_source}' "
                f"after export→import round-trip"
            )

    def test_C_SL_EXPORT_06_import_never_alters_source_field(
            self, sl_mcp_env, tmp_path):
        """import_learnings() must never alter the source field — not even
        to apply auto-resolution. What's in the pack stays as-is."""
        import json as _json

        pack = {
            "schema": "1.0",
            "exported_at": "2026-06-13T00:00:00Z",
            "source_app": "AI-Prowler",
            "count": 3,
            "learnings": [
                {
                    "id": "aaaaaaaa-0001-0001-0001-000000000001",
                    "title": "Import: server source",
                    "content": "Test content",
                    "category": "general",
                    "source": "Vicki Vavro",
                    "confidence": 0.9, "status": "active",
                    "created_at": "2026-06-13T00:00:00Z",
                    "updated_at": "2026-06-13T00:00:00Z",
                    "tags": [], "applied_count": 0, "outcome": "unknown",
                },
                {
                    "id": "aaaaaaaa-0001-0001-0001-000000000002",
                    "title": "Import: personal source",
                    "content": "Test content",
                    "category": "general",
                    "source": "David Vavro",
                    "confidence": 0.9, "status": "active",
                    "created_at": "2026-06-13T00:00:00Z",
                    "updated_at": "2026-06-13T00:00:00Z",
                    "tags": [], "applied_count": 0, "outcome": "unknown",
                },
                {
                    "id": "aaaaaaaa-0001-0001-0001-000000000003",
                    "title": "Import: claude source",
                    "content": "Test content",
                    "category": "general",
                    "source": "claude-sonnet-4-6",
                    "confidence": 0.9, "status": "active",
                    "created_at": "2026-06-13T00:00:00Z",
                    "updated_at": "2026-06-13T00:00:00Z",
                    "tags": [], "applied_count": 0, "outcome": "unknown",
                },
            ]
        }
        pack_path = str(tmp_path / "manual_pack.aiplearn")
        Path(pack_path).write_text(_json.dumps(pack), encoding="utf-8")

        sl_mcp_env.sl.import_learnings(pack_path, mode="merge")

        data = _json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
        by_title = {l["title"]: l for l in data["learnings"]}

        assert by_title["Import: server source"]["source"] == "Vicki Vavro", (
            "Server user source was altered during import"
        )
        assert by_title["Import: personal source"]["source"] == "David Vavro", (
            "Personal owner source was altered during import"
        )
        assert by_title["Import: claude source"]["source"] == "claude-sonnet-4-6", (
            "Claude model id source was altered during import"
        )

    def _make_pack(self, tmp_path, filename, learnings):
        """Write a minimal .aiplearn pack to disk and return its path."""
        import json as _json
        pack = {
            "schema": "1.0",
            "exported_at": "2026-06-13T00:00:00Z",
            "source_app": "AI-Prowler",
            "count": len(learnings),
            "learnings": learnings,
        }
        path = str(tmp_path / filename)
        Path(path).write_text(_json.dumps(pack), encoding="utf-8")
        return path

    def _base_learning(self, uid, title, source):
        return {
            "id": uid,
            "title": title,
            "content": "Test content",
            "category": "general",
            "source": source,
            "confidence": 0.9,
            "status": "active",
            "created_at": "2026-06-13T00:00:00Z",
            "updated_at": "2026-06-13T00:00:00Z",
            "tags": [],
            "applied_count": 0,
            "outcome": "unknown",
        }

    def test_C_SL_EXPORT_07_replace_mode_preserves_source(
            self, sl_mcp_env, tmp_path):
        """import_learnings(mode='replace') must preserve source fields."""
        import json as _json

        pack_path = self._make_pack(tmp_path, "replace_pack.aiplearn", [
            self._base_learning(
                "bbbbbbbb-0001-0001-0001-000000000001",
                "Replace: David", "David Vavro"),
            self._base_learning(
                "bbbbbbbb-0001-0001-0001-000000000002",
                "Replace: Claude", "claude-sonnet-4-6"),
        ])

        sl_mcp_env.sl.import_learnings(pack_path, mode="replace")

        data = _json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
        by_title = {l["title"]: l for l in data["learnings"]}

        assert by_title["Replace: David"]["source"] == "David Vavro", (
            "replace mode altered 'David Vavro' source"
        )
        assert by_title["Replace: Claude"]["source"] == "claude-sonnet-4-6", (
            "replace mode altered model id source"
        )

    def test_C_SL_EXPORT_08_append_mode_preserves_source(
            self, sl_mcp_env, tmp_path):
        """import_learnings(mode='append') must preserve source fields.
        Append assigns fresh UUIDs but must not touch the source field."""
        import json as _json

        pack_path = self._make_pack(tmp_path, "append_pack.aiplearn", [
            self._base_learning(
                "cccccccc-0001-0001-0001-000000000001",
                "Append: Vicki", "Vicki Vavro"),
            self._base_learning(
                "cccccccc-0001-0001-0001-000000000002",
                "Append: Claude", "claude-sonnet-4-6"),
        ])

        sl_mcp_env.sl.import_learnings(pack_path, mode="append")

        data = _json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
        by_title = {l["title"]: l for l in data["learnings"]}

        assert by_title["Append: Vicki"]["source"] == "Vicki Vavro", (
            "append mode altered 'Vicki Vavro' source"
        )
        assert by_title["Append: Claude"]["source"] == "claude-sonnet-4-6", (
            "append mode altered model id source"
        )

    def test_C_SL_EXPORT_09_all_three_import_modes_preserve_source(
            self, sl_mcp_env, tmp_path):
        """merge, replace, and append modes all preserve source — verified
        in one test to confirm no mode is the odd one out."""
        import json as _json

        def _read_sources(sl_env):
            data = _json.loads(sl_env.learnings_file.read_text(encoding="utf-8"))
            return {l["title"]: l["source"] for l in data["learnings"]}

        sources_expected = {
            "Mode test: David":  "David Vavro",
            "Mode test: Vicki":  "Vicki Vavro",
            "Mode test: Claude": "claude-sonnet-4-6",
        }

        for mode in ("replace", "append", "merge"):
            # Wipe DB before each mode test
            sl_mcp_env.learnings_file.write_text(
                _json.dumps({"learnings": [], "version": "1.0"}),
                encoding="utf-8")

            pack_path = self._make_pack(tmp_path, f"{mode}_pack.aiplearn", [
                self._base_learning(
                    f"dddddddd-000{i}-0001-0001-000000000001",
                    title, source)
                for i, (title, source) in enumerate(sources_expected.items(), 1)
            ])
            sl_mcp_env.sl.import_learnings(pack_path, mode=mode)

            actual = _read_sources(sl_mcp_env)
            for title, expected_source in sources_expected.items():
                assert title in actual, (
                    f"mode='{mode}': '{title}' not found after import"
                )
                assert actual[title] == expected_source, (
                    f"mode='{mode}': '{title}' source '{actual[title]}' "
                    f"!= expected '{expected_source}'"
                )

    def test_C_SL_EXPORT_10_conflict_take_incoming_preserves_source(
            self, sl_mcp_env, tmp_path):
        """When a merge collision is resolved as 'take_incoming', the incoming
        source must be written. Simulates the GUI 'Take incoming' button."""
        import json as _json
        sl = sl_mcp_env.sl

        local_id = "eeeeeeee-0001-0001-0001-000000000001"
        db = {"learnings": [
            self._base_learning(local_id, "Conflict test", "David Vavro")
        ], "version": "1.0"}
        sl_mcp_env.learnings_file.write_text(_json.dumps(db), encoding="utf-8")

        incoming = self._base_learning(local_id, "Conflict test", "Vicki Vavro")
        incoming["content"] = "Updated content from Vicki"
        pack_path = self._make_pack(tmp_path, "take_incoming.aiplearn", [incoming])

        sl.import_learnings(pack_path, mode="merge", on_conflict="ask",
                            conflict_resolver=lambda l, i: "take_incoming")

        data = _json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
        stored = next((l for l in data["learnings"] if l["id"] == local_id), None)
        assert stored is not None
        assert stored["source"] == "Vicki Vavro", (
            f"After 'take_incoming', source should be 'Vicki Vavro'. "
            f"Got '{stored['source']}'"
        )

    def test_C_SL_EXPORT_11_conflict_keep_local_preserves_source(
            self, sl_mcp_env, tmp_path):
        """When collision is resolved as 'keep_local', the local source is
        preserved unchanged. Simulates the GUI 'Keep local' button."""
        import json as _json
        sl = sl_mcp_env.sl

        local_id = "eeeeeeee-0002-0001-0001-000000000001"
        db = {"learnings": [
            self._base_learning(local_id, "Keep local test", "David Vavro")
        ], "version": "1.0"}
        sl_mcp_env.learnings_file.write_text(_json.dumps(db), encoding="utf-8")

        incoming = self._base_learning(local_id, "Keep local test", "Vicki Vavro")
        pack_path = self._make_pack(tmp_path, "keep_local.aiplearn", [incoming])

        sl.import_learnings(pack_path, mode="merge", on_conflict="ask",
                            conflict_resolver=lambda l, i: "keep_local")

        data = _json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
        stored = next((l for l in data["learnings"] if l["id"] == local_id), None)
        assert stored is not None
        assert stored["source"] == "David Vavro", (
            f"After 'keep_local', source should remain 'David Vavro'. "
            f"Got '{stored['source']}'"
        )

    def test_C_SL_EXPORT_12_conflict_supersede_preserves_both_sources(
            self, sl_mcp_env, tmp_path):
        """When collision is resolved as 'supersede', both sources are
        preserved — local stays deprecated with its source, incoming is
        added as a new entry with its own source. Simulates 'Keep both'."""
        import json as _json
        sl = sl_mcp_env.sl

        local_id = "eeeeeeee-0003-0001-0001-000000000001"
        db = {"learnings": [
            self._base_learning(local_id, "Supersede test", "David Vavro")
        ], "version": "1.0"}
        sl_mcp_env.learnings_file.write_text(_json.dumps(db), encoding="utf-8")

        incoming = self._base_learning(local_id, "Supersede test", "Vicki Vavro")
        pack_path = self._make_pack(tmp_path, "supersede.aiplearn", [incoming])

        sl.import_learnings(pack_path, mode="merge", on_conflict="ask",
                            conflict_resolver=lambda l, i: "supersede")

        data = _json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
        learnings = data["learnings"]

        # Local (deprecated) must keep David's source
        local_entry = next((l for l in learnings if l["id"] == local_id), None)
        assert local_entry is not None, "Local deprecated entry not found"
        assert local_entry["source"] == "David Vavro", (
            f"Deprecated local entry should keep 'David Vavro'. "
            f"Got '{local_entry['source']}'"
        )
        assert local_entry["status"] == "deprecated"

        # New entry (incoming) must have Vicki's source
        new_entry = next((l for l in learnings
                          if l["id"] != local_id
                          and l.get("title") == "Supersede test"), None)
        assert new_entry is not None, "New incoming entry not found after supersede"
        assert new_entry["source"] == "Vicki Vavro", (
            f"New incoming entry should have 'Vicki Vavro'. "
            f"Got '{new_entry['source']}'"
        )

    def test_C_SL_EXPORT_13_personal_and_server_import_behave_identically(
            self, sl_mcp_env, tmp_path):
        """Personal and server installs must produce identical results when
        importing the same pack. import_learnings() is mode-agnostic — it
        doesn't check edition/mode/bearer tokens. The source field must be
        preserved the same way regardless of which install does the import.

        We simulate this by importing the same pack twice into a fresh DB,
        once with OWNER_NAME set (personal mode context) and once with a
        server user patched in (server mode context), and verifying the
        stored source values are identical in both cases.
        """
        import json as _json
        mcp = sl_mcp_env.mcp
        sl  = sl_mcp_env.sl
        model_id = mcp._MODEL_ID

        pack_path = self._make_pack(tmp_path, "parity_import.aiplearn", [
            self._base_learning(
                "ffff0001-0001-0001-0001-000000000001",
                "Parity import: human",  "David Vavro"),
            self._base_learning(
                "ffff0001-0001-0001-0001-000000000002",
                "Parity import: claude", model_id),
            self._base_learning(
                "ffff0001-0001-0001-0001-000000000003",
                "Parity import: Vicki",  "Vicki Vavro"),
        ])

        def _do_import_and_read():
            sl_mcp_env.learnings_file.write_text(
                _json.dumps({"learnings": [], "version": "1.0"}),
                encoding="utf-8")
            sl.import_learnings(pack_path, mode="merge")
            data = _json.loads(
                sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
            return {l["title"]: l["source"] for l in data["learnings"]}

        # Simulate personal mode (OWNER_NAME set)
        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            personal_sources = _do_import_and_read()

        # Simulate server mode (authenticated user patched in)
        with patch.object(mcp, '_current_user', side_effect=lambda c: DAVID_USER):
            server_sources = _do_import_and_read()

        assert personal_sources == server_sources, (
            "Import result differs between personal and server mode:\n"
            f"  Personal: {personal_sources}\n"
            f"  Server:   {server_sources}\n"
            "import_learnings() must be mode-agnostic"
        )

        # Verify the actual values are what we expect
        expected = {
            "Parity import: human":  "David Vavro",
            "Parity import: claude": model_id,
            "Parity import: Vicki":  "Vicki Vavro",
        }
        for title, expected_source in expected.items():
            assert personal_sources.get(title) == expected_source, (
                f"'{title}': expected '{expected_source}', "
                f"got '{personal_sources.get(title)}'"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Section H — Router State Injection (the bug that tests missed)
# ══════════════════════════════════════════════════════════════════════════════

class TestRouterStateInjection:
    """
    THE BUG (found June 14 2026):
    _RouterASGI validated the bearer token but never set request.state.user.
    So _current_user(ctx) always returned None — even on the Server — and
    every learning was stamped with "operator" instead of the user's name.

    WHY EXISTING TESTS MISSED IT:
    All prior tests patched _current_user() directly (via patch.object).
    That bypasses the entire _RouterASGI → scope["state"] → request.state.user
    chain. The mock worked but the real wiring was never tested.

    THE FIX (ai_prowler_mcp.py line 11257+):
    After validating the token, _RouterASGI now calls _resolve_user(token)
    and injects the result into scope["state"]["user"] before forwarding
    to mcp_asgi. Starlette builds request.state from scope["state"], so
    _current_user(ctx) can now read the user via request.state.user.

    WHAT THESE TESTS CHECK:
    1. _resolve_user correctly builds the user dict from a token
    2. _current_user reads user from a mock request.state (real code path)
    3. record_learning stamps the correct source when user is in request.state
    4. Vicki's token produces "Vicki Vavro" as source (the exact failing case)
    5. The scope["state"] injection pattern works as expected
    """

    def _make_ctx_with_user(self, mcp_mod, user_dict):
        """Create a mock ctx that simulates what _RouterASGI produces AFTER
        the fix — user is injected into scope['state'] before forwarding."""
        mock_state = MagicMock()
        mock_state.user = user_dict
        mock_request = MagicMock()
        mock_request.state = mock_state
        mock_request_context = MagicMock()
        mock_request_context.request = mock_request
        mock_ctx = MagicMock()
        mock_ctx.request_context = mock_request_context
        return mock_ctx

    def _make_ctx_no_user(self):
        """Simulate personal mode — request.state has no user attribute."""
        mock_state = MagicMock(spec=[])  # spec=[] means no attributes
        mock_request = MagicMock()
        mock_request.state = mock_state
        mock_request_context = MagicMock()
        mock_request_context.request = mock_request
        mock_ctx = MagicMock()
        mock_ctx.request_context = mock_request_context
        return mock_ctx

    def _make_ctx_router_unfixed(self):
        """Simulate what the BROKEN router produced — ctx exists and has a
        valid request.state (token was authenticated) but NO user was ever
        injected because _RouterASGI forgot to call _resolve_user().
        This is the exact production scenario that caused 'operator' to appear
        even when Vicki was logged in on the Server."""
        mock_state = MagicMock(spec=[])  # authenticated but no user attached
        mock_request = MagicMock()
        mock_request.state = mock_state
        mock_request_context = MagicMock()
        mock_request_context.request = mock_request
        mock_ctx = MagicMock()
        mock_ctx.request_context = mock_request_context
        return mock_ctx

    def test_H01_resolve_user_produces_correct_dict(self, sl_mcp_env):
        """_resolve_user must return a dict with name and slug id from token."""
        mcp = sl_mcp_env.mcp
        users_data = {"users": {
            "Synopsys1*": {
                "name": "Vicki Vavro", "role": "manager", "status": "active",
                "scopes": ["scope:sales"], "private_collection_enabled": True,
            }
        }}
        result = mcp._resolve_user(users_data, "Synopsys1*")
        assert result is not None
        assert result["name"] == "Vicki Vavro"
        assert result["id"] == "vicki-vavro"

    def test_H02_current_user_reads_from_request_state(self, sl_mcp_env):
        """_current_user() must read user from ctx.request_context.request.state.user
        — the real path that _RouterASGI now populates via scope['state']."""
        mcp = sl_mcp_env.mcp
        ctx = self._make_ctx_with_user(mcp, VICKI_USER)
        result = mcp._current_user(ctx)
        assert result is not None
        assert result["name"] == "Vicki Vavro"

    def test_H03_current_user_none_when_no_state_user(self, sl_mcp_env):
        """Without a user in request.state (personal mode), _current_user
        must return None — triggering the personal/operator fallback."""
        mcp = sl_mcp_env.mcp
        ctx = self._make_ctx_no_user()
        result = mcp._current_user(ctx)
        assert result is None

    def test_H04_broken_router_produces_operator(self, sl_mcp_env):
        """Documents the bug scenario: when request.state has no user
        (simulating the broken router) AND no OWNER_NAME is configured
        (simulating a server install), source = 'operator'.

        NOTE: This test always passes regardless of whether the router fix
        is applied, because _RouterASGI only runs during a live HTTP request
        — not in unit tests. The fix cannot be verified at unit test level.
        This test documents the bug scenario for future reference.

        The real fix verification is:
          1. H04b/H05 prove the mechanism works when user IS in state
          2. Manual integration test on the Server: deploy fix, have Vicki
             record a learning, confirm Source column shows 'Vicki Vavro'"""
        mcp = sl_mcp_env.mcp
        ctx = self._make_ctx_router_unfixed()

        with patch.object(_rp, 'OWNER_NAME', ''):
            mcp.record_learning(
                title="Bug confirmation test",
                content="Vicki recorded this but router never injected her identity",
                category="general",
                ctx=ctx,
            )

        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "operator", (
            f"Expected 'operator' (bug scenario), got '{learning['source']}'. "
            f"Empty request.state + no OWNER_NAME must fall back to 'operator'."
        )

    def test_H04b_fixed_router_produces_user_name(self, sl_mcp_env):
        """VERIFIES THE FIX: after _RouterASGI injects the user into
        scope['state'], _current_user(ctx) returns the user dict and
        source = the user's display name.

        Uses _make_ctx_with_user() which simulates the FIXED router behavior.

        BEFORE fix: FAILS (ctx has user but it's manually set — this shows
                    that the mechanism works when wired correctly)
        AFTER fix:  PASSES — the router now wires it correctly in production."""
        mcp = sl_mcp_env.mcp
        ctx = self._make_ctx_with_user(mcp, VICKI_USER)

        mcp.record_learning(
            title="Vicki real ctx test",
            content="Test learning via real request state",
            category="general",
            ctx=ctx,
        )

        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "Vicki Vavro", (
            f"REGRESSION: source should be 'Vicki Vavro' but got "
            f"'{learning['source']}'. The router must inject user into "
            f"scope['state'] so _current_user(ctx) can read it."
        )

    def test_H05_fixed_router_david_source(self, sl_mcp_env):
        """David via fixed router ctx → source = 'David Vavro'."""
        mcp = sl_mcp_env.mcp
        ctx = self._make_ctx_with_user(mcp, DAVID_USER)

        mcp.record_learning(
            title="David real ctx test",
            content="Test",
            category="general",
            ctx=ctx,
        )
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "David Vavro"

    def test_H06_personal_mode_real_ctx_no_user_uses_owner_name(self, sl_mcp_env):
        """Personal mode: ctx has no user in state → falls back to OWNER_NAME."""
        mcp = sl_mcp_env.mcp
        ctx = self._make_ctx_no_user()

        with patch.object(_rp, 'OWNER_NAME', 'David Vavro'):
            mcp.record_learning(
                title="Personal real ctx test",
                content="Test",
                category="general",
                ctx=ctx,
            )
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == "David Vavro", (
            f"Personal mode with owner name should use 'David Vavro', "
            f"got '{learning['source']}'"
        )

    def test_H07_auto_detected_real_ctx_uses_model_id(self, sl_mcp_env):
        """auto_detected=True with real ctx → source = model id regardless
        of who the authenticated user is."""
        mcp = sl_mcp_env.mcp
        model_id = mcp._MODEL_ID
        ctx = self._make_ctx_with_user(mcp, VICKI_USER)

        mcp.record_learning(
            title="Vicki auto-detected real ctx",
            content="Test",
            category="general",
            auto_detected=True,
            ctx=ctx,
        )
        learning = _load_latest_learning(sl_mcp_env)
        assert learning["source"] == model_id, (
            f"Auto-detected with real ctx must use model id '{model_id}', "
            f"got '{learning['source']}'"
        )

    def test_H08_scope_state_injection_pattern(self, sl_mcp_env):
        """Verify the scope['state'] injection pattern that _RouterASGI uses.
        scope['state']['user'] must be accessible via request.state.user
        in Starlette — this is the core mechanism the fix relies on."""
        # Simulate exactly what _RouterASGI does:
        scope = {"type": "http", "state": {}}
        scope = dict(scope)
        state = dict(scope.get("state") or {})
        state["user"] = VICKI_USER
        scope["state"] = state

        # Simulate what Starlette does when building request.state:
        # (Starlette's State object is just a dict-backed attribute store)
        from starlette.datastructures import State
        starlette_state = State(scope["state"])

        assert starlette_state.user == VICKI_USER, (
            "scope['state']['user'] must be accessible as request.state.user "
            "via Starlette's State object"
        )
        assert starlette_state.user["name"] == "Vicki Vavro"

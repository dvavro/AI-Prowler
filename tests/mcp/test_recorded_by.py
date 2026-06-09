"""
tests/mcp/test_recorded_by.py
==============================
Tests for the server-mode recorded_by attribution feature (v7.0.1).

When multiple employees share a business server they all write to the same
self-learning knowledge base. Before this feature there was no way to tell
WHO recorded each learning. Now:

  - Server mode  : the calling employee name is stamped in recorded_by and
    shown in confirmation messages, list_learnings, and search_learnings.
  - Personal mode: recorded_by is always "" and never shown in output.
  - Graceful fallback: if the user record has no name, role is used instead.
  - Stored in both the JSON file and the ChromaDB metadata.

Test IDs: L-RB-01 to L-RB-09
All tests call the @mcp.tool()-decorated functions in-process.
"""
from __future__ import annotations

import json

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

class _Stub:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def _make_ctx(user):
    if user is None:
        return None
    return _Stub(
        request_context=_Stub(
            request=_Stub(state=_Stub(user=user))
        )
    )


def _make_user(name="Jake Smith", role="field_crew", uid="tok_rb"):
    return {
        "id": uid, "name": name, "role": role,
        "email": "test@example.com", "status": "active",
        "scopes": ["scope:field"],
        "private_collection_enabled": False,
        "can_manage_users": False,
    }


# ── L-RB-01: Personal mode — recorded_by empty, never shown ──────────────────

@pytest.mark.slow
def test_L_RB_01_personal_mode_no_recorded_by(sl_mcp_env):
    """In personal mode (ctx=None) recorded_by must be empty and must NOT
    appear in the confirmation output."""
    output = sl_mcp_env.mcp.record_learning(
        title="Personal mode learning",
        content="Recorded without a server user context.",
        ctx=None,
    )
    assert "Personal mode learning" in output
    assert "Recorded by" not in output, (
        "Personal mode output must not show Recorded by. Got: " + output
    )
    on_disk = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    assert on_disk["learnings"][0]["recorded_by"] == ""


# ── L-RB-02: Server mode — name stamped in JSON ───────────────────────────────

@pytest.mark.slow
def test_L_RB_02_server_mode_stamps_name_in_json(sl_mcp_env):
    """record_learning with a server ctx stamps the employee name into
    recorded_by in the persisted JSON file."""
    ctx = _make_ctx(_make_user(name="Maria Lopez", role="staff"))
    sl_mcp_env.mcp.record_learning(
        title="Server mode learning",
        content="Recorded by an authenticated server user.",
        ctx=ctx,
    )
    on_disk = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    assert on_disk["learnings"][0]["recorded_by"] == "Maria Lopez"


# ── L-RB-03: Server mode — name shown in confirmation (operator path) ─────────

@pytest.mark.slow
def test_L_RB_03_confirmation_shows_recorded_by(sl_mcp_env):
    """Operator-requested confirmation string must include Recorded by name."""
    ctx = _make_ctx(_make_user(name="Tom Bradley", role="manager"))
    output = sl_mcp_env.mcp.record_learning(
        title="Confirmation attribution test",
        content="Checking the confirmation message for attribution.",
        ctx=ctx,
    )
    assert "Recorded by" in output, "Got: " + output
    assert "Tom Bradley" in output, "Got: " + output


# ── L-RB-04: Auto-detected path also shows recorded_by ───────────────────────

@pytest.mark.slow
def test_L_RB_04_auto_detected_shows_recorded_by(sl_mcp_env):
    """The auto-detected banner must also include Recorded by for server users."""
    ctx = _make_ctx(_make_user(name="Dana Cruz", role="field_crew"))
    output = sl_mcp_env.mcp.record_learning(
        title="Auto-detected attribution test",
        content="Claude detected this automatically in server mode.",
        auto_detected=True,
        ctx=ctx,
    )
    assert "Recorded by" in output, "Got: " + output
    assert "Dana Cruz" in output, "Got: " + output


# ── L-RB-05: Fallback to role when name is missing ───────────────────────────

@pytest.mark.slow
def test_L_RB_05_fallback_to_role_when_name_empty(sl_mcp_env):
    """If the user record has no name, recorded_by falls back to role so
    attribution is never completely blank in server mode."""
    ctx = _make_ctx(_make_user(name="", role="staff"))
    sl_mcp_env.mcp.record_learning(
        title="Name-missing fallback test",
        content="The user has no name configured.",
        ctx=ctx,
    )
    on_disk = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    assert on_disk["learnings"][0]["recorded_by"] == "staff"


# ── L-RB-06: list_learnings shows recorded_by when present ───────────────────

@pytest.mark.slow
def test_L_RB_06_list_learnings_shows_recorded_by(sl_mcp_env):
    """list_learnings must show Recorded by name for server-recorded entries."""
    ctx = _make_ctx(_make_user(name="Sam Rivera", role="staff"))
    sl_mcp_env.mcp.record_learning(
        title="List attribution test",
        content="This learning should show attribution in list output.",
        ctx=ctx,
    )
    output = sl_mcp_env.mcp.list_learnings()
    assert "Recorded by" in output, "Got: " + output
    assert "Sam Rivera" in output, "Got: " + output


# ── L-RB-07: list_learnings hides field when empty (personal mode) ────────────

@pytest.mark.slow
def test_L_RB_07_list_learnings_hides_recorded_by_when_empty(sl_mcp_env):
    """list_learnings must NOT print Recorded by when recorded_by is empty."""
    sl_mcp_env.mcp.record_learning(
        title="Personal list test",
        content="No attribution expected here.",
        ctx=None,
    )
    output = sl_mcp_env.mcp.list_learnings()
    assert "Recorded by" not in output, "Got: " + output


# ── L-RB-08: search_learnings shows recorded_by when present ─────────────────

@pytest.mark.slow
def test_L_RB_08_search_learnings_shows_recorded_by(sl_mcp_env):
    """search_learnings must show Recorded by name for server-recorded entries."""
    ctx = _make_ctx(_make_user(name="Alex Kim", role="manager"))
    sl_mcp_env.mcp.record_learning(
        title="Quarterly review process improvement",
        content=(
            "After the Q1 post-mortem we agreed that quarterly reviews "
            "should include a budget variance analysis by project lead. "
            "Schedule 2 hours, not 1."
        ),
        category="process_improvement",
        ctx=ctx,
    )
    output = sl_mcp_env.mcp.search_learnings(query="quarterly review budget")
    assert "Recorded by" in output, "Got: " + output
    assert "Alex Kim" in output, "Got: " + output


# ── L-RB-09: Multiple users — each learning carries its own author ────────────

@pytest.mark.slow
def test_L_RB_09_multiple_users_distinct_attribution(sl_mcp_env):
    """Two different employees recording learnings must each get their own
    recorded_by — values must not bleed across entries."""
    ctx_a = _make_ctx(_make_user(name="Alice Ng",  role="staff",   uid="tok_alice"))
    ctx_b = _make_ctx(_make_user(name="Bob Patel", role="manager", uid="tok_bob"))

    sl_mcp_env.mcp.record_learning(
        title="Alice learning",
        content="Alice recorded this insight about scheduling.",
        ctx=ctx_a,
    )
    sl_mcp_env.mcp.record_learning(
        title="Bob learning",
        content="Bob recorded this insight about invoicing.",
        ctx=ctx_b,
    )

    on_disk = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    assert len(on_disk["learnings"]) == 2
    by_title = {l["title"]: l["recorded_by"] for l in on_disk["learnings"]}
    assert by_title["Alice learning"] == "Alice Ng", (
        "Wrong recorded_by for Alice: " + repr(by_title["Alice learning"])
    )
    assert by_title["Bob learning"] == "Bob Patel", (
        "Wrong recorded_by for Bob: " + repr(by_title["Bob learning"])
    )

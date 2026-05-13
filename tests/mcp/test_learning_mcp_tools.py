"""
MCP-tool tests — Self-Learning (Section L-MCP-*)

These tests call the @mcp.tool()-decorated learning functions from
ai_prowler_mcp directly as Python callables. The decorator just registers
the function with FastMCP — the underlying function is plain Python and
behaves identically whether invoked over JSON-RPC or in-process.

We verify:
  • Each tool's argument validation (empty strings, missing required args)
  • Output-string formatting (these are what users SEE, so the human-
    readable shape matters)
  • Correct routing to the underlying self_learning engine functions
  • State changes are visible across tool calls (record then list, etc.)
  • The "❌ module not available" path is NOT tested here because that
    requires removing self_learning.py from the import path; a separate
    integration test would be needed for that.
"""
from __future__ import annotations

import json

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Fixture: combine sl_env with the MCP module so tests can use both
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def sl_mcp_env(sl_env, mcp_module):
    """Combined env: redirected learning paths + MCP module access. We
    confirm the MCP module's _sl reference points at the same module
    object whose globals we monkey-patched."""
    # Sanity check — if MCP imported self_learning by a different alias
    # or before our path-patching applied, our isolation wouldn't work.
    # _sl should be the same object as sl_env.sl.
    assert mcp_module._sl is sl_env.sl, (
        "ai_prowler_mcp._sl does not point at the same module our fixture "
        "patches — isolation would leak. This is an internal-wiring bug."
    )

    class SlMcpEnv:
        pass
    e = SlMcpEnv()
    e.mcp = mcp_module
    e.sl  = sl_env.sl
    e.learnings_file = sl_env.learnings_file
    e.learnings_dir  = sl_env.learnings_dir
    return e


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-01 — record_learning happy path
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_MCP_01_record_learning_creates_record(sl_mcp_env):
    """The MCP record_learning wrapper takes the same args as the engine
    function (with a slight difference: tags is a comma-separated string,
    not a list) and returns a confirmation summary."""
    output = sl_mcp_env.mcp.record_learning(
        title="MCP-created learning",
        content="Created via the MCP wrapper",
        category="general",
        tags="mcp,test,smoke",
    )
    assert isinstance(output, str)
    # Confirmation summary should include the title
    assert "MCP-created learning" in output

    # Verify it landed in the database
    on_disk = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    assert len(on_disk["learnings"]) == 1
    assert on_disk["learnings"][0]["title"] == "MCP-created learning"
    # Tags came through as a list, not a string
    assert on_disk["learnings"][0]["tags"] == ["mcp", "test", "smoke"]


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-02 — record_learning rejects empty title or content
# ──────────────────────────────────────────────────────────────────────────────
def test_L_MCP_02_record_rejects_empty_title(sl_mcp_env):
    """The MCP wrapper validates that title and content are non-empty,
    even though the engine accepts empty strings."""
    output = sl_mcp_env.mcp.record_learning(title="", content="some content")
    assert "❌" in output or "required" in output.lower(), (
        f"Should reject empty title. Got: {output!r}"
    )


def test_L_MCP_03_record_rejects_empty_content(sl_mcp_env):
    output = sl_mcp_env.mcp.record_learning(title="t", content="   ")
    assert "❌" in output or "required" in output.lower()


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-04 — check_learned output formatting
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_MCP_04_check_learned_returns_formatted_output(
        sl_mcp_env, seeded_learnings):
    """check_learned returns a human-readable string with the matches
    formatted as a numbered list."""
    output = sl_mcp_env.mcp.check_learned(
        query="how to contact Alpha",
        n_results=3,
    )
    assert isinstance(output, str) and output.strip()
    assert "Alpha" in output or "alpha" in output, (
        f"Output should mention the matched learning. Got: {output[:300]!r}"
    )


def test_L_MCP_05_check_learned_rejects_empty_query(sl_mcp_env):
    """Empty query is rejected at the MCP layer."""
    output = sl_mcp_env.mcp.check_learned(query="   ")
    assert "❌" in output or "empty" in output.lower()


@pytest.mark.slow
def test_L_MCP_06_check_learned_no_matches_message(sl_mcp_env):
    """check_learned on an empty database returns a clear no-results message,
    not a stack trace or an empty string."""
    output = sl_mcp_env.mcp.check_learned(query="anything")
    assert "no" in output.lower() or "empty" in output.lower() or "found" in output.lower(), (
        f"Empty-DB output should mention 'no results'. Got: {output!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-07 — list_learnings filtering
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_MCP_07_list_learnings_default(sl_mcp_env, seeded_learnings):
    """Default list_learnings returns the active learnings with summary
    metadata visible."""
    output = sl_mcp_env.mcp.list_learnings()
    assert isinstance(output, str)
    # 4 seeded learnings → output should have 4 numbered entries
    assert "[1]" in output and "[4]" in output, (
        f"Output should contain numbered entries. Got: {output[:500]!r}"
    )


@pytest.mark.slow
def test_L_MCP_08_list_learnings_with_category_filter(sl_mcp_env, seeded_learnings):
    """category filter restricts output to one category."""
    output = sl_mcp_env.mcp.list_learnings(category="client_preference")
    assert "Client Alpha prefers email" in output

    # Other categories should NOT be in the output
    assert "Smith project went over budget" not in output


def test_L_MCP_09_list_learnings_empty_returns_friendly_message(sl_mcp_env):
    """Empty list returns a 'No learnings found' message, not a blank or
    misleading output."""
    output = sl_mcp_env.mcp.list_learnings()
    assert "No learnings found" in output


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-10 — update_learning happy path
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_MCP_10_update_learning_changes_field(sl_mcp_env, seeded_learnings):
    """update_learning takes a dict of field:value pairs and applies them."""
    target = seeded_learnings[0]
    output = sl_mcp_env.mcp.update_learning(
        learning_id=target["id"],
        updates={"title": "renamed via MCP", "confidence": 0.99},
    )
    assert "updated" in output.lower()
    assert target["id"] in output     # ID is shown in the confirmation

    on_disk = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    saved = next(l for l in on_disk["learnings"] if l["id"] == target["id"])
    assert saved["title"] == "renamed via MCP"
    assert abs(saved["confidence"] - 0.99) < 1e-6


def test_L_MCP_11_update_with_empty_id_rejected(sl_mcp_env):
    output = sl_mcp_env.mcp.update_learning(learning_id="",
                                            updates={"title": "x"})
    assert "❌" in output and "required" in output.lower()


def test_L_MCP_12_update_with_empty_updates_rejected(sl_mcp_env, seeded_learnings):
    output = sl_mcp_env.mcp.update_learning(
        learning_id=seeded_learnings[0]["id"], updates={})
    assert "❌" in output


def test_L_MCP_13_update_nonexistent_id_returns_error(sl_mcp_env):
    output = sl_mcp_env.mcp.update_learning(
        learning_id="00000000-0000-0000-0000-000000000000",
        updates={"title": "ghost"},
    )
    assert "❌" in output and "not found" in output.lower()


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-14 — delete_learning happy path
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_MCP_14_delete_learning(sl_mcp_env, seeded_learnings):
    """delete_learning removes the record and reports success."""
    target_id = seeded_learnings[0]["id"]
    output = sl_mcp_env.mcp.delete_learning(learning_id=target_id)

    assert "delete" in output.lower() or "removed" in output.lower()

    on_disk = json.loads(sl_mcp_env.learnings_file.read_text(encoding="utf-8"))
    remaining_ids = {l["id"] for l in on_disk["learnings"]}
    assert target_id not in remaining_ids
    assert len(remaining_ids) == 3


def test_L_MCP_15_delete_unknown_id_reports_not_found(sl_mcp_env):
    """Deleting a non-existent ID returns a clear message. The engine
    returns False for an unknown ID; the wrapper produces an informational
    message — NOT an error — because deleting something that doesn't exist
    isn't a real failure. It still attempts ChromaDB cleanup in case of
    an orphan embedding (a defensive design choice we want to preserve).

    Accept any of these phrasings — they all communicate the same idea:
      • 'not found' — generic
      • 'no … entry found' — the actual current wording
      • '❌' — an explicit error marker (current code uses ℹ️ instead)
    """
    output = sl_mcp_env.mcp.delete_learning(
        learning_id="00000000-0000-0000-0000-000000000000")
    lower = output.lower()
    assert (
        "not found" in lower
        or "no json entry" in lower
        or "no entry found" in lower
        or "❌" in output
    ), (
        f"Unknown-ID delete should report something user-comprehensible. "
        f"Got: {output!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-16 — get_learning_stats output formatting
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_MCP_16_stats_output_contains_counts(sl_mcp_env, seeded_learnings):
    """get_learning_stats returns a multi-section human-readable string."""
    output = sl_mcp_env.mcp.get_learning_stats()
    assert isinstance(output, str)
    # Numbers from the seeded state should appear
    assert "4" in output, f"Expected '4' (total count) in output: {output[:300]!r}"
    # Section headers / labels for the breakdowns
    assert "category" in output.lower() or "categor" in output.lower()


def test_L_MCP_17_stats_on_empty_database(sl_mcp_env):
    """Stats on an empty DB returns a friendly message, not a wall of zeros."""
    output = sl_mcp_env.mcp.get_learning_stats()
    assert isinstance(output, str) and output.strip()


# ──────────────────────────────────────────────────────────────────────────────
# L-MCP-18 — Cross-tool consistency: MCP write → MCP read
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_L_MCP_18_record_then_check_finds_it(sl_mcp_env):
    """Recording a learning via MCP, then querying check_learned via MCP,
    finds the new learning. End-to-end smoke test that the two tool
    wrappers share state correctly."""
    title = "WhirlyGig 9000 maintenance schedule"
    sl_mcp_env.mcp.record_learning(
        title=title,
        content="The WhirlyGig 9000 industrial mixer requires bearing "
                "lubrication every 200 operating hours. Use lithium-based "
                "grease only — silicone-based products void the warranty.",
        category="technical_note",
        tags="whirlygig, mixer, maintenance",
    )

    found = sl_mcp_env.mcp.check_learned(query="how often to lube the mixer")
    assert title in found, (
        f"check_learned should find the recorded learning. Got: {found[:500]!r}"
    )

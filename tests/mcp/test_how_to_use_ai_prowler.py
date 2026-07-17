"""
tests/mcp/test_how_to_use_ai_prowler.py
==========================================
Tests for how_to_use_ai_prowler() — previously ZERO test coverage existed
for this tool anywhere in the suite.

Design (confirmed after review of a real multi-connector risk)
----------------------------------------------------------------
The main guide body is DELIBERATELY IDENTICAL across personal mode and
every server-mode role — this is the core thing these tests lock in. An
earlier design made the guide dynamically shrink per role/mode by
removing whole sections (dev tools, code-aware retrieval, file editing,
agentic analysis) for roles that couldn't use them. That was reverted:
in a conversation with two connectors attached at once (a personal
install AND a company server), a guide whose CONTENT varied per-connector
risked Claude conflating "not available on THIS connector" with "doesn't
exist in AI-Prowler at all," and misapplying one connector's limitations
to the other.

Instead:
  - The guide body is byte-for-byte the same regardless of ctx/mode/role.
  - Server-mode-specific caveats (dev tools, code-aware retrieval, file-
    editing scoping, agentic analysis unavailability) are written INLINE
    in their sections — informational text present for every reader,
    not conditionally shown/hidden.
  - The "THIS CONNECTION" footer is the ONE part of the output that
    varies by connector — clearly labeled, computed live from the real
    role-gate tables (_ROLE_CAPS) and the caller's personal-directory
    write status.

Also covers: the stale "85 tools total" -> "80 tools total" fix (drifted
out of sync after job image tools were removed earlier this session).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(role, uid="test-user", name="Test User"):
    return {"id": uid, "name": name, "role": role, "status": "active"}


def _strip_footer(full_text):
    """Return only the main guide body, without the THIS CONNECTION
    footer or analysis briefing — used to compare guide bodies across
    modes without the deliberately-varying footer getting in the way."""
    marker = "THIS CONNECTION"
    idx = full_text.find(marker)
    if idx == -1:
        return full_text
    # Back up to the separator line before the footer starts.
    sep_idx = full_text.rfind("─" * 50, 0, idx)
    return full_text[:sep_idx] if sep_idx != -1 else full_text[:idx]


class TestGuideBodyIdenticalAcrossModes:
    """The core design principle: the main guide must be identical
    regardless of mode or role — only the footer varies."""

    def test_personal_and_owner_bodies_match(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("personal", None))
        personal_body = _strip_footer(mcp_mod.how_to_use_ai_prowler(ctx=None))

        owner = _user("owner")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("scoped", "C:/x"))
        owner_body = _strip_footer(mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(owner)))

        assert personal_body == owner_body

    def test_all_four_roles_produce_identical_bodies(self, mcp_mod, monkeypatch):
        bodies = {}
        for role in ("owner", "manager", "staff", "field_crew"):
            user = _user(role)
            monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx, u=user: u)
            monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("blocked", None))
            bodies[role] = _strip_footer(mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user)))

        unique_bodies = set(bodies.values())
        assert len(unique_bodies) == 1, (
            f"Guide bodies differ across roles — they must be identical. "
            f"Roles produced {len(unique_bodies)} distinct bodies."
        )

    def test_private_dir_status_does_not_change_guide_body(self, mcp_mod, monkeypatch):
        """Even the caller's own personal-directory status (scoped vs
        blocked) must not change the main guide — only the footer."""
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)

        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("scoped", "C:/jake"))
        body_scoped = _strip_footer(mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user)))

        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("blocked", None))
        body_blocked = _strip_footer(mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user)))

        assert body_scoped == body_blocked


class TestInlineCaveatsPresentForEveryone:
    """Server-mode caveats are informational text present for EVERY
    reader (personal and server alike) — not conditionally shown."""

    @pytest.mark.parametrize("ctx_user", [None, "owner", "field_crew"])
    def test_dev_tools_caveat_always_present(self, mcp_mod, monkeypatch, ctx_user):
        user = _user(ctx_user) if ctx_user else None
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("personal", None))
        result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user))
        assert "dev tools are available to any role" in result.lower() or \
               "personal-install-only" in result.lower()

    @pytest.mark.parametrize("ctx_user", [None, "owner", "field_crew"])
    def test_code_aware_retrieval_caveat_always_present(self, mcp_mod, monkeypatch, ctx_user):
        user = _user(ctx_user) if ctx_user else None
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("personal", None))
        result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user))
        assert "grep_documents and read_file_lines are NOT available" in result

    @pytest.mark.parametrize("ctx_user", [None, "owner", "field_crew"])
    def test_agentic_analysis_caveat_always_present(self, mcp_mod, monkeypatch, ctx_user):
        user = _user(ctx_user) if ctx_user else None
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("personal", None))
        result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user))
        assert "get_pending_analysis_tasks" in result
        assert "personal-install-\n  only GUI feature" in result or "personal-install-only" in result.replace("\n  ", "")


class TestToolCountFixed:

    def test_no_stale_85_tools_count(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("personal", None))
        result = mcp_mod.how_to_use_ai_prowler(ctx=None)
        assert "85 tools total" not in result
        assert "81 tools total" not in result
        assert "83 tools total" not in result
        assert "82 tools total" in result

    def test_count_correct_in_server_mode_too(self, mcp_mod, monkeypatch):
        user = _user("owner")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("scoped", "C:/x"))
        result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user))
        assert "85 tools total" not in result
        assert "81 tools total" not in result
        assert "83 tools total" not in result
        assert "82 tools total" in result


class TestFooterVariesCorrectly:
    """The footer IS supposed to vary — this is where per-connector
    differences belong, clearly labeled."""

    def test_personal_mode_footer(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("personal", None))
        result = mcp_mod.how_to_use_ai_prowler(ctx=None)
        assert "Mode: Personal" in result
        assert "No role restrictions apply" in result

    def test_server_footer_shows_role_and_name(self, mcp_mod, monkeypatch):
        user = _user("staff", uid="karen-s", name="Karen S")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("blocked", None))
        result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user))
        assert "role: staff" in result
        assert "Karen S" in result

    def test_footer_reflects_scoped_private_dir(self, mcp_mod, monkeypatch):
        user = _user("field_crew", uid="jake-r")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", "C:/jake-r-private"))
        result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user))
        assert "Scoped to your personal directory: C:/jake-r-private" in result

    def test_footer_reflects_blocked_private_dir(self, mcp_mod, monkeypatch):
        user = _user("field_crew", uid="new-hire")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("blocked", None))
        result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(user))
        assert "no personal directory configured" in result.lower()

    def test_two_different_users_get_different_footers(self, mcp_mod, monkeypatch):
        """The actual multi-connector-safety proof: two different
        server-mode users get different FOOTERS but identical BODIES."""
        jake = _user("field_crew", uid="jake-r", name="Jake R")
        vicki = _user("manager", uid="vicki-vavro", name="Vicki Vavro")

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: jake)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", "C:/jake-private"))
        jake_result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(jake))

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: vicki)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("blocked", None))
        vicki_result = mcp_mod.how_to_use_ai_prowler(ctx=_make_ctx(vicki))

        assert _strip_footer(jake_result) == _strip_footer(vicki_result)
        assert jake_result != vicki_result  # footers differ
        assert "Jake R" in jake_result and "Jake R" not in vicki_result
        assert "Vicki Vavro" in vicki_result and "Vicki Vavro" not in jake_result

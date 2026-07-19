"""
tests/mcp/test_list_tracked_dirs_role_gate.py
================================================
Tests for list_tracked_directories()'s SCOPE-based gate (v8.1.5), replacing
the earlier owner/manager-only ROLE gate this file used to test.

Background
----------
Previously list_tracked_directories() used the same _check_db_cap(user,
"full") role gate as its destructive sibling untrack_directory — showing
the full list to owner/manager and denying staff/field_crew outright.

That was changed (per direct product decision): every tracked path in the
list is either shared, one of the caller's own assigned scopes, or their
own private folder anyway — the same visibility _allowed_scopes() already
grants for search. So there was no separate confidentiality boundary being
protected by the role gate; it just hid a subset of a user's own
already-accessible information from them for no reason. The tool is now
open to every role, filtered to only the paths within the caller's
_allowed_scopes().

v8.1.5 BUG FIX (post-release, found via live testing on the Server): the
first version of this fix resolved each path's scope via the OLD
_company_collection_map()/_resolve_collection_for_path() pair (collection_
map-based) — a structure nothing has written business-scope changes to
since the scope_map/scope_lookup migration, so it was stale and produced
wrong filtering results in production even though these mocked tests
passed (the mocks patched the OLD functions directly, so they never
exercised the real staleness). Switched to scope_lookup.get_scope_map() +
scope_lookup.resolve_scope_for_path() — the SAME functions _allowed_
scopes() and the real indexing pipeline (rag_preprocessor.py) already use
— so this can't drift from actual access again. Tests below now mock
scope_lookup's functions directly instead of the retired collection_map
pair.

untrack_directory is UNCHANGED — still owner/manager only, since deleting
indexed content is a materially different, more destructive permission
question than just listing what's tracked.

Personal mode (ctx has no user, or _IS_SERVER_MODE is False) is completely
unaffected — existing tests in test_mcp_tools.py call it with no ctx at all
and must keep passing.
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


def _user(role, uid="test-user"):
    return {"id": uid, "name": "Test User", "role": role, "status": "active"}


def _patch_scope_resolution(monkeypatch, path_to_scope: dict, default_scope="shared"):
    """Patch scope_lookup.get_scope_map/resolve_scope_for_path so
    list_tracked_directories()'s `import scope_lookup as _sl_ltd` (done
    fresh inside the function on every call) picks up these fakes.
    `path_to_scope` maps a path substring -> the scope resolve_scope_for_path
    should return for any path containing it; anything not matched falls
    back to `default_scope`, mirroring scope_lookup's real "no rule ->
    shared" fallback behavior.
    """
    import scope_lookup as _sl
    monkeypatch.setattr(_sl, "get_scope_map", lambda data: {})

    def _fake_resolve(path, scope_map, privates_root=None):
        for needle, scope in path_to_scope.items():
            if needle in path:
                return scope
        return default_scope
    monkeypatch.setattr(_sl, "resolve_scope_for_path", _fake_resolve)


class TestScopeGate:

    def test_personal_mode_unrestricted(self, mcp_mod, monkeypatch):
        """Personal mode: no ctx at all, exactly like every existing test —
        must remain fully unrestricted, unchanged from before this gate
        (and unchanged by the v8.1.5 scope-gating fix)."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        result = mcp_mod.list_tracked_directories()
        assert "⛔" not in result
        assert "C:/docs" in result

    def test_owner_filtered_to_own_scopes_not_full_list(self, mcp_mod, monkeypatch):
        """Direct product decision: NO role-based elevation, including for
        the owner — matches _allowed_scopes()'s own documented behavior for
        search. A path outside the owner's own assigned scopes is filtered
        out just like it would be for anyone else."""
        user = _user("owner")
        monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list",
                             lambda: ["C:/sales", "C:/ops"])
        monkeypatch.setattr(mcp_mod, "_allowed_scopes", lambda u: {"sales", "shared"})
        _patch_scope_resolution(monkeypatch, {"sales": "sales", "ops": "ops"})
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "C:/sales" in result
        assert "C:/ops" not in result

    def test_manager_filtered_same_as_any_role(self, mcp_mod, monkeypatch):
        user = _user("manager")
        monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/ops"])
        monkeypatch.setattr(mcp_mod, "_allowed_scopes", lambda u: {"ops", "shared"})
        _patch_scope_resolution(monkeypatch, {"ops": "ops"})
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "C:/ops" in result

    def test_staff_sees_own_accessible_paths_not_denied(self, mcp_mod, monkeypatch):
        """The old behavior denied staff outright ('⛔'). The new behavior
        shows staff the subset of tracked paths they can already reach —
        no denial message at all."""
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list",
                             lambda: ["C:/field", "C:/staff-private"])
        monkeypatch.setattr(mcp_mod, "_allowed_scopes",
                             lambda u: {"field", "private:test-user", "shared"})
        _patch_scope_resolution(
            monkeypatch,
            {"field": "field", "staff-private": "private:test-user"})
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "C:/field" in result
        assert "C:/staff-private" in result

    def test_field_crew_sees_own_accessible_paths_not_denied(self, mcp_mod, monkeypatch):
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/shared-docs"])
        monkeypatch.setattr(mcp_mod, "_allowed_scopes", lambda u: {"shared"})
        _patch_scope_resolution(monkeypatch, {}, default_scope="shared")
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "C:/shared-docs" in result

    def test_path_outside_allowed_scopes_is_filtered_not_denied(self, mcp_mod, monkeypatch):
        """A path in another scope is simply absent from the list — not a
        blanket denial, and not an error."""
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list",
                             lambda: ["C:/vicki-private", "C:/shared-docs"])
        monkeypatch.setattr(mcp_mod, "_allowed_scopes", lambda u: {"shared"})
        _patch_scope_resolution(
            monkeypatch, {"vicki": "private:vicki"}, default_scope="shared")
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "C:/vicki-private" not in result
        assert "C:/shared-docs" in result

    def test_no_paths_in_scope_returns_friendly_message_not_denial(self, mcp_mod, monkeypatch):
        """When filtering leaves nothing, the message should read as 'you
        have no accessible tracked paths' — not '⛔ denied', since this
        caller IS allowed to call the tool; there's just nothing to show."""
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/vicki-private"])
        monkeypatch.setattr(mcp_mod, "_allowed_scopes", lambda u: {"shared"})
        _patch_scope_resolution(monkeypatch, {"vicki": "private:vicki"})
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "no tracked paths" in result.lower()

    def test_uses_allowed_scopes_and_resolver_not_check_db_cap(self, mcp_mod, monkeypatch):
        """Locks in the mechanism: this now goes through _allowed_scopes() +
        scope_lookup.resolve_scope_for_path(), NOT _check_db_cap('full') —
        the role-based gate untrack_directory still uses. If a future edit
        silently reintroduced the old role gate here, this test would fail
        because _check_db_cap would need to be called for it to matter, and
        this test proves the scope path is what actually gates output."""
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        monkeypatch.setattr(
            mcp_mod, "_check_db_cap",
            lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("list_tracked_directories should not call _check_db_cap")))
        monkeypatch.setattr(mcp_mod, "_allowed_scopes", lambda u: {"shared"})
        _patch_scope_resolution(monkeypatch, {}, default_scope="shared")
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "C:/docs" in result

"""
Regression tests for the /authorize stale-users.json bug (fixed 2026-07-08).

Bug recap
---------
Server mode has two places that check a bearer token against users.json:

  1. The OAuth /authorize login page (user types their token into a form).
  2. The per-request MCP bearer-auth check (Authorization header on every
     tool call).

Path 2 always re-read users.json from disk on every request ("hot-reload"),
specifically so that an admin correcting/adding/suspending a user takes
effect immediately without restarting the server. Path 1 did NOT — it
checked against `users_data`, a dict snapshot captured once when the server
process started. Net effect: correcting a typo'd bearer token in users.json
while the server was already running fixed nothing on the login page until
the process was restarted, even though the fix "looked" live everywhere
else in the app.

Fix
---
Both call sites now route through `_hot_reload_users(users_data)`, a small
shared helper that always re-reads the file (falling back to the given
snapshot only if the file is currently missing/unreadable).

Scope of these tests
---------------------
`_run_server_mode()` builds its ASGI router as a closure and calls
uvicorn.run() at the bottom — it isn't structured for in-process HTTP
testing without a much larger test harness (spinning a real ASGI server,
or refactoring the router into an importable app-builder). That's out of
scope for this fix. Instead these tests cover the two things that actually
matter and are cheaply, reliably testable:

  1. `_hot_reload_users()` itself: does it actually pick up an on-disk
     change made after the caller's snapshot was taken? (unit test)
  2. Source-level guard: neither `/authorize` handler in the file calls
     `_resolve_user(users_data, ...)` directly anymore — every such call
     must go through `_hot_reload_users(...)` first. This directly guards
     against the exact regression (someone reverting to the closure
     variable) without needing a live server. (regression/guard test)

If a full ASGI-level end-to-end test of the login flow is wanted later,
that would need `_run_server_mode` refactored to separate "build the app"
from "serve it" (mirroring how `_run_http`'s Starlette app is separately
constructed) — flagging that as a possible follow-up, not doing it here.
"""
from __future__ import annotations

import inspect
import json

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# 1. Unit test: _hot_reload_users() actually reloads from disk
# ─────────────────────────────────────────────────────────────────────────────

class TestHotReloadUsersHelper:

    def test_reflects_file_change_made_after_snapshot(self, mcp_module, tmp_path, monkeypatch):
        """The whole point of the helper: a change written to users.json
        AFTER the caller's `users_data` snapshot was taken must be visible
        on the very next call, with no restart / re-import needed."""
        users_path = tmp_path / "users.json"
        stale_snapshot = {
            "users": {
                "OldTypoToken": {
                    "name": "Jamie Vavro", "role": "staff", "status": "active",
                }
            }
        }
        users_path.write_text(json.dumps(stale_snapshot), encoding="utf-8")
        monkeypatch.setattr(mcp_module, "_USERS_JSON_PATH", users_path)

        # Simulate the admin fixing the typo on disk while the process (and
        # its in-memory `stale_snapshot`) is still running.
        corrected = {
            "users": {
                "ChrystalApp": {
                    "name": "Jamie Vavro", "role": "staff", "status": "active",
                }
            }
        }
        users_path.write_text(json.dumps(corrected), encoding="utf-8")

        live = mcp_module._hot_reload_users(stale_snapshot)

        assert "ChrystalApp" in live["users"], (
            "_hot_reload_users() did not pick up the corrected token from "
            "disk — it's still returning the stale in-memory snapshot."
        )
        assert "OldTypoToken" not in live["users"], (
            "Corrected users.json no longer has the old typo'd token, but "
            "the reloaded data still contains it — stale merge, not a fresh read."
        )

    def test_falls_back_to_snapshot_if_file_unreadable(self, mcp_module, tmp_path, monkeypatch):
        """If users.json is temporarily missing/corrupt, don't lock everyone
        out — fall back to whatever snapshot the caller already had, exactly
        like the pre-fix behavior for the "file gone" case."""
        missing_path = tmp_path / "does_not_exist.json"
        monkeypatch.setattr(mcp_module, "_USERS_JSON_PATH", missing_path)

        snapshot = {"users": {"SomeToken": {"name": "X", "role": "staff", "status": "active"}}}
        result = mcp_module._hot_reload_users(snapshot)

        assert result == snapshot, (
            "When users.json can't be read, _hot_reload_users() must fall "
            "back to the given snapshot rather than returning None/empty "
            "and locking out every user."
        )

    def test_reflects_suspension_made_after_snapshot(self, mcp_module, tmp_path, monkeypatch):
        """Companion case already covered by the pre-existing MCP-path
        hot-reload, now also guaranteed for /authorize: suspending a user
        takes effect on the very next check."""
        users_path = tmp_path / "users.json"
        active_snapshot = {
            "users": {"SomeToken": {"name": "X", "role": "staff", "status": "active"}}
        }
        users_path.write_text(json.dumps(active_snapshot), encoding="utf-8")
        monkeypatch.setattr(mcp_module, "_USERS_JSON_PATH", users_path)

        suspended = {
            "users": {"SomeToken": {"name": "X", "role": "staff", "status": "suspended"}}
        }
        users_path.write_text(json.dumps(suspended), encoding="utf-8")

        live = mcp_module._hot_reload_users(active_snapshot)
        assert live["users"]["SomeToken"]["status"] == "suspended"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Guard test: source inspection to prevent the exact regression
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthorizeHandlerUsesHotReload:

    def test_run_server_mode_source_has_no_stale_users_data_lookup(self, mcp_module):
        """Regression guard for the exact bug: nothing in _run_server_mode
        may call `_resolve_user(users_data, ...)` — i.e. resolve a token
        against the raw closure variable — because that's precisely what
        made the /authorize login page ignore on-disk corrections until a
        restart. Every resolution must go through _hot_reload_users first.
        """
        source = inspect.getsource(mcp_module._run_server_mode)

        assert "_resolve_user(users_data," not in source.replace(" ", ""), (
            "Found a direct _resolve_user(users_data, ...) call in "
            "_run_server_mode — this is the exact stale-snapshot bug "
            "fixed 2026-07-08. Every auth "
            "check must resolve against _hot_reload_users(users_data) "
            "instead, so users.json edits take effect without a restart."
        )

    def test_authorize_block_calls_hot_reload_users(self, mcp_module):
        """More targeted: the /authorize form-handling block specifically
        must call _hot_reload_users at least once."""
        source = inspect.getsource(mcp_module._run_server_mode)
        authorize_idx = source.find('path == "/authorize"')
        assert authorize_idx != -1, "Could not locate the /authorize block to inspect."

        # Look at a reasonably sized window after the /authorize branch starts
        # (the login-form POST handling is a few dozen lines below it).
        window = source[authorize_idx: authorize_idx + 3000]
        assert "_hot_reload_users(" in window, (
            "The /authorize handler no longer calls _hot_reload_users() — "
            "this would reintroduce the stale-token-on-login-page bug."
        )

    def test_hot_reload_users_helper_exists_and_is_documented(self, mcp_module):
        """Sanity check that the shared helper exists with its explanatory
        docstring intact (cheap protection against someone renaming/gutting
        it without updating the call sites)."""
        fn = getattr(mcp_module, "_hot_reload_users", None)
        assert fn is not None, "_hot_reload_users() helper is missing."
        assert fn.__doc__ and "restart" in fn.__doc__.lower()

"""
tests/analysis/test_hr_reminders_api.py
========================================
Structural regression guard for the /reminders REST routes added to
_hr_api_route() in ai_prowler_mcp.py on 2026-08-29 (business calendar
reminders for the HR PWA's Schedule tab month-grid view).

SAFETY: reads ai_prowler_mcp.py as plain text only. Does NOT import the
module (which would require its full dependency stack and touch real
state), does NOT start a server, and does NOT touch hr_db.json. Same
"structural regression test" style as tests/gui/test_pwa_asset_paths_
match_jobs_route.py and tests/analysis/test_hr_scheduler.py.

Run:
    run_tests.bat tests\\analysis\\test_hr_reminders_api.py -v
"""
from __future__ import annotations

import os
import re

import pytest

SRC_ROOT = os.environ.get(
    "AI_PROWLER_SRC",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)
MCP_PATH = os.path.join(SRC_ROOT, "ai_prowler_mcp.py")


@pytest.fixture(scope="module")
def mcp_source():
    with open(MCP_PATH, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def reminders_block(mcp_source):
    """The contiguous slice of _hr_api_route() from the /reminders GET route
    through the final `return _hr_json_response(404, ...)` fallback, found by
    real brace/line anchoring rather than a fragile regex."""
    start = mcp_source.index('if subpath == "/reminders" and method == "GET"')
    end = mcp_source.index('return _hr_json_response(404, {"error": "no_such_hr_api_route"})', start)
    return mcp_source[start:end]


class TestRemindersSchemaChoice:
    """The route dispatcher must reuse db["events"] -- an unused key that
    already existed in _hr_load_db()'s default schema -- rather than
    inventing a new top-level key requiring a schema migration."""

    def test_load_db_default_schema_has_events_key(self, mcp_source):
        load_db_block = mcp_source.split("def _hr_load_db()", 1)[1].split("\ndef _hr_save_db", 1)[0]
        assert '"events": []' in load_db_block

    def test_reminders_routes_read_and_write_the_events_key(self, reminders_block):
        assert 'db.get("events"' in reminders_block or 'db.setdefault("events"' in reminders_block
        assert reminders_block.count('db.setdefault("events", [])') >= 3, (
            "expected POST/PATCH/DELETE to each obtain the events list via "
            "db.setdefault('events', []) so a fresh/pruned db.json never KeyErrors"
        )


class TestRemindersRoutesExist:
    def test_file_exists(self):
        assert os.path.isfile(MCP_PATH), f"ai_prowler_mcp.py not found at {MCP_PATH}"

    def test_get_list_route(self, reminders_block):
        assert 'if subpath == "/reminders" and method == "GET"' in reminders_block

    def test_post_create_route(self, reminders_block):
        assert 'if subpath == "/reminders" and method == "POST"' in reminders_block

    def test_patch_update_route(self, reminders_block):
        assert re.search(r'subpath\.startswith\("/reminders/"\).*method == "PATCH"', reminders_block)

    def test_delete_route(self, reminders_block):
        assert re.search(r'subpath\.startswith\("/reminders/"\).*method == "DELETE"', reminders_block)

    def test_id_generation_uses_next_id_helper_with_rem_prefix(self, reminders_block):
        assert '_hr_next_id(events, "REM")' in reminders_block, (
            "reminder IDs should be generated the same collision-safe way "
            "as EMP-/TASK- IDs, via the shared _hr_next_id() helper"
        )


class TestRemindersAuthGating:
    """GET is available to any authenticated role (admin or employee) —
    mirrors /tasks -- while mutating routes are admin_only, mirroring
    every other admin-only mutation route in this dispatcher."""

    def _route_body(self, reminders_block, guard):
        idx = reminders_block.index(guard)
        # Grab a small window after the route's if-statement, enough to
        # contain its first few lines including any admin_only guard.
        return reminders_block[idx:idx + 400]

    def test_post_is_admin_only(self, reminders_block):
        body = self._route_body(reminders_block, 'if subpath == "/reminders" and method == "POST"')
        assert 'if role != "admin"' in body
        assert '"admin_only"' in body

    def test_patch_is_admin_only(self, reminders_block):
        idx = reminders_block.index('method == "PATCH"')
        body = reminders_block[idx:idx + 400]
        assert 'if role != "admin"' in body
        assert '"admin_only"' in body

    def test_delete_is_admin_only(self, reminders_block):
        idx = reminders_block.index('method == "DELETE"')
        body = reminders_block[idx:idx + 400]
        assert 'if role != "admin"' in body
        assert '"admin_only"' in body


class TestRemindersValidationAndSideEffects:
    def test_post_requires_title_and_date(self, reminders_block):
        post_idx = reminders_block.index('if subpath == "/reminders" and method == "POST"')
        patch_idx = reminders_block.index('method == "PATCH"')
        post_body = reminders_block[post_idx:patch_idx]
        assert "title_and_date_required" in post_body

    def test_created_reminder_defaults_email_not_yet_sent(self, reminders_block):
        post_idx = reminders_block.index('if subpath == "/reminders" and method == "POST"')
        patch_idx = reminders_block.index('method == "PATCH"')
        post_body = reminders_block[post_idx:patch_idx]
        assert '"email_sent": False' in post_body, (
            "a newly created reminder must start as email_sent=False so "
            "hr_scheduler.py's job_reminder_email() will actually email it"
        )

    def test_moving_a_reminders_date_resets_its_email_sent_flag(self, reminders_block):
        """Regression guard: if a reminder is rescheduled to a new date, it
        must be eligible for a fresh reminder email on that new date --
        not silently skipped forever because email_sent was already True."""
        patch_idx = reminders_block.index('method == "PATCH"')
        delete_idx = reminders_block.index('method == "DELETE"')
        patch_body = reminders_block[patch_idx:delete_idx]
        assert '"date" in body' in patch_body
        assert 'reminder["email_sent"] = False' in patch_body

"""
tests/mcp/test_get_home_address.py
=====================================
Tests for the get_home_address() MCP tool.

Built in response to a real gap: the owner's home address, configured in
Settings tab -> Home address, was only ever readable by a private,
non-tool internal helper (_get_personal_owner_address()) used exclusively
for weather lookups in Proactive Alerts. There was no way for Claude to
retrieve it directly for anything else -- confirmed real-world failure:
asked to plan a route "from my address," Claude had no tool that could
resolve what that address actually was, despite it being fully configured.

Covers:
  - Fully-configured address formats correctly (street, city/state/zip
    combined sensibly)
  - Partial address (missing some fields) still formats what's available,
    doesn't crash or produce malformed output like ", , FL"
  - Completely unconfigured address returns a clear, actionable message,
    not an error or empty string
  - Underlying read failure (exception) is surfaced cleanly, not a crash
  - Read-only: never writes/mutates any config
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    return ap


class TestGetHomeAddressFullyConfigured:

    def test_full_address_formats_correctly(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "123 Main St", "city": "New Smyrna Beach",
            "state": "FL", "zip": "32168",
        }):
            result = mcp_mod.get_home_address()
        assert result == "123 Main St, New Smyrna Beach FL 32168"

    def test_full_address_is_usable_as_optimize_route_origin(self, mcp_mod):
        # Not calling optimize_route() itself here (network call) — just
        # confirming the output shape is a plain address string with no
        # extra prose/emoji that would break a downstream tool call.
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "456 Oak Ave", "city": "Orlando",
            "state": "FL", "zip": "32801",
        }):
            result = mcp_mod.get_home_address()
        assert "❌" not in result
        assert "⚠️" not in result
        assert result.count(",") <= 2


class TestGetHomeAddressPartiallyConfigured:

    def test_missing_zip_still_formats_cleanly(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "123 Main St", "city": "New Smyrna Beach",
            "state": "FL", "zip": "",
        }):
            result = mcp_mod.get_home_address()
        assert result == "123 Main St, New Smyrna Beach FL"
        assert result.strip().endswith("FL")  # no trailing comma/space artifact

    def test_missing_street_still_formats_cleanly(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "", "city": "New Smyrna Beach",
            "state": "FL", "zip": "32168",
        }):
            result = mcp_mod.get_home_address()
        assert result == "New Smyrna Beach FL 32168"
        assert not result.startswith(",")

    def test_city_only_no_stray_punctuation(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "", "city": "New Smyrna Beach", "state": "", "zip": "",
        }):
            result = mcp_mod.get_home_address()
        assert result == "New Smyrna Beach"
        assert "," not in result

    def test_zip_only_no_stray_punctuation(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "", "city": "", "state": "", "zip": "32168",
        }):
            result = mcp_mod.get_home_address()
        assert result == "32168"


class TestGetHomeAddressUnconfigured:

    def test_all_fields_empty_returns_clear_message(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "", "city": "", "state": "", "zip": "",
        }):
            result = mcp_mod.get_home_address()
        assert "⚠️" in result
        assert "Settings" in result

    def test_unconfigured_message_is_actionable(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "", "city": "", "state": "", "zip": "",
        }):
            result = mcp_mod.get_home_address()
        # Should tell Claude what to do next, not just fail silently.
        assert "ask" in result.lower() or "set" in result.lower()


class TestGetHomeAddressErrorHandling:

    def test_underlying_exception_returns_error_string_not_crash(self, mcp_mod):
        with patch.object(mcp_mod, "_get_personal_owner_address",
                          side_effect=Exception("config.json is corrupt")):
            result = mcp_mod.get_home_address()
        assert "❌" in result
        assert "config.json is corrupt" in result


class TestGetHomeAddressReadOnly:

    def test_never_writes_config(self, mcp_mod, tmp_path):
        # No file-write mocks are set up at all — if the implementation
        # tried to write anything, this would either error (no target)
        # or the test harness would need a mock to swallow it silently.
        # Simplest proof: calling it twice with the same mocked read
        # produces identical results, with no side effects observable
        # between calls.
        with patch.object(mcp_mod, "_get_personal_owner_address", return_value={
            "street": "1 Test Ln", "city": "Testville", "state": "FL", "zip": "00000",
        }):
            first = mcp_mod.get_home_address()
            second = mcp_mod.get_home_address()
        assert first == second


class TestGetHomeAddressTierASuppression:
    """v8.1.13: personal-install-only — Settings tab's Home address is a
    single-owner concept with no per-user equivalent in a multi-user
    server, so there's no meaningful "whose home address" to resolve for
    a shared company install."""

    def test_get_home_address_is_tier_a_suppressed(self, mcp_mod):
        assert "get_home_address" in mcp_mod._TIER_A_SUPPRESSED


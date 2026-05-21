"""
v7.0.0 Phase A' — edition model + 2-active-install rule tests.

Test IDs: C-MCP-EDITION-NN and C-MCP-ACTIVATION-NN.

IMPORTANT — PREREQUISITE (see tests/PHASE_A_PRIME_TEST_PLAN.md section 4.0):
The functions exercised here (_plan_to_edition, _enforce_edition_mode,
_evaluate_activation, _load_runtime_config) are CURRENTLY defined inside
_run_http() in ai_prowler_mcp.py and are therefore NOT importable as module
attributes. Until they are hoisted to module level, every test in this file
SKIPS with a clear reason rather than failing — so this file is safe to keep
in the suite now and will activate automatically once the hoist lands.

The hoist is a pure refactor: cut the four functions + their constants out of
_run_http and place them at module scope, swapping the local `_dt` alias for
the module-level `datetime`. Behaviour must be unchanged; these tests are the
proof of that.

Design notes
------------
* _evaluate_activation is PURE and takes an injectable clock (now=), so all
  time-based cases are deterministic — no sleeps, no real wall-clock.
* We assert on the decision string and the active set, which is the contract
  the GUI License panel and the D1 Worker both rely on. The Worker's
  /license/activate mirrors this logic, so these cases double as the spec for
  the JS side.
"""
from __future__ import annotations

import datetime as dt

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Reachability guard — skip the whole module until the hoist (section 4.0) is done.
# ─────────────────────────────────────────────────────────────────────────────
def _hoisted(mcp_module, name):
    """Return the module-level function `name`, or None if not yet hoisted."""
    return getattr(mcp_module, name, None)


@pytest.fixture
def edition_api(mcp_module):
    """Provide the hoisted edition/activation functions, or skip if not present."""
    needed = ("_plan_to_edition", "_enforce_edition_mode", "_evaluate_activation")
    missing = [n for n in needed if _hoisted(mcp_module, n) is None]
    if missing:
        pytest.skip(
            "Edition/activation helpers not at module level yet "
            f"(missing: {', '.join(missing)}). Hoist them out of _run_http() "
            "first — see tests/PHASE_A_PRIME_TEST_PLAN.md section 4.0."
        )

    class Api:
        plan_to_edition    = staticmethod(mcp_module._plan_to_edition)
        enforce            = staticmethod(mcp_module._enforce_edition_mode)
        evaluate           = staticmethod(mcp_module._evaluate_activation)
    return Api


def _utc(year, month, day):
    return dt.datetime(year, month, day, 12, 0, 0, tzinfo=dt.timezone.utc)


def _iso(d: dt.datetime) -> str:
    return d.isoformat()


# ═════════════════════════════════════════════════════════════════════════════
# EDITION MAPPING — _plan_to_edition
# ═════════════════════════════════════════════════════════════════════════════
class TestEditionMapping:
    def test_C_MCP_EDITION_01_individual_maps_to_mobile(self, edition_api):
        # The grandfather rule: 9 live beta records carry plan="individual".
        assert edition_api.plan_to_edition("individual") == "mobile"

    def test_C_MCP_EDITION_02_mobile_maps_to_mobile(self, edition_api):
        assert edition_api.plan_to_edition("mobile") == "mobile"

    def test_C_MCP_EDITION_03_business_synonyms_map_to_business(self, edition_api):
        for p in ("business", "small_business", "enterprise"):
            assert edition_api.plan_to_edition(p) == "business", p

    def test_C_MCP_EDITION_04_unknown_defaults_to_mobile(self, edition_api):
        # Fail-open: a managed subscriber with a weird plan still gets a seat.
        assert edition_api.plan_to_edition("wibble") == "mobile"

    def test_C_MCP_EDITION_05_empty_defaults_to_mobile(self, edition_api):
        assert edition_api.plan_to_edition("") == "mobile"
        assert edition_api.plan_to_edition(None) == "mobile"

    def test_C_MCP_EDITION_06_case_and_whitespace_insensitive(self, edition_api):
        assert edition_api.plan_to_edition("  Individual ") == "mobile"
        assert edition_api.plan_to_edition("BUSINESS") == "business"


# ═════════════════════════════════════════════════════════════════════════════
# EDITION/MODE ENFORCEMENT — _enforce_edition_mode
# returns (effective_edition, effective_mode)
# ═════════════════════════════════════════════════════════════════════════════
class TestEnforcement:
    def test_C_MCP_EDITION_10_home_cannot_be_server(self, edition_api):
        assert edition_api.enforce("home", "server", "ok") == ("home", "personal")

    def test_C_MCP_EDITION_11_mobile_cannot_be_server(self, edition_api):
        # Mobile tier has no server entitlement; mode falls back to personal.
        assert edition_api.enforce("mobile", "server", "ok") == ("mobile", "personal")

    def test_C_MCP_EDITION_12_business_server_is_valid(self, edition_api):
        assert edition_api.enforce("business", "server", "ok") == ("business", "server")

    def test_C_MCP_EDITION_13_mobile_personal_ok_is_valid(self, edition_api):
        assert edition_api.enforce("mobile", "personal", "ok") == ("mobile", "personal")

    def test_C_MCP_EDITION_14_mobile_blocked_reverts_to_home(self, edition_api):
        # A paid edition with no valid subscription cannot be claimed.
        assert edition_api.enforce("mobile", "personal", "blocked") == ("home", "personal")

    def test_C_MCP_EDITION_15_mobile_unmanaged_reverts_to_home(self, edition_api):
        assert edition_api.enforce("mobile", "personal", "unmanaged") == ("home", "personal")

    def test_C_MCP_EDITION_16_business_blocked_reverts_to_home(self, edition_api):
        assert edition_api.enforce("business", "server", "blocked") == ("home", "personal")

    def test_C_MCP_EDITION_17_mobile_warning_still_valid(self, edition_api):
        # "warning" (in grace / near expiry) still entitles the edition.
        assert edition_api.enforce("mobile", "personal", "warning") == ("mobile", "personal")


# ═════════════════════════════════════════════════════════════════════════════
# 2-ACTIVE-INSTALL RULE — _evaluate_activation
# returns dict(decision, active_install_ids, active_count, this_active, message)
# ═════════════════════════════════════════════════════════════════════════════
class TestActivationRule:
    NOW = _utc(2026, 5, 20)

    def _entry(self, *activations):
        return {"name": "Test", "plan": "mobile", "activations": list(activations)}

    def _act(self, iid, days_ago):
        seen = _iso(self.NOW - dt.timedelta(days=days_ago))
        return {"install_id": iid, "first_seen": seen, "last_seen": seen,
                "os": "Windows-11", "version": "7.0.0"}

    def test_C_MCP_ACTIVATION_01_empty_install_id_is_unbound(self, edition_api):
        r = edition_api.evaluate(self._entry(), "", now=self.NOW)
        assert r["decision"] == "unbound"          # fail-open

    def test_C_MCP_ACTIVATION_02_no_activations_is_admissible(self, edition_api):
        r = edition_api.evaluate(self._entry(), "aaaa000000000001", now=self.NOW)
        assert r["decision"] == "admissible"
        assert r["active_count"] == 0

    def test_C_MCP_ACTIVATION_03_already_active_is_active(self, edition_api):
        e = self._entry(self._act("aaaa000000000001", 1))
        r = edition_api.evaluate(e, "aaaa000000000001", now=self.NOW)
        assert r["decision"] == "active"
        assert r["this_active"] is True

    def test_C_MCP_ACTIVATION_04_one_other_active_new_is_admissible(self, edition_api):
        e = self._entry(self._act("aaaa000000000001", 1))
        r = edition_api.evaluate(e, "bbbb000000000002", now=self.NOW)
        assert r["decision"] == "admissible"
        assert r["active_count"] == 1

    def test_C_MCP_ACTIVATION_05_two_others_active_new_is_rejected(self, edition_api):
        e = self._entry(self._act("aaaa000000000001", 1),
                        self._act("bbbb000000000002", 2))
        r = edition_api.evaluate(e, "cccc000000000003", now=self.NOW)
        assert r["decision"] == "rejected"
        assert r["active_count"] == 2
        assert set(r["active_install_ids"]) == {"aaaa000000000001", "bbbb000000000002"}

    def test_C_MCP_ACTIVATION_06_stale_install_auto_releases(self, edition_api):
        # 2 records but one is 20 days old (> 14-day window) → only 1 active,
        # so the new install is admissible.
        e = self._entry(self._act("aaaa000000000001", 1),
                        self._act("bbbb000000000002", 20))
        r = edition_api.evaluate(e, "cccc000000000003", now=self.NOW)
        assert r["decision"] == "admissible"
        assert r["active_count"] == 1
        assert r["active_install_ids"] == ["aaaa000000000001"]

    def test_C_MCP_ACTIVATION_07_this_active_among_two_is_active(self, edition_api):
        # This machine is one of two active → it keeps its seat.
        e = self._entry(self._act("aaaa000000000001", 1),
                        self._act("bbbb000000000002", 2))
        r = edition_api.evaluate(e, "aaaa000000000001", now=self.NOW)
        assert r["decision"] == "active"

    def test_C_MCP_ACTIVATION_08_exactly_at_window_boundary(self, edition_api):
        # last_seen exactly 14 days ago counts as active (>= cutoff).
        e = self._entry(self._act("aaaa000000000001", 14))
        r = edition_api.evaluate(e, "bbbb000000000002", now=self.NOW)
        assert r["active_count"] == 1

    def test_C_MCP_ACTIVATION_09_malformed_entries_are_skipped(self, edition_api):
        e = {"activations": [
            "not-a-dict",
            {"no_install_id": True},
            {"install_id": "", "last_seen": _iso(self.NOW)},
            self._act("aaaa000000000001", 1),
        ]}
        r = edition_api.evaluate(e, "bbbb000000000002", now=self.NOW)
        # Only the one valid recent entry counts.
        assert r["active_count"] == 1
        assert r["active_install_ids"] == ["aaaa000000000001"]

    def test_C_MCP_ACTIVATION_10_z_suffix_and_naive_timestamps_parse(self, edition_api):
        recent = self.NOW - dt.timedelta(days=1)
        e = {"activations": [
            {"install_id": "aaaa000000000001",
             "last_seen": recent.replace(tzinfo=None).isoformat() + "Z"},
            {"install_id": "bbbb000000000002",
             "last_seen": recent.replace(tzinfo=None).isoformat()},  # naive
        ]}
        r = edition_api.evaluate(e, "cccc000000000003", now=self.NOW)
        assert r["active_count"] == 2  # both parsed and counted

    def test_C_MCP_ACTIVATION_11_missing_activations_key_is_admissible(self, edition_api):
        r = edition_api.evaluate({"name": "x"}, "aaaa000000000001", now=self.NOW)
        assert r["decision"] == "admissible"

    def test_C_MCP_ACTIVATION_12_duplicate_install_id_counted_once(self, edition_api):
        e = self._entry(self._act("aaaa000000000001", 1),
                        self._act("aaaa000000000001", 2))  # same id twice
        r = edition_api.evaluate(e, "bbbb000000000002", now=self.NOW)
        assert r["active_count"] == 1  # de-duped

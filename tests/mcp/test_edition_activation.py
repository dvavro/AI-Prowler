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
import json

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


# ═════════════════════════════════════════════════════════════════════════════
# BUSINESS LICENSE GRACE LADDER — _evaluate_license_grace (v7.0.0 Phase B Block 2)
# returns dict(effective_edition, action, banner, used_network)
# Base spec §3.3/§3.4. Pure function, injectable clock → fully deterministic.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def grace_api(mcp_module):
    fn = getattr(mcp_module, "_evaluate_license_grace", None)
    if fn is None:
        pytest.skip("_evaluate_license_grace not at module level "
                    "(Phase B Block 2 not present).")
    return fn


class TestLicenseGrace:
    NOW = _utc(2026, 5, 20)

    def _cache(self, days_since_ok, status="active"):
        """A cache whose last successful validation was N days ago."""
        when = self.NOW - dt.timedelta(days=days_since_ok)
        return {"last_validated_at": _iso(when), "status": status,
                "cached_expires_at": _iso(self.NOW + dt.timedelta(days=300))}

    # ── Fresh validation this launch ────────────────────────────────────────
    def test_C_MCP_LICENSE_01_fresh_valid_is_business(self, grace_api):
        r = grace_api({}, {"valid": True, "edition": "business"}, now=self.NOW)
        assert r["effective_edition"] == "business"
        assert r["action"] == "validated"
        assert r["used_network"] is True

    def test_C_MCP_LICENSE_02_revoked_reverts_immediately(self, grace_api):
        # Even with a fresh, recent cache, an explicit revoke wins instantly.
        r = grace_api(self._cache(0), {"valid": False, "reason": "revoked"}, now=self.NOW)
        assert r["effective_edition"] == "home"
        assert r["action"] == "reverted_revoked"
        assert r["banner"]

    def test_C_MCP_LICENSE_03_parent_revoked_reverts(self, grace_api):
        r = grace_api(self._cache(0), {"valid": False, "reason": "parent_revoked"}, now=self.NOW)
        assert r["effective_edition"] == "home"
        assert r["action"] == "reverted_revoked"

    def test_C_MCP_LICENSE_04_suspended_reverts(self, grace_api):
        r = grace_api(self._cache(1), {"valid": False, "reason": "suspended"}, now=self.NOW)
        assert r["effective_edition"] == "home"

    # ── Cached fast-path (no network call made) ─────────────────────────────
    def test_C_MCP_LICENSE_05_cache_within_24h_is_business(self, grace_api):
        # validate_result None = no network call; cache 2h old → trust it.
        cache = {"last_validated_at": _iso(self.NOW - dt.timedelta(hours=2)),
                 "status": "active"}
        r = grace_api(cache, None, now=self.NOW)
        assert r["effective_edition"] == "business"
        assert r["action"] == "cached_fresh"
        assert r["used_network"] is False

    # ── Grace ladder on network failure (validate_result None, old cache) ───
    # NOTE v7.0.0: with FRESH=30d, WARN=37d, GRACE=44d, the grace ladder only
    # fires for caches OLDER than FRESH. Each tier gets a 7-day window beyond
    # the 30-day trust period. Tests below pick ages that fall cleanly in each.
    def test_C_MCP_LICENSE_06_grace_silent_under_37_days(self, grace_api):
        # 33d old → past FRESH (30d), under WARN (37d) → silent grace.
        r = grace_api(self._cache(33), None, now=self.NOW)
        assert r["effective_edition"] == "business"
        assert r["action"] == "grace_silent"
        assert r["banner"] == ""

    def test_C_MCP_LICENSE_07_grace_warning_between_37_and_44(self, grace_api):
        # 40d old → past WARN (37d), under GRACE (44d) → warning banner.
        r = grace_api(self._cache(40), None, now=self.NOW)
        assert r["effective_edition"] == "business"
        assert r["action"] == "grace_warning"
        assert r["banner"]   # non-empty warning

    def test_C_MCP_LICENSE_08_revert_after_44_days(self, grace_api):
        # 50d old → past GRACE (44d) → revert to home.
        r = grace_api(self._cache(50), None, now=self.NOW)
        assert r["effective_edition"] == "home"
        assert r["action"] == "reverted_expired"
        assert r["banner"]

    def test_C_MCP_LICENSE_09_no_cache_no_validation_is_home(self, grace_api):
        # Never validated and can't now → cannot grant business.
        r = grace_api({}, None, now=self.NOW)
        assert r["effective_edition"] == "home"
        assert r["action"] == "reverted_expired"

    def test_C_MCP_LICENSE_10_boundary_just_under_37_days(self, grace_api):
        # 36d 20h → still silent (warning starts AT 37).
        cache = {"last_validated_at": _iso(self.NOW - dt.timedelta(days=36, hours=20))}
        r = grace_api(cache, None, now=self.NOW)
        assert r["action"] == "grace_silent"

    def test_C_MCP_LICENSE_11_boundary_just_under_44_days(self, grace_api):
        # 43d 20h → still warning (revert starts AT 44).
        cache = {"last_validated_at": _iso(self.NOW - dt.timedelta(days=43, hours=20))}
        r = grace_api(cache, None, now=self.NOW)
        assert r["action"] == "grace_warning"
        assert r["effective_edition"] == "business"

    def test_C_MCP_LICENSE_12_unknown_negative_reason_uses_grace(self, grace_api):
        # A non-hard-fail negative (e.g. transient) should fall through to grace,
        # not instantly revert. With a 3-day-old cache → grace_silent.
        r = grace_api(self._cache(3), {"valid": False, "reason": "weird_transient"},
                      now=self.NOW)
        assert r["effective_edition"] == "business"
        assert r["action"] == "grace_silent"

    def test_C_MCP_LICENSE_13_z_suffix_timestamp_parses(self, grace_api):
        cache = {"last_validated_at":
                 (self.NOW - dt.timedelta(hours=1)).replace(tzinfo=None).isoformat() + "Z"}
        r = grace_api(cache, None, now=self.NOW)
        assert r["action"] == "cached_fresh"

    def test_C_MCP_LICENSE_14_corrupt_timestamp_falls_back_home(self, grace_api):
        r = grace_api({"last_validated_at": "garbage"}, None, now=self.NOW)
        assert r["effective_edition"] == "home"


# ═════════════════════════════════════════════════════════════════════════════
# MULTI-USER AUTH / SCOPING — _resolve_user, _allowed_collections, _can_index
# (v7.0.0 Phase B Block 3, spec §6). These are the SECURITY SPINE: a bug here
# leaks data between employees, so coverage is deliberately cross-role and
# adversarial. All three functions are PURE.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def mu_api(mcp_module):
    needed = ("_resolve_user", "_allowed_collections", "_can_index")
    missing = [n for n in needed if getattr(mcp_module, n, None) is None]
    if missing:
        pytest.skip(f"Multi-user helpers not present (missing: {', '.join(missing)}). "
                    "Phase B Block 3 not loaded.")

    class Api:
        resolve = staticmethod(mcp_module._resolve_user)
        allowed = staticmethod(mcp_module._allowed_collections)
        can_index = staticmethod(mcp_module._can_index)
    return Api


def _users_doc():
    """A representative users.json-shaped dict."""
    return {
        "version": "1.0",
        "company_id": "vavro-construction",
        "users": {
            "owner00000000000": {"name": "Olive Owner", "role": "owner",
                                 "scopes": [], "private_collection_enabled": True,
                                 "status": "active"},
            "mgr0000000000000": {"name": "Mona Manager", "role": "manager",
                                 "scopes": ["scope:sales", "scope:office"],
                                 "private_collection_enabled": True,
                                 "status": "active"},
            "staff00000000000": {"name": "Sam Staff", "role": "staff",
                                 "scopes": ["scope:office"],
                                 "private_collection_enabled": False,
                                 "status": "active"},
            "field00000000000": {"name": "Fred Field", "role": "field_crew",
                                 "scopes": ["scope:field"],
                                 "private_collection_enabled": False,
                                 "status": "active"},
            "suspended0000000": {"name": "Sue Suspended", "role": "manager",
                                 "scopes": ["scope:sales"], "status": "suspended"},
        },
    }


class TestResolveUser:
    def test_C_MCP_MU_01_valid_active_token_resolves(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        assert u is not None
        assert u["role"] == "manager"
        assert u["id"] == "mona-manager"   # slug from "Mona Manager" via _make_user_id()

    def test_C_MCP_MU_02_unknown_token_is_none(self, mu_api):
        assert mu_api.resolve(_users_doc(), "nope") is None

    def test_C_MCP_MU_03_empty_token_is_none(self, mu_api):
        assert mu_api.resolve(_users_doc(), "") is None

    def test_C_MCP_MU_04_suspended_user_is_none(self, mu_api):
        # Soft-revoke: present in the file but denied access.
        assert mu_api.resolve(_users_doc(), "suspended0000000") is None

    def test_C_MCP_MU_05_none_users_data_is_none(self, mu_api):
        assert mu_api.resolve(None, "mgr0000000000000") is None

    def test_C_MCP_MU_06_unknown_role_normalized_to_least_privilege(self, mu_api):
        doc = {"users": {"x": {"role": "superadmin", "status": "active"}}}
        u = mu_api.resolve(doc, "x")
        assert u["role"] == "field_crew"   # defense against hand-edited file


class TestAllowedCollections:
    ALL_ROLES = ["scope:sales", "scope:office", "scope:field", "scope:owner_only"]

    def test_C_MCP_MU_10_none_user_gets_nothing(self, mu_api):
        assert mu_api.allowed(None) == []

    def test_C_MCP_MU_11_everyone_gets_shared(self, mu_api):
        for tok in ("owner00000000000", "mgr0000000000000",
                    "staff00000000000", "field00000000000"):
            u = mu_api.resolve(_users_doc(), tok)
            assert "shared" in mu_api.allowed(u, self.ALL_ROLES)

    def test_C_MCP_MU_12_owner_reads_all_role_collections(self, mu_api):
        u = mu_api.resolve(_users_doc(), "owner00000000000")
        cols = mu_api.allowed(u, self.ALL_ROLES)
        for rc in self.ALL_ROLES:
            assert rc in cols, rc
        # Owner has private enabled too — slug from "Olive Owner".
        assert "user:olive-owner" in cols

    def test_C_MCP_MU_13_manager_only_assigned_scopes(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        cols = mu_api.allowed(u, self.ALL_ROLES)
        assert "scope:sales" in cols and "scope:office" in cols
        # NOT scopes they weren't assigned, even though they exist on the server.
        assert "scope:field" not in cols
        assert "scope:owner_only" not in cols

    def test_C_MCP_MU_14_manager_private_collection_when_enabled(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        # Private collection key is "user:<slug>" where slug = _make_user_id("Mona Manager")
        assert "user:mona-manager" in mu_api.allowed(u, self.ALL_ROLES)

    def test_C_MCP_MU_15_field_no_private_when_disabled(self, mu_api):
        u = mu_api.resolve(_users_doc(), "field00000000000")
        cols = mu_api.allowed(u, self.ALL_ROLES)
        assert not any(c.startswith("user:") for c in cols)
        assert cols == ["shared", "scope:field"]

    def test_C_MCP_MU_16_staff_scopes_only(self, mu_api):
        u = mu_api.resolve(_users_doc(), "staff00000000000")
        cols = mu_api.allowed(u, self.ALL_ROLES)
        assert cols == ["shared", "scope:office"]

    def test_C_MCP_MU_17_bare_scope_names_get_scope_prefix(self, mu_api):
        # Bare 'sales' or legacy 'role:sales' both canonicalize to 'scope:sales'.
        doc = {"users": {"x": {"role": "manager", "scopes": ["sales"],
                               "status": "active"}}}
        u = mu_api.resolve(doc, "x")
        assert "scope:sales" in mu_api.allowed(u)


class TestCanIndex:
    def test_C_MCP_MU_20_owner_can_index_anything(self, mu_api):
        u = mu_api.resolve(_users_doc(), "owner00000000000")
        for tgt in ("shared", "scope:sales", "scope:field", "user:someoneelse"):
            ok, _ = mu_api.can_index(u, tgt)
            assert ok, tgt

    def test_C_MCP_MU_21_manager_can_write_shared(self, mu_api):
        # Option A: 'shared' is the company commons — any can_write role (manager
        # included) may ADD to it. Per-file ownership still protects each doc.
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "shared")
        assert ok is True

    def test_C_MCP_MU_22_manager_can_index_assigned_scope(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "scope:sales")
        assert ok is True

    def test_C_MCP_MU_23_manager_cannot_index_unassigned_scope(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "scope:field")
        assert ok is False

    def test_C_MCP_MU_24_manager_own_private_ok(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        # Own private uses slug id: _make_user_id("Mona Manager") = "mona-manager"
        ok, _ = mu_api.can_index(u, "user:mona-manager")
        assert ok is True

    def test_C_MCP_MU_25_manager_cannot_index_others_private(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "user:someoneelse")
        assert ok is False

    def test_C_MCP_MU_26_staff_limited_index_access(self, mu_api):
        # v7.0.1: staff has manage_db='limited' — may index own private and assigned
        # scopes, but NOT the shared commons (can_write_shared=False).
        u = mu_api.resolve(_users_doc(), "staff00000000000")
        # Assigned scope (scope:office) → allowed.
        ok, _ = mu_api.can_index(u, "scope:office")
        assert ok is True, "staff should index their assigned scope"
        # Own private → allowed. slug from "Sam Staff" = "sam-staff"
        ok, _ = mu_api.can_index(u, "user:sam-staff")
        assert ok is True, "staff should index their own private collection"
        # Shared commons → denied (can_write_shared=False for staff).
        ok, _ = mu_api.can_index(u, "shared")
        assert ok is False, "staff must not write to shared"
        # An unassigned scope → denied.
        ok, _ = mu_api.can_index(u, "scope:sales")
        assert ok is False, "staff must not index scopes they are not assigned"

    def test_C_MCP_MU_27_field_cannot_index_at_all(self, mu_api):
        u = mu_api.resolve(_users_doc(), "field00000000000")
        ok, _ = mu_api.can_index(u, "scope:field")
        assert ok is False

    def test_C_MCP_MU_28_none_user_cannot_index(self, mu_api):
        ok, _ = mu_api.can_index(None, "shared")
        assert ok is False

    def test_C_MCP_MU_29_empty_target_rejected(self, mu_api):
        u = mu_api.resolve(_users_doc(), "owner00000000000")
        ok, _ = mu_api.can_index(u, "")
        assert ok is False


# ═════════════════════════════════════════════════════════════════════════════
# ADMIN ROLE GATE + AUDIT LOG helpers (v7.0.0 Phase B Block 3, spec §6.6/§9.1)
# _user_has_role, _is_admin, _format_audit_entry, _filter_audit_entries — pure.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def admin_api(mcp_module):
    needed = ("_user_has_role", "_is_admin",
              "_format_audit_entry", "_filter_audit_entries")
    missing = [n for n in needed if getattr(mcp_module, n, None) is None]
    if missing:
        pytest.skip(f"Admin/audit helpers not present (missing: {', '.join(missing)}).")

    class Api:
        has_role = staticmethod(mcp_module._user_has_role)
        is_admin = staticmethod(mcp_module._is_admin)
        fmt = staticmethod(mcp_module._format_audit_entry)
        filt = staticmethod(mcp_module._filter_audit_entries)
    return Api


class TestRoleGate:
    def test_C_MCP_ADMIN_01_owner_is_admin(self, admin_api):
        assert admin_api.is_admin({"role": "owner"}) is True

    def test_C_MCP_ADMIN_02_others_not_admin(self, admin_api):
        for role in ("manager", "staff", "field_crew"):
            assert admin_api.is_admin({"role": role}) is False, role

    def test_C_MCP_ADMIN_03_none_user_not_admin(self, admin_api):
        assert admin_api.is_admin(None) is False

    def test_C_MCP_ADMIN_04_has_role_exact_match(self, admin_api):
        assert admin_api.has_role({"role": "manager"}, "manager") is True
        assert admin_api.has_role({"role": "manager"}, "owner") is False

    def test_C_MCP_ADMIN_05_has_role_none_user_false(self, admin_api):
        assert admin_api.has_role(None, "owner") is False

    def test_C_MCP_ADMIN_06_has_role_case_insensitive(self, admin_api):
        assert admin_api.has_role({"role": "Owner"}, "owner") is True


class TestAuditHelpers:
    NOW = _utc(2026, 5, 20)

    def test_C_MCP_ADMIN_10_format_records_core_fields(self, admin_api):
        e = admin_api.fmt({"id": "u1", "name": "Al", "role": "manager"},
                          "search_documents", collection="scope:sales", now=self.NOW)
        assert e["user_id"] == "u1"
        assert e["tool"] == "search_documents"
        assert e["collection"] == "scope:sales"
        assert e["ts"].startswith("2026-05-20")

    def test_C_MCP_ADMIN_11_format_none_user_blank_fields(self, admin_api):
        e = admin_api.fmt(None, "list_users", now=self.NOW)
        assert e["user_id"] == "" and e["user_name"] == ""
        assert e["tool"] == "list_users"

    def test_C_MCP_ADMIN_12_format_event(self, admin_api):
        e = admin_api.fmt({"id": "o", "role": "owner"}, "",
                          event="remote_support_enabled", now=self.NOW)
        assert e["event"] == "remote_support_enabled"

    def test_C_MCP_ADMIN_13_filter_limit(self, admin_api):
        rows = [admin_api.fmt({"id": str(i)}, "t", now=self.NOW + dt.timedelta(minutes=i))
                for i in range(50)]
        out = admin_api.filt(rows, limit=10)
        assert len(out) == 10
        # newest-last preserved → last 10
        assert out[-1]["user_id"] == "49"

    def test_C_MCP_ADMIN_14_filter_since(self, admin_api):
        rows = [admin_api.fmt({"id": str(i)}, "t",
                              now=self.NOW + dt.timedelta(days=i)) for i in range(10)]
        cutoff = self.NOW + dt.timedelta(days=5)
        out = admin_api.filt(rows, limit=100, since=cutoff)
        # entries for days 5..9 → 5 rows
        assert len(out) == 5
        assert out[0]["user_id"] == "5"

    def test_C_MCP_ADMIN_15_filter_empty_input(self, admin_api):
        assert admin_api.filt(None) == []
        assert admin_api.filt([]) == []

    def test_C_MCP_ADMIN_16_filter_since_iso_string(self, admin_api):
        rows = [admin_api.fmt({"id": str(i)}, "t",
                              now=self.NOW + dt.timedelta(days=i)) for i in range(4)]
        out = admin_api.filt(rows, limit=100,
                             since=(self.NOW + dt.timedelta(days=2)).isoformat())
        assert len(out) == 2  # days 2,3


# ═════════════════════════════════════════════════════════════════════════════
# MULTI-COLLECTION RESULT MERGE — _merge_collection_results
# (v7.0.0 Phase B Step 2 read path). Combines per-collection ChromaDB results
# into one distance-ranked list. PURE. The final step of read enforcement:
# after querying the user's allowed collections, merge into one answer.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def merge_api(mcp_module):
    fn = getattr(mcp_module, "_merge_collection_results", None)
    if fn is None:
        pytest.skip("_merge_collection_results not present (Phase B Step 2 read path).")
    return fn


def _chroma(ids, docs, dists, metas=None):
    """Build a ChromaDB-query-shaped result (list-of-lists)."""
    metas = metas or [{} for _ in ids]
    return {"ids": [ids], "documents": [docs], "distances": [dists],
            "metadatas": [metas]}


class TestMergeCollectionResults:
    def test_C_MCP_MERGE_01_single_collection_passthrough(self, merge_api):
        per = {"shared": _chroma(["a", "b"], ["doc a", "doc b"], [0.1, 0.2])}
        out = merge_api(per, n_results=10)
        assert [h["id"] for h in out] == ["a", "b"]
        assert all(h["collection"] == "shared" for h in out)

    def test_C_MCP_MERGE_02_cross_collection_ranked_by_distance(self, merge_api):
        per = {
            "shared":     _chroma(["s1"], ["shared hit"], [0.5]),
            "scope:sales": _chroma(["r1"], ["sales hit"],  [0.1]),
            "user:bob":   _chroma(["u1"], ["bob hit"],    [0.3]),
        }
        out = merge_api(per, n_results=10)
        # Best (lowest distance) first, regardless of source collection.
        assert [h["id"] for h in out] == ["r1", "u1", "s1"]
        assert out[0]["collection"] == "scope:sales"

    def test_C_MCP_MERGE_03_truncates_to_n_results(self, merge_api):
        per = {"shared": _chroma(["a", "b", "c", "d"], ["", "", "", ""],
                                 [0.1, 0.2, 0.3, 0.4])}
        out = merge_api(per, n_results=2)
        assert len(out) == 2
        assert [h["id"] for h in out] == ["a", "b"]   # best two

    def test_C_MCP_MERGE_04_provenance_tagged(self, merge_api):
        per = {
            "scope:sales": _chroma(["r1"], ["x"], [0.2]),
            "user:bob":   _chroma(["u1"], ["y"], [0.1]),
        }
        out = merge_api(per, n_results=10)
        prov = {h["id"]: h["collection"] for h in out}
        assert prov == {"u1": "user:bob", "r1": "scope:sales"}

    def test_C_MCP_MERGE_05_dedup_by_id(self, merge_api):
        # Same id in two collections → counted once (first seen wins).
        per = {
            "shared":     _chroma(["dup"], ["from shared"], [0.4]),
            "scope:sales": _chroma(["dup"], ["from sales"],  [0.1]),
        }
        out = merge_api(per, n_results=10)
        assert len(out) == 1

    def test_C_MCP_MERGE_06_empty_dict(self, merge_api):
        assert merge_api({}, n_results=10) == []

    def test_C_MCP_MERGE_07_none_input(self, merge_api):
        assert merge_api(None, n_results=10) == []

    def test_C_MCP_MERGE_08_empty_collection_skipped(self, merge_api):
        per = {
            "shared":     _chroma([], [], []),
            "scope:sales": _chroma(["r1"], ["x"], [0.2]),
        }
        out = merge_api(per, n_results=10)
        assert [h["id"] for h in out] == ["r1"]

    def test_C_MCP_MERGE_09_malformed_result_skipped(self, merge_api):
        per = {
            "bad1": "not a dict",
            "bad2": None,
            "good": _chroma(["g1"], ["x"], [0.1]),
        }
        out = merge_api(per, n_results=10)
        assert [h["id"] for h in out] == ["g1"]

    def test_C_MCP_MERGE_10_already_unwrapped_shape_tolerated(self, merge_api):
        # Some callers may pass the single-query (already-unwrapped) form.
        per = {"shared": {"ids": ["a"], "documents": ["x"],
                          "distances": [0.1], "metadatas": [{}]}}
        out = merge_api(per, n_results=10)
        assert [h["id"] for h in out] == ["a"]

    def test_C_MCP_MERGE_11_missing_distance_sorts_last(self, merge_api):
        per = {
            "c1": {"ids": [["a"]], "documents": [["x"]], "metadatas": [[{}]]},  # no distances
            "c2": _chroma(["b"], ["y"], [0.5]),
        }
        out = merge_api(per, n_results=10)
        # 'b' has a real distance; 'a' (inf) sorts after it.
        assert [h["id"] for h in out] == ["b", "a"]

    def test_C_MCP_MERGE_12_metadata_preserved(self, merge_api):
        per = {"shared": _chroma(["a"], ["doc"], [0.1],
                                 metas=[{"source": "file.pdf", "page": 3}])}
        out = merge_api(per, n_results=10)
        assert out[0]["metadata"]["source"] == "file.pdf"
        assert out[0]["metadata"]["page"] == 3

    def test_C_MCP_MERGE_13_non_numeric_distance_treated_as_inf(self, merge_api):
        per = {
            "c1": _chroma(["a"], ["x"], ["not-a-number"]),
            "c2": _chroma(["b"], ["y"], [0.5]),
        }
        out = merge_api(per, n_results=10)
        assert [h["id"] for h in out] == ["b", "a"]   # 'a' → inf, sorts last

    def test_C_MCP_MERGE_14_document_aligned_with_id(self, merge_api):
        per = {"shared": _chroma(["a", "b"], ["doc A", "doc B"], [0.2, 0.1])}
        out = merge_api(per, n_results=10)
        # After ranking, b (0.1) first — its document must still be "doc B".
        assert out[0]["id"] == "b" and out[0]["document"] == "doc B"
        assert out[1]["id"] == "a" and out[1]["document"] == "doc A"


# ═════════════════════════════════════════════════════════════════════════════
# MODEL B PATH→COLLECTION RESOLVER — _resolve_collection_for_path
# (v7.0.0 Phase B Step 2 write path). Decides which collection an indexed file
# belongs to from a configured path→collection map. PURE. This is the WRITE-side
# data-isolation decision, so coverage is adversarial: boundary matching,
# longest-prefix precedence, and the fallback ladder.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def resolver_api(mcp_module):
    fn = getattr(mcp_module, "_resolve_collection_for_path", None)
    if fn is None:
        pytest.skip("_resolve_collection_for_path not present (Phase B Step 2 write path).")
    return fn


def _mapping(rules, default=None):
    m = {"rules": rules}
    if default is not None:
        m["default_collection"] = default
    return m


class TestResolveCollectionForPath:
    SALES = {"prefix": "C:/CompanyDocs/Sales", "collection": "scope:sales"}
    PUBLIC = {"prefix": "C:/CompanyDocs/Public", "collection": "shared"}

    def test_C_MCP_RESOLVE_01_simple_prefix_match(self, resolver_api):
        m = _mapping([self.SALES, self.PUBLIC])
        assert resolver_api("C:/CompanyDocs/Sales/q3.pdf", m) == "scope:sales"
        assert resolver_api("C:/CompanyDocs/Public/flyer.pdf", m) == "shared"

    def test_C_MCP_RESOLVE_02_longest_prefix_wins(self, resolver_api):
        # A nested rule must beat the broader one.
        m = _mapping([
            {"prefix": "C:/CompanyDocs/Sales", "collection": "scope:sales"},
            {"prefix": "C:/CompanyDocs/Sales/Confidential", "collection": "scope:exec"},
        ])
        assert resolver_api("C:/CompanyDocs/Sales/Confidential/m.pdf", m) == "scope:exec"
        assert resolver_api("C:/CompanyDocs/Sales/normal.pdf", m) == "scope:sales"

    def test_C_MCP_RESOLVE_03_segment_boundary_no_false_match(self, resolver_api):
        # 'Sales' must NOT match 'SalesArchive' (the critical leak-prevention case).
        m = _mapping([self.SALES], default="shared")
        assert resolver_api("C:/CompanyDocs/SalesArchive/old.pdf", m) == "shared"
        # but the real Sales dir still matches
        assert resolver_api("C:/CompanyDocs/Sales/new.pdf", m) == "scope:sales"

    def test_C_MCP_RESOLVE_04_exact_dir_match(self, resolver_api):
        m = _mapping([self.SALES])
        # The directory path itself (no trailing file) matches its rule.
        assert resolver_api("C:/CompanyDocs/Sales", m) == "scope:sales"

    def test_C_MCP_RESOLVE_05_case_insensitive(self, resolver_api):
        m = _mapping([self.SALES])
        assert resolver_api("c:/companydocs/SALES/x.pdf", m) == "scope:sales"

    def test_C_MCP_RESOLVE_06_backslash_agnostic(self, resolver_api):
        m = _mapping([self.SALES])
        assert resolver_api("C:\\CompanyDocs\\Sales\\x.pdf", m) == "scope:sales"

    def test_C_MCP_RESOLVE_07_no_match_uses_default(self, resolver_api):
        m = _mapping([self.SALES], default="shared")
        assert resolver_api("D:/Random/thing.pdf", m) == "shared"

    def test_C_MCP_RESOLVE_08_no_match_no_default_uses_user_private(self, resolver_api):
        m = _mapping([self.SALES])   # no default
        user = {"id": "alice000000000001", "role": "manager"}
        assert resolver_api("D:/Random/thing.pdf", m, user) == "user:alice000000000001"

    def test_C_MCP_RESOLVE_09_no_match_no_default_no_user_falls_to_documents(self, resolver_api):
        # Personal mode: no map, no user → the legacy single collection.
        assert resolver_api("D:/Random/thing.pdf", {}, None) == "documents"
        assert resolver_api("D:/Random/thing.pdf", None, None) == "documents"

    def test_C_MCP_RESOLVE_10_empty_mapping_personal_default(self, resolver_api):
        assert resolver_api("C:/anything.pdf", {"rules": []}) == "documents"

    def test_C_MCP_RESOLVE_11_malformed_rules_skipped(self, resolver_api):
        m = {"rules": ["not-a-dict", {"prefix": "", "collection": "x"},
                       {"prefix": "C:/A", "collection": ""}, self.SALES],
             "default_collection": "shared"}
        # Only the valid SALES rule applies; the junk is skipped, not crashed on.
        assert resolver_api("C:/CompanyDocs/Sales/x.pdf", m) == "scope:sales"
        assert resolver_api("C:/A/y.pdf", m) == "shared"   # the ''-collection rule was skipped

    def test_C_MCP_RESOLVE_12_user_private_target_for_home_folder(self, resolver_api):
        # A rule can map a user's home folder to their private collection.
        m = _mapping([{"prefix": "C:/Users/bob/Private", "collection": "user:bob00000000000"}])
        assert resolver_api("C:/Users/bob/Private/notes.txt", m) == "user:bob00000000000"

    def test_C_MCP_RESOLVE_13_default_beats_user_private(self, resolver_api):
        # When a default is configured, it takes precedence over the user fallback.
        m = _mapping([self.SALES], default="shared")
        user = {"id": "alice000000000001"}
        assert resolver_api("D:/unmatched/x.pdf", m, user) == "shared"

    def test_C_MCP_RESOLVE_14_trailing_slash_normalized(self, resolver_api):
        m = _mapping([{"prefix": "C:/CompanyDocs/Sales/", "collection": "scope:sales"}])
        assert resolver_api("C:/CompanyDocs/Sales/x.pdf", m) == "scope:sales"


# ═════════════════════════════════════════════════════════════════════════════
# _current_user(ctx) — extract the authed user from a FastMCP Context.
# (v7.0.0 Phase B Step 2 read path.) Returns None in personal mode / on any
# missing link in the ctx chain; never raises. Tested with stubbed ctx objects.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def current_user_api(mcp_module):
    fn = getattr(mcp_module, "_current_user", None)
    if fn is None:
        pytest.skip("_current_user not present (Phase B Step 2 read path).")
    return fn


class _Stub:
    """Minimal attribute holder for building fake ctx chains."""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class TestCurrentUser:
    def test_C_MCP_CURUSER_01_none_ctx_is_none(self, current_user_api):
        assert current_user_api(None) is None

    def test_C_MCP_CURUSER_02_happy_path_returns_user(self, current_user_api):
        user = {"id": "tok123", "role": "owner"}
        ctx = _Stub(request_context=_Stub(request=_Stub(state=_Stub(user=user))))
        assert current_user_api(ctx) == user

    def test_C_MCP_CURUSER_03_no_user_on_state_is_none(self, current_user_api):
        # State exists but middleware never set .user (e.g. exempt route) → None.
        ctx = _Stub(request_context=_Stub(request=_Stub(state=_Stub())))
        assert current_user_api(ctx) is None

    def test_C_MCP_CURUSER_04_missing_request_context_is_none(self, current_user_api):
        ctx = _Stub()   # no request_context attribute at all
        assert current_user_api(ctx) is None

    def test_C_MCP_CURUSER_05_missing_request_is_none(self, current_user_api):
        ctx = _Stub(request_context=_Stub())   # no .request
        assert current_user_api(ctx) is None

    def test_C_MCP_CURUSER_06_user_explicitly_none(self, current_user_api):
        # Middleware set state.user = None (shouldn't happen, but be safe).
        ctx = _Stub(request_context=_Stub(request=_Stub(state=_Stub(user=None))))
        assert current_user_api(ctx) is None


# ═════════════════════════════════════════════════════════════════════════════
# DATA-MANAGEMENT / OWNER PROTECTION — _can_manage_user_data, _owner_user_id
# (v7.0.0 Phase B). Owner manages anyone; admin (can_manage_users, not owner)
# manages employees but NEVER the owner's data. PURE.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def manage_api(mcp_module):
    fn = getattr(mcp_module, "_can_manage_user_data", None)
    oid = getattr(mcp_module, "_owner_user_id", None)
    if fn is None or oid is None:
        pytest.skip("_can_manage_user_data/_owner_user_id not present.")

    class Api:
        can_manage = staticmethod(fn)
        owner_id = staticmethod(oid)
    return Api


class TestDataManagement:
    OWNER = {"id": "owner001", "role": "owner", "can_manage_users": True}
    ADMIN = {"id": "admin001", "role": "manager", "can_manage_users": True}
    STAFF = {"id": "staff001", "role": "staff"}
    OWNER_ID = "owner001"

    def test_C_MCP_MANAGE_01_owner_manages_employee(self, manage_api):
        ok, _ = manage_api.can_manage(self.OWNER, "staff001", self.OWNER_ID)
        assert ok is True

    def test_C_MCP_MANAGE_02_owner_manages_own(self, manage_api):
        ok, _ = manage_api.can_manage(self.OWNER, self.OWNER_ID, self.OWNER_ID)
        assert ok is True

    def test_C_MCP_MANAGE_03_admin_manages_employee(self, manage_api):
        ok, _ = manage_api.can_manage(self.ADMIN, "staff001", self.OWNER_ID)
        assert ok is True

    def test_C_MCP_MANAGE_04_admin_CANNOT_manage_owner(self, manage_api):
        # The core protection: admin blocked from the owner's data.
        ok, reason = manage_api.can_manage(self.ADMIN, self.OWNER_ID, self.OWNER_ID)
        assert ok is False
        assert "owner" in reason.lower()

    def test_C_MCP_MANAGE_05_staff_cannot_manage(self, manage_api):
        ok, _ = manage_api.can_manage(self.STAFF, "other001", self.OWNER_ID)
        assert ok is False

    def test_C_MCP_MANAGE_06_none_actor(self, manage_api):
        ok, _ = manage_api.can_manage(None, "x", self.OWNER_ID)
        assert ok is False

    def test_C_MCP_MANAGE_07_manager_without_flag_cannot(self, manage_api):
        plain_mgr = {"id": "m9", "role": "manager"}  # no can_manage_users
        ok, _ = manage_api.can_manage(plain_mgr, "staff001", self.OWNER_ID)
        assert ok is False

    def test_C_MCP_MANAGE_08_owner_id_lookup(self, manage_api):
        users = {"users": {
            "tokOwner": {"name": "Owner Person", "role": "owner"},
            "tokMgr":   {"name": "Mgr Person",   "role": "manager"},
        }}
        # _owner_user_id now returns slug from display name, not the dict key
        assert manage_api.owner_id(users) == "owner-person"

    def test_C_MCP_MANAGE_09_owner_id_none_when_no_owner(self, manage_api):
        users = {"users": {"tokMgr": {"role": "manager"}}}
        assert manage_api.owner_id(users) is None

    def test_C_MCP_MANAGE_10_unknown_owner_id_fails_closed(self, manage_api):
        # FAIL CLOSED: if the owner's id can't be determined, an admin is DENIED
        # management of ANY target — we never risk destroying owner data we
        # cannot rule out. (Owner-protection must be robust to users.json glitches.)
        ok, reason = manage_api.can_manage(self.ADMIN, "staff001", None)
        assert ok is False
        assert "fail closed" in reason.lower() or "unknown" in reason.lower()

    def test_C_MCP_MANAGE_11_owner_unaffected_by_unknown_id(self, manage_api):
        # The owner themself is still allowed even if owner_id lookup is None
        # (they're identified by role, not by id-matching).
        ok, _ = manage_api.can_manage(self.OWNER, "anyone", None)
        assert ok is True


# ═════════════════════════════════════════════════════════════════════════════
# WRITE-SIDE RESOLVER FACTORY — _build_collection_resolver, _company_collection_map
# (v7.0.0 Phase B write-side activation). Composes company path rules + per-user
# default into a collection_resolver. PURE (users_data injected). Note: the
# factory only PROPOSES a target; _can_index gates it at the index tool.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def resolver_factory_api(mcp_module):
    fn = getattr(mcp_module, "_build_collection_resolver", None)
    cm = getattr(mcp_module, "_company_collection_map", None)
    if fn is None or cm is None:
        pytest.skip("_build_collection_resolver/_company_collection_map not present.")

    class Api:
        build = staticmethod(fn)
        cmap = staticmethod(cm)
    return Api


class TestResolverFactory:
    USERA = {"id": "usera01", "role": "manager", "scopes": ["scope:sales"]}
    USERS = {
        "users": {"usera01": {"role": "manager", "scopes": ["scope:sales"]}},
        "collection_map": {
            "rules": [{"prefix": "C:/CompanyDocs/Sales", "collection": "scope:sales"},
                      {"prefix": "C:/CompanyDocs/Public", "collection": "shared"}],
        },
    }

    def test_C_MCP_FACTORY_01_personal_mode_none_resolver(self, resolver_factory_api):
        # No user → None resolver → pipeline keeps single 'documents' behavior.
        assert resolver_factory_api.build(None, self.USERS) is None

    def test_C_MCP_FACTORY_02_company_path_rule_routes(self, resolver_factory_api):
        r = resolver_factory_api.build(self.USERA, self.USERS)
        assert r("C:/CompanyDocs/Sales/q3.pdf") == "scope:sales"
        assert r("C:/CompanyDocs/Public/flyer.pdf") == "shared"

    def test_C_MCP_FACTORY_03_unmatched_falls_to_user_private(self, resolver_factory_api):
        r = resolver_factory_api.build(self.USERA, self.USERS)
        # No rule matches, no per-user default → indexer's own private collection.
        assert r("D:/Random/thing.pdf") == "user:usera01"

    def test_C_MCP_FACTORY_04_per_user_default_overrides_fallback(self, resolver_factory_api):
        # index_target routes unmatched files — but only to a scope the user may
        # actually write (scopes assignment). index_target alone does NOT grant
        # access; _can_index still gates. Here usera01 IS in scope:sales.
        user = {"id": "usera01", "role": "manager", "scopes": ["scope:sales"],
                "index_target": "scope:sales"}
        r = resolver_factory_api.build(user, self.USERS)
        assert r("D:/Random/thing.pdf") == "scope:sales"

    def test_C_MCP_FACTORY_05_path_rule_beats_user_default(self, resolver_factory_api):
        # A matching path rule (→ scope:sales) wins over the per-user default
        # (shared). usera01 is in scope:sales so the rule target is permitted.
        user = {"id": "usera01", "role": "manager", "scopes": ["scope:sales"],
                "index_target": "shared"}
        r = resolver_factory_api.build(user, self.USERS)
        assert r("C:/CompanyDocs/Sales/x.pdf") == "scope:sales"

    def test_C_MCP_FACTORY_06_no_map_no_default_uses_private(self, resolver_factory_api):
        r = resolver_factory_api.build(self.USERA, {"users": {}})
        assert r("C:/anything.pdf") == "user:usera01"

    def test_C_MCP_FACTORY_07_company_map_extracted(self, resolver_factory_api):
        cm = resolver_factory_api.cmap(self.USERS)
        assert isinstance(cm.get("rules"), list) and len(cm["rules"]) == 2

    def test_C_MCP_FACTORY_08_company_map_absent_is_empty(self, resolver_factory_api):
        assert resolver_factory_api.cmap({"users": {}}) == {}
        assert resolver_factory_api.cmap(None) == {} or isinstance(
            resolver_factory_api.cmap(None), dict)

    def test_C_MCP_FACTORY_09_company_default_used_when_no_user_default(self, resolver_factory_api):
        # Option A: 'shared' is the company commons — a MANAGER may write it, so
        # the company default 'shared' is honored (no degrade). Per-file ownership
        # still protects what each user adds.
        users = {"users": {}, "collection_map": {"rules": [],
                 "default_collection": "shared"}}
        r = resolver_factory_api.build(self.USERA, users)
        assert r("D:/x.pdf") == "shared"

    def test_C_MCP_FACTORY_10_staff_cannot_write_shared_degrades(self, resolver_factory_api):
        # Option-A BOUNDARY: 'shared' is open to WRITERS, not literally everyone.
        # A staff user (can_write=False) cannot write shared, so the company
        # default 'shared' degrades to their own private collection. This guards
        # against accidentally opening shared to read-only roles.
        staff = {"id": "staff9", "role": "staff"}
        users = {"users": {}, "collection_map": {"rules": [],
                 "default_collection": "shared"}}
        r = resolver_factory_api.build(staff, users)
        assert r("D:/x.pdf") == "user:staff9"

    def test_C_MCP_FACTORY_11_can_index_degrades_forbidden_role_rule(self, resolver_factory_api):
        # A path rule routes to scope:field, but USERA (sales manager) isn't in
        # that scope → _can_index denies → degrade to own private.
        users = {"users": {}, "collection_map": {"rules": [
            {"prefix": "C:/Co/Field", "collection": "scope:field"}]}}
        r = resolver_factory_api.build(self.USERA, users)
        assert r("C:/Co/Field/route.pdf") == "user:usera01"

    def test_C_MCP_FACTORY_12_can_index_allows_own_role_rule(self, resolver_factory_api):
        # Same shape but routing to the manager's OWN assigned scope → allowed.
        users = {"users": {}, "collection_map": {"rules": [
            {"prefix": "C:/Co/Sales", "collection": "scope:sales"}]}}
        r = resolver_factory_api.build(self.USERA, users)
        assert r("C:/Co/Sales/quote.pdf") == "scope:sales"


# ═════════════════════════════════════════════════════════════════════════════
# CHUNK-OWNERSHIP PURGE GATE — _can_purge_chunks, _chunk_owners
# (v7.0.0 Phase B "delete only your own"). Before the index pipeline purges
# existing chunks for a path, the actor must be allowed to remove every owner
# present. PURE. This is the protection against a bad employee wiping data.
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def purge_api(mcp_module):
    fn = getattr(mcp_module, "_can_purge_chunks", None)
    co = getattr(mcp_module, "_chunk_owners", None)
    if fn is None or co is None:
        pytest.skip("_can_purge_chunks/_chunk_owners not present.")

    class Api:
        can_purge = staticmethod(fn)
        owners = staticmethod(co)
    return Api


def _meta(owner):
    return {"filepath": "C:/x.pdf", "indexed_by": owner}


class TestPurgeGate:
    ALICE = {"id": "alice01", "role": "manager"}
    BOB   = {"id": "bob01", "role": "manager"}
    ADMIN = {"id": "admin01", "role": "manager", "can_manage_users": True}
    OWNER = {"id": "owner01", "role": "owner"}
    OWNER_ID = "owner01"

    def test_C_MCP_PURGE_01_own_chunks_allowed(self, purge_api):
        ok, _ = purge_api.can_purge(self.ALICE, [_meta("alice01"), _meta("alice01")],
                                    self.OWNER_ID)
        assert ok is True

    def test_C_MCP_PURGE_02_others_chunks_blocked(self, purge_api):
        ok, reason = purge_api.can_purge(self.ALICE, [_meta("bob01")], self.OWNER_ID)
        assert ok is False
        assert "another user" in reason.lower()

    def test_C_MCP_PURGE_03_no_existing_chunks_allowed(self, purge_api):
        # Pure add — nothing destroyed.
        assert purge_api.can_purge(self.ALICE, [], self.OWNER_ID)[0] is True
        assert purge_api.can_purge(self.ALICE, None, self.OWNER_ID)[0] is True

    def test_C_MCP_PURGE_04_admin_purges_employee(self, purge_api):
        ok, _ = purge_api.can_purge(self.ADMIN, [_meta("alice01")], self.OWNER_ID)
        assert ok is True

    def test_C_MCP_PURGE_05_admin_CANNOT_purge_owner_chunks(self, purge_api):
        ok, _ = purge_api.can_purge(self.ADMIN, [_meta("owner01")], self.OWNER_ID)
        assert ok is False

    def test_C_MCP_PURGE_06_owner_purges_anything(self, purge_api):
        ok, _ = purge_api.can_purge(self.OWNER, [_meta("alice01"), _meta("bob01")],
                                    self.OWNER_ID)
        assert ok is True

    def test_C_MCP_PURGE_07_mixed_owners_one_forbidden_blocks_all(self, purge_api):
        # Alice owns some, Bob owns one → Alice can't purge the batch.
        ok, _ = purge_api.can_purge(self.ALICE,
                                    [_meta("alice01"), _meta("bob01")], self.OWNER_ID)
        assert ok is False

    def test_C_MCP_PURGE_08_legacy_ownerless_blocks_plain_user(self, purge_api):
        # Chunk with no indexed_by → only owner/admin may purge.
        ok, reason = purge_api.can_purge(self.ALICE, [{"filepath": "C:/x.pdf"}],
                                         self.OWNER_ID)
        assert ok is False
        assert "legacy" in reason.lower() or "no owner" in reason.lower()

    def test_C_MCP_PURGE_09_legacy_ownerless_allows_admin(self, purge_api):
        ok, _ = purge_api.can_purge(self.ADMIN, [{"filepath": "C:/x.pdf"}], self.OWNER_ID)
        assert ok is True

    def test_C_MCP_PURGE_10_legacy_ownerless_allows_owner(self, purge_api):
        ok, _ = purge_api.can_purge(self.OWNER, [{"filepath": "C:/x.pdf"}], self.OWNER_ID)
        assert ok is True

    def test_C_MCP_PURGE_11_no_actor_blocked(self, purge_api):
        ok, _ = purge_api.can_purge(None, [_meta("alice01")], self.OWNER_ID)
        assert ok is False

    def test_C_MCP_PURGE_12_chunk_owners_distinct(self, purge_api):
        owners = purge_api.owners([_meta("a"), _meta("a"), _meta("b")])
        assert owners == {"a", "b"}

    def test_C_MCP_PURGE_13_chunk_owners_ownerless_sentinel(self, purge_api):
        owners = purge_api.owners([{"filepath": "x"}, _meta("a")])
        # one real owner + the ownerless sentinel
        assert "a" in owners and len(owners) == 2

    def test_C_MCP_PURGE_14_admin_purges_own_and_employee_mix(self, purge_api):
        ok, _ = purge_api.can_purge(self.ADMIN,
                                    [_meta("admin01"), _meta("alice01")], self.OWNER_ID)
        assert ok is True


# ═════════════════════════════════════════════════════════════════════════════
# PER-KEY LICENSE CACHE — _load_license_cache_for / _save_license_cache_for
# (v7.0.0 #4: the server validates parent + N child keys, each needing
# independent cache state. Previously a single-license cache file would have
# been overwritten on every call. Tests cover the new shape, legacy migration,
# multi-key independence, and tolerance of missing/corrupt files.)
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def cache_io_api(mcp_module):
    load_fn = getattr(mcp_module, "_load_license_cache_for", None)
    save_fn = getattr(mcp_module, "_save_license_cache_for", None)
    if load_fn is None or save_fn is None:
        pytest.skip("_load/save_license_cache_for not present (pre-v7.0.0 #4).")

    class Api:
        load = staticmethod(load_fn)
        save = staticmethod(save_fn)
        mod  = mcp_module
    return Api


@pytest.fixture
def tmp_license_cache(cache_io_api, tmp_path, monkeypatch):
    """Redirect _LICENSE_CACHE_PATH to a per-test temp file. Returns the path."""
    p = tmp_path / "license_cache.json"
    monkeypatch.setattr(cache_io_api.mod, "_LICENSE_CACHE_PATH", p)
    return p


class TestPerKeyLicenseCache:
    PARENT = "AP-PRNT-0000-0001"
    CHILD1 = "AP-CHLD-0000-0002"
    CHILD2 = "AP-CHLD-0000-0003"

    def test_C_MCP_CACHE_01_missing_file_returns_empty(self, cache_io_api, tmp_license_cache):
        # No file on disk yet → empty dict, no exception.
        assert tmp_license_cache.exists() is False
        assert cache_io_api.load(self.PARENT) == {}

    def test_C_MCP_CACHE_02_save_then_load_roundtrip(self, cache_io_api, tmp_license_cache):
        entry = {"last_validated_at": "2026-05-28T00:00:00+00:00",
                 "status": "active", "cached_expires_at": "2027-01-01",
                 "edition": "business"}
        cache_io_api.save(self.PARENT, entry)
        got = cache_io_api.load(self.PARENT)
        assert got == entry

    def test_C_MCP_CACHE_03_two_keys_are_independent(self, cache_io_api, tmp_license_cache):
        # The whole point of #4: parent and child caches don't clobber each other.
        e1 = {"last_validated_at": "2026-05-01T00:00:00+00:00", "status": "active"}
        e2 = {"last_validated_at": "2026-05-20T00:00:00+00:00", "status": "active"}
        cache_io_api.save(self.PARENT, e1)
        cache_io_api.save(self.CHILD1, e2)
        assert cache_io_api.load(self.PARENT) == e1
        assert cache_io_api.load(self.CHILD1) == e2

    def test_C_MCP_CACHE_04_unknown_key_returns_empty(self, cache_io_api, tmp_license_cache):
        cache_io_api.save(self.PARENT, {"last_validated_at": "2026-05-28T00:00:00+00:00"})
        assert cache_io_api.load(self.CHILD2) == {}

    def test_C_MCP_CACHE_05_legacy_shape_load_returns_as_first_key(self, cache_io_api,
                                                                    tmp_license_cache):
        # v6.x cache layout (top-level fields, single license) — load returns
        # them unconditionally so the first key asked about gets the old data.
        legacy = {"last_validated_at": "2026-05-01T00:00:00+00:00",
                  "status": "active", "cached_expires_at": "2027-01-01",
                  "edition": "business"}
        tmp_license_cache.write_text(json.dumps(legacy), encoding="utf-8")
        got = cache_io_api.load(self.PARENT)
        assert got == legacy

    def test_C_MCP_CACHE_06_save_migrates_legacy_to_new_shape(self, cache_io_api,
                                                              tmp_license_cache):
        # After a save, the file is in the new {"licenses": {...}} shape and the
        # legacy top-level fields are gone.
        legacy = {"last_validated_at": "2026-05-01T00:00:00+00:00", "status": "active"}
        tmp_license_cache.write_text(json.dumps(legacy), encoding="utf-8")
        new_entry = {"last_validated_at": "2026-05-28T00:00:00+00:00", "status": "active"}
        cache_io_api.save(self.PARENT, new_entry)
        raw = json.loads(tmp_license_cache.read_text(encoding="utf-8"))
        assert "licenses" in raw and self.PARENT in raw["licenses"]
        # legacy top-level fields are dropped by the migration:
        assert "last_validated_at" not in raw

    def test_C_MCP_CACHE_07_corrupt_file_returns_empty_not_raises(self, cache_io_api,
                                                                   tmp_license_cache):
        tmp_license_cache.write_text("not valid json {{{", encoding="utf-8")
        # Must never raise — the caller treats {} as 'no cache, recheck'.
        assert cache_io_api.load(self.PARENT) == {}


# ═════════════════════════════════════════════════════════════════════════════
# CHILD-LICENSE STARTUP SWEEP — _sweep_child_licenses(users_doc, validate_fn)
# (v7.0.0 #4: in server mode the company server walks active users in users.json
# and validates each one's child_license_key. Soft policy: rejections produce
# warning entries but do NOT mutate users_doc and do NOT block bearer-token
# auth at request time. Tests inject the validate function so no network is
# needed — pure unit tests.)
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def sweep_api(mcp_module):
    fn = getattr(mcp_module, "_sweep_child_licenses", None)
    if fn is None:
        pytest.skip("_sweep_child_licenses not present (pre-v7.0.0 #4).")
    return fn


def _user(name="Alice", child_key="AP-CHLD-AAAA-0001",
          status="active", role="manager"):
    """Build a synthetic users.json user record."""
    return {
        "name": name, "role": role, "scopes": [],
        "status": status, "child_license_key": child_key,
        "private_collection_enabled": True,
    }


def _validate_ok(_key):
    return {"effective_edition": "business", "action": "validated",
            "banner": "", "used_network": True}


def _validate_revoked(_key):
    return {"effective_edition": "home", "action": "reverted_revoked",
            "banner": "Business license is no longer valid (revoked).",
            "used_network": True}


def _validate_grace_warning(_key):
    return {"effective_edition": "business", "action": "grace_warning",
            "banner": "License validation has failed for several days.",
            "used_network": False}


class TestChildLicenseSweep:
    def test_C_MCP_SWEEP_01_empty_users_yields_no_warnings(self, sweep_api):
        assert sweep_api({"users": {}}, _validate_ok) == []
        assert sweep_api({}, _validate_ok) == []
        assert sweep_api(None, _validate_ok) == []

    def test_C_MCP_SWEEP_02_all_valid_yields_no_warnings(self, sweep_api):
        users = {"users": {
            "tok_alice": _user("Alice", "AP-CHLD-AAAA-0001"),
            "tok_bob":   _user("Bob",   "AP-CHLD-BBBB-0002"),
        }}
        assert sweep_api(users, _validate_ok) == []

    def test_C_MCP_SWEEP_03_one_rejected_appears_in_warnings(self, sweep_api):
        users = {"users": {
            "tok_alice": _user("Alice", "AP-CHLD-AAAA-0001"),
            "tok_bob":   _user("Bob",   "AP-CHLD-BBBB-0002"),
        }}
        # Reject only Bob's key.
        def vfn(key):
            return _validate_revoked(key) if key.startswith("AP-CHLD-BBBB") else _validate_ok(key)
        warnings = sweep_api(users, vfn)
        assert len(warnings) == 1
        w = warnings[0]
        assert w["name"] == "Bob"
        # The mask must DISTINGUISH Bob's key from Alice's (the real contract —
        # not a brittle 'specific N chars visible' check). Confirm the masks
        # would differ, by re-running with Alice rejected and comparing.
        def vfn_a(key):
            return _validate_revoked(key) if key.startswith("AP-CHLD-AAAA") else _validate_ok(key)
        warnings_a = sweep_api(users, vfn_a)
        assert warnings_a[0]["child_key_masked"] != w["child_key_masked"], (
            f"mask too aggressive — sibling keys produce identical masks: "
            f"{w['child_key_masked']!r} vs {warnings_a[0]['child_key_masked']!r}")
        # And the mask should not be the empty/'None' string or the raw key.
        assert w["child_key_masked"] and w["child_key_masked"] != "AP-CHLD-BBBB-0002"
        assert w["reason"] == "reverted_revoked"
        assert w["banner"]                       # non-empty

    def test_C_MCP_SWEEP_04_grace_warning_is_recorded(self, sweep_api):
        # A user whose key is still valid but in grace — still a warning entry,
        # softer "reason".
        users = {"users": {"tok_alice": _user("Alice", "AP-CHLD-AAAA-0001")}}
        warnings = sweep_api(users, _validate_grace_warning)
        assert len(warnings) == 1
        assert warnings[0]["reason"] == "grace_warning"
        assert warnings[0]["name"] == "Alice"

    def test_C_MCP_SWEEP_05_suspended_user_is_skipped(self, sweep_api):
        # Soft policy: a suspended user already can't authenticate; don't burn
        # a network check on them, and don't warn about a key that's parked.
        users = {"users": {
            "tok_alice": _user("Alice", "AP-CHLD-AAAA-0001", status="suspended"),
        }}
        # Use validate_revoked — if the function were called, we'd see a warning.
        assert sweep_api(users, _validate_revoked) == []

    def test_C_MCP_SWEEP_06_user_without_child_key_is_skipped(self, sweep_api):
        # Phone-only-without-key OR not yet assigned — silently skipped.
        users = {"users": {
            "tok_alice": _user("Alice", ""),
            "tok_bob":   _user("Bob",   None),
        }}
        # Even with revoked validate (which would warn), no warnings because
        # the loop never reaches validate when child_key is empty.
        assert sweep_api(users, _validate_revoked) == []

    def test_C_MCP_SWEEP_07_malformed_entries_are_skipped(self, sweep_api):
        # users.json corrupted in places — sweep should be resilient.
        users = {"users": {
            "tok_alice": _user("Alice", "AP-CHLD-AAAA-0001"),
            "tok_bad":   "not a dict",
            "tok_none":  None,
        }}
        warnings = sweep_api(users, _validate_ok)
        assert warnings == []   # only Alice was checked, and she's valid

    def test_C_MCP_SWEEP_08_validate_exception_is_isolated(self, sweep_api):
        # If validate_fn raises for one user, the sweep continues with the next.
        users = {"users": {
            "tok_alice": _user("Alice", "AP-CHLD-AAAA-0001"),
            "tok_bob":   _user("Bob",   "AP-CHLD-BBBB-0002"),
        }}
        def vfn(key):
            if key.startswith("AP-CHLD-AAAA"):
                raise RuntimeError("simulated network blow-up")
            return _validate_revoked(key)
        # Bob's revocation should still surface even though Alice's call raised.
        warnings = sweep_api(users, vfn)
        assert len(warnings) == 1
        assert warnings[0]["name"] == "Bob"

    def test_C_MCP_SWEEP_09_warning_entry_has_expected_keys(self, sweep_api):
        # Shape check — callers (and the future GUI banner) depend on these.
        users = {"users": {"tok_alice": _user("Alice", "AP-CHLD-AAAA-0001")}}
        warnings = sweep_api(users, _validate_revoked)
        assert len(warnings) == 1
        w = warnings[0]
        for k in ("name", "child_key_masked", "reason", "banner"):
            assert k in w, f"warning entry missing key {k!r}"

    def test_C_MCP_SWEEP_10_does_not_mutate_input(self, sweep_api):
        # SOFT-POLICY contract: the sweep MUST NOT mutate users.json contents.
        # The Admin tab + the owner are the only writers; the sweep just reports.
        users = {"users": {
            "tok_alice": _user("Alice", "AP-CHLD-AAAA-0001"),
        }}
        import copy
        before = copy.deepcopy(users)
        sweep_api(users, _validate_revoked)
        assert users == before, "sweep mutated users_doc — soft-policy contract violated"


# ═════════════════════════════════════════════════════════════════════════════
# CADENCE CONSTANT — _LICENSE_FRESH_HOURS pinned to 30 days (v7.0.0 #4).
# A regression bug here (someone reverts to 24) would silently make every server
# hit the Worker daily instead of monthly. Pin it.
# ═════════════════════════════════════════════════════════════════════════════
class TestCadenceConstant:
    def test_C_MCP_CADENCE_01_fresh_hours_is_30_days(self, mcp_module):
        v = getattr(mcp_module, "_LICENSE_FRESH_HOURS", None)
        assert v == 720, (
            f"_LICENSE_FRESH_HOURS must be 720 (30d) per the v7.0.0 #4 design; got {v}. "
            f"If you intentionally changed the cadence, update this test AND learning 3dce04e8."
        )


# ═════════════════════════════════════════════════════════════════════════════
# LICENSE-WARNINGS PERSISTENCE — _save_license_warnings (v7.0.0 GUI surface).
# The engine writes child-license warnings to ~/.ai-prowler/license_warnings.json
# so the GUI's Admin tab can read them on each refresh. The file is ALWAYS
# written (even when warnings=[]) so the GUI distinguishes "all clear as of
# last_check_at" from "the sweep has never run" (file absent).
# ═════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def warnings_io_api(mcp_module):
    fn = getattr(mcp_module, "_save_license_warnings", None)
    if fn is None:
        pytest.skip("_save_license_warnings not present (pre-v7.0.0 GUI slice).")

    class Api:
        save = staticmethod(fn)
        mod = mcp_module
    return Api


@pytest.fixture
def tmp_warnings_path(warnings_io_api, tmp_path, monkeypatch):
    """Redirect _LICENSE_WARNINGS_PATH to a per-test temp file."""
    p = tmp_path / "license_warnings.json"
    monkeypatch.setattr(warnings_io_api.mod, "_LICENSE_WARNINGS_PATH", p)
    return p


class TestLicenseWarningsPersistence:
    def test_C_MCP_WARN_01_save_empty_writes_file_with_empty_list(
            self, warnings_io_api, tmp_warnings_path):
        # Empty list MUST still write a file — the absence of the file means
        # "sweep never ran", which is a different signal than "all clear".
        warnings_io_api.save([])
        assert tmp_warnings_path.exists()
        data = json.loads(tmp_warnings_path.read_text(encoding="utf-8"))
        assert data["warnings"] == []
        assert "last_check_at" in data

    def test_C_MCP_WARN_02_save_persists_warning_entries(
            self, warnings_io_api, tmp_warnings_path):
        ws = [
            {"name": "Alice", "child_key_masked": "AP-C…AAAA-0001",
             "reason": "reverted_revoked", "banner": "Revoked."},
            {"name": "Bob",   "child_key_masked": "AP-C…BBBB-0002",
             "reason": "grace_warning",    "banner": "Expires soon."},
        ]
        warnings_io_api.save(ws)
        data = json.loads(tmp_warnings_path.read_text(encoding="utf-8"))
        assert data["warnings"] == ws

    def test_C_MCP_WARN_03_save_uses_iso_utc_timestamp(
            self, warnings_io_api, tmp_warnings_path):
        warnings_io_api.save([])
        data = json.loads(tmp_warnings_path.read_text(encoding="utf-8"))
        ts = data["last_check_at"]
        # Must parse as a tz-aware ISO datetime (UTC).
        parsed = dt.datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None, f"last_check_at must be tz-aware: {ts!r}"

    def test_C_MCP_WARN_04_save_overwrites_previous(
            self, warnings_io_api, tmp_warnings_path):
        # A later sweep with fewer issues replaces an earlier sweep's warnings.
        warnings_io_api.save([
            {"name": "Alice", "child_key_masked": "AP-C…AAAA-0001",
             "reason": "reverted_revoked", "banner": "x"}])
        warnings_io_api.save([])
        data = json.loads(tmp_warnings_path.read_text(encoding="utf-8"))
        assert data["warnings"] == []

    def test_C_MCP_WARN_05_save_never_raises_on_io_error(
            self, warnings_io_api, monkeypatch, tmp_path):
        # The save is advisory — if the disk is full or the path is locked, the
        # engine startup must NOT fail because of it. Point the path at an
        # impossible location (a path inside a file, which can never be a dir)
        # and confirm no exception escapes.
        impossible = tmp_path / "real_file"
        impossible.write_text("x", encoding="utf-8")
        bad = impossible / "child" / "license_warnings.json"
        monkeypatch.setattr(warnings_io_api.mod, "_LICENSE_WARNINGS_PATH", bad)
        # Should NOT raise.
        warnings_io_api.save([{"name": "X", "child_key_masked": "x",
                                "reason": "x", "banner": "x"}])
        # And of course the file isn't there.
        assert not bad.exists()

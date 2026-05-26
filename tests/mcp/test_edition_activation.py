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
    def test_C_MCP_LICENSE_06_grace_silent_under_7_days(self, grace_api):
        r = grace_api(self._cache(3), None, now=self.NOW)
        assert r["effective_edition"] == "business"
        assert r["action"] == "grace_silent"
        assert r["banner"] == ""

    def test_C_MCP_LICENSE_07_grace_warning_between_7_and_14(self, grace_api):
        r = grace_api(self._cache(10), None, now=self.NOW)
        assert r["effective_edition"] == "business"
        assert r["action"] == "grace_warning"
        assert r["banner"]   # non-empty warning

    def test_C_MCP_LICENSE_08_revert_after_14_days(self, grace_api):
        r = grace_api(self._cache(20), None, now=self.NOW)
        assert r["effective_edition"] == "home"
        assert r["action"] == "reverted_expired"
        assert r["banner"]

    def test_C_MCP_LICENSE_09_no_cache_no_validation_is_home(self, grace_api):
        # Never validated and can't now → cannot grant business.
        r = grace_api({}, None, now=self.NOW)
        assert r["effective_edition"] == "home"
        assert r["action"] == "reverted_expired"

    def test_C_MCP_LICENSE_10_boundary_just_under_7_days(self, grace_api):
        # 6.9 days → still silent (warning starts AT 7).
        cache = {"last_validated_at": _iso(self.NOW - dt.timedelta(days=6, hours=20))}
        r = grace_api(cache, None, now=self.NOW)
        assert r["action"] == "grace_silent"

    def test_C_MCP_LICENSE_11_boundary_just_under_14_days(self, grace_api):
        cache = {"last_validated_at": _iso(self.NOW - dt.timedelta(days=13, hours=20))}
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
                                 "scopes": ["role:sales", "role:office"],
                                 "private_collection_enabled": True,
                                 "status": "active"},
            "staff00000000000": {"name": "Sam Staff", "role": "staff",
                                 "scopes": ["role:office"],
                                 "private_collection_enabled": False,
                                 "status": "active"},
            "field00000000000": {"name": "Fred Field", "role": "field_crew",
                                 "scopes": ["role:field"],
                                 "private_collection_enabled": False,
                                 "status": "active"},
            "suspended0000000": {"name": "Sue Suspended", "role": "manager",
                                 "scopes": ["role:sales"], "status": "suspended"},
        },
    }


class TestResolveUser:
    def test_C_MCP_MU_01_valid_active_token_resolves(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        assert u is not None
        assert u["role"] == "manager"
        assert u["id"] == "mgr0000000000000"   # id folded in

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
    ALL_ROLES = ["role:sales", "role:office", "role:field", "role:owner_only"]

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
        # Owner has private enabled too.
        assert "user:owner00000000000" in cols

    def test_C_MCP_MU_13_manager_only_assigned_scopes(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        cols = mu_api.allowed(u, self.ALL_ROLES)
        assert "role:sales" in cols and "role:office" in cols
        # NOT scopes they weren't assigned, even though they exist on the server.
        assert "role:field" not in cols
        assert "role:owner_only" not in cols

    def test_C_MCP_MU_14_manager_private_collection_when_enabled(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        assert "user:mgr0000000000000" in mu_api.allowed(u, self.ALL_ROLES)

    def test_C_MCP_MU_15_field_no_private_when_disabled(self, mu_api):
        u = mu_api.resolve(_users_doc(), "field00000000000")
        cols = mu_api.allowed(u, self.ALL_ROLES)
        assert not any(c.startswith("user:") for c in cols)
        assert cols == ["shared", "role:field"]

    def test_C_MCP_MU_16_staff_scopes_only(self, mu_api):
        u = mu_api.resolve(_users_doc(), "staff00000000000")
        cols = mu_api.allowed(u, self.ALL_ROLES)
        assert cols == ["shared", "role:office"]

    def test_C_MCP_MU_17_bare_scope_names_get_role_prefix(self, mu_api):
        # Tolerate a hand-written 'sales' instead of 'role:sales'.
        doc = {"users": {"x": {"role": "manager", "scopes": ["sales"],
                               "status": "active"}}}
        u = mu_api.resolve(doc, "x")
        assert "role:sales" in mu_api.allowed(u)


class TestCanIndex:
    def test_C_MCP_MU_20_owner_can_index_anything(self, mu_api):
        u = mu_api.resolve(_users_doc(), "owner00000000000")
        for tgt in ("shared", "role:sales", "role:field", "user:someoneelse"):
            ok, _ = mu_api.can_index(u, tgt)
            assert ok, tgt

    def test_C_MCP_MU_21_manager_cannot_write_shared(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "shared")
        assert ok is False

    def test_C_MCP_MU_22_manager_can_index_assigned_scope(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "role:sales")
        assert ok is True

    def test_C_MCP_MU_23_manager_cannot_index_unassigned_scope(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "role:field")
        assert ok is False

    def test_C_MCP_MU_24_manager_own_private_ok(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "user:mgr0000000000000")
        assert ok is True

    def test_C_MCP_MU_25_manager_cannot_index_others_private(self, mu_api):
        u = mu_api.resolve(_users_doc(), "mgr0000000000000")
        ok, _ = mu_api.can_index(u, "user:someoneelse")
        assert ok is False

    def test_C_MCP_MU_26_staff_cannot_index_at_all(self, mu_api):
        u = mu_api.resolve(_users_doc(), "staff00000000000")
        for tgt in ("shared", "role:office", "user:staff00000000000"):
            ok, _ = mu_api.can_index(u, tgt)
            assert ok is False, tgt

    def test_C_MCP_MU_27_field_cannot_index_at_all(self, mu_api):
        u = mu_api.resolve(_users_doc(), "field00000000000")
        ok, _ = mu_api.can_index(u, "role:field")
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
                          "search_documents", collection="role:sales", now=self.NOW)
        assert e["user_id"] == "u1"
        assert e["tool"] == "search_documents"
        assert e["collection"] == "role:sales"
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
            "role:sales": _chroma(["r1"], ["sales hit"],  [0.1]),
            "user:bob":   _chroma(["u1"], ["bob hit"],    [0.3]),
        }
        out = merge_api(per, n_results=10)
        # Best (lowest distance) first, regardless of source collection.
        assert [h["id"] for h in out] == ["r1", "u1", "s1"]
        assert out[0]["collection"] == "role:sales"

    def test_C_MCP_MERGE_03_truncates_to_n_results(self, merge_api):
        per = {"shared": _chroma(["a", "b", "c", "d"], ["", "", "", ""],
                                 [0.1, 0.2, 0.3, 0.4])}
        out = merge_api(per, n_results=2)
        assert len(out) == 2
        assert [h["id"] for h in out] == ["a", "b"]   # best two

    def test_C_MCP_MERGE_04_provenance_tagged(self, merge_api):
        per = {
            "role:sales": _chroma(["r1"], ["x"], [0.2]),
            "user:bob":   _chroma(["u1"], ["y"], [0.1]),
        }
        out = merge_api(per, n_results=10)
        prov = {h["id"]: h["collection"] for h in out}
        assert prov == {"u1": "user:bob", "r1": "role:sales"}

    def test_C_MCP_MERGE_05_dedup_by_id(self, merge_api):
        # Same id in two collections → counted once (first seen wins).
        per = {
            "shared":     _chroma(["dup"], ["from shared"], [0.4]),
            "role:sales": _chroma(["dup"], ["from sales"],  [0.1]),
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
            "role:sales": _chroma(["r1"], ["x"], [0.2]),
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
    SALES = {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}
    PUBLIC = {"prefix": "C:/CompanyDocs/Public", "collection": "shared"}

    def test_C_MCP_RESOLVE_01_simple_prefix_match(self, resolver_api):
        m = _mapping([self.SALES, self.PUBLIC])
        assert resolver_api("C:/CompanyDocs/Sales/q3.pdf", m) == "role:sales"
        assert resolver_api("C:/CompanyDocs/Public/flyer.pdf", m) == "shared"

    def test_C_MCP_RESOLVE_02_longest_prefix_wins(self, resolver_api):
        # A nested rule must beat the broader one.
        m = _mapping([
            {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
            {"prefix": "C:/CompanyDocs/Sales/Confidential", "collection": "role:exec"},
        ])
        assert resolver_api("C:/CompanyDocs/Sales/Confidential/m.pdf", m) == "role:exec"
        assert resolver_api("C:/CompanyDocs/Sales/normal.pdf", m) == "role:sales"

    def test_C_MCP_RESOLVE_03_segment_boundary_no_false_match(self, resolver_api):
        # 'Sales' must NOT match 'SalesArchive' (the critical leak-prevention case).
        m = _mapping([self.SALES], default="shared")
        assert resolver_api("C:/CompanyDocs/SalesArchive/old.pdf", m) == "shared"
        # but the real Sales dir still matches
        assert resolver_api("C:/CompanyDocs/Sales/new.pdf", m) == "role:sales"

    def test_C_MCP_RESOLVE_04_exact_dir_match(self, resolver_api):
        m = _mapping([self.SALES])
        # The directory path itself (no trailing file) matches its rule.
        assert resolver_api("C:/CompanyDocs/Sales", m) == "role:sales"

    def test_C_MCP_RESOLVE_05_case_insensitive(self, resolver_api):
        m = _mapping([self.SALES])
        assert resolver_api("c:/companydocs/SALES/x.pdf", m) == "role:sales"

    def test_C_MCP_RESOLVE_06_backslash_agnostic(self, resolver_api):
        m = _mapping([self.SALES])
        assert resolver_api("C:\\CompanyDocs\\Sales\\x.pdf", m) == "role:sales"

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
        assert resolver_api("C:/CompanyDocs/Sales/x.pdf", m) == "role:sales"
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
        m = _mapping([{"prefix": "C:/CompanyDocs/Sales/", "collection": "role:sales"}])
        assert resolver_api("C:/CompanyDocs/Sales/x.pdf", m) == "role:sales"


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
            "tokOwner": {"role": "owner"},
            "tokMgr":   {"role": "manager"},
        }}
        assert manage_api.owner_id(users) == "tokOwner"

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
    USERA = {"id": "usera01", "role": "manager", "scopes": ["role:sales"]}
    USERS = {
        "users": {"usera01": {"role": "manager", "scopes": ["role:sales"]}},
        "collection_map": {
            "rules": [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
                      {"prefix": "C:/CompanyDocs/Public", "collection": "shared"}],
        },
    }

    def test_C_MCP_FACTORY_01_personal_mode_none_resolver(self, resolver_factory_api):
        # No user → None resolver → pipeline keeps single 'documents' behavior.
        assert resolver_factory_api.build(None, self.USERS) is None

    def test_C_MCP_FACTORY_02_company_path_rule_routes(self, resolver_factory_api):
        r = resolver_factory_api.build(self.USERA, self.USERS)
        assert r("C:/CompanyDocs/Sales/q3.pdf") == "role:sales"
        assert r("C:/CompanyDocs/Public/flyer.pdf") == "shared"

    def test_C_MCP_FACTORY_03_unmatched_falls_to_user_private(self, resolver_factory_api):
        r = resolver_factory_api.build(self.USERA, self.USERS)
        # No rule matches, no per-user default → indexer's own private collection.
        assert r("D:/Random/thing.pdf") == "user:usera01"

    def test_C_MCP_FACTORY_04_per_user_default_overrides_fallback(self, resolver_factory_api):
        user = {"id": "usera01", "role": "manager", "index_target": "role:sales"}
        r = resolver_factory_api.build(user, self.USERS)
        # Unmatched path now uses the user's index_target default, not private.
        assert r("D:/Random/thing.pdf") == "role:sales"

    def test_C_MCP_FACTORY_05_path_rule_beats_user_default(self, resolver_factory_api):
        user = {"id": "usera01", "role": "manager", "index_target": "shared"}
        r = resolver_factory_api.build(user, self.USERS)
        # A matching path rule wins over the per-user default.
        assert r("C:/CompanyDocs/Sales/x.pdf") == "role:sales"

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
        # A path rule routes to role:field, but USERA (sales manager) isn't in
        # that scope → _can_index denies → degrade to own private.
        users = {"users": {}, "collection_map": {"rules": [
            {"prefix": "C:/Co/Field", "collection": "role:field"}]}}
        r = resolver_factory_api.build(self.USERA, users)
        assert r("C:/Co/Field/route.pdf") == "user:usera01"

    def test_C_MCP_FACTORY_12_can_index_allows_own_role_rule(self, resolver_factory_api):
        # Same shape but routing to the manager's OWN assigned scope → allowed.
        users = {"users": {}, "collection_map": {"rules": [
            {"prefix": "C:/Co/Sales", "collection": "role:sales"}]}}
        r = resolver_factory_api.build(self.USERA, users)
        assert r("C:/Co/Sales/quote.pdf") == "role:sales"


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

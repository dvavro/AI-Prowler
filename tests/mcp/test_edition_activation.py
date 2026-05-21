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

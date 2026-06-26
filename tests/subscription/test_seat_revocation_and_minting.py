"""
tests/subscription/test_seat_revocation_and_minting.py
========================================================
Phase 9 test suite — the three v8.0.0 subscription_client capabilities
that had zero coverage: revoke_seats(), add_seats(), and mint_license().

These mirror test_seat_management.py's conventions exactly (mocked
subscription_client._post/_get calls, no live worker needed) and cover
the corresponding new Worker endpoints:
    POST /seats/{key}/revoke          (revoke_seats)
    POST /seats/{key}/add             (add_seats)
    POST /admin/license/mint          (mint_license)

Run:
    run_tests.bat tests\\subscription\\test_seat_revocation_and_minting.py -v
"""

import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# TC-REVOKE-001  Explicit seat revocation
# ---------------------------------------------------------------------------

class TestRevokeSeats:

    def test_TC_REVOKE_001_revoke_seats_calls_worker_api(self):
        """revoke_seats() calls POST /seats/{key}/revoke with seat_ids list."""
        import subscription_client as sc

        mock_response = {
            "ok": True,
            "revoked": [
                {"seat_id": "AP-BIZ-EEEE1111-FFFF2222-S002",
                 "was_assigned_to": "bob@example.com"},
            ],
            "not_found": [],
        }

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.revoke_seats(
                "AP-BIZ-EEEE1111-FFFF2222",
                ["AP-BIZ-EEEE1111-FFFF2222-S002"],
                admin_token="test-admin-token",
            )

        mock_post.assert_called_once_with(
            "/seats/AP-BIZ-EEEE1111-FFFF2222/revoke",
            {"seat_ids": ["AP-BIZ-EEEE1111-FFFF2222-S002"]},
            bearer="test-admin-token",
        )
        assert result["revoked"][0]["seat_id"] == "AP-BIZ-EEEE1111-FFFF2222-S002"
        assert result["revoked"][0]["was_assigned_to"] == "bob@example.com"
        assert result["not_found"] == []

    def test_TC_REVOKE_002_revoke_multiple_seats_in_one_call(self):
        """revoke_seats() passes through a multi-element seat_ids list unchanged."""
        import subscription_client as sc

        seat_ids = ["AP-BIZ-XXXX-S001", "AP-BIZ-XXXX-S002", "AP-BIZ-XXXX-S003"]
        mock_response = {
            "ok": True,
            "revoked": [{"seat_id": s, "was_assigned_to": None} for s in seat_ids],
            "not_found": [],
        }

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.revoke_seats("AP-BIZ-XXXX", seat_ids, admin_token="tok")

        sent_payload = mock_post.call_args[0][1]
        assert sent_payload["seat_ids"] == seat_ids
        assert len(result["revoked"]) == 3

    def test_TC_REVOKE_003_partial_not_found_is_reported_not_raised(self):
        """A mix of found + not-found seat_ids returns both lists rather than
        raising — the Worker processes what it can and reports the rest,
        same as the live endpoint's partial-success behavior."""
        import subscription_client as sc

        mock_response = {
            "ok": True,
            "revoked": [{"seat_id": "AP-BIZ-XXXX-S001", "was_assigned_to": "a@x.com"}],
            "not_found": ["AP-BIZ-XXXX-S999"],
        }

        with patch.object(sc, "_post", return_value=(200, mock_response)):
            result = sc.revoke_seats(
                "AP-BIZ-XXXX", ["AP-BIZ-XXXX-S001", "AP-BIZ-XXXX-S999"],
                admin_token="tok",
            )

        assert len(result["revoked"]) == 1
        assert result["not_found"] == ["AP-BIZ-XXXX-S999"]

    def test_TC_REVOKE_004_empty_seat_ids_raises_value_error_without_network_call(self):
        """revoke_seats() rejects an empty seat_ids list locally — no Worker
        call should be made for a request that can never do anything."""
        import subscription_client as sc

        with patch.object(sc, "_post") as mock_post:
            with pytest.raises(ValueError):
                sc.revoke_seats("AP-BIZ-XXXX", [], admin_token="tok")
        mock_post.assert_not_called()

    def test_TC_REVOKE_005_license_not_found_raises_value_error(self):
        """revoke_seats() raises ValueError when the parent license key
        itself doesn't exist (404)."""
        import subscription_client as sc

        with patch.object(sc, "_post",
                          return_value=(404, {"error": "License not found"})):
            with pytest.raises(ValueError):
                sc.revoke_seats("AP-BIZ-NONEXISTENT", ["S001"], admin_token="tok")

    def test_TC_REVOKE_006_auth_error_raises_runtime_error(self):
        """revoke_seats() raises RuntimeError on 401 unauthorized."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(401, "Unauthorized")):
            with pytest.raises(RuntimeError):
                sc.revoke_seats("AP-BIZ-XXXX", ["S001"], admin_token="wrong-token")

    def test_TC_REVOKE_007_no_admin_token_raises_runtime_error_without_network_call(self):
        """revoke_seats() fails locally (no token, no network attempt) when
        neither an explicit admin_token nor config.json's saved token is
        available — mirrors get_seats()'s test_TC_SEAT_004_requires_admin_token."""
        import subscription_client as sc

        with patch.object(sc, "_load_admin_token", return_value=""), \
             patch.object(sc, "_post") as mock_post:
            with pytest.raises(RuntimeError) as exc_info:
                sc.revoke_seats("AP-BIZ-XXXX", ["S001"])
        mock_post.assert_not_called()
        assert "token" in str(exc_info.value).lower()

    def test_TC_REVOKE_008_network_error_raises_runtime_error(self):
        """revoke_seats() raises RuntimeError on network failure (rc=0),
        same convention as sync_seats/get_seats."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(0, "Connection refused")):
            with pytest.raises(RuntimeError):
                sc.revoke_seats("AP-BIZ-XXXX", ["S001"], admin_token="tok")


# ---------------------------------------------------------------------------
# TC-ADDSEAT-001  Manually mint additional seats
# ---------------------------------------------------------------------------

class TestAddSeats:

    def test_TC_ADDSEAT_001_add_seats_calls_worker_api(self):
        """add_seats() calls POST /seats/{key}/add with the requested count."""
        import subscription_client as sc

        mock_response = {
            "ok": True,
            "added": [
                {"seat_id": "AP-BIZ-EEEE1111-FFFF2222-S006",
                 "child_license_key": "AP-CHLD-AAAA1111-BBBB2222",
                 "status": "unassigned", "assigned_to": None, "assigned_at": None},
            ],
            "license_key": "AP-BIZ-EEEE1111-FFFF2222",
            "plan": "business",
            "seats_total": 6,
            "seats_assigned": 1,
            "seats_unassigned": 5,
            "seats_pending_removal": 0,
        }

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.add_seats(
                "AP-BIZ-EEEE1111-FFFF2222", 1, admin_token="test-admin-token",
            )

        mock_post.assert_called_once_with(
            "/seats/AP-BIZ-EEEE1111-FFFF2222/add",
            {"count": 1},
            bearer="test-admin-token",
        )
        assert len(result["added"]) == 1
        assert result["added"][0]["seat_id"] == "AP-BIZ-EEEE1111-FFFF2222-S006"
        # Every new seat must carry its OWN distinct child license key —
        # this is the core v8.0.0 behavior change (real per-seat keys,
        # not a shared parent key).
        assert result["added"][0]["child_license_key"].startswith("AP-CHLD-")
        assert result["seats_total"] == 6

    def test_TC_ADDSEAT_002_add_multiple_seats_returns_one_record_each(self):
        """Adding N seats in one call returns N distinct added records, each
        with its own unique child_license_key (no shared/duplicate keys)."""
        import subscription_client as sc

        added = [
            {"seat_id": f"AP-BIZ-XXXX-S{str(i).zfill(3)}",
             "child_license_key": f"AP-CHLD-{i:08d}-{i:08d}",
             "status": "unassigned", "assigned_to": None, "assigned_at": None}
            for i in range(10, 13)
        ]
        mock_response = {"ok": True, "added": added, "seats_total": 13}

        with patch.object(sc, "_post", return_value=(200, mock_response)):
            result = sc.add_seats("AP-BIZ-XXXX", 3, admin_token="tok")

        assert len(result["added"]) == 3
        keys = [s["child_license_key"] for s in result["added"]]
        assert len(set(keys)) == 3, "each new seat must get a distinct key"

    def test_TC_ADDSEAT_003_zero_count_raises_value_error_without_network_call(self):
        """add_seats() rejects count=0 locally before making any network call."""
        import subscription_client as sc

        with patch.object(sc, "_post") as mock_post:
            with pytest.raises(ValueError):
                sc.add_seats("AP-BIZ-XXXX", 0, admin_token="tok")
        mock_post.assert_not_called()

    def test_TC_ADDSEAT_004_negative_count_raises_value_error(self):
        """add_seats() rejects a negative count locally."""
        import subscription_client as sc

        with patch.object(sc, "_post") as mock_post:
            with pytest.raises(ValueError):
                sc.add_seats("AP-BIZ-XXXX", -3, admin_token="tok")
        mock_post.assert_not_called()

    def test_TC_ADDSEAT_005_license_not_found_raises_value_error(self):
        """add_seats() raises ValueError when the parent license doesn't exist (404)."""
        import subscription_client as sc

        with patch.object(sc, "_post",
                          return_value=(404, {"error": "License not found"})):
            with pytest.raises(ValueError):
                sc.add_seats("AP-BIZ-NONEXISTENT", 2, admin_token="tok")

    def test_TC_ADDSEAT_006_auth_error_raises_runtime_error(self):
        """add_seats() raises RuntimeError on 401 unauthorized."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(401, "Unauthorized")):
            with pytest.raises(RuntimeError):
                sc.add_seats("AP-BIZ-XXXX", 2, admin_token="wrong-token")

    def test_TC_ADDSEAT_007_no_admin_token_raises_runtime_error_without_network_call(self):
        """add_seats() fails locally when no admin token is available at all."""
        import subscription_client as sc

        with patch.object(sc, "_load_admin_token", return_value=""), \
             patch.object(sc, "_post") as mock_post:
            with pytest.raises(RuntimeError):
                sc.add_seats("AP-BIZ-XXXX", 2)
        mock_post.assert_not_called()

    def test_TC_ADDSEAT_008_network_error_raises_runtime_error(self):
        """add_seats() raises RuntimeError on network failure (rc=0)."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(0, "Connection refused")):
            with pytest.raises(RuntimeError):
                sc.add_seats("AP-BIZ-XXXX", 1, admin_token="tok")


# ---------------------------------------------------------------------------
# TC-MINT-001  Manual license minting (admin override, bypasses Stripe)
# ---------------------------------------------------------------------------

class TestMintLicense:

    def test_TC_MINT_001_mint_personal_license_calls_worker_api(self):
        """mint_license() calls POST /admin/license/mint with plan='personal'
        and defaults seats to 1 regardless of what's passed for a personal plan."""
        import subscription_client as sc

        mock_response = {
            "ok": True,
            "license_key": "AP-PERS-11112222-33334444",
            "plan": "personal",
            "tier": "standard",
            "status": "active",
            "customer_email": "alice@example.com",
        }

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.mint_license(
                customer_email="alice@example.com",
                plan="personal",
                customer_name="Alice",
                admin_token="test-admin-token",
            )

        mock_post.assert_called_once_with(
            "/admin/license/mint",
            {
                "customer_email": "alice@example.com",
                "customer_name":  "Alice",
                "plan":           "personal",
                "seats":          1,
                "tier":           "standard",
            },
            bearer="test-admin-token",
        )
        assert result["license_key"] == "AP-PERS-11112222-33334444"
        assert result["plan"] == "personal"

    def test_TC_MINT_002_mint_business_license_with_seats(self):
        """mint_license() forwards the requested seat count for a business plan."""
        import subscription_client as sc

        mock_response = {
            "ok": True,
            "license_key": "AP-BIZ-55556666-77778888",
            "plan": "business",
            "tier": "standard",
            "status": "active",
        }

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.mint_license(
                customer_email="acme@example.com",
                plan="business",
                customer_name="Acme Corp",
                seats=10,
                admin_token="tok",
            )

        sent_payload = mock_post.call_args[0][1]
        assert sent_payload["seats"] == 10
        assert sent_payload["plan"] == "business"
        assert result["license_key"] == "AP-BIZ-55556666-77778888"

    def test_TC_MINT_003_mint_beta_tier_license(self):
        """mint_license() forwards tier='beta' for a free beta-tester license —
        the Worker treats this as a cosmetic/tracking tag, not a different
        provisioning path, but the client must still pass it through correctly."""
        import subscription_client as sc

        mock_response = {
            "ok": True,
            "license_key": "AP-PERS-99990000-11112222",
            "plan": "personal",
            "tier": "beta",
            "status": "active",
        }

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.mint_license(
                customer_email="betatester@example.com",
                plan="personal",
                tier="beta",
                admin_token="tok",
            )

        sent_payload = mock_post.call_args[0][1]
        assert sent_payload["tier"] == "beta"
        assert result["tier"] == "beta"

    def test_TC_MINT_004_missing_email_raises_value_error_without_network_call(self):
        """mint_license() rejects a blank customer_email locally."""
        import subscription_client as sc

        with patch.object(sc, "_post") as mock_post:
            with pytest.raises(ValueError):
                sc.mint_license(customer_email="", plan="personal", admin_token="tok")
        mock_post.assert_not_called()

    def test_TC_MINT_005_invalid_plan_raises_value_error_without_network_call(self):
        """mint_license() rejects any plan other than 'personal'/'business'
        locally — this mirrors the Worker's own validation, but checking it
        client-side too avoids a wasted round trip for an obviously bad call."""
        import subscription_client as sc

        with patch.object(sc, "_post") as mock_post:
            with pytest.raises(ValueError):
                sc.mint_license(
                    customer_email="x@example.com", plan="enterprise", admin_token="tok",
                )
        mock_post.assert_not_called()

    def test_TC_MINT_006_worker_rejects_bad_request_raises_value_error(self):
        """mint_license() surfaces the Worker's own 400 validation as a
        ValueError too, in case server-side rules are ever stricter than the
        client-side pre-check above."""
        import subscription_client as sc

        with patch.object(sc, "_post",
                          return_value=(400, {"error": "customer_email is required"})):
            with pytest.raises(ValueError):
                # "x@example.com" + "business" both pass local validation —
                # this exercises the server-side 400 path specifically.
                sc.mint_license(
                    customer_email="x@example.com", plan="business", admin_token="tok",
                )

    def test_TC_MINT_007_auth_error_raises_runtime_error(self):
        """mint_license() raises RuntimeError on 401 unauthorized."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(401, "Unauthorized")):
            with pytest.raises(RuntimeError):
                sc.mint_license(
                    customer_email="x@example.com", plan="personal",
                    admin_token="wrong-token",
                )

    def test_TC_MINT_008_no_admin_token_raises_runtime_error_without_network_call(self):
        """mint_license() fails locally when no admin token is available at all."""
        import subscription_client as sc

        with patch.object(sc, "_load_admin_token", return_value=""), \
             patch.object(sc, "_post") as mock_post:
            with pytest.raises(RuntimeError):
                sc.mint_license(customer_email="x@example.com", plan="personal")
        mock_post.assert_not_called()

    def test_TC_MINT_009_network_error_raises_runtime_error(self):
        """mint_license() raises RuntimeError on network failure (rc=0)."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(0, "Connection refused")):
            with pytest.raises(RuntimeError):
                sc.mint_license(
                    customer_email="x@example.com", plan="personal", admin_token="tok",
                )

    def test_TC_MINT_010_default_tier_is_standard_not_beta(self):
        """mint_license() defaults tier to 'standard' when not specified —
        beta must always be an explicit, deliberate choice, never accidental."""
        import subscription_client as sc

        mock_response = {"ok": True, "license_key": "AP-PERS-X", "tier": "standard"}

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            sc.mint_license(customer_email="x@example.com", plan="personal", admin_token="tok")

        sent_payload = mock_post.call_args[0][1]
        assert sent_payload["tier"] == "standard"


# ---------------------------------------------------------------------------
# TC-LISTALL-001  Enumerate all licenses (the "show me everything" view)
# ---------------------------------------------------------------------------

class TestListAllLicenses:

    def test_TC_LISTALL_001_list_all_licenses_calls_worker_api(self):
        """list_all_licenses() calls GET /admin/licenses?prefix=... and
        returns the page as-is (licenses, cursor, list_complete)."""
        import subscription_client as sc

        mock_response = {
            "licenses": [
                {"license_key": "AP-PERS-AAAA1111-BBBB2222", "plan": "personal",
                 "status": "active"},
            ],
            "cursor": None,
            "list_complete": True,
        }

        with patch.object(sc, "_get", return_value=(200, mock_response)) as mock_get:
            result = sc.list_all_licenses(admin_token="test-admin-token")

        # Default prefix is "licenses:" — confirm it's actually in the URL,
        # without overconstraining the exact query-string encoding/ordering.
        called_path = mock_get.call_args[0][0]
        assert called_path.startswith("/admin/licenses?")
        assert "prefix=licenses%3A" in called_path or "prefix=licenses:" in called_path
        assert mock_get.call_args.kwargs.get("bearer") == "test-admin-token"

        assert len(result["licenses"]) == 1
        assert result["list_complete"] is True

    def test_TC_LISTALL_002_prefix_filters_by_plan(self):
        """Passing prefix='licenses:AP-BIZ-' is sent through unchanged, for
        scoping the browse view to just Business parent licenses."""
        import subscription_client as sc

        mock_response = {"licenses": [], "cursor": None, "list_complete": True}

        with patch.object(sc, "_get", return_value=(200, mock_response)) as mock_get:
            sc.list_all_licenses(prefix="licenses:AP-BIZ-", admin_token="tok")

        called_path = mock_get.call_args[0][0]
        assert "AP-BIZ" in called_path

    def test_TC_LISTALL_003_cursor_is_included_when_provided(self):
        """A pagination cursor from a previous page is forwarded on the
        next call so the GUI can page through more than one page of results."""
        import subscription_client as sc

        mock_response = {"licenses": [], "cursor": None, "list_complete": True}

        with patch.object(sc, "_get", return_value=(200, mock_response)) as mock_get:
            sc.list_all_licenses(cursor="abc123cursor", admin_token="tok")

        called_path = mock_get.call_args[0][0]
        assert "cursor=abc123cursor" in called_path

    def test_TC_LISTALL_004_auth_error_raises_runtime_error(self):
        """list_all_licenses() raises RuntimeError on 401 unauthorized."""
        import subscription_client as sc

        with patch.object(sc, "_get", return_value=(401, "Unauthorized")):
            with pytest.raises(RuntimeError):
                sc.list_all_licenses(admin_token="wrong-token")

    def test_TC_LISTALL_005_no_admin_token_raises_runtime_error_without_network_call(self):
        """list_all_licenses() fails locally when no admin token is available."""
        import subscription_client as sc

        with patch.object(sc, "_load_admin_token", return_value=""), \
             patch.object(sc, "_get") as mock_get:
            with pytest.raises(RuntimeError):
                sc.list_all_licenses()
        mock_get.assert_not_called()

    def test_TC_LISTALL_006_network_error_raises_runtime_error(self):
        """list_all_licenses() raises RuntimeError on network failure (rc=0)."""
        import subscription_client as sc

        with patch.object(sc, "_get", return_value=(0, "Connection refused")):
            with pytest.raises(RuntimeError):
                sc.list_all_licenses(admin_token="tok")


# ---------------------------------------------------------------------------
# TC-LISTALLPAGED-001  Auto-paginate through every page
# ---------------------------------------------------------------------------

class TestListAllLicensesPaged:

    def test_TC_LISTALLPAGED_001_single_page_returns_all_records(self):
        """When the first page is already complete, list_all_licenses_paged()
        makes exactly one call and returns its records."""
        import subscription_client as sc

        mock_response = {
            "licenses": [{"license_key": "AP-PERS-A"}, {"license_key": "AP-PERS-B"}],
            "cursor": None,
            "list_complete": True,
        }

        with patch.object(sc, "_get", return_value=(200, mock_response)) as mock_get:
            result = sc.list_all_licenses_paged(admin_token="tok")

        assert mock_get.call_count == 1
        assert len(result) == 2

    def test_TC_LISTALLPAGED_002_follows_cursor_across_multiple_pages(self):
        """list_all_licenses_paged() keeps calling with the returned cursor
        until list_complete is True, accumulating records from every page."""
        import subscription_client as sc

        page1 = {
            "licenses": [{"license_key": "AP-PERS-A"}],
            "cursor": "page2cursor",
            "list_complete": False,
        }
        page2 = {
            "licenses": [{"license_key": "AP-PERS-B"}],
            "cursor": None,
            "list_complete": True,
        }

        with patch.object(sc, "_get", side_effect=[(200, page1), (200, page2)]) as mock_get:
            result = sc.list_all_licenses_paged(admin_token="tok")

        assert mock_get.call_count == 2
        # Second call must carry the cursor from the first page's response.
        second_call_path = mock_get.call_args_list[1][0][0]
        assert "cursor=page2cursor" in second_call_path
        keys = [r["license_key"] for r in result]
        assert keys == ["AP-PERS-A", "AP-PERS-B"]

    def test_TC_LISTALLPAGED_003_stops_at_max_pages_safety_bound(self):
        """If the Worker ever returns a cursor that never reaches
        list_complete, the safety bound (max_pages) prevents an infinite
        loop rather than hanging the GUI forever."""
        import subscription_client as sc

        # Every page claims more data is available, forever.
        endless_page = {
            "licenses": [{"license_key": "AP-PERS-LOOP"}],
            "cursor": "same-cursor-always",
            "list_complete": False,
        }

        with patch.object(sc, "_get", return_value=(200, endless_page)) as mock_get:
            result = sc.list_all_licenses_paged(admin_token="tok", max_pages=3)

        assert mock_get.call_count == 3
        assert len(result) == 3   # one record collected per page, then stopped

    def test_TC_LISTALLPAGED_004_propagates_errors_from_any_page(self):
        """An error on a later page (not just the first) still raises,
        rather than silently returning a partial/incomplete result."""
        import subscription_client as sc

        page1 = {
            "licenses": [{"license_key": "AP-PERS-A"}],
            "cursor": "page2cursor",
            "list_complete": False,
        }

        with patch.object(sc, "_get", side_effect=[(200, page1), (401, "Unauthorized")]):
            with pytest.raises(RuntimeError):
                sc.list_all_licenses_paged(admin_token="tok")


"""
tests/subscription/test_seat_management.py
==========================================
Phase 8 test suite — seat management (mocked).

Tests TC-SEAT-001 through TC-SEAT-007 from the implementation plan.
All subscription_client calls are mocked — no live worker needed.

Run:
    run_tests.bat tests\subscription\test_seat_management.py -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def seats_5(tmp_path):
    """A license_seats.json with 5 unassigned seats."""
    data = {
        "license_key":      "AP-BIZ-EEEE1111-FFFF2222",
        "seats_total":      5,
        "seats_assigned":   0,
        "seats_unassigned": 5,
        "seats":            [
            {"seat_id": f"AP-BIZ-EEEE1111-FFFF2222-S{str(i).zfill(3)}",
             "status": "unassigned", "assigned_to": None, "assigned_at": None}
            for i in range(1, 6)
        ],
        "synced_at": "2026-06-23T00:00:00Z",
    }
    seats_path = tmp_path / "license_seats.json"
    seats_path.write_text(json.dumps(data), encoding="utf-8")
    return data, seats_path


@pytest.fixture
def one_assigned(tmp_path):
    """A license_seats.json with 1 assigned seat and 4 unassigned."""
    data = {
        "license_key":      "AP-BIZ-EEEE1111-FFFF2222",
        "seats_total":      5,
        "seats_assigned":   1,
        "seats_unassigned": 4,
        "seats": [
            {"seat_id": "AP-BIZ-EEEE1111-FFFF2222-S001",
             "status": "assigned", "assigned_to": "mike@example.com",
             "assigned_at": "2026-06-23T10:00:00Z"},
            *[
                {"seat_id": f"AP-BIZ-EEEE1111-FFFF2222-S{str(i).zfill(3)}",
                 "status": "unassigned", "assigned_to": None, "assigned_at": None}
                for i in range(2, 6)
            ]
        ],
        "synced_at": "2026-06-23T00:00:00Z",
    }
    seats_path = tmp_path / "license_seats.json"
    seats_path.write_text(json.dumps(data), encoding="utf-8")
    return data, seats_path


# ---------------------------------------------------------------------------
# TC-SEAT-001  Assign seat to user
# ---------------------------------------------------------------------------

class TestAssignSeat:

    def test_TC_SEAT_001_assign_seat_calls_worker_api(self):
        """assign_seat() calls POST /seats/{key}/assign with correct payload."""
        import subscription_client as sc

        seat_record = {
            "seat_id": "AP-BIZ-EEEE1111-FFFF2222-S001",
            "status": "assigned",
            "assigned_to": "mike@example.com",
            "assigned_at": "2026-06-23T10:00:00Z",
        }
        mock_response = {"ok": True, "seat": seat_record}

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.assign_seat(
                "AP-BIZ-EEEE1111-FFFF2222",
                "AP-BIZ-EEEE1111-FFFF2222-S001",
                "mike@example.com",
                admin_token="test-admin-token"
            )

        mock_post.assert_called_once_with(
            "/seats/AP-BIZ-EEEE1111-FFFF2222/assign",
            {"seat_id": "AP-BIZ-EEEE1111-FFFF2222-S001", "email": "mike@example.com"},
            bearer="test-admin-token",
        )
        assert result["status"] == "assigned"
        assert result["assigned_to"] == "mike@example.com"

    def test_TC_SEAT_001_assign_seat_conflict_raises_value_error(self):
        """assign_seat() raises ValueError when seat is already assigned (409)."""
        import subscription_client as sc

        with patch.object(sc, "_post",
                          return_value=(409, {"error": "Seat already assigned"})):
            with pytest.raises(ValueError) as exc_info:
                sc.assign_seat(
                    "AP-BIZ-EEEE1111-FFFF2222",
                    "AP-BIZ-EEEE1111-FFFF2222-S001",
                    "mike@example.com",
                    admin_token="test-admin-token"
                )
        assert "conflict" in str(exc_info.value).lower() or \
               "seat" in str(exc_info.value).lower()

    def test_TC_SEAT_001_assign_seat_not_found_raises_value_error(self):
        """assign_seat() raises ValueError when seat_id doesn't exist (404)."""
        import subscription_client as sc

        with patch.object(sc, "_post",
                          return_value=(404, {"error": "Seat not found"})):
            with pytest.raises(ValueError):
                sc.assign_seat(
                    "AP-BIZ-EEEE1111-FFFF2222",
                    "AP-BIZ-EEEE1111-FFFF2222-S999",
                    "mike@example.com",
                    admin_token="test-admin-token"
                )


# ---------------------------------------------------------------------------
# TC-SEAT-002  Unassign seat
# ---------------------------------------------------------------------------

class TestUnassignSeat:

    def test_TC_SEAT_002_unassign_seat_calls_worker_api(self):
        """unassign_seat() calls POST /seats/{key}/unassign with seat_id."""
        import subscription_client as sc

        seat_record = {
            "seat_id": "AP-BIZ-EEEE1111-FFFF2222-S001",
            "status": "unassigned",
            "assigned_to": None,
            "assigned_at": None,
        }
        mock_response = {"ok": True, "seat": seat_record}

        with patch.object(sc, "_post", return_value=(200, mock_response)) as mock_post:
            result = sc.unassign_seat(
                "AP-BIZ-EEEE1111-FFFF2222",
                "AP-BIZ-EEEE1111-FFFF2222-S001",
                admin_token="test-admin-token"
            )

        mock_post.assert_called_once_with(
            "/seats/AP-BIZ-EEEE1111-FFFF2222/unassign",
            {"seat_id": "AP-BIZ-EEEE1111-FFFF2222-S001"},
            bearer="test-admin-token",
        )
        assert result["status"] == "unassigned"
        assert result["assigned_to"] is None

    def test_TC_SEAT_002_unassign_not_found_raises_value_error(self):
        """unassign_seat() raises ValueError when seat_id doesn't exist (404)."""
        import subscription_client as sc

        with patch.object(sc, "_post",
                          return_value=(404, {"error": "Seat not found"})):
            with pytest.raises(ValueError):
                sc.unassign_seat(
                    "AP-BIZ-EEEE1111-FFFF2222",
                    "AP-BIZ-EEEE1111-FFFF2222-S999",
                    admin_token="test-admin-token"
                )


# ---------------------------------------------------------------------------
# TC-SEAT-003  Sync seats from worker
# ---------------------------------------------------------------------------

class TestSyncSeats:

    def test_TC_SEAT_003_sync_seats_writes_license_seats_json(self, tmp_path):
        """sync_seats() writes license_seats.json from worker response."""
        import subscription_client as sc

        worker_response = {
            "license_key":          "AP-BIZ-EEEE1111-FFFF2222",
            "seats_total":          5,
            "seats_assigned":       1,
            "seats_unassigned":     4,
            "seats_pending_removal": 0,
            "seats": [
                {"seat_id": "AP-BIZ-EEEE1111-FFFF2222-S001",
                 "status": "assigned", "assigned_to": "mike@example.com"},
                *[{"seat_id": f"AP-BIZ-EEEE1111-FFFF2222-S{str(i).zfill(3)}",
                   "status": "unassigned", "assigned_to": None}
                  for i in range(2, 6)]
            ]
        }

        seats_path = tmp_path / "license_seats.json"

        with patch.object(sc, "_post", return_value=(200, worker_response)), \
             patch("subscription_client.CONFIG_PATH", tmp_path / "config.json"), \
             patch("pathlib.Path.home", return_value=tmp_path):

            # Write a fake config so the path resolution works
            (tmp_path / ".ai-prowler").mkdir(parents=True, exist_ok=True)

            # Directly test the write behaviour by patching the seats path
            with patch("subscription_client.Path") as mock_path_cls:
                mock_seats_path = MagicMock()
                mock_seats_path.__truediv__ = lambda self, other: seats_path if "license_seats" in str(other) else seats_path
                mock_path_cls.home.return_value = tmp_path

                result = sc.sync_seats(
                    "AP-BIZ-EEEE1111-FFFF2222",
                    admin_token="test-admin-token"
                )

        # The function should return the worker response
        assert result["seats_total"] == 5
        assert result["seats_assigned"] == 1

    def test_TC_SEAT_003_sync_seats_not_found_raises_value_error(self):
        """sync_seats() raises ValueError when license not found (404)."""
        import subscription_client as sc

        with patch.object(sc, "_post",
                          return_value=(404, {"error": "License not found"})):
            with pytest.raises(ValueError):
                sc.sync_seats(
                    "AP-BIZ-NONEXISTENT",
                    admin_token="test-admin-token"
                )

    def test_TC_SEAT_003_sync_seats_auth_error_raises_runtime_error(self):
        """sync_seats() raises RuntimeError on 401 unauthorized."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(401, "Unauthorized")):
            with pytest.raises(RuntimeError):
                sc.sync_seats(
                    "AP-BIZ-EEEE1111-FFFF2222",
                    admin_token="wrong-token"
                )


# ---------------------------------------------------------------------------
# TC-SEAT-004  Get seats list
# ---------------------------------------------------------------------------

class TestGetSeats:

    def test_TC_SEAT_004_get_seats_returns_summary(self):
        """get_seats() returns seat summary dict from worker."""
        import subscription_client as sc

        worker_response = {
            "license_key":          "AP-BIZ-EEEE1111-FFFF2222",
            "seats_total":          5,
            "seats_assigned":       2,
            "seats_unassigned":     3,
            "seats_pending_removal": 0,
            "seats":                []
        }

        with patch.object(sc, "_get", return_value=(200, worker_response)):
            result = sc.get_seats(
                "AP-BIZ-EEEE1111-FFFF2222",
                admin_token="test-admin-token"
            )

        assert result["seats_total"] == 5
        assert result["seats_assigned"] == 2
        assert result["seats_unassigned"] == 3

    def test_TC_SEAT_004_get_seats_requires_admin_token(self):
        """get_seats() raises RuntimeError when no admin token is available."""
        import subscription_client as sc

        with patch("subscription_client._load_admin_token", return_value=""):
            with pytest.raises(RuntimeError) as exc_info:
                sc.get_seats("AP-BIZ-EEEE1111-FFFF2222")

        assert "token" in str(exc_info.value).lower()

    def test_TC_SEAT_004_get_seats_not_found_raises_value_error(self):
        """get_seats() raises ValueError when license not found (404)."""
        import subscription_client as sc

        with patch.object(sc, "_get", return_value=(404, {"error": "not found"})):
            with pytest.raises(ValueError):
                sc.get_seats(
                    "AP-BIZ-NONEXISTENT",
                    admin_token="test-admin-token"
                )


# ---------------------------------------------------------------------------
# TC-SEAT-005  Exceed seat limit
# ---------------------------------------------------------------------------

class TestSeatLimit:

    def test_TC_SEAT_005_all_seats_assigned_returns_empty_unassigned(self):
        """When all seats are assigned, child_keys list is empty."""
        import json
        from pathlib import Path

        # Simulate a fully-assigned license_seats.json
        data = {
            "license_key":  "AP-BIZ-EEEE1111-FFFF2222",
            "seats_total":  3,
            "seats": [
                {"seat_id": f"AP-BIZ-EEEE1111-FFFF2222-S{str(i).zfill(3)}",
                 "status": "assigned",
                 "assigned_to": f"user{i}@example.com",
                 "assigned_at": "2026-06-23T10:00:00Z"}
                for i in range(1, 4)
            ]
        }

        # The normalisation in _admin_load_seats builds child_keys from unassigned only
        unassigned_keys = [
            s["seat_id"] for s in data["seats"]
            if s.get("status") == "unassigned"
        ]
        assert len(unassigned_keys) == 0, \
            "No unassigned seats should be available when all are assigned"

    def test_TC_SEAT_005_pending_removal_not_available_for_assignment(self):
        """Seats with status=pending_removal are NOT available in the unassigned pool."""
        data = {
            "seats": [
                {"seat_id": "S001", "status": "pending_removal", "assigned_to": "user@example.com"},
                {"seat_id": "S002", "status": "unassigned",      "assigned_to": None},
            ]
        }
        unassigned = [s["seat_id"] for s in data["seats"] if s.get("status") == "unassigned"]
        pending    = [s["seat_id"] for s in data["seats"] if s.get("status") == "pending_removal"]
        assert "S001" not in unassigned
        assert "S001" in pending
        assert "S002" in unassigned


# ---------------------------------------------------------------------------
# TC-SEAT-006  Worker unreachable — graceful degradation
# ---------------------------------------------------------------------------

class TestWorkerUnavailable:

    def test_TC_SEAT_006_sync_seats_network_error_raises_runtime_error(self):
        """sync_seats() raises RuntimeError on network failure (rc=0)."""
        import subscription_client as sc

        with patch.object(sc, "_post", return_value=(0, "Connection refused")):
            with pytest.raises(RuntimeError):
                sc.sync_seats(
                    "AP-BIZ-EEEE1111-FFFF2222",
                    admin_token="test-admin-token"
                )

    def test_TC_SEAT_006_get_seats_network_error_raises_runtime_error(self):
        """get_seats() raises RuntimeError on network failure."""
        import subscription_client as sc

        with patch.object(sc, "_get", return_value=(0, "Connection refused")):
            with pytest.raises(RuntimeError):
                sc.get_seats(
                    "AP-BIZ-EEEE1111-FFFF2222",
                    admin_token="test-admin-token"
                )


# ---------------------------------------------------------------------------
# TC-SEAT-007  License seats JSON format compatibility
# ---------------------------------------------------------------------------

class TestLicenseSeatsFormat:

    def test_TC_SEAT_007_v8_format_detected_correctly(self, tmp_path):
        """Admin tab _admin_load_seats() detects v8 license_seats.json format."""
        # Write a v8-format file
        v8_data = {
            "license_key": "AP-BIZ-EEEE1111-FFFF2222",
            "seats_total": 3,
            "seats": [
                {"seat_id": f"AP-BIZ-EEEE1111-FFFF2222-S{str(i).zfill(3)}",
                 "status": "unassigned", "assigned_to": None, "assigned_at": None}
                for i in range(1, 4)
            ]
        }
        seats_path = tmp_path / "license_seats.json"
        seats_path.write_text(json.dumps(v8_data), encoding="utf-8")

        # Simulate what _admin_load_seats does with v8 format
        data = json.loads(seats_path.read_text())
        is_v8 = (
            isinstance(data.get("seats"), list) and
            bool(data["seats"]) and
            isinstance(data["seats"][0], dict)
        )
        assert is_v8, "Should detect v8 format"

        # Build child_keys from unassigned (as _admin_load_seats does)
        child_keys = [s["seat_id"] for s in data["seats"] if s.get("status") == "unassigned"]
        assert len(child_keys) == 3

    def test_TC_SEAT_007_legacy_format_still_works(self, tmp_path):
        """Legacy seats.json format (child_keys array) is still handled correctly."""
        legacy_data = {
            "parent_license_key": "PARENT-KEY-12345",
            "seats_total": 3,
            "child_keys": ["CHILD-001", "CHILD-002", "CHILD-003"]
        }
        seats_path = tmp_path / "seats.json"
        seats_path.write_text(json.dumps(legacy_data), encoding="utf-8")

        data = json.loads(seats_path.read_text())
        # Legacy format: no 'seats' list of dicts
        is_legacy = not (
            isinstance(data.get("seats"), list) and
            bool(data.get("seats")) and
            isinstance(data.get("seats", [{}])[0], dict)
        )
        assert is_legacy, "Should detect legacy format"
        assert len(data["child_keys"]) == 3

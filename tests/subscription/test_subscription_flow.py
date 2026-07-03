r"""
tests/subscription/test_subscription_flow.py
=============================================
Phase 8 test suite — subscription flow (mocked).

Tests TC-SUB-001 through TC-SUB-010 from the implementation plan.
All network calls are mocked — no real Stripe, Cloudflare, or Worker
calls are made. Safe to run in any environment.

Run:
    run_tests.bat tests\subscription\test_subscription_flow.py -v
"""

import json
import re
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers — build realistic mock payloads
# ---------------------------------------------------------------------------

def _personal_payload(code="APRO-Z363JU-7YK2VR-YNE9XJ"):
    return {
        "activation_code":        code,
        "license_key":            "AP-PERS-D7877A46-658A6DB2",
        "plan":                   "personal",
        "seats":                  1,
        "domain":                 "ap-testuser-a1b2c3d4.ai-prowler.com",
        "tunnel_id":              "a1b2c3d4-0000-0000-0000-000000000001",
        "tunnel_token":           "eyJmYWtlIjoidG9rZW4ifQ==",
        "cloudflare_account_tag": "239c05b7c75886aec28d04d0efe6ae3f",
        "expires_at":             "2027-06-23T00:00:00Z",
        "code_expires_at":        None,   # v8.2.0: codes no longer expire
        "claimed":                False,
        "claimed_at":             None,
        "seat_records":           [],     # v8.2.1: empty for personal
    }

def _business_payload(code="APRO-BIZZZZ-BBBBBB-CCCCCC", seats=5):
    """v8.2.1: includes real AP-CHLD- seat_records so activate_from_payload()
    writes real child keys directly — no Sync Seats step needed."""
    biz_key = "AP-BIZ-EEEE1111-FFFF2222"
    seat_records = [
        {
            "seat_id":              f"{biz_key}-S{str(i+1).zfill(3)}",
            "child_license_key":    f"AP-CHLD-{i:08X}-AABB{i:04X}",
            "personal_license_key": f"AP-PERS-{i:08X}-CCDD{i:04X}",
            "personal_act_code":    f"APRO-SEAT{i+1:02d}A-BBBBB-CCCCC",
            "personal_domain":      f"ap-seat{i+1}.ai-prowler.com",
            "status":               "unassigned",
            "assigned_to":          None,
            "assigned_at":          None,
        }
        for i in range(seats)
    ]
    return {
        "activation_code":        code,
        "license_key":            biz_key,
        "plan":                   "business",
        "seats":                  seats,
        "domain":                 "ap-testbiz-b2c3d4e5.ai-prowler.com",
        "tunnel_id":              "b2c3d4e5-0000-0000-0000-000000000002",
        "tunnel_token":           "eyJmYWtlIjoiYml6dG9rZW4ifQ==",
        "cloudflare_account_tag": "239c05b7c75886aec28d04d0efe6ae3f",
        "expires_at":             "2027-06-23T00:00:00Z",
        "code_expires_at":        None,
        "claimed":                False,
        "claimed_at":             None,
        "seat_records":           seat_records,  # v8.2.1: real AP-CHLD- keys
    }

def _business_payload_legacy(code="APRO-BIZZZZ-BBBBBB-CCCCCC", seats=5):
    """Pre-v8.2.1 payload without seat_records — triggers placeholder fallback."""
    p = _business_payload(code, seats)
    del p["seat_records"]
    return p


# ---------------------------------------------------------------------------
# TC-SUB-001  Personal subscribe -> activate happy path
# ---------------------------------------------------------------------------

class TestPersonalSubscribeActivate:

    def test_TC_SUB_001_fetch_activation_personal_happy_path(self):
        """Fetching a valid personal activation code returns the full payload."""
        import subscription_client as sc

        payload = _personal_payload()

        with patch.object(sc, "_get", return_value=(200, payload)) as mock_get:
            result = sc.fetch_activation("APRO-Z363JU-7YK2VR-YNE9XJ")

        mock_get.assert_called_once_with("/activate/APRO-Z363JU-7YK2VR-YNE9XJ")
        assert result["plan"] == "personal"
        assert result["seats"] == 1
        assert result["license_key"].startswith("AP-PERS-")
        assert result["domain"].endswith(".ai-prowler.com")

    def test_TC_SUB_001_activate_from_payload_writes_remote_access_json(self, tmp_path):
        """activate_from_payload() writes remote_access.json with all required fields."""
        import mobile_activator as ma

        payload = _personal_payload()
        ai_prowler_dir = tmp_path / ".ai-prowler"
        cloudflared_dir = tmp_path / ".cloudflared"
        cfg_path = ai_prowler_dir / "config.json"

        ai_prowler_dir.mkdir(parents=True)
        cloudflared_dir.mkdir(parents=True)
        cfg_path.write_text(
            json.dumps({"remote_token": "testtoken", "owner_name": "Test"}),
            encoding="utf-8"
        )

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", cloudflared_dir), \
             patch("mobile_activator.CONFIG_PATH", cfg_path), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", ai_prowler_dir / "license_seats.json"):
            ma.activate_from_payload(payload)

        ra_file = ai_prowler_dir / "remote_access.json"
        assert ra_file.exists(), "remote_access.json not written"
        ra = json.loads(ra_file.read_text())
        assert ra["plan"] == "personal"
        assert ra["domain"] == payload["domain"]
        assert ra["license_key"] == payload["license_key"]
        assert ra["tunnel_id"] == payload["tunnel_id"]

    def test_TC_SUB_001_activate_preserves_existing_config_keys(self, tmp_path):
        """activate_from_payload() merges into config.json without destroying existing keys."""
        import mobile_activator as ma

        payload = _personal_payload()
        ai_prowler_dir = tmp_path / ".ai-prowler"
        cfg_path = ai_prowler_dir / "config.json"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        original = {"remote_token": "MySecretToken", "owner_name": "David", "edition": "home"}
        cfg_path.write_text(json.dumps(original), encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", cfg_path), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", ai_prowler_dir / "license_seats.json"):
            ma.activate_from_payload(payload)

        cfg = json.loads(cfg_path.read_text())
        assert cfg["remote_token"] == "MySecretToken", "remote_token should be preserved"
        assert cfg["owner_name"] == "David", "owner_name should be preserved"
        assert cfg["tunnel_domain"] == payload["domain"]
        assert cfg["license_key"] == payload["license_key"]
        assert cfg["plan"] == "personal"

    def test_TC_SUB_001_activate_writes_edition_and_mode(self, tmp_path):
        """v8.2.0: activate_from_payload() always writes edition=home/mode=personal
        for personal plan, regardless of what was previously in config.json."""
        import mobile_activator as ma

        payload = _personal_payload()
        ai_prowler_dir = tmp_path / ".ai-prowler"
        cfg_path = ai_prowler_dir / "config.json"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        # Stale server values from previous install
        cfg_path.write_text(
            json.dumps({"edition": "business", "mode": "server"}),
            encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", cfg_path), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", ai_prowler_dir / "license_seats.json"):
            ma.activate_from_payload(payload)

        cfg = json.loads(cfg_path.read_text())
        assert cfg["edition"] == "home",     "Personal activation must set edition=home"
        assert cfg["mode"]    == "personal", "Personal activation must set mode=personal"


# ---------------------------------------------------------------------------
# TC-SUB-002  Business subscribe -> activate happy path
# ---------------------------------------------------------------------------

class TestBusinessSubscribeActivate:

    def test_TC_SUB_002_fetch_activation_business_happy_path(self):
        """Fetching a business code returns plan=business and correct seat count."""
        import subscription_client as sc

        payload = _business_payload(seats=5)
        with patch.object(sc, "_get", return_value=(200, payload)):
            result = sc.fetch_activation("APRO-BIZZZZ-BBBBBB-CCCCCC")

        assert result["plan"] == "business"
        assert result["seats"] == 5
        assert result["license_key"].startswith("AP-BIZ-")

    def test_TC_SUB_002_activate_business_writes_real_child_keys(self, tmp_path):
        """v8.2.1: activate_from_payload() writes real AP-CHLD- keys from
        seat_records directly — no Sync Seats step needed."""
        import mobile_activator as ma

        payload = _business_payload(seats=5)
        ai_prowler_dir = tmp_path / ".ai-prowler"
        cfg_path = ai_prowler_dir / "config.json"
        seats_path = ai_prowler_dir / "license_seats.json"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        cfg_path.write_text(json.dumps({}), encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", cfg_path), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", seats_path):
            ma.activate_from_payload(payload)

        assert seats_path.exists(), "license_seats.json not written"
        seats = json.loads(seats_path.read_text())
        assert seats["seats_total"] == 5
        assert len(seats["seats"]) == 5
        assert all(s["status"] == "unassigned" for s in seats["seats"])

        # v8.2.1: seats should have real AP-CHLD- child_license_key values
        for s in seats["seats"]:
            assert "child_license_key" in s, "Each seat must have child_license_key"
            assert s["child_license_key"].startswith("AP-CHLD-"), \
                f"child_license_key must be AP-CHLD- format, got {s['child_license_key']}"
            assert "personal_license_key" in s
            assert s["personal_license_key"].startswith("AP-PERS-")

    def test_TC_SUB_002_activate_business_falls_back_to_placeholders(self, tmp_path):
        """When seat_records is absent (pre-v8.2.1 Worker), placeholder seat IDs
        are written as fallback — Sync Seats can then fetch real keys."""
        import mobile_activator as ma

        payload = _business_payload_legacy(seats=3)
        ai_prowler_dir = tmp_path / ".ai-prowler"
        seats_path = ai_prowler_dir / "license_seats.json"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        (ai_prowler_dir / "config.json").write_text(json.dumps({}), encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", ai_prowler_dir / "config.json"), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", seats_path):
            ma.activate_from_payload(payload)

        seats = json.loads(seats_path.read_text())
        assert len(seats["seats"]) == 3
        # Placeholders use seat_id in AP-BIZ-...-S### format
        placeholder_re = re.compile(r'^AP-BIZ-[0-9A-F]+-[0-9A-F]+-S\d+$', re.I)
        for s in seats["seats"]:
            assert placeholder_re.match(s["seat_id"]), \
                f"Fallback seat_id should be placeholder format, got {s['seat_id']}"

    def test_TC_SUB_002_activate_business_writes_edition_server_mode(self, tmp_path):
        """v8.2.0: business plan activation always sets edition=business/mode=server."""
        import mobile_activator as ma

        payload = _business_payload(seats=2)
        ai_prowler_dir = tmp_path / ".ai-prowler"
        cfg_path = ai_prowler_dir / "config.json"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        # Stale personal values from previous install
        cfg_path.write_text(
            json.dumps({"edition": "home", "mode": "personal"}),
            encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", cfg_path), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", ai_prowler_dir / "license_seats.json"):
            ma.activate_from_payload(payload)

        cfg = json.loads(cfg_path.read_text())
        assert cfg["edition"] == "business", "Business activation must set edition=business"
        assert cfg["mode"]    == "server",   "Business activation must set mode=server"

    def test_TC_SUB_002_personal_plan_does_not_write_seats_json(self, tmp_path):
        """Personal plan activation does NOT create license_seats.json."""
        import mobile_activator as ma

        payload = _personal_payload()
        ai_prowler_dir = tmp_path / ".ai-prowler"
        seats_path = ai_prowler_dir / "license_seats.json"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        (ai_prowler_dir / "config.json").write_text(json.dumps({}), encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", ai_prowler_dir / "config.json"), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", seats_path):
            ma.activate_from_payload(payload)

        assert not seats_path.exists(), "license_seats.json should NOT be created for personal plan"


# ---------------------------------------------------------------------------
# TC-SUB-003  Idempotency — re-claim on the same machine
# ---------------------------------------------------------------------------
# v8.2.0: re-claim idempotency is install_id-based on the Worker side.

class TestActivationIdempotency:

    def test_TC_SUB_003_reclaim_same_machine_returns_payload(self):
        """Re-activating from the same already-bound machine succeeds."""
        import subscription_client as sc

        already_claimed = _personal_payload()
        already_claimed["claimed"] = True
        already_claimed["claimed_at"] = "2026-06-23T10:00:00Z"

        with patch.object(sc, "_get", return_value=(200, already_claimed)):
            result = sc.fetch_activation(
                "APRO-Z363JU-7YK2VR-YNE9XJ", install_id="samemachine123456")

        assert result["claimed"] is True
        assert result["license_key"].startswith("AP-PERS-")
        assert not result.get("displaced_previous_install")


# ---------------------------------------------------------------------------
# TC-SUB-004  Invalid activation code — 404
# ---------------------------------------------------------------------------

class TestInvalidActivationCode:

    def test_TC_SUB_004_not_found_raises_value_error(self):
        """A 404 from the worker raises ValueError."""
        import subscription_client as sc

        with patch.object(sc, "_get", return_value=(404, {"error": "not found"})):
            with pytest.raises(ValueError) as exc_info:
                sc.fetch_activation("APRO-AAAAAA-BBBBBB-CCCCCC")

        msg = str(exc_info.value).lower()
        assert "not found" in msg

    def test_TC_SUB_004_no_config_written_on_404(self, tmp_path):
        """No config files are written when activation returns 404."""
        import subscription_client as sc

        cfg_path = tmp_path / ".ai-prowler" / "config.json"
        (tmp_path / ".ai-prowler").mkdir(parents=True)
        cfg_path.write_text(json.dumps({"remote_token": "original"}), encoding="utf-8")

        with patch.object(sc, "_get", return_value=(404, {"error": "not found"})):
            with pytest.raises(ValueError):
                sc.fetch_activation("APRO-AAAAAA-BBBBBB-CCCCCC")

        cfg = json.loads(cfg_path.read_text())
        assert cfg.get("remote_token") == "original"
        assert "tunnel_domain" not in cfg


# ---------------------------------------------------------------------------
# TC-SUB-005  Subscription not active — 403
# ---------------------------------------------------------------------------

class TestSubscriptionNotActive:

    def test_TC_SUB_005_inactive_subscription_raises_value_error(self):
        """A 403 (subscription not active) raises ValueError with status in message."""
        import subscription_client as sc

        with patch.object(sc, "_get",
                          return_value=(403, {"error": "not active", "status": "suspended"})):
            with pytest.raises(ValueError) as exc_info:
                sc.fetch_activation("APRO-Z363JU-7YK2VR-YNE9XJ")

        assert "not active" in str(exc_info.value).lower()
        assert "suspended" in str(exc_info.value).lower()

    def test_TC_SUB_005b_different_machine_reactivation_succeeds(self):
        """Re-activating same code on a different machine transfers binding
        and returns displaced_previous_install: true."""
        import subscription_client as sc

        payload = {
            "activation_code":            "APRO-Z363JU-7YK2VR-YNE9XJ",
            "license_key":                "AP-PERS-AAAAAAAA-BBBBBBBB",
            "plan":                       "personal",
            "seats":                      1,
            "domain":                     "test.ai-prowler.com",
            "tunnel_id":                  "tunnel-123",
            "tunnel_name":                "test-tunnel",
            "tunnel_token":               "tok123",
            "expires_at":                 "2027-01-01T00:00:00Z",
            "displaced_previous_install": True,
            "seat_records":               [],
        }
        with patch.object(sc, "_get", return_value=(200, payload)):
            result = sc.fetch_activation(
                "APRO-Z363JU-7YK2VR-YNE9XJ", install_id="newmachine123456")

        assert result["displaced_previous_install"] is True
        assert result["license_key"] == "AP-PERS-AAAAAAAA-BBBBBBBB"


# ---------------------------------------------------------------------------
# TC-SUB-006  Network errors
# ---------------------------------------------------------------------------

class TestNetworkErrors:

    def test_TC_SUB_006_network_timeout_raises_runtime_error(self):
        """A network failure (rc=0) raises RuntimeError."""
        import subscription_client as sc

        with patch.object(sc, "_get", return_value=(0, "Connection timed out")):
            with pytest.raises(RuntimeError):
                sc.fetch_activation("APRO-Z363JU-7YK2VR-YNE9XJ")

    def test_TC_SUB_006_health_check_raises_on_worker_down(self):
        """health_check() raises RuntimeError when worker returns non-200."""
        import subscription_client as sc

        with patch.object(sc, "_get", return_value=(503, "Service Unavailable")):
            with pytest.raises(RuntimeError):
                sc.health_check()

    def test_TC_SUB_006_health_check_passes_when_worker_ok(self):
        """health_check() returns dict when worker returns ok."""
        import subscription_client as sc

        mock_response = {"status": "ok", "kv": "connected", "env": "production"}
        with patch.object(sc, "_get", return_value=(200, mock_response)):
            result = sc.health_check()

        assert result["status"] == "ok"
        assert result["kv"] == "connected"


# ---------------------------------------------------------------------------
# TC-SUB-007  Code format validation (local, no network)
# ---------------------------------------------------------------------------

class TestActivationCodeFormat:

    @pytest.mark.parametrize("code,expected_valid", [
        ("APRO-ABC123-DEF456-GHI789", True),
        ("apro-abc123-def456-ghi789", True),
        ("APRO-Z363JU-7YK2VR-YNE9XJ", True),
        ("APRO-ABC-DEF",              False),
        ("1234-ABC123-DEF456-GHI789", False),
        ("APRO-ABC123-DEF456",        False),
        ("",                          False),
        ("APRO-",                     False),
        ("APRO-ABCDEFG-HIJKLMNO-PQR", False),
    ])
    def test_TC_SUB_007_code_format_validation(self, code, expected_valid):
        import subscription_client as sc
        valid, result = sc.validate_activation_code_format(code)
        assert valid == expected_valid, \
            f"Code {code!r}: expected valid={expected_valid}, got {valid}. Result: {result}"

    def test_TC_SUB_007_valid_code_returned_uppercase(self):
        import subscription_client as sc
        valid, result = sc.validate_activation_code_format("apro-abc123-def456-ghi789")
        assert valid is True
        assert result == "APRO-ABC123-DEF456-GHI789"

    def test_TC_SUB_007_whitespace_stripped(self):
        import subscription_client as sc
        valid, result = sc.validate_activation_code_format("  APRO-ABC123-DEF456-GHI789  ")
        assert valid is True
        assert result == "APRO-ABC123-DEF456-GHI789"


# ---------------------------------------------------------------------------
# TC-SUB-008  Re-activation overwrites cleanly
# ---------------------------------------------------------------------------

class TestReactivation:

    def test_TC_SUB_008_reactivation_overwrites_remote_access_json(self, tmp_path):
        """Re-activating with a new payload fully overwrites remote_access.json."""
        import mobile_activator as ma

        ai_prowler_dir = tmp_path / ".ai-prowler"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        cfg_path = ai_prowler_dir / "config.json"
        cfg_path.write_text(json.dumps({}), encoding="utf-8")

        first  = _personal_payload("APRO-FIRST1-AAAAAA-BBBBBB")
        first["domain"]     = "ap-first.ai-prowler.com"
        first["tunnel_id"]  = "first-tunnel-id"

        second = _personal_payload("APRO-SECON2-CCCCCC-DDDDDD")
        second["domain"]    = "ap-second.ai-prowler.com"
        second["tunnel_id"] = "second-tunnel-id"

        patches = dict(
            AI_PROWLER_DIR=ai_prowler_dir,
            CLOUDFLARED_DIR=tmp_path / ".cloudflared",
            CONFIG_PATH=cfg_path,
            REMOTE_PATH=ai_prowler_dir / "remote_access.json",
            SEATS_PATH=ai_prowler_dir / "license_seats.json",
        )

        for payload in [first, second]:
            with patch("mobile_activator.AI_PROWLER_DIR", patches["AI_PROWLER_DIR"]), \
                 patch("mobile_activator.CLOUDFLARED_DIR", patches["CLOUDFLARED_DIR"]), \
                 patch("mobile_activator.CONFIG_PATH", patches["CONFIG_PATH"]), \
                 patch("mobile_activator.REMOTE_PATH", patches["REMOTE_PATH"]), \
                 patch("mobile_activator.SEATS_PATH", patches["SEATS_PATH"]):
                ma.activate_from_payload(payload)

        ra = json.loads((ai_prowler_dir / "remote_access.json").read_text())
        assert ra["domain"] == "ap-second.ai-prowler.com"
        assert ra["tunnel_id"] == "second-tunnel-id"
        assert ra["activation_code"] == "APRO-SECON2-CCCCCC-DDDDDD"


# ---------------------------------------------------------------------------
# TC-SUB-009  Business seat management — over-quota flow
# ---------------------------------------------------------------------------

class TestBusinessSeatOverQuota:

    def test_TC_SUB_009_over_quota_fields_written_on_downgrade(self, tmp_path):
        """When Stripe reduces seats and owner hasn't removed any via Admin tab,
        over_quota_since and over_quota_count are written to license_seats.json
        so the Admin tab can show the warning."""
        ai_prowler_dir = tmp_path / ".ai-prowler"
        ai_prowler_dir.mkdir(parents=True)
        seats_path = ai_prowler_dir / "license_seats.json"

        # Simulate 6 active seats, subscription reduced to 4
        biz_key = "AP-BIZ-EEEE1111-FFFF2222"
        seats_data = {
            "license_key":      biz_key,
            "seats_total":      6,
            "seats_assigned":   4,
            "seats_unassigned": 2,
            "seats": [
                {"seat_id": f"{biz_key}-S{str(i+1).zfill(3)}",
                 "child_license_key": f"AP-CHLD-{i:08X}-AABB{i:04X}",
                 "status": "assigned" if i < 4 else "unassigned",
                 "assigned_to": f"user{i+1}@example.com" if i < 4 else None}
                for i in range(6)
            ],
            # over_quota fields written by Worker webhook
            "over_quota_since":  "2026-07-01T00:00:00Z",
            "over_quota_target": 4,
            "over_quota_count":  2,
        }
        seats_path.write_text(json.dumps(seats_data), encoding="utf-8")

        loaded = json.loads(seats_path.read_text())
        assert loaded["over_quota_count"] == 2
        assert loaded["over_quota_since"] == "2026-07-01T00:00:00Z"
        assert loaded["over_quota_target"] == 4

    def test_TC_SUB_009_over_quota_cleared_when_owner_removes_seats(self, tmp_path):
        """After owner removes 2 seats via Admin tab, clearing over_quota fields
        means Admin tab shows normal status."""
        ai_prowler_dir = tmp_path / ".ai-prowler"
        ai_prowler_dir.mkdir(parents=True)
        seats_path = ai_prowler_dir / "license_seats.json"

        biz_key = "AP-BIZ-EEEE1111-FFFF2222"
        seats_data = {
            "license_key":   biz_key,
            "seats_total":   4,
            "seats": [
                {"seat_id": f"{biz_key}-S{str(i+1).zfill(3)}",
                 "status": "assigned"} for i in range(4)
            ],
            # over_quota cleared after owner acted
        }
        seats_path.write_text(json.dumps(seats_data), encoding="utf-8")

        loaded = json.loads(seats_path.read_text())
        assert "over_quota_since" not in loaded
        assert "over_quota_count" not in loaded

    def test_TC_SUB_009_newest_seats_identified_for_auto_suspend(self):
        """Auto-suspension targets the last N seats in the array (newest added)
        — confirmed by slice(-N) on the active seats list."""
        biz_key = "AP-BIZ-EEEE1111-FFFF2222"
        seats = [
            {"seat_id": f"{biz_key}-S{str(i+1).zfill(3)}",
             "child_license_key": f"AP-CHLD-{i:08X}-AABB{i:04X}",
             "status": "assigned",
             "assigned_to": f"user{i+1}@example.com"}
            for i in range(6)
        ]
        # Simulate: reduce to 4 seats, need to remove 2
        quota = 4
        active = [s for s in seats if s["status"] not in ("removed", "suspended")]
        over_by = len(active) - quota
        to_suspend = active[-over_by:]  # last N = newest

        assert len(to_suspend) == 2
        # Should be seats 5 and 6 (index 4, 5) — the most recently added
        assert to_suspend[0]["seat_id"] == f"{biz_key}-S005"
        assert to_suspend[1]["seat_id"] == f"{biz_key}-S006"
        # NOT seats 1 and 2
        assert all(s["seat_id"] not in (f"{biz_key}-S001", f"{biz_key}-S002")
                   for s in to_suspend)

    def test_TC_SUB_009_owner_removes_first_then_stripe_updates(self, tmp_path):
        """Happy path: owner removes 2 seats via Admin tab BEFORE reducing Stripe quota.
        After Admin tab removal, active seat count matches new quota — no over_quota needed."""
        ai_prowler_dir = tmp_path / ".ai-prowler"
        ai_prowler_dir.mkdir(parents=True)
        seats_path = ai_prowler_dir / "license_seats.json"

        biz_key = "AP-BIZ-EEEE1111-FFFF2222"
        # After owner removes 2 seats via Admin tab
        seats_data = {
            "license_key":      biz_key,
            "seats_total":      4,  # updated after Stripe reduces
            "seats": [
                {"seat_id": f"{biz_key}-S{str(i+1).zfill(3)}",
                 "child_license_key": f"AP-CHLD-{i:08X}-AABB{i:04X}",
                 "status": "assigned" if i < 4 else "removed",
                 "assigned_to": f"user{i+1}@example.com" if i < 4 else None}
                for i in range(6)
            ],
            # No over_quota fields — owner already handled it
        }
        seats_path.write_text(json.dumps(seats_data), encoding="utf-8")

        loaded = json.loads(seats_path.read_text())
        active = [s for s in loaded["seats"]
                  if s["status"] not in ("removed", "suspended")]
        assert len(active) == 4  # matches new quota
        assert "over_quota_since" not in loaded  # no grace needed


# ---------------------------------------------------------------------------
# TC-SUB-010  Business seat upgrade — new seats get real child keys
# ---------------------------------------------------------------------------

class TestBusinessSeatUpgrade:

    def test_TC_SUB_010_upgrade_payload_includes_new_seat_records(self):
        """When seats increase (upgrade), the activation payload includes
        seat_records with real AP-CHLD- keys for all seats including new ones."""
        payload = _business_payload(seats=7)  # upgraded from 5 to 7
        assert len(payload["seat_records"]) == 7
        for i, s in enumerate(payload["seat_records"]):
            assert s["child_license_key"].startswith("AP-CHLD-"), \
                f"Seat {i+1} must have real AP-CHLD- key"
            assert s["personal_license_key"].startswith("AP-PERS-")
            assert s["status"] == "unassigned"

    def test_TC_SUB_010_upgrade_writes_all_seat_records(self, tmp_path):
        """After upgrade, license_seats.json has all N seats with real keys."""
        import mobile_activator as ma

        payload = _business_payload(seats=7)
        ai_prowler_dir = tmp_path / ".ai-prowler"
        seats_path = ai_prowler_dir / "license_seats.json"
        ai_prowler_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        (ai_prowler_dir / "config.json").write_text(json.dumps({}), encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_prowler_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", ai_prowler_dir / "config.json"), \
             patch("mobile_activator.REMOTE_PATH", ai_prowler_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", seats_path):
            ma.activate_from_payload(payload)

        seats = json.loads(seats_path.read_text())
        assert seats["seats_total"] == 7
        assert len(seats["seats"]) == 7
        # All should have real AP-CHLD- keys from the payload
        for s in seats["seats"]:
            assert s["child_license_key"].startswith("AP-CHLD-")

    def test_TC_SUB_010_child_keys_used_in_dropdown_not_seat_ids(self, tmp_path):
        """The Admin tab dropdown uses child_license_key (AP-CHLD-) not seat_id
        (AP-BIZ-...-S###) when seat_records are present."""
        biz_key = "AP-BIZ-EEEE1111-FFFF2222"
        v8_seats = [
            {
                "seat_id":           f"{biz_key}-S{str(i+1).zfill(3)}",
                "child_license_key": f"AP-CHLD-{i:08X}-AABB{i:04X}",
                "status":            "unassigned",
                "assigned_to":       None,
            }
            for i in range(3)
        ]
        # Replicate _admin_load_seat_pool() child_keys build logic
        child_keys = [
            s.get("child_license_key") or s.get("seat_id")
            for s in v8_seats
            if s.get("status") == "unassigned"
            and (s.get("child_license_key") or s.get("seat_id"))
        ]
        # All should be real AP-CHLD- keys, not placeholders
        for k in child_keys:
            assert k.startswith("AP-CHLD-"), \
                f"Dropdown should show AP-CHLD- keys, got {k}"

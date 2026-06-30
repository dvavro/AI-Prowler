"""
tests/subscription/test_subscription_flow.py
=============================================
Phase 8 test suite — subscription flow (mocked).

Tests TC-SUB-001 through TC-SUB-008 from the implementation plan.
All network calls are mocked — no real Stripe, Cloudflare, or Worker
calls are made. Safe to run in any environment.

Run:
    run_tests.bat tests\subscription\test_subscription_flow.py -v
"""

import json
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
    }

def _business_payload(code="APRO-BIZZZZ-BBBBBB-CCCCCC", seats=5):
    return {
        "activation_code":        code,
        "license_key":            "AP-BIZ-EEEE1111-FFFF2222",
        "plan":                   "business",
        "seats":                  seats,
        "domain":                 "ap-testbiz-b2c3d4e5.ai-prowler.com",
        "tunnel_id":              "b2c3d4e5-0000-0000-0000-000000000002",
        "tunnel_token":           "eyJmYWtlIjoiYml6dG9rZW4ifQ==",
        "cloudflare_account_tag": "239c05b7c75886aec28d04d0efe6ae3f",
        "expires_at":             "2027-06-23T00:00:00Z",
        "code_expires_at":        None,   # v8.2.0: codes no longer expire
        "claimed":                False,
        "claimed_at":             None,
    }


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

    def test_TC_SUB_002_activate_business_writes_license_seats_json(self, tmp_path):
        """activate_from_payload() creates license_seats.json with N unassigned seats."""
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

        assert seats_path.exists(), "license_seats.json not written for business plan"
        seats = json.loads(seats_path.read_text())
        assert seats["seats_total"] == 5
        assert len(seats["seats"]) == 5
        assert all(s["status"] == "unassigned" for s in seats["seats"])
        assert all("seat_id" in s for s in seats["seats"])

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
# v8.2.0: re-claim idempotency is no longer IP-based — it's based on
# install_id matching license.active_install_id on the Worker side. From
# the client's perspective the contract is identical: a 200 with
# claimed=True comes back whether this is a first activation or a repeat
# activation on the same already-bound machine.

class TestActivationIdempotency:

    def test_TC_SUB_003_reclaim_same_machine_returns_payload(self):
        """Re-activating from the same already-bound machine (200,
        claimed=True, no displacement) succeeds."""
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
        assert "not found" in msg or "expired" in msg

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
# v8.2.0: activation codes no longer expire and the old same-IP 409 check
# was replaced with install_id-based one-machine-at-a-time binding on the
# Worker (see provision.js handleActivate). Re-activating on a different
# machine now succeeds and automatically transfers the binding rather than
# being rejected — there is no more "already used, different machine" 409
# case. The only rejection case left is the underlying subscription not
# being active (cancelled/suspended), which the Worker reports as 403.

class TestSubscriptionNotActive:

    def test_TC_SUB_005_inactive_subscription_raises_value_error(self):
        """A 403 from the worker (subscription not active) raises ValueError
        with a clear message naming the subscription status."""
        import subscription_client as sc

        with patch.object(sc, "_get",
                          return_value=(403, {"error": "not active", "status": "suspended"})):
            with pytest.raises(ValueError) as exc_info:
                sc.fetch_activation("APRO-Z363JU-7YK2VR-YNE9XJ")

        assert "not active" in str(exc_info.value).lower()
        assert "suspended" in str(exc_info.value).lower()

    def test_TC_SUB_005b_different_machine_reactivation_succeeds(self):
        """v8.2.0: re-activating the SAME code on a different machine (a new
        install_id) is no longer rejected — the Worker transfers the binding
        and returns 200 with displaced_previous_install: true."""
        import subscription_client as sc

        payload = {
            "activation_code":  "APRO-Z363JU-7YK2VR-YNE9XJ",
            "license_key":      "AP-PERS-AAAAAAAA-BBBBBBBB",
            "plan":             "personal",
            "seats":            1,
            "domain":           "test.ai-prowler.com",
            "tunnel_id":        "tunnel-123",
            "tunnel_name":      "test-tunnel",
            "tunnel_token":     "tok123",
            "expires_at":       "2027-01-01T00:00:00Z",
            "displaced_previous_install": True,
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
        """validate_activation_code_format() correctly accepts/rejects codes."""
        import subscription_client as sc
        valid, result = sc.validate_activation_code_format(code)
        assert valid == expected_valid, \
            f"Code {code!r}: expected valid={expected_valid}, got {valid}. Result: {result}"

    def test_TC_SUB_007_valid_code_returned_uppercase(self):
        """Valid lowercase code is returned cleaned and uppercased."""
        import subscription_client as sc
        valid, result = sc.validate_activation_code_format("apro-abc123-def456-ghi789")
        assert valid is True
        assert result == "APRO-ABC123-DEF456-GHI789"

    def test_TC_SUB_007_whitespace_stripped(self):
        """Leading/trailing whitespace is stripped before validation."""
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

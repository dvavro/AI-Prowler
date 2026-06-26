"""
tests/subscription/test_mobile_activator.py
===========================================
Phase 8 test suite — mobile_activator.py unit tests.

Tests TC-ACT-001 through TC-ACT-004 from the implementation plan.
All cloudflared subprocess calls and file system paths are mocked.

Run:
    run_tests.bat tests\subscription\test_mobile_activator.py -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _personal_payload():
    return {
        "activation_code":        "APRO-Z363JU-7YK2VR-YNE9XJ",
        "license_key":            "AP-PERS-D7877A46-658A6DB2",
        "plan":                   "personal",
        "seats":                  1,
        "domain":                 "ap-testuser-a1b2c3d4.ai-prowler.com",
        "tunnel_id":              "a1b2c3d4-0000-0000-0000-000000000001",
        "tunnel_token":           "eyJmYWtlIjoidG9rZW4ifQ==",
        "cloudflare_account_tag": "239c05b7c75886aec28d04d0efe6ae3f",
        "expires_at":             "2027-06-23T00:00:00Z",
        "code_expires_at":        "2026-06-26T00:00:00Z",
        "claimed":                True,
        "claimed_at":             "2026-06-23T10:00:00Z",
        "claimed_by_ip":          "1.2.3.4",
    }

def _business_payload(seats=5):
    return {
        "activation_code":        "APRO-BIZZZZ-BBBBBB-CCCCCC",
        "license_key":            "AP-BIZ-EEEE1111-FFFF2222",
        "plan":                   "business",
        "seats":                  seats,
        "domain":                 "ap-testbiz-b2c3d4e5.ai-prowler.com",
        "tunnel_id":              "b2c3d4e5-0000-0000-0000-000000000002",
        "tunnel_token":           "eyJmYWtlIjoiYml6dG9rZW4ifQ==",
        "cloudflare_account_tag": "239c05b7c75886aec28d04d0efe6ae3f",
        "expires_at":             "2027-06-23T00:00:00Z",
        "code_expires_at":        "2026-06-26T00:00:00Z",
        "claimed":                True,
        "claimed_at":             "2026-06-23T10:00:00Z",
        "claimed_by_ip":          "1.2.3.4",
    }


def _patch_dirs(tmp_path):
    """Return a dict of patches for mobile_activator paths."""
    ai_prowler_dir = tmp_path / ".ai-prowler"
    cloudflared_dir = tmp_path / ".cloudflared"
    cfg_path = ai_prowler_dir / "config.json"
    remote_path = ai_prowler_dir / "remote_access.json"
    seats_path = ai_prowler_dir / "license_seats.json"
    token_path = ai_prowler_dir / "tunnel_token.txt"

    ai_prowler_dir.mkdir(parents=True)
    cloudflared_dir.mkdir(parents=True)
    cfg_path.write_text(json.dumps({"remote_token": "testtoken"}), encoding="utf-8")

    return {
        "mobile_activator.AI_PROWLER_DIR":  ai_prowler_dir,
        "mobile_activator.CLOUDFLARED_DIR": cloudflared_dir,
        "mobile_activator.CONFIG_PATH":     cfg_path,
        "mobile_activator.REMOTE_PATH":     remote_path,
        "mobile_activator.SEATS_PATH":      seats_path,
    }, ai_prowler_dir, cloudflared_dir, cfg_path, remote_path, seats_path


# ---------------------------------------------------------------------------
# TC-ACT-001  Config files written correctly — Personal
# ---------------------------------------------------------------------------

class TestActivateFromPayloadPersonal:

    def test_TC_ACT_001_remote_access_json_written(self, tmp_path):
        """remote_access.json is created with all required fields for personal plan."""
        import mobile_activator as ma

        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
             patch("mobile_activator.CONFIG_PATH", cfg), \
             patch("mobile_activator.REMOTE_PATH", remote), \
             patch("mobile_activator.SEATS_PATH", seats):
            ma.activate_from_payload(_personal_payload())

        assert remote.exists()
        ra = json.loads(remote.read_text())

        required = ["activation_code", "license_key", "plan", "seats",
                    "domain", "tunnel_id", "cloudflare_account_tag",
                    "expires_at", "activated_at", "worker_url"]
        for field in required:
            assert field in ra, f"Missing field in remote_access.json: {field}"

        assert ra["plan"] == "personal"
        assert ra["seats"] == 1
        assert ra["domain"] == "ap-testuser-a1b2c3d4.ai-prowler.com"

    def test_TC_ACT_001_cloudflared_creds_file_written(self, tmp_path):
        """Cloudflare credentials JSON is written to ~/.cloudflared/{tunnel_id}.json."""
        import mobile_activator as ma

        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
             patch("mobile_activator.CONFIG_PATH", cfg), \
             patch("mobile_activator.REMOTE_PATH", remote), \
             patch("mobile_activator.SEATS_PATH", seats):
            ma.activate_from_payload(_personal_payload())

        cred_file = cf_dir / "a1b2c3d4-0000-0000-0000-000000000001.json"
        assert cred_file.exists(), "Tunnel credentials file not written"
        cred = json.loads(cred_file.read_text())
        assert "TunnelID" in cred
        assert cred["TunnelID"] == "a1b2c3d4-0000-0000-0000-000000000001"

    def test_TC_ACT_001_config_json_updated_with_tunnel_fields(self, tmp_path):
        """config.json is updated with tunnel_domain, tunnel_token, license_key."""
        import mobile_activator as ma

        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
             patch("mobile_activator.CONFIG_PATH", cfg), \
             patch("mobile_activator.REMOTE_PATH", remote), \
             patch("mobile_activator.SEATS_PATH", seats):
            ma.activate_from_payload(_personal_payload())

        updated = json.loads(cfg.read_text())
        assert updated["tunnel_domain"] == "ap-testuser-a1b2c3d4.ai-prowler.com"
        assert updated["tunnel_token"] == "eyJmYWtlIjoidG9rZW4ifQ=="
        assert updated["license_key"] == "AP-PERS-D7877A46-658A6DB2"
        assert updated["plan"] == "personal"
        # Original keys preserved
        assert updated["remote_token"] == "testtoken"


# ---------------------------------------------------------------------------
# TC-ACT-002  Config files written correctly — Business
# ---------------------------------------------------------------------------

class TestActivateFromPayloadBusiness:

    def test_TC_ACT_002_license_seats_json_created_for_business(self, tmp_path):
        """Business activation creates license_seats.json with N unassigned seats."""
        import mobile_activator as ma

        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
             patch("mobile_activator.CONFIG_PATH", cfg), \
             patch("mobile_activator.REMOTE_PATH", remote), \
             patch("mobile_activator.SEATS_PATH", seats):
            ma.activate_from_payload(_business_payload(seats=5))

        assert seats.exists()
        data = json.loads(seats.read_text())
        assert data["seats_total"] == 5
        assert data["seats_assigned"] == 0
        assert data["seats_unassigned"] == 5
        assert len(data["seats"]) == 5
        for s in data["seats"]:
            assert s["status"] == "unassigned"
            assert s["assigned_to"] is None

    def test_TC_ACT_002_config_json_shows_business_plan(self, tmp_path):
        """config.json shows plan=business, seats=5 after business activation."""
        import mobile_activator as ma

        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
             patch("mobile_activator.CONFIG_PATH", cfg), \
             patch("mobile_activator.REMOTE_PATH", remote), \
             patch("mobile_activator.SEATS_PATH", seats):
            ma.activate_from_payload(_business_payload(seats=5))

        updated = json.loads(cfg.read_text())
        assert updated["plan"] == "business"
        assert updated["seats"] == 5
        assert updated["license_key"] == "AP-BIZ-EEEE1111-FFFF2222"


# ---------------------------------------------------------------------------
# TC-ACT-003  Re-activation overwrites cleanly
# ---------------------------------------------------------------------------

class TestReactivationClean:

    def test_TC_ACT_003_second_activation_overwrites_remote_access_json(self, tmp_path):
        """Re-activating completely replaces remote_access.json with new data."""
        import mobile_activator as ma

        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        first = _personal_payload()
        first["domain"]    = "ap-first.ai-prowler.com"
        first["tunnel_id"] = "first-tunnel-id"
        first["activation_code"] = "APRO-FIRST1-AAAAAA-BBBBBB"

        second = _personal_payload()
        second["domain"]    = "ap-second.ai-prowler.com"
        second["tunnel_id"] = "second-tunnel-id"
        second["activation_code"] = "APRO-SECON2-CCCCCC-DDDDDD"

        for payload in [first, second]:
            with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
                 patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
                 patch("mobile_activator.CONFIG_PATH", cfg), \
                 patch("mobile_activator.REMOTE_PATH", remote), \
                 patch("mobile_activator.SEATS_PATH", seats):
                ma.activate_from_payload(payload)

        ra = json.loads(remote.read_text())
        assert ra["domain"] == "ap-second.ai-prowler.com"
        assert ra["tunnel_id"] == "second-tunnel-id"
        assert ra["activation_code"] == "APRO-SECON2-CCCCCC-DDDDDD"

    def test_TC_ACT_003_second_activation_updates_config_json(self, tmp_path):
        """Re-activating updates config.json tunnel fields without duplicate keys."""
        import mobile_activator as ma

        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        first  = _personal_payload()
        first["domain"] = "ap-first.ai-prowler.com"
        second = _personal_payload()
        second["domain"] = "ap-second.ai-prowler.com"

        for payload in [first, second]:
            with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
                 patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
                 patch("mobile_activator.CONFIG_PATH", cfg), \
                 patch("mobile_activator.REMOTE_PATH", remote), \
                 patch("mobile_activator.SEATS_PATH", seats):
                ma.activate_from_payload(payload)

        updated = json.loads(cfg.read_text())
        assert updated["tunnel_domain"] == "ap-second.ai-prowler.com"
        # Only one tunnel_domain key (no duplicate)
        raw_text = cfg.read_text()
        assert raw_text.count('"tunnel_domain"') == 1


# ---------------------------------------------------------------------------
# TC-ACT-004  activate_from_code — full flow with mocked worker + service
# ---------------------------------------------------------------------------

class TestActivateFromCode:

    def test_TC_ACT_004_activate_from_code_happy_path(self, tmp_path):
        """activate_from_code() returns success dict with domain, plan, license_key."""
        import mobile_activator as ma
        import subscription_client as sc

        payload = _personal_payload()
        patches, ai_dir, cf_dir, cfg, remote, seats = _patch_dirs(tmp_path)

        with patch.object(sc, "fetch_activation", return_value=payload), \
             patch.object(sc, "validate_activation_code_format",
                          return_value=(True, "APRO-Z363JU-7YK2VR-YNE9XJ")), \
             patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", cf_dir), \
             patch("mobile_activator.CONFIG_PATH", cfg), \
             patch("mobile_activator.REMOTE_PATH", remote), \
             patch("mobile_activator.SEATS_PATH", seats), \
             patch("mobile_activator._install_cloudflared_service", return_value=None):

            result = ma.activate_from_code("APRO-Z363JU-7YK2VR-YNE9XJ")

        assert result["ok"] is True
        assert result["plan"] == "personal"
        assert result["domain"] == payload["domain"]
        assert result["license_key"] == payload["license_key"]
        assert "message" in result

    def test_TC_ACT_004_bad_format_raises_value_error(self, tmp_path):
        """activate_from_code() raises ValueError immediately on bad code format."""
        import mobile_activator as ma
        import subscription_client as sc

        with patch.object(sc, "validate_activation_code_format",
                          return_value=(False, "Code format invalid")):
            with pytest.raises(ValueError) as exc_info:
                ma.activate_from_code("NOTACODE")

        assert "format" in str(exc_info.value).lower() or \
               "invalid" in str(exc_info.value).lower()

    def test_TC_ACT_004_worker_404_raises_value_error(self, tmp_path):
        """activate_from_code() propagates ValueError from fetch_activation on 404."""
        import mobile_activator as ma
        import subscription_client as sc

        with patch.object(sc, "validate_activation_code_format",
                          return_value=(True, "APRO-Z363JU-7YK2VR-YNE9XJ")), \
             patch.object(sc, "fetch_activation",
                          side_effect=ValueError("Activation code not found or expired")):
            with pytest.raises(ValueError) as exc_info:
                ma.activate_from_code("APRO-Z363JU-7YK2VR-YNE9XJ")

        assert "not found" in str(exc_info.value).lower() or \
               "expired" in str(exc_info.value).lower()

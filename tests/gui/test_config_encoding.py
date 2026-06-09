"""
tests/gui/test_config_encoding.py

Tests that config.json is correctly read and written with utf-8-sig encoding,
and that a BOM-encoded config.json is never silently wiped when saving tokens
or license keys.

Run with:
    pytest tests/gui/test_config_encoding.py -v
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ── Helpers ───────────────────────────────────────────────────────────────────

def write_cfg(path: Path, data: dict, encoding: str = "utf-8-sig") -> None:
    """Write a config dict to path with the given encoding."""
    path.write_text(json.dumps(data, indent=2), encoding=encoding)


def read_cfg(path: Path) -> dict:
    """Read config with utf-8-sig (handles BOM or plain UTF-8)."""
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _merge_key(cfg_path: Path, key: str, value) -> None:
    """Simulate what _save_remote_token / _save_license_key do:
    read existing config, add/update one key, write back.
    This mirrors the FIXED version (utf-8-sig reads)."""
    import json as _j
    data = {}
    if cfg_path.exists():
        try:
            data = _j.loads(cfg_path.read_text(encoding="utf-8-sig"))
        except Exception:
            pass
    data[key] = value
    cfg_path.write_text(_j.dumps(data, indent=2), encoding="utf-8-sig")


def _merge_key_buggy(cfg_path: Path, key: str, value) -> None:
    """Simulate the OLD buggy version (utf-8 read)."""
    import json as _j
    data = {}
    if cfg_path.exists():
        try:
            data = _j.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            pass   # BOM causes parse failure → data stays {}
    data[key] = value
    cfg_path.write_text(_j.dumps(data, indent=2), encoding="utf-8")


# ── Tests: encoding round-trip ─────────────────────────────────────────────────

class TestConfigEncodingRoundTrip:

    def test_utf8sig_write_and_read_back(self, tmp_path):
        """Write with utf-8-sig, read back — all keys preserved."""
        cfg = tmp_path / "config.json"
        original = {"edition": "business", "mode": "server",
                    "telemetry_enabled": True, "license_key": "ABCD-1234"}
        write_cfg(cfg, original, encoding="utf-8-sig")
        result = read_cfg(cfg)
        assert result == original

    def test_plain_utf8_write_readable_with_utf8sig(self, tmp_path):
        """Files written with plain utf-8 (no BOM) are also readable
        with utf-8-sig — the codec silently handles the no-BOM case."""
        cfg = tmp_path / "config.json"
        original = {"edition": "home", "mode": "personal"}
        write_cfg(cfg, original, encoding="utf-8")
        result = json.loads(cfg.read_text(encoding="utf-8-sig"))
        assert result == original

    def test_bom_present_after_utf8sig_write(self, tmp_path):
        """Confirm utf-8-sig actually writes a BOM at the start of the file."""
        cfg = tmp_path / "config.json"
        write_cfg(cfg, {"key": "val"}, encoding="utf-8-sig")
        raw = cfg.read_bytes()
        assert raw[:3] == b"\xef\xbb\xbf", "BOM should be present in utf-8-sig file"


# ── Tests: the silent-wipe bug ─────────────────────────────────────────────────

class TestSilentWipeBug:

    def test_buggy_path_wipes_existing_keys_on_bom_file(self, tmp_path):
        """Reproduce the original bug: BOM-encoded config written by our
        fixup scripts causes the old utf-8 reader to fail silently,
        leaving an empty dict that overwrites all existing keys."""
        cfg = tmp_path / "config.json"
        original = {
            "edition": "business",
            "mode": "server",
            "license_key": "ABCD-1234",
            "telemetry_enabled": True,
        }
        write_cfg(cfg, original, encoding="utf-8-sig")   # BOM file

        # Simulate the BUGGY _save_remote_token
        _merge_key_buggy(cfg, "remote_token", "MyToken123")

        result = json.loads(cfg.read_text(encoding="utf-8"))
        # BUG: edition, mode, license_key are all GONE
        assert "edition" not in result, \
            "Bug confirmed: edition was wiped (expected for this test)"
        assert result == {"remote_token": "MyToken123"}, \
            "Bug confirmed: only remote_token survived"

    def test_fixed_path_preserves_all_keys_on_bom_file(self, tmp_path):
        """The fixed version reads with utf-8-sig and correctly preserves
        all existing keys when adding remote_token."""
        cfg = tmp_path / "config.json"
        original = {
            "edition": "business",
            "mode": "server",
            "license_key": "ABCD-1234",
            "telemetry_enabled": True,
        }
        write_cfg(cfg, original, encoding="utf-8-sig")   # BOM file

        # Simulate the FIXED _save_remote_token
        _merge_key(cfg, "remote_token", "MyToken123")

        result = read_cfg(cfg)
        assert result["edition"] == "business"
        assert result["mode"] == "server"
        assert result["license_key"] == "ABCD-1234"
        assert result["telemetry_enabled"] is True
        assert result["remote_token"] == "MyToken123"

    def test_fixed_path_preserves_all_keys_on_plain_utf8_file(self, tmp_path):
        """Fixed version also handles plain utf-8 (no BOM) files correctly."""
        cfg = tmp_path / "config.json"
        original = {"edition": "home", "mode": "personal", "license_key": "XYZ"}
        write_cfg(cfg, original, encoding="utf-8")   # no BOM

        _merge_key(cfg, "remote_token", "Token456")

        result = read_cfg(cfg)
        assert result["edition"] == "home"
        assert result["license_key"] == "XYZ"
        assert result["remote_token"] == "Token456"

    def test_license_key_save_preserves_edition_mode(self, tmp_path):
        """Saving a license key must not wipe edition/mode on a BOM file."""
        cfg = tmp_path / "config.json"
        write_cfg(cfg, {
            "edition": "business", "mode": "server",
            "remote_token": "existing_token"
        }, encoding="utf-8-sig")

        _merge_key(cfg, "license_key", "NEW-KEY-5678")

        result = read_cfg(cfg)
        assert result["edition"] == "business"
        assert result["mode"] == "server"
        assert result["remote_token"] == "existing_token"
        assert result["license_key"] == "NEW-KEY-5678"


# ── Tests: installer-written config.json templates ───────────────────────────

class TestInstallerConfigTemplates:
    """Verify the config.json structures the installer will write for each
    installation type are valid and contain the required keys."""

    PERSONAL_CONFIG = {
        "edition": "home",
        "mode": "personal",
        "telemetry_enabled": True,
        "default_spreadsheet_path":
            "C:\\Users\\TestUser\\Documents\\AI-Prowler\\AI-Prowler_Job_Tracker.xlsx"
    }

    SERVER_CONFIG = {
        "edition": "business",
        "mode": "server",
        "telemetry_enabled": True,
        "default_spreadsheet_path":
            "C:\\Users\\TestUser\\Documents\\AI-Prowler\\AI-Prowler_Job_Tracker.xlsx"
    }

    def test_personal_config_has_required_keys(self):
        cfg = self.PERSONAL_CONFIG
        assert cfg["edition"] == "home"
        assert cfg["mode"] == "personal"
        assert cfg["telemetry_enabled"] is True
        assert "default_spreadsheet_path" in cfg

    def test_server_config_has_required_keys(self):
        cfg = self.SERVER_CONFIG
        assert cfg["edition"] == "business"
        assert cfg["mode"] == "server"
        assert cfg["telemetry_enabled"] is True
        assert "default_spreadsheet_path" in cfg

    def test_personal_config_has_no_sensitive_keys(self):
        """Installer template must NOT contain tokens, passwords, or keys."""
        cfg = self.PERSONAL_CONFIG
        assert "remote_token" not in cfg
        assert "license_key" not in cfg
        assert "tunnel_token" not in cfg
        assert "tunnel_domain" not in cfg

    def test_server_config_has_no_sensitive_keys(self):
        cfg = self.SERVER_CONFIG
        assert "remote_token" not in cfg
        assert "license_key" not in cfg
        assert "tunnel_token" not in cfg
        assert "tunnel_domain" not in cfg

    def test_personal_config_survives_roundtrip(self, tmp_path):
        """Config template is valid JSON and round-trips cleanly."""
        cfg_path = tmp_path / "config.json"
        write_cfg(cfg_path, self.PERSONAL_CONFIG, encoding="utf-8-sig")
        result = read_cfg(cfg_path)
        assert result == self.PERSONAL_CONFIG

    def test_server_config_survives_roundtrip(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        write_cfg(cfg_path, self.SERVER_CONFIG, encoding="utf-8-sig")
        result = read_cfg(cfg_path)
        assert result == self.SERVER_CONFIG

    def test_telemetry_reads_edition_from_config(self, tmp_path):
        """Telemetry compose payload can read edition/mode from a
        utf-8-sig config.json (matches the runtime code path)."""
        cfg_path = tmp_path / "config.json"
        write_cfg(cfg_path, {"edition": "business", "mode": "server",
                              "telemetry_enabled": True}, encoding="utf-8-sig")
        data = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
        edition = (str(data.get("edition", "home")).strip().lower()) or "home"
        mode    = (str(data.get("mode", "personal")).strip().lower()) or "personal"
        assert edition == "business"
        assert mode == "server"

    def test_telemetry_defaults_when_keys_missing(self, tmp_path):
        """If edition/mode not in config, defaults to home/personal."""
        cfg_path = tmp_path / "config.json"
        write_cfg(cfg_path, {"default_spreadsheet_path": "C:\\some\\path"},
                  encoding="utf-8-sig")
        data = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
        edition = (str(data.get("edition", "home")).strip().lower()) or "home"
        mode    = (str(data.get("mode", "personal")).strip().lower()) or "personal"
        assert edition == "home"
        assert mode == "personal"

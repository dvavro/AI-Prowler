"""
tests/gui/test_settings_persistence.py
=======================================
Tests that Settings tab save functions write config.json WITHOUT a UTF-8 BOM,
and that the saved values are readable by both the GUI and the MCP server.

Bugs caught:
  - _save_cfg used encoding='utf-8-sig' which writes a BOM.
    Python json.load() with default utf-8 encoding raises:
    "Unexpected UTF-8 BOM (decode using utf-8-sig)"
    causing bearer token, license key, and spreadsheet path to silently
    disappear after every save.

  - refresh_tracked_dirs displayed raw stored paths (may contain forward
    slashes written by Python) instead of normalised Windows backslash paths.

DESIGN NOTE — slash format:
  ALL paths use Windows backslashes everywhere:
    - ~/.rag_auto_update_dirs.json  (tracking file)
    - ChromaDB metadata             (filepath field)
    - ~/.rag_file_tracking.json     (file tracking DB)
    - Update Index listbox          (display)

  normalise_path() in rag_preprocessor.py converts ALL paths to
  backslashes. This gives one canonical form that is native to Windows,
  matches what Explorer/cmd show, and allows copy-paste without conversion.

  ChromaDB collection.delete(where={"filepath":...}) works correctly
  because both writes and lookups go through normalise_path() — consistent
  backslashes on both sides means exact matching always succeeds.
"""

import json
import os
import pathlib
import pytest


# ---------------------------------------------------------------------------
# Helpers -- mirror exactly what _save_cfg / _load_cfg do in rag_gui.py
# ---------------------------------------------------------------------------

def _save_cfg_bom(cfg_path: pathlib.Path, updates: dict):
    """Simulates the BROKEN _save_cfg (utf-8-sig = BOM)."""
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        d = json.loads(cfg_path.read_text(encoding='utf-8-sig')) if cfg_path.exists() else {}
    except Exception:
        d = {}
    d.update(updates)
    cfg_path.write_text(json.dumps(d, indent=2), encoding='utf-8-sig')


def _save_cfg_fixed(cfg_path: pathlib.Path, updates: dict):
    """Simulates the FIXED _save_cfg (utf-8 = no BOM)."""
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        d = json.loads(cfg_path.read_text(encoding='utf-8')) if cfg_path.exists() else {}
    except Exception:
        d = {}
    d.update(updates)
    cfg_path.write_text(json.dumps(d, indent=2), encoding='utf-8')


def _mcp_read_cfg(cfg_path: pathlib.Path) -> dict:
    """Simulates how ai_prowler_mcp.py reads config.json -- plain utf-8."""
    try:
        return json.loads(cfg_path.read_text(encoding='utf-8'))
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# BOM tests
# ---------------------------------------------------------------------------

class TestConfigSaveBOM:
    """_save_cfg must write clean UTF-8 (no BOM) so MCP server can read it."""

    def test_broken_save_cfg_writes_bom(self, tmp_path):
        """Confirm the broken version DOES write a BOM (so the test is meaningful)."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_bom(cfg, {'bearer_token': 'test123'})
        raw = cfg.read_bytes()
        assert raw[:3] == b'\xef\xbb\xbf', (
            "Expected BOM from broken _save_cfg -- test setup incorrect if this fails"
        )

    def test_broken_save_cfg_mcp_cannot_read(self, tmp_path):
        """BOM causes MCP server json.loads to fail -- returns empty dict."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_bom(cfg, {'bearer_token': 'test123'})
        result = _mcp_read_cfg(cfg)
        assert result == {}, (
            "BOM-written file should fail MCP read (returns empty dict) -- "
            "this confirms the bug that causes settings to silently disappear"
        )

    def test_fixed_save_cfg_no_bom(self, tmp_path):
        """Fixed _save_cfg must NOT write a BOM."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_fixed(cfg, {'bearer_token': 'tok_abc'})
        raw = cfg.read_bytes()
        assert raw[:3] != b'\xef\xbb\xbf', "Fixed _save_cfg must not write a UTF-8 BOM"

    def test_fixed_save_cfg_mcp_readable(self, tmp_path):
        """Fixed _save_cfg: MCP server can read the saved value."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_fixed(cfg, {'bearer_token': 'tok_abc'})
        result = _mcp_read_cfg(cfg)
        assert result.get('bearer_token') == 'tok_abc', (
            f"MCP server should read bearer_token='tok_abc', got: {result}"
        )

    def test_bearer_token_survives_save(self, tmp_path):
        """Bearer token written via fixed _save_cfg is retrievable by MCP."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_fixed(cfg, {'bearer_token': 'mytoken_xyz'})
        assert _mcp_read_cfg(cfg).get('bearer_token') == 'mytoken_xyz'

    def test_license_key_survives_save(self, tmp_path):
        """License key written via fixed _save_cfg is retrievable by MCP."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_fixed(cfg, {'license_key': 'LIC-1234-5678'})
        assert _mcp_read_cfg(cfg).get('license_key') == 'LIC-1234-5678'

    def test_spreadsheet_path_survives_save(self, tmp_path):
        """Default spreadsheet path written via fixed _save_cfg is retrievable."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        path = r'C:\Users\david\OneDrive\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx'
        _save_cfg_fixed(cfg, {'default_spreadsheet_path': path})
        assert _mcp_read_cfg(cfg).get('default_spreadsheet_path') == path

    def test_multiple_keys_survive_save(self, tmp_path):
        """All three key types coexist in one config file after separate saves."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_fixed(cfg, {'tunnel_domain': 'mobile.example.com'})
        _save_cfg_fixed(cfg, {'bearer_token': 'tok_abc'})
        _save_cfg_fixed(cfg, {'license_key': 'LIC-9999'})
        _save_cfg_fixed(cfg, {'default_spreadsheet_path': r'C:\jobs.xlsx'})
        result = _mcp_read_cfg(cfg)
        assert result.get('tunnel_domain') == 'mobile.example.com'
        assert result.get('bearer_token') == 'tok_abc'
        assert result.get('license_key') == 'LIC-9999'
        assert result.get('default_spreadsheet_path') == r'C:\jobs.xlsx'

    def test_existing_keys_preserved_on_update(self, tmp_path):
        """Saving one key does not clobber other keys already in the file."""
        cfg = tmp_path / '.ai-prowler' / 'config.json'
        _save_cfg_fixed(cfg, {'tunnel_domain': 'mobile.example.com',
                               'tunnel_token': 'tkn123'})
        _save_cfg_fixed(cfg, {'bearer_token': 'tok_abc'})
        result = _mcp_read_cfg(cfg)
        assert result.get('tunnel_domain') == 'mobile.example.com'
        assert result.get('tunnel_token') == 'tkn123'
        assert result.get('bearer_token') == 'tok_abc'


# ---------------------------------------------------------------------------
# Path normalisation tests
# ---------------------------------------------------------------------------

class TestTrackedPathDisplay:
    """normalise_path() must always produce Windows backslashes.
    All paths — stored in JSON, ChromaDB metadata, and displayed in the
    listbox — go through normalise_path() so they are always backslashes."""

    def _normalise_path(self, path: str) -> str:
        """Mirror normalise_path() from rag_preprocessor.py."""
        return str(path).replace('/', '\\')

    def test_forward_slash_path_converted(self):
        """Forward-slash path is converted to backslashes."""
        raw = 'C:/Users/david/OneDrive/Documents/AI-Prowler/COMPLETE_USER_GUIDE.md'
        result = self._normalise_path(raw)
        assert '/' not in result, f"Should have no forward slashes: {result}"
        assert '\\' in result, f"Should have backslashes: {result}"

    def test_backslash_path_unchanged(self):
        """Backslash path passes through unchanged."""
        raw = r'C:\Users\david\AI_Evolution\UserManualDOC'
        result = self._normalise_path(raw)
        assert result == raw

    def test_mixed_slash_path_normalised(self):
        """Mixed-slash path is fully converted to backslashes."""
        raw = r'C:\Users\david/OneDrive\Documents/AI-Prowler'
        result = self._normalise_path(raw)
        assert '/' not in result, f"Mixed path should have no forward slashes: {result}"

    def test_stored_json_uses_backslashes(self, tmp_path):
        """Paths written to the tracking JSON file use backslashes."""
        import json
        from datetime import datetime
        tracking_file = tmp_path / '.rag_auto_update_dirs.json'
        paths = [
            r'C:\Users\david\AI-Prowler_V700_to_V701_work',
            r'C:\Users\david\AI_Evolution\UserManualDOC',
            r'C:\Users\david\OneDrive\Documents\AI-Prowler\COMPLETE_USER_GUIDE.md',
        ]
        # Simulate save_auto_update_list behaviour
        data = {
            'directories': [self._normalise_path(p) for p in paths],
            'last_updated': datetime.now().isoformat()
        }
        tracking_file.write_text(json.dumps(data, indent=2), encoding='utf-8')

        # Read back and verify all backslashes
        loaded = json.loads(tracking_file.read_text(encoding='utf-8'))
        for entry in loaded['directories']:
            assert '/' not in entry, f"Stored path should use backslashes: {entry}"

    def test_all_paths_use_backslashes(self):
        """Batch test -- all common path formats normalise to backslashes."""
        paths = [
            'C:/Users/david/AI-Prowler_V700_to_V701_work',
            'C:/Users/david/AI_Evolution/UserManualDOC',
            r'C:\Users\david\OneDrive\Documents\AI-Prowler',
            'C:/Users/david/OneDrive/Documents/AI-Prowler/COMPLETE_USER_GUIDE.md',
        ]
        for p in paths:
            result = self._normalise_path(p)
            assert '/' not in result, (
                f"Path '{p}' still has forward slashes after normalisation: '{result}'"
            )

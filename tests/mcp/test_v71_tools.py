"""
tests/mcp/test_v71_tools.py
============================
Automated validation tests for AI-Prowler v7.1.0 new MCP tools:

  EMAIL TOOLS
    EM-01  configure_email — validation rejects missing fields
    EM-02  configure_email — saves config successfully
    EM-03  configure_email — rejects invalid port
    EM-04  send_email      — rejects missing config
    EM-05  send_email      — rejects missing recipient
    EM-06  send_email      — rejects missing subject
    EM-07  send_email      — rejects missing body
    EM-08  send_alert      — rejects missing config
    EM-09  send_alert      — rejects missing message
    EM-10  send_file       — rejects missing config
    EM-11  server-mode: configure_email/send_file/send_learnings_report(operator)
           are blocked for ALL roles (personal-mode-only email tools) —
           does NOT apply to send_email/send_alert, which allow all roles
           in server mode; see TestSendEmailCap in test_role_tool_matrix.py

  LEARNINGS EXPORT TOOLS
    EL-01  get_learnings_report — empty store returns info message
    EL-02  get_learnings_report — returns summary format by default
    EL-03  get_learnings_report — full format includes all fields
    EL-04  get_learnings_report — titles format lists only titles
    EL-05  get_learnings_report — category filter works
    EL-06  get_learnings_report — status filter works
    EL-07  export_learnings_file — rejects missing filepath
    EL-08  export_learnings_file — pack format creates valid JSON
    EL-09  export_learnings_file — csv format creates valid CSV
    EL-10  rebuild_learnings_index — returns OK even on empty store

  WRITE ZONE TOOLS
    WZ-01  list_writable_directories — returns formatted output
    WZ-02  list_writable_directories — empty zone shows info message
    WZ-03  grant_write_access — rejects empty directory
    WZ-04  grant_write_access — rejects directory not in read allowlist
    WZ-05  grant_write_access — adds directory to allowlist
    WZ-06  grant_write_access — idempotent (already-writable returns info)
    WZ-07  revoke_write_access — rejects empty directory
    WZ-08  revoke_write_access — removes directory from allowlist
    WZ-09  revoke_write_access — not-in-list returns info message
    WZ-10  server-mode: staff blocked from grant_write_access
    WZ-11  server-mode: field_crew blocked from grant_write_access
    WZ-12  server-mode: owner allowed unrestricted grant
    WZ-13  server-mode: manager allowed within scope
    WZ-14  server-mode: manager blocked outside scope
    WZ-14b personal mode always allowed

  REINDEX TOOLS
    RI-01  reindex_directory — rejects empty directory argument
    RI-02  reindex_directory — rejects directory not in read allowlist
    RI-03  reindex_all       — returns info when no tracked directories

All tests run against isolated in-process fixtures — no subprocess,
no real SMTP, no real ChromaDB writes beyond temp directories.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# sl_mcp_env is now defined in tests/mcp/conftest.py and is auto-discovered
# by pytest — no import needed here.


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — fake user records for server-mode tests
# ─────────────────────────────────────────────────────────────────────────────

def _make_user(role, scopes=None, email="user@test.com", uid="tok_test"):
    return {
        "id":     uid,
        "name":   f"{role}_user",
        "role":   role,
        "email":  email,
        "status": "active",
        "scopes": scopes or [],
        "private_collection_enabled": False,
        "can_manage_users": role == "owner",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Fixture: isolated email config + writable dirs in a temp directory
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def isolated_email_env(tmp_path, mcp_module, monkeypatch):
    """
    Redirect email_config.json and writable dirs JSON to a temp directory.
    Patch mcp_module._EMAIL_CONFIG_PATH and _WRITABLE_DIRS_FILE.
    """
    email_cfg_path   = tmp_path / "email_config.json"
    writable_path    = tmp_path / "rag_writable_dirs.json"

    monkeypatch.setattr(mcp_module, "_EMAIL_CONFIG_PATH", lambda: email_cfg_path)
    monkeypatch.setattr(mcp_module, "_WRITABLE_DIRS_FILE", writable_path)

    # Sample tracked directory for write-zone tests
    sample_dir = tmp_path / "sample_docs"
    sample_dir.mkdir()
    (sample_dir / "note.txt").write_text("hello", encoding="utf-8")

    monkeypatch.setattr(
        mcp_module, "load_auto_update_list",
        lambda: [str(sample_dir)]
    )

    class Env:
        pass
    e = Env()
    e.mcp            = mcp_module
    e.email_cfg_path = email_cfg_path
    e.writable_path  = writable_path
    e.sample_dir     = sample_dir
    e.tmp_path       = tmp_path
    return e


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL TOOLS
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigureEmail:

    def test_EM_01_rejects_missing_smtp_host(self, isolated_email_env):
        """EM-01: smtp_host is required."""
        out = isolated_email_env.mcp.configure_email(
            smtp_host="", smtp_port=587, username="user@gmail.com",
            password="app_pw")
        assert "❌" in out

    def test_EM_02_saves_config_successfully(self, isolated_email_env):
        """EM-02: valid args produce a config file with obfuscated password."""
        out = isolated_email_env.mcp.configure_email(
            smtp_host="smtp.gmail.com", smtp_port=587,
            username="user@gmail.com", password="s3cr3t",
            from_name="TestBot", default_to="dest@example.com")
        assert "✅" in out
        assert isolated_email_env.email_cfg_path.exists()
        raw = json.loads(isolated_email_env.email_cfg_path.read_text())
        # Password must NOT be stored in plain text
        assert "s3cr3t" not in json.dumps(raw)
        assert raw.get("smtp_host") == "smtp.gmail.com"
        assert raw.get("from_name") == "TestBot"
        # allowed_recipients no longer a field — server-mode only concept removed
        assert "allowed_recipients" not in raw

    def test_EM_03_rejects_invalid_port(self, isolated_email_env):
        """EM-03: port 0 is invalid."""
        out = isolated_email_env.mcp.configure_email(
            smtp_host="smtp.gmail.com", smtp_port=0,
            username="u@g.com", password="pw")
        assert "❌" in out

    def test_EM_04_send_email_no_config(self, isolated_email_env):
        """EM-04: send_email without configured SMTP returns error."""
        out = isolated_email_env.mcp.send_email(
            to="x@x.com", subject="hi", body="hello")
        assert "❌" in out
        assert "configure_email" in out.lower() or "not configured" in out.lower()

    def test_EM_05_send_email_no_recipient(self, isolated_email_env):
        """EM-05: send_email with no 'to' and no default_to returns error."""
        isolated_email_env.mcp.configure_email(
            smtp_host="smtp.gmail.com", smtp_port=587,
            username="u@g.com", password="pw")
        out = isolated_email_env.mcp.send_email(to="", subject="hi", body="b")
        assert "❌" in out

    @staticmethod
    def _inject_cfg(env, default_to=""):
        """Write a valid email config directly to the patched path,
        bypassing configure_email() so the test is independent of save logic."""
        import base64 as _b64
        cfg = {
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "username":  "u@g.com",
            "from_name": "Test",
            "default_to": default_to,
            "use_tls": True,
            "allowed_recipients": [],
            "_password_b64": _b64.b64encode(b"pw").decode(),
        }
        env.email_cfg_path.write_text(
            __import__("json").dumps(cfg), encoding="utf-8")

    def test_EM_06_send_email_no_subject(self, isolated_email_env):
        """EM-06: send_email with empty subject returns error."""
        self._inject_cfg(isolated_email_env)
        out = isolated_email_env.mcp.send_email(
            to="x@x.com", subject="", body="body")
        assert "❌" in out
        assert "subject" in out.lower()

    def test_EM_07_send_email_no_body(self, isolated_email_env):
        """EM-07: send_email with empty body returns error."""
        self._inject_cfg(isolated_email_env)
        out = isolated_email_env.mcp.send_email(
            to="x@x.com", subject="hi", body="   ")
        assert "❌" in out
        assert "body" in out.lower()

    def test_EM_08_send_alert_no_config(self, isolated_email_env):
        """EM-08: send_alert without configured SMTP returns error."""
        out = isolated_email_env.mcp.send_alert(message="test alert")
        assert "❌" in out

    def test_EM_09_send_alert_no_message(self, isolated_email_env):
        """EM-09: send_alert with empty message returns error."""
        self._inject_cfg(isolated_email_env, default_to="dest@test.com")
        out = isolated_email_env.mcp.send_alert(message="   ")
        assert "❌" in out
        assert "message" in out.lower()

    def test_EM_10_send_file_no_config(self, isolated_email_env):
        """EM-10: send_file without configured SMTP returns error."""
        out = isolated_email_env.mcp.send_file(
            to="x@x.com",
            filepath=str(isolated_email_env.sample_dir / "note.txt"))
        assert "❌" in out

    def test_EM_11_personal_only_email_tools_blocked_in_server_mode(self, isolated_email_env):
        """EM-11: configure_email / send_file / send_learnings_report(operator)
        are blocked for ALL roles in server mode — these use personal SMTP
        credentials and aren't appropriate for a shared company server.

        This does NOT apply to send_email or send_alert, which explicitly
        allow all roles in server mode via the separate _send_email_cap gate
        (see TestSendEmailCap in test_role_tool_matrix.py) — don't read this
        test as "email is blocked in server mode" in general.
        """
        # In server mode _current_user returns a user dict (not None).
        # _email_allowed_for_user blocks any non-None user regardless of role.
        for role in ("owner", "manager", "staff", "field_crew"):
            user = _make_user(role)
            allowed, reason = isolated_email_env.mcp._email_allowed_for_user(user)
            assert not allowed, f"Expected blocked for role '{role}'"
            assert "personal mode" in reason.lower()


# ══════════════════════════════════════════════════════════════════════════════
# LEARNINGS EXPORT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

class TestLearningsExportTools:

    def test_EL_01_export_text_empty_store(self, sl_mcp_env):
        """EL-01: empty store returns info message, not an error."""
        out = sl_mcp_env.mcp.get_learnings_report()
        assert "❌" not in out
        assert "ℹ️" in out or "no learnings" in out.lower()

    @pytest.mark.slow
    def test_EL_02_export_text_summary_format(self, sl_mcp_env, seeded_learnings):
        """EL-02: summary format contains numbered items."""
        out = sl_mcp_env.mcp.get_learnings_report(format="summary")
        assert isinstance(out, str)
        assert "1." in out
        assert "Learnings" in out

    @pytest.mark.slow
    def test_EL_03_export_text_full_format(self, sl_mcp_env, seeded_learnings):
        """EL-03: full format includes Category and Content fields."""
        out = sl_mcp_env.mcp.get_learnings_report(format="full")
        assert "Category" in out or "category" in out.lower()
        assert "Content" in out or "content" in out.lower()

    @pytest.mark.slow
    def test_EL_04_export_text_titles_format(self, sl_mcp_env, seeded_learnings):
        """EL-04: titles format is concise — no Category/Confidence lines."""
        out = sl_mcp_env.mcp.get_learnings_report(format="titles")
        assert "1." in out
        assert "Category" not in out
        assert "Confidence" not in out

    @pytest.mark.slow
    def test_EL_05_export_text_category_filter_nonexistent(
            self, sl_mcp_env, seeded_learnings):
        """EL-05: unknown category returns info message, not error."""
        out = sl_mcp_env.mcp.get_learnings_report(category="nonexistent_xyz_abc")
        assert "❌" not in out
        assert "ℹ️" in out or "no learnings" in out.lower()

    @pytest.mark.slow
    def test_EL_06_export_text_status_all_not_error(
            self, sl_mcp_env, seeded_learnings):
        """EL-06: status='all' returns a valid non-error response."""
        out_all = sl_mcp_env.mcp.get_learnings_report(status="all")
        assert "❌" not in out_all

    def test_EL_07_export_file_rejects_empty_filepath(self, sl_mcp_env):
        """EL-07: empty filepath is rejected with ❌."""
        out = sl_mcp_env.mcp.export_learnings_file(filepath="")
        assert "❌" in out
        assert "filepath" in out.lower()

    @pytest.mark.slow
    def test_EL_08_export_file_pack_format(
            self, sl_mcp_env, seeded_learnings, isolated_email_env, monkeypatch):
        """EL-08: pack format writes valid .aiplearn JSON."""
        dest = str(isolated_email_env.sample_dir / "test_export.aiplearn")
        sample = str(isolated_email_env.sample_dir)

        # _resolve_writable_path calls _resolve_allowlisted_path (Step 1)
        # which reads the tracking DB from rag_preprocessor directly — not
        # through load_auto_update_list on the mcp module. Patch it directly
        # so the temp path passes the read-allowlist check.
        monkeypatch.setattr(
            sl_mcp_env.mcp, "_resolve_allowlisted_path",
            lambda p: (str(Path(p).resolve()), None))
        isolated_email_env.mcp._writable_allowlist_save([sample])
        monkeypatch.setattr(
            sl_mcp_env.mcp, "_writable_allowlist_load",
            lambda: [sample])

        out = sl_mcp_env.mcp.export_learnings_file(filepath=dest, format="pack")
        assert "✅" in out, f"Expected success. Got: {out}"
        packed = json.loads(Path(dest).read_text(encoding="utf-8"))
        assert "learnings" in packed
        assert packed.get("source_app") == "AI-Prowler"
        assert "schema" in packed

    @pytest.mark.slow
    def test_EL_09_export_file_csv_format(
            self, sl_mcp_env, seeded_learnings, isolated_email_env, monkeypatch):
        """EL-09: csv format writes valid CSV with expected header row."""
        import csv as _csv
        dest = str(isolated_email_env.sample_dir / "test_export.csv")
        sample = str(isolated_email_env.sample_dir)

        monkeypatch.setattr(
            sl_mcp_env.mcp, "_resolve_allowlisted_path",
            lambda p: (str(Path(p).resolve()), None))
        isolated_email_env.mcp._writable_allowlist_save([sample])
        monkeypatch.setattr(
            sl_mcp_env.mcp, "_writable_allowlist_load",
            lambda: [sample])

        out = sl_mcp_env.mcp.export_learnings_file(filepath=dest, format="csv")
        assert "✅" in out, f"Expected success. Got: {out}"
        content = Path(dest).read_text(encoding="utf-8")
        rows = list(_csv.reader(content.splitlines()))
        assert rows[0][0] == "id"
        assert rows[0][1] == "title"
        assert len(rows) > 1

    def test_EL_10_rebuild_learnings_index_empty_ok(self, sl_mcp_env):
        """EL-10: rebuild on empty store succeeds and reports 0 rebuilt."""
        out = sl_mcp_env.mcp.rebuild_learnings_index()
        assert "❌" not in out
        assert "rebuilt" in out.lower() or "✅" in out


# ══════════════════════════════════════════════════════════════════════════════
# WRITE ZONE TOOLS
# ══════════════════════════════════════════════════════════════════════════════

class TestWriteZoneTools:

    def test_WZ_01_list_returns_formatted_string(self, isolated_email_env):
        """WZ-01: list_writable_directories returns a non-empty formatted string."""
        out = isolated_email_env.mcp.list_writable_directories()
        assert isinstance(out, str) and out.strip()
        assert "Write Zone" in out or "writable" in out.lower()

    def test_WZ_02_list_empty_zone_message(self, isolated_email_env):
        """WZ-02: empty write zone shows appropriate message."""
        out = isolated_email_env.mcp.list_writable_directories()
        # Should not show [W] for any directory since none are writable yet
        assert "[W]" not in out or "none" in out.lower()

    def test_WZ_03_grant_rejects_empty_directory(self, isolated_email_env):
        """WZ-03: empty directory is rejected."""
        out = isolated_email_env.mcp.grant_write_access(directory="")
        assert "❌" in out

    def test_WZ_04_grant_rejects_not_in_read_allowlist(self, isolated_email_env):
        """WZ-04: directory not in read allowlist is rejected."""
        untracked = str(isolated_email_env.tmp_path / "not_a_tracked_dir_xyz")
        out = isolated_email_env.mcp.grant_write_access(directory=untracked)
        assert "❌" in out

    def test_WZ_05_grant_adds_directory(self, isolated_email_env):
        """WZ-05: valid tracked directory is added to write zone."""
        sample = str(isolated_email_env.sample_dir)
        out = isolated_email_env.mcp.grant_write_access(directory=sample)
        assert "✅" in out, f"Expected success, got: {out}"
        writable = isolated_email_env.mcp._writable_allowlist_load()
        mcp = isolated_email_env.mcp
        norm_sample = mcp._normalize_path_for_match(sample)
        assert any(mcp._normalize_path_for_match(w) == norm_sample
                   for w in writable)

    def test_WZ_06_grant_idempotent(self, isolated_email_env):
        """WZ-06: granting already-writable directory returns info."""
        sample = str(isolated_email_env.sample_dir)
        isolated_email_env.mcp.grant_write_access(directory=sample)
        out2 = isolated_email_env.mcp.grant_write_access(directory=sample)
        assert "ℹ️" in out2 or "already" in out2.lower()

    def test_WZ_07_revoke_rejects_empty_directory(self, isolated_email_env):
        """WZ-07: empty directory is rejected."""
        out = isolated_email_env.mcp.revoke_write_access(directory="")
        assert "❌" in out

    def test_WZ_08_revoke_removes_directory(self, isolated_email_env):
        """WZ-08: revoking a writable directory removes it."""
        sample = str(isolated_email_env.sample_dir)
        isolated_email_env.mcp.grant_write_access(directory=sample)
        out = isolated_email_env.mcp.revoke_write_access(directory=sample)
        assert "✅" in out, f"Expected success, got: {out}"
        writable = isolated_email_env.mcp._writable_allowlist_load()
        mcp = isolated_email_env.mcp
        norm_sample = mcp._normalize_path_for_match(sample)
        assert not any(mcp._normalize_path_for_match(w) == norm_sample
                       for w in writable)

    def test_WZ_09_revoke_not_in_list_returns_info(self, isolated_email_env):
        """WZ-09: revoking non-writable directory returns info message."""
        out = isolated_email_env.mcp.revoke_write_access(
            directory=str(isolated_email_env.sample_dir))
        assert "ℹ️" in out or "not in" in out.lower()

    def test_WZ_10_staff_blocked_from_grant(self, isolated_email_env):
        """WZ-10: staff cannot manage write zones."""
        staff = _make_user("staff")
        allowed, reason = isolated_email_env.mcp._write_zone_allowed_for_user(
            staff, "/some/dir")
        assert not allowed
        assert "staff" in reason.lower() or "cannot" in reason.lower()

    def test_WZ_11_field_crew_blocked_from_grant(self, isolated_email_env):
        """WZ-11: field_crew cannot manage write zones."""
        fc = _make_user("field_crew")
        allowed, _ = isolated_email_env.mcp._write_zone_allowed_for_user(
            fc, "/some/dir")
        assert not allowed

    def test_WZ_12_owner_always_allowed(self, isolated_email_env):
        """WZ-12: owner is allowed for any directory."""
        owner = _make_user("owner")
        allowed, reason = isolated_email_env.mcp._write_zone_allowed_for_user(
            owner, "/any/path/at/all")
        assert allowed
        assert "owner" in reason.lower()

    def test_WZ_13_manager_allowed_within_scope(self, isolated_email_env):
        """WZ-13: manager with matching scope is allowed for that scope's prefix."""
        manager = _make_user("manager", scopes=["role:sales"])
        users_data = {
            "users": {},
            "collection_map": {
                "rules": [{"prefix": "C:/CompanyDocs/Sales",
                           "collection": "role:sales"}]
            }
        }
        allowed, reason = isolated_email_env.mcp._write_zone_allowed_for_user(
            manager, "C:/CompanyDocs/Sales/Quotes", users_data)
        assert allowed
        assert "scope" in reason.lower()

    def test_WZ_14_manager_blocked_outside_scope(self, isolated_email_env):
        """WZ-14: manager is blocked from directories outside their scopes."""
        manager = _make_user("manager", scopes=["role:sales"])
        users_data = {
            "users": {},
            "collection_map": {
                "rules": [
                    {"prefix": "C:/CompanyDocs/Sales",   "collection": "role:sales"},
                    {"prefix": "C:/CompanyDocs/Finance", "collection": "role:finance"},
                ]
            }
        }
        allowed, reason = isolated_email_env.mcp._write_zone_allowed_for_user(
            manager, "C:/CompanyDocs/Finance/Reports", users_data)
        assert not allowed
        assert "scope" in reason.lower() or "not within" in reason.lower()

    def test_WZ_14b_personal_mode_always_allowed(self, isolated_email_env):
        """WZ-14b: personal mode (user=None) has no restrictions."""
        allowed, reason = isolated_email_env.mcp._write_zone_allowed_for_user(
            None, "/any/directory")
        assert allowed
        assert "personal" in reason.lower()


# ══════════════════════════════════════════════════════════════════════════════
# REINDEX TOOLS
# ══════════════════════════════════════════════════════════════════════════════

class TestReindexTools:

    def test_RI_01_reindex_directory_empty_arg(self, mcp_env):
        """RI-01: empty directory argument is rejected."""
        out = mcp_env.mcp.reindex_directory(directory="")
        assert "❌" in out

    def test_RI_02_reindex_directory_not_in_allowlist(self, mcp_env):
        """RI-02: directory not in allowlist is rejected."""
        out = mcp_env.mcp.reindex_directory(
            directory="/nonexistent/path/xyz_not_tracked_at_all")
        assert "❌" in out

    def test_RI_03_reindex_all_no_dirs(self, mcp_env, monkeypatch):
        """RI-03: reindex_all with no tracked dirs returns info."""
        monkeypatch.setattr(mcp_env.mcp, "load_auto_update_list", lambda: [])
        out = mcp_env.mcp.reindex_all()
        assert "ℹ️" in out or "no tracked" in out.lower()

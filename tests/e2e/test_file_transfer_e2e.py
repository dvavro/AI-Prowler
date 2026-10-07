"""
tests/e2e/test_file_transfer_e2e.py
======================================
Phase 4 of the broader MCP tool E2E suite.

Covers the File Transfer family:
  get_file_download_url, get_file_upload_url

SECURITY NOTE
-------------
Both tools return a REAL bearer token embedded in the URL/fields they
generate (the same token used for the Remote PWA / Jobs PWA / Cloudflare
Tunnel access on this real install — confirmed live: calling these tools
manually returned the actual configured token in plaintext). This test
file deliberately NEVER hardcodes, logs, or asserts on the literal token
value anywhere — every assertion here is purely structural (URL format,
JSON keys present, filename/size/path correctness). Do not add an
assertion that would require printing or comparing against the real
token string.

SAFETY MODEL
------------
- get_file_download_url is tested against the real job tracker
  spreadsheet (always exists, always tracked, a real file whose size is
  independently verifiable via os.path.getsize) — read-only, no risk.
- get_file_upload_url is tested against the existing writable/tracked
  work directory sandbox pattern already used by test_dev_tools_e2e.py
  etc. — this tool only returns INSTRUCTIONS for an upload; it does not
  itself perform any file write, so no actual upload happens and nothing
  needs cleanup.
- Negative-path tests (disallowed extension, untracked directory,
  non-writable directory) use paths that are known not to qualify,
  without needing to create or modify any real state.

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed. Requires Cloudflare Tunnel / Remote Access
already configured on this machine (tunnel_domain + remote_token in
~/.ai-prowler/config.json) for the "happy path" tests — if not configured,
those tests are skipped with a clear reason rather than failing, since an
unconfigured Remote Access setup is a legitimate real-world state, not a
bug.

RUN
---
  run_e2e_mcp_tool.bat -k file_transfer
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
WRITABLE_TEST_DIR = Path(os.environ.get(
    "AI_PROWLER_WRITABLE_TEST_DIR",
    r"C:\Users\david\AI-Prowler-V900_to_V910_work\AI-Prowler",
))
REAL_SPREADSHEET = Path(os.environ.get(
    "AI_PROWLER_JOB_TRACKER_PATH",
    r"C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx",
))

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session")
def remote_access_configured():
    """True if tunnel_domain + remote_token are set — both file-transfer
    tools require this. Reads the same config.json path the tools
    themselves use."""
    cfg_path = Path.home() / ".ai-prowler" / "config.json"
    if not cfg_path.exists():
        return False
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    return bool(cfg.get("tunnel_domain", "").strip()) and \
        bool(cfg.get("remote_token", "").strip())


@pytest.mark.mcp_tool_e2e
class TestGetFileDownloadUrl:

    def test_01_real_file_returns_structurally_valid_url(
            self, mcp_module, remote_access_configured):
        if not remote_access_configured:
            pytest.skip("Remote Access (tunnel_domain/remote_token) not "
                        "configured — see Settings → Remote Access")
        result = mcp_module.get_file_download_url(
            file_path=str(REAL_SPREADSHEET))
        assert "❌" not in result, f"get_file_download_url failed: {result}"

        data = json.loads(result)
        assert data["download_url"].startswith("https://"), (
            f"Expected an https:// URL: {data['download_url']}"
        )
        assert "/remote/download" in data["download_url"]
        assert "path=" in data["download_url"]
        assert "token=" in data["download_url"], (
            "URL must include a token param — presence only checked, "
            "never its literal value (see module docstring)."
        )
        assert data["filename"] == REAL_SPREADSHEET.name
        assert data["size_bytes"] == REAL_SPREADSHEET.stat().st_size, (
            "Reported size_bytes must match the real file's actual size "
            "on disk"
        )

    def test_02_disallowed_extension_rejected(self, mcp_module):
        """.bat is NOT in the download extension allowlist (pdf, docx,
        xlsx, xls, doc, pptx, jpg, jpeg, png, gif, webp, heic, mp4, mov,
        avi, txt, md, csv, json, log, py, js, html, css — confirmed via
        source review; note .py/.js/.html/.css ARE allowed, an earlier
        version of this test wrongly assumed .py was rejected). Uses the
        real run_e2e_mcp_tool.bat file, which definitely exists."""
        result = mcp_module.get_file_download_url(
            file_path=str(WRITABLE_TEST_DIR / "run_e2e_mcp_tool.bat"))
        assert "not in the download allowlist" in result, (
            f"Expected a clean allowlist-rejection message: {result}"
        )

    def test_03_nonexistent_file_returns_clean_error(self, mcp_module):
        result = mcp_module.get_file_download_url(
            file_path=str(WRITABLE_TEST_DIR / "ztest_e2e_does_not_exist.pdf"))
        assert "not found" in result.lower() or "❌" in result, (
            f"Expected a clean not-found error: {result}"
        )

    def test_04_untracked_path_rejected(self, mcp_module):
        """A path with a valid extension that exists but sits outside any
        tracked directory must be rejected — using the Windows temp
        directory as a location definitely not tracked by AI-Prowler."""
        import tempfile
        untracked = Path(tempfile.gettempdir()) / "ztest_e2e_untracked.txt"
        untracked.write_text("test", encoding="utf-8")
        try:
            result = mcp_module.get_file_download_url(
                file_path=str(untracked))
            assert "not inside a tracked directory" in result, (
                f"Expected a clean untracked-path rejection: {result}"
            )
        finally:
            untracked.unlink(missing_ok=True)


@pytest.mark.mcp_tool_e2e
class TestGetFileUploadUrl:

    def test_01_writable_directory_returns_structurally_valid_instructions(
            self, mcp_module, remote_access_configured):
        if not remote_access_configured:
            pytest.skip("Remote Access (tunnel_domain/remote_token) not "
                        "configured — see Settings → Remote Access")
        result = mcp_module.get_file_upload_url(
            filename="ztest_e2e_upload_target.txt",
            target_directory=str(WRITABLE_TEST_DIR),
        )
        assert "❌" not in result, f"get_file_upload_url failed: {result}"

        data = json.loads(result)
        assert data["upload_url"].startswith("https://")
        assert "/remote/upload" in data["upload_url"]
        assert set(("file", "dir", "token")) <= set(data["fields"].keys()), (
            f"Expected file/dir/token fields, got: {list(data['fields'].keys())}"
        )
        assert data["fields"]["token"], (
            "Token field must be present and non-empty — its literal "
            "value is intentionally never asserted here (see module "
            "docstring)."
        )
        assert data["fields"]["dir"] == str(WRITABLE_TEST_DIR)
        assert "ztest_e2e_upload_target.txt" in data["destination"]
        assert "curl" in data["curl_example"].lower()
        # No actual file was created — this tool only returns
        # instructions, it never performs the upload itself.
        assert not (WRITABLE_TEST_DIR / "ztest_e2e_upload_target.txt").exists()

    def test_02_non_writable_directory_rejected(self, mcp_module):
        """A directory that's tracked (readable) but NOT in the writable
        allowlist must be rejected. Uses a fresh untracked/non-granted
        directory path rather than assuming any specific real directory's
        current permission state (which can legitimately change over
        time as grant_write_access/revoke_write_access are used)."""
        import tempfile
        never_writable = Path(tempfile.gettempdir()) / "ztest_e2e_never_writable"
        result = mcp_module.get_file_upload_url(
            filename="x.txt", target_directory=str(never_writable))
        assert (
            "not in the writable allowlist" in result
            or "not inside a tracked directory" in result
        ), f"Expected a clean permission/tracking rejection: {result}"

    def test_03_empty_filename_rejected(self, mcp_module):
        result = mcp_module.get_file_upload_url(
            filename="   ", target_directory=str(WRITABLE_TEST_DIR))
        assert "filename must not be empty" in result.lower() or "❌" in result, (
            f"Expected a clean empty-filename rejection: {result}"
        )

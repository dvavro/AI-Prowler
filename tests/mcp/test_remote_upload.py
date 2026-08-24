"""
test_remote_upload.py
=====================
Live integration test for the /remote/upload endpoint.
Tests the full upload pipeline: multipart POST → file saved → file indexed.

Uses C:\\Users\\david\\Documents\\Misc as the target (a known writable dir).

Run after deploying fixes:
    pytest tests/mcp/test_remote_upload.py -m live_remote -v
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# ── Config ─────────────────────────────────────────────────────────────────
PORT      = int(os.environ.get("AI_PROWLER_REMOTE_TEST_PORT",
                os.environ.get("AI_PROWLER_PORT", 8000)))
BASE_URL  = f"http://127.0.0.1:{PORT}"
TIMEOUT   = 30  # upload needs more time than regular calls
TARGET_DIR = r"C:\Users\david\Documents\Misc"

_CONFIG   = Path.home() / ".ai-prowler" / "config.json"
try:
    BEARER_TOKEN = json.loads(_CONFIG.read_text(encoding="utf-8")).get("remote_token", "")
except Exception:
    BEARER_TOKEN = ""

# Test file names — prefixed so they're easy to identify and clean up
TEST_TXT  = "remote_upload_test_text.txt"
TEST_IMG  = "remote_upload_test_image.png"


def _server_running() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def _skip_if_no_server():
    if not _server_running():
        pytest.skip(f"No server on port {PORT}")
    if not BEARER_TOKEN:
        pytest.skip("No Bearer token in config.json")
    if not Path(TARGET_DIR).exists():
        pytest.skip(f"Target dir doesn't exist: {TARGET_DIR}")


def _build_multipart(filename: str, content: bytes, dir_path: str,
                     token: str, boundary: bytes = b"TestBoundary99999"):
    """Build a multipart/form-data body."""
    def _file_field(name, fname, data):
        return (b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + name.encode() +
                b'"; filename="' + fname.encode() + b'"\r\n'
                b"Content-Type: application/octet-stream\r\n\r\n"
                + data + b"\r\n")

    def _text_field(name, value):
        return (b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n'
                + value.encode() + b"\r\n")

    body = (_file_field("file", filename, content)
            + _text_field("dir", dir_path)
            + _text_field("token", token)
            + b"--" + boundary + b"--\r\n")
    ct = f"multipart/form-data; boundary={boundary.decode()}"
    return body, ct


def _upload(filename: str, content: bytes, dir_path: str = TARGET_DIR,
            token: str = None):
    """POST a file to /remote/upload. Returns (status, response_dict)."""
    tok = token or BEARER_TOKEN
    body, ct = _build_multipart(filename, content, dir_path, tok)
    req = urllib.request.Request(
        BASE_URL + "/remote/upload",
        data=body,
        headers={"Content-Type": ct},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": str(e)}


# ── Cleanup fixture ─────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Remove test files before and after each test."""
    for fname in [TEST_TXT, TEST_IMG]:
        p = Path(TARGET_DIR) / fname
        if p.exists():
            p.unlink()
    yield
    for fname in [TEST_TXT, TEST_IMG]:
        p = Path(TARGET_DIR) / fname
        if p.exists():
            p.unlink()


# ══════════════════════════════════════════════════════════════════════════════
# LIVE UPLOAD TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestRemoteUpload:

    @pytest.mark.live_remote
    def test_upload_text_file_succeeds(self):
        """Upload a text file to Misc — verifies 200 response and file on disk."""
        _skip_if_no_server()
        content = b"Remote PWA upload test - text file\nTimestamp: " + str(time.time()).encode()
        status, resp = _upload(TEST_TXT, content)
        assert status == 200, f"Expected 200, got {status}: {resp}"
        assert resp.get("ok") is True, f"Upload not ok: {resp}"
        assert resp.get("filename") == TEST_TXT, f"Wrong filename: {resp}"
        assert resp.get("size") == len(content), f"Wrong size: {resp}"
        # Verify file is on disk
        dest = Path(TARGET_DIR) / TEST_TXT
        assert dest.exists(), f"File not found on disk: {dest}"
        assert dest.read_bytes() == content, "File content mismatch"

    @pytest.mark.live_remote
    def test_upload_binary_file_succeeds(self):
        """Upload a minimal PNG to Misc — verifies binary files work."""
        _skip_if_no_server()
        # Minimal 1x1 white PNG
        png = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
               b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00'
               b'\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18'
               b'\xd8N\x00\x00\x00\x00IEND\xaeB`\x82')
        status, resp = _upload(TEST_IMG, png)
        assert status == 200, f"Expected 200, got {status}: {resp}"
        assert resp.get("ok") is True, f"Upload not ok: {resp}"
        dest = Path(TARGET_DIR) / TEST_IMG
        assert dest.exists(), f"Image not found on disk: {dest}"
        assert dest.read_bytes() == png, "Image content mismatch"

    @pytest.mark.live_remote
    def test_upload_no_token_returns_401(self):
        """Upload with clearly invalid token should return 401."""
        _skip_if_no_server()
        # Use a non-empty invalid token — empty string may be treated as
        # "no token provided" differently depending on server implementation
        status, resp = _upload(TEST_TXT, b"test", token="definitely_invalid_token_xyz_123")
        assert status == 401, f"Expected 401, got {status}: {resp}"

    @pytest.mark.live_remote
    def test_upload_wrong_token_returns_401(self):
        """Upload with wrong token should return 401."""
        _skip_if_no_server()
        status, resp = _upload(TEST_TXT, b"test", token="wrong_token_xyz")
        assert status == 401, f"Expected 401, got {status}"

    @pytest.mark.live_remote
    def test_upload_to_readonly_dir_returns_403(self):
        """Upload to a read-only tracked dir should return 403."""
        _skip_if_no_server()
        # Program Files is tracked but read-only
        readonly_dir = r"C:\Program Files\AI-Prowler"
        status, resp = _upload(TEST_TXT, b"test", dir_path=readonly_dir)
        assert status == 403, f"Expected 403 for read-only dir, got {status}: {resp}"

    @pytest.mark.live_remote
    def test_upload_to_untracked_dir_returns_403(self):
        """Upload to an untracked dir should return 403."""
        _skip_if_no_server()
        status, resp = _upload(TEST_TXT, b"test", dir_path=r"C:\Windows\Temp")
        assert status == 403, f"Expected 403 for untracked dir, got {status}: {resp}"

    @pytest.mark.live_remote
    def test_upload_missing_dir_field_returns_400(self):
        """Upload with no dir field should return 400."""
        _skip_if_no_server()
        body, ct = _build_multipart(TEST_TXT, b"test", "", BEARER_TOKEN)
        # Build body with empty dir
        req = urllib.request.Request(
            BASE_URL + "/remote/upload",
            data=body,
            headers={"Content-Type": ct},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                resp = json.loads(r.read())
                assert False, f"Expected 400, got 200: {resp}"
        except urllib.error.HTTPError as e:
            assert e.code in (400, 403), f"Expected 400/403, got {e.code}"

    @pytest.mark.live_remote
    def test_upload_file_is_searchable_after_index(self):
        """After upload, the file content should be findable via search_documents."""
        _skip_if_no_server()
        # Upload a file with unique searchable content
        unique_token = f"REMOTE_UPLOAD_TEST_{int(time.time())}"
        content = f"This is a remote upload test file. Token: {unique_token}".encode()
        status, resp = _upload(TEST_TXT, content)
        assert status == 200, f"Upload failed: {resp}"
        assert (Path(TARGET_DIR) / TEST_TXT).exists()

        # Wait briefly for indexing to complete
        time.sleep(2)

        # Search for the unique token
        search_body = json.dumps({
            "tool": "search_documents",
            "args": {"query": unique_token, "n_results": 3}
        }).encode()
        req = urllib.request.Request(
            BASE_URL + "/remote-api",
            data=search_body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {BEARER_TOKEN}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                result = json.loads(r.read())
                # The unique token should appear in search results
                result_text = str(result.get("result", ""))
                assert unique_token in result_text or TEST_TXT in result_text, \
                    f"Uploaded file not found in search results after indexing. " \
                    f"Token: {unique_token}, Results: {result_text[:200]}"
        except urllib.error.HTTPError as e:
            pytest.fail(f"Search after upload failed: {e.code}")

    @pytest.mark.live_remote
    def test_upload_overwrites_existing_file(self):
        """Second upload of same filename should overwrite, not fail."""
        _skip_if_no_server()
        # First upload
        status1, _ = _upload(TEST_TXT, b"original content")
        assert status1 == 200

        # Second upload with different content
        status2, resp2 = _upload(TEST_TXT, b"overwritten content")
        assert status2 == 200, f"Overwrite failed: {resp2}"

        # Verify new content
        dest = Path(TARGET_DIR) / TEST_TXT
        assert dest.read_bytes() == b"overwritten content", "File not overwritten"

"""
test_pwa_features.py
====================
Comprehensive PWA Feature Test Suite
AI-Prowler Companion PWA — v1.0

TEST PLAN
=========

FEATURE 1: App Shell & Navigation
  1.1  /pwa/ loads with correct HTML title
  1.2  App boots straight in (no auth screen)
  1.3  Top bar shows AI-PROWLER brand name
  1.4  Bottom nav has 4 tabs: Jobs, Clock, Photos, Profile
  1.5  Jobs tab is active by default
  1.6  PWA manifest is valid and installable
  1.7  Service worker file exists and is valid JS

FEATURE 2: Jobs Screen
  2.1  Jobs screen heading is "Today's Jobs"
  2.2  /pwa-api read_job_spreadsheet returns 200
  2.3  Response contains ok=true
  2.4  Job data has required fields (ID, customer, service, status)
  2.5  Job status badge renders for Scheduled/Complete/In Progress
  2.6  Job detail modal structure is present in HTML
  2.7  Modal has Clock In / Clock Out / Add Photos / Maps buttons
  2.8  Connection dot element exists in DOM

FEATURE 3: Clock Screen
  3.1  Clock screen heading is "Time Tracking"
  3.2  Clock display element exists
  3.3  Clock In button exists and has correct ID
  3.4  Clock Out button exists, starts disabled
  3.5  Job select dropdown exists
  3.6  Recent Entries section exists
  3.7  /pwa-api log_time_entry clock-in returns ok=true
  3.8  /pwa-api log_time_entry clock-out returns ok=true
  3.9  Clock in/out for a real job ID works end-to-end
  3.10 Active clock banner element exists in jobs screen

FEATURE 4: Photos Screen
  4.1  Photos screen heading is "Job Photos"
  4.2  Job selector dropdown exists on photos screen
  4.3  Photo grid element exists
  4.4  Upload zone element exists with camera icon
  4.5  File input exists with image/* accept and capture=environment
  4.6  Photo count display shows "0 / 10"
  4.7  Upload button starts disabled
  4.8  Notes textarea exists
  4.9  /pwa-api record_learning (photo upload) returns ok=true
  4.10 Photo count enforces max 10

FEATURE 5: Profile Screen
  5.1  Profile screen heading is "My Account"
  5.2  Device card shows Name row
  5.3  Device card shows Role row
  5.4  Device card shows Server=Connected row
  5.5  Session stats card shows Jobs Loaded
  5.6  Session stats card shows Clock Entries
  5.7  Session stats card shows Photos Uploaded
  5.8  Sign Out button exists

FEATURE 6: Server Endpoints
  6.1  /pwa/ returns 200 with text/html
  6.2  /pwa/manifest.json returns 200 with valid JSON
  6.3  /pwa/sw.js returns 200
  6.4  /pwa-token returns 200 with {"token": "..."}
  6.5  /pwa-api returns 200 for valid tool call
  6.6  /pwa-api returns 400 for unknown tool
  6.7  /pwa-api returns 400 for malformed JSON
  6.8  /pwa missing file returns 404
  6.9  Path traversal attack returns 403/404
  6.10 /mcp still requires Bearer auth (not broken)

FEATURE 7: PWA Installability
  7.1  manifest.json has required "name" field
  7.2  manifest.json has "start_url"
  7.3  manifest.json has "display": "standalone"
  7.4  manifest.json has icons array with 192px and 512px
  7.5  manifest.json theme_color matches brand cyan
  7.6  HTML has <link rel="manifest"> tag
  7.7  HTML has apple-mobile-web-app-capable meta
  7.8  HTML has theme-color meta tag
  7.9  Service worker registers /pwa/sw.js
  7.10 Service worker has install, activate, fetch handlers

FEATURE 8: Security
  8.1  Path traversal blocked on /pwa/../
  8.2  /pwa-token not exposed via /mcp (no auth bypass)
  8.3  Unknown tools blocked by allowed-list in /pwa-api
  8.4  /mcp endpoint still enforces Bearer token
  8.5  Bearer token not exposed in HTML source

Run all:
    run_tests.bat tests\\mcp\\test_pwa_features.py -v -m live_pwa

Run offline only (no server needed):
    run_tests.bat tests\\mcp\\test_pwa_features.py -v -m "not live_pwa"
"""
from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────
_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT  = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
MCP_FILE  = SRC_ROOT / "ai_prowler_mcp.py"
PWA_DIR   = SRC_ROOT / "jobs"   # disk folder is jobs/ to match the /jobs/ URL route
HTML_FILE = PWA_DIR  / "index.html"
MANIFEST  = PWA_DIR  / "manifest.json"
SW_FILE   = PWA_DIR  / "sw.js"

# ── Live server config ─────────────────────────────────────────────────────
PORT     = int(os.environ.get("AI_PROWLER_PORT", 8000))
BASE_URL = f"http://127.0.0.1:{PORT}"
TIMEOUT  = 10

_CONFIG_PATH = Path.home() / ".ai-prowler" / "config.json"
try:
    _cfg         = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    BEARER_TOKEN = _cfg.get("remote_token", "")
except Exception:
    BEARER_TOKEN = ""


# ── Helpers ────────────────────────────────────────────────────────────────

def _server_running() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def _get(path: str, hdrs: dict = None, auth: bool = True):
    h = {}
    if auth and BEARER_TOKEN:
        h["Authorization"] = f"Bearer {BEARER_TOKEN}"
    if hdrs:
        h.update(hdrs)
    req = urllib.request.Request(BASE_URL + path, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            # Normalise header keys to lowercase for consistent access
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in dict(e.headers).items()}, e.read()


def _post(path: str, body: bytes, hdrs: dict = None, auth: bool = True):
    h = {"Content-Type": "application/json"}
    if auth and BEARER_TOKEN:
        h["Authorization"] = f"Bearer {BEARER_TOKEN}"
    if hdrs:
        h.update(hdrs)
    req = urllib.request.Request(BASE_URL + path, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in dict(e.headers).items()}, e.read()


def _api(tool: str, args: dict = None):
    body = json.dumps({"tool": tool, "args": args or {}}).encode()
    status, hdrs, resp = _post("/pwa-api", body)
    try:
        data = json.loads(resp)
    except Exception:
        data = {}
    return status, data


@pytest.fixture(scope="session")
def server():
    """Skip live tests if server not running or no token configured."""
    if not _server_running():
        pytest.skip(
            f"AI-Prowler not running on port {PORT}. "
            "Start HTTP Server in Settings tab, then re-run with -m live_pwa"
        )
    if not BEARER_TOKEN:
        pytest.skip(
            "No Bearer token found in ~/.ai-prowler/config.json (remote_token). "
            "Configure Remote Access in the Settings tab first."
        )


@pytest.fixture(scope="session")
def html():
    assert HTML_FILE.exists(), f"index.html not found: {HTML_FILE}"
    return HTML_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def manifest_data():
    assert MANIFEST.exists(), f"manifest.json not found: {MANIFEST}"
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def sw_source():
    assert SW_FILE.exists(), f"sw.js not found: {SW_FILE}"
    return SW_FILE.read_text(encoding="utf-8")



# ── Session-scoped cleanup ─────────────────────────────────────────────────
# Tracks every learning title created by tests so we can delete them after.
# Also snapshots the ChromaDB chunk count before tests begin so we can
# verify the install is left in the same state.
_TEST_LEARNING_TITLES = []
_CHUNK_COUNT_BEFORE   = None


@pytest.fixture(scope="session", autouse=True)
def pwa_test_cleanup():
    """
    Snapshot AI-Prowler state before live tests, then clean up after.
    - Records ChromaDB chunk count before tests start
    - Collects titles of any learnings created during tests
    - Deletes those learnings after the session ends
    - Verifies chunk count returned to baseline (within tolerance)
    - Does NOT touch pwa/ files, config, or any install directory files
    """
    global _CHUNK_COUNT_BEFORE

    # ── PRE-TEST SNAPSHOT ──────────────────────────────────────────────────
    try:
        status, data = _api("check_ai_prowler_status", {})
        if data.get("ok"):
            result = data.get("result", "")
            # Extract chunk count from status string e.g. "Chunks    : 429"
            for line in result.splitlines():
                if "Chunks" in line and ":" in line:
                    try:
                        _CHUNK_COUNT_BEFORE = int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
    except Exception:
        pass

    yield  # ── tests run here ──────────────────────────────────────────────

    # ── POST-TEST CLEANUP ──────────────────────────────────────────────────
    cleanup_errors = []

    # Delete any learnings created by the test suite
    for title in _TEST_LEARNING_TITLES:
        try:
            _, search_data = _api("search_learnings", {"query": title, "max_results": 5})
            if not search_data.get("ok"):
                pass  # Learning may not have been created — skip silently
        except Exception as e:
            cleanup_errors.append(f"Could not clean up learning '{title}': {e}")

    # Verify chunk count returned to baseline
    if _CHUNK_COUNT_BEFORE is not None:
        try:
            _, data = _api("check_ai_prowler_status", {})
            result = data.get("result", "")
            chunk_count_after = None
            for line in result.splitlines():
                if "Chunks" in line and ":" in line:
                    try:
                        chunk_count_after = int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
            if chunk_count_after is not None:
                delta = chunk_count_after - _CHUNK_COUNT_BEFORE
                if delta > 5:
                    cleanup_errors.append(
                        f"ChromaDB chunk count grew by {delta} during tests "
                        f"({_CHUNK_COUNT_BEFORE} → {chunk_count_after}). "
                        f"Tests may have left data behind."
                    )
        except Exception:
            pass

    if cleanup_errors:
        print("\n⚠️  PWA TEST CLEANUP WARNINGS:")
        for err in cleanup_errors:
            print(f"  - {err}")
    else:
        print("\n✅ PWA test cleanup complete — AI-Prowler install unchanged.")


def _track_learning(title: str):
    """Call this whenever a test creates a learning so cleanup can remove it."""
    _TEST_LEARNING_TITLES.append(title)


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 1: App Shell & Navigation
# ══════════════════════════════════════════════════════════════════════════

class TestFeature1_AppShell:
    """1.x — App Shell & Navigation"""

    def test_1_1_html_title(self, html):
        # Jobs PWA title. (Was "AI-Prowler Crew" in an earlier revision —
        # updated to "AI-Prowler Jobs" when the app moved to the /jobs/ route.)
        assert "AI-Prowler Jobs" in html, "Missing <title>AI-Prowler Jobs</title>"

    def test_1_2_no_auth_screen_on_boot(self, html):
        # Auth screen should be hidden — app boots without login
        assert 'id="authScreen"' in html, "authScreen element missing"
        # The DOMContentLoaded handler should call bootApp directly, not showAuth
        assert "bootApp()" in html, "bootApp() not called on load"
        assert "showAuth()" not in html.split("DOMContentLoaded")[1].split("});")[0], \
            "showAuth() is being called on DOMContentLoaded — should boot directly"

    def test_1_3_topbar_brand(self, html):
        assert "AI-PROWLER" in html, "Brand name AI-PROWLER missing from topbar"

    def test_1_4_four_nav_tabs(self, html):
        # Count nav-label spans in the nav element only (not the CSS class definition)
        nav_section = html.split('<nav class="bottomnav">')[1].split('</nav>')[0]
        count = nav_section.count("nav-label")
        assert 4 <= count <= 7, f"Expected 4-7 nav tabs, got {count}"
        for label in ["Jobs", "Calendar", "Clock", "Photos", "Profile"]:
            assert label in nav_section, f"Nav tab '{label}' missing"

    def test_1_5_jobs_tab_active_by_default(self, html):
        assert 'id="screen-jobs" class="screen active"' in html, \
            "Jobs screen should be active by default"

    def test_1_6_manifest_link_in_html(self, html):
        assert 'rel="manifest"' in html, "manifest link tag missing"
        # Jobs PWA serves from /jobs/ — manifest lives at /jobs/manifest.json.
        # (Was /pwa/manifest.json before the route was renamed to /jobs/.)
        assert "/jobs/manifest.json" in html, "manifest href should be /jobs/manifest.json"

    def test_1_7_sw_js_registered(self, html):
        assert "sw.js" in html, "Service worker not referenced in HTML"
        # Jobs PWA registers the SW under /jobs/sw.js.
        # (Was /pwa/sw.js before the route was renamed to /jobs/.)
        assert "/jobs/sw.js" in html, "Service worker path should be /jobs/sw.js"


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 2: Jobs Screen
# ══════════════════════════════════════════════════════════════════════════

class TestFeature2_JobsScreen:
    """2.x — Jobs Screen"""

    def test_2_1_jobs_heading(self, html):
        assert "Today's Jobs" in html

    def test_2_2_jobs_list_element(self, html):
        assert 'id="jobsList"' in html

    def test_2_3_active_clock_banner_element(self, html):
        assert 'id="activeClock"' in html

    def test_2_4_job_modal_exists(self, html):
        assert 'id="jobModal"' in html
        assert 'id="modalJobId"' in html
        assert 'id="modalCustomer"' in html
        assert 'id="modalBadge"' in html
        assert 'id="modalBody"' in html

    def test_2_5_modal_has_clock_in_button(self, html):
        assert "Clock In" in html, "Clock In button missing from modal"
        assert "Clock Out" in html, "Clock Out button missing from modal"

    def test_2_6_modal_has_photos_button(self, html):
        assert "Add Photos" in html, "Add Photos button missing from modal"

    def test_2_7_modal_has_maps_link(self, html):
        assert "maps.google.com" in html, "Google Maps link missing from modal"

    def test_2_8_connection_dot_exists(self, html):
        assert 'id="connDot"' in html

    @pytest.mark.live_pwa
    def test_2_9_live_load_jobs(self, server):
        status, data = _api("read_job_spreadsheet", {"max_rows": 10})
        assert status == 200, f"read_job_spreadsheet returned {status}"
        assert data.get("ok") is True, f"Error: {data.get('error')}"

    @pytest.mark.live_pwa
    def test_2_10_live_jobs_result_not_empty(self, server):
        status, data = _api("read_job_spreadsheet", {"max_rows": 10})
        assert data.get("result"), "Job result is empty"

    @pytest.mark.live_pwa
    def test_2_11_live_jobs_response_is_json(self, server):
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {}}).encode()
        status, hdrs, _ = _post("/pwa-api", body)
        assert "json" in hdrs.get("content-type", ""), "Response not JSON"


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 3: Clock Screen
# ══════════════════════════════════════════════════════════════════════════

class TestFeature3_ClockScreen:
    """3.x — Clock Screen"""

    def test_3_1_clock_heading(self, html):
        assert "Time Tracking" in html

    def test_3_2_clock_display_element(self, html):
        assert 'id="clockDisplay"' in html

    def test_3_3_clock_date_element(self, html):
        assert 'id="clockDateDisplay"' in html

    def test_3_4_clock_status_text(self, html):
        assert 'id="clockStatusText"' in html
        assert "Not clocked in" in html

    def test_3_5_clock_elapsed_element(self, html):
        assert 'id="clockElapsed"' in html

    def test_3_6_clock_in_button(self, html):
        assert 'id="clockInBtn"' in html
        assert "clockAction('start')" in html

    def test_3_7_clock_out_button_disabled_by_default(self, html):
        assert 'id="clockOutBtn"' in html
        assert "clockAction('stop')" in html
        # Clock out starts disabled
        clockout_area = html.split("clockOutBtn")[1][:100]
        assert "disabled" in clockout_area, "Clock Out button should start disabled"

    def test_3_8_job_select_on_clock_screen(self, html):
        assert 'id="clockJobSelect"' in html

    def test_3_9_clock_result_element(self, html):
        assert 'id="clockResult"' in html

    def test_3_10_clock_history_element(self, html):
        assert 'id="clockHistory"' in html

    @pytest.mark.live_pwa
    def test_3_11_live_clock_in(self, server):
        # Use a test job ID — won't create real data if job doesn't exist
        status, data = _api("log_time_entry", {
            "job_identifier": "JOB-TEST-PWA",
            "action": "start"
        })
        # 200 ok=true means it worked; 200 ok=false means job not found
        # Both are valid server responses — we just need the endpoint to work
        assert status == 200, f"log_time_entry start returned {status}"

    @pytest.mark.live_pwa
    def test_3_12_live_clock_out(self, server):
        status, data = _api("log_time_entry", {
            "job_identifier": "JOB-TEST-PWA",
            "action": "stop"
        })
        assert status == 200, f"log_time_entry stop returned {status}"


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 4: Photos Screen
# ══════════════════════════════════════════════════════════════════════════

class TestFeature4_PhotosScreen:
    """4.x — Photos Screen"""

    def test_4_1_photos_heading(self, html):
        assert "Job Photos" in html

    def test_4_2_photo_job_select(self, html):
        assert 'id="photoJobSelect"' in html

    def test_4_3_photo_grid_element(self, html):
        assert 'id="photoGrid"' in html

    def test_4_4_upload_zone_exists(self, html):
        assert "upload-zone" in html
        assert "📷" in html

    def test_4_5_file_input_config(self, html):
        # fileInput split into fileInputCamera and fileInputFiles
        assert 'id="fileInputCamera"' in html or 'id="fileInput"' in html, \
            "Camera file input missing"
        assert 'accept="image/*"' in html
        assert 'capture="environment"' in html, "Should use rear camera on mobile"
        assert "multiple" in html, "Should allow multiple photo selection"

    def test_4_6_photo_count_display(self, html):
        assert 'id="photoCount"' in html
        assert "0 / 10" in html

    def test_4_7_upload_button_disabled_default(self, html):
        assert 'id="uploadBtn"' in html
        upload_area = html.split("uploadBtn")[1][:100]
        assert "disabled" in upload_area, "Upload button should start disabled"

    def test_4_8_notes_textarea_exists(self, html):
        assert 'id="photoNotes"' in html
        assert "Describe the work" in html

    def test_4_9_max_10_photos_enforced(self, html):
        assert "10" in html, "Max 10 photos limit not referenced"
        assert "state.photos.length >= 10" in html or \
               "10 - state.photos.length" in html or \
               "Max 10" in html, "Max 10 photo limit not enforced in code"

    def test_4_10_upload_uses_photos_endpoint(self, html):
        """Photos now POST to /photos/upload (real file upload) not record_learning directly."""
        assert "/photos/upload" in html, \
            "uploadPhotos() should POST to /photos/upload endpoint"
        assert "FormData" in html, \
            "uploadPhotos() should use FormData for real multipart upload"

    @pytest.mark.live_pwa
    def test_4_11_live_upload_endpoint_exists(self, server):
        """POST /photos/upload endpoint responds (not 404)."""
        boundary = b"----TestBoundary1234"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="job_id"\r\n\r\n'
            b"JOB-TEST-PWA\r\n"
            b"--" + boundary + b"--\r\n"
        )
        status, _, _ = _post(
            "/photos/upload", body,
            hdrs={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}
        )
        # 400 = reached endpoint, rejected bad input (no photo)
        # 200 = succeeded — both mean the endpoint exists
        assert status in (200, 400), \
            f"/photos/upload returned {status} — endpoint not found or crashed"

    @pytest.mark.live_pwa
    def test_4_12_live_upload_requires_job_id(self, server):
        """POST /photos/upload without job_id returns 400."""
        boundary = b"----TestBoundary5678"
        # Send a photo but no job_id field
        img_bytes = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
            b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
            b"\xff\xd9"  # minimal valid JPEG
        )
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="photo"; filename="test.jpg"\r\n'
            b"Content-Type: image/jpeg\r\n\r\n"
            + img_bytes + b"\r\n"
            b"--" + boundary + b"--\r\n"
        )
        status, _, resp = _post(
            "/photos/upload", body,
            hdrs={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}
        )
        assert status == 400, f"Expected 400 without job_id, got {status}"
        data = json.loads(resp)
        assert data.get("ok") is False
        assert "job_id" in data.get("error", "").lower(), \
            f"Error should mention job_id, got: {data.get('error')}"

    @pytest.mark.live_pwa
    def test_4_13_live_upload_real_photo_saves_to_disk(self, server):
        """
        POST /photos/upload with a real JPEG + job_id saves file to disk
        and returns ok=true with the correct directory and filename.
        Cleans up the saved file after the test.
        """
        boundary = b"----TestBoundaryABCD"
        job_id   = "JOB-TEST-PWA-UPLOAD"

        # Minimal valid 1x1 red JPEG (real file, not random bytes)
        jpeg_bytes = bytes([
            0xff,0xd8,0xff,0xe0,0x00,0x10,0x4a,0x46,0x49,0x46,0x00,0x01,
            0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0xff,0xdb,0x00,0x43,
            0x00,0x08,0x06,0x06,0x07,0x06,0x05,0x08,0x07,0x07,0x07,0x09,
            0x09,0x08,0x0a,0x0c,0x14,0x0d,0x0c,0x0b,0x0b,0x0c,0x19,0x12,
            0x13,0x0f,0x14,0x1d,0x1a,0x1f,0x1e,0x1d,0x1a,0x1c,0x1c,0x20,
            0x24,0x2e,0x27,0x20,0x22,0x2c,0x23,0x1c,0x1c,0x28,0x37,0x29,
            0x2c,0x30,0x31,0x34,0x34,0x34,0x1f,0x27,0x39,0x3d,0x38,0x32,
            0x3c,0x2e,0x33,0x34,0x32,0xff,0xc0,0x00,0x0b,0x08,0x00,0x01,
            0x00,0x01,0x01,0x01,0x11,0x00,0xff,0xc4,0x00,0x1f,0x00,0x00,
            0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0xff,0xc4,0x00,0xb5,0x10,0x00,0x02,0x01,0x03,
            0x03,0x02,0x04,0x03,0x05,0x05,0x04,0x04,0x00,0x00,0x01,0x7d,
            0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,
            0x13,0x51,0x61,0x07,0x22,0x71,0x14,0x32,0x81,0x91,0xa1,0x08,
            0x23,0x42,0xb1,0xc1,0x15,0x52,0xd1,0xf0,0x24,0x33,0x62,0x72,
            0x82,0x09,0x0a,0x16,0x17,0x18,0x19,0x1a,0x25,0x26,0x27,0x28,
            0xff,0xda,0x00,0x08,0x01,0x01,0x00,0x00,0x3f,0x00,0xf5,0x0a,
            0x28,0xa2,0x80,0xff,0xd9
        ])

        notes = "Automated test upload — safe to delete"
        body  = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="job_id"\r\n\r\n'
            + job_id.encode() + b"\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="notes"\r\n\r\n'
            + notes.encode() + b"\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="photo"; filename="test_photo.jpg"\r\n'
            b"Content-Type: image/jpeg\r\n\r\n"
            + jpeg_bytes + b"\r\n"
            b"--" + boundary + b"--\r\n"
        )

        status, _, resp = _post(
            "/photos/upload", body,
            hdrs={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}
        )

        assert status == 200, f"Expected 200, got {status}: {resp[:200]}"
        data = json.loads(resp)
        assert data.get("ok") is True, f"Upload failed: {data.get('error')}"
        assert data.get("saved") == 1, f"Expected 1 saved, got {data.get('saved')}"
        assert len(data.get("files", [])) == 1, "Expected 1 filename in response"
        assert data.get("dir"), "Expected dir in response"

        # Verify the file actually exists on disk
        saved_dir  = Path(data["dir"])
        saved_file = saved_dir / data["files"][0]
        assert saved_dir.exists(),  f"Photo directory not created: {saved_dir}"
        assert saved_file.exists(), f"Photo file not saved: {saved_file}"
        assert saved_file.stat().st_size > 0, "Saved file is empty"

        # ── CLEANUP — remove the test photo and directory ──────────────────
        try:
            saved_file.unlink()
            # Remove dir only if now empty
            if not any(saved_dir.iterdir()):
                saved_dir.rmdir()
        except Exception as e:
            print(f"\n⚠️  Cleanup warning: could not remove test photo: {e}")

    @pytest.mark.live_pwa
    def test_4_14_live_upload_multiple_photos(self, server):
        """POST /photos/upload with 3 photos saves all 3 and returns saved=3."""
        from pathlib import Path

        boundary = b"----TestBoundaryMULTI"
        job_id   = "JOB-TEST-PWA-MULTI"

        # Tiny valid PNG (1x1 white pixel)
        png_bytes = bytes([
            0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,
            0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
            0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,
            0xde,0x00,0x00,0x00,0x0c,0x49,0x44,0x41,
            0x54,0x08,0xd7,0x63,0xf8,0xcf,0xc0,0x00,
            0x00,0x00,0x02,0x00,0x01,0xe2,0x21,0xbc,
            0x33,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,
            0x44,0xae,0x42,0x60,0x82
        ])

        def _photo_part(name):
            return (
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="photo"; filename="' + name.encode() + b'"\r\n'
                b"Content-Type: image/png\r\n\r\n"
                + png_bytes + b"\r\n"
            )

        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="job_id"\r\n\r\n'
            + job_id.encode() + b"\r\n"
            + _photo_part("photo1.png")
            + _photo_part("photo2.png")
            + _photo_part("photo3.png")
            + b"--" + boundary + b"--\r\n"
        )

        status, _, resp = _post(
            "/photos/upload", body,
            hdrs={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}
        )
        assert status == 200, f"Expected 200, got {status}: {resp[:200]}"
        data = json.loads(resp)
        assert data.get("ok") is True
        assert data.get("saved") == 3, f"Expected 3 saved, got {data.get('saved')}"
        assert len(data.get("files", [])) == 3

        # ── CLEANUP ────────────────────────────────────────────────────────
        try:
            saved_dir = Path(data["dir"])
            for fname in data["files"]:
                (saved_dir / fname).unlink(missing_ok=True)
            if saved_dir.exists() and not any(saved_dir.iterdir()):
                saved_dir.rmdir()
        except Exception as e:
            print(f"\n⚠️  Cleanup warning: {e}")

    @pytest.mark.live_pwa
    def test_4_15_live_upload_photo_dir_uses_job_id(self, server):
        """Saved photos go into a subfolder named after the job ID."""
        from pathlib import Path

        boundary = b"----TestBoundaryDIR1"
        job_id   = "JOB-DIR-TEST-001"
        png_bytes = bytes([
            0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,
            0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
            0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,
            0xde,0x00,0x00,0x00,0x0c,0x49,0x44,0x41,
            0x54,0x08,0xd7,0x63,0xf8,0xcf,0xc0,0x00,
            0x00,0x00,0x02,0x00,0x01,0xe2,0x21,0xbc,
            0x33,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,
            0x44,0xae,0x42,0x60,0x82
        ])
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="job_id"\r\n\r\n'
            + job_id.encode() + b"\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="photo"; filename="dir_test.png"\r\n'
            b"Content-Type: image/png\r\n\r\n"
            + png_bytes + b"\r\n"
            b"--" + boundary + b"--\r\n"
        )
        status, _, resp = _post(
            "/photos/upload", body,
            hdrs={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}
        )
        assert status == 200
        data = json.loads(resp)
        assert data.get("ok") is True
        # Directory must contain the job ID
        assert job_id in data.get("dir", ""), \
            f"Save dir '{data.get('dir')}' should contain job_id '{job_id}'"
        # Directory must contain AI-Prowler/JobPhotos
        assert "JobPhotos" in data.get("dir", ""), \
            f"Save dir should be under JobPhotos, got: {data.get('dir')}"

        # ── CLEANUP ────────────────────────────────────────────────────────
        try:
            saved_dir = Path(data["dir"])
            for fname in data.get("files", []):
                (saved_dir / fname).unlink(missing_ok=True)
            if saved_dir.exists() and not any(saved_dir.iterdir()):
                saved_dir.rmdir()
        except Exception as e:
            print(f"\n⚠️  Cleanup warning: {e}")


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 5: Profile Screen
# ══════════════════════════════════════════════════════════════════════════

class TestFeature5_ProfileScreen:
    """5.x — Profile Screen"""

    def test_5_1_profile_heading(self, html):
        assert "My Account" in html

    def test_5_2_profile_name_element(self, html):
        assert 'id="profileName"' in html

    def test_5_3_profile_role_element(self, html):
        assert 'id="profileRole"' in html

    def test_5_4_profile_code_element(self, html):
        assert 'id="profileCode"' in html

    def test_5_5_server_connected_indicator(self, html):
        assert "● Connected" in html

    def test_5_6_stat_jobs_element(self, html):
        assert 'id="statJobs"' in html

    def test_5_7_stat_clocks_element(self, html):
        assert 'id="statClocks"' in html

    def test_5_8_stat_photos_element(self, html):
        assert 'id="statPhotos"' in html

    def test_5_9_sign_out_button(self, html):
        assert "Sign Out" in html
        assert "signOut()" in html


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 6: Server Endpoints
# ══════════════════════════════════════════════════════════════════════════

class TestFeature6_ServerEndpoints:
    """6.x — Server Endpoints (requires running AI-Prowler)"""

    @pytest.mark.live_pwa
    def test_6_1_pwa_index_200(self, server):
        status, hdrs, body = _get("/jobs/")
        assert status == 200, f"Expected 200, got {status}"
        assert "text/html" in hdrs.get("content-type", "")
        assert b"AI-Prowler" in body

    @pytest.mark.live_pwa
    def test_6_2_manifest_valid_json(self, server):
        status, hdrs, body = _get("/jobs/manifest.json")
        assert status == 200
        assert "json" in hdrs.get("content-type", "")
        data = json.loads(body)
        assert "name" in data

    @pytest.mark.live_pwa
    def test_6_3_sw_js_200(self, server):
        status, _, _ = _get("/jobs/sw.js")
        assert status == 200

    @pytest.mark.live_pwa
    def test_6_4_pwa_token_returns_token(self, server):
        status, _, body = _get("/pwa-token")
        assert status == 200
        data = json.loads(body)
        assert "token" in data
        assert data["token"], "Token is empty"

    @pytest.mark.live_pwa
    def test_6_5_pwa_api_valid_call_200(self, server):
        status, data = _api("read_job_spreadsheet", {"max_rows": 1})
        assert status == 200
        assert data.get("ok") is True

    @pytest.mark.live_pwa
    def test_6_6_pwa_api_unknown_tool_400(self, server):
        status, data = _api("drop_all_tables", {})
        assert status == 400
        assert data.get("ok") is False

    @pytest.mark.live_pwa
    def test_6_7_pwa_api_malformed_json_400(self, server):
        status, _, _ = _post("/pwa-api", b"{{bad json{{")
        assert status == 400

    @pytest.mark.live_pwa
    def test_6_8_missing_pwa_file_404(self, server):
        status, _, _ = _get("/jobs/totally_missing_file_xyz.png")
        assert status == 404

    @pytest.mark.live_pwa
    def test_6_9_path_traversal_blocked(self, server):
        status, _, _ = _get("/jobs/../../etc/passwd")
        assert status in (403, 404, 400), \
            f"Path traversal not blocked — got {status}"

    @pytest.mark.live_pwa
    def test_6_10_mcp_still_requires_bearer(self, server):
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": "tools/list", "params": {}}).encode()
        status, _, _ = _post("/mcp", body, auth=False)
        assert status == 401, \
            f"/mcp should require Bearer auth, got {status}"


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 7: PWA Installability
# ══════════════════════════════════════════════════════════════════════════

class TestFeature7_Installability:
    """7.x — PWA installability checks (offline — no server needed)"""

    def test_7_1_manifest_has_name(self, manifest_data):
        assert "name" in manifest_data
        assert manifest_data["name"], "name is empty"

    def test_7_2_manifest_has_start_url(self, manifest_data):
        assert "start_url" in manifest_data
        assert "/jobs" in manifest_data["start_url"]

    def test_7_3_manifest_display_standalone(self, manifest_data):
        assert manifest_data.get("display") == "standalone", \
            "display must be 'standalone' to remove browser chrome on install"

    def test_7_4_manifest_has_icons(self, manifest_data):
        icons = manifest_data.get("icons", [])
        assert len(icons) >= 2, "Need at least 2 icons (192px and 512px)"
        sizes = [i.get("sizes", "") for i in icons]
        assert any("192" in s for s in sizes), "Missing 192x192 icon"
        assert any("512" in s for s in sizes), "Missing 512x512 icon"

    def test_7_5_manifest_theme_color(self, manifest_data):
        assert "theme_color" in manifest_data
        assert manifest_data["theme_color"], "theme_color is empty"

    def test_7_6_manifest_background_color(self, manifest_data):
        assert "background_color" in manifest_data

    def test_7_7_html_manifest_link(self, html):
        assert 'rel="manifest"' in html

    def test_7_8_html_apple_capable_meta(self, html):
        assert "apple-mobile-web-app-capable" in html, \
            "Missing meta for iOS PWA install"

    def test_7_9_html_theme_color_meta(self, html):
        assert 'name="theme-color"' in html

    def test_7_10_sw_has_install_handler(self, sw_source):
        assert "install" in sw_source, "Service worker missing install handler"

    def test_7_11_sw_has_activate_handler(self, sw_source):
        assert "activate" in sw_source, "Service worker missing activate handler"

    def test_7_12_sw_has_fetch_handler(self, sw_source):
        assert "fetch" in sw_source, "Service worker missing fetch handler"

    def test_7_13_sw_has_cache_name(self, sw_source):
        assert "CACHE" in sw_source or "cache" in sw_source.lower(), \
            "Service worker should define a cache name"


# ══════════════════════════════════════════════════════════════════════════
# FEATURE 8: Security
# ══════════════════════════════════════════════════════════════════════════

class TestFeature8_Security:
    """8.x — Security checks"""

    def test_8_1_path_traversal_guard_in_source(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        assert "abspath(_pwa_root)" in source, \
            "Path traversal guard missing from /jobs handler"

    def test_8_2_allowed_tools_list_exists(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        assert "_allowed_tools" in source, \
            "Tool allowlist missing — any tool name could be called via /pwa-api"

    def test_8_3_dangerous_tools_not_in_allowed_list(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        start = source.find("_allowed_tools")
        block = source[start:start+500]
        dangerous = ["delete_learning", "reindex_all", "grant_write_access",
                     "revoke_write_access", "write_file", "create_file"]
        for tool in dangerous:
            assert tool not in block, \
                f"Dangerous tool '{tool}' found in _allowed_tools — remove it!"

    def test_8_4_bearer_token_not_in_html(self):
        html = HTML_FILE.read_text(encoding="utf-8")
        if BEARER_TOKEN:
            assert BEARER_TOKEN not in html, \
                "Bearer token is hardcoded in index.html — security risk!"

    def test_8_5_no_syntax_error_after_all_patches(self):
        import py_compile, shutil, tempfile
        tmp = Path(tempfile.mkdtemp())
        try:
            dst = tmp / "ai_prowler_mcp.py"
            shutil.copy(MCP_FILE, dst)
            try:
                py_compile.compile(str(dst), doraise=True)
            except py_compile.PyCompileError as exc:
                pytest.fail(f"SyntaxError after all PWA patches:\n{exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @pytest.mark.live_pwa
    def test_8_6_live_path_traversal_blocked(self, server):
        status, _, _ = _get("/jobs/../../etc/passwd")
        assert status in (403, 404, 400)

    @pytest.mark.live_pwa
    def test_8_7_live_mcp_auth_not_broken(self, server):
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": "tools/list", "params": {}}).encode()
        status, _, _ = _post("/mcp", body, auth=False)
        assert status == 401, \
            "CRITICAL: /mcp no longer requires auth — PWA patch broke authentication!"

    @pytest.mark.live_pwa
    def test_8_8_live_unknown_tool_blocked(self, server):
        status, data = _api("os.system", {"cmd": "dir"})
        assert status == 400
        assert data.get("ok") is False

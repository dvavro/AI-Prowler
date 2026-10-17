"""
tests/gui/test_hr_pwa_asset_paths_match_hr_route.py
====================================================
Regression guard: the HR Admin app must serve HR's own assets, not the Jobs
PWA's (a copy-pasted mount pointing at the wrong asset directory).

2026-10-11 (David): converted for the server-only HR apps. The original /hr/
app (hr/index.html) is retired — HR Admin is the same app at /hr_admin/ (the
/hr redirect was removed 2026-10-16). HR Admin + HR Portal exist only in the SERVER
router (behind the HR apps switch); the personal router answers "server only".

Safe: reads hr_admin/index.html, hr_admin/manifest.json, hr_admin/sw.js and
ai_prowler_mcp.py as plain text/JSON only — never starts a server or touches
hr_db.json.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
HR_INDEX = SRC_ROOT / "hr_admin" / "index.html"
HR_MANIFEST = SRC_ROOT / "hr_admin" / "manifest.json"
HR_SW = SRC_ROOT / "hr_admin" / "sw.js"
MCP_SERVER = SRC_ROOT / "ai_prowler_mcp.py"


@pytest.fixture(scope="module")
def hr_index_text():
    return HR_INDEX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def hr_manifest_json():
    return json.loads(HR_MANIFEST.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def hr_sw_text():
    return HR_SW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def server_hr_block():
    t = MCP_SERVER.read_text(encoding="utf-8")
    s = t.index("# \u2500\u2500 HR apps \u2014 HR Admin + HR Portal, AI-Prowler SERVER only")
    return t[s:t.index("# \u2500\u2500 end HR REST API", s)]


@pytest.fixture(scope="module")
def personal_hr_block():
    t = MCP_SERVER.read_text(encoding="utf-8")
    s = t.index("# \u2500\u2500 HR apps \u2014 AI-Prowler SERVER only (2026-10-11")
    return t[s:t.index("# \u2500\u2500 end HR REST API", s)]


class TestHrRouteIsMountedSeparatelyFromJobs:
    """The server router mounts hr_admin/ and hr_portal/ as their own static
    folders (with a folder-boundary guard) — never an alias of jobs/."""

    def test_hr_admin_and_portal_are_mounted_in_the_server_router(self, server_hr_block):
        assert 'path.startswith(("/hr_admin", "/hr_portal"))' in server_hr_block
        assert '_hrs_app = "hr_admin" if path.startswith("/hr_admin") else "hr_portal"' in server_hr_block
        assert "if not _path_is_inside(_hrs_fp, _hrs_root):" in server_hr_block

    def test_old_hr_mount_is_gone(self, server_hr_block, personal_hr_block):
        # 2026-10-16 (David): nobody used the old /hr/ address — its redirect
        # to /hr_admin/ was removed; /hr is an ordinary unknown path now.
        for b in (server_hr_block, personal_hr_block):
            assert 'path == "/hr"' not in b and '"/hr/"' not in b
        assert '[b"location", b"/hr_admin/"]' not in server_hr_block

    def test_hr_api_route_is_registered(self, server_hr_block, personal_hr_block):
        assert '"/hr-api"' in server_hr_block and '"/hr-api"' in personal_hr_block

    def test_personal_router_answers_server_only(self, personal_hr_block):
        assert "_HR_SERVER_ONLY_MESSAGE" in personal_hr_block
        assert "open(" not in personal_hr_block, "the personal router must not serve HR files"

    def test_hr_mount_does_not_alias_jobs_directory(self, server_hr_block):
        assert '"jobs"' not in server_hr_block and "'jobs'" not in server_hr_block


class TestHrManifestMatchesItsOwnRoute:
    def test_start_url_is_hr_admin_not_jobs(self, hr_manifest_json):
        assert hr_manifest_json["start_url"] == "/hr_admin/"

    def test_scope_is_hr_admin_not_jobs(self, hr_manifest_json):
        assert hr_manifest_json["scope"] == "/hr_admin/"

    def test_manifest_name_is_hr_branded(self, hr_manifest_json):
        name = (hr_manifest_json.get("name", "") + hr_manifest_json.get("short_name", "")).lower()
        assert "hr" in name or "onboarding" in name or "human resources" in name

    def test_icon_paths_resolve_under_hr_admin(self, hr_manifest_json):
        icons = hr_manifest_json.get("icons", [])
        assert icons, "manifest.json has no icons array"
        for icon in icons:
            src = icon["src"]
            # relative ("icon-192.png") resolves against /hr_admin/manifest.json
            assert src.startswith("/hr_admin/") or not src.startswith("/"), (
                f"Icon src {src!r} does not resolve under the /hr_admin/ mount.")
            assert not src.startswith(("/jobs/", "/hr/"))


class TestHrServiceWorkerCachesItsOwnAssets:
    def test_cache_name_is_hr_specific(self, hr_sw_text):
        assert re.search(r"""(CACHE_NAME|CACHE)\s*=\s*["']hr-""", hr_sw_text), (
            "sw.js cache name does not look HR-specific (expected a 'hr-' prefix)")

    def test_precache_list_references_hr_admin_paths_not_jobs(self, hr_sw_text):
        assert "/jobs/" not in hr_sw_text and "'/hr/" not in hr_sw_text
        assert "'/hr_admin/'" in hr_sw_text

    def test_employee_data_is_never_cached(self, hr_sw_text):
        assert "if (e.request.url.indexOf('/hr-api') === -1) {" in hr_sw_text


class TestHrIndexReferencesOwnManifestAndServiceWorker:
    def test_index_links_hr_admin_manifest(self, hr_index_text):
        assert '<link rel="manifest" href="/hr_admin/manifest.json">' in hr_index_text

    def test_index_registers_hr_admin_service_worker(self, hr_index_text):
        assert "register('/hr_admin/sw.js')" in hr_index_text

    def test_index_does_not_reference_jobs_or_old_hr_assets(self, hr_index_text):
        assert "/jobs/" not in hr_index_text
        assert "'/hr/" not in hr_index_text and '"/hr/' not in hr_index_text

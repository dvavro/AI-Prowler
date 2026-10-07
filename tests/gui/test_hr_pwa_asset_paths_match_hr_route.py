"""
tests/gui/test_hr_pwa_asset_paths_match_hr_route.py
====================================================
Regression guard: the /hr/ PWA route must serve HR's own assets, not the
Jobs PWA's. Mirrors test_pwa_asset_paths_match_jobs_route.py's intent —
same failure mode (a copy-pasted mount pointing at the wrong asset
directory), different mount point.

ADAPTATION FROM IMPLEMENTATION PLAN v2.1 SECTION 13.2.1
--------------------------------------------------------
The plan's code stub assumed the mount check would be a literal '"/hr/"'
string match. The actual shipped ai_prowler_mcp.py checks
`path.startswith("/hr")` (no trailing slash, so it also matches a bare
/hr with nothing after it) in both the personal-mode and server-mode
routers. This file asserts against that real pattern rather than the
stub's assumed literal, per the test philosophy in Section 13.0:
assertions run against real shipped text, not a hand-written stand-in.

Safe: opens hr/index.html, hr/manifest.json, hr/sw.js, and
ai_prowler_mcp.py as plain text/JSON only. Never imports ai_prowler_mcp.py
as a module, never writes anywhere, never starts a server or touches
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
HR_INDEX = SRC_ROOT / "hr" / "index.html"
HR_MANIFEST = SRC_ROOT / "hr" / "manifest.json"
HR_SW = SRC_ROOT / "hr" / "sw.js"
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
def mcp_server_text():
    return MCP_SERVER.read_text(encoding="utf-8")


class TestHrRouteIsMountedSeparatelyFromJobs:
    """The MCP server must register /hr as its own static mount in BOTH the
    personal-mode and server-mode ASGI routers, not an alias of /jobs."""

    def test_hr_mount_point_is_registered(self, mcp_server_text):
        matches = re.findall(r'path\.startswith\(["\']\/hr["\']\)', mcp_server_text)
        assert len(matches) >= 2, (
            "Expected the /hr static-file guard "
            '(`path.startswith("/hr")`) in both the personal-mode and '
            "server-mode routers — found "
            f"{len(matches)} occurrence(s) in ai_prowler_mcp.py."
        )

    def test_hr_api_route_is_registered(self, mcp_server_text):
        matches = re.findall(r'path\.startswith\(["\']\/hr-api["\']\)', mcp_server_text)
        assert len(matches) >= 2, (
            '/hr-api REST route guard (`path.startswith("/hr-api")`) '
            f"expected in both routers — found {len(matches)}."
        )

    def test_hr_mount_does_not_alias_jobs_directory(self, mcp_server_text):
        for m in re.finditer(r'path\.startswith\(["\']\/hr["\']\)', mcp_server_text):
            block = mcp_server_text[m.start(): m.start() + 400]
            assert '"jobs"' not in block and "'jobs'" not in block, (
                "/hr route block appears to reference the jobs/ directory "
                "— possible copy-paste aliasing bug."
            )


class TestHrManifestMatchesItsOwnRoute:
    def test_start_url_is_hr_not_jobs(self, hr_manifest_json):
        assert hr_manifest_json["start_url"].strip("/").startswith("hr")

    def test_scope_is_hr_not_jobs(self, hr_manifest_json):
        assert hr_manifest_json["scope"].strip("/").startswith("hr")

    def test_manifest_name_is_hr_branded(self, hr_manifest_json):
        name = (hr_manifest_json.get("name", "") + hr_manifest_json.get("short_name", "")).lower()
        assert "hr" in name or "onboarding" in name or "human resources" in name

    def test_icon_paths_use_hr_prefix_not_jobs(self, hr_manifest_json):
        icons = hr_manifest_json.get("icons", [])
        assert icons, "manifest.json has no icons array"
        for icon in icons:
            assert icon["src"].startswith("/hr/"), (
                f"Icon src {icon['src']!r} does not match the /hr/ mount."
            )
            assert not icon["src"].startswith("/jobs/")


class TestHrServiceWorkerCachesItsOwnAssets:
    def test_cache_name_is_hr_specific(self, hr_sw_text):
        assert re.search(r'CACHE_NAME\s*=\s*["\']hr-', hr_sw_text), (
            "sw.js CACHE_NAME does not look HR-specific (expected a 'hr-' prefix)"
        )

    def test_precache_list_references_hr_paths_not_jobs(self, hr_sw_text):
        assert "/jobs/" not in hr_sw_text


class TestHrIndexReferencesOwnManifestAndServiceWorker:
    def test_index_links_hr_manifest(self, hr_index_text):
        assert "/hr/manifest.json" in hr_index_text

    def test_index_registers_hr_service_worker(self, hr_index_text):
        assert "register('/hr/sw.js')" in hr_index_text or 'register("/hr/sw.js")' in hr_index_text

    def test_index_does_not_reference_jobs_assets(self, hr_index_text):
        assert "/jobs/" not in hr_index_text

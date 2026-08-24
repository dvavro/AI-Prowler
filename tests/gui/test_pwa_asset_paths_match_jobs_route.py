"""
tests/gui/test_pwa_asset_paths_match_jobs_route.py
=====================================================
Regression guard for a real, previously-undetected bug: the favicon,
apple-touch-icon, manifest link, service worker registration, and the
manifest's own icon entries all referenced "/pwa/..." paths — but the
backend's actual static file server (ai_prowler_mcp.py) is mounted at
"/jobs/*", not "/pwa/*" (confirmed directly: `if path.startswith("/jobs")`).

This meant index.html itself always loaded fine (the browser navigates
directly to /jobs/, which correctly hits that handler and falls back to
index.html) — but every asset REFERENCED FROM WITHIN that HTML using the
wrong "/pwa/" prefix silently 404'd, which is exactly why the browser
tab always fell back to the generic globe icon regardless of what icon
files existed on disk or how thoroughly they'd been deployed. Neither
personal nor server mode was ever actually serving a working favicon
before this fix, in any prior session.

sw.js already correctly used /jobs/ paths and needed no change — only
index.html and manifest.json had the mismatch.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"
MANIFEST_FILE = SRC_ROOT / "jobs" / "manifest.json"
SW_FILE = SRC_ROOT / "jobs" / "sw.js"
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


@pytest.fixture(scope="module")
def pwa_source():
    return PWA_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def manifest_data():
    return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def sw_source():
    return SW_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mcp_source():
    return MCP_FILE.read_text(encoding="utf-8")


class TestStaticServerActuallyMountedAtJobs:
    """Confirms the assumption this whole test file depends on — that
    the backend's PWA static file server really is mounted at /jobs,
    not /pwa. If this ever changes, every other test here needs
    revisiting too."""

    def test_static_server_checks_jobs_prefix(self, mcp_source):
        assert 'if path.startswith("/jobs")' in mcp_source


class TestIndexHtmlAssetPathsMatchJobsRoute:
    def test_no_pwa_prefixed_asset_references_remain(self, pwa_source):
        assert '"/pwa/' not in pwa_source
        assert "'/pwa/" not in pwa_source

    def test_manifest_link_uses_jobs_prefix(self, pwa_source):
        assert '<link rel="manifest" href="/jobs/manifest.json">' in pwa_source

    def test_favicon_link_uses_jobs_prefix(self, pwa_source):
        assert '<link rel="icon" type="image/png" sizes="192x192" href="/jobs/icon-192.png">' in pwa_source

    def test_apple_touch_icon_uses_jobs_prefix(self, pwa_source):
        assert '<link rel="apple-touch-icon" href="/jobs/icon-192.png">' in pwa_source

    def test_service_worker_registration_uses_jobs_prefix(self, pwa_source):
        assert "navigator.serviceWorker.register('/jobs/sw.js')" in pwa_source


class TestManifestIconPathsMatchJobsRoute:
    def test_all_icon_src_entries_use_jobs_prefix(self, manifest_data):
        assert len(manifest_data["icons"]) >= 1
        for icon in manifest_data["icons"]:
            assert icon["src"].startswith("/jobs/"), (
                f"Icon src {icon['src']!r} does not match the actual static "
                f"file server's mount point (/jobs/*, not /pwa/*)."
            )

    def test_no_pwa_prefixed_icon_src_remains(self, manifest_data):
        for icon in manifest_data["icons"]:
            assert not icon["src"].startswith("/pwa/")


class TestServiceWorkerOfflineAssetsAlreadyCorrect:
    """sw.js already used the right prefix before this fix — confirms it
    stays that way rather than silently regressing alongside the other
    two files if someone touches it later."""

    def test_offline_assets_use_jobs_prefix(self, sw_source):
        assert "'/jobs/'" in sw_source
        assert "'/jobs/index.html'" in sw_source

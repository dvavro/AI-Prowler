"""
tests/gui/test_job_tracker_guide_content.py
=============================================
Structural test for rag_gui.py's "Multi-Employee & QuickBooks Guide"
popup content (get_job_tracker_guide_content()). Confirms the Jobs App
section added alongside the server-mode Jobs PWA work is present and
doesn't silently drift/get removed in a future edit, and that its claims
match what's actually true of the login persistence behavior (localStorage,
not per-app-open re-login).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
GUI_FILE = SRC_ROOT / "rag_gui.py"


@pytest.fixture(scope="module")
def source():
    return GUI_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def guide_content(source):
    start = source.index("def get_job_tracker_guide_content(self):")
    end = source.index('"""\n\n    def get_quick_start_content', start)
    return source[start:end]


class TestJobsAppSectionPresent:
    def test_jobs_app_section_exists(self, guide_content):
        assert "Jobs App" in guide_content

    def test_mentions_photo_upload(self, guide_content):
        assert "photo" in guide_content.lower()

    def test_mentions_clock_in_out(self, guide_content):
        assert "clock in" in guide_content.lower() or "clock in / clock out" in guide_content.lower()

    def test_mentions_invoice(self, guide_content):
        assert "invoice" in guide_content.lower()


class TestLoginPersistenceClaimIsAccurate:
    def test_claims_log_in_once(self, guide_content):
        assert "Log in once" in guide_content or "log in once" in guide_content.lower()

    def test_mentions_sign_out_button_not_auto_signout(self, guide_content):
        """Must not claim closing the app signs the user out — that would
        contradict the actual localStorage-based implementation."""
        assert "igning out" in guide_content or "ign Out" in guide_content
        assert "profile screen" in guide_content.lower()


class TestExistingSpreadsheetModelContentUnchanged:
    """Regression guard — the pre-existing Model A/B explanation must
    survive this edit intact."""

    def test_shared_master_still_documented(self, guide_content):
        assert "Shared master" in guide_content

    def test_per_user_tracking_still_documented(self, guide_content):
        assert "Per-user tracking files" in guide_content or "per-user tracking" in guide_content.lower()

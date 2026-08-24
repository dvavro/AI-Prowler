"""
tests/gui/test_pwa_multiday_multicrew_and_sorting.py
=======================================================
Structural tests for three related Jobs PWA changes:

  1. Today-first / Upcoming-below job list grouping, with completed or
     cancelled jobs hidden entirely rather than shown deprioritized.
  2. Multi-day job support — an End Date badge shown on job cards and in
     the detail modal when a job's End Date differs from its Service
     Date (backend support: ai_prowler_mcp.py's End Date column range
     filtering — see tests/unit/test_contractor_tools.py).
  3. Multiple crew members per job — the Crew / Technician field can now
     hold a comma-separated list; access-control matching for this lives
     entirely server-side (_crew_name_in_cell), so the PWA itself needs
     no special handling beyond displaying whatever string comes back.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"


@pytest.fixture(scope="module")
def pwa_source():
    return PWA_FILE.read_text(encoding="utf-8")


class TestLoadJobsFetchesBroaderRange:
    """loadJobs() previously only fetched filter_date='today', so future
    jobs could never appear in a "today first, upcoming below" list no
    matter what the frontend did with them."""

    def test_no_longer_uses_filter_date_today(self, pwa_source):
        idx = pwa_source.index("async function loadJobs()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "filter_date:'today'" not in body
        assert "filter_date: 'today'" not in body

    def test_fetches_without_date_filter(self, pwa_source):
        idx = pwa_source.index("async function loadJobs()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        # Allow either spacing style around the argument separator — the
        # important thing is no filter_date, and max_rows:200 is present.
        assert ("mcpCall('read_job_spreadsheet',{max_rows:200})" in body or
                "mcpCall('read_job_spreadsheet', {max_rows:200})" in body)

    def test_stat_count_excludes_completed_jobs(self, pwa_source):
        idx = pwa_source.index("async function loadJobs()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "isJobComplete" in body


class TestIsJobComplete:
    def test_function_exists(self, pwa_source):
        assert "function isJobComplete(j)" in pwa_source

    def test_checks_completion_via_exact_match(self, pwa_source):
        """Updated for the exact-match fix — was substring matching
        (s.includes('complete')/('cancelled')), now exact equality
        against the controlled vocabulary. See
        test_pwa_status_vocabulary_and_edit_form.py for the full
        regression coverage of that specific fix."""
        idx = pwa_source.index("function isJobComplete(j)")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "'complete'" in body
        assert "'cancelled'" in body


class TestParseJobDate:
    def test_function_exists(self, pwa_source):
        assert "function parseJobDate(s)" in pwa_source

    def test_handles_iso_format(self, pwa_source):
        idx = pwa_source.index("function parseJobDate(s)")
        nearby = pwa_source[idx:idx + 500]
        assert r"(\d{4})-(\d{1,2})-(\d{1,2})" in nearby

    def test_handles_us_slash_format(self, pwa_source):
        idx = pwa_source.index("function parseJobDate(s)")
        nearby = pwa_source[idx:idx + 500]
        assert r"(\d{1,2})\/(\d{1,2})\/(\d{4})" in nearby

    def test_blank_input_returns_null_not_throws(self, pwa_source):
        idx = pwa_source.index("function parseJobDate(s)")
        nearby = pwa_source[idx:idx + 100]
        assert "if (!s) return null;" in nearby


class TestRenderJobsListGrouping:
    def test_completed_jobs_filtered_out_before_grouping(self, pwa_source):
        idx = pwa_source.index("function renderJobsList()")
        nearby = pwa_source[idx:idx + 600]
        assert "state.jobs.filter(j=>!isJobComplete(j))" in nearby

    def test_today_section_label_present(self, pwa_source):
        idx = pwa_source.index("function renderJobsList()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "jobs-section-label" in body
        assert ">Today<" in body

    def test_upcoming_section_label_present(self, pwa_source):
        idx = pwa_source.index("function renderJobsList()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert ">Upcoming<" in body

    def test_today_section_rendered_before_upcoming_section(self, pwa_source):
        idx = pwa_source.index("function renderJobsList()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        today_pos = body.index("todayGroup.map")
        upcoming_pos = body.index("upcomingGroup.map")
        assert today_pos < upcoming_pos

    def test_jobs_sorted_chronologically(self, pwa_source):
        idx = pwa_source.index("function renderJobsList()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "withDates.sort(" in body

    def test_unparseable_dates_do_not_crash_sort(self, pwa_source):
        """A job with no parseable date must sort predictably (last),
        not throw when compared against a null date."""
        idx = pwa_source.index("function renderJobsList()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "if (!a.d && !b.d) return 0;" in body
        assert "if (!a.d) return 1;" in body

    def test_overdue_open_jobs_fold_into_today_not_hidden(self, pwa_source):
        """A job whose date has passed but isn't marked complete must
        still be visible — it lands in the Today group rather than
        silently disappearing or requiring a third 'overdue' section
        nobody asked for."""
        idx = pwa_source.index("function renderJobsList()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "d <= todayMidnight" in body


class TestJobCardHtmlEndDateBadge:
    def test_function_exists(self, pwa_source):
        assert "function jobCardHtml(j)" in pwa_source

    def test_end_date_badge_only_shown_when_it_differs_from_start(self, pwa_source):
        idx = pwa_source.index("function jobCardHtml(j)")
        nearby = pwa_source[idx:idx + 400]
        assert "j.endDate && j.endDate !== j.date" in nearby

    def test_render_jobs_list_uses_shared_card_renderer(self, pwa_source):
        """Regression guard — Today and Upcoming sections must render
        cards through the same function, not two copies that could
        drift out of sync."""
        idx = pwa_source.index("function renderJobsList()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert body.count("jobCardHtml") == 2  # once for each group


class TestParseJobsIncludesEndDate:
    def test_end_date_field_parsed(self, pwa_source):
        # Signature may have additional parameters after `raw` (e.g.
        # taxRatePercent added later), so search by prefix only.
        idx = pwa_source.index("function parseJobs(raw")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "endDate:g('End Date')" in body


class TestModalShowsDateRange:
    def test_modal_date_row_includes_end_date_when_present(self, pwa_source):
        idx = pwa_source.index("function openModal(id)")
        nearby = pwa_source[idx:idx + 1200]
        assert "j.endDate&&j.endDate!==j.date" in nearby


class TestSectionLabelCssExists:
    def test_jobs_section_label_class_defined(self, pwa_source):
        assert ".jobs-section-label{" in pwa_source

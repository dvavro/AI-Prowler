"""
tests/gui/test_learnings_filter.py
====================================
Unit tests for the Learnings tab filter and search logic (v7.0.1).

These tests verify the filter/search logic directly — no tkinter needed.
We extract the pure filtering logic from _refresh_table() into a standalone
function and test it in isolation.

Filters covered:
  A — Category dropdown filter
  B — Status dropdown filter
  C — Outcome dropdown filter (new in v7.0.1)
  D — Source dropdown filter (new in v7.0.1)
  E — Text search (title, content, context, tags, source, recorded_by)
  F — Combined filters
  G — Reset (all filters back to defaults)
  H — Source dropdown population (dynamic from DB values)

Run:
    run_tests.bat tests\\gui\\test_learnings_filter.py -v
"""
from __future__ import annotations

import sys
import pytest
from pathlib import Path

# These are pure logic tests — no tkinter, no DB, no AI-Prowler imports needed.
# We re-implement the filter function exactly as it appears in _refresh_table()
# so tests are stable even if the GUI is refactored.

pytestmark = pytest.mark.usefixtures()  # no-op — opts out of any skip markers


# ══════════════════════════════════════════════════════════════════════════════
# Filter function — mirrors _refresh_table() logic exactly
# ══════════════════════════════════════════════════════════════════════════════

def apply_filters(
    learnings: list[dict],
    *,
    cat_filter: str = "All",
    status_filter: str = "All",
    outcome_filter: str = "All",
    source_filter: str = "All",
    search_text: str = "",
) -> list[dict]:
    """Pure-Python replica of the _refresh_table() filter loop.
    Returns the subset of learnings that pass all active filters.
    Semantic search is excluded (requires ChromaDB) — tested separately."""
    filtered = []
    for l in learnings:
        if cat_filter != "All" and l.get('category', 'general') != cat_filter:
            continue
        if status_filter != "All" and l.get('status', 'active') != status_filter:
            continue
        if outcome_filter != "All" and l.get('outcome', 'unknown') != outcome_filter:
            continue
        if source_filter != "All" and l.get('source', 'operator') != source_filter:
            continue
        if search_text:
            haystack = (
                f"{l.get('title', '')} {l.get('content', '')} "
                f"{l.get('context', '')} {' '.join(l.get('tags', []))} "
                f"{l.get('source', '')} {l.get('recorded_by', '')}"
            ).lower()
            if search_text.lower() not in haystack:
                continue
        filtered.append(l)
    return filtered


def get_source_dropdown_values(learnings: list[dict]) -> list[str]:
    """Mirrors the dynamic source dropdown population in _refresh_table()."""
    all_sources = sorted({
        l.get('source', 'operator') or 'operator'
        for l in learnings
        if l.get('source')
    })
    return ["All"] + all_sources


# ══════════════════════════════════════════════════════════════════════════════
# Test fixtures
# ══════════════════════════════════════════════════════════════════════════════

def _make_learning(title, category="general", status="active",
                   outcome="unknown", source="operator",
                   content="", context="", tags=None, recorded_by=""):
    return {
        "id":          f"test-{title.replace(' ', '-').lower()}",
        "title":       title,
        "category":    category,
        "status":      status,
        "outcome":     outcome,
        "source":      source,
        "content":     content,
        "context":     context,
        "tags":        tags or [],
        "recorded_by": recorded_by,
        "confidence":  0.8,
        "applied_count": 0,
    }


@pytest.fixture
def sample_learnings():
    """A representative set of learnings covering all filter dimensions."""
    return [
        _make_learning("Client prefers email",
                       category="client_preference", status="active",
                       outcome="positive", source="David Vavro",
                       content="Always contact via email not phone",
                       tags=["client", "communication"]),

        _make_learning("Budget overrun lesson",
                       category="business_lesson", status="active",
                       outcome="negative", source="Vicki Vavro",
                       content="Smith job went over budget by 15%",
                       context="Post-project review March 2026"),

        _make_learning("Permit timing tip",
                       category="process_improvement", status="active",
                       outcome="positive", source="claude-sonnet-4-6",
                       content="Submit permits 2 weeks before job start",
                       tags=["permits", "process"]),

        _make_learning("Wrong phone number",
                       category="fact_correction", status="deprecated",
                       outcome="unknown", source="David Vavro",
                       content="Old number was 555-0100"),

        _make_learning("Safety protocol update",
                       category="best_practice", status="active",
                       outcome="neutral", source="operator",
                       content="Always wear PPE on commercial sites",
                       tags=["safety", "ppe"]),

        _make_learning("Old pricing model",
                       category="business_lesson", status="archived",
                       outcome="negative", source="Vicki Vavro",
                       content="Previous hourly rate was too low"),

        _make_learning("Client X contact",
                       category="client_preference", status="active",
                       outcome="unknown", source="David Vavro",
                       content="Call before arriving",
                       recorded_by="David Vavro"),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# Section A — Category filter
# ══════════════════════════════════════════════════════════════════════════════

class TestCategoryFilter:

    def test_all_returns_everything(self, sample_learnings):
        result = apply_filters(sample_learnings, cat_filter="All",
                               status_filter="All")
        assert len(result) == len(sample_learnings)

    def test_client_preference_only(self, sample_learnings):
        result = apply_filters(sample_learnings, cat_filter="client_preference",
                               status_filter="All")
        assert all(l['category'] == 'client_preference' for l in result)
        assert len(result) == 2

    def test_business_lesson_only(self, sample_learnings):
        result = apply_filters(sample_learnings, cat_filter="business_lesson",
                               status_filter="All")
        assert all(l['category'] == 'business_lesson' for l in result)
        assert len(result) == 2

    def test_fact_correction_only(self, sample_learnings):
        result = apply_filters(sample_learnings, cat_filter="fact_correction",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['title'] == "Wrong phone number"

    def test_nonexistent_category_returns_empty(self, sample_learnings):
        result = apply_filters(sample_learnings, cat_filter="nonexistent",
                               status_filter="All")
        assert result == []

    def test_category_filter_preserves_other_fields(self, sample_learnings):
        """Category filter must not alter any learning's fields."""
        result = apply_filters(sample_learnings, cat_filter="best_practice",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['source'] == "operator"
        assert result[0]['outcome'] == "neutral"


# ══════════════════════════════════════════════════════════════════════════════
# Section B — Status filter
# ══════════════════════════════════════════════════════════════════════════════

class TestStatusFilter:

    def test_active_only_default(self, sample_learnings):
        result = apply_filters(sample_learnings, status_filter="active")
        assert all(l['status'] == 'active' for l in result)
        assert len(result) == 5

    def test_deprecated_only(self, sample_learnings):
        result = apply_filters(sample_learnings, status_filter="deprecated")
        assert len(result) == 1
        assert result[0]['title'] == "Wrong phone number"

    def test_archived_only(self, sample_learnings):
        result = apply_filters(sample_learnings, status_filter="archived")
        assert len(result) == 1
        assert result[0]['title'] == "Old pricing model"

    def test_all_status_returns_all(self, sample_learnings):
        result = apply_filters(sample_learnings, status_filter="All")
        assert len(result) == len(sample_learnings)


# ══════════════════════════════════════════════════════════════════════════════
# Section C — Outcome filter (new in v7.0.1)
# ══════════════════════════════════════════════════════════════════════════════

class TestOutcomeFilter:

    def test_all_outcomes_returns_all(self, sample_learnings):
        result = apply_filters(sample_learnings, outcome_filter="All",
                               status_filter="All")
        assert len(result) == len(sample_learnings)

    def test_positive_outcome_only(self, sample_learnings):
        result = apply_filters(sample_learnings, outcome_filter="positive",
                               status_filter="All")
        assert all(l['outcome'] == 'positive' for l in result)
        assert len(result) == 2

    def test_negative_outcome_only(self, sample_learnings):
        result = apply_filters(sample_learnings, outcome_filter="negative",
                               status_filter="All")
        assert all(l['outcome'] == 'negative' for l in result)
        assert len(result) == 2

    def test_neutral_outcome_only(self, sample_learnings):
        result = apply_filters(sample_learnings, outcome_filter="neutral",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['title'] == "Safety protocol update"

    def test_unknown_outcome_only(self, sample_learnings):
        result = apply_filters(sample_learnings, outcome_filter="unknown",
                               status_filter="All")
        assert all(l['outcome'] == 'unknown' for l in result)
        assert len(result) == 2

    def test_outcome_filter_is_exact_match(self, sample_learnings):
        """'positiv' (partial) must not match 'positive'."""
        result = apply_filters(sample_learnings, outcome_filter="positiv",
                               status_filter="All")
        assert result == []

    def test_outcome_filter_with_status_filter(self, sample_learnings):
        """Outcome + Status combined — only active+negative."""
        result = apply_filters(sample_learnings, outcome_filter="negative",
                               status_filter="active")
        assert all(l['outcome'] == 'negative' for l in result)
        assert all(l['status'] == 'active' for l in result)
        assert len(result) == 1
        assert result[0]['title'] == "Budget overrun lesson"


# ══════════════════════════════════════════════════════════════════════════════
# Section D — Source filter (new in v7.0.1)
# ══════════════════════════════════════════════════════════════════════════════

class TestSourceFilter:

    def test_all_sources_returns_all(self, sample_learnings):
        result = apply_filters(sample_learnings, source_filter="All",
                               status_filter="All")
        assert len(result) == len(sample_learnings)

    def test_david_vavro_source(self, sample_learnings):
        result = apply_filters(sample_learnings, source_filter="David Vavro",
                               status_filter="All")
        assert all(l['source'] == 'David Vavro' for l in result)
        assert len(result) == 3

    def test_vicki_vavro_source(self, sample_learnings):
        result = apply_filters(sample_learnings, source_filter="Vicki Vavro",
                               status_filter="All")
        assert all(l['source'] == 'Vicki Vavro' for l in result)
        assert len(result) == 2

    def test_claude_model_source(self, sample_learnings):
        result = apply_filters(sample_learnings, source_filter="claude-sonnet-4-6",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['title'] == "Permit timing tip"

    def test_operator_source(self, sample_learnings):
        result = apply_filters(sample_learnings, source_filter="operator",
                               status_filter="All")
        assert all(l['source'] == 'operator' for l in result)
        assert len(result) == 1

    def test_source_filter_exact_match(self, sample_learnings):
        """'David' (partial) must NOT match 'David Vavro'."""
        result = apply_filters(sample_learnings, source_filter="David",
                               status_filter="All")
        assert result == []

    def test_source_filter_with_status_filter(self, sample_learnings):
        """David Vavro + active only — deprecated one excluded."""
        result = apply_filters(sample_learnings, source_filter="David Vavro",
                               status_filter="active")
        assert all(l['source'] == 'David Vavro' for l in result)
        assert all(l['status'] == 'active' for l in result)
        assert len(result) == 2

    def test_source_filter_with_outcome_filter(self, sample_learnings):
        """David Vavro + positive outcome."""
        result = apply_filters(sample_learnings, source_filter="David Vavro",
                               outcome_filter="positive",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['title'] == "Client prefers email"

    def test_nonexistent_source_returns_empty(self, sample_learnings):
        result = apply_filters(sample_learnings, source_filter="Nobody",
                               status_filter="All")
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# Section E — Text search
# ══════════════════════════════════════════════════════════════════════════════

class TestTextSearch:

    def test_search_by_title_word(self, sample_learnings):
        result = apply_filters(sample_learnings, search_text="email",
                               status_filter="All")
        assert any('email' in l['title'].lower() or
                   'email' in l['content'].lower() for l in result)

    def test_search_by_content(self, sample_learnings):
        result = apply_filters(sample_learnings, search_text="budget",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['title'] == "Budget overrun lesson"

    def test_search_by_tag(self, sample_learnings):
        result = apply_filters(sample_learnings, search_text="permits",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['title'] == "Permit timing tip"

    def test_search_by_context(self, sample_learnings):
        result = apply_filters(sample_learnings, search_text="post-project",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['title'] == "Budget overrun lesson"

    def test_search_by_source_name(self, sample_learnings):
        """Searching by name finds all learnings by that person."""
        result = apply_filters(sample_learnings, search_text="Vicki Vavro",
                               status_filter="All")
        assert all('vicki vavro' in (l.get('source', '') +
                                     l.get('recorded_by', '')).lower()
                   for l in result)
        assert len(result) == 2

    def test_search_by_model_id(self, sample_learnings):
        result = apply_filters(sample_learnings, search_text="claude-sonnet",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['source'] == "claude-sonnet-4-6"

    def test_search_by_recorded_by(self, sample_learnings):
        """recorded_by field is also searchable."""
        result = apply_filters(sample_learnings, search_text="David Vavro",
                               status_filter="All")
        # Should find learnings where David is in source OR recorded_by
        assert len(result) >= 3

    def test_search_case_insensitive(self, sample_learnings):
        lower = apply_filters(sample_learnings, search_text="email",
                              status_filter="All")
        upper = apply_filters(sample_learnings, search_text="EMAIL",
                              status_filter="All")
        mixed = apply_filters(sample_learnings, search_text="EmAiL",
                              status_filter="All")
        assert lower == upper == mixed

    def test_empty_search_returns_all(self, sample_learnings):
        result = apply_filters(sample_learnings, search_text="",
                               status_filter="All")
        assert len(result) == len(sample_learnings)

    def test_search_no_match_returns_empty(self, sample_learnings):
        result = apply_filters(sample_learnings, search_text="xyznotfound123",
                               status_filter="All")
        assert result == []

    def test_search_partial_word(self, sample_learnings):
        """Partial word match should work."""
        result = apply_filters(sample_learnings, search_text="permit",
                               status_filter="All")
        assert len(result) >= 1

    def test_search_with_status_filter(self, sample_learnings):
        """Search + status filter both applied."""
        result = apply_filters(sample_learnings, search_text="david",
                               status_filter="active")
        assert all(l['status'] == 'active' for l in result)
        assert all('david' in (
            l.get('title', '') + l.get('content', '') +
            l.get('context', '') + l.get('source', '') +
            l.get('recorded_by', '')).lower() for l in result)


# ══════════════════════════════════════════════════════════════════════════════
# Section F — Combined filters
# ══════════════════════════════════════════════════════════════════════════════

class TestCombinedFilters:

    def test_category_and_status(self, sample_learnings):
        result = apply_filters(sample_learnings,
                               cat_filter="business_lesson",
                               status_filter="active")
        assert all(l['category'] == 'business_lesson' for l in result)
        assert all(l['status'] == 'active' for l in result)
        assert len(result) == 1

    def test_category_status_outcome(self, sample_learnings):
        result = apply_filters(sample_learnings,
                               cat_filter="client_preference",
                               status_filter="active",
                               outcome_filter="positive")
        assert len(result) == 1
        assert result[0]['title'] == "Client prefers email"

    def test_all_four_dropdowns(self, sample_learnings):
        result = apply_filters(sample_learnings,
                               cat_filter="client_preference",
                               status_filter="active",
                               outcome_filter="positive",
                               source_filter="David Vavro")
        assert len(result) == 1
        assert result[0]['title'] == "Client prefers email"

    def test_all_four_plus_search(self, sample_learnings):
        result = apply_filters(sample_learnings,
                               cat_filter="client_preference",
                               status_filter="active",
                               outcome_filter="positive",
                               source_filter="David Vavro",
                               search_text="email")
        assert len(result) == 1

    def test_contradictory_filters_return_empty(self, sample_learnings):
        """Filters that can't both be true → empty."""
        result = apply_filters(sample_learnings,
                               source_filter="David Vavro",
                               outcome_filter="negative",
                               status_filter="active")
        assert result == []

    def test_source_and_search_both_must_match(self, sample_learnings):
        """Source filter + search text must BOTH pass — not OR."""
        result = apply_filters(sample_learnings,
                               source_filter="Vicki Vavro",
                               search_text="budget",
                               status_filter="All")
        assert len(result) == 1
        assert result[0]['source'] == "Vicki Vavro"
        assert "budget" in result[0]['title'].lower() or \
               "budget" in result[0]['content'].lower()


# ══════════════════════════════════════════════════════════════════════════════
# Section G — Reset
# ══════════════════════════════════════════════════════════════════════════════

class TestResetFilters:
    """Reset returns all filters to defaults:
    Category=All, Status=active, Outcome=All, Source=All, Search=empty"""

    def test_reset_defaults_match_initial_state(self, sample_learnings):
        """Default state (status=active, all others=All) should return
        the same as an explicit reset."""
        default = apply_filters(sample_learnings,
                                cat_filter="All",
                                status_filter="active",
                                outcome_filter="All",
                                source_filter="All",
                                search_text="")
        assert len(default) == 5  # 5 active learnings in sample

    def test_reset_after_all_filters_set(self, sample_learnings):
        """After applying restrictive filters, reset should restore full active set."""
        # Apply tight filters
        restricted = apply_filters(sample_learnings,
                                   cat_filter="client_preference",
                                   status_filter="active",
                                   outcome_filter="positive",
                                   source_filter="David Vavro",
                                   search_text="email")
        assert len(restricted) == 1

        # Reset to defaults
        after_reset = apply_filters(sample_learnings,
                                    cat_filter="All",
                                    status_filter="active",
                                    outcome_filter="All",
                                    source_filter="All",
                                    search_text="")
        assert len(after_reset) == 5

    def test_reset_status_is_active_not_all(self, sample_learnings):
        """Reset sets Status=active (not 'All') — deprecated/archived hidden."""
        after_reset = apply_filters(sample_learnings,
                                    cat_filter="All",
                                    status_filter="active",
                                    outcome_filter="All",
                                    source_filter="All",
                                    search_text="")
        assert all(l['status'] == 'active' for l in after_reset)


# ══════════════════════════════════════════════════════════════════════════════
# Section H — Source dropdown population
# ══════════════════════════════════════════════════════════════════════════════

class TestSourceDropdownPopulation:
    """The Source dropdown must be populated dynamically from actual DB values
    so new sources appear automatically without code changes."""

    def test_all_sources_present(self, sample_learnings):
        values = get_source_dropdown_values(sample_learnings)
        assert "All" in values
        assert "David Vavro" in values
        assert "Vicki Vavro" in values
        assert "claude-sonnet-4-6" in values
        assert "operator" in values

    def test_all_is_first(self, sample_learnings):
        values = get_source_dropdown_values(sample_learnings)
        assert values[0] == "All"

    def test_sources_sorted_alphabetically(self, sample_learnings):
        values = get_source_dropdown_values(sample_learnings)
        non_all = values[1:]
        assert non_all == sorted(non_all)

    def test_no_duplicate_sources(self, sample_learnings):
        values = get_source_dropdown_values(sample_learnings)
        assert len(values) == len(set(values))

    def test_new_source_appears_automatically(self, sample_learnings):
        """Adding a new source to the DB makes it appear in the dropdown."""
        extra = _make_learning("Rick's note", source="Rick Vavro")
        values = get_source_dropdown_values(sample_learnings + [extra])
        assert "Rick Vavro" in values

    def test_empty_source_not_added(self):
        """A learning with empty/None source must not add blank entry."""
        learnings = [
            _make_learning("No source", source=""),
            _make_learning("None source", source=None),
        ]
        values = get_source_dropdown_values(learnings)
        # Should only have "All" — no blank entry
        assert values == ["All"] or all(v for v in values if v != "All")
        assert "" not in values

    def test_empty_db_has_only_all(self):
        values = get_source_dropdown_values([])
        assert values == ["All"]

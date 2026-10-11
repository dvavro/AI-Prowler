"""
tests/gui/test_hr_task_status_vocabulary_and_edit_form.py
==========================================================
Exact-vocabulary regression test, per Implementation Plan v2.1 Section
13.2.3. Task status strings must be byte-identical across
hr_state_rules.json, the index.html render switch, and the Task Detail
Sheet edit-form field map — any drift breaks the UI silently (a status
renders as its own literal, unstyled JSON string).

ADAPTATION FROM THE PLAN: the plan's own code stub lists 6 statuses
(Not Started, In Progress, Completed, Overdue, Waived, Blocked). The real
shipped hr_state_rules.json and hr/index.html both use the full 8-status
vocabulary (adding Awaiting Document and Escalated), matching what the HR
Backend Engine actually generates. EXPECTED_STATUSES below uses all 8,
per Section 13.0's "test against real shipped source" philosophy.

Safe: reads hr/index.html and hr_state_rules.json as plain text/JSON only.
Never imports ai_prowler_mcp.py, never writes anywhere.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

SRC_ROOT = Path(os.environ.get("AI_PROWLER_SRC", "")) if os.environ.get("AI_PROWLER_SRC") \
    else Path(__file__).resolve().parent.parent.parent
HR_INDEX = SRC_ROOT / "hr" / "index.html"
HR_STATE_RULES = SRC_ROOT / "hr_state_rules.json"

EXPECTED_STATUSES = [
    "Not Started",
    "In Progress",
    "Awaiting Document",
    "Completed",
    "Waived",
    "Overdue",
    "Escalated",
    "Blocked",
]


@pytest.fixture(scope="module")
def hr_index_text():
    return HR_INDEX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def state_rules():
    return json.loads(HR_STATE_RULES.read_text(encoding="utf-8"))


class TestStateRulesVocabulary:
    def test_all_expected_statuses_present(self, state_rules):
        dumped = json.dumps(state_rules)
        for status in EXPECTED_STATUSES:
            assert status in dumped, f"Status '{status}' missing from hr_state_rules.json"

    def test_task_statuses_list_matches_exactly(self, state_rules):
        listed = state_rules.get("task_statuses")
        if listed is not None:
            assert set(listed) == set(EXPECTED_STATUSES), (
                f"hr_state_rules.json task_statuses {listed} does not match "
                f"the expected vocabulary {EXPECTED_STATUSES}"
            )


class TestIndexHtmlRenderVocabularyMatchesStateRules:
    @pytest.mark.parametrize("status", EXPECTED_STATUSES)
    def test_status_string_appears_verbatim_in_index(self, hr_index_text, status):
        assert status in hr_index_text, (
            f"'{status}' from hr_state_rules.json not found verbatim in hr/index.html"
        )


class TestEditFormFieldMapCoversAllStatuses:
    def test_edit_form_status_dropdown_options_match(self, hr_index_text):
        select_block_match = re.search(
            r"<select[^>]*id=[\"']task-status[^>]*>(.*?)</select>", hr_index_text, re.S
        )
        assert select_block_match, "No #task-status <select> found in the Task Detail Sheet edit form"
        block = select_block_match.group(1)
        for status in EXPECTED_STATUSES:
            assert status in block, f"Edit-form status dropdown is missing '{status}'"

    def test_edit_form_has_no_unexpected_extra_statuses(self, hr_index_text):
        select_block_match = re.search(
            r"<select[^>]*id=[\"']task-status[^>]*>(.*?)</select>", hr_index_text, re.S
        )
        assert select_block_match
        options = re.findall(r'value="([^"]+)"', select_block_match.group(1))
        extra = set(options) - set(EXPECTED_STATUSES)
        assert not extra, f"Edit-form dropdown has options not in EXPECTED_STATUSES: {extra}"

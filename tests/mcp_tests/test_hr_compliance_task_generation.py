"""
tests/mcp/test_hr_compliance_task_generation.py
================================================
Pure-function tests for state-specific task auto-generation (Implementation
Plan v2.1 Section 3.2 / 7.1, listed in the Section 13.1 file inventory but
without a code stub in the plan itself). For each of the 8 supported
states, applying the real hr_task_templates.json's template sets must
produce no duplicate template_ids, must never leak a state-restricted
template into a state it doesn't apply to, and must always include every
template that isn't state-restricted at all.

Mirrors the shipped _hr_template_applies() logic in ai_prowler_mcp.py's HR
Backend Engine section as a local pure function — reads only the real
hr_task_templates.json and hr_state_rules.json (never writes anywhere),
and never imports ai_prowler_mcp.py as a module. This matches the
established safe pattern in tests/mcp/test_pwa_api_route.py ("Safe — does
NOT start AI-Prowler, touch install dir, or require live server").
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

SRC_ROOT = Path(os.environ.get("AI_PROWLER_SRC", "")) if os.environ.get("AI_PROWLER_SRC") \
    else Path(__file__).resolve().parent.parent.parent
TEMPLATES = json.loads((SRC_ROOT / "hr_task_templates.json").read_text(encoding="utf-8"))
STATE_RULES = json.loads((SRC_ROOT / "hr_state_rules.json").read_text(encoding="utf-8"))

SUPPORTED_STATES = ["CA", "TX", "NY", "FL", "IL", "WA", "CO", "MA"]


def template_applies(tmpl: dict, work_state: str) -> bool:
    """Mirrors _hr_template_applies() in ai_prowler_mcp.py exactly."""
    if not tmpl.get("state_specific"):
        return True
    allow = tmpl.get("applicable_states")
    if allow:
        return work_state in allow
    deny = tmpl.get("not_required_states")
    if deny:
        return work_state not in deny
    return True  # state-specific but no explicit list -> generic, always include


def generate_for_state(category: str, work_state: str) -> list:
    return [t for t in TEMPLATES.get(category, []) if template_applies(t, work_state)]


class TestTemplateCatalogIntegrity:
    """Sanity checks on the shipped catalog itself, independent of any
    particular state — a duplicate or malformed entry here would silently
    break every per-state test below for the wrong reason."""

    @pytest.mark.parametrize("category", ["base", "offboarding", "annual"])
    def test_template_ids_unique_within_category(self, category):
        ids = [t["template_id"] for t in TEMPLATES.get(category, [])]
        assert len(ids) == len(set(ids)), f"Duplicate template_id(s) in '{category}': {ids}"

    @pytest.mark.parametrize("category", ["base", "offboarding", "annual"])
    def test_every_template_has_required_fields(self, category):
        required = ("template_id", "name", "phase", "priority", "due_offset_days", "due_anchor")
        for t in TEMPLATES.get(category, []):
            missing = [f for f in required if f not in t]
            assert not missing, f"{t.get('template_id', '?')} missing fields: {missing}"


@pytest.mark.parametrize("state", SUPPORTED_STATES)
class TestPerStateTaskGeneration:
    """C-HR-COMPLIANCE-01 .. 03 style checks, one run per supported state."""

    def test_no_duplicate_tasks_generated_for_state(self, state):
        generated = generate_for_state("base", state)
        ids = [t["template_id"] for t in generated]
        assert len(ids) == len(set(ids)), f"Duplicate task(s) generated for {state}: {ids}"

    def test_non_state_specific_templates_always_included(self, state):
        generated_ids = {t["template_id"] for t in generate_for_state("base", state)}
        universal = [t for t in TEMPLATES.get("base", []) if not t.get("state_specific")]
        for t in universal:
            assert t["template_id"] in generated_ids, (
                f"{t['template_id']} ({t['name']}) is not state-specific but "
                f"was excluded for {state} — federal-required tasks must "
                f"never depend on work_state."
            )

    def test_state_entry_exists_in_rules(self, state):
        assert state in STATE_RULES.get("states", {}), f"No hr_state_rules.json entry for {state}"


class TestStateRestrictedTemplatesDoNotLeak:
    """C-HR-COMPLIANCE-03 — a template scoped to specific states via
    applicable_states must never appear for a state outside that list, and
    a template scoped via not_required_states must never appear for a
    state inside that list. Iterates whatever the real catalog actually
    contains rather than hard-coding an assumed template name, so this
    stays correct even as hr_task_templates.json evolves."""

    def test_applicable_states_allowlist_is_respected(self):
        checked = 0
        for t in TEMPLATES.get("base", []) + TEMPLATES.get("offboarding", []):
            allow = t.get("applicable_states")
            if not allow:
                continue
            checked += 1
            for state in SUPPORTED_STATES:
                expected = state in allow
                assert template_applies(t, state) == expected, (
                    f"{t['template_id']} applicable_states={allow} — "
                    f"template_applies({state!r}) returned "
                    f"{not expected}, expected {expected}"
                )
        assert checked > 0, (
            "No template in the catalog uses applicable_states — this test "
            "would pass vacuously; update it if the catalog's shape changes."
        )

    def test_not_required_states_denylist_is_respected(self):
        checked = 0
        for t in TEMPLATES.get("base", []) + TEMPLATES.get("offboarding", []):
            deny = t.get("not_required_states")
            if not deny:
                continue
            checked += 1
            for state in SUPPORTED_STATES:
                expected = state not in deny
                assert template_applies(t, state) == expected, (
                    f"{t['template_id']} not_required_states={deny} — "
                    f"template_applies({state!r}) returned "
                    f"{not expected}, expected {expected}"
                )
        assert checked > 0, (
            "No template in the catalog uses not_required_states — this "
            "test would pass vacuously; update it if the catalog's shape "
            "changes."
        )

"""Coder 1 Sprint 30: the Spec's build-status section, brought current.

The "Build status by coder" section was a Nov 7 snapshot. Since then Coder 1
Sprints 21-29 landed (drawing model and plan_* tools, measurements and
takeoff_* tools, takeoff_propose / review_* / crop support, plan revision
comparison, the processing-PC queue, the full wizard, the installer, the
guide chapter) and Coder 2's Sprints 1-14 merged, but the section still
showed those blocks as in progress or not started. These tests pin the
refreshed status - and pin that the phase gates were NOT marked passed:
their evidence runs and pilots are still outstanding.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SPEC = REPO_ROOT / "docs" / "estimator" / "AI-Prowler Estimator Design Spec.md"
PLAN = REPO_ROOT / "docs" / "estimator" / "AI-Prowler Estimator Implementation Plan.md"


def _spec_lines():
    return SPEC.read_text(encoding="utf-8", errors="replace").splitlines()


def _node_line(lines, node_id):
    hits = [ln.strip() for ln in lines if ln.strip().startswith(node_id + "[")]
    assert len(hits) == 1, node_id
    return hits[0]


def test_s30_g01_status_section_is_dated_nov_9():
    text = SPEC.read_text(encoding="utf-8", errors="replace")
    assert "### Build status by coder (as of Nov 9, 2026)" in text
    assert "as of Nov 7, 2026" not in text


def test_s30_g02_all_coder1_blocks_done():
    lines = _spec_lines()
    for n in range(14):
        line = _node_line(lines, "A%d" % n)
        assert line.endswith(":::done"), line


def test_s30_g03_coder2_blocks_match_the_plan_log():
    lines = _spec_lines()
    for n in range(12):
        line = _node_line(lines, "B%d" % n)
        assert line.endswith(":::done"), line
    assert _node_line(lines, "B12").endswith(":::todo")


def test_s30_g04_score_line_is_current():
    text = SPEC.read_text(encoding="utf-8", errors="replace")
    score = [ln for ln in text.splitlines() if ln.startswith("**Score so far:**")]
    assert len(score) == 1
    assert "all 14 blocks done" in score[0]
    assert "12 of 13 blocks" in score[0]
    assert "1,310 tests" in score[0]


def test_s30_g05_stale_not_started_claims_are_gone():
    text = SPEC.read_text(encoding="utf-8", errors="replace")
    for stale in ("measurements and `takeoff_*` not started",
                  "`takeoff_propose`, `review_*` and crop reasoning not started",
                  "installer and full wizard not started",
                  "plan comparison and processing-PC queue not started",
                  "Server sign-in to come",
                  "aren't merged yet"):
        assert stale not in text, stale


def test_s30_g06_phase_gates_were_not_marked_passed():
    text = PLAN.read_text(encoding="utf-8", errors="replace")
    for gate in ("- [ ] G0", "- [ ] Phase 1", "- [ ] Phase 2", "- [ ] Phase 3",
                 "- [ ] Phase 4", "- [ ] Phase 5", "- [ ] Phase 6",
                 "- [ ] Phase 7", "- [ ] Phase 8"):
        assert gate in text, gate
    assert "- [x] G0" not in text
    assert "- [x] Phase" not in text

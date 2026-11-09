"""Coder 1 Sprint 29: the Estimator chapter of the Complete User Guide.

The Spec's Phase 8 list calls for an Estimator chapter in COMPLETE_USER_GUIDE.md;
until this sprint the shipped guide never mentioned the Estimator at all. These
tests pin the chapter, its table-of-contents entry, and the subjects it must
cover, in the same spirit as the Sprint 26 installer guard.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GUIDE = REPO_ROOT / "COMPLETE_USER_GUIDE.md"
HEADING = "## 29. Estimator — Estimates, Takeoffs and Bids"


def _guide_text():
    return GUIDE.read_text(encoding="utf-8", errors="replace")


def test_s29_g01_guide_has_the_estimator_chapter():
    assert HEADING in _guide_text()


def test_s29_g02_table_of_contents_lists_it():
    assert "29. Estimator — Estimates, Takeoffs and Bids" in _guide_text()


def test_s29_g03_chapter_sits_before_the_appendices():
    text = _guide_text()
    assert text.index(HEADING) < text.index("## Appendix A")


def test_s29_g04_chapter_covers_the_built_features():
    text = _guide_text()
    chapter = text[text.index(HEADING):text.index("## Appendix A")]
    for needle in ("setup wizard", "Team and approvals", "practice project", "Blueprint Review",
                   "Runner", "Estimating scope", "localhost:8770", "CAD and tools",
                   "ODA File Converter", "Director"):
        assert needle in chapter, needle

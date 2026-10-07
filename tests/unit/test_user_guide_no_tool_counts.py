"""
tests/unit/test_user_guide_no_tool_counts.py
=============================================
MCP tools are user-configurable (Settings -> MCP Tool Configuration), so
COMPLETE_USER_GUIDE.md must not quote tool counts — the panel's live
"N of M tools enabled" line is the source of truth. Guards against counts
creeping back into the guide.

Run with:
    run_tests.bat tests\\unit\\test_user_guide_no_tool_counts.py -v
"""
import re
from pathlib import Path

GUIDE = Path(__file__).resolve().parent.parent.parent / "COMPLETE_USER_GUIDE.md"


def _text():
    return GUIDE.read_text(encoding="utf-8")


def test_no_tool_count_in_category_headings():
    bad = [l for l in _text().splitlines()
           if l.startswith("#") and re.search(r"\(\d+ tools?\b", l)]
    assert not bad, f"headings still quote tool counts: {bad}"


def test_no_total_or_per_mode_tool_counts():
    t = _text()
    assert "Tool Counts by Mode" not in t
    assert not re.search(r"\*\*\d+ tools\*\*", t), "bold 'N tools' total found"
    assert not re.search(r"\bAll \d+ tools\b", t)
    assert not re.search(r"\b\d+ tools, currently\b", t)


def test_section_6_1_points_to_settings_panel():
    t = _text()
    assert "### 6.1 Which Tools Are Available" in t
    sec = t.split("### 6.1 Which Tools Are Available", 1)[1].split("### 6.2", 1)[0]
    assert "MCP Tool Configuration" in sec
    assert "restart" in sec.lower()

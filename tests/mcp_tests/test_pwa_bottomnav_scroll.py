"""Jobs app bottom tab bar scrolls sideways on phones (2026-10-15).

With up to 10 tabs the bar is wider than a phone screen; it used to cut off
the right-hand tabs. The bar now scrolls horizontally, each tab keeps a
minimum width, and selecting a tab scrolls it into view. On wide screens the
tabs still share the width evenly (flex:1), so nothing changes there.
"""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parents[2] / "jobs" / "index.html").read_text(encoding="utf-8")


def _rule(selector: str) -> str:
    m = re.search(re.escape(selector) + r"\{([^}]*)\}", HTML)
    assert m, f"CSS rule {selector!r} not found in jobs/index.html"
    return m.group(1)


def test_bottom_nav_scrolls_horizontally():
    rule = _rule(".bottomnav")
    assert "overflow-x:auto" in rule
    assert "overflow-y:hidden" in rule


def test_nav_buttons_keep_a_minimum_width_and_still_share_wide_screens():
    rule = _rule(".nav-btn")
    assert "flex:1" in rule
    assert re.search(r"min-width:\s*\d+px", rule)


def test_nav_labels_do_not_wrap():
    assert "white-space:nowrap" in _rule(".nav-label")


def test_selecting_a_tab_scrolls_it_into_view():
    body = HTML.split("function showScreen(name, btn) {", 1)[1].split("\nfunction ", 1)[0]
    assert "scrollLeft" in body and "scrollWidth > _nav.clientWidth" in body

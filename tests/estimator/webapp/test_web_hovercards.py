"""Hover cards on 🤖 AI Auto Measure/Count and ⚡ Run wiring (2026-11-21, David: "make a hover popup over the AI auto run to explain
what it needed for electrical to run and also the run wiring with recommendation what's needed. Do the same for all the
trades but the hover info should be focused on what is needed for each trade"). Checked in the page's own files."""
import re

from estimator.api import router

REVIEW = (router.WEB_DIR / "review.js").read_text(encoding="utf-8")
CSS = (router.WEB_DIR / "app.css").read_text(encoding="utf-8")


def _block(start: str, end: str) -> str:
    i = REVIEW.index(start)
    return REVIEW[i:REVIEW.index(end, i)]


def test_both_buttons_get_a_hover_card():                                                    # HC-01
    assert 'attachHoverCard(run, "bp-auto-run-help", autoRunHelp)' in REVIEW
    assert 'attachHoverCard(wire, "bp-run-wiring-help", wiringHelp)' in REVIEW
    card = _block("function attachHoverCard(", "function needsCard(")
    for needed in ('role: "tooltip"', "aria-describedby", "mouseenter", "focusin", 'removeAttribute("title")'):
        assert needed in card
    # The status refresh must not put a plain tooltip back on top of the card.
    assert 'if (!runBtn.closest(".hovercard-wrap")) runBtn.title' in REVIEW


def test_every_auto_run_trade_has_its_own_needs():                                          # HC-02
    trades = re.findall(r'"(\w+)"', _block("const AUTO_RUN_TRADES", ";"))
    assert len(trades) == 15
    needs = _block("const AUTO_RUN_NEEDS = {", "const WIRING_NEEDS")
    for t in trades:
        m = re.search(r"\b" + t + r": \{ needs: \[(.*?)\],\s*tips: \[(.*?)\] \}", needs, re.S)
        assert m, f"{t} has no needs/tips entry"
        assert m.group(1).strip() and m.group(2).strip(), f"{t} needs both what's needed and tips"
    elec = re.search(r"\belectrical: \{(.*?)\] \}", needs, re.S).group(1)
    assert "DXF" in elec and "panel" in elec.lower()


def test_the_wiring_card_says_the_panel_drawing_is_optional():                              # HC-03
    w = _block("const WIRING_NEEDS = {", "function attachHoverCard(")
    assert "DXF" in w and "panel symbol" in w
    assert "No panel schedule?" in w and "usual residential way" in w
    help_ = _block("function autoRunHelp(", "function autoRunTitle(")
    assert "What it needs" in REVIEW and "For the best result" in REVIEW
    assert "switched off for" in help_ and "AI measuring turned on" in help_
    assert "the panel drawing's schedule is used when there is one" in REVIEW


def test_the_card_shows_on_hover_and_focus():                                               # HC-04
    assert ".hovercard { display: none;" in CSS
    assert ".hovercard-wrap:hover .hovercard, .hovercard-wrap:focus-within .hovercard { display: block; }" in CSS

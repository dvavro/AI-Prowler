"""
Jobs app: a job-list refresh must not wipe the job the person picked
(2026-10-03, E2E SRV-SCR-07).

populateSelects() rebuilds the Clock and Photos job pickers every time the job
list refreshes. It used to throw away the current choice (only the running
clock-in's job was put back), so a refresh landing just after someone picked a
job reset the picker to "— choose a job —" — their Clock In then said "Select
a job first" and sent nothing. Seen in the server E2E run: David's screenshot
showed "— choose a job —" after the test had picked his job.

Run: run_tests.bat tests\\mcp\\test_job_picker_keeps_choice.py -v
"""
from pathlib import Path

_HTML = (Path(__file__).resolve().parent.parent.parent / "jobs" / "index.html").read_text(encoding="utf-8")


def _populate_selects():
    i = _HTML.index("function populateSelects() {")
    return _HTML[i:_HTML.index("\n}\n", i)]


def test_choices_are_read_before_the_pickers_are_rebuilt():
    body = _populate_selects()
    read = body.index("const prevClock = clockSel.value, prevPhoto = photoSel.value;")
    assert read < body.index("clockSel.innerHTML=opts;")
    assert read < body.index("photoSel.innerHTML=opts;")


def test_both_pickers_put_the_choice_back_if_the_job_still_exists():
    body = _populate_selects()
    assert "else if (_has(prevClock)) clockSel.value = prevClock;" in body
    assert "if (_has(prevPhoto)) photoSel.value = prevPhoto;" in body
    # a running clock-in still wins (R-025)
    assert body.index("state.activeClockJob && _has(state.activeClockJob)") < body.index("_has(prevClock)")


def test_buttons_follow_the_restored_choice():
    body = _populate_selects()
    assert "document.getElementById('clockInBtn').disabled = !clockSel.value;" in body
    assert "checkUploadBtn()" in body

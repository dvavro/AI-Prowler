"""
Job Board: a load that was in flight when a card was moved must not undo the
move (2026-10-02, E2E BRD-02).

Opening the Board starts a reload and the ↻ button / 60-second poll start
others. A load sent BEFORE a drag comes back with the job's OLD status; it used
to overwrite the board with that snapshot, so the card jumped back to its old
column although the move was saved (database said "In Progress", board showed
"Scheduled" until the next poll a minute later).

Fix: the drop handler bumps state.boardMoveSeq when the card moves and again
when the save finishes; loadBoard() notes the counter when it starts and throws
its result away (without advancing boardSince) if it changed meanwhile.

Run: run_tests.bat tests\\mcp\\test_board_move_race.py -v
"""
from pathlib import Path

_HTML = (Path(__file__).resolve().parent.parent.parent / "jobs" / "index.html").read_text(encoding="utf-8")


def _fn(name, size=9000):
    i = _HTML.index(name)
    return _HTML[i:i + size]


def test_loadBoard_discards_a_result_older_than_a_move():
    body = _fn("async function loadBoard(full, quiet)", 4000)
    start = body.index("const moveSeqAtStart = state.boardMoveSeq || 0;")
    fetch = body.index("mcpCall('get_board_updates'")
    check = body.index("(state.boardMoveSeq || 0) !== moveSeqAtStart")
    apply_ = body.index("if (isFirstLoad) {")
    assert start < fetch < check < apply_, \
        "note the counter BEFORE asking, compare it AFTER the reply, BEFORE applying"
    discard = body[check:apply_]
    assert "return;" in discard and "renderBoard();" in discard
    assert "boardSince" not in discard, "a discarded result must not move the cursor"


def test_drop_handler_bumps_the_counter_on_move_and_when_the_save_finishes():
    i = _HTML.index("const prevVersion = row['_version'];")
    body = _HTML[i:i + 4500]
    bump = "state.boardMoveSeq = (state.boardMoveSeq || 0) + 1;"
    first = body.index(bump)
    assert first < body.index("row['Job Status'] = newStatus;"), "bump before the card moves"
    after_save = body.index(bump, body.index("mcpCall('update_job_spreadsheet'"))
    assert after_save < body.index("if (_isFailureResult(result))")
    catch = body.index("} catch (err) {")
    assert body.index(bump, catch) < body.index("loadBoard(true);", catch), \
        "a failed save also ends the move before the board reloads"

"""Server mode — several people at once (spec §6.11.5 SRV-MULTI-01/02/04/05).
(SRV-MULTI-03, the stale-save check, is test_srv_multi.py.)

Test jobs (owner-made ZTEST, sandbox date): J-A Crew = Samual, J-B Crew = Vicki.
Owner-side changes are made straight through the owner's session (the same
update_job_spreadsheet call a Board drag makes) so the timing is exact; the
other person's window is left alone to see whether their screen catches up.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_live_multi
"""
import re
import threading
import time

import pytest
from playwright.sync_api import expect

from api import parse_records

CREW = "Samual Cronin"
OTHER = "Vicki Vavro"
POLL_S = 60             # the Board re-reads its feed every 60 s while it's open
GRACE_S = 20            # plus a little for the request itself


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


def _card(page, jid, status=None):
    col = f'#boardColumns .board-col[data-status="{status}"]' if status else "#boardColumns"
    return page.locator(f"{col} .board-card").filter(
        has=page.locator(".board-card-id", has_text=re.compile(rf"^\s*{re.escape(jid)}\s*$")))


def _open_board(w):
    w.app.goto("board")
    w.page.locator("#refreshBoardBtn").click()
    expect(w.page.locator("#boardColumns .loader")).to_have_count(0, timeout=20_000)


def _set(owner_api, jid, **updates):
    owner_api.call("update_job_spreadsheet", {"job_identifier": jid, "id_column": "JobID (JOB-####)",
                                              "updates": updates})


def _wait_for(check, timeout_s):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if check():
            return time.time() - t0
        time.sleep(2)
    return None


@pytest.fixture
def jobs(clean_slate, data):
    return {"mine": data.job("MULTI Samual", **{"Crew / Technician": CREW}),
            "theirs": data.job("MULTI Vicki", "brannon", **{"Crew / Technician": OTHER})}


# ── SRV-MULTI-01: owner's change reaches the crew's open Board within one poll ──
def test_SRV_MULTI_01_owner_change_reaches_crew_board_within_one_poll(windows, jobs, owner_api):
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    _open_board(sam)
    expect(_card(sam.page, jobs["mine"])).to_have_count(1, timeout=20_000)
    assert _card(sam.page, jobs["mine"], "In Progress").count() == 0, "job already In Progress before the change"

    sam.app.step(f"owner sets {jobs['mine']} to In Progress — Samual's Board is left alone (no refresh)")
    _set(owner_api, jobs["mine"], **{"Job Status": "In Progress"})
    took = _wait_for(lambda: _card(sam.page, jobs["mine"], "In Progress").count() == 1, POLL_S + GRACE_S)
    sam.app.log(f"[SRV-MULTI-01] Samual's Board showed the move after {took if took is None else round(took)} s")
    assert took is not None, f"Samual's open Board didn't show the owner's change within {POLL_S + GRACE_S} s"
    assert _card(sam.page, jobs["mine"]).count() == 1, "the card is now on the Board twice"


# ── SRV-MULTI-02: owner re-assigns a job to another crew ─────────────────────
def test_SRV_MULTI_02_reassigned_job_leaves_first_crews_lists(windows, jobs, owner_api):
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    _open_board(sam)
    expect(_card(sam.page, jobs["mine"])).to_have_count(1, timeout=20_000)

    sam.app.step(f"owner re-assigns {jobs['mine']} from Samual to Vicki")
    _set(owner_api, jobs["mine"], **{"Crew / Technician": OTHER})

    # 1) the automatic Board update (no tap) — recorded, see the docstring note
    gone_by_poll = _wait_for(lambda: _card(sam.page, jobs["mine"]).count() == 0, POLL_S + GRACE_S)
    sam.app.log(f"[SRV-MULTI-02] after the Board's own update: card "
                f"{'gone after ' + str(round(gone_by_poll)) + ' s' if gone_by_poll is not None else 'STILL SHOWN'}")

    # 2) what the spec requires: gone after a refresh — Board and Jobs list
    sam.page.locator("#refreshBoardBtn").click()
    expect(sam.page.locator("#boardColumns .loader")).to_have_count(0, timeout=20_000)
    expect(_card(sam.page, jobs["mine"])).to_have_count(0, timeout=10_000)
    sam.app.goto("jobs")
    sam.page.evaluate("async () => { await loadJobs(); }")
    ids = sam.page.evaluate("() => (state.jobs || []).map(j => String(j.id))")
    assert jobs["mine"] not in ids, f"re-assigned job still in Samual's Jobs list: {ids}"

    # 3) and the automatic update is how the crew actually finds out
    assert gone_by_poll is not None, (
        "a job re-assigned away from Samual stayed on his open Board through the automatic update "
        f"({POLL_S + GRACE_S} s) — it only went away when he tapped refresh")


# ── SRV-MULTI-04: everyone signed in at once ────────────────────────────────
def test_SRV_MULTI_04_all_users_at_once_each_see_their_own_set(windows, jobs, srv):
    keys = [k for k in ("U1", "U2", "U3") if k in srv["users"]]
    ws = windows(*keys)
    for w in ws:
        w.log_in()
    timings = {}
    for w in ws:
        _signed_in(w)
        t0 = time.time()
        w.app.goto("jobs")
        w.page.evaluate("async () => { await loadJobs(); }")
        ids = w.page.evaluate("() => (state.jobs || []).map(j => String(j.id))")
        t1 = time.time()
        _open_board(w)
        timings[w.user.key] = (round(t1 - t0, 1), round(time.time() - t1, 1))
        crew_only = w.user.role == "field_crew"
        assert jobs["mine"] in ids, f"{w.user.key}: Samual's job missing from Jobs: {ids}"
        assert (jobs["theirs"] in ids) != crew_only, f"{w.user.key} ({w.user.role}) Jobs list wrong: {ids}"
        expect(_card(w.page, jobs["mine"])).to_have_count(1, timeout=20_000)
        assert _card(w.page, jobs["theirs"]).count() == (0 if crew_only else 1), f"{w.user.key} Board wrong"
    ws[0].app.log(f"[SRV-MULTI-04] load times (Jobs s, Board s) per user: {timings}")


# ── SRV-MULTI-05: two people clock in at the same moment ─────────────────────
def test_SRV_MULTI_05_two_clock_ins_at_once_each_on_the_right_person(jobs, api_as, owner_api):
    pairs = [("U3", jobs["mine"], CREW), ("U2", jobs["theirs"], OTHER)]
    results, start = {}, threading.Barrier(len(pairs))

    def clock(key, jid):
        start.wait()
        results[key] = api_as(key).call("log_time_entry", {"job_identifier": jid, "action": "start"},
                                        expect_ok=False)

    threads = [threading.Thread(target=clock, args=(k, j)) for k, j, _ in pairs]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        for key, jid, name in pairs:
            assert str(results.get(key, "")).lstrip().startswith("⏱"), f"{key} clock-in failed: {results.get(key)!r}"
        rows = parse_records(owner_api.call("read_job_spreadsheet", {"sheet_name": "TimeLog", "max_rows": 1000},
                                            expect_ok=False))
        for key, jid, name in pairs:
            mine = [r for r in rows if jid in r.values()]
            assert len(mine) == 1, f"{jid}: expected one TimeLog entry, found {len(mine)}"
            assert name in mine[0].values(), f"{jid}'s entry isn't under {name}: {mine[0]}"
    finally:
        for key, jid, _ in pairs:
            api_as(key).call("log_time_entry", {"job_identifier": jid, "action": "stop"}, expect_ok=False)

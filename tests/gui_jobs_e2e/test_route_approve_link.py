"""Phase 2 completion (spec §6.5.4, §6.5.5): Approve / Un-approve (RA) and
the saved phone map link (PL).

RA — Approve writes each routed SOFT job's planned time slot into its Start /
End Time; Hard jobs and the "Original Start/End Time" fields are never
touched, which is what lets Un-approve restore the customer's window.
PL — every job on a route carries the same Google Maps link; it must have no
start point (open-ended), the stops in route order, never the same address
twice in a row, at most 9 stops, and it must follow manual changes.

Run: run_tests_gui_jobs_e2e.bat --human -k "RA_ or PL_"
"""
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from playwright.sync_api import expect

from data import PLACES
from safety import SANDBOX_DATE

JOB_ID = "JobID (JOB-####)"


# ── helpers ──────────────────────────────────────────────────────────────────
def _minutes(t: str):
    """'08:00', '8:00 AM', '5:00 PM' -> minutes after midnight (None if blank)."""
    t = (t or "").strip().upper()
    m = re.match(r"^(\d{1,2}):(\d{2})(?::\d{2})?\s*(AM|PM)?$", t)
    if not m:
        return None
    h, mi, ap = int(m.group(1)), int(m.group(2)), m.group(3)
    if ap:
        h = h % 12 + (12 if ap == "PM" else 0)
    return h * 60 + mi


def _jobs_by_id(api, ids):
    rows = {r.get(JOB_ID): r for r in api.read("Jobs_Schedule")}
    return {i: rows[i] for i in ids}


def _waypoints(url: str) -> list[str]:
    q = parse_qs(urlsplit(url).query)
    return [w for w in (q.get("waypoints", [""])[0]).split("|") if w]


def _street_of(place_key: str) -> str:
    return PLACES[place_key][0]


def _build(route, api, data, specs):
    """specs: [(label, place_key, extra_fields)] -> job ids, routed on the sandbox date."""
    ids = [data.job(label, place, **extra) for label, place, extra in specs]
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)
    route.wait_quiet()
    return ids


SOFT = {"Schedule Type (Hard/Soft)": "Soft", "Start Time": "08:00", "End Time": "17:00"}
HARD = {"Schedule Type (Hard/Soft)": "Hard", "Start Time": "11:00", "End Time": "11:30"}


@pytest.fixture
def three_stop_route(clean_slate, route, api, data):
    specs = [("RA soft 1", "city_hall", SOFT), ("RA soft 2", "brannon", SOFT), ("RA hard", "library", HARD)]
    ids = _build(route, api, data, specs)
    return {"ids": ids, "soft": ids[:2], "hard": ids[2],
            "street": {ids[0]: _street_of("city_hall"), ids[1]: _street_of("brannon"),
                       ids[2]: _street_of("library")}}


# ── RA: Approve / Un-approve ─────────────────────────────────────────────────
def _approve(route):
    btn = route.approve_btn()
    expect(btn).to_be_visible(timeout=15_000)
    with route.page.expect_request(lambda r: "/pwa-api" in r.url and "approve_route_schedule" in (r.post_data or "")):
        btn.click()
    route.wait_quiet()


def _unapprove(route):
    msgs = []

    def h(d):
        msgs.append(d.message)
        d.accept()
    route.page.on("dialog", h)
    try:
        btn = route.unapprove_btn()
        expect(btn).to_be_visible(timeout=15_000)
        with route.page.expect_request(lambda r: "/pwa-api" in r.url and "unapprove_route_schedule" in (r.post_data or "")):
            btn.click()
        route.wait_quiet()
    finally:
        route.page.remove_listener("dialog", h)
    return msgs


def test_RA_01_approve_writes_planned_times_to_soft_jobs_only(route, api, three_stop_route):
    r = three_stop_route
    _approve(route)
    jobs = _jobs_by_id(api, r["ids"])
    for jid in r["soft"]:
        j = jobs[jid]
        start, end = _minutes(j.get("Start Time")), _minutes(j.get("End Time"))
        assert start is not None and end is not None, f"{jid}: times missing after approve: {j}"
        # the planned slot is the job's 30-min duration, not its 8:00–17:00 window
        assert end - start == 30, f"{jid}: expected a 30-min planned slot, got {j.get('Start Time')}–{j.get('End Time')}"
        assert _minutes(j.get("Original Start Time")) == 8 * 60 and _minutes(j.get("Original End Time")) == 17 * 60, \
            f"{jid}: Original window changed: {j.get('Original Start Time')}–{j.get('Original End Time')}"
    h = jobs[r["hard"]]
    assert (_minutes(h.get("Start Time")), _minutes(h.get("End Time"))) == (11 * 60, 11 * 60 + 30), \
        f"Hard job's committed time changed: {h.get('Start Time')}–{h.get('End Time')}"


def test_RA_02_unapprove_restores_the_original_windows(route, api, three_stop_route):
    r = three_stop_route
    _approve(route)
    msgs = _unapprove(route)
    assert msgs, "Un-approve should ask for confirmation"
    jobs = _jobs_by_id(api, r["ids"])
    for jid in r["soft"]:
        j = jobs[jid]
        assert (_minutes(j.get("Start Time")), _minutes(j.get("End Time"))) == (8 * 60, 17 * 60), \
            f"{jid}: not restored: {j.get('Start Time')}–{j.get('End Time')}"


def test_RA_03_approve_hidden_when_route_has_no_soft_jobs(clean_slate, route, api, data):
    _build(route, api, data, [("RA hard only 1", "city_hall", HARD),
                              ("RA hard only 2", "brannon", dict(HARD, **{"Start Time": "13:00", "End Time": "13:30"}))])
    expect(route.approve_btn()).to_be_hidden()

# RA-04 (Email Route, safe tier: recorded with the right date, nothing sent) is
#   test_BTN_ROUTE_email_route_is_guarded in test_buttons.py.
# RA-05 (one REAL email) only runs with --tier email — see below.
# RA-06 (the emailed link follows manual edits): the email is built by the
#   server from the saved link, so it's checked by PL-07 below.


@pytest.mark.skipif(__import__("os").environ.get("E2E_TIER", "safe") not in ("email", "full"),
                    reason="sends one real email — run with --tier email")
def test_RA_05_email_route_really_sends_once(route, guard, three_stop_route):
    route.page.locator("#routeEmailRouteBtn").click()
    route.wait_quiet()
    assert guard.real_emails_sent == 1


# ── PL: the saved phone map link ─────────────────────────────────────────────
def _links(api, ids):
    return {jid: (j.get("Route Map URL") or "").strip() for jid, j in _jobs_by_id(api, ids).items()}


def _ui_order(route):
    return [s.job_id() for s in route.stops()]


def test_PL_01_to_06_link_is_open_ended_ordered_and_shared(route, api, three_stop_route):
    r = three_stop_route
    links = _links(api, r["ids"])
    urls = set(links.values())
    assert len(urls) == 1 and "" not in urls, f"PL-06: every routed job should carry the SAME link: {links}"
    url = urls.pop()
    q = parse_qs(urlsplit(url).query)
    assert "origin" not in q, "PL-01: the link must not set a start point (open-ended)"
    assert q.get("destination", [""])[0], "PL-02: the link needs a destination (end of day)"
    wps = _waypoints(url)
    order = _ui_order(route)
    assert len(wps) == len(order), f"PL-03: {len(wps)} waypoints vs {len(order)} stops on screen"
    for i, (wp, jid) in enumerate(zip(wps, order)):
        assert wp.lower().startswith(r["street"][jid].lower()), \
            f"PL-03: waypoint {i + 1} is '{wp}', but stop {i + 1} on screen is {jid} ({r['street'][jid]})"
    for a, b in zip(wps, wps[1:]):
        assert a.lower() != b.lower(), f"PL-04: same address twice in a row: {a}"
    assert len(wps) <= 9, f"PL-05: {len(wps)} waypoints — Google Maps allows at most 9"


def test_PL_04_same_address_pair_appears_once_in_the_link(clean_slate, route, api, data):
    """R-001: two jobs at one address must not make the link stop twice in a row."""
    ids = _build(route, api, data, [("PL dup A", "city_hall", SOFT), ("PL dup B", "city_hall", SOFT),
                                    ("PL other", "brannon", SOFT)])
    url = set(_links(api, ids).values()).pop()
    wps = _waypoints(url)
    for a, b in zip(wps, wps[1:]):
        assert a.lower() != b.lower(), f"same address twice in a row: {a}"


def test_PL_07_link_follows_a_manual_reorder(route, api, three_stop_route):
    r = three_stop_route
    before = set(_links(api, r["ids"]).values()).pop()
    route.stop(3).move_up()
    route.wait_quiet()
    # Read the order only after a refresh, like RE-01 — reading the list while it
    # was still being redrawn gave the OLD order (flaky failure 2026-09-26 20:00:
    # the saved link already had the moved stop 2nd; the screen hadn't caught up).
    route.pick_date(SANDBOX_DATE)
    order = _ui_order(route)
    after = set(_links(api, r["ids"]).values())
    assert len(after) == 1, "after a move every job should still share one link"
    after = after.pop()
    assert after != before, "the link didn't change after moving a stop"
    wps = _waypoints(after)
    for i, (wp, jid) in enumerate(zip(wps, order)):
        assert wp.lower().startswith(r["street"][jid].lower()), \
            f"after the move, waypoint {i + 1} is '{wp}' but stop {i + 1} is {jid}"

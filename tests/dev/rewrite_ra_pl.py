"""2026-10-13: bring test_route_approve_link.py up to the 2026-10-05 route
design (db_route_ops.db_approve_route_schedule / db_write_route_stops):
  * Approve is a pure flag — it NEVER writes a job's Start/End Time
  * the Approve button shows for any routed day (approval unlocks email + link)
  * the phone map link is pinned on every routed job ONLY when approved; a
    rewrite (rebuild / reorder) un-approves and unpublishes it
Replaces the module docstring and RA_01 .. PL_07; keeps the helpers."""
from pathlib import Path

p = Path(__file__).resolve().parents[2] / "tests/gui_jobs_e2e/test_route_approve_link.py"
s = p.read_text(encoding="utf-8")

doc_end = s.index('"""', 3) + 3
s = '''"""Phase 2 completion (spec §6.5.4, §6.5.5): Approve / Un-approve (RA) and
the saved phone map link (PL) — updated 2026-10-13 to the 2026-10-05 design:

RA — Approve is a pure flag. It NEVER changes a job's Start / End Time (a
job's window always reflects the customer's settings); it unlocks the route
email and pins the phone map link. The Approve button shows for any routed day.
PL — once approved, every job on the route carries the same Google Maps link:
no start point (open-ended), stops in route order, never the same address
twice in a row, at most 9 stops. Rewriting the route (a manual reorder)
un-approves it and unpublishes the link until it's approved again.

Run: run_tests_gui_jobs_e2e.bat --human -k "RA_ or PL_"
"""''' + s[doc_end:]

start = s.index("def test_RA_01_approve_writes_planned_times_to_soft_jobs_only")
s = s[:start] + '''def _times(j):
    return _minutes(j.get("Start Time")), _minutes(j.get("End Time"))


def test_RA_01_approve_never_changes_job_times_and_pins_the_link(route, api, three_stop_route):
    r = three_stop_route
    _approve(route)
    jobs = _jobs_by_id(api, r["ids"])
    for jid in r["soft"]:
        assert _times(jobs[jid]) == (8 * 60, 17 * 60), \\
            f"{jid}: approve changed the soft window: {jobs[jid].get('Start Time')}–{jobs[jid].get('End Time')}"
    assert _times(jobs[r["hard"]]) == (11 * 60, 11 * 60 + 30), "approve changed the Hard job's time"
    links = _links(api, r["ids"])
    assert len(set(links.values())) == 1 and "" not in links.values(), f"approve didn't pin one shared link: {links}"


def test_RA_02_unapprove_unpublishes_the_link_and_keeps_times(route, api, three_stop_route):
    r = three_stop_route
    _approve(route)
    msgs = _unapprove(route)
    assert msgs, "Un-approve should ask for confirmation"
    assert set(_links(api, r["ids"]).values()) == {""}, "un-approve left a published link"
    jobs = _jobs_by_id(api, r["ids"])
    for jid in r["soft"]:
        assert _times(jobs[jid]) == (8 * 60, 17 * 60), f"{jid}: times changed"


def test_RA_03_approve_shown_for_a_hard_only_route(clean_slate, route, api, data):
    ids = _build(route, api, data, [("RA hard only 1", "city_hall", HARD),
                                    ("RA hard only 2", "brannon",
                                     dict(HARD, **{"Start Time": "13:00", "End Time": "13:30"}))])
    _approve(route)
    links = _links(api, ids)
    assert len(set(links.values())) == 1 and "" not in links.values(), f"approve didn't pin the link: {links}"

# RA-04 (Email Route, safe tier: recorded with the right date, nothing sent) is
#   test_BTN_ROUTE_email_route_is_guarded in test_buttons.py.
# RA-05 (one REAL email) only runs with --tier email — see below.


@pytest.mark.skipif(__import__("os").environ.get("E2E_TIER", "safe") not in ("email", "full"),
                    reason="sends one real email — run with --tier email")
def test_RA_05_email_route_really_sends_once(route, guard, three_stop_route):
    _approve(route)                               # email is only allowed for approved routes
    route.page.locator("#routeEmailRouteBtn").click()
    route.wait_quiet()
    assert guard.real_emails_sent == 1


# ── PL: the saved phone map link (pinned on approval) ────────────────────────
def _links(api, ids):
    return {jid: (j.get("Route Map URL") or "").strip() for jid, j in _jobs_by_id(api, ids).items()}


def _ui_order(route):
    return [s.job_id() for s in route.stops()]


def _check_link(route, r_street, url):
    q = parse_qs(urlsplit(url).query)
    assert "origin" not in q, "PL-01: the link must not set a start point (open-ended)"
    assert q.get("destination", [""])[0], "PL-02: the link needs a destination (end of day)"
    wps = _waypoints(url)
    order = _ui_order(route)
    assert len(wps) == len(order), f"PL-03: {len(wps)} waypoints vs {len(order)} stops on screen"
    for i, (wp, jid) in enumerate(zip(wps, order)):
        assert wp.lower().startswith(r_street[jid].lower()), \\
            f"PL-03: waypoint {i + 1} is '{wp}', but stop {i + 1} on screen is {jid} ({r_street[jid]})"
    for a, b in zip(wps, wps[1:]):
        assert a.lower() != b.lower(), f"PL-04: same address twice in a row: {a}"
    assert len(wps) <= 9, f"PL-05: {len(wps)} waypoints — Google Maps allows at most 9"


def test_PL_00_no_link_before_approval(route, api, three_stop_route):
    assert set(_links(api, three_stop_route["ids"]).values()) == {""}, \\
        "an unapproved route must not publish a link"


def test_PL_01_to_06_link_is_open_ended_ordered_and_shared(route, api, three_stop_route):
    r = three_stop_route
    _approve(route)
    links = _links(api, r["ids"])
    urls = set(links.values())
    assert len(urls) == 1 and "" not in urls, f"PL-06: every routed job should carry the SAME link: {links}"
    _check_link(route, r["street"], urls.pop())


def test_PL_04_same_address_pair_appears_once_in_the_link(clean_slate, route, api, data):
    """R-001: two jobs at one address must not make the link stop twice in a row."""
    ids = _build(route, api, data, [("PL dup A", "city_hall", SOFT), ("PL dup B", "city_hall", SOFT),
                                    ("PL other", "brannon", SOFT)])
    _approve(route)
    urls = set(_links(api, ids).values())
    assert len(urls) == 1 and "" not in urls, f"no shared link after approve: {urls}"
    wps = _waypoints(urls.pop())
    assert wps, "the link has no waypoints"
    for a, b in zip(wps, wps[1:]):
        assert a.lower() != b.lower(), f"same address twice in a row: {a}"


def test_PL_07_reorder_unpublishes_and_reapprove_follows_the_new_order(route, api, three_stop_route):
    r = three_stop_route
    _approve(route)
    before = set(_links(api, r["ids"]).values()).pop()
    assert before, "no link after approve"
    route.stop(3).move_up()
    route.wait_quiet()
    # a rewritten route is experimental until re-approved: the link is unpublished
    assert set(_links(api, r["ids"]).values()) == {""}, "a reordered route still shows its old link"
    # Read the order only after a refresh, like RE-01 (flaky 2026-09-26 otherwise).
    route.pick_date(SANDBOX_DATE)
    _approve(route)
    after = set(_links(api, r["ids"]).values())
    assert len(after) == 1 and "" not in after, "after re-approve every job should share one link"
    after = after.pop()
    assert after != before, "the re-approved link didn't change after moving a stop"
    _check_link(route, r["street"], after)
'''
compile(s, str(p), "exec")
p.write_text(s, encoding="utf-8")
print("test_route_approve_link.py rewritten to the 2026-10-05 design")

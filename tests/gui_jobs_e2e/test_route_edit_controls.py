"""RE-01, RE-02, RE-07, RE-08, RE-09, RE-11, RE-12 (spec §6.5.3).

Deferred: RE-03 (✋ drag — needs pointer-event simulation), RE-04 (move then
move back — needs stable ETA comparison), RE-05 (hard-violation styling —
needs a Hard job placed where it can't make its time), RE-06 (✏️ duration
edit — needs the job-edit-form page object, not built yet), RE-10 (re-route
after RE-08), RE-13 (tap-to-select outline/leg highlight).
"""
import pytest

from safety import SANDBOX_DATE


@pytest.fixture
def routed_four(clean_slate, data, route):
    ids = [data.job(f"RE {i}", place) for i, place in
           enumerate(["city_hall", "brannon", "library", "flagler"], start=1)]
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.expect_stops_include(ids)
    return ids


def test_RE_01_move_up(route, routed_four):
    third = route.stop(3).job_id()
    route.stop(3).move_up()
    route.pick_date(SANDBOX_DATE)  # refresh to authoritative order
    assert route.stop(2).job_id() == third, "stop 3 didn't become stop 2"


def test_RE_02_move_down_and_edge_disabled(route, routed_four):
    first = route.stop(1).job_id()
    assert route.stop(1).up_disabled(), "▲ should be disabled on the first stop"
    assert route.stop(len(routed_four)).down_disabled(), "▼ should be disabled on the last stop"
    route.stop(1).move_down()
    route.pick_date(SANDBOX_DATE)
    assert route.stop(2).job_id() == first, "stop 1 didn't become stop 2"


def test_RE_07_remove_cancel_keeps_stop(route, routed_four):
    jid = routed_four[0]
    msg = route.stop(jid).remove(confirm=False)
    assert msg.startswith('Take "') and "kept" in msg.lower()
    route.pick_date(SANDBOX_DATE)
    route.expect_stops_include(routed_four)


def test_RE_08_remove_ok_moves_job_to_not_on_route(route, routed_four, api):
    jid = routed_four[0]
    msg = route.stop(jid).remove(confirm=True)
    assert "kept" in msg.lower() and "not deleted" in msg.lower()
    route.pick_date(SANDBOX_DATE)
    route.expect_stops_include(routed_four[1:])
    route.expect_not_on_route([jid])
    jobs = api.read("Jobs_Schedule")
    assert any(j.get("JobID (JOB-####)") == jid for j in jobs), "job was deleted, not just un-routed"


def test_RE_09_job_added_after_routing_appears_not_on_route(route, routed_four, data):
    new_id = data.job("RE09 added late", "sports")
    route.pick_date(SANDBOX_DATE)
    route.expect_stops_include(routed_four)
    route.expect_not_on_route([new_id])


def test_RE_11_help_panel_mentions_all_controls(route, routed_four, page):
    toggle = page.get_by_test_id("route-help-toggle")
    body = page.locator(".route-help-body")
    assert not body.is_visible()
    toggle.click()
    assert body.is_visible()
    text = body.inner_text().lower()
    for word in ("move up", "drag", "edit", "remove", "email", "approve"):
        assert word in text, f"help panel missing mention of '{word}'"
    toggle.click()
    assert not body.is_visible()


def test_RE_12_tooltips_present(route, routed_four):
    stop = route.stop(2)  # a middle stop so both ▲ and ▼ are enabled
    for testid in ("stop-up", "stop-down", "stop-edit", "stop-remove", "stop-drag"):
        el = stop.row.get_by_test_id(testid)
        title = el.get_attribute("title")
        assert title and title.strip(), f"{testid} has no tooltip"

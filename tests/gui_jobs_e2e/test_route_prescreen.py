"""PS-01..PS-06, PS-08..PS-11, PS-14, PS-15 (spec §6.5.2).

The Jobs-app API's prescreen_route_jobs only exposes ONE error category for
address collisions (DUPLICATE_ADDRESS — see its own tool description), so
PS-01 (same customer) and PS-02 (different customer, same address) are
expected to produce the same kind of error; assertions below check for the
category by keyword ("duplicate"/"address") rather than the spec table's
exact example wording, which was the spec author's paraphrase, not a
guaranteed literal string.

Deferred for a later pass: PS-07 (cancelled job at a duplicate address),
PS-12 (highlight for a "not on this route" job), PS-13 (✏️ chip opens the
job), PS-16 (3+ problems scroll inside their box), PS-17 (prescreen API
failure still lets routing proceed).
"""
import pytest

from safety import SANDBOX_DATE

SAME_ADDR = "city_hall"  # data.PLACES key — exact same street+coords


@pytest.fixture
def isolated(clean_slate, data):
    """Every PS test wants a clean sandbox date with only its own job(s)."""
    return data


def _titles(route):
    return [t.strip() for t in route.prescreen_box().locator(".ps-title").all_inner_texts()]


def test_PS_01_duplicate_job_same_customer_same_address(route, isolated):
    isolated.job("PS01 A", SAME_ADDR)
    isolated.job("PS01 B", SAME_ADDR)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)
    titles = " ".join(_titles(route)).lower()
    assert "duplicate" in titles or "same address" in titles, _titles(route)


def test_PS_02_two_customers_same_address_written_differently(route, isolated, api):
    out = api.call("create_customer", {"updates": {"Company Name": "ZTEST E2E Customer 2",
                    "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168",
                    "Status Active/Inactive": "Active"}})
    cust2 = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    isolated.job("PS02 A", SAME_ADDR, street="210 Sams Ave")
    isolated.job("PS02 B", SAME_ADDR, street="210 Sams Avenue", CustomerID=cust2)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)
    titles = " ".join(_titles(route)).lower()
    assert "duplicate" in titles or "same address" in titles, _titles(route)


def test_PS_03_near_neighbors_are_not_a_duplicate(route, isolated):
    # R-002: 1730 vs 1755 State Road 44, ~6 m apart — real neighbors, not a
    # geocoding collision. Reproduced with a small explicit coordinate offset.
    isolated.job("PS03 A", "city_hall", street="1730 State Road 44", lat=29.0258, lon=-80.9270)
    isolated.job("PS03 B", "city_hall", street="1755 State Road 44", lat=29.02585, lon=-80.92695)
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    route.expect_prescreen(errors=0)  # may still have 0+ warnings, just no duplicate error


def test_PS_04_no_street_address(route, isolated):
    jid = isolated.job("PS04 no address", "city_hall", street="")
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    titles = " ".join(_titles(route)).lower()
    assert "address" in titles, _titles(route)
    route.press_route_selected_date(accept_errors=True)
    route.pick_date(SANDBOX_DATE)
    assert jid not in [s.job_id() for s in route.stops()], "job with no address was routed"


def test_PS_05_hard_job_no_start_time_is_a_warning(route, isolated):
    isolated.job("PS05 hard no time", "city_hall", **{"Schedule Type (Hard/Soft)": "Hard"})
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    route.expect_prescreen(errors=0, warnings=1)


def test_PS_06_overlapping_hard_appointments(route, isolated):
    common = {"Schedule Type (Hard/Soft)": "Hard", "Start Time": "09:00", "End Time": "10:00"}
    isolated.job("PS06 A", "city_hall", **common)
    isolated.job("PS06 B", "brannon", **common)
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    titles = " ".join(_titles(route)).lower()
    assert "overlap" in titles, _titles(route)


def test_PS_08_errors_present_stop_routing_on_cancel(route, isolated):
    isolated.job("PS08 A", SAME_ADDR)
    isolated.job("PS08 B", SAME_ADDR)
    route.pick_date(SANDBOX_DATE)
    msg = route.press_route_selected_date(accept_errors=False)
    assert msg.startswith("Prescreen found"), msg
    assert "route anyway" in msg.lower() and "fix them first" in msg.lower()
    route.pick_date(SANDBOX_DATE)  # refresh view
    assert route.unrouted_jobs(), "routing should not have happened — jobs still unrouted"


def test_PS_09_errors_present_route_anyway_no_bad_link(route, isolated, api):
    jidA = isolated.job("PS09 A", SAME_ADDR)
    jidB = isolated.job("PS09 B", SAME_ADDR)
    route.pick_date(SANDBOX_DATE)
    msg = route.press_route_selected_date(accept_errors=True)
    assert msg.startswith("Prescreen found")
    route.pick_date(SANDBOX_DATE)
    route.expect_stops_include([jidA, jidB])


def test_PS_10_warnings_only_no_dialog_route_builds(route, isolated):
    isolated.job("PS10 hard no time", "city_hall", **{"Schedule Type (Hard/Soft)": "Hard"})
    route.pick_date(SANDBOX_DATE)
    # Warnings only: pressing the route button must NOT ask 'route anyway?'
    # and must build the route, with the warning still listed afterwards.
    asked = route.run_prescreen()
    assert asked == "", f"warnings alone should not ask before routing, but it asked: {asked!r}"
    route.expect_prescreen(errors=0, warnings=1)
    assert route.stops(), "warnings only — the route should have been built"


def test_PS_11_tap_prescreen_item_highlights_job(route, isolated):
    jid = isolated.job("PS11 no address", "city_hall", street="")
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    route.tap_prescreen_item(0)
    route.expect_highlighted_jobs([jid])


def test_PS_14_fix_then_recheck_clears_item(route, isolated, api):
    jid = isolated.job("PS14 no address", "city_hall", street="")
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    route.expect_prescreen(errors=1)
    api.call("update_job_spreadsheet", {"job_identifier": jid, "sheet_name": "Jobs_Schedule",
                                         "id_column": "JobID (JOB-####)",
                                         "updates": {"Street Address": "210 Sams Ave"}})
    route.prescreen_recheck()
    route.expect_prescreen(errors=0, warnings=0)


def test_PS_15_close_panel(route, isolated):
    isolated.job("PS15 no address", "city_hall", street="")
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    route.expect_prescreen(errors=1)
    route.prescreen_close()
    route.expect_no_prescreen()

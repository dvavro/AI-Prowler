"""OCT21-01..OCT21-09 — David's four Jobs-app learnings of 2026-10-21.

  OCT21-01..03  Route map pull-down bar: on a PC-size window, dragging the
                bar DOWN grows the map and UP shrinks it (before the fix the
                bar SHRANK the map on a laptop screen and could never grow it).
  OCT21-04..05  Recurring 🔮 projections land on the customer's Preferred
                Day(s): every projected date of a Weekly "Thursday" customer is
                a Thursday, and the monthly rhythm doesn't creep.
  OCT21-06..07  "Settings aren't filled out" warning: lists exactly the
                missing required settings, its button opens the Settings tab,
                and it disappears when nothing is missing.
  OCT21-08..09  Reports: a calendar-year "Net Revenue (after sales tax)" card,
                and the job-by-job net math (tax taken off invoiced jobs once,
                pre-tax estimates left alone).

Live-browser Playwright tests on David's PC, sandbox data only (ZTEST_).
Run them visibly, like every Jobs GUI test:
    run_tests.bat jobs-sandbox --human -k oct21
"""
import datetime as _dt
import re

import pytest
from playwright.sync_api import expect

from safety import SANDBOX_DATE, ZTEST_PREFIX

PREF_CUST = f"{ZTEST_PREFIX} Preferred Thursday"


# ── Route map pull-down bar on a PC-size window ─────────────────────────────
def _map_h(page):
    return page.evaluate("() => document.getElementById('routeMap').getBoundingClientRect().height")


def _settled_box(page):
    """Wait until the route screen stops loading and the bar stops moving —
    the first visit fires a burst of sheet reads that re-lay the page out,
    and a drag started mid-shuffle grabs the bar at a stale position."""
    try:
        page.wait_for_load_state("networkidle", timeout=15_000)
    except Exception:
        pass
    last = None
    for _ in range(20):
        page.evaluate("() => document.getElementById('routeMapResize').scrollIntoView({block:'center'})")
        page.wait_for_timeout(250)
        box = page.locator("#routeMapResize").bounding_box()
        if last and abs(box["y"] - last["y"]) < 1 and abs(_map_h(page) - last["h"]) < 1:
            return box
        last = dict(box, h=_map_h(page))
    return box


def _drag_bar(page, dy):
    box = _settled_box(page)
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.mouse.move(x, y)
    page.mouse.down()
    steps = 10
    for k in range(1, steps + 1):
        page.mouse.move(x, y + dy * k / steps)
    page.mouse.up()
    page.wait_for_timeout(400)


@pytest.fixture
def pc_route(app, page):
    page.set_viewport_size({"width": 1366, "height": 768})
    app.goto("route")
    expect(page.locator("#routeMapResize")).to_be_visible(timeout=30_000)
    return page


def test_OCT21_01_pc_drag_down_grows_the_map(app, pc_route):
    page = pc_route
    _settled_box(page)
    before = _map_h(page)
    app.step(f"ROUTE map {before:.0f}px - drag the bar DOWN 150px with the mouse")
    _drag_bar(page, 150)
    after = _map_h(page)
    app.step(f"ROUTE map now {after:.0f}px")
    assert after > before + 100, f"dragging down should grow the map: {before} -> {after}"


def test_OCT21_02_pc_drag_up_shrinks_the_map(app, pc_route):
    page = pc_route
    _drag_bar(page, 120)
    before = _map_h(page)
    app.step(f"ROUTE map {before:.0f}px - drag the bar UP 150px")
    _drag_bar(page, -150)
    after = _map_h(page)
    assert after < before - 100, f"dragging up should shrink the map: {before} -> {after}"


def test_OCT21_03_stop_list_keeps_its_room(app, pc_route):
    page = pc_route
    _drag_bar(page, 300)
    list_h = page.evaluate("() => document.getElementById('routeStopsList').offsetHeight")
    assert list_h >= 119, f"stop list squeezed to {list_h}px"


# ── Recurring projections follow Preferred Day(s) ───────────────────────────
@pytest.fixture
def thursday_customer(clean_slate, api, data):
    """A Weekly customer whose Preferred Day is Thursday, last serviced on a
    day that is NOT a Thursday, so a raw +7 days would never land on one."""
    sb = _dt.date.fromisoformat(SANDBOX_DATE)
    last = sb - _dt.timedelta(days=7)
    while last.weekday() == 3:                      # make sure it isn't a Thursday
        last -= _dt.timedelta(days=1)
    out = api.call("create_customer", {"updates": {
        "Company Name": PREF_CUST,
        "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168",
        "Status Active/Inactive": "Active",
        "Frequency": "Weekly",
        "Preferred Day(s)": "Thursday"}})
    cid = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    data.job("OCT21 last weekly visit", date=last.isoformat(), CustomerID=cid,
             **{"Customer Name / Company": PREF_CUST, "Job Status": "Complete"})
    return cid


def test_OCT21_04_projections_land_on_the_preferred_day(app, page, thursday_customer):
    res = page.evaluate("""async (name) => {
        const raw = await mcpCall('read_job_spreadsheet', {sheet_name: 'Customers', max_rows: 500});
        const rows = _routeParseSheetText(raw || '');
        const mine = rows.filter(r => (r['Company Name'] || '') === name);
        const p = _calRecurringProjections(mine);
        return {pref: mine.length ? _custPreferredDaysText(mine[0]) : null,
                days: p.map(x => new Date(x.date + 'T12:00:00').getDay())};
    }""", PREF_CUST)
    app.step(f"PROJECTIONS {len(res['days'])} visits, Preferred Day(s)={res['pref']!r}")
    assert res["pref"] and "thu" in res["pref"].lower(), res
    assert len(res["days"]) >= 40, res            # ~52 weekly visits in 12 months
    assert set(res["days"]) == {4}, f"every visit must be a Thursday (4): {sorted(set(res['days']))}"


def test_OCT21_05_preferred_day_rules(app, page):
    r = page.evaluate("""() => {
        const keys = s => s ? Object.keys(s).map(Number).sort() : null;
        const d = (iso) => new Date(iso + 'T12:00:00');
        const snap = (iso, txt) => _dkey(_snapToPreferredDay(d(iso), _prefDaySet(txt)));
        // Monthly customer, Preferred Mon: rhythm counted from the unsnapped dates
        const proj = _calRecurringProjections([{ 'Company Name': 'ZTEST Monthly Mon', 'Frequency': 'Monthly',
            'Last Service Date': _dkey(new Date()), 'Preferred Day(s)': 'Monday' }]);
        return {
          slash: keys(_prefDaySet('Monday/Friday')), range: keys(_prefDaySet('Mon-Wed')),
          wrap: keys(_prefDaySet('Fri-Mon')), weekdays: keys(_prefDaySet('Weekdays')),
          blank: _prefDaySet(''), typo: _prefDaySet('Thurzday'),
          sameDay: snap('2026-10-22', 'Thursday'), forward: snap('2026-10-23', 'Thursday'),
          none: snap('2026-10-23', ''),
          monthlyDays: proj.map(p => new Date(p.date + 'T12:00:00').getDay()),
          monthlyGaps: proj.slice(1).map((p, i) => (new Date(p.date) - new Date(proj[i].date)) / 864e5),
          monthlyCount: proj.length,
        };
    }""")
    assert r["slash"] == [1, 5] and r["range"] == [1, 2, 3] and r["wrap"] == [0, 1, 5, 6], r
    assert r["weekdays"] == [1, 2, 3, 4, 5], r
    assert r["blank"] is None and r["typo"] is None, "blank/unknown must mean NO constraint"
    assert r["sameDay"] == "2026-10-22" and r["forward"] == "2026-10-29" and r["none"] == "2026-10-23", r
    assert set(r["monthlyDays"]) == {1}, r
    # 12 monthly steps; snapping moves a visit 0-6 days but never doubles one
    # up or lets the rhythm creep (each gap stays a month, give or take 6 days)
    assert r["monthlyCount"] in (11, 12), r
    assert all(22 <= g <= 37 for g in r["monthlyGaps"]), r["monthlyGaps"]


# ── "Settings aren't filled out" warning ─────────────────────────────────────
def test_OCT21_06_missing_settings_are_listed(app, page):
    r = page.evaluate("""() => {
        const full = ['Tax Rate','Business Name','Business Address','Business Phone','Business Email']
          .map(k => '  Setting: ' + k + '\\n  Value: x\\n  Notes: n').join('\\n\\n');
        const noTax = full.replace('  Setting: Tax Rate\\n  Value: x', '  Setting: Tax Rate');
        return { full: _missingRequiredSettings(full), noTax: _missingRequiredSettings(noTax),
                 empty: _missingRequiredSettings(''), required: _requiredSettingKeys() };
    }""")
    assert r["required"] == ["Tax Rate", "Business Name", "Business Address", "Business Phone", "Business Email"]
    assert r["full"] == [] and r["noTax"] == ["Tax Rate"] and r["empty"] == r["required"], r


def test_OCT21_07_warning_banner_opens_settings_and_goes_away(app, page):
    app.step("SETTINGS show the warning for two missing settings")
    page.evaluate("() => _renderSettingsWarning(['Tax Rate', 'Business Phone'])")
    bar = page.get_by_test_id("settings-warning")
    expect(bar).to_be_visible()
    expect(bar).to_contain_text("Settings tab")
    expect(bar).to_contain_text("Tax Rate, Business Phone")
    app.step("SETTINGS tap Open Settings")
    page.get_by_test_id("settings-warning-open").click()
    expect(page.locator("#screenSheet")).to_have_class(re.compile(r"\bactive\b"), timeout=15_000)
    assert page.evaluate("() => _activeSheet") == "Settings"
    page.evaluate("() => _renderSettingsWarning([])")
    expect(page.get_by_test_id("settings-warning")).to_have_count(0)


# ── Reports: yearly Net revenue (after sales tax) ────────────────────────────
def test_OCT21_08_reports_shows_the_yearly_net_revenue_card(app, page):
    app.goto("reports")
    card = page.get_by_test_id("reports-year-net")
    expect(card).to_be_visible(timeout=60_000)
    year = str(_dt.date.today().year)
    expect(card).to_contain_text("Net Revenue (after sales tax)")
    expect(card).to_contain_text(year)
    expect(page.get_by_test_id("reports-year-net-total")).to_contain_text("projected")
    card.scroll_into_view_if_needed()
    app.step("REPORTS yearly Net Revenue card shown")


def test_OCT21_09_net_revenue_math(app, page):
    r = page.evaluate("""() => {
        const y = new Date().getFullYear();
        const iso = (m) => y + '-' + String(m).padStart(2, '0') + '-15';
        const rows = [
          { 'JobID (JOB-####)': 'J1', 'Service Date': iso(1), 'Job Status': 'Complete' },   // paid in full
          { 'JobID (JOB-####)': 'J2', 'Service Date': iso(2), 'Job Status': 'Complete' },   // invoiced, unpaid
          { 'JobID (JOB-####)': 'J3', 'Service Date': iso(3), 'Job Status': 'Complete' },   // half paid
          { 'JobID (JOB-####)': 'J4', 'Service Date': iso(4), 'Job Status': 'Scheduled',
            'Quote Amount ($)': '100', 'Discount Applied ($)': '10' },                       // not invoiced: pre-tax
          { 'JobID (JOB-####)': 'J5', 'Service Date': iso(5), 'Job Status': 'Complete', 'No Sales Tax': 'Yes' },
          { 'JobID (JOB-####)': 'J6', 'Service Date': iso(6), 'Job Status': 'Cancelled', 'Quote Amount ($)': '999' },
          { 'JobID (JOB-####)': 'J7', 'Service Date': (y - 1) + '-06-15', 'Job Status': 'Complete' },  // last year
        ];
        const inv = { J1: {totalDue: 107, amountPaid: 107, tax: 7}, J2: {totalDue: 107, amountPaid: 0, tax: 7},
                      J3: {totalDue: 214, amountPaid: 107, tax: 14}, J5: {totalDue: 100, amountPaid: 100, tax: 0},
                      J7: {totalDue: 500, amountPaid: 500, tax: 0} };
        const m = _reportsYearNet(rows, inv, {}, [], new Date(y, 6, 1));
        return m.map(x => [Math.round(x.actualNet * 100) / 100, Math.round(x.projNet * 100) / 100]);
    }""")
    assert r[0] == [100, 0], f"Jan paid 107 incl 7 tax -> 100 net actual: {r[0]}"
    assert r[1] == [0, 100], f"Feb unpaid 107 incl 7 tax -> 100 net projected: {r[1]}"
    assert r[2] == [100, 100], f"Mar half of 214 incl 14 tax: {r[2]}"
    assert r[3] == [0, 90], f"Apr not invoiced: 100 - 10 discount, already pre-tax: {r[3]}"
    assert r[4] == [100, 0], f"May tax-exempt: {r[4]}"
    assert r[5] == [0, 0], f"Jun cancelled job never counts: {r[5]}"
    assert sum(a + p for a, p in r) == 590, "last year's job must not count"

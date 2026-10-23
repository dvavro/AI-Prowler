"""WKP-01..WKP-06 — "🗓️ Plan Week with Any AI" on the Route tab (2026-10-22).

The user copies a week prompt (WK- code) into any AI chat connected to
AI-Prowler. The chat reads the week (get_week_plan_data) and SUGGESTS moving
soft jobs so jobs near each other share a day (propose_week_moves). Nothing
changes until the user approves the moves in the Jobs app (apply_week_moves)
or dismisses them. The server-side checks (hard jobs fixed, working days,
Preferred Day(s), not in the past, date only, crew) are unit-tested in
tests/mcp_tests/test_week_plan.py.

Here the "AI chat" is played by the test itself through the Jobs-app API —
the same two calls a real chat makes — so no AI credits are spent.

  WKP-01  PC: the button sits between 📋 Copy AI Route and 📧 Email; phone
          shows "🗓️ Week"
  WKP-02  sheet: the week defaults to the Route date's Monday; picking another
          day re-labels the week; Copy makes a WK- prompt
  WKP-03  Check with no suggestion waiting -> "No suggestions waiting"
  WKP-04  the AI suggests a move -> Check lists it -> Approve moves the job
          (date only) and the suggestion is closed
  WKP-05  Dismiss moves nothing and closes the suggestion
  WKP-06  untick one of two moves -> only the ticked one moves

Sandbox data only (ZTEST_, inside the sandbox window). Run visibly:
    run_tests.bat jobs-sandbox --human -k WKP
"""
import datetime as _dt
import json
import re

import pytest
from playwright.sync_api import expect

from api import iso_date
from data import PLACES  # noqa: F401  (city_hall / brannon are ~0.3 mi apart)
from safety import SANDBOX_DATE, SANDBOX_DAYS_AFTER, ZTEST_PREFIX


def _plan_week():
    """(monday, [weekday dates]) — the first week that has two or more
    weekdays from today on inside the sandbox window, so test jobs can be
    moved between them (moves never go into the past)."""
    base = _dt.date.fromisoformat(SANDBOX_DATE)
    weeks = {}
    for off in range(0, SANDBOX_DAYS_AFTER + 1):
        d = base + _dt.timedelta(days=off)
        if d.weekday() < 5:
            weeks.setdefault(d - _dt.timedelta(days=d.weekday()), []).append(d.isoformat())
    for mon, days in sorted(weeks.items()):
        if len(days) >= 2:
            return mon.isoformat(), days
    pytest.skip("no week with two weekdays inside the sandbox window")


MONDAY, DAYS = _plan_week()
DAY_A, DAY_B = DAYS[0], DAYS[1]


def _pending(api, monday=MONDAY):
    r = json.loads(api.call("get_week_proposal", {"week_start": monday, "crew": ""}))
    assert r.get("ok"), r
    return r.get("proposal")


def _clear_test_proposals(api):
    """Dismiss suggestions an earlier (failed) run left for this week — only
    ones whose every move is a ZTEST job."""
    for _ in range(10):
        p = _pending(api)
        if not p:
            return
        if not all(str(m.get("customer", "")).startswith(ZTEST_PREFIX) for m in p.get("moves") or []) \
                or not p.get("moves"):
            pytest.skip(f"a real Plan Week suggestion ({p.get('code')}) is waiting for this week — not touching it")
        api.call("dismiss_week_proposal", {"proposal_code": p["code"]})


@pytest.fixture
def week(clean_slate, api, route, page, app_url):
    _clear_test_proposals(api)
    try:
        page.context.grant_permissions(["clipboard-read", "clipboard-write"],
                                       origin=re.match(r"https?://[^/]+", app_url).group(0))
    except Exception:
        pass
    yield
    _clear_test_proposals(api)


def _open(page, day=DAY_A):
    page.locator("#routeWeekPlanBtn").click()
    sheet = page.locator("#aiRouteOverlay")
    expect(sheet).to_be_visible(timeout=15_000)
    page.locator("#wpWeek").fill(day)
    return sheet


def _copy_code(page, sheet):
    sheet.get_by_test_id("wp-copy").click()
    code_el = sheet.get_by_test_id("wp-prompt-code")
    expect(code_el).to_have_text(re.compile(r"^WK-[A-Z0-9]{6}$"), timeout=30_000)
    return code_el.inner_text().strip()


def _ai_suggests(api, code, moves):
    """What a pasted prompt makes the AI chat do: read the week, then suggest."""
    wk = json.loads(api.call("get_week_plan_data", {"route_code": code}))
    out = api.call("propose_week_moves", {"route_code": code, "moves": json.dumps(moves)})
    return wk, out


def _date_of(api, job_id):
    for j in api.read("Jobs_Schedule"):
        if j.get("JobID (JOB-####)", "").strip().upper() == job_id.upper():
            return iso_date(j.get("Service Date", ""))
    raise AssertionError(f"{job_id} not found")


def _check(sheet):
    sheet.get_by_test_id("wp-check").click()


# ── WKP-01 ───────────────────────────────────────────────────────────────────
def test_WKP_01_button_between_copy_and_email(route, page, app):
    page.set_viewport_size({"width": 1366, "height": 768})
    cp, wk, em = (page.locator(s) for s in ("#routeCopyAiBtn", "#routeWeekPlanBtn", "#routeEmailRouteBtn"))
    expect(wk).to_be_visible()
    expect(wk).to_contain_text("Plan Week with Any AI")
    xs = [loc.bounding_box()["x"] for loc in (cp, wk, em)]
    app.step(f"ROUTE buttons left edges: Copy {xs[0]:.0f}, Week {xs[1]:.0f}, Email {xs[2]:.0f}")
    assert xs[0] < xs[1] < xs[2], xs
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_timeout(300)
    expect(wk.locator(".lbl-short")).to_be_visible()
    expect(wk.locator(".lbl-short")).to_have_text("🗓️ Week")
    page.set_viewport_size({"width": 1366, "height": 768})


# ── WKP-02 ───────────────────────────────────────────────────────────────────
def test_WKP_02_sheet_week_and_prompt(week, route, page, app, data):
    data.job("WKP sheet job", "city_hall", date=DAY_A)
    route.pick_date(DAY_A)
    page.locator("#routeWeekPlanBtn").click()
    sheet = page.locator("#aiRouteOverlay")
    expect(sheet).to_be_visible(timeout=15_000)
    expect(page.locator("#wpWeek")).to_have_value(MONDAY)          # the Route date's Monday
    label = sheet.get_by_test_id("wp-week-label").inner_text()
    app.step(f"WEEK label {label!r} (Monday {MONDAY})")
    assert label.startswith("Mon ") and " – Sun " in label
    nxt = (_dt.date.fromisoformat(MONDAY) + _dt.timedelta(days=9)).isoformat()   # a Wednesday, next week
    page.locator("#wpWeek").fill(nxt)
    expect(sheet.get_by_test_id("wp-week-label")).not_to_have_text(label)
    page.locator("#wpWeek").fill(DAY_A)
    expect(sheet.get_by_test_id("wp-week-label")).to_have_text(label)
    code = _copy_code(page, sheet)
    text = page.locator("#wpPromptText").input_value()
    app.step(f"PROMPT {code}: {len(text)} chars")
    assert code in text and "get_week_plan_data" in text and "propose_week_moves" in text
    assert MONDAY in text
    expect(sheet.get_by_test_id("wp-prompt-status")).to_have_text(re.compile(r"Copied|Tap 📋 Copy"), timeout=10_000)
    sheet.locator("#wpClose").click()
    expect(sheet).to_have_count(0)


# ── WKP-03 ───────────────────────────────────────────────────────────────────
def test_WKP_03_check_with_nothing_waiting(week, page, app):
    sheet = _open(page)
    _check(sheet)
    expect(sheet.get_by_test_id("wp-none")).to_be_visible(timeout=15_000)
    expect(sheet.get_by_test_id("wp-move")).to_have_count(0)
    sheet.locator("#wpClose").click()


# ── WKP-04 ───────────────────────────────────────────────────────────────────
def test_WKP_04_approve_moves_the_job(week, page, app, api, data):
    a = data.job("WKP stay", "city_hall", date=DAY_A)
    b = data.job("WKP move", "brannon", date=DAY_B)
    sheet = _open(page)
    code = _copy_code(page, sheet)
    wk, out = _ai_suggests(api, code, [{"job_id": b, "to": DAY_A, "reason": f"0.3 mi from {a}"}])
    pairs = {(p["a"], p["b"]) for p in wk["nearby_pairs"]} | {(p["b"], p["a"]) for p in wk["nearby_pairs"]}
    assert (a, b) in pairs, wk["nearby_pairs"]
    assert out.startswith("✅ Saved 1"), out
    app.step(f"AI suggested: {out.splitlines()[0]}")
    assert _date_of(api, b) == DAY_B                                  # nothing changed yet
    _check(sheet)
    rows = sheet.get_by_test_id("wp-move")
    expect(rows).to_have_count(1, timeout=15_000)
    expect(rows.first).to_have_attribute("data-jobid", b)
    expect(rows.first).to_contain_text("→")
    sheet.get_by_test_id("wp-approve").click()
    expect(sheet.get_by_test_id("wp-result")).to_contain_text("Moved 1 of 1", timeout=30_000)
    assert _date_of(api, b) == DAY_A
    assert _date_of(api, a) == DAY_A                                  # the other job didn't move
    assert _pending(api) is None                                      # suggestion closed
    sheet.locator("#wpClose").click()


# ── WKP-05 ───────────────────────────────────────────────────────────────────
def test_WKP_05_dismiss_moves_nothing(week, page, app, api, data):
    data.job("WKP stay", "city_hall", date=DAY_A)
    b = data.job("WKP not moved", "brannon", date=DAY_B)
    sheet = _open(page)
    code = _copy_code(page, sheet)
    _ai_suggests(api, code, [{"job_id": b, "to": DAY_A, "reason": "nearby"}])
    _check(sheet)
    expect(sheet.get_by_test_id("wp-move")).to_have_count(1, timeout=15_000)
    sheet.get_by_test_id("wp-dismiss").click()
    expect(sheet.get_by_test_id("wp-result")).to_be_visible(timeout=15_000)
    assert _date_of(api, b) == DAY_B
    _check(sheet)
    expect(sheet.get_by_test_id("wp-none")).to_be_visible(timeout=15_000)
    sheet.locator("#wpClose").click()


# ── WKP-06 ───────────────────────────────────────────────────────────────────
def test_WKP_06_only_ticked_moves_are_applied(week, page, app, api, data):
    data.job("WKP stay", "city_hall", date=DAY_A)
    b = data.job("WKP ticked", "brannon", date=DAY_B)
    c = data.job("WKP unticked", "brannon", date=DAY_B)
    sheet = _open(page)
    code = _copy_code(page, sheet)
    _ai_suggests(api, code, [{"job_id": b, "to": DAY_A, "reason": "nearby"},
                             {"job_id": c, "to": DAY_A, "reason": "nearby"}])
    _check(sheet)
    rows = sheet.get_by_test_id("wp-move")
    expect(rows).to_have_count(2, timeout=15_000)
    sheet.locator(f'[data-testid=wp-move][data-jobid="{c}"] input[type=checkbox]').uncheck()
    sheet.get_by_test_id("wp-approve").click()
    expect(sheet.get_by_test_id("wp-result")).to_contain_text("Moved 1 of 1", timeout=30_000)
    assert _date_of(api, b) == DAY_A
    assert _date_of(api, c) == DAY_B
    sheet.locator("#wpClose").click()

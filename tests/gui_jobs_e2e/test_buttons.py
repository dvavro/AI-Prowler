"""BTN-00 — button inventory (first step of the page-by-page button sweep).

Visits each screen and records every VISIBLE clickable element: its label,
id, data-testid, title and the function its onclick calls. Written to
buttons_inventory.json in the run folder. Always passes; it's the list the
BTN-* sweep tests are built from, and re-running it shows what changed.
"""
import json
import os
from pathlib import Path

import pytest

INVENTORY_JS = r"""
(screenSel) => {
  const root = document.querySelector(screenSel);
  if (!root) return [];
  const els = root.querySelectorAll('button, [role="button"], a[onclick], [onclick]:not(button)');
  const seen = new Set();
  const out = [];
  for (const el of els) {
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    if (!r.width || !r.height || st.visibility === 'hidden' || st.display === 'none') continue;
    if (seen.has(el)) continue;
    seen.add(el);
    const oc = el.getAttribute('onclick') || '';
    const fn = (oc.match(/([A-Za-z_$][\w$]*)\s*\(/) || [])[1] || '';
    out.push({
      tag: el.tagName.toLowerCase(),
      text: (el.innerText || '').trim().replace(/\s+/g, ' ').slice(0, 60),
      id: el.id || '',
      testid: el.getAttribute('data-testid') || '',
      title: el.getAttribute('title') || el.getAttribute('aria-label') || '',
      calls: fn,
      onclick: oc.slice(0, 120),
      disabled: !!el.disabled,
    });
  }
  return out;
}
"""


def screen_selector(name: str) -> str:
    return "#screenSheet" if name == "sheet" else f"#screen-{name}"


def test_BTN_00_inventory_every_screen(app, page, data):
    # Buttons on job cards / route rows only exist when there are jobs.
    data.job("BTN inventory A", "city_hall")
    data.job("BTN inventory B", "brannon")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_timeout(1500)
    run_dir = Path(os.environ.get("E2E_RUN_DIR") or ".")
    result = {}
    for s in app.visible_screens():
        app.goto(s)
        page.wait_for_timeout(1000)
        result[s] = page.evaluate(INVENTORY_JS, screen_selector(s))
    (run_dir / "buttons_inventory.json").write_text(json.dumps(result, indent=1, ensure_ascii=False),
                                                   encoding="utf-8")
    summary = ", ".join(f"{k}: {len(v)}" for k, v in result.items())
    app.log(f"BUTTON INVENTORY {summary}")
    assert result, "no screens inventoried"


# ══════════════════════════════════════════════════════════════════════════════
# BTN sweep — every button on the Jobs and Route screens, clicked for real.
# Each is classified: SAFE (opens / refreshes / navigates), WRITE (changes
# test data on the sandbox date), or GUARDED (AI credits / outbound email —
# clicked for real, but the write guard records the call instead of letting
# it reach the server). BTN_COVERAGE fails if a screen gains a button that
# isn't classified here, so the sweep can't silently miss a new one.
# ══════════════════════════════════════════════════════════════════════════════
import re                                              # noqa: E402

from playwright.sync_api import expect                 # noqa: E402

from safety import SANDBOX_DATE                        # noqa: E402

KNOWN = {
    "jobs": {"jobsWizardBtn": "SAFE", "jobsAddBtn": "SAFE", "refreshJobsBtn": "SAFE",
             "job-card": "SAFE", "routeTodayBtn": "WRITE", "jobsAiRouteBtn": "GUARDED",
             "jobsEmailRouteBtn": "GUARDED"},
    "route": {"refreshRouteBtn": "SAFE", "routeTodayBtnRoute": "WRITE",
              "routeAiSuggestBtn": "GUARDED", "routeEmailRouteBtn": "GUARDED",
              # found by the coverage check in --human mode (2026-09-26), once
              # the map and the job list had finished loading:
              "+": "SAFE", "−": "SAFE",            # map zoom in / out
              "🏠": "SAFE", "🏁": "SAFE",           # map start / finish markers
              "unrouted-edit": "SAFE"},             # ✏️ on a job that isn't a stop yet
}


def _key(b: dict) -> str:
    return b["id"] or b["testid"] or b["calls"] or b["text"]


@pytest.fixture
def two_jobs(clean_slate, data, app, page):
    ids = [data.job("BTN A", "city_hall"), data.job("BTN B", "brannon")]
    page.evaluate("async () => { await loadJobs(); }")
    return ids


def _api_request(page, tool):
    return page.expect_request(lambda r: "/pwa-api" in r.url and f'"tool": "{tool}"' in (r.post_data or "")
                               .replace('"tool":"', '"tool": "'), timeout=20_000)


def _accept_any_dialog(page):
    msgs = []

    def h(d):
        msgs.append(d.message)
        d.accept()
    page.on("dialog", h)
    return msgs, h


def _wait_recorded(page, guard, tool, n_before, timeout_ms=30_000):
    """Wait until the write guard has recorded one more call to `tool`."""
    waited = 0
    while len(guard.recorded_calls(tool)) <= n_before and waited < timeout_ms:
        page.wait_for_timeout(250)
        waited += 250
    return guard.recorded_calls(tool)


@pytest.mark.parametrize("screen", ["jobs", "route"])
def test_BTN_COVERAGE_every_button_is_classified(app, page, two_jobs, screen):
    app.goto(screen)
    page.wait_for_timeout(1000)
    found = {_key(b) for b in page.evaluate(INVENTORY_JS, screen_selector(screen))}
    unknown = sorted(found - set(KNOWN[screen]))
    assert not unknown, (f"New button(s) on the {screen} screen not covered by the sweep: {unknown}. "
                         "Add each to KNOWN in test_buttons.py with a test.")


# ── Jobs screen ──────────────────────────────────────────────────────────────
def test_BTN_JOBS_wizard_opens(app, page, two_jobs):
    app.goto("jobs")
    page.locator("#jobsWizardBtn").click()
    expect(page.locator("#wizardModal")).to_have_class(re.compile(r"\bopen\b"))


def test_BTN_JOBS_add_opens_the_new_job_form(app, page, two_jobs):
    app.goto("jobs")
    page.locator("#jobsAddBtn").click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    page.evaluate("() => closeJobFormModal()")
    expect(page.locator("#jobFormModal")).to_be_hidden()


def test_BTN_JOBS_refresh_reloads_the_job_list(app, page, two_jobs):
    app.goto("jobs")
    with _api_request(page, "read_job_spreadsheet"):
        page.locator("#refreshJobsBtn").click()
    expect(page.locator("[data-testid='job-card']")).to_have_count(len(two_jobs))


def test_BTN_JOBS_job_card_opens_the_job(app, page, two_jobs):
    app.goto("jobs")
    page.locator(f"[data-testid='job-card'][data-jobid='{two_jobs[0]}']").click()
    expect(page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"))
    expect(page.locator("#jobModal")).to_contain_text(two_jobs[0])
    page.locator("#jobModal").click(position={"x": 5, "y": 5})        # tap outside closes
    expect(page.locator("#jobModal")).not_to_have_class(re.compile(r"\bopen\b"))


def test_BTN_JOBS_route_today_builds_todays_route(app, page, two_jobs):
    from app import RouteScreen
    app.goto("jobs")
    with _api_request(page, "suggest_route_schedule"):
        page.locator("#routeTodayBtn").click()
    expect(page.locator("#routeTodayBtn")).to_be_enabled(timeout=60_000)
    # confirm it the way a user would: today's route on the Route screen holds both jobs
    app.goto("route")
    RouteScreen(page, app.log).pick_date(SANDBOX_DATE).expect_stops_include(two_jobs)


def _click_guarded(app, page, guard, button_sel: str, tool: str):
    """Click a GUARDED button (AI credits / outbound email) and wait for the
    app's request for `tool` to actually go out — the guard answers it with a
    'recorded, not sent' reply. Waits on the real network request (like every
    other button test), not by polling the guard in a loop: that loop let all
    four guarded tests fail in --human mode on 2026-09-25 (0 calls seen in
    32 s), while passing headless. Logs before/after the click so the run log
    always shows whether the click itself completed.

    2026-10-02: waits for the RESPONSE, not just the request. The request event
    fires before the guard's route handler runs, so checking the record right
    after it raced the guard (seen 0.1 s after the click: the call WAS recorded
    a moment later, nothing reached the server). The response only exists once
    the guard has handled the call and answered it."""
    n = len(guard.recorded_calls(tool))
    msgs, h = _accept_any_dialog(page)
    try:
        btn = page.locator(button_sel)
        expect(btn).to_be_enabled(timeout=30_000)
        app.step(f"click {button_sel} ('{btn.inner_text().strip()}') — expecting a {tool} call")
        with page.expect_response(lambda r: "/pwa-api" in r.url
                                  and tool in (r.request.post_data or ""),
                                  timeout=60_000):
            btn.click()
        app.step(f"{tool} request went out and the guard answered it")
    finally:
        page.remove_listener("dialog", h)
    calls = guard.recorded_calls(tool)
    assert len(calls) == n + 1, f"{button_sel} didn't lead to a recorded {tool} call (dialogs seen: {msgs})"
    return calls[-1]


def test_BTN_JOBS_ai_route_is_guarded(app, page, two_jobs, guard):
    app.goto("jobs")
    call = _click_guarded(app, page, guard, "#jobsAiRouteBtn", "start_ai_routing")
    assert call["args"].get("route_date") == SANDBOX_DATE


def test_BTN_JOBS_email_route_is_guarded(app, page, two_jobs, guard):
    app.goto("jobs")
    call = _click_guarded(app, page, guard, "#jobsEmailRouteBtn", "email_route_now")
    assert call["args"].get("route_date") == SANDBOX_DATE
    assert guard.real_emails_sent == 0


# ── Route screen ─────────────────────────────────────────────────────────────
def test_BTN_ROUTE_refresh_reloads(app, page, two_jobs):
    app.goto("route")
    with _api_request(page, "read_job_spreadsheet"):
        page.locator("#refreshRouteBtn").click()


def test_BTN_ROUTE_route_selected_date_builds(app, page, two_jobs):
    from app import RouteScreen
    app.goto("route")
    RouteScreen(page, app.log).pick_date(SANDBOX_DATE)
    with _api_request(page, "suggest_route_schedule"):
        page.locator("#routeTodayBtnRoute").click()
    expect(page.locator("#routeTodayBtnRoute")).to_be_enabled(timeout=60_000)
    expect(page.locator("[data-testid='route-stop'][data-jobid]")).to_have_count(len(two_jobs), timeout=30_000)


def test_BTN_ROUTE_ai_route_is_guarded(app, page, two_jobs, guard):
    from app import RouteScreen
    app.goto("route")
    RouteScreen(page, app.log).pick_date(SANDBOX_DATE)
    call = _click_guarded(app, page, guard, "#routeAiSuggestBtn", "start_ai_routing")
    assert call["args"].get("route_date") == SANDBOX_DATE


def test_BTN_ROUTE_email_route_is_guarded(app, page, two_jobs, guard):
    from app import RouteScreen
    app.goto("route")
    RouteScreen(page, app.log).pick_date(SANDBOX_DATE)
    _click_guarded(app, page, guard, "#routeEmailRouteBtn", "email_route_now")
    assert guard.real_emails_sent == 0


def _map_zoom(page):
    """The Route map's real zoom level, asked of the Leaflet map itself
    (index.html keeps it as state.route.leafletMap); None if no map yet."""
    return page.evaluate("() => (state.route && state.route.leafletMap) ? state.route.leafletMap.getZoom() : null")


def _wait_zoom(page, target, timeout_ms=5000):
    waited = 0
    while _map_zoom(page) != target and waited < timeout_ms:   # Leaflet animates each zoom step
        page.wait_for_timeout(100)
        waited += 100
    return _map_zoom(page)


def _settled_zoom(page, stable_ms=1000, timeout_ms=10_000):
    """Zoom level once the map has stopped changing for `stable_ms` — after a
    date is picked the map auto-fits the day's stops, and reading mid-fit gave
    'zoom + : 13 -> 15' (2026-09-26)."""
    last, same, waited = _map_zoom(page), 0, 0
    while same < stable_ms and waited < timeout_ms:
        page.wait_for_timeout(200)
        waited += 200
        z = _map_zoom(page)
        same = same + 200 if z == last else 0
        last = z
    return last


def test_BTN_ROUTE_map_zoom_in_and_out(app, page, two_jobs):
    from app import RouteScreen
    app.goto("route")
    RouteScreen(page, app.log).pick_date(SANDBOX_DATE)
    zin = page.locator("#routeMap .leaflet-control-zoom-in")
    zout = page.locator("#routeMap .leaflet-control-zoom-out")
    expect(zin).to_be_visible(timeout=15_000)
    before = _settled_zoom(page)
    assert before is not None, "no Route map"
    zin.click()
    after_in = _settled_zoom(page)
    assert after_in > before, f"zoom + didn't zoom in: {before} -> {after_in}"
    zout.click()
    after_out = _settled_zoom(page)
    assert after_out < after_in, f"zoom − didn't zoom out: {after_in} -> {after_out}"


def test_BTN_ROUTE_map_start_and_finish_markers_respond(app, page, two_jobs):
    from app import RouteScreen
    app.goto("route")
    RouteScreen(page, app.log).pick_date(SANDBOX_DATE)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    for marker in ("🏠", "🏁"):
        m = page.locator("#screen-route").get_by_text(marker, exact=True).first
        if m.count() and m.is_visible():
            m.click()
            page.wait_for_timeout(500)
    assert not errors, errors


def test_BTN_ROUTE_unrouted_job_edit_opens_the_job(app, page, two_jobs):
    from app import RouteScreen
    app.goto("route")
    RouteScreen(page, app.log).pick_date(SANDBOX_DATE)
    edit = page.get_by_test_id("unrouted-edit").first
    expect(edit).to_be_visible(timeout=15_000)
    edit.click()
    form, detail = page.locator("#jobFormModal"), page.locator("#jobModal")
    page.wait_for_timeout(800)
    assert form.is_visible() or "open" in (detail.get_attribute("class") or ""), \
        "✏️ on an unrouted job didn't open the job"

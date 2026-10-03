"""Page objects for the Jobs app (spec §5.1). Tests call these intent-level
methods; selectors live only here (data-testid first, then stable ids)."""
from __future__ import annotations

import os

from playwright.sync_api import Page, expect

SCREENS = ["jobs", "board", "route", "calendar", "clock", "photos", "messages", "sheet", "reports", "profile"]

# "Human mode" (run_tests_gui_jobs_e2e.bat --human): characters are typed one
# at a time this many ms apart, and the launcher also sets --slowmo so every
# click / select / keypress pauses like a person would. Default is quick.
TYPE_DELAY_MS = int(os.environ.get("E2E_TYPE_DELAY", "40") or 40)
THINK_MS = int(os.environ.get("E2E_THINK_MS", "0") or 0)   # pause before typing / after a form


def type_text(page: Page, locator, text: str):
    """Click into a field and type like a person — one key at a time — instead
    of pasting it all at once with fill(). Used for EVERY text entry in the
    suite, including the login password."""
    locator.click()
    if THINK_MS:
        page.wait_for_timeout(THINK_MS)
    locator.press_sequentially(text, delay=TYPE_DELAY_MS)
    if THINK_MS:
        page.wait_for_timeout(THINK_MS)

# The app's own screen-id convention is '#screen-<name>' for every screen
# EXCEPT the Database tab, whose element is '#screenSheet' (no hyphen) — a
# known inconsistency the app's own JS special-cases too (see index.html's
# _activeScreenName(): "e.g. #screen-calendar -> 'calendar', #screenSheet ->
# 'sheet'"). Mirrored here so goto()/active_screens() match reality.
def _screen_id(name: str) -> str:
    return "screenSheet" if name == "sheet" else f"screen-{name}"


class JobsApp:
    def __init__(self, page: Page, url: str, log=None):
        self.page = page
        self.url = url
        self.log = log or (lambda *a: None)

    def step(self, msg: str):
        self.log(f"STEP {msg}")

    # ── start ────────────────────────────────────────────────────────────────
    def open(self):
        self.step(f"open {self.url}")
        self.page.goto(self.url, wait_until="domcontentloaded")
        expect(self.page.locator("#app")).to_be_visible(timeout=30_000)
        expect(self.page.locator("#authScreen")).to_be_hidden()
        return self

    def open_login_screen(self):
        self.step(f"open login screen {self.url}")
        self.page.goto(self.url, wait_until="domcontentloaded")
        expect(self.page.locator("#authScreen")).to_be_visible(timeout=30_000)
        return self

    # ── login screen ─────────────────────────────────────────────────────────
    def login(self, token: str):
        self.step("log in (token not logged)")
        type_text(self.page, self.page.locator("#authCode"), token)
        self.page.get_by_test_id("auth-unlock").click()

    def auth_error(self):
        return self.page.locator("#authError")

    # ── navigation ───────────────────────────────────────────────────────────
    def nav_button(self, screen: str):
        return self.page.get_by_test_id(f"nav-{screen}")

    def visible_screens(self) -> list[str]:
        return [s for s in SCREENS if self.nav_button(s).is_visible()]

    def goto(self, screen: str):
        self.step(f"go to screen '{screen}'")
        self.nav_button(screen).click()
        expect(self.page.locator(f"#{_screen_id(screen)}")).to_have_class(__import__("re").compile(r"\bactive\b"))
        return self

    def active_screens(self) -> list[str]:
        return self.page.eval_on_selector_all(".screen.active", "els => els.map(e => e.id)")

    # ── profile ──────────────────────────────────────────────────────────────
    def sign_out(self):
        self.step("sign out")
        self.goto("profile")
        self.page.get_by_test_id("profile-signout").click()

    # ── storage / app state ──────────────────────────────────────────────────
    def saved_auth(self):
        return self.page.evaluate("() => localStorage.getItem('ap_auth')")

    def mcp(self, tool: str, args: dict | None = None):
        """Call the app's own mcpCall() from inside the page (same auth, same guard)."""
        self.step(f"page mcpCall {tool}")
        return self.page.evaluate("([t, a]) => mcpCall(t, a)", [tool, args or {}])


# ── Route screen (spec §6.5) ─────────────────────────────────────────────────
# Confirm-dialog texts below are copied verbatim from index.html (_prescreenRoute,
# routeDeleteStop, unapproveRouteSchedule) so tests can assert on them (spec §5.3).
PRESCREEN_DIALOG_PREFIX = "Prescreen found"
DELETE_STOP_DIALOG_PREFIX = 'Take "'
UNAPPROVE_DIALOG_PREFIX = "Revert "


class Stop:
    """One row in #routeStopsList: either a real stop (data-testid="route-stop",
    has data-stopid) or an unrouted job row (data-testid="unrouted-job", no
    stop id — only .edit() applies)."""

    def __init__(self, page: Page, row, log=None):
        self.page = page
        self.row = row
        self.log = log or (lambda *a: None)

    def stop_id(self) -> str | None:
        return self.row.get_attribute("data-stopid")

    def job_id(self) -> str | None:
        return self.row.get_attribute("data-jobid")

    def index(self) -> int | None:
        v = self.row.get_attribute("data-index")
        return int(v) if v is not None else None

    def move_up(self):
        self.log(f"STEP stop {self.job_id() or self.stop_id()} move up")
        self.row.get_by_test_id("stop-up").click()
        return self

    def move_down(self):
        self.log(f"STEP stop {self.job_id() or self.stop_id()} move down")
        self.row.get_by_test_id("stop-down").click()
        return self

    def up_disabled(self) -> bool:
        return self.row.get_by_test_id("stop-up").is_disabled()

    def down_disabled(self) -> bool:
        return self.row.get_by_test_id("stop-down").is_disabled()

    def edit(self):
        """Opens the job edit form. Uses stop-edit on a real stop, unrouted-edit
        on a not-on-this-route job row."""
        self.log(f"STEP stop {self.job_id()} edit")
        btn = self.row.get_by_test_id("stop-edit")
        if btn.count() == 0:
            btn = self.row.get_by_test_id("unrouted-edit")
        btn.click()

    def remove(self, confirm: bool = True) -> str:
        """Taps 🗑️. Returns the dialog's message text (RE-07 asserts it)."""
        msg = {}

        def handle(dialog):
            msg["text"] = dialog.message
            (dialog.accept if confirm else dialog.dismiss)()

        self.page.once("dialog", handle)
        self.log(f"STEP stop {self.job_id() or self.stop_id()} remove (confirm={confirm})")
        self.row.get_by_test_id("stop-remove").click()
        self.page.wait_for_timeout(200)  # let the dialog handler run
        return msg.get("text", "")

    def select(self):
        self.row.click()

    def is_selected(self) -> bool:
        outline = self.row.evaluate("el => el.style.outline")
        return bool(outline)

    def is_hard_violation(self) -> bool:
        return "hard-violation" in (self.row.get_attribute("class") or "")

    def is_soft_violation(self) -> bool:
        return "soft-violation" in (self.row.get_attribute("class") or "")


class RouteScreen:
    def __init__(self, page: Page, log=None):
        self.page = page
        self.log = log or (lambda *a: None)

    def step(self, msg: str):
        self.log(f"ROUTE {msg}")

    # ── loading ──────────────────────────────────────────────────────────────
    def _wait_loaded(self):
        expect(self.page.locator("#routeStopsList .loader")).to_have_count(0, timeout=30_000)

    def pick_date(self, date_iso: str):
        """Selects date_iso in the Route date dropdown.

        The dropdown lists only dates (today onward) that have at least one job,
        built from the page's in-memory job list by the app's
        _populateRouteDateOptions() — and ONLY that function rebuilds it (it runs
        inside loadRoute()). Test data is created through the API after the page
        has loaded, so: refresh the job list with loadJobs(), THEN rebuild the
        dropdown. (Root cause of 25 failures on 2026-09-25 19:40: this helper
        called loadJobs() four times but never rebuilt the dropdown, so the
        option could never appear.)"""
        self.step(f"pick date {date_iso}")
        option = self.page.locator(f"#routeDatePicker option[value='{date_iso}']")
        last_err = None
        for attempt in range(3):
            self.page.evaluate("async () => { await loadJobs(); _populateRouteDateOptions(); }")
            try:
                expect(option).to_have_count(1, timeout=5_000)
                last_err = None
                break
            except Exception as e:
                last_err = e
                self.step(f"pick date {date_iso}: option not there yet (attempt {attempt + 1}), "
                          f"options now: {self.page.eval_on_selector_all('#routeDatePicker option', 'os => os.map(o => o.value)')}")
                self.page.wait_for_timeout(500)
        if last_err is not None:
            raise last_err
        self.page.locator("#routeDatePicker").select_option(date_iso)
        self._wait_loaded()
        return self

    def refresh(self):
        self.page.locator("#refreshRouteBtn").click()
        self._wait_loaded()
        return self

    # ── building ─────────────────────────────────────────────────────────────
    def press_route_selected_date(self, accept_errors: bool | None = None) -> str:
        """Presses 'Route Selected Date'. If prescreen finds errors, a native
        confirm() appears (PRESCREEN_DIALOG_PREFIX); accept_errors=True clicks
        OK ('route anyway'), False clicks Cancel ('stop'). Returns the dialog
        text seen, or '' if none appeared. Pass accept_errors=None when no
        dialog is expected (a stray one will fail the test, per spec §5.3)."""
        msg = {}

        def handle(dialog):
            msg["text"] = dialog.message
            (dialog.accept if accept_errors else dialog.dismiss)()

        if accept_errors is not None:
            # on + remove_listener (not once): a once-handler left armed when no
            # dialog appears would silently answer the NEXT dialog in the test.
            self.page.on("dialog", handle)
        try:
            self.step("press Route Selected Date")
            self.page.locator("#routeTodayBtnRoute").click()
            expect(self.page.locator("#routeTodayBtnRoute")).to_be_enabled(timeout=60_000)
            self.page.wait_for_timeout(200)
        finally:
            if accept_errors is not None:
                self.page.remove_listener("dialog", handle)
        return msg.get("text", "")

    # ── prescreen (spec §6.5.2) ──────────────────────────────────────────────
    def run_prescreen(self) -> str:
        """Shows the prescreen for the selected date the way a user gets it:
        the app runs the prescreen ONLY when a route button is pressed (not on
        picking a date). Presses 'Route Selected Date'; if the prescreen finds
        errors the app asks 'route anyway?' and this answers Cancel, so nothing
        is routed and the problems stay listed. With no errors the app doesn't
        ask and simply builds the route (fine on the sandbox date).
        Returns the dialog text, or '' if none appeared. The dialog handler is
        always removed afterwards, so it can't swallow a later dialog."""
        msg = {}

        def handle(dialog):
            msg["text"] = dialog.message
            dialog.dismiss()

        self.page.on("dialog", handle)
        try:
            self.step("run prescreen (press Route Selected Date, Cancel if it asks)")
            self.page.locator("#routeTodayBtnRoute").click()
            expect(self.page.locator("#routeTodayBtnRoute")).to_be_enabled(timeout=60_000)
            expect(self.prescreen_box()).not_to_contain_text("Checking", timeout=30_000)
        finally:
            self.page.remove_listener("dialog", handle)
        return msg.get("text", "")

    def prescreen_box(self):
        return self.page.locator("#routePrescreen")

    def prescreen_items(self):
        return self.page.locator("#routePrescreen [data-testid='prescreen-item']")

    def expect_prescreen(self, errors: int = 0, warnings: int = 0):
        box = self.prescreen_box()
        if errors == 0 and warnings == 0:
            expect(box).to_contain_text("no job problems found", timeout=15_000)
        else:
            expect(box.locator(".ps-error")).to_have_count(errors, timeout=15_000)
            expect(box.locator(".ps-warning")).to_have_count(warnings)
        return self

    def expect_no_prescreen(self):
        expect(self.prescreen_box()).to_be_empty()
        return self

    def wait_quiet(self, quiet_ms: int = 1000, timeout_ms: int = 15_000):
        """Wait until the app has had NO API request in flight for `quiet_ms` —
        what a person does without thinking: wait for the screen to stop
        changing. Found 2026-09-26 (PS-11 in --human mode): after the
        prescreen, the Route page keeps reloading its list (and geocoding the
        day's start/end) for ~1 s; a tap in that window was highlighted, then
        the redraw wiped the highlight."""
        import time
        st = {"n": 0, "t": time.monotonic()}

        def on_req(r):
            if "/pwa-api" in r.url:
                st["n"] += 1
                st["t"] = time.monotonic()

        def on_done(r):
            if "/pwa-api" in r.url:
                st["n"] = max(0, st["n"] - 1)
                st["t"] = time.monotonic()

        p = self.page
        p.on("request", on_req)
        p.on("requestfinished", on_done)
        p.on("requestfailed", on_done)
        try:
            start = time.monotonic()
            while (time.monotonic() - start) * 1000 < timeout_ms:
                p.wait_for_timeout(200)
                if st["n"] == 0 and (time.monotonic() - st["t"]) * 1000 >= quiet_ms:
                    break
        finally:
            p.remove_listener("request", on_req)
            p.remove_listener("requestfinished", on_done)
            p.remove_listener("requestfailed", on_done)
        return self

    def tap_prescreen_item(self, idx: int):
        self.wait_quiet()
        self.step(f"tap prescreen item {idx}")
        self.prescreen_items().nth(idx).click()
        return self

    def prescreen_fix(self, job_id: str):
        self.step(f"prescreen fix chip for {job_id}")
        self.prescreen_box().locator(f"[data-testid='prescreen-fix'][data-fixjob='{job_id}']").click()

    # The app draws the same prescreen panel in TWO places (#routePrescreen
    # under the map, #jobsPrescreen on the Jobs page), so its buttons exist
    # twice — always act on the Route page's copy.
    def prescreen_recheck(self):
        self.step("prescreen: Re-check")
        self.prescreen_box().get_by_test_id("prescreen-recheck").click()
        expect(self.prescreen_box()).not_to_contain_text("Re-checking", timeout=30_000)
        return self

    def prescreen_close(self):
        self.step("prescreen: close")
        self.prescreen_box().get_by_test_id("prescreen-close").click()
        return self

    # ── stops / not-on-route ─────────────────────────────────────────────────
    def stops(self) -> list[Stop]:
        rows = self.page.locator("[data-testid='route-stop']")
        return [Stop(self.page, rows.nth(i), self.log) for i in range(rows.count())]

    def stop(self, ident) -> Stop:
        """ident: a 1-based stop number (int) or a JobID (str)."""
        if isinstance(ident, int):
            row = self.page.locator(f"[data-testid='route-stop'][data-index='{ident - 1}']")
        else:
            row = self.page.locator(f"[data-testid='route-stop'][data-jobid='{ident}']")
        return Stop(self.page, row, self.log)

    def unrouted_jobs(self) -> list[Stop]:
        rows = self.page.locator("[data-testid='unrouted-job']")
        return [Stop(self.page, rows.nth(i), self.log) for i in range(rows.count())]

    def unrouted_job(self, job_id: str) -> Stop:
        return Stop(self.page, self.page.locator(f"[data-testid='unrouted-job'][data-jobid='{job_id}']"), self.log)

    # Job stops only: every route-stop row carries data-jobid, but it's empty on
    # the Company Location start/end stops (R-061) — those aren't jobs.
    JOB_STOPS = "[data-testid='route-stop'][data-jobid]:not([data-jobid=''])"   # (pre-R-061: every route-stop)

    def expect_stop_job_ids(self, job_ids: list[str]):
        expect(self.page.locator(self.JOB_STOPS)).to_have_count(len(job_ids))
        actual = [s.job_id() for s in self.stops() if s.job_id()]
        assert actual == list(job_ids), f"stop order {actual} != expected {job_ids}"
        return self

    def expect_stops_include(self, job_ids: list[str]):
        """Like expect_stop_job_ids but order-independent (route-build order
        depends on drive times, not test-controllable)."""
        expect(self.page.locator(self.JOB_STOPS)).to_have_count(len(job_ids))
        actual = sorted(s.job_id() for s in self.stops() if s.job_id())
        assert actual == sorted(job_ids), f"stops {actual} != expected {job_ids}"
        return self

    def expect_not_on_route(self, job_ids: list[str]):
        actual = sorted(s.job_id() for s in self.unrouted_jobs())
        assert actual == sorted(job_ids), f"not-on-route {actual} != expected {job_ids}"
        return self

    def expect_not_routed_banner(self, job_count: int | None = None):
        b = self.page.get_by_test_id("not-routed-banner")
        expect(b).to_be_visible()
        if job_count is not None:
            expect(b).to_contain_text(f"{job_count} job")
        return self

    def expect_no_route_no_jobs(self):
        expect(self.page.locator("#routeStopsList")).to_contain_text("No jobs on this date")
        return self

    def expect_highlighted_jobs(self, job_ids: list[str]):
        for jid in job_ids:
            expect(self.page.locator(f"[data-jobid='{jid}'].ps-highlight")).to_have_count(1)
        return self

    # ── approve / email ──────────────────────────────────────────────────────
    def approve_btn(self):
        return self.page.locator("#routeApproveBtn")

    def unapprove_btn(self):
        return self.page.locator("#routeUnapproveBtn")

    def approve(self):
        self.approve_btn().click()
        self.page.wait_for_timeout(300)
        return self

    def unapprove(self, confirm: bool = True) -> str:
        msg = {}

        def handle(dialog):
            msg["text"] = dialog.message
            (dialog.accept if confirm else dialog.dismiss)()

        self.page.once("dialog", handle)
        self.unapprove_btn().click()
        self.page.wait_for_timeout(300)
        return msg.get("text", "")

    def email_route_now(self):
        self.page.locator("#routeEmailRouteBtn").click()
        self.page.wait_for_timeout(300)
        return self

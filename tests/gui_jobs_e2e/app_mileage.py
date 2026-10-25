"""Page object for the Jobs app's mileage screens (2026-10-25):
the 🚗 Mileage tab, its bottom sheet (#miSheet: add / edit / split / fix gap /
vehicle / odometer / return / paid / cancelled-on-arrival / AI review),
Database → 🚗 Miles, Reports → Mileage & deduction, and Profile → Mileage
tracking. Selectors live only here. Text is typed key by key (human mode);
date pickers and drop-downs are set directly, like the rest of the suite."""
from __future__ import annotations

import json
import re

from playwright.sync_api import Page, expect

from app import type_text


def _tool_of(req) -> str:
    try:
        return json.loads(req.post_data or "{}").get("tool", "")
    except ValueError:
        return ""


class Mileage:
    def __init__(self, page: Page, app, log=None):
        self.page = page
        self.app = app
        self.log = log or (lambda *a: None)
        self.sheet = page.locator("#miSheet")
        self.body = page.locator("#miSheetBody")

    def step(self, msg):
        self.log(f"MILEAGE {msg}")

    # ── calls the page makes ─────────────────────────────────────────────────
    def capture(self, tool: str, action, timeout: int = 60_000) -> str:
        """Run action() (a click) and return the text result of the `tool`
        call it makes — e.g. '✅ Saved TRIP-0012 — …'."""
        with self.page.expect_response(lambda r: "/pwa-api" in r.url and _tool_of(r.request) == tool,
                                       timeout=timeout) as info:
            action()
        try:
            j = json.loads(info.value.text())
        except ValueError:
            return ""
        out = str(j.get("result", j.get("error", "")))
        self.step(f"{tool} -> {out.splitlines()[0][:160] if out else '(empty)'}")
        return out

    def wait_quiet(self, ms: int = 700):
        self.page.wait_for_timeout(ms)

    # ── Mileage tab ──────────────────────────────────────────────────────────
    def open(self, rng: str = "week"):
        self.step(f"open the Mileage tab ({rng})")
        nav = self.page.get_by_test_id("nav-mileage")
        expect(nav).to_be_visible(timeout=20_000)
        nav.click()
        expect(self.page.locator("#screen-mileage")).to_have_class(re.compile(r"\bactive\b"))
        sel = self.page.get_by_test_id("mi-range")
        if sel.input_value() != rng:
            sel.select_option(rng)
        self.loaded()
        return self

    def loaded(self):
        expect(self.page.locator("#miContent .loader")).to_have_count(0, timeout=40_000)
        return self

    def reload(self):
        self.page.evaluate("async () => { await loadMileage(); }")
        return self.loaded()

    def trip_card(self, trip_id: str):
        return self.page.locator(f"#miContent [data-testid='mi-trip'][data-trip='{trip_id}']")

    # ── the bottom sheet ─────────────────────────────────────────────────────
    def expect_sheet(self, title_part: str = ""):
        expect(self.sheet).to_be_visible(timeout=15_000)
        if title_part:
            expect(self.page.locator("#miSheetTitle")).to_contain_text(title_part)
        return self

    def close_sheet(self):
        if self.sheet.is_visible():
            self.page.evaluate("miCloseSheet()")
        return self

    def button(self, name: str):
        return self.sheet.get_by_role("button", name=re.compile(re.escape(name)))

    def type(self, el_id: str, value):
        self.step(f"type #{el_id} = {value!r}")
        el = self.page.locator(f"#{el_id}")
        el.fill("")
        if value not in (None, ""):
            type_text(self.page, el, str(value))
        return self

    def set(self, el_id: str, value):
        """date inputs: set directly (a date widget can't be typed reliably)"""
        self.step(f"set #{el_id} = {value!r}")
        self.page.locator(f"#{el_id}").fill(str(value))
        return self

    def choose(self, el_id: str, value):
        self.step(f"choose #{el_id} = {value!r}")
        self.page.locator(f"#{el_id}").select_option(str(value))
        return self

    def result_text(self, el_id: str) -> str:
        return self.page.locator(f"#{el_id}").inner_text()

    # Add trip form: (field id, kind) in screen order
    ADD_FIELDS = [("miF_date", "date"), ("miF_cat", "select"), ("miF_from", "text"), ("miF_to", "text"),
                  ("miF_purpose", "text"), ("miF_miles", "text"), ("miF_rt", "select"), ("miF_os", "text"),
                  ("miF_oe", "text"), ("miF_vehicle", "select"), ("miF_park", "text"), ("miF_toll", "text"),
                  ("miF_notes", "text")]
    EDIT_FIELDS = [("miE_date", "date"), ("miE_miles", "text"), ("miE_from", "text"), ("miE_to", "text"),
                   ("miE_purpose", "text"), ("miE_cls", "select"), ("miE_cat", "select"),
                   ("miE_vehicle", "select"), ("miE_park", "text"), ("miE_toll", "text"),
                   ("miE_reason", "text")]

    def fill(self, fields, values: dict):
        for el_id, kind in fields:
            if el_id not in values:
                continue
            v = values[el_id]
            if kind == "date":
                self.set(el_id, v)
            elif kind == "select":
                self.choose(el_id, v)
            else:
                self.type(el_id, v)
        return self

    def read(self, fields) -> dict:
        return {el_id: self.page.locator(f"#{el_id}").input_value() for el_id, _k in fields
                if self.page.locator(f"#{el_id}").count()}

    def open_add_form(self, from_miles_tab: bool = False):
        self.step("tap ＋ Add trip" + (" (Database → Miles)" if from_miles_tab else ""))
        (self.page.get_by_test_id("miles-add") if from_miles_tab else self.page.get_by_test_id("mi-add")).click()
        self.expect_sheet()
        expect(self.page.locator("#miF_to")).to_be_visible()
        return self

    def save_trip(self) -> str:
        return self.capture("add_mileage_trip", lambda: self.page.get_by_test_id("mi-save-trip").click())

    def open_trip(self, trip_id: str):
        """Tap a trip on the Mileage tab (opens the edit sheet)."""
        self.step(f"tap trip {trip_id}")
        card = self.trip_card(trip_id)
        card.scroll_into_view_if_needed()
        card.click()
        self.expect_sheet(trip_id)
        return self

    def save_edit(self) -> str:
        return self.capture("update_mileage_trip", lambda: self.page.get_by_test_id("mi-save-edit").click())

    # ── Database → 🚗 Miles ──────────────────────────────────────────────────
    def open_miles_tab(self, rng: str = "30"):
        self.step(f"Database → 🚗 Miles ({rng})")
        self.app.goto("sheet")
        self.page.locator("#sheetTabs .sheet-tab-btn[data-sheet='Miles']").click()
        expect(self.page.get_by_test_id("miles-sheet")).to_be_visible(timeout=40_000)
        r = self.page.get_by_test_id("miles-range")
        if r.input_value() != rng:
            r.select_option(rng)
            expect(self.page.get_by_test_id("miles-sheet")).to_be_visible(timeout=40_000)
            expect(self.page.get_by_test_id("miles-range")).to_have_value(rng)
        return self

    def miles_row(self, trip_id: str):
        return self.page.locator(f"#sheetContent [data-testid='miles-row'][data-trip='{trip_id}']")

    def miles_cells(self, trip_id: str) -> dict:
        cols = ["Date", "Trip", "Driver", "Vehicle", "From", "To", "Miles", "Purpose", "Type", "Entry", "Notes"]
        cells = self.miles_row(trip_id).locator("td").all_inner_texts()
        return dict(zip(cols, [c.strip() for c in cells]))

    def open_miles_row(self, trip_id: str):
        self.step(f"Database → Miles: tap {trip_id}")
        row = self.miles_row(trip_id)
        row.scroll_into_view_if_needed()
        row.click()
        self.expect_sheet(trip_id)
        return self

    # ── dialogs (confirm()) ──────────────────────────────────────────────────
    def accepting(self, action):
        """Run action() and press OK on the confirm() it raises. The handler
        is always removed, so it can't answer a later dialog."""
        seen = {}

        def h(d):
            seen["text"] = d.message
            d.accept()

        self.page.on("dialog", h)
        try:
            action()
            self.page.wait_for_timeout(300)
        finally:
            self.page.remove_listener("dialog", h)
        return seen.get("text", "")

"""Page object for the Jobs app's Getting-started wizard (index.html
openWizardModal / WIZ_STEPS). Selectors live only here."""
from __future__ import annotations

import re

from playwright.sync_api import Page, expect


class Wizard:
    def __init__(self, page: Page, log=None):
        self.page = page
        self.log = log or (lambda *a: None)
        self.modal = page.locator("#wizardModal")
        self.body = page.locator("#wizBody")

    def step(self, msg):
        self.log(f"WIZARD {msg}")

    # ── what the app says the steps are ──────────────────────────────────────
    def expected_steps(self) -> list[dict]:
        """WIZ_STEPS straight from the running app, so the test follows the
        wizard as it is today (titles, which steps have a voice example)."""
        return self.page.evaluate(
            "() => WIZ_STEPS.map(s => ({title: s.title, voice: !!s.voice, list: s.list || []}))")

    # ── actions ──────────────────────────────────────────────────────────────
    def open(self):
        self.step("open (🧙 button on the Jobs screen)")
        self.page.locator("#jobsWizardBtn").click()
        expect(self.modal).to_have_class(re.compile(r"\bopen\b"))
        return self

    def next(self):
        self.step("Next")
        self.body.get_by_role("button", name="Next", exact=True).click()

    def back(self):
        self.step("Back")
        self.body.get_by_role("button", name="Back", exact=True).click()

    def done(self):
        self.step("Done")
        self.body.get_by_role("button", name="Done", exact=True).click()

    def skip(self):
        self.step("Skip for now")
        self.body.get_by_role("button", name="Skip for now", exact=True).click()

    def click_outside(self):
        self.step("tap outside the wizard")
        self.modal.click(position={"x": 5, "y": 5})

    # ── reading ──────────────────────────────────────────────────────────────
    def is_open(self) -> bool:
        return "open" in (self.modal.get_attribute("class") or "").split()

    def expect_closed(self):
        expect(self.modal).not_to_have_class(re.compile(r"\bopen\b"))

    def expect_at(self, idx: int, total: int, title: str):
        expect(self.page.locator("#wizStepTag")).to_have_text(f"STEP {idx + 1}/{total}")
        expect(self.body.locator(".wiz-title")).to_have_text(title)
        rail = self.page.locator("#wizRail i")
        expect(rail).to_have_count(total)
        expect(self.page.locator("#wizRail i.wiz-current")).to_have_count(1)
        expect(self.page.locator("#wizRail i.wiz-done")).to_have_count(idx)

    def has_button(self, name: str) -> bool:
        b = self.body.get_by_role("button", name=name, exact=True)
        return b.count() == 1 and b.is_visible()

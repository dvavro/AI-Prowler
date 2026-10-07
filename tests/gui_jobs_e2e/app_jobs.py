"""Page object for the Jobs screen's Add / Edit Job form (#jobFormModal).
Selectors live only here. Text is typed key by key (human mode); date and
time pickers are set directly (a browser's date/time widget can't be typed
into one character at a time reliably)."""
from __future__ import annotations

import re

from playwright.sync_api import Page, expect

from app import type_text


class JobForm:
    def __init__(self, page: Page, log=None):
        self.page = page
        self.log = log or (lambda *a: None)
        self.modal = page.locator("#jobFormModal")

    def step(self, msg):
        self.log(f"JOBFORM {msg}")

    # ── opening ──────────────────────────────────────────────────────────────
    def open_new(self):
        self.step("tap + Add")
        self.page.locator("#jobsAddBtn").click()
        expect(self.modal).to_be_visible()
        # the customer list is fetched fresh each time the form opens
        expect(self.page.locator("#jfCustomer option")).not_to_have_count(1, timeout=15_000)
        return self

    def open_edit(self, job_id: str):
        self.step(f"open {job_id} and tap ✏️ Edit Job")
        self.page.locator(f"[data-testid='job-card'][data-jobid='{job_id}']").click()
        expect(self.page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"))
        self.page.locator("#jobModal").get_by_role("button", name=re.compile("Edit Job")).click()
        expect(self.modal).to_be_visible()
        expect(self.page.locator("#jfJobId")).to_have_value(job_id)
        return self

    # ── filling ──────────────────────────────────────────────────────────────
    def customer(self, customer_id: str):
        self.step(f"customer {customer_id}")
        self.page.locator("#jfCustomer").select_option(customer_id)
        return self

    def text(self, field_id: str, value: str):
        self.step(f"type {field_id} = {value!r}")
        el = self.page.locator(f"#{field_id}")
        el.fill("")
        if value:
            type_text(self.page, el, value)
        return self

    def set(self, field_id: str, value: str):
        """date / time / number inputs"""
        self.step(f"set {field_id} = {value!r}")
        self.page.locator(f"#{field_id}").fill(value)
        return self

    def choose(self, field_id: str, value: str):
        self.step(f"choose {field_id} = {value!r}")
        self.page.locator(f"#{field_id}").select_option(value)
        return self

    # ── saving ───────────────────────────────────────────────────────────────
    def save(self, tool: str | None = None):
        """Tap Save. If `tool` is given, wait for that request to go out."""
        self.step("tap Save")
        btn = self.page.locator("#jobFormSaveBtn")
        if tool:
            with self.page.expect_request(lambda r: "/pwa-api" in r.url and tool in (r.post_data or ""),
                                          timeout=30_000):
                btn.click()
        else:
            btn.click()
        expect(btn).to_be_enabled(timeout=30_000)
        return self

    def error(self):
        return self.page.locator("#jobFormError")

    def is_open(self) -> bool:
        return self.modal.is_visible()

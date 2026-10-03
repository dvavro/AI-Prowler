"""Page objects for the Remote PWA (REMOTE_PWA_E2E_TEST_SPEC.md §4).
Human-speed typing comes from the Jobs suite's type_text (honours --human)."""
from __future__ import annotations

from playwright.sync_api import Page, expect

from app import type_text          # tests\gui_jobs_e2e\app.py (on sys.path via conftest)

TABS = {"dash": "Dash", "files": "Files", "search": "Search", "perms": "Perms",
        "learn": "Learn", "tasks": "Tasks", "system": "System"}


class RemoteApp:
    def __init__(self, page: Page, url: str, log=print):
        self.page, self.url, self.log = page, url, log

    def step(self, msg: str):
        self.log(f"REMOTE {msg}")

    # ── sign-in ─────────────────────────────────────────────────────────────
    def open_login_screen(self):
        self.step(f"open {self.url}")
        self.page.goto(self.url, wait_until="domcontentloaded")
        expect(self.page.locator("#authScreen")).to_be_visible(timeout=30_000)
        return self

    def login(self, token: str):
        self.step("type the Bearer token (not logged) and tap Unlock Remote")
        box = self.page.locator("#authInput")
        box.click()
        self.page.wait_for_timeout(300)
        type_text(self.page, box, token)
        self.page.wait_for_timeout(300)
        self.page.get_by_role("button", name="Unlock Remote").click()
        return self

    def signed_in(self):
        expect(self.page.locator("#app")).to_be_visible(timeout=30_000)
        expect(self.page.locator("#authScreen")).to_be_hidden()
        return self

    def session(self) -> str | None:
        return self.page.evaluate("() => sessionStorage.getItem('ap_remote')")

    # ── navigation ──────────────────────────────────────────────────────────
    def goto(self, tab: str):
        name = TABS[tab]
        self.step(f"tap the {name} tab")
        self.page.locator(f"#nav{name}").click()
        expect(self.page.locator(f"#screen{name}")).to_have_class("screen active", timeout=10_000)
        self.page.wait_for_timeout(500)
        return self.page.locator(f"#screen{name}")

    def refresh_all(self):
        self.step("tap top-bar ↻ (refresh all)")
        self.page.locator("#refreshBtn").click()
        self.page.wait_for_timeout(1500)

    # ── direct call through the app's own api() (still passes the guard) ───
    def api(self, tool: str, args: dict | None = None) -> dict:
        return self.page.evaluate("([t, a]) => api(t, a)", [tool, args or {}])

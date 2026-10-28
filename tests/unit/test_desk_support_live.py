"""
Customer status page live updates (desk/support.html, 2026-10-28).

The page used to load the ticket once; an owner reply only showed after the
customer reloaded. It now checks every 15 s while visible, pauses in a
background tab, checks at once when the tab comes back, redraws only when
something shown changed, keeps half-typed text / picked stars, and shows
"Updated just now".

These run the REAL page headless with the /support-api mocked and Playwright's
fake clock, so a 15-second poll takes no time. (The live two-browser version
is tests/e2e/desk/test_desk_customer_cycle_e2e.py::test_S9_..., run with
tests\\run_desk_e2e.py.)
"""
import copy
import json
import re
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HTML = (ROOT / "desk" / "support.html").read_text(encoding="utf-8")
TOKEN = "LiveTok_" + "a" * 24
BASE = "http://desk.test"

pw_sync = pytest.importorskip("playwright.sync_api")

# Make document.hidden controllable (headless pages are always "visible").
VIS = """
window.__hidden = false;
Object.defineProperty(Document.prototype, 'hidden', {configurable: true, get() { return window.__hidden; }});
Object.defineProperty(Document.prototype, 'visibilityState', {configurable: true,
  get() { return window.__hidden ? 'hidden' : 'visible'; }});
window.__setHidden = h => { window.__hidden = h; document.dispatchEvent(new Event('visibilitychange')); };
"""


def _ticket(**kw):
    t = {"ticket_id": "T-0007", "title": "Streaks on the front windows", "description": "",
         "state": "In Progress", "who": {"name": "Mrs Okafor", "role": "customer"},
         "can_confirm": False, "can_reject": False, "can_reopen": False, "can_mark_done": False,
         "can_rate": False, "csat_score": None, "csat_comment": None,
         "messages": [{"author_kind": "customer", "at": "2026-10-28T14:00:00Z", "body": "Two by the garage too"}],
         "attachments": [], "updated_at": "2026-10-28T14:00:00Z"}
    t.update(kw)
    return t


class Api:
    def __init__(self):
        self.ticket = _ticket()
        self.gets = 0
        self.fail = False
        self.posts = []

    def owner_replies(self, body, minute=5):
        self.ticket["messages"].append({"author_kind": "owner", "at": f"2026-10-28T14:{minute:02d}:00Z",
                                        "body": body})

    def handle(self, route):
        req = route.request
        path = re.sub(r"^https?://[^/]+", "", req.url).split("?")[0]
        if path.startswith("/support/t/"):
            return route.fulfill(status=200, content_type="text/html; charset=utf-8", body=HTML)
        if path == "/support-api/info":
            return route.fulfill(status=200, content_type="application/json",
                                 body=json.dumps({"ok": True, "business": "Vavro Field Services",
                                                  "portal_enabled": True, "sms": True}))
        if path == f"/support-api/t/{TOKEN}" and req.method == "GET":
            self.gets += 1
            if self.fail:
                return route.fulfill(status=503, content_type="application/json",
                                     body=json.dumps({"ok": False, "message": "busy"}))
            return route.fulfill(status=200, content_type="application/json",
                                 body=json.dumps({"ok": True, "ticket": copy.deepcopy(self.ticket),
                                                  "business": "Vavro Field Services"}))
        if req.method == "POST" and path.startswith(f"/support-api/t/{TOKEN}/"):
            body = json.loads(req.post_data or "{}")
            self.posts.append((path.rsplit("/", 1)[1], body))
            if path.endswith("/reply"):
                self.ticket["messages"].append({"author_kind": "customer", "at": "2026-10-28T14:30:00Z",
                                                "body": body["body"]})
            return route.fulfill(status=201, content_type="application/json", body='{"ok": true}')
        return route.fulfill(status=404, body="")


@pytest.fixture(scope="module")
def browser():
    with pw_sync.sync_playwright() as pw:
        try:
            b = pw.chromium.launch(channel="msedge", headless=True)
        except Exception:
            try:
                b = pw.chromium.launch(headless=True)
            except Exception as e:                       # pragma: no cover
                pytest.skip(f"no browser for Playwright: {e}")
        yield b
        b.close()


@pytest.fixture
def page_api(browser):
    ctx = browser.new_context()
    page = ctx.new_page()
    page.set_default_timeout(5000)
    api = Api()
    page.add_init_script(VIS)
    # Fake clock, paused: page time moves only when a test calls tick().
    page.clock.install(time=1_800_000_000_000)
    page.clock.pause_at(1_800_000_001_000)
    page.route("**/*", api.handle)
    page.goto(f"{BASE}/support/t/{TOKEN}")
    page.locator("#h1", has_text="Request T-0007").wait_for()
    yield page, api
    ctx.close()


def settle(page, secs=0.6):
    """Let in-flight requests reach the (sync) route handler and the page draw."""
    end = time.time() + secs
    while time.time() < end:
        page.evaluate("1")
        time.sleep(0.05)


def tick(page, ms):
    page.clock.run_for(ms)
    settle(page)


def test_checks_every_15_seconds(page_api):
    page, api = page_api
    assert api.gets == 1
    tick(page, 14_000)
    assert api.gets == 1                  # not yet
    tick(page, 1_500)
    assert api.gets == 2
    tick(page, 15_000)
    assert api.gets == 3
    assert "const POLL_MS = 15000;" in HTML


def test_owner_reply_appears_without_reload_and_says_updated(page_api):
    page, api = page_api
    api.owner_replies("We'll be back Thursday at 9")
    tick(page, 15_000)
    page.get_by_text("We'll be back Thursday at 9").wait_for()
    assert page.locator("#live").is_visible()
    assert page.locator("#live").inner_text() == "Updated just now"
    tick(page, 4_500)
    assert not page.locator("#live").is_visible()      # brief


def test_no_redraw_when_nothing_shown_changed(page_api):
    page, api = page_api
    page.evaluate("document.querySelector('#app .card').dataset.mark = 'same-node'")
    api.ticket["updated_at"] = "2026-10-28T14:09:00Z"   # not on the page
    tick(page, 15_000)
    assert api.gets == 2
    assert page.evaluate("document.querySelector('#app .card').dataset.mark") == "same-node"
    assert not page.locator("#live").is_visible()


def test_half_typed_reply_survives_a_redraw(page_api):
    page, api = page_api
    page.locator("#reply").click()
    page.keyboard.type("Also the back slider is strea")
    api.owner_replies("On our way")
    tick(page, 15_000)
    page.get_by_text("On our way").wait_for()
    assert page.locator("#reply").input_value() == "Also the back slider is strea"
    assert page.evaluate("document.activeElement.id") == "reply"
    page.keyboard.type("ky")                            # still typing where they left off
    assert page.locator("#reply").input_value() == "Also the back slider is streaky"


def test_picked_stars_and_rating_comment_survive_a_redraw(page_api):
    page, api = page_api
    api.ticket.update(state="Closed", can_rate=True, can_reopen=True)
    tick(page, 15_000)
    page.locator("[data-star='4']").click()
    page.locator("#rateNote").fill("Great job, very tidy")
    api.owner_replies("Thanks for having us!")
    tick(page, 15_000)
    page.get_by_text("Thanks for having us!").wait_for()
    assert page.locator("#stars").inner_text().replace(" ", "") == "★★★★☆"
    assert page.locator("#rateNote").input_value() == "Great job, very tidy"
    page.locator("#rateGo").click()
    settle(page)
    assert api.posts[-1] == ("rating", {"score": 4, "comment": "Great job, very tidy"})


def test_paused_in_background_and_checked_at_once_on_return(page_api):
    page, api = page_api
    page.evaluate("window.__setHidden(true)")
    api.owner_replies("Running 10 minutes late")
    tick(page, 120_000)
    assert api.gets == 1                                # nothing while hidden
    assert page.get_by_text("Running 10 minutes late").count() == 0
    page.evaluate("window.__setHidden(false)")          # no clock advance needed
    settle(page)
    assert api.gets == 2
    page.get_by_text("Running 10 minutes late").wait_for()
    tick(page, 15_000)
    assert api.gets == 3                                # and back on the 15 s rhythm


def test_a_failed_check_keeps_the_page_and_tries_again(page_api):
    page, api = page_api
    page.locator("#reply").fill("draft")
    api.fail = True
    tick(page, 15_000)
    assert api.gets == 2
    assert page.locator("#reply").input_value() == "draft"
    assert page.get_by_text("Two by the garage too").count() == 1
    api.fail = False
    api.owner_replies("Back online")
    tick(page, 15_000)
    page.get_by_text("Back online").wait_for()


def test_sending_a_reply_clears_only_that_draft(page_api):
    page, api = page_api
    page.locator("#reply").fill("See you then")
    page.locator("#send").click()
    page.locator(".msg.me", has_text="See you then").wait_for()
    settle(page)
    assert page.locator("#reply").input_value() == ""
    assert api.posts[-1] == ("reply", {"body": "See you then"})

"""
Service Desk multi-user E2E (Playwright) — fixtures.

Two disposable AI-Prowler servers, each a real ai_prowler_mcp.py subprocess on
a random port with its own sandbox AIPROWLER_TEST_STATE_DIR (test_mode on):
  * business  — server mode, five users: owner, manager, staff, two field crew
  * solo      — personal mode (Solo edition), the owner's Bearer Token
Service Desk is switched on in each sandbox, and outgoing email / SMS are
caught in an outbox file (DESK_E2E_OUTBOX) instead of being sent.

One browser, one isolated BrowserContext per person (own sign-in, storage and
push subscription). Crew and customers use phone profiles; owner and managers
a desktop window. Human mode is the default (visible, slowed clicks,
key-by-key typing) — DESK_E2E_FAST=1 runs headless at full speed.

After EVERY test, desk_files.verify() checks the database, each ticket.json
and every attachment hash agree; any mismatch fails the test.

Run with:  tests\\run_desk_e2e.py            (human mode)
           tests\\run_desk_e2e.py --fast     (headless)
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[3]
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

HUMAN = os.environ.get("DESK_E2E_FAST", "") != "1"
SLOW_MO = 300 if HUMAN else 0
TYPE_DELAY = 55 if HUMAN else 0

SOLO_TOKEN = "E2E_DESK_SOLO_OWNER_TOKEN_0001"
USERS = {   # token -> record (server users.json)
    "E2E_DESK_OWNER_TOKEN_0001": {"name": "Olive Owner", "role": "owner"},
    "E2E_DESK_MANAGER_TOKEN_0001": {"name": "Mia Manager", "role": "manager"},
    "E2E_DESK_STAFF_TOKEN_0001": {"name": "Sam Staff", "role": "staff"},
    "E2E_DESK_CREW1_TOKEN_00001": {"name": "Cris Crew", "role": "field_crew"},
    "E2E_DESK_CREW2_TOKEN_00001": {"name": "Dee Crew", "role": "field_crew"},
}
TOKEN_OF = {rec["name"]: tok for tok, rec in USERS.items()}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(method, url, payload=None, token=None, timeout=15):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            if r.headers.get("content-type", "").startswith("application/json"):
                return r.status, json.loads(body)
            return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body
    except Exception as e:  # connection refused while starting, etc.
        return 0, str(e)


class Server:
    def __init__(self, kind, base, state, proc, outbox):
        self.kind, self.base, self.state, self.proc, self.outbox = kind, base, state, proc, outbox
        self.db = str(state / "tickets_database" / "ai_prowler_tickets.db")

    def messages(self):
        if not self.outbox.exists():
            return []
        return [json.loads(l) for l in self.outbox.read_text(encoding="utf-8").splitlines() if l.strip()]

    def wait_message(self, pred, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            hit = [m for m in self.messages() if pred(m)]
            if hit:
                return hit[-1]
            time.sleep(0.3)
        raise AssertionError(f"no matching outgoing message; outbox tail: {self.messages()[-5:]}")

    def api_token(self, name=None):
        """A bearer for direct /desk-api checks (server: sign-in; solo: owner token)."""
        if self.kind == "solo":
            return SOLO_TOKEN
        st, d = http("POST", f"{self.base}/desk-api/auth/login", {"name": name, "token": TOKEN_OF[name]})
        assert st == 200, d
        return d["access_token"]

    def api(self, method, path, payload=None, name=None):
        return http(method, f"{self.base}{path}", payload, token=self.api_token(name))


def _start(kind, tmp_path_factory, desk_on=True, extra_env=None) -> Server:
    state = tmp_path_factory.mktemp(f"desk_e2e_{kind}{'' if desk_on else '_off'}")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    mode = "server" if kind == "business" else "personal"
    cfg = {"edition": "business" if kind == "business" else "home", "mode": mode, "test_mode": True,
           "license_key": f"E2E-DESK-{kind.upper()}", "owner_name": "Olive Owner"}
    (state / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    if kind == "business":
        (state / "users.json").write_text(json.dumps(
            {"users": {t: {**r, "scopes": [], "status": "active"} for t, r in USERS.items()}}, indent=2),
            encoding="utf-8")
    old = os.environ.get("AIPROWLER_TEST_STATE_DIR")       # switch Service Desk on in this sandbox
    os.environ["AIPROWLER_TEST_STATE_DIR"] = str(state)
    try:
        import importlib
        import tool_config_store
        importlib.reload(tool_config_store)
        tool_config_store.set_group_enabled(mode, "service_desk", desk_on)
        if not desk_on:                    # the owner said no — and it already holds tickets,
            import sqlite3                 # so "in use" can't switch it back on by itself
            (state / "tickets_database").mkdir(exist_ok=True)
            con = sqlite3.connect(state / "tickets_database" / "ai_prowler_tickets.db")
            con.execute("CREATE TABLE IF NOT EXISTS tickets (ticket_id TEXT PRIMARY KEY)")
            con.execute("INSERT OR IGNORE INTO tickets VALUES ('T-0001')")
            con.commit()
            con.close()
    finally:
        if old is None:
            os.environ.pop("AIPROWLER_TEST_STATE_DIR", None)
        else:
            os.environ["AIPROWLER_TEST_STATE_DIR"] = old
    outbox = state / "outbox.jsonl"
    env = dict(os.environ, AIPROWLER_TEST_STATE_DIR=str(state), DESK_E2E_OUTBOX=str(outbox),
               PYTHONIOENCODING="utf-8", **(extra_env or {}))
    args = [sys.executable, str(SRC / "ai_prowler_mcp.py"), "--transport", "http", "--port", str(port),
            "--public-base", base]
    if kind == "solo":
        args += ["--token", SOLO_TOKEN]
    log = open(state / "server.log", "w", encoding="utf-8")
    proc = subprocess.Popen(args, cwd=str(SRC), env=env, stdout=log, stderr=subprocess.STDOUT)
    ok, end = False, time.time() + 90
    while time.time() < end and proc.poll() is None:
        if http("GET", f"{base}/health", timeout=3)[0] == 200:
            ok = True
            break
        time.sleep(1)
    if not ok:
        proc.kill()
        log.close()
        pytest.fail(f"{kind} server did not start. Log tail:\n" + "\n".join(
            (state / "server.log").read_text(encoding="utf-8", errors="replace").splitlines()[-40:]))
    return Server(kind, base, state, proc, outbox)


def _stop(s: Server):
    try:
        s.proc.terminate()
        s.proc.wait(timeout=10)
    except Exception:
        s.proc.kill()


@pytest.fixture(scope="session")
def business(tmp_path_factory):
    s = _start("business", tmp_path_factory)
    yield s
    _stop(s)


@pytest.fixture(scope="session")
def solo(tmp_path_factory):
    s = _start("solo", tmp_path_factory)
    yield s
    _stop(s)


@pytest.fixture(scope="module")
def business_off(tmp_path_factory):
    """A team server whose owner switched Service Desk OFF in Settings."""
    s = _start("business", tmp_path_factory, desk_on=False)
    yield s
    _stop(s)


@pytest.fixture(scope="module")
def solo_off(tmp_path_factory):
    """A personal install whose owner switched Service Desk OFF in Settings."""
    s = _start("solo", tmp_path_factory, desk_on=False)
    yield s
    _stop(s)


@pytest.fixture(scope="module")
def solo_email_only(tmp_path_factory):
    """A personal install with email set up but no texting."""
    s = _start("solo", tmp_path_factory, extra_env={"DESK_E2E_CHANNELS": "email"})
    yield s
    _stop(s)


@pytest.fixture(scope="module")
def solo_no_email(tmp_path_factory):
    """A personal install with neither email nor texting set up."""
    s = _start("solo", tmp_path_factory, extra_env={"DESK_E2E_CHANNELS": "none"})
    yield s
    _stop(s)


@pytest.fixture(scope="session")
def pw():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        yield p


@pytest.fixture(scope="session")
def browser(pw):
    try:
        b = pw.chromium.launch(channel="msedge", headless=not HUMAN, slow_mo=SLOW_MO)
    except Exception:
        b = pw.chromium.launch(headless=not HUMAN, slow_mo=SLOW_MO)
    yield b
    b.close()


class Person:
    """One person's own browser context + page, with human-style helpers."""

    def __init__(self, browser, pw, server, label, phone=False):
        opts = dict(pw.devices["Pixel 7"]) if phone else {"viewport": {"width": 1100, "height": 820}}
        self.ctx = browser.new_context(**opts)
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(15000)
        self.server, self.label = server, label
        self._dialogs = []
        self.page.on("dialog", self._on_dialog)

    def _on_dialog(self, d):
        ans = self._dialogs.pop(0) if self._dialogs else True
        if ans is False:
            d.dismiss()
        elif d.type == "prompt":
            d.accept(ans if isinstance(ans, str) else "")
        else:
            d.accept()

    def answer(self, *answers):
        """Queue answers for the next prompt()/confirm() dialogs (True = OK)."""
        self._dialogs.extend(answers)

    def type(self, selector, text):
        loc = self.page.locator(selector)
        loc.click()
        loc.fill("")
        if TYPE_DELAY:
            loc.press_sequentially(text, delay=TYPE_DELAY)
        else:
            loc.fill(text)

    def click(self, selector):
        self.page.locator(selector).first.click()

    def button(self, name):
        self.page.get_by_role("button", name=name, exact=True).first.click()

    def toast(self, text, timeout=10000):
        self.page.locator("#toast", has_text=text).wait_for(state="visible", timeout=timeout)

    def sign_in(self, name=None):
        p = self.page
        p.goto(f"{self.server.base}/desk/")
        if self.server.kind == "business":
            self.type("#lgName", name)
            self.type("#lgTok", TOKEN_OF[name])
        else:
            self.type("#lgTok", SOLO_TOKEN)
        self.click("#lgGo")
        p.locator("#tabs").wait_for(state="visible")

    def tab(self, name):
        self.page.locator(f".tab[data-filter='{name}']").click()

    def open_ticket(self, tid):
        self.page.locator(f"[data-open='{tid}']").first.click()
        self.page.locator("#back").wait_for()

    def close(self):
        self.ctx.close()


@pytest.fixture
def people(browser, pw):
    made = []

    def make(server, label, phone=False):
        p = Person(browser, pw, server, label, phone)
        made.append(p)
        return p
    yield make
    for p in made:
        p.close()


@pytest.fixture(autouse=True)
def consistency(request):
    """After every test: database, ticket.json files and attachment hashes agree."""
    yield
    import desk_files
    for name in ("business", "solo"):
        if name in request.fixturenames:
            srv = request.getfixturevalue(name)
            if Path(srv.db).exists():
                problems = desk_files.verify(srv.db)
                assert problems == [], f"{name}: consistency check failed: {problems}"

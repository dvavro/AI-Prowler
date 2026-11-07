"""Agents GUI suite — fixtures (AGENTS_GUI_E2E_TEST_SPEC.md §1).

Two throwaway sandboxes (ag_server.py), started once per session and only when a test asks for them:
  * solo     — personal edition, the owner's token
  * business — server edition: owner, manager, staff, two field crew (all made-up, @time-machine.test)
Every AI call goes to the stand-in (ai_standin.py) inside the sandbox; nothing reaches a paid API.

Off by default — never part of a normal run_tests.bat run. Run with:
    run_tests.bat agents-gui                 human mode (visible browser, slowed clicks, key-by-key typing)
    run_tests.bat agents-gui --fast          headless, full speed
    run_tests.bat agents-gui -k smoke        one group
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENABLED = os.environ.get("AIPROWLER_AGENTS_GUI") == "1"
HUMAN = os.environ.get("AG_FAST", "") != "1"
SLOW_MO = 300 if HUMAN else 0
TYPE_DELAY = 55 if HUMAN else 0
START = dt.date(2026, 11, 9)                       # Monday — the simulated week of the seed data
RUN_DIR = HERE / "results" / dt.datetime.now().strftime("run_%Y%m%d_%H%M%S")

USERS = {   # key -> (name, role) — made-up people, sandbox only
    "owner": ("ZAG Owner", "owner"),
    "manager": ("ZAG Manager", "manager"),
    "staff": ("ZAG Office Sam", "staff"),
    "cris": ("ZAG Crew Cris", "field_crew"),
    "dee": ("ZAG Crew Dee", "field_crew"),
}


def pytest_configure(config):
    config.addinivalue_line("markers", "agents_gui: agents GUI suite on sandbox servers (run_tests.bat agents-gui)")


def pytest_collection_modifyitems(config, items):
    skip = pytest.mark.skip(reason="agents GUI suite is off — run it with: run_tests.bat agents-gui")
    for it in items:
        if HERE in Path(str(it.fspath)).resolve().parents:
            it.add_marker(pytest.mark.agents_gui)
            if not ENABLED:
                it.add_marker(skip)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(method, url, body=None, token=None, timeout=60):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw
    except Exception as e:  # noqa: BLE001 — not up yet
        return 0, str(e)


class Sandbox:
    """One ag_server.py process and the calls a test makes to it."""

    def __init__(self, kind: str):
        self.kind = kind                                  # "solo" | "business"
        self.mode = "server" if kind == "business" else "personal"
        self.edition = "business" if kind == "business" else "solo"
        self.port, self.ctl_port = _free_port(), _free_port()
        self.home = RUN_DIR / f"{kind}_home"
        self.tokens = {k: "ZAG" + secrets.token_hex(12) for k in USERS}
        self.token = self.tokens["owner"]
        self.proc = None
        self._desk = {}

    # ── lifecycle ──
    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ctl(self) -> str:
        return f"http://127.0.0.1:{self.ctl_port}"

    def start(self):
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, str(HERE / "ag_server.py"), "--home", str(self.home), "--port", str(self.port),
               "--control-port", str(self.ctl_port), f"--token={self.token}", "--date", START.isoformat(),
               "--time", "09:00", "--mode", self.mode] + (["--no-sms"] if self.kind == "nosms" else [])
        if self.mode == "server":
            uf = RUN_DIR / f"{self.kind}_users.json"
            uf.write_text(json.dumps({"company_id": "ZAG-AGENTS", "users": {
                self.tokens[k]: {"name": n, "role": r, "status": "active", "scopes": [],
                                 "private_collection_enabled": False, "can_manage_users": r == "owner",
                                 "email": f"{k}@time-machine.test", "cell_phone": f"+1555010{i:04d}",
                                 "home_address": "210 Sams Ave, New Smyrna Beach, FL 32168"}
                for i, (k, (n, r)) in enumerate(USERS.items())}}, indent=1), encoding="utf-8")
            cmd += ["--users-file", str(uf)]
        env = {k: v for k, v in os.environ.items() if k != "AIPROWLER_TEST_STATE_DIR"}
        self.log = open(RUN_DIR / f"{self.kind}_server.log", "w", encoding="utf-8")
        self.proc = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT, cwd=str(ROOT), env=env)
        t0 = time.time()
        while time.time() - t0 < 180:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.kind} sandbox exited:\n" + self.server_log()[-3000:])
            if "today" in (self.control("GET", "/state", timeout=3) or {}):
                if http("GET", self.base + "/desk/", timeout=5)[0] == 200:
                    break
            time.sleep(1)
        else:
            raise RuntimeError(f"{self.kind} sandbox didn't come up in 3 minutes:\n" + self.server_log()[-3000:])
        return self

    def stop(self):
        try:
            http("POST", self.ctl + "/stop", {}, timeout=5)
        except Exception:  # noqa: BLE001
            pass
        if self.proc and self.proc.poll() is None:
            time.sleep(1)
            if self.proc.poll() is None:
                self.proc.kill()
        try:
            self.log.close()
        except Exception:  # noqa: BLE001
            pass
        # AG-SAFE-04: the sandbox goes (its log stays in results\run_<time>\); AG_KEEP=1 keeps it to look at
        if os.environ.get("AG_KEEP") != "1" and self.home.exists() and "_home" in self.home.name:
            import shutil
            for _ in range(5):
                try:
                    shutil.rmtree(self.home)
                    break
                except OSError:
                    time.sleep(1)                     # Windows: the stopped process may still hold a file for a moment

    def server_log(self) -> str:
        try:
            return (RUN_DIR / f"{self.kind}_server.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # ── the control port ──
    def control(self, method, path, body=None, timeout=120):
        st, d = http(method, self.ctl + path, body, timeout=timeout)
        if st not in (200, 201):
            if path == "/state":
                return {}
            raise AssertionError(f"control {path} -> {st}: {str(d)[:1500]}")
        return d

    def clock(self, day: dt.date, hhmm: str = "09:00"):
        return self.control("POST", "/clock", {"date": day.isoformat(), "time": hhmm})

    def now(self) -> dt.datetime:
        return dt.datetime.fromisoformat(self.control("GET", "/state")["now"])

    def agents_pass(self, force=False) -> dict:
        return self.control("POST", "/run", {"job": "agents", "force": force}, timeout=300)

    def no_key(self, on=True) -> dict:
        return self.control("POST", "/no-key", {"on": on})

    def no_runner(self, value="chat_only") -> dict:
        return self.control("POST", "/no-runner", {"value": value})

    def ai_calls(self) -> list:
        return self.control("GET", "/ai-calls")

    def ai_reset(self, name="good", rules=None):
        return self.control("POST", "/ai-reset", {"name": name, "rules": rules or {}})

    def agent_db(self) -> dict:
        return self.control("GET", "/agent-db")

    def outbox(self) -> list:
        return self.control("GET", "/outbox")

    def blocked(self) -> list:
        return [m for m in self.outbox() if m.get("kind") == "blocked_http"]

    def settings(self, desk=None, jobs=None, hr=None) -> dict:
        return self.control("POST", "/settings", {"desk": desk or {}, "jobs": jobs or {}, "hr": hr or {}})

    def tool(self, name, **args) -> str:
        return self.control("POST", "/tool", {"name": name, "args": args}).get("result")

    # ── the app's own APIs ──
    def desk_token(self, key="owner") -> str:
        if self.mode != "server":
            return self.token
        if key not in self._desk:
            st, d = http("POST", self.base + "/desk-api/auth/login", {"name": USERS[key][0], "token": self.tokens[key]})
            assert st == 200 and d.get("access_token"), f"Service Desk sign-in failed for {key}: {st} {d}"
            self._desk[key] = d["access_token"]
        return self._desk[key]

    def desk(self, method, path, body=None, key="owner"):
        st, d = http(method, self.base + "/desk-api" + path, body, token=self.desk_token(key))
        if st == 401 and self.mode == "server":                 # a clock jump outlived the session: sign in again
            self._desk.pop(key, None)
            st, d = http(method, self.base + "/desk-api" + path, body, token=self.desk_token(key))
        return st, d

    def hr(self, method, path, body=None, key="owner"):
        return http(method, self.base + "/hr-api" + path, body, token=self.tokens[key])


def _start(kind, request):
    if not ENABLED:
        pytest.skip("agents GUI suite is off")
    box = Sandbox(kind).start()
    request.addfinalizer(box.stop)
    return box


@pytest.fixture(scope="session")
def solo(request):
    return _start("solo", request)


@pytest.fixture(scope="session")
def nosms(request):
    """A personal install with email set up and SMS not (David's setup, 4 Nov)."""
    return _start("nosms", request)


@pytest.fixture(scope="session")
def business(request):
    return _start("business", request)


# ── browser (human mode by default) ──────────────────────────────────────────
@pytest.fixture(scope="session")
def browser():
    if not ENABLED:
        pytest.skip("agents GUI suite is off")
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        b = pw.chromium.launch(headless=not HUMAN, slow_mo=SLOW_MO)
    except Exception as e:  # noqa: BLE001
        pw.stop()
        pytest.skip(f"Chromium for Playwright isn't installed ({e})")
    yield b
    try:
        b.close()
    finally:
        pw.stop()


class Person:
    """One person's browser window."""

    def __init__(self, browser, box: Sandbox, label: str, phone=False):
        size = {"width": 412, "height": 900} if phone else {"width": 1280, "height": 900}
        self.ctx = browser.new_context(viewport=size, service_workers="block", timezone_id="America/New_York")
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(30_000)
        self.box, self.label, self.errors = box, label, []
        self.page.on("pageerror", lambda e: self.errors.append(f"{label} pageerror: {e}"))

    def type(self, sel, text):
        loc = self.page.locator(sel).first
        loc.click()
        loc.fill("")
        loc.press_sequentially(str(text), delay=TYPE_DELAY)

    def pause(self, ms=800):
        if HUMAN:
            self.page.wait_for_timeout(ms)

    # sign-ins
    def desk_sign_in(self, key="owner"):
        p = self.page
        p.goto(self.box.base + "/desk/")
        p.locator("#tabs:visible, #lgTok:visible").first.wait_for()   # the app remembers a sign-in on reopen
        if p.locator("#tabs").is_visible():
            self.pause()
            return
        if self.box.mode == "server":
            self.type("#lgName", USERS[key][0])
        self.type("#lgTok", self.box.tokens[key])
        p.locator("#lgGo").click()
        p.locator("#tabs").wait_for(state="visible")
        self.pause()

    def jobs_sign_in(self, key="owner"):
        if self.box.mode == "server":
            st, d = http("POST", self.box.base + "/pwa-login", {"name": USERS[key][0], "token": self.box.tokens[key]})
            assert d.get("access_token"), f"Jobs app sign-in failed: {st} {d}"
            auth = {"mode": "server", "access_token": d["access_token"], "userName": USERS[key][0],
                    "userRole": USERS[key][1]}
        else:
            auth = {"mode": "personal", "token": self.box.token}
        self.page.add_init_script("try{localStorage.setItem('ap_auth'," + json.dumps(json.dumps(auth)) + ")}catch(e){}")
        self.page.goto(self.box.base + "/jobs/")
        self.pause(1500)

    def hr_admin_sign_in(self, key="owner"):
        p = self.page
        p.goto(self.box.base + "/hr_admin/")
        self.type("#auth-name", USERS[key][0])
        self.type("#auth-token", self.box.tokens[key])
        p.click("button.auth-btn")
        p.wait_for_selector("#app", state="visible", timeout=20_000)
        self.pause(1500)

    def close(self):
        try:
            self.ctx.close()
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture
def person(browser, request):
    made = []

    def make(box, label, phone=False):
        p = Person(browser, box, label, phone)
        made.append(p)
        return p

    yield make
    for p in made:
        if p.errors:
            print("\n".join(p.errors))
        p.close()


def code_from(text: str) -> str:
    m = re.search(r"\b(\d{6})\b", text or "")
    return m.group(1) if m else ""

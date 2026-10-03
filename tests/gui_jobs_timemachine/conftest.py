"""Fixtures for the TIME MACHINE suite (spec §6.19).

A throwaway copy of AI-Prowler (tm_server.py) is started for the session in
<run folder>\\sandbox_home — its own port, empty database, every email/SMS
caught in an outbox, a clock the tests move. Nothing here can reach the real
install, so there is no write guard; the safety checks are about the sandbox
itself (it must be the one we started, and nothing may get out).

Run: run_tests_gui_jobs_e2e.bat --timemachine --human
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
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
E2E = HERE.parent / "gui_jobs_e2e"
for p in (str(HERE), str(E2E)):
    if p not in sys.path:
        sys.path.insert(0, p)

from api import ApiClient  # noqa: E402

RUN_DIR = Path(os.environ.get("E2E_RUN_DIR") or HERE / "artifacts" / _dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
RUN_DIR.mkdir(parents=True, exist_ok=True)

log = logging.getLogger("e2e")
if not log.handlers:
    log.setLevel(logging.INFO)
    _fh = logging.FileHandler(RUN_DIR / "run.log", encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", "%H:%M:%S"))
    log.addHandler(_fh)

_current = {"id": "(session)"}
STATE = {"outcomes": {}, "outbox": None, "sandbox": ""}


def _log(msg: str):
    log.info(f"[{_current['id']}] {msg}")


def _api_log(entry: dict):
    with open(RUN_DIR / "api_calls.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(dict(entry, test=_current["id"]), ensure_ascii=False) + "\n")


def pytest_collection_modifyitems(config, items):
    for it in items:
        if HERE in Path(str(it.fspath)).resolve().parents:
            it.add_marker(pytest.mark.jobs_gui_timemachine)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call":
        item.rep_call = rep                 # the story's _in_order fixture reads this
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        first = ""
        if rep.failed and rep.longrepr is not None:
            lines = [l for l in str(rep.longrepr).splitlines() if l.strip().startswith("E ")]
            first = (lines[0] if lines else str(rep.longrepr).splitlines()[-1])[:240]
        STATE["outcomes"][item.nodeid] = (rep.outcome, first, round(rep.duration, 1))


@pytest.fixture(autouse=True)
def _name_current_test(request):
    _current["id"] = request.node.name
    _log(f"===== START {request.node.nodeid}")
    yield
    _log(f"===== END   {request.node.nodeid}")
    _current["id"] = "(session)"


# ── the time machine ──────────────────────────────────────────────────────────
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _json(url, body=None, token=None, timeout=120):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"}


def next_monday(d: _dt.date) -> _dt.date:
    return d + _dt.timedelta(days=(7 - d.weekday()) % 7 or 7)


MODE = (os.environ.get("E2E_TM_MODE") or "personal").strip().lower()

# Server mode: the made-up company inside the sandbox (never real people).
#   key: (name, role, phone)
SERVER_USERS = {
    "owner":   ("ZT Owner",     "owner",      "+15550100001"),
    "manager": ("ZT Manager",   "manager",    "+15550100002"),
    "staff":   ("ZT Office Sam", "staff",     "+15550100005"),
    "alex":    ("ZT Crew Alex", "field_crew", "+15550100003"),
    "bea":     ("ZT Crew Bea",  "field_crew", "+15550100004"),
}


class TmUser:
    def __init__(self, key, name, role, token):
        self.key, self.name, self.role, self.token = key, name, role, token
        self.access_token = ""

    def __repr__(self):
        return f"{self.key} · {self.name} · {self.role}"


class TimeMachine:
    def __init__(self, start: _dt.date, mode: str = "personal"):
        self.port, self.ctl = _free_port(), _free_port()
        self.mode = mode
        self.token = secrets.token_urlsafe(24)
        self.home = RUN_DIR / "sandbox_home"
        self.start_day = start
        self.proc = None
        self.users: dict[str, TmUser] = {}
        if mode == "server":
            for key, (name, role, phone) in SERVER_USERS.items():
                tok = self.token if key == "owner" else secrets.token_urlsafe(24)
                self.users[key] = TmUser(key, name, role, tok)

    def _users_doc(self) -> dict:
        doc = {"company_id": "ZT-TIME-MACHINE", "users": {}}
        for key, u in self.users.items():
            phone = SERVER_USERS[key][2]
            doc["users"][u.token] = {
                "name": u.name, "role": u.role, "status": "active", "scopes": [],
                "private_collection_enabled": False, "can_manage_users": u.role == "owner",
                "email": f"{key}@time-machine.test", "cell_phone": phone,
                "home_address": "210 Sams Ave, New Smyrna Beach, FL 32168"}
        return doc

    # lifecycle
    def start(self):
        self.home.mkdir(parents=True, exist_ok=False)
        out = open(RUN_DIR / "tm_server.out", "w", encoding="utf-8")
        cmd = [sys.executable, str(HERE / "tm_server.py"), "--home", str(self.home), "--port", str(self.port),
               "--control-port", str(self.ctl), "--token", self.token, "--date", self.start_day.isoformat(),
               "--time", "07:00", "--mode", self.mode]
        if self.mode == "server":
            uf = RUN_DIR / "tm_users.json"          # outside the sandbox; only made-up users
            uf.write_text(json.dumps(self._users_doc(), indent=1), encoding="utf-8")
            cmd += ["--users-file", str(uf)]
        self.proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, cwd=str(HERE))
        t0 = time.time()
        while time.time() - t0 < 180:
            if self.proc.poll() is not None:
                raise RuntimeError("time machine exited:\n" + (RUN_DIR / "tm_server.out").read_text(
                    encoding="utf-8", errors="replace")[-3000:])
            st = self.state()
            if "today" in st:
                try:
                    with urllib.request.urlopen(f"{self.app_url}", timeout=5) as r:
                        if r.status == 200:
                            break
                except Exception:
                    pass
            time.sleep(1)
        else:
            raise RuntimeError("time machine didn't come up in 3 minutes")
        _log(f"TIME MACHINE up ({self.mode} mode): {self.app_url} (control :{self.ctl}) "
             f"sandbox {self.state().get('sandbox')} today {self.today()}")
        if self.mode == "server":
            info = _json(f"{self.origin}/pwa-token", timeout=30)
            assert info.get("mode") == "server", f"the time machine isn't in server mode: {info}"
            assert not info.get("token"), "SECURITY: /pwa-token hands out a token in server mode"
            for u in self.users.values():
                d = _json(f"{self.origin}/pwa-login", {"name": u.name, "token": u.token}, timeout=30)
                assert d.get("access_token"), f"login failed for {u}: {d}"
                assert d.get("role") == u.role, f"{u}: server says role {d.get('role')!r}"
                u.access_token = d["access_token"]
            _log(f"server users logged in: {list(self.users.values())}")
        return self

    def stop(self):
        try:
            _json(f"http://127.0.0.1:{self.ctl}/stop", {})
        except Exception:
            pass
        if self.proc and self.proc.poll() is None:
            time.sleep(1)
            if self.proc.poll() is None:
                self.proc.kill()

    # clock + jobs
    @property
    def app_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/jobs/"

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def state(self) -> dict:
        try:
            return _json(f"http://127.0.0.1:{self.ctl}/state", timeout=5)
        except Exception:
            return {}

    def today(self) -> _dt.date:
        return _dt.date.fromisoformat(self.state()["today"])

    def now(self) -> _dt.datetime:
        return _dt.datetime.fromisoformat(self.state()["now"])

    def login(self, key: str) -> dict:
        """(Re-)sign a server user in through /pwa-login, as the app does."""
        u = self.users[key]
        d = _json(f"{self.origin}/pwa-login", {"name": u.name, "token": u.token}, timeout=30)
        assert d.get("access_token"), f"login failed for {u}: {d}"
        u.access_token = d["access_token"]
        _log(f"signed in again: {u}")
        return d

    def client(self, key: str):
        """An ApiClient on this user's CURRENT session (e.g. after login())."""
        return ApiClient(self.origin, self.users[key].access_token, _OpenGuard(), log=_log,
                         api_log=lambda e, k=key: _api_log(dict(e, as_user=k)))

    def pwa_call(self, key: str, tool: str, args: dict) -> dict:
        """Raw /pwa-api call with this user's CURRENT session (no ApiClient)."""
        return _json(f"{self.origin}/pwa-api", {"tool": tool, "args": args},
                     token=self.users[key].access_token, timeout=60)

    def set_clock(self, day: _dt.date, hhmm: str = "07:00"):
        r = _json(f"http://127.0.0.1:{self.ctl}/clock", {"date": day.isoformat(), "time": hhmm})
        assert "now" in r, f"clock move failed: {r}"
        _log(f"⏰ CLOCK -> {day:%a %Y-%m-%d} {hhmm}")
        return r

    def run_job(self, job: str) -> dict:
        r = _json(f"http://127.0.0.1:{self.ctl}/run", {"job": job})
        assert "error" not in r, f"scheduler job {job} failed: {r}"
        return r

    def outbox(self) -> list[dict]:
        return _json(f"http://127.0.0.1:{self.ctl}/outbox")


class _OpenGuard:
    """No real data exists in the time machine, so nothing to guard — but the
    ApiClient expects this interface."""
    tier = "timemachine"

    def enforce(self, tool, args, source):
        return "allow", "time machine sandbox"

    def note_result(self, tool, result):
        pass

    def route_email_args(self, tool, args):
        return args, ""


@pytest.fixture(scope="session")
def tm():
    start = next_monday(_dt.date.today())
    machine = TimeMachine(start, MODE).start()
    STATE["sandbox"] = str(machine.home)
    STATE["mode"] = MODE
    yield machine
    try:
        STATE["outbox"] = machine.outbox()
        (RUN_DIR / "outbox.json").write_text(json.dumps(STATE["outbox"], indent=1, ensure_ascii=False),
                                             encoding="utf-8")
    except Exception:
        pass
    machine.stop()


@pytest.fixture(scope="session")
def apis(tm) -> dict:
    """One API client per person. Personal mode: just 'owner'. Server mode:
    owner, manager, alex, bea — each with their OWN session, so the server's
    role and crew rules apply to every call exactly as in the field."""
    if tm.mode != "server":
        return {"owner": ApiClient(tm.origin, tm.token, _OpenGuard(), log=_log, api_log=_api_log)}
    return {k: ApiClient(tm.origin, u.access_token, _OpenGuard(), log=_log,
                         api_log=lambda e, k=k: _api_log(dict(e, as_user=k)))
            for k, u in tm.users.items()}


@pytest.fixture(scope="session")
def api(apis) -> ApiClient:
    return apis["owner"]


# ── browser: logged in, with the page's clock at the time machine's "now" ─────
# Server mode: which person the browser is logged in as comes from the test
# module's BROWSER_USER {test name: user key}; default the owner.
@pytest.fixture
def page(page, tm, request):
    page.set_default_timeout(30_000)
    page.clock.install(time=tm.now())
    if tm.mode == "server":
        key = getattr(request.module, "BROWSER_USER", {}).get(request.node.originalname, "owner")
        u = tm.users[key]
        auth = {"mode": "server", "access_token": u.access_token, "userName": u.name, "userRole": u.role}
        _log(f"browser logged in as {u}")
    else:
        auth = {"mode": "personal", "token": tm.token}
    page.add_init_script("try{localStorage.setItem('ap_auth'," + json.dumps(json.dumps(auth)) + ")}catch(e){}")
    page.on("pageerror", lambda e: _log(f"PAGEERROR: {e}"))
    yield page


@pytest.fixture
def app(page, tm):
    from app import JobsApp
    a = JobsApp(page, tm.app_url, _log)
    a.open()
    return a


# ── SUMMARY.txt ───────────────────────────────────────────────────────────────
def pytest_sessionfinish(session, exitstatus):
    oc = STATE["outcomes"]
    passed = sum(1 for o in oc.values() if o[0] == "passed")
    failed = [(k, v) for k, v in oc.items() if v[0] == "failed"]
    skipped = sum(1 for o in oc.values() if o[0] == "skipped")
    ob = STATE["outbox"] or []
    kinds = {}
    for m in ob:
        kinds[m.get("kind")] = kinds.get(m.get("kind"), 0) + 1
    overall = "PASS" if (not failed and passed) else "FAIL"
    lines = [
        f"AI-Prowler Jobs app TIME MACHINE ({STATE.get('mode', MODE)} mode) — {overall}",
        f"Finished: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}   (throwaway copy of the app — real data never touched)",
        f"Tests: {passed} passed, {len(failed)} failed, {skipped} skipped",
        f"Sandbox: {STATE['sandbox']}",
        f"Outbox (caught, never sent): {kinds or 'empty'}",
    ]
    if failed:
        lines += ["", "Failed tests:"] + [f"  ✗ {k}  ({d}s)\n      {first}" for k, (_, first, d) in failed]
    lines += ["", f"Full log: {RUN_DIR / 'run.log'}"]
    (RUN_DIR / "SUMMARY.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

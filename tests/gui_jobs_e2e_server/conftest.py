"""pytest fixtures for the SERVER-MODE Jobs-app E2E suite (spec §6.11).

Runs on David's PC against the AI-Prowler Server's Jobs app over its public
address — the same way a crew member's phone reaches it. Its own folder (not
gui_jobs_e2e\\server\\) so the personal suite's session setup, which sweeps and
backs up the PC's OWN database with the personal token, never runs here.

Users:  users.local.json (names only) + one Windows user environment variable
        per user holding that user's token (AIPROWLER_SRV_TOKEN_U1, ...).
URL:    AIPROWLER_SRV_URL (the server's .../jobs/ address).

Token hygiene (spec §6.11.3): no Playwright traces or videos (they would store
access tokens), failure screenshots mask the login fields and the Profile code
row, and logs name users by key + name + role only.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "gui_jobs_e2e"          # page objects, guard, API client, test data
for p in (str(SHARED), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from api import ApiClient, http, origin_of          # noqa: E402
from data import TestData                           # noqa: E402
from safety import Guard, canned_reply, SANDBOX_DATE  # noqa: E402

# ── run folder + logs ─────────────────────────────────────────────────────────
RUN_DIR = Path(os.environ.get("E2E_RUN_DIR") or
               HERE / "artifacts" / _dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
RUN_DIR.mkdir(parents=True, exist_ok=True)
TIER = (os.environ.get("E2E_TIER") or "safe").lower()
KEEP_DATA = os.environ.get("E2E_KEEP_DATA", "") == "1"

log = logging.getLogger("e2e_srv")
if not log.handlers:
    log.setLevel(logging.INFO)
    _fh = logging.FileHandler(RUN_DIR / "run.log", encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", "%H:%M:%S"))
    log.addHandler(_fh)

_lock = threading.Lock()
_current_test = {"id": "(session)"}
_SECRETS: list[str] = []          # every token / access token — scrubbed from anything we write


def _scrub(text: str) -> str:
    for s in _SECRETS:
        if s:
            text = text.replace(s, "«token»")
    return text


def _log(msg: str):
    log.info(_scrub(f"[{_current_test['id']}] {msg}"))


def _api_log(entry: dict):
    entry = dict(entry, test=_current_test["id"], at=_dt.datetime.now().isoformat(timespec="milliseconds"))
    line = _scrub(json.dumps(entry, ensure_ascii=False))
    with _lock, open(RUN_DIR / "api_calls.jsonl", "a", encoding="utf-8") as f:
        f.write(line + "\n")
    _log(f"API {entry.get('source')}: {entry.get('tool')} -> {entry.get('status', '')} "
         f"{'ok' if entry.get('ok') else 'NOT ok'} ({entry.get('ms', '?')} ms)")


def _console_log(line: str):
    with _lock, open(RUN_DIR / "console.log", "a", encoding="utf-8") as f:
        f.write(_scrub(f"[{_current_test['id']}] {line}") + "\n")


STATE = {"cleanup": None, "leftovers": None, "preflight": "", "outcomes": {}, "users": ""}


# ── users + tokens ────────────────────────────────────────────────────────────
def _user_env(name: str) -> str:
    """os.environ, else the Windows USER environment in the registry — a
    variable set with setx after this process's parent started isn't in
    os.environ yet, but it is in HKCU\\Environment."""
    v = os.environ.get(name, "")
    if v:
        return v
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return str(winreg.QueryValueEx(k, name)[0])
    except Exception:
        return ""


class SrvUser:
    def __init__(self, key: str, name: str, token: str):
        self.key, self.name, self.token = key, name, token
        self.role = ""
        self.access_token = ""

    def __repr__(self):                       # never print a token
        return f"{self.key} · {self.name} · {self.role or '?'}"


def _load_users() -> tuple[str, list[SrvUser]]:
    cfg = json.loads((HERE / "users.local.json").read_text(encoding="utf-8"))
    url = _user_env(cfg.get("url_env", "AIPROWLER_SRV_URL")).strip()
    users = []
    for u in cfg["users"]:
        tok = _user_env(u["token_env"])
        if not tok:
            pytest.exit(f"Token variable {u['token_env']} (for {u['name']}) is not set.", returncode=3)
        _SECRETS.append(tok)
        users.append(SrvUser(u["key"], u["name"], tok))
    if not url:
        pytest.exit("AIPROWLER_SRV_URL is not set (the server's .../jobs/ address).", returncode=3)
    return url, users


def srv_login(origin: str, name: str, token: str) -> tuple[int, dict]:
    from srv_helpers import srv_login as _login
    return _login(origin, name, token)


# ── pytest hooks ──────────────────────────────────────────────────────────────
def pytest_configure(config):
    for m in ("expect_guard_block: the test deliberately triggers a guard block",
              # used by personal-suite modules that test_srv_buttons imports its
              # button lists from; no meaning in the server suite
              "no_login: (personal suite) test starts at the login screen",):
        config.addinivalue_line("markers", m)


def pytest_collection_modifyitems(config, items):
    for it in items:
        if HERE in Path(str(it.fspath)).resolve().parents:
            it.add_marker(pytest.mark.jobs_gui_e2e_server)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        first = ""
        if rep.failed and rep.longrepr is not None:
            lines = [l for l in str(rep.longrepr).splitlines() if l.strip().startswith("E ")]
            first = _scrub((lines[0] if lines else str(rep.longrepr).splitlines()[-1])[:220])
        STATE["outcomes"][item.nodeid] = (rep.outcome, first, round(rep.duration, 1))
        # failure screenshots of every user window, token fields masked
        if rep.failed:
            shots = RUN_DIR / "failures" / item.name.replace("[", "_").replace("]", "")
            for key, pg in getattr(item, "_srv_pages", {}).items():
                try:
                    shots.mkdir(parents=True, exist_ok=True)
                    pg.screenshot(path=str(shots / f"{key}.png"), full_page=False,
                                  mask=[pg.locator("#authCode"), pg.locator("#profileCode")])
                except Exception:
                    pass


@pytest.fixture(autouse=True)
def _name_current_test(request):
    _current_test["id"] = request.node.name
    _log(f"===== START {request.node.nodeid}")
    yield
    _log(f"===== END   {request.node.nodeid}")
    _current_test["id"] = "(session)"


# ── session: users, guard, owner API, pre-flight, sweep ───────────────────────
@pytest.fixture(scope="session")
def srv():
    """{'url', 'origin', 'users': {key: SrvUser}, 'owner': SrvUser} — every user
    logged in once via /pwa-login (no browser) to learn their role."""
    url, users = _load_users()
    origin = origin_of(url)
    st, body = http("GET", origin + "/pwa-token", timeout=30)
    if st != 200:
        pytest.exit(f"Server Jobs app not reachable ({url}): /pwa-token HTTP {st}", returncode=4)
    info = json.loads(body)
    if info.get("mode") != "server":
        pytest.exit(f"{url} is not in server mode (mode={info.get('mode')!r}).", returncode=4)
    if info.get("token"):
        pytest.exit("SECURITY: /pwa-token hands out a token — stopping.", returncode=5)
    for u in users:
        st, d = srv_login(origin, u.name, u.token)
        if st != 200 or not d.get("access_token"):
            pytest.exit(f"Login failed for {u.key} {u.name}: HTTP {st} {d.get('error', '')}", returncode=4)
        u.role, u.access_token = d.get("role", ""), d["access_token"]
        _SECRETS.append(u.access_token)
    owners = [u for u in users if u.role == "owner"]
    if not owners:
        pytest.exit("No owner among the configured users — setup/cleanup needs one.", returncode=4)
    STATE["users"] = ", ".join(repr(u) for u in users)
    _log(f"server {url} | users: {STATE['users']}")
    return {"url": url, "origin": origin, "users": {u.key: u for u in users}, "owner": owners[0]}


@pytest.fixture(scope="session")
def guard() -> Guard:
    return Guard(tier=TIER, log=_log)


@pytest.fixture(scope="session")
def owner_api(srv, guard) -> ApiClient:
    """Direct /pwa-api calls as the OWNER — setup and cleanup of ZTEST data."""
    client = ApiClient(srv["origin"], srv["owner"].access_token, guard, log=_log, api_log=_api_log)

    # Route stops are created by the server, so their ids are never in the
    # guard's registry. Let the guard look a stop up (as the owner, who sees
    # every crew's stops) and allow it only if its route is on a sandbox date.
    # The personal suite has had this since 2026-09-26; the server suite
    # didn't, so any stop-level action was blocked (found 2026-09-27 by
    # SRV-SCOPE-03).
    def _stop_route_date(stop_id):
        from api import iso_date
        for s in client.read("Route_Planner"):
            if str(s.get("ID", "")).strip() == str(stop_id).strip():
                return iso_date(s.get("Route Date", ""))
        return None

    guard.stop_resolver = _stop_route_date
    return client


@pytest.fixture(scope="session")
def api_as(srv, guard):
    """api_as('U2') -> ApiClient acting as that user (still through the guard)."""
    cache = {}

    def make(key: str) -> ApiClient:
        if key not in cache:
            u = srv["users"][key]
            cache[key] = ApiClient(srv["origin"], u.access_token, guard, log=_log,
                                   api_log=lambda e, k=key: _api_log(dict(e, as_user=k)))
        return cache[key]
    return make


@pytest.fixture(scope="session")
def data(owner_api) -> TestData:
    return TestData(owner_api, log=_log)


@pytest.fixture(scope="session", autouse=True)
def _session_preflight_and_cleanup(srv, owner_api, data, guard):
    _log(f"run dir {RUN_DIR} | tier {TIER} | keep_data {KEEP_DATA}")
    settings = {r.get("Setting", ""): r.get("Value", "") for r in owner_api.read("Settings")}
    if settings.get("Customer Reminder Daily Digest", "Disabled").strip().lower() == "enabled":
        pytest.exit("Server Settings → 'Customer Reminder Daily Digest' is Enabled — tests would send "
                    "real email. Disable it and re-run.", returncode=6)
    # R-059 (2026-09-29): "Email Route On Build" Enabled no longer stops the run —
    # the guard switches every build's auto-email off. On the server the email
    # goes to whichever user built the route (Samual included), so no real
    # route email is ever allowed here (route_email_to stays '').
    if settings.get("Email Route On Build", "Disabled").strip().lower() == "enabled":
        guard.route_email_on = True
        _log("Server Email Route On Build is Enabled — every route build's auto-email is switched off")
    from api import iso_date
    from safety import ZTEST_PREFIX, SANDBOX_DATES
    real = [f"{j.get('JobID (JOB-####)')} ({j.get('Customer Name / Company', '')})"
            for j in owner_api.read("Jobs_Schedule")
            if iso_date(j.get("Service Date", "")) in SANDBOX_DATES
            and not j.get("Customer Name / Company", "").startswith(ZTEST_PREFIX)]
    if real:
        pytest.exit(f"SAFETY: {len(real)} non-test job(s) on the server inside the sandbox window: "
                    f"{', '.join(real[:5])}. Stopping before anything is touched.", returncode=7)
    STATE["preflight"] = "ok"
    data.sweep("start-of-run")
    yield
    if KEEP_DATA:
        STATE["cleanup"] = "SKIPPED (--keep-data)"
        STATE["leftovers"] = data.leftovers()
        return
    try:
        STATE["cleanup"] = data.sweep("end-of-run")
        STATE["leftovers"] = data.leftovers()
    except Exception as e:
        STATE["cleanup"] = f"FAILED: {e}"
        STATE["leftovers"] = ["(could not verify — cleanup failed)"]


@pytest.fixture
def clean_slate(data):
    data.sweep("test start")
    yield
    data.sweep("test end")


# ── one browser window per user ───────────────────────────────────────────────
CONTEXT_ARGS = {"viewport": {"width": 900, "height": 860}, "permissions": ["geolocation"],
                "geolocation": {"latitude": 29.0258, "longitude": -80.9270},
                # SAFETY: with a service worker in control, API calls bypass page.route() (R-015)
                "service_workers": "block"}


def _install_guard(page, guard, request, user_key: str):
    """Every /pwa-api call from this window goes through the write guard; a
    request that leaves the browser without passing it fails the test."""
    seen, handled = [], []
    page.context.on("request", lambda r: seen.append(r.url) if "/pwa-api" in r.url else None)
    page.e2e_fakes = fakes = {}

    def on_api(route, req):
        handled.append(req.url)
        try:
            body = json.loads(req.post_data or "{}")
        except ValueError:
            body = {}
        tool, args = body.get("tool", ""), body.get("args") or {}
        fake = fakes.get(tool)
        if callable(fake):
            fake = fake(args)
        if fake is not None:
            _api_log({"source": f"browser:{user_key}", "tool": tool, "args": args, "status": "FAKED", "ok": True})
            route.fulfill(status=200, content_type="application/json", body=json.dumps({"ok": True, "result": fake}))
            return
        decision, why = guard.enforce(tool, args, f"browser:{user_key}")
        if decision == "block":
            _api_log({"source": f"browser:{user_key}", "tool": tool, "args": args, "status": "BLOCKED", "ok": False})
            route.abort()
            return
        if decision == "record":
            _api_log({"source": f"browser:{user_key}", "tool": tool, "args": args, "status": "RECORDED", "ok": True})
            route.fulfill(status=200, content_type="application/json", body=json.dumps(canned_reply(tool, why)))
            return
        # R-059: with Email Route On Build on, this build's auto-email is switched off
        sent_args, _note = guard.route_email_args(tool, args)
        fetch_kw = {}
        if sent_args != args:
            fetch_kw["post_data"] = json.dumps(dict(body, args=sent_args))
            args = sent_args
        try:
            resp = route.fetch(**fetch_kw)
            text = resp.text()
        except Exception as e:
            _log(f"late request after test end ignored: {tool} ({type(e).__name__})")
            try:
                route.abort()
            except Exception:
                pass
            return
        try:
            j = json.loads(text)
        except ValueError:
            j = {}
        if j.get("ok"):
            guard.note_result(tool, j.get("result", ""))
        _api_log({"source": f"browser:{user_key}", "tool": tool, "args": args, "status": resp.status,
                  "ok": bool(j.get("ok")), "excerpt": str(j.get("result", j.get("error", "")))[:300]})
        route.fulfill(response=resp, body=text)

    page.route("**/pwa-api", on_api)
    page.on("console", lambda m: _console_log(f"{user_key} {m.type}: {m.text}"))
    page.on("pageerror", lambda e: _console_log(f"{user_key} PAGEERROR: {e}"))
    page.on("response", lambda r: _console_log(f"{user_key} HTTP {r.status} {r.request.method} {r.url}")
            if r.status >= 400 else None)
    return seen, handled


class UserWindow:
    """One person's browser window: .page, .app (JobsApp), .user (SrvUser)."""

    def __init__(self, page, app, user):
        self.page, self.app, self.user = page, app, user

    def log_in(self, name: str | None = None, token: str | None = None):
        """Sign in through the real login screen, typing like a person."""
        from app import type_text
        from playwright.sync_api import expect
        a = self.app
        a.open_login_screen()
        expect(self.page.locator("#authName")).to_be_visible(timeout=15_000)   # server mode shows it
        n = self.user.name if name is None else name
        a.step(f"type name {n!r}")
        self.page.locator("#authName").fill("")
        if n:
            type_text(self.page, self.page.locator("#authName"), n)
        a.login(self.user.token if token is None else token)          # typed; token never logged
        return self


@pytest.fixture
def windows(browser, srv, guard, request):
    """windows('U1', 'U2') -> [UserWindow, ...], each in its own browser
    context (own storage, own sign-in), at the login screen's URL but NOT yet
    signed in — call .log_in(). Closed and guard-checked after the test."""
    opened = []
    request.node._srv_pages = {}

    def open_(*keys):
        from app import JobsApp
        out = []
        for key in keys:
            u = srv["users"][key]
            ctx = browser.new_context(**CONTEXT_ARGS)
            pg = ctx.new_page()
            pg.set_default_timeout(20_000)
            counts = _install_guard(pg, guard, request, key)
            w = UserWindow(pg, JobsApp(pg, srv["url"], lambda m, k=key: _log(f"[{k}] {m}")), u)
            opened.append((ctx, counts, key))
            request.node._srv_pages[key] = pg
            out.append(w)
        return out

    yield open_
    problems = []
    for ctx, (seen, handled), key in opened:
        if len(seen) > len(handled):
            problems.append(f"{key}: {len(seen) - len(handled)} API request(s) bypassed the guard")
    violations = guard.take_violations()
    for ctx, _, _ in opened:
        try:
            ctx.close()
        except Exception:
            pass
    if problems:
        pytest.fail("GUARD BYPASS — " + "; ".join(problems))
    if violations and not request.node.get_closest_marker("expect_guard_block"):
        pytest.fail("GUARD BLOCKED a write to non-test data: " +
                    "; ".join(f"{v['tool']} ({v['reason']})" for v in violations))


# ── SUMMARY.txt ───────────────────────────────────────────────────────────────
def pytest_sessionfinish(session, exitstatus):
    oc = STATE["outcomes"]
    passed = sum(1 for o in oc.values() if o[0] == "passed")
    failed = [(k, v) for k, v in oc.items() if v[0] == "failed"]
    skipped = sum(1 for o in oc.values() if o[0] == "skipped")
    left = STATE["leftovers"]
    clean_ok = left == [] and not str(STATE["cleanup"]).startswith("FAILED")
    overall = "PASS" if (not failed and passed and (clean_ok or KEEP_DATA)) else "FAIL"
    lines = [
        f"AI-Prowler Jobs app E2E — SERVER MODE — {overall}",
        f"Finished: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}   Tier: {TIER}   Sandbox date: {SANDBOX_DATE}",
        f"Users: {STATE['users'] or '(pre-flight did not finish)'}",
        f"Tests: {passed} passed, {len(failed)} failed, {skipped} skipped",
        f"Cleanup: {STATE['cleanup'] if STATE['cleanup'] is not None else 'did not run'}",
        ("" if left is None else
         "Cleanup: 0 ZTEST rows left ✅" if left == [] else
         f"Cleanup: {len(left)} ZTEST row(s) LEFT ❌: " + "; ".join(left)),
    ]
    if STATE["preflight"] != "ok":
        lines.insert(3, f"NO TESTS RAN (pytest exit code {int(exitstatus)}) — see pytest_output.txt")
    if failed:
        lines += ["", "Failed tests (screenshots per user: failures\\<test>\\<user>.png):"]
        for k, (_, first, dur) in failed:
            lines.append(f"  ✗ {k}  ({dur}s)\n      {first}")
    lines += ["", f"Full log: {RUN_DIR / 'run.log'}"]
    (RUN_DIR / "SUMMARY.txt").write_text(_scrub("\n".join(lines)) + "\n", encoding="utf-8")
    if overall == "FAIL" and exitstatus == 0:
        session.exitstatus = 1

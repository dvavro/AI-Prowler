"""pytest fixtures for the Jobs-app E2E suite (spec §3-§8).

Options come from environment variables (set by run_gui_jobs_e2e.py, so a
plain `python -m pytest tests\\gui_jobs_e2e -m jobs_gui_e2e` works too):
  E2E_RUN_DIR    folder for this run's logs/evidence (default: artifacts\\<timestamp>)
  E2E_TIER       safe (default) | email | full
  E2E_KEEP_DATA  1 = skip cleanup (inspect a failure in the app)
plus AIPROWLER_JOBS_TOKEN / AIPROWLER_JOBS_URL (see api.py).
Browser options are pytest-playwright's own: --headed, --slowmo, --browser-channel.
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
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from api import ApiClient, get_app_url, get_token, local_api_origin, origin_of  # noqa: E402
from data import TestData                                            # noqa: E402
from safety import Guard, canned_reply, SANDBOX_DATE                 # noqa: E402
from settings_switch import SettingsSwitch                           # noqa: E402

# ── run folder + logs ─────────────────────────────────────────────────────────
RUN_DIR = Path(os.environ.get("E2E_RUN_DIR") or
               HERE / "artifacts" / _dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
RUN_DIR.mkdir(parents=True, exist_ok=True)
TIER = (os.environ.get("E2E_TIER") or "safe").lower()
KEEP_DATA = os.environ.get("E2E_KEEP_DATA", "") == "1"

log = logging.getLogger("e2e")
if not log.handlers:
    log.setLevel(logging.INFO)
    _fh = logging.FileHandler(RUN_DIR / "run.log", encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", "%H:%M:%S"))
    log.addHandler(_fh)

_api_lock = threading.Lock()
_current_test = {"id": "(session)"}


def _log(msg: str):
    log.info(f"[{_current_test['id']}] {msg}")


def _api_log(entry: dict):
    entry = dict(entry, test=_current_test["id"], at=_dt.datetime.now().isoformat(timespec="milliseconds"))
    with _api_lock, open(RUN_DIR / "api_calls.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    _log(f"API {entry.get('source')}: {entry.get('tool')} -> {entry.get('status', '')} "
         f"{'ok' if entry.get('ok') else 'NOT ok'} ({entry.get('ms', '?')} ms)")


def _console_log(line: str):
    with _api_lock, open(RUN_DIR / "console.log", "a", encoding="utf-8") as f:
        f.write(f"[{_current_test['id']}] {line}\n")


STATE = {"cleanup": None, "leftovers": None, "backup": "", "preflight": "", "outcomes": {},
         "settings": None, "settings_switch": None}


def _personal_route_email_to() -> str:
    """Where a personal-mode route email goes: the SMTP config's default_to,
    else its username (same order as the server's _email_route_results). Reads
    only those two fields of ~/.ai-prowler/email_config.json; '' if unknown."""
    try:
        cfg = json.loads((Path.home() / ".ai-prowler" / "email_config.json").read_text(encoding="utf-8"))
        return str(cfg.get("default_to") or cfg.get("username") or "").strip()
    except Exception:
        return ""


# ── pytest hooks ──────────────────────────────────────────────────────────────
def pytest_configure(config):
    for m in ("no_login: test starts at the login screen (no saved session injected)",
              "expect_guard_block: the test deliberately triggers a guard block"):
        config.addinivalue_line("markers", m)


def pytest_collection_modifyitems(config, items):
    for it in items:
        if HERE in Path(str(it.fspath)).resolve().parents:
            it.add_marker(pytest.mark.jobs_gui_e2e)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        first = ""
        if rep.failed and rep.longrepr is not None:
            lines = [l for l in str(rep.longrepr).splitlines() if l.strip().startswith("E ")]
            first = (lines[0] if lines else str(rep.longrepr).splitlines()[-1])[:220]
        STATE["outcomes"][item.nodeid] = (rep.outcome, first, round(rep.duration, 1))


@pytest.fixture(autouse=True)
def _name_current_test(request):
    _current_test["id"] = request.node.name
    _log(f"===== START {request.node.nodeid}")
    yield
    _log(f"===== END   {request.node.nodeid}")
    _current_test["id"] = "(session)"


# ── session: config, guard, api, pre-flight, sweep, backup ────────────────────
@pytest.fixture(scope="session")
def app_url() -> str:
    return get_app_url()


@pytest.fixture(scope="session")
def token() -> str:
    t = get_token()
    if not t:
        pytest.exit("AIPROWLER_JOBS_TOKEN is not set — run: setx AIPROWLER_JOBS_TOKEN \"<token>\"", returncode=3)
    return t


@pytest.fixture(scope="session")
def guard() -> Guard:
    return Guard(tier=TIER, log=_log)


@pytest.fixture(scope="session")
def api(app_url, token, guard) -> ApiClient:
    client = ApiClient(local_api_origin(), token, guard, log=_log, api_log=_api_log)

    def _stop_route_date(stop_id: str):
        """Route date of a route stop (read-only lookup) — lets the guard
        recognise stops the SERVER created on sandbox routes (2026-09-26)."""
        from api import iso_date
        for s in client.read("Route_Planner"):
            if str(s.get("ID", "")).strip() == str(stop_id).strip():
                return iso_date(s.get("Route Date", ""))
        return None

    guard.stop_resolver = _stop_route_date

    def _customer(cid: str):
        """Name + email/phone on file for a customer (read-only lookup) — lets
        the guard see who a customer reminder would really reach (2026-09-28)."""
        for c in client.read("Customers"):
            if str(c.get("CustomerID (CUST-####)", "")).strip() == str(cid).strip():
                return {"name": c.get("Company Name", ""), "email": c.get("Email", ""),
                        "phone": c.get("Phone", "")}
        return None

    guard.customer_resolver = _customer
    return client


@pytest.fixture(scope="session")
def data(api) -> TestData:
    return TestData(api, log=_log)


@pytest.fixture(scope="session", autouse=True)
def _session_preflight_and_cleanup(app_url, token, api, data, guard):
    _log(f"run dir {RUN_DIR} | tier {TIER} | keep_data {KEEP_DATA} | app {app_url}")
    # server reachable + secured (§6.13 — nothing runs against an unprotected server)
    st, body = api.raw_get("/pwa-token")
    if st != 200:
        pytest.exit(f"Jobs app not reachable ({app_url}): /pwa-token HTTP {st}", returncode=4)
    try:
        if json.loads(body).get("token"):
            pytest.exit("SECURITY: /pwa-token is handing out the Bearer Token — stopping. "
                        "Deploy the 2026-09-25 security fix.", returncode=5)
    except ValueError:
        pass
    # settings that would make tests send real email (§4.4)
    settings = {r.get("Setting", ""): r.get("Value", "") for r in api.read("Settings")}
    if settings.get("Customer Reminder Daily Digest", "Disabled").strip().lower() == "enabled":
        pytest.exit("Settings → 'Customer Reminder Daily Digest' is Enabled — tests would send real "
                    "email. Disable it and re-run.", returncode=6)
    # "Email Route On Build" Enabled no longer stops the run (R-059, David
    # 2026-09-29: it was a test gap). The guard switches the automatic route
    # email off on every build except the ONE real one to David (tier email+).
    guard.route_email_to = _personal_route_email_to()
    # R-060: the three email/SMS toggles may be flipped by tests — save the
    # originals first (and put back a killed run's leftovers). From here on the
    # guard knows each toggle's value.
    switch = SettingsSwitch(api, guard, log=_log)
    snap = switch.snapshot()
    STATE["settings_switch"] = switch
    if snap["recovered"]:
        _log(f"settings: put back after an interrupted run: {snap['recovered']}")
    _log(f"Email Route On Build is {'Enabled' if guard.route_email_on else 'Disabled'} — route builds' "
         f"auto-email is handled by the guard; the one allowed real one (tier email/full) would go to "
         f"{guard.route_email_to or '(unknown)'}")
    # The sandbox date is TODAY (safety.py) and the sweep deletes every job on
    # it — so refuse to run if anything that ISN'T test data is on that date.
    # On the validation database this never triggers; on a database with real
    # work it stops the run before anything is touched.
    from api import iso_date
    from safety import ZTEST_PREFIX, SANDBOX_DATES
    real = [f"{j.get('JobID (JOB-####)')} ({j.get('Customer Name / Company', '')}, {j.get('Service Date', '')})"
            for j in api.read("Jobs_Schedule")
            if iso_date(j.get("Service Date", "")) in SANDBOX_DATES
            and not j.get("Customer Name / Company", "").startswith(ZTEST_PREFIX)]
    if real:
        pytest.exit(f"SAFETY: {len(real)} non-test job(s) are inside the sandbox window "
                    f"({min(SANDBOX_DATES)} .. {max(SANDBOX_DATES)}): "
                    f"{', '.join(real[:5])}{' …' if len(real) > 5 else ''}. The suite deletes every job "
                    "on its sandbox date — run it only against the validation database, or set "
                    "E2E_SANDBOX_DATE to an empty day.", returncode=7)
    STATE["preflight"] = "ok"
    # clean slate + safety net
    data.sweep("start-of-run")
    try:
        STATE["backup"] = api.call("backup_job_database", {}).splitlines()[0]
    except Exception as e:
        # The Jobs app's API deliberately doesn't expose backup_job_database
        # (found 2026-09-25) and it isn't added just for tests. Every delete
        # the suite does already makes its own server-side safety backup first.
        STATE["backup"] = ("not available through the Jobs app API — relying on the automatic "
                           "safety backup the server makes before every delete")
        _log(f"backup: {e}")
    _log(f"backup: {STATE['backup']}")
    yield
    # R-060: Settings toggles back to what they were — always, even --keep-data
    try:
        switch.restore()
        settings_left = switch.verify()
    except Exception as e:
        settings_left = [f"(could not verify Settings toggles — {e})"]
    STATE["settings"] = settings_left or "all back as they were"
    if KEEP_DATA:
        STATE["cleanup"] = "SKIPPED (--keep-data)"
        STATE["leftovers"] = list(data.leftovers()) + settings_left
        return
    try:
        STATE["cleanup"] = data.sweep("end-of-run")
        STATE["leftovers"] = list(data.leftovers()) + settings_left
    except Exception as e:                                  # never hide a cleanup failure
        STATE["cleanup"] = f"FAILED: {e}"
        STATE["leftovers"] = ["(could not verify — cleanup failed)"] + settings_left


@pytest.fixture
def toggles():
    """R-060: flip the email/SMS Settings toggles inside a test —
    toggles.set("Email Route On Build", "Enabled"). Every toggle is put back
    to its original value as soon as the test ends (pass or fail)."""
    switch = STATE.get("settings_switch")
    if switch is None:
        pytest.skip("Settings toggles weren't saved by the pre-flight")
    yield switch
    try:
        switch.restore()
    finally:
        left = switch.verify()
        if left:
            _log(f"settings: NOT back after the test: {left}")


# ── browser: guard on every page, console capture, optional auto-login ───────
@pytest.fixture
def browser_context_args(browser_context_args):
    # Route screen's origin logic (GPS start-point option) calls the browser
    # geolocation API — without a granted permission, Chromium shows a real,
    # native "wants to know your location" prompt that Playwright's
    # page.on("dialog") CANNOT see or dismiss (that's for JS alert/confirm/
    # prompt only), so it hangs the test — and, if a run gets killed while one
    # is open, leaves an orphaned msedge.exe process behind. Granting it a
    # fixed New Smyrna Beach location up front means the API just answers
    # instantly with no prompt at all.
    #
    # service_workers="block" — SAFETY (found 2026-09-26): once the Jobs app's
    # service worker takes control of the page (a second or two after load —
    # always in --human mode, sometimes in fast runs), the app's API requests
    # are made BY the service worker, and page.route() never sees them: in the
    # --human run of 2026-09-26 08:51 the AI Route / Email Route clicks went
    # straight to the real server, past the write guard. With service workers
    # blocked every request goes through the guard (and the bypass alarm in
    # the page fixture fails the test if one ever doesn't). PWA-behaviour tests
    # that need the service worker must opt back in explicitly.
    return {**browser_context_args, "viewport": {"width": 1400, "height": 900},
            "permissions": ["geolocation"], "geolocation": {"latitude": 29.0258, "longitude": -80.9270},
            "service_workers": "block"}


@pytest.fixture
def page(page, request, guard, token, app_url):
    page.set_default_timeout(20_000)
    # Bypass alarm (2026-09-26): count every /pwa-api request that leaves the
    # browser (context-level — also sees service-worker traffic) against the
    # ones the guard's route handler actually handled. Any difference means a
    # request reached the real server unchecked -> the test FAILS, loudly.
    seen, handled = [], []
    page.context.on("request", lambda r: seen.append(
        (r.url, (r.post_data or "")[:200])) if "/pwa-api" in r.url else None)
    # Faked replies (2026-09-26): a test can set page.e2e_fakes[tool] = "<reply text>"
    # to answer that tool from the browser side — e.g. make the app believe SMS
    # is configured on an install where it isn't. A faked call never reaches the
    # server at all, so it's safe by construction; it's still counted as handled
    # (no bypass alarm) and logged as FAKED.
    fakes = {}
    page.e2e_fakes = fakes

    def on_api(route, req):
        handled.append(req.url)
        try:
            body = json.loads(req.post_data or "{}")
        except ValueError:
            body = {}
        tool, args = body.get("tool", ""), body.get("args") or {}
        # A fake may be a fixed reply, or a function(args) -> reply | None
        # (None = not this call, let it through normally).
        fake = fakes.get(tool)
        if callable(fake):
            fake = fake(args)
        if isinstance(fake, dict) and "http_status" in fake:
            # A faked FAILURE (2026-09-26, NAV-02): answer with that HTTP status,
            # e.g. {"http_status": 503} — the server is never contacted.
            _api_log({"source": "browser", "tool": tool, "args": args, "status": f"FAKED {fake['http_status']}",
                      "ok": False})
            route.fulfill(status=int(fake["http_status"]), content_type="application/json",
                          body=json.dumps(fake.get("body", {"ok": False, "error": "E2E faked failure"})))
            return
        if fake is not None:
            _api_log({"source": "browser", "tool": tool, "args": args, "status": "FAKED", "ok": True,
                      "excerpt": str(fake)[:300]})
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"ok": True, "result": fake}))
            return
        decision, why = guard.enforce(tool, args, "browser")
        if decision == "block":
            _api_log({"source": "browser", "tool": tool, "args": args, "status": "BLOCKED", "ok": False})
            route.abort()
            return
        if decision == "record":
            _api_log({"source": "browser", "tool": tool, "args": args, "status": "RECORDED", "ok": True})
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps(canned_reply(tool, why)))
            return
        # R-059: with Email Route On Build on, switch this build's auto-email off
        # (unless it's the one allowed real route email) before it reaches the server
        sent_args, _note = guard.route_email_args(tool, args)
        fetch_kw = {}
        if sent_args != args:
            fetch_kw["post_data"] = json.dumps(dict(body, args=sent_args))
            args = sent_args
        try:
            resp = route.fetch(**fetch_kw)
            text = resp.text()
        except Exception as e:
            # The test ended (browser closing) while the app still had a
            # request in flight — nothing to check any more. Found 2026-09-26:
            # "Route.fetch: Request context disposed" surfaced as the NEXT
            # test's error.
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
        _api_log({"source": "browser", "tool": tool, "args": args, "status": resp.status,
                  "ok": bool(j.get("ok")), "excerpt": str(j.get("result", j.get("error", "")))[:300]})
        route.fulfill(response=resp, body=text)

    page.route("**/pwa-api", on_api)
    page.on("console", lambda m: _console_log(f"{m.type}: {m.text}"))
    page.on("pageerror", lambda e: _console_log(f"PAGEERROR: {e}"))
    # The browser's "Failed to load resource: 503" console line doesn't say
    # WHICH resource — log every failed response with its URL (found on the
    # Calendar screen, 2026-09-25).
    page.on("response", lambda r: _console_log(f"HTTP {r.status} {r.request.method} {r.url}")
            if r.status >= 400 else None)
    if not request.node.get_closest_marker("no_login"):
        page.add_init_script(
            "try{localStorage.setItem('ap_auth'," + json.dumps(json.dumps({"mode": "personal", "token": token}))
            + ")}catch(e){}")
    yield page
    # NOTE: deliberately NOT page.unroute_all() here — removing the guard's
    # interception before the browser closes would let a late request reach
    # the server unchecked. A late request whose browser has already closed is
    # dropped by the handler instead (see the Route.fetch note above).
    #
    # 2026-10-02: a request is "seen" a moment BEFORE the guard's handler runs,
    # so a request made right at the end of a test looked like a bypass (BTN
    # AI-route tests: the call was RECORDED a split second later, nothing reached
    # the server). Give the handler up to 2 s to catch up — wait_for_timeout
    # keeps the browser's events flowing — before calling it a bypass.
    for _ in range(10):
        if len(seen) <= len(handled):
            break
        try:
            page.wait_for_timeout(200)
        except Exception:
            break
    if len(seen) > len(handled):
        missed = seen[len(handled):] if len(handled) else seen
        _log(f"GUARD BYPASS: {len(seen)} /pwa-api requests left the browser, guard handled {len(handled)}")
        pytest.fail(f"GUARD BYPASS — {len(seen) - len(handled)} API request(s) reached the server without "
                    f"passing the write guard (service worker?). First unchecked: {missed[:2]}")
    violations = guard.take_violations()
    if violations and not request.node.get_closest_marker("expect_guard_block"):
        pytest.fail("GUARD BLOCKED a write to non-test data: " +
                    "; ".join(f"{v['tool']} ({v['reason']})" for v in violations))


@pytest.fixture
def app(page, app_url):
    """The Jobs app, logged in and showing its main screen."""
    from app import JobsApp
    a = JobsApp(page, app_url, _log)
    a.open()
    return a


@pytest.fixture
def route(app, page):
    """The Route screen, navigated to and ready (spec §6.5)."""
    from app import RouteScreen
    app.goto("route")
    return RouteScreen(page, _log)


@pytest.fixture
def clean_slate(data):
    """Sweeps ZTEST data before AND after a test, so route/prescreen tests
    that depend on an exact job count on the sandbox date aren't polluted by
    an earlier test's jobs still sitting there (module-level cleanup alone,
    per spec §4.5, only runs at module end)."""
    data.sweep("test start")
    yield
    data.sweep("test end")


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
        f"AI-Prowler Jobs app E2E — {overall}",
        f"Finished: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}   Tier: {TIER}   Sandbox date: {SANDBOX_DATE}",
        f"Tests: {passed} passed, {len(failed)} failed, {skipped} skipped",
        f"Database backup before first write: {STATE['backup'] or '(none — pre-flight stopped the run)'}",
        f"Cleanup: {STATE['cleanup'] if STATE['cleanup'] is not None else 'did not run (the run stopped before any test data was created)'}",
        ("" if left is None else
         "Cleanup: 0 ZTEST rows left ✅" if left == [] else
         f"Cleanup: {len(left)} ZTEST row(s) LEFT ❌: " + "; ".join(left)),
        ("" if not STATE.get("settings") else
         "Settings toggles: all back as they were ✅" if STATE["settings"] == "all back as they were" else
         "Settings toggles NOT back ❌: " + "; ".join(STATE["settings"])),
    ]
    if STATE["preflight"] != "ok":
        lines.insert(3, f"NO TESTS RAN (pytest exit code {int(exitstatus)}) — the pre-flight stopped the run, "
                        "or pytest couldn't start (e.g. a bad -k expression). See pytest_output.txt")
    if failed:
        lines.append("")
        lines.append("Failed tests (evidence: failures\\<test>\\trace.zip — "
                     "open with: python -m playwright show-trace <path>):")
        for k, (_, first, dur) in failed:
            lines.append(f"  ✗ {k}  ({dur}s)\n      {first}")
    lines.append("")
    lines.append(f"Full log: {RUN_DIR / 'run.log'}")
    (RUN_DIR / "SUMMARY.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if overall == "FAIL" and exitstatus == 0:
        session.exitstatus = 1          # leftover test data fails the run even if every test passed

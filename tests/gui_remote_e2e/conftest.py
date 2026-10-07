"""pytest fixtures for the Remote PWA E2E suite (REMOTE_PWA_E2E_TEST_SPEC.md).

Personal mode only. Browser → the Remote PWA at AIPROWLER_REMOTE_URL (default:
the Jobs app's tunnel origin + /remote/). Setup / cleanup → /remote-api on
http://127.0.0.1:8000 directly (no Cloudflare). Token = AIPROWLER_JOBS_TOKEN
(the personal Bearer Token). Everything passes RemoteGuard.
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
SHARED = HERE.parent / "gui_jobs_e2e"
for p in (str(SHARED), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from api import get_app_url, get_token, http, local_api_origin, origin_of   # noqa: E402
from remote_safety import (RemoteGuard, SANDBOX, ZTEST, ZTEST_FILE_PREFIX,  # noqa: E402
                           canned_reply, is_sandbox)

RUN_DIR = Path(os.environ.get("E2E_RUN_DIR") or
               HERE / "artifacts" / _dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
RUN_DIR.mkdir(parents=True, exist_ok=True)
KEEP_DATA = os.environ.get("E2E_KEEP_DATA", "") == "1"
SEED_NAME = "ZTEST_E2E_seed.txt"
SEED_TEXT = ("ZTEST E2E seed file for the Remote PWA tests.\n"
             "Line 2: zqxremoteseed marker.\nLine 3: safe to delete.\n")

log = logging.getLogger("e2e_remote")
if not log.handlers:
    log.setLevel(logging.INFO)
    _fh = logging.FileHandler(RUN_DIR / "run.log", encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", "%H:%M:%S"))
    log.addHandler(_fh)

_lock = threading.Lock()
_current = {"id": "(session)"}
_SECRETS: list[str] = []
STATE = {"cleanup": None, "left": None, "preflight": "", "outcomes": {}, "sandbox_was_writable": None}


def _scrub(t: str) -> str:
    for s in _SECRETS:
        if s:
            t = t.replace(s, "«token»").replace(s[:8], "«token-start»")
    return t


def _log(msg: str):
    log.info(_scrub(f"[{_current['id']}] {msg}"))


def _api_log(entry: dict):
    entry = dict(entry, test=_current["id"], at=_dt.datetime.now().isoformat(timespec="milliseconds"))
    with _lock, open(RUN_DIR / "api_calls.jsonl", "a", encoding="utf-8") as f:
        f.write(_scrub(json.dumps(entry, ensure_ascii=False)) + "\n")
    _log(f"API {entry.get('source')}: {entry.get('tool')} -> {entry.get('status', '')}")


# ── direct API client (setup / cleanup), guarded ──────────────────────────────
class RemoteApi:
    def __init__(self, origin: str, token: str, guard: RemoteGuard):
        self.origin, self.token, self.guard = origin, token, guard

    def call(self, tool: str, args: dict | None = None, source: str = "setup") -> dict:
        decision, why = self.guard.enforce(tool, args, source)
        if decision == "record":
            return canned_reply(tool, why)
        if decision == "block":
            raise RuntimeError(f"GUARD BLOCKED {tool}: {why}")
        st, raw = http("POST", self.origin + "/remote-api", {"tool": tool, "args": args or {}},
                       token=self.token, timeout=60)
        try:
            d = json.loads(raw)
        except ValueError:
            d = {"ok": False, "error": raw[:200]}
        if d.get("ok"):
            self.guard.note_result(tool, d.get("result", ""))
        _api_log({"source": source, "tool": tool, "args": args or {}, "status": st, "ok": d.get("ok"),
                  "excerpt": str(d.get("result", d.get("error", "")))[:300]})
        return d

    def text(self, tool: str, args: dict | None = None) -> str:
        d = self.call(tool, args)
        return str(d.get("result", "")) if d.get("ok") else "❌ " + str(d.get("error", ""))

    # sandbox write state, as the server sees it — the SAME rule the Remote app
    # uses (loadFilesList / loadPerms): a folder is writable only if its own line
    # in list_writable_directories carries [W]. (That tool also lists the READ
    # zone, so "the path appears in the text" is true either way.)
    def sandbox_writable(self) -> bool:
        target = str(SANDBOX).lower()
        for line in self.text("list_writable_directories").splitlines():
            if "[W]" not in line:
                continue
            s = "".join(ch for ch in line if 32 <= ord(ch) < 127).replace("[W]", "").strip().lower()
            if s.rstrip("\\") == target:
                return True
        return False


# ── sweeps ────────────────────────────────────────────────────────────────────
def _ztest_learning_ids(api: RemoteApi) -> list[str]:
    import re
    txt = api.text("list_learnings", {"limit": 500})
    ids = []
    for block in re.split(r"\n\s*\n|\n(?=\s*\d+[.)] )", txt):
        if ZTEST in block:
            ids += re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", block, re.I)
    return sorted(set(ids))


def _ztest_task_ids(api: RemoteApi) -> list[str]:
    txt = api.text("list_analysis_tasks")
    try:
        tasks = json.loads(txt).get("tasks", [])
    except (ValueError, AttributeError):
        return []
    return [t["task_id"] for t in tasks if str(t.get("label", "")).startswith(ZTEST)]


def _sandbox_files() -> list[Path]:
    return [p for p in SANDBOX.glob(ZTEST_FILE_PREFIX + "*") if p.is_file()]


def _sandbox_dirs() -> list[Path]:
    return [p for p in SANDBOX.glob(ZTEST_FILE_PREFIX + "*") if p.is_dir()]


def sweep(api: RemoteApi, why: str) -> dict:
    n = {"learnings": 0, "tasks": 0, "files": 0}
    for lid in _ztest_learning_ids(api):
        api.guard.register(lid, "(sweep)")
        if api.call("delete_learning", {"learning_id": lid}, source="sweep").get("ok"):
            n["learnings"] += 1
    for tid in _ztest_task_ids(api):
        api.guard.register(tid, "(sweep)")
        if api.call("delete_analysis_task", {"task_id": tid}, source="sweep").get("ok"):
            n["tasks"] += 1
    for f in _sandbox_files():
        if f.name == SEED_NAME and why == "test":
            continue
        try:
            f.unlink()
            n["files"] += 1
        except OSError:
            pass
    import shutil
    for d in _sandbox_dirs():                 # e.g. RF-02's ZTEST_E2E_sub, if a run was cut short
        shutil.rmtree(d, ignore_errors=True)
        n["files"] += 1
    _log(f"SWEEP ({why}): {n}")
    return n


def leftovers(api: RemoteApi) -> list[str]:
    left = [f"learning {i}" for i in _ztest_learning_ids(api)]
    left += [f"task {i}" for i in _ztest_task_ids(api)]
    left += [f"file {p.name}" for p in _sandbox_files()]
    left += [f"folder {p.name}" for p in _sandbox_dirs()]
    return left


# ── hooks ─────────────────────────────────────────────────────────────────────
def pytest_collection_modifyitems(config, items):
    for it in items:
        if HERE in Path(str(it.fspath)).resolve().parents:
            it.add_marker(pytest.mark.remote_gui_e2e)
    # security first (spec §5.8)
    items.sort(key=lambda it: 0 if "test_remote_security" in str(it.fspath) else 1)


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
        if rep.failed:
            pg = getattr(item, "_remote_page", None)
            if pg is not None:
                try:
                    d = RUN_DIR / "failures"
                    d.mkdir(exist_ok=True)
                    pg.screenshot(path=str(d / f"{item.name[:80]}.png"),
                                  mask=[pg.locator("#authInput"), pg.locator("#raInput"),
                                        pg.locator("#debugLog")])
                except Exception:
                    pass


@pytest.fixture(autouse=True)
def _name_current_test(request):
    _current["id"] = request.node.name
    _log(f"===== START {request.node.nodeid}")
    yield
    _log(f"===== END   {request.node.nodeid}")
    _current["id"] = "(session)"


# ── session ───────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def token() -> str:
    t = get_token()
    if not t:
        pytest.exit("AIPROWLER_JOBS_TOKEN (the personal Bearer Token) is not set.", returncode=3)
    _SECRETS.append(t)
    return t


@pytest.fixture(scope="session")
def remote_url() -> str:
    u = os.environ.get("AIPROWLER_REMOTE_URL", "").strip()
    return u or origin_of(get_app_url()) + "/remote/"


@pytest.fixture(scope="session")
def guard() -> RemoteGuard:
    return RemoteGuard(log=_log)


@pytest.fixture(scope="session")
def rapi(token, guard) -> RemoteApi:
    return RemoteApi(local_api_origin(), token, guard)


@pytest.fixture(scope="session", autouse=True)
def _session_preflight_and_cleanup(rapi, token, remote_url):
    origin = local_api_origin()
    st, body = http("GET", origin + "/pwa-token", timeout=30)
    if st != 200:
        pytest.exit(f"AI-Prowler not reachable at {origin} (/pwa-token HTTP {st}).", returncode=4)
    info = json.loads(body)
    if info.get("mode", "personal") != "personal":
        pytest.exit("The Remote PWA suite is personal-mode only — this install is in server mode.", returncode=4)
    if info.get("token"):
        pytest.exit("SECURITY: /pwa-token hands out a token — stopping.", returncode=5)
    st, _ = http("POST", origin + "/pwa-verify", {"token": token}, timeout=30)
    if st != 200:
        pytest.exit(f"The personal Bearer Token isn't accepted (/pwa-verify HTTP {st}).", returncode=4)
    SANDBOX.mkdir(parents=True, exist_ok=True)
    tracked = rapi.text("list_tracked_directories").lower()
    sb = str(SANDBOX).lower()
    if not any(sb.startswith(line.strip(" 📁📄0123456789.").strip().lower())
               for line in tracked.splitlines() if ":\\" in line):
        pytest.exit(f"The sandbox {SANDBOX} isn't inside a tracked folder, so the Remote PWA can't "
                    "show it. Track its parent folder first.", returncode=4)
    STATE["sandbox_was_writable"] = rapi.sandbox_writable()
    _log(f"run dir {RUN_DIR} | url {remote_url} | sandbox {SANDBOX} "
         f"(writable at start: {STATE['sandbox_was_writable']})")
    sweep(rapi, "start-of-run")
    (SANDBOX / SEED_NAME).write_text(SEED_TEXT, encoding="utf-8")
    STATE["preflight"] = "ok"
    yield
    # restore the sandbox's write setting to what it was before the run
    try:
        now = rapi.sandbox_writable()
        want = STATE["sandbox_was_writable"]
        if want is not None and now != want:
            rapi.call("grant_write_access" if want else "revoke_write_access",
                      {"directory": str(SANDBOX)}, source="cleanup")
    except Exception as e:
        _log(f"could not restore sandbox write setting: {e}")
    if KEEP_DATA:
        STATE["cleanup"], STATE["left"] = "SKIPPED (--keep-data)", leftovers(rapi)
        return
    try:
        STATE["cleanup"] = sweep(rapi, "end-of-run")
        STATE["left"] = leftovers(rapi)
    except Exception as e:
        STATE["cleanup"], STATE["left"] = f"FAILED: {e}", ["(could not verify)"]


@pytest.fixture
def clean_slate(rapi):
    sweep(rapi, "test")
    yield
    sweep(rapi, "test")


# ── browser ───────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    # a service worker in control would let API calls bypass page.route()
    return {**browser_context_args, "service_workers": "block",
            "viewport": {"width": 1000, "height": 860}, "accept_downloads": True}


@pytest.fixture
def page(page, request, guard):
    page.set_default_timeout(20_000)
    request.node._remote_page = page
    seen, handled = [], []
    page.context.on("request", lambda r: seen.append(r.url)
                    if ("/remote-api" in r.url or "/remote/upload" in r.url) else None)

    def on_api(route, req):
        handled.append(req.url)
        try:
            body = json.loads(req.post_data or "{}")
        except ValueError:
            body = {}
        tool, args = body.get("tool", ""), body.get("args") or {}
        decision, why = guard.enforce(tool, args, "browser")
        if decision == "block":
            _api_log({"source": "browser", "tool": tool, "args": args, "status": "BLOCKED"})
            route.abort()
            return
        if decision == "record":
            _api_log({"source": "browser", "tool": tool, "args": args, "status": "RECORDED"})
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps(canned_reply(tool, why)))
            return
        _pass_through(route, tool, args)

    def on_upload(route, req):
        handled.append(req.url)
        try:
            body = json.loads(req.post_data or "{}")
        except ValueError:
            body = {}
        decision, why = guard.enforce("upload", {"dir": body.get("dir"), "filename": body.get("filename")},
                                      "browser", decision=guard.check_upload(body))
        if decision != "allow":
            _api_log({"source": "browser", "tool": "upload", "args": {"dir": body.get("dir"),
                      "filename": body.get("filename")}, "status": "BLOCKED"})
            route.abort()
            return
        _pass_through(route, "upload", {"dir": body.get("dir"), "filename": body.get("filename")})

    def _pass_through(route, tool, args):
        try:
            resp = route.fetch()
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
        _api_log({"source": "browser", "tool": tool, "args": args, "status": resp.status,
                  "ok": bool(j.get("ok")), "excerpt": str(j.get("result", j.get("error", "")))[:300]})
        route.fulfill(response=resp, body=text)

    page.route("**/remote-api", on_api)
    page.route("**/remote/upload", on_upload)
    page.on("pageerror", lambda e: _log(f"PAGEERROR: {e}"))
    yield page
    v = guard.take_violations()
    if len(seen) > len(handled):
        pytest.fail(f"GUARD BYPASS — {len(seen) - len(handled)} request(s) skipped the guard")
    if v and not request.node.get_closest_marker("expect_guard_block"):
        pytest.fail("GUARD BLOCKED a write to real data: " + "; ".join(f"{x['tool']} ({x['reason']})" for x in v))


@pytest.fixture
def ui(page, remote_url):
    """RemoteApp at the login screen (not signed in)."""
    from remote_app import RemoteApp
    return RemoteApp(page, remote_url, _log).open_login_screen()


@pytest.fixture
def remote(ui, token):
    """RemoteApp signed in (token typed like a person)."""
    return ui.login(token).signed_in()


def pytest_configure(config):
    config.addinivalue_line("markers", "expect_guard_block: the test deliberately triggers a guard block")
    config.addinivalue_line("markers", "remote_gui_e2e: Remote PWA E2E (tests\\gui_remote_e2e)")


# ── SUMMARY.txt ───────────────────────────────────────────────────────────────
def pytest_sessionfinish(session, exitstatus):
    oc = STATE["outcomes"]
    passed = sum(1 for o in oc.values() if o[0] == "passed")
    failed = [(k, v) for k, v in oc.items() if v[0] == "failed"]
    skipped = sum(1 for o in oc.values() if o[0] == "skipped")
    left = STATE["left"]
    ok_clean = left == [] and not str(STATE["cleanup"]).startswith("FAILED")
    overall = "PASS" if (not failed and passed and (ok_clean or KEEP_DATA)) else "FAIL"
    lines = [f"AI-Prowler Remote PWA E2E — {overall}",
             f"Finished: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}",
             f"Tests: {passed} passed, {len(failed)} failed, {skipped} skipped",
             f"Cleanup: {STATE['cleanup']}",
             "" if left is None else ("Cleanup: 0 ZTEST items left ✅" if left == [] else
                                      f"Cleanup: {len(left)} ZTEST item(s) LEFT ❌: " + "; ".join(left))]
    if STATE["preflight"] != "ok":
        lines.insert(2, f"NO TESTS RAN (pytest exit code {int(exitstatus)}) — see pytest_output.txt")
    if failed:
        lines += ["", "Failed tests (screenshots: failures\\):"]
        lines += [f"  ✗ {k}  ({d}s)\n      {f}" for k, (_, f, d) in failed]
    lines += ["", f"Full log: {RUN_DIR / 'run.log'}"]
    (RUN_DIR / "SUMMARY.txt").write_text(_scrub("\n".join(lines)) + "\n", encoding="utf-8")
    if overall == "FAIL" and exitstatus == 0:
        session.exitstatus = 1

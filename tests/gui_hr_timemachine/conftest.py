"""
tests/gui_hr_timemachine — HR onboarding / offboarding SEQUENCING in a real
browser against a TIME MACHINE sandbox server (David, 2026-10-17).

hr_tm_server.py runs a throwaway AI-Prowler SERVER install (own temp folder,
ZTEST users, emails caught in an outbox, nothing sent) whose clock the tests
move. Each simulated morning the HR scheduler's jobs run in their real order
(POST /run-day); HR Admin and the HR Portal are driven in Chromium.

Part of the normal run_tests.bat run (sandbox only - safe). Skips cleanly when
Playwright / Chromium / time_machine isn't installed. On its own:
    tests\\run_tests_hr_gui_e2e.bat --timemachine [--headed]
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "gui_hr_e2e"))
from hr_gui_helpers import http  # noqa: E402
from hr_tm_helpers import HIRE_DAY, USERS  # noqa: E402

REAL_HR = Path.home() / ".ai-prowler" / "hr"
START_DATE = HIRE_DAY.isoformat()                 # the time machine starts on hire day (a Monday)


def pytest_collection_modifyitems(config, items):
    for it in items:
        if "gui_hr_timemachine" in str(it.fspath):
            it.add_marker(pytest.mark.hr_gui_timemachine)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fingerprint(folder: Path):
    if not folder.exists():
        return None
    return sorted((str(p.relative_to(folder)), p.stat().st_size, int(p.stat().st_mtime))
                  for p in folder.rglob("*") if p.is_file())


class TM:
    def __init__(self, base, ctl, home, proc):
        self.base, self.ctl, self.home, self.proc = base, ctl, home, proc

    def api(self, method, path, payload=None, who="owner", **kw):
        return http(method, f"{self.base}/hr-api{path}", token=USERS[who][1], payload=payload, **kw)

    def clock(self, date, time_="09:00"):
        st, j = http("POST", f"{self.ctl}/clock", payload={"date": str(date), "time": time_})
        assert st == 200, j

    def run_day(self, date):
        st, j = http("POST", f"{self.ctl}/run-day", payload={"date": str(date)}, timeout=60)
        assert st == 200, f"{date}: scheduler errors {j}"
        return j

    def walk(self, first, last):
        import datetime as dt
        d = first
        while d <= last:
            self.run_day(d)
            d += dt.timedelta(days=1)

    def outbox(self):
        return http("GET", f"{self.ctl}/outbox")[1]

    def today(self):
        return http("GET", f"{self.ctl}/state")[1]["today"]


@pytest.fixture(scope="session")
def tm(tmp_path_factory):
    for mod in ("playwright", "time_machine"):
        try:
            __import__(mod)
        except Exception:
            pytest.skip(f"{mod} isn't installed - needed for the HR time-machine browser tests")
    before = _fingerprint(REAL_HR)
    home = tmp_path_factory.mktemp("hr_time_machine_home")
    users_file = home.parent / (home.name + "_users.json")
    users_file.write_text(json.dumps({"users": {
        tok: {"name": n, "role": role, "status": "active", "email": em, "cell_phone": ""}
        for n, tok, role, em in USERS.values()}}), encoding="utf-8")
    port, cport = _free_port(), _free_port()
    log = open(home.parent / (home.name + "_server.log"), "w", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(HERE / "hr_tm_server.py"), "--home", str(home),
                             "--port", str(port), "--control-port", str(cport),
                             "--token", USERS["owner"][1], "--users-file", str(users_file), "--date", START_DATE],
                            cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
                            env={k: v for k, v in os.environ.items() if k != "AIPROWLER_TEST_STATE_DIR"})
    base, ctl = f"http://127.0.0.1:{port}", f"http://127.0.0.1:{cport}"
    deadline = time.time() + 120
    while time.time() < deadline and proc.poll() is None:
        if http("GET", f"{base}/health", timeout=3)[0] == 200 and http("GET", f"{ctl}/state", timeout=3)[0] == 200:
            break
        time.sleep(1)
    if http("GET", f"{base}/health", timeout=3)[0] != 200:
        proc.kill()
        log.close()
        pytest.fail("HR time-machine server didn't start:\n" + "\n".join(
            (home.parent / (home.name + "_server.log")).read_text(encoding="utf-8", errors="replace").splitlines()[-40:]))
    t = TM(base, ctl, home, proc)
    assert t.today() == START_DATE, t.today()
    st, j = t.api("POST", "/setup/complete", {
        "company_name": "ZTEST Time Machine Co", "work_states": ["FL"], "setup_complete": True,
        "hr_admin_email": "hr+hrtest@example.com", "owner_email": "owner+hrtest@example.com"})
    assert st == 200, j
    yield t
    try:
        http("POST", f"{ctl}/stop", payload={}, timeout=5)
        proc.wait(timeout=15)
    except Exception:
        proc.kill()
    log.close()
    assert _fingerprint(REAL_HR) == before, "the REAL HR folder changed during the time-machine tests"


@pytest.fixture(scope="module")
def hr_browser(tm):
    # module scope: Playwright's sync API keeps an asyncio loop running while started
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        b = pw.chromium.launch(headless=os.environ.get("HR_GUI_HEADED") != "1")
    except Exception as e:
        pw.stop()
        pytest.skip(f"Chromium for Playwright isn't installed ({e})")
    try:
        yield b
    finally:
        try:
            b.close()
        finally:
            pw.stop()

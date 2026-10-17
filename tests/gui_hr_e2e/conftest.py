"""
tests/gui_hr_e2e — HR Admin + HR Portal in a REAL browser against a SANDBOX
AI-Prowler server (David, 2026-10-17).

* A throwaway ai_prowler_mcp.py subprocess in SERVER mode on a random port,
  with AIPROWLER_TEST_STATE_DIR = a pytest temp folder (its own config.json,
  users.json with ZTEST users, tool_config.json with the HR apps switched on).
  Real HR data, the real users.json and config.json are never touched; the
  real HR folder (~/.ai-prowler/hr) is fingerprinted before and checked after.
* One Chromium (Playwright) for the run; each test opens its own browser
  context(s), so several people can be signed in at the same time.
* Part of the normal run_tests.bat run (safe: sandbox only). Skips cleanly when
  Playwright or its Chromium isn't installed. Run on its own, with a visible
  browser if you like:  tests\\run_tests_hr_gui_e2e.bat [--headed]
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hr_gui_helpers import USERS, http  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MCP_MAIN = ROOT / "ai_prowler_mcp.py"
REAL_HR = Path.home() / ".ai-prowler" / "hr"


def pytest_collection_modifyitems(config, items):
    for it in items:
        if "gui_hr_e2e" in str(it.fspath):
            it.add_marker(pytest.mark.hr_gui_e2e)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fingerprint(folder: Path):
    if not folder.exists():
        return None
    return sorted((str(p.relative_to(folder)), p.stat().st_size, int(p.stat().st_mtime))
                  for p in folder.rglob("*") if p.is_file())


class Sandbox:
    def __init__(self, base, state_dir, proc):
        self.base, self.state_dir, self.proc = base, state_dir, proc
        self.emp = {}

    def api(self, method, path, payload=None, who="owner", **kw):
        return http(method, f"{self.base}/hr-api{path}", token=USERS[who][1], payload=payload, **kw)

    def employee_id(self, who):
        return self.emp[USERS[who][0]]


@pytest.fixture(scope="session")
def hr_sandbox(tmp_path_factory):
    try:
        import playwright  # noqa: F401
    except Exception:
        pytest.skip("Playwright isn't installed (pip install playwright; python -m playwright install chromium)")
    before = _fingerprint(REAL_HR)
    state = tmp_path_factory.mktemp("hr_gui_e2e_state")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    (state / "config.json").write_text(json.dumps({
        "edition": "business", "mode": "server", "test_mode": True,
        "license_key": "ZTEST-HR-GUI-E2E", "owner_name": USERS["owner"][0]}, indent=2), encoding="utf-8")
    (state / "users.json").write_text(json.dumps({"users": {
        tok: {"name": n, "role": role, "status": "active", "email": em, "cell_phone": ""}
        for n, tok, role, em in USERS.values()}}, indent=2), encoding="utf-8")
    (state / "tool_config.json").write_text(json.dumps({"schema_version": 1, "hr_apps_enabled": True}), encoding="utf-8")
    env = dict(os.environ, AIPROWLER_TEST_STATE_DIR=str(state))
    log = open(state / "server.log", "w", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(MCP_MAIN), "--transport", "http", "--port", str(port),
                             "--token", USERS["owner"][1], "--public-base", base],
                            env=env, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 90
    while time.time() < deadline and proc.poll() is None:
        if http("GET", f"{base}/health", timeout=3)[0] == 200:
            break
        time.sleep(1)
    if http("GET", f"{base}/health", timeout=3)[0] != 200:
        proc.kill()
        log.close()
        pytest.fail("Sandbox AI-Prowler server didn't start. Log tail:\n" +
                    "\n".join((state / "server.log").read_text(encoding="utf-8", errors="replace").splitlines()[-40:]))
    sb = Sandbox(base, state, proc)
    # Company setup (fresh install), then every server user becomes an employee
    st, j = sb.api("POST", "/setup/complete", {
        "company_name": "ZTEST Widgets LLC", "ein": "00-0000000", "work_states": ["FL"],
        "hr_admin_email": "hr+hrtest@example.com", "owner_email": "owner+hrtest@example.com",
        "setup_complete": True})
    assert st == 200, (st, j)
    st, j = sb.api("GET", "/employees")
    assert st == 200 and len(j["employees"]) == len(USERS), j
    sb.emp = {e["first_name"] + " " + e["last_name"]: e["id"] for e in j["employees"]}
    yield sb
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except Exception:
        proc.kill()
    log.close()
    assert _fingerprint(REAL_HR) == before, "the REAL HR folder changed during the sandbox browser tests"


@pytest.fixture(scope="module")
def browser(hr_sandbox):
    # MODULE scope on purpose: Playwright's sync API keeps an asyncio loop
    # "running" in this thread while it's started, and every later test that
    # calls asyncio.run() would fail ("cannot be called from a running event
    # loop"). Stopping it after each file keeps the rest of run_tests.bat clean.
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        b = pw.chromium.launch(headless=os.environ.get("HR_GUI_HEADED") != "1")
    except Exception as e:
        pw.stop()
        pytest.skip(f"Chromium for Playwright isn't installed ({e}); run: python -m playwright install chromium")
    try:
        yield b
    finally:
        try:
            b.close()
        finally:
            pw.stop()

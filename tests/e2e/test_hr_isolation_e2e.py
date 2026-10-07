"""
tests/e2e/test_hr_isolation_e2e.py
====================================
Real subprocess-level end-to-end test for the AIPROWLER_TEST_STATE_DIR
isolation fix applied to the HR module (2026-08-28, follow-up to
tests/mcp/test_hr_state_dir_isolation.py).

WHY THIS EXISTS
----------------
Every other HR test file in this suite exercises HR's logic via local
mirror functions, precisely because HR's own state paths used to resolve
unconditionally to the real install directory -- no in-process test could
safely call the real _hr_create_employee_impl / _hr_api_route / hr_scheduler
without writing to the operator's real hr_db.json.

That gap is closed (_HR_STATE_DIR in ai_prowler_mcp.py, _HR_SCHED_STATE_DIR
in hr_scheduler.py both honor AIPROWLER_TEST_STATE_DIR now -- see that file's
docstring for the full before/after). This file is the first HR test that
actually spawns the real ai_prowler_mcp.py process and drives it over real
HTTP end-to-end, proving the fix holds under the real code paths rather than
just asserting the source text looks right.

Modeled directly on the already-proven tests/e2e/test_server_e2e.py (same
sandbox recipe: AIPROWLER_TEST_STATE_DIR -> tmp_path, test_mode: true in
config.json, random free port, real subprocess, real HTTP) but scoped much
smaller: personal mode only (no users.json/RBAC setup needed -- personal-mode
HR auth just checks the bearer token against the single --token value, which
_run_http pre-adds to its in-memory _access_tokens set directly, no OAuth
dance required for a raw bearer token).

SAFETY
------
- AIPROWLER_TEST_STATE_DIR is set to a pytest tmp_path for the spawned
  subprocess's entire environment -- never the real install directory or
  ~/.ai-prowler.
- config.json carries "test_mode": true -> _test_entitlement_active() fires
  in the subprocess, skipping all network license/subscription calls (same
  short-circuit test_server_e2e.py relies on).
- The subprocess runs in PERSONAL mode on a random free port -- never the
  port the real Local/Server instances use.
- Before the subprocess ever starts, this file snapshots the REAL install's
  hr_db.json bytes (or records that it doesn't exist). After every test, it
  re-reads those real bytes and asserts they are IDENTICAL to the snapshot --
  i.e. even if the fix regressed and the subprocess fell back to writing the
  real install dir, this suite would FAIL LOUDLY instead of silently
  corrupting the operator's real employee data.
- The subprocess is torn down (terminate, then kill on timeout) in the
  fixture's generator teardown, which runs even if a test fails, so a failed
  test can never leave a stray server process running.
- Marked @pytest.mark.e2e -- deselected by default by both tests/pytest.ini
  and the repo-root pytest.ini (same convention as test_server_e2e.py), so
  it never slows down or risks interfering with the default `run_tests.bat`
  invocation. Run explicitly:
      py -m pytest tests/e2e/test_hr_isolation_e2e.py -v -m e2e

Run:
    py -m pytest tests/e2e/test_hr_isolation_e2e.py -v -m e2e
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
from typing import Generator

import pytest

pytestmark = pytest.mark.e2e

_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent.parent  # tests/e2e -> src

MCP_MAIN = SRC_ROOT / "ai_prowler_mcp.py"
REAL_HR_DB = SRC_ROOT / "hr_db.json"
REAL_HR_DOCUMENTS = SRC_ROOT / "hr_documents"

TOKEN = "E2E_HR_STATE_DIR_TEST_TOKEN_0001"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http(method: str, url: str, token: str | None = None,
          payload: dict | None = None, timeout: int = 10):
    """Minimal urllib request helper. Returns (status_code, body_text).
    Returns (0, error_message) on connection error -- never raises."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, f"<connection error: {exc}>"


def _wait_healthy(base_url: str, timeout_s: int = 60) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status, _ = _http("GET", f"{base_url}/health", timeout=3)
        if status == 200:
            return True
        time.sleep(1.0)
    return False


class _Handle:
    """Everything about the running sandboxed subprocess a test might need."""
    def __init__(self, base_url: str, state_dir: Path, proc: subprocess.Popen):
        self.base_url = base_url
        self.state_dir = state_dir
        self.proc = proc

    def get(self, path: str, token: str | None = None, timeout: int = 8):
        return _http("GET", f"{self.base_url}{path}", token=token, timeout=timeout)

    def post_json(self, path: str, payload: dict, token: str | None = None, timeout: int = 10):
        return _http("POST", f"{self.base_url}{path}", token=token, payload=payload, timeout=timeout)


@pytest.fixture(scope="module")
def real_hr_snapshot():
    """Byte snapshot of the REAL install's hr_db.json (None if it doesn't
    exist) and the set of top-level hr_documents/ folder names, taken BEFORE
    the sandboxed subprocess ever starts. Every test in this file re-checks
    against this snapshot rather than trusting the fix blindly."""
    hr_db_bytes = REAL_HR_DB.read_bytes() if REAL_HR_DB.exists() else None
    doc_folders = (
        {p.name for p in REAL_HR_DOCUMENTS.iterdir()}
        if REAL_HR_DOCUMENTS.exists() and REAL_HR_DOCUMENTS.is_dir()
        else set()
    )
    return {"hr_db_bytes": hr_db_bytes, "doc_folders": doc_folders}


@pytest.fixture(scope="module")
def hr_isolated_server(tmp_path_factory, real_hr_snapshot) -> Generator[_Handle, None, None]:
    """Session-scoped-per-module: spawn one sandboxed ai_prowler_mcp.py
    subprocess in personal mode, yield a handle, tear it down after."""
    state_dir = tmp_path_factory.mktemp("hr_e2e_state")
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    config = {
        "edition": "home",
        "mode": "personal",
        "test_mode": True,
        "license_key": "E2E-HR-TEST-LICENSE",
    }
    (state_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    env = dict(os.environ)
    env["AIPROWLER_TEST_STATE_DIR"] = str(state_dir)

    proc = subprocess.Popen(
        [sys.executable, str(MCP_MAIN),
         "--transport", "http",
         "--port", str(port),
         "--token", TOKEN,
         "--public-base", base_url],
        env=env,
        cwd=str(SRC_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    if not _wait_healthy(base_url, timeout_s=60):
        try:
            proc.terminate()
            out, _ = proc.communicate(timeout=10)
        except Exception:
            out = "<no output captured>"
        pytest.fail(
            f"HR isolation e2e server did not become healthy within 60s on "
            f"port {port}.\nState dir: {state_dir}\nServer output (tail):\n"
            + "\n".join((out or "").splitlines()[-50:])
        )

    yield _Handle(base_url, state_dir, proc)

    # ── Teardown: always runs, even if a test above failed ──────────────────
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


class TestHrStateDirIsolationE2E:
    """Proves _HR_STATE_DIR actually redirects HR's mutable state under
    AIPROWLER_TEST_STATE_DIR when a real ai_prowler_mcp.py process is spawned
    with it set -- not just that the source text looks right (that's covered
    separately by tests/mcp/test_hr_state_dir_isolation.py's fast, in-process
    structural checks)."""

    def test_health(self, hr_isolated_server):
        status, body = hr_isolated_server.get("/health")
        assert status == 200, f"Expected 200, got {status}: {body[:200]}"

    def test_bad_token_rejected(self, hr_isolated_server):
        """Sanity check the auth path actually gates -- a wrong bearer token
        must not be treated as admin before we trust the "real" token below."""
        status, body = hr_isolated_server.get("/hr-api/employees", token="not-the-real-token")
        assert status == 401, f"Expected 401 for bad token, got {status}: {body[:200]}"

    def test_create_employee_writes_to_sandbox(self, hr_isolated_server):
        payload = {
            "personal": {
                "first_name": "Sandra",
                "last_name": "Sandbox",
                "personal_email": "sandra.sandbox@example.test",
            },
            "employment": {
                "start_date": "2026-01-01",
                "work_state": "CA",
                "title": "QA Engineer",
                "department": "Engineering",
            },
            "compensation": {"pay_type": "salary", "pay_rate": 90000},
        }
        status, body = hr_isolated_server.post_json("/hr-api/employees", payload, token=TOKEN)
        assert status == 200, f"Expected 200, got {status}: {body[:400]}"

        result = json.loads(body)
        assert result["id"].startswith("EMP-"), result
        assert result["tasks_generated"] > 0, "Expected onboarding tasks to be generated"

        sandbox_db_path = hr_isolated_server.state_dir / "hr_db.json"
        assert sandbox_db_path.exists(), (
            "hr_db.json was not created under the sandbox AIPROWLER_TEST_STATE_DIR "
            "-- the path-isolation fix regressed."
        )
        sandbox_db = json.loads(sandbox_db_path.read_text(encoding="utf-8"))
        assert any(e["id"] == result["id"] for e in sandbox_db["employees"]), (
            "The created employee is not present in the sandbox hr_db.json."
        )

        # The GET list route should see it too, over the same real HTTP path.
        status, body = hr_isolated_server.get("/hr-api/employees", token=TOKEN)
        assert status == 200, f"Expected 200, got {status}: {body[:300]}"
        listed = json.loads(body)["employees"]
        assert any(e["id"] == result["id"] for e in listed)

    def test_document_folders_created_under_sandbox(self, hr_isolated_server):
        """Employee creation calls _hr_create_document_folders -- confirm the
        hr_documents tree landed under the sandbox state dir."""
        sandbox_docs = hr_isolated_server.state_dir / "hr_documents"
        assert sandbox_docs.exists() and sandbox_docs.is_dir(), (
            "hr_documents/ was not created under the sandbox state dir -- "
            "_hr_create_document_folders may still be using _HR_ROOT_DIR."
        )
        subfolders = {p.name for p in sandbox_docs.iterdir()}
        assert len(subfolders) >= 1, "Expected at least one employee doc folder"

    def test_real_install_hr_db_untouched(self, hr_isolated_server, real_hr_snapshot):
        """Re-read the REAL install's hr_db.json now, AFTER the sandboxed
        subprocess created an employee and after all prior tests in this
        class, and assert it is byte-for-byte identical to the snapshot
        taken before the subprocess ever started."""
        after = REAL_HR_DB.read_bytes() if REAL_HR_DB.exists() else None
        assert after == real_hr_snapshot["hr_db_bytes"], (
            "The REAL install's hr_db.json changed during this e2e run -- "
            "the AIPROWLER_TEST_STATE_DIR isolation fix did not hold. This "
            "would mean HR wrote to the operator's real employee database."
        )

    def test_real_install_hr_documents_untouched(self, hr_isolated_server, real_hr_snapshot):
        """The sandbox employee's doc folder name must never appear among
        the REAL install's hr_documents/ folder names."""
        sandbox_docs = hr_isolated_server.state_dir / "hr_documents"
        sandbox_folder_names = (
            {p.name for p in sandbox_docs.iterdir()} if sandbox_docs.exists() else set()
        )
        real_folder_names_now = (
            {p.name for p in REAL_HR_DOCUMENTS.iterdir()}
            if REAL_HR_DOCUMENTS.exists() and REAL_HR_DOCUMENTS.is_dir()
            else set()
        )
        assert real_folder_names_now == real_hr_snapshot["doc_folders"], (
            "The REAL install's hr_documents/ folder listing changed during "
            "this e2e run -- isolation may have leaked."
        )
        assert not (sandbox_folder_names & real_folder_names_now), (
            "A sandbox employee's document folder name also appears in the "
            "REAL install's hr_documents/ -- isolation may have leaked."
        )

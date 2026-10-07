"""
tests/e2e/test_hr_isolation_server_mode_e2e.py
=================================================
Server-mode counterpart to tests/e2e/test_hr_isolation_e2e.py (which covers
personal mode). Spawns a real ai_prowler_mcp.py subprocess in SERVER mode
with a sandboxed users.json, and proves two things together over real HTTP:

1. The AIPROWLER_TEST_STATE_DIR isolation fix holds under server mode too
   (not just personal mode) -- the real install's hr_db.json/hr_documents
   are never touched.
2. The real role-based HR RBAC gate (`can_manage_hr` in _ROLE_CAPS, wired
   into the server-mode /hr-api/* auth block) actually enforces owner/
   manager-only admin access over the real wire -- staff and field_crew
   (which resolve to role=None here, having neither can_manage_hr nor an
   X-Employee-Session header) get 401, same as a wholly unrecognized
   token, matching tests/mcp/test_hr_role_based_auth.py's in-process
   mirror of this same logic (that file proves the logic is right; this
   file proves it's wired correctly into the real running server).

Modeled on tests/e2e/test_server_e2e.py's server-mode fixture (sandboxed
config.json + users.json, real subprocess, real HTTP) and on this suite's
own tests/e2e/test_hr_isolation_e2e.py (personal-mode variant) for the
HR-specific assertions and safety commentary -- see that file's docstring
for the full rationale; not repeated at length here.

SAFETY
------
Same guarantees as test_hr_isolation_e2e.py: AIPROWLER_TEST_STATE_DIR points
at a pytest tmp_path for the entire subprocess environment, test_mode: true
skips all network license calls, the subprocess runs on a random free port,
the REAL install's hr_db.json bytes and hr_documents/ folder listing are
snapshotted before the subprocess starts and re-asserted unchanged after
every test, and the subprocess is torn down (terminate, then kill) in the
fixture's generator teardown so a failing test never leaves a stray server
running.

Marked @pytest.mark.e2e -- deselected by default (same convention as
test_server_e2e.py and test_hr_isolation_e2e.py). Run explicitly:
    py -m pytest tests/e2e/test_hr_isolation_server_mode_e2e.py -v -m e2e
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

# Throwaway sandbox-only tokens -- never real, never touch the real install.
TOK_OWNER = "E2E_HR_SRV_OWNER_TOKEN_0001"
TOK_MANAGER = "E2E_HR_SRV_MANAGER_TOKEN_0002"
TOK_STAFF = "E2E_HR_SRV_STAFF_TOKEN_0003"
TOK_FIELD = "E2E_HR_SRV_FIELD_TOKEN_0004"
TOK_BAD = "E2E_HR_SRV_NOT_A_REAL_TOKEN_xxxx"

USERS_DOC = {
    "users": {
        TOK_OWNER:   {"name": "Olive Owner",   "role": "owner",      "status": "active"},
        TOK_MANAGER: {"name": "Mandy Manager", "role": "manager",    "status": "active"},
        TOK_STAFF:   {"name": "Sam Staff",     "role": "staff",      "status": "active"},
        TOK_FIELD:   {"name": "Freddy Field",  "role": "field_crew", "status": "active"},
    }
}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http(method: str, url: str, token: str | None = None,
          payload: dict | None = None, timeout: int = 10):
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
    hr_db_bytes = REAL_HR_DB.read_bytes() if REAL_HR_DB.exists() else None
    doc_folders = (
        {p.name for p in REAL_HR_DOCUMENTS.iterdir()}
        if REAL_HR_DOCUMENTS.exists() and REAL_HR_DOCUMENTS.is_dir()
        else set()
    )
    return {"hr_db_bytes": hr_db_bytes, "doc_folders": doc_folders}


@pytest.fixture(scope="module")
def hr_isolated_server_mode(tmp_path_factory, real_hr_snapshot) -> Generator[_Handle, None, None]:
    state_dir = tmp_path_factory.mktemp("hr_e2e_srv_state")
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    config = {
        "edition": "business",
        "mode": "server",
        "test_mode": True,
        "license_key": "E2E-HR-SRV-TEST-LICENSE",
        "owner_name": "Olive Owner",
    }
    (state_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    (state_dir / "users.json").write_text(json.dumps(USERS_DOC, indent=2), encoding="utf-8")

    env = dict(os.environ)
    env["AIPROWLER_TEST_STATE_DIR"] = str(state_dir)

    proc = subprocess.Popen(
        [sys.executable, str(MCP_MAIN),
         "--transport", "http",
         "--port", str(port),
         "--token", TOK_OWNER,
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
            f"HR server-mode isolation e2e server did not become healthy "
            f"within 60s on port {port}.\nState dir: {state_dir}\n"
            f"Server output (tail):\n" + "\n".join((out or "").splitlines()[-50:])
        )

    yield _Handle(base_url, state_dir, proc)

    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


class TestHrServerModeRbacE2E:
    """Proves can_manage_hr RBAC is enforced over real HTTP in server mode:
    owner/manager get HR admin access; staff/field_crew (no employee
    session presented) and a wholly unrecognized token both get 401."""

    def test_health(self, hr_isolated_server_mode):
        status, body = hr_isolated_server_mode.get("/health")
        assert status == 200, f"Expected 200, got {status}: {body[:200]}"

    def test_unrecognized_token_rejected(self, hr_isolated_server_mode):
        status, body = hr_isolated_server_mode.get("/hr-api/employees", token=TOK_BAD)
        assert status == 401, f"Expected 401 for unrecognized token, got {status}: {body[:200]}"

    def test_owner_gets_admin_access(self, hr_isolated_server_mode):
        status, body = hr_isolated_server_mode.get("/hr-api/employees", token=TOK_OWNER)
        assert status == 200, f"Expected 200 for owner, got {status}: {body[:300]}"
        assert "employees" in json.loads(body)

    def test_manager_gets_admin_access(self, hr_isolated_server_mode):
        status, body = hr_isolated_server_mode.get("/hr-api/employees", token=TOK_MANAGER)
        assert status == 200, f"Expected 200 for manager, got {status}: {body[:300]}"
        assert "employees" in json.loads(body)

    def test_staff_denied_admin_access(self, hr_isolated_server_mode):
        """Staff has can_manage_hr=False and presents no X-Employee-Session,
        so auth resolves to role=None -- same as an unrecognized token from
        _hr_api_route's point of view, hence 401 (not 403: this codebase's
        403 "admin_only" is reserved for a resolved-but-insufficient role,
        e.g. an authenticated employee hitting an admin-only route -- a
        plain non-admin bearer token with no employee session never reaches
        that branch). Confirmed empirically against the real running server;
        matches tests/mcp/test_hr_role_based_auth.py's in-process mirror."""
        status, body = hr_isolated_server_mode.get("/hr-api/employees", token=TOK_STAFF)
        assert status == 401, f"Expected 401 for staff (no admin, no employee session), got {status}: {body[:300]}"

    def test_field_crew_denied_admin_access(self, hr_isolated_server_mode):
        status, body = hr_isolated_server_mode.get("/hr-api/employees", token=TOK_FIELD)
        assert status == 401, f"Expected 401 for field_crew (no admin, no employee session), got {status}: {body[:300]}"

    def test_staff_cannot_create_employee(self, hr_isolated_server_mode):
        payload = {
            "personal": {"first_name": "Should", "last_name": "NotExist"},
            "employment": {"start_date": "2026-01-01", "work_state": "CA"},
            "compensation": {"pay_type": "salary", "pay_rate": 50000},
        }
        status, body = hr_isolated_server_mode.post_json(
            "/hr-api/employees", payload, token=TOK_STAFF)
        assert status == 401, f"Expected 401 for staff POST (no admin, no employee session), got {status}: {body[:300]}"

    def test_owner_creates_employee_writes_to_sandbox(self, hr_isolated_server_mode):
        payload = {
            "personal": {
                "first_name": "Sandra",
                "last_name": "ServerSandbox",
                "personal_email": "sandra.server.sandbox@example.test",
            },
            "employment": {
                "start_date": "2026-01-01",
                "work_state": "CA",
                "title": "QA Engineer",
                "department": "Engineering",
            },
            "compensation": {"pay_type": "salary", "pay_rate": 90000},
        }
        status, body = hr_isolated_server_mode.post_json(
            "/hr-api/employees", payload, token=TOK_OWNER)
        assert status == 200, f"Expected 200 for owner POST, got {status}: {body[:400]}"

        result = json.loads(body)
        assert result["id"].startswith("EMP-"), result
        assert result["tasks_generated"] > 0

        sandbox_db_path = hr_isolated_server_mode.state_dir / "hr_db.json"
        assert sandbox_db_path.exists(), (
            "hr_db.json was not created under the sandbox AIPROWLER_TEST_STATE_DIR "
            "in server mode -- the path-isolation fix regressed."
        )
        sandbox_db = json.loads(sandbox_db_path.read_text(encoding="utf-8"))
        assert any(e["id"] == result["id"] for e in sandbox_db["employees"])

        # The staff-created record from the prior (401) test must NOT exist.
        assert not any(e["last_name"] == "NotExist" for e in sandbox_db["employees"]), (
            "A staff user's rejected employee-creation attempt somehow wrote "
            "a record anyway -- the 401 did not actually block the write."
        )

    def test_real_install_hr_db_untouched(self, hr_isolated_server_mode, real_hr_snapshot):
        after = REAL_HR_DB.read_bytes() if REAL_HR_DB.exists() else None
        assert after == real_hr_snapshot["hr_db_bytes"], (
            "The REAL install's hr_db.json changed during this server-mode "
            "e2e run -- the AIPROWLER_TEST_STATE_DIR isolation fix did not "
            "hold under server mode."
        )

    def test_real_install_hr_documents_untouched(self, hr_isolated_server_mode, real_hr_snapshot):
        real_folder_names_now = (
            {p.name for p in REAL_HR_DOCUMENTS.iterdir()}
            if REAL_HR_DOCUMENTS.exists() and REAL_HR_DOCUMENTS.is_dir()
            else set()
        )
        assert real_folder_names_now == real_hr_snapshot["doc_folders"], (
            "The REAL install's hr_documents/ folder listing changed during "
            "this server-mode e2e run -- isolation may have leaked."
        )

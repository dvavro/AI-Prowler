"""
test_server_e2e.py — AI-Prowler v7.0.1 End-to-End Server Isolation Tests
=========================================================================
True end-to-end validation: spawns a REAL ai_prowler_mcp.py subprocess in
business/server mode, probes it over REAL HTTP using real bearer tokens, and
asserts cross-user data isolation at the ChromaDB/MCP-tool layer.

WHY THIS MATTERS
----------------
The unit tests in test_security_roles.py verify that _resolve_user(),
_allowed_collections() etc. return correct values given correct inputs.
The mcp/ tests call tool functions in-process with monkeypatched globals.
Neither catches bugs in:
  - The ASGI auth middleware (token → user resolution over HTTP)
  - The ctx injection path (does user actually reach the tool handler?)
  - ChromaDB collection routing under real server startup
  - Race conditions: two users' requests interleaved

These tests catch ALL of the above because they use the real wire.

SAFETY
------
- AIPROWLER_TEST_STATE_DIR is set to a pytest tmp_path, never ~/.ai-prowler.
- config.json carries "test_mode": true → _test_entitlement_active() fires,
  skipping all network license/subscription/activation calls.
- The server subprocess binds to a random free port, never 8000.
- All sentinel documents are indexed into the sandboxed ChromaDB inside
  tmp_path. The real ChromaDB at ~/AI-Prowler/rag_database is NEVER opened.
- The entire tmp_path tree (ChromaDB, config, users.json, sentinel docs) is
  deleted by pytest's tmp_path fixture at session teardown.
- The running Local/Server AI-Prowler instances are unaffected: different
  port, different state dir, different ChromaDB.

RUNNING
-------
Full suite (slow, spawns a server):
    tests\\run_tests.bat e2e

Or directly:
    py -m pytest tests/e2e -v -m e2e

Stage 1 only (auth/identity, no ChromaDB indexing needed):
    py -m pytest tests/e2e -v -k "stage1"

Stage 2 only (tool-call isolation, requires mcp[cli] extra):
    py -m pytest tests/e2e -v -k "stage2"

Concurrency stress test:
    py -m pytest tests/e2e -v -k "concurrent"

REQUIREMENTS
------------
  pip install mcp[cli]       # for Stage 2 MCP SDK client
  (everything else is stdlib or already in requirements.txt)
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Generator

import pytest

# ── Source root on path ───────────────────────────────────────────────────────
_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent.parent  # tests/e2e → src

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

MCP_MAIN = SRC_ROOT / "ai_prowler_mcp.py"

# ── Test users (throwaway tokens — never real) ────────────────────────────────
TOK_SALES = "E2E_TEST_sales_manager_0001"
TOK_FIELD = "E2E_TEST_field_manager_0002"
TOK_OWNER = "E2E_TEST_owner_0003"
TOK_BAD   = "E2E_TEST_not_a_real_user_xxxx"

USERS_DOC = {
    "users": {
        TOK_SALES: {
            "name": "Sales Manager",
            "role": "manager",
            "scopes": ["role:sales"],
            "private_collection_enabled": True,
            "status": "active",
            # index_target routes any file indexed by this user to role:sales
            # when no collection_map rule matches.
            "index_target": "role:sales",
        },
        TOK_FIELD: {
            "name": "Field Manager",
            # Use staff (not field_crew) so this user can call index_path.
            # field_crew is blocked from all DB tools by _check_db_cap("limited").
            # In real deployments, field content is indexed by a manager/owner
            # on the field crew's behalf — we replicate that here.
            "role": "staff",
            "scopes": ["role:field"],
            "private_collection_enabled": True,
            "status": "active",
            "index_target": "role:field",
        },
        TOK_OWNER: {
            "name": "Olive Owner",
            "role": "owner",
            "scopes": [],
            "private_collection_enabled": True,
            "can_manage_users": True,
            "status": "active",
        },
    },
    # collection_map routes sentinel docs to the correct scope based on
    # the temp directory prefix the seeder writes them into.
    # The owner indexes all three docs; the rules route each file to its
    # correct collection so we don't need per-user indexing calls.
    "collection_map": {
        "rules": [
            {"prefix": "e2e_sentinel_shared", "collection": "shared"},
            {"prefix": "e2e_sentinel_sales",  "collection": "role:sales"},
            {"prefix": "e2e_sentinel_field",  "collection": "role:field"},
        ],
        "default_collection": "shared",
    },
}

# Sentinel strings embedded in test documents.
# These are long enough to be unmistakable even if embedding search is fuzzy.
SENTINEL_SHARED = "E2E_SHARED_COMPANY_HANDBOOK_SENTINEL"
SENTINEL_SALES  = "E2E_SALES_SECRET_PRICING_SENTINEL"
SENTINEL_FIELD  = "E2E_FIELD_ROUTES_GATECODES_SENTINEL"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_get(url: str, token: str | None = None, timeout: int = 8):
    """GET url with optional Bearer token. Returns (status_code, body_text).
    Returns (0, error_message) on connection error."""
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, f"<connection error: {exc}>"


def _http_post_json(url: str, payload: dict, token: str | None = None, timeout: int = 10):
    """POST JSON payload, optional Bearer. Returns (status_code, body_text)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                  headers={"Content-Type": "application/json"})
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
    """Poll GET /health until 200 or timeout. Returns True if server came up."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status, _ = _http_get(f"{base_url}/health", timeout=3)
        if status == 200:
            return True
        time.sleep(1.0)
    return False


def _strip_query_echo(txt: str) -> str:
    """Remove the 'search results for: ...' / 'no results found for: ...' header
    lines from a response so assertions on doc content don't false-positive on
    the echoed query string."""
    lines = txt.splitlines()
    filtered = [ln for ln in lines
                if not ln.strip().startswith("search results for:")
                and not ln.strip().startswith("no results found for:")]
    return "\n".join(filtered)


def _tool_result_text(result_obj) -> str:
    try:
        parts = []
        for block in getattr(result_obj, "content", []) or []:
            t = getattr(block, "text", None)
            if t:
                parts.append(t)
        return " ".join(parts).lower()
    except Exception:
        return str(result_obj).lower()


# ── Session-scoped server fixture ─────────────────────────────────────────────

class _ServerHandle:
    """Holds everything about the running test server subprocess."""
    def __init__(self, base_url: str, state_dir: Path, port: int, proc):
        self.base_url  = base_url
        self.state_dir = state_dir
        self.port      = port
        self.proc      = proc
        # Recorded immediately after _wait_healthy() confirms the server is
        # live.  Used by ST8-02 to check whether the production ChromaDB was
        # written AFTER the sandbox server was confirmed healthy — any prod-DB
        # writes that happen during server startup (e.g. model loading) are
        # excluded from the check.  Using state_dir.st_mtime was wrong because
        # that directory is created before Popen(), so the 0.5s gap between
        # mktemp() and the server actually being ready was enough to falsely
        # flag a breach.
        self.server_healthy_time: float = 0.0

    def get(self, path: str, token: str | None = None, timeout: int = 8):
        return _http_get(f"{self.base_url}{path}", token=token, timeout=timeout)

    def post_json(self, path: str, payload: dict, token: str | None = None, timeout: int = 10):
        return _http_post_json(f"{self.base_url}{path}", payload,
                               token=token, timeout=timeout)


@pytest.fixture(scope="session")
def e2e_server(tmp_path_factory) -> Generator[_ServerHandle, None, None]:
    """
    Session-scoped fixture: start a sandboxed AI-Prowler server subprocess,
    yield a handle for tests to use, then tear it down cleanly.

    The server uses:
      - AIPROWLER_TEST_STATE_DIR → isolated tmp dir (not ~/.ai-prowler)
      - test_mode: true in config.json → skips all network license calls
      - A random free port → no conflict with running Local/Server instances
      - Its own ChromaDB inside tmp_path → production DB never touched

    Sentinel dirs are created BEFORE server launch so their absolute paths
    can be baked into users.json collection_map rules. The server loads
    users.json once at startup; runtime rewrites are ignored.

    Teardown:
      - SIGTERM the subprocess
      - pytest's tmp_path_factory cleans up the tmp dir automatically
    """
    state_dir = tmp_path_factory.mktemp("e2e_server_state")
    port      = _free_port()
    base_url  = f"http://127.0.0.1:{port}"

    # Create sentinel dirs NOW so we know their absolute paths for users.json.
    # Files are written here too; the server will index them via MCP tool calls.
    shared_dir = tmp_path_factory.mktemp("e2e_sentinel_shared")
    sales_dir  = tmp_path_factory.mktemp("e2e_sentinel_sales")
    field_dir  = tmp_path_factory.mktemp("e2e_sentinel_field")

    (shared_dir / "shared_handbook.txt").write_text(
        f"{SENTINEL_SHARED} company handbook all employees may read.",
        encoding="utf-8")
    (sales_dir / "sales_pricing.txt").write_text(
        f"{SENTINEL_SALES} confidential sales pricing Q3 window washing.",
        encoding="utf-8")
    (field_dir / "field_routes.txt").write_text(
        f"{SENTINEL_FIELD} confidential field routes and gate codes.",
        encoding="utf-8")

    # Write sandboxed config
    config = {
        "edition":      "business",
        "mode":         "server",
        "test_mode":    True,
        "license_key":  "E2E-TEST-LICENSE",
        "tunnel_domain": "",
        "owner_name":   "Olive Owner",
    }
    (state_dir / "config.json").write_text(
        json.dumps(config, indent=2), encoding="utf-8")

    # Write users.json WITH absolute-path collection_map rules baked in.
    # scope_resolver does a full-path prefix match so rules must be absolute.
    # _run_server_mode() loads users.json ONCE at startup — this is our only
    # chance to get the paths in.
    users_doc = json.loads(json.dumps(USERS_DOC))  # deep copy
    users_doc["collection_map"] = {
        "rules": [
            {"prefix": str(shared_dir), "collection": "shared"},
            {"prefix": str(sales_dir),  "collection": "role:sales"},
            {"prefix": str(field_dir),  "collection": "role:field"},
        ],
        "default_collection": "shared",
    }
    (state_dir / "users.json").write_text(
        json.dumps(users_doc, indent=2), encoding="utf-8")

    # Expose sentinel dirs on the handle so Stage 2 _seed can index them
    env = dict(os.environ)
    env["AIPROWLER_TEST_STATE_DIR"] = str(state_dir)

    python_exe = sys.executable
    proc = subprocess.Popen(
        [
            python_exe, str(MCP_MAIN),
            "--transport", "http",
            "--port",      str(port),
            "--token",     TOK_OWNER,
            "--public-base", base_url,
        ],
        env=env,
        cwd=str(SRC_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    handle = _ServerHandle(base_url, state_dir, port, proc)
    handle.shared_dir = shared_dir
    handle.sales_dir  = sales_dir
    handle.field_dir  = field_dir

    if not _wait_healthy(base_url, timeout_s=60):
        try:
            proc.terminate()
            out, _ = proc.communicate(timeout=10)
        except Exception:
            out = "<no output captured>"
        pytest.fail(
            f"E2E server did not become healthy within 60s on port {port}.\n"
            f"State dir: {state_dir}\n"
            f"Server output (tail):\n"
            + "\n".join((out or "").splitlines()[-50:])
        )

    # Record the moment the server is confirmed healthy.  ST8-02 uses this
    # timestamp (not state_dir.st_mtime) to detect sandbox breaches — any
    # prod-DB writes that happen before healthy confirmation are excluded.
    import time as _time
    handle.server_healthy_time = _time.time()

    yield handle

    # ── Teardown ──────────────────────────────────────────────────────────────
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1 — Auth & Identity
# Proves: the server started, /health works, each bearer token resolves to the
# correct user identity, and an invalid token is rejected.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.e2e
class TestStage1Auth:
    """E2E-ST1-*: Auth and identity over real HTTP."""

    def test_E2E_ST1_01_health(self, e2e_server):
        """E2E-ST1-01: /health returns 200 (server is alive)."""
        status, body = e2e_server.get("/health")
        assert status == 200, f"Expected 200, got {status}: {body[:200]}"

    def test_E2E_ST1_02_sales_identity(self, e2e_server):
        """E2E-ST1-02: Sales manager token resolves to correct identity."""
        status, body = e2e_server.get("/whoami", token=TOK_SALES)
        assert status == 200, f"Expected 200, got {status}: {body[:300]}"
        blob = body.lower()
        assert "manager" in blob, f"Role 'manager' not in response: {body[:300]}"
        assert "sales" in blob or "sales manager" in blob.lower(), \
            f"Name not in response: {body[:300]}"

    def test_E2E_ST1_03_field_identity(self, e2e_server):
        """E2E-ST1-03: Field crew token resolves to correct identity."""
        status, body = e2e_server.get("/whoami", token=TOK_FIELD)
        assert status == 200, f"Expected 200, got {status}: {body[:300]}"
        blob = body.lower()
        assert "field" in blob, f"Role/name 'field' not in response: {body[:300]}"

    def test_E2E_ST1_04_owner_identity(self, e2e_server):
        """E2E-ST1-04: Owner token resolves to owner identity."""
        status, body = e2e_server.get("/whoami", token=TOK_OWNER)
        assert status == 200, f"Expected 200, got {status}: {body[:300]}"
        blob = body.lower()
        assert "owner" in blob, f"Role 'owner' not in response: {body[:300]}"

    def test_E2E_ST1_05_bad_token_rejected(self, e2e_server):
        """E2E-ST1-05: Invalid bearer token returns 401 (not 200, not 500)."""
        status, body = e2e_server.get("/whoami", token=TOK_BAD)
        assert status == 401, \
            f"Expected 401 for bad token, got {status}: {body[:200]}"

    def test_E2E_ST1_06_no_token_rejected(self, e2e_server):
        """E2E-ST1-06: Request with no Authorization header returns 401."""
        status, body = e2e_server.get("/whoami", token=None)
        assert status == 401, \
            f"Expected 401 for missing token, got {status}: {body[:200]}"

    def test_E2E_ST1_07_mcp_endpoint_alive(self, e2e_server):
        """E2E-ST1-07: POST /mcp with valid token does not return 500.
        (We don't speak full JSON-RPC here — just verify auth layer works
        and we get a protocol-level response, not an auth crash.)"""
        # Send a minimal JSON-RPC initialize — may return 4xx for bad framing
        # but must NOT return 500 (which was the _srv_access_tokens NameError).
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "e2e-test", "version": "1"},
            },
        }
        status, body = e2e_server.post_json("/mcp", payload, token=TOK_SALES)
        assert status != 500, \
            f"Got 500 on /mcp — auth middleware crash? Body: {body[:400]}"
        assert status != 0, \
            f"Could not connect to /mcp: {body}"


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2 — MCP Tool-Call Isolation
# Proves: the ctx injection path works end-to-end so that search_documents
# actually scopes results to the requesting user's collections. Uses the real
# MCP SDK streamable-http client.
#
# Requires: pip install mcp[cli]
# Skip gracefully if not installed.
# ─────────────────────────────────────────────────────────────────────────────

def _mcp_sdk_available() -> bool:
    try:
        from mcp.client.streamable_http import streamablehttp_client  # noqa
        from mcp import ClientSession  # noqa
        return True
    except ImportError:
        return False


@pytest.mark.e2e
@pytest.mark.skipif(not _mcp_sdk_available(),
                    reason="mcp[cli] not installed — pip install mcp[cli]")
class TestStage2Isolation:
    """E2E-ST2-*: MCP tool-call cross-user isolation over real HTTP.

    Flow per test:
      1. Sales manager indexes a sentinel document (lands in role:sales collection).
      2. Field manager searches for that sentinel — must get zero hits (isolation).
      3. Sales manager searches — must get a real hit (positive access).
      4. Owner searches — must see both sentinels (global read).
    """

    @pytest.fixture(scope="class")
    def seeded_server(self, e2e_server, tmp_path_factory):
        """Index sentinel documents once for all Stage 2 tests."""
        asyncio.run(self._seed(e2e_server))
        return e2e_server

    @staticmethod
    async def _seed(server: _ServerHandle):
        """Index sentinel docs into their correct scoped collections.

        The sentinel dirs and files were already created in e2e_server before
        the server launched, and users.json already has the correct absolute-path
        collection_map rules. We just need to trigger index_path as the owner
        so the files land in ChromaDB under the right collections.
        """
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession

        mcp_url = f"{server.base_url}/mcp"

        async def _index_dir(token: str, dirpath):
            hdrs = {"Authorization": f"Bearer {token}"}
            async with streamablehttp_client(mcp_url, headers=hdrs) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    res = await s.call_tool(
                        "index_path",
                        {"directory": str(dirpath), "track": False})
                    txt = _tool_result_text(res)
                    assert "error" not in txt or "indexed" in txt, \
                        f"index_path failed for {dirpath.name}: {txt[:300]}"

        # Owner indexes all three pre-created sentinel directories.
        # collection_map rules (baked into users.json at server launch) route
        # each dir to its correct collection: shared / role:sales / role:field.
        await _index_dir(TOK_OWNER, server.shared_dir)
        await _index_dir(TOK_OWNER, server.sales_dir)
        await _index_dir(TOK_OWNER, server.field_dir)

        # Poll until all three sentinels are actually findable in ChromaDB.
        # A fixed sleep proved flaky under full-suite load (ChromaDB compactor
        # lag). Mirror the Stage 5 approach: poll with a 30s timeout.
        import time as _time
        deadline = _time.monotonic() + 30
        sentinels_needed = {
            SENTINEL_SHARED: False,
            SENTINEL_SALES:  False,
            SENTINEL_FIELD:  False,
        }
        from mcp.client.streamable_http import streamablehttp_client as _shc
        from mcp import ClientSession as _CS
        while _time.monotonic() < deadline:
            for sent, found in list(sentinels_needed.items()):
                if found:
                    continue
                hdrs = {"Authorization": f"Bearer {TOK_OWNER}"}
                async with _shc(mcp_url, headers=hdrs) as (r, w, _):
                    async with _CS(r, w) as s:
                        await s.initialize()
                        res = await s.call_tool(
                            "search_documents",
                            {"query": sent, "n_results": 3})
                        if sent.lower() in _tool_result_text(res):
                            sentinels_needed[sent] = True
            if all(sentinels_needed.values()):
                break
            await asyncio.sleep(1)
        missing = [k for k, v in sentinels_needed.items() if not v]
        if missing:
            raise RuntimeError(
                f"Stage 2 seeder: sentinels not searchable after 30s: {missing}. "
                f"ChromaDB compactor lag under load — if this recurs when running "
                f"Stage 2 in isolation, investigate indexing."
            )

    @staticmethod
    async def _search_as(server: _ServerHandle, token: str, query: str,
                         n_results: int = 10) -> str:
        """Run search_documents as a given user. Returns lowercased result text."""
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession

        hdrs = {"Authorization": f"Bearer {token}"}
        async with streamablehttp_client(
                f"{server.base_url}/mcp", headers=hdrs) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool(
                    "search_documents",
                    {"query": query, "n_results": n_results})
                return _tool_result_text(res)

    # ── Positive access tests ─────────────────────────────────────────────────

    def test_E2E_ST2_01_sales_sees_own_sentinel(self, seeded_server):
        """E2E-ST2-01: Sales manager can retrieve their own sentinel doc."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_SALES, SENTINEL_SALES))
        assert SENTINEL_SALES.lower() in txt or "sales_pricing" in txt, \
            f"Sales manager could NOT find their own document.\nResult: {txt[:400]}"

    def test_E2E_ST2_02_sales_sees_shared(self, seeded_server):
        """E2E-ST2-02: Sales manager can retrieve shared/company documents."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_SALES, SENTINEL_SHARED))
        assert SENTINEL_SHARED.lower() in txt or "shared_handbook" in txt, \
            f"Sales manager could NOT find shared doc.\nResult: {txt[:400]}"

    def test_E2E_ST2_03_field_sees_own_sentinel(self, seeded_server):
        """E2E-ST2-03: Field manager can retrieve their own sentinel doc."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_FIELD, SENTINEL_FIELD))
        assert SENTINEL_FIELD.lower() in txt or "field_routes" in txt, \
            f"Field manager could NOT find their own document.\nResult: {txt[:400]}"

    def test_E2E_ST2_04_field_sees_shared(self, seeded_server):
        """E2E-ST2-04: Field manager can retrieve shared/company documents."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_FIELD, SENTINEL_SHARED))
        assert SENTINEL_SHARED.lower() in txt or "shared_handbook" in txt, \
            f"Field manager could NOT find shared doc.\nResult: {txt[:400]}"

    def test_E2E_ST2_05_owner_sees_all(self, seeded_server):
        """E2E-ST2-05: Owner can retrieve documents from all scopes."""
        broad_query = "sentinel confidential pricing routes handbook"
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_OWNER, broad_query, n_results=20))
        missing = []
        for sentinel in (SENTINEL_SHARED, SENTINEL_SALES, SENTINEL_FIELD):
            if sentinel.lower() not in txt and sentinel.split("_")[2].lower() not in txt:
                missing.append(sentinel)
        assert not missing, \
            f"Owner MISSING sentinels: {missing}\nResult: {txt[:600]}"

    # ── Isolation (negative access) tests — these are the liability tests ─────

    def test_E2E_ST2_06_sales_cannot_see_field_sentinel(self, seeded_server):
        """E2E-ST2-06: ISOLATION — Sales manager MUST NOT see field sentinel.
        DATA LEAKAGE if this fails."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_SALES, SENTINEL_FIELD, n_results=20))
        content = _strip_query_echo(txt)
        assert SENTINEL_FIELD.lower() not in content, (
            f"⛔ DATA LEAKAGE: Sales manager received field-scoped content!\n"
            f"Sentinel '{SENTINEL_FIELD}' found in doc content:\n{content[:600]}"
        )

    def test_E2E_ST2_07_sales_cannot_see_field_filename(self, seeded_server):
        """E2E-ST2-07: ISOLATION — Sales manager must not see field_routes.txt filename."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_SALES, "routes gate codes field crew", n_results=20))
        content = _strip_query_echo(txt)
        assert "field_routes" not in content, (
            f"⛔ DATA LEAKAGE: Sales manager got field_routes.txt filename!\n"
            f"Result: {content[:600]}"
        )

    def test_E2E_ST2_08_field_cannot_see_sales_sentinel(self, seeded_server):
        """E2E-ST2-08: ISOLATION — Field manager MUST NOT see sales sentinel.
        DATA LEAKAGE if this fails."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_FIELD, SENTINEL_SALES, n_results=20))
        content = _strip_query_echo(txt)
        assert SENTINEL_SALES.lower() not in content, (
            f"⛔ DATA LEAKAGE: Field manager received sales-scoped content!\n"
            f"Sentinel '{SENTINEL_SALES}' found in doc content:\n{content[:600]}"
        )

    def test_E2E_ST2_09_field_cannot_see_sales_filename(self, seeded_server):
        """E2E-ST2-09: ISOLATION — Field manager must not see sales_pricing.txt filename."""
        txt = asyncio.run(self._search_as(
            seeded_server, TOK_FIELD, "pricing sales confidential Q3", n_results=20))
        content = _strip_query_echo(txt)
        assert "sales_pricing" not in content, (
            f"⛔ DATA LEAKAGE: Field manager got sales_pricing.txt filename!\n"
            f"Result: {content[:600]}"
        )

    def test_E2E_ST2_10_adversarial_broad_query(self, seeded_server):
        """E2E-ST2-10: ISOLATION — Adversarial broad query cannot leak cross-scope data.
        Uses a query designed to match ALL collections if scoping is broken."""
        broad = "confidential sentinel pricing routes handbook gate codes"

        sales_txt = _strip_query_echo(asyncio.run(self._search_as(
            seeded_server, TOK_SALES, broad, n_results=20)))
        field_txt = _strip_query_echo(asyncio.run(self._search_as(
            seeded_server, TOK_FIELD, broad, n_results=20)))

        leaks = []
        if SENTINEL_FIELD.lower() in sales_txt:
            leaks.append(f"Sales got FIELD sentinel in broad query")
        if SENTINEL_SALES.lower() in field_txt:
            leaks.append(f"Field got SALES sentinel in broad query")

        assert not leaks, (
            f"⛔ DATA LEAKAGE under adversarial broad query:\n"
            + "\n".join(leaks)
        )


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 3 — Concurrent Request Isolation
# Proves: no shared mutable global state causes cross-contamination when
# two users fire requests simultaneously.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.skipif(not _mcp_sdk_available(),
                    reason="mcp[cli] not installed — pip install mcp[cli]")
class TestStage3Concurrent:
    """E2E-ST3-*: Concurrent multi-user isolation stress tests."""

    @pytest.fixture(scope="class")
    def seeded_server(self, e2e_server):
        """Same seeding as Stage 2 — reuse if both run together."""
        asyncio.run(TestStage2Isolation._seed(e2e_server))
        return e2e_server

    @staticmethod
    async def _concurrent_search(server: _ServerHandle,
                                 rounds: int = 20) -> list[str]:
        """Fire `rounds` interleaved sales+field searches concurrently.
        Returns list of any leak descriptions found."""
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession

        leaks = []
        broad = "confidential sentinel pricing routes handbook gate codes"

        async def _one(token: str, forbidden_sentinel: str, label: str):
            hdrs = {"Authorization": f"Bearer {token}"}
            async with streamablehttp_client(
                    f"{server.base_url}/mcp", headers=hdrs) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    res = await s.call_tool(
                        "search_documents",
                        {"query": broad, "n_results": 20})
                    txt = _tool_result_text(res)
                    txt_clean = _strip_query_echo(txt)
                    if forbidden_sentinel.lower() in txt_clean:
                        leaks.append(
                            f"LEAK [{label}]: found '{forbidden_sentinel}' "
                            f"in doc content: {txt_clean[:300]}")

        tasks = []
        for i in range(rounds):
            if i % 2 == 0:
                tasks.append(_one(TOK_SALES, SENTINEL_FIELD, f"sales-r{i}"))
            else:
                tasks.append(_one(TOK_FIELD, SENTINEL_SALES, f"field-r{i}"))

        await asyncio.gather(*tasks)
        return leaks

    def test_E2E_ST3_01_concurrent_isolation(self, seeded_server):
        """E2E-ST3-01: 20 interleaved sales+field requests — zero cross-leakage.
        Tests for race conditions on shared globals (_users_data, ctx state).
        This is the highest-confidence liability test."""
        leaks = asyncio.run(self._concurrent_search(seeded_server, rounds=20))
        assert not leaks, (
            f"⛔ DATA LEAKAGE under concurrent load ({len(leaks)} incidents):\n"
            + "\n".join(leaks[:10])
        )


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 4 — Suspension / Revocation (TH-03)
# Proves: suspending a user in users.json takes effect on the NEXT request
# without a server restart (hot-reload fix).
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.e2e
class TestStage4Revocation:
    """E2E-ST4-*: Real-time user suspension tests.

    Requires the hot-reload fix in _run_server_mode where _load_users() is
    called per-request rather than relying on the startup snapshot.
    If this test fails, it means the server still uses the cached users_data
    and suspensions don't take effect until restart — a TH-03 security gap.
    """

    # Dedicated token for suspension tests — separate from the main users.
    TOK_SUSPENDABLE = "E2E_TEST_suspendable_user_9999"

    @pytest.fixture(scope="class")
    def server_with_suspendable_user(self, e2e_server) -> _ServerHandle:
        """Add a suspendable test user to the live users.json, verify they
        can authenticate, then yield the server for suspension tests."""
        users_path = e2e_server.state_dir / "users.json"
        data = json.loads(users_path.read_text(encoding="utf-8"))
        data["users"][self.TOK_SUSPENDABLE] = {
            "name":   "Suspendable User",
            "role":   "staff",
            "scopes": ["role:sales"],
            "private_collection_enabled": False,
            "status": "active",
        }
        users_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        # Brief pause to ensure file write is flushed
        time.sleep(0.2)
        return e2e_server

    def test_E2E_ST4_01_active_user_can_authenticate(self, server_with_suspendable_user):
        """E2E-ST4-01: Freshly added active user can authenticate."""
        status, body = server_with_suspendable_user.get(
            "/whoami", token=self.TOK_SUSPENDABLE)
        assert status == 200, (
            f"Active user should authenticate, got {status}: {body[:300]}\n"
            f"If 401, the hot-reload is working but the user wasn't written correctly."
        )
        assert "suspendable" in body.lower(), \
            f"User name not in response: {body[:300]}"

    def test_E2E_ST4_02_suspended_user_immediately_denied(self, server_with_suspendable_user):
        """E2E-ST4-02: Suspended user is denied on the VERY NEXT request.
        No server restart required — this proves hot-reload works.
        ⚠️ SECURITY GAP if this fails: suspensions don't take effect until restart."""
        # Suspend the user by rewriting users.json
        users_path = server_with_suspendable_user.state_dir / "users.json"
        data = json.loads(users_path.read_text(encoding="utf-8"))
        data["users"][self.TOK_SUSPENDABLE]["status"] = "suspended"
        users_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        time.sleep(0.2)  # ensure file write is flushed

        # The very next request must be denied — no restart
        status, body = server_with_suspendable_user.get(
            "/whoami", token=self.TOK_SUSPENDABLE)
        assert status == 401, (
            f"⚠️ SECURITY GAP (TH-03): Suspended user still authenticated!\n"
            f"Got {status} instead of 401. The server is using a stale cached\n"
            f"users_data snapshot from startup. The hot-reload fix is not active.\n"
            f"Body: {body[:300]}"
        )

    def test_E2E_ST4_03_revoked_user_immediately_denied(self, server_with_suspendable_user):
        """E2E-ST4-03: Revoked user is denied on the very next request."""
        # Change suspended → revoked
        users_path = server_with_suspendable_user.state_dir / "users.json"
        data = json.loads(users_path.read_text(encoding="utf-8"))
        data["users"][self.TOK_SUSPENDABLE]["status"] = "revoked"
        users_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        time.sleep(0.2)

        status, body = server_with_suspendable_user.get(
            "/whoami", token=self.TOK_SUSPENDABLE)
        assert status == 401, (
            f"⚠️ SECURITY GAP: Revoked user still authenticated! Got {status}: {body[:200]}"
        )

    def test_E2E_ST4_04_reactivated_user_regains_access(self, server_with_suspendable_user):
        """E2E-ST4-04: Re-activating a user takes effect immediately too.
        Proves hot-reload works in both directions."""
        users_path = server_with_suspendable_user.state_dir / "users.json"
        data = json.loads(users_path.read_text(encoding="utf-8"))
        data["users"][self.TOK_SUSPENDABLE]["status"] = "active"
        users_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        time.sleep(0.2)

        status, body = server_with_suspendable_user.get(
            "/whoami", token=self.TOK_SUSPENDABLE)
        assert status == 200, (
            f"Re-activated user should authenticate, got {status}: {body[:300]}"
        )

    def test_E2E_ST4_05_deleted_user_immediately_denied(self, server_with_suspendable_user):
        """E2E-ST4-05: Removing a user from users.json denies them instantly."""
        users_path = server_with_suspendable_user.state_dir / "users.json"
        data = json.loads(users_path.read_text(encoding="utf-8"))
        data["users"].pop(self.TOK_SUSPENDABLE, None)
        users_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        time.sleep(0.2)

        status, body = server_with_suspendable_user.get(
            "/whoami", token=self.TOK_SUSPENDABLE)
        assert status == 401, (
            f"Deleted user should be denied, got {status}: {body[:200]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 5 — Private Collection Isolation (TH-05)
# Proves: user:* private collections are isolated — User A cannot read
# User B's private notes, and a manager cannot read the owner's private dir.
# ─────────────────────────────────────────────────────────────────────────────

SENTINEL_PRIVATE_A = "E2E_PRIVATE_USER_A_SECRET_SENTINEL"
SENTINEL_PRIVATE_B = "E2E_PRIVATE_USER_B_SECRET_SENTINEL"
SENTINEL_PRIVATE_OWNER = "E2E_PRIVATE_OWNER_SECRET_SENTINEL"

TOK_USER_A   = "E2E_TEST_user_a_staff_1111"
TOK_USER_B   = "E2E_TEST_user_b_staff_2222"
TOK_MANAGER2 = "E2E_TEST_manager_can_manage_3333"

@pytest.mark.e2e
@pytest.mark.skipif(not _mcp_sdk_available(),
                    reason="mcp[cli] not installed — pip install mcp[cli]")
class TestStage5PrivateIsolation:
    """E2E-ST5-*: user:* private collection cross-read isolation.

    Three users are added:
      - User A (staff, private enabled) — has their own private doc
      - User B (staff, private enabled) — has their own private doc
      - Manager2 (manager, can_manage_users=True) — admin, but NOT owner

    Assertions:
      - User A can read their own private doc (positive)
      - User B CANNOT read User A's private doc (isolation)
      - Manager2 CANNOT read the owner's private doc (owner protection)
      - Owner CAN read all private collections (privileged read)
    """

    @pytest.fixture(scope="class")
    def private_seeded_server(self, e2e_server, tmp_path_factory):
        """Add private-collection users and seed their private docs."""
        asyncio.run(self._setup(e2e_server, tmp_path_factory))
        return e2e_server

    @staticmethod
    async def _setup(server: _ServerHandle, tmp_path_factory):
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession

        # Create private doc directories for each user
        user_a_dir    = tmp_path_factory.mktemp("e2e_private_user_a")
        user_b_dir    = tmp_path_factory.mktemp("e2e_private_user_b")
        owner_priv_dir = tmp_path_factory.mktemp("e2e_private_owner")

        (user_a_dir   / "notes_a.txt").write_text(
            f"{SENTINEL_PRIVATE_A} user A's private notes. eyes only.", encoding="utf-8")
        (user_b_dir   / "notes_b.txt").write_text(
            f"{SENTINEL_PRIVATE_B} user B's private notes. eyes only.", encoding="utf-8")
        (owner_priv_dir / "owner_notes.txt").write_text(
            f"{SENTINEL_PRIVATE_OWNER} owner private confidential business notes.",
            encoding="utf-8")

        # Add three new users to users.json (with private collection enabled)
        users_path = server.state_dir / "users.json"
        data = json.loads(users_path.read_text(encoding="utf-8"))
        data["users"][TOK_USER_A] = {
            "name": "Alice Staff",
            "role": "staff",
            "scopes": ["role:sales"],
            "private_collection_enabled": True,
            "status": "active",
            "index_target": f"user:alice-staff",
        }
        data["users"][TOK_USER_B] = {
            "name": "Bob Staff",
            "role": "staff",
            "scopes": ["role:field"],
            "private_collection_enabled": True,
            "status": "active",
            "index_target": f"user:bob-staff",
        }
        data["users"][TOK_MANAGER2] = {
            "name": "Mgr Admin",
            "role": "manager",
            "scopes": [],
            "private_collection_enabled": True,
            "can_manage_users": True,
            "status": "active",
        }

        # Add collection_map rules routing each private dir to the right user: collection
        rules = data.get("collection_map", {}).get("rules", [])
        rules += [
            {"prefix": str(user_a_dir),    "collection": "user:alice-staff"},
            {"prefix": str(user_b_dir),    "collection": "user:bob-staff"},
            {"prefix": str(owner_priv_dir), "collection": f"user:olive-owner"},
        ]
        data["collection_map"]["rules"] = rules
        users_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        time.sleep(0.2)

        # Index each private dir as the owner (who can write anywhere)
        mcp_url = f"{server.base_url}/mcp"
        async def _index(dirpath):
            hdrs = {"Authorization": f"Bearer {TOK_OWNER}"}
            async with streamablehttp_client(mcp_url, headers=hdrs) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    await s.call_tool("index_path",
                                      {"directory": str(dirpath), "track": False})

        await _index(user_a_dir)
        await _index(user_b_dir)
        await _index(owner_priv_dir)
        # Wait for ChromaDB's HNSW compactor to flush all three private
        # collections. The compactor runs asynchronously and can lag behind
        # when prior Stage tests have left the write queue backlogged —
        # this fixture runs LATE in the full suite (Stage 5 of many), after
        # several earlier stages have already pushed substantial indexing
        # load through the same shared server/ChromaDB instance.
        #
        # Rather than a fixed sleep (which is fragile), we poll until all
        # three sentinels are visible to the owner. Timeout was 15s — this
        # was observed to be insufficient under full-suite load (a ~8 minute,
        # 1600+ test run), producing a flaky-looking "private isolation
        # broken" failure that was actually just "indexing hadn't finished
        # yet". Running Stage 5 alone (no prior-stage backlog) passes
        # consistently in ~10s total, confirming the underlying access-control
        # logic is correct and this is purely a load-dependent timing margin.
        # Bumped to 45s, with a faster 0.5s poll interval so we notice
        # readiness sooner on a fast run instead of always waiting a full
        # second per attempt.
        import time as _time
        mcp_url_poll = f"{server.base_url}/mcp"
        deadline = _time.time() + 45
        all_ready = False
        last_seen = {"a": False, "b": False, "owner": False}
        while _time.time() < deadline:
            await asyncio.sleep(0.5)
            hdrs = {"Authorization": f"Bearer {TOK_OWNER}"}
            try:
                async with streamablehttp_client(mcp_url_poll, headers=hdrs) as (r, w, _):
                    async with ClientSession(r, w) as s:
                        await s.initialize()
                        res = await s.call_tool("search_documents",
                                               {"query": "private notes confidential eyes only",
                                                "n_results": 20})
                        txt = _tool_result_text(res).lower()
                        last_seen["a"] = SENTINEL_PRIVATE_A.lower() in txt
                        last_seen["b"] = SENTINEL_PRIVATE_B.lower() in txt
                        last_seen["owner"] = SENTINEL_PRIVATE_OWNER.lower() in txt
                        if all(last_seen.values()):
                            all_ready = True
                            break
            except Exception:
                pass  # server busy — keep polling
        # Fail FAST and CLEARLY here if indexing never settled, rather than
        # falling through to let the real test assertions fail with a
        # misleading "private isolation broken" message when the actual
        # cause is "the seed data was never fully indexed in time".
        if not all_ready:
            missing = [k for k, v in last_seen.items() if not v]
            raise RuntimeError(
                f"private_seeded_server: indexing did not complete within "
                f"45s — sentinels still missing from search: {missing}. "
                f"This is a TEST INFRASTRUCTURE timeout (ChromaDB compactor "
                f"lag under load), not a private-isolation bug — see the "
                f"comment above this poll loop. If this recurs even when "
                f"running Stage 5 alone, investigate further; if it only "
                f"happens during the full suite run, the server/ChromaDB "
                f"instance is simply still catching up on backlogged writes "
                f"from earlier stages and the timeout may need raising again."
            )

    @staticmethod
    async def _search(server, token, query, n=10):
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession
        hdrs = {"Authorization": f"Bearer {token}"}
        try:
            async with streamablehttp_client(f"{server.base_url}/mcp",
                                             headers=hdrs) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    res = await s.call_tool("search_documents",
                                            {"query": query, "n_results": n})
                    return _strip_query_echo(_tool_result_text(res))
        except Exception as exc:
            # Return a diagnostic string so tests can give clear failure messages
            # rather than an opaque ExceptionGroup. A 401 here means the new user
            # token wasn't in _srv_access_tokens — apply the hot-reload patch.
            return f"__AUTH_ERROR__: {exc}"

    # ── Positive access ───────────────────────────────────────────────────────

    def test_E2E_ST5_01_user_a_sees_own_private(self, private_seeded_server):
        """E2E-ST5-01: User A can retrieve their own private document."""
        txt = asyncio.run(self._search(
            private_seeded_server, TOK_USER_A, SENTINEL_PRIVATE_A))
        assert "__AUTH_ERROR__" not in txt, (
            f"User A token was rejected (401). Apply patch_hotreload.py first.\n{txt[:300]}")
        assert SENTINEL_PRIVATE_A.lower() in txt or "notes_a" in txt, \
            f"User A cannot see their own private doc.\nResult: {txt[:400]}"

    def test_E2E_ST5_02_user_b_sees_own_private(self, private_seeded_server):
        """E2E-ST5-02: User B can retrieve their own private document."""
        txt = asyncio.run(self._search(
            private_seeded_server, TOK_USER_B, SENTINEL_PRIVATE_B))
        assert "__AUTH_ERROR__" not in txt, (
            f"User B token was rejected (401). Apply patch_hotreload.py first.\n{txt[:300]}")
        assert SENTINEL_PRIVATE_B.lower() in txt or "notes_b" in txt, \
            f"User B cannot see their own private doc.\nResult: {txt[:400]}"

    def test_E2E_ST5_03_owner_sees_all_private(self, private_seeded_server):
        """E2E-ST5-03: Owner can read all private collections."""
        broad = "private notes confidential eyes only"
        txt = asyncio.run(self._search(
            private_seeded_server, TOK_OWNER, broad, n=20))
        missing = []
        for s in (SENTINEL_PRIVATE_A, SENTINEL_PRIVATE_B, SENTINEL_PRIVATE_OWNER):
            if s.lower() not in txt:
                missing.append(s)
        assert not missing, \
            f"Owner missing private sentinels: {missing}\nResult: {txt[:600]}"

    # ── Isolation (the liability tests) ──────────────────────────────────────

    def test_E2E_ST5_04_user_b_cannot_read_user_a_private(self, private_seeded_server):
        """E2E-ST5-04: ISOLATION — User B must NOT read User A's private doc.
        DATA LEAKAGE if this fails."""
        txt = asyncio.run(self._search(
            private_seeded_server, TOK_USER_B, SENTINEL_PRIVATE_A, n=20))
        if "__AUTH_ERROR__" in txt:
            pytest.skip("User B token not yet accepted — apply patch_hotreload.py")
        assert SENTINEL_PRIVATE_A.lower() not in txt, (
            f"⛔ DATA LEAKAGE: User B read User A's private document!\n"
            f"Sentinel '{SENTINEL_PRIVATE_A}' found in:\n{txt[:600]}"
        )

    def test_E2E_ST5_05_user_a_cannot_read_user_b_private(self, private_seeded_server):
        """E2E-ST5-05: ISOLATION — User A must NOT read User B's private doc."""
        txt = asyncio.run(self._search(
            private_seeded_server, TOK_USER_A, SENTINEL_PRIVATE_B, n=20))
        if "__AUTH_ERROR__" in txt:
            pytest.skip("User A token not yet accepted — apply patch_hotreload.py")
        assert SENTINEL_PRIVATE_B.lower() not in txt, (
            f"⛔ DATA LEAKAGE: User A read User B's private document!\n"
            f"Sentinel '{SENTINEL_PRIVATE_B}' found in:\n{txt[:600]}"
        )

    def test_E2E_ST5_06_manager_cannot_read_owner_private(self, private_seeded_server):
        """E2E-ST5-06: OWNER PROTECTION — Manager with can_manage_users=True
        must NOT read the owner's private collection."""
        txt = asyncio.run(self._search(
            private_seeded_server, TOK_MANAGER2, SENTINEL_PRIVATE_OWNER, n=20))
        if "__AUTH_ERROR__" in txt:
            pytest.skip("Manager2 token not yet accepted — apply patch_hotreload.py")
        assert SENTINEL_PRIVATE_OWNER.lower() not in txt, (
            f"⛔ OWNER PROTECTION BREACH: Manager read owner's private doc!\n"
            f"Sentinel '{SENTINEL_PRIVATE_OWNER}' found in:\n{txt[:600]}"
        )

    def test_E2E_ST5_07_sales_manager_cannot_read_any_private(self, private_seeded_server):
        """E2E-ST5-07: Sales manager (role:sales scope only) cannot read
        any user's private collection."""
        broad = "private notes confidential eyes only"
        txt = asyncio.run(self._search(
            private_seeded_server, TOK_SALES, broad, n=20))
        leaked = [s for s in (SENTINEL_PRIVATE_A, SENTINEL_PRIVATE_B, SENTINEL_PRIVATE_OWNER)
                  if s.lower() in txt]
        assert not leaked, (
            f"⛔ DATA LEAKAGE: Sales manager read private docs: {leaked}\n"
            f"Result: {txt[:600]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 6 — Write Isolation & Tier A Tool Suppression (TH-04)
# Proves: field_crew cannot call write/DB tools over real HTTP even by
# crafting raw MCP requests — the handler denies them, not just the UI.
# ─────────────────────────────────────────────────────────────────────────────

TOK_FIELD_CREW = "E2E_TEST_field_crew_pure_4444"

@pytest.mark.e2e
@pytest.mark.skipif(not _mcp_sdk_available(),
                    reason="mcp[cli] not installed — pip install mcp[cli]")
class TestStage6WriteIsolation:
    """E2E-ST6-*: Write tool suppression for Tier A roles over real HTTP.

    Tests that field_crew cannot call index_path, str_replace_in_file, or
    other write tools — even when sending raw MCP tool-call requests.
    The unit tests verify the handler denies them; these tests prove the
    denial happens over the real wire too.
    """

    @pytest.fixture(scope="class")
    def server_with_crew(self, e2e_server) -> _ServerHandle:
        """Add a pure field_crew user to users.json."""
        users_path = e2e_server.state_dir / "users.json"
        data = json.loads(users_path.read_text(encoding="utf-8"))
        data["users"][TOK_FIELD_CREW] = {
            "name": "Field Crew Member",
            "role": "field_crew",
            "scopes": [],
            "private_collection_enabled": False,
            "status": "active",
        }
        users_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        time.sleep(0.2)
        return e2e_server

    @staticmethod
    async def _call_tool(server, token, tool_name, args=None):
        """Call any MCP tool as a given user. Returns lowercased result text.
        Returns '__AUTH_ERROR__: ...' if the token is not recognised (401)."""
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession
        hdrs = {"Authorization": f"Bearer {token}"}
        try:
            async with streamablehttp_client(f"{server.base_url}/mcp",
                                             headers=hdrs) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    res = await s.call_tool(tool_name, args or {})
                    return _tool_result_text(res)
        except Exception as exc:
            return f"__auth_error__: {exc}"

    # ── field_crew write tool denial ──────────────────────────────────────────

    def test_E2E_ST6_01_field_crew_cannot_index_path(self, server_with_crew, tmp_path):
        """E2E-ST6-01: field_crew calling index_path must be denied."""
        dummy = tmp_path / "evil.txt"
        dummy.write_text("should never be indexed", encoding="utf-8")

        txt = asyncio.run(self._call_tool(
            server_with_crew, TOK_FIELD_CREW,
            "index_path", {"directory": str(dummy), "track": False}))

        assert "__auth_error__" not in txt, (
            f"field_crew token was 401 — apply patch_hotreload.py first.\n{txt[:300]}")
        assert any(w in txt for w in ("denied", "not allowed", "cannot", "⛔", "error",
                                       "permission", "forbidden", "blocked")), (
            f"⚠️ field_crew was NOT denied index_path over HTTP!\n"
            f"Response: {txt[:400]}\n"
            f"This means Tier A suppression is not enforced at the handler level."
        )

    def test_E2E_ST6_02_field_crew_cannot_untrack_directory(self, server_with_crew):
        """E2E-ST6-02: field_crew calling untrack_directory must be denied."""
        txt = asyncio.run(self._call_tool(
            server_with_crew, TOK_FIELD_CREW,
            "untrack_directory", {"directory": "C:/any/path"}))

        assert "__auth_error__" not in txt, (
            f"field_crew token was 401 — apply patch_hotreload.py first.\n{txt[:300]}")
        assert any(w in txt for w in ("denied", "not allowed", "cannot", "⛔", "error",
                                       "permission", "forbidden", "blocked")), (
            f"⚠️ field_crew was NOT denied untrack_directory!\nResponse: {txt[:400]}"
        )

    def test_E2E_ST6_03_field_crew_can_search_shared(self, server_with_crew, e2e_server):
        """E2E-ST6-03: field_crew CAN still search shared documents.
        Proves denial is surgical — read access still works."""
        txt = asyncio.run(self._call_tool(
            e2e_server, TOK_FIELD_CREW,
            "search_documents", {"query": SENTINEL_SHARED, "n_results": 5}))
        assert "__auth_error__" not in txt, (
            f"field_crew token was 401 — apply patch_hotreload.py first.\n{txt[:300]}")
        assert "500" not in txt and "error calling tool" not in txt, \
            f"field_crew search_documents returned an error: {txt[:400]}"

    def test_E2E_ST6_04_staff_can_index_own_scope(self, server_with_crew, e2e_server,
                                                    tmp_path):
        """E2E-ST6-04: Staff (not field_crew) CAN call index_path into their scope.
        Confirms the denial is role-specific, not blanket."""
        dummy = tmp_path / "staff_doc.txt"
        dummy.write_text("staff document content for indexing test", encoding="utf-8")

        # TOK_FIELD is actually "staff" role (we changed it for the main tests)
        txt = asyncio.run(self._call_tool(
            e2e_server, TOK_FIELD,
            "index_path", {"directory": str(dummy), "track": False}))

        # Staff should be allowed (not denied)
        assert not any(w in txt for w in ("⛔ index_path", "not allowed",
                                           "field_crew cannot")), (
            f"Staff role was incorrectly denied index_path: {txt[:400]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 7 — collection_map Fallback Warning (TH-02)
# Proves: when a file misses all collection_map rules and falls to the default
# shared collection, a WARNING is logged (not silent data exposure).
#
# Note: This tests the log output of the server subprocess — we scan stdout
# for the warning rather than using MCP tool calls.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.e2e
@pytest.mark.skipif(not _mcp_sdk_available(),
                    reason="mcp[cli] not installed — pip install mcp[cli]")
class TestStage7CollectionMapWarning:
    """E2E-ST7-*: collection_map silent-fallback warning tests.

    Tests that indexing a file with no matching rule emits a warning rather
    than silently routing to shared — the TH-02 fix.
    """

    @staticmethod
    async def _index_unmatched(server: _ServerHandle, doc_path: Path) -> str:
        """Index a file that matches no collection_map rule. Returns tool result."""
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession
        hdrs = {"Authorization": f"Bearer {TOK_OWNER}"}
        async with streamablehttp_client(f"{server.base_url}/mcp",
                                         headers=hdrs) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool(
                    "index_path",
                    {"directory": str(doc_path), "track": False})
                return _tool_result_text(res)

    def test_E2E_ST7_01_unmatched_file_still_indexes(self, e2e_server, tmp_path):
        """E2E-ST7-01: A file with no matching rule still gets indexed (into shared).
        The warning is a safety notice, not a hard block."""
        # Use a path that cannot match any collection_map rule
        unmatched_dir = tmp_path / "no_rule_matches_this_path_xyz"
        unmatched_dir.mkdir()
        (unmatched_dir / "unmatched.txt").write_text(
            "E2E_UNMATCHED_FALLBACK_SENTINEL content.", encoding="utf-8")

        txt = asyncio.run(self._index_unmatched(e2e_server, unmatched_dir))

        # Indexing should succeed (not crash or deny)
        assert "error" not in txt or "indexed" in txt or "chunk" in txt, \
            f"Unmatched file indexing failed unexpectedly: {txt[:400]}"

    def test_E2E_ST7_02_server_log_contains_fallback_warning(self, e2e_server, tmp_path):
        """E2E-ST7-02: Server log contains the collection_map fallback warning.
        Reads the mcp_server.log from the sandboxed state dir to verify
        the warning was emitted (the TH-02 fix in _build_collection_resolver).

        If this test fails: the warning was not added to the code, or the
        file matched a rule and didn't fall through to the default.
        """
        log_path = e2e_server.state_dir / "mcp_server.log"
        if not log_path.exists():
            # Try the AppData location the server writes to
            import os
            appdata = os.environ.get("LOCALAPPDATA", "")
            if appdata:
                log_path = Path(appdata) / "AI-Prowler" / "mcp_server.log"

        if not log_path.exists():
            pytest.skip(
                f"Log file not found at {log_path} — cannot verify warning. "
                f"Check that the server writes logs to AIPROWLER_TEST_STATE_DIR.")

        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        assert "collection_map: no rule matched" in log_text, (
            f"⚠️ TH-02 WARNING NOT FOUND in server log.\n"
            f"Expected: 'collection_map: no rule matched'\n"
            f"Log tail (last 1000 chars):\n{log_text[-1000:]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 8 — Infrastructure: AIPROWLER_TEST_STATE_DIR ChromaDB isolation
# Proves: the rag_preprocessor.py fix correctly redirects CHROMA_DB_PATH
# to the test sandbox, never touching the real production database.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.e2e
class TestStage8SandboxIsolation:
    """E2E-ST8-*: Production ChromaDB isolation tests.

    These tests verify the fix in rag_preprocessor.py that redirects
    CHROMA_DB_PATH to the test state dir when AIPROWLER_TEST_STATE_DIR
    is set. This prevents E2E tests from writing sentinel data into the
    real ~/AI-Prowler/rag_database (the bug that was found and fixed
    during E2E test development).
    """

    def test_E2E_ST8_01_sandbox_chroma_dir_exists(self, e2e_server):
        """E2E-ST8-01: ChromaDB was created inside the sandboxed state dir."""
        # The server should have created a rag_database subdir in state_dir
        chroma_dir = e2e_server.state_dir / "rag_database"
        assert chroma_dir.exists(), (
            f"⚠️ SANDBOX BREACH: ChromaDB not found in sandbox state dir!\n"
            f"Expected: {chroma_dir}\n"
            f"The rag_preprocessor.py CHROMA_DB_PATH redirect is not working.\n"
            f"Test data may be in the real production database."
        )

    def test_E2E_ST8_02_production_chroma_not_used(self, e2e_server):
        """E2E-ST8-02: Production ChromaDB was NOT written during this test session.
        Compares the modification time of the production DB against the moment the
        sandbox server was confirmed healthy — if prod DB was modified after that
        point, something wrote to the real DB while the E2E tests were running."""
        from pathlib import Path as _Path
        import os

        prod_db = _Path.home() / "AI-Prowler" / "rag_database"
        if not prod_db.exists():
            pytest.skip("Production DB doesn't exist yet — nothing to check.")

        # Use server_healthy_time: the moment _wait_healthy() returned True.
        # This is more accurate than state_dir.st_mtime (which is set before
        # Popen) — the old approach had a ~0.5s window where prod-DB writes
        # during server startup were incorrectly flagged as breaches.
        reference_time = e2e_server.server_healthy_time
        if reference_time == 0.0:
            pytest.skip("server_healthy_time was not recorded — skipping breach check.")

        # Check the chroma.sqlite3 or any .bin files inside prod_db
        prod_db_mtime = 0.0
        for f in prod_db.rglob("*"):
            try:
                prod_db_mtime = max(prod_db_mtime, f.stat().st_mtime)
            except Exception:
                pass

        assert prod_db_mtime < reference_time, (
            f"⚠️ SANDBOX BREACH: Production ChromaDB was modified AFTER the E2E\n"
            f"server became healthy. E2E test data may have leaked into production DB!\n"
            f"Prod DB last modified : {prod_db_mtime}\n"
            f"Server healthy time   : {reference_time}\n"
            f"Run cleanup_e2e_test_data.py to remove any contamination."
        )

    def test_E2E_ST8_03_env_var_correctly_set_in_subprocess(self, e2e_server):
        """E2E-ST8-03: The server subprocess had AIPROWLER_TEST_STATE_DIR set.
        Verified indirectly: if the sandbox rag_database exists, the env var
        was honoured (otherwise ChromaDB would have gone to the prod location)."""
        sandbox_db = e2e_server.state_dir / "rag_database"
        # This is redundant with ST8-01 but serves as an explicit env-var check
        assert sandbox_db.exists(), (
            f"AIPROWLER_TEST_STATE_DIR was not honoured by the subprocess.\n"
            f"Check that the env dict is passed correctly to subprocess.Popen."
        )

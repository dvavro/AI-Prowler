#!/usr/bin/env python3
"""
server_mode_test.py — Option C live-server validation (Stage 1: auth/identity).

Uses the test-mode hook (AIPROWLER_TEST_STATE_DIR + config test_mode:true) to
stand up a fully sandboxed server-mode AI-Prowler instance — no real license,
no touching ~/.ai-prowler — then probes it over real HTTP.

STAGE 1 (this file): prove the server boots into business/server mode under the
hook and that per-token authentication + identity works over HTTP:
  - GET /health        -> 200
  - GET /whoami (tok)  -> 200 and the RIGHT user id/role per token
  - GET /whoami (bad)  -> 401
This answers: "does the middleware resolve each bearer token to the right user
live?" — the foundation the keystone (does ctx reach the tools?) builds on.

STAGE 2 (added after Stage 1 passes): MCP tool calls over HTTP asserting
collection scoping + ownership — the full Option C.

USAGE:
    python server_mode_test.py [--port 8123] [--python <interp>] [--keep]

Exit code 0 = all probes passed, 1 = a failure (CI-friendly).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
MCP_MAIN = HERE / "ai_prowler_mcp.py"

# Three sandboxed test users (mirror the in-process harness). Keyed by bearer
# token. Tokens are throwaway test values, never real.
TOK_SALES = "TEST_TOK_sales_manager_0001"
TOK_FIELD = "TEST_TOK_field_manager_0002"
TOK_OWNER = "TEST_TOK_owner_0003"
TOK_BAD   = "TEST_TOK_not_a_real_user_xxxx"

USERS_DOC = {
    "users": {
        TOK_SALES: {"name": "Sales Manager", "role": "manager",
                    "scopes": ["role:sales"], "private_collection_enabled": True,
                    "status": "active"},
        TOK_FIELD: {"name": "Field Manager", "role": "manager",
                    "scopes": ["role:field"], "private_collection_enabled": True,
                    "status": "active"},
        TOK_OWNER: {"name": "Olive Owner", "role": "owner",
                    "scopes": [], "private_collection_enabled": True,
                    "can_manage_users": True, "status": "active"},
    }
}

CONFIG_DOC = {
    "edition": "business",
    "mode": "server",
    "test_mode": True,            # second affirmation the hook requires
    "license_key": "TEST-LICENSE",
    "tunnel_domain": "",          # local test; no real tunnel
}


def _http_get(url, token=None, timeout=5):
    """GET url, optional bearer. Returns (status, body_text). status=0 on conn err."""
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return (r.status, r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return (e.code, e.read().decode("utf-8", "replace"))
    except Exception as e:
        return (0, f"<conn error: {e}>")


def _wait_for_server(base, timeout_s=45):
    """Poll /health until 200 or timeout. Returns True if up."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status, _ = _http_get(f"{base}/health", timeout=3)
        if status == 200:
            return True
        time.sleep(1.0)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8123)
    ap.add_argument("--python", default=sys.executable,
                    help="Interpreter to launch the server with.")
    ap.add_argument("--keep", action="store_true",
                    help="Don't delete temp state dir / don't kill server on exit.")
    args = ap.parse_args()

    base = f"http://127.0.0.1:{args.port}"
    state_dir = Path(tempfile.mkdtemp(prefix="aiprowler_servertest_"))
    (state_dir / "config.json").write_text(json.dumps(CONFIG_DOC, indent=2),
                                           encoding="utf-8")
    (state_dir / "users.json").write_text(json.dumps(USERS_DOC, indent=2),
                                          encoding="utf-8")
    print(f"Sandboxed state dir: {state_dir}")
    print("   config.json: edition=business mode=server test_mode=true")
    print("   users.json : 3 users (sales-mgr, field-mgr, owner)")

    env = dict(os.environ)
    env["AIPROWLER_TEST_STATE_DIR"] = str(state_dir)

    print(f"Launching server: {args.python} ai_prowler_mcp.py "
          f"--transport http --port {args.port}")
    proc = subprocess.Popen(
        [args.python, str(MCP_MAIN), "--transport", "http",
         "--port", str(args.port), "--token", TOK_OWNER,
         "--public-base", base],
        env=env, cwd=str(HERE),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    passed = failed = 0

    def check(label, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"   [PASS] {label}")
        else:
            failed += 1
            print(f"   [FAIL] {label}  {detail}")

    def _dump_tail():
        try:
            proc.terminate()
            out, _ = proc.communicate(timeout=5)
            print("--- server output (tail) ---")
            print("\n".join(out.splitlines()[-40:]))
        except Exception:
            pass

    try:
        print("Waiting for server to come up ...")
        if not _wait_for_server(base, timeout_s=45):
            print("   [FAIL] Server did not become healthy in time.")
            _dump_tail()
            return 1

        print("STAGE 1 - AUTH / IDENTITY over real HTTP\n" + "-" * 50)

        s, _ = _http_get(f"{base}/health")
        check("/health returns 200", s == 200, f"(got {s})")

        for tok, exp_role, exp_name in (
            (TOK_SALES, "manager", "Sales Manager"),
            (TOK_FIELD, "manager", "Field Manager"),
            (TOK_OWNER, "owner",   "Olive Owner"),
        ):
            s, body = _http_get(f"{base}/whoami", token=tok)
            ok_status = (s == 200)
            ident_ok = False
            try:
                j = json.loads(body)
                blob = json.dumps(j).lower()
                ident_ok = (exp_role in blob) and (
                    tok.lower() in blob or exp_name.lower() in blob)
            except Exception:
                ident_ok = False
            check(f"/whoami [{exp_name}] 200 + correct identity",
                  ok_status and ident_ok, f"(status={s} body={body[:200]})")

        s, _ = _http_get(f"{base}/whoami", token=TOK_BAD)
        check("/whoami [bad token] -> 401", s == 401, f"(got {s})")

        print("\n" + "-" * 50)
        print(f"   RESULT: {passed} passed, {failed} failed")
        if failed:
            print("   STAGE 1 FAILED - see server output below.")
            _dump_tail()
            return 1
        print("   STAGE 1 PASSED - auth + identity work live over HTTP.")
        return 0

    finally:
        if not args.keep:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            shutil.rmtree(state_dir, ignore_errors=True)
            print(f"Cleaned up {state_dir}")
        else:
            print(f"--keep set: server still running (pid {proc.pid}), "
                  f"state dir kept at {state_dir}")


if __name__ == "__main__":
    sys.exit(main())

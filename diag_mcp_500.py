#!/usr/bin/env python3
"""
diag_mcp_500.py — diagnose the Stage 2 'POST /mcp 500' by capturing the server's
FULL traceback. Launches the sandboxed server with stdout/stderr going straight
to THIS console (not captured), then fires one minimal MCP initialize request so
the 500 (and its server-side traceback) prints live for us to read.

Run:
    python diag_mcp_500.py
Then read the server traceback printed below the request output. Ctrl-C to stop.
"""
import json, os, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
MCP_MAIN = HERE / "ai_prowler_mcp.py"
PORT = 8124
BASE = f"http://127.0.0.1:{PORT}"
TOK_OWNER = "TEST_TOK_owner_0003"

USERS_DOC = {"users": {
    TOK_OWNER: {"name": "Olive Owner", "role": "owner", "scopes": [],
                "private_collection_enabled": True, "can_manage_users": True,
                "status": "active"}}}
CONFIG_DOC = {"edition": "business", "mode": "server", "test_mode": True,
              "license_key": "TEST-LICENSE", "tunnel_domain": ""}


def post_mcp(body, extra_headers=None):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "Authorization": f"Bearer {TOK_OWNER}"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(f"{BASE}/mcp", data=data, headers=headers,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, {}, f"<conn error: {e}>"


def main():
    state_dir = Path(tempfile.mkdtemp(prefix="aiprowler_diag_"))
    (state_dir / "config.json").write_text(json.dumps(CONFIG_DOC, indent=2), encoding="utf-8")
    (state_dir / "users.json").write_text(json.dumps(USERS_DOC, indent=2), encoding="utf-8")
    env = dict(os.environ)
    env["AIPROWLER_TEST_STATE_DIR"] = str(state_dir)

    print(f"State dir: {state_dir}")
    print("Launching server (its output prints below) ...\n" + "=" * 60)
    # NOTE: stdout/stderr NOT captured -> server logs + tracebacks print live.
    proc = subprocess.Popen(
        [sys.executable, str(MCP_MAIN), "--transport", "http",
         "--port", str(PORT), "--token", TOK_OWNER, "--public-base", BASE],
        env=env, cwd=str(HERE))
    try:
        # wait for /health
        for _ in range(45):
            try:
                req = urllib.request.Request(f"{BASE}/health")
                with urllib.request.urlopen(req, timeout=3) as r:
                    if r.status == 200:
                        break
            except Exception:
                pass
            time.sleep(1)
        print("\n" + "=" * 60)
        print(">>> Sending MCP initialize to /mcp ...")
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "diag", "version": "0.0.1"},
            },
        }
        status, hdrs, text = post_mcp(body)
        print(f">>> Response status: {status}")
        print(f">>> Response headers: {json.dumps(hdrs, indent=2)[:800]}")
        print(f">>> Response body (first 1500 chars):\n{text[:1500]}")
        print("\n" + "=" * 60)
        print("If status==500, the server traceback is ABOVE this line "
              "(in the server output). Read it to find the cause.")
        print("Server still running — press Ctrl-C to stop.")
        proc.wait()
    except KeyboardInterrupt:
        print("\nStopping ...")
    finally:
        try:
            proc.terminate(); proc.wait(timeout=5)
        except Exception:
            try: proc.kill()
            except Exception: pass
        import shutil
        shutil.rmtree(state_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

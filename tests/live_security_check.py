"""Live check of the 2026-09-25 personal-mode PWA security fix, against the
REAL public address (exactly what a stranger on the internet would see).

Read-only: the only tool it calls is check_ai_prowler_status. Never prints
the token. Token source: AIPROWLER_JOBS_TOKEN (process env, else the saved
Windows user setting written by `setx`). URL: AIPROWLER_JOBS_URL origin, else
https://<tunnel_domain from ~/.ai-prowler/config.json>.

Exit code 0 = every check passed.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _token() -> str:
    t = os.environ.get("AIPROWLER_JOBS_TOKEN", "").strip()
    if t:
        return t
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return str(winreg.QueryValueEx(k, "AIPROWLER_JOBS_TOKEN")[0]).strip()
    except Exception:
        return ""


def _origin() -> str:
    u = os.environ.get("AIPROWLER_JOBS_URL", "").strip()
    if u:
        from urllib.parse import urlsplit
        p = urlsplit(u)
        return f"{p.scheme}://{p.netloc}"
    cfg = json.loads((Path.home() / ".ai-prowler" / "config.json").read_text(encoding="utf-8"))
    dom = str(cfg.get("tunnel_domain", "")).strip().strip("/")
    if not dom:
        sys.exit("No AIPROWLER_JOBS_URL and no tunnel_domain in config.json")
    return dom if dom.startswith("http") else "https://" + dom


def _req(method, url, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    r.add_header("User-Agent", "AI-Prowler-security-check")
    if token is not None:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main() -> int:
    origin, tok = _origin(), _token()
    print(f"Target: {origin}")
    if not tok:
        print("❌ No AIPROWLER_JOBS_TOKEN found (env or saved user setting).")
        return 2
    print(f"Token:  found ({len(tok)} characters — not shown)\n")
    status_call = {"tool": "check_ai_prowler_status", "args": {}}
    results = []

    def check(name, ok, detail):
        results.append(ok)
        print(("✅ PASS  " if ok else "❌ FAIL  ") + name + (f"  —  {detail}" if detail else ""))

    s, b = _req("GET", origin + "/pwa-token")
    try:
        leaked = json.loads(b).get("token", "")
    except Exception:
        leaked = None
    check("/pwa-token does NOT hand out the token", s == 200 and leaked == "",
          f"HTTP {s}, token field {'EMPTY' if leaked == '' else 'PRESENT!' if leaked else repr(leaked)}")

    s, _ = _req("POST", origin + "/pwa-api", status_call)
    check("/pwa-api with NO token is refused", s == 401, f"HTTP {s}")

    s, _ = _req("POST", origin + "/pwa-api", status_call, token="wrong-" + "x" * 20)
    check("/pwa-api with a WRONG token is refused", s == 401, f"HTTP {s}")

    s, _ = _req("POST", origin + "/photos/upload", {"job_id": "X", "photos": []})
    check("/photos/upload with NO token is refused", s == 401, f"HTTP {s}")

    s, _ = _req("POST", origin + "/pwa-verify", {"token": "wrong-" + "x" * 20})
    check("/pwa-verify rejects a WRONG token", s == 401, f"HTTP {s}")

    s, _ = _req("POST", origin + "/pwa-verify", {"token": tok})
    check("/pwa-verify accepts the RIGHT token", s == 200, f"HTTP {s}")

    s, b = _req("POST", origin + "/pwa-api", status_call, token=tok)
    ok = False
    try:
        ok = s == 200 and json.loads(b).get("ok") is True
    except Exception:
        pass
    check("/pwa-api with the RIGHT token still works", ok, f"HTTP {s}")

    passed = sum(results)
    print(f"\n{'✅ ALL' if passed == len(results) else '❌'} {passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

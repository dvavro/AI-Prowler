"""Configuration + API client for the Jobs-app E2E suite.

The client is how test SETUP, VERIFICATION and CLEANUP talk to the live
server. It goes through the same Guard as the browser, so test code can't
write to real data either.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from safety import Guard, GuardViolation


# ── configuration ────────────────────────────────────────────────────────────
def get_token() -> str:
    """AIPROWLER_JOBS_TOKEN from the process, else the saved Windows user
    setting (`setx` writes it there; a program started before `setx` — e.g.
    AI-Prowler itself — doesn't see it in its environment until restarted)."""
    t = os.environ.get("AIPROWLER_JOBS_TOKEN", "").strip()
    if t:
        return t
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return str(winreg.QueryValueEx(k, "AIPROWLER_JOBS_TOKEN")[0]).strip()
    except Exception:
        return ""


def get_app_url() -> str:
    """Full URL of the Jobs app (…/jobs/)."""
    u = os.environ.get("AIPROWLER_JOBS_URL", "").strip()
    if u:
        return u if u.endswith("/") else u + "/"
    cfg = json.loads((Path.home() / ".ai-prowler" / "config.json").read_text(encoding="utf-8"))
    dom = str(cfg.get("tunnel_domain", "")).strip().strip("/")
    if not dom:
        raise RuntimeError("Set AIPROWLER_JOBS_URL, or configure the tunnel in Settings → Remote Access.")
    base = dom if dom.startswith("http") else "https://" + dom
    return base + "/jobs/"


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def local_api_origin() -> str:
    """Where the ApiClient's own setup/verification/cleanup HTTP calls go --
    deliberately NOT the public tunnel origin. Cloudflare's bot protection
    fingerprints the TLS handshake itself (JA3/JA4), not just headers -- the
    USER_AGENT fix below stopped the fast 403 seen on the very first E2E run,
    but a plain urllib client still can't pass as a real browser at the TLS
    layer, so traffic now gets silently held at the edge instead: a clean
    reject became a ~30s read timeout on api.raw_get("/pwa-token") and every
    ApiClient.call(), intermittently, with no code-side symptom to point at.
    This install runs the Jobs app server on this same machine
    (Uvicorn on http://127.0.0.1:8000 per its own startup log), so setup
    calls can skip the tunnel/Cloudflare hop entirely and go straight to the
    origin. The Playwright-launched browser is unaffected -- it still opens
    the real public tunnel URL (app_url) for actual UI testing, which is the
    one thing here that must exercise the real deployed path end to end.
    Override with AIPROWLER_LOCAL_API_ORIGIN for a non-local server."""
    return os.environ.get("AIPROWLER_LOCAL_API_ORIGIN", "http://127.0.0.1:8000")


# ── parsing the server's text replies ────────────────────────────────────────
def parse_records(text: str) -> list[dict]:
    """read_job_spreadsheet returns blocks of '  Key: Value' lines separated by
    blank lines. Returns one dict per block."""
    recs, cur = [], {}
    for line in (text or "").splitlines():
        if line.startswith("  ") and ": " in line and not line.startswith("   "):
            k, v = line.strip().split(": ", 1)
            cur[k] = v
        elif not line.strip():
            if cur:
                recs.append(cur)
                cur = {}
    if cur:
        recs.append(cur)
    return recs


def iso_date(v: str) -> str:
    """'01/07/2030' -> '2030-01-07' (server shows dates as MM/DD/YYYY)."""
    v = (v or "").strip()
    if len(v) == 10 and v[2] == "/" and v[5] == "/":
        return f"{v[6:]}-{v[:2]}-{v[3:5]}"
    return v


# ── API client ───────────────────────────────────────────────────────────────
class ApiError(Exception):
    pass


# Cloudflare's bot protection answers 403 to Python's default
# "Python-urllib/x.y" User-Agent (found on the first E2E run, 2026-09-25).
USER_AGENT = "AI-Prowler-E2E/1.0 (+tests/gui_jobs_e2e)"


def http(method: str, url: str, body: dict | None = None, token: str | None = None,
         timeout: int = 90) -> tuple[int, str]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", USER_AGENT)
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


class ApiClient:
    def __init__(self, origin: str, token: str, guard: Guard, log=None, api_log=None):
        self.url = origin.rstrip("/") + "/pwa-api"
        self.origin = origin.rstrip("/")
        self.token = token
        self.guard = guard
        self.log = log or (lambda *a: None)
        self.api_log = api_log or (lambda *a: None)

    def call(self, tool: str, args: dict | None = None, *, expect_ok: bool = True) -> str:
        args = args or {}
        decision, why = self.guard.enforce(tool, args, "setup")
        if decision == "block":
            raise GuardViolation(f"guard blocked setup call {tool}: {why}")
        if decision == "record":
            raise GuardViolation(f"setup must not make outbound/credit calls ({tool}): {why}")
        # R-059: Email Route On Build — a route build's auto-email is switched
        # off unless it's the one allowed real route email (safety.py)
        if hasattr(self.guard, "route_email_args"):
            args, _note = self.guard.route_email_args(tool, args)
        t0 = time.time()
        status, raw = http("POST", self.url, {"tool": tool, "args": args}, token=self.token)
        ms = int((time.time() - t0) * 1000)
        try:
            data = json.loads(raw)
        except Exception:
            data = {"ok": False, "error": raw[:300]}
        result = data.get("result", "") if data.get("ok") else ""
        self.api_log({"source": "setup", "tool": tool, "args": args, "status": status, "ms": ms,
                      "ok": bool(data.get("ok")), "excerpt": (result or data.get("error", ""))[:300]})
        if status == 401:
            raise ApiError("401 Not logged in — check AIPROWLER_JOBS_TOKEN")
        if not data.get("ok"):
            raise ApiError(f"{tool} failed: {data.get('error')}")
        self.guard.note_result(tool, result)
        if expect_ok and isinstance(result, str) and result.lstrip().startswith("❌"):
            raise ApiError(f"{tool} refused: {result.splitlines()[0]}")
        return result

    # convenience
    def read(self, sheet: str = "", **kw) -> list[dict]:
        args = {"max_rows": 1000}
        if sheet:
            args["sheet_name"] = sheet
        args.update(kw)
        return parse_records(self.call("read_job_spreadsheet", args, expect_ok=False))

    def raw_get(self, path: str) -> tuple[int, str]:
        return http("GET", self.origin + path, timeout=30)

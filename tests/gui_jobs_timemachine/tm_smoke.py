"""Smoke test for the time machine (no browser): start it, call the Jobs API,
move the clock, run the morning briefing, check nothing got out, stop."""
import json
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import functools

HERE = pathlib.Path(__file__).resolve().parent
_REPORT = open(HERE / "tm_smoke_report.txt", "w", encoding="utf-8")
_print = print


def print(*a, **k):                                   # noqa: A001
    _print(*a, **k, flush=True)
    _print(*a, file=_REPORT, flush=True)
PORT, CTL = 8791, 8792


def _req(url, body=None, token=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"ok": False, "http": e.code, "error": e.read().decode("utf-8", "replace")[:300]}


def main():
    home = tempfile.mkdtemp(prefix="ap_timemachine_")
    token = secrets.token_urlsafe(24)
    log = open(pathlib.Path(home) / "tm_server.out", "w", encoding="utf-8")
    p = subprocess.Popen([sys.executable, str(HERE / "tm_server.py"), "--home", home, "--port", str(PORT),
                          "--control-port", str(CTL), "--token", token, "--date", "2026-10-05"],
                         stdout=log, stderr=subprocess.STDOUT)
    try:
        t0 = time.time()
        while time.time() - t0 < 120:
            try:
                _req(f"http://127.0.0.1:{PORT}/jobs/")      # not JSON -> raises, fine
            except json.JSONDecodeError:
                break
            except Exception:
                if p.poll() is not None:
                    raise SystemExit("server exited early:\n" + (pathlib.Path(home) / "tm_server.out").read_text()[-3000:])
                time.sleep(1)
        print("state:", _req(f"http://127.0.0.1:{CTL}/state"))
        api = f"http://127.0.0.1:{PORT}/pwa-api"
        r = _req(api, {"tool": "read_job_spreadsheet", "args": {"sheet_name": "Settings", "max_rows": 5}}, token)
        print("api ok:", r.get("ok"), str(r.get("result", r.get("error")))[:200].replace("\n", " | "))
        print("clock ->", _req(f"http://127.0.0.1:{CTL}/clock", {"date": "2026-10-12", "time": "07:30"}))
        mb = _req(f"http://127.0.0.1:{CTL}/run", {"job": "morning_briefing"})
        print("morning briefing:", mb["today"], mb["subject"])
        r = _req(api, {"tool": "create_customer", "args": {"fields": {
            "Company Name": "ZTEST TM Customer", "Email": "customer@time-machine.test", "Phone": "3865550100"}}}, token)
        print("create_customer:", str(r.get("result", r.get("error")))[:160].replace("\n", " | "))
        r = _req(api, {"tool": "check_email_configured", "args": {}}, token)
        print("check_email_configured:", str(r.get("result", r.get("error")))[:160].replace("\n", " | "))
        r = _req(api, {"tool": "check_sms_configured", "args": {}}, token)
        print("check_sms_configured:", str(r.get("result", r.get("error")))[:160].replace("\n", " | "))
        print("outbox:", _req(f"http://127.0.0.1:{CTL}/outbox"))
        print("sandbox:", home)
    finally:
        try:
            _req(f"http://127.0.0.1:{CTL}/stop", {})
        except Exception:
            pass
        time.sleep(1)
        if p.poll() is None:
            p.kill()
        log.close()
        print("--- server output tail ---")
        print((pathlib.Path(home) / "tm_server.out").read_text(encoding="utf-8", errors="replace")[-1500:])


if __name__ == "__main__":
    main()

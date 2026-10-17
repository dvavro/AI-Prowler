"""HR TIME MACHINE server (David, 2026-10-17) — a throwaway AI-Prowler SERVER
install whose clock the tests move, so HR onboarding / offboarding can be
walked day by day in a real browser.

Started by tests\\gui_hr_timemachine\\conftest.py as its own process:

    python hr_tm_server.py --home <empty temp dir> --port P --control-port C
                           --token <owner token> --users-file users.json --date 2026-11-02

Safe by construction (modeled on tests\\gui_jobs_timemachine\\tm_server.py):
  * HOME / USERPROFILE / Path.home() and AIPROWLER_TEST_STATE_DIR point into
    --home, so config.json, users.json, HR data and logs are brand-new files
    there. It refuses to start in the real home folder or a folder it didn't create.
  * Nothing can be sent: SMTP is replaced, hr_scheduler's mail goes to the
    OUTBOX, and every outbound HTTP request except 127.0.0.1 is refused.
  * Every user email must be a test address (+hrtest@example.com).
  * The HR background scheduler is NOT started: each simulated morning the test
    runs the scheduler jobs in their real daily order with POST /run-day, so
    every email belongs to a known simulated day.

The clock: time_machine moves Python's date/time for the whole process
(date.today(), datetime.now(), time.time()); asyncio's own timer keeps real
time, so the web server runs normally.

Control API (127.0.0.1:<control-port>, JSON):
    GET  /state                      -> {"now", "today", "sandbox"}
    POST /clock   {"date", "time"}   -> move the clock
    POST /run-day {"date"}           -> 06:00 on that date, then every HR job in order
    GET  /outbox                     -> every email the app tried to send
    POST /stop
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_ROOT = pathlib.Path(__file__).resolve().parents[2]
MARKER = "HR_TIME_MACHINE_SANDBOX"
OUTBOX: list = []
_lock = threading.Lock()

# The HR scheduler's jobs in their real daily order (as tests\mcp_tests\test_hr_timemachine_flow.py)
DAILY_JOBS = ("job_lifecycle_advance", "job_overdue_checker", "job_reminder_48h", "job_prestart_welcome",
              "job_benefits_window_warning", "job_doc_expiration_check", "job_daily_digest",
              "job_reminder_email", "job_due_today_sender", "job_overdue_first_notice", "job_escalation_check")


def _record(**fields):
    with _lock:
        OUTBOX.append(dict(day=dt.date.today().isoformat(), at=dt.datetime.now().isoformat(timespec="minutes"),
                           **fields))


def _prepare_home(home: pathlib.Path, users: dict) -> pathlib.Path:
    home = home.resolve()
    real_home = pathlib.Path(os.path.expanduser("~")).resolve()
    if home == real_home:
        raise SystemExit(f"refusing: --home {home} is the real home folder")
    state = home / ".ai-prowler"
    state.mkdir(parents=True, exist_ok=True)
    marker = state / MARKER
    if any(state.iterdir()) and not marker.exists():
        raise SystemExit(f"refusing: {state} has files and isn't an HR time-machine sandbox")
    marker.write_text("created by hr_tm_server.py - safe to delete\n", encoding="utf-8")
    for u in users.get("users", {}).values():
        assert str(u.get("email", "")).endswith("+hrtest@example.com"), f"non-test user address: {u}"
    os.environ["HOME"] = os.environ["USERPROFILE"] = str(home)
    os.environ["AIPROWLER_TEST_STATE_DIR"] = str(state)
    os.environ["AIPROWLER_TIME_MACHINE"] = "1"
    pathlib.Path.home = classmethod(lambda cls: cls(str(home)))          # type: ignore[assignment]
    (state / "email_config.json").write_text(json.dumps({
        "backend": "smtp", "smtp_host": "outbox.hr-time-machine.invalid", "smtp_port": 587,
        "username": "hr+hrtest@example.com", "from_address": "hr+hrtest@example.com",
        "default_to": "hr+hrtest@example.com", "use_tls": True}), encoding="utf-8")
    (state / "config.json").write_text(json.dumps({
        "edition": "business", "mode": "server", "test_mode": True, "license_key": "HR-TIME-MACHINE",
        "tunnel_domain": "", "owner_name": "ZTEST Owner"}), encoding="utf-8")
    (state / "users.json").write_text(json.dumps(users, indent=1), encoding="utf-8")
    (state / "tool_config.json").write_text(json.dumps({"schema_version": 1, "hr_apps_enabled": True}),
                                            encoding="utf-8")
    return state


def _block_outbound():
    import smtplib

    class _FakeSMTP:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self, *a, **k): return (250, b"ok")
        def starttls(self, *a, **k): return (220, b"ok")
        def login(self, *a, **k): return (235, b"ok")
        def quit(self): return (221, b"bye")
        def close(self): pass

        def sendmail(self, from_addr, to_addrs, msg):
            import email
            m = email.message_from_string(msg if isinstance(msg, str) else msg.decode("utf-8", "replace"))
            _record(source="app", to=", ".join(to_addrs) if isinstance(to_addrs, (list, tuple)) else str(to_addrs),
                    subject=str(m.get("Subject", "")))
            return {}

        def send_message(self, m, *a, **k):
            return self.sendmail(m.get("From"), [m.get("To")], m.as_string())

    smtplib.SMTP = _FakeSMTP            # type: ignore[assignment]
    smtplib.SMTP_SSL = _FakeSMTP        # type: ignore[assignment]
    try:
        import requests
        from urllib.parse import urlparse
        _orig = requests.Session.request

        def _guarded(self, method, url, *a, **k):
            host = (urlparse(str(url)).hostname or "").lower()
            if host not in ("127.0.0.1", "localhost"):
                _record(source="blocked_http", to=host, subject=f"{method} {url}"[:200])
                raise requests.ConnectionError(f"HR time machine: outbound request to {host} blocked")
            return _orig(self, method, url, *a, **k)
        requests.Session.request = _guarded                              # type: ignore[assignment]
    except Exception:
        pass


def _local(date_s: str, time_s: str = "06:00") -> dt.datetime:
    d = dt.date.fromisoformat(date_s)
    h, m = (int(x) for x in time_s.split(":")[:2])
    return dt.datetime(d.year, d.month, d.day, h, m).astimezone()


class _Control(BaseHTTPRequestHandler):
    traveller = None
    hs = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/state":
            return self._send(200, {"now": dt.datetime.now().isoformat(timespec="seconds"),
                                    "today": dt.date.today().isoformat(),
                                    "sandbox": os.environ["AIPROWLER_TEST_STATE_DIR"]})
        if self.path == "/outbox":
            with _lock:
                return self._send(200, list(OUTBOX))
        self._send(404, {"error": "unknown"})

    def do_POST(self):
        try:
            b = self._body()
            if self.path == "/clock":
                _Control.traveller.move_to(_local(b["date"], b.get("time", "06:00")))
                return self._send(200, {"now": dt.datetime.now().isoformat(timespec="seconds")})
            if self.path == "/run-day":
                _Control.traveller.move_to(_local(b["date"], "06:00"))
                results = {}
                for name in DAILY_JOBS:
                    results[name] = getattr(_Control.hs, name)()
                if dt.date.today().weekday() == 0:
                    results["job_weekly_owner_summary"] = _Control.hs.job_weekly_owner_summary()
                _Control.traveller.move_to(_local(b["date"], b.get("then", "09:00")))   # office hours
                errors = {k: v for k, v in results.items() if "error" in str(v).lower()}
                return self._send(200 if not errors else 500, {"today": dt.date.today().isoformat(),
                                                               "results": results, "errors": errors})
            if self.path == "/stop":
                self._send(200, {"ok": True})
                threading.Thread(target=lambda: os._exit(0), daemon=True).start()
                return
            self._send(404, {"error": "unknown"})
        except Exception as exc:                                            # pragma: no cover
            import traceback
            self._send(500, {"error": str(exc), "trace": traceback.format_exc()[-2000:]})


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--home", required=True)
    a.add_argument("--port", type=int, required=True)
    a.add_argument("--control-port", type=int, required=True)
    a.add_argument("--token", required=True)
    a.add_argument("--users-file", required=True)
    a.add_argument("--date", required=True)
    args = a.parse_args()

    users = json.loads(pathlib.Path(args.users_file).read_text(encoding="utf-8"))
    state = _prepare_home(pathlib.Path(args.home), users)
    sys.path.insert(0, str(APP_ROOT))
    _block_outbound()

    import time_machine
    traveller = time_machine.travel(_local(args.date, "06:00"), tick=True)
    _Control.traveller = traveller.start()

    import hr_scheduler as hs                                           # before the app starts it
    hs.start = lambda *a, **k: None                                     # the test runs each morning itself

    def _capture(subject, html_body, to_addr):
        if not to_addr:
            return False
        _record(source="hr_scheduler", to=str(to_addr), subject=str(subject))
        return True
    hs._send_mail = _capture
    _Control.hs = hs

    import ai_prowler_mcp as mcp
    ctl = ThreadingHTTPServer(("127.0.0.1", args.control_port), _Control)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    print(f"HR TIME MACHINE ready: http://127.0.0.1:{args.port}/hr_admin/  control :{args.control_port}  "
          f"sandbox {state}  today {dt.date.today()}  server_mode={mcp._IS_SERVER_MODE}", flush=True)
    assert mcp._IS_SERVER_MODE, "the sandbox must come up as a SERVER install"
    mcp._run_server_mode(port=args.port, token=args.token, public_base=f"http://127.0.0.1:{args.port}")


if __name__ == "__main__":
    main()

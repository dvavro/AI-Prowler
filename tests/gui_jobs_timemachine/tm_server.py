"""AI-Prowler TIME MACHINE server — a throwaway copy of the app for tests that
need days to pass (David 2026-09-29: "simulate the passing of days so that
the full jobs features show up through time").

Started by tests\\gui_jobs_timemachine\\conftest.py as its own process:

    python tm_server.py --home <empty temp dir> --port 8791 --control-port 8792
                        --token <random> --date 2026-10-05

What makes it safe (it can never touch the real install):
  • HOME/USERPROFILE and Path.home() point at --home, and
    AIPROWLER_TEST_STATE_DIR at <home>\\.ai-prowler — so the job database,
    settings, config, email/SMS config, users, knowledge base and logs are all
    brand-new files inside that temp folder. It refuses to start if --home
    already holds a jobs database it didn't create, or is the real home.
  • Nothing can be sent: SMTP, Outlook, SMS/WhatsApp providers and every
    outbound HTTP request except the two map services (OSRM routing,
    Nominatim geocoding) are replaced in-process. Emails/texts the app
    "sends" land in the OUTBOX instead (GET /outbox), with the simulated date.
  • AI Routing (Claude credits) is switched off in here.

The clock: time-machine moves Python's date/time for the whole process
(date.today(), datetime.now(), time.time()) while asyncio's own timer keeps
real time, so the web server runs normally. POST /clock moves it.

Control API (127.0.0.1:<control-port>, JSON):
    GET  /state                  -> {"now": ..., "today": ...}
    POST /clock {"date": "YYYY-MM-DD", "time": "HH:MM"}
    POST /run   {"job": "morning_briefing"}  -> the scheduler job's
                 {"subject", "body"} for the simulated day (never emailed)
    GET  /outbox                 -> everything the app tried to send
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

APP_ROOT = pathlib.Path(__file__).resolve().parents[2]      # ...\AI-Prowler (work copy)
ALLOWED_HOSTS = ("router.project-osrm.org", "nominatim.openstreetmap.org", "127.0.0.1", "localhost")
MARKER = "TIME_MACHINE_SANDBOX"

OUTBOX: list[dict] = []
_outbox_lock = threading.Lock()


def _record(kind: str, **fields):
    with _outbox_lock:
        OUTBOX.append(dict(kind=kind, sim_time=dt.datetime.now().isoformat(timespec="minutes"), **fields))


def _prepare_home(home: pathlib.Path, mode: str = "personal", users: dict | None = None) -> pathlib.Path:
    home = home.resolve()
    real_home = pathlib.Path(os.path.expanduser("~")).resolve()
    if home == real_home or real_home in home.parents and home.name in (".ai-prowler",):
        raise SystemExit(f"refusing: --home {home} is (inside) the real home folder")
    state = home / ".ai-prowler"
    state.mkdir(parents=True, exist_ok=True)
    marker = state / MARKER
    if any(state.iterdir()) and not marker.exists():
        raise SystemExit(f"refusing: {state} has files and isn't a time-machine sandbox")
    marker.write_text("created by tm_server.py — safe to delete\n", encoding="utf-8")
    # Everything that looks up the home folder lands in the sandbox.
    os.environ["HOME"] = os.environ["USERPROFILE"] = str(home)
    os.environ["AIPROWLER_TEST_STATE_DIR"] = str(state)
    os.environ["AIPROWLER_TIME_MACHINE"] = "1"
    pathlib.Path.home = classmethod(lambda cls: cls(str(home)))          # type: ignore[assignment]
    # A "configured" mailbox so the app's email buttons are live — every
    # message is caught by the fake SMTP below and goes to the outbox.
    (state / "email_config.json").write_text(json.dumps({
        "backend": "smtp", "smtp_host": "outbox.time-machine.invalid", "smtp_port": 587,
        "username": "owner@time-machine.test", "from_address": "owner@time-machine.test",
        "default_to": "owner@time-machine.test", "use_tls": True}), encoding="utf-8")
    cfg = {"mode": "personal", "sms_provider": "twilio", "twilio_account_sid": "ACtimemachine",
           "twilio_auth_token": "time-machine", "twilio_from_number": "+15550100000"}
    if mode == "server":
        # A Business SERVER install. test_mode + AIPROWLER_TEST_STATE_DIR is the
        # app's own sandbox switch: no license/subscription network calls, while
        # login, roles and crew scoping run for real against the users below.
        cfg.update({"edition": "business", "mode": "server", "test_mode": True,
                    "license_key": "TIME-MACHINE-TEST", "tunnel_domain": "", "owner_name": "ZT Owner"})
        for u in (users or {}).get("users", {}).values():
            for field in ("email",):
                assert str(u.get(field, "")).endswith("@time-machine.test"), f"non-test user address: {u}"
        (state / "users.json").write_text(json.dumps(users, indent=1), encoding="utf-8")
    (state / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return state


def _block_outbound():
    """Nothing leaves this process except the map lookups."""
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
            body = ""
            for part in m.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode("utf-8", "replace")
                    break
            _record("email", to=", ".join(to_addrs) if isinstance(to_addrs, (list, tuple)) else str(to_addrs),
                    subject=str(m.get("Subject", "")), body=body[:4000])
            return {}

        def send_message(self, m, *a, **k):
            return self.sendmail(m.get("From"), [m.get("To")], m.as_string())

    smtplib.SMTP = _FakeSMTP            # type: ignore[assignment]
    smtplib.SMTP_SSL = _FakeSMTP        # type: ignore[assignment]

    import sms_backends

    class _OutboxSMS:
        provider_name = "time-machine outbox"
        def __init__(self, kind): self.kind = kind
        def validate_config(self): return True, "ok"
        def send(self, to, body):
            _record(self.kind, to=str(to), body=str(body)[:2000])
            return True, "caught by the time-machine outbox (not sent)"

    sms_backends.get_sms_backend = lambda cfg=None: _OutboxSMS("sms")
    sms_backends.get_whatsapp_backend = lambda cfg=None: _OutboxSMS("whatsapp")

    import requests
    from urllib.parse import urlparse
    _orig = requests.Session.request

    def _guarded(self, method, url, *a, **k):
        host = (urlparse(str(url)).hostname or "").lower()
        if not any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS):
            _record("blocked_http", to=host, body=f"{method} {url}"[:300])
            raise requests.ConnectionError(f"time machine: outbound request to {host} blocked")
        return _orig(self, method, url, *a, **k)

    requests.Session.request = _guarded                                  # type: ignore[assignment]


def _patch_app(mcp):
    """Switch off what must never run in the sandbox."""
    try:
        mcp._outlook_is_available = lambda *a, **k: False
    except Exception:
        pass
    mcp.start_ai_routing = lambda *a, **k: "❌ AI Routing is switched off in the time machine (uses Claude credits)."
    mcp.get_weather = lambda *a, **k: "☀️ Sunny, 80°F (time machine — no real weather lookup)"
    try:
        import db_write_ops
        db_write_ops.AUTO_GEOCODE_ENABLED = True          # jobs get map locations like a real install
    except Exception:
        pass


class _Control(BaseHTTPRequestHandler):
    traveller = None
    stop_cb = None

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
                                    "today": dt.date.today().isoformat(), "sandbox": os.environ["AIPROWLER_TEST_STATE_DIR"]})
        if self.path == "/outbox":
            with _outbox_lock:
                return self._send(200, list(OUTBOX))
        self._send(404, {"error": "unknown"})

    def do_POST(self):
        try:
            b = self._body()
            if self.path == "/clock":
                when = _local(b["date"], b.get("time", "07:00"))
                _Control.traveller.move_to(when)
                return self._send(200, {"now": dt.datetime.now().isoformat(timespec="seconds")})
            if self.path == "/run":
                import scheduler_jobs
                meta = scheduler_jobs.JOB_REGISTRY.get(b.get("job", ""))
                if not meta:
                    return self._send(404, {"error": f"unknown job {b.get('job')!r}"})
                res = meta["fn"](b.get("config") or {})
                subject, body = (res if res else ("", ""))
                return self._send(200, {"subject": subject, "body": body,
                                        "today": dt.date.today().isoformat()})
            if self.path == "/stop":
                self._send(200, {"ok": True})
                threading.Thread(target=_Control.stop_cb, daemon=True).start()
                return
            self._send(404, {"error": "unknown"})
        except Exception as exc:                                            # pragma: no cover
            import traceback
            self._send(500, {"error": str(exc), "trace": traceback.format_exc()[-2000:]})


def _local(date_s: str, time_s: str = "07:00") -> dt.datetime:
    d = dt.date.fromisoformat(date_s)
    h, m = (int(x) for x in time_s.split(":")[:2])
    return dt.datetime(d.year, d.month, d.day, h, m).astimezone()        # local time zone, aware


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--control-port", type=int, default=8792)
    ap.add_argument("--token", required=True)
    ap.add_argument("--date", default=dt.date.today().isoformat())
    ap.add_argument("--time", default="07:00")
    ap.add_argument("--mode", choices=("personal", "server"), default="personal")
    ap.add_argument("--users-file", default="", help="server mode: users.json to install in the sandbox")
    a = ap.parse_args()

    users = None
    if a.mode == "server":
        users = json.loads(pathlib.Path(a.users_file).read_text(encoding="utf-8"))
    state = _prepare_home(pathlib.Path(a.home), a.mode, users)
    sys.path.insert(0, str(APP_ROOT))
    _block_outbound()

    import time_machine
    traveller = time_machine.travel(_local(a.date, a.time), tick=True)
    coords = traveller.start()
    _Control.traveller = coords

    import ai_prowler_mcp as mcp                                         # after the home/clock switch
    _patch_app(mcp)

    ctl = ThreadingHTTPServer(("127.0.0.1", a.control_port), _Control)
    _Control.stop_cb = lambda: os._exit(0)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    print(f"TIME MACHINE ready ({a.mode} mode, server_mode={mcp._IS_SERVER_MODE}): app http://127.0.0.1:{a.port}/jobs/"
          f"  control :{a.control_port}  sandbox {state}  today {dt.date.today()}", flush=True)
    if a.mode == "server":
        assert mcp._IS_SERVER_MODE, "server mode requested but the app didn't come up in server mode"
        mcp._run_server_mode(port=a.port, token=a.token, public_base=f"http://127.0.0.1:{a.port}")
    else:
        mcp._run_http(port=a.port, token=a.token, public_base=f"http://127.0.0.1:{a.port}")


if __name__ == "__main__":
    main()

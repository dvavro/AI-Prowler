"""AGENTS sandbox server (AGENTS_GUI_E2E_TEST_SPEC.md §1.1) — a throwaway AI-Prowler for the agents GUI suite.

Built on tests\\gui_jobs_timemachine\\tm_server.py (its sandbox home, outbox, outbound block, app patches and
moving clock are reused, not copied). Added here:
  * the stand-in AI (ai_standin.py) in place of desk_agent_providers._post — every agent AI call is
    answered and logged in-process; nothing reaches api.anthropic.com or api.x.ai (the outbound block
    catches anything that tries);
  * fake agent keys and the agent models saved in the sandbox, so the Claude API and Grok runners work;
  * agent runs are synchronous: desk_agent.run_in_background runs the pass on the calling thread, so a
    test knows the pass is over when /run returns;
  * HR apps switched on (server mode).

Started by conftest.py:
    python ag_server.py --home <empty dir> --port P --control-port C --token=<owner token>
                        --date 2026-11-09 [--mode server --users-file users.json]

Control API (127.0.0.1:<control-port>, JSON) — everything tm_server.py has, plus:
    POST /run {"job": "agents", "force": false}   one agent pass at the simulated time (Service Desk tick →
                                                   scans + runs; Jobs and HR ticks); force = Run now
    POST /chat-run {}                               play the chat runner: take every waiting item and answer it
    GET  /ai-calls                                  every request the stand-in AI got
    POST /ai-script {"name": "good", "rules": {}}   choose the stand-in's answers
    POST /ai-reset {"name": "good"}                 clear the log and choose the script
    GET  /agent-db                                  queue / proposals / runs in all three agent databases
    POST /settings {"desk": {...}, "jobs": {...}, "hr": {...}}   set agent settings in-process (fast setup)
    POST /tool {"name": "create_job", "args": {...}}  one of the app's MCP tools, as the owner at the PC (seed data)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sqlite3
import sys
import threading
from http.server import ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
TM_DIR = HERE.parent / "gui_jobs_timemachine"
for p in (str(TM_DIR), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import tm_server as tm  # noqa: E402
import ai_standin  # noqa: E402

FAKE_KEYS = {"claude_api": "sk-ant-ZAG-standin-not-a-real-key", "grok_api": "xai-ZAG-standin-not-a-real-key"}
MAIN_MODEL, LIGHT_MODEL = "claude-sonnet-5-5", "claude-haiku-5-5"
RUNS: list = []
_EDITION = {"v": "solo"}


def _prepare_agents(state: pathlib.Path, mode: str) -> None:
    """HR apps on (server); the rest of the sandbox is tm_server's."""
    tc = state / "tool_config.json"
    cfg = json.loads(tc.read_text(encoding="utf-8")) if tc.exists() else {"schema_version": 1}
    cfg["hr_apps_enabled"] = True
    tc.write_text(json.dumps(cfg), encoding="utf-8")


def _no_sms(state: pathlib.Path) -> None:
    """David's setup on 4 Nov: email configured, SMS never set up and the SMS & WhatsApp group switched off."""
    p = state / "config.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    for k in [k for k in cfg if k.startswith(("sms_", "twilio_"))]:
        del cfg[k]
    p.write_text(json.dumps(cfg), encoding="utf-8")
    tc = state / "tool_config.json"
    t = json.loads(tc.read_text(encoding="utf-8")) if tc.exists() else {"schema_version": 1}
    t["personal"] = {"disabled_tools": ["check_sms_configured", "check_sms_inbox", "check_whatsapp_replies",
                                        "delete_sms_consent", "get_sms_thread", "list_sms_consents",
                                        "list_sms_contacts_with_replies", "send_sms", "send_whatsapp"]}
    t["optional_groups"] = {"personal": {"job_tracker": True, "sms_whatsapp": False, "service_desk": True}}
    tc.write_text(json.dumps(t), encoding="utf-8")


def _install_agents(mcp) -> None:
    import desk_agent
    import desk_agent_providers as prov
    ai_standin.install()
    for provider, key in FAKE_KEYS.items():
        prov.store_agent_key(key, provider)
    prov.set_agent_model("claude_api", MAIN_MODEL)
    prov.set_light_model(LIGHT_MODEL)
    grok = [m for m, _ in prov.AGENT_MODELS.get("grok_api", ())]
    if grok:
        prov.set_agent_model("grok_api", grok[0])
    orig_run = desk_agent.run

    def _run_now(db, *, edition, business="", jobs_db=None, force=False):     # synchronous for the tests
        res = orig_run(db, edition=edition, business=business, jobs_db=jobs_db, force=force)
        RUNS.append(dict(res, db=str(db)))
        return True

    desk_agent.run_in_background = _run_now
    for wire in ("_jobs_agent_wire", "_hr_agent_wire"):
        fn = getattr(mcp, wire, None)
        if fn:
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                print(f"[ag_server] {wire} failed: {e}", flush=True)


def _dbs(mcp) -> dict:
    import desk_agent_hr_store
    import desk_agent_store
    out = {"tickets": None, "jobs_agent": None, "hr_agent": None}
    try:
        out["tickets"] = mcp._desk_db_path()
    except Exception:  # noqa: BLE001
        pass
    for k, mod in (("jobs_agent", desk_agent_store), ("hr_agent", desk_agent_hr_store)):
        try:
            p = mod.path()
            out[k] = p if pathlib.Path(p).exists() else None
        except Exception:  # noqa: BLE001
            pass
    return out


def _snapshot(path) -> dict:
    if not path or not pathlib.Path(path).exists():
        return {}
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    out = {}
    try:
        for t in ("agent_queue", "agent_proposals", "agent_runs"):
            try:
                rows = [dict(r) for r in con.execute(f"SELECT * FROM {t} ORDER BY rowid DESC LIMIT 60")]
            except sqlite3.Error:
                rows = []
            out[t] = rows
    finally:
        con.close()
    return out


def agents_pass(mcp, force: bool = False) -> dict:
    """One agent pass at the simulated time, the way the app's timers do it."""
    import desk_scheduler
    RUNS.clear()
    for k in ("_jobs_last", "_hr_last"):                      # their 5 / 15-minute scan throttles
        d = getattr(desk_scheduler, k, None)
        if isinstance(d, dict):
            d["scan"] = None
    did = tm._desk_tick(mcp)
    edition = tm.DESK_SCHEDULER["get_edition"]() if tm.DESK_SCHEDULER else _EDITION["v"]
    if "skipped" in did:                                      # Service Desk off: the Jobs / HR timers still run
        did = {"skipped": did["skipped"], **desk_scheduler.jobs_agent_tick(None, edition=edition),
               **desk_scheduler.hr_agent_tick(None, edition=edition)}
    if force:
        import desk_agent
        for name, db in _dbs(mcp).items():
            if db:
                RUNS.append(dict(desk_agent.run(db, edition=edition, force=True), db=str(db), forced=name))
    return {"did": did, "runs": list(RUNS), "now": dt.datetime.now().isoformat(timespec="seconds")}


def set_settings(mcp, body: dict) -> dict:
    """Agent settings straight into the sandbox (fast test setup — the GUI tests set them through the GUI)."""
    import desk_agent_hr_store
    import desk_agent_store
    import desk_db
    edition = tm.DESK_SCHEDULER["get_edition"]() if tm.DESK_SCHEDULER else _EDITION["v"]
    dbs = _dbs(mcp)
    out = {}
    for k, v in (body.get("desk") or {}).items():
        desk_db.set_setting(dbs["tickets"], k, v, edition=edition)
    if body.get("jobs"):
        adb = desk_agent_store.init()
        for k, v in body["jobs"].items():
            desk_agent_store.set_setting(k, v, actor={"id": "owner", "role": "owner"}, edition="solo", db=adb)
        desk_agent_store.sync_shared(dbs["tickets"], adb)
        out["jobs"] = desk_agent_store.settings(adb)
    if body.get("hr"):
        hdb = desk_agent_hr_store.init()
        for k, v in body["hr"].items():
            desk_agent_hr_store.set_setting(k, v, edition="solo", db=hdb)
        desk_agent_hr_store.sync_shared(dbs["tickets"], hdb)
        out["hr"] = desk_agent_hr_store.settings(hdb)
    out["desk"] = {k: v for k, v in desk_db.get_settings(dbs["tickets"]).items() if k.startswith("agent_")}
    # what's stored now, for the tests to read back (an empty body only reads)
    out.setdefault("jobs", desk_agent_store.settings(desk_agent_store.init()))
    try:
        out.setdefault("hr", desk_agent_hr_store.settings(desk_agent_hr_store.init()))
    except Exception as e:  # noqa: BLE001 — HR may not be set up in this sandbox
        out.setdefault("hr", {"error": str(e)})
    return out


class _AgControl(tm._Control):
    MINE_GET = ("/ai-calls", "/agent-db")
    MINE_POST = ("/ai-script", "/ai-reset", "/settings", "/tool", "/probe-net", "/weather", "/desk-off", "/pay-stub", "/hr-clock-in", "/no-runner", "/sub-link", "/integrity", "/no-key")

    def do_GET(self):
        if self.path == "/ai-calls":
            return self._send(200, ai_standin.calls())
        if self.path == "/agent-db":
            return self._send(200, {k: _snapshot(v) for k, v in _dbs(_AgControl.mcp).items()})
        return super().do_GET()

    def do_POST(self):
        mine = self.path in self.MINE_POST
        if self.path == "/run":                               # peek: ours only for {"job": "agents"}
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) or b"{}"
            b = json.loads(raw)
            if b.get("job") != "agents":
                self.rfile = __import__("io").BytesIO(raw)    # hand the body back to tm_server's handler
                return super().do_POST()
            try:
                return self._send(200, agents_pass(_AgControl.mcp, bool(b.get("force"))))
            except Exception as exc:  # noqa: BLE001
                import traceback
                return self._send(500, {"error": str(exc), "trace": traceback.format_exc()[-2000:]})
        if not mine:
            return super().do_POST()
        try:
            b = self._body()
            if self.path == "/ai-script":
                ai_standin.set_script(b.get("name", "good"), b.get("rules"))
                return self._send(200, {"ok": True, "script": ai_standin.SCRIPT})
            if self.path == "/ai-reset":
                ai_standin.reset(b.get("name", "good"), b.get("rules"))
                return self._send(200, {"ok": True})
            if self.path == "/settings":
                return self._send(200, set_settings(_AgControl.mcp, b))
            if self.path == "/pay-stub":                       # a stand-in checkout link; never real Stripe or Square
                import desk_portal
                if b.get("on"):
                    desk_portal.checkout_ready_fn = lambda: True
                    desk_portal.checkout_fn = lambda amount, what, ref, back: f"/support/?zagpaid={ref}&amount={amount}"
                else:
                    desk_portal.checkout_ready_fn = desk_portal.checkout_fn = None
                return self._send(200, {"ok": True})
            if self.path == "/no-key":                         # as if no agent API key were saved
                import desk_agent_providers as prov
                if not hasattr(prov, "_real_key"):
                    prov._real_key = prov._key
                prov._key = (lambda p: "") if b.get("on") else prov._real_key
                return self._send(200, {"ok": True})
            if self.path == "/sub-link":                       # a subcontractor's status link
                import desk_db
                import desk_portal
                dbs = _dbs(_AgControl.mcp)
                edition = tm.DESK_SCHEDULER["get_edition"]() if tm.DESK_SCHEDULER else _EDITION["v"]
                c = desk_db.upsert_contact(dbs["tickets"], name=b["name"], phone=b["phone"], contact_type="subcontractor")
                t = desk_db.create_ticket(dbs["tickets"], title="ZAG drywall", kind="subcontractor", contact_id=c["contact_id"], edition=edition)
                return self._send(200, {"token": desk_portal.issue_link(dbs["tickets"], t["ticket_id"], c["contact_id"]), "ticket_id": t["ticket_id"]})
            if self.path == "/integrity":                      # AG-SAFE-05: every database still whole
                import sqlite3
                out = {}
                for name, path in _dbs(_AgControl.mcp).items():
                    if path and pathlib.Path(path).exists():
                        conn = sqlite3.connect(path)
                        out[name] = conn.execute("PRAGMA integrity_check").fetchone()[0]
                        conn.close()
                return self._send(200, out)
            if self.path == "/no-runner":                      # no AI chosen: can't be saved any more, so set it directly
                import desk_db
                dbs = _dbs(_AgControl.mcp)
                edition = tm.DESK_SCHEDULER["get_edition"]() if tm.DESK_SCHEDULER else _EDITION["v"]
                desk_db.set_setting(dbs["tickets"], "agent_provider", "claude_api", edition=edition)
                conn = desk_db.get_connection(dbs["tickets"])
                try:
                    conn.execute("UPDATE desk_settings SET value = ? WHERE key = 'agent_provider'", (json.dumps(b.get("value") or "chat_only"),))
                    conn.commit()
                finally:
                    conn.close()
                return self._send(200, {"ok": True})
            if self.path == "/hr-clock-in":                    # an employee left clocked in; signing in as them isn't the point here
                m = _AgControl.mcp
                with m._hr_db_lock:
                    db = m._hr_load_db()
                    db.setdefault("time_entries", []).append({"id": b["id"], "employee_id": b["employee_id"], "clock_in": b["clock_in"], "clock_out": None})
                    m._hr_save_db(db)
                return self._send(200, {"ok": True})
            if self.path == "/desk-off":                       # the owner unticked the Service Desk group
                off = set(_AgControl.mcp._USER_DISABLED_TOOLS)
                (off.add if b.get("off") else off.discard)("list_tickets")
                _AgControl.mcp._USER_DISABLED_TOOLS = frozenset(off)
                return self._send(200, {"off": _AgControl.mcp._desk_app_turned_off()})
            if self.path == "/weather":                        # a stand-in forecast; {} goes back to none (blocked)
                import desk_agent_evidence as ev
                ev._CACHE.clear()
                if "rain" in b:
                    rain, wind = int(b["rain"]), int(b.get("wind", 5))

                    def fake(lat, lon, date):
                        hours = [f"{date}T{h:02d}:00" for h in range(24)]
                        return {"hourly": {"time": hours, "precipitation_probability": [rain] * 24, "wind_speed_10m": [wind] * 24}}
                    ev.fetch = fake
                else:
                    ev.fetch = None
                return self._send(200, {"ok": True})
            if self.path == "/probe-net":                      # AG-ENV-03: both ways out must be blocked
                out = {}
                import urllib.request
                try:
                    urllib.request.urlopen("https://api.anthropic.com/v1/messages", timeout=5)
                    out["urllib"] = "REACHED"
                except Exception as e:  # noqa: BLE001
                    out["urllib"] = f"blocked: {e}"
                try:
                    import requests
                    requests.get("https://api.x.ai/v1/models", timeout=5)
                    out["requests"] = "REACHED"
                except Exception as e:  # noqa: BLE001
                    out["requests"] = f"blocked: {e}"
                return self._send(200, out)
            if self.path == "/tool":                          # the app's own MCP tool, as the owner at the PC
                fn = getattr(_AgControl.mcp, str(b.get("name") or ""), None)
                if not callable(fn):
                    return self._send(404, {"error": f"no tool {b.get('name')!r}"})
                return self._send(200, {"result": fn(**(b.get("args") or {}))})
        except Exception as exc:  # noqa: BLE001
            import traceback
            return self._send(500, {"error": str(exc), "trace": traceback.format_exc()[-2000:]})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--control-port", type=int, required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--date", required=True)
    ap.add_argument("--time", default="09:00")
    ap.add_argument("--mode", choices=("personal", "server"), default="personal")
    ap.add_argument("--users-file", default="")
    ap.add_argument("--no-sms", action="store_true", help="a personal install with email set up and SMS not")
    a = ap.parse_args()

    users = json.loads(pathlib.Path(a.users_file).read_text(encoding="utf-8")) if a.mode == "server" else None
    state = tm._prepare_home(pathlib.Path(a.home), a.mode, users)
    _prepare_agents(state, a.mode)
    if a.no_sms:
        _no_sms(state)
    _EDITION["v"] = "business" if a.mode == "server" else "solo"
    sys.path.insert(0, str(tm.APP_ROOT))
    tm._block_outbound()

    import time_machine
    traveller = time_machine.travel(tm._local(a.date, a.time), tick=True)
    tm._Control.traveller = _AgControl.traveller = traveller.start()

    import ai_prowler_mcp as mcp                                         # after the home/clock switch
    tm._patch_app(mcp)
    _install_agents(mcp)
    tm._Control.mcp = _AgControl.mcp = mcp

    ctl = ThreadingHTTPServer(("127.0.0.1", a.control_port), _AgControl)
    tm._Control.stop_cb = _AgControl.stop_cb = lambda: os._exit(0)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    print(f"AGENTS SANDBOX ready ({a.mode}, server_mode={mcp._IS_SERVER_MODE}): app http://127.0.0.1:{a.port}/  "
          f"control :{a.control_port}  sandbox {state}  now {dt.datetime.now():%Y-%m-%d %H:%M}", flush=True)
    if a.mode == "server":
        assert mcp._IS_SERVER_MODE, "server mode requested but the app didn't come up in server mode"
        mcp._run_server_mode(port=a.port, token=a.token, public_base=f"http://127.0.0.1:{a.port}")
    else:
        mcp._run_http(port=a.port, token=a.token, public_base=f"http://127.0.0.1:{a.port}")


if __name__ == "__main__":
    main()

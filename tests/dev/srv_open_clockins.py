"""Read-only (2026-10-03): open clock-ins on the AI-Prowler SERVER.

SRV-SCR-07 timed out because David's Clock In button was disabled: the Jobs
app found an OPEN TimeLog entry (no Clock Out) in his name on the server. This
lists every open entry — who, which job, since when, and whether the job is
ZTEST test data or a real job. Signs in as the owner exactly like the server
E2E suite does; never prints a token; changes nothing.

  python tests\\dev\\srv_open_clockins.py
"""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
for p in (HERE / "gui_jobs_e2e", HERE / "gui_jobs_e2e_server"):
    sys.path.insert(0, str(p))
from api import http, origin_of, parse_records          # noqa: E402
from srv_helpers import srv_login                       # noqa: E402


def user_env(name):
    v = os.environ.get(name, "")
    if v:
        return v
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
        return str(winreg.QueryValueEx(k, name)[0])


cfg = json.loads((HERE / "gui_jobs_e2e_server" / "users.local.json").read_text(encoding="utf-8"))
origin = origin_of(user_env(cfg.get("url_env", "AIPROWLER_SRV_URL")).strip())
owner = next(u for u in cfg["users"] if u["key"] == "U1")
st, reply = srv_login(origin, owner["name"], user_env(owner["token_env"]))
access = reply.get("access_token") or reply.get("token") or reply.get("session_token")
if st != 200 or not access:
    sys.exit(f"sign-in as {owner['name']} failed (HTTP {st}): {list(reply)}")


def read(sheet):
    s, raw = http("POST", origin + "/pwa-api",
                  {"tool": "read_job_spreadsheet", "args": {"sheet_name": sheet, "max_rows": 2000}},
                  token=access)
    data = json.loads(raw)
    if not data.get("ok"):
        sys.exit(f"read {sheet} failed: {data.get('error')}")
    return parse_records(data.get("result", ""))


jobs = {str(j.get("JobID (JOB-####)") or j.get("JobID")): j for j in read("Jobs_Schedule")}
log = read("TimeLog")
open_rows = [r for r in log if str(r.get("Clock In") or "").strip() and not str(r.get("Clock Out") or "").strip()]
print(f"server: {origin}   TimeLog rows: {len(log)}   OPEN (no Clock Out): {len(open_rows)}\n")
for r in sorted(open_rows, key=lambda r: str(r.get("Clock In"))):
    jid = str(r.get("JobID (JOB-####)") or r.get("JobID") or "")
    job = jobs.get(jid)
    who = r.get("Crew / Technician") or "?"
    if job is None:
        what = "job NOT FOUND (deleted)"
    else:
        name = str(job.get("Customer Name / Company") or "")
        what = ("ZTEST test job" if name.startswith("ZTEST") else "REAL job") + f" — {name} ({job.get('Job Status')})"
    print(f"  {who:<18} {jid:<9} clocked in {r.get('Clock In')}   {what}")
if not open_rows:
    print("  none")

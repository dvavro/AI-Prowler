"""🗓️ Plan Week (2026-10-22, David) — suggest moving SOFT jobs so jobs near each
other are done on the same day, instead of driving back to the same area twice
in one week.

How it's used: the Jobs app's "🗓️ Plan Week" button copies a prompt (made by
ai_prowler_mcp.get_week_plan_prompt) that the user pastes into ANY AI chat with
this AI-Prowler connected. The AI reads the week (week_data), reasons about it,
and PROPOSES moves (validate_moves + save_proposal). Nothing changes until the
user approves the proposal in the Jobs app (apply_moves). After that each day
is routed as usual (Route, or 📋 Copy AI Route).

The rules every proposed move must pass (checked here, never left to the AI):
  * only SOFT jobs move — hard jobs stay exactly where they are;
  * not finished / cancelled / in progress / paused, single-day jobs only;
  * only to a day in the SAME week that is a Working Day, not in the past,
    and one of the job's Preferred Day(s) (the job's own, else its
    customer's) when it has any;
  * the date only — the job keeps its own time window.

"Near" = within the 'Week Plan Distance (miles)' setting (default 5).
"""
from __future__ import annotations

import datetime as _dt
import json
import math
import os
import threading
from pathlib import Path

from db_write_ops import (
    db_read_settings_lunch_break_duration_min, db_read_settings_workday_end,
    db_read_settings_workday_start, db_update_job, get_connection,
    parse_preferred_days, working_days,
)

WEEK_PLAN_MILES_KEY = "Week Plan Distance (miles)"
DEFAULT_WEEK_PLAN_MILES = 5.0
_CLOSED = {"complete", "completed", "cancelled", "canceled"}
_DAY = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_LOCK = threading.Lock()


# ── settings / dates ─────────────────────────────────────────────────────────
def read_week_plan_miles(db_path: str) -> float:
    """The 'Week Plan Distance (miles)' setting; 5 when missing or not a
    number. Kept between 0.1 and 100 so a typo can't make it meaningless."""
    try:
        conn = get_connection(db_path)
        try:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (WEEK_PLAN_MILES_KEY,)).fetchone()
        finally:
            conn.close()
        v = float(str(row["value"]).strip()) if row and str(row["value"] or "").strip() else DEFAULT_WEEK_PLAN_MILES
    except Exception:
        v = DEFAULT_WEEK_PLAN_MILES
    if not v or v != v:            # 0 / NaN
        v = DEFAULT_WEEK_PLAN_MILES
    return max(0.1, min(100.0, v))


def monday_of(d: _dt.date) -> _dt.date:
    return d - _dt.timedelta(days=d.weekday())


def parse_iso(s) -> "_dt.date | None":
    s = str(s or "").strip()
    if len(s) == 10 and s[2] == "/" and s[5] == "/":          # MM/DD/YYYY
        s = f"{s[6:]}-{s[:2]}-{s[3:5]}"
    try:
        return _dt.date.fromisoformat(s[:10])
    except ValueError:
        return None


def _minutes(hhmm: str, fallback: int) -> int:
    try:
        h, m = str(hhmm).strip().split(":")[:2]
        return int(h) * 60 + int(m)
    except Exception:
        return fallback


def miles_between(a_lat, a_lon, b_lat, b_lon) -> float:
    r = 3958.8
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp, dl = p2 - p1, math.radians(b_lon - a_lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


# ── the week's jobs ──────────────────────────────────────────────────────────
def _duration_min(row) -> int:
    try:
        v = float(str(row.get("est_duration") or "").strip() or 0)
    except ValueError:
        v = 0.0
    unit = str(row.get("est_duration_unit") or "min").strip().lower()
    if unit.startswith("h"):
        v *= 60
    elif unit.startswith("d"):
        v *= 8 * 60
    return int(round(v))


def _float(v):
    try:
        f = float(str(v).strip())
        return f if f == f else None
    except Exception:
        return None


def load_week(db_path: str, monday: _dt.date, crew: str = "") -> list:
    """Every job dated in monday..sunday (for `crew`, when given), with the
    customer's Preferred Day(s) alongside. Plain dicts."""
    sunday = monday + _dt.timedelta(days=6)
    conn = get_connection(db_path)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(customers)").fetchall()}
        cust_pref = "c.preferred_days" if "preferred_days" in cols else "''"
        rows = conn.execute(
            f"SELECT j.*, {cust_pref} AS cust_preferred_days FROM jobs j "
            "LEFT JOIN customers c ON c.customer_id = j.customer_id "
            "WHERE j.service_date >= ? AND j.service_date <= ? "
            "ORDER BY j.service_date, j.start_time, j.job_id",
            (monday.isoformat(), sunday.isoformat())).fetchall()
    finally:
        conn.close()
    want = (crew or "").strip().casefold()
    out = []
    for r in rows:
        r = dict(r)
        if want and str(r.get("crew") or "").strip().casefold() != want:
            continue
        d = parse_iso(r.get("service_date"))
        if d is None:
            continue
        end = parse_iso(r.get("end_date"))
        out.append({
            "job_id": str(r.get("job_id") or ""),
            "customer": str(r.get("customer_name") or ""),
            "address": ", ".join(p for p in (str(r.get("street_address") or "").strip(),
                                             str(r.get("city") or "").strip()) if p),
            "lat": _float(r.get("latitude")), "lon": _float(r.get("longitude")),
            "date": d.isoformat(),
            "start_time": str(r.get("start_time") or ""), "end_time": str(r.get("end_time") or ""),
            "schedule_type": "hard" if str(r.get("schedule_type") or "").strip().lower() == "hard" else "soft",
            "duration_min": _duration_min(r),
            "status": str(r.get("job_status") or ""),
            "paused": str(r.get("paused") or "").strip().lower() in ("1", "true", "yes", "y"),
            "multi_day": bool(end and end != d) or str(r.get("est_duration_unit") or "").strip().lower().startswith("d"),
            "preferred_days": str(r.get("preferred_days") or "").strip() or str(r.get("cust_preferred_days") or "").strip(),
            "crew": str(r.get("crew") or ""),
        })
    return out


def why_not_movable(job: dict, today: _dt.date) -> str:
    """'' when the job may be moved, else the reason it may not."""
    if job["schedule_type"] == "hard":
        return "hard (committed) time — never moved"
    st = job["status"].strip().lower()
    if st in _CLOSED:
        return f"already {job['status']}"
    if st == "in progress":
        return "in progress"
    if job["paused"]:
        return "paused"
    if job["multi_day"]:
        return "multi-day job"
    if parse_iso(job["date"]) < today:
        return "in the past"
    return ""


def allowed_days(job: dict, monday: _dt.date, wdays, today: _dt.date) -> list:
    """The ISO dates this week the job may sit on (its own date included when
    it qualifies): working days, not in the past, and its Preferred Day(s)."""
    pref = parse_preferred_days(job.get("preferred_days"))
    days = []
    for i in range(7):
        d = monday + _dt.timedelta(days=i)
        if d < today or d.weekday() not in wdays:
            continue
        if pref and d.weekday() not in pref:
            continue
        days.append(d.isoformat())
    return days


def day_minutes(jobs: list) -> dict:
    """Booked job minutes per date (open jobs only)."""
    out = {}
    for j in jobs:
        if j["status"].strip().lower() in _CLOSED:
            continue
        out[j["date"]] = out.get(j["date"], 0) + j["duration_min"]
    return out


def nearby_pairs(jobs: list, miles: float, today: _dt.date) -> list:
    """Jobs on DIFFERENT days within `miles` of each other, where at least one
    of the two could move — the trips worth combining. Closest first."""
    pairs = []
    for i, a in enumerate(jobs):
        for b in jobs[i + 1:]:
            if a["date"] == b["date"] or None in (a["lat"], a["lon"], b["lat"], b["lon"]):
                continue
            if why_not_movable(a, today) and why_not_movable(b, today):
                continue
            d = miles_between(a["lat"], a["lon"], b["lat"], b["lon"])
            if d <= miles:
                pairs.append({"a": a["job_id"], "a_date": a["date"], "b": b["job_id"],
                              "b_date": b["date"], "miles": round(d, 1)})
    return sorted(pairs, key=lambda p: p["miles"])


def week_data(db_path: str, monday: _dt.date, crew: str, today: _dt.date) -> dict:
    """Everything the AI needs to propose moves, in one structure."""
    jobs = load_week(db_path, monday, crew)
    wdays = working_days(db_path)
    miles = read_week_plan_miles(db_path)
    ws = db_read_settings_workday_start(db_path)
    we = db_read_settings_workday_end(db_path)
    lunch = db_read_settings_lunch_break_duration_min(db_path)
    for j in jobs:
        reason = why_not_movable(j, today)
        j["movable"] = not reason
        j["not_movable_because"] = reason
        j["may_move_to"] = allowed_days(j, monday, wdays, today) if not reason else []
    return {
        "week": [monday.isoformat(), (monday + _dt.timedelta(days=6)).isoformat()],
        "today": today.isoformat(),
        "crew": crew,
        "working_days": [_DAY[i] for i in sorted(wdays)],
        "workday": {"start": ws, "end": we, "lunch_min": lunch,
                    "job_minutes_available": max(0, _minutes(we, 1020) - _minutes(ws, 420) - int(lunch or 0))},
        "nearby_miles": miles,
        "booked_job_minutes_by_day": day_minutes(jobs),
        "jobs": jobs,
        "nearby_pairs": nearby_pairs(jobs, miles, today),
    }


# ── checking a proposal ──────────────────────────────────────────────────────
def parse_moves(moves) -> list:
    """moves: a JSON list (or its text) of {"job_id", "to", "reason"}."""
    if isinstance(moves, str):
        moves = json.loads(moves.strip() or "[]")
    if isinstance(moves, dict):
        moves = moves.get("moves", [])
    if not isinstance(moves, list):
        raise ValueError("moves must be a list")
    out = []
    for m in moves:
        if not isinstance(m, dict):
            raise ValueError("each move must be an object with job_id and to")
        out.append({"job_id": str(m.get("job_id") or "").strip().upper(),
                    "to": str(m.get("to") or m.get("new_date") or "").strip(),
                    "reason": str(m.get("reason") or "").strip()[:300]})
    return out


def validate_moves(db_path: str, monday: _dt.date, crew: str, moves: list, today: _dt.date):
    """Returns (accepted, rejected, warnings). Each accepted move carries
    job_id, customer, from, to, reason. Nothing is written."""
    jobs = {j["job_id"]: j for j in load_week(db_path, monday, crew)}
    wdays = working_days(db_path)
    accepted, rejected, seen = [], [], set()
    for m in moves:
        jid, to = m["job_id"], parse_iso(m["to"])
        j = jobs.get(jid)
        if j is None:
            rejected.append((jid or "(blank)", "not one of this week's jobs" + (f" for crew '{crew}'" if crew else "")))
            continue
        if jid in seen:
            rejected.append((jid, "listed twice"))
            continue
        why = why_not_movable(j, today)
        if why:
            rejected.append((jid, f"can't be moved: {why}"))
            continue
        if to is None:
            rejected.append((jid, f"'{m['to']}' isn't a date like 2026-10-23"))
            continue
        if to.isoformat() == j["date"]:
            rejected.append((jid, "already on that day"))
            continue
        ok_days = allowed_days(j, monday, wdays, today)
        if to.isoformat() not in ok_days:
            rejected.append((jid, f"{to.isoformat()} isn't allowed — it may move to: "
                                  + (", ".join(ok_days) or "no other day this week")))
            continue
        seen.add(jid)
        accepted.append({"job_id": jid, "customer": j["customer"], "address": j["address"],
                         "from": j["date"], "to": to.isoformat(), "reason": m["reason"]})
    # A day that would hold more job time than the workday allows is a warning
    # (driving time isn't known here) — the user decides.
    warnings = []
    load = day_minutes(list(jobs.values()))
    for a in accepted:
        load[a["from"]] = load.get(a["from"], 0) - jobs[a["job_id"]]["duration_min"]
        load[a["to"]] = load.get(a["to"], 0) + jobs[a["job_id"]]["duration_min"]
    ws, we = db_read_settings_workday_start(db_path), db_read_settings_workday_end(db_path)
    avail = max(0, _minutes(we, 1020) - _minutes(ws, 420) - int(db_read_settings_lunch_break_duration_min(db_path) or 0))
    for d in sorted({a["to"] for a in accepted}):
        if avail and load.get(d, 0) > avail:
            warnings.append(f"{d} would have {load[d] / 60:.1f} h of jobs — more than the "
                            f"{avail / 60:.1f} h workday (before driving)")
    return accepted, rejected, warnings


# ── proposals (suggestions waiting for the user) ────────────────────────────
def _load(path: Path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _save(path: Path, data: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def save_proposal(path, code: str, week_start: str, crew: str, moves: list, warnings: list, summary: str) -> dict:
    import time as _t
    with _LOCK:
        data = _load(path)
        # keep the file small: drop anything older than 30 days
        cutoff = _t.time() - 30 * 86400
        data = {k: v for k, v in data.items() if float(v.get("made_at") or 0) >= cutoff}
        data[code] = {"code": code, "week_start": week_start, "crew": crew, "moves": moves,
                      "warnings": warnings, "summary": summary[:1000], "made_at": _t.time(),
                      "status": "pending"}
        _save(path, data)
        return data[code]


def get_proposal(path, code: str) -> "dict | None":
    with _LOCK:
        return _load(path).get((code or "").strip().upper())


def latest_pending(path, week_start: str, crew: str) -> "dict | None":
    with _LOCK:
        props = [p for p in _load(path).values()
                 if p.get("status") == "pending" and p.get("week_start") == week_start
                 and (p.get("crew") or "").casefold() == (crew or "").casefold()]
    return max(props, key=lambda p: p.get("made_at") or 0) if props else None


def set_status(path, code: str, status: str, applied: "list | None" = None) -> None:
    with _LOCK:
        data = _load(path)
        p = data.get(code)
        if p is not None:
            p["status"] = status
            if applied is not None:
                p["applied"] = applied
            _save(path, data)


def apply_moves(db_path: str, proposal: dict, job_ids: list, actor: str, today: _dt.date,
                restrict: bool = False, crew_name: str = "") -> list:
    """Move the selected jobs of an approved proposal. Each one is re-checked
    first (the job may have changed since the AI looked). Returns
    [(job_id, ok, message)]."""
    monday = parse_iso(proposal["week_start"])
    wanted = {str(j).strip().upper() for j in job_ids if str(j).strip()}
    jobs = {j["job_id"]: j for j in load_week(db_path, monday, proposal.get("crew") or "")}
    wdays = working_days(db_path)
    out = []
    for m in proposal.get("moves", []):
        jid = m["job_id"]
        if jid not in wanted:
            continue
        j = jobs.get(jid)
        if j is None:
            out.append((jid, False, "no longer in this week — not moved"))
            continue
        if j["date"] != m["from"]:
            out.append((jid, False, f"was moved to {j['date']} since — not moved"))
            continue
        why = why_not_movable(j, today)
        if why:
            out.append((jid, False, f"can't be moved now: {why}"))
            continue
        if m["to"] not in allowed_days(j, monday, wdays, today):
            out.append((jid, False, f"{m['to']} is no longer allowed — not moved"))
            continue
        res = db_update_job(db_path, jid, {"Service Date": m["to"]}, actor,
                            restrict=restrict, crew_name=crew_name)
        ok = str(res).startswith("✅")
        out.append((jid, ok, f"{m['from']} → {m['to']}" if ok else str(res).splitlines()[0][:200]))
    return out

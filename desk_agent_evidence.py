"""
desk_agent_evidence.py — facts the booking agent works from, worked out in code so the AI
never has to fetch or guess them (booking-agent-spec §4 Keep on track / Learn, §5.4).

  weather(lat, lon, date, start, end)   Open-Meteo hourly forecast over the visit's window:
                                        the highest rain chance and wind, and whether it's
                                        bad enough to offer a new time (≥ 60 % rain or
                                        ≥ 25 mph wind). Free, no key. Cached an hour.
  time_on_site(jobs_db, code, minutes)  Real time on completed jobs of a service (the job
                                        timer, else the job's Actual Duration) against the
                                        service's "Takes" minutes; a pattern is ≥ 5 jobs and
                                        a median more than 20 % off.
"""
from __future__ import annotations

import datetime as dt
import json
import statistics
import time

RAIN_PCT = 60
WIND_MPH = 25
MIN_JOBS = 5
OFF_BY = 0.20
_CACHE: dict = {}
CACHE_SECONDS = 3600
fetch = None              # tests: fn(lat, lon, date) -> Open-Meteo-shaped dict; None = the real API


def _get(lat, lon, date):
    if fetch:
        return fetch(lat, lon, date)
    import urllib.parse
    import urllib.request
    q = urllib.parse.urlencode({"latitude": lat, "longitude": lon, "hourly": "precipitation_probability,wind_speed_10m",
                                "wind_speed_unit": "mph", "timezone": "auto", "start_date": date, "end_date": date})
    req = urllib.request.Request("https://api.open-meteo.com/v1/forecast?" + q,
                                 headers={"User-Agent": "AI-Prowler (booking weather check)"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def weather(lat, lon, date: str, start: str = "", end: str = "") -> dict:
    """{date, rain_pct, wind_mph, bad, why} for the hours start–end (HH:MM) of date, or
    {error} when there's no location or no forecast."""
    if lat is None or lon is None:
        return {"date": date, "error": "no map location for this address", "bad": False}
    key = (round(float(lat), 3), round(float(lon), 3), date, start, end)
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]
    try:
        data = _get(lat, lon, date)
        h = data.get("hourly") or {}
        times, rain, wind = h.get("time") or [], h.get("precipitation_probability") or [], h.get("wind_speed_10m") or []
        lo, hi = (start or "00:00"), (end or "23:59")
        pick = [i for i, t in enumerate(times) if str(t)[:10] == date and lo[:2] <= str(t)[11:13] <= hi[:2]]
        if not pick:
            raise ValueError("no forecast hours for that day")
        r = max((rain[i] or 0) for i in pick if i < len(rain)) if rain else 0
        w = max((wind[i] or 0) for i in pick if i < len(wind)) if wind else 0
    except Exception as e:  # noqa: BLE001
        out = {"date": date, "error": f"forecast unavailable: {e}"[:200], "bad": False}
        _CACHE[key] = (time.time(), out)
        return out
    bad = r >= RAIN_PCT or w >= WIND_MPH
    why = (f"{r:.0f}% chance of rain" + (f", wind up to {w:.0f} mph" if w else "")) + (
        "" if bad else f" — below the {RAIN_PCT}% / {WIND_MPH} mph line")
    out = {"date": date, "hours": f"{lo}–{hi}", "rain_pct": round(float(r)), "wind_mph": round(float(w)),
           "bad": bad, "why": why}
    _CACHE[key] = (time.time(), out)
    return out


def _minutes(value, unit) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    u = str(unit or "min").strip().lower()
    if u.startswith("h"):
        return v * 60
    if u.startswith("d"):
        return v * 60 * 8
    return v


def time_on_site(jobs_db: str, service_code: str, service_minutes: int | None, *, name: str = "",
                 limit: int = 30) -> dict:
    """Real time on site for this service's completed jobs, newest first."""
    from db_access import get_connection
    conn = get_connection(jobs_db)
    try:
        rows = conn.execute(
            "SELECT j.job_id, j.service_date, j.actual_duration, j.actual_duration_unit, "
            "(SELECT SUM(elapsed_min) FROM time_entries t WHERE t.job_id = j.job_id) AS timer_min "
            "FROM jobs j LEFT JOIN booking_requests r ON r.job_id = j.job_id "
            "WHERE LOWER(COALESCE(j.job_status, '')) IN ('complete', 'completed') AND "
            "(r.service_code = ? OR j.service_type IN (?, ?)) ORDER BY COALESCE(j.service_date, '') DESC LIMIT ?",
            (service_code, service_code, name or service_code, limit)).fetchall()
    finally:
        conn.close()
    jobs = []
    for r in rows:
        m = r["timer_min"] if r["timer_min"] else _minutes(r["actual_duration"], r["actual_duration_unit"])
        if m and 5 <= m <= 24 * 60:
            jobs.append({"job_id": r["job_id"], "date": r["service_date"], "minutes": round(m),
                         "from": "job timer" if r["timer_min"] else "actual duration"})
    out = {"service_code": service_code, "takes_minutes": service_minutes, "jobs": jobs, "n": len(jobs),
           "median_minutes": None, "pattern": False, "suggested_minutes": None, "min_jobs": MIN_JOBS,
           "off_by_pct": int(OFF_BY * 100)}
    if jobs:
        med = statistics.median(j["minutes"] for j in jobs)
        out["median_minutes"] = round(med)
        if service_minutes and len(jobs) >= MIN_JOBS and abs(med - service_minutes) > OFF_BY * service_minutes:
            out["pattern"] = True
            out["suggested_minutes"] = int(5 * round(med / 5))
    return out


def tomorrow(now: dt.datetime | None = None) -> str:
    return ((now or dt.datetime.now()).date() + dt.timedelta(days=1)).isoformat()

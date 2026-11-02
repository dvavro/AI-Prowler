"""
booking_slots.py — the availability engine for service booking (booking-spec.md §5).

Pure: no database, no clock of its own. booking_db.py gathers the inputs (the Jobs
app's working days and hours, lunch, the jobs on each day, holds, extra openings and
closed days, and — personal installs only — the business Google Calendar's busy
times) and calls open_windows().

Arrival windows (David 2026-10-30): the customer picks e.g. 8–10; the crew arrives
some time in that window and works the service's minutes (+ buffer). A window is
offered when at least one crew big enough for the service can START the work inside
the window without running into lunch, a fixed job, a held booking or a busy block,
AND still has enough free time that day once flexible (soft) jobs are counted.

Rules that apply:
  * working days and workday hours (Jobs Settings), plus extra openings / closed days
  * lunch break (Jobs Settings)
  * hard jobs, held bookings and busy blocks block their own times
  * soft jobs (no fixed time) use up time on their day but don't block an hour
  * lead time (nothing sooner than N hours), horizon (nothing later than N days)
  * max online bookings per day, full-day threshold (a day ≥ N % full shows nothing)
  * people needed (crews with fewer members can't take it)
Fairness: each window is given to the eligible crew with the most free time that day.
"""
from __future__ import annotations

import datetime as dt
import math
from dataclasses import dataclass

STEP = 15                      # minutes between possible start times inside a window
DAY = 24 * 60


# ── inputs ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rules:
    working_days: frozenset = frozenset(range(5))     # Mon=0 … Sun=6
    day_start: int = 7 * 60                           # minutes after midnight
    day_end: int = 17 * 60
    lunch_start: int | None = 12 * 60                 # None = no lunch break
    lunch_minutes: int = 60
    window_minutes: int = 120                         # arrival window length
    lead_hours: float = 24.0                          # nothing sooner than this
    horizon_days: int = 21                            # nothing later than this
    max_per_day: int = 0                              # online bookings per day; 0 = no limit
    full_pct: int = 85                                # a day this full shows no windows


@dataclass(frozen=True)
class Service:
    code: str
    minutes: int = 60
    people: int = 1
    buffer_min: int = 15

    @property
    def need(self) -> int:
        return int(self.minutes) + int(self.buffer_min)


@dataclass(frozen=True)
class Crew:
    crew_id: str
    size: int = 1


@dataclass(frozen=True)
class Booked:
    """Something already using a crew's time on one date.
    start=None -> flexible (a soft job): uses time on the day, blocks no particular hour.
    crew=None  -> everyone (a business-wide busy block, or an unassigned job — its
                  time is shared across the crews)."""
    date: dt.date
    minutes: int
    start: int | None = None
    end: int | None = None
    crew: str | None = None
    kind: str = "job"                                 # job | hold | busy
    online: bool = False                              # counts towards max_per_day


@dataclass(frozen=True)
class Opening:
    date: dt.date
    kind: str                                         # open | closed
    start: int | None = None                          # None = whole day / workday
    end: int | None = None
    crew: str | None = None                           # None = the whole business


@dataclass(frozen=True)
class Window:
    date: dt.date
    start: int
    end: int
    crew: str
    free_minutes: int                                 # the crew's free time left that day

    @property
    def key(self) -> str:
        return f"{self.date.isoformat()}T{fmt(self.start)}-{fmt(self.end)}"

    def label(self) -> str:
        return f"{self.date:%a %d %b}, {nice(self.start)}–{nice(self.end)}"


# ── small helpers (also used by booking_db) ─────────────────────────────────

def hhmm(s) -> int | None:
    """'07:00', '7:00', '07:00:00', '7:00 AM', '7am' -> minutes after midnight; None if blank/bad."""
    s = str(s or "").strip().upper().replace(".", "")
    if not s:
        return None
    pm = s.endswith("PM")
    am = s.endswith("AM")
    if am or pm:
        s = s[:-2].strip()
    parts = s.split(":")
    try:
        h = int(parts[0])
        m = int(parts[1]) if len(parts) > 1 and parts[1] else 0
    except ValueError:
        return None
    if am or pm:
        if not 1 <= h <= 12:
            return None
        h = (h % 12) + (12 if pm else 0)
    if not (0 <= h <= 24 and 0 <= m < 60) or h * 60 + m > DAY:
        return None
    return h * 60 + m


def fmt(m: int) -> str:
    return f"{m // 60:02d}:{m % 60:02d}"


def nice(m: int) -> str:
    """'8', '10:30', '1', '1:30' — 12-hour, no am/pm (windows read 8–10, 1–3)."""
    h, mm = divmod(int(m), 60)
    h12 = h % 12 or 12
    return f"{h12}" if not mm else f"{h12}:{mm:02d}"


def job_minutes(est, unit, rules: Rules, default: int = 60) -> int:
    """A job's working minutes from est_duration + est_duration_unit ('min' / 'hour' /
    'day', any case or plural). A day (or more) uses the whole workday."""
    try:
        n = float(est)
    except (TypeError, ValueError):
        return default
    if n <= 0:
        return default
    u = str(unit or "").strip().lower()
    if u.startswith("d"):
        return work_minutes([(rules.day_start, rules.day_end)], rules)
    if u.startswith("h"):
        return int(math.ceil(n * 60))
    if u.startswith("m"):
        return int(math.ceil(n))
    return int(math.ceil(n * 60)) if n <= 12 else int(math.ceil(n))   # unitless: small = hours


def _merge(iv: list) -> list:
    out = []
    for s, e in sorted(x for x in iv if x[1] > x[0]):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _cut(iv: list, s: int, e: int) -> list:
    out = []
    for a, b in iv:
        if e <= a or s >= b:
            out.append((a, b))
            continue
        if a < s:
            out.append((a, s))
        if e < b:
            out.append((e, b))
    return out


def work_minutes(iv: list, rules: Rules) -> int:
    if rules.lunch_start is not None and rules.lunch_minutes > 0:
        iv = _cut(iv, rules.lunch_start, rules.lunch_start + rules.lunch_minutes)
    return sum(b - a for a, b in iv)


def day_hours(d: dt.date, rules: Rules, openings=(), crew: str | None = None) -> list:
    """The hours a crew works on `d`: workday on working days, plus extra openings,
    minus closed days/hours (business-wide or for this crew)."""
    iv = [(rules.day_start, rules.day_end)] if d.weekday() in rules.working_days else []
    mine = [o for o in openings if o.date == d and (o.crew is None or o.crew == crew)]
    for o in mine:
        if o.kind == "open":
            iv.append((o.start if o.start is not None else rules.day_start,
                       o.end if o.end is not None else rules.day_end))
    iv = _merge(iv)
    for o in mine:
        if o.kind == "closed":
            iv = _cut(iv, o.start if o.start is not None else 0, o.end if o.end is not None else DAY)
    return iv


# ── the engine ───────────────────────────────────────────────────────────────

def _crew_day(d, crew: Crew, rules, openings, booked, n_crews):
    """(free intervals, free minutes, capacity) for one crew on one day."""
    hours = day_hours(d, rules, openings, crew.crew_id)
    capacity = work_minutes(hours, rules)
    if capacity <= 0:
        return [], 0, 0
    # Lunch is NOT cut out of the free time (Jobs Settings: "Not a stop … whichever job is
    # in progress at this time simply has its duration extended") — _fits() adds it to a
    # job that runs across it, and work_minutes() below still counts it against the day.
    free = hours
    flex = 0.0
    mine = [b for b in booked if b.date == d and (b.crew is None or b.crew == crew.crew_id)]
    windowed = []
    for b in mine:
        if b.start is not None and b.kind in WINDOWED and b.end is not None:
            windowed.append(b)                        # placed below, after the fixed blocks
        elif b.start is not None:                     # fixed: blocks its own time
            end = b.end if b.end is not None else b.start + int(b.minutes)
            free = _cut(free, b.start, max(end, b.start + int(b.minutes)))
        else:                                         # flexible: uses time on the day
            flex += b.minutes if b.crew is not None else b.minutes / max(1, n_crews)
    # Bookings with an arrival window (holds and visits booked online) are placed one after
    # another at the first free point inside their window — so two short visits share a
    # 2-hour window (7:00 and 8:15) instead of both "starting" at 7:00 (2026-10-30).
    for b in sorted(windowed, key=lambda x: (x.start, x.end)):
        s = _place(free, b.start, b.end, int(b.minutes), rules)
        if s is None:                                 # over-full window: still count its time
            s = b.start
        free = _cut(free, s, s + _with_lunch(s, int(b.minutes), rules))
    free_minutes = int(work_minutes(free, rules) - flex)
    return free, max(0, free_minutes), capacity


WINDOWED = ("hold", "window")                     # Booked kinds that may start anywhere in [start, end)


def _with_lunch(s: int, need: int, rules: Rules) -> int:
    ls = rules.lunch_start if rules.lunch_minutes > 0 else None
    return need + (rules.lunch_minutes if ls is not None and s < ls < s + need else 0)


def _place(free: list, w_start: int, w_end: int, need: int, rules: Rules) -> int | None:
    """The first start in [w_start, w_end) where the work finishes inside one free interval,
    or None. Nobody starts during lunch; work running across lunch takes that much longer
    (the Jobs app's lunch rule)."""
    ls = rules.lunch_start if rules.lunch_minutes > 0 else None
    le = ls + rules.lunch_minutes if ls is not None else None
    for a, b in free:
        s = max(a, w_start)
        s += (-(s - w_start)) % STEP                  # starts on the 15-minute grid from the window
        while s < w_end and s < b:
            if ls is not None and ls <= s < le:       # at lunch — try the next start
                s += STEP
                continue
            if s + _with_lunch(s, need, rules) <= b:
                return s
            s += STEP
    return None


def _fits(free: list, w_start: int, w_end: int, need: int, rules: Rules) -> bool:
    return _place(free, w_start, w_end, need, rules) is not None


def open_windows(service: Service, *, rules: Rules, now: dt.datetime, crews=(Crew("owner"),),
                 booked=(), openings=(), from_date: dt.date | None = None,
                 to_date: dt.date | None = None) -> list:
    """Every arrival window the service can be booked in, soonest first."""
    crews = [c for c in crews if c.size >= max(1, int(service.people))]
    if not crews:
        return []
    need = service.need
    earliest = now + dt.timedelta(hours=float(rules.lead_hours))
    first = max(from_date or now.date(), now.date())
    last = now.date() + dt.timedelta(days=int(rules.horizon_days))
    if to_date and to_date < last:
        last = to_date
    booked = list(booked)
    out = []
    d = first
    while d <= last:
        if rules.max_per_day and sum(1 for b in booked if b.date == d and b.online) >= rules.max_per_day:
            d += dt.timedelta(days=1)
            continue
        per_crew = {}
        for c in crews:
            free, free_min, cap = _crew_day(d, c, rules, openings, booked, len(crews))
            if cap <= 0 or free_min < need:
                continue
            if (cap - free_min) * 100 >= rules.full_pct * cap:      # day too full
                continue
            per_crew[c.crew_id] = (free, free_min)
        if per_crew:
            starts = sorted({s for c in crews for s, _ in day_hours(d, rules, openings, c.crew_id)})
            grid = set()
            for s0 in starts:
                hours_end = max(e for c in crews for _, e in day_hours(d, rules, openings, c.crew_id))
                w = s0
                while w < hours_end:
                    grid.add(w)
                    w += rules.window_minutes
            for w in sorted(grid):
                w_end = w + rules.window_minutes
                if dt.datetime.combine(d, dt.time()) + dt.timedelta(minutes=w) < earliest:
                    continue
                fit = [(free_min, cid) for cid, (free, free_min) in per_crew.items()
                       if _fits(free, w, w_end, need, rules)]
                if fit:
                    best = max(fit, key=lambda x: (x[0], -[c.crew_id for c in crews].index(x[1])))
                    out.append(Window(d, w, w_end, best[1], best[0]))
        d += dt.timedelta(days=1)
    return out


# ── service area (spec §5) ───────────────────────────────────────────────────

def _miles(lat1, lon1, lat2, lon2) -> float:
    r = 3958.8
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def in_service_area(zip_code="", lat=None, lon=None, *, zips=(), miles=0, origin=None) -> tuple:
    """(True/False, reason). Nothing set up = everywhere is in. A ZIP on the list, OR
    within `miles` of `origin` (lat, lon), counts as in. A radius with no location to
    check can't be confirmed, so it's out (the page turns it into a call-back request)."""
    zips = [str(z).strip()[:5] for z in (zips or []) if str(z).strip()]
    miles = float(miles or 0)
    if not zips and miles <= 0:
        return True, "no service area set"
    z = str(zip_code or "").strip()[:5]
    if zips and z in zips:
        return True, f"ZIP {z} is in the service area"
    if miles > 0 and origin and lat is not None and lon is not None:
        dist = _miles(float(lat), float(lon), float(origin[0]), float(origin[1]))
        if dist <= miles:
            return True, f"{dist:.1f} miles away"
        return False, f"{dist:.1f} miles away — outside the {miles:g}-mile area"
    if miles > 0 and not zips:
        return False, "couldn't check the distance to that address"
    return False, f"ZIP {z or '?'} isn't in the service area"

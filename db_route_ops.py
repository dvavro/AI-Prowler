"""
db_route_ops.py — Job Board Architecture Spec, Phase 1 (spec §4.2, §5, §6.4, §11).

DB-backed storage helpers for build_daily_route(). The routing logic
itself — geocoding via Nominatim, OSRM TSP optimization, the pre-flight
savings check, LATE ARRIVAL/SCHEDULE OVERLAP detection, and email
composition — has no storage dependency and is left unchanged in
ai_prowler_mcp.py. This module supplies only the storage touchpoints:

  1. db_get_jobs_for_route   — read matching Jobs_Schedule rows for a
     date (+ optional crew filter), replacing an openpyxl worksheet
     scan. Same "skip if no address" rule as before.
  2. db_update_job_geocode   — write back a geocoded lat/lon for a job.
  3. db_update_job_route_url — write the persistent route link back onto
     the job's own row (the "Route Map URL" column today).
  4. db_write_route_stops    — write the day's stops into route_stops,
     replacing the old "clear the entire Route_Planner sheet, rewrite"
     model with the spec's real fix (§4.2/§6.4): only the
     (route_date, crew_id) pairs actually present in THIS build are
     cleared and rewritten. Building Sam's route never touches Vicki's
     — that is the whole point of route_stops being keyed by
     (route_date, crew_id, stop_number) instead of one shared sheet.

Crew partitioning for a mixed-crew build (crew="" — every job on the
date, not filtered to one technician): route_stops.crew_id is NOT NULL,
so each stop is stored under ITS OWN job's Crew / Technician value
(falling back to "(unassigned)" for a blank crew field), never under
one shared placeholder for the whole build. stop_number restarts at 1
for each crew_id, counted in the same relative visit order the single
continuous route computed — so a mixed-crew build still leaves each
crew's stops independently numbered and independently addressable, even
though they came from one combined routing pass. This is this module's
interpretation of the spec's "each stop keeps its own job's own Crew /
Technician value" note (§5, build_daily_route's own docstring) applied
to the new schema — no prior code made this concrete choice, since the
old single-sheet Route_Planner never partitioned by crew at all.
"""

from db_access import get_connection, transaction, utcnow_iso
from db_write_ops import (
    db_read_settings_workday_start,
    db_read_settings_workday_end,
    db_read_settings_lunch_break_start,
    db_read_settings_lunch_break_duration_min,
    db_read_settings_hard_time_tolerance_min,
    db_read_route_origin_mode,
    db_read_route_address,
    _parse_hhmm,
    _osrm_leg,
    # Moved to db_write_ops.py 2026-09-19 (see that module's own comment
    # at their definition) so db_reorder_route_stop — which lives THERE,
    # not here — can reach them too without a circular import.
    _geocode,
    _resolve_origin,
    _resolve_jobs_only_origin,
    # R-058: multi-day jobs
    job_day_number,
    per_day_duration,
)
import datetime as _dt
import math as _math
import requests


def _crew_names(cell) -> list:
    """R-056 (David 2026-09-28): a job's Crew / Technician may name several
    people, comma-separated ("Samual Cronin, Vicki Vavro"). Returns each
    name, trimmed, blanks dropped, in the order written."""
    return [p.strip() for p in str(cell or "").split(",") if p.strip()]


def _crew_match(cell, name: str) -> str:
    """R-056: the entry of `cell` that is `name` (case-insensitive), or ""
    when `name` is not one of the people on the job."""
    want = (name or "").strip().lower()
    if not want:
        return ""
    for n in _crew_names(cell):
        if n.lower() == want:
            return n
    return ""


def _jobs_worked_on(db_path: str, route_date: str) -> list:
    """R-058: [(job row, working-day number)] for every job worked on
    route_date — one-day jobs dated that day, AND multi-day jobs whose span
    (Service Date .. End Date) covers it on a working day (Mon–Fri; the
    Service Date itself always counts). Used by every route engine, the
    prescreen and unapprove, so a 10-day job is routed on all 10 days.
    Overrun: any job still open past its End Date / Service Date is worked on
    the following working days until it is marked Complete (job_day_number)."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM jobs WHERE service_date = ? "
            "OR (COALESCE(service_date, '') <> '' AND service_date < ? "
            "    AND (COALESCE(end_date, '') >= ? OR LOWER(TRIM(COALESCE(job_status, ''))) "
            "         NOT IN ('complete', 'completed', 'cancelled', 'canceled'))) ORDER BY rowid",
            (route_date, route_date, route_date),
        ).fetchall()
    finally:
        conn.close()
    from db_write_ops import working_days
    wd = working_days(db_path)            # Settings → Working Days (default Mon–Fri)
    out = []
    for r in rows:
        n = job_day_number(r["service_date"], r["end_date"], route_date,
                           status=r["job_status"] or "", days=wd)
        if n:
            out.append((r, n))
    return out


def db_get_jobs_for_route(db_path: str, route_date: str, crew: str = "",
                          expand_multi: bool = False) -> list:
    """Returns jobs scheduled on route_date (YYYY-MM-DD text), optionally
    filtered to one person. Jobs with no street address are skipped, matching
    the original's posture that an address-less job can't be routed.

    R-056 (David 2026-09-28): a job may be assigned to several people
    ("Samual Cronin, Vicki Vavro") and is then on EACH of their routes. So
    the crew filter is a case-insensitive MEMBERSHIP test on the job's comma
    list (it used to be an exact match on the whole text), and a matched
    job's "crew" is reported as the routing person (crew.strip()) — the
    stop is written under THAT person's (route_date, crew_id) route, never
    under the combined "A, B" text.

    expand_multi (server mode, blank crew = every person's route in one
    call): a shared job is returned once PER PERSON, each copy carrying one
    name as its "crew", so the per-person grouping downstream puts it on
    every assignee's route. Personal mode (one route) leaves it False.
    """
    rows = _jobs_worked_on(db_path, route_date)       # R-058: multi-day jobs too
    from db_write_ops import working_days
    _wd_route = working_days(db_path)                  # Settings → Working Days

    crew_filter = crew.strip()
    out = []
    # Customer preferred time windows (2026-10-05, David's rule): the soft
    # "outside window" check is judged ONLY against the customer's Pref.
    # Time Start/End — never the job's Start/End Time. Batched into one
    # query; a customer with no window set contributes ("", "") = no
    # constraint, so no warning can fire for their jobs.
    _cust_win = {}
    try:
        _cids = list({str(r["customer_id"]).strip() for r, _ in rows if r["customer_id"]})
        if _cids:
            _cw_conn = get_connection(db_path)
            try:
                _ph = ",".join("?" * len(_cids))
                for _cr in _cw_conn.execute(
                    f"SELECT customer_id, preferred_time_start, preferred_time_end "
                    f"FROM customers WHERE customer_id IN ({_ph})", _cids).fetchall():
                    _cust_win[str(_cr["customer_id"])] = (
                        str(_cr["preferred_time_start"] or "").strip(),
                        str(_cr["preferred_time_end"] or "").strip())
            finally:
                _cw_conn.close()
    except Exception:
        _cust_win = {}
    for row, day_no in rows:
        job_crew = str(row["crew"] or "").strip()
        if crew_filter and not _crew_match(job_crew, crew_filter):
            continue
        # Cancelled jobs are never routed (2026-09-25): cancelling a job on the
        # Route page is one of the ways to try a better day.
        if str(row["job_status"] or "").strip().lower() in ("cancelled", "canceled"):
            continue
        # Pause (2026-10-05): a paused job is NEVER routed -- excluded for
        # every day while the pause is on. Resuming the job makes it
        # routable again.
        if str(row["paused"] or "").strip().lower() in ("1", "true", "yes"):
            continue


        street = str(row["street_address"] or "").strip()
        city = str(row["city"] or "").strip()
        state = str(row["state"] or "").strip()
        zipc = str(row["zip"] or "").strip()
        full_address = ", ".join(p for p in [street, city, f"{state} {zipc}".strip()] if p)
        if not street:
            # No street = not routable (2026-09-25). City/ZIP alone would geocode
            # to the middle of town and put a fake stop on the map. The route
            # prescreen reports these as errors before routing.
            continue

        _day_dur = per_day_duration(db_path, row["est_duration"], row["est_duration_unit"], day_no)
        _job_days = job_day_number(row["service_date"], row["end_date"],
                                   row["end_date"] or row["service_date"],
                                   days=_wd_route) or 1
        out.append({
            "job_id": row["job_id"],
            "cust_id": row["customer_id"],
            "cust_name": row["customer_name"],
            "street": street, "city": city, "state": state, "zip": zipc,
            "address": full_address,
            "lat": row["latitude"],
            "lon": row["longitude"],
            "service_type": row["service_type"],
            "start_time": row["start_time"],
            # 2026-09-16 additions (spec §14.4/§14.11 Phase 12, Route &
            # Schedule Advisor) — end_time/schedule_type were never needed
            # by build_daily_route (unchanged, still ignores them), but
            # db_suggest_route_schedule needs both to split hard/soft jobs
            # and to know a hard job's own committed window. Purely
            # additive: existing callers accessing only their known keys
            # are unaffected.
            "end_time": row["end_time"],
            # The customer-agreed window (2026-09-21). A soft job's "outside its
            # window" check must use THIS, not start_time/end_time — Approve
            # overwrites those with the routed slot, after which the "window" would
            # just be wherever the route happened to put the job.
            "original_start_time": row["original_start_time"],
            "original_end_time": row["original_end_time"],
            # Real, serious bug found live (2026-09-20): this used to
            # store the RAW sheet value with no case normalization. The
            # Jobs sheet's own dropdown stores "Hard"/"Soft" (capitalized),
            # but every downstream comparison in this file checks against
            # the lowercase literal "hard" (e.g. `schedule_type != "hard"`
            # a few hundred lines below, and _nn_order's own hard-job
            # detection). Python string comparison is case-sensitive, so
            # "Hard" != "hard" was true for every genuinely hard job in
            # the system — every hard commitment was silently treated as
            # soft by this entire scheduling engine (suggest_route_
            # schedule, apply_route_order, reorder_route_stop all read
            # jobs through this same function). Confirmed live: a route
            # for a day with three Hard jobs reported "SOFT WINDOW
            # VIOLATION" for all three and never once said "HARD TIME
            # VIOLATION" — the tell that this classification was broken
            # for every hard job it ever touched, not just an edge case.
            "schedule_type": str(row["schedule_type"] or "soft").strip().lower(),
            # R-058: for a multi-day job, THIS day's share of the work (a day unit
            # becomes that day's minutes); day_no / job_days say which day it is.
            "duration": _day_dur[0],
            "duration_unit": str(_day_dur[1] or "min").strip().lower(),
            "day_no": day_no,
            # R-058 (restored 2026-10-08): the job's planned working-day count
            # (day_no is "day N of job_days"). Was dropped in a later dict
            # refactor; the comment above still described the pair and the
            # R-058 tests read it. Purely additive - nothing else reads it.
            "job_days": _job_days,
            # Preferred-day check (2026-10-04): the job-level Preferred Day(s)
            # ("Monday/Friday" notation, blank = no constraint). _build_day_timeline
            # warns when the route_date weekday is not in this list.
            "preferred_days": row["preferred_days"],
            # Customer preferred time window (2026-10-05): the ONLY window the
            # soft "outside window" check is judged against (see _soft_window_strs).
            "cust_pref_start": _cust_win.get(str(row["customer_id"]).strip(), ("", ""))[0],
            "cust_pref_end": _cust_win.get(str(row["customer_id"]).strip(), ("", ""))[1],
            # R-058 overrun: worked past its planned End Date (still open)
            "overrun": day_no > _job_days,
            # R-056: the routing person when a crew was asked for (see the
            # docstring); the job's full assignment text stays in job_crew.
            "crew": crew_filter if crew_filter else job_crew,
            "job_crew": job_crew,
        })
        if expand_multi and not crew_filter:
            names = _crew_names(job_crew)
            if len(names) > 1:
                base = out.pop()
                for n in names:
                    copy = dict(base)
                    copy["crew"] = n
                    out.append(copy)
    return out


def db_update_job_geocode(db_path: str, job_id: str, lat: float, lon: float, actor: str) -> None:
    """Writes a freshly-geocoded lat/lon back onto a job row, same
    "skip re-geocoding next time" purpose as the spreadsheet version's
    Latitude/Longitude cell writeback."""
    with transaction(db_path) as conn:
        conn.execute(
            "UPDATE jobs SET latitude = ?, longitude = ?, version = version + 1, "
            "last_edited_by = ?, last_edited_at = ? WHERE job_id = ?",
            (lat, lon, actor, utcnow_iso(), job_id),
        )


def db_update_job_route_url(db_path: str, job_id: str, url: str, actor: str) -> None:
    """Persists the day's tap-to-navigate link onto the job's own row —
    Route_Planner-equivalent storage only ever shows the LAST date a
    route was built for, so without this a route built for a future/
    past date would have its link disappear the moment a different
    day's route gets built (same rationale as the spreadsheet version's
    identical writeback to Jobs_Schedule's own "Route Map URL" column).
    """
    with transaction(db_path) as conn:
        conn.execute(
            "UPDATE jobs SET route_map_url = ?, version = version + 1, "
            "last_edited_by = ?, last_edited_at = ? WHERE job_id = ?",
            (url, actor, utcnow_iso(), job_id),
        )


# Automatic route cleanup (2026-09-23, at the owner's request): route_stops
# is operational/ephemeral data (no "retire first" concept — see
# db_delete_route_stop's own docstring), so a route more than a week old is
# swept away automatically rather than piling up indefinitely. Hooked into
# db_write_route_stops — the single choke point every route-writing engine
# (build_daily_route, suggest_route_schedule, apply_route_order,
# reorder_route_stop/replan_route_day) funnels through — so this fires
# automatically on ordinary day-to-day use with no separate scheduler or
# extra setup required. Deliberately swallows its own errors: a failed
# housekeeping sweep must never block the actual route write that triggered
# it.
ROUTE_STOP_STALE_DAYS = 7


def _cleanup_stale_route_stops(db_path: str, exclude_date: str = "",
                             older_than_days: int = ROUTE_STOP_STALE_DAYS) -> int:
    import datetime as _dt
    cutoff = (_dt.date.today() - _dt.timedelta(days=older_than_days)).isoformat()
    try:
        with transaction(db_path) as conn:
            _ensure_route_approvals(conn)
            if exclude_date:
                # Never sweep the very date this write is about to (re)build —
                # regardless of how old it looks by wall-clock terms, a route
                # actively being written for that date is never "stale," and
                # this is what protects e.g. two crews' routes for the SAME
                # date from clobbering each other: crew A's stops must still
                # be there when crew B's write for that date runs its own
                # per-crew clear/insert a few lines below. Also matters for a
                # deliberate rebuild of a genuinely old date (an intentional
                # backfill/correction) — that date's own fresh write should
                # never be undone by the sweep that triggered it.
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM route_stops WHERE route_date < ? AND route_date != ?",
                    (cutoff, exclude_date),
                ).fetchone()
                n = row["n"] if row else 0
                if n:
                    conn.execute(
                        "DELETE FROM route_stops WHERE route_date < ? AND route_date != ?",
                        (cutoff, exclude_date),
                    )
                    # 2026-10-05: approvals die with their swept routes.
                    conn.execute(
                        "DELETE FROM route_approvals WHERE route_date < ? AND route_date != ?",
                        (cutoff, exclude_date),
                    )
            else:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM route_stops WHERE route_date < ?", (cutoff,)
                ).fetchone()
                n = row["n"] if row else 0
                if n:
                    conn.execute("DELETE FROM route_stops WHERE route_date < ?", (cutoff,))
                    # 2026-10-05: approvals die with their swept routes.
                    conn.execute("DELETE FROM route_approvals WHERE route_date < ?", (cutoff,))
            return n
    except Exception:
        return 0



def db_write_route_stops(db_path: str, route_date: str, stops: list, actor: str,
                          single_crew: bool = False) -> int:
    """Writes the day's route into route_stops, per-crew-partitioned
    (see module docstring). `stops` is a list of dicts in overall visit
    order, each with: crew (str, may be blank), job_id, cust_id,
    address, lat, lon, arrival (an "HH:MM" string), map_url (str or
    None). Two more keys are OPTIONAL and default to None via .get() if a
    caller doesn't supply them (existing callers/tests that predate the
    Route tab meta-line expansion keep working unchanged): leg_drive_min
    and leg_drive_miles — the real OSRM drive time/distance from the
    PREVIOUS stop (or the day's origin) TO this one, i.e. the same leg
    whose duration already determined `arrival` above. Both
    build_daily_route and suggest_route_schedule compute this leg via
    OSRM anyway to get `arrival` in the first place — passing it through
    here just stops that number from being thrown away afterward.

    single_crew (added for spec §6.3, personal mode): when True, every
    stop is written under ONE shared crew_id ("") in the exact order
    given, regardless of each stop's own "crew" value. Personal mode is
    a one-person operation even when different employee names happen to
    be typed into individual jobs' Crew / Technician field — without
    this, those differing text values would fragment a single person's
    day into separate (route_date, crew_id) partitions, each restarting
    its own Stop # at 1, which is exactly the per-crew isolation spec
    §6.4 exists to guarantee for real MULTI-crew server installs and
    exactly wrong for a one-crew personal install: the Route tab would
    show two interleaved "day 1"s that don't reflect any single
    person's actual visit order. Server-mode callers never pass this —
    they rely on the normal per-crew partitioning below.

    Only the (route_date, crew_id) pairs that actually appear in
    `stops` are cleared before inserting — a crew with no jobs in this
    build keeps whatever route was already stored for them on this
    date, exactly the isolation spec §6.4 exists to guarantee. This does
    NOT apply when single_crew=True: a personal install's route for a
    date is exactly one row set, so EVERY existing row for that date is
    cleared regardless of crew_id — including any leftover rows still
    sitting under an old per-crew partition (e.g. from before an install
    switched to single_crew mode, or from a pre-existing test/legacy
    row with a different crew value). Leaving those in place would
    silently duplicate the day's stops in the Route tab, which in
    personal mode reads every row for the date with no crew filter.
    Returns the total number of previously-existing rows cleared, for
    the "Cleared N previous row(s)" line in the tool's response.
    """
    if single_crew:
        by_crew: dict = {"": list(stops)}
    else:
        by_crew = {}
        for s in stops:
            # R-056: a stop whose crew still reads "A, B" (a shared job from a
            # caller that didn't expand it) goes on EACH person's route —
            # never under a combined "A, B" route nobody owns.
            names = _crew_names(s.get("crew")) or ["(unassigned)"]
            for crew_id in names:
                by_crew.setdefault(crew_id, []).append(s)

    # Automatic 7-day route cleanup — see _cleanup_stale_route_stops above.
    # Runs once per write, in its own transaction, before the actual write
    # below; failures here are swallowed and never block the real write.
    # exclude_date=route_date protects the date this call is about to
    # write from its own sweep (see that function's own comment on why).
    _cleanup_stale_route_stops(db_path, exclude_date=route_date)

    now = utcnow_iso()
    cleared = 0
    with transaction(db_path) as conn:
        _ensure_route_approvals(conn)
        _ensure_fixed_position_column(conn)
        # 2026-10-05: a rewritten route is experimental until re-approved.
        # Capture the (date, crew) pairs and jobs being cleared so their
        # approval rows and published links can go with them.
        cleared_pairs = []      # list of (route_date, crew_id)
        cleared_job_ids = set()
        # 2026-10-05 "Fix stop #" pins SURVIVE a rebuild (unlike approval):
        # capture {job_id: fixed_position} before the DELETEs below, then
        # re-attach on INSERT by job_id (an explicit fixed_position on the
        # incoming stop dict wins -- that is how a pin update is written).
        kept_pins = {}          # job_id -> fixed_position

        if single_crew:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM route_stops WHERE route_date = ?",
                (route_date,),
            ).fetchone()
            cleared += row["n"]
            for r in conn.execute(
                "SELECT DISTINCT crew_id FROM route_stops WHERE route_date = ?",
                (route_date,),
            ).fetchall():
                cleared_pairs.append((route_date, r["crew_id"]))
            for r in conn.execute(
                "SELECT job_id, fixed_position FROM route_stops WHERE route_date = ? AND job_id IS NOT NULL",
                (route_date,),
            ).fetchall():
                cleared_job_ids.add(r["job_id"])
                if r["fixed_position"] is not None:
                    kept_pins[r["job_id"]] = r["fixed_position"]
            conn.execute("DELETE FROM route_stops WHERE route_date = ?", (route_date,))

        for crew_id, crew_stops in by_crew.items():
            if not single_crew:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM route_stops WHERE route_date = ? AND crew_id = ?",
                    (route_date, crew_id),
                ).fetchone()
                cleared += row["n"]
                for r in conn.execute(
                    "SELECT job_id, fixed_position FROM route_stops WHERE route_date = ? AND crew_id = ? "
                    "AND job_id IS NOT NULL",
                    (route_date, crew_id),
                ).fetchall():
                    cleared_job_ids.add(r["job_id"])
                    if r["fixed_position"] is not None:
                        kept_pins[r["job_id"]] = r["fixed_position"]

                cleared_pairs.append((route_date, crew_id))
                conn.execute(
                    "DELETE FROM route_stops WHERE route_date = ? AND crew_id = ?",
                    (route_date, crew_id),
                )

            for i, s in enumerate(crew_stops, start=1):
                # 2026-10-05 "Fix stop #" pin: an explicit fixed_position on the
                # incoming stop wins; otherwise the pin kept from the cleared
                # rows is re-attached by job_id (pins survive rebuilds).
                _pin = s.get("fixed_position")
                if _pin is None and s.get("job_id"):
                    _pin = kept_pins.get(s.get("job_id"))
                conn.execute(
                    """INSERT INTO route_stops
                       (route_date, crew_id, stop_number, fixed_position, job_id, customer_id, address,
                        latitude, longitude, eta, leg_drive_min, leg_drive_miles, map_url,
                        created_by, last_edited_by, last_edited_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (route_date, crew_id, i, _pin, s.get("job_id"), s.get("cust_id"), s.get("address"),
                     s.get("lat"), s.get("lon"), s.get("arrival"),
                     s.get("leg_drive_min"), s.get("leg_drive_miles"), s.get("map_url"),
                     actor, actor, now),
                  )

        # 2026-10-05: the cleared pairs' approval (if any) dies with the
        # rewrite, and their published links are unpublished — an unapproved
        # route must not show a link on Jobs/Calendar nor be emailable.
        for rd, cid in cleared_pairs:
            conn.execute(
                "DELETE FROM route_approvals WHERE route_date = ? AND crew_id = ?",
                (rd, cid),
            )
        for jid in sorted(cleared_job_ids):
            conn.execute(
                "UPDATE jobs SET route_map_url = '', version = version + 1, "
                "last_edited_by = ?, last_edited_at = ? WHERE job_id = ?",
                (actor, now, jid),
            )
        # The route follows the job (2026-09-25): a job just routed on this
        # date can't still be a stop on another day it no longer belongs to
        # (e.g. moved 9/24 -> 9/25; its old 9/24 stop is stale).
        _drop_stale_job_stops(conn, [s.get("job_id") for s in stops if s.get("job_id")])
    return cleared



def _drop_stale_job_stops(conn, job_ids) -> int:
    """Deletes route_stops rows for these jobs whose route_date is outside the
    job's CURRENT date range (service_date .. end_date, or just service_date
    for a one-day job). The Route page is a place to experiment — move a job
    to another day, re-route, try again — so a job's stop must never be left
    behind on a day it was moved off. Runs inside the caller's transaction.
    Rows with no job_id (Home / Start-End bookends) are never touched.

    R-058 overrun: a multi-day job's stops AFTER its End Date are kept while
    the job is still open (up to the overrun horizon — it is still being
    worked), and once it is Complete its past overrun days stay as history;
    only its future ones are dropped."""
    ids = [j for j in dict.fromkeys(job_ids or []) if j]
    if not ids:
        return 0
    import db_write_ops as _w
    today = _w.overrun_today().isoformat()
    horizon = _w.overrun_horizon(days=_w.working_days_conn(conn)).isoformat()
    ph = ",".join("?" * len(ids))
    n = conn.execute(
        f"""DELETE FROM route_stops
            WHERE job_id IN ({ph})
              AND id IN (
                SELECT r.id FROM route_stops r JOIN jobs j ON j.job_id = r.job_id
                WHERE r.job_id IN ({ph})
                  -- Only when we KNOW the job belongs to other day(s): a job
                  -- with no Service Date is left alone (it may have been put
                  -- on a route by hand, e.g. from the Database tab).
                  AND COALESCE(j.service_date, '') <> ''
                  AND (r.route_date < j.service_date
                       OR (r.route_date > COALESCE(NULLIF(j.end_date, ''), j.service_date)
                           -- R-058 overrun: an open job keeps its stops after
                           -- its planned end (to the horizon); a finished one
                           -- keeps the days already worked.
                           AND NOT (r.route_date <= CASE
                                        WHEN LOWER(TRIM(COALESCE(j.job_status, '')))
                                             IN ('complete', 'completed', 'cancelled', 'canceled')
                                        THEN ? ELSE ? END))))""",
        ids + ids + [today, horizon],
    ).rowcount
    if n:
        # The day(s) those stops were on may now have no job left: drop their
        # Start/End/Home rows too (R-013).
        from db_write_ops import drop_orphan_route_bookends
        drop_orphan_route_bookends(conn)
    return n


def db_drop_stale_job_stops(db_path: str, job_ids) -> int:
    """Standalone wrapper for callers outside a transaction (e.g. right after
    a job's Service Date / End Date is edited). Never raises."""
    try:
        with transaction(db_path) as conn:
            return _drop_stale_job_stops(conn, job_ids)
    except Exception:
        return 0


def db_drop_cancelled_job_stops(db_path: str, job_ids) -> int:
    """Cancelling a job takes it off every route (2026-09-25) — the Route page
    is for trying things (cancel a job, re-route, see the day improve), and the
    route engines now skip Cancelled jobs too (db_get_jobs_for_route). Never
    raises."""
    ids = [j for j in dict.fromkeys(job_ids or []) if j]
    if not ids:
        return 0
    ph = ",".join("?" * len(ids))
    try:
        with transaction(db_path) as conn:
            n = conn.execute(
                f"""DELETE FROM route_stops WHERE job_id IN (
                      SELECT job_id FROM jobs WHERE job_id IN ({ph})
                        AND LOWER(TRIM(COALESCE(job_status, ''))) IN ('cancelled', 'canceled'))""",
                ids,
            ).rowcount
            if n:
                from db_write_ops import drop_orphan_route_bookends
                drop_orphan_route_bookends(conn)     # R-013
            return n
    except Exception:
        return 0


# ── Approve / Un-approve — mileage/routing follow-up (2026-09-20) ──────────
# Two dedicated, narrow tools replacing the Route tab's old "Approve times"
# client-side loop (which called the generic update_job_spreadsheet
# directly per stop). Both ONLY ever read/write jobs.start_time/end_time —
# NEITHER ever touches original_start_time/original_end_time, by design
# (see that column's own schema comment): the customer's actually-agreed
# schedule changes only through a genuine manual edit or an explicit
# Claude instruction, never as a side effect of trying out a route. This
# is what lets a route be approved and un-approved through any number of
# trial-and-error passes without ever losing track of the real target.

def _add_minutes_hhmm(hhmm: str, minutes) -> str:
    """'09:15' + 45 -> '10:00'. Returns "" if hhmm doesn't parse or minutes
    is falsy/None (mirrors the client's own _addMinutesToTimeStr, kept in
    sync deliberately — see jobs/index.html)."""
    dt = _parse_hhmm(hhmm)
    if dt is None or not minutes:
        return ""
    return (dt + _dt.timedelta(minutes=float(minutes))).strftime("%H:%M")


# ── Route approval (2026-10-05) ──────────────────────────────────────────
# Approve / Un-approve are a strict inverse pair gating email + link viewing.
# Approving a route NEVER writes to a job's Start Time / End Time (David's
# rule: a job's window always reflects the customer settings — routing must
# not touch it). Approve only records an approval row; Un-approve deletes
# that row and unpublishes the links. Any route_stops rewrite for the pair
# also clears the approval — a rebuilt route is experimental until
# re-approved.
_ROUTE_APPROVALS_DDL = """
CREATE TABLE IF NOT EXISTS route_approvals (
route_date  TEXT NOT NULL,
crew_id     TEXT NOT NULL,
approved_at TEXT NOT NULL,
approved_by TEXT,
PRIMARY KEY (route_date, crew_id)
)
"""


def _ensure_route_approvals(conn) -> None:
    """Idempotent — safe on databases created before route_approvals existed."""
    conn.execute(_ROUTE_APPROVALS_DDL)


def _ensure_fixed_position_column(conn) -> None:
    """Idempotent backstop for the 2026-10-05 "Fix stop #" pin column.

    The schema migration in db_schema.apply_schema is the primary path; this
    keeps write paths safe on databases where it hasn't run yet."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(route_stops)").fetchall()]
    if "fixed_position" not in cols:
        conn.execute("ALTER TABLE route_stops ADD COLUMN fixed_position INTEGER")




def db_is_route_approved(db_path: str, route_date: str, crew: str) -> bool:
    """True if (route_date, crew) is approved. A blank crew matches ANY
    crew's approval for the date (personal mode stores crew_id '')."""
    conn = get_connection(db_path)
    try:
        _ensure_route_approvals(conn)
        crew = (crew or "").strip()
        if crew:
            row = conn.execute(
                "SELECT 1 FROM route_approvals WHERE route_date = ? "
                "AND LOWER(TRIM(crew_id)) = LOWER(?)",
                (route_date, crew),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT 1 FROM route_approvals WHERE route_date = ?",
                (route_date,),
            ).fetchone()
        return bool(row)
    finally:
        conn.close()


def db_approve_route_schedule(db_path: str, route_date: str, crew: str, actor: str) -> str:
    """Approves the route for (route_date, crew) — the Route tab 'Approve'
    button's backend (2026-10-05 rewrite).

    Approval is a pure flag: it records a row in route_approvals, which
    grants email eligibility and link pinning/viewing for the route. It
    NEVER writes to a job's Start Time / End Time / Original Start/End
    Time (David's rule: a job's window always reflects the customer
    settings). The routed arrival/departure times live in route_stops,
    not on the job.

    The link pinning itself happens in the MCP tool wrapper (it needs the
    caller's context for the home address); this function only records the
    approval. Un-approving (db_unapprove_route_schedule) is the exact
    inverse: it deletes the approval row and unpublishes the links.
    """
    conn = get_connection(db_path)
    try:
        _ensure_route_approvals(conn)
        query = (
            "SELECT DISTINCT rs.crew_id FROM route_stops rs "
            "WHERE rs.route_date = ? AND rs.job_id IS NOT NULL"
        )
        params = [route_date]
        crew_filter = (crew or "").strip()
        if crew_filter:
            # R-056: the person's own route, whatever case their name was typed in.
            query += " AND LOWER(TRIM(rs.crew_id)) = LOWER(?)"
            params.append(crew_filter)
        crew_rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    if not crew_rows:
        scope = f" for crew '{crew}'" if (crew or "").strip() else ""
        return f"✅ No routed jobs found for {route_date}{scope} — nothing to approve."

    now = utcnow_iso()
    crew_ids = [r["crew_id"] for r in crew_rows]
    with transaction(db_path) as conn:
        _ensure_route_approvals(conn)
        for cid in crew_ids:
            conn.execute(
                "INSERT OR REPLACE INTO route_approvals "
                "(route_date, crew_id, approved_at, approved_by) VALUES (?, ?, ?, ?)",
                (route_date, cid, now, actor),
            )

    scope = f" ({', '.join(c for c in crew_ids if c.strip())})" if any(
        c.strip() for c in crew_ids) else ""
    return (
        f"✅ Route approved for {route_date}{scope}.\n"
        f"  Email is now allowed for this route, and its tap-to-navigate link "
        f"will be pinned and viewable on the Jobs and Calendar pages.\n"
        f"  No job time windows were changed — approve never touches Start/End Time."
    )



def db_unapprove_route_schedule(db_path: str, route_date: str, crew: str, actor: str) -> str:
    """The exact inverse of db_approve_route_schedule above (2026-10-05
    rewrite): deletes the approval row(s) for (route_date, crew) — revoking
    email eligibility — and unpublishes the route links (clears
    route_stops.map_url and each routed job's Route Map URL) so nothing
    approved-only remains viewable on the Jobs or Calendar pages. After
    this, the route behaves exactly as if it had never been approved: no
    leftover state where an un-approved route still behaves approved.

    It NEVER writes to a job's Start Time / End Time — approve never
    changed them, so there is nothing to restore.
    """
    crew_filter = (crew or "").strip()
    now = utcnow_iso()
    with transaction(db_path) as conn:
        _ensure_route_approvals(conn)
        if crew_filter:
            # R-056: the person's own route, whatever case their name was typed in.
            stops_q = ("SELECT job_id FROM route_stops WHERE route_date = ? "
                       "AND job_id IS NOT NULL AND LOWER(TRIM(crew_id)) = LOWER(?)")
            stops_params = (route_date, crew_filter)
            appr_check_q = ("SELECT 1 FROM route_approvals WHERE route_date = ? "
                            "AND LOWER(TRIM(crew_id)) = LOWER(?)")
            appr_check_params = (route_date, crew_filter)
            appr_q = ("DELETE FROM route_approvals WHERE route_date = ? "
                      "AND LOWER(TRIM(crew_id)) = LOWER(?)")
            appr_params = (route_date, crew_filter)
            map_q = ("UPDATE route_stops SET map_url = NULL WHERE route_date = ? "
                     "AND LOWER(TRIM(crew_id)) = LOWER(?)")
            map_params = (route_date, crew_filter)
        else:
            stops_q = ("SELECT job_id FROM route_stops WHERE route_date = ? "
                       "AND job_id IS NOT NULL")
            stops_params = (route_date,)
            appr_check_q = "SELECT 1 FROM route_approvals WHERE route_date = ?"
            appr_check_params = (route_date,)
            appr_q = "DELETE FROM route_approvals WHERE route_date = ?"
            appr_params = (route_date,)
            map_q = "UPDATE route_stops SET map_url = NULL WHERE route_date = ?"
            map_params = (route_date,)
        job_rows = conn.execute(stops_q, stops_params).fetchall()
        was_approved = bool(conn.execute(appr_check_q, appr_check_params).fetchone())
        conn.execute(appr_q, appr_params)
        conn.execute(map_q, map_params)
        job_ids = sorted({r["job_id"] for r in job_rows if r["job_id"]})
        for jid in job_ids:
            conn.execute(
                "UPDATE jobs SET route_map_url = '', version = version + 1, "
                "last_edited_by = ?, last_edited_at = ? WHERE job_id = ?",
                (actor, now, jid),
            )

    scope = f" for crew '{crew}'" if crew_filter else ""
    if not was_approved and not job_ids:
        return f"✅ No approved route found for {route_date}{scope} — nothing to un-approve."
    return (
        f"↩️ Route un-approved for {route_date}{scope}.\n"
        f"  Email is no longer allowed for this route, and its link was removed "
        f"from {len(job_ids)} job(s) — it no longer shows on the Jobs or Calendar pages.\n"
        f"  No job time windows were changed."
    )



# ── Route & Schedule Advisor, Mode A — spec §14.4/§14.11 Phase 12 ──────────
# db_suggest_route_schedule() below is the "Get AI Suggestion" button's
# backend: a deterministic scheduling heuristic (NOT a live LLM call —
# consistent with this codebase's existing free/no-external-API-cost
# posture for build_daily_route/optimize_route, and testable the same way
# they are). It reads a day's jobs, respects every hard job's committed
# time as an unmovable anchor, applies the lunch pause as a one-time
# duration extension wherever it lands on the timeline (never a stop of
# its own — spec §14.2a/§14.4), and writes the result straight into
# route_stops via db_write_route_stops above — the SAME storage function
# Mode B's manual builds already use, so the proposal shows up in the
# Route tab's normal editable list/map immediately, with no separate
# "preview" state to reconcile.
#
# HONEST LIMITATION: this is a nearest-neighbor-plus-repair heuristic, not
# an optimal TSP-with-time-windows solver. It produces a reasonable,
# always-hard-constraint-respecting route quickly and without needing a
# paid optimizer — not necessarily the shortest possible one. A day that
# genuinely doesn't fit is flagged (DAY DOES NOT FIT), never silently
# overpacked or silently dropped.

def db_get_approved_route_stops(db_path: str, start_date: str, end_date: str,
                                crew: str = "") -> dict:
    """Read-only: approved-route schedule info for a date range, backing the
    Jobs page and Board page job cards (2026-10-06 -- David: each card should
    show the APPROVED scheduled time and drive miles/time, like the Route
    page's stop cards).

    For each date in [start_date, end_date] (YYYY-MM-DD, inclusive) returns:
      {"approved": bool, "stops": [{"job_id", "stop_number", "eta",
                                    "drove_min", "drove_miles"}, ...]}

    - "approved" comes from the route_approvals table (the same source the
      email gate uses) -- never from map_url presence.
    - "stops" are the route_stops rows carrying a job_id, in visit order.
      eta is the routed arrival ("HH:MM"); drove_min/drove_miles are the leg
      FROM THE PREVIOUS STOP to this one (leg_drive_min/leg_drive_miles).
    - An unapproved date returns approved=False with no stops, so callers
      render those jobs exactly as they do today.
    - Crew scoping mirrors db_is_route_approved: a blank crew matches any
      crew's approval (personal mode stores crew_id '').
    """
    import datetime as _dt

    def _ok(d):
        try:
            _dt.date.fromisoformat(d)
            return True
        except (ValueError, TypeError):
            return False

    out = {}
    if not (_ok(start_date) and _ok(end_date)) or end_date < start_date:
        return out
    crew_filter = (crew or "").strip()
    conn = get_connection(db_path)
    try:
        _ensure_route_approvals(conn)
        d = _dt.date.fromisoformat(start_date)
        last = _dt.date.fromisoformat(end_date)
        while d <= last:
            ds = d.isoformat()
            if crew_filter:
                appr = conn.execute(
                    "SELECT 1 FROM route_approvals WHERE route_date = ? "
                    "AND LOWER(TRIM(crew_id)) = LOWER(?)",
                    (ds, crew_filter)).fetchone()
                stops_q = ("SELECT job_id, stop_number, eta, leg_drive_min, "
                           "leg_drive_miles FROM route_stops WHERE route_date = ? "
                           "AND job_id IS NOT NULL AND LOWER(TRIM(crew_id)) = LOWER(?) "
                           "ORDER BY stop_number")
                stops_p = (ds, crew_filter)
            else:
                appr = conn.execute(
                    "SELECT 1 FROM route_approvals WHERE route_date = ?",
                    (ds,)).fetchone()
                stops_q = ("SELECT job_id, stop_number, eta, leg_drive_min, "
                           "leg_drive_miles FROM route_stops WHERE route_date = ? "
                           "AND job_id IS NOT NULL ORDER BY stop_number")
                stops_p = (ds,)
            approved = bool(appr)
            stops = []
            if approved:
                for r in conn.execute(stops_q, stops_p).fetchall():
                    stops.append({
                        "job_id": r["job_id"],
                        "stop_number": r["stop_number"],
                        "eta": r["eta"] or "",
                        "drove_min": r["leg_drive_min"],
                        "drove_miles": r["leg_drive_miles"],
                    })
            out[ds] = {"approved": approved, "stops": stops}
            d += _dt.timedelta(days=1)
    finally:
        conn.close()
    return out


def _haversine_km(lat1, lon1, lat2, lon2):
    """Straight-line distance — used only to pick a reasonable geographic
    VISIT ORDER cheaply (no per-candidate network call); real drive times
    for the final ETAs still come from OSRM in _build_day_timeline below,
    exactly as they do everywhere else in this codebase."""
    r = 6371.0
    p1, p2 = _math.radians(lat1), _math.radians(lat2)
    dphi = _math.radians(lat2 - lat1)
    dlambda = _math.radians(lon2 - lon1)
    a = _math.sin(dphi / 2) ** 2 + _math.cos(p1) * _math.cos(p2) * _math.sin(dlambda / 2) ** 2
    return 2 * r * _math.asin(min(1.0, _math.sqrt(a)))


def _nn_order(jobs, origin=None, workday_start_min=420):
    """Nearest-neighbor visit order.

    Real, serious bug found live (2026-09-20): this used to seed the day
    with whichever HARD job had the earliest committed start_time,
    unconditionally, whenever any hard job existed — completely ignoring
    a SOFT job's own window even when it started EARLIER and was right
    next door. Confirmed live: a hard 8:00-9:00 AM job and a soft 7:00-
    7:45 AM job a 1-minute drive apart got routed hard-job-first, so the
    soft job was visited at 9:01 AM — over an hour past its own window —
    when visiting the soft job first (arriving comfortably within its
    7:00-7:45 window) and hopping straight to the nearby hard job would
    have hit BOTH commitments with room to spare. "A real commitment
    always outranks geographic convenience" was the wrong framing: the
    soft job's window wasn't in competition with the hard job's
    commitment at all here, since they're geographically adjacent — the
    bug was in never even considering the soft job as a candidate seed.

    The fix: EVERY job with its own start_time set (hard or soft alike —
    a soft window's start is the customer's own earliest-preferred time,
    same as a hard commitment) is now a seed candidate, ranked by
    ESTIMATED ARRIVAL TIME if visited first — max(a rough straight-line
    drive-time estimate from origin, the job's own start_time) — not by
    start_time alone. This is deliberately just a ranking heuristic for
    picking a good SEED, using straight-line distance at an assumed
    average speed (never real OSRM data) purely to compare candidates
    against each other; it does not schedule or validate anything itself
    — every actual ETA, wait, and violation check still comes from
    _build_day_timeline below, exactly as before. Using estimated
    ARRIVAL rather than raw start_time is what stops a genuinely
    far-away job with an early window from winning the seed over a
    nearby job with a slightly later one purely because its number is
    smaller — a job you can't reach until 8:00 anyway doesn't become
    more urgent than one you could realistically start at 7:10 just
    because its own label says "7:00."

    This only changes SEED selection — the rest of the walk is unchanged
    plain nearest-neighbor from wherever the day is at each step, and
    _repair_hard_order below still separately guarantees hard jobs land
    in their own committed order relative to EACH OTHER. A day with
    several early-windowed jobs scattered across the whole route (not
    just candidates for the very first stop) can still end up scheduled
    less than optimally further along the day — this fix targets the
    specific, confirmed bug (a bad SEED choice), not a full rewrite into
    a general deadline-aware routing algorithm at every step.

    Falls back to the ORIGINAL hard-only rule when no origin is known
    (nothing to estimate drive time from, so raw start_time is the best
    available signal) — see the docstring history via version control
    for that prior behavior if ever needed for comparison.

    With neither a timed job nor an origin, falls back to the first job
    in the input list (the original, origin-unaware behavior — unaffected
    for any caller that doesn't pass one).

    Args:
        workday_start_min: Workday Start Time as minutes-since-midnight
            (e.g. 420 for "07:00") — the clock reference the estimated-
            arrival calculation above uses. Defaults to 420 so any other
            future caller that doesn't pass it explicitly still gets a
            sane value rather than an error.
    """
    remaining = jobs[:]
    if not remaining:
        return []

    def _start_min(j):
        t = _parse_hhmm(j.get("start_time"))
        return (t.hour * 60 + t.minute) if t is not None else None

    timed_idxs = [i for i, j in enumerate(remaining) if _start_min(j) is not None]
    if timed_idxs and origin is not None:
        # ~40 km/h — a deliberately rough average-speed assumption. This
        # value only ever ranks seed CANDIDATES against each other; it
        # never appears in an ETA, a violation check, or anything a
        # customer or crew member sees — those all come from real OSRM
        # legs in _build_day_timeline.
        AVG_SPEED_KMH = 40.0
        def _est_arrival_min(i):
            j = remaining[i]
            drive_min = _haversine_km(origin[0], origin[1], j["lat"], j["lon"]) / AVG_SPEED_KMH * 60.0
            return max(workday_start_min + drive_min, _start_min(j))
        start_idx = min(timed_idxs, key=_est_arrival_min)
    elif timed_idxs:
        start_idx = min(timed_idxs, key=lambda i: remaining[i]["start_time"])
    elif origin is not None:
        start_idx = min(
            range(len(remaining)),
            key=lambda i: _haversine_km(origin[0], origin[1], remaining[i]["lat"], remaining[i]["lon"]),
        )
    else:
        start_idx = 0
    order = [remaining.pop(start_idx)]
    while remaining:
        last = order[-1]
        remaining.sort(key=lambda j: _haversine_km(last["lat"], last["lon"], j["lat"], j["lon"]))
        order.append(remaining.pop(0))
    return order


def _repair_hard_order(order):
    """Guarantees hard jobs appear in their own committed chronological
    order relative to EACH OTHER — a real constraint the geographic
    nearest-neighbor pass above has no way to know about — while
    disturbing soft jobs' positions as little as possible: only the
    occupants of the positions hard jobs already landed in (via NN) get
    reassigned, sorted by start_time; every soft job keeps its own NN
    position untouched. A no-op when 0 or 1 hard jobs exist, since there's
    no relative order to violate."""
    hard_positions = [i for i, j in enumerate(order) if j.get("schedule_type") == "hard" and j.get("start_time")]
    if len(hard_positions) < 2:
        return order
    hard_sorted = sorted((order[i] for i in hard_positions), key=lambda j: j["start_time"])
    for pos, job in zip(hard_positions, hard_sorted):
        order[pos] = job
    return order

def _job_dur_min(job):
    """This job's work duration in minutes — the same parse _build_day_timeline
    uses (hour units x60; unknown/blank falls back to 60 min, never a silent
    zero). Factored out 2026-10-06 so the anchor/gap scheduler and the
    timeline can't disagree on how long a job takes."""
    dur = job.get("duration")
    dur_unit = (job.get("duration_unit") or "min").lower()
    try:
        dur_min = float(dur) * 60 if dur and "hour" in dur_unit else float(dur)
        if not dur_min:
            raise ValueError
    except (TypeError, ValueError):
        dur_min = 60.0
    return dur_min


def _fmt_hhmm_ampm(dt):
    """"12:00 PM"-style clock label for a _parse_hhmm datetime."""
    return dt.strftime("%I:%M %p").lstrip("0")


def _resolve_lunch_vs_hard(anchors, lunch_start_str, lunch_dur_min, workday_start_dt, workday_end_dt):
    """Resolves the lunch block against hard-job anchors (2026-10-06, David's
    rule: a hard job's window takes priority over the lunch block).

    anchors: list of dicts with job_id, label, ws (datetime), dur (minutes),
    we (datetime or None = window end). Only each anchor's committed service
    span [ws, ws+dur] matters here, never a chained arrival.

    Returns (lunch_eff_start_str or None, split_map, notes):
      - lunch_eff_start_str: "HH:MM" for the (possibly displaced) lunch, or
        None when lunch was dropped for the day.
      - split_map: {job_id: (lunch_start_dt, lunch_end_dt)} for anchors whose
        service span strictly contains lunch ("lunch is in the middle of the
        job") — the timeline keeps lunch in place and splits the service
        around it, preserving total work time.
      - notes: warning strings (e.g. lunch skipped) for the caller to surface.

    A merely overlapping (not strictly containing) lunch is displaced to the
    nearest free adjacent slot — preferring right after the job, else right
    before — keeping its duration. If neither adjacent slot fits inside the
    workday without clashing with another anchor, lunch is dropped for the
    day with a clear note. Soft jobs never displace lunch; their absorption
    logic is untouched elsewhere.
    """
    try:
        lunch_dur_min = float(lunch_dur_min or 0)
    except (TypeError, ValueError):
        lunch_dur_min = 0.0
    ls = _parse_hhmm(lunch_start_str)
    if ls is None or lunch_dur_min <= 0:
        return (lunch_start_str, {}, [])
    le = ls + _dt.timedelta(minutes=lunch_dur_min)
    notes = []
    split_map = {}
    cur_ls, cur_le = ls, le
    dropped = False

    def _svc(a):
        return (a["ws"], a["ws"] + _dt.timedelta(minutes=a["dur"]))

    # Pass 1 (chronological): displace lunch for partial overlaps. Strict
    # containments are deferred to pass 2, so displacing for one anchor can't
    # strand another anchor's split decision.
    for a in sorted(anchors, key=lambda a: a["ws"]):
        if dropped:
            break
        ws, se = _svc(a)
        if cur_le <= ws or cur_ls >= se:
            continue  # no overlap with this anchor's service
        if ws < cur_ls and cur_le < se:
            continue  # strictly inside — handled in pass 2
        placed = False
        cands = [(se, se + _dt.timedelta(minutes=lunch_dur_min)),
                 (ws - _dt.timedelta(minutes=lunch_dur_min), ws)]
        for ns, ne in cands:
            if ns < workday_start_dt:
                continue
            if workday_end_dt is not None and ne > workday_end_dt:
                continue
            if any(ns < _svc(b)[1] and ne > _svc(b)[0] for b in anchors if b is not a):
                continue
            cur_ls, cur_le = ns, ne
            placed = True
            break
        if not placed:
            dropped = True
            notes.append(
                "\u26a0\ufe0f Lunch skipped \u2014 displaced by hard job %s %s\u2013%s." % (
                    a.get("label") or a["job_id"],
                    _fmt_hhmm_ampm(ws), _fmt_hhmm_ampm(se)))

    # Pass 2: lunch strictly inside an anchor's service span stays in place;
    # the timeline splits that anchor's service around it. (Skipped when lunch
    # was dropped — no lunch, no split.)
    if not dropped:
        for a in anchors:
            ws, se = _svc(a)
            if ws < cur_ls and cur_le < se:
                split_map[a["job_id"]] = (cur_ls, cur_le)

    if dropped:
        return (None, split_map, notes)
    return (cur_ls.strftime("%H:%M"), split_map, notes)


def _order_with_hard_anchors(jobs, origin, workday_start_min, workday_start_str,
                             workday_end_str, lunch_start_str, lunch_dur_min,
                             first_arrival_at_wds):
    """Anchor-aware visit order for db_suggest_route_schedule (2026-10-06).

    Hard jobs with a parseable start_time are ANCHORS: their service occupies
    [window start, window start + duration] — never moved, never pushed by
    lunch (see _resolve_lunch_vs_hard). Soft jobs fill the free gaps (workday
    start -> first anchor, between anchors, last anchor -> workday end) in
    proximity order using the same haversine heuristic _nn_order uses, placed
    only when they fit: arrival + duration + drive to the next anchor must fit
    inside the gap. A soft job may span the (possibly displaced) lunch block —
    it then absorbs the pause, mirroring _build_day_timeline's own absorption,
    and the fit check accounts for it. Soft jobs that fit in no gap are
    appended after the last gap in nearest-neighbor order — never silently
    dropped.

    With no anchorable hard jobs this is exactly
    _repair_hard_order(_nn_order(...)): an anchor-free day behaves identically
    to before.
    """
    anchors = []
    softs = []
    for j in jobs:
        if (str(j.get("schedule_type") or "").lower() == "hard"
                and _parse_hhmm(j.get("start_time")) is not None):
            anchors.append(j)
        else:
            softs.append(j)
    if not anchors:
        return _repair_hard_order(_nn_order(jobs, origin=origin,
                                            workday_start_min=workday_start_min))

    wds = _parse_hhmm(workday_start_str) or _parse_hhmm("07:00")
    wde = _parse_hhmm(workday_end_str)
    ainfo = []
    for j in anchors:
        ws = _parse_hhmm(j.get("start_time"))
        ainfo.append({
            "job_id": j.get("job_id"),
            "label": "%s %s" % (j.get("job_id") or "", (j.get("address") or "").strip()),
            "ws": ws,
            "dur": _job_dur_min(j),
            "we": _parse_hhmm(j.get("end_time")) if j.get("end_time") else None,
            "job": j,
        })
    ainfo.sort(key=lambda a: a["ws"])

    # Lunch position after hard-job displacement — for the absorption check
    # below only (lunch is not a gap block: soft jobs may span it, exactly as
    # _build_day_timeline lets them). _build_day_timeline runs this same
    # shared resolution itself and surfaces the notes, so they can't
    # double-fire.
    lunch_eff_str, split_map, _ = _resolve_lunch_vs_hard(
        ainfo, lunch_start_str, lunch_dur_min, wds, wde)
    try:
        _ld = float(lunch_dur_min or 0)
    except (TypeError, ValueError):
        _ld = 0.0
    _ls_eff = _parse_hhmm(lunch_eff_str) if lunch_eff_str else None
    if _ls_eff is None:
        _ld = 0.0
    # Lunch already consumed when a split exists (the split anchor absorbs it
    # in the timeline) — later soft jobs must not re-absorb it.
    lunch_used = bool(split_map) or _ls_eff is None

    # Occupied blocks: hard anchors only (extended past lunch when split).
    blocks = []  # (start, end, anchor-info)
    for a in ainfo:
        se = a["ws"] + _dt.timedelta(minutes=a["dur"])
        if a["job_id"] in split_map:
            sls, sle = split_map[a["job_id"]]
            first_seg = (sls - a["ws"]).total_seconds() / 60.0
            se = sle + _dt.timedelta(minutes=(a["dur"] - first_seg))
        blocks.append((a["ws"], se, a))
    blocks.sort(key=lambda b: b[0])

    AVG_SPEED_KMH = 40.0  # same rough ranking assumption _nn_order uses

    def _est_min(lat1, lon1, lat2, lon2):
        try:
            if None in (lat1, lon1, lat2, lon2):
                return 0.0
            return _haversine_km(lat1, lon1, lat2, lon2) / AVG_SPEED_KMH * 60.0
        except Exception:
            return 0.0

    # Pair each occupied block with its preceding free gap.
    segments = []  # (gap_tuple_or_None, block_tuple_or_None)
    prev_end = wds
    prev_pos = origin  # (lat, lon) or None
    for bs, be, a in blocks:
        gap = None
        if bs > prev_end:
            gap = (prev_end, bs, prev_pos, (a["ws"], a["job"]["lat"], a["job"]["lon"]))
        segments.append((gap, (bs, be, a)))
        if be > prev_end:
            prev_end = be
        prev_pos = (a["job"]["lat"], a["job"]["lon"])
    if wde is None or prev_end < wde:
        segments.append(((prev_end, wde, prev_pos, None), None))

    order = []
    remaining = softs[:]
    anchor_appended = False
    for gap, block in segments:
        if gap is not None:
            gs, ge, spos, end_anchor = gap
            t = gs
            pos = spos
            while remaining:
                cands = sorted(
                    remaining,
                    key=lambda j: _est_min(pos[0], pos[1], j.get("lat"), j.get("lon")) if pos else 0.0)
                pick = None
                pick_end = None
                pick_absorbed = False
                for j in cands:
                    dur = _job_dur_min(j)
                    if not order and not anchor_appended and first_arrival_at_wds:
                        # This job will be order[0]: with a soft home bookend
                        # (or none) its arrival is anchored at Workday Start —
                        # the drive happened before the workday clock starts
                        # (same rule _build_day_timeline's _anchor_first
                        # applies).
                        arr = wds
                    elif pos:
                        arr = t + _dt.timedelta(minutes=_est_min(
                            pos[0], pos[1], j.get("lat"), j.get("lon")))
                    else:
                        arr = t
                    end = arr + _dt.timedelta(minutes=dur)
                    # Mirror _build_day_timeline's lunch absorption so the fit
                    # check sees the same effective times the timeline will.
                    absorbed = False
                    if not lunch_used and _ls_eff is not None:
                        if _ls_eff <= arr:
                            arr = arr + _dt.timedelta(minutes=_ld)
                            end = arr + _dt.timedelta(minutes=dur)
                            absorbed = True
                        elif _ls_eff < end:
                            end = end + _dt.timedelta(minutes=_ld)
                            absorbed = True
                    if end_anchor is not None:
                        aws, alat, alon = end_anchor
                        ok = end + _dt.timedelta(minutes=_est_min(
                            j.get("lat"), j.get("lon"), alat, alon)) <= aws
                    else:
                        ok = ge is None or end <= ge
                    if ok:
                        pick, pick_end, pick_absorbed = j, end, absorbed
                        break
                if pick is None:
                    break
                order.append(pick)
                remaining.remove(pick)
                if pick_absorbed:
                    lunch_used = True
                pos = (pick.get("lat"), pick.get("lon"))
                t = pick_end
        if block is not None:
            order.append(block[2]["job"])
            anchor_appended = True
    if remaining:
        # Fit nowhere — still routed, after the last gap in proximity order.
        order.extend(_nn_order(remaining, origin=prev_pos,
                               workday_start_min=workday_start_min))
    return order
def _read_route_pins(db_path: str, route_date: str, crew_id=None) -> dict:
    """Reads the Route tab's "Fix stop #" pins for a date: {job_id: fixed_position}.

    (2026-10-05, David's rule: a pinned job is ALWAYS that stop number until
    unpinned -- the router orders only the unfixed jobs.) Pins live on the
    route_stops rows themselves, so they survive route rebuilds; crew_id=None
    reads every crew's pins for the date. Returns {} when the column doesn't
    exist yet (database predates the migration) -- never raises."""
    try:
        conn = get_connection(db_path)
    except Exception:
        return {}
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(route_stops)").fetchall()]
        if "fixed_position" not in cols:
            return {}
        sql = ("SELECT job_id, fixed_position FROM route_stops WHERE route_date = ? "
               "AND job_id IS NOT NULL AND fixed_position IS NOT NULL")
        args = [route_date]
        if crew_id is not None:
            sql += " AND crew_id = ?"
            args.append(crew_id)
        pins = {}
        for r in conn.execute(sql, args).fetchall():
            try:
                pos = int(r["fixed_position"])
            except (TypeError, ValueError):
                continue
            if pos >= 1 and r["job_id"] not in pins:
                pins[r["job_id"]] = pos
        return pins
    except Exception:
        return {}
    finally:
        conn.close()


def _apply_fixed_positions(jobs: list, pins: dict) -> list:
    """Enforces "Fix stop #" pins on a job order. `jobs` is a list of job
    dicts (each with job_id); `pins` is {job_id: 1-based position} among the
    JOB stops (bookends are added later and never counted).

    Pinned jobs are placed at their fixed positions first; every unfixed job
    keeps its relative order from the incoming list and fills the remaining
    slots. Guards: a duplicate pin (two jobs pinned to the same number) keeps
    the one that appears first in the incoming order and treats the other as
    unfixed; an out-of-range pin clamps to the last position; pins for jobs
    not in the list are ignored. Pure function -- no DB access."""
    if not pins or not jobs:
        return list(jobs)
    n = len(jobs)
    by_id = {}
    for j in jobs:
        jid = j.get("job_id")
        if jid and jid not in by_id:
            by_id[jid] = j
    # Normalize pins: clamp to [1, n], drop unknown jobs, first-wins on dupes
    # (in incoming-list order, so the caller's own priority decides).
    taken = set()
    fixed = {}  # job_id -> 0-based index
    for j in jobs:
        jid = j.get("job_id")
        if not jid or jid not in pins or jid in fixed:
            continue
        pos = max(1, min(int(pins[jid]), n)) - 1
        if pos in taken:
            continue  # duplicate pin -- this job stays unfixed
        taken.add(pos)
        fixed[jid] = pos
    unfixed = [j for j in jobs if j.get("job_id") not in fixed]
    out = [None] * n
    for jid, pos in fixed.items():
        out[pos] = by_id[jid]
    it = iter(unfixed)
    for i in range(n):
        if out[i] is None:
            out[i] = next(it)
    return out


def _soft_window_strs(job):
    """A soft job's CUSTOMER preferred window as ("H:MM AM/PM", "H:MM AM/PM"),
    or None when the customer has none set. (2026-10-05, David's rule: the
    "outside window" check is judged ONLY against the customer's Pref. Time
    Start/End — never the job's Start/End Time, which is a scheduled slot,
    not a constraint.) Either end may be blank (a partial window such as
    "before 10:00 AM"); both blank = None = no constraint, so the job can
    never be flagged as outside it."""
    w_start = str(job.get("cust_pref_start") or "").strip()
    w_end = str(job.get("cust_pref_end") or "").strip()
    if w_start or w_end:
        return w_start, w_end
    return None



def _build_day_timeline(order, workday_start_str, workday_end_str,
                           lunch_start_str, lunch_dur_min, tolerance_min,
                           route_date=None):
    """Chains real OSRM drive times through `order`, inserting the lunch
    pause exactly once wherever the timeline naturally crosses
    lunch_start (extending whichever job is in progress, or the gap
    before the next stop if none is — spec §14.2a's "pause, not a stop"
    model, same logic reorder_route_stop uses at the single-stop scale).
    Flags — never silently drops or auto-corrects — any hard job whose
    computed arrival drifts past tolerance, and a day that runs past
    workday_end_str once lunch and drive time are both accounted for.
    Returns (list of (job, eta_str, leg_drive_min, leg_drive_miles) in
    order sequence -- leg_* is the drive FROM the previous stop TO this
      one, None for the first stop in the order -- , warnings).
      Also flags a job whose preferred_days (blank = no constraint) does not
      include route_date weekday -- PREFERRED DAY NOT MET, never blocking.
        2026-10-06 hard/lunch priority: a hard job's window takes priority
        over the lunch block — hard jobs never absorb or get pushed by lunch
        (a merely overlapping lunch is displaced around them; lunch strictly
        inside a hard service splits the service around the in-place lunch).
        The pre-pass below resolves this via _resolve_lunch_vs_hard before the
        timeline runs, and a hard service running past its window end is now
        flagged too.
      2026-10-05 anchor: when order opens with a soft home bookend (Jobs Only
      mode), the first real job arrival is anchored at Workday Start; the
      crew leave time is (Workday Start minus the first drive), derivable
        from that job own leg_drive_min."""
    warnings = []
    workday_start_dt = _parse_hhmm(workday_start_str) or _parse_hhmm("07:00")
    # 2026-10-06: resolve the lunch block against hard-job anchors BEFORE the
    # timeline runs (David's rule — a hard job's window takes priority over
    # lunch). Same shared resolution _order_with_hard_anchors uses for gap
    # geometry, so both phases agree; notes (e.g. lunch skipped) surface here.
    _tl_anchors = []
    for _aj in order:
        if str(_aj.get("schedule_type") or "").lower() == "hard" and _aj.get("job_id"):
            _aws = _parse_hhmm(_aj.get("start_time"))
            if _aws is not None:
                _tl_anchors.append({
                    "job_id": _aj.get("job_id"),
                    "label": "%s %s" % (_aj.get("job_id") or "", (_aj.get("address") or "").strip()),
                    "ws": _aws, "dur": _job_dur_min(_aj),
                    "we": _parse_hhmm(_aj.get("end_time")) if _aj.get("end_time") else None,
                })
    _tl_wde = _parse_hhmm(workday_end_str)
    _lunch_eff_str, _split_map, _lunch_notes = _resolve_lunch_vs_hard(
        _tl_anchors, lunch_start_str, lunch_dur_min, workday_start_dt, _tl_wde)
    warnings.extend(_lunch_notes)
    # (2026-10-07) David's rule: an explicit job window takes precedence
    # over working hours. The day's timeline may start before Workday
    # Start to honor a hard anchor windowed earlier in the morning —
    # working hours are a guide, not a hard requirement.
    _eff_start_dt = workday_start_dt
    for _ea in _tl_anchors:
        if _ea["ws"] < _eff_start_dt:
            _eff_start_dt = _ea["ws"]
    cur_dt = _eff_start_dt
    lunch_dt = _parse_hhmm(_lunch_eff_str) if _lunch_eff_str else None
    lunch_applied = False
    prev_lat = prev_lon = None
    results = []
    # 2026-10-05 anchor (David's rule): when order opens with a soft home
    # bookend (Jobs Only mode -- job_id None, not hard), it is a DEPARTURE
    # POINT, not a timed stop. The first real job's arrival is anchored at
    # Workday Start; the drive happened before the workday, so the leave
    # time is workday_start minus the first leg (derived wherever it's
    # displayed from that job's own leg_drive_min). Company Location's hard
    # bookend keeps the old behavior (clock in at the address at Workday
    # Start, then drive out).
    _anchor_first = (
        len(order) > 1
        and order[0].get("job_id") is None
        and str(order[0].get("schedule_type") or "").lower() != "hard"
    )

    # Preferred-day check setup (2026-10-04): route_date's weekday name once.
    # Unparseable/missing route_date disables the check (never guess a day).
    _route_wday = None
    if route_date:
        try:
            _route_wday = _dt.datetime.strptime(
                str(route_date).strip()[:10], "%Y-%m-%d").strftime("%A")
        except (ValueError, TypeError):
            _route_wday = None
    for idx, job in enumerate(order):
        leg_min, leg_miles = None, None
        if prev_lat is not None:
            leg_min, leg_miles = _osrm_leg(prev_lat, prev_lon, job["lat"], job["lon"])
            if leg_min is None:
                warnings.append(
                    f"⚠️ DRIVE TIME UNKNOWN for {job.get('job_id') or job.get('address') or 'a stop'} — "
                    f"OSRM lookup failed; its time carries the previous stop forward unchanged "
                    f"and its miles are missing from the day's total."
                )
                leg_min = 0
            cur_dt = cur_dt + _dt.timedelta(minutes=leg_min)
            if _anchor_first and idx == 1:
                # First real job after the soft home bookend: anchor its
                # arrival at Workday Start (2026-10-05, David's rule). The
                # bookend's placeholder minute and the first drive both
                # happened before the workday clock starts.
                # (2026-10-07) Exception: a hard job explicitly windowed
                # BEFORE Workday Start keeps its own window — its window
                # takes precedence over working hours, so the drive
                # happened before that window and we anchor there instead.
                _early_hard_ws = None
                if str(job.get("schedule_type") or "").lower() == "hard":
                    _early_hard_ws = _parse_hhmm(job.get("start_time"))
                    if _early_hard_ws is not None and _early_hard_ws >= workday_start_dt:
                        _early_hard_ws = None
                cur_dt = _early_hard_ws if _early_hard_ws is not None else workday_start_dt

        eta_dt = cur_dt
        # arriving ahead of it means WAIT, never start the customer's
        # appointment early. Must run before the lunch check right below,
        # since the wait itself can push the idle gap across the lunch
        # threshold. This also means the HARD TIME VIOLATION check further
        # down naturally stops firing on early arrival (eta_dt cannot be
        # earlier than committed once clamped) — it now only ever fires on
        # genuine lateness, which is the only direction a "violation"
        # actually makes sense for a committed appointment.
        _is_hard = job.get("schedule_type") == "hard" and job.get("start_time")
        _committed_floor = _parse_hhmm(job["start_time"]) if _is_hard else None
        if _committed_floor is not None and eta_dt < _committed_floor:
            eta_dt = _committed_floor

        # (2026-10-07) David's rule: an explicit SOFT window also takes
        # precedence over working hours. If the customer's window opens
        # later than the timeline's arrival, wait for it — mirrors the
        # hard committed-floor clamp above. Runs before the lunch check,
        # since the wait itself can push the gap across the lunch
        # threshold (same reason the hard clamp does).
        _window_wait = False
        if not _is_hard:
            _sw_strs = _soft_window_strs(job)
            if _sw_strs and _sw_strs[0]:
                _sws_dt = _parse_hhmm(_sw_strs[0])
                if _sws_dt is not None and eta_dt < _sws_dt:
                    eta_dt = _sws_dt
                    _window_wait = True

        dur_min = _job_dur_min(job)

        # 2026-10-06: a hard job's window takes priority over the lunch
        # block — lunch never pushes a hard job's anchoring. (The old
        # `lunch_dt <= eta_dt` gap check fired at exact equality and shoved a
        # hard job anchored exactly at lunch start a full hour late, tripping
        # a bogus HARD TIME VIOLATION.) Exception: lunch strictly inside the
        # hard job's service span ("lunch is in the middle of the job") —
        # keep lunch in place and split the service around it, preserving
        # total work time.
        _split = _split_map.get(job.get("job_id")) if _is_hard else None
        _did_split = False
        if _split is not None and eta_dt < _split[1]:
            _sls, _sle = _split
            _first_seg = (_sls - eta_dt).total_seconds() / 60.0
            if _first_seg < 0:
                _first_seg = 0.0
            if _first_seg > dur_min:
                _first_seg = dur_min
            end_dt = _sle + _dt.timedelta(minutes=(dur_min - _first_seg))
            # Lunch is consumed by the split — later soft jobs don't re-absorb it.
            lunch_applied = True
            _did_split = True
        else:
            # Lunch fell in the gap/drive time before this stop's arrival.
            # Soft jobs only — hard jobs ignore lunch for anchoring.
            # (2026-10-07) A wait FOR an explicit window is not working
            # time — lunch during that idle wait must not push the job
            # out of its own window.
            if not lunch_applied and lunch_dt is not None and lunch_dt <= eta_dt and not _is_hard and not _window_wait:
                eta_dt = eta_dt + _dt.timedelta(minutes=lunch_dur_min)
                lunch_applied = True

            end_dt = eta_dt + _dt.timedelta(minutes=dur_min)

            # Lunch fell DURING this job's own occupied time — the job absorbs
            # the pause (spec's "extend the interrupted job" model), rather
            # than being treated as blocked from spanning it. Soft jobs only;
            # a hard job either splits (above) or ignores lunch.
            if not lunch_applied and lunch_dt is not None and lunch_dt < end_dt and not _is_hard and not _window_wait:
                end_dt = end_dt + _dt.timedelta(minutes=lunch_dur_min)
                lunch_applied = True
        if _is_hard and _committed_floor is not None:
            # eta_dt can no longer be earlier than committed (clamped
            # above), so this only ever measures lateness now — abs()
            # kept only as a defensive no-op against float rounding.
            drift = abs((eta_dt - _committed_floor).total_seconds()) / 60.0
            if drift > tolerance_min:
                warnings.append(
                    f"\u26a0\ufe0f HARD TIME VIOLATION \u2014 job {job.get('job_id') or job.get('address')} committed to "
                    f"{job['start_time']} but the proposed plan can't get there until "
                    f"{eta_dt.strftime('%H:%M')} ({round(drift)} min late, "
                    f"tolerance is {tolerance_min} min)."
                )
            # 2026-10-06: a hard job's service must fit INSIDE its window —
            # arriving on time but running past the window end (e.g. the job
            # is longer than its window, or a lunch split pushes the resume
            # past the end) is still a genuine violation, never silently
            # absorbed.
            _window_end = _parse_hhmm(job.get("end_time")) if job.get("end_time") else None
            if _window_end is not None and end_dt > _window_end:
                _over = round((end_dt - _window_end).total_seconds() / 60.0)
                warnings.append(
                    f"\u26a0\ufe0f HARD TIME VIOLATION \u2014 job {job.get('job_id') or job.get('address')} committed to "
                    f"{job['start_time']}\u2013{job['end_time']} but its service runs to "
                    f"{end_dt.strftime('%H:%M')} ({_over} min past the window end)."
                )
        # Soft jobs have no single committed point — the WINDOW they're allowed
        # to be placed within is the CUSTOMER's preferred time window (Pref.
        # Time Start/End on the customer record), and ONLY that (2026-10-05,
        # David's rule). The job's own Start/End Time is a scheduled slot,
        # not a constraint, and is never consulted here. With no customer
        # window set, the job has no constraint, so it can never be "outside"
        # it — no warning. Either end of the customer window may be blank (a
        # partial window like "before 10:00 AM" constrains only its set end).
        # No tolerance added on top: the window itself already is the slack.
        # (Same rule as the Route tab's yellow highlight.)
        elif job.get("schedule_type") != "hard" and _soft_window_strs(job):
            win_start_s, win_end_s = _soft_window_strs(job)
            win_start = _parse_hhmm(win_start_s) if win_start_s else None
            win_end = _parse_hhmm(win_end_s) if win_end_s else None
            _outside = False
            if win_start is not None and win_end is not None:
                _outside = not (win_start <= eta_dt <= win_end)
            elif win_start is not None:
                _outside = eta_dt < win_start
            elif win_end is not None:
                _outside = eta_dt > win_end
            if _outside:
                warnings.append(
                    f"⚠️ SOFT WINDOW VIOLATION — job {job.get('job_id') or job.get('address')} is set for "
                    f"{win_start_s}\u2013{win_end_s} but the proposed plan arrives at "
                    f"{eta_dt.strftime('%H:%M')}, outside that window."
                )
        # Preferred-day check (2026-10-04): a non-blank preferred_days not
        # containing route_date's weekday warns — never blocks. Blank means
        # no constraint (never warn). Full names or 3-letter abbreviations
        # both accepted; anything unparseable is ignored, not guessed.
        if _route_wday:
            _pd_raw = str(job.get("preferred_days") or "").strip()
            if _pd_raw and job.get("job_id"):
                _pd_abbr = {"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday",
                            "thu": "Thursday", "fri": "Friday",
                            "sat": "Saturday", "sun": "Sunday"}
                _pd_days = set()
                for _tok in _pd_raw.replace(",", "/").split("/"):
                    _t = _tok.strip().lower()
                    if not _t:
                        continue
                    if _t in _pd_abbr:
                        _pd_days.add(_pd_abbr[_t])
                    else:
                        for _full in _pd_abbr.values():
                            if _t == _full.lower():
                                _pd_days.add(_full)
                                break
                if _pd_days and _route_wday not in _pd_days:
                    _pd_order = ["Monday", "Tuesday", "Wednesday", "Thursday",
                                 "Friday", "Saturday", "Sunday"]
                    warnings.append(
                        "\u26a0\ufe0f PREFERRED DAY NOT MET \u2014 job "
                        + str(job.get('job_id')) + " prefers "
                        + "/".join(sorted(_pd_days, key=_pd_order.index))
                        + " but is routed for " + _route_wday
                        + " (" + str(route_date) + ")."
                    )

        cur_dt = end_dt
        prev_lat, prev_lon = job["lat"], job["lon"]
        # Collect this stop: the (job, eta, leg) tuple callers iterate to write
        # route_stops. Without this append the timeline runs (warnings fire)
        # but zero stops are ever written (found live 2026-10-05).
        results.append((job, eta_dt.strftime("%H:%M"), leg_min, leg_miles))

    workday_end_dt = _parse_hhmm(workday_end_str)
    # (2026-10-07) David's rule: explicit job windows take precedence over
    # working hours, so the "day" extends to cover them — only a genuine
    # overrun past the latest explicit commitment is flagged, never a plan
    # that merely runs into explicitly-windowed time.
    _eff_wde = workday_end_dt
    _eff_wde_label = workday_end_str
    for _ej in order:
        _ej_we = None
        if str(_ej.get("schedule_type") or "").lower() == "hard":
            _ej_we = _parse_hhmm(_ej.get("end_time")) if _ej.get("end_time") else None
            if _ej_we is None:
                _ej_ws = _parse_hhmm(_ej.get("start_time"))
                if _ej_ws is not None:
                    _ej_we = _ej_ws + _dt.timedelta(minutes=_job_dur_min(_ej))
        else:
            _ej_sw = _soft_window_strs(_ej)
            if _ej_sw and _ej_sw[1]:
                _ej_we = _parse_hhmm(_ej_sw[1])
        if _ej_we is not None and (_eff_wde is None or _ej_we > _eff_wde):
            _eff_wde = _ej_we
            _eff_wde_label = _ej_we.strftime("%H:%M")
    if _eff_wde is not None and cur_dt > _eff_wde:
        overflow = round((cur_dt - _eff_wde).total_seconds() / 60.0)
        warnings.append(
            f"⚠️ DAY DOES NOT FIT — the proposed plan runs about {overflow} min past "
            f"the day's latest committed time ({_eff_wde_label})."
        )
    return results, warnings




def _wrap_with_home_bookends(results, home_lat, home_lon, start_crew, end_crew):
    """Company Location mode + an explicit start/end choice (2026-09-19):
    puts a Home row before and after an already-built day timeline WITHOUT
    letting either one take part in it.

    In Company Location mode the configured Start/End Address is a real,
    scheduled stop — hard-anchored at Workday Start Time. Home is only where
    the day physically begins and ends, so it is a bookend AROUND that
    stop, not another stop inside the schedule: it has no dwell time, is
    never checked for violations, and never pushes anything later. Feeding
    it through _build_day_timeline as a first row would do exactly that —
    the clock starts at Workday Start, the drive to the company address
    adds minutes, and the hard clock-in would then falsely trip HARD TIME
    VIOLATION. So the timeline is built first, and the home legs are
    derived from it: leave home early enough to reach the first row at its
    own ETA; the arrival home is the last row's finish plus the drive back.

    Returns (new_results, extra_warnings). new_results has the same
    (job, eta, leg_min, leg_miles) shape _build_day_timeline returns, with
    the first real row's leg now being the drive FROM home (it was None —
    nothing came before it) and a Home row at each end."""
    if not results:
        return results, []

    warnings = []

    def _home(crew):
        return {"job_id": None, "cust_id": None, "address": "Home",
                "lat": home_lat, "lon": home_lon, "crew": crew,
                "schedule_type": "soft"}

    first_job, first_eta, _fl, _fm = results[0]
    last_job, last_eta, last_leg_min, last_leg_miles = results[-1]

    in_min, in_miles = _osrm_leg(home_lat, home_lon, first_job["lat"], first_job["lon"])
    out_min, out_miles = _osrm_leg(last_job["lat"], last_job["lon"], home_lat, home_lon)
    for leg, where in ((in_min, "the drive from Home to the first stop"),
                       (out_min, "the drive from the last stop back to Home")):
        if leg is None:
            warnings.append(f"⚠️ DRIVE TIME UNKNOWN for {where} — OSRM lookup failed; "
                            f"its time is shown as zero and its miles are missing from the day's total.")
    in_min_n = in_min or 0
    out_min_n = out_min or 0

    first_dt = _parse_hhmm(first_eta)
    last_dt = _parse_hhmm(last_eta)
    try:
        dur = float(last_job.get("duration") or 0)
        if "hour" in (last_job.get("duration_unit") or "min").lower():
            dur *= 60
    except (TypeError, ValueError):
        dur = 0.0

    depart = (first_dt - _dt.timedelta(minutes=in_min_n)) if first_dt else None
    arrive = (last_dt + _dt.timedelta(minutes=dur + out_min_n)) if last_dt else None

    new_results = [(_home(start_crew), depart.strftime("%H:%M") if depart else first_eta, None, None),
                   (first_job, first_eta, in_min, in_miles)]
    new_results.extend(results[1:])
    new_results.append((_home(end_crew), arrive.strftime("%H:%M") if arrive else last_eta,
                        out_min, out_miles))
    return new_results, warnings


def db_suggest_route_schedule(db_path: str, route_date: str, crew: str, actor: str,
                               single_crew: bool = False, origin_lat=None, origin_lon=None) -> str:
    """The "Get AI Suggestion" button's backend (spec §14.4, Mode A /
    Phase 12). Reads route_date's jobs (optionally scoped to one crew;
    blank means every crew, each scheduled independently — see the
    mixed-crew note below), splits hard from soft by schedule_type,
    builds a geographically-reasonable visit order (nearest-neighbor)
    then repairs it so hard jobs never violate their OWN relative
    chronological order, chains real drive times plus the lunch pause
    into a full-day timeline, and writes the resulting stops straight
    into route_stops via db_write_route_stops — the same function Mode
    B's manual edits already use, so the proposal appears in the Route
    tab's normal editable list/map immediately (spec §14.3: reviewing
    and hand-adjusting an AI proposal is just Mode B applied on top of
    it, not a separate approval surface).

    Mixed-crew builds (crew=""): every crew's jobs are scheduled
    independently — nearest-neighbor + repair + timeline each run once
    per crew, never combining two different people's stops into one
    route, matching db_write_route_stops' own per-(route_date, crew_id)
    partitioning and spec §14.9's "fixed crew assignment for v1" decision
    (the Advisor never reassigns a job to a different crew to balance the
    day).

    single_crew (spec §6.3, personal mode): when True, this per-crew
    independence is bypassed entirely — ALL of the date's geocoded jobs
    are scheduled together as ONE person's day, regardless of whatever
    text happens to be in each job's own Crew / Technician field, and
    written under one shared crew_id (see db_write_route_stops). A
    personal install is a one-crew show even if multiple employee names
    get typed into individual jobs; splitting them into independent
    simultaneous "days" would imply one person is in two places at
    once. Server-mode callers never pass this.

    A job missing a geocoded lat/lon is left off the plan entirely and
    listed as NOT PLACED in the response — never silently dropped without
    saying so, and never guessed at with a fabricated location.

    This never writes schedule_type — approving a soft job's suggested
    time (a separate step, the Route tab's existing Approve button) does
    not promote it to hard, per spec §14.9's decision.

    Returns a ✅ summary (per-crew stop order + times) with any HARD TIME
    VIOLATION / SOFT WINDOW VIOLATION / DRIVE TIME UNKNOWN / DAY DOES NOT
    FIT warnings and a NOT PLACED list appended, or a ✅ "nothing to
    suggest" message if the date/crew has no jobs at all.
    """
    # R-056: in server mode a blank crew lists a shared job once per person.
    all_jobs = db_get_jobs_for_route(db_path, route_date, crew, expand_multi=not single_crew)
    if not all_jobs:
        scope = f" for crew '{crew}'" if crew else ""
        return f"✅ No jobs scheduled on {route_date}{scope} — nothing to suggest."

    missing = [j for j in all_jobs if j.get("lat") is None or j.get("lon") is None]
    geocoded = [j for j in all_jobs if j.get("lat") is not None and j.get("lon") is not None]
    if not geocoded:
        return (f"❌ None of {len(all_jobs)} job(s) on {route_date} have a geocoded address yet — "
                f"nothing can be placed on a map-based plan. Run build_daily_route once first "
                f"(it geocodes as it goes), then try suggesting again.")

    workday_start = db_read_settings_workday_start(db_path)
    workday_end = db_read_settings_workday_end(db_path)
    lunch_start = db_read_settings_lunch_break_start(db_path)
    lunch_dur = db_read_settings_lunch_break_duration_min(db_path)
    tolerance = db_read_settings_hard_time_tolerance_min(db_path)
    origin = _resolve_origin(db_path, origin_lat, origin_lon)

    # spec §6.3/§14 follow-up (2026-09-17): when Route Origin Mode is
    # "Company Location", the Start/End Address is now a genuine
    # SCHEDULED stop — not just an informational bookend the Route tab
    # shows regardless of this setting (see _getRouteOriginInfo in
    # jobs/index.html) — with real drive-time impact on every downstream
    # ETA, for a business that requires the crew to physically clock in
    # there each morning. route_stops.job_id is a nullable FK (SQLite
    # skips the FK check on NULL, same pattern already used for jobs/
    # invoices/quotes.customer_id — see db_schema.py), so this genuinely
    # writes as stop #1 (and the final stop) with no schema change
    # needed.
    #
    # Mileage-tracking follow-up (2026-09-19): "Jobs Only" mode is no
    # longer a no-op here either. Real-world mileage-deduction rule this
    # models: ordinary commuting to a FIXED business address is never
    # deductible, but for a business with no separate office, home
    # qualifies as the principal place of business — so the drive from
    # home to the first job, and from the last job back home, IS real
    # deductible business mileage, same category as Company Location's
    # stop, just a different address source (home, not the business
    # Start/End Address) and resolved differently (live GPS first, then
    # the owner's configured Home Address, see
    # _resolve_jobs_only_origin) since there's no dedicated "home
    # address" Settings field the way Start/End Address is one. No real
    # commitment is attached to leaving home at a particular time, so
    # unlike Company Location's hard-anchored start, both ends of this
    # bookend are soft — see the schedule_type choice below.
    origin_mode = db_read_route_origin_mode(db_path).strip().lower()
    start_end_template = None
    if origin_mode == "company location":
        addr = db_read_route_address(db_path)
        if addr:
            coords = _geocode(addr)
            if coords:
                start_end_template = {
                    "job_id": None, "cust_id": None, "address": addr,
                    "lat": coords[0], "lon": coords[1],
                    # A near-zero, not literally zero, duration — a real
                    # dwell time of 0 would hit _build_day_timeline's
                    # "unknown duration" fallback (falsy duration → 60
                    # min default), which is exactly wrong here: this is
                    # a known, deliberately brief clock-in/clock-out
                    # waypoint, not an unknown one.
                    "duration": 1, "duration_unit": "min",
                }
    else:
        # crew_name=crew (the top-level scope this WHOLE call was made
        # for, e.g. "Get AI Suggestion" for one specific crew's day) —
        # this resolution runs ONCE, before the per-crew split below, not
        # once per crew_name inside that loop. A blank crew (server mode
        # asking for every crew's day in one call) has no single crew to
        # resolve a home address for, so it correctly gets no bookend in
        # that specific case — same "don't guess" posture as everywhere
        # else in this resolver.
        home = _resolve_jobs_only_origin(origin_lat, origin_lon, crew_name=crew, is_server_mode=not single_crew,
                                         db_path=db_path)
        if home:
            start_end_template = {
                "job_id": None, "cust_id": None, "address": "Home",
                "lat": home[0], "lon": home[1],
                "duration": 1, "duration_unit": "min",
            }

    if single_crew:
        by_crew = {"(unassigned)": geocoded}
    else:
        by_crew = {}
        for j in geocoded:
            by_crew.setdefault(j.get("crew") or "(unassigned)", []).append(j)

    all_warnings = []
    stops_to_write = []
    summary_lines = []
    for crew_name, crew_jobs in by_crew.items():
        # workday_start_min feeds _nn_order's estimated-arrival seed
        # ranking (see that function's own docstring for the full
        # rationale) — falls back to its own 420 (07:00) default if
        # workday_start somehow doesn't parse, same fallback
        # _build_day_timeline itself already uses two lines below.
        _wds_dt = _parse_hhmm(workday_start)
        _workday_start_min = (_wds_dt.hour * 60 + _wds_dt.minute) if _wds_dt is not None else 420
        # 2026-10-06: anchor-aware ordering — hard jobs hold their windows as
        # fixed anchors and soft jobs fill the gaps around them (and around
        # the lunch block, which hard jobs may displace). Falls back to the
        # old _repair_hard_order(_nn_order(...)) when no hard job carries a
        # committable start time, so anchor-free days behave exactly as before.
        _first_arrival_at_wds = not (
            origin_mode == "company location" and db_read_route_address(db_path).strip())
        order = _order_with_hard_anchors(
            crew_jobs, origin=origin, workday_start_min=_workday_start_min,
            workday_start_str=workday_start, workday_end_str=workday_end,
            lunch_start_str=lunch_start, lunch_dur_min=lunch_dur,
            first_arrival_at_wds=_first_arrival_at_wds)
        # 2026-10-05 "Fix stop #" pins (Route tab): pinned jobs hold their
        # fixed positions; the nearest-neighbor heuristic only orders the
        # unfixed jobs around them.
        _pin_crew = None if single_crew else ("" if crew_name == "(unassigned)" else crew_name)
        _pins = _read_route_pins(db_path, route_date, _pin_crew)
        if _pins:
            order = _apply_fixed_positions(order, _pins)

        if start_end_template:
            # A fresh dict per crew group — never share/mutate one dict
            # object across groups (server mode can have several).
            # Company Location's START is a hard-anchored checkpoint at
            # exactly Workday Start Time, matching a real "clock in at
            # this time" commitment — the same mechanism a real hard job
            # uses, so it gets the same HARD TIME VIOLATION guard for
            # free if the rest of the timeline somehow can't actually
            # land there. Jobs Only's home bookend has no such real
            # commitment (see the comment above this block), so both
            # ends stay soft there. END never has a committed time of
            # its own either way — its ETA is simply whatever real drive
            # time from the last job computes to, the actual
            # return-to-base time this business needs to know.
            is_company_location = (origin_mode == "company location")
            start_copy = dict(start_end_template,
                               schedule_type="hard" if is_company_location else "soft",
                               start_time=workday_start if is_company_location else None)
            end_copy = dict(start_end_template, schedule_type="soft", start_time=None)
            order = [start_copy] + order + [end_copy]
        results, warnings = _build_day_timeline(order, workday_start, workday_end, lunch_start, lunch_dur, tolerance,
                                                route_date=route_date)
        all_warnings.extend(warnings)
        if not single_crew:
            summary_lines.append(f"\n{crew_name} ({len(results)} stop(s)):")
        for i, (job, eta, leg_min, leg_miles) in enumerate(results, start=1):
            # Real bug found live (2026-09-19 mileage-tracking follow-up,
            # corrected 2026-09-20): the START bookend is only a real,
            # visible, numbered stop for Company Location mode (a genuine
            # "clock in here" location). For the Jobs-Only home-address
            # fallback, home was never supposed to be a visible stop at
            # all — only scheduled jobs are stops in that mode. The real
            # first job's OWN leg (leg_min/leg_miles right here) already
            # carries the home->job1 mileage correctly regardless of
            # whether this bookend gets written — skipping it is not a
            # loss of data, it's removing a stop that was never supposed
            # to exist. The trailing END/return-to-home bookend is
            # deliberately NOT skipped here (see the loop's own last
            # iteration) — it's the only place that leg's mileage can be
            # stored at all, and the client hides it from the visible
            # list itself (see jobs/index.html's renderRouteMapAndList).
            if i == 1 and job.get("job_id") is None and not is_company_location:
                continue
            lock = " 🔒" if job.get("schedule_type") == "hard" else ""
            summary_lines.append(f"  {i}. {eta}  {job.get('address') or job.get('job_id')}{lock}")
            stops_to_write.append({
                "crew": "" if crew_name == "(unassigned)" else crew_name,
                "job_id": job.get("job_id"), "cust_id": job.get("cust_id"),
                "address": job.get("address"), "lat": job.get("lat"), "lon": job.get("lon"),
                "arrival": eta, "leg_drive_min": leg_min, "leg_drive_miles": leg_miles,
                "map_url": None,
            })

    cleared = db_write_route_stops(db_path, route_date, stops_to_write, actor, single_crew=single_crew)

    if single_crew:
        scope = ""
    else:
        scope = f" — crew '{crew}'" if crew else " — all crews"
    header = f"✅ Proposed route for {route_date}{scope} ({len(stops_to_write)} stop(s), replacing {cleared} previous row(s)):"
    body = "\n".join(summary_lines)
    warn_block = ("\n\n" + "\n".join(all_warnings)) if all_warnings else ""
    unplaced_block = ""
    if missing:
        names = ", ".join(j.get("job_id") or j.get("address") or "?" for j in missing)
        unplaced_block = f"\n\n⚠️ NOT PLACED (no geocoded location yet): {names}"
    footer = "\n\nOpen the Route tab to review, drag to adjust, and Approve when ready."
    return header + body + warn_block + unplaced_block + footer


# ── Real drive-time/distance matrix — spec §14.12, "let a full reasoning
# pass build the route" follow-up (2026-09-18) ──────────────────────────────
def _day_start_end_point(db_path: str, crew: str, single_crew: bool):
    """R-064: where the day starts and ends, resolved EXACTLY as
    db_apply_route_order resolves it with no caller coordinates (what AI
    Routing passes): Company Location → the geocoded Start/End Address;
    Jobs Only → the home point from _resolve_jobs_only_origin. Returns
    (lat, lon, label) or None."""
    try:
        mode = db_read_route_origin_mode(db_path).strip().lower()
        if mode == "company location":
            addr = db_read_route_address(db_path)
            pt = _geocode(addr) if addr else None
            return (pt[0], pt[1], f"START/END (business: {addr})") if pt else None
        home = _resolve_jobs_only_origin(None, None, crew_name=crew, is_server_mode=not single_crew,
                                         db_path=db_path)
        return (home[0], home[1], "START/END (Home)") if home else None
    except Exception:
        return None


def db_route_drive_matrix(db_path: str, route_date: str, crew: str = "", single_crew: bool = False) -> str:
    """One real OSRM call (the /table endpoint — same free, no-API-key
    service every other routing tool here already uses) returning the full
    pairwise drive-time/distance matrix between every one of route_date's
    geocoded jobs. Exists so a caller doing its OWN reasoning about visit
    order — a human, or a Claude Code session with no code-execution tool of
    its own — doesn't have to guess at drive times or make N² separate
    /route calls; one table call gets every pair at once, then
    apply_route_order() writes whatever order that reasoning lands on.

    A job with no geocoded lat/lon is left out of the matrix and listed
    separately as NOT PLACED, never silently dropped or guessed at — same
    posture as every other tool here.

    Returns a formatted table (rows/cols both labeled by JobID + address)
    of minutes, then a second table of miles, or a ✅ "nothing to matrix"
    message if there are fewer than 2 geocoded jobs to compare.
    """
    all_jobs = db_get_jobs_for_route(db_path, route_date, crew)
    if not all_jobs:
        scope = f" for crew '{crew}'" if crew else ""
        return f"✅ No jobs scheduled on {route_date}{scope} — nothing to matrix."

    missing = [j for j in all_jobs if j.get("lat") is None or j.get("lon") is None]
    geocoded = [j for j in all_jobs if j.get("lat") is not None and j.get("lon") is not None]
    if len(geocoded) < 2:
        return (f"❌ Only {len(geocoded)} of {len(all_jobs)} job(s) on {route_date} are geocoded — "
                f"need at least 2 to build a matrix. Run build_daily_route once first "
                f"(it geocodes as it goes), then try again.")

    # R-064 (2026-09-29): the AI Routing run reasons from this matrix, and it
    # used to hold job-to-job legs only — the drive from the day's start to the
    # first job and from the last job back were invisible, so the AI picked
    # orders by job-to-job time alone (E2E MILES-04, Jobs Only: 16.16 mi where
    # the same jobs in another order were 15.92 mi). The start/end point is now
    # the first row/column.
    start = _day_start_end_point(db_path, crew, single_crew)
    points = list(geocoded)
    if start:
        points = [{"job_id": None, "address": start[2], "lat": start[0], "lon": start[1]}] + points
    coord_str = ";".join(f"{j['lon']},{j['lat']}" for j in points)
    try:
        resp = requests.get(
            f"http://router.project-osrm.org/table/v1/driving/{coord_str}",
            params={"annotations": "duration,distance"}, timeout=30,
        ).json()
    except Exception as exc:
        return f"❌ OSRM /table lookup failed: {exc}"
    if resp.get("code") != "Ok":
        return f"❌ OSRM /table lookup failed: {resp.get('code', 'unknown error')}"

    durations, distances = resp["durations"], resp["distances"]
    labels = [(f"{j['job_id']} ({j.get('address') or '?'})" if j.get("job_id") else j["address"])
              for j in points]
    n = len(labels)

    def _render(matrix, unit_fn, unit_label):
        lines = [f"Drive {unit_label} (row = FROM, column = TO):", ""]
        header = "".join(f"{i + 1:>8}" for i in range(n))
        lines.append(" " * 34 + header)
        for i in range(n):
            row = "".join(f"{unit_fn(matrix[i][j]):8.1f}" for j in range(n))
            lines.append(f"{i + 1:>2}. {labels[i][:28]:28}{row}")
        return "\n".join(lines)

    min_table = _render(durations, lambda s: s / 60.0, "MINUTES")
    mi_table = _render(distances, lambda m: m / 1609.344, "MILES")
    legend = "\n".join(f"  {i + 1}. {lbl}" for i, lbl in enumerate(labels))
    unplaced_block = ""
    if missing:
        names = ", ".join(j.get("job_id") or j.get("address") or "?" for j in missing)
        unplaced_block = f"\n\n⚠️ NOT IN MATRIX (no geocoded location yet): {names}"

    start_note = ""
    if start:
        start_note = ("\n\nRow/column 1 is where the day STARTS and ENDS (not a stop). Every order "
                      "begins with a drive FROM it to the first job and ends with a drive back TO it "
                      "— compare orders by the whole day, including those two legs.")
    return f"{min_table}\n\n{mi_table}\n\nLegend:\n{legend}{start_note}{unplaced_block}"


# ── apply_route_order — spec §14.12, real-reasoning route writer ──────────
def db_apply_route_order(db_path: str, route_date: str, stop_order: str, crew: str,
                          actor: str, single_crew: bool = False,
                          origin_lat=None, origin_lon=None) -> str:
    """Writes a CALLER-SUPPLIED visit order into route_stops, instead of
    suggest_route_schedule's own nearest-neighbor guess. This is the
    "let something that can actually reason about the day — a human or a
    full Claude Code pass, not the free nearest-neighbor heuristic — decide
    the order, then have the app do the honest mechanical part (real drive
    times, lunch placement, hard/soft violation checking, persistence)"
    tool: it hands `stop_order`'s sequence straight to the exact same
    `_build_day_timeline` engine suggest_route_schedule already uses, so
    the OUTPUT format, warnings (HARD TIME VIOLATION / SOFT WINDOW
    VIOLATION / DRIVE TIME UNKNOWN / DAY DOES NOT FIT), and Route tab
    behavior (map, list, Approve button) are all identical either way —
    the only thing that differs between the two tools is who chose the
    order.

    stop_order: a comma-separated list of JobIDs in the exact order they
    should be visited, e.g. "JOB-0021,JOB-0018,JOB-0019,JOB-0023,JOB-0020,
    JOB-0022". Every ID must belong to a geocoded job actually scheduled
    on route_date (optionally scoped to crew) — an unknown or duplicate ID
    is rejected outright with a clear error, since a caller capable of
    reasoning about order is also capable of copying real JobIDs, and
    silently dropping or ignoring one would hide a real mistake instead of
    surfacing it. A geocoded job that exists for this date/crew but is
    simply left OUT of stop_order is not an error — it's reported as NOT
    PLACED, same posture as build_daily_route/suggest_route_schedule, since
    deliberately deferring a job to another day is a legitimate choice.

    single_crew/origin_lat/origin_lon: same meaning as
    db_suggest_route_schedule's own arguments — origin currently has no
    effect on `_build_day_timeline` itself (which has no concept of a
    pre-first-stop leg) but is accepted for interface symmetry with the
    other two route-building tools and future use.
    """
    all_jobs = db_get_jobs_for_route(db_path, route_date, crew)
    if not all_jobs:
        scope = f" for crew '{crew}'" if crew else ""
        return f"✅ No jobs scheduled on {route_date}{scope} — nothing to apply an order to."

    missing = [j for j in all_jobs if j.get("lat") is None or j.get("lon") is None]
    geocoded = [j for j in all_jobs if j.get("lat") is not None and j.get("lon") is not None]
    by_id = {j["job_id"]: j for j in geocoded if j.get("job_id")}

    requested = [s.strip() for s in stop_order.split(",") if s.strip()]
    if not requested:
        return "❌ stop_order is empty — pass a comma-separated list of JobIDs in visit order."

    seen, dupes, unknown = set(), [], []
    order = []
    for job_id in requested:
        if job_id in seen:
            dupes.append(job_id)
            continue
        seen.add(job_id)
        job = by_id.get(job_id)
        if job is None:
            unknown.append(job_id)
            continue
        order.append(job)

    if unknown or dupes:
        lines = ["❌ stop_order has problems — nothing was written:"]
        if unknown:
            lines.append(f"  Not a geocoded job on {route_date}" +
                         (f" for crew '{crew}'" if crew else "") + f": {', '.join(unknown)}")
        if dupes:
            lines.append(f"  Listed more than once: {', '.join(dupes)}")
        lines.append("Fix stop_order and try again — every ID must appear exactly once.")
        return "\n".join(lines)

    # 2026-10-05 "Fix stop #" pins (Route tab): a pinned job holds its fixed
    # position no matter what order the caller asked for -- pins are re-applied
    # here as a server-side guard, so even an AI that ignores the prompt
    # constraint cannot violate them. Unfixed jobs keep the caller order.
    _ap_pins = _read_route_pins(db_path, route_date, None)
    if _ap_pins:
        order = _apply_fixed_positions(order, _ap_pins)

    workday_start = db_read_settings_workday_start(db_path)
    workday_end = db_read_settings_workday_end(db_path)
    lunch_start = db_read_settings_lunch_break_start(db_path)
    lunch_dur = db_read_settings_lunch_break_duration_min(db_path)
    tolerance = db_read_settings_hard_time_tolerance_min(db_path)

    # Same Company Location start/end bookend db_suggest_route_schedule
    # already uses (see its own comment for the full rationale) — added
    # here too after a real bug found live: _build_day_timeline has no
    # origin concept of its own, so without this, stop 1's own
    # leg_drive_min/leg_drive_miles came back None with no warning either
    # (there was no previous point to even attempt a leg from, so the
    # DRIVE TIME UNKNOWN check never triggered) — the Route tab's
    # cumulative "Total" miles/time silently excluded the very first leg
    # of the day — and the day's real return-to-base drive was never
    # computed or written at all, so there was no return-to-home row.
    #
    # Mileage-tracking follow-up (2026-09-19): "Jobs Only" mode now also
    # gets a symmetric home-based round-trip bookend when a location is
    # available — see db_suggest_route_schedule's own comment on this
    # same block for the full home-office mileage rationale. origin_lat/
    # origin_lon here is live device GPS captured client-side the moment
    # "Run AI Routing"/"Get AI Suggestion" was tapped (start_ai_routing
    # passes it straight through into the reasoning prompt it hands this
    # tool); with neither GPS nor a configured Home Address available,
    # this is still a no-op, matching the pre-existing behavior exactly.
    origin_mode = db_read_route_origin_mode(db_path).strip().lower()
    start_end_template = None
    if origin_mode == "company location":
        addr = db_read_route_address(db_path)
        if addr:
            coords = _geocode(addr)
            if coords:
                start_end_template = {
                    "job_id": None, "cust_id": None, "address": addr,
                    "lat": coords[0], "lon": coords[1],
                    "duration": 1, "duration_unit": "min",
                }
    else:
        home = _resolve_jobs_only_origin(origin_lat, origin_lon, crew_name=crew, is_server_mode=not single_crew,
                                         db_path=db_path)
        if home:
            start_end_template = {
                "job_id": None, "cust_id": None, "address": "Home",
                "lat": home[0], "lon": home[1],
                "duration": 1, "duration_unit": "min",
            }
    if start_end_template:
        # db_suggest_route_schedule assigns its per-crew loop's own
        # crew_name to every stop it writes (bookends included), so a
        # crew's bookends always share its stops' crew_id. apply_route_order
        # has no such loop — stop_order is one flat sequence — so a bookend
        # with no crew of its own would default to "(unassigned)" while the
        # real jobs keep their real crew, splitting them into different
        # crew_id groups when db_write_route_stops partitions by crew (real
        # bug caught by this file's own tests: sorted-by-crew, "(unassigned)"
        # sorts before a real crew name, so BOTH bookends would land
        # adjacent to each other instead of bracketing that crew's stops).
        # The explicit crew scope wins when given; otherwise the first/last
        # real job's own crew is the reasonable choice — whoever is
        # actually AT the origin at day-start/day-end.
        bookend_crew = crew or order[0].get("crew") or "(unassigned)"
        end_crew = crew or order[-1].get("crew") or "(unassigned)"
        # Company Location's start is hard-anchored (a real "clock in by
        # this time" commitment); Jobs Only's home bookend has no such
        # commitment, so both ends stay soft there — see
        # db_suggest_route_schedule's matching comment.
        is_company_location = (origin_mode == "company location")
        start_copy = dict(start_end_template,
                           schedule_type="hard" if is_company_location else "soft",
                           start_time=workday_start if is_company_location else None,
                           crew=bookend_crew)
        end_copy = dict(start_end_template, schedule_type="soft", start_time=None,
                         crew=end_crew)
        order = [start_copy] + order + [end_copy]

    results, warnings = _build_day_timeline(order, workday_start, workday_end, lunch_start, lunch_dur, tolerance,
                                            route_date=route_date)

    # Company Location mode + an explicit start/end choice from the caller
    # (the AI Route picker, 2026-09-19): the company Start/End Address stays
    # a real scheduled stop (built above), and the chosen home/GPS point is
    # added AROUND it as a plain bookend — not a stop, never part of the
    # timeline. See _wrap_with_home_bookends for why it can't simply be
    # another row fed through _build_day_timeline.
    if (origin_mode == "company location" and start_end_template
            and origin_lat is not None and origin_lon is not None):
        results, _home_warnings = _wrap_with_home_bookends(
            results, origin_lat, origin_lon,
            start_crew=order[0].get("crew") or "(unassigned)",
            end_crew=order[-1].get("crew") or "(unassigned)",
        )
        warnings = list(warnings) + _home_warnings

    stops_to_write = []
    summary_lines = []
    for i, (job, eta, leg_min, leg_miles) in enumerate(results, start=1):
        # Real bug found live (2026-09-19 mileage-tracking follow-up,
        # corrected 2026-09-20): a home-only bookend (job_id is None AND
        # its own address is literally "Home" — the marker both the
        # Jobs-Only start_end_template above and _wrap_with_home_bookends
        # use, as opposed to Company Location's REAL business-address
        # bookend, which keeps its actual configured address string and
        # must stay a real, visible, numbered stop) was never supposed to
        # be a visible stop at all — only scheduled jobs (and, in Company
        # Location mode, the business address) are stops. Skip writing it
        # as a row entirely when it's the leading entry — the real first
        # job's OWN leg (leg_min/leg_miles right here) already carries
        # that mileage correctly with no separate row needed. The
        # trailing return-to-home entry is NOT skipped (see the check
        # below only fires for i==1) — it's the only place that leg's
        # mileage can be stored, and the client hides it from the visible
        # list itself (see jobs/index.html's renderRouteMapAndList).
        if i == 1 and job.get("job_id") is None and job.get("address") == "Home":
            continue
        lock = " 🔒" if job.get("schedule_type") == "hard" else ""
        summary_lines.append(f"  {i}. {eta}  {job.get('address') or job.get('job_id')}{lock}")
        stops_to_write.append({
            "crew": "" if single_crew else (job.get("crew") or "(unassigned)"),
            "job_id": job.get("job_id"), "cust_id": job.get("cust_id"),
            "address": job.get("address"), "lat": job.get("lat"), "lon": job.get("lon"),
            "arrival": eta, "leg_drive_min": leg_min, "leg_drive_miles": leg_miles,
            "map_url": None,
        })

    cleared = db_write_route_stops(db_path, route_date, stops_to_write, actor, single_crew=single_crew)

    scope = "" if single_crew else (f" — crew '{crew}'" if crew else " — all crews")
    header = f"✅ Applied route for {route_date}{scope} ({len(stops_to_write)} stop(s), replacing {cleared} previous row(s)):"
    body = "\n".join(summary_lines)
    warn_block = ("\n\n" + "\n".join(warnings)) if warnings else ""
    unplaced_block = ""
    left_out = [j for j in geocoded if j.get("job_id") not in seen]
    all_unplaced = missing + left_out
    if all_unplaced:
        names = ", ".join(j.get("job_id") or j.get("address") or "?" for j in all_unplaced)
        unplaced_block = f"\n\n⚠️ NOT PLACED (left out of stop_order, or not geocoded): {names}"
    footer = "\n\nOpen the Route tab to review, drag to adjust, and Approve when ready."
    return header + body + warn_block + unplaced_block + footer


def db_reorder_and_replan(db_path: str, stop_id, new_position, actor: str,
                          restrict: bool = False, crew_name: str = "",
                          is_server_mode: bool = False) -> str:
    """Route-tab drag-and-drop / ▲▼ (2026-09-21): moves ONE stop to a new position,
    then RE-PLANS THE WHOLE DAY in that order with the same planner
    (_build_day_timeline, via db_apply_route_order) Route Today and Run AI Route
    use — so arrival times account for how long every job takes, waiting for a
    hard job's committed start, lunch, and the day's start/end, and every
    HARD TIME / SOFT WINDOW warning is judged on real times.

    Why this exists: db_reorder_route_stop (the older "narrow nudge") re-times ONLY
    the moved stops and chains drive time alone — it never adds the time spent AT
    each job. Live symptom: swapping stops 3 and 4 gave both an 8:05 arrival
    (stop 2's 8:01 + a 4-minute drive, ignoring stop 2's hour-long job), which
    lit up red/yellow "off schedule" flags — and dragging them back did not
    clear them, because putting them back re-timed them the same wrong way
    instead of restoring the original plan. Re-planning the whole day makes the
    result depend only on the ORDER, so moving a stop and moving it back always
    returns the identical times.

    Same validation and crew scoping as db_reorder_route_stop (stop must exist,
    a field_crew caller may only move a stop on their own route, position is
    clamped to the route length, moving a stop to where it already is is a
    no-op). Falls back to that narrow nudge — never fails the drag — when the
    moved stop is a bookend (no job) or the day can't be re-planned (e.g. a
    stop's job was deleted or lost its coordinates).

    Only the stops already on this route are (re)placed — jobs that are not on it
    are left alone and not reported, since a drag never adds or removes a job.
    """
    import re as _re
    from db_write_ops import db_reorder_route_stop, _crew_name_in_cell

    stop_id_str = str(stop_id or "").strip()
    try:
        new_position = int(new_position)
    except (TypeError, ValueError):
        return "❌ new_position must be a whole number (the target Stop # position)."
    if new_position < 1:
        return "❌ new_position must be 1 or greater."

    conn = get_connection(db_path)
    try:
        moving = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id_str,)).fetchone()
        if not moving:
            return f"❌ No route stop found with ID '{stop_id_str}'."
        if restrict:
            row_crew = str(moving["crew_id"] or "").strip().lower()
            if not _crew_name_in_cell(row_crew, crew_name):
                return ("❌ Reordering this route stop requires it to be on your own route. "
                        "Field crew cannot reorder a coworker's route stop.")
        route_date = moving["route_date"]
        crew_id = moving["crew_id"]
        all_stops = conn.execute(
            "SELECT * FROM route_stops WHERE route_date = ? AND crew_id = ? ORDER BY stop_number",
            (route_date, crew_id),
        ).fetchall()
    finally:
        conn.close()

    old_position = moving["stop_number"]
    new_position = min(new_position, len(all_stops))
    if new_position == old_position:
        return f"✅ Route stop {stop_id_str} is already at position {old_position} — nothing to change."

    def _narrow_nudge():
        return db_reorder_route_stop(db_path, stop_id, new_position, actor, restrict=restrict,
                                     crew_name=crew_name, is_server_mode=is_server_mode)

    if not moving["job_id"]:
        return _narrow_nudge()      # a bookend, not a job — nothing to re-plan around

    by_id = {r["id"]: r for r in all_stops}
    ids = [r["id"] for r in all_stops]
    ids.remove(moving["id"])
    ids.insert(new_position - 1, moving["id"])
    job_order = [by_id[i]["job_id"] for i in ids if by_id[i]["job_id"]]

    # 2026-10-05 "Fix stop #" pin follows the stop: if the moved stop was
    # pinned, its pin moves to the new job-position (1-based among job
    # stops, bookends excluded) so the pin still describes where the stop
    # now sits. This UPDATE runs before db_apply_route_order below, whose
    # pin enforcement then reads the moved pin and keeps the stop there.
    _was_pinned = "fixed_position" in moving.keys() and moving["fixed_position"] is not None
    if _was_pinned:
        _new_pin_pos = job_order.index(moving["job_id"]) + 1
        _pin_conn = get_connection(db_path)
        try:
            _ensure_fixed_position_column(_pin_conn)
            _pin_conn.execute(
                "UPDATE route_stops SET fixed_position = ? WHERE route_date = ? AND job_id = ?",
                (_new_pin_pos, route_date, moving["job_id"]),
            )
            _pin_conn.commit()
        finally:
            _pin_conn.close()

    crew_txt = str(crew_id or "").strip()
    crew_arg = crew_txt if (is_server_mode and crew_txt not in ("", "(unassigned)")) else ""
    result = db_apply_route_order(db_path, route_date, ",".join(job_order), crew_arg, actor,
                                  single_crew=not is_server_mode)
    if not result.startswith("✅ Applied route"):
        return _narrow_nudge()      # nothing was written (failed, or no jobs found) — safe to fall back

    # A drag never adds or removes a job, so "NOT PLACED" (other crews' jobs, or ones
    # deferred/ungeocoded earlier) would just be noise after every drag.
    result = _re.sub(r"\n\n⚠️ NOT PLACED[^\n]*", "", result)
    return result.replace("✅ Applied route for", "✅ Moved stop and re-planned the day for", 1)


def db_replan_current_order(db_path: str, route_date: str, crew: str, actor: str,
                            is_server_mode: bool = False, restrict: bool = False,
                            crew_name: str = "") -> str:
    """Re-plans a day's stored route IN ITS CURRENT ORDER (2026-09-21) — the visit
    order stays exactly as it is, but every arrival time, lunch pause and
    HARD TIME / SOFT WINDOW warning is recomputed with the same planner Route
    Today and Run AI Route use. This is what the Route tab runs after a job's
    schedule is edited from that page (a changed Start Time, Est. Duration, or
    Hard/Soft type shifts every later stop, so the old times would be stale).

    Jobs on the stored route that are no longer eligible for that day/crew — the
    edit moved them to another date or crew, or they lost their coordinates —
    are dropped from the route and named in the reply (they were not deleted).
    Personal mode is one route; server mode re-plans each crew's route on its
    own (limited to `crew` when given, and a restricted field_crew caller may
    only re-plan their own crew's route, like reorder_route_stop).
    """
    import re as _re
    from db_write_ops import _crew_name_in_cell

    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT crew_id, stop_number, job_id FROM route_stops WHERE route_date = ? "
            "ORDER BY crew_id, stop_number", (route_date,),
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        return f"✅ No route is stored for {route_date} — nothing to re-plan."

    if is_server_mode:
        groups: dict = {}
        for r in rows:
            groups.setdefault(str(r["crew_id"] or ""), []).append(r)
        crew_filter = (crew or "").strip().lower()
        if crew_filter:
            groups = {k: v for k, v in groups.items() if k.strip().lower() == crew_filter}
        if restrict:
            groups = {k: v for k, v in groups.items() if _crew_name_in_cell(k.strip().lower(), crew_name)}
            if not groups:
                return ("❌ Re-planning a route requires it to be on your own route. "
                        "Field crew cannot re-plan a coworker's route.")
    else:
        # Personal mode is ONE route however the rows' crew text happens to read.
        groups = {"": sorted(rows, key=lambda r: r["stop_number"])}

    outputs = []
    for crew_id, grp in groups.items():
        crew_txt = crew_id.strip()
        crew_arg = crew_txt if (is_server_mode and crew_txt not in ("", "(unassigned)")) else ""
        eligible = {j["job_id"] for j in db_get_jobs_for_route(db_path, route_date, crew_arg)
                    if j.get("job_id") and j.get("lat") is not None and j.get("lon") is not None}
        order = [r["job_id"] for r in grp if r["job_id"] and r["job_id"] in eligible]
        dropped = [r["job_id"] for r in grp if r["job_id"] and r["job_id"] not in eligible]
        if not order:
            outputs.append("⚠️ Nothing left on this route to re-plan"
                           + (f" ({', '.join(dropped)} no longer belong to it)." if dropped else "."))
            continue
        res = db_apply_route_order(db_path, route_date, ",".join(order), crew_arg, actor,
                                   single_crew=not is_server_mode)
        if not res.startswith("✅ Applied route"):
            outputs.append(res)            # nothing was written — surface the reason as-is
            continue
        res = _re.sub(r"\n\n⚠️ NOT PLACED[^\n]*", "", res)      # jobs never on this route: noise here
        res = res.replace("✅ Applied route for", "✅ Re-planned the day for", 1)
        if dropped:
            res += ("\n\nℹ️ No longer on this route (moved to another day/crew, or missing a "
                    "location — the job itself is unchanged): " + ", ".join(dropped))
        outputs.append(res)
    return "\n\n".join(outputs)


# ══════════════════════════════════════════════════════════════════════════════
# Route prescreen (2026-09-25)
# Runs BEFORE Route Today (suggest_route_schedule) and Run AI Route
# (start_ai_routing) and reports job-data problems that break a route or its
# phone map link, so they get fixed before routing instead of discovered in
# the car. Found live 2026-09-24: two jobs at 1755 State Road 44 routed
# back-to-back put the same address in the Google Maps link twice in a row,
# and the link opened as a stop list instead of a route.
#
# Read-only. Uses the SAME job set the route engines use (every job on the
# date, no status filter, optional crew filter) so nothing it reports is
# hypothetical. Each issue: {severity: error|warning, code, title, detail,
# job_ids: [...], crew}. "error" = the route or map link will be wrong;
# "warning" = the route will build but something looks off.
# ══════════════════════════════════════════════════════════════════════════════

_PS_ABBREV = {
    "street": "st", "road": "rd", "avenue": "ave", "av": "ave", "drive": "dr",
    "boulevard": "blvd", "lane": "ln", "court": "ct", "place": "pl",
    "highway": "hwy", "parkway": "pkwy", "circle": "cir", "terrace": "ter",
    "trail": "trl", "way": "wy", "north": "n", "south": "s", "east": "e",
    "west": "w", "suite": "ste", "apartment": "apt",
}


def _ps_street_key(street: str) -> str:
    """'1755 State Road 44' and '1755 State Rd. 44' -> the same key."""
    import re as _r
    toks = _r.findall(r"[a-z0-9]+", (street or "").lower())
    toks = [_PS_ABBREV.get(t, t) for t in toks]
    s = " ".join(toks)
    s = _r.sub(r"\bstate rd\b", "sr", s)          # State Road 44 == SR 44
    s = _r.sub(r"\b(ste|apt|unit|#)\s*\w+$", "", s).strip()  # a suite # is still the same stop
    return s


def _ps_minutes(t):
    """'13:05', '13:05:00', '1:05 PM', '1pm' -> minutes after midnight; None if blank/unparseable."""
    import re as _r
    s = str(t or "").strip().lower().replace(".", "")
    if not s:
        return None
    m = _r.match(r"^(\d{1,2})(?::(\d{2}))?(?::\d{2})?\s*(am|pm)?$", s)
    if not m:
        return None
    h, mi, ap = int(m.group(1)), int(m.group(2) or 0), m.group(3)
    if ap:
        if not 1 <= h <= 12:
            return None
        h = (h % 12) + (12 if ap == "pm" else 0)
    if h > 23 or mi > 59:
        return None
    return h * 60 + mi


def _ps_duration_min(dur, unit):
    try:
        d = float(dur)
    except (TypeError, ValueError):
        return None
    if d <= 0:
        return None
    u = str(unit or "min").strip().lower()
    return d * 60 if u.startswith("h") else d


def db_prescreen_route_jobs(db_path: str, route_date: str, crew: str = "",
                            single_crew: bool = False) -> list:
    """Returns a list of issue dicts (see the section comment above). Empty
    list = nothing to fix. single_crew=True (personal mode) checks the whole
    day as one route, matching how the route engines treat a personal install."""
    # R-058: multi-day jobs are checked on every working day they cover
    worked = _jobs_worked_on(db_path, route_date)
    rows = [r for r, _n in worked]
    day_no_of = {r["job_id"]: n for r, n in worked}

    crew_filter = (crew or "").strip()
    jobs = []
    for r in rows:
        job_crew = str(r["crew"] or "").strip()
        # R-056: a shared job ("A, B") is on each named person's route.
        if crew_filter and not _crew_match(job_crew, crew_filter):
            continue
        if str(r["job_status"] or "").strip().lower() in ("cancelled", "canceled"):
            continue            # never routed, so nothing to check (2026-09-25)
        if str(r["paused"] or "").strip().lower() in ("1", "true", "yes"):
            continue            # paused: never routed, so nothing to check (2026-10-05)
        street = str(r["street_address"] or "").strip()
        city = str(r["city"] or "").strip()
        state = str(r["state"] or "").strip()
        zipc = str(r["zip"] or "").strip()
        jobs.append({
            "id": r["job_id"],
            "name": str(r["customer_name"] or "").strip(),
            "street": street, "city": city, "state": state, "zip": zipc,
            "address": ", ".join(p for p in [street, city, f"{state} {zipc}".strip()] if p),
            "lat": r["latitude"], "lon": r["longitude"],
            "start": r["start_time"], "end": r["end_time"],
            "hard": str(r["schedule_type"] or "soft").strip().lower() == "hard",
            "dur": _ps_duration_min(*per_day_duration(db_path, r["est_duration"], r["est_duration_unit"],
                                                      day_no_of.get(r["job_id"], 1))),
            "status": str(r["job_status"] or "").strip().lower(),
            "crew": "" if single_crew else (crew_filter or job_crew or "(unassigned)"),
        })

    # R-056: with no person picked (server mode), the same-place check runs
    # per person, so a shared job's by-crew group key must be each person.
    def _groups_of(j):
        if single_crew or crew_filter:
            return [j["crew"]]
        return _crew_names(j["crew"]) or ["(unassigned)"]

    issues: list = []

    def add(sev, code, title, detail, ids, crew_id=""):
        issues.append({"severity": sev, "code": code, "title": title,
                       "detail": detail, "job_ids": list(ids), "crew": crew_id})

    def who(j):
        return f"{j['id']}" + (f" ({j['name']})" if j["name"] else "")

    # ── per-job checks ────────────────────────────────────────────────────
    for j in jobs:
        if not j["street"]:
            # No street = not routable (2026-09-25). The route engines skip it
            # (db_get_jobs_for_route), so it would silently be missing from the day.
            add("error", "NO_ADDRESS", f"{who(j)} has no street address",
                "It won't be routed — a job needs a street address to be a stop. "
                "Add the street (and city/ZIP)" + (f"; it only has \u201c{j['address']}\u201d." if j["address"] else "."),
                [j["id"]], j["crew"])
            continue
        if not (j["city"] or j["zip"]):
            add("warning", "INCOMPLETE_ADDRESS", f"{who(j)} has no city or ZIP",
                f"\u201c{j['address']}\u201d could match more than one place — its map location "
                "may be wrong. Add the city and ZIP.",
                [j["id"]], j["crew"])
        if j["lat"] is None or j["lon"] is None:
            add("error", "NOT_GEOCODED", f"{who(j)} has no map location",
                "Jobs without a map location are left off the route (NOT PLACED). "
                "Open the job and re-save its address so it gets geocoded.",
                [j["id"]], j["crew"])
        if str(j["start"] or "").strip() and _ps_minutes(j["start"]) is None:
            add("warning", "BAD_TIME", f"{who(j)} has an unreadable Start Time",
                f"\u201c{j['start']}\u201d isn't a time the router can read (use e.g. 9:30 AM).",
                [j["id"]], j["crew"])
        if j["hard"] and _ps_minutes(j["start"]) is None:
            add("warning", "HARD_NO_TIME", f"{who(j)} is Hard but has no Start Time",
                "A Hard job is a committed appointment — without a Start Time the router "
                "can't hold it to one. Add the time, or set it to Soft.",
                [j["id"]], j["crew"])

    # ── same-place check, per crew route ─────────────────────────────────
    by_crew: dict = {}
    for j in jobs:
        if j["street"]:          # street-less jobs are never routed (error above)
            for g in _groups_of(j):
                by_crew.setdefault(g, []).append(j)
    for crew_id, grp in by_crew.items():
        parent = list(range(len(grp)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for a in range(len(grp)):
            for b in range(a + 1, len(grp)):
                ja, jb = grp[a], grp[b]
                ka, kb = _ps_street_key(ja["street"]), _ps_street_key(jb["street"])
                same = False
                # The ADDRESS decides, never the map point. Found live
                # 2026-09-25: 1730 and 1755 State Road 44 geocoded ~6 m apart
                # and were flagged as the same address. A job with no street
                # is already an error above and is never routed, so there is
                # nothing for a coordinate fallback to cover.
                if ka and kb and ka == kb:
                    za, zb = ja["zip"][:5], jb["zip"][:5]
                    ca, cb = ja["city"].lower(), jb["city"].lower()
                    same = (za == zb) if (za and zb) else (ca == cb or not ca or not cb)
                if same:
                    parent[find(a)] = find(b)
        clusters: dict = {}
        for i in range(len(grp)):
            clusters.setdefault(find(i), []).append(grp[i])
        for members in clusters.values():
            if len(members) < 2:
                continue
            ids = [m["id"] for m in members]
            names = {m["name"].lower() for m in members if m["name"]}
            dup_entry = len(names) <= 1
            title = (f"Possible duplicate job: {', '.join(ids)}" if dup_entry
                     else f"{len(ids)} jobs at the same address: {', '.join(ids)}")
            add("error", "DUPLICATE_ADDRESS", title,
                f"All at {members[0]['address']}. The route will put them back-to-back, and "
                "Google Maps can't take the same address as two stops in a row — the phone "
                "map link opens as a stop list instead of a route. "
                + ("If one is a duplicate entry, cancel or delete it; if it's two pieces of "
                   "work, combine them into one job and add the durations together."
                   if dup_entry else
                   "Combine them into one job (add the durations together), or move one to "
                   "another day or crew."),
                ids, crew_id)

    # ── overlapping Hard appointments, per crew route ─────────────────────
    for crew_id, grp in by_crew.items():
        hard = []
        for j in grp:
            s = _ps_minutes(j["start"]) if j["hard"] else None
            if s is None:
                continue
            e = _ps_minutes(j["end"])
            if e is None or e <= s:
                e = s + (j["dur"] or 0)
            hard.append((s, e, j))
        hard.sort(key=lambda t: t[0])
        for i in range(len(hard)):
            for k in range(i + 1, len(hard)):
                s1, e1, j1 = hard[i]
                s2, e2, j2 = hard[k]
                if s2 >= e1 and not (s2 == s1):
                    break
                add("warning", "HARD_OVERLAP", f"Hard appointments overlap: {j1['id']} and {j2['id']}",
                    "One crew can't be at both — one of them will be late. "
                    "Change a time, set one to Soft, or give one to another crew.",
                    [j1["id"], j2["id"]], crew_id)

    order = {"error": 0, "warning": 1}
    issues.sort(key=lambda x: order.get(x["severity"], 2))
    return issues

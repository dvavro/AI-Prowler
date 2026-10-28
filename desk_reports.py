"""
desk_reports.py — AI-Prowler Service Desk, Phase 3: SLA checks, reports, digest.

sla_check()   Business: marks each open ticket's clocks (warning at 75% of a
              target, breach when it passes, escalation at 2x) — once each —
              writes an event, and emits an "sla" change so desk_alerts tells
              the assignee (warn / breach) or the owner and managers (escalate).
report()      volume, first-response and resolution times, SLA breaches and
              customer ratings for a period, optionally grouped.
digest_text() the morning list: overdue, due today, unassigned (Business),
              for the owner and managers — or, in Solo, the owner.
auto_close()  Fixed customer tickets with no customer word for
              "auto_close_days" (default 3) are Closed by "system".
"""
from __future__ import annotations

import datetime
import statistics

import desk_db
import desk_rules as rules
import desk_sla

UTC = datetime.timezone.utc
GROUPS = ("assignee", "queue_id", "type", "kind", "priority")


def _flags(t: dict) -> set:
    return {f for f in (t.get("sla_flags") or "").split(",") if f}


def sla_check(db_path: str, *, edition: str, now: datetime.datetime | None = None) -> list[tuple]:
    """Mark new SLA warnings/breaches/escalations. Returns [(ticket_id, flag), ...]."""
    if not rules.feature_enabled(edition, "sla_escalation"):
        return []
    now = now or datetime.datetime.now(UTC)
    rows = desk_db.list_tickets(db_path, open_only=True, limit=100000)   # owner view: all
    raised = []
    for t in rows:
        st = desk_sla.status(t, now)
        have = _flags(t)
        new = []
        for clock in ("response", "resolve"):
            if st[clock] in ("warn", "breach") and f"{clock}_warn" not in have:
                new.append(f"{clock}_warn")
            if st[clock] == "breach" and f"{clock}_breach" not in have:
                new.append(f"{clock}_breach")
        if st["escalate"] and "escalated" not in have:
            new.append("escalated")
        if not new:
            continue
        with desk_db.ticket_transaction(db_path) as (conn, touched):
            conn.execute("UPDATE tickets SET sla_flags = ? WHERE ticket_id = ?",
                         (",".join(sorted(have | set(new))), t["ticket_id"]))
            for f in new:
                kind = "sla_breach" if f.endswith("breach") else "sla_escalation" if f == "escalated" else "sla_warning"
                desk_db._event(conn, t["ticket_id"], "system", kind, to_value=f,
                               at=desk_sla.to_iso(now))
            touched.add(t["ticket_id"])
            fresh = desk_db._row(conn, t["ticket_id"])
        for f in new:
            # a breach supersedes its own warning raised in the same round
            if f.endswith("_warn") and f.replace("_warn", "_breach") in new:
                continue
            desk_db._emit("sla", fresh, None, edition=edition, flag=f)
            raised.append((t["ticket_id"], f))
    return raised


def auto_close(db_path: str, *, edition: str, now: datetime.datetime | None = None) -> list[str]:
    """Close customer tickets that have sat in Fixed with no word from the
    customer for "auto_close_days" (spec: "only the customer confirming, or 3
    days of silence, moves Fixed to Closed"). Silence counts from the later of
    the fix and the customer's last message. 0 days = never. Both editions.
    Returns the ticket ids it closed."""
    days = int(desk_db.get_settings(db_path).get("auto_close_days", rules.AUTO_CLOSE_DAYS) or 0)
    if days <= 0:
        return []
    now = now or datetime.datetime.now(UTC)
    cutoff = now - datetime.timedelta(days=days)
    closed = []
    for t in desk_db.list_tickets(db_path, state=rules.FIXED, kind=rules.EXTERNAL, limit=100000):
        quiet_since = desk_sla.parse(t.get("fixed_at"))
        if not quiet_since:
            continue
        conn = desk_db.get_connection(db_path)
        try:
            r = conn.execute("SELECT MAX(at) FROM ticket_messages WHERE ticket_id = ? AND "
                             "author_kind = 'customer'", (t["ticket_id"],)).fetchone()
        finally:
            conn.close()
        last_word = desk_sla.parse(r[0]) if r and r[0] else None
        if last_word and last_word > quiet_since:
            quiet_since = last_word
        if quiet_since > cutoff:
            continue
        try:
            desk_db.change_state(db_path, t["ticket_id"], rules.CLOSED, actor=None, edition=edition,
                                 reason=f"closed automatically — no reply from the customer in {days} "
                                        f"day{'s' if days != 1 else ''} after the fix",
                                 system=True)
            closed.append(t["ticket_id"])
        except desk_db.DeskError:
            continue
    return closed


def _minutes(a: str | None, b: str | None) -> float | None:
    if not a or not b:
        return None
    return (desk_sla.parse(b) - desk_sla.parse(a)).total_seconds() / 60


def _summ(rows: list[dict], breaches: dict) -> dict:
    fr = [m for m in (_minutes(t["created_at"], t["first_response_at"]) for t in rows) if m is not None]
    rs = [m for m in (_minutes(t["created_at"], t["fixed_at"] or t["closed_at"]) for t in rows
                      if t["state"] in (rules.FIXED, rules.CLOSED)) if m is not None]
    cs = [t["csat_score"] for t in rows if t["csat_score"] is not None]
    return {
        "tickets": len(rows),
        "open": sum(1 for t in rows if t["state"] != rules.CLOSED),
        "closed": sum(1 for t in rows if t["state"] == rules.CLOSED),
        "median_first_response_min": round(statistics.median(fr), 1) if fr else None,
        "median_resolution_hours": round(statistics.median(rs) / 60, 1) if rs else None,
        "sla_breaches": sum(breaches.get(t["ticket_id"], 0) for t in rows),
        "csat_avg": round(sum(cs) / len(cs), 2) if cs else None,
        "csat_count": len(cs),
    }


def report(db_path: str, *, actor=None, edition: str = rules.BUSINESS, since: str = "",
           until: str = "", group_by: str = "") -> dict:
    d = rules.can(actor, "report", edition=edition)
    if not d:
        raise desk_db.DeskError(d.reason)
    if group_by and group_by not in GROUPS:
        raise desk_db.DeskError(f"group_by must be one of {', '.join(GROUPS)}")
    if group_by in ("assignee", "queue_id") and not rules.feature_enabled(edition, "team_reports"):
        raise desk_db.DeskError("team reports are a Business feature")
    rows = [t for t in desk_db.list_tickets(db_path, actor=actor, edition=edition, limit=100000)
            if (not since or t["created_at"] >= since) and (not until or t["created_at"] < until)]
    conn = desk_db.get_connection(db_path)
    try:
        breaches = {}
        for r in conn.execute("SELECT ticket_id, COUNT(*) n FROM ticket_events WHERE kind = 'sla_breach' "
                              "GROUP BY ticket_id"):
            breaches[r["ticket_id"]] = r["n"]
    finally:
        conn.close()
    out = {"period": {"since": since or None, "until": until or None}, "total": _summ(rows, breaches)}
    if group_by:
        groups: dict = {}
        for t in rows:
            groups.setdefault(t.get(group_by) or "(none)", []).append(t)
        out["groups"] = {k: _summ(v, breaches) for k, v in sorted(groups.items())}
    return out


def report_text(rep: dict) -> str:
    def line(name, s):
        bits = [f"{s['tickets']} ticket(s), {s['open']} open, {s['closed']} closed"]
        if s["median_first_response_min"] is not None:
            bits.append(f"first reply ~{s['median_first_response_min']:.0f} min")
        if s["median_resolution_hours"] is not None:
            bits.append(f"fixed in ~{s['median_resolution_hours']} h")
        if s["sla_breaches"]:
            bits.append(f"{s['sla_breaches']} SLA breach(es)")
        if s["csat_count"]:
            bits.append(f"rating {s['csat_avg']}/5 from {s['csat_count']}")
        return f"{name}: " + ", ".join(bits)
    lines = [line("All", rep["total"])]
    for k, s in (rep.get("groups") or {}).items():
        lines.append("  " + line(k, s))
    return "\n".join(lines)


def digest_text(db_path: str, *, edition: str, now: datetime.datetime | None = None,
                for_user: str | None = None) -> str:
    """Plain-text morning digest; '' when there is nothing to report."""
    now = now or datetime.datetime.now(UTC)
    rows = desk_db.list_tickets(db_path, open_only=True, limit=100000)
    if for_user:
        rows = [t for t in rows if t.get("assignee") == for_user]
    today_end = now.astimezone().replace(hour=23, minute=59, second=59)
    overdue, today, unassigned = [], [], []
    for t in rows:
        if t["state"] in (rules.FIXED,):
            continue
        due = desk_sla.parse(t.get("due_resolve_at"))
        if due and due < now:
            overdue.append(t)
        elif due and due <= today_end:
            today.append(t)
        if edition == rules.BUSINESS and not t.get("assignee"):
            unassigned.append(t)
    if not (overdue or today or unassigned):
        return ""

    def block(title, items):
        if not items:
            return []
        return [f"{title} ({len(items)}):"] + [f"  • {t['ticket_id']} {t['title']} [{t['state']}, {t['priority']}]"
                                               + (f" → {t['assignee']}" if t.get("assignee") else "")
                                               for t in items[:25]]
    return "\n".join(["Service Desk — today", ""] + block("Overdue", overdue) + block("Due today", today)
                     + block("Not assigned yet", unassigned))

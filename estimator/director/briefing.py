"""Follow-ups due and the daily briefing.

Plain database reads: nothing here changes anything or sends anything. The
briefing text is written for a person to read in chat, the PWA or an email.
Scheduled delivery (a 7:00 am briefing) comes with the unattended Director loop.
"""
from __future__ import annotations

from datetime import date, timedelta

from estimator.context import RequestContext
from estimator.core.dates import local_date
from estimator.core.units.money import format_cents
from estimator.director.settings import get_settings


def _day(ts: str | None) -> date | None:
    return local_date(ts)


def followups_due(conn, ctx: RequestContext, today: date | None = None, mine: bool = False) -> dict:
    """Sent quotes past their follow-up date, quotes about to expire, and jobs stuck waiting on someone here."""
    today = today or date.today()
    s = get_settings(conn, ctx.company_id)
    follow_days, remind_days = s["follow_up_days"], s["review_reminder_days"]
    follow_ups, expiring, stuck = [], [], []
    sql = ("SELECT b.*, e.title, e.assigned_to FROM bids b JOIN estimates e ON e.id = b.estimate_id"
           " WHERE b.company_id = ? AND b.status IN ('sent', 'viewed')")
    args: list = [ctx.company_id]
    if mine:
        sql += " AND e.assigned_to = ?"
        args.append(ctx.user_id)
    for b in conn.execute(sql, args):
        sent = _day(b["sent_at"])
        if sent and today >= sent + timedelta(days=follow_days):
            follow_ups.append({"bid_id": b["id"], "number": b["number"], "title": b["title"], "sent_to": b["sent_to"],
                               "sent_on": sent.isoformat(), "days_since_sent": (today - sent).days,
                               "total_cents": b["total_cents"], "total": format_cents(b["total_cents"])})
        valid = _day(b["valid_until"])
        if valid and today <= valid <= today + timedelta(days=3):
            expiring.append({"bid_id": b["id"], "number": b["number"], "title": b["title"],
                             "valid_until": valid.isoformat(), "days_left": (valid - today).days,
                             "total": format_cents(b["total_cents"])})
    jsql = ("SELECT id, lane, module_id, stage, waiting_on, assigned_to, request_text, updated_at FROM director_jobs"
            " WHERE company_id = ? AND state IN ('waiting_on_user', 'active')")
    jargs: list = [ctx.company_id]
    if mine:
        jsql += " AND assigned_to = ?"
        jargs.append(ctx.user_id)
    for j in conn.execute(jsql, jargs):
        upd = _day(j["updated_at"])
        if upd and today >= upd + timedelta(days=remind_days):
            stuck.append({"job_id": j["id"], "stage": j["stage"], "waiting_on": j["waiting_on"],
                          "request": j["request_text"][:80], "days_waiting": (today - upd).days})
    follow_ups.sort(key=lambda x: -x["days_since_sent"])
    return {"ok": True, "today": today.isoformat(), "follow_ups": follow_ups, "expiring_soon": expiring,
            "stuck_jobs": stuck, "count": len(follow_ups) + len(expiring) + len(stuck),
            "settings": {"follow_up_days": follow_days, "review_reminder_days": remind_days}}


def briefing(conn, ctx: RequestContext, today: date | None = None, mine: bool = False) -> dict:
    """A short summary of where every quote and job stands, for the start of the day."""
    today = today or date.today()
    since = today - timedelta(days=1)
    week = today - timedelta(days=7)
    due = followups_due(conn, ctx, today, mine)
    scope = " AND e.assigned_to = ?" if mine else ""
    args_scope = [ctx.user_id] if mine else []

    def bids_where(cond: str, args: list) -> list:
        return [dict(r) for r in conn.execute(
            "SELECT b.number, b.total_cents, b.status, b.sent_at, b.updated_at, e.title FROM bids b"
            " JOIN estimates e ON e.id = b.estimate_id WHERE b.company_id = ?" + scope + " AND " + cond,
            [ctx.company_id] + args_scope + args)]

    sent_recent = [b for b in bids_where("b.sent_at IS NOT NULL", []) if (_day(b["sent_at"]) or date.min) >= since]
    won_week = [b for b in bids_where("b.status = 'won'", []) if (_day(b["updated_at"]) or date.min) >= week]
    lost_week = [b for b in bids_where("b.status = 'lost'", []) if (_day(b["updated_at"]) or date.min) >= week]
    jsql = ("SELECT id, stage, state, waiting_on, request_text FROM director_jobs WHERE company_id = ?"
            " AND state NOT IN ('done', 'cancelled')" + (" AND assigned_to = ?" if mine else ""))
    jobs = [dict(r) for r in conn.execute(jsql, [ctx.company_id] + args_scope)]
    approvals = [j for j in jobs if j["stage"] == "approve" and j["state"] == "waiting_on_user"]
    reviews = [j for j in jobs if j["stage"] == "review" and j["state"] == "waiting_on_user"]
    to_send = [j for j in jobs if j["stage"] == "write_bid" and j["state"] == "waiting_on_user"]
    waiting_customer = [j for j in jobs if j["state"] == "waiting_on_customer"]
    needs_answers = [j for j in jobs if j["stage"] in ("collect_answers", "triage") and j["state"] == "waiting_on_user"]
    takeoffs = [j for j in jobs if j["stage"] == "takeoff" and j["state"] == "waiting_on_user"]

    def money(rows):
        return format_cents(sum(r["total_cents"] for r in rows))

    lines = [f"Estimator briefing for {today.strftime('%A, %B %d').replace(' 0', ' ')}"]
    if sent_recent:
        lines.append(f"- {len(sent_recent)} quote(s) sent since yesterday ({money(sent_recent)}).")
    if won_week:
        lines.append(f"- Won this week: {len(won_week)} ({money(won_week)})."
                     + (f" Lost: {len(lost_week)}." if lost_week else ""))
    elif lost_week:
        lines.append(f"- Lost this week: {len(lost_week)}.")
    if approvals:
        lines.append(f"- {len(approvals)} quote(s) waiting for your approval.")
    if reviews:
        lines.append(f"- {len(reviews)} estimate(s) waiting for a reviewer.")
    if to_send:
        lines.append(f"- {len(to_send)} approved quote(s) ready to send.")
    if needs_answers:
        lines.append(f"- {len(needs_answers)} job(s) waiting for answers from the customer or you.")
    if takeoffs:
        lines.append(f"- {len(takeoffs)} plan takeoff(s) in progress: trades to measure or quantities to approve.")
    if due["follow_ups"]:
        top = due["follow_ups"][0]
        lines.append(f"- {len(due['follow_ups'])} follow-up(s) due, oldest {top['number']} ({top['title']}, "
                     f"{top['total']}) sent {top['days_since_sent']} days ago.")
    if due["expiring_soon"]:
        lines.append(f"- {len(due['expiring_soon'])} quote(s) expire within 3 days.")
    if waiting_customer:
        lines.append(f"- {len(waiting_customer)} quote(s) out with customers.")
    if due["stuck_jobs"]:
        lines.append(f"- {len(due['stuck_jobs'])} job(s) haven't moved in {due['settings']['review_reminder_days']}+ days.")
    if len(lines) == 1:
        lines.append("- Nothing waiting. All quiet.")
    return {"ok": True, "text": "\n".join(lines), "today": today.isoformat(),
            "counts": {"sent_since_yesterday": len(sent_recent), "won_this_week": len(won_week),
                       "lost_this_week": len(lost_week), "awaiting_approval": len(approvals), "awaiting_review": len(reviews),
                       "ready_to_send": len(to_send), "needs_answers": len(needs_answers),
                       "follow_ups_due": len(due["follow_ups"]), "expiring_soon": len(due["expiring_soon"]),
                       "out_with_customers": len(waiting_customer), "stuck_jobs": len(due["stuck_jobs"])},
            "follow_ups": due["follow_ups"], "expiring_soon": due["expiring_soon"], "stuck_jobs": due["stuck_jobs"]}

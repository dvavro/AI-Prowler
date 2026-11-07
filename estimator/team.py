"""Who's working on what: assignments, "my work", personal notices and the "someone else is editing" warning.

In Personal mode there's one user, so these mostly matter in Server mode, but they work the same way in both:
an estimate (and its Director job) can be assigned to a person, who gets a notice in their inbox, and anyone
reading an estimate another person changed in the last few minutes is told so before they change it too (the
`rev` check still stops a real overwrite).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from estimator.context import RequestContext
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service

ASSIGN_ROLES = ("owner", "estimator", "office")
EDITING_MINUTES = 10
OPEN_STATUSES = ("draft", "in_review", "approved", "sent")
USER_RE = re.compile(r"[A-Za-z0-9_.@-]{1,64}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def assign(conn, ctx: RequestContext, user_id: str, *, estimate_id: int | None = None, job_id: int | None = None,
           note: str = "") -> dict:
    """Assign an estimate (and its Director job) to user_id; an empty user_id clears the assignment."""
    if ctx.role not in ASSIGN_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't assign work", role=ctx.role)
    user = (user_id or "").strip()
    if user and not USER_RE.fullmatch(user):
        raise InvalidInput("user_id is a sign-in name like 'maria' or 'maria@company.com'", field="user_id")
    if not estimate_id and not job_id:
        raise InvalidInput("give estimate_id or job_id")
    job = None
    if job_id:
        job = conn.execute("SELECT * FROM director_jobs WHERE id = ? AND company_id = ?",
                           (int(job_id), ctx.company_id)).fetchone()
        if job is None:
            raise NotFound(f"no job {job_id}", job_id=job_id)
        estimate_id = estimate_id or job["estimate_id"]
    est = service.get_estimate(conn, ctx, int(estimate_id)) if estimate_id else None
    if est and job is None:
        job = conn.execute("SELECT * FROM director_jobs WHERE estimate_id = ? AND company_id = ? ORDER BY id DESC LIMIT 1",
                           (est["id"], ctx.company_id)).fetchone()
    title = (est["title"] if est else None) or (job["request_text"][:60] if job else "") or "untitled"
    stamp = _now().isoformat(timespec="seconds")
    with service.transaction(conn):
        if est:
            conn.execute("UPDATE estimates SET assigned_to = ? WHERE id = ?", (user or None, est["id"]))
        if job is not None:
            conn.execute("UPDATE director_jobs SET assigned_to = ? WHERE id = ?", (user or None, job["id"]))
        if user and user != ctx.actor:
            what = f"Estimate {est['id']}" if est else f"Job {job['id']}"
            msg = f"{what} ({title}) was assigned to you by {ctx.actor}." + (f" Note: {note.strip()[:300]}" if note.strip() else "")
            conn.execute(
                "INSERT INTO director_notices (company_id, kind, dedupe_key, job_id, estimate_id, message, created_at,"
                " delivered_via, delivered_at, for_user) VALUES (?, 'assigned', ?, ?, ?, ?, ?, 'chat', ?, ?)",
                (ctx.company_id, f"assigned:{est['id'] if est else 'j' + str(job['id'])}:{user}:{stamp}",
                 job["id"] if job is not None else None, est["id"] if est else None, msg, stamp, stamp, user))
        service._log(conn, ctx, est["id"] if est else None, "assigned",
                     {"to": user or None, "job_id": job["id"] if job is not None else None, "note": note.strip()[:300] or None})
    return {"ok": True, "estimate_id": est["id"] if est else None, "job_id": job["id"] if job is not None else None,
            "assigned_to": user or None,
            "message": f"Assigned to {user}." if user else "Assignment cleared."}


def my_work(conn, ctx: RequestContext, user_id: str | None = None) -> dict:
    """Open estimates and Director jobs assigned to a person (default: the caller), and their unread notices."""
    user = (user_id or ctx.user_id).strip()
    if user != ctx.user_id and ctx.role not in ("owner", "office"):
        raise PermissionDenied("only the owner or office can look at someone else's work", role=ctx.role)
    marks = ",".join("?" for _ in OPEN_STATUSES)
    rows = [dict(r) for r in conn.execute(
        f"SELECT id, title, status, due_date, updated_at, is_practice FROM estimates WHERE company_id = ?"
        f" AND assigned_to = ? AND status IN ({marks}) ORDER BY is_practice, COALESCE(due_date, '9999'), id",
        (ctx.company_id, user, *OPEN_STATUSES))]
    ests, practice = [], []
    for r in rows:   # practice jobs are listed, labelled and kept apart, so a notice about one always has a match
        is_practice = bool(r.pop("is_practice"))
        r["practice"] = is_practice
        if is_practice:
            r["label"] = "🎓 practice (not a real job)"
        (practice if is_practice else ests).append(r)
    jobs = [dict(r) for r in conn.execute(
        "SELECT id, lane, stage, state, waiting_on, estimate_id, due_date FROM director_jobs WHERE company_id = ?"
        " AND assigned_to = ? AND state NOT IN ('done', 'cancelled') ORDER BY COALESCE(due_date, '9999'), id",
        (ctx.company_id, user))]
    notices = [{"id": r["id"], "kind": r["kind"], "message": r["message"], "estimate_id": r["estimate_id"]}
               for r in conn.execute("SELECT * FROM director_notices WHERE company_id = ? AND for_user = ?"
                                     " AND read_at IS NULL ORDER BY id DESC LIMIT 50", (ctx.company_id, user))]
    extra = f" plus {len(practice)} practice" if practice else ""
    return {"ok": True, "user": user, "estimates": ests, "practice": practice, "jobs": jobs, "notices": notices,
            "summary": f"{len(ests)} estimate(s){extra}, {len(jobs)} job(s), {len(notices)} new notice(s) for {user}."}


def editing_warning(row, ctx: RequestContext) -> str | None:
    """'maria changed this 3 minutes ago' when someone else wrote to the estimate within EDITING_MINUTES."""
    who, when = row["updated_by"], row["updated_at"]
    if not who or who == ctx.actor or not when:
        return None
    try:
        at = datetime.fromisoformat(when)
    except ValueError:
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    age = _now() - at
    if age > timedelta(minutes=EDITING_MINUTES) or age < timedelta(0):
        return None
    mins = int(age.total_seconds() // 60)
    ago = "just now" if mins < 1 else f"{mins} minute{'s' if mins != 1 else ''} ago"
    return (f"{who} changed this estimate {ago}; they may still be working on it. Check with them before changing it "
            "(your change will be refused if theirs came first).")

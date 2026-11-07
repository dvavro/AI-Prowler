"""The practice project (est_sample_project): a ready-made estimate to try things on.

"Practice: Garcia house" has a roof replacement and a driveway and siding wash, priced from the price book, so a
new user can look at it, change it, approve it, preview a bid or record actual costs without touching real work.
Practice estimates are marked (is_practice) and left out of the history comparisons and "my work". Deleting
removes every practice estimate and what was made from it (bids, Director jobs, recorded costs).
"""
from __future__ import annotations

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied
from estimator.estimating import quick, service

TITLE = "Practice: Garcia house"
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
WASH = {"driveway_sqft": 900, "house_siding_sqft": 1800, "stories": 1}
ROLES = ("owner", "estimator")


def _existing(conn, ctx) -> list[int]:
    return [r[0] for r in conn.execute("SELECT id FROM estimates WHERE company_id = ? AND is_practice = 1 ORDER BY id",
                                       (ctx.company_id,))]


def create(conn, ctx: RequestContext, registry=None) -> dict:
    if ctx.role not in ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't make the practice project", role=ctx.role)
    have = _existing(conn, ctx)
    if have:
        est = service.get_estimate(conn, ctx, have[0])
        return {"ok": True, "created": False, "estimate_id": est["id"], "title": est["title"],
                "total_cents": (est["totals"] or {}).get("total_cents", 0),
                "message": "The practice project is already there. Delete it first to start over."}
    e = service.create_estimate(conn, ctx, TITLE, address="1234 Practice Lane (not a real job)")
    conn.execute("UPDATE estimates SET is_practice = 1 WHERE id = ?", (e["id"],))
    e = quick.answer(conn, ctx, e["id"], "roofing", ROOF, e["rev"], registry)
    e = quick.answer(conn, ctx, e["id"], "pressure_washing", WASH, e["rev"], registry)
    est = service.get_estimate(conn, ctx, e["id"])
    if ctx.role == "owner":
        from estimator.estimating import setup
        try:
            setup.setup_step(conn, ctx, "sample_quote", None, status="done")
        except Exception:  # noqa: BLE001 - the checklist tick is a nicety; the practice estimate is what matters
            pass
    return {"ok": True, "created": True, "estimate_id": est["id"], "title": est["title"],
            "total_cents": (est["totals"] or {}).get("total_cents", 0),
            "trades": [s["module_id"] for s in est["sections"]],
            "try_next": ["est_get_estimate to look at it", "est_validate for the Reviewer's checks",
                         "bid_preview after approving it, to see the quote", "est_export to get it in Excel"],
            "message": "Practice project made. It's marked practice and stays out of your history and reports."}


def delete(conn, ctx: RequestContext, confirm: bool = False) -> dict:
    if ctx.role not in ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't delete the practice project", role=ctx.role)
    ids = _existing(conn, ctx)
    if not ids:
        return {"ok": True, "deleted": 0, "message": "There's no practice project."}
    if not confirm:
        raise ConfirmationRequired(f"Delete the practice project ({len(ids)} practice estimate(s) and anything made "
                                   "from them)? Call again with confirm=true.", estimate_ids=ids)
    marks = ",".join("?" for _ in ids)
    with service.transaction(conn):
        jobs = [r[0] for r in conn.execute(f"SELECT id FROM director_jobs WHERE estimate_id IN ({marks})", ids)]
        conn.execute(f"DELETE FROM takeoff_tasks WHERE run_id IN (SELECT id FROM runs WHERE estimate_id IN ({marks}))", ids)
        conn.execute(f"DELETE FROM director_notices WHERE bid_id IN (SELECT id FROM bids WHERE estimate_id IN ({marks}))", ids)
        for table, col, keys in (("director_notices", "estimate_id", ids), ("agent_tasks", "estimate_id", ids),
                                 ("bids", "estimate_id", ids), ("estimate_scenarios", "estimate_id", ids),
                                 ("estimate_actuals", "estimate_id", ids), ("runs", "estimate_id", ids)):
            conn.execute(f"DELETE FROM {table} WHERE {col} IN ({','.join('?' for _ in keys)})", keys)
        if jobs:
            jm = ",".join("?" for _ in jobs)
            conn.execute(f"DELETE FROM director_notices WHERE job_id IN ({jm})", jobs)
            conn.execute(f"DELETE FROM director_jobs WHERE id IN ({jm})", jobs)
        conn.execute(f"DELETE FROM estimate_events WHERE estimate_id IN ({marks})", ids)
        conn.execute(f"UPDATE estimates SET parent_estimate_id = NULL WHERE parent_estimate_id IN ({marks})", ids)
        conn.execute(f"DELETE FROM estimates WHERE id IN ({marks}) AND is_practice = 1", ids)
        service._log(conn, ctx, None, "practice_deleted", {"estimate_ids": ids})
    return {"ok": True, "deleted": len(ids), "message": "Practice project deleted."}


def run(conn, ctx: RequestContext, action: str = "create", confirm: bool = False, registry=None) -> dict:
    action = (action or "create").strip().lower()
    if action == "create":
        return create(conn, ctx, registry)
    if action == "delete":
        return delete(conn, ctx, confirm)
    raise InvalidInput("action must be create or delete", field="action")

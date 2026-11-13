"""Archive, restore and delete a project (2026-11-12, David).

A project is an estimate with all its revisions (v1, v2, ...), so each action works on the whole family.

- archive: hides the project (status 'archived'); nothing is lost. Each estimate's status before is kept in
  the event log so restore puts it back. The project's Director job is cancelled (restore re-opens it).
- restore: undoes archive.
- delete: removes the project and everything made from it - plans, measurements, takeoffs, the Director job,
  quotes and the event history - for good. A backup of estimator.db is made first. A project whose quote went
  to a customer (sent / viewed / won) or became a job can't be deleted: archive it instead, so the record of
  what the customer was quoted is kept.

Owner only. Every action asks first (ConfirmationRequired); delete also needs the project's name typed.
"""
from __future__ import annotations

import json

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable, PermissionDenied
from estimator.estimating import service

ROLES = ("owner",)
KEEP_RECORD_BIDS = ("sent", "viewed", "won")


def _require(ctx: RequestContext, what: str) -> None:
    if ctx.role not in ROLES:
        raise PermissionDenied(f"only the owner can {what} a project", role=ctx.role)


def family(conn, ctx: RequestContext, estimate_id: int) -> list[dict]:
    """The estimate and every revision before or after it, oldest first."""
    est = service.get_estimate(conn, ctx, int(estimate_id))        # NotFound if it isn't this company's
    ids, todo = set(), [est["id"]]
    while todo:
        eid = todo.pop()
        if eid in ids:
            continue
        ids.add(eid)
        row = conn.execute("SELECT parent_estimate_id FROM estimates WHERE id = ? AND company_id = ?",
                           (eid, ctx.company_id)).fetchone()
        if row and row["parent_estimate_id"]:
            todo.append(row["parent_estimate_id"])
        todo.extend(r["id"] for r in conn.execute(
            "SELECT id FROM estimates WHERE parent_estimate_id = ? AND company_id = ?", (eid, ctx.company_id)))
    marks = ",".join("?" for _ in ids)
    return [dict(r) for r in conn.execute(
        f"SELECT id, title, status, revision, is_practice FROM estimates WHERE id IN ({marks}) ORDER BY id", sorted(ids))]


def _ids(fam) -> list[int]:
    return [e["id"] for e in fam]


def _in(ids) -> str:
    return ",".join("?" for _ in ids)


# ---------------------------------------------------------------- archive / restore

def archive(conn, ctx: RequestContext, estimate_id: int, confirm: bool = False) -> dict:
    _require(ctx, "archive")
    fam = family(conn, ctx, estimate_id)
    live = [e for e in fam if e["status"] != "archived"]
    title = fam[-1]["title"]
    if not live:
        return {"ok": True, "archived": 0, "message": f"'{title}' is already archived."}
    if not confirm:
        raise ConfirmationRequired(
            f"Archive '{title}'? It's hidden from Projects and the Dashboard; nothing is deleted and you can restore "
            "it from Projects (status: Archived). Call again with confirm=true.",
            estimate_ids=_ids(fam), changes=[f"v{e['revision']}: {e['status']} -> archived" for e in live])
    ids = [e["id"] for e in live]
    with service.transaction(conn):
        for e in live:
            conn.execute("UPDATE estimates SET status = 'archived' WHERE id = ?", (e["id"],))
            service._log(conn, ctx, e["id"], "project_archived", {"status": "archived"}, {"status": e["status"]})
            service._bump(conn, ctx, e["id"])
        conn.execute(f"UPDATE director_jobs SET state = 'cancelled', waiting_on = NULL, rev = rev + 1 WHERE company_id = ?"
                     f" AND estimate_id IN ({_in(_ids(fam))}) AND state NOT IN ('done', 'cancelled')",
                     (ctx.company_id, *_ids(fam)))
    return {"ok": True, "archived": len(ids), "estimate_ids": ids,
            "message": f"'{title}' archived. Find it on Projects with the Archived status to restore it."}


def restore(conn, ctx: RequestContext, estimate_id: int, confirm: bool = False) -> dict:
    _require(ctx, "restore")
    fam = family(conn, ctx, estimate_id)
    gone = [e for e in fam if e["status"] == "archived"]
    title = fam[-1]["title"]
    if not gone:
        return {"ok": True, "restored": 0, "message": f"'{title}' isn't archived."}
    before = {}
    for e in gone:
        row = conn.execute("SELECT before_json FROM estimate_events WHERE estimate_id = ? AND action = 'project_archived'"
                           " ORDER BY id DESC LIMIT 1", (e["id"],)).fetchone()
        st = (json.loads(row["before_json"]) or {}).get("status") if row and row["before_json"] else None
        before[e["id"]] = st if st in service.STATUSES and st != "archived" else "draft"
    if not confirm:
        raise ConfirmationRequired(f"Restore '{title}'? Call again with confirm=true.", estimate_ids=_ids(fam),
                                   changes=[f"v{e['revision']}: archived -> {before[e['id']]}" for e in gone])
    with service.transaction(conn):
        for e in gone:
            conn.execute("UPDATE estimates SET status = ? WHERE id = ?", (before[e["id"]], e["id"]))
            service._log(conn, ctx, e["id"], "project_restored", {"status": before[e["id"]]}, {"status": "archived"})
            service._bump(conn, ctx, e["id"])
        conn.execute(f"UPDATE director_jobs SET state = 'active', rev = rev + 1 WHERE company_id = ?"
                     f" AND estimate_id IN ({_in(_ids(fam))}) AND state = 'cancelled'", (ctx.company_id, *_ids(fam)))
    return {"ok": True, "restored": len(gone), "message": f"'{title}' restored."}


# ---------------------------------------------------------------- delete

def delete(conn, ctx: RequestContext, estimate_id: int, confirm: bool = False, title: str | None = None,
           backup: bool = True) -> dict:
    _require(ctx, "delete")
    fam = family(conn, ctx, estimate_id)
    ids = _ids(fam)
    name = fam[-1]["title"]
    kept = [r for r in conn.execute(f"SELECT number, status, job_id FROM bids WHERE estimate_id IN ({_in(ids)})", ids)
            if r["status"] in KEEP_RECORD_BIDS or r["job_id"]]
    if kept or any(e["status"] in ("sent", "won") for e in fam):
        raise NotEditable(f"'{name}' was quoted to a customer" + (f" ({kept[0]['number']} {kept[0]['status']})" if kept
                          else "") + ", so it can't be deleted; archive it instead to keep the record",
                          estimate_id=int(estimate_id))
    plans = conn.execute(f"SELECT COUNT(*) FROM plan_sets WHERE estimate_id IN ({_in(ids)})", ids).fetchone()[0]
    meas = conn.execute(f"SELECT COUNT(*) FROM measurements WHERE estimate_id IN ({_in(ids)})", ids).fetchone()[0]
    quotes = conn.execute(f"SELECT COUNT(*) FROM bids WHERE estimate_id IN ({_in(ids)})", ids).fetchone()[0]
    changes = [f"{len(ids)} estimate version(s)", f"{plans} plan set(s) with their sheets", f"{meas} measurement(s)",
               f"{quotes} draft quote(s)", "the Director job and the project's history"]
    if not confirm:
        raise ConfirmationRequired(f"Delete '{name}' for good? This can't be undone from the screens (a backup is made "
                                   "first). Call again with confirm=true and the project's name.", estimate_ids=ids,
                                   changes=changes)
    if (title or "").strip().casefold() != (name or "").strip().casefold():
        raise InvalidInput(f"type the project's name exactly ('{name}') to delete it", field="title")
    saved = None
    if backup:
        from estimator.database import backup as dbbackup
        try:
            saved = str(dbbackup.backup_database())
        except FileNotFoundError:
            saved = None                                     # an in-memory database (tests): nothing to copy
    m = _in(ids)
    with service.transaction(conn):
        jobs = [r[0] for r in conn.execute(f"SELECT id FROM director_jobs WHERE estimate_id IN ({m})", ids)]
        bids = [r[0] for r in conn.execute(f"SELECT id FROM bids WHERE estimate_id IN ({m})", ids)]
        sheets = [r[0] for r in conn.execute(
            f"SELECT s.id FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id WHERE p.estimate_id IN ({m})", ids)]
        if sheets:
            conn.execute(f"DELETE FROM sheet_trade_active WHERE sheet_id IN ({_in(sheets)})", sheets)
        conn.execute(f"DELETE FROM takeoff_tasks WHERE run_id IN (SELECT id FROM runs WHERE estimate_id IN ({m}))", ids)
        conn.execute(f"DELETE FROM takeoff_tasks WHERE estimate_id IN ({m})", ids)
        if bids:
            conn.execute(f"DELETE FROM director_notices WHERE bid_id IN ({_in(bids)})", bids)
            conn.execute(f"DELETE FROM agent_tasks WHERE bid_id IN ({_in(bids)})", bids)
        if jobs:
            conn.execute(f"DELETE FROM director_notices WHERE job_id IN ({_in(jobs)})", jobs)
            conn.execute(f"DELETE FROM agent_tasks WHERE job_id IN ({_in(jobs)})", jobs)
        for table in ("director_notices", "agent_tasks", "bids", "estimate_scenarios", "runs", "auto_runs",
                      "ai_send_log", "ai_log"):
            conn.execute(f"DELETE FROM {table} WHERE estimate_id IN ({m})", ids)
        if jobs:
            conn.execute(f"DELETE FROM director_jobs WHERE id IN ({_in(jobs)})", jobs)   # its steps go with it
        conn.execute(f"DELETE FROM estimate_events WHERE estimate_id IN ({m})", ids)
        conn.execute(f"UPDATE estimates SET parent_estimate_id = NULL WHERE id IN ({m})", ids)
        # trade sections and lines, plan sets (sheets, viewports, objects, symbols), measurements, reviews,
        # revision reports, assembly uses and job costs go with the estimate (ON DELETE CASCADE).
        conn.execute(f"DELETE FROM estimates WHERE id IN ({m}) AND company_id = ?", (*ids, ctx.company_id))
        service._log(conn, ctx, None, "project_deleted",
                     {"title": name, "estimate_ids": ids, "plan_sets": plans, "measurements": meas, "backup": saved})
    return {"ok": True, "deleted": len(ids), "estimate_ids": ids, "backup": saved,
            "message": f"'{name}' deleted." + (" A backup was made first." if saved else "")}

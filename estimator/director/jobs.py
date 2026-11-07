"""The shared job file: one record per job that every agent reads and writes."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.errors import NotFound, StaleRevision

JSON_FIELDS = ("answers_json", "open_questions_json", "next_step_json", "customer_json", "trades_json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_job(conn, ctx: RequestContext, *, request_text: str, estimate_id: int | None, lane: str | None,
               module_id: str | None, playbook, stage: str, answers: dict | None = None,
               due_date: str | None = None, customer: dict | None = None) -> int:
    now = _now()
    cur = conn.execute(
        "INSERT INTO director_jobs (company_id, estimate_id, lane, module_id, playbook_id, playbook_version, stage,"
        " request_text, answers_json, customer_json, assigned_to, due_date, created_by, created_at, updated_by,"
        " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ctx.company_id, estimate_id, lane, module_id, playbook.id if playbook else None,
         playbook.version if playbook else None, stage, request_text, json.dumps(answers or {}),
         json.dumps(customer or {}), ctx.user_id, due_date, ctx.actor, now, ctx.actor, now))
    return int(cur.lastrowid)


def load_job(conn, ctx: RequestContext, job_id: int) -> dict:
    row = conn.execute("SELECT * FROM director_jobs WHERE id = ? AND company_id = ?",
                       (job_id, ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"job {job_id} not found", job_id=job_id)
    job = dict(row)
    for f in JSON_FIELDS:
        job[f[:-5]] = json.loads(job.pop(f)) if job[f] else None
    job["answers"] = job["answers"] or {}
    job["customer"] = job["customer"] or {}
    job["trades"] = job["trades"] or {}
    return job


def save_job(conn, ctx: RequestContext, job: dict, expected_rev: int | None = None) -> None:
    if expected_rev is not None:
        cur = conn.execute("SELECT rev FROM director_jobs WHERE id = ?", (job["id"],)).fetchone()
        if int(cur["rev"]) != int(expected_rev):
            raise StaleRevision(f"job {job['id']} changed since you read it; read it again and retry",
                                job_id=job["id"], current_rev=int(cur["rev"]))
    conn.execute(
        "UPDATE director_jobs SET lane = ?, module_id = ?, playbook_id = ?, playbook_version = ?, stage = ?,"
        " state = ?, waiting_on = ?, estimate_id = ?, answers_json = ?, open_questions_json = ?,"
        " next_step_json = ?, customer_json = ?, trades_json = ?, rev = rev + 1, updated_by = ?, updated_at = ?"
        " WHERE id = ?",
        (job["lane"], job["module_id"], job["playbook_id"], job["playbook_version"], job["stage"], job["state"],
         job["waiting_on"], job["estimate_id"], json.dumps(job["answers"]),
         json.dumps(job["open_questions"]) if job["open_questions"] is not None else None,
         json.dumps(job["next_step"]) if job["next_step"] is not None else None, json.dumps(job.get("customer") or {}),
         json.dumps(job.get("trades") or {}), ctx.actor, _now(), job["id"]))


def log_step(conn, ctx: RequestContext, job_id: int, stage: str, agent: str, state: str,
             summary: str = "", result: dict | None = None) -> None:
    now = _now()
    conn.execute(
        "INSERT INTO director_steps (job_id, stage, agent_role, provider, state, input_summary, result_json, actor,"
        " started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (job_id, stage, agent, ctx.agent or "chat", state, summary,
         json.dumps(result, default=str) if result is not None else None, ctx.actor, now,
         now if state in ("done", "skipped", "failed", "blocked") else None))


def steps(conn, job_id: int) -> list[dict]:
    out = []
    for r in conn.execute("SELECT stage, agent_role, state, input_summary, actor, started_at FROM director_steps"
                          " WHERE job_id = ? ORDER BY id", (job_id,)):
        out.append(dict(r))
    return out


def list_jobs(conn, ctx: RequestContext, include_done: bool = False, mine: bool = False, limit: int = 100) -> list[dict]:
    sql = ("SELECT id, lane, module_id, stage, state, waiting_on, assigned_to, estimate_id, request_text,"
           " updated_at FROM director_jobs WHERE company_id = ?")
    args: list = [ctx.company_id]
    if not include_done:
        sql += " AND state NOT IN ('done', 'cancelled')"
    if mine:
        sql += " AND assigned_to = ?"
        args.append(ctx.user_id)
    sql += " ORDER BY updated_at DESC, id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 500)))
    return [dict(r) for r in conn.execute(sql, args)]

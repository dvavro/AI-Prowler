"""Estimate Runner.

A run takes one estimate and a list of construction trades and makes one takeoff task per trade. Tasks move:

    queued -> running -> needs_review -> completed        (or blocked / failed, with a reason)

- queued: waiting for a trade it depends on (drywall, painting and insulation wait for framing, because they use
  the same walls and rooms).
- running: the trade is being measured. Until the Plan Engine (Coder 2 track) is installed, a person or their AI in
  chat reads the plans and submits the quantities (submit_takeoff).
- needs_review: quantities were submitted; a person approves them (or sends them back with a note). Confident
  submissions skip this only when the owner turned on auto-advance for that trade.
- completed: the approved quantities are priced onto the estimate. Only approved quantities are ever priced.
- blocked: a trade it depends on failed. Retrying that trade unblocks it.
- failed: the trade couldn't be measured (the agent said why) or its module isn't available.

A failed or blocked trade never stops the other trades. When nothing is left to do, the run is completed (every
trade done), partial (some done) or failed (none done), and the estimate holds the combined total of the trades
that were done.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from estimator.agent_manager import get_config
from estimator.context import RequestContext
from estimator.core.units.money import format_cents
from estimator.errors import InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.estimating import quick, service

# A trade waits for these trades when both are in the same run.
DEPENDS_ON = {"drywall": ("framing",), "painting": ("framing",), "insulation": ("framing",)}
TASK_STATES = ("queued", "running", "needs_review", "completed", "blocked", "failed")
OPEN_RUN_STATES = ("running", "needs_review")
PROGRESS = {"queued": 0, "running": 25, "needs_review": 75, "completed": 100, "blocked": 0, "failed": 0}
START_ROLES = service.EDIT_ROLES              # owner, estimator
SUBMIT_ROLES = service.EDIT_ROLES
REVIEW_ROLES = service.APPROVE_ROLES          # owner, estimator, reviewer


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def _runner_ctx(ctx: RequestContext) -> RequestContext:
    """The Runner prices approved quantities itself, so a reviewer's approval can reach the estimate."""
    return RequestContext(company_id=ctx.company_id, user_id=ctx.user_id, role="estimator", mode=ctx.mode,
                          agent="agent:estimate_runner")


def _task(row) -> dict:
    t = dict(row)
    t["depends_on"] = json.loads(t.pop("depends_on_json") or "[]")
    t["sheet_ids"] = json.loads(t.pop("sheet_ids_json") or "null")
    t["proposed"] = json.loads(t.pop("proposed_json") or "null")
    t["answers"] = json.loads(t.pop("answers_json") or "null")
    return t


def _load_run(conn, ctx, run_id: int) -> dict:
    row = conn.execute("SELECT * FROM runs WHERE id = ? AND company_id = ?", (int(run_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"run {run_id} not found", run_id=run_id)
    return dict(row)


def _load_task(conn, ctx, task_id: int) -> dict:
    row = conn.execute("SELECT * FROM takeoff_tasks WHERE id = ? AND company_id = ?",
                       (int(task_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"takeoff task {task_id} not found", task_id=task_id)
    return _task(row)


def _tasks(conn, run_id: int) -> list[dict]:
    return [_task(r) for r in conn.execute("SELECT * FROM takeoff_tasks WHERE run_id = ? ORDER BY position, id",
                                           (run_id,))]


def _set_task(conn, task_id: int, **fields) -> None:
    if "state" in fields:
        fields.setdefault("progress", PROGRESS[fields["state"]])
    fields["updated_at"] = _now()
    cols = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE takeoff_tasks SET {cols} WHERE id = ?", [*fields.values(), task_id])


def latest_run(conn, ctx, *, estimate_id: int | None = None, job_id: int | None = None) -> dict | None:
    if job_id is not None:
        row = conn.execute("SELECT * FROM runs WHERE company_id = ? AND job_id = ? AND state != 'cancelled'"
                           " ORDER BY id DESC LIMIT 1", (ctx.company_id, int(job_id))).fetchone()
    else:
        row = conn.execute("SELECT * FROM runs WHERE company_id = ? AND estimate_id = ? AND state != 'cancelled'"
                           " ORDER BY id DESC LIMIT 1", (ctx.company_id, int(estimate_id))).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------- starting a run

def _clean_trades(conn, ctx, trades, reg) -> tuple[list[str], list[str]]:
    if isinstance(trades, str):
        trades = [t.strip() for t in trades.split(",") if t.strip()]
    if not trades or not isinstance(trades, (list, tuple)):
        raise InvalidInput("give the trades to measure, e.g. [\"framing\", \"drywall\", \"roofing\"]",
                           available=sorted(m.id for m in reg.list() if m.category == "construction"))
    keep, off = [], []
    for t in trades:
        mod = reg.modules.get(t)
        if mod is None or mod.category != "construction":
            raise InvalidInput(f"'{t}' isn't a construction trade", field="trades",
                               available=sorted(m.id for m in reg.list() if m.category == "construction"))
        if t in keep or t in off:
            continue
        (keep if get_config(conn, ctx.company_id, t, reg)["enabled"] else off).append(t)
    return keep, off


def _insert_tasks(conn, ctx, run_id: int, estimate_id: int, trades: list[str], start_pos: int) -> None:
    now = _now()
    for i, t in enumerate(trades):
        conn.execute(
            "INSERT INTO takeoff_tasks (company_id, run_id, estimate_id, module_id, position, depends_on_json, state,"
            " progress, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (ctx.company_id, run_id, estimate_id, t, start_pos + i, json.dumps(list(DEPENDS_ON.get(t, ()))),
             "queued", 0, now))


def start_run(conn, ctx: RequestContext, estimate_id: int, trades, *, job_id: int | None = None,
              plan_set_id: int | None = None, registry=None) -> dict:
    """Start a takeoff run: one task per trade. Trades the owner turned off in Agent Manager are skipped."""
    if ctx.role not in START_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't start a takeoff run", role=ctx.role)
    reg = _registry(registry)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    if est["status"] not in service.EDITABLE_STATUSES:
        raise NotEditable(f"estimate {est['id']} is {est['status']}; make a revision first", estimate_id=est["id"])
    open_run = conn.execute("SELECT id FROM runs WHERE company_id = ? AND estimate_id = ? AND state IN (?, ?)",
                            (ctx.company_id, est["id"], *OPEN_RUN_STATES)).fetchone()
    if open_run:
        raise InvalidInput(f"estimate {est['id']} already has run {open_run['id']} going; add trades to it or "
                           "check it with runner_status", run_id=open_run["id"])
    keep, off = _clean_trades(conn, ctx, trades, reg)
    if not keep:
        raise InvalidInput("every trade asked for is turned off in Agent Manager: " + ", ".join(off), turned_off=off)
    now = _now()
    with service.transaction(conn):
        cur = conn.execute(
            "INSERT INTO runs (company_id, estimate_id, job_id, plan_set_id, state, started_by, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ctx.company_id, est["id"], job_id, plan_set_id, "running", ctx.actor, now, now))
        run_id = int(cur.lastrowid)
        _insert_tasks(conn, ctx, run_id, est["id"], keep, 0)
        service._log(conn, ctx, est["id"], "runner_started", {"run_id": run_id, "trades": keep, "skipped": off})
        _advance(conn, ctx, run_id, reg)
    out = run_status(conn, ctx, run_id=run_id)
    if off:
        out["warnings"].append("Skipped (turned off in Agent Manager): " + ", ".join(off) + ".")
    return out


def add_trades(conn, ctx: RequestContext, run_id: int, trades, registry=None) -> dict:
    """Add trades to a run (it reopens if it had finished). Trades already in the run are left alone."""
    if ctx.role not in START_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't change a takeoff run", role=ctx.role)
    reg = _registry(registry)
    run = _load_run(conn, ctx, run_id)
    if run["state"] == "cancelled":
        raise NotEditable(f"run {run_id} was cancelled", run_id=run_id)
    have = [t["module_id"] for t in _tasks(conn, run["id"])]
    keep, off = _clean_trades(conn, ctx, trades, reg)
    new = [t for t in keep if t not in have]
    if new:
        with service.transaction(conn):
            _insert_tasks(conn, ctx, run["id"], run["estimate_id"], new, len(have))
            conn.execute("UPDATE runs SET state = 'running', finished_at = NULL, updated_at = ? WHERE id = ?",
                         (_now(), run["id"]))
            service._log(conn, ctx, run["estimate_id"], "runner_trades_added", {"run_id": run["id"], "trades": new})
            _advance(conn, ctx, run["id"], reg)
    out = run_status(conn, ctx, run_id=run["id"])
    out["added"] = new
    if off:
        out["warnings"].append("Skipped (turned off in Agent Manager): " + ", ".join(off) + ".")
    return out


# ---------------------------------------------------------------- moving tasks along

def _advance(conn, ctx, run_id: int, reg) -> None:
    """Start tasks whose trades are ready, block tasks whose trade failed, and settle the run state.
    Runs inside the caller's transaction."""
    tasks = _tasks(conn, run_id)
    by_module = {t["module_id"]: t for t in tasks}
    now = _now()
    for t in tasks:
        if t["state"] not in ("queued", "blocked"):
            continue
        if t["module_id"] not in reg.modules:
            _set_task(conn, t["id"], state="failed", error=f"the {t['module_id']} module isn't available", finished_at=now)
            t["state"] = "failed"
            continue
        deps = [by_module[d] for d in t["depends_on"] if d in by_module]
        bad = [d["module_id"] for d in deps if d["state"] in ("failed", "blocked")]
        if bad:
            if t["state"] != "blocked":
                _set_task(conn, t["id"], state="blocked", error="waiting on " + ", ".join(bad) + ", which couldn't be done")
                t["state"] = "blocked"
            continue
        if all(d["state"] == "completed" for d in deps):
            _set_task(conn, t["id"], state="running", error=None, started_at=t["started_at"] or now)
            t["state"] = "running"
        elif t["state"] == "blocked":
            _set_task(conn, t["id"], state="queued", error=None)
            t["state"] = "queued"
    states = [t["state"] for t in tasks]
    if all(s in ("completed", "failed", "blocked") for s in states):
        done = states.count("completed")
        state = "completed" if done == len(states) else "partial" if done else "failed"
        conn.execute("UPDATE runs SET state = ?, updated_at = ?, finished_at = COALESCE(finished_at, ?) WHERE id = ?",
                     (state, now, now, run_id))
    else:
        state = "needs_review" if "needs_review" in states and "running" not in states and "queued" not in states \
            else "running"
        conn.execute("UPDATE runs SET state = ?, updated_at = ?, finished_at = NULL WHERE id = ?", (state, now, run_id))


def _check_answers(mod, answers: dict) -> dict:
    """The same checks the Director uses before pricing: known questions, required ones, something to price."""
    stored, _ = quick.resolve_answers(mod, answers)          # raises InvalidInput with the field
    if mod.required_any and not any(_nonzero(answers.get(q)) for q in mod.required_any):
        raise InvalidInput(f"nothing to price for {mod.name}: give at least one of " + ", ".join(mod.required_any),
                           at_least_one=list(mod.required_any))
    return stored


def _nonzero(value) -> bool:
    from estimator.director.engine import _nonzero as nz
    return nz(value)


def submit_takeoff(conn, ctx: RequestContext, task_id: int, answers: dict | None = None, *,
                   confidence: int | None = None, note: str | None = None, cannot_measure: str | None = None,
                   registry=None) -> dict:
    """A takeoff agent (or a person) hands in the quantities for one trade, or says why it can't."""
    if ctx.role not in SUBMIT_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't submit takeoffs", role=ctx.role)
    reg = _registry(registry)
    task = _load_task(conn, ctx, task_id)
    if task["state"] not in ("running", "needs_review"):
        hint = {"queued": "it's waiting for " + ", ".join(task["depends_on"]),
                "completed": "it's already approved; start a new run or revise the estimate to change it",
                "blocked": "a trade it depends on failed; retry that trade first",
                "failed": "retry it first (runner_retry_task)"}.get(task["state"], "")
        raise InvalidInput(f"the {task['module_id']} task is {task['state']}: {hint}", task_id=task["id"],
                           state=task["state"])
    now = _now()
    if cannot_measure:
        with service.transaction(conn):
            _set_task(conn, task["id"], state="failed", error=str(cannot_measure)[:300], submitted_by=ctx.actor,
                      finished_at=now)
            service._log(conn, ctx, task["estimate_id"], "takeoff_failed",
                         {"task_id": task["id"], "module_id": task["module_id"], "reason": str(cannot_measure)[:300]})
            _advance(conn, ctx, task["run_id"], reg)
        return _task_result(conn, ctx, task["id"])
    if answers is None or not isinstance(answers, dict):
        raise InvalidInput("answers must be an object of question id -> quantity for this trade")
    if confidence is not None:
        if isinstance(confidence, bool) or not str(confidence).strip().isdigit() or not 0 <= int(confidence) <= 100:
            raise InvalidInput("confidence is a whole number 0-100", field="confidence")
        confidence = int(confidence)
    mod = reg.get(task["module_id"])
    cfg = get_config(conn, ctx.company_id, mod.id, reg)
    merged = {**cfg["defaults"], **answers}
    stored = _check_answers(mod, merged)
    auto = cfg["auto_advance"] and confidence is not None and confidence >= cfg["confidence_threshold"]
    with service.transaction(conn):
        _set_task(conn, task["id"], state="needs_review", proposed_json=json.dumps(merged), confidence=confidence,
                  submitted_by=ctx.actor, note=note, error=None)
        service._log(conn, ctx, task["estimate_id"], "takeoff_submitted",
                     {"task_id": task["id"], "module_id": mod.id, "answers": stored, "confidence": confidence})
        _advance(conn, ctx, task["run_id"], reg)
    if auto:
        out = _approve(conn, ctx, task["id"], merged, reg, reviewer=f"auto-advance ({confidence}% ≥ "
                                                                    f"{cfg['confidence_threshold']}%)")
        out["auto_approved"] = True
        return out
    return _task_result(conn, ctx, task["id"])


def _approve(conn, ctx, task_id: int, answers: dict, reg, reviewer: str) -> dict:
    task = _load_task(conn, ctx, task_id)
    mod = reg.get(task["module_id"])
    stored = _check_answers(mod, answers)
    est = service.get_estimate(conn, ctx, task["estimate_id"])
    if est["status"] not in service.EDITABLE_STATUSES:
        raise NotEditable(f"estimate {est['id']} is {est['status']}; make a revision first", estimate_id=est["id"])
    priced = quick.answer(conn, _runner_ctx(ctx), est["id"], mod.id, stored, est["rev"], reg)
    sub = next((s["subtotal_cents"] for s in priced["sections"] if s["module_id"] == mod.id), 0)
    with service.transaction(conn):
        _set_task(conn, task["id"], state="completed", answers_json=json.dumps(stored), reviewed_by=reviewer,
                  finished_at=_now(), error=None)
        service._log(conn, ctx, task["estimate_id"], "takeoff_approved",
                     {"task_id": task["id"], "module_id": mod.id, "answers": stored, "subtotal_cents": sub,
                      "approved_by": reviewer})
        _advance(conn, ctx, task["run_id"], reg)
    return _task_result(conn, ctx, task["id"])


def review_task(conn, ctx: RequestContext, task_id: int, *, approve: bool = False, answers: dict | None = None,
                note: str | None = None, registry=None) -> dict:
    """Approve the submitted quantities (optionally with corrections in answers), or send them back with a note."""
    if ctx.role not in REVIEW_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't review takeoffs", role=ctx.role)
    reg = _registry(registry)
    task = _load_task(conn, ctx, task_id)
    if task["state"] != "needs_review":
        raise InvalidInput(f"the {task['module_id']} task is {task['state']}, not waiting for review",
                           task_id=task["id"], state=task["state"])
    if answers is not None and not isinstance(answers, dict):
        raise InvalidInput("answers must be an object of question id -> quantity")
    if approve:
        return _approve(conn, ctx, task["id"], {**task["proposed"], **(answers or {})}, reg, reviewer=ctx.actor)
    if not (note or "").strip():
        raise InvalidInput("to send a takeoff back, say what to fix (note), or approve=true to accept it",
                           field="note")
    with service.transaction(conn):
        _set_task(conn, task["id"], state="running", note=note.strip()[:500], reviewed_by=ctx.actor)
        service._log(conn, ctx, task["estimate_id"], "takeoff_sent_back",
                     {"task_id": task["id"], "module_id": task["module_id"], "note": note.strip()[:500]})
        _advance(conn, ctx, task["run_id"], reg)
    return _task_result(conn, ctx, task["id"])


def retry_task(conn, ctx: RequestContext, task_id: int, registry=None) -> dict:
    """Try a failed or blocked trade again (trades waiting on it are unblocked too)."""
    if ctx.role not in START_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't retry takeoffs", role=ctx.role)
    reg = _registry(registry)
    task = _load_task(conn, ctx, task_id)
    if task["state"] not in ("failed", "blocked"):
        raise InvalidInput(f"the {task['module_id']} task is {task['state']}; only failed or blocked tasks are retried",
                           task_id=task["id"], state=task["state"])
    with service.transaction(conn):
        _set_task(conn, task["id"], state="queued", error=None, finished_at=None)
        conn.execute("UPDATE runs SET state = 'running', finished_at = NULL, updated_at = ? WHERE id = ?",
                     (_now(), task["run_id"]))
        service._log(conn, ctx, task["estimate_id"], "takeoff_retried",
                     {"task_id": task["id"], "module_id": task["module_id"]})
        _advance(conn, ctx, task["run_id"], reg)
    return _task_result(conn, ctx, task["id"])


# ---------------------------------------------------------------- reading

def _next_action(t: dict) -> str:
    m = t["module_id"].replace("_", " ")
    return {
        "queued": f"waits for {', '.join(d.replace('_', ' ') for d in t['depends_on'])}",
        "running": (f"measure {m} from the plans and submit it (runner_submit_takeoff task_id={t['id']})"
                    + (f"; reviewer said: {t['note']}" if t["note"] else "")),
        "needs_review": f"a person checks the {m} quantities (runner_review_task task_id={t['id']}, approve=true)",
        "completed": "done",
        "blocked": t["error"] or "blocked",
        "failed": f"couldn't be done: {t['error']}. Retry with runner_retry_task task_id={t['id']}",
    }[t["state"]]


def _public(t: dict) -> dict:
    return {"task_id": t["id"], "module_id": t["module_id"], "state": t["state"], "progress": t["progress"],
            "depends_on": t["depends_on"], "confidence": t["confidence"], "proposed": t["proposed"],
            "answers": t["answers"], "submitted_by": t["submitted_by"], "reviewed_by": t["reviewed_by"],
            "error": t["error"], "note": t["note"], "next": _next_action(t)}


def run_status(conn, ctx: RequestContext, *, run_id: int | None = None, estimate_id: int | None = None) -> dict:
    if run_id is None:
        if estimate_id is None:
            raise InvalidInput("give run_id or estimate_id")
        service.get_estimate(conn, ctx, int(estimate_id))     # company scoping
        run = latest_run(conn, ctx, estimate_id=int(estimate_id))
        if run is None:
            raise NotFound(f"estimate {estimate_id} has no takeoff run", estimate_id=estimate_id)
    else:
        run = _load_run(conn, ctx, run_id)
    tasks = [_public(t) for t in _tasks(conn, run["id"])]
    counts = {s: sum(1 for t in tasks if t["state"] == s) for s in TASK_STATES}
    est = service.get_estimate(conn, ctx, run["estimate_id"])
    total = (est["totals"] or {}).get("total_cents", 0)
    progress = round(sum(t["progress"] for t in tasks) / len(tasks)) if tasks else 0
    parts = [f"{n} {s.replace('_', ' ')}" for s, n in counts.items() if n]
    return {"ok": True, "run": {"id": run["id"], "estimate_id": run["estimate_id"], "job_id": run["job_id"],
                                "state": run["state"], "progress": progress, "started_by": run["started_by"],
                                "created_at": run["created_at"], "finished_at": run["finished_at"]},
            "tasks": tasks, "counts": counts, "estimate_total_cents": total,
            "summary": f"Run {run['id']} is {run['state'].replace('_', ' ')} ({', '.join(parts)}); "
                       f"the estimate is {format_cents(total)} so far.",
            "warnings": []}


def _task_result(conn, ctx, task_id: int) -> dict:
    task = _load_task(conn, ctx, task_id)
    out = run_status(conn, ctx, run_id=task["run_id"])
    out["task"] = next(t for t in out["tasks"] if t["task_id"] == task["id"])
    if out["run"]["state"] in ("completed", "partial") and out["run"]["job_id"]:
        out["warnings"].append(f"Every trade is settled. Continue the job with est_director_next(job_id="
                               f"{out['run']['job_id']}).")
    return out


def project_status(conn, ctx: RequestContext, estimate_id: int, registry=None) -> dict:
    """Project dashboard: totals, each trade's subtotal and headline quantities, and the takeoff tasks."""
    reg = _registry(registry)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    trades = []
    for s in est["sections"]:
        mod = reg.modules.get(s["module_id"])
        top = sorted(s["lines"], key=lambda ln: ln["total_cents"], reverse=True)[:3]
        trades.append({"module_id": s["module_id"], "name": mod.name if mod else s["module_id"],
                       "subtotal_cents": s["subtotal_cents"],
                       "headline": [f"{ln['description']}: {ln['quantity']} {ln['unit']}" for ln in top]})
    run = latest_run(conn, ctx, estimate_id=est["id"])
    job = conn.execute("SELECT id, lane, stage, state, waiting_on FROM director_jobs WHERE company_id = ? AND"
                       " estimate_id = ? ORDER BY id DESC LIMIT 1", (ctx.company_id, est["id"])).fetchone()
    out = {"ok": True,
           "estimate": {"id": est["id"], "title": est["title"], "status": est["status"], "rev": est["rev"],
                        "revision": est.get("revision"), "total_cents": (est["totals"] or {}).get("total_cents", 0)},
           "trades": trades, "run": None, "job": dict(job) if job else None}
    if run:
        st = run_status(conn, ctx, run_id=run["id"])
        out["run"] = {**st["run"], "counts": st["counts"],
                      "tasks": [{k: t[k] for k in ("task_id", "module_id", "state", "progress", "next")}
                                for t in st["tasks"]]}
    waiting = [t for t in (out["run"] or {}).get("tasks", []) if t["state"] in ("running", "needs_review", "failed")]
    out["summary"] = (f"{est['title'] or 'Estimate ' + str(est['id'])}: {format_cents(out['estimate']['total_cents'])}"
                      f" across {len(trades)} trade(s), {est['status']}."
                      + (" Needs attention: " + "; ".join(f"{t['module_id']} {t['state'].replace('_', ' ')}"
                                                           for t in waiting) + "." if waiting else ""))
    return out

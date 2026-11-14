"""The agent task queue: unattended work for the Reviewer, Bid Writer and Follow-up agents.

The watcher (every 15 minutes) calls run(): it queues work that's due and runs queued tasks on each role's
provider. Each task gets ONE context pack (the estimate, the job or the quote it's about) and the agent answers
with JSON actions only. The actions are checked and applied here, through the same service layer as everything
else, and none of them changes money or reaches a customer:

    reviewer    review_note{body}, flag{message, severity}   -> notes in the Director inbox for the reviewer
    bid_writer  draft_bid{scope_text, inclusions, exclusions} -> used for the bid when it's made (a person previews
                                                                 and sends it), or applied later with apply_draft
    follow_up   draft_message{subject, body}                 -> a draft email; a person sends it with apply_draft

A draft that mentions a dollar amount that isn't in the context pack is refused: agents never invent numbers.

Providers: chat_only tasks wait as "waiting_for_ai" until someone runs them from chat (next_task / submit). API
tasks run within the daily and monthly budget (paused when it's used up), try the backup provider if the first
one fails, and give up after 3 tries with a notice. Every call's tokens and cost are logged, and every call is
written to the AI Log (agents/ai_log.py) with its prompt, reply and parsed actions.
"""
from __future__ import annotations

import json
import re
import time
from datetime import date, datetime, timezone
from pathlib import Path

from estimator.agents import ai_log, providers, roles
from estimator.context import RequestContext
from estimator.core.units.money import format_cents
from estimator.errors import EstimatorError, InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.estimating import service

PROMPTS = Path(__file__).parent / "prompts"
MAX_ATTEMPTS = 3
PER_RUN = 5
ACTIONS = {
    "reviewer": {"review_note": {"body": 600}, "flag": {"message": 400, "severity": 10}, "no_action": {}},
    "bid_writer": {"draft_bid": {"scope_text": 3000, "inclusions": 1500, "exclusions": 1500}, "no_action": {}},
    "follow_up": {"draft_message": {"subject": 150, "body": 1500}, "no_action": {}},
}
REQUIRED = {"review_note": ("body",), "flag": ("message",), "draft_bid": ("scope_text",),
            "draft_message": ("subject", "body")}
SUBMIT_ROLES = ("owner", "estimator", "reviewer", "office")
APPLY_ROLES = service.QUICK_ROLES           # owner, estimator, office
_MONEY = re.compile(r"\$\s?(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{2}))?")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def prompt(role: str) -> str:
    """The role prompt with the shared rules (also what how_to_estimate returns)."""
    rules = (PROMPTS / "rules.md").read_text(encoding="utf-8")
    path = PROMPTS / f"{role}.md"
    if not path.exists():
        raise NotFound(f"no prompt for '{role}'", available=sorted(p.stem for p in PROMPTS.glob("*.md")
                                                                    if p.stem != "rules"))
    return path.read_text(encoding="utf-8").strip() + "\n\n" + rules.strip()


def headless_rules(role: str) -> str:
    acts = ACTIONS[role]
    fields = "; ".join(f"{a}{{{', '.join(f)}}}" if f else f"{a}{{}}" for a, f in acts.items())
    return ("You are running on your own (no person is watching). You get ONE task as JSON. Reply with ONLY one "
            'JSON object: {"actions": [{"action": "...", ...fields...}], "summary": "one line"}. '
            f"Allowed actions: {fields}. Use only facts and numbers that are in the task. If nothing is worth doing, "
            'reply {"actions": [{"action": "no_action"}], "summary": "..."}.')


# ---------------------------------------------------------------- context packs

def _estimate_pack(conn, ctx, estimate_id: int, reg) -> dict:
    est = service.get_estimate(conn, ctx, estimate_id)
    sections = []
    for s in est["sections"]:
        mod = reg.modules.get(s["module_id"])
        sections.append({"trade": mod.name if mod else s["module_id"], "module_id": s["module_id"],
                         "subtotal": format_cents(s["subtotal_cents"]),
                         "answers": s.get("answers") or {},
                         "lines": [{"description": ln["description"], "quantity": ln["quantity"], "unit": ln["unit"],
                                    "unit_cost": format_cents(ln["unit_cost_cents"] or 0),
                                    "total": format_cents(ln["total_cents"] or 0)} for ln in s["lines"]]})
    totals = est["totals"] or {}
    return {"estimate_id": est["id"], "title": est["title"], "status": est["status"], "sections": sections,
            "total": format_cents(totals.get("total_cents", 0))}


def _money_in(pack) -> set[int]:
    """Every dollar amount in a context pack, in cents (drafts may only mention these)."""
    found = set()
    for m in _MONEY.finditer(json.dumps(pack)):
        found.add(int(m.group(1).replace(",", "")) * 100 + int(m.group(2) or 0))
    return found


def build_pack(conn, ctx, task: dict, registry=None) -> dict:
    reg = _registry(registry)
    role = task["role"]
    pack: dict = {"task_id": task["id"], "role": role}
    if role == "reviewer":
        from estimator.estimating import validate
        pack["estimate"] = _estimate_pack(conn, ctx, task["estimate_id"], reg)
        v = validate.validate(conn, ctx, task["estimate_id"], registry=reg)
        pack["checks"] = [{"level": f["level"], "message": f["message"]} for f in v.get("findings", [])]
        from estimator.learning import history
        hist = history.compare_history(conn, ctx, estimate_id=task["estimate_id"])
        pack["history"] = [r["message"] for r in hist["lines"] if r.get("flag") and r.get("message")]
        job = conn.execute("SELECT request_text FROM director_jobs WHERE id = ? AND company_id = ?",
                           (task["job_id"], ctx.company_id)).fetchone() if task["job_id"] else None
        pack["request"] = job["request_text"] if job else None
    elif role == "bid_writer":
        pack["estimate"] = _estimate_pack(conn, ctx, task["estimate_id"], reg)
        pack["notes_for_scope"] = [n for s in pack["estimate"]["sections"]
                                   for n in (reg.modules[s["module_id"]].notes if s["module_id"] in reg.modules else ())]
    elif role == "follow_up":
        from estimator.bids import service as bids
        b = bids._load(conn, ctx, task["bid_id"])
        cust = b.get("customer") or {}
        company = bids._company(conn, ctx.company_id)
        pack.update(quote={"number": b["number"], "title": service.get_estimate(conn, ctx, b["estimate_id"])["title"],
                           "total": format_cents(b["total_cents"]), "sent_on": (b.get("sent_at") or "")[:10],
                           "valid_until": b["valid_until"]},
                    customer_first_name=(cust.get("name") or cust.get("first_name") or "").split(" ")[0] or None,
                    company_name=company.get("name") or "our team")
    return pack


# ---------------------------------------------------------------- queueing

def _role_provider(conn, company_id: str, role: str) -> dict:
    return roles.get_role(conn, company_id, role)


def _enqueue(conn, ctx, role: str, key: str, *, estimate_id=None, job_id=None, bid_id=None) -> int | None:
    cfg = _role_provider(conn, ctx.company_id, role)
    if cfg["provider"] == "off":
        return None
    state = "waiting_for_ai" if cfg["provider"] == "chat_only" else "queued"
    now = _now()
    cur = conn.execute("INSERT OR IGNORE INTO agent_tasks (company_id, role, dedupe_key, estimate_id, job_id, bid_id,"
                       " state, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                       (ctx.company_id, role, key, estimate_id, job_id, bid_id, state, now, now))
    return cur.lastrowid if cur.rowcount == 1 else None


def enqueue_due(conn, ctx: RequestContext, today: date | None = None) -> list[int]:
    """Queue the work that's due: estimates waiting for a reviewer, approved estimates about to get a bid,
    and sent quotes due a follow-up. Each piece of work is queued once (per estimate version or per quote)."""
    from estimator.director.briefing import followups_due
    made = []
    with service.transaction(conn):
        for j in conn.execute("SELECT j.id, j.stage, j.estimate_id, e.rev FROM director_jobs j JOIN estimates e ON"
                              " e.id = j.estimate_id WHERE j.company_id = ? AND j.state = 'waiting_on_user'"
                              " AND j.stage IN ('review', 'approve', 'write_bid')", (ctx.company_id,)).fetchall():
            if j["stage"] == "review":
                t = _enqueue(conn, ctx, "reviewer", f"review:{j['estimate_id']}:{j['rev']}",
                             estimate_id=j["estimate_id"], job_id=j["id"])
            else:
                t = _enqueue(conn, ctx, "bid_writer", f"bid:{j['estimate_id']}", estimate_id=j["estimate_id"],
                             job_id=j["id"])
            if t:
                made.append(t)
        for f in followups_due(conn, ctx, today=today)["follow_ups"]:
            t = _enqueue(conn, ctx, "follow_up", f"follow:{f['bid_id']}:{f['sent_on']}", bid_id=f["bid_id"])
            if t:
                made.append(t)
    return made


# ---------------------------------------------------------------- checking and applying actions

def _check_actions(role: str, actions, pack: dict) -> list[dict]:
    if not isinstance(actions, list) or not actions:
        raise InvalidInput("actions must be a non-empty list of {action: ..., fields}", allowed=list(ACTIONS[role]))
    allowed = ACTIONS[role]
    money = _money_in(pack)
    clean = []
    for a in actions[:8]:
        if not isinstance(a, dict) or a.get("action") not in allowed:
            raise InvalidInput(f"{role} can only use {list(allowed)}", got=a if isinstance(a, dict) else str(a)[:80])
        name = a["action"]
        out = {"action": name}
        for f, limit in allowed[name].items():
            v = a.get(f)
            if v is None:
                continue
            # AI models often send inclusions and exclusions as a list of points: one point per line (2026-11-12,
            # David: the Bid Writer gave up after 3 tries on "draft_bid.inclusions must be text").
            if isinstance(v, (list, tuple)) and all(isinstance(x, str) for x in v):
                v = "\n".join("- " + x.strip().lstrip("-• ").strip() for x in v if x.strip())
            if not isinstance(v, str):
                raise InvalidInput(f"{name}.{f} must be text", field=f)
            v = v.strip()[:limit]
            for m in _MONEY.finditer(v):
                cents = int(m.group(1).replace(",", "")) * 100 + int(m.group(2) or 0)
                if cents not in money:
                    raise InvalidInput(f"{name}.{f} mentions {m.group(0).strip()}, which isn't in the estimate or "
                                       "quote: agents never invent numbers", field=f)
            out[f] = v
        missing = [f for f in REQUIRED.get(name, ()) if not out.get(f)]
        if missing:
            raise InvalidInput(f"{name} needs {missing}", field=missing[0])
        if name == "flag":
            out["severity"] = out.get("severity") if out.get("severity") in ("info", "warning") else "warning"
        clean.append(out)
    return clean


def _notice(conn, ctx, kind, key, message, **ids):
    from estimator.director.watch import _notice as make
    return make(conn, ctx, kind, key, message, **ids)


def _apply(conn, ctx, task: dict, actions: list[dict], summary: str) -> dict:
    """Store the result and leave notes for people. Runs inside the caller's transaction."""
    role, ids = task["role"], {"job_id": task["job_id"], "estimate_id": task["estimate_id"], "bid_id": task["bid_id"]}
    notes = []
    for i, a in enumerate(actions):
        key = f"agent:{task['id']}:{i}"
        if a["action"] == "review_note":
            notes.append(_notice(conn, ctx, "agent_review", key, f"Reviewer agent, estimate {task['estimate_id']}: "
                                                                  f"{a['body']}", **ids))
        elif a["action"] == "flag":
            notes.append(_notice(conn, ctx, "agent_flag", key, f"Reviewer agent flagged estimate "
                                                                f"{task['estimate_id']} ({a['severity']}): "
                                                                f"{a['message']}", **ids))
        elif a["action"] == "draft_bid":
            notes.append(_notice(conn, ctx, "agent_draft", key, f"The Bid Writer drafted the scope for estimate "
                                                                 f"{task['estimate_id']}. It goes on the bid when it's "
                                                                 f"made (check the preview), or use it now with "
                                                                 f"est_agent_apply(task_id={task['id']}).", **ids))
        elif a["action"] == "draft_message":
            notes.append(_notice(conn, ctx, "agent_draft", key, f"Follow-up email drafted for quote (task "
                                                                 f"{task['id']}): \"{a['subject']}\". Send it with "
                                                                 f"est_agent_apply(task_id={task['id']}, confirm=true).",
                                 **ids))
    result = {"actions": actions, "summary": summary[:300]}
    conn.execute("UPDATE agent_tasks SET state = 'done', result_json = ?, error = NULL, updated_at = ?, finished_at = ?"
                 " WHERE id = ?", (json.dumps(result), _now(), _now(), task["id"]))
    if task["estimate_id"]:
        service._log(conn, ctx, task["estimate_id"], "agent_task_done",
                     {"task_id": task["id"], "role": role, "provider": task.get("provider_used"),
                      "model": task.get("model_used"), "actions": [a["action"] for a in actions]})
    return {"task_id": task["id"], "role": role, "state": "done", "actions": actions,
            "notices": [n["id"] for n in notes if n]}


def _load(conn, ctx, task_id: int) -> dict:
    row = conn.execute("SELECT * FROM agent_tasks WHERE id = ? AND company_id = ?",
                       (int(task_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"agent task {task_id} not found", task_id=task_id)
    return dict(row)


def _public(t: dict) -> dict:
    return {"task_id": t["id"], "role": t["role"], "state": t["state"], "estimate_id": t["estimate_id"],
            "job_id": t["job_id"], "bid_id": t["bid_id"], "attempts": t["attempts"], "provider": t["provider_used"],
            "model": t["model_used"], "error": t["error"],
            "result": json.loads(t["result_json"]) if t["result_json"] else None,
            "applied": bool(t["applied_at"]), "created_at": t["created_at"]}


# ---------------------------------------------------------------- running on an API key

def _run_one(conn, ctx, task: dict, cfg: dict, reg) -> dict:
    """Try the main provider, then the backup. Returns the task's new public shape."""
    try:
        pack = build_pack(conn, ctx, task, reg)
    except EstimatorError as exc:
        with service.transaction(conn):
            conn.execute("UPDATE agent_tasks SET state = 'cancelled', error = ?, updated_at = ? WHERE id = ?",
                         (f"nothing to work on: {exc.message}"[:300], _now(), task["id"]))
        return _public(_load(conn, ctx, task["id"]))
    system = prompt(task["role"]) + "\n\n" + headless_rules(task["role"])
    user = json.dumps(pack, default=str)
    purpose = f"{roles.ROLES[task['role']]['label']} agent, task {task['id']}"
    errors = []
    for which in [p for p in (cfg["provider"], cfg.get("fallback_provider")) if p]:
        ok, why = providers.ready(which)
        if not ok:
            errors.append(f"{which}: {why}")
            continue
        # The model follows the top of the Small Business tab (2026-11-13): reviewer notes are an internal step,
        # bid scope and follow-ups are customer messages (providers.STEP_GROUPS).
        model = providers.model_for_step(which, task["role"], None,
                                         cfg.get("model_pinned") if which == cfg["provider"] else None)
        started = time.monotonic()
        try:
            text, usage = providers.ask(which, system, user, model)
        except providers.ProviderError as exc:
            with service.transaction(conn):
                roles.record_usage(conn, ctx, task_id=task["id"], role=task["role"], provider=which, model=model,
                                   usage=None, ok=False, error=str(exc))
            # The AI Log row is written outside the transaction, so it stays even
            # when the run that made it fails afterwards (autocommit connection).
            ai_log.record(conn, ctx, provider=which, model=model, role=task["role"], purpose=purpose,
                          system_prompt=system, user_prompt=user, task_id=task["id"],
                          estimate_id=task["estimate_id"],
                          duration_ms=int((time.monotonic() - started) * 1000),
                          ok=False, error=str(exc))
            errors.append(f"{which}: {exc}")
            continue
        with service.transaction(conn):
            roles.record_usage(conn, ctx, task_id=task["id"], role=task["role"], provider=which, model=model,
                               usage=usage, ok=True)
        log_id = ai_log.record(conn, ctx, provider=which, model=model, role=task["role"], purpose=purpose,
                               system_prompt=system, user_prompt=user, task_id=task["id"],
                               estimate_id=task["estimate_id"], response_text=text, usage=usage,
                               duration_ms=int((time.monotonic() - started) * 1000))
        try:
            from_ai = _parse(text)
            actions = _check_actions(task["role"], from_ai["actions"], pack)
        except (InvalidInput, providers.ProviderError) as exc:
            ai_log.set_error(conn, ctx.company_id, log_id, getattr(exc, 'message', str(exc)))
            errors.append(f"{which}: {getattr(exc, 'message', str(exc))}")
            continue
        ai_log.set_parsed(conn, ctx.company_id, log_id, from_ai)
        task.update(provider_used=which, model_used=model)
        with service.transaction(conn):
            conn.execute("UPDATE agent_tasks SET provider_used = ?, model_used = ?, attempts = attempts + 1"
                         " WHERE id = ?", (which, model, task["id"]))
            if which != cfg["provider"]:
                _notice(conn, ctx, "agent_fallback", f"fallback:{task['id']}",
                        f"The {roles.ROLES[task['role']]['label']} agent used the backup ({which}) because "
                        f"{errors[0]}", job_id=task["job_id"], estimate_id=task["estimate_id"], bid_id=task["bid_id"])
            _apply(conn, ctx, task, actions, from_ai.get("summary", ""))
        return _public(_load(conn, ctx, task["id"]))
    with service.transaction(conn):
        attempts = task["attempts"] + 1
        state = "failed" if attempts >= MAX_ATTEMPTS else "queued"
        conn.execute("UPDATE agent_tasks SET attempts = ?, state = ?, error = ?, updated_at = ? WHERE id = ?",
                     (attempts, state, "; ".join(errors)[:500], _now(), task["id"]))
        if state == "failed":
            _notice(conn, ctx, "agent_failed", f"failed:{task['id']}",
                    f"The {roles.ROLES[task['role']]['label']} agent gave up after {attempts} tries: "
                    + "; ".join(errors)[:300], job_id=task["job_id"], estimate_id=task["estimate_id"],
                    bid_id=task["bid_id"])
    return _public(_load(conn, ctx, task["id"]))


def _parse(text: str) -> dict:
    t = re.sub(r"^```(?:json)?|```$", "", (text or "").strip(), flags=re.M).strip()
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        raise providers.ProviderError("the AI didn't answer with JSON")
    try:
        obj = json.loads(t[start:end + 1])
    except ValueError as exc:
        raise providers.ProviderError(f"the AI's JSON couldn't be read: {exc}") from None
    if not isinstance(obj, dict) or not isinstance(obj.get("actions"), list):
        raise providers.ProviderError("the AI's answer has no actions list")
    return obj


def run(conn, ctx: RequestContext, now: datetime | None = None, *, limit: int = PER_RUN, registry=None) -> dict:
    """Queue what's due, then run up to `limit` queued tasks on their API providers within the budget."""
    reg = _registry(registry)
    queued = enqueue_due(conn, ctx, today=(now.date() if now else None))
    ran, paused = [], []
    ok_budget, why = roles.budget_left(conn, ctx.company_id, now)
    with service.transaction(conn):
        if ok_budget:       # a new day or month, or a raised budget, lets paused work go again
            conn.execute("UPDATE agent_tasks SET state = 'queued', error = NULL, updated_at = ? WHERE company_id = ?"
                         " AND state = 'paused'", (_now(), ctx.company_id))
    rows = [dict(r) for r in conn.execute("SELECT * FROM agent_tasks WHERE company_id = ? AND state = 'queued'"
                                          " ORDER BY id LIMIT ?", (ctx.company_id, max(1, int(limit))))]
    for task in rows:
        cfg = _role_provider(conn, ctx.company_id, task["role"])
        if cfg["provider"] in ("off", "chat_only"):
            with service.transaction(conn):
                new_state = "cancelled" if cfg["provider"] == "off" else "waiting_for_ai"
                conn.execute("UPDATE agent_tasks SET state = ?, updated_at = ? WHERE id = ?",
                             (new_state, _now(), task["id"]))
            continue
        ok_budget, why = roles.budget_left(conn, ctx.company_id, now)
        if not ok_budget:
            with service.transaction(conn):
                conn.execute("UPDATE agent_tasks SET state = 'paused', error = ?, updated_at = ? WHERE company_id = ?"
                             " AND state = 'queued'", (why, _now(), ctx.company_id))
                _notice(conn, ctx, "agent_budget", f"budget:{(now or datetime.now()).strftime('%Y-%m-%d')}",
                        f"AI agents paused: {why}. They pick up again when there's budget (agent_budget_update).")
            paused.append(why)
            break
        ran.append(_run_one(conn, ctx, task, cfg, reg))
    return {"queued": queued, "ran": ran, "paused": paused[0] if paused else None}


# ---------------------------------------------------------------- from chat

def list_tasks(conn, ctx: RequestContext, state: str | None = None, limit: int = 50) -> dict:
    sql, args = "SELECT * FROM agent_tasks WHERE company_id = ?", [ctx.company_id]
    if state:
        sql += " AND state = ?"
        args.append(state)
    rows = [_public(dict(r)) for r in conn.execute(sql + " ORDER BY id DESC LIMIT ?",
                                                   [*args, max(1, min(int(limit), 200))])]
    counts = {r["state"]: r["n"] for r in conn.execute("SELECT state, COUNT(*) AS n FROM agent_tasks WHERE"
                                                       " company_id = ? GROUP BY state", (ctx.company_id,))}
    return {"ok": True, "tasks": rows, "counts": counts}


def next_task(conn, ctx: RequestContext, role: str | None = None, registry=None) -> dict:
    """The next task waiting for an AI in chat, with its role prompt, context pack and allowed actions."""
    sql = "SELECT * FROM agent_tasks WHERE company_id = ? AND state IN ('waiting_for_ai', 'queued')"
    args = [ctx.company_id]
    if role:
        if role not in ACTIONS:
            raise InvalidInput(f"role must be one of {list(ACTIONS)}", field="role")
        sql += " AND role = ?"
        args.append(role)
    row = conn.execute(sql + " ORDER BY state = 'queued', id LIMIT 1", args).fetchone()
    if row is None:
        return {"ok": True, "task": None, "say": "No agent work is waiting."}
    task = dict(row)
    return {"ok": True, "task": _public(task), "prompt": prompt(task["role"]),
            "context": build_pack(conn, ctx, task, registry),
            "allowed_actions": {a: list(f) for a, f in ACTIONS[task["role"]].items()},
            "submit_with": f"est_agent_submit(task_id={task['id']}, actions=[...])"}


def submit(conn, ctx: RequestContext, task_id: int, actions, summary: str = "", registry=None) -> dict:
    """Hand in a chat AI's actions for one task; they're checked exactly like an unattended agent's."""
    if ctx.role not in SUBMIT_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't run agent tasks", role=ctx.role)
    task = _load(conn, ctx, task_id)
    if task["state"] not in ("waiting_for_ai", "queued", "paused"):
        raise InvalidInput(f"agent task {task['id']} is {task['state']}", task_id=task["id"], state=task["state"])
    pack = build_pack(conn, ctx, task, registry)
    clean = _check_actions(task["role"], actions, pack)
    task.update(provider_used="chat", model_used=None)
    with service.transaction(conn):
        conn.execute("UPDATE agent_tasks SET provider_used = 'chat', attempts = attempts + 1 WHERE id = ?",
                     (task["id"],))
        out = _apply(conn, ctx, task, clean, summary or "")
    return {"ok": True, **out}


def latest_draft(conn, ctx, estimate_id: int) -> dict | None:
    """The newest unused Bid Writer draft for an estimate (the Director puts it on the bid)."""
    row = conn.execute("SELECT * FROM agent_tasks WHERE company_id = ? AND role = 'bid_writer' AND estimate_id = ?"
                       " AND state = 'done' AND applied_at IS NULL ORDER BY id DESC LIMIT 1",
                       (ctx.company_id, estimate_id)).fetchone()
    if row is None:
        return None
    acts = json.loads(row["result_json"] or "{}").get("actions", [])
    draft = next((a for a in acts if a["action"] == "draft_bid"), None)
    return {"task_id": row["id"], **draft} if draft else None


def mark_applied(conn, task_id: int) -> None:
    conn.execute("UPDATE agent_tasks SET applied_at = ?, updated_at = ? WHERE id = ?", (_now(), _now(), task_id))


def apply_draft(conn, ctx: RequestContext, task_id: int, *, confirm: bool = False, to: str | None = None,
                registry=None) -> dict:
    """Use a draft: a Bid Writer scope becomes a new draft bid (preview it before sending); a Follow-up email is
    sent to the customer (needs confirm=true)."""
    from estimator.bids import service as bids
    from estimator.integrations import host
    if ctx.role not in APPLY_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't use agent drafts", role=ctx.role)
    task = _load(conn, ctx, task_id)
    if task["state"] != "done" or not task["result_json"]:
        raise InvalidInput(f"agent task {task['id']} has no draft yet ({task['state']})", task_id=task["id"])
    if task["applied_at"]:
        raise InvalidInput(f"the draft from agent task {task['id']} was already used", task_id=task["id"])
    acts = json.loads(task["result_json"])["actions"]
    if task["role"] == "bid_writer":
        d = next((a for a in acts if a["action"] == "draft_bid"), None)
        if d is None:
            raise InvalidInput("this Bid Writer task has no draft")
        cur = bids.latest_for_estimate(conn, ctx, task["estimate_id"])
        if cur and cur["status"] != "draft":
            raise NotEditable(f"quote {cur['number']} was already sent; revise the estimate to change its scope",
                              bid_id=cur["id"])
        cust = (cur.get("customer") or None) if cur else None
        made = bids.generate(conn, ctx, task["estimate_id"], customer=cust, scope_text=d["scope_text"],
                             inclusions=d.get("inclusions"), exclusions=d.get("exclusions"), registry=registry)
        if cur:                                   # the unsent draft it replaces
            bids.set_status(conn, ctx, cur["id"], "void")
        with service.transaction(conn):
            mark_applied(conn, task["id"])
        return {"ok": True, "bid": made, "say": f"Quote {made['number']} now has the Bid Writer's scope. Preview it "
                                                "(bid_preview) before sending."}
    if task["role"] == "follow_up":
        d = next((a for a in acts if a["action"] == "draft_message"), None)
        if d is None:
            raise InvalidInput("this Follow-up task has no draft")
        b = bids._load(conn, ctx, task["bid_id"])
        address = (to or b.get("sent_to") or "").strip()
        if not address:
            raise InvalidInput("who should get it? give to=email", field="to")
        if not confirm:
            return {"ok": True, "confirmed": False, "would_send": {"to": address, **d},
                    "say": "Nothing sent yet. Read it to the user; send with confirm=true when they say yes."}
        host.call("send_email", to=address, subject=d["subject"], body=d["body"])
        with service.transaction(conn):
            mark_applied(conn, task["id"])
            service._log(conn, ctx, b["estimate_id"], "follow_up_sent", {"bid_id": b["id"], "to": address,
                                                                         "agent_task": task["id"]})
        return {"ok": True, "confirmed": True, "sent_to": address}
    raise InvalidInput("only Bid Writer and Follow-up drafts can be used")

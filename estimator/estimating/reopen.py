"""Reopen an approved or sent estimate for changes, and show what changed since it was approved (2026-11-16, David).

"We also will need the option to submit and update the bid/quote/estimate when the customer asks for additional work
or changes his mind on what he wants. It's got to be flexible."

An approved estimate - or one whose quote went out and the customer wants something different, or said no, or let
expire - is reopened in place (same estimate, same plans and measurements). Reopening keeps a snapshot of what was
approved; the next approval shows only what changed since then (answers, lines added, removed or changed, and the
total), so the approver checks the changes, not the whole estimate again. A quote that was already sent is kept on
record as replaced, and the next quote (Q-0004-2) tells the customer it replaces it and what changed.

Once the customer accepted (won, a job made), more work is a change order instead (change_orders.py).
"""
from __future__ import annotations

from estimator.context import RequestContext
from estimator.core.units.money import format_cents
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable
from estimator.estimating import service

REOPENABLE = ("approved", "sent", "lost", "expired")
OPEN_BID_STATUSES = ("draft", "sent", "viewed", "lost", "expired")
LINE_FIELDS = ("description", "kind", "quantity", "unit", "unit_cost_cents", "waste_pct", "total_cents")


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def _line_key(module_id: str, ln: dict) -> str:
    """A trade's own lines are matched by their rule (they get new ids when re-priced); hand lines by id."""
    rule = (ln.get("calc") or {}).get("rule")
    return f"{module_id}:{rule}" if rule else f"{module_id}:#{ln['id']}"


def snapshot(est: dict) -> dict:
    """What an approval covers: each trade's answers and lines, and the total."""
    return {"total_cents": (est.get("totals") or {}).get("total_cents", 0),
            "sections": [{"module_id": s["module_id"], "answers": s.get("answers") or {},
                          "lines": [{"key": _line_key(s["module_id"], ln), **{f: ln.get(f) for f in LINE_FIELDS}}
                                    for ln in s["lines"]]}
                         for s in est["sections"]]}


def won_quote(conn, estimate_id: int):
    return conn.execute("SELECT number, job_id FROM bids WHERE estimate_id = ? AND status = 'won' ORDER BY version DESC"
                        " LIMIT 1", (estimate_id,)).fetchone()


def can_reopen(conn, est: dict) -> bool:
    return est["status"] in REOPENABLE and won_quote(conn, est["id"]) is None


def reopen(conn, ctx: RequestContext, estimate_id: int, rev: int, reason: str = "", confirm: bool = False) -> dict:
    """Move an approved or sent estimate back to draft so it can be changed; asks first."""
    service._require_edit_role(ctx, service.EDIT_ROLES)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    won = won_quote(conn, est["id"])
    if won is not None or est["status"] == "won":
        which = f"quote {won['number']}" if won is not None else "the quote"
        raise NotEditable(f"the customer accepted {which} for estimate {est['id']}; for more or different work make a "
                          "change order (➕ Change order…)", estimate_id=est["id"], status=est["status"])
    if est["status"] not in REOPENABLE:
        if est["status"] in service.EDITABLE_STATUSES:
            raise InvalidInput(f"estimate {est['id']} is {est['status']} already; change it directly",
                               estimate_id=est["id"], status=est["status"])
        raise NotEditable(f"estimate {est['id']} is {est['status']}; make a new version to change it",
                          estimate_id=est["id"], status=est["status"])
    if int(rev) != int(est["rev"]):
        raise service.StaleRevision(f"estimate {est['id']} changed since you read it", estimate_id=est["id"],
                                    current_rev=int(est["rev"]))
    marks = ",".join("?" * len(OPEN_BID_STATUSES))
    open_bids = [dict(r) for r in conn.execute(
        f"SELECT number, status, sent_to FROM bids WHERE estimate_id = ? AND status IN ({marks}) ORDER BY version",
        (est["id"], *OPEN_BID_STATUSES))]
    drafts = [b["number"] for b in open_bids if b["status"] == "draft"]
    sent = [b for b in open_bids if b["status"] != "draft"]
    total = format_cents((est["totals"] or {}).get("total_cents", 0))
    if not confirm:
        what = f"{est['status']} at {total}" if est["status"] != "approved" else f"approved at {total}"
        raise ConfirmationRequired(
            f"Reopen estimate {est['id']} ({est['title']}, {what}) for changes? It goes back to draft"
            + (f", the unsent quote {', '.join(drafts)} is voided" if drafts else "")
            + (f", quote {', '.join(b['number'] for b in sent)} the customer was sent is kept on record as replaced, "
               "and the updated quote tells them what changed" if sent else "")
            + ". When it's approved again you only check what changed.", estimate_id=est["id"],
            total_cents=(est["totals"] or {}).get("total_cents", 0), voids=drafts,
            replaces=[b["number"] for b in sent])
    now = service._now()
    with service.transaction(conn):
        conn.execute(f"UPDATE bids SET status = 'void', rev = rev + 1, updated_by = ?, updated_at = ?"
                     f" WHERE estimate_id = ? AND status IN ({marks})", (ctx.actor, now, est["id"], *OPEN_BID_STATUSES))
        conn.execute("UPDATE estimates SET status = 'draft' WHERE id = ?", (est["id"],))
        service._log(conn, ctx, est["id"], "reopened",
                     {"reason": (reason or "").strip()[:500] or None, "voided_bids": drafts,
                      "replaced_bids": [b["number"] for b in sent], "approved": snapshot(est)},
                     {"status": est["status"]})
        service._bump(conn, ctx, est["id"])
    _rewind_director(conn, ctx, est["id"])
    out = service.get_estimate(conn, ctx, est["id"])
    out["reopened"] = True
    out["voided_bids"] = drafts
    out["replaced_bids"] = [b["number"] for b in sent]
    return out


def _rewind_director(conn, ctx, estimate_id: int) -> None:
    """Send the project's Director job back to its first step, so it checks and approves again."""
    try:
        from estimator.director import engine
        from estimator.director import jobs as jobstore
        job = engine.project_job_for(conn, ctx, estimate_id)
        if not job or job.get("state") == "cancelled":
            return
        job = jobstore.load_job(conn, ctx, job["id"])
        pb = engine.get_playbooks()[job["playbook_id"]] if job["playbook_id"] else engine.playbook_for_lane(job["lane"])
        job.update(stage=pb.stages[0].id, state="active")
        with service.transaction(conn):
            jobstore.log_step(conn, ctx, job["id"], "reopen", "director", "done",
                              "estimate reopened for changes; approve it again when it's ready", {})
            jobstore.save_job(conn, ctx, job)
    except Exception:       # the estimate is reopened either way; the Director catches up on its next look
        import logging
        logging.getLogger(__name__).warning("couldn't rewind the Director job for estimate %s", estimate_id,
                                            exc_info=True)


def last_approved(conn, ctx: RequestContext, estimate_id: int) -> dict | None:
    """The snapshot from the latest reopen, if the estimate hasn't been approved again since."""
    import json
    for r in conn.execute("SELECT action, after_json FROM estimate_events WHERE estimate_id = ? AND company_id = ?"
                          " AND action IN ('reopened', 'status_changed') ORDER BY id DESC",
                          (estimate_id, ctx.company_id)):
        after = json.loads(r["after_json"]) if r["after_json"] else {}
        if r["action"] == "status_changed" and after.get("status") == "approved":
            return None
        if r["action"] == "reopened":
            return after.get("approved")
    return None


def _num(v) -> str:
    try:
        return service.qty_text(service._dec(v, "value"))
    except Exception:
        return str(v)


def changes_since_approval(conn, ctx: RequestContext, estimate_id: int, registry=None) -> dict | None:
    """What changed since the estimate was last approved, or None if it wasn't reopened (or was approved again)."""
    old = last_approved(conn, ctx, estimate_id)
    if old is None:
        return None
    reg = _registry(registry)
    est = service.get_estimate(conn, ctx, estimate_id)
    new = snapshot(est)
    name = lambda m: reg.modules[m].name if m in reg.modules else ("Other lines" if m == service.CUSTOM_MODULE  # noqa: E731
                                                                      else m.replace("_", " "))
    answers, lines = [], []
    old_secs = {s["module_id"]: s for s in old["sections"]}
    new_secs = {s["module_id"]: s for s in new["sections"]}
    for mid in [*old_secs, *[m for m in new_secs if m not in old_secs]]:
        a, b = old_secs.get(mid), new_secs.get(mid)
        if a is None or b is None:
            lines.append({"trade": name(mid), "change": "trade added" if a is None else "trade removed",
                          "description": name(mid),
                          "from": format_cents(sum(ln["total_cents"] or 0 for ln in a["lines"])) if a else None,
                          "to": format_cents(sum(ln["total_cents"] or 0 for ln in b["lines"])) if b else None})
            continue
        mod = reg.modules.get(mid)
        for q in [*a["answers"], *[k for k in b["answers"] if k not in a["answers"]]]:
            was, now = a["answers"].get(q), b["answers"].get(q)
            if _num(was) != _num(now):
                label = q
                if mod:
                    try:
                        label = mod.question(q).label
                    except Exception:
                        pass
                answers.append({"trade": name(mid), "question": q, "label": label,
                                "from": None if was is None else _num(was), "to": None if now is None else _num(now)})
        ol = {ln["key"]: ln for ln in a["lines"]}
        nl = {ln["key"]: ln for ln in b["lines"]}
        for k in [*ol, *[k for k in nl if k not in ol]]:
            x, y = ol.get(k), nl.get(k)
            if x is not None and y is not None and "#" in k and x["description"] != y["description"] \
                    and x["kind"] != y["kind"]:
                # A hand line removed and a new one added can reuse the same id: that's two changes, not one.
                lines.append({"trade": name(mid), "change": "removed", "description": x["description"],
                              "from": format_cents(x["total_cents"] or 0), "to": None})
                x = None
            if x is None:
                lines.append({"trade": name(mid), "change": "added", "description": y["description"],
                              "from": None, "to": format_cents(y["total_cents"] or 0)})
            elif y is None:
                lines.append({"trade": name(mid), "change": "removed", "description": x["description"],
                              "from": format_cents(x["total_cents"] or 0), "to": None})
            else:
                what = [f for f in LINE_FIELDS if f != "total_cents" and _num(x[f]) != _num(y[f])]
                if what or (x["total_cents"] or 0) != (y["total_cents"] or 0):
                    lines.append({"trade": name(mid), "change": "changed", "description": y["description"],
                                  "fields": what or ["price"], "from": format_cents(x["total_cents"] or 0),
                                  "to": format_cents(y["total_cents"] or 0)})
    diff = (new["total_cents"] or 0) - (old["total_cents"] or 0)
    unchanged = sum(len(s["lines"]) for s in new["sections"]) - sum(1 for ln in lines if ln["change"] in ("added", "changed"))
    return {"answers": answers, "lines": lines, "unchanged_lines": max(unchanged, 0),
            "total_from": format_cents(old["total_cents"] or 0), "total_to": format_cents(new["total_cents"] or 0),
            "total_change_cents": diff, "count": len(answers) + len(lines),
            "summary": (f"Since it was approved at {format_cents(old['total_cents'] or 0)}: "
                        f"{len(answers)} answer(s) and {len(lines)} line(s) changed; the total is now "
                        f"{format_cents(new['total_cents'] or 0)}" if answers or lines or diff else
                        f"Nothing has changed since it was approved at {format_cents(old['total_cents'] or 0)}")}

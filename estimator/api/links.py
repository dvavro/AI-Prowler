"""Two-way linking between priced lines and measurements (Coder 2 Sprint 8; spec "Two-way linking": selecting a
material or line item highlights every measurement that feeds it, and a measurement shows the lines it drives).

How a line gets its quantity: a trade's line rule has a quantity formula over the trade's questions (quick.py keeps
it in the line's calc as "formula"). A measurement feeds one question (`feeds`). So a line is linked to every
measurement of its trade that feeds a question its formula uses. Hand-entered lines (no formula) link to nothing.

For each question that's measured or used, it also says where the priced answer came from:
  measured - the trade's answer equals the approved measurements' total
  differs  - both exist and disagree (the estimate wasn't re-priced after measuring, or someone typed a number)
  typed    - an answer with no approved measurements behind it
  waiting  - approved measurements exist but the trade isn't priced yet
Only approved measurements count (the same rule as pricing); proposed ones are listed as waiting for a person.

Reads only; changes nothing. The estimate is loaded with the caller's company check.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation

from estimator.core.formula_engine.evaluator import FormulaError, formula_variables
from estimator.estimating import service

TOLERANCE = Decimal("0.01")


def _num(v) -> Decimal | None:
    if v is None or isinstance(v, bool) or v == "":
        return None
    try:
        return Decimal(str(v))
    except (InvalidOperation, ValueError):
        return None


def _uses(formula: str | None, question_ids: set[str]) -> list[str]:
    if not formula:
        return []
    try:
        return sorted(formula_variables(formula) & question_ids)
    except FormulaError:
        return []


def estimate_links(conn, ctx, estimate_id: int, est: dict | None = None, registry=None) -> dict:
    from estimator.modules import get_registry
    from estimator.takeoff import measurements as ms

    reg = registry or get_registry()
    est = est or service.get_estimate(conn, ctx, int(estimate_id))
    rows = [dict(r) for r in conn.execute(
        "SELECT id, module_id, feeds, qty, unit, status, label, room, sheet_id, locked FROM measurements"
        " WHERE company_id = ? AND estimate_id = ? AND status != 'rejected' ORDER BY id", (ctx.company_id, est["id"]))]
    approved = ms.approved_answers(conn, ctx, est["id"], None, reg)
    by_question: dict[tuple, dict] = {}

    def question(mod, qid):
        key = (mod.id, qid)
        if key not in by_question:
            q = mod.question(qid)
            by_question[key] = {"module_id": mod.id, "id": qid, "label": q.label, "unit": q.unit, "answer": None,
                                "measured": approved.get(mod.id, {}).get(qid), "measurement_ids": [],
                                "proposed_ids": [], "line_ids": [], "priced": False}
            for m in rows:
                if m["module_id"] == mod.id and m["feeds"] == qid:
                    by_question[key]["measurement_ids" if m["status"] == "approved" else "proposed_ids"].append(m["id"])
        return by_question[key]

    lines = []
    for sec in est["sections"]:
        mod = reg.modules.get(sec["module_id"])
        qids = {q.id for q in mod.questions} if mod else set()
        answers = sec["answers"] or {}
        for li in sec["lines"]:
            uses = _uses((li.get("calc") or {}).get("formula"), qids)
            entry = {"line_id": li["id"], "section_id": sec["id"], "module_id": sec["module_id"],
                     "description": li["description"], "quantity": li["quantity"], "unit": li["unit"],
                     "questions": uses, "measurement_ids": [], "proposed_ids": []}
            for qid in uses:
                q = question(mod, qid)
                q["priced"] = True
                q["answer"] = answers.get(qid)
                q["line_ids"].append(li["id"])
                entry["measurement_ids"] += q["measurement_ids"]
                entry["proposed_ids"] += q["proposed_ids"]
            entry["measurement_ids"] = sorted(set(entry["measurement_ids"]))
            entry["proposed_ids"] = sorted(set(entry["proposed_ids"]))
            lines.append(entry)
    # Questions that were measured but aren't priced on the estimate yet.
    for m in rows:
        mod = reg.modules.get(m["module_id"]) if m["module_id"] else None
        if mod and m["feeds"] and any(q.id == m["feeds"] for q in mod.questions):
            q = question(mod, m["feeds"])
            sec = next((s for s in est["sections"] if s["module_id"] == mod.id), None)
            if sec and q["answer"] is None:
                q["answer"] = (sec["answers"] or {}).get(m["feeds"])
    out_q = []
    for q in by_question.values():
        a, meas = _num(q["answer"]), _num(q["measured"])
        if meas is not None and a is not None:
            q["state"] = "measured" if abs(a - meas) <= TOLERANCE else "differs"
        elif meas is not None:
            q["state"] = "waiting"
        elif a is not None or q["answer"] not in (None, ""):          # a number or a choice such as pitch 5/12
            q["state"] = "typed"
        else:
            q["state"] = "none"
        out_q.append(q)
    to_lines: dict[int, list[int]] = {}
    for ln in lines:
        for mid in ln["measurement_ids"] + ln["proposed_ids"]:
            to_lines.setdefault(mid, []).append(ln["line_id"])
    trades = []
    for mid in sorted({q["module_id"] for q in out_q}):
        mod = reg.modules.get(mid)
        qs = [q for q in out_q if q["module_id"] == mid]
        trades.append({"module_id": mid, "name": mod.name if mod else mid, "questions": qs,
                       "can_use_measurements": any(q["state"] in ("differs", "waiting") for q in qs)})
    return {"estimate_id": est["id"], "lines": lines, "trades": trades,
            "measurements": [{"id": m["id"], "module_id": m["module_id"], "feeds": m["feeds"], "label": m["label"],
                              "room": m["room"], "qty": m["qty"], "unit": m["unit"], "status": m["status"],
                              "locked": bool(m["locked"]), "sheet_id": m["sheet_id"],
                              "line_ids": to_lines.get(m["id"], [])} for m in rows]}


def answers_from_measurements(conn, ctx, est: dict, module_id: str, registry=None) -> tuple[dict, dict]:
    """(new answers for the trade, what changed): the trade's current answers with each measured question replaced
    by its approved measurements' total. Raises InvalidInput when nothing is approved for the trade."""
    from estimator.errors import InvalidInput
    from estimator.takeoff import measurements as ms
    approved = ms.approved_answers(conn, ctx, est["id"], module_id, registry).get(module_id, {})
    if not approved:
        raise InvalidInput("there are no approved measurements for this trade yet; approve some in Blueprint Review",
                           module_id=module_id)
    sec = next((s for s in est["sections"] if s["module_id"] == module_id), None)
    current = dict((sec or {}).get("answers") or {})
    changes = {q: {"from": current.get(q), "to": v} for q, v in approved.items()
               if _num(current.get(q)) is None or abs(_num(current.get(q)) - _num(v)) > TOLERANCE}
    return {**current, **approved}, changes

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

import re
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
        # the plans' notes choose something else (an AI redraw: wrought iron -> aluminum, 4 ft -> 4 ft 6 in)
        sec = next((s for s in est["sections"] if s["module_id"] == mid), None)
        notes = {}
        if sec and approved.get(mid):
            now = sec["answers"] or {}
            notes = {q: {"from": now.get(q), "to": v} for q, v in plan_choices(conn, ctx, est, mid, reg).items()
                     if not _same(now.get(q), v)}
        trades.append({"module_id": mid, "name": mod.name if mod else mid, "questions": qs, "plan_notes": notes,
                       "can_use_measurements": bool(notes) or any(q["state"] in ("differs", "waiting") for q in qs)})
    return {"estimate_id": est["id"], "lines": lines, "trades": trades,
            "measurements": [{"id": m["id"], "module_id": m["module_id"], "feeds": m["feeds"], "label": m["label"],
                              "room": m["room"], "qty": m["qty"], "unit": m["unit"], "status": m["status"],
                              "locked": bool(m["locked"]), "sheet_id": m["sheet_id"],
                              "line_ids": to_lines.get(m["id"], [])} for m in rows]}


def answers_from_measurements(conn, ctx, est: dict, module_id: str, registry=None,
                              with_plans: bool = False) -> tuple[dict, dict]:
    """(new answers for the trade, what changed): the trade's current answers with each measured question replaced
    by its approved measurements' total. Raises InvalidInput when nothing is approved for the trade.
    with_plans=True also takes the choices the plans' notes give (plan_choices: a fence's material and height)."""
    from estimator.errors import InvalidInput
    from estimator.takeoff import measurements as ms
    approved = ms.approved_answers(conn, ctx, est["id"], module_id, registry).get(module_id, {})
    if not approved:
        raise InvalidInput("there are no approved measurements for this trade yet; approve some in Measure",
                           module_id=module_id)
    sec = next((s for s in est["sections"] if s["module_id"] == module_id), None)
    current = dict((sec or {}).get("answers") or {})
    approved = {**_wiring_cleared(module_id, approved, current), **approved}
    changes = {q: {"from": current.get(q), "to": v} for q, v in approved.items()
               if _num(current.get(q)) is None or abs(_num(current.get(q)) - _num(v)) > TOLERANCE}
    if with_plans:
        chosen = {q: v for q, v in plan_choices(conn, ctx, est, module_id, registry).items() if q not in approved}
        changes.update({q: {"from": current.get(q), "to": v} for q, v in chosen.items() if not _same(current.get(q), v)})
        approved = {**approved, **chosen}
    return {**current, **approved}, changes


def _same(a, b) -> bool:
    na, nb = _num(a), _num(b)
    if na is not None and nb is not None:
        return abs(na - nb) <= TOLERANCE
    return str(a if a is not None else "").strip().lower() == str(b if b is not None else "").strip().lower()


def plan_choices(conn, ctx, est: dict, module_id: str, registry=None) -> dict:
    """2026-11-25 (David: an AI redraw changed the fence to aluminum, 4'-6", but the Lines still said wrought iron and
    🔄 Update from the plans had nothing to update): what the plans' notes choose for the trade - its choice and yes/no
    questions (a fence's material and height) - read by the plan reader from the project's current plans. The
    quantities stay with the approved measurements. {} for a trade the plans don't answer, or when they can't be read."""
    from estimator.building import trades as plan_trades
    from estimator.modules import get_registry
    if module_id not in plan_trades.TRADES:
        return {}
    mod = (registry or get_registry()).modules.get(module_id)
    if mod is None:
        return {}
    try:
        read = (plan_trades.answers(conn, ctx, module_id, estimate_id=est["id"]) or {}).get("answers") or {}
    except Exception:  # noqa: BLE001 - the plans can't be read for this trade: nothing to add
        return {}
    kinds = {q.id: q.type for q in mod.questions}
    # a yes/no only when the plans say yes (a note that asks for it); silence on the plans never turns one off
    return {k: v for k, v in read.items() if v not in (None, "")
            and (kinds.get(k) == "choice" or (kinds.get(k) == "boolean" and v is True))}


_WIRING_FEED = re.compile(r"^(wire_\d+_\d+_ft|thhn_\d+_ft|emt_\w+|pvc_\w+|conduit_bodies|surface_boxes|wp_boxes)$")


def _wiring_cleared(module_id: str, approved: dict, current: dict) -> dict:
    """2026-11-23 (David: "why is it counting wire twice?"): the wiring run measures the wire and conduit as one set.
    Once any of that set is approved, an answer in the set with no approved measurement left (the NM cable from an
    earlier run, after the wiring method changed to conduit - or the conduit after a change back) is cleared to 0,
    instead of staying priced as if it had been typed in."""
    from estimator.takeoff import wiring_run
    if module_id != wiring_run.MODULE_ID or not any(_WIRING_FEED.match(q) for q in approved):
        return {}
    return {q: 0 for q, v in current.items()
            if _WIRING_FEED.match(q) and q not in approved and (_num(v) or 0) != 0}

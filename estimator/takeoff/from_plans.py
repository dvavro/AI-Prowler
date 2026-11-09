"""Measurements from the plans: a trade's measured answers become proposed measurements (Coder 1 Sprint 25).

The plan engine (Coder 2) answers a trade's questions from the plans in one place, estimator.building.trades:
- framing, drywall, painting, insulation, flooring: from the shared wall-and-room model;
- electrical, plumbing, hvac: from the symbols counted on the plans (only ones a person approved, unless asked);
- and the other trades the plans answer (estimator.building.trades.TRADES: windows and doors from the schedules,
  siding from the elevations, ...).

This file turns those answers into measurements, so they go through the same review as any other takeoff: proposed,
then approved (and locked) by a person, and only approved ones are priced. Nothing is priced here.

Running it again keeps one measurement per trade question:
- the same number: nothing changes;
- a proposed one with a new number: updated, with the old number kept in its history;
- an approved one with a new number: left as it is (it's locked) with the new number beside it as a suggested change
  that only a person can accept (takeoff_confirm accept_suggestion=true);
- a rejected one: left rejected (a person decided), and reported.
Choice answers (the water heater kind) aren't quantities: they're returned for the takeoff's answers.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput
from estimator.estimating import service
from estimator.takeoff import measurements as m

SOURCE_TAG = "plans"            # calc_json["from"] marks a measurement made here, so a re-run finds it
UNIT_KIND = {"sqft": "area", "sf": "area", "lf": "length", "ft": "length", "ea": "count", "sq": "area",
             "cy": "volume", "cuyd": "volume"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _kind_unit(question) -> tuple[str, str]:
    unit = (question.unit or "").lower()
    if not unit:
        return ("count", "ea") if question.type == "integer" else ("other", "ea")
    return UNIT_KIND.get(unit, "other"), question.unit


def _symbol_ids(conn, ctx, module_id: str, question_id: str, plan_set_ids: list[int], include_proposed: bool):
    """The symbol detections behind a count, so the measurement points at what was counted."""
    from estimator.plan_engine import symbol_library as lib
    types = [it for it in lib.FEEDS if any(f[0] == module_id and f[1] == question_id for f in lib.feeds_of(it))]
    if not types or not plan_set_ids:
        return []
    states = ("approved", "proposed") if include_proposed else ("approved",)
    q_ps, q_t, q_s = (",".join("?" * len(x)) for x in (plan_set_ids, types, states))
    return [r[0] for r in conn.execute(
        f"SELECT id FROM symbol_detections WHERE company_id = ? AND plan_set_id IN ({q_ps}) AND item_type IN ({q_t})"
        f" AND status IN ({q_s}) ORDER BY id", (ctx.company_id, *plan_set_ids, *types, *states))]


def _existing(conn, ctx, estimate_id: int, module_id: str, feeds: str) -> dict | None:
    for r in conn.execute("SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ? AND module_id = ? AND"
                          " feeds = ? ORDER BY id DESC", (ctx.company_id, estimate_id, module_id, feeds)):
        calc = json.loads(r["calc_json"] or "{}")
        if calc.get("from") == SOURCE_TAG:
            return dict(r)
    return None


def plan_answers(conn, ctx: RequestContext, module_id: str, *, estimate_id: int | None = None,
                 plan_set_id: int | None = None, height_ft=None, include_proposed: bool = False) -> dict:
    from estimator.building import trades
    return trades.answers(conn, ctx, module_id, estimate_id=estimate_id, plan_set_id=plan_set_id,
                          height_ft=height_ft, include_proposed=include_proposed)


def propose(conn, ctx: RequestContext, estimate_id: int, module_id: str, *, plan_set_id: int | None = None,
            height_ft=None, include_proposed: bool = False, confirm: bool = False, registry=None) -> dict:
    """Propose (or refresh) one measurement per trade question the plans answer. Asks first, listing each one."""
    m._role(ctx, m.PROPOSE_ROLES, "propose measurements")
    est = service._load_row(conn, ctx, int(estimate_id))
    reg = m._registry(registry)
    module_id = (module_id or "").strip().lower()
    mod, _ = m._feed(reg, module_id, None)
    found = plan_answers(conn, ctx, module_id, estimate_id=est["id"], plan_set_id=plan_set_id, height_ft=height_ft,
                         include_proposed=include_proposed)
    if plan_set_id and est["id"] not in {r["estimate_id"] for r in conn.execute(
            "SELECT estimate_id FROM plan_sets WHERE id = ? AND company_id = ?", (int(plan_set_id), ctx.company_id))}:
        raise InvalidInput(f"plan set {plan_set_id} isn't on estimate {est['id']}", plan_set_id=plan_set_id)
    source = found.get("source", "the plans")
    plan_set_ids = found.get("plan_set_ids") or []
    model_key = found.get("model_key")
    plan, choices, skipped = [], {}, []
    for qid, value in found["answers"].items():
        q = mod.question(qid)
        if q.type not in ("number", "integer"):
            choices[qid] = value
            continue
        qty = Decimal(str(value))
        if qty <= 0:
            skipped.append({"feeds": qid, "why": "nothing measured (0)"})
            continue
        kind, unit = _kind_unit(q)
        from estimator.building import trades
        ids = _symbol_ids(conn, ctx, module_id, qid, plan_set_ids, include_proposed) \
            if module_id in trades.SYMBOL_TRADES else []
        old = _existing(conn, ctx, est["id"], module_id, qid)
        if old is None:
            action = "new"
        elif old["status"] == "rejected":
            action = "rejected_before"
        elif Decimal(old["qty"]) == qty and old["unit"] == unit:
            action = "unchanged"
        elif old["status"] == "approved":
            action = "same_suggestion" if old["suggested_qty"] is not None and \
                Decimal(old["suggested_qty"]) == qty else "suggest"
        else:
            action = "update"
        plan.append({"feeds": qid, "label": q.label, "qty": m._q(qty), "unit": unit, "kind": kind,
                     "how": found["from"].get(qid, source), "action": action, "symbol_detection_ids": ids,
                     "measurement_id": old["id"] if old else None,
                     "was": old["qty"] if old and action in ("update", "suggest") else None})
    if not plan:
        raise InvalidInput(f"the plans don't answer any {mod.name} quantities yet"
                           + (": " + "; ".join(found["notes"]) if found.get("notes") else ""),
                           module_id=module_id, notes=found.get("notes", []))
    todo = [p for p in plan if p["action"] in ("new", "update", "suggest")]
    counts = {a: sum(1 for p in plan if p["action"] == a) for a in
              ("new", "update", "suggest", "unchanged", "same_suggestion", "rejected_before")}
    if todo and not confirm:
        lines = [f"{p['label']}: {p['qty']} {p['unit']}" + {"new": "", "update": f" (was {p['was']})",
                                                              "suggest": f" (approved {p['was']}: as a suggested "
                                                                         "change)"}[p["action"]] for p in todo]
        raise ConfirmationRequired(
            f"Propose {mod.name} from {source}: " + "; ".join(lines) + ". Call again with confirm=true.",
            measurements=plan, counts=counts, notes=found.get("notes", []), choices=choices)
    made, now = [], _now()
    with service.transaction(conn):
        for p in todo:
            calc = {"from": SOURCE_TAG, "how": p["how"], "source": source, "qty": p["qty"],
                    "plan_set_ids": plan_set_ids, "model_key": model_key,
                    "include_proposed_symbols": bool(include_proposed)}
            if p["symbol_detection_ids"]:
                calc["symbol_detection_ids"] = p["symbol_detection_ids"]
            if p["action"] == "new":
                mid = conn.execute(
                    "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, kind, label, qty, unit,"
                    " calc_json, method, proposed_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ctx.company_id, est["id"], module_id, p["feeds"], p["kind"], p["label"], p["qty"], p["unit"],
                     json.dumps(calc), "vector", ctx.actor, now, now)).lastrowid
                row = m._load(conn, ctx, mid)
                m._log(conn, ctx, row, "measurement_proposed", {"qty": p["qty"], "unit": p["unit"],
                                                               "feeds": p["feeds"], "from": source})
            elif p["action"] == "update":
                before = m._load(conn, ctx, p["measurement_id"])
                conn.execute("UPDATE measurements SET qty = ?, unit = ?, kind = ?, calc_json = ?, proposed_by = ?,"
                             " needs_remeasure = 0, updated_at = ? WHERE id = ?",
                             (p["qty"], p["unit"], p["kind"], json.dumps(calc), ctx.actor, now, before["id"]))
                row = m._load(conn, ctx, before["id"])
                m._log(conn, ctx, row, "measurement_updated", {"qty": p["qty"], "from": source},
                       before={"qty": before["qty"]})
            else:                                   # approved and locked: a suggested change only a person accepts
                row = m._load(conn, ctx, p["measurement_id"])
                conn.execute("UPDATE measurements SET suggested_qty = ?, suggested_by = ?, suggested_reason = ?,"
                             " suggested_at = ?, updated_at = ? WHERE id = ?",
                             (p["qty"], ctx.actor, f"the plans now give {p['qty']} {p['unit']} ({p['how']})"[:300],
                              now, now, row["id"]))
                m._log(conn, ctx, row, "measurement_change_suggested", {"suggested_qty": p["qty"], "from": source})
                row = m._load(conn, ctx, row["id"])
            made.append({**m._out(row), "action": p["action"]})
    return {"ok": True, "module_id": module_id, "source": source, "plan_set_ids": plan_set_ids,
            "measurements": made, "plan": plan, "counts": counts, "choices": choices,
            "notes": found.get("notes", []), "skipped": skipped,
            "next": ("a person approves them with takeoff_confirm (they're not priced until approved); "
                     "then runner_submit_takeoff from_measurements=true or est_apply_assembly")
            if made else "nothing changed: the plans give the same quantities as before"}

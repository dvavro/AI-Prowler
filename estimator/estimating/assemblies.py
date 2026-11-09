"""Assemblies and line edits on an estimate (spec: MCP tools est_get_assemblies, est_apply_assembly,
est_update_line_item; Data model assembly_uses and line_items.override_by). Coder 1 Sprint 25.

An assembly is a trade module's priced recipe: its questions are the inputs (measurements plus parameters such as
the flooring type) and its line rules make the components (materials, labor, waste). Applying it:
- takes each quantity question from the trade's APPROVED measurements (or the measurements you pick); proposed ones
  are never priced and are listed as waiting;
- takes the other answers from the parameters you give, then a good/better/best option if you pick one, then the
  answers the trade already has on this estimate, then the module's defaults;
- replaces the trade's lines and records what was used (assembly_uses), so every line traces back to its inputs.
It asks first, showing every answer with where it came from and the lines it makes.

Line edits (est_update_line_item) are overrides: the new quantity, cost, waste or description is kept with who
changed it, when and why, and the original values, so it can be put back (revert). Re-applying the assembly keeps
cost, waste and description overrides on lines made by the same rule; quantity overrides are dropped, because the
quantity comes from the measurements. Either way it says which.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, NotFound
from estimator.estimating import quick, service

EDIT_FIELDS = ("quantity", "unit_cost_cents", "waste_pct", "description")
KEPT_ON_REAPPLY = ("unit_cost_cents", "waste_pct", "description")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def _module(reg, module_id: str):
    try:
        return reg.get((module_id or "").strip().lower())
    except Exception:
        raise InvalidInput(f"there's no trade module '{module_id}'", field="module_id") from None


def _confirm(confirm: bool, message: str, **details) -> None:
    if not confirm:
        raise ConfirmationRequired(message + " Call again with confirm=true.", **details)


# ---------------------------------------------------------------- reading

def get_assemblies(module_id: str, registry=None) -> dict:
    """A trade's assembly: its inputs (questions, which ones measurements or the plans can fill), the components its
    line rules make, and its good/better/best options. Prices are in the price book (pricebook_get)."""
    reg = _registry(registry)
    mod = _module(reg, module_id)
    from estimator.runner.runner import plan_trades
    inputs = []
    for q in mod.questions:
        d = q.as_dict()
        d["measured"] = q.type in ("number", "integer")       # a measurement can feed it (takeoff_propose feeds=)
        inputs.append(d)
    components = [{"id": r.id, "description": r.description, "kind": r.kind, "unit": r.unit,
                   "quantity": r.quantity, "waste": r.waste, "when": r.when, "price_key": r.price_key}
                  for r in mod.lines]
    return {"ok": True, "assembly_id": f"{mod.id}@{mod.version}", "module_id": mod.id, "name": mod.name,
            "version": mod.version, "description": mod.description, "inputs": inputs, "components": components,
            "options": [{"id": s["id"], "label": s["label"], "answers": s["answers"]} for s in mod.scenarios],
            "minimum_charge_cents": mod.minimum_charge_cents, "plans_answer_it": mod.id in plan_trades(),
            "notes": list(mod.notes)}


# ---------------------------------------------------------------- applying

def _measured(conn, ctx, estimate_id: int, mod, measurement_ids: list[int] | None, reg) -> tuple[dict, dict, dict]:
    """(answers, sources, waiting) from approved measurements, in each question's unit."""
    from estimator.takeoff import measurements as m
    sql = ("SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ? AND module_id = ? AND feeds IS NOT NULL")
    args = [ctx.company_id, int(estimate_id), mod.id]
    rows = [dict(r) for r in conn.execute(sql, args)]
    if measurement_ids:
        want = {int(i) for i in measurement_ids}
        found = {r["id"] for r in rows}
        missing = sorted(want - found)
        if missing:
            raise InvalidInput(f"measurement(s) {missing} aren't {mod.name} measurements on estimate {estimate_id}",
                               measurement_ids=missing)
        rows = [r for r in rows if r["id"] in want]
        not_ok = [r["id"] for r in rows if r["status"] != "approved"]
        if not_ok:
            raise InvalidInput(f"measurement(s) {not_ok} aren't approved; only approved measurements are priced "
                               "(takeoff_confirm)", measurement_ids=not_ok)
    totals, ids, waiting = {}, {}, {}
    for r in rows:
        if r["status"] == "proposed":
            waiting[r["feeds"]] = waiting.get(r["feeds"], 0) + 1
            continue
        if r["status"] != "approved":
            continue
        try:
            _, q = m._feed(reg, mod.id, r["feeds"])
        except InvalidInput:
            continue
        totals[r["feeds"]] = totals.get(r["feeds"], Decimal(0)) + m._in_question_unit(Decimal(r["qty"]), r["unit"], q)
        ids.setdefault(r["feeds"], []).append(r["id"])
    answers = {}
    for qid, total in totals.items():
        q = mod.question(qid)
        answers[qid] = int(total.to_integral_value()) if q.type == "integer" else float(m._q(total))
    sources = {qid: {"from": "measured", "measurement_ids": ids[qid]} for qid in answers}
    return answers, sources, waiting


def _plan_overrides(conn, section_id: int) -> list[dict]:
    out = []
    for li in conn.execute("SELECT * FROM line_items WHERE trade_section_id = ? AND override_by IS NOT NULL",
                           (section_id,)):
        calc = json.loads(li["calc_json"] or "{}")
        ov = calc.get("override") or {}
        out.append({"line_id": li["id"], "rule": calc.get("rule"), "description": li["description"],
                    "changed": ov.get("changed", {}), "reason": li["override_reason"], "by": li["override_by"]})
    return out


def apply_assembly(conn, ctx: RequestContext, estimate_id: int, rev: int, module_id: str, *, params: dict | None = None,
                   option: str | None = None, use_measurements: bool = True, measurement_ids: list | None = None,
                   keep_overrides: bool = True, confirm: bool = False, registry=None) -> dict:
    reg = _registry(registry)
    mod = _module(reg, module_id)
    est = service._check_writable(conn, ctx, int(estimate_id), rev)
    params = dict(params or {})
    if not isinstance(params, dict):
        raise InvalidInput("params must be an object of question id -> answer", field="params")
    unknown = sorted(set(params) - {q.id for q in mod.questions})
    if unknown:
        raise InvalidInput(f"{mod.name} has no question(s) {unknown}", unknown=unknown,
                           valid=[q.id for q in mod.questions])
    sid = service._section_id(conn, ctx, est["id"], mod.id, create=False)
    kept = {}
    if sid is not None:
        row = conn.execute("SELECT params_json FROM trade_sections WHERE id = ?", (sid,)).fetchone()
        kept = json.loads(row["params_json"]) if row and row["params_json"] else {}
    opt = {}
    if option:
        match = next((s for s in mod.scenarios if s["id"] == option), None)
        if match is None:
            raise InvalidInput(f"{mod.name} has no option '{option}'", field="option",
                               options=[s["id"] for s in mod.scenarios])
        opt = dict(match["answers"])
    measured, sources, waiting = ({}, {}, {})
    if use_measurements:
        measured, sources, waiting = _measured(conn, ctx, est["id"], mod, measurement_ids, reg)
    elif measurement_ids:
        raise InvalidInput("measurement_ids need use_measurements=true", field="measurement_ids")
    answers: dict = {}
    for qid, v in kept.items():
        if any(q.id == qid for q in mod.questions):
            answers[qid] = v
            sources[qid] = sources.get(qid) if qid in measured else {"from": "kept (already on this estimate)"}
    for qid, v in measured.items():
        answers[qid] = v
    for qid, v in opt.items():
        if qid not in measured:
            answers[qid] = v
            sources[qid] = {"from": f"option {option}"}
    for qid, v in params.items():
        if qid in measured:
            sources[qid] = {"from": "typed", "over_measured": measured[qid],
                            "measurement_ids": sources[qid]["measurement_ids"]}
        else:
            sources[qid] = {"from": "typed"}
        answers[qid] = v
    stored, variables = quick.resolve_answers(mod, answers)      # raises with what's missing
    for qid in stored:
        sources.setdefault(qid, {"from": "default"})
    from estimator.director.engine import _nonzero
    if mod.required_any and not any(_nonzero(stored.get(q)) for q in mod.required_any):
        raise InvalidInput(f"nothing to price for {mod.name}: measure or give at least one of "
                           + ", ".join(mod.required_any), at_least_one=list(mod.required_any))
    planned = quick.build_lines(mod, variables)
    overrides = _plan_overrides(conn, sid) if sid is not None else []
    rules_now = {p["rule"].id for p in planned}
    carried = [o for o in overrides if keep_overrides and o["rule"] in rules_now
               and any(k in KEPT_ON_REAPPLY for k in o["changed"])]
    dropped = [o for o in overrides if o not in carried or "quantity" in o["changed"]]
    preview = [{"rule": p["rule"].id, "description": p["rule"].description, "quantity": service.qty_text(p["quantity"]),
                "unit": p["rule"].unit, "waste_pct": str(p["waste_pct"]), "kind": p["rule"].kind} for p in planned]
    used_ids = sorted({i for s in sources.values() for i in s.get("measurement_ids", [])})
    msg = (f"Apply the {mod.name} assembly to estimate {est['id']}: "
           + ", ".join(f"{k} = {stored[k]} ({sources[k]['from']})" for k in stored)
           + f". It makes {len(planned)} line(s)" + (" and replaces the trade's current lines" if sid else ""))
    if dropped:
        msg += f"; {len(dropped)} hand change(s) on the old lines won't carry over"
    if waiting:
        msg += "; measurements still waiting for approval aren't used: " + ", ".join(
            f"{n} for {q}" for q, n in waiting.items())
    _confirm(confirm, msg + ".", answers=stored, sources=sources, lines=preview, waiting=waiting,
             overrides_kept=carried, overrides_dropped=dropped, measurement_ids=used_ids)
    priced = quick.answer(conn, ctx, est["id"], mod.id, stored, int(est["rev"]), reg)
    now = _now()
    with service.transaction(conn):
        sid = service._section_id(conn, ctx, est["id"], mod.id, create=False)
        use_id = conn.execute(
            "INSERT INTO assembly_uses (company_id, estimate_id, trade_section_id, assembly_id, module_id, params_json,"
            " sources_json, measurement_ids, applied_by, applied_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ctx.company_id, est["id"], sid, f"{mod.id}@{mod.version}", mod.id, json.dumps(stored),
             json.dumps(sources), json.dumps(used_ids), ctx.actor, now)).lastrowid
        conn.execute("UPDATE line_items SET assembly_use_id = ? WHERE trade_section_id = ?", (use_id, sid))
        reapplied = []
        for o in carried:
            li = conn.execute("SELECT * FROM line_items WHERE trade_section_id = ? AND json_extract(calc_json,"
                              " '$.rule') = ?", (sid, o["rule"])).fetchone()
            if li is None:
                continue
            changes = {k: v["to"] for k, v in o["changed"].items() if k in KEPT_ON_REAPPLY}
            if changes:
                _write_override(conn, ctx, dict(li), changes, o["reason"] or "kept from before", now)
                reapplied.append({"line_id": li["id"], "rule": o["rule"], "changed": list(changes)})
        service._log(conn, ctx, est["id"], "assembly_applied",
                     {"assembly_use_id": use_id, "module_id": mod.id, "assembly_id": f"{mod.id}@{mod.version}",
                      "answers": stored, "measurement_ids": used_ids, "lines": len(planned),
                      "overrides_kept": len(reapplied), "overrides_dropped": len(dropped)})
        if reapplied:
            service._recalculate(conn, ctx, est["id"], reg)
        service._bump(conn, ctx, est["id"])
    out = service.get_estimate(conn, ctx, est["id"])
    out.update(assembly_use_id=use_id, sources=sources, waiting=waiting, overrides_kept=reapplied,
               overrides_dropped=dropped,
               warnings=[w for w in priced.get("warnings", []) if "hand change" not in w])
    return out


def assembly_uses(conn, ctx: RequestContext, estimate_id: int) -> list[dict]:
    service._load_row(conn, ctx, int(estimate_id))
    return [{"id": r["id"], "module_id": r["module_id"], "assembly_id": r["assembly_id"],
             "answers": json.loads(r["params_json"]), "sources": json.loads(r["sources_json"]),
             "measurement_ids": json.loads(r["measurement_ids"]), "applied_by": r["applied_by"],
             "applied_at": r["applied_at"]}
            for r in conn.execute("SELECT * FROM assembly_uses WHERE company_id = ? AND estimate_id = ? ORDER BY id",
                                  (ctx.company_id, int(estimate_id)))]


# ---------------------------------------------------------------- editing a line

def _load_line(conn, ctx, estimate_id: int, line_id: int) -> dict:
    row = conn.execute("SELECT li.*, ts.module_id, ts.estimate_id FROM line_items li JOIN trade_sections ts ON"
                       " ts.id = li.trade_section_id JOIN estimates e ON e.id = ts.estimate_id WHERE li.id = ? AND"
                       " e.company_id = ?", (int(line_id), ctx.company_id)).fetchone()
    if row is None or int(row["estimate_id"]) != int(estimate_id):
        raise NotFound(f"line {line_id} isn't on estimate {estimate_id}", line_id=line_id)
    return dict(row)


def _write_override(conn, ctx, li: dict, changes: dict, reason: str | None, now: str) -> None:
    calc = json.loads(li["calc_json"] or "{}")
    ov = calc.get("override") or {"original": {k: li[k] for k in EDIT_FIELDS}, "changed": {}}
    for k, v in changes.items():
        ov["changed"][k] = {"from": ov["original"][k], "to": v}
    ov.update(by=ctx.actor, at=now, reason=reason)
    calc["override"] = ov
    sets = {**changes}
    conn.execute("UPDATE line_items SET quantity = ?, unit_cost_cents = ?, waste_pct = ?, description = ?, calc_json = ?,"
                 " override_by = ?, override_reason = ?, override_at = ?, updated_at = ? WHERE id = ?",
                 (sets.get("quantity", li["quantity"]), sets.get("unit_cost_cents", li["unit_cost_cents"]),
                  sets.get("waste_pct", li["waste_pct"]), sets.get("description", li["description"]),
                  json.dumps(calc), ctx.actor, reason, now, now, li["id"]))


def update_line_item(conn, ctx: RequestContext, estimate_id: int, rev: int, line_id: int, *, quantity=None,
                     unit_cost_cents=None, waste_pct=None, description: str | None = None, reason: str | None = None,
                     revert: bool = False, remove: bool = False, confirm: bool = False) -> dict:
    """Change one line (an override, kept with who, when and why), put it back (revert), or take it off (remove).
    Asks first, showing the change and the trade's new subtotal."""
    est = service._check_writable(conn, ctx, int(estimate_id), rev)
    li = _load_line(conn, ctx, est["id"], line_id)
    calc = json.loads(li["calc_json"] or "{}")
    from_assembly = li["module_id"] != service.CUSTOM_MODULE
    reason = " ".join(str(reason or "").split())[:300] or None
    editing = any(v not in (None, "") for v in (quantity, unit_cost_cents, waste_pct, description))
    if [bool(revert), bool(remove), editing].count(True) > 1:
        raise InvalidInput("change a line, revert it or remove it: one at a time")
    if remove:
        if from_assembly and not reason:
            raise InvalidInput("say why this priced line comes off (reason); the trade's assembly made it",
                               field="reason")
        _confirm(confirm, f"Take line {li['id']} ({li['description']}, {li['quantity']} {li['unit']}) off estimate "
                 f"{est['id']}" + (f" ({li['module_id']})" if from_assembly else "") + "?", line_id=li["id"],
                 total_cents=li["total_cents"])
        with service.transaction(conn):
            conn.execute("DELETE FROM line_items WHERE id = ?", (li["id"],))
            service._log(conn, ctx, est["id"], "line_removed", {"line_id": li["id"], "reason": reason},
                         before={"description": li["description"], "quantity": li["quantity"], "unit": li["unit"],
                                 "unit_cost_cents": li["unit_cost_cents"], "total_cents": li["total_cents"]})
            service._recalculate(conn, ctx, est["id"])
            service._bump(conn, ctx, est["id"])
        out = service.get_estimate(conn, ctx, est["id"])
        out["removed_line_id"] = li["id"]
        return out
    now = _now()
    if revert:
        ov = calc.get("override")
        if not ov:
            raise InvalidInput(f"line {li['id']} has no hand changes to put back", line_id=li["id"])
        orig = ov["original"]
        _confirm(confirm, f"Put line {li['id']} back to how it was: " + ", ".join(
            f"{k} {li[k]} → {orig[k]}" for k in ov["changed"]) + "?", line_id=li["id"], original=orig)
        calc.pop("override", None)
        with service.transaction(conn):
            conn.execute("UPDATE line_items SET quantity = ?, unit_cost_cents = ?, waste_pct = ?, description = ?,"
                         " calc_json = ?, override_by = NULL, override_reason = NULL, override_at = NULL,"
                         " updated_at = ? WHERE id = ?", (orig["quantity"], orig["unit_cost_cents"],
                                                          orig["waste_pct"], orig["description"], json.dumps(calc),
                                                          now, li["id"]))
            service._log(conn, ctx, est["id"], "line_override_reverted", {"line_id": li["id"], **orig},
                         before={k: li[k] for k in EDIT_FIELDS})
            service._recalculate(conn, ctx, est["id"])
            service._bump(conn, ctx, est["id"])
        return {**service.get_estimate(conn, ctx, est["id"]), "line_id": li["id"], "reverted": True}
    changes = {}
    if quantity not in (None, ""):
        q = service._dec(quantity, "quantity")
        if q < 0:
            raise InvalidInput("quantity can't be negative", field="quantity")
        changes["quantity"] = service.qty_text(q)
    if unit_cost_cents not in (None, ""):
        if isinstance(unit_cost_cents, bool) or not str(unit_cost_cents).strip().lstrip("-").isdigit():
            raise InvalidInput("unit_cost_cents is whole cents", field="unit_cost_cents")
        c = int(str(unit_cost_cents).strip())
        if c < 0:
            raise InvalidInput("unit_cost_cents can't be negative", field="unit_cost_cents")
        changes["unit_cost_cents"] = c
    if waste_pct not in (None, ""):
        w = service._dec(waste_pct, "waste_pct")
        if w < 0 or w > 1:
            raise InvalidInput("waste_pct is a fraction between 0 and 1 (0.10 = 10%)", field="waste_pct")
        changes["waste_pct"] = str(w)
    if description not in (None, ""):
        d = " ".join(str(description).split())[:200]
        if not d:
            raise InvalidInput("the description can't be empty", field="description")
        changes["description"] = d
    changes = {k: v for k, v in changes.items() if str(v) != str(li[k])}
    if not changes:
        raise InvalidInput("nothing to change: give quantity, unit_cost_cents, waste_pct or description with a new "
                           "value (or revert / remove)")
    if from_assembly and not reason:
        raise InvalidInput("say why (reason): this line was priced from the trade's answers, so a hand change is "
                           "an override and is kept with its reason", field="reason")
    _confirm(confirm, f"Change line {li['id']} ({li['description']}): " + ", ".join(
        f"{k} {li[k]} → {v}" for k, v in changes.items())
             + (f" (an override of the {li['module_id']} assembly; re-applying it keeps cost, waste and description "
                "changes but not quantity)" if from_assembly else "") + "?",
             line_id=li["id"], changes=changes, override=from_assembly)
    with service.transaction(conn):
        _write_override(conn, ctx, li, changes, reason, now)
        service._log(conn, ctx, est["id"], "line_overridden" if from_assembly else "line_updated",
                     {"line_id": li["id"], **changes, "reason": reason},
                     before={k: li[k] for k in changes})
        service._recalculate(conn, ctx, est["id"])
        service._bump(conn, ctx, est["id"])
    out = service.get_estimate(conn, ctx, est["id"])
    out["line_id"] = li["id"]
    out["changed"] = changes
    return out

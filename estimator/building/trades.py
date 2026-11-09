"""A trade's measured answers from the plans (Coder 2 Sprint 12), one place for every trade that's read off plans:

- framing, drywall, painting, insulation, flooring: from the shared wall-and-room model (building.model), so they
  always agree with each other;
- Sprint 14: windows and doors (door and window tags linked to their schedules), siding (elevations, else the floor
  plans' outside walls; corners from the building's outline) and HVAC (the area to heat and cool) from the same model;
- Sprint 15: fencing (fence lines, gates) and landscaping (zones by kind, the plant schedule) from the site and landscape
  plans (building.site), landscaping's trees, shrubs and zone valves also from symbols when there's no plant schedule;
- electrical, plumbing, HVAC: from the symbols counted on the plans (symbol_detections), each item type counted toward its
  trade question (plan_engine.symbol_library.FEEDS). Only symbols a person approved count unless include_proposed is
  set; the ones still to check are reported so nothing is priced from an unchecked count by surprise.

Nothing is priced or saved here: the answers go to the trade's takeoff (runner_submit_takeoff, est_quick_answer)
after a person looks at them. Answers for questions the trade module doesn't have are left out and noted.
"""
from __future__ import annotations

from estimator.building import model as building
from estimator.context import RequestContext
from estimator.errors import InvalidInput

SYMBOL_TRADES = ("electrical", "plumbing", "hvac", "landscaping")   # Sprint 15: trees, shrubs and zone valves
TRADES = building.MODEL_TRADES + tuple(t for t in SYMBOL_TRADES if t not in building.MODEL_TRADES)


def _module_questions(module_id: str) -> dict | None:
    try:
        from estimator.modules import get_registry
        mod = get_registry().get(module_id)
    except Exception:  # noqa: BLE001 - no registry or no such module: answers are given as they are
        return None
    return {q.id: q for q in mod.questions} if mod else None


def _fit(module_id: str, out: dict) -> dict:
    """Keep only answers the trade module asks for, so a changed module never gets an answer it can't use."""
    qs = _module_questions(module_id)
    if qs is None:
        return out
    unknown = [k for k in out["answers"] if k not in qs]
    for k in unknown:
        out["answers"].pop(k)
        out["from"].pop(k, None)
    if unknown:
        out["notes"].append(f"left out (the {module_id} trade has no question for them): {', '.join(unknown)}")
    return out


def symbol_answers(conn, ctx: RequestContext, module_id: str, plan_set_ids: list[int],
                   include_proposed: bool = False) -> dict:
    from estimator.plan_engine import symbol_library as lib
    counts: dict[str, dict] = {}
    if plan_set_ids:
        q = ",".join("?" * len(plan_set_ids))
        for r in conn.execute(
                f"SELECT item_type, trade, status, COUNT(*) AS n FROM symbol_detections WHERE company_id = ? AND"
                f" plan_set_id IN ({q}) AND status != 'rejected' GROUP BY item_type, trade, status",
                (ctx.company_id, *plan_set_ids)):
            c = counts.setdefault(r["item_type"] or "unknown", {"approved": 0, "proposed": 0, "trade": r["trade"]})
            c[r["status"]] = c.get(r["status"], 0) + r["n"]
            c["trade"] = c["trade"] or r["trade"]
    answers, src, waiting, not_counted = {}, {}, {}, {}
    for it, c in sorted(counts.items()):
        feeds = [f for f in lib.feeds_of(it) if f[0] == module_id]
        n = c["approved"] + (c["proposed"] if include_proposed else 0)
        if not feeds:
            if it != "unknown" and lib.module_of_trade(c["trade"]) == module_id:   # this trade's, not one of its questions
                not_counted[it] = c["approved"] + c["proposed"]
            continue
        for feed in feeds:
            qid = feed[1]
            if len(feed) == 3:                               # a choice (water heater kind, HVAC system)
                if n:
                    rank = {v: i for i, v in enumerate(lib.CHOICE_ORDER.get(qid, ()))}
                    current = answers.get(qid)
                    if current is None or rank.get(feed[2], 99) < rank.get(current, 99):
                        answers[qid] = feed[2]
                    src.setdefault(qid, []).append(f"{n} {it.replace('_', ' ')}")
                continue
            if not include_proposed and c["proposed"]:
                waiting[qid] = waiting.get(qid, 0) + c["proposed"]
            if n:
                answers[qid] = answers.get(qid, 0) + n
                src.setdefault(qid, []).append(f"{n} {it.replace('_', ' ')}")
    notes = []
    if waiting:
        notes.append("still to check in Reviews (not counted yet): " +
                     ", ".join(f"{n} for {q.replace('_', ' ')}" for q, n in waiting.items()))
    if not_counted:
        notes.append("found but not a question in this trade: " +
                     ", ".join(f"{n} {it.replace('_', ' ')}" for it, n in not_counted.items()))
    unk = counts.get("unknown")
    if unk and unk["trade"] in (module_id, None):
        notes.append(f"{unk['approved'] + unk['proposed']} unidentified symbol(s): name them in Reviews to count them")
    for c in counts.values():
        c.pop("trade", None)
    if not answers:
        notes.append(f"no approved {module_id} symbols yet: approve them in Reviews first"
                     if not include_proposed else f"no {module_id} symbols found on the plans")
    return {"ok": True, "module_id": module_id, "answers": answers, "from": {k: "; ".join(v) for k, v in src.items()},
            "waiting": waiting, "notes": notes, "counts": counts, "include_proposed": include_proposed}


def answers(conn, ctx: RequestContext, module_id: str, *, estimate_id: int | None = None,
            plan_set_id: int | None = None, height_ft: float | None = None, include_proposed: bool = False) -> dict:
    """A trade's measured answers from the plans, with where each came from. Changes nothing."""
    module_id = (module_id or "").strip().lower()
    if module_id not in TRADES:
        raise InvalidInput(f"answers from the plans are for {', '.join(TRADES)}", module_id=module_id,
                           valid=list(TRADES))
    if module_id in building.MODEL_TRADES:
        m = building.build(conn, ctx, estimate_id=estimate_id, plan_set_id=plan_set_id, height_ft=height_ft)
        return _fit(module_id, _one(conn, ctx, m, module_id, include_proposed))
    sets = building._plan_sets(conn, ctx, plan_set_id, estimate_id)
    out = symbol_answers(conn, ctx, module_id, [p["id"] for p in sets], include_proposed)
    out.update(plan_set_ids=[p["id"] for p in sets], source="symbols counted on the plans")
    return _fit(module_id, out)


def _one(conn, ctx, m: dict, module_id: str, include_proposed: bool) -> dict:
    """A model trade's answers; a trade that's also counted from symbols (HVAC) gets both, the symbols adding their
    questions (registers, returns, thermostats, the system) to the model's (the area to heat and cool)."""
    out = building.answers_for(m, module_id)
    out.update(plan_set_ids=m["plan_set_ids"], source="wall-and-room model", summary=m["summary"])
    if module_id in SYMBOL_TRADES:
        s = symbol_answers(conn, ctx, module_id, m["plan_set_ids"], include_proposed)
        for k, v in s["answers"].items():
            out["answers"].setdefault(k, v)                 # the model's own answer wins (a plant schedule's counts)
            out["from"].setdefault(k, s["from"].get(k, "symbols counted on the plans"))
        snotes = s["notes"]
        if module_id in building.SITE_TRADES and not s["counts"]:
            snotes = []                                     # no landscape symbols at all: nothing to say about them
        out["notes"] = snotes + out["notes"]
        out.update(waiting=s["waiting"], counts=s["counts"], include_proposed=include_proposed,
                   source="wall-and-room model and symbols counted on the plans")
    return out


def all_answers(conn, ctx: RequestContext, *, estimate_id: int | None = None, plan_set_id: int | None = None,
                height_ft: float | None = None, include_proposed: bool = False) -> dict:
    """Every plan-read trade's answers at once, all from the same model (so they agree) - the Plan quantities page."""
    m = building.build(conn, ctx, estimate_id=estimate_id, plan_set_id=plan_set_id, height_ft=height_ft)
    out = {}
    for t in TRADES:
        if t in building.MODEL_TRADES:
            out[t] = _fit(t, _one(conn, ctx, m, t, include_proposed))
        else:
            out[t] = _fit(t, symbol_answers(conn, ctx, t, m["plan_set_ids"], include_proposed))
    return {"ok": True, "model": m, "trades": out}

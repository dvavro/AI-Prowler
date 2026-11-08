"""The Estimates screen (Coder 2 Sprint 8): one estimate's trades and lines, linked both ways to the measurements
behind them, plus the estimate tools the screen mirrors (est_get_estimate, est_add_line_item, est_calculate,
est_validate, est_scenarios / est_choose_scenario, est_compare_history, est_create_revision).

  GET  /estimates/<id>/detail               the estimate (costs hidden for roles that can't see margins), the links
                                            (estimator/api/links.py), saved options, and what I may do
  GET  /estimates/<id>/validate             est_validate
  GET  /estimates/<id>/history              est_compare_history (roles that see margins)
  POST /estimates/<id>/options {module_id?}                         est_scenarios (prices and saves the options)
  POST /estimates/<id>/options/choose {option_id, module_id?, rev, confirm?}     est_choose_scenario (asks first)
  POST /estimates/<id>/lines {kind, description, quantity, unit, unit_cost_cents | price_key, waste_pct?, rev}
                                                                    est_add_line_item
  POST /estimates/<id>/calculate {rev}                              est_calculate
  POST /estimates/<id>/revision {change_summary, confirm?}          est_create_revision (asks first)
  POST /estimates/<id>/use-measurements {module_id, rev, confirm?}  re-price a trade with its approved measurements
                                                                    (est_quick_answer with takeoff_list's totals; asks)
The service layer checks every role and the estimate's state again; the page only hides what would be refused.
"""
from __future__ import annotations

import re

from estimator.api import nav

_DETAIL = re.compile(r"^/estimates/(\d+)/(detail|validate|history)$")
_ACTION = re.compile(r"^/estimates/(\d+)/(options|options/choose|lines|calculate|revision|use-measurements)$")


def handles(sub: str) -> bool:
    return bool(_DETAIL.match(sub) or _ACTION.match(sub))


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def _rev(b: dict) -> int:
    v = b.get("rev")
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise _refuse("rev is needed to change the estimate (it stops two people overwriting each other)")
    try:
        return int(v)
    except ValueError:
        raise _refuse("rev must be a whole number") from None


def _text(b: dict, key: str, limit: int = 200) -> str | None:
    v = b.get(key)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (str, int, float)):
        raise _refuse(f"{key} must be text")
    v = str(v).strip()
    if len(v) > limit:
        raise _refuse(f"{key} is too long ({limit} characters at most)")
    return v


def _asked(question: str, **details):
    from estimator.api.router import _ok
    return _ok(needs_confirmation=True, question=question, **details)


def route(m: str, sub: str, req, ctx, conn, see: bool):
    from estimator.api import links
    from estimator.api.router import _body, _fail, _json, _ok, redact
    from estimator.estimating import quick, scenarios, service, validate
    from estimator.learning import history
    from estimator.modules import get_registry

    if not nav.can_open(ctx.role, "estimates"):
        raise _refuse("your role can't open estimates", 403, "permission_denied")
    mm = _DETAIL.match(sub) or _ACTION.match(sub)
    eid, what = int(mm.group(1)), mm.group(2)

    if what == "detail" and m == "GET":
        est = service.get_estimate(conn, ctx, eid)
        editable = est["status"] in service.EDITABLE_STATUSES
        return _ok(estimate=redact(est, see), links=links.estimate_links(conn, ctx, eid, est),
                   options=redact(scenarios.list_options(conn, ctx, eid), see), see_margins=see,
                   can_edit=editable and ctx.role in service.EDIT_ROLES,
                   can_options=editable and ctx.role in service.QUICK_ROLES,
                   can_revise=est["status"] in service.REVISABLE_STATUSES and ctx.role in service.QUICK_ROLES,
                   can_review=nav.can_open(ctx.role, "takeoffs"), line_kinds=list(service.LINE_KINDS))

    if what == "validate" and m == "GET":
        return _json(200, redact(validate.validate(conn, ctx, eid), see))

    if what == "history" and m == "GET":
        if not see:
            raise _refuse("your role doesn't see costs, so it can't compare them", 403, "permission_denied")
        return _json(200, history.compare_history(conn, ctx, eid))

    if m != "POST":
        return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
    b = _body(req)
    confirm = b.get("confirm") is True

    if what == "options":
        return _json(200, redact(scenarios.price_options(conn, ctx, eid, _text(b, "module_id", 64) or None), see))

    if what == "options/choose":
        option_id = _text(b, "option_id", 64)
        if not option_id:
            raise _refuse("say which option (option_id)")
        rev = _rev(b)
        module_id = _text(b, "module_id", 64) or None
        if not confirm:
            opts = [o for o in scenarios.list_options(conn, ctx, eid)
                    if o["id"] == option_id and (module_id is None or o["module_id"] == module_id)]
            if not opts:
                raise _refuse(f"there's no option '{option_id}'; price the options first")
            return _asked(f"Switch {opts[0]['module_id'].replace('_', ' ')} to “{opts[0]['label']}”? That trade is "
                          "priced again with its answers.", option_id=option_id)
        return _json(200, redact(scenarios.choose_option(conn, ctx, eid, option_id, rev, module_id), see))

    if what == "lines":
        unit_cost = b.get("unit_cost_cents")
        if unit_cost is not None and (isinstance(unit_cost, bool) or not isinstance(unit_cost, int)):
            raise _refuse("unit_cost_cents must be a whole number of cents")
        out = service.add_line_item(conn, ctx, eid, _rev(b), kind=_text(b, "kind", 20) or "",
                                    description=_text(b, "description") or "", quantity=_text(b, "quantity", 30) or "",
                                    unit=_text(b, "unit", 20) or "", unit_cost_cents=unit_cost,
                                    price_key=_text(b, "price_key", 100) or None,
                                    waste_pct=_text(b, "waste_pct", 10) or "0")
        return _json(200, redact(out, see))

    if what == "calculate":
        return _json(200, redact(service.calculate(conn, ctx, eid, _rev(b)), see))

    if what == "revision":
        summary = _text(b, "change_summary", 500) or ""
        if not summary:
            raise _refuse("say what's changing, e.g. “customer added the back patio”")
        if not confirm:
            est = service.get_estimate(conn, ctx, eid)
            return _asked(f"Make version {est['revision'] + 1 if est.get('revision') else 2} of “{est['title']}” to "
                          "change it? This one stays as it is, and its open quotes are voided.")
        return _json(200, redact(service.create_revision(conn, ctx, eid, summary), see))

    if what == "use-measurements":
        module_id = _text(b, "module_id", 64)
        if not module_id:
            raise _refuse("say which trade (module_id)")
        if ctx.role not in service.EDIT_ROLES:
            raise _refuse("only owners and estimators re-price trades", 403, "permission_denied")
        reg = get_registry()
        try:
            mod = reg.get(module_id)
        except Exception:  # noqa: BLE001
            raise _refuse(f"there's no trade '{module_id}'") from None
        rev = _rev(b)
        est = service.get_estimate(conn, ctx, eid)
        answers, changes = links.answers_from_measurements(conn, ctx, est, module_id, reg)
        if not confirm:
            said = "; ".join(f"{mod.question(q).label}: {c['from'] if c['from'] is not None else 'none'} → {c['to']}"
                             for q, c in changes.items()) or "the answers already match"
            return _asked(f"Price {mod.name} with the approved measurements ({said})?", changes=changes)
        out = quick.answer(conn, ctx, eid, module_id, answers, rev, reg)
        return _json(200, {**redact(out, see), "changes": changes})

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")

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
  POST /estimates/<id>/lines/<line_id> {quantity?, unit_cost_cents?, waste_pct?, description?, price_key?,
                                    price_default?, reason?, revert?, remove?, confirm?}
                                                                    est_update_line_item (change, revert or remove; asks first)
  POST /estimates/<id>/calculate {rev}                              est_calculate
  POST /estimates/<id>/revision {change_summary, confirm?}          est_create_revision (asks first)
  POST /estimates/<id>/use-measurements {module_id, rev, confirm?}  re-price a trade with its approved measurements
                                                                    (est_quick_answer with takeoff_list's totals; asks)
   GET  /estimates/<id>/inspection-review                              the latest Inspector code review per trade, if any
   POST /estimates/<id>/inspection-review {zip_code?, module_id?}     run the Inspector's code review (one trade, or all construction trades on the estimate)
   POST /estimates/<id>/inspection-review/<review_id>/apply {item_id, rev}   add a suggested item as a line
   GET  /estimates/<id>/bom                                   the bill of materials: material lines per construction trade
   POST /estimates/<id>/bom/ordered {section_id, item_key, ordered}   tick a BOM item ordered (or untick it)
The service layer checks every role and the estimate's state again; the page only hides what would be refused.
"""
from __future__ import annotations

import re

from estimator.api import nav

_DETAIL = re.compile(r"^/estimates/(\d+)/(detail|validate|history)$")
_ACTION = re.compile(r"^/estimates/(\d+)/(options|options/choose|lines|calculate|revision|reopen|change-order"
                     r"|use-measurements)$")
_LINE = re.compile(r"^/estimates/(\d+)/lines/(\d+)$")
_BOM = re.compile(r"^/estimates/(\d+)/bom(?:/(ordered))?$")
_INSPECTION = re.compile(r"^/estimates/(\d+)/inspection-review(?:/(\d+)/apply)?$")


def handles(sub: str) -> bool:
    return bool(_DETAIL.match(sub) or _ACTION.match(sub) or _LINE.match(sub) or _BOM.match(sub)
                or _INSPECTION.match(sub))


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
    from estimator.estimating import bom, quick, scenarios, service, validate
    from estimator.learning import history
    from estimator.modules import get_registry

    if not nav.can_open(ctx.role, "estimates"):
        raise _refuse("your role can't open estimates", 403, "permission_denied")
    lm = _LINE.match(sub)
    if lm:
        if m != "POST":
            return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
        from estimator.api.router import _question
        from estimator.errors import ConfirmationRequired
        from estimator.estimating import assemblies
        b = _body(req)
        eid, line_id = int(lm.group(1)), int(lm.group(2))
        unit_cost = b.get("unit_cost_cents")
        if unit_cost is not None and (isinstance(unit_cost, bool) or not isinstance(unit_cost, int)):
            raise _refuse("unit_cost_cents must be a whole number of cents")
        try:
            out = assemblies.update_line_item(conn, ctx, eid, _rev(b), line_id,
                                              quantity=_text(b, "quantity", 30),
                                              unit_cost_cents=unit_cost,
                                              waste_pct=_text(b, "waste_pct", 10),
                                              description=_text(b, "description"),
                                              price_key=_text(b, "price_key", 100),
                                              price_default=b.get("price_default") is True,
                                              reason=_text(b, "reason", 300),
                                              revert=b.get("revert") is True,
                                              remove=b.get("remove") is True,
                                              confirm=b.get("confirm") is True)
        except ConfirmationRequired as e:
            return _asked(_question(e.message), **e.details)
        return _json(200, redact(out, see))
    bm = _BOM.match(sub)
    if bm:
        eid, action = int(bm.group(1)), bm.group(2)
        if action is None:
            if m != "GET":
                return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
            return _ok(bom=redact(bom.bom_for_estimate(conn, ctx.company_id, eid), see))
        if m != "POST":
            return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
        b = _body(req)
        section_id = b.get("section_id")
        if isinstance(section_id, bool) or not isinstance(section_id, int):
            raise _refuse("say which section (section_id)")
        item_key = _text(b, "item_key", 300)
        if not item_key:
            raise _refuse("say which item (item_key)")
        return _ok(**bom.set_ordered(conn, ctx, eid, section_id, item_key, b.get("ordered") is True))
    im = _INSPECTION.match(sub)
    if im:
        from estimator.estimating import inspection_review
        eid, review_id = int(im.group(1)), im.group(2)
        if review_id is None:
            if m == "GET":
                return _ok(reviews=redact(list(inspection_review.latest_reviews(conn, ctx.company_id, eid).values()), see))
            if m != "POST":
                return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
            b = _body(req)
            out = inspection_review.run_review(
                conn, ctx, eid, _text(b, "zip_code", 10) or None, _text(b, "module_id", 64) or None)
            return _json(200, redact(out, see))
        if m != "POST":
            return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
        b = _body(req)
        item_id = _text(b, "item_id", 80)
        if not item_id:
            raise _refuse("say which checklist item (item_id)")
        out = inspection_review.apply_item(conn, ctx, eid, int(review_id), item_id, _rev(b))
        return _json(200, redact(out, see))
    mm = _DETAIL.match(sub) or _ACTION.match(sub)
    eid, what = int(mm.group(1)), mm.group(2)

    if what == "detail" and m == "GET":
        from estimator.estimating import reopen
        from estimator.estimating import inspection_review
        est = service.get_estimate(conn, ctx, eid)
        editable = est["status"] in service.EDITABLE_STATUSES
        since = reopen.changes_since_approval(conn, ctx, eid) if editable else None
        from estimator.estimating import change_orders
        can_reopen = ctx.role in service.EDIT_ROLES and reopen.can_reopen(conn, est)
        return _ok(estimate=redact(est, see), links=links.estimate_links(conn, ctx, eid, est),
                   since_approval=redact(since, see) if since else None, can_reopen=can_reopen,
                   change_order=change_orders.info(conn, ctx, eid), change_orders=change_orders.list_for(conn, ctx, eid),
                   can_change_order=change_orders.can_make(conn, ctx, est),
                   options=redact(scenarios.list_options(conn, ctx, eid), see), see_margins=see,
                   scenario_defs=scenarios.list_definitions(get_registry(),
                                                            [s["module_id"] for s in est["sections"]]),
                   can_edit=editable and ctx.role in service.EDIT_ROLES,
                   can_options=editable and ctx.role in service.QUICK_ROLES,
                   can_revise=est["status"] in service.REVISABLE_STATUSES and ctx.role in service.QUICK_ROLES,
                   can_review=nav.can_open(ctx.role, "takeoffs"), line_kinds=list(service.LINE_KINDS),
                   bom=redact(bom.bom_for_estimate(conn, ctx.company_id, eid), see),
                   inspector=inspection_review.inspector_setting(conn, ctx.company_id),
                   inspection_reviews=redact(list(inspection_review.latest_reviews(conn, ctx.company_id, eid).values()), see),
                   reviewable_trades=inspection_review.reviewable_on(est))

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

    if what == "reopen":
        from estimator.api.router import _question
        from estimator.errors import ConfirmationRequired
        from estimator.estimating import reopen
        try:
            out = reopen.reopen(conn, ctx, eid, _rev(b), reason=_text(b, "reason", 500) or "", confirm=confirm)
        except ConfirmationRequired as e:
            return _asked(_question(e.message), **e.details)
        return _json(200, redact(out, see))

    if what == "change-order":
        from estimator.api.router import _question
        from estimator.errors import ConfirmationRequired
        from estimator.estimating import change_orders
        try:
            out = change_orders.create(conn, ctx, eid, _text(b, "change_summary", 500) or "", confirm=confirm)
        except ConfirmationRequired as e:
            return _asked(_question(e.message), **e.details)
        return _json(200, redact(out, see))

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

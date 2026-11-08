"""The Director's step engine.

start() triages a request, creates the estimate and the job file, then runs the
job forward until it needs something: an answer, an approval, or a feature that
isn't built yet. next() takes what the user supplied (answers, an approval) and
runs it forward again. Every result says what happens next, who it's waiting
on, and what to say, phrased for the person's role.

The Director never does maths: prices come from the quick-estimate engine and
the pricing stack, and the approval threshold is a company setting.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation

from estimator.context import RequestContext
from estimator.core.dates import local_date_text
from estimator.core.units.money import format_cents
from estimator.director import jobs as jobstore
from estimator.director import overrides
from estimator.director.playbooks import get_playbooks, playbook_for_lane
from estimator.director.settings import get_settings
from estimator.director.triage import trades_mentioned, triage
from estimator.errors import ConfirmationRequired, EstimatorError, InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.bids import service as bids
from estimator.integrations import host
from estimator.estimating import quick, service, validate
from estimator.estimating import scenarios as _scenarios
from estimator.agent_manager import list_configs
from estimator.runner import runner

FULL_APPROVE_ROLES = ("owner", "reviewer")
REVIEW_ROLES = ("owner", "reviewer")
LANE_NAMES = {"quick_quote": "quick quote", "standard_estimate": "standard estimate",
              "full_takeoff": "full plan takeoff"}
CUSTOMER_FACING_ROLES = ("office", "field")


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def _tx(conn, fn):
    with service.transaction(conn):
        return fn()


# ------------------------------------------------------------------ public API

def start(conn, ctx: RequestContext, request: str, *, customer_id: str | None = None, address: str | None = None,
          module_id: str | None = None, has_plans: bool = False, answers: dict | None = None,
          due_date: str | None = None, customer: dict | None = None, registry=None) -> dict:
    """Start a job from a plain-language request."""
    if not (request or "").strip() and not module_id:
        raise InvalidInput("tell the Director what the job is (or give a module_id)")
    reg = _registry(registry)
    cust = bids.clean_customer(customer)
    if customer_id:
        cust["customer_id"] = customer_id
    if address and not cust.get("address"):
        cust["address"] = address
    tri = triage(request, reg, has_plans=has_plans, module_id=module_id or None)
    title = (request or "").strip().splitlines()[0][:80] if request else (module_id or "New job")
    est = service.create_estimate(conn, ctx, title, customer_id=customer_id, address=address, due_date=due_date)
    pb = playbook_for_lane(tri.lane) if tri.lane else None
    stage = pb.stages[0].id if pb else "triage"

    def make():
        jid = jobstore.create_job(conn, ctx, request_text=request or "", estimate_id=est["id"], lane=tri.lane,
                                  module_id=tri.module_id, playbook=pb, stage=stage, answers=answers or {},
                                  due_date=due_date, customer=cust)
        jobstore.log_step(conn, ctx, jid, "triage", "director", "done" if tri.lane else "blocked",
                          tri.reason, tri.as_dict())
        service._log(conn, ctx, est["id"], "director_job_started",
                     {"job_id": jid, "lane": tri.lane, "module_id": tri.module_id})
        return jid
    job_id = _tx(conn, make)
    return _run(conn, ctx, job_id, reg, triage_info=tri.as_dict())


def next_step(conn, ctx: RequestContext, job_id: int, *, answers: dict | None = None, module_id: str | None = None,
              approve: bool = False, confirm_sample_prices: bool = False, rev: int | None = None,
              customer: dict | None = None, send: bool = False, send_to: str | None = None,
              outcome: str | None = None, convert: bool = False, service_date: str | None = None,
              revise: bool = False, change_summary: str | None = None, reprice: bool = False,
              reviewed: bool = False, scenarios: bool = False, choose_scenario: str | None = None,
              scenario_module: str | None = None, checklist_done: bool = False, trades=None,
              confirm: bool = False, registry=None) -> dict:
    """Give the Director what it asked for (answers, a module choice, the trades in a plan takeoff, an approval, a
    send, the customer's answer) and get the next step. send=true and convert=true reach outside the Estimator
    (an email to the customer; a customer, quote and job in AI-Prowler), so they ask first: without confirm=true
    nothing changes and ConfirmationRequired carries the question to put to the user."""
    reg = _registry(registry)
    if outcome is not None and outcome not in ("won", "lost"):
        raise InvalidInput("outcome must be won or lost", field="outcome")
    job = jobstore.load_job(conn, ctx, int(job_id))
    if rev is not None and int(rev) != int(job["rev"]):
        jobstore.save_job(conn, ctx, job, expected_rev=rev)   # raises StaleRevision
    if job["state"] in ("done", "cancelled"):
        return _result(conn, ctx, job, reg)
    if (send or convert) and not confirm:
        _ask_before_sending(conn, ctx, job, send=send, send_to=send_to, customer=customer, convert=convert,
                            outcome=outcome, service_date=service_date)

    if customer:
        cust = bids.clean_customer(customer)
        job = jobstore.load_job(conn, ctx, job["id"])
        job["customer"].update(cust)
        _tx(conn, lambda: jobstore.save_job(conn, ctx, job))

    if trades is not None:
        if isinstance(trades, str):
            trades = [t.strip() for t in trades.split(",") if t.strip()]
        if job["lane"] != "full_takeoff":
            raise InvalidInput("trades=[...] is for plan takeoff jobs; add a trade to this job with "
                               "est_director_add_trade", lane=job["lane"])
        if not isinstance(trades, (list, tuple)) or not trades:
            raise InvalidInput("trades is a list, e.g. [\"framing\", \"drywall\"]", field="trades")
        bad = [t for t in trades if t not in reg.modules or reg.modules[t].category != "construction"]
        if bad:
            raise InvalidInput(f"not construction trades: {bad}", field="trades",
                               available=sorted(m.id for m in reg.list() if m.category == "construction"))
        est = service.get_estimate(conn, ctx, job["estimate_id"])
        if est["status"] not in service.EDITABLE_STATUSES:
            raise NotEditable(f"the estimate is {est['status']}; make a revision (revise=true) first",
                              estimate_id=est["id"], status=est["status"])
        order = list(dict.fromkeys(trades))
        job = jobstore.load_job(conn, ctx, job["id"])
        job.update(module_id=order[0], trades={t: job["trades"].get(t, {}) for t in order[1:]},
                   stage=get_playbooks()[job["playbook_id"]].stages[0].id, state="active")
        _tx(conn, lambda: (jobstore.log_step(conn, ctx, job["id"], "trades", "director", "done",
                                             "trades: " + ", ".join(order), {"trades": order}),
                           jobstore.save_job(conn, ctx, job)))

    if (job["lane"] is None or job["module_id"] is None) and (module_id or answers):
        if not module_id:
            raise InvalidInput("which service is this? give module_id", candidates=[m.id for m in reg.list()])
        tri = triage(job["request_text"], reg, module_id=module_id)
        if job["lane"] == "full_takeoff":
            tri.lane = "full_takeoff"
        pb = playbook_for_lane(tri.lane)
        job.update(lane=tri.lane, module_id=tri.module_id, playbook_id=pb.id, playbook_version=pb.version,
                   stage=pb.stages[0].id)
        _tx(conn, lambda: (jobstore.log_step(conn, ctx, job["id"], "triage", "director", "done",
                                             f"module chosen: {tri.module_id}", tri.as_dict()),
                           jobstore.save_job(conn, ctx, job)))

    if revise:
        # The customer wants changes after the quote was approved or sent: new revision, back to the questions.
        new = service.create_revision(conn, ctx, job["estimate_id"],
                                      change_summary or "changes requested after the quote")
        job = jobstore.load_job(conn, ctx, job["id"])
        job.update(estimate_id=new["id"], stage=get_playbooks()[job["playbook_id"]].stages[0].id
                   if job["playbook_id"] else job["stage"], state="active")
        _tx(conn, lambda: (jobstore.log_step(conn, ctx, job["id"], "revise", "director", "done",
                                             f"revision {new['revision']} (estimate {new['id']})",
                                             {"from": new["revision_of"], "voided_bids": new["voided_bids"]}),
                           jobstore.save_job(conn, ctx, job)))

    if reprice and not answers and not revise:
        job = jobstore.load_job(conn, ctx, job["id"])
        est = service.get_estimate(conn, ctx, job["estimate_id"])
        if est["status"] not in service.EDITABLE_STATUSES:
            raise NotEditable(f"the quote was {est['status']}; use revise=true to make a new version with new prices",
                              estimate_id=est["id"], status=est["status"])
        if job["lane"] in ("quick_quote", "standard_estimate"):
            job["stage"] = get_playbooks()[job["playbook_id"]].stages[0].id
            _tx(conn, lambda: jobstore.save_job(conn, ctx, job))

    if answers:
        if not isinstance(answers, dict):
            raise InvalidInput("answers must be an object of question id -> answer")
        est = service.get_estimate(conn, ctx, job["estimate_id"])
        if est["status"] not in service.EDITABLE_STATUSES:
            raise NotEditable(f"the quote was {est['status']}; to change it, call again with revise=true "
                              "(and a change_summary) to make a new version", estimate_id=est["id"],
                              status=est["status"])
        job = jobstore.load_job(conn, ctx, job["id"])
        job["answers"].update(answers)
        first = get_playbooks()[job["playbook_id"]].stages[0].id if job["playbook_id"] else job["stage"]
        if job["lane"] in ("quick_quote", "standard_estimate") and job["stage"] != first:
            job["stage"] = first                   # re-price (and re-check) with the new answers
        _tx(conn, lambda: jobstore.save_job(conn, ctx, job))

    if choose_scenario:
        job = jobstore.load_job(conn, ctx, job["id"])
        est = service.get_estimate(conn, ctx, job["estimate_id"])
        if est["status"] not in service.EDITABLE_STATUSES:
            raise NotEditable(f"the quote was {est['status']}; to switch options call again with revise=true "
                              "(and a change_summary) plus choose_scenario", estimate_id=est["id"], status=est["status"])
        picked = _scenarios.choose_option(conn, ctx, est["id"], choose_scenario, est["rev"], module_id=scenario_module,
                                          registry=reg)["chosen_option"]
        job = jobstore.load_job(conn, ctx, job["id"])
        if picked["module_id"] == job["module_id"]:
            job["answers"].update(picked["answers"])
        else:
            job["trades"].setdefault(picked["module_id"], {}).update(picked["answers"])
        job["stage"] = get_playbooks()[job["playbook_id"]].stages[0].id
        _tx(conn, lambda: (jobstore.log_step(conn, ctx, job["id"], "choose_scenario", "pricer", "done",
                                             f"chose '{picked['label']}'", picked),
                           jobstore.save_job(conn, ctx, job)))

    inputs = {"approve": approve, "confirm_sample_prices": confirm_sample_prices, "send": send, "reviewed": reviewed,
              "checklist_done": checklist_done,
              "send_to": send_to, "outcome": outcome, "convert": convert, "service_date": service_date}
    out = _run(conn, ctx, job["id"], reg, inputs=inputs)
    if scenarios:
        priced = _scenarios.price_options(conn, ctx, out["job"]["estimate_id"], module_id=scenario_module, registry=reg)
        out["scenarios"] = priced["options"]
        out.setdefault("notes", []).append(
            f"{priced['trade']} options: {priced['summary']}. Pick one with choose_scenario=<id>, or keep the quote as it "
            "is; the options are shown on the bid.")
    return out


def _ask_before_sending(conn, ctx, job, *, send, send_to, customer, convert, outcome, service_date) -> None:
    """Raise ConfirmationRequired before an email to the customer or new records in AI-Prowler (decision 2026-11-08,
    David: the Director asks first in chat too, the same as bid_send and bid_convert_to_job). Nothing has changed
    yet when this raises. A send with no email address anywhere asks nothing: nothing can be sent, and the Director
    then says it needs the address."""
    bid = bids.latest_for_estimate(conn, ctx, job["estimate_id"]) if job["estimate_id"] else None
    est = service.get_estimate(conn, ctx, job["estimate_id"]) if job["estimate_id"] else None
    money = format_cents(bid["total_cents"] if bid else ((est or {}).get("totals") or {}).get("total_cents", 0))
    cust = dict(job.get("customer") or {})
    if isinstance(customer, dict):
        cust.update({k: v for k, v in customer.items() if v})
    if convert:
        if bid is not None and (bid["job_id"] or (bid["status"] != "won" and outcome != "won")):
            convert = False          # already a job, or not won: the step does nothing, so there's nothing to ask
    if convert:
        name = cust.get("name") or (bid["customer"].get("name") if bid else "")
        when = f" with service on {service_date}" if service_date else ""
        raise ConfirmationRequired(
            f"Turn the {money} quote into a job{' for ' + name if name else ''}{when}? This creates the customer "
            "(if new), an approved quote and a job in AI-Prowler. Call again with confirm=true once the user says yes.",
            job_id=job["id"], action="convert", total_cents=bid["total_cents"] if bid else None,
            service_date=service_date)
    if send:
        to = (send_to or cust.get("email") or (bid["customer"].get("email") if bid else "") or "").strip()
        if bid is not None and bid["status"] != "draft":
            return                   # already sent: the step does nothing
        if to:
            raise ConfirmationRequired(
                f"Email the {money} quote to {to}? Call again with confirm=true once the user says yes.",
                job_id=job["id"], action="send", to=to)


def status(conn, ctx: RequestContext, job_id: int, registry=None) -> dict:
    reg = _registry(registry)
    job = jobstore.load_job(conn, ctx, int(job_id))
    out = _result(conn, ctx, job, reg)
    out["steps"] = jobstore.steps(conn, job["id"])
    return out


def board(conn, ctx: RequestContext, mine: bool = False, include_done: bool = False) -> dict:
    rows = jobstore.list_jobs(conn, ctx, include_done=include_done, mine=mine)
    by_lane: dict[str, list] = {}
    for r in rows:
        by_lane.setdefault(r["lane"] or "needs_triage", []).append(r)
    return {"ok": True, "count": len(rows), "jobs": rows, "by_lane": by_lane}


def change_lane(conn, ctx: RequestContext, job_id: int, lane: str, *, module_id: str | None = None,
                reason: str | None = None, registry=None) -> dict:
    """Move a job to another lane (e.g. a quick quote that turns out bigger becomes a standard estimate with a
    Reviewer check). The estimate, the answers and the customer are kept."""
    reg = _registry(registry)
    pbs = {pb.lane: pb for pb in get_playbooks().values()}
    if lane not in pbs:
        raise InvalidInput(f"lane must be one of {sorted(pbs)}", field="lane")
    pb = pbs[lane]
    job = jobstore.load_job(conn, ctx, int(job_id))
    if job["state"] in ("done", "cancelled"):
        raise NotEditable(f"job {job['id']} is {job['state']}", job_id=job["id"])
    if job["lane"] == lane and not module_id:
        return _result(conn, ctx, job, reg)
    est = service.get_estimate(conn, ctx, job["estimate_id"])
    if est["status"] not in service.EDITABLE_STATUSES:
        raise NotEditable(f"the estimate is {est['status']}; make a revision (revise=true) before changing lanes",
                          estimate_id=est["id"], status=est["status"])
    mid = module_id or job["module_id"]
    if mid:
        mod = reg.get(mid)
        if lane == "quick_quote" and (mod.category != "service" or mod.path not in ("quick_estimate", "both")):
            raise InvalidInput(f"{mod.name} can't be a quick quote; use standard_estimate", module_id=mid)
    elif lane == "quick_quote":
        raise InvalidInput("which service is this? give module_id", candidates=[m.id for m in reg.list()])
    old = job["lane"]
    job.update(lane=lane, module_id=mid, playbook_id=pb.id, playbook_version=pb.version, stage=pb.stages[0].id,
               state="active")
    _tx(conn, lambda: (jobstore.log_step(conn, ctx, job["id"], "change_lane", "director", "done",
                                         f"{LANE_NAMES.get(old, old or 'none')} -> {LANE_NAMES[lane]}"
                                         + (f": {reason}" if reason else ""),
                                         {"from": old, "to": lane, "module_id": mid}),
                       jobstore.save_job(conn, ctx, job),
                       service._log(conn, ctx, est["id"], "director_lane_changed",
                                    {"job_id": job["id"], "from": old, "to": lane, "reason": reason})))
    return _run(conn, ctx, job["id"], reg)


def add_trade(conn, ctx: RequestContext, job_id: int, module_id: str, answers: dict | None = None,
              remove: bool = False, registry=None) -> dict:
    """Add another trade or service to a job's estimate (e.g. pressure washing plus window cleaning, or roofing plus
    flooring), change its answers, or take it off. Everything is priced and approved together."""
    reg = _registry(registry)
    job = jobstore.load_job(conn, ctx, int(job_id))
    if job["state"] in ("done", "cancelled"):
        raise NotEditable(f"job {job['id']} is {job['state']}", job_id=job["id"])
    if job["lane"] is None or job["module_id"] is None:
        raise InvalidInput("pick the job's main service or trade first (module_id)", job_id=job["id"])
    if module_id == job["module_id"]:
        raise InvalidInput("that's the job's main trade; change its answers with est_director_next(answers=...)",
                           module_id=module_id)
    mod = reg.get(module_id)
    est = service.get_estimate(conn, ctx, job["estimate_id"])
    if est["status"] not in service.EDITABLE_STATUSES:
        raise NotEditable(f"the estimate is {est['status']}; make a revision (revise=true) first",
                          estimate_id=est["id"], status=est["status"])
    if answers is not None and not isinstance(answers, dict):
        raise InvalidInput("answers must be an object of question id -> answer")
    summary = ""
    if remove:
        if module_id not in job["trades"]:
            raise NotFound(f"'{module_id}' isn't on this job", module_id=module_id)
        job["trades"].pop(module_id)
        if any(s["module_id"] == module_id for s in est["sections"]):
            service.remove_trade(conn, ctx, est["id"], module_id, est["rev"])
        summary = f"removed {mod.name}"
    else:
        if mod.path not in ("quick_estimate", "both"):
            raise InvalidInput(f"{mod.name} can't be priced from answers yet", module_id=module_id)
        summary = f"updated {mod.name}" if module_id in job["trades"] else f"added {mod.name}"
        job["trades"][module_id] = {**job["trades"].get(module_id, {}), **(answers or {})}
        if job["lane"] == "quick_quote" and mod.category == "construction":
            pb = playbook_for_lane("standard_estimate")
            job.update(lane=pb.lane, playbook_id=pb.id, playbook_version=pb.version)
            summary += " (now a standard estimate, because construction work gets a Reviewer check)"
    job["stage"] = get_playbooks()[job["playbook_id"]].stages[0].id
    job["state"] = "active"
    _tx(conn, lambda: (jobstore.log_step(conn, ctx, job["id"], "add_trade", "director", "done", summary,
                                         {"module_id": module_id, "answers": answers, "remove": remove}),
                       jobstore.save_job(conn, ctx, job)))
    out = _run(conn, ctx, job["id"], reg)
    out.setdefault("notes", []).insert(0, summary[0].upper() + summary[1:] + ".")
    return out


def book_site_visit(conn, ctx: RequestContext, job_id: int, date: str, *, start_time: str | None = None,
                    end_time: str | None = None, notes: str | None = None, customer: dict | None = None,
                    confirm: bool = False, registry=None) -> dict:
    """Book a site visit to measure, as a scheduled job in AI-Prowler (only when the owner turned this on)."""
    import re
    from datetime import date as _date
    reg = _registry(registry)
    if not get_settings(conn, ctx.company_id)["calendar_booking_enabled"]:
        raise InvalidInput("Site-visit booking is turned off. The owner can turn it on with "
                           "est_director_settings_update({\"calendar_booking_enabled\": true}).",
                           setting="calendar_booking_enabled")
    service._require_edit_role(ctx, service.QUICK_ROLES)
    job = jobstore.load_job(conn, ctx, int(job_id))
    if job["state"] in ("done", "cancelled"):
        raise NotEditable(f"job {job['id']} is {job['state']}", job_id=job["id"])
    try:
        day = _date.fromisoformat(str(date))
    except ValueError:
        raise InvalidInput("date must be YYYY-MM-DD", field="date") from None
    for name, t in (("start_time", start_time), ("end_time", end_time)):
        if t and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t.strip()):
            raise InvalidInput(f"{name} must be HH:MM (24-hour), e.g. 09:30", field=name)
    if customer:
        job["customer"].update(bids.clean_customer(customer))
        _tx(conn, lambda: jobstore.save_job(conn, ctx, job))
    cust = job["customer"]
    if not cust.get("customer_id") and not cust.get("name"):
        raise InvalidInput("who is the customer? give at least their name and the address to visit", field="customer")
    when = day.strftime("%A, %B %d").replace(" 0", " ") + (f" at {start_time}" if start_time else "")
    who = cust.get("name") or cust.get("customer_id")
    where = f" at {cust['address']}" if cust.get("address") else ""
    if not confirm:
        raise ConfirmationRequired(
            f"Book a site visit for {who}{where} on {when}? This creates "
            + ("" if cust.get("customer_id") else "a customer and ") + "a scheduled job in AI-Prowler. "
            "Call again with confirm=true once the user says yes.", job_id=job["id"], date=day.isoformat())
    customer_id, created = bids.ensure_customer(cust)
    mod = reg.modules.get(job["module_id"]) if job["module_id"] else None
    updates = {"CustomerID": customer_id, "Customer Name / Company": who, "Street Address": cust.get("address", ""),
               "City": cust.get("city", ""), "Service Type": f"Site visit (estimate{': ' + mod.name if mod else ''})",
               "Service Date": day.isoformat(), "Job Status": "Scheduled", "Quote Amount ($)": "0.00",
               "Service Details / Notes": (f"Measure for Estimator job {job['id']} (estimate {job['estimate_id']}): "
                                           f"{job['request_text']}" + (f" {notes}" if notes else ""))[:1000]}
    if start_time:
        updates["Start Time"] = start_time.strip()
    if end_time:
        updates["End Time"] = end_time.strip()
    text = host.call("create_job", updates=updates)
    visit_id = host.extract_id(text, "JOB")
    job = jobstore.load_job(conn, ctx, job["id"])
    job["customer"]["customer_id"] = customer_id
    _tx(conn, lambda: (jobstore.log_step(conn, ctx, job["id"], "site_visit", "intake", "done",
                                         f"site visit {visit_id} on {day.isoformat()}",
                                         {"visit_job_id": visit_id, "date": day.isoformat(), "start_time": start_time,
                                          **created}),
                       jobstore.save_job(conn, ctx, job),
                       service._log(conn, ctx, job["estimate_id"], "site_visit_booked",
                                    {"job_id": job["id"], "visit_job_id": visit_id, "date": day.isoformat()})))
    return {"ok": True, "job_id": job["id"], "visit_job_id": visit_id, "customer_id": customer_id,
            "date": day.isoformat(), "start_time": start_time, "created": created,
            "say": f"Booked: site visit for {who}{where} on {when} (AI-Prowler job {visit_id}). After the visit, give me "
                   "the measurements (est_director_next with answers) and I'll price it."}


# ------------------------------------------------------------------ engine

def _run(conn, ctx, job_id: int, reg, inputs: dict | None = None, triage_info: dict | None = None) -> dict:
    notes: list[str] = []
    inputs = dict(inputs or {})
    for _ in range(20):   # a playbook has a handful of stages; this only guards against a loop
        job = jobstore.load_job(conn, ctx, job_id)
        if job["lane"] is None:
            _wait(conn, ctx, job, "waiting_on_user", "user", _triage_step(job, reg))
            break
        pb = get_playbooks()[job["playbook_id"]]
        if not pb.available:
            _wait(conn, ctx, job, "waiting_on_feature", "feature", {
                "stage": job["stage"], "agent": pb.stage(job["stage"]).agent,
                "say": f"This is a {LANE_NAMES[job['lane']]} job. The Director can run it start to finish from "
                       f"{pb.available_from}. The estimate is created; until then you can add line items by hand "
                       f"(est_add_line_item) and price them (est_calculate).",
                "tools": ["est_add_line_item", "est_calculate"]})
            break
        if job["module_id"] is None and job["lane"] == "standard_estimate":
            trade = triage(job["request_text"], reg).trade or "this"
            have = sorted(m.id for m in reg.list() if m.category == "construction")
            _wait(conn, ctx, job, "waiting_on_feature", "feature", {
                "stage": job["stage"], "agent": "director",
                "say": f"This is a {trade.replace('_', ' ')} job. I can price these trades from measurements now: "
                       + ", ".join(have) + f". The {trade.replace('_', ' ')} module comes later; the estimate is "
                       "created, so you can add line items by hand (est_add_line_item) and price them (est_calculate), "
                       "or tell me which trade module to use (module_id).",
                "ask": have, "tools": ["est_director_next(job_id, module_id=...)", "est_add_line_item", "est_calculate"]})
            break
        stage = pb.stage(job["stage"])
        handler = _HANDLERS[stage.action]
        try:
            moved = handler(conn, ctx, job, reg, stage, notes=notes, inputs=inputs)
        except EstimatorError as exc:
            # Record what went wrong so the job never shows a stale next step, then report the error.
            failed = jobstore.load_job(conn, ctx, job_id)
            _wait(conn, ctx, failed, "waiting_on_user", "user", {
                "stage": stage.id, "agent": stage.agent, "error": exc.code,
                "say": f"{stage.label} didn't work: {exc.message} Fix that, then ask me to try again.",
                "tools": ["est_director_next(job_id, ...)"]})
            _tx(conn, lambda: jobstore.log_step(conn, ctx, job_id, stage.id, stage.agent, "failed", exc.message[:300]))
            raise
        if not moved:
            break
        nxt = pb.next_stage(stage.id)
        job = jobstore.load_job(conn, ctx, job_id)
        if nxt is None:
            job.update(state="done", waiting_on=None, open_questions=None,
                       next_step={"stage": "done", "say": "This job is finished."})
            _tx(conn, lambda: jobstore.save_job(conn, ctx, job))
            break
        job.update(stage=nxt.id, state="active")
        _tx(conn, lambda: jobstore.save_job(conn, ctx, job))
    job = jobstore.load_job(conn, ctx, job_id)
    out = _result(conn, ctx, job, reg)
    if triage_info:
        out["triage"] = triage_info
    if notes:
        out["notes"] = notes
    return out


def _wait(conn, ctx, job, state, waiting_on, next_step, open_questions=None):
    job.update(state=state, waiting_on=waiting_on, next_step=next_step, open_questions=open_questions)
    _tx(conn, lambda: jobstore.save_job(conn, ctx, job))


def _voice(ctx) -> str:
    return "customer" if ctx.role in CUSTOMER_FACING_ROLES else "estimator"


def _triage_step(job, reg) -> dict:
    tri = triage(job["request_text"], reg)
    return {"stage": "triage", "agent": "director", "say": tri.question, "ask": tri.candidates,
            "tools": ["est_director_next(job_id, module_id=...)"],
            "why": tri.reason}


def _collect_answers(conn, ctx, job, reg, stage, notes, **_):
    mod = reg.get(job["module_id"])
    answers = job["answers"]
    valid = {q.id for q in mod.questions}
    unknown = sorted(set(answers) - valid)
    if unknown:
        for k in unknown:
            answers.pop(k)
        job["answers"] = answers
        notes.append(f"Ignored answers that aren't {mod.name} questions: {', '.join(unknown)}.")
        _tx(conn, lambda: jobstore.save_job(conn, ctx, job))
    missing = [q for q in mod.questions if q.required and q.id not in answers]
    if not missing and mod.required_any and not any(_nonzero(answers.get(q)) for q in mod.required_any):
        missing = [mod.question(q) for q in mod.required_any]
        say = ("Ask the customer what needs doing: " if _voice(ctx) == "customer" else "Give at least one of: ")
        _wait(conn, ctx, job, "waiting_on_user", "user", {
            "stage": stage.id, "agent": stage.agent,
            "say": say + ", ".join(q.label for q in missing) + ".",
            "ask": [q.as_dict() for q in missing], "at_least_one": True,
            "tools": ["est_director_next(job_id, answers={...})"],
            "why": "nothing to price yet"}, open_questions=list(mod.required_any))
        return False
    if not missing:
        try:
            quick.resolve_answers(mod, answers)
        except InvalidInput as exc:
            bad = exc.details.get("field")
            if bad and bad in answers:
                answers.pop(bad)
                job["answers"] = answers
            _wait(conn, ctx, job, "waiting_on_user", "user", {
                "stage": stage.id, "agent": stage.agent, "say": f"That answer didn't work: {exc.message}",
                "ask": [mod.question(bad).as_dict()] if bad and bad in {q.id for q in mod.questions} else [],
                "tools": ["est_director_next(job_id, answers={...})"]},
                open_questions=[bad] if bad else None)
            return False
        if not _check_trades(conn, ctx, job, reg, stage):
            return False
        _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                            "answers complete", {"answers": answers, "trades": job["trades"]}))
        return True
    optional = [q.as_dict() for q in mod.questions if not q.required and q.id not in answers]
    labels = ", ".join(q.label for q in missing)
    if _voice(ctx) == "customer":
        say = f"Ask the customer: {labels}." + (" Optional, if they know: " + ", ".join(
            o["label"] for o in optional) + "." if optional else "")
    else:
        kind = "estimate" if mod.category == "construction" else "quote"
        say = f"{mod.name} {kind} — I need: {labels}." + (
            " Optional (defaults used otherwise): " + ", ".join(o["id"] for o in optional) + "." if optional else "")
    _wait(conn, ctx, job, "waiting_on_user", "user", {
        "stage": stage.id, "agent": stage.agent, "say": say,
        "ask": [q.as_dict() for q in missing], "optional": optional,
        "tools": ["est_director_next(job_id, answers={...})"],
        "why": "these questions have no default"}, open_questions=[q.id for q in missing])
    return False


def _check_trades(conn, ctx, job, reg, stage) -> bool:
    """Every extra trade on the job needs its own answers before pricing."""
    for mid, ans in job["trades"].items():
        mod = reg.get(mid)
        missing = [q for q in mod.questions if q.required and q.id not in ans]
        if not missing and mod.required_any and not any(_nonzero(ans.get(q)) for q in mod.required_any):
            missing = [mod.question(q) for q in mod.required_any]
        problem = None
        if not missing:
            try:
                quick.resolve_answers(mod, ans)
            except InvalidInput as exc:
                problem = exc.message
        if missing or problem:
            say = f"For the {mod.name} part: " + (f"that answer didn't work: {problem}" if problem else
                                                  "I need " + ", ".join(q.label for q in missing) + ".")
            _wait(conn, ctx, job, "waiting_on_user", "user", {
                "stage": stage.id, "agent": stage.agent, "say": say, "module_id": mid,
                "ask": [q.as_dict() for q in missing],
                "tools": ["est_director_add_trade(job_id, module_id, answers={...})"]},
                open_questions=[f"{mid}.{q.id}" for q in missing] or None)
            return False
    return True


def _nonzero(value) -> bool:
    if value is None or value is False:
        return False
    if str(value).strip().lower() in ("", "none", "no", "false"):   # a "none" choice counts as not answered
        return False
    try:
        return Decimal(str(value).replace(",", "").strip()) != 0
    except InvalidOperation:
        return bool(str(value).strip())


def _price_quick(conn, ctx, job, reg, stage, notes, **_):
    est = service.get_estimate(conn, ctx, job["estimate_id"])
    result = quick.answer(conn, ctx, est["id"], job["module_id"], job["answers"], est["rev"], reg)
    notes.extend(result.get("warnings") or [])
    for mid, ans in job["trades"].items():
        result = quick.answer(conn, ctx, est["id"], mid, ans, result["rev"], reg)
        notes.extend(w for w in result.get("warnings") or [] if w not in notes)
    total = result["totals"]["total_cents"]
    _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                        f"priced at {format_cents(total)}",
                                        {"total_cents": total, "warnings": result.get("warnings")}))
    return True


def _uses_samples(est) -> list[str]:
    keys = []
    for sec in est["sections"]:
        for ln in sec["lines"]:
            if ln["calc"].get("sample_price"):
                keys.append(ln["price_key"])
    return keys


def _approve(conn, ctx, job, reg, stage, notes, inputs, **_):
    approve = inputs.pop("approve", False)          # an approval is used once
    confirm_sample_prices = inputs.get("confirm_sample_prices", False)
    est = service.get_estimate(conn, ctx, job["estimate_id"])
    if est["status"] not in service.EDITABLE_STATUSES:
        return True    # already approved (or further along)
    total = (est["totals"] or {}).get("total_cents", 0)
    settings = overrides.effective_settings(conn, ctx.company_id, job["playbook_id"])
    limit = settings["quick_send_limit_cents"]
    one_tap = job["lane"] == "quick_quote" and limit > 0 and total <= limit
    checklist = overrides.checklist_for(conn, ctx.company_id, job["playbook_id"], [job["module_id"], *job["trades"]])
    roles = service.QUICK_ROLES if one_tap else FULL_APPROVE_ROLES
    samples = _uses_samples(est)
    money = format_cents(total)

    if approve:
        if ctx.role not in roles:
            if one_tap:
                msg = f"role '{ctx.role}' can't approve quotes"
            elif job["lane"] == "quick_quote":
                msg = (f"this {money} quote is over the one-tap limit of {format_cents(limit)}; an owner or reviewer"
                       " must approve it")
            else:
                msg = f"an owner or reviewer must approve this {money} estimate"
            raise PermissionDenied(msg, role=ctx.role)
        if checklist and not inputs.get("checklist_done"):
            notes.append("Not approved yet: confirm the checklist first (checklist_done=true): " + "; ".join(checklist) + ".")
        elif samples and not confirm_sample_prices:
            notes.append("Not approved: it still uses sample prices (" + ", ".join(sorted(set(samples)))
                         + "). Set your own prices, or approve again with confirm_sample_prices=true.")
        else:
            service.set_status(conn, ctx, est["id"], est["rev"], "approved", roles=roles)
            _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                                f"approved at {money}" + (" (one tap)" if one_tap else ""),
                                                {"total_cents": total, "one_tap": one_tap,
                                                 "sample_prices_confirmed": bool(samples),
                                                 "checklist_confirmed": checklist or None}))
            return True

    if one_tap:
        say = (f"The quote is {money}. Send this {money} quote? (one tap, once they say yes: approve=true, send=true, confirm=true)"
               if _voice(ctx) == "estimator" else
               f"Tell the customer the price is {money}. If they're happy, approve it (approve=true).")
    elif job["lane"] == "quick_quote":
        say = (f"The estimate is {money}, over the one-tap limit of {format_cents(limit)}. "
               "An owner or reviewer needs to check and approve it.")
    else:
        say = f"The {money} estimate is checked and ready. An owner or reviewer approves it (approve=true)."
    if checklist:
        say += " Before approving, confirm: " + "; ".join(checklist) + " (checklist_done=true)."
    mods_with_options = [m for m in [job["module_id"], *job["trades"]] if m in reg.modules and reg.modules[m].scenarios]
    if mods_with_options and not _scenarios.list_options(conn, ctx, est["id"]):
        say += " Want good/better/best options on the bid? (scenarios=true)"
    if samples:
        say += (" Warning: it uses sample prices, not yours (" + ", ".join(sorted(set(samples)))
                + "). Set your own in the price book, or approve with confirm_sample_prices=true.")
    _wait(conn, ctx, job, "waiting_on_user", "approver" if not one_tap else "user", {
        "stage": stage.id, "agent": stage.agent, "say": say, "total_cents": total,
        "approval": "one_tap" if one_tap else "full", "approver_roles": list(roles),
        "sample_prices": sorted(set(samples)), "checklist": checklist,
        "tools": ["est_director_next(job_id, approve=true)", "est_get_estimate(estimate_id)"],
        "why": "money and anything sent to a customer need a person's OK"})
    return False


def _review(conn, ctx, job, reg, stage, notes, inputs, **_):
    """Reviewer QA. Small jobs are checked automatically; over the review limit a reviewer signs off."""
    reviewed = inputs.pop("reviewed", False)
    est = service.get_estimate(conn, ctx, job["estimate_id"])
    if est["status"] not in service.EDITABLE_STATUSES:
        return True
    qa = validate.validate(conn, ctx, est["id"], registry=reg)
    total = qa["total_cents"]
    money = format_cents(total)
    limit = overrides.effective_settings(conn, ctx.company_id, job["playbook_id"])["review_required_over_cents"]
    problems = [f["message"] for f in qa["findings"] if f["level"] == "warning"]
    reminders = [f["message"] for f in qa["findings"] if f["level"] == "info"]
    if not qa["passed"]:
        _wait(conn, ctx, job, "waiting_on_user", "user", {
            "stage": stage.id, "agent": stage.agent, "error": "review_failed",
            "say": "This can't be approved yet: " + " ".join(f["message"] for f in qa["findings"]
                                                              if f["level"] == "error"),
            "findings": qa["findings"], "tools": ["est_director_next(job_id, answers={...})", "est_validate(estimate_id)"]})
        return False
    needs_person = total > limit
    # An owner or reviewer who approves also signs off the review in the same step.
    signed = reviewed or (needs_person and inputs.get("approve") and ctx.role in REVIEW_ROLES)
    if needs_person and not signed:
        if est["status"] == "draft":
            service.set_status(conn, ctx, est["id"], est["rev"], "in_review", roles=service.QUICK_ROLES)
        say = (f"The {money} estimate is over the review limit of {format_cents(limit)}, so a reviewer checks it. "
               + (f"Things to look at: {' '.join(problems)} " if problems else "No problems found. ")
               + (f"Reminders: {' '.join(reminders)} " if reminders else "")
               + "When it's checked, say reviewed=true (an owner can review and approve together).")
        _wait(conn, ctx, job, "waiting_on_user", "reviewer", {
            "stage": stage.id, "agent": stage.agent, "say": say, "total_cents": total, "findings": qa["findings"],
            "reviewer_roles": list(REVIEW_ROLES),
            "tools": ["est_director_next(job_id, reviewed=true)", "est_director_next(job_id, reviewed=true, approve=true)",
                      "est_validate(estimate_id)", "est_get_estimate(estimate_id)"],
            "why": "bigger estimates get a second look before a price goes out"})
        return False
    if needs_person and ctx.role not in REVIEW_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't sign off a review; an owner or reviewer does", role=ctx.role)
    notes.extend(reminders)
    if problems and not needs_person:
        notes.extend(problems)
    _tx(conn, lambda: jobstore.log_step(
        conn, ctx, job["id"], stage.id, stage.agent, "done",
        (f"reviewed by {ctx.actor}" if needs_person else f"automatic check (under {format_cents(limit)})")
        + f": {qa['warnings']} warning(s)", {"findings": qa["findings"], "reviewer": ctx.actor if needs_person else None}))
    return True


# ------------------------------------------------------------------ full plan takeoff lane

def _job_trades(job) -> list[str]:
    return [m for m in [job["module_id"], *job["trades"]] if m]


def _collect_trades(conn, ctx, job, reg, stage, notes, **_):
    """Which trades are in the bid: the ones the request names, or ask."""
    if not job["module_id"]:
        found = trades_mentioned(job["request_text"], reg)
        enabled = set(list_configs(conn, ctx.company_id, reg)["enabled"])
        off = [t for t in found if t not in enabled]
        found = [t for t in found if t in enabled]
        if off:
            notes.append("Left out (turned off in Agent Manager): " + ", ".join(off) + ".")
        if not found:
            have = sorted(enabled)
            _wait(conn, ctx, job, "waiting_on_user", "user", {
                "stage": stage.id, "agent": stage.agent,
                "say": "Which trades are in this bid? I can run takeoffs for: " + ", ".join(have) + ".",
                "ask": have, "tools": ["est_director_next(job_id, trades=[...])"],
                "why": "the Runner makes one takeoff task per trade"}, open_questions=["trades"])
            return False
        job.update(module_id=found[0], trades={t: job["trades"].get(t, {}) for t in found[1:]})
        _tx(conn, lambda: jobstore.save_job(conn, ctx, job))
    _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                        "trades: " + ", ".join(_job_trades(job)), {"trades": _job_trades(job)}))
    return True


def _read_plans(conn, ctx, job, reg, stage, notes, **_):
    if not any(s["stage"] == stage.id for s in jobstore.steps(conn, job["id"])):
        notes.append("The Plan Engine isn't installed yet, so each trade is measured from the plans by a person or "
                     "by your AI in chat and handed to the Runner (runner_submit_takeoff).")
        _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "skipped",
                                            "Plan Engine not installed; trades measured by hand or in chat"))
    return True


def _run_takeoff(conn, ctx, job, reg, stage, notes, **_):
    """Hand the trades to the Estimate Runner, wait for the takeoffs, then take the approved quantities back."""
    trades = _job_trades(job)
    run = runner.latest_run(conn, ctx, job_id=job["id"])
    if run is None or run["estimate_id"] != job["estimate_id"]:
        st = runner.start_run(conn, ctx, job["estimate_id"], trades, job_id=job["id"], registry=reg)
        notes.extend(st["warnings"])
        _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "running",
                                            f"run {st['run']['id']} started: " + ", ".join(trades),
                                            {"run_id": st["run"]["id"]}))
    else:
        have = {t["module_id"] for t in runner.run_status(conn, ctx, run_id=run["id"])["tasks"]}
        missing = [t for t in trades if t not in have]
        st = runner.add_trades(conn, ctx, run["id"], missing, registry=reg) if missing else \
            runner.run_status(conn, ctx, run_id=run["id"])
    tasks = st["tasks"]
    if st["run"]["state"] in runner.OPEN_RUN_STATES:
        measure = [t["module_id"] for t in tasks if t["state"] == "running"]
        check = [t["module_id"] for t in tasks if t["state"] == "needs_review"]
        later = [t["module_id"] for t in tasks if t["state"] == "queued"]
        stuck = [t["module_id"] for t in tasks if t["state"] in ("failed", "blocked")]
        parts = []
        if measure:
            parts.append("Measure and submit: " + ", ".join(measure) + ".")
        if check:
            parts.append("Check and approve the quantities for: " + ", ".join(check) + ".")
        if later:
            parts.append("Waiting on framing first: " + ", ".join(later) + ".")
        if stuck:
            parts.append("Couldn't be done (retry if you can): " + ", ".join(stuck) + ".")
        _wait(conn, ctx, job, "waiting_on_user", "takeoff" if measure else "reviewer", {
            "stage": stage.id, "agent": stage.agent, "run_id": st["run"]["id"],
            "say": f"Takeoff run {st['run']['id']} ({st['run']['progress']}% done). " + " ".join(parts),
            "tasks": [{k: t[k] for k in ("task_id", "module_id", "state", "next")} for t in tasks],
            "tools": ["runner_submit_takeoff(task_id, answers={...})", "runner_review_task(task_id, approve=true)",
                      "runner_status(run_id)", "est_director_next(job_id)"],
            "why": "only quantities a person approved are priced"})
        return False
    done = [t for t in tasks if t["state"] == "completed"]
    left = [t["module_id"] for t in tasks if t["state"] != "completed"]
    if not done:
        _wait(conn, ctx, job, "waiting_on_user", "user", {
            "stage": stage.id, "agent": stage.agent, "run_id": st["run"]["id"], "error": "takeoff_failed",
            "say": "None of the trades could be measured: " + "; ".join(
                f"{t['module_id']}: {t['error']}" for t in tasks) + ". Retry a trade, or add line items by hand.",
            "tools": ["runner_retry_task(task_id)", "est_add_line_item"]})
        return False
    job.update(module_id=done[0]["module_id"], answers=done[0]["answers"],
               trades={t["module_id"]: t["answers"] for t in done[1:]})
    if left:
        notes.append("Not in this estimate (couldn't be measured): " + ", ".join(left) + ".")
    _tx(conn, lambda: (jobstore.save_job(conn, ctx, job),
                       jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                         f"run {st['run']['id']} {st['run']['state']}: "
                                         + ", ".join(t["module_id"] for t in done) + " approved",
                                         {"run_id": st["run"]["id"], "left_out": left})))
    return True


def _not_built(when: str):
    def handler(conn, ctx, job, reg, stage, notes, **_):
        est = service.get_estimate(conn, ctx, job["estimate_id"])
        total = (est["totals"] or {}).get("total_cents", 0)
        _wait(conn, ctx, job, "waiting_on_feature", "feature", {
            "stage": stage.id, "agent": stage.agent,
            "say": f"Approved at {format_cents(total)}. {stage.label} arrives in {when}; for now you can give the "
                   "customer the total and line items from est_get_estimate.",
            "tools": ["est_get_estimate(estimate_id)"]})
        return False
    return handler


def _write_bid(conn, ctx, job, reg, stage, notes, inputs, **_):
    bid = bids.latest_for_estimate(conn, ctx, job["estimate_id"])
    if ctx.role not in service.QUICK_ROLES:
        _wait(conn, ctx, job, "waiting_on_user", "staff", {
            "stage": stage.id, "agent": stage.agent,
            "say": "Approved. An owner, estimator or office person can now make and send the quote.",
            "tools": ["est_director_next(job_id, send=true, confirm=true)"]})
        return False
    if bid is None:
        from estimator.agents import queue as agent_queue
        draft = agent_queue.latest_draft(conn, ctx, job["estimate_id"])
        scope = {k: draft.get(k) for k in ("scope_text", "inclusions", "exclusions")} if draft else {}
        made = bids.generate(conn, ctx, job["estimate_id"], customer=job["customer"], registry=reg,
                             **{k: v for k, v in scope.items() if v})
        notes.extend(made.get("warnings") or [])
        if draft:
            _tx(conn, lambda: agent_queue.mark_applied(conn, draft["task_id"]))
            notes.append("The scope on this quote was written by the Bid Writer agent: check it in the preview "
                         "before sending.")
        _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                            f"bid {made['number']} made", {"bid_id": made["id"]}))
        bid = bids._load(conn, ctx, made["id"])
    if bid["status"] != "draft":
        return True                                   # already sent
    to = (inputs.get("send_to") or job["customer"].get("email") or "").strip()
    if inputs.pop("send", False):
        if not to:
            notes.append("Not sent yet: I need the customer's email address (send_to or customer.email).")
        else:
            sent = bids.send(conn, ctx, bid["id"], to=to, confirm=True)
            notes.extend(sent.get("warnings") or [])
            _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                                f"sent {bid['number']} to {to}", {"bid_id": bid["id"], "to": to}))
            return True
    money = format_cents(bid["total_cents"])
    files = "PDF and HTML" if bid["pdf_path"] else "HTML"
    if to:
        say = f"Quote {bid['number']} ({money}) is ready as {files}. Send it to {to}? (send=true, confirm=true once they say yes)"
    else:
        say = (f"Quote {bid['number']} ({money}) is ready as {files}. What's the customer's email so I can send "
               "it? (customer={email: ...}, then send=true, confirm=true)")
    _wait(conn, ctx, job, "waiting_on_user", "user", {
        "stage": stage.id, "agent": stage.agent, "say": say, "bid_id": bid["id"], "bid_number": bid["number"],
        "pdf_path": bid["pdf_path"], "html_path": bid["html_path"], "send_to": to or None,
        "tools": ["est_director_next(job_id, send=true, confirm=true)", "bid_preview(bid_id)"],
        "why": "sending reaches the customer, so a person says when"})
    return False


def _follow_up(conn, ctx, job, reg, stage, notes, inputs, **_):
    bid = bids.latest_for_estimate(conn, ctx, job["estimate_id"])
    if bid is None:
        return True
    outcome = inputs.pop("outcome", None)
    convert = inputs.pop("convert", False)
    if outcome == "lost":
        bids.set_status(conn, ctx, bid["id"], "lost")
        _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done", "customer said no"))
        return True
    if outcome == "won" and bid["status"] not in ("won",):
        bids.set_status(conn, ctx, bid["id"], "won")
        bid = bids._load(conn, ctx, bid["id"])
    if bid["status"] == "won":
        if bid["job_id"]:
            return True
        if convert:
            done = bids.convert_to_job(conn, ctx, bid["id"], confirm=True, customer=job["customer"],
                                       service_date=inputs.get("service_date"), registry=reg)
            _tx(conn, lambda: jobstore.log_step(conn, ctx, job["id"], stage.id, stage.agent, "done",
                                                f"converted to job {done['job_id']}", done.get("created")))
            notes.append(f"Created in AI-Prowler: {', '.join(f'{k} {v}' for k, v in done['created'].items() if v)}.")
            return True
        _wait(conn, ctx, job, "waiting_on_user", "user", {
            "stage": stage.id, "agent": stage.agent,
            "say": f"The customer accepted {bid['number']} ({format_cents(bid['total_cents'])}). Make it a job in "
                   "AI-Prowler? (convert=true, confirm=true once they say yes, optionally service_date=YYYY-MM-DD)",
            "tools": ["est_director_next(job_id, convert=true, confirm=true, service_date=...)"],
            "why": "creating customers, quotes and jobs needs a person's OK"})
        return False
    settings = get_settings(conn, ctx.company_id)
    sent_on = local_date_text(bid["sent_at"])
    follow = ""
    if sent_on:
        from datetime import date, timedelta
        follow = (date.fromisoformat(sent_on) + timedelta(days=settings["follow_up_days"])).isoformat()
    _wait(conn, ctx, job, "waiting_on_customer", "customer", {
        "stage": stage.id, "agent": stage.agent,
        "say": f"Quote {bid['number']} was sent to {bid['sent_to']} on {sent_on}. "
               + (f"Follow up on {follow} if there's no answer. " if follow else "")
               + "When the customer answers, tell me: outcome=won (convert=true, confirm=true to make it a job) or outcome=lost.",
        "follow_up_on": follow or None, "bid_id": bid["id"],
        "tools": ["est_director_next(job_id, outcome='won', convert=true, confirm=true)", "est_director_next(job_id, outcome='lost')"]})
    return False


_HANDLERS = {
    "collect_answers": _collect_answers,
    "price_quick": _price_quick,
    "approve": _approve,
    "write_bid": lambda *a, **k: _write_bid(*a, **k),
    "follow_up": lambda *a, **k: _follow_up(*a, **k),
    "collect_job": _collect_answers,
    "price": _price_quick,
    "review": lambda *a, **k: _review(*a, **k),
    "collect_trades": _collect_trades,
    "read_plans": _read_plans,
    "run_takeoff": _run_takeoff,
}


def _result(conn, ctx, job, reg) -> dict:
    est = service.get_estimate(conn, ctx, job["estimate_id"]) if job["estimate_id"] else None
    return {
        "ok": True,
        "job": {k: job[k] for k in ("id", "rev", "lane", "module_id", "playbook_id", "stage", "state", "waiting_on",
                                    "estimate_id", "answers", "trades", "open_questions", "assigned_to",
                                    "request_text")},
        "next_step": job["next_step"],
        "estimate": {"id": est["id"], "rev": est["rev"], "status": est["status"],
                     "total_cents": (est["totals"] or {}).get("total_cents", 0)} if est else None,
    }

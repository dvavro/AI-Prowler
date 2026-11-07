"""Estimator MCP tools.

Thin wrappers over estimator.estimating: each opens estimator.db, calls the
service layer with the caller's RequestContext and returns a JSON string.
Errors come back as {"ok": false, "error": <code>, "message": ...} so the AI
can explain them and retry (for example re-read after stale_revision).

Money is integer cents. Every change needs the estimate's current `rev`
(from est_get_estimate or the previous change), so two chats or agents can't
silently overwrite each other.

To expose these tools in AI-Prowler, ai_prowler_mcp.py calls register(mcp)
once after the FastMCP server is created.
"""
from __future__ import annotations

import json
from contextlib import closing

from estimator.context import RequestContext, personal_context
from estimator.database import open_database
from estimator.errors import EstimatorError, InvalidInput, PermissionDenied
from estimator.bids import service as bids
from estimator.director import briefing as director_briefing
from estimator.director import engine as director
from estimator.director import overrides as director_overrides
from estimator.director import settings as director_settings
from estimator.director import watch as director_watch
from estimator.estimating import quick, scenarios, service, setup, validate
from estimator import agent_manager
from estimator.runner import runner
from estimator.agents import queue as agent_queue
from estimator.agents import roles as agent_roles
from estimator.modules import get_registry
from estimator.pricing import price_book
from estimator.pricing import importer as price_import
from estimator.learning import history
from estimator import data_move, exports, practice, team

# Server mode will replace this with the API key / signed-in user's context.
_context_provider = personal_context


def set_context_provider(fn) -> None:
    global _context_provider
    _context_provider = fn


def _ctx() -> RequestContext:
    return _context_provider()


def _run(fn, *args, **kwargs) -> str:
    try:
        with closing(open_database()) as conn:
            result = fn(conn, *args, **kwargs)
    except EstimatorError as exc:
        return json.dumps(exc.as_dict(), default=str)
    except Exception as exc:  # never crash the MCP server; report it
        return json.dumps({"ok": False, "error": "internal_error", "message": f"{type(exc).__name__}: {exc}"})
    return json.dumps(result, default=str)


def _obj(value, name: str) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value) if value.strip() else {}
        except json.JSONDecodeError:
            raise InvalidInput(f"{name} must be a JSON object") from None
    if not isinstance(value, dict):
        raise InvalidInput(f"{name} must be an object")
    return value


def est_list_modules(category: str = "") -> str:
    """List the Estimator's trade and service modules (id, name, category, quick-estimate or plan takeoff).

    category: optional filter, "service" or "construction".
    """
    reg = get_registry()
    mods = [m.summary() for m in reg.list() if not category or m.category == category]
    return json.dumps({"ok": True, "count": len(mods), "modules": mods,
                       "load_errors": reg.errors})


def est_create_estimate(title: str = "", customer_id: str = "", address: str = "", due_date: str = "") -> str:
    """Create a new draft estimate. Returns the estimate with its id and rev (needed for later changes)."""
    return _run(lambda c: service.create_estimate(c, _ctx(), title, customer_id=customer_id or None,
                                                  address=address or None, due_date=due_date or None))


def est_get_estimate(estimate_id: int) -> str:
    """Get an estimate: status, rev, trade sections, line items with full price breakdown, and totals (cents)."""
    return _run(lambda c: service.get_estimate(c, _ctx(), int(estimate_id)))


def est_list_estimates(status: str = "", limit: int = 50) -> str:
    """List estimates, newest first. status: optional filter (draft, in_review, approved, sent, won, lost…)."""
    return _run(lambda c: service.list_estimates(c, _ctx(), status or None, limit))


def est_add_line_item(estimate_id: int, rev: int, kind: str, description: str, quantity: str, unit: str,
                      unit_cost_cents: int | None = None, price_key: str = "", waste_pct: str = "0") -> str:
    """Add a hand-entered line item to an estimate's custom section.

    kind: material, labor, equipment, sub or other. quantity and waste_pct are numbers as text
    ("12.5", "0.10" = 10%). Give unit_cost_cents (integer cents) or a price_key from the price book.
    rev: the estimate's current rev.
    """
    return _run(lambda c: service.add_line_item(
        c, _ctx(), int(estimate_id), rev, kind=kind, description=description, quantity=quantity, unit=unit,
        unit_cost_cents=unit_cost_cents, price_key=price_key or None, waste_pct=waste_pct))


def est_calculate(estimate_id: int, rev: int) -> str:
    """Re-run the pricing stack for an estimate (after prices or markups changed). Returns the new totals."""
    return _run(lambda c: service.calculate(c, _ctx(), int(estimate_id), rev))


def est_quick_questions(module_id: str) -> str:
    """Get the questions to ask for a quick estimate (e.g. pressure_washing, house_cleaning).

    Ask the customer or user these, then call est_quick_answer with the answers.
    """
    try:
        return json.dumps(quick.questions(module_id), default=str)
    except EstimatorError as exc:
        return json.dumps(exc.as_dict(), default=str)


def est_quick_answer(estimate_id: int, module_id: str, answers: dict | str, rev: int) -> str:
    """Price a quick estimate from answers (question id -> answer) and put the lines on the estimate.

    Booleans as true/false, choices by their value (e.g. "heavy"), numbers as numbers.
    Answering again replaces that module's lines. Watch "warnings": sample prices are placeholders.
    """
    def go(c):
        return quick.answer(c, _ctx(), int(estimate_id), module_id, _obj(answers, "answers"), rev)
    return _run(go)


def _opt_obj(value, name: str) -> dict | None:
    if value is None or value == "":
        return None
    return _obj(value, name)


# ---------------------------------------------------------------- Estimating Director

def _list(value, name: str) -> list | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        v = value.strip()
        if v.startswith("["):
            try:
                value = json.loads(v)
            except ValueError:
                raise InvalidInput(f"{name} must be a list", field=name) from None
        else:
            value = [x.strip() for x in v.split(",") if x.strip()]
    if not isinstance(value, list):
        raise InvalidInput(f"{name} must be a list", field=name)
    return value


def est_director_start(request: str, customer_id: str = "", address: str = "", module_id: str = "",
                       has_plans: bool = False, answers: dict | str | None = None, due_date: str = "",
                       customer: dict | str | None = None) -> str:
    """START HERE for any new estimate or quote. The Estimating Director takes a plain-language request
    ("customer wants their driveway pressure washed", "bid the roof on the Smith house", "pour a 400 sq ft patio"),
    picks the lane (quick quote for services; standard estimate for one construction trade from measurements;
    full plan takeoff with has_plans=true, where the Estimate Runner makes one takeoff task per trade), creates the
    estimate and job, and returns next_step:
    what to ask, what to say and which tool to call next. Pass any answers you already have.
    customer: optional {name, email, phone, address, city, state, zip} — needed later to send the quote.
    Follow next_step.say and call est_director_next with what the user supplies.
    """
    def go(c):
        return director.start(c, _ctx(), request, customer_id=customer_id or None, address=address or None,
                              module_id=module_id or None, has_plans=bool(has_plans),
                              answers=_opt_obj(answers, "answers"), due_date=due_date or None,
                              customer=_opt_obj(customer, "customer"))
    return _run(go)


def est_director_next(job_id: int, answers: dict | str | None = None, module_id: str = "", approve: bool = False,
                      confirm_sample_prices: bool = False, rev: int | None = None,
                      customer: dict | str | None = None, send: bool = False, send_to: str = "",
                      outcome: str = "", convert: bool = False, service_date: str = "",
                      revise: bool = False, change_summary: str = "", reprice: bool = False,
                      reviewed: bool = False, scenarios: bool = False, choose_scenario: str = "",
                      scenario_module: str = "", checklist_done: bool = False,
                      trades: list | str | None = None) -> str:
    """Continue a Director job with what it asked for:
    answers / module_id; approve=true at the approval checkpoint (only when the user clearly said yes;
    confirm_sample_prices=true only if they knowingly accept sample prices); customer={name, email, ...};
    send=true (optionally send_to) to email the quote — only after the user says send;
    outcome='won' or 'lost' when the customer answers; convert=true (optional service_date YYYY-MM-DD) to make
    a won quote an AI-Prowler job. approve=true and send=true can go together for a one-tap quote.
    revise=true (with change_summary) when the customer wants changes to an approved or sent quote: makes a new
    version and goes back to the questions. reprice=true re-prices a not-yet-approved quote after price changes.
    reviewed=true when an owner or reviewer has checked a standard estimate over the review limit (can go with
    approve=true). scenarios=true prices good/better/best options (they go on the bid); choose_scenario=<id> switches
    the quote to that option (scenario_module when several trades have options). checklist_done=true when the
    person confirms the company's approval checklist. trades=["framing", "drywall", ...] says which trades are in a
    plan takeoff job (full_takeoff lane). Returns the next step.
    """
    def go(c):
        return director.next_step(c, _ctx(), int(job_id), answers=_opt_obj(answers, "answers"),
                                  module_id=module_id or None, approve=bool(approve),
                                  confirm_sample_prices=bool(confirm_sample_prices), rev=rev,
                                  customer=_opt_obj(customer, "customer"), send=bool(send),
                                  send_to=send_to or None, outcome=outcome or None, convert=bool(convert),
                                  service_date=service_date or None, revise=bool(revise),
                                  change_summary=change_summary or None, reprice=bool(reprice),
                                  reviewed=bool(reviewed), scenarios=bool(scenarios),
                                  choose_scenario=choose_scenario or None, scenario_module=scenario_module or None,
                                  checklist_done=bool(checklist_done), trades=_list(trades, "trades"))
    return _run(go)


def est_director_change_lane(job_id: int, lane: str, module_id: str = "", reason: str = "") -> str:
    """Move a Director job to another lane, keeping its estimate, answers and customer: quick_quote (one-tap
    service quote) or standard_estimate (measurements plus a Reviewer check by job size). Use it when a quick quote
    turns out bigger than expected, or to pick the trade module for a standard job (module_id)."""
    return _run(lambda c: director.change_lane(c, _ctx(), int(job_id), lane, module_id=module_id or None,
                                               reason=reason or None))


def est_director_add_trade(job_id: int, module_id: str, answers: dict | str | None = None,
                           remove: bool = False) -> str:
    """Add another service or trade to a Director job so it's priced, approved and bid together (e.g. pressure washing
    plus window cleaning, or roofing plus flooring). Call again to change its answers; remove=true takes it off.
    Adding a construction trade to a quick quote makes it a standard estimate (with a Reviewer check)."""
    return _run(lambda c: director.add_trade(c, _ctx(), int(job_id), module_id, _opt_obj(answers, "answers"),
                                             remove=bool(remove)))


def est_director_book_site_visit(job_id: int, date: str, start_time: str = "", end_time: str = "", notes: str = "",
                                 customer: dict | str | None = None, confirm: bool = False) -> str:
    """Book a site visit to measure, as a scheduled job in AI-Prowler (date YYYY-MM-DD, times HH:MM). Only works when
    the owner turned on calendar_booking_enabled (off by default). Without confirm=true it returns
    needs_confirmation: ask the user, then call again."""
    return _run(lambda c: director.book_site_visit(c, _ctx(), int(job_id), date, start_time=start_time or None,
                                                   end_time=end_time or None, notes=notes or None,
                                                   customer=_opt_obj(customer, "customer"), confirm=bool(confirm)))


def est_scenarios(estimate_id: int, module_id: str = "", options: list | str | None = None) -> str:
    """Price good/better/best options for a trade on the estimate (roofing, flooring, concrete, window cleaning and
    pressure washing have built-in ones), or your own: options=[{id, label, answers}, ...] (2 to 4). Shows each
    option's total job price; changes nothing on the estimate. The options are shown on the next bid."""
    def go(c):
        opts = options
        if isinstance(opts, str):
            opts = json.loads(opts) if opts.strip() else None
        return scenarios.price_options(c, _ctx(), int(estimate_id), module_id or None, opts)
    return _run(go)


def est_choose_scenario(estimate_id: int, option_id: str, rev: int, module_id: str = "") -> str:
    """Switch an estimate to one of its priced options (re-prices that trade). The estimate must not be approved yet."""
    return _run(lambda c: scenarios.choose_option(c, _ctx(), int(estimate_id), option_id, rev, module_id or None))


def est_playbook_update(playbook_id: str, changes: dict | str, reset: bool = False) -> str:
    """Change how a Director lane works for this company (owner only; confirm with the user first):
    review_required_over_cents (standard_estimate), quick_send_limit_cents (quick_quote), and checklist, things to
    confirm before approval: {"*": ["..."], "roofing": ["Site photo taken"]}. A value of null removes it; reset=true
    clears all changes."""
    return _run(lambda c: director_overrides.update_overrides(c, _ctx(), playbook_id, _obj(changes, "changes"),
                                                              reset=bool(reset)))


def est_validate(estimate_id: int) -> str:
    """Reviewer QA checks on an estimate: errors that block approval, warnings to look at (sample prices, unit
    costs far from normal, margin under 10%, $0 lines) and reminders (minimum charge, trade notes such as
    hot-weather pours). Changes nothing."""
    return _run(lambda c: validate.validate(c, _ctx(), int(estimate_id)))


def est_job_status(job_id: int) -> str:
    """Where a Director job stands: lane, stage, who it's waiting on, open questions, total, steps so far."""
    return _run(lambda c: director.status(c, _ctx(), int(job_id)))


def est_jobs_board(mine: bool = False, include_done: bool = False) -> str:
    """All open Director jobs grouped by lane and stage. mine=true for jobs assigned to the current user."""
    return _run(lambda c: director.board(c, _ctx(), mine=bool(mine), include_done=bool(include_done)))


def est_director_settings_get() -> str:
    """Director settings: quick-send (one-tap) limit in cents (default 10000 = $100), review limit for standard
    estimates (review_required_over_cents, default 50000 = $500; 0 = review everything), the watcher
    (watcher_enabled, watch_interval_minutes 15, auto_expire_bids, due_soon_days 2, briefing_email), calendar site-visit booking
    (default off), customer-facing intake (off), follow-up days, review reminder days, daily briefing."""
    return _run(lambda c: {"ok": True, "settings": director_settings.get_settings(c, _ctx().company_id)})


def est_director_settings_update(changes: dict | str) -> str:
    """Change Director settings (owner only), e.g. {"quick_send_limit_cents": 25000, "calendar_booking_enabled": true}.
    Confirm with the user before changing anything."""
    return _run(lambda c: director_settings.update_settings(c, _ctx(), _obj(changes, "changes")))


def est_playbook_list() -> str:
    """The Director's playbooks: the steps of each lane, which agent does each, the approval checkpoints, and this
    company's changes (limits, approval checklist)."""
    return _run(lambda c: {"ok": True, "playbooks": director_overrides.list_with_overrides(c, _ctx().company_id)})


# ---------------------------------------------------------------- Setup wizard

def est_setup_status() -> str:
    """Setup wizard progress: each step's status, the next step, and whether sample prices are still in use."""
    return _run(lambda c: setup.setup_status(c, _ctx()))


def est_setup_step(step: str, data: dict | str | None = None, status: str = "done") -> str:
    """Save one setup step (owner only). Steps: company_profile {name, address, phone, license_no},
    services {modules: [...]}, tax {tax_pct, taxable_kinds, tax_base}, labor_rates {prices: {key: "dollars"}},
    markups {overhead_pct, profit_pct, labor_burden_pct, minimum_charge}, price_book_review {prices: {key: "dollars"},
    keep_samples}, bid_template, ai_check, sample_quote. Percentages are fractions ("0.10" = 10%).
    status: done or skipped. Confirm money changes with the user first."""
    return _run(lambda c: setup.setup_step(c, _ctx(), step, _opt_obj(data, "data"), status))


# ---------------------------------------------------------------- Bids

def bid_generate(estimate_id: int, customer: dict | str | None = None, scope_text: str = "", inclusions: str = "",
                 exclusions: str = "", terms: str = "", valid_days: int = 0, price_detail: str = "") -> str:
    """Make a bid (HTML, plus PDF when Edge/Chrome is available) from an APPROVED estimate. Freezes the prices.
    Doesn't send anything. Customers see line prices and the total, never costs or margins. price_detail: "lines"
    (every line priced) or "trade_totals" (one price per trade, scope listed); the default is the bid template's."""
    return _run(lambda c: bids.generate(c, _ctx(), int(estimate_id), customer=_opt_obj(customer, "customer"),
                                        scope_text=scope_text or None, inclusions=inclusions or None,
                                        exclusions=exclusions or None, terms=terms or None,
                                        valid_days=int(valid_days) or None, price_detail=price_detail or None))


def bid_preview(bid_id: int) -> str:
    """A bid's text version, lines, totals and file paths, to show the user before sending."""
    return _run(lambda c: bids.preview(c, _ctx(), int(bid_id)))


def bid_send(bid_id: int, to: str = "", confirm: bool = False, message: str = "") -> str:
    """Email a bid to the customer through AI-Prowler's email (PDF attached when allowed, quote in the body).
    Without confirm=true it returns needs_confirmation with what would be sent: ask the user, then call again."""
    return _run(lambda c: bids.send(c, _ctx(), int(bid_id), to=to or None, confirm=bool(confirm),
                                    message=message or None))


def bid_set_status(bid_id: int, status: str) -> str:
    """Mark a bid viewed, won, lost, expired or void. The estimate's status follows."""
    return _run(lambda c: bids.set_status(c, _ctx(), int(bid_id), status))


def bid_convert_to_job(bid_id: int, confirm: bool = False, customer: dict | str | None = None,
                       service_date: str = "") -> str:
    """Turn a won (or accepted) bid into AI-Prowler records: a customer (if new), an Approved quote and a job.
    Without confirm=true it returns needs_confirmation: ask the user first."""
    return _run(lambda c: bids.convert_to_job(c, _ctx(), int(bid_id), confirm=bool(confirm),
                                              customer=_opt_obj(customer, "customer"),
                                              service_date=service_date or None))


def bid_list(status: str = "", estimate_id: int = 0) -> str:
    """List bids, newest first; filter by status (draft, sent, viewed, won, lost, expired, void) or estimate."""
    return _run(lambda c: bids.list_bids(c, _ctx(), status or None, int(estimate_id) or None))


def est_followups_due(mine: bool = False) -> str:
    """Quotes that need a follow-up today (sent and past the follow-up days), quotes about to expire, and jobs that
    haven't moved in a while. mine=true for the current user's jobs only."""
    return _run(lambda c: director_briefing.followups_due(c, _ctx(), mine=bool(mine)))


def est_director_inbox(unread_only: bool = True, mark_read: bool = False, limit: int = 50) -> str:
    """What the Director noticed on its own: follow-ups due, quotes expiring or expired, jobs waiting on a reviewer
    or approval too long, jobs that haven't moved, jobs near or past their due date, and the daily briefing.
    mark_read=true marks the ones shown as read."""
    return _run(lambda c: director_watch.inbox(c, _ctx(), bool(unread_only), bool(mark_read), int(limit)))


def est_director_watch_now() -> str:
    """Run the Director's check right now (it also runs on its own every watch_interval_minutes while AI-Prowler is
    open). Never sends anything to customers; may mark overdue quotes expired (setting auto_expire_bids)."""
    return _run(lambda c: director_watch.tick(c, _ctx()))


def est_director_watch_status() -> str:
    """Is the Director checking jobs on its own: on/off, how often, the last run and what it found, the briefing
    time and channel, unread notices."""
    return _run(lambda c: director_watch.status(c, _ctx()))


def est_director_briefing(mine: bool = False) -> str:
    """Today's Estimator briefing: quotes sent, won and lost, approvals waiting, quotes ready to send, follow-ups
    due, quotes expiring, jobs out with customers. Show the 'text' to the user."""
    return _run(lambda c: director_briefing.briefing(c, _ctx(), mine=bool(mine)))


# ---------------------------------------------------------------- Price book and revisions

def pricebook_get(module_id: str = "", samples_only: bool = False) -> str:
    """The company's prices (cost per unit, in cents), marked "yours" or "sample". Filter by module_id (e.g.
    pressure_washing) or samples_only=true to see which prices still need setting."""
    return _run(lambda c: price_book.list_prices(c, _ctx().company_id, module_id or None, bool(samples_only)))


def pricebook_update(prices: dict | str, confirm: bool = False, effective_date: str = "") -> str:
    """Set your own costs: {"price_key": "dollars"}, e.g. {"pw_driveway_sqft": "0.18", "hc_labor_hr": "45"}.
    Without confirm=true it returns needs_confirmation listing old -> new: show the user, then call again.
    Bids already made keep their prices; use est_director_next(reprice=true) to re-price an open quote."""
    return _run(lambda c: price_book.update_prices(c, _ctx(), _obj(prices, "prices"), confirm=bool(confirm),
                                                   effective_date=effective_date or None))


def pricebook_import(file_path: str = "", csv_text: str = "", mapping: dict | str | None = None, sheet: str = "",
                     effective_date: str = "", add_new: bool = False, confirm: bool = False) -> str:
    """Import a supplier's price list into the price book: file_path (a .csv or .xlsx on this PC) or csv_text
    (pasted CSV). Columns are found by name (item code / price key, unit price / cost, description, unit, kind,
    supplier) or by mapping, e.g. {"cost": "Net Price", "description": "Item"}. Rows update existing prices by key or
    description; add_new=true adds unmatched rows as new prices (they need a unit). Rows with a different unit are
    skipped, never converted. Without confirm=true it returns needs_confirmation with the changes: show the user."""
    return _run(lambda c: price_import.import_prices(
        c, _ctx(), file_path=file_path or None, csv_text=csv_text or None,
        mapping=_obj(mapping, "mapping") if mapping else None, sheet=sheet or None,
        effective_date=effective_date or None, add_new=bool(add_new), confirm=bool(confirm)))


def est_record_actuals(estimate_id: int, actuals: list | str, replace: bool = False, note: str = "") -> str:
    """After a sold job is done, record what it really cost (dollars). Items: {"line_id": 12, "cost": "480", "quantity":
    "1900", "hours": "6"} for one line, {"price_key": "...", "cost": "..."}, {"kind": "labor", "cost": "2200", "hours":
    "40"} for all of one kind, or {"total": "9800"} for the whole job. replace=true clears earlier records. The estimate
    itself never changes; est_compare_history uses these to show where prices run high or low."""
    def go(c):
        items = json.loads(actuals) if isinstance(actuals, str) and actuals.strip() else actuals
        if isinstance(items, dict):
            items = [items]
        return history.record_actuals(c, _ctx(), int(estimate_id), items, replace=bool(replace), note=note)
    return _run(go)


def est_compare_history(estimate_id: int = 0, price_key: str = "", module_id: str = "") -> str:
    """Compare unit costs with past estimates and with what jobs really cost (from est_record_actuals). With
    estimate_id: each line against your usual unit cost and real job costs, flagging lines 25% off. With price_key: that
    price's history. Neither: every price with job costs, biggest gaps first, plus suggested pricebook_update calls when
    two or more jobs show your price is 10% or more off. Changes nothing."""
    return _run(lambda c: history.compare_history(c, _ctx(), int(estimate_id) or None, price_key or None,
                                                  module_id or None))


def est_export(estimate_id: int = 0, status: str = "", format: str = "csv") -> str:  # noqa: A002 - tool argument name
    """Export to a CSV or Excel (format="xlsx") file in the Estimator's exports folder. With estimate_id: its line items
    (trade, kind, quantity, unit cost, cost, price) and totals. Without: a list of estimates (optionally one status,
    e.g. "won"). Returns the file path for send_file or get_file_download_url."""
    return _run(lambda c: exports.export(c, _ctx(), int(estimate_id) or None, status or None, format))


def est_assign(user_id: str, estimate_id: int = 0, job_id: int = 0, note: str = "") -> str:
    """Assign an estimate (and its Director job) to a person by their sign-in name, e.g. "maria"; they get a notice in
    their inbox. user_id="" clears the assignment. Owner, estimator or office."""
    return _run(lambda c: team.assign(c, _ctx(), user_id, estimate_id=int(estimate_id) or None,
                                      job_id=int(job_id) or None, note=note))


def est_my_work(user_id: str = "") -> str:
    """Open estimates and Director jobs assigned to me (or, for the owner or office, to user_id), with new notices."""
    return _run(lambda c: team.my_work(c, _ctx(), user_id or None))


def est_sample_project(action: str = "create", confirm: bool = False) -> str:
    """The practice project: action="create" makes "Practice: Garcia house" (a roof and a house wash, priced from your
    price book) to try things on; action="delete" removes it and anything made from it (needs confirm=true). Practice
    estimates stay out of your history comparisons and "my work"."""
    return _run(lambda c: practice.run(c, _ctx(), action, bool(confirm)))


def est_data_export(include_practice: bool = False) -> str:
    """Pack all of this company's Estimator data (estimates, quotes and their PDFs, prices, settings, Director jobs,
    job costs) into one .zip in the exports folder, to move to AI-Prowler Server or another PC. Owner only."""
    return _run(lambda c: data_move.export_data(c, _ctx(), bool(include_practice)))


def est_data_import(file_path: str, confirm: bool = False) -> str:
    """Load a .zip made by est_data_export into this company. Every estimate gets a new number here; quote numbers stay.
    A company that already has estimates keeps its own settings and prices. Without confirm=true it shows what would
    come in. Owner only."""
    return _run(lambda c: data_move.import_data(c, _ctx(), file_path, bool(confirm)))


def est_create_revision(estimate_id: int, change_summary: str) -> str:
    """Make a new editable version (v2, v3…) of an approved, sent, lost or expired estimate. The original stays
    unchanged and its open bids are voided."""
    return _run(lambda c: service.create_revision(c, _ctx(), int(estimate_id), change_summary))


# ---------------------------------------------------------------- Estimate Runner and Agent Manager

def runner_start(estimate_id: int, trades: list | str) -> str:
    """Start a multi-trade takeoff run on an estimate: one task per trade (e.g. ["framing", "drywall", "roofing"]).
    Drywall, painting and insulation wait for framing. Trades turned off in Agent Manager are skipped. A Director plan
    job starts its own run, so use this for estimates outside the Director."""
    return _run(lambda c: runner.start_run(c, _ctx(), int(estimate_id), _list(trades, "trades")))


def runner_status(run_id: int = 0, estimate_id: int = 0) -> str:
    """A takeoff run's state and every trade task: queued (waiting on another trade), running (measure and submit),
    needs_review (a person approves), completed, blocked or failed, with what to do next for each."""
    return _run(lambda c: runner.run_status(c, _ctx(), run_id=int(run_id) or None,
                                            estimate_id=int(estimate_id) or None))


def runner_submit_takeoff(task_id: int, answers: dict | str | None = None, confidence: int | None = None,
                          note: str = "", cannot_measure: str = "") -> str:
    """Hand in one trade's quantities, measured from the plans: answers are that trade's questions (see
    est_quick_questions(module_id)). Every number must come from the plans or the user, never a guess.
    confidence 0-100 is how sure you are. If the trade can't be measured, give cannot_measure="why" instead.
    The quantities wait for a person's approval unless the owner turned on auto-advance for the trade."""
    return _run(lambda c: runner.submit_takeoff(c, _ctx(), int(task_id), _opt_obj(answers, "answers"),
                                                confidence=confidence, note=note or None,
                                                cannot_measure=cannot_measure or None))


def runner_review_task(task_id: int, approve: bool = False, answers: dict | str | None = None, note: str = "") -> str:
    """A person checks a trade's submitted quantities: approve=true prices them onto the estimate (answers can correct
    a few first); approve=false with a note sends them back to be measured again. Only approve when the user says so."""
    return _run(lambda c: runner.review_task(c, _ctx(), int(task_id), approve=bool(approve),
                                             answers=_opt_obj(answers, "answers"), note=note or None))


def runner_retry_task(task_id: int) -> str:
    """Try a failed or blocked trade again (trades waiting on it start again too)."""
    return _run(lambda c: runner.retry_task(c, _ctx(), int(task_id)))


def est_project_status(estimate_id: int) -> str:
    """Project dashboard: total, each trade's subtotal and biggest lines, the takeoff run's tasks, and the Director
    job's stage. Changes nothing."""
    return _run(lambda c: runner.project_status(c, _ctx(), int(estimate_id)))


def agent_config_get(module_id: str = "") -> str:
    """Trade-agent settings (Agent Manager): for each construction trade, enabled, confidence_threshold (0-100),
    auto_advance (approve confident takeoffs without a person, off by default), sheet_rules (which plan sheets it
    reads) and defaults (answers the company always uses). module_id for one trade."""
    def go(c):
        if module_id:
            return {"ok": True, "agent": agent_manager.get_config(c, _ctx().company_id, module_id, get_registry())}
        return agent_manager.list_configs(c, _ctx().company_id, get_registry())
    return _run(go)


def agent_config_update(module_id: str, changes: dict | str, confirm: bool = False) -> str:
    """Change one trade agent's settings (owner only), e.g. {"enabled": false} or {"defaults": {"height": "6"}}.
    Without confirm=true it only shows what would change; confirm with the user first."""
    return _run(lambda c: agent_manager.update_config(c, _ctx(), module_id, _obj(changes, "changes"),
                                                      confirm=bool(confirm), registry=get_registry()))


# ---------------------------------------------------------------- AI agents (API keys) and role prompts

def how_to_estimate(role: str = "") -> str:
    """How to run the Estimator well: with no role, the overview (start with est_director_start); with a role
    (director, intake, quick_pricer, plan_reader, takeoff, estimate_runner, pricer, reviewer, bid_writer,
    follow_up), that agent's instructions and the rules every agent follows."""
    def go(c):
        if role:
            return {"ok": True, "role": role, "instructions": agent_queue.prompt(role)}
        roles_list = sorted(p.stem for p in agent_queue.PROMPTS.glob("*.md") if p.stem != "rules")
        return {"ok": True, "instructions": agent_queue.prompt("director"), "roles": roles_list,
                "more": "how_to_estimate(role=...) for one agent's instructions"}
    return _run(go)


def agent_roles_get() -> str:
    """The AI agents that can run on their own: each role's provider (off, chat_only, claude_api, grok_api), model,
    backup provider and whether it's ready (an API key saved in AI-Prowler's Small Business tab), plus the daily and
    monthly budget and what's been spent. Keys are never shown."""
    return _run(lambda c: agent_roles.overview(c, _ctx().company_id))


def agent_roles_update(role: str, changes: dict | str, confirm: bool = False) -> str:
    """Choose how one agent role runs (owner only): {"provider": "claude_api" | "grok_api" | "chat_only" | "off",
    "model": "claude-haiku-5-5" or "" for the default, "fallback_provider": "grok_api" or ""}. API calls cost money,
    so without confirm=true it only shows what would change."""
    return _run(lambda c: agent_roles.update_role(c, _ctx(), role, _obj(changes, "changes"), confirm=bool(confirm)))


def agent_budget_update(changes: dict | str, confirm: bool = False) -> str:
    """Set the AI agents' spending limits in cents (owner only): {"daily_cents": 200, "monthly_cents": 2000}.
    Agents pause when a limit is reached. Without confirm=true it only shows what would change."""
    return _run(lambda c: agent_roles.update_budget(c, _ctx(), _obj(changes, "changes"), confirm=bool(confirm)))


def est_agent_tasks(state: str = "", limit: int = 50) -> str:
    """Agent work: queued, waiting_for_ai (to run from chat), paused (budget), done (with the notes or drafts),
    failed or cancelled."""
    return _run(lambda c: agent_queue.list_tasks(c, _ctx(), state or None, limit))


def est_agent_next(role: str = "") -> str:
    """The next agent task waiting for an AI in chat (chat_only roles): its instructions, the context to work from
    and the allowed actions. Do it, then hand the actions in with est_agent_submit."""
    return _run(lambda c: agent_queue.next_task(c, _ctx(), role or None))


def est_agent_submit(task_id: int, actions: list | str, summary: str = "") -> str:
    """Hand in your actions for one agent task, e.g. [{"action": "review_note", "body": "..."}]. They're checked like
    an unattended agent's: only the role's actions, and no dollar amounts that aren't in the context."""
    return _run(lambda c: agent_queue.submit(c, _ctx(), int(task_id), _list(actions, "actions")
                                             if isinstance(actions, str) else actions, summary))


def est_agent_apply(task_id: int, confirm: bool = False, to: str = "") -> str:
    """Use an agent's draft: a Bid Writer scope makes a new draft quote (preview it before sending); a Follow-up
    email is sent to the customer only with confirm=true, after the user has read it."""
    return _run(lambda c: agent_queue.apply_draft(c, _ctx(), int(task_id), confirm=bool(confirm), to=to or None))


def est_agent_run_now() -> str:
    """Queue and run the agents' work now instead of waiting for the watcher (uses the API budget)."""
    def go(c):
        ctx = _ctx()
        if ctx.role not in ("owner", "estimator"):
            raise PermissionDenied("only an owner or estimator can run the agents now", role=ctx.role)
        out = agent_queue.run(c, ctx)
        return {"ok": True, "queued": out["queued"], "ran": out["ran"], "paused": out["paused"]}
    return _run(go)


TOOLS = (
    est_director_start, est_director_next, est_director_change_lane, est_job_status, est_jobs_board,
    est_director_add_trade, est_director_book_site_visit, est_validate, est_scenarios, est_choose_scenario,
    est_followups_due, est_director_briefing, est_director_inbox, est_director_watch_now, est_director_watch_status,
    est_director_settings_get, est_director_settings_update, est_playbook_list, est_playbook_update,
    pricebook_get, pricebook_update, pricebook_import, est_create_revision,
    est_record_actuals, est_compare_history, est_export, est_assign, est_my_work, est_sample_project,
    est_data_export, est_data_import,
    est_setup_status, est_setup_step,
    est_list_modules, est_create_estimate, est_get_estimate, est_list_estimates, est_add_line_item,
    est_calculate, est_quick_questions, est_quick_answer,
    bid_generate, bid_preview, bid_send, bid_set_status, bid_convert_to_job, bid_list,
    runner_start, runner_status, runner_submit_takeoff, runner_review_task, runner_retry_task, est_project_status,
    agent_config_get, agent_config_update,
    how_to_estimate, agent_roles_get, agent_roles_update, agent_budget_update, est_agent_tasks, est_agent_next,
    est_agent_submit, est_agent_apply, est_agent_run_now,
)


def register(mcp) -> list[str]:
    """Register the Estimator tools on a FastMCP server. Returns the tool names.

    While the Estimator is switched off (Setup AI-Prowler → Change my choices, or the 🏗 Estimator tab) nothing is
    registered and the background checks don't start; its data and settings are untouched."""
    from estimator.ui.model import is_on
    if not is_on():
        return []
    for fn in TOOLS:
        mcp.tool()(fn)
    director_watch.start_background()      # the Director checks jobs on its own (ESTIMATOR_WATCHER=off stops it)
    return [fn.__name__ for fn in TOOLS]

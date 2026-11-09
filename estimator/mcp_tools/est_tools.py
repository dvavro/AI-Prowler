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
from estimator.drawing_model import engine as plan_engine
from estimator.drawing_model import store as plans
from estimator.takeoff import measurements as takeoffs
from estimator.takeoff import reviews
from estimator.drawing_model import crops

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
                      trades: list | str | None = None, confirm: bool = False) -> str:
    """Continue a Director job with what it asked for:
    answers / module_id; approve=true at the approval checkpoint (only when the user clearly said yes;
    confirm_sample_prices=true only if they knowingly accept sample prices); customer={name, email, ...};
    send=true (optionally send_to) to email the quote; outcome='won' or 'lost' when the customer answers;
    convert=true (optional service_date YYYY-MM-DD) to make a won quote an AI-Prowler job. send and convert ask
    first: without confirm=true nothing happens and you get needs_confirmation with the question — ask the user,
    and call again with confirm=true only once they say yes. approve=true, send=true and confirm=true can go
    together for a one-tap quote after the user said yes to sending it.
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
                                  checklist_done=bool(checklist_done), trades=_list(trades, "trades"),
                                  confirm=bool(confirm))
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
    """Open estimates and Director jobs assigned to me (or, for the owner or office, to user_id), with new notices.
    Practice jobs come back separately under "practice", labelled, and never count as real work."""
    return _run(lambda c: team.my_work(c, _ctx(), user_id or None))


def est_sample_project(action: str = "create", confirm: bool = False) -> str:
    """The practice project: action="create" makes "Practice: Garcia house" (a roof and a house wash, priced from your
    price book) to try things on; action="delete" removes it and anything made from it (needs confirm=true). Practice
    estimates stay out of your history comparisons; in "my work" they are listed apart, labelled practice."""
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
                          note: str = "", cannot_measure: str = "", from_measurements: bool = False) -> str:
    """Hand in one trade's quantities, measured from the plans: answers are that trade's questions (see
    est_quick_questions(module_id)). Every number must come from the plans or the user, never a guess.
    from_measurements=true fills them from the trade's approved measurements (takeoff_list); answers given too win.
    confidence 0-100 is how sure you are. If the trade can't be measured, give cannot_measure="why" instead.
    The quantities wait for a person's approval unless the owner turned on auto-advance for the trade."""
    return _run(lambda c: runner.submit_takeoff(c, _ctx(), int(task_id), _opt_obj(answers, "answers"),
                                                confidence=confidence, note=note or None,
                                                cannot_measure=cannot_measure or None,
                                                from_measurements=bool(from_measurements)))


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

def how_to_estimate(role: str = "", topic: str = "") -> str:
    """How to run the Estimator well: with no role, the overview (start with est_director_start) and the list of
    how-to guides; with a role (director, intake, quick_pricer, plan_reader, takeoff, estimate_runner, pricer,
    reviewer, bid_writer, follow_up), that agent's instructions and the rules every agent follows. topic= a guide
    id or the user's question in their words ("how do I send a quote?") returns the step-by-step guide that fits,
    the same steps the web app's Help screen shows - walk the user through them."""
    from estimator.ui import help as guides

    def go(c):
        if topic:
            ids = {g["id"] for g in guides.list_guides()}
            key = topic.strip().lower().replace(" ", "_").replace("-", "_")
            if key in ids:
                return {"ok": True, "guide": guides.get_guide(key)}
            found = guides.search(topic)
            if not found:
                return {"ok": True, "guide": None, "guides": guides.list_guides(),
                        "say": "No guide matches that yet; here are the guides there are."}
            return {"ok": True, "guide": guides.get_guide(found[0]["id"]),
                    "also": [g for g in found[1:4]]}
        if role:
            return {"ok": True, "role": role, "instructions": agent_queue.prompt(role)}
        roles_list = sorted(p.stem for p in agent_queue.PROMPTS.glob("*.md") if p.stem != "rules")
        return {"ok": True, "instructions": agent_queue.prompt("director"), "roles": roles_list,
                "guides": guides.list_guides(),
                "more": "how_to_estimate(role=...) for one agent's instructions; how_to_estimate(topic=...) for a "
                        "step-by-step guide (a guide id or the user's question)"}
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


# ---------------------------------------------------------------- plans and the drawing model

def plan_upload(estimate_id: int, file_path: str, supersedes_plan_set_id: int = 0, confirm: bool = False) -> str:
    """Attach a plan file on this PC (full path; PDF, PNG, JPG, TIFF, DXF or DWG, up to 300 MB) to an estimate. The file
    is checked first (real file type, not empty, not password-protected, not already on the estimate) and copied into
    the Estimator's folder. For a revised set, give the plan set it replaces. Asks first (confirm=true)."""
    return _run(lambda c: plans.upload(c, _ctx(), int(estimate_id), file_path, int(supersedes_plan_set_id) or None,
                                       bool(confirm)))


def plan_process(plan_set_id: int, confirm: bool = False) -> str:
    """Read a plan set with the plan engine in the background: sheets, viewports and scales, drawing objects,
    schedules and legends. Check progress with plan_status. Asks first; reading an already-read set again replaces its
    drawing model. Until the plan engine is installed this says so."""
    from estimator.database import open_database as _open
    return _run(lambda c: plan_engine.start(c, _ctx(), int(plan_set_id), bool(confirm), open_conn=_open))


def plan_status(plan_set_id: int = 0, estimate_id: int = 0) -> str:
    """Progress of a plan set (uploaded, processing, processed or failed with the reason, counts, sheets that still
    need a scale). With estimate_id instead: every plan set on that estimate. Also says whether the plan engine is
    installed."""
    def go(c):
        if plan_set_id:
            out = plans.status(c, _ctx(), int(plan_set_id))
        elif estimate_id:
            out = plans.list_plan_sets(c, _ctx(), int(estimate_id))
        else:
            raise InvalidInput("give a plan_set_id or an estimate_id")
        return {**out, "plan_engine": plan_engine.engine_info()}
    return _run(go)


def plan_get_sheets(plan_set_id: int, discipline: str = "") -> str:
    """Sheets in a plan set: sheet number, title, discipline (architectural, structural, plumbing, electrical...),
    revision, units, viewports with their scales, and needs_scale when something can't be measured yet."""
    return _run(lambda c: plans.sheets(c, _ctx(), int(plan_set_id), discipline or None))


def plan_get_sheet_image(sheet_id: int) -> str:
    """Where the rendered image of a sheet is, for looking at it (AI vision) or review."""
    return _run(lambda c: plans.sheet_image(c, _ctx(), int(sheet_id)))


def plan_get_viewports(sheet_id: int) -> str:
    """Viewports on a sheet (main plan, enlarged plans, details) with each one's scale, how it was found, confidence,
    and NTS. Objects are measured with the scale of the viewport they sit in."""
    return _run(lambda c: plans.viewports(c, _ctx(), int(sheet_id)))


def plan_set_scale(viewport_id: int, scale_note: str = "", scale_ratio: str = "", calibration: dict | str = "",
                   confirm: bool = False) -> str:
    """Set a viewport's scale and re-measure everything in it. Give one of: scale_note like 1/4" = 1'-0", 1" = 20',
    1:100 or NTS; scale_ratio (real per paper, e.g. 48); or calibration {"p1": [x, y], "p2": [x, y], "distance":
    "12'-6\""} from two points on the sheet and the real distance between them. Asks first."""
    def go(c):
        cal = _obj(calibration, "calibration") if calibration not in ("", None, {}) else None
        return plans.set_scale(c, _ctx(), int(viewport_id), scale_note or None, scale_ratio or None, cal,
                               bool(confirm))
    return _run(go)


def plan_get_objects(plan_set_id: int = 0, sheet_id: int = 0, kind: str = "", layer: str = "", tag: str = "",
                     viewport_id: int = 0, area: list | str = "", include_geometry: bool = False, limit: int = 200,
                     offset: int = 0) -> str:
    """Query the drawing model: rooms, walls, openings, symbols, text, dimensions, lines. Filter by plan set or
    sheet, kind (or several, comma separated), layer, tag (e.g. D3), viewport, or an area [x0, y0, x1, y1] on one
    sheet. Each object has its real size (area_sqft, perimeter_ft or length_ft) or why it isn't measured, plus totals
    by kind. include_geometry adds the points."""
    def go(c):
        box = [float(x) for x in _list(area, "area")] if area not in ("", None) else None
        return plans.objects(c, _ctx(), int(plan_set_id) or None, int(sheet_id) or None, kind or None, layer or None,
                             tag or None, int(viewport_id) or None, box, bool(include_geometry), int(limit), int(offset))
    return _run(go)


def plan_get_schedules(plan_set_id: int, schedule_type: str = "") -> str:
    """Schedules read from the plans (door, window, finish, plumbing, lighting, panel, equipment, wall-type): every
    row with its mark, columns, confidence, the plan objects tagged with that mark, and marks no tag points to."""
    return _run(lambda c: plans.schedules(c, _ctx(), int(plan_set_id), schedule_type or None))


def plan_update_schedule_row(row_id: int, fields: dict | str = "", mark: str = "", confirm: bool = False) -> str:
    """Correct a schedule row that was read wrong: some of its columns ({"size": "3'-0\" x 6'-8\""}) and/or its
    mark. The row is marked reviewed and re-linked to the plan tags. Asks first."""
    def go(c):
        f = _obj(fields, "fields") if fields not in ("", None) else None
        return plans.update_schedule_row(c, _ctx(), int(row_id), f, mark or None, bool(confirm))
    return _run(go)


def plan_get_legends(plan_set_id: int) -> str:
    """Symbol legends found on a plan set's sheets (electrical, plumbing, HVAC...)."""
    return _run(lambda c: plans.legends(c, _ctx(), int(plan_set_id)))


def symbol_detections_list(plan_set_id: int = 0, estimate_id: int = 0, item_type: str = "", sheet_id: int = 0,
                           room: str = "", status: str = "", min_confidence: str = "", needs_review: str = "",
                           limit: int = 200, offset: int = 0) -> str:
    """Symbols the plan engine found from the plan set's legend (outlets, switches, fixtures, detectors...), with
    counts by item type, sheet and room. Filter by item_type (e.g. duplex_receptacle_gfci), sheet, room name,
    status (proposed/approved/rejected), min_confidence (0-1) or needs_review (true/false). Each detection says
    where it is, which legend entry or library it came from and each technology's score (legend, vision, ocr, cad).
    Counts are proposals until a person approves them in Blueprint Review."""
    def go(c):
        from estimator.symbols import service as symbol_service
        nr = None if needs_review in ("", None) else str(needs_review).strip().lower() in ("1", "true", "yes")
        return symbol_service.detections_list(c, _ctx(), int(plan_set_id) or None, int(estimate_id) or None,
                                              item_type or None, int(sheet_id) or None, room or None, status or None,
                                              min_confidence or None, nr, int(limit), int(offset))
    return _run(go)


# ---------------------------------------------------------------- takeoff measurements

def _ids(value, name: str) -> list[int]:
    items = _list(value, name) or []
    try:
        return [int(x) for x in items]
    except (TypeError, ValueError):
        raise InvalidInput(f"{name} must be a list of numbers", field=name) from None


def takeoff_propose(estimate_id: int, module_id: str, object_ids: list | str, feeds: str = "", kind: str = "",
                    label: str = "", room: str = "", confidence: str = "", one_per_object: bool = False,
                    confirm: bool = False) -> str:
    """Propose measurements for a trade from drawing objects (ids from plan_get_objects). The quantity comes from the
    drawing model's real sizes, never typed: kind area, perimeter, length or count (guessed from the shapes if left
    out). feeds is the trade question it fills (e.g. roof_area_sqft). Unscaled or NTS objects are refused. Proposed
    measurements wait for a person (takeoff_confirm). Asks first."""
    return _run(lambda c: takeoffs.propose(c, _ctx(), int(estimate_id), module_id, _ids(object_ids, "object_ids"),
                                           feeds=feeds or None, kind=kind or None, label=label or None,
                                           room=room or None, confidence=confidence or None,
                                           one_per_object=bool(one_per_object), confirm=bool(confirm)))


def takeoff_manual(estimate_id: int, module_id: str, feeds: str = "", qty: str = "", unit: str = "", kind: str = "",
                   label: str = "", room: str = "", viewport_id: int = 0, geometry: dict | str = "",
                   approve: bool = False, confirm: bool = False) -> str:
    """Add a measurement by hand: typed (qty and unit, e.g. 1450 sqft) or drawn (geometry {"type": "polygon",
    "points": [[x, y], ...]} in sheet inches, inside viewport_id, measured with its scale). A person can approve it in
    the same step (approve=true). Asks first."""
    def go(c):
        g = _obj(geometry, "geometry") if geometry not in ("", None) else None
        return takeoffs.manual(c, _ctx(), int(estimate_id), module_id, feeds=feeds or None, qty=qty or None,
                               unit=unit or None, kind=kind or None, label=label or None, room=room or None,
                               viewport_id=int(viewport_id) or None, geometry=g, approve=bool(approve),
                               confirm=bool(confirm))
    return _run(go)


def takeoff_list(estimate_id: int, module_id: str = "", status: str = "", sheet_id: int = 0) -> str:
    """Measurements with status (proposed, approved = locked, rejected) and confidence; the review queue, lowest
    confidence first; approved totals per trade question in that question's unit (what
    runner_submit_takeoff(from_measurements=true) uses); ones that need re-measuring; suggested changes waiting."""
    return _run(lambda c: takeoffs.list_measurements(c, _ctx(), int(estimate_id), module_id or None, status or None,
                                                     int(sheet_id) or None))


def takeoff_confirm(measurement_ids: list | str = "", estimate_id: int = 0, module_id: str = "",
                    above_confidence: str = "", accept_suggestion: bool = False, confirm: bool = False) -> str:
    """A person approves measurements, which locks them: by id, or a bulk approve of a trade's proposals at or above
    a confidence (estimate_id + above_confidence, e.g. 0.9). accept_suggestion=true instead accepts the suggested
    change on approved ones. Agents can't approve. Asks first."""
    return _run(lambda c: takeoffs.confirm_measurements(
        c, _ctx(), _ids(measurement_ids, "measurement_ids") if measurement_ids not in ("", None) else None,
        estimate_id=int(estimate_id) or None, module_id=module_id or None,
        above_confidence=above_confidence or None, accept_suggestion=bool(accept_suggestion), confirm=bool(confirm)))


def takeoff_edit(measurement_id: int, qty: str = "", label: str = "", room: str = "", feeds: str = "",
                 confirm: bool = False) -> str:
    """Change a measurement's quantity, label, room or the question it feeds. Approved (locked) ones can only be
    changed by a person; an agent gets told to use takeoff_suggest_change. Asks first."""
    return _run(lambda c: takeoffs.edit(c, _ctx(), int(measurement_id), qty=qty or None, label=label or None,
                                        room=room or None, feeds=feeds or None, confirm=bool(confirm)))


def takeoff_delete(measurement_id: int, reason: str = "", confirm: bool = False) -> str:
    """Reject a measurement. It's kept in the history with the reason and never priced. Approved ones can only be
    rejected by a person. Asks first."""
    return _run(lambda c: takeoffs.reject(c, _ctx(), int(measurement_id), reason, bool(confirm)))


def takeoff_detail(measurement_id: int) -> str:
    """Everything behind one measurement: the calculation, sheet and viewport with its scale, the source drawing
    objects, method, confidence, who proposed and approved it, and every change."""
    return _run(lambda c: takeoffs.detail(c, _ctx(), int(measurement_id)))


def takeoff_suggest_change(measurement_id: int, qty: str, reason: str, confirm: bool = False) -> str:
    """Propose a new value for an approved (locked) measurement. It's shown beside the approved value and never
    replaces it; a person accepts it with takeoff_confirm(accept_suggestion=true). Asks first."""
    return _run(lambda c: takeoffs.suggest_change(c, _ctx(), int(measurement_id), qty, reason, bool(confirm)))


# ---------------------------------------------------------------- reviews and what's sent to the AI

def review_start(target_type: str, target_id: int) -> str:
    """Open a review of a count or measurement (target_type=count or measurement, target_id = measurement id) or of a
    schedule row and its linked plan tags (target_type=schedule). The current result is kept as version 0 the first
    time. Returns the open version and where every item is on the plans. If one is already open, returns it."""
    return _run(lambda c: reviews.start(c, _ctx(), target_type, int(target_id)))


def review_save(review_id: int, add: str = "", remove: str = "", relabel: str = "", relabel_matching: bool = False,
                qty: str = "", note: str = "") -> str:
    """Save review changes as a new version. add / remove: drawing object ids (missed symbols, false hits). relabel:
    JSON {object_id: "new label"} for a wrong match (it leaves this count); relabel_matching=true relabels every
    identical symbol in the count too. qty: a hand-corrected area or length (not for counts). Not priced until a
    person approves it with review_approve."""
    return _run(lambda c: reviews.save(c, _ctx(), int(review_id), add=_ids(add, "add"), remove=_ids(remove, "remove"),
                                       relabel=_opt_obj(relabel, "relabel"), relabel_matching=bool(relabel_matching),
                                       qty=qty or None, note=note or None))


def review_approve(review_id: int, second_check: bool = False, confirm: bool = False) -> str:
    """A person approves a review version; it becomes the number used for pricing and the measurement is locked.
    Agents can't approve. second_check=true: a different person signs off an approved version. Asks first."""
    return _run(lambda c: reviews.approve(c, _ctx(), int(review_id), second_check=bool(second_check),
                                          confirm=bool(confirm)))


def review_history(target_type: str, target_id: int) -> str:
    """Every version of a count or measurement: who changed what (+3 added, −2 removed, 1 relabelled), when, the
    quantity, and which version is approved. Status: unreviewed, in_review or approved."""
    return _run(lambda c: reviews.history(c, _ctx(), target_type, int(target_id)))


def review_highlight(target_type: str, target_id: int, version: int | None = None) -> str:
    """Where every item behind a count or quantity is on the plans: sheet by sheet with boxes (sheet units, origin
    top-left like the sheet image), numbered for next/previous, plus a per-sheet breakdown. version: an earlier
    review version instead of the current one."""
    return _run(lambda c: reviews.highlight(c, _ctx(), target_type, int(target_id),
                                            int(version) if version not in (None, "") else None))


def review_require_before_send(enabled: bool | None = None, confirm: bool = False) -> str:
    """Owner setting: quotes can only be sent once every count and measurement on the estimate is approved (no
    proposed, flagged or open reviews). Without enabled, shows the current setting. Changing it asks first."""
    def go(c):
        ctx = _ctx()
        if enabled is None:
            return {"ok": True, "require_reviews_before_send": reviews.require_before_send(c, ctx)}
        return reviews.set_require_before_send(c, ctx, bool(enabled), bool(confirm))
    return _run(go)


def est_ai_privacy(crop_sending: bool | None = None, show_log: int = 0, estimate_id: int | None = None,
                   confirm: bool = False) -> str:
    """What the Estimator sends to your AI provider. Shows whether symbol-crop sending is on (on by default), the
    one-time notice, the limits, and how much has been sent. crop_sending=true/false: the owner turns it on or off
    (asks first). show_log=N: the last N things sent (crop or whole sheet, size, why, who), optionally for one
    estimate."""
    def go(c):
        ctx = _ctx()
        out = crops.set_enabled(c, ctx, bool(crop_sending), bool(confirm)) if crop_sending is not None \
            else crops.settings(c, ctx)
        if show_log:
            out["log"] = crops.send_log(c, ctx, int(estimate_id) if estimate_id else None, int(show_log))["sent"]
        return out
    return _run(go)


def plan_get_crop(purpose: str, object_id: int | None = None, sheet_id: int | None = None, bbox: str = "",
                  whole_sheet: bool = False, user_asked: bool = False, provider: str = "") -> str:
    """Get a small image of the plans to look at, and log that it was sent to the AI. Crop around a drawing object
    (object_id) or an area (sheet_id + bbox [x0,y0,x1,y1] in sheet units, at most 15% of the sheet). A whole sheet
    only when the user asked you to look at it (whole_sheet=true, user_asked=true). purpose: why you need to see it.
    The first crop ever returns a one-time notice to tell the user. Refused when crop sending is off."""
    return _run(lambda c: crops.prepare(c, _ctx(), int(sheet_id) if sheet_id not in (None, "") else None,
                                        bbox=_list(bbox, "bbox") if bbox else None,
                                        object_id=int(object_id) if object_id not in (None, "") else None,
                                        purpose=purpose, provider=provider or None, whole_sheet=bool(whole_sheet),
                                        user_asked=bool(user_asked)))


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
    plan_upload, plan_process, plan_status, plan_get_sheets, plan_get_sheet_image, plan_get_viewports,
    plan_set_scale, plan_get_objects, plan_get_schedules, plan_update_schedule_row, plan_get_legends,
    symbol_detections_list,
    takeoff_propose, takeoff_manual, takeoff_list, takeoff_confirm, takeoff_edit, takeoff_delete,
    takeoff_detail, takeoff_suggest_change,
    review_start, review_save, review_approve, review_history, review_highlight, review_require_before_send,
    est_ai_privacy, plan_get_crop,
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

"""Bids: generate, preview, send, track, and convert a won bid into an AI-Prowler job.

A bid is a frozen copy of an approved estimate: its line items, prices and
totals are snapshotted when the bid is made, so later price-book changes never
change a bid a customer has seen. Sending and converting to a job need an
explicit confirmation, because they reach the customer or create real records.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

from estimator import config
from estimator.bids import render
from estimator.context import RequestContext
from estimator.core.dates import local_date_text
from estimator.core.units.money import format_cents
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable, NotFound
from estimator.estimating import service
from estimator.integrations import host

BID_STATUSES = ("draft", "sent", "viewed", "won", "lost", "expired", "void")
ESTIMATE_STATUS_FOR = {"sent": "sent", "won": "won", "lost": "lost", "expired": "expired"}
CUSTOMER_FIELDS = ("name", "email", "phone", "address", "city", "state", "zip",
                   # 2026-11-14: the New customer popup fills these like the Jobs app's own form does.
                   "first_name", "last_name", "company", "customer_type")
CUSTOMER_TYPES = ("Residential", "Commercial")
DEFAULT_VALID_DAYS = 30
PRICE_DETAILS = ("lines", "trade_totals")    # every line priced, or one price per trade with the scope listed
DEFAULT_TERMS = ("This quote is valid until {valid_until}. Payment is due when the work is complete. "
                 "The price is based on the information provided; if the scope changes, the price may change.")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def dollars(cents: int) -> str:
    """Integer cents to a plain dollar string for AI-Prowler's job tables (e.g. 26750 -> "267.50")."""
    sign = "-" if cents < 0 else ""
    c = abs(int(cents))
    return f"{sign}{c // 100}.{c % 100:02d}"


def clean_customer(customer: dict | None) -> dict:
    if not customer:
        return {}
    if not isinstance(customer, dict):
        raise InvalidInput("customer must be an object with name, email, phone, address")
    bad = sorted(set(customer) - set(CUSTOMER_FIELDS) - {"customer_id"})
    if bad:
        raise InvalidInput(f"unknown customer fields: {bad}", valid=list(CUSTOMER_FIELDS))
    out = {k: str(v).strip() for k, v in customer.items() if v not in (None, "")}
    if "email" in out and "@" not in out["email"]:
        raise InvalidInput("that email address doesn't look right", field="email")
    if "customer_type" in out:
        kind = out["customer_type"].lower()[:3]
        match = [t for t in CUSTOMER_TYPES if t.lower().startswith(kind)]
        if not match:
            raise InvalidInput("customer_type is Residential or Commercial", field="customer_type")
        out["customer_type"] = match[0]
    if not out.get("name"):
        # The name on the quote and the job: the company, else the person.
        person = " ".join(x for x in (out.get("first_name"), out.get("last_name")) if x)
        if out.get("company") or person:
            out["name"] = out.get("company") or person
    return out


def find_customers(ctx: RequestContext, query: str = "", limit: int = 25) -> dict:
    """AI-Prowler's existing customers, for the "Use an existing customer" list when a quote becomes a job."""
    service._require_edit_role(ctx, service.QUICK_ROLES)
    rows = host.find_customers(query=query, limit=limit)
    return {"customers": [_customer_view(r) for r in rows], "count": len(rows), "query": query}


def _customer_view(r: dict) -> dict:
    """One AI-Prowler customer row in the Estimator's customer shape (the fields clean_customer takes)."""
    person = " ".join(x for x in (r.get("first_name"), r.get("last_name")) if x)
    out = {"customer_id": r.get("customer_id", ""), "name": r.get("company_name") or person or r.get("customer_id", ""),
           "company": r.get("company_name", ""), "first_name": r.get("first_name", ""), "last_name": r.get("last_name", ""),
           "email": r.get("email", ""), "phone": r.get("phone", ""), "address": r.get("street_address", ""),
           "city": r.get("city", ""), "state": r.get("state", ""), "zip": r.get("zip", ""),
           "customer_type": r.get("customer_type", ""), "status": r.get("status", "")}
    return {k: str(v) for k, v in out.items()}


def fill_from_prowler(cust: dict) -> dict:
    """An existing AI-Prowler customer given by ID only gets its name, email, phone and address filled in from
    AI-Prowler (2026-11-15, Jamie): picked by ID alone, the quote showed no name and the job's name was the ID.
    Anything already given wins; with no customer list here (or no such customer) it comes back as it was."""
    if not cust or not cust.get("customer_id") or cust.get("name"):
        return cust
    try:
        found = host.find_customers(customer_id=cust["customer_id"], limit=1)
    except host.HostUnavailable:
        return cust
    if not found:
        return cust
    view = {k: v for k, v in _customer_view(found[0]).items() if v and k in set(CUSTOMER_FIELDS)}
    return {**view, **cust}


def _company(conn, company_id: str) -> dict:
    row = conn.execute("SELECT * FROM company_profile WHERE company_id = ?", (company_id,)).fetchone()
    return dict(row) if row else {}


def _template(conn, company_id: str) -> dict:
    row = conn.execute("SELECT data_json FROM setup_progress WHERE company_id = ? AND step = 'bid_template'"
                       " AND status = 'done'", (company_id,)).fetchone()
    return json.loads(row["data_json"]) if row and row["data_json"] else {}


def _shown(ln: dict) -> tuple:
    """The count and unit the customer sees for a line (2026-11-15, Jamie): the module's `show` count ("1 vehicle")
    when it has one and nobody changed the line by hand, else the priced quantity and unit."""
    calc = ln.get("calc") or {}
    if calc.get("show_quantity") and calc.get("show_unit") and not calc.get("override"):
        q = calc["show_quantity"]
        word = calc["show_unit"]
        return q, word if q in ("1", "1.0") else word + "s"
    return ln["quantity"], ln["unit"]


def _snapshot(est: dict, registry=None) -> dict:
    from estimator.modules import get_registry
    reg = registry or get_registry()
    sections, line_sum, tax = [], 0, 0
    for sec in est["sections"]:
        mod = reg.modules.get(sec["module_id"])
        title = mod.name if mod else ("Additional items" if sec["module_id"] == "custom" else sec["module_id"])
        lines = []
        for ln in sec["lines"]:
            price = ln["calc"].get("price", {})
            ln_tax = int(price.get("tax_cents", 0))
            ln_total = int(ln["total_cents"] or 0)
            qty, unit = _shown(ln)
            lines.append({"description": ln["description"], "quantity": qty, "unit": unit,
                          "price_cents": ln_total - ln_tax,
                          # 2026-11-22: which module line made it and its own tax, so Make it a job can tell a
                          # month's repeating work from one-time work (decision B)
                          "rule": (ln.get("calc") or {}).get("rule"), "tax_cents": ln_tax})
            line_sum += ln_total - ln_tax
            tax += ln_tax
        if lines:
            sections.append({"module_id": sec["module_id"], "title": title, "lines": lines,
                             "subtotal_cents": sum(x["price_cents"] for x in lines)})
    total = int((est["totals"] or {}).get("total_cents", 0))
    return {"estimate_id": est["id"], "estimate_rev": est["rev"], "sections": sections,
            "totals": {"lines_cents": line_sum, "tax_cents": tax, "adjustment_cents": total - line_sum - tax,
                       "total_cents": total}}


def _row_to_bid(row) -> dict:
    b = dict(row)
    b["snapshot"] = json.loads(b.pop("snapshot_json"))
    b["customer"] = json.loads(b.pop("customer_json")) if b.get("customer_json") else {}
    return b


def _load(conn, ctx, bid_id: int) -> dict:
    row = conn.execute("SELECT * FROM bids WHERE id = ? AND company_id = ?", (int(bid_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"bid {bid_id} not found", bid_id=bid_id)
    return _row_to_bid(row)


def _public(b: dict) -> dict:
    return {"ok": True, "id": b["id"], "number": b["number"], "version": b["version"], "estimate_id": b["estimate_id"],
            "status": b["status"], "total_cents": b["total_cents"], "total": format_cents(b["total_cents"]),
            "valid_until": b["valid_until"], "customer": b["customer"], "customer_id": b["customer_id"],
            "html_path": b["html_path"], "pdf_path": b["pdf_path"], "sent_at": b["sent_at"], "sent_to": b["sent_to"],
            "quote_id": b["quote_id"], "job_id": b["job_id"], "rev": b["rev"]}


def latest_for_estimate(conn, ctx, estimate_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM bids WHERE estimate_id = ? AND company_id = ? AND status != 'void'"
                       " ORDER BY version DESC LIMIT 1", (estimate_id, ctx.company_id)).fetchone()
    return _row_to_bid(row) if row else None


_NOT_NAMES = {"the", "and", "for", "with", "unless", "added", "writing", "other", "than", "such", "including", "beyond",
              "listed", "their", "fees", "existing", "any", "all", "work", "per", "not", "included", "extra"}


def _words(text: str) -> set:
    import re
    return {w for w in re.findall(r"[a-z]{3,}", (text or "").lower()) if w not in _NOT_NAMES}


def drop_priced_exclusions(exclusions: str | None, snap: dict) -> tuple[str | None, list[str]]:
    """Take off the "Not included" list anything the quote prices (2026-11-17, David: "Vapor barrier" was listed as not
    included while the estimate priced a vapor barrier line). A short exclusion (one to three key words) is dropped
    when every one of its words is in one priced line's description. Returns (exclusions, what was dropped)."""
    if not exclusions:
        return exclusions, []
    priced = [_words(ln["description"]) for sec in snap["sections"] for ln in sec["lines"]]
    keep, dropped = [], []
    for raw in exclusions.splitlines():
        item = raw.strip().lstrip("-•*").strip()
        key = _words(item)
        if item and 1 <= len(key) <= 3 and any(key <= p for p in priced):
            dropped.append(item)
        else:
            keep.append(raw)
    return "\n".join(keep).strip() or None, dropped


def replaced_quote(conn, ctx, estimate_id: int, snap: dict) -> dict | None:
    """The last quote the customer was sent for this estimate, if it was replaced (the estimate was reopened):
    its number, when it was sent, its total, and what changed line by line, in the customer's words."""
    row = conn.execute("SELECT * FROM bids WHERE estimate_id = ? AND company_id = ? AND sent_at IS NOT NULL"
                       " ORDER BY version DESC LIMIT 1", (estimate_id, ctx.company_id)).fetchone()
    if row is None or row["status"] != "void":
        return None
    old = json.loads(row["snapshot_json"])
    key = lambda sec, ln: (sec["title"], ln["description"])  # noqa: E731
    was = {key(s, ln): ln for s in old["sections"] for ln in s["lines"]}
    now = {key(s, ln): ln for s in snap["sections"] for ln in s["lines"]}
    changes = []
    for k in [*was, *[k for k in now if k not in was]]:
        a, b = was.get(k), now.get(k)
        if a is None:
            changes.append({"title": k[0], "description": k[1], "change": "added", "from_cents": None,
                            "to_cents": b["price_cents"]})
        elif b is None:
            changes.append({"title": k[0], "description": k[1], "change": "removed", "from_cents": a["price_cents"],
                            "to_cents": None})
        elif a["price_cents"] != b["price_cents"] or str(a["quantity"]) != str(b["quantity"]):
            changes.append({"title": k[0], "description": k[1], "change": "changed", "from_cents": a["price_cents"],
                            "to_cents": b["price_cents"]})
    return {"number": row["number"], "sent_on": local_date_text(row["sent_at"]), "total_cents": row["total_cents"],
            "changes": changes}


def generate(conn, ctx: RequestContext, estimate_id: int, *, customer: dict | None = None,
             scope_text: str | None = None, inclusions: str | None = None, exclusions: str | None = None,
             terms: str | None = None, valid_days: int | None = None, price_detail: str | None = None,
             registry=None) -> dict:
    """Make a bid (PDF and HTML) from an approved estimate. Doesn't send anything."""
    service._require_edit_role(ctx, service.QUICK_ROLES)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    if est["status"] in service.EDITABLE_STATUSES:
        raise NotEditable("approve the estimate before making a bid", estimate_id=est["id"], status=est["status"])
    if est["status"] in ("lost", "expired", "archived"):
        raise NotEditable(f"the estimate is {est['status']}", estimate_id=est["id"], status=est["status"])
    tpl = _template(conn, ctx.company_id)
    days = int(valid_days or tpl.get("valid_days") or DEFAULT_VALID_DAYS)
    if not 1 <= days <= 365:
        raise InvalidInput("valid_days must be between 1 and 365", field="valid_days")
    today = date.today()
    valid_until = (today + timedelta(days=days)).isoformat()
    cust = clean_customer(customer)
    detail = price_detail or tpl.get("price_detail") or "lines"
    if detail not in PRICE_DETAILS:
        raise InvalidInput(f"price_detail must be one of {PRICE_DETAILS}", field="price_detail")
    snap = _snapshot(est, registry)
    snap["price_detail"] = detail
    from estimator.estimating import scenarios
    titles = {s["module_id"]: s["title"] for s in snap["sections"]}
    snap["options"] = [dict(o, title=titles.get(o["module_id"], o["module_id"]))
                       for o in scenarios.list_options(conn, ctx, est["id"])]
    if not snap["sections"]:
        raise InvalidInput("the estimate has no line items to put on a bid", estimate_id=est["id"])
    # An updated quote says which quote it replaces and what changed for the customer; a change order says which
    # accepted quote it adds to (2026-11-16, David).
    rep = replaced_quote(conn, ctx, est["id"], snap)
    if rep:
        snap["replaces"] = rep
    from estimator.estimating import change_orders
    co = change_orders.quote_info(conn, ctx, est, snap["totals"]["total_cents"])
    if co:
        snap["change_order"] = co
    if scope_text is None:
        scope_text = "\n".join(f"{ln['description']} ({ln['quantity']} {ln['unit']})"
                               for sec in snap["sections"] for ln in sec["lines"])
    terms = (terms or tpl.get("terms") or DEFAULT_TERMS).replace("{valid_until}", valid_until)
    version = conn.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM bids WHERE estimate_id = ?",
                           (est["id"],)).fetchone()[0]
    number = f"Q-{est['id']:04d}-{version}"
    excl, dropped = drop_priced_exclusions(exclusions if exclusions is not None else tpl.get("exclusions"), snap)
    bid = {"number": number, "version": version, "date": today.isoformat(), "valid_until": valid_until,
           "scope_text": scope_text, "inclusions": inclusions if inclusions is not None else tpl.get("inclusions"),
           "exclusions": excl, "terms": terms, "snapshot": snap}
    company = _company(conn, ctx.company_id)
    folder = config.data_dir() / "projects" / f"estimate_{est['id']:04d}" / "bids"
    folder.mkdir(parents=True, exist_ok=True)
    html_path = folder / f"{number}.html"
    html_path.write_text(render.bid_html(bid, company, cust), encoding="utf-8")
    pdf_path = folder / f"{number}.pdf"
    pdf_problem = render.write_pdf(html_path, pdf_path)
    now = _now()
    with service.transaction(conn):
        cur = conn.execute(
            "INSERT INTO bids (company_id, estimate_id, version, number, customer_id, customer_json, scope_text,"
            " inclusions, exclusions, terms, snapshot_json, total_cents, html_path, pdf_path, status, valid_until,"
            " created_by, created_at, updated_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'draft',?,?,?,?,?)",
            (ctx.company_id, est["id"], version, number, cust.get("customer_id") or est["customer_id"],
             json.dumps(cust), scope_text, bid["inclusions"], bid["exclusions"], terms, json.dumps(snap),
             snap["totals"]["total_cents"], str(html_path), None if pdf_problem else str(pdf_path), valid_until,
             ctx.actor, now, ctx.actor, now))
        bid_id = cur.lastrowid
        service._log(conn, ctx, est["id"], "bid_generated",
                     {"bid_id": bid_id, "number": number, "total_cents": snap["totals"]["total_cents"]})
    out = _public(_load(conn, ctx, bid_id))
    out["warnings"] = ([pdf_problem] if pdf_problem else []) + (
        [f"Taken off “Not included” because this quote prices it: {'; '.join(dropped)}."] if dropped else [])
    return out


def preview(conn, ctx: RequestContext, bid_id: int) -> dict:
    b = _load(conn, ctx, bid_id)
    company = _company(conn, ctx.company_id)
    view = dict(b, date=local_date_text(b["created_at"]))
    out = _public(b)
    out["text"] = render.bid_text(view, company, b["customer"])
    out["lines"] = [ln for sec in b["snapshot"]["sections"] for ln in sec["lines"]]
    out["totals"] = b["snapshot"]["totals"]
    return out


def send(conn, ctx: RequestContext, bid_id: int, *, to: str | None = None, confirm: bool = False,
         message: str | None = None) -> dict:
    """Email the bid to the customer through AI-Prowler's send_email. Needs confirm=True."""
    service._require_edit_role(ctx, service.QUICK_ROLES)
    b = _load(conn, ctx, bid_id)
    if b["status"] not in ("draft", "sent", "viewed"):
        raise NotEditable(f"bid {b['number']} is {b['status']} and can't be sent", bid_id=b["id"], status=b["status"])
    to = (to or b["customer"].get("email") or "").strip()
    if not to:
        raise InvalidInput("who should get it? give the customer's email address", field="to")
    from estimator.takeoff import reviews
    if reviews.require_before_send(conn, ctx):
        problems = reviews.unreviewed_for_send(conn, ctx, b["estimate_id"])
        if problems:
            raise NotEditable("this company requires every count and measurement to be approved before a quote is "
                              "sent: " + "; ".join(problems[:10]) + (f" (and {len(problems) - 10} more)"
                                                                     if len(problems) > 10 else ""),
                              bid_id=b["id"], problems=problems)
    if not confirm:
        raise ConfirmationRequired(f"Send quote {b['number']} ({format_cents(b['total_cents'])}) to {to}? "
                                   "Call again with confirm=true once the user says yes.",
                                   bid_id=b["id"], to=to, total_cents=b["total_cents"])
    company = _company(conn, ctx.company_id)
    view = dict(b, date=local_date_text(b["created_at"]))
    body = ((message.strip() + "\n\n") if message else "") + render.bid_text(view, company, b["customer"])
    body_html = (f"<p>{render._e(message)}</p>" if message else "") + render.bid_html(view, company, b["customer"])
    kind = ("change order" if b["snapshot"].get("change_order") else
            "updated quote" if b["snapshot"].get("replaces") else "quote")
    subject = f"Your {kind} from {company.get('name') or 'us'} — {b['number']} ({format_cents(b['total_cents'])})"
    warnings = []
    kwargs = dict(to=to, subject=subject, body=body, body_html=body_html)
    if b["pdf_path"]:
        kwargs["attachment_path"] = b["pdf_path"]
    try:
        result = host.call("send_email", **kwargs)
    except host.HostError as exc:
        if "attachment_path" not in kwargs:
            raise
        kwargs.pop("attachment_path")            # e.g. the bids folder isn't in AI-Prowler's allowed folders
        result = host.call("send_email", **kwargs)
        warnings.append(f"Sent without the PDF attachment (the quote is in the email body): {exc.message[:200]}")
    now = _now()
    with service.transaction(conn):
        conn.execute("UPDATE bids SET status = 'sent', sent_at = ?, sent_to = ?, rev = rev + 1, updated_by = ?,"
                     " updated_at = ? WHERE id = ?", (now, to, ctx.actor, now, b["id"]))
        service._log(conn, ctx, b["estimate_id"], "bid_sent", {"bid_id": b["id"], "to": to, "result": result[:200]})
    est = service.get_estimate(conn, ctx, b["estimate_id"])
    if est["status"] == "approved":
        service.set_status(conn, ctx, est["id"], est["rev"], "sent", roles=service.QUICK_ROLES)
    out = _public(_load(conn, ctx, b["id"]))
    out["warnings"] = warnings
    return out


def set_status(conn, ctx: RequestContext, bid_id: int, status: str) -> dict:
    """Mark a bid viewed, won, lost, expired or void. The estimate follows (won/lost/expired)."""
    if status not in BID_STATUSES or status in ("draft", "sent"):
        raise InvalidInput("status must be viewed, won, lost, expired or void", field="status")
    service._require_edit_role(ctx, service.QUICK_ROLES)
    b = _load(conn, ctx, bid_id)
    if b["status"] in ("won", "lost", "void") and status != b["status"]:
        raise NotEditable(f"bid {b['number']} is already {b['status']}", bid_id=b["id"], status=b["status"])
    now = _now()
    with service.transaction(conn):
        conn.execute("UPDATE bids SET status = ?, rev = rev + 1, updated_by = ?, updated_at = ? WHERE id = ?",
                     (status, ctx.actor, now, b["id"]))
        service._log(conn, ctx, b["estimate_id"], "bid_status", {"bid_id": b["id"], "status": status},
                     {"status": b["status"]})
    est_status = ESTIMATE_STATUS_FOR.get(status)
    if est_status:
        est = service.get_estimate(conn, ctx, b["estimate_id"])
        if est["status"] != est_status and est["status"] not in service.EDITABLE_STATUSES:
            service.set_status(conn, ctx, est["id"], est["rev"], est_status, roles=service.QUICK_ROLES)
    return _public(_load(conn, ctx, b["id"]))


def _split_name(name: str) -> tuple[str, str]:
    parts = name.split()
    return (parts[0], " ".join(parts[1:])) if len(parts) > 1 else (name, "")


def _recurrence(conn, ctx, estimate_id: int, registry=None) -> str | None:
    """The repeat schedule from the quote's answers (e.g. weekly pool service -> "Weekly"), if any."""
    return _repeat_plan(conn, ctx, estimate_id, registry)[0]


def _repeat_plan(conn, ctx, estimate_id: int, registry=None) -> tuple[str | None, dict | None]:
    """(Recurrence, plan). plan is set when the repeating module's price covers a month of visits:
    {"module_id", "visits" (a month), "once" (one-time line ids)} - see recurrence per_month in the registry."""
    from estimator.modules import get_registry
    reg = registry or get_registry()
    est = service.get_estimate(conn, ctx, estimate_id)
    for sec in est["sections"]:
        mod = reg.modules.get(sec["module_id"])
        if mod and mod.recurrence and sec["answers"]:
            value = sec["answers"].get(mod.recurrence["question"])
            mapped = mod.recurrence["map"].get(str(value)) if value is not None else None
            if mapped:
                visits = (mod.recurrence.get("per_month") or {}).get(str(value))
                plan = ({"module_id": mod.id, "visits": int(visits), "once": set(mod.recurrence.get("once") or ())}
                        if visits else None)
                return mapped, plan
    return None, None


def split_month(snapshot: dict, plan: dict) -> dict | None:
    """Decision B (David, 2026-11-22): a monthly-priced repeating quote becomes a job billed per visit, and its
    one-time work (and any other trade on the same quote) becomes a job of its own, so a weekly pool job isn't
    billed the whole month every week. Amounts include their own tax; the quote's minimum-charge/rounding
    adjustment is shared out by size. Returns {"visit_cents", "month_cents", "once_cents", "once_lines"}, or None
    when the quote was saved before lines knew their rule (no split - the old behaviour)."""
    lines = [(sec["module_id"], ln) for sec in snapshot["sections"] for ln in sec["lines"]]
    if not lines or any(mid == plan["module_id"] and not ln.get("rule") for mid, ln in lines):
        return None
    month = once = 0
    once_lines = []
    for mid, ln in lines:
        cents = int(ln["price_cents"]) + int(ln.get("tax_cents") or 0)
        if mid == plan["module_id"] and ln["rule"] not in plan["once"]:
            month += cents
        else:
            once += cents
            once_lines.append(ln)
    totals = snapshot["totals"]
    adjustment = int(totals["total_cents"]) - month - once
    if month + once:
        month_adj = round(adjustment * month / (month + once))
        month, once = month + month_adj, once + adjustment - month_adj
    visits = max(int(plan["visits"]), 1)
    return {"visit_cents": round(month / visits), "month_cents": month, "once_cents": once, "once_lines": once_lines,
            "visits": visits}


def ensure_customer(cust: dict, customer_id: str | None = None, frequency: str | None = None) -> tuple[str, dict]:
    """The AI-Prowler CustomerID for this customer, creating the customer there if needed (caller confirms first).
    frequency (e.g. "Weekly" from a weekly pool quote) goes on a NEW customer's Frequency (2026-11-15, Jamie): the
    daily recurring sweep and the next-job chain read the customer's Frequency, so without it a weekly customer
    made from a quote got one follow-up job and then stopped. An existing customer's Frequency is left alone."""
    customer_id = customer_id or cust.get("customer_id")
    if customer_id:
        return customer_id, {}
    if not (cust.get("name") or cust.get("first_name") or cust.get("last_name") or cust.get("company")):
        raise InvalidInput("who is the customer? give at least their name (and email/phone/address if known)",
                           field="customer")
    if cust.get("first_name") or cust.get("last_name"):
        first, last = cust.get("first_name", ""), cust.get("last_name", "")
    elif cust.get("company") and not cust.get("name"):
        first, last = "", ""
    else:
        first, last = _split_name(cust["name"])
    updates = {"First Name": first, "Last Name": last, "Status Active/Inactive": "Active"}
    for src, col in (("email", "Email"), ("phone", "Phone"), ("address", "Street Address"), ("city", "City"),
                     ("state", "State"), ("zip", "ZIP"), ("company", "Company Name"),
                     ("customer_type", "Customer Type Comm/Res")):
        if cust.get(src):
            updates[col] = cust[src]
    if frequency:
        updates["Frequency"] = frequency
    text = host.call("create_customer", updates=updates)
    new_id = host.extract_id(text, "CUST")
    if not new_id:
        raise host.HostError("AI-Prowler created the customer but didn't return its CustomerID", result=text[:300])
    return new_id, {"customer_id": new_id}


def convert_to_job(conn, ctx: RequestContext, bid_id: int, *, confirm: bool = False, customer: dict | None = None,
                   service_date: str | None = None, registry=None) -> dict:
    """Won bid -> AI-Prowler customer (if needed), an Approved quote and a job. Needs confirm=True."""
    service._require_edit_role(ctx, service.QUICK_ROLES)
    b = _load(conn, ctx, bid_id)
    if b["job_id"]:
        out = _public(b)
        out["already_converted"] = True
        return out
    if b["status"] not in ("sent", "viewed", "won"):
        raise NotEditable(f"bid {b['number']} is {b['status']}; only a sent or won bid can become a job",
                          bid_id=b["id"], status=b["status"])
    # A change order adds to the job the accepted quote already made (2026-11-16, David): an approved quote for it,
    # and the job's amount goes up - no second job.
    if (b["snapshot"].get("change_order") or {}).get("job_id"):
        from estimator.estimating import change_orders
        done = change_orders.accept(conn, ctx, b, confirm=confirm)
        out = _public(_load(conn, ctx, b["id"]))
        out["created"] = {"quote_id": done["quote_id"], "job_id": None}
        out["change_order"] = done
        out["warnings"] = []
        return out
    if service_date:
        try:
            date.fromisoformat(service_date)
        except ValueError:
            raise InvalidInput("service_date must be YYYY-MM-DD", field="service_date") from None
    picked = clean_customer(customer)
    if picked.get("customer_id"):
        # An existing AI-Prowler customer chosen in the popup (2026-11-14): use that customer as it is, and check it's
        # really there first so the quote can't point at a customer that doesn't exist.
        try:
            found = host.find_customers(customer_id=picked["customer_id"], limit=1)
        except host.HostUnavailable:
            found = None                       # no customer list here (a host without one) - trust the ID
        if found is not None and not found:
            raise InvalidInput(f"there's no customer {picked['customer_id']} in AI-Prowler; pick another or make a new one",
                               field="customer")
        cust = dict(_customer_view(found[0]), **picked) if found else picked
        cust = {k: v for k, v in cust.items() if v and k in set(CUSTOMER_FIELDS) | {"customer_id"}}
    else:
        cust = dict(b["customer"])
        cust.pop("customer_id", None) if picked else None
        cust.update(picked)
        cust = fill_from_prowler(cust)
    customer_id = cust.get("customer_id") or (None if picked else b["customer_id"])
    if not customer_id and not cust.get("name"):
        raise InvalidInput("who is the customer? give at least their name (and email/phone/address if known)",
                           field="customer")
    if not confirm:
        raise ConfirmationRequired(
            f"Turn quote {b['number']} ({format_cents(b['total_cents'])}) into a job"
            + (f" for {cust.get('name')}" if cust.get("name") else "") + "? This creates "
            + ("" if customer_id else "a customer, ") + "an approved quote and a job in AI-Prowler. "
            "Call again with confirm=true once the user says yes.", bid_id=b["id"])
    if b["status"] != "won":
        set_status(conn, ctx, b["id"], "won")
    secs = b["snapshot"]["sections"]
    service_type = ", ".join(sec["title"] for sec in secs)[:80]
    details = "; ".join(f"{ln['description']} {ln['quantity']} {ln['unit']}" for sec in secs for ln in sec["lines"])
    recurrence, plan = _repeat_plan(conn, ctx, b["estimate_id"], registry)
    split = split_month(b["snapshot"], plan) if plan else None
    customer_id, created = ensure_customer(cust, customer_id, frequency=recurrence)
    name = cust.get("name") or customer_id
    totals = b["snapshot"]["totals"]
    quote_updates = {
        "CustomerID": customer_id, "Customer Name / Company": name, "Address": cust.get("address", ""),
        "City": cust.get("city", ""), "Quote Date": local_date_text(b["created_at"]), "Valid Until": b["valid_until"],
        "Service Type": service_type, "Service Description": f"Estimator quote {b['number']}: {details}"[:1000],
        "Subtotal ($)": dollars(totals["total_cents"] - totals["tax_cents"]), "Tax (Tax%) ($)": dollars(totals["tax_cents"]),
        "QUOTE TOTAL ($)": dollars(totals["total_cents"]), "Status (Open/Approved/Declined)": "Approved",
    }
    qtext = host.call("create_quote", updates=quote_updates)
    quote_id = host.extract_id(qtext, "QTE")
    job_updates = {
        "CustomerID": customer_id, "Customer Name / Company": name, "Street Address": cust.get("address", ""),
        "City": cust.get("city", ""), "Service Type": service_type,
        "Service Details / Notes": f"From Estimator quote {b['number']}"
                                   + (f" (Quote {quote_id})" if quote_id else "") + f": {details}"[:1000],
        "Quote Amount ($)": dollars(totals["total_cents"]),
        # Decision A (David, 2026-11-22): the quote total already includes the Estimator's tax, so the job is marked
        # No Sales Tax and its invoice equals what the customer accepted (before, the invoice added tax again).
        "No Sales Tax": 1,
    }
    if service_date:
        job_updates.update({"Service Date": service_date, "Job Status": "Scheduled"})
    once_job_id = None
    if split:
        # Decision B: the repeating job is billed per visit; one-time work gets a job of its own.
        job_updates["Quote Amount ($)"] = dollars(split["visit_cents"])
        job_updates["Service Details / Notes"] = (
            f"Per visit: {format_cents(split['month_cents'])} a month / {split['visits']} visit"
            f"{'s' if split['visits'] != 1 else ''}. " + job_updates["Service Details / Notes"])[:1000]
        if split["once_cents"] > 0:
            once_updates = {k: v for k, v in job_updates.items() if k != "Service Details / Notes"}
            once_updates["Quote Amount ($)"] = dollars(split["once_cents"])
            once_updates["Service Details / Notes"] = (
                f"One-time work from Estimator quote {b['number']}" + (f" (Quote {quote_id})" if quote_id else "")
                + ": " + "; ".join(f"{ln['description']} {ln['quantity']} {ln['unit']}" for ln in split["once_lines"]))[:1000]
            otext = host.call("create_job", updates=once_updates)
            once_job_id = host.extract_id(otext, "JOB")
    if recurrence:
        job_updates["Recurrence"] = recurrence
        job_updates["Service Details / Notes"] = f"{recurrence} service. " + job_updates["Service Details / Notes"]
    jtext = host.call("create_job", updates=job_updates)
    job_id = host.extract_id(jtext, "JOB")
    if once_job_id:
        created = dict(created, once_job_id=once_job_id)
    now = _now()
    with service.transaction(conn):
        conn.execute("UPDATE bids SET customer_id = ?, customer_json = ?, quote_id = ?, job_id = ?, rev = rev + 1,"
                     " updated_by = ?, updated_at = ? WHERE id = ?",
                     (customer_id, json.dumps(dict(cust, customer_id=customer_id)), quote_id, job_id, ctx.actor, now,
                      b["id"]))
        conn.execute("UPDATE estimates SET customer_id = COALESCE(customer_id, ?), job_id = ?, rev = rev + 1,"
                     " updated_by = ?, updated_at = ? WHERE id = ?", (customer_id, job_id, ctx.actor, now,
                                                                      b["estimate_id"]))
        service._log(conn, ctx, b["estimate_id"], "bid_converted_to_job",
                     {"bid_id": b["id"], "customer_id": customer_id, "quote_id": quote_id, "job_id": job_id,
                      **created})
    out = _public(_load(conn, ctx, b["id"]))
    out["created"] = dict(created, quote_id=quote_id, job_id=job_id)
    out["recurrence"] = recurrence
    if split:
        out["per_visit"] = {"visit": format_cents(split["visit_cents"]), "month": format_cents(split["month_cents"]),
                            "visits_a_month": split["visits"], "one_time": format_cents(split["once_cents"]),
                            "one_time_job_id": once_job_id}
    out["warnings"] = job_warnings(cust, ctx, job_id)
    return out


def job_warnings(cust: dict, ctx: RequestContext, job_id: str | None) -> list[str]:
    """What the new AI-Prowler job is missing for scheduling and routing (2026-11-15, Jamie). A job with no street
    address is left off every route without a word, and in Server mode a job with no crew is on nobody's route
    (a blank route request means "my own jobs"). The crew isn't guessed: Estimator sign-in names aren't the
    Jobs app's crew names."""
    job = job_id or "The job"
    out = []
    if not (cust.get("address") or "").strip():
        out.append(f"{job} has no street address, so it won't appear on any route. Add the address in the Jobs app.")
    if ctx.mode == "server":
        out.append(f"{job} has no crew yet, so it isn't on anyone's route. Assign a crew in the Jobs app.")
    return out


def list_bids(conn, ctx: RequestContext, status: str | None = None, estimate_id: int | None = None) -> dict:
    sql = "SELECT * FROM bids WHERE company_id = ?"
    args: list = [ctx.company_id]
    if status:
        if status not in BID_STATUSES:
            raise InvalidInput(f"status must be one of {BID_STATUSES}", field="status")
        sql += " AND status = ?"
        args.append(status)
    if estimate_id:
        sql += " AND estimate_id = ?"
        args.append(int(estimate_id))
    sql += " ORDER BY id DESC LIMIT 200"
    bids = [_public(_row_to_bid(r)) for r in conn.execute(sql, args)]
    return {"ok": True, "count": len(bids), "bids": bids}

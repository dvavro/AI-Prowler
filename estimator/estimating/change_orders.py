"""Change orders: more or different work after the customer accepted a quote (2026-11-16, David).

"What about after the customer said YES (quote won, job created) and then asks for more work?" - a change order: a
separate add-on estimate just for the extra or changed work, priced, approved and quoted on its own. Its quote says
which accepted quote it adds to and what the job comes to with it. When the customer accepts it, AI-Prowler gets an
approved quote for the change order and the existing job's amount goes up by it. The original accepted quote stays as
signed.

A change order hangs off the accepted (won) estimate: estimates.change_order_of = that estimate's id. Several change
orders on one job are numbered 1, 2, 3 in the order they were made.
"""
from __future__ import annotations

from estimator.context import RequestContext
from estimator.core.units.money import format_cents
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable
from estimator.estimating import service


def _won_bid(conn, estimate_id: int):
    return conn.execute("SELECT * FROM bids WHERE estimate_id = ? AND status = 'won' ORDER BY version DESC LIMIT 1",
                        (estimate_id,)).fetchone()


def _row(conn, ctx, estimate_id: int):
    return service._load_row(conn, ctx, int(estimate_id))


def parent_of(conn, ctx, estimate_id: int) -> int | None:
    row = _row(conn, ctx, estimate_id)
    return row["change_order_of"] if "change_order_of" in row.keys() else None


def _children(conn, ctx, parent_id: int) -> list:
    return conn.execute("SELECT * FROM estimates WHERE company_id = ? AND change_order_of = ? ORDER BY id",
                        (ctx.company_id, parent_id)).fetchall()


def number_of(conn, ctx, est_row) -> int:
    ids = [r["id"] for r in _children(conn, ctx, est_row["change_order_of"])]
    return ids.index(est_row["id"]) + 1 if est_row["id"] in ids else len(ids) + 1


def can_make(conn, ctx, est: dict) -> bool:
    """A change order can be made from an accepted estimate (or from one of its change orders)."""
    if ctx.role not in service.QUICK_ROLES:
        return False
    root = parent_of(conn, ctx, est["id"]) or est["id"]
    return _won_bid(conn, root) is not None


def create(conn, ctx: RequestContext, estimate_id: int, summary: str, confirm: bool = False, registry=None) -> dict:
    """Make a change order (a new, empty estimate for the extra work) on an accepted estimate; asks first."""
    service._require_edit_role(ctx, service.QUICK_ROLES)
    summary = " ".join((summary or "").split())[:500]
    if not summary:
        raise InvalidInput("say what the customer wants added or changed, e.g. “extend the patio 10 ft”",
                           field="change_summary")
    src = _row(conn, ctx, estimate_id)
    root_id = src["change_order_of"] or src["id"]
    root = _row(conn, ctx, root_id)
    won = _won_bid(conn, root_id)
    if won is None:
        raise NotEditable(f"estimate {root_id} hasn't been accepted by the customer yet; reopen it for changes "
                          "(✏️ Reopen for changes) instead of a change order", estimate_id=root_id, status=root["status"])
    n = len(_children(conn, ctx, root_id)) + 1
    title = f"{root['title']} — Change order {n}"
    if not confirm:
        raise ConfirmationRequired(
            f"Make change order {n} on “{root['title']}” (accepted quote {won['number']}, "
            f"{format_cents(won['total_cents'])}) for: {summary}? It's a new estimate just for this work; the "
            "accepted quote stays as signed, and when the customer accepts the change order the job's amount goes up "
            "by it.", estimate_id=root_id, n=n)
    now = service._now()
    with service.transaction(conn):
        cur = conn.execute(
            "INSERT INTO estimates (company_id, customer_id, job_id, address, title, revision, change_summary, due_date,"
            " assigned_to, created_by, created_at, updated_by, updated_at, change_order_of)"
            " VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?,?)",
            (ctx.company_id, root["customer_id"] or won["customer_id"], won["job_id"] or root["job_id"], root["address"],
             title, summary, root["due_date"], root["assigned_to"], ctx.actor, now, ctx.actor, now, root_id))
        new_id = cur.lastrowid
        service._log(conn, ctx, root_id, "change_order_created", {"estimate_id": new_id, "n": n, "summary": summary})
        service._log(conn, ctx, new_id, "estimate_created", {"change_order_of": root_id, "n": n, "summary": summary})
    _director_job(conn, ctx, root_id, new_id, registry)
    out = service.get_estimate(conn, ctx, new_id)
    out["change_order"] = info(conn, ctx, new_id)
    return out


def _director_job(conn, ctx, root_id: int, new_id: int, registry=None) -> None:
    """Give the change order its Director job, with the customer the accepted quote went to."""
    try:
        from estimator.director import engine
        from estimator.director import jobs as jobstore
        engine.adopt(conn, ctx, new_id, registry=registry)
        job = engine.project_job_for(conn, ctx, new_id)
        old = engine.project_job_for(conn, ctx, root_id)
        if job is None:
            return
        job = jobstore.load_job(conn, ctx, job["id"])
        cust = dict((old or {}).get("customer") or {})
        won = _won_bid(conn, root_id)
        if won is not None:
            import json
            cust = {**json.loads(won["customer_json"] or "{}"), **cust}
            if won["customer_id"]:
                cust.setdefault("customer_id", won["customer_id"])
        if cust:
            job["customer"] = {**cust, **(job.get("customer") or {})}
            with service.transaction(conn):
                jobstore.save_job(conn, ctx, job)
    except Exception:                         # the change order exists either way; the Director asks for what's missing
        import logging
        logging.getLogger(__name__).warning("couldn't set up the Director for change order %s", new_id, exc_info=True)


def _job_total(conn, root_id: int, extra_cents: int = 0, exclude_estimate: int | None = None) -> int:
    """The accepted quote plus every accepted change order (and extra_cents for one being quoted now)."""
    won = _won_bid(conn, root_id)
    total = int(won["total_cents"]) if won else 0
    for r in conn.execute("SELECT b.total_cents FROM bids b JOIN estimates e ON e.id = b.estimate_id"
                          " WHERE e.change_order_of = ? AND b.status = 'won' AND e.id != ?",
                          (root_id, exclude_estimate or -1)):
        total += int(r["total_cents"])
    return total + extra_cents


def info(conn, ctx, estimate_id: int) -> dict | None:
    """For a change order: which accepted estimate and quote it adds to, its number, and its job."""
    row = _row(conn, ctx, estimate_id)
    root_id = row["change_order_of"] if "change_order_of" in row.keys() else None
    if not root_id:
        return None
    root = _row(conn, ctx, root_id)
    won = _won_bid(conn, root_id)
    return {"of_estimate_id": root_id, "of_title": root["title"], "n": number_of(conn, ctx, row),
            "of_number": won["number"] if won else None, "of_total_cents": int(won["total_cents"]) if won else 0,
            "job_id": (won["job_id"] if won else None) or root["job_id"], "summary": row["change_summary"]}


def quote_info(conn, ctx, est: dict, total_cents: int) -> dict | None:
    """What a change order's quote says about the accepted quote it adds to (bids.generate)."""
    co = info(conn, ctx, est["id"])
    if co is None:
        return None
    co["job_total_cents"] = _job_total(conn, co["of_estimate_id"], total_cents, exclude_estimate=est["id"])
    return co


def list_for(conn, ctx, estimate_id: int) -> list[dict]:
    """An accepted estimate's change orders: number, title, status, total and what it's for."""
    import json
    out = []
    for i, r in enumerate(_children(conn, ctx, int(estimate_id)), 1):
        totals = json.loads(r["totals_json"]) if r["totals_json"] else {}
        out.append({"id": r["id"], "n": i, "title": r["title"], "status": r["status"], "summary": r["change_summary"],
                    "total_cents": totals.get("total_cents", 0)})
    return out


def accept(conn, ctx: RequestContext, bid: dict, *, confirm: bool = False) -> dict:
    """The customer accepted a change order's quote: an approved quote for it in AI-Prowler, and the existing job's
    amount goes up by it (bids.convert_to_job sends change orders here)."""
    from estimator.bids import service as bids
    from estimator.integrations import host
    co = bid["snapshot"].get("change_order") or {}
    root_id = co.get("of_estimate_id")
    job_id = co.get("job_id")
    if not root_id or not job_id:
        return {}                                   # no job to add to yet: an ordinary conversion makes one
    new_total = _job_total(conn, root_id, int(bid["total_cents"]), exclude_estimate=bid["estimate_id"])
    if not confirm:
        raise ConfirmationRequired(
            f"The customer accepted change order {co.get('n')} ({bid['number']}, {format_cents(bid['total_cents'])})? "
            f"This adds an approved quote in AI-Prowler and sets job {job_id} to {format_cents(new_total)}. Call again "
            "with confirm=true once the user says yes.", bid_id=bid["id"], job_id=job_id, job_total_cents=new_total)
    if bid["status"] != "won":
        bids.set_status(conn, ctx, bid["id"], "won")
    cust = bid["customer"] or {}
    customer_id = bid["customer_id"] or cust.get("customer_id")
    totals = bid["snapshot"]["totals"]
    details = "; ".join(f"{ln['description']} {ln['quantity']} {ln['unit']}"
                        for sec in bid["snapshot"]["sections"] for ln in sec["lines"])
    qtext = host.call("create_quote", updates={
        "CustomerID": customer_id or "", "Customer Name / Company": cust.get("name") or customer_id or "",
        "Address": cust.get("address", ""), "City": cust.get("city", ""), "Valid Until": bid["valid_until"],
        "Service Type": f"Change order {co.get('n')} for {job_id}",
        "Service Description": (f"Estimator change order {bid['number']} to quote {co.get('of_number')} for job "
                                f"{job_id}: {co.get('summary') or ''} — {details}")[:1000],
        "Subtotal ($)": bids.dollars(totals["total_cents"] - totals["tax_cents"]),
        "Tax (Tax%) ($)": bids.dollars(totals["tax_cents"]), "QUOTE TOTAL ($)": bids.dollars(totals["total_cents"]),
        "Status (Open/Approved/Declined)": "Approved"})
    quote_id = host.extract_id(qtext, "QTE")
    host.call("update_job_spreadsheet", job_identifier=job_id, id_column="JobID", sheet_name="Jobs_Schedule",
              updates={"Quote Amount ($)": bids.dollars(new_total)})
    now = service._now()
    with service.transaction(conn):
        conn.execute("UPDATE bids SET quote_id = ?, job_id = ?, rev = rev + 1, updated_by = ?, updated_at = ?"
                     " WHERE id = ?", (quote_id, job_id, ctx.actor, now, bid["id"]))
        conn.execute("UPDATE estimates SET job_id = ?, rev = rev + 1, updated_by = ?, updated_at = ? WHERE id = ?",
                     (job_id, ctx.actor, now, bid["estimate_id"]))
        for eid in (bid["estimate_id"], root_id):
            service._log(conn, ctx, eid, "change_order_accepted",
                         {"bid_id": bid["id"], "number": bid["number"], "quote_id": quote_id, "job_id": job_id,
                          "job_total_cents": new_total})
    return {"quote_id": quote_id, "job_id": job_id, "job_total_cents": new_total, "job_total": format_cents(new_total)}

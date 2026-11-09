"""Settings screen - Coder 2 Sprint 17 (spec: Screens and controls, Settings). Owner only.

  GET  /settings                          everything the screen shows: company profile, tax, markups, labor rates,
                                          bid template, approval rules, AI and privacy, users and roles, data folder
                                          and backups, sample prices still in use
  POST /settings/<section> {data, confirm}   change one section; the first call answers needs_confirmation with
                                          each change (old -> new), the second (confirm=true) saves it
      company_profile  name, address, phone, license_no, logo_path        (est_setup_step company_profile)
      tax              tax_pct (percent, e.g. "7"), taxable_kinds [material, labor, ...], tax_base cost|price
      markups          overhead_pct, profit_pct, labor_burden_pct (percent), minimum_charge (dollars), round_to_cents
      bid_template     valid_days, price_detail lines|trade_totals, terms, inclusions [..], exclusions [..]
      approvals        review_required_over, quick_send_limit (dollars), follow_up_days, review_reminder_days,
                       auto_expire_bids                                   (Director settings)
      ai_privacy       crop_sending true|false                            (est_ai_privacy)
      labor_rates      prices {price_key: dollars}                        (pricebook_update; labor prices only)
  POST /settings/backup {confirm}         back up estimator.db now (keeps the newest 30)
  GET  /settings/audit?limit=&action=&estimate_id=   the audit log: who changed what, newest first

Everything is saved through the same service calls the AI's tools use (est_setup_step, Director settings,
est_ai_privacy, pricebook_update), so the web app and chat stay the same. Percentages are typed as percents here and
stored as fractions ("7" -> "0.07"), as est_setup_step expects.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation

from estimator.api import nav

SECTIONS = ("company_profile", "tax", "markups", "bid_template", "approvals", "ai_privacy", "labor_rates")
PROFILE = ("name", "address", "phone", "license_no", "logo_path")
PCT_KEYS = ("tax_pct", "overhead_pct", "profit_pct", "labor_burden_pct")
KINDS = ("material", "labor", "equipment", "sub", "other")
_SECTION = re.compile(r"^/settings/([a-z_]+)$")
AUDIT_MAX = 500


def handles(sub: str) -> bool:
    return sub == "/settings" or sub.startswith("/settings/")


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _ask_first, _body, _ok
    if not nav.can_open(ctx.role, "settings"):
        raise _refuse("only the owner can open Settings", 403, "permission_denied")
    if sub == "/settings" and m == "GET":
        return _ok(**read_all(conn, ctx))
    if sub == "/settings/audit" and m == "GET":
        return _ok(**audit(conn, ctx, req.query))
    if sub == "/settings/backup" and m == "POST":
        b = _body(req)
        return _ask_first(lambda: backup_now(conn, ctx, b.get("confirm") is True))
    mm = _SECTION.match(sub)
    if mm and m == "POST":
        section = mm.group(1)
        if section not in SECTIONS:
            raise _refuse(f"no settings section '{section}'; sections: {', '.join(SECTIONS)}", 404, "not_found")
        b = _body(req)
        data = b.get("data") or {}
        if not isinstance(data, dict):
            raise _refuse("data must be an object")
        return _ask_first(lambda: save(conn, ctx, section, data, b.get("confirm") is True))
    raise _refuse(f"no such Estimator API call: {m} {sub}", 404, "not_found")


# ---------------------------------------------------------------- reading

def _pct(frac) -> str:
    try:
        return format((Decimal(str(frac or "0")) * 100).normalize(), "f")
    except InvalidOperation:
        return "0"


def _template(conn, company_id: str) -> dict:
    row = conn.execute("SELECT data_json FROM setup_progress WHERE company_id = ? AND step = 'bid_template'",
                       (company_id,)).fetchone()
    return json.loads(row["data_json"]) if row and row["data_json"] else {}


def read_all(conn, ctx) -> dict:
    from estimator import config
    from estimator.bids import service as bids
    from estimator.database import backup
    from estimator.director import settings as director
    from estimator.drawing_model import crops
    from estimator.estimating import setup
    from estimator.pricing import price_book
    prof = conn.execute("SELECT * FROM company_profile WHERE company_id = ?", (ctx.company_id,)).fetchone()
    profile = {f: (prof[f] if prof else None) for f in PROFILE}
    mk = conn.execute("SELECT * FROM markups WHERE company_id = ?", (ctx.company_id,)).fetchone()
    markups = {"overhead_pct": _pct(mk["overhead_pct"] if mk else 0), "profit_pct": _pct(mk["profit_pct"] if mk else 0),
               "labor_burden_pct": _pct(mk["labor_burden_pct"] if mk else 0),
               "minimum_charge_cents": mk["minimum_charge_cents"] if mk else None,
               "round_to_cents": mk["round_to_cents"] if mk else None}
    tax = {"tax_pct": _pct(mk["tax_pct"] if mk else 0),
           "taxable_kinds": [k for k in (mk["taxable_kinds"] if mk else "material").split(",") if k],
           "tax_base": mk["tax_base"] if mk else "cost"}
    labor = [p for p in price_book.list_prices(conn, ctx.company_id)["prices"] if p["kind"] == "labor"]
    tpl = _template(conn, ctx.company_id)
    template = {"valid_days": tpl.get("valid_days") or bids.DEFAULT_VALID_DAYS,
                "price_detail": tpl.get("price_detail") or "lines", "terms": tpl.get("terms") or bids.DEFAULT_TERMS,
                "inclusions": tpl.get("inclusions") or [], "exclusions": tpl.get("exclusions") or [],
                "price_details": list(bids.PRICE_DETAILS)}
    d = director.get_settings(conn, ctx.company_id)
    approvals = {k: d[k] for k in ("review_required_over_cents", "quick_send_limit_cents", "follow_up_days",
                                   "review_reminder_days", "auto_expire_bids")}
    files = backup.list_backups()
    roles = [{"role": r, **p, "screens": [s["label"] for s in nav.SCREENS if r in s["roles"]]}
             for r, p in nav.PERMISSIONS.items()]
    status = setup.setup_status(conn, ctx)
    return {"company_profile": profile, "tax": tax, "markups": markups, "labor_rates": labor, "bid_template": template,
            "approvals": approvals, "ai_privacy": crops.settings(conn, ctx), "roles": roles,
            "roles_note": ("People and their roles come from AI-Prowler's own accounts (Admin, Users). The owner has "
                           "everything; managers and staff sign in as office, and as estimators when they have the "
                           "Estimating scope; field crew can look, but not change or approve."),
            "data_folder": str(config.data_dir()), "mode": ctx.mode,
            "backups": [{"file": f.name, "size": f.stat().st_size} for f in reversed(files[-10:])],
            "backup_count": len(files), "samples_in_use": status["sample_prices_in_use"],
            "setup": {"done": status["done"], "total": status["total"]}, "kinds": list(KINDS)}


def audit(conn, ctx, q: dict) -> dict:
    try:
        limit = max(1, min(int(q.get("limit") or 100), AUDIT_MAX))
    except ValueError:
        raise _refuse("limit must be a whole number") from None
    sql = ("SELECT e.id, e.estimate_id, e.actor, e.on_behalf_of, e.action, e.after_json, e.at, s.title FROM"
           " estimate_events e LEFT JOIN estimates s ON s.id = e.estimate_id WHERE e.company_id = ?")
    args: list = [ctx.company_id]
    action = (q.get("action") or "").strip()
    if action:
        if not re.fullmatch(r"[a-z_]{1,64}", action):
            raise _refuse("action is a name like prices_changed")
        sql += " AND e.action = ?"
        args.append(action)
    if (q.get("estimate_id") or "").strip():
        try:
            args.append(int(q["estimate_id"]))
        except ValueError:
            raise _refuse("estimate_id must be a whole number") from None
        sql += " AND e.estimate_id = ?"
    rows = []
    for r in conn.execute(sql + " ORDER BY e.id DESC LIMIT ?", args + [limit]):
        after = r["after_json"]
        rows.append({"id": r["id"], "estimate_id": r["estimate_id"], "estimate_title": r["title"], "actor": r["actor"],
                     "on_behalf_of": r["on_behalf_of"], "action": r["action"], "at": r["at"],
                     "detail": after[:400] if after else None})
    actions = [r[0] for r in conn.execute("SELECT DISTINCT action FROM estimate_events WHERE company_id = ? ORDER BY 1",
                                          (ctx.company_id,))]
    return {"events": rows, "count": len(rows), "actions": actions}


# ---------------------------------------------------------------- saving

def _frac(v, name: str) -> str:
    try:
        d = Decimal(str(v).strip().rstrip("%"))
    except InvalidOperation:
        raise _refuse(f"{words(name)} must be a percent, like 10") from None
    if not d.is_finite() or d < 0 or d > 100:
        raise _refuse(f"{words(name)} must be between 0 and 100 percent")
    return format((d / 100).normalize(), "f")


def words(s: str) -> str:
    return s.replace("_pct", "").replace("_", " ")


def _dollars_to_cents(v, name: str) -> int:
    from estimator.core.units.money import cents_from_decimal
    try:
        c = cents_from_decimal(str(v).strip().lstrip("$").replace(",", ""))
    except (ValueError, TypeError, InvalidOperation):
        raise _refuse(f"{words(name)} must be dollars, like 750") from None
    if c < 0:
        raise _refuse(f"{words(name)} can't be negative")
    return c


def _lines(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = v.splitlines()
    if not isinstance(v, list):
        raise _refuse("inclusions and exclusions are lists of lines")
    out = [str(x).strip()[:300] for x in v if str(x).strip()]
    if len(out) > 50:
        raise _refuse("at most 50 inclusion or exclusion lines")
    return out


def _confirm(changes: list[dict], what: str, confirm: bool):
    from estimator.errors import ConfirmationRequired
    if not confirm:
        raise ConfirmationRequired(f"Save these {what} changes? Call again with confirm=true.",
                                   changes=[f"{c['field']}: {c['old'] if c['old'] not in (None, '') else '(blank)'} → "
                                            f"{c['new'] if c['new'] not in (None, '') else '(blank)'}" for c in changes])


def _diff(old: dict, new: dict) -> list[dict]:
    return [{"field": words(k), "old": old.get(k), "new": v} for k, v in new.items() if old.get(k) != v]


def save(conn, ctx, section: str, data: dict, confirm: bool) -> dict:
    from estimator.estimating import setup
    if ctx.agent:
        raise _refuse("settings are changed by a person", 403, "permission_denied")
    current = read_all(conn, ctx)
    if section == "ai_privacy":
        from estimator.drawing_model import crops
        if not isinstance(data.get("crop_sending"), bool):
            raise _refuse("crop_sending must be true or false")
        return {"ai_privacy": crops.set_enabled(conn, ctx, data["crop_sending"], confirm), "section": section}
    if section == "labor_rates":
        from estimator.pricing import price_book
        prices = data.get("prices")
        if not isinstance(prices, dict) or not prices:
            raise _refuse("change at least one labor rate")
        labor = {p["price_key"] for p in current["labor_rates"]}
        other = sorted(set(prices) - labor)
        if other:
            raise _refuse(f"these aren't labor rates: {', '.join(other)}; change them in the Price Book")
        out = price_book.update_prices(conn, ctx, {str(k): str(v) for k, v in prices.items()}, confirm=confirm)
        return {**out, "section": section}
    if section == "company_profile":
        bad = sorted(set(data) - set(PROFILE))
        if bad:
            raise _refuse(f"unknown company profile fields: {', '.join(bad)}")
        new = {**current["company_profile"], **{k: (str(v).strip() if v is not None else None) for k, v in data.items()}}
        if not (new.get("name") or "").strip():
            raise _refuse("the company name is required")
        for k in PROFILE:
            if new.get(k) and len(new[k]) > 300:
                raise _refuse(f"{words(k)} is too long")
        changes = _diff(current["company_profile"], new)
        _apply_or_ask(changes, "company profile", confirm)
        setup.setup_step(conn, ctx, "company_profile", new)
    elif section == "tax":
        bad = sorted(set(data) - {"tax_pct", "taxable_kinds", "tax_base"})
        if bad:
            raise _refuse(f"unknown tax fields: {', '.join(bad)}")
        step, shown = {}, {}
        if "tax_pct" in data:
            step["tax_pct"] = _frac(data["tax_pct"], "tax_pct")
            shown["tax_pct"] = _pct(step["tax_pct"])
        if "taxable_kinds" in data:
            kinds = data["taxable_kinds"]
            if not isinstance(kinds, list) or any(k not in KINDS for k in kinds):
                raise _refuse(f"taxable kinds are among {', '.join(KINDS)}")
            step["taxable_kinds"] = tuple(kinds)
            shown["taxable_kinds"] = list(kinds)
        if "tax_base" in data:
            if data["tax_base"] not in ("cost", "price"):
                raise _refuse("tax is figured on cost or price")
            step["tax_base"] = shown["tax_base"] = data["tax_base"]
        _apply_or_ask(_diff(current["tax"], shown), "tax", confirm)
        setup.setup_step(conn, ctx, "tax", step)
    elif section == "markups":
        allowed = {"overhead_pct", "profit_pct", "labor_burden_pct", "minimum_charge", "round_to_cents"}
        bad = sorted(set(data) - allowed)
        if bad:
            raise _refuse(f"unknown markup fields: {', '.join(bad)}")
        step, shown = {}, {}
        for k in ("overhead_pct", "profit_pct", "labor_burden_pct"):
            if k in data:
                step[k] = _frac(data[k], k)
                shown[k] = _pct(step[k])
        old = dict(current["markups"])
        if "minimum_charge" in data:
            cents = None if str(data["minimum_charge"]).strip() == "" else _dollars_to_cents(data["minimum_charge"],
                                                                                          "minimum_charge")
            step["minimum_charge_cents"] = shown["minimum_charge_cents"] = cents
        if "round_to_cents" in data:
            v = data["round_to_cents"]
            if v in (None, "", 0, "0"):
                v = None
            else:
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    raise _refuse("round to is a whole number of cents, e.g. 100 for whole dollars") from None
                if v not in (5, 10, 25, 50, 100, 500, 1000):
                    raise _refuse("round to 5, 10, 25 or 50 cents, or 1, 5 or 10 dollars")
            step["round_to_cents"] = shown["round_to_cents"] = v
        _apply_or_ask(_diff(old, shown), "markup", confirm)
        setup.setup_step(conn, ctx, "markups", step)
    elif section == "bid_template":
        allowed = {"valid_days", "price_detail", "terms", "inclusions", "exclusions"}
        bad = sorted(set(data) - allowed)
        if bad:
            raise _refuse(f"unknown bid template fields: {', '.join(bad)}")
        old = {k: current["bid_template"][k] for k in allowed}
        new = dict(old)
        if "valid_days" in data:
            try:
                new["valid_days"] = int(data["valid_days"])
            except (TypeError, ValueError):
                raise _refuse("valid for is a number of days") from None
            if not 1 <= new["valid_days"] <= 365:
                raise _refuse("a quote is valid for 1 to 365 days")
        if "price_detail" in data:
            if data["price_detail"] not in current["bid_template"]["price_details"]:
                raise _refuse("show every line (lines) or one price per trade (trade_totals)")
            new["price_detail"] = data["price_detail"]
        if "terms" in data:
            t = str(data["terms"] or "").strip()
            if len(t) > 3000:
                raise _refuse("the terms are too long (3,000 characters at most)")
            new["terms"] = t
        for k in ("inclusions", "exclusions"):
            if k in data:
                new[k] = _lines(data[k])
        _apply_or_ask(_diff(old, new), "bid template", confirm)
        setup.setup_step(conn, ctx, "bid_template", new)
    elif section == "approvals":
        from estimator.director import settings as director
        allowed = {"review_required_over", "quick_send_limit", "follow_up_days", "review_reminder_days",
                   "auto_expire_bids"}
        bad = sorted(set(data) - allowed)
        if bad:
            raise _refuse(f"unknown approval fields: {', '.join(bad)}")
        changes = {}
        for k in ("review_required_over", "quick_send_limit"):
            if k in data:
                changes[f"{k}_cents"] = _dollars_to_cents(data[k], k)
        for k in ("follow_up_days", "review_reminder_days", "auto_expire_bids"):
            if k in data:
                changes[k] = data[k]
        _apply_or_ask(_diff(current["approvals"], changes), "approval rule", confirm)
        director.update_settings(conn, ctx, changes)
    return {"section": section, "saved": True, "settings": read_all(conn, ctx)}


def _apply_or_ask(changes: list[dict], what: str, confirm: bool) -> None:
    if not changes:
        raise _refuse("nothing changed")
    _confirm(changes, what, confirm)


def backup_now(conn, ctx, confirm: bool) -> dict:
    from estimator.database import backup
    from estimator.errors import ConfirmationRequired
    from estimator.estimating import service
    if not confirm:
        raise ConfirmationRequired("Back up the Estimator database now? The newest 30 backups are kept. "
                                   "Call again with confirm=true.", changes=[])
    path = backup.backup_database()
    removed = backup.prune_backups()
    with service.transaction(conn):
        service._log(conn, ctx, None, "backup_made", {"file": path.name, "removed": len(removed)})
    return {"file": path.name, "removed": len(removed), "backups": len(backup.list_backups())}

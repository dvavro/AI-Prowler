"""The Inspector agent: an AI-powered inspection audit and checklist for construction trades.

(2026-11-18, David): before the final quote is approved, the estimate can be
checked against the code requirements for the job's zip code, one trade at a
time. The Inspector is an agent role (agents/roles.py) - it starts Off, like
every role, and does nothing until the owner picks a provider, so pros who don't
need it see nothing new. Running a review is interactive (no queue, no detached
runner): one LLM call per trade through the providers layer, within the budget,
logged to the AI Log.

The AI matches, it does not invent: the prompt carries the estimate's answers
and line items for that trade, the jurisdiction (city/state) and the code
edition, and a reference list of requirements (inspection_refs.py) that the APP
provides. The AI checks the estimate against that list and answers with STRICT
JSON. A suggested_action may name a price-book item to add; the person adds it
with one click (apply_item), as a hand-entered line in "Other lines", so a later
re-price of the trade never deletes it.

A run reviews one trade (module_id given) or every construction trade on the
estimate with a reference list. A run is atomic: a parse failure on any trade
aborts the whole run and stores nothing from it.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

from estimator.agents import ai_log, providers, roles
from estimator.context import RequestContext
from estimator.errors import EstimatorError, InvalidInput, NotFound
from estimator.estimating import service
from estimator.estimating.inspection_refs import (
    NO_CHECKLIST, REFERENCE_REQUIREMENTS, TRADE_CODE, has_references)
from estimator.estimating.zip_lookup import code_edition, lookup_zip, parse_zip_from_address
from estimator.pricing.price_book import get_price

ROLE = "inspector"              # the agent role that turns this on (roles.py)
STATUSES = ("pass", "flag", "missing")

AHJ_NOTE = ("Local amendments vary by jurisdiction — flag anything that depends on a local amendment as "
            "'verify with the AHJ' rather than asserting it.")


def _trade_name(module_id: str) -> str:
    """The trade's display name from the registry ('Windows and Doors'), or plain words."""
    try:
        from estimator.modules import get_registry
        return get_registry().get(module_id).name
    except Exception:  # noqa: BLE001 - without the registry the id still reads
        return module_id.replace("_", " ")


def _system_prompt(module_id: str) -> str:
    """The system prompt for one trade: its name, its code, and the STRICT JSON shape."""
    name = _trade_name(module_id)
    lower = name if name.isupper() else name.lower()
    article = "an" if lower[:1] in "aeiou" or name == "HVAC" else "a"
    first = REFERENCE_REQUIREMENTS[module_id][0]
    return (
        f"You are {article} {lower} inspection assistant reviewing a residential {lower} estimate against "
        f"{TRADE_CODE.get(module_id, 'the Florida Building Code')}. "
        "Check the estimate ONLY against the reference list of requirements in "
        "the request — do not add other code sections and do not invent requirements. "
        "For each requirement say whether the estimate passes it, flags a concern, or is missing it. "
        "Reply with ONLY one JSON object, nothing else: "
        f'{{"checklist": [{{"id": "{first["id"]}", "description": "...", "code_ref": "{first["code_ref"]}", '
        '"status": "pass|flag|missing", '
        '"note": "...", "suggested_action": {"price_key": "...", "quantity": 1, "unit": "ea", '
        '"description": "..."}}]}. '
        "A suggested_action names a price-book item to add to the estimate; include one only when something is "
        "missing or flagged and a standard item fixes it. " + AHJ_NOTE)


# The electrical prompt, kept for callers that still import it.
SYSTEM_PROMPT = _system_prompt("electrical")


class InspectionReviewError(EstimatorError):
    """The review couldn't run or the AI's answer couldn't be used. The message is safe to show."""
    code = "not_available"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ the setting

def inspector_setting(conn, company_id: str) -> dict:
    """The Inspector setting: on when the inspector role has an API provider (like llm_takeoff.llm_setting)."""
    cfg = roles.get_role(conn, company_id, ROLE)
    enabled = cfg["provider"] in providers.API_PROVIDERS
    return {"enabled": enabled,
            "provider": cfg["provider"] if enabled else None,
            "provider_label": providers.PROVIDER_LABELS[cfg["provider"]] if enabled else None,
            "model": cfg["model"] if enabled else None,
            "ready": bool(cfg["ready"]) if enabled else False,
            "why_not": cfg["why_not"] if enabled else "",
            "fallback_provider": cfg.get("fallback_provider") if enabled else None}


# ------------------------------------------------------------------ the prompt

def _answer_lines(answers: dict, module_id: str) -> str:
    """The trade's answers as 'Label: value' lines (choice values shown as their labels)."""
    questions = {}
    try:
        from estimator.modules import get_registry
        questions = {q.id: q for q in get_registry().get(module_id).questions}
    except Exception:  # noqa: BLE001 - without the registry the raw ids still read
        pass
    out = []
    for qid, value in (answers or {}).items():
        if value is None:
            continue
        q = questions.get(qid)
        label = q.label if q else qid.replace("_", " ")
        if q is not None and q.choices:
            value = next((c["label"] for c in q.choices
                          if str(c["value"]) == str(value) or str(c.get("factor")) == str(value)), value)
        elif isinstance(value, bool):
            value = "yes" if value else "no"
        out.append(f"- {label}: {value}")
    return "\n".join(out) or "- (no answers recorded)"


def _edition_text(edition: dict, module_id: str) -> str:
    """The edition line for the prompt: the NEC year for electrical, the code edition otherwise."""
    if not edition["edition"]:
        return "unknown — " + edition["note"]
    if module_id == "electrical":
        return f"{edition['edition']} NEC under {edition['code']}"
    return edition["code"]


def build_prompt(est: dict, section: dict, jurisdiction: dict, edition: dict,
                 module_id: str) -> tuple[str, str]:
    """(system, user) for one trade's review: that trade's answers and lines, the jurisdiction
    and code edition, and the reference requirements the AI checks against."""
    name = _trade_name(module_id)
    lower = name if name.isupper() else name.lower()
    lines = ["- %s %s — %s" % (ln["quantity"], ln["unit"], ln["description"]) for ln in section["lines"]]
    if jurisdiction.get("city"):
        place = f"{jurisdiction['city']}, {jurisdiction['state']} ({jurisdiction['state_abbr']})"
    else:
        place = (f"unknown — the zip lookup was unreachable, so the city and state are unverified "
                 f"(zip {jurisdiction['zip']})")
    refs = "\n".join(f"- [{r['id']}] {r['description']} ({r['code_ref']})"
                     + (f" — {r['note']}" if r.get("note") else "")
                     for r in REFERENCE_REQUIREMENTS[module_id])
    user = (
        f"Estimate: {est['title']} (#{est['id']}) — {est.get('address') or 'no address'}\n"
        f"Job zip code: {jurisdiction['zip']}\n"
        f"Jurisdiction: {place}\n"
        f"Code edition: {_edition_text(edition, module_id)}\n"
        "(The edition that governs a job is set by the permit application date; this review uses the "
        "current date to pick the edition.)\n"
        f"\n{name} answers:\n" + _answer_lines(section.get("answers") or {}, module_id) +
        "\n\nLine items:\n" + ("\n".join(lines) or "- (no lines priced)") +
        f"\n\nReference — residential {lower} requirements to check the estimate against "
        "(do not add other code sections):\n" + refs +
        "\n\n" + AHJ_NOTE +
        "\n\nReply with ONLY one JSON object: {\"checklist\": [{\"id\", \"description\", \"code_ref\", "
        "\"status\": \"pass|flag|missing\", \"note\", \"suggested_action\"}]}. "
        "A suggested_action is {\"price_key\", \"quantity\", \"unit\", \"description\"}; include one only "
        "when a standard price-book item fixes a missing or flagged item.")
    return _system_prompt(module_id), user


# ------------------------------------------------------------------ the answer

def parse_review_response(text: str) -> list[dict]:
    """The AI's reply as a validated checklist. Anything wrong rejects the whole response -
    never a partial checklist."""
    t = re.sub(r"^```(?:json)?|```$", "", (text or "").strip(), flags=re.M).strip()
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        raise InspectionReviewError("the AI didn't answer with JSON")
    try:
        obj = json.loads(t[start:end + 1])
    except ValueError as exc:
        raise InspectionReviewError(f"the AI's JSON couldn't be read: {exc}") from None
    if not isinstance(obj, dict) or not isinstance(obj.get("checklist"), list):
        raise InspectionReviewError("the AI's answer has no checklist")
    out, seen = [], set()
    for i, item in enumerate(obj["checklist"]):
        where = f"checklist item {i + 1}"
        if not isinstance(item, dict):
            raise InspectionReviewError(f"{where} isn't an object")
        for key in ("id", "description", "code_ref", "status"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise InspectionReviewError(f"{where} is missing {key}")
        if item["status"] not in STATUSES:
            raise InspectionReviewError(f"{where} has status '{item['status']}' (pass, flag or missing)")
        if item["id"] in seen:
            raise InspectionReviewError(f"checklist item '{item['id']}' appears twice")
        seen.add(item["id"])
        clean = {"id": item["id"].strip()[:80], "description": item["description"].strip()[:500],
                 "code_ref": item["code_ref"].strip()[:80], "status": item["status"],
                 "note": str(item.get("note") or "").strip()[:500]}
        action = item.get("suggested_action")
        if action is not None:
            if not isinstance(action, dict) or not isinstance(action.get("price_key"), str) \
                    or not action["price_key"].strip():
                raise InspectionReviewError(f"{where} has a suggested action without a price_key")
            qty = action.get("quantity", 1)
            if isinstance(qty, bool) or not isinstance(qty, (int, float)) or qty <= 0:
                raise InspectionReviewError(f"{where} has a suggested quantity that isn't a positive number")
            clean["suggested_action"] = {"price_key": action["price_key"].strip()[:100], "quantity": qty,
                                         "unit": str(action.get("unit") or "").strip()[:20],
                                         "description": str(action.get("description") or "").strip()[:200]}
        out.append(clean)
    if not out:
        raise InspectionReviewError("the AI's answer has an empty checklist")
    return out


# ------------------------------------------------------------------ the call

def _call(conn, ctx: RequestContext, cfg: dict, est: dict, system: str, user: str,
          purpose: str = "Inspection review") -> tuple[str, str, str, int]:
    """One text call on the main provider, then the backup. (text, provider, model, AI Log id).

    Follows llm_takeoff._call: the budget is checked first; every attempt's
    usage is recorded (agents/roles.py), including failed ones; every attempt
    is written to the AI Log (agents/ai_log.py) - the prompt, the reply (or
    the error), tokens and cost. The caller fills in the parsed result after.
    """
    ok_budget, why = roles.budget_left(conn, ctx.company_id)
    if not ok_budget:
        raise InspectionReviewError(f"the inspection review can't run: {why}")
    errors = []
    for which in [p for p in (cfg["provider"], cfg.get("fallback_provider")) if p]:
        ok, why = providers.ready(which)
        if not ok:
            errors.append(f"{which}: {why}")
            continue
        model = providers.model_for_step(which, ROLE, "review",
                                         cfg.get("model_pinned") if which == cfg["provider"] else None)
        started = time.monotonic()
        try:
            text, usage = providers.ask(which, system, user, model)
        except providers.ProviderError as exc:
            roles.record_usage(conn, ctx, task_id=None, role=ROLE, provider=which, model=model,
                               usage=None, ok=False, error=str(exc))
            ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose,
                          system_prompt=system, user_prompt=user, estimate_id=est["id"],
                          duration_ms=int((time.monotonic() - started) * 1000), ok=False, error=str(exc))
            errors.append(f"{which}: {exc}")
            continue
        roles.record_usage(conn, ctx, task_id=None, role=ROLE, provider=which, model=model,
                           usage=usage, ok=True)
        log_id = ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose,
                               system_prompt=system, user_prompt=user, estimate_id=est["id"],
                               response_text=text, usage=usage,
                               duration_ms=int((time.monotonic() - started) * 1000))
        return text, which, model, log_id
    raise InspectionReviewError("the AI couldn't answer: " + "; ".join(errors))


# ------------------------------------------------------------------ running and reading reviews

def _shape(row) -> dict:
    return {"id": row["id"], "estimate_id": row["estimate_id"], "module_id": row["module_id"],
            "zip_code": row["zip_code"],
            "jurisdiction": json.loads(row["jurisdiction_json"] or "{}"),
            "code_edition": row["nec_edition"],
            "checklist": json.loads(row["checklist_json"]),
            "status": row["status"], "created_by": row["created_by"], "created_at": row["created_at"]}


def latest_review(conn, company_id: str, estimate_id: int, module_id: str | None = None) -> dict | None:
    """The estimate's latest inspection review, or the latest for one trade, or None."""
    if module_id is None:
        row = conn.execute("SELECT * FROM inspection_reviews WHERE company_id = ? AND estimate_id = ?"
                           " ORDER BY id DESC LIMIT 1", (company_id, estimate_id)).fetchone()
    else:
        row = conn.execute("SELECT * FROM inspection_reviews WHERE company_id = ? AND estimate_id = ?"
                           " AND module_id = ? ORDER BY id DESC LIMIT 1",
                           (company_id, estimate_id, module_id)).fetchone()
    return _shape(row) if row else None


def latest_reviews(conn, company_id: str, estimate_id: int) -> dict[str, dict]:
    """The estimate's latest review per trade, {module_id: review}."""
    rows = conn.execute("SELECT * FROM inspection_reviews WHERE company_id = ? AND estimate_id = ?"
                        " ORDER BY id DESC", (company_id, estimate_id)).fetchall()
    out = {}
    for row in rows:
        out.setdefault(row["module_id"], _shape(row))
    return out


def reviewable_on(est: dict) -> list[str]:
    """The module_ids on this estimate with a reference list, in estimate order."""
    seen, out = set(), []
    for s in est["sections"]:
        if s["module_id"] not in seen and has_references(s["module_id"]):
            seen.add(s["module_id"])
            out.append(s["module_id"])
    return out


def _no_checklist_message(module_id: str) -> str:
    """Why one trade can't be reviewed: its own reason, or that services aren't reviewed."""
    name = _trade_name(module_id)
    if module_id in NO_CHECKLIST:
        return f"the {name} trade has no inspection checklist — {NO_CHECKLIST[module_id]}"
    return (f"the {name} trade has no inspection checklist —"
            " the Inspector reviews construction trades only")


def run_review(conn, ctx: RequestContext, estimate_id: int, zip_code: str | None = None,
               module_id: str | None = None, *, on_date=None) -> dict:
    """Run the inspection review and store it. Returns {"reviews": [one shaped review per trade]}.

    With module_id, only that trade is reviewed (it must be on the estimate and
    have a reference list); without it, every construction trade on the estimate
    with a reference list is reviewed, one LLM call per trade. The zip comes from
    the caller or the estimate's address; the jurisdiction comes from the zip
    lookup (unverified when the lookup is unreachable, and the review still
    runs). Refuses when the Inspector role is off or has no ready provider, when
    there's no zip, and when no trade on the estimate has a checklist. A parse
    failure on any trade aborts the whole run and stores nothing from it.
    """
    service._require_edit_role(ctx)  # EDIT_ROLES: it costs money and stores a review
    est = service.get_estimate(conn, ctx, estimate_id)
    if module_id is not None:
        module_id = str(module_id).strip()
        section = next((s for s in est["sections"] if s["module_id"] == module_id), None)
        if section is None:
            raise InvalidInput(f"estimate {estimate_id} has no {_trade_name(module_id)} section",
                               estimate_id=estimate_id)
        if not has_references(module_id):
            raise InvalidInput(_no_checklist_message(module_id), estimate_id=estimate_id)
        targets = [(module_id, section)]
    else:
        targets, seen = [], set()
        for s in est["sections"]:
            if s["module_id"] in seen or not has_references(s["module_id"]):
                continue
            seen.add(s["module_id"])
            targets.append((s["module_id"], s))
    if not targets:
        raise InvalidInput(f"estimate {estimate_id} has no trade with an inspection checklist —"
                           " the Inspector reviews construction trades only",
                           estimate_id=estimate_id)
    zip_code = (zip_code or "").strip() or parse_zip_from_address(est.get("address") or "")
    if not zip_code:
        raise InvalidInput("no zip code: the estimate's address has none — give a zip code to run the review",
                           estimate_id=estimate_id)
    if not re.fullmatch(r"\d{5}", zip_code):
        raise InvalidInput(f"'{zip_code}' isn't a zip code (5 digits)", field="zip_code")
    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    if cfg["provider"] not in providers.API_PROVIDERS:
        raise InvalidInput("the Inspector agent is off — turn it on in 🤖 AI agents (Estimator tab)"
                           " to run a code review")
    if not cfg["ready"]:
        raise InvalidInput(f"the Inspector agent can't run yet: {cfg['why_not'] or 'its provider is not ready'}")
    place = lookup_zip(zip_code, conn)
    jurisdiction = dict(place) if place else {"zip": zip_code, "city": None, "state": None,
                                              "state_abbr": None}
    jurisdiction["verified"] = place is not None
    done = []
    for mid, section in targets:
        edition = code_edition(jurisdiction["state_abbr"], mid, on_date)
        system, user = build_prompt(est, section, jurisdiction, edition, mid)
        text, _provider, _model, log_id = _call(conn, ctx, cfg, est, system, user,
                                                purpose=f"Inspection review ({_trade_name(mid)})")
        try:
            checklist = parse_review_response(text)
        except InspectionReviewError as exc:
            ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
            raise InspectionReviewError(
                f"the {_trade_name(mid)} review couldn't be used: {exc}") from None
        ai_log.set_parsed(conn, ctx.company_id, log_id, {"checklist": checklist})
        stored_jurisdiction = dict(jurisdiction)
        stored_jurisdiction["edition"] = edition
        done.append((mid, stored_jurisdiction, edition, checklist))
    with service.transaction(conn):
        ids = []
        for mid, jur, edition, checklist in done:
            cur = conn.execute("INSERT INTO inspection_reviews (company_id, estimate_id, module_id, zip_code,"
                               " jurisdiction_json, nec_edition, checklist_json, status, created_by, created_at)"
                               " VALUES (?,?,?,?,?,?,?,?,?,?)",
                               (ctx.company_id, estimate_id, mid, zip_code, json.dumps(jur),
                                edition["edition"], json.dumps(checklist), "complete", ctx.actor, _now()))
            ids.append(int(cur.lastrowid))
    rows = [conn.execute("SELECT * FROM inspection_reviews WHERE id = ?", (rid,)).fetchone() for rid in ids]
    return {"reviews": [_shape(row) for row in rows]}


# ------------------------------------------------------------------ applying a suggested item

def apply_item(conn, ctx: RequestContext, estimate_id: int, review_id: int, item_id: str, rev: int) -> dict:
    """Add one checklist item's suggested price-book item as a hand-entered line.

    The line goes in the default 'custom' section ("Other lines"), so a later
    re-price of the trade never deletes it. The estimate must still be editable
    (add_line_item checks that, the role and the revision).
    """
    row = conn.execute("SELECT * FROM inspection_reviews WHERE id = ? AND company_id = ? AND estimate_id = ?",
                       (review_id, ctx.company_id, estimate_id)).fetchone()
    if row is None:
        raise NotFound(f"inspection review {review_id} not found on estimate {estimate_id}",
                       estimate_id=estimate_id, review_id=review_id)
    checklist = json.loads(row["checklist_json"])
    item = next((c for c in checklist if c["id"] == item_id), None)
    if item is None:
        raise NotFound(f"checklist item '{item_id}' isn't in review {review_id}", item_id=item_id)
    action = item.get("suggested_action")
    if not action:
        raise InvalidInput(f"'{item['description']}' has no item to add", item_id=item_id)
    price = get_price(conn, ctx.company_id, action["price_key"])
    if price is None:
        raise NotFound(f"no price '{action['price_key']}' in the price book", price_key=action["price_key"])
    return service.add_line_item(conn, ctx, estimate_id, rev, kind=price.kind,
                                 description=action.get("description") or price.description,
                                 quantity=action.get("quantity", 1), unit=price.unit,
                                 price_key=action["price_key"])

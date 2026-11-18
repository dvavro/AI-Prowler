"""The Inspector agent: an AI-powered inspection audit and checklist for electrical estimates.

(2026-11-18, David): before the final quote is approved, the estimate can be
checked against the residential NEC requirements for the job's zip code. The
Inspector is an agent role (agents/roles.py) - it starts Off, like every
role, and does nothing until the owner picks a provider, so pros who don't
need it see nothing new. Running a review is interactive (no queue, no
detached runner): one LLM call through the providers layer, within the
budget, logged to the AI Log.

The AI matches, it does not invent: the prompt carries the estimate's
electrical answers and line items, the jurisdiction (city/state) and the NEC
edition, and a reference list of residential NEC requirements
(REFERENCE_REQUIREMENTS, below) that the APP provides. The AI checks the
estimate against that list and answers with STRICT JSON. A suggested_action
may name a price-book item to add; the person adds it with one click
(apply_item), as a hand-entered line in "Other lines", so a later re-price of
the electrical trade never deletes it.
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
from estimator.estimating.zip_lookup import lookup_zip, nec_edition, parse_zip_from_address
from estimator.pricing.price_book import get_price

ROLE = "inspector"              # the agent role that turns this on (roles.py)
MODULE_ID = "electrical"        # the only trade this reviews, for now
STATUSES = ("pass", "flag", "missing")

# Residential NEC requirements (2020), verified facts the app provides - the AI
# checks the estimate against this list, it does not make up code sections.
# The wire-gauge limits are 240.4(D) (14/12/10 AWG) with 8 AWG from Table 310.16.
REFERENCE_REQUIREMENTS = (
    {"id": "afci", "description": "AFCI protection on bedroom and living-area circuits",
     "code_ref": "210.12"},
    {"id": "gfci", "description": "GFCI protection in bathrooms, kitchens, garage, laundry, outdoors,"
                                 " basement/crawl — all 125–250V receptacles in those areas",
     "code_ref": "210.8"},
    {"id": "kitchen_circuits", "description": "Two 20A small-appliance circuits in the kitchen",
     "code_ref": "210.11(C)(1)"},
    {"id": "laundry_circuit", "description": "Dedicated 20A laundry circuit",
     "code_ref": "210.11(C)(2)"},
    {"id": "bathroom_circuit", "description": "Dedicated 20A bathroom circuit",
     "code_ref": "210.11(C)(3)"},
    {"id": "receptacle_spacing", "description": "A receptacle within 6 ft of any point along a wall",
     "code_ref": "210.52(A)"},
    {"id": "tamper_resistant", "description": "Tamper-resistant receptacles",
     "code_ref": "406.12"},
    {"id": "tub_clearance", "description": "No receptacle within 3 ft horizontal / 8 ft vertical of the tub rim",
     "code_ref": "406.9(C)"},
    {"id": "switched_light", "description": "Switch-controlled light in every habitable room, hallway and garage",
     "code_ref": "210.70(A)"},
    {"id": "outdoor_receptacles", "description": "Outdoor receptacle at the front and the back",
     "code_ref": "210.52(E)"},
    {"id": "service_receptacle", "description": "A receptacle within 25 ft of equipment needing service",
     "code_ref": "210.63"},
    {"id": "surge_protection", "description": "Whole-house surge protection device",
     "code_ref": "230.67"},
    {"id": "panel_clearance", "description": "Panel working clearance 30\"W x 36\"D x 6.5'H",
     "code_ref": "110.26"},
    {"id": "panel_directory", "description": "Panel directory labeled",
     "code_ref": "408.4"},
    {"id": "subpanel_grounds", "description": "Neutral and ground separated in subpanels",
     "code_ref": "250.24(A)(5)"},
    {"id": "grounding_electrode", "description": "Grounding electrode system",
     "code_ref": "250.50"},
    {"id": "wire_gauge", "description": "Wire gauge matches the breaker"
                                        " (14 AWG/15A, 12 AWG/20A, 10 AWG/30A, 8 AWG/40A)",
     "code_ref": "240.4(D), Table 310.16"},
    {"id": "smoke_co", "description": "Hardwired interconnected smoke/CO detectors",
     "code_ref": "NFPA 72"},
)

AHJ_NOTE = ("Local amendments vary by jurisdiction — flag anything that depends on a local amendment as "
            "'verify with the AHJ' rather than asserting it.")

SYSTEM_PROMPT = (
    "You are an electrical inspection assistant reviewing a residential electrical estimate against the "
    "National Electrical Code (NEC). Check the estimate ONLY against the reference list of requirements in "
    "the request — do not add other code sections and do not invent requirements. "
    "For each requirement say whether the estimate passes it, flags a concern, or is missing it. "
    "Reply with ONLY one JSON object, nothing else: "
    '{"checklist": [{"id": "gfci", "description": "...", "code_ref": "210.8", "status": "pass|flag|missing", '
    '"note": "...", "suggested_action": {"price_key": "...", "quantity": 1, "unit": "ea", '
    '"description": "..."}}]}. '
    "A suggested_action names a price-book item to add to the estimate; include one only when something is "
    "missing or flagged and a standard item fixes it. " + AHJ_NOTE)


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

def _answer_lines(answers: dict) -> str:
    """The electrical answers as 'Label: value' lines (choice values shown as their labels)."""
    questions = {}
    try:
        from estimator.modules import get_registry
        questions = {q.id: q for q in get_registry().get(MODULE_ID).questions}
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


def build_prompt(est: dict, jurisdiction: dict, nec: dict) -> tuple[str, str]:
    """(system, user) for one review: the estimate's answers and lines, the jurisdiction and NEC
    edition, and the reference requirements the AI checks against."""
    elec = next(s for s in est["sections"] if s["module_id"] == MODULE_ID)
    lines = ["- %s %s — %s" % (ln["quantity"], ln["unit"], ln["description"]) for ln in elec["lines"]]
    if jurisdiction.get("city"):
        place = f"{jurisdiction['city']}, {jurisdiction['state']} ({jurisdiction['state_abbr']})"
    else:
        place = (f"unknown — the zip lookup was unreachable, so the city and state are unverified "
                 f"(zip {jurisdiction['zip']})")
    if nec["edition"]:
        edition = f"{nec['edition']} NEC under {nec['code']}"
    else:
        edition = "unknown — " + nec["note"]
    refs = "\n".join(f"- [{r['id']}] {r['description']} (NEC {r['code_ref']})"
                     for r in REFERENCE_REQUIREMENTS)
    user = (
        f"Estimate: {est['title']} (#{est['id']}) — {est.get('address') or 'no address'}\n"
        f"Job zip code: {jurisdiction['zip']}\n"
        f"Jurisdiction: {place}\n"
        f"NEC edition: {edition}\n"
        "(The edition that governs a job is set by the permit application date; this review uses the "
        "current date to pick the edition.)\n"
        "\nElectrical answers:\n" + _answer_lines(elec.get("answers") or {}) +
        "\n\nLine items:\n" + ("\n".join(lines) or "- (no lines priced)") +
        "\n\nReference — residential NEC requirements to check the estimate against "
        "(do not add other code sections):\n" + refs +
        "\n\n" + AHJ_NOTE +
        "\n\nReply with ONLY one JSON object: {\"checklist\": [{\"id\", \"description\", \"code_ref\", "
        "\"status\": \"pass|flag|missing\", \"note\", \"suggested_action\"}]}. "
        "A suggested_action is {\"price_key\", \"quantity\", \"unit\", \"description\"}; include one only "
        "when a standard price-book item fixes a missing or flagged item.")
    return SYSTEM_PROMPT, user


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

def _call(conn, ctx: RequestContext, cfg: dict, est: dict, system: str, user: str) -> tuple[str, str, str, int]:
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
            ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose="Inspection review",
                          system_prompt=system, user_prompt=user, estimate_id=est["id"],
                          duration_ms=int((time.monotonic() - started) * 1000), ok=False, error=str(exc))
            errors.append(f"{which}: {exc}")
            continue
        roles.record_usage(conn, ctx, task_id=None, role=ROLE, provider=which, model=model,
                           usage=usage, ok=True)
        log_id = ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose="Inspection review",
                               system_prompt=system, user_prompt=user, estimate_id=est["id"],
                               response_text=text, usage=usage,
                               duration_ms=int((time.monotonic() - started) * 1000))
        return text, which, model, log_id
    raise InspectionReviewError("the AI couldn't answer: " + "; ".join(errors))


# ------------------------------------------------------------------ running and reading reviews

def _shape(row) -> dict:
    return {"id": row["id"], "estimate_id": row["estimate_id"], "zip_code": row["zip_code"],
            "jurisdiction": json.loads(row["jurisdiction_json"] or "{}"),
            "nec_edition": row["nec_edition"],
            "checklist": json.loads(row["checklist_json"]),
            "status": row["status"], "created_by": row["created_by"], "created_at": row["created_at"]}


def latest_review(conn, company_id: str, estimate_id: int) -> dict | None:
    """The estimate's latest inspection review, or None."""
    row = conn.execute("SELECT * FROM inspection_reviews WHERE company_id = ? AND estimate_id = ?"
                       " ORDER BY id DESC LIMIT 1", (company_id, estimate_id)).fetchone()
    return _shape(row) if row else None


def run_review(conn, ctx: RequestContext, estimate_id: int, zip_code: str | None = None, *,
               on_date=None) -> dict:
    """Run one inspection review on an electrical estimate and store it. Returns the review.

    The zip comes from the caller or the estimate's address; the jurisdiction
    comes from the zip lookup (unverified when the lookup is unreachable, and
    the review still runs). Refuses when the Inspector role is off or has no
    ready provider, when there's no zip, and when the estimate has no
    electrical section.
    """
    service._require_edit_role(ctx)  # EDIT_ROLES: it costs money and stores a review
    est = service.get_estimate(conn, ctx, estimate_id)
    if not any(s["module_id"] == MODULE_ID for s in est["sections"]):
        raise InvalidInput(f"estimate {estimate_id} has no electrical section;"
                           " the inspection review checks electrical estimates", estimate_id=estimate_id)
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
    nec = nec_edition(jurisdiction["state_abbr"], on_date)
    jurisdiction["nec"] = nec
    system, user = build_prompt(est, jurisdiction, nec)
    text, _provider, _model, log_id = _call(conn, ctx, cfg, est, system, user)
    try:
        checklist = parse_review_response(text)
    except InspectionReviewError as exc:
        ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
        raise
    ai_log.set_parsed(conn, ctx.company_id, log_id, {"checklist": checklist})
    with service.transaction(conn):
        cur = conn.execute("INSERT INTO inspection_reviews (company_id, estimate_id, zip_code, jurisdiction_json,"
                           " nec_edition, checklist_json, status, created_by, created_at)"
                           " VALUES (?,?,?,?,?,?,?,?,?)",
                           (ctx.company_id, estimate_id, zip_code, json.dumps(jurisdiction),
                            nec["edition"], json.dumps(checklist), "complete", ctx.actor, _now()))
        rid = int(cur.lastrowid)
    row = conn.execute("SELECT * FROM inspection_reviews WHERE id = ?", (rid,)).fetchone()
    return _shape(row)


# ------------------------------------------------------------------ applying a suggested item

def apply_item(conn, ctx: RequestContext, estimate_id: int, review_id: int, item_id: str, rev: int) -> dict:
    """Add one checklist item's suggested price-book item as a hand-entered line.

    The line goes in the default 'custom' section ("Other lines"), so a later
    re-price of the electrical trade never deletes it. The estimate must still
    be editable (add_line_item checks that, the role and the revision).
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

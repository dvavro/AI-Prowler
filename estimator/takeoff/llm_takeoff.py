"""LLM-assisted takeoff: read the foundation sheet with the AI when geometry finds nothing.

Phase 1 of the Concrete agent auto-run finds the slab from the drawing's own lines
(estimator/takeoff/slab_find.py, no LLM, no cost). Some plans don't draw the slab
outline as axis-aligned lines at all - the NSB shed slab's foundation sheet has only
diagonal detail lines and small labels, so no rectangle can form. For those sheets,
the auto-run falls back to the AI reading the plan - but only when the owner turned
the LLM takeoff role on (agents/roles.py: "llm_takeoff", off by default), and only
when a person starts the auto-run.

    1. classify: which sheet of the plan set is the foundation plan? The trade's
       sheet rules (agent_configs, e.g. titles like "foundation") shortlist the
       sheets; when they don't settle it, the AI picks from thumbnails.
    2. read: the AI reads the slab's overall dimensions and the footing detail
       from the foundation sheet image, and answers with strict JSON.
    3. the APP does the maths: the dimension strings are parsed with
       slab_find.parse_feet_inches and the area and perimeter are computed here.
       The LLM never computes and never invents - a dimension it can't read comes
       back null, and then the run fails with a clear message instead of a fake
       measurement.
    4. the measurements (slab area, footer length, form length) are proposed like
       any other, marked proposed_by "llm-takeoff" with full provenance in their
       calc, and still need a person to approve them.

Images go through drawing_model/crops.prepare like every other image the Estimator
sends to an AI: each send is logged in ai_send_log. A whole sheet is only sent
because a person asked for it - the person who clicked auto-run - and the owner
opted in by turning the role on; the runner derives a person context (no agent)
for the prepare call on that basis.

Cost: every call goes through the provider/budget system (agents/providers.py,
agents/roles.py) - the budget is checked before calling, usage is recorded after,
and the role's backup provider is tried when the first one fails. Every call is
also written to the AI Log (agents/ai_log.py) - the prompt, the images, the reply,
the parsed result, tokens and cost - including failed calls, so a run that fails
still shows what the AI was given and what came back. Tests never call a real
LLM: providers.set_provider(fake) stands in for Claude and Grok.
"""
from __future__ import annotations

import base64
import io
import json
import re
import time
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

from estimator.agents import ai_log, providers, roles
from estimator.context import RequestContext
from estimator.errors import EstimatorError
from estimator.estimating import service
from estimator.takeoff import slab_find

ROLE = "llm_takeoff"              # the agent role that turns this on (roles.py)
PROPOSED_BY = "llm-takeoff"       # proposed_by on every measurement the LLM makes
MODULE_ID = "concrete"            # Phase 1: only the concrete agent reads plans
CANDIDATE_ID = "llm"              # the run's pseudo-candidate (no drawn outline)
CLASSIFY_MAX_SHEETS = 8           # thumbnails in one classify call (token cost)
CLASSIFY_MAX_PX = 768             # long side of a classify thumbnail
MAX_HINT_LABELS = 40              # dimension/text labels offered as hints to the reader


class LlmTakeoffError(Exception):
    """The LLM fallback couldn't run or couldn't read the plan. The message is safe to show."""


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _qty2(value) -> str:
    return str(Decimal(str(value)).quantize(Decimal("0.01")))


# ------------------------------------------------------------------ the setting

def llm_setting(conn, company_id: str) -> dict:
    """The LLM-takeoff setting: on when the llm_takeoff role has an API provider."""
    cfg = roles.get_role(conn, company_id, ROLE)
    enabled = cfg["provider"] in providers.API_PROVIDERS
    return {"enabled": enabled,
            "provider": cfg["provider"] if enabled else None,
            "provider_label": providers.PROVIDER_LABELS[cfg["provider"]] if enabled else None,
            "model": cfg["model"] if enabled else None,
            "ready": bool(cfg["ready"]) if enabled else False,
            "why_not": cfg["why_not"] if enabled else "",
            "fallback_provider": cfg.get("fallback_provider") if enabled else None}


# ------------------------------------------------------------------ which sheet is the foundation plan

def _sheet_rules(conn, company_id: str, module_id: str) -> dict:
    """Which sheets this trade reads: the company's own rules, else the trade's defaults."""
    from estimator.agent_manager.configs import DEFAULT_SHEET_RULES
    try:
        row = conn.execute("SELECT sheet_rules_json FROM agent_configs WHERE company_id = ? AND module_id = ?",
                           (company_id, module_id)).fetchone()
        if row and row["sheet_rules_json"]:
            rules = json.loads(row["sheet_rules_json"])
            if isinstance(rules, dict) and isinstance(rules.get("prefixes"), list) \
                    and isinstance(rules.get("titles"), list):
                return rules
    except Exception:  # noqa: BLE001 - a bad row just means the defaults
        pass
    return dict(DEFAULT_SHEET_RULES.get(module_id, {"prefixes": [], "titles": []}))


def _sheets_with_images(conn, company_id: str, plan_set_id: int) -> list[dict]:
    """The plan set's sheets that have a rendered image the AI can be shown, in page order."""
    out = []
    for r in conn.execute("SELECT * FROM sheets WHERE company_id = ? AND plan_set_id = ? ORDER BY page_no",
                          (company_id, int(plan_set_id))):
        s = dict(r)
        if s["image_path"] and Path(s["image_path"]).is_file():
            out.append(s)
    return out


def pick_foundation_sheets(conn, company_id: str, plan_set_id: int,
                           hint_sheet_id: int | None = None) -> list[dict]:
    """The plan set's sheets, best foundation-plan match first, each with a score.

    A title word (foundation, slab, ...) is worth 2, a sheet-number prefix (S, A)
    is worth 1, and the sheet the run started on breaks ties. Only sheets with a
    rendered image are listed - the AI can't read a sheet with no picture.
    """
    rules = _sheet_rules(conn, company_id, MODULE_ID)
    titles = [str(w).strip().lower() for w in rules.get("titles") or [] if str(w).strip()]
    prefixes = [str(p).strip().upper() for p in rules.get("prefixes") or [] if str(p).strip()]
    scored = []
    for s in _sheets_with_images(conn, company_id, plan_set_id):
        score = 0.0
        title = (s["title"] or "").lower()
        for w in titles:
            if w in title:
                score += 2
        no = (s["sheet_no"] or "").strip().upper()
        if any(no.startswith(p) for p in prefixes):
            score += 1
        if hint_sheet_id and s["id"] == hint_sheet_id:
            score += 0.5
        scored.append({**s, "score": score})
    scored.sort(key=lambda s: (-s["score"], s["page_no"]))
    return scored


def _sheet_label(s: dict) -> str:
    return f"sheet {s['id']} ({s['sheet_no'] or 'page ' + str(s['page_no'])}" \
        + (f" '{s['title']}'" if s["title"] else "") + ")"


# ------------------------------------------------------------------ the AI calls

CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the foundation plan. "
                   "Reply with ONLY one JSON object, nothing else.")

READ_SYSTEM = ("You are reading a foundation plan to measure the concrete slab. "
               "Reply with ONLY one JSON object, nothing else.")


def _parse_json_object(text: str) -> dict:
    """The AI's reply as a JSON object - tolerant of code fences and chatter around it."""
    t = re.sub(r"^```(?:json)?|```$", "", (text or "").strip(), flags=re.M).strip()
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        raise LlmTakeoffError("the AI didn't answer with JSON")
    try:
        obj = json.loads(t[start:end + 1])
    except ValueError as exc:
        raise LlmTakeoffError(f"the AI's JSON couldn't be read: {exc}") from None
    if not isinstance(obj, dict):
        raise LlmTakeoffError("the AI's answer isn't a JSON object")
    return obj


def parse_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(foundation sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    obj = _parse_json_object(text)
    fid = obj.get("foundation_sheet_id")
    notes = str(obj.get("notes") or "")[:500]
    if fid is None:
        return None, notes
    try:
        fid = int(fid)
    except (TypeError, ValueError):
        return None, notes
    return (fid if fid in set(sheet_ids) else None), notes


def parse_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: dimension strings (or None), footer detail,
    confidence 0-1 (or None), notes. The foundation sheet is the one that was shown,
    whatever id the AI wrote down."""
    obj = _parse_json_object(text)

    def _text(key):
        v = obj.get(key)
        if v is None:
            return None
        if not isinstance(v, str):
            raise LlmTakeoffError(f"the AI's answer has {key} = {v!r}, not text")
        return v.strip() or None

    conf = obj.get("confidence")
    try:
        conf = max(0.0, min(1.0, float(conf))) if conf is not None else None
    except (TypeError, ValueError):
        conf = None
    notes = _text("notes") or ""
    fid = obj.get("foundation_sheet_id")
    try:
        fid = int(fid) if fid is not None else None
    except (TypeError, ValueError):
        fid = None
    if fid is not None and fid != sheet_id:
        notes = (notes + f" (the AI named sheet {fid}, but it was shown sheet {sheet_id})").strip()
    return {"foundation_sheet_id": sheet_id, "slab_width_ft": _text("slab_width_ft"),
            "slab_length_ft": _text("slab_length_ft"), "footer_size": _text("footer_size"),
            "footer_bar": _text("footer_bar"), "confidence": conf, "notes": notes[:500]}


def _call(conn, ctx: RequestContext, cfg: dict, run: dict, system: str, user: str,
          images: list[dict], *, purpose: str, images_refs: list[dict]) -> tuple[str, str, str, int]:
    """One vision call on the main provider, then the backup. (text, provider, model, AI Log id).

    The budget is checked first; every attempt's usage is recorded (agents/roles.py),
    including failed ones, so the budget meter sees the real cost. Every attempt is
    also written to the AI Log (agents/ai_log.py) - the prompt, the images, the reply
    (or the error), tokens and cost - so a failed run still shows what the AI was
    given and what came back. The caller fills in the parsed result afterwards.
    """
    ok_budget, why = roles.budget_left(conn, ctx.company_id)
    if not ok_budget:
        raise LlmTakeoffError(f"LLM takeoff can't run: {why}")
    errors = []
    for which in [p for p in (cfg["provider"], cfg.get("fallback_provider")) if p]:
        ok, why = providers.ready(which)
        if not ok:
            errors.append(f"{which}: {why}")
            continue
        model = providers.model_for(which, cfg["model"] if which == cfg["provider"] else None)
        started = time.monotonic()
        try:
            text, usage = providers.ask_vision(which, system, user, images, model)
        except providers.ProviderError as exc:
            roles.record_usage(conn, ctx, task_id=run["id"], role=ROLE, provider=which, model=model,
                               usage=None, ok=False, error=str(exc))
            ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose,
                          system_prompt=system, user_prompt=user, images=images_refs,
                          auto_run_id=run["id"], estimate_id=run["estimate_id"],
                          duration_ms=int((time.monotonic() - started) * 1000),
                          ok=False, error=str(exc))
            errors.append(f"{which}: {exc}")
            continue
        roles.record_usage(conn, ctx, task_id=run["id"], role=ROLE, provider=which, model=model,
                           usage=usage, ok=True)
        log_id = ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose,
                               system_prompt=system, user_prompt=user, images=images_refs,
                               auto_run_id=run["id"], estimate_id=run["estimate_id"],
                               response_text=text, usage=usage,
                               duration_ms=int((time.monotonic() - started) * 1000))
        return text, which, model, log_id
    raise LlmTakeoffError("the AI couldn't answer: " + "; ".join(errors))


# ------------------------------------------------------------------ the images (through crops.prepare, logged)

def _prepare_image(conn, person_ctx: RequestContext, sheet_id: int, purpose: str,
                   provider: str) -> dict:
    """The sheet image the AI may see, prepared and logged like every other AI send.
    Returns the prepare result: the file to send, plus its ai_send_log row (log_id),
    so the AI Log can point at the image that was actually sent."""
    from estimator.drawing_model import crops
    try:
        return crops.prepare(conn, person_ctx, sheet_id, purpose=purpose, provider=provider,
                             whole_sheet=True, user_asked=True)
    except EstimatorError as exc:
        raise LlmTakeoffError(exc.message) from None


def _image_ref(prepared: dict, sent_max_px: int | None = None) -> dict:
    """One prepared image as the AI Log stores it: the ai_send_log row, the sheet,
    and the file the AI was shown (downscaled to sent_max_px in memory when set)."""
    ref = {"ai_send_log_id": prepared["log_id"], "sheet_id": prepared["sheet_id"],
           "sheet_no": prepared.get("sheet_no"), "kind": prepared["kind"],
           "file_path": prepared["file_path"], "width_px": prepared["width_px"],
           "height_px": prepared["height_px"]}
    if sent_max_px is not None:
        ref["sent_max_px"] = sent_max_px
    return ref


def _image_payload(path, max_side: int | None = None) -> dict:
    """A prepared image as {media_type, data (base64)} - downscaled to max_side when asked."""
    data = Path(path).read_bytes()
    if max_side is None:
        return {"media_type": "image/png", "data": base64.b64encode(data).decode("ascii")}
    try:
        from PIL import Image
    except ImportError:
        return {"media_type": "image/png", "data": base64.b64encode(data).decode("ascii")}
    with Image.open(path) as img:
        if max(img.size) <= max_side:
            return {"media_type": "image/png", "data": base64.b64encode(data).decode("ascii")}
        img = img.convert("RGB")
        img.thumbnail((max_side, max_side))
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=85)
    return {"media_type": "image/jpeg", "data": base64.b64encode(buf.getvalue()).decode("ascii")}


def _hints(conn, company_id: str, sheet_id: int) -> list[str]:
    """Dimension and text labels the drawing model found on the sheet - hints for the
    reader, never the answer: the dimensions are read from the image."""
    labels = []
    for r in conn.execute("SELECT DISTINCT label FROM drawing_objects WHERE company_id = ? AND sheet_id = ?"
                          " AND kind IN ('dimension', 'text') AND label IS NOT NULL AND label != ''"
                          " ORDER BY label LIMIT ?", (company_id, int(sheet_id), MAX_HINT_LABELS)):
        labels.append(r["label"])
    return labels


# ------------------------------------------------------------------ the app's maths (never the LLM's)

def quantities_from_reading(reading: dict) -> dict:
    """Area and perimeter from the dimensions the AI read. Both dimensions must be
    present and parseable - anything else fails loudly instead of guessing."""
    missing = [name for name, key in (("width", "slab_width_ft"), ("length", "slab_length_ft"))
               if not reading.get(key)]
    if missing:
        raise LlmTakeoffError("the AI read the foundation sheet but couldn't read the slab "
                              + " and ".join(missing) + " - it left "
                              + ("it" if len(missing) == 1 else "them")
                              + " blank; measure the slab by hand")
    inches = {}
    for name, key in (("width", "slab_width_ft"), ("length", "slab_length_ft")):
        got = slab_find.parse_feet_inches(reading[key])
        if got is None:
            raise LlmTakeoffError(f"the AI read the slab {name} as {reading[key]!r}, which isn't a length"
                                  " (feet'-inches\"); measure the slab by hand")
        inches[key] = got
    w_ft = Decimal(str(inches["slab_width_ft"])) / Decimal(12)
    h_ft = Decimal(str(inches["slab_length_ft"])) / Decimal(12)
    area = (w_ft * h_ft).quantize(Decimal("0.01"))
    perim = ((w_ft + h_ft) * 2).quantize(Decimal("0.01"))
    return {"width_ft": _qty2(w_ft), "height_ft": _qty2(h_ft), "width_in": inches["slab_width_ft"],
            "height_in": inches["slab_length_ft"], "area_sqft": str(area), "perimeter_lf": str(perim)}


def llm_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape slab candidates use.
    No corners or drawing objects - there is no drawn outline."""
    return {"id": CANDIDATE_ID, "source": "llm",
            "label": f"{reading['slab_width_ft']} x {reading['slab_length_ft']} (read by the AI)",
            "width_ft": float(quantities["width_ft"]), "height_ft": float(quantities["height_ft"]),
            "area_sqft": float(quantities["area_sqft"]), "perimeter_lf": float(quantities["perimeter_lf"]),
            "foundation_sheet_id": reading["foundation_sheet_id"], "provider": provider, "model": model}


# ------------------------------------------------------------------ the measurements

def create_measurements(conn, ctx: RequestContext, run: dict, reading: dict, quantities: dict,
                        provider: str, model: str) -> list[int]:
    """Propose the slab, footer and form measurements from the quantities the app
    computed. Proposed, never approved; the calc carries the full provenance."""
    sheet_id = reading["foundation_sheet_id"]
    if run["sheet_id"] == sheet_id:
        viewport_id = run["viewport_id"]
    else:
        row = conn.execute("SELECT id FROM viewports WHERE sheet_id = ? ORDER BY id LIMIT 1",
                           (sheet_id,)).fetchone()
        viewport_id = row["id"] if row else None
    dims = f"{reading['slab_width_ft']} x {reading['slab_length_ft']}"
    footer = "".join(x for x in (f", footer {reading['footer_size']}" if reading["footer_size"] else "",
                                 f" {reading['footer_bar']}" if reading["footer_bar"] else ""))
    conf = reading["confidence"]
    made = []
    now = _now()
    planned = [
        ("area", "area_sqft", "Slab (AI)", quantities["area_sqft"], "sqft",
         f"slab area from the dimensions the AI read ({dims})"),
        ("length", "footing_lf", "Footer (AI)", quantities["perimeter_lf"], "lf",
         f"footer length = slab perimeter from the dimensions the AI read ({dims})"),
        ("perimeter", "perimeter_lf", "Forms (AI)", quantities["perimeter_lf"], "lf",
         f"form length = slab perimeter from the dimensions the AI read ({dims})"),
    ]
    with service.transaction(conn):
        for kind, feeds, label, qty, unit, how in planned:
            calc = {"source": "llm", "auto_run_id": run["id"], "candidate_id": CANDIDATE_ID, "how": how,
                    "qty": qty, "slab_width": reading["slab_width_ft"],
                    "slab_length": reading["slab_length_ft"], "footer_size": reading["footer_size"],
                    "footer_bar": reading["footer_bar"], "foundation_sheet_id": sheet_id,
                    "provider": provider, "model": model, "notes": reading["notes"]}
            mid = conn.execute(
                "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id,"
                " kind, label, qty, unit, source_object_ids, calc_json, method, confidence, status, locked,"
                " proposed_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,'[]',?,'ai',?,'proposed',0,?,?,?)",
                (ctx.company_id, run["estimate_id"], MODULE_ID, feeds, sheet_id, viewport_id, kind, label,
                 qty, unit, json.dumps(calc), None if conf is None else str(conf), PROPOSED_BY, now, now)
                ).lastrowid
            service._log(conn, ctx, run["estimate_id"], "measurement_proposed",
                         {"measurement_id": mid, "qty": qty, "unit": unit, "feeds": feeds})
            made.append(mid)
    return made


# ------------------------------------------------------------------ the whole fallback

def run_llm_takeoff(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the foundation sheet with the AI and propose the concrete measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids and the run's pseudo-candidate.
    """
    def step(text):
        if on_step:
            on_step(text)

    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    if cfg["provider"] not in providers.API_PROVIDERS:
        raise LlmTakeoffError("LLM takeoff is off - turn it on in \U0001f916 AI agents (Setup) to let the AI"
                              " read the plan when no slab outline is found")
    ok_budget, why = roles.budget_left(conn, ctx.company_id)
    if not ok_budget:
        raise LlmTakeoffError(f"LLM takeoff can't run: {why}")
    sheet = conn.execute("SELECT * FROM sheets WHERE id = ? AND company_id = ?",
                         (int(run["sheet_id"]), ctx.company_id)).fetchone()
    if sheet is None:
        raise LlmTakeoffError(f"sheet {run['sheet_id']} not found")
    # The sends are person-asked: the person who started this auto-run asked the AI
    # to read the plans, and the owner opted in by turning the role on.
    person_ctx = replace(ctx, agent=None)

    step("finding the foundation sheet")
    ranked = pick_foundation_sheets(conn, ctx.company_id, sheet["plan_set_id"], run["sheet_id"])
    if not ranked:
        raise LlmTakeoffError("none of this plan set's sheets has a rendered image yet - the plan engine makes"
                              " them when it reads the plans")
    foundation = None
    if ranked[0]["score"] > 0 and (len(ranked) == 1 or ranked[0]["score"] > ranked[1]["score"]):
        foundation = ranked[0]          # the sheet rules settle it: no classify call needed
    else:
        shown = ranked[:CLASSIFY_MAX_SHEETS]
        preps = [_prepare_image(conn, person_ctx, s["id"],
                                "LLM takeoff: find the foundation sheet", cfg["provider"]) for s in shown]
        images = [_image_payload(Path(p["file_path"]), CLASSIFY_MAX_PX) for p in preps]
        refs = [_image_ref(p, CLASSIFY_MAX_PX) for p in preps]
        listed = "\n".join(f"{i + 1}. {_sheet_label(s)}" for i, s in enumerate(shown))
        text, _, _, log_id = _call(conn, ctx, cfg, run, CLASSIFY_SYSTEM,
                                   "These are the sheets of one plan set, in order:\n" + listed
                                   + "\nWhich sheet shows the foundation / concrete slab drawing (footings, slab outline,"
                                     " foundation sections)? Reply with ONLY this JSON: {\"foundation_sheet_id\": <the"
                                     " sheet's id, or null if none of these sheets shows a foundation drawing>,"
                                     " \"notes\": \"one line saying why\"}. If you cannot tell, return null - never guess.",
                                   images, purpose="LLM takeoff: find the foundation sheet",
                                   images_refs=refs)
        try:
            found_id, notes = parse_classification(text, [s["id"] for s in shown])
        except LlmTakeoffError as exc:
            ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
            raise
        ai_log.set_parsed(conn, ctx.company_id, log_id,
                          {"foundation_sheet_id": found_id, "notes": notes})
        foundation = next((s for s in shown if s["id"] == found_id), None)
        if foundation is None:
            raise LlmTakeoffError("the AI couldn't tell which sheet is the foundation plan"
                                  + (f" ({notes})" if notes else "")
                                  + " - open the foundation sheet and run it from there")

    step("reading the plan with the AI")
    prep = _prepare_image(conn, person_ctx, foundation["id"],
                          "LLM takeoff: read the slab dimensions", cfg["provider"])
    path = Path(prep["file_path"])
    hints = _hints(conn, ctx.company_id, foundation["id"])
    hint_text = (" Labels the drawing model found on this sheet (hints only - read the dimensions from the"
                 " image, not from these): " + ", ".join(repr(h) for h in hints) + ".") if hints else ""
    text, provider, model, log_id = _call(
        conn, ctx, cfg, run, READ_SYSTEM,
        f"This is {_sheet_label(foundation)} of a plan set. Read the slab's overall dimensions from the"
        f" dimension lines printed on the drawing, and the footing detail (size and bar) if one is shown."
        + hint_text
        + " Reply with ONLY this JSON: {\"foundation_sheet_id\": " + str(foundation["id"])
        + ", \"slab_width_ft\": \"45'-7\\\"\", \"slab_length_ft\": \"46'-7\\\"\", \"footer_size\": \"12x20\","
          " \"footer_bar\": \"#5\", \"confidence\": 0.9, \"notes\": \"one line\"}."
          " Rules: slab_width_ft and slab_length_ft are the dimension strings exactly as printed"
          " (feet'-inches\", e.g. 45'-7\"); if you cannot read a dimension clearly, put null for it and say"
          " so in notes - never guess, never compute, never invent. footer_size is the footing width x depth"
          " as printed (e.g. 12x20) or null; footer_bar is the bar size as printed (e.g. #5) or null."
          " confidence is 0-1, how sure you are about the dimensions you did read.",
        [_image_payload(path)],
        purpose="LLM takeoff: read the slab dimensions", images_refs=[_image_ref(prep)])
    try:
        reading = parse_reading(text, foundation["id"])
    except LlmTakeoffError as exc:
        ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
        raise
    ai_log.set_parsed(conn, ctx.company_id, log_id, reading)
    quantities = quantities_from_reading(reading)

    step("measuring")
    measurement_ids = create_measurements(conn, ctx, run, reading, quantities, provider, model)
    return {"reading": reading, "quantities": quantities, "measurement_ids": measurement_ids,
            "provider": provider, "model": model, "foundation_sheet_id": foundation["id"],
            "candidate": llm_candidate(reading, quantities, provider, model)}

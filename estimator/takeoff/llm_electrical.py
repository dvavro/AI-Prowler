"""LLM-assisted electrical takeoff: count the devices on the electrical plan with the AI.

Phase 1 of the multi-trade AI auto-run. Unlike concrete, there is no geometric
step to try first: the plan engine reads the electrical sheet's symbols but cannot
classify them - sheet 10 of the US standard electrical plan has 44 symbol objects
and zero symbol_detections rows, with block names like 'CE' that mean nothing on
their own - so guessing what a symbol is would invent counts. The AI reads the
plan instead, the same way the concrete LLM takeoff reads the foundation sheet
(estimator/takeoff/llm_takeoff.py), and only when the owner turned the LLM takeoff
role on (agents/roles.py: "llm_takeoff", off by default), and only when a person
starts the auto-run.

    1. find: which sheet of the plan set is the electrical plan? The trade's
       sheet rules (agent_configs, e.g. prefix "E", titles like "electrical")
       shortlist the sheets; when they don't settle it, the AI picks from
       thumbnails. Only sheets switched ON for Electrical are sent to the AI.
    2. read: the AI counts the devices on the electrical sheet image - outlets,
       switches, GFCI outlets, lights, ceiling fans, dedicated 15 Amp and
       30 Amp circuits, low-voltage drops - and answers with strict JSON,
       with the evidence for each count (what was counted, which symbols
       and areas), so a person can check every number.
    3. the measurements (one count per device kind found) are proposed like
       any other, marked proposed_by "llm-takeoff" with full provenance in
       their calc, and still need a person to approve them. A zero count gets
       no measurement row - the run's candidate still carries it, so the
       results show it as 0. Approved counts feed the Electrical trade's
       answers like any other takeoff measurement.

The choices (voltage, box material, type of work, subpanel size) stay
user-answered - the auto-run fills counts only. There is no calibration and
no footer step: counts need no scale.

Images go through drawing_model/crops.prepare like every other image the
Estimator sends to an AI: each send is logged in ai_send_log. A whole sheet is
only sent because a person asked for it - the person who clicked auto-run -
and the owner opted in by turning the role on; the runner derives a person
context (no agent) for the prepare call on that basis.

Cost: every call goes through the provider/budget system (agents/providers.py,
agents/roles.py) - the budget is checked before calling, usage is recorded
after, and the role's backup provider is tried when the first one fails. Every
call is also written to the AI Log (agents/ai_log.py) - the prompt, the images,
the reply, the parsed result, tokens and cost - including failed calls, so a
run that fails still shows what the AI was given and what came back. Tests
never call a real LLM: providers.set_provider(fake) stands in for Claude
and Grok.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from estimator.agents import ai_log, providers, roles
from estimator.context import RequestContext
from estimator.estimating import service
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "electrical"            # this trade's module id (the manifest, the sheet switches)

# The Electrical manifest's count questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary).
COUNT_QUESTIONS = (
    ("outlets", "Outlets", "outlets"),
    ("switches", "Switches", "switches"),
    ("gfci", "GFCI outlets", "GFCI outlets"),
    ("lights", "Light fixtures or recessed lights", "lights"),
    ("fans", "Ceiling fans", "ceiling fans"),
    ("appliance_circuits", "Dedicated 30 Amp circuits (range, dryer, AC, EV charger)",
     "dedicated 30A circuits"),
    ("circuits_15a", "Dedicated 15 Amp circuits (microwave, disposal, fridge)",
     "dedicated 15A circuits"),
    ("low_voltage", "Data or TV drops", "data/TV drops"),
)
COUNT_IDS = tuple(q[0] for q in COUNT_QUESTIONS)
LABELS = {q[0]: q[1] for q in COUNT_QUESTIONS}
PLURALS = {q[0]: q[2] for q in COUNT_QUESTIONS}


def _label(feeds: str) -> str:
    """The measurement label for a count: "Outlets", "Dedicated 30A circuits"."""
    plural = PLURALS[feeds]
    return plural[0].upper() + plural[1:]


# ------------------------------------------------------------------ the AI calls

ELECTRICAL_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the electrical plan. "
                              "Reply with ONLY one JSON object, nothing else.")

ELECTRICAL_READ_SYSTEM = ("You are reading an electrical plan to count the devices on it. "
                          "Reply with ONLY one JSON object, nothing else.")


def parse_electrical_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(electrical sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    obj = lt._parse_json_object(text)
    fid = obj.get("electrical_sheet_id")
    notes = str(obj.get("notes") or "")[:500]
    if fid is None:
        return None, notes
    try:
        fid = int(fid)
    except (TypeError, ValueError):
        return None, notes
    return (fid if fid in set(sheet_ids) else None), notes


def parse_electrical_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: eight whole-number counts (0 when there are
    none - never null), the evidence for each count, confidence 0-1 (or None), notes.
    Any defect rejects the whole answer - a count the AI hedged on is no count at
    all. The electrical sheet is the one that was shown, whatever id the AI wrote down."""
    obj = lt._parse_json_object(text)
    counts = {}
    for feeds in COUNT_IDS:
        if feeds not in obj:
            raise lt.LlmTakeoffError(f"the AI's answer is missing the {feeds} count")
        v = obj[feeds]
        if isinstance(v, bool) or not isinstance(v, int):
            raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v!r}, not a whole number")
        if v < 0:
            raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v}, a negative count")
        counts[feeds] = v
    evidence = obj.get("evidence")
    if evidence is None:
        evidence = {}
    if not isinstance(evidence, dict):
        raise lt.LlmTakeoffError(f"the AI's answer has evidence = {evidence!r}, not an object")
    ev = {}
    for feeds in COUNT_IDS:
        v = evidence.get(feeds)
        if v is None:
            ev[feeds] = ""
        elif isinstance(v, str):
            ev[feeds] = v.strip()[:500]
        else:
            raise lt.LlmTakeoffError(f"the AI's answer has evidence for {feeds} = {v!r}, not text")
    conf = obj.get("confidence")
    try:
        conf = max(0.0, min(1.0, float(conf))) if conf is not None else None
    except (TypeError, ValueError):
        conf = None
    notes = obj.get("notes")
    if notes is None:
        notes = ""
    elif not isinstance(notes, str):
        raise lt.LlmTakeoffError(f"the AI's answer has notes = {notes!r}, not text")
    else:
        notes = notes.strip()
    fid = obj.get("electrical_sheet_id")
    try:
        fid = int(fid) if fid is not None else None
    except (TypeError, ValueError):
        fid = None
    if fid is not None and fid != sheet_id:
        notes = (notes + f" (the AI named sheet {fid}, but it was shown sheet {sheet_id})").strip()
    return {"electrical_sheet_id": sheet_id, "counts": counts, "evidence": ev,
            "confidence": conf, "notes": notes[:500]}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: count the devices on this sheet, with the evidence
    for each count, so a person can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Count the electrical devices shown on it."
        " Count each symbol once, from the drawing itself (use the legend when one is printed):"
        " outlets are standard duplex wall receptacles; switches are light switches (single, 3-way, 4-way,"
        " dimmer); gfci are GFCI or GFI-protected outlets; lights are light fixtures, recessed cans, pendants"
        " and wall lights; fans are ceiling fans; circuits_15a are dedicated 15 Amp circuits (microwave,"
        " disposal, fridge); appliance_circuits are dedicated 30 Amp / 240 V circuits (range, dryer, AC,"
        " EV charger, 240 V receptacles); low_voltage are data, TV/CATV and phone drops."
        " Do not double-count: a GFCI outlet counts as gfci, not outlets; a 240 V receptacle counts as"
        " appliance_circuits, not outlets."
        " Reply with ONLY this JSON: {\"electrical_sheet_id\": " + str(sheet["id"])
        + ", \"outlets\": 12, \"switches\": 4, \"gfci\": 2, \"lights\": 6, \"fans\": 1,"
          " \"circuits_15a\": 1, \"appliance_circuits\": 1, \"low_voltage\": 3, \"confidence\": 0.9,"
          " \"notes\": \"one line\", \"evidence\": {\"outlets\": \"what was counted, which symbols and areas\","
          " \"switches\": \"...\", \"gfci\": \"...\", \"lights\": \"...\", \"fans\": \"...\","
          " \"circuits_15a\": \"...\", \"appliance_circuits\": \"...\", \"low_voltage\": \"...\"}}."
        " Rules: every count is a whole number - answer 0 when there are none, never null, never a guess."
        " evidence says what was counted for each number, so a person can check it; confidence is 0-1,"
        " how sure you are about the counts.")


# ------------------------------------------------------------------ the counts

def quantities_from_reading(reading: dict) -> dict:
    """The counts as the run reports them: all eight questions, plus the total."""
    counts = {feeds: int(reading["counts"][feeds]) for feeds in COUNT_IDS}
    return {"counts": counts, "total_devices": sum(counts.values())}


def electrical_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI counted, in the shape the results page
    reads. It carries every count - including the zeros, which get no measurement row."""
    return {"id": lt.CANDIDATE_ID, "source": "llm", "counts": dict(quantities["counts"]),
            "evidence": dict(reading["evidence"]), "confidence": reading["confidence"],
            "notes": reading["notes"], "sheet_id": reading["electrical_sheet_id"],
            "provider": provider, "model": model}


def _summary(sheet_id: int, quantities: dict, measurement_ids: list[int]) -> str:
    """One line for the runner's log: what was counted, on which sheet."""
    parts = [f"{quantities['counts'][feeds]} {PLURALS[feeds]}"
             for feeds in COUNT_IDS if quantities["counts"][feeds] > 0]
    counted = ", ".join(parts) if parts else "none found"
    return (f"counted {quantities['total_devices']} devices on sheet {sheet_id} ({counted}); "
            f"measurements {measurement_ids}")


# ------------------------------------------------------------------ the measurements

def create_measurements(conn, ctx: RequestContext, run: dict, reading: dict, quantities: dict,
                        provider: str, model: str) -> list[int]:
    """Propose one count measurement per device kind the AI found - a zero count gets
    no row (the candidate still carries it, so the results show it as 0). Proposed,
    never approved; the calc carries the full provenance, including what the AI
    counted. The viewport is the run's: the API picks it when the run starts."""
    sheet_id = reading["electrical_sheet_id"]
    conf = reading["confidence"]
    made = []
    now = lt._now()
    with service.transaction(conn):
        for feeds in COUNT_IDS:
            qty = quantities["counts"][feeds]
            if qty <= 0:
                continue
            how = reading["evidence"].get(feeds) or f"{qty} counted on the electrical plan"
            calc = {"source": "llm", "auto_run_id": run["id"], "candidate_id": lt.CANDIDATE_ID,
                    "how": how, "qty": str(qty), "electrical_sheet_id": sheet_id,
                    "counts": dict(quantities["counts"]),
                    "provider": provider, "model": model, "notes": reading["notes"]}
            mid = conn.execute(
                "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id,"
                " kind, label, qty, unit, source_object_ids, calc_json, geometry_json, method, confidence, status,"
                " locked, proposed_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,'[]',?,?,'ai',?,'proposed',0,?,?,?)",
                (ctx.company_id, run["estimate_id"], MODULE_ID, feeds, sheet_id, run["viewport_id"],
                 "count", f"{_label(feeds)} (AI)", str(qty), "ea", json.dumps(calc), None,
                 None if conf is None else str(conf), lt.PROPOSED_BY, now, now)
                ).lastrowid
            service._log(conn, ctx, run["estimate_id"], "measurement_proposed",
                         {"measurement_id": mid, "qty": str(qty), "unit": "ea", "feeds": feeds})
            made.append(mid)
    return made


# ------------------------------------------------------------------ the whole run

def run_llm_electrical(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Count the devices on the electrical plan with the AI and propose the count measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration, no
    footer: counts need no scale.
    """
    def step(text):
        if on_step:
            on_step(text)

    cfg = roles.get_role(conn, ctx.company_id, lt.ROLE)
    if cfg["provider"] not in providers.API_PROVIDERS:
        raise lt.LlmTakeoffError("LLM takeoff is off - turn it on in \U0001f916 AI agents (Setup) to let the AI"
                                 " count the devices on the plan")
    ok_budget, why = roles.budget_left(conn, ctx.company_id)
    if not ok_budget:
        raise lt.LlmTakeoffError(f"LLM takeoff can't run: {why}")
    sheet = conn.execute("SELECT * FROM sheets WHERE id = ? AND company_id = ?",
                         (int(run["sheet_id"]), ctx.company_id)).fetchone()
    if sheet is None:
        raise lt.LlmTakeoffError(f"sheet {run['sheet_id']} not found")
    # The sends are person-asked: the person who started this auto-run asked the AI
    # to read the plans, and the owner opted in by turning the role on.
    person_ctx = replace(ctx, agent=None)

    step("finding the electrical sheet")
    ranked = lt.pick_foundation_sheets(conn, ctx.company_id, sheet["plan_set_id"], run["sheet_id"],
                                       module_id=MODULE_ID)
    if not ranked:
        raise lt.LlmTakeoffError("none of this plan set's sheets has a rendered image yet - the plan engine makes"
                                 " them when it reads the plans")
    # Only the sheets switched ON for Electrical are sent to the AI (the Plans screen's switches).
    from estimator.takeoff import sheet_trades
    ranked = [s for s in ranked if sheet_trades.is_active(conn, ctx.company_id, s["id"], MODULE_ID)]
    if not ranked:
        raise lt.LlmTakeoffError("every sheet of this plan set is switched off for Electrical - switch the electrical"
                                 " sheet on from the Plans screen")
    electrical = None
    if len(ranked) == 1:
        electrical = ranked[0]          # one sheet switched on: that's the one, no classify call needed
    elif ranked[0]["score"] > 0 and ranked[0]["score"] > ranked[1]["score"]:
        electrical = ranked[0]          # the sheet rules settle it: no classify call needed
    else:
        shown = ranked[:lt.CLASSIFY_MAX_SHEETS]
        preps = [lt._prepare_image(conn, person_ctx, s["id"],
                                   "LLM takeoff: find the electrical sheet", cfg["provider"]) for s in shown]
        images = [lt._image_payload(Path(p["file_path"]), lt.CLASSIFY_MAX_PX) for p in preps]
        refs = [lt._image_ref(p, lt.CLASSIFY_MAX_PX) for p in preps]
        listed = "\n".join(f"{i + 1}. {lt._sheet_label(s)}" for i, s in enumerate(shown))
        text, _, _, log_id = lt._call(conn, ctx, cfg, run, ELECTRICAL_CLASSIFY_SYSTEM,
                                      "These are the sheets of one plan set, in order:\n" + listed
                                      + "\nWhich sheet shows the electrical plan (outlets, switches, lighting, panel)?"
                                        " Reply with ONLY this JSON: {\"electrical_sheet_id\": <the"
                                        " sheet's id, or null if none of these sheets shows an electrical drawing>,"
                                        " \"notes\": \"one line saying why\"}. If you cannot tell, return null - never guess.",
                                      images, purpose="LLM takeoff: find the electrical sheet",
                                      images_refs=refs, step="classify")
        try:
            found_id, notes = parse_electrical_classification(text, [s["id"] for s in shown])
        except lt.LlmTakeoffError as exc:
            ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
            raise
        ai_log.set_parsed(conn, ctx.company_id, log_id,
                          {"electrical_sheet_id": found_id, "notes": notes})
        electrical = next((s for s in shown if s["id"] == found_id), None)
        if electrical is None:
            raise lt.LlmTakeoffError("the AI couldn't tell which sheet is the electrical plan"
                                     + (f" ({notes})" if notes else "")
                                     + " - open the electrical sheet and run it from there")

    step("reading the plan with the AI")
    prep = lt._prepare_image(conn, person_ctx, electrical["id"],
                             "LLM takeoff: read the electrical plan", cfg["provider"])
    path = Path(prep["file_path"])
    text, provider, model, log_id = lt._call(
        conn, ctx, cfg, run, ELECTRICAL_READ_SYSTEM, read_prompt(electrical),
        [lt._image_payload(path)],
        purpose="LLM takeoff: read the electrical plan", images_refs=[lt._image_ref(prep)])
    try:
        reading = parse_electrical_reading(text, electrical["id"])
    except lt.LlmTakeoffError as exc:
        ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
        raise
    ai_log.set_parsed(conn, ctx.company_id, log_id, reading)
    quantities = quantities_from_reading(reading)

    step("counting the devices")
    measurement_ids = create_measurements(conn, ctx, run, reading, quantities, provider, model)
    cand = electrical_candidate(reading, quantities, provider, model)
    return {"reading": reading, "quantities": quantities, "measurement_ids": measurement_ids,
            "provider": provider, "model": model, "sheet_id": electrical["id"],
            "candidate": cand, "summary": _summary(electrical["id"], quantities, measurement_ids)}


# ------------------------------------------------------------------ the results

def electrical_results(conn, ctx, row: dict) -> dict | None:
    """What a finished electrical run counted, as a list to show, plus all eight
    counts - including the zeros, which got no measurement row. Evidence for a
    counted device comes from its measurement; for a zero count, from what the AI
    said it looked for. Nothing here is approved."""
    ids = json.loads(row.get("measurement_ids_json") or "[]")
    candidates = json.loads(row.get("candidates_json") or "[]")
    cand = next((c for c in candidates if isinstance(c, dict) and c.get("id") == lt.CANDIDATE_ID), None)
    counts = (cand or {}).get("counts") or {}
    if not ids and not counts:
        return None
    lines = []
    by_feeds = {}
    if ids:
        rows = conn.execute(f"SELECT id, label, feeds, qty, unit, status, calc_json, sheet_id, viewport_id FROM measurements"
                            f" WHERE company_id = ? AND id IN ({','.join('?' * len(ids))}) ORDER BY id",
                            (ctx.company_id, *ids)).fetchall()
        for r in rows:
            try:
                calc = json.loads(r["calc_json"] or "{}")
            except ValueError:
                calc = {}
            lines.append({"id": r["id"], "label": r["label"], "feeds": r["feeds"], "qty": r["qty"], "unit": r["unit"],
                          "status": r["status"], "how": calc.get("how")})
            by_feeds[r["feeds"]] = {"qty": r["qty"], "how": calc.get("how"), "sheet_id": r["sheet_id"]}
    if not counts:                       # a run with no candidate: the measurements are the counts
        counts = {feeds: int(float(by_feeds[feeds]["qty"])) for feeds in COUNT_IDS if feeds in by_feeds}
    evidence = (cand or {}).get("evidence") or {}
    out_counts = []
    for feeds in COUNT_IDS:
        qty = int(counts.get(feeds) or 0)
        ev = (by_feeds.get(feeds) or {}).get("how") or evidence.get(feeds) or ""
        out_counts.append({"feeds": feeds, "label": LABELS[feeds], "qty": qty, "evidence": ev})
    sheet_id = (cand or {}).get("sheet_id")
    if sheet_id is None and by_feeds:
        sheet_id = next(iter(by_feeds.values()))["sheet_id"]
    if sheet_id is None:
        sheet_id = row.get("sheet_id")
    return {"lines": lines,
            "electrical": {"counts": out_counts, "sheet_id": sheet_id,
                           "confidence": (cand or {}).get("confidence"),
                           "notes": (cand or {}).get("notes") or ""}}

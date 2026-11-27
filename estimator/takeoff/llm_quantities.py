"""Shared LLM auto-run flow for the quantity trades (plumbing, HVAC, flooring, ...).

Phase 2 of the multi-trade AI auto-run. Every trade after electrical reads the
plan the same way - find the trade's sheet, read it with the AI, propose the
quantities as measurements - so the flow lives here once, driven by a small
per-trade spec (estimator/takeoff/llm_<trade>.py). Concrete and electrical
keep their own readers; this module is for the trades that came after them.

A trade's spec is a dict:

    module_id            the manifest id ("plumbing")
    label                the display name ("Plumbing")
    sheet_phrase         "the plumbing sheet" (step names, error messages)
    questions            ((feeds, label, plural, kind, unit), ...) in manifest
                         order; kind is "count", "area" or "length"
    classify_system      the system prompt for the find-the-sheet call
    classify_question    "Which sheet shows the plumbing plan ...?"
    read_system          the system prompt for the read call
    read_prompt          fn(sheet) -> the read call's user prompt
    parse_reading        fn(text, sheet_id) -> the reading, validated
    quantities_from_reading
                         fn(reading) -> {"values": {feeds: int | str}, ...}
                         Counts are ints; areas and lengths are Decimal
                         strings ("1234.56"). The APP does the maths here -
                         the AI only reads printed dimensions and counts.

The reading a parse function returns must carry:
    "<module_id>_sheet_id"   the sheet that was shown
    "evidence"               {feeds: str} - what each number was read from
    "confidence"             0-1 or None
    "notes"                  one line of text
plus whatever raw data the trade's quantities need (counts, room dimensions).

Rules, the same as electrical's:
  - STRICT JSON only; any defect rejects the whole answer, and each error
    names the field, so the AI Log says what was wrong.
  - A zero quantity gets no measurement row (the candidate still carries it,
    so the results show it as 0). Measurements are proposed, never approved.
  - Only sheets switched ON for the trade are sent to the AI.
  - Every call goes through the provider/budget system and the AI Log.
  - Tests never call a real LLM: providers.set_provider(fake) stands in.
"""

from __future__ import annotations

import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

from estimator.agents import ai_log, providers, roles
from estimator.context import RequestContext
from estimator.estimating import service
from estimator.takeoff import llm_takeoff as lt


# ------------------------------------------------------------------ parsing helpers


def parse_evidence(obj: dict, ids) -> dict:
    """The evidence object, one text per quantity id ("" when the AI said nothing)."""
    evidence = obj.get("evidence")
    if evidence is None:
        evidence = {}
    if not isinstance(evidence, dict):
        raise lt.LlmTakeoffError(f"the AI's answer has evidence = {evidence!r}, not an object")
    ev = {}
    for feeds in ids:
        v = evidence.get(feeds)
        if v is None:
            ev[feeds] = ""
        elif isinstance(v, str):
            ev[feeds] = v.strip()[:500]
        else:
            raise lt.LlmTakeoffError(f"the AI's answer has evidence for {feeds} = {v!r}, not text")
    return ev


def parse_confidence_notes(obj: dict) -> tuple[float | None, str]:
    """confidence clamped to 0-1 (or None) and notes as text."""
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
    return conf, notes[:500]


def parse_sheet_id(obj: dict, key: str, shown_id: int, notes: str) -> tuple[int, str]:
    """The sheet that was shown, whatever id the AI wrote down (a mismatch is noted)."""
    fid = obj.get(key)
    try:
        fid = int(fid) if fid is not None else None
    except (TypeError, ValueError):
        fid = None
    if fid is not None and fid != shown_id:
        notes = (notes + f" (the AI named sheet {fid}, but it was shown sheet {shown_id})").strip()
    return shown_id, notes[:500]


def parse_counts(text: str, sheet_id: int, count_ids, sheet_key: str) -> dict:
    """A count-only answer, validated: every count a whole number (0 when there
    are none - never null), the evidence for each count, confidence, notes.
    Any defect rejects the whole answer."""
    obj = lt._parse_json_object(text)
    counts = {}
    for feeds in count_ids:
        if feeds not in obj:
            raise lt.LlmTakeoffError(f"the AI's answer is missing the {feeds} count")
        v = obj[feeds]
        if isinstance(v, bool) or not isinstance(v, int):
            raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v!r}, not a whole number")
        if v < 0:
            raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v}, a negative count")
        counts[feeds] = v
    ev = parse_evidence(obj, count_ids)
    conf, notes = parse_confidence_notes(obj)
    sheet_id, notes = parse_sheet_id(obj, sheet_key, sheet_id, notes)
    return {sheet_key: sheet_id, "counts": counts, "evidence": ev,
            "confidence": conf, "notes": notes}


def dimension_inches(value, field: str) -> int:
    """A printed dimension ("14'-6\"", "45'-7\"") in inches, or a loud failure
    naming the field - the AI's reading is never guessed at."""
    from estimator.takeoff import slab_find
    got = slab_find.parse_feet_inches(value) if isinstance(value, str) else None
    if got is None:
        raise lt.LlmTakeoffError(f"the AI read {field} as {value!r}, which isn't a length"
                                 " (feet'-inches\"); measure it by hand")
    return got


def parse_rooms(value, key: str) -> list[dict]:
    """A list of named rectangles the AI read off the plan: each has a name
    and width/length strings. The app does the area maths from these."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise lt.LlmTakeoffError(f"the AI's answer has {key} = {value!r}, not a list")
    rooms = []
    for i, item in enumerate(value):
        where = f"{key}[{i}]"
        if not isinstance(item, dict):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} = {item!r}, not an object")
        name = item.get("name")
        if name is not None and not isinstance(name, str):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} name = {name!r}, not text")
        for side in ("width_ft", "length_ft"):
            v = item.get(side)
            if v is None:
                raise lt.LlmTakeoffError(f"the AI's answer is missing {where} {side}")
            if not isinstance(v, str) or not v.strip():
                raise lt.LlmTakeoffError(f"the AI's answer has {where} {side} = {v!r}, not text")
        rooms.append({"name": (name or "").strip()[:80],
                      "width_ft": item["width_ft"].strip(), "length_ft": item["length_ft"].strip()})
    return rooms


def rooms_area_sqft(rooms: list[dict]) -> str:
    """The rooms' areas added up, to 0.01 sq ft (the app's maths, not the AI's)."""
    total = Decimal(0)
    for r in rooms:
        w = Decimal(dimension_inches(r["width_ft"], f"room {r['name'] or '?'} width")) / Decimal(12)
        ln = Decimal(dimension_inches(r["length_ft"], f"room {r['name'] or '?'} length")) / Decimal(12)
        total += w * ln
    return str(total.quantize(Decimal("0.01")))


def rooms_perimeter_lf(rooms: list[dict]) -> str:
    """The rooms' perimeters added up, to 0.01 lf (baseboard, trim)."""
    total = Decimal(0)
    for r in rooms:
        w = Decimal(dimension_inches(r["width_ft"], f"room {r['name'] or '?'} width")) / Decimal(12)
        ln = Decimal(dimension_inches(r["length_ft"], f"room {r['name'] or '?'} length")) / Decimal(12)
        total += (w + ln) * 2
    return str(total.quantize(Decimal("0.01")))


def parse_classification(text: str, sheet_ids, key: str) -> tuple[int | None, str]:
    """(trade sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    obj = lt._parse_json_object(text)
    fid = obj.get(key)
    notes = str(obj.get("notes") or "")[:500]
    if fid is None:
        return None, notes
    try:
        fid = int(fid)
    except (TypeError, ValueError):
        return None, notes
    return (fid if fid in set(sheet_ids) else None), notes


# ------------------------------------------------------------------ the quantities


def quantities_from_counts(reading: dict, count_ids) -> dict:
    """The counts as the run reports them."""
    return {"values": {feeds: int(reading["counts"][feeds]) for feeds in count_ids}}


def make_candidate(reading: dict, quantities: dict, provider: str, model: str,
                   module_id: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results
    page reads. It carries every quantity - including the zeros, which get no
    measurement row."""
    return {"id": lt.CANDIDATE_ID, "source": "llm", "values": dict(quantities["values"]),
            "evidence": dict(reading["evidence"]), "confidence": reading["confidence"],
            "notes": reading["notes"], "sheet_id": reading[f"{module_id}_sheet_id"],
            "provider": provider, "model": model}


def _summary(sheet_id: int, quantities: dict, measurement_ids: list[int], spec: dict) -> str:
    """One line for the runner's log: what was read, on which sheet."""
    values = quantities["values"]
    parts = []
    for feeds, _label, plural, _kind, _unit in spec["questions"]:
        v = values.get(feeds)
        if v is None:
            continue
        try:
            if Decimal(str(v)) <= 0:
                continue
        except Exception:  # noqa: BLE001 - a non-number is never summarised
            continue
        parts.append(f"{v} {plural}")
    found = ", ".join(parts) if parts else "none found"
    return (f"read the {spec['label']} quantities on sheet {sheet_id} ({found}); "
            f"measurements {measurement_ids}")


# ------------------------------------------------------------------ the measurements


def create_measurements(conn, ctx: RequestContext, run: dict, reading: dict, quantities: dict,
                        provider: str, model: str, spec: dict) -> list[int]:
    """Propose one measurement per quantity the AI found - a zero quantity gets
    no row (the candidate still carries it, so the results show it as 0).
    Proposed, never approved; the calc carries the full provenance. The
    viewport is the run's: the API picks it when the run starts."""
    module_id = spec["module_id"]
    sheet_id = reading[f"{module_id}_sheet_id"]
    conf = reading["confidence"]
    made = []
    now = lt._now()
    values = quantities["values"]
    with service.transaction(conn):
        kept = lt.replace_earlier_proposals(conn, ctx, run, module_id, sheet_id)   # a rerun replaces, never adds
        covered = lt.plans_measured(conn, ctx, run, module_id, sheet_id)         # the plan reader's approved ones
        for feeds, label, _plural, kind, unit in spec["questions"]:
            qty = values.get(feeds)
            if qty is None or feeds in kept:     # kept: already approved, and the run keeps approved items
                continue
            try:
                if Decimal(str(qty)) <= 0:
                    continue
            except Exception:  # noqa: BLE001 - a non-number is never proposed
                continue
            if lt.already_measured(conn, ctx, run, covered, feeds, qty):   # never priced twice (2026-11-25)
                continue
            how = reading["evidence"].get(feeds) or f"{qty} {unit} read on the {spec['label']} plan"
            calc = {"source": "llm", "auto_run_id": run["id"], "candidate_id": lt.CANDIDATE_ID,
                    "how": how, "qty": str(qty), f"{module_id}_sheet_id": sheet_id,
                    "values": {k: str(v) for k, v in values.items()},
                    "provider": provider, "model": model, "notes": reading["notes"]}
            mid = conn.execute(
                "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id,"
                " kind, label, qty, unit, source_object_ids, calc_json, geometry_json, method, confidence, status,"
                " locked, proposed_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,'[]',?,?,'ai',?,'proposed',0,?,?,?)",
                (ctx.company_id, run["estimate_id"], module_id, feeds, sheet_id, run["viewport_id"],
                 kind, f"{label} (AI)", str(qty), unit, json.dumps(calc), None,
                 None if conf is None else str(conf), lt.PROPOSED_BY, now, now)
                ).lastrowid
            service._log(conn, ctx, run["estimate_id"], "measurement_proposed",
                         {"measurement_id": mid, "qty": str(qty), "unit": unit, "feeds": feeds})
            made.append(mid)
    return made


# ------------------------------------------------------------------ the whole run


def run_llm_quantities(conn, ctx: RequestContext, run: dict, spec: dict, on_step=None) -> dict:
    """Read the trade's plan with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration: the
    AI reads printed dimensions, and the app does the maths from them.
    """
    module_id = spec["module_id"]
    label = spec["label"]
    sheet_key = f"{module_id}_sheet_id"

    def step(text):
        if on_step:
            on_step(text)

    cfg = roles.get_role(conn, ctx.company_id, lt.ROLE)
    if cfg["provider"] not in providers.API_PROVIDERS:
        raise lt.LlmTakeoffError(f"AI measuring is off - turn it on in \U0001f916 AI agents (Setup) to let the AI"
                                 f" read the {label} plan")
    ok_budget, why = roles.budget_left(conn, ctx.company_id)
    if not ok_budget:
        raise lt.LlmTakeoffError(f"AI measuring can't run: {why}")
    sheet = conn.execute("SELECT * FROM sheets WHERE id = ? AND company_id = ?",
                         (int(run["sheet_id"]), ctx.company_id)).fetchone()
    if sheet is None:
        raise lt.LlmTakeoffError(f"sheet {run['sheet_id']} not found")
    # The sends are person-asked: the person who started this auto-run asked the AI
    # to read the plans, and the owner opted in by turning the role on.
    person_ctx = replace(ctx, agent=None)

    step(f"finding {spec['sheet_phrase']}")
    ranked = lt.pick_foundation_sheets(conn, ctx.company_id, sheet["plan_set_id"], run["sheet_id"],
                                       module_id=module_id)
    if not ranked:
        raise lt.LlmTakeoffError("none of this plan set's sheets has a rendered image yet - the plan engine makes"
                                 " them when it reads the plans")
    # Only the sheets switched ON for the trade are sent to the AI (the Plans screen's switches).
    from estimator.takeoff import sheet_trades
    ranked = [s for s in ranked if sheet_trades.is_active(conn, ctx.company_id, s["id"], module_id)]
    if not ranked:
        raise lt.LlmTakeoffError(f"every sheet of this plan set is switched off for {label} - switch"
                                 f" {spec['sheet_phrase']} on from the Plans screen")
    trade_sheet = None
    if len(ranked) == 1:
        trade_sheet = ranked[0]          # one sheet switched on: that's the one, no classify call needed
    elif ranked[0]["score"] > 0 and ranked[0]["score"] > ranked[1]["score"]:
        trade_sheet = ranked[0]          # the sheet rules settle it: no classify call needed
    else:
        shown = ranked[:lt.CLASSIFY_MAX_SHEETS]
        preps = [lt._prepare_image(conn, person_ctx, s["id"],
                                   f"AI measuring: find {spec['sheet_phrase']}", cfg["provider"]) for s in shown]
        images = [lt._image_payload(Path(p["file_path"]), lt.CLASSIFY_MAX_PX) for p in preps]
        refs = [lt._image_ref(p, lt.CLASSIFY_MAX_PX) for p in preps]
        listed = "\n".join(f"{i + 1}. {lt._sheet_label(s)}" for i, s in enumerate(shown))
        text, _, _, log_id = lt._call(conn, ctx, cfg, run, spec["classify_system"],
                                      "These are the sheets of one plan set, in order:\n" + listed
                                      + f"\n{spec['classify_question']}"
                                        f" Reply with ONLY this JSON: {{\"{sheet_key}\": <the"
                                        " sheet's id, or null if none of these sheets shows"
                                        f" {spec['sheet_phrase'].replace('the ', 'a ', 1)}>," 
                                        " \"notes\": \"one line saying why\"}. If you cannot tell, return null - never guess.",
                                      images, purpose=f"AI measuring: find {spec['sheet_phrase']}",
                                      images_refs=refs, step="classify")
        try:
            found_id, notes = parse_classification(text, [s["id"] for s in shown], sheet_key)
        except lt.LlmTakeoffError as exc:
            ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
            raise
        ai_log.set_parsed(conn, ctx.company_id, log_id, {sheet_key: found_id, "notes": notes})
        trade_sheet = next((s for s in shown if s["id"] == found_id), None)
        if trade_sheet is None:
            raise lt.LlmTakeoffError(f"the AI couldn't tell which sheet is {spec['sheet_phrase']}"
                                     + (f" ({notes})" if notes else "")
                                     + f" - open {spec['sheet_phrase']} and run it from there")

    step("reading the plan with the AI")
    prep = lt._prepare_image(conn, person_ctx, trade_sheet["id"],
                             f"AI measuring: read {spec['sheet_phrase']}", cfg["provider"])
    path = Path(prep["file_path"])
    text, provider, model, log_id = lt._call(
        conn, ctx, cfg, run, spec["read_system"], spec["read_prompt"](trade_sheet),
        [lt._image_payload(path)],
        purpose=f"AI measuring: read {spec['sheet_phrase']}", images_refs=[lt._image_ref(prep)])
    try:
        reading = spec["parse_reading"](text, trade_sheet["id"])
    except lt.LlmTakeoffError as exc:
        ai_log.set_error(conn, ctx.company_id, log_id, str(exc))
        raise
    ai_log.set_parsed(conn, ctx.company_id, log_id, reading)
    quantities = spec["quantities_from_reading"](reading)

    step("working out the quantities")
    measurement_ids = create_measurements(conn, ctx, run, reading, quantities, provider, model, spec)
    cand = make_candidate(reading, quantities, provider, model, module_id)
    return {"reading": reading, "quantities": quantities, "measurement_ids": measurement_ids,
            "provider": provider, "model": model, "sheet_id": trade_sheet["id"],
            "candidate": cand, "summary": _summary(trade_sheet["id"], quantities, measurement_ids, spec)}


# ------------------------------------------------------------------ the results


def generic_results(conn, ctx, row: dict, spec: dict) -> dict | None:
    """What a finished quantity run read, as a list to show, plus every
    quantity - including the zeros, which got no measurement row. Evidence for
    a proposed quantity comes from its measurement; for a zero quantity, from
    what the AI said it looked for. Nothing here is approved."""
    module_id = spec["module_id"]
    ids = json.loads(row.get("measurement_ids_json") or "[]")
    candidates = json.loads(row.get("candidates_json") or "[]")
    cand = next((c for c in candidates if isinstance(c, dict) and c.get("id") == lt.CANDIDATE_ID), None)
    values = (cand or {}).get("values") or {}
    if not ids and not values:
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
    if not values:                       # a run with no candidate: the measurements are the quantities
        values = {feeds: by_feeds[feeds]["qty"] for feeds, *_ in spec["questions"] if feeds in by_feeds}
    evidence = (cand or {}).get("evidence") or {}
    items = []
    for feeds, label, _plural, kind, unit in spec["questions"]:
        raw = values.get(feeds)
        if raw is None:
            qty = 0
        elif kind == "count":
            qty = int(raw) if isinstance(raw, int) else int(float(raw))
        else:
            qty = raw
        ev = (by_feeds.get(feeds) or {}).get("how") or evidence.get(feeds) or ""
        items.append({"feeds": feeds, "label": label, "qty": qty, "unit": unit, "evidence": ev})
    sheet_id = (cand or {}).get("sheet_id")
    if sheet_id is None and by_feeds:
        sheet_id = next(iter(by_feeds.values()))["sheet_id"]
    if sheet_id is None:
        sheet_id = row.get("sheet_id")
    return {"lines": lines,
            "quantities": {"trade": module_id, "label": spec["label"], "items": items,
                           "sheet_id": sheet_id, "confidence": (cand or {}).get("confidence"),
                           "notes": (cand or {}).get("notes") or ""}}

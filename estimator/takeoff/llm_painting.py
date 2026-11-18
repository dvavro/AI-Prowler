"""LLM-assisted painting takeoff: read the areas to paint with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the finish sheet, read it with
the AI, propose one measurement per quantity found. This module is only what
is painting's own - the questions, the prompts, the parsing.

The AI reads the room dimensions off the finish sheet - the ceiling area and
the trim length both come from those, worked out by the app - reads each
exterior elevation's printed width and height, and counts the doors. The app
does every bit of maths: the AI never computes an area or a length.

The interior wall area stays user-answered: it needs the wall height, and
plans don't print one, so it cannot be read honestly - guessing a height
would invent the area. The coats, the primer, the paint grade, the permit
and inspections stay user-answered too - the auto-run fills quantities only.
There is no calibration: the AI reads printed dimensions, and the app does
the maths.
"""

from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "painting"             # this trade's module id (the manifest, the sheet switches)

# The Painting manifest's read questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit). wall_sqft is not here: interior wall area needs the
# wall height, which plans don't print.
QUESTIONS = (
    ("ceiling_sqft", "Ceiling area", "sq ft of ceiling", "area", "sqft"),
    ("exterior_sqft", "Exterior wall area (siding, stucco)", "sq ft of exterior wall", "area", "sqft"),
    ("trim_lf", "Trim and baseboard", "lf of trim", "length", "lf"),
    ("doors", "Doors (both sides)", "doors", "count", "ea"),
)
IDS = tuple(q[0] for q in QUESTIONS)
COUNT_IDS = ("doors",)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

PAINTING_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the finish sheet. "
                            "Reply with ONLY one JSON object, nothing else.")

PAINTING_READ_SYSTEM = ("You are reading a finish sheet to measure the areas to paint on it. "
                        "Reply with ONLY one JSON object, nothing else.")


def parse_painting_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(finish sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "painting_sheet_id")


def _count(obj: dict, feeds: str) -> int:
    """One whole-number count from the AI's answer (0 when there are none - never null)."""
    if feeds not in obj:
        raise lt.LlmTakeoffError(f"the AI's answer is missing the {feeds} count")
    v = obj[feeds]
    if isinstance(v, bool) or not isinstance(v, int):
        raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v!r}, not a whole number")
    if v < 0:
        raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v}, a negative count")
    return v


def _parse_elevations(value) -> list[dict]:
    """The exterior elevations the AI read off the plan: each has a printed width
    and height in feet'-inches". The app works the areas out - the AI never does."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise lt.LlmTakeoffError(f"the AI's answer has elevations = {value!r}, not a list")
    elevations = []
    for i, item in enumerate(value):
        where = f"elevations[{i}]"
        if not isinstance(item, dict):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} = {item!r}, not an object")
        name = item.get("name")
        if name is not None and not isinstance(name, str):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} name = {name!r}, not text")
        for side in ("width_ft", "height_ft"):
            v = item.get(side)
            if v is None:
                raise lt.LlmTakeoffError(f"the AI's answer is missing {where} {side}")
            if not isinstance(v, str) or not v.strip():
                raise lt.LlmTakeoffError(f"the AI's answer has {where} {side} = {v!r}, not text")
            lq.dimension_inches(v.strip(), f"{where} {side.replace('_ft', '')}")
        elevations.append({"name": (name or "").strip()[:80],
                           "width_ft": item["width_ft"].strip(), "height_ft": item["height_ft"].strip()})
    return elevations


def _elevations_area_sqft(elevations: list[dict]) -> str:
    """The elevations' areas added up, to 0.01 sq ft (the app's maths, not the AI's)."""
    total = Decimal(0)
    for e in elevations:
        w = Decimal(lq.dimension_inches(e["width_ft"], f"elevation {e['name'] or '?'} width")) / Decimal(12)
        h = Decimal(lq.dimension_inches(e["height_ft"], f"elevation {e['name'] or '?'} height")) / Decimal(12)
        total += w * h
    return str(total.quantize(Decimal("0.01")))


def parse_painting_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the rooms (each a name and printed width
    and length in feet'-inches"), the exterior elevations (each a printed width
    and height), the door count (0 when there are none - never null), the
    evidence for each quantity, confidence 0-1 (or None), notes. Any defect
    rejects the whole answer - a dimension the AI hedged on is no dimension at
    all. The finish sheet is the one that was shown, whatever id the AI wrote down."""
    obj = lt._parse_json_object(text)
    rooms = lq.parse_rooms(obj.get("rooms"), "rooms")
    for r in rooms:      # the dimensions must parse now - a bad one rejects the whole answer
        lq.dimension_inches(r["width_ft"], f"room {r['name'] or '?'} width")
        lq.dimension_inches(r["length_ft"], f"room {r['name'] or '?'} length")
    elevations = _parse_elevations(obj.get("elevations"))
    counts = {feeds: _count(obj, feeds) for feeds in COUNT_IDS}
    ev = lq.parse_evidence(obj, IDS)
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "painting_sheet_id", sheet_id, notes)
    return {"painting_sheet_id": sheet_id, "rooms": rooms, "elevations": elevations,
            "counts": counts, "evidence": ev, "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read the room dimensions and the elevations and
    count the doors on this sheet, with the evidence for each number, so a person
    can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the areas to paint shown on this finish sheet."
        " Read every room's printed width and length from the finish schedule or the floor plan on"
        " this sheet, exactly as printed (feet'-inches\", like 14'-6\"): one rooms entry per room."
        " When this sheet shows no room dimensions, rooms is an empty list. The ceiling area and"
        " the trim length come from the room dimensions - do not work them out, the app does."
        " Read every exterior elevation from the elevation drawings on this sheet: width_ft and"
        " height_ft exactly as printed. When this sheet shows no elevations, elevations is an"
        " empty list. Count the doors to paint from the door symbols: doors are doors (both sides"
        " count once - the count is doors, not sides)."
        " Reply with ONLY this JSON: {\"painting_sheet_id\": " + str(sheet["id"])
        + ", \"rooms\": [{\"name\": \"Living room\", \"width_ft\": \"14'-6\\\"\", \"length_ft\": \"18'-0\\\"\"}],"
          " \"elevations\": [{\"name\": \"Front\", \"width_ft\": \"40'-0\\\"\", \"height_ft\": \"9'-0\\\"\"}],"
          " \"doors\": 8, \"confidence\": 0.9,"
          " \"notes\": \"one line\", \"evidence\": {\"ceiling_sqft\": \"what the room dimensions were read from\","
          " \"exterior_sqft\": \"...\", \"trim_lf\": \"...\", \"doors\": \"...\"}}."
        " Rules: every dimension is exactly as printed - never a guess, never computed; doors is a"
        " whole number - answer 0 when there are none, never null, never a guess. evidence says"
        " what each number was read from, so a person can check it; confidence is 0-1, how sure"
        " you are about the dimensions and the count.")


# ------------------------------------------------------------------ the quantities

def quantities_from_reading(reading: dict) -> dict:
    """The quantities as the run reports them: the ceiling area (the rooms' areas
    added up), the exterior area (the elevations' areas added up), the trim
    length (the rooms' perimeters added up), the door count. All four questions,
    even when the answer is zero."""
    return {"values": {"ceiling_sqft": lq.rooms_area_sqft(reading["rooms"]),
                       "exterior_sqft": _elevations_area_sqft(reading["elevations"]),
                       "trim_lf": lq.rooms_perimeter_lf(reading["rooms"]),
                       "doors": int(reading["counts"]["doors"])}}


def painting_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Painting",
    "sheet_phrase": "the finish sheet",
    "questions": QUESTIONS,
    "classify_system": PAINTING_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the finishes (the finish schedule, the elevations)?",
    "read_system": PAINTING_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_painting_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_painting(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the areas to paint on the finish sheet with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def painting_results(conn, ctx, row: dict) -> dict | None:
    """What a finished painting run read, as a list to show, plus all four
    quantities - including the zeros, which got no measurement row. Evidence for
    a proposed quantity comes from its measurement; for a zero quantity, from
    what the AI said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

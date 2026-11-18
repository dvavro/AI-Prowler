"""LLM-assisted drywall takeoff: read the floor plan with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the drywall sheet, read it with
the AI, propose one measurement per quantity found. This module is only what is
drywall's own - the questions, the prompts, the parsing.

The AI reads the rooms (their printed width and length, for the ceiling area)
and the window and door schedule (each opening's printed width and height, for
the area to leave out). The app does all the maths from those readings - the
areas are never the AI's numbers. When the plan has no window or door schedule,
the openings area is 0.

Wall length stays user-answered: per-wall lengths are not printed on plans, so
the AI cannot read them, and guessing a length from the picture would invent
it. The honest path is geometric - adding up the plan engine's detected wall
objects on a calibrated viewport - which is a follow-up, not this batch. The
choices (wall height, board, finish level) and the yes/no questions (tear out
the old drywall, permit, inspections) stay user-answered too - the auto-run
fills quantities only. There is no calibration: the AI reads printed
dimensions, and the app does the maths from them.
"""

from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "drywall"               # this trade's module id (the manifest, the sheet switches)

# The Drywall manifest's quantity questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit). Wall length is not here: per-wall lengths are not
# printed on plans, so the AI cannot read them (see the module docstring).
QUESTIONS = (
    ("ceiling_sqft", "Ceiling area", "sq ft of ceiling", "area", "sqft"),
    ("openings_sqft", "Door and window area to leave out", "sq ft of openings", "area", "sqft"),
)
QUESTION_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

DRYWALL_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the floor plan. "
                           "Reply with ONLY one JSON object, nothing else.")

DRYWALL_READ_SYSTEM = ("You are reading a floor plan to measure the ceilings and the door and window openings. "
                       "Reply with ONLY one JSON object, nothing else.")


def parse_drywall_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(drywall sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "drywall_sheet_id")


def _parse_faces(value, key: str) -> list[dict]:
    """A list of named rectangles the AI read off the plan: each has a width and
    a height string. The app does the area maths from these."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise lt.LlmTakeoffError(f"the AI's answer has {key} = {value!r}, not a list")
    faces = []
    for i, item in enumerate(value):
        where = f"{key}[{i}]"
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
        faces.append({"name": (name or "").strip()[:80],
                      "width_ft": item["width_ft"].strip(), "height_ft": item["height_ft"].strip()})
    return faces


def _check_rects(rects: list[dict], kind: str, second: str = "length_ft") -> None:
    """Every printed width and length (or height) must be a length the app can
    read - a dimension the AI hedged on rejects the whole answer, here, so the
    AI Log says which one was wrong."""
    for r in rects:
        lq.dimension_inches(r["width_ft"], f"{kind} {r['name'] or '?'} width")
        lq.dimension_inches(r[second], f"{kind} {r['name'] or '?'} {second[:-3]}")


def parse_drywall_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the rooms (for the ceiling area) and
    the window and door openings from the schedule - every printed dimension a
    feet'-inches" string the app can read - the evidence for each quantity,
    confidence 0-1 (or None), notes. Any defect rejects the whole answer. The
    drywall sheet is the one that was shown, whatever id the AI wrote down."""
    obj = lt._parse_json_object(text)
    rooms = lq.parse_rooms(obj.get("rooms"), "rooms")
    openings = _parse_faces(obj.get("openings"), "openings")
    _check_rects(rooms, "room")
    _check_rects(openings, "opening", "height_ft")
    ev = lq.parse_evidence(obj, QUESTION_IDS)
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "drywall_sheet_id", sheet_id, notes)
    return {"drywall_sheet_id": sheet_id, "rooms": rooms, "openings": openings,
            "evidence": ev, "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read the rooms and the window and door schedule,
    with the printed dimensions and the evidence for each quantity, so a person
    can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the rooms on this floor plan, each with its"
        " printed width and length, and read the window and door schedule, each opening with its printed"
        " width and height. When the plan has no window or door schedule, answer openings as an empty list"
        " and say \"no schedule on the plan\" in the evidence for openings_sqft - never null, never a guess."
        " Read the dimensions exactly as printed, as feet'-inches\" strings like \"14'-6\\\"\" - never"
        " compute an area or a total; the app does the maths."
        " Reply with ONLY this JSON: {\"drywall_sheet_id\": " + str(sheet["id"])
        + ", \"rooms\": [{\"name\": \"Living room\", \"width_ft\": \"14'-0\\\"\", \"length_ft\": \"20'-0\\\"\"}],"
          " \"openings\": [{\"name\": \"Window W-1\", \"width_ft\": \"3'-0\\\"\", \"height_ft\": \"4'-0\\\"\"}],"
          " \"confidence\": 0.9, \"notes\": \"one line\","
          " \"evidence\": {\"ceiling_sqft\": \"which rooms, which printed dimensions\","
          " \"openings_sqft\": \"which schedule entries, which printed sizes\"}}."
          " Rules: every list is empty when nothing is shown for it. evidence says what was read for each"
          " number, so a person can check it; confidence is 0-1, how sure you are about the reading.")


# ------------------------------------------------------------------ the quantities

def _faces_area_sqft(faces: list[dict], kind: str) -> str:
    """The faces' areas added up, to 0.01 sq ft (the app's maths, not the AI's)."""
    total = Decimal(0)
    for f in faces:
        w = Decimal(lq.dimension_inches(f["width_ft"], f"{kind} {f['name'] or '?'} width")) / Decimal(12)
        h = Decimal(lq.dimension_inches(f["height_ft"], f"{kind} {f['name'] or '?'} height")) / Decimal(12)
        total += w * h
    return str(total.quantize(Decimal("0.01")))


def quantities_from_reading(reading: dict) -> dict:
    """The quantities as the run reports them: both questions. The ceiling area
    is the rooms' area; the openings area is the schedule openings' area added up."""
    return {"values": {
        "ceiling_sqft": lq.rooms_area_sqft(reading["rooms"]),
        "openings_sqft": _faces_area_sqft(reading["openings"], "opening"),
    }}


def drywall_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Drywall",
    "sheet_phrase": "the drywall sheet",
    "questions": QUESTIONS,
    "classify_system": DRYWALL_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the floor plan (rooms, wall types, ceilings)?",
    "read_system": DRYWALL_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_drywall_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_drywall(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the floor plan with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def drywall_results(conn, ctx, row: dict) -> dict | None:
    """What a finished drywall run read, as a list to show, plus both quantities
    - including the zeros, which got no measurement row. Evidence for a proposed
    quantity comes from its measurement; for a zero quantity, from what the AI
    said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

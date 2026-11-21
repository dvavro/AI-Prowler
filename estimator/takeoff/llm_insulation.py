"""LLM-assisted insulation takeoff: read the attic and wall areas with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the insulation sheet, read it with
the AI, propose one area measurement per area found. This module is only what
is insulation's own - the questions, the prompts, the parsing.

The AI reads printed dimensions and the app does all the maths (Decimal, to
0.01 sq ft): the attic area is the footprint, worked out from the rooms'
printed dimensions; the wall area is the sum of length x height over the wall
runs the plan or the wall sections dimension. The AI never computes an area
itself. When the plan doesn't dimension the walls, the wall area is 0.00 and
the evidence says so.

Spray foam area stays user-answered: which areas get foam is a choice, not
something readable from the plan. The R-values and foam thickness (choices)
and the yes/no questions (remove the old insulation, air-seal, vapor barrier)
stay user-answered too.
"""

from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "insulation"            # this trade's module id (the manifest, the sheet switches)

# The Insulation manifest's read questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("attic_sqft", "Attic area (blown-in)", "sq ft of attic", "area", "sqft"),
    ("wall_sqft", "Open wall area (batts)", "sq ft of open wall", "area", "sqft"),
)
ALL_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

INSULATION_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the insulation sheet. "
                              "Reply with ONLY one JSON object, nothing else.")

INSULATION_READ_SYSTEM = ("You are reading an insulation sheet to read the attic and wall dimensions "
                          "on it. Reply with ONLY one JSON object, nothing else.")


def parse_insulation_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(insulation sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "insulation_sheet_id")


def parse_wall_runs(value, key: str = "wall_runs") -> list[dict]:
    """A list of wall runs the AI read off the plan or the wall sections: each has a
    length and a height string. The app does the area maths from these."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise lt.LlmTakeoffError(f"the AI's answer has {key} = {value!r}, not a list")
    runs = []
    for i, item in enumerate(value):
        where = f"{key}[{i}]"
        if not isinstance(item, dict):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} = {item!r}, not an object")
        name = item.get("name")
        if name is not None and not isinstance(name, str):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} name = {name!r}, not text")
        for side in ("length_ft", "height_ft"):
            v = item.get(side)
            if v is None:
                raise lt.LlmTakeoffError(f"the AI's answer is missing {where} {side}")
            if not isinstance(v, str) or not v.strip():
                raise lt.LlmTakeoffError(f"the AI's answer has {where} {side} = {v!r}, not text")
        runs.append({"name": (name or "").strip()[:80],
                     "length_ft": item["length_ft"].strip(), "height_ft": item["height_ft"].strip()})
    return runs


def wall_runs_area_sqft(runs: list[dict]) -> str:
    """The wall runs' areas (length x height each) added up, to 0.01 sq ft
    (the app's maths, not the AI's)."""
    total = Decimal(0)
    for r in runs:
        ln = Decimal(lq.dimension_inches(r["length_ft"], f"wall run {r['name'] or '?'} length")) / Decimal(12)
        ht = Decimal(lq.dimension_inches(r["height_ft"], f"wall run {r['name'] or '?'} height")) / Decimal(12)
        total += ln * ht
    return str(total.quantize(Decimal("0.01")))


def parse_insulation_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the rooms with their printed dimensions
    (the attic footprint) and the wall runs with their printed lengths and heights,
    the evidence for each area, confidence 0-1 (or None), notes. Any defect rejects
    the whole answer. The insulation sheet is the one that was shown, whatever id
    the AI wrote down. No wall runs means the plan doesn't dimension the walls -
    the evidence says so. A dimension that isn't a length rejects the whole answer
    here, so the AI Log says which one was wrong."""
    obj = lt._parse_json_object(text)
    rooms = lq.parse_rooms(obj.get("rooms"), "rooms")
    wall_runs = parse_wall_runs(obj.get("wall_runs"))
    for r in rooms:      # the dimensions must parse now - a bad one rejects the whole answer
        lq.dimension_inches(r["width_ft"], f"room {r['name'] or '?'} width")
        lq.dimension_inches(r["length_ft"], f"room {r['name'] or '?'} length")
    for r in wall_runs:
        lq.dimension_inches(r["length_ft"], f"wall run {r['name'] or '?'} length")
        lq.dimension_inches(r["height_ft"], f"wall run {r['name'] or '?'} height")
    ev = lq.parse_evidence(obj, ALL_IDS)
    if not wall_runs and not ev["wall_sqft"]:
        ev["wall_sqft"] = "the plan doesn't dimension the walls"
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "insulation_sheet_id", sheet_id, notes)
    return {"insulation_sheet_id": sheet_id, "rooms": rooms, "wall_runs": wall_runs,
            "evidence": ev, "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read the room dimensions for the attic footprint and
    the wall runs for the open wall area, with the evidence for each number, so a
    person can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the insulation areas on it:"
        " the attic area is the footprint of the house, so read the printed dimensions of every"
        " room on the floor plan; the open wall area comes from the wall runs, so read the length"
        " and height of every wall run the plan or the wall sections dimension."
        " Reply with ONLY this JSON: {\"insulation_sheet_id\": " + str(sheet["id"])
        + ", \"rooms\": [{\"name\": \"Living\", \"width_ft\": \"14'-6\\\"\", \"length_ft\": \"20'-0\\\"\"}],"
        " \"wall_runs\": [{\"name\": \"North wall\", \"length_ft\": \"40'-0\\\"\", \"height_ft\": \"8'-0\\\"\"}],"
        " \"confidence\": 0.9, \"notes\": \"one line\","
        " \"evidence\": {\"attic_sqft\": \"which rooms were dimensioned\","
        " \"wall_sqft\": \"which wall runs were dimensioned, or that the plan doesn't dimension the walls\"}}."
        " Rules: dimensions are feet'-inches\" (\"14'-6\\\"\"); an empty rooms list means the plan prints"
        " no room dimensions, and an empty wall_runs list means the plan doesn't dimension the walls."
        " evidence says what was read for each number, so a person can check it; confidence is 0-1,"
        " how sure you are about the dimensions. Do not work out any areas yourself -"
        " the app does the maths from the dimensions you read.")


# ------------------------------------------------------------------ the areas

def quantities_from_reading(reading: dict) -> dict:
    """The areas as the run reports them: the attic area from the rooms the AI
    dimensioned, the wall area from the wall runs it dimensioned (Decimal, to
    0.01 sq ft - the app's maths, not the AI's). No dimensions means 0.00 sq ft."""
    return {"values": {"attic_sqft": lq.rooms_area_sqft(reading["rooms"]),
                       "wall_sqft": wall_runs_area_sqft(reading["wall_runs"])}}


def insulation_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI dimensioned, in the shape the results
    page reads. It carries every area - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Insulation",
    "sheet_phrase": "the insulation sheet",
    "questions": QUESTIONS,
    "classify_system": INSULATION_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the wall sections or the insulation plan (insulation, energy)?",
    "read_system": INSULATION_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_insulation_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_insulation(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the insulation areas on the insulation sheet with the AI and propose the area measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def insulation_results(conn, ctx, row: dict) -> dict | None:
    """What a finished insulation run dimensioned, as a list to show, plus both areas
    - including the zeros, which got no measurement row. Evidence for a proposed
    area comes from its measurement; for a zero area, from what the AI said it
    looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

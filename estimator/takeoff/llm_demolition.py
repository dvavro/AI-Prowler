"""LLM-assisted demolition takeoff: read the demolition plan with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the demolition sheet, read it with
the AI, propose one measurement per quantity found. This module is only what is
demolition's own - the questions, the prompts, the parsing.

The AI reads only what the plan marks for removal, with the printed dimensions:
the rooms or areas to demo (their printed width and length), the wall runs and
cabinet runs marked for removal (their printed lengths), the fixtures to remove
(a count), and the concrete breakout areas and structure footprints (their
printed width and length). The app does all the maths from those readings - the
areas and the run lengths are never the AI's numbers. Flooring tear-out covers
the floor of the same rooms as the interior demolition, so it takes the rooms'
area too.

An unmarked room, wall or slab is not demolition, and a quantity with nothing
marked on the plan is 0. The choices (how much comes out, the flooring type)
and the yes/no questions (dust protection, hazard testing, permit,
inspections) stay user-answered - the auto-run fills quantities only. There is
no calibration: the AI reads printed dimensions, and the app does the maths
from them.
"""

from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "demolition"            # this trade's module id (the manifest, the sheet switches)

# The Demolition manifest's quantity questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("interior_sqft", "Interior area to demo", "sq ft of interior to demo", "area", "sqft"),
    ("walls_lf", "Non-bearing walls to remove", "lf of walls to remove", "length", "lf"),
    ("cabinets_lf", "Cabinets to remove", "lf of cabinets to remove", "length", "lf"),
    ("fixtures", "Fixtures to remove (toilets, tubs, sinks)", "fixtures to remove", "count", "ea"),
    ("flooring_sqft", "Flooring to tear out", "sq ft of flooring to tear out", "area", "sqft"),
    ("concrete_sqft", "Concrete to break out (4 in)", "sq ft of concrete to break out", "area", "sqft"),
    ("structure_sqft", "Shed, carport or small structure footprint", "sq ft of structure to demolish",
     "area", "sqft"),
)
QUESTION_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

DEMOLITION_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the demolition plan. "
                              "Reply with ONLY one JSON object, nothing else.")

DEMOLITION_READ_SYSTEM = ("You are reading a demolition plan to find what is marked for removal. "
                          "Reply with ONLY one JSON object, nothing else.")


def parse_demolition_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(demolition sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "demolition_sheet_id")


def _parse_runs(value, key: str) -> list[dict]:
    """A list of named runs the AI read off the plan: each has a length string.
    The app adds the lengths up - the AI never totals them."""
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
        v = item.get("length_ft")
        if v is None:
            raise lt.LlmTakeoffError(f"the AI's answer is missing {where} length_ft")
        if not isinstance(v, str) or not v.strip():
            raise lt.LlmTakeoffError(f"the AI's answer has {where} length_ft = {v!r}, not text")
        runs.append({"name": (name or "").strip()[:80], "length_ft": v.strip()})
    return runs


def _parse_count(obj: dict, feeds: str) -> int:
    """One whole-number count (0 when there are none - never null)."""
    if feeds not in obj:
        raise lt.LlmTakeoffError(f"the AI's answer is missing the {feeds} count")
    v = obj[feeds]
    if isinstance(v, bool) or not isinstance(v, int):
        raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v!r}, not a whole number")
    if v < 0:
        raise lt.LlmTakeoffError(f"the AI's answer has {feeds} = {v}, a negative count")
    return v


def _check_rects(rects: list[dict], kind: str) -> None:
    """Every printed width and length must be a length the app can read - a
    dimension the AI hedged on rejects the whole answer, here, so the AI Log
    says which one was wrong."""
    for r in rects:
        lq.dimension_inches(r["width_ft"], f"{kind} {r['name'] or '?'} width")
        lq.dimension_inches(r["length_ft"], f"{kind} {r['name'] or '?'} length")


def _check_runs(runs: list[dict], kind: str) -> None:
    """Every printed run length must be a length the app can read."""
    for r in runs:
        lq.dimension_inches(r["length_ft"], f"{kind} {r['name'] or '?'} length")


def parse_demolition_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the rooms to demo, the wall and cabinet
    runs marked for removal, the fixture count, the concrete breakout and
    structure areas - every printed dimension a feet'-inches" string the app can
    read - the evidence for each quantity, confidence 0-1 (or None), notes. Any
    defect rejects the whole answer. The demolition sheet is the one that was
    shown, whatever id the AI wrote down."""
    obj = lt._parse_json_object(text)
    rooms = lq.parse_rooms(obj.get("rooms"), "rooms")
    wall_runs = _parse_runs(obj.get("wall_runs"), "wall_runs")
    cabinet_runs = _parse_runs(obj.get("cabinet_runs"), "cabinet_runs")
    concrete_areas = lq.parse_rooms(obj.get("concrete_areas"), "concrete_areas")
    structure_areas = lq.parse_rooms(obj.get("structure_areas"), "structure_areas")
    _check_rects(rooms, "room")
    _check_runs(wall_runs, "wall run")
    _check_runs(cabinet_runs, "cabinet run")
    _check_rects(concrete_areas, "concrete area")
    _check_rects(structure_areas, "structure area")
    counts = {"fixtures": _parse_count(obj, "fixtures")}
    ev = lq.parse_evidence(obj, QUESTION_IDS)
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "demolition_sheet_id", sheet_id, notes)
    return {"demolition_sheet_id": sheet_id, "rooms": rooms, "wall_runs": wall_runs,
            "cabinet_runs": cabinet_runs, "counts": counts, "concrete_areas": concrete_areas,
            "structure_areas": structure_areas, "evidence": ev, "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read what this plan marks for removal, with the
    printed dimensions and the evidence for each quantity, so a person can check
    every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read what this demolition plan marks for removal,"
        " with the printed dimensions - only what is marked for removal (demolition notes, hatching, dashed"
        " or marked-out walls and areas). Do not read anything that stays: an unmarked room, wall or slab"
        " is not demolition."
        " Read the rooms or areas to demo as rooms, each with its printed width and length (a whole demo area"
        " with one overall width and length is one room); the flooring torn out is the floor of those same"
        " rooms. Read each wall run marked for removal with its printed length, each cabinet run marked for"
        " removal with its printed length, and count the fixtures to remove (toilets, tubs, sinks). Read"
        " each concrete area to break out and each structure footprint with its printed width and length."
        " When a quantity has nothing marked on the plan, answer an empty list (or 0 for fixtures) - never"
        " null, never a guess. Read the dimensions exactly as printed, as feet'-inches\" strings like"
        " \"14'-6\\\"\" - never compute an area or a total; the app does the maths."
        " Reply with ONLY this JSON: {\"demolition_sheet_id\": " + str(sheet["id"])
        + ", \"rooms\": [{\"name\": \"Kitchen\", \"width_ft\": \"12'-0\\\"\", \"length_ft\": \"14'-6\\\"\"}],"
          " \"wall_runs\": [{\"name\": \"Kitchen north wall\", \"length_ft\": \"14'-6\\\"\"}],"
          " \"cabinet_runs\": [{\"name\": \"Kitchen base cabinets\", \"length_ft\": \"10'-0\\\"\"}],"
          " \"fixtures\": 3, \"concrete_areas\": [{\"name\": \"Patio slab\", \"width_ft\": \"10'-0\\\"\","
          " \"length_ft\": \"12'-0\\\"\"}], \"structure_areas\": [], \"confidence\": 0.9,"
          " \"notes\": \"one line\", \"evidence\": {\"interior_sqft\": \"which rooms, which printed dimensions\","
          " \"walls_lf\": \"...\", \"cabinets_lf\": \"...\", \"fixtures\": \"...\", \"flooring_sqft\": \"...\","
          " \"concrete_sqft\": \"...\", \"structure_sqft\": \"...\"}}."
          " Rules: every count is a whole number - answer 0 when there are none, never null, never a guess;"
          " every list is empty when nothing is marked for it. evidence says what was read for each number,"
          " so a person can check it; confidence is 0-1, how sure you are about the reading.")


# ------------------------------------------------------------------ the quantities

def _runs_length_lf(runs: list[dict], kind: str) -> str:
    """The runs' lengths added up, to 0.01 lf (the app's maths, not the AI's)."""
    total = Decimal(0)
    for r in runs:
        total += Decimal(lq.dimension_inches(r["length_ft"], f"{kind} {r['name'] or '?'} length")) / Decimal(12)
    return str(total.quantize(Decimal("0.01")))


def quantities_from_reading(reading: dict) -> dict:
    """The quantities as the run reports them: all seven questions. The interior
    and flooring areas are the same rooms' area; the run lengths and the breakout
    areas are added up from the printed dimensions."""
    rooms_area = lq.rooms_area_sqft(reading["rooms"])
    return {"values": {
        "interior_sqft": rooms_area,
        "walls_lf": _runs_length_lf(reading["wall_runs"], "wall run"),
        "cabinets_lf": _runs_length_lf(reading["cabinet_runs"], "cabinet run"),
        "fixtures": int(reading["counts"]["fixtures"]),
        "flooring_sqft": rooms_area,
        "concrete_sqft": lq.rooms_area_sqft(reading["concrete_areas"]),
        "structure_sqft": lq.rooms_area_sqft(reading["structure_areas"]),
    }}


def demolition_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Demolition",
    "sheet_phrase": "the demolition sheet",
    "questions": QUESTIONS,
    "classify_system": DEMOLITION_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the demolition plan (demolition notes, areas marked for removal)?",
    "read_system": DEMOLITION_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_demolition_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_demolition(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the demolition plan with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def demolition_results(conn, ctx, row: dict) -> dict | None:
    """What a finished demolition run read, as a list to show, plus all seven
    quantities - including the zeros, which got no measurement row. Evidence for
    a proposed quantity comes from its measurement; for a zero quantity, from
    what the AI said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

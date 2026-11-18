"""LLM-assisted siding takeoff: read the elevations with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the elevations sheet, read it with
the AI, propose one measurement per quantity found. This module is only what is
siding's own - the questions, the prompts, the parsing.

The AI reads each outside wall face on the elevations (its printed width and
height) and counts the windows and doors in those walls and the outside and
inside corners. The app does all the maths from those readings - the wall area
is the faces' areas added up, and the eave length is the faces' widths added
up (the eaves run the full width of each elevation) - never the AI's numbers.

The choices (material, simple or complex walls, stories, soffit depth) and the
yes/no questions (new house wrap, remove the old siding, permit, inspections)
stay user-answered - the auto-run fills quantities only. There is no
calibration: the AI reads printed dimensions, and the app does the maths from
them.
"""

from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "siding"                # this trade's module id (the manifest, the sheet switches)

# The Siding manifest's quantity questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("wall_sqft", "Outside wall area (all sides)", "sq ft of outside wall", "area", "sqft"),
    ("openings", "Windows and doors in those walls", "openings", "count", "ea"),
    ("outside_corners", "Outside corners", "outside corners", "count", "ea"),
    ("inside_corners", "Inside corners", "inside corners", "count", "ea"),
    ("eave_lf", "Eaves (soffit and fascia)", "lf of eaves", "length", "lf"),
)
QUESTION_IDS = tuple(q[0] for q in QUESTIONS)
COUNT_IDS = ("openings", "outside_corners", "inside_corners")
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

SIDING_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the elevations. "
                          "Reply with ONLY one JSON object, nothing else.")

SIDING_READ_SYSTEM = ("You are reading building elevations to measure the outside walls. "
                      "Reply with ONLY one JSON object, nothing else.")


def parse_siding_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(elevations sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "siding_sheet_id")


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


def _check_faces(faces: list[dict]) -> None:
    """Every printed width and height must be a length the app can read - a
    dimension the AI hedged on rejects the whole answer, here, so the AI Log
    says which one was wrong."""
    for f in faces:
        lq.dimension_inches(f["width_ft"], f"elevation {f['name'] or '?'} width")
        lq.dimension_inches(f["height_ft"], f"elevation {f['name'] or '?'} height")


def parse_siding_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the elevation faces - every printed
    dimension a feet'-inches" string the app can read - the openings and corner
    counts (whole numbers, 0 when there are none, never null), the evidence for
    each quantity, confidence 0-1 (or None), notes. Any defect rejects the whole
    answer. The elevations sheet is the one that was shown, whatever id the AI
    wrote down."""
    obj = lt._parse_json_object(text)
    elevations = _parse_faces(obj.get("elevations"), "elevations")
    _check_faces(elevations)
    counts = {feeds: _parse_count(obj, feeds) for feeds in COUNT_IDS}
    ev = lq.parse_evidence(obj, QUESTION_IDS)
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "siding_sheet_id", sheet_id, notes)
    return {"siding_sheet_id": sheet_id, "elevations": elevations, "counts": counts,
            "evidence": ev, "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read the elevation faces and count the openings
    and corners, with the printed dimensions and the evidence for each quantity,
    so a person can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read each outside wall face on these elevations,"
        " with its printed width and height, and count the windows and doors in those walls, the outside"
        " corners and the inside corners. The eaves run the full width of each elevation shown - say so in"
        " the evidence for eave_lf."
        " When a quantity has nothing shown on the plan, answer an empty list (or 0 for a count) - never"
        " null, never a guess. Read the dimensions exactly as printed, as feet'-inches\" strings like"
        " \"40'-0\\\"\" - never compute an area or a total; the app does the maths."
        " Reply with ONLY this JSON: {\"siding_sheet_id\": " + str(sheet["id"])
        + ", \"elevations\": [{\"name\": \"Front\", \"width_ft\": \"40'-0\\\"\", \"height_ft\": \"9'-0\\\"\"}],"
          " \"openings\": 12, \"outside_corners\": 4, \"inside_corners\": 2, \"confidence\": 0.9,"
          " \"notes\": \"one line\", \"evidence\": {\"wall_sqft\": \"which faces, which printed dimensions\","
          " \"openings\": \"...\", \"outside_corners\": \"...\", \"inside_corners\": \"...\","
          " \"eave_lf\": \"the eaves run the full width of each elevation shown\"}}."
          " Rules: every count is a whole number - answer 0 when there are none, never null, never a guess;"
          " every list is empty when nothing is shown for it. evidence says what was read for each number,"
          " so a person can check it; confidence is 0-1, how sure you are about the reading.")


# ------------------------------------------------------------------ the quantities

def _faces_area_sqft(faces: list[dict]) -> str:
    """The faces' areas added up, to 0.01 sq ft (the app's maths, not the AI's)."""
    total = Decimal(0)
    for f in faces:
        w = Decimal(lq.dimension_inches(f["width_ft"], f"elevation {f['name'] or '?'} width")) / Decimal(12)
        h = Decimal(lq.dimension_inches(f["height_ft"], f"elevation {f['name'] or '?'} height")) / Decimal(12)
        total += w * h
    return str(total.quantize(Decimal("0.01")))


def _faces_width_lf(faces: list[dict]) -> str:
    """The faces' widths added up, to 0.01 lf - the eaves run the full width of
    each elevation (the app's maths, not the AI's)."""
    total = Decimal(0)
    for f in faces:
        total += Decimal(lq.dimension_inches(f["width_ft"], f"elevation {f['name'] or '?'} width")) / Decimal(12)
    return str(total.quantize(Decimal("0.01")))


def quantities_from_reading(reading: dict) -> dict:
    """The quantities as the run reports them: all five questions. The wall area
    is the elevation faces' areas added up; the eave length is their widths added up."""
    return {"values": {
        "wall_sqft": _faces_area_sqft(reading["elevations"]),
        "openings": int(reading["counts"]["openings"]),
        "outside_corners": int(reading["counts"]["outside_corners"]),
        "inside_corners": int(reading["counts"]["inside_corners"]),
        "eave_lf": _faces_width_lf(reading["elevations"]),
    }}


def siding_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Siding",
    "sheet_phrase": "the elevations sheet",
    "questions": QUESTIONS,
    "classify_system": SIDING_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the elevations (outside walls, wall sections)?",
    "read_system": SIDING_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_siding_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_siding(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the elevations with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def siding_results(conn, ctx, row: dict) -> dict | None:
    """What a finished siding run read, as a list to show, plus all five
    quantities - including the zeros, which got no measurement row. Evidence for
    a proposed quantity comes from its measurement; for a zero quantity, from
    what the AI said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

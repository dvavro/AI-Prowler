"""LLM-assisted framing takeoff: count the openings, corners and trusses, and read
the room dimensions for the floor area, with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the framing sheet, read it with
the AI, propose one measurement per quantity found. This module is only what
is framing's own - the questions, the prompts, the parsing.

The AI counts door and window openings, corners and wall ends, and roof
trusses, and reads the printed room dimensions - the app works the floor area
out from those dimensions (Decimal, to 0.01 sq ft). The AI never computes an
area itself.

Wall length stays user-answered: per-wall lengths are not printed on plans, so
the AI cannot read them. The honest path is geometric summing of the plan
engine's detected wall objects on a calibrated viewport, which is a follow-up,
not this reader. The choices (wall height, stud size, spacing, exterior walls)
stay user-answered too - the auto-run fills counts and areas only.
"""

from __future__ import annotations

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "framing"               # this trade's module id (the manifest, the sheet switches)

# The Framing manifest's read questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("corners", "Corners and wall ends", "corners and wall ends", "count", "ea"),
    ("openings", "Door and window openings", "door and window openings", "count", "ea"),
    ("floor_sqft", "Floor to frame (joists and subfloor)", "sq ft of floor to frame", "area", "sqft"),
    ("trusses", "Roof trusses to set", "roof trusses", "count", "ea"),
)
COUNT_IDS = ("corners", "openings", "trusses")
ALL_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

FRAMING_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the framing plan. "
                           "Reply with ONLY one JSON object, nothing else.")

FRAMING_READ_SYSTEM = ("You are reading a framing plan to count the openings, corners and trusses "
                       "and read the room dimensions on it. "
                       "Reply with ONLY one JSON object, nothing else.")


def parse_framing_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(framing sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "framing_sheet_id")


def parse_framing_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: three whole-number counts (0 when there are
    none - never null), the rooms with their printed dimensions, the evidence for
    each quantity, confidence 0-1 (or None), notes. Any defect rejects the whole
    answer - a count the AI hedged on is no count at all, and a dimension it hedged
    on is no dimension at all. The framing sheet is the one that was shown,
    whatever id the AI wrote down."""
    obj = lt._parse_json_object(text)
    rooms = lq.parse_rooms(obj.get("rooms"), "rooms")
    for r in rooms:      # the dimensions must parse now - a bad one rejects the whole answer
        lq.dimension_inches(r["width_ft"], f"room {r['name'] or '?'} width")
        lq.dimension_inches(r["length_ft"], f"room {r['name'] or '?'} length")
    reading = lq.parse_counts(text, sheet_id, COUNT_IDS, "framing_sheet_id")
    reading["evidence"] = lq.parse_evidence(obj, ALL_IDS)
    reading["rooms"] = rooms
    return reading


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: count the openings, corners and trusses on this
    sheet, and read the printed room dimensions, with the evidence for each
    number, so a person can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the framing quantities shown on it."
        " Count the door and window openings on the plan or the schedule (each door and each window"
        " is one opening); count the corners and wall ends on the floor plan; count the roof trusses"
        " on the roof framing plan - answer 0 for trusses when this sheet shows no roof framing plan."
        " Read the printed dimensions of every room (width and length), so the floor area can be"
        " worked out from them - use the dimensions printed on the plan, as feet'-inches\"."
        " Reply with ONLY this JSON: {\"framing_sheet_id\": " + str(sheet["id"])
        + ", \"corners\": 4, \"openings\": 12, \"trusses\": 18,"
        " \"rooms\": [{\"name\": \"Living\", \"width_ft\": \"14'-6\\\"\", \"length_ft\": \"20'-0\\\"\"}],"
        " \"confidence\": 0.9, \"notes\": \"one line\","
        " \"evidence\": {\"corners\": \"what was counted, which walls and corners\","
        " \"openings\": \"...\", \"floor_sqft\": \"which rooms were dimensioned\", \"trusses\": \"...\"}}."
        " Rules: every count is a whole number - answer 0 when there are none, never null, never a guess;"
        " rooms holds every room whose dimensions are printed, as feet'-inches\" (\"14'-6\\\"\");"
        " an empty rooms list means the plan prints no room dimensions."
        " evidence says what was counted or read for each number, so a person can check it; confidence is 0-1,"
        " how sure you are about the counts and dimensions. Do not work out any areas yourself -"
        " the app does the maths from the dimensions you read.")


# ------------------------------------------------------------------ the quantities

def quantities_from_reading(reading: dict) -> dict:
    """The counts as the run reports them, plus the floor area worked out from the
    rooms the AI dimensioned (Decimal, to 0.01 sq ft - the app's maths, not the
    AI's). No dimensioned rooms means 0.00 sq ft."""
    return {"values": {"corners": int(reading["counts"]["corners"]),
                       "openings": int(reading["counts"]["openings"]),
                       "floor_sqft": lq.rooms_area_sqft(reading["rooms"]),
                       "trusses": int(reading["counts"]["trusses"])}}


def framing_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI counted and dimensioned, in the shape
    the results page reads. It carries every quantity - including the zeros, which
    get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Framing",
    "sheet_phrase": "the framing sheet",
    "questions": QUESTIONS,
    "classify_system": FRAMING_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the framing plan (floor framing, roof framing, wall framing)?",
    "read_system": FRAMING_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_framing_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_framing(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the framing quantities on the framing plan with the AI and propose the measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def framing_results(conn, ctx, row: dict) -> dict | None:
    """What a finished framing run counted and dimensioned, as a list to show, plus
    all four quantities - including the zeros, which got no measurement row.
    Evidence for a proposed quantity comes from its measurement; for a zero
    quantity, from what the AI said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

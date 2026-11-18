"""LLM-assisted roofing takeoff: read the roof dimensions off the roof plan.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the roof plan sheet, read it with
the AI, propose one measurement per quantity found. This module is only what
is roofing's own - the questions, the prompts, the parsing.

The AI reads the overall printed roof dimensions - width and length as seen
from above, including overhangs - and the ridge lengths when the plan prints
them. The app does the maths: the roof area is width times length, the eaves
and rakes are the perimeter, the ridge is the printed ridge length. The AI
never computes an area or a length. Both overall dimensions are required - a
roof the AI couldn't dimension is measured by hand, never guessed. When the
plan doesn't dimension the ridges, the ridge length is 0.00 and the pricing
falls back to its estimate from the roof area.

The choices (pitch, shape, roofing, stories) stay user-answered - the auto-run
fills quantities only. Layers and decking sheets stay user-answered too: a plan
can't say how many layers are on the roof or how much decking is rotten - that
is a site check. Permit and inspections are the person's call. There is no
calibration: the AI reads printed dimensions, and the app does the maths from
them.
"""

from __future__ import annotations

import json
from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "roofing"               # this trade's module id (the manifest, the sheet switches)

# The Roofing manifest's extracted questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("roof_area_sqft", "Roof area seen from above (include overhangs)", "sq ft of roof",
     "area", "sqft"),
    ("edges_lf", "Eaves and rakes (drip edge)", "lf of eaves and rakes", "length", "lf"),
    ("ridge_lf", "Ridges and hips", "lf of ridges and hips", "length", "lf"),
)
ALL_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}

NO_RIDGE_EVIDENCE = "the plan doesn't dimension the ridges"


# ------------------------------------------------------------------ the AI calls

ROOFING_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the roof plan. "
                           "Reply with ONLY one JSON object, nothing else.")

ROOFING_READ_SYSTEM = ("You are reading a roof plan to read the roof dimensions on it. "
                       "Reply with ONLY one JSON object, nothing else.")


def parse_roofing_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(roof plan sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "roofing_sheet_id")


def parse_roofing_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the overall roof dimensions as text (or
    None when the AI couldn't read them - the quantities step fails loudly then),
    the ridge length as text (or None when the plan doesn't dimension the ridges),
    the evidence for each quantity, confidence 0-1 (or None), notes. Any defect
    rejects the whole answer - a dimension the AI hedged on is no dimension at all.
    The roof plan sheet is the one that was shown, whatever id the AI wrote down."""
    obj = lt._parse_json_object(text)

    def _text(key):
        v = obj.get(key)
        if v is None:
            return None
        if not isinstance(v, str):
            raise lt.LlmTakeoffError(f"the AI's answer has {key} = {v!r}, not text")
        return v.strip() or None

    width = _text("roof_width_ft")
    length = _text("roof_length_ft")
    ridge = _text("ridge_ft")
    ev = lq.parse_evidence(obj, ALL_IDS)
    if ridge is None and not ev["ridge_lf"]:
        ev["ridge_lf"] = NO_RIDGE_EVIDENCE
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "roofing_sheet_id", sheet_id, notes)
    return {"roofing_sheet_id": sheet_id, "roof_width_ft": width, "roof_length_ft": length,
            "ridge_ft": ridge, "evidence": ev, "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read the overall roof dimensions on this sheet and
    the ridge lengths when the plan prints them, with the evidence for each number,
    so a person can check every number against the drawing."""
    example = {"roofing_sheet_id": sheet["id"], "roof_width_ft": "40'-0\"",
               "roof_length_ft": "50'-0\"", "ridge_ft": "24'-0\"",
               "confidence": 0.9, "notes": "one line",
               "evidence": {"roof_area_sqft": "which overall dimensions were read",
                            "edges_lf": "which overall dimensions were read",
                            "ridge_lf": "which ridge lengths were read"}}
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the roof plan on it: the overall roof"
        " dimensions as seen from above, and the ridge lengths if the plan prints them."
        " Read the overall width and length of the roof - the outside dimensions including overhangs -"
        " as feet'-inches\", from the dimension lines on the plan, not from the scale."
        " Read the ridge lengths the same way when the plan prints them; when it doesn't dimension the"
        " ridges, answer null for ridge_ft - never guess a length."
        " Reply with ONLY this JSON: " + json.dumps(example) + "."
        " Rules: roof_width_ft and roof_length_ft are the overall printed dimensions - both are required,"
        " never null. ridge_ft is the printed ridge length, or null when the plan doesn't dimension the"
        " ridges. evidence says what was read for each number, so a person can check it; confidence is"
        " 0-1, how sure you are about the dimensions.")


# ------------------------------------------------------------------ the quantities

def quantities_from_reading(reading: dict) -> dict:
    """Area and lengths from the dimensions the AI read. Both overall dimensions
    must be present and parseable - anything else fails loudly instead of guessing,
    like concrete's missing slab dimensions. The ridge is 0.00 when the plan
    doesn't dimension the ridges. All three questions, in manifest order."""
    missing = [name for name, key in (("width", "roof_width_ft"), ("length", "roof_length_ft"))
                 if not reading.get(key)]
    if missing:
        raise lt.LlmTakeoffError("the AI read the roof plan sheet but couldn't read the roof "
                                 + " and ".join(missing) + " - it left "
                                 + ("it" if len(missing) == 1 else "them")
                                 + " blank; measure the roof by hand")
    w_ft = Decimal(lq.dimension_inches(reading["roof_width_ft"], "roof width")) / Decimal(12)
    l_ft = Decimal(lq.dimension_inches(reading["roof_length_ft"], "roof length")) / Decimal(12)
    area = (w_ft * l_ft).quantize(Decimal("0.01"))
    edges = ((w_ft + l_ft) * 2).quantize(Decimal("0.01"))
    if reading.get("ridge_ft"):
        ridge = (Decimal(lq.dimension_inches(reading["ridge_ft"], "ridge length"))
                 / Decimal(12)).quantize(Decimal("0.01"))
    else:
        ridge = Decimal("0.00")
    return {"values": {"roof_area_sqft": str(area), "edges_lf": str(edges),
                       "ridge_lf": str(ridge)}}


def roofing_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Roofing",
    "sheet_phrase": "the roof plan sheet",
    "questions": QUESTIONS,
    "classify_system": ROOFING_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the roof plan (roof outline, ridges, elevations)?",
    "read_system": ROOFING_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_roofing_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_roofing(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the roof plan with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration: the AI
    reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def roofing_results(conn, ctx, row: dict) -> dict | None:
    """What a finished roofing run read, as a list to show, plus all three
    quantities - including the zeros, which got no measurement row. Evidence for a
    proposed quantity comes from its measurement; for a zero quantity, from what
    the AI said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

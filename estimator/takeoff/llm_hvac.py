"""LLM-assisted HVAC takeoff: read the conditioned area and count the devices on the mechanical plan.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the mechanical sheet, read it with
the AI, propose one measurement per quantity found. This module is only what
is HVAC's own - the questions, the prompts, the parsing.

The AI reads the printed room dimensions and counts the devices: mini-split
indoor heads, supply registers, return grilles, thermostats. The app does the
area maths from the room dimensions - the AI never computes an area. When the
sheet shows no room dimensions, the conditioned area is 0.00 and the person
measures it by hand.

The choices (system, ducts) stay user-answered - the auto-run fills quantities
only. Tons and square feet per ton stay user-answered too: they are the sizing
rule, derived from the area, not read off the plan. The duct and line-set
lengths stay user-answered as well: a plan image doesn't dimension duct runs
or line sets, and guessing a length from the picture would invent it. Removal,
permit and inspections are the person's call. There is no calibration: the AI
reads printed dimensions, and the app does the maths from them.
"""

from __future__ import annotations

import json

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "hvac"                  # this trade's module id (the manifest, the sheet switches)

# The HVAC manifest's extracted questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("conditioned_sqft", "Area to heat and cool", "sq ft conditioned", "area", "sqft"),
    ("zones", "Mini-split indoor heads", "mini-split heads", "count", "ea"),
    ("registers", "Supply registers", "supply registers", "count", "ea"),
    ("returns", "Return grilles", "return grilles", "count", "ea"),
    ("thermostats", "Thermostats", "thermostats", "count", "ea"),
)
COUNT_IDS = ("zones", "registers", "returns", "thermostats")
ALL_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

HVAC_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the mechanical plan. "
                        "Reply with ONLY one JSON object, nothing else.")

HVAC_READ_SYSTEM = ("You are reading a mechanical plan to count the HVAC devices and read the room"
                    " dimensions on it. Reply with ONLY one JSON object, nothing else.")


def parse_hvac_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(mechanical sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "hvac_sheet_id")


def parse_hvac_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: four whole-number counts (0 when there are
    none - never null), the rooms the AI read printed dimensions for (an empty list
    when the sheet shows none), the evidence for each quantity, confidence 0-1 (or
    None), notes. Any defect rejects the whole answer - a count the AI hedged on is
    no count at all, and a dimension it hedged on is no dimension at all. The
    mechanical sheet is the one that was shown, whatever id the AI wrote down."""
    reading = lq.parse_counts(text, sheet_id, COUNT_IDS, "hvac_sheet_id")
    obj = lt._parse_json_object(text)
    reading["rooms"] = lq.parse_rooms(obj.get("rooms"), "rooms")
    for r in reading["rooms"]:      # the dimensions must parse now - a bad one rejects the whole answer
        lq.dimension_inches(r["width_ft"], f"room {r['name'] or '?'} width")
        lq.dimension_inches(r["length_ft"], f"room {r['name'] or '?'} length")
    reading["evidence"] = lq.parse_evidence(obj, ALL_IDS)
    return reading


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: count the HVAC devices on this sheet and read the
    printed room dimensions, with the evidence for each number, so a person can check
    every number against the drawing."""
    example = {"hvac_sheet_id": sheet["id"], "zones": 3, "registers": 8, "returns": 2,
               "thermostats": 2,
               "rooms": [{"name": "Living room", "width_ft": "14'-6\"", "length_ft": "18'-0\""}],
               "confidence": 0.9, "notes": "one line",
               "evidence": {"conditioned_sqft": "which rooms and dimensions were read",
                            "zones": "...", "registers": "...", "returns": "...",
                            "thermostats": "..."}}
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the mechanical plan on it: count the"
        " HVAC devices and read the printed room dimensions."
        " Count each device once, from the drawing itself (use the legend when one is printed):"
        " zones are ductless mini-split indoor heads (wall or ceiling units); registers are supply"
        " registers and diffusers; returns are return grilles; thermostats are thermostat locations."
        " Read the printed dimensions of every conditioned room (living room, bedrooms, kitchen, ...) as"
        " feet'-inches\" - width and length for each room, from the dimension lines on the plan, not from"
        " the scale. Do not add up areas and do not guess a dimension that isn't printed: a room with no"
        " printed dimensions is left out of the rooms list."
        " Reply with ONLY this JSON: " + json.dumps(example) + "."
        " Rules: every count is a whole number - answer 0 when there are none, never null, never a guess."
        " rooms is the list of rooms with printed dimensions - an empty list when the sheet shows no room"
        " dimensions. evidence says what was counted or read for each number, so a person can check it;"
        " confidence is 0-1, how sure you are about the counts and dimensions.")


# ------------------------------------------------------------------ the quantities

def quantities_from_reading(reading: dict) -> dict:
    """The quantities as the run reports them: the conditioned area the app worked
    out from the rooms' printed dimensions (0.00 when the sheet shows none), and the
    four counts. All five questions, in manifest order."""
    values = {feeds: int(reading["counts"][feeds]) for feeds in COUNT_IDS}
    return {"values": {"conditioned_sqft": lq.rooms_area_sqft(reading["rooms"]),
                       "zones": values["zones"], "registers": values["registers"],
                       "returns": values["returns"], "thermostats": values["thermostats"]}}


def hvac_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "HVAC",
    "sheet_phrase": "the mechanical sheet",
    "questions": QUESTIONS,
    "classify_system": HVAC_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the mechanical plan (HVAC, ducts, air handlers)?",
    "read_system": HVAC_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_hvac_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_hvac(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the mechanical plan with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration: the AI
    reads printed dimensions, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def hvac_results(conn, ctx, row: dict) -> dict | None:
    """What a finished HVAC run read, as a list to show, plus all five quantities -
    including the zeros, which got no measurement row. Evidence for a proposed
    quantity comes from its measurement; for a zero quantity, from what the AI said
    it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

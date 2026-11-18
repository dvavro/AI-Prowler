"""LLM-assisted plumbing takeoff: count the fixtures on the plumbing plan with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the plumbing sheet, read it with
the AI, propose one count measurement per fixture kind found. This module is
only what is plumbing's own - the questions, the prompts, the parsing.

The AI counts fixtures: toilets, bathroom sinks, kitchen or bar sinks, showers
and tubs, dishwashers to hook up, washer boxes, hose bibs. Pipe lengths
(supply, drain and vent, gas) stay user-answered: a plan image doesn't
dimension pipe runs, and guessing a length from the picture would invent it.

The choices (type of work, water heater, supply the fixtures) stay
user-answered too - the auto-run fills counts only. There is no calibration:
counts need no scale.
"""

from __future__ import annotations

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "plumbing"              # this trade's module id (the manifest, the sheet switches)

# The Plumbing manifest's count questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("toilets", "Toilets", "toilets", "count", "ea"),
    ("sinks", "Bathroom sinks", "bathroom sinks", "count", "ea"),
    ("kitchen_sinks", "Kitchen or bar sinks", "kitchen or bar sinks", "count", "ea"),
    ("showers", "Showers and tubs", "showers and tubs", "count", "ea"),
    ("dishwashers", "Dishwashers to hook up", "dishwashers", "count", "ea"),
    ("washers", "Washer boxes (laundry)", "washer boxes", "count", "ea"),
    ("hose_bibs", "Hose bibs", "hose bibs", "count", "ea"),
)
COUNT_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

PLUMBING_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the plumbing plan. "
                            "Reply with ONLY one JSON object, nothing else.")

PLUMBING_READ_SYSTEM = ("You are reading a plumbing plan to count the fixtures on it. "
                        "Reply with ONLY one JSON object, nothing else.")


def parse_plumbing_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(plumbing sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "plumbing_sheet_id")


def parse_plumbing_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: seven whole-number counts (0 when there are
    none - never null), the evidence for each count, confidence 0-1 (or None), notes.
    Any defect rejects the whole answer - a count the AI hedged on is no count at
    all. The plumbing sheet is the one that was shown, whatever id the AI wrote down."""
    return lq.parse_counts(text, sheet_id, COUNT_IDS, "plumbing_sheet_id")


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: count the fixtures on this sheet, with the evidence
    for each count, so a person can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Count the plumbing fixtures shown on it."
        " Count each fixture once, from the drawing itself (use the legend when one is printed):"
        " toilets are water closets; sinks are bathroom lavatories; kitchen_sinks are kitchen or bar sinks;"
        " showers are showers and bathtubs (a tub/shower combination counts once, as showers);"
        " dishwashers are dishwasher hookups; washers are laundry washer boxes; hose_bibs are exterior"
        " hose bibs or sillcocks."
        " Do not double-count: a bathroom sink counts as sinks, not kitchen_sinks; a laundry tub"
        " is not a washer box."
        " Reply with ONLY this JSON: {\"plumbing_sheet_id\": " + str(sheet["id"])
        + ", \"toilets\": 2, \"sinks\": 3, \"kitchen_sinks\": 1, \"showers\": 2, \"dishwashers\": 1,"
          " \"washers\": 1, \"hose_bibs\": 2, \"confidence\": 0.9,"
          " \"notes\": \"one line\", \"evidence\": {\"toilets\": \"what was counted, which symbols and areas\","
          " \"sinks\": \"...\", \"kitchen_sinks\": \"...\", \"showers\": \"...\", \"dishwashers\": \"...\","
          " \"washers\": \"...\", \"hose_bibs\": \"...\"}}."
        " Rules: every count is a whole number - answer 0 when there are none, never null, never a guess."
        " evidence says what was counted for each number, so a person can check it; confidence is 0-1,"
        " how sure you are about the counts.")


# ------------------------------------------------------------------ the counts

def quantities_from_reading(reading: dict) -> dict:
    """The counts as the run reports them: all seven questions."""
    return lq.quantities_from_counts(reading, COUNT_IDS)


def plumbing_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI counted, in the shape the results page
    reads. It carries every count - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Plumbing",
    "sheet_phrase": "the plumbing sheet",
    "questions": QUESTIONS,
    "classify_system": PLUMBING_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the plumbing plan (fixtures, water supply, drain)?",
    "read_system": PLUMBING_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_plumbing_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_plumbing(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Count the fixtures on the plumbing plan with the AI and propose the count measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    counts need no scale.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def plumbing_results(conn, ctx, row: dict) -> dict | None:
    """What a finished plumbing run counted, as a list to show, plus all seven
    counts - including the zeros, which got no measurement row. Evidence for a
    counted fixture comes from its measurement; for a zero count, from what the AI
    said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

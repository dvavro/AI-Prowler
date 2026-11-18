"""LLM-assisted windows and doors takeoff: count the windows and doors on the
window and door sheet with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the window and door sheet, read it
with the AI, propose one count measurement per unit kind found. This module is
only what is windows and doors' own - the questions, the prompts, the parsing.

The AI counts small windows (under 15 sq ft), large windows (15 sq ft and
over), patio sliders and French doors, exterior doors, interior doors and
garage doors. The small/large split comes from the window schedule when sizes
are listed; otherwise the AI judges each window against the 3 ft doors shown,
and the evidence says which method was used.

The choices (type of install, window type, casing, remove the old units) stay
user-answered - the auto-run fills counts only. There is no calibration:
counts need no scale.
"""

from __future__ import annotations

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "windows_doors"         # this trade's module id (the manifest, the sheet switches)

# The Windows and Doors manifest's count questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("windows_small", "Windows under 15 sq ft", "small windows", "count", "ea"),
    ("windows_large", "Windows 15 sq ft and over", "large windows", "count", "ea"),
    ("patio_doors", "Patio sliders or French doors", "patio doors", "count", "ea"),
    ("exterior_doors", "Exterior doors (prehung)", "exterior doors", "count", "ea"),
    ("interior_doors", "Interior doors (prehung)", "interior doors", "count", "ea"),
    ("garage_doors", "Garage doors", "garage doors", "count", "ea"),
)
COUNT_IDS = tuple(q[0] for q in QUESTIONS)
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

WINDOWS_DOORS_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the window and door "
                                 "sheet. Reply with ONLY one JSON object, nothing else.")

WINDOWS_DOORS_READ_SYSTEM = ("You are reading a window and door sheet to count the windows and doors "
                             "on it. Reply with ONLY one JSON object, nothing else.")


def parse_windows_doors_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(window and door sheet id or None, notes) from the classify call. An id that
    wasn't shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "windows_doors_sheet_id")


def parse_windows_doors_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: six whole-number counts (0 when there are
    none - never null), the evidence for each count, confidence 0-1 (or None), notes.
    Any defect rejects the whole answer - a count the AI hedged on is no count at
    all. The window and door sheet is the one that was shown, whatever id the AI wrote down."""
    return lq.parse_counts(text, sheet_id, COUNT_IDS, "windows_doors_sheet_id")


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: count the windows and doors on this sheet, with the
    evidence for each count, so a person can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Count the windows and doors shown on it."
        " Use the window and door schedules when they are printed; otherwise count from the plan"
        " and the elevations. A window is small when it is under 15 sq ft and large when it is"
        " 15 sq ft and over: take the size from the schedule when sizes are listed, otherwise judge"
        " each window against the 3 ft doors shown, and say in the evidence which method was used."
        " patio_doors are patio sliders and French doors; exterior_doors are exterior doors;"
        " interior_doors are interior doors; garage_doors are garage doors (a double-width garage"
        " door counts once, as one door)."
        " Do not double-count: a patio slider counts as patio_doors, not exterior_doors."
        " Reply with ONLY this JSON: {\"windows_doors_sheet_id\": " + str(sheet["id"])
        + ", \"windows_small\": 6, \"windows_large\": 2, \"patio_doors\": 1, \"exterior_doors\": 2,"
        " \"interior_doors\": 5, \"garage_doors\": 1, \"confidence\": 0.9, \"notes\": \"one line\","
        " \"evidence\": {\"windows_small\": \"what was counted, and whether the sizes came from the schedule"
        " or were judged against the doors\", \"windows_large\": \"...\", \"patio_doors\": \"...\","
        " \"exterior_doors\": \"...\", \"interior_doors\": \"...\", \"garage_doors\": \"...\"}}."
        " Rules: every count is a whole number - answer 0 when there are none, never null, never a guess."
        " evidence says what was counted for each number, so a person can check it; confidence is 0-1,"
        " how sure you are about the counts.")


# ------------------------------------------------------------------ the counts

def quantities_from_reading(reading: dict) -> dict:
    """The counts as the run reports them: all six questions."""
    return lq.quantities_from_counts(reading, COUNT_IDS)


def windows_doors_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI counted, in the shape the results page
    reads. It carries every count - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Windows and Doors",
    "sheet_phrase": "the window and door sheet",
    "questions": QUESTIONS,
    "classify_system": WINDOWS_DOORS_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the window and door schedule or the elevations?",
    "read_system": WINDOWS_DOORS_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_windows_doors_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_windows_doors(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Count the windows and doors on the window and door sheet with the AI and propose the count measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    counts need no scale.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def windows_doors_results(conn, ctx, row: dict) -> dict | None:
    """What a finished windows and doors run counted, as a list to show, plus all six
    counts - including the zeros, which got no measurement row. Evidence for a
    counted unit comes from its measurement; for a zero count, from what the AI
    said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

"""LLM-assisted fencing takeoff: read the fence line on the site plan with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the site plan sheet, read it with
the AI, propose one measurement per quantity found. This module is only what
is fencing's own - the questions, the prompts, the parsing.

The AI reads the fence runs off the site plan - each run's printed length -
and counts the walk and drive gates. The app adds the runs up: the AI never
computes a total. A single printed total length is one run; no fence line at
all is an empty list and a zero length.

The material and height stay user-answered: they are choices, not things a
plan shows. Removing the old fence, the permit, inspections and the survey
stay user-answered too - the auto-run fills quantities only. There is no
calibration: the AI reads printed lengths, and the app does the maths.
"""

from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "fencing"              # this trade's module id (the manifest, the sheet switches)

# The Fencing manifest's read questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("length_lf", "Fence length", "lf of fence", "length", "lf"),
    ("walk_gates", "Walk gates", "walk gates", "count", "ea"),
    ("drive_gates", "Drive (double) gates", "drive gates", "count", "ea"),
)
IDS = tuple(q[0] for q in QUESTIONS)
COUNT_IDS = ("walk_gates", "drive_gates")
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}


# ------------------------------------------------------------------ the AI calls

FENCING_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the site plan. "
                           "Reply with ONLY one JSON object, nothing else.")

FENCING_READ_SYSTEM = ("You are reading a site plan to measure the fence line on it. "
                       "Reply with ONLY one JSON object, nothing else.")


def parse_fencing_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(site plan sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "fencing_sheet_id")


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


def _parse_runs(value, key: str) -> list[dict]:
    """A list of printed run lengths the AI read off the plan: each has a
    length_ft string in feet'-inches". The app adds them up - the AI never does."""
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
        lq.dimension_inches(v.strip(), f"{where} length")
        runs.append({"name": (name or "").strip()[:80], "length_ft": v.strip()})
    return runs


def _runs_length_lf(runs: list[dict]) -> str:
    """The runs' lengths added up, to 0.01 lf (the app's maths, not the AI's)."""
    total = Decimal(0)
    for r in runs:
        total += Decimal(lq.dimension_inches(r["length_ft"], f"run {r['name'] or '?'} length")) / Decimal(12)
    return str(total.quantize(Decimal("0.01")))


def parse_fencing_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the fence runs (each a printed length in
    feet'-inches"), two whole-number gate counts (0 when there are none - never
    null), the evidence for each quantity, confidence 0-1 (or None), notes.
    Any defect rejects the whole answer - a length the AI hedged on is no length
    at all. The site plan sheet is the one that was shown, whatever id the AI wrote down."""
    obj = lt._parse_json_object(text)
    runs = _parse_runs(obj.get("fence_runs"), "fence_runs")
    counts = {feeds: _count(obj, feeds) for feeds in COUNT_IDS}
    ev = lq.parse_evidence(obj, IDS)
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "fencing_sheet_id", sheet_id, notes)
    return {"fencing_sheet_id": sheet_id, "runs": runs, "counts": counts, "evidence": ev,
            "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read the fence runs and count the gates on this
    sheet, with the evidence for each number, so a person can check every number
    against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the fence line shown on this site plan."
        " Read every run of new fence from the dimensions printed on the plan, exactly as printed"
        " (feet'-inches\", like 120'-6\"): one fence_runs entry per run, with length_ft as printed."
        " When the plan prints a single total fence length, give that as the one run; when it shows"
        " no fence line at all, fence_runs is an empty list. Do not measure the drawing yourself"
        " and do not add the runs up - the app works the total out."
        " Count the gates from the gate symbols (use the legend when one is printed): walk_gates"
        " are single pedestrian gates, drive_gates are double (driveway) gates."
        " Reply with ONLY this JSON: {\"fencing_sheet_id\": " + str(sheet["id"])
        + ", \"fence_runs\": [{\"length_ft\": \"120'-6\\\"\"}, {\"length_ft\": \"128'-0\\\"\"}],"
          " \"walk_gates\": 2, \"drive_gates\": 1, \"confidence\": 0.9,"
          " \"notes\": \"one line\", \"evidence\": {\"length_lf\": \"what the fence lengths were read from\","
          " \"walk_gates\": \"...\", \"drive_gates\": \"...\"}}."
        " Rules: every length is exactly as printed - never a guess, never computed; every count is"
        " a whole number - answer 0 when there are none, never null, never a guess. evidence says"
        " what each number was read from, so a person can check it; confidence is 0-1, how sure"
        " you are about the lengths and the counts.")


# ------------------------------------------------------------------ the quantities

def quantities_from_reading(reading: dict) -> dict:
    """The quantities as the run reports them: the fence length (the runs added up),
    both gate counts. All three questions, even when the answer is zero."""
    return {"values": {"length_lf": _runs_length_lf(reading["runs"]),
                       "walk_gates": int(reading["counts"]["walk_gates"]),
                       "drive_gates": int(reading["counts"]["drive_gates"])}}


def fencing_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Fencing",
    "sheet_phrase": "the site plan sheet",
    "questions": QUESTIONS,
    "classify_system": FENCING_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the site plan (the fence line, the lot, the boundaries)?",
    "read_system": FENCING_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_fencing_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_fencing(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the fence line on the site plan with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed lengths, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def fencing_results(conn, ctx, row: dict) -> dict | None:
    """What a finished fencing run read, as a list to show, plus all three
    quantities - including the zeros, which got no measurement row. Evidence for
    a proposed quantity comes from its measurement; for a zero quantity, from
    what the AI said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

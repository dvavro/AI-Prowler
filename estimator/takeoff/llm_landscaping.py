"""LLM-assisted landscaping takeoff: read the landscape plan with the AI.

Phase 2 of the multi-trade AI auto-run. The flow is the shared quantity flow
(estimator/takeoff/llm_quantities.py): find the landscape sheet, read it with
the AI, propose one measurement per quantity found. This module is only what
is landscaping's own - the questions, the prompts, the parsing.

The AI reads the landscape zones off the plan - each zone's material (clear,
sod, turf, rock, pavers) and either the area the plan prints for it or both
printed dimensions - counts the shrubs, trees and irrigation zones, and reads
the edging runs. The app works every area and total out: the AI never computes
one. A zone with neither a printed area nor both dimensions is no zone at all.

Grading, the rock depth and the weed barrier stay user-answered: they are a
choice and yes-or-no answers, not things a plan shows. The permit, inspections
and the survey stay user-answered too - the auto-run fills quantities only.
There is no calibration: the AI reads printed dimensions and areas, and the
app does the maths.
"""

from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.takeoff import llm_quantities as lq
from estimator.takeoff import llm_takeoff as lt

MODULE_ID = "landscaping"          # this trade's module id (the manifest, the sheet switches)

# The Landscaping manifest's read questions, in manifest order:
# (question id, the manifest's label, the short plural used in labels and the summary,
#  measurement kind, unit).
QUESTIONS = (
    ("clear_sqft", "Area to clear and haul (old grass, rock, weeds)", "sq ft to clear", "area", "sqft"),
    ("sod_sqft", "Sod", "sq ft of sod", "area", "sqft"),
    ("turf_sqft", "Artificial turf", "sq ft of artificial turf", "area", "sqft"),
    ("rock_sqft", "Decorative rock or decomposed granite", "sq ft of rock", "area", "sqft"),
    ("pavers_sqft", "Pavers", "sq ft of pavers", "area", "sqft"),
    ("shrubs", "Shrubs (5 gal)", "shrubs", "count", "ea"),
    ("trees", "Trees (24 in box)", "trees", "count", "ea"),
    ("drip_zones", "Drip zones", "drip zones", "count", "ea"),
    ("sprinkler_zones", "Sprinkler zones", "sprinkler zones", "count", "ea"),
    ("edging_lf", "Landscape edging or curbing", "lf of edging", "length", "lf"),
)
IDS = tuple(q[0] for q in QUESTIONS)
COUNT_IDS = ("shrubs", "trees", "drip_zones", "sprinkler_zones")
LABELS = {q[0]: q[1] for q in QUESTIONS}
PLURALS = {q[0]: q[2] for q in QUESTIONS}

# The materials a zone can be, and the question each one feeds.
ZONE_MATERIALS = ("clear", "sod", "turf", "rock", "pavers")
ZONE_AREAS = {"clear": "clear_sqft", "sod": "sod_sqft", "turf": "turf_sqft",
              "rock": "rock_sqft", "pavers": "pavers_sqft"}


# ------------------------------------------------------------------ the AI calls

LANDSCAPING_CLASSIFY_SYSTEM = ("You are reading construction plan sheets to find the landscape plan. "
                               "Reply with ONLY one JSON object, nothing else.")

LANDSCAPING_READ_SYSTEM = ("You are reading a landscape plan to measure the landscape areas on it. "
                           "Reply with ONLY one JSON object, nothing else.")


def parse_landscaping_classification(text: str, sheet_ids) -> tuple[int | None, str]:
    """(landscape sheet id or None, notes) from the classify call. An id that wasn't
    shown is treated as no match - the AI's word for the id is never trusted blindly."""
    return lq.parse_classification(text, sheet_ids, "landscaping_sheet_id")


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


def _parse_zones(value) -> list[dict]:
    """The landscape zones the AI read off the plan: each has a material and
    either the area the plan prints for it or both printed dimensions. A zone
    with neither is rejected - the app can work an area out from dimensions,
    but it cannot invent one. A printed area is used as-is, even when the zone
    also carries dimensions."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise lt.LlmTakeoffError(f"the AI's answer has zones = {value!r}, not a list")
    zones = []
    for i, item in enumerate(value):
        where = f"zones[{i}]"
        if not isinstance(item, dict):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} = {item!r}, not an object")
        name = item.get("name")
        if name is not None and not isinstance(name, str):
            raise lt.LlmTakeoffError(f"the AI's answer has {where} name = {name!r}, not text")
        if "material" not in item:
            raise lt.LlmTakeoffError(f"the AI's answer is missing {where} material")
        material = item["material"]
        if material not in ZONE_MATERIALS:
            raise lt.LlmTakeoffError(f"the AI's answer has {where} material = {material!r},"
                                     " not one of clear, sod, turf, rock, pavers")
        area = item.get("area_sqft")
        if area is not None:
            if isinstance(area, bool) or not isinstance(area, (int, float)):
                raise lt.LlmTakeoffError(f"the AI's answer has {where} area_sqft = {area!r}, not a number")
            if area < 0:
                raise lt.LlmTakeoffError(f"the AI's answer has {where} area_sqft = {area}, a negative area")
            zones.append({"name": (name or "").strip()[:80], "material": material,
                          "area_sqft": str(area)})
            continue
        for side in ("width_ft", "length_ft"):
            v = item.get(side)
            if v is None:
                raise lt.LlmTakeoffError(f"the AI's answer is missing {where} {side} - a zone needs"
                                         " its printed area_sqft or both dimensions")
            if not isinstance(v, str) or not v.strip():
                raise lt.LlmTakeoffError(f"the AI's answer has {where} {side} = {v!r}, not text")
            lq.dimension_inches(v.strip(), f"{where} {side.replace('_ft', '')}")
        zones.append({"name": (name or "").strip()[:80], "material": material,
                      "width_ft": item["width_ft"].strip(), "length_ft": item["length_ft"].strip()})
    return zones


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


def parse_landscaping_reading(text: str, sheet_id: int) -> dict:
    """The read call's answer, validated: the landscape zones (each a material and
    either a printed area or both printed dimensions), four whole-number counts
    (0 when there are none - never null), the edging runs (each a printed length
    in feet'-inches"), the evidence for each quantity, confidence 0-1 (or None),
    notes. Any defect rejects the whole answer - a zone the AI hedged on is no
    zone at all. The landscape sheet is the one that was shown, whatever id the
    AI wrote down."""
    obj = lt._parse_json_object(text)
    zones = _parse_zones(obj.get("zones"))
    counts = {feeds: _count(obj, feeds) for feeds in COUNT_IDS}
    edging_runs = _parse_runs(obj.get("edging_runs"), "edging_runs")
    ev = lq.parse_evidence(obj, IDS)
    conf, notes = lq.parse_confidence_notes(obj)
    sheet_id, notes = lq.parse_sheet_id(obj, "landscaping_sheet_id", sheet_id, notes)
    return {"landscaping_sheet_id": sheet_id, "zones": zones, "counts": counts,
            "edging_runs": edging_runs, "evidence": ev, "confidence": conf, "notes": notes}


def read_prompt(sheet: dict) -> str:
    """What the reader is asked: read the landscape zones, count the plants and
    irrigation zones, and read the edging runs on this sheet, with the evidence
    for each number, so a person can check every number against the drawing."""
    return (
        f"This is {lt._sheet_label(sheet)} of a plan set. Read the landscape areas shown on this landscape sheet."
        " Read every zone from the plan: material is one of clear (area to clear of old grass, rock or"
        " weeds), sod, turf (artificial turf), rock (decorative rock or decomposed granite) or pavers."
        " area_sqft only when the plan prints the area; otherwise give the dimensions and the app works"
        " it out. Dimensions are exactly as printed (feet'-inches\", like 20'-0\")."
        " Count the plants from the planting symbols (use the legend when one is printed): shrubs are"
        " shrubs, trees are trees. Count the irrigation zones from the irrigation plan or legend:"
        " drip_zones are drip zones, sprinkler_zones are sprinkler zones. Read every run of edging"
        " from the dimensions printed on the plan, exactly as printed: one edging_runs entry per run."
        " When the plan shows no edging at all, edging_runs is an empty list. Do not measure the"
        " drawing yourself and do not work any area or total out - the app works them out."
        " Reply with ONLY this JSON: {\"landscaping_sheet_id\": " + str(sheet["id"])
        + ", \"zones\": [{\"material\": \"sod\", \"width_ft\": \"20'-0\\\"\", \"length_ft\": \"30'-0\\\"\"},"
          " {\"material\": \"rock\", \"area_sqft\": 450}],"
          " \"shrubs\": 12, \"trees\": 3, \"drip_zones\": 2, \"sprinkler_zones\": 1,"
          " \"edging_runs\": [{\"length_ft\": \"85'-0\\\"\"}], \"confidence\": 0.9,"
          " \"notes\": \"one line\", \"evidence\": {\"clear_sqft\": \"...\", \"sod_sqft\": \"what the sod areas were read from\","
          " \"turf_sqft\": \"...\", \"rock_sqft\": \"...\", \"pavers_sqft\": \"...\", \"shrubs\": \"...\","
          " \"trees\": \"...\", \"drip_zones\": \"...\", \"sprinkler_zones\": \"...\", \"edging_lf\": \"...\"}}."
        " Rules: every dimension and printed area is exactly as printed - never a guess, never"
        " computed; every count is a whole number - answer 0 when there are none, never null, never"
        " a guess. evidence says what each number was read from, so a person can check it;"
        " confidence is 0-1, how sure you are about the areas and the counts.")


# ------------------------------------------------------------------ the quantities

def _zone_area_sqft(zone: dict) -> Decimal:
    """One zone's area: the printed area when the plan gave one, else width x length."""
    if "area_sqft" in zone:
        return Decimal(zone["area_sqft"])
    w = Decimal(lq.dimension_inches(zone["width_ft"], f"zone {zone['name'] or '?'} width")) / Decimal(12)
    ln = Decimal(lq.dimension_inches(zone["length_ft"], f"zone {zone['name'] or '?'} length")) / Decimal(12)
    return w * ln


def quantities_from_reading(reading: dict) -> dict:
    """The quantities as the run reports them: each material's area (its zones
    added up), the four counts, the edging length (the runs added up). All ten
    questions, even when the answer is zero."""
    areas = {m: Decimal(0) for m in ZONE_MATERIALS}
    for z in reading["zones"]:
        areas[z["material"]] += _zone_area_sqft(z)
    values = {ZONE_AREAS[m]: str(areas[m].quantize(Decimal("0.01"))) for m in ZONE_MATERIALS}
    values.update({feeds: int(reading["counts"][feeds]) for feeds in COUNT_IDS})
    values["edging_lf"] = _runs_length_lf(reading["edging_runs"])
    return {"values": values}


def landscaping_candidate(reading: dict, quantities: dict, provider: str, model: str) -> dict:
    """The run's pseudo-candidate: what the AI read, in the shape the results page
    reads. It carries every quantity - including the zeros, which get no measurement row."""
    return lq.make_candidate(reading, quantities, provider, model, MODULE_ID)


# ------------------------------------------------------------------ the whole run

SPEC = {
    "module_id": MODULE_ID,
    "label": "Landscaping",
    "sheet_phrase": "the landscape sheet",
    "questions": QUESTIONS,
    "classify_system": LANDSCAPING_CLASSIFY_SYSTEM,
    "classify_question": "Which sheet shows the landscape plan (planting, irrigation, sod and rock areas)?",
    "read_system": LANDSCAPING_READ_SYSTEM,
    "read_prompt": read_prompt,
    "parse_reading": parse_landscaping_reading,
    "quantities_from_reading": quantities_from_reading,
}


def run_llm_landscaping(conn, ctx: RequestContext, run: dict, on_step=None) -> dict:
    """Read the landscape plan with the AI and propose the quantity measurements.

    run is the auto_runs row (id, company_id, estimate_id, sheet_id, viewport_id).
    on_step(step) reports progress to the runner. Returns the reading, the
    quantities, the measurement ids, the run's pseudo-candidate, the sheet that
    was read, and a one-line summary for the runner's log. No calibration:
    the AI reads printed dimensions and areas, and the app does the maths from them.
    """
    return lq.run_llm_quantities(conn, ctx, run, SPEC, on_step=on_step)


# ------------------------------------------------------------------ the results

def landscaping_results(conn, ctx, row: dict) -> dict | None:
    """What a finished landscaping run read, as a list to show, plus all ten
    quantities - including the zeros, which got no measurement row. Evidence for
    a proposed quantity comes from its measurement; for a zero quantity, from
    what the AI said it looked for. Nothing here is approved."""
    return lq.generic_results(conn, ctx, row, SPEC)

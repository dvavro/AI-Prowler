"""Auto calibrator: set a view's scale from the dimensions written on the plan (2026-11-13, David).

"Let's build an auto calibrator and if written dimensions are not found then a manual calibration is required and
specified."

How a view is calibrated, cheapest and surest first:

1. The drawing's own lines. Dimension objects the plan engine read from the PDF (a line plus its written length,
   e.g. 46'-0"). A line that carries two different lengths is ambiguous and is dropped. It calibrates only when at
   least two dimensions on different lines agree within 1% - one alone could be a label paired with the wrong line.
   No AI, no cost.
2. The AI reading the sheet (only when the owner turned AI takeoff on, and a person asked): the AI is shown the sheet
   and lists the longest dimensions in the view - the written length and where each end of its dimension line is.
   Each end is then pinned down in a close-up crop (a small crop, logged like every other), and snapped to the PDF's
   extension line when there is one, because a point read off a whole sheet can be a few pixels out. It calibrates on
   the longest dimension and checks it against the others: they must agree within 1.5%. One dimension alone is used,
   but marked unchecked.
3. Otherwise a person must calibrate it by hand - the view is marked "manual calibration required" with the reason
   (no written dimensions found, the ones found disagree, AI reading is off, ...) and how to do it.

The AI never computes anything: it reads the written lengths and points at the ends; the app does the maths
(geometry.calibrate) and the cross-check. Every AI call goes through the provider/budget/AI Log path the AI takeoff
uses. The result is kept on the view (viewports.calibration_json) and the scale is saved like a person's
calibration, stamped scale_set_by = "auto-calibrator".
"""
from __future__ import annotations

import json
import math
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, EstimatorError
from estimator.takeoff.slab_find import parse_feet_inches

AGENT = "auto-calibrator"            # scale_set_by on a view it calibrated
ROLE = "llm_takeoff"                 # the AI role (and budget) it uses for reading the sheet
AGREE_VECTOR = 0.01                  # dimensions read from the drawing's own lines must agree this closely
AGREE_AI = 0.015                     # ...and dimensions the AI pointed at
MIN_PAPER_IN = 0.75                  # shorter lines on paper can't calibrate precisely
RATIO_RANGE = (1.0, 3000.0)          # full size .. 1" = 250'
MAX_AI_DIMS = 4                      # dimensions the AI is asked for
MAX_PINNED = 3                       # dimensions whose ends get close-ups (two AI calls each)
CLOSEUP_HALF_IN = 0.6                # a close-up is 1.2" x 1.2" of paper around one end
SNAP_IN = 0.05                       # snap an end to an extension line this close
MANUAL_HOW = ("Calibrate it by hand: open the sheet in Blueprint Review, pick 📏 Calibrate, click both ends of a "
              "dimension whose length is written on the plan (the longer the better) and type that length.")

FIND_SYSTEM = ("You are reading a construction drawing to find its written dimensions so the drawing can be scaled. "
               "Reply with ONLY one JSON object, nothing else.")
PIN_SYSTEM = ("You are looking at a close-up of a construction drawing to find the exact end of one dimension line. "
              "Reply with ONLY one JSON object, nothing else.")


class CalibrationError(Exception):
    """The AI part couldn't run or answer. The message is safe to show."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ small geometry

def _dist(a, b) -> float:
    return math.hypot(float(b[0]) - float(a[0]), float(b[1]) - float(a[1]))


def _inside(p, box, pad: float = 0.0) -> bool:
    return box[0] - pad <= p[0] <= box[2] + pad and box[1] - pad <= p[1] <= box[3] + pad


def _dim(label: str, real: float, p1, p2, source: str, **extra) -> dict | None:
    paper = _dist(p1, p2)
    if paper < MIN_PAPER_IN or not real:
        return None
    ratio = real / paper
    if not RATIO_RANGE[0] <= ratio <= RATIO_RANGE[1]:
        return None
    return {"label": label, "real_in": round(real, 3), "p1": [round(float(p1[0]), 4), round(float(p1[1]), 4)],
            "p2": [round(float(p2[0]), 4), round(float(p2[1]), 4)], "paper_in": round(paper, 4),
            "ratio": ratio, "source": source, **extra}


def agreeing(dims: list[dict], tol: float) -> list[dict]:
    """The biggest group of dimensions on different lines whose scales agree within tol, longest first. Ties go to
    the group with the most paper length (longer lines are more precise)."""
    best: list[dict] = []
    for d in dims:
        group, seen = [], set()
        for e in sorted(dims, key=lambda x: -x["paper_in"]):
            key = (tuple(e["p1"]), tuple(e["p2"]))
            if key in seen or abs(e["ratio"] - d["ratio"]) > tol * d["ratio"]:
                continue
            seen.add(key)
            group.append(e)
        if (len(group), sum(x["paper_in"] for x in group)) > (len(best), sum(x["paper_in"] for x in best)):
            best = group
    return best


# ------------------------------------------------------------------ 1. the drawing's own lines

def vector_dimensions(conn, company_id: str, vp: dict) -> list[dict]:
    """Dimension lines with a written length in this view, from the plan engine. A line that carries two different
    lengths (the label was paired with the wrong line) is dropped."""
    box = json.loads(vp["bbox_json"]) if vp.get("bbox_json") else None
    by_line: dict[tuple, set] = {}
    found: dict[tuple, dict] = {}
    for o in conn.execute("SELECT viewport_id, label, geometry_json FROM drawing_objects WHERE company_id = ? AND"
                          " sheet_id = ? AND kind = 'dimension'", (company_id, vp["sheet_id"])):
        g = json.loads(o["geometry_json"] or "{}")
        pts = g.get("points") or []
        if g.get("type") != "line" or len(pts) < 2:
            continue
        p1, p2 = pts[0], pts[-1]
        mid = [(p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2]
        if o["viewport_id"] != vp["id"] and not (o["viewport_id"] is None and box and _inside(mid, box)):
            continue
        label = o["label"] or g.get("label")
        real = parse_feet_inches(label)
        if real is None:
            continue
        key = (round(p1[0], 3), round(p1[1], 3), round(p2[0], 3), round(p2[1], 3))
        by_line.setdefault(key, set()).add(round(real, 2))
        d = _dim(label, real, p1, p2, "drawing")
        if d:
            found[key] = d
    return [d for k, d in found.items() if len(by_line[k]) == 1]


# ------------------------------------------------------------------ 2. the AI reading the sheet

def _ai_call(conn, ctx, cfg: dict, run_like: dict, system: str, user: str, images: list, refs: list,
             purpose: str, step: str) -> dict:
    from estimator.agents import ai_log
    from estimator.takeoff import llm_takeoff as lt
    try:
        text, _prov, _model, log_id = lt._call(conn, ctx, cfg, run_like, system, user, images,
                                                purpose=purpose, images_refs=refs, step=step, flow="auto_calibrate")
        obj = lt._parse_json_object(text)
    except lt.LlmTakeoffError as exc:
        raise CalibrationError(str(exc)) from None
    ai_log.set_parsed(conn, ctx.company_id, log_id, obj)
    return obj


def _prepare(conn, ctx, sheet_id: int, purpose: str, provider: str, bbox=None) -> dict:
    from estimator.drawing_model import crops
    try:
        if bbox is None:
            return crops.prepare(conn, ctx, sheet_id, purpose=purpose, provider=provider, whole_sheet=True,
                                 user_asked=True)
        return crops.prepare(conn, ctx, sheet_id, bbox=bbox, purpose=purpose, provider=provider)
    except EstimatorError as exc:
        raise CalibrationError(exc.message) from None


def _pt(v) -> list[float] | None:
    try:
        if isinstance(v, (list, tuple)) and len(v) == 2:
            return [float(v[0]), float(v[1])]
        if isinstance(v, dict) and "x" in v and "y" in v:
            return [float(v["x"]), float(v["y"])]
    except (TypeError, ValueError):
        return None
    return None


def _segments(conn, sheet: dict) -> list:
    """The PDF's own line work for the sheet's page (for snapping), or [] when there's no PDF to read."""
    try:
        ps = conn.execute("SELECT file_path, file_type FROM plan_sets WHERE id = ?", (sheet["plan_set_id"],)).fetchone()
        if ps is None or (ps["file_type"] or "").lower() != "pdf" or not Path(ps["file_path"]).is_file():
            return []
        from estimator.plan_engine import pdf_pages
        return pdf_pages.page_segments(ps["file_path"], int(sheet["page_no"]))
    except Exception:  # noqa: BLE001 - snapping is a refinement; without it the close-up point is used
        return []


def snap(end: list[float], other: list[float], segments: list) -> tuple[list[float], bool]:
    """Move a dimension line's end onto the extension line it meets: for a horizontal dimension the nearest vertical
    line crossing the end's height within SNAP_IN, for a vertical one the nearest horizontal line."""
    dx, dy = abs(other[0] - end[0]), abs(other[1] - end[1])
    horizontal = dx >= dy
    best = None
    for (x0, y0), (x1, y1) in segments:
        if horizontal and abs(x0 - x1) < 0.005 and min(y0, y1) - 0.1 <= end[1] <= max(y0, y1) + 0.1:
            d = abs(x0 - end[0])
            if d <= SNAP_IN and (best is None or d < best[0]):
                best = (d, [x0, end[1]])
        elif not horizontal and abs(y0 - y1) < 0.005 and min(x0, x1) - 0.1 <= end[0] <= max(x0, x1) + 0.1:
            d = abs(y0 - end[1])
            if d <= SNAP_IN and (best is None or d < best[0]):
                best = (d, [end[0], y0])
    return (best[1], True) if best else (end, False)


def ai_dimensions(conn, ctx, vp: dict, sheet: dict, cfg: dict, run_like: dict) -> tuple[list[dict], str]:
    """(dimensions with pinned-down ends, the AI's notes). Raises CalibrationError when the AI can't run."""
    from estimator.takeoff import llm_takeoff as lt
    sw, sh = float(sheet["width"]), float(sheet["height"])
    box = json.loads(vp["bbox_json"]) if vp.get("bbox_json") else [0, 0, sw, sh]
    purpose = f"Auto-calibrate: find the written dimensions in {vp['label'] or 'the view'}"
    prep = _prepare(conn, ctx, sheet["id"], purpose, cfg["provider"])
    iw, ih = prep["width_px"], prep["height_px"]
    kx, ky = iw / sw, ih / sh
    px_box = [round(box[0] * kx), round(box[1] * ky), round(box[2] * kx), round(box[3] * ky)]
    user = (f"This image is {iw} x {ih} pixels. Look only inside the box from pixel ({px_box[0]}, {px_box[1]}) to "
            f"({px_box[2]}, {px_box[3]}) - that is the view '{vp['label'] or 'main view'}'. List up to {MAX_AI_DIMS} of "
            "the LONGEST dimensions drawn there: a dimension line with its length written on it (like 45'-7\"). For "
            "each, give the length exactly as written and the two pixel points where the dimension line ends (where "
            "it meets its extension lines - the tick, arrowhead or dot). Prefer one horizontal and one vertical "
            "dimension. Reply with ONLY this JSON: {\"dimensions\": [{\"text\": \"45'-7\\\"\", \"end1\": [x, y], "
            "\"end2\": [x, y]}], \"notes\": \"one line\"}. If no dimension has a readable written length, return "
            "{\"dimensions\": [], \"notes\": \"why\"} - never guess, never compute a length.")
    obj = _ai_call(conn, ctx, cfg, run_like, FIND_SYSTEM, user, [lt._image_payload(Path(prep["file_path"]))],
                   [lt._image_ref(prep)], purpose, "find")
    notes = str(obj.get("notes") or "")[:300]
    rough = []
    for d in (obj.get("dimensions") or [])[:MAX_AI_DIMS]:
        if not isinstance(d, dict):
            continue
        text = str(d.get("text") or "").strip()
        real = parse_feet_inches(text)
        a, b = _pt(d.get("end1")), _pt(d.get("end2"))
        if real is None or a is None or b is None:
            continue
        p1, p2 = [a[0] / kx, a[1] / ky], [b[0] / kx, b[1] / ky]
        if not (_inside(p1, box, 0.3) and _inside(p2, box, 0.3)):
            continue
        rough.append((text, real, p1, p2))
    rough.sort(key=lambda r: -_dist(r[2], r[3]))
    segments = _segments(conn, sheet) if rough else []
    out = []
    for text, real, p1, p2 in rough[:MAX_PINNED]:
        ends, snapped = [], 0
        for end, other, which in ((p1, p2, "first"), (p2, p1, "second")):
            got = _pin(conn, ctx, cfg, run_like, sheet, vp, text, end, which)
            if got is None:
                break
            got, did = snap(got, other, segments)
            snapped += did
            ends.append(got)
        if len(ends) == 2:
            d = _dim(text, real, ends[0], ends[1], "ai", snapped=snapped)
            if d:
                out.append(d)
    return out, notes


def _pin(conn, ctx, cfg, run_like, sheet, vp, text, end, which) -> list[float] | None:
    """One end of a dimension line, pinned down in a close-up (inches on the sheet), or None."""
    from estimator.takeoff import llm_takeoff as lt
    sw, sh = float(sheet["width"]), float(sheet["height"])
    x0, y0 = max(0.0, end[0] - CLOSEUP_HALF_IN), max(0.0, end[1] - CLOSEUP_HALF_IN)
    x1, y1 = min(sw, end[0] + CLOSEUP_HALF_IN), min(sh, end[1] + CLOSEUP_HALF_IN)
    purpose = f"Auto-calibrate: pin down the {which} end of the {text} dimension"
    prep = _prepare(conn, ctx, sheet["id"], purpose, cfg["provider"], bbox=[x0, y0, x1, y1])
    cw, ch = prep["width_px"], prep["height_px"]
    user = (f"This {cw} x {ch} pixel close-up shows one end of the dimension line labelled {text} (the {which} end). "
            "Give the exact pixel where that dimension line ends at its extension line (the tick, arrowhead tip or "
            "dot). Reply with ONLY this JSON: {\"x\": 0, \"y\": 0}. If that end isn't in the picture, reply "
            "{\"x\": null, \"y\": null}.")
    obj = _ai_call(conn, ctx, cfg, run_like, PIN_SYSTEM, user, [lt._image_payload(Path(prep["file_path"]))],
                   [lt._image_ref(prep)], purpose, "pinpoint")
    p = _pt(obj)
    if p is None or not (0 <= p[0] <= cw and 0 <= p[1] <= ch):
        return None
    bx = prep.get("bbox") or [x0, y0, x1, y1]
    return [bx[0] + p[0] / cw * (bx[2] - bx[0]), bx[1] + p[1] / ch * (bx[3] - bx[1])]


# ------------------------------------------------------------------ the whole thing

def _check(used: dict, group: list[dict]) -> list[dict]:
    return [{"label": d["label"], "ratio": round(d["ratio"], 4),
             "off_pct": round(abs(d["ratio"] - used["ratio"]) / used["ratio"] * 100, 2)} for d in group if d is not used]


def _save_result(conn, vp_id: int, result: dict) -> None:
    keep = {k: result.get(k) for k in ("status", "method", "reason", "how", "used", "check", "at", "notes", "scale_ratio",
                                        "auto_run_id") if result.get(k) is not None}
    conn.execute("UPDATE viewports SET calibration_json = ? WHERE id = ?", (json.dumps(keep), vp_id))


def _manual(conn, ctx, vp: dict, reason: str, **extra) -> dict:
    from estimator.estimating import service
    result = {"ok": True, "status": "manual_required", "viewport_id": vp["id"], "reason": reason, "how": MANUAL_HOW,
              "at": _now(), **extra}
    with service.transaction(conn):
        _save_result(conn, vp["id"], result)
    return result


def _apply(conn, ctx, vp: dict, used: dict, group: list[dict], method: str, **extra) -> dict:
    from estimator.drawing_model import store
    from estimator.estimating import service
    out = store.set_scale(conn, ctx, vp["id"], calibration={"p1": used["p1"], "p2": used["p2"],
                                                            "distance": used["label"]}, confirm=True)
    check = _check(used, group)
    status = "calibrated" if check else "calibrated_unchecked"
    conf = "0.95" if check and method == "drawing" else "0.9" if check else "0.6"
    result = {"ok": True, "status": status, "viewport_id": vp["id"], "method": method,
              "scale_ratio": out["viewport"]["scale_ratio"], "at": _now(),
              "used": {k: used[k] for k in ("label", "real_in", "paper_in", "p1", "p2")} | (
                  {"snapped_ends": used.get("snapped")} if "snapped" in used else {}),
              "check": check, **extra}
    if not check:
        result["reason"] = (f"only one written dimension ({used['label']}) could be read, so the scale couldn't be "
                            "cross-checked - measure something you know to check it")
    with service.transaction(conn):
        conn.execute("UPDATE viewports SET scale_set_by = ?, scale_confidence = ? WHERE id = ?", (AGENT, conf, vp["id"]))
        _save_result(conn, vp["id"], result)
        ps = conn.execute("SELECT p.estimate_id FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id"
                          " WHERE s.id = ?", (vp["sheet_id"],)).fetchone()
        service._log(conn, ctx, ps["estimate_id"] if ps else None, "scale_auto_calibrated",
                     {"viewport_id": vp["id"], "scale_ratio": result["scale_ratio"], "method": method,
                      "used": used["label"], "check": check})
    from estimator.drawing_model.store import _load_viewport, _vp_out
    result["viewport"] = _vp_out(_load_viewport(conn, ctx, vp["id"]))
    return result


def auto_calibrate(conn, ctx: RequestContext, viewport_id: int, *, confirm: bool = False,
                   run: dict | None = None, use_ai: bool = True) -> dict:
    """Calibrate one view from its written dimensions, or mark it "manual calibration required" with why.

    confirm: needed to replace a scale the view already has. run: the auto-run that asked (its person started it,
    so the sheet may be shown to the AI, and the AI calls are logged against it)."""
    from estimator.agents import providers, roles
    from estimator.drawing_model import store
    store._role(ctx, store.EDIT_ROLES, "calibrate plan scales")
    vp = store._load_viewport(conn, ctx, viewport_id)
    sheet = store._load_sheet(conn, ctx, vp["sheet_id"])
    label = vp["label"] or f"view {vp['id']}"
    if sheet["units"] != "paper_in":
        return {"ok": True, "status": "not_needed", "viewport_id": vp["id"],
                "reason": f"{label} is a CAD drawing in real {sheet['units']}; it has no paper scale to set"}
    if vp["scale_ratio"] and not vp["is_nts"] and not confirm:
        by = vp["scale_set_by"] or ("the plan's scale note" if vp["scale_method"] == "note" else "someone")
        raise ConfirmationRequired(
            f"{label} already has a scale (1 paper inch = {float(vp['scale_ratio']):g} real inches, set by {by}). "
            "Replace it with an automatic calibration from the written dimensions? Call again with confirm=true.",
            viewport_id=vp["id"], scale_ratio=vp["scale_ratio"])
    drawn = vector_dimensions(conn, ctx.company_id, vp)
    group = agreeing(drawn, AGREE_VECTOR)
    if len(group) >= 2:
        return _apply(conn, ctx, vp, group[0], group, "drawing")
    why_drawing = (f"the drawing's own lines give {len(drawn)} written dimension(s) in {label}, not two that agree"
                   if drawn else f"the drawing's own lines carry no written dimensions in {label}")
    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    if not use_ai:
        return _manual(conn, ctx, vp, why_drawing + ".")
    if cfg["provider"] not in providers.API_PROVIDERS:
        return _manual(conn, ctx, vp, why_drawing + ", and the AI can't read the plan because AI takeoff is off "
                       "(turn it on in AI-Prowler's 🏗 Estimator tab → 🤖 AI agents: AI takeoff → Suggest).")
    if ctx.agent and run is None:
        return _manual(conn, ctx, vp, why_drawing + ", and an agent working on its own can't show the sheet to the AI.")
    person = replace(ctx, agent=None)
    est = conn.execute("SELECT estimate_id FROM plan_sets WHERE id = ?", (sheet["plan_set_id"],)).fetchone()
    run_like = {"id": (run or {}).get("id"), "estimate_id": est["estimate_id"] if est else None}
    try:
        dims, notes = ai_dimensions(conn, person, vp, sheet, cfg, run_like)
    except CalibrationError as exc:
        return _manual(conn, ctx, vp, f"{why_drawing}, and the AI couldn't read the plan: {exc}",
                       auto_run_id=run_like["id"])
    if not dims:
        return _manual(conn, ctx, vp, f"No written dimensions were found in {label}"
                       + (f" (the AI said: {notes})" if notes else "") + ".", notes=notes or None,
                       auto_run_id=run_like["id"])
    group = agreeing(dims, AGREE_AI)
    if len(dims) >= 2 and len(group) < 2:
        listed = ", ".join(f"{d['label']} → 1:{d['ratio']:.1f}" for d in dims)
        return _manual(conn, ctx, vp, f"The written dimensions in {label} don't agree on one scale ({listed}), so "
                       "none can be trusted on its own.", notes=notes or None, auto_run_id=run_like["id"])
    return _apply(conn, ctx, vp, group[0], group, "ai", notes=notes or None, auto_run_id=run_like["id"])

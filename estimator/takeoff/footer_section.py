"""The footer (footing) under a slab, from the footer detail: what the AI read, the app's maths, and the AI's check.

2026-11-15 (David, NSB shed slab): the slab is measured to its outside edge, so the slab volume already covers the
concrete over the footer. The footer only adds what is BELOW the slab, less the rail ledge notched out of it:

    below the slab (in)   = outside face height - slab thickness       (the outside face read as printed, top to bottom)
    cross-section (sq in) = width x below-slab height - ledge (w x d) + sloped haunch (1/2 x w x h, when dimensioned)
    length (lf)           = slab perimeter - 4 x footer width           (along the footer's middle: the outside
                                                                          perimeter counts each corner twice)
    volume (cu yd)        = length x cross-section / 144 / 27

The AI never computes: it reads the dimension strings printed on the detail (read_prompt), then a second call
shows it the same picture and what was read, and asks it to check each value against the drawing (check_prompt)
- the way a person double-checks a takeoff. Disagreements are flagged for a person, never resolved silently.
A person can correct any value in Blueprint Review; the volume is worked out again from their numbers.

2026-11-16 (David): a person can also draw areas on the detail - a sloped edge with no dimension, by clicking its
three corners - and add them to the cross-section or take them away (sec["adjust"]: {sign, sqin, label, ...}, the
area from the detail's scale; see takeoff_shapes.area_sqin).
"""
from __future__ import annotations

import json
import re
from decimal import Decimal

FIELDS = ("outside_in", "slab_in", "width_in", "ledge_w_in", "ledge_d_in", "haunch_w_in", "haunch_h_in")
LABELS = {"outside_in": "outside face height", "slab_in": "slab thickness", "width_in": "footer width",
          "ledge_w_in": "ledge width", "ledge_d_in": "ledge depth", "haunch_w_in": "sloped haunch width",
          "haunch_h_in": "sloped haunch height"}
MAX_IN = 120.0                      # nothing in a footer section is over 10 ft


def inches(text) -> float | None:
    """A printed length as inches: 4", 6-1/2", 6 1/2", 3 1/2 in, 1'-6", 18. None when it isn't one."""
    if text is None:
        return None
    if isinstance(text, (int, float)):
        v = float(text)
        return v if 0 < v <= MAX_IN else None
    s = str(text).strip().lower().replace("”", '"').replace("″", '"').replace("′", "'").replace("’", "'")
    s = s.replace("inches", '"').replace("inch", '"').replace("in.", '"').replace(" in", '"')
    m = re.fullmatch(r"(?:(\d+(?:\.\d+)?)\s*'\s*-?\s*)?(?:(\d+(?:\.\d+)?)(?:\s*[- ]\s*(\d+)\s*/\s*(\d+))?|(\d+)\s*/\s*(\d+))?\s*\"?",
                     s)
    if not m or not any(m.groups()):
        return None
    feet, whole, num, den, fnum, fden = m.groups()
    try:
        total = float(feet or 0) * 12 + float(whole or 0)
        if num:
            total += int(num) / int(den)
        elif fnum:
            total += int(fnum) / int(fden)
    except (ValueError, ZeroDivisionError):
        return None
    return total if 0 < total <= MAX_IN else None


def _json(text: str) -> dict:
    t = re.sub(r"^```(?:json)?|```$", "", (text or "").strip(), flags=re.M).strip()
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise ValueError("the AI didn't answer with JSON")
    obj = json.loads(t[a:b + 1])
    if not isinstance(obj, dict):
        raise ValueError("the AI's answer isn't a JSON object")
    return obj


# ------------------------------------------------------------------ the AI's two calls

READ_SYSTEM = ("You are reading the footer (footing) section detail of a foundation plan. "
               "Reply with ONLY one JSON object, nothing else.")
CHECK_SYSTEM = ("You are checking another reader's work against a footer (footing) section detail of a foundation plan."
                " Reply with ONLY one JSON object, nothing else.")


def read_prompt(sheet_label: str) -> str:
    return (f"This is the footer / footing section detail from {sheet_label}. Read the dimensions printed on it."
            " Reply with ONLY this JSON: {\"detail_found\": true, \"slab_thickness\": \"4\\\"\","
            " \"outside_face\": [\"3-1/2\\\"\", \"6-1/2\\\"\", \"12\\\"\"], \"footer_width\": \"12\\\"\","
            " \"ledge_width\": null, \"ledge_depth\": null, \"inside_slope\": true, \"haunch_width\": null,"
            " \"haunch_height\": null, \"notes\": \"one line\"}."
            " Rules: every value is a dimension string exactly as printed, or null - never guess, never compute,"
            " never invent. outside_face is the chain of vertical dimensions on the footer's OUTSIDE face, from the"
            " top of the slab down to the bottom of the footer, in order. footer_width is the footer's bottom width."
            " ledge_width / ledge_depth are a notch or step (rat ledge, brick ledge, rail ledge) cut out of the top"
            " outside corner, if one is dimensioned. inside_slope is true when the footer's inside face slopes up"
            " to the bottom of the slab; haunch_width / haunch_height are that slope's dimensions if printed."
            " detail_found is false when no footer section is shown.")


def check_prompt(read: dict, slab: str | None) -> str:
    shown = {k: read.get(k) for k in ("slab_thickness", "outside_face", "footer_width", "ledge_width", "ledge_depth",
                                      "inside_slope", "haunch_width", "haunch_height")}
    return ("Another reader looked at this footer section detail and wrote down: " + json.dumps(shown)
            + (f". The plan's slab dimensions were read as {slab}." if slab else ".")
            + " Check every value against the drawing, one by one, the way an estimator double-checks a takeoff."
              " Reply with ONLY this JSON: {\"checks\": [{\"item\": \"slab_thickness\", \"read\": \"4\\\"\","
              " \"drawing_shows\": \"4\\\"\", \"agrees\": true, \"why\": \"one line\"}], \"overall\": \"agrees\","
              " \"notes\": \"one line\"}. One check per item above. overall is \"agrees\" or \"disagrees\"."
              " If a dimension can't be read clearly, say so in why and set agrees to false - never guess.")


def parse_read(text: str) -> dict:
    """The read call's answer, validated: printed strings (or None) and each one as inches."""
    obj = _json(text)

    def txt(k):
        v = obj.get(k)
        return str(v).strip() if isinstance(v, (str, int, float)) and str(v).strip() else None
    face = obj.get("outside_face") or []
    if isinstance(face, str):
        face = [p for p in re.split(r"[,+;]", face) if p.strip()]
    face = [str(p).strip() for p in face if str(p).strip()][:8]
    out = {"detail_found": obj.get("detail_found") is not False, "slab_thickness": txt("slab_thickness"),
           "outside_face": face, "footer_width": txt("footer_width"), "ledge_width": txt("ledge_width"),
           "ledge_depth": txt("ledge_depth"), "inside_slope": bool(obj.get("inside_slope")),
           "haunch_width": txt("haunch_width"), "haunch_height": txt("haunch_height"),
           "notes": (txt("notes") or "")[:500]}
    return out


def parse_check(text: str) -> dict:
    obj = _json(text)
    checks = []
    for c in obj.get("checks") or []:
        if not isinstance(c, dict):
            continue
        checks.append({"item": str(c.get("item") or "")[:40], "read": str(c.get("read") or "")[:40],
                       "drawing_shows": str(c.get("drawing_shows") or "")[:60],
                       "agrees": c.get("agrees") is True, "why": str(c.get("why") or "")[:200]})
    overall = "agrees" if checks and all(c["agrees"] for c in checks) and obj.get("overall") != "disagrees" \
        else ("disagrees" if checks else "not checked")
    return {"checks": checks, "overall": overall, "notes": str(obj.get("notes") or "")[:300]}


# ------------------------------------------------------------------ from the reading to numbers

def from_read(read: dict | None, footer_size: str | None = None, slab_thickness: str | None = None) -> dict:
    """The section in inches. From the footer detail when it was read; otherwise from the footer size the plan's notes
    give (e.g. 12x20: 12 wide, 20 overall) and the slab thickness. Each value says where it came from."""
    sec = {k: None for k in FIELDS}
    src = {}
    read = read or {}
    if read.get("detail_found") is not False and read.get("outside_face"):
        parts = [inches(p) for p in read["outside_face"]]
        if parts and all(p is not None for p in parts):
            sec["outside_in"], src["outside_in"] = sum(parts), "footer detail: " + " + ".join(read["outside_face"])
    for f, k in (("slab_in", "slab_thickness"), ("width_in", "footer_width"), ("ledge_w_in", "ledge_width"),
                 ("ledge_d_in", "ledge_depth"), ("haunch_w_in", "haunch_width"), ("haunch_h_in", "haunch_height")):
        v = inches(read.get(k))
        if v is not None:
            sec[f], src[f] = v, "footer detail: " + str(read[k])
    nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", str(footer_size or ""))]
    if sec["width_in"] is None and len(nums) >= 2:
        sec["width_in"], src["width_in"] = nums[0], f"footer size {footer_size}"
    if sec["outside_in"] is None and len(nums) >= 2:
        sec["outside_in"], src["outside_in"] = nums[1], f"footer size {footer_size} (overall depth)"
    if sec["slab_in"] is None and inches(slab_thickness) is not None:
        sec["slab_in"], src["slab_in"] = inches(slab_thickness), "slab note: " + str(slab_thickness)
    if sec["slab_in"] is None:
        sec["slab_in"], src["slab_in"] = 4.0, "the Concrete trade's default (4 in)"
    if sec["width_in"] is None:
        sec["width_in"], src["width_in"] = 12.0, "none on the plan: 12 in"
    if sec["outside_in"] is None:
        sec["outside_in"], src["outside_in"] = sec["slab_in"] + 12.0, "none on the plan: 12 in below the slab"
    sec["from"] = src
    sec["inside_slope"] = bool(read.get("inside_slope"))
    return sec


def _d(v) -> Decimal:
    return Decimal(str(v or 0))


def _q(v, places=2) -> str:
    return str(Decimal(v).quantize(Decimal(1).scaleb(-places)))


def _n(v) -> str:
    d = Decimal(str(v)).normalize()
    return f"{d:f}" if d != d.to_integral() else f"{d.to_integral():f}"


def compute(sec: dict, perimeter_lf) -> dict:
    """The footer below the slab: each step written out, rounded before the next step uses it."""
    out_h, slab, w = _d(sec.get("outside_in")), _d(sec.get("slab_in")), _d(sec.get("width_in"))
    lw, ld, hw, hh = (_d(sec.get(k)) for k in ("ledge_w_in", "ledge_d_in", "haunch_w_in", "haunch_h_in"))
    below = max(Decimal(0), out_h - slab)
    ledge = lw * ld
    haunch = hw * hh / 2
    adjust = [a for a in (sec.get("adjust") or []) if a.get("sqin") is not None]
    drawn = sum((Decimal(str(a["sqin"])) * (1 if int(a.get("sign", 1)) > 0 else -1) for a in adjust), Decimal(0))
    sq_in = Decimal(_q(max(Decimal(0), w * below - ledge + haunch + drawn)))
    sq_ft = Decimal(_q(sq_in / 144, 4))
    per = _d(perimeter_lf)
    length = Decimal(_q(max(Decimal(0), per - 4 * w / 12)))
    cuyd = Decimal(_q(length * sq_in / 144 / 27))
    steps = [{"what": "Footer depth below the slab", "formula": f"{_n(out_h)} in - {_n(slab)} in slab",
              "result": f"{_n(below)} in", "note": "the slab is measured to its outside edge, so the top "
                                                   f"{_n(slab)} in of the footer is already in the slab"}]
    xs = f"{_n(w)} in x {_n(below)} in"
    if ledge:
        xs += f" - ({_n(lw)} in x {_n(ld)} in ledge)"
    if haunch:
        xs += f" + 1/2 x {_n(hw)} in x {_n(hh)} in haunch"
    for a in adjust:                          # areas a person drew on the detail (2026-11-16)
        xs += f" {'+' if int(a.get('sign', 1)) > 0 else '-'} {_q(_d(a['sqin']))} sq in ({a.get('label') or 'drawn'})"
    plus = [a for a in adjust if int(a.get("sign", 1)) > 0]
    minus = [a for a in adjust if int(a.get("sign", 1)) <= 0]
    steps.append({"what": "Footer cross-section", "formula": xs, "result": f"{_n(sq_in)} sq in = {_q(sq_ft, 3)} sq ft",
                  "note": "width x depth below the slab" + (", less the ledge notch" if ledge else "")
                          + (", plus the sloped haunch" if haunch else "")
                          + (", plus the area(s) drawn on the detail" if plus else "")
                          + (", less the area(s) drawn on the detail" if minus else "")
                          + ("; the inside face slopes but the slope isn't dimensioned, so it isn't counted - draw it"
                             " on the detail to add it" if sec.get("inside_slope") and not haunch and not plus else "")
                          + "; ÷ 144 turns sq in into sq ft"})
    steps.append({"what": "Footer length (middle line)", "formula": f"{_q(per)} lf - 4 x {_n(w)} in ÷ 12",
                  "result": f"{_q(length)} lf", "note": "the outside perimeter counts each of the 4 corners twice"})
    steps.append({"what": "Footer concrete", "formula": f"{_q(length)} lf x {_n(sq_in)} sq in ÷ 144 ÷ 27",
                  "result": f"{_q(cuyd)} cu yd", "note": "÷ 27 turns cubic feet into cubic yards"})
    return {"below_slab_in": _n(below), "section_sqin": _n(sq_in), "section_sqft": _q(sq_ft, 4),
            "length_lf": _q(length), "cuyd": _q(cuyd), "steps": steps}


def edit(sec: dict, values: dict) -> dict:
    """A person's corrections (inches) on top of the section; each corrected value says so."""
    new = {**{k: sec.get(k) for k in FIELDS}, "from": dict(sec.get("from") or {}),
           "inside_slope": bool(sec.get("inside_slope")), "adjust": list(sec.get("adjust") or [])}
    if sec.get("anchor"):
        new["anchor"] = dict(sec["anchor"])          # where the section sits on the detail (2026-11-16)
    for k in FIELDS:
        if k in values and values[k] not in (None, ""):
            v = values[k]
            try:
                v = float(v)
            except (TypeError, ValueError):
                v = inches(v)
            if v is None or v < 0 or v > MAX_IN:
                raise ValueError(f"{LABELS[k]} must be a length in inches between 0 and {int(MAX_IN)}")
            new[k] = v
            new["from"][k] = "entered by a person"
    if new["outside_in"] is not None and new["slab_in"] is not None and new["outside_in"] < new["slab_in"]:
        raise ValueError("the outside face height must be at least the slab thickness")
    return new

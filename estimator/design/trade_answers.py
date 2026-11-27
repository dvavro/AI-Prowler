"""2026-11-27 (David: "I am doing a Demolition estimate, but that job does not need a drawing like other jobs. The draw the
plans button should say run AI Design and add a selection to draw plans and other options like include pricing and
inspections ... this can be the same for all trades").

✨ Run AI design can now fill in the estimate straight from the description: the AI answers each quoted trade's own
questions (the ones a person answers on the estimate - square feet, counts, choices) and approving prices them, with or
without a drawing. This module tells the AI what each trade asks, and turns what it answers into answers the trade takes:
only its own question ids, only the choice values it offers, numbers within each question's range. Anything else is
dropped and said, never guessed. Permit and inspection questions are answered only when the person ticks "Include
permits and inspections"; otherwise they're left as the estimate has them.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

PERMIT_RE = re.compile(r"permit|inspect", re.I)
MAX_TRADES = 12


def is_permit_question(qid: str) -> bool:
    """A permit or inspection question (permit, inspections, permit_ea ...)."""
    return bool(PERMIT_RE.search(qid or ""))


def _range(q) -> str:
    lo, hi = getattr(q, "min", None), getattr(q, "max", None)
    if lo is None and hi is None:
        return ""
    return f", {lo if lo is not None else ''}-{hi if hi is not None else ''}"


def questions_text(registry, trades: list[str], permits: bool) -> str:
    """Each trade's questions for the prompt: id (label) [type, unit, choices or range]."""
    out = []
    for t in list(dict.fromkeys(trades or []))[:MAX_TRADES]:
        mod = registry.modules.get(t)
        if mod is None:
            continue
        rows = []
        for q in mod.questions:
            if is_permit_question(q.id) and not permits:
                continue
            kind = q.type
            if q.type == "choice" and q.choices:
                kind = "one of: " + " | ".join(str(c.get("value")) for c in q.choices)
            elif q.type in ("number", "integer"):
                kind = q.type + (f" {q.unit}" if q.unit else "") + _range(q)
            rows.append(f'    "{q.id}" ({q.label}): {kind}')
        if rows:
            out.append(f'  "{mod.id}" - {mod.name}:\n' + "\n".join(rows))
    return "\n".join(out)


def prompt_part(registry, trades: list[str], permits: bool, draw: bool) -> str:
    """What the design prompt adds when the person ticks "Price the estimate"."""
    qs = questions_text(registry, trades, permits)
    if not qs:
        return ""
    return ("\n\nAlso fill in the estimate: add \"trade_answers\": {\"<trade id>\": {\"<question id>\": value}} for each "
            "trade below, answering its questions from the description and the pictures (sizes, square feet, counts, "
            "choices). Use ONLY these question ids and, for a choice, one of its listed values; numbers are plain numbers "
            "in the unit shown. Leave out a question the description doesn't settle and you can't reasonably estimate; "
            "say every number you estimated in \"assumptions\"."
            + (" Answer the permit and inspection questions as this job needs them where it is (a permit: true or false; "
               "inspections: how many)." if permits else "")
            + ("" if draw else " This time the plans are NOT drawn - only the estimate is filled in - so the layout can "
                               "be rough; put the care into the trade answers.")
            + "\n" + qs)


def _num(v):
    if isinstance(v, bool):
        return None
    try:
        return Decimal(str(v).replace(",", "").strip())
    except (InvalidOperation, ValueError):
        return None


def clean(mod, raw, permits: bool) -> tuple[dict, list[str]]:
    """The AI's answers for one trade, as answers it takes, and what was dropped (each with why)."""
    raw = raw if isinstance(raw, dict) else {}
    qs = {q.id: q for q in mod.questions}
    out, dropped = {}, []
    for k, v in raw.items():
        q = qs.get(str(k))
        if q is None:
            dropped.append(f"{k}: not one of {mod.name}'s questions")
            continue
        if is_permit_question(q.id) and not permits:
            continue                                         # left as the estimate has it (not asked for)
        if v is None or v == "":
            continue
        if q.type == "choice":
            vals = {str(c.get("value")): c for c in q.choices}
            labels = {str(c.get("label") or "").strip().lower(): str(c.get("value")) for c in q.choices}
            s = str(v).strip()
            if s in vals:
                out[q.id] = s
            elif s.lower() in labels:
                out[q.id] = labels[s.lower()]
            else:
                dropped.append(f"{q.label}: '{s}' isn't one of its choices")
        elif q.type == "boolean":
            if isinstance(v, bool):
                out[q.id] = v
            elif str(v).strip().lower() in ("true", "yes", "1", "y"):
                out[q.id] = True
            elif str(v).strip().lower() in ("false", "no", "0", "n"):
                out[q.id] = False
            else:
                dropped.append(f"{q.label}: '{v}' isn't yes or no")
        elif q.type in ("number", "integer"):
            n = _num(v)
            if n is None or not n.is_finite():
                dropped.append(f"{q.label}: '{v}' isn't a number")
                continue
            if (q.min is not None and n < Decimal(str(q.min))) or (q.max is not None and n > Decimal(str(q.max))):
                dropped.append(f"{q.label}: {n} is outside {q.min}-{q.max}")
                continue
            out[q.id] = int(n) if q.type == "integer" else (int(n) if n == n.to_integral_value() else float(n))
        else:
            out[q.id] = str(v)[:200]
    return out, dropped


def parse(raw) -> dict:
    """The design's "trade_answers" as {trade: {question: plain value}} (shape only - clean() checks each answer)."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for t, ans in list(raw.items())[:MAX_TRADES]:
        if isinstance(ans, dict):
            out[str(t)[:40]] = {str(k)[:60]: v for k, v in list(ans.items())[:60]
                                if isinstance(v, (str, int, float, bool)) or v is None}
    return out


def shown(mod, answers: dict) -> list[dict]:
    """The answers as a person reads them: the question's label and the choice's label."""
    rows = []
    for q in mod.questions:
        if q.id not in answers:
            continue
        v = answers[q.id]
        if q.type == "choice":
            v = next((c.get("label") for c in q.choices if str(c.get("value")) == str(v)), v)
        elif q.type == "boolean":
            v = "yes" if v else "no"
        elif q.unit:
            v = f"{v:g} {q.unit}" if isinstance(v, (int, float)) else f"{v} {q.unit}"
        rows.append({"id": q.id, "label": q.label, "value": str(v)})
    return rows

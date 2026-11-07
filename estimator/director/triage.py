"""Triage: pick the lane (and the service module) for a plain-language request.

Rules, in order:
1. A module id given by the caller wins.
2. Plans attached means a full plan takeoff.
3. Words that match a service module's keywords mean a quick quote for it.
4. Construction trade words mean a standard estimate, using that trade's module
   when one is installed (concrete, flooring, roofing so far).
5. Otherwise the Director asks one question instead of guessing.
Longer matching phrases count more, so "roof wash" (pressure washing) beats "roof" (roofing).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

TRADE_WORDS = {
    "concrete": ["concrete", "slab", "footing", "foundation", "flatwork pour", "sidewalk pour"],
    "framing": ["framing", "frame the", "studs", "joists", "trusses"],
    "roofing": ["roof", "roofing", "shingle", "re-roof", "reroof"],
    "flooring": ["flooring", "floor install", "tile floor", "hardwood", "laminate", "carpet", "lvp"],
    "drywall": ["drywall", "sheetrock"],
    "painting": ["paint", "painting", "repaint"],
    "plumbing": ["plumbing", "repipe", "water heater", "fixtures"],
    "electrical": ["electrical", "rewire", "panel upgrade", "outlets", "lighting install"],
    "hvac": ["hvac", "air conditioner", "ac unit", "furnace", "ductwork", "heat pump"],
    "fencing": ["fence install", "new fence", "fencing"],
    "siding": ["siding install", "new siding", "re-side"],
    "windows_doors": ["window install", "replace windows", "replace the windows", "new windows", "replacement windows",
                      "window replacement", "door install", "replace doors", "replace the doors", "new doors"],
    "insulation": ["insulation", "insulate"],
    "landscaping": ["landscaping", "sod", "irrigation", "pavers"],
    "demolition": ["demolition", "demo ", "tear out", "tear-out"],
}


@dataclass
class TriageResult:
    lane: str | None
    module_id: str | None = None
    trade: str | None = None
    reason: str = ""
    question: str | None = None
    candidates: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _norm(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9\- ]+", " ", (text or "").lower()) + " "


def _score(text: str, phrases) -> int:
    return sum(len(p) for p in phrases if f" {p} " in text or (len(p) > 4 and p in text))


def _service_mods(registry):
    return [m for m in registry.list() if m.category == "service" and m.path in ("quick_estimate", "both")]


def triage(request: str, registry, has_plans: bool = False, module_id: str | None = None) -> TriageResult:
    quick_mods = _service_mods(registry)
    if module_id:
        mod = registry.get(module_id)   # raises NotFound with the list of modules
        if mod.category == "construction":
            if has_plans:
                return TriageResult("full_takeoff", mod.id, trade=mod.id, reason="plans were attached")
            return TriageResult("standard_estimate", mod.id, trade=mod.id,
                                reason=f"'{mod.name}' is a construction trade priced from measurements")
        if mod.path in ("quick_estimate", "both"):
            return TriageResult("quick_quote", mod.id, reason=f"module '{mod.id}' was chosen")
        return TriageResult("standard_estimate", mod.id, reason=f"module '{mod.id}' is a plan/measurement trade")
    if has_plans:
        return TriageResult("full_takeoff", reason="plans were attached")

    text = _norm(request)
    scored = sorted(((
        _score(text, list(m.keywords) + [m.name.lower(), m.id.replace("_", " ")]), m.id) for m in quick_mods),
        reverse=True)
    scored = [(s, mid) for s, mid in scored if s > 0]
    trade_mods = {m.id: m for m in registry.list() if m.category == "construction"}
    trade_words = {t: list(words) + list(trade_mods[t].keywords if t in trade_mods else ())
                   for t, words in TRADE_WORDS.items()}
    trades = sorted(((_score(text, words), t) for t, words in trade_words.items()), reverse=True)
    trades = [(s, t) for s, t in trades if s > 0]

    if scored and (not trades or scored[0][0] >= trades[0][0]):
        if len(scored) > 1 and scored[1][0] == scored[0][0]:
            names = [mid for _, mid in scored if _ == scored[0][0]]
            return TriageResult(None, reason="request matches more than one service", candidates=names,
                                question="Which service is this for: " + ", ".join(n.replace("_", " ") for n in names) + "?")
        return TriageResult("quick_quote", scored[0][1], reason=f"request mentions {scored[0][1].replace('_', ' ')}")
    if trades:
        trade = trades[0][1]
        return TriageResult("standard_estimate", trade if trade in trade_mods else None, trade=trade,
                            reason=f"request mentions {trade.replace('_', ' ')} work")
    names = [m.id for m in quick_mods]
    return TriageResult(None, reason="couldn't tell what kind of job this is", candidates=names,
                        question="What kind of job is this? Quick services I can price now: "
                                 + ", ".join(n.replace("_", " ") for n in names)
                                 + ". Construction trades from measurements: "
                                 + (", ".join(sorted(trade_mods)) or "none yet")
                                 + ". Or attach plans.")


def trades_mentioned(request: str, registry) -> list[str]:
    """Every construction trade a request names, in the order the trade list keeps them (for multi-trade bids)."""
    text = _norm(request)
    trade_mods = {m.id: m for m in registry.list() if m.category == "construction"}
    found = []
    for t, words in TRADE_WORDS.items():
        if t in trade_mods and _score(text, list(words) + list(trade_mods[t].keywords)) > 0:
            found.append(t)
    return found

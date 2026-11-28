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
    "flooring": ["flooring", "floor install", "tile floor", "hardwood", "laminate", "carpet", "lvp",
                 # 2026-11-27: garage / concrete floor coatings are flooring
                 "floor coating", "garage floor coating", "concrete floor coating", "concrete coating", "epoxy",
                 "epoxy floor", "garage epoxy", "polyaspartic", "polyurea", "paint chips", "paint chip", "flake floor"],
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
    # 2026-11-27 (Jamie, per David): garage door installs and repairs are a trade
    "garage_doors": ["garage door", "garage doors", "overhead door", "garage door opener", "garage door spring"],
}


# What the person wants done to what (2026-11-15, Jamie): keywords alone sent "replace 8 windows" to window cleaning,
# "paint 3 bedrooms" to house cleaning and "wash the siding" to siding. An action word with a thing it's done to
# gives that module a bonus, so the verb decides between cleaning a thing and building or replacing it.
_BUILD = ("replace", "replacing", "install", "installing", "new", "build", "put in", "put down", "pour", "add",
          "upgrade", "swap")
_CLEAN = ("clean", "cleaned", "cleaning", "wash", "washed", "washing", "power wash", "pressure wash", "soft wash")
INTENT_PAIRS = [
    ("pressure_washing", _CLEAN, ("siding", "roof", "driveway", "deck", "fence", "patio", "sidewalk", "pavers")),
    ("house_cleaning", ("clean", "cleaned", "cleaning", "deep clean"),
     ("house", "home", "apartment", "condo", "bed", "beds", "bath", "baths", "bedroom", "bedrooms"),
     ("carpet", "carpets", "rug", "rugs", "upholstery")),          # 2026-11-27: carpets are carpet cleaning
    # 2026-11-27 (Jamie): cleaning carpets, rugs or a couch is carpet cleaning - not a car's carpets
    ("carpet_cleaning", _CLEAN + ("shampoo", "shampooed", "steam", "steam clean", "steam cleaned", "stains", "stain"),
     ("carpet", "carpets", "rug", "rugs", "upholstery", "couch", "sofa", "sofas", "sectional"),
     ("car", "cars", "truck", "suv", "van", "jeep", "vehicle")),
    # 2026-11-27 (Jamie): anything wrong with or done to a garage door is the garage doors trade
    ("garage_doors", ("repair", "fix", "fixed", "replace", "service", "tune", "tune-up", "broke", "broken", "stuck",
                            "install", "new", "noisy", "spring", "springs", "cable", "cables", "opener", "off"),
     ("garage door", "garage doors", "overhead door")),
    ("car_detailing", _CLEAN + ("detail", "detailed", "ceramic", "ceramic coat", "wax", "polish"),
     ("car", "cars", "truck", "suv", "van", "jeep", "vehicle", "vehicles", "minivan"),
     ("clean out", "cleanout", "half a truck", "truck load", "truckload", "a truck", "junk", "haul")),
    ("concrete", _BUILD, ("slab", "driveway", "patio", "sidewalk", "footing", "footings")),
    ("flooring", _BUILD, ("carpet", "floor", "floors", "flooring", "tile", "lvp", "laminate", "hardwood"),
     ("clean", "cleaned", "cleaning", "shampoo", "steam clean")),   # 2026-11-27: cleaning carpet isn't new flooring
    ("painting", ("paint", "painted", "painting", "repaint"),
     ("room", "rooms", "bedroom", "bedrooms", "house", "home", "interior", "exterior", "walls", "ceilings", "cabinets",
      "trim", "garage", "kitchen", "bathroom"),
     # not a garage floor coating with paint chips (2026-11-27) - that's flooring
     ("paint chips", "paint chip", "epoxy", "floor coating", "polyaspartic", "polyurea", "garage floor")),
    ("plumbing", _BUILD, ("toilet", "toilets", "sink", "sinks", "faucet", "faucets", "shower", "tub", "water heater")),
    ("windows_doors", _BUILD, ("window", "windows", "door", "doors", "slider", "sliding door"),
     ("garage door", "garage doors", "overhead door")),            # 2026-11-27: garage doors have their own service
    ("landscaping", _BUILD, ("gravel", "rock", "plants", "turf", "artificial turf", "trees", "shrubs", "drip")),
]
INTENT_BONUS = 15


def _has(text: str, words) -> bool:
    return any(f" {w} " in text for w in words)


def _intent_bonus(text: str) -> dict:
    out: dict = {}
    for mid, verbs, things, *unless in INTENT_PAIRS:
        if _has(text, verbs) and _has(text, things) and not (unless and _has(text, unless[0])):
            out[mid] = out.get(mid, 0) + INTENT_BONUS
    return out


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


def triage(request: str, registry, has_plans: bool = False, module_id: str | None = None,
           off=frozenset()) -> TriageResult:
    """off: trades switched off in AI-Prowler's 🏗 Estimator tab (2026-11-17) - a request naming one gets no module, so
    the Director says it's switched off instead of pricing it. A service that's off isn't matched at all."""
    quick_mods = [m for m in _service_mods(registry) if m.id not in off]
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
    bonus = _intent_bonus(text)
    scored = sorted(((
        _score(text, list(m.keywords) + [m.name.lower(), m.id.replace("_", " ")]) + bonus.get(m.id, 0), m.id)
        for m in quick_mods), reverse=True)
    scored = [(s, mid) for s, mid in scored if s > 0]
    trade_mods = {m.id: m for m in registry.list() if m.category == "construction"}
    trade_words = {t: list(words) + list(trade_mods[t].keywords if t in trade_mods else ())
                   for t, words in TRADE_WORDS.items()}
    trades = sorted(((_score(text, words) + bonus.get(t, 0), t) for t, words in trade_words.items()), reverse=True)
    trades = [(s, t) for s, t in trades if s > 0]

    # A request for a service that's switched off: say so rather than guess another service (2026-11-17).
    off_hits = sorted(((_score(text, list(m.keywords) + [m.name.lower(), m.id.replace("_", " ")]) + bonus.get(m.id, 0),
                        m.id, m.name) for m in _service_mods(registry) if m.id in off), reverse=True)
    if off_hits and off_hits[0][0] > 0 and off_hits[0][0] > max([s for s, _ in scored[:1]] + [s for s, _ in trades[:1]]
                                                                + [0]):
        return TriageResult(None, reason=f"request mentions {off_hits[0][2]}, which is switched off",
                            candidates=[m.id for m in quick_mods],
                            question=f"{off_hits[0][2]} is switched off in AI-Prowler's 🏗 Estimator tab (Trades) - turn "
                                     "it on there to quote it. Services I can price now: "
                                     + (", ".join(m.id.replace("_", " ") for m in quick_mods) or "none") + ".")
    if scored and (not trades or scored[0][0] >= trades[0][0]):
        if len(scored) > 1 and scored[1][0] == scored[0][0]:
            names = [mid for _, mid in scored if _ == scored[0][0]]
            return TriageResult(None, reason="request matches more than one service", candidates=names,
                                question="Which service is this for: " + ", ".join(n.replace("_", " ") for n in names) + "?")
        return TriageResult("quick_quote", scored[0][1], reason=f"request mentions {scored[0][1].replace('_', ' ')}")
    if trades:
        trade = trades[0][1]
        return TriageResult("standard_estimate", trade if trade in trade_mods and trade not in off else None,
                            trade=trade, reason=f"request mentions {trade.replace('_', ' ')} work"
                            + (" (switched off)" if trade in off else ""))
    names = [m.id for m in quick_mods]
    return TriageResult(None, reason="couldn't tell what kind of job this is", candidates=names,
                        question="What kind of job is this? Quick services I can price now: "
                                 + ", ".join(n.replace("_", " ") for n in names)
                                 + ". Construction trades from measurements: "
                                 + (", ".join(sorted(t for t in trade_mods if t not in off)) or "none yet")
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

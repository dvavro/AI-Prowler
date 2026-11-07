"""Trade-agent settings (the Agent Manager screen and agent_config_* tools).

One row per company and construction trade:
- enabled: the Estimate Runner makes a takeoff task for this trade (off = the trade is skipped)
- confidence_threshold: 0-100; a takeoff agent's submission at or above it can skip review if auto_advance is on
- auto_advance: approve confident submissions without a person (off by default; money still needs a person later)
- sheet_rules: which plan sheets this trade reads (sheet number prefixes and title words), used by the Plan Engine
- defaults: answers this company always uses for the trade (e.g. fence height 6 ft), filled in under each takeoff

Defaults apply until the owner changes something; every change is logged.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service

# Which sheets each trade reads, by sheet-number prefix (A architectural, S structural, E electrical, P plumbing,
# M mechanical, L landscape, C civil, D demolition) and title words.
DEFAULT_SHEET_RULES = {
    "concrete": {"prefixes": ["S", "A"], "titles": ["foundation", "slab", "site"]},
    "framing": {"prefixes": ["S", "A"], "titles": ["framing", "floor plan", "roof framing"]},
    "roofing": {"prefixes": ["A"], "titles": ["roof plan", "elevations"]},
    "flooring": {"prefixes": ["A", "I"], "titles": ["floor plan", "finish"]},
    "drywall": {"prefixes": ["A"], "titles": ["floor plan", "wall types", "ceiling"]},
    "painting": {"prefixes": ["A", "I"], "titles": ["finish", "elevations"]},
    "plumbing": {"prefixes": ["P"], "titles": ["plumbing", "fixture"]},
    "electrical": {"prefixes": ["E"], "titles": ["electrical", "lighting", "power", "panel"]},
    "hvac": {"prefixes": ["M"], "titles": ["mechanical", "hvac", "duct"]},
    "windows_doors": {"prefixes": ["A"], "titles": ["door schedule", "window schedule", "elevations"]},
    "siding": {"prefixes": ["A"], "titles": ["elevations", "wall sections"]},
    "insulation": {"prefixes": ["A"], "titles": ["wall sections", "insulation", "energy"]},
    "fencing": {"prefixes": ["C", "L", "A"], "titles": ["site plan", "fence"]},
    "landscaping": {"prefixes": ["L", "C"], "titles": ["landscape", "irrigation", "planting"]},
    "demolition": {"prefixes": ["D", "A"], "titles": ["demolition", "demo plan", "existing"]},
}
DEFAULTS = {"enabled": True, "confidence_threshold": 85, "auto_advance": False}
SETTING_KEYS = ("enabled", "confidence_threshold", "auto_advance", "sheet_rules", "defaults")
CONFIG_ROLES = ("owner",)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _trades(registry) -> dict:
    return {m.id: m for m in registry.list() if m.category == "construction"}


def _shape(module_id: str, mod, row) -> dict:
    out = {"module_id": module_id, "name": mod.name, **DEFAULTS,
           "sheet_rules": DEFAULT_SHEET_RULES.get(module_id, {"prefixes": [], "titles": []}), "defaults": {},
           "changed": False}
    if row:
        out.update(enabled=bool(row["enabled"]), confidence_threshold=int(row["confidence_threshold"]),
                   auto_advance=bool(row["auto_advance"]), changed=True)
        if row["sheet_rules_json"]:
            out["sheet_rules"] = json.loads(row["sheet_rules_json"])
        if row["defaults_json"]:
            out["defaults"] = json.loads(row["defaults_json"])
    return out


def get_config(conn, company_id: str, module_id: str, registry) -> dict:
    trades = _trades(registry)
    if module_id not in trades:
        raise NotFound(f"'{module_id}' isn't a construction trade", module_id=module_id, available=sorted(trades))
    row = conn.execute("SELECT * FROM agent_configs WHERE company_id = ? AND module_id = ?",
                       (company_id, module_id)).fetchone()
    return _shape(module_id, trades[module_id], row)


def list_configs(conn, company_id: str, registry) -> dict:
    trades = _trades(registry)
    rows = {r["module_id"]: r for r in conn.execute("SELECT * FROM agent_configs WHERE company_id = ?", (company_id,))}
    agents = [_shape(mid, trades[mid], rows.get(mid)) for mid in sorted(trades)]
    return {"ok": True, "agents": agents, "enabled": [a["module_id"] for a in agents if a["enabled"]],
            "turned_off": [a["module_id"] for a in agents if not a["enabled"]]}


def _bool(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "yes", "on", "1", "false", "no", "off", "0"):
        return value.strip().lower() in ("true", "yes", "on", "1")
    raise InvalidInput(f"{name} must be true or false", field=name)


def _rules(value) -> dict:
    if not isinstance(value, dict) or set(value) - {"prefixes", "titles"}:
        raise InvalidInput("sheet_rules is {prefixes: [...], titles: [...]}", field="sheet_rules")
    out = {}
    for k in ("prefixes", "titles"):
        items = value.get(k, [])
        if not isinstance(items, list) or not all(isinstance(i, str) and i.strip() for i in items):
            raise InvalidInput(f"sheet_rules.{k} must be a list of words", field="sheet_rules")
        out[k] = [i.strip().upper() if k == "prefixes" else i.strip().lower() for i in items]
    return out


def _defaults(mod, value) -> dict:
    from estimator.estimating.quick import _coerce
    if not isinstance(value, dict):
        raise InvalidInput("defaults must be an object of question id -> answer", field="defaults")
    valid = {q.id: q for q in mod.questions}
    unknown = sorted(set(value) - set(valid))
    if unknown:
        raise InvalidInput(f"{mod.name} has no questions {unknown}", field="defaults", valid=sorted(valid))
    return {k: _coerce(valid[k], v)[0] for k, v in value.items()}


def update_config(conn, ctx: RequestContext, module_id: str, changes: dict, *, confirm: bool = False,
                  registry=None) -> dict:
    if ctx.role not in CONFIG_ROLES:
        raise PermissionDenied("only the owner can change trade-agent settings", role=ctx.role)
    if not isinstance(changes, dict) or not changes:
        raise InvalidInput("changes is an object, e.g. {\"auto_advance\": true}", valid=list(SETTING_KEYS))
    unknown = sorted(set(changes) - set(SETTING_KEYS))
    if unknown:
        raise InvalidInput(f"unknown settings: {unknown}", valid=list(SETTING_KEYS))
    before = get_config(conn, ctx.company_id, module_id, registry)
    mod = _trades(registry)[module_id]
    new = dict(before)
    for k, v in changes.items():
        if k in ("enabled", "auto_advance"):
            new[k] = _bool(v, k)
        elif k == "confidence_threshold":
            if isinstance(v, bool):
                raise InvalidInput("confidence_threshold is a whole number 0-100", field=k)
            try:
                n = int(str(v).strip())
            except ValueError:
                raise InvalidInput("confidence_threshold is a whole number 0-100", field=k) from None
            if not 0 <= n <= 100:
                raise InvalidInput("confidence_threshold is a whole number 0-100", field=k)
            new[k] = n
        elif k == "sheet_rules":
            new[k] = _rules(v)
        elif k == "defaults":
            new[k] = _defaults(mod, v)
    diff = {k: new[k] for k in changes if new[k] != before[k]}
    if not confirm:
        return {"ok": True, "confirmed": False, "would_change": diff, "current": before,
                "say": "Nothing changed yet. Check these with the owner, then call again with confirm=true."}
    with service.transaction(conn):
        conn.execute(
            "INSERT INTO agent_configs (company_id, module_id, enabled, confidence_threshold, auto_advance,"
            " sheet_rules_json, defaults_json, updated_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT (company_id, module_id) DO UPDATE SET enabled = excluded.enabled,"
            " confidence_threshold = excluded.confidence_threshold, auto_advance = excluded.auto_advance,"
            " sheet_rules_json = excluded.sheet_rules_json, defaults_json = excluded.defaults_json,"
            " updated_by = excluded.updated_by, updated_at = excluded.updated_at",
            (ctx.company_id, module_id, int(new["enabled"]), new["confidence_threshold"], int(new["auto_advance"]),
             json.dumps(new["sheet_rules"]), json.dumps(new["defaults"]), ctx.actor, _now()))
        service._log(conn, ctx, None, "agent_config_changed", {"module_id": module_id, **diff},
                     {"module_id": module_id, **{k: before[k] for k in diff}})
    out = get_config(conn, ctx.company_id, module_id, registry)
    return {"ok": True, "confirmed": True, "changed": diff, "config": out}

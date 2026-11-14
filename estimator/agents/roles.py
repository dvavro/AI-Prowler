"""Agent roles: which AI runs each unattended role, its model and backup, the budget, and what's been spent.

Every role starts Off, so nothing runs (or costs anything) until the owner chooses a provider:
- off: the role does nothing
- chat_only: work is queued as "waiting for AI" until someone runs it from chat (est_agent_next / est_agent_submit)
- claude_api / grok_api: the watcher runs it on the agents' own API key, within the budget; an optional backup
  provider is tried if the first one fails
"""
from __future__ import annotations

from datetime import datetime, timezone

from estimator.agents import providers
from estimator.context import RequestContext
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service

# Roles that have unattended work today, and the ones waiting for the Plan Engine (Coder 2 track).
ROLES = {
    "reviewer": {"label": "Reviewer", "works_now": True,
                 "does": "Writes notes for the human reviewer on estimates waiting for review: missing items, odd "
                         "quantities, unit costs that look off. It never approves or changes prices."},
    "bid_writer": {"label": "Bid Writer", "works_now": True,
                   "does": "Drafts the scope, inclusions and exclusions for an approved estimate. A person sees the "
                           "draft in the bid preview before anything is sent."},
    "follow_up": {"label": "Follow-up", "works_now": True,
                  "does": "Drafts a short follow-up email for quotes that are due one. A person sends it."},
    "plan_reader": {"label": "Plan Reader", "works_now": False,
                    "does": "Reads and classifies plan sheets. Starts when the Plan Engine is installed."},
    "takeoff": {"label": "Takeoff agents", "works_now": False,
                "does": "Measures each trade from the plans for the Estimate Runner. Starts when the Plan Engine is "
                        "installed; until then trades are measured by a person or from chat."},
    "llm_takeoff": {"label": "LLM takeoff", "works_now": True,
                    "does": "When the concrete auto-run finds no slab outline in the drawing, reads the foundation "
                            "sheet with the AI instead (uses the API key, costs tokens, counts against the budget "
                            "below). It only reads dimensions - the app does the maths - and every measurement it "
                            "proposes still needs a person to approve it. Concrete only for now."},
}
CONFIG_ROLES = ("owner",)
DEFAULT_BUDGET = {"daily_cents": 200, "monthly_cents": 2000}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _shape(role: str, row) -> dict:
    meta = ROLES[role]
    provider = row["provider"] if row else "off"
    fallback = row["fallback_provider"] if row else None
    ok, why = providers.ready(provider)
    out = {"role": role, "label": meta["label"], "does": meta["does"], "works_now": meta["works_now"],
           "provider": provider, "provider_label": providers.PROVIDER_LABELS[provider],
           "model": (row["model"] if row else None) or (providers.model_for(provider) if ok else None),
           "fallback_provider": fallback, "ready": ok, "why_not": "" if ok else why,
           # The model this agent was set to itself (2026-11-13), or None = its group's model from the top of the
           # Small Business tab (complex & customer, or internal steps).
           "model_pinned": (row["model"] if row else None) or None}
    if fallback:
        fok, fwhy = providers.ready(fallback)
        out.update(fallback_ready=fok, fallback_why_not="" if fok else fwhy)
    return out


def get_role(conn, company_id: str, role: str) -> dict:
    if role not in ROLES:
        raise NotFound(f"no agent role '{role}'", role=role, available=list(ROLES))
    row = conn.execute("SELECT * FROM agent_roles WHERE company_id = ? AND role = ?", (company_id, role)).fetchone()
    return _shape(role, row)


def get_budget(conn, company_id: str) -> dict:
    row = conn.execute("SELECT * FROM agent_budgets WHERE company_id = ?", (company_id,)).fetchone()
    return {"daily_cents": row["daily_cents"], "monthly_cents": row["monthly_cents"]} if row else dict(DEFAULT_BUDGET)


def spent(conn, company_id: str, now: datetime | None = None) -> dict:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    day, month = now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")

    def total(prefix):
        r = conn.execute("SELECT COALESCE(SUM(cost_micros), 0), COUNT(*), COALESCE(SUM(input_tokens), 0),"
                         " COALESCE(SUM(output_tokens), 0) FROM agent_usage WHERE company_id = ? AND at LIKE ?",
                         (company_id, prefix + "%")).fetchone()
        return {"micros": r[0], "cents": round(r[0] / 10_000, 2), "calls": r[1], "input_tokens": r[2],
                "output_tokens": r[3]}
    return {"today": total(day), "this_month": total(month)}


def budget_left(conn, company_id: str, now: datetime | None = None) -> tuple[bool, str]:
    """(True, '') while both limits have room, else (False, which limit was reached)."""
    b, s = get_budget(conn, company_id), spent(conn, company_id, now)
    if s["this_month"]["micros"] >= b["monthly_cents"] * 10_000:
        return False, f"the monthly AI budget (${b['monthly_cents'] / 100:.2f}) is used up"
    if s["today"]["micros"] >= b["daily_cents"] * 10_000:
        return False, f"today's AI budget (${b['daily_cents'] / 100:.2f}) is used up"
    return True, ""


def overview(conn, company_id: str) -> dict:
    rows = {r["role"]: r for r in conn.execute("SELECT * FROM agent_roles WHERE company_id = ?", (company_id,))}
    roles = [_shape(r, rows.get(r)) for r in ROLES]
    b, s = get_budget(conn, company_id), spent(conn, company_id)
    keys = {p: providers.ready(p)[0] for p in providers.API_PROVIDERS}
    return {"ok": True, "roles": roles, "budget": b, "spent": s, "api_keys_saved": keys,
            "providers": list(providers.PROVIDERS),
            "where_keys_go": "🔑 Agent API Key at the top of AI-Prowler's Small Business tab"}


def record_usage(conn, ctx, *, task_id, role, provider, model, usage, ok, error=None) -> int:
    micros = providers.cost_micros(model, usage) if usage else 0
    conn.execute("INSERT INTO agent_usage (company_id, task_id, role, provider, model, input_tokens, output_tokens,"
                 " cost_micros, ok, error, at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (ctx.company_id, task_id, role, provider, model, int((usage or {}).get("input", 0)),
                  int((usage or {}).get("output", 0)), micros, int(bool(ok)), (error or None) and str(error)[:300],
                  _now()))
    return micros


def _owner(ctx):
    if ctx.role not in CONFIG_ROLES:
        raise PermissionDenied("only the owner can change the AI agents", role=ctx.role)


def update_role(conn, ctx: RequestContext, role: str, changes: dict, *, confirm: bool = False) -> dict:
    _owner(ctx)
    before = get_role(conn, ctx.company_id, role)
    if not isinstance(changes, dict) or not changes:
        raise InvalidInput("changes is an object, e.g. {\"provider\": \"claude_api\"}",
                           valid=["provider", "model", "fallback_provider"])
    unknown = sorted(set(changes) - {"provider", "model", "fallback_provider"})
    if unknown:
        raise InvalidInput(f"unknown settings: {unknown}", valid=["provider", "model", "fallback_provider"])
    row = conn.execute("SELECT * FROM agent_roles WHERE company_id = ? AND role = ?",
                       (ctx.company_id, role)).fetchone()
    new = {"provider": row["provider"] if row else "off", "model": row["model"] if row else None,
           "fallback_provider": row["fallback_provider"] if row else None}
    if "provider" in changes:
        if changes["provider"] not in providers.PROVIDERS:
            raise InvalidInput(f"provider must be one of {providers.PROVIDERS}", field="provider")
        new["provider"] = changes["provider"]
    if "model" in changes:
        m = changes["model"]
        if m not in (None, "") and (not isinstance(m, str) or len(m) > 80 or not m.replace("-", "").replace(".", "")
                                    .replace("_", "").isalnum()):
            raise InvalidInput("model is a model name like claude-sonnet-5-5, or empty for AI-Prowler's choice",
                               field="model")
        new["model"] = m or None
    if "fallback_provider" in changes:
        f = changes["fallback_provider"] or None
        if f is not None and f not in providers.API_PROVIDERS:
            raise InvalidInput(f"fallback_provider must be one of {providers.API_PROVIDERS} or empty",
                               field="fallback_provider")
        new["fallback_provider"] = f
    if new["fallback_provider"] and new["fallback_provider"] == new["provider"]:
        raise InvalidInput("the backup provider must be different from the main one", field="fallback_provider")
    if new["provider"] in ("off", "chat_only"):
        new["fallback_provider"] = None
    warnings = []
    if new["provider"] in providers.API_PROVIDERS:
        ok, why = providers.ready(new["provider"])
        if not ok:
            warnings.append(f"{providers.PROVIDER_LABELS[new['provider']]} isn't ready: {why}. Work will wait until "
                            "it is.")
    if not ROLES[role]["works_now"] and new["provider"] != "off":
        warnings.append(f"{ROLES[role]['label']} has no work until the Plan Engine is installed.")
    if not confirm:
        return {"ok": True, "confirmed": False, "would_set": new, "current": before, "warnings": warnings,
                "say": "Nothing changed yet. Check with the owner (API calls cost money), then confirm=true."}
    with service.transaction(conn):
        conn.execute("INSERT INTO agent_roles (company_id, role, provider, model, fallback_provider, updated_by,"
                     " updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT (company_id, role) DO UPDATE SET"
                     " provider = excluded.provider, model = excluded.model,"
                     " fallback_provider = excluded.fallback_provider, updated_by = excluded.updated_by,"
                     " updated_at = excluded.updated_at",
                     (ctx.company_id, role, new["provider"], new["model"], new["fallback_provider"], ctx.actor, _now()))
        service._log(conn, ctx, None, "agent_role_changed", {"role": role, **new},
                     {"role": role, **{k: before[k] for k in ("provider", "model", "fallback_provider")}})
    return {"ok": True, "confirmed": True, "role": get_role(conn, ctx.company_id, role), "warnings": warnings}


def update_budget(conn, ctx: RequestContext, changes: dict, *, confirm: bool = False) -> dict:
    _owner(ctx)
    if not isinstance(changes, dict) or not changes or set(changes) - {"daily_cents", "monthly_cents"}:
        raise InvalidInput("changes is {daily_cents, monthly_cents}, e.g. {\"monthly_cents\": 5000} for $50",
                           valid=["daily_cents", "monthly_cents"])
    before = get_budget(conn, ctx.company_id)
    new = dict(before)
    for k, v in changes.items():
        if isinstance(v, bool) or not str(v).strip().isdigit():
            raise InvalidInput(f"{k} is a whole number of cents", field=k)
        n = int(str(v).strip())
        if not 0 <= n <= 1_000_000:
            raise InvalidInput(f"{k} must be between 0 and 1,000,000 cents ($10,000)", field=k)
        new[k] = n
    if new["daily_cents"] > new["monthly_cents"]:
        raise InvalidInput("the daily budget can't be more than the monthly one", field="daily_cents")
    if not confirm:
        return {"ok": True, "confirmed": False, "would_set": new, "current": before,
                "say": "Nothing changed yet. Confirm the new limits with the owner, then confirm=true."}
    with service.transaction(conn):
        conn.execute("INSERT INTO agent_budgets (company_id, daily_cents, monthly_cents, updated_by, updated_at)"
                     " VALUES (?,?,?,?,?) ON CONFLICT (company_id) DO UPDATE SET daily_cents = excluded.daily_cents,"
                     " monthly_cents = excluded.monthly_cents, updated_by = excluded.updated_by,"
                     " updated_at = excluded.updated_at",
                     (ctx.company_id, new["daily_cents"], new["monthly_cents"], ctx.actor, _now()))
        service._log(conn, ctx, None, "agent_budget_changed", new, before)
    return {"ok": True, "confirmed": True, "budget": new}

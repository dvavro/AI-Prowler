"""Company playbook overrides (est_playbook_update).

A company can adjust a lane without new code:
- review_required_over_cents (standard estimate lane): its own review limit
- quick_send_limit_cents (quick quote lane): its own one-tap limit
- checklist: things a person must confirm before approving, for every job ("*") or one trade,
  e.g. {"roofing": ["Site photo taken", "Layers checked in the attic"]}

Stored in playbook_overrides; only the owner can change them; every change is logged.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.director.playbooks import get_playbooks
from estimator.director.settings import _int, get_settings
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service

LANE_KEYS = {"review_required_over_cents": ("standard_estimate",), "quick_send_limit_cents": ("quick_quote",)}
MAX_ITEMS = 10


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_overrides(conn, company_id: str, playbook_id: str) -> dict:
    row = conn.execute("SELECT overrides_json FROM playbook_overrides WHERE company_id = ? AND playbook_id = ?",
                       (company_id, playbook_id)).fetchone()
    return json.loads(row["overrides_json"]) if row else {}


def effective_settings(conn, company_id: str, playbook_id: str | None) -> dict:
    """Director settings with this playbook's overrides applied."""
    s = get_settings(conn, company_id)
    if playbook_id:
        ov = get_overrides(conn, company_id, playbook_id)
        for k in LANE_KEYS:
            if k in ov:
                s[k] = ov[k]
    return s


def checklist_for(conn, company_id: str, playbook_id: str | None, module_ids) -> list[str]:
    if not playbook_id:
        return []
    cl = get_overrides(conn, company_id, playbook_id).get("checklist") or {}
    items = list(cl.get("*", []))
    for m in module_ids:
        items += [i for i in cl.get(m, []) if i not in items]
    return items


def _clean_checklist(value, registry) -> dict:
    if not isinstance(value, dict):
        raise InvalidInput('checklist must look like {"*": ["..."], "roofing": ["Site photo taken"]}', field="checklist")
    out = {}
    for key, items in value.items():
        if key != "*" and key not in registry.modules:
            raise InvalidInput(f"checklist key '{key}' must be \"*\" or a module id", field="checklist",
                               modules=sorted(registry.modules))
        if items in (None, []):
            continue
        if (not isinstance(items, list) or len(items) > MAX_ITEMS
                or not all(isinstance(i, str) and 0 < len(i.strip()) <= 200 for i in items)):
            raise InvalidInput(f"checklist for '{key}' must be a list of up to {MAX_ITEMS} short items",
                               field="checklist")
        out[key] = [i.strip() for i in items]
    return out


def update_overrides(conn, ctx: RequestContext, playbook_id: str, changes: dict, reset: bool = False,
                     registry=None) -> dict:
    from estimator.modules import get_registry
    reg = registry or get_registry()
    if ctx.role != "owner":
        raise PermissionDenied("only the owner can change playbooks", role=ctx.role)
    books = get_playbooks()
    if playbook_id not in books:
        raise NotFound(f"no playbook '{playbook_id}'", playbook_id=playbook_id, available=sorted(books))
    pb = books[playbook_id]
    if not isinstance(changes, dict):
        raise InvalidInput("changes must be an object")
    allowed = {k for k, lanes in LANE_KEYS.items() if pb.lane in lanes} | {"checklist"}
    unknown = sorted(set(changes) - allowed)
    if unknown:
        raise InvalidInput(f"the {pb.name} playbook can't change {unknown}", valid=sorted(allowed))
    before = get_overrides(conn, ctx.company_id, playbook_id)
    new = {} if reset else dict(before)
    for k, v in changes.items():
        if v is None:
            new.pop(k, None)
        elif k == "checklist":
            cl = {**(new.get("checklist") or {}), **_clean_checklist(v, reg)}
            for key, items in v.items():
                if items in (None, []):
                    cl.pop(key, None)
            new["checklist"] = cl
            if not cl:
                new.pop("checklist")
        else:
            new[k] = _int(v, k, 0, 100_000_000)
    with service.transaction(conn):
        if new:
            conn.execute(
                "INSERT INTO playbook_overrides (company_id, playbook_id, overrides_json, updated_by, updated_at)"
                " VALUES (?,?,?,?,?) ON CONFLICT (company_id, playbook_id) DO UPDATE SET"
                " overrides_json = excluded.overrides_json, updated_by = excluded.updated_by,"
                " updated_at = excluded.updated_at", (ctx.company_id, playbook_id, json.dumps(new), ctx.actor, _now()))
        else:
            conn.execute("DELETE FROM playbook_overrides WHERE company_id = ? AND playbook_id = ?",
                         (ctx.company_id, playbook_id))
        service._log(conn, ctx, None, "playbook_changed", {"playbook_id": playbook_id, "overrides": new},
                     {"overrides": before})
    return {"ok": True, "playbook_id": playbook_id, "overrides": new}


def list_with_overrides(conn, company_id: str) -> list[dict]:
    out = []
    for pb in get_playbooks().values():
        d = pb.summary()
        d["overrides"] = get_overrides(conn, company_id, pb.id)
        out.append(d)
    return out

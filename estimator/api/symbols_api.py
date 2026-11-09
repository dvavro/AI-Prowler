"""Reviews, Symbol Library and Agents screens - Coder 2 Sprint 11.

The JSON calls behind the three screens, through the same services as the MCP tools (symbol_* in estimator.symbols,
Jamie's agent_manager and runner). Every change asks first (needs_confirmation, then the page sends confirm=true);
agents never approve symbols; the services check each role again.

  Reviews (owner, estimator, reviewer, field - field looks, owner/estimator/reviewer decide):
  GET  /symbol-reviews                       plan sets with symbols found, and how many still need a person
  POST /symbol-detections/review {detection_ids?, action, item_type?, apply_to_matches?, sheet_id?, point?, note?,
                                  confirm?}   approve, reject, relabel, reset or add (symbol_detection_review)
  POST /symbol-detections/similar {detection_id | sheet_id + box, item_type?, confirm?}   symbol_find_similar
  GET  /symbol-detections/<id>/crop.png      the detection's thumbnail, cut from its sheet image
  (the detections themselves: GET /plan-sets/<id>/symbols in router.py)

  Symbol Library (owner, estimator, reviewer):
  GET  /symbol-library?level=&trade=         symbol_library_list
  POST /symbol-library/define {item_type, description?, trade?, code?, assembly_id?, definition_id?,
                               from_detection_ids?, confirm?}                    symbol_define
  GET  /symbol-library/export                the company library as a file (ai-prowler-symbol-library)
  POST /symbol-library/import {data, confirm?}

  Agents (owner, estimator; only the owner changes settings):
  GET  /agents                               agent_config_get for every trade, recent takeoff runs
  POST /agents/<module_id> {changes, confirm?}   agent_config_update
  GET  /runs/<id>                            runner_status
  POST /runs {estimate_id, trades, confirm?} runner_start (asks first here; the tool starts at once)
  POST /runner-tasks/<id>/retry {confirm?}   runner_retry_task
"""
from __future__ import annotations

import json
import re

from estimator.api import nav

_CROP = re.compile(r"^/symbol-detections/(\d+)/crop\.png$")
_AGENT = re.compile(r"^/agents/([a-z0-9_]{1,40})$")
_RUN = re.compile(r"^/runs/(\d+)$")
_RETRY = re.compile(r"^/runner-tasks/(\d+)/retry$")
MAX_IDS = 5000
MAX_TEXT = 300
RECENT_RUNS = 30


def handles(sub: str) -> bool:
    return (sub == "/symbol-reviews" or sub.startswith("/symbol-detections/") or sub == "/symbol-library"
            or sub.startswith("/symbol-library/") or sub == "/agents" or sub.startswith("/agents/") or sub == "/runs"
            or sub.startswith("/runs/") or sub.startswith("/runner-tasks/"))


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def _need(ctx, screen: str, what: str) -> None:
    if not nav.can_open(ctx.role, screen):
        raise _refuse(f"your role can't open {what}", 403, "permission_denied")


def _ids(value, field: str, required: bool = True) -> list[int]:
    if value in (None, []) and not required:
        return []
    if not isinstance(value, list) or not value:
        raise _refuse(f"{field} must be a list of ids")
    if len(value) > MAX_IDS:
        raise _refuse(f"at most {MAX_IDS} at a time")
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in value):
        raise _refuse(f"{field} must be a list of ids")
    return list(value)


def _nums(value, field: str, n: int) -> list[float] | None:
    if value is None:
        return None
    if (not isinstance(value, list) or len(value) != n
            or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in value)):
        raise _refuse(f"{field} must be {n} numbers (sheet inches)")
    return [float(v) for v in value]


def _text(b: dict, key: str) -> str | None:
    v = b.get(key)
    if v is None or v == "":
        return None
    if not isinstance(v, str):
        raise _refuse(f"{key} must be text")
    v = v.strip()
    if len(v) > MAX_TEXT:
        raise _refuse(f"{key} is too long ({MAX_TEXT} characters at most)")
    return v or None


def _int(b: dict, key: str) -> int | None:
    v = b.get(key)
    if v in (None, "", 0):
        return None
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise _refuse(f"{key} must be an id")
    return v


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _ask_first, _body, _ok

    # ------------------------------------------------------------------ Reviews
    if sub == "/symbol-reviews" and m == "GET":
        _need(ctx, "reviews", "reviews")
        from estimator.symbols import review
        rows = conn.execute(
            "SELECT ps.id AS plan_set_id, ps.original_name, ps.revision, ps.estimate_id, e.title AS estimate_title,"
            " COUNT(d.id) AS found, SUM(d.status = 'proposed') AS proposed, SUM(d.status = 'approved') AS approved,"
            " SUM(d.status = 'rejected') AS rejected, SUM(d.status = 'proposed' AND d.needs_review = 1) AS needs_review,"
            " MAX(COALESCE(d.reviewed_at, d.created_at)) AS last_activity"
            " FROM symbol_detections d JOIN plan_sets ps ON ps.id = d.plan_set_id"
            " JOIN estimates e ON e.id = ps.estimate_id AND e.company_id = d.company_id"
            " WHERE d.company_id = ? GROUP BY ps.id ORDER BY needs_review DESC, last_activity DESC LIMIT 200",
            (ctx.company_id,)).fetchall()
        sets = [{k: (r[k] or 0) if k in ("found", "proposed", "approved", "rejected", "needs_review") else r[k]
                 for k in r.keys()} for r in rows]
        return _ok(plan_sets=sets, count=len(sets), can_review=ctx.role in review.REVIEW_ROLES and not ctx.agent,
                   actions=list(review.ACTIONS))

    if sub == "/symbol-detections/review" and m == "POST":
        _need(ctx, "reviews", "reviews")
        from estimator.symbols import review
        b = _body(req)
        action = _text(b, "action") or "approve"
        ids = _ids(b.get("detection_ids"), "detection_ids", required=action != "add")
        point = _nums(b.get("point"), "point", 2)
        return _ask_first(lambda: review.review(
            conn, ctx, ids, action, _text(b, "item_type"), b.get("apply_to_matches") is True, _int(b, "sheet_id"),
            point, _text(b, "note"), b.get("confirm") is True))

    if sub == "/symbol-detections/similar" and m == "POST":
        _need(ctx, "reviews", "reviews")
        from estimator.symbols import review
        b = _body(req)
        return _ask_first(lambda: review.find_similar(
            conn, ctx, _int(b, "detection_id"), _int(b, "sheet_id"), _nums(b.get("box"), "box", 4),
            _text(b, "item_type"), b.get("confirm") is True))

    mm = _CROP.match(sub)
    if mm and m == "GET":
        _need(ctx, "reviews", "reviews")
        from estimator import config
        from estimator.api.router import SECURITY_HEADERS, Response
        from estimator.symbols import review
        try:
            path = review.crop_png(conn, ctx, int(mm.group(1)), config.data_dir())
        except (OSError, ValueError) as e:
            raise _refuse(f"no picture of this symbol: {e}", 404, "not_found") from None
        return Response(200, "image/png", path.read_bytes(), {"Cache-Control": "private, max-age=3600",
                                                              **SECURITY_HEADERS})

    # ------------------------------------------------------------------ Symbol Library
    if sub == "/symbol-library" and m == "GET":
        _need(ctx, "symbol_library", "the symbol library")
        from estimator.symbols import library
        q = req.query
        got = library.list_library(conn, ctx, (q.get("level") or "").strip() or None,
                                   (q.get("trade") or "").strip() or None)
        return _ok(**{k: v for k, v in got.items() if k != "ok"})          # libraries, can_define, trades

    if sub == "/symbol-library/define" and m == "POST":
        _need(ctx, "symbol_library", "the symbol library")
        from estimator.symbols import library
        b = _body(req)
        item_type = _text(b, "item_type")
        if not item_type:
            raise _refuse("item_type is required, e.g. floor_box")
        ids = _ids(b.get("from_detection_ids"), "from_detection_ids", required=False) or None
        return _ask_first(lambda: library.define(
            conn, ctx, item_type, _text(b, "description"), _text(b, "trade"), _text(b, "code"),
            _text(b, "assembly_id"), _int(b, "definition_id"), ids, b.get("confirm") is True))

    if sub == "/symbol-library/export" and m == "GET":
        _need(ctx, "symbol_library", "the symbol library")
        from estimator.api.router import SECURITY_HEADERS, Response
        from estimator.symbols import library
        data = library.export_library(conn, ctx)
        return Response(200, "application/json", json.dumps(data, indent=1).encode("utf-8"),
                        {"Content-Disposition": 'attachment; filename="symbol-library.json"',
                         "Cache-Control": "no-store", **SECURITY_HEADERS})

    if sub == "/symbol-library/import" and m == "POST":
        _need(ctx, "symbol_library", "the symbol library")
        from estimator.symbols import library
        b = _body(req)
        if not isinstance(b.get("data"), dict):
            raise _refuse("data must be a symbol library file (ai-prowler-symbol-library)")
        return _ask_first(lambda: library.import_library(conn, ctx, b["data"], b.get("confirm") is True))

    # ------------------------------------------------------------------ Agents
    if sub == "/agents" and m == "GET":
        _need(ctx, "agents", "Agent Manager")
        from estimator import agent_manager
        from estimator.modules import get_registry
        from estimator.runner import runner
        cfg = agent_manager.list_configs(conn, ctx.company_id, get_registry())
        runs = []
        for r in conn.execute(
                "SELECT r.id, r.estimate_id, r.state, r.started_by, r.created_at, r.finished_at, e.title"
                " FROM runs r JOIN estimates e ON e.id = r.estimate_id AND e.company_id = r.company_id"
                " WHERE r.company_id = ? ORDER BY r.id DESC LIMIT ?", (ctx.company_id, RECENT_RUNS)):
            tasks = [dict(t) for t in conn.execute(
                "SELECT id, module_id, state, progress FROM takeoff_tasks WHERE run_id = ? ORDER BY position, id",
                (r["id"],))]
            prog = round(sum(t["progress"] or 0 for t in tasks) / len(tasks)) if tasks else 0
            runs.append({**dict(r), "estimate_title": r["title"], "progress": prog, "tasks": tasks})
        return _ok(agents=cfg["agents"], enabled=cfg["enabled"], turned_off=cfg["turned_off"], runs=runs,
                   task_states=list(runner.TASK_STATES), can_configure=ctx.role == "owner" and not ctx.agent,
                   can_start=ctx.role in runner.START_ROLES)

    mm = _AGENT.match(sub)
    if mm and m == "POST":
        _need(ctx, "agents", "Agent Manager")
        from estimator import agent_manager
        from estimator.api.router import _question
        from estimator.modules import get_registry
        b = _body(req)
        changes = b.get("changes")
        if not isinstance(changes, dict) or not changes:
            raise _refuse('changes is an object, e.g. {"enabled": false}')
        out = agent_manager.update_config(conn, ctx, mm.group(1), changes, confirm=b.get("confirm") is True,
                                          registry=get_registry())
        if not out.get("confirmed"):
            diff = out["would_change"]
            if not diff:
                return _ok(changed={}, config=out["current"], message="Nothing to change.")
            words = ", ".join(f"{k.replace('_', ' ')} to {json.dumps(v)}" for k, v in diff.items())
            return _ok(needs_confirmation=True, question=_question(f"Set {out['current']['name']} {words}"),
                       would_change=diff, current=out["current"])
        return _ok(changed=out["changed"], config=out["config"])

    mm = _RUN.match(sub)
    if mm and m == "GET":
        _need(ctx, "agents", "Agent Manager")
        from estimator.runner import runner
        got = runner.run_status(conn, ctx, run_id=int(mm.group(1)))
        return _ok(**{k: v for k, v in got.items() if k != "ok"})

    if sub == "/runs" and m == "POST":
        _need(ctx, "agents", "Agent Manager")
        from estimator.api.router import _question
        from estimator.errors import PermissionDenied
        from estimator.runner import runner
        b = _body(req)
        eid = _int(b, "estimate_id")
        trades = b.get("trades")
        if not eid:
            raise _refuse("estimate_id is required")
        if not isinstance(trades, list) or not trades or not all(isinstance(t, str) and t.strip() for t in trades):
            raise _refuse('trades is a list of trades, e.g. ["framing", "drywall"]')
        if ctx.role not in runner.START_ROLES:
            raise PermissionDenied(f"role '{ctx.role}' can't start a takeoff run", role=ctx.role)
        if b.get("confirm") is not True:
            from estimator.estimating import service
            est = service.get_estimate(conn, ctx, eid)
            return _ok(needs_confirmation=True, estimate_id=eid, trades=trades,
                       question=_question(f"Start a takeoff run on {est['title']} for {', '.join(trades)}"))
        got = runner.start_run(conn, ctx, eid, trades)
        return _ok(**{k: v for k, v in got.items() if k != "ok"})

    mm = _RETRY.match(sub)
    if mm and m == "POST":
        _need(ctx, "agents", "Agent Manager")
        from estimator.api.router import _question
        from estimator.runner import runner
        b = _body(req)
        if b.get("confirm") is not True:
            return _ok(needs_confirmation=True, task_id=int(mm.group(1)),
                       question=_question(f"Try takeoff task {mm.group(1)} again"))
        got = runner.retry_task(conn, ctx, int(mm.group(1)))
        return _ok(**{k: v for k, v in got.items() if k != "ok"})

    from estimator.api.router import _fail
    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")

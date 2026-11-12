"""Concrete agent auto-run (Phase 1): slab candidates, run rows, and the agent's stamp.

The auto-run finds the slab on a foundation plan (pure geometry - see
estimator/takeoff/slab_find.py, no LLM and no cost), then a Playwright agent
drives the Blueprint Review page the way a person would: it draws the
measurements, and the page's own save stamps each one through mark-agent below.
A person still approves everything; the agent never approves, and approved
measurements stay locked.

When the drawing has no slab outline at all, the run falls back to the AI
reading the foundation sheet (estimator/takeoff/llm_takeoff.py) - but only when
the owner turned LLM takeoff on (the llm_takeoff agent role, off by default).
That runner needs no browser: it reads the dimensions, the app does the maths,
and the measurements are proposed as "llm-takeoff" for a person to approve.

  GET  /viewports/<id>/slab-candidates   rectangles on the viewport, biggest first
                                          (empty when the sheet is switched off for Concrete)
  POST /auto-run {estimate_id, sheet_id, viewport_id, module_id}   start a run (concrete only, Phase 1)
                                          (refused when the sheet is switched off for Concrete)
  GET  /auto-run/<id>                    the run: status, step, candidates, measurements
  POST /auto-run/<id>/rerun              delete the run's proposed agent measurements, start again
  POST /measurements/<id>/retarget {candidate_id, confirm?}   recompute a proposed agent measurement
                                                              from another candidate (asks first)
  POST /measurements/<id>/mark-agent {auto_run_id, candidate_id}   stamp a measurement the agent just
                                                              saved in the page (owner, estimator)

The agent runs as a detached subprocess (sys.executable -m
estimator.agents.concrete_autorun --base <server base URL> --db <db path>
--run-id <id> --headed) so the start call returns at once; it reports back by
writing its run row (update_run) and stamping measurements through mark-agent.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from estimator.api import nav

_CANDIDATES = re.compile(r"^/viewports/(\d+)/slab-candidates$")
_RUNS = re.compile(r"^/auto-run$")
_RUN_ONE = re.compile(r"^/auto-run/(\d+)$")
_RERUN = re.compile(r"^/auto-run/(\d+)/rerun$")
_MEAS_ACT = re.compile(r"^/measurements/(\d+)/(retarget|mark-agent)$")

AGENT = "concrete-agent"         # proposed_by on every measurement the agent makes
LLM_AGENT = "llm-takeoff"          # proposed_by on every measurement the LLM fallback makes
MODULE_ID = "concrete"           # Phase 1: only the concrete agent runs itself
STATUSES = ("running", "done", "failed")
PLAYWRIGHT_ERROR = "Playwright/Chromium is not installed — run: playwright install chromium"


def handles(sub: str) -> bool:
    return (bool(_CANDIDATES.match(sub)) or bool(_RUNS.match(sub)) or bool(_RUN_ONE.match(sub))
            or bool(_RERUN.match(sub)) or bool(_MEAS_ACT.match(sub)))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def _role(ctx, roles, what: str) -> None:
    from estimator.errors import PermissionDenied
    if ctx.role not in roles:
        raise PermissionDenied(f"only {', '.join(roles)} can {what}", role=ctx.role)


def _ask(fn, extra: str = ""):
    """Like takeoff_api._ask: a write that asks first, then runs with confirm=true."""
    from estimator.api.router import _ok, _question
    from estimator.errors import ConfirmationRequired
    try:
        return _ok(**fn())
    except ConfirmationRequired as e:
        q = _question(e.message)
        if extra:
            q = q.rstrip("?") + "? " + extra if q.endswith("?") else q + " " + extra
        return _ok(needs_confirmation=True, question=q, **e.details)


def _qty2(value) -> str:
    return str(Decimal(str(value)).quantize(Decimal("0.01")))


# ------------------------------------------------------------------ run rows

def _shape_run(row) -> dict:
    r = dict(row)
    cands = json.loads(r["candidates_json"] or "[]")
    return {"id": r["id"], "estimate_id": r["estimate_id"], "sheet_id": r["sheet_id"],
            "viewport_id": r["viewport_id"], "module_id": r["module_id"], "status": r["status"],
            "step": r["step"], "error": r["error"], "candidate_id": r["candidate_id"],
            "candidates": cands,
            "source": "llm" if any(c.get("source") == "llm" for c in cands) else "geometry",
            "measurement_ids": json.loads(r["measurement_ids_json"] or "[]"),
            "created_at": r["created_at"], "updated_at": r["updated_at"]}


def _load_run(conn, ctx, run_id: int) -> dict:
    from estimator.errors import NotFound
    row = conn.execute("SELECT * FROM auto_runs WHERE id = ? AND company_id = ?",
                       (int(run_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"auto-run {run_id} not found", run_id=run_id)
    return dict(row)


def create_run(conn, ctx, estimate_id: int, sheet_id: int, viewport_id: int,
               module_id: str, candidates: list | None = None) -> int:
    """A run row, starting. The caller starts the agent (or marks it failed)."""
    now = _now()
    cur = conn.execute(
        "INSERT INTO auto_runs (company_id, estimate_id, sheet_id, viewport_id, module_id, status, step,"
        " candidates_json, measurement_ids_json, created_by, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, 'running', 'starting', ?, '[]', ?, ?, ?)",
        (ctx.company_id, estimate_id, sheet_id, viewport_id, module_id,
         json.dumps(candidates or []), ctx.actor, now, now))
    return cur.lastrowid


def update_run(conn, run_id: int, status: str | None = None, step: str | None = None,
               error: str | None = None, candidate_id: str | None = None,
               candidates: list | None = None, measurement_ids: list | None = None) -> dict:
    """How the agent reports back: its step, its candidates, what it measured, done/failed.

    Only the given fields change (None leaves a field alone). Raises NotFound
    for a run that isn't there.
    """
    from estimator.errors import InvalidInput, NotFound
    row = conn.execute("SELECT * FROM auto_runs WHERE id = ?", (int(run_id),)).fetchone()
    if row is None:
        raise NotFound(f"auto-run {run_id} not found", run_id=run_id)
    sets, args = [], []
    if status is not None:
        if status not in STATUSES:
            raise InvalidInput(f"status must be one of {', '.join(STATUSES)}", field="status")
        sets.append("status = ?")
        args.append(status)
    if step is not None:
        sets.append("step = ?")
        args.append(step)
    if error is not None:
        sets.append("error = ?")
        args.append(error)
    if candidate_id is not None:
        sets.append("candidate_id = ?")
        args.append(candidate_id)
    if candidates is not None:
        sets.append("candidates_json = ?")
        args.append(json.dumps(candidates))
    if measurement_ids is not None:
        sets.append("measurement_ids_json = ?")
        args.append(json.dumps([int(m) for m in measurement_ids]))
    sets.append("updated_at = ?")
    args.append(_now())
    args.append(int(run_id))
    conn.execute(f"UPDATE auto_runs SET {', '.join(sets)} WHERE id = ?", args)
    return _shape_run(conn.execute("SELECT * FROM auto_runs WHERE id = ?", (int(run_id),)).fetchone())


# ------------------------------------------------------------------ the agent process

def server_base_url() -> str:
    """The Estimator server's base URL (origin only): the agent adds /estimator/ and /estimator-api/."""
    from estimator.api import router, server
    url = server.url()
    if url:
        base = url[:-1] if url.endswith("/") else url
        if base.endswith(router.APP):
            base = base[:-len(router.APP)]
        if base:
            return base
    return f"http://localhost:{server.default_port()}"


def _playwright_available() -> bool:
    """Playwright's Python package plus a Chromium it can actually launch."""
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return Path(p.chromium.executable_path).exists()
    except Exception:  # noqa: BLE001 - any failure here means the agent can't run
        return False


def spawn_agent(run_id: int, base_url: str | None = None, db_path=None):
    """Start the Playwright agent as a detached process; it must never block the server."""
    import estimator
    from estimator import config
    cmd = [sys.executable, "-m", "estimator.agents.concrete_autorun",
           "--base", base_url or server_base_url(), "--db", str(db_path or config.db_path()),
           "--run-id", str(run_id), "--headed"]
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
              "cwd": str(Path(estimator.__file__).resolve().parents[1])}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(cmd, **kwargs)


def _start_agent(conn, ctx, run_id: int):
    """Start the agent for a run row, or mark the run failed when it can't start."""
    from estimator.api.router import _ok
    if not _playwright_available():
        update_run(conn, run_id, status="failed", step="failed", error=PLAYWRIGHT_ERROR)
        return _ok(run_id=run_id, status="failed", error=PLAYWRIGHT_ERROR)
    try:
        spawn_agent(run_id)
    except OSError as e:
        update_run(conn, run_id, status="failed", step="failed", error=f"could not start the agent: {e}")
        return _ok(run_id=run_id, status="failed", error=f"could not start the agent: {e}")
    return _ok(run_id=run_id, status="running")


def spawn_llm_agent(run_id: int, db_path=None):
    """Start the LLM takeoff runner as a detached process; it must never block the server."""
    import estimator
    from estimator import config
    cmd = [sys.executable, "-m", "estimator.agents.llm_takeoff_runner",
           "--db", str(db_path or config.db_path()), "--run-id", str(run_id)]
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
              "cwd": str(Path(estimator.__file__).resolve().parents[1])}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(cmd, **kwargs)


def _start_llm_agent(conn, ctx, run_id: int):
    """Start the LLM takeoff runner for a run row, or mark the run failed when it can't start."""
    from estimator.api.router import _ok
    try:
        spawn_llm_agent(run_id)
    except OSError as e:
        update_run(conn, run_id, status="failed", step="failed", error=f"could not start the agent: {e}")
        return _ok(run_id=run_id, status="failed", error=f"could not start the agent: {e}")
    return _ok(run_id=run_id, status="running")


def _start_run(conn, ctx, run_id: int, candidates: list):
    """Start the right agent for a run row: the geometric agent when the drawing gave
    outlines, else the LLM fallback when the owner turned it on. With LLM takeoff off
    (the default) there is nothing left to try - the drawing gave no outline and the
    AI is not to run - so the run fails at once, saying the AI did not run and where
    to turn it on. (It used to start the geometric agent, which then failed with
    'no slab outline' and looked like the AI had run and failed.)"""
    from estimator.api.router import _ok
    from estimator.agents import roles
    from estimator.takeoff import llm_takeoff
    if candidates:
        return _start_agent(conn, ctx, run_id)
    setting = llm_takeoff.llm_setting(conn, ctx.company_id)
    if not setting["enabled"]:
        msg = ("No slab outline found on this sheet — the AI did not run because LLM takeoff is off. "
               "Turn it on in 🤖 AI agents (Setup) to let the AI read the plan, or measure the slab manually.")
        update_run(conn, run_id, status="failed", step="failed", error=msg)
        return _ok(run_id=run_id, status="failed", error=msg)
    if not setting["ready"]:
        msg = (f"LLM takeoff is on but {setting['provider_label']} isn't ready: {setting['why_not']}."
               " Save a key in 🔑 Agent API Key, or turn LLM takeoff off.")
        update_run(conn, run_id, status="failed", step="failed", error=msg)
        return _ok(run_id=run_id, status="failed", error=msg)
    ok_budget, why = roles.budget_left(conn, ctx.company_id)
    if not ok_budget:
        msg = f"LLM takeoff can't run: {why}"
        update_run(conn, run_id, status="failed", step="failed", error=msg)
        return _ok(run_id=run_id, status="failed", error=msg)
    return _start_llm_agent(conn, ctx, run_id)


# ------------------------------------------------------------------ retarget / mark-agent

def retarget_measurement(conn, ctx, measurement_id: int, candidate_id: str, confirm: bool = False) -> dict:
    """Recompute a proposed agent measurement from another candidate rectangle.

    The rectangle comes from the measurement's own run; the quantity is
    recomputed from the rectangle with the viewport's current scale. Approved
    measurements are locked and never retargeted.
    """
    from estimator.errors import ConfirmationRequired, InvalidInput
    from estimator.estimating import service
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import slab_find

    d = ms.detail(conn, ctx, int(measurement_id))
    m, calc = d["measurement"], d["calc"]
    if m["proposed_by"] != AGENT:
        raise InvalidInput("only a measurement the concrete agent proposed can be retargeted",
                           measurement_id=m["id"])
    if m["status"] != "proposed":
        raise InvalidInput("that measurement is approved and locked; it can't be retargeted",
                           measurement_id=m["id"])
    if m["kind"] not in ("area", "length", "perimeter"):
        raise InvalidInput(f"a {m['kind']} measurement can't be retargeted (only area, length, perimeter)",
                           measurement_id=m["id"])
    run_id = calc.get("auto_run_id")
    if not run_id:
        raise InvalidInput("that measurement has no auto-run to retarget from", measurement_id=m["id"])
    run = _shape_run(_load_run(conn, ctx, int(run_id)))
    cand = next((c for c in run["candidates"] if c["id"] == candidate_id), None)
    if cand is None:
        raise InvalidInput(f"this run has no candidate '{candidate_id}'", candidate_id=candidate_id)
    vp = conn.execute("SELECT * FROM viewports WHERE id = ?", (m["viewport_id"],)).fetchone() \
        if m["viewport_id"] else None
    ratio = slab_find._scale_ratio(vp)
    if not ratio:
        raise InvalidInput("that viewport has no scale, so the measurement can't be recomputed",
                           viewport_id=m["viewport_id"])
    per_ft = ratio / 12
    if m["kind"] == "area":
        qty, unit = _qty2(cand["width"] * per_ft * cand["height"] * per_ft), "sqft"
    else:
        qty, unit = _qty2(cand["perimeter"] * per_ft), "lf"
    label = cand.get("label") or candidate_id
    if not confirm:
        raise ConfirmationRequired(
            f"Retarget '{m['label'] or m['kind']}' to {label} ({qty} {unit})?"
            " Call again with confirm=true.",
            measurement_id=m["id"], candidate_id=candidate_id, qty=qty, unit=unit)
    now = _now()
    new_calc = {**calc, "candidate_id": candidate_id}
    with service.transaction(conn):
        conn.execute("UPDATE measurements SET qty = ?, unit = ?, source_object_ids = ?, geometry_json = ?,"
                     " calc_json = ?, updated_at = ? WHERE id = ?",
                     (qty, unit, json.dumps(cand["object_ids"]),
                      json.dumps({"type": "polygon", "points": cand["corners"]}),
                      json.dumps(new_calc), now, m["id"]))
        service._log(conn, ctx, m["estimate_id"], "measurement_retargeted",
                     {"measurement_id": m["id"], "candidate_id": candidate_id, "qty": qty, "unit": unit},
                     before={"qty": m["qty"], "candidate_id": calc.get("candidate_id")})
    return {"measurement": ms.detail(conn, ctx, m["id"])["measurement"]}


def mark_agent_measurement(conn, ctx, measurement_id: int, auto_run_id: int, candidate_id: str) -> dict:
    """Stamp a measurement the agent just saved in the page as the agent's own.

    Sets proposed_by to the agent and records the run and candidate in its
    calc, and adds it to the run's measurement list. Proposed only: an approved
    measurement is locked and never restamped.
    """
    from estimator.errors import InvalidInput
    from estimator.takeoff import measurements as ms

    d = ms.detail(conn, ctx, int(measurement_id))
    m, calc = d["measurement"], d["calc"]
    if m["status"] != "proposed":
        raise InvalidInput("only a proposed measurement can be marked as the agent's",
                           measurement_id=m["id"])
    run = _shape_run(_load_run(conn, ctx, int(auto_run_id)))
    if candidate_id not in {c["id"] for c in run["candidates"]}:
        raise InvalidInput(f"run {auto_run_id} has no candidate '{candidate_id}'",
                           candidate_id=candidate_id)
    new_calc = {**calc, "auto_run_id": int(auto_run_id), "candidate_id": candidate_id}
    conn.execute("UPDATE measurements SET proposed_by = ?, calc_json = ?, updated_at = ? WHERE id = ?",
                 (AGENT, json.dumps(new_calc), _now(), m["id"]))
    if m["id"] not in run["measurement_ids"]:
        update_run(conn, int(auto_run_id), measurement_ids=[*run["measurement_ids"], m["id"]])
    return {"measurement": ms.detail(conn, ctx, m["id"])["measurement"]}


# ------------------------------------------------------------------ routes

def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _body, _fail, _int_opt, _ok
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import slab_find

    if not nav.can_open(ctx.role, "takeoffs"):
        raise _refuse("your role can't open takeoffs", 403, "permission_denied")

    mm = _CANDIDATES.match(sub)
    if mm and m == "GET":
        found = slab_find.find_slab_candidates(conn, ctx.company_id, int(mm.group(1)))
        vp = conn.execute("SELECT sheet_id FROM viewports WHERE id = ? AND company_id = ?",
                          (int(mm.group(1)), ctx.company_id)).fetchone()
        if vp is not None:
            # A sheet switched off for Concrete shows no candidates: the page already says
            # "Agent found no slab outline on this sheet" for an empty list.
            from estimator.takeoff import sheet_trades
            if not sheet_trades.is_active(conn, ctx.company_id, vp["sheet_id"], MODULE_ID):
                found = {**found, "candidates": []}
        return _ok(**found)

    if _RUNS.match(sub) and m == "POST":
        _role(ctx, ms.PROPOSE_ROLES, "run the takeoff agent")
        b = _body(req)
        estimate_id = _int_opt(b.get("estimate_id"))
        sheet_id = _int_opt(b.get("sheet_id"))
        viewport_id = _int_opt(b.get("viewport_id"))
        if estimate_id is None:
            raise _refuse("say which estimate to measure (estimate_id)")
        if sheet_id is None:
            raise _refuse("say which sheet to measure (sheet_id)")
        if viewport_id is None:
            raise _refuse("say which viewport to measure (viewport_id)")
        if str(b.get("module_id") or "").strip() != MODULE_ID:
            raise _refuse("only the concrete agent runs itself for now (module_id must be 'concrete')")
        from estimator.estimating import service
        service.get_estimate(conn, ctx, estimate_id)          # not found / another company's estimate
        sheet = conn.execute("SELECT id FROM sheets WHERE id = ? AND company_id = ?",
                             (sheet_id, ctx.company_id)).fetchone()
        if sheet is None:
            raise _refuse(f"sheet {sheet_id} not found", 404, "not_found")
        vp = conn.execute("SELECT id, sheet_id FROM viewports WHERE id = ? AND company_id = ?",
                          (viewport_id, ctx.company_id)).fetchone()
        if vp is None:
            raise _refuse(f"viewport {viewport_id} not found", 404, "not_found")
        if vp["sheet_id"] != sheet_id:
            raise _refuse("that viewport is on a different sheet")
        from estimator.takeoff import sheet_trades
        if not sheet_trades.is_active(conn, ctx.company_id, sheet_id, MODULE_ID):
            raise _refuse("this sheet is switched off for Concrete — switch it back on from the Plans screen to run the agent")
        busy = conn.execute("SELECT id FROM auto_runs WHERE company_id = ? AND estimate_id = ?"
                            " AND viewport_id = ? AND module_id = ? AND status = 'running'",
                            (ctx.company_id, estimate_id, viewport_id, MODULE_ID)).fetchone()
        if busy is not None:
            raise _refuse("an auto-run is already going for this viewport; wait for it to finish")
        found = slab_find.find_slab_candidates(conn, ctx.company_id, viewport_id)
        run_id = create_run(conn, ctx, estimate_id, sheet_id, viewport_id, MODULE_ID, found["candidates"])
        return _start_run(conn, ctx, run_id, found["candidates"])

    mm = _RUN_ONE.match(sub)
    if mm and m == "GET":
        return _ok(run=_shape_run(_load_run(conn, ctx, int(mm.group(1)))))

    mm = _RERUN.match(sub)
    if mm and m == "POST":
        _role(ctx, ms.PROPOSE_ROLES, "re-run the takeoff agent")
        from estimator.estimating import service
        old = _load_run(conn, ctx, int(mm.group(1)))
        if old["status"] == "running":
            raise _refuse("that run is still going; wait for it to finish before re-running it")
        from estimator.takeoff import sheet_trades
        if not sheet_trades.is_active(conn, ctx.company_id, old["sheet_id"], old["module_id"]):
            raise _refuse("this sheet is switched off for that trade — switch it back on from the Plans screen to re-run the agent")
        # Only this run's own proposed measurements go: approved ones are locked, and other runs'
        # (or a person's) measurements are never touched.
        doomed = []
        for r in conn.execute("SELECT id, calc_json FROM measurements WHERE company_id = ? AND estimate_id = ?"
                              " AND proposed_by IN (?, ?) AND status = 'proposed'",
                              (ctx.company_id, old["estimate_id"], AGENT, LLM_AGENT)):
            try:
                calc = json.loads(r["calc_json"] or "{}")
            except ValueError:
                continue
            if calc.get("auto_run_id") == old["id"]:
                doomed.append(r["id"])
        found = slab_find.find_slab_candidates(conn, ctx.company_id, old["viewport_id"])
        with service.transaction(conn):
            for mid in doomed:
                conn.execute("DELETE FROM measurements WHERE id = ?", (mid,))
            service._log(conn, ctx, old["estimate_id"], "auto_run_rerun",
                         {"run_id": old["id"], "deleted_measurement_ids": doomed})
            new_id = create_run(conn, ctx, old["estimate_id"], old["sheet_id"], old["viewport_id"],
                                old["module_id"], found["candidates"])
        return _start_run(conn, ctx, new_id, found["candidates"])

    mm = _MEAS_ACT.match(sub)
    if mm and m == "POST":
        b, mid, act = _body(req), int(mm.group(1)), mm.group(2)
        if act == "retarget":
            _role(ctx, ms.PROPOSE_ROLES + ("reviewer",), "retarget measurements")
            candidate_id = b.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id.strip():
                raise _refuse("say which candidate to retarget to (candidate_id)")
            return _ask(lambda: retarget_measurement(conn, ctx, mid, candidate_id.strip(),
                                                     b.get("confirm") is True))
        _role(ctx, ms.PROPOSE_ROLES, "mark agent measurements")
        auto_run_id = _int_opt(b.get("auto_run_id"))
        if auto_run_id is None:
            raise _refuse("say which auto-run made this measurement (auto_run_id)")
        candidate_id = b.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise _refuse("say which candidate this measurement came from (candidate_id)")
        return _ok(**mark_agent_measurement(conn, ctx, mid, auto_run_id, candidate_id.strip()))

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")

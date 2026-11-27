"""Takeoff agent auto-run (Phase 1): slab candidates, run rows, and the agent's stamp.

The auto-run finds the slab on a foundation plan (pure geometry - see
estimator/takeoff/slab_find.py, no LLM and no cost), then a Playwright agent
drives the Blueprint Review page the way a person would: it draws the
measurements, and the page's own save stamps each one through mark-agent below.
A person still approves everything; the agent never approves, and approved
measurements stay locked.

When the owner turned LLM takeoff on (the llm_takeoff agent role, off by default)
and its API key is ready, the run is the AI reading the foundation sheet
(estimator/takeoff/llm_takeoff.py) after calibrating it (2026-11-15: AI Auto Measure/Count);
otherwise the drawing-only agent runs when the drawing has slab outlines.
The AI runner needs no browser: it reads the dimensions, the app does the maths,
and the measurements are proposed as "llm-takeoff" for a person to approve.

  GET  /viewports/<id>/slab-candidates   rectangles on the viewport, biggest first
                                          (empty when the sheet is switched off for Concrete)
  POST /auto-run {estimate_id, sheet_id?, viewport_id?, module_id}   start a run (concrete and electrical, Phase 1).
                                          Only sheets switched ON for the trade are measured: with no sheet (or a
                                          switched-off one) it picks the best sheet for the trade that is on, and the
                                          trade's view on it; refused when every sheet is switched off
  GET  /auto-run/<id>                    the run: status, step, candidates, measurements, and when done its
                                          results (each measurement, and the concrete volume they add up to,
                                          with every step's formula written out to check by hand)
  GET  /auto-run?estimate_id=&sheet_id=   the latest run on that sheet (same shape), or run: null
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
_VP_MARK = re.compile(r"^/viewports/(\d+)/mark-agent$")
_VP_AUTOCAL = re.compile(r"^/viewports/(\d+)/auto-calibrate$")
_FOOTER = re.compile(r"^/auto-run/(\d+)/footer$")
_ADJUST = re.compile(r"^/auto-run/(\d+)/adjust$")          # 2026-11-16: add / take away / remove a drawn area
_PLACE = re.compile(r"^/auto-run/(\d+)/section-place$")    # 2026-11-16: where the footer section sits on its detail

AGENT = "concrete-agent"         # proposed_by on every measurement the agent makes
LLM_AGENT = "llm-takeoff"          # proposed_by on every measurement the LLM fallback makes
MODULE_ID = "concrete"           # the slab-candidates endpoint is concrete-only; STRATEGIES lists the trades that run
STATUSES = ("running", "done", "failed")
PLAYWRIGHT_ERROR = "Playwright/Chromium is not installed — run: playwright install chromium"


def handles(sub: str) -> bool:
    return (bool(_CANDIDATES.match(sub)) or bool(_RUNS.match(sub)) or bool(_RUN_ONE.match(sub))
            or bool(_RERUN.match(sub)) or bool(_MEAS_ACT.match(sub)) or bool(_VP_MARK.match(sub))
            or bool(_VP_AUTOCAL.match(sub)) or bool(_FOOTER.match(sub)) or bool(_ADJUST.match(sub))
            or bool(_PLACE.match(sub)))


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
            "calibration": next((c["calibration"] for c in cands if c.get("calibration")), None),
            "measurement_ids": json.loads(r["measurement_ids_json"] or "[]"),
            # The AI's progress while it reads (2026-11-21): its latest sentence and how much has come back.
            "live": _live(r) if r["status"] in ("queued", "running") else None,
            "created_at": r["created_at"], "updated_at": r["updated_at"]}


def _live(r: dict):
    try:
        v = json.loads(r.get("live_json") or "null")
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def _load_run(conn, ctx, run_id: int) -> dict:
    from estimator.errors import NotFound
    row = conn.execute("SELECT * FROM auto_runs WHERE id = ? AND company_id = ?",
                       (int(run_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"auto-run {run_id} not found", run_id=run_id)
    return dict(row)


def _keep_approved(body: dict) -> bool:
    """The run's keep-approved choice from the request: on unless the caller says false (2026-11-19, David)."""
    v = (body or {}).get("keep_approved", True)
    return not (v is False or str(v).strip().lower() in ("0", "false", "no", "off"))


def create_run(conn, ctx, estimate_id: int, sheet_id: int, viewport_id: int,
               module_id: str, candidates: list | None = None, keep_approved: bool = True) -> int:
    """A run row, starting. The caller starts the agent (or marks it failed). keep_approved: the rerun keeps the
    items a person already approved (and doesn't propose them again) - else it starts the trade over from scratch."""
    now = _now()
    cur = conn.execute(
        "INSERT INTO auto_runs (company_id, estimate_id, sheet_id, viewport_id, module_id, status, step,"
        " candidates_json, measurement_ids_json, created_by, created_at, updated_at, keep_approved)"
        " VALUES (?, ?, ?, ?, ?, 'running', 'starting', ?, '[]', ?, ?, ?, ?)",
        (ctx.company_id, estimate_id, sheet_id, viewport_id, module_id,
         json.dumps(candidates or []), ctx.actor, now, now, 1 if keep_approved else 0))
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


def _start_run(conn, ctx, run_id: int, candidates: list, module_id: str):
    """Start the right agent for a run row: the AI (LLM takeoff) when the owner turned it on and
    its key is ready (2026-11-15), else the drawing agent when the trade has one and the drawing
    gave outlines. With LLM takeoff off (the default) and nothing to fall back on, the run fails
    at once, saying the AI did not run and where to turn it on. (It used to start the geometric
    agent, which then failed with 'no slab outline' and looked like the AI had run and failed.)

    Concrete keeps its Phase 1 behaviour exactly: the AI first, the drawing agent when the AI is
    off, not ready, or out of budget. Electrical has no drawing agent - the symbols are
    unclassified, so there is nothing to count geometrically - and is LLM-only."""
    from estimator.api.router import _ok
    from estimator.agents import roles
    from estimator.takeoff import llm_takeoff
    strategy = STRATEGIES[module_id]
    setting = llm_takeoff.llm_setting(conn, ctx.company_id)
    # 2026-11-15 (David): with LLM takeoff on and its API key ready, AI Auto Measure/Count sends the sheet to the AI (after
    # calibrating it) even when the drawing has outlines - the AI reads the written dimensions and the footer detail,
    # the app does the maths. The drawing-only agent runs when the AI is off, not ready, or out of budget.
    if setting["enabled"] and setting["ready"] and roles.budget_left(conn, ctx.company_id)[0]:
        return _start_llm_agent(conn, ctx, run_id)
    if candidates and strategy["geometric"]:
        return _start_agent(conn, ctx, run_id)
    if not setting["enabled"]:
        msg = strategy["llm_off"]
        update_run(conn, run_id, status="failed", step="failed", error=msg)
        return _ok(run_id=run_id, status="failed", error=msg)
    if not setting["ready"]:
        msg = (f"AI measuring is on but {setting['provider_label']} isn't ready: {setting['why_not']}."
               " Save a key in 🔑 Agent API Key, or turn AI measuring off.")
        update_run(conn, run_id, status="failed", step="failed", error=msg)
        return _ok(run_id=run_id, status="failed", error=msg)
    ok_budget, why = roles.budget_left(conn, ctx.company_id)
    if not ok_budget:
        msg = f"AI measuring can't run: {why}"
        update_run(conn, run_id, status="failed", step="failed", error=msg)
        return _ok(run_id=run_id, status="failed", error=msg)
    return _start_llm_agent(conn, ctx, run_id)


# ------------------------------------------------------------------ which sheet AI Auto Measure/Count measures (2026-11-15)

def _sheet_on(conn, ctx, sheet_id: int, module_id: str) -> bool:
    from estimator.takeoff import sheet_trades
    return sheet_trades.is_active(conn, ctx.company_id, int(sheet_id), module_id)


def pick_run_sheet(conn, ctx, estimate_id: int, module_id: str) -> int:
    """The sheet AI Auto Measure/Count measures when none (or a switched-off one) is named: of the project's read plans, the
    sheets switched ON for the trade, best match first for the trade's sheet rules (the same ranking the AI uses).
    Refuses when every sheet is switched off, or no plans have been read."""
    from estimator.takeoff import llm_takeoff
    strategy = STRATEGIES[module_id]
    sets = [r["id"] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?"
                                          " AND status = 'processed' ORDER BY id DESC", (ctx.company_id, int(estimate_id)))]
    if not sets:
        raise _refuse("this project's plans haven't been read yet — upload them on the project page first")
    ranked = []
    for ps in sets:
        ranked += [s for s in llm_takeoff.pick_foundation_sheets(conn, ctx.company_id, ps, module_id=module_id)
                   if _sheet_on(conn, ctx, s["id"], module_id)]
    if not ranked:
        any_on = conn.execute("SELECT s.id FROM sheets s WHERE s.company_id = ? AND s.plan_set_id IN ("
                              + ",".join("?" * len(sets)) + ")", (ctx.company_id, *sets)).fetchall()
        if any(_sheet_on(conn, ctx, r["id"], module_id) for r in any_on):
            raise _refuse(f"the sheets switched on for {strategy['label']} have no picture to read — read the plans again")
        raise _refuse(f"every sheet is switched off for {strategy['label']} — switch "
                      f"{strategy['sheet_phrase']} on from the Plans screen")
    ranked.sort(key=lambda s: (-s["score"], s["page_no"]))
    return int(ranked[0]["id"])


# ------------------------------------------------------------------ the run's results (2026-11-15)

def _footer_inches(size) -> tuple[int, int] | None:
    """'12x20', '12"X20"', '12 x 20 in' -> (12, 20); None when it isn't two numbers."""
    nums = re.findall(r"\d+(?:\.\d+)?", str(size or ""))
    if len(nums) < 2:
        return None
    return float(nums[0]), float(nums[1])


def _thickness_in(text) -> Decimal | None:
    """'4"', '4 in', '4 IN. SLAB' -> 4; None when no sensible number (1-24 in) is in it."""
    m = re.search(r"\d+(?:\.\d+)?", str(text or ""))
    if not m:
        return None
    v = Decimal(m.group(0))
    return v if Decimal(1) <= v <= Decimal(24) else None


def _n(v, places: int = 2) -> str:
    """A number for a worked formula: thousands commas, trailing .00 kept for money-like precision."""
    d = Decimal(str(v)).quantize(Decimal(1).scaleb(-places)) if places else Decimal(str(v)).quantize(Decimal(1))
    return f"{d:,}"


def run_results(conn, ctx, row: dict) -> dict | None:
    """What a finished run measured, shaped for its trade (concrete: the list plus the concrete volume, each step
    written out so a person can check it by hand; electrical: the devices the AI counted). A run for a trade the
    auto-run doesn't know returns None - it is shown without results, never crashed on."""
    strategy = STRATEGIES.get(row.get("module_id"))
    if strategy is None:
        return None
    return strategy["results"](conn, ctx, row)


def concrete_results(conn, ctx, row: dict) -> dict | None:
    """What a finished concrete run measured, as a list to show, plus the concrete it adds up to,
    each step written out so a person can check it by hand (2026-11-15, David):
      slab area      = width x length               (the dimensions the AI read off the plan)
      perimeter      = 2 x (width + length)          (footer and form length)
      slab volume    = area x thickness / 12 / 27    (thickness read off the plan, else the trade's default)
      footer volume  = length x (w x d / 144) / 27   (footer size read off the plan, else 12 x 12 in)
      total          = slab + footer; with waste = total x 1.05 (the Concrete trade's 5%)
    The app does the maths; nothing here is approved."""
    ids = json.loads(row.get("measurement_ids_json") or "[]")
    if not ids:
        return None
    rows = conn.execute(f"SELECT id, label, feeds, qty, unit, status, calc_json, sheet_id, viewport_id FROM measurements"
                        f" WHERE company_id = ? AND id IN ({','.join('?' * len(ids))}) ORDER BY id",
                        (ctx.company_id, *ids)).fetchall()
    lines, area, footer_lf, calc0 = [], Decimal(0), Decimal(0), {}
    slab_row = next((r for r in rows if r["feeds"] == "area_sqft"), None)
    for r in rows:
        try:
            calc = json.loads(r["calc_json"] or "{}")
        except ValueError:
            calc = {}
        calc0 = calc0 or calc
        lines.append({"id": r["id"], "label": r["label"], "feeds": r["feeds"], "qty": r["qty"], "unit": r["unit"],
                      "status": r["status"], "how": calc.get("how")})
        if r["status"] == "rejected":
            continue
        if r["feeds"] == "area_sqft":
            area += Decimal(str(r["qty"] or 0))
        elif r["feeds"] == "footing_lf":
            footer_lf += Decimal(str(r["qty"] or 0))
    # 2026-11-15 (David): the footer only adds what's BELOW the slab (the slab is measured to its outside edge), less
    # the ledge notch, along the footer's middle line. See takeoff/footer_section.py; the section was read off the
    # footer detail and checked by the AI, or a person corrected it. Older runs fall back to the footer size note.
    from estimator.takeoff import footer_section as fs
    sec = calc0.get("footer_section") or fs.from_read(None, calc0.get("footer_size"), calc0.get("slab_thickness"))
    perimeter = calc0.get("perimeter_lf")
    if perimeter is None:                   # runs before 2026-11-15 measured the footer along the outside perimeter
        perimeter = str(footer_lf)
    worked = fs.compute(sec, perimeter)
    thickness = Decimal(str(sec.get("slab_in") or 4))
    t_from = (sec.get("from") or {}).get("slab_in") or "the Concrete trade's default (4 in)"
    q2 = lambda v: str(Decimal(v).quantize(Decimal("0.01")))  # noqa: E731
    # Each step is rounded to 0.01 before the next uses it, so the written formulas add up exactly by hand.
    slab_cy = Decimal(q2(area * thickness / 12 / 27))
    footer_cy = Decimal(worked["cuyd"]) if footer_lf else Decimal(0)
    total = slab_cy + footer_cy
    waste = Decimal(q2(total * Decimal("1.05")))
    concrete = None
    if area or footer_lf:
        steps = []
        w, ln = calc0.get("slab_width"), calc0.get("slab_length")
        slab_adj = list(calc0.get("slab_adjust") or [])
        if w and ln:
            drawn = "".join(f" {'+' if a['sign'] > 0 else '-'} {a['sqft']} sq ft ({a['label']})" for a in slab_adj)
            base = f" ({_n(_slab_base(calc0, rows))} sq ft)" if slab_adj else ""
            steps.append({"what": "Slab area", "formula": f"{w} x {ln}{base}{drawn}", "result": f"{_n(area)} sq ft",
                          "note": "the slab's dimensions as the AI read them off the plan, to the slab's outside edge"
                                  + ("; plus / less the areas drawn on the plan" if slab_adj else "")})
            steps.append({"what": "Slab perimeter", "formula": f"2 x ({w} + {ln})", "result": f"{q2(perimeter)} lf",
                          "note": "the forms run around the outside edge"})
        steps.append({"what": "Slab concrete",
                      "formula": f"{_n(area)} sq ft x {fs._n(thickness)} in ÷ 12 ÷ 27",
                      "result": f"{q2(slab_cy)} cu yd",
                      "note": f"thickness {fs._n(thickness)} in ({t_from}); it runs to the outside edge, over the"
                              " footer; ÷ 12 turns inches into feet, ÷ 27 turns cubic feet into cubic yards"})
        if footer_lf:
            steps += worked["steps"]
        steps.append({"what": "Total concrete", "formula": f"{q2(slab_cy)} + {q2(footer_cy)}",
                      "result": f"{q2(total)} cu yd", "note": "slab plus the footer below it"})
        steps.append({"what": "Order with waste", "formula": f"{q2(total)} x 1.05", "result": f"{q2(waste)} cu yd",
                      "note": "the Concrete trade's 5% waste"})
        section = {k: sec.get(k) for k in fs.FIELDS}
        concrete = {"thickness_in": q2(thickness), "thickness_from": t_from, "slab_cuyd": q2(slab_cy),
                    "footer_size": calc0.get("footer_size") or None, "footer_section": section,
                    "footer_from": sec.get("from") or {}, "inside_slope": bool(sec.get("inside_slope")),
                    "footer_below_slab_in": worked["below_slab_in"], "footer_section_sqin": worked["section_sqin"],
                    "footer_lf": worked["length_lf"] if footer_lf else "0.00", "footer_cuyd": q2(footer_cy),
                    "footer_check": calc0.get("footer_check"), "footer_read": calc0.get("footer_read"),
                    "footer_error": calc0.get("footer_error"),
                    "total_cuyd": q2(total), "with_waste_cuyd": q2(waste), "steps": steps}
        _add_shapes(conn, ctx, concrete, calc0, sec, slab_row, slab_adj)
    return {"lines": lines, "concrete": concrete}


# ------------------------------------------------------------------ per-trade strategies (multi-trade auto-run, Phase 1)
#
# Each trade the auto-run knows how to run: its display name, which sheet and view to measure, how to find
# candidates on the drawing, how to shape its finished results, and what to say when the AI can't run.
# Concrete keeps its Phase 1 behaviour exactly; electrical has no geometric detection (the symbols on an
# electrical sheet are unclassified, so there is nothing to count from the drawing) and is LLM-only.
# The thirteen quantity trades below are LLM-only too: each reads its own sheet with the AI and proposes
# the quantities its manifest asks for (counts, areas, lengths), through the shared flow in
# takeoff/llm_quantities.py. Their results are shaped by their own reader module, imported lazily.


def _trade_label(module_id: str) -> str:
    """The trade's display name from its manifest, else the module id as given."""
    try:
        from estimator.modules import get_registry
        return get_registry().get(module_id).name
    except Exception:  # noqa: BLE001 - no manifest, no registry: the id is the name
        return module_id


def _concrete_viewport(conn, sheet_id: int) -> int | None:
    """The slab plan's view on the sheet (llm_takeoff's pick: the foundation/slab view, else the biggest)."""
    from estimator.takeoff import llm_takeoff
    return llm_takeoff._slab_viewport(conn, sheet_id)


def _first_viewport(conn, sheet_id: int) -> int | None:
    """The first viewport on the sheet, by id: an electrical sheet's plan view."""
    row = conn.execute("SELECT id FROM viewports WHERE sheet_id = ? ORDER BY id LIMIT 1",
                       (int(sheet_id),)).fetchone()
    return row["id"] if row is not None else None


def _slab_candidates(conn, company_id: str, viewport_id: int) -> dict:
    """The slab rectangles on the viewport, biggest first (concrete's geometric detection)."""
    from estimator.takeoff import slab_find
    return slab_find.find_slab_candidates(conn, company_id, viewport_id)


def _no_candidates(conn, company_id: str, viewport_id: int) -> dict:
    """No geometric candidates: the LLM-only trades have no drawing detection to run."""
    return {"candidates": []}


def electrical_results(conn, ctx, row: dict) -> dict | None:
    """An electrical run's results, shaped by the electrical reader (imported lazily, as llm_takeoff is,
    so this module loads before that file lands)."""
    from estimator.takeoff import llm_electrical
    return llm_electrical.electrical_results(conn, ctx, row)


def _trade_results(conn, ctx, row: dict, module_id: str) -> dict | None:
    """A quantity trade's results, shaped by its reader (imported lazily, as llm_takeoff is,
    so this module loads before that file lands)."""
    import importlib
    mod = importlib.import_module(f"estimator.takeoff.llm_{module_id}")
    return getattr(mod, f"{module_id}_results")(conn, ctx, row)


STRATEGIES = {
    "concrete": {
        "label": "Concrete",
        "sheet_phrase": "the foundation sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "concrete"),
        "pick_viewport": _concrete_viewport,
        "find_candidates": _slab_candidates,
        "results": concrete_results,
        "geometric": True,            # the drawing-only agent is the fallback when the AI can't run
        "llm_off": ("No slab outline found on this sheet — the AI did not run because AI measuring is off. "
                    "Turn it on in 🤖 AI agents (Setup) to let the AI read the plan, or measure the slab manually."),
    },
    "electrical": {
        "label": "Electrical",
        "sheet_phrase": "the electrical sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "electrical"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": electrical_results,
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("electrical auto-run reads the plan with the AI — turn AI measuring on in 🤖 AI agents (Setup)"
                    " to let it count the devices, or count them manually."),
    },

    "plumbing": {
        "label": "Plumbing",
        "sheet_phrase": "the plumbing sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "plumbing"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "plumbing"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("plumbing auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it count the fixtures, or count them manually."),
    },
    "hvac": {
        "label": "HVAC",
        "sheet_phrase": "the mechanical sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "hvac"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "hvac"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("HVAC auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the mechanical plan, or measure it manually."),
    },
    "flooring": {
        "label": "Flooring",
        "sheet_phrase": "the floor plan sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "flooring"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "flooring"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("flooring auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the floor areas, or measure them manually."),
    },
    "roofing": {
        "label": "Roofing",
        "sheet_phrase": "the roof plan sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "roofing"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "roofing"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("roofing auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the roof plan, or measure it manually."),
    },
    "framing": {
        "label": "Framing",
        "sheet_phrase": "the framing sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "framing"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "framing"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("framing auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the framing plan, or measure it manually."),
    },
    "windows_doors": {
        "label": "Windows and Doors",
        "sheet_phrase": "the window and door sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "windows_doors"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "windows_doors"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("windows and doors auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it count the windows and doors, or count them manually."),
    },
    "insulation": {
        "label": "Insulation",
        "sheet_phrase": "the insulation sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "insulation"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "insulation"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("insulation auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the insulated areas, or measure them manually."),
    },
    "demolition": {
        "label": "Demolition",
        "sheet_phrase": "the demolition sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "demolition"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "demolition"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("demolition auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the demolition plan, or measure it manually."),
    },
    "drywall": {
        "label": "Drywall",
        "sheet_phrase": "the drywall sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "drywall"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "drywall"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("drywall auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the wall and ceiling areas, or measure them manually."),
    },
    "siding": {
        "label": "Siding",
        "sheet_phrase": "the elevations sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "siding"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "siding"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("siding auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the outside walls, or measure them manually."),
    },
    "fencing": {
        "label": "Fencing",
        "sheet_phrase": "the site plan sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "fencing"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "fencing"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("fencing auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the fence line, or measure it manually."),
    },
    "landscaping": {
        "label": "Landscaping",
        "sheet_phrase": "the landscape sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "landscaping"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "landscaping"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("landscaping auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the landscape plan, or measure it manually."),
    },
    "painting": {
        "label": "Painting",
        "sheet_phrase": "the finish sheet",
        "pick_sheet": lambda conn, ctx, estimate_id: pick_run_sheet(conn, ctx, estimate_id, "painting"),
        "pick_viewport": _first_viewport,
        "find_candidates": _no_candidates,
        "results": lambda conn, ctx, row: _trade_results(conn, ctx, row, "painting"),
        "geometric": False,           # LLM-only: no drawing detection, so no geometric fallback
        "llm_off": ("painting auto-run reads the plan with the AI \u2014 turn AI measuring on in \U0001f916 AI agents (Setup)"
                    " to let it read the areas to paint, or measure them manually."),
    },
}


# Which shapes each formula row highlights on the drawing (2026-11-16, David).
# "@parts" are the footer section's parts on its detail once a person placed it there; until then the detail's frame.
STEP_SHAPES = {"Slab area": ["slab", "+slab"], "Slab perimeter": ["forms"], "Slab concrete": ["slab", "+slab"],
               "Footer depth below the slab": ["@part:below", "@part:slab"],
               "Footer cross-section": ["@part:below", "@part:slab", "@part:ledge", "@part:haunch", "+footer"],
               "Footer length (middle line)": ["footer_middle", "footer"], "Footer concrete": ["footer"],
               "Total concrete": ["slab", "footer"], "Order with waste": ["slab", "footer"]}


def _add_shapes(conn, ctx, concrete: dict, calc0: dict, sec: dict, slab_row, slab_adj: list) -> None:
    """Put the run's shapes on its results: where the slab, footer, forms and footer detail are on the sheet, and the
    areas a person drew - worked out from the plan as it is now (so a run from before 2026-11-16 gets them too, and a
    new calibration moves them). Each formula row lists the shapes it highlights."""
    from estimator.takeoff import takeoff_shapes as ts
    shapes, fit = {}, None
    if slab_row is not None:
        w_in = slab_find_inches(calc0.get("slab_width"))
        l_in = slab_find_inches(calc0.get("slab_length"))
        try:
            got = ts.shapes_for(conn, ctx.company_id, slab_row["sheet_id"], slab_row["viewport_id"], w_in, l_in,
                                sec.get("width_in"))
        except Exception:  # noqa: BLE001 - a shape is a convenience; the numbers never depend on it
            got = {}
        fit = got.pop("slab_fit", None)
        shapes.update(got)
    drawn = []
    for a in list(sec.get("adjust") or []) + list(slab_adj):
        key = "adj:" + str(a.get("id"))
        shapes[key] = {"sheet_id": a.get("sheet_id"), "viewport_id": a.get("viewport_id"), "type": "polygon",
                       "points": a.get("points") or [], "sign": a.get("sign", 1)}
        drawn.append({"id": a.get("id"), "key": key, "target": a.get("target"), "sign": a.get("sign", 1),
                      "label": a.get("label"), "view": a.get("view"),
                      "amount": f"{a['sqin']} sq in" if a.get("target") == "footer" else f"{a.get('sqft')} sq ft"})
    # The footer section's parts on its detail (2026-11-16): drawn to the detail's scale from where a person placed it.
    from estimator.takeoff import slab_find
    det = shapes.get("detail")
    det_vp = conn.execute("SELECT id, label, scale_ratio, is_nts, calibration_json FROM viewports WHERE id = ?",
                          (det["viewport_id"],)).fetchone() if det else None
    det_ratio = slab_find._scale_ratio(det_vp) if det_vp is not None else None
    anchor = sec.get("anchor") or None
    parts = {}
    if anchor and det:
        a_vp = det_vp if anchor.get("viewport_id") in (None, det["viewport_id"]) else conn.execute(
            "SELECT id, scale_ratio, is_nts FROM viewports WHERE id = ?", (anchor["viewport_id"],)).fetchone()
        parts = ts.section_parts(sec, slab_find._scale_ratio(a_vp) if a_vp is not None else None, det["sheet_id"])
        shapes.update({"part:" + k: v for k, v in parts.items()})
    for s in concrete["steps"]:
        keys = []
        for k in STEP_SHAPES.get(s["what"], []):
            if k.startswith("+"):
                keys += [d["key"] for d in drawn if d["target"] == k[1:]]
            elif k.startswith("@"):
                if k[1:] in shapes:
                    keys.append(k[1:])
            elif k in shapes:
                keys.append(k)
        if s["what"] in ("Footer depth below the slab", "Footer cross-section") and not parts and "detail" in shapes:
            keys.insert(0, "detail")                    # not placed yet: the detail's frame
        s["shapes"] = keys
    concrete["shapes"] = shapes
    concrete["slab_fit"] = fit
    concrete["drawn_areas"] = drawn
    if det:
        try:
            cal = json.loads(det_vp["calibration_json"] or "null") if det_vp is not None else None
        except (TypeError, ValueError, IndexError):
            cal = None
        concrete["detail"] = {"viewport_id": det["viewport_id"], "sheet_id": det["sheet_id"],
                              "label": det_vp["label"] if det_vp is not None else None, "scaled": bool(det_ratio),
                              "scale_ratio": det_ratio, "placed": bool(parts), "anchor": anchor,
                              "calibration": {k: cal.get(k) for k in ("status", "reason") if cal.get(k)}
                              if isinstance(cal, dict) else None}


def slab_find_inches(text):
    from estimator.takeoff import slab_find
    try:
        return slab_find.parse_feet_inches(text) if text else None
    except (TypeError, ValueError):
        return None


def edit_footer(conn, ctx, run_id: int, values: dict, confirm: bool = False) -> dict:
    """A person corrects the footer section (inches): the run's footer length and cross-section measurements are
    worked out again from their numbers. Asks first; approved (locked) measurements are never changed."""
    from estimator.errors import ConfirmationRequired, InvalidInput
    from estimator.estimating import service
    from estimator.takeoff import footer_section as fs
    from estimator.takeoff import measurements as ms
    _role(ctx, ms.PROPOSE_ROLES, "correct the footer")
    row = _load_run(conn, ctx, run_id)
    ids = json.loads(row.get("measurement_ids_json") or "[]")
    rows = [dict(r) for r in conn.execute(
        f"SELECT id, feeds, qty, status, calc_json FROM measurements WHERE company_id = ? AND id IN"
        f" ({','.join('?' * len(ids))}) ORDER BY id", (ctx.company_id, *ids))] if ids else []
    if not rows:
        raise InvalidInput("this run has no measurements to correct", run_id=run_id)
    if any(r["status"] == "approved" and r["feeds"] in ("footing_lf", "footing_section_sqft") for r in rows):
        raise InvalidInput("the footer measurements are approved and locked; they can't be changed", run_id=run_id)
    calc0 = json.loads(rows[0]["calc_json"] or "{}")
    sec = calc0.get("footer_section") or fs.from_read(None, calc0.get("footer_size"), calc0.get("slab_thickness"))
    try:
        new = fs.edit(sec, values or {})
    except ValueError as exc:
        raise InvalidInput(str(exc), field="footer") from None
    perimeter = calc0.get("perimeter_lf")
    if perimeter is None:
        perimeter = next((r["qty"] for r in rows if r["feeds"] == "perimeter_lf"), None) \
            or next((r["qty"] for r in rows if r["feeds"] == "footing_lf"), "0")
    worked = fs.compute(new, perimeter)
    if not confirm:
        raise ConfirmationRequired(
            f"Change the footer to {worked['steps'][1]['formula']} = {worked['section_sqin']} sq in, along"
            f" {worked['length_lf']} lf ({worked['cuyd']} cu yd)? Call again with confirm=true.",
            run_id=run_id, section_sqin=worked["section_sqin"], cuyd=worked["cuyd"])
    with service.transaction(conn):
        _save_footer(conn, ctx, row, rows, ids, new, perimeter, worked)
        service._log(conn, ctx, row["estimate_id"], "footer_corrected",
                     {"run_id": run_id, "section": {k: new.get(k) for k in fs.FIELDS},
                      "section_sqin": worked["section_sqin"], "cuyd": worked["cuyd"]},
                     before={k: sec.get(k) for k in fs.FIELDS})
    fresh = _load_run(conn, ctx, run_id)
    return {"run_id": run_id, "results": run_results(conn, ctx, fresh)}


def _save_footer(conn, ctx, row: dict, rows: list[dict], ids: list, new: dict, perimeter, worked: dict) -> None:
    """Write a new footer section into the run's measurements (inside the caller's transaction): the footer length and
    cross-section are worked out again; approved measurements keep their quantity."""
    run_id = row["id"]
    now = _now()
    for r in rows:
        c = json.loads(r["calc_json"] or "{}")
        c["footer_section"] = new
        c["perimeter_lf"] = str(perimeter)
        qty = r["qty"]
        if r["status"] != "approved" and r["feeds"] == "footing_lf":
            qty = worked["length_lf"]
            c["how"] = f"footer length along its middle = {worked['steps'][2]['formula']}"
        elif r["status"] != "approved" and r["feeds"] == "footing_section_sqft":
            qty = worked["section_sqft"]
            c["how"] = f"footer below the slab: {worked['steps'][1]['formula']} = {worked['section_sqin']} sq in"
        c["qty"] = qty
        conn.execute("UPDATE measurements SET qty = ?, calc_json = ?, updated_at = ? WHERE id = ?",
                     (qty, json.dumps(c), now, r["id"]))
    # A run from before 2026-11-15 has no cross-section measurement: add it, so the price uses this footer too.
    if not any(r["feeds"] == "footing_section_sqft" for r in rows):
        src = next((r for r in rows if r["feeds"] == "footing_lf"), rows[0])
        base = dict(conn.execute("SELECT * FROM measurements WHERE id = ?", (src["id"],)).fetchone())
        c = {**json.loads(base["calc_json"] or "{}"), "footer_section": new, "perimeter_lf": str(perimeter),
             "qty": worked["section_sqft"],
             "how": f"footer below the slab: {worked['steps'][1]['formula']} = {worked['section_sqin']} sq in"}
        mid = conn.execute(
            "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label,"
            " qty, unit, source_object_ids, calc_json, method, confidence, status, locked, proposed_by, created_at,"
            " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,'[]',?,?,?,'proposed',0,?,?,?)",
            (ctx.company_id, base["estimate_id"], base["module_id"], "footing_section_sqft", base["sheet_id"],
             base["viewport_id"], "area", "Footer cross-section (AI)", worked["section_sqft"], "sqft/lf",
             json.dumps(c), base["method"], base["confidence"], base["proposed_by"], now, now)).lastrowid
        conn.execute("UPDATE auto_runs SET measurement_ids_json = ? WHERE id = ?",
                     (json.dumps(ids + [mid]), run_id))


# ------------------------------------------------------------------ areas a person adds or takes away (2026-11-16)

ADJUST_TARGETS = {"footer": "the footer cross-section", "slab": "the slab area"}


def _run_rows(conn, ctx, row: dict) -> tuple[list, list[dict]]:
    ids = json.loads(row.get("measurement_ids_json") or "[]")
    rows = [dict(r) for r in conn.execute(
        f"SELECT id, feeds, qty, status, calc_json, sheet_id, viewport_id FROM measurements WHERE company_id = ? AND id IN"
        f" ({','.join('?' * len(ids))}) ORDER BY id", (ctx.company_id, *ids))] if ids else []
    return ids, rows


def _sign(v) -> int | None:
    if v in (1, "1", "+1", "+", "add"):
        return 1
    if v in (-1, "-1", "-", "subtract"):
        return -1
    return None


def _slab_base(calc0: dict, rows: list[dict]) -> Decimal:
    """The slab area before any drawn areas: as the AI's dimensions give it."""
    if calc0.get("area_read") not in (None, ""):
        return Decimal(str(calc0["area_read"]))
    slab = next((r for r in rows if r["feeds"] == "area_sqft"), None)
    return Decimal(str(slab["qty"] if slab else 0))


def place_section(conn, ctx, run_id: int, body: dict) -> dict:
    """Put the footer section on its detail (2026-11-16, David): where its bottom outside corner is (a point a person
    clicked on the sheet) and which way the inside is (dir +1 = to the right on the sheet, -1 = to the left). Only where
    the parts are drawn changes - no quantity - so it doesn't ask first. {"clear": true} takes it off again."""
    from estimator.errors import InvalidInput
    from estimator.estimating import service
    from estimator.takeoff import footer_section as fs
    from estimator.takeoff import measurements as ms
    _role(ctx, ms.PROPOSE_ROLES, "place the footer section")
    row = _load_run(conn, ctx, run_id)
    _, rows = _run_rows(conn, ctx, row)
    if not rows:
        raise InvalidInput("this run has no measurements", run_id=run_id)
    anchor = None
    if not body.get("clear"):
        try:
            vp = conn.execute("SELECT v.id, p.estimate_id FROM viewports v JOIN sheets s ON s.id = v.sheet_id"
                              " JOIN plan_sets p ON p.id = s.plan_set_id WHERE v.id = ? AND v.company_id = ?",
                              (int(body.get("viewport_id")), ctx.company_id)).fetchone()
        except (TypeError, ValueError):
            vp = None
        if vp is None or vp["estimate_id"] != row["estimate_id"]:
            raise InvalidInput("click the footer's corner inside the footer detail", field="viewport_id")
        try:
            point = [round(float(body["point"][0]), 4), round(float(body["point"][1]), 4)]
        except (KeyError, TypeError, ValueError, IndexError):
            raise InvalidInput("point must be [x, y] on the sheet", field="point") from None
        anchor = {"viewport_id": vp["id"], "point": point, "dir": 1 if _sign(body.get("dir", 1)) != -1 else -1}
    now = _now()
    with service.transaction(conn):
        for r in rows:
            c = json.loads(r["calc_json"] or "{}")
            sec = c.get("footer_section") or fs.from_read(None, c.get("footer_size"), c.get("slab_thickness"))
            sec = {k: v for k, v in sec.items() if k != "anchor"}
            if anchor:
                sec["anchor"] = anchor
            c["footer_section"] = sec
            conn.execute("UPDATE measurements SET calc_json = ?, updated_at = ? WHERE id = ?", (json.dumps(c), now, r["id"]))
        service._log(conn, ctx, row["estimate_id"], "footer_section_placed", {"run_id": run_id, "anchor": anchor})
    return {"run_id": run_id, "results": run_results(conn, ctx, _load_run(conn, ctx, run_id))}


def adjust_area(conn, ctx, run_id: int, body: dict, confirm: bool = False) -> dict:
    """Add an area a person drew (3+ points on the drawing) to the footer cross-section or the slab area, take one away,
    or remove one they drew before (body["remove"] = its id). The area comes from the scale of the view it was drawn
    in - a footer detail needs its own scale first. Asks first; approved measurements are never changed."""
    from estimator.errors import ConfirmationRequired, InvalidInput
    from estimator.estimating import service
    from estimator.takeoff import footer_section as fs
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import slab_find
    from estimator.takeoff import takeoff_shapes as ts
    _role(ctx, ms.PROPOSE_ROLES, "change the measured areas")
    row = _load_run(conn, ctx, run_id)
    ids, rows = _run_rows(conn, ctx, row)
    if not rows:
        raise InvalidInput("this run has no measurements to change", run_id=run_id)
    calc0 = json.loads(rows[0]["calc_json"] or "{}")
    sec = calc0.get("footer_section") or fs.from_read(None, calc0.get("footer_size"), calc0.get("slab_thickness"))
    footer_adj = list(sec.get("adjust") or [])
    slab_adj = list(calc0.get("slab_adjust") or [])
    remove = body.get("remove")
    if remove:
        old = next((a for a in footer_adj + slab_adj if a.get("id") == str(remove)), None)
        if old is None:
            raise InvalidInput(f"this run has no drawn area '{remove}'", remove=remove)
        target, adj = old["target"], None
    else:
        target = body.get("target")
        if target not in ADJUST_TARGETS:
            raise InvalidInput("target must be 'footer' (the footer cross-section) or 'slab' (the slab area)",
                               field="target")
        sign = _sign(body.get("sign"))
        if sign is None:
            raise InvalidInput("sign must be 'add' or 'subtract'", field="sign")
        try:
            pts = ts.clean_points(body.get("points"))
        except ValueError as exc:
            raise InvalidInput(str(exc), field="points") from None
        try:
            vp = conn.execute("SELECT v.*, p.estimate_id FROM viewports v JOIN sheets s ON s.id = v.sheet_id"
                              " JOIN plan_sets p ON p.id = s.plan_set_id WHERE v.id = ? AND v.company_id = ?",
                              (int(body.get("viewport_id")), ctx.company_id)).fetchone()
        except (TypeError, ValueError):
            vp = None
        if vp is None or vp["estimate_id"] != row["estimate_id"]:
            raise InvalidInput("draw the area inside a view of this project's plans", field="viewport_id")
        name = vp["label"] or "that view"
        ratio = slab_find._scale_ratio(vp)
        if not ratio:
            raise InvalidInput(f"{name} has no scale yet, so the area you drew has no real size - calibrate it first"
                               " (🤖 Auto-calibrate, or 📏 Calibrate on one of its written dimensions)",
                               field="viewport_id", viewport_id=vp["id"])
        sqin = ts.area_sqin(pts, ratio)
        n = max([int(str(a.get("id", "a0"))[1:] or 0) for a in footer_adj + slab_adj if str(a.get("id", "")).startswith("a")]
                + [0]) + 1
        label = str(body.get("label") or "").strip()[:60] or ("added area" if sign > 0 else "taken-away area")
        adj = {"id": f"a{n}", "target": target, "sign": sign, "label": label, "sheet_id": vp["sheet_id"],
               "viewport_id": vp["id"], "points": pts, "scale_ratio": ratio, "view": name, "at": _now(),
               "by": ctx.user_id}
        if target == "footer":
            adj["sqin"] = str(Decimal(str(sqin)).quantize(Decimal("0.01")))
        else:
            adj["sqft"] = str((Decimal(str(sqin)) / 144).quantize(Decimal("0.01")))
    locked = ("footing_lf", "footing_section_sqft") if target == "footer" else ("area_sqft",)
    if any(r["status"] == "approved" and r["feeds"] in locked for r in rows):
        raise InvalidInput(f"{ADJUST_TARGETS[target]} is approved and locked; it can't be changed", run_id=run_id)
    verb = (("Remove" if remove else "Add" if adj["sign"] > 0 else "Take away"))
    what = old if remove else adj
    amount = f"{what['sqin']} sq in" if target == "footer" else f"{what['sqft']} sq ft"
    if target == "footer":
        new_list = [a for a in footer_adj if a.get("id") != str(remove)] if remove else footer_adj + [adj]
        new_sec = {**sec, "adjust": new_list}
        perimeter = calc0.get("perimeter_lf")
        if perimeter is None:
            perimeter = next((r["qty"] for r in rows if r["feeds"] == "perimeter_lf"), None) \
                or next((r["qty"] for r in rows if r["feeds"] == "footing_lf"), "0")
        worked = fs.compute(new_sec, perimeter)
        if Decimal(worked["section_sqin"]) <= 0:
            raise InvalidInput("that would leave no footer cross-section", run_id=run_id)
        result = (f"the footer cross-section becomes {worked['steps'][1]['formula']} = {worked['section_sqin']} sq in"
                  f" ({worked['cuyd']} cu yd of footer)")
    else:
        new_list = [a for a in slab_adj if a.get("id") != str(remove)] if remove else slab_adj + [adj]
        base = _slab_base(calc0, rows)
        new_area = (base + sum((Decimal(a["sqft"]) * a["sign"] for a in new_list), Decimal(0))).quantize(Decimal("0.01"))
        if new_area <= 0:
            raise InvalidInput("that would leave no slab area", run_id=run_id)
        result = f"the slab area becomes {_n(new_area)} sq ft"
    if not confirm:
        prep = " to " if not remove and adj["sign"] > 0 else " from "
        raise ConfirmationRequired(
            f"{verb} {amount} ({what['label']}){prep}{ADJUST_TARGETS[target]}? Then {result}."
            " Call again with confirm=true.", run_id=run_id, target=target, amount=amount)
    now = _now()
    with service.transaction(conn):
        if target == "footer":
            _save_footer(conn, ctx, row, rows, ids, new_sec, perimeter, worked)
        else:
            for r in rows:
                c = json.loads(r["calc_json"] or "{}")
                c["slab_adjust"] = new_list
                c["area_read"] = str(base)
                qty = r["qty"]
                if r["feeds"] == "area_sqft" and r["status"] != "approved":
                    qty = str(new_area)
                    c["qty"] = qty
                    c["how"] = (f"slab area from the dimensions the AI read ({c.get('slab_width')} x"
                                f" {c.get('slab_length')} = {base} sq ft)"
                                + "".join(f" {'+' if a['sign'] > 0 else '-'} {a['sqft']} sq ft ({a['label']})"
                                          for a in new_list))
                conn.execute("UPDATE measurements SET qty = ?, calc_json = ?, updated_at = ? WHERE id = ?",
                             (qty, json.dumps(c), now, r["id"]))
        service._log(conn, ctx, row["estimate_id"], "area_removed" if remove else "area_adjusted",
                     {"run_id": run_id, "target": target, "id": what["id"], "sign": what["sign"], "amount": amount,
                      "label": what["label"]})
    fresh = _load_run(conn, ctx, run_id)
    return {"run_id": run_id, "results": run_results(conn, ctx, fresh)}


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


def mark_agent_scale(conn, ctx, viewport_id: int, auto_run_id: int) -> dict:
    """Stamp the calibration the agent just made in the page as the agent's (2026-11-13, David).

    The agent calibrates through Blueprint Review's own Calibrate tool, signed in as the person who started it,
    so the scale was recorded as set by that person and nothing said the agent had done it. Only the run's own
    viewport, only a calibration, and only one made after the run started can be stamped."""
    from estimator.errors import InvalidInput
    from estimator.estimating import service
    run = _load_run(conn, ctx, int(auto_run_id))
    if int(run["viewport_id"]) != int(viewport_id):
        raise InvalidInput(f"run {auto_run_id} measures another viewport", viewport_id=viewport_id)
    vp = conn.execute("SELECT * FROM viewports WHERE id = ? AND company_id = ?",
                      (int(viewport_id), ctx.company_id)).fetchone()
    if vp is None or vp["scale_method"] != "calibration" or (vp["scale_set_at"] or "") < (run["created_at"] or ""):
        raise InvalidInput("that viewport wasn't calibrated during this run", viewport_id=viewport_id)
    with service.transaction(conn):
        conn.execute("UPDATE viewports SET scale_set_by = ? WHERE id = ?", (AGENT, vp["id"]))
        service._log(conn, ctx, run["estimate_id"], "scale_calibrated_by_agent",
                     {"run_id": run["id"], "viewport_id": vp["id"], "scale_ratio": vp["scale_ratio"]})
    return {"viewport_id": vp["id"], "scale_ratio": vp["scale_ratio"], "scale_set_by": AGENT}


def run_scale(conn, ctx, run: dict) -> dict | None:
    """The scale a run measured with, and who set it - so the page can say "the agent calibrated the sheet" or
    "used the scale the owner calibrated on Nov 11" instead of leaving it unsaid."""
    vp = conn.execute("SELECT scale_ratio, scale_method, scale_set_by, scale_set_at, is_nts FROM viewports"
                      " WHERE id = ? AND company_id = ?", (run["viewport_id"], ctx.company_id)).fetchone()
    if vp is None or not vp["scale_ratio"]:
        return None
    by = vp["scale_set_by"] or ("the plan's scale note" if vp["scale_method"] == "note" else None)
    return {"scale_ratio": vp["scale_ratio"], "method": vp["scale_method"], "set_by": by,
            "set_at": vp["scale_set_at"], "by_agent": vp["scale_set_by"] in (AGENT, LLM_AGENT, "auto-calibrator"),
            "during_run": bool(vp["scale_set_at"]) and vp["scale_set_at"] >= (run["created_at"] or "")}


# ------------------------------------------------------------------ routes

def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _body, _fail, _int_opt, _ok
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import slab_find

    if not nav.can_open(ctx.role, "takeoffs"):
        raise _refuse("your role can't open the Measure screen", 403, "permission_denied")

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
        _role(ctx, ms.PROPOSE_ROLES, "run the measuring agent")
        b = _body(req)
        estimate_id = _int_opt(b.get("estimate_id"))
        sheet_id = _int_opt(b.get("sheet_id"))
        viewport_id = _int_opt(b.get("viewport_id"))
        if estimate_id is None:
            raise _refuse("say which estimate to measure (estimate_id)")
        module_id = str(b.get("module_id") or "").strip()
        if not module_id:
            raise _refuse("say which trade to run (module_id)")
        if module_id not in STRATEGIES:
            raise _refuse(f"auto-run isn't built for {_trade_label(module_id)} yet")
        strategy = STRATEGIES[module_id]
        from estimator.estimating import service
        service.get_estimate(conn, ctx, estimate_id)          # not found / another company's estimate
        # 2026-11-15 (David): AI Auto Measure/Count runs on the sheets switched ON for the trade. With no sheet named (or the
        # open sheet switched off), it picks the best sheet for the trade that is on, and the trade's view on it.
        if sheet_id is None or not _sheet_on(conn, ctx, sheet_id, module_id):
            sheet_id = strategy["pick_sheet"](conn, ctx, estimate_id)
            viewport_id = None
        if viewport_id is None:
            viewport_id = strategy["pick_viewport"](conn, sheet_id)
            if viewport_id is None:
                raise _refuse("that sheet has no view to measure — read the plans again on the Plans screen")
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
        if not _sheet_on(conn, ctx, sheet_id, module_id):
            raise _refuse(f"this sheet is switched off for {strategy['label']} — switch it back on from the Plans screen"
                          " to run the agent")
        busy = conn.execute("SELECT id FROM auto_runs WHERE company_id = ? AND estimate_id = ?"
                            " AND viewport_id = ? AND module_id = ? AND status = 'running'",
                            (ctx.company_id, estimate_id, viewport_id, module_id)).fetchone()
        if busy is not None:
            raise _refuse("an auto-run is already going for this viewport; wait for it to finish")
        found = strategy["find_candidates"](conn, ctx.company_id, viewport_id)
        run_id = create_run(conn, ctx, estimate_id, sheet_id, viewport_id, module_id, found["candidates"],
                            keep_approved=_keep_approved(b))
        return _start_run(conn, ctx, run_id, found["candidates"], module_id)

    if _RUNS.match(sub) and m == "GET":
        # 2026-11-15 (David): the latest run on a sheet, so Blueprint Review shows a run that is still going (and
        # keeps watching it) or the last run's results after the page is reloaded or opened again later.
        estimate_id = _int_opt(req.query.get("estimate_id"))
        sheet_id = _int_opt(req.query.get("sheet_id"))
        if estimate_id is None:
            raise _refuse("say which estimate (estimate_id)")
        sql, args = "SELECT * FROM auto_runs WHERE company_id = ? AND estimate_id = ?", [ctx.company_id, estimate_id]
        if sheet_id is not None:
            sql += " AND sheet_id = ?"
            args.append(sheet_id)
        row = conn.execute(sql + " ORDER BY id DESC LIMIT 1", args).fetchone()
        if row is None:
            return _ok(run=None)
        row = dict(row)
        return _ok(run={**_shape_run(row), "scale": run_scale(conn, ctx, row),
                        "results": run_results(conn, ctx, row) if row["status"] == "done" else None})

    mm = _FOOTER.match(sub)
    if mm and m == "POST":
        b = _body(req)
        return _ask(lambda: edit_footer(conn, ctx, int(mm.group(1)), b.get("section") or {},
                                        confirm=b.get("confirm") is True))

    mm = _ADJUST.match(sub)
    if mm and m == "POST":
        b = _body(req)
        return _ask(lambda: adjust_area(conn, ctx, int(mm.group(1)), b, confirm=b.get("confirm") is True))

    mm = _PLACE.match(sub)
    if mm and m == "POST":
        return _ok(**place_section(conn, ctx, int(mm.group(1)), _body(req)))

    mm = _RUN_ONE.match(sub)
    if mm and m == "GET":
        row = _load_run(conn, ctx, int(mm.group(1)))
        return _ok(run={**_shape_run(row), "scale": run_scale(conn, ctx, row),
                        "results": run_results(conn, ctx, row) if row["status"] == "done" else None})

    mm = _VP_MARK.match(sub)
    if mm and m == "POST":
        _role(ctx, ms.PROPOSE_ROLES, "mark an agent calibration")
        auto_run_id = _int_opt(_body(req).get("auto_run_id"))
        if auto_run_id is None:
            raise _refuse("say which auto-run calibrated this viewport (auto_run_id)")
        return _ok(**mark_agent_scale(conn, ctx, int(mm.group(1)), auto_run_id))

    mm = _VP_AUTOCAL.match(sub)
    if mm and m == "POST":
        # 2026-11-13: calibrate from the written dimensions, or say a person must (and why). Asks before replacing a
        # scale the view already has. auto_run_id: the run that asked (its person started it).
        from estimator.takeoff import auto_calibrate
        b = _body(req)
        run = None
        rid = _int_opt(b.get("auto_run_id"))
        if rid is not None:
            run = _load_run(conn, ctx, rid)
            if int(run["viewport_id"]) != int(mm.group(1)):
                raise _refuse(f"run {rid} measures another viewport")
        return _ask(lambda: auto_calibrate.auto_calibrate(conn, ctx, int(mm.group(1)), confirm=bool(b.get("confirm")),
                                                          run=run))

    mm = _RERUN.match(sub)
    if mm and m == "POST":
        _role(ctx, ms.PROPOSE_ROLES, "re-run the measuring agent")
        from estimator.estimating import service
        old = _load_run(conn, ctx, int(mm.group(1)))
        if old["status"] == "running":
            raise _refuse("that run is still going; wait for it to finish before re-running it")
        if old["module_id"] not in STRATEGIES:
            raise _refuse(f"auto-run isn't built for {_trade_label(old['module_id'])} yet")
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
        found = STRATEGIES[old["module_id"]]["find_candidates"](conn, ctx.company_id, old["viewport_id"])
        with service.transaction(conn):
            for mid in doomed:
                conn.execute("DELETE FROM measurements WHERE id = ?", (mid,))
            service._log(conn, ctx, old["estimate_id"], "auto_run_rerun",
                         {"run_id": old["id"], "deleted_measurement_ids": doomed})
            new_id = create_run(conn, ctx, old["estimate_id"], old["sheet_id"], old["viewport_id"],
                                old["module_id"], found["candidates"], keep_approved=_keep_approved(_body(req)))
        return _start_run(conn, ctx, new_id, found["candidates"], old["module_id"])

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

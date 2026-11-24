"""AI design jobs (2026-11-21, David: "can we add that option in the Measure where a user can type in a command like here's
my shed drawings, I want to add electricity to it, design me the lighting and receptacles ... it uses the API key").

One design per project and trade, kept in the data folder (design/estimate_<id>/<trade>.json, with each revision's
drawings beside it) - the same way the wiring run keeps its results:

    start    the person's request (+ their specs) on one of the project's plan sets: read the building (a CAD drawing's
             walls, or the AI reads the sheets of a PDF / photo), the AI designs it and places every symbol, the app
             draws it (plan + panel schedule DXF), checks it against the code rules and against the wiring reader, and
             - when the check finds errors - gives the AI one turn to fix them. Status: proposed.
    change   a change in plain words ("add two outlets on the rear wall"): the AI returns the whole new design and what
             changed; drawn and checked again as the next revision.
    approve  the proposed design becomes the project's plan sets (plan + panel schedule), read by the plan engine, so AI
             Auto Run and the wiring run measure it and the estimate is priced from it. A design with errors can't be
             approved. Approving again (after more changes) replaces the plan sets it made last time.
    discard  forget it; nothing on the estimate changes.

Nothing is priced while a design is proposed. The AI runs on the agent API key through the AI measuring role
(agents/roles.py "llm_takeoff"): the budget is checked before each call, usage is recorded, and every call is in the AI
Log. Calls take a minute or two, so start and change run in the background; the page polls the job.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.errors import InvalidInput, NotFound, PermissionDenied

ROLE = "llm_takeoff"                  # the AI measuring role: the owner turned it on with the agent API key
FLOW = "ai_design"                    # its steps in providers.STEP_GROUPS (read, design: both complex)
RUN_INLINE = False                    # tests: run the job in the caller's thread
WORK_ROLES = ("owner", "estimator")
MAX_REQUEST = 3000
MAX_REVISIONS = 30
# The trades that can be designed. Electrical first (David, 2026-11-21); the others are on the way.
TRADES = {"electrical": {"label": "Electrical", "ready": True,
                         "example": "Here's my shed. Add electricity: LED shop lighting, 120 V receptacles on 20 A"
                                    " circuits, one 240 V 30 A receptacle and a 100 A subpanel fed underground from the"
                                    " house garage's 100 A subpanel."},
          "plumbing": {"label": "Plumbing", "ready": False}, "hvac": {"label": "HVAC", "ready": False},
          "low_voltage": {"label": "Low voltage", "ready": False}}
_lock = threading.Lock()
_busy: set = set()


class DesignJobError(Exception):
    """A design step failed. The message is safe to show."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def folder(estimate_id: int) -> Path:
    p = config.data_dir() / "design" / f"estimate_{int(estimate_id)}"
    p.mkdir(parents=True, exist_ok=True)
    return p


def state_path(estimate_id: int, trade: str) -> Path:
    return folder(estimate_id) / f"{trade}.json"


def load(estimate_id: int, trade: str) -> dict | None:
    p = state_path(estimate_id, trade)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save(state: dict) -> None:
    state["updated_at"] = _now()
    p = state_path(state["estimate_id"], state["trade"])
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
    tmp.replace(p)


def file_path(estimate_id: int, trade: str, rev: int, what: str) -> Path:
    return folder(estimate_id) / f"{trade}_rev{int(rev)}_{what}.dxf"


def _trade(trade: str) -> dict:
    t = TRADES.get((trade or "").strip().lower())
    if not t:
        raise InvalidInput(f"there's no AI design for '{trade}' - one of: {', '.join(TRADES)}", field="trade")
    if not t["ready"]:
        raise InvalidInput(f"AI design for {t['label']} is coming - Electrical is ready now", field="trade")
    return t


def _role(ctx: RequestContext) -> None:
    if ctx.role not in WORK_ROLES:
        raise PermissionDenied(f"only {', '.join(WORK_ROLES)} can run an AI design", role=ctx.role)


# ------------------------------------------------------------------ what the page shows
def public(state: dict | None) -> dict | None:
    if not state:
        return None
    from estimator.design import building as bmod
    from estimator.design import electrical
    d = state.get("design")
    f = state.get("findings") or []
    out = {k: state.get(k) for k in ("id", "estimate_id", "trade", "status", "step", "error", "request", "specs",
                                     "plan_set_id", "rev", "created_at", "updated_at", "approved_plan_set_ids",
                                     "provider", "model", "cost_usd", "revisions", "approval", "approved_at")}
    out["building"] = ({"name": state["building"].get("name"), "kind": state["building"].get("kind"),
                        "source": state["building"].get("source"), "size": bmod.size_line(state["building"]),
                        "notes": state["building"].get("notes"), "rooms": [r["name"] for fl in state["building"]["floors"]
                                                                          for r in fl["rooms"]]}
                       if state.get("building") else None)
    if d:
        out["design"] = {"summary": d.get("summary"), "panel": d.get("panel"), "circuits": d.get("circuits"),
                         "assumptions": d.get("assumptions"), "code_notes": d.get("code_notes"),
                         "changes": d.get("changes")}
        out["counts"] = electrical.summary(d)
    out["findings"] = f
    out["errors"] = sum(1 for x in f if x["level"] == "error")
    out["warnings"] = sum(1 for x in f if x["level"] == "warning")
    out["can_approve"] = (state.get("status") == "proposed" or _needs_reapply(state)) and out["errors"] == 0
    out["reapply"] = _needs_reapply(state)
    out["has_drawings"] = bool(state.get("rev") and file_path(state["estimate_id"], state["trade"], state["rev"],
                                                              "plan").is_file())
    return out


def plan_sets(conn, ctx: RequestContext, estimate_id: int) -> list[dict]:
    """The project's current plan sets a design can go on (not the drawings an AI design made)."""
    rows = [dict(r) for r in conn.execute(
        "SELECT id, original_name, file_type, status, supersedes_plan_set_id FROM plan_sets WHERE company_id = ?"
        " AND estimate_id = ? ORDER BY id", (ctx.company_id, int(estimate_id)))]
    gone = {r["supersedes_plan_set_id"] for r in rows if r["supersedes_plan_set_id"]}
    mine = set()
    for t in TRADES:
        s = load(estimate_id, t)
        mine |= set((s or {}).get("approved_plan_set_ids") or [])
    return [{"id": r["id"], "name": r["original_name"], "file_type": r["file_type"], "status": r["status"]}
            for r in rows if r["id"] not in gone and r["id"] not in mine]


def options(conn, ctx: RequestContext, estimate_id: int) -> dict:
    from estimator.agents import providers, roles
    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    on = cfg["provider"] in providers.API_PROVIDERS
    return {"trades": [{"id": k, "label": v["label"], "ready": v["ready"], "example": v.get("example", "")}
                       for k, v in TRADES.items()],
            "plan_sets": plan_sets(conn, ctx, estimate_id), "ai_on": on,
            "ai_label": providers.PROVIDER_LABELS.get(cfg["provider"]) if on else None,
            "why_off": "" if on else "AI measuring is off - turn it on in 🤖 AI agents (Setup) with the agent API key",
            "can_run": ctx.role in WORK_ROLES}


# ------------------------------------------------------------------ the AI calls
def _ask(conn, ctx: RequestContext, state: dict, system: str, prompt: str, images: list, *, purpose: str,
         step: str, refs: list | None = None) -> str:
    """One call on the AI measuring role's provider (then its backup), budget-checked, usage recorded, in the AI Log."""
    from estimator.agents import ai_log, providers, roles
    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    if cfg["provider"] not in providers.API_PROVIDERS:
        raise DesignJobError("AI measuring is off - turn it on in 🤖 AI agents (Setup) with the agent API key, so the AI"
                             " can design")
    ok, why = roles.budget_left(conn, ctx.company_id)
    if not ok:
        raise DesignJobError(f"the AI design can't run: {why}")
    errors = []
    for which in [p for p in (cfg["provider"], cfg.get("fallback_provider")) if p]:
        ready, why = providers.ready(which)
        if not ready:
            errors.append(f"{which}: {why}")
            continue
        model = providers.model_for_step(which, FLOW, step, cfg.get("model_pinned") if which == cfg["provider"] else None)
        started = time.monotonic()
        try:
            if images:
                text, usage = providers.ask_vision(which, system, prompt, images, model)
            else:
                text, usage = providers.ask(which, system, prompt, model)
        except providers.ProviderError as exc:
            spent = getattr(exc, "usage", None)
            roles.record_usage(conn, ctx, task_id=None, role=ROLE, provider=which, model=model, usage=spent, ok=False,
                               error=str(exc))
            ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose, system_prompt=system,
                          user_prompt=prompt, images=refs or [], usage=spent, estimate_id=state["estimate_id"],
                          duration_ms=int((time.monotonic() - started) * 1000), ok=False, error=str(exc))
            errors.append(f"{which}: {exc}")
            continue
        roles.record_usage(conn, ctx, task_id=None, role=ROLE, provider=which, model=model, usage=usage, ok=True)
        state["_log_id"] = ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose,
                                         system_prompt=system, user_prompt=prompt, images=refs or [],
                                         estimate_id=state["estimate_id"], response_text=text, usage=usage,
                                         duration_ms=int((time.monotonic() - started) * 1000))
        state["provider"], state["model"] = which, model
        state["cost_usd"] = round(float(state.get("cost_usd") or 0) + providers.cost_micros(model, usage) / 1e6, 4)
        return text
    raise DesignJobError("the AI couldn't answer: " + "; ".join(errors))


def _logged(conn, ctx, state, parsed=None, error=None):
    from estimator.agents import ai_log
    lid = state.pop("_log_id", None)
    if lid is None:
        return
    if error:
        ai_log.set_error(conn, ctx.company_id, lid, error)
    elif parsed is not None:
        ai_log.set_parsed(conn, ctx.company_id, lid, parsed)


# ------------------------------------------------------------------ the steps
def _read_building(conn, ctx: RequestContext, state: dict) -> dict:
    from estimator.design import building as bmod
    from estimator.drawing_model import store
    from estimator.takeoff import llm_takeoff as lt
    ps = store.load_plan_set(conn, ctx, int(state["plan_set_id"]))
    name = Path(ps["original_name"] or "Building").stem.replace("_", " ")[:60]
    if ps["file_type"] == "dxf":
        try:
            return bmod.from_dxf(ps["file_path"], name)
        except bmod.BuildingError as exc:
            raise DesignJobError(f"couldn't read the building from {ps['original_name']}: {exc}") from None
    sheets = bmod.plan_sheets(conn, ctx.company_id, ps["id"])
    if not sheets:
        raise DesignJobError(f"{ps['original_name']} has no sheet pictures yet - read the plans first (📖 on the"
                             " project page)")
    from estimator.agents import roles
    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    person = replace(ctx, agent=None)                  # a person asked for it: the one who started the design
    preps = [lt._prepare_image(conn, person, s["id"], "AI design: read the building", cfg["provider"]) for s in sheets]
    images = [lt._image_payload(Path(p["file_path"]), bmod.READ_MAX_PX) for p in preps]
    refs = [lt._image_ref(p, bmod.READ_MAX_PX) for p in preps]
    hints = []
    for s in sheets:
        hints += lt._hints(conn, ctx.company_id, s["id"])
    text = _ask(conn, ctx, state, bmod.READ_SYSTEM, bmod.read_prompt(sheets, hints[:60], state["request"]), images,
                purpose="AI design: read the building", step="read", refs=refs)
    try:
        b = bmod.parse_reading(text)
    except bmod.BuildingError as exc:
        _logged(conn, ctx, state, error=str(exc))
        raise DesignJobError(f"the AI couldn't read the building: {exc}") from None
    _logged(conn, ctx, state, parsed=b)
    return b


def _draw_and_check(state: dict, design: dict, rev: int) -> list[dict]:
    from estimator.design import draw_electrical as dr
    from estimator.design import electrical
    est, trade = state["estimate_id"], state["trade"]
    title = f"{state['building'].get('name') or 'Building'} - electrical"
    drawn = dr.draw_plan(state["building"], design, str(file_path(est, trade, rev, "plan")), title)
    dr.draw_panel(design, str(file_path(est, trade, rev, "panel")), title)
    findings = electrical.check(state["building"], design, drawn["placed"], state["building"].get("kind", ""))
    findings += _wiring_check(est, trade, rev, design)
    return findings


def _wiring_check(est: int, trade: str, rev: int, design: dict) -> list[dict]:
    """Read the drawings back the way the wiring run will: every device on the circuit the design gave it."""
    from estimator.takeoff import wiring
    out = []
    try:
        plan = wiring.read_floor_plan(str(file_path(est, trade, rev, "plan")))
        sched = wiring.read_panel_schedule(str(file_path(est, trade, rev, "panel")))
        left = wiring.assign(plan, sched)
        chk = wiring.drawing_check(plan, sched)
    except Exception as exc:  # noqa: BLE001 - a drawing the reader can't take is itself the finding
        return [{"level": "error", "code": "read_back", "message": f"the wiring run can't read the drawing back: {exc}",
                 "devices": []}]
    if plan.get("panel") is None:
        out.append({"level": "error", "code": "read_back", "message": "the wiring run doesn't find the panel on the"
                    " drawing", "devices": []})
    if left:
        out.append({"level": "warning", "code": "read_back", "message": f"{len(left)} device(s) aren't on a circuit when"
                    " the wiring run reads the drawing: " + ", ".join(d.id for d in left[:6]), "devices": []})
    if chk.get("differ"):
        out.append({"level": "info", "code": "read_back", "message": f"{len(chk['differ'])} home run(s) start at a device"
                    " on another circuit", "devices": []})
    n_sched = len(sched["circuits"])
    if n_sched != len(design["circuits"]):
        out.append({"level": "warning", "code": "read_back", "message": f"the panel schedule reads back {n_sched}"
                    f" circuits; the design has {len(design['circuits'])}", "devices": []})
    return out


MAX_SHOTS = 3                      # screenshots with one request or change
SHOT_MAX_BYTES = 4 * 1024 * 1024   # each, as sent
SHOT_MAX_PX = 1600                 # their long side when they go to the AI


def save_shots(estimate_id: int, trade: str, images, tag: str) -> list[str]:
    """2026-11-23 (David: "add screenshots to the AI Design to give geometric guidance, for example move this here"):
    the person's screenshots (data: URLs from the page - pasted or picked), checked to be real pictures, shrunk to
    SHOT_MAX_PX and kept beside the design. Returns their paths."""
    import base64
    import re as _re
    if not images:
        return []
    if not isinstance(images, list) or len(images) > MAX_SHOTS:
        raise InvalidInput(f"attach up to {MAX_SHOTS} screenshots", field="images")
    try:
        from PIL import Image
    except ImportError:                                             # pragma: no cover - Pillow ships with AI-Prowler
        raise InvalidInput("pictures can't be read on this PC (Pillow is missing)", field="images") from None
    out = []
    for i, s in enumerate(images):
        m = _re.match(r"^data:image/(png|jpe?g|webp|gif|bmp);base64,([A-Za-z0-9+/=\s]+)$", str(s or ""))
        if not m:
            raise InvalidInput(f"screenshot {i + 1} isn't a picture (PNG, JPG, WebP)", field="images")
        try:
            raw = base64.b64decode(m.group(2), validate=False)
        except ValueError:
            raise InvalidInput(f"screenshot {i + 1} couldn't be read", field="images") from None
        if len(raw) > SHOT_MAX_BYTES:
            raise InvalidInput(f"screenshot {i + 1} is over {SHOT_MAX_BYTES // (1024 * 1024)} MB", field="images")
        try:
            import io
            with Image.open(io.BytesIO(raw)) as im:
                im.load()
                im = im.convert("RGB")
                im.thumbnail((SHOT_MAX_PX, SHOT_MAX_PX))
                p = folder(estimate_id) / f"{trade}_{tag}_shot{i + 1}.jpg"
                im.save(p, "JPEG", quality=88)
        except Exception:  # noqa: BLE001 - not a picture Pillow can open
            raise InvalidInput(f"screenshot {i + 1} couldn't be read as a picture", field="images") from None
        out.append(str(p))
    return out


def _pictures(state: dict, shots: list[str], with_design: bool) -> tuple[list, list]:
    """The pictures for a request with screenshots: the app's reference drawing first, then the person's screenshots."""
    import base64
    from estimator.design import reference
    ref = folder(state["estimate_id"]) / f"{state['trade']}_reference_rev{int(state.get('rev') or 0)}.png"
    ref.write_bytes(reference.render(state["building"], state["design"] if with_design else None))
    payload = [{"media_type": "image/png", "data": base64.b64encode(ref.read_bytes()).decode("ascii")}]
    refs = [{"kind": "reference", "file_path": str(ref)}]
    for p in shots:
        payload.append({"media_type": "image/jpeg", "data": base64.b64encode(Path(p).read_bytes()).decode("ascii")})
        refs.append({"kind": "screenshot", "file_path": p})
    return payload, refs


def _design_step(conn, ctx, state: dict, prompt: str, kind: str, text_in: str, shots: list[str] | None = None) -> None:
    """Ask, parse, draw, check, and give the AI one turn to fix what the check calls an error."""
    from estimator.design import electrical
    state["step"] = "the AI is placing the symbols" if kind == "design" else "the AI is making the change"
    save(state)
    images, refs = [], []
    if shots:
        images, refs = _pictures(state, shots, with_design=kind == "change")
        prompt += electrical.images_note(len(shots), has_design=kind == "change")
    text = _ask(conn, ctx, state, electrical.DESIGN_SYSTEM, prompt, images, refs=refs,
                purpose=f"AI design: electrical {'design' if kind == 'design' else 'change'}"
                        + (f" ({len(shots)} screenshot{'s' if len(shots) > 1 else ''})" if shots else ""),
                step="design")
    try:
        design = electrical.parse_design(text, state["building"])
    except electrical.DesignError as exc:
        _logged(conn, ctx, state, error=str(exc))
        raise DesignJobError(str(exc)) from None
    _logged(conn, ctx, state, parsed={"devices": len(design["devices"]), "circuits": len(design["circuits"])})
    rev = int(state.get("rev") or 0) + 1
    state["step"] = "drawing and checking it"
    save(state)
    findings = _draw_and_check(state, design, rev)
    fixed = False
    if any(f["level"] == "error" for f in findings):
        state["step"] = "the AI is fixing what the code check found"
        save(state)
        text = _ask(conn, ctx, state, electrical.DESIGN_SYSTEM,
                    electrical.fix_prompt(state["building"], design, findings, state["request"]), [],
                    purpose="AI design: fix the code check's errors", step="design")
        try:
            fixed_design = electrical.parse_design(text, state["building"])
            _logged(conn, ctx, state, parsed={"devices": len(fixed_design["devices"])})
            fixed_findings = _draw_and_check(state, fixed_design, rev)
            if sum(f["level"] == "error" for f in fixed_findings) <= sum(f["level"] == "error" for f in findings):
                design, findings, fixed = fixed_design, fixed_findings, True
                design["changes"] = (design.get("changes") or [])
            else:
                _draw_and_check(state, design, rev)                  # the first try was better: draw it again
        except electrical.DesignError as exc:
            _logged(conn, ctx, state, error=str(exc))
            _draw_and_check(state, design, rev)
    state["design"], state["findings"], state["rev"] = design, findings, rev
    revs = state.setdefault("revisions", [])
    revs.append({"rev": rev, "at": _now(), "kind": kind, "text": text_in[:500], "changes": design.get("changes") or [],
                 "screenshots": len(shots or []),
                 "auto_fixed": fixed, "errors": sum(f["level"] == "error" for f in findings),
                 "warnings": sum(f["level"] == "warning" for f in findings)})
    del revs[:-MAX_REVISIONS]
    state["status"], state["step"], state["error"] = "proposed", "", None


def _job(conn_factory, ctx, estimate_id, trade, work) -> None:
    key = (ctx.company_id, int(estimate_id), trade)

    def go(conn):
        state = load(estimate_id, trade)
        try:
            work(conn, ctx, state)
        except DesignJobError as exc:
            state["status"], state["error"], state["step"] = state.get("_was") or "failed", str(exc), ""
            if state["status"] == "proposed":
                state["error"] = "the change didn't go through: " + str(exc)
        except Exception as exc:  # noqa: BLE001 - recorded on the job, never lost
            state["status"], state["error"], state["step"] = state.get("_was") or "failed", \
                f"{type(exc).__name__}: {exc}", ""
        state.pop("_was", None)
        state.pop("_log_id", None)
        save(state)
        try:
            conn.commit()
        except Exception:  # noqa: BLE001
            pass

    def run():
        try:
            if conn_factory is None:
                go(ctx_conn[0])
            else:
                from contextlib import closing
                with closing(conn_factory()) as c2:
                    go(c2)
        finally:
            with _lock:
                _busy.discard(key)
    ctx_conn = [None]
    with _lock:
        if key in _busy:
            raise InvalidInput("an AI design is already running on this project - wait for it to finish")
        _busy.add(key)
    return run, ctx_conn


def _launch(conn, run, ctx_conn, open_conn):
    if RUN_INLINE or open_conn is None:
        ctx_conn[0] = conn
        run()
        return
    t = threading.Thread(target=run, name="ai-design", daemon=True)
    t.start()
    _launch.last_thread = t


def start(conn, ctx: RequestContext, estimate_id: int, trade: str, request: str, plan_set_id: int,
          specs: str = "", open_conn=None, images=None) -> dict:
    """Start an AI design. Returns the job (status 'working'); the page polls get()."""
    from estimator.drawing_model import store
    from estimator.estimating import service
    _role(ctx)
    _trade(trade)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    request = (request or "").strip()
    if len(request) < 8:
        raise InvalidInput("say what you want designed - e.g. 'add LED lighting and 20 A receptacles to my shed'",
                           field="request")
    if len(request) > MAX_REQUEST or len(specs or "") > MAX_REQUEST:
        raise InvalidInput(f"keep the request and the specs under {MAX_REQUEST} characters each", field="request")
    ps = store.load_plan_set(conn, ctx, int(plan_set_id))
    if ps["estimate_id"] != est["id"]:
        raise NotFound(f"plan set {plan_set_id} isn't on this project", plan_set_id=plan_set_id)
    if ps["file_type"] != "dxf" and ps["status"] != "processed":
        raise InvalidInput(f"{ps['original_name']} hasn't been read yet - read the plans first (📖 on the project page)",
                           field="plan_set_id")
    old = load(est["id"], trade)
    if old and old.get("status") == "working":
        raise InvalidInput("an AI design is already running on this project - wait for it to finish")
    keep_building = old and old.get("building") and old.get("plan_set_id") == ps["id"]
    shots = save_shots(est["id"], trade, images, f"start{int(time.time())}")
    state = {"id": int(time.time()), "estimate_id": est["id"], "trade": trade, "status": "working",
             "step": "reading the building", "error": None, "request": request, "specs": (specs or "").strip(),
             "plan_set_id": ps["id"], "building": old["building"] if keep_building else None, "design": None,
             "findings": [], "rev": int((old or {}).get("rev") or 0), "revisions": [],
             "approved_plan_set_ids": (old or {}).get("approved_plan_set_ids") or [], "cost_usd": 0.0,
             "created_at": _now(), "pending_shots": shots}
    save(state)
    run, holder = _job(open_conn, ctx, est["id"], trade, _new_work)
    _launch(conn, run, holder, open_conn)
    return public(load(est["id"], trade))


def _new_work(conn, ctx, state):
    from estimator.design import electrical
    if not state.get("building"):
        state["building"] = _read_building(conn, ctx, state)
        save(state)
    _design_step(conn, ctx, state, electrical.design_prompt(state["building"], state["request"], state["specs"]),
                 "design", state["request"], state.pop("pending_shots", None))


def change(conn, ctx: RequestContext, estimate_id: int, trade: str, text: str, open_conn=None, images=None) -> dict:
    """A change in plain words to the proposed design."""
    from estimator.estimating import service
    _role(ctx)
    _trade(trade)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    state = load(est["id"], trade)
    if not state or not state.get("design"):
        raise InvalidInput("there's no AI design on this project yet - start one first")
    if state["status"] not in ("proposed", "approved"):
        raise InvalidInput(f"the design is {state['status']} - it can be changed once it's proposed")
    text = (text or "").strip()
    if len(text) < 3 or len(text) > MAX_REQUEST:
        raise InvalidInput(f"say what to change (under {MAX_REQUEST} characters)", field="text")
    state["pending_shots"] = save_shots(est["id"], trade, images, f"rev{int(state.get('rev') or 0) + 1}")
    state["_was"] = "proposed"
    state["status"], state["step"], state["error"], state["pending_change"] = "working", "the AI is making the change", \
        None, text
    save(state)
    run, holder = _job(open_conn, ctx, est["id"], trade, _change_work)
    _launch(conn, run, holder, open_conn)
    return public(load(est["id"], trade))


def _change_work(conn, ctx, state):
    from estimator.design import electrical
    text = state.pop("pending_change", "")
    _design_step(conn, ctx, state, electrical.change_prompt(state["building"], state["design"], text, state["request"],
                                                            state.get("specs") or ""), "change", text,
                 state.pop("pending_shots", None))


def get(conn, ctx: RequestContext, estimate_id: int, trade: str) -> dict | None:
    from estimator.estimating import service
    est = service.get_estimate(conn, ctx, int(estimate_id))
    return public(load(est["id"], trade))


# ------------------------------------------------------------------ approve: the design takes over the trade
# 2026-11-23 (David: "I used the AI Design and then when I went through the sheets for the electrical drawing and wiring,
# it did not use the new AI Design ... I want all the older drawings to be updated along with the wiring and estimate and
# so on ... the flow to be easy and automatic, not confusing"). Approving a design is the person's one decision; the app
# then does the rest in the background, the way a new plan revision replaces the old one (store.upload):
#   1. the older electrical drawings on the project (plan sets whose every sheet is electrical - drawn by hand, uploaded,
#      or made by an earlier approval) are replaced by the design's plan and panel schedule, with their measurements;
#   2. any other electrical measurement left on the estimate (e.g. counted on an architectural sheet) is rejected with
#      the reason, so only the design is priced - rejected ones stay in the history;
#   3. the plan engine reads the new drawings; every device is counted from the drawing's symbols (exact, no AI);
#   4. the wiring run routes every circuit and measures the cable;
#   5. those counts and the cable are approved (the person approved the design they come from) and
#   6. the estimate's Electrical is updated from them (a draft one; an approved or sent one waits for 🔄 Update from the
#      plans, which reopens it).
# A step that can't finish leaves the design approved and says what to do by hand.

def _sheet_disciplines(conn, plan_set_id: int) -> list[str]:
    return [(r[0] or "").lower() for r in conn.execute("SELECT discipline FROM sheets WHERE plan_set_id = ?",
                                                      (plan_set_id,))]


def _is_panel_set(conn, row: dict) -> bool:
    titles = " ".join((r[0] or "") for r in conn.execute("SELECT title FROM sheets WHERE plan_set_id = ?", (row["id"],)))
    if row["file_type"] == "dxf" and row.get("file_path") and Path(row["file_path"]).is_file():
        from estimator.takeoff import wiring_run
        if wiring_run._is_panel_drawing(row["file_path"]):
            return True
    import re as _re
    return bool(_re.search(r"\bPANEL\b|\bSCHEDULE\b", f"{row['original_name']} {titles}".upper()))


def replaced_by_design(conn, ctx: RequestContext, estimate_id: int, state: dict) -> dict:
    """What approving the design replaces: {plan, panel, extra} older electrical plan sets (dicts), and the other
    electrical measurements on the estimate that would be rejected. Changes nothing."""
    from estimator.takeoff import plan_delete
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM plan_sets WHERE company_id = ? AND estimate_id = ? ORDER BY id DESC",
        (ctx.company_id, int(estimate_id)))]
    gone = {r["supersedes_plan_set_id"] for r in rows if r["supersedes_plan_set_id"]}
    mine = set(state.get("approved_plan_set_ids") or [])
    old = []
    for r in rows:
        if r["id"] in gone:
            continue                                    # replaced already
        # an electrical-only drawing is replaced even when the design was drawn on it (its walls are in the design);
        # the architectural plans the design was drawn on stay
        disc = _sheet_disciplines(conn, r["id"])
        if r["id"] in mine or (disc and all(d == "electrical" for d in disc)):
            r["panel"] = _is_panel_set(conn, r)
            r["counts"] = plan_delete.plan_set_counts(conn, ctx, r)
            old.append(r)
    plan = next((r for r in old if not r["panel"]), None)
    panel = next((r for r in old if r["panel"]), None)
    extra = [r for r in old if r is not plan and r is not panel]
    old_ids = [r["id"] for r in old]
    marks = ",".join("?" * len(old_ids)) or "NULL"
    others = [dict(r) for r in conn.execute(
        "SELECT m.id, m.status, m.feeds FROM measurements m LEFT JOIN sheets s ON s.id = m.sheet_id"
        f" WHERE m.company_id = ? AND m.estimate_id = ? AND m.module_id = ? AND m.status != 'rejected'"
        f" AND (s.plan_set_id IS NULL OR s.plan_set_id NOT IN ({marks}))",
        (ctx.company_id, int(estimate_id), state["trade"], *old_ids))]
    return {"plan": plan, "panel": panel, "extra": extra, "other_measurements": others}


def _approve_question(conn, state: dict, c: dict, r: dict) -> str:
    from estimator.drawing_model import store
    olds = [x for x in (r["plan"], r["panel"], *r["extra"]) if x]
    n = sum(x["counts"]["measurements"] for x in olds) + len(r["other_measurements"])
    ok = sum(x["counts"]["measurements_approved"] for x in olds) + sum(1 for m in r["other_measurements"]
                                                                       if m["status"] == "approved")
    q = (f"Approve the AI design (revision {state['rev']}: {c['total']} devices on {c['circuits']} circuits, a"
         f" {c['panel']})? It becomes the project's electrical plan and panel schedule")
    if olds:
        q += (" and replaces the older electrical drawings - " + ", ".join(
            f"plan set {store.plan_set_label(conn, x)} ({x['original_name']})" for x in olds) + " -")
    if n:
        q += f" with their {n} electrical measurement{'s' if n != 1 else ''}" + (f" ({ok} approved)" if ok else "")
    q += (". Then the app reads the new drawings, counts every device, runs the wiring, approves those counts and the"
          " cable (they come from the design you're approving), and updates the estimate's electrical prices.")
    if olds:
        q += " The older drawings can't be brought back."
    return q


def _needs_reapply(state: dict) -> bool:
    """A design approved before 2026-11-23 only became plan sets: the older drawings stayed and nothing was measured.
    It can be approved once more, to do the rest."""
    return state.get("status") == "approved" and not state.get("approval")


def approve(conn, ctx: RequestContext, estimate_id: int, trade: str, confirm: bool = False, open_conn=None) -> dict:
    """Approve the proposed design: it replaces the older electrical work and the app measures and prices it (above).
    Asks first. Runs in the background; the page polls the job (status working, then approved)."""
    from estimator.design import electrical
    from estimator.errors import ConfirmationRequired
    from estimator.estimating import service
    _role(ctx)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    state = load(est["id"], trade)
    if not state or not (state.get("status") == "proposed" or _needs_reapply(state)):
        raise InvalidInput("there's no proposed AI design to approve on this project")
    errs = [f for f in state["findings"] if f["level"] == "error"]
    if errs:
        raise InvalidInput(f"the design has {len(errs)} code error(s) - change it first (e.g. 'fix the errors'): "
                           + errs[0]["message"])
    c = electrical.summary(state["design"])
    r = replaced_by_design(conn, ctx, est["id"], state)
    if not confirm:
        raise ConfirmationRequired(_approve_question(conn, state, c, r) + " Call again with confirm=true.",
                                   rev=state["rev"], counts=c,
                                   replaces=[{"plan_set_id": x["id"], "file": x["original_name"], **x["counts"]}
                                             for x in (r["plan"], r["panel"], *r["extra"]) if x],
                                   other_measurements=len(r["other_measurements"]))
    state["_was"], state["status"], state["error"] = state["status"], "working", None
    state["step"] = "approving: putting the design in place of the older drawings"
    state["approval"] = None
    save(state)
    run, holder = _job(open_conn, ctx, est["id"], trade, _approve_work)
    _launch(conn, run, holder, open_conn)
    out = public(load(est["id"], trade))
    if out["status"] == "approved":
        out["say"] = (out.get("approval") or {}).get("say") or "Approved."
    return out


def _approve_work(conn, ctx, state):
    from estimator.drawing_model import engine, store
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import plan_delete
    est_id, trade = state["estimate_id"], state["trade"]
    r = replaced_by_design(conn, ctx, est_id, state)
    done = {"replaced": [], "rejected": 0, "plan_set_ids": [], "counted": 0, "wired": 0, "approved": 0,
            "estimate": None, "todo": [], "say": ""}

    def step(text):
        state["step"] = "approving: " + text
        save(state)

    # 1. the design's drawings replace the older ones (the same as uploading a new revision) - drawn again first, so
    #    they always come from today's drawing code (2026-11-23: the legend's samples moved to their own layer)
    from estimator.design import draw_electrical as dr
    title = f"{state['building'].get('name') or 'Building'} - electrical"
    dr.draw_plan(state["building"], state["design"], str(file_path(est_id, trade, state["rev"], "plan")), title)
    dr.draw_panel(state["design"], str(file_path(est_id, trade, state["rev"], "panel")), title)
    nice = {"plan": f"AI design - {trade} plan.dxf", "panel": f"AI design - {trade} panel schedule.dxf"}
    tmpdir = folder(est_id) / f"approve_rev{state['rev']}"
    tmpdir.mkdir(exist_ok=True)
    made = []
    for what in ("plan", "panel"):
        dst = tmpdir / nice[what]
        shutil.copyfile(file_path(est_id, trade, state["rev"], what), dst)
        sup = r[what]
        up = store.upload(conn, ctx, est_id, str(dst), sup["id"] if sup else None, confirm=True,
                          design_firm="AI design (AI-Prowler)")
        made.append(up["plan_set_id"])
        if sup:
            done["replaced"].append(sup["original_name"])
    for x in r["extra"]:
        plan_delete.delete_plan_set(conn, ctx, x["id"], confirm=True)
        done["replaced"].append(x["original_name"])
    conn.commit()
    # from here on the design IS approved: a later step that can't finish says what to do by hand
    state.pop("_was", None)
    state["status"], state["approved_plan_set_ids"], state["approved_at"] = "approved", made, _now()
    done["plan_set_ids"] = made
    state["approval"] = done
    save(state)

    def later(what, how, exc):
        done["todo"].append(f"{what} didn't finish ({exc}) - {how}")

    # 2. electrical measurements left on the estimate from before: rejected, with the reason (kept in the history)
    for m in r["other_measurements"]:
        try:
            ms.reject(conn, ctx, m["id"], reason="replaced by the approved AI design", confirm=True)
            done["rejected"] += 1
        except Exception as exc:  # noqa: BLE001
            later(f"setting aside measurement {m['id']}", "reject it in Measure", exc)
            break
    # 3. the plan engine reads the new drawings (small CAD files: read here, in this job)
    step("reading the new drawings")
    try:
        for pid in made:
            engine.start(conn, ctx, pid, confirm=True, open_conn=None)
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        later("reading the new drawings", "read them on the project page (📖), then run AI Auto Run and ⚡ Run wiring",
              exc)
        return _approve_done(state, done)
    ids = []
    # 4. every device, counted from the drawing's symbols (exact - the app drew them)
    step("counting the devices")
    try:
        from estimator.takeoff import from_plans
        out = from_plans.propose(conn, ctx, est_id, trade, plan_set_id=made[0], include_proposed=True, confirm=True)
        new = [m["id"] for m in out["measurements"] if m["status"] == "proposed"]
        ids += new
        done["counted"] = len(new)
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        later("counting the devices", "run 🤖 AI Auto Run on the AI design sheet", exc)
    # 5. the wiring run: every circuit routed, the cable measured
    step("running the wiring")
    try:
        from estimator.takeoff import wiring_run
        # the design's wiring method (2026-11-23: a metal building in EMT on steel), over the company's own defaults
        w = wiring_run.run(conn, ctx, est_id, settings=(state["design"].get("wiring") or None), keep_approved=False)
        ids += list(w.get("measurement_ids") or [])
        done["wired"] = len(w.get("measurement_ids") or [])
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        later("the wiring run", "click ⚡ Run wiring on the Measure screen", exc)
    # 6. approved: the person approved the design these come from
    if ids:
        step("approving the counts and the cable")
        try:
            ms.confirm_measurements(conn, ctx, ids, confirm=True)
            done["approved"] = len(ids)
            conn.commit()
        except Exception as exc:  # noqa: BLE001 - e.g. an agent approved the design: a person approves the counts
            later("approving the counts", "approve them in Measure (or ✓ Reviews)", exc)
    # 7. the estimate's Electrical, from the approved counts and cable
    step("updating the estimate")
    try:
        done["estimate"] = _update_estimate(conn, ctx, est_id, trade)
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        later("updating the estimate", "click 🔄 Update from the plans on the estimate", exc)
    return _approve_done(state, done)


def _update_estimate(conn, ctx, est_id: int, trade: str) -> str:
    """Re-price the trade from its approved measurements (the 🔄 Update from the plans button, for this trade only).
    An estimate that's approved or sent is left for the person: updating it reopens it."""
    from estimator.api.estimate_api import plan_changes
    from estimator.estimating import quick, service
    from estimator.modules import get_registry
    reg = get_registry()
    est = service.get_estimate(conn, ctx, est_id)
    if not any(s["module_id"] == trade for s in est["sections"]):
        return "no_trade"
    todo = [t for t in plan_changes(conn, ctx, est, reg) if t["module_id"] == trade]
    if not todo:
        return "unchanged"
    if est["status"] not in service.EDITABLE_STATUSES:
        return "needs_reopen"
    for t in todo:
        quick.answer(conn, ctx, est_id, t["module_id"], t["answers"], int(est["rev"]), reg)
    return "updated"


def _approve_done(state: dict, done: dict) -> None:
    bits = []
    if done["replaced"]:
        bits.append("replaced " + ", ".join(done["replaced"]))
    if done["counted"] or done["wired"]:
        bits.append(f"measured {done['counted']} device count{'s' if done['counted'] != 1 else ''} and"
                    f" {done['wired']} cable size{'s' if done['wired'] != 1 else ''}"
                    + (" (approved)" if done["approved"] else ""))
    est = {"updated": "updated the estimate's electrical prices", "unchanged": "the estimate already matched",
           "needs_reopen": "the estimate is approved or sent: click 🔄 Update from the plans to reopen and update it",
           "no_trade": "Electrical isn't on the estimate yet: add the trade, then 🔄 Update from the plans"}
    if done["estimate"] in est:
        bits.append(est[done["estimate"]])
    done["say"] = "Approved: " + "; ".join(bits) + "." if bits else "Approved."
    state["approval"] = done
    state["status"], state["step"], state["error"] = "approved", "", None
    if done["todo"]:
        state["error"] = "Approved, but " + "; ".join(done["todo"])
    save(state)


def discard(conn, ctx: RequestContext, estimate_id: int, trade: str) -> dict:
    from estimator.estimating import service
    _role(ctx)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    state = load(est["id"], trade)
    if not state:
        raise InvalidInput("there's no AI design on this project")
    if state.get("status") == "working":
        raise InvalidInput("the AI design is still running - wait for it to finish")
    state["status"], state["step"] = "discarded", ""
    save(state)
    return public(state)


def drawing(estimate_id: int, trade: str, what: str) -> Path:
    state = load(estimate_id, trade)
    if not state or not state.get("rev"):
        raise NotFound("there's no AI design drawing yet")
    p = file_path(estimate_id, trade, state["rev"], "panel" if what == "panel" else "plan")
    if not p.is_file():
        raise NotFound("there's no AI design drawing yet")
    return p

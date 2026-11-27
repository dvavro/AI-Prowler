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
    approve  the proposed design becomes the project's plan sets (plan + panel schedule), read by the plan engine, so
             AI Auto Measure/Count and the wiring run measure it and the estimate is priced from it. A design with errors can't be
             approved. Approving again (after more changes) replaces the plan sets it made last time.
    discard  forget it; nothing on the estimate changes.

Nothing is priced while a design is proposed. The AI runs on the agent API key through the AI measuring role
(agents/roles.py "llm_takeoff"): the budget is checked before each call, usage is recorded, and every call is in the AI
Log. Calls take a minute or two, so start and change run in the background; the page polls the job.
"""
from __future__ import annotations

import json
import re
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
          "low_voltage": {"label": "Low voltage", "ready": False},
          # 2026-11-24 (David: "If the user does not have plans I want the user to be able to use AI Design button so the
          # user can just describe the plans and have AI Design it for him" - every trade, as a drawn plan): no plan set
          # needed; the AI lays out the whole job from the description and the app draws the sheets (describe.py,
          # draw_plans.py). Approving makes them the project's plans, measured like any designer's.
          "plans": {"label": "Plans from a description", "ready": True, "no_plans": True,
                    "example": "Back yard of a 100 x 150 lot behind a 40 x 30 house: 6 ft wood privacy fence on three"
                               " sides from the house's back corners, a 4 ft walk gate and a 12 ft double drive gate,"
                               " St. Augustine sod in the back yard."}}
PLANS = "plans"
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


def approved_rev(state: dict | None) -> int | None:
    """Which of the design's revisions is the project's plans now (approved_rev; before 2026-11-25 it wasn't kept, so the
    newest approve_plans_revN folder says it)."""
    if not state or not state.get("approved_plan_set_ids"):
        return None
    if state.get("approved_rev"):
        return int(state["approved_rev"])
    revs = [int(m.group(1)) for p in folder(state["estimate_id"]).glob(f"approve_{state['trade']}_rev*")
            if (m := re.match(rf"approve_{state['trade']}_rev(\d+)$", p.name))]
    if not revs and state.get("trade") == "electrical":
        revs = [int(m.group(1)) for p in folder(state["estimate_id"]).glob("approve_rev*")
                if (m := re.match(r"approve_rev(\d+)$", p.name))]
    return max(revs) if revs else None


def on_measure(estimate_id: int) -> dict:
    """2026-11-25 (David: "I just reran AI Design and the drawing showed the notes, then when I went back to measure and
    hit the reload icon, it did not bring up rev 4"): what the Measure screen says about AI design - which design revision
    each of its plan sets is, and a redraw that's drawn but not approved yet (it isn't the plans until it's approved).
    {"plan_sets": {plan_set_id: design rev}, "waiting": {trade, rev, approved_rev} | None}."""
    out, waiting = {}, None
    for trade in (PLANS, "electrical"):
        st = load(estimate_id, trade)
        if not st:
            continue
        ar = approved_rev(st)
        for pid in st.get("approved_plan_set_ids") or []:
            if ar:
                out[int(pid)] = ar
        placed = st.get("placed") or {}
        if placed.get("rev"):                   # the drawing on the Measure screen (2026-11-25: every redraw goes there)
            for pid in placed.get("plan_set_ids") or []:
                out[int(pid)] = int(placed["rev"])
        shown = int(placed.get("rev") or 0) or None
        if st.get("status") == "proposed" and st.get("rev") and (ar is None or int(st["rev"]) > ar) and waiting is None:
            waiting = {"trade": trade, "rev": int(st["rev"]), "approved_rev": ar,
                       "on_screen": shown == int(st["rev"])}
    return {"plan_sets": out, "waiting": waiting}


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
    if d and state.get("trade") == PLANS:
        from estimator.design import describe, draw_plans
        out["design"] = {"summary": d.get("summary"), "assumptions": d.get("assumptions"), "notes": d.get("notes"),
                         "changes": d.get("changes")}
        out["counts"] = describe.summary(d)
        out["sheets"] = ([{"key": k, "title": draw_plans.SHEETS[k],
                           "ready": bool(state.get("rev")) and sheet_path(state["estimate_id"], state["rev"], k).is_file()}
                          for k in describe.sheets_for(d)] if _does(state, "draw") else [])
        out["trade_answers"] = _answers_shown(state)
    elif d:
        out["design"] = {"summary": d.get("summary"), "panel": d.get("panel"), "circuits": d.get("circuits"),
                         "assumptions": d.get("assumptions"), "code_notes": d.get("code_notes"),
                         "changes": d.get("changes")}
        out["counts"] = electrical.summary(d)
    out["findings"] = f
    out["errors"] = sum(1 for x in f if x["level"] == "error")
    out["warnings"] = sum(1 for x in f if x["level"] == "warning")
    out["can_approve"] = (state.get("status") == "proposed" or _needs_reapply(state)) and out["errors"] == 0
    out["reapply"] = _needs_reapply(state)
    # 2026-11-25: which drawing is on the Measure screen and which one is approved (AI plans and electrical)
    p = state.get("placed") or {}
    out["placed"] = ({"rev": p.get("rev"), "plan_set_ids": p.get("plan_set_ids") or [], "measured": p.get("measured") or {},
                      "gone": len(p.get("gone") or []), "todo": p.get("todo") or [], "at": p.get("at")}
                     if p.get("rev") else None)
    out["approved_rev"] = approved_rev(state)
    if state.get("trade") == PLANS:
        out["keep_approved"] = bool(state.get("keep_approved", True))
        out["auto_approve"] = bool(state.get("auto_approve", False))
        out["has_drawings"] = bool(out.get("sheets")) and all(s["ready"] for s in out["sheets"])
        out["do"] = {k: _does(state, k) for k in DO_KEYS}
    else:
        out["has_drawings"] = bool(state.get("rev") and file_path(state["estimate_id"], state["trade"], state["rev"],
                                                                  "plan").is_file())
    return out


def _answers_shown(state: dict) -> list[dict]:
    """The trade answers the AI filled in, as the person reads them: [{trade, name, answers: [{label, value}]}]."""
    d = state.get("design") or {}
    if not _does(state, "price") or not d.get("trade_answers"):
        return []
    from estimator.design import trade_answers
    from estimator.modules import get_registry
    try:
        reg = get_registry()
    except Exception:  # noqa: BLE001 - the card shows without them
        return []
    out = []
    for t, raw in d["trade_answers"].items():
        mod = reg.modules.get(t)
        if mod is None:
            continue
        ans, _dropped = trade_answers.clean(mod, raw, _does(state, "permits"))
        if ans:
            out.append({"trade": t, "name": mod.name, "answers": trade_answers.shown(mod, ans)})
    return out


def sheet_path(estimate_id: int, rev: int, key: str) -> Path:
    """A plans-from-a-description sheet (draw_plans.SHEETS key) of one revision."""
    return folder(estimate_id) / f"{PLANS}_rev{int(rev)}_{key}.dxf"


def plan_sets(conn, ctx: RequestContext, estimate_id: int) -> list[dict]:
    """The project's current plan sets a design can go on (not the drawings an AI design made)."""
    rows = [dict(r) for r in conn.execute(
        "SELECT id, original_name, file_type, status, supersedes_plan_set_id FROM plan_sets WHERE company_id = ?"
        " AND estimate_id = ? ORDER BY id", (ctx.company_id, int(estimate_id)))]
    gone = {r["supersedes_plan_set_id"] for r in rows if r["supersedes_plan_set_id"]}
    mine = set()
    for t in TRADES:
        if t == PLANS:
            continue     # plans the AI drew from a description are the project's plans: electrical can be designed on them
        s = load(estimate_id, t)
        mine |= set((s or {}).get("approved_plan_set_ids") or [])
    return [{"id": r["id"], "name": r["original_name"], "file_type": r["file_type"], "status": r["status"]}
            for r in rows if r["id"] not in gone and r["id"] not in mine]


def options(conn, ctx: RequestContext, estimate_id: int) -> dict:
    from estimator.agents import providers, roles
    from estimator.estimating import service
    from estimator.modules import get_registry
    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    on = cfg["provider"] in providers.API_PROVIDERS
    # 2026-11-25 (David: "The AI Design should know what trade I am in as a default (it should come up as fence)"): the
    # project's trades, and which design to open on - electrical when the project quotes electrical, otherwise the plans
    est = service.get_estimate(conn, ctx, int(estimate_id))
    reg = get_registry()
    quoted = _project_trades(conn, ctx, est)
    names = [reg.modules[t].name if t in reg.modules else t.replace("_", " ").title() for t in quoted]
    plans_job = load(est["id"], PLANS) or {}
    default = ("plans" if plans_job.get("status") in ("working", "proposed", "approved")
               else "electrical" if "electrical" in quoted or not quoted else "plans")
    return {"trades": [{"id": k, "label": v["label"], "ready": v["ready"], "example": v.get("example", ""),
                        "no_plans": bool(v.get("no_plans"))} for k, v in TRADES.items()],
            "project_trades": [{"id": t, "name": n} for t, n in zip(quoted, names)], "default_trade": default,
            "plan_sets": plan_sets(conn, ctx, estimate_id), "ai_on": on,
            "ai_label": providers.PROVIDER_LABELS.get(cfg["provider"]) if on else None,
            "why_off": "" if on else "AI measuring is off - turn it on in 🤖 AI agents (Setup) with the agent API key",
            "can_run": ctx.role in WORK_ROLES,
            # 2026-11-27: what ✨ Run AI design does unless the person changes it (no drawing for a demolition-only job)
            "do_default": {"draw": draw_by_default(quoted), "price": True, "permits": False}}


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


def _shot_payload(shots: list[str]) -> tuple[list, list]:
    """The person's screenshots alone, for the AI (plans from a description have no drawing of their own to show)."""
    import base64
    payload = [{"media_type": "image/jpeg", "data": base64.b64encode(Path(p).read_bytes()).decode("ascii")} for p in shots]
    return payload, [{"kind": "screenshot", "file_path": p} for p in shots]


def _plans_step(conn, ctx, state: dict, prompt: str, kind: str, text_in: str, shots: list[str] | None = None) -> None:
    """Plans from a description: ask, parse, draw every sheet, check, and give the AI one turn to fix an error.
    shots: the person's screenshots or photos (2026-11-25) - an aerial view with the fence line marked, a plot plan ..."""
    from estimator.design import describe
    state["step"] = "the AI is laying out the job" if kind == "design" else "the AI is making the change"
    save(state)
    shots = [p for p in (shots or []) if Path(p).is_file()]
    images, refs = _shot_payload(shots) if shots else ([], [])
    if shots:
        prompt += describe.images_note(len(shots), has_design=kind == "change")
    text = _ask(conn, ctx, state, describe.DESIGN_SYSTEM, prompt, images, refs=refs,
                purpose=f"AI design: plans from a description ({'design' if kind == 'design' else 'change'})"
                        + (f" ({len(shots)} screenshot{'s' if len(shots) > 1 else ''})" if shots else ""), step="design")
    drawing = _does(state, "draw")          # 2026-11-27: ✨ Run AI design without "Draw the plans" fills in the estimate only
    try:
        design = describe.parse_design(text, drawing=drawing)
    except describe.DesignError as exc:
        _logged(conn, ctx, state, error=str(exc))
        raise DesignJobError(str(exc)) from None
    _logged(conn, ctx, state, parsed=describe.summary(design))
    rev = int(state.get("rev") or 0) + 1
    state["step"] = "drawing the sheets and checking them" if drawing else "checking the answers"
    save(state)
    findings = describe.check(design, drawing=drawing)
    fixed = False
    if any(f["level"] == "error" for f in findings):
        state["step"] = "the AI is fixing what the check found"
        save(state)
        text = _ask(conn, ctx, state, describe.DESIGN_SYSTEM, describe.fix_prompt(design, findings, state["request"]), [],
                    purpose="AI design: fix the plans check's errors", step="design")
        try:
            again = describe.parse_design(text, drawing=drawing)
            _logged(conn, ctx, state, parsed=describe.summary(again))
            f2 = describe.check(again, drawing=drawing)
            if sum(f["level"] == "error" for f in f2) <= sum(f["level"] == "error" for f in findings):
                design, findings, fixed = again, f2, True
        except describe.DesignError as exc:
            _logged(conn, ctx, state, error=str(exc))
    findings += _answer_findings(design, state)
    if drawing:
        _draw_plans(state, design, rev)
    state["design"], state["findings"], state["rev"] = design, findings, rev
    revs = state.setdefault("revisions", [])
    revs.append({"rev": rev, "at": _now(), "kind": kind, "text": text_in[:500], "changes": design.get("changes") or [],
                 "screenshots": len(shots), "auto_fixed": fixed, "errors": sum(f["level"] == "error" for f in findings),
                 "warnings": sum(f["level"] == "warning" for f in findings)})
    del revs[:-MAX_REVISIONS]
    state["status"], state["step"], state["error"] = "proposed", "", None


def _answer_findings(design: dict, state: dict) -> list[dict]:
    """What the check says about the AI's trade answers (2026-11-27): an answer a trade doesn't take is dropped - said
    as a warning, never guessed; a quoted trade it didn't fill in is said as info."""
    if not _does(state, "price"):
        return []
    from estimator.design import trade_answers
    from estimator.modules import get_registry
    reg = get_registry()
    out = []
    got = design.get("trade_answers") or {}
    for t, raw in got.items():
        mod = reg.modules.get(t)
        if mod is None:
            continue
        _ans, dropped = trade_answers.clean(mod, raw, _does(state, "permits"))
        for d in dropped:
            out.append({"level": "warning", "code": "answer_dropped", "message": f"{mod.name}: {d} - left out"})
    for t in state.get("trades") or []:
        if t in reg.modules and not got.get(t) and not _does(state, "draw"):
            out.append({"level": "info", "code": "not_answered",
                        "message": f"{reg.modules[t].name}: the AI didn't fill it in - say more about it, or fill it in "
                                   "on the estimate"})
    return out


def _draw_plans(state: dict, design: dict, rev: int) -> list[dict]:
    from estimator.design import describe, draw_plans
    est = state["estimate_id"]
    out = []
    for key in describe.sheets_for(design):
        out.append(draw_plans.DRAW[key](design, str(sheet_path(est, rev, key)), state.get("project") or "Project"))
    return out


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


def _options(state: dict, keep_approved=None, auto_approve=None) -> None:
    """The person's choices for plans from a description (2026-11-25): keep approved items when a new drawing is put
    on the Measure screen (the Measure screen's "Keep approved items on rerun", on unless said), and approve each new
    drawing automatically (off unless said)."""
    if keep_approved is not None:
        state["keep_approved"] = bool(keep_approved)
    if auto_approve is not None:
        state["auto_approve"] = bool(auto_approve)
    state.setdefault("keep_approved", True)
    state.setdefault("auto_approve", False)


# 2026-11-27 (David: "I am doing a Demolition estimate, but that job does not need a drawing like other jobs. The draw the
# plans button should say run AI Design and add a selection to draw plans and other options like include pricing and
# inspections ... this can be the same for all trades"). What ✨ Run AI design does, as the person picks it:
#   draw    - draw the plans and put them on the Measure screen (as before). On unless no quoted trade is measured from a
#             drawing (a demolition-only job).
#   price   - fill in each quoted trade's own questions from the description (trade_answers.py) and price them when the
#             design is approved. A trade the drawing measures is priced from the drawing; the AI's answers fill the rest.
#   permits - answer the permit and inspection questions too (otherwise they stay as the estimate has them).
DO_KEYS = ("draw", "price", "permits")


def draw_by_default(trades: list[str]) -> bool:
    """Draw unless every quoted trade is one a drawing doesn't measure (demolition ...)."""
    from estimator.building import trades as plan_trades
    if not trades:
        return True
    return any(t in plan_trades.TRADES or t in ("concrete", "electrical", "roofing") for t in trades)


def _do_options(state: dict, do: dict | None) -> None:
    for k, v in (do or {}).items():
        if k in DO_KEYS and v is not None:
            state[k] = bool(v)
    state.setdefault("draw", draw_by_default(state.get("trades") or []))
    state.setdefault("price", True)
    state.setdefault("permits", False)
    if not state["draw"] and not state["price"]:
        raise InvalidInput("pick what AI design should do: draw the plans, price the estimate, or both", field="draw")


def _does(state: dict, key: str) -> bool:
    """A design made before 2026-11-27 drew the plans and priced from them."""
    return bool(state.get(key, key != "permits"))


def _answers_extra(conn, ctx, state) -> str:
    """The trades' questions the AI fills in, when the person ticked "Price the estimate"."""
    if not _does(state, "price"):
        return ""
    from estimator.design import trade_answers
    from estimator.modules import get_registry
    return trade_answers.prompt_part(get_registry(), _wanted_trades(conn, ctx, state), _does(state, "permits"),
                                     _does(state, "draw"))


def start(conn, ctx: RequestContext, estimate_id: int, trade: str, request: str, plan_set_id: int,
          specs: str = "", open_conn=None, images=None, keep_approved=None, auto_approve=None, do=None) -> dict:
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
    old = load(est["id"], trade)
    if old and old.get("status") == "working":
        raise InvalidInput("an AI design is already running on this project - wait for it to finish")
    if trade == PLANS:
        # plans from a description: nothing to read - the description is the plans (2026-11-24)
        state = {"id": int(time.time()), "estimate_id": est["id"], "trade": trade, "status": "working",
                 "step": "the AI is laying out the job", "error": None, "request": request,
                 "specs": (specs or "").strip(), "plan_set_id": None, "building": None, "design": None, "findings": [],
                 "rev": int((old or {}).get("rev") or 0), "revisions": [],
                 "approved_plan_set_ids": (old or {}).get("approved_plan_set_ids") or [],
                 "approved_sheets": (old or {}).get("approved_sheets") or {}, "cost_usd": 0.0, "created_at": _now(),
                 "project": est.get("title") or f"Project {est['id']}", "address": est.get("address") or "",
                 "trades": _project_trades(conn, ctx, est),
                 "pending_shots": save_shots(est["id"], trade, images, f"start{int(time.time())}")}
        # what's on the project from this design so far stays known: the new drawing replaces it, Discard puts it back
        for k in ("placed", "approved_rev", "approved_design", "keep_approved", "auto_approve"):
            if (old or {}).get(k) is not None:
                state[k] = old[k]
        _options(state, keep_approved, auto_approve)
        _do_options(state, do)
        save(state)
        run, holder = _job(open_conn, ctx, est["id"], trade, _new_work)
        _launch(conn, run, holder, open_conn)
        return public(load(est["id"], trade))
    if not plan_set_id:
        raise InvalidInput("pick the plan set the design goes on", field="plan_set_id")
    ps = store.load_plan_set(conn, ctx, int(plan_set_id))
    if ps["estimate_id"] != est["id"]:
        raise NotFound(f"plan set {plan_set_id} isn't on this project", plan_set_id=plan_set_id)
    if ps["file_type"] != "dxf" and ps["status"] != "processed":
        raise InvalidInput(f"{ps['original_name']} hasn't been read yet - read the plans first (📖 on the project page)",
                           field="plan_set_id")
    keep_building = old and old.get("building") and old.get("plan_set_id") == ps["id"]
    shots = save_shots(est["id"], trade, images, f"start{int(time.time())}")
    state = {"id": int(time.time()), "estimate_id": est["id"], "trade": trade, "status": "working",
             "step": "reading the building", "error": None, "request": request, "specs": (specs or "").strip(),
             "plan_set_id": ps["id"], "building": old["building"] if keep_building else None, "design": None,
             "findings": [], "rev": int((old or {}).get("rev") or 0), "revisions": [],
             "approved_plan_set_ids": (old or {}).get("approved_plan_set_ids") or [], "cost_usd": 0.0,
             "created_at": _now(), "pending_shots": shots}
    for k in ("placed", "approved_rev", "approved_design", "approved_sheets"):   # what this design put on the project
        if (old or {}).get(k) is not None:
            state[k] = old[k]
    save(state)
    run, holder = _job(open_conn, ctx, est["id"], trade, _new_work)
    _launch(conn, run, holder, open_conn)
    return public(load(est["id"], trade))


def _project_trades(conn, ctx, est: dict) -> list[str]:
    """The trades this project quotes: the Director's picked trades, then the ones priced on the estimate."""
    out = []
    try:
        from estimator.director import engine as director
        from estimator.director import jobs as jobstore
        row = conn.execute("SELECT id FROM director_jobs WHERE company_id = ? AND estimate_id = ? ORDER BY id DESC LIMIT 1",
                           (ctx.company_id, est["id"])).fetchone()
        if row:
            out += director.project_trades(jobstore.load_job(conn, ctx, row[0]))
    except Exception:  # noqa: BLE001 - no Director job: the estimate's trades say it
        pass
    from estimator.estimating import service
    out += [s["module_id"] for s in est.get("sections") or [] if s["module_id"] != service.CUSTOM_MODULE]
    return list(dict.fromkeys(out))


def _new_work(conn, ctx, state):
    if state["trade"] == PLANS:
        from estimator.design import describe
        _plans_step(conn, ctx, state, describe.design_prompt(state["request"], state["specs"],
                                                             state.get("trades"), state.get("address") or "",
                                                             _answers_extra(conn, ctx, state)),
                    "design", state["request"], state.pop("pending_shots", None))
        return _after_redraw(conn, ctx, state)
    from estimator.design import electrical
    if not state.get("building"):
        state["building"] = _read_building(conn, ctx, state)
        save(state)
    _design_step(conn, ctx, state, electrical.design_prompt(state["building"], state["request"], state["specs"]),
                 "design", state["request"], state.pop("pending_shots", None))
    _after_electrical_redraw(conn, ctx, state)


def change(conn, ctx: RequestContext, estimate_id: int, trade: str, text: str, open_conn=None, images=None,
           keep_approved=None, auto_approve=None, do=None) -> dict:
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
    if trade == PLANS:
        _options(state, keep_approved, auto_approve)
        _do_options(state, do)
    state["_was"] = "proposed"
    state["status"], state["step"], state["error"], state["pending_change"] = "working", "the AI is making the change", \
        None, text
    save(state)
    run, holder = _job(open_conn, ctx, est["id"], trade, _change_work)
    _launch(conn, run, holder, open_conn)
    return public(load(est["id"], trade))


def _change_work(conn, ctx, state):
    text = state.pop("pending_change", "")
    if state["trade"] == PLANS:
        from estimator.design import describe
        _plans_step(conn, ctx, state, describe.change_prompt(state["design"], text, state["request"],
                                                             state.get("specs") or "", _answers_extra(conn, ctx, state)),
                    "change", text, state.pop("pending_shots", None))
        return _after_redraw(conn, ctx, state)
    from estimator.design import electrical
    _design_step(conn, ctx, state, electrical.change_prompt(state["building"], state["design"], text, state["request"],
                                                            state.get("specs") or ""), "change", text,
                 state.pop("pending_shots", None))
    _after_electrical_redraw(conn, ctx, state)


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
    # 2026-11-25: the design's own drawing is on the Measure screen already - it's what's approved, not what's replaced
    placed = state.get("placed") or {}
    here = set(placed.get("plan_set_ids") or []) if placed.get("rev") == state.get("rev") else set()
    old = []
    for r in rows:
        if r["id"] in gone or r["id"] in here:
            continue                                    # replaced already, or the design's drawing itself
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
    old_ids = [r["id"] for r in old] + list(here)
    marks = ",".join("?" * len(old_ids)) or "NULL"
    others = []
    for m in conn.execute(
            "SELECT m.id, m.status, m.feeds, m.calc_json FROM measurements m LEFT JOIN sheets s ON s.id = m.sheet_id"
            f" WHERE m.company_id = ? AND m.estimate_id = ? AND m.module_id = ? AND m.status != 'rejected'"
            f" AND (s.plan_set_id IS NULL OR s.plan_set_id NOT IN ({marks}))",
            (ctx.company_id, int(estimate_id), state["trade"], *old_ids)):
        calc = json.loads(m["calc_json"] or "{}")
        if here and calc.get("from") == "plans":
            continue        # counted from the design's drawing on the Measure screen (a new number waits beside it)
        others.append({"id": m["id"], "status": m["status"], "feeds": m["feeds"]})
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


def approve(conn, ctx: RequestContext, estimate_id: int, trade: str, confirm: bool = False, open_conn=None,
            keep_approved=None) -> dict:
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
    if trade == PLANS:
        from estimator.design import describe, draw_plans
        keys = describe.sheets_for(state["design"])
        keep = bool(state.get("keep_approved", True) if keep_approved is None else keep_approved)
        if not confirm and not _does(state, "draw"):
            # 2026-11-27: no drawing - approving prices the trades from the AI's answers
            names = [a["name"] for a in _answers_shown(state)]
            raise ConfirmationRequired(
                f"Approve AI design revision {state['rev']}? "
                + (("It fills in " + ", ".join(names) + " on the estimate from your description and prices "
                    + ("it" if len(names) == 1 else "them") + ".") if names else
                   "It has no answers for the estimate's trades - nothing would be priced.")
                + (" Permit and inspection answers are included." if _does(state, "permits") else "")
                + " No plans are drawn. Call again with confirm=true.",
                rev=state["rev"], counts=describe.summary(state["design"]), sheets=[], keep_approved=keep)
        if not confirm:
            placed = state.get("placed") or {}
            here = placed.get("rev") == state["rev"] and placed.get("plan_set_ids")
            raise ConfirmationRequired(
                f"Approve the AI plans (revision {state['rev']}: " + ", ".join(draw_plans.SHEETS[k] for k in keys)
                + ")? " + ("They're the drawing on the Measure screen now." if here else
                           "They become this project's plans and the app reads and measures them.")
                + " Their measurements are approved, what you'd approved before takes the new drawing's numbers, anything"
                  " that isn't on it any more is taken off, and "
                + ("the estimate's prices are updated" + (" (what the drawing doesn't measure is filled in from your"
                                                          " description)" if _answers_shown(state) else "")
                   if _does(state, "price") else "the estimate's prices stay as they are (Price the estimate is off)")
                + ". Call again with confirm=true.",
                rev=state["rev"], counts=describe.summary(state["design"]), sheets=keys, keep_approved=keep)
        state["_was"], state["status"], state["error"] = state["status"], "working", None
        state["step"] = "approving the drawing"
        state["approval"], state["pending_keep_approved"] = None, keep
        save(state)
        run, holder = _job(open_conn, ctx, est["id"], trade, _approve_plans_work)
        _launch(conn, run, holder, open_conn)
        out = public(load(est["id"], trade))
        if out["status"] == "approved":
            out["say"] = (out.get("approval") or {}).get("say") or "Approved."
        return out
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
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import plan_delete
    est_id, trade = state["estimate_id"], state["trade"]
    done = {"replaced": [], "rejected": 0, "plan_set_ids": [], "counted": 0, "wired": 0, "approved": 0,
            "estimate": None, "todo": [], "say": "", "changed": 0, "removed": 0}

    def step(text):
        state["step"] = "approving: " + text
        save(state)

    # 1. the design's drawing is on the Measure screen already (2026-11-25: every design and change goes there when it's
    #    drawn); one drawn before that is put there now. The person's older electrical drawings go (with what was
    #    measured on them), the way a new revision replaces the old one.
    placed = state.get("placed") or {}
    if placed.get("rev") != state["rev"] or not placed.get("plan_set_ids"):
        _place_electrical(conn, ctx, state, step=step)
    placed = state["placed"]
    done["todo"] += placed.get("todo") or []
    r = replaced_by_design(conn, ctx, est_id, state)
    made = [placed["sheets"][k] for k in ("plan", "panel") if placed["sheets"].get(k)]
    for x in (r["plan"], r["panel"], *r["extra"]):
        if x:
            plan_delete.delete_plan_set(conn, ctx, x["id"], confirm=True)
            done["replaced"].append(x["original_name"])
    conn.commit()
    # from here on the design IS approved: a later step that can't finish says what to do by hand
    state.pop("_was", None)
    state["status"], state["approved_plan_set_ids"], state["approved_at"] = "approved", made, _now()
    state["approved_rev"], state["approved_sheets"], state["approved_design"] = state["rev"], placed["sheets"], \
        state["design"]
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
    # 3./4. the drawing was read and every device counted when it was put on the Measure screen (exact - the app drew
    #    the symbols): its counts are approved, a count the drawing changed takes the new number, a device that isn't on
    #    it any more is taken off (2026-11-25: the drawing is the latest)
    ids, zero = [], set()
    step("approving the device counts")
    try:
        ids += [m["id"] for m in _plans_ms(conn, ctx, est_id, [trade], ("proposed",))]
        done["counted"] = len(ids) + sum(1 for m in _plans_ms(conn, ctx, est_id, [trade], ("approved",)))
        for m in _plans_ms(conn, ctx, est_id, [trade], ("approved",)):
            if (m.get("suggested_reason") or "").startswith(GONE):
                ms.reject(conn, ctx, m["id"], f"not on the approved AI design (revision {state['rev']})", confirm=True)
                zero.add(m["feeds"])
                done["removed"] += 1
            elif m.get("suggested_qty") is not None:
                ms.confirm_measurements(conn, ctx, [m["id"]], accept_suggestion=True, confirm=True)
                done["changed"] += 1
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        later("approving the device counts", "approve them in Measure (or ✓ Reviews)", exc)
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
        done["estimate"] = _update_estimate(conn, ctx, est_id, trade, zero)
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        later("updating the estimate", "click 🔄 Update from the plans on the estimate", exc)
    return _approve_done(state, done)


# ------------------------------------------------------------------ plans: every redraw is on the Measure screen
# 2026-11-25 (David: "lets always show the latest drawing to not confuse the user, then the user still need to approve the
# new drawing, dont auto approve unless the user selects that and also conform to the keep approved items on rerun unless
# that item has been removed"). Each drawing the AI makes is PUT IN PLACE at once (_place_plans): its sheets replace the
# ones on the project, the plan engine reads them, and every trade the plans answer is measured - as proposals. What a
# person already approved stays approved: a different number waits beside it as a suggested change, and an item the new
# drawing doesn't have any more waits as a suggested 0 (GONE). Approving (_approve_placed) is the person accepting the
# drawing: the proposals are approved, the items that are gone are taken off, approved items keep their numbers when
# "Keep approved items on rerun" is ticked (the suggestions stay for the person) and take the new ones when it isn't, and
# the estimate is priced. "Approve automatically" does that right after each drawing. 🗑 Discard puts the approved drawing
# back.
GONE = "not on AI design revision"


def _plans_ms(conn, ctx, est_id: int, trades: list[str], statuses=("proposed", "approved")) -> list[dict]:
    """The measurements made from the plans (calc from == 'plans') of these trades."""
    if not trades:
        return []
    q_t, q_s = ",".join("?" * len(trades)), ",".join("?" * len(statuses))
    out = []
    for r in conn.execute(f"SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ? AND module_id IN ({q_t})"
                          f" AND status IN ({q_s}) ORDER BY id", (ctx.company_id, est_id, *trades, *statuses)):
        r = dict(r)
        calc = json.loads(r.get("calc_json") or "{}")
        if calc.get("from") == "plans":
            r["_calc"] = calc
            out.append(r)
    return out


def _wanted_trades(conn, ctx, state) -> list[str]:
    from estimator.estimating import service
    est = service.get_estimate(conn, ctx, state["estimate_id"])
    return list(dict.fromkeys((state.get("trades") or []) + _project_trades(conn, ctx, est)))


def _place_plans(conn, ctx, state, rev: int | None = None, keys: list[str] | None = None, redraw: bool = False,
                 step=None) -> dict:
    """Put one revision's sheets on the project in place of the ones this design put there before, read them and propose
    their measurements (above). state["placed"] says what's there. Nothing is approved or priced here."""
    from estimator.building import trades as plan_trades
    from estimator.design import describe, draw_plans
    from estimator.drawing_model import engine, store
    from estimator.takeoff import plan_delete
    step = step or (lambda text: None)
    est_id = state["estimate_id"]
    rev = int(rev or state["rev"])
    keys = keys or describe.sheets_for(state["design"])
    placed = {"rev": rev, "sheets": {}, "plan_set_ids": [], "measured": {}, "answered": [], "auto_run": [], "gone": [],
              "todo": [], "at": _now()}

    def later(what, how, exc):
        placed["todo"].append(f"{what} didn't finish ({exc}) - {how}")

    # 1. the sheets: each replaces the one this design put there before (a sheet the drawing doesn't have any more goes)
    step("putting the new drawing on the Measure screen")
    live = {r["id"] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?",
                                          (ctx.company_id, est_id))}
    gone_by = {r[0] for r in conn.execute("SELECT supersedes_plan_set_id FROM plan_sets WHERE company_id = ? AND"
                                          " estimate_id = ? AND supersedes_plan_set_id IS NOT NULL", (ctx.company_id, est_id))}
    had = (state.get("placed") or {}).get("sheets") or state.get("approved_sheets") or {}
    before = {k: v for k, v in had.items() if v in live and v not in gone_by}
    tmpdir = folder(est_id) / f"place_plans_rev{rev}"
    tmpdir.mkdir(exist_ok=True)
    for key in keys:
        src = sheet_path(est_id, rev, key)
        if redraw or not src.is_file():
            draw_plans.DRAW[key](state["design"], str(src), state.get("project") or "Project")
        dst = tmpdir / f"{draw_plans.SHEETS[key]}.dxf"
        shutil.copyfile(src, dst)
        up = store.upload(conn, ctx, est_id, str(dst), before.get(key), confirm=True, design_firm="AI design (AI-Prowler)")
        placed["plan_set_ids"].append(up["plan_set_id"])
        placed["sheets"][key] = up["plan_set_id"]
    for key, pid in before.items():
        if key not in placed["sheets"]:
            plan_delete.delete_plan_set(conn, ctx, pid, confirm=True)
    conn.commit()
    state["placed"] = placed
    save(state)
    # 2. read them (small CAD files: read here)
    step("reading the new drawing")
    try:
        for pid in placed["plan_set_ids"]:
            engine.start(conn, ctx, pid, confirm=True, open_conn=None)
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        later("reading the new drawing", "read it on the project page (📖), then run 🤖 AI Auto Measure/Count", exc)
        state["placed"] = placed
        return placed
    # 3. measure every trade the plans answer - as proposals. The suggestions an earlier drawing left are worked out
    #    again from this one first.
    live = {r["id"] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?",
                                          (ctx.company_id, est_id))}
    others = live - set(placed["plan_set_ids"])                 # plans this design didn't draw (a designer's upload)
    wanted = _wanted_trades(conn, ctx, state)
    # what the design itself answers (2026-11-25: concrete from its own foundation plan and flatwork - no AI call)
    design = state["design"] if rev == int(state.get("rev") or 0) else (state.get("approved_design") or state["design"])
    own = {}
    if "concrete" in wanted:
        c = describe.concrete_answers(design or {})
        if c:
            own["concrete"] = {"answers": c, "source": "the AI design's foundation and site plans", "method": "cad",
                               "plan_set_ids": placed["plan_set_ids"],
                               "from": {k: "the slab and flatwork outlines on the AI design" for k in c}}
    placed["choices"] = {t: {k: v for k, v in f["answers"].items() if isinstance(v, str)} for t, f in own.items()}
    plan_wanted = [t for t in wanted if t in plan_trades.TRADES or t in own]
    placed["auto_run"] = [t for t in wanted if t not in plan_wanted]
    _measure_placed(conn, ctx, est_id, placed, plan_wanted, own, others, step)
    state["placed"] = placed
    save(state)
    return placed


def _measure_placed(conn, ctx, est_id: int, placed: dict, trades: list[str], own: dict, others: set, step,
                    plan_set_id: int | None = None) -> None:
    """Measure the drawing just put on the Measure screen, trade by trade, as proposals (above): an approved item the
    drawing measures differently gets the new number beside it; one the drawing doesn't have any more (and no other
    plans on the project back) gets a suggested 0, taken off when the drawing is approved; a proposal from an earlier
    drawing that isn't on this one goes. The suggestions an earlier drawing left are worked out again from this one."""
    from estimator.takeoff import from_plans
    from estimator.takeoff import measurements as ms
    rev = placed["rev"]
    for m in _plans_ms(conn, ctx, est_id, trades, ("approved",)):
        if m.get("suggested_qty") is not None:
            conn.execute("UPDATE measurements SET suggested_qty = NULL, suggested_by = NULL, suggested_reason = NULL,"
                         " suggested_at = NULL WHERE id = ?", (m["id"],))
    conn.commit()
    for t in trades:
        step(f"measuring {t.replace('_', ' ')}")
        now_feeds = set()
        try:
            out = from_plans.propose(conn, ctx, est_id, t, include_proposed=True, confirm=True, plan_set_id=plan_set_id,
                                     found=dict(own[t]) if t in own else None)
            now_feeds = {p["feeds"] for p in out.get("plan") or []}
            placed["measured"][t] = sum(1 for p in out.get("plan") or [] if p["action"] in ("new", "update", "suggest"))
            placed["answered"].append(t)
        except InvalidInput:
            placed["measured"][t] = 0                     # the plans don't answer this trade
        except Exception as exc:  # noqa: BLE001
            placed["todo"].append(f"measuring {t} didn't finish ({exc}) - run 🤖 AI Auto Measure/Count on the Measure screen")
            continue
        for m in _plans_ms(conn, ctx, est_id, [t]):
            if m["feeds"] in now_feeds or set(m["_calc"].get("plan_set_ids") or []) & others:
                continue
            if m["status"] == "proposed":
                conn.execute("DELETE FROM measurements WHERE id = ?", (m["id"],))
            else:
                ms.suggest_change(conn, ctx, m["id"], "0", f"{GONE} {rev} - it's taken off when you approve the drawing",
                                  confirm=True)
                placed["gone"].append(m["id"])
                if t not in placed["answered"]:
                    placed["answered"].append(t)
        conn.commit()


def _electrical_sheets(conn, ctx, state) -> dict:
    """{plan, panel} plan set ids this electrical design put on the project (on Measure now, else the approved ones)."""
    placed = state.get("placed") or {}
    if placed.get("sheets"):
        return dict(placed["sheets"])
    if state.get("approved_sheets"):
        return dict(state["approved_sheets"])
    ids = list(state.get("approved_plan_set_ids") or [])        # approved before 2026-11-25: the plan, then the panel
    return {k: v for k, v in zip(("plan", "panel"), ids)}


def _place_electrical(conn, ctx, state, rev: int | None = None, step=None) -> dict:
    """2026-11-25 (David: "the electrical and cement as well"): an electrical design's plan and panel schedule go on the
    Measure screen the moment they're drawn - in place of the ones this design put there before (the person's own older
    electrical drawings stay until the design is approved) - read, and every device counted as a proposal."""
    from estimator.design import draw_electrical as dr
    from estimator.drawing_model import engine, store
    step = step or (lambda text: None)
    est_id, trade = state["estimate_id"], state["trade"]
    rev = int(rev or state["rev"])
    design = state["design"] if rev == int(state.get("rev") or 0) else (state.get("approved_design") or state["design"])
    placed = {"rev": rev, "sheets": {}, "plan_set_ids": [], "measured": {}, "answered": [], "auto_run": [], "gone": [],
              "todo": [], "at": _now(), "choices": {}}
    step("putting the new drawing on the Measure screen")
    title = f"{(state.get('building') or {}).get('name') or 'Building'} - electrical"
    if rev == int(state.get("rev") or 0) or not file_path(est_id, trade, rev, "plan").is_file():
        dr.draw_plan(state["building"], design, str(file_path(est_id, trade, rev, "plan")), title)
        dr.draw_panel(design, str(file_path(est_id, trade, rev, "panel")), title)
    live = {r["id"] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?",
                                          (ctx.company_id, est_id))}
    gone_by = {r[0] for r in conn.execute("SELECT supersedes_plan_set_id FROM plan_sets WHERE company_id = ? AND"
                                          " estimate_id = ? AND supersedes_plan_set_id IS NOT NULL", (ctx.company_id, est_id))}
    before = {k: v for k, v in _electrical_sheets(conn, ctx, state).items() if v in live and v not in gone_by}
    nice = {"plan": f"AI design - {trade} plan.dxf", "panel": f"AI design - {trade} panel schedule.dxf"}
    tmpdir = folder(est_id) / f"place_{trade}_rev{rev}"
    tmpdir.mkdir(exist_ok=True)
    for what in ("plan", "panel"):
        dst = tmpdir / nice[what]
        shutil.copyfile(file_path(est_id, trade, rev, what), dst)
        up = store.upload(conn, ctx, est_id, str(dst), before.get(what), confirm=True, design_firm="AI design (AI-Prowler)")
        placed["sheets"][what] = up["plan_set_id"]
        placed["plan_set_ids"].append(up["plan_set_id"])
    conn.commit()
    state["placed"] = placed
    save(state)
    step("reading the new drawing")
    try:
        for pid in placed["plan_set_ids"]:
            engine.start(conn, ctx, pid, confirm=True, open_conn=None)
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        placed["todo"].append(f"reading the new drawing didn't finish ({exc}) - read it on the project page (📖)")
        return placed
    live = {r["id"] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?",
                                          (ctx.company_id, est_id))}
    step("counting the devices")
    _measure_placed(conn, ctx, est_id, placed, [trade], {}, live - set(placed["plan_set_ids"]), step,
                    plan_set_id=placed["sheets"]["plan"])
    state["placed"] = placed
    save(state)
    return placed


def _after_electrical_redraw(conn, ctx, state) -> None:
    """A new electrical design or change goes on the Measure screen at once (it still waits for approval)."""
    def step(text):
        state["step"] = text
        save(state)
    if state.get("status") != "proposed":
        return
    try:
        _place_electrical(conn, ctx, state, step=step)
    except Exception as exc:  # noqa: BLE001 - the design is made; it's put in place when it's approved
        state["placed"] = {**(state.get("placed") or {}), "todo": [f"putting it on the Measure screen didn't finish "
                                                                    f"({type(exc).__name__}: {exc}) - approve it to try again"]}
    state["status"], state["step"] = "proposed", ""
    save(state)


def _approve_placed(conn, ctx, state, keep_approved: bool, done: dict, step=None, price: bool = True) -> None:
    """The person accepts the drawing on the Measure screen (above): approve, take off, keep or update, and price
    (unless the person unticked "Price the estimate", 2026-11-27 - then the measurements are approved and the prices
    stay as they are)."""
    from estimator.takeoff import measurements as ms
    step = step or (lambda text: None)
    est_id, placed = state["estimate_id"], state["placed"]
    trades = list(dict.fromkeys(placed["answered"] + list(placed["measured"])))
    done.update(plan_set_ids=placed["plan_set_ids"], measured=dict(placed["measured"]), auto_run=placed["auto_run"])
    done["todo"] += placed.get("todo") or []
    zero: dict[str, set] = {}
    step("approving the measurements")
    try:
        new = [m["id"] for m in _plans_ms(conn, ctx, est_id, trades, ("proposed",))]
        approved = _plans_ms(conn, ctx, est_id, trades, ("approved",))
        gone = [m for m in approved if (m.get("suggested_reason") or "").startswith(GONE)]
        changed = [m["id"] for m in approved if m.get("suggested_qty") is not None and m not in gone]
        for m in gone:
            ms.reject(conn, ctx, m["id"], f"not on the approved AI design (revision {placed['rev']})", confirm=True)
            zero.setdefault(m["module_id"], set()).add(m["feeds"])
        if new:
            ms.confirm_measurements(conn, ctx, new, confirm=True)
        # 2026-11-25 (David: "pre assume that he made the changes for a good reason ... a change to the drawing is treated
        # like the current one and estimates are based on it"): what the new drawing measures differently takes its new
        # number - the drawing is the latest. (Keep approved items on rerun is for AI Auto Measure/Count reruns.)
        if changed:
            ms.confirm_measurements(conn, ctx, changed, accept_suggestion=True, confirm=True)
        done["approved"] = len(new)
        done["changed"] = len(changed)
        done["removed"] = len(gone)
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        done["todo"].append(f"approving the measurements didn't finish ({exc}) - approve them in Measure (or ✓ Reviews)")
    step("updating the estimate")
    done["not_priced"] = not price
    for t in trades if price else []:
        try:
            r = _price_from_plans(conn, ctx, est_id, t, zero.get(t), (placed.get("choices") or {}).get(t))
            if r == "updated":
                done["updated"].append(t)
            elif r == "needs_reopen":
                done["todo"].append(f"{t}: the estimate is approved or sent, so its prices didn't change - open the "
                                    "estimate and click 🔄 Update from the plans (it reopens it and takes the plans' "
                                    "quantities, material and height)")
            elif r == "nothing" and placed["measured"].get(t):
                done["todo"].append(f"{t}: add the trade to the estimate, then 🔄 Update from the plans")
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            done["todo"].append(f"updating {t} didn't finish ({exc}) - click 🔄 Update from the plans on the estimate")
    state["approved_plan_set_ids"], state["approved_sheets"] = placed["plan_set_ids"], placed["sheets"]
    state["approved_rev"], state["approved_at"] = placed["rev"], _now()
    state["approved_design"] = state.get("design")
    state.pop("_was", None)


def _new_done() -> dict:
    return {"plan_set_ids": [], "measured": {}, "approved": 0, "updated": [], "auto_run": [], "todo": [], "say": ""}


def _after_redraw(conn, ctx, state) -> None:
    """A new drawing (a design or a change) goes on the Measure screen at once; approved too when the person asked for
    that (auto_approve) and the check found no error."""
    def step(text):
        state["step"] = text
        save(state)
    drawing = _does(state, "draw")
    if drawing:
        try:
            _place_plans(conn, ctx, state, step=step)
        except Exception as exc:  # noqa: BLE001 - the drawing is made; it's put in place again when it's approved
            state["placed"] = {**(state.get("placed") or {}), "todo": [
                f"putting it on the Measure screen didn't finish ({type(exc).__name__}: {exc}) - approve it to try again"]}
    state["status"], state["step"] = "proposed", ""
    errors = sum(1 for f in state.get("findings") or [] if f["level"] == "error")
    if state.get("auto_approve") and not errors and (not drawing or (state.get("placed") or {}).get("rev") == state["rev"]):
        return _approve_plans_work(conn, ctx, state, auto=True)
    save(state)


def _approve_plans_work(conn, ctx, state, auto: bool = False):
    """Plans from a description, approved: the drawing on the Measure screen is accepted (above). A drawing made before it
    went on the Measure screen by itself (before 2026-11-25) is put there first. Then (2026-11-27, "Price the estimate")
    the trades the drawing doesn't measure are priced from the AI's own answers to their questions; without "Draw the
    plans" every quoted trade is."""
    done = _new_done()
    keep = bool(state.pop("pending_keep_approved", state.get("keep_approved", True)))

    def step(text):
        state["step"] = "approving: " + text
        save(state)
    if _does(state, "draw"):
        if (state.get("placed") or {}).get("rev") != state["rev"] or not (state.get("placed") or {}).get("plan_set_ids"):
            _place_plans(conn, ctx, state, redraw=True, step=step)
        _approve_placed(conn, ctx, state, keep, done, step=step, price=_does(state, "price"))
    else:
        state["approved_rev"], state["approved_at"] = state["rev"], _now()
        state["approved_design"] = state.get("design")
    if _does(state, "price"):
        _price_from_answers(conn, ctx, state, done, step)
    done["auto"] = auto
    return _plans_done(state, done)


def _price_from_answers(conn, ctx, state, done: dict, step) -> None:
    """Price each quoted trade from the AI's answers to its questions (trade_answers.py) - on top of what the estimate
    already says, with the approved measurements over them (a person's or a drawing's measure wins). A trade the drawing
    priced only takes the permit and inspection answers (when asked for). Nothing the trade doesn't take is used."""
    from estimator.design import trade_answers
    from estimator.estimating import quick, service
    from estimator.modules import get_registry
    from estimator.takeoff import measurements as ms
    reg = get_registry()
    est_id = state["estimate_id"]
    permits = _does(state, "permits")
    got = (state.get("design") or {}).get("trade_answers") or {}
    quoted = _wanted_trades(conn, ctx, state)
    done.setdefault("answered", [])
    for t in [t for t in quoted if t in got] + [t for t in got if t not in quoted and t in reg.modules]:
        mod = reg.modules.get(t)
        if mod is None:
            continue
        ans, _dropped = trade_answers.clean(mod, got.get(t), permits)
        if t in done["updated"]:
            ans = {k: v for k, v in ans.items() if trade_answers.is_permit_question(k)}   # the drawing priced it
        if not ans:
            continue
        step(f"pricing {mod.name.lower()} from the description")
        try:
            est = service.get_estimate(conn, ctx, est_id)
            if est["status"] not in service.EDITABLE_STATUSES:
                done["todo"].append(f"{mod.name}: the estimate is approved or sent, so it wasn't priced - make a new "
                                    "version of it (or reopen it), then run AI design again")
                continue
            sec = next((s for s in est["sections"] if s["module_id"] == t), None)
            ids = {q.id for q in mod.questions}
            have = {k: v for k, v in ((sec or {}).get("answers") or {}).items() if k in ids and v not in (None, "")}
            measured = {k: v for k, v in (ms.approved_answers(conn, ctx, est_id, t).get(t) or {}).items() if k in ids}
            answers = {**have, **ans, **measured}
            if sec and all(have.get(k) == v for k, v in answers.items()):
                continue
            quick.answer(conn, ctx, est_id, t, answers, int(est["rev"]), reg)
            conn.commit()
            if t not in done["updated"]:
                done["updated"].append(t)
            done["answered"].append(t)
            if t in done["auto_run"]:
                done["auto_run"].remove(t)                  # priced from the description - nothing left to measure
        except InvalidInput as exc:
            done["todo"].append(f"{mod.name} wasn't priced ({exc}) - fill it in on the estimate")
        except Exception as exc:  # noqa: BLE001
            done["todo"].append(f"pricing {mod.name} didn't finish ({type(exc).__name__}: {exc}) - fill it in on the "
                                "estimate")


def _unplace(conn, ctx, state) -> None:
    """🗑 Discard after a drawing was put on the Measure screen: its proposals go, and the approved drawing goes back
    (with its measurements as they were); with nothing approved yet, its sheets go too."""
    from estimator.design import draw_plans
    from estimator.takeoff import plan_delete
    est_id, placed = state["estimate_id"], state.get("placed") or {}
    trades = list(dict.fromkeys((placed.get("answered") or []) + list((placed.get("measured") or {}))))
    for m in _plans_ms(conn, ctx, est_id, trades, ("proposed",)):
        conn.execute("DELETE FROM measurements WHERE id = ?", (m["id"],))
    for m in _plans_ms(conn, ctx, est_id, trades, ("approved",)):
        conn.execute("UPDATE measurements SET suggested_qty = NULL, suggested_by = NULL, suggested_reason = NULL,"
                     " suggested_at = NULL WHERE id = ?", (m["id"],))
    conn.commit()
    ar = approved_rev(state)
    if state.get("trade") != PLANS:                    # electrical: the approved plan and panel schedule go back
        if ar and file_path(est_id, state["trade"], ar, "plan").is_file() and \
                file_path(est_id, state["trade"], ar, "panel").is_file():
            _place_electrical(conn, ctx, state, rev=ar)
            return
    keys = [k for k in (state.get("approved_sheets") or {}) if k in draw_plans.SHEETS]
    if state.get("trade") == PLANS and ar and keys and all(sheet_path(est_id, ar, k).is_file() for k in keys):
        _place_plans(conn, ctx, state, rev=ar, keys=keys)
        return
    live = {r["id"] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?",
                                          (ctx.company_id, est_id))}
    for pid in placed.get("plan_set_ids") or []:
        if pid in live and pid not in (state.get("approved_plan_set_ids") or []):
            plan_delete.delete_plan_set(conn, ctx, pid, confirm=True)
    conn.commit()
    state["placed"] = None


def _price_from_plans(conn, ctx, est_id: int, trade: str, zero: set | None = None, choices: dict | None = None) -> str:
    """Price one trade from approved plans: the trade's answers on the estimate, then what the plan reader answers
    (the design the person approved), then the approved measurements on top. A trade the project quotes that isn't on
    the estimate yet is added. Returns updated / unchanged / needs_reopen / nothing."""
    from estimator.building import trades as plan_trades
    from estimator.estimating import quick, service
    from estimator.modules import get_registry
    from estimator.takeoff import measurements as ms
    reg = get_registry()
    mod = reg.modules.get(trade)
    if mod is None:
        return "nothing"
    est = service.get_estimate(conn, ctx, est_id)
    sec = next((s for s in est["sections"] if s["module_id"] == trade), None)
    if est["status"] not in service.EDITABLE_STATUSES:
        return "needs_reopen" if sec else "nothing"
    ids = {q.id for q in mod.questions}
    have = {k: v for k, v in ((sec or {}).get("answers") or {}).items() if k in ids and v not in (None, "")}
    try:
        read = (plan_trades.answers(conn, ctx, trade, estimate_id=est_id) or {}).get("answers") or {}
    except Exception:  # noqa: BLE001 - the measurements alone, then
        read = {}
    measured = ms.approved_answers(conn, ctx, est_id, trade).get(trade) or {}
    if not measured and not zero:
        return "nothing"
    plan = {k: v for k, v in {**read, **(choices or {})}.items() if k in ids and v not in (None, "")}
    # zero: what the person took off (not on the approved drawing any more) is priced as none
    gone = {k: 0 for k in (zero or set()) if k in ids and k not in measured}
    answers = {**have, **plan, **gone, **{k: v for k, v in measured.items() if k in ids}}
    if sec and all(have.get(k) == v for k, v in answers.items()):
        return "unchanged"
    try:
        quick.answer(conn, ctx, est_id, trade, answers, int(est["rev"]), reg)
    except InvalidInput:
        # a plan answer the trade doesn't take as written: the estimate's own answers and the measurements
        quick.answer(conn, ctx, est_id, trade, {**have, **gone, **{k: v for k, v in measured.items() if k in ids}},
                     int(est["rev"]), reg)
    return "updated"


def _plans_done(state: dict, done: dict) -> None:
    from estimator.design import draw_plans
    bits = [f"{len(done['plan_set_ids'])} sheet(s) are the project's plans now"] if done["plan_set_ids"] else []
    if done.get("answered"):
        bits.append("filled in " + ", ".join(t.replace("_", " ") for t in done["answered"]) + " from the description")
    if done.get("not_priced"):
        bits.append("the prices weren't changed (Price the estimate was off)")
    meas = {t: n for t, n in done["measured"].items() if n}
    if meas:
        bits.append("measured " + ", ".join(f"{t.replace('_', ' ')} ({n})" for t, n in meas.items())
                    + (" and approved them" if done["approved"] else ""))
    if done.get("removed"):
        bits.append(f"took off {done['removed']} approved item(s) that aren't on the drawing any more")
    if done.get("changed"):
        bits.append(f"{done['changed']} approved item(s) took the new drawing's numbers")
    if done["updated"]:
        bits.append("updated the estimate's " + ", ".join(t.replace("_", " ") for t in done["updated"]) + " prices")
    if done["auto_run"]:
        sheet = {"concrete": draw_plans.SHEETS["foundation"], "roofing": draw_plans.SHEETS["roof"],
                 "demolition": draw_plans.SHEETS["demolition"]}
        bits.append("next: 🤖 AI Auto Measure/Count measures " + ", ".join(
            t.replace("_", " ") + (f" (from {sheet[t]})" if t in sheet else "") for t in done["auto_run"]))
    done["say"] = ("Approved automatically: " if done.get("auto") else "Approved: ") + \
        ("; ".join(bits) if bits else "nothing on the estimate needed to change") + "."
    state["approval"] = done
    state["status"], state["step"], state["error"] = "approved", "", None
    if done["todo"]:
        state["error"] = "Approved, but " + "; ".join(done["todo"])
    save(state)


def _update_estimate(conn, ctx, est_id: int, trade: str, zero: set | None = None) -> str:
    """Re-price the trade from its approved measurements (the 🔄 Update from the plans button, for this trade only).
    An estimate that's approved or sent is left for the person: updating it reopens it. zero: what was taken off the
    drawing (2026-11-25) - priced as none."""
    from estimator.api.estimate_api import plan_changes
    from estimator.estimating import quick, service
    from estimator.modules import get_registry
    reg = get_registry()
    est = service.get_estimate(conn, ctx, est_id)
    if not any(s["module_id"] == trade for s in est["sections"]):
        return "no_trade"
    todo = [t for t in plan_changes(conn, ctx, est, reg) if t["module_id"] == trade]
    if zero:
        cur = next(s for s in est["sections"] if s["module_id"] == trade)["answers"] or {}
        z = {k: 0 for k in zero if str(cur.get(k) or 0) not in ("0", "0.0")}
        if z and todo:
            todo[0]["answers"].update(z)
        elif z:
            todo = [{"module_id": trade, "answers": {**cur, **z}}]
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
    placed = state.get("placed") or {}
    if placed.get("rev") and placed.get("rev") != approved_rev(state):
        _unplace(conn, ctx, state)         # the drawing on the Measure screen wasn't approved: the approved one goes back
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

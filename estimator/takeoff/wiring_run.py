"""The Wiring run (2026-11-19, David): the second Electrical measuring stage, on the Measure screen.

It finds the project's two CAD drawings - the electrical floor plan (devices, rooms, the panel) and the panel drawing
(the panel schedule) - runs the wiring takeoff (estimator/takeoff/wiring.py), keeps the result and the wiring DXF in
the data folder (wiring/estimate_<id>.json and .dxf), and proposes one measurement per cable size
(feeds wire_12_2_ft ...) for a person to approve, the same way AI Auto Run proposes its counts. Approved, they price
the cable on the estimate and fill the Bill of Materials; the 'average run per device' wire lines step aside.

Plain geometry: no AI tokens. Rerunning replaces the run's proposed measurements (approved ones stay).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.errors import InvalidInput
from estimator.estimating import service
from estimator.takeoff import wiring

MODULE_ID = "electrical"
PROPOSED_BY = "wiring-takeoff"
SIZE_FEEDS = {"14/2": "wire_14_2_ft", "14/3": "wire_14_3_ft", "12/2": "wire_12_2_ft", "12/3": "wire_12_3_ft",
              "10/2": "wire_10_2_ft", "10/3": "wire_10_3_ft", "8/3": "wire_8_3_ft", "6/3": "wire_6_3_ft"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _folder() -> Path:
    p = config.data_dir() / "wiring"
    p.mkdir(parents=True, exist_ok=True)
    return p


def result_path(estimate_id: int) -> Path:
    return _folder() / f"estimate_{int(estimate_id)}.json"


def dxf_path(estimate_id: int) -> Path:
    return _folder() / f"estimate_{int(estimate_id)}_wiring.dxf"


def schematic_path(estimate_id: int) -> Path:
    """2026-11-20 (David): the wiring schematic - panel, breakers and each circuit's conductors (wiring_schematic.py)."""
    return _folder() / f"estimate_{int(estimate_id)}_schematic.dxf"


def clear(estimate_id: int) -> list[str]:
    """Forget the project's last wiring run (its routes, wiring DXF and schematic). Called when a new revision of a CAD
    plan replaces the old one (2026-11-21): the old routes were drawn on sheets that are gone, so the run starts again
    on the new plans. Returns the file names removed."""
    gone = []
    for p in (result_path(estimate_id), dxf_path(estimate_id), schematic_path(estimate_id)):
        try:
            p.unlink()
            gone.append(p.name)
        except FileNotFoundError:
            pass
        except OSError:
            pass                                      # best effort: a locked file is simply replaced by the next run
    return gone


def _is_panel_drawing(path: str) -> bool:
    try:
        return bool(wiring.read_panel_schedule(path)["circuits"])
    except Exception:  # noqa: BLE001 - not a panel drawing (or not readable as one)
        return False


def sources(conn, ctx: RequestContext, estimate_id: int) -> dict:
    """The project's CAD plan files: which is the floor plan and which the panel drawing (the one with a panel
    schedule). A newer revision of a file is used over the one it replaced."""
    rows = [dict(r) for r in conn.execute(
        "SELECT id, file_path, original_name, file_type, supersedes_plan_set_id FROM plan_sets"
        " WHERE company_id = ? AND estimate_id = ? AND file_type = 'dxf' ORDER BY id", (ctx.company_id, int(estimate_id)))]
    replaced = {r["supersedes_plan_set_id"] for r in rows if r["supersedes_plan_set_id"]}
    rows = [r for r in rows if r["id"] not in replaced and r["file_path"] and Path(r["file_path"]).is_file()]
    panel = next((r for r in reversed(rows) if _is_panel_drawing(r["file_path"])), None)
    plan = next((r for r in reversed(rows) if r is not panel), None)
    out = {"plan": None, "panel": None}
    for key, r in (("plan", plan), ("panel", panel)):
        if r:
            sheet = conn.execute("SELECT id FROM sheets WHERE plan_set_id = ? ORDER BY page_no LIMIT 1",
                                 (r["id"],)).fetchone()
            out[key] = {"plan_set_id": r["id"], "name": r["original_name"], "path": r["file_path"],
                        "sheet_id": sheet["id"] if sheet else None}
    return out


# The routing options a person sets before a run (2026-11-21, David): numbers with their range, and choices.
NUMBERS = (("ceiling_ft", 7, 20), ("floor_framing_ft", 0.5, 3), ("panel_center_ft", 3, 7), ("waste", 0, 0.5),
           ("basement_ceiling_ft", 6, 12), ("wall_max_ft", 4, 40), ("receptacle_in", 6, 60), ("switch_in", 30, 60),
           ("counter_in", 36, 60), ("wall_detour", 1, 2), ("makeup_ft_per_end", 0.5, 3), ("panel_makeup_ft", 0, 10))
CHOICES = {"foundation": wiring.FOUNDATIONS, "outlets_via": wiring.VIAS, "upper_feed": ("below", "above")}
OPTION_KEYS = [k for k, _, _ in NUMBERS] + list(CHOICES) + ["panel_in_basement"]


def _settings(raw: dict | None) -> dict:
    """Only the settings a person can change, in range."""
    raw = raw or {}
    s = {}
    for key, lo, hi in NUMBERS:
        if raw.get(key) not in (None, ""):
            try:
                v = float(raw[key])
            except (TypeError, ValueError):
                raise InvalidInput(f"{key.replace('_', ' ')} should be a number", field=key) from None
            if not lo <= v <= hi:
                raise InvalidInput(f"{key.replace('_', ' ')} should be between {lo} and {hi}", field=key)
            s[key] = v
    for key, allowed in CHOICES.items():
        if raw.get(key) not in (None, ""):
            if raw[key] not in allowed:
                raise InvalidInput(f"{key.replace('_', ' ')} is one of: {', '.join(allowed)}", field=key)
            s[key] = raw[key]
    if raw.get("panel_in_basement") not in (None, ""):
        v = raw["panel_in_basement"]
        s["panel_in_basement"] = not (v is False or str(v).strip().lower() in ("0", "false", "no", "off"))
    route = {}
    for k, v in (raw.get("route") or {}).items():
        if v in (None, "", "auto"):
            continue                                   # 2026-11-21: "auto" - the routing options decide
        if v not in ("ceiling", "walls"):
            raise InvalidInput("a floor's route is 'ceiling' or 'walls'", field="route")
        route[int(k)] = v
    if route:
        s["route"] = route
    return s


# ---- the user's own routing defaults (2026-11-21, David: "I like the user setting defaults for routing wires"):
# saved per company beside the runs; a project's first run starts from them, a rerun from its last run's settings.
def _defaults_path(ctx: RequestContext) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(ctx.company_id or "personal"))
    return _folder() / f"routing_defaults_{safe}.json"


def saved_defaults(ctx: RequestContext) -> dict:
    """The routing options this company saved as its defaults ({} when none)."""
    p = _defaults_path(ctx)
    if not p.is_file():
        return {}
    try:
        return _settings(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError, InvalidInput):
        return {}


def save_defaults(ctx: RequestContext, raw: dict) -> dict:
    """Save routing options as this company's defaults (owners and estimators). Returns what was saved."""
    from estimator.takeoff import measurements as ms
    if ctx.role not in ms.PROPOSE_ROLES:
        from estimator.errors import PermissionDenied
        raise PermissionDenied(f"only {', '.join(ms.PROPOSE_ROLES)} can set the wiring defaults", role=ctx.role)
    s = {k: v for k, v in _settings(raw).items() if k != "route"}    # a floor forced by hand belongs to one project
    _defaults_path(ctx).write_text(json.dumps(s), encoding="utf-8")
    return s


def options(ctx: RequestContext, estimate_id: int | None = None) -> dict:
    """What the options box opens with: this project's last run settings, else the saved defaults, else built in -
    plus the built-in values and the saved defaults themselves (for 'back to my defaults')."""
    builtin = {k: wiring.DEFAULTS[k] for k in OPTION_KEYS}
    saved = saved_defaults(ctx)
    last = (latest(ctx, estimate_id) or {}).get("settings") if estimate_id else None
    try:
        last_s = _settings(last) if last else {}
    except InvalidInput:
        last_s, last = {}, None                        # an old run's value out of today's range: start from defaults
    current = {**builtin, **saved, **last_s}
    route = current.pop("route", {}) if isinstance(current.get("route"), dict) else {}
    return {"current": {**{k: current[k] for k in OPTION_KEYS}, "route": {str(k): v for k, v in route.items()}},
            "saved": saved, "builtin": builtin, "from": "last run" if last else ("your defaults" if saved else "built in")}


def run(conn, ctx: RequestContext, estimate_id: int, settings: dict | None = None,
        overrides: dict | None = None, keep_approved: bool = True, on_step=None) -> dict:
    """Run the wiring takeoff for an estimate and propose its cable measurements (keep_approved: see _propose).
    on_step(text): each stage as it starts, for AI Auto Run's waiting message (2026-11-21, David)."""
    say = on_step or (lambda _t: None)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    src = sources(conn, ctx, est["id"])
    if not src["plan"]:
        raise InvalidInput("upload the electrical floor plan as a DXF (CAD) file on the Plans screen first")
    # No panel drawing (2026-11-21, David: "Add the fall back"): the circuits are laid out from the floor plan the
    # usual residential way, and every circuit says so - an uploaded panel schedule is always used when there is one.
    s = {**saved_defaults(ctx), **_settings(settings)}      # the user's own defaults under what this run was given
    clean_overrides = {str(k): str(v) for k, v in (overrides or {}).items() if v}
    say("wiring: reading the panel schedule and routing each circuit from the panel" if src["panel"] else
        "wiring: no panel schedule - laying out the circuits the usual residential way, then routing them")
    try:
        result = wiring.takeoff(src["plan"]["path"], src["panel"]["path"] if src["panel"] else None, s,
                                out_path=str(dxf_path(est["id"])), overrides=clean_overrides)
    except ValueError as exc:
        raise InvalidInput(f"the wiring run couldn't read the drawings: {exc}") from None
    result.pop("dxf", None)
    routed = sum(1 for c in result["circuits"] if c.get("assigned") or c.get("devices"))
    say(f"wiring: {routed} circuits routed - drawing the wiring schematic")
    from estimator.takeoff import wiring_schematic
    wiring_schematic.write(result, str(schematic_path(est["id"])), est.get("title") or f"estimate {est['id']}")
    result["schematic"] = True
    result["settings"] = {k: v for k, v in result["settings"].items() if k != "route"} | \
        {"route": {str(k): v for k, v in result["settings"].get("route", {}).items()}}
    result["routing"] = wiring.routing_summary(result["settings"])
    result["overrides"] = clean_overrides
    result["sources"] = {k: {kk: vv for kk, vv in v.items() if kk != "path"} if v else None for k, v in src.items()}
    result["estimate_id"] = est["id"]
    result["ran_at"] = _now()
    result["ran_by"] = ctx.user_id
    result["overlay"] = _overlay(conn, src["plan"]["sheet_id"], result)
    result["keep_approved"] = bool(keep_approved)
    say(f"wiring: proposing the cable lengths ({len(result.get('bom') or [])} cable sizes) and breaker counts")
    result["measurement_ids"] = _propose(conn, ctx, est["id"], src["plan"]["sheet_id"], result, bool(keep_approved))
    result_path(est["id"]).write_text(json.dumps(result, default=float), encoding="utf-8")
    return result


def _overlay(conn, sheet_id, result: dict) -> dict | None:
    """The routes in the Measure screen's sheet coordinates, so they can be drawn on the plan. The plan reader puts a
    CAD sheet's top-left corner at the drawing's extents and turns y downward (x - left, top - y, in drawing units);
    the panel symbol, which both sides know, gives that corner."""
    panel = result.get("panel")
    if not sheet_id or not panel:
        return None
    k = float(result.get("units_ft") or 1.0)
    row = conn.execute("SELECT geometry_json FROM drawing_objects WHERE sheet_id = ? AND kind = 'symbol'"
                       " AND UPPER(COALESCE(block_name, '')) LIKE '%PANEL%' ORDER BY id", (sheet_id,)).fetchall()
    px, py = panel["x"] / k, panel["y"] / k
    best = None
    for r in row:                                   # the plan's panel, not the legend's: the one nearest a sane corner
        g = json.loads(r["geometry_json"])
        sx, sy = g["points"][0]
        left, top = px - sx, sy + py
        if best is None or abs(left) + abs(top) < abs(best[0]) + abs(best[1]):
            best = (left, top)
    if best is None:
        return None
    left, top = best

    def to_sheet(p):
        return [round(p[0] / k - left, 3), round(top - p[1] / k, 3)]
    return {"circuits": [{"id": c["id"], "wire": c["wire"],
                          "lines": ([[to_sheet(p) for p in c["home_path"]]] if c["home_path"] else [])
                          + [[to_sheet(p) for p in path] for path in c["paths"]],
                          "devices": [to_sheet((a["x"], a["y"])) for a in c["assigned"]]}
                         for c in result["circuits"]],
            # 2026-11-20 (David): the marks for what the drawing has no symbol for (range/dryer receptacles, breakers)
            "added": [{"kind": a["kind"], "feeds": a["feeds"], "circuit": a["circuit"],
                       "circuits": a.get("circuits") or ([a["circuit"]] if a["circuit"] else []),
                       "label": a["label"], "at": to_sheet((a["x"], a["y"]))}
                      for a in (result.get("added") or [])]}


def _propose(conn, ctx: RequestContext, estimate_id: int, sheet_id, result: dict,
             keep_approved: bool = True) -> list[int]:
    """One proposed measurement per cable size (routed feet plus box make-up; the estimate adds the waste). A rerun
    replaces the earlier wiring measurements (2026-11-19, David). keep_approved (the default - "this can cost the user
    lots of review time"): a cable size already approved stays, and isn't proposed again; off, every earlier wiring
    measurement goes and the cable starts over from scratch. The estimate's history log records each removal."""
    vp = conn.execute("SELECT id FROM viewports WHERE sheet_id = ? ORDER BY id LIMIT 1", (sheet_id,)).fetchone() \
        if sheet_id else None
    now = _now()
    made = []
    kept = {}
    suggested = []
    result["suggested_ids"] = suggested

    def suggest(feeds: str, qty, unit: str) -> None:
        """2026-11-21 (David: "I reran the run wiring with different defaults and I don't see any changes to approve"):
        an approved size the new run measures differently keeps its approved value, with the new one as a suggested
        change - the person accepts it (✓ Accept the new lengths), the same way the plans' re-read suggests changes."""
        from decimal import Decimal
        from estimator.takeoff import measurements as ms
        row = kept[feeds]
        new = Decimal(str(qty)).quantize(Decimal("0.1"))
        if Decimal(str(row["qty"])).quantize(Decimal("0.1")) == new:
            return                                           # the same: nothing to accept
        m = ms._load(conn, ctx, row["id"])
        if m["suggested_qty"] is not None and Decimal(str(m["suggested_qty"])).quantize(Decimal("0.1")) == new:
            suggested.append(row["id"])
            return
        ms._suggest(conn, ctx, dict(m), new, f"the wiring run now gives {new} {unit} ({result.get('routing') or 'rerun'})"[:300])
        suggested.append(row["id"])
    with service.transaction(conn):
        for r in conn.execute("SELECT id, feeds, qty, unit, status, sheet_id FROM measurements WHERE company_id = ?"
                              " AND estimate_id = ? AND proposed_by = ?",
                              (ctx.company_id, estimate_id, PROPOSED_BY)).fetchall():
            if keep_approved and r["status"] == "approved" and r["sheet_id"] is None:
                # 2026-11-20 (David): approved cable from before the plans were read again (its sheet is gone). It is
                # not "already approved" for the plans as they read now, so the size is proposed again; approving the
                # new length takes the old one off (measurements.confirm_measurements), and the audit offers that.
                continue
            if keep_approved and r["status"] == "approved":
                kept[r["feeds"]] = dict(r)
                continue
            conn.execute("DELETE FROM measurements WHERE id = ?", (r["id"],))
            service._log(conn, ctx, estimate_id, "measurement_deleted",
                         {"measurement_id": r["id"], "qty": r["qty"], "unit": r["unit"], "feeds": r["feeds"],
                          "status": r["status"], "reason": "replaced by a new wiring run"})
        for b in result["bom"]:
            size = b["cable"].split()[0]
            feeds = SIZE_FEEDS.get(size)
            if not feeds:
                continue
            if feeds in kept:
                suggest(feeds, b["measured_ft"], "lf")
                continue
            circuits = [c["id"] for c in result["circuits"] if c["wire"] == size or
                        (c["travelers_ft"] and wiring.TRAVELER.get(c["wire"]) == size)]
            calc = {"source": "wiring", "how": f"{b['measured_ft']} ft of {size} routed on circuits "
                    f"{', '.join(circuits)} (home runs, device to device, box make-up)",
                    "qty": str(b["measured_ft"]), "circuits": circuits, "order_ft": b["order_ft"], "rolls": b["rolls"]}
            mid = conn.execute(
                "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label,"
                " qty, unit, source_object_ids, calc_json, geometry_json, method, confidence, status, locked,"
                " proposed_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,'length',?,?,'lf','[]',?,NULL,'cad',NULL,'proposed',0,?,?,?)",
                (ctx.company_id, estimate_id, MODULE_ID, feeds, sheet_id, vp["id"] if vp else None,
                 f"Cable {size} (wiring)", str(b["measured_ft"]), json.dumps(calc), PROPOSED_BY, now, now)).lastrowid
            service._log(conn, ctx, estimate_id, "measurement_proposed",
                         {"measurement_id": mid, "qty": str(b["measured_ft"]), "unit": "lf", "feeds": feeds})
            made.append(mid)
        # 2026-11-20 (David: the breakers and the range/dryer receptacles): what the panel schedule says, as counts -
        # the 15/20 Amp branch circuits (one breaker each) and the range and dryer circuits (a 240 V receptacle each).
        for feeds, qty, label, how in _counts(result):
            if feeds in kept:
                if qty > 0:
                    suggest(feeds, qty, "ea")
                continue
            if qty <= 0:
                continue
            calc = {"source": "wiring", "how": how, "qty": str(qty)}
            mid = conn.execute(
                "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label,"
                " qty, unit, source_object_ids, calc_json, geometry_json, method, confidence, status, locked,"
                " proposed_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,'count',?,?,'ea','[]',?,NULL,'cad',NULL,'proposed',0,?,?,?)",
                (ctx.company_id, estimate_id, MODULE_ID, feeds, sheet_id, vp["id"] if vp else None,
                 label, str(qty), json.dumps(calc), PROPOSED_BY, now, now)).lastrowid
            service._log(conn, ctx, estimate_id, "measurement_proposed",
                         {"measurement_id": mid, "qty": str(qty), "unit": "ea", "feeds": feeds})
            made.append(mid)
    return made


def _counts(result: dict) -> list[tuple[str, int, str, str]]:
    """(feeds, qty, label, how) for the counts the panel schedule gives."""
    branch = [c["id"] for c in result["circuits"] if c["amps"] < 30 and c["devices"]]
    ranges = [c["id"] for c in result["circuits"] if c["amps"] >= 30 and "RANGE" in c["description"].upper()]
    dryers = [c["id"] for c in result["circuits"] if c["amps"] >= 30 and "DRYER" in c["description"].upper()]
    return [("branch_circuits", len(branch), "Branch circuits (wiring)",
             f"{len(branch)} branch circuits on the panel schedule: {', '.join(branch)} - one breaker each"),
            ("range_receptacles", len(ranges), "Range receptacles (wiring)",
             f"range circuit(s) on the panel schedule: {', '.join(ranges)}"),
            ("dryer_receptacles", len(dryers), "Dryer receptacles (wiring)",
             f"dryer circuit(s) on the panel schedule: {', '.join(dryers)}")]


def latest(ctx: RequestContext, estimate_id: int) -> dict | None:
    p = result_path(estimate_id)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def download_name(estimate_id: int, what: str = "wiring") -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", f"estimate_{int(estimate_id)}_{what}.dxf")

"""Server mode compute limits: the processing-PC queue, publishing results to the server, and the heavy-job guard
(spec: "Server mode compute limits").

The server only does light work. Reading plans is heavy, so in Server mode an uploaded plan set is queued for a
processing PC (the uploader's own by default). The server and the PCs share one folder (config.exchange_dir(), a
network share in practice):

    exchange/jobs/<company>__<plan set>/job.json      written by the server: what to read, who uploaded it
    exchange/jobs/<company>__<plan set>/plan.<ext>    a copy of the plan file
    exchange/jobs/<company>__<plan set>/claim.json    created (exclusively) by the PC that takes the job
    exchange/jobs/<company>__<plan set>/progress.json the PC's progress
    exchange/inbox/<company>__<plan set>.json         the PC's published results
    exchange/pcs/<pc>.json                            each PC's heartbeat (online = seen in the last 10 minutes)

On a processing PC: plan_processing_queue(claim=true) takes the next job and puts the plan file into this PC's own
Estimator, plan_process reads it with the plan engine, plan_publish_to_server sends the results. On the server,
plan_processing_queue (and the Director's watcher) imports published results: the drawing model, viewports, schedules,
sheet images and proposed measurements. From then on everyone works on it through the server.

Heavy-job guard: the server never runs the plan engine unless the owner turned on "Allow small plan processing on the
server" (off by default), and then only for vector PDF or DXF sets of up to 10 sheets (setting), one at a time.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.drawing_model import store, uploads
from estimator.errors import ConfirmationRequired, EstimatorError, InvalidInput, NotAvailable, PermissionDenied
from estimator.estimating import service

ONLINE_MINUTES = 10
STALE_HOURS = 2                 # a claim with no progress for this long goes back to the queue
ANY_PC_AFTER_MINUTES = 15       # after this, any PC may take a job meant for the uploader's PC
SMALL_TYPES = ("pdf", "dxf")
BUNDLE_FORMAT = 1


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat(timespec="seconds")


def _parse(text: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(text) if text else None
    except ValueError:
        return None


def _key(company_id: str, plan_set_id: int) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", company_id)
    return f"{safe}__{int(plan_set_id)}"


def _dirs() -> dict[str, Path]:
    root = config.exchange_dir()
    out = {"root": root, "jobs": root / "jobs", "inbox": root / "inbox", "pcs": root / "pcs", "done": root / "done",
           "failed": root / "failed"}
    for p in out.values():
        p.mkdir(parents=True, exist_ok=True)
    return out


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------- settings and the guard

def settings(conn, ctx: RequestContext) -> dict:
    row = conn.execute("SELECT server_small_processing, server_small_max_sheets FROM company_profile"
                       " WHERE company_id = ?", (ctx.company_id,)).fetchone()
    return {"ok": True, "mode": ctx.mode, "small_processing_on_server": bool(row and row[0]),
            "small_max_sheets": int(row[1]) if row else 10, "small_file_types": list(SMALL_TYPES),
            "one_job_at_a_time": True,
            "say": ("Personal mode: this PC does everything." if ctx.mode != "server" else
                    "The server does light work only; plans are read on processing PCs" +
                    (" (small vector PDF or DXF sets may be read on the server)." if row and row[0] else "."))}


def set_settings(conn, ctx: RequestContext, small_processing: bool | None = None, max_sheets: int | None = None,
                 confirm: bool = False) -> dict:
    """Owner only: allow small plan processing on the server (off by default) and its sheet limit."""
    if ctx.role != "owner" or ctx.agent:
        raise PermissionDenied("only the owner can change what the server processes", role=ctx.role)
    cur = settings(conn, ctx)
    on = cur["small_processing_on_server"] if small_processing is None else bool(small_processing)
    limit = cur["small_max_sheets"] if max_sheets in (None, "") else int(max_sheets)
    if not 1 <= limit <= 50:
        raise InvalidInput("max_sheets must be from 1 to 50 (bigger sets always go to a processing PC)",
                           field="max_sheets")
    if not confirm:
        raise ConfirmationRequired(("Allow" if on else "Don't allow") + f" plan processing on the server for vector PDF "
                                   f"or DXF sets of up to {limit} sheets, one at a time? Call again with confirm=true.",
                                   small_processing=on, max_sheets=limit)
    with service.transaction(conn):
        conn.execute("INSERT INTO company_profile (company_id, server_small_processing, server_small_max_sheets,"
                     " updated_by, updated_at) VALUES (?,?,?,?,?) ON CONFLICT (company_id) DO UPDATE SET"
                     " server_small_processing = excluded.server_small_processing, server_small_max_sheets ="
                     " excluded.server_small_max_sheets, updated_by = excluded.updated_by, updated_at ="
                     " excluded.updated_at", (ctx.company_id, int(on), limit, ctx.actor, _iso()))
        service._log(conn, ctx, None, "server_compute_changed", {"small_processing": on, "max_sheets": limit})
    return settings(conn, ctx)


def page_count(path: Path, file_type: str) -> int | None:
    """Pages in a plan file without reading it properly (DXF is one sheet). None when it can't tell."""
    if file_type == "dxf":
        return 1
    if file_type != "pdf":
        return None
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    n = len(re.findall(rb"/Type\s*/Page(?![a-zA-Z])", data))
    return n or None


def guard(conn, ctx: RequestContext, ps: dict) -> dict:
    """Where may this plan set be read? {"where": "here"} (Personal mode or a small allowed set on the server) or
    {"where": "processing_pc", "why": ...}."""
    if ctx.mode != "server":
        return {"where": "here"}
    s = settings(conn, ctx)
    if not s["small_processing_on_server"]:
        return {"where": "processing_pc", "why": "the server doesn't read plans (small plan processing is off)"}
    if ps["file_type"] not in SMALL_TYPES:
        return {"where": "processing_pc", "why": f"{ps['file_type'].upper()} plans are always read on a processing PC"}
    pages = page_count(Path(ps["file_path"]), ps["file_type"])
    if pages is None or pages > s["small_max_sheets"]:
        return {"where": "processing_pc",
                "why": f"{pages or 'an unknown number of'} sheet(s) is more than the server's limit of "
                       f"{s['small_max_sheets']}"}
    busy = conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND status = 'processing' AND id != ?",
                        (ctx.company_id, ps["id"])).fetchone()
    if busy:
        return {"where": "processing_pc", "why": f"the server is already reading plan set {busy[0]} (one at a time)"}
    return {"where": "here", "small": True, "pages": pages}


# ---------------------------------------------------------------- the server's side

def enqueue(conn, ctx: RequestContext, ps: dict, why: str = "") -> dict:
    """Queue a plan set for a processing PC (the uploader's own first) and put the job in the shared folder."""
    d = _dirs()
    key = _key(ctx.company_id, ps["id"])
    job_dir = d["jobs"] / key
    job_dir.mkdir(parents=True, exist_ok=True)
    plan_copy = job_dir / f"plan.{ps['file_type']}"
    if not plan_copy.exists():
        shutil.copy2(ps["file_path"], plan_copy)
    preferred = ps["uploaded_by"] if ps.get("uploaded_by") and not str(ps["uploaded_by"]).startswith("agent:") \
        else ctx.user_id
    _write_json(job_dir / "job.json", {
        "format": BUNDLE_FORMAT, "key": key, "company_id": ctx.company_id, "plan_set_id": ps["id"],
        "estimate_id": ps["estimate_id"], "file": ps["original_name"], "file_type": ps["file_type"],
        "sha256": ps["sha256"], "revision": ps["revision"], "preferred_user": preferred, "queued_at": _iso(),
        "why": why})
    with service.transaction(conn):
        conn.execute("UPDATE plan_sets SET queue_state = 'waiting', queue_pc = ?, queued_at = ? WHERE id = ?",
                     (preferred, _iso(), ps["id"]))
        service._log(conn, ctx, ps["estimate_id"], "plan_queued",
                     {"plan_set_id": ps["id"], "for_user": preferred, "why": why})
    online = [p for p in _pcs() if p["online"]]
    if not online:
        from estimator.director.watch import _notice
        _notice(conn, ctx, "plans", f"no_pc:{ps['id']}", f"📐 Plan set {ps['id']} ({ps['original_name']}) is waiting "
                f"for a processing PC, and none is online. Open AI-Prowler on an estimator's PC and say \"pick up "
                f"plan jobs\".", estimate_id=ps["estimate_id"])
    return {"queued_for": preferred, "pcs_online": len(online)}


def _pcs() -> list[dict]:
    out = []
    cutoff = _now() - timedelta(minutes=ONLINE_MINUTES)
    for f in sorted(_dirs()["pcs"].glob("*.json")):
        p = _read_json(f)
        if not p:
            continue
        seen = _parse(p.get("last_seen"))
        p["online"] = bool(seen and seen >= cutoff)
        out.append(p)
    return out


def describe(conn, ctx: RequestContext, ps: dict) -> dict | None:
    """Queue information for one plan set, in words (used by plan_status and the Director)."""
    if ps.get("queue_state") in (None, "", "published"):
        if ps.get("published_from"):
            return {"state": "published", "from_pc": ps["published_from"], "at": ps["published_at"],
                    "say": f"Read on {ps['published_from']} and published to the server."}
        return None
    job_dir = _dirs()["jobs"] / _key(ctx.company_id, ps["id"])
    claim = _read_json(job_dir / "claim.json")
    prog = _read_json(job_dir / "progress.json") or {}
    if claim:
        who = claim.get("user") or claim.get("pc")
        return {"state": "claimed", "pc": claim.get("pc"), "user": claim.get("user"), "claimed_at": claim.get("at"),
                "progress": prog.get("state", "claimed"),
                "say": f"Waiting for plan processing on {who}'s PC ({prog.get('state', 'picked up')})."}
    return {"state": "waiting", "for_user": ps.get("queue_pc"), "queued_at": ps.get("queued_at"),
            "say": f"Waiting for plan processing on {ps.get('queue_pc') or 'a processing'}'s PC (not picked up yet)."}


def _release_stale(conn, ctx) -> list[int]:
    released = []
    cutoff = _now() - timedelta(hours=STALE_HOURS)
    for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND queue_state = 'waiting'",
                          (ctx.company_id,)).fetchall():
        job_dir = _dirs()["jobs"] / _key(ctx.company_id, r[0])
        claim = _read_json(job_dir / "claim.json")
        if not claim:
            continue
        prog = _read_json(job_dir / "progress.json") or {}
        last = _parse(prog.get("at")) or _parse(claim.get("at"))
        if last and last < cutoff:
            for name in ("claim.json", "progress.json"):
                (job_dir / name).unlink(missing_ok=True)
            released.append(r[0])
    return released


def queue(conn, ctx: RequestContext) -> dict:
    """plan_processing_queue on the server: import anything published, release stale claims, list what's waiting."""
    if ctx.mode != "server":
        raise InvalidInput("this install is in Personal mode, so there's no server queue. On a processing PC use "
                           "claim=true to pick up the next plan job", mode=ctx.mode)
    imported = import_published(conn, ctx)
    released = _release_stale(conn, ctx)
    rows = [dict(r) for r in conn.execute(
        "SELECT p.*, e.title AS estimate_title FROM plan_sets p JOIN estimates e ON e.id = p.estimate_id"
        " WHERE p.company_id = ? AND p.queue_state = 'waiting' ORDER BY p.queued_at, p.id", (ctx.company_id,))]
    jobs = []
    for r in rows:
        info = describe(conn, ctx, r)
        queued = _parse(r["queued_at"])
        jobs.append({"plan_set_id": r["id"], "estimate_id": r["estimate_id"], "estimate": r["estimate_title"],
                     "file": r["original_name"], "uploaded_by": r["uploaded_by"],
                     "waiting_minutes": int((_now() - queued).total_seconds() // 60) if queued else None, **info})
    pcs = _pcs()
    return {"ok": True, "count": len(jobs), "jobs": jobs, "imported": imported, "released": released,
            "pcs": [{k: p.get(k) for k in ("pc", "user", "name", "last_seen", "online")} for p in pcs],
            "pcs_online": sum(p["online"] for p in pcs),
            "say": (f"{len(jobs)} plan set(s) waiting for a processing PC; {sum(p['online'] for p in pcs)} PC(s) "
                    "online." if jobs else "No plan sets waiting.") +
                   (f" Imported {len(imported)} published result(s)." if imported else "")}


def import_published(conn, ctx: RequestContext) -> list[dict]:
    """Take in every result a processing PC published for this company. Bad ones go to exchange/failed with why."""
    d = _dirs()
    prefix = _key(ctx.company_id, 0)[:-1]
    out = []
    for f in sorted(d["inbox"].glob(f"{prefix}*.json")):
        bundle = _read_json(f)
        try:
            if bundle is None:
                raise InvalidInput("the published file isn't readable")
            res = receive(conn, ctx, bundle)
            shutil.move(str(f), str(d["done"] / f.name))
            out.append({"plan_set_id": res["plan_set_id"], "ok": True, "from_pc": res["from_pc"],
                        "measurements": res["proposed_measurements"]})
        except EstimatorError as exc:
            shutil.move(str(f), str(d["failed"] / f.name))
            (d["failed"] / (f.name + ".why.txt")).write_text(exc.message, encoding="utf-8")
            out.append({"file": f.name, "ok": False, "error": exc.message})
    return out


def receive(conn, ctx: RequestContext, bundle: dict) -> dict:
    """Save a processing PC's published results on the server: images, drawing model, proposed measurements."""
    if bundle.get("format") != BUNDLE_FORMAT or not isinstance(bundle.get("results"), dict):
        raise InvalidInput("that isn't a published plan result this version understands")
    if bundle.get("company_id") != ctx.company_id:
        raise PermissionDenied("that result belongs to another company")
    ps = store.load_plan_set(conn, ctx, int(bundle.get("plan_set_id") or 0))
    if ps["queue_state"] != "waiting":
        raise InvalidInput(f"plan set {ps['id']} isn't waiting for a processing PC (it's {ps['queue_state'] or 'not queued'})",
                           plan_set_id=ps["id"])
    if bundle.get("sha256") != ps["sha256"]:
        raise InvalidInput("the published result was made from a different file than this plan set",
                           plan_set_id=ps["id"])
    pc = str(bundle.get("from_pc") or "a processing PC")[:80]
    folder = uploads.plans_folder(ps["estimate_id"]) / f"{ps['id']}_sheets"
    folder.mkdir(parents=True, exist_ok=True)
    results = json.loads(json.dumps(bundle["results"]))
    images = bundle.get("images") or {}
    for s in results.get("sheets", []):
        img = images.get(str(s.get("page_no")))
        s["image_path"] = None
        if img:
            ext = re.sub(r"[^a-z0-9]", "", str(img.get("ext", "png")).lower())[:5] or "png"
            dest = folder / f"page_{int(s['page_no']):04d}.{ext}"
            dest.write_bytes(base64.b64decode(img["data"]))
            s["image_path"] = str(dest)
    pub_ctx = RequestContext(company_id=ctx.company_id, user_id=ctx.user_id, role="estimator", mode=ctx.mode,
                             agent=f"pc:{pc}")
    saved = store.save_results(conn, pub_ctx, ps["id"], results,
                               f"{bundle.get('engine') or 'plan engine'} (read on {pc})")
    by_page: dict[int, list[int]] = {}
    for r in conn.execute("SELECT o.id, s.page_no FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
                          " WHERE s.plan_set_id = ? ORDER BY o.id", (ps["id"],)):
        by_page.setdefault(r["page_no"], []).append(r["id"])
    made, skipped = [], []
    from estimator.takeoff import measurements
    for pm in bundle.get("measurements") or []:
        try:
            ids = [by_page[int(p)][int(i)] for p, i in pm["objects"]]
            res = measurements.propose(conn, pub_ctx, ps["estimate_id"], pm["module_id"], ids, feeds=pm.get("feeds"),
                                       kind=pm.get("kind"), label=pm.get("label"), room=pm.get("room"),
                                       layer=pm.get("layer"), confidence=pm.get("confidence"), confirm=True)
            made += [m["id"] for m in res["proposed"]]
        except (EstimatorError, KeyError, IndexError, TypeError, ValueError) as exc:
            skipped.append({"label": pm.get("label"), "why": getattr(exc, "message", str(exc))})
    now = _iso()
    with service.transaction(conn):
        conn.execute("UPDATE plan_sets SET queue_state = 'published', published_from = ?, published_at = ?"
                     " WHERE id = ?", (pc, now, ps["id"]))
        service._log(conn, ctx, ps["estimate_id"], "plan_published",
                     {"plan_set_id": ps["id"], "from_pc": pc, "sheets": saved["sheets"], "objects": saved["objects"],
                      "measurements": len(made), "skipped": len(skipped)})
        from estimator.director.watch import _notice
        _notice(conn, ctx, "plans", f"published:{ps['id']}", f"📐 Plan set {ps['id']} ({ps['original_name']}) was read "
                f"on {pc}: {saved['sheets']} sheet(s), {saved['objects']} object(s), {len(made)} proposed "
                f"measurement(s). It's ready to review.", estimate_id=ps["estimate_id"])
    shutil.rmtree(_dirs()["jobs"] / _key(ctx.company_id, ps["id"]), ignore_errors=True)
    return {"ok": True, "plan_set_id": ps["id"], "from_pc": pc, "sheets": saved["sheets"], "objects": saved["objects"],
            "proposed_measurements": made, "skipped_measurements": skipped}


# ---------------------------------------------------------------- a processing PC's side

def heartbeat(name: str | None = None, user: str | None = None) -> dict:
    p = {"pc": config.pc_id(), "user": user or config.server_user(), "name": name or config.pc_id(),
         "last_seen": _iso()}
    _write_json(_dirs()["pcs"] / f"{re.sub(r'[^A-Za-z0-9_-]', '_', p['pc'])}.json", p)
    return p


def _holder_estimate(conn, ctx, job: dict) -> int:
    title = f"Server plan job {job['key']}"
    row = conn.execute("SELECT id FROM estimates WHERE company_id = ? AND title = ?", (ctx.company_id, title)).fetchone()
    if row:
        return row[0]
    return service.create_estimate(conn, ctx, title)["id"]


def claim_next(conn, ctx: RequestContext, user: str | None = None, any_job: bool = False) -> dict:
    """plan_processing_queue(claim=true) on a processing PC: take the next plan job and put its plan file into this
    PC's Estimator. Jobs from this PC's own user come first; others after they've waited a while (or any_job=true)."""
    store._role(ctx, store.EDIT_ROLES, "pick up plan jobs")
    me = heartbeat(user=user)
    d = _dirs()
    jobs = []
    for f in d["jobs"].glob("*/job.json"):
        job = _read_json(f)
        if job and not (f.parent / "claim.json").exists():
            jobs.append(job)
    jobs.sort(key=lambda j: (j.get("preferred_user") != me["user"], j.get("queued_at") or ""))
    cutoff = _now() - timedelta(minutes=ANY_PC_AFTER_MINUTES)
    for job in jobs:
        mine = me["user"] and job.get("preferred_user") == me["user"]
        old = (_parse(job.get("queued_at")) or _now()) <= cutoff
        if not (mine or old or any_job):
            continue
        job_dir = d["jobs"] / job["key"]
        try:
            fd = os.open(job_dir / "claim.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            continue                                          # another PC got there first
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"pc": me["pc"], "user": me["user"], "at": _iso()}, fh)
        _write_json(job_dir / "progress.json", {"state": "picked up", "at": _iso()})
        est_id = _holder_estimate(conn, ctx, job)
        named = job_dir / job["file"]
        shutil.copy2(job_dir / f"plan.{job['file_type']}", named)
        try:
            up = store.upload(conn, ctx, est_id, str(named), confirm=True)
        except InvalidInput as exc:
            dup = exc.details.get("plan_set_id")
            if not dup:
                raise
            up = {"plan_set_id": dup}
        finally:
            named.unlink(missing_ok=True)
        conn.execute("UPDATE plan_sets SET server_job = ? WHERE id = ?", (job["key"], up["plan_set_id"]))
        return {"ok": True, "claimed": True, "job": job["key"], "server_plan_set_id": job["plan_set_id"],
                "file": job["file"], "plan_set_id": up["plan_set_id"], "estimate_id": est_id,
                "next": f"plan_process({up['plan_set_id']}) to read it here, then "
                        f"plan_publish_to_server({up['plan_set_id']})"}
    waiting = len(jobs)
    return {"ok": True, "claimed": False, "waiting": waiting, "pc": me["pc"],
            "say": ("No plan jobs waiting." if not waiting else f"{waiting} job(s) waiting, but they're for other "
                    "people's PCs and haven't waited long. Use any_job=true to take one anyway.")}


def note_progress(conn, ctx: RequestContext, plan_set_id: int, state: str) -> None:
    """A processing PC tells the server how a job is going (called when it starts and finishes reading)."""
    row = conn.execute("SELECT server_job FROM plan_sets WHERE id = ? AND company_id = ?",
                       (int(plan_set_id), ctx.company_id)).fetchone()
    if row and row[0]:
        job_dir = _dirs()["jobs"] / row[0]
        if job_dir.is_dir():
            _write_json(job_dir / "progress.json", {"state": state, "at": _iso()})


def export_results(conn, plan_set_id: int) -> tuple[dict, dict, dict[int, tuple[int, int]]]:
    """This PC's drawing model in the plan engine's own result format, the sheet images, and where each object is."""
    sheets, images, where = [], {}, {}
    for s in conn.execute("SELECT * FROM sheets WHERE plan_set_id = ? ORDER BY page_no", (plan_set_id,)).fetchall():
        vps = [{"key": str(v["id"]), "label": v["label"],
                "bbox": json.loads(v["bbox_json"]) if v["bbox_json"] else None, "scale_note": v["scale_note"],
                "scale_ratio": v["scale_ratio"], "scale_method": v["scale_method"],
                "scale_confidence": v["scale_confidence"], "is_nts": bool(v["is_nts"])}
               for v in conn.execute("SELECT * FROM viewports WHERE sheet_id = ? ORDER BY id", (s["id"],))]
        objs = []
        for i, o in enumerate(conn.execute("SELECT * FROM drawing_objects WHERE sheet_id = ? ORDER BY id",
                                           (s["id"],)).fetchall()):
            where[o["id"]] = (s["page_no"], i)
            objs.append({"viewport": str(o["viewport_id"]) if o["viewport_id"] else None, "kind": o["kind"],
                         "geometry": json.loads(o["geometry_json"]), "layer": o["layer"], "block_name": o["block_name"],
                         "label": o["label"], "tag": o["tag"], "source": o["source"], "confidence": o["confidence"]})
        scheds = []
        for c in conn.execute("SELECT * FROM schedules WHERE sheet_id = ? ORDER BY id", (s["id"],)).fetchall():
            rows = [{"mark": r["mark"], "fields": json.loads(r["fields_json"]), "confidence": r["confidence"]}
                    for r in conn.execute("SELECT * FROM schedule_rows WHERE schedule_id = ? ORDER BY id", (c["id"],))]
            scheds.append({"schedule_type": c["schedule_type"], "title": c["title"],
                           "bbox": json.loads(c["bbox_json"]) if c["bbox_json"] else None,
                           "confidence": c["confidence"], "rows": rows})
        legends = [{"discipline": g["discipline"], "title": g["title"],
                    "bbox": json.loads(g["bbox_json"]) if g["bbox_json"] else None, "confidence": g["confidence"]}
                   for g in conn.execute("SELECT * FROM legends WHERE sheet_id = ? ORDER BY id", (s["id"],))]
        sheets.append({"page_no": s["page_no"], "sheet_no": s["sheet_no"], "title": s["title"],
                       "discipline": s["discipline"], "revision": s["revision"], "revision_date": s["revision_date"],
                       "units": s["units"], "width": s["width"], "height": s["height"], "confidence": s["confidence"],
                       "viewports": vps, "objects": objs, "schedules": scheds, "legends": legends})
        if s["image_path"] and Path(s["image_path"]).is_file():
            images[str(s["page_no"])] = {"ext": Path(s["image_path"]).suffix.lstrip(".") or "png",
                                         "data": base64.b64encode(Path(s["image_path"]).read_bytes()).decode("ascii")}
    pc_row = conn.execute("SELECT page_count FROM plan_sets WHERE id = ?", (plan_set_id,)).fetchone()
    return {"sheets": sheets, "page_count": pc_row[0] if pc_row else None}, images, where


def publish(conn, ctx: RequestContext, plan_set_id: int, confirm: bool = False) -> dict:
    """plan_publish_to_server on a processing PC: send a read plan set's results to the company server."""
    store._role(ctx, store.EDIT_ROLES, "publish plans")
    ps = store.load_plan_set(conn, ctx, int(plan_set_id))
    if not ps.get("server_job"):
        raise InvalidInput(f"plan set {ps['id']} isn't a server plan job (pick one up with plan_processing_queue "
                           "claim=true)", plan_set_id=ps["id"])
    if ps["status"] != "processed":
        raise InvalidInput(f"plan set {ps['id']} hasn't been read yet (it's {ps['status']}); run plan_process first",
                           plan_set_id=ps["id"])
    job_dir = _dirs()["jobs"] / ps["server_job"]
    job = _read_json(job_dir / "job.json")
    if job is None:
        raise NotAvailable("the server no longer has that job (it may have been published already or cancelled)",
                           job=ps["server_job"])
    claim = _read_json(job_dir / "claim.json") or {}
    if claim.get("pc") != config.pc_id():
        raise PermissionDenied(f"that job was picked up by {claim.get('pc') or 'no PC'}, not this one",
                               job=ps["server_job"])
    results, images, where = export_results(conn, ps["id"])
    pms = []
    for m in conn.execute("SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ? AND status != 'rejected'"
                          " AND source_object_ids != '[]'", (ctx.company_id, ps["estimate_id"])):
        refs = [where.get(i) for i in json.loads(m["source_object_ids"] or "[]")]
        if refs and all(refs):
            pms.append({"module_id": m["module_id"], "feeds": m["feeds"], "kind": m["kind"], "label": m["label"],
                        "room": m["room"], "layer": m["layer"], "confidence": m["confidence"],
                        "objects": [list(r) for r in refs]})
    n_obj = sum(len(s["objects"]) for s in results["sheets"])
    if not confirm:
        raise ConfirmationRequired(f"Publish plan set {ps['id']} ({ps['original_name']}) to the server: "
                                   f"{len(results['sheets'])} sheet(s), {n_obj} object(s), {len(images)} sheet image(s), "
                                   f"{len(pms)} proposed measurement(s)? Call again with confirm=true.",
                                   sheets=len(results["sheets"]), objects=n_obj, measurements=len(pms))
    bundle = {"format": BUNDLE_FORMAT, "company_id": job["company_id"], "plan_set_id": job["plan_set_id"],
              "sha256": ps["sha256"], "from_pc": config.pc_id(), "from_user": claim.get("user"),
              "engine": ps["engine"], "results": results, "images": images, "measurements": pms,
              "published_at": _iso()}
    _write_json(_dirs()["inbox"] / f"{ps['server_job']}.json", bundle)
    _write_json(job_dir / "progress.json", {"state": "published, waiting for the server to take it in", "at": _iso()})
    with service.transaction(conn):
        conn.execute("UPDATE plan_sets SET published_at = ?, published_from = ? WHERE id = ?",
                     (_iso(), config.pc_id(), ps["id"]))
        service._log(conn, ctx, ps["estimate_id"], "plan_published_to_server",
                     {"plan_set_id": ps["id"], "job": ps["server_job"], "objects": n_obj, "measurements": len(pms)})
    return {"ok": True, "published": True, "job": ps["server_job"], "server_plan_set_id": job["plan_set_id"],
            "sheets": len(results["sheets"]), "objects": n_obj, "images": len(images), "measurements": len(pms),
            "say": "Sent to the server. It takes the results in on its next check (plan_processing_queue there)."}

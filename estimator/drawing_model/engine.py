"""Where the plan engine (Coder 2 track) plugs in.

The plan engine reads a plan file and returns plain results. It never opens estimator.db: the Estimator checks the
results, measures them and saves them (estimator/drawing_model/store.py). So the engine can be built and tested on its
own, and a bad result never leaves half a drawing model.

How it is found: a package named `estimator.plan_engine` with a function

    process(file_path: pathlib.Path, file_type: str, info: dict) -> dict

is picked up automatically the first time plans are processed (or call register_engine(name, fn) directly).
`file_type` is "pdf", "image", "dxf" or "dwg". `info` has plan_set_id, estimate_id, original_name, revision and
work_dir (a folder for rendered sheet images). Raise an exception with a plain message if the file can't be read.

What it returns (only "sheets" and each sheet's "page_no" are required):

    {
      "page_count": 12,
      "sheets": [{
        "page_no": 1, "sheet_no": "A-101", "title": "FLOOR PLAN", "discipline": "architectural",
        "revision": "B", "revision_date": "2026-10-01",
        "units": "paper_in",                 # inches on the paper (PDF/scan), or "ft"/"in"/"m"/"cm"/"mm" for CAD
        "width": 36, "height": 24,           # sheet size in its units
        "image_path": "C:/.../sheet_1.png",  # rendered page for review and AI vision
        "confidence": 0.9,
        "viewports": [{"key": "main", "label": "FLOOR PLAN", "bbox": [1, 1, 30, 22],
                       "scale_note": "1/4\\" = 1'-0\\"",          # or "scale_ratio": 48, or "is_nts": true
                       "scale_method": "note", "scale_confidence": 0.95}],
        "objects": [{"viewport": "main", "kind": "room", "label": "KITCHEN", "tag": null,
                     "geometry": {"type": "polygon", "points": [[2, 2], [5, 2], [5, 5], [2, 5]]},
                     "layer": "A-ROOM", "block_name": null, "source": "vector", "confidence": 0.92}],
        "schedules": [{"schedule_type": "door", "title": "DOOR SCHEDULE", "bbox": [31, 1, 35, 8],
                       "rows": [{"mark": "D3", "fields": {"size": "3'-0\\" x 6'-8\\"", "type": "solid core"},
                                 "confidence": 0.9}]}],
        "legends": [{"discipline": "electrical", "title": "ELECTRICAL LEGEND", "bbox": [31, 9, 35, 14]}]
      }]
    }

Allowed values: discipline architectural/structural/plumbing/electrical/mechanical/landscape/roof/site/civil/fire/
general/other; kind line/polyline/polygon/room/wall/opening/symbol/text/dimension; geometry type point/line/polyline/
polygon; source cad/vector/raster/ai/manual; schedule_type door/window/finish/plumbing/lighting/panel/equipment/
wall-type/other; confidences 0 to 1. Objects say which viewport they sit in by its key, so each is measured with its
own viewport's scale.
"""
from __future__ import annotations

import importlib
import threading
from contextlib import closing
from pathlib import Path

from estimator.context import RequestContext
from estimator.drawing_model import store, uploads
from estimator.errors import EstimatorError, InvalidInput, NotAvailable

ENGINE_MODULES = ("estimator.plan_engine",)
RUN_INLINE = False                    # tests set this to process in the caller's thread

_engine: dict | None = None
_lock = threading.Lock()


def register_engine(name: str, fn) -> None:
    global _engine
    if not callable(fn):
        raise TypeError("the plan engine must be a function process(file_path, file_type, info)")
    _engine = {"name": str(name), "fn": fn}


def clear_engine() -> None:
    global _engine
    _engine = None


def _discover() -> dict | None:
    if _engine is not None:
        return _engine
    for mod_name in ENGINE_MODULES:
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            continue
        fn = getattr(mod, "process", None)
        if callable(fn):
            register_engine(getattr(mod, "ENGINE_NAME", mod_name), fn)
            return _engine
    return None


def engine_info() -> dict:
    eng = _discover()
    return {"installed": eng is not None, "name": eng["name"] if eng else None}


def _run_engine(conn, ctx: RequestContext, plan_set_id: int, eng: dict) -> dict:
    ps = store.load_plan_set(conn, ctx, plan_set_id)
    work = uploads.plans_folder(ps["estimate_id"]) / f"{ps['id']}_sheets"
    work.mkdir(parents=True, exist_ok=True)
    info = {"plan_set_id": ps["id"], "estimate_id": ps["estimate_id"], "original_name": ps["original_name"],
            "revision": ps["revision"], "work_dir": str(work)}
    try:
        results = eng["fn"](Path(ps["file_path"]), ps["file_type"], info)
        return store.save_results(conn, ctx, ps["id"], results, eng["name"])
    except EstimatorError as exc:
        store.mark_failed(conn, ctx, ps["id"], f"the plan engine's results didn't pass the checks: {exc.message}")
        raise
    except Exception as exc:  # the engine's own failure: record it and say why
        store.mark_failed(conn, ctx, ps["id"], f"{type(exc).__name__}: {exc}")
        return {"ok": False, "error": "processing_failed", "plan_set_id": ps["id"],
                "message": f"the plan engine couldn't read the file: {exc}"}


def start(conn, ctx: RequestContext, plan_set_id: int, confirm: bool = False, open_conn=None):
    """Start reading a plan set. Returns right away (status 'processing'); plan_status shows progress.

    Re-reading a processed plan set replaces its drawing model (schedule corrections included), so that asks first."""
    store._role(ctx, store.EDIT_ROLES, "process plans")
    ps = store.load_plan_set(conn, ctx, plan_set_id)
    eng = _discover()
    if eng is None:
        raise NotAvailable("the plan engine isn't installed yet (it's being built on the Coder 2 track). Until then, "
                           "read the plans yourself and give the measurements to the estimate, or use runner_start "
                           "and runner_submit_takeoff", plan_set_id=ps["id"])
    if ps["status"] == "processing":
        raise InvalidInput(f"plan set {ps['id']} is already being read", plan_set_id=ps["id"])
    if ps["status"] == "processed":
        store._confirm(confirm, f"Plan set {ps['id']} was already read. Reading it again replaces its sheets, "
                       "objects and schedules, including any schedule rows you corrected.", plan_set_id=ps["id"])
    elif not confirm:
        store._confirm(False, f"Read plan set {ps['id']} ({ps['original_name']}) with the plan engine now?",
                       plan_set_id=ps["id"])
    store.mark_processing(conn, ctx, ps["id"], eng["name"])
    if RUN_INLINE or open_conn is None:
        return {**_run_engine(conn, ctx, ps["id"], eng)} | {"plan_set_id": ps["id"]}

    def work():
        with _lock, closing(open_conn()) as c2:
            try:
                _run_engine(c2, ctx, ps["id"], eng)
            except EstimatorError:
                pass                           # already recorded as failed with the reason

    thread = threading.Thread(target=work, name=f"plan-set-{ps['id']}", daemon=True)
    thread.start()
    start.last_thread = thread                 # tests can wait for it
    return {"ok": True, "plan_set_id": ps["id"], "status": "processing", "engine": eng["name"],
            "say": "Reading the plans in the background. Check with plan_status."}

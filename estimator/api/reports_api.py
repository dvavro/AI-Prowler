"""Reports screen and the revision overlay - Coder 2 Sprint 17 (spec: Screens and controls, Reports; Plan revisions).

Reports (owner, estimator, reviewer, office; read only unless noted):
  GET  /reports/summary?months=12          win/loss: estimates by status, win rate, value won and lost, by month and trade
  GET  /reports/takeoff/<estimate_id>      the takeoff report: every measurement by trade, with approved and waiting totals
  GET  /reports/actuals?estimate_id=       estimate vs actual (est_compare_history): prices against real job costs
  POST /reports/export {estimate_id?, status?, format: csv|xlsx}   est_export: writes a file to the exports folder
  GET  /reports/files/<name>               download a file from the exports folder (only that folder, plain names only)
Plan revisions (the overlay):
  GET  /reports/revisions?estimate_id=     saved revision reports, and revised plan sets not compared yet
  GET  /reports/revisions/<id>             one report with what the overlay needs (both sheets' sizes, the changed boxes,
                                           the measurements flagged to re-measure, schedule changes)
  POST /reports/revisions {new_plan_set_id, old_plan_set_id?, confirm}   plan_compare_revisions (asks first; Coder 1's
                                           drawing_model/revisions.compare; owner and estimator)
"""
from __future__ import annotations

import json
import re
from datetime import date

from estimator.api import nav

_TAKEOFF = re.compile(r"^/reports/takeoff/(\d+)$")
_REVISION = re.compile(r"^/reports/revisions/(\d+)$")
_FILE = re.compile(r"^/reports/files/([A-Za-z0-9_.-]{1,120})$")
FILE_TYPES = {".csv": "text/csv; charset=utf-8",
              ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
CLOSED = ("won", "lost")
OPEN_BIDS = ("sent",)


def handles(sub: str) -> bool:
    return sub == "/reports" or sub.startswith("/reports/")


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _ask_first, _body, _json, _ok, redact
    if not nav.can_open(ctx.role, "reports"):
        raise _refuse("your role can't open reports", 403, "permission_denied")
    see = nav.permissions(ctx.role).get("see_margins", False)
    q = req.query

    if sub == "/reports/summary" and m == "GET":
        return _ok(**summary(conn, ctx, _int(q.get("months"), 12, 1, 60)))

    mm = _TAKEOFF.match(sub)
    if mm and m == "GET":
        return _ok(**takeoff_report(conn, ctx, int(mm.group(1))))

    if sub == "/reports/actuals" and m == "GET":
        if not see:
            raise _refuse("your role can't see costs", 403, "permission_denied")
        from estimator.learning import history
        eid = _int(q.get("estimate_id"), None, 1)
        return _json(200, history.compare_history(conn, ctx, eid, None, (q.get("module_id") or "").strip() or None))

    if sub == "/reports/export" and m == "POST":
        from estimator import exports
        b = _body(req)
        fmt = str(b.get("format") or "csv").lower()
        if fmt not in exports.FORMATS:
            raise _refuse("format must be csv or xlsx")
        eid = _int(b.get("estimate_id"), None, 1)
        status = str(b.get("status") or "").strip() or None
        out = exports.export(conn, ctx, eid, status, fmt)
        return _ok(file=out["file"], format=out["format"], what=out["what"],
                   url=f"/estimator-api/reports/files/{out['file']}")

    mm = _FILE.match(sub)
    if mm and m == "GET":
        return _download(mm.group(1))

    if sub == "/reports/revisions" and m == "GET":
        return _ok(**revision_list(conn, ctx, _int(q.get("estimate_id"), None, 1)))

    if sub == "/reports/revisions" and m == "POST":
        from estimator.drawing_model import revisions
        b = _body(req)
        new_id = _int(b.get("new_plan_set_id"), None, 1)
        if new_id is None:
            raise _refuse("give the new plan set (new_plan_set_id)")
        old_id = _int(b.get("old_plan_set_id"), None, 1)
        return _ask_first(lambda: revisions.compare(conn, ctx, new_id, old_id, confirm=b.get("confirm") is True))

    mm = _REVISION.match(sub)
    if mm and m == "GET":
        return _ok(**redact(revision_detail(conn, ctx, int(mm.group(1))), see))

    raise _refuse(f"no such Estimator API call: {m} {sub}", 404, "not_found")


def _int(v, default, lo=None, hi=None):
    if v in (None, ""):
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise _refuse(f"'{v}' isn't a whole number") from None
    if (lo is not None and n < lo) or (hi is not None and n > hi):
        raise _refuse(f"{n} is out of range")
    return n


def _download(name: str):
    from estimator import exports
    from estimator.api.router import SECURITY_HEADERS, Response, _fail
    folder = exports.exports_dir().resolve()
    path = (folder / name).resolve()
    if path.parent != folder or path.suffix.lower() not in FILE_TYPES or not path.is_file():
        return _fail(404, "not_found", "no such export")
    return Response(200, FILE_TYPES[path.suffix.lower()], path.read_bytes(),
                    {"Cache-Control": "no-store", **SECURITY_HEADERS,
                     "Content-Disposition": f'attachment; filename="{path.name}"'})


# ---------------------------------------------------------------- win / loss

def summary(conn, ctx, months: int = 12) -> dict:
    """Estimates by status, win rate (won / (won + lost)), value won and lost, by month and by trade. Practice
    estimates are left out."""
    rows = [dict(r) for r in conn.execute(
        "SELECT id, status, totals_json, updated_at FROM estimates WHERE company_id = ? AND is_practice = 0",
        (ctx.company_id,))]
    trades: dict[int, list[str]] = {}
    for r in conn.execute("SELECT s.estimate_id, s.module_id FROM trade_sections s JOIN estimates e ON e.id = s.estimate_id"
                          " WHERE e.company_id = ? AND e.is_practice = 0", (ctx.company_id,)):
        trades.setdefault(r["estimate_id"], []).append(r["module_id"])
    today = date.today()
    keys = []
    y, mo = today.year, today.month
    for _ in range(months):
        keys.append(f"{y:04d}-{mo:02d}")
        mo -= 1
        if mo == 0:
            y, mo = y - 1, 12
    keys.reverse()
    by_status: dict[str, int] = {}
    value = {"won_cents": 0, "lost_cents": 0, "open_bids_cents": 0}
    by_month = {k: {"month": k, "won": 0, "lost": 0, "won_cents": 0, "lost_cents": 0} for k in keys}
    by_trade: dict[str, dict] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        total = int((json.loads(r["totals_json"]) if r["totals_json"] else {}).get("total_cents", 0) or 0)
        if r["status"] in CLOSED:
            value[f"{r['status']}_cents"] += total
            mk = (r["updated_at"] or "")[:7]
            if mk in by_month:
                by_month[mk][r["status"]] += 1
                by_month[mk][f"{r['status']}_cents"] += total
            for t in trades.get(r["id"], []):
                d = by_trade.setdefault(t, {"module_id": t, "won": 0, "lost": 0, "won_cents": 0, "lost_cents": 0})
                d[r["status"]] += 1
                d[f"{r['status']}_cents"] += total
        elif r["status"] in OPEN_BIDS:
            value["open_bids_cents"] += total
    won, lost = by_status.get("won", 0), by_status.get("lost", 0)
    for d in list(by_month.values()) + list(by_trade.values()):
        d["win_rate"] = round(d["won"] / (d["won"] + d["lost"]), 3) if d["won"] + d["lost"] else None
    return {"by_status": by_status, "total": len(rows), "won": won, "lost": lost,
            "win_rate": round(won / (won + lost), 3) if won + lost else None, **value,
            "by_month": list(by_month.values()), "by_trade": sorted(by_trade.values(), key=lambda d: -(d["won"] + d["lost"])),
            "note": None if won + lost else "No won or lost estimates yet: mark bids won or lost on the Bids screen."}


# ---------------------------------------------------------------- takeoff report

def takeoff_report(conn, ctx, estimate_id: int) -> dict:
    """Every measurement on an estimate by trade: approved (priced) and waiting totals per question, what needs
    re-measuring after a plan revision, and where each came from. Rejected ones are listed apart."""
    from estimator.estimating import service
    est = service.get_estimate(conn, ctx, estimate_id)
    rows = [dict(r) for r in conn.execute(
        "SELECT id, module_id, feeds, kind, label, room, qty, unit, method, confidence, status, needs_remeasure,"
        " suggested_qty, sheet_id, approved_by, approved_at, proposed_by FROM measurements WHERE company_id = ?"
        " AND estimate_id = ? ORDER BY module_id, feeds, id", (ctx.company_id, estimate_id))]
    sheets = {r["id"]: r["sheet_no"] for r in conn.execute(
        "SELECT s.id, s.sheet_no FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id WHERE p.company_id = ?"
        " AND p.estimate_id = ?", (ctx.company_id, estimate_id))}
    trades: dict[str, dict] = {}
    rejected = []
    for r in rows:
        r["sheet_no"] = sheets.get(r["sheet_id"])
        r["needs_remeasure"] = bool(r["needs_remeasure"])
        if r["status"] == "rejected":
            rejected.append(r)
            continue
        t = trades.setdefault(r["module_id"] or "other", {"module_id": r["module_id"] or "other", "questions": {},
                                                          "measurements": [], "approved": 0, "waiting": 0,
                                                          "remeasure": 0, "raster": 0})
        t["measurements"].append(r)
        t["approved" if r["status"] == "approved" else "waiting"] += 1
        t["remeasure"] += r["needs_remeasure"]
        t["raster"] += r["method"] == "raster"
        key = f"{r['feeds'] or r['label'] or 'other'}|{r['unit']}"
        qd = t["questions"].setdefault(key, {"feeds": r["feeds"], "label": r["label"], "unit": r["unit"],
                                             "approved_qty": 0.0, "waiting_qty": 0.0, "count": 0})
        try:
            qty = float(r["qty"])
        except (TypeError, ValueError):
            qty = 0.0
        qd["approved_qty" if r["status"] == "approved" else "waiting_qty"] += qty
        qd["count"] += 1
    out_trades = []
    for t in trades.values():
        t["questions"] = [{**q, "approved_qty": round(q["approved_qty"], 2), "waiting_qty": round(q["waiting_qty"], 2)}
                          for q in t["questions"].values()]
        out_trades.append(t)
    totals = {"measurements": len(rows) - len(rejected), "approved": sum(t["approved"] for t in out_trades),
              "waiting": sum(t["waiting"] for t in out_trades), "remeasure": sum(t["remeasure"] for t in out_trades),
              "raster": sum(t["raster"] for t in out_trades), "rejected": len(rejected)}
    notes = []
    if totals["waiting"]:
        notes.append(f"{totals['waiting']} measurement(s) still wait for approval; only approved ones are priced.")
    if totals["remeasure"]:
        notes.append(f"{totals['remeasure']} measurement(s) need re-measuring after a plan revision.")
    if totals["raster"]:
        notes.append(f"{totals['raster']} measurement(s) came from scanned or photographed plans: check them on the plan.")
    return {"estimate_id": est["id"], "estimate_title": est["title"], "status": est["status"], "trades": out_trades,
            "rejected": rejected, "totals": totals, "notes": notes}


# ---------------------------------------------------------------- revisions

def _letter(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    return chr(ord("A") + n - 1) if 1 <= n <= 26 else str(n)


def revision_list(conn, ctx, estimate_id: int | None = None) -> dict:
    sql = ("SELECT r.id, r.estimate_id, r.old_plan_set_id, r.new_plan_set_id, r.summary_json, r.flagged_measurement_ids,"
           " r.carried_measurement_ids, r.created_by, r.created_at, e.title FROM revision_reports r JOIN estimates e"
           " ON e.id = r.estimate_id WHERE r.company_id = ?")
    args: list = [ctx.company_id]
    if estimate_id:
        sql += " AND r.estimate_id = ?"
        args.append(estimate_id)
    reports = []
    done = set()
    for r in conn.execute(sql + " ORDER BY r.id DESC LIMIT 200", args):
        s = json.loads(r["summary_json"] or "{}")
        done.add((r["old_plan_set_id"], r["new_plan_set_id"]))
        reports.append({"report_id": r["id"], "estimate_id": r["estimate_id"], "estimate_title": r["title"],
                        "old_plan_set_id": r["old_plan_set_id"], "new_plan_set_id": r["new_plan_set_id"],
                        "said": s.get("said"), "totals": s.get("totals"),
                        "flagged": len(json.loads(r["flagged_measurement_ids"] or "[]")),
                        "carried": len(json.loads(r["carried_measurement_ids"] or "[]")),
                        "created_by": r["created_by"], "created_at": r["created_at"]})
    sql = ("SELECT n.id, n.estimate_id, n.revision, n.original_name, n.supersedes_plan_set_id, n.status, o.revision AS"
           " old_revision, o.status AS old_status, e.title FROM plan_sets n JOIN plan_sets o ON o.id ="
           " n.supersedes_plan_set_id JOIN estimates e ON e.id = n.estimate_id WHERE n.company_id = ?")
    args = [ctx.company_id]
    if estimate_id:
        sql += " AND n.estimate_id = ?"
        args.append(estimate_id)
    waiting = []
    for r in conn.execute(sql + " ORDER BY n.id DESC", args):
        if (r["supersedes_plan_set_id"], r["id"]) in done:
            continue
        ready = r["status"] == "processed" and r["old_status"] == "processed"
        waiting.append({"new_plan_set_id": r["id"], "old_plan_set_id": r["supersedes_plan_set_id"],
                        "estimate_id": r["estimate_id"], "estimate_title": r["title"], "name": r["original_name"],
                        "from_rev": _letter(r["old_revision"]), "to_rev": _letter(r["revision"]), "ready": ready,
                        "why_not": None if ready else "read both plan sets first"})
    from estimator.drawing_model import store
    return {"reports": reports, "not_compared": waiting, "can_compare": ctx.role in store.EDIT_ROLES}


def revision_detail(conn, ctx, report_id: int) -> dict:
    from estimator.drawing_model import revisions
    rep = revisions.compare(conn, ctx, report_id=report_id)
    ids = {s["old_sheet_id"] for s in rep.get("sheets", [])} | {s["new_sheet_id"] for s in rep.get("sheets", [])}
    sizes = {}
    if ids:
        q = ",".join("?" * len(ids))
        for r in conn.execute(f"SELECT id, sheet_no, title, width, height, units, image_path FROM sheets WHERE id IN ({q})",
                              sorted(ids)):
            sizes[r["id"]] = {"sheet_id": r["id"], "sheet_no": r["sheet_no"], "title": r["title"],
                              "width": r["width"], "height": r["height"], "units": r["units"],
                              "has_image": bool(r["image_path"])}
    for s in rep.get("sheets", []):
        s["old_sheet"] = sizes.get(s["old_sheet_id"])
        s["new_sheet"] = sizes.get(s["new_sheet_id"])
    flagged = []
    fid = rep.get("flagged_measurement_ids") or []
    if fid:
        q = ",".join("?" * len(fid))
        for r in conn.execute(f"SELECT id, module_id, feeds, label, room, qty, unit, status, needs_remeasure, calc_json"
                              f" FROM measurements WHERE company_id = ? AND id IN ({q}) ORDER BY id",
                              (ctx.company_id, *fid)):
            calc = json.loads(r["calc_json"] or "{}")
            flagged.append({"id": r["id"], "module_id": r["module_id"], "feeds": r["feeds"], "label": r["label"],
                            "room": r["room"], "qty": r["qty"], "unit": r["unit"], "status": r["status"],
                            "still_flagged": bool(r["needs_remeasure"]),
                            "why": (calc.get("revision") or {}).get("why") or []})
    ps = {r["id"]: dict(r) for r in conn.execute("SELECT id, revision, original_name FROM plan_sets WHERE id IN (?, ?)",
                                                 (rep["old_plan_set_id"], rep["new_plan_set_id"]))}
    old, new = ps.get(rep["old_plan_set_id"], {}), ps.get(rep["new_plan_set_id"], {})
    rep.pop("changed_object_ids", None)
    return {**rep, "flagged": flagged, "from_rev": _letter(old.get("revision")), "to_rev": _letter(new.get("revision")),
            "old_name": old.get("original_name"), "new_name": new.get("original_name")}

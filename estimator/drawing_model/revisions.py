"""Plan revisions (Rev A → Rev B): compare two processed plan sets through the drawing model (spec: "Plan revisions").

Sheets are matched by sheet number (then title, then page). On each pair of sheets, drawing objects are matched by what
they are (kind, label, tag, block, layer) and where they are:
- unchanged: same shape in the same place, same real size
- moved: same shape somewhere else on the sheet
- changed: a different size or shape (or the same lines measured at a new scale)
- removed / added: no partner on the other sheet
Schedule rows are matched by type and mark (added, removed, fields changed). Revision clouds and deltas on the new set
are counted and drawn on the overlay.

What happens to measurements (flag only; quantities are never changed here):
- every source object unchanged → the measurement carries over to the new set (its objects, sheet and viewport point to
  the new ones) and keeps its status
- any source object changed, moved or removed → flagged "re-measure"; it keeps pointing at the old set until a person
  re-measures it
The old plan set stays on file for the audit trail. The result is saved as a revision report.
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.drawing_model import store
from estimator.errors import ConfirmationRequired, InvalidInput, NotAvailable, NotFound
from estimator.estimating import service

SERVER_OBJECT_CAP = 20000          # above this a comparison is heavy work and isn't run on the server
OVERLAY_CAP = 500                  # boxes listed per sheet and change type in the report
REV_MARK = re.compile(r"\b(REV|REVISION|CLOUD|DELTA)\b", re.I)
PLACES = 3


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm(text) -> str:
    return "".join(str(text or "").split()).upper()


def _points(geom: dict) -> list[tuple[float, float]]:
    pts = geom.get("points") or []
    return [(round(float(p[0]), PLACES), round(float(p[1]), PLACES)) for p in pts]


def _centroid(pts) -> tuple[float, float]:
    if not pts:
        return (0.0, 0.0)
    return (sum(p[0] for p in pts) / len(pts), sum(p[1] for p in pts) / len(pts))


def _shape(pts) -> tuple:
    """The shape with its position taken out (points relative to the first one)."""
    if not pts:
        return ()
    x0, y0 = pts[0]
    return tuple((round(x - x0, PLACES), round(y - y0, PLACES)) for x, y in pts)


def _bbox(pts) -> list[float] | None:
    if not pts:
        return None
    return [min(p[0] for p in pts), min(p[1] for p in pts), max(p[0] for p in pts), max(p[1] for p in pts)]


def _objects(conn, sheet_id: int) -> list[dict]:
    out = []
    for r in conn.execute("SELECT o.*, v.label AS vp_label FROM drawing_objects o LEFT JOIN viewports v"
                          " ON v.id = o.viewport_id WHERE o.sheet_id = ? ORDER BY o.id", (sheet_id,)):
        r = dict(r)
        pts = _points(json.loads(r["geometry_json"]))
        r.update(pts=pts, center=_centroid(pts), shape=_shape(pts), box=_bbox(pts),
                 real=json.loads(r["real_units_json"]) if r["real_units_json"] else None,
                 key=(r["kind"], _norm(r["label"]), _norm(r["tag"]), _norm(r["block_name"]), _norm(r["layer"])))
        out.append(r)
    return out


def _sheets(conn, plan_set_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM sheets WHERE plan_set_id = ? ORDER BY page_no",
                                          (plan_set_id,))]


def _match_sheets(old: list[dict], new: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    pairs, left, right = [], list(old), list(new)
    for field in ("sheet_no", "title", "page_no"):
        for o in list(left):
            if field != "page_no" and not o[field]:
                continue
            match = next((n for n in right if (n[field] == o[field] if field == "page_no"
                                                else _norm(n[field]) == _norm(o[field]))), None)
            if match:
                pairs.append((o, match))
                left.remove(o)
                right.remove(match)
    return pairs, left, right


def _diff_sheet(old_objs: list[dict], new_objs: list[dict], diag: float | None) -> dict:
    result = {"unchanged": [], "moved": [], "changed": [], "removed": [], "added": []}
    remaining_new = list(new_objs)
    unmatched_old = []
    for o in old_objs:                                   # pass 1: same thing, same place, same shape
        hit = next((n for n in remaining_new if n["key"] == o["key"] and n["pts"] == o["pts"]), None)
        if hit:
            remaining_new.remove(hit)
            kind = "unchanged" if (hit["real"] or {}) == (o["real"] or {}) else "changed"
            result[kind].append((o, hit))
        else:
            unmatched_old.append(o)
    limit = diag * 0.25 if diag else math.inf
    for o in unmatched_old:                              # pass 2: same thing, nearest one
        candidates = [n for n in remaining_new if n["key"] == o["key"]]
        if not candidates:
            result["removed"].append((o, None))
            continue
        best = min(candidates, key=lambda n: math.dist(n["center"], o["center"]))
        if math.dist(best["center"], o["center"]) > limit:
            result["removed"].append((o, None))
            continue
        remaining_new.remove(best)
        same_shape = best["shape"] == o["shape"] and (best["real"] or {}) == (o["real"] or {})
        result["moved" if same_shape else "changed"].append((o, best))
    result["added"] = [(None, n) for n in remaining_new]
    return result


def _schedule_rows(conn, plan_set_id: int) -> dict:
    rows = {}
    for r in conn.execute("SELECT c.schedule_type, r.mark, r.fields_json FROM schedule_rows r JOIN schedules c"
                          " ON c.id = r.schedule_id JOIN sheets s ON s.id = c.sheet_id WHERE s.plan_set_id = ?",
                          (plan_set_id,)):
        rows[(r["schedule_type"], _norm(r["mark"]))] = {"mark": r["mark"], "fields": json.loads(r["fields_json"])}
    return rows


def _item(o: dict | None) -> dict | None:
    if o is None:
        return None
    return {"object_id": o["id"], "kind": o["kind"], "label": o["label"], "tag": o["tag"], "bbox": o["box"],
            "real_units": o["real"]}


def _compare(conn, ctx, old_ps: dict, new_ps: dict) -> dict:
    old_sheets, new_sheets = _sheets(conn, old_ps["id"]), _sheets(conn, new_ps["id"])
    pairs, gone, fresh = _match_sheets(old_sheets, new_sheets)
    status: dict[int, str] = {}                          # old object id -> unchanged/moved/changed/removed
    mapping: dict[int, int] = {}                         # old object id -> new object id
    sheet_map = {o["id"]: n["id"] for o, n in pairs}
    vp_map: dict[int, int] = {}
    per_sheet, totals = [], {"unchanged": 0, "moved": 0, "changed": 0, "removed": 0, "added": 0}
    changed_new = []
    for o_s, n_s in pairs:
        new_vps = {_norm(v["label"]): v["id"] for v in conn.execute("SELECT id, label FROM viewports WHERE sheet_id = ?",
                                                                     (n_s["id"],))}
        for v in conn.execute("SELECT id, label FROM viewports WHERE sheet_id = ?", (o_s["id"],)):
            if _norm(v["label"]) in new_vps:
                vp_map[v["id"]] = new_vps[_norm(v["label"])]
        dims = [float(x) for x in (n_s["width"], n_s["height"]) if x]
        diag = math.hypot(*dims) if len(dims) == 2 else None
        new_objs = _objects(conn, n_s["id"])
        d = _diff_sheet(_objects(conn, o_s["id"]), new_objs, diag)
        entry = {"old_sheet_id": o_s["id"], "new_sheet_id": n_s["id"], "sheet_no": n_s["sheet_no"] or o_s["sheet_no"],
                 "title": n_s["title"]}
        for kind, items in d.items():
            totals[kind] += len(items)
            entry[kind] = len(items)
            for old_o, new_o in items:
                if old_o is not None:
                    status[old_o["id"]] = kind
                    if new_o is not None:
                        mapping[old_o["id"]] = new_o["id"]
                if kind in ("moved", "changed", "added") and new_o is not None:
                    changed_new.append(new_o["id"])
            if kind != "unchanged":
                entry[f"{kind}_items"] = [{"old": _item(a), "new": _item(b)} for a, b in items[:OVERLAY_CAP]]
        marks = [o for o in new_objs
                 if REV_MARK.search(" ".join(filter(None, (o["label"], o["layer"], o["block_name"]))))]
        entry["marks"] = len(marks)
        if marks:
            entry["marks_items"] = [{"old": None, "new": _item(o)} for o in marks[:OVERLAY_CAP]]
        entry["changed_anything"] = any(entry[k] for k in ("moved", "changed", "removed", "added", "marks"))
        per_sheet.append(entry)
    for s in gone:
        for o in _objects(conn, s["id"]):
            status[o["id"]] = "removed"
            totals["removed"] += 1
    for s in fresh:
        n = conn.execute("SELECT COUNT(*) FROM drawing_objects WHERE sheet_id = ?", (s["id"],)).fetchone()[0]
        totals["added"] += n
        changed_new += [r[0] for r in conn.execute("SELECT id FROM drawing_objects WHERE sheet_id = ?", (s["id"],))]
    old_rows, new_rows = _schedule_rows(conn, old_ps["id"]), _schedule_rows(conn, new_ps["id"])
    sched = {"added": [new_rows[k]["mark"] for k in new_rows if k not in old_rows],
             "removed": [old_rows[k]["mark"] for k in old_rows if k not in new_rows],
             "changed": [{"type": k[0], "mark": new_rows[k]["mark"],
                          "fields": {f: [old_rows[k]["fields"].get(f), new_rows[k]["fields"].get(f)]
                                     for f in sorted(set(old_rows[k]["fields"]) | set(new_rows[k]["fields"]))
                                     if old_rows[k]["fields"].get(f) != new_rows[k]["fields"].get(f)}}
                         for k in new_rows if k in old_rows and new_rows[k]["fields"] != old_rows[k]["fields"]]}
    marks = sum(1 for r in conn.execute(
        "SELECT o.label, o.layer, o.block_name FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
        " WHERE s.plan_set_id = ?", (new_ps["id"],)) if REV_MARK.search(" ".join(filter(None, tuple(r)))))
    return {"totals": totals, "sheets": per_sheet,
            "sheets_removed": [{"sheet_id": s["id"], "sheet_no": s["sheet_no"], "title": s["title"]} for s in gone],
            "sheets_added": [{"sheet_id": s["id"], "sheet_no": s["sheet_no"], "title": s["title"]} for s in fresh],
            "schedules": sched, "revision_marks": marks, "status": status, "mapping": mapping, "sheet_map": sheet_map,
            "vp_map": vp_map, "changed_new": changed_new,
            "changed_sheets": {e["old_sheet_id"] for e in per_sheet if e["changed_anything"]}}


def _measurement_effects(conn, ctx, old_ps: dict, diff: dict) -> tuple[list[dict], list[dict]]:
    """Which measurements on the old set carry over and which are flagged to re-measure."""
    old_sheets = {r[0] for r in conn.execute("SELECT id FROM sheets WHERE plan_set_id = ?", (old_ps["id"],))}
    carry, flag = [], []
    for m in conn.execute("SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ? AND status != 'rejected'",
                          (ctx.company_id, old_ps["estimate_id"])):
        m = dict(m)
        ids = json.loads(m["source_object_ids"] or "[]")
        if ids:
            states = [diff["status"].get(i) for i in ids]
            if all(s is None for s in states):
                continue                                  # not on the old set
            bad = sorted({s or "removed" for s in states if s != "unchanged"})
            if not bad:
                carry.append({"m": m, "ids": [diff["mapping"][i] for i in ids]})
            else:
                flag.append({"m": m, "why": bad})
        elif m["sheet_id"] in old_sheets:                 # drawn or typed on a sheet of the old set
            if m["sheet_id"] in diff["changed_sheets"] or m["sheet_id"] not in diff["sheet_map"]:
                flag.append({"m": m, "why": ["sheet changed"]})
            else:
                carry.append({"m": m, "ids": []})
    return carry, flag


def _load_report(conn, ctx, report_id: int) -> dict:
    r = conn.execute("SELECT * FROM revision_reports WHERE id = ? AND company_id = ?",
                     (int(report_id), ctx.company_id)).fetchone()
    if r is None:
        raise NotFound(f"revision report {report_id} not found", report_id=report_id)
    r = dict(r)
    return {"ok": True, "report_id": r["id"], "estimate_id": r["estimate_id"], "old_plan_set_id": r["old_plan_set_id"],
            "new_plan_set_id": r["new_plan_set_id"], **json.loads(r["summary_json"]),
            "changed_object_ids": json.loads(r["changed_object_ids"]),
            "flagged_measurement_ids": json.loads(r["flagged_measurement_ids"]),
            "carried_measurement_ids": json.loads(r["carried_measurement_ids"]), "created_by": r["created_by"],
            "created_at": r["created_at"]}


def compare(conn, ctx: RequestContext, new_plan_set_id: int | None = None, old_plan_set_id: int | None = None, *,
            confirm: bool = False, report_id: int | None = None) -> dict:
    """plan_compare_revisions: compare a revised plan set with the one it replaces (or any two processed sets on the
    same estimate). Saves a revision report, carries unchanged measurements over and flags the rest to re-measure.
    Asks first. With report_id, shows a saved report instead."""
    if report_id is not None:
        return _load_report(conn, ctx, report_id)
    store._role(ctx, store.EDIT_ROLES, "compare plan revisions")
    if new_plan_set_id is None:
        raise InvalidInput("give the new plan set (new_plan_set_id)", field="new_plan_set_id")
    new_ps = store.load_plan_set(conn, ctx, int(new_plan_set_id))
    old_id = old_plan_set_id or new_ps["supersedes_plan_set_id"]
    if not old_id:
        raise InvalidInput(f"plan set {new_ps['id']} doesn't replace another one; give old_plan_set_id",
                           field="old_plan_set_id")
    old_ps = store.load_plan_set(conn, ctx, int(old_id))
    if old_ps["id"] == new_ps["id"]:
        raise InvalidInput("those are the same plan set")
    if old_ps["estimate_id"] != new_ps["estimate_id"]:
        raise InvalidInput("both plan sets must be on the same estimate")
    for ps in (old_ps, new_ps):
        if ps["status"] != "processed":
            raise InvalidInput(f"plan set {ps['id']} hasn't been read yet (it's {ps['status']}); process it first",
                               plan_set_id=ps["id"])
    if ctx.mode == "server":
        n = conn.execute("SELECT COUNT(*) FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
                         " WHERE s.plan_set_id IN (?, ?)", (old_ps["id"], new_ps["id"])).fetchone()[0]
        if n > SERVER_OBJECT_CAP:
            raise NotAvailable(f"comparing {n} drawing objects is heavy work, and the server only does light work. "
                               "Compare them on a processing PC", objects=n, cap=SERVER_OBJECT_CAP)
    diff = _compare(conn, ctx, old_ps, new_ps)
    carry, flag = _measurement_effects(conn, ctx, old_ps, diff)
    t = diff["totals"]
    summary = {"totals": t, "sheets": diff["sheets"], "sheets_removed": diff["sheets_removed"],
               "sheets_added": diff["sheets_added"], "schedules": diff["schedules"],
               "revision_marks": diff["revision_marks"],
               "said": (f"Rev {old_ps['revision']} → Rev {new_ps['revision']}: {t['added']} added, {t['removed']} "
                        f"removed, {t['moved']} moved, {t['changed']} changed, {t['unchanged']} unchanged; "
                        f"schedule rows {len(diff['schedules']['added'])} added, "
                        f"{len(diff['schedules']['removed'])} removed, {len(diff['schedules']['changed'])} changed. "
                        f"{len(carry)} measurement(s) carry over, {len(flag)} need re-measuring.")}
    if not confirm:
        raise ConfirmationRequired(summary["said"] + " Save the revision report and update the measurements? "
                                   "Call again with confirm=true.", totals=t, carry=len(carry), flag=len(flag))
    now = _now()
    with service.transaction(conn):
        for c in carry:
            m = c["m"]
            calc = json.loads(m["calc_json"] or "{}")
            calc["carried_over"] = {"from_plan_set": old_ps["id"], "to_plan_set": new_ps["id"], "at": now}
            new_sheet = diff["sheet_map"].get(m["sheet_id"]) if m["sheet_id"] else None
            new_vp = diff["vp_map"].get(m["viewport_id"]) if m["viewport_id"] else None
            if c["ids"] and new_sheet is None:
                new_sheet = conn.execute("SELECT sheet_id FROM drawing_objects WHERE id = ?",
                                         (c["ids"][0],)).fetchone()[0]
            conn.execute("UPDATE measurements SET source_object_ids = ?, sheet_id = COALESCE(?, sheet_id),"
                         " viewport_id = COALESCE(?, viewport_id), calc_json = ?, updated_at = ? WHERE id = ?",
                         (json.dumps(c["ids"]) if c["ids"] else m["source_object_ids"], new_sheet, new_vp,
                          json.dumps(calc), now, m["id"]))
            service._log(conn, ctx, m["estimate_id"], "measurement_carried_over",
                         {"measurement_id": m["id"], "plan_set_id": new_ps["id"]})
        for f in flag:
            m = f["m"]
            calc = json.loads(m["calc_json"] or "{}")
            calc["revision"] = {"plan_set": new_ps["id"], "why": f["why"], "at": now}
            conn.execute("UPDATE measurements SET needs_remeasure = 1, calc_json = ?, updated_at = ? WHERE id = ?",
                         (json.dumps(calc), now, m["id"]))
            service._log(conn, ctx, m["estimate_id"], "measurement_flagged",
                         {"measurement_id": m["id"], "reason": "plan revision: " + ", ".join(f["why"])})
        rid = int(conn.execute(
            "INSERT INTO revision_reports (company_id, estimate_id, old_plan_set_id, new_plan_set_id, summary_json,"
            " changed_object_ids, flagged_measurement_ids, carried_measurement_ids, created_by, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ctx.company_id, new_ps["estimate_id"], old_ps["id"], new_ps["id"], json.dumps(summary),
             json.dumps(sorted(diff["changed_new"])), json.dumps(sorted(f["m"]["id"] for f in flag)),
             json.dumps(sorted(c["m"]["id"] for c in carry)), ctx.actor, now)).lastrowid)
        service._log(conn, ctx, new_ps["estimate_id"], "plan_revision_compared",
                     {"report_id": rid, "old_plan_set_id": old_ps["id"], "new_plan_set_id": new_ps["id"], **t})
    return _load_report(conn, ctx, rid)

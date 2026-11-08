"""Reviews: checking a count or measurement on the plans, saving the check as versions, and approving it.

Spec: "Visual verification of counts and detections". History is never rewritten:
- The first time a count is reviewed, its current result is kept as version 0 ("original").
- Every save is a new version (status in_review); the one before it is marked superseded.
- Approving a version (a person only) makes it the value used for pricing. The measurement it belongs to takes the
  approved quantity and objects and is locked. Earlier versions stay viewable; bids already sent keep their counts.

Targets: `measurement` (any measurement), `count` (a measurement of kind count), `schedule` (a schedule row and the
plan tags linked to it). `detection_set` waits for the symbol engine (Coder 2) and says so.

Review status per count: unreviewed (no versions) -> in_review -> approved.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal

from estimator.context import RequestContext
from estimator.drawing_model import geometry as geo
from estimator.errors import (ConfirmationRequired, InvalidInput, NotAvailable, NotEditable, NotFound,
                              PermissionDenied)
from estimator.estimating import service
from estimator.takeoff import measurements as meas

TARGETS = ("count", "measurement", "detection_set", "schedule")
WORK_ROLES = service.EDIT_ROLES + ("reviewer",)     # who can open and save reviews (agents may draft)
MAX_CHANGE = 5000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _confirm(confirm: bool, message: str, **details) -> None:
    if not confirm:
        raise ConfirmationRequired(message + " Call again with confirm=true.", **details)


def _role(ctx: RequestContext, what: str) -> None:
    if ctx.role not in WORK_ROLES:
        raise PermissionDenied(f"only {', '.join(WORK_ROLES)} can {what}", role=ctx.role)


def _ids(values, field: str) -> list[int]:
    if values in (None, ""):
        return []
    if isinstance(values, (int, str)):
        values = [v for v in str(values).replace(",", " ").split() if v]
    try:
        out = sorted({int(v) for v in values})
    except (TypeError, ValueError):
        raise InvalidInput(f"{field} must be drawing object ids (numbers)", field=field) from None
    if len(out) > MAX_CHANGE:
        raise InvalidInput(f"at most {MAX_CHANGE} objects at once", field=field)
    return out


# ---------------------------------------------------------------- targets

def _target(conn, ctx, target_type: str, target_id: int) -> dict:
    """What is being reviewed: {type, id, estimate_id, object_ids, qty, unit, kind, label, row}."""
    if target_type not in TARGETS:
        raise InvalidInput(f"target_type must be one of {', '.join(TARGETS)}", field="target_type", valid=list(TARGETS))
    if target_type == "detection_set":
        raise NotAvailable("symbol detections come from the symbol engine, which isn't installed yet. Review the "
                           "count as a measurement instead (target_type=count)", target_type=target_type)
    if target_type in ("measurement", "count"):
        m = meas._load(conn, ctx, target_id)
        if target_type == "count" and m["kind"] != "count":
            raise InvalidInput(f"measurement {m['id']} is a {m['kind']}, not a count; use target_type=measurement",
                               field="target_type")
        if m["status"] == "rejected":
            raise NotEditable("that measurement was rejected; there's nothing to review", measurement_id=m["id"])
        kind = "count" if m["kind"] == "count" else "measurement"      # one name per measurement, whichever was asked
        return {"type": kind, "id": m["id"], "estimate_id": m["estimate_id"],
                "object_ids": json.loads(m["source_object_ids"] or "[]"), "qty": m["qty"], "unit": m["unit"],
                "kind": m["kind"], "label": m["label"] or m["feeds"] or m["kind"], "row": m}
    r = conn.execute(
        "SELECT r.*, s.sheet_id, s.schedule_type, s.title, p.estimate_id FROM schedule_rows r"
        " JOIN schedules s ON s.id = r.schedule_id JOIN sheets h ON h.id = s.sheet_id"
        " JOIN plan_sets p ON p.id = h.plan_set_id WHERE r.id = ? AND r.company_id = ?",
        (int(target_id), ctx.company_id)).fetchone()
    if r is None:
        raise NotFound(f"schedule row {target_id} not found", target_id=target_id)
    r = dict(r)
    ids = json.loads(r["linked_object_ids"] or "[]")
    return {"type": "schedule", "id": r["id"], "estimate_id": r["estimate_id"], "object_ids": ids,
            "qty": str(len(ids)), "unit": "ea", "kind": "count",
            "label": f"{r['schedule_type']} {r['mark'] or ''}".strip(), "row": r}


def _plan_sets(conn, ctx, estimate_id: int) -> set[int]:
    return {r[0] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?",
                                       (ctx.company_id, estimate_id))}


def _objects(conn, ctx, ids: list[int], estimate_id: int) -> dict[int, dict]:
    if not ids:
        return {}
    rows = {r["id"]: dict(r) for r in conn.execute(
        f"SELECT o.*, s.plan_set_id, s.sheet_no, s.page_no, s.image_path, s.width AS sheet_width,"
        f" s.height AS sheet_height FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
        f" WHERE o.company_id = ? AND o.id IN ({','.join('?' for _ in ids)})", [ctx.company_id, *ids])}
    missing = sorted(set(ids) - set(rows))
    if missing:
        raise NotFound(f"drawing object(s) {missing} not found", object_ids=missing)
    mine = _plan_sets(conn, ctx, estimate_id)
    other = sorted(i for i, r in rows.items() if r["plan_set_id"] not in mine)
    if other:
        raise InvalidInput(f"object(s) {other} are on another estimate's plans", object_ids=other)
    return rows


def _qty(conn, ctx, target: dict, ids: list[int]) -> str:
    """The quantity a set of objects adds up to, measured the same way as the target."""
    if target["type"] == "schedule":
        return str(len(ids))
    if target["kind"] == "count":
        return meas._q(Decimal(len(ids)))
    if target["kind"] not in meas.KIND_UNITS:
        return target["qty"]                          # volume/other: typed numbers, only edited by qty
    if not ids:
        return "0.00"
    rows = list(_objects(conn, ctx, ids, target["estimate_id"]).values())
    total, bad = meas._measure_objects(rows, target["kind"])
    if bad:
        raise InvalidInput(f"object(s) {bad} can't be measured as {target['kind']} (no scale or wrong shape)",
                           object_ids=bad)
    return meas._q(total)


# ---------------------------------------------------------------- versions

def _versions(conn, ctx, target_type: str, target_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM reviews WHERE company_id = ? AND target_type = ? AND target_id = ? ORDER BY version",
        (ctx.company_id, target_type, int(target_id)))]


def _load(conn, ctx, review_id: int) -> dict:
    row = conn.execute("SELECT * FROM reviews WHERE id = ? AND company_id = ?",
                       (int(review_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"review {review_id} not found", review_id=review_id)
    return dict(row)


def _summary(changes: dict) -> str:
    parts = []
    if changes.get("added"):
        parts.append(f"+{len(changes['added'])} added")
    if changes.get("removed"):
        parts.append(f"−{len(changes['removed'])} removed")
    if changes.get("relabelled"):
        parts.append(f"{len(changes['relabelled'])} relabelled")
    if changes.get("edited"):
        parts.append("quantity edited")
    return ", ".join(parts) or "no changes"


def _public(v: dict) -> dict:
    changes = json.loads(v["changes_json"] or "{}")
    return {"id": v["id"], "target_type": v["target_type"], "target_id": v["target_id"], "version": v["version"],
            "base_version": v["base_version"], "status": v["status"], "result_qty": v["result_qty"],
            "unit": v["unit"], "objects": len(json.loads(v["object_ids"] or "[]")), "changes": changes,
            "summary": _summary(changes), "note": v["note"], "reviewer": v["reviewer_id"],
            "approver": v["approver_id"], "approved_at": v["approved_at"], "second_check_by": v["second_check_by"],
            "created_at": v["created_at"]}


def _status(versions: list[dict]) -> str:
    live = [v for v in versions if v["status"] in ("in_review", "approved")]
    if any(v["status"] == "in_review" for v in live):
        return "in_review"
    if any(v["status"] == "approved" for v in live):
        return "approved"
    return "unreviewed"


def _insert(conn, ctx, target: dict, version: int, base, status: str, ids: list[int], changes: dict, qty: str,
            note: str | None) -> int:
    return int(conn.execute(
        "INSERT INTO reviews (company_id, estimate_id, target_type, target_id, version, base_version, status,"
        " object_ids, changes_json, result_qty, unit, note, reviewer_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ctx.company_id, target["estimate_id"], target["type"], target["id"], version, base, status, json.dumps(ids),
         json.dumps(changes), qty, target["unit"], note, ctx.actor, _now())).lastrowid)


# ---------------------------------------------------------------- the tools

def start(conn, ctx: RequestContext, target_type: str, target_id: int) -> dict:
    """review_start: open a review on a count, measurement or schedule row. Keeps the current result as version 0 the
    first time. If a review is already open, returns it."""
    _role(ctx, "review counts")
    target = _target(conn, ctx, target_type, target_id)
    versions = _versions(conn, ctx, target["type"], target["id"])
    open_ = next((v for v in versions if v["status"] == "in_review"), None)
    if open_:
        return {"ok": True, "review": _public(open_), "already_open": True, "status": "in_review",
                "next": "add, remove or relabel objects with review_save, then a person approves with review_approve"}
    with service.transaction(conn):
        if not versions:
            _insert(conn, ctx, target, 0, None, "original", target["object_ids"],
                    {"original": True, "label": target["label"]}, target["qty"], "the result before any review")
        base = max(v["version"] for v in versions) if versions else 0
        rid = _insert(conn, ctx, target, base + 1, base, "in_review", target["object_ids"], {}, target["qty"], None)
        service._log(conn, ctx, target["estimate_id"], "review_started",
                     {"review_id": rid, "target_type": target["type"], "target_id": target["id"], "version": base + 1})
    return {"ok": True, "review": _public(_load(conn, ctx, rid)), "status": "in_review",
            "highlight": highlight(conn, ctx, target["type"], target["id"])["sheets"],
            "next": "add, remove or relabel objects with review_save, then a person approves with review_approve"}


def save(conn, ctx: RequestContext, review_id: int, *, add=None, remove=None, relabel: dict | None = None,
         relabel_matching: bool = False, qty=None, note: str | None = None) -> dict:
    """review_save: save changes as a new version. add/remove are drawing object ids; relabel is {object_id: new label}
    (the object leaves this count; relabel_matching=true does the same to every identical symbol on that plan set);
    qty overrides the quantity for an area or length edited by hand. Nothing is priced until a person approves."""
    _role(ctx, "save reviews")
    cur = _load(conn, ctx, review_id)
    if cur["status"] != "in_review":
        raise NotEditable(f"review version {cur['version']} is {cur['status']}; open a new one with review_start",
                          review_id=cur["id"], status=cur["status"])
    target = _target(conn, ctx, cur["target_type"], cur["target_id"])
    adds, removes = _ids(add, "add"), _ids(remove, "remove")
    relabel = relabel or {}
    if not isinstance(relabel, dict):
        raise InvalidInput("relabel must be {object_id: new label}", field="relabel")
    try:
        relabel = {int(k): str(v).strip() for k, v in relabel.items()}
    except (TypeError, ValueError):
        raise InvalidInput("relabel keys must be drawing object ids", field="relabel") from None
    if any(not v for v in relabel.values()):
        raise InvalidInput("every relabel needs a new label", field="relabel")
    if set(adds) & set(removes):
        raise InvalidInput("an object can't be added and removed at once", object_ids=sorted(set(adds) & set(removes)))
    ids = json.loads(cur["object_ids"] or "[]")
    have = set(ids)
    rows = _objects(conn, ctx, sorted(set(adds) | set(removes) | set(relabel)), target["estimate_id"])
    if relabel_matching and relabel:
        for oid, label in list(relabel.items()):
            o = rows[oid]
            key = ("block_name", o["block_name"]) if o["block_name"] else ("label", o["label"])
            if key[1] is None:
                continue
            for r in conn.execute(f"SELECT o.id FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
                                  f" WHERE o.company_id = ? AND s.plan_set_id = ? AND o.{key[0]} = ?",
                                  (ctx.company_id, o["plan_set_id"], key[1])):
                if r["id"] in have:
                    relabel.setdefault(r["id"], label)
    not_in = sorted(i for i in set(removes) | set(relabel) if i not in have)
    if not_in:
        raise InvalidInput(f"object(s) {not_in} aren't in this count", object_ids=not_in)
    already = sorted(i for i in adds if i in have)
    if already:
        raise InvalidInput(f"object(s) {already} are already in this count", object_ids=already)
    if not (adds or removes or relabel or qty not in (None, "")):
        raise InvalidInput("nothing to save: give add, remove, relabel or qty")
    new_ids = sorted((have | set(adds)) - set(removes) - set(relabel))
    changes = json.loads(cur["changes_json"] or "{}")
    for k, vals in (("added", adds), ("removed", removes)):
        changes[k] = sorted(set(changes.get(k, [])) | set(vals))
    # an object added then removed again in a later save is simply not a change
    both = set(changes.get("added", [])) & set(changes.get("removed", []))
    changes["added"] = sorted(set(changes.get("added", [])) - both)
    changes["removed"] = sorted(set(changes.get("removed", [])) - both)
    rel = changes.get("relabelled", {})
    rel.update({str(k): v for k, v in relabel.items()})
    changes["relabelled"] = rel
    result = _qty(conn, ctx, target, new_ids)
    if qty not in (None, ""):
        if target["kind"] == "count" or target["type"] == "schedule":
            raise InvalidInput("a count is changed by adding or removing objects, not by typing a number", field="qty")
        value = geo.dec(qty, "qty")
        if value < 0:
            raise InvalidInput("a quantity can't be negative", field="qty")
        changes["edited"] = {"from": result, "to": meas._q(value), "by": ctx.actor}
        result = meas._q(value)
    elif "edited" in changes and not (adds or removes):
        result = changes["edited"]["to"]
    with service.transaction(conn):
        conn.execute("UPDATE reviews SET status = 'superseded' WHERE id = ?", (cur["id"],))
        rid = _insert(conn, ctx, target, cur["version"] + 1, cur["version"], "in_review", new_ids, changes, result,
                      note if note is not None else cur["note"])
        service._log(conn, ctx, target["estimate_id"], "review_saved",
                     {"review_id": rid, "target_type": target["type"], "target_id": target["id"],
                      "version": cur["version"] + 1, "summary": _summary(changes), "result_qty": result})
    v = _load(conn, ctx, rid)
    return {"ok": True, "review": _public(v), "was": cur["result_qty"], "now": result,
            "next": "a person approves this version with review_approve"}


def approve(conn, ctx: RequestContext, review_id: int, *, second_check: bool = False, confirm: bool = False) -> dict:
    """review_approve: a person approves a review version; it becomes the value used for pricing. With
    second_check=true, a different person signs off an already approved version."""
    meas._person(ctx, "approve a review")
    v = _load(conn, ctx, review_id)
    if second_check:
        if v["status"] != "approved":
            raise NotEditable("a second check is for an approved version; approve it first", review_id=v["id"])
        if v["approver_id"] == ctx.actor:
            raise PermissionDenied("the second check has to be someone other than the approver",
                                   approver=v["approver_id"])
        if v["second_check_by"]:
            raise NotEditable(f"{v['second_check_by']} already did the second check", review_id=v["id"])
        _confirm(confirm, f"Sign off the second check on {v['target_type']} {v['target_id']} "
                          f"({v['result_qty']} {v['unit']})?", review_id=v["id"])
        with service.transaction(conn):
            conn.execute("UPDATE reviews SET second_check_by = ?, second_check_at = ? WHERE id = ?",
                         (ctx.actor, _now(), v["id"]))
            service._log(conn, ctx, v["estimate_id"], "review_second_check", {"review_id": v["id"]})
        return {"ok": True, "review": _public(_load(conn, ctx, v["id"]))}
    if v["status"] != "in_review":
        raise NotEditable(f"review version {v['version']} is {v['status']}; only an open review can be approved",
                          review_id=v["id"], status=v["status"])
    target = _target(conn, ctx, v["target_type"], v["target_id"])
    changes = json.loads(v["changes_json"] or "{}")
    _confirm(confirm, f"Approve {target['label']}: {target['qty']} → {v['result_qty']} {v['unit']} "
                      f"({_summary(changes)})? This becomes the number used for pricing.",
             review_id=v["id"], was=target["qty"], now=v["result_qty"])
    ids = json.loads(v["object_ids"] or "[]")
    now = _now()
    with service.transaction(conn):
        conn.execute("UPDATE reviews SET status = 'superseded' WHERE company_id = ? AND target_type = ? AND"
                     " target_id = ? AND status = 'approved'", (ctx.company_id, v["target_type"], v["target_id"]))
        conn.execute("UPDATE reviews SET status = 'approved', approver_id = ?, approved_at = ? WHERE id = ?",
                     (ctx.actor, now, v["id"]))
        for oid, label in (changes.get("relabelled") or {}).items():
            conn.execute("UPDATE drawing_objects SET label = ? WHERE id = ? AND company_id = ?",
                         (label, int(oid), ctx.company_id))
        if target["type"] in ("measurement", "count"):
            m = target["row"]
            calc = json.loads(m["calc_json"] or "{}")
            calc["review"] = {"review_id": v["id"], "version": v["version"], "by": ctx.actor, "at": now,
                              "from": m["qty"], "to": v["result_qty"], "summary": _summary(changes)}
            conn.execute("UPDATE measurements SET qty = ?, source_object_ids = ?, calc_json = ?, status = 'approved',"
                         " locked = 1, needs_remeasure = 0, approved_by = ?, approved_at = ?, updated_at = ?"
                         " WHERE id = ?", (v["result_qty"], json.dumps(ids), json.dumps(calc), ctx.actor, now, now,
                                           m["id"]))
        else:
            conn.execute("UPDATE schedule_rows SET linked_object_ids = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                         (json.dumps(ids), ctx.actor, now, target["id"]))
        service._log(conn, ctx, v["estimate_id"], "review_approved",
                     {"review_id": v["id"], "target_type": v["target_type"], "target_id": v["target_id"],
                      "version": v["version"], "result_qty": v["result_qty"], "summary": _summary(changes)},
                     before={"qty": target["qty"]})
    return {"ok": True, "review": _public(_load(conn, ctx, v["id"])), "status": "approved",
            "was": target["qty"], "now": v["result_qty"]}


def history(conn, ctx: RequestContext, target_type: str, target_id: int) -> dict:
    """review_history: every version of a count with who changed what."""
    target = _target(conn, ctx, target_type, target_id)
    versions = _versions(conn, ctx, target["type"], target["id"])
    current = next((v for v in versions if v["status"] == "approved"), None)
    return {"ok": True, "target_type": target["type"], "target_id": target["id"], "label": target["label"],
            "status": _status(versions), "current_qty": target["qty"], "unit": target["unit"],
            "approved_version": current["version"] if current else None,
            "versions": [_public(v) for v in versions]}


def status_for_estimate(conn, ctx: RequestContext, estimate_id: int) -> dict:
    """{measurement_id: unreviewed/in_review/approved} plus the open review ids, for lists and the send check."""
    out, open_ = {}, []
    for r in conn.execute("SELECT id, target_type, target_id, status FROM reviews WHERE company_id = ? AND"
                          " estimate_id = ? AND status IN ('in_review', 'approved')", (ctx.company_id, int(estimate_id))):
        key = (r["target_type"] if r["target_type"] == "schedule" else "measurement", r["target_id"])
        if r["status"] == "in_review":
            out[key] = "in_review"
            open_.append(r["id"])
        else:
            out.setdefault(key, "approved")
    return {"by_target": out, "open_reviews": open_}


# ---------------------------------------------------------------- highlighting

def _bbox(geometry: dict) -> list[float] | None:
    pts = geometry.get("points") or ([[geometry["x"], geometry["y"]]] if "x" in geometry else None)
    if geometry.get("type") == "point" and not pts and "point" in geometry:
        pts = [geometry["point"]]
    if not pts:
        return None
    xs = [float(p[0]) for p in pts]
    ys = [float(p[1]) for p in pts]
    return [min(xs), min(ys), max(xs), max(ys)]


def highlight(conn, ctx: RequestContext, target_type: str, target_id: int, version: int | None = None) -> dict:
    """review_highlight: where every object behind a count or quantity is, sheet by sheet, in order for
    next/previous navigation. Boxes are in the sheet's units (origin top-left, like the sheet image)."""
    target = _target(conn, ctx, target_type, target_id)
    ids = target["object_ids"]
    if version is not None:
        v = next((x for x in _versions(conn, ctx, target["type"], target["id"]) if x["version"] == int(version)), None)
        if v is None:
            raise NotFound(f"there's no version {version} of this count", version=version)
        ids = json.loads(v["object_ids"] or "[]")
    rows = {r["id"]: dict(r) for r in conn.execute(
        f"SELECT o.id, o.sheet_id, o.kind, o.label, o.tag, o.geometry_json, o.confidence, s.sheet_no, s.page_no,"
        f" s.title, s.image_path, s.width, s.height FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
        f" WHERE o.company_id = ? AND o.id IN ({','.join('?' for _ in ids)})", [ctx.company_id, *ids])} if ids else {}
    sheets: dict[int, dict] = {}
    for oid in ids:
        r = rows.get(oid)
        if r is None:
            continue
        s = sheets.setdefault(r["sheet_id"], {"sheet_id": r["sheet_id"], "sheet_no": r["sheet_no"],
                                              "page_no": r["page_no"], "title": r["title"],
                                              "has_image": bool(r["image_path"]), "width": r["width"],
                                              "height": r["height"], "hits": []})
        s["hits"].append({"object_id": oid, "kind": r["kind"], "label": r["label"], "tag": r["tag"],
                          "confidence": r["confidence"], "bbox": _bbox(json.loads(r["geometry_json"]))})
    ordered = sorted(sheets.values(), key=lambda s: (s["page_no"] or 0, s["sheet_id"]))
    n = 0
    for s in ordered:
        s["hits"].sort(key=lambda h: (h["bbox"] or [0, 0])[1::-1])     # top to bottom, then left to right
        for h in s["hits"]:
            n += 1
            h["n"] = n
        s["count"] = len(s["hits"])
    return {"ok": True, "target_type": target["type"], "target_id": target["id"], "label": target["label"],
            "qty": target["qty"], "unit": target["unit"], "total_hits": n, "sheets": ordered,
            "by_sheet": {s["sheet_no"] or f"page {s['page_no']}": s["count"] for s in ordered},
            "missing_objects": sorted(set(ids) - set(rows)),
            "status": _status(_versions(conn, ctx, target["type"], target["id"]))}


# ---------------------------------------------------------------- review before sending

def unreviewed_for_send(conn, ctx: RequestContext, estimate_id: int) -> list[str]:
    """What stops a bid from being sent when the company requires every count and measurement to be approved."""
    problems = []
    for m in conn.execute("SELECT id, label, feeds, kind, status, needs_remeasure, suggested_qty FROM measurements"
                          " WHERE company_id = ? AND estimate_id = ? AND status != 'rejected'",
                          (ctx.company_id, int(estimate_id))):
        name = f"measurement {m['id']} ({m['label'] or m['feeds'] or m['kind']})"
        if m["status"] != "approved":
            problems.append(f"{name} isn't approved")
        elif m["needs_remeasure"]:
            problems.append(f"{name} needs re-measuring")
        elif m["suggested_qty"]:
            problems.append(f"{name} has a suggested change waiting")
    st = status_for_estimate(conn, ctx, estimate_id)
    for (kind, tid), s in st["by_target"].items():
        if s == "in_review":
            problems.append(f"the review of {kind} {tid} is still open")
    return problems


def require_before_send(conn, ctx: RequestContext) -> bool:
    row = conn.execute("SELECT require_reviews_before_send FROM company_profile WHERE company_id = ?",
                       (ctx.company_id,)).fetchone()
    return bool(row and row[0])


def set_require_before_send(conn, ctx: RequestContext, enabled: bool, confirm: bool = False) -> dict:
    """Owner setting: bids can only be sent once every count and measurement on the estimate is approved."""
    if ctx.role != "owner" or ctx.agent:
        raise PermissionDenied("only the owner can change this setting", role=ctx.role)
    enabled = bool(enabled)
    _confirm(confirm, ("Require" if enabled else "Stop requiring") + " every count and measurement to be approved "
             "before a quote can be sent?", require_reviews_before_send=enabled)
    with service.transaction(conn):
        conn.execute("INSERT INTO company_profile (company_id, require_reviews_before_send, updated_by, updated_at)"
                     " VALUES (?,?,?,?) ON CONFLICT (company_id) DO UPDATE SET require_reviews_before_send ="
                     " excluded.require_reviews_before_send, updated_by = excluded.updated_by,"
                     " updated_at = excluded.updated_at", (ctx.company_id, int(enabled), ctx.actor, _now()))
    return {"ok": True, "require_reviews_before_send": enabled}

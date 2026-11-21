"""Audit & clean up (2026-11-20, David: "can we have an AI Cleanup run that fixes and removes double counted items and
'from before the plans were read again' issues ... all these rejected items also cause confusion ... make sure the user
can mass accept all of the changes").

audit() looks over an estimate's measurements and lists what needs a person, each finding with the fix it proposes:

  double_counted   an approved AI count from before the plans were read again (its sheet went) and an approved count for
                   the same question on the new sheet: both are priced. Fix: take the old one off.
  replace_old      an approved old count and a new count waiting for review. Fix: approve the new count (at the number on
                   the drawing when the drawing shows a different one); approving it takes the old one off.
  waiting          a count waiting for review. Fix: approve it (at the number on the drawing when that differs).
  drawing_differs  an approved count that isn't what the drawing shows. Fix: change it to the drawing's number.
  rerun            an approved count from before the plans were read again with nothing new to replace it (the wiring
                   run's cable, say). No fix here: it says which run to do again.
  rejected         rejected measurements (never priced, kept as history). Fix: remove them for good.

"What the drawing shows" is the symbols the plan reader classified for the question on the measurement's sheet - the
same symbols the Measure screen lights up (symbol_library.FEEDS; the 30 Amp labels for dedicated circuits). A fix is
ticked to start with when it's safe to accept without looking: the drawing is CAD (its symbols are exact) or agrees with
the count. apply() redoes the audit and applies the chosen findings with the measurement service, so the usual rules hold:
only a person approves, every change is logged.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied
from estimator.estimating import service
from estimator.takeoff import measurements as ms

LABEL_COUNTS = {("electrical", "appliance_circuits"): re.compile(r"\b(?:30|40|50|60)\s?A(?:MP)?\b", re.I)}
WIRING_FEEDS = re.compile(r"^wire_\d+_\d+_ft$")


def _num(v) -> Decimal:
    try:
        return Decimal(str(v))
    except Exception:  # noqa: BLE001 - a bad number is just "no number"
        return Decimal(0)


def _fmt(v) -> str:
    d = _num(v)
    return str(int(d)) if d == d.to_integral_value() else str(d.normalize())


def _drawing_counts(conn, ctx: RequestContext, sheet_ids: set[int]) -> dict:
    """{(sheet_id, module_id, feeds): {"n": count, "cad": all exact}} from the symbols on the sheets."""
    from estimator.plan_engine import symbol_library as lib
    out: dict = {}
    if not sheet_ids:
        return out
    marks = ",".join("?" * len(sheet_ids))
    for d in conn.execute(f"SELECT sheet_id, item_type, method, status FROM symbol_detections WHERE company_id = ?"
                          f" AND sheet_id IN ({marks}) AND status != 'rejected'", (ctx.company_id, *sheet_ids)):
        f = lib.FEEDS.get(d["item_type"] or "")
        if not f or len(f) != 2:
            continue
        k = (d["sheet_id"], f[0], f[1])
        e = out.setdefault(k, {"n": 0, "cad": True})
        e["n"] += 1
        e["cad"] = e["cad"] and d["method"] == "cad"
    for (module_id, feeds), rx in LABEL_COUNTS.items():
        for s in sheet_ids:
            n = sum(1 for t in conn.execute("SELECT label FROM drawing_objects WHERE sheet_id = ? AND kind = 'text'", (s,))
                    if rx.search(t["label"] or ""))
            if n:
                e = out.setdefault((s, module_id, feeds), {"n": 0, "cad": True})
                e["n"] += n
    return out


def _safe(d, target) -> bool:
    """Tick the fix to start with when the drawing backs it: it agrees with the count, or it's CAD (exact symbols) and
    the fix uses its number. Nothing on the drawing to compare with: a person ticks it after a look."""
    return d is not None and (target is None or d["cad"])


def _name(m: dict) -> str:
    label = (m.get("label") or m.get("feeds") or "measurement").replace(" (AI)", "")
    return label[:1].upper() + label[1:]


def _q(m: dict) -> str:
    return f"{_fmt(m['qty'])} {m['unit']}"


def audit(conn, ctx: RequestContext, estimate_id: int) -> dict:
    est = service._load_row(conn, ctx, int(estimate_id))
    rows = [dict(r) for r in conn.execute("SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ?"
                                          " ORDER BY id", (ctx.company_id, est["id"]))]
    live = [m for m in rows if m["status"] != "rejected"]
    old = [m for m in live if m["status"] == "approved" and not m["sheet_id"] and m["proposed_by"] in ms.SHEET_AGENTS]
    old_ids = {m["id"] for m in old}
    current = [m for m in live if m["id"] not in old_ids]
    drawing = _drawing_counts(conn, ctx, {m["sheet_id"] for m in current if m["sheet_id"]})

    def on_drawing(m):
        if not m["sheet_id"] or m["unit"] != "ea" or not m["feeds"]:
            return None
        return drawing.get((m["sheet_id"], m["module_id"], m["feeds"]))

    findings = []

    def add(fid, kind, title, detail, fix, selected, *, ids=(), approve=(), set_qty=None, feeds=None, module_id=None,
            sheet_id=None, delete=()):
        findings.append({"id": fid, "kind": kind, "title": title, "detail": detail, "fix": fix,
                         "selected": bool(selected) and bool(fix), "can_fix": bool(fix),
                         "reject_ids": list(ids), "approve_ids": list(approve), "set_qty": set_qty or {},
                         "delete_ids": list(delete), "feeds": feeds, "module_id": module_id, "sheet_id": sheet_id})

    by_q: dict = {}
    for m in current:
        if m["feeds"]:
            by_q.setdefault((m["module_id"], m["feeds"]), []).append(m)
    done_old = set()
    for o in old:
        key = (o["module_id"], o["feeds"])
        news = by_q.get(key, [])
        approved = [m for m in news if m["status"] == "approved"]
        waiting = [m for m in news if m["status"] == "proposed"]
        if approved:
            done_old.add(o["id"])
            add(f"double:{o['id']}", "double_counted", f"{_name(o)} is priced twice",
                f"The approved {_q(o)} is from before the plans were read again, and {_q(approved[0])} is approved on the"
                f" plans as they read now - both are priced ({_fmt(_num(o['qty']) + sum(_num(m['qty']) for m in approved))}"
                f" {o['unit']}).", f"Take the old {_q(o)} off; keep {_q(approved[0])}.", True, ids=[o["id"]],
                feeds=o["feeds"], module_id=o["module_id"], sheet_id=approved[0]["sheet_id"])
        elif waiting:
            done_old.add(o["id"])
            w = waiting[0]
            d = on_drawing(w)
            target = d["n"] if d and d["n"] and _num(d["n"]) != _num(w["qty"]) else None
            new_q = f"{_fmt(target)} {w['unit']}" if target is not None else _q(w)
            why = (f" (the {target} on the drawing; the AI said {_fmt(w['qty'])})" if target is not None else "")
            # Cable from the wiring run is routed from the CAD drawings (plain geometry): ticked to start with.
            routed = w["proposed_by"] == "wiring-takeoff"
            length = routed and w.get("kind") != "count"     # the wiring run also counts circuits and receptacles
            add(f"replace:{o['id']}", "replace_old", f"{_name(o)}: a new " + ("length" if length else "count") + " is waiting",
                f"The approved {_q(o)} is from before the plans were read again. "
                + (f"The wiring run routed {_q(w)} on the plans as they read now." if length else
                   f"The wiring run found {_q(w)} on the plans as they read now." if routed else
                   f"The AI counted {_q(w)} on the plans as they read now" + (f"; the drawing shows {d['n']}." if d else ".")),
                f"Approve {new_q}{why}; that takes the old {_q(o)} off.", routed or _safe(d, target),
                approve=[w["id"]], set_qty={w["id"]: target} if target is not None else None,
                feeds=w["feeds"], module_id=w["module_id"], sheet_id=w["sheet_id"])
        else:
            done_old.add(o["id"])
            wired = o.get("proposed_by") == "wiring-takeoff" or bool(WIRING_FEEDS.match(o["feeds"] or ""))
            add(f"rerun:{o['id']}", "rerun", f"{_name(o)} is from before the plans were read again",
                f"The approved {_q(o)} was measured on the plans as they read before; nothing new has been measured for"
                f" it since. It's still priced.", "", False, feeds=o["feeds"], module_id=o["module_id"])
            # 2026-11-20 (David: "how do I just run the wiring estimate? is it the same as AI Auto Run?"): say exactly
            # which button, and the audit window offers it (rerun = "wiring" or "auto").
            findings[-1]["rerun"] = "wiring" if wired else "auto"
            findings[-1]["advice"] = (
                "Run the wiring again: ⚡ Run wiring now (here, or in the ⚡ Wiring card under Electrical on this screen)."
                " It routes the cable from the plans as they read now - plain geometry, no AI tokens; you don't need AI"
                " Auto Run for it. Then audit again and approve the new length: that takes this one off." if wired else
                f"Run 🤖 AI Auto Run for {o['module_id'].replace('_', ' ').title()} again (the button above the drawing),"
                f" then audit again: approving the new {_name(o).lower()} takes this one off.")
    handled = {i for f in findings for i in f["approve_ids"]}
    for m in current:
        if m["status"] == "proposed" and m["id"] not in handled and m["proposed_by"] == "wiring-takeoff":
            # 2026-11-20 (David: "3 of these items don't have symbols"): the wiring run isn't the AI - it routes the
            # panel schedule's circuits over the CAD plan (plain geometry), and marks what the designer drew no symbol
            # for (range/dryer receptacles at the appliance, the breakers at the panel). Ticked, like its cable.
            length = m["kind"] != "count"
            d = None if length else on_drawing(m)
            detail = (f"The wiring run routed {_q(m)} from the panel schedule over the plan." if length else
                      f"The wiring run found {_q(m)} on the panel schedule; the drawing shows {d['n']}." if d else
                      f"The wiring run found {_q(m)} on the panel schedule. The designer's drawing has no symbol for"
                      f" it, so the wiring run marks it on the plan (Show on drawing).")
            add(f"waiting:{m['id']}", "waiting", f"{_name(m)} is waiting for review", detail, f"Approve {_q(m)}.",
                True, approve=[m["id"]], feeds=m["feeds"], module_id=m["module_id"], sheet_id=m["sheet_id"])
        elif m["status"] == "proposed" and m["id"] not in handled:
            d = on_drawing(m)
            target = d["n"] if d and d["n"] and _num(d["n"]) != _num(m["qty"]) else None
            detail = (f"The AI counted {_q(m)}." + (f" The drawing shows {d['n']}." if d else
                                                     " There's nothing for it on the drawing to compare with."))
            fix = (f"Approve {_fmt(target)} {m['unit']} (the drawing's number; the AI said {_fmt(m['qty'])})."
                   if target is not None else f"Approve {_q(m)}.")
            add(f"waiting:{m['id']}", "waiting", f"{_name(m)} is waiting for review", detail, fix,
                _safe(d, target), approve=[m["id"]],
                set_qty={m["id"]: target} if target is not None else None, feeds=m["feeds"], module_id=m["module_id"],
                sheet_id=m["sheet_id"])
        elif m["status"] == "approved":
            d = on_drawing(m)
            if d and d["n"] and _num(d["n"]) != _num(m["qty"]):
                add(f"differs:{m['id']}", "drawing_differs", f"{_name(m)}: {_q(m)} approved, the drawing shows {d['n']}",
                    f"The approved count isn't what's lit up on the drawing ({d['n']}).",
                    f"Change it to {d['n']} {m['unit']}.", d["cad"], set_qty={m["id"]: d["n"]},
                    feeds=m["feeds"], module_id=m["module_id"], sheet_id=m["sheet_id"])
    rejected = [m for m in rows if m["status"] == "rejected"]
    in_use = _in_assemblies(conn, ctx, {m["id"] for m in rejected})
    gone = [m for m in rejected if m["id"] not in in_use]
    if gone:
        add("rejected", "rejected", f"{len(gone)} rejected item(s)",
            "Rejected items are never priced; they're kept as history (" +
            ", ".join(sorted({(m['reject_reason'] or 'rejected') for m in gone}))[:300] + ").",
            "Remove them for good.", True, delete=[m["id"] for m in gone])
    order = ["double_counted", "replace_old", "drawing_differs", "waiting", "rerun", "rejected"]
    findings.sort(key=lambda f: order.index(f["kind"]))
    for f in findings:
        f["set_qty"] = {str(k): str(v) for k, v in f["set_qty"].items()}
    return {"ok": True, "estimate_id": est["id"], "findings": findings, "count": len(findings),
            "selected": sum(1 for f in findings if f["selected"]),
            "summary": _summary(findings)}


def _in_assemblies(conn, ctx, ids: set[int]) -> set[int]:
    out = set()
    if not ids:
        return out
    for a in conn.execute("SELECT measurement_ids FROM assembly_uses WHERE company_id = ?", (ctx.company_id,)):
        try:
            out |= set(json.loads(a["measurement_ids"] or "[]")) & ids
        except (TypeError, ValueError):
            continue
    return out


# The findings that make the price wrong (the Director's last check before the estimate moves on stops on these):
# a count priced twice, an old count still priced, an approved count the drawing disagrees with. Counts waiting for
# review and rejected items aren't priced, so they don't stop it.
PRICE_KINDS = ("double_counted", "replace_old", "drawing_differs", "rerun")


def price_problems(conn, ctx: RequestContext, estimate_id: int) -> dict:
    """{"count", "summary", "findings"} for the Director: what in the audit makes the price wrong. Never fails the
    Director - an audit that can't run (no measurements table yet, say) reports nothing."""
    try:
        found = audit(conn, ctx, estimate_id)["findings"]
    except Exception:  # noqa: BLE001 - the checklist must still show
        return {"count": 0, "summary": "", "findings": []}
    bad = [f for f in found if f["kind"] in PRICE_KINDS]
    return {"count": len(bad), "summary": _summary(bad).rstrip(".") if bad else "", "findings": [f["id"] for f in bad],
            "waiting": sum(1 for f in found if f["kind"] == "waiting"),
            "rejected": sum(len(f["delete_ids"]) for f in found if f["kind"] == "rejected")}


def _summary(findings: list[dict]) -> str:
    if not findings:
        return "Nothing to clean up: every count is approved once, matches the drawing, and there are no rejected items."
    # (one, more than one) - 2026-11-20: "3 new count waiting" read wrong.
    names = {"double_counted": ("priced twice", "priced twice"),
             "replace_old": ("new count waiting to replace an old one", "new counts waiting to replace old ones"),
             "drawing_differs": ("approved count that differs from the drawing",
                                 "approved counts that differ from the drawing"),
             "waiting": ("waiting for review", "waiting for review"),
             "rerun": ("needs a run done again", "need a run done again"),
             "rejected": ("rejected item to remove", "rejected items to remove")}
    by: dict = {}
    for f in findings:
        n = len(f["delete_ids"]) if f["kind"] == "rejected" else 1
        by[f["kind"]] = by.get(f["kind"], 0) + n
    return "; ".join(f"{n} {names[k][n != 1]}" for k, n in by.items()) + "."


def apply(conn, ctx: RequestContext, estimate_id: int, finding_ids: list[str], confirm: bool = False) -> dict:
    """Apply the chosen findings' fixes (the audit is done again first, so a stale screen can't apply an old fix)."""
    if ctx.agent or ctx.role not in ms.APPROVE_ROLES:
        raise PermissionDenied("only a person who approves measurements can apply the audit's fixes")
    if not finding_ids:
        raise InvalidInput("choose the fixes to apply (finding_ids)")
    now = audit(conn, ctx, estimate_id)
    by_id = {f["id"]: f for f in now["findings"]}
    chosen = [by_id[i] for i in finding_ids if i in by_id and by_id[i]["can_fix"]]
    missing = [i for i in finding_ids if i not in by_id]
    if not chosen:
        raise InvalidInput("none of those fixes are needed any more - audit again", missing=missing)
    if not confirm:
        raise ConfirmationRequired(f"Apply {len(chosen)} fix(es)? " + " ".join(f["fix"] for f in chosen)[:600],
                                   finding_ids=[f["id"] for f in chosen], missing=missing)
    done = {"taken_off": [], "approved": [], "changed": [], "removed": []}
    for f in chosen:
        for mid, qty in f["set_qty"].items():
            ms.edit(conn, ctx, int(mid), qty=qty, confirm=True)
            done["changed"].append(int(mid))
        for mid in f["reject_ids"]:
            ms.reject(conn, ctx, mid, "audit: priced twice - the count on the plans as they read now stays", confirm=True)
            done["taken_off"].append(mid)
        if f["approve_ids"]:
            out = ms.confirm_measurements(conn, ctx, f["approve_ids"], confirm=True)
            done["approved"] += out["done"]
            done["taken_off"] += out.get("replaced", [])
    # Removing the rejected items goes last, and takes the old counts this same click took off too - otherwise the
    # clean-up would leave fresh clutter behind it.
    if any(f["kind"] == "rejected" for f in chosen):
        ids = [f["delete_ids"] for f in chosen if f["kind"] == "rejected"][0] + done["taken_off"]
        ids = [i for i in ids if i not in _in_assemblies(conn, ctx, set(ids))]
        done["removed"] += _remove(conn, ctx, ids)
    with service.transaction(conn):
        service._log(conn, ctx, int(estimate_id), "measurements_audited",
                     {"findings": [f["id"] for f in chosen], **{k: v for k, v in done.items() if v}})
    parts = []
    if done["approved"]:
        parts.append(f"{len(done['approved'])} approved")
    if done["changed"]:
        parts.append(f"{len(done['changed'])} changed to the drawing's number")
    if done["taken_off"]:
        parts.append(f"{len(done['taken_off'])} old count(s) taken off")
    if done["removed"]:
        parts.append(f"{len(done['removed'])} rejected item(s) removed")
    return {"ok": True, "applied": [f["id"] for f in chosen], "missing": missing, **done,
            "summary": ("Done: " + ", ".join(parts) + ".") if parts else "Nothing changed."}


def _remove(conn, ctx, ids: list[int]) -> list[int]:
    """Delete rejected measurements for good (and any review of them); each is logged with what it was."""
    marks = ",".join("?" * len(ids))
    rows = [dict(r) for r in conn.execute(f"SELECT * FROM measurements WHERE company_id = ? AND status = 'rejected'"
                                          f" AND id IN ({marks})", (ctx.company_id, *ids))]
    with service.transaction(conn):
        for m in rows:
            conn.execute("DELETE FROM reviews WHERE target_type IN ('measurement', 'count') AND target_id = ?", (m["id"],))
            conn.execute("DELETE FROM measurements WHERE id = ?", (m["id"],))
            service._log(conn, ctx, m["estimate_id"], "measurement_deleted",
                         {"measurement_id": m["id"], "qty": m["qty"], "unit": m["unit"], "feeds": m["feeds"],
                          "reason": "audit: a rejected item removed for good", "was": m["reject_reason"]})
    return [m["id"] for m in rows]

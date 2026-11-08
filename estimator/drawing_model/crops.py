"""What the Estimator sends to the customer's AI provider when it looks at plans (spec: Security, privacy and licensing;
test plan: AI crop privacy).

- Only small crops around a symbol or area, plus structured text. A crop is at most CROP_MAX_SHARE of the sheet and is
  scaled down to CROP_MAX_PX on its long side.
- Whole sheets only when a person asked the AI to look at that sheet (user_asked=true). An unattended agent never
  sends a whole sheet.
- Symbol-crop sending is on by default. The first crop shows a one-time notice explaining what is sent (returned with
  the crop and left in the owner's inbox). The owner can turn it off; then no crop is made at all.
- Every crop or sheet prepared for the AI is written to ai_send_log: what, how big, its fingerprint, why, for which
  provider, and who asked.

The symbol engine (Coder 2) and the AI agents call `prepare(...)` for every image they send; nothing else may read
sheet images for the AI.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, NotAvailable, NotFound, PermissionDenied
from estimator.estimating import service

CROP_MAX_SHARE = 0.15          # a crop may cover at most 15% of the sheet's area
CROP_MAX_PX = 1024             # long side of what's sent, in pixels
SHEET_MAX_PX = 2400            # a whole sheet (only when a person asked) is scaled to this
VIEW_ROLES = ("owner", "estimator", "reviewer", "office")
PAD = 0.25                     # padding around an object's box when cropping around an object
NOTICE = ("To identify symbols on your plans, AI-Prowler sends small crops (a few inches of the drawing around one "
          "symbol, plus the legend entry and nearby text) to your AI provider. Whole sheets are only sent when you ask "
          "the AI to look at one. Your plans, prices and bids stay on this PC or your AI-Prowler server. Every crop "
          "sent is logged. The owner can turn crop sending off in Settings → AI and privacy (est_ai_privacy).")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _profile(conn, company_id: str) -> dict:
    row = conn.execute("SELECT crop_sending_enabled, crop_notice_shown_at FROM company_profile WHERE company_id = ?",
                       (company_id,)).fetchone()
    return dict(row) if row else {"crop_sending_enabled": 1, "crop_notice_shown_at": None}


def settings(conn, ctx: RequestContext) -> dict:
    p = _profile(conn, ctx.company_id)
    n = conn.execute("SELECT COUNT(*), MAX(created_at) FROM ai_send_log WHERE company_id = ?",
                     (ctx.company_id,)).fetchone()
    return {"ok": True, "crop_sending_enabled": bool(p["crop_sending_enabled"]),
            "notice_shown_at": p["crop_notice_shown_at"], "notice": NOTICE, "sent_so_far": n[0],
            "last_sent_at": n[1], "limits": {"crop_max_share_of_sheet": CROP_MAX_SHARE, "crop_max_px": CROP_MAX_PX,
                                              "whole_sheet": "only when a person asks"}}


def set_enabled(conn, ctx: RequestContext, enabled: bool, confirm: bool = False) -> dict:
    """Owner only: turn symbol-crop sending on or off for the company."""
    if ctx.role != "owner" or ctx.agent:
        raise PermissionDenied("only the owner can change what's sent to the AI", role=ctx.role)
    enabled = bool(enabled)
    if not confirm:
        raise ConfirmationRequired(
            ("Turn symbol-crop sending ON? Small crops of your plans will be sent to your AI provider to identify "
             "symbols." if enabled else "Turn symbol-crop sending OFF? Nothing from your plans will be sent for symbol "
             "identification; doubtful symbols will wait for a person instead.") + " Call again with confirm=true.",
            crop_sending_enabled=enabled)
    with service.transaction(conn):
        conn.execute("INSERT INTO company_profile (company_id, crop_sending_enabled, updated_by, updated_at)"
                     " VALUES (?,?,?,?) ON CONFLICT (company_id) DO UPDATE SET crop_sending_enabled ="
                     " excluded.crop_sending_enabled, updated_by = excluded.updated_by, updated_at = excluded.updated_at",
                     (ctx.company_id, int(enabled), ctx.actor, _now()))
        service._log(conn, ctx, None, "crop_sending_changed", {"enabled": enabled})
    return settings(conn, ctx)


def send_log(conn, ctx: RequestContext, estimate_id: int | None = None, limit: int = 50) -> dict:
    """What was prepared for the AI, newest first (owner, estimator or reviewer)."""
    if ctx.role not in ("owner", "estimator", "reviewer"):
        raise PermissionDenied("only owner, estimator or reviewer can see the AI send log", role=ctx.role)
    limit = max(1, min(int(limit or 50), 500))
    sql = "SELECT * FROM ai_send_log WHERE company_id = ?"
    args: list = [ctx.company_id]
    if estimate_id:
        sql += " AND estimate_id = ?"
        args.append(int(estimate_id))
    rows = [dict(r) for r in conn.execute(sql + " ORDER BY id DESC LIMIT ?", args + [limit])]
    for r in rows:
        r["bbox"] = json.loads(r.pop("bbox_json")) if r.get("bbox_json") else None
        r["user_asked"] = bool(r["user_asked"])
    return {"ok": True, "count": len(rows), "sent": rows}


# ---------------------------------------------------------------- preparing an image for the AI

def _sheet(conn, ctx, sheet_id: int) -> dict:
    row = conn.execute("SELECT s.*, p.estimate_id FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id"
                       " WHERE s.id = ? AND s.company_id = ?", (int(sheet_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"sheet {sheet_id} not found", sheet_id=sheet_id)
    return dict(row)


def _box(values, field: str) -> list[float]:
    try:
        box = [float(v) for v in (json.loads(values) if isinstance(values, str) else values)]
    except (TypeError, ValueError, json.JSONDecodeError):
        raise InvalidInput(f"{field} must be [x0, y0, x1, y1] in the sheet's units", field=field) from None
    if len(box) != 4 or box[2] <= box[0] or box[3] <= box[1]:
        raise InvalidInput(f"{field} must be [x0, y0, x1, y1] with x1 > x0 and y1 > y0", field=field)
    return box


def _object_box(conn, ctx, object_id: int) -> tuple[int, list[float]]:
    from estimator.takeoff.reviews import _bbox
    row = conn.execute("SELECT sheet_id, geometry_json FROM drawing_objects WHERE id = ? AND company_id = ?",
                       (int(object_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"drawing object {object_id} not found", object_id=object_id)
    b = _bbox(json.loads(row["geometry_json"]))
    if b is None:
        raise InvalidInput(f"object {object_id} has no position to crop around", object_id=object_id)
    w, h = max(b[2] - b[0], 0.5), max(b[3] - b[1], 0.5)
    pad = max(w, h) * PAD + 0.25
    return row["sheet_id"], [b[0] - pad, b[1] - pad, b[2] + pad, b[3] + pad]


def _crops_folder(estimate_id: int) -> Path:
    folder = config.data_dir() / "projects" / f"estimate_{int(estimate_id):04d}" / "ai_sent"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _notice_once(conn, ctx) -> str | None:
    """The one-time notice: returned with the first crop and left in the inbox. Only the first caller gets it."""
    cur = conn.execute("INSERT INTO company_profile (company_id, crop_notice_shown_at, updated_by, updated_at)"
                       " VALUES (?,?,?,?) ON CONFLICT (company_id) DO UPDATE SET crop_notice_shown_at ="
                       " excluded.crop_notice_shown_at WHERE company_profile.crop_notice_shown_at IS NULL",
                       (ctx.company_id, _now(), ctx.actor, _now()))
    if cur.rowcount != 1:
        return None
    from estimator.director.watch import _notice
    _notice(conn, ctx, "privacy", "crop_notice", "🔒 " + NOTICE)
    return NOTICE


def prepare(conn, ctx: RequestContext, sheet_id: int | None = None, *, bbox=None, object_id: int | None = None,
            purpose: str = "", provider: str | None = None, whole_sheet: bool = False,
            user_asked: bool = False) -> dict:
    """Make the image the AI may see and log it. Give an object_id (crop around it) or a sheet_id and bbox. A whole
    sheet needs whole_sheet=true and user_asked=true from a person. Returns the file path to send plus what was logged."""
    if ctx.role not in VIEW_ROLES:
        raise PermissionDenied(f"only {', '.join(VIEW_ROLES)} can send plan images to the AI", role=ctx.role)
    purpose = (purpose or "").strip()
    if not purpose:
        raise InvalidInput("say why the AI needs to see this (purpose), e.g. \"is this a GFI outlet?\"", field="purpose")
    if object_id is not None:
        sid, box = _object_box(conn, ctx, object_id)
        if sheet_id is not None and int(sheet_id) != sid:
            raise InvalidInput(f"object {object_id} is on sheet {sid}, not {sheet_id}", field="sheet_id")
        sheet_id = sid
    if sheet_id is None:
        raise InvalidInput("give the sheet_id (with a bbox) or an object_id to crop around", field="sheet_id")
    s = _sheet(conn, ctx, sheet_id)
    if whole_sheet:
        if not user_asked:
            raise PermissionDenied("a whole sheet is only sent when a person asks the AI to look at it; send a crop "
                                   "around the symbol instead", sheet_id=s["id"])
        if ctx.agent:
            raise PermissionDenied("an agent working on its own can't send a whole sheet; send a crop instead",
                                   agent=ctx.agent)
        kind = "full_sheet"
    else:
        if not _profile(conn, ctx.company_id)["crop_sending_enabled"]:
            raise NotAvailable("symbol-crop sending is turned off for this company, so nothing was sent. A person can "
                               "check this symbol, or the owner can turn crop sending on (est_ai_privacy)",
                               setting="crop_sending_enabled")
        if object_id is None:
            if bbox is None:
                raise InvalidInput("give the area to crop as bbox [x0, y0, x1, y1] in the sheet's units", field="bbox")
            box = _box(bbox, "bbox")
        kind = "crop"
    path = Path(s["image_path"]) if s["image_path"] else None
    if path is None or not path.is_file():
        raise NotAvailable("this sheet has no image yet (the plan engine makes them), so there's nothing to crop",
                           sheet_id=s["id"])
    try:
        from PIL import Image
    except ImportError:
        raise NotAvailable("the image library (Pillow) isn't installed") from None
    with Image.open(path) as img:
        img.load()
        iw, ih = img.size
        sw = float(s["width"]) if s["width"] else None
        sh = float(s["height"]) if s["height"] else None
        if kind == "crop":
            if not (sw and sh):
                raise NotAvailable("this sheet's size isn't known, so a crop can't be placed", sheet_id=s["id"])
            x0, y0 = max(box[0], 0.0), max(box[1], 0.0)
            x1, y1 = min(box[2], sw), min(box[3], sh)
            if x1 <= x0 or y1 <= y0:
                raise InvalidInput("that area is outside the sheet", field="bbox")
            share = (x1 - x0) * (y1 - y0) / (sw * sh)
            if share > CROP_MAX_SHARE:
                raise InvalidInput(f"that's {share:.0%} of the sheet; a crop can be at most {CROP_MAX_SHARE:.0%}. Crop "
                                   "closer to the symbol, or ask the user before sending the whole sheet",
                                   field="bbox", share=round(share, 3))
            px = (int(x0 / sw * iw), int(y0 / sh * ih), max(int(x1 / sw * iw), int(x0 / sw * iw) + 1),
                  max(int(y1 / sh * ih), int(y0 / sh * ih) + 1))
            out = img.crop(px)
            limit, box_out = CROP_MAX_PX, [round(v, 3) for v in (x0, y0, x1, y1)]
        else:
            out, limit, box_out = img.copy(), SHEET_MAX_PX, None
        if max(out.size) > limit:
            out.thumbnail((limit, limit))
        if out.mode not in ("RGB", "L"):
            out = out.convert("RGB")
        folder = _crops_folder(s["estimate_id"])
        with service.transaction(conn):
            notice = _notice_once(conn, ctx) if kind == "crop" else None
            log_id = int(conn.execute(
                "INSERT INTO ai_send_log (company_id, estimate_id, sheet_id, kind, purpose, bbox_json, width_px,"
                " height_px, provider, user_asked, actor, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ctx.company_id, s["estimate_id"], s["id"], kind, purpose[:500], json.dumps(box_out) if box_out else None,
                 out.size[0], out.size[1], provider, int(bool(user_asked)), ctx.actor, _now())).lastrowid)
            dest = folder / f"{log_id:06d}_{kind}_sheet{s['id']}.png"
            out.save(dest, "PNG")
            data = dest.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            conn.execute("UPDATE ai_send_log SET bytes = ?, sha256 = ?, file_path = ? WHERE id = ?",
                         (len(data), digest, str(dest), log_id))
    result = {"ok": True, "log_id": log_id, "kind": kind, "file_path": str(dest), "width_px": out.size[0],
              "height_px": out.size[1], "bytes": len(data), "sha256": digest, "sheet_id": s["id"],
              "sheet_no": s["sheet_no"], "bbox": box_out, "purpose": purpose}
    if notice:
        result["notice"] = notice
        result["show_notice"] = "Tell the user this once, in your own words: " + notice
    return result

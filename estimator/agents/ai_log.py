"""The AI Log: every LLM call the Estimator makes, what was sent and what came back.

David asked for this after a concrete auto-run failed with "No slab outline found
on this sheet" and nobody could tell whether the AI had run at all. The answer is
here: one row per call, with the full prompt, the plan images (references to the
ai_send_log rows crops.prepare made), the raw reply, the parsed result, tokens,
cost, duration and outcome - including failed calls, so a failure still shows
what was sent and what came back (or the error).

Who writes: the LLM takeoff (estimator/takeoff/llm_takeoff.py, vision) and the
agent task queue (estimator/agents/queue.py, text). Both record every attempt,
main provider and backup, success and failure, through record() - right after
the call, so the row is there even when the run that made it fails afterwards
(the connection is autocommit; see estimator/database/connection.py).

What never goes in: API keys or credentials of any kind. The prompts, the
images and the replies are the business's own plan data, and they are the
whole point - but a key is never part of a prompt, and record() takes only
what its callers pass it. The table has no key column at all (a test pins
that).

Who reads: the owner and estimators - the Agents screen's roles, where the
AI Log page lives (#/agents/ai-log, estimator/ui/web/verify.js). The image
files stay on disk; the API serves them by index, never the path.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from estimator.agents import providers
from estimator.errors import NotFound, PermissionDenied

# The Agents screen's roles (estimator/api/nav.py): the AI Log page hangs off it.
VIEW_ROLES = ("owner", "estimator")

# What one image reference carries. file_path stays server-side: the API serves
# the bytes (image_file), the browser never sees the path. sent_max_px is set
# when the image was downscaled before sending (the classify call's thumbnails).
IMAGE_KEYS = ("ai_send_log_id", "sheet_id", "sheet_no", "kind", "file_path",
              "width_px", "height_px", "sent_max_px")
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg")
MAX_ERROR = 500


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _can_view(ctx) -> None:
    if ctx.role not in VIEW_ROLES:
        raise PermissionDenied("only the owner or an estimator can see the AI Log", role=ctx.role)


def _image_ref(image: dict) -> dict:
    return {k: image.get(k) for k in IMAGE_KEYS if image.get(k) is not None}


def record(conn, ctx, *, provider: str, model: str, role: str, purpose: str,
           system_prompt: str, user_prompt: str, images=(), auto_run_id: int | None = None,
           task_id: int | None = None, estimate_id: int | None = None,
           response_text: str | None = None, parsed: dict | None = None,
           usage: dict | None = None, duration_ms: int | None = None,
           ok: bool = True, error: str | None = None) -> int:
    """One LLM call, as one row. Returns the row id, for set_parsed/set_error.

    usage is {"input": n, "output": n} from the provider; the cost comes from
    AI-Prowler's price table (providers.cost_micros), like agent_usage.
    A failed call (ok=False) has no response and no usage - but the prompt
    and the images it was sent with are still recorded.
    """
    usage = usage or {}
    micros = providers.cost_micros(model, usage) if usage else 0
    return int(conn.execute(
        "INSERT INTO ai_log (company_id, created_at, provider, model, role, purpose, auto_run_id,"
        " task_id, estimate_id, system_prompt, user_prompt, images_json, response_text, parsed_json,"
        " input_tokens, output_tokens, cost_micros, duration_ms, ok, error)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ctx.company_id, _now(), provider, model, role, purpose[:500], auto_run_id, task_id,
         estimate_id, system_prompt, user_prompt, json.dumps([_image_ref(i) for i in images]),
         response_text, json.dumps(parsed) if parsed is not None else None,
         int(usage.get("input", 0)), int(usage.get("output", 0)), micros,
         int(duration_ms) if duration_ms is not None else None, int(bool(ok)),
         (str(error)[:MAX_ERROR] if error else None))).lastrowid)


def set_parsed(conn, company_id: str, entry_id: int, parsed: dict) -> None:
    """The call's answer, once the caller has parsed it (the reading, the actions)."""
    conn.execute("UPDATE ai_log SET parsed_json = ? WHERE id = ? AND company_id = ?",
                 (json.dumps(parsed), int(entry_id), company_id))


def set_error(conn, company_id: str, entry_id: int, error: str) -> None:
    """The AI answered, but the answer couldn't be used (not JSON, wrong shape):
    the call counts as failed, with the raw reply still on the row to look at."""
    conn.execute("UPDATE ai_log SET ok = 0, error = ? WHERE id = ? AND company_id = ?",
                 (str(error)[:MAX_ERROR], int(entry_id), company_id))


def _summary(row: dict) -> dict:
    images = json.loads(row["images_json"] or "[]")
    return {"id": row["id"], "created_at": row["created_at"], "provider": row["provider"],
            "model": row["model"], "role": row["role"], "purpose": row["purpose"],
            "auto_run_id": row["auto_run_id"], "task_id": row["task_id"],
            "estimate_id": row["estimate_id"], "image_count": len(images),
            "input_tokens": row["input_tokens"], "output_tokens": row["output_tokens"],
            "cost_micros": row["cost_micros"], "cost_cents": round(row["cost_micros"] / 10_000, 2),
            "duration_ms": row["duration_ms"], "ok": bool(row["ok"]), "error": row["error"]}


def list_entries(conn, ctx, *, auto_run_id: int | None = None, task_id: int | None = None,
                 role: str | None = None, estimate_id: int | None = None,
                 limit: int = 50, offset: int = 0) -> dict:
    """Log entries, newest first, paginated. The list carries no prompts or
    replies - the detail call has those."""
    _can_view(ctx)
    limit = max(1, min(int(limit or 50), 200))
    offset = max(0, int(offset or 0))
    sql = " FROM ai_log WHERE company_id = ?"
    args: list = [ctx.company_id]
    for column, value in (("auto_run_id", auto_run_id), ("task_id", task_id),
                          ("role", role), ("estimate_id", estimate_id)):
        if value is not None and value != "":
            sql += f" AND {column} = ?"
            args.append(int(value) if column != "role" else str(value))
    total = conn.execute("SELECT COUNT(*)" + sql, args).fetchone()[0]
    rows = [dict(r) for r in conn.execute("SELECT *" + sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
                                          args + [limit, offset])]
    return {"ok": True, "entries": [_summary(r) for r in rows], "total": total,
            "limit": limit, "offset": offset}


def get_entry(conn, ctx, entry_id: int) -> dict:
    """One entry in full: the prompt, the images (with a URL for each), the raw
    reply and the parsed result. The image file paths stay server-side."""
    _can_view(ctx)
    row = conn.execute("SELECT * FROM ai_log WHERE id = ? AND company_id = ?",
                       (int(entry_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"AI Log entry {entry_id} not found", entry_id=entry_id)
    row = dict(row)
    out = _summary(row)
    images = []
    for i, img in enumerate(json.loads(row["images_json"] or "[]")):
        images.append({k: v for k, v in img.items() if k != "file_path"} |
                      {"image_url": f"/ai-log/{row['id']}/image/{i}"})
    out.update(system_prompt=row["system_prompt"], user_prompt=row["user_prompt"],
               images=images, response_text=row["response_text"],
               parsed=json.loads(row["parsed_json"]) if row["parsed_json"] else None)
    return {"ok": True, "entry": out}


def image_file(conn, ctx, entry_id: int, index: int) -> Path:
    """The prepared image file for one entry's image, checked: the entry is
    this company's, the index is one of its images, and the file is a picture
    inside the Estimator's data folder (same rule as a sheet's image)."""
    from estimator import config

    _can_view(ctx)
    row = conn.execute("SELECT * FROM ai_log WHERE id = ? AND company_id = ?",
                       (int(entry_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"AI Log entry {entry_id} not found", entry_id=entry_id)
    images = json.loads(dict(row)["images_json"] or "[]")
    if not 0 <= int(index) < len(images) or not images[int(index)].get("file_path"):
        raise NotFound(f"AI Log entry {entry_id} has no image {index}",
                       entry_id=entry_id, index=index)
    path = Path(images[int(index)]["file_path"])
    root = config.data_dir().resolve()
    if not path.is_file() or root not in path.resolve().parents \
            or path.suffix.lower() not in IMAGE_SUFFIXES:
        raise NotFound(f"AI Log entry {entry_id} has no image {index} to show",
                       entry_id=entry_id, index=index)
    return path

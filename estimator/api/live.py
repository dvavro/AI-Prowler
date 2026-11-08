"""Live updates for the web app.

Every change to an estimate - from the web app, from chat (MCP tools), from an
API-key agent or from the Director watcher - is written by the service layer to
the estimate_events audit table. The web app follows that table by id, so it
sees changes made in any process (the MCP server and the web app can run in
different processes) without each writer having to remember to publish.

Two ways to follow it, same data:
  GET /estimator-api/updates?since=<cursor>   polling (also the PWA fallback)
  GET /estimator-api/events                    server-sent events (spec "Technology")

Only pointers go out (which estimate, what kind of change, who, when); the page
re-reads what it shows through the normal API, so role rules (hidden margins)
apply exactly once, in one place. Company scoping applies to every query.
"""
from __future__ import annotations

import json

from estimator.context import RequestContext

MAX_BATCH = 200


def latest_cursor(conn, ctx: RequestContext) -> int:
    row = conn.execute("SELECT MAX(id) FROM estimate_events WHERE company_id = ?", (ctx.company_id,)).fetchone()
    return int(row[0] or 0)


def updates(conn, ctx: RequestContext, since: int | None, limit: int = MAX_BATCH) -> dict:
    """Changes after `since`. With since=None the caller is just starting: no backlog, only the cursor."""
    if since is None or since < 0:
        return {"ok": True, "cursor": latest_cursor(conn, ctx), "events": [], "more": False}
    limit = max(1, min(int(limit), MAX_BATCH))
    rows = conn.execute(
        "SELECT id, estimate_id, actor, on_behalf_of, action, at FROM estimate_events"
        " WHERE company_id = ? AND id > ? ORDER BY id LIMIT ?", (ctx.company_id, int(since), limit + 1)).fetchall()
    more = len(rows) > limit
    rows = rows[:limit]
    events = [{"id": r["id"], "estimate_id": r["estimate_id"], "actor": r["actor"],
               "on_behalf_of": r["on_behalf_of"], "action": r["action"], "at": r["at"]} for r in rows]
    cursor = events[-1]["id"] if events else int(since)
    return {"ok": True, "cursor": cursor, "events": events, "more": more}


def sse_message(event: dict) -> bytes:
    """One server-sent-events message. The id lets the browser resume with Last-Event-ID."""
    data = json.dumps(event, separators=(",", ":"), default=str)
    return f"id: {event['id']}\nevent: change\ndata: {data}\n\n".encode("utf-8")


def sse_comment(text: str = "ping") -> bytes:
    """Keep-alive line the browser ignores (stops proxies closing an idle stream)."""
    return f": {text}\n\n".encode("utf-8")


def parse_cursor(value) -> int | None:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None

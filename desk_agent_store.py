"""
desk_agent_store.py — the Jobs agent's own database (jobs-agent-spec.md; David 2026-10-31:
"4 = a separate agent database"), so the Jobs agent works whether or not Service Desk is on.

    ~/.ai-prowler/agent_database/agent.db
        desk_settings     the Jobs agent's settings (agent_jb_*), same layout as Service Desk's
        agent_queue, agent_proposals, agent_runs   the shared engine's tables (kind 'job')

The ticket and booking sections keep using the Service Desk database. The engine
(desk_agent.py) takes a database path, so the Jobs agent simply runs it against this file.
"""
from __future__ import annotations

from pathlib import Path

import desk_agent_settings as das
import desk_db
from db_access import get_connection

PATH_OVERRIDE = None          # tests: a temp path
_SCHEMA = """
CREATE TABLE IF NOT EXISTS desk_settings (
    key            TEXT PRIMARY KEY,
    value          TEXT NOT NULL,
    last_edited_at TEXT NOT NULL,
    last_edited_by TEXT NOT NULL
);
"""


def path() -> str:
    if PATH_OVERRIDE:
        return str(PATH_OVERRIDE)
    import os
    sandbox = os.environ.get("AIPROWLER_TEST_STATE_DIR")       # the test runner's throwaway folder
    if sandbox:
        return str(Path(sandbox) / "agent_database" / "agent.db")
    return str(Path.home() / ".ai-prowler" / "agent_database" / "agent.db")


def init(db: str | None = None) -> str:
    db = db or path()
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db)
    try:
        conn.executescript(_SCHEMA)
    finally:
        conn.close()
    import desk_agent
    desk_agent.ensure_schema(db)
    return db


def settings(db: str | None = None) -> dict:
    """The Jobs agent's settings (defaults filled in). Only agent_jb_* keys are meaningful here."""
    db = init(db)
    s = desk_db.get_settings(db)
    return {k: s[k] for k in das.JB_KEYS}


def set_setting(key: str, value, *, actor=None, edition: str = "solo", db: str | None = None) -> dict:
    if key not in das.JB_KEYS:
        raise desk_db.DeskError(f"{key} isn't a Jobs agent setting")
    desk_db.set_setting(init(db), key, value, actor=actor, edition=edition)
    return settings(db)


# The runner and the assistant's name are set once (Service Desk → 🤖 Agent) and used by every
# section, so they're copied here before each run. With no Service Desk the defaults apply
# (the agent then runs in a chat only).
SHARED_KEYS = ("agent_provider", "agent_name", "agent_label", "agent_hours", "agent_monthly_budget_usd", "agent_budget_alert_pct",
               "agent_batch_seconds", "agent_max_items", "agent_reply_signoff")


def sync_shared(tickets_db: str | None, db: str | None = None) -> dict:
    """Copy the shared runner / persona settings from the Service Desk database. Returns the
    agent database's full settings."""
    import json
    db = init(db)
    if tickets_db and Path(tickets_db).exists():
        try:
            src = desk_db.get_settings(tickets_db)
            from db_access import utcnow_iso
            conn = get_connection(db)
            try:
                for k in SHARED_KEYS + ("agent_shared_with",):
                    v = str(Path(tickets_db).resolve()) if k == "agent_shared_with" else src.get(k)
                    conn.execute("INSERT INTO desk_settings (key, value, last_edited_at, last_edited_by) VALUES "
                                 "(?, ?, ?, 'sync') ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                                 "last_edited_at = excluded.last_edited_at, last_edited_by = 'sync' "
                                 "WHERE desk_settings.value IS NOT excluded.value",     # only when it changed
                                 (k, json.dumps(v), utcnow_iso()))
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 — the copy is best effort; the last good copy stays
            pass
    return desk_db.get_settings(db)


def flow(edition: str | None = None, db: str | None = None, overrides: dict | None = None,
         which: str = "jobs") -> dict:
    """The Jobs diagram (or, which="route", the Route flow) for the saved settings, or for
    unsaved choices (overrides)."""
    s = settings(db)
    if overrides:
        s.update({k: v for k, v in overrides.items() if k in das.JB_KEYS})
    return das.route_flow(s, edition) if which == "route" else das.jobs_flow(s, edition)

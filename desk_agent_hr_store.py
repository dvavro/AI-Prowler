"""
desk_agent_hr_store.py — the HR agent's own database (hr-agent-spec.md; Vicki 2026-10-31:
"4 = have its own database inside the HR data folder"), so HR backups and HR permissions cover
everything the agent sees and suggests.

    <HR data folder>\\agent\\hr_agent.db
        desk_settings     the HR agent's settings (agent_hr_*), plus a copy of the shared runner
                          and persona settings (sync_shared)
        agent_queue, agent_proposals, agent_runs   the shared engine's tables (kind 'hr')

The HR data folder is the one ai_prowler_mcp's HR module uses (_HR_STATE_DIR: the test
sandbox AIPROWLER_TEST_STATE_DIR, else ~/.ai-prowler/hr). hr_root_fn can point elsewhere;
tests set PATH_OVERRIDE.
"""
from __future__ import annotations

import json
from pathlib import Path

import desk_agent_settings as das
import desk_db
from db_access import get_connection, utcnow_iso

PATH_OVERRIDE = None          # tests: a temp path
hr_root_fn = None             # ai_prowler_mcp: lambda: _hr_data_root()
FILE = "hr_agent.db"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS desk_settings (
    key            TEXT PRIMARY KEY,
    value          TEXT NOT NULL,
    last_edited_at TEXT NOT NULL,
    last_edited_by TEXT NOT NULL
);
"""
SHARED_KEYS = ("agent_provider", "agent_name", "agent_label", "agent_hours", "agent_monthly_budget_usd", "agent_budget_alert_pct",
               "agent_batch_seconds", "agent_max_items", "agent_reply_signoff")


def path() -> str:
    if PATH_OVERRIDE:
        return str(PATH_OVERRIDE)
    root = None
    if hr_root_fn:
        try:
            root = hr_root_fn()
        except Exception:  # noqa: BLE001
            root = None
    if not root:            # the same folder ai_prowler_mcp's _HR_STATE_DIR uses (hr_db.json lives there)
        import os
        root = (os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
                or str(Path.home() / ".ai-prowler" / "hr"))
    return str(Path(root) / "agent" / FILE)


def init(db: str | None = None) -> str:
    db = db or path()
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db)
    try:
        conn.executescript(_SCHEMA)
    finally:
        conn.close()
    try:
        import desk_agent
        desk_agent.ensure_schema(db)
    except Exception:  # noqa: BLE001 — the engine tables arrive with H1; settings work without them
        pass
    return db


def all_settings(db: str | None = None) -> dict:
    """Every setting in the HR agent database (its own + the shared copy), defaults filled in."""
    return desk_db.get_settings(init(db))


def settings(db: str | None = None) -> dict:
    """The HR agent's own settings (agent_hr_*), defaults filled in."""
    s = all_settings(db)
    return {k: s[k] for k in das.HR_KEYS}


def set_setting(key: str, value, *, actor=None, edition: str = "business", db: str | None = None) -> dict:
    if key not in das.HR_KEYS:
        raise desk_db.DeskError(f"{key} isn't an HR agent setting")
    desk_db.set_setting(init(db), key, value, actor=actor, edition=edition)
    return settings(db)


def set_settings(values: dict, *, actor=None, edition: str = "business", db: str | None = None) -> dict:
    """Several at once, all or nothing (finding F-6, 2026-11-03)."""
    bad = [k for k in values if k not in das.HR_KEYS]
    if bad:
        raise desk_db.DeskError(f"{bad[0]} isn't an HR agent setting")
    desk_db.set_settings(init(db), dict(values), actor=actor, edition=edition)
    return settings(db)


def sync_shared(tickets_db: str | None, db: str | None = None) -> dict:
    """Copy the shared runner / persona settings from the Service Desk database (same as the Jobs
    agent's store). Returns the HR agent database's full settings."""
    db = init(db)
    if tickets_db and Path(tickets_db).exists():
        try:
            src = desk_db.get_settings(tickets_db)
            conn = get_connection(db)
            try:
                vals = {**{k: src.get(k) for k in SHARED_KEYS},
                        "agent_shared_with": str(Path(tickets_db).resolve())}     # one budget for all agents
                for k in vals:      # only when it changed — never rewrite the HR folder for nothing (2026-10-31)
                    conn.execute("INSERT INTO desk_settings (key, value, last_edited_at, last_edited_by) VALUES "
                                 "(?, ?, ?, 'sync') ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                                 "last_edited_at = excluded.last_edited_at, last_edited_by = 'sync' "
                                 "WHERE desk_settings.value IS NOT excluded.value",
                                 (k, json.dumps(vals[k]), utcnow_iso()))
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 — best effort; the last good copy stays
            pass
    return desk_db.get_settings(db)


def flow(edition: str | None = "business", db: str | None = None, overrides: dict | None = None,
         shared: dict | None = None) -> dict:
    """The HR diagram for the saved settings, or for unsaved choices (overrides). `shared`
    (e.g. Service Desk's settings) supplies the runner when the copy here is older."""
    s = all_settings(db)
    if shared:
        s.update({k: shared[k] for k in SHARED_KEYS if k in shared})
    if overrides:
        s.update({k: v for k, v in overrides.items() if k in das.HR_KEYS})
    return das.hr_flow(s, edition)

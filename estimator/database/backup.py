"""Backup and restore for estimator.db.

Uses SQLite's online backup API, so a backup is consistent even while the web
app or agents are writing. Backups land in <data folder>/backups as
estimator_YYYYMMDD_HHMMSS.db. AI-Prowler's existing backup routine
(db_backup_ops.py) will call backup_database() so estimator.db is backed up
with the other databases (bridge added when the Estimator tab ships).
"""
from __future__ import annotations

import shutil
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from estimator import config

BACKUP_PREFIX = "estimator_"
DEFAULT_KEEP = 30


def backup_database(src: str | Path | None = None, dest_dir: str | Path | None = None) -> Path:
    src = Path(src) if src else config.db_path()
    dest_dir = Path(dest_dir) if dest_dir else config.backups_dir()
    if not src.exists():
        raise FileNotFoundError(f"database not found: {src}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    dest = dest_dir / f"{BACKUP_PREFIX}{stamp}.db"
    with closing(sqlite3.connect(str(src))) as s, closing(sqlite3.connect(str(dest))) as d:
        s.backup(d)
    if not integrity_ok(dest):
        dest.unlink(missing_ok=True)
        raise RuntimeError("backup failed integrity check")
    return dest


def list_backups(dest_dir: str | Path | None = None) -> list[Path]:
    dest_dir = Path(dest_dir) if dest_dir else config.backups_dir()
    if not dest_dir.exists():
        return []
    return sorted(dest_dir.glob(f"{BACKUP_PREFIX}*.db"))


def prune_backups(keep: int = DEFAULT_KEEP, dest_dir: str | Path | None = None) -> list[Path]:
    """Delete the oldest backups beyond `keep`. Returns the files removed."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    files = list_backups(dest_dir)
    removed = files[:-keep] if len(files) > keep else []
    for f in removed:
        f.unlink(missing_ok=True)
    return removed


def integrity_ok(path: str | Path) -> bool:
    try:
        with closing(sqlite3.connect(str(path))) as c:
            return c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    except sqlite3.DatabaseError:
        return False


def restore_database(backup: str | Path, target: str | Path | None = None) -> Path:
    """Restore a backup over the database. The current file is kept as <name>.before_restore."""
    backup, target = Path(backup), Path(target) if target else config.db_path()
    if not integrity_ok(backup):
        raise RuntimeError(f"backup is damaged and was not restored: {backup}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.copy2(target, target.with_suffix(target.suffix + ".before_restore"))
        for side in (target.with_name(target.name + "-wal"), target.with_name(target.name + "-shm")):
            side.unlink(missing_ok=True)
    with closing(sqlite3.connect(str(backup))) as s, closing(sqlite3.connect(str(target))) as d:
        s.backup(d)
    return target

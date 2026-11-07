"""SQLite connection helpers for estimator.db."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from estimator import config


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a connection with the Estimator's standard settings."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)  # autocommit; we manage transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")      # readers don't block the writer (Server mode)
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def open_database(path: str | Path | None = None) -> sqlite3.Connection:
    """Open estimator.db (default location from config), creating folders and applying migrations."""
    from estimator.database.migrations import migrate

    if path is None:
        config.ensure_data_dirs()
        path = config.db_path()
    conn = connect(path)
    migrate(conn)
    return conn

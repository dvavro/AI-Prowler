"""Paths and defaults for the Estimator.

Data folder resolution, in order:
  1. ESTIMATOR_DATA_DIR environment variable (explicit override)
  2. AIPROWLER_TEST_STATE_DIR/estimator (the test sandbox AI-Prowler already uses)
  3. %USERPROFILE%/AI-Prowler/Estimator (default, design spec "Runtime work directory")

Server mode can point ESTIMATOR_DATA_DIR at the server's data drive.
"""
from __future__ import annotations

import os
from pathlib import Path

DB_FILENAME = "estimator.db"

# Sub-folders created under the data folder (design spec "Runtime work directory").
DATA_SUBDIRS = (
    "projects",
    "price_books/imports",
    "price_books/exports",
    "modules_custom",
    "symbol_libraries/company",
    "symbol_libraries/firms",
    "templates",
    "cache",
    "logs",
    "backups",
)


def data_dir() -> Path:
    override = os.environ.get("ESTIMATOR_DATA_DIR", "").strip()
    if override:
        return Path(override)
    test_dir = os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    if test_dir:
        return Path(test_dir) / "estimator"
    return Path.home() / "AI-Prowler" / "Estimator"


def db_path() -> Path:
    return data_dir() / DB_FILENAME


def backups_dir() -> Path:
    return data_dir() / "backups"


def ensure_data_dirs(base: Path | None = None) -> Path:
    """Create the data folder and its sub-folders. Returns the data folder."""
    root = Path(base) if base else data_dir()
    for sub in DATA_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root

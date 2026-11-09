"""The standard symbol library, kept in estimator.db per company (spec: symbol_libraries level "standard").

Company and firm libraries (approved definitions and the learning workflow) come in Sprint 11; they'll sit beside this
one and win over it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_standard(conn, company_id: str) -> dict[str, int]:
    """Make sure the company has the current standard library. Returns {item type: definition id}.
    Runs inside the caller's transaction."""
    from estimator.plan_engine import symbol_library as lib

    row = conn.execute("SELECT id, version FROM symbol_libraries WHERE company_id = ? AND level = 'standard'",
                       (company_id,)).fetchone()
    if row is None:
        lib_id = conn.execute("INSERT INTO symbol_libraries (company_id, level, version, updated_at) VALUES (?, 'standard', ?, ?)",
                              (company_id, lib.VERSION, _now())).lastrowid
        have = {}
    else:
        lib_id = row["id"]
        have = {r["item_type"]: r["id"] for r in conn.execute(
            "SELECT id, item_type FROM symbol_definitions WHERE library_id = ?", (lib_id,))}
        if row["version"] >= lib.VERSION and len(have) >= len(lib.STANDARD):
            return have
    now = _now()
    for e in lib.STANDARD:
        values = (e["description"], e["trade"], json.dumps(e["aliases"]), json.dumps(e["block_words"]))
        if e["item_type"] in have:
            conn.execute("UPDATE symbol_definitions SET description = ?, trade = ?, ocr_aliases_json = ?,"
                         " block_names_json = ?, version = ? WHERE id = ?", (*values, lib.VERSION, have[e["item_type"]]))
        else:
            have[e["item_type"]] = conn.execute(
                "INSERT INTO symbol_definitions (company_id, library_id, item_type, description, trade, ocr_aliases_json,"
                " block_names_json, status, approved_by, version, created_at, confidence)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'approved', 'AI-Prowler standard library', ?, ?, '0.9')",
                (company_id, lib_id, e["item_type"], *values, lib.VERSION, now)).lastrowid
    conn.execute("UPDATE symbol_libraries SET version = ?, updated_at = ? WHERE id = ?", (lib.VERSION, now, lib_id))
    return have

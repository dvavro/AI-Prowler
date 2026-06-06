"""
scope_resolver.py — single source of truth for folder -> scope resolution.

Pure, dependency-free path/scope logic shared by:
  * ai_prowler_mcp.py  (server-mode write path: WHERE a file gets indexed)
  * rag_gui.py         (Update Index tab: WHAT scope a folder is shown as)

Keeping ONE implementation here means the scope the operator SEES in the GUI is
exactly the scope the engine ENFORCES at query time -- they cannot drift. Every
function is pure (no I/O, no globals, no os.path) so it unit-tests headlessly
with no Tk and no MCP-server import.

NOTE on normalization: this deliberately uses plain string ops (NOT os.path) so
behavior is identical on every OS and does NOT collapse '..' segments -- the
exact historical behavior of the engine's _normalize_path_for_match.
"""

from __future__ import annotations

__all__ = [
    "normalize_path_for_match",
    "resolve_collection_for_path",
    "upsert_scope_rule",
]


def normalize_path_for_match(p: str) -> str:
    """Lowercased, forward-slashed, trailing-slash-free path for prefix match."""
    s = (p or "").replace("\\", "/").strip()
    s = s.rstrip("/")
    return s.lower()


def resolve_collection_for_path(filepath, mapping, indexer_user=None):
    """Return the target collection name for `filepath`. PURE.

    Args:
        filepath:     the file/folder being classified.
        mapping:      {"rules": [{"prefix","collection"}...],
                       "default_collection": "..."}  (may be {} / None).
        indexer_user: resolved user dict (for the user:<id> fallback). May be
                      None -- then the ultimate fallback is the single default
                      'documents' collection (personal/Home behavior).

    Resolution order:
      1. Longest matching prefix rule wins.
      2. Else mapping['default_collection'] if set.
      3. Else indexer's own 'user:<id>' (if a user is known).
      4. Else 'documents' (personal/Home single-collection default).
    """
    fp = normalize_path_for_match(filepath)

    best_collection = None
    best_len = -1
    for rule in ((mapping or {}).get("rules") or []):
        if not isinstance(rule, dict):
            continue
        prefix = normalize_path_for_match(rule.get("prefix", ""))
        coll = str(rule.get("collection", "")).strip()
        if not prefix or not coll:
            continue
        # Segment-boundary match: exact, or prefix followed by '/', so
        # '.../Sales' never spuriously matches '.../SalesArchive'.
        if fp == prefix or fp.startswith(prefix + "/"):
            if len(prefix) > best_len:
                best_len = len(prefix)
                best_collection = coll

    if best_collection:
        return best_collection

    default_coll = str((mapping or {}).get("default_collection", "")).strip()
    if default_coll:
        return default_coll

    if indexer_user and indexer_user.get("id"):
        return f"user:{indexer_user['id']}"

    return "documents"


def upsert_scope_rule(rules, path, scope):
    """Add or update an EXACT-prefix rule mapping `path` -> `scope`.

    Returns a NEW rules list; the input list and its dicts are NOT mutated.
    An existing rule is matched on NORMALIZED prefix equality, so 'C:/Sales'
    and 'c:\\\\sales\\\\' are treated as the same rule (collection updated in
    place rather than a duplicate appended). One scope per folder by design.
    """
    target = normalize_path_for_match(path)
    scope = str(scope).strip()
    out = []
    replaced = False
    for r in (rules or []):
        if not isinstance(r, dict):
            out.append(r)
            continue
        if normalize_path_for_match(r.get("prefix", "")) == target:
            updated = dict(r)
            updated["collection"] = scope
            out.append(updated)
            replaced = True
        else:
            out.append(dict(r))
    if not replaced:
        out.append({"prefix": str(path), "collection": scope})
    return out

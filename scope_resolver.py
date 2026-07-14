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
    "resolve_collection_for_unattended_path",
    "known_user_ids",
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


def known_user_ids(users_data) -> set:
    """Extract the set of currently-valid user ids from a loaded
    users.json dict. Tolerant of missing/malformed structure — returns an
    empty set rather than raising, so a caller that fails to load
    users.json degrades to "treat every user:<id> as unknown" (safe: that
    just means resolve_collection_for_unattended_path skips more, never
    less) rather than crashing.

    NOTE: users.json's "users" key is itself keyed by the user's bearer
    TOKEN, not their id — the id is a field INSIDE each user's dict, not
    the dict key. (This mirrors ai_prowler_mcp.py's own _resolve_user,
    which does the identical users.get(token) lookup — see that function's
    docstring for why: "the users.json dict key IS the bearer token".)
    Also tolerates a plain list-of-dicts shape defensively.
    """
    try:
        users = (users_data or {}).get("users") or {}
        if isinstance(users, dict):
            return {u.get("id") for u in users.values()
                    if isinstance(u, dict) and u.get("id")}
        if isinstance(users, list):
            return {u.get("id") for u in users
                    if isinstance(u, dict) and u.get("id")}
    except Exception:
        pass
    return set()


def resolve_collection_for_unattended_path(filepath, mapping,
                                           known_ids=None):
    """Return the target collection for `filepath` for an UNATTENDED
    indexer — the file watchdog, or the Scheduled Task's standalone CLI
    invocation — that has no acting user/session to fall back to. PURE.

    This is deliberately a DIFFERENT function from resolve_collection_for_
    path, not a parameterized variant of it, because the two have
    genuinely different safety contracts:

      resolve_collection_for_path (live MCP call): ALWAYS has a real user
      to fall back to, so an unmatched file safely lands in THAT person's
      own private space — never nothing, never guessed into the open.

      resolve_collection_for_unattended_path (background process): has NO
      user to fall back to. There is no "own private space" to retreat
      to. So instead of guessing (e.g. a shared/company-wide default,
      which would risk silently exposing content that was never meant to
      be shared — see the 2026-07 Christina incident writeup), this
      returns None and the CALLER MUST treat that as "skip this file and
      log a clear warning for the operator to investigate" — never index
      it somewhere unverified.

    Two things must BOTH hold for a match:
      1. A prefix rule actually matches (longest-prefix wins, same
         matching as resolve_collection_for_path). No default_collection
         fallback — an operator must set an EXPLICIT rule for a directory
         to be auto-indexed unattended; there is no implicit default.
      2. If the matched collection is "user:<id>" AND known_ids is
         provided, <id> must actually be in known_ids — a rule pointing
         at a deleted/renamed user's stale id is exactly as unsafe as no
         rule at all (the private collection it names may no longer be
         monitored/owned by anyone real), so it's treated as no match
         rather than blindly writing into an orphaned private space.

    Args:
        filepath:  the file/folder being classified.
        mapping:   {"rules": [{"prefix","collection"}...]}. A
                   "default_collection" key, if present, is deliberately
                   IGNORED here — see rationale above.
        known_ids: set of currently-valid user ids (see known_user_ids()).
                   Pass None to skip the existence check entirely (NOT
                   recommended — only appropriate if the caller has
                   already validated the id some other way).

    Returns:
        The collection name string, or None — callers MUST skip + log
        on None, never substitute a guessed destination.
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
        if fp == prefix or fp.startswith(prefix + "/"):
            if len(prefix) > best_len:
                best_len = len(prefix)
                best_collection = coll

    if not best_collection:
        return None

    if known_ids is not None and best_collection.startswith("user:"):
        uid = best_collection[len("user:"):]
        if uid not in known_ids:
            return None

    return best_collection


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

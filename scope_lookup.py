"""
scope_lookup.py -- Phase 1 of the single-collection scope redesign
(see SCOPE_SIMPLIFICATION_SPEC.md at the repo root for the full design).

SERVER MODE ONLY. This module is never imported or called in personal/Home
installs -- personal mode has exactly one ChromaDB collection ("documents")
and no concept of scope at all, unchanged. Callers (command_update in
server context, ai_prowler_mcp.py's read tools) are responsible for
checking server mode is active before calling anything here; this module
does not re-detect mode itself, to keep it a pure, dependency-free unit.

Replaces scope_resolver.py's collection-routing responsibility with a
much smaller one: given a file path, return ONE scope STRING (not a
ChromaDB collection name -- there is only one physical collection now,
"documents", and scope is stored as chunk metadata instead). See
SCOPE_SIMPLIFICATION_SPEC.md section 3.7 for what this replaces and why.

Pure, dependency-free, no I/O, no globals -- unit-tests headlessly with no
Tk and no MCP-server import, same design constraint as scope_resolver.py.
"""

from __future__ import annotations

__all__ = [
    "normalize_path_for_match",
    "canon_scope_name",
    "resolve_scope_for_path",
    "allowed_scopes_for_user",
    "get_scope_map",
    "set_scope_for_path",
    "remove_scope_for_path",
    "get_scope_catalog",
    "add_scope_to_catalog",
    "remove_scope_from_catalog",
    "scope_picker_options",
    "scope_picker_selected",
    "format_scope_display",
    "MAX_CATALOG_SCOPES",
]

DEFAULT_SCOPE = "shared"
MAX_CATALOG_SCOPES = 15


def normalize_path_for_match(p: str) -> str:
    """Lowercased, forward-slashed, trailing-slash-free path for prefix
    matching. Identical semantics to scope_resolver.normalize_path_for_match
    -- duplicated (not imported) so this module has zero dependency on the
    module it is replacing; scope_resolver.py can be deleted later (spec
    Phase 7) without touching this file at all."""
    s = (p or "").replace("\\", "/").strip()
    s = s.rstrip("/")
    return s.lower()


def canon_scope_name(scope: str) -> str:
    """Canonicalize a scope string to its bare form for comparison.

    Strips a legacy 'scope:' or 'role:' prefix (users.json currently stores
    user-assigned scopes as e.g. 'scope:office' from the old N-collections
    design) so old-format and new plain-format ('office') values compare
    equal without requiring a synchronized rewrite of users.json in the
    same change. 'shared' and 'private:<id>' pass through unchanged --
    'private:' is deliberately NOT stripped, since the id after the colon
    is load-bearing (identifies WHICH user's private scope).
    """
    s = (scope or "").strip().lower()
    if s.startswith("private:"):
        return s
    if s.startswith("scope:") or s.startswith("role:"):
        return s.split(":", 1)[1]
    return s


def resolve_scope_for_path(filepath: str, scope_map: dict,
                            privates_root: str | None = None,
                            private_suffix: str = "-private") -> str:
    """Return the scope string for `filepath`. PURE. Never returns None --
    always resolves to a real scope, defaulting to DEFAULT_SCOPE ("shared")
    per direct product decision: an unscoped tracked file/folder is
    indexed and shared-visible immediately, never blocked or quarantined.
    (Note this only applies to paths the watchdog is ALREADY watching --
    see SCOPE_SIMPLIFICATION_SPEC.md section 3.5: a path that was never
    tracked at all is invisible to the watchdog and never reaches this
    function in the first place. That gap needs a different, GUI-surfaced
    fix -- section 6.3 -- not a default-scope fallback.)

    Resolution order:
      1. Private-folder convention: if privates_root is given and filepath
         falls under <privates_root>/<slug><private_suffix>/..., return
         "private:<slug>" regardless of scope_map -- private folder scope
         is derived by naming convention, never stored as an explicit rule,
         so there is nothing to keep in sync when a user is renamed.
      2. Longest matching prefix key in scope_map wins (segment-boundary
         match: exact, or prefix followed by '/', so '.../Sales' never
         spuriously matches '.../SalesArchive').
      3. DEFAULT_SCOPE ("shared").

    Args:
        filepath:      the file or directory being classified.
        scope_map:     {normalized-or-raw path prefix: scope string, ...}
                       -- keys are normalized internally, so callers may
                       pass raw users.json paths as-is.
        privates_root: root directory containing <slug>-private folders,
                       or None to skip private-folder detection entirely
                       (e.g. when resolving a path known not to be under
                       the privates tree).
        private_suffix: folder-name suffix identifying a private folder.
                       Matches the existing convention in rag_gui.py's
                       _admin_setup_private_folder / _make_user_id.
    """
    fp = normalize_path_for_match(filepath)

    if privates_root:
        root = normalize_path_for_match(privates_root)
        if root and (fp == root or fp.startswith(root + "/")):
            rest = fp[len(root):].lstrip("/")
            if rest:
                slug_folder = rest.split("/", 1)[0]
                if slug_folder.endswith(private_suffix):
                    slug = slug_folder[:-len(private_suffix)]
                    if slug:
                        return f"private:{slug}"

    best_scope = None
    best_len = -1
    for raw_prefix, scope in (scope_map or {}).items():
        prefix = normalize_path_for_match(raw_prefix)
        scope = (scope or "").strip()
        if not prefix or not scope:
            continue
        if fp == prefix or fp.startswith(prefix + "/"):
            if len(prefix) > best_len:
                best_len = len(prefix)
                best_scope = scope

    return best_scope if best_scope else DEFAULT_SCOPE


def allowed_scopes_for_user(user: "dict | None") -> set:
    """Return the set of scope strings `user` may SEARCH. PURE.

    allowed_scopes(user) = {"shared"}
                            union user's assigned scopes (canonicalized)
                            union {"private:<user id>"} if enabled

    Every user, with no exception (including owner/admin), always gets
    "shared" -- per direct product decision, this is unconditional, not
    role-dependent. Owner/admin do NOT automatically get every other
    user's private:<id> scope -- private stays private from everyone but
    its own user, including the owner (see SCOPE_SIMPLIFICATION_SPEC.md
    section 3.6 and section 5 for how owner/admin can still purge orphaned
    private-scope chunks without ever being able to search/read them).

    None user -> empty set (mirrors ai_prowler_mcp.py's existing
    _allowed_collections(None) == [] convention: no resolved token -> no
    access; the auth middleware 401s before this is ever reached).
    """
    if not user:
        return set()

    scopes = {DEFAULT_SCOPE}
    for s in (user.get("scopes") or []):
        canon = canon_scope_name(s)
        if canon:
            scopes.add(canon)

    if user.get("private_collection_enabled") and user.get("id"):
        scopes.add(f"private:{user['id']}")

    return scopes


# ── scope_map read/write (PURE -- callers own the actual users.json I/O) ──
# These operate on an already-loaded users_data-shaped dict, mirroring the
# existing _admin_sync_collection_map(self, data) pattern in rag_gui.py:
# callers (GUI's _admin_load_users()/save, the MCP user-loading path) are
# responsible for reading/writing users.json itself; this module stays
# pure and dependency-free. Used by the Index Docs tab's scope-assignment
# UI (spec section 3.3) -- the Update Index tab remains a read-only
# consumer of resolve_scope_for_path(), never a writer.

def get_scope_map(users_data: dict) -> dict:
    """Return the flat {tracked_path: scope} map from a loaded users.json
    dict. Empty dict if missing, malformed, or personal mode (no
    users.json at all). Read-only -- never mutates users_data. The
    returned dict is a shallow copy, safe for a caller to inspect without
    risk of accidentally mutating the loaded users_data in place."""
    sm = (users_data or {}).get("scope_map")
    return dict(sm) if isinstance(sm, dict) else {}


def set_scope_for_path(scope_map: dict, path: str, scope: str) -> dict:
    """Return a NEW scope_map with `path` -> `scope` upserted. PURE --
    does not mutate the input dict; the caller is responsible for storing
    the result back onto users_data["scope_map"] and saving.

    Path is normalized before storing, so the same folder typed with
    different slashes or case always overwrites the SAME entry rather
    than accumulating duplicates ('C:/Docs/Sales' and 'C:\\Docs\\Sales\\'
    upsert identically). One scope per path by design (section 3.2) --
    setting a path that already has an entry replaces it, never adds a
    second one.

    A blank path or blank scope is a no-op (returns an unchanged copy) --
    callers should validate user input before calling this, but this
    function itself never produces a broken entry.
    """
    key = normalize_path_for_match(path)
    scope = (scope or "").strip()
    out = dict(scope_map or {})
    if key and scope:
        out[key] = scope
    return out


def remove_scope_for_path(scope_map: dict, path: str) -> dict:
    """Return a NEW scope_map with `path`'s entry removed, if present.
    PURE. A no-op (returns an equal copy) if the path has no entry --
    removing something that was never there is not an error."""
    key = normalize_path_for_match(path)
    out = dict(scope_map or {})
    out.pop(key, None)
    return out


# ── scope_catalog: admin-managed list of pickable business scopes ──────
# Direct product decision (2026-07-16): the Admin tab lets the owner/admin
# maintain a company-wide catalog of up to MAX_CATALOG_SCOPES named
# scopes (e.g. office/sales/ops/field). This catalog populates EVERY
# scope-picker dropdown in the app -- Index Docs tab assignment, Update
# Index tab's editable scope column, and the Add/Edit User dialog's scope
# multi-select -- so an operator picks from a controlled list instead of
# free-typing a scope name that could typo-drift from what's actually in
# use elsewhere (e.g. "office" vs "Office" vs "offices" silently becoming
# three different scopes). "shared" is NOT stored in the catalog -- it is
# always implicitly available everywhere and cannot be removed, since it
# is the mandatory default (section 3.4). "private:<id>" scopes are never
# catalog entries either -- they are derived per-user from folder naming
# convention (section 3.3), never manually added.

def get_scope_catalog(users_data: dict) -> list:
    """Return the admin-managed list of available business scope names,
    for populating scope-picker dropdowns throughout the GUI. Does NOT
    include "shared" (always implicitly available, not admin-removable)
    or any "private:<id>" scope (derived per-user, never catalog-managed).
    Empty list if missing or malformed."""
    cat = (users_data or {}).get("scope_catalog")
    if isinstance(cat, list):
        return [str(s).strip() for s in cat if str(s).strip()]
    return []


def add_scope_to_catalog(catalog: list, name: str) -> tuple:
    """Return (new_catalog, ok, reason). PURE -- does not mutate the
    input list.

    Rejects (ok=False, catalog unchanged):
      - blank name
      - "shared" (implicit, never catalog-managed)
      - a name starting with "private:" (derived per-user, never
        catalog-managed)
      - a name already in the catalog, case-insensitively (canon_scope_name
        is used for the comparison, so "Office" and "scope:office" are
        treated as the same entry -- prevents near-duplicate scopes that
        would otherwise silently split search results)
      - adding would exceed MAX_CATALOG_SCOPES

    On success, the name is stored via canon_scope_name() so the catalog
    never accumulates legacy 'scope:'/'role:' prefixed entries even if a
    caller passes one in.
    """
    catalog = list(catalog or [])
    canon = canon_scope_name(name)
    if not canon:
        return (catalog, False, "scope name cannot be blank")
    if canon == DEFAULT_SCOPE:
        return (catalog, False, f'"{DEFAULT_SCOPE}" is always available and cannot be added to the catalog')
    if canon.startswith("private:"):
        return (catalog, False, "private scopes are per-user and cannot be added to the catalog")
    existing_canon = {canon_scope_name(s) for s in catalog}
    if canon in existing_canon:
        return (catalog, False, f'"{canon}" is already in the catalog')
    if len(catalog) >= MAX_CATALOG_SCOPES:
        return (catalog, False, f"catalog is full ({MAX_CATALOG_SCOPES} scopes max)")
    return (catalog + [canon], True, f'added "{canon}"')


def remove_scope_from_catalog(catalog: list, name: str) -> list:
    """Return a NEW catalog with `name` removed, if present
    (case-insensitive / prefix-tolerant via canon_scope_name). PURE. A
    no-op (returns an equal copy) if the name isn't in the catalog.

    Deliberately does NOT touch scope_map or any user's assigned scopes --
    removing a scope from the picker list does not retroactively unscope
    already-tracked files or unassign it from users who already have it;
    it only stops it from being offered for NEW assignments going
    forward. (Cleaning up existing usages, if desired, is a separate,
    explicit action -- not an automatic side effect of a catalog edit.)
    """
    canon = canon_scope_name(name)
    return [s for s in (catalog or []) if canon_scope_name(s) != canon]


# ── Scope-picker widget helpers (Add/Edit User dialog, Index Docs tab, ────
# Update Index tab -- SCOPE_SIMPLIFICATION_SPEC.md sections 3.3, 3.3a) ────
# Extracted as pure functions so the "which options to show, which are
# pre-selected" logic is testable independent of the Tk widget code that
# uses it -- none of the dialogs themselves are unit-tested in this
# codebase's convention (see tests/gui/test_admin_tab.py's manual QA
# checklist), but there's no reason the DATA behind them can't be.

def scope_picker_options(catalog: list, existing_scopes: list) -> list:
    """Return the ordered list of scope names to show in a scope-picker
    widget: the catalog, followed by any of `existing_scopes` that aren't
    already in it (compared via canon_scope_name). PURE.

    This matters when a scope a user (or file) was already assigned has
    since been removed from the catalog -- see remove_scope_from_catalog's
    docstring: removal never touches existing assignments, so that scope
    needs somewhere to keep showing up, or it would silently vanish from
    the widget (and, if the widget derives its Save value purely from
    what's checked, silently get unassigned on the next save even though
    nobody chose to remove it).
    """
    catalog = list(catalog or [])
    catalog_canon = {canon_scope_name(s) for s in catalog}
    existing_canon = [canon_scope_name(s) for s in (existing_scopes or [])]
    extra = [s for s in existing_canon if s and s not in catalog_canon]
    return catalog + extra


def scope_picker_selected(existing_scopes: list) -> set:
    """Return the canonicalized set of scopes that should be pre-selected
    in a scope-picker widget, given the current assignment. PURE. Compare
    widget option strings against this set using canon_scope_name() on
    each, since scope_picker_options() may return catalog entries in
    their stored casing while this set is always canonicalized."""
    return {canon_scope_name(s) for s in (existing_scopes or []) if canon_scope_name(s)}


# ── Update Index tab: staged (not-yet-committed) scope changes ────────────
# SCOPE_SIMPLIFICATION_SPEC.md section 3.3b: the Update Index tab's scope
# column is editable, but a change doesn't write to scope_map immediately
# -- it's staged in memory and only committed (written + triggers the
# normal purge/reindex, which now tags fresh chunks with the new scope)
# when the operator actually runs Update Selected / Update All. A staged
# changes dict has the exact same {normalized_path: scope} shape as
# scope_map itself, so no new data structure is needed -- only a tiny
# display-formatting helper, since staging/committing themselves are just
# set_scope_for_path() / get_scope_map() calls against a different dict.

def format_scope_display(resolved_scope_label: str, pending_scope: "str | None") -> str:
    """Return the text to show in a tracked-directory list row, given the
    currently-persisted scope's display label and an optional staged
    (not-yet-committed) replacement. PURE.

    A pending change always takes visual precedence over the persisted
    label -- the operator needs to see what WILL happen on the next
    Update, not what's currently true, once they've made an edit."""
    pending_scope = (pending_scope or "").strip()
    if pending_scope:
        return f"\u2192{pending_scope} (pending)"
    return resolved_scope_label


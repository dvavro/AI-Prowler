# AI-Prowler Server Mode — Scope Simplification Spec

Status: DRAFT — for review, not yet implemented
Author: David/Vicki + Claude (brainstorm session, 2026-07-16)
Scope of this doc: single-server deployment (ours). No migration section —
there is one server, we will rebuild its index from source files directly.

---

## 1. Motivation

Two real bugs were found and root-caused on 2026-07-16 in the current
N-collections design (see incident notes at the end of this doc):

1. **Index-time collection routing silently skipped files.** Two different
   resolver functions (`resolve_collection_for_path` for GUI display vs.
   `resolve_collection_for_unattended_path` for actual indexing) could
   disagree about whether a directory had a valid scope rule. The GUI showed
   a plausible-looking scope label with no real rule behind it, so an
   operator had no way to tell a folder was actually being silently skipped
   by Update All / the scheduled reindex.

2. **Content indexed into a collection that became invisible to search**,
   even after a full process restart, even for the owner role, with no
   permissions bug involved — root cause not fully determined, but directly
   enabled by the N-collections architecture (multiple physical ChromaDB
   collections, each independently created/opened, each a chance for a
   process to hold a stale or inconsistent handle).

Both failure classes are architectural, not one-off mistakes. The fix is to
remove the thing that made them possible: multiple physical collections and
a routing resolver that decides which one a file belongs to at index time.

### Guiding principle

**Indexing is not a data leak. Only search is.** A file can always be
indexed — the only thing that must be airtight is which chunks a given
user's search is allowed to return. That moves all of the security-critical
logic to one place (query time) instead of two (index-time routing AND
query-time filtering), and it means indexing never needs to "guess" or
"skip" — it always has a safe, well-defined default.

---

## 2. Current architecture (for contrast)

- N physical ChromaDB collections: `shared`, `scope-role-office`,
  `scope-role-sales`, `scope-role-ops`, `scope-role-field`, and one
  `scope-user-<id>` per user with a private collection enabled.
- `collection_map.rules` in `users.json`: a list of `{prefix, collection}`
  rules, longest-prefix-wins, resolved by `scope_resolver.py`.
- Two separate resolver functions with different fallback behavior
  (permissive display resolver vs. strict unattended-indexing resolver).
- `chroma_collection_name()` sanitizes logical names (`user:david-vavro`,
  `scope:sales`) into physical ChromaDB collection names
  (`scope-user-david-vavro`, `scope-role-sales`).
- `_allowed_collections(user)` in `ai_prowler_mcp.py` computes, per query,
  which of the N physical collections a user's search is allowed to open.

---

## 3. Proposed architecture

### 3.1 One physical collection

All chunks — every scope, every user, every file — live in a single
ChromaDB collection (working name: `documents`, matching the existing
personal-mode default so minimal code assumes multiple collections exist).

### 3.2 Scope is a metadata field, not a collection

Every chunk gets one extra metadata key: `scope`. Valid values:

- `"office"`, `"sales"`, `"ops"`, `"field"` — the four named business
  scopes (exact set is company-configurable; these four are ours today)
- `"shared"` — the default, always-visible-to-everyone scope
- `"private:<user_id>"` — one per user with a private collection enabled

**One scope per file.** Not per chunk, not per directory-with-overrides.
Every chunk a file produces inherits that single file's scope tag. This
removes the "a subfolder can override its parent's scope" feature from the
current design entirely — deliberate simplification, not an oversight. If a
business need for multi-scope files shows up later, it can be revisited;
it is not needed today.

### 3.3 Scope assignment lives on the tracked root, not per-file

A scope is set once, on a *tracked directory or individually-tracked file*,
in the **Index Docs tab** (not a separate Update Index tab step — this is
the exact drift that caused Bug 1). Every file under a tracked directory
inherits that root's scope recursively, including subfolders and files that
don't exist yet at assignment time.

**Direct product decision (2026-07-16): the Update Index tab keeps its
existing read-only display** — the `[R]`/`[W]` write-permission prefix and
the resolved scope label next to each tracked path, unchanged from today's
behavior. Only the *assignment* action (the "Set Scope for Selected
Folder" button and its dialog) moves to the Index Docs tab, at the point a
directory/file is added or re-indexed. Update Index becomes purely a status
view for scope, same as it already is for write-permission; Index Docs
becomes the only place scope is actually set.

**Escape hatch for misfiled documents:** an owner/admin can override the
scope of one specific already-tracked file directly (same mechanism the
current code already uses for individually-tracked files like
`COMPLETE_USER_GUIDE.md` — carried over, not new).

### 3.3a Admin-managed scope catalog (up to 15) — direct instruction, 2026-07-16

Free-typing a scope name anywhere it's assigned risks silent drift
("office" vs "Office" vs "offices" becoming three different scopes that
split search results without anyone noticing). Instead: the **Admin tab**
lets the owner/admin maintain a company-wide catalog of up to
`MAX_CATALOG_SCOPES` (15) named business scopes. This catalog populates
**every** scope-picker in the app as a dropdown instead of free text:

- Index Docs tab's scope-assignment control (§3.3)
- Update Index tab's editable scope column (§3.3b, below)
- The Add/Edit User dialog's scope selector — assigning scopes to a user
  becomes picking from the dropdown, not typing a comma-separated string

`"shared"` is never a catalog entry — it's implicitly available
everywhere and cannot be removed (§3.4's mandatory default). A
`"private:<id>"` scope is never a catalog entry either — it's derived
from folder-naming convention (§3.3), never manually added. Removing a
scope from the catalog does not retroactively touch any file's already-
assigned scope or any user's already-assigned scopes — it only stops
that name from being *offered* for new assignments going forward.

Implemented in `scope_lookup.py` (Phase 1/3 backend, already built and
tested): `get_scope_catalog()`, `add_scope_to_catalog()` (validates
blank/`shared`/`private:`-prefixed/duplicate/over-cap), and
`remove_scope_from_catalog()`.

### 3.3b Update Index tab becomes editable — purge + re-tag on scope change

Refines §3.3's original "Update Index tab stays read-only display"
decision: **the scope column in Update Index gets an actual dropdown
(populated from the §3.3a catalog), not just a label.** Changing it does
**not** write immediately — the change is staged in memory only.
Clicking **Update All** or **Index Selected** is what commits it, as
part of the same run that already re-indexes the file:

1. Persist the new `scope_map` entry (`scope_lookup.set_scope_for_path()`
   + save `users.json`).
2. **Purge** every existing chunk for that path (the existing
   reindex machinery already does this unconditionally on every
   reindex — "purge old chunks, rebuild fresh" — so no new purge logic
   is needed here).
3. **Re-chunk and re-embed** the file, tagging every new chunk's
   metadata with the *new* scope.

**This surfaces a real gap in the current build, not yet closed:** step 3
requires the indexing pipeline (`rag_preprocessor.py`'s chunking code)
to actually call `scope_lookup.resolve_scope_for_path()` and write the
result into each chunk's `scope` metadata field at index time.
Phase 1 only built the pure resolver; Phase 2 only wired *query-side*
scope filtering (`_allowed_scopes()`, additive, not yet live). Neither
phase wired the *write* side — chunks are not yet being tagged with a
`scope` field at all. This wiring is required before any of Phase 3's
purge-and-retag behavior can actually work, and is the next concrete
backend increment (ahead of, or alongside, the GUI widget work).

### 3.4 Default scope = `shared`

Per direct instruction from David: **any tracked file or directory with no
explicit scope assignment defaults to `shared` automatically.** No
unscoped/quarantine state, no manual classification queue, no skip-and-log.
This applies to:

- A brand-new tracked root added with no scope chosen.
- A subfolder or file that appears later under an already-tracked root and
  was never given an explicit override.

Tradeoff, stated plainly: since every user always gets `shared` (see 3.6),
an unscoped drop into (for example) a sales-only folder is briefly
company-wide-visible until someone tightens its scope. This is accepted as
correct behavior, not a bug — "indexed and visible to everyone" is a safe
default; "not indexed at all" is not. See §6 for how this stays visible
rather than silent.

### 3.5 Watchdog only sees tracked paths — this is a separate gap

Per direct instruction from David: the file-watchdog only auto-indexes
paths that are **already tracked**. A brand-new folder — even one sitting
inside an already-mapped network share — is invisible to the watchdog until
a person explicitly adds it as a tracked path via the Index Docs tab. There
is no way to make an entirely unknown folder self-index; someone has to
tell AI-Prowler it exists, exactly once.

This is a *different* gap from §3.4 and needs its own visibility, not a
default-scope fallback (there's no file to tag a scope onto if it was never
tracked in the first place). See §6.2.

### 3.6 Query-time enforcement — no role elevation, purely per-user scopes

```
allowed_scopes(user) =
    {"shared"}
    ∪ user.scopes                                  # e.g. {"sales","office"}
    ∪ ({"private:" + user.id} if user.private_collection_enabled else {})
```

Every server-mode read tool (`search_documents`, `multi_query_search`,
`search_within_directory`, `read_document`, etc.) builds one Chroma `where`
filter:

```python
collection.query(..., where={"scope": {"$in": list(allowed_scopes(user))}})
```

**Direct product decision (2026-07-16): there is no role-based elevation of
search visibility, at all, for anyone — including owner.** This was
initially drafted with an "owner/admin see every business scope
automatically" carve-out (mirroring the current code's
`read_all_role_scopes` capability), and was deliberately rejected as
unnecessary complexity. The rule is now uniform for every user without
exception: your search visibility is exactly `{"shared"} ∪ your own
assigned scopes ∪ your own private scope if enabled` — computed the exact
same way regardless of role. If the owner wants to search `office`, their
own user record needs `office` in their `scopes` list, same as anyone
else's. This is a data-assignment fact, not a privilege check.

**Role (owner / admin-with-`can_manage_users`) now means exactly one
thing: access to the Admin tab (user management — add/edit/suspend users,
regenerate tokens, assign scopes, purge orphaned chunks per §5).** It
grants no additional search visibility whatsoever. This removes an entire
class of "does the role-elevation logic agree with the scope-assignment
logic" bugs before it can exist, and it means `allowed_scopes_for_user()`
(scope_lookup.py, already implemented in Phase 1) is complete as written —
no `all_business_scopes` / role-elevation parameter needed.

Private stays private from everyone but its owner, including the owner's
own account viewing someone ELSE's private scope, by direct instruction —
unaffected by the above; this was never role-elevated to begin with. See
§5 for how owner/admin can still clean up orphaned private-scope chunks
without ever reading their content.

### 3.7 What gets deleted

This design removes, not just deprecates:

- `scope_resolver.py`'s prefix-matching / longest-prefix-wins logic
  (`resolve_collection_for_path`, `resolve_collection_for_unattended_path`,
  `known_user_ids`, `upsert_scope_rule`) — replaced by a single
  dict lookup: tracked-path → scope string.
- `chroma_collection_name()` — no logical→physical name sanitization
  needed when there is only one physical collection.
- `_enumerate_role_collections()` — nothing to enumerate.
- `collection_map.rules` / `default_collection` distinction in
  `users.json` — replaced by a flat `{tracked_path: scope}` map.
- `_admin_sync_collection_map()`'s private-folder auto-provisioning
  complexity — replaced by: private folder path is fixed by convention
  (`<privates_root>/<slug>-private`), scope is always `private:<user_id>`,
  nothing to keep in sync.
- The GUI's dual-resolver split between "what the list displays" and
  "what indexing actually uses" — one function, one source of truth,
  used by both.

Rough sense of scale: this is a meaningful net reduction in surface area,
not just a refactor — an entire class of "does the rule that matches what
the operator sees also match what the indexer enforces" bugs stops being
possible because there's only one thing to check.

---

## 4. Data model

### 4.1 `users.json` — replaces `collection_map`

```json
{
  "scope_map": {
    "C:/Users/AI-Prowler-Server/Documents/AI-Prowler-Server-field":  "field",
    "C:/Users/AI-Prowler-Server/Documents/AI-Prowler-Server-ops":    "ops",
    "C:/Users/AI-Prowler-Server/Documents/AI-Prowler-Server-projects":"office",
    "C:/Users/AI-Prowler-Server/Documents/AI-Prowler-Server-sales":  "sales",
    "C:/Users/AI-Prowler-Server/Documents/AI-Prowler-Server-shared": "shared",
    "C:/Users/AI-Prowler-Server/Documents/AI-Prowler/COMPLETE_USER_GUIDE.md": "shared"
  }
}
```

Lookup for a given file path: longest tracked-path prefix match against
`scope_map` keys; if nothing matches, scope = `"shared"` (§3.4). Private
folders (`<privates_root>/<slug>-private`) are not stored in `scope_map` at
all — their scope is derived by convention (`private:<user_id>`) directly
from the path, so there's nothing to drift out of sync when a user is
renamed or removed. (Removing a user's `private_collection_enabled` simply
stops that folder from being included in `allowed_scopes` for anyone —
the chunks stay put until purged, see §5.)

### 4.2 ChromaDB chunk metadata

Every chunk gains one field:

```json
{"scope": "sales", "...": "existing metadata unchanged"}
```

---

## 5. Purge capability for owner/admin (content-blind)

Per direct instruction: owner/admin must be able to clean up old/orphaned
directories — including private ones — by deleting the files and
reindexing to purge the corresponding chunks, **without ever being able to
read that scope's content.**

This works because purge is a different operation from search:

- **Search** = "return chunks whose content is semantically relevant" —
  requires the scope to be in `allowed_scopes(user)`.
- **Purge** = "remove chunks whose source file no longer exists on disk" —
  keyed purely by `document_id` / `filepath` metadata, never by content.
  It's a maintenance sweep, not a read.

Concretely: `reindex_directory()` / `command_update()`'s existing
delete-detection pass (compares tracked-file list against what's on disk,
purges ChromaDB entries for files that vanished) is **not scope-gated at
all** for owner/admin — it operates on path metadata only, matching what
the current code already does for the four named scopes today. This is
already-correct behavior; the spec is just making explicit that it must
keep working identically for `private:<id>` scopes, and that this does not
constitute a read of private content. A test should assert exactly this:
owner/admin can trigger a purge of a private folder's orphaned chunks and
the operation succeeds, while a parallel test asserts `search_documents`
with the same owner/admin credentials cannot retrieve that scope's content.

---

## 6. Debug logging

Two capped, structured, greppable log files — designed so a future
debugging session looks like a `grep`, not a forensic reconstruction from a
full reindex-all dump (which is what this session required).

### 6.1 Format and location

- `~/.ai-prowler/index_debug.log` — one line per file indexed/skipped/purged.
- `~/.ai-prowler/query_debug.log` — one line per search request.
- Pipe-delimited, fixed field order, ISO timestamps:

```
2026-07-16T15:20:03 | INDEX | path=.../Test sales docs.txt | scope=sales | chunks=1 | OK
2026-07-16T15:20:04 | INDEX | path=.../UserManualDOC/Part1.md | scope=shared (default, no rule) | chunks=8 | OK
2026-07-16T15:31:11 | PURGE | path=.../old-file.txt | scope=private:david-vavro | reason=file deleted from disk
2026-07-16T16:02:47 | QUERY | user=vicki-vavro | role=manager | allowed_scopes=[shared,sales,office] | query="proactive alerts" | results=4
```

- Both files live alongside `scheduler_log.txt` — an existing tracked
  location, so they're automatically searchable/greppable with no extra
  setup, and consistent with where an operator already looks for logs.

### 6.2 Ring-buffer cap at 1,000 lines

Append-then-trim: each write appends a line, then if the file exceeds 1,000
lines, truncate to the newest 1,000 (drop oldest). Checked on every write —
cheap enough at this data volume (dozens to low-thousands of chunks) that a
periodic/batched trim isn't needed. Two files instead of one so an indexing
spree doesn't push query history out of the window and vice versa.

### 6.3 Untracked-directory visibility (the §3.5 gap)

Since the watchdog cannot see a folder that was never tracked, the log
above is not enough — there's no index event to log. Proposal: a
lightweight periodic scan (piggybacking on the existing Update Index
"check for changes" pass) that, for each already-tracked *parent* of a
network-mapped root, lists immediate subdirectories on disk and diffs
against `scope_map` keys. Anything present on disk but not tracked gets
counted and surfaced in the GUI (Index Docs tab: "3 folders found on disk
but not yet tracked — click to add") rather than silently never indexed.
This is scoped to only the parts of the filesystem AI-Prowler already has
permission to read (existing tracked roots), so it adds no new filesystem
access surface.

---

## 7. Implementation phases

No migration section — single server, rebuilding the index from source
files directly is simpler than migrating N collections' worth of chunks.

1. **Schema + index-time tagging.** Add `scope` to chunk metadata at index
   time. Add `scope_map` to `users.json`, replacing `collection_map`.
   Implement the single lookup function (longest tracked-path prefix match,
   default `"shared"`).
2. **Query-time filter switch.** Replace `_allowed_collections()` +
   multi-collection query fan-out in `ai_prowler_mcp.py` with
   `allowed_scopes()` + a single `where={"scope": {"$in": ...}}` query
   against the one collection. Port existing role tests
   (`test_list_tracked_dirs_role_gate.py` etc.) to the new mechanism.
3. **GUI: Index Docs tab scope assignment.** Move scope-setting UI from
   Update Index tab into Index Docs tab, at the point a directory/file is
   added. Remove the old dual-resolver (`_resolve_scope_for_path` display
   vs. unattended-indexing enforcement) — one function, used everywhere.
4. **Purge capability.** Confirm/extend the existing delete-detection purge
   pass to work identically for `private:<id>` scopes for owner/admin,
   with the content-blind guarantee from §5 covered by tests.
5. **Debug logging.** Both capped log files, ring-buffer trim, wired into
   every index/purge/query code path.
6. **Untracked-directory visibility.** The periodic scan + GUI surface
   from §6.3.
7. **Delete old code.** Remove everything listed in §3.7 once the above
   phases are live and tested — not before, so there's a working fallback
   during development.
8. **Full re-index.** Wipe `rag_database`, re-run Update All from a clean
   single running instance, confirm every tracked path lands in the one
   collection with the correct `scope` tag, confirm search results for
   each of the six current users match their expected `allowed_scopes`.

---

## Appendix: incident notes (2026-07-16 debugging session)

- `AI-Prowler-Server-shared` (a tracked *directory*) had no real
  `collection_map` rule despite the GUI displaying "shared" as its scope —
  the display resolver's permissive fallback chain painted a label with no
  rule behind it. The 6 files under it (`UserManualDOC/`, an unrelated
  Unity Creature Evolution System manual — worth deciding if this belongs
  in the company knowledge base at all) failed to index.
- All 6 `<slug>-private` folders failed identically. `_admin_sync_collection_map()`
  only runs "automatically on every Add/Edit user save" per its own
  docstring — not after a database wipe/restore — so any staleness there
  goes unrepaired until someone re-saves each user record.
- `COMPLETE_USER_GUIDE.md` (an individually-tracked *file*, separate from
  the directory above) reported "45 chunks added" successfully into
  physical collection `shared`, survived a full process restart, and was
  still completely unreadable via `list_indexed_documents`/`read_document`/
  `search_documents` even for the owner role. Reviewed `_allowed_collections()`
  and `chroma_collection_name()` directly — both correct and unconditional
  for `shared`. Root cause not fully determined; points at a lower-level
  ChromaDB persistence/process-handle issue rather than application logic,
  which this redesign structurally prevents from recurring (one collection,
  opened one way, by every process, always).

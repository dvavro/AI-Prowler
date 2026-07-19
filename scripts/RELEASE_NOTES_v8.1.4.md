# AI-Prowler v8.1.4

## Business Server: single unified knowledge base

Business Server installs previously indexed each scope (per-user private,
per-role, shared) into a **separate physical ChromaDB collection**. As of
this release, every install — Personal and Business Server alike — uses
**one shared knowledge base**. Each indexed chunk carries a `scope` tag
(`sales`, `office`, `shared`, `private:<user>`, ...) instead of living in
its own database, and every search tool filters by that tag at query time.

This removes a whole class of "which collection is this actually in" bugs
that came from keeping N databases in sync, and makes the access-control
story much simpler to reason about: **scope decides visibility, not
infrastructure.**

**What changed as a direct result:**

- **No more owner search-visibility exception.** Every role — including
  the owner — now sees exactly `shared` + their own assigned scopes +
  their own private scope (if enabled). If the owner needs to see a
  scope, it's assigned to them the same way as anyone else. (The owner
  still has full filesystem access to any directory directly, and can
  still see any user's private *folder* on disk — what's gone is
  reading another user's already-indexed private *content* through
  search tools.)
- **Indexing is open to every role.** `index_path`, `update_tracked_directories`,
  `reindex_file`, and `reindex_directory` no longer require owner/manager,
  and field crew are no longer confined to indexing only their own personal
  directory. Indexing was never the actual confidentiality boundary —
  scope-based search access is, and that boundary is unchanged.
  `untrack_directory` and `list_tracked_directories` remain owner/manager-only.

## New: Scope catalog and pickers (Admin tab / Update Index tab)

- **🏷️ Manage Scopes** (Admin tab) — an admin-managed catalog of up to 15
  scope names, used everywhere a scope needs to be assigned. `shared` is
  always available and isn't listed; private scopes are per-user and
  controlled by the *Private collection enabled* checkbox, not the catalog.
- **Multi-select scope picker on Add/Edit User** — replaces the old
  comma-separated free-text field, picking straight from the catalog.
- **Editable scope column on the Update Index tab** — select a tracked
  folder, click **🔀 Change Scope for Selected**, pick a scope. The change
  is *staged*, shown as `→<scope> (pending)`, and only takes effect the
  next time you run **Update Selected** or **Update All**, which commits
  it and re-indexes in the same step.

## Other fixes in this release

- **Scheduler jobs (Morning Briefing, Weather Watch) now read the email
  recipient and owner name/location live from Settings** instead of a
  separate `scheduler_config.json` copy with its own hardcoded defaults —
  closes a gap where the two could silently drift apart from your actual
  SMTP configuration.
- **Learnings tab live auto-refresh** — a learning recorded during a live
  session now appears in the 🧠 Learnings tab without a manual refresh,
  while that tab is the one open. Never refreshes with Semantic search
  toggled on (that fires a real ChromaDB query, reserved for explicit
  action) or while a different tab is active.

## Upgrade notes

- Business Server installs: after updating, a **full reindex** (wipe +
  rebuild) is recommended so existing content gets tagged with the new
  `scope` metadata field. Until then, previously-indexed content still
  works but won't carry a scope tag (it defaults to `shared`).
- No action needed for Personal/Home installs.

---

**Full test coverage:** all four release-gate suites green — main test
suite, ai-prowler-subscription Worker, ai-prowler-telemetry Worker, and
the end-to-end server-isolation suite (spawns a real server subprocess
and verifies scope isolation over actual HTTP, including the new
single-collection query path).

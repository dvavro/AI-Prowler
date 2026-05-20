# Release Notes Draft — v6.0.2

This file is **reference copy** for filling in `release-drafts/welcome_ad.json` and
`release-drafts/notifications.json` after running `release 6.0.2`. The release
script always generates those JSONs with `EDIT ME` placeholders — paste from
here, adjust as needed, then commit to the admin repo.

Keep this file updated for each release: future-you will be glad you did.

---

## welcome_ad.json — copy into the admin repo

```json
{
  "version": "1.0",
  "headline": "AI-Prowler v6.0.2 — Mobile Write Zones",
  "bullets": [
    "Claude can now create, edit, and back up files in directories you've explicitly pre-authorized — from desktop or mobile.",
    "Nine new MCP code tools: create_file, write_file, str_replace_in_file, create_directory, list_directory, copy_to_backup, list_backups, restore_backup, reset_write_counter.",
    "New [W] / [W*] / [R] indicators in the Update Index tab — double-click to grant or revoke write access per directory.",
    "Double-lock security: read allowlist + writable allowlist + hard blocklist + 20-write circuit breaker per session.",
    "Windows files keep their CRLF line endings cleanly across edits — no more silent conversion to LF."
  ],
  "cta_label": "Download AI-Prowler v6.0.2",
  "cta_url": "https://github.com/dvavro/AI-Prowler/releases/tag/v6.0.2"
}
```

## notifications.json — copy into the admin repo

```json
{
  "version": "1.0",
  "notifications": [],
  "latest_version": "6.0.2",
  "update_url": "https://github.com/dvavro/AI-Prowler/releases/tag/v6.0.2",
  "update_notes": "AI-Prowler v6.0.2 introduces Mobile Write Zones — Claude can now modify files in directories you've pre-authorized through the GUI, from any client including mobile. Nine new code tools (create/edit/list/backup/restore) are gated by a double-lock security model with a hard blocklist and a per-session 20-write circuit breaker. The Update Index tab gains [W] / [W*] / [R] indicators with double-click toggles. Windows CRLF line endings are now preserved cleanly across edits. Full details: https://github.com/dvavro/AI-Prowler/releases/tag/v6.0.2"
}
```

---

## GitHub Release Body — copy into the GitHub release page

```markdown
# AI-Prowler v6.0.2 — Mobile Write Zones & Code Tools

## What's new

**Nine new MCP code tools.** Claude can now create, edit, list, back up, and
restore files in directories you've explicitly authorized. This makes AI-Prowler
work as a coding agent over your Cloudflare tunnel — usable from desktop, mobile
web, or any future Claude client.

- `create_file`, `write_file`, `str_replace_in_file` — file content authoring
- `create_directory`, `list_directory` — directory operations
- `copy_to_backup`, `list_backups`, `restore_backup` — explicit version control
- `reset_write_counter` — session circuit-breaker management

**New Update Index tab UI.** The tracked-paths listbox now shows a write-permission
prefix on every row:

- `[W]` — writable (Claude can modify files here)
- `[W*]` — partially writable (a sub-directory is granted)
- `[R]` — read-only (search only)

Double-click a row to toggle. Granting opens a confirmation dialog explaining the
implications. `[W*]` rows offer a one-click widening flow that absorbs narrower
sub-grants into a single grant at the row's level.

**Double-lock security model.** Write access is intentionally separate from
indexing access. Four independent layers must all permit an operation:

1. **Read allowlist** (`~/.rag_auto_update_dirs.json`) — the file's parent must be tracked
2. **Writable allowlist** (`~/.rag_writable_dirs.json`) — separate file, opt-in only via the GUI or hand-edit
3. **Hard blocklist** — Windows, Program Files (except AI-Prowler's own state), `.git`, `.ssh`, `.aws`, the job tracker `.xlsx` — always wins
4. **Per-session circuit breaker** — 20 writes max, then `reset_write_counter` required

The trust root for "may Claude write here" stays at the keyboard, not in the chat
channel. Mobile clients can use write tools, but cannot grant new permissions.

**Backup-as-audit-trail.** Every modification leaves a `.bak<N>` next to the
file. Backups are never auto-deleted. The complete edit history of any file is
reconstructible from the filesystem alone.

## Bug fixes

- **Line endings preserved on Windows files.** Previously `str_replace_in_file`
  and `write_file` silently converted CRLF to LF on every edit. Now both detect
  the existing convention from the file on disk and write back matching bytes.
  `create_file` now translates pure-LF content to the platform native ending
  on Windows (CRLF) so new files match the rest of the codebase.
- **`_watch_http` thread crash.** The HTTP server status watcher now decodes
  subprocess stdout as UTF-8 (was platform-default `cp1252` on Windows). Emoji
  status markers and non-ASCII log content no longer crash the watcher thread,
  which means the GUI status indicator stays accurate across long sessions.

## Test coverage

294 tests pass — up from 287. Seven new regression tests pin the line-ending
preservation behavior across `create_file`, `write_file`, and `str_replace_in_file`
on both CRLF and LF files.

## Upgrade notes

Existing entries in `~/.rag_writable_dirs.json` (from prior popup-driven
approvals) continue to work. The new GUI shows them as `[W]` if they exactly
match a tracked path, or `[W*]` if they're a sub-directory of one. Double-clicking
a `[W*]` row offers to widen the grant up to the tracked path.

No data migration required.

## Roadmap — v6.0.3 candidates

- Remove the legacy approval-popup path entirely (the GUI checkbox is now the
  blessed grant mechanism)
- Process-lifecycle hardening — clean MCP subprocess termination on GUI exit so
  port orphans don't recur after abrupt PowerShell kills
- Optional per-token write quotas for sharing the MCP server with beta testers
```

---

## Beta-tester email — copy into your email tool

```
Subject: AI-Prowler v6.0.2 is out — Mobile Write Zones

Hi {first_name},

v6.0.2 just shipped. The headline feature is Mobile Write Zones: Claude can now
create, edit, and back up files in directories you've pre-authorized through
the AI-Prowler desktop GUI. This works from any Claude client — including mobile
web, which means you can ask Claude to patch a config file or check a log
from your phone while you're away from the desk.

Nine new MCP tools (create_file, write_file, str_replace_in_file, and friends),
all gated by a double-lock security model: a read allowlist for indexing PLUS
a separate writable allowlist for modifications, with a hard blocklist that
always wins and a 20-write circuit breaker per session.

HOW TO UPGRADE (important): For this release, please upgrade by downloading and
running the full installer:

   https://github.com/dvavro/AI-Prowler/releases/tag/v6.0.2

Download AI-Prowler_INSTALL.exe from that page and run it. If your AI-Prowler is
running, close it first (File → Exit), then run the installer.

A note on the in-app updater: starting with this version, AI-Prowler has a new
one-click "Download Update" button that applies updates in place — no installer,
no uninstall. That smooth path becomes available for the NEXT update (6.0.2 →
whatever comes next). For getting ONTO 6.0.2 from an older build, the installer
above is the reliable route, so please use it this one time. After you're on
6.0.2, future updates will just be a button click.

After install, open the Update Index tab. You'll see new [W] / [W*] / [R]
indicators on every tracked directory. Double-click any row to toggle write
access. Existing approvals from prior versions are automatically detected and
displayed.

Full feature details and the new MCP tool reference are in Section 4 and
Section 6 of the User Guide (Help → Open User Guide).

As always, feedback welcome. The first thing I'd love to know: did the [W*] →
[W] "widen" flow make sense the first time you saw it? It's a new UI pattern
and I'm not sure I got the wording right.

— David
```

import subprocess
from pathlib import Path

REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")

COMMIT_MSG = """Release v8.1.4

- Business Server: single unified knowledge base instead of one ChromaDB
  collection per scope. Every chunk now carries a "scope" metadata tag;
  every search tool filters by it at query time instead of by which
  physical collection a chunk lived in.

- No more owner search-visibility exception: every role, including
  owner, now sees exactly shared + their own assigned scopes + their
  own private scope (no exceptions).

- Indexing (index_path, update_tracked_directories, reindex_file,
  reindex_directory) is now open to every role, not just owner/manager
  or field crew confined to their own directory. Indexing was never the
  real confidentiality boundary -- scope-based search access is.

- New: Admin-managed scope catalog (Manage Scopes) and multi-select
  scope picker on Add/Edit User, replacing free-typed comma-separated
  scopes.

- New: editable scope column on the Update Index tab (Change Scope for
  Selected) -- stages a change, applies on the next Update.

- Fix: Scheduler jobs (Morning Briefing, Weather Watch) now read the
  email recipient and owner name/location live from Settings instead of
  a separate scheduler_config.json copy with its own defaults.

- New: Learnings tab live auto-refresh while the tab is open (mtime-
  gated, skipped while Semantic search is on).
"""

def run(cmd, **kw):
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, shell=True, **kw)
    return r.stdout.decode("utf-8", errors="replace"), r.stderr.decode("utf-8", errors="replace"), r.returncode

msg_file = REPO / "scripts" / "_commit_msg.txt"
msg_file.write_text(COMMIT_MSG, encoding="utf-8")

out, err, rc = run(f'git commit -F "{msg_file}"')
print("COMMIT rc=", rc)
print("OUT:", out)
print("ERR:", err)

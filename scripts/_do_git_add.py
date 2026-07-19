import subprocess
from pathlib import Path

REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")

FILES_TO_STAGE = [
    # Modified — this session's Phase 7 scope redesign + David's scheduler fix
    "AI-Prowler-Setup.iss",
    "COMPLETE_USER_GUIDE.md",
    "ai_prowler_mcp.py",
    "file_watchdog.py",
    "rag_gui.py",
    "rag_preprocessor.py",
    "scheduler_engine.py",
    "scheduler_jobs.py",
    "scripts/release.py",
    "tests/analysis/test_scheduler.py",
    "tests/e2e/test_server_e2e.py",
    "tests/gui/test_admin_tab.py",
    "tests/gui/test_proactive_alerts_autosave.py",
    "tests/gui/test_server_status_tab.py",
    "tests/mcp/test_database_stats_scope.py",
    "tests/mcp/test_edition_activation.py",
    "tests/mcp/test_how_to_use_ai_prowler.py",
    "tests/mcp/test_index_path_private_only.py",
    "tests/mcp/test_kb_overview_tracked_dirs_scope.py",
    "tests/mcp/test_owner_dir_isolation.py",
    "tests/mcp/test_reindex_collection_aware.py",
    "tests/mcp/test_update_tracked_dirs_role_gate.py",
    "tests/test_security_roles.py",
    "tests/unit/test_build_collection_resolver.py",
    "tests/unit/test_command_update_scope_awareness.py",
    "tests/unit/test_file_watchdog.py",
    # New files — product + tests
    "SCOPE_SIMPLIFICATION_SPEC.md",
    "scope_lookup.py",
    "tests/gui/test_admin_scope_catalog.py",
    "tests/gui/test_job_tracker_guide.py",
    "tests/gui/test_learnings_auto_refresh.py",
    "tests/gui/test_update_index_scope_column.py",
    "tests/mcp/test_allowed_scopes.py",
    "tests/test_scope_lookup.py",
    "tests/unit/test_build_scope_resolver.py",
    # Release artifacts from this run
    "VERSION",
    "update_manifest.json",
    "release-drafts/notifications.json",
    "release-drafts/welcome_ad.json",
]

def run(cmd):
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, shell=True)
    return r.stdout.decode("utf-8", errors="replace"), r.stderr.decode("utf-8", errors="replace"), r.returncode

lines = []
out, err, rc = run("git add -- " + " ".join(f'"{f}"' for f in FILES_TO_STAGE))
lines.append(f"git add rc={rc}\nerr={err}")

out, err, rc = run("git status --short")
lines.append(f"\ngit status after add:\n{out}")

(REPO / "scripts" / "_diff_output.txt").write_text("\n".join(lines), encoding="utf-8")
print("done")

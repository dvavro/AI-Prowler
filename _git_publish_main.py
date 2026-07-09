import subprocess
import sys

def run(cmd, cwd, timeout=60):
    print(f"$ {' '.join(cmd)}  (in {cwd})")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    print(f"  exit={result.returncode}")
    if result.stdout.strip():
        print(f"  stdout: {result.stdout.strip()}")
    if result.stderr.strip():
        print(f"  stderr: {result.stderr.strip()}")
    print()
    return result

main_dir = r'C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler'

print("=" * 70)
print("Fetch first to check for remote divergence before committing")
print("=" * 70)
run(['git', 'fetch', 'origin'], main_dir, timeout=60)
diverge = run(['git', 'log', '--oneline', '-5', 'HEAD..origin/main'], main_dir)

print("=" * 70)
print("STEP 1 — AI-Prowler (main program): add + commit")
print("=" * 70)
run(['git', 'add', '-A'], main_dir)
r = run(['git', 'commit', '-m',
        'Add create_analysis_task tool, raise custom-task cap to 25, live-refresh GUI panel, fix tool counts\n\n'
        '- ai_prowler_mcp.py: new create_analysis_task MCP tool (Tier A suppressed, personal-mode only), '
        'day-granularity/pull-based scheduling documented honestly in its docstring; fixed missing tool name '
        'in AGENTIC ANALYSIS WORKFLOW server-mode caveat; corrected tool counts to 81 total / 80 personal / 54 server\n'
        '- custom_tasks_manager.py: MAX_CUSTOM_TASKS raised 10 -> 25; cap enforcement centralized inside '
        'create_task() itself (calls load_custom_tasks() internally) so no caller can bypass it\n'
        '- rag_gui.py: My Custom Analyses panel now live-polls custom_analysis_tasks.json (mtime-based) so tasks '
        'created externally (e.g. by create_analysis_task) appear without a manual tab switch; removed the now-'
        'redundant duplicate cap check; fixed hardcoded "/ 10" count display to read MAX_CUSTOM_TASKS dynamically; '
        'exposed _custom_list_frame/_custom_count_var/_poll_custom_tasks_file for testability; About dialog tool '
        'counts corrected to 81\n'
        '- COMPLETE_USER_GUIDE.md: tool counts and Agentic Analysis Tools section updated for the new tool\n'
        '- New tests: test_create_analysis_task.py, test_custom_tasks_manager_cap.py, '
        'test_quick_links_custom_tasks_live_refresh.py; test_how_to_use_ai_prowler.py updated for the new count\n'
        '- Output/AI-Prowler_INSTALL.exe: untracked (already gitignored, was tracked before that rule existed)'],
       main_dir)
if r.returncode != 0:
    print("COMMIT FAILED for AI-Prowler — stopping here.")
    sys.exit(1)

print("=" * 70)
print("STEP 2 — Push")
print("=" * 70)
r = run(['git', 'push', 'origin', 'main'], main_dir, timeout=120)
if r.returncode != 0:
    print("PUSH FAILED for AI-Prowler — stopping here (commit is safe locally).")
    sys.exit(1)

print("=" * 70)
print("STEP 3 — Move v8.0.0 tag to the new HEAD and push it")
print("=" * 70)
run(['git', 'tag', '-f', 'v8.0.0'], main_dir)
r = run(['git', 'push', 'origin', 'v8.0.0', '--force'], main_dir, timeout=60)
if r.returncode != 0:
    print("TAG PUSH FAILED.")
    sys.exit(1)

print("ALL STEPS COMPLETED SUCCESSFULLY.")

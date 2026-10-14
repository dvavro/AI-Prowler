"""2026-10-12 — finish David's Grok (xAI) queue runner in task_queue_automation.py:

  1. tool cap: xAI accepts at most 128 tools per request; a broad allowed_tools
     ("mcp__*") used to send every AI-Prowler tool (well over 128) and the
     first call failed. Now ranked + capped at GROK_MAX_TOOLS (120): queue
     essentials, then knowledge base / learnings / analysis / email / SMS
     groups, then READ-ONLY Jobs tools; file-writing / script / restore tools
     are never offered.
  2. no {"type": "web_search"} on /v1/chat/completions — xAI documents its
     built-in tools on the Responses API only; the Grok prompt now says to use
     general knowledge where the Claude prompt says WebSearch/WebFetch.
  3. default model grok-4.3 (grok-4-1-fast isn't one of xAI's documented
     redirects after the May 15, 2026 retirement).
Also removes the unused api_agent_runner.py (superseded by David's in-module
runner; Muse has no API key for this). Checks every anchor. ASCII output."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
F = ROOT / "task_queue_automation.py"
raw = F.read_bytes().decode("utf-8")
NL = "\r\n" if "\r\n" in raw else "\n"
s = raw.replace("\r\n", "\n")


def rep(old, new):
    global s
    assert s.count(old) == 1, f"anchor not found once: {old[:70]!r} ({s.count(old)})"
    s = s.replace(old, new)


rep('GROK_MODEL = "grok-4-1-fast"   # override per-install via task_automation_config.json "grok_model"',
    '# 2026-10-12: grok-4.3 — xAI\'s recommended model for agentic tool calling; the\n'
    '# old grok-4-1-fast slug is not one of the documented post-May-15-2026 redirects.\n'
    'GROK_MODEL = "grok-4.3"   # override per-install via task_automation_config.json "grok_model"')

rep('GROK_QUEUE_DEADLINE = 30 * 60    # seconds for a whole queue run',
    'GROK_QUEUE_DEADLINE = 30 * 60    # seconds for a whole queue run\n'
    'GROK_MAX_TOOLS = 120             # xAI accepts at most 128 tools per request\n'
    '\n'
    '# Which AI-Prowler tools a Grok run is offered when allowed_tools is broad\n'
    '# ("mcp__*"): the queue essentials first, then whole feature groups, then\n'
    '# READ-ONLY Jobs tools — capped at GROK_MAX_TOOLS. Never anything that writes\n'
    '# files, runs scripts or restores data (an unattended run doesn\'t need it).\n'
    'GROK_ESSENTIAL_TOOLS = (\n'
    '    "get_pending_analysis_tasks", "get_all_queued_tasks", "complete_analysis_task",\n'
    '    "save_analysis_report", "how_to_use_ai_prowler", "check_ai_prowler_status",\n'
    '    "search_documents", "multi_query_search", "read_document", "expand_search_result",\n'
    '    "get_knowledge_base_overview", "list_indexed_documents", "search_within_directory",\n'
    '    "search_learnings", "record_learning", "list_learnings", "get_learning",\n'
    '    "get_learning_stats", "get_learnings_report",\n'
    '    "send_email", "send_sms", "send_whatsapp", "get_weather",\n'
    ')\n'
    'GROK_GROUP_ORDER = ("core_kb", "self_learning", "agentic_analysis", "status_system",\n'
    '                    "email", "sms_whatsapp")\n'
    'GROK_READ_ONLY_PREFIXES = ("get_", "read_", "list_", "find_", "search_", "check_",\n'
    '                           "export_", "build_maps_url", "geocode_")\n'
    'GROK_NEVER_OFFER = frozenset({\n'
    '    "create_file", "write_file", "edit_file", "str_replace_in_file", "line_replace_in_file",\n'
    '    "delete_file", "run_script", "run_script_start", "untrack_directory", "reindex_all",\n'
    '    "restore_backup", "restore_job_database", "grant_access", "grant_write_access",\n'
    '    "revoke_access", "revoke_write_access",\n'
    '})')

rep('''        "to WebSearch or WebFetch for anything current or specific that "
        "requires looking up",
        "to web_search for anything current or specific that requires looking up")''',
    '''        "to WebSearch or WebFetch for anything current or specific that "
        "requires looking up",
        # 2026-10-12: no web search in a Grok run — xAI's built-in web_search
        # is a Responses-API tool, and this runner uses Chat Completions.
        "to your own general knowledge for anything current or specific (there "
        "is no web search in this run — say so in the report where it matters)")''')

rep('''    web = bool(wanted & {"WebSearch", "WebFetch"})
    selected = []
    for t in mcp_tools or []:
        name = t.get("name", "")
        if broad or name in specific:
            selected.append(_mcp_tool_to_xai_function(t))
    return selected, web''',
    '''    web = bool(wanted & {"WebSearch", "WebFetch"})
    by_name = {t.get("name", ""): t for t in (mcp_tools or []) if t.get("name")}
    if broad:
        # 2026-10-12: rank and cap (xAI's 128-tool limit) — see GROK_ESSENTIAL_TOOLS.
        avail = {n for n in by_name if n not in GROK_NEVER_OFFER}
        order = [n for n in GROK_ESSENTIAL_TOOLS if n in avail]
        try:
            import mcp_tool_catalog as _cat
            for _g in GROK_GROUP_ORDER:
                order += sorted(n for n in _cat.tools_in_category(_g) if n in avail and n not in order)
            order += sorted(n for n in _cat.tools_in_category("job_tracker")
                            if n in avail and n not in order and n.startswith(GROK_READ_ONLY_PREFIXES))
        except Exception:
            order += sorted(n for n in avail if n not in order and n.startswith(GROK_READ_ONLY_PREFIXES))
        names = order[:GROK_MAX_TOOLS]
    else:
        names = [n for n in by_name if n in specific][:GROK_MAX_TOOLS]
    return [_mcp_tool_to_xai_function(by_name[n]) for n in names], web''')

rep('''        if web:
            # xAI server-side web search (metered by xAI); the prompt's
            # WebSearch/WebFetch references map onto this one tool.
            xai_tools.append({"type": "web_search"})
''',
    '''        # 2026-10-12: no {"type": "web_search"} here — xAI's built-in tools are
        # documented for the Responses API, not /v1/chat/completions (a 400
        # would fail every run). The Grok prompt says to use general knowledge.
''')

compile(s, str(F), "exec")
F.write_bytes(s.replace("\n", NL).encode("utf-8"))
print("task_queue_automation.py: tool cap, no web_search on chat completions, grok-4.3")

old = ROOT / "api_agent_runner.py"
if old.exists():
    old.unlink()
    print("removed unused api_agent_runner.py")

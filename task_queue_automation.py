"""
task_queue_automation.py — Autonomous execution of AI-Prowler's analysis
task queue via Claude Code headless CLI, on a Windows Scheduled Task.

Design reference: C:\\Users\\david\\AI-Prowler-ADMIN\\
                   autonomous-task-execution-architecture-spec.md

Scope (Phases 1-6 of that spec):
  - Wrapper script generation (Phase 1)
  - Assumes .claude/skills/ai-prowler-tasks/SKILL.md exists (Phase 2)
  - Permission scoping is baked into the generated claude -p command (Phase 3)
  - Windows Scheduled Task install/uninstall (Phase 4)
  - Audit logging is a Claude Code hook (Phase 5, see .claude/settings.json),
    not this module — this module only reads the resulting log for display.
  - Notification is also a hook (Phase 6) — same note.

Deliberately NOT in scope here: subagent parallelism, OpenClaw integration
(both explicitly deferred in the spec, Section 6).

Everything this module writes lives under ~/.ai-prowler/ or the AI-Prowler
install directory that's ALREADY running — it does not touch
C:\\Program Files\\AI-Prowler unless install_wrapper_script() is explicitly
pointed there by the caller (the GUI passes the live install dir only when
the user clicks Enable; the dev/test harness in this file's __main__ block
never does).
"""

from __future__ import annotations
import json
import os
import getpass
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Crash-safe / reader-safe saves (2026-10-19) - see safe_save.py. Used for the
# queue config, last-run status, saved API keys and OAuth tokens: temp file +
# atomic swap, so the GUI / scheduled run never reads them empty or cut short.
try:
    from safe_save import atomic_write_text as _ss_write_text, read_json_retry as _ss_read_json
except Exception:                                    # safe_save.py missing (partial update): plain writes
    def _ss_write_text(path, text, encoding="utf-8", **_k):
        Path(path).write_text(text, encoding=encoding)

    def _ss_read_json(path, default=None, **_k):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except Exception:
            if default is None:
                raise
            return default

AI_PROWLER_HOME = Path.home() / ".ai-prowler"
CONFIG_PATH = AI_PROWLER_HOME / "task_automation_config.json"
STATUS_PATH = AI_PROWLER_HOME / "task_automation_last_run.json"
AUDIT_LOG_PATH = AI_PROWLER_HOME / "autonomous_run_audit.log"
WRAPPER_SCRIPT_NAME = "run_ai_prowler_queue.bat"
SCHEDULED_TASK_NAME = "AI-Prowler-QueueRunner"
# 2026-10-22 (David): the Jobs app's 🧠 "Run AI Routing" (Claude CLI) and its
# dedicated on-demand Scheduled Task were REMOVED — AI routing now happens in
# any AI chat connected to AI-Prowler (📋 Copy AI Route / 🗓️ Plan Week).
# These names are kept only so retire_cli_ai_routing() can clean up what an
# older version left on this computer.
RETIRED_AI_ROUTING_TASK_NAME = "AI-Prowler-AIRoutingRunner"
RETIRED_AI_ROUTING_DIR = AI_PROWLER_HOME / "ai_routing"   # wrapper, prompt, per-user tokens
RETIRED_ROUTE_TASK_LABEL = "AI Route Optimizer (full reasoning)"
RETIRED_AI_ROUTING_MARKER = AI_PROWLER_HOME / "cli_ai_routing_retired.marker"
# v8.1.13 fix: NEVER rely on bare `python` resolving via PATH inside the
# generated wrapper's self-gate check. Confirmed live (2026-07-28, David's
# machine) that Python's own install directory is present on the
# INTERACTIVE user PATH but silently absent from the PATH inherited by
# non-interactive process launches — Windows Task Scheduler's S4U logon,
# and even this AI-Prowler background process's own environment. This is a
# known Windows quirk: the python.org installer's "Add to PATH" option
# updates the User environment registry key, but processes spawned outside
# an interactive logon session don't reliably pick that up without a
# reboot/relog. Live evidence: `where python` failed and
# `python -c "print(1)"` produced ZERO output in that context — `for /f`
# then captures nothing, AIP_WINDOW_CHECK stays unset, and the self-gate
# falls through to its generic SKIP branch. Same exact "clean 0x0 exit,
# zero actual work" shape as the v8.1.10 (%USERPROFILE% cd) and v8.1.12
# (%a escaping) bugs — a THIRD, fully independent cause producing an
# identical-looking symptom, discovered only because the v8.1.12 fix was
# deployed and verified correct, yet the real-world SKIP persisted
# unchanged. Embedding the ABSOLUTE path to the interpreter already
# running THIS module (sys.executable) sidesteps PATH lookup entirely —
# this is always correct by construction, since it's literally the same
# interpreter generating the wrapper. Quoted in the .bat to tolerate
# spaces in the path (e.g. "C:\Program Files\Python311\python.exe" on
# other machines, even though David's own path happens not to have any).
# v9.0.0 fix: replace pythonw.exe with python.exe. The GUI launches via
# pythonw.exe (so sys.executable is pythonw.exe at import time), but the
# active-days gate subshell in the generated .bat uses this path in a
# `for /f ('...')` command — pythonw.exe discards stdout, so the gate
# check produces no output, AIP_WINDOW_CHECK stays empty, the condition
# fails, and the bat exits 0 before ever reaching the claude -p line.
# Confirmed live: last_headless_run.json was 0 bytes because the bat
# exited at the gate check. _get_python_exe() is not yet defined here
# (module-level constant), so we replicate its core logic inline.
_SELF_GATE_PYTHON = (sys.executable or "python").replace(
    "pythonw.exe", "python.exe").replace("pythonw", "python")


def _self_gate_python_invocation() -> str:
    """Formats _SELF_GATE_PYTHON for safe use as the first token of a
    `for /f ('...')` subshell command in the generated wrapper.

    v8.1.13 follow-up fix: naively wrapping the path in quotes (i.e.
    '"{_SELF_GATE_PYTHON}" -c "..."') looks correct but breaks in
    practice. cmd.exe's /C quote-handling has a documented quirk: quotes
    on the command line are preserved ONLY if there are EXACTLY TWO quote
    characters total, with no special characters (one of &<>()@^|)
    between them. Our embedded python one-liner always contains
    parentheses (`print(...)`), so adding a quoted path introduces a
    THIRD and FOURTH quote character and disqualifies that fast path.
    cmd then falls back to its "old" behavior: if the first character of
    the whole command is a quote, strip just that one character, and
    likewise for the last character — regardless of whether they're
    actually a matching pair. Since our command starts with a quoted path
    and ends with the closing quote of the python -c argument, this
    strips the OPENING quote before the path and the FINAL closing quote,
    leaving a stray, mismatched quote sitting right after ".exe" —
    confirmed live: cmd.exe reported
    'C:\\...\\python.exe" -c "import' as an unrecognized command, exactly
    matching this corruption. The original bare `python -c "..."` never
    hit this because the command didn't start with a quote character at
    all. Fix: only quote the path when it actually contains a space (the
    only reason quoting would be needed), and even then, prefix with
    `call` — a plain word, not a quote character — so the command no
    longer starts with `"` and cmd's flanking-quote heuristic never
    triggers. See TestWrapperActiveWindowSelfGateUsesExplicitPythonPath
    and the *ExecutesCorrectly real .bat-file tests for the regression
    coverage that caught this on the very same day as the fix it was
    following up on.
    """
    if " " not in _SELF_GATE_PYTHON:
        return _SELF_GATE_PYTHON
    return f'call "{_SELF_GATE_PYTHON}"'
# v8.1.11: written by AI-Prowler-Setup.iss's GrantBatchLogonRight procedure
# on a successful install-time grant of "Log on as a batch job", and by
# grant_batch_logon_right()'s own TEMPORARY fallback below on a successful
# runtime (UAC-prompted) grant. Same path constant on both sides —
# {%USERPROFILE}\.ai-prowler\batch_logon_granted.marker in the installer's
# Pascal, this in Python. Its presence means the current user never needs
# to be re-prompted.
BATCH_LOGON_MARKER_PATH = AI_PROWLER_HOME / "batch_logon_granted.marker"

# v8.1.11 fix: the wrapper used to invoke `claude -p "/ai-prowler-run-queue"`,
# relying on Claude Code discovering .claude/skills/ai-prowler-tasks/SKILL.md
# as a slash command from the current working directory. Confirmed via two
# real scheduled runs (2026-07-25, exact same "Unknown command:
# /ai-prowler-run-queue" result both times, despite the v8.1.10 cd-directory
# fix being correctly in place and verified working) that this never worked
# at all: Skills and slash commands are two DIFFERENT Claude Code mechanisms
# — Skills are meant to be auto-discovered contextually, not invoked via
# literal /name syntax, which specifically requires files under
# .claude/commands/ (which this project never had). The cd-directory fix
# was still necessary and correct — it's just not sufficient on its own.
# The fix here is to sidestep the whole commands-vs-skills question
# entirely: embed the actual task-runner instructions directly as the
# prompt text, rather than a slash-command invocation string. This has no
# dependency on Claude Code's project-file discovery working correctly in
# headless mode at all. Keep this in sync with the human-facing version at
# .claude/skills/ai-prowler-tasks/SKILL.md if the sequence ever changes —
# that file is still useful as in-repo documentation and for anyone running
# the same steps manually or interactively, it's just no longer what the
# headless wrapper actually relies on.
QUEUE_RUNNER_PROMPT = (
    # v9.0.2: removed the sync_due_tasks_to_queue step that was previously
    # step 1. The queue is user-controlled — only the user manually queues
    # tasks. Custom tasks are a saved library the user can queue or not;
    # the runner must never auto-promote them into the queue behind the
    # user's back. The runner only processes what the user has already
    # explicitly queued.
    "Run AI-Prowler's pending analysis task queue. Follow this sequence "
    "exactly, in order. "
    "1. Call get_pending_analysis_tasks. This only returns entries that "
    "are actually due right now. If nothing is returned, report that "
    "plainly and stop; do not treat an empty or not-yet-due result as an "
    "error. "
    "2. For each task returned, in the order given: read the task's "
    "prompt, scope_dirs, and label; perform the actual analysis using "
    "AI-Prowler's own MCP tools only, scoped to scope_dirs if provided, "
    "otherwise the task's default scope; call record_learning for any "
    "concrete findings worth persisting ONLY IF the task's prompt "
    "explicitly includes an Output instruction to save key insights as "
    "learnings — do not call record_learning if the task prompt does not "
    "ask for it; call complete_analysis_task with "
    "the task_id and a real, specific summary of what was found, not a "
    "placeholder; next_due advancement and re-arming are handled "
    "automatically by AI-Prowler, do not compute this yourself; if the "
    "task's configuration requested a saved report, call "
    "save_analysis_report after complete_analysis_task. "
    "3. After all tasks are processed, produce a final one-paragraph "
    "summary: how many tasks ran, one line per task on what was found, "
    "and any tasks that failed partway. "
    "If a single task's analysis fails partway through, still call "
    "complete_analysis_task for it with a summary that says it failed and "
    "why; do not leave it silently stuck in the queue, and do not let one "
    "failed task stop the rest of the queue from processing. If "
    "get_pending_analysis_tasks itself fails, stop immediately and report "
    "that clearly; do not retry silently in a loop. "
    "Use AI-Prowler's own MCP tools, mcp__ai-prowler__ prefixed, as the "
    "first choice for anything they can answer. When AI-Prowler itself has "
    "no tool or data for something a task's prompt asks for, such as "
    "current weather details AI-Prowler's own weather tool omits, sunrise "
    "or sunset times, or local event listings, fall back to your own "
    "general knowledge where that is enough, and to WebSearch or WebFetch "
    "for anything current or specific that requires looking up; use these "
    "rather than declining that part of a task and noting it as "
    "unavailable. If the task's prompt explicitly requires a connected "
    "third-party tool (such as Gmail, QuickBooks, Slack, or any other MCP "
    "connector the user has set up), use it — the user queued this task "
    "knowing what tools it needs. Do not use tools that are clearly outside "
    "the scope of what the task asks for. "
    "Do not create new task definitions; only process what is already "
    "queued."
)

DEFAULT_CONFIG = {
    "enabled": False,
    "schedule_time": "06:00",     # 24h HH:MM, used when check_mode == "daily"
    "allowed_tools": "mcp__ai-prowler__*,WebSearch,WebFetch",
    "mcp_config_path": "",         # filled in by the GUI at Enable time
    "install_dir": "",             # filled in by the GUI at Enable time
    "notify_on_complete": False,   # Phase 6 — see build_wrapper_script_content
    "notify_method": "sms",        # "sms" or "whatsapp" — which AI-Prowler tool to use
    "use_api_key": False,          # False = OAuth setup-token (default, uses subscription
                                    # allowance). True = API key (separate, metered
                                    # billing, no expiry/refresh risk) — which
                                    # provider's key is chosen by api_key_provider
                                    # below. See spec §5.3 for the tradeoff — this
                                    # does NOT affect agentic tool access, only
                                    # billing + reliability.
    "api_key_provider": "anthropic",  # 2026-10-12: which API key "use_api_key" means —
                                    # "anthropic" (Claude) or "grok" (xAI). Muse has
                                    # no public API key yet, so it is not an option.

    # v8.1.11: independently configurable check frequency + active window.
    # This is DELIBERATELY decoupled from any individual custom task's own
    # schedule (daily/weekly/hourly/etc.) — a task's schedule only decides
    # WHETHER it's due; these fields decide how often the checker itself
    # wakes up to look, and when during the day/week it's allowed to.
    # Default reproduces prior behavior exactly: daily, at schedule_time,
    # every day of the week, no time-of-day restriction — existing saved
    # configs (which predate these keys) get these via the load_config()
    # merge and see zero behavior change until explicitly customized.
    "check_mode": "daily",          # "daily" or "interval"
    "check_interval_hours": 1,      # DEPRECATED as of v9.0.1 — retained only
                                     # so pre-v9.0.1 configs still load/merge
                                     # cleanly. New code reads/writes
                                     # check_times_per_day instead (below).
    "schedule_end_time": "23:00",   # 24h HH:MM. v9.0.1: only used when
                                     # check_times_per_day > 1 — paired with
                                     # schedule_time (the start) to define
                                     # the [start, end] range that
                                     # check_times_per_day checks get evenly
                                     # spread across, via the exact same
                                     # custom_tasks_manager.compute_daily_
                                     # run_times() algorithm the My Custom AI
                                     # Analyses / Common Business AI Analysis
                                     # editors already use for the same
                                     # "Start time / End time / Times per
                                     # day" pattern — so the two features
                                     # behave identically and can't drift out
                                     # of sync with each other.
    "check_times_per_day": 1,       # v9.0.1: canonical, lossless storage of
                                     # "Check queue: N times/day" — replaces
                                     # the old check_interval_hours=round(24/N)
                                     # round-trip, which silently distorted N
                                     # for any value that doesn't divide 24
                                     # evenly (e.g. 5x/day became a 5-hour
                                     # interval — round(24/5)=5 — not the 5
                                     # evenly-spaced checks actually asked
                                     # for), compounded further by the
                                     # interval-trigger anchor bug this whole
                                     # redesign replaces.
    "active_days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
    "active_start_time": "00:00",   # only enforced when check_mode == "interval"
    "active_end_time": "23:59",     # only enforced when check_mode == "interval"
}

VALID_CHECK_MODES = frozenset({"daily", "interval"})
VALID_DAY_CODES = frozenset({"mon", "tue", "wed", "thu", "fri", "sat", "sun"})


# ── Config I/O ───────────────────────────────────────────────────────────

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return dict(DEFAULT_CONFIG)
    try:
        data = _ss_read_json(CONFIG_PATH)            # retries a mid-save read
        merged = dict(DEFAULT_CONFIG)
        merged.update(data or {})
        return merged
    except Exception:
        # Corrupt config should never crash the GUI panel — fall back to
        # a safe, disabled default and let the user reconfigure.
        return dict(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    _ss_write_text(CONFIG_PATH, json.dumps(cfg, indent=2))      # atomic (safe_save)


def load_last_run() -> dict | None:
    if not STATUS_PATH.exists():
        return None
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def _write_last_run(status: str, detail: str, task_count: int | None = None) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    _ss_write_text(STATUS_PATH, json.dumps({                   # atomic (safe_save)
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,          # "success" | "failure" | "dry_run_ok" | "dry_run_failed"
        "detail": detail,
        "task_count": task_count,
    }, indent=2))


# ── Wrapper script generation (Phase 1) ─────────────────────────────────

def build_wrapper_script_content(mcp_config_path: str, allowed_tools: str,
                                  notify_on_complete: bool = False,
                                  notify_method: str = "sms",
                                    use_api_key: bool = False,
                                    api_key_provider: str = "anthropic",
                                  check_mode: str = "daily",
                                  active_days: list | None = None,
                                  active_start_time: str = "00:00",
                                  active_end_time: str = "23:59") -> str:
    """Returns the .bat content. Kept as a pure function (no file I/O) so
    it's independently unit-testable — see test_task_queue_automation.py.

    Phase 6 (notification) is implemented as a PROMPT instruction, not a
    separate hook — hooks are observer scripts and can't make MCP tool
    calls themselves. Instead, Claude is told to call AI-Prowler's own
    send_sms/send_whatsapp tool as its own last step; the PostToolUse hook
    then logs that call in the audit trail like any other tool use.

    use_api_key / api_key_provider: when use_api_key is True, the script reads
    the selected provider's key from its file at RUNTIME and exports it before
    invoking the runner — ANTHROPIC_API_KEY for "anthropic" (Claude Code picks
    it up automatically via its documented auth priority), XAI_API_KEY for
    "grok" (read by run_grok_queue_headless). The actual key value is never
    embedded in this generated script text — only the file-read mechanism is,
    so the .bat file itself stays safe to open in a text editor without
    exposing the secret.

    v8.1.14: always cd's into AI_PROWLER_HOME (~/.ai-prowler), which now
    also holds .claude/ (settings.json's PostToolUse audit-log hook,
    hooks/log_tool_call.py, skills/ai-prowler-tasks/SKILL.md). This
    replaces the earlier install_dir PARAMETER entirely — no longer a
    value a caller has to remember to compute and pass through several
    layers (rag_gui.py -> here / run_single_prompt_now / run_queue_now).
    That design directly caused two real bugs found in the same
    debugging session: run_queue_now() silently omitted the parameter
    entirely (fell back to the old broken %USERPROFILE% default), and
    build_single_prompt_wrapper_content() (the "▶ NOW" button) had never
    been updated to accept it at all. Removing the parameter removes the
    whole bug class — there's no longer a value to forget to pass,
    because this function now always uses the same module-level constant
    every other piece of AI-Prowler state already lives under.

    v8.1.10's original fix (install_dir = the AI-Prowler CODE directory,
    e.g. C:\\Program Files\\AI-Prowler) solved the immediate cd-target bug
    but created a DIFFERENT one, found later the same day: .claude therefore
    had to be shipped into a Program-Files-class location, which requires
    admin elevation to write to — meaning generate_mcp_config()'s hook
    self-heal (_ensure_hook_uses_absolute_python(), which runs as the
    normal non-elevated AI-Prowler process) could never actually write to
    it, silently failing every time via its own try/except. AI_PROWLER_HOME
    is the one location that's simultaneously (a) discoverable by Claude
    Code via a plain `cd` — no --project-dir flag exists — (b) already
    where every other piece of AI-Prowler's own state lives
    (config/tokens/logs/generated MCP config), and (c) fully writable by
    the same non-elevated user account that runs both the GUI and the
    Scheduled Task, so self-healing code can actually do its job.
    """
    active_days = active_days if active_days is not None else list(DEFAULT_CONFIG["active_days"])
    _days_py_list = "{" + ",".join(f"'{d}'" for d in active_days) + "}"

    # v9.0.2 fix: always ensure WebSearch and WebFetch are present, and
    # broaden the MCP wildcard to mcp__* so any third-party MCP connector
    # the user has set up (QuickBooks, Gmail, Slack, etc.) is permitted.
    # The prompt already instructs Claude to use AI-Prowler's own tools
    # first — the wildcard just opens the permission gate for connectors
    # a task prompt may explicitly require. Without this, a task like
    # "check my QuickBooks invoices" would be denied at the CLI permission
    # layer even though the user deliberately queued it knowing what
    # tools it needs.
    _required_tools = {"WebSearch", "WebFetch"}
    _tools_set = {t.strip() for t in allowed_tools.split(",") if t.strip()}
    _tools_set |= _required_tools
    # Replace any mcp__ai-prowler__* with the broader mcp__* wildcard so
    # all connected MCP servers are reachable, not just AI-Prowler's own.
    _tools_set = {t if t != "mcp__ai-prowler__*" else "mcp__*" for t in _tools_set}
    # If no mcp__ wildcard at all, add the broad one.
    if not any(t.startswith("mcp__") for t in _tools_set):
        _tools_set.add("mcp__*")
    allowed_tools = ",".join(sorted(_tools_set))

    if check_mode == "interval":
        # Single Python one-liner does the whole window check and prints
        # RUN or SKIP — far more robust than parsing %DATE%/%TIME% in batch,
        # which is locale-dependent and has bitten this project before.
        _window_check_py = (
            "import datetime as _d; "
            "_n = _d.datetime.now(); "
            # v8.1.12 fix: %a and %H:%M MUST be escaped as %%a / %%H:%%M here —
            # this string is embedded inside a `for /f ... in ('python -c "..."')`
            # construct in a .bat file (see window_check_block below), and cmd.exe
            # parses a bare % as the start of ITS OWN variable substitution before
            # python ever runs. With no variable named `a`, `%a` silently resolved
            # to an empty string, so strftime('') always returned '' — which never
            # matched any entry in the active-days set, so this printed SKIP
            # unconditionally, every single day, regardless of active_days or the
            # actual weekday, while the wrapper still exited 0 ("success"). Same
            # root cause, same silent-0x0-with-zero-actual-work shape as the
            # v8.1.10 %USERPROFILE% cd bug above — just one layer deeper, inside
            # the self-gate meant to run BEFORE that code even executes. See
            # TestWrapperActiveWindowSelfGateExecutesCorrectly in
            # test_task_queue_automation.py, which actually runs the generated
            # command through cmd.exe rather than only asserting on source text —
            # the string-only assertions in TestWrapperActiveWindowSelfGate above
            # passed throughout even while this was broken.
            "_day = _n.strftime('%%a').lower()[:3]; "
            "_t = _n.strftime('%%H:%%M'); "
            f"_days = {_days_py_list}; "
            f"print('RUN' if (_day in _days and '{active_start_time}' <= _t <= '{active_end_time}') else 'SKIP')"
        )
        window_check_block = f"""REM v8.1.11: active-window self-gate. The OS-level trigger (installed by
REM install_scheduled_task()) just fires every check_interval_hours hours,
REM around the clock — day-of-week and time-of-day filtering happen HERE
REM instead, so a check outside the configured window exits before ever
REM invoking claude -p (zero cost), rather than the OS trigger trying to
REM express "every N hours, but only Mon-Fri, only 7am-10pm" directly,
REM which schtasks.exe's simple CLI can't cleanly do.
for /f "delims=" %%R in ('{_self_gate_python_invocation()} -c "{_window_check_py}"') do set AIP_WINDOW_CHECK=%%R
if not "%AIP_WINDOW_CHECK%"=="RUN" (
    echo {{"result": "Skipped — outside configured active window (day/time restriction)."}} > "%USERPROFILE%\\.ai-prowler\\last_headless_run.json"
    exit /b 0
)

"""
    else:
        # Daily mode: schedule_time IS the single trigger point (set via
        # /st on the OS trigger) — only active_days needs checking here,
        # never a time window, which would only ever contradict it.
        _window_check_py = (
            "import datetime as _d; "
            # v8.1.12 fix: same %a-escaping bug as the interval-mode branch above
            # (see the detailed comment there) — %a here MUST be %%a for the same
            # reason: this string is embedded inside a `for /f ... in ('python -c
            # "..."')` construct in a .bat file, and a bare % is consumed by
            # cmd.exe's own variable substitution before python ever sees it.
            "_day = _d.datetime.now().strftime('%%a').lower()[:3]; "
            f"_days = {_days_py_list}; "
            "print('RUN' if _day in _days else 'SKIP')"
        )
        window_check_block = f"""REM v8.1.11: active-days self-gate (daily mode). schedule_time already
REM pins the single time-of-day this fires (via the OS trigger) — only
REM day-of-week needs checking here, e.g. for a "weekdays only" setup.
for /f "delims=" %%R in ('{_self_gate_python_invocation()} -c "{_window_check_py}"') do set AIP_WINDOW_CHECK=%%R
if not "%AIP_WINDOW_CHECK%"=="RUN" (
    echo {{"result": "Skipped — today is not in the configured active days."}} > "%USERPROFILE%\\.ai-prowler\\last_headless_run.json"
    exit /b 0
)

"""

    notify_clause = ""
    if notify_on_complete:
        tool = "send_whatsapp" if notify_method == "whatsapp" else "send_sms"
        notify_clause = (
            f" After completing all tasks (or confirming the queue was "
            f"empty), call AI-Prowler's {tool} tool with a one- or two-"
            f"sentence summary of what ran and what was found. If {tool} "
            f"is not configured/available, skip this step silently rather "
            f"than treating it as a task failure."
        )

    prompt = QUEUE_RUNNER_PROMPT + notify_clause

    api_key_block = ""
    # 2026-10-12: which credential actually drives the run. Grok has no
    # Claude-Code-style CLI, so its branch exports XAI_API_KEY and invokes
    # the in-module Grok runner (run_grok_queue_headless) instead of
    # shelling out to `claude -p`.
    _provider = _normalize_provider(api_key_provider)
    if use_api_key and _provider == "grok":
        _grok_path = api_key_path("grok")
        api_key_block = f"""REM Use XAI_API_KEY (Grok) instead of Claude auth \u2014
REM metered xAI billing, no OAuth expiry/refresh risk. Read from a
REM dedicated file at runtime so the actual key never appears in this
REM script's own text.
if exist "{_grok_path}" (
    set /p XAI_API_KEY=<"{_grok_path}"
) else (
    echo [ERROR] Grok API key auth is selected but {_grok_path} was not found.
    exit /b 1
)

"""
        _tqa_parent = str(LOCAL_MCP_SCRIPT_PATH.parent)
        # _self_gate_python_invocation() — NOT a naively-quoted path: the
        # v8.1.13 cmd.exe quote quirk breaks "path" -c "..." outright.
        _invoke_block = (
            f'{_self_gate_python_invocation()} -c "import sys; '
            f"sys.path.insert(0, r'{_tqa_parent}'); "
            "import task_queue_automation as _tqa; "
            '_tqa.run_grok_queue_headless()" '
            '> "%USERPROFILE%\\\\.ai-prowler\\\\last_headless_run.json" 2>&1\n'
        )
    else:
        if use_api_key:
            api_key_block = f"""REM Use ANTHROPIC_API_KEY instead of the OAuth subscription token \u2014
REM metered billing, but no OAuth expiry/refresh risk. Read from a
REM dedicated file at runtime so the actual key never appears in this
REM script's own text.
if exist "{API_KEY_PATH}" (
    set /p ANTHROPIC_API_KEY=<{API_KEY_PATH}
) else (
    echo [ERROR] use_api_key is enabled but {API_KEY_PATH} was not found.
    exit /b 1
)

"""
        else:
            # v8.1.6 second fix: `claude -p` in a Scheduled Task context has
            # no interactive terminal and no guarantee of inheriting the same
            # environment as an interactively-signed-in session, so it can't
            # rely on ambient ~/.claude/.credentials.json the way a manual
            # `claude` session would. CLAUDE_CODE_OAUTH_TOKEN is Claude Code's
            # documented mechanism for exactly this — headless/CI auth via a
            # setup-token-generated token. Read from OAUTH_TOKEN_PLAIN_PATH
            # with a plain `set /p`, identical to the ANTHROPIC_API_KEY block
            # above — the first attempt at this parsed JSON via a PowerShell
            # one-liner invoked through `for /f` + backticks, which turned
            # out to fail with cryptic "could not be parsed" errors despite
            # valid JSON (nested-quoting fragility, same class of bug as the
            # setup-token launch command itself — see
            # build_setup_token_batch_content()'s docstring). Keeping the
            # runtime read as simple as the already-proven API-key path
            # avoids that whole category of problem.
            api_key_block = f"""REM Use the Claude Code OAuth token captured from setup-token \u2014
REM see OAUTH_TOKEN_PLAIN_PATH / try_capture_setup_token() in task_queue_automation.py.
if exist "{OAUTH_TOKEN_PLAIN_PATH}" (
    set /p CLAUDE_CODE_OAUTH_TOKEN=<{OAUTH_TOKEN_PLAIN_PATH}
) else (
    echo [ERROR] No Claude Code OAuth token found \u2014 click Get / Renew Token in AI-Prowler first.
    exit /b 1
)

"""
        # 2026-10-22 (David): ONLY the AI-Prowler that's running on this PC —
        # scheduled_run_mcp_config() connects to it (starting the normal app
        # and waiting if needed) and prints its config path, or NO_SERVER
        # after recording why the run was skipped. Never a second copy.
        _tqa_dir = str(LOCAL_MCP_SCRIPT_PATH.parent)
        _invoke_block = (
            'set "AIP_MCP_CONFIG="\n'
            f'for /f "delims=" %%M in (\'{_self_gate_python_invocation()} -c "import sys; '
            f"sys.path.insert(0, r'{_tqa_dir}'); import task_queue_automation as _t; "
            "print(_t.scheduled_run_mcp_config())\" 2^>nul') do set \"AIP_MCP_CONFIG=%%M\"\n"
            'if "%AIP_MCP_CONFIG%"=="" (\n'
            '    echo {"result": "Skipped - could not check for the running AI-Prowler."} > '
            '"%USERPROFILE%\\.ai-prowler\\last_headless_run.json"\n'
            '    exit /b 1\n'
            ')\n'
            'if "%AIP_MCP_CONFIG%"=="NO_SERVER" exit /b 1\n'
            f'"{_get_claude_exe()}" -p "{prompt}" ^\n'
            '  --mcp-config "%AIP_MCP_CONFIG%" ^\n'
            # 2026-10-22: ONLY that config — never also the user's own
            # Claude MCP servers (which may include a second AI-Prowler).
            "  --strict-mcp-config ^\n"
            f'  --allowedTools "{allowed_tools}" ^\n'
            "  --output-format json ^\n"
            '  --permission-mode bypassPermissions > "%USERPROFILE%\\\\.ai-prowler\\\\last_headless_run.json" 2>&1\n'
        )

    return rf"""@echo off
chcp 65001 >nul
REM v8.1.16 fix: chcp 65001 switches THIS cmd.exe process to the UTF-8
REM codepage before anything else runs. Without it, cmd.exe defaults to
REM the legacy OEM codepage (e.g. cp437 on US Windows) for every byte in
REM this file -- corrupting any non-ASCII character (em-dashes, curly
REM quotes, etc.) anywhere below this line, INCLUDING inside the quoted
REM prompt argument further down, not just in REM comments. Confirmed
REM live (2026-07-29): a UTF-8 BOM (encoding="utf-8-sig" when writing this
REM file) was tried first and reverted -- it works for a double-clicked
REM or interactively-run .bat, but NOT for subprocess.run(..., shell=True)
REM invocation, which doesn't auto-strip the BOM; the raw BOM bytes
REM showed up as literal garbage text ("ï»¿") prepended to this very
REM first line, corrupting `@echo off` itself and breaking the script
REM outright. chcp as an explicit in-script command has no such
REM invocation-path dependency.
REM Auto-generated by task_queue_automation.py — do not edit by hand.
REM Runs AI-Prowler's pending analysis task queue unattended via Claude
REM Code headless mode. See the architecture spec for design rationale.

{window_check_block}REM v8.1.14: cd into AI_PROWLER_HOME (~/.ai-prowler), which holds
REM .claude/hooks/log_tool_call.py's audit-log hook (via settings.json) and
REM .claude/skills/ai-prowler-tasks/SKILL.md — Claude Code only discovers
REM project-level hooks/skills from the CURRENT WORKING DIRECTORY's own
REM .claude folder. This used to cd into the AI-Prowler CODE directory
REM instead (v8.1.10) — fixed the original "Unknown command" bug, but that
REM location (e.g. C:\\Program Files\\AI-Prowler) requires admin elevation
REM to write to, which silently broke the separate audit-log hook self-heal
REM (a normal non-elevated process can't write there). AI_PROWLER_HOME is
REM fully non-elevated and writable, and is already where every other piece
REM of AI-Prowler's own state lives.
cd /d "{AI_PROWLER_HOME}"

REM command_debug.log — only written when debug_logging=true in config.json
for /f "tokens=*" %%G in ('{_self_gate_python_invocation()} -c "import json,pathlib; c=json.loads(pathlib.Path.home().joinpath('.ai-prowler','config.json').read_text()); print('1' if c.get('debug_logging') else '0')" 2^>nul') do set _DBG=%%G
if "%_DBG%"=="1" (
echo. >> "%USERPROFILE%\.ai-prowler\command_debug.log"
echo ================================================================ >> "%USERPROFILE%\.ai-prowler\command_debug.log"
echo [%date% %time%] SCHEDULED QUEUE RUN -- full script below: >> "%USERPROFILE%\.ai-prowler\command_debug.log"
type "%~f0" >> "%USERPROFILE%\.ai-prowler\command_debug.log"
)

REM v9.0.0: rotate the audit log before each run so it never grows without
REM bound. Two backup files kept: .log.1 (previous run) and .log.2 (oldest).
REM Best-effort — failure is silently ignored so it never blocks the run.
"{_get_python_exe()}" -c "import sys; sys.path.insert(0,r'{str(LOCAL_MCP_SCRIPT_PATH.parent)}'); import task_queue_automation as _tqa; _tqa.rotate_audit_log()" >nul 2>&1

{api_key_block}{_invoke_block}

set RC=%ERRORLEVEL%
exit /b %RC%
"""


def install_wrapper_script(target_dir: Path, mcp_config_path: str, allowed_tools: str,
                            notify_on_complete: bool = False,
                            notify_method: str = "sms",
                               use_api_key: bool = False,
                               api_key_provider: str = "anthropic",
                            check_mode: str = "daily",
                            active_days: list | None = None,
                            active_start_time: str = "00:00",
                            active_end_time: str = "23:59") -> Path:
    """Writes the wrapper script into target_dir. Caller decides target_dir —
    the GUI passes ~/.ai-prowler/ (NOT the install directory) so this never
    needs write access to C:\\Program Files\\AI-Prowler.

    check_mode/active_days/active_start_time/active_end_time (v8.1.11):
    forwarded straight through to build_wrapper_script_content() — see
    that function's docstring for the full rationale.

    v8.1.14: no longer accepts install_dir — build_wrapper_script_content()
    always cd's into AI_PROWLER_HOME now, see that function's docstring."""
    target_dir.mkdir(parents=True, exist_ok=True)
    script_path = target_dir / WRAPPER_SCRIPT_NAME
    # v8.1.16 fix, corrected: a UTF-8 BOM (encoding="utf-8-sig") was tried
    # first here and reverted -- confirmed live that subprocess.run(...,
    # shell=True) does NOT auto-detect/strip a BOM the way Windows 10
    # 1903+ does for a double-clicked or interactively-run .bat file. The
    # BOM bytes (EF BB BF) instead showed up as literal garbage text
    # (mojibake: "ï»¿") prepended to the very first line, corrupting
    # `@echo off` into `ï»¿@echo off` -- which cmd.exe then failed to
    # recognize as a command at all. `chcp 65001` as an explicit command
    # inside the script (added in build_wrapper_script_content()) is the
    # actually-reliable fix for this specific invocation path -- plain
    # "utf-8" (no BOM) here.
    script_path.write_text(
          build_wrapper_script_content(mcp_config_path, allowed_tools,
                                         notify_on_complete, notify_method,
                                         use_api_key,
                                           api_key_provider=api_key_provider,
                                           check_mode=check_mode,
                                           active_days=active_days,
                                           active_start_time=active_start_time,
                                           active_end_time=active_end_time),
        encoding="utf-8")
    return script_path


# ── Dry-run validation (safe — never invokes `claude -p` for real) ──────

def dry_run_check(auth: str | None = None) -> dict:
    """Validates every precondition for a real run WITHOUT triggering one.
    Returns a report dict the GUI renders as a checklist. This is the
    button-safe operation — it never touches pending_tasks.json, never
    spends usage, never sends a notification.

    v8.1.14: also runs _ensure_hook_uses_absolute_python() as a side
    effect (not itself one of the numbered checks below — this is a
    self-heal, not a validation). generate_mcp_config() already does this
    too, but ONLY runs when a config is first created or explicitly
    regenerated (e.g. toggling Enable) — a machine that already has a
    saved mcp_config_path (the common case: audit log silently stopped
    working sometime after initial setup, not before it) would never
    naturally re-trigger it. Test Setup (Dry Run) is the one button
    available at any time regardless of current Enabled state, so it's
    the most reliable place to also catch this without requiring a full
    re-enable cycle. No-ops harmlessly if .claude/settings.json doesn't
    exist yet or is already fixed — see that function's own docstring.
    """
    _ensure_hook_uses_absolute_python()
    checks = []

    # 2026-10-12 (David): test the auth method actually SELECTED in the panel
    # when the GUI passes it — 'oauth' (subscription token), 'anthropic'
    # (Claude API key) or 'grok' (Grok API key). Each needs only its own
    # credential. None = the saved setting (scheduled run / older callers).
    _sel = (auth or "").strip().lower()
    if _sel not in ("oauth", "anthropic", "grok"):
        _sel = effective_api_key_provider()

    # 2026-10-12: the runner-auth checks branch on the selected provider.
    # Grok needs no CLI at all — it calls the xAI API directly — so the
    # Claude Code CLI checks are skipped for it, replaced with a light
    # xAI reachability probe (any HTTP response, even 401, proves reachability).
    _prov = _sel
    if _prov == "grok":
        try:
            import urllib.request as _gr
            import urllib.error as _ge
            _greq = _gr.Request(XAI_MODELS_URL, method="GET")
            try:
                with _gr.urlopen(_greq, timeout=8) as _gresp:
                    _grok_net = (True, f"xAI API reachable (HTTP {_gresp.status})")
            except _ge.HTTPError as _he:
                _grok_net = (True, f"xAI API reachable (HTTP {_he.code})")
        except Exception as _e:
            _grok_net = (False, f"xAI API not reachable: {_e}")
        checks.append({
            "name": "xAI API reachable",
            "ok": _grok_net[0],
            "detail": _grok_net[1],
        })
    else:
        # 1a. Is claude.exe findable (PATH or well-known disk location)?
        #     Two-level check so we can give the user a precise action when it's
        #     on disk but PATH is broken — the exact failure mode from 2026-08-10.
        claude_path = shutil.which("claude")
        _default_disk = Path.home() / ".local" / "bin" / "claude.exe"
        _on_disk = _default_disk.exists()
        if claude_path is not None:
            _cli_detail = claude_path
        elif _on_disk:
            _cli_detail = (f"Found at {_default_disk} but not on PATH — "
                "click \\u2b07 Install Claude Code CLI to register it.")
        else:
            _cli_detail = ("`claude` not found — click \\u2b07 Install Claude Code CLI.")
        checks.append({
            "name": "Claude Code CLI on PATH",
            "ok": claude_path is not None,
            "detail": _cli_detail,
        })

        # 1b. Will Task Scheduler actually find it? dry_run_check() runs in the
        #     GUI process (full user PATH), but the Scheduled Task runs in a
        #     stripped environment that often lacks user PATH entries. This check
        #     verifies that _get_claude_exe() resolved an absolute path — meaning
        #     the wrapper .bat will use a hard path and never depend on PATH at all.
        _claude_abs = _get_claude_exe()
        _sched_ok = _claude_abs != "claude"   # resolved to something absolute
        checks.append({
            "name": "Claude Code CLI — Task Scheduler path",
            "ok": _sched_ok,

            "detail": (f"Wrapper will use absolute path: {_claude_abs}"
                if _sched_ok else
                "No absolute path found — Task Scheduler will fail. "
                "Click \\u2b07 Install Claude Code CLI to fix."),
        })

        # 2. Is there a setup-token / valid auth? We don't invoke a real call;
        #    `claude --version` is a safe, read-only smoke test that at least
        #    confirms the binary runs.
        if claude_path:
            try:
                r = subprocess.run(["claude", "--version"], capture_output=True,
                    text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW)
                checks.append({
                    "name": "Claude Code CLI runs",
                    "ok": r.returncode == 0,
                    "detail": (r.stdout or r.stderr or "").strip()[:200],
                })
            except Exception as e:
                checks.append({"name": "Claude Code CLI runs", "ok": False, "detail": str(e)})

    # 3. 2026-10-22: AI analyses only ever use the RUNNING AI-Prowler on this
    #    PC, over its local connection — which needs remote access (a Bearer
    #    Token). Read-only health check; never starts anything.
    cfg = load_config()
    _tok = _bearer_token()
    checks.append({
        "name": "Remote access (Bearer Token)",
        "ok": bool(_tok),
        "detail": ("set up (value never displayed)" if _tok else NO_REMOTE_ACCESS_MSG),
    })
    _up = bool(_tok) and _server_answers(_tok)
    checks.append({
        "name": "Running AI-Prowler (local connection)",
        "ok": _up,
        "detail": (f"answering on {LOCAL_SERVER_URL}" if _up else
                   "not answering — start it in Settings → Remote Access (a scheduled run "
                   "starts the AI-Prowler app itself if it isn't open)"),
    })

    # 4. Does the Skill file exist?
    # v8.1.14: checks under AI_PROWLER_HOME now, not the code install
    # directory — .claude/ moved there entirely (see
    # build_wrapper_script_content()'s docstring for the full history: the
    # v8.1.11 fix below was itself superseded by this move, kept here for
    # context on why __file__-relative resolution was ever used in the
    # first place).
    #
    # v8.1.11 fix (historical): real-world bug — Path.cwd() reflects
    # whatever the CALLING process's current working directory happens to
    # be, which is only correct by accident (e.g. a desktop shortcut's
    # "Start in" field). Confirmed live: a fresh install auto-launched via
    # the AI-Prowler-AutoStart Scheduled Task (no explicit working
    # directory) inherited Windows' default of C:\Windows\System32, and
    # this check reported the Skill file "missing" at
    # C:\Windows\System32\.claude\skills\..., even though it was correctly
    # installed. __file__-relative resolution fixed that specific bug, but
    # depended on .claude/ living alongside the code — which is exactly
    # the assumption v8.1.14 removed, for the admin-elevation reasons
    # documented above.
    skill_path = AI_PROWLER_HOME / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
    # 2026-10-12: Claude Code only — a Grok run doesn't use the Skill file.
    if _sel != "grok":
        checks.append({
            "name": "AI-Prowler Skill file",
            "ok": skill_path.exists(),
            "detail": str(skill_path),
        })

    # 5. Is an MCP config path configured?
    mcp_cfg_ok = bool(cfg.get("mcp_config_path")) and Path(cfg["mcp_config_path"]).exists()
    checks.append({
        "name": "MCP config file",
        "ok": mcp_cfg_ok,
        "detail": cfg.get("mcp_config_path") or "(not set — click Enable to generate one)",
    })

    # 6. Auth check — branches on which mechanism is configured. Only one
    # of these is relevant at a time; showing the others would be noise
    # (and, in the API-key case, checking OAuth expiry is meaningless).
    _auth_prov = _sel
    if _auth_prov == "grok":
        _grok_key_ok = has_api_key("grok")
        checks.append({
            "name": "Grok API key (xAI)",
            "ok": _grok_key_ok,
            "detail": ("configured (value never displayed)" if _grok_key_ok
                       else "not set — paste one in the Auth section and click Save Key"),
        })
    elif _auth_prov == "anthropic":
        key_ok = has_api_key("anthropic")
        checks.append({
            "name": "Claude API key",
            "ok": key_ok,
            "detail": ("configured (value never displayed)" if key_ok
                       else f"not set — click Get / Renew Token to add one "
                            f"(saved to {API_KEY_PATH})"),
        })
    else:
        token_info = check_token_expiry()
        checks.append({
            "name": "Claude Code auth token",
            "ok": token_info["status"] in ("ok", "expiring_soon"),
            "detail": token_info["detail"],
        })

    all_ok = all(c["ok"] for c in checks)
    _write_last_run("dry_run_ok" if all_ok else "dry_run_failed",
                     f"{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed")
    return {"all_ok": all_ok, "checks": checks}


# ── AI-Prowler MCP config generation ──────────────────────────────────────
# This is a SEPARATE auth layer from Claude's own Anthropic auth (OAuth
# setup-token or, if added later, ANTHROPIC_API_KEY). AI-Prowler's own MCP
# server requires its own Bearer token regardless of how the calling Claude
# session authenticates to Anthropic — see architecture spec §"two auth
# layers" discussion.
#
# v8.2.x fix (bug report: fresh install / fresh machine — Test Setup (Dry
# Run) never produced a config file even after successfully getting a
# Claude Code token): generate_mcp_config() used to ONLY write a remote
# HTTP config, which requires a Bearer Token + Cloudflare tunnel domain to
# already be saved under Settings → Remote Access. Those are a THIRD,
# unrelated piece of setup — not the Claude Code OAuth token, not AI-
# Prowler's install itself — so on a genuinely fresh machine (no tunnel
# ever configured) this silently failed every time, regardless of the
# Claude Code token being valid. Since the headless wrapper always runs ON
# THIS SAME MACHINE (a local Windows Scheduled Task, not a remote mobile
# client), a local stdio config — the exact same shape as the Claude
# Desktop auto-config the installer already writes into
# %APPDATA%\Claude\claude_desktop_config.json — needs nothing but AI-Prowler's own
# install path, which is always known. generate_mcp_config() now tries
# that FIRST (zero setup required), and only falls back to the remote HTTP
# path for users who've actually configured remote/mobile access.
AI_PROWLER_CONFIG_PATH = Path.home() / ".ai-prowler" / "config.json"
GENERATED_MCP_CONFIG_PATH = AI_PROWLER_HOME / "claude_mcp_config.json"
# Resolved once at import time, same directory task_queue_automation.py and
# ai_prowler_mcp.py always ship in together (see AI-Prowler-Setup.iss).
# Exposed as a module-level constant (rather than computed inline) so tests
# can monkeypatch it, matching the pattern already used for every other
# path in this module.
LOCAL_MCP_SCRIPT_PATH = Path(__file__).resolve().parent / "ai_prowler_mcp.py"


def _get_python_exe() -> str:
    """Return the console python.exe path, never pythonw.exe.

    sys.executable is pythonw.exe when AI-Prowler launches as a GUI app
    (RAG_RUN.bat uses pythonw to suppress the console window). That's
    correct for the GUI itself but breaks stdio MCP server usage: claude -p
    communicates with the MCP server via stdin/stdout pipes, and pythonw.exe
    explicitly discards both — pipes connect to null handles, so the MCP
    server produces no output and claude -p hangs indefinitely waiting for
    responses that never arrive. Confirmed live (2026-07-29): every ▶ NOW
    run with a stdio MCP config hung for 10+ minutes before being killed.
    Fix: always use python.exe (console variant) for spawning child processes.
    """
    exe = sys.executable or ""
    if exe.lower().endswith("pythonw.exe"):
        exe = exe[:-len("pythonw.exe")] + "python.exe"
    return exe


def _get_claude_exe() -> str:
    """Return the absolute path to claude.exe for embedding in the .bat
    wrapper. Never relies on bare 'claude' on PATH — Task Scheduler runs
    in a stripped environment that often lacks the user's PATH entries,
    which is exactly what caused the 2026-08-10 silent-failure bug where
    the .bat fired correctly but 'claude' was not recognized as a command.

    Resolution order (mirrors claude_code_cli_installed()'s disk fallback
    so both functions agree on what "installed" means):
      1. shutil.which("claude") — covers any user-configured install path.
      2. ~/.local/bin/claude.exe — Anthropic's default install location when
         their install.ps1 script doesn't add itself to PATH automatically.
      3. Bare "claude" as a last resort so the generated .bat fails loudly
         with a recognisable error rather than silently doing nothing.

    Called at wrapper-generation time (Enable / Apply / Run Due Tasks), so
    the resolved path is baked into the .bat — the running Scheduled Task
    never has to search PATH at all.
    """
    path = shutil.which("claude")
    if path:
        return path
    default = Path.home() / ".local" / "bin" / "claude.exe"
    if default.exists():
        return str(default)
    return "claude"


# ── Always the RUNNING AI-Prowler (2026-10-22, David) ────────────────────────
# "The task queue or custom analysis tasks should never open up a new
# AI-Prowler — always use the AI-Prowler that's running (it starts with the
# PC)." Every Claude / Grok run of the Autonomous AI Task Queue (scheduled or
# ▶ NOW) talks to this PC's running AI-Prowler over its local connection
# (http://localhost:8000/mcp — never the internet tunnel), signed in with this
# install's Bearer Token so the server knows the call is the owner's.
#
# The old stdio config (Claude starting its own ai_prowler_mcp.py for the run)
# and the Grok runner's own stdio copy are GONE: two AI-Prowlers on one
# database is what made runs crawl or hang.
#
# The local connection only exists when remote access is set up (a Bearer
# Token) — David chose to REQUIRE that rather than open one without a token.
# If AI-Prowler isn't running when a scheduled run fires, the run starts the
# normal app (the AI-Prowler-AutoStart task the installer registers to start
# it at sign-in — never a hidden copy), waits for it, then runs; if it still
# doesn't answer, the run is skipped and says why.
LOCAL_SERVER_URL = "http://localhost:8000"
STARTUP_TASK_NAME = "AI-Prowler-AutoStart"
SERVER_START_WAIT_SEC = 300
NO_REMOTE_ACCESS_MSG = (
    "Remote access isn't set up on this PC (no Bearer Token), so there is no running "
    "AI-Prowler connection for AI analyses to use. Set it up in Settings → Remote Access, "
    "then try again.")


def _bearer_token() -> str:
    """This install's Bearer Token (config.json remote_token); '' if none."""
    try:
        cfg = json.loads(AI_PROWLER_CONFIG_PATH.read_text(encoding="utf-8-sig")) \
            if AI_PROWLER_CONFIG_PATH.exists() else {}
    except Exception:
        cfg = {}
    return str(cfg.get("remote_token") or "").strip()


def _server_answers(token: str, timeout: float = 3) -> bool:
    """True when the running AI-Prowler answers on its local connection."""
    import urllib.request as _ur
    try:
        req = _ur.Request(LOCAL_SERVER_URL + "/health", headers={"Authorization": f"Bearer {token}"})
        with _ur.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


def _write_server_config(token: str, path) -> tuple[bool, str]:
    """Writes a Claude Code --mcp-config that points at the running AI-Prowler."""
    mcp_config = {"mcpServers": {"ai-prowler": {
        "type": "http",
        "url": LOCAL_SERVER_URL + "/mcp",
        "headers": {"Authorization": f"Bearer {token}"},
    }}}
    try:
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        _ss_write_text(Path(path), json.dumps(mcp_config, indent=2))   # atomic (safe_save)
    except Exception as e:
        return False, f"Could not write MCP config: {e}"
    return True, str(path)


def _ai_prowler_app_running() -> bool:
    """True when the AI-Prowler desktop app (rag_gui.py) is running for this
    user — then we never start another, we just wait for its connection."""
    if os.name != "nt":
        return False
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" | "
             "Where-Object { $_.CommandLine -like '*rag_gui.py*' } | Measure-Object).Count"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return int((r.stdout or "0").strip().splitlines()[-1]) > 0
    except Exception:
        return False


def _start_ai_prowler_app() -> tuple[bool, str]:
    """Starts the normal AI-Prowler app the same way signing in to Windows
    does (the installer's AI-Prowler-AutoStart task) — on your own desktop,
    never a hidden copy. Windows only starts it while you're signed in."""
    if os.name != "nt":
        return False, "starting AI-Prowler automatically is Windows-only"
    try:
        r = subprocess.run(["schtasks", "/run", "/tn", STARTUP_TASK_NAME],
                           capture_output=True, text=True, timeout=30,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as e:
        return False, f"couldn't start AI-Prowler ({e})"
    if r.returncode != 0:
        return False, ("couldn't start AI-Prowler (" + ((r.stderr or r.stdout or "").strip()[:200]
                                                        or f"schtasks exit {r.returncode}") + ")")
    return True, "AI-Prowler was started"


def connect_to_running_ai_prowler(wait_sec: int = SERVER_START_WAIT_SEC, start_app: bool = True,
                                  config_path=None) -> tuple[bool, str]:
    """(True, mcp-config path) for the running AI-Prowler, or (False, why).
    Never starts a second copy: needs a Bearer Token (remote access); if the
    connection doesn't answer and start_app is set, starts the normal app —
    only when it isn't already open — and waits up to wait_sec."""
    token = _bearer_token()
    if not token:
        return False, NO_REMOTE_ACCESS_MSG
    target = config_path or RUNNING_SERVER_MCP_CONFIG_PATH
    deadline = time.time() + max(0, wait_sec)
    started, tried = "", False
    while True:
        if _server_answers(token):
            return _write_server_config(token, target)
        if start_app and not tried:
            tried = True
            if not _ai_prowler_app_running():
                _ok, started = _start_ai_prowler_app()
        if time.time() >= deadline:
            break
        time.sleep(5)
    why = "AI-Prowler isn't running on this PC — its local connection didn't answer"
    if wait_sec:
        why += f" within {max(1, wait_sec // 60)} minute(s)"
    why += "."
    if started:
        why += f" ({started}; it starts when you're signed in to Windows.)"
    elif start_app and tried:
        why += " (The AI-Prowler app is open but its connection isn't on — check Settings → Remote Access.)"
    return False, why


def generate_mcp_config_for_now_button() -> tuple[bool, str]:
    """▶ NOW button: the running AI-Prowler (the GUI that has the button is it)."""
    return connect_to_running_ai_prowler(wait_sec=10, start_app=False,
                                         config_path=AI_PROWLER_HOME / "claude_mcp_config_now.json")


def _ensure_hook_uses_absolute_python() -> None:
    """v8.1.14 fix: self-heal .claude/settings.json's PostToolUse hook
    command to invoke the audit-log hook via an ABSOLUTE python.exe path
    (sys.executable) instead of a bare `python` token.

    This is the exact same bug, and the exact same fix, as the v8.1.13
    bare-`python` issue documented in detail at the top of this module for
    the wrapper .bat's self-gate window check — confirmed live on David's
    machine (2026-07-28) that `python` resolves fine in an interactive
    shell but is silently ABSENT from PATH for non-interactive process
    launches (Windows Task Scheduler S4U logon). That fix covered the
    wrapper .bat. It did NOT cover this hook, because the hook's launch
    command lives in a separate, static file — .claude/settings.json,
    shipped as-is by the installer — rather than being generated fresh
    by this module the way the wrapper .bat is.

    Practical effect of the gap: after the v8.1.10-and-later fixes, the
    Scheduled Task correctly cd's into the app directory, .claude/settings.json
    and .claude/hooks/log_tool_call.py are correctly present (once
    reinstalled), the hook's PostToolUse matcher correctly matches AI-
    Prowler's MCP tool names ("mcp__ai-prowler__.*") — and STILL nothing
    ever lands in autonomous_run_audit.log, because Claude Code's own
    subprocess spawn for the hook command inherits the same PATH-less
    environment as everything else launched non-interactively, so `python
    ".../log_tool_call.py"` fails to even start. No error surfaces
    anywhere the user would see it — Claude Code hooks are fire-and-forget
    by design (a hook is never allowed to block or fail the actual tool
    call), so a hook that can't launch just silently produces zero output,
    identical in appearance to "the hook ran and correctly decided this
    wasn't an AI-Prowler tool call."

    Self-heals rather than being a one-time build-time fix, because a
    hardcoded absolute path baked in on David's dev machine at build time
    would be wrong on every other end user's machine (different Python
    install location). Called from generate_mcp_config(), which already
    runs before every real execution path (Test Setup / Dry Run, the
    Scheduled Task's own setup, and every "▶ NOW" / "Run Due Tasks"
    invocation all require a valid MCP config first) — so this keeps
    itself correct for whichever machine and Python install it's actually
    running under, no separate install-time step required.

    v8.1.14 follow-up: settings_path now resolves under AI_PROWLER_HOME,
    not the code install directory — see build_wrapper_script_content()'s
    docstring for why .claude/ moved there (in short: the code directory
    can be a Program-Files-class admin-only location, which this very
    self-heal function can't write to).

    Best-effort and silent: never raises, matching the philosophy of the
    hook script itself (audit logging must never be allowed to interfere
    with the actual task run). A missing settings.json, unreadable JSON,
    an already-fixed command, or a locked/read-only file are all treated
    as "nothing to do" rather than errors.
    """
    try:
        settings_path = AI_PROWLER_HOME / ".claude" / "settings.json"
        if not settings_path.exists():
            return
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        hook_entry = (data.get("hooks", {})
                          .get("PostToolUse", [{}])[0]
                          .get("hooks", [{}])[0])
        current_cmd = hook_entry.get("command", "")
        if not current_cmd or not current_cmd.lstrip().startswith("python "):
            return  # already fixed, or not the shape we expect — leave it alone

        python_exe = sys.executable or "python"
        # Rebuild the command with an absolute, quoted interpreter path in
        # place of the bare `python` token. Everything after the first
        # token (the script path, including the ${CLAUDE_PROJECT_DIR}
        # placeholder Claude Code itself expands) is preserved unchanged.
        rest = current_cmd.split(" ", 1)[1] if " " in current_cmd else ""
        new_cmd = f'"{python_exe}" {rest}'.rstrip()
        if new_cmd == current_cmd:
            return

        data["hooks"]["PostToolUse"][0]["hooks"][0]["command"] = new_cmd
        _ss_write_text(settings_path, json.dumps(data, indent=2))   # atomic (safe_save)
    except Exception:
        pass  # self-heal is best-effort — never let this block MCP config generation


def _ensure_workspace_trusted() -> None:
    """R-051 (2026-09-28): mark AI_PROWLER_HOME as a trusted Claude Code
    workspace for the Windows account these runs use.

    Every headless run cd's into AI_PROWLER_HOME (see the wrappers). Claude
    Code ignores that folder's .claude/settings.json allow-list until the
    folder has been trusted once interactively, and prints this warning on
    every run:
        "Ignoring 2 permissions.allow entries from .claude/settings.json:
         this workspace has not been trusted. ..."
    Nothing was blocked (the wrappers pass --allowedTools and
    --permission-mode bypassPermissions), but the warning is merged into the
    run's JSON output file (2>&1) and broke parsing of the AI Route result —
    confirmed live 2026-09-28, the Jobs app showed the raw output.

    Claude Code keeps trust in ~/.claude.json under
    projects["C:/Users/<you>/.ai-prowler"].hasTrustDialogAccepted — the exact
    setting its own warning tells you to set. The home folder is derived from
    AI_PROWLER_HOME (always ~/.ai-prowler) so tests that point AI_PROWLER_HOME
    at a temp folder never touch the real file. Only that one key is added;
    everything else in the file is kept. Writes only when it isn't already
    set, via a temp file + os.replace. An unreadable or odd-shaped file is
    left alone. Best-effort — never blocks a run.
    """
    try:
        cfg_path = AI_PROWLER_HOME.parent / ".claude.json"
        key = str(AI_PROWLER_HOME).replace("\\", "/")
        if cfg_path.exists():
            text = cfg_path.read_text(encoding="utf-8").strip()
            data = json.loads(text) if text else {}
        else:
            data = {}
        if not isinstance(data, dict):
            return
        projects = data.setdefault("projects", {})
        if not isinstance(projects, dict):
            return
        entry = projects.setdefault(key, {})
        if not isinstance(entry, dict):
            return
        if entry.get("hasTrustDialogAccepted") is True:
            return
        entry["hasTrustDialogAccepted"] = True
        tmp = cfg_path.with_name(cfg_path.name + ".aip_tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(cfg_path))
    except Exception:
        pass


def parse_claude_json_output(raw: str) -> dict | None:
    """R-051: the result object from `claude -p --output-format json` output,
    even when Claude Code printed warning lines before or after it (the
    wrappers merge stderr into the same file). Returns the LAST JSON object
    that looks like a Claude result (has "result", "is_error" or "type"), or
    None if there isn't one — the caller then shows the raw text."""
    if not raw:
        return None
    text = raw.strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except ValueError:
        pass
    decoder = json.JSONDecoder()
    found = None
    i = text.find("{")
    while i != -1:
        try:
            obj, end = decoder.raw_decode(text, i)
        except ValueError:
            i = text.find("{", i + 1)
            continue
        if isinstance(obj, dict) and ("result" in obj or "is_error" in obj or "type" in obj):
            found = obj
        i = text.find("{", end)
    return found


def generate_mcp_config(prefer_remote: bool = False) -> tuple[bool, str]:
    """Writes/refreshes the --mcp-config file for scheduled runs. 2026-10-22:
    ALWAYS the running AI-Prowler on this PC (see the section above) — never a
    stdio copy, never the internet tunnel — so it needs remote access (a
    Bearer Token): without one this returns (False, NO_REMOTE_ACCESS_MSG) and
    the task queue can't be turned on. Doesn't need AI-Prowler to be answering
    right now; each run connects (and starts the app if needed) at run time.
    prefer_remote is ignored (kept for older callers).

    v8.1.14 / R-051: also self-heals the audit-log hook and marks
    AI_PROWLER_HOME a trusted Claude Code workspace.
    Returns (success, path_or_error_message)."""
    _ensure_hook_uses_absolute_python()
    _ensure_workspace_trusted()
    token = _bearer_token()
    if not token:
        return False, NO_REMOTE_ACCESS_MSG
    return _write_server_config(token, GENERATED_MCP_CONFIG_PATH)




# ── API KEY storage, per provider (2026-10-12: Grok added) ────────────────
# Alternative to the OAuth setup-token path. Same agentic tool access —
# this is purely a billing/auth-mechanism choice. Trades subscription
# billing for metered per-token billing, in exchange for no expiry/refresh
# risk (a static key doesn't expire the way an OAuth access token does).
# Stored as a separate plain-text file, not inside task_automation_config.json,
# so a casual look at the config file (e.g. for debugging schedule/notify
# settings) doesn't also expose the key. This is the same plaintext-on-disk
# tradeoff AI-Prowler's own config.json already makes for the Bearer token —
# not introducing a new class of risk, just being deliberate about where.

API_KEY_PROVIDERS = ("anthropic", "grok")
# The Anthropic file keeps its historical "claude_api_key.txt" name so an
# already-saved Claude key is never orphaned by this change.
API_KEY_PATH = AI_PROWLER_HOME / "claude_api_key.txt"
GROK_API_KEY_PATH = AI_PROWLER_HOME / "grok_api_key.txt"


def _normalize_provider(provider: str | None) -> str:
    """Coerce to a known provider; unknown/blank values fall back to
    "anthropic" rather than raising — a hand-edited config must never crash
    the queue, it just runs on Claude like before."""
    p = (provider or "anthropic").strip().lower()
    p = {"xai": "grok", "claude": "anthropic"}.get(p, p)
    return p if p in API_KEY_PROVIDERS else "anthropic"


def api_key_path(provider: str = "anthropic") -> Path:
    """File holding the saved API key for a provider. Reads the module-level
    constants at CALL time (not import time) so tests can monkeypatch them,
    matching the pattern used for every other path in this module.

    Strict: unknown providers raise ValueError rather than silently landing
    in the wrong file. Config-originated values go through _normalize_provider
    first (graceful fallback); direct callers must name a real provider."""
    p = (provider or "").strip().lower()
    if p in ("grok", "xai"):
        return GROK_API_KEY_PATH
    if p in ("anthropic", "claude"):
        return API_KEY_PATH
    raise ValueError(f"Unknown API key provider: {provider!r}")


def save_api_key(key: str, provider: str = "anthropic") -> None:
    _p = api_key_path(provider)
    _p.parent.mkdir(parents=True, exist_ok=True)      # the key file's own folder
    _ss_write_text(_p, key.strip())                   # atomic (safe_save) - never an empty key file


def load_api_key(provider: str = "anthropic") -> str | None:
    path = api_key_path(provider)
    if not path.exists():
        return None
    val = path.read_text(encoding="utf-8").strip()
    return val or None


def has_api_key(provider: str = "anthropic") -> bool:
    """Presence check only — never returns or logs the actual key value.
    Use this for GUI/dry-run display; use load_api_key() only where the
    real value is actually needed (i.e. never, in this module — the
    wrapper .bat reads the file itself at runtime, see
    build_wrapper_script_content)."""
    return load_api_key(provider) is not None


def delete_api_key(provider: str = "anthropic") -> None:
    path = api_key_path(provider)
    if path.exists():
        path.unlink()


def effective_api_key_provider(cfg: dict | None = None) -> str:
    """Which credential the queue will actually run on: "anthropic", "grok",
    or "oauth". Returns "oauth" whenever use_api_key is falsy — the GUI
    writes both keys, so callers never have to reconcile them by hand."""
    cfg = cfg if cfg is not None else load_config()
    if not cfg.get("use_api_key"):
        return "oauth"
    return _normalize_provider(cfg.get("api_key_provider"))

# ── Grok (xAI) headless runner ──────────────────────────────────────────
# 2026-10-12: unattended queue execution on a Grok API key. Muse and Grok
# have no Claude-Code-style CLI, so unlike the Claude path (which shells out
# to `claude -p`), the Grok path runs IN-PROCESS here:
#   1. spawn AI-Prowler's own MCP server over stdio (the same proven shape
#      the scheduled task's --mcp-config uses — no port, no Bearer, no
#      tunnel needed; safe overnight when the GUI is closed),
#   2. list its tools and expose them to Grok as OpenAI-style functions,
#   3. drive the standard multi-turn function-calling loop against
#      https://api.x.ai/v1/chat/completions.
# Muse has no public API key yet, so there is no third runner.

XAI_API_URL = "https://api.x.ai/v1/chat/completions"
XAI_MODELS_URL = "https://api.x.ai/v1/models"
# 2026-10-12: grok-4.3 — xAI's recommended model for agentic tool calling; the
# old grok-4-1-fast slug is not one of the documented post-May-15-2026 redirects.
GROK_MODEL = "grok-4.3"   # override per-install via task_automation_config.json "grok_model"
GROK_MAX_TOOL_ROUNDS = 40
GROK_HTTP_TIMEOUT = 300          # seconds per xAI call
GROK_SINGLE_PROMPT_TIMEOUT = 600
GROK_QUEUE_DEADLINE = 30 * 60    # seconds for a whole queue run
GROK_MAX_TOOLS = 120             # xAI accepts at most 128 tools per request

# Which AI-Prowler tools a Grok run is offered when allowed_tools is broad
# ("mcp__*"): the queue essentials first, then whole feature groups, then
# READ-ONLY Jobs tools — capped at GROK_MAX_TOOLS. Never anything that writes
# files, runs scripts or restores data (an unattended run doesn't need it).
GROK_ESSENTIAL_TOOLS = (
    "get_pending_analysis_tasks", "get_all_queued_tasks", "complete_analysis_task",
    "save_analysis_report", "how_to_use_ai_prowler", "check_ai_prowler_status",
    "search_documents", "multi_query_search", "read_document", "expand_search_result",
    "get_knowledge_base_overview", "list_indexed_documents", "search_within_directory",
    "search_learnings", "record_learning", "list_learnings", "get_learning",
    "get_learning_stats", "get_learnings_report",
    "send_email", "send_sms", "send_whatsapp", "get_weather",
)
GROK_GROUP_ORDER = ("core_kb", "self_learning", "agentic_analysis", "status_system",
                    "email", "sms_whatsapp")
GROK_READ_ONLY_PREFIXES = ("get_", "read_", "list_", "find_", "search_", "check_",
                           "export_", "build_maps_url", "geocode_")
GROK_NEVER_OFFER = frozenset({
    "create_file", "write_file", "edit_file", "str_replace_in_file", "line_replace_in_file",
    "delete_file", "run_script", "run_script_start", "untrack_directory", "reindex_all",
    "restore_backup", "restore_job_database", "grant_access", "grant_write_access",
    "revoke_access", "revoke_write_access",
})

GROK_QUEUE_RUNNER_PROMPT = (
    QUEUE_RUNNER_PROMPT
    .replace(
        "Use AI-Prowler's own MCP tools, mcp__ai-prowler__ prefixed, as the "
        "first choice for anything they can answer.",
        "Use AI-Prowler's own MCP tools (exposed to you as functions) as the "
        "first choice for anything they can answer.")
    .replace(
        "to WebSearch or WebFetch for anything current or specific that "
        "requires looking up",
        # 2026-10-12: no web search in a Grok run — xAI's built-in web_search
        # is a Responses-API tool, and this runner uses Chat Completions.
        "to your own general knowledge for anything current or specific (there "
        "is no web search in this run — say so in the report where it matters)")
)


class _HttpMCPClient:
    """Minimal MCP client over the running AI-Prowler's local connection
    (Streamable HTTP, http://localhost:8000/mcp): initialize, tools/list,
    tools/call. 2026-10-22: replaced _StdioMCPClient, which started its own
    copy of AI-Prowler for every Grok run."""

    def __init__(self, token: str, url: str = None):
        self._url = url or (LOCAL_SERVER_URL + "/mcp")
        self._token = token
        self._sid = None
        self._next_id = 1

    def _post(self, payload, timeout):
        import urllib.request as _ur
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "Authorization": f"Bearer {self._token}"}
        if self._sid:
            headers["Mcp-Session-Id"] = self._sid
        req = _ur.Request(self._url, data=json.dumps(payload).encode("utf-8"),
                          headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._sid = sid
            ctype = (resp.headers.get("Content-Type") or "").lower()
            body = resp.read().decode("utf-8", errors="replace")
        return self._parse(body, ctype)

    @staticmethod
    def _parse(body: str, ctype: str) -> list:
        if not body.strip():
            return []
        if "text/event-stream" in ctype or body.lstrip().startswith(("event:", "data:")):
            msgs, data = [], []
            for line in body.replace("\r\n", "\n").split("\n"):
                if line.startswith("data:"):
                    data.append(line[5:].lstrip())
                elif not line.strip() and data:
                    msgs.append("\n".join(data))
                    data = []
            if data:
                msgs.append("\n".join(data))
            out = []
            for m in msgs:
                try:
                    obj = json.loads(m)
                except Exception:
                    continue
                out.extend(obj if isinstance(obj, list) else [obj])
            return out
        obj = json.loads(body)
        return obj if isinstance(obj, list) else [obj]

    def _request(self, method, params=None, timeout=180):
        rid = self._next_id
        self._next_id += 1
        for msg in self._post({"jsonrpc": "2.0", "id": rid, "method": method,
                               "params": params or {}}, timeout):
            if isinstance(msg, dict) and msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"MCP {method} error: {msg['error']}")
                return msg.get("result")
        raise RuntimeError(f"MCP {method}: no reply from AI-Prowler")

    def initialize(self, timeout=60):
        result = self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ai-prowler-grok-runner", "version": "1.0"},
        }, timeout=timeout)
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, 30)
        except Exception:
            pass
        return result

    def list_tools(self):
        return (self._request("tools/list") or {}).get("tools", [])

    def call_tool(self, name, arguments=None, timeout=300):
        res = self._request("tools/call", {"name": name, "arguments": arguments or {}},
                            timeout=timeout) or {}
        parts = [c.get("text", "") for c in res.get("content", [])
                 if isinstance(c, dict) and c.get("type") == "text"]
        text = "\n".join(parts)
        if res.get("isError"):
            raise RuntimeError(text or f"tool {name} reported an error")
        return text

    def close(self):
        if not self._sid:
            return
        try:
            import urllib.request as _ur
            _ur.urlopen(_ur.Request(self._url, method="DELETE", headers={
                "Authorization": f"Bearer {self._token}", "Mcp-Session-Id": self._sid}), timeout=10)
        except Exception:
            pass


def _grok_chat(api_key, messages, tools, model=None):
    """One chat-completions call against the xAI API. Returns the assistant
    message dict. Raises RuntimeError carrying the API's own error text."""
    import urllib.request as _ur
    import urllib.error as _ue
    body = {"model": (model or GROK_MODEL),
            "messages": messages,
            "tool_choice": "auto"}
    if tools:
        body["tools"] = tools
    req = _ur.Request(
        XAI_API_URL, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + api_key},
        method="POST")
    try:
        with _ur.urlopen(req, timeout=GROK_HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except _ue.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            detail = str(e)
        raise RuntimeError(f"xAI API HTTP {e.code}: {detail}")
    except Exception as e:
        raise RuntimeError(f"xAI API request failed: {e}")
    choices = (data or {}).get("choices") or []
    if not choices or not isinstance(choices[0].get("message"), dict):
        raise RuntimeError(f"xAI API returned no message: {str(data)[:300]}")
    return choices[0]["message"]


def _mcp_tool_to_xai_function(tool):
    """Convert one MCP tools/list entry to an xAI/OpenAI function tool."""
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        schema = {"type": "object", "properties": {}}
    return {"type": "function",
            "function": {"name": tool.get("name", "unnamed_tool"),
                         "description": str(tool.get("description") or "")[:1000],
                         "parameters": schema}}


def _grok_select_tools(allowed_tools, mcp_tools):
    """Map the queue's allowed_tools string (Claude-style names) onto the
    MCP tools actually available. Returns (xai_tools, web_search_enabled).
    "mcp__ai-prowler__*" / "mcp__*" / "*" select everything; a bare
    "mcp__ai-prowler__<name>" selects one; WebSearch/WebFetch enable xAI's
    server-side web_search tool (metered by xAI per call)."""
    wanted = {t.strip() for t in (allowed_tools or "").split(",") if t.strip()}
    broad = bool(wanted & {"mcp__ai-prowler__*", "mcp__*", "*"})
    specific = set()
    for w in wanted:
        if w.startswith("mcp__ai-prowler__") and not w.endswith("*"):
            specific.add(w[len("mcp__ai-prowler__"):])
        elif w.startswith("mcp__") and not w.endswith("*") and "__" in w:
            specific.add(w.split("__", 1)[1])
    web = bool(wanted & {"WebSearch", "WebFetch"})
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
        # fill spare room with everything else available (ranked tools first)
        order += sorted(n for n in avail if n not in order)
        names = order[:GROK_MAX_TOOLS]
    else:
        names = [n for n in by_name if n in specific][:GROK_MAX_TOOLS]
    return [_mcp_tool_to_xai_function(by_name[n]) for n in names], web


def _grok_audit(text):
    """One audit-log line for a Grok run — same file the Claude hook writes."""
    try:
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} [grok] {text}\n")
    except Exception:
        pass


def _grok_tool_loop(api_key, prompt, xai_tools, mcp_client, model, timeout_sec):
    """The multi-turn function-calling loop. Returns (ok, summary)."""
    messages = [
        {"role": "system",
         "content": ("You are Grok, running AI-Prowler's scheduled analysis task "
                     "queue headlessly. Be efficient: make the tool calls the task "
                     "needs, then finish with complete_analysis_task for each task "
                     "and a short final summary. Never ask the user questions — "
                     "there is no one to answer.")},
        {"role": "user", "content": prompt},
    ]
    deadline = time.time() + timeout_sec
    for _round in range(GROK_MAX_TOOL_ROUNDS):
        if time.time() > deadline:
            return False, "overall time budget exceeded before the queue finished"
        try:
            msg = _grok_chat(api_key, messages, xai_tools, model)
        except Exception as e:
            return False, f"xAI API call failed: {e}"
        assistant_msg = {"role": "assistant"}
        if msg.get("content"):
            assistant_msg["content"] = msg["content"]
        tool_calls = msg.get("tool_calls") or []
        if tool_calls:
            assistant_msg["tool_calls"] = [
                {"id": tc.get("id"),
                 "type": "function",
                 "function": {"name": (tc.get("function") or {}).get("name", ""),
                              "arguments": (tc.get("function") or {}).get("arguments") or "{}"}}
                for tc in tool_calls]
        messages.append(assistant_msg)
        if not tool_calls:
            return True, (msg.get("content") or "Run finished.").strip()[:4000]
        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name", "")
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except Exception:
                args = {}
            _grok_audit(f"tool_call {name}")
            try:
                result = mcp_client.call_tool(name, args)
            except Exception as e:
                result = f"ERROR calling {name}: {e}"
            messages.append({"role": "tool",
                             "tool_call_id": tc.get("id"),
                             "content": str(result)[:20000]})
    return False, f"stopped after {GROK_MAX_TOOL_ROUNDS} tool rounds without a final summary"


def _run_grok_headless(prompt, timeout_sec, run_label, wait_sec=SERVER_START_WAIT_SEC, start_app=True):
    """Shared machinery for run_grok_queue_headless / run_grok_prompt_headless.
    2026-10-22: uses the RUNNING AI-Prowler (connect_to_running_ai_prowler) —
    never starts its own copy."""
    api_key = os.environ.get("XAI_API_KEY", "").strip() or (load_api_key("grok") or "")
    if not api_key:
        detail = "No Grok API key: XAI_API_KEY is not set and no key is saved (Auth section)."
        _write_last_run("failure", f"Grok {run_label}: {detail}")
        return False, detail
    ok_conn, conn = connect_to_running_ai_prowler(wait_sec=wait_sec, start_app=start_app,
                                                  config_path=RUNNING_SERVER_MCP_CONFIG_PATH)
    if not ok_conn:
        _write_last_run("failure", f"Grok {run_label}: {conn}")
        return False, conn
    rotate_audit_log()
    client = None
    try:
        try:
            client = _HttpMCPClient(_bearer_token())
            client.initialize()
            mcp_tools = client.list_tools()
        except Exception as e:
            detail = f"Could not connect to the running AI-Prowler: {e}"
            _write_last_run("failure", f"Grok {run_label}: {detail}")
            return False, detail
        cfg = load_config()
        xai_tools, web = _grok_select_tools(cfg.get("allowed_tools", ""), mcp_tools)
        # 2026-10-12: no {"type": "web_search"} here — xAI's built-in tools are
        # documented for the Responses API, not /v1/chat/completions (a 400
        # would fail every run). The Grok prompt says to use general knowledge.
        model = (cfg.get("grok_model") or GROK_MODEL).strip() or GROK_MODEL
        _grok_audit(f"run start model={model} tools={len(xai_tools)}")
        ok, detail = _grok_tool_loop(api_key, prompt, xai_tools, client, model, timeout_sec)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    _write_last_run("success" if ok else "failure", f"Grok {run_label} — {detail[:220]}")
    return ok, detail


def run_grok_queue_headless(timeout_sec=GROK_QUEUE_DEADLINE):
    """Runs the pending analysis task queue right now via the xAI API (Grok),
    headless — the Grok equivalent of the `claude -p` scheduled run. Called
    by the generated .bat when the queue's auth method is Grok; also usable
    directly. Returns (success, detail)."""
    cfg = load_config()
    prompt = GROK_QUEUE_RUNNER_PROMPT
    if cfg.get("notify_on_complete"):
        tool = "send_sms" if cfg.get("notify_method", "sms") == "sms" else "send_whatsapp"
        prompt += (f" After completing all tasks (or confirming the queue was empty), "
                   f"call AI-Prowler's {tool} tool with a one- or two-sentence summary "
                   f"of what ran and what was found. If {tool} is not configured/available, "
                   f"skip this step silently rather than treating it as a task failure.")
    return _run_grok_headless(prompt, timeout_sec, "queue run")


def run_grok_prompt_headless(prompt, timeout_sec=GROK_SINGLE_PROMPT_TIMEOUT):
    """Runs one ad-hoc prompt via the xAI API (Grok) — the Grok equivalent of
    run_single_prompt_now()'s `claude -p` call. Returns (success, detail)."""
    return _run_grok_headless(prompt, timeout_sec, "single prompt run", wait_sec=10, start_app=False)

# ── CLAUDE_CODE_OAUTH_TOKEN persistence (v8.1.6 fix) ──────────────────────
# `claude setup-token` does NOT write ~/.claude/.credentials.json — that
# file is only ever created by the interactive `claude login` flow. Per
# Claude Code's own docs, setup-token instead PRINTS a one-year OAuth
# token to the terminal and expects the caller to capture it and export
# it as CLAUDE_CODE_OAUTH_TOKEN. The old check_token_expiry() checked
# .credentials.json, so it failed unconditionally after every successful
# setup-token sign-in — not a timing issue, the two mechanisms simply
# never touch the same file. This section captures the printed token
# from a redirected-output wrapper (see build_setup_token_launch_args)
# and persists it the same way API_KEY_PATH already does, so the
# headless wrapper .bat can `set CLAUDE_CODE_OAUTH_TOKEN=` from it at
# runtime (see build_wrapper_script_content).

OAUTH_TOKEN_PATH = AI_PROWLER_HOME / "claude_oauth_token.json"
OAUTH_TOKEN_PLAIN_PATH = AI_PROWLER_HOME / "claude_oauth_token.txt"
SETUP_TOKEN_OUTPUT_PATH = AI_PROWLER_HOME / "setup_token_output.txt"
SETUP_TOKEN_BAT_PATH = AI_PROWLER_HOME / "run_setup_token.bat"
OAUTH_TOKEN_LIFETIME_DAYS = 365  # per Claude Code docs: setup-token is one-year

_OAUTH_TOKEN_PATTERN = re.compile(r"sk-ant-oat[A-Za-z0-9\-_]{10,}")


def save_oauth_token(token: str, issued_at: datetime | None = None) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    issued = issued_at or datetime.now(timezone.utc)
    clean = token.strip()
    _ss_write_text(OAUTH_TOKEN_PATH, json.dumps({     # atomic (safe_save)
        "token": clean,
        "issued_at": issued.isoformat(),
    }))
    # v8.1.6 second fix: build_wrapper_script_content() originally parsed
    # this JSON at runtime via a PowerShell one-liner invoked through
    # `for /f` + backticks — that combination of nested quoting turned
    # out to be exactly as fragile as the setup-token launch command was
    # (see build_setup_token_batch_content()'s docstring for the same
    # class of bug), and failed with "the token could not be parsed"
    # even though the JSON itself was completely valid. A plain-text
    # mirror lets the .bat just `set /p` it, identical to how
    # API_KEY_PATH already works — no external process, no quoting.
    _ss_write_text(OAUTH_TOKEN_PLAIN_PATH, clean)    # atomic (safe_save)


def load_oauth_token() -> str | None:
    if not OAUTH_TOKEN_PATH.exists():
        return None
    try:
        data = json.loads(OAUTH_TOKEN_PATH.read_text(encoding="utf-8"))
        val = (data.get("token") or "").strip()
        return val or None
    except Exception:
        return None


def has_oauth_token() -> bool:
    return load_oauth_token() is not None


def delete_oauth_token() -> None:
    if OAUTH_TOKEN_PATH.exists():
        OAUTH_TOKEN_PATH.unlink()
    if OAUTH_TOKEN_PLAIN_PATH.exists():
        OAUTH_TOKEN_PLAIN_PATH.unlink()


def try_capture_setup_token() -> bool:
    """Opportunistically parses SETUP_TOKEN_OUTPUT_PATH (written by the
    wrapper `cmd` launched from Get / Renew Token) for a printed OAuth
    token. Called from check_token_expiry() so the very next Test Setup
    (Dry Run) after sign-in picks it up automatically — no separate
    'confirm' step needed. Deletes the output file once a token is
    successfully captured, so a plaintext copy doesn't linger on disk
    longer than necessary. Returns True if a new token was captured."""
    if not SETUP_TOKEN_OUTPUT_PATH.exists():
        return False
    try:
        text = SETUP_TOKEN_OUTPUT_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    match = _OAUTH_TOKEN_PATTERN.search(text)
    if not match:
        return False
    save_oauth_token(match.group(0))
    try:
        SETUP_TOKEN_OUTPUT_PATH.unlink()
    except Exception:
        pass
    return True


# ── Claude Code CLI presence + install (for existing users who updated ──
# in-place rather than via a fresh installer run — the installer's own
# Pascal Script install step, see AI-Prowler-Setup.iss, only runs during
# an actual Setup.exe run, never during an in-app file-sync update).

def claude_code_cli_installed() -> bool:
    """Presence check — does `claude` resolve on PATH, OR does it exist at
    the well-known default install location even if PATH doesn't
    currently resolve it? Does not verify auth/token status; see
    check_token_expiry / has_api_key for that.

    v8.1.11 fix: real-world bug report — Claude Code CLI was genuinely
    installed and working (confirmed by the Setup.exe install log showing
    "[Claude Code] Already on PATH — skipping install"), but AI-Prowler's
    OWN status check reported "Not Installed" after being reopened. Root
    cause: shutil.which() only reflects the CURRENT PROCESS's inherited
    PATH environment snapshot — if AI-Prowler is relaunched via the
    AI-Prowler-AutoStart Scheduled Task (ONLOGON trigger, registered by
    the installer) shortly after Claude Code CLI's PATH entry was
    registry-written by some OTHER process, the newly-spawned AI-Prowler
    process can inherit a stale environment block from before that PATH
    update, even though the registry itself is already correct — a
    well-documented Windows environment-propagation quirk, not something
    unique to this codebase. install_claude_code_cli() already had a
    disk-fallback for exactly this class of problem, but only as part of
    its OWN post-install verification — it never helped a status check
    for a Claude Code CLI that was installed by something OTHER than
    that button (e.g. a prior separate install, as in this report). This
    same disk-fallback is now applied to the plain status check too, so
    the GUI's live indicator and Dry Run checklist are accurate even when
    PATH itself hasn't propagated to this particular process yet.
    """
    if shutil.which("claude") is not None:
        return True
    default_install_dir = Path.home() / ".local" / "bin"
    return (default_install_dir / "claude.exe").exists()


def _add_to_user_path(new_dir: Path) -> bool:
    """Persistently adds new_dir to the current user's PATH via the
    registry (HKCU\\Environment) if not already present, broadcasts
    WM_SETTINGCHANGE so other processes eventually pick it up, AND
    updates os.environ["PATH"] so THIS already-running process sees it
    immediately — otherwise AI-Prowler would report the install as
    failed until restarted, even though it just succeeded.
    Returns True if PATH was actually changed (False if already present
    or if anything went wrong — never raises)."""
    new_dir_str = str(new_dir)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                             winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                current = ""
            parts = [p for p in current.split(";") if p]
            already_present = any(p.lower() == new_dir_str.lower() for p in parts)
            if not already_present:
                parts.append(new_dir_str)
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(parts))

        # Broadcast so other already-open windows (e.g. a fresh terminal)
        # see the change without a logoff/logon — same fix already used
        # elsewhere in this codebase (AI-Prowler-Setup.iss's Tesseract
        # and Claude Code CLI install steps).
        try:
            import ctypes
            result = ctypes.c_long()
            ctypes.windll.user32.SendMessageTimeoutW(
                0xFFFF, 0x1A, 0, "Environment", 0x0002, 5000, ctypes.byref(result))
        except Exception:
            pass  # cosmetic — other windows just won't see it until restarted

        # This process's own PATH — the one shutil.which() actually reads —
        # doesn't refresh from the registry on its own. Without this, the
        # very next claude_code_cli_installed() check in THIS same
        # AI-Prowler session would still report "not found" even though
        # the registry (and every future process) now has it correctly.
        if new_dir_str.lower() not in os.environ.get("PATH", "").lower():
            os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + new_dir_str

        return not already_present
    except Exception:
        return False


# ── Audit log rotation (v9.0.0) ─────────────────────────────────────────────

def rotate_audit_log(max_backups: int = 2) -> None:
    """Rotate autonomous_run_audit.log before each Task Queue run.

    Keeps up to max_backups numbered backup files (.log.1, .log.2) so the
    active log never grows without bound while preserving recent history.
    Rotation scheme (same as Python's RotatingFileHandler):
        autonomous_run_audit.log.2  ← oldest, overwritten each rotation
        autonomous_run_audit.log.1  ← previous run
        autonomous_run_audit.log    ← current (just started) run

    Best-effort — never raises. A failure here must never prevent the
    actual queue run from starting.
    """
    try:
        base = AUDIT_LOG_PATH
        if not base.exists():
            return  # Nothing to rotate yet

        # Shift existing backups up by one (oldest is silently overwritten)
        for i in range(max_backups, 0, -1):
            src = Path(str(base) + f".{i}")
            dst = Path(str(base) + f".{i + 1}") if i < max_backups else None
            if dst is not None and src.exists():
                try:
                    src.replace(dst)
                except Exception:
                    pass

        # Rotate current log → .1
        rotated = Path(str(base) + ".1")
        try:
            base.replace(rotated)
        except Exception:
            pass
        # Start fresh (touch, so the next append has somewhere to go)
        try:
            base.write_text("", encoding="utf-8")
        except Exception:
            pass
    except Exception:
        pass


# ── Jobs directory purge (v9.0.0) ───────────────────────────────────────────

def purge_old_jobs(max_age_days: int = 2) -> int:
    """Delete job files from ~/.ai-prowler/jobs/ older than max_age_days.

    Each job produces three files: <job_id>.json (manifest), <job_id>.log
    (stdout/stderr), and <job_id>_wrapper.py (launcher). All three are removed
    together whenever the job is older than the retention window.

    Retention rule (2026-10-08 policy — David: no legitimate script run takes
    2 days; anything older than 2 days gets deleted, no exceptions):
      - Jobs older than `max_age_days` (default 2, by manifest started_at
        falling back to file mtime) are deleted.
      - A job whose manifest still says "running" gets a PID liveness check:
        PID dead/missing → treated as finished, deleted. PID alive → killed
        via taskkill /F /T (whole process tree), manifest marked "killed",
        then deleted.

    Returns the number of jobs deleted. Never raises.

    Called from run_script_start() on every new job launch AND from the MCP
    server startup path, so cleanup happens automatically.
    """
    deleted = 0
    try:
        import time as _time
        import subprocess as _sp
        jobs_dir = AI_PROWLER_HOME / "jobs"
        if not jobs_dir.exists():
            return 0
        cutoff = _time.time() - (max_age_days * 86400)
        import json as _j

        def _pid_alive_win(pid):
            """True if a process with this PID exists (Windows, no psutil)."""
            try:
                out = _sp.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=0x08000000).stdout
                return f"\"{pid}\"" in out
            except Exception:
                return False

        def _kill_tree_win(pid):
            """Kill a process and its whole tree on Windows."""
            try:
                _sp.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True, text=True, timeout=30,
                        creationflags=0x08000000)
            except Exception:
                pass

        def _delete_triplet(mani_path):
            """Delete manifest + log + wrapper. Returns True on success."""
            ok = True
            for p in (mani_path,
                      mani_path.with_suffix(".log"),
                      mani_path.with_name(mani_path.stem + "_wrapper.py")):
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    ok = False
            return ok

        for mani_path in jobs_dir.glob("job_*.json"):
            try:
                if mani_path.stat().st_mtime >= cutoff:
                    continue  # Recent enough — keep it
                # Check running status with PID liveness
                is_running = False
                pid = None
                try:
                    mani = _j.loads(mani_path.read_text(encoding="utf-8"))
                    is_running = (mani.get("status") == "running")
                    pid = mani.get("pid")
                except Exception:
                    pass  # Unreadable manifest — purge it anyway
                if is_running:
                    alive = _pid_alive_win(pid) if pid else False
                    if alive:
                        # Kill it — no legitimate run takes 2 days. Mark
                        # killed in manifest before deleting (best-effort).
                        _kill_tree_win(pid)
                        try:
                            m = _j.loads(mani_path.read_text(encoding="utf-8"))
                            m["status"] = "killed"
                            from datetime import datetime as _dtm
                            m["finished_at"] = _dtm.now().isoformat()
                            mani_path.write_text(_j.dumps(m, indent=2),
                                                 encoding="utf-8")
                        except Exception:
                            pass
                    # Dead or just killed — safe to delete
                if _delete_triplet(mani_path):
                    deleted += 1
            except Exception:
                pass

        # Second pass — orphaned wrapper scripts with no manifest left to key
        # off of. These are the backlog from the missing-wrapper-deletion bug
        # above: every run before this fix already lost its .json/.log pair
        # here, leaving the _wrapper.py behind with nothing to pair it to.
        # Aged off by the wrapper file's own mtime instead, since there's no
        # manifest left to read a status from — a wrapper script itself is
        # never "running" (the launched process runs independently of it;
        # the wrapper's job is done the moment it starts that process), so
        # there's no in-progress state to protect here the way the manifest
        # loop above protects a running job.
        for wrapper_path in jobs_dir.glob("*_wrapper.py"):
            try:
                if wrapper_path.stat().st_mtime >= cutoff:
                    continue  # Recent enough — keep it
                mani_path = wrapper_path.with_name(
                    wrapper_path.name[: -len("_wrapper.py")] + ".json"
                )
                if mani_path.exists():
                    continue  # Has a manifest — handled by the loop above
                wrapper_path.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass
    return deleted


def run_queue_now(mcp_config_path: str, allowed_tools: str,
                  use_api_key: bool = False,
                  notify_on_complete: bool = False,
                  notify_method: str = "sms",
                  timeout: int = 600,
                  api_key_provider: str = "anthropic") -> tuple[bool, str]:
    # 2026-10-12: api_key_provider is LAST (keyword) so existing positional
    # callers keep their notify_on_complete / notify_method / timeout meaning.
    """Runs the task queue right now via a real headless Claude Code
    session — the exact same command the Scheduled Task runs, just
    triggered immediately instead of waiting for the clock. This is
    what "Run Due Tasks" / "Run Pending Analysis" call instead of the
    old copy-into-a-new-chat flow, once Claude Code CLI is installed.

    Blocking — a real analysis run can take anywhere from seconds to
    several minutes. Callers MUST invoke this from a background thread,
    never directly on the Tk main thread, or the whole GUI will freeze
    for the duration of the run.

    Reuses build_wrapper_script_content() / install_wrapper_script() so
    the exact command that runs here is identical to what the Scheduled
    Task uses — no behavior drift between "run now" and "run on
    schedule." Written to a separate manual_run/ subfolder rather than
    the Scheduled Task's own wrapper location, so a manual run never
    collides with (or overwrites mid-execution) the scheduled one.

    v8.1.14: no longer accepts/forwards install_dir — see
    build_wrapper_script_content()'s docstring. (This function previously
    had a real bug here: it never accepted or forwarded install_dir at
    all, even after install_wrapper_script() gained support for it, so
    every "Run Due Tasks Now" click silently used the old %USERPROFILE%
    fallback regardless of what the Scheduled Task itself was correctly
    configured with. Removing the parameter from the whole call chain
    fixes this by construction — there's nothing left to have forgotten.)

    Returns (success, detail) — detail is either the tail of the
    session's real output (truncated to keep dialog boxes reasonable)
    or a plain-language reason it never ran."""
    _provider_now = _normalize_provider(api_key_provider) if use_api_key else "oauth"
    if _provider_now != "grok" and not claude_code_cli_installed():
        return False, ("Claude Code CLI is not installed. Install it from "
                        "the \U0001F916 Autonomous AI Task Queue panel above, then try again.")
    if not mcp_config_path:
        return False, ("No MCP config is set up yet. Click 'Generate MCP "
                        "Config' in the 🤖 Autonomous AI Task Queue panel above, "
                        "then try again.")

    # v9.0.0: rotate the audit log before each queue run so it never grows
    # without bound. Best-effort — never prevents the run.
    rotate_audit_log()

    wrapper_dir = AI_PROWLER_HOME / "manual_run"
    wrapper_path = install_wrapper_script(
        wrapper_dir, mcp_config_path, allowed_tools,
        notify_on_complete, notify_method, use_api_key,
        api_key_provider=api_key_provider)

    try:
        r = subprocess.run([str(wrapper_path)], capture_output=True,
                            text=True, timeout=timeout, shell=True)
    except subprocess.TimeoutExpired:
        _write_last_run("failure", f"Manual run timed out after {timeout}s")
        return False, f"Run timed out after {timeout}s — check your internet connection."
    except Exception as e:
        _write_last_run("failure", f"Manual run error: {e}")
        return False, str(e)

    ok = (r.returncode == 0)
    _write_last_run("success" if ok else "failure",
                     f"Manual run — exit code {r.returncode}")
    output = ((r.stdout or "") + (r.stderr or "")).strip()
    if output:
        return ok, output[-4000:]
    return ok, ("Run completed." if ok else f"Run failed (exit code {r.returncode}), no output captured.")


def _sanitize_prompt_for_batch(prompt: str) -> str:
    """Makes an arbitrary prompt string safe to embed as a single quoted
    argument on ONE line of a generated .bat file.

    v8.1.15 fix: custom_tasks_manager.py's build_task_prompt() joins its
    output with embedded newlines -- entirely correct for its own purpose
    (multi-line display in the GUI's task editor), but fatal once that
    text gets embedded in a .bat file's single-line `claude -p "..."`
    invocation. cmd.exe parses .bat files line-by-line BEFORE any
    quote-aware parsing happens, so a literal newline unconditionally
    ends the current command regardless of quoting -- everything after it
    gets executed as a completely separate command. Confirmed live
    (2026-07-29, David): a custom task's "▶ NOW" run failed with cmd.exe
    reporting `'Output:' is not recognized as an internal or external
    command` -- "Output:" is literally the start of build_task_prompt()'s
    own action-summary line, which had simply become its own broken
    command once the newline before it split the .bat file's execution.

    Unlike QUEUE_RUNNER_PROMPT (a static, hand-verified single-line
    constant covered by test_wrapper_prompt_has_no_batch_unsafe_characters
    in the test suite), prompts reaching this function are effectively
    arbitrary text -- built-in task prompts, and now custom task prompts
    -- and can't be guaranteed batch-safe by construction. This sanitizes
    at the one point they all funnel through before hitting a .bat file,
    rather than requiring every prompt-producing function upstream to
    independently know about this downstream transport quirk.

    v8.1.16 follow-up: also normalizes common "smart" typographic
    characters (em/en dash, curly quotes, ellipsis) to plain ASCII.
    Discovered live testing this fix: custom_tasks_manager.py's own
    generated action-summary text uses a real em-dash ("email the full
    analysis via send_email() -- leave 'to' blank..."), and a .bat file
    written without a UTF-8 BOM gets read by cmd.exe under the legacy OEM
    codepage (e.g. cp437) by default -- silently corrupting every
    non-ASCII byte in the file, INCLUDING inside the quoted claude -p
    "..." argument, not just in REM comments. The real, complete fix is
    the UTF-8 BOM now added where these .bat files get written (see
    install_wrapper_script() / run_single_prompt_now()) -- Windows 10
    1903+ auto-detects it and switches the whole file to codepage 65001.
    This ASCII normalization is defense-in-depth on top of that, not a
    substitute for it: it only covers a handful of common punctuation
    substitutions, not arbitrary Unicode (accented names, emoji, non-Latin
    scripts, etc., still depend entirely on the BOM fix being in place).
    - Newlines become spaces: the prompt is instructions for Claude to
      read, not something whose exact line breaks carry meaning.
    - A literal '%' is doubled to '%%', cmd.exe's own escape for a
      literal percent -- otherwise a bare % still triggers environment-
      variable expansion attempts even inside a quoted argument (the same
      root mechanism already documented at length elsewhere in this file
      for the %a/%%a self-gate escaping bugs).
    Double-quote escaping is handled separately by the caller (doubling,
    for the outer -p "..." argument), so this function leaves " alone.
    """
    sanitized = prompt.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
    sanitized = sanitized.replace('%', '%%')
    # Typographic punctuation -> ASCII equivalents (defense-in-depth; see
    # docstring above -- the UTF-8 BOM on the .bat file is the real fix).
    _typographic_map = {
        '\u2014': ' - ',   # em dash —
        '\u2013': '-',     # en dash –
        '\u2018': "'",     # left single quote '
        '\u2019': "'",     # right single quote '
        '\u201c': '"',     # left double quote "
        '\u201d': '"',     # right double quote "
        '\u2026': '...',   # ellipsis …
    }
    for char, replacement in _typographic_map.items():
        sanitized = sanitized.replace(char, replacement)
    return sanitized


def build_single_prompt_wrapper_content(prompt: str, mcp_config_path: str,
                                         allowed_tools: str,
                                        use_api_key: bool = False,
                                        api_key_provider: str = "anthropic"):
    """v8.1.6: like build_wrapper_script_content() but for an arbitrary
    one-off PROMPT instead of the fixed queue-processing slash command —
    backs the "▶ NOW" button on each Common Business AI Analysis item, so
    a user can try one immediately without queuing it (no pending_tasks.json
    entry at all — this never touches the queue).

    Kept as a separate function rather than adding an optional prompt
    parameter to build_wrapper_script_content(): the two wrappers do
    genuinely different jobs (process the existing queue vs. run one
    ad-hoc prompt right now) even though the auth-block plumbing is
    identical — see that function's docstring for why each auth path
    reads its credential from a file at runtime rather than embedding it.
    Double-quotes in the prompt are escaped for the batch string.

    v8.1.14: cd's into AI_PROWLER_HOME unconditionally now, no install_dir
    parameter — same fix, same rationale, as build_wrapper_script_content();
    see that function's docstring for the full history. This function
    previously took its OWN install_dir parameter (a v8.1.14-at-the-time
    fix for a hardcoded %USERPROFILE% cd that broke the audit-log hook —
    confirmed live 2026-07-28), which then had to be threaded through
    run_single_prompt_now() and every GUI call site individually. Now
    there's simply nothing to thread through — one fewer parameter, one
    fewer place for a caller to forget it (this is exactly the class of
    bug run_queue_now() had, found the same session).
    """
    escaped_prompt = _sanitize_prompt_for_batch(prompt).replace('"', '""')
    api_key_block = ""
    _invoke_block = ""
    # 2026-10-12: Grok has no Claude-Code-style CLI — its branch exports
    # XAI_API_KEY and invokes the in-module Grok runner on the ad-hoc prompt
    # (base64-encoded at generation time so batch quoting can't corrupt it).
    _provider = _normalize_provider(api_key_provider)
    if use_api_key and _provider == "grok":
        _grok_path = api_key_path("grok")
        api_key_block = f"""REM Use XAI_API_KEY (Grok) — see build_wrapper_script_content()'s
REM docstring for why this reads from a file at runtime.
if exist "{_grok_path}" (
    set /p XAI_API_KEY=<"{_grok_path}"
) else (
    echo [ERROR] Grok API key auth is selected but {_grok_path} was not found.
    exit /b 1
)

"""
        import base64 as _b64mod
        _b64 = _b64mod.b64encode(prompt.encode("utf-8")).decode("ascii")
        _tqa_parent = str(LOCAL_MCP_SCRIPT_PATH.parent)
        # _self_gate_python_invocation() — NOT a naively-quoted path (v8.1.13).
        _invoke_block = (
            f'{_self_gate_python_invocation()} -c "import sys,base64; '
            f"sys.path.insert(0,r'{_tqa_parent}'); "
            "import task_queue_automation as _tqa; "
            f"_tqa.run_grok_prompt_headless(base64.b64decode('{_b64}').decode('utf-8'))\" "
            '> "%USERPROFILE%\\.ai-prowler\\last_single_run.json" 2>&1'
        )
    elif use_api_key:
        api_key_block = f"""REM Use ANTHROPIC_API_KEY — see build_wrapper_script_content()'s
REM docstring for why this reads from a file at runtime.
if exist "{API_KEY_PATH}" (
    set /p ANTHROPIC_API_KEY=<"{API_KEY_PATH}"
) else (
    echo [ERROR] use_api_key is enabled but {API_KEY_PATH} was not found.
    exit /b 1
)

"""
        _invoke_block = (
            f'claude -p "{escaped_prompt}" ^\n'
            f'  --mcp-config "{mcp_config_path}" ^\n'
            '  --strict-mcp-config ^\n'
            f'  --allowedTools "{allowed_tools}" ^\n'
            '  --output-format json ^\n'
            '  --permission-mode bypassPermissions > "%USERPROFILE%\\.ai-prowler\\last_single_run.json" 2>&1'
        )
    else:
        api_key_block = f"""REM Use the Claude Code OAuth token — see build_wrapper_script_content()'s
REM docstring for why this reads from a file at runtime.
if exist "{OAUTH_TOKEN_PLAIN_PATH}" (
    set /p CLAUDE_CODE_OAUTH_TOKEN=<"{OAUTH_TOKEN_PLAIN_PATH}"
) else (
    echo [ERROR] No Claude Code OAuth token found — click Get / Renew Token in AI-Prowler first.
    exit /b 1
)

"""
        _invoke_block = (
            f'claude -p "{escaped_prompt}" ^\n'
            # 2026-10-22: these two were missing the f prefix, so the .bat got
            # the literal text {mcp_config_path} / {allowed_tools}.
            f'  --mcp-config "{mcp_config_path}" ^\n'
            '  --strict-mcp-config ^\n'
            f'  --allowedTools "{allowed_tools}" ^\n'
            '  --output-format json ^\n'
            '  --permission-mode bypassPermissions > "%USERPROFILE%\\.ai-prowler\\last_single_run.json" 2>&1'
        )
    return rf"""@echo off
chcp 65001 >nul
REM v8.1.16 fix: see build_wrapper_script_content()'s matching comment for
REM the full discovery story (UTF-8 BOM tried first, reverted -- broke
REM this invocation path outright). chcp as an explicit command has no
REM such invocation-path dependency.
REM Auto-generated by task_queue_automation.py — do not edit by hand.
REM Runs a single ad-hoc analysis prompt right now (the "▶ NOW" button) —
REM never touches pending_tasks.json, unlike the scheduled queue wrapper.

REM v8.1.14: cd into AI_PROWLER_HOME — see build_wrapper_script_content()'s
REM docstring for the full rationale (in short: this is where
REM .claude/hooks/log_tool_call.py's audit-log hook and
REM .claude/skills/ai-prowler-tasks/SKILL.md now live, and it's fully
REM non-elevated/writable unlike the code install directory this used to
REM point at).
cd /d "{AI_PROWLER_HOME}"

REM v8.1.17: same append-only command debug log as the scheduled wrapper —
REM see build_wrapper_script_content()'s matching comment for the full
REM rationale.
echo. >> "%USERPROFILE%\.ai-prowler\command_debug.log"
echo ================================================================ >> "%USERPROFILE%\.ai-prowler\command_debug.log"
echo [%date% %time%] SINGLE PROMPT RUN (NOW button) -- full script below: >> "%USERPROFILE%\.ai-prowler\command_debug.log"
type "%~f0" >> "%USERPROFILE%\.ai-prowler\command_debug.log"

{api_key_block}{_invoke_block}

set RC=%ERRORLEVEL%
exit /b %RC%
"""


def run_single_prompt_now(prompt: str, mcp_config_path: str, allowed_tools: str,
                             use_api_key: bool = False,
                             api_key_provider: str = "anthropic",
                           timeout: int = 600) -> tuple[bool, str]:
    """v8.1.6: runs ONE ad-hoc prompt right now via a real headless Claude
    Code session — backs the "▶ NOW" button on each analysis item.

    v8.1.18: always calls generate_mcp_config_for_now_button() to get a
    config that points at the already-running localhost:8000 HTTP MCP server
    instead of spawning a SECOND stdio MCP server process alongside the one
    the GUI already has running. Confirmed live (2026-07-29): the duplicate
    stdio process causes severe ChromaDB contention — runs that normally
    complete in ~2 minutes would hang for 10+ minutes. The caller-supplied
    mcp_config_path is now ignored (kept for API compatibility only).

    Returns (success, detail)."""
    _provider_1p = _normalize_provider(api_key_provider) if use_api_key else "oauth"
    if _provider_1p != "grok" and not claude_code_cli_installed():
        return False, ("Claude Code CLI is not installed. Install it from "
                        "the \U0001F916 Autonomous AI Task Queue panel above, then try again.")

    # v8.1.18: prefer localhost HTTP over stdio for the NOW button.
    ok_now, now_mcp_path = generate_mcp_config_for_now_button()
    if not ok_now:
        return False, f"Could not set up MCP config for ▶ NOW run: {now_mcp_path}"

    wrapper_dir = AI_PROWLER_HOME / "single_run"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    script_path = wrapper_dir / "run_single_now.bat"
    bat_content = build_single_prompt_wrapper_content(prompt, now_mcp_path, allowed_tools,
                                                     use_api_key,
                                                     api_key_provider=api_key_provider)
    script_path.write_text(bat_content, encoding="utf-8")

    # NOW-button debug log removed — run-now feature defeatured in v9.1.0
    import datetime as _dt

    def _dbg(msg: str):
        pass  # debug logging removed

    _ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _dbg(f"\n{'='*70}")
    _dbg(f"[{_ts}] ▶ NOW run started")
    _dbg(f"  MCP config path : {now_mcp_path}")
    _dbg(f"  allowed_tools   : {allowed_tools}")
    _dbg(f"  use_api_key     : {use_api_key}")
    _dbg(f"  timeout         : {timeout}s")
    try:
        _dbg(f"  MCP config contents:\n{Path(now_mcp_path).read_text(encoding='utf-8')}")
    except Exception as _e:
        _dbg(f"  (could not read MCP config: {_e})")
    _dbg(f"\n  .bat script path: {script_path}")
    _dbg(f"  .bat contents:\n{bat_content}")

    try:
        r = subprocess.run([str(script_path)], capture_output=True,
                            text=True, timeout=timeout, shell=True)
    except subprocess.TimeoutExpired:
        _dbg(f"[{_dt.datetime.now().strftime('%H:%M:%S')}] TIMED OUT after {timeout}s")
        # Read whatever last_single_run.json has at timeout time
        _out_file = AI_PROWLER_HOME / "last_single_run.json"
        if _out_file.exists() and _out_file.stat().st_size > 0:
            _dbg(f"  last_single_run.json ({_out_file.stat().st_size} bytes):\n"
                  f"{_out_file.read_text(encoding='utf-8', errors='replace')[-3000:]}")
        else:
            _dbg(f"  last_single_run.json: empty or missing (claude -p never wrote output)")
        return False, f"Run timed out after {timeout}s"
    except Exception as e:
        _dbg(f"[{_dt.datetime.now().strftime('%H:%M:%S')}] EXCEPTION: {e}")
        return False, str(e)

    _dbg(f"[{_dt.datetime.now().strftime('%H:%M:%S')}] .bat exited — rc={r.returncode}")
    _dbg(f"  stdout: {r.stdout!r}")
    _dbg(f"  stderr: {r.stderr!r}")
    _out_file = AI_PROWLER_HOME / "last_single_run.json"
    if _out_file.exists() and _out_file.stat().st_size > 0:
        _dbg(f"  last_single_run.json ({_out_file.stat().st_size} bytes):\n"
              f"{_out_file.read_text(encoding='utf-8', errors='replace')[-3000:]}")
    else:
        _dbg(f"  last_single_run.json: empty or missing")

    ok = (r.returncode == 0)
    output = ((r.stdout or "") + (r.stderr or "")).strip()
    if output:
        return ok, output[-4000:]
    return ok, ("Run completed." if ok else f"Run failed (exit code {r.returncode}), no output captured.")


def install_claude_code_cli() -> tuple[bool, str]:
    """Runs Anthropic's official native installer — the same
    dependency-free command AI-Prowler-Setup.iss runs silently during a
    fresh install (no Node.js/npm required). This is the GUI-triggered
    equivalent for existing users who updated in-place and never got it.
    Blocking (the user clicked a button and is watching a status line;
    unlike open_setup_token_terminal, no interactive browser step is
    needed here, so waiting for completion is fine — typically a few
    seconds). Returns (success, detail)."""
    # Fast path: PATH is fine — nothing to do.
    if shutil.which("claude") is not None:
        return True, "Already installed."
    # Slow path: claude.exe is on disk but not on PATH (Anthropic's installer
    # sometimes skips the PATH update on certain Windows configurations).
    # _add_to_user_path() was already written for exactly this case but was
    # previously only reachable after a fresh install — not when the user
    # clicked the button on a machine where claude.exe already existed on disk
    # but PATH was broken, because the old guard used claude_code_cli_installed()
    # which returns True via the disk fallback and bailed out immediately.
    default_install_dir = Path.home() / ".local" / "bin"
    if (default_install_dir / "claude.exe").exists():
        _add_to_user_path(default_install_dir)
        if claude_code_cli_installed():
            return True, ("Claude Code CLI was installed but missing from PATH — "
                          "registered successfully. Scheduled tasks will now find it.")
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             "[Net.ServicePointManager]::SecurityProtocol = "
             "[Net.SecurityProtocolType]::Tls12; irm https://claude.ai/install.ps1 | iex"],
            capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return False, "Install timed out after 120s — check your internet connection."
    except Exception as e:
        return False, str(e)

    # Same philosophy as the installer: re-check that `claude` actually
    # resolves rather than trusting the subprocess return code alone.
    #
    # Real-world finding: the native installer writes to
    # %USERPROFILE%\.local\bin but does NOT reliably add that folder to
    # PATH itself — on some systems it just prints a manual instruction
    # ("Add it by opening System Properties...") and leaves it there.
    # Confirmed live: the install succeeds every time, but without this
    # fallback, AI-Prowler would report "failed" forever afterward
    # because it only checks PATH, and PATH was never actually updated.
    #
    # v8.1.11: checks shutil.which() directly here, NOT
    # claude_code_cli_installed() — that function now also checks the
    # disk fallback location itself, which would make THIS guard always
    # see "already usable" once claude.exe exists on disk, even before
    # PATH has actually been persistently registered. That would silently
    # skip the one-time PATH registration below on every future call,
    # leaving PATH broken for any OTHER process (a fresh terminal, a
    # scheduled task) that doesn't get the disk-fallback's benefit.
    if shutil.which("claude") is None:
        default_install_dir = Path.home() / ".local" / "bin"
        if (default_install_dir / "claude.exe").exists():
            _add_to_user_path(default_install_dir)

    if claude_code_cli_installed():
        return True, "Installed successfully."
    detail = (r.stderr or r.stdout or "").strip()[:300]
    return False, f"Install did not complete — claude still not found on PATH. {detail}"


CLAUDE_CREDENTIALS_PATH = Path.home() / ".claude" / ".credentials.json"


def check_token_expiry() -> dict:
    """Checks CLAUDE_CODE_OAUTH_TOKEN status (see OAUTH_TOKEN_PATH above).

    v8.1.6 fix: this used to read ~/.claude/.credentials.json, which is
    only ever written by the interactive `claude login` flow. The
    Get / Renew Token button runs `claude setup-token`, which per Claude
    Code's own docs prints a one-year token to the terminal and does NOT
    save it anywhere — so the old check failed unconditionally, every
    time, regardless of whether sign-in actually succeeded. This now
    checks the token AI-Prowler itself captured and persisted to
    OAUTH_TOKEN_PATH (see try_capture_setup_token()).

    Does NOT guarantee the token is actually still valid — a token can
    be revoked server-side before its stated one-year expiry. This is a
    best-effort early warning, not a guarantee; the reactive 401 check
    in a real run is the authoritative signal.
    Returns dict: {status, expires_at, days_remaining, detail}
    status is one of: "no_credentials", "unreadable", "expired",
    "expiring_soon" (<7 days), "ok"
    """
    # Pick up a token that just appeared from a completed setup-token
    # sign-in, if any, before checking status.
    try_capture_setup_token()

    if not OAUTH_TOKEN_PATH.exists():
        return {"status": "no_credentials", "expires_at": None,
                "days_remaining": None,
                "detail": "No Claude Code token yet — click 🔑 Get / Renew Token, "
                          "complete the browser sign-in, then come back and click "
                          "Test Setup (Dry Run) again."}
    try:
        data = json.loads(OAUTH_TOKEN_PATH.read_text(encoding="utf-8"))
        if not data.get("token"):
            return {"status": "unreadable", "expires_at": None,
                     "days_remaining": None,
                     "detail": "claude_oauth_token.json found but has no token field."}
        # v8.1.6 third fix / self-heal: OAUTH_TOKEN_PLAIN_PATH was added
        # AFTER OAUTH_TOKEN_PATH already existed for anyone who signed in
        # before this fix — save_oauth_token() only started writing the
        # plain-text mirror going forward, so an already-saved (still
        # perfectly valid, still not expired) token would otherwise leave
        # the wrapper script's `set /p` with nothing to read from, even
        # though check_token_expiry() itself reports everything is fine.
        # Backfilling here, on every dry-run/status check, means an
        # already-signed-in user never needs to redo the browser OAuth
        # flow just because of an internal storage-format change.
        if not OAUTH_TOKEN_PLAIN_PATH.exists():
            try:
                _ss_write_text(OAUTH_TOKEN_PLAIN_PATH, data["token"].strip())  # atomic (safe_save)
            except Exception:
                pass  # best-effort; wrapper script will surface a clear error if this failed
        issued_dt = datetime.fromisoformat(data["issued_at"])
        expires_dt = issued_dt + timedelta(days=OAUTH_TOKEN_LIFETIME_DAYS)
        remaining = expires_dt - datetime.now(timezone.utc)
        days_remaining = remaining.total_seconds() / 86400
        if days_remaining <= 0:
            status = "expired"
        elif days_remaining <= 7:
            status = "expiring_soon"
        else:
            status = "ok"
        return {
            "status": status,
            "expires_at": expires_dt.isoformat(),
            "days_remaining": round(days_remaining, 1),
            "detail": f"{'Expired' if status == 'expired' else 'Expires'} "
                      f"{expires_dt.strftime('%Y-%m-%d %H:%M UTC')} "
                      f"({days_remaining:+.1f} days)",
        }
    except Exception as e:
        return {"status": "unreadable", "expires_at": None,
                 "days_remaining": None, "detail": f"Could not read saved token: {e}"}


def build_setup_token_batch_content() -> str:
    """Returns the .bat file content used to run `claude setup-token` and
    capture its output. Kept as a pure function for testability, same
    reasoning as build_setup_token_launch_args() below.

    v8.1.6 second fix: the FIRST v8.1.6 fix (teeing output via a single
    `cmd /k "claude setup-token > "...\\file" 2>&1 & type "...\\file""`
    command-line string) is itself broken — Windows' list2cmdline()
    quoting and cmd.exe's own command-line parser disagree about nested
    quotes, and the combination reliably produces "The filename,
    directory name, or volume label syntax is incorrect." This is a
    well-known cmd.exe /k quoting failure mode, not something that can
    be escaped around reliably. The fix is to never hand cmd.exe a
    complex quoted command line at all: write the real commands to an
    actual .bat file (plain text, no shell-quoting ambiguity) and launch
    THAT with a single, simple, one-level-quoted path.
    """
    return (
        "@echo off\r\n"
        f'claude setup-token > "{SETUP_TOKEN_OUTPUT_PATH}" 2>&1\r\n'
        f'type "{SETUP_TOKEN_OUTPUT_PATH}"\r\n'
        "echo.\r\n"
        "echo Press any key to close this window...\r\n"
        "pause >nul\r\n"
    )


def build_setup_token_launch_args() -> list[str]:
    """Returns the argv for launching an interactive terminal that runs
    SETUP_TOKEN_BAT_PATH (see build_setup_token_batch_content). Kept as a
    pure function (no subprocess.Popen call) so the command construction
    is independently testable without actually spawning a window during
    tests. `cmd /c` is sufficient — the .bat itself ends with `pause` so
    the window stays open on its own; no need for `/k` here.
    """
    return ["cmd", "/c", str(SETUP_TOKEN_BAT_PATH)]


def open_setup_token_terminal() -> tuple[bool, str]:
    """Actually launches the terminal. This is the one function in this
    module that opens a visible window — everything else is silent/
    background. Requires a human to complete the browser OAuth step that
    follows; this function only gets them to that point."""
    try:
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        # Clear any stale output from a previous incomplete attempt so
        # try_capture_setup_token() never picks up an old/partial file.
        if SETUP_TOKEN_OUTPUT_PATH.exists():
            SETUP_TOKEN_OUTPUT_PATH.unlink()
        SETUP_TOKEN_BAT_PATH.write_text(build_setup_token_batch_content(), encoding="utf-8")
        subprocess.Popen(build_setup_token_launch_args(),
                          creationflags=subprocess.CREATE_NEW_CONSOLE)
        return True, "Terminal opened — complete the browser sign-in it prompts for."
    except Exception as e:
        return False, str(e)




def compute_next_checker_run(schedule_time: str, schedule_end_time: str,
                              times_per_day: int,
                              now: datetime | None = None) -> datetime:
    """v9.0.1: compute the checker's true next-run datetime PURELY LOCALLY,
    from its own Start time / End time / Times per day config and the real
    current date/time — no schtasks query, no subprocess call, no I/O at
    all. Safe (and cheap enough) to call as often as needed.

    This works because we already know exactly which HH:MM times get
    registered as Windows Daily triggers — the identical
    custom_tasks_manager.compute_daily_run_times() call
    _build_register_queue_task_ps1() uses to build those triggers in the
    first place. Given that same list of times, "what's the next
    occurrence from right now" is a pure calendar calculation: walk
    forward through today's remaining slots, and if none are left, take
    the first slot tomorrow.

    Found live: David set Start=08:30 (once/day), the checker fired
    successfully at 8:30 AM, and the "Armed" line kept showing "next: 8/7"
    instead of advancing to 8/8. Windows itself DID correctly advance its
    own internal state — that's exactly what a plain Daily trigger always
    does — but get_scheduled_task_display_info() (which reported that
    state) is only ever called on explicit GUI actions (Apply, Toggle,
    etc.), never on a timer, so the displayed text was simply stale. This
    function replaces the schtasks-sourced value entirely for display
    purposes, and because it's pure computation (not a subprocess call),
    it can safely be recomputed on a lightweight GUI timer without the
    risk profile that got an earlier schtasks-query-based periodic
    refresh removed (see rag_gui.py's _tqa_refresh_status_display()
    history for that incident — this doesn't reintroduce it).

    now defaults to datetime.now() — overridable for tests.
    """
    now = now or datetime.now()
    n = max(1, int(times_per_day))
    import custom_tasks_manager as _ctm_next
    run_times = _ctm_next.compute_daily_run_times(
        schedule_time, schedule_end_time, n)

    today = now.date()
    for t in run_times:
        hh, mm = (int(p) for p in t.split(":"))
        candidate = datetime(today.year, today.month, today.day, hh, mm)
        if candidate > now:
            return candidate

    # Every slot today has already passed — first slot tomorrow.
    tomorrow = today + timedelta(days=1)
    hh, mm = (int(p) for p in run_times[0].split(":"))
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day, hh, mm)


def get_scheduled_task_display_info() -> dict:
    """v8.1.11: real, OS-level truth about the actual armed Windows
    Scheduled Task — not what the GUI's config file says should be true,
    but what schtasks itself reports right now. Built specifically so the
    Autonomous AI Task Queue panel can show David what's actually armed
    rather than just echoing back the text field he typed into, and so
    Toggle Off can be visually confirmed as genuinely having disarmed the
    real task, not just flipped a local config flag.

    v9.0.1: the human-readable "cadence" half of `display` (e.g. "Daily at
    07:00" or "3x/day (07:00, 15:00, 23:00)") is now computed from OUR OWN
    saved config via load_config() + compute_daily_run_times(), not from
    schtasks's Schedule Type / Start Time / Repeat fields. Those fields
    can't cleanly describe the new multi-trigger design (N times/day now
    registers as several independent -Daily triggers; schtasks's simple
    `/v /fo list` query reports something unhelpful like "Schedule Type:
    Multiple Triggers" for a task like that, with no per-trigger
    breakdown). `next_run_time` below is UNCHANGED — still read straight
    from schtasks, still genuine OS truth: Windows itself correctly
    computes the true soonest occurrence across however many triggers are
    registered, regardless of how unhelpfully schtasks describes the
    schedule type in English. schedule_type/start_time/repeat_every are
    still parsed and returned in the info dict below (unchanged) for
    anyone who wants the raw schtasks fields directly — only `display`
    itself stopped depending on them for the cadence description.

    Returns a dict:
        exists:   bool
        enabled:  bool | None (None if it doesn't exist)
        schedule_type: str | None  ("Daily", "Multiple Triggers", etc. as
                       schtasks itself reports it — informational only,
                       no longer used to build `display`)
        start_time: str | None    ("Start Time" field, HH:MM:SS as
                       schtasks reports it — informational only)
        repeat_every: str | None  ("Repeat: Every" field, when present —
                       informational only; the new multi-trigger design
                       never sets this, it's legacy/only relevant to a
                       pre-v9.0.1 task that hasn't been re-Applied yet)
        next_run_time: str | None ("Next Run Time" field — still genuine
                       OS truth, used in `display`)
        display: str               a single human-readable summary line,
                       ready to drop straight into the GUI, e.g.
                       "🟢 Armed — Daily at 07:00 (next: 7/27/2026 6:00 AM)"
                       or "🔴 Not armed" if disabled/missing.
    """
    info = {
        "exists": False, "enabled": None, "schedule_type": None,
        "start_time": None, "repeat_every": None, "next_run_time": None,
        "display": "🔴 Not armed",
    }
    r = subprocess.run(
        ["schtasks", "/query", "/tn", SCHEDULED_TASK_NAME, "/v", "/fo", "list"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode != 0:

        return info

    info["exists"] = True
    field_map = {
        "scheduled task state": "enabled",
        "schedule type": "schedule_type",
        "start time": "start_time",
        "next run time": "next_run_time",
    }
    for raw_line in r.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # "Repeat: Every:" is a genuine schtasks.exe output quirk — the
        # field NAME itself contains a colon, so a naive single-split on
        # ":" would incorrectly parse "Repeat" as the key and "Every:  2
        # Hour(s)..." as the value. Handle this one field explicitly.
        if line.lower().startswith("repeat: every:"):
            value = line.split(":", 2)[2].strip()
            if value:
                info["repeat_every"] = value
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key not in field_map or not value:
            continue
        dest = field_map[key]
        if dest == "enabled":
            info["enabled"] = (value.lower() == "enabled")
        else:
            info[dest] = value

    if not info["enabled"]:
        info["display"] = "🔴 Not armed" + (" (disabled)" if info["enabled"] is False else "")
        return info

    cfg = load_config()
    n = max(1, int(cfg.get("check_times_per_day", 1) or 1))
    start = cfg.get("schedule_time", "06:00")
    end = cfg.get("schedule_end_time", "23:00")
    if n <= 1:
        cadence = f"Daily at {start}"
    else:
        try:
            import custom_tasks_manager as _ctm_disp
            run_times = _ctm_disp.compute_daily_run_times(start, end, n)
            cadence = f"{n}x/day ({', '.join(run_times)})"
        except Exception:
            # Malformed start/end in the saved config (shouldn't happen —
            # the GUI validates before saving) — fall back to something
            # still informative rather than a blank cadence.
            cadence = f"{n}x/day ({start}-{end})"

    # v9.0.1: "next:" now comes from compute_next_checker_run() — a pure
    # local calculation from our own config + the real current time — not
    # from schtasks's own Next Run Time field. Windows' own state is
    # correct (a plain Daily trigger always advances itself right after
    # firing); the problem was this whole function only ever being called
    # on explicit GUI actions, so the OLD schtasks-sourced value could sit
    # stale for a full day after a run. See compute_next_checker_run()'s
    # docstring for the full incident. Falls back to the schtasks-reported
    # value only if our own computation fails outright (malformed config).
    # No seconds in the format — every trigger we register is HH:MM only,
    # so seconds are always :00 and would just be noise.
    try:
        next_dt = compute_next_checker_run(start, end, n)
        info["next_run_time_computed"] = next_dt.isoformat()
        next_run = f" (next: {next_dt.strftime('%#m/%#d/%Y %#I:%M %p')})"
    except Exception:
        next_run = f" (next: {info['next_run_time']})" if info["next_run_time"] else ""

    info["display"] = f"🟢 Armed — {cadence}{next_run}"
    return info


# ── v8.1.11: "Log on as a batch job" right (SeBatchLogonRight) ─────────────
# Real-world root cause finding: schtasks /RU <username> (without /RP) is
# SUPPOSED to produce an S4U logon type ("Run whether user is logged on or
# not") — but this silently degrades to Interactive-only if the account
# doesn't already hold SeBatchLogonRight. Standard Windows accounts don't
# have this right by default, and schtasks gives no error when it's
# missing — it just quietly creates a weaker task than requested, which is
# exactly what caused the QueueRunner task to fail during a full logoff
# despite the /RU fix being correctly applied in code. Confirmed live via
# `whoami /priv | findstr batch` returning nothing for the affected account.

_GRANT_BATCH_LOGON_MARKER = "AI_PROWLER_GRANT_RESULT:"


def _build_grant_batch_logon_ps1(username: str, result_file: str) -> str:
    """Returns a PowerShell script that grants SeBatchLogonRight to
    `username` via the documented Win32 LSA policy API (LsaAddAccountRights)
    — the standard, tool-free way to script this; no ntrights.exe or
    third-party utility needed. Writes a one-line result to result_file
    so the (elevated, detached) process's outcome can be observed by the
    calling (non-elevated) Python process afterward."""
    return f"""$ErrorActionPreference = 'Stop'
try {{
    Add-Type @'
using System;
using System.Runtime.InteropServices;

public class AiProwlerLsa {{
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING {{
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }}

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES {{
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }}

    [DllImport("advapi32.dll", PreserveSig = true)]
    private static extern uint LsaOpenPolicy(ref LSA_UNICODE_STRING SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, int AccessMask, out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint LsaAddAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, LSA_UNICODE_STRING[] UserRights, int CountOfRights);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr ObjectHandle);

    public static void AddPrivilege(string accountName, string privilege) {{
        var sid = (System.Security.Principal.SecurityIdentifier)
            new System.Security.Principal.NTAccount(accountName)
                .Translate(typeof(System.Security.Principal.SecurityIdentifier));
        byte[] sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);
        IntPtr sidPtr = Marshal.AllocHGlobal(sidBytes.Length);
        Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);

        var oa = new LSA_OBJECT_ATTRIBUTES();
        var system = new LSA_UNICODE_STRING();
        IntPtr policyHandle;

        // POLICY_CREATE_ACCOUNT (0x0010) | POLICY_LOOKUP_NAMES (0x0800)
        uint openResult = LsaOpenPolicy(ref system, ref oa, 0x0810, out policyHandle);
        if (openResult != 0) {{
            Marshal.FreeHGlobal(sidPtr);
            throw new Exception("LsaOpenPolicy failed, NTSTATUS 0x" + openResult.ToString("X"));
        }}

        var rights = new LSA_UNICODE_STRING[1];
        rights[0] = new LSA_UNICODE_STRING();
        rights[0].Buffer = Marshal.StringToHGlobalUni(privilege);
        rights[0].Length = (ushort)(privilege.Length * 2);
        rights[0].MaximumLength = (ushort)((privilege.Length + 1) * 2);

        uint addResult = LsaAddAccountRights(policyHandle, sidPtr, rights, 1);
        Marshal.FreeHGlobal(rights[0].Buffer);
        Marshal.FreeHGlobal(sidPtr);
        LsaClose(policyHandle);

        if (addResult != 0) {{
            throw new Exception("LsaAddAccountRights failed, NTSTATUS 0x" + addResult.ToString("X"));
        }}
    }}
}}
'@
    [AiProwlerLsa]::AddPrivilege('{username}', 'SeBatchLogonRight')
    Set-Content -Path '{result_file}' -Value '{_GRANT_BATCH_LOGON_MARKER}OK' -Encoding UTF8
}} catch {{
    $msg = $_.Exception.Message -replace "[\\r\\n]+", " "
    Set-Content -Path '{result_file}' -Value "{_GRANT_BATCH_LOGON_MARKER}FAIL: $msg" -Encoding UTF8
}}
"""


def grant_batch_logon_right(username: str = None, timeout_sec: int = 30) -> tuple[bool, str]:
    """Grants 'Log on as a batch job' (SeBatchLogonRight) to `username`
    (defaults to the current user), so that schtasks /RU <username>
    (without /RP) actually produces the S4U logon type it's meant to,
    instead of silently degrading to Interactive-only.

    v8.1.11 TEMPORARY FALLBACK — remove once it's safe to assume every
    live install has the installer-side grant (AI-Prowler-Setup.iss's
    GrantBatchLogonRight procedure, which runs this same LSA call while
    the installer is already elevated, no UAC prompt needed). This
    function exists only to fix installs that predate that installer
    change without requiring a full reinstall.

    First checks BATCH_LOGON_MARKER_PATH — if the installer already
    granted this (or a previous call to this same function already did),
    skip entirely and return success immediately, no prompt.

    If the marker is absent, this REQUIRES a one-time UAC consent prompt
    — confirmed via direct testing that the originally-planned silent
    approach (a temporary /RL HIGHEST Scheduled Task, no prompt) does NOT
    work: AI-Prowler's GUI deliberately runs non-elevated (see
    RAG_RUN.bat), and Windows UAC's split-token model means even an
    administrator account's non-elevated processes can't silently create
    a highest-privilege task — real result from a live test: "ERROR:
    Access is denied." A genuine UAC prompt, via the same Start-Process
    -Verb RunAs pattern RAG_RUN.bat already uses for its own update-apply
    step, is the only reliable way to get the elevation this needs. On
    success, writes the SAME marker file the installer would have, so
    this only ever prompts once per machine, not once per Enable/Apply
    click.

    Returns (success, detail).
    """
    if username is None:
        username = os.environ.get("USERNAME") or getpass.getuser()

    if BATCH_LOGON_MARKER_PATH.exists():
        return True, f"'Log on as a batch job' already granted for {username} (marker found)."

    result_file = AI_PROWLER_HOME / f"_grant_batch_logon_result_{os.getpid()}.txt"
    ps1_path = AI_PROWLER_HOME / f"_grant_batch_logon_{os.getpid()}.ps1"
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    try:
        ps1_path.write_text(
            _build_grant_batch_logon_ps1(username, str(result_file)),
            encoding="utf-8")
    except Exception as e:
        return False, f"Could not write grant script: {e}"

    try:
        # Launches an ELEVATED powershell.exe to run the inner grant
        # script. -Verb RunAs triggers exactly one UAC consent prompt
        # (expected and required — can't elevate silently). The inner
        # process runs hidden so no extra console window stays open after
        # the user clicks yes.
        launcher = subprocess.run(
            ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
             f'Start-Process -FilePath "powershell.exe" -ArgumentList '
             f'\'-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{ps1_path}"\' '
             f'-Verb RunAs -Wait'],
            capture_output=True, text=True, timeout=timeout_sec,
            creationflags=subprocess.CREATE_NO_WINDOW)



        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if result_file.exists():
                break
            time.sleep(0.5)
        else:
            return False, (
                "Timed out waiting for the elevated grant to complete "
                "— if a UAC prompt appeared, it may have been declined "
                "or is still waiting for a response.")

        # v8.1.11 fix: real-world bug — Windows PowerShell 5.1's
        # `Set-Content -Encoding UTF8` writes a BOM (Byte Order Mark) by
        # default (PowerShell 7+ does not). Reading that back with plain
        # "utf-8" leaves an invisible leading U+FEFF character, which made
        # content.startswith(...) fail even when the file's actual text
        # was correct — confirmed live: the detail message shown to the
        # user literally contained "AI_PROWLER_GRANT_RESULT:OK" (the
        # success marker!) while still being treated as a failure.
        # "utf-8-sig" strips a BOM if present and is a safe no-op if not.
        content = result_file.read_text(encoding="utf-8-sig", errors="replace").strip()
        if content.startswith(f"{_GRANT_BATCH_LOGON_MARKER}OK"):
            try:
                BATCH_LOGON_MARKER_PATH.write_text(
                    f"Granted at runtime via one-time UAC prompt for {username}.",
                    encoding="utf-8")
            except Exception:
                pass  # non-fatal — worst case, prompts again next time
            return True, f"'Log on as a batch job' granted to {username}."
        detail = content[len(_GRANT_BATCH_LOGON_MARKER):] if content.startswith(_GRANT_BATCH_LOGON_MARKER) else content
        return False, detail or "Unknown failure — no result written."
    except subprocess.TimeoutExpired:
        return False, "Timed out."
    except Exception as e:
        return False, str(e)
    finally:
        for p in (ps1_path, result_file):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass


def scheduled_task_exists() -> bool:
    r = subprocess.run(["schtasks", "/query", "/tn", SCHEDULED_TASK_NAME],
                        capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW)
    return r.returncode == 0


def scheduled_task_enabled() -> bool | None:
    """Returns True if the task exists and is enabled, False if it exists
    and is disabled, None if it doesn't exist at all (or the state
    couldn't be determined). schtasks' own exit code from a plain /query
    only tells you presence/absence — it returns 0 for a disabled task
    just as readily as an enabled one, so scheduled_task_exists() alone
    can't distinguish the two. This parses /query /v /fo list's
    "Scheduled Task State" field, which does."""
    r = subprocess.run(
        ["schtasks", "/query", "/tn", SCHEDULED_TASK_NAME, "/v", "/fo", "list"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode != 0:

        return None
    for line in r.stdout.splitlines():
        if line.strip().lower().startswith("scheduled task state"):
            value = line.split(":", 1)[1].strip().lower()
            return value == "enabled"
    return None


def _build_register_queue_task_ps1(wrapper_script_path: str, schedule_time: str,
                                    schedule_end_time: str, check_mode: str,
                                    times_per_day: int, username: str, enabled: bool,
                                    result_file: str) -> str:
    """Returns a PowerShell script that (re)registers SCHEDULED_TASK_NAME
    with a genuine S4U principal via the ScheduledTasks module — the
    mechanism confirmed live to actually work, unlike schtasks.exe's /RU
    (see install_scheduled_task()'s docstring for the full story). Single
    quotes in wrapper_script_path must already be doubled by the caller
    (PowerShell's own escaping convention) — Windows paths essentially
    never contain them, but this is defensive correctness, not a fix for
    an observed problem.

    v9.0.1 REDESIGN — check_mode == "interval" no longer means "fire every
    N hours around the clock" (an hour-repetition trigger anchored at
    Get-Date, which silently ignored schedule_time and — worse — baked
    whatever arbitrary seconds Apply happened to be clicked at into every
    future occurrence forever; see the incident this replaced for the full
    story). It now means "fire at exactly `times_per_day` times, evenly
    spread across [schedule_time, schedule_end_time]" — computed by
    custom_tasks_manager.compute_daily_run_times(), the EXACT SAME function
    the My Custom AI Analyses and Common Business AI Analysis editors use
    for their own Start time / End time / Times per day fields, so this
    panel's "Check queue: N times/day" behaves identically to those and
    the two features can never drift out of sync with each other. Each
    computed time becomes its own plain `-Daily -At 'HH:MM'` trigger
    (registered together as an array via `-Trigger`) — a Daily trigger's
    time-of-day never drifts, sidestepping the whole class of anchor-drift
    bug the old repetition-based approach was vulnerable to.
    """
    if check_mode == "interval":
        n = max(1, int(times_per_day))
        try:
            import custom_tasks_manager as _ctm_trig
            run_times = _ctm_trig.compute_daily_run_times(
                schedule_time, schedule_end_time, n)
        except Exception:
            # Malformed start/end (shouldn't happen — the GUI validates
            # before calling in) — fall back to a single daily trigger
            # rather than fail registration outright.
            run_times = [schedule_time]
        trigger_lines = "\n    ".join(
            f"$t{i} = New-ScheduledTaskTrigger -Daily -At '{t}'"
            for i, t in enumerate(run_times)
        )
        trigger_array = ", ".join(f"$t{i}" for i in range(len(run_times)))
        trigger_block = f"{trigger_lines}\n    $trigger = @({trigger_array})"
    else:
        trigger_block = f"$trigger = New-ScheduledTaskTrigger -Daily -At '{schedule_time}'"

    disable_line = ""
    if not enabled:
        disable_line = (
            f"\n    Disable-ScheduledTask -TaskName '{SCHEDULED_TASK_NAME}' | Out-Null"
        )

    return f"""$ErrorActionPreference = 'Stop'
try {{
    $action = New-ScheduledTaskAction -Execute '{wrapper_script_path}'
    {trigger_block}
    $principal = New-ScheduledTaskPrincipal -UserId '{username}' -LogonType S4U -RunLevel Limited
    Register-ScheduledTask -TaskName '{SCHEDULED_TASK_NAME}' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null{disable_line}
    Set-Content -Path '{result_file}' -Value 'OK' -Encoding UTF8
}} catch {{
    $msg = $_.Exception.Message -replace "[\\r\\n]+", " "
    Set-Content -Path '{result_file}' -Value "FAIL: $msg" -Encoding UTF8
}}
"""


def _register_queue_task_elevated(wrapper_script_path: Path, schedule_time: str,
                                   schedule_end_time: str, check_mode: str,
                                   times_per_day: int, enabled: bool, username: str,
                                   timeout_sec: int = 30) -> tuple[bool, str]:
    """Runs _build_register_queue_task_ps1()'s script through the same
    one-time-UAC-prompt elevation pattern as grant_batch_logon_right() —
    Register-ScheduledTask with an explicit S4U principal requires
    elevation just like the rights grant does (confirmed live: fails
    "Access is denied" non-elevated, even with -RunLevel Limited)."""
    result_file = AI_PROWLER_HOME / f"_register_queue_task_result_{os.getpid()}.txt"
    ps1_path = AI_PROWLER_HOME / f"_register_queue_task_{os.getpid()}.ps1"
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    try:
        ps1_path.write_text(
            _build_register_queue_task_ps1(
                str(wrapper_script_path).replace("'", "''"), schedule_time,
                schedule_end_time, check_mode, times_per_day, username, enabled,
                str(result_file)),
            encoding="utf-8")
    except Exception as e:
        return False, f"Could not write task registration script: {e}"

    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
             f'Start-Process -FilePath "powershell.exe" -ArgumentList '
             f'\'-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{ps1_path}"\' '
             f'-Verb RunAs -Wait'],
            capture_output=True, text=True, timeout=timeout_sec,
            creationflags=subprocess.CREATE_NO_WINDOW)



        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if result_file.exists():
                break
            time.sleep(0.5)
        else:
            return False, (
                "Timed out waiting for the elevated task registration to "
                "complete — if a UAC prompt appeared, it may have been "
                "declined or is still waiting for a response.")

        # v8.1.11: same BOM defensive fix as grant_batch_logon_right() —
        # Windows PowerShell 5.1's Set-Content -Encoding UTF8 writes a
        # BOM by default, which broke a plain startswith() check there.
        content = result_file.read_text(encoding="utf-8-sig", errors="replace").strip()
        if content.startswith("OK"):
            return True, "ok"
        return False, content[len("FAIL: "):] if content.startswith("FAIL:") else content
    except subprocess.TimeoutExpired:
        return False, "Timed out."
    except Exception as e:
        return False, str(e)
    finally:
        for p in (ps1_path, result_file):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass


def install_scheduled_task(wrapper_script_path: Path, schedule_time: str,
                            enabled: bool = True,
                            check_mode: str = "daily",
                            schedule_end_time: str = "23:00",
                            times_per_day: int = 1,
                            run_as_user: str = None) -> tuple[bool, str]:
    """Creates (or replaces) the Scheduled Task. `enabled=False` creates it
    DISABLED — used by the test harness below to prove the mechanism works
    without leaving anything live.

    v8.1.11, redesigned v9.0.1: check_mode/schedule_end_time/times_per_day
    control the OS-level trigger(s). "daily" (default, matches all prior
    behavior) fires once a day at schedule_time. "interval" fires exactly
    `times_per_day` times, evenly spread across [schedule_time,
    schedule_end_time] via custom_tasks_manager.compute_daily_run_times() —
    the SAME function the My Custom AI Analyses / Common Business AI
    Analysis editors use for their own Start/End/Times-per-day fields.
    Each computed time is registered as its own genuine `-Daily -At`
    trigger, so none of them can drift the way the old single hour-
    repetition trigger did (see _build_register_queue_task_ps1()'s
    docstring for that incident).

    Day-of-week restriction (active_days) still isn't expressible as an OS
    trigger constraint via this mechanism (Register-ScheduledTask CAN
    express it via -DaysOfWeek, but that's left as a possible future
    tightening rather than done here) — it's still enforced inside the
    generated wrapper script itself (see build_wrapper_script_content()'s
    active-window self-check), simpler to build correctly and far easier
    to unit-test as plain string content than to validate real Task
    Scheduler XML/state.

    v8.1.11 fix: real-world bug report — the checker worked fine while the
    user was actively logged in, but silently never fired while the
    screensaver was active / screen locked, even with sleep/hibernate
    already disabled per the "Keep It Running" guide. Root cause: without
    an explicit /RU, schtasks.exe creates the task with the "Run only when
    user is logged on" logon type (INTERACTIVE_TOKEN) — this genuinely can
    fail to launch its process without an active interactive desktop
    session, which a locked screen / screensaver doesn't reliably provide,
    even though the user is technically still logged on. The documented
    fix is /RU <username> WITHOUT /RP (no stored password) — this switches
    the task to the S4U logon type ("Run whether user is logged on or
    not"), which runs in a batch logon session instead of requiring an
    interactive desktop, and works correctly whether the session is
    active, locked, or the screensaver is running. run_as_user defaults to
    the current Windows username (os.environ["USERNAME"]) — the same user
    whose %USERPROFILE%\\.ai-prowler\\ paths the rest of this module
    already assumes throughout; S4U still runs as that same user account
    (just a different logon session type), so every existing path
    assumption keeps working unchanged.
    """
    if run_as_user is None:
        run_as_user = os.environ.get("USERNAME") or getpass.getuser()

    # v8.1.11 fix: /RU alone doesn't guarantee the S4U logon type it's
    # meant to produce — it silently degrades to Interactive-only if the
    # account lacks SeBatchLogonRight ("Log on as a batch job"), which
    # standard Windows accounts don't have by default. Confirmed live:
    # this exact silent degradation is what caused the QueueRunner task
    # to still fail during a full logoff even after the /RU fix above was
    # correctly deployed. Grant the right proactively here, every time —
    # LsaAddAccountRights is idempotent (granting an already-held right is
    # a harmless no-op), so there's no cost to attempting this on every
    # Enable/Apply rather than trying to detect whether it's already
    # present first. If the grant fails (e.g. a genuinely non-admin
    # account, where the elevation-via-Scheduled-Task trick itself can't
    # succeed), task creation still proceeds — an Interactive-only task is
    # still better than none, and grant_detail is folded into the
    # returned message so the caller can surface it rather than silently
    # losing the information.
    _grant_ok, _grant_detail = grant_batch_logon_right(run_as_user)

    # v8.1.11 SECOND fix, found via live testing after the grant above
    # still didn't produce a working task: schtasks.exe's /RU <user>
    # (without /RP) does NOT actually set S4U logon type through its
    # simple CLI, REGARDLESS of SeBatchLogonRight — confirmed via direct
    # side-by-side testing (schtasks-created task: "Logon Mode:
    # Interactive only" even with the right freshly confirmed present in
    # secedit's own USER_RIGHTS export). PowerShell's ScheduledTasks
    # module (New-ScheduledTaskPrincipal -LogonType S4U +
    # Register-ScheduledTask) DOES produce a genuine S4U task — confirmed
    # live: "Logon Mode: Interactive/Background". That registration call
    # ALSO requires elevation (confirmed: fails "Access is denied" from a
    # non-elevated process even with -RunLevel Limited), so this reuses
    # the exact same one-time-UAC-prompt elevation pattern as the grant
    # above. Deliberate design choice (Option 1, by direct instruction):
    # always take the fully-proven elevated path rather than trying to
    # cleverly avoid re-prompting for simple schedule tweaks via
    # non-elevated schtasks /change — that fallback hasn't been verified
    # to actually work, and this session already burned real effort on
    # two unverified assumptions. The real cost: Apply/Toggle-On shows one
    # UAC consent click each time the schedule is actually (re)created,
    # not just once ever like the rights grant.
    reg_ok, reg_detail = _register_queue_task_elevated(
        wrapper_script_path, schedule_time, schedule_end_time, check_mode,
        times_per_day, enabled, run_as_user)
    if not reg_ok:
        return False, reg_detail

    if _grant_ok:
        return True, "ok"
    return True, (
        f"ok (note: could not confirm 'Log on as a batch job' for "
        f"{run_as_user} — {_grant_detail}. The task may still fall back "
        f"to running only while logged on.)")


def _unregister_queue_task_elevated(timeout_sec: int = 30) -> tuple[bool, str]:
    """Elevated fallback for uninstall_scheduled_task(). A task registered
    via _register_queue_task_elevated()'s S4U principal requires elevation
    to modify — confirmed there (see its docstring) to fail "Access is
    denied" non-elevated even with -RunLevel Limited. Deletion hits the
    same wall (confirmed live: a plain, non-elevated `schtasks /delete`
    against this task returns exit code 1 / "ERROR: Access is denied.").
    Uses the identical one-time-UAC-prompt + result-file handshake as
    _register_queue_task_elevated(), rather than trying to capture stdout
    from the elevated child directly (which Start-Process -Verb RunAs
    doesn't expose to the launcher)."""
    result_file = AI_PROWLER_HOME / f"_unregister_queue_task_result_{os.getpid()}.txt"
    ps1_path = AI_PROWLER_HOME / f"_unregister_queue_task_{os.getpid()}.ps1"
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    ps1_content = f"""$ErrorActionPreference = 'Stop'
try {{
    Unregister-ScheduledTask -TaskName '{SCHEDULED_TASK_NAME}' -Confirm:$false -ErrorAction Stop
    Set-Content -Path '{result_file}' -Value 'OK' -Encoding UTF8
}} catch {{
    $msg = $_.Exception.Message -replace "[\\r\\n]+", " "
    Set-Content -Path '{result_file}' -Value "FAIL: $msg" -Encoding UTF8
}}
"""
    try:
        ps1_path.write_text(ps1_content, encoding="utf-8")
    except Exception as e:
        return False, f"Could not write task removal script: {e}"

    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
             f'Start-Process -FilePath "powershell.exe" -ArgumentList '
             f'\'-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{ps1_path}"\' '
             f'-Verb RunAs -Wait'],
            capture_output=True, text=True, timeout=timeout_sec,
            creationflags=subprocess.CREATE_NO_WINDOW)

        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if result_file.exists():
                break
            time.sleep(0.5)
        else:
            return False, (
                "Timed out waiting for the elevated task removal to "
                "complete — if a UAC prompt appeared, it may have been "
                "declined or is still waiting for a response.")


        content = result_file.read_text(encoding="utf-8-sig", errors="replace").strip()
        if content.startswith("OK"):
            return True, "ok"
        return False, content[len("FAIL: "):] if content.startswith("FAIL:") else content
    except subprocess.TimeoutExpired:
        return False, "Timed out."
    except Exception as e:
        return False, str(e)
    finally:
        for p in (ps1_path, result_file):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass


def uninstall_scheduled_task() -> tuple[bool, str]:
    if not scheduled_task_exists():
        return True, "not present"
    r = subprocess.run(["schtasks", "/delete", "/tn", SCHEDULED_TASK_NAME, "/f"],
                        capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode == 0:
        return True, "ok"
    # v8.1.16 fix: the plain non-elevated delete above used to be the only
    # attempt — its result was even discarded entirely by the GUI's disable
    # path, so a task registered via the elevated S4U principal (see
    # _register_queue_task_elevated()) silently stayed armed: the button
    # flipped to OFF and config was rewritten as disabled while the real
    # Windows Scheduled Task kept running on schedule. Retry once, elevated,
    # before reporting failure.
    plain_detail = (r.stderr or r.stdout).strip()
    ok, elevated_detail = _unregister_queue_task_elevated()
    if ok:
        return True, "ok (required elevation)"
    return False, f"{plain_detail} | elevated retry also failed: {elevated_detail}"


# ── Scheduled runs: connect to the running AI-Prowler (2026-10-22, David) ────
RUNNING_SERVER_MCP_CONFIG_PATH = AI_PROWLER_HOME / "claude_mcp_config_running.json"


def scheduled_run_mcp_config() -> str:
    """Called by the scheduled queue wrapper right before Claude runs: prints
    the --mcp-config path for the running AI-Prowler (starting the normal app
    and waiting when needed), or NO_SERVER after recording why the run was
    skipped (last-run status, last_headless_run.json and the audit log)."""
    ok, result = connect_to_running_ai_prowler()
    if ok:
        return result
    _record_skipped_run(result)
    return "NO_SERVER"


def _record_skipped_run(why: str) -> None:
    try:
        _write_last_run("failure", f"Scheduled run skipped — {why}")
    except Exception:
        pass
    try:
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        (AI_PROWLER_HOME / "last_headless_run.json").write_text(
            json.dumps({"result": f"Skipped — {why}"}), encoding="utf-8")
    except Exception:
        pass
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] scheduled run skipped: {why}\n")
    except Exception:
        pass


def retire_cli_ai_routing() -> list:
    """2026-10-22 (David): cleans up what the removed Claude CLI AI routing
    left on this computer. Safe to call on every start — once clean it does
    nothing. Returns a list of what it did (for the log).

      * the "AI Route Optimizer (full reasoning)" custom analysis task (and
        any queued copy of it) — routing is done from the Jobs app now;
      * the on-demand Scheduled Task (AI-Prowler-AIRoutingRunner) — it has no
        trigger, so if Windows refuses to delete it without admin rights it is
        left in place (it can never run on its own);
      * ~/.ai-prowler/ai_routing — its wrapper, prompt and the per-user Claude
        tokens saved for it (no longer used by anything).
    """
    if RETIRED_AI_ROUTING_MARKER.exists():
        return []
    done = []
    try:
        import custom_tasks_manager as _ctm
        tasks = _ctm.load_custom_tasks()
        ids = [x.get("task_id") for x in tasks
               if isinstance(x, dict) and x.get("label") == RETIRED_ROUTE_TASK_LABEL]
        if ids:
            for tid in ids:
                _ctm.delete_task(tasks, tid)
            if _ctm.save_custom_tasks(tasks):
                done.append(f"removed the '{RETIRED_ROUTE_TASK_LABEL}' custom task")
        pending = AI_PROWLER_HOME / "pending_tasks.json"
        if pending.exists():
            queue = _ss_read_json(pending, default=None)
            if isinstance(queue, list):
                keep = [e for e in queue if not (isinstance(e, dict) and (
                    e.get("label") == RETIRED_ROUTE_TASK_LABEL or (ids and e.get("source_id") in ids)))]
                if len(keep) != len(queue):
                    _ss_write_text(pending, json.dumps(keep, indent=2, ensure_ascii=False))
                    done.append(f"removed {len(queue) - len(keep)} queued AI Route Optimizer run(s)")
    except Exception as e:  # noqa: BLE001
        done.append(f"custom task cleanup skipped: {e}")
    if os.name == "nt":
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            q = subprocess.run(["schtasks", "/query", "/tn", RETIRED_AI_ROUTING_TASK_NAME],
                               capture_output=True, text=True, timeout=20, creationflags=flags)
            if q.returncode == 0:
                d = subprocess.run(["schtasks", "/delete", "/tn", RETIRED_AI_ROUTING_TASK_NAME, "/f"],
                                   capture_output=True, text=True, timeout=20, creationflags=flags)
                done.append("removed the AI Routing scheduled task" if d.returncode == 0 else
                            "the old AI Routing scheduled task needs admin rights to remove "
                            "(harmless — it has no trigger and never runs)")
        except Exception as e:  # noqa: BLE001
            done.append(f"scheduled task check skipped: {e}")
    try:
        if RETIRED_AI_ROUTING_DIR.exists():
            shutil.rmtree(RETIRED_AI_ROUTING_DIR, ignore_errors=True)
            done.append("removed ~/.ai-prowler/ai_routing (runner files and per-user tokens)")
    except Exception as e:  # noqa: BLE001
        done.append(f"ai_routing folder cleanup skipped: {e}")
    # Clean (or only the harmless admin-only task left): don't check again.
    if not any("skipped" in d for d in done) and not RETIRED_AI_ROUTING_DIR.exists():
        try:
            AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
            RETIRED_AI_ROUTING_MARKER.write_text(
                datetime.now().isoformat(timespec="seconds") + "\n" + "\n".join(done), encoding="utf-8")
        except Exception:
            pass
    return done


# ── Audit log read (for the GUI's "View Audit Log" button) ──────────────

def read_audit_log_tail(n_lines: int = 200) -> str:
    if not AUDIT_LOG_PATH.exists():
        return "(no audit log yet — the log is written by a Claude Code hook on the first run)"
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-n_lines:])

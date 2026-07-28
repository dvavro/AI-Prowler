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

AI_PROWLER_HOME = Path.home() / ".ai-prowler"
CONFIG_PATH = AI_PROWLER_HOME / "task_automation_config.json"
STATUS_PATH = AI_PROWLER_HOME / "task_automation_last_run.json"
AUDIT_LOG_PATH = AI_PROWLER_HOME / "autonomous_run_audit.log"
WRAPPER_SCRIPT_NAME = "run_ai_prowler_queue.bat"
SCHEDULED_TASK_NAME = "AI-Prowler-QueueRunner"
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
    "Run AI-Prowler's pending analysis task queue. Follow this sequence "
    "exactly, in order. "
    "1. Call sync_due_tasks_to_queue first. This pushes any due custom "
    "task definitions into the run queue that aren't already sitting "
    "there. Safe to call every time; it is idempotent and will not "
    "duplicate an already-queued entry. "
    "2. Call get_pending_analysis_tasks. This only returns entries that "
    "are actually due right now. If nothing is returned, report that "
    "plainly and stop; do not treat an empty or not-yet-due result as an "
    "error. "
    "3. For each task returned, in the order given: read the task's "
    "prompt, scope_dirs, and label; perform the actual analysis using "
    "AI-Prowler's own MCP tools only, scoped to scope_dirs if provided, "
    "otherwise the task's default scope; call record_learning for any "
    "concrete findings worth persisting; call complete_analysis_task with "
    "the task_id and a real, specific summary of what was found, not a "
    "placeholder; next_due advancement and re-arming are handled "
    "automatically by AI-Prowler, do not compute this yourself; if the "
    "task's configuration requested a saved report, call "
    "save_analysis_report after complete_analysis_task. "
    "4. After all tasks are processed, produce a final one-paragraph "
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
    "unavailable. Do not use any other tool outside AI-Prowler's own MCP "
    "tools plus WebSearch and WebFetch. "
    "Do not create new task definitions; only process what is already "
    "due or queued."
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
                                    # allowance). True = ANTHROPIC_API_KEY (separate,
                                    # metered billing, no expiry/refresh risk). See
                                    # spec §5.3 for the tradeoff — this does NOT affect
                                    # agentic tool access, only billing + reliability.

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
    "check_interval_hours": 1,      # only used when check_mode == "interval"
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
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
        merged = dict(DEFAULT_CONFIG)
        merged.update(data or {})
        return merged
    except Exception:
        # Corrupt config should never crash the GUI panel — fall back to
        # a safe, disabled default and let the user reconfigure.
        return dict(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def load_last_run() -> dict | None:
    if not STATUS_PATH.exists():
        return None
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def _write_last_run(status: str, detail: str, task_count: int | None = None) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,          # "success" | "failure" | "dry_run_ok" | "dry_run_failed"
        "detail": detail,
        "task_count": task_count,
    }, indent=2), encoding="utf-8")


# ── Wrapper script generation (Phase 1) ─────────────────────────────────

def build_wrapper_script_content(mcp_config_path: str, allowed_tools: str,
                                  notify_on_complete: bool = False,
                                  notify_method: str = "sms",
                                  use_api_key: bool = False,
                                  install_dir: str = "",
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

    use_api_key: when True, the script reads a key from API_KEY_PATH at
    RUNTIME and sets ANTHROPIC_API_KEY before invoking claude. The actual
    key value is never embedded in this generated script text — only the
    file-read mechanism is, so the .bat file itself stays safe to open in
    a text editor without exposing the secret. Claude Code's own
    documented auth priority means ANTHROPIC_API_KEY, when present in the
    environment, is used in preference to any subscription/OAuth
    credential automatically — no extra flag needed to force this.

    install_dir: the AI-Prowler application directory (contains
    .claude/skills/ai-prowler-tasks/SKILL.md, which defines the
    /ai-prowler-run-queue slash command this script invokes). v8.1.10 fix
    — this used to `cd` into %USERPROFILE% instead, which has no .claude
    folder of its own. Claude Code resolves project-level slash commands
    from the CURRENT WORKING DIRECTORY's .claude folder, so every
    scheduled run silently failed with "Unknown command:
    /ai-prowler-run-queue" (0 turns, $0 cost, exits "success" in ~100ms)
    — Windows Task Scheduler reported the run as successful throughout,
    because the .bat itself did exit 0; nothing about the failure was
    visible anywhere except the raw last_headless_run.json transcript. If
    install_dir is not provided (e.g. an old caller not yet updated),
    falls back to %USERPROFILE% to preserve prior (broken) behavior rather
    than guessing wrong.

    check_mode/active_days/active_start_time/active_end_time (v8.1.11):
    the checker's own frequency (set via check_mode + the OS trigger
    install_scheduled_task() creates) and active window are DELIBERATELY
    independent of any individual custom task's own schedule — this is
    about when the CHECKER wakes up at all, not whether any given task is
    due. active_days always applies (both modes); active_start_time/
    active_end_time are only enforced in "interval" mode — in "daily"
    mode, schedule_time itself already IS the single trigger point, so an
    additional time-window check would be redundant (and could only ever
    contradict schedule_time, never usefully narrow it). If the check
    lands outside the active window, the script exits immediately, before
    ever invoking `claude -p` — zero cost for a skipped check, not just a
    fast failure.
    """
    active_days = active_days if active_days is not None else list(DEFAULT_CONFIG["active_days"])
    _days_py_list = "{" + ",".join(f"'{d}'" for d in active_days) + "}"

    if check_mode == "interval":
        # Single Python one-liner does the whole window check and prints
        # RUN or SKIP — far more robust than parsing %DATE%/%TIME% in batch,
        # which is locale-dependent and has bitten this project before.
        _window_check_py = (
            "import datetime as _d; "
            "_n = _d.datetime.now(); "
            "_day = _n.strftime('%a').lower()[:3]; "
            "_t = _n.strftime('%H:%M'); "
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
for /f "delims=" %%R in ('python -c "{_window_check_py}"') do set AIP_WINDOW_CHECK=%%R
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
            "_day = _d.datetime.now().strftime('%a').lower()[:3]; "
            f"_days = {_days_py_list}; "
            "print('RUN' if _day in _days else 'SKIP')"
        )
        window_check_block = f"""REM v8.1.11: active-days self-gate (daily mode). schedule_time already
REM pins the single time-of-day this fires (via the OS trigger) — only
REM day-of-week needs checking here, e.g. for a "weekdays only" setup.
for /f "delims=" %%R in ('python -c "{_window_check_py}"') do set AIP_WINDOW_CHECK=%%R
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
    if use_api_key:
        api_key_block = f"""REM Use ANTHROPIC_API_KEY instead of the OAuth subscription token —
REM metered billing, but no OAuth expiry/refresh risk. Read from a
REM dedicated file at runtime so the actual key never appears in this
REM script's own text.
if exist "{API_KEY_PATH}" (
    set /p ANTHROPIC_API_KEY=<"{API_KEY_PATH}"
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
        api_key_block = f"""REM Use the Claude Code OAuth token captured from setup-token —
REM see OAUTH_TOKEN_PLAIN_PATH / try_capture_setup_token() in task_queue_automation.py.
if exist "{OAUTH_TOKEN_PLAIN_PATH}" (
    set /p CLAUDE_CODE_OAUTH_TOKEN=<"{OAUTH_TOKEN_PLAIN_PATH}"
) else (
    echo [ERROR] No Claude Code OAuth token found — click Get / Renew Token in AI-Prowler first.
    exit /b 1
)

"""

    _cd_target = install_dir.strip() if install_dir and install_dir.strip() else "%USERPROFILE%"

    return f"""@echo off
REM Auto-generated by task_queue_automation.py — do not edit by hand.
REM Runs AI-Prowler's pending analysis task queue unattended via Claude
REM Code headless mode. See the architecture spec for design rationale.

{window_check_block}REM v8.1.10 fix: MUST cd into the AI-Prowler app directory, not
REM %USERPROFILE% — the /ai-prowler-run-queue slash command is defined by
REM .claude/skills/ai-prowler-tasks/SKILL.md, and Claude Code only
REM discovers project-level skills/commands from the current working
REM directory's own .claude folder. Running from %USERPROFILE% (which has
REM no .claude/skills of its own) silently resolved to "Unknown command"
REM every single time, with the .bat still exiting 0 — Task Scheduler
REM showed "successful" runs that did nothing at all.
cd /d "{_cd_target}"

{api_key_block}claude -p "{prompt}" ^
  --mcp-config "{mcp_config_path}" ^
  --allowedTools "{allowed_tools}" ^
  --output-format json ^
  --permission-mode acceptEdits > "%USERPROFILE%\\.ai-prowler\\last_headless_run.json" 2>&1

set RC=%ERRORLEVEL%
exit /b %RC%
"""


def install_wrapper_script(target_dir: Path, mcp_config_path: str, allowed_tools: str,
                            notify_on_complete: bool = False,
                            notify_method: str = "sms",
                            use_api_key: bool = False,
                            install_dir: str = "",
                            check_mode: str = "daily",
                            active_days: list | None = None,
                            active_start_time: str = "00:00",
                            active_end_time: str = "23:59") -> Path:
    """Writes the wrapper script into target_dir. Caller decides target_dir —
    the GUI passes ~/.ai-prowler/ (NOT the install directory) so this never
    needs write access to C:\\Program Files\\AI-Prowler.

    install_dir: passed straight through to build_wrapper_script_content()
    — the directory the generated .bat should `cd` into before invoking
    `claude -p`, i.e. wherever THIS AI-Prowler is actually running from
    (contains .claude/skills/ai-prowler-tasks/SKILL.md). See that
    function's docstring for why this is required (v8.1.10 fix).

    check_mode/active_days/active_start_time/active_end_time (v8.1.11):
    forwarded straight through to build_wrapper_script_content() — see
    that function's docstring for the full rationale."""
    target_dir.mkdir(parents=True, exist_ok=True)
    script_path = target_dir / WRAPPER_SCRIPT_NAME
    script_path.write_text(
        build_wrapper_script_content(mcp_config_path, allowed_tools,
                                      notify_on_complete, notify_method,
                                      use_api_key, install_dir,
                                      check_mode, active_days,
                                      active_start_time, active_end_time),
        encoding="utf-8")
    return script_path


# ── Dry-run validation (safe — never invokes `claude -p` for real) ──────

def dry_run_check() -> dict:
    """Validates every precondition for a real run WITHOUT triggering one.
    Returns a report dict the GUI renders as a checklist. This is the
    button-safe operation — it never touches pending_tasks.json, never
    spends usage, never sends a notification."""
    checks = []

    # 1. Is the `claude` CLI on PATH at all?
    claude_path = shutil.which("claude")
    checks.append({
        "name": "Claude Code CLI on PATH",
        "ok": claude_path is not None,
        "detail": claude_path or "`claude` not found on PATH — install Claude Code first.",
    })

    # 2. Is there a setup-token / valid auth? We don't invoke a real call;
    #    `claude --version` is a safe, read-only smoke test that at least
    #    confirms the binary runs.
    if claude_path:
        try:
            r = subprocess.run(["claude", "--version"], capture_output=True,
                                text=True, timeout=10)
            checks.append({
                "name": "Claude Code CLI runs",
                "ok": r.returncode == 0,
                "detail": (r.stdout or r.stderr or "").strip()[:200],
            })
        except Exception as e:
            checks.append({"name": "Claude Code CLI runs", "ok": False, "detail": str(e)})

    # 3. Is AI-Prowler's own HTTP MCP server reachable? (read-only health
    #    check, same one the LED reconciliation loop uses)
    cfg = load_config()
    port = 8000
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2.5) as resp:
            checks.append({
                "name": f"AI-Prowler HTTP MCP server (port {port})",
                "ok": True,
                "detail": f"responded {resp.status}",
            })
    except Exception as e:
        checks.append({
            "name": f"AI-Prowler HTTP MCP server (port {port})",
            "ok": False,
            "detail": f"not reachable: {e}",
        })

    # 4. Does the Skill file exist?
    # v8.1.11 fix: real-world bug — Path.cwd() reflects whatever the
    # CALLING process's current working directory happens to be, which is
    # only correct by accident (e.g. a desktop shortcut's "Start in"
    # field). Confirmed live: a fresh install auto-launched via the
    # AI-Prowler-AutoStart Scheduled Task (no explicit working directory)
    # inherited Windows' default of C:\Windows\System32, and this check
    # reported the Skill file "missing" at
    # C:\Windows\System32\.claude\skills\..., even though it was correctly
    # installed at the real AI-Prowler directory. __file__ always
    # resolves to where THIS module itself is actually running from
    # (task_queue_automation.py is deployed alongside .claude\ in every
    # install), independent of the calling process's cwd — the same
    # robust pattern already used elsewhere (e.g. rag_gui.py's own
    # install_dir computation for the wrapper script). RAG_RUN.bat now
    # also sets a correct working directory explicitly as the real root
    # fix; this is defense-in-depth for any other launch path that
    # doesn't go through RAG_RUN.bat at all (e.g. a raw `python
    # rag_gui.py` invocation from an arbitrary directory).
    _this_module_dir = Path(__file__).resolve().parent
    skill_path = _this_module_dir / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
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
    # of these is relevant at a time; showing the other would be noise
    # (and, in the API-key case, checking OAuth expiry is meaningless).
    if cfg.get("use_api_key"):
        key_ok = has_api_key()
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
# Desktop auto-config the installer already writes, see
# claude_desktop_config_example.json — needs nothing but AI-Prowler's own
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


def _generate_local_mcp_config() -> tuple[bool, str]:
    """Writes a stdio --mcp-config pointing headless Claude Code directly
    at AI-Prowler's own ai_prowler_mcp.py — identical in shape to the
    Claude Desktop config the installer auto-writes. Requires no Bearer
    Token, no tunnel, no remote setup of any kind: it's the same machine,
    so a local subprocess is all that's needed. Returns
    (success, path_or_error_message)."""
    if not LOCAL_MCP_SCRIPT_PATH.exists():
        return False, (f"ai_prowler_mcp.py not found at {LOCAL_MCP_SCRIPT_PATH} "
                        "— reinstall AI-Prowler.")

    mcp_config = {
        "mcpServers": {
            "ai-prowler": {
                "command": sys.executable,
                "args": [str(LOCAL_MCP_SCRIPT_PATH)],
                "env": {
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONIOENCODING": "utf-8",
                    "PYTHONUNBUFFERED": "1",
                    "PYTHONWARNINGS": "ignore",
                },
            }
        }
    }

    try:
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        GENERATED_MCP_CONFIG_PATH.write_text(
            json.dumps(mcp_config, indent=2), encoding="utf-8")
    except Exception as e:
        return False, f"Could not write MCP config: {e}"

    return True, str(GENERATED_MCP_CONFIG_PATH)


def _generate_remote_mcp_config() -> tuple[bool, str]:
    """Reads AI-Prowler's own config.json for remote_token + tunnel_domain
    and writes a Claude Code-compatible --mcp-config JSON file, in the
    schema Anthropic's own docs specify for a remote HTTP MCP server with
    a static auth header. Only relevant for users who've actually set up
    remote/mobile access — see generate_mcp_config() for why the local
    stdio path is tried first. Returns (success, path_or_error_message)."""
    if not AI_PROWLER_CONFIG_PATH.exists():
        return False, ("AI-Prowler config.json not found — set up the HTTP "
                        "MCP server and Bearer Token in Settings first.")
    try:
        cfg = json.loads(AI_PROWLER_CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return False, f"Could not read AI-Prowler config.json: {e}"

    token = (cfg.get("remote_token") or "").strip()
    domain = (cfg.get("tunnel_domain") or "").strip()

    if not token:
        return False, "No Bearer Token saved yet — Settings → Remote Access → Save Token."
    if not domain:
        return False, "No tunnel domain configured yet — Settings → Remote Access → set up a tunnel."

    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    url = f"https://{domain}/mcp"

    mcp_config = {
        "mcpServers": {
            "ai-prowler": {
                "type": "http",
                "url": url,
                "headers": {
                    "Authorization": f"Bearer {token}",
                },
            }
        }
    }

    try:
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        GENERATED_MCP_CONFIG_PATH.write_text(
            json.dumps(mcp_config, indent=2), encoding="utf-8")
    except Exception as e:
        return False, f"Could not write MCP config: {e}"

    return True, str(GENERATED_MCP_CONFIG_PATH)


def generate_mcp_config(prefer_remote: bool = False) -> tuple[bool, str]:
    """Writes/refreshes the --mcp-config file headless Claude Code needs to
    reach AI-Prowler. Tries local stdio first (works out of the box on any
    install, no user setup required); falls back to the remote HTTP config
    if the local script can't be found. Pass prefer_remote=True to flip
    that order — e.g. a Personal-mode user who's already set up remote/
    mobile access and wants the scheduled task to exercise that same HTTP
    path (matches what their mobile client actually uses, useful for
    diagnosing remote-only issues). NOTE: this whole feature is Personal
    mode only — server mode suppresses Task Queue automation entirely
    (see dry_run_check() callers / the architecture spec), so there is no
    server-mode case here at all. Either way, if the preferred path isn't
    actually usable, the other one is tried automatically rather than
    failing outright. Returns (success, path_or_error_message)."""
    first, second = (_generate_remote_mcp_config, _generate_local_mcp_config) \
        if prefer_remote else (_generate_local_mcp_config, _generate_remote_mcp_config)
    ok, result = first()
    if ok:
        return ok, result
    return second()




# ── ANTHROPIC_API_KEY fallback (Phase 1 addendum) ─────────────────────────
# Alternative to the OAuth setup-token path. Same agentic tool access —
# this is purely a billing/auth-mechanism choice. Trades subscription
# billing for metered per-token billing, in exchange for no expiry/refresh
# risk (a static key doesn't expire the way an OAuth access token does).
# Stored as a separate plain-text file, not inside task_automation_config.json,
# so a casual look at the config file (e.g. for debugging schedule/notify
# settings) doesn't also expose the key. This is the same plaintext-on-disk
# tradeoff AI-Prowler's own config.json already makes for the Bearer token —
# not introducing a new class of risk, just being deliberate about where.

API_KEY_PATH = AI_PROWLER_HOME / "claude_api_key.txt"


def save_api_key(key: str) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    API_KEY_PATH.write_text(key.strip(), encoding="utf-8")


def load_api_key() -> str | None:
    if not API_KEY_PATH.exists():
        return None
    val = API_KEY_PATH.read_text(encoding="utf-8").strip()
    return val or None


def has_api_key() -> bool:
    """Presence check only — never returns or logs the actual key value.
    Use this for GUI/dry-run display; use load_api_key() only where the
    real value is actually needed (i.e. never, in this module — the
    wrapper .bat reads the file itself at runtime, see
    build_wrapper_script_content)."""
    return load_api_key() is not None


def delete_api_key() -> None:
    if API_KEY_PATH.exists():
        API_KEY_PATH.unlink()


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
    OAUTH_TOKEN_PATH.write_text(json.dumps({
        "token": clean,
        "issued_at": issued.isoformat(),
    }), encoding="utf-8")
    # v8.1.6 second fix: build_wrapper_script_content() originally parsed
    # this JSON at runtime via a PowerShell one-liner invoked through
    # `for /f` + backticks — that combination of nested quoting turned
    # out to be exactly as fragile as the setup-token launch command was
    # (see build_setup_token_batch_content()'s docstring for the same
    # class of bug), and failed with "the token could not be parsed"
    # even though the JSON itself was completely valid. A plain-text
    # mirror lets the .bat just `set /p` it, identical to how
    # API_KEY_PATH already works — no external process, no quoting.
    OAUTH_TOKEN_PLAIN_PATH.write_text(clean, encoding="utf-8")


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


def run_queue_now(mcp_config_path: str, allowed_tools: str,
                   use_api_key: bool = False,
                   notify_on_complete: bool = False,
                   notify_method: str = "sms",
                   timeout: int = 600) -> tuple[bool, str]:
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

    Returns (success, detail) — detail is either the tail of the
    session's real output (truncated to keep dialog boxes reasonable)
    or a plain-language reason it never ran."""
    if not claude_code_cli_installed():
        return False, ("Claude Code CLI is not installed. Install it from "
                        "the 🤖 Autonomous AI Task Queue panel above, then try again.")
    if not mcp_config_path:
        return False, ("No MCP config is set up yet. Click 'Generate MCP "
                        "Config' in the 🤖 Autonomous AI Task Queue panel above, "
                        "then try again.")

    wrapper_dir = AI_PROWLER_HOME / "manual_run"
    wrapper_path = install_wrapper_script(
        wrapper_dir, mcp_config_path, allowed_tools,
        notify_on_complete, notify_method, use_api_key)

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


def build_single_prompt_wrapper_content(prompt: str, mcp_config_path: str,
                                         allowed_tools: str,
                                         use_api_key: bool = False) -> str:
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
    """
    api_key_block = ""
    if use_api_key:
        api_key_block = f"""REM Use ANTHROPIC_API_KEY — see build_wrapper_script_content()'s
REM docstring for why this reads from a file at runtime.
if exist "{API_KEY_PATH}" (
    set /p ANTHROPIC_API_KEY=<"{API_KEY_PATH}"
) else (
    echo [ERROR] use_api_key is enabled but {API_KEY_PATH} was not found.
    exit /b 1
)

"""
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

    escaped_prompt = prompt.replace('"', '""')
    return f"""@echo off
REM Auto-generated by task_queue_automation.py — do not edit by hand.
REM Runs a single ad-hoc analysis prompt right now (the "▶ NOW" button) —
REM never touches pending_tasks.json, unlike the scheduled queue wrapper.

cd /d "%USERPROFILE%"

{api_key_block}claude -p "{escaped_prompt}" ^
  --mcp-config "{mcp_config_path}" ^
  --allowedTools "{allowed_tools}" ^
  --output-format json ^
  --permission-mode acceptEdits > "%USERPROFILE%\\.ai-prowler\\last_single_run.json" 2>&1

set RC=%ERRORLEVEL%
exit /b %RC%
"""


def run_single_prompt_now(prompt: str, mcp_config_path: str, allowed_tools: str,
                           use_api_key: bool = False,
                           timeout: int = 600) -> tuple[bool, str]:
    """v8.1.6: runs ONE ad-hoc prompt right now via a real headless Claude
    Code session — backs the "▶ NOW" button on each Common Business AI
    Analysis item so a user can try one before deciding whether to queue
    it. Deliberately does NOT touch pending_tasks.json or
    complete_analysis_task() bookkeeping — this is a trial run, not part
    of the tracked queue. Written to its own single_run/ subfolder,
    separate from both the Scheduled Task's wrapper and manual_run/ (see
    run_queue_now()'s docstring), so none of the three ever collide.
    Blocking — callers MUST invoke from a background thread, never
    directly on the Tk main thread, same requirement as run_queue_now().
    Returns (success, detail)."""
    if not claude_code_cli_installed():
        return False, ("Claude Code CLI is not installed. Install it from "
                        "the 🤖 Autonomous AI Task Queue panel above, then try again.")
    if not mcp_config_path:
        return False, ("No MCP config is set up yet. See the 🤖 Autonomous "
                        "AI Task Queue panel above (Test Setup (Dry Run) will "
                        "show what's missing), then try again.")

    wrapper_dir = AI_PROWLER_HOME / "single_run"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    script_path = wrapper_dir / "run_single_now.bat"
    script_path.write_text(
        build_single_prompt_wrapper_content(prompt, mcp_config_path, allowed_tools, use_api_key),
        encoding="utf-8")

    try:
        r = subprocess.run([str(script_path)], capture_output=True,
                            text=True, timeout=timeout, shell=True)
    except subprocess.TimeoutExpired:
        return False, f"Run timed out after {timeout}s — check your internet connection."
    except Exception as e:
        return False, str(e)

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
    if claude_code_cli_installed():
        return True, "Already installed."
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
                OAUTH_TOKEN_PLAIN_PATH.write_text(data["token"].strip(), encoding="utf-8")
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




def get_scheduled_task_display_info() -> dict:
    """v8.1.11: real, OS-level truth about the actual armed Windows
    Scheduled Task — not what the GUI's config file says should be true,
    but what schtasks itself reports right now. Built specifically so the
    Autonomous AI Task Queue panel can show David what's actually armed
    rather than just echoing back the text field he typed into, and so
    Toggle Off can be visually confirmed as genuinely having disarmed the
    real task, not just flipped a local config flag.

    Returns a dict:
        exists:   bool
        enabled:  bool | None (None if it doesn't exist)
        schedule_type: str | None  ("Daily", "Hourly", etc. as schtasks
                       itself reports it)
        start_time: str | None    ("Start Time" field, HH:MM:SS as
                       schtasks reports it)
        repeat_every: str | None  ("Repeat: Every" field, when present —
                       only set for interval/hourly-mode tasks)
        next_run_time: str | None ("Next Run Time" field)
        display: str               a single human-readable summary line,
                       ready to drop straight into the GUI, e.g.
                       "🟢 Armed — Daily at 6:00 AM (next: 7/27/2026 6:00 AM)"
                       or "🔴 Not armed" if disabled/missing.
    """
    info = {
        "exists": False, "enabled": None, "schedule_type": None,
        "start_time": None, "repeat_every": None, "next_run_time": None,
        "display": "🔴 Not armed",
    }
    r = subprocess.run(
        ["schtasks", "/query", "/tn", SCHEDULED_TASK_NAME, "/v", "/fo", "list"],
        capture_output=True, text=True)
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

    if info["repeat_every"] and info["repeat_every"] not in ("Disabled", ""):
        cadence = f"every {info['repeat_every']}"
    elif info["start_time"]:
        cadence = f"{info['schedule_type'] or 'Daily'} at {info['start_time']}"
    else:
        cadence = info["schedule_type"] or "scheduled"

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
        # script, showing exactly one UAC consent prompt. -Wait blocks
        # this (non-elevated) call until the elevated process exits.
        launcher = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f'Start-Process -FilePath "powershell.exe" -ArgumentList '
             f'\'-NoProfile -ExecutionPolicy Bypass -File "{ps1_path}"\' '
             f'-Verb RunAs -Wait'],
            capture_output=True, text=True, timeout=timeout_sec)

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
                        capture_output=True, text=True)
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
        capture_output=True, text=True)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if line.strip().lower().startswith("scheduled task state"):
            value = line.split(":", 1)[1].strip().lower()
            return value == "enabled"
    return None


def _build_register_queue_task_ps1(wrapper_script_path: str, schedule_time: str,
                                    check_mode: str, check_interval_hours: int,
                                    username: str, enabled: bool,
                                    result_file: str) -> str:
    """Returns a PowerShell script that (re)registers SCHEDULED_TASK_NAME
    with a genuine S4U principal via the ScheduledTasks module — the
    mechanism confirmed live to actually work, unlike schtasks.exe's /RU
    (see install_scheduled_task()'s docstring for the full story). Single
    quotes in wrapper_script_path must already be doubled by the caller
    (PowerShell's own escaping convention) — Windows paths essentially
    never contain them, but this is defensive correctness, not a fix for
    an observed problem.
    """
    if check_mode == "interval":
        trigger_block = (
            "$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) "
            f"-RepetitionInterval (New-TimeSpan -Hours {max(1, int(check_interval_hours))}) "
            "-RepetitionDuration (New-TimeSpan -Days 3650)"
        )
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
                                   check_mode: str, check_interval_hours: int,
                                   enabled: bool, username: str,
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
                check_mode, check_interval_hours, username, enabled,
                str(result_file)),
            encoding="utf-8")
    except Exception as e:
        return False, f"Could not write task registration script: {e}"

    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f'Start-Process -FilePath "powershell.exe" -ArgumentList '
             f'\'-NoProfile -ExecutionPolicy Bypass -File "{ps1_path}"\' '
             f'-Verb RunAs -Wait'],
            capture_output=True, text=True, timeout=timeout_sec)

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
                            check_interval_hours: int = 1,
                            run_as_user: str = None) -> tuple[bool, str]:
    """Creates (or replaces) the Scheduled Task. `enabled=False` creates it
    DISABLED — used by the test harness below to prove the mechanism works
    without leaving anything live.

    v8.1.11: check_mode/check_interval_hours control the OS-level trigger
    type. "daily" (default, matches all prior behavior) fires once a day
    at schedule_time. "interval" fires every check_interval_hours hours,
    around the clock — day-of-week and time-of-day restrictions for
    interval mode are DELIBERATELY NOT expressed here as OS trigger
    constraints (schtasks.exe's simple CLI can't cleanly combine an hourly
    repetition with day-of-week + time-window filtering — that requires a
    full XML task definition). Instead, that filtering happens inside the
    generated wrapper script itself (see build_wrapper_script_content()'s
    active-window self-check) — simpler to build correctly and far easier
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
        wrapper_script_path, schedule_time, check_mode, check_interval_hours,
        enabled, run_as_user)
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
            ["powershell.exe", "-NoProfile", "-Command",
             f'Start-Process -FilePath "powershell.exe" -ArgumentList '
             f'\'-NoProfile -ExecutionPolicy Bypass -File "{ps1_path}"\' '
             f'-Verb RunAs -Wait'],
            capture_output=True, text=True, timeout=timeout_sec)

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
                        capture_output=True, text=True)
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


# ── Audit log read (for the GUI's "View Audit Log" button) ──────────────

def read_audit_log_tail(n_lines: int = 200) -> str:
    if not AUDIT_LOG_PATH.exists():
        return "(no audit log yet — the log is written by a Claude Code hook on the first run)"
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-n_lines:])

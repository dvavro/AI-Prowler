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
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

AI_PROWLER_HOME = Path.home() / ".ai-prowler"
CONFIG_PATH = AI_PROWLER_HOME / "task_automation_config.json"
STATUS_PATH = AI_PROWLER_HOME / "task_automation_last_run.json"
AUDIT_LOG_PATH = AI_PROWLER_HOME / "autonomous_run_audit.log"
WRAPPER_SCRIPT_NAME = "run_ai_prowler_queue.bat"
SCHEDULED_TASK_NAME = "AI-Prowler-QueueRunner"

DEFAULT_CONFIG = {
    "enabled": False,
    "schedule_time": "06:00",     # 24h HH:MM, daily trigger
    "allowed_tools": "mcp__ai-prowler__*",
    "mcp_config_path": "",         # filled in by the GUI at Enable time
    "install_dir": "",             # filled in by the GUI at Enable time
    "notify_on_complete": False,   # Phase 6 — see build_wrapper_script_content
    "notify_method": "sms",        # "sms" or "whatsapp" — which AI-Prowler tool to use
    "use_api_key": False,          # False = OAuth setup-token (default, uses subscription
                                    # allowance). True = ANTHROPIC_API_KEY (separate,
                                    # metered billing, no expiry/refresh risk). See
                                    # spec §5.3 for the tradeoff — this does NOT affect
                                    # agentic tool access, only billing + reliability.
}


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
                                  use_api_key: bool = False) -> str:
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

    prompt = "/ai-prowler-run-queue" + notify_clause

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

    return f"""@echo off
REM Auto-generated by task_queue_automation.py — do not edit by hand.
REM Runs AI-Prowler's pending analysis task queue unattended via Claude
REM Code headless mode. See the architecture spec for design rationale.

cd /d "%USERPROFILE%"

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
                            use_api_key: bool = False) -> Path:
    """Writes the wrapper script into target_dir. Caller decides target_dir —
    the GUI passes ~/.ai-prowler/ (NOT the install directory) so this never
    needs write access to C:\\Program Files\\AI-Prowler."""
    target_dir.mkdir(parents=True, exist_ok=True)
    script_path = target_dir / WRAPPER_SCRIPT_NAME
    script_path.write_text(
        build_wrapper_script_content(mcp_config_path, allowed_tools,
                                      notify_on_complete, notify_method, use_api_key),
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
    skill_path = Path.cwd() / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
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
# layers" discussion. This function reads AI-Prowler's own saved config
# (the same remote_token / tunnel_domain fields the existing Claude.ai
# connector guide already surfaces) and writes the --mcp-config file
# Claude Code needs, in the schema Anthropic's own docs specify for a
# remote HTTP MCP server with a static auth header.

AI_PROWLER_CONFIG_PATH = Path.home() / ".ai-prowler" / "config.json"
GENERATED_MCP_CONFIG_PATH = AI_PROWLER_HOME / "claude_mcp_config.json"


def generate_mcp_config() -> tuple[bool, str]:
    """Reads AI-Prowler's own config.json for remote_token + tunnel_domain
    and writes a Claude Code-compatible --mcp-config JSON file. Returns
    (success, path_or_error_message)."""
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


# ── Claude Code CLI presence + install (for existing users who updated ──
# in-place rather than via a fresh installer run — the installer's own
# Pascal Script install step, see AI-Prowler-Setup.iss, only runs during
# an actual Setup.exe run, never during an in-app file-sync update).

def claude_code_cli_installed() -> bool:
    """Cheap presence check — does `claude` resolve on PATH at all.
    Does not verify auth/token status; see check_token_expiry /
    has_api_key for that."""
    return shutil.which("claude") is not None


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
                        "the 🤖 Autonomous Task Queue panel above, then try again.")
    if not mcp_config_path:
        return False, ("No MCP config is set up yet. Click 'Generate MCP "
                        "Config' in the 🤖 Autonomous Task Queue panel above, "
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
    if not claude_code_cli_installed():
        default_install_dir = Path.home() / ".local" / "bin"
        if (default_install_dir / "claude.exe").exists():
            _add_to_user_path(default_install_dir)

    if claude_code_cli_installed():
        return True, "Installed successfully."
    detail = (r.stderr or r.stdout or "").strip()[:300]
    return False, f"Install did not complete — claude still not found on PATH. {detail}"


CLAUDE_CREDENTIALS_PATH = Path.home() / ".claude" / ".credentials.json"


def check_token_expiry() -> dict:
    """Reads ~/.claude/.credentials.json for the OAuth token's expiresAt
    field. Does NOT guarantee the token is actually still valid — Claude
    Code has multiple open bug reports where the silent refresh-token flow
    fails and a token can stop working well before its stated expiry. This
    is a best-effort early warning, not a guarantee; the reactive 401 check
    in a real run is the authoritative signal.
    Returns dict: {status, expires_at, days_remaining, detail}
    status is one of: "no_credentials", "unreadable", "expired",
    "expiring_soon" (<7 days), "ok"
    """
    if not CLAUDE_CREDENTIALS_PATH.exists():
        return {"status": "no_credentials", "expires_at": None,
                "days_remaining": None,
                "detail": "No Claude Code credentials found — run setup-token first."}
    try:
        data = json.loads(CLAUDE_CREDENTIALS_PATH.read_text(encoding="utf-8-sig"))
        expires_at_ms = data.get("expiresAt")
        if expires_at_ms is None:
            return {"status": "unreadable", "expires_at": None,
                     "days_remaining": None,
                     "detail": "credentials.json found but has no expiresAt field."}
        expires_dt = datetime.fromtimestamp(expires_at_ms / 1000, tz=timezone.utc)
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
                 "days_remaining": None, "detail": f"Could not read credentials: {e}"}


def build_setup_token_launch_args() -> list[str]:
    """Returns the argv for launching an interactive terminal running
    `claude setup-token`. Kept as a pure function (no subprocess.Popen
    call) so the command construction is independently testable without
    actually spawning a window during tests.
    Windows-specific: `cmd /k` keeps the window open after the command
    finishes so the user can see the result / any error, rather than the
    window vanishing the instant setup-token exits.
    """
    return ["cmd", "/k", "claude setup-token"]


def open_setup_token_terminal() -> tuple[bool, str]:
    """Actually launches the terminal. This is the one function in this
    module that opens a visible window — everything else is silent/
    background. Requires a human to complete the browser OAuth step that
    follows; this function only gets them to that point."""
    try:
        subprocess.Popen(build_setup_token_launch_args(),
                          creationflags=subprocess.CREATE_NEW_CONSOLE)
        return True, "Terminal opened — complete the browser sign-in it prompts for."
    except Exception as e:
        return False, str(e)




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


def install_scheduled_task(wrapper_script_path: Path, schedule_time: str,
                            enabled: bool = True) -> tuple[bool, str]:
    """Creates (or replaces) the Scheduled Task. `enabled=False` creates it
    DISABLED — used by the test harness below to prove the mechanism works
    without leaving anything live."""
    args = [
        "schtasks", "/create", "/tn", SCHEDULED_TASK_NAME,
        "/tr", f'"{wrapper_script_path}"',
        "/sc", "daily",
        "/st", schedule_time,
        "/f",  # overwrite if it already exists
    ]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()

    if not enabled:
        r2 = subprocess.run(["schtasks", "/change", "/tn", SCHEDULED_TASK_NAME, "/disable"],
                             capture_output=True, text=True)
        if r2.returncode != 0:
            return False, f"created but failed to disable: {(r2.stderr or r2.stdout).strip()}"

    return True, "ok"


def uninstall_scheduled_task() -> tuple[bool, str]:
    if not scheduled_task_exists():
        return True, "not present"
    r = subprocess.run(["schtasks", "/delete", "/tn", SCHEDULED_TASK_NAME, "/f"],
                        capture_output=True, text=True)
    return (r.returncode == 0), (r.stderr or r.stdout).strip()


# ── Audit log read (for the GUI's "View Audit Log" button) ──────────────

def read_audit_log_tail(n_lines: int = 200) -> str:
    if not AUDIT_LOG_PATH.exists():
        return "(no audit log yet — the log is written by a Claude Code hook on the first run)"
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-n_lines:])

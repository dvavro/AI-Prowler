"""
task_queue_automation.py — the Autonomous AI Task Queue, API keys only (2026-11-01 redesign).

David, 2026-11-01: "remove the CLI token method in the Task Queue and only use API tokens and we should use
the same API token that the agents use and then we can simplify the complex Install CLI and test dry run
setup complex processes." His choices: the scheduler is AI-Prowler itself (no Windows Scheduled Task); one
shared monthly budget with the agents; the agents' complex & customer Claude model; the old Task Queue keys
and the Claude CLI token are removed (re-entered by hand in 🔑 Agent API Key); the CLI is removed everywhere.

How a run works now
  * The key is the agents' key — 🔑 Agent API Key at the top of the Small Business tab
    (desk_agent_providers.load_agent_key). Claude → the agents' "complex & customer" model; Grok → the
    agents' Grok model.
  * AI-Prowler's own background scheduler (start_scheduler, started inside the running AI-Prowler's
    local server, personal installs only) wakes once a minute. At each check time it first looks at the
    queue itself — free, no AI call — and only calls the AI when something is due.
  * The AI works through AI-Prowler's own tools over this PC's local connection
    (http://localhost:8000/mcp, signed in with this install's Bearer Token) — never a second copy.
  * Every run is recorded in ~/.ai-prowler/agent_database/task_queue.db (table agent_runs, same layout as
    the agents'), so its cost counts in the agents' monthly budget, forecast, cost popup and alerts. A run
    doesn't start when the budget is used up, and stops partway if it would go past it.

Kept from the old module (other code uses them): load_config/save_config (the agents' model settings
live in the same file), purge_old_jobs, rotate_audit_log, read_audit_log_tail, retire_cli_ai_routing,
compute_next_checker_run, _HttpMCPClient, GROK_MODEL, XAI_API_URL.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

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
PENDING_TASKS_PATH = AI_PROWLER_HOME / "pending_tasks.json"
RUNS_DB_PATH = AI_PROWLER_HOME / "agent_database" / "task_queue.db"
SCHED_STATE_PATH = AI_PROWLER_HOME / "task_queue_scheduler.json"
RUN_LOCK_PATH = AI_PROWLER_HOME / "task_queue_run.lock"
AI_PROWLER_CONFIG_PATH = AI_PROWLER_HOME / "config.json"

# 2026-10-22: the removed Claude CLI AI routing — kept only so retire_cli_ai_routing() can clean up.
RETIRED_AI_ROUTING_TASK_NAME = "AI-Prowler-AIRoutingRunner"
RETIRED_AI_ROUTING_DIR = AI_PROWLER_HOME / "ai_routing"
RETIRED_ROUTE_TASK_LABEL = "AI Route Optimizer (full reasoning)"
RETIRED_AI_ROUTING_MARKER = AI_PROWLER_HOME / "cli_ai_routing_retired.marker"

# 2026-11-01: what the old CLI / Windows-Scheduled-Task Task Queue left behind (retire_legacy_queue).
LEGACY_HOME = AI_PROWLER_HOME
LEGACY_SCHEDULED_TASK_NAME = "AI-Prowler-QueueRunner"
LEGACY_MARKER_NAME = "task_queue_cli_retired.marker"
LEGACY_FILES = (
    "claude_api_key.txt", "grok_api_key.txt",                       # the Task Queue's own keys
    "claude_oauth_token.json", "claude_oauth_token.txt",            # the Claude CLI setup-token
    "setup_token_output.txt", "run_setup_token.bat",
    "run_ai_prowler_queue.bat", "batch_logon_granted.marker",
    "claude_mcp_config.json", "claude_mcp_config_now.json", "claude_mcp_config_running.json",
    "last_headless_run.json", "last_single_run.json", "command_debug.log",
)
LEGACY_DIRS = ("manual_run", "single_run")

PROVIDERS = {"claude": "claude_api", "grok": "grok_api"}            # Task Queue choice → agents' runner
PROVIDER_LABELS = {"claude": "Claude (Anthropic)", "grok": "Grok (xAI)"}

TASK_RUN_PROMPT = (
    "Run this AI-Prowler analysis task now. Its name is \"{label}\".\n\n"
    "{body}\n\n"
    "How to work: use AI-Prowler's own tools first for anything they can answer. When AI-Prowler has no "
    "tool or data for something the task asks for (weather details its weather tool leaves out, sunrise or "
    "sunset times, local events), use your general knowledge where that is enough{web}. Do exactly the "
    "outputs the task asks for (learnings, a saved report via save_analysis_report with task_id "
    "\"{task_id}\", an email) — nothing else. This is an unattended analysis: only READ the business data — "
    "never create, change, approve or delete jobs, invoices, tickets, bookings, customers or employees, never "
    "mark messages read (check_sms_replies with mark_read=false), and never message a customer unless the "
    "task explicitly says to. Don't create, change or delete tasks. AI-Prowler records this "
    "run and moves the task to its next time itself. Finish with a short, specific summary of what you "
    "found and what you saved or sent; if part of the task couldn't be done, say what and why."
)
QUEUE_RUNNER_PROMPT = TASK_RUN_PROMPT              # older name

DEFAULT_CONFIG = {
    "paused": False,                 # True = no task runs on its own (the master switch)
    "provider": "claude",            # "claude" | "grok" — the default AI for tasks that don't pick one
    "notify_on_complete": False,
    "notify_method": "sms",          # "sms" | "whatsapp"
    "web_search": True,              # Claude runs may use Anthropic's web search ($10 per 1,000 searches)
    "max_cost_per_run_usd": 1.0,     # a single run stops here even when the monthly budget has room
}

VALID_DAY_CODES = frozenset({"mon", "tue", "wed", "thu", "fri", "sat", "sun"})
DAY_CODES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


# ── config / status ──────────────────────────────────────────────────────────────────

def _migrate(cfg: dict) -> dict:
    """Old configs (CLI / Task Queue keys): keep the schedule and on/off, take the provider from the old
    auth choice, drop nothing (the agents' settings live in this file too)."""
    if "provider" not in cfg:
        old = str(cfg.get("api_key_provider") or "").lower()
        cfg["provider"] = "grok" if (cfg.get("use_api_key") and old in ("grok", "xai")) else "claude"
    if cfg.get("provider") not in PROVIDERS:
        cfg["provider"] = "claude"
    return cfg


def load_config() -> dict:
    merged = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            data = _ss_read_json(CONFIG_PATH)
            if isinstance(data, dict):
                merged.update(data)
                if "provider" not in data:
                    merged.pop("provider", None)
        except Exception:
            return _migrate(dict(DEFAULT_CONFIG))
    return _migrate(merged)


def save_config(cfg: dict) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    _ss_write_text(CONFIG_PATH, json.dumps(cfg, indent=2))


def load_last_run() -> dict | None:
    if not STATUS_PATH.exists():
        return None
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def _write_last_run(status: str, detail: str, task_count: int | None = None, cost: float | None = None) -> None:
    AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    _ss_write_text(STATUS_PATH, json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,              # "success" | "failure" | "nothing_due" | "skipped"
        "detail": detail,
        "task_count": task_count,
        "cost_usd": cost,
    }, indent=2))


def _audit(text: str) -> None:
    try:
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {text}\n")
        cap_audit_log()
    except Exception:
        pass


# ── which key / model / budget ───────────────────────────────────────────────────────

def runner(cfg: dict | None = None, task: dict | None = None) -> str:
    """The agents' runner name for a task: its own AI if it picked one, else the default —
    'claude_api' | 'grok_api'."""
    p = (task or {}).get("ai_provider") or _migrate(dict(cfg if cfg is not None else load_config())).get("provider")
    return PROVIDERS.get(p, "claude_api")


def model_for(cfg: dict | None = None, task: dict | None = None) -> str:
    """The task's own model if it picked one; else Claude → the agents' "complex & customer" model,
    Grok → the agents' Grok model."""
    import desk_agent_providers as prov
    cfg = cfg if cfg is not None else load_config()
    if task and task.get("ai_provider") and task.get("ai_model"):
        return task["ai_model"]
    return prov.model_for(runner(cfg, task), cfg)


def provider_of(cfg: dict | None = None, task: dict | None = None) -> str:
    return {v: k for k, v in PROVIDERS.items()}[runner(cfg, task)]


def has_key(cfg: dict | None = None, task: dict | None = None) -> bool:
    import desk_agent_providers as prov
    return prov.has_agent_key(runner(cfg, task))


def _load_key(cfg: dict, task: dict | None = None) -> str:
    import desk_agent_providers as prov
    return prov.load_agent_key(runner(cfg, task))


def runs_db_path() -> str:
    return str(RUNS_DB_PATH)


def _runs_conn():
    p = Path(RUNS_DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), timeout=15)
    con.execute("CREATE TABLE IF NOT EXISTS agent_runs (run_id INTEGER PRIMARY KEY, provider TEXT, model TEXT, "
                "started_at TEXT, ended_at TEXT, items INTEGER, ok INTEGER, input_tokens INTEGER, "
                "output_tokens INTEGER, cost_usd REAL, summary TEXT)")
    return con


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record_run(provider: str, model: str, started: str, items: int, ok: bool, usage: dict, cost: float,
                summary: str) -> None:
    try:
        con = _runs_conn()
        try:
            con.execute("INSERT INTO agent_runs (provider, model, started_at, ended_at, items, ok, input_tokens, "
                        "output_tokens, cost_usd, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (provider, model, started, _utc_iso(), int(items), 1 if ok else 0,
                         int(usage.get("input", 0)) + int(usage.get("cache_write", 0)) + int(usage.get("cache_read", 0)),
                         int(usage.get("output", 0)), round(float(cost), 5), (summary or "")[:1000]))
            con.commit()
        finally:
            con.close()
    except Exception as e:  # noqa: BLE001 — never lose the run over its record
        _audit(f"could not record the run's cost: {e}")


def _budget_settings() -> dict:
    """The shared budget settings (Service Desk's settings database holds them)."""
    import desk_db
    db = desk_db.default_db_path()
    desk_db.init_db(db)
    return desk_db.get_settings(db)


def budget_left(now: datetime | None = None) -> tuple:
    """(dollars left this month, budget). Spend counts every agent database plus the Task Queue's."""
    import desk_agent_budget as ab
    now = now or datetime.now().astimezone()
    s = _budget_settings()
    budget = float(s.get("agent_monthly_budget_usd") or 0)
    spent = ab.month_totals(ab.agent_db_paths(None, s), now.strftime("%Y-%m"))["cost"]
    return round(budget - spent, 4), budget


def _alert_budget(model: str) -> None:
    try:
        import desk_agent_budget as ab
        ab.check_and_alert(_budget_settings(), edition="solo", model=model)
    except Exception as e:  # noqa: BLE001
        _audit(f"budget alert check failed: {e}")


def run_cost(model: str, usage: dict, web_searches: int = 0) -> float:
    """Exact cost: cache writes at 1.25x input, cache reads at 0.1x input, web searches $0.01 each."""
    import desk_agent_providers as prov
    pr = prov.price_for(model) or (0.0, 0.0)
    c = (usage.get("input", 0) * pr[0] + usage.get("cache_write", 0) * pr[0] * 1.25
         + usage.get("cache_read", 0) * pr[0] * 0.10 + usage.get("output", 0) * pr[1]) / 1_000_000
    return round(c + 0.01 * int(web_searches or usage.get("web_searches", 0)), 5)


# ── the running AI-Prowler on this PC ────────────────────────────────────────────────

LOCAL_SERVER_URL = "http://localhost:8000"
NO_REMOTE_ACCESS_MSG = (
    "Remote access isn't set up on this PC (no Bearer Token), so the Task Queue has no connection to "
    "AI-Prowler's tools. Set it up in Settings → Remote Access, then try again.")


def _is_server() -> bool:
    try:
        cfg = json.loads(AI_PROWLER_CONFIG_PATH.read_text(encoding="utf-8-sig")) \
            if AI_PROWLER_CONFIG_PATH.exists() else {}
        return (str(cfg.get("edition", "")).strip().lower() == "business"
                and str(cfg.get("mode", "")).strip().lower() == "server")
    except Exception:
        return False


def _server_user_token(owner_id: str = "") -> str:
    """On a server (2026-11-02): the sign-in token of the person who owns the task — so a run sees exactly
    what that person may see in the apps, never more. No owner on the task (made in the server's own
    window) → the first active owner. Only owners and managers can have tasks; anyone else → ""."""
    try:
        data = json.loads((AI_PROWLER_HOME / "users.json").read_text(encoding="utf-8-sig")) or {}
    except Exception:
        return ""
    import re as _re_u
    owners, match = [], ""
    for tok, rec in (data.get("users") or {}).items():
        if not isinstance(rec, dict) or str(rec.get("status", "active") or "active").strip().lower() != "active":
            continue
        role = str(rec.get("role") or "").strip().lower()
        # the same id the server gives the user at sign-in (ai_prowler_mcp._make_user_id)
        uid = _re_u.sub(r"[\s_]+", "-", str(rec.get("name") or "").strip().lower())
        uid = _re_u.sub(r"-+", "-", _re_u.sub(r"[^a-z0-9-]", "", uid)).strip("-")
        if role == "owner":
            owners.append(tok)
        if owner_id and uid == str(owner_id).strip().lower() and role in ("owner", "manager"):
            match = tok
    if owner_id:
        return match
    return owners[0] if owners else ""


def _task_owner_email(task: dict | None) -> str:
    """Server: the email of the person a task belongs to (the first owner for tasks made in the server's
    own window). "" when not found."""
    tok = _bearer_token(task)
    if not tok:
        return ""
    try:
        data = json.loads((AI_PROWLER_HOME / "users.json").read_text(encoding="utf-8-sig")) or {}
        return str(((data.get("users") or {}).get(tok) or {}).get("email") or "").strip()
    except Exception:
        return ""


def _bearer_token(task: dict | None = None) -> str:
    if _is_server():
        return _server_user_token(str((task or {}).get("owner_user_id") or ""))
    try:
        cfg = json.loads(AI_PROWLER_CONFIG_PATH.read_text(encoding="utf-8-sig")) \
            if AI_PROWLER_CONFIG_PATH.exists() else {}
    except Exception:
        cfg = {}
    return str(cfg.get("remote_token") or "").strip()


def _server_answers(token: str, timeout: float = 3) -> bool:
    import urllib.request as _ur
    try:
        req = _ur.Request(LOCAL_SERVER_URL + "/health", headers={"Authorization": f"Bearer {token}"})
        with _ur.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


class _HttpMCPClient:
    """Minimal MCP client over the running AI-Prowler's local connection (Streamable HTTP):
    initialize, tools/list, tools/call."""

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
        req = _ur.Request(self._url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
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
        for msg in self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}, timeout):
            if isinstance(msg, dict) and msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"MCP {method} error: {msg['error']}")
                return msg.get("result")
        raise RuntimeError(f"MCP {method}: no reply from AI-Prowler")

    def initialize(self, timeout=60):
        result = self._request("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "ai-prowler-task-queue", "version": "2.0"},
        }, timeout=timeout)
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, 30)
        except Exception:
            pass
        return result

    def list_tools(self):
        return (self._request("tools/list") or {}).get("tools", [])

    def call_tool(self, name, arguments=None, timeout=300):
        res = self._request("tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout) or {}
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


# ── which tools a run is offered ─────────────────────────────────────────────────────

MAX_TOOLS = 120                  # xAI accepts at most 128 per request; Claude gets the same set
ESSENTIAL_TOOLS = (
    "save_analysis_report", "how_to_use_ai_prowler", "check_ai_prowler_status",
    "search_documents", "multi_query_search", "read_document", "expand_search_result",
    "get_knowledge_base_overview", "list_indexed_documents", "search_within_directory",
    "search_learnings", "record_learning", "list_learnings", "get_learning",
    "get_learning_stats", "get_learnings_report",
    "send_email", "send_sms", "send_whatsapp", "get_weather",
    # 2026-11-01 (David: "Find Problems is out of date ... doesn't include the service desk, booking and
    # scheduling, HR app"): the read tools the business analyses use are always offered, never cut by
    # MAX_TOOLS. Only the ones this install has are offered (HR tools exist on a server only).
    "read_job_spreadsheet", "get_board_updates", "get_ar_aging_report", "find_stale_customers",
    "get_working_days", "list_tickets", "ticket_summary", "ticket_report", "triage_inbox",
    "review_booking", "check_sms_replies", "list_sms_contacts_with_replies",
    "review_mileage_log", "get_mileage_report", "hr_get_task_digest", "hr_get_report",
)
GROUP_ORDER = ("core_kb", "self_learning", "agentic_analysis", "status_system", "email", "sms_whatsapp")
READ_ONLY_PREFIXES = ("get_", "read_", "list_", "find_", "search_", "check_", "export_",
                      "build_maps_url", "geocode_")
NEVER_OFFER = frozenset({
    "create_file", "write_file", "edit_file", "str_replace_in_file", "line_replace_in_file",
    "delete_file", "run_script", "run_script_start", "run_script_kill", "untrack_directory", "reindex_all",
    "restore_backup", "restore_job_database", "restore_tickets_database", "grant_access",
    "grant_write_access", "revoke_access", "revoke_write_access",
    # a task run never manages tasks — AI-Prowler records the run itself (2026-11-01)
    "create_analysis_task", "update_analysis_task", "delete_analysis_task", "complete_analysis_task",
    "queue_single_task", "get_pending_analysis_tasks", "get_all_queued_tasks", "list_analysis_tasks",
})


def select_tools(mcp_tools: list) -> list:
    """The MCP tool entries a run is offered: the queue essentials first, then whole feature groups,
    then read-only Jobs tools, then the rest — never anything that writes files, runs scripts or restores
    data. Capped at MAX_TOOLS."""
    by_name = {t.get("name", ""): t for t in (mcp_tools or []) if t.get("name")}
    avail = {n for n in by_name if n not in NEVER_OFFER}
    order = [n for n in ESSENTIAL_TOOLS if n in avail]
    try:
        import mcp_tool_catalog as _cat
        for g in GROUP_ORDER:
            order += sorted(n for n in _cat.tools_in_category(g) if n in avail and n not in order)
        order += sorted(n for n in _cat.tools_in_category("job_tracker")
                        if n in avail and n not in order and n.startswith(READ_ONLY_PREFIXES))
    except Exception:
        order += sorted(n for n in avail if n not in order and n.startswith(READ_ONLY_PREFIXES))
    order += sorted(n for n in avail if n not in order)
    return [by_name[n] for n in order[:MAX_TOOLS]]


def _schema(tool: dict) -> dict:
    s = tool.get("inputSchema")
    return s if isinstance(s, dict) and s.get("type") == "object" else {"type": "object", "properties": {}}


# ── the AI calls ─────────────────────────────────────────────────────────────────────

CLAUDE_URL = "https://api.anthropic.com/v1/messages"
XAI_API_URL = "https://api.x.ai/v1/chat/completions"
XAI_MODELS_URL = "https://api.x.ai/v1/models"
GROK_MODEL = "grok-4.3"
HTTP_TIMEOUT = 300
MAX_ROUNDS = 40
QUEUE_DEADLINE = 30 * 60
SINGLE_PROMPT_DEADLINE = 10 * 60
CLAUDE_MAX_TOKENS = 4096
WEB_SEARCH_TOOL = {"type": "web_search_20250305", "name": "web_search", "max_uses": 5}
SYSTEM_TEXT = ("You are running AI-Prowler's scheduled analysis task queue on your own — no person is "
               "watching and there is no one to answer questions. Be efficient: make the tool calls the "
               "tasks need, call complete_analysis_task for each task, then give a short final summary.")
http_post = None                 # tests: fn(url, body, headers) -> dict; None = the real HTTPS call


class RunError(RuntimeError):
    pass


def _post_json(url: str, body: dict, headers: dict) -> dict:
    if http_post is not None:
        return http_post(url, body, headers)
    import urllib.error as ue
    import urllib.request as ur
    req = ur.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with ur.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except ue.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:  # noqa: BLE001
            detail = str(e)
        raise RunError(f"HTTP {e.code}: {detail}") from None
    except Exception as e:  # noqa: BLE001
        raise RunError(f"request failed: {e}") from None


class _Spend:
    """Running usage and cost of one run, with its ceiling (budget left, per-run cap)."""

    def __init__(self, model: str, ceiling: float):
        self.model, self.ceiling = model, ceiling
        self.usage = {"input": 0, "cache_write": 0, "cache_read": 0, "output": 0, "web_searches": 0}

    def add(self, **kw):
        for k, v in kw.items():
            self.usage[k] = self.usage.get(k, 0) + int(v or 0)

    @property
    def cost(self) -> float:
        return run_cost(self.model, self.usage)

    def over(self) -> bool:
        return self.cost >= self.ceiling


def _with_cache_mark(messages: list) -> list:
    """A copy whose last content block carries a cache breakpoint, so each round re-reads the growing
    conversation from the cache (0.1x price) instead of paying full price for it again."""
    out = [dict(m) for m in messages]
    last = out[-1]
    content = last["content"]
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
    content = [dict(b) for b in content]
    if content and content[-1].get("type") in ("text", "tool_result"):
        content[-1]["cache_control"] = {"type": "ephemeral"}
    last["content"] = content
    return out


def _claude_loop(key, model, prompt, tools, client, spend, deadline, web_search) -> tuple:
    """Claude Messages API tool loop. Returns (ok, summary)."""
    tool_defs = [{"name": t["name"], "description": str(t.get("description") or "")[:1000],
                  "input_schema": _schema(t)} for t in tools]
    if tool_defs:
        tool_defs[-1] = dict(tool_defs[-1], cache_control={"type": "ephemeral"})
    if web_search:
        tool_defs.append(dict(WEB_SEARCH_TOOL))
    headers = {"Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"}
    system = [{"type": "text", "text": SYSTEM_TEXT, "cache_control": {"type": "ephemeral"}}]
    messages = [{"role": "user", "content": prompt}]
    for _round in range(MAX_ROUNDS):
        if time.time() > deadline:
            return False, "stopped: the run's time limit was reached before the queue finished"
        if spend.over():
            return False, f"stopped: the run reached its spending limit (${spend.ceiling:.2f})"
        body = {"model": model, "max_tokens": CLAUDE_MAX_TOKENS, "system": system,
                "tools": tool_defs, "messages": _with_cache_mark(messages)}
        try:
            data = _post_json(CLAUDE_URL, body, headers)
        except RunError as e:
            if web_search and "web_search" in str(e) and "400" in str(e):
                tool_defs = [t for t in tool_defs if t.get("type") != WEB_SEARCH_TOOL["type"]]
                web_search = False
                _audit("web search isn't available on this key — continuing without it")
                continue
            return False, f"Claude API call failed: {e}"
        u = data.get("usage") or {}
        spend.add(input=u.get("input_tokens"), cache_write=u.get("cache_creation_input_tokens"),
                  cache_read=u.get("cache_read_input_tokens"), output=u.get("output_tokens"),
                  web_searches=(u.get("server_tool_use") or {}).get("web_search_requests"))
        content = data.get("content") or []
        messages.append({"role": "assistant", "content": content})
        uses = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
        if not uses:
            if data.get("stop_reason") == "pause_turn":
                continue                                   # a long web search paused the turn — resume it
            text = "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
            return True, (text or "Run finished.").strip()[:4000]
        results = []
        for b in uses:
            _audit(f"[claude] tool_call {b.get('name')}")
            try:
                out, err = client.call_tool(b.get("name", ""), b.get("input") or {}), False
            except Exception as e:  # noqa: BLE001
                out, err = f"ERROR calling {b.get('name')}: {e}", True
            results.append({"type": "tool_result", "tool_use_id": b.get("id"),
                            "content": str(out)[:20000], "is_error": err})
        messages.append({"role": "user", "content": results})
    return False, f"stopped after {MAX_ROUNDS} tool rounds without a final summary"


def _grok_loop(key, model, prompt, tools, client, spend, deadline) -> tuple:
    """xAI chat-completions function-calling loop. Returns (ok, summary)."""
    fns = [{"type": "function", "function": {"name": t["name"],
                                             "description": str(t.get("description") or "")[:1000],
                                             "parameters": _schema(t)}} for t in tools]
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + key}
    messages = [{"role": "system", "content": SYSTEM_TEXT}, {"role": "user", "content": prompt}]
    for _round in range(MAX_ROUNDS):
        if time.time() > deadline:
            return False, "stopped: the run's time limit was reached before the queue finished"
        if spend.over():
            return False, f"stopped: the run reached its spending limit (${spend.ceiling:.2f})"
        body = {"model": model, "messages": messages, "tool_choice": "auto"}
        if fns:
            body["tools"] = fns
        try:
            data = _post_json(XAI_API_URL, body, headers)
        except RunError as e:
            return False, f"xAI API call failed: {e}"
        u = data.get("usage") or {}
        spend.add(input=u.get("prompt_tokens"), output=u.get("completion_tokens"))
        msg = ((data.get("choices") or [{}])[0]).get("message") or {}
        calls = msg.get("tool_calls") or []
        am = {"role": "assistant"}
        if msg.get("content"):
            am["content"] = msg["content"]
        if calls:
            am["tool_calls"] = [{"id": c.get("id"), "type": "function",
                                 "function": {"name": (c.get("function") or {}).get("name", ""),
                                              "arguments": (c.get("function") or {}).get("arguments") or "{}"}}
                                for c in calls]
        messages.append(am)
        if not calls:
            return True, (msg.get("content") or "Run finished.").strip()[:4000]
        for c in calls:
            fn = c.get("function") or {}
            raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except Exception:  # noqa: BLE001
                args = {}
            _audit(f"[grok] tool_call {fn.get('name')}")
            try:
                out = client.call_tool(fn.get("name", ""), args)
            except Exception as e:  # noqa: BLE001
                out = f"ERROR calling {fn.get('name')}: {e}"
            messages.append({"role": "tool", "tool_call_id": c.get("id"), "content": str(out)[:20000]})
    return False, f"stopped after {MAX_ROUNDS} tool rounds without a final summary"


# ── one task run (2026-11-01: every task has its own schedule — no queue) ────────────

LOCK_STALE_SEC = QUEUE_DEADLINE + 10 * 60


def _take_lock() -> bool:
    p = Path(RUN_LOCK_PATH)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and time.time() - p.stat().st_mtime < LOCK_STALE_SEC:
            return False
        p.write_text(f"{os.getpid()} {_utc_iso()}", encoding="utf-8")
        return True
    except OSError:
        return False


def _drop_lock() -> None:
    try:
        Path(RUN_LOCK_PATH).unlink(missing_ok=True)
    except OSError:
        pass


def why_not_ready(cfg: dict | None = None, task: dict | None = None) -> str:
    """'' when a run can start, else what's missing in plain words (no AI call, no network)."""
    cfg = cfg if cfg is not None else load_config()
    if not has_key(cfg, task):
        return (f"no {PROVIDER_LABELS[provider_of(cfg, task)]} API key saved — add it in 🔑 Agent API Key at "
                f"the top of the Small Business tab")
    if not _bearer_token(task):
        if _is_server():
            return ("the person this task belongs to isn't an active owner or manager on this server any more "
                    "— change it in the AI Analysis Tasks list or delete it")
        return NO_REMOTE_ACCESS_MSG
    try:
        left, budget = budget_left()
    except Exception:  # noqa: BLE001
        return ""
    if budget <= 0:
        return "the monthly AI budget is $0 (🔑 Agent API Key → Monthly budget)"
    if left <= 0:
        return f"this month's AI budget is used up (${budget:g}) — runs wait until the 1st"
    return ""


def build_prompt(cfg: dict, task: dict) -> str:
    import custom_tasks_manager as ctm
    web = (", and the web_search tool for anything current or specific that needs looking up"
           if runner(cfg, task) == "claude_api" and cfg.get("web_search", True)
           else " (there is no web search in this run — say so in your summary where it matters)")
    p = TASK_RUN_PROMPT.format(label=task.get("label", ""), body=ctm.build_task_prompt(task), web=web,
                               task_id=task.get("task_id", ""))
    # Server (2026-11-02): an emailed result goes to the person the task belongs to, not the company inbox.
    to = _task_owner_email(task) if _is_server() and task.get("output_email") else ""
    if to:
        p += f" Send the email to {to} (put that address in send_email's 'to')."
    if cfg.get("notify_on_complete"):
        tool = "send_sms" if cfg.get("notify_method", "sms") == "sms" else "send_whatsapp"
        p += (f" When you're done, call AI-Prowler's {tool} tool with a one- or two-sentence summary. If "
              f"{tool} isn't set up, skip this step silently.")
    return p


def run_task(task_id: str, trigger: str = "manual", timeout_sec: int | None = None) -> tuple:
    """Run one task now on its AI (its own, or the default) and the Agent API Key. Blocking — call it from
    a background thread. AI-Prowler records the run on the task (last result, cost) and moves it to its
    next time. trigger 'schedule' = AI-Prowler's scheduler: a run that can't start (no key, budget, no
    connection, the AI service unreachable) leaves the task due and is tried again an hour later.
    Returns (ok, detail). Never raises."""
    import custom_tasks_manager as ctm
    cfg = load_config()
    tasks = ctm.load_custom_tasks()
    task = ctm.get_task(tasks, task_id)
    if not task:
        return False, f"task {task_id} not found"
    label = task.get("label", task_id)

    def skip(why):
        _write_last_run("skipped", f"{label}: {why}")
        _audit(f"'{label}' skipped: {why}")
        if trigger == "schedule":
            fresh = ctm.load_custom_tasks()
            ctm.record_skip(fresh, task_id, why)
            ctm.save_custom_tasks(fresh)
        return False, why

    why = why_not_ready(cfg, task)
    if why:
        if "budget" in why:
            _alert_budget(model_for(cfg, task))
        return skip(why)
    if not _take_lock():
        return False, "another task is running right now — it will be tried again shortly"
    token, model, rn = _bearer_token(task), model_for(cfg, task), runner(cfg, task)
    started = _utc_iso()
    try:
        left, _budget = budget_left()
        ceiling = max(0.0, min(left, float(cfg.get("max_cost_per_run_usd") or DEFAULT_CONFIG["max_cost_per_run_usd"])))
        spend = _Spend(model, ceiling)
        if not _server_answers(token, timeout=5):
            return skip("AI-Prowler's local connection didn't answer (is AI-Prowler running?)")
        # (2026-11-02: no longer starts a new log file per run — see AUDIT_LOG_MAX_BYTES)
        _audit(f"'{label}' start ({trigger}) — {rn} {model}, limit ${ceiling:.2f}")
        client = _HttpMCPClient(token)
        try:
            client.initialize()
            tools = select_tools(client.list_tools())
            deadline = time.time() + (timeout_sec or QUEUE_DEADLINE)
            text, key = build_prompt(cfg, task), _load_key(cfg, task)
            if rn == "claude_api":
                ok, detail = _claude_loop(key, model, text, tools, client, spend, deadline,
                                          bool(cfg.get("web_search", True)))
            else:
                ok, detail = _grok_loop(key, model, text, tools, client, spend, deadline)
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"could not reach AI-Prowler's tools: {e}"
        finally:
            client.close()
        cost = spend.cost
        if not ok and not any(spend.usage.values()):
            return skip(detail)                                # the AI never answered — try again later
        _record_run(rn, model, started, 1, ok, spend.usage, cost, f"{label}: {detail}")
        fresh = ctm.load_custom_tasks()
        nxt = ctm.record_run(fresh, task_id, "completed" if ok else "failed", detail, cost)
        ctm.save_custom_tasks(fresh)
        _write_last_run("success" if ok else "failure", f"{label} — {detail[:220]}", 1, cost)
        _audit(f"'{label}' {'done' if ok else 'failed'} — ${cost:.4f}; next {nxt or 'manual'}: {detail[:300]}")
        _alert_budget(model)
        return ok, detail + f"\n\n(Cost of this run: ${cost:.4f})"
    except Exception as e:  # noqa: BLE001
        _write_last_run("failure", f"{label}: {e}")
        return False, str(e)
    finally:
        _drop_lock()


# ── AI-Prowler's own scheduler ───────────────────────────────────────────────────────

TICK_SECONDS = 60
_sched_thread = None
_sched_stop = threading.Event()


def scheduler_tick(now: datetime | None = None, run_fn=None) -> list:
    """One wake-up: run every auto-run task that's due (and phone ▶ Run now requests), one AI call each.
    A task that couldn't start waits an hour. Returns [(task_id, ok)] — or ['paused']."""
    import custom_tasks_manager as ctm
    if load_config().get("paused"):
        return ["paused"]
    now = now or datetime.now()
    out = []
    for t in ctm.load_custom_tasks():
        if not ctm.auto_runs_now(t, now) or ctm.skipped_recently(t, now):
            continue
        ok, _detail = (run_fn or (lambda tid: run_task(tid, "schedule")))(t["task_id"])
        out.append((t["task_id"], ok))
    return out


def start_scheduler() -> bool:
    """Start the background scheduler once (inside the running AI-Prowler's local server, personal only)."""
    global _sched_thread
    if _sched_thread and _sched_thread.is_alive():
        return False
    if os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip():
        return False                  # a test server must never run the owner's real tasks
    try:
        retire_queue()
    except Exception as e:  # noqa: BLE001
        _audit(f"queue retirement skipped: {e}")
    _sched_stop.clear()

    def loop():
        while not _sched_stop.wait(TICK_SECONDS):
            try:
                scheduler_tick()
            except Exception as e:  # noqa: BLE001
                _audit(f"scheduler tick failed: {e}")

    _sched_thread = threading.Thread(target=loop, name="task-scheduler", daemon=True)
    _sched_thread.start()
    return True


def stop_scheduler() -> None:
    _sched_stop.set()


def schedule_display(cfg: dict | None = None, now: datetime | None = None, tasks: list | None = None) -> dict:
    """{'on', 'display', 'next'} for the panel: paused or on, how many tasks run on their own and which
    one is next — from the tasks themselves, no system query."""
    import custom_tasks_manager as ctm
    cfg = cfg if cfg is not None else load_config()
    tasks = ctm.load_custom_tasks() if tasks is None else tasks
    now = now or datetime.now()
    auto = [t for t in tasks if t.get("auto_run") and t.get("schedule", "none") != "none"]
    if cfg.get("paused"):
        return {"on": False, "next": None, "display": f"⏸ Automatic runs paused — {len(auto)} task(s) wait"}
    if not auto:
        return {"on": True, "next": None,
                "display": "🟢 Automatic runs on — no task is set to run on its own yet (tick ⏱ Auto-run on a task)"}
    nxt = min(auto, key=lambda t: ctm.due_at(t) or datetime.max)
    at = ctm.due_at(nxt)
    when = ("now" if at and at <= now else
            f"{at:%a %b} {at.day} {at.strftime('%I:%M %p').lstrip('0')}" if at else "—")
    return {"on": True, "next": at.isoformat() if at else None,
            "display": f"🟢 Automatic runs on — {len(auto)} task(s) run on their own; next: "
                       f"{nxt.get('label', '')} ({when})"}


# Kept for older callers.
def get_scheduled_task_display_info() -> dict:
    d = schedule_display()
    return {"exists": d["on"], "enabled": d["on"], "display": d["display"], "next_run_time": d["next"]}


def retire_queue() -> list:
    """2026-11-01: the one-time move from the queue to per-task schedules (custom_tasks_manager.retire_queue),
    plus the Task Queue's old on/off: if it was on, the scheduled tasks keep running on their own."""
    import custom_tasks_manager as ctm
    done = ctm.retire_queue()
    cfg = load_config()
    if "enabled" in cfg:
        was_on = bool(cfg.pop("enabled"))
        for k in ("schedule_time", "schedule_end_time", "check_times_per_day", "active_days", "check_mode",
                  "check_interval_hours", "active_start_time", "active_end_time", "allowed_tools",
                  "mcp_config_path", "install_dir", "use_api_key", "api_key_provider"):
            cfg.pop(k, None)
        if was_on:
            tasks = ctm.load_custom_tasks()
            n = ctm.enable_auto_run_for_scheduled(tasks)
            if n:
                ctm.save_custom_tasks(tasks)
                done.append(f"{n} scheduled task(s) set to run on their own (the Task Queue was on)")
        cfg["paused"] = False
        save_config(cfg)
    return done


# ── retiring the old CLI / Windows Scheduled Task queue ──────────────────────────────

def _no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def legacy_task_present() -> bool:
    if os.name != "nt":
        return False
    try:
        r = subprocess.run(["schtasks", "/query", "/tn", LEGACY_SCHEDULED_TASK_NAME],
                           capture_output=True, text=True, timeout=20, creationflags=_no_window())
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def remove_legacy_task_elevated() -> tuple:
    """One-time button: remove the old Windows task with admin rights (one UAC prompt)."""
    if os.name != "nt":
        return False, "Windows only"
    try:
        r = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                            "Start-Process schtasks -ArgumentList '/delete','/tn','"
                            + LEGACY_SCHEDULED_TASK_NAME + "','/f' -Verb RunAs -Wait -WindowStyle Hidden"],
                           capture_output=True, text=True, timeout=120, creationflags=_no_window())
    except Exception as e:  # noqa: BLE001
        return False, str(e)
    if legacy_task_present():
        return False, ((r.stderr or r.stdout or "").strip()[:300] or "the old task is still there")
    return True, "removed"


def retire_legacy_queue(home: Path | None = None) -> list:
    """Clean up what the old CLI Task Queue left on this computer: its own API key files, the Claude CLI
    setup-token, wrapper scripts, MCP config files — and the Windows task "AI-Prowler-QueueRunner"
    (a plain delete; if Windows wants admin rights the panel shows a one-time button). Once clean it
    writes a marker and does nothing again. Returns what it did."""
    home = Path(home or LEGACY_HOME)
    marker = home / LEGACY_MARKER_NAME
    if marker.exists():
        return []
    done = []
    for name in LEGACY_FILES:
        p = home / name
        try:
            if p.exists():
                p.unlink()
                done.append(f"removed {name}")
        except OSError as e:
            done.append(f"could not remove {name}: {e}")
    for name in LEGACY_DIRS:
        p = home / name
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
            done.append(f"removed {name}/")
    task_left = False
    if os.name == "nt" and home == Path(AI_PROWLER_HOME) and legacy_task_present():
        try:
            d = subprocess.run(["schtasks", "/delete", "/tn", LEGACY_SCHEDULED_TASK_NAME, "/f"],
                               capture_output=True, text=True, timeout=20, creationflags=_no_window())
            task_left = d.returncode != 0
            done.append("removed the old AI-Prowler-QueueRunner Windows task" if not task_left else
                        "the old AI-Prowler-QueueRunner Windows task needs admin rights to remove")
        except Exception as e:  # noqa: BLE001
            task_left = True
            done.append(f"old Windows task check skipped: {e}")
    if not task_left:
        try:
            home.mkdir(parents=True, exist_ok=True)
            marker.write_text(datetime.now().isoformat(timespec="seconds") + "\n" + "\n".join(done),
                              encoding="utf-8")
        except OSError:
            pass
    return done


def retire_cli_ai_routing() -> list:
    """2026-10-22: clean up the removed Claude CLI AI routing (custom task, its on-demand Windows task and
    ~/.ai-prowler/ai_routing). Safe on every start — once clean it does nothing."""
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
            q = subprocess.run(["schtasks", "/query", "/tn", RETIRED_AI_ROUTING_TASK_NAME],
                               capture_output=True, text=True, timeout=20, creationflags=_no_window())
            if q.returncode == 0:
                d = subprocess.run(["schtasks", "/delete", "/tn", RETIRED_AI_ROUTING_TASK_NAME, "/f"],
                                   capture_output=True, text=True, timeout=20, creationflags=_no_window())
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
    if not any("skipped" in d for d in done) and not RETIRED_AI_ROUTING_DIR.exists():
        try:
            AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
            RETIRED_AI_ROUTING_MARKER.write_text(
                datetime.now().isoformat(timespec="seconds") + "\n" + "\n".join(done), encoding="utf-8")
        except Exception:
            pass
    return done


# ── logs and job cleanup ─────────────────────────────────────────────────────────────

# 2026-11-02 (David: "make sure they have size control"): the run log is capped by SIZE, not rotated
# at the start of every run. It used to start a new file only when a task run began — but AI-Prowler
# also writes a line for every tool call from every app (Claude Desktop, the phone, the Jobs app), so
# with no task runs it grew without limit, and with several runs in a row "Run log" only ever showed
# the last one. Now: when the file passes AUDIT_LOG_MAX_BYTES it becomes .log.1 (and .1 → .2), so the
# whole log is never more than about 3 × 512 KB.
AUDIT_LOG_MAX_BYTES = 512 * 1024
AUDIT_LOG_BACKUPS = 2


def audit_log_files() -> list:
    """The run log and its backups (.log.1, .log.2), newest first."""
    return [AUDIT_LOG_PATH] + [Path(str(AUDIT_LOG_PATH) + f".{i}") for i in range(1, AUDIT_LOG_BACKUPS + 1)]


def cap_audit_log(max_bytes: int = None) -> None:
    """Start a new run-log file once the current one passes max_bytes. Cheap (one stat). Never raises."""
    try:
        limit = AUDIT_LOG_MAX_BYTES if max_bytes is None else max_bytes
        if AUDIT_LOG_PATH.exists() and AUDIT_LOG_PATH.stat().st_size > limit:
            rotate_audit_log(AUDIT_LOG_BACKUPS)
    except Exception:
        pass


def clear_audit_log() -> bool:
    """Empty the run log and delete its backups (the Clear log button). Leaves one line saying when."""
    try:
        for p in audit_log_files()[1:]:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        AUDIT_LOG_PATH.write_text(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Log cleared\n",
                                  encoding="utf-8")
        return True
    except Exception:
        return False


def rotate_audit_log(max_backups: int = 2) -> None:
    """Move autonomous_run_audit.log to .log.1 (.1 → .2, the oldest dropped) and start an empty one.
    Called by cap_audit_log when the file gets too big. Never raises."""
    try:
        base = AUDIT_LOG_PATH
        if not base.exists():
            return
        for i in range(max_backups, 0, -1):
            src = Path(str(base) + f".{i}")
            dst = Path(str(base) + f".{i + 1}") if i < max_backups else None
            if dst is not None and src.exists():
                try:
                    src.replace(dst)
                except Exception:
                    pass
        try:
            base.replace(Path(str(base) + ".1"))
        except Exception:
            pass
        try:
            base.write_text("", encoding="utf-8")
        except Exception:
            pass
    except Exception:
        pass


def read_audit_log_tail(n_lines: int = 200) -> str:
    # 2026-11-02: reads back into .log.1 / .log.2 when the current file has fewer than n_lines, so
    # the newest history still shows right after the size limit started a fresh file.
    files = [p for p in audit_log_files() if p.exists()]
    if not files:
        return "(no audit log yet — it's written on the first run)"
    lines: list = []
    for p in files:                                    # newest file first
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines() + lines
        except Exception:
            continue
        if len(lines) >= n_lines:
            break
    return "\n".join(lines[-n_lines:])


def purge_old_jobs(max_age_days: int = 2) -> int:
    """Delete run_script_start job files in ~/.ai-prowler/jobs/ older than max_age_days (2026-10-08 policy:
    no legitimate script run takes 2 days). A job still marked running whose PID is alive is killed first.
    Returns how many jobs were deleted. Never raises."""
    deleted = 0
    try:
        jobs_dir = AI_PROWLER_HOME / "jobs"
        if not jobs_dir.exists():
            return 0
        cutoff = time.time() - (max_age_days * 86400)

        def _pid_alive_win(pid):
            try:
                out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                                     capture_output=True, text=True, timeout=10, creationflags=0x08000000).stdout
                return f"\"{pid}\"" in out
            except Exception:
                return False

        def _kill_tree_win(pid):
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, text=True,
                               timeout=30, creationflags=0x08000000)
            except Exception:
                pass

        def _delete_triplet(mani_path):
            ok = True
            for p in (mani_path, mani_path.with_suffix(".log"),
                      mani_path.with_name(mani_path.stem + "_wrapper.py")):
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    ok = False
            return ok

        for mani_path in jobs_dir.glob("job_*.json"):
            try:
                if mani_path.stat().st_mtime >= cutoff:
                    continue
                is_running, pid = False, None
                try:
                    mani = json.loads(mani_path.read_text(encoding="utf-8"))
                    is_running = (mani.get("status") == "running")
                    pid = mani.get("pid")
                except Exception:
                    pass
                if is_running and pid and _pid_alive_win(pid):
                    _kill_tree_win(pid)
                    try:
                        m = json.loads(mani_path.read_text(encoding="utf-8"))
                        m["status"] = "killed"
                        m["finished_at"] = datetime.now().isoformat()
                        mani_path.write_text(json.dumps(m, indent=2), encoding="utf-8")
                    except Exception:
                        pass
                if _delete_triplet(mani_path):
                    deleted += 1
            except Exception:
                pass
        for wrapper_path in jobs_dir.glob("*_wrapper.py"):
            try:
                if wrapper_path.stat().st_mtime >= cutoff:
                    continue
                if wrapper_path.with_name(wrapper_path.name[: -len("_wrapper.py")] + ".json").exists():
                    continue
                wrapper_path.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass
    return deleted

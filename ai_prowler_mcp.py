#!/usr/bin/env python3
"""
AI-Prowler MCP Server
=====================
Exposes AI-Prowler's RAG knowledge base as MCP tools so Claude Desktop
(and any other MCP-compatible agent) can query, index, and manage your
local document collection directly from a Claude conversation.

Transport : stdio  (required by Claude Desktop)
Protocol  : MCP 1.x via the official `mcp` Python SDK (FastMCP)

Install the MCP package:
    pip install mcp

Then register this server in Claude Desktop's config
(see claude_desktop_config_example.json for the exact snippet).

Author: AI-Prowler project
"""

# ── Critical env vars — must come before ANY library import ──────────────────
import os
import sys

# ── Windows console UTF-8 fix ────────────────────────────────────────────────
# Force stdout/stderr to UTF-8 so non-ASCII characters in learnings (em-dashes,
# emoji, smart quotes) don't trigger UnicodeEncodeError when ChromaDB or our
# logging code writes them. Critical on Windows where the default codepage is
# cp1252. errors='replace' ensures we never crash on stray bad characters —
# we'd rather lose a glyph than fail a delete or index operation.
try:
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr is not None and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
os.environ.setdefault('HF_HUB_DISABLE_TELEMETRY', '1')
os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')
os.environ.setdefault('TRANSFORMERS_VERBOSITY', 'error')
os.environ.setdefault('TRANSFORMERS_NO_ADVISORY_WARNINGS', '1')
# Prevent sentence-transformers from making HuggingFace update-check HTTP calls
# on every load. Model is cached locally; network checks add 4-5s to startup.
os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')

# Fix the HuggingFace double-backslash Errno 22 bug on Windows 10
if not os.environ.get('HF_HUB_CACHE'):
    from pathlib import Path as _P
    os.environ['HF_HUB_CACHE'] = str(_P.home() / '.cache' / 'huggingface' / 'hub')

# ── Ensure rag_preprocessor is importable ─────────────────────────────────────
# The MCP server must be placed in the same directory as rag_preprocessor.py
# (i.e. C:\Program Files\AI-Prowler).  We add that directory to sys.path so
# Python finds rag_preprocessor even when Claude Desktop launches this script
# from a different working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ── Suppress warnings so they don't corrupt the MCP stdio stream ─────────────
import warnings
warnings.filterwarnings('ignore')

import io
import json
import contextlib
import threading
import queue
import argparse
from pathlib import Path
from typing import Optional

# ── File logging — all output captured here since the window is hidden ────────
import logging
import traceback

_LOG_PATH = Path.home() / "AppData" / "Local" / "AI-Prowler" / "mcp_server.log"
_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# Keep last 3 log files by rotating on each startup
import glob as _glob, shutil as _shutil
for _i in range(2, 0, -1):
    _old = _LOG_PATH.with_suffix(f".log.{_i}")
    _prev = _LOG_PATH.with_suffix(f".log.{_i-1}") if _i > 1 else _LOG_PATH
    if _prev.exists():
        _shutil.copy2(str(_prev), str(_old))

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S.%f",   # millisecond precision for timing diagnosis
    handlers=[
        logging.FileHandler(str(_LOG_PATH), mode="w", encoding="utf-8"),
    ],
)
_log = logging.getLogger("ai_prowler_mcp")

# Patch the Formatter to actually emit milliseconds — Python's datefmt
# with strftime doesn't support %f natively, so we override formatTime.
class _MsFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        import datetime as _dt
        ct = _dt.datetime.fromtimestamp(record.created)
        return ct.strftime("%Y-%m-%d %H:%M:%S.") + f"{int(record.msecs):03d}"

for _h in logging.root.handlers:
    _h.setFormatter(_MsFormatter(
        fmt="%(asctime)s [%(levelname)-8s] %(message)s"
    ))

# Redirect stderr to the log file so crashes and tracebacks are captured too
class _StderrToLog:
    def write(self, msg):
        msg = msg.rstrip()
        if msg:
            _log.error("STDERR: %s", msg)
    def flush(self):
        pass

sys.stderr = _StderrToLog()

_log.info("=" * 60)
_log.info("AI-Prowler MCP server process started")
_log.info("Python : %s", sys.version)
_log.info("Script : %s", __file__)
_log.info("CWD    : %s", os.getcwd())
_log.info("=" * 60)

# ── MCP SDK ───────────────────────────────────────────────────────────────────
_log.info("Importing MCP SDK (FastMCP)…")
try:
    from mcp.server.fastmcp import FastMCP
    _log.info("MCP SDK imported OK")
    # Context enables per-request user threading in server mode (Phase B).
    # Optional: if a build lacks it, fall back to None so `ctx: Context = None`
    # tool params remain harmless (personal mode never reads ctx anyway).
    try:
        from mcp.server.fastmcp import Context
    except Exception:
        Context = None
        _log.warning("FastMCP Context not importable — server-mode user "
                     "threading will be unavailable (personal mode unaffected).")
except ImportError:
    _log.critical("FATAL: 'mcp' package not found. Run: pip install mcp")
    print(
        "ERROR: 'mcp' package not found.\n"
        "Install it with:  pip install mcp\n",
        file=sys.stderr,
    )
    sys.exit(1)

# ── AI-Prowler engine ─────────────────────────────────────────────────────────
#
# STARTUP SPEED FIX — patch requests timeout before rag_preprocessor import
# ──────────────────────────────────────────────────────────────────────────
# rag_preprocessor probes localhost:11434 (Ollama) at module-import time using
# the requests library with its own timeout= argument.  socket.setdefaulttimeout()
# has NO effect on requests — it ignores it entirely.  So the probe still hangs
# for the full requests timeout (3-4 seconds) even with the socket cap in place.
#
# Fix: monkeypatch requests.Session.request to cap any timeout to 0.8s for the
# duration of the import, then restore the original method in the finally block.
# Belt-and-suspenders: also cap socket timeout for any raw socket probes.
import socket as _socket
_pre_import_socket_timeout = _socket.getdefaulttimeout()
_socket.setdefaulttimeout(1.0)

_requests_patched      = False
_orig_session_request  = None
try:
    import requests as _requests_mod
    _orig_session_request = _requests_mod.Session.request

    def _fast_session_request(self, method, url, **kwargs):
        existing = kwargs.get('timeout', None)
        if existing is None or (isinstance(existing, (int, float)) and existing > 0.8):
            kwargs['timeout'] = 0.8
        elif isinstance(existing, tuple) and any(
            isinstance(v, (int, float)) and v > 0.8 for v in existing
        ):
            kwargs['timeout'] = 0.8
        return _orig_session_request(self, method, url, **kwargs)

    _requests_mod.Session.request = _fast_session_request
    _requests_patched = True
    _log.info("requests.Session.request patched: timeout capped to 0.8s during import")
except ImportError:
    pass   # requests not available yet; will be imported by rag_preprocessor

_log.info("Importing rag_preprocessor from: %s (Ollama probe timeout capped)", _HERE)
try:
    import rag_preprocessor as _engine
    from rag_preprocessor import (
        index_directory, index_file_list,
        scan_directory, scan_directory_for_changes,
        command_update,
        show_stats, clear_database,
        load_config,
        load_auto_update_list, add_to_auto_update_list,
        remove_directory_from_index,
        normalise_path,
    )

    # Run headless — disable the terminal spinner and GUI-mode code paths
    _engine.GUI_MODE  = False
    _engine._MCP_MODE = True

    # Load saved user config (chunk size, etc.)
    load_config()
    _log.info("rag_preprocessor imported OK")

except ImportError as _e:
    _log.critical("FATAL: Could not import rag_preprocessor: %s", _e)
    _log.critical(traceback.format_exc())
    print(
        f"ERROR: Could not import rag_preprocessor: {_e}\n"
        f"Make sure ai_prowler_mcp.py is in the same folder as rag_preprocessor.py.\n",
        file=sys.stderr,
    )
    sys.exit(1)

finally:
    # Restore socket timeout and requests patch regardless of outcome
    _socket.setdefaulttimeout(_pre_import_socket_timeout)
    if _requests_patched and _orig_session_request is not None:
        try:
            _requests_mod.Session.request = _orig_session_request
            _log.info("requests patch removed — normal timeouts restored")
        except Exception:
            pass
    _log.info("Import phase complete, socket timeout restored to: %s",
              _pre_import_socket_timeout)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

# ── Stdio-mode guard ─────────────────────────────────────────────────────────
# Set to True in the entry point BEFORE mcp.run(transport="stdio") is called.
# _capture_stdout() reads this flag at call-time to decide whether it is safe
# to redirect sys.stdout.  In stdio mode sys.stdout IS the MCP JSON-RPC pipe —
# replacing it (even briefly) corrupts the protocol and causes Claude Desktop
# to show "Claude's response was interrupted".
_STDIO_MODE = False  # bool — set True in stdio entry point before mcp.run()


@contextlib.contextmanager
def _capture_stdout():
    """
    Capture everything printed to stdout and return it as a StringIO buffer.

    STDIO MODE — safe no-op:
        sys.stdout is the MCP JSON-RPC pipe.  Redirecting it — even for a
        single tool call — corrupts the binary frame stream and causes Claude
        Desktop to drop the response ("response was interrupted").
        In stdio mode stdout is NOT redirected — it is the live MCP pipe.
        We simply yield an empty buffer without touching sys.stdout.

    HTTP MODE — normal redirect:
        sys.stdout is an ordinary terminal/pipe; temporarily replacing it is
        safe and lets us capture print()-based output from rag_preprocessor.
    """
    if _STDIO_MODE:
        # stdio: never touch sys.stdout — yield an empty buffer and return.
        yield io.StringIO()
        return

    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old


# ─────────────────────────────────────────────────────────────────────────────
# MCP server definition
# ─────────────────────────────────────────────────────────────────────────────

# ── FastMCP server — version-aware instructions ───────────────────────────────
# The instructions= parameter was added in mcp >= 1.2.0.
# We extract the text into _INSTRUCTIONS and detect support at runtime so the
# server starts cleanly on older installs and upgrades automatically benefit.
_INSTRUCTIONS = (
    "AI-Prowler is an Agentic RAG knowledge base WITH a self-learning memory layer. "
    "Claude retrieves raw chunks AND stored learnings directly, then synthesizes "
    "answers — no local LLM required.\n\n"

    "═══════════════════════════════════════════════════════════════\n"
    " MANDATORY SEARCH ORDER FOR EVERY USER QUESTION\n"
    "═══════════════════════════════════════════════════════════════\n"
    "You MUST run search_learnings(query=...) BEFORE answering ANY user\n"
    "question. No exceptions. The user uses AI-Prowler as a personal\n"
    "knowledge store for everything — not just business. Recipes,\n"
    "preferences, opinions, hobbies, how they like things done — any\n"
    "of these may live in the learnings store and override what your\n"
    "training data would say.\n\n"

    "  STEP 1 (ALWAYS, NO EXCEPTIONS):  search_learnings(query=...)\n"
    "    Self-learning is the AUTHORITATIVE override layer. It contains\n"
    "    the user's deliberate corrections, preferences, and lessons.\n"
    "    These are newer and more curated than anything in your training\n"
    "    data or the document index.\n"
    "    Run search_learnings BEFORE generating any answer, EVEN FOR:\n"
    "      • General world-knowledge questions ('what's a good recipe\n"
    "        for ribs', 'best way to clean windows', 'what wine pairs\n"
    "        with salmon') — the user may have recorded a personal\n"
    "        version that overrides the generic answer\n"
    "      • Definitional questions ('what is X') — the user may have\n"
    "        recorded their own working definition\n"
    "      • How-to questions — the user may have recorded their\n"
    "            preferred technique\n"
    "      • Recommendations of any kind\n"
    "      • Business / client / project questions\n"
    "    The ONLY questions you may skip search_learnings on are pure\n"
    "    arithmetic ('what is 7 * 13') and language translation, where\n"
    "    there's no plausible way a personal learning could apply.\n"
    "    When in doubt, SEARCH. The cost of an unnecessary search is\n"
    "    one tool call; the cost of missing a stored preference is the\n"
    "    user getting a wrong or generic answer.\n\n"

    "  STEP 2 (CONDITIONAL):  search_documents(query=...)\n"
    "    Run document RAG when the question is plausibly about\n"
    "    something in the indexed knowledge base — work documents,\n"
    "    contracts, manuals, case files, spreadsheets, the user's own\n"
    "    writing. Skip it for purely personal-preference questions\n"
    "    where no document is likely to be relevant (e.g. 'what's my\n"
    "    rib recipe' — that's a learning, not a document).\n\n"

    "  BLEND BOTH SOURCES IN YOUR ANSWER (when they don't conflict):\n"
    "    If a learning and a document chunk are about the same topic but\n"
    "    cover different aspects, COMBINE them in your response. Do not\n"
    "    pick one and discard the other.\n"
    "    Example — user asks 'how do I reach Rick?':\n"
    "      • Learning says: 'Rick prefers email; phone and Slack are secondary'\n"
    "      • Doc chunk says: 'Rick's email is rick@austin-underground.com,\n"
    "        cell is 555-0100, available on DWService for installs'\n"
    "      → Answer: 'Rick can be reached by email at rick@austin-underground.com\n"
    "        (his preferred channel — fastest response), or by phone at 555-0100\n"
    "        as backup. For installs, DWService remote sessions work well.'\n"
    "    The learning shapes the recommendation; the docs supply the specifics.\n\n"

    "  CONFLICT RESOLUTION (when sources actually disagree):\n"
    "    If a learning and a document chunk give CONTRADICTORY information,\n"
    "    THE LEARNING WINS. Surface both to the user, but apply the learning.\n"
    "    Example: a doc says 'invoice on Friday' but a learning says 'Crabby's\n"
    "    only processes invoices on Mondays' — recommend Monday and mention\n"
    "    the doc as outdated background.\n\n"

    "  LEARNING vs. TRAINING-DATA CONFLICT (the recipe case):\n"
    "    If search_learnings returns a personal version of something general\n"
    "    (e.g. the user's rib recipe vs. recipes you know from training),\n"
    "    THE STORED LEARNING WINS. Lead with the user's version. Do not\n"
    "    fall back on web search or generic recipes unless the user\n"
    "    explicitly asks for alternatives.\n\n"

    "  RELEVANCE INTERPRETATION:\n"
    "    Relevance labels on search_learnings results are now calibrated:\n"
    "      🟢 HIGH (≥ 0.70)     — near-identical phrasing match; trust fully\n"
    "      🟡 MODERATE (0.40+)  — solid semantic match; APPLY THIS\n"
    "      🟠 LOW (< 0.40)      — likely irrelevant; ignore unless title\n"
    "                             is obviously on-topic\n"
    "    Most legitimate matches will land in MODERATE — that band is\n"
    "    trustworthy. Do NOT skip a MODERATE result just because it isn't\n"
    "    HIGH. Only treat LOW as a signal to ignore, and even then check\n"
    "    the title before discarding.\n\n"

    "═══════════════════════════════════════════════════════════════\n"
    " DOCUMENT RAG — Detailed Tool Reference\n"
    "═══════════════════════════════════════════════════════════════\n"
    "After running search_learnings (Step 1), use these for Step 2 and beyond:\n"
    "  • get_knowledge_base_overview — orient: what's indexed, what topics\n"
    "  • list_indexed_documents      — browse files for a topic area\n"
    "  • search_documents            — PRIMARY document retrieval\n"
    "  • multi_query_search          — parallel searches across synonyms\n"
    "  • search_within_directory     — restrict to a specific case/project\n"
    "  • expand_search_result        — expand a cut-off result\n"
    "  • read_document               — read a document sequentially\n\n"
    "Use check_ai_prowler_status() to verify the knowledge base is healthy.\n\n"

    "═══════════════════════════════════════════════════════════════\n"
    " SELF-LEARNING — Capture, Review, and Override\n"
    "═══════════════════════════════════════════════════════════════\n"

    "  AUTO-RECORDING — record WITHOUT being asked when you detect:\n"
    "    • User corrects a fact you stated or that exists in learnings\n"
    "    • User shares a project outcome, success, or failure\n"
    "    • User mentions a client preference or complaint\n"
    "    • A post-operation review reveals what went right or wrong\n"
    "    • New information contradicts an existing active learning\n"
    "      (in this case, ALSO pass supersedes_id with the old learning's UUID)\n"
    "    • User describes a process improvement or better approach\n"
    "    When auto-recording, ALWAYS set auto_detected=True so the\n"
    "    confirmation message flags this as your initiative.\n\n"

    "  CONFIRMATION PROTOCOL — ALWAYS follow after recording:\n"
    "    1. Tell the user WHAT you recorded (title + one-line summary)\n"
    "    2. Tell the user WHY you recorded it (the trigger you detected)\n"
    "    3. Ask: 'Is that correct, or should I adjust it?'\n"
    "    4. If the user says no or corrects you → call update_learning()\n"
    "       or delete_learning() immediately\n"
    "    NEVER record silently. The user must always see what was captured.\n\n"

    "  POST-OPERATION ANALYSIS workflow:\n"
    "    When asked to review/analyze a completed project or job:\n"
    "    1. Call search_learnings() FIRST to see existing learnings for this topic\n"
    "    2. Call search_within_directory() or search_documents() for full context\n"
    "    3. Identify: what went wrong, what went right, process gaps\n"
    "    4. For EACH insight, call record_learning() with proper category\n"
    "       and auto_detected=True\n"
    "    5. Present ALL recorded learnings to the user for confirmation\n"
    "    6. Adjust any the user disagrees with\n\n"

    "Tool sequence: search_learnings → search_documents → (record_learning if new info)"
)

import inspect as _inspect
_fastmcp_params = list(_inspect.signature(FastMCP.__init__).parameters.keys())
if "instructions" in _fastmcp_params:
    mcp = FastMCP("AI-Prowler", instructions=_INSTRUCTIONS)
    _log.info("FastMCP created with instructions= (mcp >= 1.2.0) — "
              "guidance sent to Claude at every handshake")
else:
    mcp = FastMCP("AI-Prowler")
    _log.warning(
        "FastMCP does not support instructions= on this version — "
        "falling back to how_to_use_ai_prowler() tool. "
        "Upgrade with: pip install --upgrade mcp"
    )
_log.info("FastMCP server object created OK")

# ══════════════════════════════════════════════════════════════════════════════
# Telemetry — track tool call counts per tool name on every successful
# invocation. Read by rag_gui.py's heartbeat sender, which resets the counter
# after a successful POST to the Cloudflare Worker.
#
# Counter file format (v2):
#     {"tool_calls": {"check_ai_prowler_status": 12, "search_documents": 3, ...}}
#
# v1 -> v2 migration is automatic on first read; old single-int totals are
# discarded (they aren't recoverable as per-tool buckets).
#
# Failure modes are all silent — telemetry must NEVER cause a tool call to
# fail. If the counter file is locked, missing, corrupted, or in a path the
# process can't write to, we just skip the increment and the user never sees
# anything go wrong.
# ══════════════════════════════════════════════════════════════════════════════
_TELEMETRY_COUNTER_PATH = (
    Path.home() / '.ai-prowler' / 'telemetry_counter.json')
_telemetry_lock = threading.Lock()


def _telemetry_increment_tool_count(tool_name='_unknown'):
    """Bump tool_calls[tool_name] by 1. Concurrency-safe, fail-silent."""
    try:
        with _telemetry_lock:
            data = {'tool_calls': {}}
            try:
                if _TELEMETRY_COUNTER_PATH.exists():
                    raw = _TELEMETRY_COUNTER_PATH.read_text(encoding='utf-8')
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        # v1 -> v2 migration: drop old single-int field
                        if 'tool_calls' in parsed and isinstance(
                                parsed['tool_calls'], dict):
                            data = parsed
                        else:
                            data = {'tool_calls': {}}
            except Exception:
                pass

            tc = data.setdefault('tool_calls', {})
            if not isinstance(tc, dict):
                tc = {}
                data['tool_calls'] = tc
            current = int(tc.get(tool_name, 0))
            tc[tool_name] = current + 1

            try:
                _TELEMETRY_COUNTER_PATH.parent.mkdir(
                    parents=True, exist_ok=True)
            except Exception:
                pass

            tmp = _TELEMETRY_COUNTER_PATH.with_suffix('.tmp')
            tmp.write_text(json.dumps(data), encoding='utf-8')
            os.replace(str(tmp), str(_TELEMETRY_COUNTER_PATH))
    except Exception as _e:
        _log.debug("telemetry counter update skipped: %s", _e)


# ── Monkeypatch mcp.tool() ───────────────────────────────────────────────────
import functools as _functools

_orig_mcp_tool = mcp.tool


def _counting_mcp_tool(*tool_args, **tool_kwargs):
    """Wrap mcp.tool() so each registered tool increments the per-tool
    counter on successful return. Uses fn.__name__ as the tool key."""
    real_decorator = _orig_mcp_tool(*tool_args, **tool_kwargs)

    def _outer(fn):
        _tool_name = getattr(fn, '__name__', '_unknown')

        @_functools.wraps(fn)
        def _inner(*args, **kwargs):
            result = fn(*args, **kwargs)
            _telemetry_increment_tool_count(_tool_name)
            return result
        return real_decorator(_inner)

    return _outer


mcp.tool = _counting_mcp_tool
_log.info("Monkeypatched mcp.tool() — all subsequent @mcp.tool decorators "
          "will increment ~/.ai-prowler/telemetry_counter.json by tool name "
          "on success")

# Module-level event set by the background prewarm thread when ChromaDB and
# the embedding model are fully loaded.  Tool handlers that need ChromaDB
# wait on this event (max 60s) before proceeding.
_prewarm_event = threading.Event()
_prewarm_event.set()   # default: don't block (overridden to clear() in stdio entry)

# ══════════════════════════════════════════════════════════════════════════════
# DB WRITER THREAD (v7.0.0)
# ──────────────────────────────────────────────────────────────────────────────
# ChromaDB's PersistentLocalHnswSegment has thread-affinity on its write/consumer
# path. Under the HTTP transport every tool runs on a ROTATING anyio threadpool
# worker, so a ChromaDB *write* (delete/add) arriving on a different thread than
# the one that owns the segment lock raises "resource deadlock would occur"
# (EDEADLK) and wedges the server — reproducibly, even for a 5-byte file.
#
# Fix: funnel ALL ChromaDB writes through ONE dedicated, long-lived thread. Tool
# handlers submit a callable + wait synchronously for its result. Because the
# same thread always performs the write, the segment lock affinity is never
# violated. Reads are left on the pool (they tolerate cross-thread access).
_db_write_queue: "queue.Queue" = queue.Queue()
_db_writer_started = threading.Event()
_db_writer_lock = threading.Lock()


def _db_writer_loop():
    """Single owner thread for ChromaDB writes. Runs submitted jobs serially."""
    _log.info("DB-writer thread started (tid=%s)", threading.get_ident())
    while True:
        fn, args, kwargs, result_box, done = _db_write_queue.get()
        try:
            result_box["result"] = fn(*args, **kwargs)
        except BaseException as exc:   # capture EVERYTHING, incl. EDEADLK OSError
            result_box["error"] = exc
        finally:
            done.set()
            _db_write_queue.task_done()


def _ensure_db_writer():
    """Start the writer thread once, lazily and thread-safely."""
    if _db_writer_started.is_set():
        return
    with _db_writer_lock:
        if _db_writer_started.is_set():
            return
        t = threading.Thread(target=_db_writer_loop, name="db-writer",
                             daemon=True)
        t.start()
        _db_writer_started.set()


def _db_write(fn, *args, timeout: float = 900.0, **kwargs):
    """Run fn(*args, **kwargs) on the dedicated DB-writer thread and return its
    result. Raises the worker's exception in the caller, or TimeoutError if the
    job does not finish within `timeout` seconds. This is what makes reindex
    safe on the HTTP transport — the write never touches the rotating pool."""
    _ensure_db_writer()
    result_box: dict = {}
    done = threading.Event()
    _db_write_queue.put((fn, args, kwargs, result_box, done))
    if not done.wait(timeout=timeout):
        raise TimeoutError(
            f"DB write did not complete within {timeout:.0f}s "
            f"(job still running on db-writer thread)")
    if "error" in result_box:
        raise result_box["error"]
    return result_box.get("result")

# ══════════════════════════════════════════════════════════════════════════════
# GUIDANCE TOOL — how_to_use_ai_prowler
# ══════════════════════════════════════════════════════════════════════════════
# Bulletproof fallback that works on ALL FastMCP versions.
# When instructions= is not supported by the installed mcp package, Claude
# reads this tool's docstring and calls it naturally at the start of sessions.
# Even when instructions= IS supported, this tool gives Claude an on-demand
# reference it can re-read during any conversation.
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def how_to_use_ai_prowler() -> str:
    """
    Returns the recommended workflow for using AI-Prowler as an Agentic RAG
    knowledge base with Claude.

    CALL THIS TOOL FIRST at the start of any new research or question-answering
    session to understand the correct tool sequence and capabilities.

    Returns:
        Step-by-step guidance on which tools to use and in what order,
        plus key facts about capabilities.
    """
    import mcp as _mcp_pkg
    try:
        mcp_version = _mcp_pkg.__version__
    except Exception:
        mcp_version = "unknown"

    instructions_active = "instructions" in _fastmcp_params

    return (
        "AI-Prowler — Agentic RAG Knowledge Base\n"
        + "=" * 50 + "\n\n"

        "TOOL CATEGORIES (30 tools total)\n"
        + "-" * 30 + "\n"
        "AI-Prowler exposes five tool families. Most question-answering\n"
        "tasks use the first two; the others are for code, actions and admin.\n\n"

        "  • Knowledge retrieval (RAG over indexed documents):\n"
        "      get_knowledge_base_overview, list_indexed_documents,\n"
        "      list_indexed_directories, search_documents, search_within_directory,\n"
        "      multi_query_search, expand_search_result,\n"
        "      read_document\n\n"

        "  • Code-aware retrieval (exact match + line-accurate reads):\n"
        "      grep_documents, read_file_lines\n\n"

        "  • Self-learning memory (corrections, post-mortems, preferences):\n"
        "      search_learnings, record_learning, list_learnings,\n"
        "      update_learning, delete_learning, get_learning_stats\n\n"

        "  • Field service actions (free public APIs, no key needed):\n"
        "      geocode_address, get_weather, optimize_route,\n"
        "      build_maps_url, read_job_spreadsheet, update_job_spreadsheet,\n"
        "      check_tools_status\n\n"

        "  • Indexing & admin:\n"
        "      index_path, update_tracked_directories,\n"
        "      list_tracked_directories, untrack_directory,\n"
        "      get_database_stats, check_ai_prowler_status\n\n"

        "PREFERRED TOOL SEQUENCE — KNOWLEDGE RETRIEVAL\n"
        + "-" * 30 + "\n"
        "Use these tools in order for any research or question-answering task:\n\n"

        "  STEP 1  get_knowledge_base_overview()\n"
        "    Orient yourself: see what documents are indexed, file types,\n"
        "    topics covered, tracked directories, and directory tree.\n\n"

        "  STEP 2  list_indexed_documents(filter_ext, filter_path)\n"
        "    Browse specific files when the user asks about a particular\n"
        "    document, company, or topic area.\n\n"

        "  STEP 3  list_indexed_directories()\n"
        "    See the directory tree of all indexed content. Use this to\n"
        "    identify the right scope for targeted searches.\n\n"

        "  STEP 4  search_documents(query, n_results)\n"
        "    PRIMARY retrieval. Call MULTIPLE TIMES with different\n"
        "    phrasings to gather full context. Example:\n"
        "      search_documents('refund policy')\n"
        "      search_documents('money back guarantee')\n\n"

        "  STEP 5  search_within_directory(query, directory, n_results)\n"
        "    TARGETED retrieval. Use when the user asks about a specific\n"
        "    case, project, client, or folder. Restricts search to only\n"
        "    chunks from that directory tree — prevents cross-contamination.\n"
        "    Example:\n"
        "      search_within_directory('summary of damages', 'Smith_v_Jones')\n\n"

        "  STEP 6  multi_query_search(queries)\n"
        "    Parallel search when a topic has synonyms or multiple angles.\n"
        "    More efficient than calling search_documents() repeatedly.\n\n"

        "  STEP 7  expand_search_result(filename, chunk_index)\n"
        "    Expand around a result that appears cut off or references\n"
        "    content in the surrounding paragraphs.\n\n"

        "  STEP 8  read_document(filename, start_chunk)\n"
        "    Read a whole document sequentially for full summaries or\n"
        "    when the user asks about a specific document's contents.\n\n"

        "CODE-AWARE RETRIEVAL — FOR PROGRAM FILES\n"
        + "-" * 30 + "\n"
        "Semantic search degrades on source code. When the user asks about\n"
        "code (symbols, definitions, call sites, TODOs), use this pair\n"
        "INSTEAD OF search_documents — same workflow Claude Code uses.\n\n"

        "  STEP C1  grep_documents(pattern, filter_ext, filter_path)\n"
        "    Locate exact matches with real line numbers. Use for any\n"
        "    'where is X defined / called / used' question.\n"
        "    Examples:\n"
        "      grep_documents('def clear_database', filter_ext='.py')\n"
        "      grep_documents('TODO', filter_path='rag_')\n"
        "      grep_documents(r'class \\w+Error', regex=True)\n\n"

        "  STEP C2  read_file_lines(filepath, start_line, end_line)\n"
        "    After grep, extract the surrounding function or block at\n"
        "    original fidelity. Returns numbered lines so you can keep\n"
        "    paging through with start_line=last_seen+1.\n\n"

        "  Both tools read only files under the tracked-paths allowlist.\n"
        "  Useful especially for mobile users who cannot attach files —\n"
        "  ask them to index_path() the project once, then\n"
        "  use grep + read_file_lines for all subsequent code questions.\n\n"

        "EDITING FILES — REINDEX WHEN DONE (v7.0.0)\n"
        + "-" * 30 + "\n"
        "Write tools (create_file, write_file, str_replace_in_file,\n"
        "restore_backup) NO LONGER auto-index. They write to disk and create\n"
        "backups, but ChromaDB is NOT updated until you ask for it.\n"
        "  • Make ALL your edits to a file first (any number of\n"
        "    str_replace_in_file calls).\n"
        "  • When you are DONE editing that file, call reindex_file(path)\n"
        "    ONCE to sync it into the database.\n"
        "  • Do NOT call reindex_file between every edit — one call at the\n"
        "    end of the edit session per file is correct.\n"
        "  • For a whole folder, use reindex_directory() / index_path()\n"
        "    instead of many reindex_file() calls.\n"
        "  Rationale: re-embedding on every write deadlocked the HTTP server\n"
        "  on large files; explicit end-of-session reindex avoids that.\n\n"

        "SELF-LEARNING WORKFLOW — PERSISTENT MEMORY\n"
        + "-" * 30 + "\n"
        "Stored learnings are corrections, post-mortems, and preferences\n"
        "captured from prior sessions. They override built-in knowledge\n"
        "and represent the operator's verified ground truth. Use them.\n\n"

        "  STEP A  search_learnings(query)\n"
        "    Call BEFORE answering ANY user question. No exceptions for\n"
        "    questions that look like general knowledge — the user may\n"
        "    have recorded a personal version of a recipe, technique,\n"
        "    preference, or recommendation that overrides what your\n"
        "    training data would suggest. If a learning contradicts your\n"
        "    built-in knowledge or any web search result, prefer the\n"
        "    learning.\n"
        "    The ONLY questions you may skip on are pure arithmetic and\n"
        "    language translation. When in doubt, search.\n"
        "    Triggers that GUARANTEE a search_learnings call:\n"
        "      - User asks 'what's a good X' / 'how do I X' / 'recommend X'\n"
        "      - User says 'what did we learn about...', 'do you remember...'\n"
        "      - User mentions a client, project, recipe, or case by name\n"
        "      - You're about to make a recommendation of any kind\n"
        "      - You're about to state a fact that may have been corrected\n\n"

        "  STEP B  record_learning(category, content, ...)\n"
        "    Auto-record (without being asked) when the user:\n"
        "      - Corrects a fact you stated\n"
        "      - Shares a project outcome or post-mortem\n"
        "      - States a client preference or standing instruction\n"
        "      - Says 'next time we should...' or similar\n"
        "      - Provides info that contradicts an existing active learning\n\n"

        "  STEP C  list_learnings() / get_learning_stats()\n"
        "    Browse stored learnings when the user asks for an overview\n"
        "    of what's remembered, or before bulk updates.\n\n"

        "  STEP D  update_learning(id, ...) / delete_learning(id)\n"
        "    Refine or retire learnings when the user provides better\n"
        "    information. Always confirm destructive actions first.\n\n"

        "DOCUMENT PROVENANCE — CRITICAL\n"
        + "-" * 30 + "\n"
        "  Every search result includes rich provenance metadata:\n"
        "    - parent_directory: immediate folder name\n"
        "    - directory_chain: breadcrumb path from root to file\n"
        "    - document_id: SHA-256 content fingerprint (unique per file)\n"
        "    - doc_title: extracted document title (from PDF/DOCX/PPTX)\n"
        "    - file_modified: last modification date of the source file\n"
        "    - [SOURCE: ...] header embedded in every chunk's text\n\n"

        "  RULES FOR ANSWERING:\n"
        "  1. ALWAYS verify that ALL chunks you cite come from the SAME\n"
        "     document or directory group before synthesizing an answer.\n"
        "  2. If chunks from DIFFERENT parent_directory values appear in\n"
        "     results, explicitly tell the user which source each piece\n"
        "     of information comes from.\n"
        "  3. NEVER blend facts from chunks with different document_id or\n"
        "     parent_directory values into a single statement without\n"
        "     clear attribution.\n"
        "  4. If the user asks about a specific case/project/client, use\n"
        "     search_within_directory() to restrict search to that scope.\n"
        "  5. When multiple files share the same name (e.g. 'complaint.pdf'\n"
        "     in different case folders), use parent_directory and\n"
        "     directory_chain to distinguish them for the user.\n\n"

        "KEY FACTS\n"
        + "-" * 30 + "\n"
        "  - NO Ollama required — no local LLM involved at all.\n"
        "  - Claude receives RAW CHUNKS and synthesizes answers directly.\n"
        "  - For complex questions, always search multiple times before answering.\n"
        "  - Stored learnings outrank built-in knowledge — always search_learnings\n"
        "    before answering ANY user question (the only exceptions are pure\n"
        "    arithmetic and language translation).\n"
        "  - Use check_ai_prowler_status() to verify the knowledge base is healthy.\n"
        "  - Use check_tools_status() to verify field-service tools.\n"
        "  - Re-call this tool any time you need a reminder of the workflow.\n\n"

        f"MCP SDK version       : {mcp_version}\n"
        f"instructions= active  : {'yes — guidance sent at every handshake' if instructions_active else 'no — upgrade with: pip install --upgrade mcp'}\n"
        "AI-Prowler Agentic RAG ready."
    )


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — index_path
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def index_path(
    directory: str,
    recursive: bool = True,
    track: bool = True,
    ctx: Context = None,
) -> str:
    """
    Index all supported documents inside a local folder OR a single file
    and (optionally) add it to the auto-update tracking list.

    Accepts either:
      • A directory path — every supported file inside is indexed (subject
        to smart-scan extension/directory filters). Recursion controlled by
        the `recursive` argument.
      • An individual file path — that one file is indexed regardless of
        the smart-scan extension filters. Per-file tracking is explicit
        user opt-in, so SKIP_EXTENSIONS does not apply.

    Supported formats: PDF, Word, Excel, PowerPoint, plain text, code,
    Markdown, HTML, email (.msg / .eml / .mbox), images (OCR), and many more.

    Args:
        directory:  Absolute path to the folder OR file you want to index.
                    Examples:
                      "C:/Users/David/Documents/ProjectDocs"
                      "C:/Program Files/AI-Prowler/COMPLETE_USER_GUIDE.md"
        recursive:  Include sub-folders when indexing a directory (default True).
                    Ignored for single-file targets.
        track:      Add the path to the auto-update list so future
                    `update_tracked_directories` calls will pick up changes
                    (default True).

    Returns:
        Summary of how many files were indexed and any errors encountered.
    """
    target = Path(directory)
    if not target.exists():
        return f"❌ Path not found: {directory}"

    load_config()

    # v7.0.0 Phase B: in server mode build the per-user write controls. Personal
    # mode (no authenticated user) leaves all three None → pipeline unchanged.
    #   • resolver   — routes each file to its scoped collection (WHERE), with
    #                  _can_index enforced inside the resolver (WHETHER).
    #   • indexer_user— stamps indexed_by for the ownership model.
    #   • purge_gate  — blocks overwriting/destroying chunks the user doesn't own.
    _user = _current_user(ctx)
    _resolver = _build_collection_resolver(_user) if _user else None
    _indexer_user = _user
    _purge_gate = None
    if _user:
        _oid = _owner_user_id()
        _purge_gate = lambda metas: _can_purge_chunks(_user, metas, _oid)

    is_file = target.is_file()

    with _capture_stdout() as buf:
        try:
            if is_file:
                # Single-file path — bypass SKIP_EXTENSIONS smart-scan filter
                from rag_preprocessor import index_file_list, normalise_path
                fp = normalise_path(str(target.resolve()))
                stats = index_file_list(
                    [fp],
                    label="1/1",
                    root_directory=str(target.parent),
                    collection_resolver=_resolver,
                    indexer_user=_indexer_user,
                    purge_gate=_purge_gate,
                )
                chunks = stats.get('chunks', 0) if stats else 0
                print(f"✅ Indexed file: {target.name} — {chunks} chunk(s)")
            else:
                index_directory(str(target), recursive=recursive,
                                collection_resolver=_resolver,
                                indexer_user=_indexer_user,
                                purge_gate=_purge_gate)
        except Exception as exc:
            return f"❌ Indexing failed: {exc}"

    output = buf.getvalue().strip()

    if track:
        try:
            # For directories, index_directory already adds to the auto-update
            # list via add_to_auto_update_list(). Calling it again is a no-op
            # (returns False) but ensures file targets are added too.
            added = add_to_auto_update_list(str(target.resolve()))
            kind = "File" if is_file else "Directory"
            note = (
                f"\n✅ {kind} added to auto-update tracking."
                if added
                else f"\nℹ️  {kind} was already in the tracking list."
            )
            output += note
        except Exception as exc:
            output += f"\n⚠️  Could not add to tracking list: {exc}"

    return output if output else "✅ Indexing complete (no output produced)."


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — update_tracked_directories
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def update_tracked_directories(directory: Optional[str] = None,
                               ctx: Context = None) -> str:
    """
    Re-scan all tracked paths (directories AND individually-tracked files) for
    new, modified, or deleted files and update the index incrementally — only
    changed files are re-indexed.

    Args:
        directory:  If provided, update only this specific path (directory
                    or file). If omitted, update ALL tracked paths.

    Returns:
        A summary of changes detected and files re-indexed.
    """
    load_config()

    # v7.0.0 Phase B: server-mode write controls (None in personal mode →
    # pipeline unchanged). Same trio as index_path. The purge gate
    # matters especially here: command_update PURGES deleted files (destructive).
    _user = _current_user(ctx)
    _resolver = _build_collection_resolver(_user) if _user else None
    _purge_gate = None
    if _user:
        _oid = _owner_user_id()
        _purge_gate = lambda metas: _can_purge_chunks(_user, metas, _oid)

    dirs_to_update: list[str] = []
    if directory:
        dirs_to_update = [directory]
    else:
        dirs_to_update = load_auto_update_list()

    if not dirs_to_update:
        return (
            "ℹ️  No tracked paths found.\n"
            "Use index_path first to index a folder or file and add it to tracking."
        )

    with _capture_stdout() as buf:
        for d in dirs_to_update:
            try:
                command_update(d, recursive=True, auto_confirm=True,
                                collection_resolver=_resolver,
                                indexer_user=_user,
                                purge_gate=_purge_gate)
            except Exception as exc:
                print(f"⚠️  Error updating {d}: {exc}")

    return buf.getvalue().strip() or "✅ All tracked paths are up to date."


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — get_database_stats
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def get_database_stats(ctx: Context = None) -> str:
    """
    Return statistics about the indexed knowledge base: total chunk count,
    number of unique documents, breakdown by file type, and database location.

    Returns:
        A formatted statistics report.
    """
    # Build stats directly from ChromaDB rather than capturing show_stats()
    # print output.  This is safe in BOTH stdio mode (where sys.stdout is the
    # MCP pipe and must never be redirected) and HTTP mode.
    try:
        from rag_preprocessor import CHROMA_DB_PATH
        try:
            _collections = _scoped_collections_for_ctx(ctx)
        except RuntimeError:
            return "📭 Database is empty or not yet created."

        total_chunks = 0
        metadatas = []
        for _col in _collections:
            c = _col.count()
            total_chunks += c
            if c:
                sample = _col.get(limit=min(5000, c), include=["metadatas"])
                metadatas.extend(sample.get('metadatas', []))
        if total_chunks == 0:
            return "📭 Database is empty."

        unique_files: dict = {}
        ext_counts:   dict = {}
        for m in metadatas:
            fp  = m.get('filepath', '')
            ext = m.get('extension', 'unknown').lower().lstrip('.') or 'other'
            if fp not in unique_files:
                unique_files[fp] = ext
                ext_counts[ext] = ext_counts.get(ext, 0) + 1

        lines = [
            "📊 AI-Prowler Database Statistics",
            "─" * 40,
            f"  Total chunks     : {total_chunks:,}",
            f"  Unique documents : {len(unique_files):,}",
            f"  Database path    : {CHROMA_DB_PATH}",
            "",
            "  Documents by type:",
        ]
        for ext in sorted(ext_counts.keys()):
            lines.append(
                f"    {ext.upper():>8} : {ext_counts[ext]:,} file(s)"
            )
        return "\n".join(lines)

    except Exception as exc:
        return f"❌ Could not retrieve stats: {exc}"


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — list_tracked_directories
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def list_tracked_directories() -> str:
    """
    List all paths (directories AND individually-tracked files) currently
    registered for auto-update tracking.

    Each entry is annotated with its type — 📁 for directories, 📄 for files —
    so it's clear which entries are watched as folders vs. as single files.

    Returns:
        A formatted list of tracked paths, or a message if none are registered.
    """
    dirs = load_auto_update_list()
    if not dirs:
        return (
            "ℹ️  No paths are currently tracked.\n"
            "Use index_path to index a folder or file and add it to tracking."
        )
    lines = ["📁 Tracked paths:"]
    for i, d in enumerate(dirs, 1):
        try:
            icon = "📄" if Path(d).is_file() else ("📁" if Path(d).exists() else "❓")
        except Exception:
            icon = "❓"
        lines.append(f"  {i}. {icon} {d}")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 6 — untrack_directory
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def untrack_directory(directory: str) -> str:
    """
    Remove a tracked path (directory OR individually-tracked file) from the
    tracking list AND delete all of its indexed chunks from the ChromaDB
    knowledge base.

    This is a destructive operation — the documents from this path will no
    longer be searchable until you re-index them.

    Args:
        directory:  Absolute path to the directory or file to remove.

    Returns:
        A summary of what was removed.
    """
    with _capture_stdout() as buf:
        try:
            result = remove_directory_from_index(directory)
        except Exception as exc:
            return f"❌ Failed to remove path: {exc}"

    output = buf.getvalue().strip()
    if isinstance(result, dict):
        chunks = result.get('chunks_removed', 'unknown')
        files  = result.get('files_removed', 'unknown')
        output += f"\n✅ Removed {chunks} chunk(s) from {files} file(s)."
    return output or f"✅ Path removed: {directory}"


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 7 — check_ai_prowler_status
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def check_ai_prowler_status() -> str:
    """
    Check AI-Prowler's health: ChromaDB connectivity, embedding model status,
    document count, and database path. No Ollama or local LLM involved.

    Returns:
        A diagnostic status report for the Agentic RAG knowledge base.
    """
    # Wait for background prewarm (ChromaDB + embedding model) — max 25s.
    # Prewarm runs in a thread so mcp.run() could start before it finishes.
    _log.info("check_ai_prowler_status: tool called — waiting for prewarm if still running")
    if not _prewarm_event.wait(timeout=60):
        _log.warning("check_ai_prowler_status: prewarm timeout — returning early")
        return (
            "⏳ AI-Prowler is still initializing (ChromaDB + embedding model "
            "loading in background).\n\n"
            "This usually takes 15–60 seconds on first use after Claude Desktop "
            "starts. Please wait a moment and try again."
        )
    _log.info("check_status: prewarm ready, executing")

    from rag_preprocessor import get_chroma_client, COLLECTION_NAME, CHROMA_DB_PATH

    lines = ["🔍 AI-Prowler Status Check", "─" * 40]

    # ── ChromaDB & embedding model ────────────────────────────────────────────
    with _capture_stdout() as buf:
        try:
            client, embedding_func = get_chroma_client()
            collection = client.get_or_create_collection(
                name=COLLECTION_NAME,
                embedding_function=embedding_func
            )
            db_ok = True
            chunk_count = collection.count()
        except Exception as exc:
            db_ok = False
            chunk_count = 0
            db_error = str(exc)

    init_output = buf.getvalue().strip()

    if db_ok:
        lines.append("✅ ChromaDB  : connected")
        lines.append(f"   Chunks    : {chunk_count:,}")
        lines.append(f"   Database  : {CHROMA_DB_PATH}")
    else:
        lines.append("❌ ChromaDB  : not reachable")
        lines.append(f"   Error     : {db_error}")
        lines.append("   Try re-indexing with index_path.")

    # ── Embedding model info (parsed from init output) ────────────────────────
    # Bug fix v7.0.0: filter the captured stdout to ONLY surface the clean
    # "✅ Embedding model loaded on <device>" line emitted by rag_preprocessor.
    # The old filter accepted any line containing "Loading" or "embedding",
    # which on fresh installs caught HuggingFace's first-time download /
    # cache-resolution chatter and made the status check look like an error.
    # Reported by Rick, Jamie, and Sam during v6.0.2 installs (learning fe420ae5).
    lines.append("")
    emitted_embedding_line = False
    if init_output:
        for line in init_output.splitlines():
            s = line.strip()
            # Allowlist: only the clean rag_preprocessor confirmation line.
            # Look for the ✅ + "Embedding model loaded" signature, OR an
            # explicit device announcement we control.
            if ("Embedding model loaded" in s
                    or "Embedding model is loaded" in s):
                lines.append(f"   {s}")
                emitted_embedding_line = True
                break  # one line is enough — don't dump the rest
    if not emitted_embedding_line:
        lines.append("   Embedding model: loaded")

    # ── Empty-knowledge-base hint ─────────────────────────────────────────────
    # Bug fix v7.0.0: on a fresh install ChromaDB connects fine but has zero
    # chunks. The previous status output buried this fact under technical
    # diagnostics, leading users (Rick/Jamie/Sam) to think AI-Prowler was
    # broken. Lead with a clear "this is what's expected and here's how to
    # fix it" message so the first impression is friendly and actionable.
    if db_ok and chunk_count == 0:
        lines.append("")
        lines.append("ℹ️  Knowledge base is empty — this is normal on a fresh install.")
        lines.append("   To index your documents, either:")
        lines.append("     • Call index_path(\"<path>\") from this tool, OR")
        lines.append("     • Open the AI-Prowler GUI → Reindex tab → pick a folder.")
        lines.append("   Once indexed, search_documents and friends will return real results.")

    # ── Tracked paths (directories + individually-tracked files) ─────────────
    try:
        from rag_preprocessor import load_auto_update_list
        tracked = load_auto_update_list() or []
        n_files = sum(1 for p in tracked if Path(p).is_file())
        n_dirs  = sum(1 for p in tracked if Path(p).is_dir())
        lines.append("")
        suffix_parts = []
        if n_dirs:  suffix_parts.append(f"{n_dirs} dir(s)")
        if n_files: suffix_parts.append(f"{n_files} file(s)")
        suffix = f" ({', '.join(suffix_parts)})" if suffix_parts else ""
        lines.append(f"📁 Tracked paths : {len(tracked)}{suffix}")
        for d in tracked[:5]:
            try:
                icon = "📄" if Path(d).is_file() else ("📁" if Path(d).exists() else "❓")
            except Exception:
                icon = "❓"
            lines.append(f"   {icon} {d}")
        if len(tracked) > 5:
            lines.append(f"   ... and {len(tracked) - 5} more")
    except Exception:
        pass

    lines.append("")
    lines.append("✅ AI-Prowler Agentic RAG ready." if db_ok else "⚠️  Knowledge base unavailable.")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ░░  AGENTIC RAG TOOLS  ░░
# ══════════════════════════════════════════════════════════════════════════════


def _get_collection():
    """Return ChromaDB collection directly, using cached client/embedding."""
    from rag_preprocessor import get_chroma_client, COLLECTION_NAME
    client, embedding_func = get_chroma_client()
    try:
        col = client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )
        if col.count() == 0:
            raise RuntimeError(
                "No indexed documents found. "
                "Use index_path to index some documents first."
            )
        return col
    except RuntimeError:
        raise
    except Exception:
        raise RuntimeError(
            "No indexed documents found. "
            "Use index_path to index some documents first."
        )


def _scoped_collections_for_ctx(ctx):
    """Return the list of ChromaDB collection OBJECTS the current request may
    read. v7.0.0 Phase B Step 2 — the shared foundation for the read tools that
    access collections directly (via .get()/.query()) rather than delegating to
    rag_preprocessor.search_documents.

    Personal mode (no user on the request, i.e. ctx None or no .user): returns
    [the single default 'documents' collection] — byte-for-byte the old
    single-collection behavior, so these tools are unchanged for personal use.

    Server mode (a user is present): returns one collection object per entry in
    _allowed_collections(user), skipping any that don't exist yet. Logical scope
    names are sanitized to physical names via chroma_collection_name().

    Raises RuntimeError only in personal mode when nothing is indexed (preserves
    the existing _get_collection error contract for the tools' try/except).
    """
    from rag_preprocessor import (get_chroma_client, COLLECTION_NAME,
                                  chroma_collection_name)
    client, embedding_func = get_chroma_client()

    user = _current_user(ctx)
    if user is None:
        # Personal mode — single collection, original contract (raises if absent).
        try:
            return [client.get_collection(name=COLLECTION_NAME,
                                          embedding_function=embedding_func)]
        except Exception:
            raise RuntimeError(
                "No indexed documents found. "
                "Use index_path to index some documents first.")

    # Two SEPARATE elevated capabilities (decoupled by design):
    #   • read_all_role_scopes (role cap; owner has it) → read every role:*
    #     collection ("see all team knowledge bases").
    #   • can_manage_users (per-user flag in users.json, independent of role) →
    #     read every user:* PRIVATE collection ("data custodian": cleanup when an
    #     employee leaves, administer the database). This is deliberately a flag,
    #     not a role, so an owner can DELEGATE custody to e.g. an office manager
    #     without making them a full owner. NOTE: company-server user: collections
    #     are administrative workspace, NOT true privacy — real privacy is a
    #     separate AI-Prowler install on the employee's own PC. Communicate this
    #     to employees in onboarding.
    caps = _role_caps(user.get("role"))
    can_read_all_roles    = bool(caps.get("read_all_role_scopes")) or _is_admin(user)
    # Owner ALWAYS has custody (implicit can_manage_users); a non-owner needs the
    # flag explicitly set. The owner reads all privates incl. their own; admins
    # read all employees' privates but are blocked from the owner's (below).
    can_read_all_privates = _user_has_role(user, "owner") or bool(user.get("can_manage_users"))

    if can_read_all_roles or can_read_all_privates:
        # Build the elevated set from physical collections directly (avoids any
        # logical<->physical round-trip fragility). Always include the user's own
        # base set first (shared + own scopes + own private), then add the
        # elevated categories they're entitled to.
        cols = []
        seen = set()

        def _add_phys(phys):
            if phys in seen:
                return
            seen.add(phys)
            try:
                cols.append(client.get_collection(
                    name=phys, embedding_function=embedding_func))
            except Exception:
                pass  # not created yet — skip

        # The user's own base allowed set (shared + their scopes + own private).
        for logical in _allowed_collections(user, None):
            _add_phys(chroma_collection_name(logical))

        # Elevated role visibility.
        if can_read_all_roles:
            _add_phys(chroma_collection_name(_SHARED_COLLECTION))
            for phys in _enumerate_scope_collections(client, "scope-role-"):
                _add_phys(phys)

        # Elevated private/custody visibility (can_manage_users). The OWNER's
        # private collection is PROTECTED: an admin (can_manage_users but not the
        # owner) can read every employee's private collection EXCEPT the owner's.
        # The owner's private space is private even from their own admins. The
        # owner themself reads everything (they're not excluded from their own).
        if can_read_all_privates:
            requester_is_owner = _user_has_role(user, "owner")
            owner_id = None if requester_is_owner else _owner_user_id()
            owner_priv_phys = (chroma_collection_name(f"user:{owner_id}")
                               if owner_id else None)
            for phys in _enumerate_scope_collections(client, "scope-user-"):
                if owner_priv_phys and phys == owner_priv_phys:
                    continue  # protect the owner's private data from admins
                _add_phys(phys)

        return cols

    # Standard user: own scopes + shared + own private only.
    cols = []
    for logical in _allowed_collections(user, None):
        phys = chroma_collection_name(logical)
        try:
            cols.append(client.get_collection(name=phys,
                                              embedding_function=embedding_func))
        except Exception:
            continue  # scope collection not created yet — skip, not an error
    return cols


def _enumerate_scope_collections(client, prefix: str = "scope-") -> list:
    """List existing PHYSICAL collection names beginning with `prefix`
    (default all 'scope-*' — i.e. every shared/role/user scope collection).
    Used to give owners/admins read access to everything on the company server.
    Returns [] on any error (fail-closed: owner sees fewer, never more).
    """
    try:
        raw = client.list_collections()
        names = []
        for c in raw:
            names.append(c if isinstance(c, str) else getattr(c, "name", str(c)))
    except Exception:
        return []
    return [n for n in names if n.startswith(prefix)]


def _enumerate_role_collections(client) -> list:
    """List all existing role:* collections (LOGICAL names) by inspecting
    ChromaDB for physical 'scope-role-<name>' collections. Retained for
    _allowed_collections' owner role-enumeration arg and unit tests. Returns []
    on any error (fail-closed).
    """
    role_logicals = []
    for phys in _enumerate_scope_collections(client, "scope-role-"):
        sub = phys[len("scope-role-"):]
        if sub:
            role_logicals.append(f"role:{sub}")
    return role_logicals


@mcp.tool()
def get_knowledge_base_overview(ctx: Context = None) -> str:
    """
    AGENTIC RAG - Start here.
    Returns a high-level summary of the AI-Prowler knowledge base: total
    document count, file types present, tracked source directories, and
    total chunk count. Call this at the start of any research task so you
    understand what knowledge is available before deciding how to search.
    No LLM or Ollama required.

    Returns:
        Structured overview of the knowledge base contents.
    """
    if not _prewarm_event.wait(timeout=60):
        _log.warning("get_knowledge_base_overview: prewarm timeout — returning early")
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    from rag_preprocessor import CHROMA_DB_PATH, load_auto_update_list
    try:
        _collections = _scoped_collections_for_ctx(ctx)
    except Exception:
        return (
            "Knowledge base is empty — no documents indexed yet.\n"
            "Use index_path to index a folder of documents."
        )

    total_chunks = 0
    metadatas = []
    for _col in _collections:
        c = _col.count()
        total_chunks += c
        if c:
            sample = _col.get(limit=min(2000, c))
            metadatas.extend(sample.get('metadatas', []))
    if total_chunks == 0:
        return "Knowledge base is empty."

    unique_files = {}
    ext_counts   = {}
    dir_counts   = {}   # parent_directory → set of filepaths
    for m in metadatas:
        fp  = m.get('filepath', '')
        fn  = m.get('filename', fp)
        ext = m.get('extension', 'unknown').lower()
        if fp not in unique_files:
            unique_files[fp] = {'filename': fn, 'extension': ext,
                                'total_chunks': m.get('total_chunks', 1)}
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

        # Build directory tree from provenance metadata
        parent_dir = m.get('parent_directory', '')
        dir_chain  = m.get('directory_chain', '')
        tree_key   = dir_chain if dir_chain else parent_dir
        if tree_key:
            if tree_key not in dir_counts:
                dir_counts[tree_key] = set()
            dir_counts[tree_key].add(fp)

    tracked_dirs = load_auto_update_list() or []

    lines = [
        "AI-Prowler Knowledge Base Overview",
        "=" * 45,
        f"Total documents : {len(unique_files):,}",
        f"Total chunks    : {total_chunks:,}",
        f"Database path   : {CHROMA_DB_PATH}",
        "",
        "Document types:",
    ]
    for ext, cnt in sorted(ext_counts.items(), key=lambda x: -x[1]):
        pct = cnt / total_chunks * 100
        lines.append(f"  {ext:12s}  {cnt:5,} chunks  ({pct:.1f}%)")

    if dir_counts:
        lines.append("")
        lines.append("Directory tree (by content location):")
        for chain in sorted(dir_counts.keys()):
            n_files = len(dir_counts[chain])
            lines.append(f"  📁 {chain}  ({n_files} file{'s' if n_files != 1 else ''})")

    if tracked_dirs:
        lines.append("")
        lines.append("Tracked source directories:")
        for d in tracked_dirs:
            lines.append(f"  - {d}")

    lines.append("")
    lines.append(
        "Next steps: search_documents(query) for broad search | "
        "search_within_directory(query, dir) for targeted search | "
        "list_indexed_directories() for full directory tree"
    )
    return "\n".join(lines)


@mcp.tool()
def search_documents(
    query: str,
    n_results: int = 8,
    min_similarity: float = 0.0,
    ctx: Context = None,
) -> str:
    """
    AGENTIC RAG - Primary search tool.
    Searches the knowledge base using semantic similarity and returns raw
    document chunks. No LLM involved — Claude receives chunks directly and
    does all reasoning itself. Call multiple times with different or refined
    queries to gather context before synthesising an answer.
    No Ollama required — works on any machine.

    Args:
        query:          Natural language search query. Try different phrasings
                        if the first search misses something.
        n_results:      Number of chunks to return (default 8, max 20).
        min_similarity: Filter chunks below this score 0.0-1.0 (default 0.0).

    Returns:
        Numbered list of matching chunks with source file, chunk position,
        similarity score, and full text content.
    """
    if not query.strip():
        return "Query cannot be empty."

    if not _prewarm_event.wait(timeout=60):
        _log.warning("search_documents: prewarm timeout — returning early")
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    n_results = min(max(1, n_results), 20)

    # ── Server-mode collection scoping (v7.0.0 Phase B; personal mode = None) ──
    # In server mode the auth middleware attached a user to the request; restrict
    # the search to that user's allowed collections. In personal mode there is
    # no user (ctx None or no .user), so collection_names stays None and the
    # search hits the single 'documents' collection exactly as before.
    _scoped_collections = None
    _user = _current_user(ctx)
    if _user is not None:
        _scoped_collections = _allowed_collections(_user)
        _log.debug("search_documents scoped for user=%s to %s",
                   _user.get("id"), _scoped_collections)

    try:
        from rag_preprocessor import search_documents as _search
        chunks = _search(query, n_results=n_results,
                         collection_names=_scoped_collections)
    except Exception as exc:
        return f"Search failed: {exc}"

    if not chunks:
        return (
            f"No results found for: '{query}'\n"
            "Try different keywords or call get_knowledge_base_overview() "
            "to see what is indexed."
        )

    if min_similarity > 0.0:
        chunks = [c for c in chunks if c.get('similarity', 0) >= min_similarity]
        if not chunks:
            return (
                f"No results above similarity {min_similarity:.2f} for: '{query}'\n"
                "Try lowering min_similarity or rephrasing."
            )

    lines = [
        f"Search results for: \"{query}\"",
        f"Returning {len(chunks)} chunk(s)",
        "-" * 55, "",
    ]
    for i, chunk in enumerate(chunks, 1):
        meta      = chunk.get('metadata', {})
        filename  = meta.get('filename', 'unknown')
        filepath  = meta.get('filepath', '')
        chunk_idx = meta.get('chunk_index', 0)
        total_ch  = meta.get('total_chunks', 1)
        ext       = meta.get('extension', '')
        sim       = chunk.get('similarity', 0.0)
        content   = chunk.get('content', '').strip()

        # ── Provenance fields (graceful fallback for pre-upgrade chunks) ──
        dir_chain   = meta.get('directory_chain', '')
        doc_id      = meta.get('document_id', '')
        doc_title   = meta.get('doc_title', '')
        file_mod    = meta.get('file_modified', '')
        parent_dir  = meta.get('parent_directory', '')

        lines.append(
            f"[{i}] {filename}  chunk {chunk_idx+1}/{total_ch}  "
            f"similarity: {sim:.3f}  type: {ext}"
        )
        if dir_chain:
            lines.append(f"    📁 {dir_chain}")
        elif filepath and filepath != filename:
            lines.append(f"    Path: {filepath}")
        if doc_id:
            lines.append(f"    📄 Document ID: {doc_id}")
        if doc_title and doc_title != Path(filename).stem:
            lines.append(f"    📝 Title: {doc_title}")
        if file_mod:
            lines.append(f"    ⏱  Modified: {file_mod[:10]}")
        lines.append("")
        lines.append(content)
        lines.append("")
        lines.append("-" * 55)
        lines.append("")
    lines.append(
        "Tips: search_documents() again with different query | "
        "search_within_directory(query, dir) for targeted results | "
        "Use expand_search_result(filename, chunk_index) to expand | "
        "list_indexed_directories() to see indexed folder tree"
    )
    return "\n".join(lines)


@mcp.tool()
def expand_search_result(
    filename: str,
    chunk_index: int,
    window: int = 2,
    ctx: Context = None,
) -> str:
    """
    AGENTIC RAG - Expand context around a search result.
    Retrieves the chunks immediately before and after a specific chunk,
    giving fuller context when a search result is cut off at a boundary.
    Use this when a result looks relevant but is incomplete.
    No Ollama required.

    Args:
        filename:    Filename from a search_documents result (partial match ok).
        chunk_index: Zero-based chunk index from the search result.
        window:      Chunks before and after to include (default 2, max 5).

    Returns:
        Target chunk plus surrounding chunks in reading order.
    """
    window = max(1, min(5, window))

    try:
        _collections = _scoped_collections_for_ctx(ctx)
    except RuntimeError as e:
        return str(e)

    try:
        fn_lower  = filename.lower()
        chunk_map = {}
        for _col in _collections:
            sample = _col.get(limit=5000, include=["metadatas", "documents"])
            for doc, meta in zip(sample['documents'], sample['metadatas']):
                if fn_lower in meta.get('filename', '').lower() or \
                   fn_lower in meta.get('filepath', '').lower():
                    chunk_map[meta.get('chunk_index', 0)] = (doc, meta)
    except Exception as exc:
        return f"Could not retrieve chunks: {exc}"

    if not chunk_map:
        return (
            f"No document matching '{filename}' found.\n"
            "Use list_indexed_documents() to see available filenames."
        )
    if chunk_index not in chunk_map:
        return (
            f"Chunk index {chunk_index} not found for '{filename}'.\n"
            f"Available: {sorted(chunk_map.keys())[:20]}"
        )

    target_meta  = chunk_map[chunk_index][1]
    total_chunks = target_meta.get('total_chunks', max(chunk_map.keys()) + 1)
    filepath     = target_meta.get('filepath', filename)
    start        = max(0, chunk_index - window)
    end          = min(total_chunks - 1, chunk_index + window)

    lines = [
        f"Context for: {filepath}",
        f"Showing chunks {start+1}-{end+1} of {total_chunks} "
        f"(target chunk {chunk_index+1} marked with >)",
        "=" * 55, "",
    ]
    for idx in range(start, end + 1):
        if idx not in chunk_map:
            lines.append(f"[chunk {idx+1}/{total_chunks}]  (not in current sample)")
            lines.append("")
            continue
        content, _ = chunk_map[idx]
        marker = "> " if idx == chunk_index else "  "
        lines.append(f"{marker}[chunk {idx+1}/{total_chunks}]")
        lines.append(content.strip())
        lines.append("")
    return "\n".join(lines)


@mcp.tool()
def read_document(
    filename: str,
    start_chunk: int = 0,
    max_chunks: int = 10,
    ctx: Context = None,
) -> str:
    """
    AGENTIC RAG - Read a whole document in sequence.
    Retrieves chunks from a specific indexed document in reading order.
    Use when you need to read a full document rather than search fragments —
    e.g. summarise a contract, read a manual section, review a report.
    For long documents, make multiple calls with increasing start_chunk.
    No Ollama required.

    Args:
        filename:    Filename to retrieve (partial matches accepted).
                     Use list_indexed_documents() to browse available files.
        start_chunk: Zero-based chunk to start from (default 0).
        max_chunks:  Max chunks to return (default 10, max 30).

    Returns:
        Sequential chunks in reading order with position indicators and
        a continuation hint if the document has more chunks.
    """
    max_chunks = min(max(1, max_chunks), 30)

    try:
        _collections = _scoped_collections_for_ctx(ctx)
    except RuntimeError as e:
        return str(e)

    try:
        fn_lower = filename.lower()
        matches  = []
        for _col in _collections:
            sample = _col.get(limit=5000, include=["metadatas", "documents"])
            for doc, meta in zip(sample['documents'], sample['metadatas']):
                if fn_lower in meta.get('filename', '').lower() or \
                   fn_lower in meta.get('filepath', '').lower():
                    matches.append((meta.get('chunk_index', 0), doc, meta))
    except Exception as exc:
        return f"Could not access knowledge base: {exc}"

    if not matches:
        return (
            f"No document matching '{filename}' found.\n"
            "Use list_indexed_documents() to see available filenames."
        )

    matches.sort(key=lambda x: x[0])
    total_chunks = matches[-1][2].get('total_chunks', len(matches))
    actual_name  = matches[0][2].get('filename', filename)
    actual_path  = matches[0][2].get('filepath', filename)
    ext          = matches[0][2].get('extension', '')

    page = [(idx, doc, meta) for idx, doc, meta in matches
            if idx >= start_chunk][:max_chunks]

    if not page:
        return (
            f"No chunks from index {start_chunk} onwards.\n"
            f"'{actual_name}' has {total_chunks} chunks (indices 0-{total_chunks-1})."
        )

    last_shown = page[-1][0]
    has_more   = last_shown < total_chunks - 1

    lines = [
        f"Document: {actual_name}",
        f"Path    : {actual_path}",
        f"Type    : {ext}  |  Total chunks: {total_chunks}",
        f"Showing chunks {page[0][0]+1}-{last_shown+1} of {total_chunks}",
        "=" * 55, "",
    ]
    for idx, doc, _ in page:
        lines.append(f"[chunk {idx+1}/{total_chunks}]")
        lines.append(doc.strip())
        lines.append("")

    if has_more:
        next_start = last_shown + 1
        lines.append("-" * 55)
        lines.append(
            f"Document continues — {total_chunks - last_shown - 1} more chunk(s). "
            f"Call: read_document('{actual_name}', start_chunk={next_start})"
        )
    return "\n".join(lines)


@mcp.tool()
def list_indexed_documents(
    filter_ext: Optional[str] = None,
    filter_path: Optional[str] = None,
    limit: int = 50,
    ctx: Context = None,
) -> str:
    """
    AGENTIC RAG - Browse the knowledge base.
    Lists all indexed documents with file type, path, and chunk count.
    Use this to orient yourself — especially useful for questions like
    "what documents do you have about X?" or "do you have the Q3 report?"
    No Ollama required.

    Args:
        filter_ext:  Only show this file type, e.g. "pdf", "docx".
        filter_path: Only show files whose path contains this string.
        limit:       Max documents to list (default 50).

    Returns:
        Sorted list of indexed documents grouped by file type.
    """
    try:
        _collections = _scoped_collections_for_ctx(ctx)
    except RuntimeError as e:
        return str(e)

    # Aggregate metadata across all allowed collections (one in personal mode).
    try:
        metas = []
        for _col in _collections:
            total   = _col.count()
            sample  = _col.get(limit=min(5000, total), include=["metadatas"])
            metas.extend(sample.get('metadatas', []))
    except Exception as exc:
        return f"Could not list documents: {exc}"

    docs = {}
    for m in metas:
        fp  = m.get('filepath', '')
        fn  = m.get('filename', fp)
        ext = m.get('extension', '').lower().lstrip('.')
        tc  = m.get('total_chunks', 1)
        if filter_ext and ext != filter_ext.lower().lstrip('.'):
            continue
        if filter_path and filter_path.lower() not in fp.lower():
            continue
        if fp not in docs:
            docs[fp] = {'filename': fn, 'extension': ext,
                        'total_chunks': tc, 'filepath': fp}

    if not docs:
        note = ""
        if filter_ext:
            note += f" with type '{filter_ext}'"
        if filter_path:
            note += f" in path '{filter_path}'"
        return f"No documents found{note}."

    shown  = sorted(docs.values(), key=lambda d: d['filename'].lower())[:limit]
    by_ext = {}
    for d in shown:
        by_ext.setdefault(d['extension'] or 'other', []).append(d)

    lines = [
        f"Indexed documents: {len(docs):,} total  (showing {len(shown)})",
        "-" * 55, "",
    ]
    for ext in sorted(by_ext.keys()):
        lines.append(f"{ext.upper()} ({len(by_ext[ext])} files)")
        for d in sorted(by_ext[ext], key=lambda x: x['filename'].lower()):
            lines.append(
                f"  - {d['filename']}  ({d['total_chunks']} chunk"
                f"{'s' if d['total_chunks'] != 1 else ''})"
            )
            if d['filepath'] != d['filename']:
                lines.append(f"    {d['filepath']}")
        lines.append("")

    if len(docs) > limit:
        lines.append(f"... and {len(docs)-limit} more. Use filter_ext or filter_path.")
    lines.append("Call read_document(filename) to read a specific document.")
    return "\n".join(lines)


@mcp.tool()
def multi_query_search(
    queries: list[str],
    n_results_each: int = 5,
    min_similarity: float = 0.0,
    ctx: Context = None,
) -> str:
    """
    AGENTIC RAG - Parallel multi-angle search.
    Runs several semantic searches in one call and returns deduplicated results
    ranked by best similarity. Use when a topic has multiple angles, synonyms,
    or when you want to reformulate a question several ways at once.
    More efficient than calling search_documents() multiple times.
    No Ollama required.

    Args:
        queries:        List of 2-6 search queries to run in parallel.
                        Example: ["refund policy", "money back guarantee"]
        n_results_each: Chunks per query (default 5, max 10).
        min_similarity: Discard chunks below this score (default 0.0).

    Returns:
        Deduplicated chunks from all queries sorted by best similarity,
        labelled with which query found them.
    """
    if not queries:
        return "Provide at least one query."
    queries = [q.strip() for q in queries[:6] if q.strip()]
    n_results_each = min(max(1, n_results_each), 10)

    try:
        from rag_preprocessor import search_documents as _search
    except Exception as exc:
        return f"Could not access knowledge base: {exc}"

    # Server-mode scoping (personal mode → None → single 'documents' collection).
    _scoped_collections = None
    _user = _current_user(ctx)
    if _user is not None:
        _scoped_collections = _allowed_collections(_user)

    all_chunks: dict = {}
    for q in queries:
        try:
            results = _search(q, n_results=n_results_each,
                             collection_names=_scoped_collections)
        except Exception:
            continue
        for chunk in results:
            sim  = chunk.get('similarity', 0.0)
            if sim < min_similarity:
                continue
            meta = chunk.get('metadata', {})
            key  = f"{meta.get('filepath','')}::{meta.get('chunk_index',0)}"
            if key not in all_chunks or sim > all_chunks[key]['similarity']:
                all_chunks[key] = {**chunk, 'found_by': q, 'also_found_by': []}
            elif key in all_chunks and q != all_chunks[key]['found_by']:
                all_chunks[key]['also_found_by'].append(q)

    if not all_chunks:
        return (
            "No results found for any query:\n"
            + "\n".join(f"  - {q}" for q in queries)
            + "\nTry different keywords or call get_knowledge_base_overview()."
        )

    ranked = sorted(all_chunks.values(),
                    key=lambda c: c['similarity'], reverse=True)

    lines = [
        f"Multi-query search — {len(queries)} queries, "
        f"{len(ranked)} unique chunk(s) found",
        f"Queries: {' | '.join(queries)}",
        "-" * 55, "",
    ]
    for i, chunk in enumerate(ranked, 1):
        meta     = chunk.get('metadata', {})
        fn       = meta.get('filename', 'unknown')
        fp       = meta.get('filepath', '')
        cidx     = meta.get('chunk_index', 0)
        total    = meta.get('total_chunks', 1)
        ext      = meta.get('extension', '')
        sim      = chunk.get('similarity', 0.0)
        found_by = chunk.get('found_by', '')
        also     = chunk.get('also_found_by', [])
        content  = chunk.get('content', '').strip()

        # ── Provenance fields ──
        dir_chain   = meta.get('directory_chain', '')
        doc_id      = meta.get('document_id', '')
        doc_title   = meta.get('doc_title', '')
        file_mod    = meta.get('file_modified', '')

        found_note = f'found by: "{found_by}"'
        if also:
            found_note += f' (also: {", ".join(also)})'

        lines.append(
            f"[{i}] {fn}  chunk {cidx+1}/{total}  "
            f"similarity: {sim:.3f}  {found_note}"
        )
        if dir_chain:
            lines.append(f"    📁 {dir_chain}")
        elif fp and fp != fn:
            lines.append(f"    Path: {fp}")
        if doc_id:
            lines.append(f"    📄 Document ID: {doc_id}")
        if doc_title and doc_title != Path(fn).stem:
            lines.append(f"    📝 Title: {doc_title}")
        if file_mod:
            lines.append(f"    ⏱  Modified: {file_mod[:10]}")
        lines.append("")
        lines.append(content)
        lines.append("")
        lines.append("-" * 55)
        lines.append("")

    lines.append(
        "Tips: search_within_directory(query, dir) for targeted results | "
        "expand_search_result(filename, chunk_index) to expand any result."
    )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — search_within_directory  (Provenance-Aware Scoped Search)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def search_within_directory(
    query: str,
    directory: str,
    n_results: int = 8,
    min_similarity: float = 0.0,
    ctx: Context = None,
) -> str:
    """
    AGENTIC RAG - Directory-scoped search to prevent cross-contamination.
    Searches ONLY within a specific directory tree, filtering by the
    parent_directory or directory_chain metadata. Use this when the user
    asks about a specific case, project, client, or folder and you need
    to ensure results come only from that scope.
    No Ollama required.

    Args:
        query:          Natural language search query.
        directory:      Directory name or path fragment to restrict search to.
                        Matches against parent_directory and directory_chain.
                        Examples: 'Smith_v_Jones', '2024', 'Contracts'
        n_results:      Number of chunks to return (default 8, max 20).
        min_similarity: Filter chunks below this score 0.0-1.0 (default 0.0).

    Returns:
        Numbered list of matching chunks — all guaranteed to be from the
        specified directory tree.
    """
    if not query.strip():
        return "Query cannot be empty."
    if not directory.strip():
        return "Directory cannot be empty. Use search_documents() for unscoped search."

    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    n_results = min(max(1, n_results), 20)
    dir_lower = directory.strip().lower()

    try:
        _collections = _scoped_collections_for_ctx(ctx)
    except RuntimeError as e:
        return str(e)

    # ── Strategy: fetch more results than requested, then filter by directory ──
    # ChromaDB's `where` filter supports exact match on metadata fields.
    # We try parent_directory exact match first (fastest).  If that yields
    # too few results, fall back to a broader search + client-side filter
    # on directory_chain (substring match). Both attempts run across EACH of the
    # user's allowed collections (one in personal mode) and accumulate.
    chunks_raw = []
    # Attempt 1: exact match on parent_directory, per collection.
    for collection in _collections:
        try:
            results = collection.query(
                query_texts=[query],
                n_results=min(n_results * 3, 60),
                where={"parent_directory": directory.strip()}
            )
            for i in range(len(results['documents'][0])):
                chunks_raw.append({
                    'content':    results['documents'][0][i],
                    'metadata':   results['metadatas'][0][i],
                    'distance':   results['distances'][0][i],
                    'similarity': 1 - results['distances'][0][i],
                })
        except Exception:
            continue

    # Attempt 2: if exact match found nothing, do a broad search and
    # filter client-side on directory_chain (case-insensitive substring).
    if not chunks_raw:
        for collection in _collections:
            try:
                results = collection.query(
                    query_texts=[query],
                    n_results=min(n_results * 5, 100),
                )
                for i in range(len(results['documents'][0])):
                    meta = results['metadatas'][0][i]
                    chain = meta.get('directory_chain', '').lower()
                    parent = meta.get('parent_directory', '').lower()
                    fp = meta.get('filepath', '').lower()
                    if (dir_lower in chain or dir_lower in parent
                            or dir_lower in fp):
                        chunks_raw.append({
                            'content':    results['documents'][0][i],
                            'metadata':   meta,
                            'distance':   results['distances'][0][i],
                            'similarity': 1 - results['distances'][0][i],
                        })
            except Exception:
                continue

    # Merge across collections by best similarity before filtering/truncating.
    chunks_raw.sort(key=lambda c: c['distance'])

    if min_similarity > 0.0:
        chunks_raw = [c for c in chunks_raw if c['similarity'] >= min_similarity]

    # Limit to requested count
    chunks_raw = chunks_raw[:n_results]

    if not chunks_raw:
        return (
            f"No results found for '{query}' within directory '{directory}'.\n"
            "Possible causes:\n"
            f"  - No documents indexed from a directory matching '{directory}'\n"
            "  - Try a broader search with search_documents() first\n"
            "  - Call list_indexed_directories() to see available directory trees"
        )

    lines = [
        f"Scoped search for: \"{query}\"",
        f"Directory filter: \"{directory}\"",
        f"Returning {len(chunks_raw)} chunk(s)",
        "-" * 55, "",
    ]
    for i, chunk in enumerate(chunks_raw, 1):
        meta      = chunk['metadata']
        filename  = meta.get('filename', 'unknown')
        chunk_idx = meta.get('chunk_index', 0)
        total_ch  = meta.get('total_chunks', 1)
        ext       = meta.get('extension', '')
        sim       = chunk['similarity']
        content   = chunk['content'].strip()
        dir_chain = meta.get('directory_chain', '')
        doc_id    = meta.get('document_id', '')
        doc_title = meta.get('doc_title', '')
        file_mod  = meta.get('file_modified', '')

        lines.append(
            f"[{i}] {filename}  chunk {chunk_idx+1}/{total_ch}  "
            f"similarity: {sim:.3f}  type: {ext}"
        )
        if dir_chain:
            lines.append(f"    📁 {dir_chain}")
        if doc_id:
            lines.append(f"    📄 Document ID: {doc_id}")
        if doc_title and doc_title != Path(filename).stem:
            lines.append(f"    📝 Title: {doc_title}")
        if file_mod:
            lines.append(f"    ⏱  Modified: {file_mod[:10]}")
        lines.append("")
        lines.append(content)
        lines.append("")
        lines.append("-" * 55)
        lines.append("")

    lines.append(
        "All results are from the specified directory scope. "
        "Use expand_search_result(filename, chunk_index) to expand."
    )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — list_indexed_directories  (Directory Tree Discovery)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def list_indexed_directories(ctx: Context = None) -> str:
    """
    AGENTIC RAG - Directory tree discovery.
    Lists all indexed directory trees with document counts per directory.
    Use this to understand the knowledge base structure and identify the
    right directory scope for search_within_directory().
    No Ollama required.

    Returns:
        Directory tree with file counts, sorted alphabetically.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    try:
        _collections = _scoped_collections_for_ctx(ctx)
    except RuntimeError as e:
        return str(e)

    try:
        metadatas = []
        for _col in _collections:
            total = _col.count()
            if total == 0:
                continue
            sample = _col.get(limit=min(5000, total), include=["metadatas"])
            metadatas.extend(sample.get('metadatas', []))
    except Exception as exc:
        return f"Could not read knowledge base: {exc}"

    if not metadatas:
        return "Knowledge base is empty — no documents indexed yet."

    # Build directory tree: directory_chain → set of unique filepaths
    dir_tree = {}       # chain → set(filepath)
    parent_dirs = {}    # parent_directory → set(filepath)
    for m in metadatas:
        fp    = m.get('filepath', '')
        chain = m.get('directory_chain', '')
        pdir  = m.get('parent_directory', '')

        if chain:
            if chain not in dir_tree:
                dir_tree[chain] = set()
            dir_tree[chain].add(fp)

        if pdir:
            if pdir not in parent_dirs:
                parent_dirs[pdir] = set()
            parent_dirs[pdir].add(fp)

    if not dir_tree and not parent_dirs:
        return (
            "No directory provenance metadata found.\n"
            "This likely means the documents were indexed before the\n"
            "provenance system was added.  Re-index your directories\n"
            "to add directory_chain metadata to all chunks."
        )

    lines = [
        "AI-Prowler — Indexed Directory Tree",
        "=" * 50,
        "",
    ]

    if dir_tree:
        lines.append("Directory chains (full breadcrumb paths):")
        lines.append("-" * 40)
        total_files = 0
        for chain in sorted(dir_tree.keys()):
            n = len(dir_tree[chain])
            total_files += n
            lines.append(f"  📁 {chain}  ({n} file{'s' if n != 1 else ''})")
        lines.append("")
        lines.append(f"Total: {len(dir_tree)} directories, {total_files} files")
    elif parent_dirs:
        lines.append("Parent directories (immediate folder names):")
        lines.append("-" * 40)
        total_files = 0
        for pdir in sorted(parent_dirs.keys()):
            n = len(parent_dirs[pdir])
            total_files += n
            lines.append(f"  📁 {pdir}  ({n} file{'s' if n != 1 else ''})")
        lines.append("")
        lines.append(f"Total: {len(parent_dirs)} directories, {total_files} files")

    lines.append("")
    lines.append(
        "Use search_within_directory(query, directory_name) to search "
        "within a specific directory."
    )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ░░  ACTION TOOLS — Field Service Automation  ░░
#
# All free-tier tools use no API key:
#   • Weather    : Open-Meteo  (https://open-meteo.com)
#   • Geocoding  : Nominatim / OpenStreetMap (https://nominatim.openstreetmap.org)
#   • Routing    : OSRM public server (http://router.project-osrm.org)
#                  OSRM's /trip endpoint solves TSP natively — no OR-Tools needed
#   • Maps URL   : Google Maps URL scheme (free, no key, tap-to-navigate)
#
# Spreadsheet update uses openpyxl (already installed).
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# ACTION TOOL 1 — get_weather
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def get_weather(location: str, days: int = 3) -> str:
    """
    Get current weather conditions and a multi-day forecast for any location.
    Uses Open-Meteo for weather data and Nominatim for geocoding.
    Both are completely free with no API key required.

    Use this before planning outdoor field service schedules to flag rain risk.
    Rain probability >= 50% is flagged with a warning symbol.

    Args:
        location: City name, address, or zip code.
                  Examples: "Orlando FL", "32801", "Chicago Illinois"
        days:     Number of forecast days to return (1-7, default 3).

    Returns:
        Current conditions plus a daily forecast with high/low temps,
        weather description, and rain probability. Rain-risk days are flagged.
    """
    import requests as _req
    import time as _time

    # ── Step 1: Geocode the location via Nominatim ────────────────────────────
    try:
        geo = _req.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": location, "format": "json", "limit": 1},
            headers={"User-Agent": "AI-Prowler/5.0 (field-service-tool)"},
            timeout=10,
        ).json()
        if not geo:
            return f"❌ Could not geocode '{location}'. Try a more specific address."
        lat        = float(geo[0]["lat"])
        lon        = float(geo[0]["lon"])
        place_name = geo[0].get("display_name", location).split(",")[0]
    except Exception as exc:
        return f"❌ Geocoding failed: {exc}"

    # ── Step 2: Fetch forecast from Open-Meteo ───────────────────────────────
    days = max(1, min(7, days))
    try:
        wx = _req.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude":            lat,
                "longitude":           lon,
                "current_weather":     True,
                "daily":               ",".join([
                    "temperature_2m_max",
                    "temperature_2m_min",
                    "precipitation_probability_max",
                    "weathercode",
                ]),
                "temperature_unit":    "fahrenheit",
                "wind_speed_unit":     "mph",
                "precipitation_unit":  "inch",
                "timezone":            "auto",
                "forecast_days":       days,
            },
            timeout=10,
        ).json()
    except Exception as exc:
        return f"❌ Weather fetch failed: {exc}"

    # WMO weather code descriptions (simplified subset)
    _WMO = {
        0: "Clear sky",       1: "Mainly clear",    2: "Partly cloudy",
        3: "Overcast",        45: "Foggy",           48: "Icy fog",
        51: "Light drizzle",  53: "Drizzle",         55: "Heavy drizzle",
        61: "Light rain",     63: "Rain",            65: "Heavy rain",
        71: "Light snow",     73: "Snow",            75: "Heavy snow",
        80: "Light showers",  81: "Rain showers",    82: "Heavy showers",
        95: "Thunderstorm",   96: "Hail storm",      99: "Heavy hailstorm",
    }

    cur     = wx.get("current_weather", {})
    daily   = wx.get("daily", {})
    dates   = daily.get("time", [])
    highs   = daily.get("temperature_2m_max", [])
    lows    = daily.get("temperature_2m_min", [])
    rain    = daily.get("precipitation_probability_max", [])
    codes   = daily.get("weathercode", [])

    lines = [
        f"🌤️  Weather for {place_name}",
        "─" * 45,
        f"Now:  {cur.get('temperature','?')}°F  "
        f"{'  ' + _WMO.get(int(cur.get('weathercode',0)), 'Unknown')}"
        f"  Wind: {cur.get('windspeed','?')} mph",
        "",
    ]
    for i, date in enumerate(dates):
        desc      = _WMO.get(int(codes[i]) if i < len(codes) else 0, "Unknown")
        rain_pct  = int(rain[i]) if i < len(rain) else 0
        rain_flag = "  ⚠️  RAIN RISK — consider rescheduling outdoor jobs" if rain_pct >= 50 else ""
        lines.append(
            f"  {date}:  "
            f"High {highs[i] if i < len(highs) else '?'}°F  "
            f"Low {lows[i]  if i < len(lows)  else '?'}°F  "
            f"{desc}  Rain: {rain_pct}%{rain_flag}"
        )

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ACTION TOOL 2 — geocode_address
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def geocode_address(address: str) -> str:
    """
    Convert a street address to GPS coordinates (latitude/longitude).
    Uses Nominatim / OpenStreetMap — free, no API key required.

    Useful for verifying that a job address can be geocoded before running
    route optimization, or for looking up coordinates manually.

    Args:
        address: Full street address.
                 Example: "1203 Pine Ave, Orlando FL 32801"

    Returns:
        Latitude, longitude, and display name for the matched location.
    """
    import requests as _req

    try:
        data = _req.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": address, "format": "json", "limit": 1},
            headers={"User-Agent": "AI-Prowler/5.0 (field-service-tool)"},
            timeout=10,
        ).json()
    except Exception as exc:
        return f"❌ Geocoding request failed: {exc}"

    if not data:
        return (
            f"❌ Address not found: '{address}'\n"
            "Try including city and state for better results."
        )

    r = data[0]
    return (
        f"📍 {r.get('display_name', address)}\n"
        f"   Latitude:  {r['lat']}\n"
        f"   Longitude: {r['lon']}\n"
        f"   Type:      {r.get('type', 'unknown')}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# ACTION TOOL 3 — optimize_route
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def optimize_route(
    stops: list[str],
    origin: str,
    optimize_for: str = "time",
    departure_hour: int = 7,
    return_to_origin: bool = True,
) -> str:
    """
    Calculate the optimal driving route for a list of job stops (Traveling Salesman).
    Returns stops in the best visit order with estimated arrival times for each.

    Uses:
    - Nominatim (OpenStreetMap) for geocoding — free, no API key
    - OSRM public routing server for TSP optimization — free, no API key
      OSRM's /trip endpoint solves the Traveling Salesman Problem natively.
      Routing is via real streets with real drive times — not straight-line distance.

    Note: Nominatim requires a small delay between requests (0.3s per address).
    Geocoding 20 addresses takes about 6 seconds. This is a free service courtesy
    limitation — not a bug.

    Args:
        stops:            List of job addresses to visit (any order — the tool
                          reorders them into the optimal sequence).
        origin:           Starting address (your home base or depot).
        optimize_for:     "time" to minimize total drive time (recommended),
                          "distance" to minimize total miles driven.
        departure_hour:   Hour to leave origin in 24h format (default 7 = 7:00 AM).
                          Used to calculate estimated arrival times per stop.
        return_to_origin: If True (default), route ends back at origin (round trip).

    Returns:
        Optimized stop sequence with estimated arrival time, drive time, and
        distance for each leg. Includes totals and a hint to call build_maps_url().
    """
    import requests as _req
    import datetime  as _dt
    import time      as _time

    all_addresses = [origin] + list(stops)

    # ── Step 1: Geocode all addresses via Nominatim ───────────────────────────
    coords  = []
    failed  = []
    for addr in all_addresses:
        _time.sleep(0.35)  # Nominatim courtesy rate limit: max 1 req/s
        try:
            geo = _req.get(
                "https://nominatim.openstreetmap.org/search",
                params={"q": addr, "format": "json", "limit": 1},
                headers={"User-Agent": "AI-Prowler/5.0 (field-service-tool)"},
                timeout=10,
            ).json()
            if geo:
                coords.append({
                    "address": addr,
                    "lat":     float(geo[0]["lat"]),
                    "lon":     float(geo[0]["lon"]),
                    "short":   geo[0].get("display_name", addr).split(",")[0],
                })
            else:
                failed.append(addr)
                coords.append(None)
        except Exception as exc:
            failed.append(f"{addr} (error: {exc})")
            coords.append(None)

    valid = [c for c in coords if c is not None]
    if len(valid) < 2:
        return (
            f"❌ Could not geocode enough addresses to build a route.\n"
            f"Failed addresses: {failed}"
        )

    # ── Step 2: Call OSRM /trip endpoint (solves TSP natively) ───────────────
    # Format: lon,lat;lon,lat;...
    coord_str = ";".join(f"{c['lon']},{c['lat']}" for c in valid)
    destination_param = "any" if return_to_origin else "last"
    try:
        osrm_resp = _req.get(
            f"http://router.project-osrm.org/trip/v1/driving/{coord_str}",
            params={
                "roundtrip":   "true" if return_to_origin else "false",
                "source":      "first",
                "destination": destination_param,
                "annotations": "false",
            },
            timeout=30,
        ).json()
    except Exception as exc:
        return f"❌ Route optimization request failed: {exc}"

    if osrm_resp.get("code") != "Ok":
        return (
            f"❌ OSRM routing error: {osrm_resp.get('message', 'Unknown error')}\n"
            "The OSRM public server may be temporarily overloaded. Try again in a moment."
        )

    trips     = osrm_resp.get("trips",     [])
    waypoints = osrm_resp.get("waypoints", [])
    if not trips or not waypoints:
        return "❌ No route returned. Check that addresses are valid street addresses."

    trip          = trips[0]
    total_dur_s   = trip.get("duration", 0)   # seconds
    total_dist_m  = trip.get("distance",  0)  # meters
    total_miles   = total_dist_m / 1609.34
    total_mins    = total_dur_s  / 60.0
    legs          = trip.get("legs", [])

    # OSRM returns waypoints sorted by trip visit order via trips_index/waypoint_index
    sorted_wps = sorted(
        waypoints,
        key=lambda w: w.get("trips_index", 0) * 1000 + w.get("waypoint_index", 0)
    )

    # ── Step 3: Build human-readable schedule ────────────────────────────────
    now        = _dt.datetime(2026, 1, 1, departure_hour, 0, 0)
    cur_time   = now

    lines = [
        "🗺️  Optimized Route Plan",
        "─" * 50,
        f"  Stops:          {len(stops)}",
        f"  Total drive:    {total_mins:.0f} min  ({total_miles:.1f} miles)",
        f"  Departure:      {now.strftime('%I:%M %p')}",
        f"  Optimized for:  {optimize_for}",
        "",
    ]

    if failed:
        lines.append(f"⚠️  Could not geocode (excluded from route): {', '.join(failed)}")
        lines.append("")

    lines.append("OPTIMIZED SEQUENCE:")
    lines.append("")

    for i, wp in enumerate(sorted_wps):
        wp_idx = wp.get("waypoint_index", i)
        if wp_idx >= len(valid):
            continue
        info = valid[wp_idx]

        if i == 0:
            lines.append(f"  🏠 ORIGIN")
            lines.append(f"     {info['address']}")
            lines.append(f"     Depart: {cur_time.strftime('%I:%M %p')}")
        else:
            leg_idx  = i - 1
            if leg_idx < len(legs):
                leg_s    = legs[leg_idx].get("duration", 0)
                leg_m    = legs[leg_idx].get("distance", 0) / 1609.34
                leg_mins = leg_s / 60.0
                cur_time += _dt.timedelta(seconds=leg_s)
            else:
                leg_mins = 0.0
                leg_m    = 0.0
            lines.append(f"  ▼  Drive {leg_mins:.0f} min  ({leg_m:.1f} mi)")
            lines.append(f"  {i}. {info['address']}")
            lines.append(f"     Arrive: {cur_time.strftime('%I:%M %p')}")
        lines.append("")

    if return_to_origin and legs:
        last_leg  = legs[-1] if legs else {}
        last_s    = last_leg.get("duration", 0)
        last_m    = last_leg.get("distance", 0) / 1609.34
        cur_time += _dt.timedelta(seconds=last_s)
        lines.append(f"  ▼  Drive {last_s/60:.0f} min  ({last_m:.1f} mi)")
        lines.append(f"  🏠 Return to Origin")
        lines.append(f"     Arrive: {cur_time.strftime('%I:%M %p')}")
        lines.append("")

    lines += [
        "─" * 50,
        f"✅ Route total: {total_mins:.0f} min drive,  {total_miles:.1f} miles",
        "",
        "Next step: call build_maps_url(stops_in_order, origin) to generate",
        "a tap-to-navigate Google Maps link for your phone.",
    ]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ACTION TOOL 4 — build_maps_url
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def build_maps_url(
    stops: list[str],
    origin: str,
    app: str = "google",
) -> str:
    """
    Build a tap-to-navigate multi-stop directions URL.
    The user taps the link on their phone and Google Maps (or Apple Maps) opens
    immediately in navigation mode with all stops pre-loaded in the correct order.

    Google Maps supports 9 waypoints per URL. For larger routes the tool
    automatically splits the day into legs (each with its own tap-to-navigate
    link) so no stops are lost.

    No API key required — uses the public Google Maps and Apple Maps URL schemes.
    Works on iPhone, Android, CarPlay, Android Auto, and desktop Chrome.

    Args:
        stops:  Job addresses in the OPTIMIZED visit order
                (use the sequence returned by optimize_route()).
        origin: Starting address (home base or depot).
        app:    "google" (default, all devices) or "apple" (iPhone/iPad only).

    Returns:
        One or more tap-to-navigate URLs. For routes > 9 stops, multiple
        leg links are provided — tap each when the previous leg is complete.
    """
    import urllib.parse as _up

    def _enc(s: str) -> str:
        return _up.quote(s.replace(" ", "+"), safe="+")

    GOOGLE_MAX = 9  # Google Maps URL waypoint limit per link

    if app.lower() == "apple":
        lines = [
            f"📍 Apple Maps Navigation Links  ({len(stops)} stops)",
            "(iPhone / iPad only — opens Apple Maps)",
            "",
        ]
        for i, stop in enumerate(stops, 1):
            url = (
                "http://maps.apple.com/?saddr=Current+Location"
                f"&daddr={_enc(stop)}&dirflg=d"
            )
            lines.append(f"  Stop {i}: {stop}")
            lines.append(f"  {url}")
            lines.append("")
        return "\n".join(lines)

    # ── Google Maps ───────────────────────────────────────────────────────────
    def _google_url(orig: str, dest: str, waypoints: list[str]) -> str:
        base   = "https://www.google.com/maps/dir/?api=1"
        params = f"&origin={_enc(orig)}&destination={_enc(dest)}&travelmode=driving"
        if waypoints:
            params += "&waypoints=" + "|".join(_enc(w) for w in waypoints)
        return base + params

    if len(stops) <= GOOGLE_MAX:
        url = _google_url(
            orig      = origin,
            dest      = origin,
            waypoints = stops,
        )
        return (
            f"📍 TAP TO NAVIGATE  —  {len(stops)} stops loaded\n\n"
            f"{url}\n\n"
            f"Opens Google Maps with all {len(stops)} stops in optimized order.\n"
            f"Works on: iPhone (Google Maps app), Android, CarPlay, Android Auto,\n"
            f"          and desktop Chrome.\n"
            f"Tap 'Start' in Maps for turn-by-turn navigation."
        )

    # Split into legs of GOOGLE_MAX stops each
    leg_groups = [stops[i:i + GOOGLE_MAX] for i in range(0, len(stops), GOOGLE_MAX)]
    total_legs  = len(leg_groups)
    lines = [
        f"📍 NAVIGATION ROUTE  —  {len(stops)} stops  ({total_legs} legs)",
        f"   Google Maps limit is {GOOGLE_MAX} waypoints per link.",
        f"   Tap each leg link when you finish the previous leg.",
        "",
    ]

    leg_origin = origin
    for leg_num, group in enumerate(leg_groups, 1):
        is_last_leg = leg_num == total_legs
        leg_dest    = origin if is_last_leg else group[-1]
        leg_wps     = group  if is_last_leg else group[:-1]

        stop_start = (leg_num - 1) * GOOGLE_MAX + 1
        stop_end   = min(leg_num * GOOGLE_MAX, len(stops))
        url = _google_url(leg_origin, leg_dest, leg_wps)

        lines.append(f"  LEG {leg_num}/{total_legs}  (stops {stop_start}–{stop_end}):")
        lines.append(f"  {url}")
        lines.append(f"  Tap when Leg {leg_num - 1 if leg_num > 1 else 0} is complete.")
        lines.append("")
        leg_origin = leg_dest

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ACTION TOOL 5 — update_job_spreadsheet
# ══════════════════════════════════════════════════════════════════════════════

def _get_default_spreadsheet_path() -> str:
    """Read the default spreadsheet path from ~/.ai-prowler/config.json."""
    try:
        _cfg_path = Path.home() / '.ai-prowler' / 'config.json'
        if _cfg_path.exists():
            import json as _jcfg
            cfg = _jcfg.loads(_cfg_path.read_text(encoding='utf-8'))
            return cfg.get('default_spreadsheet_path', '').strip()
    except Exception as _e:
        _log.warning("Could not read default_spreadsheet_path from config: %s", _e)
    return ''


def _backup_spreadsheet(fp: str, keep_days: int = 30) -> str:
    """
    Copy fp into a _backups subfolder next to the file, timestamped.
    Prunes backups older than keep_days days.

    Returns a short status string (success path or warning message).
    """
    import shutil as _shutil
    import datetime as _dt

    src = Path(fp)
    backup_dir = src.parent / '_backups'
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return f"⚠️  Could not create backup folder: {exc}"

    ts  = _dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')
    dst = backup_dir / f"{src.stem}_{ts}{src.suffix}"
    try:
        _shutil.copy2(str(src), str(dst))
    except Exception as exc:
        return f"⚠️  Backup copy failed: {exc}"

    # Prune old backups
    cutoff = _dt.datetime.now() - _dt.timedelta(days=keep_days)
    pruned = 0
    try:
        for old in backup_dir.glob(f"{src.stem}_*{src.suffix}"):
            if old == dst:
                continue
            try:
                mtime = _dt.datetime.fromtimestamp(old.stat().st_mtime)
                if mtime < cutoff:
                    old.unlink()
                    pruned += 1
            except Exception:
                pass
    except Exception:
        pass

    msg = f"💾 Backup saved: _backups/{dst.name}"
    if pruned:
        msg += f"  ({pruned} old backup(s) pruned)"
    return msg


@mcp.tool()
def update_job_spreadsheet(
    job_identifier: str,
    updates:        dict,
    filepath:       str = "",
    id_column:      str = "Customer",
    sheet_name:     str = "",
    backup:         bool = True,
) -> str:
    """
    Update a row in a job tracking spreadsheet after a job is completed.

    Finds the correct row by matching job_identifier against id_column
    (e.g. customer name), then writes new values to specified columns
    (e.g. marks job complete, records invoice number, updates last service date).

    Uses openpyxl — already installed, no new package needed.
    Works only on .xlsx files. For .xls, convert to .xlsx first.

    If filepath is omitted, the default spreadsheet path configured in
    AI-Prowler Settings → Small Business → Default Spreadsheet Path is used
    automatically — no need to specify the path every time.

    Args:
        job_identifier: Value to search for in id_column.
                        Example: "Crabby's Daytona" (partial matches accepted)
        updates:        Dict of {column_header: new_value} pairs to write.
                        Example: {"Job\\nStatus": "Complete",
                                  "Last Service\\nDate": "2026-03-31",
                                  "Actual\\nDuration (min)": 45,
                                  "Actual\\nAmount ($)": 150.00}
        filepath:       Full path to the Excel spreadsheet (.xlsx).
                        If omitted, uses the path saved in AI-Prowler Settings.
                        Example: "C:/Users/Dave/Documents/jobs.xlsx"
        id_column:      Column header to search in (default "Customer").
        sheet_name:     Sheet to use (default: first/active sheet).
        backup:         If True (default), a timestamped backup copy of the
                        spreadsheet is saved in a _backups subfolder next to
                        the file before any changes are written.
                        Backups older than 30 days are pruned automatically.
                        Set to False to skip the backup (faster, no disk use).

    Returns:
        Confirmation listing exactly which cells were updated, backup status,
        or an error if the file, row, or column was not found.
    """
    try:
        import openpyxl as _opx
    except ImportError:
        return "❌ openpyxl not installed. Run: pip install openpyxl"

    # Resolve filepath — use default from config if not supplied
    if not filepath:
        filepath = _get_default_spreadsheet_path()
    if not filepath:
        return (
            "❌ No spreadsheet path provided and no default path configured.\n"
            "Set one in AI-Prowler → Settings → Small Business → Default Spreadsheet Path,\n"
            "or pass the full filepath argument explicitly."
        )

    fp = filepath.replace("\\", "/")
    if not os.path.exists(fp):
        return f"❌ Spreadsheet not found: {fp}"
    if not fp.lower().endswith(".xlsx"):
        return (
            "❌ Only .xlsx files are supported for updates.\n"
            "Save the spreadsheet as .xlsx in Excel first."
        )

    # ── Backup before modifying ───────────────────────────────────────────────
    backup_msg = ""
    if backup:
        backup_msg = _backup_spreadsheet(fp)
        if backup_msg.startswith("⚠️") or backup_msg.startswith("❌"):
            # Backup failed — abort to protect the file
            return (
                f"{backup_msg}\n"
                "Spreadsheet was NOT modified. Fix the backup issue or pass backup=False to skip."
            )

    try:
        wb = _opx.load_workbook(fp)
    except Exception as exc:
        return f"❌ Could not open spreadsheet: {exc}"

    ws = (wb[sheet_name] if sheet_name and sheet_name in wb.sheetnames
          else wb.active)

    # ── Detect header row (skip title/banner rows, same logic as read tool) ───
    # Scans the first 5 rows and uses the first row that has ≥ 3 non-empty
    # cells as the real header row.  This handles decorative title rows like
    # "📅 JOBS & SCHEDULE — All Service Appointments" in row 1.
    header_row_num: int | None = None
    headers: dict[str, int] = {}
    for r in ws.iter_rows(min_row=1, max_row=5):
        non_empty = [c for c in r if c.value is not None]
        if len(non_empty) >= 3:
            header_row_num = r[0].row
            for col_idx, cell in enumerate(r, 1):
                if cell.value is not None:
                    raw = str(cell.value).strip()
                    headers[raw] = col_idx
                    # Register a newline-normalised alias so callers can pass
                    # either "Job\nStatus" or "Job Status" and both resolve.
                    normalised = raw.replace('\n', ' ')
                    if normalised != raw:
                        headers.setdefault(normalised, col_idx)
            break

    if header_row_num is None or not headers:
        return (
            "❌ Could not detect a header row in the spreadsheet.\n"
            "Expected a row with at least 3 non-empty cells in the first 5 rows."
        )

    if id_column not in headers:
        avail = [k for k in headers.keys() if '\n' not in k][:15]
        return (
            f"❌ Column '{id_column}' not found in headers (detected on row {header_row_num}).\n"
            f"Available columns: {', '.join(avail)}"
        )

    id_col_idx = headers[id_column]

    # ── Find matching row ─────────────────────────────────────────────────────
    found_row = None
    for row in ws.iter_rows(min_row=header_row_num + 1):
        cell_val = row[id_col_idx - 1].value
        if cell_val and job_identifier.lower() in str(cell_val).lower():
            found_row = row
            break

    if found_row is None:
        return (
            f"❌ No row found where {id_column} contains '{job_identifier}'.\n"
            "Check the spelling — partial matches are accepted."
        )

    # ── Apply updates ─────────────────────────────────────────────────────────
    updated:    list[str] = []
    not_found:  list[str] = []

    for col_name, new_val in updates.items():
        if col_name in headers:
            found_row[headers[col_name] - 1].value = new_val
            updated.append(f"{col_name} → {new_val}")
        else:
            not_found.append(col_name)

    # ── Save ──────────────────────────────────────────────────────────────────
    try:
        wb.save(fp)
    except Exception as exc:
        return f"❌ Could not save spreadsheet: {exc}"

    row_num = found_row[0].row
    lines   = [
        f"✅ Spreadsheet updated: {os.path.basename(fp)}",
        f"   Row:     {row_num}  ({id_column}: {job_identifier})",
        f"   Updated: {', '.join(updated)}",
    ]
    if backup_msg:
        lines.append(f"   {backup_msg}")
    if not_found:
        lines.append(
            f"   ⚠️  Columns not found (check spelling): {', '.join(not_found)}"
        )
    lines.append(
        "\n📑 Re-index the spreadsheet to keep AI-Prowler search results current:\n"
        "   Call update_tracked_directories() after updating the file."
    )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ACTION TOOL 6 — read_job_spreadsheet
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def read_job_spreadsheet(
    filepath:    str = "",
    sheet_name:  str = "",
    filter_date: str = "",
    max_rows:    int = 200,
) -> str:
    """
    Read job data from the AI-Prowler job tracking spreadsheet.

    Returns rows from the Jobs_Schedule sheet (or any named sheet) as
    structured text so Claude can answer questions like:
      - "What jobs do I have scheduled for today?"
      - "Which jobs are still open?"
      - "Show me everything scheduled this week."
      - "What customers haven't been serviced yet?"

    If filepath is omitted, the default spreadsheet path configured in
    AI-Prowler Settings -> Small Business -> Default Spreadsheet Path is used
    automatically.

    Args:
        filepath:    Full path to the .xlsx spreadsheet.
                     If omitted, uses the path saved in AI-Prowler Settings.
        sheet_name:  Sheet to read (default: "Jobs_Schedule").
                     Use "Customers" to read the customer master list.
                     Leave blank to default to Jobs_Schedule.
        filter_date: Optional date string to filter rows by Service Date.
                     Examples: "2026-03-31", "03/31/2026", "today"
                     Leave blank to return all rows.
        max_rows:    Maximum data rows to return (default 200, max 500).

    Returns:
        A formatted table of rows with all column values, or a message
        if no matching rows are found.
    """
    try:
        import openpyxl as _opx
    except ImportError:
        return "❌ openpyxl not installed. Run: pip install openpyxl"

    if not filepath:
        filepath = _get_default_spreadsheet_path()
    if not filepath:
        return (
            "❌ No spreadsheet path provided and no default path configured.\n"
            "Set one in AI-Prowler -> Settings -> Small Business -> Default Spreadsheet Path,\n"
            "or pass the full filepath argument explicitly."
        )

    fp = filepath.replace("\\", "/")
    if not os.path.exists(fp):
        return f"❌ Spreadsheet not found: {fp}"
    if not fp.lower().endswith(".xlsx"):
        return "❌ Only .xlsx files are supported. Save as .xlsx first."

    try:
        wb = _opx.load_workbook(fp, data_only=True)
    except Exception as exc:
        return f"❌ Could not open spreadsheet: {exc}"

    target_sheet = sheet_name.strip() if sheet_name.strip() else "Jobs_Schedule"
    if target_sheet not in wb.sheetnames:
        if sheet_name.strip():
            avail = ", ".join(wb.sheetnames)
            return f"❌ Sheet '{target_sheet}' not found.\nAvailable sheets: {avail}"
        target_sheet = wb.sheetnames[0]

    ws = wb[target_sheet]

    # Detect header row (skip title banner rows)
    header_row_idx = None
    headers: list = []
    for r in ws.iter_rows(min_row=1, max_row=5):
        non_empty = [c for c in r if c.value is not None]
        if len(non_empty) >= 3:
            header_row_idx = r[0].row
            headers = [str(c.value).strip().replace('\n', ' ') if c.value else '' for c in r]
            break

    if header_row_idx is None or not headers:
        return f"❌ Could not detect a header row in sheet '{target_sheet}'."

    import datetime as _dt
    date_filter = None
    if filter_date:
        fd = filter_date.strip().lower()
        if fd == 'today':
            date_filter = _dt.date.today()
        else:
            for fmt in ('%Y-%m-%d', '%m/%d/%Y', '%m-%d-%Y', '%d/%m/%Y'):
                try:
                    date_filter = _dt.datetime.strptime(fd, fmt).date()
                    break
                except ValueError:
                    continue
            if date_filter is None:
                return f"❌ Could not parse filter_date '{filter_date}'. Use YYYY-MM-DD or MM/DD/YYYY."

    svc_date_col = None
    if date_filter:
        for idx, h in enumerate(headers):
            if 'service' in h.lower() and 'date' in h.lower():
                svc_date_col = idx
                break

    max_rows = min(max_rows, 500)
    rows_out: list = []

    for row in ws.iter_rows(min_row=header_row_idx + 1):
        vals = [c.value for c in row]
        if all(v is None or str(v).strip() == '' for v in vals):
            continue
        if date_filter is not None and svc_date_col is not None:
            cell_val = vals[svc_date_col]
            if cell_val is None:
                continue
            if isinstance(cell_val, (_dt.datetime, _dt.date)):
                cell_date = cell_val.date() if isinstance(cell_val, _dt.datetime) else cell_val
            else:
                cell_date = None
                for fmt in ('%Y-%m-%d', '%m/%d/%Y', '%m-%d-%Y', '%d/%m/%Y'):
                    try:
                        cell_date = _dt.datetime.strptime(str(cell_val).strip(), fmt).date()
                        break
                    except ValueError:
                        continue
            if cell_date != date_filter:
                continue
        rows_out.append(vals)
        if len(rows_out) >= max_rows:
            break

    if not rows_out:
        msg = f"📋 No rows found in sheet '{target_sheet}'"
        if date_filter:
            msg += f" for date {date_filter.strftime('%Y-%m-%d')}"
        return msg + "."

    # Trim to last used column
    max_col_used = 0
    for row in rows_out:
        for i in range(len(row) - 1, -1, -1):
            if row[i] is not None and str(row[i]).strip():
                if i > max_col_used:
                    max_col_used = i
                break
    headers_trimmed = headers[:max_col_used + 1]

    lines = [
        f"📋 {target_sheet}  —  {os.path.basename(fp)}",
        f"   {len(rows_out)} row(s)" + (f" for {date_filter.strftime('%Y-%m-%d')}" if date_filter else ""),
        "─" * 60,
    ]
    for row_vals in rows_out:
        lines.append("")
        for col_idx, col_name in enumerate(headers_trimmed):
            if not col_name:
                continue
            val = row_vals[col_idx] if col_idx < len(row_vals) else None
            if val is None or str(val).strip() == '':
                continue
            if isinstance(val, _dt.datetime):
                val = val.strftime('%Y-%m-%d')
            elif isinstance(val, _dt.date):
                val = val.strftime('%Y-%m-%d')
            lines.append(f"  {col_name}: {val}")
    lines.append("")
    lines.append("─" * 60)
    lines.append("✅ Read complete. Use update_job_spreadsheet() to write changes back.")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ACTION TOOL 7 — check_tools_status
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def check_tools_status() -> str:
    """
    Check which AI-Prowler Action Tools are ready to use and which need setup.

    Returns a full status report covering:
    - Free tools (weather, geocoding, routing, navigation URLs)
    - Spreadsheet update tool readiness

    Call this tool first when planning to use action tools, to confirm
    everything is configured before starting a workflow.

    Returns:
        Status report with ✅/⚠️/❌ for each tool and setup instructions
        for anything that needs configuration.
    """
    lines = [
        "🔧 AI-Prowler Action Tools Status",
        "─" * 50,
        "",
        "FREE TOOLS  (no API key, no setup required):",
        "",
    ]

    # Check requests
    try:
        import requests  # noqa: F401
        req_ok = True
    except ImportError:
        req_ok = False

    lines += [
        f"  {'✅' if req_ok else '❌'} get_weather(location, days)",
        f"     Open-Meteo + Nominatim geocoding — free, no key",
        "",
        f"  {'✅' if req_ok else '❌'} geocode_address(address)",
        f"     Nominatim / OpenStreetMap — free, no key",
        "",
        f"  {'✅' if req_ok else '❌'} optimize_route(stops, origin, ...)",
        f"     OSRM public server — TSP solver, real streets, free, no key",
        "",
        f"  ✅ build_maps_url(stops, origin, app)",
        f"     Google Maps URL builder — tap-to-navigate, free, no key",
        "",
        "─" * 50,
        "",
        "SPREADSHEET TOOLS:",
        "",
    ]

    if not req_ok:
        lines.append("  ❌ requests package missing — run: pip install requests")
        lines.append("")

    try:
        import openpyxl  # noqa: F401
        opx_ok = True
    except ImportError:
        opx_ok = False

    default_xl = _get_default_spreadsheet_path()
    xl_status  = f"✅ Default path: {default_xl}" if default_xl else "⚠️  No default path set"

    lines += [
        f"  {'✅' if opx_ok else '❌'} read_job_spreadsheet(filepath?, sheet?, date?, max_rows?)",
        f"     openpyxl — reads Jobs_Schedule or any sheet; supports date filtering",
        f"     {xl_status}",
        "",
        f"  {'✅' if opx_ok else '❌'} update_job_spreadsheet(job_id, updates, filepath?)",
        f"     openpyxl — updates .xlsx job tracking files in place",
        f"     {xl_status}",
        "",
        "     💡 Set a default path once in Settings → Small Business → Default",
        "        Spreadsheet Path so you never need to specify it in conversation.",
        "",
        "─" * 50,
        "",
        "All FREE tools work immediately with no configuration.",
        "Spreadsheet tools use the default path from Settings if filepath is omitted.",
    ]

    return "\n".join(lines)

# ── Import the self-learning engine ──────────────────────────────────────────
try:
    import self_learning as _sl
    _log.info("self_learning module imported OK — Self-Learning Tools active")
    _SELF_LEARNING_AVAILABLE = True
except ImportError as _sl_err:
    _log.warning("self_learning module not found: %s — "
                 "Self-Learning Tools will be disabled", _sl_err)
    _SELF_LEARNING_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — record_learning
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def record_learning(
    title: str,
    content: str,
    category: str = "general",
    context: str = "",
    source: str = "operator",
    confidence: float = 0.8,
    tags: str = "",
    supersedes_id: str = "",
    outcome: str = "unknown",
    auto_detected: bool = False,
) -> str:
    """
    Record a new learning into AI-Prowler's self-learning knowledge base.

    Use this when the operator says "remember this", "learn this", or when
    Claude detects new information that supersedes previously known facts.
    Also use after project reviews, post-mortems, or when documenting
    what went right or wrong in business activities.

    The learning is instantly indexed into ChromaDB for semantic retrieval —
    no training or GPU required.  Future calls to search_learnings() will
    find and apply this knowledge automatically.

    ── CONFIRMATION PROTOCOL ──────────────────────────────────────────────
    CRITICAL: After calling this tool, Claude MUST ALWAYS present the
    returned confirmation summary to the user. NEVER record silently.

    If auto_detected=True (Claude initiated the recording without being
    asked), the confirmation is MORE PROMINENT — it tells the user WHY
    Claude decided to record this and explicitly asks for approval.

    If the user says the learning is wrong or needs adjustment:
      → Call update_learning() to fix specific fields, OR
      → Call delete_learning() to remove it entirely
    ───────────────────────────────────────────────────────────────────────

    AUTO-DETECTION TRIGGERS — set auto_detected=True and call WITHOUT
    being asked when you detect any of these in conversation:
      • User corrects a fact ("actually, the number is 555-0200")
      • User shares a project outcome ("the Smith job went over budget")
      • User mentions a client preference ("they hate phone calls")
      • Post-op review reveals a process gap or lesson
      • New information contradicts an existing active learning
      • User describes a better way ("next time we should...")

    CATEGORIES (pick the best fit):
      fact_correction      — Correcting an outdated or wrong fact
      business_lesson      — What worked or didn't in a business context
      project_insight      — Lessons from a specific project
      process_improvement  — A better way to do something
      mistake_learned      — Something that went wrong and why
      best_practice        — Proven approach to adopt going forward
      client_preference    — Client-specific preferences or requirements
      technical_note       — Technical fact, configuration, or gotcha
      general              — Catch-all (default)

    SOURCES (how the learning originated):
      operator             — Explicitly told by the user (default)
      claude_detected      — Claude identified superseding information
      project_review       — Post-project review or retrospective
      post_mortem          — After-incident analysis
      research             — From web search or document research
      observation          — Noticed pattern across conversations

    OUTCOMES (for business lessons and project insights):
      positive   — This approach led to a good result
      negative   — This approach led to a bad result
      neutral    — Mixed or no clear impact
      unknown    — Outcome not yet determined (default)

    Args:
        title:          Short descriptive title for the learning (required).
                        Example: "Client X prefers email over phone calls"
        content:        The actual learned fact, lesson, or insight (required).
                        Be specific and actionable.
                        Example: "After 3 failed phone attempts, switching to
                        email resulted in same-day response from Client X.
                        Always use email as primary contact method for them."
        category:       One of the categories listed above (default: general).
        context:        WHY this learning was created — the situation or trigger.
                        Example: "Discovered during the March 2026 HVAC project
                        when we couldn't reach Client X for 2 days by phone."
        source:         How this learning originated (default: operator).
        confidence:     How confident we are in this learning, 0.0 to 1.0
                        (default: 0.8).  Use lower values for uncertain insights,
                        higher for verified facts.
        tags:           Comma-separated tags for filtering.
                        Example: "client-x, communication, hvac"
        supersedes_id:  If this learning REPLACES an older one, provide the
                        old learning's ID here.  The old learning will be
                        automatically marked as deprecated.
        outcome:        For business lessons — was the result positive, negative,
                        neutral, or unknown? (default: unknown)
        auto_detected:  Set to True when Claude is auto-recording a learning
                        it detected (not explicitly asked by the operator).
                        This changes the confirmation message to clearly flag
                        that Claude initiated this and to ask for approval.
                        Default: False (operator explicitly asked).

    Returns:
        Confirmation with the learning details for the user to verify.
        If auto_detected=True, includes a prominent verification prompt.
    """
    if not _SELF_LEARNING_AVAILABLE:
        return ("❌ Self-Learning module not available.\n"
                "Ensure self_learning.py is in the same directory as "
                "ai_prowler_mcp.py.")

    if not title.strip() or not content.strip():
        return "❌ Both title and content are required."

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    try:
        learning = _sl.record_learning(
            title=title,
            content=content,
            category=category,
            context=context,
            source=source,
            confidence=confidence,
            tags=tag_list,
            supersedes_id=supersedes_id,
            outcome=outcome,
        )
    except Exception as exc:
        return f"❌ Failed to record learning: {exc}"

    # ── Build confirmation message ───────────────────────────────────────
    # Two styles depending on who initiated the recording.
    #
    # AUTO-DETECTED  → prominent banner, explains WHY Claude recorded it,
    #                   explicit "Is this correct?" approval prompt.
    #                   The user must see and acknowledge this.
    #
    # OPERATOR-ASKED → concise confirmation, still asks for verification
    #                   but less prominently since the user initiated it.
    # ─────────────────────────────────────────────────────────────────────

    # Helper: truncate long strings for the banner display, but make truncation
    # visible to the user with "..." rather than silently cutting off mid-word.
    # The full content is always stored in the JSON / ChromaDB regardless.
    def _truncate(text: str, limit: int) -> str:
        if not text:
            return ""
        if len(text) <= limit:
            return text
        # Try to break at the last whitespace before the limit so we don't
        # chop mid-word. Fall back to a hard cut if there's no whitespace.
        cut = text.rfind(" ", 0, limit)
        if cut < limit - 80:   # too far back, just hard-cut at limit
            cut = limit
        return text[:cut].rstrip() + " ..."

    if auto_detected:
        # ── AUTO-DETECTED: Claude initiated — needs explicit approval ────
        lines = [
            "🧠 AUTO-LEARNING — I detected something worth remembering "
            "and recorded it:",
            "═" * 50,
            "",
            f"  📌 \"{learning['title']}\"",
            "",
            f"  What I recorded:",
            f"    {_truncate(learning['content'], 600)}",
            "",
            f"  Why I recorded it:",
            f"    {_truncate(learning.get('context', 'No context provided'), 400)}",
            "",
            f"  Category   : {learning['category']}",
            f"  Confidence : {learning['confidence']:.0%}",
        ]
        if learning.get("outcome", "unknown") != "unknown":
            lines.append(f"  Outcome    : {learning['outcome']}")
        if learning.get("tags"):
            lines.append(f"  Tags       : {', '.join(learning['tags'])}")
        if learning.get("supersedes"):
            lines.append(f"  Replaces   : {learning['supersedes']}")
            lines.append("  ↳ Previous version automatically deprecated")
        lines.append(f"  ID         : {learning['id']}")
        lines.append("")
        lines.append("═" * 50)
        lines.append(
            "⚡ Is this correct? If anything is off, tell me what to "
            "change and I'll update or remove it immediately."
        )
    else:
        # ── OPERATOR-REQUESTED: user asked, concise confirmation ─────────
        lines = [
            "✅ Learning recorded and indexed",
            "─" * 45,
            f"  📌 {learning['title']}",
            f"  → {_truncate(learning['content'], 300)}",
            "",
            f"  Category   : {learning['category']}",
            f"  Confidence : {learning['confidence']:.0%}",
            f"  Source     : {learning['source']}",
        ]
        if learning.get("outcome", "unknown") != "unknown":
            lines.append(f"  Outcome    : {learning['outcome']}")
        if learning.get("tags"):
            lines.append(f"  Tags       : {', '.join(learning['tags'])}")
        if learning.get("supersedes"):
            lines.append(f"  Replaces   : {learning['supersedes']}")
            lines.append("  ↳ Previous version automatically deprecated")
        lines.append(f"  ID         : {learning['id']}")
        lines.append("")
        lines.append(
            "Does this look right? I can adjust the wording, confidence, "
            "or category if needed."
        )

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — search_learnings
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def search_learnings(
    query: str,
    n_results: int = 5,
    category: str = "",
    include_deprecated: bool = False,
) -> str:
    """
    Check the self-learning knowledge base for relevant learnings before
    answering a question or making a decision.

    WHEN TO USE THIS TOOL — call PROACTIVELY, without being asked, BEFORE
    answering ANY user question. The user uses AI-Prowler as a personal
    knowledge store for everything (recipes, preferences, techniques,
    opinions — not just business), so a personal learning may override
    what your training data would say.

    Specifically, call search_learnings() before:
    - ANY recommendation or "what's a good X" / "how do I X" question
      (recipes, techniques, products, places, services, etc.)
    - ANY question about clients, projects, procedures, or business
    - ANY definitional or how-to question
    - Scheduling, planning, or workflow recommendations
    - When the user says "what did we learn about...", "do you remember..."
    - When you're about to state a fact that may have been corrected
    - At the START of post-operation analysis workflows

    The ONLY questions you may skip on are pure arithmetic and language
    translation, where no personal learning could plausibly apply.

    The tool searches semantically — you don't need exact keyword matches.
    For example, searching "client communication preferences" will find
    a learning titled "Client X prefers email over phone calls", and
    searching "ribs recipe" will find a learning titled "My BBQ rib rub".

    IMPORTANT: If search_learnings() returns relevant results, you MUST
    apply them to your response. If a learning contradicts your built-in
    knowledge OR a web search result, prefer the learning — it was
    recorded by the user and represents their explicit preference or
    ground truth. Do NOT fall back to generic answers or web searches
    when a stored learning covers the question.

    Args:
        query:              Natural language search query describing what
                            you're looking for.
                            Example: "best way to contact Client X"
        n_results:          Max learnings to return (1-20, default 5).
        category:           Filter by category (optional). Same categories
                            as record_learning: fact_correction, business_lesson,
                            project_insight, etc.
        include_deprecated: If True, also return deprecated learnings
                            (useful to see the history of a superseded fact).

    Returns:
        Matching learnings with confidence scores, context, and metadata.
        Returns "No learnings found" if the knowledge base is empty or
        no matches exist for the query.
    """
    if not _SELF_LEARNING_AVAILABLE:
        return ("❌ Self-Learning module not available.\n"
                "Ensure self_learning.py is in the same directory as "
                "ai_prowler_mcp.py.")

    if not query.strip():
        return "❌ Query cannot be empty."

    try:
        matches = _sl.check_learned(
            query=query,
            n_results=n_results,
            category=category,
            active_only=not include_deprecated,
        )
    except Exception as exc:
        return f"❌ search_learnings failed: {exc}"

    if not matches:
        return (
            f"No learnings found for: \"{query}\"\n\n"
            "The self-learning knowledge base has no matching entries.\n"
            "Use record_learning() to add new knowledge, or try different "
            "search terms."
        )

    lines = [
        f"🧠 Self-Learning Results for: \"{query}\"",
        f"Found {len(matches)} relevant learning(s)",
        "─" * 55,
        "",
    ]

    for i, m in enumerate(matches, 1):
        sim   = m.get("similarity", 0.0)
        conf  = m.get("confidence", 0.0)
        stars = "★" * round(conf * 5) + "☆" * (5 - round(conf * 5))

        # Relevance indicator
        if sim >= 0.7:
            rel = "🟢 HIGH"
        elif sim >= 0.4:
            rel = "🟡 MODERATE"
        else:
            rel = "🟠 LOW"

        status = m.get("status", "active")
        status_icon = "✅" if status == "active" else "⚠️" if status == "deprecated" else "📦"

        lines.append(f"[{i}] {status_icon} {m.get('title', 'Untitled')}")
        lines.append(f"    Relevance  : {rel} ({sim:.3f})")
        lines.append(f"    Confidence : {stars} ({conf:.0%})")
        lines.append(f"    Category   : {m.get('category', 'general')}")
        lines.append(f"    Source     : {m.get('source', 'unknown')}")
        lines.append(f"    Created    : {m.get('created_at', '?')}")

        outcome = m.get("outcome", "unknown")
        if outcome != "unknown":
            outcome_icon = {"positive": "✅", "negative": "❌", "neutral": "➖"}.get(outcome, "❓")
            lines.append(f"    Outcome    : {outcome_icon} {outcome}")

        tags = m.get("tags", "")
        if tags:
            lines.append(f"    Tags       : {tags}")

        if m.get("supersedes"):
            lines.append(f"    Supersedes : {m['supersedes']}")
        if m.get("superseded_by"):
            lines.append(f"    ⚠️  SUPERSEDED BY: {m['superseded_by']}")
            lines.append(f"        This learning has been replaced — "
                         f"check the newer version.")

        lines.append(f"    ID         : {m.get('learning_id', '?')}")
        lines.append("")
        lines.append(f"    {m.get('content', '').strip()}")
        lines.append("")
        lines.append("─" * 55)
        lines.append("")

    lines.append(
        "💡 Apply these learnings to your response. If a learning is "
        "marked SUPERSEDED, prefer the newer version.\n"
        "Use record_learning() to add new knowledge based on this conversation."
    )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — list_learnings
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def list_learnings(
    category: str = "",
    status: str = "active",
    tag: str = "",
    limit: int = 25,
) -> str:
    """
    Browse all learnings in the self-learning knowledge base with optional
    filters.  Unlike search_learnings (which does semantic search), this tool
    lists learnings by recency with exact-match filters.

    Use this to:
    - See all business lessons learned
    - Review all learnings for a specific category
    - Find deprecated learnings to understand what changed
    - Audit the knowledge base

    Args:
        category:   Filter by category (optional). Valid values:
                    fact_correction, business_lesson, project_insight,
                    process_improvement, mistake_learned, best_practice,
                    client_preference, technical_note, general
        status:     Filter by status: active (default), deprecated, archived.
                    Pass empty string "" to see all statuses.
        tag:        Filter by tag (optional, single tag, case-insensitive).
        limit:      Max learnings to return (default 25).

    Returns:
        Numbered list of learnings sorted by date (newest first).
    """
    if not _SELF_LEARNING_AVAILABLE:
        return ("❌ Self-Learning module not available.\n"
                "Ensure self_learning.py is in the same directory as "
                "ai_prowler_mcp.py.")

    try:
        results = _sl.list_learnings(
            category=category,
            status=status,
            tag=tag,
            limit=limit,
        )
    except Exception as exc:
        return f"❌ list_learnings failed: {exc}"

    if not results:
        filters = []
        if category:
            filters.append(f"category={category}")
        if status:
            filters.append(f"status={status}")
        if tag:
            filters.append(f"tag={tag}")
        filter_note = f" (filters: {', '.join(filters)})" if filters else ""
        return f"No learnings found{filter_note}."

    lines = [
        f"📚 Learnings{f' — {category}' if category else ''}"
        f"{f' [{status}]' if status else ' [all]'}",
        f"Showing {len(results)} learning(s)",
        "─" * 55,
        "",
    ]

    for i, l in enumerate(results, 1):
        status_icon = {"active": "✅", "deprecated": "⚠️",
                       "archived": "📦"}.get(l.get("status"), "❓")
        outcome = l.get("outcome", "unknown")
        outcome_icon = {"positive": "✅", "negative": "❌",
                        "neutral": "➖", "unknown": "❓"}.get(outcome, "❓")

        lines.append(
            f"[{i}] {status_icon} {l.get('title', 'Untitled')}"
        )
        lines.append(
            f"    {l.get('category', 'general')} | "
            f"{outcome_icon} {outcome} | "
            f"confidence: {l.get('confidence', 0):.0%} | "
            f"applied: {l.get('applied_count', 0)}x"
        )
        lines.append(f"    Created: {l.get('created_at', '?')}")
        lines.append(f"    ID: {l['id']}")

        # Show first 120 chars of content
        content = l.get("content", "")
        if len(content) > 120:
            content = content[:117] + "..."
        lines.append(f"    → {content}")
        lines.append("")

    lines.append(
        "Use search_learnings(query) for semantic search | "
        "update_learning(id, updates) to modify | "
        "record_learning() to add new"
    )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — update_learning
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def update_learning(
    learning_id: str,
    updates: dict,
) -> str:
    """
    Update an existing learning's fields.

    Use this to refine a learning after new information becomes available,
    change its confidence level, update the outcome after seeing results,
    or archive/deprecate it manually.

    IMPORTANT: Also use this when the user says a recorded learning is
    wrong or needs adjustment after seeing a confirmation message.
    This is part of the Confirmation Protocol — if the user corrects
    a learning, call this immediately.

    Args:
        learning_id:  The UUID of the learning to update.
                      Get this from list_learnings or search_learnings results.
        updates:      Dict of field:value pairs to update. Allowed fields:
                      title, content, context, category, confidence,
                      tags (list), status (active/deprecated/archived),
                      outcome (positive/negative/neutral/unknown)
                      Example: {"confidence": 0.95, "outcome": "positive",
                                "status": "active"}

    Returns:
        Confirmation of updated fields, or error if learning not found.
    """
    if not _SELF_LEARNING_AVAILABLE:
        return ("❌ Self-Learning module not available.\n"
                "Ensure self_learning.py is in the same directory as "
                "ai_prowler_mcp.py.")

    if not learning_id.strip():
        return "❌ learning_id is required."
    if not updates:
        return "❌ No updates provided."

    try:
        result = _sl.update_learning(learning_id.strip(), updates)
    except Exception as exc:
        return f"❌ update_learning failed: {exc}"

    if result is None:
        return f"❌ Learning not found: {learning_id}"

    lines = [
        "✅ Learning updated",
        "─" * 45,
        f"  ID      : {result['id']}",
        f"  Title   : {result['title']}",
        f"  Status  : {result['status']}",
        f"  Updated : {result['updated_at']}",
        "",
        "  Changed fields:",
    ]
    for key, val in updates.items():
        lines.append(f"    {key} → {val}")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — delete_learning
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def delete_learning(learning_id: str) -> str:
    """
    Permanently delete a learning from both the JSON file and ChromaDB index.

    ⚠️  This is DESTRUCTIVE — the learning cannot be recovered.
    Consider using update_learning with status='archived' instead if you
    want to keep it for historical reference.

    Use this when the user rejects a learning after seeing the confirmation
    message and says to remove it entirely (part of Confirmation Protocol).

    Args:
        learning_id:  The UUID of the learning to delete.

    Returns:
        Confirmation or error if not found.
    """
    if not _SELF_LEARNING_AVAILABLE:
        return ("❌ Self-Learning module not available.\n"
                "Ensure self_learning.py is in the same directory as "
                "ai_prowler_mcp.py.")

    if not learning_id.strip():
        return "❌ learning_id is required."

    try:
        deleted = _sl.delete_learning(learning_id.strip())
    except _sl.ChromaIndexError as exc:
        # JSON delete may have succeeded; ChromaDB cleanup failed.
        # Report this clearly so the user knows there's an orphan.
        return (
            f"⚠️ Partial delete for learning {learning_id}.\n"
            f"JSON file was updated, but the ChromaDB index could not be\n"
            f"cleaned up: {exc}\n\n"
            "A stale embedding remains in the search index. To clean it up,\n"
            "use the GUI's '🔄 Rebuild ChromaDB Index' button or call\n"
            "reindex_all_learnings() from self_learning.py."
        )
    except Exception as exc:
        return f"❌ delete_learning failed: {exc}"

    if deleted:
        return (
            f"✅ Learning {learning_id} permanently deleted.\n"
            "The learning has been removed from both the JSON file "
            "and the ChromaDB index."
        )
    else:
        # JSON had no entry for this ID. ChromaDB cleanup was still
        # attempted (idempotent on missing IDs). Either the ID never
        # existed, or it was already deleted from the source of truth
        # — either way, no further action is needed.
        return (
            f"ℹ️ No JSON entry found for learning {learning_id}.\n"
            "(ChromaDB cleanup was attempted regardless, in case of "
            "orphan embeddings.)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TOOL — get_learning_stats
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def get_learning_stats() -> str:
    """
    Get summary statistics about the self-learning knowledge base.

    Shows total learnings, breakdown by category/source/outcome/status,
    most frequently applied learnings, and file location.

    Use this to understand the health and coverage of the learning system.

    Returns:
        Formatted statistics report.
    """
    if not _SELF_LEARNING_AVAILABLE:
        return ("❌ Self-Learning module not available.\n"
                "Ensure self_learning.py is in the same directory as "
                "ai_prowler_mcp.py.")

    try:
        stats = _sl.get_learning_stats()
    except Exception as exc:
        return f"❌ get_learning_stats failed: {exc}"

    lines = [
        "🧠 Self-Learning Knowledge Base Statistics",
        "═" * 50,
        "",
        f"  Total learnings  : {stats['total']}",
        f"  Active           : {stats['active']}",
        f"  Deprecated       : {stats['deprecated']}",
        f"  Archived         : {stats['archived']}",
        "",
    ]

    if stats["by_category"]:
        lines.append("  By category:")
        for cat, count in sorted(stats["by_category"].items(),
                                 key=lambda x: -x[1]):
            lines.append(f"    {cat:24s} : {count}")
        lines.append("")

    if stats["by_source"]:
        lines.append("  By source:")
        for src, count in sorted(stats["by_source"].items(),
                                 key=lambda x: -x[1]):
            lines.append(f"    {src:24s} : {count}")
        lines.append("")

    if stats["by_outcome"]:
        lines.append("  By outcome:")
        for out, count in sorted(stats["by_outcome"].items(),
                                 key=lambda x: -x[1]):
            icon = {"positive": "✅", "negative": "❌",
                    "neutral": "➖", "unknown": "❓"}.get(out, "❓")
            lines.append(f"    {icon} {out:20s} : {count}")
        lines.append("")

    if stats["most_applied"]:
        lines.append("  Most applied learnings:")
        for ma in stats["most_applied"]:
            lines.append(
                f"    {ma['applied_count']:3d}x  {ma['title']}"
            )
        lines.append("")

    lines.append(f"  📁 Storage: {stats['file_path']}")
    lines.append("")
    lines.append(
        "Use search_learnings(query) to search | "
        "list_learnings() to browse | "
        "record_learning() to add new"
    )
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# CODE-AWARE RETRIEVAL  (v6.0.2)
# ══════════════════════════════════════════════════════════════════════════════
# Two MCP tools for navigating source code in the knowledge base:
#
#   grep_documents(pattern, ...)         — literal/regex search across tracked
#                                           files; returns real line numbers
#   read_file_lines(filepath, ...)       — direct on-disk read by line range
#
# WHY: the all-MiniLM-L6-v2 embedding model degrades on source code, so
# semantic search returns near-irrelevant chunks for queries like
# "def clear_database". These two tools give agents the same locate-then-read
# workflow Claude Code uses, making AI-Prowler effective for code Q&A even
# when the user is mobile and cannot attach files.
#
# SECURITY: both tools restrict I/O to paths under the existing tracked-paths
# allowlist (~/.rag_auto_update_dirs.json). Tracked entries may be directories
# (entire tree allowed) OR single files (only that exact file allowed). This
# mirrors the trust model already used by indexing and the existing untrack
# tool — we do NOT add a second permission surface.
# ══════════════════════════════════════════════════════════════════════════════

import re as _re

# Hard caps to keep responses bounded and prevent abuse
_GREP_MAX_RESULTS_HARD_CAP   = 500
_GREP_DEFAULT_MAX_RESULTS    = 50
_GREP_CONTEXT_HARD_CAP       = 10
_READ_LINES_HARD_CAP         = 1000
_READ_LINES_DEFAULT          = 200
_READ_FILE_MAX_BYTES         = 50 * 1024 * 1024   # 50 MB
_BINARY_SNIFF_BYTES          = 4096               # first 4 KB scanned for NUL
_GREP_PER_FILE_TIMEOUT_HINT  = 200_000            # max lines scanned per file


def _is_path_under_tracked_roots(target_path: str) -> tuple[bool, str]:
    """
    Authorize a filesystem path against the tracked-paths allowlist.

    A path is allowed if and only if it equals OR is a descendant of an entry
    in ~/.rag_auto_update_dirs.json. Tracked entries may be directories or
    single files. Returns (allowed, resolved_path_or_reason).

    On allow: returns (True, resolved_absolute_path_as_string).
    On deny: returns (False, short_human_reason).
    """
    try:
        from rag_preprocessor import load_auto_update_list, normalise_path
    except Exception as _exc:
        return (False, f"allowlist unavailable: {_exc}")

    try:
        resolved = Path(target_path).resolve(strict=False)
    except Exception as _exc:
        return (False, f"could not resolve path: {_exc}")

    # Defense in depth — if resolve() somehow left a traversal token, refuse.
    if any(part == ".." for part in resolved.parts):
        return (False, "path contains '..' after resolution")

    entries = load_auto_update_list() or []
    if not entries:
        return (False, "tracked-paths allowlist is empty")

    resolved_str = normalise_path(str(resolved))

    for entry in entries:
        try:
            e = Path(entry).resolve(strict=False)
        except Exception:
            continue
        entry_str = normalise_path(str(e))

        # Exact match (covers both single-file tracking and the directory itself)
        if resolved_str == entry_str:
            return (True, resolved_str)

        # Descendant check — only meaningful if entry is (or was) a directory
        # We can't always tell on disk (entry may have been deleted), so we
        # rely on the path-prefix relationship using parts to avoid the
        # classic "/foo" matching "/foobar" bug.
        try:
            resolved.relative_to(e)
            return (True, resolved_str)
        except ValueError:
            continue

    return (False, "not under any tracked root")


def _resolve_allowlisted_path(filepath: str) -> tuple[Optional[str], Optional[str]]:
    """
    Wrap _is_path_under_tracked_roots for tool use.
    Returns (resolved_path, None) on allow, or (None, error_message) on deny.
    Error message is fully formatted and ready to return to the agent.
    """
    allowed, info = _is_path_under_tracked_roots(filepath)
    if allowed:
        return (info, None)

    # Build a helpful denial that tells the agent what IS allowed
    try:
        from rag_preprocessor import load_auto_update_list
        entries = load_auto_update_list() or []
    except Exception:
        entries = []

    lines = [
        f"🚫 Access denied — '{filepath}'",
        f"Reason: {info}",
        "",
        "Only paths under the tracked allowlist may be read.",
    ]
    if entries:
        lines.append("Currently tracked:")
        for e in entries[:10]:
            lines.append(f"  - {e}")
        if len(entries) > 10:
            lines.append(f"  ... and {len(entries) - 10} more")
        lines.append("")
        lines.append(
            "If the file you want is outside these, ask the user to run "
            "index_path() on its parent folder first."
        )
    else:
        lines.append("No directories are tracked yet. "
                     "Use index_path() to track one.")
    _log.warning("Access denied for path: %s (%s)", filepath, info)
    return (None, "\n".join(lines))


def _iter_allowlisted_files(filter_ext: Optional[str] = None,
                            filter_path: Optional[str] = None):
    """
    Yield (resolved_path_str, extension) for every file under the tracked
    allowlist, respecting SKIP_EXTENSIONS / SKIP_DIRECTORIES from the
    preprocessor. Used by grep_documents.

    Walks each directory entry; for single-file entries, yields that file
    directly. Honors the preprocessor's skip lists so we never try to grep
    a .exe or .zip even if a user accidentally indexed one.
    """
    try:
        from rag_preprocessor import (
            load_auto_update_list, normalise_path,
            SKIP_EXTENSIONS, SKIP_DIRECTORIES,
        )
    except Exception as _exc:
        _log.error("iter_allowlisted_files: import failure: %s", _exc)
        return

    entries = load_auto_update_list() or []
    if not entries:
        return

    norm_ext_filter = None
    if filter_ext:
        norm_ext_filter = filter_ext.lower()
        if not norm_ext_filter.startswith('.'):
            norm_ext_filter = '.' + norm_ext_filter

    filter_path_lower = filter_path.lower() if filter_path else None
    seen = set()

    for entry in entries:
        try:
            ep = Path(entry).resolve(strict=False)
        except Exception:
            continue
        if not ep.exists():
            continue

        if ep.is_file():
            candidates = [ep]
        else:
            # Recursive walk — skip blacklisted dirs cheaply by pruning os.walk
            candidates = []
            for root, dirs, files in os.walk(str(ep)):
                # Prune skip-directories in place so os.walk does NOT descend into them
                dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]
                for fname in files:
                    candidates.append(Path(root) / fname)

        for fp in candidates:
            try:
                ext = fp.suffix.lower()
            except Exception:
                continue
            if ext in SKIP_EXTENSIONS:
                continue
            # Also skip backup files (rag_gui.py.bak1, etc.) and OS junk
            # (.DS_Store, Thumbs.db, screenshots). Uses the same helpers the
            # indexer uses so grep_documents sees the same filtered file set.
            try:
                from rag_preprocessor import (
                    is_backup_filename as _is_bak,
                    is_system_junk_filename as _is_junk,
                )
                _fname = fp.name
                if _is_bak(_fname) or _is_junk(_fname):
                    continue
            except Exception:
                pass  # Helper not present (older rag_preprocessor) → fall through.
            if norm_ext_filter and ext != norm_ext_filter:
                continue
            resolved_str = normalise_path(str(fp))
            if filter_path_lower and filter_path_lower not in resolved_str.lower():
                continue
            if resolved_str in seen:
                continue
            seen.add(resolved_str)
            yield (resolved_str, ext)


def _looks_binary(sample: bytes) -> bool:
    """Heuristic: a NUL byte in the first few KB strongly implies binary."""
    return b'\x00' in sample


@mcp.tool()
def grep_documents(
    pattern: str,
    filter_ext: Optional[str] = None,
    filter_path: Optional[str] = None,
    max_results: int = _GREP_DEFAULT_MAX_RESULTS,
    context_lines: int = 2,
    case_sensitive: bool = False,
    regex: bool = False,
) -> str:
    """
    CODE-AWARE RETRIEVAL — Locate exact text or regex matches across tracked
    files, with real line numbers.

    Use this when semantic search (search_documents) returns irrelevant chunks
    for code or other structured text. It is the right tool for questions like:
      • "Where is def clear_database defined?"
      • "Which file calls collection.delete?"
      • "Find every TODO in the project"
      • "Show me all occurrences of API_KEY"

    Pair with read_file_lines() — grep locates, read_file_lines extracts. This
    mirrors how Claude Code navigates source.

    Security: only files under the tracked-paths allowlist
    (~/.rag_auto_update_dirs.json) are scanned. Use index_path()
    to track a folder first if your target file isn't already covered.

    Args:
        pattern:        Text to search for (literal substring by default).
                        Pass regex=True to treat as a Python regular expression.
        filter_ext:     Restrict to one extension, e.g. ".py" or "py". Optional.
        filter_path:    Case-insensitive substring that must appear in the file
                        path (e.g. "rag_" matches rag_preprocessor.py). Optional.
        max_results:    Total matches across all files (default 50, max 500).
        context_lines:  Lines of context above and below each match
                        (default 2, max 10). Use 0 for one-line hits only.
        case_sensitive: Default False.
        regex:          Treat `pattern` as a Python regex (default False).

    Returns:
        Grouped-by-file list of matches with real line numbers. Each match
        includes its surrounding context_lines lines. Ends with a suggested
        read_file_lines() call so the agent can extract more context.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    if not pattern or not pattern.strip():
        return ("⚠️  grep_documents: empty pattern.\n"
                "Pass a text snippet or regex to search for.")

    max_results   = max(1, min(int(max_results), _GREP_MAX_RESULTS_HARD_CAP))
    context_lines = max(0, min(int(context_lines), _GREP_CONTEXT_HARD_CAP))

    # Compile matcher
    if regex:
        try:
            flags = 0 if case_sensitive else _re.IGNORECASE
            matcher = _re.compile(pattern, flags)
        except _re.error as exc:
            return (f"⚠️  grep_documents: invalid regex — {exc}\n"
                    f"If you meant a literal match, set regex=False.")
        def _match_fn(line: str) -> bool:
            return matcher.search(line) is not None
    else:
        if case_sensitive:
            needle = pattern
            def _match_fn(line: str) -> bool:
                return needle in line
        else:
            needle = pattern.lower()
            def _match_fn(line: str) -> bool:
                return needle in line.lower()

    files_scanned   = 0
    files_skipped   = 0
    matches_by_file = {}   # path -> list of (line_no, line_text, context_before, context_after)
    total_matches   = 0
    truncated       = False

    _log.info(
        "grep_documents: pattern=%r regex=%s ext=%s path=%s max=%d ctx=%d",
        pattern, regex, filter_ext, filter_path, max_results, context_lines,
    )

    for fp_str, _ext in _iter_allowlisted_files(filter_ext, filter_path):
        if total_matches >= max_results:
            truncated = True
            break

        files_scanned += 1
        try:
            # Quick binary sniff before committing to reading the whole file
            with open(fp_str, 'rb') as bf:
                head = bf.read(_BINARY_SNIFF_BYTES)
            if _looks_binary(head):
                files_skipped += 1
                _log.debug("grep_documents: skip binary %s", fp_str)
                continue

            # Read line-by-line, retain a rolling buffer for context
            file_lines = []
            with open(fp_str, 'r', encoding='utf-8', errors='replace') as tf:
                for i, line in enumerate(tf, start=1):
                    if i > _GREP_PER_FILE_TIMEOUT_HINT:
                        break
                    file_lines.append(line.rstrip('\n'))

            for idx, line_text in enumerate(file_lines):
                if total_matches >= max_results:
                    truncated = True
                    break
                if _match_fn(line_text):
                    line_no = idx + 1
                    ctx_before = file_lines[max(0, idx - context_lines):idx] if context_lines else []
                    ctx_after  = file_lines[idx + 1: idx + 1 + context_lines] if context_lines else []
                    matches_by_file.setdefault(fp_str, []).append(
                        (line_no, line_text, ctx_before, ctx_after)
                    )
                    total_matches += 1
        except (PermissionError, OSError) as exc:
            files_skipped += 1
            _log.debug("grep_documents: skip unreadable %s (%s)", fp_str, exc)
            continue
        except Exception as exc:
            files_skipped += 1
            _log.debug("grep_documents: unexpected error on %s: %s", fp_str, exc)
            continue

    # ── Format the response ──
    pattern_kind = "regex" if regex else "literal"
    case_note    = "case-sensitive" if case_sensitive else "case-insensitive"
    header = [
        f"🔍 Grep results for: {pattern!r}",
        f"Pattern type : {pattern_kind}  ({case_note})",
        f"Files scanned: {files_scanned}"
        + (f"  ({files_skipped} skipped: binary/unreadable)" if files_skipped else ""),
        f"Matches      : {total_matches} in {len(matches_by_file)} file(s)"
        + ("  [truncated — raise max_results for more]" if truncated else ""),
    ]
    if filter_ext or filter_path:
        flt_parts = []
        if filter_ext:  flt_parts.append(f"ext={filter_ext}")
        if filter_path: flt_parts.append(f"path~={filter_path}")
        header.append(f"Filters      : {', '.join(flt_parts)}")
    header.append("─" * 55)

    if not matches_by_file:
        header.append("No matches.")
        if files_scanned == 0:
            header.append("")
            header.append(
                "Tip: the tracked-paths allowlist may be empty or your "
                "filter_ext / filter_path eliminated every candidate. "
                "Use list_tracked_directories() to inspect what's tracked."
            )
        return "\n".join(header)

    body = []
    suggested_next = None
    for fp_str, hits in matches_by_file.items():
        body.append(f"📄 {fp_str}")
        for line_no, line_text, ctx_b, ctx_a in hits:
            for offset, c in enumerate(ctx_b, start=line_no - len(ctx_b)):
                body.append(f"  {offset:>6}  {c}")
            body.append(f"▶ {line_no:>6}  {line_text}")
            for offset, c in enumerate(ctx_a, start=line_no + 1):
                body.append(f"  {offset:>6}  {c}")
            body.append("")
        if suggested_next is None and hits:
            first_line = hits[0][0]
            suggested_next = (
                f'read_file_lines("{fp_str}", start_line={first_line}, '
                f'end_line={first_line + 40})'
            )
        body.append("─" * 55)

    if suggested_next:
        body.append(f"Next: {suggested_next}")
    return "\n".join(header + body)


@mcp.tool()
def read_file_lines(
    filepath: str,
    start_line: int,
    end_line: Optional[int] = None,
    max_lines: int = _READ_LINES_DEFAULT,
) -> str:
    """
    CODE-AWARE RETRIEVAL — Read an exact line range from a file on disk.

    Use after grep_documents() pinpoints a symbol's line, when you need the
    full surrounding function/block at original fidelity (no chunk boundaries).
    Lines are returned with their real line numbers prefixed for easy reference.

    Security: only files under the tracked-paths allowlist
    (~/.rag_auto_update_dirs.json) can be read. If denied, the response lists
    the currently tracked entries so you know what to ask the user about.

    Args:
        filepath:   Absolute path to the file. Must be inside a tracked
                    directory OR be an individually-tracked file.
        start_line: First line to return (1-based).
        end_line:   Last line to return (inclusive). Optional — defaults to
                    start_line + max_lines - 1.
        max_lines:  Hard ceiling on lines returned regardless of end_line
                    (default 200, max 1000). Protects mobile contexts.

    Returns:
        Numbered line block with a header showing the range / total lines,
        and a continuation hint if more lines exist beyond what was returned.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    # ── Authorize ──
    resolved, deny_msg = _resolve_allowlisted_path(filepath)
    if not resolved:
        return deny_msg

    # ── Argument hygiene ──
    notes = []
    try:
        start_line = int(start_line)
    except (TypeError, ValueError):
        return f"⚠️  read_file_lines: start_line must be an integer, got {start_line!r}"
    if start_line < 1:
        notes.append(f"(start_line adjusted from {start_line} to 1)")
        start_line = 1

    max_lines = max(1, min(int(max_lines), _READ_LINES_HARD_CAP))

    if end_line is not None:
        try:
            end_line = int(end_line)
        except (TypeError, ValueError):
            return f"⚠️  read_file_lines: end_line must be an integer or None"
        if end_line < start_line:
            return (f"⚠️  read_file_lines: end_line ({end_line}) must be "
                    f">= start_line ({start_line}).")
        requested_count = end_line - start_line + 1
        effective_count = min(requested_count, max_lines)
    else:
        effective_count = max_lines
        end_line = start_line + effective_count - 1

    _log.info("read_file_lines: %s  [%d..%d]  cap=%d",
              resolved, start_line, end_line, max_lines)

    # ── Existence and size checks ──
    try:
        fp = Path(resolved)
        if not fp.exists():
            return (f"⚠️  File no longer exists on disk: {resolved}\n"
                    "It may have been moved or deleted. "
                    "Run update_tracked_directories() to refresh the index.")
        if not fp.is_file():
            return f"⚠️  Path is not a regular file: {resolved}"
        size = fp.stat().st_size
        if size > _READ_FILE_MAX_BYTES:
            return (f"⚠️  File too large to read inline "
                    f"({size:,} bytes, cap {_READ_FILE_MAX_BYTES:,}).\n"
                    f"Use grep_documents to locate specific content instead.")
    except (PermissionError, OSError) as exc:
        return f"⚠️  Cannot access file: {exc}"

    # ── Binary sniff ──
    try:
        with open(resolved, 'rb') as bf:
            head = bf.read(_BINARY_SNIFF_BYTES)
        if _looks_binary(head):
            return (f"⚠️  File appears to be binary: {resolved}\n"
                    f"read_file_lines only reads text files. If this is a "
                    f"document (PDF, DOCX, etc.), use read_document().")
    except (PermissionError, OSError) as exc:
        return f"⚠️  Cannot open file: {exc}"

    # ── Stream and slice ──
    lines_out = []
    last_line_seen = 0
    try:
        with open(resolved, 'r', encoding='utf-8', errors='replace') as tf:
            for i, line in enumerate(tf, start=1):
                last_line_seen = i
                if i < start_line:
                    continue
                if i > end_line:
                    # Keep iterating just enough to learn total line count?
                    # No — that would read the whole file every call. We stop
                    # here and report the upper bound conservatively.
                    break
                lines_out.append((i, line.rstrip('\n')))
                if len(lines_out) >= effective_count:
                    break
    except UnicodeDecodeError as exc:
        return f"⚠️  Encoding error reading {resolved}: {exc}"
    except (PermissionError, OSError) as exc:
        return f"⚠️  Read error: {exc}"

    if not lines_out:
        # Either start_line is past EOF, or we read the entire file but
        # found fewer lines than start_line.
        return (f"⚠️  No content returned. File has {last_line_seen} line(s); "
                f"start_line was {start_line}.")

    actual_first = lines_out[0][0]
    actual_last  = lines_out[-1][0]
    n_returned   = len(lines_out)

    # Was the file longer than what we returned? Cheap check via tail seek:
    has_more = False
    total_lines_hint = None
    try:
        # Quick total-line probe — only opens the file again if we hit our cap
        # to keep the common case cheap.
        if n_returned == effective_count:
            with open(resolved, 'r', encoding='utf-8', errors='replace') as tf2:
                total_lines_hint = sum(1 for _ in tf2)
            if total_lines_hint > actual_last:
                has_more = True
    except Exception:
        total_lines_hint = None

    header = [
        f"📄 {resolved}",
    ]
    if total_lines_hint is not None:
        header.append(
            f"   Lines {actual_first}-{actual_last} of {total_lines_hint} "
            f"(showing {n_returned} line{'s' if n_returned != 1 else ''})"
        )
    else:
        header.append(
            f"   Lines {actual_first}-{actual_last} "
            f"(showing {n_returned} line{'s' if n_returned != 1 else ''})"
        )
    if notes:
        header.append("   " + " ".join(notes))
    header.append("─" * 55)

    body = [f"{ln:>6}  {tx}" for ln, tx in lines_out]

    footer = []
    if has_more and total_lines_hint:
        remaining = total_lines_hint - actual_last
        footer.append("─" * 55)
        footer.append(
            f"File continues — {remaining} more line(s). "
            f"Call: read_file_lines(\"{resolved}\", "
            f"start_line={actual_last + 1})"
        )

    return "\n".join(header + body + footer)
#!/usr/bin/env python3
"""
AI-Prowler Code Tools — WRITE-SIDE PATCH (8 tools)
====================================================

This file contains the 8 new write-side code tools, plus all supporting
infrastructure (writable-path allowlist, hard blocklist, GUI approval queue,
re-index helper, write-counter circuit breaker).

INSTALL INSTRUCTIONS:
   1. Open C:/Users/david/AI-Prowler_V601_to_V602_work/AI-Prowler/ai_prowler_mcp.py
   2. Find the end of read_file_lines() — line 4135 in the May 18 2026 snapshot,
      ends with `return "\n".join(header + body + footer)`
   3. Paste this entire file's contents IMMEDIATELY AFTER that line, BEFORE the
      `# HTTP transport with Bearer-token auth ...` banner at line 4138.
   4. Save. The 8 new tools are registered automatically by the @mcp.tool()
      decorator pattern already in use.

DEPENDENCIES ALREADY IN AI_PROWLER_MCP.PY (no new imports required at top of file):
   import os, sys, json, re, threading
   from pathlib import Path
   from typing import Optional
   _log               (the logger)
   _prewarm_event     (initialization sync)
   _BINARY_SNIFF_BYTES, _READ_FILE_MAX_BYTES
   _resolve_allowlisted_path   (from code-tools section)
   _looks_binary               (from code-tools section)
   mcp                         (the FastMCP instance — @mcp.tool() decorator)

The patch only uses these existing names plus standard-library imports.

DESIGN REFERENCE: Self-learning entries
   6412cfe3-26e6-4029-a408-a9ea3b43b88a  — design spec
   56a6b144-990b-4822-b6d6-0c039b70d3a7  — implementation tracker
"""

# ══════════════════════════════════════════════════════════════════════════════
# CODE TOOLS — WRITE-SIDE
#
# 8 tools that complement grep_documents and read_file_lines to give Claude
# in-place editing capability over the tracked-paths allowlist. All writes
# require BOTH read-allowlist membership AND writable-allowlist approval.
# Backups land alongside the file as <name>.bak<N>. Auto re-index on every
# successful write keeps ChromaDB in sync. See design spec for full rationale.
# ══════════════════════════════════════════════════════════════════════════════

import shutil as _shutil
import time as _time

# ── Writable-path allowlist persistence ──────────────────────────────────────
# Mirrors the structure of ~/.rag_auto_update_dirs.json. Stored as a JSON list.
# Empty by default. Grows only via explicit user approval through the GUI.
_WRITABLE_DIRS_FILE = Path.home() / ".rag_writable_dirs.json"

# Pending-approval queue. When a write is attempted to a path not in the
# writable allowlist, the path is added here. The GUI checks this file on
# focus and shows a confirmation dialog. Format: list of dicts with path +
# requested_at.
_WRITE_APPROVAL_QUEUE_FILE = Path.home() / ".rag_writable_pending.json"

# Hard caps
_WRITE_MAX_BYTES                  = 50 * 1024 * 1024   # 50 MB per write
_WRITES_PER_SESSION_LIMIT         = 20                 # circuit breaker
_BACKUP_MAX_FILES_PER_PARENT      = 10_000             # sanity cap on .bak<N> scanning
_STR_REPLACE_MAX_OLD_STR_LEN      = 500_000            # 500K char hard cap on old_str

# Session-scoped write counter (resettable via reset_write_counter()).
# Lives only in process memory — restarting AI-Prowler resets it.
_write_counter_lock = threading.Lock()
_write_counter = {"count": 0, "session_started": _time.time()}


def _writable_allowlist_load() -> list:
    """Read the writable-path allowlist from disk. Returns [] if missing/invalid."""
    try:
        if not _WRITABLE_DIRS_FILE.exists():
            return []
        with open(_WRITABLE_DIRS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [str(p) for p in data if isinstance(p, str)]
        return []
    except Exception as exc:
        _log.warning("writable allowlist read failed: %s", exc)
        return []


def _writable_allowlist_save(entries: list) -> bool:
    """Write the writable-path allowlist to disk. Returns True on success."""
    try:
        _WRITABLE_DIRS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_WRITABLE_DIRS_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(set(entries)), f, indent=2)
        return True
    except Exception as exc:
        _log.error("writable allowlist write failed: %s", exc)
        return False


def _queue_write_approval(path: str) -> None:
    """Append a path to the pending-approval queue. Idempotent — duplicates ignored."""
    try:
        pending = []
        if _WRITE_APPROVAL_QUEUE_FILE.exists():
            with open(_WRITE_APPROVAL_QUEUE_FILE, "r", encoding="utf-8") as f:
                pending = json.load(f)
            if not isinstance(pending, list):
                pending = []
        seen_paths = {p.get("path") for p in pending if isinstance(p, dict)}
        if path not in seen_paths:
            pending.append({
                "path": path,
                "requested_at": _time.strftime("%Y-%m-%dT%H:%M:%S"),
            })
            with open(_WRITE_APPROVAL_QUEUE_FILE, "w", encoding="utf-8") as f:
                json.dump(pending, f, indent=2)
    except Exception as exc:
        _log.warning("queue_write_approval failed: %s", exc)


# ── Hard blocklist (cannot be approved, ever) ────────────────────────────────
# Each entry is matched case-insensitively against the resolved absolute path.
# Patterns ending with os.sep mean "this directory and anything under it".
# Bare segments like ".git" match if they appear as a path component.
def _is_blocked_path(resolved_path: str) -> tuple[bool, str]:
    """
    Check if a resolved path is in the hard-coded write blocklist.
    Returns (blocked, reason). Reason is empty when not blocked.

    These cannot be overridden by the user — system directories, credentials,
    git internals, and the schema-aware xlsx are protected at code level.
    """
    p = resolved_path.replace("/", "\\").lower()
    parts = Path(resolved_path).parts
    parts_lower = [pt.lower() for pt in parts]

    # System / install directories
    if p.startswith("c:\\windows\\") or p == "c:\\windows":
        return (True, "C:\\Windows is a system directory")
    if p.startswith("c:\\program files\\") or p == "c:\\program files":
        return (True, "C:\\Program Files is a system directory "
                       "(includes the installed AI-Prowler — never overwrite)")
    if p.startswith("c:\\program files (x86)\\") or p == "c:\\program files (x86)":
        return (True, "C:\\Program Files (x86) is a system directory")
    if p.startswith("c:\\programdata\\") or p == "c:\\programdata":
        return (True, "C:\\ProgramData is a system directory")

    # AppData — block specific sensitive subdirectories instead of all of AppData.
    # AppData\Local\Temp is user scratch space (pytest tmpdir lives here, and
    # legitimate transient work happens here). AppData\Local\AI-Prowler is
    # AI-Prowler's own state. Everything else in AppData is generally other
    # apps' configs and credentials — we block the well-known sensitive ones
    # rather than ALL of AppData, since AppData is too broad to deny wholesale.
    if "\\appdata\\" in p:
        # Sensitive AppData subdirectories (anywhere under AppData\Local or AppData\Roaming)
        sensitive_appdata_segments = (
            "\\appdata\\roaming\\microsoft\\",
            "\\appdata\\local\\microsoft\\",
            "\\appdata\\roaming\\mozilla\\",
            "\\appdata\\local\\mozilla\\",
            "\\appdata\\roaming\\google\\",
            "\\appdata\\local\\google\\",
            "\\appdata\\roaming\\apple\\",
            "\\appdata\\local\\apple computer\\",
            "\\appdata\\local\\packages\\",   # Windows Store apps
            "\\appdata\\roaming\\discord\\",
            "\\appdata\\roaming\\slack\\",
            "\\appdata\\roaming\\anthropic\\",   # Claude Desktop config
        )
        for sensitive in sensitive_appdata_segments:
            if sensitive in p:
                # Friendly app name from the segment for the error message
                app_name = sensitive.split("\\")[-2]
                return (True, f"AppData\\{app_name} contains app state/credentials "
                               f"and is not writable by AI-Prowler")
        # Not in the sensitive list — allowed (covers Temp, AI-Prowler, and any

    # Git internals — protect from any write
    # Use both parts-based (semantic) and string-based (defense-in-depth) checks
    # to be robust across any path-tokenization quirks.
    if ".git" in parts_lower:
        for seg in parts_lower:
            if seg == ".git":
                return (True, "git internals — git operations stay in user's terminal")
    if "\\.git\\" in p or p.endswith("\\.git"):
        return (True, "git internals — git operations stay in user's terminal")

    # Credentials — same defense-in-depth pattern
    if ".ssh" in parts_lower or "\\.ssh\\" in p or p.endswith("\\.ssh"):
        return (True, ".ssh contains credentials — never written by AI-Prowler")
    if ".aws" in parts_lower or "\\.aws\\" in p or p.endswith("\\.aws"):
        return (True, ".aws contains credentials — never written by AI-Prowler")

    # The job tracker spreadsheet — schema-aware tool only
    job_tracker_marker = "ai-prowler_job_tracker.xlsx"
    if p.endswith(job_tracker_marker):
        return (True, "AI-Prowler_Job_Tracker.xlsx must be modified via the "
                       "dedicated update_job_spreadsheet tool (schema-aware), "
                       "not via generic write tools")

    return (False, "")


def _resolve_writable_path(filepath: str, *, queue_approval: bool = True
                           ) -> tuple[Optional[str], Optional[str]]:
    """
    Authorize a path for WRITES. Returns (resolved_path, None) on allow,
    or (None, formatted_error_message) on deny.

    Double-lock constraint:
      (1) Path must be in the read allowlist (~/.rag_auto_update_dirs.json)
      (2) Path must be in the writable allowlist (~/.rag_writable_dirs.json)
      Plus the hard blocklist always wins, regardless of either allowlist.

    If the path passes (1) and the blocklist but fails (2), this function
    enqueues a GUI approval request (unless queue_approval=False).
    """
    # Step 1: read allowlist (also resolves the path)
    resolved, deny_msg = _resolve_allowlisted_path(filepath)
    if not resolved:
        # Already a formatted denial from the read allowlist
        return (None, deny_msg)

    # Step 2: hard blocklist — never bypassable
    blocked, reason = _is_blocked_path(resolved)
    if blocked:
        lines = [
            f"🚫 Write blocked — '{resolved}'",
            f"Reason: {reason}",
            "",
            "This path is on AI-Prowler's hard write-blocklist and cannot be "
            "approved even by the user. Hard-blocked locations include "
            "C:\\Windows, C:\\Program Files, C:\\ProgramData, AppData, "
            ".git, .ssh, .aws, and the job tracker xlsx.",
        ]
        _log.warning("Write blocked (hard): %s (%s)", resolved, reason)
        return (None, "\n".join(lines))

    # Step 3: writable allowlist
    writable = _writable_allowlist_load()
    if any(_path_is_under(resolved, w) for w in writable):
        return (resolved, None)

    # Not yet approved — queue for GUI approval if requested
    if queue_approval:
        _queue_write_approval(resolved)

    lines = [
        f"🔐 Write needs approval — '{resolved}'",
        "",
        "This path is in the READ allowlist but not yet in the WRITABLE "
        "allowlist. AI-Prowler has queued an approval request — the next time "
        "you focus the AI-Prowler GUI window, it will ask you to approve "
        "writes to:",
        f"    {Path(resolved).parent}",
        "",
        "Once approved, this and all paths under that directory will be "
        "writable in future sessions. No need to re-run this tool — the "
        "approval persists in ~/.rag_writable_dirs.json.",
    ]
    if writable:
        lines.append("")
        lines.append("Currently writable:")
        for w in writable[:10]:
            lines.append(f"  - {w}")
    return (None, "\n".join(lines))


def _path_is_under(target: str, ancestor: str) -> bool:
    """True if target equals or is a descendant of ancestor (both resolved)."""
    try:
        t = Path(target).resolve(strict=False)
        a = Path(ancestor).resolve(strict=False)
        if t == a:
            return True
        try:
            t.relative_to(a)
            return True
        except ValueError:
            return False
    except Exception:
        return False


# ── Backup naming (.bak<N> alongside the file) ───────────────────────────────
_BAK_RE = _re.compile(r"\.bak(\d+)$", _re.IGNORECASE)


def _next_backup_path(filepath: str) -> Path:
    """
    Find the next available <filepath>.bak<N> in the file's parent directory.
    N = (max existing bak number for this base filename) + 1.
    Returns the Path object for where the new backup should be written.
    Does NOT create the file — caller must copy contents into it.
    """
    fp = Path(filepath)
    parent = fp.parent
    base = fp.name
    highest = 0
    try:
        prefix = base + ".bak"
        prefix_lower = prefix.lower()
        # List parent dir; cap scan to avoid pathological cases
        scanned = 0
        for sibling in parent.iterdir():
            scanned += 1
            if scanned > _BACKUP_MAX_FILES_PER_PARENT:
                break
            name = sibling.name
            if name.lower().startswith(prefix_lower):
                tail = name[len(prefix):]   # the digit portion after ".bak"
                if tail.isdigit():
                    n = int(tail)
                    if n > highest:
                        highest = n
    except Exception as exc:
        _log.warning("_next_backup_path: directory scan failed in %s: %s", parent, exc)
    return parent / f"{base}.bak{highest + 1}"


def _make_backup(filepath: str) -> tuple[Optional[str], Optional[str]]:
    """
    Copy filepath to <filepath>.bak<N> alongside it. Returns (backup_path, None)
    on success or (None, error_message) on failure.

    Caller has already verified the file exists.
    """
    try:
        target = _next_backup_path(filepath)
        _shutil.copy2(filepath, str(target))   # copy2 preserves mtime
        _log.info("Backup created: %s -> %s", filepath, target)
        return (str(target), None)
    except Exception as exc:
        msg = f"backup failed: {exc}"
        _log.error("_make_backup: %s", msg)
        return (None, msg)


# ── Line-ending preservation helper ──────────────────────────────────────────
# Background: Python's text-mode file I/O on Windows silently converts
# CRLF → LF on read and LF → platform-native on write. The write-side
# tools previously round-tripped through text mode and binary write,
# which silently stripped CRLF endings from Windows files on every edit.
# These helpers let us detect the existing convention and preserve it.

def _detect_line_ending(file_bytes: bytes) -> str:
    """Detect the dominant line ending in raw file bytes.

    Returns one of:
        '\\r\\n'  — Windows / CRLF  (any CRLF presence wins)
        '\\r'     — Classic Mac     (only \\r, no \\n)
        '\\n'     — Unix / LF       (the default; also empty files)

    Strategy: any CRLF in the file = treat the whole file as CRLF. This
    correctly handles slightly-mixed files (rare in practice, but they
    do occur from tools that append LF-only lines to a CRLF file).
    """
    if b"\r\n" in file_bytes:
        return "\r\n"
    if b"\r" in file_bytes and b"\n" not in file_bytes:
        return "\r"
    return "\n"


def _read_text_preserving_endings(filepath: str) -> tuple[str, str]:
    """Read filepath, return (lf_normalized_text, original_line_ending).

    The returned text always uses LF newlines so that in-memory string
    operations (str_replace, etc.) behave uniformly regardless of the
    file's on-disk convention. The caller is responsible for re-applying
    the returned line ending before writing back.

    Caller has already verified the file exists and is small enough.
    Decoding errors are replaced (matches the previous read behavior).
    """
    with open(filepath, "rb") as f:
        raw = f.read()
    line_ending = _detect_line_ending(raw)
    decoded = raw.decode("utf-8", errors="replace")
    # Normalize all endings to LF for consistent in-memory editing.
    # Order matters: handle \r\n before bare \r.
    normalized = decoded.replace("\r\n", "\n").replace("\r", "\n")
    return (normalized, line_ending)


def _apply_line_ending(text: str, line_ending: str) -> str:
    """Re-apply the given line ending to LF-normalized text.

    If line_ending is '\\n', returns text unchanged (zero allocations).
    Otherwise replaces every '\\n' with the target ending.
    """
    if line_ending == "\n":
        return text
    return text.replace("\n", line_ending)


# ── Write-counter circuit breaker ────────────────────────────────────────────
def _check_and_increment_write_counter() -> tuple[bool, str]:
    """
    Returns (allowed, message). Increments the counter on each call.
    The counter is process-scoped — restarting AI-Prowler resets it.
    """
    with _write_counter_lock:
        if _write_counter["count"] >= _WRITES_PER_SESSION_LIMIT:
            return (False,
                    f"🛑 Write circuit-breaker tripped: "
                    f"{_WRITES_PER_SESSION_LIMIT} writes already this session. "
                    f"This protects against runaway loops. Restart AI-Prowler "
                    f"or call reset_write_counter from the GUI to continue.")
        _write_counter["count"] += 1
        return (True, "")


def _reset_write_counter_internal() -> int:
    """Reset session write counter. Returns the count that was reset from."""
    with _write_counter_lock:
        old = _write_counter["count"]
        _write_counter["count"] = 0
        _write_counter["session_started"] = _time.time()
        return old


# ── Auto re-index helper ─────────────────────────────────────────────────────
def _reindex_file_after_write(filepath: str, *, was_new: bool = False) -> None:
    """
    DISABLED in v7.0.0 — intentional no-op.

    Auto-reindex-on-write was removed: re-embedding the whole file on the
    uvicorn request thread re-entered the already-open ChromaDB collection and
    caused "resource deadlock would occur", hanging the HTTP MCP server. Large
    files (e.g. rag_gui.py at ~700 KB) reproduced it every time.

    The database is now updated only by EXPLICIT reindex: call reindex_file()
    once you are done editing a file, or reindex_directory()/index_path() for a
    whole tree. Writes still create backups and land on disk immediately; they
    just no longer touch ChromaDB. Kept as a stub so existing call sites and any
    external references remain valid.
    """
    return


# ── Parent directory must exist (helper for create_file / write_file) ────────
def _parent_dir_check(filepath: str) -> Optional[str]:
    """Return an error message if the parent directory doesn't exist, else None."""
    try:
        parent = Path(filepath).parent
        if not parent.exists():
            return (f"⚠️  Parent directory does not exist: {parent}\n"
                    f"Call create_directory({parent}) first, then retry.")
        if not parent.is_dir():
            return f"⚠️  Parent path is not a directory: {parent}"
    except Exception as exc:
        return f"⚠️  Could not check parent directory: {exc}"
    return None


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — create_file
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def create_file(filepath: str, content: str) -> str:
    """
    CODE TOOLS — Create a NEW file. FAILS if the file already exists.

    Use this for files that should not yet exist. To modify an existing file,
    use write_file (whole-file overwrite) or str_replace_in_file (surgical edit).

    Security: the path must be in BOTH the read allowlist
    (~/.rag_auto_update_dirs.json) AND the writable allowlist
    (~/.rag_writable_dirs.json). The first time you attempt a write to a new
    directory, AI-Prowler queues a GUI approval request that you must accept
    at the desktop. Subsequent writes to that directory succeed silently.

    Hard-blocked locations (cannot be approved):
      C:\\Windows, C:\\Program Files, C:\\ProgramData, AppData (except
      AI-Prowler's own state), .git, .ssh, .aws, the job tracker xlsx.

    Args:
        filepath:  Absolute path of the file to create.
        content:   Full file contents as a string. Empty string is allowed.

    Returns:
        Success: confirmation with byte count and a note that the file is now
                 indexed in ChromaDB. Failure: a clear error explaining what
                 went wrong (path not allowlisted, file already exists,
                 parent missing, write circuit-breaker tripped, etc.).
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    # Authorize
    resolved, deny = _resolve_writable_path(filepath)
    if not resolved:
        return deny

    # Existence check — create_file fails if file exists (negative space: use write_file)
    if Path(resolved).exists():
        return (f"⚠️  File already exists: {resolved}\n"
                f"create_file is for NEW files only. To modify an existing "
                f"file, use write_file (full overwrite) or "
                f"str_replace_in_file (surgical edit).")

    # Parent directory must already exist (force explicit create_directory call)
    parent_err = _parent_dir_check(resolved)
    if parent_err:
        return parent_err

    # Size cap
    # Line-ending handling for NEW files: if the caller passed pure-LF content
    # and we're on Windows, translate to CRLF so the new file matches the
    # rest of the codebase. If the caller passed content with explicit \r
    # bytes, respect their choice exactly. Empty content is untouched.
    if "\r" in content:
        # Caller chose their endings explicitly — write as-is.
        final_content = content
    elif "\n" in content and os.linesep != "\n":
        # Pure-LF content on a non-LF platform: convert to native.
        # On Windows os.linesep == "\r\n"; on Linux/macOS it's "\n" already.
        final_content = content.replace("\n", os.linesep)
    else:
        final_content = content
    try:
        content_bytes = final_content.encode("utf-8")
    except Exception as exc:
        return f"⚠️  Content could not be encoded as UTF-8: {exc}"
    if len(content_bytes) > _WRITE_MAX_BYTES:
        return (f"⚠️  Content too large ({len(content_bytes):,} bytes, "
                f"cap {_WRITE_MAX_BYTES:,}).")

    # Circuit breaker
    ok, msg = _check_and_increment_write_counter()
    if not ok:
        return msg

    # Write
    try:
        with open(resolved, "wb") as f:
            f.write(content_bytes)
    except Exception as exc:
        return f"⚠️  Write failed: {exc}"

    _log.info("create_file: %s (%d bytes)", resolved, len(content_bytes))

    return (f"✅ Created {resolved}\n"
            f"   {len(content_bytes):,} bytes written\n"
            f"   NOT yet indexed — call reindex_file({resolved!r}) when done editing.")


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — write_file
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def write_file(filepath: str, content: str, verify_after_write: bool = False) -> str:
    """
    CODE TOOLS — Overwrite an EXISTING file with new content. FAILS if the
    file does not exist.

    Use this for whole-file rewrites. To create a new file, use create_file.
    For surgical single-string edits, use str_replace_in_file (much cheaper
    in tokens for large files).

    Auto-backup: before writing, the current file is copied to
    <filepath>.bak<N> alongside it, where N is the next available number.
    Backups are kept forever — manual cleanup only. The .bak<N> file is
    never indexed in ChromaDB.

    Auto re-index: after the write succeeds, all existing ChromaDB chunks
    for this filepath are purged and the new content is re-chunked and added.

    Args:
        filepath:           Absolute path to overwrite.
        content:            Full new file contents.
        verify_after_write: If True (default False for write_file), re-read the
                            file after writing and include the first/last 5
                            lines of the new content in the response so you
                            can confirm the write landed.

    Returns:
        Success: confirmation including backup path and byte counts.
        Failure: a clear error message.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    # Authorize
    resolved, deny = _resolve_writable_path(filepath)
    if not resolved:
        return deny

    # Existence check — write_file requires the file to exist
    if not Path(resolved).exists():
        return (f"⚠️  File does not exist: {resolved}\n"
                f"write_file is for EXISTING files only. To create a new "
                f"file, use create_file.")
    if not Path(resolved).is_file():
        return f"⚠️  Path is not a regular file: {resolved}"

    # Detect the existing file's line-ending convention so we can preserve
    # it when writing the new content. The user passes `content` with \n
    # newlines (the normal Python convention); we translate to whatever
    # the file currently uses. Without this, every Windows file we touch
    # silently loses its CRLF endings on write.
    # Read up to 64 KB — plenty to find the first CRLF in any real file.
    try:
        with open(resolved, "rb") as f:
            existing_head = f.read(65536)
        line_ending = _detect_line_ending(existing_head)
    except Exception as exc:
        return f"⚠️  Cannot probe existing file for line endings: {exc}"

    # Normalize incoming content to LF, then re-apply the detected ending.
    # Normalization makes the behavior predictable: whether the caller
    # passes \n or \r\n, the output uses the file's existing convention.
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    final_content = _apply_line_ending(normalized_content, line_ending)

    # Size cap on new content
    try:
        content_bytes = final_content.encode("utf-8")
    except Exception as exc:
        return f"⚠️  Content could not be encoded as UTF-8: {exc}"
    if len(content_bytes) > _WRITE_MAX_BYTES:
        return (f"⚠️  Content too large ({len(content_bytes):,} bytes, "
                f"cap {_WRITE_MAX_BYTES:,}).")

    # Circuit breaker
    ok, msg = _check_and_increment_write_counter()
    if not ok:
        return msg

    # Auto-backup before overwriting
    old_size = Path(resolved).stat().st_size
    backup_path, backup_err = _make_backup(resolved)
    if backup_err:
        return f"⚠️  Aborting write — could not create backup: {backup_err}"

    # Write
    try:
        with open(resolved, "wb") as f:
            f.write(content_bytes)
    except Exception as exc:
        return (f"⚠️  Write failed (backup preserved at {backup_path}): {exc}\n"
                f"Use restore_backup to recover if needed.")

    _log.info("write_file: %s (%d -> %d bytes, backup %s)",
              resolved, old_size, len(content_bytes), backup_path)

    # Build response (auto-reindex removed in v7.0.0 — see _reindex_file_after_write)
    out = [
        f"✅ Wrote {resolved}",
        f"   {old_size:,} bytes  →  {len(content_bytes):,} bytes",
        f"   Backup: {backup_path}",
        f"   NOT yet indexed — call reindex_file() when done editing.",
    ]
    if verify_after_write:
        out.append("")
        out.append("─── Verify (first 5 / last 5 lines of new content) ───")
        try:
            with open(resolved, "r", encoding="utf-8", errors="replace") as f:
                new_lines = f.read().splitlines()
            total = len(new_lines)
            head = new_lines[:5]
            tail = new_lines[-5:] if total > 10 else []
            for i, ln in enumerate(head, start=1):
                out.append(f"  {i:>4}  {ln}")
            if tail:
                out.append(f"  ... ({total - 10} line(s) omitted)")
                for i, ln in enumerate(tail, start=total - 4):
                    out.append(f"  {i:>4}  {ln}")
        except Exception as exc:
            out.append(f"  (verify read failed: {exc})")
    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — str_replace_in_file  (THE MOST IMPORTANT WRITE TOOL)
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def str_replace_in_file(filepath: str,
                        old_str: str,
                        new_str: str,
                        dry_run: bool = False,
                        verify_after_write: bool = True) -> str:
    """
    CODE TOOLS — Surgical in-place edit: replace one unique occurrence of
    old_str with new_str. This is THE primary write tool — prefer it over
    write_file for any change to a specific section of a file.

    Why this is so much better than read-modify-write for large files:
        A round-trip of rag_gui.py (12,209 lines, ~120K tokens) costs
        ~240K tokens vs ~250 tokens for a str_replace edit. 1000x savings.

    UNIQUENESS CONSTRAINT: old_str must appear in the file EXACTLY ONCE.
    If it appears zero times, the tool fails (typo or already-edited).
    If it appears more than once, the tool fails and reports each match's
    line number so you can pick a more distinctive old_str.

    Auto-backup: before any write, the file is copied to <filepath>.bak<N>.
    Auto re-index: ChromaDB chunks for this file are purged and rebuilt.

    Args:
        filepath:           Absolute path to edit. Must be writable-allowlisted.
        old_str:            Exact substring to find. Must appear exactly once.
                            Whitespace is significant.
        new_str:            Replacement text. May be empty to delete a span.
                            May include multiple lines.
        dry_run:            If True, returns a unified diff WITHOUT modifying
                            the file. No backup is created. Useful for mobile
                            confirmation — review the diff, then call again
                            with dry_run=False.
        verify_after_write: If True (default True for str_replace_in_file),
                            include 5 lines before and after the changed
                            region in the response. Catches silent failures
                            (file locked by AV, OneDrive sync conflict).

    Returns:
        Success: confirmation with line where the change landed, backup path,
                 and (if verify_after_write) the surrounding context.
        Failure: detailed error explaining why (not found, ambiguous, etc.).
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    # Sanity checks on the strings
    if old_str is None:
        return "⚠️  old_str cannot be None."
    if new_str is None:
        return "⚠️  new_str cannot be None (use empty string to delete a span)."
    if len(old_str) == 0:
        return "⚠️  old_str cannot be empty (would match infinitely)."
    if len(old_str) > _STR_REPLACE_MAX_OLD_STR_LEN:
        return (f"⚠️  old_str too long ({len(old_str):,} chars, cap "
                f"{_STR_REPLACE_MAX_OLD_STR_LEN:,}). Use a smaller distinctive "
                f"snippet or write_file for whole-file rewrites.")

    # ── CRLF FIX (v7.0.0) ──────────────────────────────────────────────────────
    # The file is read and LF-normalized by _read_text_preserving_endings(), but
    # old_str / new_str arrive straight from the MCP client. When a multi-line
    # snippet is copied from a CRLF (Windows) source — which is every file in this
    # codebase — old_str carries '\r\n' while the in-memory file text carries only
    # '\n'. text.count(old_str) then compares a CRLF needle against LF-normalized
    # text and returns 0, so the edit fails with "old_str not found". Single-line
    # old_str has no newline and so was never affected — which is exactly why this
    # bug only manifested on multi-line matches. Normalize both args to LF here so
    # all matching logic below is line-ending-agnostic; the file's original ending
    # is re-applied at write time by _apply_line_ending().
    old_str = old_str.replace("\r\n", "\n").replace("\r", "\n")
    new_str = new_str.replace("\r\n", "\n").replace("\r", "\n")

    # Authorize (suppress queueing if it's a dry-run — no actual write attempted)
    resolved, deny = _resolve_writable_path(filepath, queue_approval=not dry_run)
    if not resolved:
        return deny

    if not Path(resolved).exists():
        return f"⚠️  File does not exist: {resolved}"
    if not Path(resolved).is_file():
        return f"⚠️  Path is not a regular file: {resolved}"

    # Size cap on the file
    try:
        size = Path(resolved).stat().st_size
    except Exception as exc:
        return f"⚠️  Cannot stat file: {exc}"
    if size > _READ_FILE_MAX_BYTES:
        return (f"⚠️  File too large for in-memory edit "
                f"({size:,} bytes, cap {_READ_FILE_MAX_BYTES:,}).")

    # Binary sniff
    try:
        with open(resolved, "rb") as bf:
            head = bf.read(_BINARY_SNIFF_BYTES)
        if _looks_binary(head):
            return (f"⚠️  File appears to be binary: {resolved}\n"
                    f"str_replace_in_file only edits text files.")
    except Exception as exc:
        return f"⚠️  Cannot open file: {exc}"

    # Read whole file — in BINARY first so we can detect the line-ending
    # convention, then decode to an LF-normalized in-memory string. This
    # preserves CRLF files on the round-trip; without it Python's text-mode
    # write silently strips \r bytes from every Windows file we edit.
    try:
        text, line_ending = _read_text_preserving_endings(resolved)
    except Exception as exc:
        return f"⚠️  Read failed: {exc}"

    # Count occurrences
    count = text.count(old_str)
    if count == 0:
        return (f"⚠️  old_str not found in {resolved}.\n"
                f"Possible causes: typo in old_str, file already edited, "
                f"whitespace difference (tabs vs spaces, trailing newline). "
                f"Tip: use grep_documents to verify the exact text first.")
    if count > 1:
        # Find each occurrence and report its line number for disambiguation
        lines_of_match = []
        start_at = 0
        while True:
            idx = text.find(old_str, start_at)
            if idx == -1:
                break
            line_no = text.count("\n", 0, idx) + 1
            lines_of_match.append(line_no)
            start_at = idx + 1
            if len(lines_of_match) > 20:
                break
        return (f"⚠️  old_str found {count} times in {resolved}.\n"
                f"Match line numbers: {lines_of_match[:20]}"
                + ("  (more not listed)" if count > 20 else "") + "\n"
                f"old_str must match EXACTLY ONCE. Add surrounding context "
                f"(a few lines before/after) until it's unique, then retry.")

    # Compute the change
    new_text = text.replace(old_str, new_str, 1)

    # Find where the change happened (for verify and reporting)
    change_idx = text.find(old_str)
    line_of_change = text.count("\n", 0, change_idx) + 1
    # Report the size as it will be on disk — i.e. AFTER re-applying the
    # original line ending. Otherwise size previews are wrong for CRLF files.
    new_bytes_on_disk = _apply_line_ending(new_text, line_ending).encode("utf-8")
    new_byte_count = len(new_bytes_on_disk)

    # ── DRY RUN ──
    if dry_run:
        out = [
            f"🔎 DRY RUN — no changes written to {resolved}",
            f"   Match found at line {line_of_change}",
            f"   File size would change: {size:,} → {new_byte_count:,} bytes",
            "",
            "─── Unified diff (a=before, b=after) ───",
        ]
        try:
            import difflib as _difflib
            diff = list(_difflib.unified_diff(
                text.splitlines(keepends=False),
                new_text.splitlines(keepends=False),
                fromfile=f"a/{Path(resolved).name}",
                tofile=f"b/{Path(resolved).name}",
                lineterm="",
                n=3,
            ))
            if diff:
                out.extend(diff[:200])
                if len(diff) > 200:
                    out.append(f"... ({len(diff) - 200} more diff lines suppressed)")
            else:
                out.append("(no textual diff — old_str and new_str are identical)")
        except Exception as exc:
            out.append(f"(diff generation failed: {exc})")
        out.append("")
        out.append("To apply: call again with dry_run=False.")
        return "\n".join(out)

    # ── REAL WRITE ──
    # Circuit breaker
    ok, msg = _check_and_increment_write_counter()
    if not ok:
        return msg

    # Size cap on new content
    if new_byte_count > _WRITE_MAX_BYTES:
        return (f"⚠️  Resulting content too large ({new_byte_count:,} bytes, "
                f"cap {_WRITE_MAX_BYTES:,}).")

    # Auto-backup
    backup_path, backup_err = _make_backup(resolved)
    if backup_err:
        return f"⚠️  Aborting edit — could not create backup: {backup_err}"

    # Write — re-apply the original line ending convention. new_bytes_on_disk
    # was already computed above for the size report; reuse it here.
    try:
        with open(resolved, "wb") as f:
            f.write(new_bytes_on_disk)
    except Exception as exc:
        return (f"⚠️  Write failed (backup preserved at {backup_path}): {exc}\n"
                f"Use restore_backup to recover.")

    _log.info("str_replace_in_file: %s line=%d (%d -> %d bytes, backup %s)",
              resolved, line_of_change, size, new_byte_count, backup_path)

    # (auto-reindex removed in v7.0.0 — call reindex_file() when done editing)
    out = [
        f"✅ Edited {resolved}",
        f"   Change at line {line_of_change}",
        f"   {size:,} bytes  →  {new_byte_count:,} bytes",
        f"   Backup: {backup_path}",
        f"   NOT yet indexed — call reindex_file() when done editing.",
    ]
    if verify_after_write:
        out.append("")
        out.append("─── Verify (5 lines before, change region, 5 lines after) ───")
        try:
            new_lines_list = new_text.splitlines()
            new_total = len(new_lines_list)
            new_str_line_count = new_str.count("\n") + 1
            change_start = max(1, line_of_change - 5)
            change_end = min(new_total, line_of_change + new_str_line_count + 4)
            for i in range(change_start, change_end + 1):
                marker = "▶" if change_start + 5 <= i < change_start + 5 + new_str_line_count else " "
                if i <= new_total:
                    out.append(f"  {marker}{i:>5}  {new_lines_list[i - 1]}")
        except Exception as exc:
            out.append(f"  (verify read failed: {exc})")
    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — create_directory
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def create_directory(dirpath: str, parents: bool = True) -> str:
    """
    CODE TOOLS — Create a directory inside an indexed AND writable area.
    Idempotent: succeeds if the directory already exists.

    Args:
        dirpath:  Absolute path to create.
        parents:  If True (default), create missing parent directories
                  (mkdir -p semantics). If False, parent must already exist.

    Returns:
        Confirmation with whether the directory was newly created or already
        existed, or an error explaining why creation failed.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    resolved, deny = _resolve_writable_path(dirpath)
    if not resolved:
        return deny

    dp = Path(resolved)
    if dp.exists():
        if dp.is_dir():
            return f"✅ Directory already exists: {resolved}\n   (idempotent — no action taken)"
        return f"⚠️  Path exists but is not a directory: {resolved}"

    # Circuit breaker (directory creation counts toward the limit)
    ok, msg = _check_and_increment_write_counter()
    if not ok:
        return msg

    try:
        dp.mkdir(parents=parents, exist_ok=False)
    except FileNotFoundError as exc:
        return (f"⚠️  Parent directory does not exist: {exc}\n"
                f"Retry with parents=True, or call create_directory on the "
                f"parent first.")
    except Exception as exc:
        return f"⚠️  Could not create directory: {exc}"

    _log.info("create_directory: %s (parents=%s)", resolved, parents)
    return f"✅ Created directory: {resolved}"


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — list_directory
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def list_directory(dirpath: str, show_hidden: bool = False) -> str:
    """
    CODE TOOLS — List the contents of a directory (files and subdirectories).
    Read-only — no writable-allowlist requirement; only the read allowlist
    applies.

    Args:
        dirpath:      Absolute path to list.
        show_hidden:  If True, include entries beginning with '.'
                      (default False).

    Returns:
        A formatted listing with file/dir indicators, sizes for files, and
        a summary line. Output is sorted: directories first, then files,
        each group alphabetically.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    # read-only — only the read allowlist applies
    resolved, deny = _resolve_allowlisted_path(dirpath)
    if not resolved:
        return deny

    dp = Path(resolved)
    if not dp.exists():
        return f"⚠️  Path does not exist: {resolved}"
    if not dp.is_dir():
        return f"⚠️  Path is not a directory: {resolved}"

    try:
        entries = list(dp.iterdir())
    except Exception as exc:
        return f"⚠️  Cannot list directory: {exc}"

    dirs = []
    files = []
    backups = []
    for e in entries:
        name = e.name
        if not show_hidden and name.startswith("."):
            continue
        try:
            if e.is_dir():
                dirs.append(name)
            elif _BAK_RE.search(name):
                # .bak<N> files grouped separately so the listing emphasizes
                # active code over historical backups
                try:
                    size = e.stat().st_size
                except Exception:
                    size = 0
                backups.append((name, size))
            else:
                try:
                    size = e.stat().st_size
                except Exception:
                    size = 0
                files.append((name, size))
        except Exception:
            continue

    dirs.sort(key=str.lower)
    files.sort(key=lambda x: x[0].lower())
    backups.sort(key=lambda x: x[0].lower())

    out = [
        f"📁 {resolved}",
        f"   {len(dirs)} dir(s), {len(files)} file(s)"
        + (f", {len(backups)} backup(s)" if backups else ""),
        "─" * 55,
    ]
    for name in dirs:
        out.append(f"   📁  {name}/")
    for name, size in files:
        out.append(f"   📄  {name}   ({size:,} bytes)")
    if backups:
        out.append("")
        out.append("   Backups (not indexed in ChromaDB):")
        for name, size in backups:
            out.append(f"   💾  {name}   ({size:,} bytes)")
    if not dirs and not files and not backups:
        out.append("   (empty)")
    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 6 — copy_to_backup
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def copy_to_backup(filepath: str) -> str:
    """
    CODE TOOLS — Take a manual snapshot of a file. Creates <filepath>.bak<N>
    alongside the file WITHOUT modifying the active file.

    This is the 'soft delete' primitive in AI-Prowler — there is no delete
    tool. To remove content from active use, copy_to_backup first, then
    write_file an empty string (or simply stop touching the file).

    Differs from the auto-backup inside write_file / str_replace_in_file:
    that one fires automatically before a modification. This one is for
    when you want a checkpoint of the current state without changing it.

    The .bak<N> file is NOT indexed in ChromaDB. The active file's existing
    chunks are untouched (no re-index needed).

    Args:
        filepath:  Absolute path of the file to snapshot.

    Returns:
        Confirmation including the backup path, or an error.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    resolved, deny = _resolve_writable_path(filepath)
    if not resolved:
        return deny

    if not Path(resolved).exists():
        return f"⚠️  File does not exist: {resolved}"
    if not Path(resolved).is_file():
        return f"⚠️  Path is not a regular file: {resolved}"

    # Counts toward the circuit breaker (it does create a file)
    ok, msg = _check_and_increment_write_counter()
    if not ok:
        return msg

    backup_path, backup_err = _make_backup(resolved)
    if backup_err:
        return f"⚠️  Snapshot failed: {backup_err}"

    try:
        size = Path(backup_path).stat().st_size
    except Exception:
        size = 0

    return (f"💾 Snapshot created\n"
            f"   Source: {resolved}\n"
            f"   Backup: {backup_path}\n"
            f"   {size:,} bytes\n"
            f"   Active file unchanged. Backup NOT indexed in ChromaDB.")


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 7 — list_backups
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def list_backups(filepath: str) -> str:
    """
    CODE TOOLS — Show all <filepath>.bak<N> files next to the given file,
    with their sizes and modification times.

    Args:
        filepath:  Absolute path of the active file whose backups to enumerate.

    Returns:
        Sorted list (newest = highest N first) of backups, or a message if
        none exist.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    # Read-only — only the read allowlist applies. Backups don't need write
    # approval to be listed.
    resolved, deny = _resolve_allowlisted_path(filepath)
    if not resolved:
        return deny

    fp = Path(resolved)
    parent = fp.parent
    base = fp.name
    prefix = base + ".bak"
    prefix_lower = prefix.lower()

    found = []
    try:
        for sibling in parent.iterdir():
            name = sibling.name
            if name.lower().startswith(prefix_lower):
                tail = name[len(prefix):]
                if tail.isdigit():
                    try:
                        stat = sibling.stat()
                        found.append((int(tail), str(sibling), stat.st_size, stat.st_mtime))
                    except Exception:
                        continue
    except Exception as exc:
        return f"⚠️  Could not scan {parent}: {exc}"

    if not found:
        return (f"📂 No backups for {resolved}\n"
                f"   No <{base}>.bak<N> files found in {parent}")

    # Sort newest first (highest N first)
    found.sort(key=lambda x: x[0], reverse=True)

    out = [
        f"📂 Backups for {resolved}",
        f"   {len(found)} backup(s) found in {parent}",
        f"   (newest = highest .bak number)",
        "─" * 55,
    ]
    for n, path, size, mtime in found:
        when = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(mtime))
        out.append(f"   .bak{n:<4}  {size:>12,} bytes  {when}")
        out.append(f"             {path}")
    out.append("")
    out.append(f"Restore: restore_backup({resolved!r}, backup_number=<N>)")
    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 8 — restore_backup
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def restore_backup(filepath: str, backup_number: int) -> str:
    """
    CODE TOOLS — Restore <filepath>.bak<N> over the active file at filepath.

    Does NOT auto-backup the current state before restoring — this is
    deliberate to keep the tool simple. If you want to preserve the broken
    state for later study, call copy_to_backup(filepath) FIRST, then call
    restore_backup.

    Triggers a full ChromaDB re-index of the active file (functionally a
    write — the file's contents change on disk).

    Args:
        filepath:       Absolute path of the active file to restore over.
        backup_number:  The N in <filepath>.bak<N>. Use list_backups to see
                        what's available.

    Returns:
        Confirmation with byte counts before and after, or an error.
    """
    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait a moment and try again."

    resolved, deny = _resolve_writable_path(filepath)
    if not resolved:
        return deny

    try:
        n = int(backup_number)
        if n < 1:
            return f"⚠️  backup_number must be >= 1, got {backup_number}"
    except (TypeError, ValueError):
        return f"⚠️  backup_number must be an integer, got {backup_number!r}"

    fp = Path(resolved)
    backup_path = fp.parent / f"{fp.name}.bak{n}"

    if not backup_path.exists():
        return (f"⚠️  Backup not found: {backup_path}\n"
                f"Call list_backups({resolved!r}) to see what's available.")

    # Active file may or may not exist (e.g. after a failed write that left
    # only the backup). Allow restore-over-missing for recovery.
    old_size = fp.stat().st_size if fp.exists() else 0
    try:
        backup_size = backup_path.stat().st_size
    except Exception as exc:
        return f"⚠️  Could not read backup: {exc}"

    # Circuit breaker
    ok, msg = _check_and_increment_write_counter()
    if not ok:
        return msg

    # Restore: copy backup over active path
    try:
        _shutil.copy2(str(backup_path), str(fp))
    except Exception as exc:
        return f"⚠️  Restore failed: {exc}"

    _log.info("restore_backup: %s <- %s (%d -> %d bytes)",
              resolved, backup_path, old_size, backup_size)

    # (auto-reindex removed in v7.0.0 — call reindex_file() if you want the
    #  restored content re-indexed)
    return (f"✅ Restored {resolved}\n"
            f"   Source: {backup_path}\n"
            f"   {old_size:,} bytes  →  {backup_size:,} bytes\n"
            f"   NOT yet indexed — call reindex_file() if you want it indexed.\n"
            f"   .bak{n} preserved (restore is non-destructive to backups).")


# ══════════════════════════════════════════════════════════════════════════════
# BONUS — reset_write_counter (admin tool, not part of the 8)
# ══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def reset_write_counter() -> str:
    """
    CODE TOOLS — Reset the per-session write circuit-breaker counter.

    The circuit breaker limits AI-Prowler to 20 write operations per process
    lifetime to protect against runaway loops. This tool resets the count so
    legitimate large editing sessions can continue without restarting the
    server.

    Returns:
        Confirmation with the count that was reset.
    """
    old = _reset_write_counter_internal()
    _log.info("Write counter reset (was %d)", old)
    return (f"✅ Write counter reset\n"
            f"   Was: {old} / {_WRITES_PER_SESSION_LIMIT}\n"
            f"   Now: 0 / {_WRITES_PER_SESSION_LIMIT}")


# ══════════════════════════════════════════════════════════════════════════════
# DEV CHECK TOOLS — compile_check / check_python_import  (v7.0.0)
# ══════════════════════════════════════════════════════════════════════════════
# Let the agent verify its own edits on THIS machine (real interpreter, real
# installed stack) instead of asking the user to run py_compile / import by hand.
#
# SAFETY MODEL — these are developer conveniences, NOT customer-facing tools:
#   • Edition-gated: only available when this install is the Home edition OR
#     config.json explicitly sets {"dev_tools": true}. On any deployed Business
#     server (edition != home, no dev_tools flag) they are HARD-DISABLED and
#     return a refusal — so a tunnel-exposed customer box is never an RCE host.
#   • NO free-form shell: each tool builds a FIXED argument list
#     ([sys.executable, "-m", "py_compile", path] etc.) and runs it with
#     subprocess.run(shell=False). The agent cannot inject a command string.
#   • Path-scoped: compile_check validates filepath against the SAME tracked-root
#     allowlist the edit tools use (_resolve_allowlisted_path). No arbitrary file.
#   • Bounded: a hard timeout prevents a hung interpreter from wedging the server.
# ══════════════════════════════════════════════════════════════════════════════
_DEV_CHECK_TIMEOUT_SEC = 120   # generous enough for an import that loads heavy deps


def _dev_tools_enabled() -> tuple[bool, str]:
    """Return (enabled, reason). Dev tools are enabled in ALL editions/modes.

    History: v6.x and earlier had this gated to Home-edition-only because the
    tools (compile_check, check_python_import, ...) were considered too exposed for
    mobile/business installs accessed via Cloudflare Tunnel. v7.0.0 (2026-05-30)
    removed the gate per operator decision: the dev tools are read-only
    subprocess calls bounded by the same read allowlist as every other tool,
    so the same path-based protection that gates search_documents also gates
    syntax_check / pytest_check / lint_check.

    Kept as a function (not inlined) so re-tightening later is a one-line
    change: simply return (False, "...") here for the modes you want to lock.
    The opt-in dev_tools flag is preserved as a historical escape hatch but
    is now redundant — every code path it would unlock is already enabled.
    """
    try:
        cfg = _load_runtime_config()   # module-level; safe, never raises
    except Exception:
        cfg = {}
    edition = cfg.get("edition", "home")
    mode    = cfg.get("mode",    "personal")
    if cfg.get("dev_tools") is True:
        return (True, "dev_tools flag set in config.json")
    return (True, f"edition={edition!r} mode={mode!r} (dev tools enabled in all configurations)")


@mcp.tool()
def compile_check(filepath: str, timeout_sec: int = _DEV_CHECK_TIMEOUT_SEC) -> str:
    """
    DEV TOOLS — Byte-compile a Python file with this machine's interpreter to
    check for SYNTAX errors. Equivalent to `python -m py_compile <file>`.

    Use this after editing a .py file to confirm it parses before relying on it.
    Catches syntax errors only (not import-time or runtime errors — use
    check_python_import for those). Available in all editions/modes; the file must be
    under a tracked read-allowlisted root regardless of edition.

    Args:
        filepath:    Path to a .py file under a tracked root.
        timeout_sec: Max seconds to wait (default 120).

    Returns:
        "✅ compile OK" or the compiler's error output.
    """
    enabled, why = _dev_tools_enabled()
    if not enabled:
        return f"🚫 compile_check is disabled here ({why})."

    resolved, err = _resolve_allowlisted_path(filepath)
    if err:
        return err
    if not resolved.lower().endswith(".py"):
        return f"⚠️  compile_check only handles .py files (got {resolved})."

    import subprocess as _sp
    try:
        proc = _sp.run(
            [sys.executable, "-m", "py_compile", resolved],
            capture_output=True, text=True, timeout=max(5, int(timeout_sec)),
            shell=False)
    except _sp.TimeoutExpired:
        return f"⏱️  compile_check timed out after {timeout_sec}s on {resolved}."
    except Exception as exc:
        return f"⚠️  compile_check could not run: {exc}"

    if proc.returncode == 0:
        _log.info("compile_check OK: %s", resolved)
        return f"✅ compile OK — {resolved}\n   (python -m py_compile, rc=0)"
    out = (proc.stderr or proc.stdout or "").strip()
    _log.warning("compile_check FAILED: %s\n%s", resolved, out)
    return (f"❌ compile FAILED — {resolved}  (rc={proc.returncode})\n"
            f"───\n{out}")


@mcp.tool()
def check_python_import(module_or_path: str, timeout_sec: int = _DEV_CHECK_TIMEOUT_SEC) -> str:
    """
    DEV TOOLS — Import a Python module with this machine's interpreter to catch
    LOAD-TIME errors (NameError, ImportError, bad module-level references) that
    syntax-only compile_check misses. Equivalent to `python -c "import <module>"`.

    Accepts either a bare module name (e.g. "ai_prowler_mcp") or a path to a .py
    file under a tracked root (the module name is derived from the filename).
    The import runs in a SEPARATE interpreter process, so it cannot disturb the
    running server. Available in all editions/modes; the file must be under
    a tracked read-allowlisted root regardless of edition.

    Args:
        module_or_path: Module name, or path to a .py file under a tracked root.
        timeout_sec:    Max seconds to wait (default 120; imports of heavy deps
                        like torch/chromadb can take a while).

    Returns:
        "✅ import OK" or the traceback the import produced.
    """
    enabled, why = _dev_tools_enabled()
    if not enabled:
        return f"🚫 check_python_import is disabled here ({why})."

    # Resolve to a module name + a working directory to run from.
    cwd = None
    if module_or_path.replace("_", "").isalnum() and "/" not in module_or_path \
            and "\\" not in module_or_path and not module_or_path.endswith(".py"):
        module = module_or_path           # bare module name
    else:
        resolved, err = _resolve_allowlisted_path(module_or_path)
        if err:
            return err
        if not resolved.lower().endswith(".py"):
            return f"⚠️  check_python_import path must be a .py file (got {resolved})."
        import os as _os
        cwd = _os.path.dirname(resolved)
        module = _os.path.splitext(_os.path.basename(resolved))[0]

    # Validate the derived module name is a safe identifier — no injection via -c.
    if not module.isidentifier():
        return f"⚠️  '{module}' is not a valid module name."

    import subprocess as _sp
    try:
        proc = _sp.run(
            [sys.executable, "-c", f"import {module}"],
            capture_output=True, text=True, timeout=max(5, int(timeout_sec)),
            shell=False, cwd=cwd)
    except _sp.TimeoutExpired:
        return f"⏱️  check_python_import timed out after {timeout_sec}s importing {module}."
    except Exception as exc:
        return f"⚠️  check_python_import could not run: {exc}"

    if proc.returncode == 0:
        _log.info("check_python_import OK: %s", module)
        note = (proc.stderr or "").strip()
        extra = f"\n   (stderr, non-fatal):\n{note}" if note else ""
        return f"✅ import OK — {module}\n   (python -c 'import {module}', rc=0){extra}"
    out = (proc.stderr or proc.stdout or "").strip()
    _log.warning("check_python_import FAILED: %s\n%s", module, out)
    return (f"❌ import FAILED — {module}  (rc={proc.returncode})\n"
            f"───\n{out}")


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-LANGUAGE DEV TOOLS — syntax_check + lint_check (v7.0.0)
# ══════════════════════════════════════════════════════════════════════════════
# Why one tool per concern (syntax / lint / pytest) instead of one tool per
# language: keeps the MCP tool surface narrow (3 tools) instead of N×M (one
# per language per concern = ~24 tools). Each tool auto-detects language by
# file extension and dispatches to the right underlying binary. If the binary
# isn't installed, return a clean "❌ Not available — install <tool>" message
# rather than a cryptic subprocess error.
#
# Coverage choices, with honest tradeoffs:
#   • Python  : py_compile (syntax) + pyflakes (lint). Both bundled with Python.
#   • JS      : node --check (syntax). Lint via eslint if installed.
#   • TS      : tsc --noEmit (syntax+type). Same tool for lint.
#   • C/C++   : gcc -fsyntax-only on POSIX, cl /Zs on Windows. Lint via cppcheck.
#                Headers without their full dependency graph WILL produce false
#                errors — this is single-file checking, not full build.
#   • Go      : go build -o NUL/devnull (syntax). go vet (lint).
#   • Rust    : NOT supported single-file — cargo expects a Cargo.toml project.
#                Return a clear message pointing the operator at `cargo check`.
#   • Java    : javac -d <tmpdir> (syntax). No standard lint tool.
#   • Perl    : perl -c. No lint.
#   • Ruby    : ruby -c. No lint (rubocop is third-party).
#   • PHP     : php -l. No standard lint.
#   • Bash    : bash -n (on Windows requires Git Bash or WSL). shellcheck if installed.
# ══════════════════════════════════════════════════════════════════════════════

# Extension → language config. Each entry is (lang_name, needs_binary, syntax_argv, lint_argv).
# {file} placeholder in argv is replaced with the resolved filepath at runtime.
# argv = None means "not supported for this concern" (e.g. no standard lint for Perl).
_LANG_CONFIG = {
    # Python
    ".py":   ("Python",  sys.executable, [sys.executable, "-m", "py_compile", "{file}"],
                                          [sys.executable, "-m", "pyflakes", "{file}"]),
    # JavaScript
    ".js":   ("JavaScript", "node", ["node", "--check", "{file}"], None),
    ".mjs":  ("JavaScript", "node", ["node", "--check", "{file}"], None),
    ".cjs":  ("JavaScript", "node", ["node", "--check", "{file}"], None),
    # TypeScript
    ".ts":   ("TypeScript", "tsc",  ["tsc", "--noEmit", "{file}"], ["tsc", "--noEmit", "{file}"]),
    ".tsx":  ("TypeScript", "tsc",  ["tsc", "--noEmit", "{file}"], ["tsc", "--noEmit", "{file}"]),
    # C / C++
    ".c":    ("C",   "gcc", ["gcc", "-fsyntax-only", "{file}"], None),
    ".h":    ("C",   "gcc", ["gcc", "-fsyntax-only", "-x", "c-header", "{file}"], None),
    ".cpp":  ("C++", "g++", ["g++", "-fsyntax-only", "{file}"], None),
    ".cc":   ("C++", "g++", ["g++", "-fsyntax-only", "{file}"], None),
    ".cxx":  ("C++", "g++", ["g++", "-fsyntax-only", "{file}"], None),
    ".hpp":  ("C++", "g++", ["g++", "-fsyntax-only", "-x", "c++-header", "{file}"], None),
    # Go
    ".go":   ("Go", "go", ["go", "vet", "{file}"], ["go", "vet", "{file}"]),
    # Java
    ".java": ("Java", "javac", ["javac", "-d", "{tmpdir}", "{file}"], None),
    # Perl
    ".pl":   ("Perl", "perl", ["perl", "-c", "{file}"], None),
    ".pm":   ("Perl", "perl", ["perl", "-c", "{file}"], None),
    # Ruby
    ".rb":   ("Ruby", "ruby", ["ruby", "-c", "{file}"], None),
    # PHP
    ".php":  ("PHP", "php", ["php", "-l", "{file}"], None),
    # Bash
    ".sh":   ("Bash",   "bash", ["bash", "-n", "{file}"], None),
    ".bash": ("Bash",   "bash", ["bash", "-n", "{file}"], None),
    # ── Hardware Description Languages (HDL) ─────────────────────────────────
    # Verilog / SystemVerilog — Icarus Verilog (iverilog)
    #   iverilog -t null -o /dev/null {file}  → syntax-only, no binary output
    #   On Windows iverilog writes to NUL instead of /dev/null.
    #   Lint: verilator --lint-only (deeper static analysis, optional install)
    ".v":    ("Verilog",         "iverilog",
              ["iverilog", "-t", "null", "-o", "{verilog_null}", "{file}"], None),
    ".vh":   ("Verilog Header",  "iverilog",
              ["iverilog", "-t", "null", "-o", "{verilog_null}", "{file}"], None),
    ".sv":   ("SystemVerilog",   "iverilog",
              ["iverilog", "-g2012", "-t", "null", "-o", "{verilog_null}", "{file}"], None),
    ".svh":  ("SystemVerilog Header", "iverilog",
              ["iverilog", "-g2012", "-t", "null", "-o", "{verilog_null}", "{file}"], None),
    # VHDL — GHDL
    #   ghdl -s {file}  → syntax-only analysis, no elaborate/run step
    #   Lint: ghdl -a {file}  → full semantic analysis (catches more than -s)
    ".vhd":  ("VHDL", "ghdl",
              ["ghdl", "-s", "{file}"],
              ["ghdl", "-a", "{file}"]),
    ".vhdl": ("VHDL", "ghdl",
              ["ghdl", "-s", "{file}"],
              ["ghdl", "-a", "{file}"]),
}

# Languages we intentionally do NOT auto-dispatch on (require project setup).
_LANG_NOT_SUPPORTED = {
    ".rs": ("Rust", "cargo check (requires Cargo.toml — single-file Rust check isn't viable; "
                    "run `cargo check` in your crate root instead)"),
}


def _detect_language(filepath: str) -> Optional[tuple]:
    """Return (lang_name, needs_binary, syntax_argv, lint_argv) for filepath,
    or None if the extension isn't recognised."""
    ext = os.path.splitext(filepath)[1].lower()
    return _LANG_CONFIG.get(ext)


def _binary_available(binary: str) -> bool:
    """Quick PATH check — returns True if shutil.which(binary) finds it."""
    import shutil as _shutil
    # Special case: sys.executable is a full path, not a PATH name.
    if binary == sys.executable:
        return True
    return _shutil.which(binary) is not None


def _run_dev_subprocess(argv: list, timeout_sec: int,
                        tmpdir_for_java: Optional[str] = None) -> tuple[int, str]:
    """Run a dev-tool subprocess with timeout. Returns (returncode, output).
    Substitutes {file}/{tmpdir} placeholders in argv. Output is the combined
    stderr+stdout (stripped). Returns (-1, error_message) if the subprocess
    could not be launched at all (e.g. binary disappeared between PATH check
    and run)."""
    import subprocess as _sp
    try:
        proc = _sp.run(argv, capture_output=True, text=True,
                       timeout=max(5, int(timeout_sec)), shell=False)
        out = (proc.stderr or "") + (proc.stdout or "")
        return proc.returncode, out.strip()
    except _sp.TimeoutExpired:
        return -2, f"⏱️ subprocess timed out after {timeout_sec}s"
    except FileNotFoundError as exc:
        return -1, f"binary not found: {exc}"
    except Exception as exc:
        return -1, f"subprocess could not run: {exc}"


@mcp.tool()
def syntax_check(filepath: str, timeout_sec: int = _DEV_CHECK_TIMEOUT_SEC) -> str:
    """
    DEV TOOLS — Multi-language syntax checker. Auto-detects language by file
    extension and runs the appropriate compiler/parser in --check / -fsyntax-only
    mode (does not produce binaries).

    Supports: Python (.py), JavaScript (.js/.mjs/.cjs), TypeScript (.ts/.tsx),
    C (.c/.h), C++ (.cpp/.cc/.cxx/.hpp), Go (.go), Java (.java), Perl (.pl/.pm),
    Ruby (.rb), PHP (.php), Bash (.sh/.bash),
    Verilog (.v/.vh), SystemVerilog (.sv/.svh) — requires iverilog,
    VHDL (.vhd/.vhdl) — requires ghdl.

    Rust requires a Cargo project and is intentionally NOT supported here —
    use `cargo check` in your project root.

    If the underlying tool isn't installed on this machine (e.g. no `go` binary
    on PATH), returns a clean "❌ Not available — install <tool>" message rather
    than a cryptic subprocess error.

    Honest limitations:
      • C/C++ single-file checks may report false errors when headers reference
        symbols defined in other compilation units (single-file ≠ full build).
      • Bash on Windows requires Git Bash or WSL to provide a `bash` binary.
      • TypeScript needs a tsconfig.json in the project root for most non-
        trivial files; lone .ts files may report import resolution errors.
      • Verilog/SystemVerilog: install Icarus Verilog (iverilog) from
        http://iverilog.icarus.com or via winget: winget install IcarusVerilog
      • VHDL: install GHDL from https://github.com/ghdl/ghdl/releases or
        via winget: winget install ghdl.ghdl

    Available in all editions/modes; the file must be under a tracked
    read-allowlisted root regardless of edition.

    Args:
        filepath:    Path to the source file under a tracked root.
        timeout_sec: Max seconds to wait (default 120).

    Returns:
        "✅ syntax OK — <lang>" or the compiler's error output.
    """
    enabled, why = _dev_tools_enabled()
    if not enabled:
        return f"🚫 syntax_check is disabled here ({why})."

    resolved, err = _resolve_allowlisted_path(filepath)
    if err:
        return err

    # Detect language
    ext = os.path.splitext(resolved)[1].lower()
    if ext in _LANG_NOT_SUPPORTED:
        lang_name, msg = _LANG_NOT_SUPPORTED[ext]
        return f"ℹ️  {lang_name} not supported as single-file syntax check: {msg}"

    cfg = _detect_language(resolved)
    if cfg is None:
        return (f"⚠️  syntax_check: unsupported extension {ext!r} (file {resolved}). "
                f"Supported: .py .js .mjs .cjs .ts .tsx .c .h .cpp .cc .cxx .hpp .go "
                f".java .pl .pm .rb .php .sh .bash "
                f".v .vh .sv .svh (iverilog) .vhd .vhdl (ghdl)")

    lang_name, needs_binary, syntax_argv, _lint_argv = cfg

    # Binary availability check (clean error before subprocess)
    if not _binary_available(needs_binary):
        return (f"❌ {lang_name} syntax_check not available: '{needs_binary}' is not on PATH. "
                f"Install it to enable {lang_name} checking on this machine.")

    # Substitute {file} (and {tmpdir} for Java which needs a -d target).
    import tempfile as _tempfile
    # {verilog_null} is the platform null output target for iverilog (-o NUL on
    # Windows, -o /dev/null on POSIX) so syntax-only checks produce no binary.
    _verilog_null = "NUL" if sys.platform == "win32" else "/dev/null"
    tmpdir = _tempfile.mkdtemp(prefix="aiprowler_syncheck_") if "{tmpdir}" in " ".join(syntax_argv) else None
    try:
        argv = [arg.replace("{file}", resolved)
                    .replace("{tmpdir}", tmpdir or "")
                    .replace("{verilog_null}", _verilog_null)
                for arg in syntax_argv]
        rc, out = _run_dev_subprocess(argv, timeout_sec)
    finally:
        if tmpdir:
            try:
                import shutil as _shutil
                _shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

    if rc == 0:
        _log.info("syntax_check OK (%s): %s", lang_name, resolved)
        return f"✅ syntax OK — {lang_name} — {resolved}\n   ({' '.join(argv)}, rc=0)"
    if rc == -1:
        return f"⚠️  syntax_check could not run: {out}"
    if rc == -2:
        return out  # already-formatted timeout message
    _log.warning("syntax_check FAILED (%s): %s\n%s", lang_name, resolved, out)
    return (f"❌ syntax FAILED — {lang_name} — {resolved}  (rc={rc})\n"
            f"───\n{out}")


@mcp.tool()
def lint_check(filepath: str, timeout_sec: int = _DEV_CHECK_TIMEOUT_SEC) -> str:
    """
    DEV TOOLS — Multi-language linter. Auto-detects language by extension and
    runs the appropriate lint tool. Catches unused imports, undefined names,
    style issues, and other warnings that syntax_check would let through.

    Tool used per language:
      Python      : pyflakes  (bundled — catches NameError-ish issues at lint time)
      TypeScript  : tsc --noEmit  (same as syntax_check; tsc IS the linter for TS)
      Go          : go vet  (built into Go toolchain)
      VHDL        : ghdl -a  (full semantic analysis, catches more than ghdl -s)
      Others      : no standard lint tool — use syntax_check instead.

    If a language has no lint tool available (Perl, Ruby, PHP, C/C++,
    Verilog/SystemVerilog, etc.), returns a clear "ℹ️ No lint tool for <lang>;
    use syntax_check" message.

    Available in all editions/modes; the file must be under a tracked
    read-allowlisted root regardless of edition.

    Args:
        filepath:    Path to the source file under a tracked root.
        timeout_sec: Max seconds to wait (default 120).

    Returns:
        "✅ lint clean — <lang>" or the linter's warnings/errors.
    """
    enabled, why = _dev_tools_enabled()
    if not enabled:
        return f"🚫 lint_check is disabled here ({why})."

    resolved, err = _resolve_allowlisted_path(filepath)
    if err:
        return err

    ext = os.path.splitext(resolved)[1].lower()
    cfg = _detect_language(resolved)
    if cfg is None:
        return (f"⚠️  lint_check: unsupported extension {ext!r}. "
                f"Use syntax_check to see supported languages.")

    lang_name, _needs_binary, _syntax_argv, lint_argv = cfg
    if lint_argv is None:
        return (f"ℹ️  No standard lint tool for {lang_name}. "
                f"Use syntax_check({filepath!r}) instead — it catches the same "
                f"errors syntax-level tools can detect.")

    lint_binary = lint_argv[0] if lint_argv[0] != sys.executable else sys.executable
    if not _binary_available(lint_binary):
        return (f"❌ {lang_name} lint_check not available: '{lint_binary}' is not on PATH. "
                f"Install it to enable {lang_name} linting on this machine.")

    argv = [arg.replace("{file}", resolved) for arg in lint_argv]
    rc, out = _run_dev_subprocess(argv, timeout_sec)

    if rc == 0 and not out.strip():
        _log.info("lint_check clean (%s): %s", lang_name, resolved)
        return f"✅ lint clean — {lang_name} — {resolved}\n   ({' '.join(argv)}, rc=0)"
    if rc == 0:
        # pyflakes returns rc=0 even when it has warnings — surface them
        return (f"⚠️  lint findings — {lang_name} — {resolved}  (rc=0, warnings only)\n"
                f"───\n{out}")
    if rc == -1:
        return f"⚠️  lint_check could not run: {out}"
    if rc == -2:
        return out
    _log.warning("lint_check FAILED (%s): %s\n%s", lang_name, resolved, out)
    return (f"❌ lint FAILED — {lang_name} — {resolved}  (rc={rc})\n"
            f"───\n{out}")


@mcp.tool()
def pytest_check(test_path: str, k_filter: str = "",
                 timeout_sec: int = 300, max_output_lines: int = 200) -> str:
    """
    DEV TOOLS — Run pytest against a test file or directory and return a
    summary plus the first failure trace (if any).

    Python-only by design: cross-language test runners differ enough (Go has
    `go test`, Rust has `cargo test`, JS has 5+ frameworks) that a unified
    abstraction would be confusing. For other languages, run their native
    test command via your normal dev workflow.

    Args:
        test_path:        Test file or directory under a tracked root.
        k_filter:         Optional `-k` substring filter (e.g. "REINDEX" runs
                          only test_C_REINDEX_*). Empty = run all in path.
        timeout_sec:      Max seconds (default 300 — pytest can be slow).
        max_output_lines: Truncate output to N lines from the end (default 200)
                          so a 10,000-line test log doesn't blow context.

    Returns:
        "✅ N passed in Xs" + summary, OR the failure section with first traces.
        Always includes the pass/fail counts on the last line for easy parsing.

    Available in all editions/modes; the file must be under a tracked
    read-allowlisted root regardless of edition.
    """
    enabled, why = _dev_tools_enabled()
    if not enabled:
        return f"🚫 pytest_check is disabled here ({why})."

    resolved, err = _resolve_allowlisted_path(test_path)
    if err:
        return err

    # Verify pytest is available in this Python's environment.
    import subprocess as _sp
    try:
        _check = _sp.run([sys.executable, "-c", "import pytest"],
                         capture_output=True, text=True, timeout=10, shell=False)
        if _check.returncode != 0:
            return ("❌ pytest_check: pytest is not installed in this Python "
                    "environment. Install with: `py -m pip install pytest`")
    except Exception as exc:
        return f"⚠️  pytest_check could not verify pytest availability: {exc}"

    argv = [sys.executable, "-m", "pytest", resolved, "-v", "--tb=short",
            "--no-header"]
    if k_filter:
        argv.extend(["-k", k_filter])

    # Run pytest from the project's directory so relative imports resolve.
    cwd = os.path.dirname(resolved) if os.path.isfile(resolved) else resolved
    # Walk up to find a likely project root (contains pytest.ini, pyproject.toml,
    # or tests/) so pytest's discovery works.
    project_root = cwd
    for _ in range(6):  # don't traverse forever
        if any(os.path.exists(os.path.join(project_root, marker))
               for marker in ("pytest.ini", "pyproject.toml", "setup.py")):
            break
        parent = os.path.dirname(project_root)
        if parent == project_root:
            break
        project_root = parent

    try:
        proc = _sp.run(argv, capture_output=True, text=True,
                       timeout=max(10, int(timeout_sec)), shell=False,
                       cwd=project_root)
    except _sp.TimeoutExpired:
        return (f"⏱️  pytest_check timed out after {timeout_sec}s on {resolved}. "
                f"Consider narrowing with k_filter, or raise timeout_sec.")
    except Exception as exc:
        return f"⚠️  pytest_check could not run: {exc}"

    out = (proc.stdout or "") + (proc.stderr or "")
    # Truncate from the top, keep the most recent lines (failures + summary).
    lines = out.splitlines()
    truncated = ""
    if len(lines) > max_output_lines:
        truncated = (f"... (truncated {len(lines) - max_output_lines} earlier "
                     f"lines; raise max_output_lines to see more) ...\n")
        lines = lines[-max_output_lines:]
    out_trimmed = truncated + "\n".join(lines)

    # pytest exit codes: 0=all passed, 1=tests failed, 2=interrupted,
    # 3=internal error, 4=usage error, 5=no tests collected
    if proc.returncode == 0:
        _log.info("pytest_check PASSED: %s", resolved)
        return (f"✅ pytest PASSED — {resolved}"
                f"{(' (filter: -k ' + k_filter + ')') if k_filter else ''}\n"
                f"───\n{out_trimmed}")
    if proc.returncode == 5:
        return (f"ℹ️  pytest_check: no tests collected for {resolved}"
                f"{(' (filter: -k ' + k_filter + ')') if k_filter else ''}.\n"
                f"───\n{out_trimmed}")
    _log.warning("pytest_check FAILED: %s  (rc=%d)", resolved, proc.returncode)
    return (f"❌ pytest FAILED — {resolved}  (rc={proc.returncode})"
            f"{(' (filter: -k ' + k_filter + ')') if k_filter else ''}\n"
            f"───\n{out_trimmed}")


# ══════════════════════════════════════════════════════════════════════════════
# END OF CODE TOOLS WRITE-SIDE PATCH
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL TOOLS  (v7.1.0)
# ══════════════════════════════════════════════════════════════════════════════
# SMTP Option-A implementation: Python stdlib only (smtplib + email + ssl).
# One-time configure_email() stores credentials in ~/.ai-prowler/email_config.json
# (password stored base64-obfuscated, same pattern as the bearer token file).
# All subsequent email tools (send_email, send_alert, send_learnings_report,
# send_file) pick up the stored config automatically.
#
# Server-mode safety: in server mode only owner/manager roles may send email;
# staff/field_crew are blocked.  The 'to' address must either be the requesting
# user's own email or be in the configured allowed_recipients list (if defined).
# ══════════════════════════════════════════════════════════════════════════════

import base64 as _b64

def _EMAIL_CONFIG_PATH() -> Path:
    return _state_dir() / "email_config.json"


def _email_config_load() -> "dict | None":
    """Load email config from disk. Returns None if not configured."""
    try:
        if _EMAIL_CONFIG_PATH().exists():
            raw = json.loads(_EMAIL_CONFIG_PATH().read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("smtp_host"):
                # Decode obfuscated password
                raw = dict(raw)
                enc = raw.get("_password_b64", "")
                if enc:
                    raw["password"] = _b64.b64decode(enc.encode()).decode("utf-8")
                return raw
    except Exception as _e:
        _log.warning("email_config load failed: %s", _e)
    return None


def _email_config_save(cfg: dict) -> bool:
    """Save email config to disk. Obfuscates password with base64."""
    try:
        _EMAIL_CONFIG_PATH().parent.mkdir(parents=True, exist_ok=True)
        out = dict(cfg)
        pw = out.pop("password", "")
        if pw:
            out["_password_b64"] = _b64.b64encode(pw.encode("utf-8")).decode()
        tmp = _EMAIL_CONFIG_PATH().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(out, indent=2), encoding="utf-8")
        import os as _eos
        _eos.replace(str(tmp), str(_EMAIL_CONFIG_PATH()))
        return True
    except Exception as _e:
        _log.error("email_config save failed: %s", _e)
        return False


def _send_smtp(to: str, subject: str, body: str,
               attachment_path: "str | None" = None,
               body_html: "str | None" = None) -> tuple:
    """Core SMTP send. Returns (ok: bool, message: str). Uses stored config."""
    import smtplib
    import ssl as _ssl
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders as _enc

    cfg = _email_config_load()
    if not cfg:
        return (False, "Email not configured. Call configure_email() first.")

    smtp_host = cfg.get("smtp_host", "").strip()
    smtp_port = int(cfg.get("smtp_port", 587))
    username  = cfg.get("username", "").strip()
    password  = cfg.get("password", "")
    from_addr = cfg.get("from_address", username).strip() or username
    from_name = cfg.get("from_name", "AI-Prowler").strip()
    use_tls   = cfg.get("use_tls", True)

    if not smtp_host or not username:
        return (False, "Incomplete email config — smtp_host and username required.")

    # Build message
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"]    = f"{from_name} <{from_addr}>" if from_name else from_addr
    msg["To"]      = to

    # Body — prefer HTML if provided, plain-text fallback
    alt_part = MIMEMultipart("alternative")
    alt_part.attach(MIMEText(body, "plain", "utf-8"))
    if body_html:
        alt_part.attach(MIMEText(body_html, "html", "utf-8"))
    msg.attach(alt_part)

    # Optional attachment
    if attachment_path:
        try:
            ap = Path(attachment_path)
            with open(ap, "rb") as _fh:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(_fh.read())
            _enc.encode_base64(part)
            part.add_header("Content-Disposition",
                            f'attachment; filename="{ap.name}"')
            msg.attach(part)
        except Exception as _ae:
            return (False, f"Could not attach file: {_ae}")

    # Connect and send
    try:
        context = _ssl.create_default_context()
        if smtp_port == 465:
            # SMTPS — SSL from the start
            with smtplib.SMTP_SSL(smtp_host, smtp_port,
                                  context=context, timeout=20) as server:
                server.login(username, password)
                server.sendmail(from_addr, [to], msg.as_bytes())
        else:
            # STARTTLS (port 587 typical)
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    server.starttls(context=context)
                    server.ehlo()
                server.login(username, password)
                server.sendmail(from_addr, [to], msg.as_bytes())
        _log.info("Email sent to %s subject=%r", to, subject)
        return (True, f"✅ Email sent to {to}")
    except smtplib.SMTPAuthenticationError:
        return (False,
                "❌ SMTP authentication failed — check username/password. "
                "For Gmail, use a 16-digit App Password (not your account password). "
                "Get one at: myaccount.google.com → Security → App passwords.")
    except smtplib.SMTPException as _se:
        return (False, f"❌ SMTP error: {_se}")
    except Exception as _ge:
        return (False, f"❌ Send failed: {_ge}")


def _email_allowed_for_user(user: "dict | None") -> tuple:
    """Gate email tools to personal mode only.
    Returns (allowed: bool, reason: str). PURE.

    Email tools are personal-mode only. They use the personal SMTP credentials
    configured by the individual user and are not appropriate for a shared
    company server where multiple employees connect via bearer tokens.

    Personal mode (user=None): always allowed.
    Server mode (user is not None): always blocked.
    """
    if user is None:
        return (True, "personal mode")
    return (False,
            "Email tools are only available in personal mode. "
            "In server mode each user should configure email on their own "
            "personal AI-Prowler install.")


@mcp.tool()
def configure_email(smtp_host: str, smtp_port: int, username: str,
                    password: str, from_name: str = "AI-Prowler",
                    default_to: str = "",
                    ctx: Context = None) -> str:
    """
    Configure SMTP email settings for AI-Prowler. One-time setup — all other
    email tools use the saved config automatically after this.

    Email tools are available in personal mode only. They are not available
    on shared company servers (server mode).

    Supports any SMTP provider:
      • Gmail   : smtp.gmail.com  port 587  (requires a 16-digit App Password,
                  NOT your account password. Create one at:
                  myaccount.google.com → Security → App passwords)
      • Outlook : smtp.office365.com  port 587
      • Yahoo   : smtp.mail.yahoo.com  port 587
      • Any other SMTP server your provider documents

    Args:
        smtp_host:  SMTP server hostname (e.g. 'smtp.gmail.com')
        smtp_port:  SMTP port — 587 for STARTTLS (most common),
                    465 for SMTPS, 25 for plain (not recommended)
        username:   Your email address / SMTP login
        password:   App password or SMTP password (stored obfuscated)
        from_name:  Display name shown in the From field (default: 'AI-Prowler')
        default_to: Default recipient email address. Tools that take a 'to'
                    argument use this when none is supplied.
        ctx:        MCP context (injected automatically)

    Returns:
        Confirmation string, or an error if the config could not be saved.
    """
    _telemetry_increment_tool_count("configure_email")

    # Personal-mode only
    user = _current_user(ctx)
    allowed, why = _email_allowed_for_user(user)
    if not allowed:
        return f"❌ {why}"

    smtp_host = smtp_host.strip()
    username  = username.strip()
    if not smtp_host:
        return "❌ smtp_host is required."
    if not username:
        return "❌ username (your email address) is required."
    if not password:
        return "❌ password is required."
    if smtp_port < 1 or smtp_port > 65535:
        return f"❌ smtp_port {smtp_port} is invalid (must be 1-65535)."

    cfg = {
        "smtp_host":    smtp_host,
        "smtp_port":    smtp_port,
        "username":     username,
        "password":     password,
        "from_address": username,
        "from_name":    from_name.strip() or "AI-Prowler",
        "default_to":   default_to.strip(),
        "use_tls":      smtp_port != 465,
    }

    if not _email_config_save(cfg):
        return "❌ Could not save email config. Check disk permissions."

    lines = [
        "✅ Email configured successfully.",
        f"   SMTP host  : {smtp_host}:{smtp_port}",
        f"   Account    : {username}",
        f"   From name  : {cfg['from_name']}",
    ]
    if default_to:
        lines.append(f"   Default to : {default_to}")
    lines += [
        "",
        "To test: call send_alert() or send_email() with a test message.",
        "Note: for Gmail use a 16-digit App Password — your account",
        "password will not work (Google blocks it for security).",
    ]
    return "\n".join(lines)


@mcp.tool()
def send_email(to: str, subject: str, body: str,
               attachment_path: str = "",
               ctx: Context = None) -> str:
    """
    Send an email via the configured SMTP account.

    Args:
        to:              Recipient email address. Leave blank to use the
                         configured default_to address.
        subject:         Email subject line.
        body:            Plain-text email body.
        attachment_path: Optional — absolute path to a file in a tracked
                         read-allowlisted directory to attach to the email.
        ctx:             MCP context (injected automatically)

    Returns:
        "✅ Email sent to <address>" on success, or an error string.

    Voice examples:
        "Email a summary of today's jobs to john@company.com"
        "Send the Johnson quote to the client"
        "Email myself the status report"
    """
    _telemetry_increment_tool_count("send_email")

    cfg = _email_config_load()
    if not cfg:
        return ("❌ Email not configured. "
                "Call configure_email() first with your SMTP settings.")

    to = (to or "").strip() or cfg.get("default_to", "").strip()
    if not to:
        return "❌ No recipient address. Provide a 'to' address or set default_to via configure_email()."

    subject = subject.strip()
    if not subject:
        return "❌ subject is required."
    if not body.strip():
        return "❌ body is required."

    # Personal-mode only gate
    user = _current_user(ctx)
    allowed, why = _email_allowed_for_user(user)
    if not allowed:
        return f"❌ {why}"

    # Resolve optional attachment
    attach = None
    if attachment_path and attachment_path.strip():
        resolved_attach, err = _resolve_allowlisted_path(attachment_path.strip())
        if err:
            return f"❌ Attachment: {err}"
        attach = resolved_attach

    ok, msg = _send_smtp(to, subject, body, attachment_path=attach)
    return msg


@mcp.tool()
def send_alert(message: str, to: str = "",
               ctx: Context = None) -> str:
    """
    Send a quick one-line alert email. Subject is auto-generated from the
    message. Great for short voice-commanded notifications.

    Args:
        message: The alert text. Keep it concise — it becomes both the
                 subject (truncated) and the body.
        to:      Recipient. Leave blank to use the configured default_to.
        ctx:     MCP context (injected automatically)

    Returns:
        "✅ Alert sent to <address>" on success, or an error string.

    Voice examples:
        "Send an alert to myself — the Johnson job is running late"
        "Ping sarah that I'm on my way"
        "Alert the team that the server is back up"
    """
    _telemetry_increment_tool_count("send_alert")

    cfg = _email_config_load()
    if not cfg:
        return ("❌ Email not configured. "
                "Call configure_email() first with your SMTP settings.")

    to = (to or "").strip() or cfg.get("default_to", "").strip()
    if not to:
        return "❌ No recipient. Provide a 'to' address or set default_to via configure_email()."

    message = message.strip()
    if not message:
        return "❌ message is required."

    user = _current_user(ctx)
    allowed, why = _email_allowed_for_user(user)
    if not allowed:
        return f"❌ {why}"

    # Subject: first 80 chars of message
    subject = f"AI-Prowler Alert: {message[:80]}"
    import datetime as _dt2
    body = (f"{message}\n\n"
            f"— Sent by AI-Prowler at "
            f"{_dt2.datetime.now().strftime('%Y-%m-%d %H:%M')}")

    ok, msg = _send_smtp(to, subject, body)
    return msg


@mcp.tool()
def send_file(to: str, filepath: str,
              subject: str = "", body: str = "",
              ctx: Context = None) -> str:
    """
    Send any file from a tracked directory as an email attachment.

    Args:
        to:       Recipient email address. Leave blank for default_to.
        filepath: Absolute path to the file to send (must be in the read
                  allowlist). Any file type is supported.
        subject:  Email subject. Auto-generated from filename if blank.
        body:     Email body text. Auto-generated if blank.
        ctx:      MCP context (injected automatically)

    Returns:
        "✅ Email sent" or an error string.

    Voice examples:
        "Email the Q3 report to the boss"
        "Send the updated config to john@company.com"
        "Email the job tracker spreadsheet to myself"
    """
    _telemetry_increment_tool_count("send_file")

    cfg = _email_config_load()
    if not cfg:
        return ("❌ Email not configured. "
                "Call configure_email() first.")

    to = (to or "").strip() or cfg.get("default_to", "").strip()
    if not to:
        return "❌ No recipient address."

    resolved, err = _resolve_allowlisted_path(filepath.strip())
    if err:
        return f"❌ {err}"

    fname = Path(resolved).name
    if not subject.strip():
        subject = f"AI-Prowler: {fname}"
    if not body.strip():
        import datetime as _dt3
        body = (f"File attached: {fname}\n\n"
                f"Sent by AI-Prowler at "
                f"{_dt3.datetime.now().strftime('%Y-%m-%d %H:%M')}")

    user = _current_user(ctx)
    allowed, why = _email_allowed_for_user(user)
    if not allowed:
        return f"❌ {why}"

    ok, msg = _send_smtp(to, subject, body, attachment_path=resolved)
    return msg


# ══════════════════════════════════════════════════════════════════════════════
# LEARNINGS MOBILE EXPORT TOOLS  (v7.1.0)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def get_learnings_report(category: str = "",
                          status: str = "active",
                          format: str = "summary",
                          ctx: Context = None) -> str:
    """
    Return learnings as formatted text directly in the conversation — no file
    dialog, no desktop required. Full mobile control over the learning store.

    Args:
        category: Filter to a single category (e.g. 'business', 'client',
                  'technical'). Leave blank for all categories.
        status:   'active' (default), 'archived', 'deprecated', or 'all'.
        format:   'summary'  — title + category + one-line content (default)
                  'full'     — everything: all fields per learning
                  'titles'   — titles only (quick list)
        ctx:      MCP context (injected automatically)

    Returns:
        Formatted text of the matching learnings, suitable for Claude to
        read aloud or display in the conversation.

    Voice examples:
        "Read me all my business learnings"
        "What have we learned about the Johnson account?"
        "List all my active technical learnings"
        "Show me a full summary of my client preferences"
    """
    _telemetry_increment_tool_count("get_learnings_report")

    if not _sl:
        return "❌ Self-learning module not available."

    try:
        db = _sl._load_db()
        learnings = db.get("learnings", [])
    except Exception as _e:
        return f"❌ Could not load learnings: {_e}"

    # Filter by status
    status = (status or "active").strip().lower()
    if status != "all":
        learnings = [l for l in learnings
                     if l.get("status", "active").lower() == status]

    # Filter by category
    cat = (category or "").strip().lower()
    if cat:
        learnings = [l for l in learnings
                     if l.get("category", "").lower() == cat]

    if not learnings:
        filters = []
        if cat:
            filters.append(f"category='{category}'")
        if status != "all":
            filters.append(f"status='{status}'")
        filter_str = " with " + ", ".join(filters) if filters else ""
        return f"ℹ️  No learnings found{filter_str}."

    fmt = (format or "summary").strip().lower()
    lines = [f"📚 AI-Prowler Learnings — {len(learnings)} found\n"]

    for i, l in enumerate(learnings, 1):
        title    = l.get("title", "(no title)")
        cat_val  = l.get("category", "")
        content  = l.get("content", "")
        conf     = l.get("confidence", "")
        outcome  = l.get("outcome", "")
        tags     = l.get("tags", [])
        recorded = l.get("recorded_at", "")[:10] if l.get("recorded_at") else ""

        if fmt == "titles":
            lines.append(f"{i}. {title}")
        elif fmt == "full":
            lines.append(f"{'─'*50}")
            lines.append(f"{i}. {title}")
            if cat_val:
                lines.append(f"   Category  : {cat_val}")
            if conf:
                lines.append(f"   Confidence: {conf}")
            if outcome:
                lines.append(f"   Outcome   : {outcome}")
            if recorded:
                lines.append(f"   Recorded  : {recorded}")
            if tags:
                lines.append(f"   Tags      : {', '.join(tags)}")
            lines.append(f"   Content   : {content}")
        else:  # summary
            short = content[:120].strip()
            if len(content) > 120:
                short += "…"
            cat_str = f"[{cat_val}] " if cat_val else ""
            lines.append(f"{i}. {cat_str}{title}")
            lines.append(f"   {short}")

    return "\n".join(lines)


@mcp.tool()
def export_learnings_file(filepath: str,
                          format: str = "pack",
                          category: str = "",
                          include_inactive: bool = False,
                          ctx: Context = None) -> str:
    """
    Export learnings to a file in a writable zone — mobile equivalent of the
    GUI's 'Export Pack' and 'Export to CSV' buttons.

    Args:
        filepath:         Destination path inside a writable zone. Use
                          '.aiplearn' extension for a pack (importable by
                          other AI-Prowler installs), '.csv' for spreadsheet.
                          Example: 'C:/Users/david/Documents/learnings.aiplearn'
        format:           'pack' (default) — .aiplearn JSON pack file
                          'csv'            — comma-separated spreadsheet
        category:         Filter to a single category. Leave blank for all.
        include_inactive: Include archived/deprecated learnings (default False).
        ctx:              MCP context (injected automatically)

    Returns:
        "✅ Exported N learnings to <path>" or an error string.

    Voice examples:
        "Export all my learnings to my documents folder"
        "Save a CSV of my business learnings to the desktop"
        "Export a learning pack to my OneDrive"
    """
    _telemetry_increment_tool_count("export_learnings_file")

    if not _sl:
        return "❌ Self-learning module not available."

    filepath = filepath.strip()
    if not filepath:
        return "❌ filepath is required."

    # Must be in a writable zone
    resolved, deny = _resolve_writable_path(filepath)
    if not resolved:
        return f"❌ {deny}"

    try:
        db = _sl._load_db()
        learnings = list(db.get("learnings", []))
    except Exception as _e:
        return f"❌ Could not load learnings: {_e}"

    # Filter
    cat = (category or "").strip().lower()
    if cat:
        learnings = [l for l in learnings if l.get("category", "").lower() == cat]
    if not include_inactive:
        learnings = [l for l in learnings
                     if l.get("status", "active") == "active"]

    if not learnings:
        return "ℹ️  No learnings matched the filter — nothing exported."

    fmt = (format or "pack").strip().lower()
    dest = Path(resolved)
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        if fmt == "csv":
            import csv as _csv
            import io as _io
            buf = _io.StringIO()
            writer = _csv.writer(buf)
            writer.writerow(["id", "title", "content", "category", "confidence",
                             "outcome", "tags", "status", "recorded_at",
                             "supersedes", "superseded_by"])
            for l in learnings:
                writer.writerow([
                    l.get("id", ""),
                    l.get("title", ""),
                    l.get("content", ""),
                    l.get("category", ""),
                    l.get("confidence", ""),
                    l.get("outcome", ""),
                    "|".join(l.get("tags", [])),
                    l.get("status", ""),
                    l.get("recorded_at", ""),
                    l.get("supersedes", ""),
                    l.get("superseded_by", ""),
                ])
            dest.write_text(buf.getvalue(), encoding="utf-8")
        else:
            # .aiplearn pack — same format as self_learning.export_learnings
            import datetime as _dt4
            pack = {
                "schema":      "1.0",
                "exported_at": _dt4.datetime.now(_dt4.timezone.utc).isoformat(),
                "source_app":  "AI-Prowler",
                "count":       len(learnings),
                "learnings":   learnings,
            }
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_text(json.dumps(pack, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            import os as _eos2
            _eos2.replace(str(tmp), str(dest))

        _log.info("export_learnings_file: %d learnings → %s (%s)",
                  len(learnings), dest, fmt)
        return (f"✅ Exported {len(learnings)} learning(s) to:\n"
                f"   {dest}\n"
                f"   Format: {'Learning Pack (.aiplearn)' if fmt != 'csv' else 'CSV spreadsheet'}")
    except Exception as _e:
        return f"❌ Export failed: {_e}"


@mcp.tool()
def send_learnings_report(to: str = "",
                          category: str = "",
                          subject: str = "",
                          include_inactive: bool = False,
                          ctx: Context = None) -> str:
    """
    Export learnings as a formatted HTML email report and send it. Combines
    get_learnings_report with send_email in one voice command.

    Args:
        to:               Recipient email. Leave blank for configured default_to.
        category:         Filter to a single category. Leave blank for all.
        subject:          Email subject. Auto-generated if blank.
        include_inactive: Include archived/deprecated learnings (default False).
        ctx:              MCP context (injected automatically)

    Returns:
        "✅ Learnings report sent to <address>" or error string.

    Voice examples:
        "Email all my learnings to david@company.com"
        "Send my business lessons to the team"
        "Email a summary of my client learnings to myself"
    """
    _telemetry_increment_tool_count("send_learnings_report")

    cfg = _email_config_load()
    if not cfg:
        return ("❌ Email not configured. "
                "Call configure_email() first.")

    to = (to or "").strip() or cfg.get("default_to", "").strip()
    if not to:
        return "❌ No recipient address."

    user = _current_user(ctx)
    allowed, why = _email_allowed_for_user(user)
    if not allowed:
        return f"❌ {why}"

    if not _sl:
        return "❌ Self-learning module not available."

    try:
        db = _sl._load_db()
        learnings = list(db.get("learnings", []))
    except Exception as _e:
        return f"❌ Could not load learnings: {_e}"

    cat = (category or "").strip().lower()
    if cat:
        learnings = [l for l in learnings if l.get("category", "").lower() == cat]
    if not include_inactive:
        learnings = [l for l in learnings
                     if l.get("status", "active") == "active"]

    if not learnings:
        return "ℹ️  No learnings matched the filter — nothing to send."

    import datetime as _dt5

    # Build HTML report
    cat_label = category if category else "All Categories"
    html_rows = ""
    for l in learnings:
        tags = ", ".join(l.get("tags", []))
        html_rows += (
            f"<tr>"
            f"<td style='padding:6px;border-bottom:1px solid #eee'><b>{l.get('title','')}</b></td>"
            f"<td style='padding:6px;border-bottom:1px solid #eee'>{l.get('category','')}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #eee'>{l.get('confidence','')}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #eee'>{l.get('content','')[:200]}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #eee'>{tags}</td>"
            f"<td style='padding:6px;border-bottom:1px solid #eee'>{l.get('recorded_at','')[:10]}</td>"
            f"</tr>"
        )

    html_body = f"""<html><body style='font-family:Segoe UI,Arial,sans-serif;color:#222'>
<h2 style='color:#005a9e'>AI-Prowler Learnings Report</h2>
<p><b>Category:</b> {cat_label} &nbsp;|&nbsp; <b>Count:</b> {len(learnings)}
   &nbsp;|&nbsp; <b>Generated:</b> {_dt5.datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<table style='border-collapse:collapse;width:100%;font-size:13px'>
<tr style='background:#005a9e;color:white'>
  <th style='padding:8px;text-align:left'>Title</th>
  <th style='padding:8px;text-align:left'>Category</th>
  <th style='padding:8px;text-align:left'>Confidence</th>
  <th style='padding:8px;text-align:left'>Content</th>
  <th style='padding:8px;text-align:left'>Tags</th>
  <th style='padding:8px;text-align:left'>Recorded</th>
</tr>
{html_rows}
</table>
<p style='color:#888;font-size:11px;margin-top:20px'>
Sent by AI-Prowler — Agentic RAG Knowledge Base</p>
</body></html>"""

    # Plain-text fallback
    plain = f"AI-Prowler Learnings Report — {cat_label} — {len(learnings)} entries\n\n"
    for l in learnings:
        plain += f"• {l.get('title','')} [{l.get('category','')}]\n"
        plain += f"  {l.get('content','')[:120]}\n\n"

    if not subject.strip():
        subject = (f"AI-Prowler Learnings Report"
                   + (f" — {category}" if category else "")
                   + f" ({len(learnings)} entries)")

    ok, msg = _send_smtp(to, subject, plain, body_html=html_body)
    if ok:
        return f"✅ Learnings report sent to {to} ({len(learnings)} learning(s))"
    return msg


@mcp.tool()
def rebuild_learnings_index(ctx: Context = None) -> str:
    """
    Rebuild the ChromaDB learnings index from the JSON data file. Fixes the
    case where search_learnings() returns nothing but learnings exist in the
    JSON file (index/data mismatch). Mobile equivalent of the GUI's
    'Rebuild ChromaDB Index' button in the Learnings tab.

    Returns:
        "✅ Rebuilt N learnings in ChromaDB" or error string.

    Voice examples:
        "Rebuild the learnings search index"
        "Fix the learnings database"
        "Reindex all my learnings"
    """
    _telemetry_increment_tool_count("rebuild_learnings_index")

    if not _sl:
        return "❌ Self-learning module not available."

    try:
        db = _sl._load_db()
        learnings = [l for l in db.get("learnings", [])
                     if l.get("status", "active") == "active"]
        count = 0
        for l in learnings:
            try:
                _sl.reindex_learning(l)
                count += 1
            except Exception:
                pass
        return f"✅ Rebuilt {count} active learning(s) in ChromaDB index."
    except Exception as _e:
        return f"❌ Rebuild failed: {_e}"


# ══════════════════════════════════════════════════════════════════════════════
# WRITE ZONE MANAGEMENT TOOLS  (v7.1.0)
# ══════════════════════════════════════════════════════════════════════════════
# Tools to list, grant, and revoke write-zone permissions from mobile.
#
# Server-mode scope enforcement:
#   • owner      — may grant/revoke any directory in the read allowlist
#   • manager    — may grant/revoke directories that are in their scope
#                  (scope is determined by the collection_map prefix rules)
#   • staff /    — no write-zone management; read-only users cannot grant
#     field_crew   themselves write access
#
# Personal mode (no ctx user): full access — no restrictions.
# ══════════════════════════════════════════════════════════════════════════════

def _write_zone_allowed_for_user(user: "dict | None", directory: str,
                                 users_data: "dict | None" = None) -> tuple:
    """Server-mode gate: may this user grant/revoke write access to directory?
    Returns (allowed: bool, reason: str). PURE-ish (reads users_data once)."""
    if user is None:
        return (True, "personal mode — no restrictions")

    role = (user.get("role") or "").lower()
    caps = _role_caps(role)

    # staff / field_crew: never
    if not caps.get("can_write"):
        return (False,
                f"role '{role}' cannot manage write zones. "
                "Only owner or manager roles may change write permissions.")

    # owner: unrestricted
    if caps.get("is_admin"):
        return (True, "owner may manage any write zone")

    # manager: directory must fall within one of their assigned scopes'
    # prefix rules in the collection_map (or their own private area).
    # We check the allowlisted read paths and whether the requested directory
    # is under a prefix the user can write to per _can_index.
    if users_data is None:
        users_data = _load_users()

    coll_map = _company_collection_map(users_data)
    dir_norm  = _normalize_path_for_match(directory)

    # Does any collection-map rule whose collection is in the user's scopes
    # cover this directory?
    user_scopes = set()
    for s in (user.get("scopes") or []):
        s = str(s).strip()
        user_scopes.add(s if s.startswith("role:") else f"role:{s}")

    for rule in (coll_map.get("rules") or []):
        prefix = _normalize_path_for_match(rule.get("prefix", ""))
        coll   = str(rule.get("collection", "")).strip()
        if not prefix or not coll:
            continue
        if (dir_norm == prefix or dir_norm.startswith(prefix + "/")):
            if coll in user_scopes:
                return (True, f"directory is within manager's scope '{coll}'")

    # Also allow manager's own private area (no scope rule needed)
    uid = user.get("id", "")
    if uid:
        priv_col = f"user:{uid}"
        allowed_priv, _ = _can_index(user, priv_col)
        if allowed_priv:
            # Check if the directory is the user's home or a known private path
            # (we can't know exactly — use a conservative check: allow if no
            # company rules matched but the user explicitly owns this area)
            pass   # fall through to denial — safest for managers

    return (False,
            f"directory '{directory}' is not within any scope assigned to role "
            f"'{role}'. Only the owner can grant write access outside your "
            f"assigned scopes.")


@mcp.tool()
def list_writable_directories(ctx: Context = None) -> str:
    """
    List all directories currently in the write-zone allowlist
    (~/.rag_writable_dirs.json) with their status.

    Returns a formatted list of writable directories. Also shows the read
    allowlist for reference so you can see what's readable vs writable.

    Voice examples:
        "What directories can Claude write to?"
        "Show me my write permissions"
        "List all writable folders"
    """
    _telemetry_increment_tool_count("list_writable_directories")

    writable = _writable_allowlist_load()
    read_dirs = load_auto_update_list() or []

    lines = ["📁 AI-Prowler Write Zone Status\n"]
    lines.append(f"Writable directories ({len(writable)}):")
    if writable:
        for w in sorted(writable):
            lines.append(f"  ✅ [W]  {w}")
    else:
        lines.append("  (none configured — Claude can read but not write files)")

    lines.append("")
    read_only = [r for r in read_dirs if r not in writable]
    lines.append(f"Read-only directories ({len(read_only)}):")
    if read_only:
        for r in sorted(read_only):
            lines.append(f"  📖 [R]  {r}")
    else:
        lines.append("  (no additional read-only directories)")

    lines += [
        "",
        "Legend: [W] = writable  [R] = read-only",
        "Use grant_write_access() to enable writes, revoke_write_access() to disable.",
    ]
    return "\n".join(lines)


@mcp.tool()
def grant_write_access(directory: str, ctx: Context = None) -> str:
    """
    Add a directory to the write-zone allowlist, giving Claude permission to
    create and edit files there. The directory must already be in the tracked
    read allowlist.

    In server mode, managers may only grant write access to directories within
    their assigned scopes. The owner may grant any directory.
    In personal mode there are no restrictions.

    Args:
        directory: Absolute path to the directory to make writable.
                   Must be in the tracked read allowlist.
        ctx:       MCP context (injected automatically)

    Returns:
        Confirmation string or error.

    Voice examples:
        "Grant write access to my AI-Prowler work folder"
        "Make the documents folder writable"
        "Allow Claude to edit files in C:/Projects/MyProject"
    """
    _telemetry_increment_tool_count("grant_write_access")

    directory = directory.strip()
    if not directory:
        return "❌ directory is required."

    # Normalize the path
    try:
        resolved = str(Path(directory).resolve())
    except Exception:
        resolved = directory

    # Server-mode scope check
    user = _current_user(ctx)
    users_data = _load_users() if user else None
    allowed, why = _write_zone_allowed_for_user(user, resolved, users_data)
    if not allowed:
        return f"❌ {why}"

    # Must be in the read allowlist
    read_dirs = load_auto_update_list() or []
    read_norm = [_normalize_path_for_match(r) for r in read_dirs]
    dir_norm  = _normalize_path_for_match(resolved)

    in_read = any(
        dir_norm == rn or dir_norm.startswith(rn + "/")
        for rn in read_norm
    )
    if not in_read:
        return (f"❌ '{resolved}' is not in the read allowlist.\n"
                f"Add it first with index_path(), then grant write access.")

    # Check if already writable
    writable = _writable_allowlist_load()
    writable_norm = [_normalize_path_for_match(w) for w in writable]
    if any(dir_norm == wn or dir_norm.startswith(wn + "/")
           for wn in writable_norm):
        return f"ℹ️  '{resolved}' is already in the write zone — no change needed."

    # Add and save
    writable.append(resolved)
    if not _writable_allowlist_save(writable):
        return "❌ Could not save write-zone allowlist. Check disk permissions."

    who = f" (granted by {user.get('name','?')})" if user else ""
    _log.info("grant_write_access: %s%s", resolved, who)
    return (f"✅ Write zone granted: '{resolved}'\n"
            f"Claude can now create and edit files in this directory.\n"
            f"Use revoke_write_access() to remove this permission.")


@mcp.tool()
def revoke_write_access(directory: str, ctx: Context = None) -> str:
    """
    Remove a directory from the write-zone allowlist. Claude will no longer
    be able to create or edit files there (read access is unaffected).

    In server mode, the same scope restrictions as grant_write_access apply.
    In personal mode there are no restrictions.

    Args:
        directory: Path to remove from the write zone.
        ctx:       MCP context (injected automatically)

    Returns:
        Confirmation string or error.

    Voice examples:
        "Revoke write access to the downloads folder"
        "Make the temp folder read-only again"
        "Remove write permission from C:/OldProject"
    """
    _telemetry_increment_tool_count("revoke_write_access")

    directory = directory.strip()
    if not directory:
        return "❌ directory is required."

    try:
        resolved = str(Path(directory).resolve())
    except Exception:
        resolved = directory

    # Server-mode scope check
    user = _current_user(ctx)
    users_data = _load_users() if user else None
    allowed, why = _write_zone_allowed_for_user(user, resolved, users_data)
    if not allowed:
        return f"❌ {why}"

    writable = _writable_allowlist_load()
    dir_norm  = _normalize_path_for_match(resolved)

    # Find matches (exact or parent)
    to_remove = [w for w in writable
                 if _normalize_path_for_match(w) == dir_norm
                 or _normalize_path_for_match(w).startswith(dir_norm + "/")]

    if not to_remove:
        return f"ℹ️  '{resolved}' is not in the write zone — nothing to revoke."

    new_list = [w for w in writable if w not in to_remove]
    if not _writable_allowlist_save(new_list):
        return "❌ Could not save write-zone allowlist. Check disk permissions."

    who = f" (revoked by {user.get('name','?')})" if user else ""
    removed = ", ".join(to_remove)
    _log.info("revoke_write_access: removed %s%s", removed, who)
    return (f"✅ Write zone revoked: '{resolved}'\n"
            f"Claude can still READ files there but can no longer write or edit them.")


# ══════════════════════════════════════════════════════════════════════════════
# REINDEX TOOLS  (v7.1.0)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def reindex_file(filepath: str, ctx: Context = None) -> str:
    """
    Re-index a SINGLE file in ChromaDB to match its current on-disk content.

    Call this ONCE when you have finished editing a file — NOT after every
    individual str_replace_in_file. Writes no longer auto-index (that caused an
    HTTP-server deadlock on large files), so the database stays stale until you
    run this. Delete-then-add: purges the file's existing chunks, then re-chunks
    and re-embeds the current content.

    Args:
        filepath: Absolute path to the file. Must be under a tracked
                  read-allowlisted root.

    Voice examples:
        "Re-index rag_gui.py"
        "Update the index for the file I just edited"
    """
    _telemetry_increment_tool_count("reindex_file")
    try:
        from rag_preprocessor import (
            normalise_path, index_file_list,
            get_chroma_client, COLLECTION_NAME,
        )
    except Exception as exc:
        return f"❌ reindex_file failed to import indexer: {exc}"

    # Resolve + allowlist-gate using the SAME wrapper the write/read tools use.
    # Returns (resolved_path, None) on allow, or (None, error_message) on deny.
    resolved, err = _resolve_allowlisted_path(filepath)
    if err:
        return err

    if not Path(resolved).is_file():
        return f"❌ Not a file (or does not exist): {resolved}"

    # All ChromaDB writes run on the single dedicated db-writer thread to avoid
    # the HNSW cross-thread EDEADLK ("resource deadlock would occur") that wedges
    # the HTTP server. purge + re-index happen together inside one job.
    def _job():
        try:
            client, embedding_func = get_chroma_client()
            coll = client.get_or_create_collection(
                name=COLLECTION_NAME,
                embedding_function=embedding_func,
            )
            coll.delete(where={"filepath": resolved})
        except Exception as exc:
            _log.warning("reindex_file: purge failed for %s: %s", resolved, exc)
            # continue — index_file_list still adds fresh chunks
        return index_file_list([resolved], label="reindex_file",
                               root_directory=str(Path(resolved).parent))

    try:
        stats = _db_write(_job, timeout=900.0)
    except TimeoutError as exc:
        return f"⏱️  reindex_file timed out for {resolved}: {exc}"
    except Exception as exc:
        return f"❌ reindex_file failed for {resolved}: {exc}"

    chunks = 0
    try:
        chunks = int(stats.get("chunks", 0)) if isinstance(stats, dict) else 0
    except Exception:
        pass

    return (f"✅ Re-indexed {resolved}\n"
            f"   {chunks:,} chunk(s) now in ChromaDB for this file.")


@mcp.tool()
def reindex_directory(directory: str, purge_first: bool = True,
                      ctx: Context = None) -> str:
    """
    Fully re-index a tracked directory — purge all existing chunks then
    rebuild from scratch. More thorough than update_tracked_directories which
    only processes changed files. Use this after chunk-size changes, suspected
    index corruption, or when you want a guaranteed clean slate.

    Args:
        directory:   Absolute path to the tracked directory to reindex.
                     Must be in the read allowlist.
        purge_first: If True (default), delete existing chunks before
                     re-indexing. Set False to add/update without purging
                     (faster but won't remove stale chunks for deleted files).
        ctx:         MCP context (injected automatically)

    Returns:
        Summary of files indexed and chunks created.

    Voice examples:
        "Completely re-index my documents folder"
        "Wipe and rebuild the index for the work folder"
        "Reindex everything in AI-Prowler"
    """
    _telemetry_increment_tool_count("reindex_directory")

    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait and try again."

    directory = directory.strip()
    if not directory:
        return "❌ directory is required."

    resolved, err = _resolve_allowlisted_path(directory)
    if err:
        return f"❌ {err}"

    try:
        import datetime as _dt6
        start = _dt6.datetime.now()

        # purge + re-index run together on the dedicated db-writer thread to
        # avoid the HNSW cross-thread EDEADLK that wedges the HTTP server.
        def _job():
            if purge_first:
                try:
                    client = _engine.get_chroma_client()
                    if isinstance(client, tuple):
                        client = client[0]
                    coll   = client.get_or_create_collection("documents")
                    existing = coll.get(where={"source": {"$regex": ".*"}},
                                        include=["metadatas"])
                    norm_dir = _normalize_path_for_match(resolved)
                    ids_to_del = [
                        existing["ids"][i]
                        for i, meta in enumerate(existing.get("metadatas") or [])
                        if _normalize_path_for_match(
                               str(meta.get("source",""))).startswith(norm_dir)
                    ]
                    if ids_to_del:
                        coll.delete(ids=ids_to_del)
                        _log.info("reindex_directory: purged %d chunks for %s",
                                  len(ids_to_del), resolved)
                except Exception as _pe:
                    _log.warning("reindex_directory: purge step warning: %s", _pe)
            with _capture_stdout() as buf:
                _r = index_directory(resolved)
            return _r, buf.getvalue()

        result, _out = _db_write(_job, timeout=1800.0)
        buf_value = _out
        elapsed = (_dt6.datetime.now() - start).total_seconds()

        output = (buf_value or "").strip()
        if isinstance(result, dict):
            files   = result.get("files_indexed", "?")
            chunks  = result.get("chunks_added", "?")
            return (f"✅ Reindex complete for: {resolved}\n"
                    f"   Files indexed : {files}\n"
                    f"   Chunks created: {chunks}\n"
                    f"   Time          : {elapsed:.1f}s\n"
                    + (f"   Output        : {output[:200]}" if output else ""))
        else:
            return (f"✅ Reindex triggered for: {resolved}\n"
                    f"   Time: {elapsed:.1f}s\n"
                    + (f"   {output[:300]}" if output else ""))

    except Exception as _e:
        _log.error("reindex_directory error: %s", _e)
        return f"❌ Reindex failed: {_e}"


@mcp.tool()
def reindex_all(purge_first: bool = True, ctx: Context = None) -> str:
    """
    Fully re-index ALL tracked directories — the nuclear option. Purges and
    rebuilds the entire ChromaDB index from scratch. Use after changing
    chunk size settings, or to fix any index corruption.

    This may take several minutes depending on how many documents are indexed.

    Args:
        purge_first: If True (default), wipe the entire index before
                     re-indexing. Set False to update without purging.
        ctx:         MCP context (injected automatically)

    Returns:
        Summary of all directories processed, files indexed, and time taken.

    Voice examples:
        "Rebuild the entire knowledge base from scratch"
        "Reindex all tracked directories"
        "Do a full reindex of everything"
    """
    _telemetry_increment_tool_count("reindex_all")

    if not _prewarm_event.wait(timeout=60):
        return "⏳ AI-Prowler is still initializing. Please wait and try again."

    read_dirs = load_auto_update_list() or []
    if not read_dirs:
        return "ℹ️  No tracked directories found. Use index_path() first."

    import datetime as _dt7
    start     = _dt7.datetime.now()
    results   = []
    total_files  = 0
    total_chunks = 0
    errors = []

    for d in read_dirs:
        try:
            dir_result = reindex_directory(d, purge_first=purge_first, ctx=ctx)
            results.append(f"  ✅ {d}")
            # Parse counts from the returned string if available
            for line in dir_result.splitlines():
                if "Files indexed" in line:
                    try:
                        total_files += int(line.split(":")[-1].strip())
                    except Exception:
                        pass
                if "Chunks created" in line:
                    try:
                        total_chunks += int(line.split(":")[-1].strip())
                    except Exception:
                        pass
        except Exception as _e:
            errors.append(f"  ❌ {d}: {_e}")

    elapsed = (_dt7.datetime.now() - start).total_seconds()
    lines = [
        f"✅ Full reindex complete — {len(read_dirs)} director{'y' if len(read_dirs)==1 else 'ies'}",
        f"   Total files  : {total_files}",
        f"   Total chunks : {total_chunks}",
        f"   Time         : {elapsed:.1f}s",
        "",
        "Directories processed:",
    ] + results

    if errors:
        lines += ["", "Errors:"] + errors

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# EDITION / MODE + ACTIVATION — MODULE-LEVEL PURE HELPERS  (v7.0.0 Phase A')
# ══════════════════════════════════════════════════════════════════════════════
# These four functions are PURE (no I/O beyond reading config.json in
# _load_runtime_config) and were hoisted out of _run_http() to module level so
# the test suite (tests/mcp/test_edition_activation.py) can import and call them
# directly without launching the HTTP server. _run_http() calls them by bare
# name, which now resolves here. See PHASE_A_PRIME_TEST_PLAN.md §4.0.
#
# EDITION : "home" | "mobile" | "business"     MODE : "personal" | "server"
# Valid combos: (home,personal) (mobile,personal) (business,personal)
#               (business,server).  (home,server) and (mobile,server) invalid.
# Backwards-compat: plan "individual" reads as the "mobile" edition; no live
# subs.json record is ever rewritten.
# ══════════════════════════════════════════════════════════════════════════════
# ── Test-state sandbox hook (v7.0.0 — pre-release server-mode validation) ─────
# When AIPROWLER_TEST_STATE_DIR is set, AI-Prowler reads its state files
# (config.json, users.json, and the subs cache) from that directory instead of
# ~/.ai-prowler. This lets an automated test suite stand up a fully sandboxed
# server-mode instance without touching the operator's real state and without a
# live license. SAFETY: this only redirects WHERE state is read from; it does
# NOT disable any enforcement (auth, scoping, ownership all still run for real).
# The companion entitlement short-circuit (_test_entitlement_active / used in
# main()) is what skips the NETWORK license/subscription calls under test, and
# it is HARD-GATED to dev/Home boxes — see _test_entitlement_active(). The env
# var must be set at process launch, so it can never be flipped on a deployed,
# tunnel-exposed customer install by editing a file or calling a tool.
def _state_dir() -> Path:
    """Directory holding AI-Prowler's state files. Honors the test sandbox env
    var AIPROWLER_TEST_STATE_DIR when set; otherwise the real ~/.ai-prowler."""
    import os as _os
    td = _os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    if td:
        return Path(td)
    return Path.home() / ".ai-prowler"


def _test_state_active() -> bool:
    """True iff the test-state sandbox env var is set (paths are redirected)."""
    import os as _os
    return bool(_os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip())


def _test_entitlement_active(cfg: "dict | None" = None) -> bool:
    """True iff the test ENTITLEMENT short-circuit may engage — i.e. the startup
    flow should substitute a sandboxed (edition/mode/status) verdict and SKIP the
    network license/subscription/activation calls.

    HARD-GATED by TWO independent affirmations, both only settable by whoever
    launches the process (never by a deployed customer box at runtime):
      1. AIPROWLER_TEST_STATE_DIR env var is set (state is sandboxed), AND
      2. the sandboxed config.json explicitly carries "test_mode": true.
    Either alone is insufficient. This short-circuit substitutes only the
    ENTITLEMENT verdict; it never disables auth, scoping, or ownership — those
    run for real against the sandboxed users.json. PURE (reads cfg only)."""
    if not _test_state_active():
        return False
    if cfg is None:
        try:
            cfg = _load_runtime_config()
        except Exception:
            return False
    return cfg.get("test_mode") is True


_CONFIG_PATH = _state_dir() / "config.json"

_VALID_EDITIONS = ("home", "mobile", "business")
_VALID_MODES    = ("personal", "server")
_MOBILE_PLAN_SYNONYMS   = ("mobile", "individual")
_BUSINESS_PLAN_SYNONYMS = ("business", "small_business", "enterprise")

# 2-active-install rule (architecture spec §4)
_ACTIVE_WINDOW_DAYS  = 14   # last_seen within N days == "active"
_MAX_ACTIVE_INSTALLS = 2    # at most this many active install_ids per license


def _plan_to_edition(plan: str) -> str:
    """Map a subs.json plan string onto an edition. Unknown/empty → 'mobile'
    (any managed subscriber gets at least remote access; a fail-open default
    that never strips entitlement from a paying user)."""
    p = (plan or "").strip().lower()
    if p in _BUSINESS_PLAN_SYNONYMS:
        return "business"
    if p in _MOBILE_PLAN_SYNONYMS:
        return "mobile"
    return "mobile"


def _load_runtime_config() -> dict:
    """Read ~/.ai-prowler/config.json and return a normalized dict with at
    least edition/mode keys. Missing file or unreadable JSON yields the safe
    default (home, personal). Never raises."""
    cfg = {}
    try:
        if _CONFIG_PATH.exists():
            # utf-8-sig tolerates a BOM from PowerShell/Notepad-edited configs.
            cfg = json.loads(_CONFIG_PATH.read_text(encoding="utf-8-sig")) or {}
    except Exception as _e:
        _log.warning("config.json unreadable (%s) — defaulting to home/personal", _e)
        cfg = {}
    edition = str(cfg.get("edition", "home")).strip().lower()
    mode    = str(cfg.get("mode", "personal")).strip().lower()
    if edition not in _VALID_EDITIONS:
        _log.warning("Unknown edition %r in config — defaulting to 'home'", edition)
        edition = "home"
    if mode not in _VALID_MODES:
        _log.warning("Unknown mode %r in config — defaulting to 'personal'", mode)
        mode = "personal"
    cfg["edition"] = edition
    cfg["mode"]    = mode
    return cfg


def _enforce_edition_mode(edition: str, mode: str, sub_status: str) -> tuple[str, str]:
    """Belt-and-suspenders startup enforcement (architecture spec §2),
    hardened against manual config.json tampering. Returns the (possibly
    downgraded) effective (edition, mode).

    Rules:
      1. server mode requires business edition → else fall back to personal.
      2. mobile/business editions require a VALID managed subscription
         (sub_status 'ok' or 'warning'); otherwise fall back to home.
    """
    eff_edition, eff_mode = edition, mode

    if eff_mode == "server" and eff_edition != "business":
        _log.warning(
            "Server mode requires Business edition; got edition=%s. "
            "Falling back to personal mode.", eff_edition)
        eff_mode = "personal"

    if eff_edition in ("mobile", "business") and sub_status not in ("ok", "warning"):
        _log.warning(
            "Edition=%s requires a valid subscription but status is %r. "
            "Falling back to Home edition (remote access disabled).",
            eff_edition, sub_status)
        eff_edition = "home"
        eff_mode = "personal"   # home can never be server

    return eff_edition, eff_mode


def _evaluate_activation(entry: dict, install_id: str, now=None) -> dict:
    """Decide this install_id's activation standing for a subscriber entry.
    PURE — no I/O, no mutation. Returns a dict with keys: decision
    ('active'|'admissible'|'rejected'|'unbound'), active_install_ids,
    active_count, this_active, message. See architecture spec §4 and
    PHASE_A_PRIME_TEST_PLAN.md §4.1 for the full decision table.

    'now' is an injectable clock (datetime) for deterministic tests; defaults
    to UTC now. Records older than _ACTIVE_WINDOW_DAYS are not counted (they
    auto-release); pruning is a write-side concern, not done here."""
    import datetime as _dt

    if not install_id:
        return {"decision": "unbound", "active_install_ids": [],
                "active_count": 0, "this_active": False,
                "message": "install_id unavailable — activation binding skipped (fail-open)"}

    if now is None:
        now = _dt.datetime.now(_dt.timezone.utc)

    def _parse(ts: str):
        if not ts:
            return None
        try:
            s = ts.strip().replace("Z", "+00:00")
            d = _dt.datetime.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=_dt.timezone.utc)
            return d
        except Exception:
            return None

    cutoff = now - _dt.timedelta(days=_ACTIVE_WINDOW_DAYS)
    activations = entry.get("activations", []) or []

    active_ids = []
    for a in activations:
        if not isinstance(a, dict):
            continue
        iid = a.get("install_id")
        if not iid:
            continue
        seen = _parse(a.get("last_seen", "")) or _parse(a.get("first_seen", ""))
        if seen is not None and seen >= cutoff:
            if iid not in active_ids:
                active_ids.append(iid)

    this_active = install_id in active_ids
    count = len(active_ids)

    if this_active:
        return {"decision": "active", "active_install_ids": active_ids,
                "active_count": count, "this_active": True,
                "message": f"This machine is an active install ({count} of {_MAX_ACTIVE_INSTALLS})."}

    if count < _MAX_ACTIVE_INSTALLS:
        return {"decision": "admissible", "active_install_ids": active_ids,
                "active_count": count, "this_active": False,
                "message": (f"New install with capacity "
                            f"({count} of {_MAX_ACTIVE_INSTALLS} used) — will activate.")}

    return {"decision": "rejected", "active_install_ids": active_ids,
            "active_count": count, "this_active": False,
            "message": (
                f"This license is already active on {_MAX_ACTIVE_INSTALLS} machines. "
                f"Release one in your AI-Prowler License panel, or purchase an "
                f"additional license, to use it here.")}


# ══════════════════════════════════════════════════════════════════════════════
# BUSINESS LICENSE VALIDATION + GRACE LADDER  (v7.0.0 Phase B — base spec §3.3/§3.4)
# ══════════════════════════════════════════════════════════════════════════════
# A Business install validates its license key against the Worker's
# /license/validate endpoint on launch, caching the result in
# ~/.ai-prowler/license_cache.json. The cache + grace ladder protect a paying
# customer from network blips: a brief outage must NOT instantly downgrade them
# to Home. The ladder (§3.4), measured from last SUCCESSFUL validation:
#   • within 30 days of success                → use cache, no network call needed
#   • network fail, within 30 days of last ok  → cached_fresh (still trust)
#   • network fail, 30-37 days since last ok    → run business, log silently
#   • network fail, 37-44 days since last ok    → run business, show warning banner
#   • network fail, ≥ 44 days since last ok     → revert to home (data kept, features gated)
#   • explicit 'revoked'/'suspended'            → revert to home IMMEDIATELY (no grace)
#
# Constants are ordered FRESH ≤ WARN ≤ GRACE; the grace ladder only fires for
# caches OLDER than FRESH, so each tier gets a meaningful 7-day window beyond
# the 30-day trust period.
#
# _evaluate_license_grace() is PURE (no I/O) so it is unit-testable; the I/O
# wrapper _validate_business_license() does the cache read/write + HTTP POST.
_LICENSE_CACHE_PATH   = Path.home() / ".ai-prowler" / "license_cache.json"
_LICENSE_FRESH_HOURS  = 720  # within this since last success → trust cache, skip network (30 days, v7.0.0)
_LICENSE_WARN_DAYS    = 37   # network-fail past this since success → warning banner (30d trust + 7d silent)
_LICENSE_GRACE_DAYS   = 44   # network-fail past this since success → revert to home (30d trust + 14d grace)

# Reasons the Worker returns that mean "stop being business right now" (no grace).
_LICENSE_HARD_FAIL_REASONS = ("revoked", "suspended", "parent_revoked",
                              "parent_suspended", "not_found", "bad_format")


def _evaluate_license_grace(cache: dict, validate_result: "dict | None",
                            now=None) -> dict:
    """Decide the effective Business-license standing. PURE.

    Args:
        cache:           parsed license_cache.json (may be {} if none yet).
                         Recognized keys: last_validated_at (ISO), status,
                         cached_expires_at (ISO).
        validate_result: the Worker's /license/validate JSON this launch, or
                         None if the network call wasn't made/failed. Shape:
                         {valid: bool, reason?, edition?, expires_at?, status?}.
        now:             injectable clock (datetime); defaults to UTC now.

    Returns dict:
        effective_edition : 'business' | 'home'
        action            : 'validated' | 'cached_fresh' | 'grace_silent'
                            | 'grace_warning' | 'reverted_expired'
                            | 'reverted_revoked'
        banner            : str  (warning/notice text, '' if none)
        used_network      : bool (did we trust a fresh validate_result)
    """
    import datetime as _dt

    if now is None:
        now = _dt.datetime.now(_dt.timezone.utc)

    def _parse(ts):
        if not ts:
            return None
        try:
            s = str(ts).strip().replace("Z", "+00:00")
            d = _dt.datetime.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=_dt.timezone.utc)
            return d
        except Exception:
            return None

    # 1) Fresh successful validation this launch → trust it.
    if validate_result is not None:
        if validate_result.get("valid") is True:
            return {"effective_edition": "business", "action": "validated",
                    "banner": "", "used_network": True}
        # Explicit negative from the Worker — hard fail, no grace.
        reason = validate_result.get("reason", "invalid")
        if reason in _LICENSE_HARD_FAIL_REASONS:
            return {"effective_edition": "home", "action": "reverted_revoked",
                    "banner": (f"Business license is no longer valid ({reason}). "
                               f"Reverted to Home features. Contact "
                               f"david.vavro1@gmail.com to restore service."),
                    "used_network": True}
        # Unknown negative reason — treat as a soft/network-ish failure, fall
        # through to the cache-based grace ladder below.

    # 2) No fresh success (network failure, or unknown negative). Lean on cache.
    last_ok = _parse(cache.get("last_validated_at"))
    if last_ok is None:
        # Never successfully validated and can't now → can't grant business.
        return {"effective_edition": "home", "action": "reverted_expired",
                "banner": ("Could not validate your Business license and no "
                           "prior validation is cached. Running Home features. "
                           "Check your connection and license key."),
                "used_network": False}

    age = now - last_ok
    age_days = age.total_seconds() / 86400.0

    # 2a) Within 24h of a prior success and we didn't need the network → cached.
    if validate_result is None and age.total_seconds() <= _LICENSE_FRESH_HOURS * 3600:
        return {"effective_edition": "business", "action": "cached_fresh",
                "banner": "", "used_network": False}

    # 2b) Grace ladder by days since last success.
    if age_days < _LICENSE_WARN_DAYS:
        return {"effective_edition": "business", "action": "grace_silent",
                "banner": "", "used_network": False}

    if age_days < _LICENSE_GRACE_DAYS:
        revert_on = (last_ok + _dt.timedelta(days=_LICENSE_GRACE_DAYS)).date().isoformat()
        return {"effective_edition": "business", "action": "grace_warning",
                "banner": (f"License validation has failed for several days. "
                           f"Renew/reconnect before {revert_on} or Business "
                           f"features will be disabled."),
                "used_network": False}

    return {"effective_edition": "home", "action": "reverted_expired",
            "banner": ("Business license could not be validated for "
                       f"{_LICENSE_GRACE_DAYS}+ days. Reverted to Home features. "
                       "Your data is intact; reconnect to restore Business."),
            "used_network": False}


def _load_license_cache_for(license_key: str) -> dict:
    """Return the cached validation entry for ONE license key, or {} if absent.

    Cache shape (v7.0.0): a per-key map keyed by full license_key:
        {"licenses": {"AP-XXXX-...": {"last_validated_at": "...", ...}}}

    Backward compat: a legacy file with top-level last_validated_at is treated
    as the entry for the FIRST key we're asked about (the parent at startup),
    and migrated to the new shape on the next successful save.
    """
    try:
        if not _LICENSE_CACHE_PATH.exists():
            return {}
        raw = json.loads(_LICENSE_CACHE_PATH.read_text(encoding="utf-8-sig")) or {}
    except Exception as _e:
        _log.warning("license_cache.json unreadable (%s)", _e)
        return {}

    # New shape: {"licenses": {key: entry}}
    if isinstance(raw.get("licenses"), dict):
        entry = raw["licenses"].get(license_key)
        return entry if isinstance(entry, dict) else {}

    # Legacy shape: top-level fields belong to whichever key asks first.
    # We can't distinguish, so we return it unconditionally — the writer below
    # will migrate it to the new shape under THIS key on next success.
    if "last_validated_at" in raw:
        return raw
    return {}


def _save_license_cache_for(license_key: str, entry: dict) -> None:
    """Persist a per-key cache entry under the new shape, migrating legacy
    top-level fields into the new map if needed. Never raises."""
    try:
        _LICENSE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if _LICENSE_CACHE_PATH.exists():
            try:
                existing = json.loads(
                    _LICENSE_CACHE_PATH.read_text(encoding="utf-8-sig")) or {}
            except Exception:
                existing = {}

        # Ensure we end up with the new shape: {"licenses": {key: entry, ...}}
        licenses_map = {}
        if isinstance(existing.get("licenses"), dict):
            licenses_map = dict(existing["licenses"])
        elif "last_validated_at" in existing:
            # Legacy single-license file — we don't know which key it belonged
            # to. Drop it: the new save below puts the current key in correctly,
            # and the legacy entry is only useful if it matches the active key,
            # in which case the new entry replaces it anyway.
            pass

        licenses_map[license_key] = entry
        _LICENSE_CACHE_PATH.write_text(
            json.dumps({"licenses": licenses_map}, indent=2), encoding="utf-8")
    except Exception as _e:
        _log.warning("Could not write license_cache.json (%s)", _e)


def _validate_business_license(license_key: str, install_id: str,
                               endpoint: str, now=None) -> dict:
    """I/O wrapper around _evaluate_license_grace: read PER-KEY cache, decide
    whether to call the Worker, POST /license/validate, persist a fresh success,
    and return the grace evaluation. Never raises.

    Returns the _evaluate_license_grace dict, plus 'license_key_present': bool.

    v7.0.0 changes: per-key cache (so the server can validate parent + N child
    keys without overwriting each other), and a 30-day fresh-cache window
    (_LICENSE_FRESH_HOURS = 720) so a long-running server hits the network on
    a ~30d cadence and a daily-launched personal install skips the network on
    each launch within those 30 days.
    """
    import datetime as _dt
    if now is None:
        now = _dt.datetime.now(_dt.timezone.utc)

    if not license_key:
        return {"effective_edition": "home", "action": "no_license",
                "banner": "", "used_network": False, "license_key_present": False}

    # Load this key's cache entry (tolerant of missing/corrupt file).
    cache = _load_license_cache_for(license_key)

    # If cache is fresh (<30d since success), skip the network entirely.
    last_ok = None
    try:
        s = str(cache.get("last_validated_at", "")).strip().replace("Z", "+00:00")
        if s:
            last_ok = _dt.datetime.fromisoformat(s)
            if last_ok.tzinfo is None:
                last_ok = last_ok.replace(tzinfo=_dt.timezone.utc)
    except Exception:
        last_ok = None

    if last_ok is not None and (now - last_ok).total_seconds() <= _LICENSE_FRESH_HOURS * 3600:
        result = _evaluate_license_grace(cache, None, now=now)
        result["license_key_present"] = True
        return result

    # Otherwise POST to the Worker.
    validate_result = None
    try:
        import requests as _req
        resp = _req.post(
            f"{endpoint.rstrip('/')}/license/validate",
            json={"license_key": license_key, "install_id": install_id or ""},
            headers={"Content-Type": "application/json",
                     "User-Agent": "AI-Prowler-MCP/1.0"},
            timeout=10, proxies={"http": None, "https": None})
        if resp.status_code == 200:
            validate_result = resp.json()
        else:
            _log.warning("license/validate returned HTTP %s", resp.status_code)
    except Exception as _e:
        _log.warning("license/validate unreachable (%s) — using grace ladder", _e)

    result = _evaluate_license_grace(cache, validate_result, now=now)

    # Persist a fresh SUCCESS to the cache (so the 30d fast-path + grace anchor work).
    if validate_result is not None and validate_result.get("valid") is True:
        _save_license_cache_for(license_key, {
            "last_validated_at": now.isoformat(),
            "status": validate_result.get("status", "active"),
            "cached_expires_at": validate_result.get("expires_at", ""),
            "edition": validate_result.get("edition", "business"),
        })

    result["license_key_present"] = True
    return result


def _sweep_child_licenses(users_doc, validate_fn):
    """Walk active users and validate each one's child_license_key.

    PURE-AT-THE-EDGE — takes the users dict + the validate function as injectables
    so tests can stub the network. Returns a list of warning entries; the caller
    decides what to do with them (log, surface in GUI, etc.). Soft policy per
    David 2026-05-28: rejections produce warnings but do NOT mutate users_doc.

    Args:
        users_doc:    The parsed users.json dict, or anything with a 'users' key
                      mapping bearer-token → user record. Falsy/missing 'users'
                      yields an empty result.
        validate_fn:  Callable(license_key: str) -> dict matching the shape of
                      _validate_business_license's return:
                        {'effective_edition': 'business'|'home',
                         'action': str,
                         'banner': str, ...}

    Returns:
        list of dicts: [{name, child_key_masked, reason, banner}, ...]
        Empty list when nothing is wrong.

    Skip rules (each entry is silently skipped if):
      - record is not a dict (malformed users.json entry)
      - status is not 'active' (suspended/removed users don't consume checks)
      - child_license_key is empty (not yet assigned)

    A user whose validate_fn returns effective_edition=='business' AND no banner
    is healthy and contributes nothing to the result.
    """
    warnings = []
    if not isinstance(users_doc, dict):
        return warnings
    users_map = users_doc.get("users") or {}
    if not isinstance(users_map, dict):
        return warnings

    for _utok, urec in users_map.items():
        if not isinstance(urec, dict):
            continue
        if urec.get("status", "active") != "active":
            continue
        # Read the child key. Treat JSON null / missing / empty / non-string all
        # as 'no key assigned'. (A bare str() on None becomes the literal string
        # "None" which is truthy, so the falsy-check has to come FIRST.)
        ckey_raw = urec.get("child_license_key")
        if not ckey_raw or not isinstance(ckey_raw, str):
            continue   # phone-only-without-key OR not yet assigned OR malformed
        ckey = ckey_raw.strip()
        if not ckey:
            continue   # whitespace-only is treated as no key

        try:
            cres = validate_fn(ckey) or {}
        except Exception as _ve:
            # A failed validate call shouldn't kill the sweep — record it and
            # move on (the caller's outer try/except still catches catastrophic
            # failures, but per-user errors should be local).
            _log.warning("validate_fn raised for child key (%s); skipping user", _ve)
            continue

        eff = cres.get("effective_edition")
        banner = cres.get("banner", "")
        # Mask: first 4 + last 8. The dashed AP-key format puts the distinguishing
        # bits in the last two segments, so a short tail like 4 would still leave
        # sibling keys looking identical (e.g. AP-CHLD-AAAA-0001 vs ...-BBBB-0002
        # both shrink to AP-C…0001 / AP-C…0002 — same prefix, indistinguishable).
        # 8 trailing chars preserves the AAAA/BBBB segment.
        masked = (ckey[:4] + "…" + ckey[-8:]) if len(ckey) > 13 else ckey

        if eff != "business":
            warnings.append({
                "name": urec.get("name", "(unnamed)"),
                "child_key_masked": masked,
                "reason": cres.get("action", "rejected"),
                "banner": banner,
            })
            _log.warning(
                "Child license check FAILED for user=%s key=%s → %s",
                urec.get("name", "?"), masked, cres.get("action", "rejected"))
        elif banner:
            # Grace-warning on a child key — surface as a softer warning.
            warnings.append({
                "name": urec.get("name", "(unnamed)"),
                "child_key_masked": masked,
                "reason": cres.get("action", "grace_warning"),
                "banner": banner,
            })
            _log.warning(
                "Child license grace-warning for user=%s key=%s: %s",
                urec.get("name", "?"), masked, banner)

    return warnings


# Path the engine writes child-license warnings to; the GUI Admin tab reads it
# on each refresh. Always written (even when warnings=[]) so the GUI can tell
# "no issues as of <last_check_at>" from "the sweep has never run" (file absent).
_LICENSE_WARNINGS_PATH = Path.home() / ".ai-prowler" / "license_warnings.json"


def _save_license_warnings(warnings):
    """Persist the child-license warnings list for the GUI to read. Atomic
    write (tmp + os.replace). Never raises — a failed write should never
    block startup, since the warnings are advisory (the bearer-token auth
    path still works regardless)."""
    import datetime as _dt
    try:
        _LICENSE_WARNINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_check_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "warnings":      list(warnings or []),
        }
        tmp = _LICENSE_WARNINGS_PATH.with_suffix(
            _LICENSE_WARNINGS_PATH.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        import os as _os
        _os.replace(str(tmp), str(_LICENSE_WARNINGS_PATH))
    except Exception as _e:
        _log.warning("Could not write %s (%s)", _LICENSE_WARNINGS_PATH, _e)


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-USER MODEL — pure auth/scoping helpers  (v7.0.0 Phase B Block 3, spec §6)
# ══════════════════════════════════════════════════════════════════════════════
# Server-mode only. These PURE functions are the security spine (§6.4): they
# resolve a bearer token to a user, compute the exact set of ChromaDB collections
# that user may touch, and decide indexing permission. They have NO I/O — the
# uvicorn middleware (built at the keyboard) reads users.json, calls
# _resolve_user(), attaches request.state.user, then uses _allowed_collections()
# to constrain every ChromaDB call. Enforcement is at the collection-selection
# level, never a post-filter, so a request can never receive results from a
# collection outside its scope.
#
# Roles (§6.1) are a FIXED set. The matrix below encodes the cross-cutting
# capabilities; collection READ scope is computed per-user from role + scopes.
_USER_ROLES = ("owner", "manager", "staff", "field_crew")

# Per-role capabilities that are NOT per-collection (those come from scopes):
#   read_all_role_scopes : owner sees every role:* collection regardless of scopes
#   read_others_private  : owner may read any user:* collection
#   can_write            : may write/index (subject to per-collection rules in _can_index)
#   is_admin             : may use Admin-tab/user-management tools
_ROLE_CAPS = {
    "owner":      {"read_all_role_scopes": True,  "read_others_private": True,
                   "can_write": True,  "is_admin": True},
    "manager":    {"read_all_role_scopes": False, "read_others_private": False,
                   "can_write": True,  "is_admin": False},
    "staff":      {"read_all_role_scopes": False, "read_others_private": False,
                   "can_write": False, "is_admin": False},
    "field_crew": {"read_all_role_scopes": False, "read_others_private": False,
                   "can_write": False, "is_admin": False},
}

_SHARED_COLLECTION = "shared"


def _role_caps(role: str) -> dict:
    """Capabilities for a role; unknown roles get the most-restricted set."""
    return _ROLE_CAPS.get((role or "").strip().lower(), _ROLE_CAPS["field_crew"])


def _resolve_user(users_data: "dict | None", token: str) -> "dict | None":
    """Look up a bearer token in users.json data. Returns the user dict
    (augmented with 'id') if found AND active, else None. PURE.

    A non-active status ('suspended'/'revoked') resolves to None — a soft-revoke
    that denies access without losing the audit record. Matches §6.4 steps 1-2.
    """
    if not token or not users_data:
        return None
    users = users_data.get("users", {})
    entry = users.get(token)
    if not isinstance(entry, dict):
        return None
    if entry.get("status", "active") != "active":
        return None
    # Return a shallow copy with the id folded in, so callers have everything.
    user = dict(entry)
    user["id"] = token
    # Normalize role to the known set (defense against a hand-edited users.json).
    if user.get("role") not in _USER_ROLES:
        user["role"] = "field_crew"
    return user


def _current_user(ctx) -> "dict | None":
    """Extract the authenticated user that server-mode auth middleware attached
    to this request, via the FastMCP Context. Returns None in personal mode
    (no server-mode middleware, so no user on request.state) or if anything in
    the chain is absent. PURE-ish (only reads ctx; no other I/O). Never raises.

    The access path (ctx.request_context.request.state.user) was confirmed
    against the live FastMCP version by the Step-2 context probe: the auth
    middleware sets request.state.user, and FastMCP exposes the genuine
    per-call Starlette Request here — so this is the safe per-request identity,
    not ambient/thread-local state.
    """
    if ctx is None:
        return None
    try:
        return getattr(ctx.request_context.request.state, "user", None)
    except Exception:
        return None


def _allowed_collections(user: "dict | None",
                         all_role_collections: "list | tuple | None" = None) -> list:
    """Compute the ordered list of ChromaDB collections this user may READ.
    PURE. Implements §6.4 step 5 / §6.2.

    Args:
        user: a resolved user dict (from _resolve_user), or None.
        all_role_collections: the full set of existing 'role:<name>' collection
            names on this server. Only consulted for owners (who read ALL
            role-scoped collections regardless of their own scopes). For
            non-owners, scopes alone decide.

    Returns a de-duplicated list:
        - always 'shared'
        - each 'role:<scope>' the user is entitled to
        - 'user:<id>' iff private_collection_enabled
    None user → [] (no token resolved → no access; the middleware 401s earlier).
    """
    if not user:
        return []

    cols = [_SHARED_COLLECTION]
    caps = _role_caps(user.get("role"))

    if caps["read_all_role_scopes"] and all_role_collections:
        # Owner: every role collection on the server.
        for c in all_role_collections:
            if c and c not in cols:
                cols.append(c)
    else:
        # Everyone else: only their assigned scopes (which are already
        # 'role:<name>' strings per the users.json schema).
        for scope in (user.get("scopes") or []):
            s = str(scope).strip()
            if not s:
                continue
            # Tolerate either 'role:sales' or bare 'sales' in the data.
            col = s if s.startswith("role:") else f"role:{s}"
            if col not in cols:
                cols.append(col)

    # Per-user private collection.
    if user.get("private_collection_enabled"):
        priv = f"user:{user.get('id')}"
        if priv not in cols:
            cols.append(priv)

    return cols


def _can_index(user: "dict | None", target_collection: str,
               all_role_collections: "list | tuple | None" = None) -> tuple:
    """Decide whether `user` may INDEX (write) into `target_collection`. PURE.
    Implements §6.5. Returns (allowed: bool, reason: str).

    Rules:
      - owner: may index into ANY collection (shared, any role:*, any user:*).
      - manager: may index into role:* collections that are in their scopes,
                 and into their own private collection. NOT shared, NOT others'.
      - staff / field_crew: cannot index server-side at all.
    """
    if not user:
        return (False, "no user context")
    caps = _role_caps(user.get("role"))
    role = user.get("role")
    target = (target_collection or "").strip()
    if not target:
        return (False, "no target collection")

    if role == "owner":
        return (True, "owner may index any collection")

    if not caps["can_write"]:
        return (False, f"role '{role}' cannot index server-side")

    # manager from here on.
    if target == _SHARED_COLLECTION:
        # Option A: 'shared' is the company commons — any can_write role may
        # ADD files here (read+write for everyone who can write server-side).
        # The chunk-ownership gate (_can_purge_chunks) still protects each file:
        # you own what you add, only you (+ owner/admin custody) may modify or
        # delete it, and the owner's posted files (e.g. safety manual) can't be
        # clobbered by anyone else.
        return (True, "shared is the company commons — any writer may add")

    if target.startswith("user:"):
        if target == f"user:{user.get('id')}":
            return (True, "own private collection")
        return (False, "cannot index another user's private collection")

    if target.startswith("role:"):
        scopes = set()
        for s in (user.get("scopes") or []):
            s = str(s).strip()
            scopes.add(s if s.startswith("role:") else f"role:{s}")
        if target in scopes:
            return (True, "assigned role scope")
        return (False, "role scope not assigned to this manager")

    return (False, "unrecognized collection type")


# ── Multi-collection result merge (v7.0.0 Phase B Step 2 read path) ───────────
# After a server-mode read tool queries the user's N _allowed_collections, it
# gets N separate ChromaDB result sets. This merges them into ONE ranked list,
# the final step of the read-enforcement flow. PURE — no ChromaDB, no I/O — so
# it's unit-testable in isolation.
#
# ChromaDB query() returns parallel lists per collection: ids, documents,
# metadatas, distances (LOWER distance = more similar). We flatten all hits,
# tag each with its source collection, dedup by id (defensive — collections are
# disjoint so dupes shouldn't occur, but a chunk indexed into two scopes would),
# sort by distance ascending, and truncate to n_results.
def _merge_collection_results(per_collection: "dict", n_results: int = 10) -> list:
    """Merge per-collection ChromaDB query results into one ranked list. PURE.

    Args:
        per_collection: {collection_name: chroma_result_dict}, where each
            chroma_result_dict has the shape ChromaDB query() returns:
            {"ids": [[...]], "documents": [[...]], "metadatas": [[...]],
             "distances": [[...]]}  (each value is a list-of-lists; we use [0]).
            A value may also be the already-unwrapped single-query form
            {"ids": [...], ...} — both are tolerated.
        n_results: max hits to return after merge.

    Returns a list of dicts sorted by distance ascending (best first):
        {"id", "document", "metadata", "distance", "collection"}
    Hits missing a distance sort last (treated as +inf). Malformed entries are
    skipped, never raised on.
    """
    merged = []
    seen_ids = set()

    for cname, res in (per_collection or {}).items():
        if not isinstance(res, dict):
            continue

        def _col(key):
            """Pull a column, unwrapping Chroma's list-of-lists if present."""
            v = res.get(key)
            if v is None:
                return []
            # list-of-lists (multi-query shape) → take first query's row
            if isinstance(v, list) and len(v) == 1 and isinstance(v[0], list):
                return v[0]
            return v if isinstance(v, list) else []

        ids       = _col("ids")
        docs      = _col("documents")
        metas     = _col("metadatas")
        distances = _col("distances")

        for i, _id in enumerate(ids):
            if _id is None:
                continue
            if _id in seen_ids:
                continue           # dedup across collections
            seen_ids.add(_id)
            dist = distances[i] if i < len(distances) and distances[i] is not None else float("inf")
            try:
                dist = float(dist)
            except (TypeError, ValueError):
                dist = float("inf")
            merged.append({
                "id":         _id,
                "document":   docs[i]  if i < len(docs)  else "",
                "metadata":   metas[i] if i < len(metas) else {},
                "distance":   dist,
                "collection": cname,
            })

    merged.sort(key=lambda h: h["distance"])
    if n_results and n_results > 0:
        merged = merged[:n_results]
    return merged


# ── Model B: path → collection resolver (v7.0.0 Phase B Step 2 write path) ─────
# Decides which ChromaDB collection an indexed file belongs to, from a
# CONFIGURED path→collection map (the owner declares it once; assignment is an
# auditable config artifact, not per-index human judgment). PURE — no I/O — so
# it is unit-testable. The pipeline surgery that CALLS this (inside
# index_directory / index_file_list) is a separate, keyboard-tested step.
#
# mapping shape (from config, e.g. users.json or a company collection_map):
#   {"rules": [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
#              {"prefix": "C:/CompanyDocs/Public", "collection": "shared"}],
#    "default_collection": "shared"}   # optional; see fallback below
#
# Matching: longest matching prefix wins (most specific rule), case-insensitive,
# slash-agnostic. No rule + no default → the indexer's OWN private collection
# (user:<id>) — the safe fallback: an unclassified doc goes to the indexer's
# own space, NEVER accidentally to shared.
def _normalize_path_for_match(p: str) -> str:
    """Lowercased, forward-slashed, trailing-slash-free path for prefix match."""
    s = (p or "").replace("\\", "/").strip()
    s = s.rstrip("/")
    return s.lower()


def _resolve_collection_for_path(filepath: str, mapping: "dict | None",
                                 indexer_user: "dict | None" = None) -> str:
    """Return the target collection name for `filepath`. PURE.

    Args:
        filepath:     the file being indexed.
        mapping:      {"rules": [{"prefix","collection"}...],
                       "default_collection": "..."}  (may be {} / None).
        indexer_user: resolved user dict (for the user:<id> fallback). May be
                      None in personal mode — then the ultimate fallback is the
                      single default 'documents' collection (personal behavior).

    Resolution order:
      1. Longest matching prefix rule wins.
      2. Else mapping['default_collection'] if set.
      3. Else indexer's own 'user:<id>' (if a user is known).
      4. Else 'documents' (personal/Home single-collection default).
    """
    fp = _normalize_path_for_match(filepath)

    best_collection = None
    best_len = -1
    for rule in ((mapping or {}).get("rules") or []):
        if not isinstance(rule, dict):
            continue
        prefix = _normalize_path_for_match(rule.get("prefix", ""))
        coll   = str(rule.get("collection", "")).strip()
        if not prefix or not coll:
            continue
        # Prefix match on a path-segment boundary: either exact, or followed
        # by '/', so '.../Sales' doesn't spuriously match '.../SalesArchive'.
        if fp == prefix or fp.startswith(prefix + "/"):
            if len(prefix) > best_len:
                best_len = len(prefix)
                best_collection = coll

    if best_collection:
        return best_collection

    default_coll = str((mapping or {}).get("default_collection", "")).strip()
    if default_coll:
        return default_coll

    if indexer_user and indexer_user.get("id"):
        return f"user:{indexer_user['id']}"

    # Personal/Home single-collection default.
    return "documents"


def _company_collection_map(users_data: "dict | None" = None) -> dict:
    """Return the company path→scope mapping from users.json's top-level
    'collection_map' key, or {} if absent/malformed. Shape:
      {"rules": [{"prefix","collection"}...], "default_collection": "..."}
    PURE given users_data; loads users.json if not supplied."""
    if users_data is None:
        users_data = _load_users()
    if not isinstance(users_data, dict):
        return {}
    cm = users_data.get("collection_map")
    return cm if isinstance(cm, dict) else {}


def _build_collection_resolver(user: "dict | None", users_data: "dict | None" = None):
    """Build a collection_resolver(filepath)->logical_collection_name for the
    given indexing user (v7.0.0 Phase B write-side activation). Returns None in
    personal mode (no user) so the index pipeline keeps its single-'documents'
    behavior untouched.

    Resolution (via the tested _resolve_collection_for_path):
      1. company path→scope rules (collection_map.rules) — longest-prefix match
      2. else the user's own 'index_target' default scope (if set in users.json)
      3. else the user's own private 'user:<id>' (safe fallback — never shared)

    IMPORTANT: this only PROPOSES a target. The index tool MUST still gate the
    proposed target with _can_index(user, target) before writing, so a path rule
    can never let a user write somewhere they're not permitted. Routing decides
    WHERE; _can_index decides WHETHER.
    """
    if user is None:
        return None  # personal mode — no resolver, single 'documents' collection

    company_map = _company_collection_map(users_data)
    # Compose the mapping the resolver expects: company rules + this user's
    # default scope as the mapping default (per-user override of the global one).
    mapping = {"rules": list((company_map or {}).get("rules") or [])}
    user_default = str(user.get("index_target", "")).strip()
    if user_default:
        mapping["default_collection"] = user_default
    elif company_map.get("default_collection"):
        mapping["default_collection"] = company_map["default_collection"]

    def _resolver(filepath):
        target = _resolve_collection_for_path(filepath, mapping, indexer_user=user)
        # WHETHER-gate: the factory PROPOSES a target (WHERE); enforce _can_index
        # (WHETHER) here so a path rule can never land a write in a collection the
        # user isn't permitted to write to. On denial, degrade to the user's own
        # private collection — the always-safe target (you may always write your
        # own). This keeps indexing from silently leaking into a forbidden scope.
        try:
            allowed, _why = _can_index(user, target)
        except Exception:
            allowed = False
        if allowed:
            return target
        own_private = f"user:{user.get('id')}" if user.get("id") else "documents"
        return own_private
    return _resolver


# ── Admin role gate (§9.1 / spec item 9) ──────────────────────────────────────
# Admin MCP tools (add_user, revoke_user, view_audit_log, ...) are owner-only.
# This is the PURE decision the @requires_role gate / middleware will call.
def _user_has_role(user: "dict | None", required_role: str) -> bool:
    """True iff the resolved user holds exactly `required_role`. PURE.
    A None user (unauthenticated) never satisfies a role requirement."""
    if not user:
        return False
    return (user.get("role") or "").strip().lower() == required_role.strip().lower()


def _is_admin(user: "dict | None") -> bool:
    """True iff the user may use admin/user-management tools. PURE.
    Currently only 'owner' is admin (§6.1 matrix)."""
    if not user:
        return False
    return bool(_role_caps(user.get("role")).get("is_admin"))


# ── Audit log (§6.6 / spec item 11) — pure format + filter helpers ────────────
# The audit log records {timestamp, user, tool, collection} per request, plus
# named events like 'remote_support_enabled'. These two helpers are the pure
# surface; the actual append (one JSONL line per entry) and the Admin-tab table
# rendering are thin I/O built at the keyboard. Kept deliberately small.
def _format_audit_entry(user: "dict | None", tool: str,
                        collection: str = "", event: str = "",
                        now=None) -> dict:
    """Build one audit record. PURE (except reading the clock when now is None).
    Records only tool name + collection — no query content or results (§6.6:
    'read-only, no detail beyond tool name and collection')."""
    import datetime as _dt
    if now is None:
        now = _dt.datetime.now(_dt.timezone.utc)
    return {
        "ts":         now.isoformat(),
        "user_id":    (user or {}).get("id", ""),
        "user_name":  (user or {}).get("name", ""),
        "role":       (user or {}).get("role", ""),
        "tool":       tool or "",
        "collection": collection or "",
        "event":      event or "",
    }


def _filter_audit_entries(entries: "list | None", limit: int = 20,
                          since=None) -> list:
    """Return the most recent `limit` entries, optionally only those at/after
    `since` (a datetime or ISO string). PURE. Newest-last input is assumed
    (append order); returns newest-last, trimmed to `limit`."""
    import datetime as _dt
    rows = list(entries or [])

    if since is not None:
        if isinstance(since, str):
            try:
                s = since.strip().replace("Z", "+00:00")
                since = _dt.datetime.fromisoformat(s)
                if since.tzinfo is None:
                    since = since.replace(tzinfo=_dt.timezone.utc)
            except Exception:
                since = None

    def _ts(row):
        try:
            s = str(row.get("ts", "")).strip().replace("Z", "+00:00")
            d = _dt.datetime.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=_dt.timezone.utc)
            return d
        except Exception:
            return None

    if since is not None:
        rows = [r for r in rows if (_ts(r) is not None and _ts(r) >= since)]

    if limit and limit > 0:
        rows = rows[-limit:]
    return rows


# ══════════════════════════════════════════════════════════════════════════════
# SERVER MODE — multi-user HTTP transport  (v7.0.0 Phase B Block 3, spec §5.1/§6.4)
# ══════════════════════════════════════════════════════════════════════════════
# Business "company server" transport. Differs from _run_http (single shared
# token) by authenticating EACH request against users.json: bearer token →
# _resolve_user() → request.state.user, 401 on unknown/suspended. This is
# STEP 1 — the AUTHENTICATION layer only. Per-user ChromaDB COLLECTION SCOPING
# (using _allowed_collections / _can_index) is STEP 2, wired into the tools
# next; until then a logged warning makes clear data is not yet user-scoped.
#
# SAFETY: only reached when config.json mode=server. If prerequisites are
# missing (no users.json, deps unavailable) it FALLS BACK to _run_http so a
# server install is never left with no transport. _run_http itself is untouched.
_USERS_JSON_PATH = _state_dir() / "users.json"


def _load_users() -> "dict | None":
    """Load users.json. Returns the parsed dict, or None if missing/unreadable
    (caller treats None as 'server mode not provisioned')."""
    try:
        if _USERS_JSON_PATH.exists():
            # utf-8-sig: tolerate a BOM (PowerShell Out-File / some editors add
            # one). Reads correctly whether or not a BOM is present.
            data = json.loads(_USERS_JSON_PATH.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and isinstance(data.get("users"), dict):
                return data
            _log.error("users.json present but malformed (no 'users' map).")
            return None
    except Exception as _e:
        _log.error("users.json unreadable: %s", _e)
    return None


def _owner_user_id(users_data: "dict | None" = None) -> "str | None":
    """Return the user id (token) of the OWNER from users.json, or None if no
    owner is defined / users.json absent. Used to PROTECT the owner's private
    collection from admins (can_manage_users grants read of all OTHER users'
    privates, but never the owner's). If multiple owners exist (unusual), the
    first found is returned. PURE given users_data; loads it if not supplied."""
    if users_data is None:
        users_data = _load_users()
    if not users_data:
        return None
    for uid, entry in (users_data.get("users") or {}).items():
        if isinstance(entry, dict) and (entry.get("role") or "").strip().lower() == "owner":
            return uid
    return None


def _can_manage_user_data(actor: "dict | None", target_user_id: str,
                          owner_id: "str | None") -> tuple:
    """Decide whether `actor` may DELETE / clean up the data of target_user_id.
    PURE. Guards the (future) Admin-tab data-management / departed-employee
    cleanup operation — NOT yet wired to any delete op, encoded now + tested.

    Rules (FAIL CLOSED on the owner-protection — never destroy owner data on a
    guess):
      • The owner may manage anyone's data (including their own).
      • An admin (can_manage_users, not owner) may manage any EMPLOYEE's data
        but NEVER the owner's. If the owner's id cannot be determined
        (owner_id is None/empty), an admin is DENIED — we will not risk
        deleting owner data we cannot rule out.
      • Anyone else: no management rights.
    Returns (allowed: bool, reason: str).
    """
    if not actor:
        return (False, "no actor")
    if _user_has_role(actor, "owner"):
        return (True, "owner may manage any data")
    if not actor.get("can_manage_users"):
        return (False, "actor lacks can_manage_users")
    # Admin from here. Owner data is protected — and we FAIL CLOSED: if we can't
    # identify the owner, we cannot prove the target isn't the owner, so deny.
    if not owner_id:
        return (False, "owner id unknown — refusing to risk owner data (fail closed)")
    if target_user_id == owner_id:
        return (False, "owner data is protected from admins")
    return (True, "admin may manage employee data")


# ── Chunk-ownership purge gate (v7.0.0 Phase B — "delete only your own") ───────
# Filesystem-style protection against a bad actor wiping others' data: every
# indexed chunk carries indexed_by=<user_id>. Before the index pipeline PURGES
# existing chunks for a path (the delete(where=filepath) that precedes every
# re-add), this gate checks the actor may remove every owner present. PURE.
_OWNERLESS = "__ownerless__"  # sentinel for legacy chunks lacking indexed_by


def _chunk_owners(existing_metadatas: "list | None") -> set:
    """Distinct indexed_by owners across the given chunk metadatas. Chunks with
    no indexed_by map to the _OWNERLESS sentinel. PURE."""
    owners = set()
    for meta in (existing_metadatas or []):
        if not isinstance(meta, dict):
            continue
        owners.add(str(meta.get("indexed_by") or _OWNERLESS))
    return owners


def _can_purge_chunks(actor: "dict | None", existing_metadatas: "list | None",
                      owner_id: "str | None") -> tuple:
    """May `actor` purge/overwrite the given existing chunks? PURE.

    Rule (filesystem-like): you may purge chunks you OWN; an owner/admin may
    purge employees' chunks (subject to owner-data protection in
    _can_manage_user_data); legacy chunks with no indexed_by are treated as
    manageable only by owner/admin (a normal user can't wipe un-owned data).

    • No existing chunks (empty/None) → allowed (pure add, nothing destroyed).
    • Else: allowed iff the actor can manage EVERY distinct owner present.
      For each owner X present, require _can_manage_user_data(actor, X, owner_id);
      ownerless legacy chunks require actor to be owner/admin.
    Returns (allowed: bool, reason: str).
    """
    if not actor:
        return (False, "no actor")
    owners = _chunk_owners(existing_metadatas)
    if not owners:
        return (True, "no existing chunks to purge")

    actor_id = actor.get("id")
    for owner in owners:
        if owner == _OWNERLESS:
            # Legacy/un-owned: only owner/admin (manage rights over *anyone*) may
            # purge. Reuse _can_manage_user_data against a non-owner placeholder
            # so a plain user is denied but owner/admin allowed.
            allowed, _ = _can_manage_user_data(actor, "__legacy__", owner_id)
            if not allowed:
                return (False, "contains chunks with no owner (legacy) — only "
                               "owner/admin may purge")
            continue
        if owner == actor_id:
            continue  # you always may purge your own
        allowed, reason = _can_manage_user_data(actor, owner, owner_id)
        if not allowed:
            return (False, f"contains chunks owned by another user ({reason})")
    return (True, "actor may purge all present owners")


def _run_server_mode(port: int, token: str,
                     public_base: str = "https://mobile.dvavro-ai-prowler.com") -> None:
    """Multi-user server transport. STEP 1: authentication layer.

    Falls back to _run_http() if server mode can't be established, so a
    misconfigured Business server still serves (single-user) rather than dying.
    """
    users_data = _load_users()
    if users_data is None:
        _log.error(
            "Server mode requested but ~/.ai-prowler/users.json is missing or "
            "malformed. Falling back to single-user HTTP transport. Create the "
            "first owner user via the Admin tab to enable multi-user mode.")
        return _run_http(port=port, token=token, public_base=public_base)

    try:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse, PlainTextResponse
        from starlette.routing import Route, Mount
        from starlette.requests import Request
    except ImportError as _ie:
        _log.error("Server mode needs uvicorn/starlette (%s). Falling back.", _ie)
        return _run_http(port=port, token=token, public_base=public_base)

    n_users = len(users_data.get("users", {}))
    company = users_data.get("company_id", "<unknown>")
    _log.info("Server mode: company=%s, %d user(s) loaded from users.json",
              company, n_users)

    # ── FastMCP ASGI app ──────────────────────────────────────────────────────
    # FastMCP exposes a streamable-http ASGI app mounted at /mcp.
    try:
        mcp_asgi = mcp.streamable_http_app()
    except Exception as _e:
        _log.error("Could not get FastMCP ASGI app (%s). Falling back.", _e)
        return _run_http(port=port, token=token, public_base=public_base)

    # ── Pure-ASGI multi-user router (spec §6.4 steps 1-4) ─────────────────────
    # CRITICAL: this is a raw ASGI app, NOT BaseHTTPMiddleware. BaseHTTPMiddleware
    # buffers responses and breaks the MCP streamable-HTTP SSE transport (that was
    # the POST /mcp 500). This mirrors _run_http's proven _RouterASGI pattern:
    #   1. /health, /whoami, /.well-known/* handled inline (plain JSON, no auth
    #      except /whoami which needs the user).
    #   2. every other path: bearer → _resolve_user → stash the user in
    #      scope["state"] so FastMCP's Request(scope).state.user resolves it
    #      (this is what _current_user(ctx) reads inside the tools — the keystone),
    #      then inject the MCP headers (Accept/Content-Type/Host/MCP-Protocol-
    #      Version) exactly like _run_http, then stream to mcp_asgi WITHOUT
    #      buffering so SSE works.
    _local_host = f"127.0.0.1:{port}".encode()

    async def _send_json(send, status, payload):
        import json as _json
        body = _json.dumps(payload).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def _send_text(send, status, text):
        body = text.encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    def _bearer_from_scope(scope):
        for hk, hv in scope.get("headers", []):
            if hk.lower() == b"authorization":
                v = hv.decode("utf-8", "replace")
                if v.lower().startswith("bearer "):
                    return v[7:].strip()
        return ""

    class _ServerRouterASGI:
        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                # lifespan/websocket — pass straight through to FastMCP.
                await mcp_asgi(scope, receive, send)
                return

            path = scope.get("path", "")
            method = scope.get("method", "GET")

            # Exempt: health + OAuth discovery (no auth).
            if path == "/health":
                await _send_text(send, 200, "OK")
                return
            if path.startswith("/.well-known/"):
                await mcp_asgi(scope, receive, send)
                return

            # Authenticate every other path.
            tok = _bearer_from_scope(scope)
            if not tok:
                await _send_json(send, 401, {"error": "missing bearer token"})
                return
            user = _resolve_user(users_data, tok)
            if user is None:
                _log.info("Auth rejected for token …%s on %s",
                          tok[-4:] if tok else "", path)
                await _send_json(send, 401, {"error": "invalid or revoked token"})
                return

            # Stash the user where FastMCP's Request(scope).state will expose it.
            # Starlette's Request.state is backed by scope["state"]; setting it
            # here is what makes _current_user(ctx) resolve the right user inside
            # the tools over HTTP (the keystone).
            scope = dict(scope)
            state = dict(scope.get("state") or {})
            state["user"] = user
            state["allowed_collections"] = _allowed_collections(user)
            scope["state"] = state
            _log.debug("Authenticated user=%s role=%s", user.get("id"),
                       user.get("role"))

            # /whoami diagnostic (now reports scoping_active=True — tools scope).
            if path == "/whoami":
                await _send_json(send, 200, {
                    "user_id": user.get("id"), "name": user.get("name"),
                    "role": user.get("role"),
                    "allowed_collections": state["allowed_collections"],
                    "scoping_active": True,
                })
                return

            # ── MCP header injection (mirrors _run_http; required by FastMCP's
            #    streamable_http_app validators) ────────────────────────────────
            if path == "/mcp" or path.startswith("/mcp"):
                headers = list(scope.get("headers", []))

                def _has(name, frag):
                    return any(hk.lower() == name and frag in hv.lower()
                               for hk, hv in headers)

                def _set(name, value):
                    for i, (hk, hv) in enumerate(headers):
                        if hk.lower() == name:
                            headers[i] = (name, value); return
                    headers.append((name, value))

                if method == "POST":
                    if not _has(b"content-type", b"application/json"):
                        _set(b"content-type", b"application/json")
                    if not _has(b"accept", b"text/event-stream"):
                        _set(b"accept", b"application/json, text/event-stream")
                elif method == "GET":
                    if not _has(b"accept", b"text/event-stream"):
                        _set(b"accept", b"text/event-stream")

                # Host rewrite + MCP-Protocol-Version (FastMCP validators).
                _set(b"host", _local_host)
                if not any(hk.lower() == b"mcp-protocol-version"
                           for hk, hv in headers):
                    _set(b"mcp-protocol-version", b"2025-03-26")

                scope["headers"] = headers

            # Stream to FastMCP WITHOUT buffering (SSE-safe).
            await mcp_asgi(scope, receive, send)

    app = _ServerRouterASGI()

    _log.info("Server mode (multi-user, scoped) listening on port %d", port)
    _log.info("Pure-ASGI router active — SSE-safe, per-user ctx scoping live.")
    uvicorn.run(app, host="0.0.0.0", port=port,
                proxy_headers=True, forwarded_allow_ips="*", log_config=None)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP transport with Bearer-token auth (launched by GUI or manually)
# ══════════════════════════════════════════════════════════════════════════════

def _run_http(port: int, token: str, public_base: str = "https://mobile.dvavro-ai-prowler.com") -> None:
    """
    Run the MCP server over HTTP with OAuth 2.0 + PKCE authentication.

    Claude.ai custom connectors require OAuth — they first fetch
    /.well-known/oauth-authorization-server to discover auth endpoints,
    then redirect the user to /authorize where they enter the Bearer token,
    then exchange the auth code for an access token at /token.
    Subsequent MCP requests use the returned access token as a Bearer token.

    The server binds to 127.0.0.1 only.  Cloudflare Tunnel provides the
    public HTTPS endpoint.
    """
    try:
        import uvicorn
        import hashlib
        import base64
        import urllib.parse
        from starlette.applications import Starlette
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import PlainTextResponse, JSONResponse, HTMLResponse, RedirectResponse
        from starlette.routing import Route, Mount
        from starlette.requests import Request
    except ImportError as _ie:
        print(f"ERROR: {_ie}\nRun: pip install uvicorn", file=sys.stderr)
        sys.exit(1)

    if not token:
        print("ERROR: --token is required for HTTP transport.", file=sys.stderr)
        sys.exit(1)

    # ══════════════════════════════════════════════════════════════════════════
    # SUBSCRIPTION REGISTRY
    # ══════════════════════════════════════════════════════════════════════════
    # The user's Bearer token NEVER changes between billing periods.
    # Subscription validity is managed server-side in a subs.json file that
    # only David controls, hosted on a private GitHub repo.
    #
    # Check schedule:
    #   • On startup — fetch and cache the registry
    #   • Every 30 days — re-fetch silently in a background thread
    #   • If fetch fails — use cached copy; allow up to 30 days on stale cache
    #
    # Grace / warning periods:
    #   • Subscription expires → 30-day WARNING period begins
    #     - Server stays running
    #     - Login page shows a friendly renewal banner
    #     - Log shows daily warnings
    #   • 30 days after expiry (GRACE_DAYS) → access BLOCKED
    #     - Server refuses to start (if caught at startup)
    #     - /authorize page shows expiry notice instead of login form
    #
    # subs.json format (hosted on GitHub):
    # {
    #   "subscribers": {
    #     "<sha256_first_16_of_token>": {
    #       "name":    "Acme Corp",
    #       "expires": "2026-04-16",
    #       "plan":    "individual"
    #     }
    #   }
    # }
    # The token itself is never stored — only a short hash is used as the
    # lookup key, so the file leaks no credentials even if publicly visible.
    # ══════════════════════════════════════════════════════════════════════════

    import hashlib    as _hashlib
    import datetime   as _dt
    import threading  as _threading

    _SUBS_CACHE        = Path.home() / "AppData" / "Local" / "AI-Prowler" / "subs_cache.json"
    _CHECK_INTERVAL_DAYS = 30   # re-fetch registry every 30 days
    _WARN_DAYS           = 30   # show renewal warning this many days before / after expiry
    _GRACE_DAYS          = 30   # block access this many days AFTER expiry

    _SUBS_RAW_URL = (
        "https://raw.githubusercontent.com/dvavro/ai-prowler-subs/main/subs.json"
    )

    # ── EDITION / MODE helpers (v7.0.0) ───────────────────────────────────────
    # _plan_to_edition, _load_runtime_config, _enforce_edition_mode and the
    # edition/mode constants were HOISTED to module level (just before
    # _run_http) so the test suite can call them directly. The bare-name calls
    # below resolve to those module-level definitions. See the module-level
    # block and PHASE_A_PRIME_TEST_PLAN.md §4.0.

    def _token_key(tok: str) -> str:
        """Short hash of token used as lookup key in subs.json."""
        return _hashlib.sha256(tok.encode()).hexdigest()[:16]

    # ── install_id (v7.0.0 — Phase A' install-id binding) ─────────────────────
    # The GUI generates ~/.ai-prowler/install_id on first launch (a 16-char
    # sha256 hash). The MCP server reads it here so the subscription check and
    # the 2-active-install rule can bind a license to specific machines. If the
    # file is missing (e.g. server started before the GUI ever ran), we generate
    # it here too so the server is self-sufficient — same format the GUI uses.
    _INSTALL_ID_PATH = Path.home() / ".ai-prowler" / "install_id"

    def _read_or_create_install_id() -> str:
        """Return this machine's install_id, creating it if absent. Never raises;
        returns '' only if the home directory itself is unwritable."""
        try:
            if _INSTALL_ID_PATH.exists():
                val = _INSTALL_ID_PATH.read_text(encoding="utf-8").strip()
                if val:
                    return val
        except Exception as _e:
            _log.warning("Could not read install_id (%s)", _e)
        # Generate — mirror the GUI's algorithm (uuid4 → sha256 → first 16 hex)
        try:
            import uuid as _uuid
            new_id = _hashlib.sha256(str(_uuid.uuid4()).encode()).hexdigest()[:16]
            _INSTALL_ID_PATH.parent.mkdir(parents=True, exist_ok=True)
            _INSTALL_ID_PATH.write_text(new_id, encoding="utf-8")
            _log.info("Generated new install_id for this machine")
            return new_id
        except Exception as _e:
            _log.warning("Could not create install_id (%s) — install-id binding disabled", _e)
            return ""

    _INSTALL_ID = _read_or_create_install_id()


    def _fetch_subs_registry() -> dict | None:
        """
        Fetch subs.json from the public GitHub registry.
        No authentication needed — the repo is public (read-only for everyone;
        only the repo owner can write via their GitHub credentials).
        Falls back to the local cache if the network is unavailable.
        """
        try:
            import requests as _req
            resp = _req.get(
                _SUBS_RAW_URL,
                headers={"User-Agent": "AI-Prowler-MCP/1.0",
                         "Cache-Control": "no-cache"},
                timeout=10,
                proxies={"http": None, "https": None})
            if resp.status_code == 200:
                _log.info("Subscription registry fetched from GitHub OK")
                return resp.json()
            _log.warning("Subscription registry fetch returned HTTP %s",
                         resp.status_code)
        except Exception as _e:
            _log.warning("Subscription registry fetch failed: %s", _e)
        return None
    def _load_cached_subs() -> tuple:
        """Returns (data_dict, cache_age_days). data_dict is None if no cache."""
        try:
            if _SUBS_CACHE.exists():
                import json as _json
                raw      = _json.loads(_SUBS_CACHE.read_text(encoding="utf-8"))
                cached_at = _dt.date.fromisoformat(raw.get("cached_at", "2000-01-01"))
                age      = (_dt.date.today() - cached_at).days
                return raw.get("data"), age
        except Exception as _e:
            _log.warning("Could not read subscription cache: %s", _e)
        return None, 999

    def _save_subs_cache(data: dict):
        try:
            import json as _json
            _SUBS_CACHE.parent.mkdir(parents=True, exist_ok=True)
            payload = {"cached_at": _dt.date.today().isoformat(), "data": data}
            _SUBS_CACHE.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as _e:
            _log.warning("Could not save subscription cache: %s", _e)

    def _check_subscription(tok: str, subs_data: dict | None) -> dict:
        """
        Returns a status dict:
          status:    "ok" | "warning" | "blocked" | "unmanaged"
          name:      subscriber name (or None)
          days_left: days until expiry (negative = days past expiry)
          message:   human-readable explanation
          banner:    HTML snippet for the login page (empty string if none needed)
          edition:   "home" | "mobile" | "business" — entitlement derived from
                     the subscriber's plan via _plan_to_edition(). Unmanaged /
                     not-found tokens get "home" (no remote-access entitlement).
        """
        if subs_data is None:
            return {"status": "unmanaged", "name": None, "days_left": None,
                    "message": "No registry — unmanaged/local mode",
                    "banner": "", "edition": "home"}

        key         = _token_key(tok)
        subscribers = subs_data.get("subscribers", {})

        if key not in subscribers:
            # Token not in registry — treat as local/unmanaged, not an error
            return {"status": "unmanaged", "name": None, "days_left": None,
                    "message": "Token not in managed registry — local mode",
                    "banner": "", "edition": "home"}

        entry    = subscribers[key]
        name     = entry.get("name", "Subscriber")
        _edition = _plan_to_edition(entry.get("plan", ""))
        exp_str  = entry.get("expires", "")
        try:
            expiry = _dt.date.fromisoformat(exp_str)
        except ValueError:
            return {"status": "unmanaged", "name": name, "days_left": None,
                    "message": f"Invalid expiry date for {name}",
                    "banner": "", "edition": "home"}

        today     = _dt.date.today()
        days_left = (expiry - today).days   # negative = past expiry

        if days_left >= 0:
            # Active subscription
            if days_left <= _WARN_DAYS:
                banner = (
                    f"<div style='background:#7c4a00;border-radius:6px;padding:10px 14px;"
                    f"margin-top:12px;font-size:13px;color:#ffe082;'>"
                    f"⚠️  Your remote access subscription expires in <strong>{days_left} day(s)</strong>"
                    f" ({expiry}).  "
                    f"<a href='mailto:david.vavro1@gmail.com' style='color:#ffd54f;'>Renew now →</a>"
                    f"</div>"
                )
                return {"status": "warning", "name": name, "days_left": days_left,
                        "message": f"Subscription for '{name}' expires in {days_left} day(s) ({expiry}) — renewal recommended",
                        "banner": banner, "edition": _edition}
            return {"status": "ok", "name": name, "days_left": days_left,
                    "message": f"Subscription OK — '{name}', {days_left} day(s) remaining",
                    "banner": "", "edition": _edition}

        # Past expiry
        days_over = -days_left

        if days_over <= _GRACE_DAYS:
            # WARNING period — still allowed, but banner shown
            banner = (
                f"<div style='background:#7c0000;border-radius:6px;padding:10px 14px;"
                f"margin-top:12px;font-size:13px;color:#ffcdd2;'>"
                f"🔴  Your remote access subscription <strong>expired {days_over} day(s) ago</strong>"
                f" ({expiry}).  "
                f"You have <strong>{_GRACE_DAYS - days_over} day(s)</strong> remaining before access is blocked.  "
                f"<a href='mailto:david.vavro1@gmail.com' style='color:#ff8a80;'>Renew at david.vavro1@gmail.com →</a>"
                f"</div>"
            )
            return {"status": "warning", "name": name, "days_left": days_left,
                    "message": (
                        f"SUBSCRIPTION EXPIRED {days_over} day(s) ago for '{name}' ({expiry}).  "
                        f"Grace period: {_GRACE_DAYS - days_over} day(s) remaining.  "
                        f"Renew at david.vavro1@gmail.com"
                    ),
                    "banner": banner, "edition": _edition}

        # Past grace period — BLOCKED
        return {"status": "blocked", "name": name, "days_left": days_left,
                "message": (
                    f"Remote access BLOCKED — subscription for '{name}' expired "
                    f"{days_over} day(s) ago ({expiry}) and the {_GRACE_DAYS}-day grace period has elapsed.  "
                    f"Renew at david.vavro1@gmail.com"
                ),
                "banner": "", "edition": _edition}

    # ── 2-active-install rule (v7.0.0) ────────────────────────────────────────
    # _evaluate_activation and the constants _ACTIVE_WINDOW_DAYS /
    # _MAX_ACTIVE_INSTALLS were HOISTED to module level (just before _run_http)
    # so the test suite can call the pure evaluator directly. The bare-name
    # references below resolve to those module-level definitions. See the
    # module-level block and PHASE_A_PRIME_TEST_PLAN.md §4.

    # ── D1-backed activation (v7.0.0 — Phase A' Option X, D1 variant) ─────────
    # Activations are authoritatively stored in the telemetry Worker's D1
    # database (table license_activations), NOT in subs.json. The client POSTs
    # its install_id + token HASH (never the raw token) to /license/activate and
    # the Worker returns the binding decision. If the Worker is unreachable we
    # FAIL OPEN — fall back to the local _evaluate_activation() over whatever
    # activations subs.json may carry, and ultimately allow access. This mirrors
    # the 14-day cached-validation grace philosophy: a network blip must never
    # lock out a paying customer.
    _TELEMETRY_DEFAULT_ENDPOINT = "https://ai-prowler-telemetry.david-vavro1.workers.dev"

    def _activation_endpoint() -> str:
        """Resolve the Worker base URL (config override or default), no trailing slash."""
        base = _TELEMETRY_DEFAULT_ENDPOINT
        try:
            ep = (_runtime_cfg_for_endpoint or {}).get("telemetry_endpoint", "")
            if ep:
                base = str(ep)
        except Exception:
            pass
        return base.rstrip("/")

    def _post_activation(license_hash: str, install_id: str,
                         os_str: str, version: str) -> dict | None:
        """POST to the Worker's /license/activate. Returns the parsed decision
        dict on success, or None on any failure (caller falls back to local)."""
        if not install_id or not license_hash:
            return None
        url = f"{_activation_endpoint()}/license/activate"
        payload = {
            "license_key_hash": license_hash,
            "install_id":       install_id,
            "os":               os_str,
            "version":          version,
        }
        try:
            import requests as _req
            resp = _req.post(
                url, json=payload,
                headers={"User-Agent": "AI-Prowler-MCP/1.0",
                         "Content-Type": "application/json"},
                timeout=10,
                proxies={"http": None, "https": None})
            if resp.status_code == 200:
                data = resp.json()
                _log.info("D1 activation decision=%s (%s of %s active)",
                          data.get("decision"), data.get("active_count"),
                          data.get("max_active"))
                return data
            _log.warning("Activation endpoint returned HTTP %s", resp.status_code)
        except Exception as _e:
            _log.warning("Activation endpoint unreachable (%s) — failing open", _e)
        return None

    # Pulled out so _activation_endpoint can see the loaded config without a
    # forward reference; populated just before the activation call below.
    _runtime_cfg_for_endpoint = None

    # ── Perform initial subscription check on startup ─────────────────────────
    if _test_entitlement_active():
        # TEST ENTITLEMENT SHORT-CIRCUIT (pre-release validation only). Both the
        # env var AND config.json "test_mode": true are set (dev/test launch).
        # Skip the network subscription/license/activation calls and substitute
        # a known-good verdict so the suite can exercise the REAL auth + scoping
        # + ownership code against the sandboxed users.json. Enforcement is NOT
        # disabled — only the entitlement verdict and state-file paths are
        # sandboxed. Loud on purpose.
        _log.warning(
            "⚠️  TEST ENTITLEMENT ACTIVE — network license/subscription checks "
            "SKIPPED, entitlement sandboxed (edition=business,status=ok). "
            "State dir=%s. NOT FOR PRODUCTION.", _state_dir())
        _subs_data = None
        _sub_result = {"status": "ok", "name": "TEST", "days_left": None,
                       "edition": "business",
                       "message": "test entitlement (sandboxed; network skipped)"}
    else:
        _subs_data = _fetch_subs_registry()
        if _subs_data is not None:
            _save_subs_cache(_subs_data)
            _log.info("Subscription registry fetched from GitHub OK")
        else:
            _subs_data, _cache_age = _load_cached_subs()
            if _subs_data is not None:
                _log.warning(
                    "Using cached subscription registry (%d days old, max cache age: %d days)",
                    _cache_age, _CHECK_INTERVAL_DAYS + _GRACE_DAYS
                )
            else:
                _log.warning(
                    "No subscription registry available (no internet + no cache).  "
                    "Starting in unmanaged mode — all tokens accepted."
                )

        _sub_result = _check_subscription(token, _subs_data)
    _log.info("Startup subscription check: %s", _sub_result["message"])

    if _sub_result["status"] == "blocked":
        _log.critical("ACCESS BLOCKED: %s", _sub_result["message"])
        print(f"ERROR: {_sub_result['message']}", file=sys.stderr)
        sys.exit(1)
    elif _sub_result["status"] == "warning":
        _log.warning("SUBSCRIPTION NOTICE: %s", _sub_result["message"])

    # ── Resolve effective edition / mode (v7.0.0 — Phase A') ──────────────────
    # config.json declares the *requested* edition/mode; the subscription check
    # decides whether the token is actually entitled to it. _enforce_edition_mode
    # reconciles the two, downgrading to home/personal where the request can't be
    # honored. The subscriber's plan (via _sub_result["edition"]) is the upper
    # bound on entitlement; config.json can request equal-or-lower, never higher.
    _runtime_cfg       = _load_runtime_config()
    _requested_edition = _runtime_cfg["edition"]
    _requested_mode    = _runtime_cfg["mode"]
    _entitled_edition  = _sub_result.get("edition", "home")

    # The requested edition may not exceed what the subscription entitles.
    # Ranking: home(0) < mobile(1) < business(2). Clamp request to entitlement.
    _EDITION_RANK = {"home": 0, "mobile": 1, "business": 2}
    if _EDITION_RANK.get(_requested_edition, 0) > _EDITION_RANK.get(_entitled_edition, 0):
        _log.warning(
            "config.json requests edition=%s but subscription only entitles %s. "
            "Clamping to %s.", _requested_edition, _entitled_edition, _entitled_edition)
        _requested_edition = _entitled_edition

    _EFFECTIVE_EDITION, _EFFECTIVE_MODE = _enforce_edition_mode(
        _requested_edition, _requested_mode, _sub_result["status"])

    # ── Business license validation + grace ladder (v7.0.0 Phase B Block 2) ───
    # If we've landed on the Business edition, validate the company license key
    # against the D1 Worker (/license/validate) through the cache + grace ladder.
    # The ladder can soft-revert Business → Home on a hard fail (revoked) or
    # after the 14-day grace window of failed validations. This runs BEFORE the
    # activation rule so the activation check sees the edition that actually
    # survived license validation. The license key comes from config.json
    # ('license_key'); if absent, Business can't be validated → revert to home.
    _runtime_cfg_for_endpoint = _runtime_cfg   # let _activation_endpoint() see config (used here + by the activation rule below)
    _license_grace = {"effective_edition": _EFFECTIVE_EDITION, "action": "n/a",
                      "banner": "", "license_key_present": False}
    if _EFFECTIVE_EDITION == "business" and _test_entitlement_active():
        _log.warning("⚠️  TEST ENTITLEMENT — skipping D1 Business license "
                     "validation (network); keeping Business edition.")
    elif _EFFECTIVE_EDITION == "business":
        _lic_key = str(_runtime_cfg.get("license_key", "")).strip()
        _license_grace = _validate_business_license(
            _lic_key, _INSTALL_ID, _activation_endpoint())
        if _license_grace["effective_edition"] != "business":
            _log.warning(
                "Business license check → %s (action=%s). Reverting to Home.",
                _license_grace["effective_edition"], _license_grace["action"])
            _EFFECTIVE_EDITION = "home"
            _EFFECTIVE_MODE    = "personal"
            _sub_result = dict(_sub_result)
            _sub_result["license_reverted"] = True
            _sub_result["license_message"]  = _license_grace.get("banner", "")
        elif _license_grace.get("banner"):
            # Still Business, but a grace-period warning to surface in the GUI.
            _log.warning("Business license grace warning: %s",
                         _license_grace["banner"])
            _sub_result = dict(_sub_result)
            _sub_result["license_warning"] = _license_grace["banner"]

    # ── Per-user child-license validation (server mode only, v7.0.0) ──────────
    # When running as a company server, each active employee in users.json may
    # carry a child_license_key (their paid seat). On startup AND on the
    # natural 30-day fresh-cache rhythm of _validate_business_license, validate
    # every active user's child key against the Worker. Soft policy per David
    # 2026-05-28: REJECTIONS LOG + SHOW A BANNER, they DO NOT mutate users.json
    # and do NOT block the bearer-token auth at request time. The owner sees
    # the banner and acts via the Admin tab. The hard enforcement that matters
    # is the future-dated expires_at on the child key in D1; when it eventually
    # comes back expired, validate just keeps reporting that — the seat is
    # logically dead but service continues (white-glove model).
    #
    # The actual sweep logic lives in _sweep_child_licenses(users_doc, validate_fn)
    # so it's testable in isolation (tests pass synthetic users_doc + stubbed
    # validate_fn, no network).
    _child_warnings = []
    if (_EFFECTIVE_EDITION == "business" and _EFFECTIVE_MODE == "server"
            and not _test_entitlement_active()):
        try:
            _users_doc = _load_users() or {}
            _endpoint  = _activation_endpoint()
            _validate  = lambda k: _validate_business_license(k, _INSTALL_ID, _endpoint)
            _child_warnings = _sweep_child_licenses(_users_doc, _validate)
        except Exception as _cwerr:
            # Never let a child-key sweep block startup. Log and continue.
            _log.warning("Child-license sweep failed (%s); continuing.", _cwerr)
        # Persist the warnings (or the empty list) so the Admin tab can display
        # them. ALWAYS write — an absent file means 'sweep never ran', a present
        # file with warnings=[] means 'all clear as of last_check_at'.
        _save_license_warnings(_child_warnings)
    if _child_warnings:
        _sub_result = dict(_sub_result)
        _sub_result["child_license_warnings"] = _child_warnings

    _log.info(
        "Effective runtime: edition=%s mode=%s install_id=%s (requested edition=%s mode=%s; "
        "subscription status=%s, entitles=%s)",
        _EFFECTIVE_EDITION, _EFFECTIVE_MODE, _INSTALL_ID or "<none>",
        _runtime_cfg["edition"], _runtime_cfg["mode"],
        _sub_result["status"], _entitled_edition)

    # ── Apply the 2-active-install rule (v7.0.0 — Phase A') ───────────────────
    # Only relevant once we've cleared edition entitlement: a Home install has
    # no remote-access seat to bind, so there's nothing to enforce. For a
    # mobile/business effective edition, determine THIS machine's activation
    # standing. Authoritative source is the D1-backed Worker (/license/activate);
    # if it's unreachable we FAIL OPEN by falling back to the local evaluator
    # over subs.json activations (which may be empty), and ultimately allowing
    # access — a network blip must never lock out a paying customer.
    # A "rejected" decision → soft-revert to Home (spec §4.4 Mobile flow),
    # leaving everything else functional, and annotate _sub_result so the
    # License panel and /authorize page can surface the "release a machine" CTA.

    _activation = {"decision": "unbound", "active_install_ids": [],
                   "active_count": 0, "this_active": False, "message": ""}
    if _test_entitlement_active():
        _log.warning("⚠️  TEST ENTITLEMENT — skipping D1 activation (2-install) "
                     "check (network); treating this install as active.")
        _activation["this_active"] = True
    elif _EFFECTIVE_EDITION in ("mobile", "business"):
        # Build an OS string for the activation record.
        try:
            import platform as _platform
            _os_str = f"{_platform.system()}-{_platform.release()}"[:50]
        except Exception:
            _os_str = "unknown"
        _license_hash = _token_key(token)

        # Resolve the app version for the activation record. APP_VERSION lives
        # in rag_gui.py, not here, so read the bundled VERSION file directly
        # (same value the installer ships) with a safe fallback.
        _app_version = ""
        try:
            _ver_file = Path(__file__).resolve().parent / "VERSION"
            if _ver_file.exists():
                _app_version = _ver_file.read_text(encoding="utf-8").strip()
        except Exception:
            _app_version = ""

        # Try the authoritative D1 endpoint first.
        _d1 = _post_activation(_license_hash, _INSTALL_ID, _os_str, _app_version)
        if _d1 is not None and _d1.get("decision"):
            _activation = {
                "decision":           _d1.get("decision"),
                "active_install_ids": _d1.get("active_install_ids", []),
                "active_count":       _d1.get("active_count", 0),
                "this_active":        _d1.get("decision") == "active",
                "message":            _d1.get("message", ""),
            }
            _log.info("Activation (D1): decision=%s (%d of %d active)",
                      _activation["decision"], _activation["active_count"],
                      _MAX_ACTIVE_INSTALLS)
        else:
            # FAIL OPEN — local evaluation over subs.json activations.
            _sub_key   = _token_key(token)
            _sub_entry = (_subs_data or {}).get("subscribers", {}).get(_sub_key, {}) \
                         if _subs_data else {}
            _activation = _evaluate_activation(_sub_entry, _INSTALL_ID)
            _log.warning("Activation (local fallback): decision=%s (%d of %d active) — %s",
                         _activation["decision"], _activation["active_count"],
                         _MAX_ACTIVE_INSTALLS, _activation["message"])

        if _activation["decision"] == "rejected":
            _log.warning(
                "Install-id rejected (2-active-install cap reached). Soft-reverting "
                "to Home edition; remote access disabled on this machine.")
            _EFFECTIVE_EDITION = "home"
            _EFFECTIVE_MODE    = "personal"
            _sub_result = dict(_sub_result)
            _sub_result["activation_rejected"] = True
            _sub_result["activation_message"]  = _activation["message"]
            _sub_result["active_install_ids"]  = _activation["active_install_ids"]

    # Mutable container so background thread can update it
    _current_sub_result = [_sub_result]
    _subs_lock          = _threading.Lock()

    # ── Background 30-day registry refresh ───────────────────────────────────
    def _periodic_sub_refresh():
        import time as _time
        while True:
            _time.sleep(_CHECK_INTERVAL_DAYS * 86400)   # 30 days in seconds
            _log.info("30-day subscription registry refresh starting…")
            fresh = _fetch_subs_registry()
            if fresh is not None:
                _save_subs_cache(fresh)
                result = _check_subscription(token, fresh)
                with _subs_lock:
                    _current_sub_result[0] = result
                _log.info("Subscription re-check: %s", result["message"])
                if result["status"] == "blocked":
                    _log.critical(
                        "ACCESS NOW BLOCKED on re-check — new /authorize attempts "
                        "will show expiry page: %s", result["message"]
                    )
                elif result["status"] == "warning":
                    _log.warning("SUBSCRIPTION NOTICE: %s", result["message"])
            else:
                _log.warning(
                    "30-day registry re-fetch failed — keeping current status: %s",
                    _current_sub_result[0]["status"]
                )

    if _test_entitlement_active():
        _log.warning("⚠️  TEST ENTITLEMENT — not starting the 30-day "
                     "subscription refresh thread (would hit the network).")
    else:
        _threading.Thread(target=_periodic_sub_refresh, daemon=True).start()

    # In-memory stores for OAuth codes and issued access tokens
    # code -> {redirect_uri, code_challenge, code_challenge_method}
    _auth_codes: dict = {}
    # access_token -> True
    _access_tokens: set = set()
    # Pre-add the user's own bearer token so existing curl/manual clients still work
    _access_tokens.add(token)

    PUBLIC_BASE = public_base.rstrip("/")   # passed in from CLI / config.json

    def _get_public_base(request: Request = None, scope: dict = None) -> str:
        """Derive the public base URL dynamically from the request.

        If a Request or ASGI scope is provided, use the Host header so that
        OAuth endpoints always point back to the URL Claude is actually
        connecting through — whether that's a Named Tunnel, Quick Tunnel,
        or localhost.  Falls back to the configured PUBLIC_BASE if the
        Host header isn't available.
        """
        host = ''
        if request is not None:
            host = request.headers.get('host', '') or request.headers.get('x-forwarded-host', '')
        elif scope is not None:
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            host = (headers.get(b"host", b"")
                    or headers.get(b"x-forwarded-host", b"")).decode("utf-8", errors="ignore")
        if host:
            # Use https for any non-localhost host
            scheme = "http" if host.startswith("127.") or host.startswith("localhost") else "https"
            return f"{scheme}://{host}"
        return PUBLIC_BASE

    # ── OAuth discovery endpoints ─────────────────────────────────────────────
    async def oauth_protected_resource(request: Request):
        """RFC 9728 — OAuth 2.0 Protected Resource Metadata.
        Claude.ai fetches THIS endpoint first when it receives a 401.
        It tells Claude where the authorization server lives.
        """
        base = _get_public_base(request)
        return JSONResponse({
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
        })

    async def oauth_metadata(request: Request):
        """RFC 8414 — OAuth 2.0 Authorization Server Metadata.
        Claude.ai fetches this second, using the AS URL from above.
        """
        base = _get_public_base(request)
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
        })

    # ── Dynamic Client Registration (RFC 7591) ───────────────────────────────
    # Claude.ai POSTs here before starting the OAuth flow to register itself.
    # We accept any registration and echo back a generated client_id.
    async def register_client(request: Request):
        import secrets as _sec, time as _time
        try:
            body = await request.json()
        except Exception:
            body = {}
        client_id = _sec.token_urlsafe(16)
        return JSONResponse({
            "client_id": client_id,
            "client_id_issued_at": int(_time.time()),
            "grant_types": body.get("grant_types", ["authorization_code"]),
            "response_types": body.get("response_types", ["code"]),
            "redirect_uris": body.get("redirect_uris", []),
            "token_endpoint_auth_method": "none",
            "client_name": body.get("client_name", "Claude"),
        }, status_code=201)

    # ── Authorization endpoint ────────────────────────────────────────────────
    async def authorize(request: Request):
        """
        Show a login form.  User enters their Bearer token.
        On success, redirect back to Claude.ai with an auth code.
        """
        params = dict(request.query_params)
        redirect_uri      = params.get("redirect_uri", "")
        state             = params.get("state", "")
        code_challenge    = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "plain")

        # Get current subscription status for banner display
        with _subs_lock:
            _cur_sub = _current_sub_result[0]

        # If subscription is BLOCKED, show expiry page instead of login form
        if _cur_sub["status"] == "blocked":
            html = f"""<!DOCTYPE html>
<html>
<head>
  <title>AI-Prowler — Access Suspended</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
            display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
    .card {{ background: #16213e; border-radius: 12px; padding: 40px; width: 380px;
             box-shadow: 0 4px 24px rgba(0,0,0,0.4); text-align: center; }}
    h2 {{ margin: 0 0 8px; color: #ef5350; }}
    p  {{ color: #aaa; font-size: 14px; margin: 12px 0; line-height: 1.5; }}
    a  {{ color: #4fc3f7; }}
    .badge {{ background: #7c0000; border-radius: 6px; padding: 12px 16px;
              font-size: 13px; color: #ffcdd2; margin-top: 16px; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>🔒 Remote Access Suspended</h2>
    <p>Your AI-Prowler managed remote access subscription has expired and
       the grace period has elapsed.</p>
    <div class="badge">
      To restore access, please renew your subscription:<br><br>
      <strong><a href="mailto:david.vavro1@gmail.com">david.vavro1@gmail.com</a></strong>
    </div>
    <p style="font-size:12px;color:#555;margin-top:20px;">
      AI-Prowler desktop features continue to work normally.<br>
      Only remote / Claude.ai access requires a subscription.
    </p>
  </div>
</body>
</html>"""
            return HTMLResponse(html, status_code=403)

        if request.method == "POST":
            form = await request.form()
            entered = (form.get("token") or "").strip()
            if entered == token:
                # Generate a one-time auth code
                import secrets
                code = secrets.token_urlsafe(32)
                _auth_codes[code] = {
                    "redirect_uri": redirect_uri,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                }
                sep = "&" if "?" in redirect_uri else "?"
                target = f"{redirect_uri}{sep}code={code}&state={urllib.parse.quote(state)}"
                return RedirectResponse(url=target, status_code=302)
            else:
                error_msg = "<p style='color:red;margin-top:8px'>Incorrect token — try again.</p>"
        else:
            error_msg = ""

        # Show renewal banner if subscription is in warning period
        sub_banner = _cur_sub.get("banner", "")

        html = f"""<!DOCTYPE html>
<html>
<head>
  <title>AI-Prowler Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
            display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
    .card {{ background: #16213e; border-radius: 12px; padding: 40px; width: 360px;
             box-shadow: 0 4px 24px rgba(0,0,0,0.4); }}
    h2 {{ margin: 0 0 8px; color: #4fc3f7; }}
    p  {{ color: #aaa; font-size: 14px; margin: 0 0 24px; }}
    input {{ width: 100%; padding: 10px 12px; border-radius: 6px; border: 1px solid #333;
             background: #0f3460; color: #eee; font-size: 15px; box-sizing: border-box; }}
    button {{ margin-top: 16px; width: 100%; padding: 11px; border-radius: 6px; border: none;
              background: #4fc3f7; color: #111; font-size: 15px; font-weight: bold; cursor: pointer; }}
    button:hover {{ background: #81d4fa; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>🐾 AI-Prowler</h2>
    <p>Enter your Bearer token to connect Claude to your knowledge base.</p>
    <form method="post">
      <input type="password" name="token" placeholder="Bearer token" autofocus>
      <button type="submit">Connect</button>
    </form>
    {error_msg}
    {sub_banner}
  </div>
</body>
</html>"""
        return HTMLResponse(html)

    # ── Token endpoint ────────────────────────────────────────────────────────
    async def token_endpoint(request: Request):
        """Exchange auth code for access token."""
        try:
            form = await request.form()
        except Exception:
            form = {}
        grant_type    = form.get("grant_type", "")
        code          = form.get("code", "")
        code_verifier = form.get("code_verifier", "")

        if grant_type != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        if code not in _auth_codes:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        stored = _auth_codes.pop(code)

        # Verify PKCE if code_challenge was stored
        if stored.get("code_challenge"):
            method = stored.get("code_challenge_method", "plain")
            if method == "S256":
                digest = hashlib.sha256(code_verifier.encode()).digest()
                computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            else:
                computed = code_verifier
            if computed != stored["code_challenge"]:
                return JSONResponse({"error": "invalid_grant", "error_description": "PKCE mismatch"}, status_code=400)

        import secrets
        access_token = secrets.token_urlsafe(48)
        _access_tokens.add(access_token)

        return JSONResponse({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 31536000,  # 1 year
        })

    # ── Pure ASGI auth middleware ─────────────────────────────────────────────
    # IMPORTANT: Must NOT use BaseHTTPMiddleware here — it buffers the entire
    # response body which breaks FastMCP's Server-Sent Events streaming transport
    # causing 500 Internal Server Error on every MCP request.
    # This pure ASGI class passes bytes through directly without any buffering.
    _PUBLIC_PATHS = {"/health", "/authorize", "/token", "/register",
                     "/.well-known/oauth-authorization-server",
                     "/.well-known/oauth-protected-resource"}

    class _AuthASGI:
        """Zero-buffering ASGI auth wrapper — safe for SSE/streaming responses."""
        def __init__(self, asgi_app):
            self._app = asgi_app

        async def __call__(self, scope, receive, send):
            if scope["type"] not in ("http", "websocket"):
                await self._app(scope, receive, send)
                return

            path = scope.get("path", "")
            if path in _PUBLIC_PATHS or path.startswith("/authorize"):
                await self._app(scope, receive, send)
                return

            # Extract Authorization header from raw ASGI scope headers
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            auth_raw = headers.get(b"authorization", b"")
            auth = auth_raw.decode("utf-8", errors="ignore")
            tok  = auth[7:].strip() if auth.lower().startswith("bearer ") else ""

            if tok not in _access_tokens:
                # Return 401 — derive public base from the Host header
                # so Claude discovers OAuth endpoints at the correct URL
                _dyn_base = _get_public_base(scope=scope)
                body = b'{"error":"unauthorized","error_description":"Invalid or missing Bearer token"}'
                www_auth = (
                    f'Bearer realm="{_dyn_base}", '
                    f'resource_metadata="{_dyn_base}/.well-known/oauth-protected-resource"'
                ).encode()
                await send({"type": "http.response.start", "status": 401,
                            "headers": [
                                [b"content-type",  b"application/json"],
                                [b"content-length", str(len(body)).encode()],
                                [b"www-authenticate", www_auth],
                            ]})
                await send({"type": "http.response.body", "body": body, "more_body": False})
                return

            # Authenticated — pass straight through, no buffering
            await self._app(scope, receive, send)

    # ── Build OAuth-only routes app ──────────────────────────────────────────
    oauth_only_app = Starlette(routes=[
        Route("/health",  PlainTextResponse("OK")),
        Route("/.well-known/oauth-protected-resource",   oauth_protected_resource),
        Route("/.well-known/oauth-authorization-server", oauth_metadata),
        Route("/register",  register_client, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/token",   token_endpoint, methods=["POST"]),
    ])

    # ── Get FastMCP ASGI app ──────────────────────────────────────────────────
    # Claude.ai custom connectors use the Streamable HTTP transport (MCP spec
    # 2025-03-26): POST /mcp to send, GET /mcp to receive SSE responses.
    # streamable_http_app() implements this correctly and mounts at /mcp, so
    # no path rewriting is needed.
    # The earlier 421 errors were caused by missing proxy_headers on uvicorn —
    # that is now fixed.  sse_app() is kept as a fallback only for older mcp
    # installs that pre-date streamable_http_app().
    try:
        mcp_asgi = mcp.streamable_http_app()
        _log.info("FastMCP ASGI: using streamable_http_app() [Streamable HTTP — correct for Claude.ai]")
    except AttributeError:
        try:
            mcp_asgi = mcp.sse_app()
            _log.info("FastMCP ASGI: streamable_http_app() not found, falling back to sse_app()")
        except AttributeError:
            _log.critical("FATAL: FastMCP has neither streamable_http_app() nor sse_app(). Run: pip install --upgrade mcp")
            print("ERROR: FastMCP does not expose an ASGI app. Run: pip install --upgrade mcp",
                  file=sys.stderr)
            sys.exit(1)

    # ── Router ASGI app ───────────────────────────────────────────────────────
    # FastMCP MUST receive lifespan events to initialize its internal task group
    # (otherwise: RuntimeError "Task group is not initialized. Make sure to use run()").
    # _RouterASGI passes lifespan events to mcp_asgi, routes OAuth paths to
    # oauth_only_app, checks Bearer token, then forwards MCP paths to mcp_asgi.
    # Zero buffering — streaming/SSE responses pass through untouched.

    _OAUTH_PATHS = {"/health", "/authorize", "/token", "/register",
                    "/.well-known/oauth-authorization-server",
                    "/.well-known/oauth-protected-resource"}

    class _RouterASGI:
        async def __call__(self, scope, receive, send):
            stype = scope.get("type", "")

            # Lifespan MUST go to mcp_asgi so task group initialises
            if stype == "lifespan":
                _log.info("LIFESPAN event received — forwarding to mcp_asgi")
                await mcp_asgi(scope, receive, send)
                return

            if stype not in ("http", "websocket"):
                await oauth_only_app(scope, receive, send)
                return

            path = scope.get("path", "")
            method = scope.get("method", "?")
            _log.debug("REQUEST  %s %s", method, path)

            # OAuth / health — no auth required
            if path in _OAUTH_PATHS or path.startswith("/authorize"):
                _log.debug("ROUTE -> oauth_only_app  (%s)", path)
                await oauth_only_app(scope, receive, send)
                return

            # Everything else (including /mcp) — check Bearer token first
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            auth_raw = headers.get(b"authorization", b"")
            auth = auth_raw.decode("utf-8", errors="ignore")
            tok  = auth[7:].strip() if auth.lower().startswith("bearer ") else ""

            if tok not in _access_tokens:
                _log.warning("AUTH FAIL: no valid Bearer token for %s %s (got: '%s…')",
                             method, path, tok[:8] if tok else "<empty>")
                body = b'{"error":"unauthorized","error_description":"Invalid or missing Bearer token"}'
                www  = (f'Bearer realm="{PUBLIC_BASE}", '
                        f'resource_metadata="{PUBLIC_BASE}/.well-known/oauth-protected-resource"'
                        ).encode()
                await send({"type": "http.response.start", "status": 401,
                            "headers": [[b"content-type",  b"application/json"],
                                        [b"content-length", str(len(body)).encode()],
                                        [b"www-authenticate", www]]})
                await send({"type": "http.response.body", "body": body, "more_body": False})
                return

            # Authenticated — forward to FastMCP.
            #
            # HEADER INJECTION: streamable_http_app() (and sse_app() fallback)
            # strictly validate request headers per the MCP spec. Claude.ai's
            # custom connector does NOT send all required headers, causing 421.
            # We inject the missing headers into the ASGI scope before
            # forwarding so FastMCP's validators pass.
            #
            # Required headers per MCP Streamable HTTP spec (2025-03-26):
            #   POST /mcp: Content-Type: application/json
            #              Accept: application/json, text/event-stream
            #   GET  /mcp: Accept: text/event-stream
            #
            # Log ALL incoming headers on /mcp requests so we can see exactly
            # what Claude.ai sends (invaluable for debugging transport issues).
            if path == "/mcp":
                # Dump headers to log for diagnosis
                incoming_hdrs = scope.get("headers", [])
                _log.debug("--- HEADERS from Claude.ai (%s %s) ---", method, path)
                for hk, hv in incoming_hdrs:
                    _log.debug("  %s: %s", hk.decode("utf-8","replace"), hv.decode("utf-8","replace"))
                _log.debug("--- END HEADERS ---")

                # Shallow-copy scope so we can modify headers safely
                scope = dict(scope)
                headers = list(scope.get("headers", []))

                def _has_header(name: bytes, value_fragment: bytes) -> bool:
                    for hk, hv in headers:
                        if hk.lower() == name and value_fragment in hv.lower():
                            return True
                    return False

                def _set_header(name: bytes, value: bytes) -> None:
                    """Replace first matching header or append if absent."""
                    for i, (hk, hv) in enumerate(headers):
                        if hk.lower() == name:
                            headers[i] = (name, value)
                            return
                    headers.append((name, value))

                if method == "POST":
                    # Ensure Content-Type: application/json
                    if not _has_header(b"content-type", b"application/json"):
                        _log.debug("INJECT Content-Type: application/json")
                        _set_header(b"content-type", b"application/json")
                    # Ensure Accept includes both json and event-stream
                    if not _has_header(b"accept", b"text/event-stream"):
                        _log.debug("INJECT Accept: application/json, text/event-stream")
                        _set_header(b"accept", b"application/json, text/event-stream")

                elif method == "GET":
                    # Ensure Accept: text/event-stream
                    if not _has_header(b"accept", b"text/event-stream"):
                        _log.debug("INJECT Accept: text/event-stream")
                        _set_header(b"accept", b"text/event-stream")

                scope["headers"] = headers

            # ── Header fixes for /mcp requests ───────────────────────────────────
            # FastMCP's streamable_http_app() performs two validations that fail
            # when requests arrive via Cloudflare Tunnel:
            #
            # 1. HOST HEADER: FastMCP checks that the Host header matches the
            #    server's bound address (127.0.0.1:{port}). Cloudflare rewrites
            #    it to the public domain (mobile.dvavro-ai-prowler.com), so
            #    FastMCP rejects every request with HTTP 421 "Invalid Host header".
            #    Fix: rewrite host → 127.0.0.1:{port} before forwarding.
            #
            # 2. MCP-Protocol-Version: newer FastMCP builds require this header.
            #    Claude.ai does not send it. Fix: inject it.
            if path == "/mcp":
                scope = dict(scope)
                hdrs  = list(scope.get("headers", []))

                # Rewrite Host to match the bound address FastMCP expects
                local_host = f"127.0.0.1:{port}".encode()
                new_hdrs = []
                host_rewritten = False
                for hk, hv in hdrs:
                    if hk.lower() == b"host":
                        _log.debug("REWRITE Host: %s -> %s",
                                   hv.decode("utf-8","replace"),
                                   local_host.decode())
                        new_hdrs.append((b"host", local_host))
                        host_rewritten = True
                    else:
                        new_hdrs.append((hk, hv))
                if not host_rewritten:
                    new_hdrs.append((b"host", local_host))

                # Inject MCP-Protocol-Version if absent
                has_proto = any(k.lower() == b"mcp-protocol-version"
                                for k, v in new_hdrs)
                if not has_proto:
                    _log.debug("INJECT MCP-Protocol-Version: 2025-03-26")
                    new_hdrs.append((b"mcp-protocol-version", b"2025-03-26"))

                scope["headers"] = new_hdrs

            # Wrap send() to log what status code FastMCP actually returns.
            # This is critical for diagnosis — we can see if it's still 421
            # and whether our header injections took effect.
            _resp_status = []
            async def _logging_send(message):
                if message.get("type") == "http.response.start":
                    _resp_status.append(message.get("status", "?"))
                    _log.info("FASTMCP RESPONSE: %s %s → HTTP %s",
                              method, path, message.get("status", "?"))
                    if message.get("status", 200) >= 400:
                        resp_hdrs = message.get("headers", [])
                        for rk, rv in resp_hdrs:
                            _log.debug("  RESP-HDR  %s: %s",
                                       rk.decode("utf-8","replace"),
                                       rv.decode("utf-8","replace"))
                await send(message)

            _log.debug("AUTH OK  -> mcp_asgi  (%s %s)", method, path)
            await mcp_asgi(scope, receive, _logging_send)

    app = _RouterASGI()

    print(f"\U0001f680 AI-Prowler HTTP MCP server starting…", flush=True)
    print(f"   Local endpoint : http://127.0.0.1:{port}/mcp", flush=True)
    print(f"   Health check   : http://127.0.0.1:{port}/health", flush=True)
    print(f"   OAuth login    : {PUBLIC_BASE}/authorize", flush=True)
    print(f"   Auth           : OAuth 2.0 + PKCE  (token: {len(token)} chars)", flush=True)
    print(f"   AI-Prowler HTTP server ready", flush=True)

    _log.info("HTTP MCP server starting on port %d", port)
    _log.info("Public base : %s", PUBLIC_BASE)
    _log.info("Token length: %d chars", len(token))
    _log.info("Calling uvicorn.run() — server will block here until stopped")

    # ── Wire uvicorn loggers to our file handler BEFORE calling uvicorn.run() ──
    # IMPORTANT: Do NOT pass log_config= to uvicorn.run().  Doing so causes
    # uvicorn to call logging.config.dictConfig() internally which OVERWRITES
    # the root logger's FileHandler — silencing all _log.debug() calls made
    # inside _RouterASGI (i.e. during every request).  Instead we attach our
    # existing file handler directly to uvicorn's named loggers here, then
    # let uvicorn.run() manage its own internal lifecycle without touching
    # the logging configuration.
    _our_file_handler = logging.root.handlers[0] if logging.root.handlers else None
    if _our_file_handler:
        _uv_fmt = logging.Formatter(
            "%(asctime)s [UVICORN ] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        _our_file_handler.setFormatter(_uv_fmt)
        for _uv_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            _uv_lg = logging.getLogger(_uv_logger_name)
            _uv_lg.setLevel(logging.DEBUG)
            _uv_lg.propagate = True   # propagate → root → our FileHandler
    _log.info("Uvicorn loggers wired to our file handler — debug logging active during requests")

    uvicorn.run(app, host='127.0.0.1', port=port,
                proxy_headers=True,
                forwarded_allow_ips="*",
                log_config=None)   # None = don't touch our logging config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AI-Prowler MCP Server')
    parser.add_argument('--transport', default='stdio', choices=['stdio', 'http'],
                        help='Transport mode: stdio (Claude Desktop) or http (remote/mobile)')
    parser.add_argument('--port', type=int, default=8000,
                        help='Port for HTTP transport (default: 8000)')
    parser.add_argument('--token', default='',
                        help='Bearer token for HTTP transport authentication')
    parser.add_argument('--public-base', default='',
                        dest='public_base',
                        help='Public HTTPS base URL for this tunnel, e.g. '
                             'https://john.dvavro-ai-prowler.com  '
                             'Falls back to tunnel_domain in ~/.ai-prowler/config.json '
                             'then to the built-in default.')
    args = parser.parse_args()

    # ── Resolve public_base ───────────────────────────────────────────────────
    # Priority: --public-base CLI arg > config.json tunnel_domain > built-in default
    resolved_public_base = args.public_base.strip()

    if not resolved_public_base:
        try:
            _cfg_path = _CONFIG_PATH   # honors AIPROWLER_TEST_STATE_DIR sandbox
            if _cfg_path.exists():
                import json as _jcfg
                _cfg = _jcfg.loads(_cfg_path.read_text(encoding='utf-8'))
                _domain = _cfg.get('tunnel_domain', '').strip()
                if _domain:
                    resolved_public_base = (
                        _domain if _domain.startswith('http')
                        else f'https://{_domain}'
                    )
        except Exception as _ce:
            _log.warning("Could not read tunnel_domain from config.json: %s", _ce)

    if not resolved_public_base:
        _log.warning(
            "public_base: no --public-base arg and no tunnel_domain in config.json. "
            "OAuth endpoints will be misconfigured. "
            "Set your Cloudflare tunnel hostname in the AI-Prowler Settings tab."
        )
        resolved_public_base = "http://127.0.0.1:8000"  # safe local fallback
    else:
        _log.info("public_base: resolved to %s", resolved_public_base)

    _log.info("Entry point: transport=%s port=%s public_base=%s",
              args.transport, args.port, resolved_public_base)

    if args.transport == 'http':
        # ── Server mode dispatch (v7.0.0 Phase B) ─────────────────────────────
        # When config.json sets mode=server (Business company server), use the
        # multi-user server transport instead of the single-token _run_http.
        # Personal/Mobile/Home installs are UNAFFECTED — _run_http is unchanged
        # and remains the default path. _run_server_mode falls back to _run_http
        # if its prerequisites aren't met (no users.json, missing deps), so a
        # misconfigured server can never end up with NO transport.
        try:
            _rt = _load_runtime_config()
        except Exception:
            _rt = {"mode": "personal", "edition": "home"}
        if _rt.get("mode") == "server":
            _log.info("Starting SERVER-MODE HTTP transport on port %d (multi-user)", args.port)
            _run_server_mode(port=args.port, token=args.token,
                             public_base=resolved_public_base)
        else:
            _log.info("Starting HTTP transport on port %d", args.port)
            _run_http(port=args.port, token=args.token, public_base=resolved_public_base)
    else:
        _log.info("Starting stdio transport (Claude Desktop mode)")

        # ── Protect the MCP pipe — _STDIO_MODE flag only ──────────────────────
        #
        # CRITICAL: do NOT replace sys.stdout with devnull here.
        #
        # In mcp 1.x, mcp.run(transport="stdio") accesses sys.stdout.buffer at
        # call-time to set up its JSON-RPC write stream.  If sys.stdout has been
        # replaced with a devnull file object before mcp.run() is called, FastMCP
        # picks up the devnull handle and every response — including the initial
        # initialize reply — goes into a black hole.  Claude Desktop never
        # receives a response and shows "not connected" / no tools.
        #
        # The _STDIO_MODE = True flag is the correct and sufficient protection:
        #   - _capture_stdout() becomes a no-op so no tool handler can
        #     accidentally redirect sys.stdout during a tool call.
        #   - All output goes via tool return values and the log file.
        #   - warnings are already suppressed via warnings.filterwarnings above.
        _STDIO_MODE = True
        _log.info("STDIO mode: _STDIO_MODE=True — _capture_stdout() is a no-op")

        # ── BACKGROUND PREWARM — mcp.run() starts immediately ─────────────────
        #
        # Problem: get_chroma_client() initialises ChromaDB and loads the
        # sentence-transformers embedding model (~3s even with HF offline).
        # This MUST NOT block mcp.run() because Claude Desktop sends its
        # initialize message immediately on process launch.  Any delay before
        # mcp.run() starts causes Desktop to time out and disconnect.
        #
        # Problem: rag_preprocessor.get_chroma_client() calls print() directly.
        # In stdio mode stdout is the MCP JSON-RPC pipe — any non-JSON bytes
        # corrupt the protocol.
        # Fix: _do_prewarm() installs _StdoutFilter which discards write() calls
        # while keeping .buffer pointed at the real pipe for mcp.run().
        # NOTE: GUI_MODE=True must NOT be set here — it causes rag_preprocessor
        # to invoke tkinter callbacks that hang forever with no event loop.
        #
        # Problem: get_chroma_client() has internal asyncio code paths that
        # deadlock silently when called from inside a FastMCP tool handler
        # (conflicts with the already-running event loop).
        # Fix: prewarm runs in a background thread OUTSIDE the asyncio loop.
        # rag_preprocessor caches the client and model in module-level globals.
        # Tool handlers wait on _prewarm_event then return cached objects
        # instantly — no asyncio-conflicting initialisation code runs.

        # Prints from rag_preprocessor are suppressed by _StdoutFilter inside
        # _do_prewarm() — GUI_MODE=True is NOT set here because it causes
        # rag_preprocessor to invoke tkinter/GUI callbacks that hang forever
        # in a subprocess with no event loop running.

        # Event that tool handlers wait on before using ChromaDB
        _prewarm_event.clear()

        def _do_prewarm():
            # ── Stdout pollution guard ────────────────────────────────────────
            # Some libraries (PyTorch Blackwell GPU detection, sentence-
            # transformers, tokenizers) print directly to sys.stdout during
            # model load.  In stdio mode sys.stdout IS the MCP JSON-RPC pipe,
            # so any stray text corrupts it and Claude Desktop shows
            # "not valid JSON".
            #
            # Fix: replace sys.stdout with a filter that discards Python-level
            # write() calls (killing stray prints) while keeping .buffer
            # pointing at the real pipe (so mcp.run() can still write JSON).
            # This is race-condition-safe: mcp.run() uses sys.stdout.buffer,
            # and _StdoutFilter.buffer always points to the real pipe regardless
            # of when the swap happens.
            import sys as _sys
            _real_stdout = _sys.stdout   # capture before any modification

            class _StdoutFilter:
                """Discards print()-level writes; exposes real .buffer for mcp."""
                buffer   = getattr(_real_stdout, 'buffer', _real_stdout)
                encoding = getattr(_real_stdout, 'encoding', 'utf-8')
                errors   = getattr(_real_stdout, 'errors',   'replace')
                def write(self, s):   pass   # discard stray prints
                def flush(self):      pass
                def fileno(self):
                    return _real_stdout.fileno()

            _sys.stdout = _StdoutFilter()
            try:
                _log.info("PREWARM: background thread started — loading ChromaDB "
                          "+ embedding model...")
                from rag_preprocessor import get_chroma_client, COLLECTION_NAME
                _pw_client, _pw_emb = get_chroma_client()
                try:
                    _pw_col   = _pw_client.get_or_create_collection(
                                    name=COLLECTION_NAME,
                                    embedding_function=_pw_emb)
                    _pw_count = _pw_col.count()
                    _log.info("PREWARM: done — %d chunks indexed, model cached, "
                              "asyncio-safe", _pw_count)
                except Exception:
                    _log.info("PREWARM: done — DB empty/not created yet, "
                              "embedding model cached")
            except Exception as _pw_err:
                _log.warning("PREWARM: failed (%s) — tool calls will load on demand",
                             _pw_err)
            finally:
                _sys.stdout = _real_stdout   # restore before unblocking tools
                _prewarm_event.set()          # unblock any waiting tool handlers
                _log.info("PREWARM: complete, tool handlers unblocked")

        threading.Thread(target=_do_prewarm, daemon=True, name="prewarm").start()
        _log.info("PREWARM: thread launched — calling mcp.run() immediately")

        mcp.run(transport="stdio")

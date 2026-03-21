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
    "AI-Prowler is an Agentic RAG knowledge base. "
    "Claude retrieves raw document chunks directly and synthesizes answers "
    "using its own intelligence — no local LLM or Ollama required.\n\n"
    "Preferred tool order for any research or question-answering task:\n"
    "  1. get_knowledge_base_overview  — call FIRST to orient yourself: "
         "what documents are indexed, what file types, what topics.\n"
    "  2. list_indexed_documents       — browse specific files when the user "
         "asks about a particular document or topic area.\n"
    "  3. search_documents             — PRIMARY retrieval. Call MULTIPLE TIMES "
         "with different phrasings to gather full context before answering.\n"
    "  4. search_by_multiple_queries   — when a topic has synonyms or multiple "
         "angles; runs parallel searches and deduplicates automatically.\n"
    "  5. get_chunk_context            — expand around a promising result "
         "that appears cut off or references nearby content.\n"
    "  6. get_document_chunks          — read a whole document in sequence "
         "for summaries or full-document review tasks.\n\n"
    "Use check_status() to verify the knowledge base is healthy and reachable."
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

# Module-level event set by the background prewarm thread when ChromaDB and
# the embedding model are fully loaded.  Tool handlers that need ChromaDB
# wait on this event (max 60s) before proceeding.
_prewarm_event = threading.Event()
_prewarm_event.set()   # default: don't block (overridden to clear() in stdio entry)

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

        "PREFERRED TOOL SEQUENCE\n"
        + "-" * 30 + "\n"
        "Use these tools in order for any research or question-answering task:\n\n"

        "  STEP 1  get_knowledge_base_overview()\n"
        "    Orient yourself: see what documents are indexed, file types,\n"
        "    topics covered, and tracked source directories.\n\n"

        "  STEP 2  list_indexed_documents(filter_ext, filter_path)\n"
        "    Browse specific files when the user asks about a particular\n"
        "    document, company, or topic area.\n\n"

        "  STEP 3  search_documents(query, n_results)\n"
        "    PRIMARY retrieval. Call MULTIPLE TIMES with different\n"
        "    phrasings to gather full context. Example:\n"
        "      search_documents('refund policy')\n"
        "      search_documents('money back guarantee')\n\n"

        "  STEP 4  search_by_multiple_queries(queries)\n"
        "    Parallel search when a topic has synonyms or multiple angles.\n"
        "    More efficient than calling search_documents() repeatedly.\n\n"

        "  STEP 5  get_chunk_context(filename, chunk_index)\n"
        "    Expand around a result that appears cut off or references\n"
        "    content in the surrounding paragraphs.\n\n"

        "  STEP 6  get_document_chunks(filename, start_chunk)\n"
        "    Read a whole document sequentially for full summaries or\n"
        "    when the user asks about a specific document's contents.\n\n"

        "KEY FACTS\n"
        + "-" * 30 + "\n"
        "  - NO Ollama required — no local LLM involved at all.\n"
        "  - Claude receives RAW CHUNKS and synthesizes answers directly.\n"
        "  - For complex questions, always search multiple times before answering.\n"
        "  - Use check_status() to verify the knowledge base is healthy.\n"
        "  - Re-call this tool any time you need a reminder of the workflow.\n\n"

        f"MCP SDK version       : {mcp_version}\n"
        f"instructions= active  : {'yes — guidance sent at every handshake' if instructions_active else 'no — upgrade with: pip install --upgrade mcp'}\n"
        "AI-Prowler Agentic RAG ready."
    )


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — add_and_index_directory
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def add_and_index_directory(
    directory: str,
    recursive: bool = True,
    track: bool = True,
) -> str:
    """
    Index all supported documents inside a local folder and (optionally)
    add it to the auto-update tracking list.

    Supported formats: PDF, Word, Excel, PowerPoint, plain text, code,
    Markdown, HTML, email (.msg / .eml / .mbox), images (OCR), and many more.

    Args:
        directory:  Absolute path to the folder you want to index.
                    Example: "C:/Users/David/Documents/ProjectDocs"
        recursive:  Include sub-folders (default True).
        track:      Add the directory to the auto-update list so future
                    `update_tracked_directories` calls will pick up changes
                    (default True).

    Returns:
        Summary of how many files were indexed and any errors encountered.
    """
    dir_path = Path(directory)
    if not dir_path.exists():
        return f"❌ Directory not found: {directory}"
    if not dir_path.is_dir():
        return f"❌ Path is not a directory: {directory}"

    load_config()

    with _capture_stdout() as buf:
        try:
            index_directory(str(dir_path), recursive=recursive)
        except Exception as exc:
            return f"❌ Indexing failed: {exc}"

    output = buf.getvalue().strip()

    if track:
        try:
            added = add_to_auto_update_list(str(dir_path))
            note = (
                "\n✅ Directory added to auto-update tracking."
                if added
                else "\nℹ️  Directory was already in the tracking list."
            )
            output += note
        except Exception as exc:
            output += f"\n⚠️  Could not add to tracking list: {exc}"

    return output if output else "✅ Indexing complete (no output produced)."


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — update_tracked_directories
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def update_tracked_directories(directory: Optional[str] = None) -> str:
    """
    Re-scan tracked directories for new or modified files and update the
    index incrementally (only changed files are re-indexed).

    Args:
        directory:  If provided, update only this specific directory.
                    If omitted, update ALL tracked directories.

    Returns:
        A summary of changes detected and files re-indexed.
    """
    load_config()

    dirs_to_update: list[str] = []
    if directory:
        dirs_to_update = [directory]
    else:
        dirs_to_update = load_auto_update_list()

    if not dirs_to_update:
        return (
            "ℹ️  No tracked directories found.\n"
            "Use add_and_index_directory first to index a folder and add it to tracking."
        )

    with _capture_stdout() as buf:
        for d in dirs_to_update:
            try:
                command_update(d, recursive=True, auto_confirm=True)
            except Exception as exc:
                print(f"⚠️  Error updating {d}: {exc}")

    return buf.getvalue().strip() or "✅ All tracked directories are up to date."


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — get_database_stats
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def get_database_stats() -> str:
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
        from rag_preprocessor import get_chroma_client, COLLECTION_NAME, CHROMA_DB_PATH
        client, embedding_func = get_chroma_client()
        try:
            collection = client.get_collection(
                name=COLLECTION_NAME,
                embedding_function=embedding_func
            )
        except Exception:
            return "📭 Database is empty or not yet created."

        total_chunks = collection.count()
        if total_chunks == 0:
            return "📭 Database is empty."

        sample    = collection.get(limit=min(5000, total_chunks), include=["metadatas"])
        metadatas = sample.get('metadatas', [])

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
    List all directories currently registered for auto-update tracking.

    Returns:
        A newline-separated list of directory paths, or a message if none
        are registered yet.
    """
    dirs = load_auto_update_list()
    if not dirs:
        return (
            "ℹ️  No directories are currently tracked.\n"
            "Use add_and_index_directory to index a folder and add it to tracking."
        )
    lines = ["📁 Tracked directories:"]
    for i, d in enumerate(dirs, 1):
        lines.append(f"  {i}. {d}")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 6 — remove_directory
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def remove_directory(directory: str) -> str:
    """
    Remove a directory from the tracking list AND delete all of its indexed
    chunks from the ChromaDB knowledge base.

    This is a destructive operation — the documents from this directory
    will no longer be searchable until you re-index them.

    Args:
        directory:  Absolute path to the directory to remove.

    Returns:
        A summary of what was removed.
    """
    with _capture_stdout() as buf:
        try:
            result = remove_directory_from_index(directory)
        except Exception as exc:
            return f"❌ Failed to remove directory: {exc}"

    output = buf.getvalue().strip()
    if isinstance(result, dict):
        chunks = result.get('chunks_removed', 'unknown')
        files  = result.get('files_removed', 'unknown')
        output += f"\n✅ Removed {chunks} chunk(s) from {files} file(s)."
    return output or f"✅ Directory removed: {directory}"


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 7 — check_status
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def check_status() -> str:
    """
    Check AI-Prowler's health: ChromaDB connectivity, embedding model status,
    document count, and database path. No Ollama or local LLM involved.

    Returns:
        A diagnostic status report for the Agentic RAG knowledge base.
    """
    # Wait for background prewarm (ChromaDB + embedding model) — max 25s.
    # Prewarm runs in a thread so mcp.run() could start before it finishes.
    _log.info("check_status: tool called — waiting for prewarm if still running")
    if not _prewarm_event.wait(timeout=60):
        _log.warning("check_status: prewarm timeout — returning early")
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
            collection = client.get_collection(
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
        lines.append("   Try re-indexing with add_and_index_directory.")

    # ── Embedding model info (parsed from init output) ────────────────────────
    lines.append("")
    if init_output:
        for line in init_output.splitlines():
            if any(k in line for k in ("Embedding", "embedding", "Loading", "device", "GPU", "CPU", "Blackwell")):
                lines.append(f"   {line.strip()}")
    else:
        lines.append("   Embedding model: loaded (no detail available)")

    # ── Tracked directories ───────────────────────────────────────────────────
    try:
        from rag_preprocessor import load_auto_update_list
        tracked = load_auto_update_list() or []
        lines.append("")
        lines.append(f"📁 Tracked directories : {len(tracked)}")
        for d in tracked[:5]:
            lines.append(f"   - {d}")
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
        return client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )
    except Exception:
        raise RuntimeError(
            "No indexed documents found. "
            "Use add_and_index_directory to index some documents first."
        )


@mcp.tool()
def get_knowledge_base_overview() -> str:
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

    from rag_preprocessor import (
        get_chroma_client, COLLECTION_NAME, CHROMA_DB_PATH,
        load_auto_update_list
    )
    try:
        client, embedding_func = get_chroma_client()
        collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )
    except Exception:
        return (
            "Knowledge base is empty — no documents indexed yet.\n"
            "Use add_and_index_directory to index a folder of documents."
        )

    total_chunks = collection.count()
    if total_chunks == 0:
        return "Knowledge base is empty."

    sample    = collection.get(limit=min(2000, total_chunks))
    metadatas = sample.get('metadatas', [])

    unique_files = {}
    ext_counts   = {}
    for m in metadatas:
        fp  = m.get('filepath', '')
        fn  = m.get('filename', fp)
        ext = m.get('extension', 'unknown').lower()
        if fp not in unique_files:
            unique_files[fp] = {'filename': fn, 'extension': ext,
                                'total_chunks': m.get('total_chunks', 1)}
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

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

    if tracked_dirs:
        lines.append("")
        lines.append("Tracked source directories:")
        for d in tracked_dirs:
            lines.append(f"  - {d}")

    lines.append("")
    lines.append("Next step: use search_documents(query) to find relevant content.")
    return "\n".join(lines)


@mcp.tool()
def search_documents(
    query: str,
    n_results: int = 8,
    min_similarity: float = 0.0,
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

    try:
        from rag_preprocessor import search_documents as _search
        chunks = _search(query, n_results=n_results)
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
        lines.append(
            f"[{i}] {filename}  chunk {chunk_idx+1}/{total_ch}  "
            f"similarity: {sim:.3f}  type: {ext}"
        )
        if filepath and filepath != filename:
            lines.append(f"     Path: {filepath}")
        lines.append("")
        lines.append(content)
        lines.append("")
        lines.append("-" * 55)
        lines.append("")
    lines.append(
        "Tips: call search_documents() again with different query | "
        "get_chunk_context(filename, chunk_index) to expand | "
        "get_document_chunks(filename) to read whole document"
    )
    return "\n".join(lines)


@mcp.tool()
def get_chunk_context(
    filename: str,
    chunk_index: int,
    window: int = 2,
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
        collection = _get_collection()
    except RuntimeError as e:
        return str(e)

    try:
        sample    = collection.get(limit=5000, include=["metadatas", "documents"])
        fn_lower  = filename.lower()
        chunk_map = {}
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
def get_document_chunks(
    filename: str,
    start_chunk: int = 0,
    max_chunks: int = 10,
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
        collection = _get_collection()
    except RuntimeError as e:
        return str(e)

    try:
        sample   = collection.get(limit=5000, include=["metadatas", "documents"])
        fn_lower = filename.lower()
        matches  = []
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
            f"Call: get_document_chunks('{actual_name}', start_chunk={next_start})"
        )
    return "\n".join(lines)


@mcp.tool()
def list_indexed_documents(
    filter_ext: Optional[str] = None,
    filter_path: Optional[str] = None,
    limit: int = 50,
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
        collection = _get_collection()
    except RuntimeError as e:
        return str(e)

    try:
        total   = collection.count()
        sample  = collection.get(limit=min(5000, total), include=["metadatas"])
        metas   = sample.get('metadatas', [])
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
    lines.append("Call get_document_chunks(filename) to read a specific document.")
    return "\n".join(lines)


@mcp.tool()
def search_by_multiple_queries(
    queries: list[str],
    n_results_each: int = 5,
    min_similarity: float = 0.0,
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

    all_chunks: dict = {}
    for q in queries:
        try:
            results = _search(q, n_results=n_results_each)
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

        found_note = f'found by: "{found_by}"'
        if also:
            found_note += f' (also: {", ".join(also)})'

        lines.append(
            f"[{i}] {fn}  chunk {cidx+1}/{total}  "
            f"similarity: {sim:.3f}  {found_note}"
        )
        if fp and fp != fn:
            lines.append(f"     Path: {fp}")
        lines.append("")
        lines.append(content)
        lines.append("")
        lines.append("-" * 55)
        lines.append("")

    lines.append(
        "Call get_chunk_context(filename, chunk_index) to expand any result."
    )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

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

    def _token_key(tok: str) -> str:
        """Short hash of token used as lookup key in subs.json."""
        return _hashlib.sha256(tok.encode()).hexdigest()[:16]

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
        """
        if subs_data is None:
            return {"status": "unmanaged", "name": None, "days_left": None,
                    "message": "No registry — unmanaged/local mode",
                    "banner": ""}

        key         = _token_key(tok)
        subscribers = subs_data.get("subscribers", {})

        if key not in subscribers:
            # Token not in registry — treat as local/unmanaged, not an error
            return {"status": "unmanaged", "name": None, "days_left": None,
                    "message": "Token not in managed registry — local mode",
                    "banner": ""}

        entry    = subscribers[key]
        name     = entry.get("name", "Subscriber")
        exp_str  = entry.get("expires", "")
        try:
            expiry = _dt.date.fromisoformat(exp_str)
        except ValueError:
            return {"status": "unmanaged", "name": name, "days_left": None,
                    "message": f"Invalid expiry date for {name}",
                    "banner": ""}

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
                        "banner": banner}
            return {"status": "ok", "name": name, "days_left": days_left,
                    "message": f"Subscription OK — '{name}', {days_left} day(s) remaining",
                    "banner": ""}

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
                    "banner": banner}

        # Past grace period — BLOCKED
        return {"status": "blocked", "name": name, "days_left": days_left,
                "message": (
                    f"Remote access BLOCKED — subscription for '{name}' expired "
                    f"{days_over} day(s) ago ({expiry}) and the {_GRACE_DAYS}-day grace period has elapsed.  "
                    f"Renew at david.vavro1@gmail.com"
                ),
                "banner": ""}

    # ── Perform initial subscription check on startup ─────────────────────────
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

    _threading.Thread(target=_periodic_sub_refresh, daemon=True).start()

    # In-memory stores for OAuth codes and issued access tokens
    # code -> {redirect_uri, code_challenge, code_challenge_method}
    _auth_codes: dict = {}
    # access_token -> True
    _access_tokens: set = set()
    # Pre-add the user's own bearer token so existing curl/manual clients still work
    _access_tokens.add(token)

    PUBLIC_BASE = public_base.rstrip("/")   # passed in from CLI / config.json

    # ── OAuth discovery endpoints ─────────────────────────────────────────────
    async def oauth_protected_resource(request: Request):
        """RFC 9728 — OAuth 2.0 Protected Resource Metadata.
        Claude.ai fetches THIS endpoint first when it receives a 401.
        It tells Claude where the authorization server lives.
        """
        return JSONResponse({
            "resource": f"{PUBLIC_BASE}/mcp",
            "authorization_servers": [PUBLIC_BASE],
        })

    async def oauth_metadata(request: Request):
        """RFC 8414 — OAuth 2.0 Authorization Server Metadata.
        Claude.ai fetches this second, using the AS URL from above.
        """
        return JSONResponse({
            "issuer": PUBLIC_BASE,
            "authorization_endpoint": f"{PUBLIC_BASE}/authorize",
            "token_endpoint": f"{PUBLIC_BASE}/token",
            "registration_endpoint": f"{PUBLIC_BASE}/register",
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
                # Return 401 without touching the downstream app at all
                body = b'{"error":"unauthorized","error_description":"Invalid or missing Bearer token"}'
                www_auth = (
                    f'Bearer realm="{PUBLIC_BASE}", '
                    f'resource_metadata="{PUBLIC_BASE}/.well-known/oauth-protected-resource"'
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
            _cfg_path = Path.home() / '.ai-prowler' / 'config.json'
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
                    _pw_col   = _pw_client.get_collection(
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

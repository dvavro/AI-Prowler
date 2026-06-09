"""
MCP-tool tests — conftest.

Architecture decision: instead of spawning ai_prowler_mcp.py as a subprocess
and speaking JSON-RPC, we import the module directly and call the @mcp.tool()-
decorated functions as ordinary Python functions. They ARE ordinary Python
functions — the decorator just registers them with FastMCP for dispatch over
stdio. Calling them in-process tests the same code paths and is dramatically
faster and easier to debug.

Why this works
--------------
Each MCP tool is a thin wrapper around rag_preprocessor functions. The
wrapper does three things:
  1. captures stdout via _capture_stdout()
  2. calls the underlying engine function
  3. formats the result into a human-readable string

We exercise all three when we call the function directly, so we get the same
end-to-end coverage that JSON-RPC would, minus the wire-format check
(which is the MCP SDK's responsibility, not ours).

Fixture sharing
---------------
The MCP module imports rag_preprocessor at module-load time. So the same
conftest path-redirection trick we use in tests/unit works here too —
the underlying state files (TRACKING_DB, CHROMA_DB_PATH, etc.) are still
in rag_preprocessor's globals, and patching them affects every caller.

We import the MCP module lazily inside a session-scoped fixture so that
its hefty FastMCP / requests-patching side effects only run once per
pytest session.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Re-use the conftest path setup from tests/conftest.py — that one already
# ensures rag_preprocessor is importable. The MCP module sits in the same
# directory, so it's importable as a side-effect of that.
_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    # tests/mcp/ → tests/ → repo root
    SRC_ROOT = Path(__file__).resolve().parent.parent.parent

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


@pytest.fixture(scope="session")
def mcp_module():
    """Import ai_prowler_mcp once per session.

    NOTE: this import has noticeable side effects:
      • Configures logging to ~/AppData/Local/AI-Prowler/mcp_server.log
      • Patches requests.Session.request temporarily during the load
      • Constructs a FastMCP() server object
      • Sets _engine.GUI_MODE = False, _engine._MCP_MODE = True

    None of these affect test correctness, but they're worth knowing about
    if you wonder why the first MCP test takes a couple of seconds longer
    than the others.
    """
    import ai_prowler_mcp as mcp_mod
    return mcp_mod


@pytest.fixture
def mcp_env(isolated_env, mcp_module):
    """Combine the unit-test isolation fixture with MCP-module access.

    The MCP module imports rag_preprocessor by name at the top, so it shares
    the same global state — when isolated_env redirects TRACKING_DB and
    CHROMA_DB_PATH, the MCP tools see the redirected paths automatically.

    This fixture exists mostly to give tests a single dependency to depend on
    (rather than having to spell out both isolated_env and mcp_module every
    time) and to make the relationship explicit in the fixture graph.
    """
    class McpEnv:
        pass
    e = McpEnv()
    e.mcp = mcp_module
    e.rag = isolated_env.rag
    e.sample_root = isolated_env.sample_root
    e.tmp_path = isolated_env.tmp_path
    e.tracking_db = isolated_env.tracking_db
    e.auto_update = isolated_env.auto_update
    e.email_index = isolated_env.email_index
    e.db_dir = isolated_env.db_dir
    return e


# ─────────────────────────────────────────────────────────────────────────────
# Self-learning fixtures — imported from the shared module so the learning
# tests in tests/mcp/ can use sl_env / seeded_learnings.
# Pytest treats imported fixtures the same as locally-defined ones.
# ─────────────────────────────────────────────────────────────────────────────
from tests.learning_fixtures import (  # noqa: F401, E402
    sl_module,
    sl_env,
    seeded_learnings,
)


@pytest.fixture
def sl_mcp_env(sl_env, mcp_module):
    """Combined env: redirected learning paths + MCP module access.

    Defined here (rather than only in test_learning_mcp_tools.py) so that
    any test file in tests/mcp/ can use it — including test_recorded_by.py.

    Confirms the MCP module's _sl reference points at the same module object
    whose globals the sl_env fixture monkey-patched, so isolation is guaranteed.
    """
    assert mcp_module._sl is sl_env.sl, (
        "ai_prowler_mcp._sl does not point at the same module our fixture "
        "patches — isolation would leak. This is an internal-wiring bug."
    )

    class SlMcpEnv:
        pass
    e = SlMcpEnv()
    e.mcp = mcp_module
    e.sl  = sl_env.sl
    e.learnings_file = sl_env.learnings_file
    e.learnings_dir  = sl_env.learnings_dir
    return e

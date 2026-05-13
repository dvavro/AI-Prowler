"""
Shared fixtures for self-learning tests.

Pytest auto-discovers conftest.py files by walking UP the directory tree,
not across siblings. So fixtures defined in tests/learning/conftest.py
are invisible to tests/mcp/ and tests/gui/.

The standard solution would be to put the fixtures in the parent's
tests/conftest.py, but that would force you to manually merge them with
the existing fixtures already in there.

Instead, this module holds the fixtures as plain functions, and each
sibling conftest.py imports them. Pytest treats `from foo import bar`
inside a conftest exactly like a fixture defined locally — no magic.

To use these fixtures in a test directory, add to its conftest.py:

    from tests.learning_fixtures import sl_module, sl_env, seeded_learnings
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# Path setup — duplicated from conftest.py so this module is self-contained
# (it's imported as a regular module, not auto-loaded by pytest, so the
# conftest's sys.path manipulation may not have run yet).
_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


@pytest.fixture(scope="session")
def sl_module():
    """Import self_learning once per session."""
    import self_learning as sl
    return sl


@pytest.fixture
def sl_env(isolated_env, sl_module, monkeypatch):
    """Per-test isolated learning environment.

    Depends on isolated_env (from the top-level conftest) so ChromaDB and
    tracking-DB are also isolated.
    """
    sl = sl_module
    learnings_dir  = isolated_env.tmp_path / "learnings"
    learnings_dir.mkdir(exist_ok=True)

    learnings_file = learnings_dir / "self_learning_data.json"
    conflict_file  = learnings_dir / "conflict_settings.json"

    monkeypatch.setattr(sl, "LEARNINGS_DIR",          learnings_dir)
    monkeypatch.setattr(sl, "LEARNINGS_FILE",         learnings_file)
    monkeypatch.setattr(sl, "CONFLICT_SETTINGS_FILE", conflict_file)

    # Drop any pre-existing learnings collection so each test starts clean
    try:
        from rag_preprocessor import get_chroma_client
        client, _ = get_chroma_client()
        try:
            client.delete_collection(name=sl.LEARNINGS_COLLECTION)
        except Exception:
            pass
    except Exception:
        pass

    class SlEnv:
        pass
    e = SlEnv()
    e.sl = sl
    e.rag = isolated_env.rag
    e.learnings_dir  = learnings_dir
    e.learnings_file = learnings_file
    e.conflict_file  = conflict_file
    e.tmp_path = isolated_env.tmp_path
    yield e

    # Teardown cleanup
    try:
        from rag_preprocessor import get_chroma_client
        client, _ = get_chroma_client()
        try:
            client.delete_collection(name=sl.LEARNINGS_COLLECTION)
        except Exception:
            pass
    except Exception:
        pass


@pytest.fixture
def seeded_learnings(sl_env):
    """Pre-populate the DB with 4 deterministic learnings."""
    sl = sl_env.sl
    items = [
        sl.record_learning(
            title="Client Alpha prefers email over phone",
            content="Client Alpha responds to email within 1 hour. Phone "
                    "calls reach voicemail and are often missed. Always use "
                    "email as the primary contact channel.",
            category="client_preference",
            source="operator",
            tags=["alpha", "communication"],
            confidence=0.95,
        ),
        sl.record_learning(
            title="Always submit permits 2 weeks ahead",
            content="HVAC permits in this county require 10 business days to "
                    "process. Submitting any closer to the job start risks "
                    "delaying the build. Default lead time: 14 calendar days.",
            category="best_practice",
            source="post_mortem",
            tags=["permits", "hvac"],
            confidence=0.9,
            outcome="positive",
        ),
        sl.record_learning(
            title="Smith project went over budget by 30%",
            content="The Smith kitchen renovation came in 30% over the "
                    "estimate. Root cause: underestimated demo time and "
                    "two unexpected lead-pipe replacements. For older homes, "
                    "add a 15% demo contingency.",
            category="project_insight",
            source="project_review",
            tags=["smith", "kitchen", "budget"],
            confidence=0.85,
            outcome="negative",
        ),
        sl.record_learning(
            title="Use FastMCP version >= 1.2 for instructions support",
            content="The instructions= argument on FastMCP() was added in "
                    "1.2.0. Earlier versions silently ignore it. Pin to "
                    ">=1.2 in requirements if you need server instructions.",
            category="technical_note",
            source="claude_detected",
            tags=["mcp", "fastmcp"],
            confidence=0.8,
        ),
    ]
    return items

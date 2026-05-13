"""
Conftest for tests/learning/ — re-exports the shared learning fixtures.

The fixtures themselves live in tests/learning_fixtures.py so that sibling
test directories (tests/mcp/, tests/gui/) can also import them. Pytest
auto-discovers conftest.py files by walking UP the directory tree, not
across siblings — that's why we need this import-based sharing pattern
rather than just defining the fixtures here.
"""
from tests.learning_fixtures import (  # noqa: F401  (re-exported for pytest)
    sl_module,
    sl_env,
    seeded_learnings,
)

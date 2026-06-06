"""
Parity test: the GUI's shared resolver (scope_resolver) MUST agree with the MCP
engine's own _resolve_collection_for_path / _normalize_path_for_match on every
case. If they ever drift, the operator would SEE a different scope in the GUI
than the engine ENFORCES at index time -- this test makes that impossible to
ship silently.

Until the engine is repointed at scope_resolver, these two implementations are
maintained separately on purpose; this test is the guard that keeps them equal.

Uses the session-scoped `mcp_module` fixture from tests/mcp/conftest.py so the
(side-effecting) engine import happens once.

    pytest tests/mcp/test_scope_resolver_parity.py -v
"""
import pytest

import scope_resolver as sr


_MAPPINGS = [
    {"rules": []},
    {"rules": [], "default_collection": "shared"},
    {"rules": [{"prefix": "C:/Co", "collection": "role:all"},
               {"prefix": "C:/Co/Sales", "collection": "role:sales"}]},
    {"rules": [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}],
     "default_collection": "shared"},
    {"rules": [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}]},
    {"rules": [None, "junk", {"prefix": "", "collection": "x"},
               {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}]},
]

_PATHS = [
    "C:/Co/Sales/q3.pdf",
    r"C:\Co\Sales\q3.pdf",
    "C:/CompanyDocs/SalesArchive/x.pdf",
    "C:/CompanyDocs/Sales",
    "c:/companydocs/sales/deal.docx",
    "C:/Unrelated/notes.txt",
    "C:/Co",
]


def test_normalize_parity(mcp_module):
    eng = getattr(mcp_module, "_normalize_path_for_match", None)
    if eng is None:
        pytest.skip("engine _normalize_path_for_match not present")
    for p in _PATHS + ["", "C:/Docs/", "C:/Docs\\", None]:
        assert eng(p) == sr.normalize_path_for_match(p), repr(p)


def test_resolve_parity(mcp_module):
    eng = getattr(mcp_module, "_resolve_collection_for_path", None)
    if eng is None:
        pytest.skip("engine _resolve_collection_for_path not present")
    for mapping in _MAPPINGS:
        for path in _PATHS:
            assert eng(path, mapping) == sr.resolve_collection_for_path(path, mapping), \
                (mapping, path)


def test_resolve_parity_with_indexer_user(mcp_module):
    eng = getattr(mcp_module, "_resolve_collection_for_path", None)
    if eng is None:
        pytest.skip("engine _resolve_collection_for_path not present")
    user = {"id": "alice01"}
    for path in _PATHS:
        assert eng(path, {"rules": []}, user) == \
            sr.resolve_collection_for_path(path, {"rules": []}, user), path

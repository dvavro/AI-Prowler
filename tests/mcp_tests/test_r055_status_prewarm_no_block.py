#!/usr/bin/env python3
"""
R-055 regression test: check_ai_prowler_status must not block the event loop.

Bug (proven from 3 log files ending at "Load pretrained SentenceTransformer"
with no traceback): check_ai_prowler_status calls get_chroma_client()
synchronously, which loads the SentenceTransformer model (10-30s), blocking
uvicorn's event loop. /health times out -> GUI shows "Stopped" -> user kills
the server mid-load.

Fix: make check_ai_prowler_status async and dispatch get_chroma_client()
via asyncio.to_thread (same pattern as R-053 for reindex_file).
"""
import ast
import os
import re
import sys


def _get_repo_file():
    # tests/mcp_tests/test_r055_... -> repo root -> ai_prowler_mcp.py
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    return os.path.join(repo_root, 'ai_prowler_mcp.py')


def _get_function_node():
    path = _get_repo_file()
    with open(path, 'r', encoding='utf-8') as f:
        src = f.read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == 'check_ai_prowler_status':
                return node, src
    return None, src


def test_check_status_is_async():
    """check_ai_prowler_status must be 'async def' to await to_thread."""
    node, src = _get_function_node()
    assert node is not None, "R-055: check_ai_prowler_status function not found"
    assert isinstance(node, ast.AsyncFunctionDef), (
        "R-055 FAIL: check_ai_prowler_status is 'def', not 'async def'. "
        "It cannot await asyncio.to_thread, so get_chroma_client() "
        "(10-30s SentenceTransformer load) blocks the event loop."
    )


def test_get_chroma_client_offloads_to_thread():
    """get_chroma_client() must go via asyncio.to_thread, not direct call."""
    node, src = _get_function_node()
    assert node is not None, "R-055: check_ai_prowler_status function not found"
    assert isinstance(node, ast.AsyncFunctionDef), (
        "R-055: check_ai_prowler_status is not async — cannot use to_thread"
    )
    seg = ast.get_source_segment(src, node)
    assert seg is not None, "R-055: could not extract function source"
    # Must use thread offload
    uses_thread = ('to_thread' in seg) or ('run_in_executor' in seg)
    assert uses_thread, (
        "R-055 FAIL: check_ai_prowler_status does not use asyncio.to_thread "
        "or run_in_executor — get_chroma_client() blocks the event loop."
    )
    # Must NOT call get_chroma_client() directly outside to_thread
    # Find all occurrences and verify each is inside a to_thread call
    for m in re.finditer(r'get_chroma_client\s*\(', seg):
        before = seg[max(0, m.start() - 80):m.start()]
        # The call should be wrapped: to_thread(get_chroma_client ...) or
        # await asyncio.to_thread(get_chroma_client
        if 'to_thread' not in before and 'run_in_executor' not in before:
            raise AssertionError(
                "R-055 FAIL: get_chroma_client() called directly (not via "
                "to_thread) in check_ai_prowler_status — blocks event loop."
            )


if __name__ == '__main__':
    failed = 0
    for test_fn in [test_check_status_is_async, test_get_chroma_client_offloads_to_thread]:
        try:
            test_fn()
            print(f"PASS: {test_fn.__name__}")
        except AssertionError as e:
            print(f"FAIL: {test_fn.__name__}: {e}")
            failed += 1
    sys.exit(1 if failed else 0)

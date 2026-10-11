"""
R-053 (2026-10-08): the MCP HTTP server wedged — alive but unresponsive.

Server log ended mid-line at "Load pretrained SentenceTransformer:
all-MiniLM-L6-v2" with no crash and no traceback. The reindex_file tool
loaded the embedding model synchronously in the request handler, blocking
uvicorn's event loop for 10-30s. During the block /health could not be
served: the GUI LED correctly showed "Stopped" (not responding), but the
Start button saw the OS process alive (poll() is None) and refused with
"Already Running". The user was trapped in Stop+Start.

Three fixes, each with a regression test below:
 1. reindex_file offloads the model load + indexing to a thread pool
    (asyncio.to_thread) so the event loop stays responsive to /health.
 2. The GUI distinguishes "busy" (proc alive, health failing) from
    "stopped" (proc dead) via a _http_server_state() helper.
 3. The /health probe timeout is raised from 2.5s to 10s.

Run: run_tests.bat tests\\mcp_tests\\test_r053_server_wedge_regression.py -v
"""
import ast
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_MCP_SRC = _SRC / "ai_prowler_mcp.py"
_GUI_SRC = _SRC / "rag_gui.py"


def _find_func(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def test_reindex_file_offloads_to_thread():
    """reindex_file must dispatch heavy work via asyncio.to_thread (or
    loop.run_in_executor) so the event loop stays responsive to /health
    while the embedding model loads. A synchronous blocking call here
    wedges the whole HTTP server (R-053)."""
    src = _MCP_SRC.read_text(encoding="utf-8")
    func = _find_func(ast.parse(src), "reindex_file")
    assert func is not None, "reindex_file not found in ai_prowler_mcp.py"
    offloaded = False
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ("to_thread", "run_in_executor"):
                offloaded = True
                break
    assert offloaded, (
        "reindex_file does not offload work via asyncio.to_thread/run_in_executor — "
        "the event loop will block during model load and /health will stop answering (R-053)"
    )


def _load_http_server_state():
    """Extract the _http_server_state helper from rag_gui.py source and
    exec it in isolation (avoids importing tkinter). Returns the function
    or None if not present."""
    src = _GUI_SRC.read_text(encoding="utf-8")
    node = _find_func(ast.parse(src), "_http_server_state")
    if node is None:
        return None
    seg = ast.get_source_segment(src, node)
    ns = {}
    exec(compile(ast.parse(seg), "<_http_server_state>", "exec"), ns)
    return ns["_http_server_state"]


def test_busy_not_stopped_when_proc_alive():
    """When /health fails but the server process is still alive, the GUI
    must report 'busy' — not 'stopped'. Reporting 'stopped' while the
    Start button sees a live process traps the user (R-053)."""
    fn = _load_http_server_state()
    assert fn is not None, (
        "_http_server_state helper not found in rag_gui.py — "
        "the busy-vs-stopped distinction is not implemented (R-053)"
    )
    # Health failing + proc alive = busy (server wedged, will recover)
    assert fn(health_alive=False, proc_alive=True) == "busy"
    # Health failing + proc dead = stopped (genuinely down)
    assert fn(health_alive=False, proc_alive=False) == "stopped"
    # Health ok = running regardless of proc tracking
    assert fn(health_alive=True, proc_alive=True) == "running"
    assert fn(health_alive=True, proc_alive=False) == "running"


def test_health_check_timeout_generous():
    """The /health probe timeout must be >= 8s. At 2.5s a legitimate
    model-load stall (10-30s) flips the LED to Stopped before the server
    has any chance to answer (R-053)."""
    src = _GUI_SRC.read_text(encoding="utf-8")
    func = _find_func(ast.parse(src), "_http_health_check")
    assert func is not None, "_http_health_check not found in rag_gui.py"
    arg_names = [a.arg for a in func.args.args]
    assert "timeout" in arg_names, "_http_health_check has no timeout parameter"
    idx = arg_names.index("timeout")
    defaults = func.args.defaults
    def_idx = idx - (len(arg_names) - len(defaults))
    assert def_idx >= 0, "_http_health_check timeout has no default value"
    val = ast.literal_eval(defaults[def_idx])
    assert val >= 8, (
        f"_http_health_check timeout is {val}s — must be >= 8s so a "
        f"model-load stall does not flip the LED to Stopped (R-053)"
    )

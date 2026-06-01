# AI-Prowler 6.0.0 — Phase 2 test harness (MCP + GUI)

This adds two new test directories on top of the existing `tests/unit/` harness:

```
tests/
├── unit/         ← (existing) functional tests for rag_preprocessor   — 37 tests
├── mcp/          ← (new)      MCP tool tests                          — 12 tests
└── gui/          ← (new)      Tkinter GUI tests                       — 23 tests
                                                          total 72 tests
```

## What's new

### MCP layer (`tests/mcp/`)

Tests every `@mcp.tool()`-decorated function in `ai_prowler_mcp.py` that touches indexing or tracking. Calls them directly as Python functions instead of spawning a JSON-RPC subprocess — that's much faster and exercises the same code paths.

Covers `index_path`, `update_tracked_directories`, `get_database_stats`, `list_tracked_directories`, `untrack_directory`, error handling for non-existent paths, and the cross-component consistency that lets MCP and the GUI share state.

### GUI layer (`tests/gui/`)

Drives the Tkinter UI in-process. The conftest creates a real `Tk` root, instantiates `RAGGui(root)`, and pumps the event loop with `root.update()` between actions — no pywinauto, no screen recording, no flakiness.

Covers the Index Docs tab (queue management, button states, pre-scan), the Update Index tab (tracked-list refresh, remove-with-confirmation), and the Database management area (Clear Database).

What it doesn't cover: visual layout, theme correctness, real mouse pointer behaviour. For those, the manual smoke test in the test plan is your check.

## How to run

```
# Everything (~3 minutes — GUI tests load embedding model multiple times)
py -m pytest tests

# Just the unit tests — fast, no GUI dependencies
py -m pytest tests/unit

# Just the MCP tests
py -m pytest tests/mcp

# Just the GUI tests
py -m pytest tests/gui

# Skip slow tests (no embedding-model load) — handy for quick smoke
py -m pytest tests -m "not slow"
```

The `tests/run_tests.bat` runner has shortcuts: `tests\run_tests.bat unit`, `mcp`, `gui`, `fast`, `bugs`, or any substring for `-k` matching.

## Setup notes

### MCP tests

Need the `mcp` Python SDK installed (you already have it, since `ai_prowler_mcp.py` imports it at the top):

```
py -m pip install mcp
```

If MCP isn't installed the entire `tests/mcp/` directory will error out at collection — that's intentional, it tells you to install the SDK.

### GUI tests

Need a display. On Windows that's automatic (your desktop session). On macOS the same. On a headless Linux runner you'd wrap pytest in `xvfb-run -a`. The conftest auto-skips the GUI directory if no display is detected, so you won't see false failures.

The GUI tests open a real `Tk` window but immediately call `withdraw()` to hide it. If you want to *see* what the test is doing — useful for debugging — find this line in `tests/gui/conftest.py`:

```python
root.withdraw()
```

…and comment it out. The window will pop into view as the tests run.

### Modal dialogs

The GUI fixture patches `tkinter.messagebox` so dialogs don't actually pop up and block. Each test can control return values via the `dialogs` fixture:

```python
def test_something(gui):
    gui.dialogs.set_response("askyesno", True)   # User clicks "Yes"
    gui.app.some_destructive_button.invoke()
    # ... assertions ...

    # Inspect what dialog the GUI showed
    assert gui.dialogs.last_call("askyesno")["title"] == "Confirm Removal"
```

### Subprocess silencer

The GUI's `__init__` schedules a bunch of `root.after(...)` callbacks that try to start Ollama, an HTTP MCP server, etc. The conftest patches `subprocess.Popen`, `subprocess.run`, etc. to no-ops so those callbacks can't actually launch anything during tests. This is why the GUI tests don't pollute your environment.

## Test → plan ID mapping

Every GUI test name starts with the matching test plan ID:

```
test_G_IDX_01a_add_directory_to_queue        → G-IDX-01 (queue mgmt)
test_G_UPD_03b_cancel_keeps_directory_tracked → G-UPD-03 (remove confirmation)
test_G_DB_02_clear_database_wipes_all         → G-DB-01 + B-04 verification
test_G_MCP_06_untrack_directory_reports_real   → G-MCP-06 + B-03 verification
```

So you can grep for an ID in the test plan Word doc and find the test, or vice versa.

## Architecture: why we don't spawn subprocesses

Both new harnesses prefer in-process testing over subprocess-driven testing. This is deliberate:

**For MCP**: the `@mcp.tool()` decorator just registers the function with FastMCP. The functions themselves are ordinary Python and behave the same whether called via JSON-RPC or directly. Calling them in-process is faster, debuggable in pytest's standard tracebacks, and doesn't require sandbox setup — but covers the same code paths that production traffic does.

**For the GUI**: pywinauto-style automation works on Windows but is slow, flaky, and brittle to layout changes. Tkinter's button `command=` callbacks are just method references — calling the method directly does exactly what clicking does, with no missing coverage. Widget state (`cget('state')`, `listbox.get(0, END)`, `var.get()`) is fully observable through the standard Tk API.

This means both layers run on a build server with no GUI session needed (though GUI tests still need a display, which you handle with xvfb on Linux).

## Known limitations

- **Background threads in GUI tests**: tests that involve worker threads (e.g. `_run_prescan`, `_remove_tracked_worker`) use `gui.wait_until(predicate)` to block until the worker finishes. Default timeout is 30 seconds — if your machine is slow, bump that.
- **One Tk root per process**: pytest will reuse the same Tk underlying interpreter across tests in a session. The fixture destroys the root after each test, but if you see weird "invalid command name" errors, that's the cause and the fix is to add `--forked` or run the GUI tests in their own pytest invocation.
- **First-run model load**: every fixture invalidates the ChromaDB cache for isolation, which means each test re-loads the embedding model (~3-8 s on CPU). If suite time becomes painful, see the comment in `tests/conftest.py` about scoping the heavy fixture to `module` instead of `function`.

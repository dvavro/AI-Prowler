#!/usr/bin/env python3
"""
AI-Prowler MCP Diagnostics  (comprehensive)
============================================
Checks everything needed to debug Claude Desktop MCP connectivity:

  1.  Python executable  -- python.exe vs pythonw.exe
  2.  MCP package        -- version, FastMCP, instructions= support
  3.  AI-Prowler files   -- mcp script, rag_preprocessor importable
  4.  ChromaDB           -- can connect, chunk count
  5.  Claude Desktop     -- config path, entry type (stdio vs HTTP URL)
  6.  Exact command      -- what Claude Desktop will actually run
  7.  Stdio smoke-test   -- launch the MCP server and send initialize
  8.  MCP server log     -- last 40 lines from mcp_server.log
  9.  Tool count         -- how many tools are registered

Usage (run from AI-Prowler install dir):
    python mcp_diagnostics.py
"""

import sys
import os

# Force UTF-8 on Windows console -- must happen before ANY print()
os.environ["PYTHONUTF8"] = "1"
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
import json
import subprocess
import time
import threading
from pathlib import Path

_HERE = Path(os.path.dirname(os.path.abspath(__file__)))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

SEP  = "=" * 64
SEP2 = "-" * 40
OK   = "  [OK] "
ERR  = "  [ERR] "
WARN = "  [WARN]"

issues   = []   # list of (severity, message) -- 'error' | 'warning'
findings = []   # list of key=value strings for final summary

def _ok(msg):   print(f"{OK} {msg}")
def _err(msg):  print(f"{ERR} {msg}");  issues.append(('error',   msg))
def _warn(msg): print(f"{WARN} {msg}"); issues.append(('warning', msg))
def _info(msg): print(f"     {msg}")
def _kv(k, v):  findings.append(f"{k}: {v}"); print(f"     {k}: {v}")

print(SEP)
print("  AI-Prowler MCP Diagnostics")
print(f"  Run at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
print(SEP)

# ==============================================================
# 1. Python Executable
# ==============================================================
print(f"\n{'1. Python Executable':}")
print(SEP2)

py_exe = sys.executable
_kv("sys.executable", py_exe)
_kv("Python version",  sys.version.split()[0])

if "pythonw" in py_exe.lower():
    _err("pythonw.exe DETECTED -- this BREAKS stdio MCP!")
    _info("pythonw.exe redirects stdout to NUL.")
    _info("Claude Desktop reads stdout as the JSON-RPC pipe.")
    _info("Result: every tool call silently returns nothing.")
    _info("FIX: Click 'Auto-configure Claude Desktop' in AI-Prowler Settings -> MCP")
    _info(f"     It will replace: {py_exe}")
    import re as _re
    fixed = _re.sub(r'(?i)pythonw\.exe$', 'python.exe', py_exe)
    _info(f"     With:           {fixed}")
else:
    _ok("python.exe (correct -- stdout is available for MCP pipe)")

# ==============================================================
# 2. MCP Package
# ==============================================================
print(f"\n{'2. MCP Package':}")
print(SEP2)

mcp_pkg = None
try:
    import mcp as mcp_pkg
    # __version__ missing on some installs -- use importlib.metadata as fallback
    try:
        _ver = mcp_pkg.__version__
    except AttributeError:
        try:
            import importlib.metadata as _im
            _ver = _im.version("mcp")
        except Exception:
            _ver = "(unknown -- __version__ not set and importlib.metadata failed)"
    _kv("mcp version",  _ver)
    _kv("mcp location", mcp_pkg.__file__)
    _ok("mcp package importable")
except ImportError:
    _err("mcp package NOT installed -- run: pip install mcp")

if mcp_pkg:
    try:
        from mcp.server.fastmcp import FastMCP
        import inspect as _inspect
        params = list(_inspect.signature(FastMCP.__init__).parameters.keys())
        if "instructions" in params:
            _ok("FastMCP supports instructions= (mcp >= 1.2.0)")
        else:
            _warn("FastMCP does NOT support instructions= -- upgrade: pip install --upgrade mcp")

        # Count tools registered in ai_prowler_mcp.py by importing it dry
        _info("Checking tool count (importing ai_prowler_mcp)...")
        mcp_script_path = _HERE / 'ai_prowler_mcp.py'
        tool_count = 0
        if mcp_script_path.exists():
            with open(mcp_script_path, encoding='utf-8') as _f:
                _src = _f.read()
            tool_count = _src.count('@mcp.tool()')
            _kv("@mcp.tool() decorators found", tool_count)
            if tool_count >= 13:
                _ok(f"{tool_count} tools registered")
            elif tool_count > 0:
                _warn(f"Only {tool_count} tools found -- expected 13")
            else:
                _err("No @mcp.tool() decorators found in ai_prowler_mcp.py")
    except Exception as _e:
        _err(f"FastMCP import error: {_e}")

# ==============================================================
# 3. AI-Prowler Files
# ==============================================================
print(f"\n{'3. AI-Prowler Files':}")
print(SEP2)

_kv("Install directory", str(_HERE))

mcp_script  = _HERE / 'ai_prowler_mcp.py'
rag_script  = _HERE / 'rag_preprocessor.py'

if mcp_script.exists():
    _ok(f"ai_prowler_mcp.py found  ({mcp_script.stat().st_size:,} bytes)")
else:
    _err(f"ai_prowler_mcp.py NOT found at {mcp_script}")

if rag_script.exists():
    _ok(f"rag_preprocessor.py found ({rag_script.stat().st_size:,} bytes)")
else:
    _err(f"rag_preprocessor.py NOT found at {rag_script}")

# Try importing rag_preprocessor
print()
_info("Attempting import of rag_preprocessor...")
rag_ok = False
try:
    import rag_preprocessor as _rag
    _ok("rag_preprocessor imported OK")
    rag_ok = True
except Exception as _ie:
    _err(f"rag_preprocessor import FAILED: {_ie}")
    _info("This means every MCP tool call will crash immediately.")
    _info("Check that all Python dependencies are installed.")

# ==============================================================
# 4. ChromaDB
# ==============================================================
print(f"\n{'4. ChromaDB Knowledge Base':}")
print(SEP2)

if rag_ok:
    try:
        from rag_preprocessor import get_chroma_client, COLLECTION_NAME, CHROMA_DB_PATH
        _kv("ChromaDB path", CHROMA_DB_PATH)
        client, emb_fn = get_chroma_client()
        try:
            col = client.get_collection(name=COLLECTION_NAME,
                                        embedding_function=emb_fn)
            count = col.count()
            _ok(f"ChromaDB connected -- {count:,} chunks indexed")
            _kv("Collection name", COLLECTION_NAME)
            if count == 0:
                _warn("Database is empty -- no documents indexed yet")
        except Exception as _ce:
            _warn(f"Collection not found or empty: {_ce}")
            _info("Run 'Index Documents' in AI-Prowler to index some files first.")
    except Exception as _ce:
        _err(f"ChromaDB connection failed: {_ce}")
else:
    _warn("Skipping ChromaDB check (rag_preprocessor import failed)")

# ==============================================================
# 5. Claude Desktop Config
# ==============================================================
print(f"\n{'5. Claude Desktop Configuration':}")
print(SEP2)

if sys.platform == 'win32':
    appdata = os.environ.get('APPDATA', '')
    config_path = Path(appdata) / 'Claude' / 'claude_desktop_config.json' if appdata else None
elif sys.platform == 'darwin':
    config_path = Path.home() / 'Library' / 'Application Support' / 'Claude' / 'claude_desktop_config.json'
else:
    config_path = Path.home() / '.config' / 'Claude' / 'claude_desktop_config.json'

_kv("Config path", str(config_path))

if not config_path or not config_path.exists():
    _err("claude_desktop_config.json NOT FOUND")
    _info("Install Claude Desktop, then click 'Auto-configure Claude Desktop'.")
else:
    _ok("Config file exists")
    try:
        cfg     = json.loads(config_path.read_text(encoding='utf-8-sig'))
        servers = cfg.get('mcpServers', {})
        _kv("mcpServers keys", list(servers.keys()) or "(none)")

        # -- Check for AI-Prowler entry ---------------------------------
        if 'AI-Prowler' not in servers:
            _err("No 'AI-Prowler' key in mcpServers")
            _info("Click 'Auto-configure Claude Desktop' in AI-Prowler Settings -> MCP")
        else:
            entry = servers['AI-Prowler']
            _info(f"AI-Prowler entry keys: {list(entry.keys())}")

            if 'url' in entry:
                _err("AI-Prowler entry has 'url' -- this is an HTTP entry (WRONG for Desktop)")
                _info(f"  url: {entry['url']}")
                _info("Claude Desktop is connecting over HTTP instead of stdio.")
                _info("That's why it needs the HTTP server running.")
                _info("FIX: Click 'Auto-configure Claude Desktop' in Settings -> MCP")

            elif 'command' in entry:
                cmd  = entry['command']
                args = entry.get('args', [])
                env  = entry.get('env', {})
                _kv("  command", cmd)
                _kv("  args",    args)
                _kv("  env",     env)

                if 'pythonw' in cmd.lower():
                    _err(f"command uses pythonw.exe -- BREAKS stdio MCP")
                    _info("FIX: Click 'Auto-configure Claude Desktop' in Settings -> MCP")
                else:
                    _ok("command uses python.exe (correct)")

                if not Path(cmd).exists():
                    _err(f"command path does not exist: {cmd}")
                    _info("The Python interpreter Claude Desktop would launch is missing.")
                    _info("FIX: Click 'Auto-configure Claude Desktop' to use the current Python.")
                else:
                    _ok("command path exists on disk")

                if args and not Path(args[0]).exists():
                    _err(f"args[0] (MCP script) does not exist: {args[0]}")
                    _info("FIX: Click 'Auto-configure Claude Desktop' to fix the script path.")
                elif args:
                    _ok(f"args[0] (MCP script) exists: {args[0]}")

                if 'PYTHONUNBUFFERED' not in env:
                    _warn("env missing PYTHONUNBUFFERED=1 -- output buffering may delay responses")
                if 'PYTHONNOUSERSITE' not in env:
                    _warn("env missing PYTHONNOUSERSITE=1 -- user-site packages may interfere")

            else:
                _err("AI-Prowler entry has neither 'command' nor 'url' -- malformed entry")
                _info("FIX: Click 'Auto-configure Claude Desktop' in Settings -> MCP")

        # -- Warn about Remote entry being in Desktop config --------------
        if 'AI-Prowler-Remote' in servers:
            _warn("'AI-Prowler-Remote' entry found in Claude Desktop config")
            _info("This HTTP entry belongs in Claude.ai web settings, not here.")
            _info("It won't break Claude Desktop but it's unnecessary clutter.")

    except Exception as _pe:
        _err(f"Could not parse config file: {_pe}")

# ==============================================================
# 6. Exact Command Claude Desktop Will Run
# ==============================================================
print(f"\n{'6. Exact Command Claude Desktop Will Run':}")
print(SEP2)

try:
    cfg2    = json.loads(config_path.read_text(encoding='utf-8-sig'))
    entry2  = cfg2.get('mcpServers', {}).get('AI-Prowler', {})
    if 'command' in entry2:
        cmd_str = f'"{entry2["command"]}" ' + ' '.join(f'"{a}"' for a in entry2.get('args', []))
        _info(f"Command: {cmd_str}")
        _info("(env vars are injected by Claude Desktop before launch)")
    elif 'url' in entry2:
        _info(f"URL (HTTP): {entry2['url']}")
        _info("No subprocess launched -- Claude Desktop connects over HTTP.")
        _err("This is the wrong transport for Claude Desktop.")
    else:
        _info("(could not determine -- entry missing command and url)")
except Exception:
    _info("(could not read config)")

# ==============================================================
# 7. Stdio Smoke-Test
# ==============================================================
print(f"\n{'7. Stdio Smoke-Test (launch MCP server + send initialize)':}")
print(SEP2)

_info("Launching ai_prowler_mcp.py over stdio and sending MCP initialize...")
_info("(timeout: 60 seconds)")

# The MCP initialize request Claude Desktop sends on startup
INIT_MSG = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities":    {},
        "clientInfo":      {"name": "mcp_diagnostics", "version": "1.0"}
    }
}) + "\n"

smoke_ok     = False
smoke_output = ""
smoke_error  = ""

if not mcp_script.exists():
    _warn("Skipping smoke-test -- ai_prowler_mcp.py not found")
elif not rag_ok:
    _warn("Skipping smoke-test -- rag_preprocessor import failed")
else:
    try:
        # Use python.exe explicitly (not pythonw)
        import re as _re
        smoke_py = _re.sub(r'(?i)pythonw\.exe$', 'python.exe', sys.executable)
        env_copy = os.environ.copy()
        env_copy.update({
            'PYTHONNOUSERSITE':  '1',
            'PYTHONIOENCODING':  'utf-8',
            'PYTHONUNBUFFERED':  '1',
        })

        proc = subprocess.Popen(
            [smoke_py, str(mcp_script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env_copy,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )

        response_lines = []
        stderr_lines   = []

        def _read_stdout():
            try:
                for line in proc.stdout:
                    decoded = line.decode('utf-8', errors='replace').strip()
                    if decoded:
                        response_lines.append(decoded)
            except Exception:
                pass

        def _read_stderr():
            try:
                for line in proc.stderr:
                    decoded = line.decode('utf-8', errors='replace').strip()
                    if decoded:
                        stderr_lines.append(decoded)
            except Exception:
                pass

        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        # Send initialize message
        proc.stdin.write(INIT_MSG.encode('utf-8'))
        proc.stdin.flush()

        # Wait up to 55 seconds -- startup includes Ollama probe + embedding model load
        deadline = time.time() + 55
        while time.time() < deadline:
            if response_lines:
                break
            time.sleep(0.2)

        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

        t_out.join(timeout=2)
        t_err.join(timeout=2)

        if response_lines:
            # Try to parse first JSON response
            for line in response_lines:
                try:
                    parsed = json.loads(line)
                    if parsed.get('id') == 1 and 'result' in parsed:
                        result = parsed['result']
                        server_info = result.get('serverInfo', {})
                        capabilities = result.get('capabilities', {})
                        instructions = result.get('instructions', '')
                        _ok("MCP server responded to initialize!")
                        _kv("  serverInfo",    server_info)
                        _kv("  capabilities",  list(capabilities.keys()))
                        if instructions:
                            _ok(f"  instructions= active ({len(instructions)} chars)")
                        smoke_ok = True
                        break
                    elif 'error' in parsed:
                        _err(f"Server returned error: {parsed['error']}")
                except json.JSONDecodeError:
                    # Could be a non-JSON line (log output leaking to stdout!)
                    _warn(f"Non-JSON line on stdout: {line[:120]}")
                    _info("This means stdout is NOT clean -- log output is leaking.")
                    _info("This corrupts the MCP JSON-RPC pipe.")

            if not smoke_ok and not any('error' in l for l in response_lines):
                _warn("Got stdout output but no valid initialize response")
                for l in response_lines[:5]:
                    _info(f"  stdout: {l[:100]}")
        else:
            _err("No response from MCP server within 55 seconds")
            _info("Possible causes:")
            _info("  * rag_preprocessor import hangs (Ollama connection attempt)")
            _info("  * ChromaDB takes too long to load embedding model")
            _info("  * Python path or script path is wrong")
            _info("  * Process crashed immediately (check stderr below)")

        if stderr_lines:
            _info(f"Stderr output ({len(stderr_lines)} lines):")
            for l in stderr_lines[:10]:
                _info(f"  stderr: {l[:120]}")

    except Exception as _se:
        _err(f"Smoke-test failed to launch: {_se}")

# ==============================================================
# 8. MCP Server Log (last 40 lines)
# ==============================================================
print(f"\n{'8. MCP Server Log (last 40 lines)':}")
print(SEP2)

log_path = Path.home() / "AppData" / "Local" / "AI-Prowler" / "mcp_server.log"
_kv("Log path", str(log_path))

if log_path.exists():
    try:
        lines = log_path.read_text(encoding='utf-8', errors='replace').splitlines()
        tail  = lines[-40:] if len(lines) > 40 else lines
        _ok(f"Log found -- {len(lines)} total lines, showing last {len(tail)}")
        print()
        for l in tail:
            print(f"  {l}")
    except Exception as _le:
        _err(f"Could not read log: {_le}")
else:
    _warn("mcp_server.log not found -- MCP server has not run yet under this user")
    _info(f"Expected: {log_path}")

# ==============================================================
# 9. Tool List from ai_prowler_mcp.py
# ==============================================================
print(f"\n{'9. Registered MCP Tools':}")
print(SEP2)

if mcp_script.exists():
    with open(mcp_script, encoding='utf-8') as _f:
        src_lines = _f.readlines()

    tools_found = []
    for i, line in enumerate(src_lines):
        if '@mcp.tool()' in line:
            # Next non-blank line should be 'def tool_name'
            for j in range(i+1, min(i+4, len(src_lines))):
                next_line = src_lines[j].strip()
                if next_line.startswith('def ') or next_line.startswith('async def '):
                    name = next_line.split('(')[0].replace('def ', '').replace('async ', '').strip()
                    tools_found.append(name)
                    break

    _kv("Tool count", len(tools_found))
    for t in tools_found:
        _info(f"  * {t}")

    EXPECTED = {
        'how_to_use_ai_prowler', 'check_status', 'get_knowledge_base_overview',
        'search_documents', 'search_by_multiple_queries', 'get_chunk_context',
        'get_document_chunks', 'list_indexed_documents', 'get_database_stats',
        'add_and_index_directory', 'update_tracked_directories',
        'list_tracked_directories', 'remove_directory'
    }
    missing = EXPECTED - set(tools_found)
    if missing:
        _warn(f"Expected tools not found: {missing}")
    else:
        _ok("All 13 expected tools present")

# ==============================================================
# FINAL SUMMARY
# ==============================================================
print(f"\n{SEP}")
print("  FINAL SUMMARY")
print(SEP)

errors   = [m for s, m in issues if s == 'error']
warnings = [m for s, m in issues if s == 'warning']

if not errors and not warnings:
    print(f"\n{OK} Everything looks correct!")
    print("   If Claude Desktop still doesn't work, try:")
    print("   1. Restart Claude Desktop (fully close and reopen)")
    print("   2. Check the MCP server log above for runtime errors")
    print("   3. In Claude Desktop, start a new conversation and ask 'check AI-Prowler status'")
else:
    if errors:
        print(f"\n{ERR} {len(errors)} ERROR(S) FOUND -- must be fixed:")
        for i, e in enumerate(errors, 1):
            print(f"   {i}. {e}")
    if warnings:
        print(f"\n{WARN} {len(warnings)} WARNING(S):")
        for i, w in enumerate(warnings, 1):
            print(f"   {i}. {w}")

print(f"\n  Key findings:")
for f in findings:
    print(f"    {f}")

if smoke_ok:
    print(f"\n{OK} Stdio smoke-test PASSED -- MCP server responds correctly")
    print("   If Claude Desktop still fails, the issue is in the Desktop config.")
    print("   Click 'Auto-configure Claude Desktop' and restart Desktop.")
elif mcp_script.exists() and rag_ok:
    print(f"\n{ERR} Stdio smoke-test FAILED -- MCP server did not respond")
    print("   Check Section 7 output above for the specific failure.")

print(f"\n  Diagnostics complete -- {time.strftime('%Y-%m-%d %H:%M:%S')}")
print(SEP)

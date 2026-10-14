"""Dev helper: is the MCP Python client available (stdio + streamable HTTP)?"""
import importlib.metadata as md

for pkg in ("mcp", "httpx", "anyio"):
    try:
        print(pkg, md.version(pkg))
    except Exception as e:
        print(pkg, "MISSING", e)
for mod in ("mcp.client.stdio", "mcp.client.streamable_http", "mcp.client.session"):
    try:
        __import__(mod)
        print("ok", mod)
    except Exception as e:
        print("FAIL", mod, e)

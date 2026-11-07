"""David 4 Nov: how_to_use_ai_prowler has to stay up to date. Every tool must be named in the guide, and known to the
MCP Tool Configuration catalog, so a new tool can't be added without either."""
import re
from pathlib import Path

import mcp_tool_catalog as tc

SRC = (Path(__file__).resolve().parents[2] / "ai_prowler_mcp.py").read_text(encoding="utf-8", errors="replace")
TOOLS = re.findall(r"^@mcp\.tool\(\)\s*\n(?:@[^\n]*\n)*def (\w+)\(", SRC, re.M)


def _guide():
    a = SRC.index("def how_to_use_ai_prowler(")
    b = SRC.index("\n@mcp.tool()", a)
    return SRC[SRC.rfind("\n# ", 0, a - 40000):b]             # with the text blocks it's built from


def test_every_tool_is_named_in_the_guide():
    guide = _guide()
    assert not [t for t in TOOLS if not re.search(r"\b" + t + r"\b", guide)]


def test_every_tool_is_in_the_catalog():
    assert not sorted(set(TOOLS) - set(tc.TOOL_CATALOG))


def test_the_guide_explains_the_switches():
    a = SRC.index("def how_to_use_ai_prowler(")
    guide = SRC[a:SRC.index("\n@mcp.tool()", a)]
    assert "Setup" in guide and "Center" in guide and "MCP Tool" in guide and "DISABLED" in guide
    assert "agent" in guide and "Tool Configuration (Settings tab" in guide

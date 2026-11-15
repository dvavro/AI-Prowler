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


def test_every_estimator_tool_is_named_in_the_guide():
    # 2026-11-14 (David): the Estimator's tools are registered by est_tools.register, not @mcp.tool(), so the check
    # above never saw them - and the guide named none of them.
    from estimator.mcp_tools.est_tools import TOOLS as EST
    guide = _guide()
    assert not [f.__name__ for f in EST if not re.search(r"\b" + f.__name__ + r"\b", guide)]


def test_the_estimator_section_follows_its_switch(monkeypatch):
    import estimator.ui.model as em
    import importlib
    import tool_config_store as tcs
    src = SRC
    assert "+ _estimator_guide() +" in src
    ns = {}
    a = src.index("_ESTIMATOR_GUIDE = (")
    b = src.index("# Access-only folders section", a)
    exec(src[a:b], ns)                                       # the constants and _estimator_guide, on their own
    monkeypatch.setattr(em, "is_on", lambda: True)
    assert "est_project_trades" in ns["_estimator_guide"]()
    monkeypatch.setattr(em, "is_on", lambda: False)
    off = ns["_estimator_guide"]()
    assert "turned off" in off and "est_" not in off
    assert tcs.FEATURE_CATEGORIES["estimator"] == "estimator"      # off -> its tools count as off in the footer


def test_every_tool_is_in_the_catalog():
    assert not sorted(set(TOOLS) - set(tc.TOOL_CATALOG))


def test_the_guide_explains_the_switches():
    a = SRC.index("def how_to_use_ai_prowler(")
    guide = SRC[a:SRC.index("\n@mcp.tool()", a)]
    assert "Setup" in guide and "Center" in guide and "MCP Tool" in guide and "DISABLED" in guide
    assert "agent" in guide and "Tool Configuration (Settings tab" in guide

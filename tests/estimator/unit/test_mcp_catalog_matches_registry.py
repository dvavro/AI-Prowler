"""Sprint 31 (Coder 1): the Spec's MCP tool catalog must match the registry.

The catalog in the Design Spec is what an AI client reads to discover the
Estimator's tools. It drifted once (28 registered tools missing, and the
intro still said "About 45"); these guards fail the suite if it drifts again.
"""
import io
import os
import re

from estimator.mcp_tools.est_tools import TOOLS

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SPEC = os.path.join(REPO_ROOT, "docs", "estimator", "AI-Prowler Estimator Design Spec.md")


def _catalog_section():
    with io.open(SPEC, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("## MCP tool catalog"))
    end = next(i for i, ln in enumerate(lines) if ln.startswith("**Conventions**"))
    return lines[start:end]


def _catalogued_tool_names():
    names = set()
    for ln in _catalog_section():
        if ln.lstrip().startswith("|"):
            cells = ln.split("|")
            if len(cells) > 2:
                names.update(re.findall(r"`([a-z][a-z0-9_]+)`", cells[2]))
    return names


def test_s31_g01_every_registered_tool_is_catalogued():
    registered = {fn.__name__ for fn in TOOLS}
    missing = registered - _catalogued_tool_names()
    assert not missing, "tools missing from the Spec catalog: %s" % sorted(missing)


def test_s31_g02_every_catalogued_tool_is_registered():
    registered = {fn.__name__ for fn in TOOLS}
    extra = _catalogued_tool_names() - registered
    assert not extra, "catalog lists tools that are not registered: %s" % sorted(extra)


def test_s31_g03_catalog_intro_states_the_true_count():
    intro = next(ln for ln in _catalog_section()
                 if "registered in the same MCP server" in ln)
    assert ("%d tools" % len(TOOLS)) in intro

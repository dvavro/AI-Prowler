"""
Every app module the MCP server imports must be in every deploy list
(2026-10-28).

oauth_store.py was added and imported by ai_prowler_mcp.py but wasn't in
update_install.bat, so after an update the HTTP server stopped at start-up
(ModuleNotFoundError) and took the Claude connector with it. This checks the
installer, the release manifest and both update scripts against the modules
ai_prowler_mcp.py actually imports from the app folder.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
LOCAL = {p.stem for p in ROOT.glob("*.py")}


def _imported_local_modules():
    mods = set()
    for m in re.finditer(r"^\s*(?:from\s+(\w+)\s+import|import\s+([\w, ]+))", SRC, re.M):
        names = [m.group(1)] if m.group(1) else [n.strip().split(" ")[0] for n in m.group(2).split(",")]
        mods.update(n for n in names if n in LOCAL and n != "ai_prowler_mcp")
    return sorted(mods)


MODULES = _imported_local_modules()


def test_found_the_imports():
    assert "oauth_store" in MODULES and "safe_save" in MODULES


def _missing(text, wildcard_desk=False):
    return [m for m in MODULES
            if f"{m}.py" not in text and not (wildcard_desk and m.startswith("desk_"))]


def test_installer_ships_every_imported_module():
    iss = (ROOT / "AI-Prowler-Setup.iss").read_text(encoding="utf-8", errors="replace")
    desk_wild = bool(re.search(r'Source:\s*"desk_\*\.py"', iss))
    assert _missing(iss, desk_wild) == []


def test_release_manifest_ships_every_imported_module():
    rel = (ROOT / "scripts" / "release.py").read_text(encoding="utf-8", errors="replace")
    desk_wild = "desk_*.py" in rel or "desk_" in rel and "glob(" in rel
    assert _missing(rel, desk_wild) == []


@pytest.mark.parametrize("bat", ["update_install.bat", "update_install_server.bat"])
def test_update_scripts_copy_every_imported_module(bat):
    p = ROOT / bat
    if not p.exists():                      # kept out of git - only on David's PC
        pytest.skip(f"{bat} not in this checkout")
    text = p.read_text(encoding="utf-8", errors="replace")
    assert _missing(text, wildcard_desk='desk_*.py' in text) == []

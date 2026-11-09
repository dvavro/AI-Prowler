# Sprint 31 (Coder 1) — Test Plan

**Scope:** the Design Spec's MCP tool catalog had drifted from the code (same
class of staleness Sprint 30 fixed in the build-status section). An audit
compared the catalog's Tool column against the registered TOOLS tuple in
`estimator/mcp_tools/est_tools.py`: 108 tools are registered, the catalog
listed 80 of them, and its intro still said "About 45 new tools". Sprint 31
adds the 28 missing tools to the catalog (grouped with their areas, Purpose
and Writes? taken from each tool's docstring), corrects the intro count, and
adds drift guards so the catalog cannot silently drift again.

Out of scope: tool behavior (unchanged — docs and guards only), the phase
gates (still not passed; the evidence runs, spec review, version bump and
Word copy remain outstanding), and Coder 2's work.

## Manual checks

None — the catalog is data, verified by the guards below against the live
registry.

## Automated checks

New file: `tests/estimator/unit/test_mcp_catalog_matches_registry.py`

| ID | Check |
| --- | --- |
| S31-G01 | Every tool in the registered TOOLS tuple appears in the catalog's Tool column |
| S31-G02 | Every name in the catalog's Tool column is a registered tool (no phantom tools) |
| S31-G03 | The catalog intro states the true tool count (len(TOOLS)) |

Run:

```
python -m pytest tests/estimator/unit/test_mcp_catalog_matches_registry.py -q
python -m pytest tests/estimator -q
```

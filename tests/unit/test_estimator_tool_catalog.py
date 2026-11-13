"""Estimator tools in the MCP Tool Configuration catalog (2026-11-12, David).

The 108 Estimator tools were live (registered via est_tools.register) but
had no rows in mcp_tool_catalog.py, so the Settings tab's MCP Tool
Configuration panel could not show or toggle them — and the Tier C
suppression in ai_prowler_mcp.py silently dropped them from any hand-edited
tool_config.json (it only honours names in TOOL_CATALOG).

These guards fail the suite if the catalog's estimator entries drift from
the registry again. Pattern follows
tests/estimator/unit/test_mcp_catalog_matches_registry.py (which guards the
Design Spec's catalog section, not this one).
"""
import mcp_tool_catalog as tc
from estimator.mcp_tools.est_tools import TOOLS


def _registered_names():
    return {fn.__name__ for fn in TOOLS}


def test_every_registered_tool_is_catalogued_as_estimator():
    missing = [n for n in sorted(_registered_names())
               if tc.TOOL_CATALOG.get(n) is None
               or tc.TOOL_CATALOG[n].category != "estimator"]
    assert not missing


def test_every_catalogued_estimator_tool_is_registered():
    extra = sorted(set(tc.tools_in_category("estimator")) - _registered_names())
    assert not extra


def test_catalog_states_the_true_count():
    assert len(TOOLS) == 108
    assert len(tc.tools_in_category("estimator")) == 108


def test_estimator_category_exists_last_and_unlocked():
    cat = next(c for c in tc.CATEGORY_ORDER if c.key == "estimator")
    assert cat.label == "Estimator"
    assert not cat.locked
    assert tc.CATEGORY_ORDER[-1].key == "estimator"
    assert tc.category_label("estimator") == "Estimator"
    assert tc.category_description("estimator")
    assert not tc.category_is_locked("estimator")


def test_all_estimator_tools_are_both_modes():
    personal = set(tc.tools_available_in_mode("personal"))
    server = set(tc.tools_available_in_mode("server"))
    for name in tc.tools_in_category("estimator"):
        assert name in personal, name
        assert name in server, name
        assert tc.modes_of(name) == {"personal", "server"}, name


def test_estimator_tools_have_labels_and_descriptions():
    for name in tc.tools_in_category("estimator"):
        meta = tc.TOOL_CATALOG[name]
        assert meta.label.strip(), name
        assert meta.description.strip(), name
        assert meta.label != name, name  # a human label, not the raw tool name


def test_no_estimator_tool_is_locked_or_pwa_dependent():
    for name in tc.tools_in_category("estimator"):
        meta = tc.TOOL_CATALOG[name]
        assert not meta.locked, name
        assert not meta.locked_reason, name
        assert not meta.pwa_dependency, name
        assert meta.pwa_dependency_note is None, name


def test_estimator_is_not_a_default_off_group():
    # The Estimator is on by default — its tools must stay enabled on a new
    # install. DEFAULT_OFF_GROUPS is for opt-in features (Job Tracker, SMS,
    # Service Desk); putting estimator there would switch the tools off.
    import tool_config_store as tcs
    assert "estimator" not in tcs.DEFAULT_OFF_GROUPS


def test_panel_group_list_includes_estimator_with_108_tools():
    # The panel (rag_gui.py MCP Tool Configuration) builds one row per
    # category in CATEGORY_ORDER, keeping only the tools whose modes include
    # the current mode. Replicate that data path (no GUI) and check the
    # estimator row shows up with all 108 tools in both modes.
    for mode in ("personal", "server"):
        cats = []
        for cat in tc.CATEGORY_ORDER:
            tools = [n for n in tc.tools_in_category(cat.key)
                     if mode in tc.modes_of(n)]
            if tools:
                cats.append((cat.key, tools))
        est = dict(cats).get("estimator")
        assert est is not None, mode
        assert len(est) == 108, mode
        assert set(est) == _registered_names(), mode


def test_panel_totals_include_estimator_tools():
    # Personal: 198 catalogued + 108 estimator = 306. Server: 186 + 108 = 294.
    # (The panel header reads "N of M tools enabled in <mode> mode".)
    assert len(tc.tools_available_in_mode("personal")) == 306
    assert len(tc.tools_available_in_mode("server")) == 294
    assert len(tc.TOOL_CATALOG) == 328
